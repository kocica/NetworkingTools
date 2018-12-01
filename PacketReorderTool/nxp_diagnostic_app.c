/**
 * @file nxp_diagnostic_app.c
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Constants used in diagnostic application
 *
 * Important:
 *   - Running this application with corelist (bcs 0. core handles ints)
 *       -l 1-7
 * 
 *   - seqn, ts and pkt len should be saved in little endian
 *
 *   - example running app:
 *          <target> -l 1-7 -- -r 262144 -m 65536 -n 262144
 *          Depends on how many packets are stored in one package packet
 *          eg. there are 3 packets in one package packet, then output mempool
 *          (-n) should be 3x bigger than input mempool (-m) to store all of these
 *          parsed packets
 */

#include "defines.h"
#include "rx_thread.h"
#include "transport_thread.h"
#include "stats.h"
#include "reorder.h"

volatile uint8_t   quit_signal,
                   free_mem,
                   transport;

uint16_t           max_pkts_burst = MAX_PKTS_BURST,
                   nb_rxd = RX_DESC_PER_QUEUE;

unsigned           mbuf_pool_size_out = RTE_MBUF_DEFAULT_BUF_SIZE;

uint8_t            verbose;

struct timeval     start;

struct rte_mempool *mbuf_pool_in,
                   *mbuf_pool_out;

#ifdef PCAP_DUMP
    pcap_dumper_t  *pcap_file_p;
#else
    FILE           *pcap_file_p;
#endif

static inline int
configure_eth_port(uint16_t port_id)
{
        struct 			ether_addr addr;
        const uint16_t 		rxRings = 1, txRings = 0;
        const uint8_t 		nb_ports = rte_eth_dev_count();
        int 			ret;
        uint16_t 		q, nb_txd = 0;
        struct rte_eth_conf port_conf = port_conf_default;

        if (port_id > nb_ports)
                return -1;
        ret = rte_eth_dev_configure(port_id, rxRings, txRings, &port_conf_default);
        if (ret != 0)
                return ret;
        ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
        if (ret != 0)
                return ret;
        for (q = 0; q < rxRings; q++) {
                ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                rte_eth_dev_socket_id(port_id), NULL,
                                mbuf_pool_in);
                if (ret < 0)
                        return ret;
        }
        ret = rte_eth_dev_start(port_id);
        if (ret < 0)
                return ret;
        rte_eth_macaddr_get(port_id, &addr);
        printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
                        " %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
                        port_id,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);
        rte_eth_promiscuous_enable(port_id);
        return 0;
}

static void
int_handler(int sig_num)
{
        printf("Recieved signal %d.\n", sig_num);
        quit_signal = 1;
}

int
main(int argc, char **argv)
{
        printf("Compiled %s - %s\n", __DATE__, __TIME__);
        int 			ret;
        unsigned 		nb_ports, lcore_id, master_lcore_id;
        uint16_t 		port_id, nb_ports_available;
        struct 			transport_thread_args transport_args = {NULL, NULL};
        struct 			rx_thread_args rx_args[NXP_MAX_PORTS];
        struct 			rte_ring *rx_to_transport;
        pcap_t 			*pd;
        char 			*pcap_file_name = "nxpOut.pcap";
#ifndef PCAP_DUMP
        struct 			pcap_file_header header;
        header.linktype 	= DLT_EN10MB;
        header.snaplen 		= 65535;
        header.sigfigs 		= 0;
        header.thiszone 	= 0;
        header.version_minor 	= 4;
        header.version_major 	= 2;
        header.magic 		= 0xa1b2cd34;
#endif

        /* catch ctrl-c so we can print stats on exit */
        signal(SIGINT, int_handler);

        /* Initialize EAL */
        ret = rte_eal_init(argc, argv);
        if (ret < 0)
                return -1;

        argc -= ret;
        argv += ret;

        /* Parse args */
        int opt;
        unsigned reorder_size 		= REORDER_BUFFER_SIZE;
        unsigned ring_size 		= RING_SIZE;
        unsigned mbufs_per_pool_in	= MBUF_PER_POOL;
        unsigned mbufs_per_pool_out	= MBUF_PER_POOL;
        unsigned mbuf_pool_size_in 	= PKG_PKT_MAX_SIZE + RTE_PKTMBUF_HEADROOM;
        /// Mbuf_pool_size_out is global
        uint16_t mbuf_cache_size 	= MBUF_POOL_CACHE_SIZE;
        /// Max_pkts_burst is global

        while ((opt = getopt(argc, argv, "hvr:i:m:n:s:o:c:p:d:")) != EOF) {
                switch (opt) {
                case 'r':
                        reorder_size = atoi(optarg);
                        break;
                case 'i':
                        ring_size = atoi(optarg);
                        break;
                case 'd':
                        nb_rxd = atoi(optarg);
                        break;
                case 'm':
                        mbufs_per_pool_in = atoi(optarg);
                        break;
                case 'n':
                        mbufs_per_pool_out = atoi(optarg);
                        break;
                case 's':
                        mbuf_pool_size_in = atoi(optarg);
                        break;
                case 'o':
                        mbuf_pool_size_out = atoi(optarg);
                        break;
                case 'c':
                        mbuf_cache_size = atoi(optarg);
                        break;
                case 'p':
                        max_pkts_burst = atoi(optarg);
                        break;
                case 'v':
                        verbose = 1;
                        break;
                case 'h':
                default:
                        puts("Usage:");
                        puts(" -h              Prints this help");
                        puts(" -v              Verbose mod");
                        puts(" -r    (2^n)     Reorder buffer size");
                        puts(" -i    (2^n)     Ring size");
                        puts(" -m    (2^n-1)   Mbufs per pool in");
                        puts(" -n    (2^n-1)   Mbufs per pool out");
                        puts(" -s    (10k)     Mbuf pool size in");
                        puts(" -o    (2ki)     Mbuf pool size out");
                        puts(" -c    (~256)    Mbuf cache size");
                        puts(" -p    (16-64)   Max pckts burst");
                        puts(" -d    (~1024)   RX descriptors");
                        return -1;
                }
        }

        if (verbose) {
                printf("Reorder size         : %u\n", reorder_size);
                printf("Ring size            : %u\n", ring_size);
                printf("Mbufs per pool in    : %u\n", mbufs_per_pool_in);
                printf("Mbufs per pool out   : %u\n", mbufs_per_pool_out);
                printf("Mbuf pool size in    : %u\n", mbuf_pool_size_in);
                printf("Mbuf pool size out   : %u\n", mbuf_pool_size_out);
                printf("Mbuf cache size      : %u\n", mbuf_cache_size);	
                printf("Max pckts burst      : %u\n", max_pkts_burst);
                printf("RX descriptors       : %u\n", nb_rxd);
        }

        /* Check if we have enought cores */
        if (rte_lcore_count() < NXP_MIN_LCORES)
                rte_exit(EXIT_FAILURE, "Error, This application needs at "
                                "least %d logical cores to run:\n"
                                "%d lcore for packet RX\n"
                                "1 lcore for packet Transport(TX)\n",
                                NXP_MIN_LCORES, NXP_MIN_LCORES-1);

        /* Check if weve got correct number of ports */
        nb_ports = rte_eth_dev_count();
        if (nb_ports < NXP_MIN_PORTS)
                rte_exit(EXIT_FAILURE, "Error: %d ethernet ports expected\n",
                        NXP_MIN_PORTS);

        /* Open pcap file */
#ifdef PCAP_DUMP
        pd = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_file_p = pcap_dump_open(pd, pcap_file_name);
        if (pcap_file_p == NULL) {
                rte_exit(EXIT_FAILURE, "PCAP -- pcap file open failed\n");
        }
#else
        pcap_file_p = fopen(pcap_file_name, "wb"); /* Important wb */
        if (pcap_file_p == NULL) {
                rte_exit(EXIT_FAILURE, "PCAP -- pcap file open failed\n");
        }
        fwrite((char*)&header, sizeof(header), 1, pcap_file_p);
#endif
        printf("Opened pcap file %s\n", pcap_file_name);

        /* Create in mbuf pool */
        mbuf_pool_in = rte_pktmbuf_pool_create("mbuf_pool_in", mbufs_per_pool_in,
                        mbuf_cache_size, 0, mbuf_pool_size_in,
                        rte_socket_id());
        if (mbuf_pool_in == NULL)
                rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

        /* Create out mbuf pool */
        mbuf_pool_out = rte_pktmbuf_pool_create("mbuf_pool_out", mbufs_per_pool_out,
                        mbuf_cache_size, 0, mbuf_pool_size_out + RTE_PKTMBUF_HEADROOM,
                        rte_socket_id());
        if (mbuf_pool_out == NULL)
                rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

        nb_ports_available = nb_ports;
        /* initialize all ports */
        for (port_id = 0; port_id < nb_ports; port_id++) {
                /* init port */
                printf("Initializing port %u... done\n", port_id);
                if (configure_eth_port(port_id) != 0)
                        rte_exit(EXIT_FAILURE, "Cannot initialize port %"PRIu8"\n",
                                        port_id);
        }
        /* Is any port unavaible ? */
        if (nb_ports_available != nb_ports) {
                rte_exit(EXIT_FAILURE,
                        "%d available ports expected.\n", NXP_MIN_PORTS);
        }

        /* Create ring for inter core communication */
        rx_to_transport = rte_ring_create("rx_to_transport", ring_size, rte_socket_id(), 0);
        if (rx_to_transport == NULL)
                rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

        /* Alloc stat structs for both rx & transport threads */
        struct app_stats_rx *rx_stats = rte_zmalloc(NULL, sizeof *rx_stats, 0);
        struct app_stats_transport *transport_stats = rte_zmalloc(NULL, sizeof *transport_stats, 0);

        /* Create reorder buffer */
        transport_args.buffer = rte_reorder_create("PKT_RO", rte_socket_id(),
                                                reorder_size);
        if (transport_args.buffer == NULL)
                                rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
        transport_args.buffer->min_seqn = 0;
        transport_args.buffer->is_initialized = 1;

        /* Get master lcore id and leave it to transport_thread */
        master_lcore_id = rte_get_master_lcore();
        
        /* Start timer */
        gettimeofday(&start, NULL);

        /* Start rx_thread() for each port (4 for NXP) */
        if (nb_ports > 4) nb_ports = 4;
        for (lcore_id = 1, port_id = 0; lcore_id < rte_lcore_count() && port_id < nb_ports; ++lcore_id) {
                if (lcore_id != master_lcore_id) {
                        rx_args[port_id].ring_out = rx_to_transport;
                        rx_args[port_id].port = port_id;
                        rx_args[port_id].stats = rx_stats;
                        rte_eal_remote_launch((lcore_function_t *)rx_thread,
                                        (void *)&rx_args[port_id++], lcore_id);
                }
        }

        /* Start transport_thread() on master lcore */
        transport_args.ring_in = rx_to_transport;
        transport_args.stats = transport_stats;
        transport_thread(&transport_args);

        printf("waiting for cores to finish\n");
        /* Wait for lcores to finish */
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0)
                        return -1;
        }

        /* close pcap */
#ifdef PCAP_DUMP
        pcap_close(pd);
        pcap_dump_close(pcap_file_p);
#else
        fclose(pcap_file_p);
#endif

        print_stats(rx_stats, transport_stats);
        return 0;
}
