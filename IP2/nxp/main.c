#include <signal.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_reorder.h>
#include <rte_ip.h>
#include <pcap/pcap.h>

#define RX_DESC_PER_QUEUE 1024
#define TX_DESC_PER_QUEUE 1024
#define MAX_PKTS_BURST 32
#define REORDER_BUFFER_SIZE 8192
#define MBUF_PER_POOL 65535
#define MBUF_POOL_CACHE_SIZE 250
#define RING_SIZE 16384
#define NXP_MIN_PORTS 1  /* TODO: 4 */
#define NXP_MAX_PORTS 4
#define NXP_MIN_LCORES 2 /* TODO: 5 */
#define RTE_LOGTYPE_REORDERAPP RTE_LOGTYPE_USER1

uint32_t seqn = 0;

volatile uint8_t quit_signal;

static struct rte_mempool *mbuf_pool;

static struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .ignore_offload_bitfield = 1,
        },
};

struct rx_thread_args {
	struct rte_ring *ring_out;
	uint8_t port;
};

struct transport_thread_args {
        struct rte_ring *ring_in;
        struct rte_reorder_buffer *buffer;
};

volatile struct app_stats {
        struct {
                uint64_t rx_pkts;
                uint64_t enqueue_pkts;
                uint64_t enqueue_failed_pkts;
        } rx __rte_cache_aligned;
        struct {
                uint64_t dequeue_pkts;
                uint64_t saved_pckts;
                uint64_t tx_pkts;
        } transport __rte_cache_aligned;
} app_stats;

static inline void
pktmbuf_free_bulk(struct rte_mbuf *mbuf_table[], unsigned n)
{
        unsigned int i;
        for (i = 0; i < n; i++)
                rte_pktmbuf_free(mbuf_table[i]);
}

/*
 * Tx buffer error callback
 */
static void
flush_tx_error_callback(struct rte_mbuf **unsent, uint16_t count,
                void *userdata __rte_unused) {
        /* free the mbufs which failed from transmit */
        RTE_LOG_DP(DEBUG, REORDERAPP, "%s:Packet loss with tx_burst\n", __func__);
        pktmbuf_free_bulk(unsent, count);
}

static inline int
free_tx_buffers(struct rte_eth_dev_tx_buffer *tx_buffer[]) {
        const uint8_t nb_ports = rte_eth_dev_count();
        unsigned port_id;
        /* initialize buffers for all ports */
        for (port_id = 0; port_id < nb_ports; port_id++) {
                rte_free(tx_buffer[port_id]);
        }
        return 0;
}

static inline int
configure_tx_buffers(struct rte_eth_dev_tx_buffer *tx_buffer[])
{
        const uint8_t nb_ports = rte_eth_dev_count();
        unsigned port_id;
        int ret;
        /* initialize buffers for all ports */
        for (port_id = 0; port_id < nb_ports; port_id++) {
                /* Initialize TX buffers */
                tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
                                RTE_ETH_TX_BUFFER_SIZE(MAX_PKTS_BURST), 0,
                                rte_eth_dev_socket_id(port_id));
                if (tx_buffer[port_id] == NULL)
                        rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                                 port_id);
                rte_eth_tx_buffer_init(tx_buffer[port_id], MAX_PKTS_BURST);
                ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[port_id],
                                flush_tx_error_callback, NULL);
                if (ret < 0)
                        rte_exit(EXIT_FAILURE,
                        "Cannot set error callback for tx buffer on port %u\n",
                                 port_id);
        }
        return 0;
}

static inline int
configure_eth_port(uint16_t port_id)
{
        struct ether_addr addr;
        const uint16_t rxRings = 1, txRings = 1;
        const uint8_t nb_ports = rte_eth_dev_count();
        int ret;
        uint16_t q;
        uint16_t nb_rxd = RX_DESC_PER_QUEUE;
        uint16_t nb_txd = TX_DESC_PER_QUEUE;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;
        struct rte_eth_conf port_conf = port_conf_default;
        if (port_id > nb_ports)
                return -1;
        rte_eth_dev_info_get(port_id, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
                port_conf.txmode.offloads |=
                        DEV_TX_OFFLOAD_MBUF_FAST_FREE;
        ret = rte_eth_dev_configure(port_id, rxRings, txRings, &port_conf_default);
        if (ret != 0)
                return ret;
        ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
        if (ret != 0)
                return ret;
        for (q = 0; q < rxRings; q++) {
                ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                rte_eth_dev_socket_id(port_id), NULL,
                                mbuf_pool);
                if (ret < 0)
                        return ret;
        }
        txconf = dev_info.default_txconf;
        txconf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
        txconf.offloads = port_conf.txmode.offloads;
        for (q = 0; q < txRings; q++) {
                ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                rte_eth_dev_socket_id(port_id), &txconf);
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
print_stats(void)
{
        const uint8_t nb_ports = rte_eth_dev_count();
        unsigned i;
        struct rte_eth_stats eth_stats;
        printf("\nRX thread stats:\n");
        printf(" - Pkts received:               %"PRIu64"\n",
                                                app_stats.rx.rx_pkts);
        printf(" - Pkts parsed and enqd:        %"PRIu64"\n",
                                                app_stats.rx.enqueue_pkts);
        printf(" - Pkts failed to enq:          %"PRIu64"\n",
                                                app_stats.rx.enqueue_failed_pkts);
        printf("\nTransport stats:\n");
        printf(" - Pkts deqd from rx ring:      %"PRIu64"\n",
                                                app_stats.transport.dequeue_pkts);
        printf(" - Pkts saved to pcap:          %"PRIu64"\n",
                                                app_stats.transport.saved_pckts);
        printf(" - Pkts tramsmited:             %"PRIu64"\n",
                                                app_stats.transport.tx_pkts);
        for (i = 0; i < nb_ports; i++) {
                rte_eth_stats_get(i, &eth_stats);
                printf("\nPort %u stats:\n", i);
                printf(" - Pkts in:   %"PRIu64"\n", eth_stats.ipackets);
                printf(" - Pkts out:  %"PRIu64"\n", eth_stats.opackets);
                printf(" - In Errs:   %"PRIu64"\n", eth_stats.ierrors);
                printf(" - Out Errs:  %"PRIu64"\n", eth_stats.oerrors);
                printf(" - Mbuf Errs: %"PRIu64"\n", eth_stats.rx_nombuf);
        }
}

static void
int_handler(int sig_num)
{
        printf("Exiting on signal %d\n", sig_num);
        quit_signal = 1;
}

static int
rx_thread(void *args)
{
        const uint8_t nb_ports = rte_eth_dev_count();
	//uint8_t portno = 0;
	uint32_t out_pckt_counter = 0;
        uint16_t i, ret = 0;
        uint16_t nb_rx_pkts, port_id;
        struct rte_mbuf *pkts[MAX_PKTS_BURST];
	struct rte_mbuf *m;
	struct rte_mbuf *out_pkts[MAX_PKTS_BURST * 100];
	struct ipv4_hdr *ip_hdr;
	struct ether_hdr *eth_hdr;
	uint32_t pkts_len = 0, ipdata_offset, data_len, pad_len = 0;
	struct rx_thread_args *rx_args = (struct rx_thread_args *)args;


        RTE_LOG(INFO, REORDERAPP, "%s() started on lcore %u\n", __func__,
                                                        rte_lcore_id());

        while (!quit_signal) {
		/* receive packets */
		nb_rx_pkts = rte_eth_rx_burst(rx_args->port, 0, pkts, MAX_PKTS_BURST);
		if (nb_rx_pkts == 0) {
				RTE_LOG_DP(DEBUG, REORDERAPP,
				"%s():Received zero packets\n", __func__);
				continue;
		}
		app_stats.rx.rx_pkts += nb_rx_pkts;

		for(int i = 0; i < nb_rx_pkts; ++i)
		{
			m = pkts[i];

			/* Package packet */
			if (m->pkt_len > 10000) // To poznani package paketu se prepise
			{
				eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
				ipdata_offset = sizeof(struct ether_hdr);
				ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset);
				ipdata_offset += (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
				data_len = rte_pktmbuf_data_len(m) - ipdata_offset;
				while (pkts_len < data_len)
				{
					ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset + pkts_len + sizeof(struct ether_hdr));

					out_pkts[out_pckt_counter] = rte_pktmbuf_alloc(mbuf_pool);
					if (out_pkts[out_pckt_counter] == NULL) {
						rte_exit(EXIT_FAILURE, "Failed to allocate mbuf on mempool\n");

					}

					//rte_pktmbuf_read(m, ipdata_offset + pkts_len,
							//rte_bswap16(ip_hdr->total_length) + sizeof(struct ether_hdr),
							//(void *)out_pkts[out_pckt_counter]);

					rte_memcpy(rte_pktmbuf_mtod(out_pkts[out_pckt_counter], void*),
							(void *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset + pkts_len),
							rte_bswap16(ip_hdr->total_length) + sizeof(struct ether_hdr));

					out_pkts[out_pckt_counter]->data_off = 0;
					out_pkts[out_pckt_counter]->seqn = seqn++;
					out_pkts[out_pckt_counter]->data_len = rte_bswap16(ip_hdr->total_length) + sizeof(struct ether_hdr);

					pkts_len += rte_bswap16(ip_hdr->total_length) + sizeof(struct ether_hdr);

					out_pckt_counter++;
				}
				// Free package MBUF
				pktmbuf_free_bulk(&m, 1);
			}
			/* otherwise normal packet */
			else
			{
				// Move mbuf
				out_pkts[out_pckt_counter] = m;
				out_pkts[out_pckt_counter++]->seqn = seqn++;
			}
		}


		/* enqueue to rx_to_transport ring */
		ret = rte_ring_enqueue_burst(rx_args->ring_out,
				(void *)out_pkts, out_pckt_counter, NULL);

		app_stats.rx.enqueue_pkts += ret;
		if (unlikely(ret < out_pckt_counter)) {
				app_stats.rx.enqueue_failed_pkts += (out_pckt_counter-ret);
				pktmbuf_free_bulk(&out_pkts[ret], out_pckt_counter - ret);
		}

		out_pckt_counter = 0;
        }
        return 0;
}

static int
transport_thread(struct transport_thread_args *args)
{
	/* pcap */
	pcap_dumper_t *pcap_file_p;
	pcap_t *pd;
	struct pcap_pkthdr pcap_hdr;
	u_char *packet;

        int ret;
        unsigned int i, dret;
        uint16_t nb_dq_mbufs;
        uint8_t outp;
        unsigned sent;
	struct rte_mbuf *mbuf;
        struct rte_mbuf *mbufs[MAX_PKTS_BURST];
        struct rte_mbuf *rombufs[MAX_PKTS_BURST] = {NULL};
        //static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
	static unsigned out_file_counter = 1;
	char pcap_file_name[32];

        RTE_LOG(INFO, REORDERAPP, "%s() started on lcore %u\n", __func__, rte_lcore_id());

        //configure_tx_buffers(tx_buffer);

	/* pcap config */
	// Tohle pak bude u kazdeho transportu paketu */
	pd = pcap_open_dead(DLT_EN10MB, 65535);
	sprintf(pcap_file_name, "nxpOutput%u.pcap", out_file_counter++);
	pcap_file_p = pcap_dump_open(pd, pcap_file_name);
	if (pcap_file_p == NULL) {
		rte_exit(EXIT_FAILURE, "PCAP -- pcap_dump_open failed\n");
	}
	RTE_LOG(INFO, REORDERAPP, "Opened file pcap file %s\n", pcap_file_name);

        while (!quit_signal) {
                /* deque the mbufs from rx_to_transport ring */
                nb_dq_mbufs = rte_ring_dequeue_burst(args->ring_in,
                                (void *)mbufs, MAX_PKTS_BURST, NULL);
                if (unlikely(nb_dq_mbufs == 0))
                        continue;
                app_stats.transport.dequeue_pkts += nb_dq_mbufs;
                for (i = 0; i < nb_dq_mbufs; i++) {
                        /* send dequeued mbufs for reordering */
                        ret = rte_reorder_insert(args->buffer, mbufs[i]);
			
			//rte_pktmbuf_free(mbufs[i]); // TODO: Free mbuf ?

			/* we ran out of the space for mbufs - transport them to pcap */
                        if (ret == -1 && rte_errno == ENOSPC) {
				/*
				 * drain MAX_PKTS_BURST of reordered
				 * mbufs for writing to PCAP
				 */
				dret = rte_reorder_drain(args->buffer, rombufs, MAX_PKTS_BURST);
				while (dret != 0) {
					for (i = 0; i < dret; i++) {
						mbuf = rombufs[i];
						pcap_hdr.caplen = rte_pktmbuf_data_len(mbuf);
						pcap_hdr.len = rte_pktmbuf_data_len(mbuf);
						packet = rte_pktmbuf_mtod(mbuf, u_char*);
						/* write to pcap */
						pcap_dump((u_char *)pcap_file_p, &pcap_hdr, packet);
						app_stats.transport.saved_pckts++;
					}
					dret = rte_reorder_drain(args->buffer, rombufs, MAX_PKTS_BURST);
				}
				/* insert mbuf which failed to insert */
				rte_reorder_insert(args->buffer, mbufs[i]);
                        }
                }
        }

	// ======================== REMOVE ========================
	// Toto je tu jen proto abych to odzkousel
	// protoze se mi nezaplni reorder buffer

	dret = rte_reorder_drain(args->buffer, rombufs, MAX_PKTS_BURST);
	while (dret != 0) {
		for (i = 0; i < dret; i++) {
			mbuf = rombufs[i];
			pcap_hdr.caplen = rte_pktmbuf_data_len(mbuf);
			pcap_hdr.len = rte_pktmbuf_data_len(mbuf);
			packet = rte_pktmbuf_mtod(mbuf, u_char*);
			/* write to pcap */
			pcap_dump((u_char *)pcap_file_p, &pcap_hdr, packet);
			app_stats.transport.saved_pckts++;
		}
		dret = rte_reorder_drain(args->buffer, rombufs, MAX_PKTS_BURST);
	}

	// ======================== REMOVE ========================

	/* close pcap */
	pcap_close(pd);
	pcap_dump_close(pcap_file_p);

        //free_tx_buffers(tx_buffer);
        return 0;
}

int
main(int argc, char **argv)
{
        int ret;
        unsigned nb_ports;
        unsigned int lcore_id, master_lcore_id;
        uint16_t port_id;
        uint16_t nb_ports_available;
        struct transport_thread_args transport_args = {NULL, NULL};
	struct rx_thread_args rx_args[NXP_MAX_PORTS];
        struct rte_ring *rx_to_transport;

        /* catch ctrl-c so we can print stats on exit */
        signal(SIGINT, int_handler);

        /* Initialize EAL */
        ret = rte_eal_init(argc, argv);
        if (ret < 0)
                return -1;

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

	/* Create mbuf pool */
        mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", MBUF_PER_POOL,
                        MBUF_POOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                        rte_socket_id());
        if (mbuf_pool == NULL)
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
        rx_to_transport = rte_ring_create("rx_to_transport", RING_SIZE, rte_socket_id(),
                        RING_F_SP_ENQ);
        if (rx_to_transport == NULL)
                rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	/* Create reorder buffer */
	transport_args.buffer = rte_reorder_create("PKT_RO", rte_socket_id(),
						REORDER_BUFFER_SIZE);
	if (transport_args.buffer == NULL)
				rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	/* Get master lcore id and leave it to transport_thread */
        master_lcore_id = rte_get_master_lcore();
	
	/* Start rx_thread() for each port (4 for NXP) */
	for (lcore_id = 0, port_id = 0; lcore_id < rte_lcore_count() && port_id < nb_ports; ++lcore_id) {
		if (lcore_id != master_lcore_id) {
			rx_args[port_id].ring_out = rx_to_transport;
			rx_args[port_id].port = port_id;
			rte_eal_remote_launch((lcore_function_t *)rx_thread,
					(void *)&rx_args[port_id++], lcore_id);
		}
	}

        /* Start transport_thread() on master lcore */
	transport_args.ring_in = rx_to_transport;
        transport_thread(&transport_args);

	/* Wait for lcores to finish */
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0)
                        return -1;
        }

        print_stats();
        return 0;
}
