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
#define RTE_LOGTYPE_REORDERAPP RTE_LOGTYPE_USER1

/** TODO: Give seqn numbers to pkts */
//uint32_t seqn = 0;

/** Max 1kB packages TODO: 10kB */
const uint16_t MAX_PKG_LEN = 1000;

volatile uint8_t quit_signal;

static struct rte_mempool *mbuf_pool;

static struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .ignore_offload_bitfield = 1,
        },
};

pcap_dumper_t *pcap_file_p;
pcap_t *pd;
struct pcap_pkthdr pcap_hdr;

static inline void
pktmbuf_free_bulk(struct rte_mbuf *mbuf_table[], unsigned n)
{
        unsigned int i;
        for (i = 0; i < n; i++)
                rte_pktmbuf_free(mbuf_table[i]);
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
int_handler(int sig_num)
{
        printf("Exiting on signal %d\n", sig_num);
        quit_signal = 1;
}

static void
save_pkg(unsigned char* pkg, uint16_t len)
{
	pcap_hdr.caplen = pcap_hdr.len = len;
	pcap_hdr.ts.tv_sec = 1396306094;
	pcap_dump((u_char *)pcap_file_p, &pcap_hdr, pkg);

	/*
	struct pcap_pkthdr pkhdr;
	pkhdr.len = pkhdr.caplen = len;
	pkhdr.ts.tv_sec = 1396306094; // TODO: timestamp
	// TODO: seqn number
	fwrite(&pkhdr, sizeof(pkhdr), 1, file);
	fwrite(pkg, len, 1, file);
	*/
}

static void
generator()
{
	uint16_t act_len = 0;
	uint16_t i, j, ret = 0;
	uint16_t nb_rx_pkts, port_id;
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	unsigned char pkg[MAX_PKG_LEN];
	struct ipv4_hdr ip;
	struct ether_hdr eth;

        ip.version_ihl = (0x40 | 0x05);
        ip.type_of_service = 0;
        ip.packet_id = 0;
        ip.fragment_offset = 0x0040;
        ip.time_to_live = 5;
        ip.next_proto_id = IPPROTO_TCP;
        ip.hdr_checksum = 0;
        ip.src_addr = 0;
        ip.dst_addr = 0;

	eth.ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);
	for (int i = 0; i < 6; i++) {
		eth.d_addr.addr_bytes[i] = i;
		eth.s_addr.addr_bytes[i] = i;
	}

	act_len = sizeof(ip) + sizeof(eth);

	while (!quit_signal) {
		for (i = 0; i < rte_eth_dev_count(); i++) {
			nb_rx_pkts = rte_eth_rx_burst(i, 0, pkts, MAX_PKTS_BURST);

			for (j = 0; j < nb_rx_pkts; j++) {
				if (rte_pktmbuf_data_len(pkts[j]) > MAX_PKG_LEN) {
					// Skip
					continue;
				}
				else if ((act_len + rte_pktmbuf_data_len(pkts[j])) > MAX_PKG_LEN) {
					// Save pkg to pcap file
					ip.total_length = rte_bswap16(act_len - sizeof(eth));
					rte_memcpy(pkg, &eth, sizeof(eth));
					rte_memcpy(pkg + sizeof(eth), &ip, sizeof(ip));

					save_pkg(pkg, act_len);
					act_len = sizeof(ip) + sizeof(eth);

					// Read last mbuf again
					j--;
				}
				else {
					// Save mbuf to pkg
					rte_memcpy((void *)(pkg + act_len),
							rte_pktmbuf_mtod(pkts[j], void *),
							rte_pktmbuf_data_len(pkts[j]));

					act_len += rte_pktmbuf_data_len(pkts[j]);
				}
			}
		}
	}
}

static void
pcap_file_init()
{
	pd = pcap_open_dead(DLT_EN10MB, 65535);
	pcap_file_p = pcap_dump_open(pd, "pcap_pkg.pcap");

	/*
	struct pcap_file_header fh;
	fh.magic = 0xa1b2c3d4;
	fh.sigfigs = 0;
	fh.version_major = 2;
	fh.version_minor = 4;
	fh.snaplen = USHRT_MAX;
	fh.thiszone = 0;
	fh.linktype = 1;
	fwrite(&fh, sizeof(fh), 1, file);
	*/
}

int
main(int argc, char **argv)
{
        int ret;
        uint16_t port_id;

        /* catch ctrl-c so we can print stats on exit */
        signal(SIGINT, int_handler);

        /* Initialize EAL */
        ret = rte_eal_init(argc, argv);
        if (ret < 0)
                return -1;

	/* Create mbuf pool */
        mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", MBUF_PER_POOL,
                        MBUF_POOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                        rte_socket_id());
        if (mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

        /* initialize all ports */
        for (port_id = 0; port_id < rte_eth_dev_count(); port_id++) {
                /* init port */
                printf("Initializing port %u... done\n", port_id);
                if (configure_eth_port(port_id) != 0)
                        rte_exit(EXIT_FAILURE, "Cannot initialize port %"PRIu8"\n",
                                        port_id);
        }

	pcap_file_init();
        generator();
	pcap_close(pd);
	pcap_dump_close(pcap_file_p);

        return 0;
}
