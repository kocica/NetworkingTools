/**
 * @file rx_thread.c
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Function which is executed on every input port
 */

#include "rx_thread.h"

static inline void
pktmbuf_free_bulk(struct rte_mbuf *mbuf_table[], unsigned n)
{
        unsigned int 		i;

        for (i = 0; i < n; i++)
                rte_pktmbuf_free(mbuf_table[i]);
}

int
rx_thread(void *args)
{
        const uint8_t 		nb_ports = rte_eth_dev_count();
        uint32_t 		out_pckt_counter = 0, pkts_len = 0,
                                ipdata_offset, data_len, pad_len = 0, *seqn, *ts;
        uint16_t 		i, nb_rx_pkts, port_id, *pkt_len, len = 0, size = 0;
        int 			ret = 0;
        struct rte_mbuf 	*pkts[max_pkts_burst], *m, *tmp, *out_pkts[max_pkts_burst * 128];
        struct ipv4_hdr 	*ip_hdr;
        struct ether_hdr 	*eth_hdr;
        struct rx_thread_args 	*rx_args = (struct rx_thread_args *)args;

        printf("%s() started on lcore %u\n", __func__, rte_lcore_id());

        /* Reset stats */
        ret = rte_eth_stats_reset(rx_args->port);
        if (ret != 0) {
                fprintf(stderr, "ERROR: Failed to reset stats for NIC %u\n", port_id);
        }

        /* set max pck size we can recv to PKG_PKT_MAX_SIZE */
        rte_eth_dev_set_mtu(rx_args->port, PKG_PKT_MAX_SIZE);

        while (!quit_signal && !free_mem) {
                /* receive packets */
                nb_rx_pkts = rte_eth_rx_burst(rx_args->port, 0, pkts, max_pkts_burst);

                /* no pckts, skip */
                if (nb_rx_pkts == 0) {
                        continue;
                }

                if (verbose) printf("Received %u packets from port %u\n", nb_rx_pkts, rx_args->port);

                /* add recvd pckts to counter */
                __sync_fetch_and_add(&rx_args->stats->rx_pkts, nb_rx_pkts);
                /* for each pckt */
                for(int i = 0; i < nb_rx_pkts; ++i)
                {
                        m = pkts[i];

                        __sync_fetch_and_add(&rx_args->stats->rx_bytes, rte_pktmbuf_data_len(m));

                        /* get eth hdr */
                        eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
                        ipdata_offset = sizeof(struct ether_hdr);

                        /* get ipv4 hdr */
                        //ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset);
                        //ipdata_offset += (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

                        /* len of data in pckt (without header) */
                        data_len = rte_pktmbuf_data_len(m) - ipdata_offset;

                        if (verbose) printf("Data len: %u\n", data_len);

                        /* iterate over pckts in package pckt */
                        while (pkts_len < data_len)
                        {
                                /* first 32 bits are seqn number */
                                seqn = (uint32_t *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset + pkts_len);
                                *seqn = rte_cpu_to_be_32(*seqn);

                                if (verbose) printf("seqn: %u\n", *seqn);

                                /* next 32 bits are timestamp */
                                ts = (uint32_t *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset + pkts_len + sizeof(uint32_t));
                                *ts = rte_cpu_to_be_32(*ts);

                                if (verbose) printf("ts: %u\n", *ts);

                                /* next 16 bits are length of pckt */
                                pkt_len = (uint16_t *)(rte_pktmbuf_mtod(m, char *)  + ipdata_offset + pkts_len + sizeof(uint32_t) + sizeof(uint32_t));

                                *pkt_len = rte_cpu_to_be_16(*pkt_len);

                                if (verbose) printf("pkt_len: %u\n", *pkt_len);

                                /* behind these are pckt data which seqn, timestamp and length belongs to */
                                //ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset + pkts_len + sizeof(struct ether_hdr) + (2*sizeof(uint32_t)));

                                /* allocate new mbuf in mbuf pool */
                                //out_pkts[out_pckt_counter] = rte_pktmbuf_alloc(mbuf_pool_out);
                                ret = rte_mempool_get_bulk(mbuf_pool_out, (void **) &out_pkts[out_pckt_counter], 1);
                                if (out_pkts[out_pckt_counter] == NULL || ret < 0) {
STOP:
                                        rte_eth_dev_stop(rx_args->port);
                                        /* ran out of memory, tell other threads to stop */
                                        printf("ran out of memory for mbufs\n");
                                        if (free_mem) {
                                                printf("rx_thread on core %u finished 3\n", rte_lcore_id());
                                                return 0;
                                        }

                                        free_mem = 1;
                                        
                                        /* enqueue already allocated mbufs */
                                        ret = rte_ring_enqueue_burst(rx_args->ring_out,
                                                (void *)out_pkts, out_pckt_counter, NULL);
                                        __sync_fetch_and_add(&rx_args->stats->enqueue_pkts, ret);
                                        /* if any mbufs failed to enqueue, free them */
                                        if (unlikely(ret < out_pckt_counter)) {
                                                __sync_fetch_and_add(&rx_args->stats->enqueue_failed_pkts, (out_pckt_counter-ret));
                                                pktmbuf_free_bulk(&out_pkts[ret], out_pckt_counter - ret);
                                        }

                                        /* tell transport thread to transport mbufs */
                                        transport = 1;

                                        /* finish */
                                        printf("rx_thread on core %u finished 4\n", rte_lcore_id());
                                        return 0;
                                }

                                /* get pckt len - endian swap */
                                //pkt_len = rte_bswap16(ip_hdr->total_length) + sizeof(struct ether_hdr);

                                if (verbose) printf("Copying data to mbuf\n");

                                /* copy pckt data to mbuf data segments(s) */
                                len = 0; size = 0; tmp = out_pkts[out_pckt_counter];
                                while (len < *pkt_len) {
                                        if (len != 0) {
                                                ret = rte_mempool_get_bulk(mbuf_pool_out, (void **) &tmp->next, 1);
                                                tmp = tmp->next;
                                                if (ret != 0 || tmp == NULL) { goto STOP; }
                                        }
                                        size  = (*pkt_len-len) > (mbuf_pool_size_out) ? (mbuf_pool_size_out) : (*pkt_len-len);
                                        rte_memcpy((void*)(rte_pktmbuf_mtod(tmp, char*)),
                                                (void *)(rte_pktmbuf_mtod(m, char *) + len + ipdata_offset + pkts_len + sizeof(uint16_t) + (2*sizeof(uint32_t))),
                                                size);
                                        len += size;
                                        tmp->data_len = size;
                                }

                                /*rte_memcpy((void*)(rte_pktmbuf_mtod(out_pkts[out_pckt_counter], char*)),
                                                (void *)(rte_pktmbuf_mtod(m, char *) + ipdata_offset + pkts_len + sizeof(uint16_t) + (2*sizeof(uint32_t))),
                                                *pkt_len);*/

                                /* add aditional info to mbuf eg. seqn number, ts */
                                /* set offset to data */
                                out_pkts[out_pckt_counter]->data_off = RTE_PKTMBUF_HEADROOM;
                                out_pkts[out_pckt_counter]->seqn = *seqn;
                                //out_pkts[out_pckt_counter]->data_len = *pkt_len;
                                out_pkts[out_pckt_counter]->timestamp = *ts;

                                /* move to the next packet OR end of package packet */
                                pkts_len += *pkt_len + sizeof(uint16_t) + (2*sizeof(uint32_t));
                                out_pckt_counter++;
                                if (verbose) printf("Moving to next pkt\n");
                        }

                        pkts_len = 0;
                        /* Free package pckt mbuf */
                        rte_pktmbuf_free(m);
                }


                /* enqueue mbuf buffer to rx_to_transport ring */
                ret = rte_ring_enqueue_burst(rx_args->ring_out,
                                (void *)out_pkts, out_pckt_counter, NULL);

                /* did any mbufs fail to enqueue ? */
                __sync_fetch_and_add(&rx_args->stats->enqueue_pkts, ret);
                if (unlikely(ret < out_pckt_counter)) {
                        __sync_fetch_and_add(&rx_args->stats->enqueue_failed_pkts, (out_pckt_counter-ret));
                        pktmbuf_free_bulk(&out_pkts[ret], out_pckt_counter - ret);
                }

                out_pckt_counter = 0;
        }
        rte_eth_dev_stop(rx_args->port);
        printf("rx_thread on core %u finished 5\n", rte_lcore_id());
        return 0;
}
