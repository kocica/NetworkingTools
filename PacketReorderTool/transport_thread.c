/**
 * @file transport_thread.c
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Function which is executed on main lcore and saves
 *        parsed packets to pcap file
 */

#include "transport_thread.h"

static void
transport_buffer(struct transport_thread_args *args)
{
        struct rte_mbuf 	*mbuf, *rombufs[max_pkts_burst], *tmp;
        unsigned		dret, size;
        u_char 			*packet;
#ifdef PCAP_DUMP
        unsigned char		pckt[PKG_PKT_MAX_SIZE + RTE_PKTMBUF_HEADROOM];
        struct pcap_pkthdr 	pcap_hdr;
#else
        struct pcap_sf_pkthdr 	pcap_hdr;
#endif

        /* drain max_pkts_burst of reordered mbufs for writing to PCAP */
        dret = rte_reorder_drain(args->buffer, rombufs, max_pkts_burst);
        while (dret != 0) {
                for (int j = 0; j < dret; j++) {
                        mbuf = rombufs[j]; size = 0;

                        pcap_hdr.ts.tv_sec = mbuf->timestamp;
                        pcap_hdr.ts.tv_usec = 0;

#ifdef PCAP_DUMP
                        /* ============================================================== */
                        /// Copying mbufs from linked list to one buffer, then using pcap_dump

                        while (mbuf != NULL) {
                                rte_memcpy(&pckt[size], rte_pktmbuf_mtod(mbuf, unsigned char *), rte_pktmbuf_data_len(mbuf));

                                size += rte_pktmbuf_data_len(mbuf);

                                mbuf = mbuf->next;
                        }

                        __sync_fetch_and_add(&args->stats->saved_bytes, size);

                        pckt[size] = 0;
                        pcap_hdr.caplen = pcap_hdr.len = size;
                        packet = &pckt[0];
                        pcap_dump((u_char *)pcap_file_p, &pcap_hdr, packet);
                        /* ============================================================== */
#else
                        /* ============================================================== */
                        /// Find out size of all mbufs, save header, then save mbufs one by one

                        tmp = mbuf;
                        while(tmp != NULL) {
                                size += rte_pktmbuf_data_len(tmp);
                                tmp = tmp->next;
                        }

                        __sync_fetch_and_add(&args->stats->saved_bytes, size);

                        pcap_hdr.caplen = pcap_hdr.len = size;

                        fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, pcap_file_p);

                        while(mbuf != NULL) {
                                fwrite(rte_pktmbuf_mtod(mbuf, unsigned char *), rte_pktmbuf_data_len(mbuf), 1, pcap_file_p);
                                mbuf = mbuf->next;
                        }
                        /* ============================================================== */
#endif

                        __sync_fetch_and_add(&args->stats->saved_pckts, 1);
                }
                for (int j = 0; j < dret; j++) {
                        /* free mbufs */
                        rte_pktmbuf_free(rombufs[j]);
                }
                dret = rte_reorder_drain(args->buffer, rombufs, max_pkts_burst);
        }
}



int
transport_thread(struct transport_thread_args *args)
{
        uint8_t 		outp;
        unsigned 		sent, i;
        uint64_t 		nb_dq_mbufs;
        int 			ret;
        struct rte_mbuf 	*mbufs[max_pkts_burst];

        printf("%s() started on lcore %u\n", __func__, rte_lcore_id());

        while (!quit_signal) {
                /* deque the mbufs from rx_to_transport ring */
                nb_dq_mbufs = rte_ring_dequeue_burst(args->ring_in,
                                (void *)mbufs, max_pkts_burst, NULL);

                /* didnt enqueue single packet -> skip */
                if (unlikely(nb_dq_mbufs == 0)) {
                        if (transport) goto EXPORT;
                        continue;
                }

                if (verbose) printf("Dqd %lu mbufs from ring\n", nb_dq_mbufs);


                /* add amount of dequeued pckts to counter */
                __sync_fetch_and_add(&args->stats->dequeue_pkts, nb_dq_mbufs);

                /* for each dequed mbuf */
                for (i = 0; i < nb_dq_mbufs; i++) {

                        /* ran out of the space for mbufs - transport them to pcap */
                        if (transport) {
                                for (int k = i; k < nb_dq_mbufs; k++) {
                                        /* store mbuf to reorder insert */
                                        ret = reorder_insert(args->buffer, mbufs[k]);
                                        if (ret == -1) {
                                                /*if (rte_errno == ENOSPC)
                                                        printf("Reorder: ENOSPC1\n");
                                                else
                                                        printf("Reorder: ERANGE1\n");*/
                                                /* move mbufs from reorder buffer to ready buffer */
                                                reorder_to_ready(args->buffer);

                                                /* export mbufs to pcap file */
                                                transport_buffer(args);

                                                /* actualize min_seqn */
                                                args->buffer->min_seqn = mbufs[k]->seqn-100;

                                                /* insert mbuf which failed to insert */
                                                reorder_insert(args->buffer, mbufs[k]);
                                        }
                                }
EXPORT:
                                /* dequeue mbufs which stucked in rx_to_transmit ring */
                                do {
                                        nb_dq_mbufs = rte_ring_dequeue_burst(args->ring_in,
                                                (void *)mbufs, max_pkts_burst, NULL);
                                        /* add amount of dequeued pckts to counter */
                                        __sync_fetch_and_add(&args->stats->dequeue_pkts, nb_dq_mbufs);
                                        for (int k = 0; k < nb_dq_mbufs; k++) {
                                                /* store mbuf to reorder insert */
                                                ret = reorder_insert(args->buffer, mbufs[k]);
                                                if (ret == -1) {
                                                        /*if (rte_errno == ENOSPC)
                                                                printf("Reorder: ENOSPC2\n");
                                                        else
                                                                printf("Reorder: ERANGE2\n");*/
                                                        /* move mbufs from reorder buffer to ready buffer */
                                                        reorder_to_ready(args->buffer);

                                                        /* export mbufs to pcap file */
                                                        transport_buffer(args);


                                                        /* actualize min_seqn */
                                                        args->buffer->min_seqn = mbufs[k]->seqn-100;

                                                        /* insert mbuf which failed to insert */
                                                        reorder_insert(args->buffer, mbufs[k]);
                                                }
                                        }
                                } while (nb_dq_mbufs > 0);

                                /* move mbufs from reorder buffer to ready buffer */
                                reorder_to_ready(args->buffer);

                                /* export mbufs to pcap file */
                                transport_buffer(args);

                                /* finish thread */
                                printf("transport_thread on core %u finished\n", rte_lcore_id());
                                return 0;
                        }
                        else  {
                                /* store mbuf to reorder insert */
                                ret = reorder_insert(args->buffer, mbufs[i]);

                                if (ret == -1) {
                                        /*if (rte_errno == ENOSPC)
                                                printf("Reorder: ENOSPC3\n");
                                        else
                                                printf("Reorder: ERANGE3\n");*/
                                        /* move mbufs from reorder buffer to ready buffer */
                                        reorder_to_ready(args->buffer);

                                        /* export mbufs to pcap file */
                                        transport_buffer(args);
                                        
                                        /* actualize min_seqn */
                                        args->buffer->min_seqn = mbufs[i]->seqn-100;

                                        /* insert mbuf which failed to insert */
                                        reorder_insert(args->buffer, mbufs[i]);
                                }
                        }
                }
        }

        /* move mbufs from reorder buffer to ready buffer */
        reorder_to_ready(args->buffer);

        /* export mbufs to pcap file */
        transport_buffer(args);

        printf("transport_thread on core %u finished\n", rte_lcore_id());
        return 0;
}
