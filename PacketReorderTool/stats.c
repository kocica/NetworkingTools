/**
 * @file stats.c
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Prints stats before application ends
 */

#include "stats.h"

void
print_stats(struct app_stats_rx *rx, struct app_stats_transport *transport)
{
        const uint8_t nb_ports = rte_eth_dev_count();
        unsigned i;
        struct rte_eth_stats eth_stats;

        printf("\n====================== Stats ======================\n");
        printf("\nRX threads stats:\n");
        printf(" - Pkts received:               %"PRIu64"\n",
                                                rx->rx_pkts);
        printf(" - Pkts parsed and enqd:        %"PRIu64"\n",
                                                rx->enqueue_pkts);
        printf(" - Pkts failed to enq:          %"PRIu64"\n",
                                                rx->enqueue_failed_pkts);
        printf(" - Bytes received:              %"PRIu64"\n",
                                                rx->rx_bytes);

        printf("\nTransport thread stats:\n");
        printf(" - Pkts deqd from rx ring:      %"PRIu64"\n",
                                                transport->dequeue_pkts);
        printf(" - Pkts saved to pcap:          %"PRIu64"\n",
                                                transport->saved_pckts);
        printf(" - Bytes saved to pcap:         %"PRIu64"\n",
                                                transport->saved_bytes);

        printf("\nTX threads stats:\n");
        printf(" - Not implemented\n");

        for (i = 0; i < nb_ports; i++) {
                rte_eth_stats_get(i, &eth_stats);
                printf("\nPort %u stats:\n", i);
                printf(" - Pkts in:                     %"PRIu64"\n", eth_stats.ipackets);
                printf(" - In Errs:                     %"PRIu64"\n", eth_stats.ierrors);
                printf(" - In Missed:                   %"PRIu64"\n", eth_stats.imissed);
                printf(" - Mbuf Errs:                   %"PRIu64"\n", eth_stats.rx_nombuf);
        }

        struct timeval end;
        gettimeofday(&end, NULL);
        double t = (end.tv_sec - start.tv_sec) * 1000.0;
        t += (end.tv_usec - start.tv_usec) / 1000.0;
        double speed = (((transport->saved_bytes)/(t/1000.0))*8)/100000;

        printf(" - Time:                        %f sec\n", t / 1000.0);
        //printf(" - Speed:                       %f Mbps\n", speed);

        printf("\n===================================================\n\n");
}
