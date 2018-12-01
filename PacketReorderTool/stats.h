/**
 * @file stats.h
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Prints stats before application end
 */

#ifndef __STATS_H
#define __STATS_H

#include "defines.h"


struct app_stats_rx {
        uint64_t rx_pkts;			/**< Amount of received pckts */
        uint64_t enqueue_pkts;			/**< Amount of pckts enqueued to ring buffer */
        uint64_t enqueue_failed_pkts;		/**< Amount of pckts failed to enqueue to ring buffer */
        uint64_t rx_bytes;			/**< Amount of received bytes */
};

struct app_stats_transport {
        uint64_t dequeue_pkts;			/**< Amount of pckts drained from ring buffer */
        uint64_t saved_pckts;			/**< Amount of pckts written to pcap file */
        uint64_t saved_bytes;			/**< Amount of bytes written to pcap file */
};

/**
 * @param rx rx thread stats
 * @param transport transport thread stats
 * @brief prints out the stats of every port and rx/transport threads
 */
void
print_stats(struct app_stats_rx *rx, struct app_stats_transport *transport);

extern struct timeval start;

#endif /* ! __STATS_H */
