/**
 * @file rx_thread.h
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Function which is executed on every input port
 */

#ifndef __RX_THREAD_H
#define __RX_THREAD_H

#include "defines.h"
#include "stats.h"

struct rx_thread_args {
        struct rte_ring *ring_out; 		/**< Ring where rx thread stores mbufs */
        uint8_t port;				/**< Which port to read from */
        struct app_stats_rx *stats;             /**< RX stats */
};


/**
 * @params args Args to an thread, containing port to read from & communication ring
 * @return success or failure
 * @brief read the packets from specified port & parses them. Parsed packets stored into
 *        reorder buffer
 */
int
rx_thread(void *args);

/**
 * @param mbuf_table array of pointers to mbufs
 * @param n count of freed mbufs
 * @return failure or success
 * @brief frees bulk of mbufs in buffer
 */
static inline void
pktmbuf_free_bulk(struct rte_mbuf *mbuf_table[], unsigned n);


extern uint16_t         max_pkts_burst;
extern uint8_t          verbose;
extern volatile uint8_t quit_signal, transport, free_mem;
extern unsigned         mbuf_pool_size_out;
extern struct           rte_mempool *mbuf_pool_out;

static struct           rte_eth_conf port_conf_default = {
        .rxmode = {
                .ignore_offload_bitfield = 1,
        },
};

#endif /* ! __RX_THREAD_H */
