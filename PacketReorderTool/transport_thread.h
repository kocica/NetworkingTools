/**
 * @file transport_thread.h
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Function which is executed on main lcore and saves
 *        parsed packets to pcap file
 */

#ifndef __TRANSPORT_THREAD_H
#define __TRANSPORT_THREAD_H

#include "defines.h"
#include "stats.h"
#include "reorder.h"

struct transport_thread_args {
        struct rte_ring *ring_in;		/**< Ring from which transport thread drains mbufs */
        struct rte_reorder_buffer *buffer;	/**< Buffer where mbufs are reordered */
        struct app_stats_transport *stats;      /**< Transport stats */
};


#ifndef PCAP_DUMP
struct pcap_timeval {
        bpf_int32 tv_sec;
        bpf_int32 tv_usec;
};

struct pcap_sf_pkthdr {
        struct pcap_timeval ts;
        bpf_u_int32 caplen;
        bpf_u_int32 len;
        bpf_u_int32 allignment1;
        bpf_u_int32 allignment2;
};
#endif

/**
 * @param args arguments to thread, like communication ring & reorder buffer
 * @return success or failure
 * @brief help function for transport_thread under, transports the whole buffer to the pcap file
 */
static void
transport_buffer(struct transport_thread_args *args);

/**
 * @param args arguments to thread, like communication ring & reorder buffer
 * @return success or failure
 * @brief enques parsed and reordered packets from ring and saves them to the pcap file
 */
int
transport_thread(struct transport_thread_args *args);


extern uint16_t         max_pkts_burst;
extern uint8_t          verbose;
extern volatile uint8_t quit_signal, transport, free_mem;
extern unsigned         mbuf_pool_size_out;
extern struct           rte_mempool *mbuf_pool_out;
#ifdef PCAP_DUMP
        extern pcap_dumper_t *pcap_file_p;
#else
        extern FILE *pcap_file_p;
#endif

#endif /* ! __TRANSPORT_THREAD_H */
