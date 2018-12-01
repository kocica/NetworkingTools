/**
 * @file reorder.h
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Functions used for reordering of packets in ring
 */

#ifndef __REORDER_H
#define __REORDER_H

#include "defines.h"
#include "stats.h"

struct cir_buffer {
        unsigned int size;   			/**< Number of entries that can be stored */
        unsigned int mask;   			/**< [buffer_size - 1]: used for wrap-around */
        unsigned int head;   			/**< insertion point in buffer */
        unsigned int tail;   			/**< extraction point in buffer */
        struct rte_mbuf **entries;
} __rte_cache_aligned;


struct rte_reorder_buffer {
        char name[32];
        uint32_t min_seqn;  			/**< Lowest seq. number that can be in the buffer */
        unsigned int memsize; 			/**< memory area size of reorder buffer */
        struct cir_buffer ready_buf; 		/**< temp buffer for dequeued entries */
        struct cir_buffer order_buf; 		/**< buffer used to reorder entries */
        int is_initialized;
} __rte_cache_aligned;


/**
 * @param b reorder buffer to with packets to reorder
 * @brief Moves packets from reorder to ready buffer before exporting
 */
void
reorder_to_ready(struct rte_reorder_buffer *b);

/**
 * @param b reorder buffer to with packets to reorder
 * @param mbuf mbuf to be inserted
 * @return failure of success
 * @brief Stores mbuf to the reorder buffer
 */
int
reorder_insert(struct rte_reorder_buffer *b, struct rte_mbuf *mbuf);


extern uint8_t verbose;


#endif /* ! __REORDER_H */
