/**
 * @file reorder.c
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Functions used for reordering of packets in ring
 */

#include "reorder.h"

int
reorder_insert(struct rte_reorder_buffer *b, struct rte_mbuf *mbuf)
{
        struct cir_buffer *order_buf = &b->order_buf;
        uint32_t offset;

        static uint8_t seqn_overflow = 0;

        // TODO if seqn number overflowed, export reorder buffer
        if (!seqn_overflow && mbuf->seqn > 1000000) {
                seqn_overflow = 1;
        } else if (seqn_overflow && mbuf->seqn < 100000) {
                seqn_overflow = 0;
                return ENOSPC;
        }

        offset = mbuf->seqn - b->min_seqn;

        if (verbose) printf("Reorder insert to offset %u\n", offset);

        if (offset < (b->order_buf.size-1)) {
                order_buf->entries[offset] = mbuf;
        }
        else {
                rte_errno = ERANGE;
                return -1;
        }

        return 0;
}

void
reorder_to_ready(struct rte_reorder_buffer *b)
{
        struct cir_buffer *order_buf = &b->order_buf,
                        *ready_buf = &b->ready_buf;

        if (verbose) printf("Reorder to ready\n");

        while (((order_buf->head + 1) & order_buf->mask) != order_buf->tail &&
                        ((ready_buf->head + 1) & ready_buf->mask) != ready_buf->tail) {
                /* if we are blocked waiting on a packet, skip it */
                if (order_buf->entries[order_buf->head] == NULL) {
                        order_buf->head = (order_buf->head + 1) & order_buf->mask;
                }

                /* Move all ready entries that fit to the ready_buf */
                while (order_buf->entries[order_buf->head] != NULL) {
                        ready_buf->entries[ready_buf->head] =
                                        order_buf->entries[order_buf->head];

                        order_buf->entries[order_buf->head] = NULL;

                        order_buf->head = (order_buf->head + 1) & order_buf->mask;

                        if (((ready_buf->head + 1) & ready_buf->mask) == ready_buf->tail)
                                break;
                        ready_buf->head = (ready_buf->head + 1) & ready_buf->mask;
                }
        }

        order_buf->head = order_buf->tail = 0;
}
