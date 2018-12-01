/**
 * @file defines.h
 * @date 23/05/2018
 * @author Filip Kocica <xkocic01@fit.vutbr.cz>
 * @brief Constants used in diagnostic application
 */


#ifndef __DEFINES_H
#define __DEFINES_H

/* Defines which have to take place for correct cross platform
   compilation */
#define RTE_MAX_LCORE 128
#define RTE_CACHE_LINE_SIZE 64
#define RTE_MEMPOOL_CACHE_MAX_SIZE 512
#define RTE_PKTMBUF_HEADROOM 128
#define RTE_MAX_QUEUES_PER_PORT 1024
#define RTE_ETHDEV_QUEUE_STAT_CNTRS 16

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
#include <sys/time.h>
#include <limits.h>

/* Size of input queue */
#define RX_DESC_PER_QUEUE 	1024
/* Implicit burst enque/deque from queue */
#define MAX_PKTS_BURST 		16
/* Implicit size of reorder buffer */
#define REORDER_BUFFER_SIZE 	32768
/* Implicit size of mempool */
#define MBUF_PER_POOL 		1024
/* Implicit cache size */
#define MBUF_POOL_CACHE_SIZE 	256
/* Implicit size of communication ring */
#define RING_SIZE 		32768
/* Max ports on NXP device */
#define NXP_MAX_PORTS 		4
/* Min ports on NXP device */
#define NXP_MIN_PORTS 		1
/* Min lcores required for app */
#define NXP_MIN_LCORES 		2
/* Max size of package packet created in FPGA */
#define PKG_PKT_MAX_SIZE        10000


/**
 * If defined, copying mbufs from linked list to one buffer, then using pcap_dump
 * 
 * else find out size of all mbufs, save header, then save mbufs one by one using fwrite
 */
#define PCAP_DUMP		1

#endif /* ! __DEFINES_H */
