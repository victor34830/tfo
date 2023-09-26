/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** tfo_debug.h for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/


#ifndef TFO_DEBUG_H_
#define TFO_DEBUG_H_

#include "tfo_config.h"

#if defined DEBUG_STRUCTURES ||	\
    defined DEBUG_CHECK_PKTS || \
    defined DEBUG_PKTS || \
    defined DEBUG_TIMERS || \
    defined DEBUG_CHECK_PKTS || \
    defined DEBUG_DELAYED_ACK || \
    defined DEBUG_RACK ||      \
    defined EXPOSE_EFLOW_DUMP || \
    defined DEBUG_TIMER_TREE || \
    defined DEBUG_XMIT_LIST || \
    defined DEBUG_CLEAR_OPTIMIZE || \
    defined DEBUG_BURST || \
    defined DEBUG_RTO || \
    defined DEBUG_TS_SPEED
# define NEED_DUMP_DETAILS
#endif

#include <stdbool.h>
#include <stddef.h>

#ifdef WRITE_PCAP
#include <rte_pcapng.h>
#endif


#include "tfo_worker.h"

#ifdef NEED_DUMP_DETAILS
extern time_ns_t start_ns;
extern thread_local char debug_time_abs[19];
extern thread_local char debug_time_rel[20 + 1 + 9 + 5 + 20 + 1 + 9 + 1];
#endif

void dump_eflow(const struct tfo_eflow *ef);
void dump_details(const struct tcp_worker *w);
void dump_pkt_ctx_mbuf(const struct tfo_pktrx_ctx *tr);
void format_debug_time(void);

#if defined NEED_DUMP_DETAILS || defined DEBUG_MEM || defined DEBUG_PKT_RX
const char *get_state_name(enum tcp_state state);
const char *get_timer_name(enum tfo_timer timer);
#endif

#ifdef DEBUG_STRUCTURES
void do_post_pkt_dump(const struct tcp_worker *w, struct tfo_eflow *ef);
#endif

#ifdef DEBUG_XMIT_LIST
void check_xmit_ts_list(struct tfo_side *fos);
#endif

#ifdef DEBUG_CHECKSUM
bool check_checksum(struct tfo_pkt *pkt, const char *msg);
bool check_checksum_in(struct rte_mbuf *m, const char *msg);
#endif

#ifdef DEBUG_DLSPEED
void update_speed_ring(struct tfo_side *fos, uint64_t howmuch);
void print_dl_speed(struct tfo_side *fos);
#endif

#ifdef DEBUG_DUPLICATE_MBUFS
bool check_mbuf_in_use(struct rte_mbuf *m, struct tcp_worker *w);
#endif

#ifdef DEBUG_TCP_WINDOW
void tfo_debug_print_eflow_window(struct tfo_eflow *ef);
#endif


#ifdef WRITE_PCAP
extern bool save_pcap;
void write_pcap(struct rte_mbuf **bufs, uint16_t nb_buf, enum rte_pcapng_direction direction);
#endif


void tfo_debug_worker_init(void);

#endif
