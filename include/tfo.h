/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#ifndef _TFO_H
#define _TFO_H

/*
** tfo.h for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/


#include "tfo_config.h"

#include <rte_mbuf_core.h>
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wsuggest-attribute=pure\"")
#include <rte_mempool.h>
#include <rte_ip.h>
_Pragma("GCC diagnostic pop")
#include <time.h>
#ifdef EXPOSE_EFLOW_DUMP
#include <stdio.h>
#endif

#ifdef CONFIG_FOR_CGN
#include "fn_app.h"
#endif

/* worker packet statistics */
enum tfo_pkt_state {
#ifdef CONFIG_FOR_CGN
	TFO_PKT_INVALID = FN_PKT_STAT_BASE_MAX,
#else
	TFO_PKT_INVALID,
#endif
	TFO_PKT_HANDLED,
	TFO_PKT_FORWARD,
#ifdef CONFIG_FOR_CGN
	TFO_PKT_FWD_OPTIMIZED,
	TFO_PKT_FWD_RETRANSMITTED,
	TFO_PKT_GEN_ACK,
#endif
	TFO_PKT_DROP,
	TFO_PKT_NOT_TCP,
	TFO_PKT_NO_RESOURCE,		/* user/flow max rss reached */

	TFO_PKT_STAT_MAX,
};

struct tcp_timeouts {
	uint16_t		to_syn;
	uint16_t		to_est;
	uint16_t		to_fin;
};

union tfo_ip_p {
	struct rte_ipv4_hdr	*ip4h;
	struct rte_ipv6_hdr	*ip6h;
};

#ifdef DEBUG_PRINT_TO_BUF
#define TFO_CONFIG_FL_BUFFER_KEEP	0x04
#endif
#ifdef DEBUG_STRUCTURES
#define	TFO_CONFIG_FL_DUMP_ALL_EFLOWS	0x08
#endif

struct tcp_config {
	uint16_t		(*tx_burst)(void *, struct rte_mbuf **, uint16_t, int);
	unsigned		fastpath_time;
	unsigned		option_flags;
	uint32_t		tcp_min_rtt_wlen;	/* In milli-seconds */

#ifdef PER_THREAD_LOGS
	const char		*log_file_name_template;
#endif

#ifdef	DEBUG_PRINT_TO_BUF
	unsigned		print_buf_size;		/* Size of circular print buffer in Mb */
#endif

	uint32_t		u_n;
	uint32_t		hu_n;
	uint32_t		hu_mask;
	uint32_t		ef_n;
	uint32_t		hef_n;
	uint32_t		hef_mask;
	uint32_t		f_n;
	uint32_t		p_n;

	/* tcp timeouts config, per port */
	uint16_t		max_port_to;
	struct tcp_timeouts	*tcp_to;

	/* TCP keepalive parameters */
	uint32_t		tcp_keepalive_time;	// Linux default 7200 (2 hours)
	uint32_t		tcp_keepalive_probes;	// Linux default 9
	uint32_t		tcp_keepalive_intvl;	// Linux default 75

	uint64_t		dynflag_priv_mask;
	uint16_t		mbuf_priv_offset;
};

struct tfo_worker_params {
	void			*params;		// opaque data for lib user
	struct			rte_mempool *ack_pool;
};

#ifdef DEBUG_CHECK_PKTS
extern void check_packets(const char *);
#endif
#if defined DEBUG_MEMPOOL_INIT || defined DEBUG_ACK_MEMPOOL_INIT
extern void show_mempool(const char *name);
#endif
extern void tcp_worker_mbuf_burst(struct rte_mbuf **, uint16_t, struct timespec *);
extern void tcp_worker_mbuf(struct rte_mbuf *, int, struct timespec *);
extern void tfo_process_timers(const struct timespec *);
extern uint64_t tcp_worker_init(struct tfo_worker_params *);
extern void tcp_init(const struct tcp_config *);
extern uint16_t tfo_max_ack_pkt_size(void) __attribute__((const));
extern uint16_t tfo_get_mbuf_priv_size(void) __attribute__((const));
#ifdef DEBUG_PRINT_TO_BUF
extern void tfo_printf_dump(const char *);
#endif
#ifdef EXPOSE_EFLOW_DUMP
extern void tfo_eflow_dump(void);
extern void tfo_eflow_dump_fp(FILE *fp);
#endif

#endif	/* defined _TFO_H */
