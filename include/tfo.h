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


/* worker packet statistics */
enum tfo_pkt_state {
	TFO_PKT_INVALID,
	TFO_PKT_HANDLED,
	TFO_PKT_FORWARD,
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

#define TFO_CONFIG_FL_NO_VLAN_CHG	0x01
#define TFO_CONFIG_FL_NO_MAC_CHG	0x02

struct tcp_config {
	void 			(*capture_output_packet)(void *, int, const struct rte_mbuf *, const struct timespec *, int, union tfo_ip_p);
	void 			(*capture_input_packet)(void *, int, const struct rte_mbuf *, const struct timespec *, int, union tfo_ip_p);
	uint16_t		(*tx_burst)(uint16_t, uint16_t, struct rte_mbuf **, uint16_t);
	unsigned		fastpath_time;
	unsigned		option_flags;
	uint32_t		tcp_min_rtt_wlen;	/* In milli-seconds */

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
	void			*params;
	uint16_t		port_id;
	uint16_t		queue_idx;
	uint16_t		public_vlan_tci;
	uint16_t		private_vlan_tci;
	struct			rte_mempool *ack_pool;
};

struct tfo_tx_bufs {
	struct rte_mbuf **m;
	uint8_t		*acks;
	uint16_t	nb_tx;
	uint16_t	max_tx;
	uint16_t	nb_inc;
};

#ifdef DEBUG_CHECK_PKTS
extern void check_packets(const char *);
#endif
#if defined DEBUG_MEMPOOL_INIT || defined DEBUG_ACK_MEMPOOL_INIT
extern void show_mempool(const char *name);
#endif
extern struct tfo_tx_bufs *tcp_worker_mbuf_burst(struct rte_mbuf **, uint16_t, struct timespec *, struct tfo_tx_bufs *);
extern void tcp_worker_mbuf_burst_send(struct rte_mbuf **, uint16_t, struct timespec *);
extern struct tfo_tx_bufs *tcp_worker_mbuf(struct rte_mbuf *, int, struct timespec *, struct tfo_tx_bufs *);
extern void tcp_worker_mbuf_send(struct rte_mbuf *, int, struct timespec *);
extern void tfo_process_timers(const struct timespec *, struct tfo_tx_bufs *);
extern void tfo_process_timers_send(const struct timespec *);
extern void tfo_packet_no_room_for_vlan(struct rte_mbuf *);
extern bool tfo_post_send(struct tfo_tx_bufs *, uint16_t);
extern void tfo_setup_failed_resend(struct tfo_tx_bufs *);
extern uint64_t tcp_worker_init(struct tfo_worker_params *);
extern void tcp_init(const struct tcp_config *);
extern uint16_t tfo_max_ack_pkt_size(void) __attribute__((const));
extern uint16_t tfo_get_mbuf_priv_size(void) __attribute__((const));
#ifdef EXPOSE_EFLOW_DUMP
extern void tfo_eflow_dump(void);
#endif

#endif	/* defined _TFO_H */
