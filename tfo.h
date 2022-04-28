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


#include <rte_mbuf_core.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <time.h>

//#define DEBUG_MEMPOOL_INIT
//#define DEBUG_ACK_MEMPOOL_INIT


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

#define	TFO_MBUF_PRIV_OFFSET_ALIGN(x)	(((x) + tfo_mbuf_priv_alignment - 1) & ~(tfo_mbuf_priv_alignment - 1))

struct tcp_config {
	void 			(*capture_output_packet)(void *, int, const struct rte_mbuf *, const struct timespec *, int, union tfo_ip_p);
	void 			(*capture_input_packet)(void *, int, const struct rte_mbuf *, const struct timespec *, int, union tfo_ip_p);
	uint16_t		(*tx_burst)(uint16_t, uint16_t, struct rte_mbuf **, uint16_t);
	unsigned		fastpath_time;
	unsigned		slowpath_time;	/* In units of 1ms */
	unsigned		option_flags;

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
	struct rte_mbuf	**m;
	uint16_t	nb_tx;
	uint16_t	max_tx;
	uint16_t	nb_inc;
};

extern const uint8_t tfo_mbuf_priv_alignment;

#if defined DEBUG_MEMPOOL_INIT || defined DEBUG_ACK_MEMPOOL_INIT
extern void show_mempool(const char *name);
#endif
extern struct tfo_tx_bufs *tcp_worker_mbuf_burst(struct rte_mbuf **, uint16_t, struct timespec *, struct tfo_tx_bufs *);
extern void tcp_worker_mbuf_burst_send(struct rte_mbuf **, uint16_t, struct timespec *);
extern struct tfo_tx_bufs *tcp_worker_mbuf(struct rte_mbuf *, int, struct timespec *, struct tfo_tx_bufs *);
extern void tcp_worker_mbuf_send(struct rte_mbuf *, int, struct timespec *);
extern void tfo_garbage_collect(const struct timespec *, struct tfo_tx_bufs *);
extern void tfo_garbage_collect_send(const struct timespec *);
extern void tfo_packet_no_room_for_vlan(struct rte_mbuf *);
extern void tfo_packets_not_sent(struct tfo_tx_bufs *, uint16_t);
extern uint64_t tcp_worker_init(struct tfo_worker_params *);
extern void tcp_init(const struct tcp_config *);
extern uint16_t tfo_max_ack_pkt_size(void);
extern uint16_t tfo_get_mbuf_priv_size(void);

#endif	/* defined _TFO_H */
