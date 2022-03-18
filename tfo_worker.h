/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** tfo_worker.h for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/


#ifndef TFO_WORKER_H_
#define TFO_WORKER_H_

#include <limits.h>
#include <netinet/in.h>

#include "tfo.h"

#include "linux_jhash.h"
#include "linux_list.h"

#define	min(a,b) ((a) < (b) ? (a) : (b))
#define	max(a,b) ((a) < (b) ? (b) : (a))

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

enum tcp_state {
	TCP_STATE_CLOSED,
	TCP_STATE_SYN,
	TCP_STATE_SYN_ACK,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN1,
	TCP_STATE_FIN2,
	TCP_STATE_TIMED_WAIT,
	TCP_STATE_NONE,
	TCP_STATE_RESET,
	TCP_STATE_BAD,
	TCP_STATE_NUM,
	TFO_STATE_NONE = (uint32_t)~0
};

enum tcp_state_stats {
	TCP_STATE_STAT_OPTIMIZED = TCP_STATE_NUM,
	TCP_STATE_STAT_NUM
};

#define PKT_IN_LIST	((void *)~0)
#define PKT_VLAN_ERR	((void *)(~0 - 1))

#define TFO_FL_OPTIMIZE		0x0001

struct tcp_option {
	uint8_t opt_code;
	uint8_t opt_len;	/* Not present for TCPOPT_EOL and TCPOPT_NOP */
	uint8_t opt_data[0];
} __rte_packed;

struct tcp_timestamp_option {
	uint8_t	opt_code;
	uint8_t opt_len;
	uint32_t ts_val;
	uint32_t ts_ecr;
} __rte_packed;

struct tcp_sack_option {
	uint8_t	opt_code;
	uint8_t opt_len;
	struct sack_edges {
		uint32_t left_edge;
		uint32_t right_edge;
	} edges[0];
} __rte_packed;

/* Packets to process */
struct tfo_pkts {
	struct rte_mbuf		**pkts;
	uint16_t		max_pkts;
	uint16_t		nb_pkts;
};

/* context on packet processing */
struct tfo_pkt_in
{
	struct rte_mbuf		*m;
// The next two should be a union
	struct rte_ipv4_hdr	*ip4h;
	struct rte_ipv6_hdr	*ip6h;
	size_t			pktlen;
	bool			from_priv;

	struct rte_tcp_hdr	*tcp;
	uint32_t		seglen;

	struct timeval		tv;		/* current time for pkt capture */
						/* Remove this - use w->ts */
	uint32_t		ts_val;
	uint32_t		ts_ecr;
	struct tcp_sack_option	*sack_opt;
};


#define TFO_PKT_FL_SENT		0x01
#define TFO_PKT_FL_RESENT	0x02
#define TFO_PKT_FL_FROM_PRIV	0x04

/* buffered packet */
struct tfo_pkt
{
	struct list_head	list;
	struct rte_mbuf		*m;
	union {
		struct rte_ipv4_hdr *ipv4;
		struct rte_ipv6_hdr *ipv6;
	};
	struct rte_tcp_hdr	*tcp;
	uint32_t		seq;
	uint32_t		seglen;
	uint64_t		ns;	/* timestamp in nanosecond */
	uint32_t		ts_val;
	uint16_t		flags;
};



/* tcp flow, only one side */
struct tfo_side
{
	struct list_head	pktlist;	/* struct tfo_pkt, oldest first */

	uint32_t		rcv_nxt;
	uint32_t		snd_una;
	uint32_t		snd_nxt;
	uint32_t		fin_seq;

	uint16_t		snd_win;	/* Last window received, i.e. controls what we can send */
	uint16_t		rcv_win;	/* Last window sent, i.e. controlling what we can receive */
	uint8_t			rcv_ttl;

	/* For RFC7323 timestamp updates */
	uint32_t		latest_ts_val_sent;
	uint32_t		ts_recent;

	/* be able to stop optimization in the middle */
	uint32_t		optim_until_seq;	/* We need a bool to say it is set */

	/* rtt. in milliseconds */
	uint32_t		srtt;
	uint32_t		rttvar;
	uint32_t		rto;

	uint32_t		pktcount;	/* stat */

// Why do we need is_priv?
//	bool			is_priv;
};

/* tcp optimized flow, both sides */
struct tfo
{
	struct tfo_side			priv;
	struct tfo_side			pub;
	uint32_t			idx;	/* in tfo_ctx->f */
	uint32_t			flags;
	struct list_head		list;

	/* periodic tick */
//	struct rb_node			node;
	uint64_t			wakeup_ns;
};


#define TFO_EF_FL_SYN_FROM_PRIV		0x0001
#define TFO_EF_FL_FIN_FROM_PRIV		0x0002
#define TFO_EF_FL_SIMULTANEOUS_OPEN	0x0004
#define TFO_EF_FL_OPTIMIZE		0x0008
#define TFO_EF_FL_SACK			0x0010
#define TFO_EF_FL_TIMESTAMP		0x0020
#define TFO_EF_FL_IPV6			0x0040
#ifdef DEBUG_MEM
#define TFO_EF_FL_USED			0x8000
#endif

#define EF_WIN_SCALE_UNSET		UINT8_MAX

#define TFO_IDX_UNUSED			((uint32_t)~0)

/*
 * existing flow (either optimized or not)
 */
struct tfo_eflow
{
	struct hlist_node	hlist;		/* hash index */
	struct hlist_node	flist;		/* flow or free list */
	uint8_t			state;		/* enum tcp_state */
	union {
		uint8_t		priv_snd_wind_shift;
		uint8_t		pub_rcv_wind_shift;
	};
	union {
		uint8_t		pub_snd_wind_shift;
		uint8_t		priv_rcv_wind_shift;
	};
	uint16_t		flags;
	uint16_t		last_use;
	uint16_t		priv_port;	/* cpu order */
	uint16_t		pub_port;	/* cpu order */
	uint32_t		server_snd_una;
	uint16_t		client_snd_win;
	uint32_t		client_rcv_nxt;
// Why not just use a pointer for tfo_idx?
	uint32_t		tfo_idx;	/* index in w->f */
	union {
		uint32_t	v4;
		struct in6_addr	v6;
	}			pub_addr;
	struct tfo_user		*u;
};


///* YYYY work out best way to handle IPv6
#define TFO_USER_FL_V6		0x0001
#ifdef DEBUG_MEM
#define TFO_USER_FL_USED	0x80000000
#endif

/*
 * user (by its priv ip addr)
 * right now just a placeholder.
 */
struct tfo_user
{
	struct hlist_node	hlist;	/* hash index or free list */
	union {
		uint32_t	v4;
		struct in6_addr	v6;
	}			priv_addr;

//#ifdef DEBUG_MEM
	uint32_t		flags;
//#endif
	uint32_t		flow_n;
	struct hlist_head	flow_list;	/* struct tfo_eflow */
};


/*
 * tcp flow stats, per worker
 */
struct tfo_stats
{
	uint64_t		syn_pkt;
	uint64_t		syn_dup_pkt;
	uint64_t		syn_ack_first_pkt;
	uint64_t		syn_bad_flag_pkt;
	uint64_t		syn_bad_state_pkt;
	uint64_t		syn_bad_pkt;
	uint64_t		syn_on_eflow_pkt;
	uint64_t		syn_simlt_open_pkt;
	uint64_t		syn_ack_pkt;
	uint64_t		syn_ack_dup_pkt;
	uint64_t		syn_ack_bad_pkt;
	uint64_t		syn_ack_on_eflow_pkt;

	uint64_t		fin_pkt;
	uint64_t		fin_dup_pkt;
	uint64_t		fin_unexpected_pkt;

	uint64_t		rst_pkt;
	uint64_t		estb_noflag_pkt;
	uint64_t		estb_ack_pkt;
	uint64_t		estb_push_pkt;
	uint64_t		estb_pushack_pkt;
	uint64_t		syn_state_pkt;
	uint64_t		fin_state_pkt;
	uint64_t		rst_state_pkt;
	uint64_t		bad_state_pkt;

	uint32_t		flow_state[TCP_STATE_STAT_NUM];
};


/*
 * module data
 */
struct tfo_module
{
	struct fn_app			*a;
	struct tfo_worker		**w;
	struct fn_capture_ctx		*pcap;
};


struct tcp_worker {
// Is param used?
	void			*param;

	struct timespec		ts;

#ifdef DEBUG_PKTS
	struct tfo_user		*u;
#endif
	uint32_t		u_use;
	struct hlist_head	u_free;
	struct hlist_head	*hu;	/* key: { user ip } */

//#ifdef DEBUG_PKTS
	struct tfo_eflow	*ef;
//#endif
	uint32_t		ef_use;
	struct hlist_head	ef_free;
	struct hlist_head	*hef;	/* key: { user ip+port, pub ip+port } */
	uint32_t		ef_gc;	/* next garbage collection start point */

//#ifdef DEBUG_PKTS
	struct tfo		*f;
//#endif
	uint32_t		f_use;
	struct list_head	f_free;
//	struct rb_root		f_root;	/* used flows */

#ifdef DEBUG_PKTS
	struct tfo_pkt		*p;
#endif
	uint32_t		p_use;
	uint32_t		p_max_use;
	struct list_head	p_free;

	struct tfo_stats	st;
};


/* global */
extern struct tfo_module *g_tfo;


/* tfo_worker.c */
int tfo_worker_mbuf_in(struct rte_mbuf *m, int from_priv);
void tfo_stats_to_str(const struct tfo_stats *st, char *out);

/* tfo_test.c */
int tfo_self_test(struct tfo_worker *w, int t);



static inline uint32_t
tfo_eflow_v6_hash(const struct tcp_config *c, struct in6_addr *priv, uint16_t priv_port,
		  struct in6_addr *pub, uint16_t pub_port)
{
	uint32_t h;

	h = jhash2(priv->s6_addr32, 4, priv_port) ^
		jhash2(pub->s6_addr32, 4, pub_port);
	return h & c->hef_mask;
}

static inline uint32_t
tfo_eflow_v4_hash(const struct tcp_config *c, uint32_t priv, uint16_t priv_port,
		  uint32_t pub, uint16_t pub_port)
{
	uint32_t h;

	h = priv ^ pub ^ (priv_port | (pub_port << 16));
// PQA - this ignores too many bits
	return h & c->hef_mask;
}


static inline struct tfo_eflow *
tfo_eflow_v6_lookup(const struct tcp_worker *w, struct in6_addr *priv, uint16_t priv_port,
		    struct in6_addr *pub, uint16_t pub_port,
		    uint32_t flow_hash)
{
	struct tfo_eflow *f;

	hlist_for_each_entry(f, &w->hef[flow_hash], hlist) {
		if (f->priv_port == priv_port && f->pub_port == pub_port &&
		    IN6_ARE_ADDR_EQUAL(&f->u->priv_addr.v6, priv) &&
		    IN6_ARE_ADDR_EQUAL(&f->pub_addr.v6, pub)) {
			return f;
		}
	}

	return NULL;
}

static inline struct tfo_eflow *
tfo_eflow_v4_lookup(const struct tcp_worker *w, uint32_t priv, uint16_t priv_port,
		    uint32_t pub, uint16_t pub_port, uint32_t flow_hash)
{
	struct tfo_eflow *f;

	hlist_for_each_entry(f, &w->hef[flow_hash], hlist) {
		if (f->priv_port == priv_port && f->pub_port == pub_port &&
		    pub == f->pub_addr.v4 && priv == f->u->priv_addr.v4) {
			return f;
		}
	}

	return NULL;
}


static inline uint32_t
tfo_user_v6_hash(const struct tcp_config *c, const struct in6_addr *priv)
{
	uint32_t h;

	h = jhash2(priv->s6_addr32, 4, 0);
	return h & c->hu_mask;
}

static inline uint32_t
tfo_user_v4_hash(const struct tcp_config *c, uint32_t priv)
{
	return priv & c->hu_mask;
}

static inline struct tfo_user *
tfo_user_v6_lookup(const struct tcp_worker *w, const struct in6_addr *priv, uint32_t h)
{
	struct tfo_user *u;

	hlist_for_each_entry(u, &w->hu[h], hlist) {
		if ((u->flags & TFO_USER_FL_V6) &&
		    IN6_ARE_ADDR_EQUAL(priv, &u->priv_addr.v6))
			return u;
	}

	return NULL;
}

static inline struct tfo_user *
tfo_user_v6_addr(const struct tcp_config *c, const struct tcp_worker *w, const struct in6_addr *priv)
{
	uint32_t h;

	h = tfo_user_v6_hash(c, priv);
	return tfo_user_v6_lookup(w, priv, h);
}

static inline struct tfo_user *
tfo_user_v4_lookup(const struct tcp_worker *w, uint32_t priv, uint32_t h)
{
	struct tfo_user *u;

	hlist_for_each_entry(u, &w->hu[h], hlist) {
		if (!(u->flags & TFO_USER_FL_V6) && u->priv_addr.v4 == priv)
			return u;
	}

	return NULL;
}

static inline struct tfo_user *
tfo_user_v4_addr(const struct tcp_config *c, const struct tcp_worker *w, uint32_t priv)
{
	uint32_t h;

	h = tfo_user_v4_hash(c, priv);
	return tfo_user_v4_lookup(w, priv, h);
}

static inline uint64_t
timespec_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * 1000000000UL + ts->tv_nsec;
}

static inline uint64_t
packet_timeout(uint64_t sent_ns, uint32_t rto)
{
	return sent_ns + rto * 1000000UL;
}
/*
 * before(), between() and after() are taken from Linux include/net/tcp.h
 *
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 *
 * Note: between(10, 2, 1) == true since 2 <= 10 <= 0x100000001
 *  therefore cannot do between(s1, s2, s3 - 1) for s1 <= s2 < s3
 *  since between_end_ex(1, 2, 2) evaluates to true.
 */

static inline bool before(uint32_t seq1, uint32_t seq2)
{
        return (int32_t)(seq1 - seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

/* is s2 <= s1 <= s3 ? */
static inline bool between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
        return seq3 - seq2 >= seq1 - seq2;
}

/* is s2 <= s1 < s3 ? */
static inline bool between_end_ex(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
        return seq1 != seq3 && between(seq1, seq2, seq3);
}

/* is s2 < s1 <= s3 ? */
static inline bool between_beg_ex(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
        return seq1 != seq2 && between(seq1, seq2, seq3);
}

#endif /* TFO_WORKER_H_ */
