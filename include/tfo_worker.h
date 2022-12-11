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

#include "tfo_config.h"

#include <limits.h>
#include <netinet/in.h>

#include "tfo.h"
#include "tfo_rbtree.h"
#include "win_minmax.h"

#ifdef CONFIG_FOR_CGN
# include <libfbxlist.h>
# include <fmutils.h>
# include <jhash.h>
#else
# include "linux_jhash.h"
# include "linux_list.h"

# define	min(a,b) ((a) < (b) ? (a) : (b))
# define	max(a,b) ((a) < (b) ? (b) : (a))
#endif

/* Make it easy to see when we are converting time units */
#define MSEC_PER_SEC	1000U
#define USEC_PER_SEC	1000000UL
#define NSEC_PER_SEC	1000000000UL
#define USEC_PER_MSEC	1000U
#define NSEC_PER_MSEC	1000000UL
#define NSEC_PER_USEC	1000UL

/* Timeout in ms. RFC2998 states 1 second, but Linux uses 200ms */
#define TFO_TCP_RTO_MIN_MS	200U
#define TFO_TCP_RTO_MAX_MS	(120U * MSEC_PER_SEC)	/* 120 seconds */

/* RFC5681 DupAckTreshold is currently 3 */
#define DUP_ACK_THRESHOLD	3


enum tcp_state {
	TCP_STATE_SYN,
	TCP_STATE_SYN_ACK,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_CLEAR_OPTIMIZE,
	TCP_STATE_NUM,
	TFO_STATE_NONE = (uint8_t)~0
};

enum tcp_state_stats {
	TCP_STATE_STAT_OPTIMIZED = TCP_STATE_NUM,
	TCP_STATE_STAT_NUM
};

#define PKT_IN_LIST	((struct tfo_pkt *)~0)
#define PKT_VLAN_ERR	((struct tfo_pkt *)(~0 - 1))
#ifdef HAVE_DUPLICATE_MBUF_BUG
#define PKT_DUPLICATE_MBUF ((struct tfo_pkt *)(~0 - 2))
#define PKT_MIN_ERR	PKT_DUPLICATE_MBUF
#else
#define PKT_MIN_ERR	PKT_VLAN_ERR
#endif


struct tcp_option {
	uint8_t opt_code;
	uint8_t opt_len;	/* Not present for TCPOPT_EOL and TCPOPT_NOP */
	uint8_t opt_data[];
} __rte_packed;

struct tcp_timestamp_option {
	uint8_t	opt_code;
	uint8_t opt_len;
	uint32_t ts_val;
	uint32_t ts_ecr;
} __rte_packed;

#define MAX_SACK_ENTRIES	4

struct tcp_sack_option {
	uint8_t	opt_code;
	uint8_t opt_len;
	struct sack_edges {
		uint32_t left_edge;
		uint32_t right_edge;
	} edges[];
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
	union tfo_ip_p		iph;
	size_t			pktlen;
	bool			from_priv;

	uint8_t			win_shift;
	struct rte_tcp_hdr	*tcp;
	struct tcp_timestamp_option *ts_opt;
	struct tcp_sack_option	*sack_opt;
	uint16_t		mss_opt;

	uint32_t		seglen;

	struct timeval		tv;		/* current time for pkt capture */
						/* Remove this - use w->ts */
};

/****************************************************************************
 *
 * A packet can be on up to three lists. It will always be on the tfo_side's
 *   pktlist, and uses the list_head list. This list is maintained in order of
 *   the packet's seq.
 *
 * Once a packet has been successfully sent (i.e. rte_eth_tx_burst() has been
 *   called including the packet and it is included in the number of packets
 *   successfully sent), it will be added on the tfo_side's xmit_ts_list,
 *   using the packet's xmit_ts_list list_head. It will be added at the end of
 *   the xmit_ts_list (but before any packets marked as lost). The tfo_side's
 *   last_sent points to the xmit_ts_list of the last entry on the tfo_side's
 *   xmit_ts_list that has been sent iut not lost (i.e. the entry after that,
 *   if it exists  will be marked as lost). The xmit_ts_list is maintained in
 *   order of the latest sent time of the packets, but with any lost entries
 *   at the end.
 *
 * Any packet which fails to be sent when rte_eth_tx_burst() is called will
 *   be added to the global send_failed_list, using the send_failed_list
 *   list_head. This is used for quickly resending packets that failed to be
 *   sent, and once sucessfully sent the packets will be removed from the
 *   global send_failed_list.
 *
 * There are various packet flags that relate to the lists:
 *
 * TFO_PKT_FL_SENT
 *   This flag being set is equivalent to the packet being on the xmit_ts_list
 *
 * TFO_PKT_FL_RESENT
 *   The packet has been resent. This does not relate to being on any queue.
 *
 * TFO_PKT_FL_LOST
 *   RACK (RFC8985) has identified that the packet has been lost since it was
 *   last sent. The packet will be moved to the tail of the xmit_ts_list list.
 *
 * TFO_PKT_FL_QUEUED_SENT
 *   The packet has been added to the tx_bufs that will be sent at the end of
 *   processing the received burst or timeout. After the call to
 *   rte_eth_tx_burst(), this flag will be cleared. The main use of the flag
 *   is for if a packet is queued to be resent, but a subsequent packet in
 *   the received burst acks the packet.
 *
 * Much of the setting and clearing of packet flags and list management is
 *   handled by postprocess_sent_packets() and tfo_packets_not_sent().
 *   When packets are freed (pkt_free() or pkt_mbuf_free()) or their state
 *   changes, it is important that the flags are set/cleared appropriately,
 *   and that and lists are handled appropriately.
 *
 * TFO_PKT_FL_ACKED and TFO_PKT_FL_SACKED are only used while processing the
 *   current received packet, and indicated that the lastest packed ack'd or
 *   sacked the packet. One the processing of the latest received packet is
 *   complete, these flags will be clear again.
 *
 * When a packet is freed, SACK'd or otherwise changes status, it is important
 *   that the flags and list entries are updated consistently.
 *
****************************************************************************/

#define TFO_PKT_FL_SENT		0x01U		/* S */
#define TFO_PKT_FL_RESENT	0x02U		/* R */
#define TFO_PKT_FL_RTT_CALC	0x04U		/* r */
#define TFO_PKT_FL_LOST		0x08U		/* L */
#define TFO_PKT_FL_FROM_PRIV	0x10U		/* P */
#define TFO_PKT_FL_ACKED	0x20U		/* a */
#define	TFO_PKT_FL_SACKED	0x40U		/* s */
#define TFO_PKT_FL_QUEUED_SEND	0x80U		/* Q */

/* We use time_ns_t to make it clearer that the variable is a nsec time */
typedef uint64_t time_ns_t;

/* buffered packet */
struct tfo_pkt
{
	struct list_head	list;
	struct list_head	xmit_ts_list;
	struct list_head	send_failed_list;
	struct rte_mbuf		*m;
/* Change to have:
 * 	uint8_t			ip_ofs;
 * 	uint8_t			tcp_ofs;
 * 	uint8_t			ts_ofs;
 * 	uint8_t			sack_offs;
 * and
 * 	pkt_ipv4(struct tfo_pkt *pkt) { return rte_pktmbuf_mtod_offset(pkt->m, struct rte_ipv4_hdr *, ip_ofs); }
 * 	pkt_ipv6(struct tfo_pkt *pkt) { return rte_pktmbuf_mtod_offset(pkt->m, struct rte_ipv6_hdr *, ip_ofs); }
 * 	pkt_tcp(struct tfo_pkt *pkt) { return rte_pktmbuf_mtod_offset(pkt->m, struct rte_tcp_hdr *, tcp_ofs); }
 * 	pkt_ts(struct tfo_pkt *pkt) { return pkt->ts_offs ? rte_pktmbuf_mtod_offset(pkt->m, struct tcp_timestamp_option *, ts_offs) : NULL; }
 * 	pkt_sack(struct tfo_pkt *pkt) { return pkt->sack_offs ? rte_pktmbuf_mtod_offset(pkt->m, struct tcp_sack_option *, sack_offs) : NULL; }
 */
	union tfo_ip_p		iph;
	struct rte_tcp_hdr	*tcp;
	struct tcp_timestamp_option *ts;
	struct tcp_sack_option *sack;
	uint32_t		seq;
	uint32_t		seglen;
	time_ns_t		ns;	/* timestamp in nanosecond */
	uint16_t		flags;
	uint16_t		rack_segs_sacked;
};

typedef enum tfo_timer {
	TFO_TIMER_NONE,
	TFO_TIMER_RTO,
	TFO_TIMER_PTO,
	TFO_TIMER_REO,
	TFO_TIMER_ZERO_WINDOW,
	TFO_TIMER_KEEPALIVE,
	TFO_TIMER_SHUTDOWN
} tfo_timer_t;

#define TFO_SIDE_FL_RTT_CALC_IN_PROGRESS	0x01	/* RTT calc without timestamps in progress */
#define TFO_SIDE_FL_IN_RECOVERY			0x02
#define TFO_SIDE_FL_ENDING_RECOVERY		0x04
#define	TFO_SIDE_FL_RACK_REORDERING_SEEN	0x08
#define	TFO_SIDE_FL_DSACK_ROUND			0x10
#define	TFO_SIDE_FL_TLP_IN_PROGRESS		0x20
#define	TFO_SIDE_FL_TLP_IS_RETRANS		0x40
#define	TFO_SIDE_FL_NEW_RTT			0x80
#define	TFO_SIDE_FL_FIN_RX			0x100
#define	TFO_SIDE_FL_CLOSED			0x200
#define	TFO_SIDE_FL_RTT_FROM_SYN		0x400
#define TFO_SIDE_FL_TS_CLOCK_OVERFLOW		0x800

#define TFO_TS_NONE				0UL
#define TFO_INFINITE_TS				UINT64_MAX
#define TFO_ACK_NOW_TS				(UINT64_MAX - 1)
#define ack_delayed(xxx)			((xxx)->delayed_ack_timeout > TFO_TS_NONE && (xxx)->delayed_ack_timeout < TFO_ACK_NOW_TS)

#ifdef DEBUG_DLSPEED
/* Size of the download speed history ring. */
#define DLSPEED_HISTORY_SIZE 20

/* The minimum time length of a history sample.  By default, each
   sample is at least 150ms long, which means that, over the course of
   20 samples, "current" download speed spans at least 3s into the
   past.  */
#define DLSPEED_SAMPLE_MIN 150000000UL

/* The time after which the download starts to be considered
   "stalled", i.e. the current bandwidth is not printed and the recent
   download speeds are scratched.  */
#define STALL_START_TIME 5
#endif

/* Forward reference */
struct tfo;

/* tcp flow, only one side */
struct tfo_side
{
	struct tfo_eflow	*ef;

	uint16_t		mss;		/* MSS we can send - only used for RFC5681 */

	struct list_head	pktlist;	/* struct tfo_pkt, oldest first */
	struct list_head	xmit_ts_list;
	struct list_head	*last_sent;	/* Last entry on xmit_ts_list not marked lost */

	uint32_t		rcv_nxt;
	uint32_t		snd_una;
	uint32_t		snd_nxt;
	uint32_t		fin_seq;
#ifdef DEBUG_RELATIVE_SEQ
	uint32_t		first_seq;
#endif
	uint32_t		last_ack_sent;	/* RFC7323 for updating ts_recent */

	uint32_t		vtc_flow;

	uint16_t		snd_win;	/* Last window received, i.e. controls what we can send */
	uint16_t		rcv_win;	/* Last window sent, i.e. controlling what we can receive */
	uint8_t			rcv_ttl;
	uint32_t		last_rcv_win_end;

	uint32_t		cwnd;
	uint32_t		ssthresh;
#ifndef CWND_USE_ALTERNATE
	uint32_t		cum_ack;
#endif

	uint16_t		flags;

	/* RFC2581 fast retransmission */
	uint8_t			dup_ack;

	/* Window shifts. snd/rcv relates to when we use them. */
	uint8_t			snd_win_shift;	/* The window shift we received */
	uint8_t			rcv_win_shift;	/* The window shift we sent */

	/* SACK entries to send */
	struct {
		uint32_t	left_edge;
		uint32_t	right_edge;	/* If right_edge == left_edge the entry is not in use */
	} sack_edges[MAX_SACK_ENTRIES];
	uint8_t			first_sack_entry;
	uint8_t			sack_entries;
	uint16_t		sack_gap;

	/* For RFC7323 timestamp updates */
	uint32_t		ts_recent;	/* In network byte order */
	uint32_t		latest_ts_val;	/* In host byte order - this is the highest ts_val we have received */
#ifdef CALC_TS_CLOCK
	uint32_t		ts_start;	/* Initial ts_val received */
	time_ns_t		ts_start_time;	/* Used to estimate speed of far end's TS clock */
	uint32_t		nsecs_per_tock;	/* Used to avoid TSval overflow */
	time_ns_t		latest_ts_val_time;	/* Time latest_ts_val was set */
	uint32_t		last_ts_val_sent;	/* The latest ts_val sent */
#endif
	uint8_t			keepalive_probes; /* Number of probes remaining before reset the connection */

	/* RFC7323 RTTM calculation */
	uint32_t		pkts_in_flight;
	uint32_t		pkts_queued_send;
	struct minmax		rtt_min;

	/* rtt. in microseconds */
	uint32_t		srtt_us;
	uint32_t		rttvar_us;
	uint32_t		rto_us;

	uint32_t		packet_type;	/* Set when generating ACKs. Update for 464XLAT */

	uint32_t		pktcount;	/* stat */

	/* RFC8985 RACK-TLP */
	time_ns_t		rack_xmit_ts;
	uint32_t		rack_end_seq;
	uint32_t		rack_segs_sacked;
	uint32_t		rack_fack;
	uint32_t		rack_rtt_us;		/* In microseconds */
	uint32_t		rack_reo_wnd_us;	/* In microseconds */
	uint32_t		rack_dsack_round;
	uint8_t			rack_reo_wnd_mult;
	uint8_t			rack_reo_wnd_persist;
	uint32_t		tlp_end_seq;
	uint32_t		tlp_max_ack_delay_us;	// This is a constant?
	uint32_t		recovery_end_seq;

//	time_ns_t		rack_reordering_to;
	tfo_timer_t		cur_timer;
	time_ns_t		timeout;		/* In nanoseconds */
	time_ns_t		delayed_ack_timeout;

#ifdef DEBUG_PKT_DELAYS
	time_ns_t		last_rx_data;
	time_ns_t		last_rx_ack;
#endif

#ifdef DEBUG_DLSPEED
	struct dl_hist {
		struct dl_speed_hist {
			int pos;
			time_ns_t times[DLSPEED_HISTORY_SIZE];
			uint64_t bytes[DLSPEED_HISTORY_SIZE];

			/* The sum of times and bytes respectively, maintained for efficiency. */
			time_ns_t total_time;
			uint64_t total_bytes;
		} hist;

		time_ns_t recent_start;		/* timestamp of beginning of current position. */
		uint64_t recent_bytes;		/* bytes downloaded so far. */

		bool stalled;			/* set when no data arrives for longer than STALL_START_TIME, then reset when new data arrives. */
	} dl;
#endif

// Why do we need is_priv?
//	bool			is_priv;
};

/* tcp optimized flow, both sides */
struct tfo
{
	struct tfo_side			priv;
	struct tfo_side			pub;
	uint32_t			idx;	/* in tfo_ctx->f - this is only a corruption check - remove it */
	struct list_head		list;

	/* periodic tick */
//	struct rb_node			node;
};

/* data in the private area of the mbuf */
struct tfo_mbuf_priv {
	struct tfo_side *fos;
	struct tfo_pkt *pkt;
};


#define TFO_EF_FL_SYN_FROM_PRIV		0x0001
#define TFO_EF_FL_CLOSED		0x0002
#define TFO_EF_FL_SIMULTANEOUS_OPEN	0x0004
#define TFO_EF_FL_STOP_OPTIMIZE		0x0008
#define TFO_EF_FL_SACK			0x0010
#define TFO_EF_FL_TIMESTAMP		0x0020
#define TFO_EF_FL_IPV6			0x0040
#define TFO_EF_FL_DUPLICATE_SYN		0x0080
#ifdef DEBUG_MEM
#define TFO_EF_FL_USED			0x8000
#endif

#define TFO_WIN_SCALE_UNSET		UINT8_MAX

#define TFO_IDX_UNUSED			((uint32_t)~0)

/*
 * existing flow (either optimized or not)
 */
struct tfo_eflow
{
	struct hlist_node	hlist;		/* hash index or free list */
	struct timer_rb_node	timer;
	uint8_t			state;		/* enum tcp_state */
	uint8_t			win_shift;	/* The win_shift in the SYN packet */
	uint16_t		flags;
	uint16_t		priv_port;	/* cpu order */
	uint16_t		pub_port;	/* cpu order */
	uint16_t		client_snd_win;
	uint32_t		server_snd_una;
	uint32_t		client_rcv_nxt;
	uint32_t		client_vtc_flow;
	uint16_t		client_mss;
	uint8_t			client_ttl;
	time_ns_t		idle_timeout;
	time_ns_t		start_time;
// Why not just use a pointer for tfo_idx?
	uint32_t		tfo_idx;	/* index in w->f */
	uint32_t		client_packet_type;
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	}			priv_addr;
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	}			pub_addr;
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


struct tcp_worker
{
	void			*param;

	struct timespec		ts;

//#ifdef DEBUG_PKTS
	struct tfo_eflow	*ef;
//#endif
	uint32_t		ef_use;
	struct hlist_head	ef_free;
	struct hlist_head	*hef;	/* key: { user ip+port, pub ip+port } */

//#ifdef DEBUG_PKTS
	struct tfo		*f;
//#endif
	uint32_t		f_use;
	struct list_head	f_free;

#ifdef DEBUG_PKTS
	struct tfo_pkt		*p;
#endif
	uint32_t		p_use;
	uint32_t		p_max_use;
	struct list_head	p_free;

	struct tfo_stats	st;
};

#define segend(p)	((p)->seq + (p)->seglen)
#define payload_len(p)	((p)->seglen - !!((p)->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG)))

/* Helper definitions for printing times */
#define NSEC_TIME_PRINT_FORMAT			"%" PRIu64 ".%9.9" PRIu64
#define NSEC_TIME_PRINT_PARAMS(time)		((time) == 0 ? 0 : (((time) - start_ns) / NSEC_PER_SEC)), ((time) == 0 ? 0 : (((time) - start_ns) % NSEC_PER_SEC))
#define NSEC_TIME_PRINT_PARAMS_ABS(time)	(time) / NSEC_PER_SEC, (time) % NSEC_PER_SEC
#define TIMESPEC_TIME_PRINT_FORMAT		"%" PRIu64 ".%9.9" PRIu64
#define TIMESPEC_TIME_PRINT_PARAMS(ts)		((timespec_to_ns(ts) - start_ns) / NSEC_PER_SEC), ((timespec_to_ns(ts) - start_ns) % NSEC_PER_SEC)


static inline bool
using_rack(const struct tfo_eflow *ef)
{
	return ef->flags & TFO_EF_FL_SACK;
}

static inline struct rte_ipv4_hdr *
pkt_ipv4(struct tfo_pkt *pkt)
{
	return pkt->iph.ip4h;
}

static inline struct rte_ipv6_hdr *
pkt_ipv6(struct tfo_pkt *pkt)
{
	return pkt->iph.ip6h;
}

static inline struct rte_tcp_hdr *
pkt_tcp(struct tfo_pkt *pkt)
{
	return pkt->tcp;
}

static inline struct tcp_timestamp_option *
pkt_ts(struct tfo_pkt *pkt)
{
	return pkt->ts;
}

static inline struct tcp_sack_option *
pkt_sack(struct tfo_pkt *pkt)
{
	return pkt->sack;
}

static inline uint32_t __attribute__((pure))
tfo_eflow_v6_hash(const struct tcp_config *c, struct in6_addr *priv, uint16_t priv_port,
		  struct in6_addr *pub, uint16_t pub_port)
{
	uint32_t h;

	h = jhash2(priv->s6_addr32, 4, priv_port) ^
		jhash2(pub->s6_addr32, 4, pub_port);
	return h & c->hef_mask;
}

static inline uint32_t //__attribute__((pure))
tfo_eflow_v4_hash(const struct tcp_config *c, uint32_t priv, uint16_t priv_port,
		  uint32_t pub, uint16_t pub_port)
{
	uint32_t h;

	h = priv ^ pub ^ (priv_port | (pub_port << 16));
// PQA - this ignores too many bits
	return h & c->hef_mask;
}


static inline struct tfo_eflow * __attribute__((pure))
tfo_eflow_v6_lookup(const struct tcp_worker *w, struct in6_addr *priv, uint16_t priv_port,
		    struct in6_addr *pub, uint16_t pub_port,
		    uint32_t flow_hash)
{
	struct tfo_eflow *f;

	hlist_for_each_entry(f, &w->hef[flow_hash], hlist) {
		if (f->priv_port == priv_port && f->pub_port == pub_port &&
		    IN6_ARE_ADDR_EQUAL(&f->priv_addr.v6, priv) &&
		    IN6_ARE_ADDR_EQUAL(&f->pub_addr.v6, pub)) {
			return f;
		}
	}

	return NULL;
}

static inline struct tfo_eflow * __attribute__((pure))
tfo_eflow_v4_lookup(const struct tcp_worker *w, uint32_t priv, uint16_t priv_port,
		    uint32_t pub, uint16_t pub_port, uint32_t flow_hash)
{
	struct tfo_eflow *f;

	hlist_for_each_entry(f, &w->hef[flow_hash], hlist) {
		if (f->priv_port == priv_port && f->pub_port == pub_port &&
		    pub == f->pub_addr.v4.s_addr && priv == f->priv_addr.v4.s_addr) {
			return f;
		}
	}

	return NULL;
}

static inline time_ns_t
timespec_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

static inline time_ns_t
packet_timeout(time_ns_t sent_ns, uint32_t rto_us)
{
	return sent_ns + rto_us * NSEC_PER_USEC;
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
