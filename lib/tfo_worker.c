/*
 * RACK TODO
 *
 * IMMEDIATE
 *   rack_segs_sacked handling when packets acked
 *
 * tlp_send_probe has a problem if resending last packet and
 *   it has been sack'd
 *
 * Check/fix sending dup sacks
 *
 * Work without timestamps
 *
 * Check RFC errors and implementations
 *
 */

/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
**
** tfo_worker.c for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**         Olivier Gournet <ogournet@corp.free.fr>
**
*/

// SEE https://fedoramagazine.org/tcp-window-scaling-timestamps-and-sack/

// Use private area in pktmbuf rather than malloc for tfo_pkt structures
//
// SACK - we must keep data, mark packets as SACK'd, but if get another SACK we must be prepared to un-SACK packets
//	- see https://hal.archives-ouvertes.fr/hal-02549760/document for non-renegable SACK

/* TODOs
 *
 * -9  Check when receive ack that we have packet it relates to (except data with syn - perhaps we should queue syn packets with data, but clear the syn bit and set ack bit. We can
 *       then send them if the data isn't ack'd in the SYN+ACK/ACK packets
 *
 * 0. Check working:
 *   a. Packet queueing
 *   b. RTO calculation
 *   c. packet resending after timeout
 *   d. seq and ack validation correct including window scaling
 *   e. Data with SYNs
 *   f. debug option to dump everything after each packet
 *   g. timers pkt->ts etc
 *
 * -4. Sort out what packets are not forwarded - we must forward ICMP (and inspect for relating to TCP)
 * -3. DPDK code for generating bad packet sequences
 * -1. Timestamp, ack and win updating on send
 * -0.9. Work out our policy for window size
 * 1. Tidy up code
 * 2. Optimize code
 * 2.1 See https://www.hamilton.ie/net/LinuxHighSpeed.pdf:
 *	Order the SACK blocks by seq so walk pktlist once
 *	Walk the SACK holes
 *	Cache pointers for retransmission walk
 *	When number of holes becomes large, cache the SACK entries so walk fewer times
 * 3.1. Option to add timestamps if not there
 * 4. Add selective ACK option when forward SYN
 * 5. Congestion control
 * 6. Tunnelling
 */

/* From Wikipedia - references are in https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 *
 * RFC 0793 - old TCP RFC (superceeded by RFC9293)
 * RFC 1072 - precursor to RFC 7323
 * RFC 1122 - Host Requirements for Internet Hosts, clarified a number of TCP protocol implementation requirements including delayed ack
 * RFC 1185 - precursor to RFC 7323
 * RFC 1191 - Path MTU discovery
 * RFC 1624 - incremental checksum calculation
 * RFC 1948 - defending against sequence number attaacks
 * RFC 1981 - Path MTU discovery for IPv6
 * RFC 2018 - Selective ACK (SACK)
 * RFC 2309 - queue control
 * RFC 2401 -
 * RFC 2460 - IPv6 TCP checksum
 * RFC 2474 -
 * RFC 2581 - congestion control slow start, fast retransmit and fast recovery - superceeded by RFC5681
 * RFC 2675 - header changes (IPv6 jumbograms)
 * RFC 2883 - An Extension to the Selective Acknowledgement (SACK) Option for TCP (DSACK)
 * RFC 2884 - sample results from using ECN
 * RFC 2988 - initial RTO (updated by 6298)
 * RFC 3042 - Limited transmit ?etc
 * RFC 3168 - Explicit Congestion Notification (ECN), a congestion avoidance signaling mechanism.
 * RFC 3390 - initial window sizes (?etc)
 * RFC 3465 - slow start and congestion avoidance
 * RFC 3515 - Performance Enhancing Proxies Intended to Mitigate Link-Related Degradations
 * RFC 3517 - revised by RFC 6675
 * RFC 3540 - further experimental support for ECN
 * RFC 3522 - Eifel detection algorithm
 * RFC 3708 - detection of spurious transmissions
 * RFC 3782 -
 * RFC 4015 - Eifel Response algorithm
 * RFC 4138 - superceeded by RFC 5682
 * RFC 4413 - lists TCP options
 * RFC 4522 - Eifel detection algorithm
 * RFC 4653 - Improving the Robustness of TCP to Non-Congestion Events - experimental
 * RFC 4821 - Packetization layer path MTU discovery
 * RFC 4953 - 7414 p15 - carry on from here
 * RFC 5681 - TCP congestion control
 * RFC 5682 - Forward RTO recovery
 * RFC 5827 - Early Retransmit for TCP and SCTP (experimental)
 * RFC 6093 - Urgent indications
 * RFC 6247 - ? just obsoleting other RFCs
 * RFC 6298 - computing TCPs retransmission timer
 * RFC 6582 - New Reno
 * RFC 6633 - deprecation of ICMP source quench messages
 * RFC 6675 - conservative loss recovery - SACK (use RFC8985 instead)
 * RFC 6691 - TCP Options and MSS
 * RFC 6824 - TCP Extensions for Multipath Operation with Multiple Addresses
 * RFC 6937 - Proportional Rate Reduction for TCP - experimental, but used by Linux
 * RFC 7323 - TCP Extensions for High Performance
 * RFC 7413 - TCP Fast Open
 * RFC 7414 - A list of the 8 required specifications and over 20 strongly encouraged enhancements, includes RFC 2581, TCP Congestion Control.
 * RFC 8312 - ? TCP CUBIC
 * RFC 8985 - The RACK-TLP Loss Detection Algorithm for TCP
		 see also https://datatracker.ietf.org/meeting/100/materials/slides-100-tcpm-draft-ietf-tcpm-rack-01
 * RFC 9293 - TCP

 * BBR congestion control - see Linux code and https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control and https://scholar.google.com/citations?user=cUYzvKgAAAAJ&hl=en

 * Historic (from RFC7805)
 * RFC 813  - Window and acknowledgement strategy in TCP
 * RFC 896  - Nagle's algorithm and Congestion Control

 * Obsolete
 * RFC 1323 - TCP timestamps (on by default for Linux, off for Windows Server), window size scaling etc

The original TCP congestion avoidance algorithm was known as "TCP Tahoe", but many alternative algorithms have since been proposed (including TCP Reno, TCP Vegas, FAST TCP, TCP New Reno, and TCP Hybla).

TCP Veno: TCP Enhancement for Transmission Over Wireless Access Networks (see https://www.ie.cuhk.edu.hk/fileadmin/staff_upload/soung/Journal/J3.pdf)

TCP Interactive (iTCP) [40] is a research effort into TCP extensions that allows applications to subscribe to TCP events and register handler components that can launch applications for various purposes, including application-assisted congestion control.

Multipath TCP (MPTCP) [41][42] is an ongoing effort within the IETF that aims at allowing a TCP connection to use multiple paths to maximize resource usage and increase redundancy. The redundancy offered by Multipath TCP in the context of wireless networks enables the simultaneous utilization of different networks, which brings higher throughput and better handover capabilities. Multipath TCP also brings performance benefits in datacenter environments.[43] The reference implementation[44] of Multipath TCP is being developed in the Linux kernel.[45] Multipath TCP is used to support the Siri voice recognition application on iPhones, iPads and Macs [46]

TCP Cookie Transactions (TCPCT) is an extension proposed in December 2009 to secure servers against denial-of-service attacks. Unlike SYN cookies, TCPCT does not conflict with other TCP extensions such as window scaling. TCPCT was designed due to necessities of DNSSEC, where servers have to handle large numbers of short-lived TCP connections.

tcpcrypt is an extension proposed in July 2010 to provide transport-level encryption directly in TCP itself. It is designed to work transparently and not require any configuration. Unlike TLS (SSL), tcpcrypt itself does not provide authentication, but provides simple primitives down to the application to do that. As of 2010, the first tcpcrypt IETF draft has been published and implementations exist for several major platforms.

Proposed in May 2013, Proportional Rate Reduction (PRR) is a TCP extension developed by Google engineers. PRR ensures that the TCP window size after recovery is as close to the Slow-start threshold as possible.[49] The algorithm is designed to improve the speed of recovery and is the default congestion control algorithm in Linux 3.2+ kernels

Google proposals for sub-millisecond TS granularity etc
https://datatracker.ietf.org/meeting/97/materials/slides-97-tcpm-tcp-options-for-low-latency-00

See https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_for_real_time/7/html/tuning_guide/reducing_the_tcp_delayed_ack_timeout re qucik ack and delayed ack

*/

/*
 * Implementation plan
 *	0. DSACK - RFC2883
 *	1. RFC8985
 *		Replaces loss recovery in RFCs 5681, 6675, 5827 and 4653.
 *		Is compatible with RFCs 6298, 7765, 5682 and 3522.
 *		Does not modify congestion control in RFCs 5681, 6937 (recommended)
 *	1a. RFC7323 - using timestamps - when send a packet send it with latest TS received, or use calculated clock to calculate own
 *	1b. ACK alternate packets with a timeout
 *  2. Congestion control without SACK - ? New Reno. Could use C2TCP or Elastic-TCP. (see Wikipedia TCP_congestion_control)
 *  3. TCP CUBIC is the default for Linux
 *  4. ECN.
 *  5. ? TCP BRRv2
 */

/* DPDK usage performance:
 *
 * 1. Use stack base mempools - see https://www.intel.com/content/www/us/en/developer/articles/technical/optimize-memory-usage-in-multi-threaded-data-plane-development-kit-dpdk-applications.html
 * 2. _thread declares a thread local variable
 *
 */

/* Definitions for optional behaviour */
// TODO - RELEASE_SACKED_PACKETS	// XXX - add code for not releasing and detecting reneging (see Linux code/RFC8985 for detecting)


#include "tfo_config.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <ev.h>
#include <threads.h>
#include <stddef.h>

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wsuggest-attribute=pure\"")
#include <rte_ether.h>
_Pragma("GCC diagnostic pop")
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_net.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#ifdef DEBUG_PKT_TYPES
#include <rte_mbuf_ptype.h>
#endif

#ifndef CONFIG_FOR_CGN
#include "linux_list.h"
#include "util.h"
#endif

#include "tfo_common.h"
#include "tfo_worker.h"
#include "tfo_rbtree.h"
#include "win_minmax.h"
#include "tfo_debug.h"

struct tfo_addr_info
{
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src_addr;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
};


/* THE FOLLOWING NEED TO BE IN thread local storage  (possibly some per node),
 * and we need arrays indexed by numa_node and lcore_id */

/* Global data */
static struct tcp_config global_config_data;
static uint64_t dynflag_queued_send_mask;
static uint32_t g_eflow_dbg_idx;

/* Per NUMA node data */
static struct tcp_config *node_config_copy[RTE_MAX_NUMA_NODES];

/* Per thread data */
thread_local struct tcp_worker worker;
thread_local struct tcp_config *config;
static thread_local unsigned option_flags;
static thread_local struct rte_mempool *ack_pool;
static thread_local uint16_t ack_pool_priv_size;
thread_local time_ns_t now;
thread_local struct rb_root_cached timer_tree;


#ifdef DEBUG_PKT_NUM
static thread_local uint32_t pkt_num = 0;
#endif
thread_local char epfx_buf[32];


/* local forward */
static inline bool tlp_process_ack(uint32_t ack, struct tfo_pktrx_ctx *tr, struct tfo_side *fos);
static inline void add_tx_buf(struct tcp_worker *w, struct rte_mbuf *m, struct tfo_side *s);
#ifdef CONFIG_PACE_TX_PACKETS
static inline bool pace_tx_packets_may_send(struct tfo_side *s, struct rte_mbuf *m);
static inline void pace_tx_unspool(struct tcp_worker *w, struct tfo_side *s);
#endif
static inline bool timer_less(struct rb_node *node_a, const struct rb_node *node_b);
static void timer_update_ef(struct tfo_eflow *ef);




static inline struct rte_mbuf *
get_mbuf_from_priv(struct tfo_mbuf_priv *mp)
{
	return (struct rte_mbuf *)RTE_PTR_SUB((uint8_t *)(mp) - config->mbuf_priv_offset,
					      sizeof (struct rte_mbuf));
}



/****************************************************************************/
/* PACKET ACK/RST GENERATOR, PACKET UPDATE */
/****************************************************************************/

static inline uint16_t
update_checksum(uint16_t old_cksum, void *old_bytes, void *new_bytes, uint16_t len)
{
	uint32_t new_cksum = old_cksum ^ 0xffff;
	uint16_t *old = old_bytes;
	uint16_t *new = new_bytes;

#ifdef DEBUG_CHECKSUM_DETAIL
	uint8_t *old_bytes_u = old_bytes, *new_bytes_u = new_bytes;
	if (len >= 4) {
		printf("update_checksum old %4.4x len %u old_bytes %p [0] %2.2x [1] %2.2x "
		       "[2] %2.2x [3] %2.2x new_bytes %p [0] %2.2x [1] %2.2x [2] %2.2x [3] %2.2x",
		       old_cksum, len, old_bytes_u, old_bytes_u[0], old_bytes_u[1], old_bytes_u[2],
		       old_bytes_u[3], new_bytes_u, new_bytes_u[0], new_bytes_u[1], new_bytes_u[2], new_bytes_u[3]);
	} else if (len == 2) {
		printf("update_checksum old %4.4x len %u old_bytes %p [0] %2.2x [1] %2.2x "
		       " new_bytes %p [0] %2.2x [1] %2.2x",
		       old_cksum, len, old_bytes_u, old_bytes_u[0], old_bytes_u[1],
		       new_bytes_u, new_bytes_u[0], new_bytes_u[1]);
	} else {
		printf("update_checksum old %4.4x len %u\n", old_cksum, len);
	}
#endif

	while (len >= sizeof(*old)) {
		new_cksum += (*old ^ 0xffff) + *new;
		*old++ = *new++;
		len -= sizeof(*old);
	}

	if (unlikely(len)) {
		uint16_t left = 0;
		*(uint8_t *)&left = ((*(uint8_t *)old) ^ 0xff) + *(uint8_t *)new;
		new_cksum += left;

		*(uint8_t *)old = *(uint8_t *)new;
	}

	new_cksum = (new_cksum & 0xffff) + (new_cksum >> 16);
	new_cksum = (new_cksum & 0xffff) + (new_cksum >> 16);

#ifdef DEBUG_CHECKSUM_DETAIL
	printf(" new cksum 0x%4.4x\n", new_cksum ^ 0xffff);
#endif

	return new_cksum ^ 0xffff;
}

static inline uint16_t
remove_from_checksum(uint16_t old_cksum, void *old_bytes, uint16_t len)
{
	uint32_t new_cksum = old_cksum ^ 0xffff;
	uint16_t *old = old_bytes;

	while (len >= sizeof(*old)) {
		new_cksum += (*old ^ 0xffff);
		len -= sizeof(*old);
		old++;
	}

	if (unlikely(len)) {
		uint16_t left = 0;
		*(uint8_t *)&left = ((*(uint8_t *)old) ^ 0xff);
		new_cksum += left;
	}

	new_cksum = (new_cksum & 0xffff) + (new_cksum >> 16);
	new_cksum = (new_cksum & 0xffff) + (new_cksum >> 16);

	return new_cksum ^ 0xffff;
}


/*
 * compute new receive window for 'fos'
 */
static inline bool
set_rcv_win(struct tfo_side *fos, struct tfo_side *foos)
{
	uint32_t win_end;
	uint16_t old_rcv_win = fos->rcv_win;

#ifdef DEBUG_RCV_WIN
	printf("  updating rcv_win from %u, foos: snd_win %u<<%u cwnd %u snd_una %u fos: rcv_win %u",
	       fos->last_rcv_win_end, foos->snd_win, foos->snd_win_shift, foos->cwnd, foos->snd_una, fos->rcv_win);
#endif

	/* The offered receive window size has a significant impact on
	 * throughput. Using the MSS_MULT option below is not good.
	 * ALLOW_MAX may overload TFO. Reflecting the window we receive
	 * on the other side appears to work well.
	 * We may need to be cleverer about this, especially if queues
	 * grow on the radio side. */
#if defined RECEIVE_WINDOW_MSS_MULT
	uint32_t win_size = foos->snd_win << foos->snd_win_shift;

	/* This needs experimenting with to optimise. This is currently calculated as:
	 * min(max(min(send_window, cwnd * 2), 20 * mss), RECEIVE_WINDOW_MSS_MULT * mss) */
	if (win_size > 2 * foos->cwnd)
		win_size = 2 * foos->cwnd;
	if (win_size < 20 * foos->mss)
		win_size = 20 * foos->mss;
	else if (win_size > RECEIVE_WINDOW_MSS_MULT * foos->mss)
		win_size = RECEIVE_WINDOW_MSS_MULT * foos->mss;

	win_end = foos->snd_una + win_size;
#elif defined RECEIVE_WINDOW_ALLOW_MAX
	/* Window size if based on what we have ack'd
	 *   WARNING - this can produce very large send queues. */
	win_end = fos->rcv_nxt + (foos->snd_win << foos->snd_win_shift);
#else
	/* Window size is based on what has been ack'd to us, i.e.
	 * we will only receive packets that we can send immediately. */
	win_end = foos->snd_una + (foos->snd_win << foos->snd_win_shift);
#endif

	/* win_end *cannot* go backward */
	if (after(win_end, fos->last_rcv_win_end))
		fos->last_rcv_win_end = win_end;

	if (after(fos->last_rcv_win_end, fos->rcv_nxt)) {
		fos->rcv_win = (fos->last_rcv_win_end - fos->rcv_nxt) >> fos->rcv_win_shift;

		/* window less than scale factor. but we are not full. */
		/* do something about silly window update */
		if (unlikely(!fos->rcv_win))
			fos->rcv_win = 1;

	} else {
		/* full on the other side */
#ifdef DEBUG_RCV_WIN
		printf(" === FULL ON THE OTHER SIDE (lrwe:%u < rcv_nxt:%u) === ", fos->last_rcv_win_end, fos->rcv_nxt);
#endif
		fos->rcv_win = 0;
		fos->last_rcv_win_end = fos->rcv_nxt;
	}

#ifdef DEBUG_RCV_WIN
	printf(" => %u (shift:%u), last_rcv_win_end %u\n",
	       fos->rcv_win, fos->rcv_win_shift, fos->last_rcv_win_end);
#endif

	/* We want to notify opening or closing the window immediately */
	if (!fos->rcv_win || !old_rcv_win)
		return true;

	/* Don't worry about explicitly reducing the window - we'll cope */
	if (old_rcv_win >= fos->rcv_win)
		return false;

	/* It is only worth explicitly notifying and expansion of the window
	 * if in 1 RTT the window could end up being filled.
	 *
	 * We don't really know the receive rate, so as a compromise, if the space
	 * left is less than 25% of the window and the window is increase by more than
	 * 10% of the current window, notify the update. */
	if (win_end - fos->rcv_nxt < (win_end - foos->snd_una) / 4 &&
	    fos->rcv_win - old_rcv_win >= (old_rcv_win + 9) / 10)
		return true;

	return false;
}


/*
 * how much data can be sent on wire. restricted by the lower of cwnd or rwnd.
 */
static inline uint32_t
get_snd_win_end(const struct tfo_side *fos, uint32_t allow_extra)
{
	uint32_t rwnd, win_end;

	rwnd = fos->snd_win << fos->snd_win_shift;
	win_end = min(rwnd, fos->cwnd + allow_extra);

#ifdef DEBUG_TCP_WINDOW
	/* printf("[%s] get_snd_win %u (rwnd %u, cwnd %d + %d)\n", */
	/*        _spfx(fos), win_end, rwnd, fos->cwnd, allow_extra); */
#endif
	return fos->snd_una + win_end;
}


#ifdef CALC_TS_CLOCK
static inline uint32_t
calc_ts_val(struct tfo_side *fos, struct tfo_side *foos)
{
	uint32_t ts_val = foos->latest_ts_val;
	bool update_cur_timer;

	/* If the TS counter wraps, we will have problems with the calculation of rate, so
	 * if latest_ts_val - ts_start > 2^31, i.e. half way to wrapping, we will just
	 * save the rate in nsecs_per_tock and use that for future calculations.
	 *
	 * We still have a problem if there is no packet in the second half of the timestamp
	 * range, but this:
	 *  a) is exceedingly unlikely
	 *  b) is solved by sending keepalives
	 *
	 * RFC7323 states the maximum clock rate should be 1000 tocks per second, which means
	 * that the TS overflow will occur in 49 days. Even if high speed networks increase the
	 * rate to 1000000 tocks per second (for extremely high speed networks) TS overlow would
	 * take more than 1 hour (and what is the point of having a connection on a high speed
	 * network and not passing any trafic for 1/2 an hour).
	 */
	if (!(foos->flags & TFO_SIDE_FL_TS_CLOCK_OVERFLOW)) {
		/* The TS_val may wrap, so we need to save the rate  and use that
		 * before it does. This still isn't correct if no packet is received
		 * in the second half of the TS window, but we will send a keepalive
		 * to ensure that doesn't happen. */
		if (foos->latest_ts_val - foos->ts_start > (1U << 31)) {
			foos->flags |= TFO_SIDE_FL_TS_CLOCK_OVERFLOW;
		} else if (foos->latest_ts_val_time != foos->ts_start_time &&
			   (before(foos->ts_start + 9, foos->latest_ts_val) ||
			    foos->latest_ts_val_time - foos->ts_start_time >= 10UL * NSEC_PER_SEC)) {
			/* If time has elapsed since the latest ts_val was received, and
			 * there have been at least 10 ts_val tocks since we started or
			 * at least 10 seconds have elapsed, then update ts_val. */

			/* If the current timer is a keepalive and we haven't calculated nsecs_per_tock
			 * before, we may need to update the timeout. */
			update_cur_timer = (!foos->nsecs_per_tock && foos->cur_timer == TFO_TIMER_KEEPALIVE);

			/* Add half divisor to round up as appropriate */
			foos->nsecs_per_tock = (foos->latest_ts_val_time - foos->ts_start_time + (foos->latest_ts_val - foos->ts_start) / 2) / (foos->latest_ts_val - foos->ts_start);

			if (unlikely(update_cur_timer) &&
			    (time_ns_t)foos->nsecs_per_tock * (1U << 31) < foos->timeout_at - now)
				foos->timeout_at = now + (time_ns_t)foos->nsecs_per_tock * (1U << 31);
		}
	}

	if (foos->nsecs_per_tock) {
		ts_val += (now - foos->latest_ts_val_time) / foos->nsecs_per_tock;

		/* Don't let the TS go backwards */
		if (after(ts_val, fos->last_ts_val_sent))
			fos->last_ts_val_sent = ts_val;
	}

	return rte_cpu_to_be_32(fos->last_ts_val_sent);
}
#endif

static inline void
add_sack_option(struct tfo_side *fos, uint8_t *ptr, unsigned sack_blocks, uint32_t *dup_sack)
{
	struct {
		uint8_t b:2;
	} four;
	uint8_t i;
	struct tcp_sack_option *sack_opt;

/* Note: RFC2883 4 (4) is probably not implemented here.
 * Specifically note: an entry is a dup_sack iff:
 *   sack[0].left_edge < ack ||
 *   sack[0] is a subset of sack[1]
 */
	*ptr++ = TCPOPT_NOP;
	*ptr++ = TCPOPT_NOP;
	sack_opt = (struct tcp_sack_option *)(ptr);
	sack_opt->opt_code = TCPOPT_SACK;
	sack_opt->opt_len = sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges);
	if (dup_sack && dup_sack[0] != dup_sack[1]) {
		sack_opt->edges[0].left_edge = rte_cpu_to_be_32(dup_sack[0]);
		sack_opt->edges[0].right_edge = rte_cpu_to_be_32(dup_sack[1]);
		i = 1;
	} else
		i = 0;

	for (four.b = fos->first_sack_entry; i < sack_blocks; i++, four.b++) {
		sack_opt->edges[i].left_edge = rte_cpu_to_be_32(fos->sack_edges[four.b].left_edge);
		sack_opt->edges[i].right_edge = rte_cpu_to_be_32(fos->sack_edges[four.b].right_edge);
	}

#ifdef DEBUG_SEND_DSACK_CHECK
	bool is_dsack;
	bool pkt_dsack;
	bool dsack_err;

	is_dsack = (dup_sack && dup_sack[0] != dup_sack[1]);
	printf("Sending SACK with seq 0x%x ack 0x%x%s fos->sack_entries %u, sack_blocks %u opt_len %u", fos->snd_una, fos->rcv_nxt,
		is_dsack ? " with dSACK" : "", fos->sack_entries, sack_blocks, sack_opt->opt_len);
	for (i = 0; i < (sack_opt->opt_len - sizeof(struct tcp_sack_option)) / sizeof(struct sack_edges); i++)
		printf("  [%u] = 0x%x -> 0x%x", i, (unsigned)rte_be_to_cpu_32(sack_opt->edges[i].left_edge), (unsigned)rte_be_to_cpu_32(sack_opt->edges[i].right_edge));
	pkt_dsack = (before(rte_be_to_cpu_32(sack_opt->edges[0].left_edge), fos->rcv_nxt) ||
		     ((sack_opt->opt_len - sizeof(struct tcp_sack_option)) / sizeof(struct sack_edges) > 1 &&
		      !before(rte_be_to_cpu_32(sack_opt->edges[0].left_edge), rte_be_to_cpu_32(sack_opt->edges[1].left_edge)) &&
		      !after(rte_be_to_cpu_32(sack_opt->edges[0].right_edge), rte_be_to_cpu_32(sack_opt->edges[1].right_edge))));
	dsack_err = ((before(rte_be_to_cpu_32(sack_opt->edges[0].left_edge), fos->rcv_nxt) &&
		      after(rte_be_to_cpu_32(sack_opt->edges[0].right_edge), fos->rcv_nxt)) ||
		     (before(rte_be_to_cpu_32(sack_opt->edges[0].left_edge), rte_be_to_cpu_32(sack_opt->edges[1].left_edge)) &&
		      !before(rte_be_to_cpu_32(sack_opt->edges[0].right_edge), rte_be_to_cpu_32(sack_opt->edges[1].left_edge))) ||
		     (!after(rte_be_to_cpu_32(sack_opt->edges[0].left_edge), rte_be_to_cpu_32(sack_opt->edges[1].right_edge)) &&
		      after(rte_be_to_cpu_32(sack_opt->edges[0].right_edge), rte_be_to_cpu_32(sack_opt->edges[1].right_edge))));
	if (pkt_dsack != is_dsack)
		printf(" DSACK MISMATCH ERROR");
	if (dsack_err)
		printf(" DSACK IMPROPER ERROR");
	printf("\n");
#endif
}

static bool
update_packet_length(struct tfo_pkt *pkt, uint8_t *offs, int8_t len)
{
	uint8_t *pkt_start = rte_pktmbuf_mtod(pkt->m, uint8_t *);
	uint8_t *pkt_end = pkt_start + pkt->m->data_len;
	uint16_t before_len, after_len;
	struct {
		uint8_t data_off;
		uint8_t tcp_flags;
	} new_hdr;
	uint16_t new_len_v4;
	uint16_t ph_old_len_v4;
	uint32_t new_len_v6;
	uint32_t ph_old_len_v6;

	if (!len)
		return true;

	if (len < 0) {
		/* Remove the checksum for what is being removed */
		pkt->tcp->cksum = remove_from_checksum(pkt->tcp->cksum, offs, -len);
		after_len = pkt_end - (offs - len);
	} else
		after_len = pkt_end - offs;
	before_len = offs - pkt_start;

	if (before_len < after_len) {
		/* The header is shorter than the data */
		if (len > 0) {
			uint8_t *new_start = (uint8_t *)rte_pktmbuf_prepend(pkt->m, len);

			if (!new_start) {
				printf("No room to add %d bytes at front of packet %p seq 0x%x\n", len, pkt->m, pkt->seq);
				return false;
			}

			memmove(new_start, pkt_start, offs - pkt_start);
			memset(new_start + (offs - pkt_start), 0, len);
		} else {
			memmove(pkt_start + -len, pkt_start, offs - pkt_start);
			rte_pktmbuf_adj(pkt->m, -len);
		}

		pkt_start -= len;
		/* The following works for IPv6 too */
		pkt->iph.ip4h = (struct rte_ipv4_hdr *)((uint8_t *)pkt->iph.ip4h - len);
		pkt->tcp = (struct rte_tcp_hdr*)((uint8_t *)pkt->tcp - len);
		if (pkt->ts && (uint8_t *)pkt->ts < offs)
			pkt->ts = (struct tcp_timestamp_option *)((uint8_t *)pkt->ts - len);
		if (pkt->sack && (uint8_t *)pkt->sack < offs)
			pkt->sack = (struct tcp_sack_option *)((uint8_t *)pkt->sack - len);
	} else {
		if (len > 0) {
			if (!rte_pktmbuf_append(pkt->m, len)) {
				printf("No room to add %d bytes at end of packet %p seq 0x%x\n", len, pkt->m, pkt->seq);
				return false;
			}
			if (after_len)
				memmove(offs + len, offs, after_len);
			memset(offs, 0, len);
		} else {
			if (after_len)
				memmove(offs, offs - len, after_len);
			rte_pktmbuf_trim(pkt->m, -len);
		}
	}

	/* Update tcp header length */
	new_hdr.tcp_flags = pkt->tcp->tcp_flags;
	new_hdr.data_off = (((pkt->tcp->data_off >> 4) + len / 4) << 4) | (pkt->tcp->data_off & 0x0f);
	pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &pkt->tcp->data_off, &new_hdr, sizeof(new_hdr));

	if (pkt->m->packet_type & RTE_PTYPE_L3_IPV4) {
		/* Update the TCP checksum for the length change in the TCP pseudo header */
		ph_old_len_v4 = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
		new_len_v4 = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start) + len);
		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &ph_old_len_v4, &new_len_v4, sizeof(new_len_v4));

		/* Update IP packet length */
		new_len_v4 = rte_cpu_to_be_16(rte_be_to_cpu_16(pkt->iph.ip4h->total_length) + len);
		pkt->iph.ip4h->hdr_checksum = update_checksum(pkt->iph.ip4h->hdr_checksum, &pkt->iph.ip4h->total_length, &new_len_v4, sizeof(new_len_v4));
	} else {
		/* Update the TCP checksum for the length change in the TCP pseudo header */
		ph_old_len_v6 = rte_cpu_to_be_32(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
		new_len_v6 = rte_cpu_to_be_32(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start) + len);
		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &ph_old_len_v6, &new_len_v6, sizeof(new_len_v6));

		/* Update IP packet length */
		pkt->iph.ip6h->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(pkt->iph.ip6h->payload_len) + len);
	}

	return true;
}

#ifdef DEBUG_CHECK_ADDR
static inline void
check_addr(struct tfo_pkt *pkt, const char *msg)
{
	if (!pkt->m->packet_type & RTE_PTYPE_L3_IPV4)
		return;

	if ((pkt->iph.ip4h->src_addr != rte_cpu_to_be_32(0x0a000003) &&
	     pkt->iph.ip4h->src_addr != rte_cpu_to_be_32(0xc0a80002)) ||
	    (pkt->iph.ip4h->dst_addr != rte_cpu_to_be_32(0x0a000003) &&
	     pkt->iph.ip4h->dst_addr != rte_cpu_to_be_32(0xc0a80002))) {
		printf("%s: WRONG src/dst 0x%x/0x%x\n", msg, rte_be_to_cpu_32(pkt->ipv4->src_addr), rte_be_to_cpu_32(pkt->ipv4->dst_addr));
		printf("Orig packet m %p eh %p ipv4 %p tcp %p ts %p sack %p\n", pkt->m, rte_pktmbuf_mtod(pkt->m, char *), pkt->ipv4, pkt->tcp, pkt->ts, pkt->sack);
		dump_m(pkt->m);

		/* Produce a core dump */
		fflush(stdout);
		int i = *(int *)(1);
		printf("At 0 - %d\n", i);
	}
}
#endif

/* WARNING - with gcc 11.3.1 and using -O2 or above if the final call of check_addr()
 * is not included - i.e. DEBUG_CHECK_ADDR is defined, then we appear to get a compiler
 * error which causes sftp transfers to stall.
 */
_Pragma("GCC push_options")
_Pragma("GCC optimize \"-Og\"")
//static inline bool
static bool
update_sack_option(struct tfo_pkt *pkt, struct tfo_side *fos)
{
	uint8_t sack_blocks, cur_sack_blocks;
	struct {
		uint8_t nop[2];
		uint8_t sack_opt;
		uint8_t sack_len;
		struct sack_edges edges[4];
	} __rte_packed sack = { .nop[0] = TCPOPT_NOP, .nop[1] = TCPOPT_NOP, .sack_opt = TCPOPT_SACK };
	uint8_t *tcp_end;
	struct {
		uint8_t b:2;
	} four;
	uint8_t i;
	int insert_len;

#ifdef DEBUG_CHECK_ADDR
	check_addr(pkt, "uso start");
#endif
	tcp_end = (uint8_t *)pkt->tcp + ((pkt->tcp->data_off & 0xf0) >> 2);

	/* If there is a sack option, there must be at least 12 bytes used */
	if (pkt->sack) {
		/* It should be (cur_sack->opt_len - 2) / sizeof(struct sack_edges)
		 * but integer arithmetic gives the same result */
		cur_sack_blocks = pkt->sack->opt_len / sizeof(struct sack_edges);
	} else
		cur_sack_blocks = 0;

#ifdef DEBUG_CHECK_ADDR
	printf("uso: eh %p ipv4 %p tcp %p ts %p sack %p tcp_end %p fos->sack_entries %u, cur_sack_blocks %u, sack_blocks %d\n",
		rte_pktmbuf_mtod(pkt->m, uint8_t *), pkt->ipv4, pkt->tcp, pkt->ts, pkt->sack, tcp_end, fos->sack_entries,
		cur_sack_blocks, min(fos->sack_entries, 4 - !!(pkt->ts)));
#endif

	if (!fos->sack_entries && !cur_sack_blocks)
		return true;

	sack_blocks = min(fos->sack_entries, 4 - !!(pkt->ts));

	/* XXX The sack option can be repeatedly inserted and removed. We need to ensure that we don't keep
	 * moving the packet earlier and earlier, or later and later until there is no room. */
	if (sack_blocks > cur_sack_blocks) {
		insert_len = (sack_blocks - cur_sack_blocks) * sizeof(struct sack_edges) + (cur_sack_blocks ? 0 : 4);
		if (!update_packet_length(pkt, cur_sack_blocks ? ((uint8_t *)pkt->sack + sizeof(struct tcp_sack_option) + cur_sack_blocks * sizeof(struct sack_edges)) : tcp_end, insert_len))
			return false;
	} else if (sack_blocks < cur_sack_blocks) {
		insert_len = (sack_blocks - cur_sack_blocks) * sizeof(struct sack_edges) - (sack_blocks ? 0 : 4);
		if (!update_packet_length(pkt, sack_blocks ? ((uint8_t *)pkt->sack + sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges)) : ((uint8_t *)pkt->sack - 2), insert_len))
			return false;
	} else
		insert_len = 0;

	if (!sack_blocks) {
		pkt->sack = NULL;

#ifdef DEBUG_CHECK_ADDR
		printf("End uso no new sack: eh %p ipv4 %p tcp %p ts %p sack %p\n", rte_pktmbuf_mtod(pkt->m, uint8_t *), pkt->ipv4, pkt->tcp, pkt->ts, pkt->sack);
		check_addr(pkt, "uso end none");
#endif

		return true;
	}

	if (!pkt->sack)
		pkt->sack = (struct tcp_sack_option *)((pkt->ts ? ((uint8_t *)pkt->ts + sizeof(struct tcp_timestamp_option)) : ((uint8_t *)pkt->tcp + sizeof(struct rte_tcp_hdr))) + 2);

	sack.sack_len = sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges);

	for (i = 0, four.b = fos->first_sack_entry; i < sack_blocks; i++, four.b++) {
		sack.edges[i].left_edge = rte_cpu_to_be_32(fos->sack_edges[four.b].left_edge);
		sack.edges[i].right_edge = rte_cpu_to_be_32(fos->sack_edges[four.b].right_edge);
	}

	/* Update the TCP checksum */
	pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, (uint8_t *)pkt->sack - 2, &sack, sack.sack_len + 2);

#ifdef DEBUG_CHECK_ADDR
	printf("End uso: eh %p ipv4 %p tcp %p ts %p sack %p\n", rte_pktmbuf_mtod(pkt->m, uint8_t *), pkt->ipv4, pkt->tcp, pkt->ts, pkt->sack);
	check_addr(pkt, "uso end with");	// Stalls just without this with gcc 11.3.1 and -O2 or -O3
#endif

#ifdef DEBUG_CHECKSUM
	check_checksum(pkt, "SACK update");
#endif
	return true;
}
_Pragma("GCC pop_options")

static void
_send_ack_pkt(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_pkt *pkt, struct tfo_addr_info *addr,
	      bool to_priv, struct tfo_side *foos, uint32_t *dup_sack,
	      bool same_dirn, bool must_send, bool is_keepalive, bool send_rst)
{
	struct rte_ether_hdr *eh;
	union tfo_ip_p iph;
	struct rte_tcp_hdr *tcp;
	struct tcp_timestamp_option *ts_opt;
	struct tfo_mbuf_priv *mp;
	struct rte_mbuf *m;
	uint8_t *ptr;
	uint16_t pkt_len;
	uint8_t sack_blocks;
	bool do_dup_sack = (dup_sack && dup_sack[0] != dup_sack[1]);
	bool is_ipv6 = !!(ef->flags & TFO_EF_FL_IPV6);

/* CREATE AND KEEP COPY OF ACK FOR SENDING. */
	if (unlikely(!ack_pool)) {
		if (unlikely(!pkt)) {
			/* This should never occur. We can't send an ACK
			 * without receiving a packet first. */
			return;
		}

		ack_pool = pkt->m->pool;
		ack_pool_priv_size = rte_pktmbuf_priv_size(ack_pool);
	}

	/* See Linux commit 5d9f4262b7ea for SACK compression. Delay appears
	 * to be 0.625% of rtt, rather than the stated 5%. */
	if (fos->delayed_ack_timeout == TFO_INFINITE_TS && !must_send && !do_dup_sack) {
		if (!(ef->flags & TFO_EF_FL_SACK)) {
#ifdef DO_QUICKACK
			time_ns_t ato = TFO_ATO_MIN;	// see Linux net/ipv4/tcp_output.c
							// This is from Linux, see pingpong mode
							// icsk->icsk_ack.ato doubles for something

			if (ato > TFO_DELACK_MIN) {
				time_ns_t max_ato = SECS_TO_NSECS / 2;

				if (in_pingpong || ack_pending)
					max_ato = TFO_DELACK_MAX;

				rtt = max(fos->srtt_us / 8, TFO_DELACK_MIN);
				if (rtt < max_ato)
					max_ato = rtt;

				ato = min(ato, max_ato);
			}
			ato = min(ato, socket_delack_max);
#endif

			fos->delayed_ack_timeout = now + NSEC_PER_SEC / 25;
		} else if (fos->tlp_max_ack_delay_us > fos->srtt_us) {
			/* We want to ensure the other end received the ACK before it
			 * times out and retransmits, so reduce the ack delay by
			 * 2 * (srtt / 2). srtt / 2 is best estimate of time for ack
			 * to reach the other end, and allow 2 of those intervals to
			 * be conservative. */
			fos->delayed_ack_timeout = now + (fos->tlp_max_ack_delay_us - fos->srtt_us) * NSEC_PER_USEC;
		}

		if (fos->delayed_ack_timeout != TFO_INFINITE_TS) {
#ifdef DEBUG_DELAYED_ACK
			printf("Delaying ack for %lu us, same_dirn %d\n", (fos->delayed_ack_timeout - now ) / NSEC_PER_USEC, same_dirn);
#endif
			return;
		}
	}
#ifdef DEBUG_DELAYED_ACK
	printf("Not delaying ack_delay ");
	if (fos->delayed_ack_timeout == TFO_INFINITE_TS)
		printf("unset");
	else if (fos->delayed_ack_timeout == TFO_ACK_NOW_TS)
		printf("3WHS ACK");
	else
		printf(NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(fos->delayed_ack_timeout), NSEC_TIME_PRINT_PARAMS_ABS(fos->delayed_ack_timeout - now));
	printf(" must_send %d dup_sack %p %u:%u, same_dirn %d\n",
		must_send, dup_sack, dup_sack ? dup_sack[0] : 1U, dup_sack ? dup_sack[1] : 0, same_dirn);
#endif

	fos->delayed_ack_timeout = TFO_INFINITE_TS;

	m = rte_pktmbuf_alloc(ack_pool);
	if (unlikely(m == NULL)) {
#ifdef DEBUG_NO_MBUF
		printf("ERROR - Unable to ack %u - no mbuf\n", fos->rcv_nxt);
#endif
		return;
	}
	m->port = 0;

	/* initialize private area */
	memset(rte_mbuf_to_priv(m), 0x00, ack_pool_priv_size);
	mp = get_priv_addr(m);
	INIT_LIST_HEAD(&mp->list);
	assert(mp->pkt == NULL);
	m->ol_flags = to_priv ? config->dynflag_priv_mask : 0;

	/* This will need addressing when we implement 464XLAT */
	m->packet_type = fos->packet_type;

	if ((fos->sack_entries || do_dup_sack))
		sack_blocks = min(fos->sack_entries + !!do_dup_sack, 4 - !!(ef->flags & TFO_EF_FL_TIMESTAMP));
	else
		sack_blocks = 0;

#ifdef DEBUG_DUP_SACK_SEND
	if (do_dup_sack)
		printf("Sending D-SACK 0x%x -> 0x%x\n", dup_sack[0], dup_sack[1]);
#endif

	pkt_len = sizeof (struct rte_ether_hdr) +
		   (is_ipv6 ? sizeof(struct rte_ipv6_hdr) : sizeof (struct rte_ipv4_hdr)) +
		   sizeof (struct rte_tcp_hdr) +
		   (ef->flags & TFO_EF_FL_TIMESTAMP ? sizeof(struct tcp_timestamp_option) + 2 : 0) +
		   (sack_blocks ? (sizeof(struct tcp_sack_option) + 2 + sizeof(struct sack_edges) * sack_blocks) : 0);

	eh = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, pkt_len);

	eh->ether_type = rte_cpu_to_be_16(is_ipv6 ? RTE_ETHER_TYPE_IPV6 : RTE_ETHER_TYPE_IPV4);
	iph.ip4h = (struct rte_ipv4_hdr *)(eh + 1);

	if (!is_ipv6) {
		iph.ip4h->version_ihl = 0x45;
		iph.ip4h->type_of_service = 0;
iph.ip4h->type_of_service = 0x10;
		iph.ip4h->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof (*eh));
// See RFC6864 re identification
		iph.ip4h->packet_id = 0;
// A random!! number
iph.ip4h->packet_id = rte_cpu_to_be_16(now);
iph.ip4h->packet_id = 0x3412;
		iph.ip4h->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
		iph.ip4h->time_to_live = foos->rcv_ttl;
		iph.ip4h->next_proto_id = IPPROTO_TCP;
		iph.ip4h->hdr_checksum = 0;
		if (unlikely(addr)) {
			iph.ip4h->src_addr = addr->src_addr.v4.s_addr;
			iph.ip4h->dst_addr = addr->dst_addr.v4.s_addr;
		} else if (likely(!same_dirn)) {
			iph.ip4h->src_addr = pkt->iph.ip4h->dst_addr;
			iph.ip4h->dst_addr = pkt->iph.ip4h->src_addr;
		} else {
			iph.ip4h->src_addr = pkt->iph.ip4h->src_addr;
			iph.ip4h->dst_addr = pkt->iph.ip4h->dst_addr;
		}
// Checksum offload?
		iph.ip4h->hdr_checksum = rte_ipv4_cksum(iph.ip4h);
// Should we copy IPv4 options ?

		tcp = (struct rte_tcp_hdr *)(iph.ip4h + 1);
	} else {
		iph.ip6h->vtc_flow = fos->vtc_flow;
		iph.ip6h->payload_len = rte_cpu_to_be_16(
					sizeof (struct rte_tcp_hdr) +
					(ef->flags & TFO_EF_FL_TIMESTAMP ? sizeof(struct tcp_timestamp_option) + 2 : 0) +
					(sack_blocks ? (sizeof(struct tcp_sack_option) + 2 + sizeof(struct sack_edges) * sack_blocks) : 0));
		iph.ip6h->proto = IPPROTO_TCP;
		iph.ip6h->hop_limits = foos->rcv_ttl;
		if (unlikely(addr)) {
			memcpy(iph.ip6h->src_addr, &addr->src_addr.v6, sizeof(iph.ip6h->src_addr));
			memcpy(iph.ip6h->dst_addr, &addr->dst_addr.v6, sizeof(iph.ip6h->dst_addr));
		} else if (likely(!same_dirn)) {
			memcpy(iph.ip6h->src_addr, pkt->iph.ip6h->dst_addr, sizeof(iph.ip6h->src_addr));
			memcpy(iph.ip6h->dst_addr, pkt->iph.ip6h->src_addr, sizeof(iph.ip6h->dst_addr));
		} else {
			memcpy(iph.ip6h->src_addr, pkt->iph.ip6h->src_addr, sizeof(iph.ip6h->src_addr));
			memcpy(iph.ip6h->dst_addr, pkt->iph.ip6h->dst_addr, sizeof(iph.ip6h->dst_addr));
		}

		tcp = (struct rte_tcp_hdr *)(iph.ip6h + 1);
	}

	if (unlikely(addr)) {
		tcp->src_port = addr->src_port;
		tcp->dst_port = addr->dst_port;
	} else if (likely(!same_dirn)) {
		tcp->src_port = pkt->tcp->dst_port;
		tcp->dst_port = pkt->tcp->src_port;
	} else {
		tcp->src_port = pkt->tcp->src_port;
		tcp->dst_port = pkt->tcp->dst_port;
	}
	tcp->sent_seq = rte_cpu_to_be_32(fos->snd_nxt - !!is_keepalive);
	tcp->recv_ack = rte_cpu_to_be_32(fos->rcv_nxt);
	tcp->data_off = 5 << 4;
	if (unlikely(send_rst))
		tcp->tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
	else
		tcp->tcp_flags = RTE_TCP_ACK_FLAG;
	set_rcv_win(fos, foos);
	tcp->rx_win = rte_cpu_to_be_16(fos->rcv_win);
	tcp->cksum = 0;
	tcp->tcp_urp = 0;

	/* Point to end of tcp header */
	ptr = (uint8_t *)(tcp + 1);

	/* Need tcp options - timestamp and SACK */
	if (ef->flags & TFO_EF_FL_TIMESTAMP) {
		*(uint32_t *)ptr = rte_cpu_to_be_32(TCPOPT_TSTAMP_HDR);
		ts_opt = (struct tcp_timestamp_option *)(ptr + 2);
#ifdef CALC_TS_CLOCK
		ts_opt->ts_val = calc_ts_val(fos, foos);
#else
		ts_opt->ts_val = rte_cpu_to_be_32(foos->latest_ts_val);
#endif
		ts_opt->ts_ecr = fos->ts_recent;
		tcp->data_off += ((1 + 1 + TCPOLEN_TIMESTAMP) / 4) << 4;
		ptr += sizeof(struct tcp_timestamp_option) + 2;

		/* For ts_recent updates */
		fos->last_ack_sent = fos->rcv_nxt;
	}

	if (sack_blocks) {
		add_sack_option(fos, ptr, sack_blocks, dup_sack);
		tcp->data_off += ((1 + 1 + sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges)) / 4) << 4;
	}

// Checksum offload?
	if (ef->flags & TFO_EF_FL_IPV6)
		tcp->cksum = rte_ipv6_udptcp_cksum(iph.ip6h, tcp);
	else
		tcp->cksum = rte_ipv4_udptcp_cksum(iph.ip4h, tcp);

#ifdef DEBUG_ACK_PKT_LIST
	bool sack_err = false;

	printf("Sending ack %p seq 0x%x ack 0x%x len %u", m, fos->snd_nxt, fos->rcv_nxt, m->data_len);
	if (ef->flags & TFO_EF_FL_TIMESTAMP)
		printf(" ts_val %1$u (0x%1$x) ts_ecr %2$u (0x%2$x)", foos->latest_ts_val, rte_be_to_cpu_32(fos->ts_recent));
	printf(" packet_type 0x%x\n", m->packet_type);
	if (ef->flags & TFO_EF_FL_SACK) {
		if (!sack_blocks)
			printf("no sack_blocks");
		else {
			printf("\tsack_blocks %u", sack_blocks);
			if (sack_blocks != (ptr[3] - 2 ) / sizeof(struct sack_edges))
				printf(" (%lu)", (ptr[3] - 2 ) / sizeof(struct sack_edges));
			for (unsigned i = 0; i < sack_blocks; i++) {
				if ((i || !do_dup_sack) &&
				    before(rte_be_to_cpu_32(*(uint32_t *)(ptr + 4 + i * sizeof(struct sack_edges))), fos->rcv_nxt))
					sack_err = true;

				printf(" 0x%x->0x%x", rte_be_to_cpu_32(*(uint32_t *)(ptr + 4 + i * sizeof(struct sack_edges))),
							rte_be_to_cpu_32(*(uint32_t *)(ptr + 4 + i * sizeof(struct sack_edges) + 4)));
				if (!i && do_dup_sack)
					printf("*");
			}
			if (sack_err)
				printf(" ERROR");
		}
		printf("\n");

	}
#endif

#ifdef DEBUG_SACK_VERIFY
	if (fos->sack_entries) {
		bool sack_error = false;

		for (unsigned entry = fos->first_sack_entry, i = 0; i < fos->sack_entries; i++, entry = (entry + 1) % MAX_SACK_ENTRIES) {
			if (!before(fos->sack_edges[entry].left_edge, fos->sack_edges[entry].right_edge)) {
				printf("entry %u error 1 ", entry);
				sack_error = true;
			} else if (!after(fos->sack_edges[entry].right_edge, fos->rcv_nxt)) {
				printf("entry %u error 2 ", entry);
				sack_error = true;
			}

			/* We could also check we have received all the packets */
		}

		if (sack_error)
			printf("SACK ERROR\n");
	}
#endif

	add_tx_buf(w, m, fos);

#ifdef DEBUG_PKT_TX
	printf("[%s] ACK_TX, seq:%u(%u) ack:%u(%u) tcp.rx_win:%u\n",
	       _spfx(fos), rte_be_to_cpu_32(tcp->sent_seq), rte_be_to_cpu_32(tcp->sent_seq) - foos->first_seq,
	       rte_be_to_cpu_32(tcp->recv_ack), rte_be_to_cpu_32(tcp->recv_ack) - fos->first_seq,
	       rte_be_to_cpu_16(tcp->rx_win));
#endif
}

static inline void
_send_ack_pkt_in(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, const struct tfo_pktrx_ctx *tr,
		bool to_priv, struct tfo_side *foos, uint32_t *dup_sack, bool same_dirn)
{
	struct tfo_pkt pkt;

	pkt.m = tr->m;
	pkt.iph = tr->iph;
	pkt.tcp = tr->tcp;
	pkt.flags = tr->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;

	_send_ack_pkt(w, ef, fos, &pkt, NULL, to_priv, foos, dup_sack, same_dirn, true, false, false);
}

static inline void
generate_ack_rst(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, bool is_keepalive, bool send_rst)
{
// Change send_ack_pkt to make up address if pkt == NULL
	struct tfo_addr_info addr;

	if (fos == fos->ef->pub) {
		if (ef->flags & TFO_EF_FL_IPV6) {
			addr.src_addr.v6 = ef->priv_addr.v6;
			addr.dst_addr.v6 = ef->pub_addr.v6;
		} else {
			addr.src_addr.v4.s_addr = rte_cpu_to_be_32(ef->priv_addr.v4.s_addr);
			addr.dst_addr.v4.s_addr = rte_cpu_to_be_32(ef->pub_addr.v4.s_addr);
		}
		addr.src_port = rte_cpu_to_be_16(ef->priv_port);
		addr.dst_port = rte_cpu_to_be_16(ef->pub_port);
	} else {
		if (ef->flags & TFO_EF_FL_IPV6) {
			addr.src_addr.v6 = ef->pub_addr.v6;
			addr.dst_addr.v6 = ef->priv_addr.v6;
		} else {
			addr.src_addr.v4.s_addr = rte_cpu_to_be_32(ef->pub_addr.v4.s_addr);
			addr.dst_addr.v4.s_addr = rte_cpu_to_be_32(ef->priv_addr.v4.s_addr);
		}
		addr.src_port = rte_cpu_to_be_16(ef->pub_port);
		addr.dst_port = rte_cpu_to_be_16(ef->priv_port);
	}

#ifdef DEBUG_DELAYED_ACK
	printf("Sending %s 0x%x\n", is_keepalive ? "keepalive ACK" : send_rst ? "RST" : "delayed ACK", fos->rcv_nxt);
#endif
	_send_ack_pkt(w, ef, fos, NULL, &addr, fos == ef->priv, foos, NULL, false, true, is_keepalive, send_rst);
}

static inline void
generate_rst(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos)
{
	/* Send an RST packet */
	generate_ack_rst(w, ef, fos, foos, false, true);
}

static inline void
send_keepalive(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos)
{
#ifdef DEBUG_KEEPALIVES
	printf("[%s] send_keepalive: probes %d\n", _spfx(fos), fos->keepalive_probes);
#endif

	if (!fos->keepalive_probes) {
		/* The connection is dead, send RSTs */
		generate_rst(w, ef, fos, foos);
		generate_rst(w, ef, foos, fos);

		/* will free on next timer round */
		ef->idle_timeout = now;
#ifdef DEBUG_FLOW
		printf("[%s] from keepalive: will free using idle_timeout\n", _epfx(ef, fos));
#endif

	} else {
		fos->keepalive_probes--;

		generate_ack_rst(w, ef, fos, foos, true, false);
	}
}


/*
 * remove a packet from xmit list.
 * also remove from immediate send queue, if it was queued.
 */
static inline void
_pkt_remove_from_flight(struct tfo_side *fos, struct tfo_pkt *pkt)
{
	struct tfo_mbuf_priv *mp;

	assert(pkt->m != NULL);

	if (pkt->flags & TFO_PKT_FL_QUEUED_SEND) {
		mp = get_priv_addr(pkt->m);
		assert(!list_empty(&mp->list));
		list_del_init(&mp->list);
		rte_pktmbuf_refcnt_update(pkt->m, -1);
		pkt->flags &= ~TFO_PKT_FL_QUEUED_SEND;
		fos->pkts_queued_send--;
#ifdef DEBUG_PKT_REFCNT
		printf("[%s] refcnt: remove m %p from xmit_list, m->refcnt %d\n",
		       _spfx(fos), pkt->m, rte_mbuf_refcnt_read(pkt->m));
#endif
	}

	if (list_is_queued(&pkt->xmit_ts_list)) {
		if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_LOST)) == TFO_PKT_FL_SENT) {
			fos->pkts_in_flight--;
#ifdef DEBUG_IN_FLIGHT
			printf("[%s] pkt_remove_from_flight(%u) pkts_in_flight-- => %u\n",
			       _spfx(fos), pkt->seq, fos->pkts_in_flight);
#endif
		}

		if (&pkt->xmit_ts_list == fos->last_sent)
			fos->last_sent = pkt->xmit_ts_list.prev;

		list_del_init(&pkt->xmit_ts_list);
	}

	if (fos->tlp_highest_sent_pkt == pkt)
		fos->tlp_highest_sent_pkt = NULL;

	pkt->flags &= ~TFO_PKT_FL_LOST;
}


/*
 * free pkt, return to worker's free list.
 */
static void
pkt_free(struct tcp_worker *w, struct tfo_side *fos, struct tfo_pkt *pkt)
{
#if defined DEBUG_MEMPOOL || defined DEBUG_ACK_MEMPOOL
	printf("pkt_free m %p refcnt %u seq %u\n", pkt->m, pkt->m ? rte_mbuf_refcnt_read(pkt->m) : ~0U, pkt->seq);
	show_mempool("packet_pool_0");
#endif

	/* We might have already freed the mbuf if using SACK */
	if (pkt->m != NULL) {
		_pkt_remove_from_flight(fos, pkt);

#ifdef DEBUG_PKT_REFCNT
		/* it may happen with some nic drivers (eg. mlx5) that may
		 * free tx packets later */
		struct rte_mbuf *m = rte_pktmbuf_prefree_seg(pkt->m);
		if (likely(m != NULL)) {
			rte_mbuf_raw_free(m);
		} else {
			printf("[%s] refcnt: packet %u mbuf %p not freed!\n",
			       _spfx(fos), pkt->seq, pkt->m);
		}
#else
		NO_INLINE_WARNING(rte_pktmbuf_free(pkt->m));
#endif
	} else {
		assert(list_empty(&pkt->xmit_ts_list));
	}

	list_move(&pkt->list, &w->p_free);

	--w->p_use;
	--fos->pktcount;
	fos->rack_total_segs_sacked -= pkt->rack_segs_sacked;

#ifdef DEBUG_RACK_SACKED
	if (pkt->rack_segs_sacked)
		printf("pkt_free(seq:%u) decremented fos->rack_total_segs_sacked by %u to %u\n",
		       pkt->seq, pkt->rack_segs_sacked, fos->rack_total_segs_sacked);
#endif

#ifdef DEBUG_MEMPOOL
	printf("After:\n");
	show_mempool("packet_pool_0");
#endif
#ifdef DEBUG_ACK_MEMPOOL
	show_mempool("ack_pool_0");
#endif
}


/*
 * free pkt mbuf, while keeping some pkt data (sacked packets).
 */
static inline void
pkt_free_mbuf(struct tfo_side *fos, struct tfo_pkt *pkt)
{
#if defined DEBUG_MEMPOOL || defined DEBUG_ACK_MEMPOOL
	printf("pkt_free_mbuf m %p refcnt %u seq 0x%x\n", pkt->m, pkt->m ? rte_mbuf_refcnt_read(pkt->m) : ~0U, pkt->seq);
	show_mempool("packet_pool_0");
#endif

	_pkt_remove_from_flight(fos, pkt);

#ifdef DEBUG_PKT_REFCNT
	struct rte_mbuf *m = rte_pktmbuf_prefree_seg(pkt->m);
	if (likely(m != NULL)) {
		rte_mbuf_raw_free(m);
	} else {
		printf("[%s] refcnt: packet %u mbuf %p (only) not freed!\n",
		       _spfx(fos), pkt->seq, pkt->m);
	}
#else
	NO_INLINE_WARNING(rte_pktmbuf_free(pkt->m));
#endif

	pkt->m = NULL;

	pkt->iph.ip4h = NULL;
	pkt->tcp = NULL;
	pkt->ts = NULL;
	pkt->sack = NULL;
}


/*
 * Called on first SYN of flow (i.e. no ACK)
 */
static struct tfo_eflow *
_eflow_alloc(struct tcp_worker *w, uint32_t h)
{
	struct tfo_eflow *ef;

	if (unlikely(hlist_empty(&w->ef_free)))
		return NULL;

	ef = hlist_entry(w->ef_free.first, struct tfo_eflow, hlist);

#ifdef DEBUG_MEM
	if (ef->flags)
		printf("Allocating eflow %p with flags 0x%x\n", ef, ef->flags);
	ef->flags = TFO_EF_FL_USED;
	if (ef->state != TFO_STATE_NONE)
		printf("Allocating eflow %p in state %s\n", ef, get_state_name(ef->state));
	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		printf("Allocating eflow %p with tfo %u\n", ef, ef->tfo_idx);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}
#endif

	ef->dbg_idx = __sync_add_and_fetch(&g_eflow_dbg_idx, 1);
	ef->priv = NULL;
	ef->pub = NULL;
	ef->state = TCP_STATE_SYN;
	ef->win_shift = TFO_WIN_SCALE_UNSET;
	ef->client_mss = TCP_MSS_DEFAULT;

	__hlist_del(&ef->hlist);
	hlist_add_head(&ef->hlist, &w->hef[h]);

	RB_CLEAR_NODE(&ef->timer.node);

	++w->ef_use;
	++w->st.flow_state[ef->state];

#ifdef DEBUG_FLOW
	printf("[%s] eflow_alloc\n", _epfx(ef, NULL));
#endif

	return ef;
}

static void
_eflow_free(struct tcp_worker *w, struct tfo_eflow *ef)
{
#ifdef DEBUG_FLOW
	printf("[%s] eflow_free flags 0x%x, state %s\n", _epfx(ef, NULL),
	       ef->flags, get_state_name(ef->state));
#endif

	if (ef->priv != NULL) {
		struct tfo_pkt *pkt, *pkt_tmp;

		/* del pkt lists */
		list_for_each_entry_safe(pkt, pkt_tmp, &ef->priv->pktlist, list)
			pkt_free(w, ef->priv, pkt);
		list_for_each_entry_safe(pkt, pkt_tmp, &ef->pub->pktlist, list)
			pkt_free(w, ef->pub, pkt);

		list_add(&ef->priv->flow_list, &w->f_free);
		list_add(&ef->pub->flow_list, &w->f_free);
		w->f_use -= 2;
	}

	if (!RB_EMPTY_NODE(&ef->timer.node)) {
#ifdef DEBUG_TIMER_TREE
		if ((!rb_parent(&ef->timer.node) && timer_tree.rb_root.rb_node != &ef->timer.node) ||
		    (rb_parent(&ef->timer.node) &&
		     rb_parent(&ef->timer.node)->rb_left != &ef->timer.node &&
		     rb_parent(&ef->timer.node)->rb_right != &ef->timer.node)) {
			dump_eflow(ef);
			if (!rb_parent(&ef->timer.node))
				printf("eflow free timer rb tree error, ef %p timer.node %p timer_tree.rb_root.rb_node %p leftmost %p no parent ERROR\n", ef, &ef->timer.node, timer_tree.rb_root.rb_node, timer_tree.rb_leftmost);
			else
				printf("eflow free timer rb tree error, ef %p, timer.node %p parent %p, left %p right %p ERROR\n", ef, &ef->timer.node,
					rb_parent(&ef->timer.node), rb_parent(&ef->timer.node)->rb_left, rb_parent(&ef->timer.node)->rb_right);
		}
#endif
		rb_erase_cached(&ef->timer.node, &timer_tree);
		RB_CLEAR_NODE(&ef->timer.node);
	}

	--w->ef_use;
	--w->st.flow_state[ef->state];
	ef->state = TFO_STATE_NONE;

#ifdef DEBUG_MEM
	if (!(ef->flags & TFO_EF_FL_USED))
		printf("[%s] ERROR freeing eflow %p without used flag set\n",
		       _epfx(ef, NULL), ef);
#endif

	ef->flags = 0;

	__hlist_del(&ef->hlist);
	hlist_add_head(&ef->hlist, &w->ef_free);
}

/* called in packet rx and timer context, before use */
static void
_eflow_before_use(struct tfo_eflow *ef)
{
	if (ef->priv != NULL) {
		ef->priv->flags &= ~(TFO_SIDE_FL_ACKED_DATA | TFO_SIDE_FL_ENDING_RECOVERY);
		ef->pub->flags &= ~(TFO_SIDE_FL_ACKED_DATA | TFO_SIDE_FL_ENDING_RECOVERY);
	}
}


static inline void
eflow_update_idle_timeout(struct tfo_eflow *ef)
{
	unsigned port_index;

	/* Use the port on the "server" side */
	port_index = (ef->flags & TFO_EF_FL_SYN_FROM_PRIV) ? ef->pub_port : ef->priv_port;
	if (port_index > config->max_port_to)
		port_index = 0;

	if (ef->state == TCP_STATE_ESTABLISHED) {
		/* If we have received a FIN from either side, use the FIN timer */
		if ((ef->priv->flags | ef->pub->flags) & TFO_SIDE_FL_FIN_RX)
			ef->idle_timeout = now + config->tcp_to[port_index].to_fin * NSEC_PER_SEC;
		else
			ef->idle_timeout = now + config->tcp_to[port_index].to_est * NSEC_PER_SEC;
	} else {
		/* We must be doing the 3WHS */
		ef->idle_timeout = now + config->tcp_to[port_index].to_syn * NSEC_PER_SEC;
	}
}

static bool
set_tcp_options(struct tfo_pktrx_ctx *tr, struct tfo_eflow *ef)
{
	unsigned opt_off = sizeof(struct rte_tcp_hdr);
	uint8_t opt_size = (tr->tcp->data_off & 0xf0) >> 2;
	uint8_t *opt_ptr = (uint8_t *)tr->tcp;
	struct tcp_option *opt;


	tr->ts_opt = NULL;
	tr->sack_opt = NULL;
	tr->win_shift = TFO_WIN_SCALE_UNSET;
	tr->mss_opt = 0;

	while (opt_off < opt_size) {
		opt = (struct tcp_option *)(opt_ptr + opt_off);

#ifdef DEBUG_TCP_OPTIONS
		printf("[%s]  tcp %p, opt 0x%x opt_off %u opt_size %u\n",
		       _epfx(ef, NULL), tr->tcp, opt->opt_code, opt_off,
		       opt->opt_code > TCPOPT_NOP ? opt->opt_len : 1U);
#endif

		if (opt->opt_code == TCPOPT_EOL) {
			opt_off += 4 - opt_off % 4;
			break;
		}
		if (opt->opt_code == TCPOPT_NOP) {
			opt_off++;
			continue;
		}

		/* Check we have all of the option and a cursory check that it is valid */
		if (opt_off + sizeof(*opt) > opt_size ||
		    opt->opt_len < 2 ||
		    opt_off + opt->opt_len > opt_size)
			return false;

		switch (opt->opt_code) {
		case TCPOPT_WINDOW:
			if (opt->opt_len != TCPOLEN_WINDOW)
				return false;

			if (tr->tcp->tcp_flags & RTE_TCP_SYN_FLAG)
				tr->win_shift = min(TCP_MAX_WINSHIFT, opt->opt_data[0]);
			break;
		case TCPOPT_SACK_PERMITTED:
			if (opt->opt_len != TCPOLEN_SACK_PERMITTED)
				return false;

#ifdef DEBUG_DISABLE_SACK
			if ((tr->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == RTE_TCP_SYN_FLAG) {
				struct tfo_pktrx_ctx ctx;
				uint16_t nops[1] = { [0] = 0x0101 };

				ctx.m = tr->m;
				ctx.iph = tr->iph;
				ctx.tcp = tr->tcp;
				ctx.ts = NULL;
				ctx.sack = NULL;

				ctx.tcp->cksum = update_checksum(ctx.tcp->cksum, opt, nops, sizeof(nops));
			}
#endif
			if ((tr->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_SACK;
			break;
		case TCPOPT_MAXSEG:
			if (opt->opt_len != TCPOLEN_MAXSEG)
				return false;

			tr->mss_opt = rte_be_to_cpu_16(*(uint16_t *)opt->opt_data);
			break;
		case TCPOPT_TIMESTAMP:
			if (opt->opt_len != TCPOLEN_TIMESTAMP)
				return false;

			tr->ts_opt = (struct tcp_timestamp_option *)opt;

#ifdef DEBUG_TCP_OPTIONS
			printf("[%s]  ts_val %u ts_ecr %u\n", _epfx(ef, NULL),
			       rte_be_to_cpu_32(tr->ts_opt->ts_val), rte_be_to_cpu_32(tr->ts_opt->ts_ecr));
#endif

#ifdef DEBUG_DISABLE_TS
			if ((tr->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == RTE_TCP_SYN_FLAG) {
				struct tfo_pktrx_ctx ctx;
				uint16_t nops[5] = { [0] = 0x0101, [1] = 0x0101, [2] = 0x0101, [3] = 0x0101, [4] = 0x0101 };

				ctx.m = tr->m;
				ctx.iph = tr->iph;
				ctx.tcp = tr->tcp;
				ctx.ts = NULL;
				ctx.sack = NULL;

				ctx.tcp->cksum = update_checksum(ctx.tcp->cksum, opt, nops, sizeof(nops));
				tr->ts_opt = NULL;
			}
#endif
			if ((tr->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_TIMESTAMP;
			break;
//		case 16 ... 18:		// Not IANA assigned
//		case 20 ... 24:		// Not IANA assigned
//		case 26 ... 27:		// 26 Not IANA assigned, 27 RFC4782 experimental in 2007
		case 28 ... 30:		// 28 RFC5482, 29 RFC5925, 30 RFC8684 - all in any packet
		case 34:		// TCP fast open cookie - SYN only
//		case 69:		// RFC8547 experimental 2019 in any packet
			/* See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
			 * for the list of assigned options. */
			break;
		default:
			/* Don't try optimizing if there are options we don't understand */
			return false;
		}

		opt_off += opt->opt_len;
	}

#if defined DEBUG_DISABLE_SACK || defined DEBUG_DISABLE_TS
	struct tfo_pkt pkt;
	uint8_t *opt_start = (uint8_t *)tr->tcp + sizeof(struct rte_tcp_hdr);
	uint8_t opt_len = ((tr->tcp->data_off & 0xf0) >> 2) - sizeof(struct rte_tcp_hdr);
	bool updated = false;

	pkt.m = tr->m;
	pkt.iph = tr->iph;
	pkt.tcp = tr->tcp;
	pkt.ts = tr->ts_opt;
	pkt.sack = tr->sack_opt;

	for (int i = 0; i < opt_len / 2 - 1; i++) {
		if (*(uint32_t *)(opt_start + 2 * i) == ((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_NOP << 8) | TCPOPT_NOP)) {
			update_packet_length(&pkt, opt_start + 2 * i, -4);
			i--;
			opt_len -= 4;
			opt_start = (uint8_t *)pkt.tcp + sizeof(struct rte_tcp_hdr);
			updated = true;
		}
	}

	if (updated) {
		tr->iph = pkt.iph;
		tr->tcp = pkt.tcp;
		tr->ts_opt = pkt.ts;
		tr->sack_opt = pkt.sack;
	}
#endif

	return (opt_off == opt_size);
}

static inline bool
set_estab_options(struct tfo_pktrx_ctx *tr, struct tfo_eflow *ef)
{
	unsigned opt_off = sizeof(struct rte_tcp_hdr);
	uint8_t opt_size = (tr->tcp->data_off & 0xf0) >> 2;
	uint8_t *opt_ptr = (uint8_t *)tr->tcp;
	struct tcp_option *opt;


	tr->ts_opt = NULL;
	tr->sack_opt = NULL;

	while (opt_off < opt_size) {
		opt = (struct tcp_option *)(opt_ptr + opt_off);

#ifdef DEBUG_TCP_OPTIONS
		printf("[%s]  rd tcp %p, opt 0x%x opt_off %u opt_size %u\n",
		       _epfx(ef, NULL), tr->tcp, opt->opt_code, opt_off, opt->opt_code > TCPOPT_NOP ? opt->opt_len : 1U);
#endif

		if (opt->opt_code == TCPOPT_EOL) {
			opt_off += 4 - opt_off % 4;
			break;
		}
		if (opt->opt_code == TCPOPT_NOP) {
			opt_off++;
			continue;
		}

		/* Check we have all of the option and a cursory check that it is valid */
		if (opt_off + sizeof (*opt) > opt_size || opt->opt_len < 2 ||
		    opt_off + opt->opt_len > opt_size) {
#ifdef DEBUG_VALID_TCP_OPTIONS
			printf("[%s]  tcp option size not correct: code:%d off:%d size:%d len:%d\n",
			       _epfx(ef, NULL), opt->opt_code, opt_off, opt_size, opt->opt_len);
#endif
			return false;
		}

		switch (opt->opt_code) {
		case TCPOPT_SACK:
			if (!(ef->flags & TFO_EF_FL_SACK)) {
#ifdef DEBUG_VALID_TCP_OPTIONS
				printf("[%s]   Received SACK option but not negotiated\n",
				       _epfx(ef, NULL));
#endif
				return false;
			}

			tr->sack_opt = (struct tcp_sack_option *)opt;
#if defined DEBUG_TCP_OPTIONS
			printf("[%s]  SACK option size %u, blocks %lu\n", _epfx(ef, NULL),
			       tr->sack_opt->opt_len, (tr->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges));
			for (unsigned i = 0; i < (tr->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges); i++)
				printf("    %u: 0x%x -> 0x%x\n", i, rte_be_to_cpu_32(tr->sack_opt->edges[i].left_edge), rte_be_to_cpu_32(tr->sack_opt->edges[i].right_edge));
#endif
			break;
		case TCPOPT_TIMESTAMP:
			if (!(ef->flags & TFO_EF_FL_TIMESTAMP)) {
#ifdef DEBUG_VALID_TCP_OPTIONS
				printf("[%s]  Received timestamp option but not negotiated\n", _epfx(ef, NULL));
#endif
				return false;
			}

			if (opt->opt_len != TCPOLEN_TIMESTAMP) {
#ifdef DEBUG_VALID_TCP_OPTIONS
				printf("[%s]  Received bad len tcp_opt timestamp (%d)\n", _epfx(ef, NULL), opt->opt_len);
#endif
				return false;
			}

			tr->ts_opt = (struct tcp_timestamp_option *)opt;

#ifdef DEBUG_TCP_OPTIONS
			printf("[%s]  ts_val %u ts_ecr %u\n", _epfx(ef, NULL),
			       rte_be_to_cpu_32(tr->ts_opt->ts_val), rte_be_to_cpu_32(tr->ts_opt->ts_ecr));
#endif

			break;
		case 28 ... 30:
			/* See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
			 * for the list of assigned options. */
			break;
		default:
#ifdef DEBUG_VALID_TCP_OPTIONS
			printf("[%s]  Received unknown tcp option 0x%02x\n",
			       _epfx(ef, NULL), opt->opt_code);
#endif
			/* Don't try optimizing if there are options we don't understand */
			return false;
		}

		opt_off += opt->opt_len;
	}

	/* If timestamps are negotiated, they must be included in every packet */
	if ((ef->flags & TFO_EF_FL_TIMESTAMP) && !tr->ts_opt) {
#ifdef DEBUG_VALID_TCP_OPTIONS
		printf("[%s] Timestamp was negociated, but rx packet didn't include it\n", _epfx(ef, NULL));
#endif
		return false;
	}

#ifdef DEBUG_VALID_TCP_OPTIONS
	if (opt_off != opt_size)
		printf("[%s]  bad tcp option, at the end, off:%d, size:%d\n",
		       _epfx(ef, NULL), opt_off, opt_size);
#endif

	return opt_off == opt_size;
}


static inline uint32_t
initial_cwnd_from_mss(uint16_t mss)
{
	if (mss > 2190)
		return 2 * mss;
	if (mss > 1095)
		return 3 * mss;
	return 4 * mss;
}

/*
 * called at SYN+ACK. optimize this tcp connection
 */
static void
eflow_start_optimize(struct tcp_worker *w, const struct tfo_pktrx_ctx *tr, struct tfo_eflow *ef)
{
	struct tfo_side *client_fo, *server_fo;
	uint32_t rtt_us;

	/* alloc flows */
	assert(!list_empty(&w->f_free));
	ef->priv = list_first_entry(&w->f_free, struct tfo_side, flow_list);
	list_del_init(&ef->priv->flow_list);
	assert(!list_empty(&w->f_free));
	ef->pub = list_first_entry(&w->f_free, struct tfo_side, flow_list);
	list_del_init(&ef->pub->flow_list);
	w->f_use += 2;

#ifdef DEBUG_FLOW
	printf("[%s] start optimizing. flows allocated\n", _epfx(ef, NULL));
#endif

	if (unlikely(tr->from_priv)) {
		/* original SYN from public */
		client_fo = ef->pub;
		server_fo = ef->priv;

	} else {
		/* original SYN from private */
		client_fo = ef->priv;
		server_fo = ef->pub;
	}

	memset(client_fo, 0x00, sizeof (*client_fo));
	memset(server_fo, 0x00, sizeof (*server_fo));

	client_fo->ef = ef;
	client_fo->rto_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
#ifdef DEBUG_PKT_DELAYS
	client_fo->last_rx_data = now;
	client_fo->last_rx_ack = now;
#endif
	INIT_LIST_HEAD(&client_fo->pktlist);
	INIT_LIST_HEAD(&client_fo->xmit_ts_list);
	client_fo->last_sent = &client_fo->xmit_ts_list;

	server_fo->ef = ef;
	server_fo->rto_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
#ifdef DEBUG_PKT_DELAYS
	server_fo->last_rx_data = now;
	server_fo->last_rx_ack = now;
#endif
	INIT_LIST_HEAD(&server_fo->pktlist);
	INIT_LIST_HEAD(&server_fo->xmit_ts_list);
	server_fo->last_sent = &server_fo->xmit_ts_list;


#ifdef CONFIG_PACE_TX_PACKETS
	/* will only pace packets on our radio network (priv) */
	ef->priv->pace_enabled = true;
	ef->pub->pace_enabled = false;
	INIT_LIST_HEAD(&client_fo->pace_xmit_list);
	INIT_LIST_HEAD(&server_fo->pace_xmit_list);
#endif

	/* Clear window scaling if either side didn't send it */
	if (tr->win_shift == TFO_WIN_SCALE_UNSET ||
	    ef->win_shift == TFO_WIN_SCALE_UNSET) {
		client_fo->snd_win_shift = 0;
		server_fo->snd_win_shift = 0;
	} else {
		client_fo->snd_win_shift = ef->win_shift;  /* win in syn */
		server_fo->snd_win_shift = tr->win_shift;   /* win in syn+ack */
	}

	/* We just set the rcv_win_shift (i.e. what we send)
	 * to match what we have received. We need to do this in case we
	 * stop optimizing the flow. */
	client_fo->rcv_win_shift = server_fo->snd_win_shift;
	server_fo->rcv_win_shift = client_fo->snd_win_shift;

	/* We set up rcv_nxt, snd_una, snd_nxt, last_ack_sent as though
	 * the SYN+ACK has not yet been received. This enables the processing
	 * of the SYN+ACK as a new packet to process normally. */
	client_fo->rcv_nxt = rte_be_to_cpu_32(tr->tcp->recv_ack);
	client_fo->snd_una = rte_be_to_cpu_32(tr->tcp->sent_seq);
	client_fo->snd_nxt = client_fo->snd_una;
	client_fo->last_ack_sent = ef->server_snd_una;
	client_fo->first_seq = ef->server_snd_una;
	server_fo->last_rcv_win_end = client_fo->snd_una + ef->client_snd_win;
	client_fo->snd_win = ((ef->client_snd_win - 1) >> client_fo->snd_win_shift) + 1;
	client_fo->rack_fack = client_fo->snd_una;
	server_fo->rack_fack = client_fo->first_seq;
	client_fo->rack_reo_wnd_mult = 1;
	server_fo->rack_reo_wnd_mult = 1;
#ifdef DEBUG_RCV_WIN
	printf("client side: server lrwe %u snd_una %u and snd_win %u << 0 (%u)\n",
	       server_fo->last_rcv_win_end, client_fo->snd_una, ef->client_snd_win, client_fo->snd_win);
#endif
	server_fo->rcv_win = client_fo->snd_win;
	client_fo->mss = ef->client_mss;
	if (tr->ts_opt) {
		client_fo->ts_recent = tr->ts_opt->ts_ecr;
		client_fo->latest_ts_val = rte_be_to_cpu_32(client_fo->ts_recent);
#ifdef CALC_TS_CLOCK
		client_fo->ts_start = client_fo->latest_ts_val;
		client_fo->ts_start_time = ef->start_time;
		client_fo->latest_ts_val_time = ef->start_time;
		server_fo->last_ts_val_sent = client_fo->latest_ts_val;

#ifdef DEBUG_TS_SPEED
		printf("Client TS start %u at " NSEC_TIME_PRINT_FORMAT "\n", client_fo->ts_start, NSEC_TIME_PRINT_PARAMS(client_fo->ts_start_time));
#endif
#endif
	}
	client_fo->packet_type = ef->client_packet_type;

// We might get stuck with client implementations that don't receive data with SYN+ACK. Adjust when go to established state
	server_fo->rcv_nxt = client_fo->snd_una;
	server_fo->snd_una = ef->server_snd_una;
	server_fo->snd_nxt = client_fo->rcv_nxt;
	server_fo->last_ack_sent = server_fo->snd_una;
	server_fo->first_seq = client_fo->snd_una;
	client_fo->last_rcv_win_end = server_fo->snd_una + rte_be_to_cpu_16(tr->tcp->rx_win);
	server_fo->snd_win = ((rte_be_to_cpu_16(tr->tcp->rx_win) - 1) >> server_fo->snd_win_shift) + 1;
	client_fo->rcv_win = server_fo->snd_win;
#ifdef DEBUG_RCV_WIN
	printf("server side: client lrwe %u snd_una %u and snd_win %d << 0 (%u)\n",
	       client_fo->last_rcv_win_end, server_fo->snd_una, rte_be_to_cpu_16(tr->tcp->rx_win), server_fo->snd_win);
#endif
	server_fo->mss = tr->mss_opt ? tr->mss_opt : (ef->flags & TFO_EF_FL_IPV6) ? TCP_MSS_DESIRED : TCP_MSS_DEFAULT;
	if (tr->ts_opt) {
		server_fo->ts_recent = tr->ts_opt->ts_val;
		server_fo->latest_ts_val = rte_be_to_cpu_32(server_fo->ts_recent);
#ifdef CALC_TS_CLOCK
		server_fo->ts_start = server_fo->latest_ts_val;
		server_fo->ts_start_time = now;
		server_fo->latest_ts_val_time = now;
		client_fo->last_ts_val_sent = server_fo->latest_ts_val;
		server_fo->nsecs_per_tock = 0;
		client_fo->nsecs_per_tock = 0;

#ifdef DEBUG_TS_SPEED
		printf("Server TS start %u at " NSEC_TIME_PRINT_FORMAT "\n", server_fo->ts_start, NSEC_TIME_PRINT_PARAMS(server_fo->ts_start_time));
#endif
#endif
	}
	server_fo->packet_type = tr->m->packet_type;
	client_fo->rcv_ttl = ef->client_ttl;
	if (ef->flags & TFO_EF_FL_IPV6) {
		client_fo->vtc_flow = ef->client_vtc_flow;
		server_fo->vtc_flow = tr->iph.ip6h->vtc_flow;
		server_fo->rcv_ttl = tr->iph.ip6h->hop_limits;
	} else
		server_fo->rcv_ttl = tr->iph.ip4h->time_to_live;

	/* RFC5681 3.2 */
	if (!(ef->flags & TFO_EF_FL_DUPLICATE_SYN)) {
		client_fo->cwnd = initial_cwnd_from_mss(client_fo->mss);
		server_fo->cwnd = initial_cwnd_from_mss(server_fo->mss);
	} else {
		client_fo->cwnd = client_fo->mss;
		server_fo->cwnd = server_fo->mss;
	}
	client_fo->ssthresh = 0xffff << client_fo->snd_win_shift;
	server_fo->ssthresh = 0xffff << server_fo->snd_win_shift;

	/* RFC8985 7.1 */
	server_fo->cur_timer = TFO_TIMER_NONE;
	server_fo->timeout_at = TFO_INFINITE_TS;
	server_fo->delayed_ack_timeout = TFO_ACK_NOW_TS;	// Ensure the 3WHS ACK is sent immediately
	server_fo->tlp_max_ack_delay_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	server_fo->tlp_highest_sent_seq = server_fo->snd_una;
	client_fo->cur_timer = TFO_TIMER_NONE;
	client_fo->timeout_at = TFO_INFINITE_TS;
	client_fo->delayed_ack_timeout = TFO_INFINITE_TS;
	client_fo->tlp_max_ack_delay_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	client_fo->tlp_highest_sent_seq = client_fo->snd_una;

	/* We make an initial estimate of the server side RTT, but
	 * since there might be overheads in establishing a
	 * connection, we start again once we get the first ack. */
	rtt_us = (now - ef->start_time) / NSEC_PER_USEC;
	server_fo->srtt_us = rtt_us;
	server_fo->rttvar_us = rtt_us / 2;
	if (ef->flags & TFO_EF_FL_SACK) {
		server_fo->rack_rtt_us = rtt_us;
		minmax_running_min(&server_fo->rtt_min, config->tcp_min_rtt_wlen * USEC_PER_MSEC, now / NSEC_PER_USEC, rtt_us);
	}
	server_fo->flags |= TFO_SIDE_FL_RTT_FROM_SYN;

#ifdef DEBUG_OPTIMIZE
	printf("priv rx/tx win 0x%x:0x%x pub rx/tx 0x%x:0x%x, priv send win 0x%x, pub 0x%x\n",
		fo->priv.rcv_win, fo->priv.snd_win, fo->pub.rcv_win, fo->pub.snd_win,
		fo->priv.snd_nxt + (fo->priv.snd_win << fo->priv.snd_win_shift),
		fo->pub.snd_nxt + (fo->pub.snd_win << fo->pub.snd_win_shift));
	printf("clnt ts_recent = %1$u (0x%1$x) svr ts_recent = %2$u (0x%2$x)\n", rte_be_to_cpu_32(client_fo->ts_recent), rte_be_to_cpu_32(server_fo->ts_recent));
	printf("WE WILL optimize pub s:n 0x%x:0x%x priv 0x%x:0x%x\n", fo->pub.snd_una, fo->pub.rcv_nxt, fo->priv.snd_una, fo->priv.rcv_nxt);
#endif

}


/*
 * NOTE: If we return false, an ACK might need to be sent
 */
static bool
send_tcp_pkt(struct tcp_worker *w, struct tfo_pkt *pkt, struct tfo_side *fos,
	     struct tfo_side *foos, __attribute__((unused)) const char *dbg_loc)
{
	uint32_t new_val32[2];
	uint16_t new_val16[1];

#ifdef DEBUG_SEND_PKT_LOCATION
	printf("[%s] send_tcp_pkt [%s] seq %u\n", _spfx(fos), dbg_loc, pkt->seq);
#endif
	if (pkt->rack_segs_sacked) {
		printf("Ignore request to send sack'd packet %p, seq %u\n", pkt, pkt->seq);
		return false;
	}

#ifdef DEBUG_CHECKSUM
	check_checksum(pkt, "send_tcp_pkt");
#endif

	if (pkt->flags & TFO_PKT_FL_QUEUED_SEND) {
#ifdef DEBUG_QUEUED
		printf("[%s] skip sending %u (m=%p) since already queued\n",
		       _spfx(fos), pkt->seq, pkt->m);
#endif
		return false;
	}

	/* Update the ack */
	new_val32[0] = rte_cpu_to_be_32(fos->rcv_nxt);
	if (likely(pkt->tcp->recv_ack != new_val32[0])) {
		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &pkt->tcp->recv_ack, new_val32, sizeof(pkt->tcp->recv_ack));

		/* For ts_recent updates */
		fos->last_ack_sent = fos->rcv_nxt;

#ifdef DEBUG_CHECKSUM
		check_checksum(pkt, "After ack update");
#endif
	}

	/* Update the timestamp option if in use */
	if (pkt->ts) {
		/* The following is to ensure the order of assignment to new_val32[2] is correct.
		 * If the order is wrong it will produce a compilation error. */
		char dummy[(int)offsetof(struct tcp_timestamp_option, ts_ecr) - (int)offsetof(struct tcp_timestamp_option, ts_val)] __attribute__((unused));

#ifdef CALC_TS_CLOCK
		new_val32[0] = calc_ts_val(fos, foos);
#else
		new_val32[0] = rte_cpu_to_be_32(foos->latest_ts_val);
#endif
		new_val32[1] = fos->ts_recent;

		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &pkt->ts->ts_val, new_val32, 2 * sizeof(pkt->ts->ts_val));

#ifdef DEBUG_CHECKSUM
		check_checksum(pkt, "After ts update");
#endif
	}

	update_sack_option(pkt, fos);
#ifdef DEBUG_CHECKSUM
	check_checksum(pkt, "After sack update");
#endif

	/* Update the offered send window */
	set_rcv_win(fos, foos);
	new_val16[0] = rte_cpu_to_be_16(fos->rcv_win);
	if (likely(pkt->tcp->rx_win != new_val16[0])) {
		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &pkt->tcp->rx_win, new_val16, sizeof(pkt->tcp->rx_win));
#ifdef DEBUG_CHECKSUM
		check_checksum(pkt, "After rxwin update");
#endif
	}

	/* save highest sent seq, for tlp */
	if (after(pkt->seq, fos->tlp_highest_sent_seq)) {
		fos->tlp_highest_sent_pkt = pkt;
		fos->tlp_highest_sent_seq = pkt->seq;
	}

#ifdef DEBUG_PKT_PTRS
	struct tfo_mbuf_priv *mp = get_priv_addr(pkt->m);

	if (mp->pkt != pkt)
		printf("ERROR send_tcp_pkt pkt %p != priv->pkt %p\n", pkt, mp->pkt);
	if (mp->fos != fos)
		printf("ERROR send_tcp_pkt pkt %p priv->fos %p != fos\n", pkt, mp->fos);
#endif

	rte_pktmbuf_refcnt_update(pkt->m, 1);		/* so we keep it after it is sent */
	pkt->m->ol_flags |= dynflag_queued_send_mask;	/* to remove FL_QUEUED_SEND after tx_burst */
	pkt->flags |= TFO_PKT_FL_QUEUED_SEND;
	add_tx_buf(w, pkt->m, fos);
	fos->pkts_queued_send++;
#ifdef DEBUG_SEND_PKT
	printf("Sending packet seq %u m %p refcnt %d\n", pkt->seq, pkt->m, rte_mbuf_refcnt_read(pkt->m));
#endif

	/* No need to send an ACK if one is delayed */
	fos->delayed_ack_timeout = TFO_INFINITE_TS;

#ifdef DEBUG_PKT_TX
	printf("[%s] TX, seq:%u(%u) ack:%u(%u) len:%u tcp.rx_win:%u\n",
	       _spfx(fos), rte_be_to_cpu_32(pkt->tcp->sent_seq), rte_be_to_cpu_32(pkt->tcp->sent_seq) - foos->first_seq,
	       rte_be_to_cpu_32(pkt->tcp->recv_ack), rte_be_to_cpu_32(pkt->tcp->recv_ack) - fos->first_seq,
	       pkt->seglen, rte_be_to_cpu_16(pkt->tcp->rx_win));
#endif

	return true;
}


/*
 * The principles of the queue are:
 *  - A queued packet always contains data before its successor
 *	pkt->seq < next_pkt->seq
 *  - The next packet always contains data after its predecessor
 *	pkt->seq + pkt->seglen < next_pkt->seq + next_pkt->seglen
 *	  (i.e. segend(pkt) < segend(next_pkt))
 *
 * If a packet arrives that contains data that we have not previously
 *  received, it will always be queued. If any queued packets no longer
 *  provide data provided by other packets, remove them.
 *
 * If part of a new packet has been SACK'd, discard it.
 *
 * If a packet arrives that is wholly contained within another packet,
 *  remove/discard the longer one(s) that doesn't increase any gaps.
 *
 * If a packet arrives that allows two or more queued packets to be discarded,
 *  queue the new packet and remove the redundant ones.
 *
 * Otherwise discard the packet.
 *
 */
static struct tfo_pkt *
queue_pkt(struct tcp_worker *w, struct tfo_side *foos, struct tfo_pktrx_ctx *tr, uint32_t seq, uint32_t rcv_nxt, uint32_t *dup_sack)
{
	struct tfo_pkt *prev_pkt;	/* Last packet before pkt which does not overlap */
	struct tfo_pkt *first_pkt;	/* First packet which overlaps pkt */
	struct tfo_pkt *last_pkt;	/* Last packet which overlaps pkt */
	struct tfo_pkt *next_pkt;	/* First packet that starts after end of pkt */
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_pkt *queue_after;
	struct tfo_mbuf_priv *mp;
	uint32_t seg_end;
	uint32_t first_seq, last_seq;
	bool pkt_needed;
	uint32_t wanted_seq;
	int sack_gaps;
	uint32_t dummy_dup_sack[2];

	if (!dup_sack)
		dup_sack = dummy_dup_sack;

	seg_end = seq + tr->seglen;

	if (!after(seg_end, rcv_nxt)) {
#ifdef DEBUG_QUEUE_PKTS
		printf("[%s] queue_pkt seq %u, len %u before our window\n", _spfx(foos), seq, tr->seglen);
#endif
		dup_sack[0] = seq;
		dup_sack[1] = seg_end;

		return PKT_IN_LIST;
	}

	prev_pkt = first_pkt = last_pkt = next_pkt = NULL;
	pkt_needed = false;
	if (!list_empty(&foos->pktlist)) {
		/* Check if after end of current list, or before beginning */
		if (unlikely(!after(seg_end, (pkt = list_first_entry(&foos->pktlist, struct tfo_pkt, list))->seq))) {
			next_pkt = pkt;
		} else if (pkt = list_last_entry(&foos->pktlist, struct tfo_pkt, list),
			   !after(segend(pkt), seq)) {
			prev_pkt = pkt;
		} else {
			list_for_each_entry_reverse(pkt, &foos->pktlist, list) {
				if (before(pkt->seq, seg_end)) {
					next_pkt = list_is_last(&pkt->list, &foos->pktlist) ? NULL : list_next_entry(pkt, list);
					break;
				}
			}

			if (!list_is_head(&pkt->list, &foos->pktlist) && after(segend(pkt), seq)) {
				last_pkt = pkt;
				if (before(segend(last_pkt), seg_end))
					pkt_needed = true;
			} else
				pkt_needed = true;

			list_for_each_entry_from_reverse(pkt, &foos->pktlist, list) {
				if (!after(segend(pkt), seq))
					break;
				if (before(segend(pkt), seg_end) &&
				    before(segend(pkt), list_next_entry(pkt, list)->seq))
					pkt_needed = true;
				first_pkt = pkt;
			}

			if (first_pkt && before(seq, first_pkt->seq))
				pkt_needed = true;

			if (!list_is_head(&pkt->list, &foos->pktlist))
				prev_pkt = pkt;
		}
	}

#ifdef DEBUG_QUEUE_PKTS_OVERLAP
	if (first_pkt || last_pkt) {
		printf("[%s] pkt_overlap DUPLICATION!!!\n", _spfx(foos));
		printf("  prev 0x%x first 0x%x last 0x%x next 0x%x\n",
		       prev_pkt ? prev_pkt->seq : 0xffff,
		       first_pkt ? first_pkt->seq : 0xffff,
		       last_pkt ? last_pkt->seq : 0xffff,
		       next_pkt ? next_pkt->seq : 0xffff);
	}
#endif

	if (!first_pkt) {
		if (last_pkt) {
			dup_sack[1] = after(segend(last_pkt), seg_end) ? seg_end : segend(last_pkt);
			pkt = last_pkt;
			list_for_each_entry_from_reverse(pkt, &foos->pktlist, list) {
				if (before(pkt->seq, seq)) {
					dup_sack[0] = seq;
					break;
				} else
					dup_sack[0] = pkt->seq;
			}
		}

		wanted_seq = prev_pkt ? segend(prev_pkt) : foos->snd_una;
		sack_gaps = 0;
		if (!next_pkt) {
			if (before(wanted_seq, seq))
				sack_gaps++;
		} else {
			if (before(wanted_seq, seq) &&
			    before(seg_end, next_pkt->seq))
				sack_gaps++;
			else if (!before(wanted_seq, seq) &&
				 !before(seg_end, next_pkt->seq))
				sack_gaps--;
		}
		queue_after = prev_pkt ? prev_pkt : NULL;
		foos->sack_gap += sack_gaps;
	} else if (!pkt_needed) {
		dup_sack[0] = seq;
		dup_sack[1] = seg_end;

		/* We need to decide whether to queue this packet and remove others.
		 * If all (!sent or lost) then definitely replace. */
#ifdef DEBUG_QUEUE_PKTS
		printf("[%s] could replace pkts seq range %u -> %u with new pkt\n",
		       _spfx(foos), first_pkt->seq, last_pkt->seq);
#endif
		return PKT_IN_LIST;
	} else {
		first_seq = prev_pkt && !before(segend(prev_pkt), first_pkt->seq) ? prev_pkt->seq : first_pkt->seq;
		last_seq = next_pkt && !before(segend(last_pkt), next_pkt->seq) ? next_pkt->seq : segend(last_pkt);

		dup_sack[0] = after(first_pkt->seq, seq) ? first_pkt->seq : seq;
		dup_sack[1] = before(segend(first_pkt), seg_end) ? segend(first_pkt) : seg_end;

		wanted_seq = prev_pkt ? segend(prev_pkt) : foos->snd_una;
		sack_gaps = 0;
		if (next_pkt &&
		    before(segend(last_pkt), next_pkt->seq) &&
		    !before(seg_end, next_pkt->seq))
			sack_gaps--;

		first_seq = prev_pkt && !before(segend(prev_pkt), seq) ? prev_pkt->seq : seq;
		last_seq = next_pkt && !after(next_pkt->seq, seg_end) ? next_pkt->seq : seg_end;

		pkt = first_pkt;
		queue_after = prev_pkt ? prev_pkt : NULL;
		list_for_each_entry_safe_from(pkt, pkt_tmp, &foos->pktlist, list) {
			if (!before(dup_sack[1], pkt->seq))
				dup_sack[1] = before(segend(pkt), seg_end) ? segend(pkt) : seg_end;

			if (after(pkt->seq, wanted_seq) &&
			    !after(seq, wanted_seq) &&
			    !before(seg_end, pkt->seq))
				sack_gaps--;

			if (!before(pkt->seq, first_seq) && !after(segend(pkt), last_seq))
				pkt_free(w, foos, pkt);
			else if (before(pkt->seq, seq))
				queue_after = pkt;

			if (pkt == last_pkt)
				break;
			wanted_seq = segend(pkt);
		}

		foos->sack_gap += sack_gaps;
	}

#ifdef DEBUG_QUEUE_PKTS
	printf("[%s] queue_pkt, refcount %u\n", _spfx(foos), rte_mbuf_refcnt_read(tr->m));
#endif

	/* bufferize this packet */
// Re need to stop optimizing and ensure this packet is sent due to !handled
	if (list_empty(&w->p_free))
		return NULL;

	pkt = list_first_entry(&w->p_free, struct tfo_pkt, list);
	list_del_init(&pkt->list);
	if (++w->p_use > w->p_max_use)
		w->p_max_use = w->p_use;

	pkt->m = tr->m;
	tr->m->ol_flags ^= config->dynflag_priv_mask;

	/* Update the mbuf private area so we can find the tfo_side and tfo_pkt from the mbuf */
	mp = get_priv_addr(tr->m);
	mp->fos = foos;
	mp->pkt = pkt;

	pkt->seq = seq;
	pkt->seglen = tr->seglen;
	pkt->iph = tr->iph;
	pkt->tcp = tr->tcp;
	pkt->flags = tr->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
	pkt->ns = 0;
	pkt->ts = tr->ts_opt;
	pkt->sack = tr->sack_opt;
	pkt->rack_segs_sacked = 0;
	INIT_LIST_HEAD(&pkt->xmit_ts_list);

	if (!queue_after) {
#ifdef DEBUG_QUEUE_PKTS
		printf(" adding pkt at head %p m %p seq %u to fo %p\n", pkt, pkt->m, seq, foos);
#endif
		list_add(&pkt->list, &foos->pktlist);

	} else {
#ifdef DEBUG_QUEUE_PKTS
		printf(" adding packet not at head\n");
#endif
		list_add(&pkt->list, &queue_after->list);
	}

	foos->pktcount++;

	return pkt;
}

static void
_eflow_set_state(struct tcp_worker *w, struct tfo_eflow *ef, uint8_t new_state)
{
	--w->st.flow_state[ef->state];
	++w->st.flow_state[new_state];
	ef->state = new_state;
}


#ifdef DEBUG_CLEAR_OPTIMIZE
#define clear_optimize(w,e,tr,r)	do_clear_optimize(w,e,tr,r)
#else
#define clear_optimize(w,e,tr,r)	do_clear_optimize(w,e)
#endif

static void
do_clear_optimize(struct tcp_worker *w, struct tfo_eflow *ef
#ifdef DEBUG_CLEAR_OPTIMIZE
			, const struct tfo_pktrx_ctx *tr, const char *reason
#endif
									)
{
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_side *s;
	uint32_t rcv_nxt;

#ifdef DEBUG_CLEAR_OPTIMIZE
	printf("clear optimize %s- %s - ERROR\n", ef->state == TCP_STATE_CLEAR_OPTIMIZE ? "(already set) " : "", reason);
	if (tr) {
		dump_eflow(ef);
		dump_pkt_ctx_mbuf(tr);
	}
#endif

	/* stop current optimization */
	_eflow_set_state(w, ef, TCP_STATE_CLEAR_OPTIMIZE);

	if (ef->priv != NULL) {
		/* Remove any buffered packets that we haven't ack'd */
		s = ef->priv;
		rcv_nxt = ef->pub->rcv_nxt;
		while (true) {
			if (!list_empty(&s->pktlist)) {
				/* Remove any packets that have been sent but not been ack'd */
				list_for_each_entry_safe_reverse(pkt, pkt_tmp, &s->pktlist, list) {
					if (after(rcv_nxt, segend(pkt))) {
						break;
					}
					if (!(pkt->flags & TFO_PKT_FL_QUEUED_SEND))
						pkt_free(w, s, pkt);
				}
			}

			if (s == ef->pub)
				break;

			s = ef->pub;
			rcv_nxt = ef->priv->rcv_nxt;
		}
	}

	if (ef->priv == NULL ||
	    (list_empty(&ef->priv->pktlist) && list_empty(&ef->pub->pktlist))) {
#ifdef DEBUG_FLOW
		printf("[%s] clear_optimize: no packet, free using idle_timeout\n", _epfx(ef, NULL));
#endif
		ef->idle_timeout = now;
	}
}


#ifdef DEBUG_SACK_SEND
static void
dump_sack_entries(const struct tfo_side *fos)
{
	unsigned i;

	printf("  sack_gap %u sack_entries %u first_sack_entry %u\n", fos->sack_gap, fos->sack_entries, fos->first_sack_entry);
	for (i = 0; i < MAX_SACK_ENTRIES; i++)
		printf("    %u: %u -> %u%s\n", i, fos->sack_edges[i].left_edge, fos->sack_edges[i].right_edge, i == fos->first_sack_entry ? " *" : "");
}
#endif


/*
 * called from tfo_handle_pkt()
 */
static void
update_sack_for_seq(struct tfo_side *fos, struct tfo_pkt *pkt, struct tfo_side *foos)
{
	struct tfo_pkt *begin, *end, *next;
	uint32_t left, right;
	uint8_t entry, last_entry, next_entry;

	/* fos is where the packet is queued, foos is the side that wants the SACK info */
	if (!fos->sack_gap) {
		foos->sack_entries = 0;
		return;
	}

#ifdef DEBUG_SACK_SEND
	printf("[%s] writing SACK: before new packet seq %u rcv_nxt %u --\n",
	       _spfx(fos), pkt->seq, foos->rcv_nxt);
	dump_sack_entries(foos);
#endif

	/* Find the contiguous block start and end, but only if this
	 * packet is after rcv_nxt. */
	if (after(pkt->seq, foos->rcv_nxt)) {
		next = pkt;
		begin = pkt;
		list_for_each_entry_continue_reverse(next, &fos->pktlist, list) {
			if (before(segend(next), begin->seq))
				break;
			begin = next;
		}

		next = pkt;
		end = pkt;
		list_for_each_entry_continue(next, &fos->pktlist, list) {
			if (before(segend(end), next->seq))
				break;
			end = next;
		}

		left = begin->seq;
		right = segend(end);
	} else {
		/* We don't have a block after rcv_nxt */
		left = foos->rcv_nxt;
		right = foos->rcv_nxt;
	}

#ifdef DEBUG_SACK_SEND
	printf("packet block is %u -> %u\n", left, right);
#endif

	if (foos->sack_entries) {
		last_entry = (foos->first_sack_entry + foos->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
		for (entry = foos->first_sack_entry; ; entry = (entry + 1) % MAX_SACK_ENTRIES) {
			/* If the entry is before rcv_nxt, or is covered by the new
			 * contiguous block, remove it */
			if (!after(foos->sack_edges[entry].right_edge, foos->rcv_nxt) ||
			    (!after(left, foos->sack_edges[entry].left_edge) &&
			     !before(right, foos->sack_edges[entry].right_edge))) {
				/* Remove the entry */
				foos->sack_entries--;
				if (entry == foos->first_sack_entry)
					foos->first_sack_entry = (foos->first_sack_entry + 1) % MAX_SACK_ENTRIES;
				else {
					/* Move the remaining entries backwards */
					for (next_entry = entry; next_entry != last_entry; next_entry = (next_entry + 1) % MAX_SACK_ENTRIES)
						foos->sack_edges[next_entry] = foos->sack_edges[(next_entry + 1) % MAX_SACK_ENTRIES];

					/* Since we have moved the next entry to the current entry,
					 * we need to decrement entry, so that next time around the
					 * loop we look at the same entry. */
					entry = (entry + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;

					/* Last entry is decremented too */
					last_entry = (last_entry + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
				}
			} else if (before(foos->sack_edges[entry].left_edge, foos->rcv_nxt)) {
				/* Adjust the left edge */
				foos->sack_edges[entry].left_edge = foos->rcv_nxt;
			}

			if (entry == last_entry)
				break;
		}
	}

	if (left != right) {
		/* Move the head back and add the entry */
		foos->first_sack_entry = (foos->first_sack_entry + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
		if (foos->sack_entries < MAX_SACK_ENTRIES)
			foos->sack_entries++;

		foos->sack_edges[foos->first_sack_entry].left_edge = left;
		foos->sack_edges[foos->first_sack_entry].right_edge = right;
	}

#ifdef DEBUG_SACK_SEND
	printf("writing SACK: after new packet:\n");
	dump_sack_entries(foos);
	printf("done writing SACK --\n");
#endif
}


enum seq_status {
	SEQ_OK,
	SEQ_BAD,
	SEQ_OLD
};

/*
 * RFC9293 3.10.7.4 - SEGMENT_ARRIVES - first check sequence number
 */
static inline enum seq_status
check_seq(uint32_t seq, uint32_t seglen, uint32_t win_end, struct tfo_side *s)
{
	enum seq_status status;

	if (before(seq + seglen, s->rcv_nxt)) {
#ifdef DEBUG_EARLY_PACKETS
		if (!(s->flags & TFO_SIDE_FL_SEQ_WRAPPED)) {
			/* We have seen (Linux 6.0.9 as source):
			 *   SYN seq = 0x78772668
			 *   SYN+ACK seq = 0x1db856a9 ack=0x78772669
			 *   ACK seq = 0x78772669 ack = 0x1db856aa
			 *  0.3/0.99 secs later
			 *   ACK seq = 0x78772668, ack = 0x1db856aa
			 * This occurred on two connections, with the
			 * second ACKs being received in the same burst
			 * of 176 packets.
			 * They look like keepalives, but is it valid
			 * to send a keepalive with the same seq as the SYN
			 * but without SYN set?
			 * The check below was if (!after(... but is now changed
			 * to before so that this scenario will return SEQ_OLD
			 * rather than SEQ_BAD. */
			if (seq == s->first_seq && seglen == 0)
				printf("ERROR - early keepalive seen with SYN's seq\n");
			if (before(seq, s->first_seq) ||
			    (seq == s->first_seq && seglen))
				return SEQ_BAD;
		}
#endif

		return SEQ_OLD;
	}

	if (seglen == 0) {
		if (s->rcv_win == 0)
			return seq == s->rcv_nxt ? SEQ_OK : SEQ_BAD;

		return between_end_ex(seq, s->rcv_nxt, win_end) ? SEQ_OK : SEQ_BAD;

	} else {
		status = (s->rcv_win != 0 &&
			  (between_end_ex(seq, s->rcv_nxt, win_end) ||
			   between(seq + seglen, s->rcv_nxt, win_end))) ? SEQ_OK : SEQ_BAD;

#ifdef DEBUG_EARLY_PACKETS
		if (status == SEQ_OK && !(s->flags & TFO_SIDE_FL_SEQ_WRAPPED) &&
		    before(seq, s->first_seq) && !before(seq + seglen, s->first_seq)) {
			s->flags |= TFO_SIDE_FL_SEQ_WRAPPED;
		}
#endif

		return status;
	}
}


static void
update_rto(struct tfo_side *fos, time_ns_t pkt_ns)
{
	uint32_t rtt = (now - pkt_ns) / NSEC_PER_USEC;

#ifdef DEBUG_RTO
	printf("[%s] update_rto() pkt_ns " NSEC_TIME_PRINT_FORMAT
	       " rtt_ns " NSEC_TIME_PRINT_FORMAT " rtt %u\n",
	       _spfx(fos), NSEC_TIME_PRINT_PARAMS(pkt_ns),
	       NSEC_TIME_PRINT_PARAMS_ABS(now - pkt_ns), rtt);
#endif

	if (unlikely(!fos->srtt_us || fos->flags & TFO_SIDE_FL_RTT_FROM_SYN)) {
		fos->srtt_us = rtt;
		fos->rttvar_us = rtt / 2;
		fos->flags &= ~TFO_SIDE_FL_RTT_FROM_SYN;
		minmax_reset(&fos->rtt_min, 0, 0);
	} else {
		fos->rttvar_us = (fos->rttvar_us * 3 + (fos->srtt_us > rtt ? (fos->srtt_us - rtt) : (rtt - fos->srtt_us))) / 4;
		fos->srtt_us = (fos->srtt_us * 7 + rtt) / 8;
	}
	fos->rto_us = fos->srtt_us + max(1U, fos->rttvar_us * 4);

	if (fos->rto_us < TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC)
		fos->rto_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	else if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC)
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;

	fos->flags |= TFO_SIDE_FL_TLP_NEW_RTT;
}

static void
update_rto_ts(struct tfo_side *fos, time_ns_t pkt_ns, uint32_t pkts_ackd)
{
	uint32_t rtt = (now - pkt_ns) / NSEC_PER_USEC;
	uint32_t new_rttvar;

#ifdef DEBUG_RTO
	printf("[%s] update_rto_ts() pkt_ns " NSEC_TIME_PRINT_FORMAT
	       " rtt_ns " NSEC_TIME_PRINT_FORMAT " rtt %u pkts in flight %u ackd %u\n",
	       _spfx(fos), NSEC_TIME_PRINT_PARAMS(pkt_ns), NSEC_TIME_PRINT_PARAMS_ABS(now - pkt_ns),
	       rtt, fos->pkts_in_flight, pkts_ackd);
#endif

	/* RFC7323 Appendix G. However, we are using actual packet counts rather than the
	 * estimate of FlightSize / (MSS * 2). This is because we can't calculate FlightSize
	 * by using snd_nxt - snd_una since we can have gaps between pkts if we have
	 * not yet received some packets. */
	if (unlikely(!fos->srtt_us || fos->flags & TFO_SIDE_FL_RTT_FROM_SYN)) {
		fos->srtt_us = rtt;
		fos->rttvar_us = rtt / 2;
		fos->flags &= ~TFO_SIDE_FL_RTT_FROM_SYN;
		minmax_reset(&fos->rtt_min, 0, 0);
	} else {
		if (unlikely(!fos->pkts_in_flight))
			return;

		new_rttvar = fos->srtt_us > rtt ? (fos->srtt_us - rtt) : (rtt - fos->srtt_us);
		fos->rttvar_us = ((4ULL * fos->pkts_in_flight - pkts_ackd) * fos->rttvar_us + pkts_ackd * new_rttvar) / (fos->pkts_in_flight * 4);
		fos->srtt_us = ((8ULL * fos->pkts_in_flight - pkts_ackd) * fos->srtt_us + pkts_ackd * rtt) / (fos->pkts_in_flight * 8);
	}
	fos->rto_us = fos->srtt_us + max(1U, fos->rttvar_us * 4);

	if (fos->rto_us < TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC)
		fos->rto_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	else if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC)
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;

	fos->flags |= TFO_SIDE_FL_TLP_NEW_RTT;
}

static inline void
on_rto_timeout(struct tfo_side *fos, struct tfo_pkt *pkt)
{
	/* RFC5681 3.2 */
	if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_RESENT)) == TFO_PKT_FL_SENT) {
		fos->ssthresh = min((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
		fos->cwnd = fos->mss; /* yeah that's terrible */
	}

	/* forget about current tlp */
	fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);

	/* RFC 6298 5.5 */
	fos->rto_us *= 2;
	if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC)
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;

	if (fos->ef->state == TCP_STATE_ESTABLISHED && !(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
		printf("[%s] Entering RTO recovery, end seq=%u\n", _spfx(fos), fos->recovery_end_seq);
#endif
	}
}


static inline struct tfo_pkt *
tr_queue_packet(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_side *fos, struct tfo_side *foos,
		uint32_t *dup_sack)
{
	struct tfo_pkt *pkt, *queued_pkt;
	bool rcv_nxt_updated;
	uint32_t nxt_exp;

	/* If there is no gap before this packet, update rcv_nxt */
	if (!after(tr->seq, fos->rcv_nxt) && after(tr->seq + tr->seglen, fos->rcv_nxt)) {
		if (tr->tcp->tcp_flags & RTE_TCP_PSH_FLAG)
			tr->fos_must_ack = true;
		else
			tr->fos_send_ack = true;

		rcv_nxt_updated = true;
	} else {
		rcv_nxt_updated = false;
	}

	/* Queue the packet, and see if we can advance fos->rcv_nxt further */
	queued_pkt = queue_pkt(w, foos, tr, tr->seq, fos->rcv_nxt, dup_sack);

	if (unlikely(queued_pkt == PKT_IN_LIST)) {
		/* The packet has already been received */
		tr->free_mbuf = true;

	} else if (queued_pkt != NULL) {
		/* the lowest-seq packet to be transmitted first */
		if (foos->first_unsent == NULL ||
		    before(queued_pkt->seq, foos->first_unsent->seq))
			foos->first_unsent = queued_pkt;

		/* RFC5681 3.2 - filling all or part of a gap */
		if (!list_is_last(&queued_pkt->list, &foos->pktlist) ||
		    (!list_is_first(&queued_pkt->list, &foos->pktlist) &&
		     before(segend(list_prev_entry(queued_pkt, list)), queued_pkt->seq)))
			tr->fos_must_ack = true;

		/* We have new data, update idle timeout */
		eflow_update_idle_timeout(fos->ef);

		if (rcv_nxt_updated) {
			nxt_exp = segend(queued_pkt);
			fos->rcv_nxt = nxt_exp;

			pkt = queued_pkt;
			list_for_each_entry_continue(pkt, &foos->pktlist, list) {
				if (after(pkt->seq, nxt_exp))
					break;

				nxt_exp = segend(pkt);
				fos->rcv_nxt = nxt_exp;
			}
		} else {
			/* we must have a missing packet, so resend ack */
			tr->fos_must_ack = true;
		}

		if ((fos->ef->flags & TFO_EF_FL_SACK))
			update_sack_for_seq(foos, queued_pkt, fos);

	} else {
		// This might confuse things later
		if (fos->ef->state != TCP_STATE_CLEAR_OPTIMIZE)
			clear_optimize(w, fos->ef, tr, "no tfo_pkt");
	}

	return queued_pkt;
}

/*
 * if window allow, send more packets from 'fos' side.
 * called at the end of packet RX
 * XXX can it be called at the end of timer call ?
 */
static inline void
tr_send_more_packets(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos, uint32_t win_end)
{
	struct tfo_pkt *pkt;
	uint32_t snd_nxt;

	if ((pkt = fos->first_unsent) == NULL)
		return;

	list_for_each_entry_from(pkt, &fos->pktlist, list) {
		if (after(segend(pkt), win_end)) {
			fos->first_unsent = pkt;
			return;
		}

		/* may happen if we received packets in disorder */
		if (pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_QUEUED_SEND)) {
			printf("[%s] send_more_packets: skip pkt seq %u, already sent\n", _spfx(fos), pkt->seq);
			continue;
		}

		assert(send_tcp_pkt(w, pkt, fos, foos, "SendMore"));

		/* update fos->snd_nxt */
		snd_nxt = segend(pkt);
#ifdef DEBUG_SND_NXT
		printf("[%s] send pkt seq %u, snd_nxt %u => %u (+%u)\n",
		       _spfx(fos), pkt->seq, fos->snd_nxt, snd_nxt, snd_nxt - fos->snd_nxt);
#endif
		if (after(snd_nxt, fos->snd_nxt))
			fos->snd_nxt = snd_nxt;
	}

	fos->first_unsent = NULL;
}


/****************************************************************************/
/* STANDARD RECEIVE / PACKET BUFFER MANAGEMENT (no sack/rack) */
/****************************************************************************/

/*
 * remove acked buffered packets. We want the time the
 * most recent packet was sent to update the RTT.
 */
static inline void
tr_ack_pkts(struct tfo_pktrx_ctx *tr, struct tfo_side *fos, uint32_t *pkts_ackd, time_ns_t *newest_send_time)
{
	struct tfo_pkt *pkt, *pkt_tmp;

	list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
#ifdef DEBUG_ACK_PKT_LIST
		printf("  pkt->seq 0x%x pkt->seglen 0x%x, tcp_flags 0x%x, ack 0x%x\n",
		       pkt->seq, pkt->seglen, tr->tcp->tcp_flags, ack);
#endif

		if (unlikely(after(segend(pkt), tr->ack)))
			break;

		/* The packet hasn't been ack'd before */
		++*pkts_ackd;
		fos->flags |= TFO_SIDE_FL_ACKED_DATA;

		if (pkt->ts) {
			if (pkt->ts->ts_val == tr->ts_opt->ts_ecr &&
			    pkt->ns > *newest_send_time)
				*newest_send_time = pkt->ns;
#ifdef DEBUG_RTO
			else if (pkt->ts->ts_val != tr->ts_opt->ts_ecr)
				printf("ERR tsecr 0x%x != tsval 0x%x\n",
				       rte_be_to_cpu_32(tr->ts_opt->ts_ecr), rte_be_to_cpu_32(pkt->ts->ts_val));
#endif

		} else {
			if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
				update_rto(fos, pkt->ns);
				pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
				fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
			}
		}

		/* acked, remove buffered packet */
#ifdef DEBUG_ACK_PKT_LIST
		printf("  calling pkt_free m %p, seq %u\n", pkt->m, pkt->seq);
#endif
		pkt_free(&worker, fos, pkt);
	}

#ifdef DEBUG_ACK
	printf("[%s] removed %u cumulatively ack'd packets\n", _spfx(fos), *pkts_ackd);
#endif
}


/*
 * RFC5681 3.2
 */
static inline void
tr_send_in_fast_recovery(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_side *fos)
{
	struct tfo_pkt *pkt;
	bool only_one_packet;
	int32_t bytes_sent;
	uint32_t win_end;
	uint32_t snd_nxt;

	if ((pkt = fos->first_unsent) == NULL)
		return;

	if (fos->dup_ack > DUP_ACK_THRESHOLD) {
		/* RFC5681 3.2.4 */
		fos->cwnd += fos->mss;
		only_one_packet = false;
		win_end = get_snd_win_end(fos, 0);
	} else {
		/* RFC5681 3.2.1 */
		only_one_packet = true;
		win_end = get_snd_win_end(fos, 2 * fos->mss);
	}

#ifdef DEBUG_RFC5681
	printf("[%s] FastRecovery(%d), sending more packets, only_one:%d win_end:%u(%u)\n",
	       _spfx(fos), fos->dup_ack, only_one_packet, win_end, win_end - fos->snd_una);
#endif

	/* If dup_ack > threshold, RFC5681 3.2.5 - we can send up to MSS bytes if within limits */
	bytes_sent = 0;
	while (!after(segend(pkt), win_end) &&
	       bytes_sent + pkt->seglen <= fos->mss) {
#ifdef DEBUG_RFC5681
		printf("    sending seq %u len %u fl 0x%x\n", pkt->seq, pkt->seglen, pkt->flags);
#endif

#ifdef DEBUG_CHECKSUM
		check_checksum(pkt, "SENDING");
#endif
		if (!(pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_QUEUED_SEND))) {
			assert(send_tcp_pkt(w, pkt, fos, tr->foos, "DupAckSendMore"));

			/* advance fos->snd_nxt */
			snd_nxt = segend(pkt);
#ifdef DEBUG_SND_NXT
			printf("[%s] snd_nxt(fastrec) send pkt %u, snd_nxt %u => %u (+%u)\n",
			       _spfx(fos), pkt->seq, fos->snd_nxt, snd_nxt, snd_nxt - fos->snd_nxt);
#endif
			if (after(snd_nxt, fos->snd_nxt))
				fos->snd_nxt = snd_nxt;
		}

		if (list_is_last(&pkt->list, &fos->pktlist)) {
			fos->first_unsent = NULL;
			return;
		}
		bytes_sent += pkt->seglen;
		pkt = list_next_entry(pkt, list);
		if (only_one_packet)
			break;
	}
	fos->first_unsent = pkt;
}

static inline void
tr_recv_dup_ack_pkt(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_side *fos)
{
	struct tfo_pkt *send_pkt;

	if (list_empty(&fos->pktlist)) {
		printf("[%s] ERROR receiving dup_ack, but pktlist is empty!!!\n", _spfx(fos));
		return;
	}
	send_pkt = list_first_entry(&fos->pktlist, struct tfo_pkt, list);

#ifdef DEBUG_RFC5681
	printf("[%s] receiving dup_ack(%d), snd_una:%u seq:%u\n",
	       _spfx(fos), fos->dup_ack + 1, fos->snd_una, send_pkt->seq);
#endif

	if (after(send_pkt->seq, fos->snd_una)) {
		/* We haven't got the next packet, but have subsequent packets.
		 * The dup_ack process will be triggered, so we need to trigger it
		 * to the other side. */
		/* OG: should never happen ?  */
#ifdef DEBUG_RFC5681
		printf("[%s] REQUESTING missing packet 0x%x by sending ACK to other side\n",
		       _spfx(fos), send_pkt->seq);
#endif
		tr->foos_send_ack = true;
	}

	/* RFC5681 and errata state that the rx_win should be the same -
	 *    fos->snd_win == rte_be_to_cpu_16(tcp->rx_win) */
	/* This counts pure ack's, i.e. no data, and ignores ACKs with data.
	 * RFC5681 doesn't state that the SEQs should all be the same, and I
	 * don't think that is necessary since we check seglen == 0. */

	/* RFC5681 3.2 - fast recovery */
	if (++fos->dup_ack == DUP_ACK_THRESHOLD) {

		/* We have the first packet, so resend it */
		if (fos->snd_una == send_pkt->seq) {
#ifdef DEBUG_RFC5681
			printf("RESENDING m %p seq 0x%x, len %u due to 3 duplicate ACKS\n",
			       send_pkt, send_pkt->seq, send_pkt->seglen);
#endif

#ifdef DEBUG_CHECKSUM
			check_checksum(send_pkt, "RESENDING");
#endif
			send_tcp_pkt(w, send_pkt, fos, tr->foos, "DupAck");
		}

		/* RFC5681 3.2.2 */
		fos->ssthresh = max((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
		fos->cwnd = fos->ssthresh + DUP_ACK_THRESHOLD * fos->mss;

		if (!(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
			fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
			fos->recovery_end_seq = fos->snd_una + 1;
#ifdef DEBUG_RECOVERY
			printf("[%s] Entering fast recovery, end %u\n",
			       _spfx(fos), fos->recovery_end_seq);
#endif
		}

	} else {
		tr_send_in_fast_recovery(w, tr, fos);
	}
}


static inline void
tr_update_after_ack(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_side *fos,
		 uint32_t pkts_ackd, time_ns_t newest_send_time)
{
	struct tfo_pkt *pkt;
	uint32_t win_end;

	if (newest_send_time) {
		/* We are using timestamps */
		update_rto_ts(fos, newest_send_time, pkts_ackd);

		/* 300 = /proc/sys/net/ipv4/tcp_min_rtt_wlen. Kernel passes 2nd and 3rd parameters in jiffies (1000 jiffies/sec on x86_64).
		   We record rtt_min in usecs  */
		minmax_running_min(&fos->rtt_min,
				   config->tcp_min_rtt_wlen * USEC_PER_MSEC,
				   now / NSEC_PER_USEC,
				   (now - newest_send_time) / NSEC_PER_USEC);
	}

	/* if (fos->dup_ack && fos->dup_ack < DUP_ACK_THRESHOLD) */
	/* 	tr_send_in_fast_recovery(w, tr, fos); */

	/* Window scaling is rfc7323 */
	win_end = fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift);

	if (fos->snd_una == tr->ack && !list_empty(&fos->pktlist)) {
		pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
		if (pkt->flags & TFO_PKT_FL_SENT &&
		    now > packet_timeout(pkt->ns, fos->rto_us) &&
		    !after(segend(pkt), win_end)) {
#ifdef DEBUG_ACK
			printf("Resending seq 0x%x due to repeat ack and timeout, now %lu, rto %u, pkt tmo %lu\n",
			       tr->ack, now, fos->rto_us, packet_timeout(pkt->ns, fos->rto_us));
#endif
			send_tcp_pkt(w, list_first_entry(&fos->pktlist, typeof(*pkt), list), fos, tr->foos, "ResendAckTo");
		}
	}

}


/* XXX check if ack field is correctly filled at this time */
static inline void
tr_resend_timed_out_packets(struct tcp_worker *w, struct tfo_pktrx_ctx *tr,
			    struct tfo_side *fos, struct tfo_side *foos)
{
	struct tfo_pkt *pkt;

	/* call before rto timer fire (it has a poor resolution) */
	if (!list_empty(&fos->xmit_ts_list)) {
		pkt = list_first_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);
		if (unlikely(packet_timeout(pkt->ns, fos->rto_us) < now)) {
			send_tcp_pkt(w, pkt, fos, foos, "RTO-N");
			on_rto_timeout(fos, pkt);
			tr->fos_send_ack = false;
		}
	}

	/* same thing on the other side */
	if (!list_empty(&foos->xmit_ts_list)) {
		pkt = list_first_entry(&foos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);
		if (unlikely(packet_timeout(pkt->ns, foos->rto_us) < now)) {
			send_tcp_pkt(w, pkt, foos, fos, "RTO-OT");
			on_rto_timeout(foos, pkt);
			tr->foos_send_ack = false;
		}
	}
}

/*
 * RTO code when SACK/RACK is not in use
 * RFC6298 5.4
 */
static void
handle_rto(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos)
{
	struct tfo_pkt *pkt;

	if (unlikely(list_empty(&fos->xmit_ts_list))) {
		printf("[%s] ERROR RTO timeout handler with empty xmit_ts_list\n", _spfx(fos));
		return;
	}

	pkt = list_first_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);
	send_tcp_pkt(w, pkt, fos, foos, "RTO-T");
	on_rto_timeout(fos, pkt);
}



/****************************************************************************/
/* SACK/RACK CODE (RFC8985) */
/****************************************************************************/



static inline bool
rack_sent_after(time_ns_t t1, time_ns_t t2, uint32_t seq1, uint32_t seq2)
{
	return t1 > t2 || (t1 == t2 && after(seq1, seq2));
}


/* RFC8985  Step 2 (for one packet) */
static inline void
update_most_recent_acked_pkt(struct tfo_pktrx_ctx *tr, struct tfo_side *fos,
			     struct tfo_pkt *pkt, bool using_ts, uint32_t ack_ts_ecr)
{
	if (!rack_sent_after(pkt->ns, tr->most_recent_ns,
			     segend(pkt), tr->most_recent_seqend))
		return;

	if (pkt->flags & TFO_PKT_FL_RESENT) {
		if (using_ts) {
			/* RFC8985 Step 2 point 1 */
			if (after(rte_be_to_cpu_32(pkt->ts->ts_val), ack_ts_ecr))
				return;
		}

		/* RFC8985 Step 2 point 2 */
		if (after(pkt->ns + minmax_get(&fos->rtt_min), now))
			return;
	}

	tr->most_recent_ns = pkt->ns;
	tr->most_recent_seqend = segend(pkt);
}

/* RFC8985 Step 3: Detect data segment reordering (for one packet) */
static inline void
rack_detect_reordering(struct tfo_side *fos, struct tfo_pkt *pkt)
{
	if (after(segend(pkt), fos->rack_fack)) {
		fos->rack_fack = segend(pkt);

	} else if (before(segend(pkt), fos->rack_fack) &&
		   !(pkt->flags & TFO_PKT_FL_RESENT)) {
#ifdef DEBUG_RACK_REO_WND
		printf("[%s] RACK reordering seen (pkt.seqend=%u rack.fack=%u)\n",
		       _spfx(fos), segend(pkt), fos->rack_fack);
#elif DEBUG_RACK
		if (!(fos->flags & TFO_SIDE_FL_RACK_REORDERING_SEEN))
			printf("[%s] RACK first reordering seen (pkt.seqend=%u rack.fack=%u)\n",
			       _spfx(fos), segend(pkt), fos->rack_fack);
#endif
		fos->flags |= TFO_SIDE_FL_RACK_REORDERING_SEEN;
	}
}

/* mark a tfo_pkt as sacked: remove mbuf, merge with contiguous sacked packets */
static inline void
rack_mark_sacked_packet(struct tcp_worker *w, struct tfo_side *fos, struct tfo_pkt *pkt)
{
	struct tfo_pkt *sack_pkt = NULL;
	struct tfo_pkt *next_pkt;

	/* free mbuf. we won't re-send this packet anymore (even for TLP) */
	pkt_free_mbuf(fos, pkt);

	/* This is being sack'd for the first time, and it can't be lost any more */
	pkt->rack_segs_sacked = 1;
	pkt->flags &= ~TFO_PKT_FL_LOST;

	/* previous packet was already sacked */
	if (!list_is_first(&pkt->list, &fos->pktlist) &&
	    list_prev_entry(pkt, list)->rack_segs_sacked) {
		sack_pkt = list_prev_entry(pkt, list);
		/* check there is no gap between them */
		if (pkt->seq != segend(sack_pkt))
			sack_pkt = NULL;
	}

	if (sack_pkt == NULL) {
		sack_pkt = pkt;
#ifdef DEBUG_SACK_RX
		printf("[%s] sack pkt now %u, len %u, segs_sacked: 1\n",
		       _spfx(fos), pkt->seq, pkt->seglen);
#endif

	} else {
		sack_pkt->rack_segs_sacked += pkt->rack_segs_sacked;
		sack_pkt->seglen = segend(pkt) - sack_pkt->seq;
		/* We want the earliest anything in the block was sent */
		if (sack_pkt->ns > pkt->ns)
			sack_pkt->ns = pkt->ns;

#ifdef DEBUG_SACK_RX
		printf("[%s] sack pkt updated %u, len %u segs_sacked %d; and free pkt %p\n",
		       _spfx(fos), sack_pkt->seq, sack_pkt->seglen,
		       sack_pkt->rack_segs_sacked, pkt);
#endif
		pkt->rack_segs_sacked = 0;
		pkt_free(w, fos, pkt);
	}

	/* If the following packet is a sack entry and there is no gap between this
	 * sack entry and the next, and the next entry extends beyond right_edge,
	 * merge them */
	if (!list_is_last(&sack_pkt->list, &fos->pktlist)) {
		next_pkt = list_next_entry(sack_pkt, list);
		if (next_pkt->rack_segs_sacked &&
		    !before(segend(sack_pkt), next_pkt->seq)) {
			next_pkt->seglen = segend(next_pkt) - sack_pkt->seq;
			next_pkt->seq = sack_pkt->seq;
			next_pkt->rack_segs_sacked += sack_pkt->rack_segs_sacked;
			/* We want the earliest anything in the block was sent */
			if (sack_pkt->ns < next_pkt->ns)
				next_pkt->ns = sack_pkt->ns;
#ifdef DEBUG_SACK_RX
			printf("[%s] sack free sack_pkt seq %u pkt %p\n",
			       _spfx(fos), sack_pkt->seq, sack_pkt);
#endif
			sack_pkt->rack_segs_sacked = 0;
			pkt_free(w, fos, sack_pkt);
		}
	}
}


/*
 * Step 2: Update the state for the most recently sent segment that has been delivered.
 *
 * SACK: RFC2018
 * D-SACK: RFC2883
 *
 * also do step 3.
 */
static inline void
rack_update(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_side *fos)
{
	uint32_t ack_ts_ecr;
	struct tfo_pkt *pkt, *pkt_tmp;
	uint32_t pkts_ackd = 0;
	bool using_ts;
#if defined DEBUG_RACK_SACKED || defined DEBUG_RACK
	uint32_t old_rack_segs_sacked = fos->rack_total_segs_sacked;
#endif

	tr->most_recent_ns = 0;
	tr->most_recent_seqend = 0;

	if (tr->ts_opt) {
		ack_ts_ecr = rte_be_to_cpu_32(tr->ts_opt->ts_ecr);
		using_ts = true;
	} else {
		ack_ts_ecr = 0;
		using_ts = false;
	}

	/* Mark all cumulatively ack'd packets */
	list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
		if (after(segend(pkt), tr->ack))
			break;

		fos->flags |= TFO_SIDE_FL_ACKED_DATA;

		/* not previously sacked */
		if (!pkt->rack_segs_sacked) {
			pkts_ackd++;

			update_most_recent_acked_pkt(tr, fos, pkt, using_ts, ack_ts_ecr);
			rack_detect_reordering(fos, pkt);

			if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
				update_rto(fos, pkt->ns);
				pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
				fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
			}
		}

		/* we don't need it anymore */
		pkt_free(w, fos, pkt);
	}

	/* Mark all selectively acked packets as sacked */
	if (tr->sack_opt) {
		uint32_t sack_blocks[MAX_SACK_ENTRIES][2];
		uint8_t sack_idx[MAX_SACK_ENTRIES];
		uint8_t tmp_sack_idx;
		uint32_t left_edge, right_edge;
		uint8_t num_sack_ent;
		uint8_t i, j;
		bool have_dsack = false;

// For elsewhere - if get SACK and !resent snd_una packet recently (whatever that means), resent unack'd packets not recently resent.
// If don't have them, send ACK to other side if not sending packets
		num_sack_ent = (tr->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges);
#ifdef DEBUG_SACK_RX
		printf("[%s] Rack update SACK with %u entries\n", _spfx(fos), num_sack_ent);
#endif

		for (i = 0; i < num_sack_ent; i++) {
			sack_blocks[i][0] = rte_be_to_cpu_32(tr->sack_opt->edges[i].left_edge);
			sack_blocks[i][1] = rte_be_to_cpu_32(tr->sack_opt->edges[i].right_edge);
			sack_idx[i] = i;
		}

		/* See RFC2883 4.1 and 4.2. For a DSACK, either first SACK entry is before ACK
		 * or it is a (not necessarily proper) subset of the second SACK entry */
		if (before(rte_be_to_cpu_32(tr->sack_opt->edges[0].left_edge), tr->ack)) {
			if (!((fos->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) && fos->tlp_end_seq == tr->ack))
				fos->flags |= TFO_SIDE_FL_DSACK_SEEN;
			have_dsack = true;
		} else if (num_sack_ent > 1 &&
			   !before(sack_blocks[0][0], sack_blocks[1][0]) &&
			   !after(sack_blocks[0][1], sack_blocks[1][1])) {
			if (!((fos->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) && fos->tlp_end_seq == tr->ack))
				fos->flags |= TFO_SIDE_FL_DSACK_SEEN;
			have_dsack = true;
		}

		if (have_dsack) {
#ifdef DEBUG_RACK_SACKED
			printf("[%s] DSACK seen", _spfx(fos));
			for (i = 0; i < num_sack_ent; i++)
				printf(" [%u] %u -> %u", i, sack_blocks[i][0], sack_blocks[i][1]);
			printf("\n");
#endif
			/* discard the DSACK entry (the first block, others are SACK info) */
			for (i = 1; i < num_sack_ent; i++)
				sack_idx[i - 1] = i;
			--num_sack_ent;
		}

		if (num_sack_ent > 0) {
			/* bubble sort - max 6 comparisons (3 if TS option) - think n(n - 1)/2 */
			for (j = num_sack_ent - 1; j > 0; j--) {
				for (i = 0; i < j; i++) {
					if (after(sack_blocks[sack_idx[i]][0], sack_blocks[sack_idx[i + 1]][0])) {
						tmp_sack_idx = sack_idx[i + 1];
						sack_idx[i + 1] = sack_idx[i];
						sack_idx[i] = tmp_sack_idx;
					}
				}
			}

#ifdef DEBUG_SACK_RX
			printf(" sorted SACK - ");
			for (i = 0; i < num_sack_ent; i++)
				printf("%s%u -> %u", i ? "    " : "", sack_blocks[sack_idx[i]][0], sack_blocks[sack_idx[i]][1]);
			printf("\n");
#endif

			left_edge = sack_blocks[sack_idx[0]][0];
			right_edge = sack_blocks[sack_idx[0]][1];
			i = 0;
#ifdef DEBUG_SACK_RX
			printf("  %u: %u -> %u\n", sack_idx[i], left_edge, right_edge);
#endif
			list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
				/* Check if we need to move on to the next sack block */
				while (after(segend(pkt), right_edge)) {
#ifdef DEBUG_SACK_RX
					printf("     %u + %u (%u) after window\n",
						pkt->seq, pkt->seglen, segend(pkt));
#endif
					if (++i == num_sack_ent)
						break;

					left_edge = sack_blocks[sack_idx[i]][0];
					right_edge = sack_blocks[sack_idx[i]][1];
#ifdef DEBUG_SACK_RX
					printf("  %u: %u -> %u\n", sack_idx[i], left_edge, right_edge);
#endif
				}

				if (i == num_sack_ent)
					break;

				if (pkt->rack_segs_sacked) {
#ifdef DEBUG_SACK_RX
					if (!before(pkt->seq, left_edge))
						printf("     %u + %u (%u) already SACK'd in window\n",
							pkt->seq, pkt->seglen, segend(pkt));
#endif
					continue;
				}

				if (before(pkt->seq, left_edge))
					continue;

#ifdef DEBUG_SACK_RX
				printf("     %u + %u (%u) in window\n",
					pkt->seq, pkt->seglen, segend(pkt));
#endif

				fos->rack_total_segs_sacked++;
				pkts_ackd++;

				update_most_recent_acked_pkt(tr, fos, pkt, using_ts, ack_ts_ecr);
				rack_detect_reordering(fos, pkt);

				if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
					update_rto(fos, pkt->ns);
					pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
					fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
				}

				rack_mark_sacked_packet(w, fos, pkt);
			}
		}
#ifdef DEBUG_RACK
		if (have_dsack || old_rack_segs_sacked != fos->rack_total_segs_sacked) {
			printf("[%s] RACK fos->segs_sack %u -> %u (have_dsack:%d)\n",
			       _spfx(fos), fos->rack_total_segs_sacked, old_rack_segs_sacked,
			       have_dsack);
		}
#endif

	}

// Why are we doing this here?
	if (tlp_process_ack(tr->ack, tr, fos)) {
//		invoke_congestion_control(fos);
		/* In tcp_process_tlp_ack() in tcp_input.c:
			tcp_init_cwnd_reduction(sk);
			tcp_set_ca_state(sk, TCP_CA_CWR);
			tcp_end_cwnd_reduction(sk);
			tcp_try_keep_open(sk);
		 */
	}

	if (tr->most_recent_ns) {
		/* RFC8985 Step 1 */
		if (using_ts)
			update_rto_ts(fos, tr->most_recent_ns, pkts_ackd);

		/* 300 = /proc/sys/net/ipv4/tcp_min_rtt_wlen. Kernel passes 2nd and 3rd parameters in jiffies (1000 jiffies/sec on x86_64).
		   We record rtt_min in usecs  */
		minmax_running_min(&fos->rtt_min, config->tcp_min_rtt_wlen * USEC_PER_MSEC,
				   now / NSEC_PER_USEC, (now - tr->most_recent_ns) / NSEC_PER_USEC);

		/* RFC8985 Step 2 */
		fos->rack_rtt_us = (now - tr->most_recent_ns) / NSEC_PER_USEC;
		if (rack_sent_after(tr->most_recent_ns, fos->rack_xmit_ts, tr->most_recent_seqend, fos->rack_end_seq)) {
			fos->rack_xmit_ts = tr->most_recent_ns;
			fos->rack_end_seq = tr->most_recent_seqend;
		}
	}
}


/* RFC8985 Step 4: Update the RACK reordering window */
static inline uint32_t
rack_update_reo_wnd(struct tfo_side *fos, uint32_t ack)
{
	uint32_t reo_to;

	if (fos->flags & TFO_SIDE_FL_DSACK_ROUND) {
		if (before(ack, fos->rack_dsack_round))
			fos->flags &= ~TFO_SIDE_FL_DSACK_SEEN;
		else
			fos->flags &= ~TFO_SIDE_FL_DSACK_ROUND;
	}

	if ((fos->flags & (TFO_SIDE_FL_DSACK_SEEN | TFO_SIDE_FL_DSACK_ROUND)) == TFO_SIDE_FL_DSACK_SEEN) {
		fos->flags &= ~TFO_SIDE_FL_DSACK_SEEN;
		fos->flags |= TFO_SIDE_FL_DSACK_ROUND;
		fos->rack_dsack_round = fos->snd_nxt;
		fos->rack_reo_wnd_mult++;
		fos->rack_reo_wnd_persist = 16;
#ifdef DEBUG_RACK_REO_WND
		printf("[%s] reo_wnd: dsack seen, set mult %d persist %d round %u\n",
		       _spfx(fos), fos->rack_reo_wnd_mult, fos->rack_reo_wnd_persist,
		       fos->rack_dsack_round);
#endif

	} else if (fos->flags & TFO_SIDE_FL_ENDING_RECOVERY) {
		if (fos->rack_reo_wnd_persist)
			fos->rack_reo_wnd_persist--;
		if (!fos->rack_reo_wnd_persist)
			fos->rack_reo_wnd_mult = 1;
#ifdef DEBUG_RACK_REO_WND
		printf("[%s] reo_wnd: rack ending recovery, set mult %d persist %d\n",
		       _spfx(fos), fos->rack_reo_wnd_mult, fos->rack_reo_wnd_persist);

#endif
	}

	if (!(fos->flags & TFO_SIDE_FL_RACK_REORDERING_SEEN) &&
	    ((fos->flags & TFO_SIDE_FL_IN_RECOVERY) ||
	     fos->rack_total_segs_sacked >= DUP_ACK_THRESHOLD)) {
#ifdef DEBUG_RACK_REO_WND
		if (fos->rack_reo_wnd_us > 0) {
			printf("[%s] RACK compute reo_wnd_to set to 0, fos->flags 0x%x, "
			       "seg_sacked %d, reo_to was %d us\n",
			       _spfx(fos), fos->flags, fos->rack_total_segs_sacked, fos->rack_reo_wnd_us);
		}
#endif
		return 0;
	}

	reo_to = fos->rack_reo_wnd_mult * minmax_get(&fos->rtt_min) / 4;

#ifdef DEBUG_RACK_REO_WND
	printf("[%s] RACK compute reo_wnd_to: reo_to %d us srtt %d us"
	       " (mult %d rtt_min %d) was: %d\n",
	       _spfx(fos), reo_to, fos->srtt_us, fos->rack_reo_wnd_mult, minmax_get(&fos->rtt_min),
	       fos->rack_reo_wnd_us);
#endif

	return min(reo_to, fos->srtt_us);
}

static inline void
rack_mark_packet_lost(struct tfo_pkt *pkt, struct tfo_side *fos)
{
	pkt->flags |= TFO_PKT_FL_LOST;
	pkt->ns = TFO_TS_NONE;
	fos->pkts_in_flight--;

#ifdef DEBUG_IN_FLIGHT
	printf("[%s] rack_mark_packet_lost pkts_in_flight-- => %u\n",
	       _spfx(fos), fos->pkts_in_flight);
#endif

	if (fos->last_sent == &pkt->xmit_ts_list)
		fos->last_sent = pkt->xmit_ts_list.prev;

	list_move_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);
}

#if 0
static inline void
rack_remove_acked_sacked_packet(struct tcp_worker *w, struct tfo_side *fos, struct tfo_pkt *pkt, uint32_t ack)
{
	struct tfo_pkt *sack_pkt = NULL;
	struct tfo_pkt *next_pkt;

	/* Remove packets marked after the new ack */
	if (!after(segend(pkt), ack)) {
#if defined DEBUG_ACK || defined DEBUG_SACK_RX
		printf("  pk acked: pkt_free pkt %p m %p, seq %u\n", pkt, pkt->m, pkt->seq);
#endif
		pkt_free(w, fos, pkt);

		return;
	}

	/* previous packet was already sacked */
	if (!list_is_first(&pkt->list, &fos->pktlist) &&
	    list_prev_entry(pkt, list)->rack_segs_sacked) {
		sack_pkt = list_prev_entry(pkt, list);
		/* check there is no gap between them */
		if (pkt->seq != segend(sack_pkt))
			sack_pkt = NULL;
	}

	/* free mbuf. we won't re-send this packet anymore (even for TLP) */
	pkt_free_mbuf(fos, pkt);

	/* This is being sack'd for the first time, and it can't be lost any more */
	pkt->rack_segs_sacked = 1;
	pkt->flags &= ~(TFO_PKT_FL_SACKED | TFO_PKT_FL_LOST);

	if (sack_pkt == NULL) {
		sack_pkt = pkt;
#ifdef DEBUG_SACK_RX
		printf("[%s] sack pkt now %u, len %u, segs_sacked: 1\n",
		       _spfx(fos), pkt->seq, pkt->seglen);
#endif

	} else {
		sack_pkt->rack_segs_sacked += pkt->rack_segs_sacked;
		sack_pkt->seglen = segend(pkt) - sack_pkt->seq;
		/* We want the earliest anything in the block was sent */
		if (sack_pkt->ns > pkt->ns)
			sack_pkt->ns = pkt->ns;

#ifdef DEBUG_SACK_RX
		printf("[%s] sack pkt updated %u, len %u segs_sacked %d; and free pkt %p\n",
		       _spfx(fos), sack_pkt->seq, sack_pkt->seglen,
		       sack_pkt->rack_segs_sacked, pkt);
#endif
		pkt->rack_segs_sacked = 0;
		pkt_free(w, fos, pkt);
	}

	/* If the following packet is a sack entry and there is no gap between this
	 * sack entry and the next, and the next entry extends beyond right_edge,
	 * merge them */
	if (!list_is_last(&sack_pkt->list, &fos->pktlist)) {
		next_pkt = list_next_entry(sack_pkt, list);
		if (next_pkt->rack_segs_sacked &&
		    !before(segend(sack_pkt), next_pkt->seq)) {
			sack_pkt->seglen = segend(next_pkt) - sack_pkt->seq;
			sack_pkt->rack_segs_sacked += next_pkt->rack_segs_sacked;
			/* We want the earliest anything in the block was sent */
			if (next_pkt->ns < sack_pkt->ns)
				sack_pkt->ns = next_pkt->ns;
#ifdef DEBUG_SACK_RX
			printf("[%s] sack free next_pkt seq %u pkt %p\n",
			       _spfx(fos), next_pkt->seq, next_pkt);
#endif
			next_pkt->rack_segs_sacked = 0;
			pkt_free(w, fos, next_pkt);
		}
	}
}
#endif


/* RFC8985 Step 5: Detect losses */
static time_ns_t
rack_detect_loss(struct tcp_worker *w, struct tfo_side *fos, uint32_t ack)
{
#ifndef DETECT_LOSS_MIN
	time_ns_t timeout = 0;
#else
	time_ns_t timeout = UINT64_MAX;
#endif
	time_ns_t first_timeout;
	struct tfo_pkt *pkt, *pkt_tmp;
#ifdef DEBUG_XMIT_LIST
	unsigned pkt_count = 0, start_pkt_count = fos->pktcount;
#endif
	uint32_t lost_pkt_n = 0;
	uint32_t sacked_pkts = 0;

	if (list_empty(&fos->pktlist))
		return 0;

	first_timeout = now - (fos->rack_rtt_us + fos->rack_reo_wnd_us) * NSEC_PER_USEC;

#ifdef DEBUG_RACK_LOSS
	printf("[%s] rack_detect_loss ack %u first_timeout " NSEC_TIME_PRINT_FORMAT " rack_rtt %u rack_reo_wnd %u\n",
	       _spfx(fos), ack, NSEC_TIME_PRINT_PARAMS(first_timeout), fos->rack_rtt_us, fos->rack_reo_wnd_us);
#endif

#ifdef DEBUG_XMIT_LIST
	check_xmit_ts_list(fos);
#endif

	list_for_each_entry_safe(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
		/* stop processing once we reach the first lost packet */
		if (pkt->flags & TFO_PKT_FL_LOST)
			break;

#if 0
		/* NOTE: if we send packets out of sequence in the same batch (with same pkt->ns),
		 * then we may skip packets that could be sacked. */
		if (!rack_sent_after(fos->rack_xmit_ts, pkt->ns, fos->rack_end_seq, segend(pkt)))
			break;
#else
		/* loop on all same pkt->ns */
		if (pkt->ns > fos->rack_xmit_ts)
			break;
		if (!rack_sent_after(fos->rack_xmit_ts, pkt->ns, fos->rack_end_seq, segend(pkt)))
			continue;
#endif

#ifdef DEBUG_XMIT_LIST
		if (++pkt_count > start_pkt_count) {
			/* Something has gone wrong here */
			printf("xmit_pkt_list ERROR fos %p pkt %p\n", fos, pkt);
			check_xmit_ts_list(fos);
			dump_eflow(fos->ef);
			printf("ERROR - fos %p pkt %p got to %uth packet on xmit_list but only %u packets queued\n", fos, pkt, pkt_count, fos->pktcount);
			break;
		}
#endif


#ifdef DEBUG_RACK_LOSS
		printf("  rack_xmit_ts " NSEC_TIME_PRINT_FORMAT " pkt->ns " NSEC_TIME_PRINT_FORMAT " seq %u rack_end_seq %u segend %u\n",
		       NSEC_TIME_PRINT_PARAMS(fos->rack_xmit_ts), NSEC_TIME_PRINT_PARAMS(pkt->ns),
		       pkt->seq, fos->rack_end_seq, segend(pkt));
#endif

		if (pkt->ns <= first_timeout) {
			rack_mark_packet_lost(pkt, fos);
			++lost_pkt_n;
		} else {
#ifndef DETECT_LOSS_MIN
			timeout = max(pkt->ns - first_timeout, timeout);
#else
			timeout = min(pkt->ns - first_timeout, timeout);
#endif
		}
	}

#ifdef DEBUG_RACK_SACKED
	list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
		sacked_pkts += pkt->rack_segs_sacked;
	}
	if (sacked_pkts != fos->rack_total_segs_sacked) {
		printf("ERROR *** pkt_seg_sacked %u != fos->tack_total_sefs_sacked %u\n",
		       sacked_pkts, fos->rack_total_segs_sacked);
		dump_eflow(fos->ef);
	}
#endif

#ifdef DETECT_LOSS_MIN
	if (timeout == UINT64_MAX)
		timeout = 0;
#endif

#ifdef DEBUG_RACK
	if (lost_pkt_n > 0) {
		printf("[%s] RACK mark %u packets as lost (xmit:%u+%u total:%u "
		       "rack_sacked:%u, nxt_timeout:%lu ns)\n",
		       _spfx(fos), lost_pkt_n, fos->pkts_in_flight, fos->pkts_queued_send,
		       fos->pktcount, fos->rack_total_segs_sacked, timeout);
	}
#endif

	if (lost_pkt_n > 0 && !(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
		/* RFC8985 step 4, entering fast recovery */
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->recovery_end_seq = fos->rack_fack;

#ifdef DEBUG_RECOVERY
		printf("[%s] Entering rack loss recovery, end_seq %u\n",
		       _spfx(fos), fos->recovery_end_seq);
		uint32_t sav_snd_una = fos->snd_una;
		fos->snd_una = ack;
		dump_details(w);
		//dump_eflow(ef);
		fos->snd_una = sav_snd_una;
#endif
	}

#ifdef DEBUG_RACK_LOSS
	printf("[%s] ~rack_detect_loss, timeout %lu\n", _spfx(fos), timeout);
#endif

	return timeout;
}

static void
rack_detect_loss_and_arm_timer(struct tcp_worker *w, struct tfo_side *fos, uint32_t ack)
{
	time_ns_t timeout;

	timeout = rack_detect_loss(w, fos, ack);

#ifdef DEBUG_RACK
	/* sanity check: timeout should only be set if there are sacked segs */
	if (timeout > 0 && !fos->rack_total_segs_sacked) {
		printf("[%s] ERROR rack reo timer: timeout: %lu rack_segs: %u\n",
		       _spfx(fos), timeout, fos->rack_total_segs_sacked);
	}
#endif

	if (timeout > 0) {
#ifdef DEBUG_TIMERS
		printf("[%s] overwrite timer %s => REO (timeout %.6f sec)\n",
		       _spfx(fos), get_timer_name(fos->cur_timer),
		       (double)timeout / NSEC_PER_SEC);
#endif
		/* overwrite current timer */
		fos->cur_timer = TFO_TIMER_REO;
		fos->timeout_at = now + timeout;

	} else if (fos->cur_timer == TFO_TIMER_REO) {
#ifdef DEBUG_TIMERS
		printf("[%s] reset timer REO => NONE\n", _spfx(fos));
#endif
		fos->cur_timer = TFO_TIMER_NONE;
	}
}


static void
rack_resend_lost_packets(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos)
{
	struct tfo_pkt *pkt, *pkt_tmp;
#ifdef DEBUG_RACK
	uint32_t count = 0;
#endif

	if (list_empty(&fos->xmit_ts_list)) {
#ifdef DEBUG_LAST_SENT
		if (fos->last_sent != &fos->xmit_ts_list)
			printf("ERROR - fos %p xmit_ts_list empty last_sent %p != &fos->xmit_ts_list %p\n",
			       fos, fos->last_sent, &fos->xmit_ts_list);
#endif
		return;
	}

	pkt = list_entry(fos->last_sent, struct tfo_pkt, xmit_ts_list);
	list_for_each_entry_safe_continue(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
		if (pkt->flags & TFO_PKT_FL_LOST) {
#ifdef DEBUG_RACK
			if (send_tcp_pkt(w, pkt, fos, foos, "RackResend"))
				count++;
#else
			send_tcp_pkt(w, pkt, fos, foos, "RackResend");
#endif
		} else {
			printf("[%s] rack_resend_lost_pkt: hey pkt should be lost!!!\n", _spfx(fos));
		}
	}
#ifdef DEBUG_RACK
	if (count)
		printf("[%s] rack: %u lost pkt were re-sent\n", _spfx(fos), count);
#endif
}


/*
 * 6.2: Upon Receiving an ACK
 *
 * called from tfo_handle_pkt()
 */
static void
do_rack(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_side *fos)
{
	uint32_t pre_in_flight = fos->pkts_in_flight;

	rack_update(w, tr, fos);

	if (fos->flags & TFO_SIDE_FL_IN_RECOVERY &&
	    after(tr->ack, fos->recovery_end_seq)) {	// Alternative is fos->rack_segs_sacked == 0
#if defined DEBUG_RACK || defined DEBUG_RECOVERY
		printf("[%s] Ending RACK recovery\n", _spfx(fos));
#endif
		fos->flags |= TFO_SIDE_FL_ENDING_RECOVERY;
		fos->flags &= ~TFO_SIDE_FL_IN_RECOVERY;
	}

	fos->rack_reo_wnd_us = rack_update_reo_wnd(fos, tr->ack);

	rack_detect_loss_and_arm_timer(w, fos, tr->ack);

	/* send lost packets again */
	if (fos->pkts_in_flight < pre_in_flight) {
#ifdef DEBUG_IN_FLIGHT
		printf("[%s] do_rack() pkts_in_flight %u => %u, resend lost pkts\n",
		       _spfx(fos), pre_in_flight, fos->pkts_in_flight);
#endif
		rack_resend_lost_packets(w, fos, tr->foos);
	}

	/* no reordering, and 3 sacked segment */
	/* XXX: Should we check for needing to continue in recovery, or starting it again? */
	if (!(fos->flags & (TFO_SIDE_FL_IN_RECOVERY | TFO_SIDE_FL_RACK_REORDERING_SEEN)) &&
	    fos->rack_total_segs_sacked >= DUP_ACK_THRESHOLD) {
		/* RFC8985 Step 4 */
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->recovery_end_seq = fos->snd_nxt;

#if defined DEBUG_RACK || defined DEBUG_RECOVERY
		printf("[%s] Entering RACK no reordering recovery, end %u\n",
		       _spfx(fos), fos->recovery_end_seq);
#endif
	}
}


/*
 * 6.3.  Upon RTO Expiration
 * See RFC8985 5.4 and 8 re managing timers
 */
static void
rack_mark_losses_on_rto(struct tfo_side *fos)
{
	struct tfo_pkt *pkt, *pkt_tmp;
	time_ns_t timeout = (fos->rack_rtt_us + fos->rack_reo_wnd_us) * NSEC_PER_USEC;

	if (unlikely(list_empty(&fos->xmit_ts_list))) {
		printf("[%s] ERROR Rack RTO timeout handler with empty xmit_ts_list\n", _spfx(fos));
		return;
	}

	pkt = list_first_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);
	on_rto_timeout(fos, pkt);

#ifdef DEBUG_RACK
	if (pkt->ns + timeout > now) {
		printf("[%s] RACK rto timeout fired, but first packet %u not timeou't"
		       "(rack_to:%u us, rto:%u us)\n",
		       _spfx(fos), pkt->seq, fos->rack_rtt_us + fos->rack_reo_wnd_us, fos->rto_us);
		dump_eflow(fos->ef);
	}
#endif
	/* set the latest sent packet (first in xmit_ts_list) as lost. unlike rfc state,
	 * it may not be pkt.seq == snd_una */
	rack_mark_packet_lost(pkt, fos);

	/* mark all timeout-ed packets as lost */
	list_for_each_entry_safe(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
		if ((pkt->flags & TFO_PKT_FL_LOST) || (pkt->ns + timeout > now))
			break;
		rack_mark_packet_lost(pkt, fos);
	}
}


// See Linux tcp_input.c tcp_clear_retrans() to tcp_try_to_open() for Recovery handling
static void
invoke_congestion_control(__attribute__((unused)) struct tfo_side *fos)
{
	/* RFC8985 7.4.2 says invoke congestion control response equivalent to a fast recovery.
	 * I presume this means some parts of RFC5681 3.2. The Linux code for this is in
	 * net/ipv4/tcp_input.c tcp_process_tlp_ack() and uses RFC6937. */

	/* See RFC8985 9.3 for recommendations */

	printf("INVOKE_CONGESTION_CONTROL called\n");
}

/* RFC8985 7.4.2 */
/* Returns true if need to invoke congestion control */
static inline bool
tlp_process_ack(uint32_t ack, struct tfo_pktrx_ctx *tr, struct tfo_side *fos)
{
	/* not probing, or ack for a previous packet (still probing) */
	if (!likely((fos->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) ||
		    before(ack, fos->tlp_end_seq)))
		return false;

	/* probe was sent with fresh data. now acked. */
	if (!(fos->flags & TFO_SIDE_FL_TLP_IS_RETRANS)) {
		fos->flags &= ~TFO_SIDE_FL_TLP_IN_PROGRESS;
		return false;
	}

	if (fos->flags & TFO_SIDE_FL_DSACK_SEEN &&
	    rte_be_to_cpu_32(tr->sack_opt->edges[0].right_edge) == fos->tlp_end_seq) {
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		return false;
	}

	if (after(ack, fos->tlp_end_seq)) {
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		invoke_congestion_control(fos);
		return true;
	}

	if (!after(ack, fos->snd_una) && !tr->sack_opt) {
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		return false;
	}

	return false;
}

/* 7.2: Scheduling a loss probe */
static time_ns_t
tlp_calc_pto(struct tfo_side *fos)
{
	time_ns_t pto, rto;

	if (unlikely(!fos->srtt_us))
		pto = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	else {
		pto = 2 * fos->srtt_us;
		if (fos->pkts_in_flight + fos->pkts_queued_send == 1)
			pto += fos->tlp_max_ack_delay_us;
	}
	pto *= NSEC_PER_USEC;

	/* if the rto would fire before, schedule a tlp at that time */
	if (fos->cur_timer == TFO_TIMER_RTO && fos->timeout_at > now)
		rto = fos->timeout_at - now;
	else
		rto = fos->rto_us * NSEC_PER_USEC;

	return min(rto, pto);
}

/*
 * 7.3: Sending a Loss Probe upon PTO Expiration
 *
 * called from timer context
 */
static void
tlp_send_probe(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos)
{
	struct tfo_pkt *next_pkt, *pkt;

#ifdef DEBUG_SEND_PROBE
	printf("[%s] entering tlp_send_probe, fos->flags 0x%x pkt_in_flight %u rack_segs_sacked: %u\n",
	       _spfx(fos), fos->flags, fos->pkts_in_flight, fos->rack_total_segs_sacked);
#endif

	/* send probe if:
	 *  1. no loss probe in flight
	 *  2. got a new rtt measurement */
	if ((fos->flags & (TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_NEW_RTT)) != TFO_SIDE_FL_TLP_NEW_RTT)
		return;

	/* get highest seq packet sent so far.
	 * if there is none, then it mean that no packet are sent, or this packet is sacked,
	 * and we should not have armed this timer */
	if ((pkt = fos->tlp_highest_sent_pkt) == NULL) {
#ifdef DEBUG_SEND_PROBE
		printf("[%s] ERROR tlp_highest_sent_pkt is NULL\n", _spfx(fos));
#endif
		return;
	}
	assert(pkt->m != NULL);

	/* send next packet if within receiver's window */
	if (!list_is_last(&pkt->list, &fos->pktlist)) {
		next_pkt = list_next_entry(pkt, list);
		if (!after(segend(next_pkt), get_snd_win_end(fos, fos->mss))) {
			pkt = next_pkt;
#ifdef DEBUG_SEND_PROBE
			printf("[%s] send next pkt as probe, seq %u snd_nxt %u\n",
			       _spfx(fos), pkt->seq, fos->snd_nxt);
#endif
		}
	}

#ifdef DEBUG_RACK
	printf("tlp_send_probe(%u)\n", pkt->seq);
#endif
	if (pkt == fos->tlp_highest_sent_pkt) {
		fos->flags |= TFO_SIDE_FL_TLP_IS_RETRANS;
#ifdef DEBUG_SEND_PROBE
		printf("[%s] send highest_seq sent pkt as probe (retransmit), seq %u snd_nxt %u\n",
		       _spfx(fos), pkt->seq, fos->snd_nxt);
#endif
		send_tcp_pkt(w, pkt, fos, foos, "LossProbeResent");

	} else {
		assert(send_tcp_pkt(w, pkt, fos, foos, "LossProbeNew"));

#ifdef DEBUG_SND_NXT
		printf("[%s] lossprobe send pkt seq %u, snd_nxt %u => %u (+%u)\n",
		       _spfx(fos), pkt->seq, fos->snd_nxt, segend(pkt), segend(pkt) - fos->snd_nxt);
#endif
		if (fos->first_unsent == pkt) {
			if (!list_is_last(&pkt->list, &fos->pktlist))
				fos->first_unsent = list_next_entry(pkt, list);
			else
				fos->first_unsent = NULL;
#ifdef DEBUG_SEND_PROBE
			printf("[%s]  and set fos->first_unset to seq %u\n",
			       _spfx(fos), fos->first_unsent != NULL ? fos->first_unsent->seq : 0);
#endif
		}

		if (after(segend(pkt), fos->snd_nxt))
			fos->snd_nxt = segend(pkt);
	}

	fos->tlp_end_seq = fos->snd_nxt;
	fos->flags |= TFO_SIDE_FL_TLP_IN_PROGRESS;
	fos->flags &= ~TFO_SIDE_FL_TLP_NEW_RTT;
}



/****************************************************************************/
/* RECEIVING RX PACKET / TCP HIGH LEVEL SM */
/****************************************************************************/


// *** Note: We may need to do more checking about whether the packet is just an ACK or has payload.
// *** Also check PSH isn't set if have no payload. Also URG.
// *** There is not below about an ACK (no payload) with the SEQ indicating missing packets.
// *** Generally we shouldn't ACK an ACK.
static enum tfo_pkt_state
tfo_handle_pkt(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_eflow *ef)
{
	struct tfo_side *fos, *foos;
	struct tfo_pkt *pkt;
	struct tfo_pkt *queued_pkt;
	time_ns_t newest_send_time;
	uint32_t pkts_ackd;
	uint32_t seq;
	uint32_t ack;
	struct rte_tcp_hdr* tcp = tr->tcp;
	enum seq_status seq_ok;
	uint32_t win_end;
	uint32_t new_snd_win;
	uint32_t old_snd_win;
#ifdef CWND_USE_ALTERNATE
	uint32_t incr;
#endif
	uint32_t dup_sack[2] = { 0, 0 };
	uint32_t ts_diff;


	if (unlikely(ef->priv == NULL || ef->pub == NULL)) {
		printf("ERROR tfo_handle_pkt called without flow\n");
		return TFO_PKT_FORWARD;
	}

	tr->fos_send_ack = false;
	tr->fos_must_ack = false;
	tr->foos_send_ack = false;
	tr->free_mbuf = false;
	tr->seq = seq = rte_be_to_cpu_32(tcp->sent_seq);
	tr->ack = ack = rte_be_to_cpu_32(tcp->recv_ack);

	if (tr->from_priv) {
		fos = ef->priv;
		tr->foos = foos = ef->pub;
	} else {
		fos = ef->pub;
		tr->foos = foos = ef->priv;
	}

#ifdef DEBUG_PKT_RX
	printf("[%s] RX (%s), seq:%u(%u) ack:%u(%u) len:%u tcp.rx_win:%d\n",
	       _spfx(fos), get_state_name(ef->state),
	       seq, seq - fos->first_seq, ack, ack - foos->first_seq, tr->seglen, rte_be_to_cpu_16(tcp->rx_win));
# ifdef DEBUG_TCP_WINDOW
	tfo_debug_print_eflow_window(ef);
# endif
#endif

#if defined DEBUG_PKT_DELAYS || defined DEBUG_DLSPEED
	if (tr->seglen && !(tr->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))) {
#if defined DEBUG_PKT_DELAYS
		/* There is payload */
		printf("[%s] pkt interval " NSEC_TIME_PRINT_FORMAT "\n", _spfx(fos),
		       NSEC_TIME_PRINT_PARAMS_ABS(now - fos->last_rx_data));
		fos->last_rx_data = now;
#endif

#ifdef DEBUG_DLSPEED
		update_speed_ring(fos, tr->seglen);
		printf("Transfer rate ");
		print_dl_speed(fos);
		printf("\n");
#endif
	}
#if defined DEBUG_PKT_DELAYS
	else if (!(tr->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))) {
		/* This is an ACK */
		printf("[%s] ACK interval " NSEC_TIME_PRINT_FORMAT "\n", _spfx(fos),
		       NSEC_TIME_PRINT_PARAMS_ABS(now - fos->last_rx_ack));
		fos->last_rx_ack = now;
	}
#endif
#endif

	/* Basic validity checks of packet - SEQ, ACK, options */
	if (!set_estab_options(tr, ef)) {
		/* There was something wrong with the options - stop optimizing. */
		clear_optimize(w, ef, tr, "estab_options");
		return TFO_PKT_FORWARD;
	}

	/* For a packet to be valid, it must meet the following:
	 *  1. Any timestamp must be no more than 2^31 beyond the last timestamp (PAWS)
	 *  2. seq >= rcv_nxt and seq + seglen < rcv_nxt + rcv_win << rcv_win_shift
	 *      or
	 *     seq no more that 2^30 before rcv_nxt (delayed duplicate packet)
	 *  3. ack <= snd_nxt
	 *	and
	 *     ack no more that 2^30 before snd_una (delayed duplicate ack)
	 */

	/* RFC7323 - 5.3 R1 - PAWS */
	if (tr->ts_opt && tr->seglen) {
		ts_diff = rte_be_to_cpu_32(fos->ts_recent) - rte_be_to_cpu_32(tr->ts_opt->ts_val);
		if (ts_diff > 0 && ts_diff < (1U << 31)) {
#ifdef DEBUG_PAWS
			printf("[%s] Packet PAWS seq %u NOT OK, ts_recent %u ts_val %u\n", _spfx(fos),
			       seq, rte_be_to_cpu_32(fos->ts_recent), rte_be_to_cpu_32(tr->ts_opt->ts_val));
#endif

			_send_ack_pkt_in(w, ef, fos, tr, tr->from_priv, foos, NULL, false);

			NO_INLINE_WARNING(rte_pktmbuf_free(tr->m));

			return TFO_PKT_HANDLED;
		}
	}

	/* Check the ACK is within the window, or a duplicate.
	 * We could remember the initial SEQ we sent and ensure it
	 * is not before that, until that becomes 2^31 ago */
	if (after(ack, fos->snd_nxt)
#ifdef DEBUG_EARLY_PACKETS
				     ||
	    (!(fos->flags & TFO_SIDE_FL_SEQ_WRAPPED) &&
	     before(ack, foos->first_seq))
#endif
					) {
//Had ack 0xc1c6b4b1 when snd_una == 0xc1c6b7fc. Ended up receiving an mbuf we already had queued. problem.001.log - search for HERE
#ifdef DEBUG_PKT_VALID
		dump_eflow(ef);
		dump_pkt_ctx_mbuf(tr);
		printf("Packet ef %p ack 0x%x not OK - ERROR\n", ef, ack);
#endif

		clear_optimize(w, ef, tr, "bad_ack");
		return TFO_PKT_FORWARD;
	}

	/* if the keepalive timer is running, restart it */
	if (fos->cur_timer == TFO_TIMER_KEEPALIVE)
		fos->cur_timer = TFO_TIMER_NONE;

	/* RFC9293 - 3.10 and cf./ PAWS R2 */
	win_end = fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift);
	seq_ok = check_seq(seq, tr->seglen, win_end, fos);

	if (seq_ok == SEQ_BAD) {
#ifdef DEBUG_BAD_SEQ
		printf("[%s] got SEQ_BAD ERROR, seq=%u-%u rcv_nxt=%u rcv_win=%d win_end=%u\n",
		       _epfx(ef, fos), seq, seq + tr->seglen, fos->rcv_nxt, fos->rcv_win, win_end);
#endif
#ifdef DEBUG_PKT_VALID
		if (fos->rcv_nxt - seq > (1U << 30)) {
			dump_eflow(ef);
			dump_pkt_ctx_mbuf(tr);
			printf("Packet seq %u not OK - ERROR\n", seq);
		}
#endif

		clear_optimize(w, ef, tr, "seq_bad");
		return TFO_PKT_FORWARD;
	}

	if (seq_ok == SEQ_OLD) {
		/* We have already had this packet */
		if (seq + 1 == fos->rcv_nxt &&
		    tr->seglen <= 1 &&
		    (tcp->tcp_flags & ~(RTE_TCP_ECE_FLAG | RTE_TCP_CWR_FLAG)) == RTE_TCP_ACK_FLAG) {
			/* This looks like a keepalive */
#ifdef DEBUG_KEEPALIVES
			printf("[%s] keepalive received\n", _spfx(fos));
#endif
		} else {
#ifdef DEBUG_BAD_SEQ
			printf("[%s] check_seq: old packet received: seq %u rcv_nxt %u seglen %u\n",
			       _spfx(fos), seq, fos->rcv_nxt, tr->seglen);
#endif
		}

		if (tr->seglen) {
			dup_sack[0] = seq;
			dup_sack[1] = seq + tr->seglen;
		}
		_send_ack_pkt_in(w, ef, fos, tr, tr->from_priv, foos, tr->seglen ? dup_sack : NULL, false);

		NO_INLINE_WARNING(rte_pktmbuf_free(tr->m));

		return TFO_PKT_HANDLED;
	}

	/* SEQ and ACK are now validated as within windows or recent duplicates, and options OK */

	/* If we have received a FIN on this side, we must not receive any later data. */
	if (unlikely(tcp->tcp_flags & RTE_TCP_FIN_FLAG)) {
/* Check seq + tr->seglen after rcv_nxt */
		tr->fos_must_ack = true;
		if (likely(!(fos->flags & TFO_SIDE_FL_FIN_RX))) {
			fos->flags |= TFO_SIDE_FL_FIN_RX;
			fos->fin_seq = seq + tr->seglen;
			++w->st.fin_pkt;
#ifdef DEBUG_FIN
			printf("[%s] Set fin_seq %u - seq %u seglen %u\n",
			       _spfx(fos), fos->fin_seq, seq, tr->seglen);
#endif
		} else {
			++w->st.fin_dup_pkt;
#ifdef DEBUG_FIN
			printf("[%s] Duplicate FIN\n", _spfx(fos));
#endif
		}

// DISCARD ANY QUEUED PACKETS WITH SEQ > SEQ of FIN
	}

	if (unlikely(!(tcp->tcp_flags & RTE_TCP_ACK_FLAG))) {
		/* This is invalid, unless RST */
		return TFO_PKT_FORWARD;
	}

	/* RFC 7323 4.3 (2) and PAWS R3 */
	if (tr->ts_opt) {
		if (after(rte_be_to_cpu_32(tr->ts_opt->ts_val), rte_be_to_cpu_32(fos->ts_recent)) &&
		    !after(seq, fos->last_ack_sent) &&
		    !before(seq, fos->rcv_nxt))
			fos->ts_recent = tr->ts_opt->ts_val;

		if (after(rte_be_to_cpu_32(tr->ts_opt->ts_val), fos->latest_ts_val)) {
			fos->latest_ts_val = rte_be_to_cpu_32(tr->ts_opt->ts_val);
#ifdef CALC_TS_CLOCK
			fos->latest_ts_val_time = now;
#ifdef DEBUG_USERS_TX_CLOCK
			unsigned long ts_delta = fos->latest_ts_val - fos->ts_start;
			unsigned long us_delta = (now - fos->ts_start_time) / NSEC_PER_USEC;

			printf("TS clock %lu ns for %lu tocks - %lu us per tock\n",
			       us_delta, ts_delta, (us_delta + ts_delta / 2) / ts_delta);
#endif
#endif
		}
	}

	/* We will check if the send window increased */
	old_snd_win = get_snd_win_end(fos, 0);

	/* Save the ttl/hop_limit to use when generating acks */
	fos->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? tr->iph.ip6h->hop_limits : tr->iph.ip4h->time_to_live;

#ifdef DEBUG_ZERO_WINDOW
	if (!fos->snd_win || !tcp->rx_win)
		printf("Zero window %s - %u -> %u\n", fos->snd_win ? "freed" : "set", fos->snd_win, (unsigned)rte_be_to_cpu_16(tcp->rx_win));
#endif

	fos->snd_win = rte_be_to_cpu_16(tcp->rx_win);

// *** If we receive an ACK and the SEQ is beyond what we have received,
// *** it indicates a missing packet. We should consider sending an ACK.
	if (using_rack(ef))
		do_rack(w, tr, fos);

	newest_send_time = 0;
	pkts_ackd = 0;
	if (between_beg_ex(ack, fos->snd_una, fos->snd_nxt)) {
		if (!using_rack(ef) &&
		    (fos->flags & TFO_SIDE_FL_IN_RECOVERY) &&
		    after(ack, fos->recovery_end_seq)) {
			fos->flags &= ~TFO_SIDE_FL_IN_RECOVERY;
#ifdef DEBUG_RECOVERY
			printf("[%s] ending recovery\n", _spfx(fos));
#endif
		}

		/* RFC5681 3.2 */
		if (fos->cwnd < fos->ssthresh) {
			/* Slow start */
			fos->cwnd += min(ack - fos->snd_una, fos->mss);
#ifndef CWND_USE_ALTERNATE
			fos->cum_ack = 0;
#endif
		} else {
			/* Congestion avoidance. */
#ifndef CWND_USE_ALTERNATE
			/* This is the recommended way in RFC5681 */
			fos->cum_ack += ack - fos->snd_una;
			if (fos->cum_ack >= fos->cwnd) {
				fos->cum_ack -= fos->cwnd;
				fos->cwnd += fos->mss;
			}
#else
			/* This is an approximation - eqn (3).
			 * There are better ways to do this. */
			incr = (fos->mss * fos->mss) / fos->cwnd;
			fos->cwnd += incr ? incr : 1;
#endif
		}

		/* RFC 5681 3.2.6 */
		if (unlikely(fos->dup_ack > 0)) {
#ifdef DEBUG_RFC5681
			printf("[%s] reset dup_ack %d => 0; cwnd = %u\n",
			       _spfx(fos), fos->dup_ack, fos->ssthresh);
#endif
			fos->cwnd = fos->ssthresh;
			fos->dup_ack = 0;
		}

		/* cumulatively ack packets */
		if (!using_rack(ef))
			tr_ack_pkts(tr, fos, &pkts_ackd, &newest_send_time);

		fos->snd_una = ack;

		if (unlikely((foos->flags & (TFO_SIDE_FL_FIN_RX | TFO_SIDE_FL_CLOSED)) == TFO_SIDE_FL_FIN_RX &&
			     list_empty(&fos->pktlist))) {
			/* An empty packet list means the FIN has been ack'd */
			foos->flags |= TFO_SIDE_FL_CLOSED;
#ifdef DEBUG_FIN
			printf("[%s] rcv fin and no packet, side now closed\n", _epfx(ef, foos));
#endif

			/* The other side is closed, If this side is closed, the connection
			 * is fully terminated. */
			if (fos->flags & TFO_SIDE_FL_CLOSED) {
				ef->idle_timeout = now;
#ifdef DEBUG_FLOW
				printf("[%s] both sides are FIN. free using idle_timeout\n", _spfx(fos));
#endif
				return TFO_PKT_HANDLED;
			}
		}

	} else if (!using_rack(ef)) {
		/* here either  ack < fos->snd_una  (reordered ack packet. ignored here)
		 *  or          ack == fos->snd_una (ack for duplicated packet)
		 * but not      ack > fos->snd_una  (impossible, checked before) */

		/* ack but snd_una not advanced, mean receiver has lost or duplicate (reordered) packets */
		if (ack == fos->snd_una && tr->seglen == 0)
			tr_recv_dup_ack_pkt(w, tr, fos);
	}

	/* Can we send more packets to fos due to ack or rx_win increased? */
	new_snd_win = get_snd_win_end(fos, 0);
	if (after(new_snd_win, old_snd_win)) {
		/* Can we open up the send window for the other side? */
		if (set_rcv_win(foos, fos))
			tr->foos_send_ack = true;

		tr_send_more_packets(w, fos, foos, new_snd_win);
	}

	if (!using_rack(ef))
		tr_update_after_ack(w, tr, fos, pkts_ackd, newest_send_time);

	/* If we are no longer optimizing, then the ACK is the only thing we want
	 * to deal with. */
	if (ef->state == TCP_STATE_CLEAR_OPTIMIZE) {
		/* If all our queued packets have been acked,
		 * we can go away */
		if (list_empty(&ef->priv->pktlist) && list_empty(&ef->pub->pktlist)) {
#ifdef DEBUG_FLOW
			printf("[%s] handle_packet, clear_optimize state. "
			       "no more packet, will free\n", _epfx(ef, NULL));
#endif
			ef->idle_timeout = now;
		}

		return TFO_PKT_FORWARD;
	}

// NOTE: RFC793 says SEQ + WIN should never be reduced - i.e. once a window is given
//  it will be able to be filled.
// BUT: RFC7323 2.4 says the window can be reduced (due to window scaling)
// This isn't right. dup_sack must be for seq, seq + seglen
// Can use dup_sack if segend(pkt) !after fos->rcv_nxt
// Also, if this duplicates SACK'd entries, we need seq, seq + seglen, then the SACK block for this
//   which we might already do

	/* OG: receiving duplicate packet. prepare DSACK info */
	if (using_rack(ef) && tr->seglen && before(seq, fos->rcv_nxt)) {
		dup_sack[0] = seq;
		if (!after(seq + tr->seglen, fos->rcv_nxt))
			dup_sack[1] = seq + tr->seglen;
		else if (list_empty(&foos->pktlist) ||
			 after(list_first_entry(&foos->pktlist, struct tfo_pkt, list)->seq, fos->rcv_nxt))
			dup_sack[1] = fos->rcv_nxt;
		else {
			list_for_each_entry(pkt, &foos->pktlist, list) {
				if (!before(segend(pkt), seq + tr->seglen)) {
					dup_sack[1] = seq + tr->seglen;
					break;
				}

				if (list_is_last(&pkt->list, &foos->pktlist) ||
				    before(segend(pkt), list_next_entry(pkt, list)->seq)) {
					dup_sack[1] = segend(pkt);
					break;
				}
			}
		}
	}

	/* Check no data received after FIN */
	if (unlikely((fos->flags & TFO_SIDE_FL_FIN_RX) &&
		     tr->seglen &&
		     after(seq + tr->seglen, fos->fin_seq))) {
		printf("ERROR pkt %p m %p seq 0x%x seglen %u has payload after fin_seq 0x%x\n", tr, tr->m, seq, tr->seglen, fos->fin_seq);

		/* Alternatively we could just discard this as an invalid packet */
		//	ret = TFO_PKT_FORWARD;
	}

	if (foos->rcv_win == 0 &&
	    before(foos->rcv_nxt, fos->snd_una + (fos->snd_win << fos->snd_win_shift))) {
		/* If the window is extended, (or at least not full),
		 * send an ack on foos */
		tr->foos_send_ack = true;
	}

	if (seq != fos->rcv_nxt) {
		/* RFC5681 3.2 - fast recovery */
#ifdef DEBUG_RFC5681
		printf("[%s] resending ack %u due to out of sequence packet %u\n",
		       _spfx(fos), fos->rcv_nxt, seq);
#endif
		/* RFC5681 3.2 - out of sequence, or fills a gap */
		tr->fos_must_ack = true;
	}

	if (tr->seglen) {
		queued_pkt = tr_queue_packet(w, tr, fos, foos, dup_sack);
	} else {
		/* It is an ACK with no data. */
		queued_pkt = NULL;
		tr->free_mbuf = true;
	}

	if (fos->rack_total_segs_sacked && tr->seglen)
		tr->fos_must_ack = true;

	if (!using_rack(ef))
		tr_resend_timed_out_packets(w, tr, fos, foos);

	tr_send_more_packets(w, foos, fos, get_snd_win_end(foos, 0));

#ifdef DEBUG_ACK
	printf("[%s] ACK status: fos_send_ack %d fos_must_ack %d foos_send_ack %d\n",
	       _spfx(fos), tr->fos_send_ack, tr->fos_must_ack, tr->foos_send_ack);
#endif

	if (tr->fos_send_ack || tr->fos_must_ack) {
		if (tr->seglen) {
			struct tfo_pkt unq_pkt;
			struct tfo_pkt *pkt_in = queued_pkt;
			if (queued_pkt == NULL || queued_pkt == PKT_IN_LIST) {
				pkt_in = &unq_pkt;
				unq_pkt.iph = tr->iph;
				unq_pkt.tcp = tr->tcp;
				unq_pkt.m = tr->m;
				unq_pkt.flags = tr->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
			}

			_send_ack_pkt(w, ef, fos, pkt_in, NULL, tr->from_priv, foos, dup_sack, false,
				      tr->fos_must_ack, false, false);
		} else
			_send_ack_pkt_in(w, ef, fos, tr, tr->from_priv, foos, dup_sack, false);
	}

	if (tr->foos_send_ack)
		_send_ack_pkt_in(w, ef, foos, tr, !tr->from_priv, fos, NULL, true);

	/* XXX check if it's true. we did stop tx timer. */
	if (list_empty(&fos->pktlist))
		assert(!fos->pkts_in_flight && !fos->pkts_queued_send);

	if (tr->free_mbuf) {
		NO_INLINE_WARNING(rte_pktmbuf_free(tr->m));
		tr->m = NULL;
	}

# ifdef DEBUG_TCP_WINDOW
	printf("[%s] end of packet RX\n", _spfx(fos));
	tfo_debug_print_eflow_window(ef);
# endif

	return TFO_PKT_HANDLED;
}



static inline void
set_estb_pkt_counts(struct tcp_worker *w, uint8_t flags)
{
	if (likely(flags & RTE_TCP_ACK_FLAG)) {
		if (unlikely(flags & RTE_TCP_PSH_FLAG))
			++w->st.estb_pushack_pkt;
		else
			++w->st.estb_ack_pkt;
	} else {
		if (unlikely(flags & RTE_TCP_PSH_FLAG))
			++w->st.estb_push_pkt;
		else
			++w->st.estb_noflag_pkt;
	}
}


// PQA - enum here, but order important
/*
 * state:
 *   TCP_STATE_SYN: syn seen	// See RFC793 for strange connection setup sequences
 *   TCP_STATE_SYN_ACK: syn+ack seen
 *   TCP_STATE_ESTABLISHED: established
 */
static enum tfo_pkt_state
tfo_tcp_sm(struct tcp_worker *w, struct tfo_pktrx_ctx *tr, struct tfo_eflow *ef)
{
	uint8_t tcp_flags = tr->tcp->tcp_flags;
	struct tfo_side *server_fo, *client_fo, *fos;
	uint32_t seq, ack;
	enum tfo_pkt_state ret = TFO_PKT_FORWARD;
	struct tfo_pkt *queued_pkt;

	_eflow_before_use(ef);

/* Can we do this via a lookup table:
 *
 * flag_lookup = tcp->flags & 0x07 | (tcp->flags & ACK ? 0x08 : 0);
 * new_state = state_chg[cur_state][flag_lookup];
 * if (new_state != cur_state) set_state();
 *
 * eflow_set_state will then alloc or de-alloc flow
 */

// Free eflow if state BAD/RST/???
#ifdef DEBUG_SM
	printf("[%s] %s, tcp flags 0x%x, flow flags 0x%x, seq %u, ack %u, data_len %lu\n",
	       _epfx(ef, NULL), get_state_name(ef->state), tcp_flags, ef->flags,
	       rte_be_to_cpu_32(tr->tcp->sent_seq), rte_be_to_cpu_32(tr->tcp->recv_ack),
	       (unsigned long)(rte_pktmbuf_mtod(tr->m, uint8_t *) + tr->m->pkt_len - ((uint8_t *)tr->tcp + (tr->tcp->data_off >> 2))));
#endif

	/* NOTE: if the previous packet changed the state, the receiver of that packet may not have received
	 *	 it yet, and so we might get a packet from the receiver of the previous packet that relates
	 *	 to the previous state, e.g. ACK of SYN+ACK not received, but we are now in ESTABLISHED state
	 *	 but the SYN+ACK gets resent. */
#if 0
	/* This version of jump_state is my first ass at what it should be */
	static void *jump_state[1 << 4][TCP_STATE_NUM] = {
		/*     TCP_STATE_SYN    TCP_STATE_SYN_ACK   TCP_STATE_ESTABLISHED TCP_STATE_CLEAR_OPTIMIZE */
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// All flags clear
		{	   &&invalid,	    &&process_pkt,	    &&process_pkt,	    &&process_pkt },	// FIN
		{	 &&simul_syn,		&&dup_syn,		&&dup_syn,		&&dup_syn },	// SYN
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// SYN, FIN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// RST
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// RST, FIN
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// RST, SYN
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// RST, SYN, FIN
		{	   &&invalid,	    &&syn_ack_ack,	    &&process_pkt,	    &&process_ack },	// ACK
		{	   &&invalid,		&&invalid,	    &&process_pkt,	    &&process_pkt },	// ACK, FIN
		{	   &&syn_ack,	    &&dup_syn_ack,	    &&dup_syn_ack,	    &&dup_syn_ack },	// ACK, SYN
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// ACK, SYN, FIN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// ACK, RST
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// ACK, RST, FIN
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// ACK, RST, SYN
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// ACK, RST, SYN, FIN
	};
#else
	/* This version of jump_state reflects what the code did before the jump table implementation */
	static void *jump_state[1 << 4][TCP_STATE_NUM] = {
		/*     TCP_STATE_SYN    TCP_STATE_SYN_ACK   TCP_STATE_ESTABLISHED TCP_STATE_CLEAR_OPTIMIZE */
		{	   &&invalid,		&&invalid,		&&invalid,		&&invalid },	// All flags clear
		{	 &&other_fin,		 &&no_ack,		 &&no_ack,		 &&no_ack },	// FIN
		{       &&syn_no_ack,	     &&syn_no_ack,		 &&no_ack,		 &&no_ack },	// SYN
		{	   &&syn_fin,		 &&no_ack,		 &&no_ack,		 &&no_ack },	// SYN, FIN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// RST
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// RST, FIN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// RST, SYN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// RST, SYN, FIN
		{	   &&syn_ack,	    &&syn_ack_ack,	    &&process_pkt,	    &&process_pkt },	// ACK
		{	 &&other_fin,	      &&other_fin,	    &&process_pkt,	    &&process_pkt },	// ACK, FIN
		{      &&syn_syn_ack,   &&syn_ack_syn_ack,	    &&est_syn_ack,	    &&est_syn_ack },	// ACK, SYN
		{	   &&syn_fin,		&&syn_fin,		&&syn_fin,		&&syn_fin },	// ACK, SYN, FIN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// ACK, RST
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// ACK, RST, FIN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// ACK, RST, SYN
		{	     &&reset,		  &&reset,		  &&reset,		  &&reset },	// ACK, RST, SYN, FIN
	};
#endif

	goto *jump_state[(tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_SYN_FLAG | RTE_TCP_RST_FLAG)) | ((tcp_flags & RTE_TCP_ACK_FLAG) ? 0x08 : 0)][ef->state];

invalid:
	clear_optimize(w, ef, tr, "invalid flags");
	return TFO_PKT_FORWARD;

reset:
	/* reset flag, stop everything */
	/* We don't need to ensure that queued packets that we have ack'd on other
	 * side are ack'd to us first before forwarding RST since RFC793 states:
	 *    All segment queues should be flushed.
	 */
	++w->st.rst_pkt;
	_eflow_free(w, ef);

#ifdef DEBUG_RST
	printf("[%s] Received RST\n", _epfx(ef, NULL));
#endif

	return TFO_PKT_FORWARD;

process_pkt:
	set_estb_pkt_counts(w, tcp_flags);

	return tfo_handle_pkt(w, tr, ef);

no_ack:
	/* A duplicate SYN could have no ACK, otherwise it is an error */
	++w->st.estb_noflag_pkt;
	clear_optimize(w, ef, tr, "no ack");

	return ret;

// Assume SYN and FIN packets can contain data - see last para p26 of RFC793,
//   i.e. before sequence number selection

syn_fin:
// Should only have ACK, ECE (and ? PSH, URG)
// We should delay forwarding RST until have received ACK for all data we have ACK'd - or not as the case may be
	clear_optimize(w, ef, tr, "syn+fin");
	++w->st.syn_bad_flag_pkt;
	return ret;

#ifdef INCLUDE_UNUSED_CODE
syn_ack_syn_no_ack:	// Unused
#endif


#ifdef INCLUDE_UNUSED_CODE
est_syn_no_ack:		// Unused
	++w->st.syn_on_eflow_pkt;
	clear_optimize(w, ef, tr, "established syn no ack");
	return ret;
#endif

	/* SYN flag only, in STATE_SYN or STATE_SYN_ACK.
	 * we won't be here on first SYN, as eflow is not yet allocated */
 syn_no_ack:
	if (!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) == !!tr->from_priv) {
		/* it is a retransmission */
		if (ef->server_snd_una != rte_be_to_cpu_32(tr->tcp->sent_seq)) {
			/* if SEQs don't match, do not optimize and let
			 * other side send RST - see RFC793 */
			clear_optimize(w, ef, tr, "dup SYN seq mismatch");
			return TFO_PKT_FORWARD;
		}
		/* duplicate of first syn */
		++w->st.syn_dup_pkt;
		ef->flags |= TFO_EF_FL_DUPLICATE_SYN;

		/* reduce cwnd (RFC5681 3.2) */
		if (ef->priv != NULL) {
			ef->priv->cwnd = ef->priv->mss;
			ef->pub->cwnd = ef->pub->mss;
		}

		/* do not forward - other side won't shrink its window */
		return TFO_PKT_HANDLED;

	} else if (!(ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN)) {
		/* simultaneous open, do not optimize */
		++w->st.syn_simlt_open_pkt;
		ef->flags |= TFO_EF_FL_SIMULTANEOUS_OPEN;

		if (ef->priv != NULL)
			clear_optimize(w, ef, tr, "simultaneous open");
	}
	return TFO_PKT_FORWARD;

	/* SYN+ACK flags set, in STATE_SYN */
 syn_syn_ack:
	if (unlikely(ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN)) {
		/* syn+ack from one side, too complex, don't optimize */
		clear_optimize(w, ef, tr, "simultaneous syn");
		++w->st.syn_ack_pkt;
		return ret;
	}

	if (unlikely(!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) == !!tr->from_priv)) {
		/* syn+ack from syn side */
		clear_optimize(w, ef, tr, "bad syn+ack seq");
		++w->st.syn_ack_bad_pkt;

		return ret;
	}

	ack = rte_be_to_cpu_32(tr->tcp->recv_ack);
	if (unlikely(!between_beg_ex(ack, ef->server_snd_una, ef->client_rcv_nxt))) {
#ifdef DEBUG_SM
		printf("SYN seq does not match SYN+ACK recv_ack, snd_una %x ack %x client_rcv_nxt %x\n",
		       ef->server_snd_una, ack, ef->client_rcv_nxt);
#endif

		clear_optimize(w, ef, tr, "SYN seq/ack mismatch");
		++w->st.syn_bad_pkt;
		return ret;
	}

	if (!set_tcp_options(tr, ef)) {
		clear_optimize(w, ef, tr, "bad syn tcp options");
		++w->st.syn_bad_pkt;
		return ret;
	}

	++w->st.syn_ack_pkt;

	/* not enough memory left. do not optimize */
	if (unlikely(w->f_use >= config->f_n * 2 - 2) ||
	    w->p_use >= config->p_n * 3 / 4) {
		_eflow_set_state(w, ef, TCP_STATE_CLEAR_OPTIMIZE);
		return TFO_PKT_FORWARD;
	}

	/* okay, start optimization */
	_eflow_set_state(w, ef, TCP_STATE_SYN_ACK);
	eflow_start_optimize(w, tr, ef);

	// Do initial RTT if none for user, otherwise ignore due to additional time for connection establishment
	// RTT is per user on private side, per flow on public side
	if (tr->from_priv) {
		server_fo = ef->priv;
		client_fo = ef->pub;
	} else {
		server_fo = ef->pub;
		client_fo = ef->priv;
	}

	queued_pkt = queue_pkt(w, client_fo, tr, client_fo->snd_una, server_fo->rcv_nxt, NULL);

	/* When check_do_optimize() sets up the seq nos, it sets it up
	 * as though the SYN_ACK has not been received. */
	server_fo->rcv_nxt += tr->seglen;
	server_fo->snd_una = rte_be_to_cpu_32(tr->tcp->recv_ack);
	server_fo->rack_fack = server_fo->snd_una;

	send_tcp_pkt(w, queued_pkt, client_fo, server_fo, "SynAck");

	/* We ACK the SYN+ACK to speed up startup */
	// _send_ack_pkt(w, ef, server_fo, &queued_pkt, NULL, p->from_priv, client_fo, false, false, true, false, false);
	_send_ack_pkt_in(w, ef, server_fo, tr, tr->from_priv, client_fo, NULL, false);

	return TFO_PKT_HANDLED;


	/* ACK flag set, in STATE_SYN. should not happen */
 syn_ack:
	++w->st.syn_state_pkt;
	_eflow_free(w, ef);
	return TFO_PKT_FORWARD;


	/* SYN+ACK flags set, in STATE_SYN_ACK. This is a duplicate packet */
 syn_ack_syn_ack:
#ifdef DEBUG_SM
	printf("duplicate syn+ack packet in state_syn_ack\n");
#endif
	++w->st.syn_ack_dup_pkt;
	ef->flags |= TFO_EF_FL_DUPLICATE_SYN;

	/* reduce cwnd (RFC5681 3.2) */
	ef->priv->cwnd = ef->priv->mss;
	ef->pub->cwnd = ef->pub->mss;
	return ret;

	/* SYN+ACK flags set, in STATE_ESTABLISHED. */
	/* Is the SYN+ACK being resent because the server hasn't received
	 * the ACK for the SYN+ACK? */
 est_syn_ack:
#ifdef DEBUG_SM
	printf("duplicate syn+ack packet in established state\n");
#endif
	fos = tr->from_priv ? ef->priv : ef->pub;
	seq = rte_be_to_cpu_32(tr->tcp->sent_seq);
	if (!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) != !tr->from_priv &&
	    seq == fos->first_seq &&
	    seq + tr->seglen == fos->rcv_nxt)
		goto process_pkt;

	++w->st.syn_ack_on_eflow_pkt;
	if (ef->state != TCP_STATE_CLEAR_OPTIMIZE)
		clear_optimize(w, ef, tr, "established syn+ack");
	return ret;

	/* ACK flag set, in STATE_SYN_ACK. */
 syn_ack_ack:
	if (unlikely(!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) != !!tr->from_priv)) {
		/* in some case, the server could ack the ACK we generated on syn+ack,
		 * before we receive ACK from client */
		/* allow only (and do not forward) if there is no data */
		ack = rte_be_to_cpu_32(tr->tcp->recv_ack);
		if (between_beg_ex(ack, ef->server_snd_una, ef->client_rcv_nxt) && !tr->seglen) {
			return TFO_PKT_HANDLED;
		} else {
			clear_optimize(w, ef, tr, "ack from wrong side in 3 way handshake");
			return TFO_PKT_FORWARD;
		}
	}

	// Note: when tfo_handle_pkt acks the SYN+ACK, the timestamp
	// will be the same as in the original SYN. This should not be
	// a problem since the timestamps we send should not be interpreted
	// by the remote end. tfo_handle_pkt could increment the TSval by
	// 1 if it wants. Clock rates can be as low as 1Hz, so better not
	// increment until we know.
	ret = tfo_handle_pkt(w, tr, ef);
	if (ret == TFO_PKT_HANDLED) {
		// We should do the following in handle_pkt - PKT_HANDLED is insufficient
		_eflow_set_state(w, ef, TCP_STATE_ESTABLISHED);
		(tr->from_priv ? ef->priv : ef->pub)->flags |= TFO_SIDE_FL_RTT_FROM_SYN;
	}

	return ret;

#ifdef INCLUDE_UNUSED_CODE
syn_other:	// Unused
	/* we're in fin, rst, or bad state */
	++w->st.syn_bad_state_pkt;
	return ret;

est_fin:	// Unused
	return ret;
#endif

other_fin:
	clear_optimize(w, ef, NULL, NULL);
	++w->st.fin_unexpected_pkt;

	return TFO_PKT_FORWARD;
}

static inline int
tcp_header_complete(struct rte_mbuf *m, struct rte_tcp_hdr *tcp)
{
	uint8_t *data_end = rte_pktmbuf_mtod(m, uint8_t *) + m->data_len;

	return data_end >= (uint8_t *)tcp + sizeof(*tcp) &&
	       data_end >= (uint8_t *)tcp + ((tcp->data_off & 0xf0) >> 2);
}

static enum tfo_pkt_state
tfo_mbuf_in_v4(struct tcp_worker *w, struct tfo_pktrx_ctx *tr)
{
	struct tfo_eflow *ef;
	in_addr_t priv_addr, pub_addr;
	uint16_t priv_port, pub_port;
	uint32_t h;
	enum tfo_pkt_state ret;

	if (!tcp_header_complete(tr->m, tr->tcp))
		return TFO_PKT_INVALID;

	tr->seglen = tr->m->pkt_len - ((uint8_t *)tr->tcp - rte_pktmbuf_mtod(tr->m, uint8_t *))
				- ((tr->tcp->data_off & 0xf0) >> 2)
				+ !!(tr->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

#ifdef DEBUG_PKT_RX
	/* printf("pkt_len %u tcp %p tcp_offs %ld, tcp_len %u, mtod %p, seg_len %u tcp_flags 0x%x\n", */
	/*        tr->m->pkt_len, tr->tcp, (uint8_t *)tr->tcp - rte_pktmbuf_mtod(tr->m, uint8_t *), */
	/*        (tr->tcp->data_off & 0xf0U) >> 2, rte_pktmbuf_mtod(tr->m, uint8_t *), tr->seglen, tr->tcp->tcp_flags); */
#endif

// PQA - use in_addr, out_addr, in_port, out_port, and don't check tr->from_priv
// PQA - don't call rte_be_to_cpu_32 etc. Do everything in network order
	/* get/create flow */
	if (likely(tr->from_priv)) {
		priv_addr = rte_be_to_cpu_32(tr->iph.ip4h->src_addr);
		pub_addr = rte_be_to_cpu_32(tr->iph.ip4h->dst_addr);
		priv_port = rte_be_to_cpu_16(tr->tcp->src_port);
		pub_port = rte_be_to_cpu_16(tr->tcp->dst_port);
	} else {
		priv_addr = rte_be_to_cpu_32(tr->iph.ip4h->dst_addr);
		pub_addr = rte_be_to_cpu_32(tr->iph.ip4h->src_addr);
		priv_port = rte_be_to_cpu_16(tr->tcp->dst_port);
		pub_port = rte_be_to_cpu_16(tr->tcp->src_port);
	}

// PQA - add tr->from_priv check here
// ? two stage hash. priv_addr/port
	h = tfo_eflow_v4_hash(config, priv_addr, priv_port, pub_addr, pub_port);
	ef = tfo_eflow_v4_lookup(w, priv_addr, priv_port, pub_addr, pub_port, h);

	if (unlikely(!ef)) {
		/* ECE and CWR can be set. Don't know about URG, PSH or NS yet */
		if ((tr->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
			/* This is not a new flow  - it might have existed before we started */
			return TFO_PKT_FORWARD;
		}

#ifdef DEBUG_SM
		printf("Received SYN, flags 0x%x, send_seq 0x%x seglen %u rx_win %hu\n",
			tr->tcp->tcp_flags, rte_be_to_cpu_32(tr->tcp->sent_seq), tr->seglen, rte_be_to_cpu_16(tr->tcp->rx_win));
#endif

		ef = _eflow_alloc(w, h);
		if (!ef)
			return TFO_PKT_NO_RESOURCE;
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v4.s_addr = pub_addr;
		ef->priv_addr.v4.s_addr = priv_addr;

		if (!set_tcp_options(tr, ef)) {
			_eflow_free(w, ef);
			++w->st.syn_bad_pkt;
			return TFO_PKT_FORWARD;
		}

		ef->win_shift = tr->win_shift;
		ef->server_snd_una = rte_be_to_cpu_32(tr->tcp->sent_seq);
		ef->client_rcv_nxt = ef->server_snd_una + tr->seglen;
		ef->client_snd_win = rte_be_to_cpu_16(tr->tcp->rx_win);
		ef->client_mss = tr->mss_opt;
		ef->client_ttl = tr->iph.ip4h->time_to_live;
		ef->client_packet_type = tr->m->packet_type;
#ifdef CALC_TS_CLOCK
		ef->start_time = now;
#endif
		if (tr->from_priv)
			ef->flags |= TFO_EF_FL_SYN_FROM_PRIV;

		/* Add a timer to the timer queue */
		eflow_update_idle_timeout(ef);
		ef->timer.time = ef->idle_timeout;

		rb_add_cached(&ef->timer.node, &timer_tree, timer_less);

		++w->st.syn_pkt;

		ret = TFO_PKT_FORWARD;
	} else
		ret = tfo_tcp_sm(w, tr, ef);

#ifdef DEBUG_STRUCTURES
	do_post_pkt_dump(w, ef);
#endif

	timer_update_ef(ef);

	return ret;
}

static enum tfo_pkt_state
tfo_mbuf_in_v6(struct tcp_worker *w, struct tfo_pktrx_ctx *tr)
{
	struct tfo_eflow *ef;
	struct in6_addr *priv_addr, *pub_addr;
	uint16_t priv_port, pub_port;
	uint32_t h;
	enum tfo_pkt_state ret;

	if (!tcp_header_complete(tr->m, tr->tcp))
		return TFO_PKT_INVALID;

	tr->seglen = tr->m->pkt_len - ((uint8_t *)tr->tcp - rte_pktmbuf_mtod(tr->m, uint8_t *))
				- ((tr->tcp->data_off & 0xf0) >> 2)
				+ !!(tr->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

#ifdef DEBUG_PKT_RX
	printf("pkt_len %u tcp %p tcp_offs %ld, tcp_len %u, mtod %p, seg_len %u tcp_flags 0x%x\n",
		tr->m->pkt_len, tr->tcp, (uint8_t *)tr->tcp - rte_pktmbuf_mtod(tr->m, uint8_t *),
		(tr->tcp->data_off & 0xf0U) >> 2, rte_pktmbuf_mtod(tr->m, uint8_t *), tr->seglen, tr->tcp->tcp_flags);
#endif

// PQA - use in_addr, out_addr, in_port, out_port, and don't check tr->from_priv
// PQA - don't call rte_be_to_cpu_32 etc. Do everything in network order
	/* get/create flow */
	if (likely(tr->from_priv)) {
		priv_addr = (struct in6_addr *)tr->iph.ip6h->src_addr;
		pub_addr = (struct in6_addr *)tr->iph.ip6h->dst_addr;
		priv_port = rte_be_to_cpu_16(tr->tcp->src_port);
		pub_port = rte_be_to_cpu_16(tr->tcp->dst_port);
	} else {
		priv_addr = (struct in6_addr *)tr->iph.ip6h->dst_addr;
		pub_addr = (struct in6_addr *)tr->iph.ip6h->src_addr;
		priv_port = rte_be_to_cpu_16(tr->tcp->dst_port);
		pub_port = rte_be_to_cpu_16(tr->tcp->src_port);
	}

// PQA - add tr->from_priv check here
// ? two stage hash. priv_addr/port
	h = tfo_eflow_v6_hash(config, priv_addr, priv_port, pub_addr, pub_port);
	ef = tfo_eflow_v6_lookup(w, priv_addr, priv_port, pub_addr, pub_port, h);

	if (unlikely(ef == NULL)) {
		/* ECN and CWR can be set. Don't know about URG, PSH or NS yet */
		if ((tr->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
			/* This is not a new flow  - it might have existed before we started */
			return TFO_PKT_FORWARD;
		}

#ifdef DEBUG_SM
		printf("Received SYN, flags 0x%x, send_seq 0x%x seglen %u rx_win %hu\n",
			tr->tcp->tcp_flags, rte_be_to_cpu_32(tr->tcp->sent_seq), tr->seglen, rte_be_to_cpu_16(tr->tcp->rx_win));
#endif

		ef = _eflow_alloc(w, h);
		if (!ef)
			return TFO_PKT_NO_RESOURCE;
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v6 = *pub_addr;
		ef->priv_addr.v6 = *priv_addr;
		ef->flags |= TFO_EF_FL_IPV6;

		if (!set_tcp_options(tr, ef)) {
			_eflow_free(w, ef);
			++w->st.syn_bad_pkt;
			return TFO_PKT_FORWARD;
		}

		ef->win_shift = tr->win_shift;
		ef->server_snd_una = rte_be_to_cpu_32(tr->tcp->sent_seq);
		ef->client_rcv_nxt = ef->server_snd_una + tr->seglen;
		ef->client_snd_win = rte_be_to_cpu_16(tr->tcp->rx_win);
		ef->client_mss = tr->mss_opt;
		ef->client_ttl = tr->iph.ip6h->hop_limits;
		ef->client_packet_type = tr->m->packet_type;
		ef->client_vtc_flow = tr->iph.ip6h->vtc_flow;
#ifdef CALC_TS_CLOCK
		ef->start_time = now;
#endif
		if (tr->from_priv)
			ef->flags |= TFO_EF_FL_SYN_FROM_PRIV;

		/* Add a timer to the timer queue */
		eflow_update_idle_timeout(ef);
		ef->timer.time = ef->idle_timeout;

		rb_add_cached(&ef->timer.node, &timer_tree, timer_less);

		++w->st.syn_pkt;

		ret = TFO_PKT_FORWARD;
	} else
		ret = tfo_tcp_sm(w, tr, ef);

#ifdef DEBUG_STRUCTURES
	do_post_pkt_dump(w, ef);
#endif

	timer_update_ef(ef);

	return ret;
}

// Do IPv4 defragmentation - see https://packetpushers.net/ip-fragmentation-in-detail/

static int
tcp_worker_mbuf_pkt(struct tcp_worker *w, struct rte_mbuf *m, int from_priv)
{
	struct tfo_pktrx_ctx tr;
	int16_t proto;
	uint32_t hdr_len;
	uint32_t off;
	int frag;

#ifdef DEBUG_DUPLICATE_MBUFS
	if (check_mbuf_in_use(m, w))
		printf("Received mbuf %p already in use\n", m);
#endif

	tr.m = m;
	tr.from_priv = from_priv;
	tr.sack_opt = NULL;
	tr.ts_opt = NULL;
	tr.mss_opt = 0;

#ifdef DEBUG_PKT_TYPES
	char ptype[128];
	rte_get_ptype_name(m->packet_type, ptype, sizeof(ptype));
	printf("Received m %p %s from %s, length %u (%u), vlan %u\n",
	       m, ptype, from_priv ? "priv" : "pub", m->pkt_len, m->data_len, m->vlan_tci);
#endif

	/* skip ethernet + vlan(s) */
	switch (m->packet_type & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER:
		hdr_len = sizeof (struct rte_ether_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_VLAN:
		hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_QINQ:
		hdr_len = sizeof (struct rte_ether_hdr) + 2 * sizeof (struct rte_vlan_hdr);
		break;
	default:
		/* It might be tunnelled TCP */
		return TFO_PKT_NOT_TCP;
	}

	/* The following works for IPv6 too */
	tr.iph.ip4h = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdr_len);
	tr.pktlen = m->pkt_len - hdr_len;

	switch (m->packet_type & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
		tr.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));

		/* A minimum ethernet + IPv4 + TCP packet with no options or data
		 * is 54 bytes; we will be given a pkt_len of 60 */
		if (m->pkt_len > rte_be_to_cpu_16(tr.iph.ip4h->total_length) + hdr_len)
			rte_pktmbuf_trim(m, m->pkt_len - (rte_be_to_cpu_16(tr.iph.ip4h->total_length) + hdr_len));

		return tfo_mbuf_in_v4(w, &tr);

	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		tr.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(tr.iph.ip4h));

		/* A minimum ethernet + IPv4 + TCP packet with no options or data
		 * is 54 bytes; we will be given a pkt_len of 60 */
		if (m->pkt_len > rte_be_to_cpu_16(tr.iph.ip4h->total_length) + hdr_len)
			rte_pktmbuf_trim(m, m->pkt_len - (rte_be_to_cpu_16(tr.iph.ip4h->total_length) + hdr_len));

		return tfo_mbuf_in_v4(w, &tr);

	case RTE_PTYPE_L3_IPV6:
		tr.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv6_hdr));

		return tfo_mbuf_in_v6(w, &tr);

	case RTE_PTYPE_L3_IPV6_EXT:
	case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
		off = hdr_len;
		proto = rte_net_skip_ip6_ext(tr.iph.ip6h->proto, m, &off, &frag);
		if (unlikely(proto < 0))
			return TFO_PKT_INVALID;
		if (proto != IPPROTO_TCP)
			return TFO_PKT_NOT_TCP;

		tr.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + off);
		return tfo_mbuf_in_v6(w, &tr);

	default:
		/* It is not IPv4/6 */
		return TFO_PKT_INVALID;
	}
}



/****************************************************************************/
/* SENDING TX PACKETS */
/****************************************************************************/


/*
 * add packet either:
 *   - to pace queue list, which send a certain amount of data every 10ms
 *   - to immediate tx_burst (at the end of tcp_worker_mbuf_burst() or tfo_process_timers())
 */
static inline void
add_tx_buf(struct tcp_worker *w, struct rte_mbuf *m, __attribute__((unused)) struct tfo_side *s)
{
	struct tfo_mbuf_priv *mp = get_priv_addr(m);

#ifdef CONFIG_PACE_TX_PACKETS
	if (s != NULL && s->pace_enabled) {
		/* the current pace queue may be flushed */
		if (!list_empty(&s->pace_xmit_list) && s->pace_timeslot != w->pace_timeslot)
			pace_tx_unspool(w, s);

		/* still packets in pace queue. queue this packet */
		if (!list_empty(&s->pace_xmit_list)) {
			assert(list_empty(&mp->list));
			list_add_tail(&mp->list, &s->pace_xmit_list);
#ifdef DEBUG_PACE_TX_PACKETS
			printf(NSEC_TIME_PRINT_FORMAT ": queue packet %p to pace list\n",
			       NSEC_TIME_PRINT_PARAMS(now), m);
#endif
			return;
		}

		/* can not send it right now, queue this packet, and start timer */
		if (!pace_tx_packets_may_send(s, m)) {
			assert(list_empty(&mp->list));
			list_add_tail(&mp->list, &s->pace_xmit_list);
			s->pace_timeout = now + (NSEC_PER_SEC / 100);
#ifdef DEBUG_PACE_TX_PACKETS
			printf(NSEC_TIME_PRINT_FORMAT ": queue packet %p to pace list, and start timer\n",
			       NSEC_TIME_PRINT_PARAMS(now), m);
#endif
			return;
		}
#ifdef DEBUG_PACE_TX_PACKETS
		printf(NSEC_TIME_PRINT_FORMAT ": immediately send packet %p (remain %lu bytes)\n",
		       NSEC_TIME_PRINT_PARAMS(now), m, s->pace_timeslot_remain);
#endif
	}
#endif

	assert(list_empty(&mp->list));
	list_add_tail(&mp->list, &w->pkt_send_list);
	++w->pkt_send_n;
}



#ifdef CONFIG_PACE_TX_PACKETS
static inline bool
pace_tx_packets_may_send(struct tfo_side *s, struct rte_mbuf *m)
{
	if (unlikely(s->pace_timeslot != worker.pace_timeslot)) {
		uint64_t m;

#if 0
		/* full window of data, or at least 100k */
		m = max(100000, s->snd_win << s->snd_win_shift);
		if (s->srtt_us > 0 && s->srtt_us < 1000) {
			/* rtt < 1ms */
			s->pace_timeslot_remain = m * (1000 - s->srtt_us) / 10;
		} else if (s->srtt_us > 1000 && s->srtt_us <= 1000000) {
			/* 1ms < rtt < 1s */
			s->pace_timeslot_remain = (m * 100000) / s->srtt_us;
		} else {
			/* no measure, or > 1s */
			s->pace_timeslot_remain = m / 20;
		}
#else
		if (s->srtt_us > 0)
			m = (uint64_t)(s->snd_win << s->snd_win_shift) * USEC_PER_SEC / s->srtt_us;
		else
			m = (s->snd_win << s->snd_win_shift);
		s->pace_timeslot_remain = m / 100; /* bytes per 10ms */
		s->pace_timeslot_remain = max(s->pace_timeslot_remain, 20000);
#ifdef DEBUG_PACE_TX_PACKETS
		printf("[%s] snd_win:%u srtt:%.4f m:%ld bytes_per_sec:%.3f remain:%lu\n",
		       _spfx(s), s->snd_win << s->snd_win_shift, (double)s->srtt_us / USEC_PER_SEC,
		       m, (double)m / USEC_PER_SEC, s->pace_timeslot_remain);
#endif
#endif

		s->pace_timeslot = worker.pace_timeslot;
	}

	if (s->pace_timeslot_remain > m->data_len) {
		s->pace_timeslot_remain -= m->data_len;
		return true;
	}

	return false;
}

static inline void
pace_tx_unspool(struct tcp_worker *w, struct tfo_side *s)
{
	struct tfo_mbuf_priv *mp, *mp_tmp;
	struct rte_mbuf *m;
#ifdef DEBUG_PACE_TX_PACKETS
	uint32_t pkt_sent = 0, pkt_skip = 0;
#endif

	list_for_each_entry_safe(mp, mp_tmp, &s->pace_xmit_list, list) {
		m = get_mbuf_from_priv(mp);
		if (!pace_tx_packets_may_send(s, m)) {
			s->pace_timeout = now + (NSEC_PER_SEC / 100);
#ifdef DEBUG_PACE_TX_PACKETS
			pkt_skip = 1;
			list_for_each_entry_continue(mp, &s->pace_xmit_list, list) {
				pkt_skip++;
			}
#endif
			break;
		}

		list_del(&mp->list);
		list_add_tail(&mp->list, &w->pkt_send_list);
		++w->pkt_send_n;

#ifdef DEBUG_PACE_TX_PACKETS
		++pkt_sent;
		if ((m->ol_flags & dynflag_queued_send_mask) &&
		    !(mp->pkt->flags & TFO_PKT_FL_QUEUED_SEND)) {
			printf("ERROR m:%p pkt:%p queued but miss fl_queued_send\n", m, mp->pkt);
		}
#endif
	}

#ifdef DEBUG_PACE_TX_PACKETS
	if (pkt_sent > 0) {
		printf(NSEC_TIME_PRINT_FORMAT ": send %d/%d paced packets (remain % 6ld bytes, pkts:% 4d, rtt:%ld.%6.6ld win:%d)\n",
		       NSEC_TIME_PRINT_PARAMS(now), pkt_sent, pkt_sent + pkt_skip,
		       s->pace_timeslot_remain, s->pktcount, s->srtt_us / USEC_PER_SEC, s->srtt_us % USEC_PER_SEC,
		       s->snd_win << s->snd_win_shift);
	}
#endif
}
#endif


static inline void
_send_mbuf_burst(struct rte_mbuf **mbufs, uint16_t m_n, int to_priv)
{
	struct tfo_mbuf_priv *mp;
	struct tfo_side *fos;
	struct tfo_pkt *pkt;
	struct rte_mbuf *m;
	struct list_head *last_sent_pkt;
	uint16_t nb_tx, i;

#ifdef DEBUG_SEND_BURST
	printf("tx_burst sending %u packets to %s\n", m_n, to_priv ? "priv" : "pub");
#endif

#ifdef WRITE_PCAP
	if (save_pcap)
		write_pcap(mbufs, m_n, RTE_PCAPNG_DIRECTION_OUT);
#endif

	nb_tx = config->tx_burst(worker.param, mbufs, m_n, to_priv);

#ifdef DEBUG_SEND_BURST
	printf("tx_burst sent %u/%u packets\n", nb_tx, m_n);
#elif defined DEBUG_SEND_BURST_NOT_SENT
	if (nb_tx != m_n)
		printf("tx_burst: only sent %u of %u packets\n", nb_tx, m_n);
#endif


	for (i = 0; i < nb_tx; i++) {
		m = mbufs[i];

		/* We don't do anything with ACKs */
		if (!(m->ol_flags & dynflag_queued_send_mask))
			continue;

		mp = get_priv_addr(m);
		pkt = mp->pkt;

		if (pkt == NULL || pkt->m != m) {
			printf("postprocess *** mbuf %p pkt %p priv %p priv->pkt %p prov->fos %p ERROR\n",
			       m, pkt, mp, mp->pkt, mp->fos);
			abort();
		}

		fos = mp->fos;
		fos->pkts_queued_send--;

		pkt->ns = now;

		if (pkt->flags & TFO_PKT_FL_SENT) {
			pkt->flags |= TFO_PKT_FL_RESENT;

			/* Is this a TLP retransmission ? */
			if ((fos->flags & TFO_SIDE_FL_TLP_IS_RETRANS) &&
			    fos->tlp_end_seq == segend(pkt)) {
				pkt->flags &= ~TFO_PKT_FL_QUEUED_SEND;
				continue;
			}

			if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
				/* Abort RTT calculation */
				fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
				pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
			}

			/* If the packet has been marked lost increment in_flight */
			if (pkt->flags & TFO_PKT_FL_LOST) {
				fos->pkts_in_flight++;
#ifdef DEBUG_IN_FLIGHT
				printf("[%s] after tx_burst pkt %u pkts_in_flight++ => %u for lost pkt\n",
				       _spfx(fos), pkt->seq, fos->pkts_in_flight);
#endif
			}
		} else {
			pkt->flags |= TFO_PKT_FL_SENT;
			fos->pkts_in_flight++;
#ifdef DEBUG_IN_FLIGHT
			printf("[%s] after tx_burst pkt %u pkts_in_flight++ => %u\n",
			       _spfx(fos), pkt->seq, fos->pkts_in_flight);
#endif

			/* If not using timestamps and no RTT calculation in progress,
			 * start one, but we don't calculate RTT from a resent packet */
			if (!pkt->ts && !(fos->flags & TFO_SIDE_FL_RTT_CALC_IN_PROGRESS)) {
				fos->flags |= TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
				pkt->flags |= TFO_PKT_FL_RTT_CALC;
			}
		}

#ifdef DEBUG_LAST_SENT
		struct tfo_pkt *lost_pkt;

		/* Find the last entry not lost. If none lost, points to list_head */
		if (!list_empty(&fos->xmit_ts_list)) {
			list_for_each_entry_reverse(lost_pkt, &fos->xmit_ts_list, xmit_ts_list) {
				if (!(lost_pkt->flags & TFO_PKT_FL_LOST))
					break;
			}
			last_sent_pkt = &lost_pkt->xmit_ts_list;
		} else
			last_sent_pkt = &fos->xmit_ts_list;

		/* FIXME Just checking for now that we agree with fos->last_sent */
		if (last_sent_pkt != fos->last_sent) {
			dump_eflow(fos->ef);
			printf("ERROR postprocess - mbuf %p pkt %p last_sent_pkt %p, fos->last_sent %p, last sent 0x%x, last sent found 0x%x\n",
				m, pkt, last_sent_pkt, fos->last_sent,
				list_is_head(fos->last_sent, &fos->xmit_ts_list) ? 0U : list_entry(fos->last_sent, struct tfo_pkt, xmit_ts_list)->seq,
				list_is_head(last_sent_pkt, &fos->xmit_ts_list) ? 0U : list_entry(last_sent_pkt, struct tfo_pkt, xmit_ts_list)->seq);
		}
#endif

		last_sent_pkt = fos->last_sent;

		/* RFC 8985 6.1 for LOST */
		pkt->flags &= ~(TFO_PKT_FL_LOST | TFO_PKT_FL_QUEUED_SEND);

		/* RFC8985 to make step 2 faster */

		/* Add the packet after the last sent packet not lost */
		if (list_is_queued(&pkt->xmit_ts_list)) {
			if (last_sent_pkt != &pkt->xmit_ts_list)
				list_move(&pkt->xmit_ts_list, last_sent_pkt);
		} else
			list_add(&pkt->xmit_ts_list, last_sent_pkt);

		fos->last_sent = &pkt->xmit_ts_list;

		/* OG: it should not happen (XXX: only after syn-ack) */
		if (after(segend(pkt), fos->snd_nxt)) {
#ifdef DEBUG_SND_NXT
			printf("[%s] increased snd_nxt %u => %u after tx_burst\n",
			       _spfx(fos), fos->snd_nxt, segend(pkt));
#endif
			fos->snd_nxt = segend(pkt);
		}

#ifdef DEBUG_POSTPROCESS
// This ack might duplicate a previous ACK, and fos->snd_una has moved forward. Once have fos->first_seq, use that
// This also doesn't cope with seq wrapping
// Once saw: received packet len 293, seq say 0x1000 for which we had received an ack, then received same packet but with
// FIN set. It failed what was the first check - before(pkt->seq, fos->snd_una);
		if (!after(pkt->seq + pkt->seglen, fos->snd_una) || after(pkt->seq + pkt->seglen, fos->snd_nxt))
			printf("ERROR postprocess mbuf %p pkt %p seq 0x%x len %u not between fos->snd_una 0x%x"
			       "and fos->snd_next 0x%x, fos %p, xmit_ts_list %p:%p\n",
			       m, pkt, pkt->seq, pkt->seglen, fos->snd_una,
			       fos->snd_nxt, fos, pkt->xmit_ts_list.prev, pkt->xmit_ts_list.next);
#endif
	}

	/* Mark any unsent packets as not having been sent. */
	if (unlikely(nb_tx < m_n)) {
		printf("tx_burst %u packets sent %u packets ERROR\n", m_n, nb_tx);

		for (i = nb_tx; i < m_n; i++) {
			m = mbufs[i];
			if (!(m->ol_flags & dynflag_queued_send_mask)) {
				rte_pktmbuf_free(m);
			} else {
				rte_pktmbuf_refcnt_update(m, -1);
				mp = get_priv_addr(m);
				pkt = mp->pkt;
#ifdef DEBUG_SEND_BURST_ERRORS
				if (pkt == NULL || pkt->m != m) {
					printf("ERROR *** tfo_packets_not_sent pkt %p m %p, "
					       "priv %p priv->fos %p nb_tx %u tx_bufs->nb_tx %u\n",
					       pkt, m, mp, mp->fos, nb_tx, m_n);
					continue;
				}
#endif
				pkt->flags &= ~TFO_PKT_FL_QUEUED_SEND;
				mp->fos->pkts_queued_send--;
			}
		}
	}
}

static inline void
tfo_send_burst(struct tcp_worker *w)
{
	struct tfo_mbuf_priv *mp, *mp_tmp;
	struct rte_mbuf *mb_priv[64], *mb_pub[64];
	struct rte_mbuf *m;
	uint32_t burst_size = 64;
	uint32_t kpr = 0, kpu = 0;

#ifdef DEBUG_PKT_NUM
	printf("Sending %u packets (%u-%u)\n", w->pkt_send_n, pkt_num + 1,
	       pkt_num + w->pkt_send_n);
	pkt_num += w->pkt_send_n;
#endif

	list_for_each_entry_safe(mp, mp_tmp, &w->pkt_send_list, list) {
		list_del_init(&mp->list);
		m = get_mbuf_from_priv(mp);
		if (m->ol_flags & config->dynflag_priv_mask) {
			mb_priv[kpr] = m;
			if (++kpr >= burst_size) {
				_send_mbuf_burst(mb_priv, kpr, 1);
				kpr = 0;
			}

		} else {
			mb_pub[kpu] = m;
			if (++kpu >= burst_size) {
				_send_mbuf_burst(mb_pub, kpu, 0);
				kpu = 0;
			}
		}
	}

	if (kpu > 0)
		_send_mbuf_burst(mb_pub, kpu, 0);
	if (kpr > 0)
		_send_mbuf_burst(mb_priv, kpr, 1);

	w->pkt_send_n = 0;
}

__visible void
tcp_worker_mbuf_burst(struct rte_mbuf **rx_buf, uint16_t nb_rx, struct timespec *ts)
{
	struct tcp_worker *w = &worker;
	struct timespec ts_local;
	struct rte_mbuf *m;
	struct tfo_mbuf_priv *mp;
	bool from_priv;
	uint16_t i;

	if (ts == NULL)
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts_local);
	else
		ts_local = *ts;
	now = timespec_to_ns(&ts_local);

#ifdef DEBUG_BURST
	format_debug_time();
	printf("\n%s Burst received %u pkts time %s\n", debug_time_abs, nb_rx, debug_time_rel);
#endif

	for (i = 0; i < nb_rx; i++) {
// Note: driver may not support packet_type, in which case we want to set these
// ourselves. Use rte_the_dev_get_supported_ptypes() to find what is supported,
// see examples/l3fwd/l3fwd_em.c.

// We may want to handle RTE_PTYPE_L4_FRAG
// If (!all_classified) classify_pkt(w->classified, m);
// rte_net_get_ptype() in lib/net/rte_net.c looks good but inefficient
// SYN can get ICMP responses - see with wireshark and Linux to Linux connection to closed port
		m = rx_buf[i];
		from_priv = !!(m->ol_flags & config->dynflag_priv_mask);

		/* ensure the private area is initialised */
		mp = get_priv_addr(m);
		INIT_LIST_HEAD(&mp->list);
		mp->pkt = NULL;
		mp->fos = NULL;

#ifdef DEBUG_PKT_NUM
		format_debug_time();
#ifdef DEBUG_NEWLINE_BETWEEN_PKTS
		printf("\n");
#endif
		printf("***** %s Processing packet %u from %s, size:%d\n",
		       debug_time_abs, ++pkt_num, from_priv ? "priv" : "pub", m->data_len);
#endif

		if (unlikely(!m->data_len)) {
#ifdef DEBUG_EMPTY_PACKETS
			char ptype[128];
			rte_get_ptype_name(m->packet_type, ptype, sizeof(ptype));
			printf("ERROR *** Received empty packet mbuf %p data_len %u pkt_len %u packet_type %s (0x%x) pool %s\n",
			       m, m->data_len, m->pkt_len, ptype, m->packet_type, m->pool->name);
#endif
			rte_pktmbuf_free(m);
			continue;
		}

#ifdef DEBUG_CHECKSUM
		if ((m->packet_type & RTE_PTYPE_L4_MASK) != RTE_PTYPE_L4_TCP)
			check_checksum_in(m, "Received packet");
#endif

		if ((m->packet_type & RTE_PTYPE_L4_MASK) != RTE_PTYPE_L4_TCP ||
		    (tcp_worker_mbuf_pkt(w, m, from_priv) != TFO_PKT_HANDLED)) {
			m->ol_flags ^= config->dynflag_priv_mask;
#ifdef DEBUG_QUEUE_PKTS
			printf("forwarding pkt to %s, add m=%p to queue\n",
			       !!(m->ol_flags & config->dynflag_priv_mask) ? "priv" : "pub", m);
#endif
			/* we don't have 'fos', but some packets may be queued on it... */
			add_tx_buf(w, m, NULL);
		}
	}

	if (w->pkt_send_n)
		tfo_send_burst(w);
}

__visible void
tcp_worker_mbuf(struct rte_mbuf *m, int from_priv, struct timespec *ts)
{
	if (from_priv)
		m->ol_flags |= config->dynflag_priv_mask;

	tcp_worker_mbuf_burst(&m, 1, ts);
}


/****************************************************************************/
/* TIMERS */
/****************************************************************************/

static inline bool
timer_less(struct rb_node *node_a, const struct rb_node *node_b)
{
	return container_of(node_a, struct timer_rb_node, node)->time < const_container_of(node_b, struct timer_rb_node, node)->time;
}

static inline void
update_timer_move(struct tfo_eflow *ef)
{
	struct rb_node *prev, *next;

	/* Check if already in correct position */
#ifdef CONFIG_FOR_CGN
	prev = rb_prev_tfo(&ef->timer.node);
	next = rb_next_tfo(&ef->timer.node);
#else
	prev = rb_prev(&ef->timer.node);
	next = rb_next(&ef->timer.node);
#endif

	/* If we are already in the right place, leave it there */
	if ((!prev || container_of(prev, struct timer_rb_node, node)->time <= ef->timer.time) &&
	    (!next || container_of(next, struct timer_rb_node, node)->time >= ef->timer.time)) {
		return;
	}

#ifdef DEBUG_TIMER_TREE
	if ((!rb_parent(&ef->timer.node) && timer_tree.rb_root.rb_node != &ef->timer.node) ||
	    (rb_parent(&ef->timer.node) &&
	     rb_parent(&ef->timer.node)->rb_left != &ef->timer.node &&
	     rb_parent(&ef->timer.node)->rb_right != &ef->timer.node)) {
		dump_details(&worker);
		if (!rb_parent(&ef->timer.node))
			printf("timer rb tree error, ef %p timer.node %p timer_tree.rb_root.rb_node %p leftmost %p no parent ERROR\n", ef, &ef->timer.node, timer_tree.rb_root.rb_node, timer_tree.rb_leftmost);
		else
			printf("timer rb tree error, ef %p, timer.node %p parent %p, left %p right %p ERROR\n", ef, &ef->timer.node,
				rb_parent(&ef->timer.node), rb_parent(&ef->timer.node)->rb_left, rb_parent(&ef->timer.node)->rb_right);
	}
#endif

	rb_erase_cached(&ef->timer.node, &timer_tree);
	rb_add_cached(&ef->timer.node, &timer_tree, timer_less);
}


static inline time_ns_t
timer_rearm(struct tfo_side *fos)
{
	enum tfo_timer new = TFO_TIMER_NONE;
	time_ns_t timeout = TFO_INFINITE_TS;

	if (fos->cur_timer == TFO_TIMER_REO) {
		/* set and unset in rack_detect_loss_and_arm_timer(). do not overwrite it. */

	} else if ((fos->pkts_in_flight || fos->pkts_queued_send) &&
		   using_rack(fos->ef) && !fos->rack_total_segs_sacked &&
		   !(fos->flags & (TFO_SIDE_FL_IN_RECOVERY |
				   TFO_SIDE_FL_TLP_IN_PROGRESS)) &&
		   !(fos->cur_timer == TFO_TIMER_PTO && fos->timeout_at <= now)) {
		/* RFC8985 7.2 Scheduling a loss probe. timer is set on these conditions:
		 *   - packet(s) in flight
		 *   - using rack, no sacked segs (TIMER_REO will be set in this case)
		 *   - not in recovery or probe sent, and a new rtt measurement made
		 *   - we're not from the tlp timer callback */

		/* set/reset timer if data is sent or acked */
		if (fos->cur_timer != TFO_TIMER_PTO ||
		    (fos->flags & TFO_SIDE_FL_ACKED_DATA) || fos->pkts_queued_send) {
			new = TFO_TIMER_PTO;
			timeout = tlp_calc_pto(fos);
		}

	} else if (fos->pkts_queued_send || fos->pkts_in_flight)  {
		/* data is sent (RFC6298 5.1), received an ACK (RFC6298 5.3),
		 * or data in-flight and rto not set. */
		if (fos->cur_timer != TFO_TIMER_RTO ||
		    (fos->flags & TFO_SIDE_FL_ACKED_DATA)) {
			new = TFO_TIMER_RTO;
			timeout = fos->rto_us * NSEC_PER_USEC;
		}

	} else if (!fos->pkts_in_flight && fos->cur_timer != TFO_TIMER_KEEPALIVE) {
		/* no packets are on wire. set keepalive timer */
		new = TFO_TIMER_KEEPALIVE;
		timeout = (time_ns_t)config->tcp_keepalive_time * NSEC_PER_SEC;
		fos->keepalive_probes = config->tcp_keepalive_probes;
#ifdef CALC_TS_CLOCK
		/* Ensure that a keepalive is sent in half the timestamp clock
		 * wrap around time */
		if (fos->nsecs_per_tock &&
		    (time_ns_t)fos->nsecs_per_tock * (1U << 31) < timeout)
			timeout = (time_ns_t)fos->nsecs_per_tock * (1U << 31);
#endif
	} else if (fos->cur_timer == TFO_TIMER_NONE) {
		printf("[%s] ERROR bug timer is still NONE\n", _spfx(fos));

	} else {
		/* rto or keepalive timer is running, do not modify */
	}


	if (new != TFO_TIMER_NONE) {
#ifdef DEBUG_TIMERS
		if (!(fos->cur_timer == TFO_TIMER_NONE &&
		      new == TFO_TIMER_KEEPALIVE &&
		      fos->timeout_at != TFO_INFINITE_TS)) {
			printf("[%s] set timer %s => %s (timeout %.6f sec)\n",
			       _spfx(fos), get_timer_name(fos->cur_timer),
			       get_timer_name(new), (double)timeout / NSEC_PER_SEC);
		}
#endif
		fos->cur_timer = new;
		timeout += now;
		fos->timeout_at = timeout;

	} else {
		timeout = fos->timeout_at;
	}

	if (ack_delayed(fos) && fos->delayed_ack_timeout < timeout)
		timeout = fos->delayed_ack_timeout;

#ifdef CONFIG_PACE_TX_PACKETS
	if (!list_empty(&fos->pace_xmit_list) && fos->pace_timeout < timeout)
		timeout = fos->pace_timeout;
#endif

	return timeout;
}

/*
 * called at the end of eflow processing, on each packet rx or
 * on all timer trigger.
 */
static void
timer_update_ef(struct tfo_eflow *ef)
{
	time_ns_t timeout, min_time = TFO_INFINITE_TS;

	if (ef->priv != NULL && ef->state != TCP_STATE_CLEAR_OPTIMIZE) {
		timeout = timer_rearm(ef->priv);
		if (timeout < min_time)
			min_time = timeout;
		timeout = timer_rearm(ef->pub);
		if (timeout < min_time)
			min_time = timeout;
	}

	if (unlikely(ef->idle_timeout < min_time))
		min_time = ef->idle_timeout;

	if (ef->timer.time != min_time) {
		ef->timer.time = min_time;
		update_timer_move(ef);
	}
}


/*
 * called from timer context.
 * This is also called for connections not using RACK, but
 * in that case we won't have a REO or PTO timer
 */
static void
tfo_timer_triggered(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos)
{
#if defined DEBUG_RACK || defined DEBUG_TIMERS
	printf("[%s] timer %s triggered\n",
	       _spfx(fos), get_timer_name(fos->cur_timer));
#endif

	switch (fos->cur_timer) {
	case TFO_TIMER_NONE:
		break;

	case TFO_TIMER_RTO:
		if (using_rack(ef))
			rack_mark_losses_on_rto(fos);
		else
			handle_rto(w, fos, foos);
		fos->cur_timer = TFO_TIMER_NONE;
		break;

	case TFO_TIMER_PTO:
		tlp_send_probe(w, fos, foos);
		break;

	case TFO_TIMER_REO:
		rack_detect_loss_and_arm_timer(w, fos, fos->snd_una);
		break;

	case TFO_TIMER_ZERO_WINDOW:
		// TODO
		break;

	case TFO_TIMER_KEEPALIVE:
		send_keepalive(w, ef, fos, foos);

		/* schedule next keepalive */
		fos->timeout_at = now + (time_ns_t)config->tcp_keepalive_intvl * NSEC_PER_SEC;
		break;
	}

	rack_resend_lost_packets(w, fos, foos);
}


static void
process_flow_side_timeout(struct tcp_worker *w, struct tfo_eflow *ef,
			  struct tfo_side *fos, struct tfo_side *foos)
{
#ifdef CONFIG_PACE_TX_PACKETS
	if (fos->pace_enabled)
		pace_tx_unspool(w, fos);
#endif

	if (fos->cur_timer != TFO_TIMER_NONE && fos->timeout_at <= now) {
		tfo_timer_triggered(w, ef, fos, foos);

#ifdef DEBUG_STRUCTURES
		do_post_pkt_dump(w, ef);
#endif
	}

	if (fos->delayed_ack_timeout <= now) {
		generate_ack_rst(w, ef, fos, foos, false, false);

#ifdef DEBUG_STRUCTURES
		do_post_pkt_dump(w, ef);
#endif
	}
}

static void
process_flow_timeout(struct tcp_worker *w, struct tfo_eflow *ef)
{
	if (ef->idle_timeout <= now) {
#ifdef DEBUG_FLOW
		printf("[%s] idle timeout fired (ts=%lu)\n", _epfx(ef, NULL), ef->idle_timeout - now);
#endif
		_eflow_free(w, ef);
		return;
	}

	_eflow_before_use(ef);

	if (ef->state != TCP_STATE_CLEAR_OPTIMIZE) {
		process_flow_side_timeout(w, ef, ef->priv, ef->pub);
		process_flow_side_timeout(w, ef, ef->pub, ef->priv);
	}

	timer_update_ef(ef);

#ifdef DEBUG_TIMERS
	if (ef->timer.time <= now) {
		printf("[%s] timer not reset, may loop (eflow_timeout:%.3fs)\n",
		       _epfx(ef, NULL), (double)(ef->idle_timeout - now) / (double)NSEC_PER_SEC);
		if (ef->priv != NULL && ef->pub != NULL) {
			printf(" priv: cur_timer:%u to:%.3fs ack_delay:%.3fs pace:%.3fs\n",
			       ef->priv->cur_timer, (double)(ef->priv->timeout_at - now) / NSEC_PER_SEC,
			       ack_delayed(ef->priv) ? (double)(ef->priv->delayed_ack_timeout - now) / NSEC_PER_SEC : 0,
#ifdef CONFIG_PACE_TX_PACKETS
			       !list_empty(&ef->priv->pace_xmit_list) ? (double)(ef->priv->pace_timeout - now) / NSEC_PER_SEC : 0
#else
			       -1.0D
#endif
			       );
			printf(" pub: cur_timer:%u to:%.3fs ack_delay:%.3fs pace:%.3fs\n",
			       ef->pub->cur_timer, (double)(ef->pub->timeout_at - now) / NSEC_PER_SEC,
			       ack_delayed(ef->pub) ? (double)(ef->pub->delayed_ack_timeout - now) / NSEC_PER_SEC : 0,
#ifdef CONFIG_PACE_TX_PACKETS
			       !list_empty(&ef->pub->pace_xmit_list) ? (double)(ef->pub->pace_timeout - now) / NSEC_PER_SEC : 0
#else
			       -1.0D
#endif
			       );
		}
	}
#endif
}


/*
 * called every 2-5ms
 */
__visible void
tfo_process_timers(const struct timespec *ts)
{
	struct tfo_eflow *ef;
	struct tcp_worker *w = &worker;
	struct timer_rb_node *timer;
	struct timespec ts_local;

	if (ts != NULL)
		ts_local = *ts;
	else
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts_local);
	now = timespec_to_ns(&ts_local);

	/* tx pacing timeslot. increment every 10ms */
	w->pace_timeslot = (now * 100 / NSEC_PER_SEC);

	if (RB_EMPTY_ROOT(&timer_tree.rb_root))
		return;
	timer = rb_entry(rb_first_cached(&timer_tree), struct timer_rb_node, node);

#ifdef DEBUG_TIMERS
	if (timer->time <= now) {
		format_debug_time();
#ifdef DEBUG_NEWLINE_BETWEEN_PKTS
		printf("\n");
#endif
		printf("***** %s Timer time: %s\n", debug_time_abs, debug_time_rel);
	}
#endif

	int cpt = 0;
	/* Process each expired timer */
	while (timer->time <= now) {
		assert(++cpt < 50);
		ef = container_of(timer, struct tfo_eflow, timer);
		process_flow_timeout(w, ef);

		/* We may have removed the last eflow due to its idle timer */
		if (RB_EMPTY_ROOT(&timer_tree.rb_root))
			break;

		timer = rb_entry(rb_first_cached(&timer_tree), struct timer_rb_node, node);
	}

	if (w->pkt_send_n)
		tfo_send_burst(w);
}


/****************************************************************************/
/* GLOBAL INIT */
/****************************************************************************/


__visible uint64_t
tcp_worker_init(struct tfo_worker_params *params)
{
	int socket_id = rte_socket_id();
	struct tcp_worker *w;
	struct tcp_config *c;
	struct tfo_pkt *p;
	struct tfo_side *s;
	struct tfo_eflow *ef;
	unsigned k;
	int j;

	/* Need some locking here */
	/* We want the config held in our NUMA node local memory */
	if (!node_config_copy[socket_id]) {
		node_config_copy[socket_id] = rte_malloc("worker config", sizeof(struct tcp_config), 0);
		*node_config_copy[socket_id] = global_config_data;
		node_config_copy[socket_id]->tcp_to = rte_malloc("worker config timeouts", (node_config_copy[socket_id]->max_port_to + 1) * sizeof(struct tcp_timeouts), 0);
		rte_memcpy(node_config_copy[socket_id]->tcp_to, global_config_data.tcp_to, (node_config_copy[socket_id]->max_port_to + 1) * sizeof(struct tcp_timeouts));
	}

	config = c = node_config_copy[socket_id];

	tfo_debug_worker_init();

	w = &worker;
	w->param = params->params;
	ack_pool = params->ack_pool;
	option_flags = node_config_copy[socket_id]->option_flags;

	if (ack_pool)
		ack_pool_priv_size = rte_pktmbuf_priv_size(ack_pool);

	struct tfo_eflow *ef_mem = rte_malloc("worker ef", c->ef_n * sizeof (struct tfo_eflow), 0);
	w->hef = rte_calloc("worker hef", c->hef_n, sizeof (struct hlist_head), 0);
	struct tfo_side *f_mem = rte_malloc("worker f", c->f_n * 2 * sizeof (struct tfo_side), 0);
	struct tfo_pkt *p_mem = rte_malloc("worker p", c->p_n * sizeof (struct tfo_pkt), 0);

	/* existing flows */
	INIT_HLIST_HEAD(&w->ef_free);
	for (j = c->ef_n - 1; j >= 0; j--) {
		ef = ef_mem + j;
		ef->flags = 0;
		ef->state = TFO_STATE_NONE;
		hlist_add_head(&ef->hlist, &w->ef_free);
	}

	/* optimized flows */
	INIT_LIST_HEAD(&w->f_free);
	for (k = 0; k < c->f_n * 2; k++) {
		s = f_mem + k;
		list_add_tail(&s->flow_list, &w->f_free);
	}

	/* buffered packets */
	INIT_LIST_HEAD(&w->p_free);
	for (k = 0; k < c->p_n; k++) {
		p = p_mem + k;
		list_add_tail(&p->list, &w->p_free);
		INIT_LIST_HEAD(&p->xmit_ts_list);
	}

	/* initialise the timer RB tree */
	timer_tree = RB_ROOT_CACHED;

	INIT_LIST_HEAD(&w->pkt_send_list);
	w->pace_timeslot = 0;

	return config->dynflag_priv_mask;
}

__visible void
tcp_init(const struct tcp_config *c)
{
	global_config_data = *c;
	int flag;
	const struct rte_mbuf_dynflag dynflag = {
		.name = "dynflag-priv",
		.flags = 0,
	};
	const struct rte_mbuf_dynflag dynflag_queued_send = {
		.name = "dynflag-queued-send",
		.flags = 0,
	};

	global_config_data.hef_n = next_power_of_2(global_config_data.hef_n);
	global_config_data.hef_mask = global_config_data.hef_n - 1;
	global_config_data.option_flags = c->option_flags;
	global_config_data.tcp_min_rtt_wlen = c->tcp_min_rtt_wlen ? c->tcp_min_rtt_wlen : (300 * MSEC_PER_SEC);	// Linux default value is 300 seconds
	global_config_data.tcp_keepalive_time = c->tcp_keepalive_time ?: 7200;
	global_config_data.tcp_keepalive_probes = c->tcp_keepalive_probes ?: 9;
	global_config_data.tcp_keepalive_intvl = c->tcp_keepalive_intvl ?: 75;
	global_config_data.mbuf_priv_offset = c->mbuf_priv_offset;
#ifdef PER_THREAD_LOGS
	global_config_data.log_file_name_template = c->log_file_name_template;
#endif
#ifdef DEBUG_PRINT_TO_BUF
	global_config_data.print_buf_size = c->print_buf_size;
#endif

	/* tx_burst is mandatory */
	assert(global_config_data.tx_burst != NULL);

	/* mbuf is_ack, when queued for delivery */
	flag = rte_mbuf_dynflag_register(&dynflag_queued_send);
	assert(flag != -1);
	dynflag_queued_send_mask = (1ULL << flag);

	/* set a dynamic flag mask */
	flag = rte_mbuf_dynflag_register(&dynflag);
	assert(flag != -1);
	global_config_data.dynflag_priv_mask = (1ULL << flag);

#if defined NEED_DUMP_DETAILS
	struct timespec start_monotonic, start_time[2];
	const char *ts;

	clock_gettime(CLOCK_REALTIME, &start_time[0]);
	clock_gettime(CLOCK_MONOTONIC_RAW, &start_monotonic);
	clock_gettime(CLOCK_REALTIME, &start_time[1]);
	start_ns = timespec_to_ns(&start_monotonic);

	if (start_time[0].tv_sec != start_time[1].tv_sec)
		start_time[0].tv_nsec += NSEC_PER_SEC;
	if ((start_time[0].tv_nsec += start_time[1].tv_nsec) >= 2 * (signed)NSEC_PER_SEC)
		start_time[0].tv_sec = start_time[1].tv_sec;
	start_time[0].tv_nsec = (start_time[0].tv_nsec / 2) % NSEC_PER_SEC;

	ts = ctime(&start_time[0].tv_sec);
	printf("\nStarted at %.10s%.5s %.8s.%9.9ld\n\n", ts, ts + 19, ts + 11, start_time[0].tv_nsec);
#endif
}

__visible uint16_t __attribute__((const))
tfo_max_ack_pkt_size(void)
{
	/* maximum TCP header length */
	return sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_vlan_hdr) +
		sizeof(struct rte_ipv6_hdr) +
		(0xf0 >> 2);
}

__visible uint16_t __attribute__((const))
tfo_get_mbuf_priv_size(void)
{
	return sizeof(struct tfo_mbuf_priv);
}
