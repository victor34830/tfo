/*
 * RACK TODO
 *
 * IMMEDIATE
 *   rack_segs_sacked handling when packets acked
 *   Stop using timespec_to_ns and use global now.
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
 *   g. timers w->ts, pkt->ts etc
 *
 * -4. Sort out what packets are not forwarded - we must forward ICMP (and inspect for relating to TCP)
 * -3. DPDK code for generating bad packet sequences
 * -1. Timestamp, ack and win updating on send
 * -0.9. Work out our policy for window size
 * 1. Tidy up code
 * 2. Optimize code
 * 2.1 See https://www.hamilton.ie/net/LinuxHighSpeed.pdf:
 * 	Order the SACK blocks by seq so walk pktlist once
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
 * RFC 2018 - Selective ACK
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
 *  	1. RFC8985
 *  		Replaces loss recovery in RFCs 5681, 6675, 5827 and 4653.
 *  		Is compatible with RFCs 6298, 7765, 5682 and 3522.
 *  		Does not modify congestion control in RFCs 5681, 6937 (recommended)
 *  	1a. RFC7323 - using timestamps - when send a packet send it with latest TS received, or use calculated clock to calculate own
 *  	1b. ACK alternate packets with a timeout
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
#define WRITE_PCAP
#define RELEASE_SACKED_PACKETS	// XXX - add code for not releasing and detecting reneging (see Linux code/RFC8985 for detecting)
#define CWND_USE_RECOMMENDED
#define HAVE_DUPLICATE_MBUF_BUG
//#define	RECEIVE_WINDOW_MSS_MULT	50
//#define RECEIVE_WINDOW_ALLOW_MAX


#ifndef NO_DEBUG
//#define DEBUG_MEM
#define DEBUG_PKTS
#define DEBUG_BURST
#define DEBUG_PKT_TYPES
#define DEBUG_PKT_VALID
//#define DEBUG_VLAN
//#define DEBUG_VLAN1
#define DEBUG_VLAN_TCI
#define DEBUG_STRUCTURES
//#define DEBUG_TCP_OPT
//#define DEBUG_QUEUE_PKTS
#define DEBUG_ACK
#define DEBUG_RST
//#define DEBUG_ACK_PKT_LIST
//#define DEBUG_CHECKSUM
//#define DEBUG_CHECKSUM_DETAIL
//#define DEBUG_CHECK_ADDR
#define DEBUG_RCV_WIN
#define DEBUG_FLOW
#define DEBUG_USER
//#define DEBUG_OPTIMIZE
#define DEBUG_NO_MBUF
#define DEBUG_PKT_RX
//#define DEBUG_TCP_WINDOW
#define DEBUG_SND_NXT
#define DEBUG_RTO
#define DEBUG_FIN
#define DEBUG_SM
//#define DEBUG_ETHDEV
//#define DEBUG_CONFIG
#define DEBUG_TIMERS
#define DEBUG_RFC5681
#define DEBUG_PKT_NUM
#define DEBUG_DUMP_DETAILS
//#define DEBUG_MEMPOOL
//#define DEBUG_ACK_MEMPOOL
#define DEBUG_RTT_MIN
#define DEBUG_ZERO_WINDOW
//#define DEBUG_SEND_BURST
#define DEBUG_SEND_BURST_ERRORS
#define DEBUG_SEND_BURST_NOT_SENT
#define DEBUG_REMOVE_TX_PKT
#define DEBUG_IN_FLIGHT
#define DEBUG_SACK_RX
#define DEBUG_SACK_SEND
#define DEBUG_DUP_SACK_SEND
#define DEBUG_RACK
#define DEBUG_RACK_LOSS
#define DEBUG_RACK_SACKED
#define DEBUG_TS_SPEED
#define DEBUG_QUEUED
#define DEBUG_POSTPROCESS
//#define DEBUG_DUP_ACK
#define DEBUG_DELAYED_ACK
#define DEBUG_USERS_TX_CLOCK
//#define DEBUG_SEND_PKT
//#define DEBUG_SEND_PKT_LOCATION
//#define DEBUG_SEND_DSACK_CHECK
//#define DEBUG_THROUGHPUT
//#define DEBUG_DISABLE_TS
//#define DEBUG_DISABLE_SACK
#define DEBUG_LAST_SENT
#define DEBUG_RECOVERY
#define DEBUG_VALID_OPTIONS
#define DEBUG_EMPTY_PACKETS
#define DEBUG_SEND_PROBE
#define DEBUG_DUPLICATE_MBUFS
//#define DEBUG_PACKET_POOL
#define DEBUG_PKT_DELAYS
#define DEBUG_DLSPEED
//#define DEBUG_DLSPEED_DEBUG
#define DEBUG_KEEPALIVES
#define DEBUG_RESEND_FAILED_PACKETS
#ifdef WRITE_PCAP
// #define DEBUG_PCAP_MEMPOOL
#endif
#endif


#ifdef WRITE_PCAP
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#endif
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <ev.h>
#include <threads.h>
#include <stddef.h>

#include "linux_list.h"

#include "tfo_options.h"
#include "tfo_worker.h"
#include "tfo_rbtree.h"
#include "win_minmax.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_net.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#ifdef WRITE_PCAP
#include <rte_cycles.h>
#include <rte_pcapng.h>
#include <rte_errno.h>
#include <rte_version.h>
#endif


#ifdef DEBUG_PKT_TYPES
#include <rte_mbuf_ptype.h>
#endif

#ifndef HAVE_FREE_HEADERS
#include "util.h"
#endif

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

/* Per NUMA node data */
static struct tcp_config *node_config_copy[RTE_MAX_NUMA_NODES];

/* Per thread data */
static thread_local struct tcp_worker worker;
static thread_local struct tcp_config *config;
static thread_local uint16_t pub_vlan_tci;
static thread_local uint16_t priv_vlan_tci;
static thread_local unsigned option_flags;
static thread_local struct rte_mempool *ack_pool;
static thread_local uint16_t ack_pool_priv_size = UINT16_MAX;
static thread_local uint16_t port_id;
static thread_local uint16_t queue_idx;
static thread_local time_ns_t now;
static thread_local struct list_head send_failed_list;
static thread_local struct rb_root_cached timer_tree;
#ifdef WRITE_PCAP
static thread_local struct rte_mempool *pcap_mempool;
static thread_local int pcap_priv_fd;
static thread_local rte_pcapng_t *pcap_priv;
static thread_local int pcap_pub_fd;
static thread_local rte_pcapng_t *pcap_pub;
static thread_local int pcap_all_fd;
static thread_local rte_pcapng_t *pcap_all;
#endif
static thread_local bool saved_mac_addr;
static thread_local struct rte_ether_addr local_mac_addr;
static thread_local struct rte_ether_addr remote_mac_addr;


#ifdef WRITE_PCAP
static bool save_pcap = false;
#endif

#ifdef DEBUG_PKT_NUM
static thread_local uint32_t pkt_num = 0;
#endif
#if defined DEBUG_STRUCTURES || defined DEBUG_PKTS || defined DEBUG_TIMERS
static thread_local time_ns_t last_time;
#endif


#ifdef DEBUG_DLSPEED
/* This code is "borrowed" from wget. wget has shown that the download
 * speed sometimes drops by 30% or more then gradually improves again.
 * We need to same code as wget so that we can write to the logs when
 * this happens.
 *
 * This code attempts to maintain the notion of a "current" download
 * speed, over the course of no less than 3s.  (Shorter intervals
 * produce very erratic results.)

 * To do so, it samples the speed in 150ms intervals and stores the
 * recorded samples in a FIFO history ring.  The ring stores no more
 * than 20 intervals, hence the history covers the period of at least
 * three seconds and at most 20 reads into the past.  This method
 * should produce reasonable results for downloads ranging from very
 * slow to very fast.

 * The idea is that for fast downloads, we get the speed over exactly
 * the last three seconds.  For slow downloads (where a network read
 * takes more than 150ms to complete), we get the speed over a larger
 * time period, as large as it takes to complete twenty reads.  This
 * is good because slow downloads tend to fluctuate more and a
 * 3-second average would be too erratic.
 */
static void
update_speed_ring(struct tfo_side *fos, uint64_t howmuch)
{
	struct dl_speed_hist *hist = &fos->dl.hist;
	time_ns_t recent_age = now - fos->dl.recent_start;

	/* Update the download count. */
	fos->dl.recent_bytes += howmuch;
	if (!fos->dl.recent_start) {
		fos->dl.recent_start = now;
		return;
	}

	/* For very small time intervals, we return after having updated the
	 * "recent" download count.  When its age reaches or exceeds minimum
	 * sample time, it will be recorded in the history ring. */
	if (recent_age < DLSPEED_SAMPLE_MIN)
		return;

	if (!howmuch) {
		/* If we're not downloading anything, we might be stalling,
		 * i.e. not downloading anything for an extended period of time.
		 * Since 0-reads do not enter the history ring, recent_age
		 * effectively measures the time since last read. */
		if (recent_age >= STALL_START_TIME) {
			/* If we're stalling, reset the ring contents because it's
			 * stale and because it will make bar_update stop printing
			 * the (bogus) current bandwidth.  */
			fos->dl.stalled = true;
			memset(hist, 0, sizeof(*hist));
			fos->dl.recent_bytes = 0;
		}
		return;
	}

	/* We now have a non-zero amount to store to the speed ring */

	/* If the stall status was acquired, reset it. */
	if (fos->dl.stalled) {
		fos->dl.stalled = false;
		/* "recent_age" includes the entire stalled period, which
		 * could be very long.  Don't update the speed ring with that
		 * value because the current bandwidth would start too small.
		 * Start with an arbitrary (but more reasonable) time value and
		 * let it level out.
		 */
		recent_age = 1;
	}

	/* Store "recent" bytes and download time to history ring at the position POS.  */

	/* To correctly maintain the totals, first invalidate existing data
	 * (least recent in time) at this position. */
	hist->total_time  -= hist->times[hist->pos];
	hist->total_bytes -= hist->bytes[hist->pos];

	/* Now store the new data and update the totals. */
	hist->times[hist->pos] = recent_age;
	hist->bytes[hist->pos] = fos->dl.recent_bytes;
	hist->total_time  += recent_age;
	hist->total_bytes += fos->dl.recent_bytes;

	/* Start a new "recent" period. */
	fos->dl.recent_start = now;
	fos->dl.recent_bytes = 0;

	/* Advance the current ring position. */
	if (++hist->pos == DLSPEED_HISTORY_SIZE)
		hist->pos = 0;

#if 0
	/* Sledgehammer check to verify that the totals are accurate. */
	int i;
	uint64_t sumt = 0, sumb = 0;
	for (i = 0; i < DLSPEED_HISTORY_SIZE; i++) {
		sumt += hist->times[i];
		sumb += hist->bytes[i];
	}
	assert (sumb == hist->total_bytes);
// The following coment does not work when ising ns timers
	/* We can't use assert(sumt==hist->total_time) because some
	 precision is lost by adding and subtracting floating-point
	 numbers.  But during a download this precision should not be
	 detectable, i.e. no larger than 1ns.  */
	time_ns_t diff = sumt - hist->total_time;
	if (diff < 0) diff = -diff;
	assert (diff < 1);
#endif
}

/* Calculate the download rate and trim it as appropriate for the
   speed.  Appropriate means that if rate is greater than 1K/s,
   kilobytes are used, and if rate is greater than 1MB/s, megabytes
   are used.

   UNITS is zero for B/s, one for KB/s, two for MB/s, and three for
   GB/s.  */

bool report_bps;

static uint64_t
convert_to_bits(uint64_t bytes)
{
	if (report_bps)
		return bytes * 8;

	return bytes;
}

static uint64_t
calc_rate(uint64_t bytes, time_ns_t nano_secs, int *units)
{
	uint64_t dlrate, dlrate_mille;
	uint64_t bibyte;

	if (!report_bps)
		bibyte = 1024;
	else
		bibyte = 1000;

#if 0
	if (secs == 0)
		/* If elapsed time is exactly zero, it means we're under the
		 * resolution of the timer.  This can easily happen on systems
		 * that use time() for the timer.  Since the interval lies between
		 * 0 and the timer's resolution, assume half the resolution. */
		secs = ptimer_resolution () / 2.0;
#endif

	dlrate_mille = nano_secs ? convert_to_bits(bytes * 1000000000) / (nano_secs / 1000) : 0;
	dlrate = dlrate_mille / 1000;
	if (dlrate < bibyte)
		*units = 0;
	else if (dlrate < (bibyte * bibyte))
		*units = 1, dlrate_mille /= bibyte;
	else if (dlrate < (bibyte * bibyte * bibyte))
		*units = 2, dlrate_mille /= (bibyte * bibyte);
	else if (dlrate < (bibyte * bibyte * bibyte * bibyte))
		*units = 3, dlrate_mille /= (bibyte * bibyte * bibyte);
	else {
		*units = 4, dlrate_mille /= (bibyte * bibyte * bibyte * bibyte);
#if 0
		if (dlrate_mille > 99.99)
			dlrate_mille = 99.99; // upper limit 99.99TB/s
#endif
	}

	return dlrate_mille;
}

#if 0
/* Return a printed representation of the download rate, along with
   the units appropriate for the download speed.  */
static const char *
retr_rate (uint64_t bytes, time_ns_t n_secs)
{
  static char res[20];
  static const char *rate_names[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s" };
  static const char *rate_names_bits[] = {"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s" };
  int units;

  uint64_t dlrate = calc_rate(bytes, n_secs, &units);
  /* Use more digits for smaller numbers (regardless of unit used),
     e.g. "1022", "247", "12.5", "2.38".  */
  snprintf(res, sizeof(res), "%lu.%.*lu %s",
	   dlrate / 1000,
           dlrate >= 100000 ? 0 : dlrate >= 10000 ? 1 : 2,
	   dlrate >= 100000 ? 0 : dlrate >= 10000 ? (dlrate % 1000) / 100 : (dlrate % 1000) / 10,
           !report_bps ? rate_names[units]: rate_names_bits[units]);

  return res;
}
#endif

static const char *short_units[] = { " B/s", "KB/s", "MB/s", "GB/s", "TB/s" };
static const char *short_units_bits[] = { " b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s" };

static void
print_dl_speed(struct tfo_side *fos)
{
	/* " 12.52Kb/s or 12.52KB/s" */
	if (fos->dl.hist.total_time > 0 && fos->dl.hist.total_bytes) {
		int units = 0;
		/* Calculate the download speed using the history ring and
		 * recent data that hasn't made it to the ring yet. */
		uint64_t dlquant = fos->dl.hist.total_bytes + fos->dl.recent_bytes;
		time_ns_t dltime = fos->dl.hist.total_time + (now - fos->dl.recent_start);
		uint64_t dlspeed = calc_rate(dlquant, dltime, &units);
		printf("%lu.%*.*lu%s", dlspeed / 1000,
			dlspeed >= 100000 ? 0 : dlspeed >= 10000 ? 1 : 2,
			dlspeed >= 100000 ? 0 : dlspeed >= 10000 ? 1 : 2,
			dlspeed >= 100000 ? 0 : dlspeed >= 10000 ? (dlspeed % 1000) / 100 : (dlspeed % 1000) / 10,
			!report_bps ? short_units[units] : short_units_bits[units]);
	}
}
#endif

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
	prev = rb_prev(&ef->timer.node);
	next = rb_next(&ef->timer.node);

	/* If we are already in the right place, leave it there */
	if ((!prev || container_of(prev, struct timer_rb_node, node)->time <= ef->timer.time) &&
	    (!next || container_of(next, struct timer_rb_node, node)->time >= ef->timer.time)) {
		return;
	}

	rb_erase_cached(&ef->timer.node, &timer_tree);
	rb_add_cached(&ef->timer.node, &timer_tree, timer_less);
}

static inline void
update_timer_ef(struct tfo_eflow *ef)
{
	time_ns_t min_time = TFO_INFINITE_TS;
	struct  tfo *fo;

	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		fo = &worker.f[ef->tfo_idx];

		/* Note, the timeouts cannot be TFO_TS_NONE */
		if (fo->priv.timeout < min_time)
			min_time = fo->priv.timeout;
		if (fo->pub.timeout < min_time)
			min_time = fo->pub.timeout;

		if (ack_delayed(&fo->priv) && fo->priv.delayed_ack_timeout < min_time)
			min_time = fo->priv.delayed_ack_timeout;
		if (ack_delayed(&fo->pub) && fo->pub.delayed_ack_timeout < min_time)
			min_time = fo->pub.delayed_ack_timeout;
	}

	if (unlikely(ef->idle_timeout < min_time))
		min_time = ef->idle_timeout;

	if (ef->timer.time == min_time)
		return;

	ef->timer.time = min_time;
	update_timer_move(ef);
}

static inline void
update_timer(struct tfo_eflow *ef, time_ns_t ns)
{
	if (ns == ef->timer.time)
		return;

	if (ns < ef->timer.time) {
		ef->timer.time = ns;

		update_timer_move(ef);
		return;
	}

	update_timer_ef(ef);
}

static inline void
set_ack_bit(struct tfo_tx_bufs *tx_bufs, uint16_t bit)
{
	tx_bufs->acks[bit / CHAR_BIT] |= (1U << (bit % CHAR_BIT));
}

static inline void
clear_ack_bit(struct tfo_tx_bufs *tx_bufs, uint16_t bit)
{
	tx_bufs->acks[bit / CHAR_BIT] &= ~(1U << (bit % CHAR_BIT));
}

static inline bool
ack_bit_is_set(struct tfo_tx_bufs *tx_bufs, uint16_t bit)
{
	return !!(tx_bufs->acks[bit / CHAR_BIT] & (1U << (bit % CHAR_BIT)));
}

#if defined DEBUG_MEMPOOL || defined DEBUG_ACK_MEMPOOL || defined DEBUG_MEMPOOL_INIT || defined DEBUG_ACK_MEMPOOL_INIT || defined DEBUG_PCAP_MEMPOOL
void show_mempool(const char *);	// Prototype needed in case not declared in tfo.h
void
show_mempool(const char *name)
{
	char bdr_str[256];
	const char *bdr_fmt = "==========";

	snprintf(bdr_str, sizeof(bdr_str), " show - MEMPOOL ");
	printf("%s%s%s\n", bdr_fmt, bdr_str, bdr_fmt);

	if (name != NULL) {
		struct rte_mempool *ptr = rte_mempool_lookup(name);
		if (ptr != NULL) {
			struct rte_mempool_ops *ops;
			uint64_t flags = ptr->flags;

			ops = rte_mempool_get_ops(ptr->ops_index);
			printf("  - Name: %s on socket %d\n"
				"  - flags:\n"
				"\t  -- No spread (%c)\n"
				"\t  -- No cache align (%c)\n"
				"\t  -- SP put (%c), SC get (%c)\n"
				"\t  -- Pool created (%c)\n"
				"\t  -- No IOVA config (%c)\n"
				"\t  -- Not used for IO (%c)\n",
				ptr->name,
				ptr->socket_id,
				(flags & RTE_MEMPOOL_F_NO_SPREAD) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_NO_CACHE_ALIGN) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_SP_PUT) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_SC_GET) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_POOL_CREATED) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_NO_IOVA_CONTIG) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_NON_IO) ? 'y' : 'n');
			printf("  - Size %u Cache %u element %u\n"
				"  - header %u trailer %u\n"
				"  - private data size %u\n",
				ptr->size,
				ptr->cache_size,
				ptr->elt_size,
				ptr->header_size,
				ptr->trailer_size,
				ptr->private_data_size);
			printf("  - memezone - socket %d\n",
				ptr->mz->socket_id);
			printf("  - Count: avail (%u), in use (%u)\n",
				rte_mempool_avail_count(ptr),
				rte_mempool_in_use_count(ptr));
			printf("  - ops_index %d ops_name %s\n",
				ptr->ops_index, ops ? ops->name : "NA");

			return;
		}
	}

	rte_mempool_list_dump(stdout);
}
#endif

#ifdef WRITE_PCAP
static void
open_pcap(void)
{
	pid_t tid = gettid();
	char filename[100];
	struct utsname uts;
	char osname[sizeof(uts.sysname) + 1 + sizeof(uts.release) + 1];
	char appname[50];

	uname(&uts);
	sprintf(osname, "%s %s", uts.sysname, uts.release);
	sprintf(appname, "tfo 0.2 %s", rte_version());

	sprintf(filename, "/tmp/tfo-priv-%u-%u-%d.pcapng", port_id, queue_idx, tid);
	pcap_priv_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
	pcap_priv = rte_pcapng_fdopen(pcap_priv_fd, osname, uts.machine, appname, "Packets on private side");

	sprintf(filename, "/tmp/tfo-pub-%u-%u-%d.pcapng", port_id, queue_idx, tid);
	pcap_pub_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
	pcap_pub = rte_pcapng_fdopen(pcap_pub_fd, osname, uts.machine, appname, "Packets on public side");

	sprintf(filename, "/tmp/tfo-all-%u-%u-%d.pcapng", port_id, queue_idx, tid);
	pcap_all_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
	pcap_all = rte_pcapng_fdopen(pcap_all_fd, osname, uts.machine, appname, "Packets on both sides");
}

static inline void
write_and_free_pcap(struct rte_mbuf **pcap_bufs_all, uint16_t *nb_all,
			struct rte_mbuf **pcap_bufs_pub, uint16_t *nb_pub,
			struct rte_mbuf **pcap_bufs_priv, uint16_t *nb_priv)
{
	if (*nb_all) {
		rte_pcapng_write_packets(pcap_all, pcap_bufs_all, *nb_all);
		rte_pktmbuf_free_bulk(pcap_bufs_all, *nb_all);
		*nb_all = 0;
	}

	if (*nb_pub) {
		rte_pcapng_write_packets(pcap_pub, pcap_bufs_pub, *nb_pub);
		rte_pktmbuf_free_bulk(pcap_bufs_pub, *nb_pub);
		*nb_pub = 0;
	}

	if (*nb_priv) {
		rte_pcapng_write_packets(pcap_priv, pcap_bufs_priv, *nb_priv);
		rte_pktmbuf_free_bulk(pcap_bufs_priv, *nb_priv);
		*nb_priv = 0;
	}
}

static void
write_pcap(struct rte_mbuf **bufs, uint16_t nb_buf, enum rte_pcapng_direction direction)
{
	uint64_t tsc = rte_rdtsc();
	struct rte_mbuf **pcap_bufs_all;
	struct rte_mbuf **pcap_bufs_priv;
	struct rte_mbuf **pcap_bufs_pub;
	uint16_t i;
	uint16_t nb_pub = 0;
	uint16_t nb_priv = 0;
	uint16_t nb_all = 0;
	struct rte_mbuf *copy_all, *copy_side;
	char packet_pool_name[16];
	bool failed = false;

	if (!nb_buf)
		return;

	if (!pcap_mempool) {
		if (rte_pktmbuf_data_room_size(bufs[0]->pool) >= rte_pcapng_mbuf_size(1500))
			pcap_mempool = bufs[0]->pool;
		else {
			snprintf(packet_pool_name, sizeof(packet_pool_name), "pcap_pool_%u", port_id);
			/* We want BURST_SIZE * 2 * 2 - every received packet could be forwarded and ack'd, and
			 * we save each packet twice. The correct way to do this would be for BURST_SIZE to be
			 * passed as a parameter at tfo_worker_init() */
			pcap_mempool = rte_pktmbuf_pool_create(packet_pool_name,
								32 * 2 * 2 * 2 - 1,
								32,
								0,
								rte_pcapng_mbuf_size(1500),
								rte_socket_id());
		}
	}

	pcap_bufs_all = rte_malloc("pcap_all", nb_buf * sizeof(struct rte_mbuf *), 0);
	pcap_bufs_priv = rte_malloc("pcap_all", nb_buf * sizeof(struct rte_mbuf *), 0);
	pcap_bufs_pub = rte_malloc("pcap_all", nb_buf * sizeof(struct rte_mbuf *), 0);

	for (i = 0; i < nb_buf; i++) {
		copy_all = rte_pcapng_copy(port_id, queue_idx, bufs[i], pcap_mempool, UINT32_MAX, tsc, direction);
		copy_side = rte_pcapng_copy(port_id, queue_idx, bufs[i], pcap_mempool, UINT32_MAX, tsc, direction);
		if (!copy_all || !copy_side) {
			if (copy_all || copy_side)
				rte_pktmbuf_free(copy_all ? copy_all : copy_side);

			printf("rte_pcap_copy failed, i %u, nb_all %u, nb_buf %u, rte_errno %d\n", i, nb_all, nb_buf, rte_errno);

			if (nb_all == 0 || failed)
				return;

			write_and_free_pcap(pcap_bufs_all, &nb_all, pcap_bufs_pub, &nb_pub, pcap_bufs_priv, &nb_priv);

			failed = true;
			i--;
			continue;
		}

		failed = false;
		pcap_bufs_all[nb_all++] = copy_all;
		if (!!(bufs[i]->ol_flags & config->dynflag_priv_mask) ==
		    (direction == RTE_PCAPNG_DIRECTION_IN))
			pcap_bufs_priv[nb_priv++] = copy_side;
		else
			pcap_bufs_pub[nb_pub++] = copy_side;
	}

#ifdef DEBUG_PCAP_MEMPOOL
	snprintf(packet_pool_name, sizeof(packet_pool_name), "pcap_pool_%u", port_id);
	show_mempool(packet_pool_name);
#endif

	write_and_free_pcap(pcap_bufs_all, &nb_all, pcap_bufs_pub, &nb_pub, pcap_bufs_priv, &nb_priv);

	rte_free(pcap_bufs_all);
	rte_free(pcap_bufs_pub);
	rte_free(pcap_bufs_priv);
}
#endif

#if (defined DEBUG_QUEUE_PKTS && defined DEBUG_PKTS) || defined DEBUG_CHECKSUM || defined DEBUG_CHECK_ADDR
static void
dump_m(struct rte_mbuf *m)
{
	uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

	for (unsigned i = 0; i < m->data_len; i++) {
		if (i && !(i % 8)) {
			if (!(i % 16))
				printf("\n");
			else
				printf(" ");
		}
		if (!(i % 16))
			printf("%4.4x\t", i);
		else
			printf(" ");
		printf("%2.2x", p[i]);
	}
	printf("\n");
}
#endif

#if defined DEBUG_STRUCTURES || defined DEBUG_PKTS || defined DEBUG_TIMERS
#define	SI	"  "
#define	SIS	" "
time_ns_t start_ns;

static thread_local char debug_time_abs[19];
static thread_local char debug_time_rel[20 + 1 + 9 + 5 + 20 + 1 + 9 + 1];

static inline void
format_debug_time(void)
{
	struct timespec ts_wallclock;
	struct tm tm;
	time_ns_t gap;

	if (!last_time)
		last_time = start_ns;

	clock_gettime(CLOCK_REALTIME, &ts_wallclock);
	gap = now - last_time;
	localtime_r(&ts_wallclock.tv_sec, &tm);
	strftime(debug_time_abs, sizeof(debug_time_abs), "%T", &tm);
	sprintf(debug_time_abs + 8, ".%9.9ld", ts_wallclock.tv_nsec);
	sprintf(debug_time_rel, NSEC_TIME_PRINT_FORMAT " gap " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(now), gap / NSEC_PER_SEC, gap % NSEC_PER_SEC);
	last_time = now;
}

static void
print_side(const struct tfo_side *s, const struct tfo_eflow *ef)
{
	struct tfo_pkt *p;
	uint32_t next_exp;
	time_ns_t time_diff;
	uint16_t num_gaps = 0;
	uint8_t *data_start;
	unsigned sack_entry, last_sack_entry;
	uint16_t num_in_flight = 0;
	uint16_t num_sacked = 0;
	uint16_t num_queued = 0;
	char flags[13];

	flags[0] = '\0';
	if (s->flags & TFO_SIDE_FL_IN_RECOVERY) strcat(flags, "R");
	if (s->flags & TFO_SIDE_FL_ENDING_RECOVERY) strcat(flags, "r");
	if (s->flags & TFO_SIDE_FL_RACK_REORDERING_SEEN) strcat(flags, "O");
	if (s->flags & TFO_SIDE_FL_DSACK_ROUND) strcat(flags, "D");
	if (s->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) strcat(flags, "P");
	if (s->flags & TFO_SIDE_FL_TLP_IS_RETRANS) strcat(flags, "t");
	if (s->flags & TFO_SIDE_FL_RTT_CALC_IN_PROGRESS) strcat(flags, "C");
	if (s->flags & TFO_SIDE_FL_NEW_RTT) strcat(flags, "n");
	if (s->flags & TFO_SIDE_FL_FIN_RX) strcat(flags, "F");
	if (s->flags & TFO_SIDE_FL_CLOSED) strcat(flags, "c");
	if (s->flags & TFO_SIDE_FL_RTT_FROM_SYN) strcat(flags, "S");
#ifdef CALC_USERS_TS_CLOCK
	if (s->flags & TFO_SIDE_FL_TS_CLOCK_OVERFLOW) strcat (flags, "T");
#endif

	printf(SI SI SI "rcv_nxt 0x%x snd_una 0x%x snd_nxt 0x%x snd_win 0x%x rcv_win 0x%x ssthresh 0x%x"
		" cwnd 0x%x dup_ack %u last_rcv_win_end 0x%x\n"
		SI SI SI SIS "snd_win_shift %u rcv_win_shift %u mss 0x%x flags-%s packet_type 0x%x in_flight %u queued %u",
		s->rcv_nxt, s->snd_una, s->snd_nxt, s->snd_win, s->rcv_win, s->ssthresh, s->cwnd, s->dup_ack, s->last_rcv_win_end,
		s->snd_win_shift, s->rcv_win_shift, s->mss, flags, s->packet_type, s->pkts_in_flight, s->pkts_queued_send);
	if (ef->flags & TFO_EF_FL_SACK)
		printf(" rtt_min %u", minmax_get(&s->rtt_min));
	if (!list_empty(&s->xmit_ts_list))
		printf(" xmit_ts seq 0x%x<->0x%x",
			list_first_entry(&s->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->seq,
			list_last_entry(&s->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->seq);
	if (s->last_sent == &s->xmit_ts_list)
		printf(" no last sent");
	else
		printf(" last sent 0x%x", list_entry(s->last_sent, struct tfo_pkt, xmit_ts_list)->seq);
	printf(" last_ack 0x%x pktcount %u\n", s->last_ack_sent, s->pktcount);
	if ((ef->flags & TFO_EF_FL_SACK) &&
	     (s->sack_entries || s->sack_gap)) {
		printf(SI SI SI SIS "sack_gaps %u sack_entries %u, first_entry %u", s->sack_gap, s->sack_entries, s->first_sack_entry);
		last_sack_entry = (s->first_sack_entry + s->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
		for (sack_entry = s->first_sack_entry; ; sack_entry = (sack_entry + 1) % MAX_SACK_ENTRIES) {
			printf(" [%u]: 0x%x -> 0x%x", sack_entry, s->sack_edges[sack_entry].left_edge, s->sack_edges[sack_entry].right_edge);
			if (sack_entry == last_sack_entry)
				break;
		}
		printf("\n");
	}
	printf(SI SI SI SIS "srtt %u rttvar %u rto %u #pkt %u, ttl %u", s->srtt_us, s->rttvar_us, s->rto_us, s->pktcount, s->rcv_ttl);
	if (ef->flags & TFO_EF_FL_IPV6)
		printf(", vtc_flow 0x%x", s->vtc_flow);
	printf(" snd_win_end 0x%x rcv_win_end 0x%x",
		s->snd_una + (s->snd_win << s->snd_win_shift),
		s->rcv_nxt + (s->rcv_win << s->rcv_win_shift));
#ifdef DEBUG_RTT_MIN
	if (ef->flags & TFO_EF_FL_SACK) {
		printf(" rtt_min [0] %u," NSEC_TIME_PRINT_FORMAT,
			s->rtt_min.s[0].v, NSEC_TIME_PRINT_PARAMS(s->rtt_min.s[0].t * NSEC_PER_USEC));
		if (s->rtt_min.s[1].t == s->rtt_min.s[0].t &&
		    s->rtt_min.s[1].v == s->rtt_min.s[0].v)
			printf(" [1] = [0]");
		else
			printf(" [1] %u," NSEC_TIME_PRINT_FORMAT,
				s->rtt_min.s[1].v, NSEC_TIME_PRINT_PARAMS(s->rtt_min.s[1].t * NSEC_PER_USEC));
		if (s->rtt_min.s[2].t == s->rtt_min.s[1].t &&
		    s->rtt_min.s[2].v == s->rtt_min.s[2].v)
			printf(" [2] = [1]");
		else
			printf(" [2] %u," NSEC_TIME_PRINT_FORMAT,
				s->rtt_min.s[2].v, NSEC_TIME_PRINT_PARAMS(s->rtt_min.s[2].t * NSEC_PER_USEC));
	}
#endif
	if (ef->flags & TFO_EF_FL_TIMESTAMP) {
		printf("\n" SI SI SI SIS "ts_recent %1$u (0x%1$x) latest_ts_val %2$u (0x%2$x)", rte_be_to_cpu_32(s->ts_recent), s->latest_ts_val);
#ifdef CALC_USERS_TS_CLOCK
		printf(" last_ts_val_sent %u TS start %u",
				s->last_ts_val_sent, s->ts_start);
		printf(" at " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->ts_start_time));
		if (s->flags & TFO_SIDE_FL_TS_CLOCK_OVERFLOW)
			printf(" ovf");
		printf(" nsecs per tock %u", s->nsecs_per_tock);
#endif
	}

#ifdef CWND_USE_RECOMMENDED
	printf(" cum_ack 0x%x", s->cum_ack);
#endif
	printf(" ack_delay ");
	if (s->delayed_ack_timeout == TFO_INFINITE_TS)
		printf("unset");
	else if (s->delayed_ack_timeout == TFO_ACK_NOW_TS)
		printf("3WHS ACK");
	else if (s->delayed_ack_timeout >= now)
		printf (NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->delayed_ack_timeout), NSEC_TIME_PRINT_PARAMS_ABS(s->delayed_ack_timeout - now));
	else
		printf (NSEC_TIME_PRINT_FORMAT " - " NSEC_TIME_PRINT_FORMAT " ago", NSEC_TIME_PRINT_PARAMS(s->delayed_ack_timeout), NSEC_TIME_PRINT_PARAMS_ABS(now - s->delayed_ack_timeout));
#ifdef DEBUG_RACK
	if (using_rack(ef))
		printf("\n" SI SI SI SIS "RACK: xmit_ts " NSEC_TIME_PRINT_FORMAT " end_seq 0x%x segs_sacked %u fack 0x%x rtt %u reo_wnd %u dsack_round 0x%x reo_wnd_mult %u\n"
		       SI SI SI SIS "      reo_wnd_persist %u tlp_end_seq 0x%x tlp_max_ack_delay %u",
			NSEC_TIME_PRINT_PARAMS(s->rack_xmit_ts), s->rack_end_seq, s->rack_segs_sacked, s->rack_fack,
			s->rack_rtt_us, s->rack_reo_wnd_us, s->rack_dsack_round, s->rack_reo_wnd_mult,
			s->rack_reo_wnd_persist, s->tlp_end_seq, s->tlp_max_ack_delay_us);
#endif

	printf(" recovery_end_seq 0x%x cur_timer ", s->recovery_end_seq);
	if (s->cur_timer == TFO_TIMER_NONE) printf("none");
	else if (s->cur_timer == TFO_TIMER_RTO) printf("RTO");
	else if (s->cur_timer == TFO_TIMER_PTO) printf("PTO");
	else if (s->cur_timer == TFO_TIMER_REO) printf("REO");
	else if (s->cur_timer == TFO_TIMER_ZERO_WINDOW) printf("ZW");
	else if (s->cur_timer == TFO_TIMER_KEEPALIVE) printf("KA");
	else if (s->cur_timer == TFO_TIMER_SHUTDOWN) printf("SH");
	else printf("unknown %u", s->cur_timer);
	if (s->timeout == TFO_INFINITE_TS)
		printf(" unset");
	else if (s->timeout >= now)
		printf (" timeout " NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->timeout), NSEC_TIME_PRINT_PARAMS_ABS(s->timeout - now));
	else
		printf (" timeout " NSEC_TIME_PRINT_FORMAT " - " NSEC_TIME_PRINT_FORMAT " ago", NSEC_TIME_PRINT_PARAMS(s->timeout), NSEC_TIME_PRINT_PARAMS_ABS(now - s->timeout));
	printf(" ka probes %u\n", s->keepalive_probes);

#ifdef DEBUG_DLSPEED_DEBUG
	printf(SI SI SI SIS "total: time " NSEC_TIME_PRINT_FORMAT " bytes %lu, recent: time " NSEC_TIME_PRINT_FORMAT " bytes %lu pos %d\n",
		 NSEC_TIME_PRINT_PARAMS_ABS(s->dl.hist.total_time), s->dl.hist.total_bytes, NSEC_TIME_PRINT_PARAMS_ABS(now - s->dl.recent_start), s->dl.recent_bytes, s->dl.hist.pos);
	for (unsigned i = 0; i < DLSPEED_HISTORY_SIZE; i++) {
		if (!(i % 5))
			printf(SI SI SI SIS);
		printf("[%2u] " NSEC_TIME_PRINT_FORMAT " %lu", i, NSEC_TIME_PRINT_PARAMS_ABS(s->dl.hist.times[(i) % DLSPEED_HISTORY_SIZE]), s->dl.hist.bytes[(i) % DLSPEED_HISTORY_SIZE]);
		if (i % 5 == 4) {
			printf("\n");
		} else if (i != DLSPEED_HISTORY_SIZE - 1)
			printf(", ");
	}
	if (DLSPEED_HISTORY_SIZE % 5)
		printf("\n");
#endif

	next_exp = s->snd_una;
	unsigned i = 0;
	list_for_each_entry(p, &s->pktlist, list) {
		char s_flags[10];
		char tcp_flags[9];

		s_flags[0] = '\0';
		if (p->flags & TFO_PKT_FL_SENT) strcat(s_flags, "S");
		if (p->flags & TFO_PKT_FL_RESENT) strcat(s_flags, "R");
		if (p->flags & TFO_PKT_FL_RTT_CALC) strcat(s_flags, "r");
		if (p->flags & TFO_PKT_FL_LOST) strcat(s_flags, "L");
		if (p->flags & TFO_PKT_FL_FROM_PRIV) strcat(s_flags, "P");
		if (p->flags & TFO_PKT_FL_ACKED) strcat(s_flags, "a");
		if (p->flags & TFO_PKT_FL_SACKED) strcat(s_flags, "s");
		if (p->flags & TFO_PKT_FL_QUEUED_SEND) strcat(s_flags, "Q");
		if (list_is_queued(&p->send_failed_list)) strcat(s_flags, "F");

		i++;
		if (after(p->seq, next_exp)) {
			printf(SI SI SI "%4u:\t  *** expected 0x%x, gap = %u\n", i, next_exp, p->seq - next_exp);
			num_gaps++;
			i++;
		}

		/* Check ordering of packets */
		if (!list_is_first(&p->list, &s->pktlist) &&
		    !before(list_prev_entry(p, list)->seq, p->seq))
			printf(" ERROR *** pkt not after previous pkt");
		if (!list_is_last(&p->list, &s->pktlist) &&
		    !before(segend(p), segend(list_next_entry(p, list))))
			printf(" ERROR *** pkt ends after next pkt ends");

		data_start = p->m ? rte_pktmbuf_mtod(p->m, uint8_t *) : 0;
		if (p->m) {
			tcp_flags[0] = '\0';
			if (p->tcp->tcp_flags & RTE_TCP_SYN_FLAG) strcat(tcp_flags, "S");
			if (p->tcp->tcp_flags & RTE_TCP_ACK_FLAG) strcat(tcp_flags, "A");
			if (p->tcp->tcp_flags & RTE_TCP_URG_FLAG) strcat(tcp_flags, "U");
			if (p->tcp->tcp_flags & RTE_TCP_PSH_FLAG) strcat(tcp_flags, "P");
			if (p->tcp->tcp_flags & RTE_TCP_CWR_FLAG) strcat(tcp_flags, "C");
			if (p->tcp->tcp_flags & RTE_TCP_ECE_FLAG) strcat(tcp_flags, "E");
			if (p->tcp->tcp_flags & RTE_TCP_FIN_FLAG) strcat(tcp_flags, "F");
			if (p->tcp->tcp_flags & RTE_TCP_RST_FLAG) strcat(tcp_flags, "R");

			printf(SI SI SI "%4u:\tm %p, seq 0x%x%s ack 0x%x, len %u flags-%s tcp_flags-%s vlan %u ip %ld tcp %ld",
				i, p->m, p->seq, after(segend(p), s->snd_una + (s->snd_win << s->snd_win_shift)) ? "*" : "",
				ntohl(p->tcp->recv_ack), p->seglen, s_flags, tcp_flags, p->m->vlan_tci,
				(uint8_t *)p->iph.ip4h - data_start,
				(uint8_t *)p->tcp - data_start);
			if (ef->flags & TFO_EF_FL_TIMESTAMP || p->ts)
				printf(" ts %ld", p->ts ? (uint8_t *)p->ts - data_start : 0U);
			if (ef->flags & TFO_EF_FL_SACK || p->sack) {
				printf(" sack %ld", p->sack ? (uint8_t *)p->sack - data_start : 0U);
				if (ef->flags & TFO_EF_FL_SACK)
					printf(" sacked segs %u", p->rack_segs_sacked);
			}
			printf(" refcnt %u", p->m->refcnt);
		} else
			printf(SI SI SI "%4u:\tm %p, seq 0x%x%s len %u flags-%s sacked_segs %u",
				i, p->m, p->seq, segend(p) > s->snd_una + (s->snd_win << s->snd_win_shift) ? "*" : "",
				p->seglen, s_flags,
				p->rack_segs_sacked);
		if (p->ns != TFO_TS_NONE) {
			time_diff = now - p->ns;
			printf(" ns " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS_ABS(time_diff));

			if (!(p->flags & TFO_PKT_FL_SENT))
				printf(" (%lu)", p->ns);
		}
		if (!list_empty(&p->xmit_ts_list)) {
			printf(" flgt 0x%x <-> 0x%x",
				list_is_first(&p->xmit_ts_list, &s->xmit_ts_list) ? 0 : list_prev_entry(p, xmit_ts_list)->seq,
				list_is_last(&p->xmit_ts_list, &s->xmit_ts_list) ? 0 : list_next_entry(p, xmit_ts_list)->seq);

			if (!(p->flags & TFO_PKT_FL_LOST))
				num_in_flight++;

			if (s->last_sent == &p->xmit_ts_list)
				printf(" last sent");
		}

		if (p->flags & TFO_PKT_FL_QUEUED_SEND)
			num_queued++;

		if (!p->m)
			num_sacked += p->rack_segs_sacked;

		if (before(p->seq, next_exp)) {
			if (!before(next_exp, segend(p)))
				printf(" ERROR *** packet contained in previous packet");
			else
				printf(" *** overlap = %ld", (int64_t)next_exp - (int64_t)p->seq);
		}
		printf("\n");
		next_exp = segend(p);
	}

	if (num_gaps != s->sack_gap)
		printf("ERROR *** s->sack_gap %u, num_gaps %u\n", s->sack_gap, num_gaps);

	if (s->pkts_in_flight != num_in_flight)
		printf("ERROR *** NUM_IN_FLIGHT should be %u\n", num_in_flight);

	if (s->pkts_queued_send != num_queued)
		printf("ERROR *** NUM_QUEUED should be %u\n", num_queued);

	if (s->rack_segs_sacked != num_sacked)
		printf("ERROR *** NUM_SEGS_SACKED should be %u\n", num_sacked);
}

#ifdef DEBUG_DUPLICATE_MBUFS
static bool
check_mbuf_in_use(struct rte_mbuf *m, struct tcp_worker *w, struct tfo_tx_bufs *tx_bufs)
{
	unsigned i;
	struct tfo_eflow *ef;
	struct tfo *fo;
	struct tfo_side *s;
	struct tfo_pkt *pkt;
	bool in_use = false;
	unsigned pkt_no;

	for (i = 0; i < config->hef_n; i++) {
		if (!hlist_empty(&w->hef[i])) {
			hlist_for_each_entry(ef, &w->hef[i], hlist) {
				if (ef->tfo_idx == TFO_IDX_UNUSED)
					continue;
				fo = &w->f[ef->tfo_idx];
				s = &fo->priv;
				while (s) {
					pkt_no = 0;
					list_for_each_entry(pkt, &s->pktlist, list) {
						pkt_no++;
						if (pkt->m == m) {
							printf("New mbuf %p already in use by eflow %p %s pkt %u\n", m, ef, s == &fo->priv ? "priv" : "pub", pkt_no);
							in_use = true;
						}
					}
					s = s == &fo->priv ? &fo->pub : NULL;
				}
			}
		}
	}

	for (i = 0; i < tx_bufs->nb_tx; i++) {
		if (m == tx_bufs->m[i]) {
			in_use = true;
			printf("New mbuf %p already queued for sending slot %u\n", m, i);
		}
	}

	return in_use;
}
#endif

static void
dump_details(const struct tcp_worker *w)
{
	struct tfo_eflow *ef;
	struct tfo *fo;
	unsigned i;
	char flags[9];
	char pub_addr_str[INET6_ADDRSTRLEN];
	char priv_addr_str[INET6_ADDRSTRLEN];
	in_addr_t addr;
#ifdef DEBUG_ETHDEV
	uint16_t port;
	struct rte_eth_stats eth_stats;
#endif

	printf("In use: eflows %u, flows %u, packets %u, max_packets %u timer rb root %p left %p\n", w->ef_use, w->f_use, w->p_use, w->p_max_use,
		RB_EMPTY_ROOT(&timer_tree.rb_root) ? NULL : container_of(timer_tree.rb_root.rb_node, struct tfo_eflow, timer.node),
		timer_tree.rb_leftmost ? container_of(timer_tree.rb_leftmost, struct tfo_eflow, timer.node) : NULL);
	for (i = 0; i < config->hef_n; i++) {
		if (!hlist_empty(&w->hef[i])) {
			printf("Flow hash %u\n", i);
			hlist_for_each_entry(ef, &w->hef[i], hlist) {
				// print eflow
				flags[0] = '\0';
				if (ef->flags & TFO_EF_FL_SYN_FROM_PRIV) strcat(flags, "P");
				if (ef->flags & TFO_EF_FL_CLOSED) strcat(flags, "C");
				if (ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN) strcat(flags, "s");
				if (ef->flags & TFO_EF_FL_SACK) strcat(flags, "S");
				if (ef->flags & TFO_EF_FL_TIMESTAMP) strcat(flags, "T");
				if (ef->flags & TFO_EF_FL_IPV6) strcat(flags, "6");
				if (ef->flags & TFO_EF_FL_DUPLICATE_SYN) strcat(flags, "D");

				if (ef->flags & TFO_EF_FL_IPV6) {
					inet_ntop(AF_INET6, &ef->pub_addr.v6, pub_addr_str, sizeof(pub_addr_str));
					inet_ntop(AF_INET6, &ef->priv_addr.v6, priv_addr_str, sizeof(priv_addr_str));
				} else {
					addr = rte_be_to_cpu_32(ef->pub_addr.v4.s_addr);
					inet_ntop(AF_INET, &addr, pub_addr_str, sizeof(pub_addr_str));
					addr = rte_be_to_cpu_32(ef->priv_addr.v4.s_addr);
					inet_ntop(AF_INET, &addr, priv_addr_str, sizeof(priv_addr_str));
				}
				printf(SI SI "ef %p state %u tfo_idx %u, addr: priv %s pub %s port: priv %u pub %u flags-%s\n",
					ef, ef->state, ef->tfo_idx, priv_addr_str, pub_addr_str, ef->priv_port, ef->pub_port, flags);
				printf(SI SI SIS "idle_timeout " NSEC_TIME_PRINT_FORMAT " (" NSEC_TIME_PRINT_FORMAT ") timer " NSEC_TIME_PRINT_FORMAT " (" NSEC_TIME_PRINT_FORMAT ") rb %p / %p \\ %p\n",
					NSEC_TIME_PRINT_PARAMS(ef->idle_timeout), NSEC_TIME_PRINT_PARAMS_ABS(ef->idle_timeout - now),
					NSEC_TIME_PRINT_PARAMS(ef->timer.time), NSEC_TIME_PRINT_PARAMS_ABS(ef->timer.time - now),
					ef->timer.node.rb_left ? container_of(ef->timer.node.rb_left, struct tfo_eflow, timer.node) : NULL,
					rb_parent(&ef->timer.node) ? container_of(rb_parent(&ef->timer.node), struct tfo_eflow, timer.node) : NULL,
					ef->timer.node.rb_right ? container_of(ef->timer.node.rb_right, struct tfo_eflow, timer.node) : NULL);
				if (ef->state == TCP_STATE_SYN)
					printf(SI SI SIS "svr_snd_una 0x%x cl_snd_win 0x%x cl_rcv_nxt 0x%x cl_ttl %u SYN ns " NSEC_TIME_PRINT_FORMAT "\n",
					       ef->server_snd_una, ef->client_snd_win, ef->client_rcv_nxt, ef->client_ttl, NSEC_TIME_PRINT_PARAMS(ef->start_time));
				if (ef->tfo_idx != TFO_IDX_UNUSED) {
					// Print tfo
					fo = &w->f[ef->tfo_idx];
					printf(SI SI SIS "idx %u\n", fo->idx);
					printf(SI SI SIS "private: (%p)\n", &fo->priv);
					print_side(&fo->priv, ef);
					printf(SI SI SIS "public: (%p)\n", &fo->pub);
					print_side(&fo->pub, ef);
				}
				printf("\n");
			}
		}
	}

#ifdef DEBUG_ETHDEV
	if (rte_eth_stats_get(port = (rte_lcore_id() - 1), &eth_stats))
		printf("Failed to get stats for port %u\n", port);
	else {
		printf("port %u: i (p, b, e) %lu %lu %lu o %lu %lu %lu m %lu nom %lu\n",
			port,
			eth_stats.ipackets, eth_stats.ibytes, eth_stats.ierrors,
			eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors,
			eth_stats.imissed, eth_stats.rx_nombuf);

#ifdef DEBUG_MEMPOOL
		if (eth_stats.rx_nombuf)
			show_mempool("packet_pool_0");
#endif
	}
#endif

	printf("\n");
	fflush(stdout);
}
#endif

#ifdef DEBUG_CHECKSUM
static bool
check_checksum(struct tfo_pkt *pkt, const char *msg)
{
	if (rte_ipv4_udptcp_cksum_verify(pkt->ipv4, pkt->tcp)) {
		printf("%s: ip checksum 0x%4.4x (%4.4x), tcp checksum 0x%4.4x (%4.4x), not GOOD\n", msg,
		rte_be_to_cpu_16(pkt->ipv4->hdr_checksum), rte_ipv4_cksum(pkt->ipv4),
		rte_be_to_cpu_16(pkt->tcp->cksum), rte_ipv4_udptcp_cksum(pkt->ipv4, pkt->tcp));

		dump_m(pkt->m);

		return false;
	}

	return true;
}

static bool
check_checksum_in(struct rte_mbuf *m, const char *msg)
{
	struct tfo_pkt pkt;
	uint16_t hdr_len;

	pkt.m = m;
	switch (m->packet_type & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER:
		hdr_len = sizeof (struct rte_ether_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_VLAN:
		hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
		break;
	}
	pkt.ipv4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdr_len);
	switch (m->packet_type & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));
		break;
	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(pkt.ipv4));
		break;
	}

	return check_checksum(&pkt, msg);
}
#endif

static inline uint16_t
update_checksum(uint16_t old_cksum, void *old_bytes, void *new_bytes, uint16_t len)
{
	uint32_t new_cksum = old_cksum ^ 0xffff;
	uint16_t *old = old_bytes;
	uint16_t *new = new_bytes;

#ifdef DEBUG_CHECKSUM_DETAIL
	uint8_t *old_bytes_u = old_bytes, *new_bytes_u = new_bytes;
	printf("update_checksum old %4.4x len %u old_bytes %p [0] %2.2x [1] %2.2x [2] %2.2x [3] %2.2x new_bytes %p [0] %2.2x [1] %2.2x [2] %2.2x [3] %2.2x",
	old_cksum, len, old_bytes_u, old_bytes_u[0], old_bytes_u[1], old_bytes_u[2], old_bytes_u[3], new_bytes_u, new_bytes_u[0], new_bytes_u[1], new_bytes_u[2], new_bytes_u[3]);
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

static inline struct tfo_mbuf_priv *
get_priv_addr(struct rte_mbuf *m)
{
	char *priv = rte_mbuf_to_priv(m);

	return (struct tfo_mbuf_priv *)(priv + config->mbuf_priv_offset);
}

/* Change this so that we return m and it can be added to tx_bufs */
static inline void
add_tx_buf(const struct tcp_worker *w, struct rte_mbuf *m, struct tfo_tx_bufs *tx_bufs, bool from_priv, union tfo_ip_p iph, bool discard_after_send)
{
#ifdef DEBUG_QUEUE_PKTS
	printf("Adding packet m %p data_len %u pkt_len %u vlan %u\n", m, m->data_len, m->pkt_len, m->vlan_tci);
#ifdef DEBUG_PKTS
	dump_m(m);
#endif
#endif

	/* Update TTL, timestamp and ack */

	if (unlikely(!tx_bufs->m)) {
		tx_bufs->max_tx = tx_bufs->nb_inc;
		tx_bufs->m = rte_malloc("tx_bufs", tx_bufs->max_tx * sizeof(struct rte_mbuf *), 0);
		tx_bufs->acks = rte_malloc("tx_bufs_ack", (tx_bufs->max_tx - 1) / CHAR_BIT + 1, 0);
	} else if (unlikely(tx_bufs->nb_tx == tx_bufs->max_tx)) {
		tx_bufs->max_tx += tx_bufs->nb_inc;
		tx_bufs->m = rte_realloc(tx_bufs->m, tx_bufs->max_tx * sizeof(struct rte_mbuf *), 0);
		tx_bufs->acks = rte_realloc(tx_bufs->acks, (tx_bufs->max_tx - 1) / CHAR_BIT + 1, 0);
	}

	tx_bufs->m[tx_bufs->nb_tx] = m;
	if (discard_after_send)
		set_ack_bit(tx_bufs, tx_bufs->nb_tx);
	else
		clear_ack_bit(tx_bufs, tx_bufs->nb_tx);
	tx_bufs->nb_tx++;

	if (iph.ip4h && config->capture_output_packet)
		config->capture_output_packet(w->param, m->packet_type & RTE_PTYPE_L3_IPV6 ? IPPROTO_IPV6 : IPPROTO_IP, m, &w->ts, from_priv, iph);
}

static inline void
tfo_reset_timer(struct tfo_side *fos, tfo_timer_t timer, uint32_t timeout)
{
	fos->cur_timer = timer;
	fos->timeout = now + timeout * NSEC_PER_USEC;

	update_timer(fos->ef, fos->timeout);
}

static inline void
tfo_reset_timer_ns(struct tfo_side *fos, tfo_timer_t timer, time_ns_t timeout)
{
	fos->cur_timer = timer;
	fos->timeout = now + timeout;

	update_timer(fos->ef, fos->timeout);
}

static inline void
tfo_cancel_xmit_timer(struct tfo_side *fos)
{
	time_ns_t timeout = (time_ns_t)config->tcp_keepalive_time * NSEC_PER_SEC;

#ifdef CALC_USERS_TS_CLOCK
	/* Ensure that a keepalive is sent in half the timestamp clock
	 * wrap around time */
	if (fos->nsecs_per_tock &&
	    (time_ns_t)fos->nsecs_per_tock * (1U << 31) < timeout)
		timeout = (time_ns_t)fos->nsecs_per_tock * (1U << 31);
#endif

	tfo_reset_timer_ns(fos, TFO_TIMER_KEEPALIVE, timeout);
	fos->keepalive_probes = config->tcp_keepalive_probes;
	update_timer_ef(fos->ef);
}

static inline void
tfo_restart_keepalive_timer(struct tfo_side *fos)
{
	if (fos->cur_timer == TFO_TIMER_KEEPALIVE)
		tfo_cancel_xmit_timer(fos);
}

static inline bool
set_rcv_win(struct tfo_side *fos, struct tfo_side *foos) {
	uint32_t win_end;
	uint16_t old_rcv_win = fos->rcv_win;

#ifdef DEBUG_RCV_WIN
	printf("Updating rcv_win from 0x%x, foos snd_win 0x%x snd_win_shift %u cwnd 0x%x snd_una 0x%x fos: rcv_win 0x%x",
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

	if (after(win_end, fos->last_rcv_win_end))
		fos->last_rcv_win_end = win_end;
	if (after(fos->last_rcv_win_end, fos->rcv_nxt)) {
		fos->rcv_win = ((fos->last_rcv_win_end - fos->rcv_nxt - 1) >> fos->rcv_win_shift) + 1;

		/* Don't bother with reducing by 1, probably caused by rcv_win_shift */
		if (fos->rcv_win == old_rcv_win - 1)
			fos->rcv_win++;
	} else {
#ifdef DEBUG_TCP_WINDOW
		printf("Send on %s rcv_win = 0x0, foos snd_una 0x%x snd_win 0x%x shift %u, fos->rcv_nxt 0x%x\n", fos < foos ? "priv" : "pub",
			foos->snd_una, foos->snd_win, foos->snd_win_shift, fos->rcv_nxt);
#endif
		fos->rcv_win = 0;
		fos->last_rcv_win_end = fos->rcv_nxt;
	}

#ifdef DEBUG_RCV_WIN
	printf(" to fos rcv_win 0x%x (old 0x%x), last_rcv_win_end 0x%x, len 0x%x(%u)\n", fos->rcv_win, old_rcv_win, fos->last_rcv_win_end, fos->last_rcv_win_end - fos->rcv_win, fos->last_rcv_win_end - fos->rcv_win);
#endif

	return old_rcv_win != fos->rcv_win;
}

static inline uint32_t
get_snd_win_end(const struct tfo_side *fos)
{
	uint32_t len;

	len = fos->snd_win << fos->snd_win_shift;
	if (fos->cwnd < len)
		len = fos->cwnd;

	return fos->snd_una + len;
}

#ifdef CALC_USERS_TS_CLOCK
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
			    (time_ns_t)foos->nsecs_per_tock * (1U << 31) < foos->timeout)
				tfo_reset_timer_ns(foos, TFO_TIMER_KEEPALIVE, (time_ns_t)foos->nsecs_per_tock * (1U << 31));
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
		printf(" DSACK MISMATCH");
	if (dsack_err)
		printf(" DSACK IMPROPER");
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

	if (pkt->m->packet_type & RTE_PTYPE_L3_IPV4)
		ph_old_len_v4 = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
	else
		ph_old_len_v6 = rte_cpu_to_be_32(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));

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
		new_len_v4 = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &ph_old_len_v4, &new_len_v4, sizeof(new_len_v4));

		/* Update IP packet length */
		new_len_v4 = rte_cpu_to_be_16(rte_be_to_cpu_16(pkt->iph.ip4h->total_length) + len);
		pkt->iph.ip4h->hdr_checksum = update_checksum(pkt->iph.ip4h->hdr_checksum, &pkt->iph.ip4h->total_length, &new_len_v4, sizeof(new_len_v4));
	} else {
		/* Update the TCP checksum for the length change in the TCP pseudo header */
		new_len_v6 = rte_cpu_to_be_32(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
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

	return true;
}
_Pragma("GCC pop_options")

static void
_send_ack_pkt(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_pkt *pkt, struct tfo_addr_info *addr,
		uint16_t vlan_id, struct tfo_side *foos, uint32_t *dup_sack, struct tfo_tx_bufs *tx_bufs,
		bool same_dirn, bool must_send, bool is_keepalive, bool send_rst)
{
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vl;
	union tfo_ip_p iph;
	struct rte_tcp_hdr *tcp;
	struct tcp_timestamp_option *ts_opt;
	struct rte_mbuf *m;
	uint8_t *ptr;
	uint16_t pkt_len;
	uint8_t sack_blocks;
	bool do_dup_sack = (dup_sack && dup_sack[0] != dup_sack[1]);
	bool is_ipv6 = !!(ef->flags & TFO_EF_FL_IPV6);

	if (unlikely(!ack_pool)) {
		if (unlikely(!pkt)) {
			/* This should never occur. We can't send an ACK
			 * without receiving a packet first. */
			return;
		}

		ack_pool = pkt->m->pool;
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
			update_timer(ef, fos->delayed_ack_timeout);
		} else if (fos->tlp_max_ack_delay_us > fos->srtt_us) {
			/* We want to ensure the other end received the ACK before it
			 * times out and retransmits, so reduce the ack delay by
			 * 2 * (srtt / 2). srtt / 2 is best estimate of time for ack
			 * to reach the other end, and allow 2 of those intervals to
			 * be conservative. */
			fos->delayed_ack_timeout = now + (fos->tlp_max_ack_delay_us - fos->srtt_us) * NSEC_PER_USEC;
			update_timer(ef, fos->delayed_ack_timeout);
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
		printf (NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(fos->delayed_ack_timeout), NSEC_TIME_PRINT_PARAMS_ABS(fos->delayed_ack_timeout - now));
	printf(" must_send %d dup_sack %p %u:%u, same_dirn %d\n",
		must_send, dup_sack, dup_sack ? dup_sack[0] : 1U, dup_sack ? dup_sack[1] : 0, same_dirn);
#endif

	fos->delayed_ack_timeout = TFO_INFINITE_TS;
	update_timer_ef(ef);

	m = rte_pktmbuf_alloc(ack_pool);

// Handle not forwarding ACK somehow
	if (m == NULL) {
#ifdef DEBUG_NO_MBUF
		printf("Unable to ack 0x%x - no mbuf - vlan %u\n", fos->rcv_nxt, vlan_id);
#endif
		return;
	}

#ifdef DEBUG_DUPLICATE_MBUFS
	printf("ACK packet allocated m %p, pool %s\n", m, m->pool->name);
	if (check_mbuf_in_use(m, w, tx_bufs))
		printf("ACK mbuf %p already in use\n", m);
#endif

	/* If we haven't initialised the private area size, do so now */
	if (ack_pool_priv_size == UINT16_MAX)
		ack_pool_priv_size = rte_pktmbuf_priv_size(m->pool);

	if (ack_pool_priv_size) {
		/* We don't use the private area for ACKs, but the code using this library might */
		memset(get_priv_addr(m), 0x00, sizeof(ack_pool_priv_size));
	}

	if (option_flags & TFO_CONFIG_FL_NO_VLAN_CHG) {
		if (vlan_id == pub_vlan_tci)
			m->ol_flags &= ~config->dynflag_priv_mask;
		else
			m->ol_flags |= config->dynflag_priv_mask;
	} else
		m->vlan_tci = vlan_id;

	/* This will need addressing when we implement 464XLAT */
	m->packet_type = fos->packet_type;

	if ((fos->sack_entries || do_dup_sack) && (ef->flags & TFO_EF_FL_SACK))
		sack_blocks = min(fos->sack_entries + !!do_dup_sack, 4 - !!(ef->flags & TFO_EF_FL_TIMESTAMP));
	else
		sack_blocks = 0;

#ifdef DEBUG_DUP_SACK_SEND
	if (do_dup_sack)
		printf("Sending D-SACK 0x%x -> 0x%x\n", dup_sack[0], dup_sack[1]);
#endif

	pkt_len = sizeof (struct rte_ether_hdr) +
		   (m->vlan_tci ? sizeof(struct rte_vlan_hdr) : 0) +
		   (is_ipv6 ? sizeof(struct rte_ipv6_hdr) : sizeof (struct rte_ipv4_hdr)) +
		   sizeof (struct rte_tcp_hdr) +
		   (ef->flags & TFO_EF_FL_TIMESTAMP ? sizeof(struct tcp_timestamp_option) + 2 : 0) +
		   (sack_blocks ? (sizeof(struct tcp_sack_option) + 2 + sizeof(struct sack_edges) * sack_blocks) : 0);

	eh = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, pkt_len);

	if (unlikely(addr))
		m->port = port_id;
	else
		m->port = pkt->m->port;

	rte_ether_addr_copy(&local_mac_addr, &eh->src_addr);
	rte_ether_addr_copy(&remote_mac_addr, &eh->dst_addr);

	if (m->vlan_tci) {
		eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		vl = (struct rte_vlan_hdr *)(eh + 1);
		vl->vlan_tci = rte_cpu_to_be_16(vlan_id);
		vl->eth_proto = rte_cpu_to_be_16(is_ipv6 ? RTE_ETHER_TYPE_IPV6 : RTE_ETHER_TYPE_IPV4);
		iph.ip4h = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(eh + 1) + 1);
	} else {
		eh->ether_type = rte_cpu_to_be_16(is_ipv6 ? RTE_ETHER_TYPE_IPV6 : RTE_ETHER_TYPE_IPV4);
		iph.ip4h = (struct rte_ipv4_hdr *)(eh + 1);
	}

	if (!is_ipv6) {
		iph.ip4h->version_ihl = 0x45;
		iph.ip4h->type_of_service = 0;
iph.ip4h->type_of_service = 0x10;
		iph.ip4h->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof (*eh) - (m->vlan_tci ? sizeof(*vl) : 0));
// See RFC6864 re identification
		iph.ip4h->packet_id = 0;
// A random!! number
iph.ip4h->packet_id = rte_cpu_to_be_16(w->ts.tv_nsec);
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
#ifdef CALC_USERS_TS_CLOCK
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

#ifdef DEBUG_DUP_SACK_SEND
	if (do_dup_sack)
		printf("ack with D-SACK 0x%x -> 0x%x\n", dup_sack[0], dup_sack[1]);
#endif

	if (sack_blocks) {
		add_sack_option(fos, ptr, sack_blocks, dup_sack);
		tcp->data_off += ((1 + 1 + sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges)) / 4) << 4;
	}

// Checksum offload?
	if (ef->flags & TFO_EF_FL_IPV6)
		tcp->cksum = rte_ipv6_udptcp_cksum(iph.ip6h, tcp);
	else
		tcp->cksum = rte_ipv4_udptcp_cksum(iph.ip4h, tcp);

#ifdef DEBUG_ACK
	printf("Sending ack %p seq 0x%x ack 0x%x len %u", m, fos->snd_nxt, fos->rcv_nxt, m->data_len);
	if (ef->flags & TFO_EF_FL_TIMESTAMP)
		printf(" ts_val %1$u (0x%1$x) ts_ecr %2$u (0x%2$x)", foos->latest_ts_val, rte_be_to_cpu_32(fos->ts_recent));
	printf(" vlan %u, packet_type 0x%x", vlan_id, m->packet_type);
	if (ef->flags & TFO_EF_FL_SACK)
		printf(", sack_blocks %u dup_sack 0x%x:0x%x\n", sack_blocks, dup_sack ? dup_sack[0] : 0, dup_sack ? dup_sack[1] : 0);
#endif

	add_tx_buf(w, m, tx_bufs, pkt ? !(pkt->flags & TFO_PKT_FL_FROM_PRIV) : foos == &w->f[ef->tfo_idx].pub, iph, true);
}

static inline void
_send_ack_pkt_in(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, const struct tfo_pkt_in *p,
		uint16_t vlan_id, struct tfo_side *foos, uint32_t *dup_sack, struct tfo_tx_bufs *tx_bufs, bool same_dirn)
{
	struct tfo_pkt pkt;

	pkt.m = p->m;
	pkt.iph = p->iph;
	pkt.tcp = p->tcp;
	pkt.flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;

	_send_ack_pkt(w, ef, fos, &pkt, NULL, vlan_id, foos, dup_sack, tx_bufs, same_dirn, true, false, false);
}

static inline void
generate_ack_rst(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs, bool is_keepalive, bool send_rst)
{
// Change send_ack_pkt to make up address if pkt == NULL
	struct tfo_addr_info addr;
	struct tfo *fo = &w->f[ef->tfo_idx];

	if (fos == &fo->pub) {
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
	_send_ack_pkt(w, ef, fos, NULL, &addr, fos == &fo->pub ? pub_vlan_tci : priv_vlan_tci, foos, NULL, tx_bufs, false, true, is_keepalive, send_rst);
}

static inline void
generate_rst(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	/* Send an RST packet */
	generate_ack_rst(w, ef, fos, foos, tx_bufs, false, true);
}

static inline bool
send_keepalive(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	if (fos->cur_timer != TFO_TIMER_KEEPALIVE) {
#ifdef DEBUG_KEEPALIVES
		printf("send_keepalive called for side %p with timer %u\n", fos, fos->cur_timer);
#endif
		return false;
	}

	if (!fos->keepalive_probes) {
		/* The connection is dead, send RSTs */
		generate_rst(w, ef, fos, foos, tx_bufs);
		generate_rst(w, ef, foos, fos, tx_bufs);

		/* We need to allow this timer run to complete before freeing the eflow */
		tfo_reset_timer(fos, TFO_TIMER_SHUTDOWN, 0);

		return true;
	}

	fos->keepalive_probes--;

	generate_ack_rst(w, ef, fos, foos, tx_bufs, true, false);
	tfo_reset_timer_ns(fos, TFO_TIMER_KEEPALIVE, (time_ns_t)config->tcp_keepalive_intvl * NSEC_PER_SEC);

	return false;
}

static inline uint32_t
_flow_alloc(struct tcp_worker *w, struct tfo_eflow *ef)
{
	struct tfo* fo;
	struct tfo_side *fos;

	/* Allocated when decide to optimze flow (following SYN ACK) */

	/* alloc flow */
	fo = list_first_entry(&w->f_free, struct tfo, list);
	list_del_init(&fo->list);

	fos = &fo->priv;
	while (true) {
		fos->ef = ef;
		fos->flags = 0;
		fos->srtt_us = 0;
		fos->rack_rtt_us = 0;
		minmax_reset(&fos->rtt_min, 0, 0);
		fos->rto_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
		fos->dup_ack = 0;
//		fos->is_priv = true;
		fos->sack_gap = 0;
		fos->first_sack_entry = 0;
		fos->sack_entries = 0;
#ifdef CWND_USE_RECOMMENDED
		fos->cum_ack = 0;
#endif

		INIT_LIST_HEAD(&fos->pktlist);
		INIT_LIST_HEAD(&fos->xmit_ts_list);
		INIT_LIST_HEAD(&send_failed_list);

		if (fos == &fo->pub)
			break;

		fos = &fo->pub;
	}

// fo->flags is not set

#ifdef DEBUG_MEM
	if (fo != &w->f[fo->idx])
		printf("flow %p, allocated from %p has index %u instead of %u\n", fo, w->f, fo->idx, (fo - w->f) / sizeof(*fo));
#endif

	++w->f_use;

#ifdef DEBUG_FLOW
	printf("Alloc'd flow %u to worker %p\n", fo->idx, w);
#endif

	return fo->idx;
}

/* A packet can be marked as lost, queued to resend, but is then ack'd/sack'd
 * later in the packet burst. There are other scenarios such as receiving RST. */
static void
remove_pkt_from_tx_bufs(struct tfo_pkt *pkt, struct tfo_tx_bufs *tx_bufs, struct tfo_side *fos)
{
	unsigned p;

	if (!tx_bufs)
		return;

	for (p = 0; p < tx_bufs->nb_tx; p++) {
		if (pkt->m != tx_bufs->m[p])
			continue;

		rte_pktmbuf_refcnt_update(pkt->m, -1);
		pkt->flags &= ~TFO_PKT_FL_QUEUED_SEND;
		fos->pkts_queued_send--;

		/* Yes - it might be the last entry, but it doesn't matter */
		tx_bufs->m[p] = tx_bufs->m[--tx_bufs->nb_tx];
		if (ack_bit_is_set(tx_bufs, tx_bufs->nb_tx))
			set_ack_bit(tx_bufs, p);
		else
			clear_ack_bit(tx_bufs, p);

#ifdef DEBUG_REMOVE_TX_PKT
		printf("Removed pkt %p seq 0x%x from tx_bufs\n", pkt->m, pkt->seq);
#endif

		return;
	}

#ifdef DEBUG_REMOVE_TX_PKT
	printf("FAILED to remove pkt %p seq 0x%x from tx_bufs\n", pkt->m, pkt->seq);
#endif
}

static void
pkt_free(struct tcp_worker *w, struct tfo_side *s, struct tfo_pkt *pkt, struct tfo_tx_bufs *tx_bufs)
{
#if defined DEBUG_MEMPOOL || defined DEBUG_ACK_MEMPOOL
	printf("pkt_free m %p refcnt %u seq 0x%x\n", pkt->m, pkt->m ? rte_mbuf_refcnt_read(pkt->m) : ~0U, pkt->seq);
	show_mempool("packet_pool_0");
#endif

	/* We might have already freed the mbuf if using SACK */
	if (pkt->m) {
		if (pkt->flags & TFO_PKT_FL_QUEUED_SEND)
			remove_pkt_from_tx_bufs(pkt, tx_bufs, s);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		rte_pktmbuf_free(pkt->m);
_Pragma("GCC diagnostic pop")
		if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_LOST)) == TFO_PKT_FL_SENT) {
			s->pkts_in_flight--;

#ifdef DEBUG_IN_FLIGHT
			printf("pkt_free(0x%x) pkts_in_flight decremented to %u\n", pkt->seq, s->pkts_in_flight);
#endif
		}

		if (&pkt->xmit_ts_list == s->last_sent)
			s->last_sent = pkt->xmit_ts_list.prev;
	}

	if (likely(list_is_queued(&pkt->xmit_ts_list)))
		list_del_init(&pkt->xmit_ts_list);
	if (unlikely(list_is_queued(&pkt->send_failed_list)))
		list_del_init(&pkt->send_failed_list);
	list_move(&pkt->list, &w->p_free);

	--w->p_use;
	--s->pktcount;
	s->rack_segs_sacked -= pkt->rack_segs_sacked;

#ifdef DEBUG_RACK_SACKED
	printf("pkt_free decremented s->rack_segs_sacked by %u to %u\n", pkt->rack_segs_sacked, s->rack_segs_sacked);
#endif

#ifdef DEBUG_MEMPOOL
	printf("After:\n");
	show_mempool("packet_pool_0");
#endif
#ifdef DEBUG_ACK_MEMPOOL
	show_mempool("ack_pool_0");
#endif
}

static inline void
pkt_free_mbuf(struct tfo_pkt *pkt, struct tfo_side *s, struct tfo_tx_bufs *tx_bufs)
{
#if defined DEBUG_MEMPOOL || defined DEBUG_ACK_MEMPOOL
	printf("pkt_free_mbuf m %p refcnt %u seq 0x%x\n", pkt->m, pkt->m ? rte_mbuf_refcnt_read(pkt->m) : ~0U, pkt->seq);
	show_mempool("packet_pool_0");
#endif

	if (pkt->m) {
		if (pkt->flags & TFO_PKT_FL_QUEUED_SEND)
			remove_pkt_from_tx_bufs(pkt, tx_bufs, s);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		rte_pktmbuf_free(pkt->m);
_Pragma("GCC diagnostic pop")
		pkt->m = NULL;
		pkt->iph.ip4h = NULL;
		pkt->tcp = NULL;
		pkt->ts = NULL;
		pkt->sack = NULL;
		if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_LOST)) == TFO_PKT_FL_SENT) {
			s->pkts_in_flight--;
#ifdef DEBUG_IN_FLIGHT
			printf("pkt_free_mbuf(0x%x) pkts_in_flight decremented to %u\n", pkt->seq, s->pkts_in_flight);
#endif
		}

		if (likely(list_is_queued(&pkt->xmit_ts_list))) {
			if (&pkt->xmit_ts_list == s->last_sent)
				s->last_sent = pkt->xmit_ts_list.prev;

			list_del_init(&pkt->xmit_ts_list);
		}
		if (unlikely(list_is_queued(&pkt->send_failed_list)))
			list_del_init(&pkt->send_failed_list);

		pkt->flags &= ~TFO_PKT_FL_LOST;
	}

#ifdef DEBUG_MEMPOOL
	printf("After:\n");
	show_mempool("packet_pool_0");
#endif
#ifdef DEBUG_ACK_MEMPOOL
	show_mempool("ack_pool_0");
#endif
}

static void
_flow_free(struct tcp_worker *w, struct tfo *f, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt, *pkt_tmp;

#ifdef DEBUG_FLOW
	printf("flow_free %u worker %p\n", f->idx, w);
#endif

	/* del pkt lists */
	list_for_each_entry_safe(pkt, pkt_tmp, &f->priv.pktlist, list)
		pkt_free(w, &f->priv, pkt, tx_bufs);
	list_for_each_entry_safe(pkt, pkt_tmp, &f->pub.pktlist, list)
		pkt_free(w, &f->pub, pkt, tx_bufs);

	list_add(&f->list, &w->f_free);
	--w->f_use;
}

static struct tfo_eflow *
_eflow_alloc(struct tcp_worker *w, uint32_t h)
{
	struct tfo_eflow *ef;

	/* Called on first SYN of flow (i.e. no ACK) */

	if (unlikely(hlist_empty(&w->ef_free)))
		return NULL;

	ef = hlist_entry(w->ef_free.first, struct tfo_eflow, hlist);

#ifdef DEBUG_MEM
	if (ef->flags)
		printf("Allocating eflow %p with flags 0x%x\n", ef, ef->flags);
	ef->flags = TFO_EF_FL_USED;
	if (ef->state != TFO_STATE_NONE)
		printf("Allocating eflow %p in state %u\n", ef, ef->state);
	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		printf("Allocating eflow %p with tfo %u\n", ef, ef->tfo_idx);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}
	if (ef->u)
		printf("Allocating eflow %p with user %p\n", ef, ef->u);
#endif

	ef->state = TCP_STATE_SYN;
	ef->win_shift = TFO_WIN_SCALE_UNSET;
	ef->client_mss = TCP_MSS_DEFAULT;

	__hlist_del(&ef->hlist);
	hlist_add_head(&ef->hlist, &w->hef[h]);

	RB_CLEAR_NODE(&ef->timer.node);

	++w->ef_use;
	++w->st.flow_state[ef->state];

#ifdef DEBUG_FLOW
	printf("Alloc'd eflow %p to worker %p\n", ef, w);
#endif

	return ef;
}

static void
_eflow_free(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
#ifdef DEBUG_FLOW
	printf("eflow_free w %p ef %p ef->tfo_idx %u flags 0x%x, state %u\n", w, ef, ef->tfo_idx, ef->flags, ef->state);
#endif

	if (ef->state == TCP_STATE_CLEAR_OPTIMIZE)
		--w->st.flow_state[TCP_STATE_CLEAR_OPTIMIZE];
	else
		--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		_flow_free(w, &w->f[ef->tfo_idx], tx_bufs);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}

	rb_erase_cached(&ef->timer.node, &timer_tree);

	--w->ef_use;
	--w->st.flow_state[ef->state];
	ef->state = TFO_STATE_NONE;

#ifdef DEBUG_MEM
	if (!(ef->flags & TFO_EF_FL_USED))
		printf("Freeing eflow %p without used flag set\n", ef);
#endif

	ef->flags = 0;

	__hlist_del(&ef->hlist);
	hlist_add_head(&ef->hlist, &w->ef_free);
}

static inline void
update_eflow_timeout(struct tfo_eflow *ef)
{
	unsigned port_index;
	struct tfo *fo;

	/* Use the port on the "server" side */
	port_index = (ef->flags & TFO_EF_FL_SYN_FROM_PRIV) ? ef->pub_port : ef->priv_port;
	if (port_index > config->max_port_to)
		port_index = 0;

	if (ef->state == TCP_STATE_ESTABLISHED) {
		fo = &worker.f[ef->tfo_idx];

		/* If we have received a FIN from either side, use the FIN timer */
		if ((fo->priv.flags | fo->pub.flags) & TFO_SIDE_FL_FIN_RX)
			ef->idle_timeout = now + config->tcp_to[port_index].to_fin * NSEC_PER_SEC;
		else
			ef->idle_timeout = now + config->tcp_to[port_index].to_est * NSEC_PER_SEC;
	} else {
		/* We must be doing the 3WHS */
		ef->idle_timeout = now + config->tcp_to[port_index].to_syn * NSEC_PER_SEC;
	}
}

static bool
set_tcp_options(struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
	unsigned opt_off = sizeof(struct rte_tcp_hdr);
	uint8_t opt_size = (p->tcp->data_off & 0xf0) >> 2;
	uint8_t *opt_ptr = (uint8_t *)p->tcp;
	struct tcp_option *opt;


	p->ts_opt = NULL;
	p->sack_opt = NULL;
	p->win_shift = TFO_WIN_SCALE_UNSET;
	p->mss_opt = 0;

	while (opt_off < opt_size) {
		opt = (struct tcp_option *)(opt_ptr + opt_off);

#ifdef DEBUG_TCP_OPT
		printf("tcp %p, opt 0x%x opt_off %u opt_size %u\n", p->tcp, opt->opt_code, opt_off, opt->opt_code > TCPOPT_NOP ? opt->opt_len : 1U);
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

			if (p->tcp->tcp_flags & RTE_TCP_SYN_FLAG)
				p->win_shift = min(TCP_MAX_WINSHIFT, opt->opt_data[0]);
			break;
		case TCPOPT_SACK_PERMITTED:
			if (opt->opt_len != TCPOLEN_SACK_PERMITTED)
				return false;

#ifdef DEBUG_DISABLE_SACK
			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == RTE_TCP_SYN_FLAG) {
				struct tfo_pkt pkt;
				uint16_t nops[1] = { [0] = 0x0101 };

				pkt.m = p->m;
				pkt.iph = p->iph;
				pkt.tcp = p->tcp;
				pkt.ts = NULL;
				pkt.sack = NULL;

				pkt.tcp->cksum = update_checksum(pkt.tcp->cksum, opt, nops, sizeof(nops));
			}
#endif
			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_SACK;
			break;
		case TCPOPT_MAXSEG:
			if (opt->opt_len != TCPOLEN_MAXSEG)
				return false;

			p->mss_opt = rte_be_to_cpu_16(*(uint16_t *)opt->opt_data);
			break;
		case TCPOPT_TIMESTAMP:
			if (opt->opt_len != TCPOLEN_TIMESTAMP)
				return false;

			p->ts_opt = (struct tcp_timestamp_option *)opt;

#ifdef DEBUG_TCP_OPT
			printf("ts_val %u ts_ecr %u\n", rte_be_to_cpu_32(p->ts_opt->ts_val), rte_be_to_cpu_32(p->ts_opt->ts_ecr));
#endif

#ifdef DEBUG_DISABLE_TS
			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == RTE_TCP_SYN_FLAG) {
				struct tfo_pkt pkt;
				uint16_t nops[5] = { [0] = 0x0101, [1] = 0x0101, [2] = 0x0101, [3] = 0x0101, [4] = 0x0101 };

				pkt.m = p->m;
				pkt.iph = p->iph;
				pkt.tcp = p->tcp;
				pkt.ts = NULL;
				pkt.sack = NULL;

				pkt.tcp->cksum = update_checksum(pkt.tcp->cksum, opt, nops, sizeof(nops));
				p->ts_opt = NULL;
			}
#endif
			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
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
	uint8_t *opt_start = (uint8_t *)p->tcp + sizeof(struct rte_tcp_hdr);
	uint8_t opt_len = ((p->tcp->data_off & 0xf0) >> 2) - sizeof(struct rte_tcp_hdr);
	bool updated = false;

	pkt.m = p->m;
	pkt.iph = p->iph;
	pkt.tcp = p->tcp;
	pkt.ts = p->ts_opt;
	pkt.sack = p->sack_opt;

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
		p->iph = pkt.iph;
		p->tcp = pkt.tcp;
		p->ts_opt = pkt.ts;
		p->sack_opt = pkt.sack;
	}
#endif

	return (opt_off == opt_size);
}

static inline bool
set_estab_options(struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
	unsigned opt_off = sizeof(struct rte_tcp_hdr);
	uint8_t opt_size = (p->tcp->data_off & 0xf0) >> 2;
	uint8_t *opt_ptr = (uint8_t *)p->tcp;
	struct tcp_option *opt;


	p->ts_opt = NULL;
	p->sack_opt = NULL;

	while (opt_off < opt_size) {
		opt = (struct tcp_option *)(opt_ptr + opt_off);

#ifdef DEBUG_TCP_OPT
		printf("tcp %p, opt 0x%x opt_off %u opt_size %u\n", p->tcp, opt->opt_code, opt_off, opt->opt_code > TCPOPT_NOP ? opt->opt_len : 1U);
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
		case TCPOPT_SACK:
			if (!(ef->flags & TFO_EF_FL_SACK)) {
#ifdef DEBUG_VALID_OPTIONS
				printf("Received SACK option but not negotiated\n");
#endif
				return false;
			}

			p->sack_opt = (struct tcp_sack_option *)opt;
#if defined DEBUG_TCP_OPT
			printf("SACK option size %u, blocks %lu\n", p->sack_opt->opt_len, (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges));
			for (unsigned i = 0; i < (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges); i++)
				printf("  %u: 0x%x -> 0x%x\n", i, rte_be_to_cpu_32(p->sack_opt->edges[i].left_edge), rte_be_to_cpu_32(p->sack_opt->edges[i].right_edge));
#endif
			break;
		case TCPOPT_TIMESTAMP:
			if (!(ef->flags & TFO_EF_FL_TIMESTAMP)) {
#ifdef DEBUG_VALID_OPTIONS
				printf("Received timestamp option but not negotiated\n");
#endif
				return false;
			}

			if (opt->opt_len != TCPOLEN_TIMESTAMP)
				return false;

			p->ts_opt = (struct tcp_timestamp_option *)opt;

#ifdef DEBUG_TCP_OPT
			printf("ts_val %u ts_ecr %u\n", rte_be_to_cpu_32(p->ts_opt->ts_val), rte_be_to_cpu_32(p->ts_opt->ts_ecr));
#endif

			break;
		case 28 ... 30:
			/* See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
			 * for the list of assigned options. */
			break;
		default:
			/* Don't try optimizing if there are options we don't understand */
			return false;
		}

		opt_off += opt->opt_len;
	}

	/* If timestamps are negotiated, they must be included in every packet */
	if ((ef->flags & TFO_EF_FL_TIMESTAMP) && !p->ts_opt)
		return false;

	return (opt_off == opt_size);
}

static inline uint32_t
icwnd_from_mss(uint16_t mss)
{
	if (mss > 2190)
		return 2 * mss;
	if (mss > 1095)
		return 3 * mss;
	return 4 * mss;
}

/*
 * called at SYN+ACK. decide if we'll optimize this tcp connection
 */
static bool
check_do_optimize(struct tcp_worker *w, const struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
	struct tfo *fo;
	struct tfo_side *client_fo, *server_fo;
	uint32_t rtt_us;

	/* should not happen */
	if (unlikely(list_empty(&w->f_free)) ||
	    w->p_use >= config->p_n * 3 / 4) {
		_eflow_free(w, ef, NULL);
		return false;
	}

	/* alloc flow */
	ef->tfo_idx = _flow_alloc(w, ef);
	++w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

	fo = &w->f[ef->tfo_idx];

	if (unlikely(p->from_priv)) {
		/* original SYN from public */
		client_fo = &fo->pub;
		server_fo = &fo->priv;
	} else {
		/* original SYN from private */
		client_fo = &fo->priv;
		server_fo = &fo->pub;
	}

	/* Clear window scaling if either side didn't send it */
	if (p->win_shift == TFO_WIN_SCALE_UNSET ||
	    ef->win_shift == TFO_WIN_SCALE_UNSET) {
		client_fo->snd_win_shift = 0;
		server_fo->snd_win_shift = 0;
	} else {
		client_fo->snd_win_shift = ef->win_shift;
		server_fo->snd_win_shift = p->win_shift;
	}

	/* For now, we just set the rcv_win_shift (i.e. what we send)
	 * to match what we have received. We could have an optimization
	 * to increase it, or if the client doesn't offer it, we could offer
	 * it on the server side. */
	client_fo->rcv_win_shift = server_fo->snd_win_shift;
	server_fo->rcv_win_shift = client_fo->snd_win_shift;

	client_fo->rcv_nxt = rte_be_to_cpu_32(p->tcp->recv_ack);
	client_fo->snd_una = rte_be_to_cpu_32(p->tcp->sent_seq);
	client_fo->snd_nxt = rte_be_to_cpu_32(p->tcp->sent_seq) + p->seglen;
	server_fo->last_rcv_win_end = client_fo->snd_una + ef->client_snd_win;
	client_fo->snd_win = ((ef->client_snd_win - 1) >> client_fo->snd_win_shift) + 1;
#ifdef DEBUG_RCV_WIN
	printf("server lrwe 0x%x from client snd_una 0x%x and snd_win 0x%x << 0\n", server_fo->last_rcv_win_end, client_fo->snd_una, ef->client_snd_win);
#endif
	server_fo->rcv_win = client_fo->snd_win;
	client_fo->mss = ef->client_mss;
	if (p->ts_opt) {
		client_fo->ts_recent = p->ts_opt->ts_ecr;
		client_fo->latest_ts_val = rte_be_to_cpu_32(client_fo->ts_recent);
#ifdef CALC_USERS_TS_CLOCK
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
	server_fo->rcv_nxt = client_fo->snd_nxt;
	server_fo->snd_una = rte_be_to_cpu_32(p->tcp->recv_ack);
	server_fo->snd_nxt = ef->client_rcv_nxt;
	client_fo->last_rcv_win_end = server_fo->snd_una + rte_be_to_cpu_16(p->tcp->rx_win);
#ifdef DEBUG_RCV_WIN
//	printf("client lrwe 0x%x from server snd_una 0x%x and snd_win 0x%x << 0\n", client_fo->last_rcv_win_end, server_fo->snd_una, rte_be_to_cpu_16(p->tcp->rx_win));
	printf("client lrwe 0x%x from server snd_una 0x%x and snd_win 0x%hx << 0\n", client_fo->last_rcv_win_end, server_fo->snd_una, rte_bswap16(p->tcp->rx_win));
#endif
	server_fo->snd_win = ((rte_be_to_cpu_16(p->tcp->rx_win) - 1) >> server_fo->snd_win_shift) + 1;
	client_fo->rcv_win = server_fo->snd_win;
	server_fo->mss = p->mss_opt ? p->mss_opt : (ef->flags & TFO_EF_FL_IPV6) ? TCP_MSS_DESIRED : TCP_MSS_DEFAULT;
	if (p->ts_opt) {
		server_fo->ts_recent = p->ts_opt->ts_val;
		server_fo->latest_ts_val = rte_be_to_cpu_32(server_fo->ts_recent);
#ifdef CALC_USERS_TS_CLOCK
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
	server_fo->packet_type = p->m->packet_type;
	client_fo->rcv_ttl = ef->client_ttl;
	if (ef->flags & TFO_EF_FL_IPV6) {
		client_fo->vtc_flow = ef->client_vtc_flow;
		server_fo->vtc_flow = p->iph.ip6h->vtc_flow;
		server_fo->rcv_ttl = p->iph.ip6h->hop_limits;
	} else
		server_fo->rcv_ttl = p->iph.ip4h->time_to_live;

	/* RFC5681 3.2 */
	if (!(ef->flags & TFO_EF_FL_DUPLICATE_SYN)) {
		client_fo->cwnd = icwnd_from_mss(client_fo->mss);
		server_fo->cwnd = icwnd_from_mss(server_fo->mss);
	} else {
		client_fo->cwnd = client_fo->mss;
		server_fo->cwnd = server_fo->mss;
	}
	client_fo->ssthresh = 0xffff << client_fo->snd_win_shift;
	server_fo->ssthresh = 0xffff << server_fo->snd_win_shift;

	/* RFC8985 7.1 */
	server_fo->tlp_end_seq = 0;	// Probably need a flag
	server_fo->flags &= ~TFO_SIDE_FL_TLP_IS_RETRANS;
	client_fo->tlp_end_seq = 0;	// Probably need a flag
	client_fo->flags &= ~TFO_SIDE_FL_TLP_IS_RETRANS;
	tfo_cancel_xmit_timer(server_fo);
	server_fo->delayed_ack_timeout = TFO_ACK_NOW_TS;	// Ensure the 3WHS ACK is sent immediately
	server_fo->tlp_max_ack_delay_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	client_fo->cur_timer = TFO_TIMER_NONE;
	client_fo->timeout = TFO_INFINITE_TS;
	client_fo->delayed_ack_timeout = TFO_INFINITE_TS;
	client_fo->tlp_max_ack_delay_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	client_fo->pkts_in_flight = 0;
	server_fo->pkts_in_flight = 0;
	client_fo->rack_segs_sacked = 0;
	server_fo->rack_segs_sacked = 0;
	server_fo->rack_xmit_ts = 0;
	client_fo->rack_xmit_ts = 0;
	server_fo->pkts_queued_send = 0;
	client_fo->pkts_queued_send = 0;

	client_fo->last_sent = &client_fo->xmit_ts_list;
	server_fo->last_sent = &server_fo->xmit_ts_list;

#ifdef DEBUG_PKT_DELAYS
	client_fo->last_rx_data = now;
	client_fo->last_rx_ack = now;
	server_fo->last_rx_data = now;
	server_fo->last_rx_ack = now;
#endif

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

	return true;
}

static time_ns_t
tlp_calc_pto(struct tfo_side *fos)
{
	time_ns_t pto;
	time_ns_t rto;
	struct tfo_pkt *oldest_pkt;

	if (unlikely(!fos->srtt_us))
		pto = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	else {
		pto = 2 * fos->srtt_us;
		if (fos->pkts_in_flight + fos->pkts_queued_send == 1)
			pto += fos->tlp_max_ack_delay_us;
	}

	pto *= NSEC_PER_USEC;

	if (!list_empty(&fos->xmit_ts_list)) {
		oldest_pkt = list_first_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);
		if ((oldest_pkt->flags & (TFO_PKT_FL_SENT & TFO_PKT_FL_QUEUED_SEND)) == TFO_PKT_FL_SENT) {
			rto = oldest_pkt->ns + fos->rto_us * NSEC_PER_USEC;
			if (now + pto > rto)
				pto = rto - now;
		}
	}

	return pto;
}

static void
tfo_reset_xmit_timer(struct tfo_side *fos, bool is_tlp)
{
#ifdef DEBUG_RACK
	printf("tfo_reset_xmit_timer snd_una 0x%x%s cur_timer %u", fos->snd_una, is_tlp ? " for TLP" : "", fos->cur_timer);
#endif

	if (list_empty(&fos->pktlist)) {
		tfo_cancel_xmit_timer(fos);
#ifdef DEBUG_RACK
		printf("\n");
#endif
		return;
	}

	/* Try set PTO else set RTO */
	if (!is_tlp &&
	    !(fos->flags & (TFO_SIDE_FL_IN_RECOVERY | TFO_SIDE_FL_TLP_IN_PROGRESS)) &&
	    !fos->rack_segs_sacked &&
	    fos->rack_rtt_us) {		// FIXME: This is a bodge for detecting using SACK
		fos->cur_timer = TFO_TIMER_PTO;
		fos->timeout = now + tlp_calc_pto(fos);
#ifdef DEBUG_RACK
		printf(" tlp_calc_pto %lu", fos->timeout - now);
#endif
	} else {
		fos->cur_timer = TFO_TIMER_RTO;
		fos->timeout = now + fos->rto_us * NSEC_PER_USEC;
	}

	update_timer(fos->ef, fos->timeout);

#ifdef DEBUG_RACK
	printf(" now %u, timeout %lu\n", fos->cur_timer, fos->timeout - now);
#endif
}

static bool
send_tcp_pkt(struct tcp_worker *w, struct tfo_pkt *pkt, struct tfo_tx_bufs *tx_bufs, struct tfo_side *fos, struct tfo_side *foos, bool is_tail_loss_probe)
{
	uint32_t new_val32[2];
	uint16_t new_val16[1];

// NOTE: If we return false, an ACK might need to be sent
	if (!pkt->m) {
		printf("Request to send sack'd packet %p, seq 0x%x\n", pkt, pkt->seq);
		return false;
	}

#ifdef DEBUG_CHECKSUM
	check_checksum(pkt, "send_tcp_pkt", false);
#endif

	if (pkt->ns == now) {
		/* This can happen if receive delayed packet in same burst as the third duplicated ACK */
		return false;
	}

	if (pkt->flags & TFO_PKT_FL_QUEUED_SEND) {
#ifdef DEBUG_QUEUED
		printf("Skipping sending 0x%x since already queued\n", pkt->seq);
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

#ifdef CALC_USERS_TS_CLOCK
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

	if (!(pkt->flags & TFO_PKT_FL_QUEUED_SEND)) {
		rte_pktmbuf_refcnt_update(pkt->m, 1);	/* so we keep it after it is sent */
		add_tx_buf(w, pkt->m, tx_bufs, pkt->flags & TFO_PKT_FL_FROM_PRIV, pkt->iph, false);
		pkt->flags |= TFO_PKT_FL_QUEUED_SEND;
		fos->pkts_queued_send++;
		if (list_is_queued(&pkt->send_failed_list))
			list_del_init(&pkt->send_failed_list);
#ifdef DEBUG_SEND_PKT
		printf("Sending packet 0x%x\n", pkt->seq);
#endif
	}

	/* No need to send an ACK if one is delayed */
	fos->delayed_ack_timeout = TFO_INFINITE_TS;

	tfo_reset_xmit_timer(fos, is_tail_loss_probe);

	return true;
}

static void
tlp_send_probe(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *probe_pkt = NULL;
	struct tfo_pkt *pkt;

#ifdef DEBUG_SEND_PROBE
	printf("In tlp_send_probe for %p, flags 0x%x\n", fos, fos->flags);
#endif

	if (list_empty(&fos->pktlist)) {
		printf("!!! tlp_send_probe called with empty pktlist !!!\n");
		tfo_cancel_xmit_timer(fos);
		return;
	}

	if ((fos->flags & (TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_NEW_RTT)) == TFO_SIDE_FL_NEW_RTT) {
// We may want send_tcp_pkt to keep pointer to pkt with highest segend sent. It must be valid
// (but we may have a problem if the last entry has been sacked - but then we won't be sending
// TLPs???)
		list_for_each_entry_reverse(pkt, &fos->pktlist, list) {
			if (after(pkt->seq, fos->snd_nxt)) {
#ifdef DEBUG_SEND_PROBE
				printf("seq 0x%x after snd_nxt 0x%x\n", pkt->seq, fos->snd_nxt);
#endif
				continue;
			}

			/* If we are before snd_nxt and there is a later packet within window, use that */
#ifdef DEBUG_SEND_PROBE
			printf("pkt->seq 0x%x snd_nxt 0x%x\n", pkt->seq, fos->snd_nxt);
#endif
			if (pkt->seq != fos->snd_nxt &&
			    !list_is_last(&pkt->list, &fos->pktlist)) {
				pkt = list_next_entry(pkt, list);
#ifdef DEBUG_SEND_PROBE
				printf("Using next packet 0x%x\n", pkt->seq);
#endif
			}

			if (!after(segend(pkt), fos->snd_una + (fos->snd_win << fos->snd_win_shift))) {
				probe_pkt = pkt;
#ifdef DEBUG_IN_FLIGHT
				printf("tlp_send_probe() pkts_in_flight not incremented to %u\n", fos->pkts_in_flight);
#endif
			} else if (!list_is_first(&pkt->list, &fos->pktlist)) {
				probe_pkt = list_prev_entry(pkt, list);
#ifdef DEBUG_SEND_PROBE
				printf("Using previous packet 0x%x\n", probe_pkt->seq);
#endif
			}

			break;
		}

		if (!probe_pkt) {
#ifdef DEBUG_RACK
			printf("!!! tlp_send_probe has no probe_pkt !!!\n");
#endif
			return;
		}

		if (before(probe_pkt->seq, fos->snd_nxt))
			fos->flags |= TFO_SIDE_FL_TLP_IS_RETRANS;
		else
			fos->flags &= ~TFO_SIDE_FL_TLP_IS_RETRANS;

#ifdef DEBUG_SEND_PROBE
		printf("Retrans %d\n", !!(fos->flags & TFO_SIDE_FL_TLP_IS_RETRANS));
#endif

#ifdef DEBUG_RACK
		printf("tlp_send_probe(0x%x)\n", probe_pkt->seq);
#endif
#ifdef DEBUG_SEND_PKT_LOCATION
		printf("send_tcp_pkt A\n");
#endif
		send_tcp_pkt(w, probe_pkt, tx_bufs, fos, foos, true);
		fos->tlp_end_seq = fos->snd_nxt;
		fos->flags |= TFO_SIDE_FL_TLP_IN_PROGRESS;

		fos->flags &= ~TFO_SIDE_FL_NEW_RTT;
	}

// Check RFC8985 7.3 for correct operation here
// Also check if we need TLP.is_retrans set on the packet
// Check para "If such an unsent segment ..." Do we handle the assumption of lost packets correctly?
#ifdef DEBUG_SEND_PROBE
	printf("pkts in flight %u\n", fos->pkts_in_flight);
#endif

	if (fos->pkts_in_flight)
		tfo_reset_timer(fos, TFO_TIMER_RTO, fos->rto_us);
}

static inline bool
set_vlan(struct rte_mbuf* m, struct tfo_pkt_in *p)
{
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
	uint16_t vlan_cur;
	uint16_t vlan_new;
	uint8_t *buf;
#ifdef DEBUG_VLAN
	struct rte_ipv4_hdr *iph = NULL;
	struct rte_ipv6_hdr *ip6h = NULL;
#endif

	eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
//printf("m->vlan_tci %u, eh->ether_type %x, m->ol_flags 0x%x\n", m->vlan_tci, rte_be_to_cpu_16(eh->ether_type), m->ol_flags);

	if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
		vh = (struct rte_vlan_hdr *)(eh + 1);

		vlan_cur = rte_be_to_cpu_16(vh->vlan_tci);
	} else
		vlan_cur = 0;

	vlan_new = m->vlan_tci;

#ifdef DEBUG_VLAN
	if (vlan_cur) {
		if (vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			iph = (struct rte_ipv4_hdr *)(vh + 1);
		else if (vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
			ip6h = (struct rte_ipv6_hdr *)(vh + 1);
#ifdef DEBUG_VLAN1
		else
			printf("vh->eth_proto = 0x%x\n", rte_be_to_cpu_16(vh->eth_proto));
#endif
	} else {
		if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			iph = (struct rte_ipv4_hdr *)(eh + 1);
		else if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
			ip6h = (struct rte_ipv6_hdr *)(eh + 1);
#ifdef DEBUG_VLAN1
		else
			printf("eh->eth_type = 0x%x\n", rte_be_to_cpu_16(eh->ether_type));
#endif
	}
	if (iph) {
		char addr[2][INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &iph->src_addr, addr[0], INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &iph->dst_addr, addr[1], INET_ADDRSTRLEN);

		printf("%s -> %s\n", addr[0], addr[1]);
	}
	else if (ip6h) {
		char addr[2][INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ip6h->src_addr, addr[0], INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ip6h->dst_addr, addr[1], INET6_ADDRSTRLEN);

		printf("%s -> %s\n", addr[0], addr[1]);
	}
	else {
#ifdef DEBUG_VLAN1
		printf("Unknown layer 3 protocol mbuf %u\n", i);
#endif
	}
#endif

	if (vlan_new == 4096)
		return true;

	if (!vlan_new) {
		if (vlan_cur) {
			/* remove vlan encapsulation */
			eh->ether_type = vh->eth_proto;		// We could avoid this, and copy sizeof - 2
			memmove(rte_pktmbuf_adj(m, sizeof (struct rte_vlan_hdr)),
				eh, sizeof (struct rte_ether_hdr));
			eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			m->packet_type = (m->packet_type & ~RTE_PTYPE_L2_MASK) | RTE_PTYPE_L2_ETHER;
		}
	} else if (vlan_cur) {
		vh->vlan_tci = rte_cpu_to_be_16(vlan_new);
	} else {
		/* add vlan encapsulation */
		buf = (uint8_t *)rte_pktmbuf_prepend(m, sizeof(struct rte_vlan_hdr));

		if (unlikely(buf == NULL)) {
			buf = (uint8_t *)rte_pktmbuf_append(m, sizeof(struct rte_vlan_hdr));
			if (unlikely(!buf))
				return false;

			/* This is so unlikely, just move the whole packet to
			 * make room at the beginning to move the ether hdr */
			memmove(eh + sizeof(struct rte_vlan_hdr), eh, m->data_len - sizeof (struct rte_vlan_hdr));
			if (p) {
				if (m->packet_type & RTE_PTYPE_L3_IPV4)
					p->iph.ip4h = (struct rte_ipv4_hdr *)((uint8_t *)p->iph.ip4h + sizeof(struct rte_vlan_hdr));
				else
					p->iph.ip6h = (struct rte_ipv6_hdr *)((uint8_t *)p->iph.ip6h + sizeof(struct rte_vlan_hdr));
				p->tcp = (struct rte_tcp_hdr *)((uint8_t *)p->tcp + sizeof(struct rte_vlan_hdr));
				if (p->ts_opt)
					p->ts_opt = (struct tcp_timestamp_option *)((uint8_t *)p->ts_opt + sizeof(struct rte_vlan_hdr));
				if (p->sack_opt)
					p->sack_opt = (struct tcp_sack_option *)((uint8_t *)p->sack_opt + sizeof(struct rte_vlan_hdr));
			}
			buf = rte_pktmbuf_mtod(m, uint8_t *);
			eh = (struct rte_ether_hdr *)(buf + sizeof(struct rte_vlan_hdr));
		}

		/* move ethernet header at the start */
		memmove(buf, eh, sizeof (struct rte_ether_hdr));		// we could do sizeof - 2
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

		vh = (struct rte_vlan_hdr *)(eh + 1);
		vh->vlan_tci = rte_cpu_to_be_16(vlan_new);
		vh->eth_proto = eh->ether_type;

		eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		m->packet_type = (m->packet_type & ~RTE_PTYPE_L2_MASK) | RTE_PTYPE_L2_ETHER_VLAN;
	}

#ifdef DEBUG_VLAN
	printf("Moving packet from vlan %u to %u\n", vlan_cur, vlan_new);
#endif

	return true;
}

static uint16_t
update_vlan(struct tfo_pkt_in *p)
{
	uint16_t orig_vlan;

	/* I don't like the following bit of code, with two identical assignments to
	 * orig_vlan, but I can't think of anything better at the moment.
	 * It could be simplified to:
	 *   if (p->from_priv) {
	 * 	...
	 * 	if (!(option_flags ...))
	 * 		p->m->vlan_tci = pub_vlan_tci
	 * 	orig_vlan = priv_vlan_tci;
	 *   } ...
	 * but is that right? I think we should use p->m->vlan_tci where we can.
	 */
	if (p->from_priv) {
		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
			orig_vlan = p->m->vlan_tci;
			p->m->vlan_tci = pub_vlan_tci;
		} else
			orig_vlan = priv_vlan_tci;
	} else {
		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
			orig_vlan = p->m->vlan_tci;
			p->m->vlan_tci = priv_vlan_tci;
		} else
			orig_vlan = pub_vlan_tci;
	}

	return orig_vlan;
}

static void
swap_mac_addr(struct rte_mbuf *m)
{
	struct rte_ether_addr sav_src_addr;
	struct rte_ether_hdr *eh;

	/* Swap MAC addresses */
	eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	rte_ether_addr_copy(&eh->src_addr, &sav_src_addr);
	rte_ether_addr_copy(&eh->dst_addr, &eh->src_addr);
	rte_ether_addr_copy(&sav_src_addr, &eh->dst_addr);
}

static inline bool
update_pkt(struct rte_mbuf *m, struct tfo_pkt_in *p)
{
	if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
		if (unlikely(!set_vlan(m, p))) {
			/* The Vlan header could not be added. */
			return false;
		}
	}

	if (!(option_flags & TFO_CONFIG_FL_NO_MAC_CHG))
		swap_mac_addr(m);

	return true;
}

/*
 * The principles of the queue are:
 *  - A queued packet always contains data before its successor
 *  	pkt->seq < next_pkt->seq
 *  - The next packet always contains data after its predecessor
 *  	pkt->seq + pkt->seglen < next_pkt->seq + next_pkt->seglen
 *  	  (i.e. segend(pkt) < segend(next_pkt))
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
queue_pkt(struct tcp_worker *w, struct tfo_side *foos, struct tfo_pkt_in *p, uint32_t seq, uint32_t *dup_sack, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *prev_pkt, *first_pkt, *last_pkt, *next_pkt;
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_pkt *queue_after;
	uint32_t seg_end;
	uint32_t first_seq, last_seq;
	bool pkt_needed;
	uint32_t wanted_seq;
	int sack_gaps;
	struct tfo_mbuf_priv *priv;

	seg_end = seq + p->seglen + (p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG) ? 1 : 0);

	if (!after(seg_end, foos->snd_una)) {
#ifdef DEBUG_QUEUE_PKTS
		printf("queue_pkt seq 0x%x, len %u before our window\n", seq, p->seglen);
#endif
		dup_sack[0] = seq;
		dup_sack[1] = seg_end;

		return PKT_IN_LIST;
	}

	first_pkt = prev_pkt = last_pkt = next_pkt = NULL;
	pkt_needed = false;
	if (!list_empty(&foos->pktlist)) {
		/* Check if after end of current list, of before begining */
		if (likely(!after(seg_end, (pkt = list_first_entry(&foos->pktlist, struct tfo_pkt, list))->seq)))
			next_pkt = pkt;
		else if (pkt = list_last_entry(&foos->pktlist, struct tfo_pkt, list),
			 !after(segend(pkt), seq))
			prev_pkt = pkt;
		else {
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
	printf("prev 0x%x first 0x%x last 0x%x next 0x%x\n",
			prev_pkt ? prev_pkt->seq : 0xffff,
			first_pkt ? first_pkt->seq : 0xffff,
			last_pkt ? last_pkt->seq : 0xffff,
			next_pkt ? next_pkt->seq : 0xffff);

	if (!first_pkt) {
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
printf("Could replace pkts 0x%x -> 0x%x with new pkt\n", first_pkt->seq, last_pkt->seq);
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
				pkt_free(w, foos, pkt, tx_bufs);
			else if (before(pkt->seq, seq))
				queue_after = pkt;

			if (pkt == last_pkt)
				break;
			wanted_seq = segend(pkt);
		}

		foos->sack_gap += sack_gaps;
	}

	if (!update_pkt(p->m, p))
		return PKT_VLAN_ERR;

#ifdef DEBUG_QUEUE_PKTS
	printf("In queue_pkt, refcount %u\n", rte_mbuf_refcnt_read(p->m));
#endif

	/* bufferize this packet */
// Re need to stop optimizing and ensure this packet is sent due to !handled
	if (list_empty(&w->p_free))
		return NULL;

	pkt = list_first_entry(&w->p_free, struct tfo_pkt, list);
	list_del_init(&pkt->list);
	if (++w->p_use > w->p_max_use)
		w->p_max_use = w->p_use;

	pkt->m = p->m;

	/* Update the mbuf private area so we can find the tfo_side and tfo_pkt from the mbuf */
        priv = get_priv_addr(p->m);
        priv->fos = foos;
        priv->pkt = pkt;

        if (option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)
                p->m->ol_flags ^= config->dynflag_priv_mask;

	pkt->seq = seq;
	pkt->seglen = p->seglen;
	pkt->iph = p->iph;
	pkt->tcp = p->tcp;
	pkt->flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
	pkt->ns = 0;
	pkt->ts = p->ts_opt;
	pkt->sack = p->sack_opt;
	pkt->rack_segs_sacked = 0;
	INIT_LIST_HEAD(&pkt->xmit_ts_list);

	if (!queue_after) {
#ifdef DEBUG_QUEUE_PKTS
		printf("Adding pkt at head %p m %p seq 0x%x to fo %p, vlan %u\n", pkt, pkt->m, seq, foos, p->m->vlan_tci);
#endif

		list_add(&pkt->list, &foos->pktlist);
	} else {
#ifdef DEBUG_QUEUE_PKTS
		printf("Adding packet not at head");
#endif

		list_add(&pkt->list, &queue_after->list);
	}

	foos->pktcount++;

	return pkt;
}

static void
clear_optimize(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_side *s;
	uint32_t rcv_nxt;
	struct tfo *fo;

	if (unlikely(ef->state == TCP_STATE_CLEAR_OPTIMIZE))
		return;

	--w->st.flow_state[ef->state];
	++w->st.flow_state[TCP_STATE_CLEAR_OPTIMIZE];

	/* stop current optimization */
	ef->state = TCP_STATE_CLEAR_OPTIMIZE;
	--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

	fo = &w->f[ef->tfo_idx];

	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		/* Remove any buffered packets that we haven't ack'd */
		s = &fo->priv;
		rcv_nxt = fo->pub.rcv_nxt;
		while (true) {
			if (!list_empty(&s->pktlist)) {
				/* Remove any packets that have been sent but not been ack'd */
				list_for_each_entry_safe_reverse(pkt, pkt_tmp, &s->pktlist, list) {
					if (after(segend(pkt), rcv_nxt))
						break;
					if (!(pkt->flags & TFO_PKT_FL_QUEUED_SEND))
						pkt_free(w, s, pkt, tx_bufs);
				}
			}

			if (s == &fo->pub)
				break;

			s = &fo->pub;
			rcv_nxt = fo->priv.rcv_nxt;
		}
	}

	if (ef->tfo_idx == TFO_IDX_UNUSED ||
	    (list_empty(&fo->priv.pktlist) &&
	     list_empty(&fo->pub.pktlist))) {
		_eflow_free(w, ef, tx_bufs);

		return;
	}
}

static void
_eflow_set_state(struct tcp_worker *w, struct tfo_eflow *ef, uint8_t new_state)
{
	--w->st.flow_state[ef->state];
	++w->st.flow_state[new_state];
	ef->state = new_state;
}

#ifdef DEBUG_SACK_SEND
static void
dump_sack_entries(const struct tfo_side *fos)
{
	unsigned i;

	printf("sack_gap %u sack_entries %u first_sack_entry %u\n", fos->sack_gap, fos->sack_entries, fos->first_sack_entry);
	for (i = 0; i < MAX_SACK_ENTRIES; i++)
		printf("  %u: 0x%x -> 0x%x%s\n", i, fos->sack_edges[i].left_edge, fos->sack_edges[i].right_edge, i == fos->first_sack_entry ? " *" : "");
}
#endif

static void
update_sack_for_ack(struct tfo_side *fos)
{
	unsigned ent, last, next_op;

#ifdef DEBUG_SACK_SEND
	printf("SACK entries before ack:\n");
	dump_sack_entries(fos);
#endif

	/* Any SACK entries before fos->snd_una need to be removed */
	last = (fos->first_sack_entry + fos->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
	for (next_op = ent = fos->first_sack_entry; ; ent = (ent + 1) % MAX_SACK_ENTRIES) {
		if (after(fos->snd_una, fos->sack_edges[ent].right_edge)) {
			/* We don't want this entry any more */
			if (!--fos->sack_entries)
				break;
			continue;
		}

		if (after(fos->snd_una, fos->sack_edges[ent].left_edge))
			fos->sack_edges[ent].left_edge = fos->snd_una;

		if (ent != next_op)
			fos->sack_edges[next_op] = fos->sack_edges[ent];
		next_op = (next_op + 1) % MAX_SACK_ENTRIES;
				
		if (ent == last)
			break;
	}

#ifdef DEBUG_SACK_SEND
	printf("SACK entries before ack:\n");
	dump_sack_entries(fos);
#endif
}

static void
update_sack_for_seq(struct tfo_side *fos, struct tfo_pkt *pkt, struct tfo_side *foos)
{
	struct tfo_pkt *begin, *end, *next;
	uint32_t left, right;
	uint8_t entry, last_entry, next_free;

	/* fos is where the packet is queued, foos is the side that wants the SACK info */
	if (!fos->sack_gap) {
		foos->sack_entries = 0;
		return;
	}

#ifdef DEBUG_SACK_SEND
	printf("SACK entries before new packet:\n");
	dump_sack_entries(foos);
#endif

	/* Find the contiguous block start and end */
	next = pkt;
	begin = pkt;
	list_for_each_entry_continue_reverse(next, &fos->pktlist, list) {
		if (before(segend(next), begin->seq))
			break;
		begin = next;
	}

	if (begin->seq == fos->snd_una) {
		/* There is no gap, do nothing */
#ifdef DEBUG_SACK_SEND
		printf("seq 0x%x is in initial block without a gap\n", pkt->seq);
#endif
		return;
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

#ifdef DEBUG_SACK_SEND
	printf("packet block is 0x%x -> 0x%x\n", left, right);
#endif

	if (foos->sack_entries) {
		if (!after(left, foos->sack_edges[foos->first_sack_entry].left_edge) &&
		    !before(right, foos->sack_edges[foos->first_sack_entry].right_edge)) {
			/* We are just expanding the entry - reuse it */
		} else {
			/* Check this new entry is not covering any other entry */
			if (foos->sack_entries > 1) {
				last_entry = (foos->first_sack_entry + foos->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
				for (entry = (foos->first_sack_entry + 1) % MAX_SACK_ENTRIES, next_free = entry; ; entry = (entry + 1) % MAX_SACK_ENTRIES) {
					if (!after(left, foos->sack_edges[entry].left_edge) &&
					    !before(right, foos->sack_edges[entry].right_edge)) {
						/* Remove the entry */
						foos->sack_entries--;
					} else {
						if (entry != next_free)
							foos->sack_edges[next_free] = foos->sack_edges[entry];
						next_free = (next_free + 1) % MAX_SACK_ENTRIES;
					}

					if (entry == last_entry)
						break;
				}
			}

			/* Move the head back and add the entry */
			foos->first_sack_entry = (foos->first_sack_entry + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
			if (foos->sack_entries < MAX_SACK_ENTRIES)
				foos->sack_entries++;
		}
	} else
		foos->sack_entries = 1;

	foos->sack_edges[foos->first_sack_entry].left_edge = left;
	foos->sack_edges[foos->first_sack_entry].right_edge = right;

#ifdef DEBUG_SACK_SEND
	printf("SACK entries after new packet:\n");
	dump_sack_entries(foos);
#endif
}

static inline bool
check_seq(uint32_t seq, uint32_t seglen, uint32_t win_end, const struct tfo_side *fo)
{
	/* RFC793 3.9 - SEGMENT_ARRIVES - first check sequence number */
	if (seglen == 0) {
		if (fo->rcv_win == 0)
			return seq == fo->rcv_nxt;

		return between_end_ex(seq, fo->rcv_nxt, win_end);
	}

	return (fo->rcv_win != 0 &&
		(between_end_ex(seq, fo->rcv_nxt, win_end) ||
		 between_end_ex(seq + seglen - 1, fo->rcv_nxt, win_end)));
}

// See Linux tcp_input.c tcp_clear_retrans() to tcp_try_to_open() for Recovery handling

static void
invoke_congestion_control(struct tfo_side *fos)
{
	/* RFC8985 7.4.2 says invoke congestion control response equivalent to a fast recovery.
	 * I presume this means some parts of RFC5681 3.2. The Linux code for this is in
	 * net/ipv4/tcp_input.c tcp_process_tlp_ack() and uses RFC6937. */
	printf("INVOKE_CONGESTION_CONTROL called\n");
}

static inline bool
rack_sent_after(time_ns_t t1, time_ns_t t2, uint32_t seq1, uint32_t seq2)
{
	return t1 > t2 || (t1 == t2 && after(seq1, seq2));
}

// Returns true if need to invoke congestion control
static inline bool
tlp_process_ack(uint32_t ack, struct tfo_pkt_in *p, struct tfo_side *fos, bool dsack)
{
	/* RFC8985 7.4.2 */
	if (!(fos->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) ||
	    before(ack, fos->tlp_end_seq))
		return false;

	if (!(fos->flags & TFO_SIDE_FL_TLP_IS_RETRANS)) {
		fos->flags &= ~TFO_SIDE_FL_TLP_IN_PROGRESS;
		return false;
	}

	if (dsack && rte_be_to_cpu_32(p->sack_opt->edges[0].right_edge) == fos->tlp_end_seq) {
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		return false;
	}

	if (after(ack, fos->tlp_end_seq)) {
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		invoke_congestion_control(fos);
		return true;
	}

	if (!after(ack, fos->snd_una) && !p->sack_opt) {
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		return false;
	}

	return false;
}

static void
update_rto(struct tfo_side *fos, time_ns_t pkt_ns)
{
	uint32_t rtt = (now - pkt_ns) / NSEC_PER_USEC;

#ifdef DEBUG_RTO
	printf("update_rto() pkt_ns %lu rtt %u\n", pkt_ns, rtt);
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
	else if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC) {
#ifdef DEBUG_RTO
		printf("New running rto %u us, reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC);
#endif
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;
	}

	fos->flags |= TFO_SIDE_FL_NEW_RTT;
}

static void
update_rto_ts(struct tfo_side *fos, time_ns_t pkt_ns, uint32_t pkts_ackd)
{
	uint32_t rtt = (now - pkt_ns) / NSEC_PER_USEC;
	uint32_t new_rttvar;

#ifdef DEBUG_RACK
	printf("update_rto_ts() pkt_ns " NSEC_TIME_PRINT_FORMAT " rtt_ns " NSEC_TIME_PRINT_FORMAT " rtt %u pkts in flight %u ackd %u\n", NSEC_TIME_PRINT_PARAMS(pkt_ns), NSEC_TIME_PRINT_PARAMS_ABS(now - pkt_ns), rtt, fos->pkts_in_flight, pkts_ackd);
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
		fos->rttvar_us = ((4 * fos->pkts_in_flight - pkts_ackd) * fos->rttvar_us + pkts_ackd * new_rttvar) / (fos->pkts_in_flight * 4);
		fos->srtt_us = ((8 * fos->pkts_in_flight - pkts_ackd) * fos->srtt_us + pkts_ackd * rtt) / (fos->pkts_in_flight * 8);
	}
	fos->rto_us = fos->srtt_us + max(1U, fos->rttvar_us * 4);

	if (fos->rto_us < TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC)
		fos->rto_us = TFO_TCP_RTO_MIN_MS * USEC_PER_MSEC;
	else if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC) {
#ifdef DEBUG_RTO
		printf("New running rto %u us, reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC);
#endif
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;
	}

	fos->flags |= TFO_SIDE_FL_NEW_RTT;
}

static inline void
rack_remove_acked_sacked_packet(struct tcp_worker *w, struct tfo_side *fos, struct tfo_pkt *pkt, uint32_t ack, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *sack_pkt, *next_pkt;

	/* Remove packets marked after the new ack */
printf("acked %d, segend_pkt 0x%x snd_una 0x%x\n", !!(pkt->flags & TFO_PKT_FL_ACKED), segend(pkt), ack);
	if (!after(segend(pkt), ack)) {
#ifdef DEBUG_ACK
		printf("Calling pkt_free m %p, seq 0x%x\n", pkt->m, pkt->seq);
#endif
		pkt_free(w, fos, pkt, tx_bufs);

		return;
	}

	/* This is being sack'd for the first time */
	pkt->rack_segs_sacked = 1;
	pkt->flags &= ~TFO_PKT_FL_SACKED;

	if (!list_is_first(&pkt->list, &fos->pktlist) &&
	    !list_prev_entry(pkt, list)->m) {
		sack_pkt = list_prev_entry(pkt, list);
		if (after(pkt->seq, segend(sack_pkt)))
			sack_pkt = NULL;
	} else
		sack_pkt = NULL;

	if (!sack_pkt) {
#ifdef DEBUG_SACK_RX
		printf("sack pkt now 0x%x, len %u\n", pkt->seq, pkt->seglen);
#endif
		sack_pkt = pkt;
		pkt_free_mbuf(pkt, fos, tx_bufs);
	} else {
		sack_pkt->rack_segs_sacked += pkt->rack_segs_sacked;
		sack_pkt->seglen = segend(pkt) - sack_pkt->seq;

		/* We want the earliest anything in the block was sent */
		if (sack_pkt->ns > pkt->ns)
			sack_pkt->ns = pkt->ns;

		pkt->rack_segs_sacked = 0;

		pkt_free(w, fos, pkt, tx_bufs);
#ifdef DEBUG_SACK_RX
		printf("sack pkt updated 0x%x, len %u\n", sack_pkt->seq, sack_pkt->seglen);
#endif
	}
#ifdef DEBUG_RACK_SACKED
	printf("rack_segs_sacked for 0x%x now %u\n", sack_pkt->seq, sack_pkt->rack_segs_sacked);
#endif

	/* If the following packet is a sack entry and there is no gap between this
	 * sack entry and the next, and the next entry extends beyond right_edge,
	 * merge them */
	if (!list_is_last(&sack_pkt->list, &fos->pktlist)) {
		next_pkt = list_next_entry(sack_pkt, list);
		if (!next_pkt->m &&
		    !before(segend(sack_pkt), next_pkt->seq)) {
			sack_pkt->seglen = segend(next_pkt) - sack_pkt->seq;
			sack_pkt->rack_segs_sacked += next_pkt->rack_segs_sacked;
			next_pkt->rack_segs_sacked = 0;

			/* We want the earliest anything in the block was sent */
			if (next_pkt->ns < sack_pkt->ns)
				sack_pkt->ns = next_pkt->ns;

			pkt_free(w, fos, next_pkt, tx_bufs);
		}
	}
}

static uint32_t max_segend;	// Make this a parameter
static bool dsack_seen;		// This must be returned too

static void
rack_resend_lost_packets(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt, *pkt_tmp;

	pkt = list_entry(fos->last_sent, struct tfo_pkt, xmit_ts_list);
	list_for_each_entry_safe_continue(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
		if (pkt->flags & TFO_PKT_FL_LOST) {
#ifdef DEBUG_SEND_PKT_LOCATION
			printf("send_tcp_pkt B\n");
#endif
			send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);
		}
	}
}

static inline void
update_most_recent_pkt(struct tfo_pkt *pkt, struct tfo_side *fos, struct tfo_pkt **most_recent_pkt, bool using_ts, uint32_t ack_ts_ecr)
{
	if (!*most_recent_pkt) {
		*most_recent_pkt = pkt;
		return;
	}

	if (pkt->ns < (*most_recent_pkt)->ns)
		return;

	if (pkt->ns == (*most_recent_pkt)->ns &&
	    !after(segend(pkt), segend(*most_recent_pkt)))
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

	*most_recent_pkt = pkt;
}

static inline void
rack_update(struct tfo_pkt_in *p, struct tfo_side *fos)
{
	uint32_t ack;
	struct tfo_pkt *most_recent_pkt = NULL;
	uint32_t ack_ts_ecr;
	struct tfo_pkt *pkt;
	struct tfo_pkt *first_not_acked_pkt;
	uint32_t pkts_ackd = 0;
	bool using_ts;

	dsack_seen = false;

	ack = rte_be_to_cpu_32(p->tcp->recv_ack);
	max_segend = ack;

	if (p->ts_opt) {
		ack_ts_ecr = rte_be_to_cpu_32(p->ts_opt->ts_ecr);
		using_ts = true;
	} else {
		ack_ts_ecr = 0;		/* This isn't used of using_ts is false, but gcc can't work that out */
		using_ts = false;
	}

	/* Mark all ack'd packets */
	list_for_each_entry(pkt, &fos->pktlist, list) {
		if (after(segend(pkt), ack))
			break;

		pkt->flags |= TFO_PKT_FL_ACKED;

		if (!pkt->m)
			continue;

		pkts_ackd++;

		update_most_recent_pkt(pkt, fos, &most_recent_pkt, using_ts, ack_ts_ecr);

		if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
			update_rto(fos, pkt->ns);
			pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
			fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
		}
	}
	first_not_acked_pkt = pkt;

//	if (after(ack, fos->snd_una))
//		fos->snd_una = ack;

	/* Mark all sack'd packets as sacked */
	if (p->sack_opt) {
		uint32_t sack_blocks[MAX_SACK_ENTRIES][2];
		uint8_t sack_idx[MAX_SACK_ENTRIES];
		uint8_t num_sack_blocks;
		uint8_t tmp_sack_idx;
		uint32_t left_edge, right_edge;
		uint8_t num_sack_ent;
		uint8_t i, j;

// For elsewhere - if get SACK and !resent snd_una packet recently (whatever that means), resent unack'd packets not recently resent.
// If don't have them, send ACK to other side if not sending packets
		num_sack_ent = (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges);
#ifdef DEBUG_SACK_RX
		printf("Rack update SACK with %u entries\n", num_sack_ent);
#endif

		/* See RFC2883 4.1 and 4.2. For a DSACK, either first SACK entry is before ACK
		 * or it is a (not necessarily proper) subset of the second SACK entry */
		if (before(rte_be_to_cpu_32(p->sack_opt->edges[0].left_edge), ack))
			dsack_seen = true;
		else if (num_sack_ent > 1 &&
			 !before(rte_be_to_cpu_32(p->sack_opt->edges[0].left_edge), rte_be_to_cpu_32(p->sack_opt->edges[1].left_edge)) &&
			 !after(rte_be_to_cpu_32(p->sack_opt->edges[0].right_edge), rte_be_to_cpu_32(p->sack_opt->edges[1].right_edge)))
			dsack_seen = true;
#ifdef DEBUG_RACK
		if (dsack_seen)
			printf("*** DSACK seen\n");
#endif

		if (num_sack_ent > dsack_seen) {
			/* If the first entry is a DSACK, we don't need it */
			for (i = dsack_seen, num_sack_blocks = 0; i < num_sack_ent; i++, num_sack_blocks++) {
				sack_blocks[num_sack_blocks][0] = rte_be_to_cpu_32(p->sack_opt->edges[i].left_edge);
				sack_blocks[num_sack_blocks][1] = rte_be_to_cpu_32(p->sack_opt->edges[i].right_edge);
				sack_idx[num_sack_blocks] = num_sack_blocks;
			}

			/* bubble sort - max 6 comparisons (3 if TS option) - think n(n - 1)/2 */
			for (j = num_sack_blocks - 1; j > 0; j--) {
				for (i = 0; i < j; i++) {
					if (after(sack_blocks[sack_idx[i]][0], sack_blocks[sack_idx[i + 1]][0])) {
						tmp_sack_idx = sack_idx[i + 1];
						sack_idx[i + 1] = sack_idx[i];
						sack_idx[i] = tmp_sack_idx;
					}
				}
			}

#ifdef DEBUG_SACK_RX
			printf("Sorted SACK - ");
			for (i = 0; i < num_sack_blocks; i++)
				printf("%s0x%x -> 0x%x", i ? "    " : "", sack_blocks[sack_idx[i]][0], sack_blocks[sack_idx[i]][1]);
			printf("\n");
#endif

			left_edge = sack_blocks[sack_idx[0]][0];
			right_edge = sack_blocks[sack_idx[0]][1];
			i = 0;
#ifdef DEBUG_SACK_RX
			printf("  %u: 0x%x -> 0x%x\n", sack_idx[i], left_edge, right_edge);
#endif
			pkt = first_not_acked_pkt;
			list_for_each_entry_from(pkt, &fos->pktlist, list) {
				/* Check if we need to move on to the next sack block */
				while (after(segend(pkt), right_edge)) {
#ifdef DEBUG_SACK_RX
					printf("     0x%x + %u (0x%x) after window\n",
						pkt->seq, pkt->seglen, segend(pkt));
#endif
					if (++i == num_sack_blocks)
						break;

					left_edge = sack_blocks[sack_idx[i]][0];
					right_edge = sack_blocks[sack_idx[i]][1];
#ifdef DEBUG_SACK_RX
					printf("  %u: 0x%x -> 0x%x\n", sack_idx[i], left_edge, right_edge);
#endif
				}
				if (i == num_sack_blocks)
					break;

				if (!pkt->m) {
#ifdef DEBUG_SACK_RX
					if (!before(pkt->seq, left_edge))
						printf("     0x%x + %u (0x%x) already SACK'd in window\n",
							pkt->seq, pkt->seglen, segend(pkt));
#endif
					continue;
				}

				/* It shouldn't be possible to have the SACKED flag set here */
				if (before(pkt->seq, left_edge) ||
				    (pkt->flags & (TFO_PKT_FL_ACKED | TFO_PKT_FL_SACKED)))
					continue;

#ifdef DEBUG_SACK_RX
				printf("     0x%x + %u (0x%x) in window\n",
					pkt->seq, pkt->seglen, segend(pkt));
#endif

				fos->rack_segs_sacked++;
#ifdef DEBUG_RACK_SACKED
				printf("  fos->rack_segs_sacked for 0x%x incremented to %u\n", pkt->seq, fos->rack_segs_sacked);
#endif

				/* This is being "ack'd" for the first time */
				pkt->flags |= TFO_PKT_FL_SACKED;

				update_most_recent_pkt(pkt, fos, &most_recent_pkt, using_ts, ack_ts_ecr);

				if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
					update_rto(fos, pkt->ns);
					pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
					fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
				}

				if (after(segend(pkt), max_segend))
					max_segend = segend(pkt);

				pkts_ackd++;
			}
		}
	}

// Why are we doing this here?
	if (tlp_process_ack(ack, p, fos, dsack_seen)) {
//		invoke_congestion_control(fos);
		/* In tcp_process_tlp_ack() in tcp_input.c:
			tcp_init_cwnd_reduction(sk);
			tcp_set_ca_state(sk, TCP_CA_CWR);
			tcp_end_cwnd_reduction(sk);
			tcp_try_keep_open(sk);
		 */
	}

	if (most_recent_pkt) {
		/* RFC8985 Step 1 */
		if (using_ts)
			update_rto_ts(fos, most_recent_pkt->ns, pkts_ackd);

		/* 300 = /proc/sys/net/ipv4/tcp_min_rtt_wlen. Kernel passes 2nd and 3rd parameters in jiffies (1000 jiffies/sec on x86_64).
		   We record rtt_min in usecs  */
		minmax_running_min(&fos->rtt_min, config->tcp_min_rtt_wlen * USEC_PER_MSEC, now / NSEC_PER_USEC, (now - most_recent_pkt->ns) / NSEC_PER_USEC);

		/* RFC8985 Step 2 */
		fos->rack_rtt_us = (now - most_recent_pkt->ns) / NSEC_PER_USEC;
		if (rack_sent_after(most_recent_pkt->ns, fos->rack_xmit_ts, segend(most_recent_pkt), fos->rack_end_seq)) {
			fos->rack_xmit_ts = most_recent_pkt->ns;
			fos->rack_end_seq = segend(most_recent_pkt);
		}
	}
}

/* RFC8985 Step 3 */
static inline void
rack_detect_reordering(struct tfo_side *fos)
{
	struct tfo_pkt *pkt;

	list_for_each_entry(pkt, &fos->pktlist, list) {
		if (after(segend(pkt), max_segend))
			break;

		if (!(pkt->flags & (TFO_PKT_FL_ACKED | TFO_PKT_FL_SACKED)))
			continue;

		if (after(segend(pkt), fos->rack_fack))
			fos->rack_fack = segend(pkt);
		else if (before(segend(pkt), fos->rack_fack) &&
			 !(pkt->flags & TFO_PKT_FL_RESENT))
			fos->flags |= TFO_SIDE_FL_RACK_REORDERING_SEEN;
	}
}

/* RFC8985 Step 4 */
static inline uint32_t
rack_update_reo_wnd(struct tfo_side *fos, uint32_t ack)
{
	if ((fos->flags & TFO_SIDE_FL_DSACK_ROUND) &&
	    !before(ack, fos->rack_dsack_round))
		fos->flags &= ~TFO_SIDE_FL_DSACK_ROUND;

	if (!(fos->flags & TFO_SIDE_FL_DSACK_ROUND) && dsack_seen) {
		fos->flags |= TFO_SIDE_FL_DSACK_ROUND;
		fos->rack_dsack_round = fos->snd_nxt;
		fos->rack_reo_wnd_mult++;
		fos->rack_reo_wnd_persist = 16;
	} else if (fos->flags & TFO_SIDE_FL_ENDING_RECOVERY) {
		if (fos->rack_reo_wnd_persist)
			fos->rack_reo_wnd_persist--;
		if (!fos->rack_reo_wnd_persist)
			fos->rack_reo_wnd_mult = 1;
	}

	if (!(fos->flags & TFO_SIDE_FL_RACK_REORDERING_SEEN)) {
// RFC is unclear if in recovery excludes ending recovery
		if ((fos->flags & (TFO_SIDE_FL_IN_RECOVERY | TFO_SIDE_FL_ENDING_RECOVERY)) == TFO_SIDE_FL_IN_RECOVERY ||
		    fos->rack_segs_sacked >= DUP_ACK_THRESHOLD)
			return 0;
	}

	return min(fos->rack_reo_wnd_mult * minmax_get(&fos->rtt_min) / 4, fos->srtt_us);
}

static inline void
mark_packet_lost(struct tfo_pkt *pkt, struct tfo_side *fos)
{
	pkt->flags |= TFO_PKT_FL_LOST;
	pkt->ns = TFO_TS_NONE;		// Could remove this from xmit_ts_list (in which case need list_for_each_entry_safe())
	fos->pkts_in_flight--;

	if (fos->last_sent == &pkt->xmit_ts_list)
		fos->last_sent = pkt->xmit_ts_list.prev;

	list_move_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);
}
//
//#define DETECT_LOSS_MIN

/* RFC8985 Step 5 */
static uint32_t
rack_detect_loss(struct tcp_worker *w, struct tfo_side *fos, uint32_t ack, struct tfo_tx_bufs *tx_bufs)
{
#ifndef DETECT_LOSS_MIN
	time_ns_t timeout = 0;
#else
	time_ns_t timeout = UINT64_MAX;
#endif
	time_ns_t first_timeout = now - (fos->rack_rtt_us + fos->rack_reo_wnd_us) * NSEC_PER_USEC;
	struct tfo_pkt *pkt, *pkt_tmp;
	bool pkt_lost = false;

#ifdef DEBUG_RACK_LOSS
	printf("rack_detect_loss fos %p ack 0x%x\n", fos, ack);
#endif
	fos->rack_reo_wnd_us = rack_update_reo_wnd(fos, ack);

	list_for_each_entry_safe(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
#ifdef DEBUG_RACK_LOSS
		printf("rack_xmit_ts " NSEC_TIME_PRINT_FORMAT " pkt->ns " NSEC_TIME_PRINT_FORMAT " rack_end_seq 0x%x segend 0x%x\n",
				NSEC_TIME_PRINT_PARAMS(fos->rack_xmit_ts), NSEC_TIME_PRINT_PARAMS(pkt->ns), fos->rack_end_seq, segend(pkt));
#endif
		if (pkt->flags & (TFO_PKT_FL_ACKED | TFO_PKT_FL_SACKED)) {
			rack_remove_acked_sacked_packet(w, fos, pkt, ack, tx_bufs);
			continue;
		}

		/* NOTE: if we send packets out of sequence in the same batch, then this will
		 * trigger loss here if rack_reo_wnd == 0. We many want to add 1ns for each
		 * packet sent. */
		if (!rack_sent_after(fos->rack_xmit_ts, pkt->ns, fos->rack_end_seq, segend(pkt)))
			break;

		if (pkt->flags & TFO_PKT_FL_LOST)
			break;

		if (pkt->ns <= first_timeout) {
			mark_packet_lost(pkt, fos);
			pkt_lost = true;
#ifdef DEBUG_IN_FLIGHT
			printf("rack_detect_loss decremented pkts_in_flight to %u\n", fos->pkts_in_flight);
#endif
		} else {
#ifndef DETECT_LOSS_MIN
			timeout = max(pkt->ns - first_timeout, timeout);
#else
			timeout = min(pkt->ns - first_timeout, timeout);
#endif
		}
	}

	list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
#ifdef DEBUG_RACK_LOSS
		printf("A remove packet snd_una 0x%x segend 0x%x\n", fos->snd_una, segend(pkt));
#endif
		if (after(segend(pkt), ack))
			break;
		rack_remove_acked_sacked_packet(w, fos, pkt, ack, tx_bufs);
	}

	if (pkt_lost &&
	    !(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		/* RFC8985 step 4 */
		fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
		printf("Entering rack loss recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
	}

#ifndef DETECT_LOSS_MIN
	return timeout;
#else
	return timeout != UINT64_MAX ?: 0;
#endif
}

static bool
rack_detect_loss_and_arm_timer(struct tcp_worker *w, struct tfo_side *fos, uint32_t ack, struct tfo_tx_bufs *tx_bufs)
{
	uint32_t timeout;

	timeout = rack_detect_loss(w, fos, ack, tx_bufs);

	if (timeout) {
		tfo_reset_timer(fos, TFO_TIMER_REO, timeout);
		return true;
	}

	return false;
}

static void
do_rack(struct tfo_pkt_in *p, uint32_t ack, struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	uint32_t pre_in_flight;

	rack_update(p, fos);

	if (fos->flags & TFO_SIDE_FL_IN_RECOVERY &&
	    !before(ack, fos->recovery_end_seq)) {	// Alternative is fos->rack_segs_sacked == 0
#ifdef DEBUG_RECOVERY
		printf("Ending recovery\n");
#endif
		fos->flags |= TFO_SIDE_FL_ENDING_RECOVERY;
	}

	rack_detect_reordering(fos);

	pre_in_flight = fos->pkts_in_flight;
	rack_detect_loss_and_arm_timer(w, fos, ack, tx_bufs);

#ifdef DEBUG_IN_FLIGHT
	printf("do_rack() pre_in_flight %u fos->pkts_in_flight %u\n", pre_in_flight, fos->pkts_in_flight);
#endif

	if (fos->pkts_in_flight < pre_in_flight) {
		/* Some packets have been lost */
		rack_resend_lost_packets(w, fos, foos, tx_bufs);
	}

// Should we check for needing to continue in recovery, or starting it again?
	if (fos->flags & TFO_SIDE_FL_ENDING_RECOVERY)
		fos->flags &= ~(TFO_SIDE_FL_IN_RECOVERY | TFO_SIDE_FL_ENDING_RECOVERY);
	else if (!(fos->flags & (TFO_SIDE_FL_IN_RECOVERY | TFO_SIDE_FL_RACK_REORDERING_SEEN)) &&
		 fos->rack_segs_sacked >= DUP_ACK_THRESHOLD) {
		/* RFC8985 Step 4 */
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
		printf("Entering RACK no reordering recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
	}
}

// See RFC8985 5.4 and 8 re managing timers
static void
rack_mark_losses_on_rto(struct tfo_side *fos)
{
	struct tfo_pkt *pkt;
	bool pkt_lost = false;

/* Not sure about the check against snd_una. Imagine:
 *   Send packets 1 2 3 4 5
 *   3 is sacked
 *   After reo_wnd 1 and 2 are resent
 *   Get rto, snd_una == 1, but 1 still in flight and not timed out
 */
	list_for_each_entry(pkt, &fos->xmit_ts_list, xmit_ts_list) {
		if (pkt->ns + (fos->rack_rtt_us + fos->rack_reo_wnd_us) * NSEC_PER_USEC > now)
			break;

		if (pkt->flags & TFO_PKT_FL_LOST)
			break;

//		if (pkt->seq == fos->snd_una ||		// The first packet sent ??? Should be first pkt on xmit_ts_list
		mark_packet_lost(pkt, fos);
		pkt_lost = true;

#ifdef DEBUG_IN_FLIGHT
		printf("rack_mark_losses_on_rto decremented pkts_in_flight to %u\n", fos->pkts_in_flight);
#endif

	}

	if (pkt_lost &&
	    !(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->flags &= ~(TFO_SIDE_FL_TLP_IN_PROGRESS | TFO_SIDE_FL_TLP_IS_RETRANS);
		fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
		printf("Entering RTO recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
	}

	/* RFC 6298 5.5 */
	fos->rto_us *= 2;
	if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC) {
#ifdef DEBUG_RTO
		printf("rto fos resend after RTO double %u - reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC);
#endif
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;
	}
}

static void
handle_delayed_ack_timeout(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	if (fos->delayed_ack_timeout <= now)
		generate_ack_rst(w, ef, fos, foos, tx_bufs, false, false);
}

static void
handle_rto(struct tcp_worker *w, struct tfo_side *fos,
	   struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt;

	pkt = list_first_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);

	/* RFC5681 3.2 */
	if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_RESENT)) == TFO_PKT_FL_SENT) {
		fos->ssthresh = min((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
		fos->cwnd = fos->mss;
	}

#ifdef DEBUG_SEND_PKT_LOCATION
	printf("send_tcp_pkt L\n");
#endif
	send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);

#ifdef DEBUG_TIMERS
	printf("  Resending 0x%x %u\n", pkt->seq, pkt->seglen);
#endif

	fos->rto_us *= 2;
	if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC) {
#ifdef DEBUG_RTO
		printf("rto resend after timeout double %u - reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC);
#endif
		fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;
	}

	if (!(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
		printf("Entering RTO recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
	}
}

/* This is also called for connections not using RACK, but
 * in that case we won't have a REO or PTO timer */
static bool
handle_rack_tlp_timeout(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	bool set_timer = true;

#ifdef DEBUG_RACK
	printf("RACK timeout %s (fos %p)\n",
		fos->cur_timer == TFO_TIMER_REO ? "REO" :
		fos->cur_timer == TFO_TIMER_PTO ? "PTO" :
		fos->cur_timer == TFO_TIMER_RTO ? "RTO" :
		fos->cur_timer == TFO_TIMER_ZERO_WINDOW ? "ZW" :
		fos->cur_timer == TFO_TIMER_KEEPALIVE ? "KA" :
		fos->cur_timer == TFO_TIMER_SHUTDOWN ? "SH" :
		"unknown",
		fos);
#endif

	switch(fos->cur_timer) {
	case TFO_TIMER_REO:
		set_timer = rack_detect_loss_and_arm_timer(w, fos, fos->snd_una, tx_bufs);
		break;
	case TFO_TIMER_PTO:
// Must use RTO now. tlp_send_probe() can set timer - do we handle that properly?
		tlp_send_probe(w, fos, foos, tx_bufs);
		break;
	case TFO_TIMER_RTO:
		if (unlikely(!using_rack(ef)))
			handle_rto(w, fos, foos, tx_bufs);
		else
			rack_mark_losses_on_rto(fos);
		break;
	case TFO_TIMER_ZERO_WINDOW:
		// TODO
		break;
	case TFO_TIMER_KEEPALIVE:
		send_keepalive(w, ef, fos, foos, tx_bufs);
		set_timer = false;
		break;
	case TFO_TIMER_SHUTDOWN:
		_eflow_free(w, ef, tx_bufs);
		return true;
	case TFO_TIMER_NONE:
		// Keep gcc happy
		break;
	}

	if (!list_empty(&fos->xmit_ts_list) &&
	    list_last_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->flags & TFO_PKT_FL_LOST)
		rack_resend_lost_packets(w, fos, foos, tx_bufs);

	if (set_timer)
		tfo_reset_xmit_timer(fos, false);

	return false;
}

// *** Note: We may need to do more checking about whether the packet is just an ACK or has payload.
// *** Also check PSH isn't set if have no payload. Also URG.
// *** There is not below about an ACK (no payload) with the SEQ indicating missing packets.
// *** Generally we shouldn't ACK an ACK.
static enum tfo_pkt_state
tfo_handle_pkt(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo *fo;
	struct tfo_side *fos, *foos;
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_pkt *send_pkt;
	struct tfo_pkt *queued_pkt;
	time_ns_t newest_send_time;
	uint32_t pkts_ackd;
	uint32_t seq;
	uint32_t ack;
	bool seq_ok = false;
	uint32_t snd_nxt;
	uint32_t win_end;
	uint32_t nxt_exp;
	struct rte_tcp_hdr* tcp = p->tcp;
	bool rcv_nxt_updated = false;
	bool snd_win_updated = false;
	bool free_mbuf = false;
	uint16_t orig_vlan;
	enum tfo_pkt_state ret = TFO_PKT_HANDLED;
	uint32_t new_win;
	bool fos_send_ack = false;
	bool fos_must_ack = false;
	bool fos_ack_from_queue = false;
	bool foos_send_ack = false;
#ifndef CWND_USE_RECOMMENDED
	uint32_t incr;
#endif
	int32_t bytes_sent;
	bool snd_wnd_increased = false;
	uint32_t dup_sack[2] = { 0, 0 };
	bool only_one_packet;


	if (ef->tfo_idx == TFO_IDX_UNUSED) {
		printf("tfo_handle_pkt called without flow\n");
		return TFO_PKT_FORWARD;
	}

	fo = &w->f[ef->tfo_idx];

	if (p->from_priv) {
		fos = &fo->priv;
		foos = &fo->pub;
	} else {
		fos = &fo->pub;
		foos = &fo->priv;
	}

	orig_vlan = update_vlan(p);

#ifdef DEBUG_PKT_RX
	printf("Handling packet, state %u, from %s, seq 0x%x, ack 0x%x, rx_win 0x%hx, fos: snd_una 0x%x, snd_nxt 0x%x rcv_nxt 0x%x foos 0x%x 0x%x 0x%x\n",
		ef->state, p->from_priv ? "priv" : "pub", rte_be_to_cpu_32(tcp->sent_seq), rte_be_to_cpu_32(tcp->recv_ack),
		rte_be_to_cpu_16(tcp->rx_win), fos->snd_una, fos->snd_nxt, fos->rcv_nxt, foos->snd_una, foos->snd_nxt, foos->rcv_nxt);
#endif

#if defined DEBUG_PKT_DELAYS || defined DEBUG_DLSPEED
	uint32_t payload = rte_pktmbuf_mtod(p->m, uint8_t *) + p->m->pkt_len - ((uint8_t *)p->tcp + (p->tcp->data_off >> 2));
	if (payload) {
#if defined DEBUG_PKT_DELAYS
		/* There is payload */
		printf("Packet interval from %s " NSEC_TIME_PRINT_FORMAT "\n", p->from_priv ? "priv" : "pub", NSEC_TIME_PRINT_PARAMS_ABS(now - fos->last_rx_data));
		fos->last_rx_data = now;
#endif

#ifdef DEBUG_DLSPEED
		update_speed_ring(fos, payload);
		printf("Transfer rate ");
		print_dl_speed(fos);
		printf("\n");
#endif
	}
#if defined DEBUG_PKT_DELAYS
	else {
		/* This is an ACK */
		printf("ACK interval from %s " NSEC_TIME_PRINT_FORMAT "\n", p->from_priv ? "priv" : "pub", NSEC_TIME_PRINT_PARAMS_ABS(now - fos->last_rx_ack));
		fos->last_rx_ack = now;
	}
#endif
#endif

	/* Basic validity checks of packet - SEQ, ACK, options */
	if (!set_estab_options(p, ef)) {
		/* There was something wrong with the options - stop optimizing. */
		clear_optimize(w, ef, tx_bufs);
		return TFO_PKT_FORWARD;
	}

	/* For a packet to be valid, it must meet the following:
	 *  1. Any timestamp must be no more than 2^31 beyond the last timestamp (PAWS)
	 *  2. seq >= rcv_nxt and seq + seglen < rcv_nxt + rcv_win << rcv_win_shift
	 *      or
	 *     seq no more that 2^30 before rcv_nxt (delayed duplicate packet)
	 *  3. ack <= snd_nxt
	 *  	and
	 *     ack no more that 2^30 before snd_una (delayed duplicate ack)
	 */

	seq = rte_be_to_cpu_32(tcp->sent_seq);
	ack = rte_be_to_cpu_32(tcp->recv_ack);

	/* RFC7323 - 5.3 R1 - PAWS */
	if (p->ts_opt &&
	    rte_be_to_cpu_32(p->ts_opt->ts_val) - rte_be_to_cpu_32(fos->ts_recent) >= (1U << 31)) {
// We are seeing these - problem.002.log
#ifdef DEBUG_PKT_VALID
		printf("Packet PAWS seq 0x%x not OK, ts_recent %u ts_val %u\n", seq, rte_be_to_cpu_32(fos->ts_recent), rte_be_to_cpu_32(p->ts_opt->ts_val));
#endif
		_send_ack_pkt_in(w, ef, fos, p, orig_vlan, foos, dup_sack, tx_bufs, false);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		rte_pktmbuf_free(p->m);
_Pragma("GCC diagnostic pop")

		return TFO_PKT_HANDLED;
	}

	/* Check the ACK is within the window, or a duplicate.
	 * We could remember the initial SEQ we sent and ensure it
	 * is not before that, until that becomes 2^31 ago */
	if (after(ack, fos->snd_nxt) || ack - fos->snd_una > (1U << 30)) {
//Had ack 0xc1c6b4b1 when snd_una == 0xc1c6b7fc. Ended up receiving an mbuf we already had queued. problem.001.log - search for HERE
#ifdef DEBUG_PKT_VALID
		printf("Packet ack 0x%x not OK\n", ack);
#endif
		_send_ack_pkt_in(w, ef, fos, p, orig_vlan, foos, dup_sack, tx_bufs, false);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		rte_pktmbuf_free(p->m);
_Pragma("GCC diagnostic pop")

		return TFO_PKT_HANDLED;
	}

	/* If the keepalive timer is running, restart it. Yes, we
	 * do want to do it even if the SEQ is invalid */
	if (fos->cur_timer == TFO_TIMER_KEEPALIVE)
		tfo_restart_keepalive_timer(fos);
// We can handle last_use here

	/* RFC793 - 3.9 p 65 et cf./ PAWS R2 */
	win_end = fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift);
	seq_ok = check_seq(seq, p->seglen, win_end, fos);
	if (!seq_ok) {
		if (seq + 1 == fos->rcv_nxt &&
		    p->seglen <= 1 &&
		    (tcp->tcp_flags & ~(RTE_TCP_ECE_FLAG | RTE_TCP_CWR_FLAG)) == RTE_TCP_ACK_FLAG) {
			/* This looks like a keepalive */
#ifdef DEBUG_KEEPALIVES
			printf("keepalive received\n");
#endif
		}
#ifdef DEBUG_PKT_VALID
		else if (fos->rcv_nxt - seq > (1U << 30))
			printf("Packet seq 0x%x not OK\n", seq);
#endif
		_send_ack_pkt_in(w, ef, fos, p, orig_vlan, foos, dup_sack, tx_bufs, false);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		rte_pktmbuf_free(p->m);
_Pragma("GCC diagnostic pop")

		return TFO_PKT_HANDLED;
	}

	/* SEQ and ACK are now validated as within windows or recent duplicates, and options OK */

	/* If we have received a FIN on this side, we must not receive any later data. */
	if (unlikely(tcp->tcp_flags & RTE_TCP_FIN_FLAG)) {
/* Check seq + p->seglen after rcv_nxt */
		fos_must_ack = true;
		if (likely(!(fos->flags & TFO_SIDE_FL_FIN_RX))) {
			fos->flags |= TFO_SIDE_FL_FIN_RX;
			fos->fin_seq = seq + p->seglen;
			++w->st.fin_pkt;
#ifdef DEBUG_FIN
			printf("Set fin_seq 0x%x - seq 0x%x seglen %u\n", fos->fin_seq, seq, p->seglen);
#endif
		} else {
			++w->st.fin_dup_pkt;
#ifdef DEBUG_FIN
			printf("Duplicate FIN\n");
#endif
		}

// DISCARD ANY QUEUED PACKETS WITH SEQ > SEQ of FIN
	}

	if (unlikely(!(tcp->tcp_flags & RTE_TCP_ACK_FLAG))) {
		/* This is invalid, unless RST */
		return TFO_PKT_FORWARD;
	}

	/* RFC 7323 4.3 (2) and PAWS R3 */
	if (p->ts_opt) {
		if (after(rte_be_to_cpu_32(p->ts_opt->ts_val), rte_be_to_cpu_32(fos->ts_recent)) &&
		    !after(seq, fos->last_ack_sent) &&
		    !before(seq, fos->rcv_nxt))
			fos->ts_recent = p->ts_opt->ts_val;

		if (after(rte_be_to_cpu_32(p->ts_opt->ts_val), fos->latest_ts_val)) {
			fos->latest_ts_val = rte_be_to_cpu_32(p->ts_opt->ts_val);
#ifdef CALC_USERS_TS_CLOCK
			fos->latest_ts_val_time = now;
#ifdef DEBUG_USERS_TX_CLOCK
			unsigned long ts_delta = fos->latest_ts_val - fos->ts_start;
			unsigned long us_delta = (now - fos->ts_start_time) / NSEC_PER_USEC;

			printf("TS clock %lu ns for %lu tocks - %lu us per tock\n", us_delta, ts_delta, (us_delta + ts_delta / 2) / ts_delta);
#endif
#endif
		}
	}

#ifdef DEBUG_TCP_WINDOW
	printf("fos->rcv_nxt 0x%x, fos->rcv_win 0x%x rcv_win_shift %u = 0x%x: seg 0x%x p->seglen 0x%x, tcp->rx_win 0x%x = 0x%x\n",
		fos->rcv_nxt, fos->rcv_win, fos->rcv_win_shift, fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift),
		seq, p->seglen, (unsigned)rte_be_to_cpu_16(tcp->rx_win), seq + p->seglen + (rte_be_to_cpu_16(tcp->rx_win) << fos->rcv_win_shift));
#endif

// This is merely reflecting the same window though.
// This should be optimised to allow a larger window that we buffer.
	/* Update the send window */
	if (before(fos->snd_una + (fos->snd_win << fos->snd_win_shift),
		   ack + (rte_be_to_cpu_16(tcp->rx_win) << fos->snd_win_shift)))
		snd_win_updated = true;

	/* Save the ttl/hop_limit to use when generating acks */
	fos->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->iph.ip6h->hop_limits : p->iph.ip4h->time_to_live;

#ifdef DEBUG_TCP_WINDOW
	if (fos->snd_una + (fos->snd_win << fos->snd_win_shift) !=
		   ack + (rte_be_to_cpu_16(tcp->rx_win) << fos->snd_win_shift))
		printf("fos->snd_win updated from 0x%x to 0x%x\n", fos->snd_win, (unsigned)rte_be_to_cpu_16(tcp->rx_win));
#endif
#ifdef DEBUG_ZERO_WINDOW
	if (!fos->snd_win || !tcp->rx_win)
		printf("Zero window %s - 0x%x -> 0x%x\n", fos->snd_win ? "freed" : "set", fos->snd_win, (unsigned)rte_be_to_cpu_16(tcp->rx_win));
#endif

	if (seq_ok)
		fos->snd_win = rte_be_to_cpu_16(tcp->rx_win);

// *** If we receive an ACK and the SEQ is beyond what we have received,
// *** it indicates a missing packet. We should consider sending an ACK.
	if (using_rack(ef))
		do_rack(p, ack, w, fos, foos, tx_bufs);

	newest_send_time = 0;
	pkts_ackd = 0;
	if (between_beg_ex(ack, fos->snd_una, fos->snd_nxt)) {
		if (!using_rack(ef) &&
		    (fos->flags & TFO_SIDE_FL_IN_RECOVERY) &&
		    !before(ack, fos->recovery_end_seq)) {
			fos->flags &= ~TFO_SIDE_FL_IN_RECOVERY;
#ifdef DEBUG_RECOVERY
			printf("Ending recovery\n");
#endif
		}

		/* RFC5681 3.2 */
		if (fos->cwnd < fos->ssthresh) {
			/* Slow start */
			fos->cwnd += min(ack - fos->snd_una, fos->mss);
#ifdef CWND_USE_RECOMMENDED
			fos->cum_ack = 0;
#endif
		} else {
			/* Congestion avoidance. */
#ifdef CWND_USE_RECOMMENDED
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

		snd_wnd_increased = true;
		fos->snd_una = ack;
		fos->dup_ack = 0;

		if (using_rack(ef)) {
			if (fos->sack_entries)
				update_sack_for_ack(fos);
		} else {
			/* remove acked buffered packets. We want the time the
			 * most recent packet was sent to update the RTT. */
#ifdef DEBUG_ACK
			printf("Looking to remove ack'd packets\n");
#endif
	// ### use xmit_ts list
			list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
#ifdef DEBUG_ACK_PKT_LIST
				printf("  pkt->seq 0x%x pkt->seglen 0x%x, tcp_flags 0x%x, ack 0x%x\n", pkt->seq, pkt->seglen, p->tcp->tcp_flags, ack);
#endif

				if (unlikely(after(segend(pkt), ack)))
					break;

				if (pkt->m) {
					/* The packet hasn't been ack'd before */
					if (pkt->ts) {
						if (pkt->ts->ts_val == p->ts_opt->ts_ecr &&
						    pkt->ns > newest_send_time)
							newest_send_time = pkt->ns;
#ifdef DEBUG_RTO
						else if (pkt->ts->ts_val != p->ts_opt->ts_ecr)
							printf("tsecr 0x%x != tsval 0x%x\n", rte_be_to_cpu_32(p->ts_opt->ts_ecr), rte_be_to_cpu_32(pkt->ts->ts_val));
#endif
						pkts_ackd++;
					} else {
						if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
							update_rto(fos, pkt->ns);
							pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
							fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
						}
					}
				}

				/* acked, remove buffered packet */
#ifdef DEBUG_ACK
				printf("Calling pkt_free m %p, seq 0x%x\n", pkt->m, pkt->seq);
#endif
				pkt_free(w, fos, pkt, tx_bufs);
			}
		}

		if (unlikely((foos->flags & (TFO_SIDE_FL_FIN_RX | TFO_SIDE_FL_CLOSED)) == TFO_SIDE_FL_FIN_RX &&
			     list_empty(&fos->pktlist))) {
			/* An empty packet list means the FIN has been ack'd */
			foos->flags |= TFO_SIDE_FL_CLOSED;
#ifdef DEBUG_FIN
			printf("Side %p now closed\n", foos);
#endif

			/* The other side is closed, If this side is closed, the connection
			 * is fully terminated. */
			if (fos->flags & TFO_SIDE_FL_CLOSED)
				ef->flags |= TFO_EF_FL_CLOSED;

			return TFO_PKT_HANDLED;
		}

		/* RFC8985 7.2 */
		tfo_reset_xmit_timer(fos, false);

		/* newest_send_time is set if we have removed a packet from the queue. */
		if (newest_send_time) {
			/* Can we open up the send window for the other side? */
// Only send ack if window nearly full
			if (set_rcv_win(foos, fos))
				foos_send_ack = true;

			/* Some packets have been acked. Does that open up our send window to
			 * send more packets? */
			if (snd_win_updated &&
			    fos->snd_win &&
			    !list_empty(&fos->pktlist) &&
			    (!(list_last_entry(&fos->pktlist, struct tfo_pkt, list)->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_QUEUED_SEND)))) {
// Maintain pointer to last (in SEQ order) pkt sent
				/* The last packet has neither been queued for sending nor sent, so we have some unsent packets */
				list_for_each_entry_reverse(pkt, &fos->pktlist, list) {
					if (pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_QUEUED_SEND))
						break;
				}

				win_end = get_snd_win_end(fos);
				list_for_each_entry_continue(pkt, &fos->pktlist, list) {
					if (after(segend(pkt), win_end))
						break;	/* beyond window */

#ifdef DEBUG_SEND_PKT_LOCATION
					printf("send_tcp_pkt M\n");
#endif
					send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);
				}
			}
		}
// What if fos->snd_una > ack ??? - reordering
	} else if (!using_rack(ef)) {
		if (fos->snd_una == ack &&		/* snd_una not advanced */
		   !list_empty(&fos->pktlist)) {
			if (p->seglen == 0) {
				send_pkt = list_first_entry(&fos->pktlist, struct tfo_pkt, list);

				if (after(send_pkt->seq, fos->snd_una)) {
					/* We haven't got the next packet, but have subsequent
					 * packets. The dup_ack process will be triggered, so
					 * we need to trigger it to the other side. */
#ifdef DEBUG_RFC5681
					printf("REQUESTING missing packet 0x%x by sending ACK to other side\n", send_pkt->seq);
#endif
					foos_send_ack = true;
				}

				/* RFC5681 and errata state that the rx_win should be the same -
				 *    fos->snd_win == rte_be_to_cpu_16(tcp->rx_win) */
				/* This counts pure ack's, i.e. no data, and ignores ACKs with data.
				 * RFC5681 doesn't state that the SEQs should all be the same, and I
				 * don't think that is necessary since we check seglen == 0. */
				if (++fos->dup_ack == DUP_ACK_THRESHOLD) {
					/* RFC5681 3.2 - fast recovery */

					if (fos->snd_una == send_pkt->seq) {
						/* We have the first packet, so resend it */
#ifdef DEBUG_RFC5681
						printf("RESENDING m %p seq 0x%x, len %u due to 3 duplicate ACKS\n", send_pkt, send_pkt->seq, send_pkt->seglen);
#endif

#ifdef DEBUG_CHECKSUM
						check_checksum(send_pkt, "RESENDING");
#endif
#ifdef DEBUG_SEND_PKT_LOCATION
						printf("send_tcp_pkt C\n");
#endif
						send_tcp_pkt(w, send_pkt, tx_bufs, fos, foos, false);
					}

					/* RFC5681 3.2.2 */
					fos->ssthresh = max((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
					fos->cwnd = fos->ssthresh + DUP_ACK_THRESHOLD * fos->mss;

					if (!(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
						fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
						fos->recovery_end_seq = fos->snd_una + 1;

#ifdef DEBUG_RECOVERY
						printf("Entering fast recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
					}
				} else {
					if (fos->dup_ack > DUP_ACK_THRESHOLD) {
						/* RFC5681 3.2.4 */
						fos->cwnd += fos->mss;
						only_one_packet = false;
						win_end = get_snd_win_end(fos);
					} else {
						/* RFC5681 3.2.1 */
						only_one_packet = true;

						win_end = fos->snd_win << fos->snd_win_shift;
						if (fos->cwnd + 2 * fos->mss < win_end)
							win_end = fos->cwnd + 2 * fos->mss;

						win_end += fos->snd_una;
					}

					if ((!(list_last_entry(&fos->pktlist, struct tfo_pkt, list)->flags & TFO_PKT_FL_SENT))) {
						list_for_each_entry_reverse(pkt, &fos->pktlist, list) {
							if (pkt->flags & TFO_PKT_FL_SENT)
								break;
							send_pkt = pkt;
						}

						/* If dup_ack > threshold, RFC5681 3.2.5 - we can send up to MSS bytes if within limits */
						bytes_sent = 0;
						while (!after(segend(send_pkt), win_end) &&
						       bytes_sent + send_pkt->seglen <= fos->mss) {
#ifdef DEBUG_RFC5681
							printf("SENDING new packet m %p seq 0x%x, len %u due to %u duplicate ACKS\n", send_pkt, send_pkt->seq, send_pkt->seglen, fos->dup_ack);
#endif

#ifdef DEBUG_CHECKSUM
							check_checksum(send_pkt, "RESENDING");
#endif
#ifdef DEBUG_SEND_PKT_LOCATION
							printf("send_tcp_pkt D\n");
#endif
							send_tcp_pkt(w, send_pkt, tx_bufs, fos, foos, false);

							if (only_one_packet ||
							    list_is_last(&send_pkt->list, &fos->pktlist))
								break;

							bytes_sent += send_pkt->seglen;
							send_pkt = list_next_entry(send_pkt, list);
						}
					}
				}
			}
		} else {
			/* RFC 5681 3.2.6 */
			if (fos->dup_ack)
				fos->cwnd = fos->ssthresh;
			fos->dup_ack = 0;
		}
	}

	if (!using_rack(ef)) {
		if (newest_send_time) {
			/* We are using timestamps */
			update_rto_ts(fos, newest_send_time, pkts_ackd);

			/* 300 = /proc/sys/net/ipv4/tcp_min_rtt_wlen. Kernel passes 2nd and 3rd parameters in jiffies (1000 jiffies/sec on x86_64).
			   We record rtt_min in usecs  */
			minmax_running_min(&fos->rtt_min, config->tcp_min_rtt_wlen * USEC_PER_MSEC, now / NSEC_PER_USEC, (now - newest_send_time) / NSEC_PER_USEC);
		}

		/* The assignment to send_pkt is completely unnecessary due to the checks below,
		 * but otherwise GCC generates a maybe-unitialized warning re send_pkt in the
		 * printf below, even though it is happier with the intervening uses. */
		if (fos->dup_ack &&
		    fos->dup_ack < DUP_ACK_THRESHOLD &&
		    !list_empty(&fos->pktlist) &&
		    (!((send_pkt = list_last_entry(&fos->pktlist, struct tfo_pkt, list))->flags & TFO_PKT_FL_SENT))) {
			/* RFC5681 3.2.1 - we can send an unsent packet if it is within limits */
			list_for_each_entry_reverse(pkt, &fos->pktlist, list) {
				if (pkt->flags & TFO_PKT_FL_SENT)
					break;
				send_pkt = pkt;
			}

			/* We can't use get_snd_win_end() here due to the extra 2 * fos->mss */
			if (!after(segend(send_pkt), fos->snd_una + (fos->snd_win << fos->snd_win_shift)) &&
			     !after(segend(send_pkt), fos->snd_una + fos->cwnd + 2 * fos->mss)) {
#ifdef DEBUG_RFC5681
				printf("SENDING new packet m %p seq 0x%x, len %u due to %u duplicate ACKS\n", send_pkt, send_pkt->seq, send_pkt->seglen, fos->dup_ack);
#endif

#ifdef DEBUG_CHECKSUM
				check_checksum(send_pkt, "RESENDING");
#endif
#ifdef DEBUG_SEND_PKT_LOCATION
				printf("send_tcp_pkt E\n");
#endif
				send_tcp_pkt(w, send_pkt, tx_bufs, fos, foos, false);
			}
		}

		/* Window scaling is rfc7323 */
		win_end = fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift);

		if (fos->snd_una == ack && !list_empty(&fos->pktlist)) {
			pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
			if (pkt->flags & TFO_PKT_FL_SENT &&
			    now > packet_timeout(pkt->ns, fos->rto_us) &&
			    !after(segend(pkt), win_end)) {
#ifdef DEBUG_ACK
				printf("Resending seq 0x%x due to repeat ack and timeout, now %lu, rto %u, pkt tmo %lu\n",
					ack, now, fos->rto_us, packet_timeout(pkt->ns, fos->rto_us));
#endif
#ifdef DEBUG_SEND_PKT_LOCATION
				printf("send_tcp_pkt F\n");
#endif
				send_tcp_pkt(w, list_first_entry(&fos->pktlist, typeof(*pkt), list), tx_bufs, fos, foos, false);
			}
		}
	}

	/* If we are no longer optimizing, then the ACK is the only thing we want
	 * to deal with. */
	if (ef->state == TCP_STATE_CLEAR_OPTIMIZE)
		return TFO_PKT_FORWARD;

// NOTE: RFC793 says SEQ + WIN should never be reduced - i.e. once a window is given
//  it will be able to be filled.
// BUT: RFC7323 2.4 says the window can be reduced (due to window scaling)

// This isn't right. dup_sack must be for seq, seq + seglen
// Can use dup_sack if segend(pkt) !after fos->rcv_nxt
// Also, if this duplicates SACK'd entries, we need seq, seq + seglen, then the SACK block for this
//   which we might already do
	if (using_rack(ef) && p->seglen && before(seq, fos->rcv_nxt)) {
		dup_sack[0] = seq;
		if (!after(seq + p->seglen, fos->rcv_nxt))
			dup_sack[1] = seq + p->seglen;
		else if (list_empty(&foos->pktlist) ||
			 after(list_first_entry(&foos->pktlist, struct tfo_pkt, list)->seq, fos->rcv_nxt))
			dup_sack[1] = fos->rcv_nxt;
		else {
			list_for_each_entry(pkt, &foos->pktlist, list) {
				if (!before(segend(pkt), seq + p->seglen)) {
					dup_sack[1] = seq + p->seglen;
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

	if (!seq_ok) {
		/* Packet is either bogus or duplicate */
#ifdef DEBUG_TCP_WINDOW
		printf("seq 0x%x len %u is outside rx window fos->rcv_nxt 0x%x -> 0x%x (+0x%x << %u)\n", seq, p->seglen, fos->rcv_nxt, win_end, fos->rcv_win, fos->rcv_win_shift);
#endif
		if (!after(seq + p->seglen, fos->rcv_nxt)) {
// This may want optimizing, and also think about SACKs
#ifdef DEBUG_RFC5681
			printf("Sending ack for duplicate seq 0x%x len 0x%x %s, orig_vlan %u\n",
				seq, p->seglen,
				seq + p->seglen == fos->rcv_nxt && ack_delayed(fos) ? "ack delayed" : "already ack'd",
				orig_vlan);
#endif

			_send_ack_pkt_in(w, ef, fos, p, orig_vlan, foos, dup_sack, tx_bufs, false);

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
			rte_pktmbuf_free(p->m);
_Pragma("GCC diagnostic pop")

			return TFO_PKT_HANDLED;
		}
// What does it mean to get here?
	} else {
		/* Check no data received after FIN */
		if (unlikely((fos->flags & TFO_SIDE_FL_FIN_RX) && !before(seq, fos->fin_seq)))
			ret = TFO_PKT_FORWARD;

#ifdef DEBUG_TCP_WINDOW
		if (!foos->rcv_win)
			printf("snd_win_updated %d foos rcv_win 0x%x rcv_nxt 0x%x fos snd_win 0x%x snd_win_shift 0x%x\n",
				snd_win_updated, foos->rcv_win, foos->rcv_nxt, fos->snd_win, fos->snd_win_shift);
#endif

		if (snd_win_updated &&
		    foos->rcv_win == 0 &&
		    before(foos->rcv_nxt, fos->snd_una + (fos->snd_win << fos->snd_win_shift))) {
			/* If the window is extended, (or at least not full),
			 * send an ack on foos */
			foos_send_ack = true;
		}

		if (seq != fos->rcv_nxt) {
			/* RFC5681 3.2 - fast recovery */
#ifdef DEBUG_RFC5681
			printf("Resending ack 0x%x due to out of sequence packet 0x%x\n", fos->rcv_nxt, seq);
#endif
			/* RFC5681 3.2 - out of sequence, or fills a gap */
			fos_must_ack = true;
		}

		/* If there is no gap before this packet, update rcv_nxt */
		if (!after(seq, fos->rcv_nxt) && after(seq + p->seglen, fos->rcv_nxt)) {
			if (p->tcp->tcp_flags & RTE_TCP_PSH_FLAG)
				fos_must_ack = true;
			else
				fos_send_ack = true;

			fos->rcv_nxt = seq + p->seglen;
			rcv_nxt_updated = true;
		}
	}

	if (seq_ok && p->seglen) {
		/* Queue the packet, and see if we can advance fos->rcv_nxt further */
		queued_pkt = queue_pkt(w, foos, p, seq, dup_sack, tx_bufs);
		fos_ack_from_queue = true;

// LOOK AT THIS ON PAPER TO WORK OUT WHAT IS HAPPENING
#ifdef HAVE_DUPLICATE_MBUF_BUG
		if (unlikely(queued_pkt == PKT_DUPLICATE_MBUF)) {
			/* We already have this mbuf queued, so we
			 * don't want to touch it or free it. */
			ret = TFO_PKT_HANDLED;
		} else
#endif
		if (unlikely(queued_pkt == PKT_IN_LIST)) {
			/* The packet has already been received */
			free_mbuf = true;
			ret = TFO_PKT_HANDLED;
		} else if (unlikely(queued_pkt == PKT_VLAN_ERR)) {
// We should split the packet and reduce receive MSS
			/* The Vlan header could not be added */
			clear_optimize(w, ef, tx_bufs);

			/* The packet can't be forwarded, so don't return TFO_PKT_FORWARD */
			ret = TFO_PKT_HANDLED;
		} else if (queued_pkt) {
			/* RFC5681 3.2 - filling all or part of a gap */
			if (!list_is_last(&queued_pkt->list, &foos->pktlist) ||
			    (!list_is_first(&queued_pkt->list, &foos->pktlist) &&
			     before(segend(list_prev_entry(queued_pkt, list)), queued_pkt->seq)))
				fos_must_ack = true;

			/* We have new data, update idle timeout */
			update_eflow_timeout(ef);

#ifdef DEBUG_SND_NXT
			printf("Queued packet m %p seq 0x%x, len %u, rcv_nxt_updated %d\n",
				queued_pkt->m, queued_pkt->seq, queued_pkt->seglen, rcv_nxt_updated);
#endif
		} else {
// This might confuse things later
			if (ef->state != TCP_STATE_CLEAR_OPTIMIZE)
				clear_optimize(w, ef, tx_bufs);

			ret = TFO_PKT_FORWARD;
		}

		if (likely(queued_pkt && queued_pkt != PKT_IN_LIST && queued_pkt != PKT_VLAN_ERR)) {
			if ((ef->flags & TFO_EF_FL_SACK))
				update_sack_for_seq(foos, queued_pkt, fos);

			if (rcv_nxt_updated) {
				nxt_exp = segend(queued_pkt);

				pkt = queued_pkt;
				list_for_each_entry_continue(pkt, &foos->pktlist, list) {
#ifdef DEBUG_SND_NXT
					printf("Checking pkt m %p, seq 0x%x, seglen %u, fos->rcv_nxt 0x%x\n",
						pkt->m, pkt->seq, pkt->seglen, fos->rcv_nxt);
#endif

					if (after(pkt->seq, nxt_exp))
						break;

					nxt_exp = segend(pkt);
					fos->rcv_nxt = nxt_exp;
				}
			} else {
				/* If !rcv_nxt_updated, we must have a missing packet, so resent ack */
				fos_must_ack = true;
			}
		}
	} else {
		/* It is probably an ACK with no data.
		 * What should we do if !seq_ok? */
		free_mbuf = true;
	}

	if (fos->rack_segs_sacked && p->seglen)
		fos_must_ack = true;

	if (!using_rack(ef)) {
// COMBINE THE NEXT TWO blocks
// What is limit of no of timeouted packets to send?
		/* Are there sent packets whose timeout has expired */
		if (!list_empty(&fos->pktlist)) {
			pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
// Sort out this check - first packet should never have been sack'd
			if (pkt->m &&
			    !after(segend(pkt), win_end) &&
			    packet_timeout(pkt->ns, fos->rto_us) < now) {
#ifdef DEBUG_RTO
				printf("Resending m %p pkt %p timeout pkt->ns %lu fos->rto_us %u now " NSEC_TIME_PRINT_FORMAT "\n",
					pkt->m, pkt, pkt->ns, fos->rto_us, NSEC_TIME_PRINT_PARAMS(now));
#endif

#ifdef DEBUG_SEND_PKT_LOCATION
				printf("send_tcp_pkt G\n");
#endif
				send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);
				fos->rto_us *= 2;		/* See RFC6928 5.5 */
				if (fos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC) {
#ifdef DEBUG_RTO
					printf("rto fos resend after timeout double %u - reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC);
#endif
					fos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;
				}
				fos_send_ack = false;
			}
		}

// This needs some optimization. ? keep a pointer to last pkt in window, which must be invalidated
		if (snd_win_updated || snd_wnd_increased) {
			new_win = get_snd_win_end(fos);

#ifdef DEBUG_SND_NXT
			printf("Considering packets to send, win 0x%x\n", new_win);
#endif

			list_for_each_entry(pkt, &fos->pktlist, list) {
#ifdef DEBUG_SND_NXT
				printf("pkt_seq 0x%x, seg_len 0x%x sent 0x%x\n", pkt->seq, pkt->seglen, pkt->flags & TFO_PKT_FL_SENT);
#endif

				if (after(segend(pkt), new_win))
					break;
				if (!(pkt->flags & TFO_PKT_FL_SENT) || (pkt->flags & TFO_PKT_FL_LOST)) {
#ifdef DEBUG_SND_NXT
					printf("snd_next 0x%x, fos->snd_nxt 0x%x\n", segend(pkt), fos->snd_nxt);
#endif

#ifdef DEBUG_SEND_PKT_LOCATION
					printf("send_tcp_pkt H\n");
#endif
					send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);
					fos_send_ack = false;
				}
			}
		}
	}

	/* Are there sent packets on other side whose timeout has expired */
	win_end = get_snd_win_end(foos);

	if (!using_rack(ef)) {
		if (!list_empty(&foos->pktlist)) {
			pkt = list_first_entry(&foos->pktlist, typeof(*pkt), list);

// Sort out this check - the first entry should never have been sack'd
			if (pkt->m &&
			    !after(segend(pkt), win_end)) {
				if (!(pkt->flags & TFO_PKT_FL_SENT)) {
#ifdef DEBUG_RTO
					printf("snd_next 0x%x, foos->snd_nxt 0x%x\n", segend(pkt), foos->snd_nxt);
#endif

#ifdef DEBUG_SEND_PKT_LOCATION
					printf("send_tcp_pkt I\n");
#endif
					send_tcp_pkt(w, pkt, tx_bufs, foos, fos, false);
				} else if (packet_timeout(pkt->ns, foos->rto_us) < now) {
#ifdef DEBUG_RTO
					printf("Resending packet %p on foos for timeout, pkt flags 0x%x ns %lu foos->rto %u now " NSEC_TIME_PRINT_FORMAT "\n",
						pkt->m, pkt->flags, pkt->ns, foos->rto_us, NSEC_TIME_PRINT_PARAMS(now));
#endif

#ifdef DEBUG_SEND_PKT_LOCATION
					printf("send_tcp_pkt J\n");
#endif
					send_tcp_pkt(w, pkt, tx_bufs, foos, fos, false);
					foos->rto_us *= 2;		/* See RFC6928 5.5 */

					if (foos->rto_us > TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC) {
#ifdef DEBUG_RTO
						printf("rto foos resend after timeout double %u - reducing to %u\n", foos->rto_us, TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC);
#endif
						foos->rto_us = TFO_TCP_RTO_MAX_MS * USEC_PER_MSEC;
					}
				}
			}
		}
	}

// This should only be the packet we have received
	/* Is there anything to send on other side? */

#ifdef DEBUG_TCP_WINDOW
	printf("win_end 0x%x rcv_nxt 0x%x, rcv_win 0x%x win_shift %u\n", win_end, foos->rcv_nxt, foos->rcv_win, foos->rcv_win_shift);
#endif

// Optimise this - ? point to last_sent ??
	list_for_each_entry(pkt, &foos->pktlist, list) {
#ifdef DEBUG_TCP_WINDOW
		if (pkt->tcp)
			printf("  pkt->seq 0x%x, flags 0x%x pkt->seglen %u tcp flags 0x%x foos->snd_nxt 0x%x\n",
				pkt->seq, pkt->flags, pkt->seglen, (unsigned)((pkt->tcp->data_off << 8) | pkt->tcp->tcp_flags) & 0xfff, foos->snd_nxt);
#endif

		if (after(segend(pkt), win_end))
			break;
		if (!(pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_QUEUED_SEND))) {
			snd_nxt = segend(pkt);
			if (after(snd_nxt, foos->snd_nxt)) {
#ifdef DEBUG_TCP_WINDOW
				printf("Sending queued packet %p, updating foos->snd_nxt from 0x%x to 0x%x\n",
					pkt->m, foos->snd_nxt, snd_nxt);
#endif
				foos->snd_nxt = snd_nxt;
			}
#ifdef DEBUG_TCP_WINDOW
			else
				printf("Sending queued packet %p, not updating foos->snd_nxt from 0x%x to 0x%x\n",
					pkt->m, foos->snd_nxt, snd_nxt);
#endif

#ifdef DEBUG_SEND_PKT_LOCATION
			printf("send_tcp_pkt K\n");
#endif
			send_tcp_pkt(w, pkt, tx_bufs, foos, fos, false);
		}
	}

#ifdef DEBUG_ACK
	printf("ACK status: fos_send_ack %d fos_must_ack %d fos_ack_from_queue %d foos_send_ack %d\n", fos_send_ack, fos_must_ack, fos_ack_from_queue, foos_send_ack);
#endif

	if (fos_send_ack || fos_must_ack) {
		if (fos_ack_from_queue) {
			struct tfo_pkt unq_pkt;
			struct tfo_pkt *pkt_in = queued_pkt;
			if (!queued_pkt || queued_pkt == PKT_IN_LIST || queued_pkt == PKT_VLAN_ERR) {
				pkt_in = &unq_pkt;
				unq_pkt.iph = p->iph;
				unq_pkt.tcp = p->tcp;
				unq_pkt.m = p->m;
				unq_pkt.flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
			}

			_send_ack_pkt(w, ef, fos, pkt_in, NULL, orig_vlan, foos, dup_sack, tx_bufs, false, fos_must_ack, false, false);
		} else
			_send_ack_pkt_in(w, ef, fos, p, orig_vlan, foos, dup_sack, tx_bufs, false);
	}

	if (foos_send_ack)
		_send_ack_pkt_in(w, ef, foos, p, p->from_priv ? pub_vlan_tci : priv_vlan_tci, fos, NULL, tx_bufs, true);

	if (list_empty(&fos->pktlist))
		tfo_cancel_xmit_timer(fos);

	if (unlikely(free_mbuf)) {
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		rte_pktmbuf_free(p->m);
_Pragma("GCC diagnostic pop")
		p->m = NULL;
	}

	return ret;
}

static inline void
set_estb_pkt_counts(struct tcp_worker *w,  uint8_t flags)
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
tfo_tcp_sm(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	uint8_t tcp_flags = p->tcp->tcp_flags;
	struct tfo_side *server_fo, *client_fo;
	uint32_t ack;
	struct tfo *fo;
	enum tfo_pkt_state ret = TFO_PKT_FORWARD;
	struct tfo_pkt *queued_pkt;

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
	printf("State %u, tcp flags 0x%x, flow flags 0x%x, seq 0x%x, ack 0x%lx, data_len 0x%lx\n", ef->state, tcp_flags, ef->flags,
		rte_be_to_cpu_32(p->tcp->sent_seq), ((tcp_flags | RTE_TCP_ACK_FLAG) ? 0UL : 0xffff00000000UL) + rte_be_to_cpu_32(p->tcp->recv_ack),
		(unsigned long)(rte_pktmbuf_mtod(p->m, uint8_t *) + p->m->pkt_len - ((uint8_t *)p->tcp + (p->tcp->data_off >> 2))));
#endif

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
		{	   &&syn_ack,	    &&dup_syn_ack,	    &&dup_syn_ack,	    &&sup_syn_ack },	// ACK, SYN
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
		{   &&syn_syn_no_ack,		 &&no_ack,		 &&no_ack,		 &&no_ack },	// SYN
//				     &&syn_ack_syn_no_ack,	 &&est_syn_no_ack,
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
	clear_optimize(w, ef, tx_bufs);
	return TFO_PKT_FORWARD;

reset:
	/* reset flag, stop everything */
	/* We don't need to ensure that queued packets that we have ack'd on other
	 * side are ack'd to us first before forwarding RST since RFC793 states:
	 *    All segment queues should be flushed.
	 */
	++w->st.rst_pkt;
	_eflow_free(w, ef, tx_bufs);

#ifdef DEBUG_RST
	printf("Received RST for eflow %p\n", ef);
#endif

	return TFO_PKT_FORWARD;

process_pkt:
	set_estb_pkt_counts(w, tcp_flags);

	ret = tfo_handle_pkt(w, p, ef, tx_bufs);

// BUG - ef may no longer be valid
	if (ef->flags & TFO_EF_FL_CLOSED)
		_eflow_free(w, ef, tx_bufs);
	else
		update_timer_ef(ef);

	return ret;

#if 0
#ifdef DEBUG_CHECK_ADDR
	printf("ef->state %u tcp_flags 0x%x p->tcp %p p->tcp->tcp_flags 0x%x ret %u\n", ef->state, tcp_flags, p->tcp, p->tcp->tcp_flags, ret);
#endif

	if (unlikely(ef->state == TCP_STATE_CLEAR_OPTIMIZE)) {
		fo = &w->f[ef->tfo_idx];
		if (list_empty(&fo->priv.pktlist) &&
		    list_empty(&fo->pub.pktlist)) {
			/* The pkt queues are now empty. */
			_eflow_free(w, ef, tx_bufs);
		}

		return TFO_PKT_FORWARD;
	}
#endif

no_ack:
	/* A duplicate SYN could have no ACK, otherwise it is an error */
	++w->st.estb_noflag_pkt;
	clear_optimize(w, ef, tx_bufs);

	return ret;

// Assume SYN and FIN packets can contain data - see last para p26 of RFC793,
//   i.e. before sequence number selection

syn_fin:
// Should only have ACK, ECE (and ? PSH, URG)
// We should delay forwarding RST until have received ACK for all data we have ACK'd - or not as the case may be
	clear_optimize(w, ef, tx_bufs);
	++w->st.syn_bad_flag_pkt;
	return ret;

syn_ack_syn_ack:
	/* duplicate syn+ack */
	++w->st.syn_ack_dup_pkt;
	ef->flags |= TFO_EF_FL_DUPLICATE_SYN;
	return ret;

#ifdef INCLUDE_UNUSED_CODE
syn_ack_syn_no_ack:	// Unused
#endif
est_syn_ack:
	++w->st.syn_ack_on_eflow_pkt;
	clear_optimize(w, ef, tx_bufs);
	return ret;

#ifdef INCLUDE_UNUSED_CODE
est_syn_no_ack:		// Unused
	++w->st.syn_on_eflow_pkt;
	clear_optimize(w, ef, tx_bufs);
	return ret;
#endif

syn_syn_no_ack:
	if (!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) == !!p->from_priv) {
		/* duplicate of first syn */
		++w->st.syn_dup_pkt;
		ef->flags |= TFO_EF_FL_DUPLICATE_SYN;
// If SEQs don't match send RST - see RFC793
	} else if (!(ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN)) {
		/* simultaneous open, let it go */
		++w->st.syn_simlt_open_pkt;
		ef->flags |= TFO_EF_FL_SIMULTANEOUS_OPEN;
	}
	return ret;

syn_syn_ack:
	if (unlikely(ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN)) {
		/* syn+ack from one side, too complex, don't optimize */
// See RFC793 Figure 8. Only worth supporting if easy
		_eflow_set_state(w, ef, TCP_STATE_SYN_ACK);
// When allow this, look at normal code for going to SYN_ACK
clear_optimize(w, ef, tx_bufs);
ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
		++w->st.syn_ack_pkt;

		return ret;
	}

	if (likely(!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) != !!p->from_priv)) {
		/* syn+ack from other side */
		ack = rte_be_to_cpu_32(p->tcp->recv_ack);
		if (unlikely(!between_beg_ex(ack, ef->server_snd_una, ef->client_rcv_nxt))) {
#ifdef DEBUG_SM
			printf("SYN seq does not match SYN+ACK recv_ack, snd_una %x ack %x client_rcv_nxt %x\n", ef->server_snd_una, ack, ef->client_rcv_nxt);
#endif

			clear_optimize(w, ef, tx_bufs);
			++w->st.syn_bad_pkt;
			return ret;
		}

		if (!set_tcp_options(p, ef)) {
			clear_optimize(w, ef, tx_bufs);
			++w->st.syn_bad_pkt;
			return ret;
		}

		++w->st.syn_ack_pkt;
		_eflow_set_state(w, ef, TCP_STATE_SYN_ACK);
		if (check_do_optimize(w, p, ef)) {
// Do initial RTT if none for user, otherwise ignore due to additional time for connection establishment
// RTT is per user on private side, per flow on public side
			fo = &w->f[ef->tfo_idx];
			if (p->from_priv) {
				server_fo = &fo->priv;
				client_fo = &fo->pub;
			} else {
				server_fo = &fo->pub;
				client_fo = &fo->priv;
			}

uint16_t orig_vlan;
			orig_vlan = update_vlan(p);

			queued_pkt = queue_pkt(w, client_fo, p, client_fo->snd_una, false, tx_bufs);
#ifdef HAVE_DUPLICATE_MBUF_BUG
			if (likely(queued_pkt != PKT_DUPLICATE_MBUF))
#endif
			send_tcp_pkt(w, queued_pkt, tx_bufs, client_fo, server_fo, false);

			/* We ACK the SYN+ACK to speed up startup */
// _send_ack_pkt(w, ef, server_fo, &queued_pkt, NULL, orig_vlan, client_fo, false, tx_bufs, false, true, false, false);
			_send_ack_pkt_in(w, ef, server_fo, p, orig_vlan, client_fo, NULL, tx_bufs, false);

			update_timer_ef(ef);

			return TFO_PKT_HANDLED;
		}

		return TFO_PKT_FORWARD;
	}
// Could be duplicate SYN+ACK
	/* bad sequence, won't optimize */
	clear_optimize(w, ef, tx_bufs);
	++w->st.syn_ack_bad_pkt;

	return TFO_PKT_FORWARD;

#ifdef INCLUDE_UNUSED_CODE
syn_other:	// Unused
	/* we're in fin, rst, or bad state */
	++w->st.syn_bad_state_pkt;
	return ret;

est_fin:	// Unused
	return ret;
#endif

other_fin:
	clear_optimize(w, ef, tx_bufs);
	++w->st.fin_unexpected_pkt;

	return ret;

syn_ack_ack:
	if (!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) == !!p->from_priv) {
		// Note: when tfo_handle_pkt acks the SYN+ACK, the timestamp
		// will be the same as in the original SYN. This should not be
		// a problem since the timestamps we send should not be interpreted
		// by the remote end. tfo_handle_pkt could increment the TSval by
		// 1 if it wants. Clock rates can be as low as 1Hz, so better not
		// increment until we know.
		ret = tfo_handle_pkt(w, p, ef, tx_bufs);
		if (ret == TFO_PKT_HANDLED) {
// We should do the following in handle_pkt - PKT_HANDLED is insufficient
			_eflow_set_state(w, ef, TCP_STATE_ESTABLISHED);

			fo = &w->f[ef->tfo_idx];
			(p->from_priv ? &fo->priv : &fo->pub)->flags |= TFO_SIDE_FL_RTT_FROM_SYN;

			update_timer_ef(ef);
		}

		return ret;
	}

syn_ack:
	++w->st.syn_state_pkt;
	_eflow_free(w, ef, tx_bufs);

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
tfo_mbuf_in_v4(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_eflow *ef;
	in_addr_t priv_addr, pub_addr;
	uint16_t priv_port, pub_port;
	uint32_t h;

	/* capture input tcp packet */
	if (config->capture_input_packet)
		config->capture_input_packet(w->param, IPPROTO_IP, p->m, &w->ts, p->from_priv, p->iph);

	if (!tcp_header_complete(p->m, p->tcp))
		return TFO_PKT_INVALID;

	p->seglen = p->m->pkt_len - ((uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *))
				- ((p->tcp->data_off & 0xf0) >> 2)
				+ !!(p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

#ifdef DEBUG_PKT_RX
	printf("pkt_len %u tcp %p tcp_offs %ld, tcp_len %u, mtod %p, seg_len %u tcp_flags 0x%x\n",
		p->m->pkt_len, p->tcp, (uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *),
		(p->tcp->data_off & 0xf0U) >> 2, rte_pktmbuf_mtod(p->m, uint8_t *), p->seglen, p->tcp->tcp_flags);
#endif

// PQA - use in_addr, out_addr, in_port, out_port, and don't check p->from_priv
// PQA - don't call rte_be_to_cpu_32 etc. Do everything in network order
	/* get/create flow */
	if (likely(p->from_priv)) {
		priv_addr = rte_be_to_cpu_32(p->iph.ip4h->src_addr);
		pub_addr = rte_be_to_cpu_32(p->iph.ip4h->dst_addr);
		priv_port = rte_be_to_cpu_16(p->tcp->src_port);
		pub_port = rte_be_to_cpu_16(p->tcp->dst_port);
	} else {
		priv_addr = rte_be_to_cpu_32(p->iph.ip4h->dst_addr);
		pub_addr = rte_be_to_cpu_32(p->iph.ip4h->src_addr);
		priv_port = rte_be_to_cpu_16(p->tcp->dst_port);
		pub_port = rte_be_to_cpu_16(p->tcp->src_port);
	}

// PQA - add p->from_priv check here
// ? two stage hash. priv_addr/port
	h = tfo_eflow_v4_hash(config, priv_addr, priv_port, pub_addr, pub_port);
	ef = tfo_eflow_v4_lookup(w, priv_addr, priv_port, pub_addr, pub_port, h);
#ifdef DEBUG_FLOW
	printf("h = %u, ef = %p\n", h, ef);
#endif

	if (unlikely(!ef)) {
		/* ECE and CWR can be set. Don't know about URG, PSH or NS yet */
		if ((p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
			/* This is not a new flow  - it might have existed before we started */
			return TFO_PKT_FORWARD;
		}

#ifdef DEBUG_SM
		printf("Received SYN, flags 0x%x, send_seq 0x%x seglen %u rx_win %hu\n",
			p->tcp->tcp_flags, rte_be_to_cpu_32(p->tcp->sent_seq), p->seglen, rte_be_to_cpu_16(p->tcp->rx_win));
#endif

		ef = _eflow_alloc(w, h);
		if (!ef)
			return TFO_PKT_NO_RESOURCE;
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v4.s_addr = pub_addr;
		ef->priv_addr.v4.s_addr = priv_addr;

		if (!set_tcp_options(p, ef)) {
			_eflow_free(w, ef, tx_bufs);
			++w->st.syn_bad_pkt;
			return TFO_PKT_FORWARD;
		}

		ef->win_shift = p->win_shift;
		ef->server_snd_una = rte_be_to_cpu_32(p->tcp->sent_seq);
		ef->client_rcv_nxt = ef->server_snd_una + p->seglen;
		ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
		ef->client_mss = p->mss_opt;
		ef->client_ttl = p->iph.ip4h->time_to_live;
		ef->client_packet_type = p->m->packet_type;
#ifdef CALC_USERS_TS_CLOCK
		ef->start_time = now;
#endif
		if (p->from_priv)
			ef->flags |= TFO_EF_FL_SYN_FROM_PRIV;

		/* Add a timer to the timer queue */
		update_eflow_timeout(ef);
		ef->timer.time = ef->idle_timeout;

		rb_add_cached(&ef->timer.node, &timer_tree, timer_less);

		++w->st.syn_pkt;

		return TFO_PKT_FORWARD;
	}

	return tfo_tcp_sm(w, p, ef, tx_bufs);
}

static enum tfo_pkt_state
tfo_mbuf_in_v6(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_eflow *ef;
	struct in6_addr *priv_addr, *pub_addr;
	uint16_t priv_port, pub_port;
	uint32_t h;

	/* capture input tcp packet */
	if (config->capture_input_packet)
		config->capture_input_packet(w->param, IPPROTO_IPV6, p->m, &w->ts, p->from_priv, p->iph);

	if (!tcp_header_complete(p->m, p->tcp))
		return TFO_PKT_INVALID;

	p->seglen = p->m->pkt_len - ((uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *))
				- ((p->tcp->data_off & 0xf0) >> 2)
				+ !!(p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

#ifdef DEBUG_PKT_RX
	printf("pkt_len %u tcp %p tcp_offs %ld, tcp_len %u, mtod %p, seg_len %u tcp_flags 0x%x\n",
		p->m->pkt_len, p->tcp, (uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *),
		(p->tcp->data_off & 0xf0U) >> 2, rte_pktmbuf_mtod(p->m, uint8_t *), p->seglen, p->tcp->tcp_flags);
#endif

// PQA - use in_addr, out_addr, in_port, out_port, and don't check p->from_priv
// PQA - don't call rte_be_to_cpu_32 etc. Do everything in network order
	/* get/create flow */
	if (likely(p->from_priv)) {
		priv_addr = (struct in6_addr *)p->iph.ip6h->src_addr;
		pub_addr = (struct in6_addr *)p->iph.ip6h->dst_addr;
		priv_port = rte_be_to_cpu_16(p->tcp->src_port);
		pub_port = rte_be_to_cpu_16(p->tcp->dst_port);
	} else {
		priv_addr = (struct in6_addr *)p->iph.ip6h->dst_addr;
		pub_addr = (struct in6_addr *)p->iph.ip6h->src_addr;
		priv_port = rte_be_to_cpu_16(p->tcp->dst_port);
		pub_port = rte_be_to_cpu_16(p->tcp->src_port);
	}

// PQA - add p->from_priv check here
// ? two stage hash. priv_addr/port
	h = tfo_eflow_v6_hash(config, priv_addr, priv_port, pub_addr, pub_port);
	ef = tfo_eflow_v6_lookup(w, priv_addr, priv_port, pub_addr, pub_port, h);
#ifdef DEBUG_FLOW
	printf("h = %u, ef = %p\n", h, ef);
#endif

	if (unlikely(ef == NULL)) {
		/* ECN and CWR can be set. Don't know about URG, PSH or NS yet */
		if ((p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
			/* This is not a new flow  - it might have existed before we started */
			return TFO_PKT_FORWARD;
		}

#ifdef DEBUG_SM
		printf("Received SYN, flags 0x%x, send_seq 0x%x seglen %u rx_win %hu\n",
			p->tcp->tcp_flags, rte_be_to_cpu_32(p->tcp->sent_seq), p->seglen, rte_be_to_cpu_16(p->tcp->rx_win));
#endif

		ef = _eflow_alloc(w, h);
		if (!ef)
			return TFO_PKT_NO_RESOURCE;
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v6 = *pub_addr;
		ef->priv_addr.v6 = *priv_addr;
		ef->flags |= TFO_EF_FL_IPV6;

		if (!set_tcp_options(p, ef)) {
			_eflow_free(w, ef, tx_bufs);
			++w->st.syn_bad_pkt;
			return TFO_PKT_FORWARD;
		}

		ef->win_shift = p->win_shift;
		ef->server_snd_una = rte_be_to_cpu_32(p->tcp->sent_seq);
		ef->client_rcv_nxt = ef->server_snd_una + p->seglen;
		ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
		ef->client_mss = p->mss_opt;
		ef->client_ttl = p->iph.ip6h->hop_limits;
		ef->client_packet_type = p->m->packet_type;
		ef->client_vtc_flow = p->iph.ip6h->vtc_flow;
#ifdef CALC_USERS_TS_CLOCK
		ef->start_time = now;
#endif
		if (p->from_priv)
			ef->flags |= TFO_EF_FL_SYN_FROM_PRIV;

		/* Add a timer to the timer queue */
		update_eflow_timeout(ef);
		ef->timer.time = ef->idle_timeout;

		rb_add_cached(&ef->timer.node, &timer_tree, timer_less);

		++w->st.syn_pkt;

		return TFO_PKT_FORWARD;
	}

	return tfo_tcp_sm(w, p, ef, tx_bufs);
}

// Do IPv4 defragmentation - see https://packetpushers.net/ip-fragmentation-in-detail/

static int
tcp_worker_mbuf_pkt(struct tcp_worker *w, struct rte_mbuf *m, int from_priv, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt_in pkt;
	int16_t proto;
	uint32_t hdr_len;
	uint32_t off;
	int frag;
	uint16_t vlan_tci;
	struct rte_vlan_hdr *vl;


	pkt.m = m;

#ifdef DEBUG_DUPLICATE_MBUFS
	if (check_mbuf_in_use(m, w, tx_bufs))
		printf("Received mbuf %p already in use\n", m);
#endif

	/* Ensure the private area is initialised */
	get_priv_addr(m)->pkt = NULL;

// Should we set these?
	pkt.tv.tv_sec = 0;
	pkt.tv.tv_usec = 0;
	pkt.from_priv = from_priv;
	pkt.sack_opt = NULL;
	pkt.ts_opt = NULL;
	pkt.mss_opt = 0;

#ifdef DEBUG_PKT_TYPES
	char ptype[128];
	rte_get_ptype_name(m->packet_type, ptype, sizeof(ptype));
	printf("\nReceived m %p %s from %s, length %u (%u), vlan %u", m, ptype, from_priv ? "priv" : "pub", m->pkt_len, m->data_len, m->vlan_tci);
#endif

	/* skip ethernet + vlan(s) */
	switch (m->packet_type & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER:
		hdr_len = sizeof (struct rte_ether_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_VLAN:
		hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
			vl = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, sizeof(struct rte_ether_hdr));
			vlan_tci = rte_be_to_cpu_16(vl->vlan_tci);
#ifdef DEBUG_VLAN_TCI
			if (m->vlan_tci && m->vlan_tci != vlan_tci)
				printf("vlan id mismatch - m %u pkt %u\n", m->vlan_tci, vlan_tci);
#endif
			m->vlan_tci = vlan_tci;
		}
		break;
	case RTE_PTYPE_L2_ETHER_QINQ:
		hdr_len = sizeof (struct rte_ether_hdr) + 2 * sizeof (struct rte_vlan_hdr);
		break;
	default:
		/* It might be tunnelled TCP */
		return TFO_PKT_NOT_TCP;
	}

#ifdef DEBUG_PKT_TYPES
	if (m->vlan_tci)
		printf(" set to %u\n", m->vlan_tci);
	else
		printf("\n");
#endif

	/* The following works for IPv6 too */
	pkt.iph.ip4h = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdr_len);
	pkt.pktlen = m->pkt_len - hdr_len;

	switch (m->packet_type & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));

		/* A minimum ethernet + IPv4 + TCP packet with no options or data
		 * is 54 bytes; we will be given a pkt_len of 60 */
		if (m->pkt_len > rte_be_to_cpu_16(pkt.iph.ip4h->total_length) + hdr_len)
			rte_pktmbuf_trim(m, m->pkt_len - (rte_be_to_cpu_16(pkt.iph.ip4h->total_length) + hdr_len));

		return tfo_mbuf_in_v4(w, &pkt, tx_bufs);

	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(pkt.iph.ip4h));

		/* A minimum ethernet + IPv4 + TCP packet with no options or data
		 * is 54 bytes; we will be given a pkt_len of 60 */
		if (m->pkt_len > rte_be_to_cpu_16(pkt.iph.ip4h->total_length) + hdr_len)
			rte_pktmbuf_trim(m, m->pkt_len - (rte_be_to_cpu_16(pkt.iph.ip4h->total_length) + hdr_len));

		return tfo_mbuf_in_v4(w, &pkt, tx_bufs);

	case RTE_PTYPE_L3_IPV6:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv6_hdr));

		return tfo_mbuf_in_v6(w, &pkt, tx_bufs);

	case RTE_PTYPE_L3_IPV6_EXT:
	case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
		off = hdr_len;
		proto = rte_net_skip_ip6_ext(pkt.iph.ip6h->proto, m, &off, &frag);
		if (unlikely(proto < 0))
			return TFO_PKT_INVALID;
		if (proto != IPPROTO_TCP)
			return TFO_PKT_NOT_TCP;

		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + off);
		return tfo_mbuf_in_v6(w, &pkt, tx_bufs);

	default:
		/* It is not IPv4/6 */
// ARP?
		return TFO_PKT_INVALID;
	}
}

void
tfo_packet_no_room_for_vlan(__attribute__((unused)) struct rte_mbuf *m)
{
	/* The packet cannot be sent, remove it, turn off optimization */
}

static void
postprocess_sent_packets(struct tfo_tx_bufs *tx_bufs, uint16_t nb_tx)
{
	struct tfo_mbuf_priv *priv;
	struct tfo_side *fos;
	struct tfo_pkt *pkt;
#ifdef DEBUG_LAST_SENT
	struct tfo_pkt *lost_pkt;
#endif
	struct list_head *last_sent_pkt;
	uint16_t buf;

	for (buf = 0; buf < nb_tx; buf++) {
		/* We don't do anything with ACKs */
		if (ack_bit_is_set(tx_bufs, buf))
			continue;

		priv = get_priv_addr(tx_bufs->m[buf]);
		if (!(pkt = priv->pkt)) {
#ifdef DEBUG_POSTPROCESS
			printf("*** pkt %p priv %p priv->pkt %p\n", pkt, priv, priv->pkt);
#endif
			continue;
		}

		fos = priv->fos;
		fos->pkts_queued_send--;

		if (pkt->flags & TFO_PKT_FL_SENT) {
			pkt->flags |= TFO_PKT_FL_RESENT;
			if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
				/* Abort RTT calculation */
				fos->flags &= ~TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
				pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
			}

			if (pkt->flags & TFO_PKT_FL_LOST) {
				fos->pkts_in_flight++;
#if defined DEBUG_POSTPROCESS || defined DEBUG_IN_FLIGHT
				printf("postprocess seq 0x%x incrementing pkts_in_flight to %u for lost pkt\n", pkt->seq, fos->pkts_in_flight);
#endif
			}
		} else {
// update foos snd_nxt
			pkt->flags |= TFO_PKT_FL_SENT;
			fos->pkts_in_flight++;
#if defined DEBUG_POSTPROCESS || defined DEBUG_IN_FLIGHT
			printf("postprocess(0x%x) pkts_in_flight incremented to %u\n", pkt->seq, fos->pkts_in_flight);
#endif

			/* If not using timestamps and no RTT calculation in progress,
			 * start one, but we don't calculate RTT from a resent packet */
			if (!pkt->ts && !(fos->flags & TFO_SIDE_FL_RTT_CALC_IN_PROGRESS)) {
				fos->flags |= TFO_SIDE_FL_RTT_CALC_IN_PROGRESS;
				pkt->flags |= TFO_PKT_FL_RTT_CALC;
			}
		}

#ifdef DEBUG_LAST_SENT
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
			printf("ERROR - last sent 0x%x, last sent found 0x%x\n",
					list_is_head(fos->last_sent, &fos->xmit_ts_list) ? 0U : list_entry(fos->last_sent, struct tfo_pkt, xmit_ts_list)->seq,
					list_is_head(last_sent_pkt, &fos->xmit_ts_list) ? 0U : list_entry(last_sent_pkt, struct tfo_pkt, xmit_ts_list)->seq);
			dump_details(&worker);
		}
#endif

		last_sent_pkt = fos->last_sent;

		/* RFC 8985 6.1 for LOST */
		pkt->flags &= ~(TFO_PKT_FL_LOST | TFO_PKT_FL_QUEUED_SEND);

		/* This makes sure the packets are timestamped sequentially. This means that if packets
		 * are sent out of order in the same burst, and rack_reo_wnd is 0 we won't
		 * unnecessarily trigger marking a packet lost. */
		pkt->ns = now - nb_tx + buf;

		/* RFC8985 to make step 2 faster */
if (before(pkt->seq, fos->snd_una))
	printf("postprocess ERROR pkt->seq 0x%x before fos->snd_una 0x%x, xmit_ts_list %p:%p\n", pkt->seq, fos->snd_una, pkt->xmit_ts_list.prev, pkt->xmit_ts_list.next);

		/* Add the packet after the last sent packet not lost */
		if (list_is_queued(&pkt->xmit_ts_list)) {
			if (last_sent_pkt != &pkt->xmit_ts_list)
				list_move(&pkt->xmit_ts_list, last_sent_pkt);
		} else
			list_add(&pkt->xmit_ts_list, last_sent_pkt);

		fos->last_sent = &pkt->xmit_ts_list;

		if (after(segend(pkt), fos->snd_nxt))
			fos->snd_nxt = segend(pkt);
	}
}

static void
tfo_packets_not_sent(struct tfo_tx_bufs *tx_bufs, uint16_t nb_tx) {
	struct tfo_mbuf_priv *priv;
	struct tfo_pkt *pkt;

	for (uint16_t buf = nb_tx; buf < tx_bufs->nb_tx; buf++) {
#ifdef DEBUG_TIMERS
		printf("\tm %p not sent\n", tx_bufs->m[buf]);
#endif
		if (ack_bit_is_set(tx_bufs, buf))
			rte_pktmbuf_free(tx_bufs->m[buf]);
		else {
			rte_pktmbuf_refcnt_update(tx_bufs->m[buf], -1);
			priv = get_priv_addr(tx_bufs->m[buf]);
			pkt = priv->pkt;
#ifdef DEBUG_SEND_BURST_ERRORS
			if (!pkt)
				printf("*** tfo_packets_not_sent pkt NULL, priv %p priv->fos %p nb_tx %u tx_bufs->nb_tx %u\n", priv, priv->fos, nb_tx, tx_bufs->nb_tx); else
#endif
			pkt->flags &= ~TFO_PKT_FL_QUEUED_SEND;
			priv->fos->pkts_queued_send--;
			list_add_tail(&pkt->send_failed_list, &send_failed_list);
		}
	}
}

/* Called by the app if it sends the packets itself */
bool
tfo_post_send(struct tfo_tx_bufs *tx_bufs, uint16_t nb_tx)
{
	postprocess_sent_packets(tx_bufs, nb_tx);
	if (unlikely(nb_tx < tx_bufs->nb_tx)) {
#ifdef DEBUG_SEND_BURST_NOT_SENT
		printf("tx_burst %u packets sent %u packets\n", tx_bufs->nb_tx, nb_tx);
#endif
		tfo_packets_not_sent(tx_bufs, nb_tx);
	}

	return !list_empty(&send_failed_list);
}

#ifdef DEBUG_PACKET_POOL
static inline struct rte_tcp_hdr *
find_tcp(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4;
	uint16_t hdr_len = sizeof(struct rte_ether_hdr);

	switch (m->packet_type & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER:
		hdr_len = sizeof (struct rte_ether_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_VLAN:
		hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
		break;
	}
	ipv4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdr_len);
	switch (m->packet_type & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
		return rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));
	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		return rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(ipv4));
	}

	return NULL;
}
#endif

static inline void
tfo_send_burst(struct tfo_tx_bufs *tx_bufs)
{
	uint16_t nb_tx;

#ifdef DEBUG_SEND_BURST_ERRORS
	for (unsigned i = 0; i < tx_bufs->nb_tx; i++) {
		struct tfo_mbuf_priv *priv;

		if (!ack_bit_is_set(tx_bufs, i)) {
			priv = get_priv_addr(tx_bufs->m[i]);
			if (!priv->fos || !priv->pkt)
				printf("*** send_burst non-ack m %p %u priv->fos %p ->pkt %p\n", tx_bufs->m[i], i, priv->fos, priv->pkt);
		}
	}
#endif

	if (tx_bufs->nb_tx) {
#ifdef WRITE_PCAP
		if (save_pcap)
			write_pcap(tx_bufs->m, tx_bufs->nb_tx, RTE_PCAPNG_DIRECTION_OUT);
#endif

#if defined DEBUG_SEND_BURST_ERRORS || defined DEBUG_SEND_BURST
#ifdef DEBUG_SEND_BURST
		printf("Sending %u packets:\n", tx_bufs->nb_tx);
#endif

		for (int i = 0; i < tx_bufs->nb_tx; i++) {
			bool ack_error = !ack_bit_is_set(tx_bufs, i) == !strncmp("ack_pool_", tx_bufs->m[i]->pool->name, 9);
#ifdef DEBUG_PACKET_POOL
#ifdef DEBUG_SEND_BURST_ERRORS
			if (ack_error)
#endif
			{
				struct rte_tcp_hdr *tcp = find_tcp(tx_bufs->m[i]);

				if (!tcp || !(tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_RST_FLAG)))
					printf("\t%3.3d: %p - tcp_flags 0x%x ack 0x%x pool %s%s", i, tx_bufs->m[i], tcp->tcp_flags, tx_bufs->acks[i / CHAR_BIT] & (1U << (i % CHAR_BIT)), tx_bufs->m[i]->pool->name, ack_error ? " *** ACK FLAG mismatch pool" : "");
			}
#endif
#ifdef DEBUG_SEND_BURST_ERRORS
			if (!ack_bit_is_set(tx_bufs, i)) {
				struct tfo_mbuf_priv *priv;
				priv = get_priv_addr(tx_bufs->m[i]);
				if (!priv->fos || !priv->pkt)
					printf(" fos %p pkt %p refcnt %u %s\n", priv->fos, priv->pkt, rte_mbuf_refcnt_read(tx_bufs->m[i]), !priv->fos || !priv->pkt ? " ***" : "");
			} else if (ack_error)
				printf("\n");
#endif
#ifdef DEBUG_PACKET_POOL
			printf("\t%3.3d: m %p pool %s ack %s refcnt %u\n", i, tx_bufs->m[i], tx_bufs->m[i]->pool->name, tx_bufs->acks[i / CHAR_BIT] & (1U << (i % CHAR_BIT)) ? "ack" : "data", tx_bufs->m[i]->refcnt);
#endif
		}
#endif

		/* send the burst of TX packets. */
		nb_tx = config->tx_burst(port_id, queue_idx, tx_bufs->m, tx_bufs->nb_tx);

#ifdef DEBUG_SEND_BURST_NOT_SENT
		if (nb_tx != tx_bufs->nb_tx)
			printf("Only sent %u of %u packets\n", nb_tx, tx_bufs->nb_tx);
#endif

#if defined DEBUG_SEND_BURST || defined DEBUG_SEND_BURST_ERRORS
#ifdef DEBUG_SEND_BURST
		printf("After sending packets, nb_tx %u:\n", nb_tx);
#endif
		for (int i = 0; i < tx_bufs->nb_tx; i++) {
#ifdef DEBUG_SEND_BURST
			printf("\t%3.3d: %p - ack 0x%x", i, tx_bufs->m[i], tx_bufs->acks[i / CHAR_BIT] & (1U << (i % CHAR_BIT)));
#endif
			if (!ack_bit_is_set(tx_bufs, i)) {
				struct tfo_mbuf_priv *priv;
				priv = get_priv_addr(tx_bufs->m[i]);
				if (!priv->fos || !priv->pkt) {
#ifndef DEBUG_SEND_BURST
					printf("\t%3.3d: %p - ack 0x%x", i, tx_bufs->m[i], tx_bufs->acks[i / CHAR_BIT] & (1U << (i % CHAR_BIT)));
#endif
					printf(" priv->fos %p ->pkt %p ***\n", priv->fos, priv->pkt);
				}
#ifdef DEBUG_SEND_BURST
				else
					printf("\n");
#endif
			}
#ifdef DEBUG_SEND_BURST
			else
				printf("\n");
#endif
		}
#endif

		postprocess_sent_packets(tx_bufs, nb_tx);

		/* Mark any unsent packets as not having been sent. */
		if (unlikely(nb_tx < tx_bufs->nb_tx)) {
#ifdef DEBUG_TIMERS
			printf("tx_burst %u packets sent %u packets ***\n", tx_bufs->nb_tx, nb_tx);
#else
			printf("tx_burst %u packets sent %u packets ***\n", tx_bufs->nb_tx, nb_tx);
#endif

			tfo_packets_not_sent(tx_bufs, nb_tx);
		}

#ifdef DEBUG_STRUCTURES
		printf("After packets sent:\n");
		dump_details(&worker);
#endif
	}

	if (tx_bufs->m) {
		rte_free(tx_bufs->m);
		rte_free(tx_bufs->acks);
	}
}

struct tfo_tx_bufs *
tcp_worker_mbuf_burst(struct rte_mbuf **rx_buf, uint16_t nb_rx, struct timespec *ts, struct tfo_tx_bufs *tx_bufs)
{
	uint16_t i;
	struct tcp_worker *w = &worker;
	int ret = -1;
	struct timespec ts_local;
	struct rte_mbuf *m;
	bool from_priv;

	if (!saved_mac_addr) {
		struct rte_ether_hdr *eh;

		/* Save the MAC addresses */
		eh = rte_pktmbuf_mtod(rx_buf[0], struct rte_ether_hdr *);
		rte_ether_addr_copy(&eh->dst_addr, &local_mac_addr);
		rte_ether_addr_copy(&eh->src_addr, &remote_mac_addr);

		saved_mac_addr = true;
	}

	if (!ts) {
		ts = &ts_local;
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts_local);
	}

	w->ts = *ts;
	/* Ensure tv_sec does not overflow when multiplied by 10^9 */

	now = timespec_to_ns(&w->ts);

#ifdef DEBUG_BURST
	format_debug_time();
	printf("\n%s Burst received %u pkts time %s\n", debug_time_abs, nb_rx, debug_time_rel);
#endif

#ifdef WRITE_PCAP
	if (save_pcap)
		write_pcap(rx_buf, nb_rx, RTE_PCAPNG_DIRECTION_IN);
#endif

	for (i = 0; i < nb_rx; i++) {
// Note: driver may not support packet_type, in which case we want to set these
// ourselves. Use rte_the_dev_get_supported_ptypes() to find what is supported,
// see examples/l3fwd/l3fwd_em.c.

// We may want to handle RTE_PTYPE_L4_FRAG
// If (!all_classified) classify_pkt(w->classified, m);
// rte_net_get_ptype() in lib/net/rte_net.c looks good but inefficient
// SYN can get ICMP responses - see with wireshark and Linux to Linux connection to closed port
#ifdef DEBUG_PKT_NUM
		printf("Processing packet %u\n", ++pkt_num);
#endif
		m = rx_buf[i];

		if (!m->data_len) {
#ifdef DEBUG_EMPTY_PACKETS
			char ptype[128];
			rte_get_ptype_name(m->packet_type, ptype, sizeof(ptype));
			printf("ERROR *** Received packet data_len %u pkt_len %u packet_type %s (0x%x) pool %s\n", m->data_len, m->pkt_len, ptype, m->packet_type, m->pool->name);
#endif
			rte_pktmbuf_free(m);
			continue;
		}

#ifdef DEBUG_CHECKSUM
		check_checksum_in(m, "Received packet");
#endif

		from_priv = !!(m->ol_flags & config->dynflag_priv_mask);

		if ((m->packet_type & RTE_PTYPE_L4_MASK) != RTE_PTYPE_L4_TCP ||
		    ((ret = tcp_worker_mbuf_pkt(w, m, from_priv, tx_bufs)) != TFO_PKT_HANDLED &&
		     ret != TFO_PKT_INVALID)) {
			if (option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)
				m->ol_flags ^= config->dynflag_priv_mask;
			else
				m->vlan_tci = from_priv ? pub_vlan_tci : priv_vlan_tci;

			if (update_pkt(m, NULL)) {
#ifdef DEBUG_QUEUE_PKTS
				printf("adding tx_buf %p, vlan %u, ret %d\n", m, m->vlan_tci, ret);
#endif
				add_tx_buf(w, m, tx_bufs, from_priv, (union tfo_ip_p)(struct rte_ipv4_hdr *)NULL, true);
			} else
				printf("dropping tx_buf %p, vlan %u, ret %d, no room for vlan header\n", m, m->vlan_tci, ret);
		}
#ifdef DEBUG_STRUCTURES
		dump_details(w);
#endif
	}

	if (!tx_bufs->nb_tx && tx_bufs->m) {
		rte_free(tx_bufs->m);
		rte_free(tx_bufs->acks);
		tx_bufs->m = NULL;
	}

	return tx_bufs;
}

void
tfo_setup_failed_resend(struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt, *tmp_pkt;
	struct tfo_mbuf_priv *priv;
	struct tfo *fo;

	tx_bufs->nb_tx = 0;
	list_for_each_entry_safe(pkt, tmp_pkt, &send_failed_list, send_failed_list) {
		priv = get_priv_addr(pkt->m);
		fo = &worker.f[priv->fos->ef->tfo_idx];
		send_tcp_pkt(&worker, pkt, tx_bufs, priv->fos,
			     &fo->priv == priv->fos ? &fo->pub : &fo->priv, false);
		list_del_init(&pkt->send_failed_list);
	}
}

void
tcp_worker_mbuf_burst_send(struct rte_mbuf **rx_buf, uint16_t nb_rx, struct timespec *ts)
{
	struct tfo_tx_bufs tx_bufs = { .nb_inc = nb_rx };

#ifdef DEBUG_MEMPOOL
	show_mempool("packet_pool_0");
#endif

	tcp_worker_mbuf_burst(rx_buf, nb_rx, ts, &tx_bufs);

#ifdef DEBUG_PKT_NUM
	if (tx_bufs.nb_tx) {
		printf("Sending packets %u -> %u\n", pkt_num + 1, pkt_num + tx_bufs.nb_tx);
		pkt_num += tx_bufs.nb_tx;
	} else
		printf("Sending no packets (%u)\n", pkt_num);
#endif
	tfo_send_burst(&tx_bufs);

	/* Are there any packets that tried to be sent but failed */
	if (!list_empty(&send_failed_list)) {
		tx_bufs.m = NULL;
		tx_bufs.acks = NULL;

		tfo_setup_failed_resend(&tx_bufs);

#ifdef DEBUG_RESEND_FAILED_PACKETS
		printf("Resending %u failed packets\n", tx_bufs.nb_tx);
#endif

		tfo_send_burst(&tx_bufs);
	}
}

struct tfo_tx_bufs *
tcp_worker_mbuf(struct rte_mbuf *m, int from_priv, struct timespec *ts, struct tfo_tx_bufs *tx_bufs)
{
	if (from_priv)
		m->ol_flags |= config->dynflag_priv_mask;

	return tcp_worker_mbuf_burst(&m, 1, ts, tx_bufs);
}

void
tcp_worker_mbuf_send(struct rte_mbuf *m, int from_priv, struct timespec *ts)
{
	if (from_priv)
		m->ol_flags |= config->dynflag_priv_mask;

	tcp_worker_mbuf_burst_send(&m, 1, ts);
}

static void
process_eflow_timeout(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_side *fos, *foos;
	struct tfo *fo;
	bool shutdown;

	fo = &w->f[ef->tfo_idx];
	fos = &fo->priv;
	foos = &fo->pub;

	while (true) {
		if (ef->idle_timeout <= now) {
			_eflow_free(w, ef, tx_bufs);
			return;
		}

		if (unlikely(fos->cur_timer != TFO_TIMER_NONE && fos->timeout <= now)) {
			shutdown = handle_rack_tlp_timeout(w, ef, fos, foos, tx_bufs);

#ifdef DEBUG_STRUCTURES
			dump_details(w);
#endif

			if (shutdown)
				break;
		}

		if (fos->delayed_ack_timeout <= now) {
			handle_delayed_ack_timeout(w, ef, fos, foos, tx_bufs);

#ifdef DEBUG_STRUCTURES
			dump_details(w);
#endif
		}

		if (fos == &fo->pub)
			break;

		foos = fos;
		fos = &fo->pub;
	}

	update_timer_ef(ef);
}

void
tfo_process_timers(const struct timespec *ts, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_eflow *ef;
	struct tcp_worker *w = &worker;
	struct timer_rb_node *timer;


	if (RB_EMPTY_ROOT(&timer_tree.rb_root)) {
		/* We shouldn't get here. If there are no eflows,
		 * then no timer should be running */
		return;
	}

	if (ts)
		w->ts = *ts;
	else
		clock_gettime(CLOCK_MONOTONIC_RAW, &w->ts);
	now = timespec_to_ns(&w->ts);

	timer = rb_entry(rb_first_cached(&timer_tree), struct timer_rb_node, node);

#ifdef DEBUG_TIMERS
	if (timer->time <= now) {
		format_debug_time();
		printf("%s Timer time: %s\n", debug_time_abs, debug_time_rel);
	}
#endif

	/* Process each expired timer */
	while (timer->time <= now) {
		ef = container_of(timer, struct tfo_eflow, timer);
		process_eflow_timeout(w, ef, tx_bufs);

		timer = rb_entry(rb_first_cached(&timer_tree), struct timer_rb_node, node);
	}
}

void
tfo_process_timers_send(const struct timespec *ts)
{
	struct tfo_tx_bufs tx_bufs = { .nb_inc = 1024 };

	tfo_process_timers(ts, &tx_bufs);
	tfo_send_burst(&tx_bufs);
}

#ifdef DEBUG_CONFIG
static void
dump_config(const struct tcp_config *c)
{
	printf("u_n = %u\n", c->u_n);
	printf("hu_n = %u\n", c->hu_n);
	printf("hu_mask = %u\n", c->hu_mask);
	printf("ef_n = %u\n", c->ef_n);
	printf("hef_n = %u\n", c->hef_n);
	printf("hef_mask = %u\n", c->hef_mask);
	printf("f_n = %u\n", c->f_n);
	printf("p_n = %u\n", c->p_n);
	printf("tcp_min_rtt_wlen = %u\n", c->tcp_min_rtt_wlen);
	printf("keepalived timer = %u\n", c->tcp_keepalive_time);
	printf("keepalived probes = %u\n", c->tcp_keepalive_probes);
	printf("keepalived intvl = %u\n", c->tcp_keepalive_intvl);

	printf("\nmax_port_to %u\n", c->max_port_to);
	for (int i = 0; i <= c->max_port_to; i++) {
		if (!i || c->tcp_to[i].to_syn != c->tcp_to[0].to_syn ||
			  c->tcp_to[i].to_est != c->tcp_to[0].to_est ||
			  c->tcp_to[i].to_fin != c->tcp_to[0].to_fin)
			printf("%5d: %6d %6d %6d\n", i, c->tcp_to[i].to_syn, c->tcp_to[i].to_est, c->tcp_to[i].to_fin);
	}
}
#endif

#ifdef DEBUG
int
em_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4_ext = 0;
	int ptype_l3_ipv6_ext = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		printf("Support %u %s %s %s\n", ptypes[i], rte_get_ptype_l2_name(ptypes[i]), rte_get_ptype_l3_name(ptypes[i]), rte_get_ptype_l4_name(ptypes[i]));
	}
}
#endif

uint64_t
tcp_worker_init(struct tfo_worker_params *params)
{
	int socket_id = rte_socket_id();
	struct tcp_worker *w;
	struct tcp_config *c;
	struct tfo_pkt *p;
	struct tfo *f;
	struct tfo_eflow *ef;
	unsigned k;
	int j;

#ifdef DEBUG_MEMPOOL
	show_mempool("packet_pool_0");
#endif

#ifdef DEBUG
	em_check_ptype(rte_lcore_id() - 1);
#endif

/* Need some locking here */
	/* We want the config held in our NUMA node local memory */
	if (!node_config_copy[socket_id]) {
		node_config_copy[socket_id] = rte_malloc("worker config", sizeof(struct tcp_config), 0);
		*node_config_copy[socket_id] = global_config_data;
		node_config_copy[socket_id]->tcp_to = rte_malloc("worker config timeouts", (node_config_copy[socket_id]->max_port_to + 1) * sizeof(struct tcp_timeouts), 0);
		rte_memcpy(node_config_copy[socket_id]->tcp_to, global_config_data.tcp_to, (node_config_copy[socket_id]->max_port_to + 1) * sizeof(struct tcp_timeouts));
	}

	config = c = node_config_copy[socket_id];

#ifdef DEBUG_CONFIG
	printf("Dump config for socket %d\n", socket_id);
	dump_config(c);
#endif

	w = &worker;

	w->param = params->params;
	INIT_LIST_HEAD(&send_failed_list);
	pub_vlan_tci = params->public_vlan_tci;
	priv_vlan_tci = params->private_vlan_tci;
	ack_pool = params->ack_pool;
	port_id = params->port_id;
	queue_idx = params->queue_idx;
	option_flags = node_config_copy[socket_id]->option_flags;

#ifdef DEBUG_CONFIG
	printf("tfo_worker_init port %u queue_idx %u, vlan_tci: pub %u priv %u\n", port_id, queue_idx, pub_vlan_tci, priv_vlan_tci);
#endif

	struct tfo_eflow *ef_mem = rte_malloc("worker ef", c->ef_n * sizeof (struct tfo_eflow), 0);
	w->hef = rte_calloc("worker hef", c->hef_n, sizeof (struct hlist_head), 0);
	struct tfo *f_mem = rte_malloc("worker f", c->f_n * sizeof (struct tfo), 0);
	struct tfo_pkt *p_mem = rte_malloc("worker p", c->p_n * sizeof (struct tfo_pkt), 0);

#ifdef DEBUG_PKTS
	w->p = p_mem;
#endif
w->ef = ef_mem;
w->f = f_mem;

	INIT_HLIST_HEAD(&w->ef_free);
	for (j = c->ef_n - 1; j >= 0; j--) {
		ef = ef_mem + j;
		ef = &w->ef[j];
		ef->flags = 0;
		ef->tfo_idx = TFO_IDX_UNUSED;
		ef->state = TFO_STATE_NONE;
/* I think we can use ef->hlist instead of ef->flist. We can
 * then remove ef->flist, and user->flow_list */
		hlist_add_head(&ef->hlist, &w->ef_free);
	}

	INIT_LIST_HEAD(&w->f_free);
	for (k = 0; k < c->f_n; k++) {
		f = f_mem + k;
// Why don't we just use a pointer ?
		f->idx = k;
		list_add_tail(&f->list, &w->f_free);
	}

	INIT_LIST_HEAD(&w->p_free);
	for (k = 0; k < c->p_n; k++) {
		p = p_mem + k;
		list_add_tail(&p->list, &w->p_free);
		INIT_LIST_HEAD(&p->xmit_ts_list);
		INIT_LIST_HEAD(&p->send_failed_list);
	}

	/* Initialise the timer RB tree */
	timer_tree = RB_ROOT_CACHED;

#ifdef WRITE_PCAP
	if (save_pcap)
		open_pcap();
#endif

	return config->dynflag_priv_mask;
}

void
tcp_init(const struct tcp_config *c)
{
	global_config_data = *c;
	int flag;
	const struct rte_mbuf_dynflag dynflag = {
		.name = "dynflag-priv",
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

	/* If no tx function is specified, default to rte_eth_tx_burst() */
	if (!global_config_data.tx_burst)
		global_config_data.tx_burst = rte_eth_tx_burst;

	flag = rte_mbuf_dynflag_register(&dynflag);
	if (flag == -1)
		fprintf(stderr, "failed to register in-priv dynamic flag, flag=%d: %s",
			flag, strerror(errno));

	/* set a dynamic flag mask */
	global_config_data.dynflag_priv_mask = (1ULL << flag);

#if defined DEBUG_STRUCTURES || defined DEBUG_PKTS || defined DEBUG_TIMERS
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

uint16_t __attribute__((const))
tfo_max_ack_pkt_size(void)
{
	return sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_vlan_hdr) +
		sizeof(struct rte_ipv6_hdr) +
		(0xf0 >> 2);		/* maximum TCP header length */
}

uint16_t __attribute__((const))
tfo_get_mbuf_priv_size(void)
{
	return sizeof(struct tfo_mbuf_priv);
}
