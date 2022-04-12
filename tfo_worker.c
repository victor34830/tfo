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
 * -2. Make ACK after SYN+ACK normal packet processing
 * -1.9. We generate ACK to SYN+ACK and therefore queue it - this should be an option
 * -1. Timestamp, ack and win updating on send
 *  -0.95. Use timestamp along with seq/ack to ensure packet not 'old' - PAWS in RFC7323
 *  -0.94. Ensure seq/ack within 1GiB. Anythink more that 1GiB old is dubious (or at least old)
 * -0.9. Work out our policy for window size
 * 1. Tidy up code
 * 2. Optimize code
 * 3. Timestamps (RTTM option RFC7323)
 * 3.1. Option to add timestamps if not there
 * 4. Selective ACK
 * 5. Congestion control
 * 6. Tunnelling
 */

/* TODOs
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
 * -2. Make ACK after SYN+ACK normal packet processing
 * -1.9. We generate ACK to SYN+ACK and therefore queue it - this should be an option
 * -1. Timestamp, ack and win updating on send
 *  -0.95. Use timestamp along with seq/ack to ensure packet not 'old' - PAWS in RFC7323
 *  -0.94. Ensure seq/ack within 1GiB. Anythink more that 1GiB old is dubious (or at least old)
 * -0.9. Work out our policy for window size
 * 1. Tidy up code
 * 2. Optimize code
 * 3. Timestamps (RTTM option RFC7323)
 * 3.1. Option to add timestamps if not there
 * 4. Selective ACK
 * 5. Congestion control
 * 6. Tunnelling
 */

/* From Wikipedia - references are in https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 *
 * RFC 793  - TCP
 * RFC 813  - Window and acknowledgement strategy in TCP
 * RFC 896  - Nagle's algorithm and Congestion Control
 * RFC 1072 - precursor to RFC 7323
 * RFC 1122 - Host Requirements for Internet Hosts, clarified a number of TCP protocol implementation requirements including delayed ack
 * RFC 1185 - precursor to RFC 7323
 * RFC 1191 - Path MTU discovery
 * RFC 1323 - TCP timestamps (on by default for Linux, off for Windows Server), window size scaling etc
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
 * RFC 2883 - An Extension to the Selective Acknowledgement (SACK) Option for TCP
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
 * RFC 4821 - Packetization layer path MTU discovery
 * RFC 4953 - 7414 p15 - carry on from here
 * RFC 5681 - TCP congestion control
 * RFC 5682 - Forward RTO recovery
 * RFC 6093 - Urgent indications
 * RFC 6247 - ? just obsoleting other RFCs
 * RFC 6298 - computing TCPs retransmission timer
 * RFC 6582 - New Reno
 * RFC 6633 - deprecation of ICMP source quench messages
 * RFC 6675 - conservative loss recovery - SACK
 * RFC 6824 - TCP Extensions for Multipath Operation with Multiple Addresses
 * RFC 7323 - TCP Extensions for High Performance
 * RFC 7413 - TCP Fast Open
 * RFC 7414 - A list of the 8 required specifications and over 20 strongly encouraged enhancements, includes RFC 2581, TCP Congestion Control.


The original TCP congestion avoidance algorithm was known as "TCP Tahoe", but many alternative algorithms have since been proposed (including TCP Reno, TCP Vegas, FAST TCP, TCP New Reno, and TCP Hybla).

TCP Interactive (iTCP) [40] is a research effort into TCP extensions that allows applications to subscribe to TCP events and register handler components that can launch applications for various purposes, including application-assisted congestion control.

Multipath TCP (MPTCP) [41][42] is an ongoing effort within the IETF that aims at allowing a TCP connection to use multiple paths to maximize resource usage and increase redundancy. The redundancy offered by Multipath TCP in the context of wireless networks enables the simultaneous utilization of different networks, which brings higher throughput and better handover capabilities. Multipath TCP also brings performance benefits in datacenter environments.[43] The reference implementation[44] of Multipath TCP is being developed in the Linux kernel.[45] Multipath TCP is used to support the Siri voice recognition application on iPhones, iPads and Macs [46]

TCP Cookie Transactions (TCPCT) is an extension proposed in December 2009 to secure servers against denial-of-service attacks. Unlike SYN cookies, TCPCT does not conflict with other TCP extensions such as window scaling. TCPCT was designed due to necessities of DNSSEC, where servers have to handle large numbers of short-lived TCP connections.

tcpcrypt is an extension proposed in July 2010 to provide transport-level encryption directly in TCP itself. It is designed to work transparently and not require any configuration. Unlike TLS (SSL), tcpcrypt itself does not provide authentication, but provides simple primitives down to the application to do that. As of 2010, the first tcpcrypt IETF draft has been published and implementations exist for several major platforms.

Proposed in May 2013, Proportional Rate Reduction (PRR) is a TCP extension developed by Google engineers. PRR ensures that the TCP window size after recovery is as close to the Slow-start threshold as possible.[49] The algorithm is designed to improve the speed of recovery and is the default congestion control algorithm in Linux 3.2+ kernels
*/

/* DPDK usage performance:
 *
 * 1. Use stack base mempools - see https://www.intel.com/content/www/us/en/developer/articles/technical/optimize-memory-usage-in-multi-threaded-data-plane-development-kit-dpdk-applications.html
 * 2. _thread declares a thread local variable
 *
 */

//#define DEBUG_MEM
#define DEBUG_PKTS
#define DEBUG_BURST
#define DEBUG_PKT_TYPES
#define DEBUG_VLAN_TCI
#define DEBUG_STRUCTURES
//#define DEBUG_TCP_OPT
//#define DEBUG_QUEUE_PKTS
#define DEBUG_ACK
//#define DEBUG_ACK_PKT_LIST
//#define DEBUG_CHECKSUM
//#define DEBUG_CHECKSUM_DETAIL
#define DEBUG_SACK_RX
#define DEBUG_SACK_SEND
#define DEBUG_CHECK_ADDR
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
#define DEBUG_ETHDEV
//#define DEBUG_CONFIG
#define DEBUG_GARBAGE
#define DEBUG_RFC5681
#define DEBUG_PKT_NUM
#define DEBUG_DUMP_DETAILS


// XXX - add code for not releasing
#define RELEASE_SACKED_PACKETS

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <ev.h>
#include <threads.h>
#include <stddef.h>

#include "linux_list.h"

#include "tfo_worker.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mempool.h>
#include <rte_mbuf_dyn.h>
#include <rte_net.h>
#include <rte_malloc.h>

#ifdef DEBUG_PKT_TYPES
#include <rte_mbuf_ptype.h>
#endif
#ifdef DEBUG_ETHDEV
#include <rte_ethdev.h>
#endif

#ifndef HAVE_FREE_HEADERS
#include "util.h"
#endif

#ifdef RELEASE_SACKED_PACKETS
struct tfo_addr_info
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
};
#endif


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
static thread_local uint16_t port_id;
static thread_local uint16_t queue_idx;
#ifdef RELEASE_SACKED_PACKETS
static thread_local bool saved_mac_addr;
static thread_local struct rte_ether_addr local_mac_addr;
static thread_local struct rte_ether_addr remote_mac_addr;
#endif

struct tfo_pkt_align
{
	uint8_t	start;
	struct tfo_pkt align;
};

/* tfo_mbuf_priv_alignment is needed for TFO_MBUF_PRIV_OFFSET_ALIGN */
const uint8_t tfo_mbuf_priv_alignment = offsetof(struct tfo_pkt_align, align);


#ifdef DEBUG_PKT_NUM
static thread_local uint32_t pkt_num = 0;
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

#if defined DEBUG_STRUCTURES || defined DEBUG_PKTS || defined DEBUG_GARBAGE
static void
print_side(const struct tfo_side *s, const struct timespec *ts)
{
	struct tfo_pkt *p;
	uint32_t next_exp;
	uint64_t time_diff;
	uint16_t num_gaps = 0;
	uint8_t *data_start;
	unsigned sack_entry, last_sack_entry;

	printf("\t\t\trcv_nxt 0x%x snd_una 0x%x snd_nxt 0x%x snd_win 0x%x rcv_win 0x%x ssthresh 0x%x"
		" cwnd 0x%x dup_ack %u\n\t\t\t  last_rcv_win_end 0x%x snd_win_shift %u rcv_win_shift %u mss 0x%x\n",
		s->rcv_nxt, s->snd_una, s->snd_nxt, s->snd_win, s->rcv_win,
		s->ssthresh, s->cwnd, s->dup_ack, s->last_rcv_win_end, s->snd_win_shift, s->rcv_win_shift, s->mss);
	if (s->sack_entries) {
		printf("\t\t\t  sack_gaps %u sack_entries %u, first_entry %u", s->sack_gap, s->sack_entries, s->first_sack_entry);
		last_sack_entry = (s->first_sack_entry + s->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
		for (sack_entry = s->first_sack_entry; ; sack_entry = (sack_entry + 1) % MAX_SACK_ENTRIES) {
			printf(" [%u]: 0x%x -> 0x%x", sack_entry, s->sack_edges[sack_entry].left_edge, s->sack_edges[sack_entry].right_edge);
			if (sack_entry == last_sack_entry)
				break;
		}
		printf("\n");
	}
	printf("\t\t\t  srtt %u rttvar %u rto %u #pkt %u, ttl %u snd_win_end 0x%x rcv_win_end 0x%x sack_gaps %u\n",
		s->srtt, s->rttvar, s->rto, s->pktcount, s->rcv_ttl,
		s->snd_una + (s->snd_win << s->snd_win_shift),
		s->rcv_nxt + (s->rcv_win << s->rcv_win_shift), s->sack_gap);
	printf("\t\t\t  ts_recent %1$u (0x%1$x), ack_sent_time %2$" PRIu64 ".%3$9.9" PRIu64 "\n",
		rte_be_to_cpu_32(s->ts_recent), s->ack_sent_time / 1000000000UL, s->ack_sent_time % 1000000000UL);

	next_exp = s->snd_una;
	list_for_each_entry(p, &s->pktlist, list) {
		if (after(p->seq, next_exp)) {
			printf("\t\t\t\t  *** expected 0x%x, gap = %u\n", next_exp, p->seq - next_exp);
			num_gaps++;
		}
		time_diff = timespec_to_ns(ts) - p->ns;
		data_start = p->m ? rte_pktmbuf_mtod(p->m, uint8_t *) : 0;
		printf("\t\t\t\tm %p, seq 0x%x%s %slen %u flags 0x%x tcp_flags 0x%x vlan %u ip %ld tcp %ld ts %ld sack %ld refcnt %u ns %" PRIu64 ".%9.9" PRIu64,
			p->m, p->seq, segend(p) > s->snd_una + (s->snd_win << s->snd_win_shift) ? "*" : "",
			p->m ? "seg" : "sack_", p->seglen, p->flags, p->m ? p->tcp->tcp_flags : 0U, p->m ? p->m->vlan_tci : 0U,
			p->m ? (uint8_t *)p->ipv4 - data_start : 0,
			p->m ? (uint8_t *)p->tcp - data_start : 0,
			p->m && p->ts ? (uint8_t *)p->ts - data_start : 0,
			p->m && p->sack ? (uint8_t *)p->sack - data_start : 0,
			p->m ? p->m->refcnt : 0U, time_diff / 1000000000UL, time_diff % 1000000000UL);
		if (before(p->seq, next_exp))
			printf(" *** overlap = %ld", (int64_t)next_exp - (int64_t)p->seq);
		printf("\n");
		next_exp = segend(p);
	}

	if (num_gaps != s->sack_gap)
		printf("*** s->sack_gap %u, num_gaps %u\n", s->sack_gap, num_gaps);
}

static void
dump_details(const struct tcp_worker *w)
{
	struct tfo_user *u;
	struct tfo_eflow *ef;
	struct tfo *fo;
	unsigned i;
#ifdef DEBUG_ETHDEV
	uint16_t port;
	struct rte_eth_stats eth_stats;
#endif

	printf("time: %ld.%9.9ld\n", w->ts.tv_sec, w->ts.tv_nsec);
	printf("In use: users %u, eflows %u, flows %u, packets %u, max_packets %u\n", w->u_use, w->ef_use, w->f_use, w->p_use, w->p_max_use);
	for (i = 0; i < config->hu_n; i++) {
		if (!hlist_empty(&w->hu[i])) {
			printf("\nUser hash %u\n", i);
			hlist_for_each_entry(u, &w->hu[i], hlist) {
				// print user
				printf("\tUser: %p priv addr %x, flags 0x%x num flows %u\n", u, u->priv_addr.v4, u->flags, u->flow_n);
				hlist_for_each_entry(ef, &u->flow_list, flist) {
					// print eflow
					printf("\t\tef %p state %u tfo_idx %u, ef->pub_addr.v4 %x port: priv %u pub %u flags 0x%x user %p last_use %u\n",
						ef, ef->state, ef->tfo_idx, ef->pub_addr.v4, ef->priv_port, ef->pub_port, ef->flags, ef->u, ef->last_use);
					if (ef->state == TCP_STATE_SYN)
						printf("\t\t  svr_snd_una 0x%x cl_snd_win 0x%x cl_rcv_nxt 0x%x\n", ef->server_snd_una, ef->client_snd_win, ef->client_rcv_nxt);
					if (ef->tfo_idx != TFO_IDX_UNUSED) {
						// Print tfo
						fo = &w->f[ef->tfo_idx];
						printf("\t\t  idx %u, wakeup_ns %" PRIu64 "\n", fo->idx, fo->wakeup_ns);
						printf("\t\t  private:\n");
						print_side(&fo->priv, &w->ts);
						printf("\t\t  public:\n");
						print_side(&fo->pub, &w->ts);
					}
					printf("\n");
				}
			}
		}
	}

	for (i = 0; i < config->hef_n; i++) {
		if (!hlist_empty(&w->hef[i])) {
			printf("Flow hash %u\n", i);
			hlist_for_each_entry(ef, &w->hu[i], hlist)
				printf("\t ef %p\n", ef);
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

/* Change this so that we return m and it can be added to tx_bufs */
static inline void
add_tx_buf(const struct tcp_worker *w, struct rte_mbuf *m, struct tfo_tx_bufs *tx_bufs, bool from_priv, union tfo_ip_p iph)
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
	} else if (unlikely(tx_bufs->nb_tx == tx_bufs->max_tx)) {
		tx_bufs->max_tx += tx_bufs->nb_inc;
		tx_bufs->m = rte_realloc(tx_bufs->m, tx_bufs->max_tx * sizeof(struct rte_mbuf *), 0);
	}

	tx_bufs->m[tx_bufs->nb_tx++] = m;

	if (iph.ip4h && config->capture_output_packet)
		config->capture_output_packet(w->param, IPPROTO_IP, m, &w->ts, from_priv, iph);
}

static inline void
set_rcv_win(struct tfo_side *fos, struct tfo_side *foos) {
	uint32_t win_size = foos->snd_win << foos->snd_win_shift;
	uint32_t win_end;

#ifdef DEBUG_RCV_WIN
	printf("Updating rcv_win from 0x%x, foos snd_win 0x%x snd_win_shift %u cwnd 0x%x snd_una 0x%x fos: rcv_win 0x%x",
		fos->last_rcv_win_end, foos->snd_win, foos->snd_win_shift, foos->cwnd, foos->snd_una, fos->rcv_win);
#endif

	/* This needs experimenting with to optimise. This is currently calculated as:
	 * min(max(min(send_window, cwnd * 2), 20 * mss), 50 * mss) */
	if (win_size > 2 * foos->cwnd)
		win_size = 2 * foos->cwnd;
	if (win_size < 20 * foos->mss)
		win_size = 20 * foos->mss;
	if (win_size > 50 * foos->mss)
		win_size = 50 * foos->mss;

	win_end = foos->snd_una + win_size;

	if (after(win_end, fos->last_rcv_win_end))
		fos->last_rcv_win_end = win_end;
	if (after(fos->last_rcv_win_end, fos->rcv_nxt)) {
		fos->rcv_win = ((fos->last_rcv_win_end - fos->rcv_nxt - 1) >> fos->rcv_win_shift) + 1;
	} else {
#ifdef DEBUG_TCP_WINDOW
		printf("Send on %s rcv_win = 0x0, foos snd_una 0x%x snd_win 0x%x shift %u, fos->rcv_nxt 0x%x\n", fos < foos ? "priv" : "pub",
			foos->snd_una, foos->snd_win, foos->snd_win_shift, fos->rcv_nxt);
#endif
		fos->rcv_win = 0;
		fos->last_rcv_win_end = fos->rcv_nxt;
	}

#ifdef DEBUG_RCV_WIN
	printf(" to fos rcv_win 0x%x, last_rcv_win_end 0x%x, len 0x%x(%u)\n", fos->rcv_win, fos->last_rcv_win_end, fos->last_rcv_win_end - fos->rcv_win, fos->last_rcv_win_end - fos->rcv_win);
#endif
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

static inline void
add_sack_option(struct tfo_side *fos, uint8_t *ptr, unsigned sack_blocks)
{
	struct {
		uint8_t b:2;
	} four;
	uint8_t i;
	struct tcp_sack_option *sack_opt;

	*(uint32_t *)ptr = rte_cpu_to_be_32(TCPOPT_NOP << 24 |
					    TCPOPT_NOP << 16 |
					    TCPOPT_SACK << 8 |
					    (sizeof(struct tcp_sack_option) + 2 + sack_blocks * sizeof(struct sack_edges)));
	*ptr++ = TCPOPT_NOP;
	*ptr++ = TCPOPT_NOP;
	sack_opt = (struct tcp_sack_option *)(ptr);
	sack_opt->opt_code = TCPOPT_SACK;
	sack_opt->opt_len = sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges);
	for (i = 0, four.b = fos->first_sack_entry; i < sack_blocks; i++, four.b++) {
		sack_opt->edges[i].left_edge = rte_cpu_to_be_32(fos->sack_edges[four.b].left_edge);
		sack_opt->edges[i].right_edge = rte_cpu_to_be_32(fos->sack_edges[four.b].right_edge);
	}
}

static bool
update_packet_length(struct tfo_pkt *pkt, uint8_t *offs, int8_t len)
{
	uint8_t *pkt_start = rte_pktmbuf_mtod(pkt->m, uint8_t *);
	uint8_t *pkt_end;
	struct {
		uint8_t data_off;
		uint8_t tcp_flags;
	} new_hdr;
	uint16_t new_len;
	uint16_t ph_old_len = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
	uint16_t payload_bytes = payload_len(pkt);

	if (!len)
		return true;

	/* Remove the checksum for what is being removed */
	if (len < 0)
		pkt->tcp->cksum = remove_from_checksum(pkt->tcp->cksum, offs, -len);

	if (!payload_bytes) {
		/* No data, so nothing to move */
		if (len > 0) {
			pkt_end = pkt_start + pkt->m->data_len;
			rte_pktmbuf_append(pkt->m, len);
			memset(pkt_end, 0, len);
		} else
			rte_pktmbuf_trim(pkt->m, -len);
	} else if (offs - pkt_start < payload_bytes) {
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
		pkt->ipv4 = (struct rte_ipv4_hdr *)((uint8_t *)pkt->ipv4 - len);
		pkt->tcp = (struct rte_tcp_hdr*)((uint8_t *)pkt->tcp - len);
		if (pkt->ts)
			pkt->ts = (struct tcp_timestamp_option *)((uint8_t *)pkt->ts - len);
		if (pkt->sack)
			pkt->sack = (struct tcp_sack_option *)((uint8_t *)pkt->sack - len);
	} else {
		uint8_t *data_start = pkt_start + pkt->m->data_len - payload_bytes;

		if (len > 0) {
			if (!rte_pktmbuf_append(pkt->m, len)) {
				printf("No room to add %d bytes at end of packet %p seq 0x%x\n", len, pkt->m, pkt->seq);
				return false;
			}
			memmove(data_start + len, data_start, payload_bytes);
			memset(data_start, 0, len);
		} else {
			memmove(data_start + len, data_start, payload_bytes);
			rte_pktmbuf_trim(pkt->m, -len);
		}
	}

	/* Update tcp header length */
	new_hdr.tcp_flags = pkt->tcp->tcp_flags;
	new_hdr.data_off = (((pkt->tcp->data_off >> 4) + len / 4) << 4) | (pkt->tcp->data_off & 0x0f);
//	new_hdr.data_off = pkt->tcp->data_off + (len << 2);
	pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &pkt->tcp->data_off, &new_hdr, sizeof(new_hdr));

	/* Update the TCP checksum for the length change in the TCP pseudo header */
	new_len = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));
	pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &ph_old_len, &new_len, sizeof(new_len));

	/* Update IP packet length */
	new_len = rte_cpu_to_be_16(rte_be_to_cpu_16(pkt->ipv4->total_length) + len);
	pkt->ipv4->hdr_checksum = update_checksum(pkt->ipv4->hdr_checksum, &pkt->ipv4->total_length, &new_len, sizeof(new_len));

	return true;
}

#ifdef DEBUG_CHECK_ADDR
static inline void
check_addr(struct tfo_pkt *pkt, const char *msg)
{
	if ((pkt->ipv4->src_addr != rte_cpu_to_be_32(0x0a000003) &&
	     pkt->ipv4->src_addr != rte_cpu_to_be_32(0xc0a80002)) ||
	    (pkt->ipv4->dst_addr != rte_cpu_to_be_32(0x0a000003) &&
	     pkt->ipv4->dst_addr != rte_cpu_to_be_32(0xc0a80002))) {
		printf("%s: WRONG src/dst 0x%x/0x%x\n", msg, rte_be_to_cpu_32(pkt->ipv4->src_addr), rte_be_to_cpu_32(pkt->ipv4->dst_addr));
		printf("Orig packet m %p eh %p ipv4 %p tcp %p ts %p sack %p\n", pkt->m, rte_pktmbuf_mtod(pkt->m, char *), pkt->ipv4, pkt->tcp, pkt->ts, pkt->sack);
		dump_m(pkt->m);

		/* Produce a core dump */
		fflush(stdout);
		int i = *(int *)NULL;
		printf("At 0 - %d\n", i);
	}

}
#endif

static inline bool
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
	check_addr(pkt, "uso end with");
#endif

	return true;
}

static void
_send_ack_pkt(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_pkt *pkt, struct tfo_addr_info *addr,
		uint16_t vlan_id, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs, bool from_queue, bool same_dirn)
{
	struct rte_ether_hdr *eh;
	struct rte_ether_hdr *eh_in;
	struct rte_vlan_hdr *vl;
	struct rte_ipv4_hdr *ipv4;
	struct rte_tcp_hdr *tcp;
	struct tcp_timestamp_option *ts_opt;
	struct rte_mbuf *m;
	uint8_t *ptr;
	uint16_t pkt_len;
	uint8_t sack_blocks;


	m = rte_pktmbuf_alloc(ack_pool ? ack_pool : pkt->m->pool);
// Handle not forwarding ACK somehow
	if (m == NULL) {
#ifdef DEBUG_NO_MBUF
		printf("Unable to ack 0x%x - no mbuf - vlan %u\n", fos->rcv_nxt, vlan_id);
#endif
		return;
	}

	if (option_flags & TFO_CONFIG_FL_NO_VLAN_CHG) {
		if (vlan_id == pub_vlan_tci)
			m->ol_flags &= ~config->dynflag_priv_mask;
		else
			m->ol_flags |= config->dynflag_priv_mask;
	} else
		m->vlan_tci = vlan_id;

	if (fos->sack_gap && (ef->flags & TFO_EF_FL_SACK))
		sack_blocks = min(fos->sack_entries, 4 - !!(ef->flags & TFO_EF_FL_TIMESTAMP));
	else
		sack_blocks = 0;

// PQA - we are setting all fields.
//	memset(m + 1, 0x00, sizeof (struct fn_mbuf_priv));
	pkt_len = sizeof (struct rte_ether_hdr) +
		   (m->vlan_tci ? sizeof(struct rte_vlan_hdr) : 0) +
		   sizeof (struct rte_ipv4_hdr) +
		   sizeof (struct rte_tcp_hdr) +
		   (ef->flags & TFO_EF_FL_TIMESTAMP ? sizeof(struct tcp_timestamp_option) + 2 : 0) +
		   (sack_blocks ? (sizeof(struct tcp_sack_option) + 2 + sizeof(struct sack_edges) * sack_blocks) : 0);

	eh = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, pkt_len);

	if (unlikely(addr)) {
		m->port = port_id;

		rte_ether_addr_copy(&local_mac_addr, &eh->dst_addr);
		rte_ether_addr_copy(&remote_mac_addr, &eh->src_addr);
	} else {
		m->port = pkt->m->port;

		eh_in = rte_pktmbuf_mtod(pkt->m, struct rte_ether_hdr *);
		if (likely(from_queue)) {
			rte_ether_addr_copy(&eh_in->dst_addr, &eh->dst_addr);
			rte_ether_addr_copy(&eh_in->src_addr, &eh->src_addr);
		} else {
			rte_ether_addr_copy(&eh_in->src_addr, &eh->dst_addr);
			rte_ether_addr_copy(&eh_in->dst_addr, &eh->src_addr);
		}
	}

	if (m->vlan_tci) {
		eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		vl = (struct rte_vlan_hdr *)(eh + 1);
		vl->vlan_tci = rte_cpu_to_be_16(vlan_id);
		vl->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		ipv4 = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(eh + 1) + 1);
	} else {
		eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		ipv4 = (struct rte_ipv4_hdr *)(eh + 1);
	}

	ipv4->version_ihl = 0x45;
	ipv4->type_of_service = 0;
ipv4->type_of_service = 0x10;
	ipv4->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof (*eh) - (vlan_id ? sizeof(*vl) : 0));
// See RFC6864 re identification
	ipv4->packet_id = 0;
// A random!! number
ipv4->packet_id = rte_cpu_to_be_16(w->ts.tv_nsec);
ipv4->packet_id = 0x3412;
	ipv4->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
	ipv4->time_to_live = foos->rcv_ttl;
	ipv4->next_proto_id = IPPROTO_TCP;
	ipv4->hdr_checksum = 0;
	if (unlikely(addr)) {
		ipv4->src_addr = addr->src_addr;
		ipv4->dst_addr = addr->dst_addr;
	} else if (likely(!same_dirn)) {
		ipv4->src_addr = pkt->ipv4->dst_addr;
		ipv4->dst_addr = pkt->ipv4->src_addr;
	} else {
		ipv4->src_addr = pkt->ipv4->src_addr;
		ipv4->dst_addr = pkt->ipv4->dst_addr;
	}
// Checksum offload?
	ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
// Should we copy IPv4 options ?

	tcp = (struct rte_tcp_hdr *)(ipv4 + 1);
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
	tcp->sent_seq = rte_cpu_to_be_32(fos->snd_nxt);
	tcp->recv_ack = rte_cpu_to_be_32(fos->rcv_nxt);
	tcp->data_off = 5 << 4;
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
		ts_opt->ts_val = foos->ts_recent;
		ts_opt->ts_ecr = fos->ts_recent;
		tcp->data_off += ((1 + 1 + TCPOLEN_TIMESTAMP) / 4) << 4;
		ptr += sizeof(struct tcp_timestamp_option) + 2;
	}

	if (sack_blocks)
		add_sack_option(fos, ptr, sack_blocks);

// Checksum offload?
	tcp->cksum = rte_ipv4_udptcp_cksum(ipv4, tcp);

	fos->ack_sent_time = timespec_to_ns(&w->ts);

#ifdef DEBUG_ACK
	printf("Sending ack %p seq 0x%x ack 0x%x len %u ts_val %u ts_ecr %u vlan %u\n",
		m, fos->snd_nxt, fos->rcv_nxt, m->data_len,
		(ef->flags & TFO_EF_FL_TIMESTAMP) ? rte_be_to_cpu_32(foos->ts_recent) : 0,
		(ef->flags & TFO_EF_FL_TIMESTAMP) ? rte_be_to_cpu_32(fos->ts_recent) : 0,
		vlan_id);
#endif

#ifndef TFO_UNDER_TEST
	add_tx_buf(w, m, tx_bufs, pkt ? !(pkt->flags & TFO_PKT_FL_FROM_PRIV) : foos == &w->f[ef->tfo_idx].pub, (union tfo_ip_p)ipv4);
#else
	rte_pktmbuf_free(m);
#endif
}

static void
_send_ack_pkt_in(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_pkt_in *p, struct tfo_addr_info *addr,
		uint16_t vlan_id, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs, bool from_queue, bool same_dirn)
{
	struct tfo_pkt pkt;

	pkt.m = p->m;
	pkt.ipv4 = p->ip4h;
	pkt.tcp = p->tcp;
	pkt.flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;

	_send_ack_pkt(w, ef, fos, &pkt, addr, vlan_id, foos, tx_bufs, from_queue, same_dirn);
}

static inline uint32_t
_flow_alloc(struct tcp_worker *w)
{
	struct tfo* fo;
	struct tfo_side *fos;

	/* Allocated when decide to optimze flow (following SYN ACK) */

	/* alloc flow */
	fo = list_first_entry(&w->f_free, struct tfo, list);
	list_del_init(&fo->list);

	fos = &fo->priv;
	while (true) {
		fos->srtt = 0;
		fos->rto = 1000;
		fos->dup_ack = 0;
//		fos->is_priv = true;
		fos->sack_gap = 0;
		fos->first_sack_entry = 0;
		fos->sack_entries = 0;

		INIT_LIST_HEAD(&fos->pktlist);

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

static inline void
pkt_free(struct tcp_worker *w, struct tfo_side *s, struct tfo_pkt *pkt)
{
	list_del(&pkt->list);

	/* We might have already freed the mbuf if using SACK */
	if (pkt->m)
		rte_pktmbuf_free(pkt->m);
	list_add(&pkt->list, &w->p_free);
	--w->p_use;
	--s->pktcount;
}

static inline void
pkt_free_mbuf(struct tfo_pkt *pkt)
{
	if (pkt->m) {
		rte_pktmbuf_free(pkt->m);
		pkt->m = NULL;
		pkt->ipv4 = NULL;
		pkt->tcp = NULL;
		pkt->ts = NULL;
		pkt->sack = NULL;
	}
}

static void
_flow_free(struct tcp_worker *w, struct tfo *f)
{
	struct tfo_pkt *pkt, *pkt_tmp;

#ifdef DEBUG_FLOW
	printf("flow_free %u worker %p\n", f->idx, w);
#endif

	/* del pkt lists */
	list_for_each_entry_safe(pkt, pkt_tmp, &f->priv.pktlist, list)
		pkt_free(w, &f->priv, pkt);
	list_for_each_entry_safe(pkt, pkt_tmp, &f->pub.pktlist, list)
		pkt_free(w, &f->pub, pkt);

	list_add(&f->list, &w->f_free);
	--w->f_use;
}

static struct tfo_user *
_user_alloc(struct tcp_worker *w, uint32_t h, uint32_t flags)
{
	struct tfo_user *u;

	/* Allocated when first eflow allocated for user */

	if (unlikely(hlist_empty(&w->u_free)))
		return NULL;

	u = hlist_entry(w->u_free.first, struct tfo_user, hlist);

#ifdef DEBUG_MEM
	if (u->flags)
		printf("Allocating user %p with flags 0x%x\n", u, u->flags);
	if (u->flow_n)
		printf("Allocating user %p with flow count %u\n", u, u->flow_n);
	u->flags = TFO_USER_FL_USED;
	u->flow_n = 0;
#endif

	u->flags |= flags;
	INIT_HLIST_HEAD(&u->flow_list);

	__hlist_del(&u->hlist);
	hlist_add_head(&u->hlist, &w->hu[h]);

	++w->u_use;

#ifdef DEBUG_USER
	printf("Alloc'd user %p to worker %p\n", u, w);
#endif

	return u;
}

static inline void
_user_free(struct tcp_worker *w, struct tfo_user *u)
{
#ifdef DEBUG_USER
	printf("user_free w %p u %p\n", w, u);
#endif

#ifdef DEBUG_MEM
	if (!(u->flags & TFO_USER_FL_USED))
		printf("Freeing user %p without used flag set\n", u);
#endif

	u->flags = 0;

	--w->u_use;

	__hlist_del(&u->hlist);
	hlist_add_head(&u->hlist, &w->u_free);
}

static struct tfo_eflow *
_eflow_alloc(struct tcp_worker *w, struct tfo_user *u, uint32_t h)
{
	struct tfo_eflow *ef;

	/* Called on first SYN of flow (i.e. no ACK) */

	if (unlikely(hlist_empty(&w->ef_free)))
		return NULL;

	ef = hlist_entry(w->ef_free.first, struct tfo_eflow, flist);

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
	ef->u = u;
	ef->win_shift = TFO_WIN_SCALE_UNSET;
	ef->client_mss = TCP_MSS_DEFAULT;

	__hlist_del(&ef->flist);
	hlist_add_head(&ef->hlist, &w->hef[h]);
	hlist_add_head(&ef->flist, &u->flow_list);

	++w->ef_use;
	++u->flow_n;
	++w->st.flow_state[ef->state];

#ifdef DEBUG_FLOW
	printf("Alloc'd eflow %p to worker %p\n", ef, w);
#endif

	return ef;
}

static inline void
_eflow_free(struct tcp_worker *w, struct tfo_eflow *ef)
{
	struct tfo_user *u = ef->u;

#ifdef DEBUG_FLOW
	printf("eflow_free w %p ef %p ef->tfo_idx %u flags 0x%x, state %u\n", w, ef, ef->tfo_idx, ef->flags, ef->state);
#endif

	if (!(ef->flags & TFO_EF_FL_STOP_OPTIMIZE))
		--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		_flow_free(w, &w->f[ef->tfo_idx]);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}

	--w->ef_use;
	--u->flow_n;
	--w->st.flow_state[ef->state];
	ef->state = TFO_STATE_NONE;

#ifdef DEBUG_MEM
	if (!(ef->flags & TFO_EF_FL_USED))
		printf("Freeing eflow %p without used flag set\n", ef);
#endif

	ef->flags = 0;
	ef->u = NULL;

	__hlist_del(&ef->hlist);

	__hlist_del(&ef->flist);
	hlist_add_head(&ef->flist, &w->ef_free);

	if (u->flow_n == 0)
		_user_free(w, u);
}

static inline int
_eflow_timeout_remain(struct tfo_eflow *ef, uint16_t lnow)
{
	struct tcp_config *c = config;
	int port_index = ef->pub_port > c->max_port_to ? 0 : ef->pub_port;

	switch (ef->state) {
	case TCP_STATE_SYN ... TCP_STATE_SYN_ACK:
		return c->tcp_to[port_index].to_syn - (uint16_t)(lnow - ef->last_use);
	case TCP_STATE_ESTABLISHED:
		return c->tcp_to[port_index].to_est - (uint16_t)(lnow - ef->last_use);
	default:
		return c->tcp_to[port_index].to_fin - (uint16_t)(lnow - ef->last_use);
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

	while (opt_off < opt_size) {
		opt = (struct tcp_option *)(opt_ptr + opt_off);

#ifdef DEBUG_TCP_OPT
		printf("tcp %p, opt 0x%x opt_off %d opt_size %d\n", p->tcp, opt->opt_code, opt_off, opt->opt_code > 1 ? opt->opt_len : 1);
#endif

		if (opt->opt_code == TCPOPT_EOL) {
			opt_off += 8 - opt_off % 8;
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

			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_SACK;
			break;
		case TCPOPT_MAXSEG:
			if (opt->opt_len != TCPOLEN_MAXSEG)
				return false;

			p->mss_opt = rte_be_to_cpu_16(*(uint16_t *)opt->opt_data);
			break;
		case TCPOPT_SACK:
			p->sack_opt = (struct tcp_sack_option *)opt;
#if defined DEBUG_TCP_OPT
			printf("SACK option size %u, blocks %u\n", p->sack_opt->opt_len, (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges));
			for (unsigned i = 0; i < (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges); i++)
				printf("  %u: 0x%x -> 0x%x\n", i, rte_be_to_cpu_32(p->sack_opt->edges[i].left_edge), rte_be_to_cpu_32(p->sack_opt->edges[i].right_edge));
#endif
			break;
		case TCPOPT_TIMESTAMP:
			if (opt->opt_len != TCPOLEN_TIMESTAMP)
				return false;

			p->ts_opt = (struct tcp_timestamp_option *)opt;

#ifdef DEBUG_TCP_OPT
			printf("ts_val %u ts_ecr %u\n", rte_be_to_cpu_32(p->ts_opt->ts_val), ret_be_to_cpu_32(p->ts_opt->ts_ecr));
#endif

			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_TIMESTAMP;
			break;
		case 16 ... 18:
		case 20 ... 24:
		case 26 ... 30:
		case 34:
		case 69:
			/* See https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
			 * for the list of assigned options. */
			break;
		default:
			/* Don't try optimizing if there are options we don't understand */
			return false;
		}

		opt_off += opt->opt_len;
	}

	return (opt_off == opt_size);
}

static inline bool
set_estab_options(struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
// We might want to optimise this and not use set_tcp_options
	return set_tcp_options(p, ef);
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
static void
check_do_optimize(struct tcp_worker *w, const struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
	struct tfo *fo;
	struct tfo_side *client_fo, *server_fo;

	/* should not happen */
	if (unlikely(list_empty(&w->f_free)) ||
	    w->p_use >= config->p_n * 3 / 4) {
		_eflow_free(w, ef);
		return;
	}

	/* alloc flow */
	ef->tfo_idx = _flow_alloc(w);
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
	client_fo->snd_nxt = rte_be_to_cpu_32(p->tcp->sent_seq) + 1 + p->seglen;
	server_fo->last_rcv_win_end = client_fo->snd_una + ef->client_snd_win;
	client_fo->snd_win = ((ef->client_snd_win - 1) >> client_fo->snd_win_shift) + 1;
#ifdef DEBUG_RCV_WIN
	printf("server lrwe 0x%x from client snd_una 0x%x and snd_win 0x%x << 0\n", server_fo->last_rcv_win_end, client_fo->snd_una, ef->client_snd_win);
#endif
	server_fo->rcv_win = client_fo->snd_win;
	client_fo->mss = ef->client_mss;
	if (p->ts_opt)
		client_fo->ts_recent = p->ts_opt->ts_ecr;

// We might get stuck with client implementations that don't receive data with SYN+ACK. Adjust when go to established state
	server_fo->rcv_nxt = client_fo->snd_nxt;
	server_fo->snd_una = rte_be_to_cpu_32(p->tcp->recv_ack);
	server_fo->snd_nxt = ef->client_rcv_nxt;
	client_fo->last_rcv_win_end = server_fo->snd_una + rte_be_to_cpu_16(p->tcp->rx_win);
#ifdef DEBUG_RCV_WIN
	printf("client lrwe 0x%x from server snd_una 0x%x and snd_win 0x%x << 0\n", client_fo->last_rcv_win_end, server_fo->snd_una, rte_be_to_cpu_16(p->tcp->rx_win));
#endif
	server_fo->snd_win = ((rte_be_to_cpu_16(p->tcp->rx_win) - 1) >> server_fo->snd_win_shift) + 1;
	client_fo->rcv_win = server_fo->snd_win;
	server_fo->mss = p->mss_opt ? p->mss_opt : TCP_MSS_DEFAULT;
	if (p->ts_opt)
		server_fo->ts_recent = p->ts_opt->ts_val;
	server_fo->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->ip6h->hop_limits : p->ip4h->time_to_live;

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

#ifdef DEBUG_OPTIMIZE
	printf("priv rx/tx win 0x%x:0x%x pub rx/tx 0x%x:0x%x, priv send win 0x%x, pub 0x%x\n",
		fo->priv.rcv_win, fo->priv.snd_win, fo->pub.rcv_win, fo->pub.snd_win,
		fo->priv.snd_nxt + (fo->priv.snd_win << fo->priv.snd_win_shift),
		fo->pub.snd_nxt + (fo->pub.snd_win << fo->pub.snd_win_shift));
	printf("clnt ts_recent = %1$u (0x%1$x) svr ts_recent = %2$u (0x%2$x)\n", rte_be_to_cpu_32(client_fo->ts_recent), rte_be_to_cpu_32(server_fo->ts_recent));
	printf("WE WILL optimize pub s:n 0x%x:0x%x priv 0x%x:0x%x\n", fo->pub.snd_una, fo->pub.rcv_nxt, fo->priv.snd_una, fo->priv.rcv_nxt);
#endif
}

static bool
send_tcp_pkt(struct tcp_worker *w, struct tfo_pkt *pkt, struct tfo_tx_bufs *tx_bufs, struct tfo_side *fos, struct tfo_side *foos)
{
	uint32_t new_val32[2];
	uint16_t new_val16[1];

// NOTE: If we return false, an ACK might need to be sent
	if (!pkt->m) {
		printf("Request to send sack'd packet %p, seq 0x%x\n", pkt, pkt->seq);
		return false;
	}

#ifdef DEBUG_CHECKSUM
	check_checksum(pkt, "send_tcp_pkt");
#endif

	if (pkt->ns == timespec_to_ns(&w->ts)) {
		/* This can happen if receive delayed packet in same burst as the third duplicated ACK */
		return false;
	}

	if (rte_mbuf_refcnt_read(pkt->m) > 1) {
		/* Someone else is referencing the packet. It is presumably queued for sending */
		return false;
	}

	/* Update the ack */
	new_val32[0] = rte_cpu_to_be_32(fos->rcv_nxt);
	if (likely(pkt->tcp->recv_ack != new_val32[0])) {
		pkt->tcp->cksum = update_checksum(pkt->tcp->cksum, &pkt->tcp->recv_ack, new_val32, sizeof(pkt->tcp->recv_ack));

#ifdef DEBUG_CHECKSUM
		check_checksum(pkt, "After ack update");
#endif
	}

	/* Update the timestamp option if in use */
	if (pkt->ts) {
		/* The following is to ensure the order of assignment to new_val32[2] is correct.
		 * If the order is wrong it will produce a compilation error. */
		char dummy[(int)offsetof(struct tcp_timestamp_option, ts_ecr) - (int)offsetof(struct tcp_timestamp_option, ts_val)] __attribute__((unused));

		new_val32[0] = foos->ts_recent;
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

	if (pkt->flags & TFO_PKT_FL_SENT)
		pkt->flags |= TFO_PKT_FL_RESENT;
	else {
// update foos snd_nxt
		pkt->flags |= TFO_PKT_FL_SENT;
	}

	rte_pktmbuf_refcnt_update(pkt->m, 1);	/* so we keep it after it is sent */

	pkt->ns = timespec_to_ns(&w->ts);

	add_tx_buf(w, pkt->m, tx_bufs, pkt->flags & TFO_PKT_FL_FROM_PRIV, (union tfo_ip_p)pkt->ipv4);

	if (after(segend(pkt), fos->snd_nxt))
		fos->snd_nxt = segend(pkt);

	return true;
}

static inline struct tfo_pkt *
find_previous_pkt(struct list_head *pktlist, uint32_t seq)
{
	struct tfo_pkt *pkt;

	pkt = list_first_entry(pktlist, struct tfo_pkt, list);
	if (seq == pkt->seq)
		return pkt;
	if (before(seq, pkt->seq))
		return NULL;

	/* Iterate backward through the list */
	list_for_each_entry_reverse(pkt, pktlist, list) {
		if (!after(pkt->seq, seq))
			return pkt;
	}

	return NULL;
}

static inline void
unqueue_pkt(struct tfo_side *fos, struct tfo_pkt *pkt)
{
	if (list_is_first(&pkt->list, &fos->pktlist)) {
		if (before(fos->snd_una, pkt->seq) &&
		    (list_is_last(&pkt->list, &fos->pktlist) ||
		     before(segend(pkt), list_next_entry(pkt, list)->seq)))
			fos->sack_gap--;
		else if (!list_is_last(&pkt->list, &fos->pktlist) &&
			 !before(fos->snd_una, pkt->seq) &&
			 after(list_next_entry(pkt, list)->seq, fos->snd_una))
			fos->sack_gap++;
	} else {
		struct tfo_pkt *p_pkt = list_prev_entry(pkt, list);
		struct tfo_pkt *n_pkt = list_next_entry(pkt, list);

		if (before(segend(p_pkt), pkt->seq) &&
		    (list_is_last(&pkt->list, &fos->pktlist) ||
		     before(segend(pkt), list_next_entry(pkt, list)->seq)))
			fos->sack_gap--;
		else if (!list_is_last(&pkt->list, &fos->pktlist) &&
			 !before(segend(p_pkt), pkt->seq) &&
			 !before(segend(pkt), n_pkt->seq) &&
			 before(segend(p_pkt), n_pkt->seq))
			fos->sack_gap++;
	}
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

	if (vlan_new && vlan_cur) {
		vh->vlan_tci = rte_cpu_to_be_16(vlan_new);
	} else if (!vlan_new && !vlan_cur) {
		/* Do nothing */
	} else if (!vlan_new) {
		/* remove vlan encapsulation */
		eh->ether_type = vh->eth_proto;		// We could avoid this, and copy sizeof - 2
		memmove(rte_pktmbuf_adj(m, sizeof (struct rte_vlan_hdr)),
			eh, sizeof (struct rte_ether_hdr));
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
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
				if (p->ip4h)
					p->ip4h = (struct rte_ipv4_hdr *)((uint8_t *)p->ip4h + sizeof(struct rte_vlan_hdr));
				if (p->ip6h)
					p->ip6h = (struct rte_ipv6_hdr *)((uint8_t *)p->ip6h + sizeof(struct rte_vlan_hdr));
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
	}

#ifdef DEBUG_VLAN
	printf("Moving packet from vlan %u to %u\n", vlan_cur, vlan_new);
#endif

	return true;
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
queue_pkt(struct tcp_worker *w, struct tfo_side *foos, struct tfo_pkt_in *p, uint32_t seq)
{
	struct tfo_pkt *pkt;
	struct tfo_pkt *pkt_tmp;
	struct tfo_pkt *prev_pkt;
	uint32_t seg_end;
	uint32_t prev_end, next_seq;
	bool pkt_needed = false;
	uint16_t smaller_ent = 0;
	struct tfo_pkt *reusing_pkt = NULL;


	seg_end = seq + p->seglen;

	if (!after(seg_end, foos->snd_una)) {
#ifdef DEBUG_QUEUE_PKTS
		printf("queue_pkt seq 0x%x, len %u before our window\n", seq, p->seglen);
#endif
		return PKT_IN_LIST;
	}

	if (!list_empty(&foos->pktlist)) {
		uint32_t next_byte_needed = seq;
		struct tfo_pkt *prev_prev_pkt;
		struct tfo_pkt *last_pkt;

		prev_pkt = find_previous_pkt(&foos->pktlist, seq);
		if (prev_pkt) {
			next_byte_needed = segend(prev_pkt);

			if (!before(next_byte_needed, seg_end))
				return PKT_IN_LIST;

			/* If the packet before prev_pkt reaches this packet, prev_pkt is not needed */
			if (!list_is_first(&prev_pkt->list, &foos->pktlist)) {
				prev_prev_pkt = list_prev_entry(prev_pkt, list);
				if (!before(segend(prev_prev_pkt), seq)) {
					next_byte_needed = segend(prev_prev_pkt);
					if (before(prev_pkt->seq, seq)) {
						smaller_ent++;
						reusing_pkt = prev_pkt;
						unqueue_pkt(foos, prev_pkt);
						list_del_init(&prev_pkt->list);
						prev_pkt = prev_prev_pkt;
					}
				}
			}
			pkt = prev_pkt;
		} else
			pkt = list_first_entry(&foos->pktlist, struct tfo_pkt, list);

		last_pkt = list_last_entry(&foos->pktlist, struct tfo_pkt, list);
		if (before(segend(last_pkt), seg_end))
			pkt_needed = true;

		list_for_each_entry_safe_from(pkt, pkt_tmp, &foos->pktlist, list) {
			/* If previous packet does not reach the next packet, the new packet is needed */
			if (after(pkt->seq, next_byte_needed))
				pkt_needed = true;

			if (!before(pkt->seq, seg_end))
				break;

			last_pkt = pkt;

			next_byte_needed = segend(pkt);
			if (!before(pkt->seq, seq) && !after(segend(pkt), seg_end)) {
				smaller_ent++;
				unqueue_pkt(foos, pkt);
				if (pkt == prev_pkt) {
					if (list_is_first(&pkt->list, &foos->pktlist))
						prev_pkt = NULL;
					else
						prev_pkt = list_prev_entry(pkt, list);
				}
				if (!reusing_pkt) {
					reusing_pkt = pkt;
					list_del_init(&pkt->list);
				} else {
					pkt_free(w, foos, pkt);
					foos->pktcount--;
				}
			}

			if (!after(seg_end, segend(pkt)))
				break;
		}

		if (!pkt_needed && smaller_ent <= 1)
			return PKT_IN_LIST;

	} else {
		prev_pkt = NULL;
		pkt_needed = true;
	}

#ifdef DEBUG_QUEUE_PKTS
	if (prev_pkt)
		printf("prev_pkt 0x%x len %u, seq 0x%x len %u\n", prev_pkt->seq, prev_pkt->seglen, seq, p->seglen);
	else
		printf("No prev pkt\n");
#endif

	if (!update_pkt(p->m, p))
		return PKT_VLAN_ERR;

	if (reusing_pkt) {
		pkt = reusing_pkt;

#ifdef DEBUG_QUEUE_PKTS
		printf("Replacing shorter 0x%x %u\n", pkt->seq, pkt->seglen);
#endif
		if (pkt->m)
			rte_pktmbuf_free(pkt->m);
	} else {
#ifdef DEBUG_QUEUE_PKTS
		printf("In queue_pkt, refcount %u\n", rte_mbuf_refcnt_read(p->m));
#endif

		/* bufferize this packet */
		if (list_empty(&w->p_free))
			return NULL;

		pkt = list_first_entry(&w->p_free, struct tfo_pkt, list);
		list_del_init(&pkt->list);
		if (++w->p_use > w->p_max_use)
			w->p_max_use = w->p_use;
	}

	pkt->m = p->m;
	if (option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)
		p->m->ol_flags ^= config->dynflag_priv_mask;

	pkt->seq = seq;
	pkt->seglen = p->seglen;
	pkt->ipv4 = p->ip4h;
	pkt->tcp = p->tcp;
	pkt->flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
	pkt->ns = 0;
	pkt->ts = p->ts_opt;
	pkt->sack = p->sack_opt;

	if (!prev_pkt) {
#ifdef DEBUG_QUEUE_PKTS
		printf("Adding pkt at head %p m %p seq 0x%x to fo %p, vlan %u\n", pkt, pkt->m, seq, foos, p->m->vlan_tci);
#endif

		list_add(&pkt->list, &foos->pktlist);
	} else {
#ifdef DEBUG_QUEUE_PKTS
		printf("Adding packet not at head\n");
#endif

		list_add(&pkt->list, &prev_pkt->list);
	}

	if (!reusing_pkt)
		foos->pktcount++;

	next_seq = list_is_last(&pkt->list, &foos->pktlist) ? seg_end + 1 : list_next_entry(pkt, list)->seq;
	if (list_is_first(&pkt->list, &foos->pktlist))
		prev_end = foos->snd_una;
	else {
		struct tfo_pkt *p_pkt = list_prev_entry(pkt, list);

		prev_end = segend(p_pkt);
	}

	if (before(prev_end, next_seq)) {
		if (!before(prev_end, seq) && !list_is_last(&pkt->list, &foos->pktlist) && !before(seg_end, next_seq))
			foos->sack_gap--;
		else if (before(prev_end, seq) && (list_is_last(&pkt->list, &foos->pktlist) || before(seg_end, next_seq)))
			foos->sack_gap++;
	} else
		printf("ERROR - no gap to fill prev_end 0x%x, next_beg 0x%x, seq 0x%x, end 0x%x\n", prev_end, next_seq, seq, seg_end);

	return pkt;
}

static inline void
clear_optimize(struct tcp_worker *w, struct tfo_eflow *ef)
{
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_side *s;
	uint32_t rcv_nxt;
	struct tfo *fo;

	if (unlikely(ef->flags & TFO_EF_FL_STOP_OPTIMIZE))
		return;

	/* XXX stop current optimization */
	ef->flags |= TFO_EF_FL_STOP_OPTIMIZE;
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
					pkt_free(w, s, pkt);
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
		_eflow_free(w, ef);

		return;
	}
}

static void
_eflow_set_state(struct tcp_worker *w, struct tfo_eflow *ef, uint8_t new_state)
{
	--w->st.flow_state[ef->state];
	++w->st.flow_state[new_state];
	ef->state = new_state;

	if (new_state == TCP_STATE_BAD)
		clear_optimize(w, ef);
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

static enum tfo_pkt_state
tfo_handle_pkt(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo *fo;
	struct tfo_side *fos, *foos;
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_pkt *next_pkt;
	struct tfo_pkt *send_pkt;
	struct tfo_pkt *queued_pkt;
	uint64_t newest_send_time;
	bool duplicate;
	uint32_t seq;
	uint32_t ack;
	bool seq_ok = false;
	uint32_t snd_nxt;
	uint32_t win_end;
	uint32_t nxt_exp;
	struct rte_tcp_hdr* tcp = p->tcp;
	uint32_t rtt;
	bool rcv_nxt_updated = false;
	bool snd_win_updated = false;
	bool free_mbuf = false;
	uint16_t orig_vlan;
	enum tfo_pkt_state ret = TFO_PKT_HANDLED;
	bool fin_set;
	bool fin_rx;
	uint32_t last_seq;
	uint32_t new_win;
	bool fos_send_ack = false;
	bool fos_must_ack = false;
	bool fos_ack_from_queue = false;
	bool foos_send_ack = false;
	bool new_sack_info = false;
	uint32_t incr;
	uint32_t bytes_sent;
	bool snd_wnd_increased = false;

// Need:
//    If syn+ack does not have window scaling, set scale to 0 on original side
//   window from last rx packet (also get from SYN/SYN+ACK/ACK)
	if (ef->tfo_idx == TFO_IDX_UNUSED) {
		printf("tfo_handle_pkt called without flow\n");
		return TFO_PKT_FORWARD;
	}

	fo = &w->f[ef->tfo_idx];

	/* If we have received a FIN on this side, we must not receive any
	 * later data. */
	fin_rx = ((ef->state == TCP_STATE_FIN1 &&
		   !!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) == !!(p->from_priv)) ||
		  ef->state == TCP_STATE_FIN2);

	orig_vlan = p->m->vlan_tci;

	if (p->from_priv) {
		fos = &fo->priv;
		foos = &fo->pub;

		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG))
			p->m->vlan_tci = pub_vlan_tci;
	} else {
		fos = &fo->pub;
		foos = &fo->priv;

		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG))
			p->m->vlan_tci = priv_vlan_tci;
	}

	/* Save the ttl/hop_limit to use when generating acks */
	fos->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->ip6h->hop_limits : p->ip4h->time_to_live;

#ifdef DEBUG_PKT_RX
	printf("Handling packet, state %u,from %s, seq 0x%x, ack 0x%x, rx_win 0x%x, fos: snd_una 0x%x, snd_nxt 0x%x rcv_nxt 0x%x foos 0x%x 0x%x 0x%x\n",
		ef->state, p->from_priv ? "priv" : "pub", rte_be_to_cpu_32(tcp->sent_seq), rte_be_to_cpu_32(tcp->recv_ack),
		rte_be_to_cpu_16(tcp->rx_win), fos->snd_una, fos->snd_nxt, fos->rcv_nxt, foos->snd_una, foos->snd_nxt, foos->rcv_nxt);
#endif


// Handle RST
	if (unlikely(!(tcp->tcp_flags & RTE_TCP_ACK_FLAG))) {
		/* This is invalid, unless RST */
		return TFO_PKT_FORWARD;
	}

	fin_set = !!unlikely((tcp->tcp_flags & RTE_TCP_FIN_FLAG));

// This should be optimized, but for now we just want to get it working
	if (ef->flags & (TFO_EF_FL_TIMESTAMP | TFO_EF_FL_SACK)) {
		if (!set_estab_options(p, ef)) {
			/* There was something wrong with the options -
			 * stop optimizing. */
			_eflow_set_state(w, ef, TCP_STATE_BAD);
			return TFO_PKT_FORWARD;
		}
	}

	ack = rte_be_to_cpu_32(tcp->recv_ack);

	/* ack obviously out of range. stop optimizing this connection */
// See RFC7232 2.3 for this

//CHECK ACK AND SEQ NOT OLD
	/* This may be a duplicate */
	if (between_beg_ex(ack, fos->snd_una, fos->snd_nxt)) {
#ifdef DEBUG_ACK
		printf("Looking to remove ack'd packets\n");
#endif

		/* RFC5681 3.2 */
		if (fos->cwnd < fos->ssthresh)
			fos->cwnd += min(ack - fos->snd_una, fos->mss);
		else {
			/* This is a approximation - eqn (3).
			 * There are better ways to do this. */
			incr = fos->mss * fos->mss / fos->cwnd;
			fos->cwnd += incr ? incr : 1;
		}

		snd_wnd_increased = true;
		fos->snd_una = ack;
		fos->dup_ack = 0;

		/* remove acked buffered packets. We want the time the
		 * most recent packet was sent to update the RTT. */
		newest_send_time = 0;
		list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
#ifdef DEBUG_ACK_PKT_LIST
			printf("  pkt->seq 0x%x pkt->seglen 0x%x, tcp_flags 0x%x, ack 0x%x\n", pkt->seq, pkt->seglen, p->tcp->tcp_flags, ack);
#endif

			if (unlikely(after(segend(pkt), ack)))
				break;

// If have timestamps, don't do the next bit
			if (pkt->m && pkt->ns > newest_send_time) {
				newest_send_time = pkt->ns;
// Compare timestamp and clear duplicate if timestamp present
// We could use timestamp to calculate rtt of packet
// else
				duplicate = !!(pkt->flags & TFO_PKT_FL_RESENT);
			}

			/* acked, remove buffered packet */
#ifdef DEBUG_ACK
			printf("Calling pkt_free m %p, seq 0x%x\n", pkt->m, pkt->seq);
#endif
			pkt_free(w, fos, pkt);
		}

		if ((ef->flags & TFO_EF_FL_SACK) && fos->sack_entries)
			update_sack_for_ack(fos);

		/* Do RTT calculation on newest_pkt */
		if (newest_send_time && !duplicate) {
			/* rtt/rto computation. got ack for packet we sent
			 * (or a later packet, meaning our data packet is acked) */
			/* rfc6298 */
// See http://ccr.sigcomm.org/archive/1995/jan95/ccr-9501-partridge87.pdf for Kahn's algorithm
//  and https://ee.lbl.gov/papers/congavoid.pdf for Jacobson
// Consider using timestamps
// It appears we are operating in ms. How long does it take to send a packet and a reply at 100Gbps?
// Check pcap files to see shortest time.
// change w->rs to be uint64_t ns counter
// Since using ms, store times in ms rather than ns
			rtt = (timespec_to_ns(&w->ts) - newest_send_time) / 1000000;
			if (!fos->srtt) {
				fos->srtt = rtt;
				fos->rttvar = rtt / 2;
			} else {
				fos->rttvar = (fos->rttvar * 3 + (fos->srtt > rtt ? (fos->srtt - rtt) : (rtt - fos->srtt))) / 4;
				fos->srtt = (fos->srtt * 7 + rtt) / 8;
			}
			fos->rto = fos->srtt + max(TFO_TCP_RTO_MIN, fos->rttvar * 4);

			if (fos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
				printf("New running rto %u, reducing to 60000\n", fos->rto);
#endif
				fos->rto = 60 * 1000;
			}
		}
	} else if (fos->snd_una == ack &&
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
			if (++fos->dup_ack == 3) {
				/* RFC5681 3.2 - fast recovery */

				if (fos->snd_una == send_pkt->seq) {
					/* We have the first packet, so resend it */
#ifdef DEBUG_RFC5681
					printf("RESENDING m %p seq 0x%x, len %u due to 3 duplicate ACKS\n", send_pkt, send_pkt->seq, send_pkt->seglen);
#endif

#ifdef DEBUG_CHECKSUM
					check_checksum(send_pkt, "RESENDING");
#endif
//printf("send_tcp_pkt A\n");
					send_tcp_pkt(w, send_pkt, tx_bufs, fos, foos);
				}

				/* RFC5681 3.2.2 */
				fos->ssthresh = max((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
				fos->cwnd = fos->ssthresh + 3 * fos->mss;
			} else if (fos->dup_ack > 3) {
				/* RFC5681 3.2.4 */
				fos->cwnd += fos->mss;

				if ((!(list_last_entry(&fos->pktlist, struct tfo_pkt, list)->flags & TFO_PKT_FL_SENT))) {
					/* RFC5681 3.2.5 - we can send up to MSS bytes if within limits */
					list_for_each_entry_reverse(pkt, &fos->pktlist, list) {
						if (pkt->flags & TFO_PKT_FL_SENT)
							break;
						send_pkt = pkt;
					}

					bytes_sent = 0;
					win_end = get_snd_win_end(fos);
					while (!after(segend(send_pkt), win_end) &&
					       !after(bytes_sent + send_pkt->seglen, fos->mss)) {
						bytes_sent += send_pkt->seglen;
#ifdef DEBUG_RFC5681
						printf("SENDING new packet m %p seq 0x%x, len %u due to %u duplicate ACKS\n", send_pkt, send_pkt->seq, send_pkt->seglen, fos->dup_ack);
#endif

#ifdef DEBUG_CHECKSUM
						check_checksum(send_pkt, "RESENDING");
#endif
//printf("send_tcp_pkt Z\n");
						send_tcp_pkt(w, send_pkt, tx_bufs, fos, foos);

						if (list_is_last(&send_pkt->list, &fos->pktlist))
							break;
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

	if (p->sack_opt) {
		/* Remove all packets ACK'd via SACK */
		uint32_t left_edge, right_edge;
		uint8_t sack_ent, num_sack_ent;
		struct tfo_pkt *sack_pkt;
		struct tfo_pkt *resend = NULL;

// For elsewhere - if get SACK and !resent snd_una packet recently (whatever that means), resent unack'd packets not recently resent.
// If don't have them, send ACK to other side if not sending packets
		num_sack_ent = (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges);
#ifdef DEBUG_SACK_RX
		printf("Handling SACK with %u entries\n", num_sack_ent);
#endif

		for (sack_ent = 0; sack_ent < num_sack_ent; sack_ent++) {
			left_edge = rte_be_to_cpu_32(p->sack_opt->edges[sack_ent].left_edge);
			right_edge = rte_be_to_cpu_32(p->sack_opt->edges[sack_ent].right_edge);
#ifdef DEBUG_SACK_RX
			printf("  %u: 0x%x -> 0x%x\n", sack_ent,
				rte_be_to_cpu_32(p->sack_opt->edges[sack_ent].left_edge),
				rte_be_to_cpu_32(p->sack_opt->edges[sack_ent].right_edge));
#endif

			sack_pkt = NULL;
			last_seq = fos->snd_una;
			list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
				if (after(segend(pkt), right_edge)) {
#ifdef DEBUG_SACK_RX
					printf("     0x%x + %u (0x%x) after window\n",
						pkt->seq, pkt->seglen, segend(pkt));
#endif
					break;
				}

				if (!before(pkt->seq, left_edge)) {
#ifdef DEBUG_SACK_RX
					printf("     0x%x + %u (0x%x) in window, resend %p\n",
						pkt->seq, pkt->seglen, segend(pkt), resend);
#endif

					if (pkt->m) {
						/* This is being "ack'd" for the first time */
						new_sack_info = true;
						if (pkt->ns > newest_send_time) {
							newest_send_time = pkt->ns;
							duplicate = !!(pkt->flags & TFO_PKT_FL_RESENT);
						}
					}

					if (after(pkt->seq, last_seq))
						sack_pkt = NULL;

					if (!sack_pkt) {
						sack_pkt = pkt;
						if (pkt->m)
							pkt_free_mbuf(pkt);
#ifdef DEBUG_SACK_RX
						printf("sack pkt now 0x%x, len %u\n", pkt->seq, pkt->seglen);
#endif
					} else {
						if (after(segend(pkt), segend(sack_pkt)))
							sack_pkt->seglen = segend(pkt) - sack_pkt->seq;
						pkt_free(w, fos, pkt);
#ifdef DEBUG_SACK_RX
						printf("sack pkt updated 0x%x, len %u\n", sack_pkt->seq, sack_pkt->seglen);
#endif
					}

					/* If the following packet is a sack entry and there is no gap between this
					 * sack entry and the next, and the next entry extends beyond right_edge,
					 * merge them */
					if (!list_is_last(&sack_pkt->list, &fos->pktlist)) {
						next_pkt = list_next_entry(sack_pkt, list);
						if (!next_pkt->m &&
						    !before(segend(sack_pkt), next_pkt->seq) &&
						    after(segend(next_pkt), right_edge)) {
							sack_pkt->seglen = segend(next_pkt) - sack_pkt->seq;
							pkt_free(w, fos, next_pkt);
							break;
						}
					}
				} else {
#ifdef DEBUG_SACK_RX
					printf("pkt->m %p, resend %p", pkt->m, resend);
#endif
					if (!pkt->m) {
						sack_pkt = pkt;
						resend = NULL;
					} else
						sack_pkt = NULL;
#ifdef DEBUG_SACK_RX
					printf(" now %p\n", resend);
#endif
				}

				last_seq = segend(pkt);
			}
		}

		if (likely(!list_empty(&fos->pktlist))) {
			if (fos->dup_ack != 3)
				printf("NOT sending ACK/packet following SACK since dup_ack == %u\n", fos->dup_ack);
		}
	}

	if (fos->dup_ack &&
	    fos->dup_ack < 3 &&
	    !list_empty(&fos->pktlist) &&
	    (!(list_last_entry(&fos->pktlist, struct tfo_pkt, list)->flags & TFO_PKT_FL_SENT)) &&
	    (!(ef->flags & TFO_EF_FL_SACK) || new_sack_info)) {
		/* RFC5681 3.2.1 - we can send an unset packet if it is within limits */
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
			send_tcp_pkt(w, send_pkt, tx_bufs, fos, foos);
		}
	}

// See RFC 7323 2.3 - it says seq must be within 2^31 bytes of left edge of window,
//  otherwise it should be discarded as "old"
	/* Window scaling is rfc7323 */
	win_end = fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift);

// should the following only happen if not sack?
	if (fos->snd_una == ack && !list_empty(&fos->pktlist)) {
		pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
		if (pkt->flags & TFO_PKT_FL_SENT &&
		    timespec_to_ns(&w->ts) > packet_timeout(pkt->ns, fos->rto) &&
		    !after(segend(pkt), win_end) &&
		    pkt->m) {		/* first entry should never have been sack'd */
#ifdef DEBUG_ACK
			printf("Resending seq 0x%x due to repeat ack and timeout, now %lu, rto %u, pkt tmo %lu\n",
				ack, timespec_to_ns(&w->ts), fos->rto, packet_timeout(pkt->ns, fos->rto));
#endif
//printf("send_tcp_pkt C\n");
			send_tcp_pkt(w, list_first_entry(&fos->pktlist, typeof(*pkt), list), tx_bufs, fos, foos);
		}
	}

	/* If we are no longer optimizing, then the ACK is the only thing we want
	 * to deal with. */
	if (ef->flags & TFO_EF_FL_STOP_OPTIMIZE)
		return TFO_PKT_FORWARD;

// If have timestamp option, we just compare pkt->TSecr against w->rs.tv_sec, except TSecr is only 32 bits long.

// NOTE: RFC793 says SEQ + WIN should never be reduced - i.e. once a window is given
//  it will be able to be filled.
// BUT: RFC7323 2.4 says the window can be reduced (due to window scaling)
	seq = rte_be_to_cpu_32(p->tcp->sent_seq);

	if (unlikely(!fin_rx && fin_set))
		fos->fin_seq = seq + p->seglen;

	/* Check seq is in valid range */
	seq_ok = check_seq(seq, p->seglen, win_end, fos);

	if (!seq_ok) {
		/* Packet is either bogus or duplicate */
// Sort out duplicate behind our window
//		return NULL;
#ifdef DEBUG_TCP_WINDOW
		printf("seq 0x%x len %u is outside rx window fos->rcv_nxt 0x%x -> 0x%x (+0x%x << %u)\n", seq, p->seglen, fos->rcv_nxt, win_end, fos->rcv_win, fos->rcv_win_shift);
#endif
		if (before(seq, fos->rcv_nxt)) {
// This may want optimizing, and also think about SACKs
#ifdef DEBUG_RFC5681
			printf("Sending ack for duplicate seq 0x%x len 0x%x already ack'd, orig_vlan %u\n", seq, p->seglen, orig_vlan);
#endif

			_send_ack_pkt_in(w, ef, fos, p, NULL, orig_vlan, foos, tx_bufs, false, false);

			rte_pktmbuf_free(p->m);

			return TFO_PKT_HANDLED;
		}
	} else {
		/* Check no data received after FIN */
// We don't appear to get here
		if (unlikely(fin_rx) && after(seq, fos->fin_seq))
			ret = TFO_PKT_FORWARD;

		/* Update the send window */
#ifdef DEBUG_TCP_WINDOW
		printf("fos->rcv_nxt 0x%x, fos->rcv_win 0x%x rcv_win_shift %u = 0x%x: seg 0x%x p->seglen 0x%x, tcp->rx_win 0x%x = 0x%x\n",
			fos->rcv_nxt, fos->rcv_win, fos->rcv_win_shift, fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift),
			seq, p->seglen , rte_be_to_cpu_16(tcp->rx_win), seq + p->seglen + (rte_be_to_cpu_16(tcp->rx_win) << fos->rcv_win_shift));
#endif

// This is merely reflecting the same window though.
// This should be optimised to allow a larger window that we buffer.
		if (before(fos->snd_una + (fos->snd_win << fos->snd_win_shift),
			   ack + (rte_be_to_cpu_16(tcp->rx_win) << fos->snd_win_shift)))
			snd_win_updated = true;

#ifdef DEBUG_TCP_WINDOW
		if (fos->snd_una + (fos->snd_win << snd_wind_shift) !=
			   ack + (rte_be_to_cpu_16(tcp->rx_win) << snd_wind_shift))
			printf("fos->snd_win updated from 0x%x to 0x%x\n", fos->snd_win, rte_be_to_cpu_16(tcp->rx_win));
#endif
		fos->snd_win = rte_be_to_cpu_16(tcp->rx_win);

#ifdef DEBUG_TCP_WINDOW
		if (!foos->rcv_win)
			printf("snd_win_updated %d foos rcv_win 0x%x rcv_nxt 0x%x fos snd_win 0x%x snd_win_shift 0x%x\n",
				snd_win_updated, foos->rcv_win, foos->rcv_nxt, fos->snd_win, fos->snd_win_shift);
#endif

		if (snd_win_updated && foos->rcv_win == 0 &&
		    before(foos->rcv_nxt, fos->snd_una + (fos->snd_win << fos->snd_win_shift))) {
			/* If the window is extended, (or at least not full),
			 * send an ack on foos */
			foos_send_ack = true;
		}

		/* RFC 7323 4.3 (2) */
		if ((ef->flags & TFO_EF_FL_TIMESTAMP) &&
		    after(rte_be_to_cpu_32(p->ts_opt->ts_val), rte_be_to_cpu_32(fos->ts_recent)) &&
		    !after(seq, fos->rcv_nxt))
			fos->ts_recent = p->ts_opt->ts_val;

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
			fos_send_ack = true;

			fos->rcv_nxt = seq + p->seglen;
			rcv_nxt_updated = true;
		}
	}

	if (seq_ok && p->seglen) {
		/* Queue the packet, and see if we can advance fos->rcv_nxt further */
		queued_pkt = queue_pkt(w, foos, p, seq);
		fos_ack_from_queue = true;

// LOOK AT THIS ON PAPER TO WORK OUT WHAT IS HAPPENING
		if (unlikely(queued_pkt == PKT_IN_LIST)) {
			/* The packet has already been received */
			free_mbuf = true;
			ret = TFO_PKT_HANDLED;
		} else if (unlikely(queued_pkt == PKT_VLAN_ERR)) {
			/* The Vlan header could not be added */
			_eflow_set_state(w, ef, TCP_STATE_BAD);

			/* The packet can't be forwarded, so don't return TFO_PKT_FORWARD */
			ret = TFO_PKT_HANDLED;
// This might confuse things later
		} else if (!queued_pkt) {
			if (!(ef->flags & TFO_EF_FL_STOP_OPTIMIZE))
				_eflow_set_state(w, ef, TCP_STATE_BAD);

			ret = TFO_PKT_FORWARD;
		}
#ifdef DEBUG_SND_NXT
		else {
			printf("Queued packet m %p seq 0x%x, len %u, rcv_nxt_updated %d\n",
				queued_pkt->m, queued_pkt->seq, queued_pkt->seglen, rcv_nxt_updated);
		}
#endif

		if (likely(queued_pkt != PKT_IN_LIST && queued_pkt != PKT_VLAN_ERR)) {
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

#ifdef DEBUG_SND_NXT
					printf("Checking pkt m %p, seq 0x%x, seglen %u, fos->rcv_nxt 0x%x\n",
						pkt->m, pkt->seq, pkt->seglen, fos->rcv_nxt);
#endif
					fos->rcv_nxt = segend(pkt);
				}
			} else {
				/* If !rcv_nxt_updated, we must have a missing packet, so resent ack */
				fos_must_ack = true;
			}
		}
	}

	fos_send_ack = rcv_nxt_updated;

// COMBINE THE NEXT TWO blocks
// What is limit of no of timeouted packets to send?
	/* Are there sent packets whose timeout has expired */
	if (!list_empty(&fos->pktlist)) {
		pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
// Sort out this check - first packet should never have been sack'd
		if (pkt->m &&
		    !after(segend(pkt), win_end) &&
		    packet_timeout(pkt->ns, fos->rto) < timespec_to_ns(&w->ts)) {
#ifdef DEBUG_RTO
			printf("Resending m %p pkt %p timeout pkt->ns %lu fos->rto %u w->ts %ld.%9.9ld\n",
				pkt->m, pkt, pkt->ns, fos->rto, w->ts.tv_sec, w->ts.tv_nsec);
#endif

//printf("send_tcp_pkt D\n");
			send_tcp_pkt(w, pkt, tx_bufs, fos, foos);
			fos->rto *= 2;		/* See RFC6928 5.5 */
			if (fos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
				printf("rto fos resend after timeout double %u - reducing to 60000\n", fos->rto);
#endif
				fos->rto = 60 * 1000;
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
			if (!(pkt->flags & TFO_PKT_FL_SENT)) {
#ifdef DEBUG_SND_NXT
				printf("snd_next 0x%x, fos->snd_nxt 0x%x\n", segend(pkt), fos->snd_nxt);
#endif

//printf("send_tcp_pkt E\n");
				send_tcp_pkt(w, pkt, tx_bufs, fos, foos);
				fos_send_ack = false;
			}
		}
	}

	/* Are there sent packets on other side whose timeout has expired */
	win_end = get_snd_win_end(foos);

	if (!list_empty(&foos->pktlist)) {
		pkt = list_first_entry(&foos->pktlist, typeof(*pkt), list);

// Sort out this check - the first entry should never have been sack'd
		if (pkt->m &&
		    !after(segend(pkt), win_end)) {
			if (!(pkt->flags & TFO_PKT_FL_SENT)) {
#ifdef DEBUG_RTO
				printf("snd_next 0x%x, foos->snd_nxt 0x%x\n", segend(pkt), foos->snd_nxt);
#endif

//printf("send_tcp_pkt F\n");
				send_tcp_pkt(w, pkt, tx_bufs, foos, fos);
			} else if (packet_timeout(pkt->ns, foos->rto) < timespec_to_ns(&w->ts)) {
#ifdef DEBUG_RTO
				printf("Resending packet %p on foos for timeout, pkt flags 0x%x ns %lu foos->rto %u w time %ld.%9.9ld\n",
					pkt->m, pkt->flags, pkt->ns, foos->rto, w->ts.tv_sec, w->ts.tv_nsec);
#endif

//printf("send_tcp_pkt G\n");
				send_tcp_pkt(w, pkt, tx_bufs, foos, fos);
				foos->rto *= 2;		/* See RFC6928 5.5 */

				if (foos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
					printf("rto foos resend after timeout double %u - reducing to 60000\n", foos->rto);
#endif
					foos->rto = 60 * 1000;
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
				pkt->seq, pkt->flags, pkt->seglen, ((pkt->tcp->data_off << 8) | pkt->tcp->tcp_flags) & 0xfff, foos->snd_nxt);
#endif

		if (after(segend(pkt), win_end))
			break;
		if (!(pkt->flags & TFO_PKT_FL_SENT)) {
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

//printf("send_tcp_pkt H\n");
			send_tcp_pkt(w, pkt, tx_bufs, foos, fos);
		}
	}

	if (fos_send_ack || fos_must_ack) {
		if (fos_ack_from_queue) {
			struct tfo_pkt unq_pkt;
			struct tfo_pkt *pkt_in = queued_pkt;
			if (!queued_pkt || queued_pkt == PKT_IN_LIST || queued_pkt == PKT_VLAN_ERR) {
				pkt_in = &unq_pkt;
				unq_pkt.ipv4 = p->ip4h;
				unq_pkt.tcp = p->tcp;
				unq_pkt.m = p->m;
				unq_pkt.flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
			}
			_send_ack_pkt(w, ef, fos, pkt_in, NULL, orig_vlan, foos, tx_bufs, true, false);
		} else
			_send_ack_pkt_in(w, ef, fos, p, NULL, orig_vlan, foos, tx_bufs, false, false);
	}
	if (foos_send_ack)
		_send_ack_pkt_in(w, ef, foos, p, NULL, p->from_priv ? pub_vlan_tci : priv_vlan_tci, fos, tx_bufs, false, true);

	if (fin_set && !fin_rx) {
		fos->fin_seq = seq + p->seglen;
#ifdef DEBUG_FIN
		printf("Set fin_seq 0x%x - seq 0x%x seglen %u\n", fos->fin_seq, seq, p->seglen);
#endif
	}

	if (unlikely(free_mbuf)) {
		rte_pktmbuf_free(p->m);
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
 *   TCP_STATE_FIN1: connection closing (fin seen in 1 way)
 *   TCP_STATE_FIN2: connection closing (fin seen in 2 way)
 *   TCP_STATE_RESET: reset state
 *   TCP_STATE_BAD: bad state
 */
static enum tfo_pkt_state
tfo_tcp_sm(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	uint8_t tcp_flags = p->tcp->tcp_flags;
	struct tfo_side *server_fo, *client_fo;
	uint32_t ack;
	uint32_t seq;
	struct tfo *fo;
	uint32_t win_end;
	bool seq_ok;
	enum tfo_pkt_state ret = TFO_PKT_FORWARD;

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

	/* reset flag, stop everything */
	if (unlikely(tcp_flags & RTE_TCP_RST_FLAG)) {
// We might want to ensure all queued packets on other side are ack'd first before forwarding RST - but with a timeout
		++w->st.rst_pkt;
		_eflow_free(w, ef);

		return TFO_PKT_FORWARD;
	}

	/* RST flag unset */

	/* Most packets will be in established state with ACK set */
	if ((likely(ef->state == TCP_STATE_ESTABLISHED) ||
	     unlikely(ef->state == TCP_STATE_FIN1) ||
	     unlikely(ef->state == TCP_STATE_FIN2)) &&
	    (likely((tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_RST_FLAG)) == RTE_TCP_ACK_FLAG))) {
		set_estb_pkt_counts(w, tcp_flags);

		ret = tfo_handle_pkt(w, p, ef, tx_bufs);

		/* FIN, and ACK after FIN need more processing */
		if (likely(!(tcp_flags & RTE_TCP_FIN_FLAG) &&
			   ef->state != TCP_STATE_FIN2))
			return ret;
	}

#ifdef DEBUG_CHECK_ADDR
	printf("ef->state %u tcp_flags 0x%x p->tcp %p p->tcp->tcp_flags 0x%x ret %u\n", ef->state, tcp_flags, p->tcp, p->tcp->tcp_flags, ret);
#endif

	if (unlikely(ef->flags & TFO_EF_FL_STOP_OPTIMIZE)) {
		fo = &w->f[ef->tfo_idx];
		if (list_empty(&fo->priv.pktlist) &&
		    list_empty(&fo->pub.pktlist)) {
			/* The pkt queues are now empty. */
			_eflow_free(w, ef);
		}

		return TFO_PKT_FORWARD;
	}

	/* A duplicate SYN could have no ACK, otherwise it is an error */
	if (unlikely(!(tcp_flags & RTE_TCP_ACK_FLAG) &&
		     ef->state != TCP_STATE_SYN)) {
		++w->st.estb_noflag_pkt;
		_eflow_set_state(w, ef, TCP_STATE_BAD);

		return ret;
	}

// Assume SYN and FIN packets can contain data - see last para p26 of RFC793,
//   i.e. before sequence number selection
	/* syn flag */
	if (tcp_flags & RTE_TCP_SYN_FLAG) {
		/* invalid packet, won't optimize */
		if (tcp_flags & RTE_TCP_FIN_FLAG) {
// Should only have ACK, ECE (and ? PSH, URG)
// We should delay forwarding FIN until have received ACK for all data we have ACK'd
// Not sure about RST
			_eflow_set_state(w, ef, TCP_STATE_BAD);
			++w->st.syn_bad_flag_pkt;
			return ret;
		}

		switch (ef->state) {
		case TCP_STATE_SYN_ACK:
			if ((tcp_flags & RTE_TCP_ACK_FLAG)) {
				/* duplicate syn+ack */
				++w->st.syn_ack_dup_pkt;
				ef->flags |= TFO_EF_FL_DUPLICATE_SYN;
				break;
			}
			/* fallthrough */

		case TCP_STATE_ESTABLISHED:
			if (tcp_flags & RTE_TCP_ACK_FLAG)
				++w->st.syn_ack_on_eflow_pkt;
			else
				++w->st.syn_on_eflow_pkt;

			/* already optimizing, this is a new flow ? free current */
			/* XXX todo */
			_eflow_set_state(w, ef, TCP_STATE_BAD);
			break;

		case TCP_STATE_SYN:
			/* syn flag alone */
			if (!(tcp_flags & RTE_TCP_ACK_FLAG)) {
				if (!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) ==
				    !!p->from_priv) {
					/* duplicate of first syn */
					++w->st.syn_dup_pkt;
					ef->flags |= TFO_EF_FL_DUPLICATE_SYN;
				} else if (!(ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN)) {
					/* simultaneous open, let it go */
					++w->st.syn_simlt_open_pkt;
					ef->flags |= TFO_EF_FL_SIMULTANEOUS_OPEN;
				}
				break;
			}

			/* SYN and ACK flags set */

			if (unlikely(ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN)) {
				/* syn+ack from one side, too complex, don't optimize */
				_eflow_set_state(w, ef, TCP_STATE_SYN_ACK);
// When allow this, look at normal code for going to SYN_ACK
_eflow_set_state(w, ef, TCP_STATE_BAD);
ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
				++w->st.syn_ack_pkt;
			} else if (likely(!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) != !!p->from_priv)) {
				/* syn+ack from other side */
				ack = rte_be_to_cpu_32(p->tcp->recv_ack);
				if (unlikely(!between_beg_ex(ack, ef->server_snd_una, ef->client_rcv_nxt))) {
#ifdef DEBUG_SM
					printf("SYN seq does not match SYN+ACK recv_ack, snd_una %x ack %x client_rcv_nxt %x\n", ef->server_snd_una, ack, ef->client_rcv_nxt);
#endif

					_eflow_set_state(w, ef, TCP_STATE_BAD);
					++w->st.syn_bad_pkt;
					break;
				}

				if (!set_tcp_options(p, ef)) {
					_eflow_set_state(w, ef, TCP_STATE_BAD);
					++w->st.syn_bad_pkt;
					break;
				}

				_eflow_set_state(w, ef, TCP_STATE_SYN_ACK);
				check_do_optimize(w, p, ef);
// Do initial RTT if none for user, otherwise ignore due to additional time for connection establishment
// RTT is per user on private side, per flow on public side
				++w->st.syn_ack_pkt;
// Reply to SYN+ACK with ACK - we essentially go to ESTABLISHED processing
// This means the SYN+ACK needs to be queued on client side - must not change timestamp though on that
			} else {
// Could be duplicate SYN+ACK
				/* bad sequence, won't optimize */
				_eflow_set_state(w, ef, TCP_STATE_BAD);
				++w->st.syn_ack_bad_pkt;
			}
			break;

		default:
			/* we're in fin, rst, or bad state */
			++w->st.syn_bad_state_pkt;
			break;
		}
		return ret;
	}

	/* SYN and RST flags unset */

	/* fin flag */
	if (tcp_flags & RTE_TCP_FIN_FLAG) {
		switch (ef->state) {
		case TCP_STATE_SYN:
		case TCP_STATE_SYN_ACK:
		default:
// Setting state BAD should stop optimisation
			_eflow_set_state(w, ef, TCP_STATE_BAD);
			++w->st.fin_unexpected_pkt;

			return ret;

		case TCP_STATE_ESTABLISHED:
			if (ret == TFO_PKT_HANDLED) {
				_eflow_set_state(w, ef, TCP_STATE_FIN1);
				if (p->from_priv)
					ef->flags |= TFO_EF_FL_FIN_FROM_PRIV;
			}

			++w->st.fin_pkt;

			return ret;

		case TCP_STATE_FIN1:
			if (!!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) != !!p->from_priv) {
				if (ret == TFO_PKT_HANDLED)
					_eflow_set_state(w, ef, TCP_STATE_FIN2);

				++w->st.fin_pkt;
			} else
				++w->st.fin_dup_pkt;

			return ret;

		case TCP_STATE_FIN2:
			++w->st.fin_dup_pkt;
			break;
		}

		return ret;
	}

	/* SYN, FIN and RST flags unset */

	if (ef->state == TCP_STATE_SYN_ACK && (tcp_flags & RTE_TCP_ACK_FLAG) &&
	    !!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) == !!p->from_priv) {
// We should just call handle_pkt, which detects state SYN_ACK and if pkt ok transitions to ESTABLISHED
		fo = &w->f[ef->tfo_idx];
		if (p->from_priv) {
			server_fo = &fo->pub;
			client_fo = &fo->priv;
		} else {
			server_fo = &fo->priv;
			client_fo = &fo->pub;
		}

// We should only receive more data from server after we have forwarded 3rd ACK unless arrive out of sequence,
//  in which case 3rd ACK can be dropped when receive
		ack = rte_be_to_cpu_32(p->tcp->recv_ack);
		seq = rte_be_to_cpu_32(p->tcp->sent_seq);

// See RFC 7232 2.3
		/* Window scaling is rfc7323 */
		win_end = get_snd_win_end(client_fo);
#ifdef DEBUG_TCP_WINDOW
		printf("rcv_win 0x%x cl rcv_nxt 0x%x rcv_win 0x%x win_shift %u cwnd %u\n",
			win_end, client_fo->rcv_nxt, client_fo->rcv_win, client_fo->rcv_win_shift, client_fo->cwnd);
#endif

		/* Check seq is in valid range */
		seq_ok = check_seq(seq, p->seglen, win_end, client_fo);

		if (unlikely(!between_beg_ex(ack, client_fo->snd_una, client_fo->snd_nxt) ||
			     !seq_ok)) {
#ifdef DEBUG_SM
			printf("ACK to SYN_ACK%s%s mismatch, seq:ack packet 0x%x:0x%x saved rn 0x%x rw 0x%x su 0x%x sn 0x%x\n",
				!between_beg_ex(ack, client_fo->snd_una, client_fo->snd_nxt) ? " ack" : "",
				seq_ok ? "" : " seq",
				rte_be_to_cpu_32(p->tcp->sent_seq),
				rte_be_to_cpu_32(p->tcp->recv_ack),
				client_fo->rcv_nxt, client_fo->rcv_win,
				client_fo->snd_una, client_fo->snd_nxt);
#endif

			_eflow_set_state(w, ef, TCP_STATE_BAD);

			return TFO_PKT_FORWARD;
		}

		/* last ack of 3way handshake, go to established state */
// It might have data, so handle_pkt needs to be called
		_eflow_set_state(w, ef, TCP_STATE_ESTABLISHED);
// Set next in send_pkt
		client_fo->snd_una = ack;
		server_fo->rcv_nxt = rte_be_to_cpu_32(p->tcp->recv_ack);
		client_fo->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->ip6h->hop_limits : p->ip4h->time_to_live;
		set_estab_options(p, ef);
		if (p->ts_opt)
			client_fo->ts_recent = p->ts_opt->ts_val;
set_estb_pkt_counts(w, tcp_flags);

		if (payload_len(p))
			return tfo_handle_pkt(w, p, ef, tx_bufs);

		return TFO_PKT_FORWARD;
	}

	if (ef->state == TCP_STATE_FIN2 && (tcp_flags & RTE_TCP_ACK_FLAG)) {
		/* ack in fin2 state, go to time_wait state if all pkts ack'd */
		fo = &w->f[ef->tfo_idx];
#ifdef DEBUG_SM
		printf("FIN2 - cl rcv_nxt 0x%x fin_seq 0x%x, sv rcv_nxt 0x%x fin_seq 0x%x ret %u\n",
			fo->priv.rcv_nxt, fo->priv.fin_seq, fo->pub.rcv_nxt, fo->pub.fin_seq, ret);
#endif
		if (!!p->from_priv == !!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) &&
		    payload_len(p)) {
			if (ret == TFO_PKT_HANDLED) {
// We should not need fin_seq - it will be seq of last packet on queue
				if (fo->priv.rcv_nxt == fo->priv.fin_seq &&
				    fo->pub.rcv_nxt == fo->pub.fin_seq) {
					_eflow_free(w, ef);
				}
#ifdef DEBUG_SM
				else
					printf("FIN2 check failed - cl rcv_nxt 0x%x fin_seq 0x%x, sv rcv_nxt 0x%x fin_seq 0x%x\n",
						fo->priv.rcv_nxt, fo->priv.fin_seq, fo->pub.rcv_nxt, fo->pub.fin_seq);
#endif
			}
		} else {
			printf("ACK from FIN2 side or payload_len (%u) != 0\n", payload_len(p));
			++w->st.fin_dup_pkt;
		}

		return ret;
	}

// XXX - We don't get here - although it appears we can
printf("At XXX\n");
	if (likely(ef->state == TCP_STATE_ESTABLISHED)) {
		set_estb_pkt_counts(w, tcp_flags);
	} else if (ef->state < TCP_STATE_ESTABLISHED) {
		++w->st.syn_state_pkt;
	} else if (ef->state == TCP_STATE_RESET) {
		++w->st.rst_state_pkt;
	} else if (ef->state == TCP_STATE_BAD) {
		++w->st.bad_state_pkt;
	}

// tfo_handle_pkt should only be called if data or ack. ? Not for SYN with data ? What about FIN with data
// This is probably OK since we only optimize when in EST, FIN1 or FIN2 state
// We need to handle stopping optimisation - we can stop on a side once see an ack for the last packet we have
// YYYY - I don't think we want this here
	if (!(ef->flags & TFO_EF_FL_STOP_OPTIMIZE))
		return tfo_handle_pkt(w, p, ef, tx_bufs);

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
	struct tfo_user *u;
	struct tfo_eflow *ef;
	uint32_t priv_addr, pub_addr;
	uint16_t priv_port, pub_port;
	uint32_t h, hu;

	/* capture input tcp packet */
	if (config->capture_input_packet)
		config->capture_input_packet(w->param, IPPROTO_IP, p->m, &w->ts, p->from_priv, (union tfo_ip_p)p->ip4h);

	if (!tcp_header_complete(p->m, p->tcp))
		return TFO_PKT_INVALID;

	p->seglen = p->m->pkt_len - ((uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *))
				- ((p->tcp->data_off & 0xf0) >> 2)
				+ !!(p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

#ifdef DEBUG_PKT_RX
	printf("pkt_len %u tcp %p tcp_offs %ld, tcp_len %u, mtod %p, seg_len %u\n",
		p->m->pkt_len, p->tcp, (uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *),
		(p->tcp->data_off & 0xf0U) >> 2, rte_pktmbuf_mtod(p->m, uint8_t *), p->seglen);
#endif

// PQA - use in_addr, out_addr, in_port, out_port, and don't check p->from_priv
// PQA - don't call rte_be_to_cpu_32 etc. Do everything in network order
	/* get/create flow */
	if (likely(p->from_priv)) {
		priv_addr = rte_be_to_cpu_32(p->ip4h->src_addr);
		pub_addr = rte_be_to_cpu_32(p->ip4h->dst_addr);
		priv_port = rte_be_to_cpu_16(p->tcp->src_port);
		pub_port = rte_be_to_cpu_16(p->tcp->dst_port);
	} else {
		priv_addr = rte_be_to_cpu_32(p->ip4h->dst_addr);
		pub_addr = rte_be_to_cpu_32(p->ip4h->src_addr);
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

	if (unlikely(ef == NULL)) {
		/* ECN and CWR can be set. Don't know about URG, PSH or NS yet */
		if ((p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
			/* This is not a new flow  - it might have existed before we started */
			return TFO_PKT_FORWARD;
		}

#ifdef DEBUG_SM
		printf("Received SYN, flags 0x%x, send_seq 0x%x seglen %u rx_win %u\n",
			p->tcp->tcp_flags, rte_be_to_cpu_32(p->tcp->sent_seq), p->seglen, rte_be_to_cpu_16(p->tcp->rx_win));
#endif

		hu = tfo_user_v4_hash(config, priv_addr);
		u = tfo_user_v4_lookup(w, priv_addr, hu);
#ifdef DEBUG_USER
		printf("hu = %u, u = %p\n", hu, u);
#endif

		if (unlikely((!u && hlist_empty(&w->u_free)) ||
			     hlist_empty(&w->ef_free)))
			return TFO_PKT_NO_RESOURCE;

		if (u == NULL) {
			u = _user_alloc(w, hu, 0);
			u->priv_addr.v4 = priv_addr;

#ifdef DEBUG_USER
			printf("u now %p\n", u);
#endif
		}
		ef = _eflow_alloc(w, u, h);
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v4 = pub_addr;

		if (!set_tcp_options(p, ef)) {
			_eflow_free(w, ef);
			++w->st.syn_bad_pkt;
			return TFO_PKT_FORWARD;
		}

		ef->win_shift = p->win_shift;
		ef->server_snd_una = rte_be_to_cpu_32(p->tcp->sent_seq);
		ef->client_rcv_nxt = ef->server_snd_una + p->seglen;
		ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
		ef->client_mss = p->mss_opt;
		if (p->from_priv)
			ef->flags |= TFO_EF_FL_SYN_FROM_PRIV;
		++w->st.syn_pkt;

		return TFO_PKT_FORWARD;
	}

	ef->last_use = w->ts.tv_sec;

	return tfo_tcp_sm(w, p, ef, tx_bufs);
}

static int
tfo_mbuf_in_v6(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_user *u;
	struct tfo_eflow *ef;
	struct in6_addr *priv_addr, *pub_addr;
	uint16_t priv_port, pub_port;
	uint32_t h, hu;


	/* capture input tcp packet */
	if (config->capture_input_packet)
		config->capture_input_packet(w->param, IPPROTO_IPV6, p->m, &w->ts, p->from_priv, (union tfo_ip_p)p->ip6h);

	if (!tcp_header_complete(p->m, p->tcp))
		return TFO_PKT_INVALID;

	p->seglen = p->m->pkt_len - ((uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *))
				- ((p->tcp->data_off & 0xf0) << 2)
				+ !!(p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));

// PQA - use in_addr, out_addr, in_port, out_port, and don't check p->from_priv
// PQA - don't call rte_be_to_cpu_32 etc. Do everything in network order
	/* get/create flow */
	if (likely(p->from_priv)) {
		priv_addr = (struct in6_addr *)p->ip6h->src_addr;
		pub_addr = (struct in6_addr *)p->ip6h->dst_addr;
		priv_port = rte_be_to_cpu_16(p->tcp->src_port);
		pub_port = rte_be_to_cpu_16(p->tcp->dst_port);
	} else {
		priv_addr = (struct in6_addr *)p->ip6h->dst_addr;
		pub_addr = (struct in6_addr *)p->ip6h->src_addr;
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
		if (p->tcp->tcp_flags & RTE_TCP_RST_FLAG)
			return TFO_PKT_FORWARD;

// Even for a CGN it may have split traffic, e.g. in on Wifi, out on mobile network
if ((p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
	/* This is not a new flow - it might have existed before we started */
	return TFO_PKT_FORWARD;
}

		hu = tfo_user_v6_hash(config, priv_addr);
		u = tfo_user_v6_lookup(w, priv_addr, hu);
#ifdef DEBUG_USER
		printf("hu = %u, u = %p\n", hu, u);
#endif

		if (u == NULL) {
			u = _user_alloc(w, hu, TFO_USER_FL_V6);
			if (u == NULL)
				return TFO_PKT_NO_RESOURCE;
			u->priv_addr.v6 = *priv_addr;

#ifdef DEBUG_USER
			printf("u now %p\n", u);
#endif
		}
		ef = _eflow_alloc(w, u, h);
		if (ef == NULL)
			return TFO_PKT_NO_RESOURCE;
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v6 = *pub_addr;
		ef->client_rcv_nxt = rte_be_to_cpu_32(p->tcp->sent_seq) + p->seglen;
		ef->flags |= TFO_EF_FL_IPV6;
	}

	ef->last_use = w->ts.tv_sec;
// We should only call tfo_tcp_sm if we haven't allocated the ef, since then we know the state
	tfo_tcp_sm(w, p, ef, tx_bufs);

	return TFO_PKT_FORWARD;
}

// Do IPv4 defragmentation - see https://packetpushers.net/ip-fragmentation-in-detail/

static int
tcp_worker_mbuf_pkt(struct tcp_worker *w, struct rte_mbuf *m, int from_priv, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt_in pkt;
	struct rte_ipv4_hdr *iph;
	int16_t proto;
	uint32_t hdr_len;
	uint32_t off;
	int frag;
	uint16_t vlan_tci;
	struct rte_vlan_hdr *vl;


	pkt.m = m;
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
	printf("\nReceived %s from %s, length %u (%u), vlan %u", ptype, from_priv ? "priv" : "pub", m->pkt_len, m->data_len, m->vlan_tci);
#endif

	/* skip ethernet + vlan(s) */
	switch (m->packet_type & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER:
		hdr_len = sizeof (struct rte_ether_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_VLAN:
		hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
		vl = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, sizeof(struct rte_ether_hdr));
#ifdef DEBUG_VLAN_TCI
		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
			vlan_tci = rte_be_to_cpu_16(vl->vlan_tci);
			if (m->vlan_tci && m->vlan_tci != vlan_tci)
				printf("vlan id mismatch - m %u pkt %u\n", m->vlan_tci, vlan_tci);
			m->vlan_tci = vlan_tci;
		}
#endif
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

	iph = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdr_len);
	pkt.pktlen = m->pkt_len - hdr_len;

	switch (m->packet_type & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
		pkt.ip4h = iph;
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));

		/* A minimum ethernet + IPv4 + TCP packet with no options or data
		 * is 54 bytes; we will be given a pkt_len of 60 */
		if (m->pkt_len > rte_be_to_cpu_16(iph->total_length) + hdr_len)
			rte_pktmbuf_trim(m, m->pkt_len - (rte_be_to_cpu_16(iph->total_length) + hdr_len));

		return tfo_mbuf_in_v4(w, &pkt, tx_bufs);

	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		pkt.ip4h = iph;
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(iph));

		/* A minimum ethernet + IPv4 + TCP packet with no options or data
		 * is 54 bytes; we will be given a pkt_len of 60 */
		if (m->pkt_len > rte_be_to_cpu_16(iph->total_length) + hdr_len)
			rte_pktmbuf_trim(m, m->pkt_len - (rte_be_to_cpu_16(iph->total_length) + hdr_len));

		return tfo_mbuf_in_v4(w, &pkt, tx_bufs);

	case RTE_PTYPE_L3_IPV6:
		pkt.ip6h = (struct rte_ipv6_hdr *)iph;
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv6_hdr));

		return tfo_mbuf_in_v6(w, &pkt, tx_bufs);

	case RTE_PTYPE_L3_IPV6_EXT:
	case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
		pkt.ip6h = (struct rte_ipv6_hdr *)iph;
		off = hdr_len;
		proto = rte_net_skip_ip6_ext(pkt.ip6h->proto, m, &off, &frag);
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
tfo_packet_no_room_for_vlan(__attribute__((unused)) struct rte_mbuf *m) {
	/* The packet cannot be sent, remove it, turn off optimization */
}

void
tfo_packets_not_sent(struct tfo_tx_bufs *tx_bufs, uint16_t nb_tx) {
	/* Once the mbuf holds the tfo_pkt in private data, we can
	 * update the packet to mark not_sent, and possibly clear ns */
	for (uint16_t buf = nb_tx; buf < tx_bufs->nb_tx; buf++) {
#ifdef DEBUG_GARBAGE
		printf("\tm %p not sent\n", tx_bufs->m[buf]);
#endif
	}
}

static inline void
tfo_send_burst(struct tfo_tx_bufs *tx_bufs)
{
	uint16_t nb_tx;

	if (tx_bufs->nb_tx) {
		/* send the burst of TX packets. */
		nb_tx = config->tx_burst(port_id, queue_idx, tx_bufs->m, tx_bufs->nb_tx);

		/* Mark any unsent packets as not having been sent. */
		if (unlikely(nb_tx < tx_bufs->nb_tx)) {
#ifdef DEBUG_GARBAGE
			printf("tx_burst %u packets sent %u packets\n", tx_bufs->nb_tx, nb_tx);
#endif
			printf("tx_burst %u packets sent %u packets\n", tx_bufs->nb_tx, nb_tx);

			tfo_packets_not_sent(tx_bufs, nb_tx);
		}
	}

	if (tx_bufs->m)
		rte_free(tx_bufs->m);
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
#ifdef DEBUG_BURST
	struct tm tm;
	char str[24];
	unsigned long gap;
	static thread_local struct timespec last_time;
#endif

#ifdef RELEASE_SACKED_PACKETS
	if (!saved_mac_addr) {
		struct rte_ether_hdr *eh;

		/* Save the MAC addresses */
		eh = rte_pktmbuf_mtod(rx_buf[0], struct rte_ether_hdr *);
		rte_ether_addr_copy(&eh->dst_addr, &local_mac_addr);
		rte_ether_addr_copy(&eh->src_addr, &remote_mac_addr);

		saved_mac_addr = true;
	}
#endif

	if (!ts) {
		ts = &ts_local;
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts_local);
	}

#ifdef DEBUG_BURST
	gap = (ts->tv_sec - last_time.tv_sec) * 1000000000UL + (ts->tv_nsec - last_time.tv_nsec);
	localtime_r(&ts->tv_sec, &tm);
	strftime(str, 24, "%T", &tm);
	printf("\n%s.%9.9ld Burst received %u pkts time %ld.%9.9ld gap %lu.%9.9lu\n", str, ts->tv_nsec, nb_rx, ts->tv_sec, ts->tv_nsec, gap / 1000000000UL, gap % 1000000000UL);
	last_time = *ts;
#endif

	w->ts = *ts;
	/* Ensure tv_sec does not overflow when multiplied by 1000 */

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
#ifndef DEBUG_PKTS
				printf("adding tx_buf %p, vlan %u, ret %d\n", m, m->vlan_tci, ret);
#endif
				add_tx_buf(w, m, tx_bufs, from_priv, (union tfo_ip_p)(struct rte_ipv4_hdr *)NULL);
			} else
				printf("dropping tx_buf %p, vlan %u, ret %d, no room for vlan header\n", m, m->vlan_tci, ret);
		}
#ifdef DEBUG_STRUCTURES
		dump_details(w);
#endif
	}

	if (!tx_bufs->nb_tx && tx_bufs->m) {
		rte_free(tx_bufs->m);
		tx_bufs->m = NULL;
	}
	return tx_bufs;
}

void
tcp_worker_mbuf_burst_send(struct rte_mbuf **rx_buf, uint16_t nb_rx, struct timespec *ts)
{
	struct tfo_tx_bufs tx_bufs = { .nb_inc = nb_rx };

	tcp_worker_mbuf_burst(rx_buf, nb_rx, ts, &tx_bufs);

#ifdef DEBUG_PKT_NUM
	printf("Sending packets %u -> %u\n", pkt_num, pkt_num + tx_bufs.nb_tx - 1);
	pkt_num += tx_bufs.nb_tx;
#endif
	tfo_send_burst(&tx_bufs);
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

/*
 * run every 2ms or 5ms.
 * do not spend more than 1ms here
 */
void
tfo_garbage_collect(uint16_t snow, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_eflow *ef;
	unsigned k, iter;
	struct tcp_worker *w = &worker;
	uint64_t now;
	uint32_t i;
	struct tfo_side *fos, *foos;
	struct tfo_pkt *p;
	struct tfo_user *u;
	struct tfo *fo;
	bool pkt_resent;
	uint32_t win_end;
#ifdef DEBUG_PKTS
	bool removed_eflow = false;
#endif
#ifdef DEBUG_GARBAGE
	bool sent = false;
#endif

	/* eflow garbage collection */

/* We run 500 times per second => 10 should be config->ef_n / 500 */
	iter = max(10, config->ef_n * config->slowpath_time / 1000);
	for (k = 0; k < iter; k++) {
		ef = &w->ef[w->ef_gc];
		if (ef->flags && _eflow_timeout_remain(ef, snow) <= 0) {
// This is too simple if we have ack'd data but not received the ack
// We need a timeout for not receiving an ack for data we have ack'd
//  - both to resend and drop connection
			_eflow_free(w, ef);
#ifdef DEBUG_PKTS
			removed_eflow = true;
#endif
		}
		if (unlikely(++w->ef_gc >= config->ef_n))
			w->ef_gc = 0;
	}

#ifdef DEBUG_PKTS
	if (removed_eflow)
		dump_details(w);
#endif
	/* Linux does a first resent after 0.21s, then after 0.24s, then 0.48s, 0.96s ... */
	clock_gettime(CLOCK_REALTIME, &w->ts);
	now = timespec_to_ns(&w->ts);

	for (i = 0; i < config->hu_n; i++) {
		if (!hlist_empty(&w->hu[i])) {
			hlist_for_each_entry(u, &w->hu[i], hlist) {
				// print user
				hlist_for_each_entry(ef, &u->flow_list, flist) {
					if (ef->tfo_idx == TFO_IDX_UNUSED)
						continue;

					fo = &w->f[ef->tfo_idx];
					fos = &fo->priv;
					foos = &fo->pub;

					while (true) {
					win_end = get_snd_win_end(fos);
						pkt_resent = false;
						list_for_each_entry(p, &fos->pktlist, list) {
							if (after(segend(p), win_end))
								break;

							if (p->m &&
							    (!(p->flags & TFO_PKT_FL_SENT) ||
							     packet_timeout(p->ns, fos->rto) < now)) {
								if (p->flags & TFO_PKT_FL_SENT)
									pkt_resent = true;

								/* RFC5681 3.2 */
								if ((p->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_RESENT)) == TFO_PKT_FL_SENT) {
									fos->ssthresh = min((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
									fos->cwnd = fos->mss;
									win_end = get_snd_win_end(fos);
								}
#ifdef DEBUG_GARBAGE
								bool already_sent = !!(p->flags & TFO_PKT_FL_SENT);
#endif

								send_tcp_pkt(w, p, tx_bufs, fos, foos);

#ifdef DEBUG_GARBAGE
								if (!sent) {
									printf("\nGarbage send at %ld.%9.9ld\n", w->ts.tv_sec, w->ts.tv_nsec);
									sent = true;
								}
								printf("  %sending 0x%x %u\n", already_sent? "Res" : "S", p->seq, p->seglen);
#endif
							}
						}

						if (pkt_resent) {
							fos->rto *= 2;

							if (fos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
								printf("rto garbage resend after timeout double %u - reducing to 60000\n", fos->rto);
#endif
								fos->rto = 60 * 1000;
							}
						}

						/* If the first entry on the pktlist is a SACK entry, we are missing a
						 * packet before that entry, and we will have sent a duplicate ACK for
						 * it. If we have not received the packet within rto time, we need to
						 * resend the ACK. */
						if(!list_empty(&fos->pktlist) &&
						   !(p = list_first_entry(&fos->pktlist, struct tfo_pkt, list))->m &&
						   packet_timeout(foos->ack_sent_time, foos->rto) < now) {
#ifdef DEBUG_GARBAGE
							if (!sent) {
								printf("\nGarbage send at %ld.%9.9ld\n", w->ts.tv_sec, w->ts.tv_nsec);
								sent = true;
							}
							printf("  Garbage resend ack 0x%x due to timeout\n", foos->rcv_nxt);
#endif
#ifdef RELEASE_SACKED_PACKETS
							struct tfo_addr_info addr;

							if (foos == &fo->pub) {
								addr.src_addr = rte_cpu_to_be_32(ef->u->priv_addr.v4);
								addr.dst_addr = rte_cpu_to_be_32(ef->pub_addr.v4);
								addr.src_port = rte_cpu_to_be_16(ef->priv_port);
								addr.dst_port = rte_cpu_to_be_16(ef->pub_port);
							} else {
								addr.src_addr = rte_cpu_to_be_32(ef->pub_addr.v4);
								addr.dst_addr = rte_cpu_to_be_32(ef->u->priv_addr.v4);
								addr.src_port = rte_cpu_to_be_16(ef->pub_port);
								addr.dst_port = rte_cpu_to_be_16(ef->priv_port);
							}

							_send_ack_pkt(w, ef, foos, NULL, &addr, foos == &fo->pub ? pub_vlan_tci : priv_vlan_tci, fos, tx_bufs, true, false);
#else
							p = list_first_entry(&fos->pktlist, struct rte_pkt, list);

							_send_ack_pkt(w, ef, foos, p, NULL, foos == &fo->pub ? pub_vlan_tci : priv_vlan_tci, fos, tx_bufs, true, false);
#endif
// Should we double foos->rto ?
						}

						if (fos == &fo->pub)
							break;

						foos = fos;
						fos = &fo->pub;
					}
				}
			}
		}
	}

#ifdef DEBUG_GARBAGE
	if (sent) {
		dump_details(w);
	}
#endif
}

void
tfo_garbage_collect_send(uint16_t snow)
{
	struct tfo_tx_bufs tx_bufs = { .nb_inc = 1024 };

	tfo_garbage_collect(snow, &tx_bufs);

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

	printf("\ngarbage collection interval = %ums\n", c->slowpath_time);

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
	struct tfo_user *u;
	unsigned k;
	int j;

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
	pub_vlan_tci = params->public_vlan_tci;
	priv_vlan_tci = params->private_vlan_tci;
	ack_pool = params->ack_pool;
	port_id = params->port_id;
	queue_idx = params->queue_idx;
	option_flags = node_config_copy[socket_id]->option_flags;

#ifdef DEBUG_CONFIG
	printf("tfo_worker_init port %u queue_idx %u, vlan_tci: pub %u priv %u\n", port_id, queue_idx, pub_vlan_tci, priv_vlan_tci);
#endif

	struct tfo_user *u_mem = rte_malloc("worker u", c->u_n * sizeof (struct tfo_user), 0);
	w->hu = rte_calloc("worker hu", c->hu_n, sizeof (struct hlist_head), 0);
	struct tfo_eflow *ef_mem = rte_malloc("worker ef", c->ef_n * sizeof (struct tfo_eflow), 0);
	w->hef = rte_calloc("worker hef", c->hef_n, sizeof (struct hlist_head), 0);
	struct tfo *f_mem = rte_malloc("worker f", c->f_n * sizeof (struct tfo), 0);
	struct tfo_pkt *p_mem = rte_malloc("worker p", c->p_n * sizeof (struct tfo_pkt), 0);

#ifdef DEBUG_PKTS
	w->u = u_mem;
	w->p = p_mem;
#endif
w->ef = ef_mem;
w->f = f_mem;

	INIT_HLIST_HEAD(&w->u_free);
	for (j = c->u_n - 1; j >= 0; j--) {
		u = u_mem + j;
		hlist_add_head(&u->hlist, &w->u_free);
	}

	INIT_HLIST_HEAD(&w->ef_free);
	for (j = c->ef_n - 1; j >= 0; j--) {
		ef = ef_mem + j;
		ef = &w->ef[j];
		ef->flags = 0;
		ef->tfo_idx = TFO_IDX_UNUSED;
		ef->state = TFO_STATE_NONE;
/* I think we can use ef->hlist instead of ef->flist. We can
 * then remove ef->flist, and user->flow_list */
		hlist_add_head(&ef->flist, &w->ef_free);
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
	}

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

	global_config_data.hu_n = next_power_of_2(global_config_data.hu_n);
	global_config_data.hu_mask = global_config_data.hef_n - 1;
	global_config_data.hef_n = next_power_of_2(global_config_data.hu_n);
	global_config_data.hef_mask = global_config_data.hef_n - 1;
	global_config_data.option_flags = c->option_flags;

	/* If no tx function is specified, default to rte_eth_tx_burst() */
	if (!global_config_data.tx_burst)
		global_config_data.tx_burst = rte_eth_tx_burst;

	flag = rte_mbuf_dynflag_register(&dynflag);
	if (flag == -1)
		fprintf(stderr, "failed to register in-priv dynamic flag, flag=%d: %s",
			flag, strerror(errno));

	/* set a dynamic flag mask */
	global_config_data.dynflag_priv_mask = (1ULL << flag);
}

uint16_t
tfo_max_ack_pkt_size(void)
{
	return sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_vlan_hdr) +
		sizeof(struct rte_ipv6_hdr) +
		(0xf0 >> 2);		/* maximum TCP header length */
}

uint16_t
tfo_get_mbuf_priv_size(void)
{
	return 0;
	return sizeof(struct tfo_pkt);
}
