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
 * RFC 1122 - Host Requirements for Internet Hosts, clarified a number of TCP protocol implementation requirements including delayed ack
 * RFC 1323 - TCP timestamps (on by default for Linux, off for Windows Server), window size scaling etc
 * RFC 1624 - incremental checksum calculation
 * RFC 1948 - defending against sequence number attaacks
 * RFC 2018 - Selective ACK
 * RFC 2460 - IPv6 TCP checksum
 * RFC 2581 - congenstion control
 * RFC 2883 - An Extension to the Selective Acknowledgement (SACK) Option for TCP
 * RFC 3168 - Explicit Congestion Notification (ECN), a congestion avoidance signaling mechanism.
 * RFC 3515 - Performance Enhancing Proxies Intended to Mitigate Link-Related Degradations
 * RFC 4522 - Eifel detection algorithm
 * RFC 5681 - TCP congestion control
 * RFC 6247 - ? just obsoleting other RFCs
 * RFC 6298 - computing TCPs retransmission timer
 * RFC 6824 – TCP Extensions for Multipath Operation with Multiple Addresses
 * RFC 7323 – TCP Extensions for High Performance
 * RFC 7413 - TCP Fast Open
 * RFC 7414 – A Roadmap for TCP Specification Documents
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
#define DEBUG_STRUCTURES
//#define DEBUG_TCP_OPT
//#define DEBUG_QUEUE_PKTS
#define DEBUG_ACK
//#define DEBUG_ACK_PKT_LIST
#define DEBUG_SACK_RX
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


#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <ev.h>
#include <threads.h>

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

#include "tfo.h"
#include "util.h"


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


#if defined DEBUG_QUEUE_PKTS && defined DEBUG_PKTS
static void
dump_m(struct rte_mbuf *m)
{
	uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

	for (int i = 0; i < m->data_len; i++) {
		if (i && !(i % 8)) {
			if (!(i %16))
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

#ifdef DEBUG_STRUCTURES
static void
print_side(const struct tfo_side *s, const struct timespec *ts)
{
	struct tfo_pkt *p;
	uint32_t next_exp;

	printf("\t\t\trcv_nxt 0x%x snd_una 0x%x snd_nxt 0x%x snd_win 0x%x rcv_win 0x%x\n", s->rcv_nxt, s->snd_una, s->snd_nxt, s->snd_win, s->rcv_win);
	printf("\t\t\t  srtt %u rttvar %u rto %u #pkt %u optim to 0x%x\n", s->srtt, s->rttvar, s->rto, s->pktcount, s->optim_until_seq);
	printf("\t\t\t     latest_ts_val_sent %1$u (0x%1$x), ts_recent %2$u (0x%2$x)\n", s->latest_ts_val_sent, s->ts_recent);

	next_exp = s->snd_una;
	list_for_each_entry(p, &s->pktlist, list) {
		if (p->seq != next_exp)
			printf("\t\t\t\t  *** expected 0x%x, gap = %d\n", next_exp, p->seq - next_exp);
		printf("\t\t\t\tm %p, seq 0x%x %slen %u flags 0x%x refcnt %u ns %" PRIu64 "\n", p->m, p->seq, p->m ? "seg" : "sack_", p->seglen, p->flags, p->m ? p->m->refcnt : -1, ts->tv_sec * 1000000000UL + ts->tv_nsec - p->ns);
		next_exp = p->seq + p->seglen;
	}
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
					printf("\t\tef %p state %u tfo_idx %u, ef->pub_addr.v4 %x port: priv %u pub %u flags 0x%x user %p\n",
						ef, ef->state, ef->tfo_idx, ef->pub_addr.v4, ef->priv_port, ef->pub_port, ef->flags, ef->u);
					printf("\t\t  last_use %u priv_snd_win_sft %u pub_snd_win_sft %u\n", ef->last_use, ef->priv_snd_wind_shift, ef->pub_snd_wind_shift);
					if (ef->state == TCP_STATE_SYN)
						printf("\t\t  svr_snd_una 0x%x cl_snd_win 0x%x cl_rcv_nxt 0x%x\n", ef->server_snd_una, ef->client_snd_win, ef->client_rcv_nxt);
					if (ef->tfo_idx != TFO_IDX_UNUSED) {
						// Print tfo
						fo = &w->f[ef->tfo_idx];
						printf("\t\t  flow flags 0x%x, idx %u, wakeup_ns %" PRIu64 "\n", fo->flags, fo->idx, fo->wakeup_ns);
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

	if (tx_bufs->nb_tx == tx_bufs->max_tx)
		tx_bufs->m = rte_realloc(tx_bufs->m, (tx_bufs->max_tx += tx_bufs->nb_inc) * sizeof(struct rte_mbuf *), 0);

	tx_bufs->m[tx_bufs->nb_tx++] = m;

	if (iph.ip4h && config->capture_output_packet)
		config->capture_output_packet(w->param, IPPROTO_IP, m, &w->ts, from_priv, iph);
}

static void
_send_ack_pkt(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos,
	      struct tfo_pkt_in *p, uint16_t orig_vlan, struct tfo_tx_bufs *tx_bufs)
{
	struct rte_ether_hdr *eh;
	struct rte_ether_hdr *eh_in;
	struct rte_vlan_hdr *vl;
	struct rte_ipv4_hdr *ipv4;
	struct rte_tcp_hdr *tcp;
	struct tcp_timestamp_option *ts_opt;
	struct rte_mbuf *m;
	uint32_t *ptr;
	uint16_t pkt_len;

	m = rte_pktmbuf_alloc(ack_pool);
// Handle not forwarding ACK somehow
	if (m == NULL) {
#ifdef DEBUG_NO_MBUF
		printf("Unable to ack 0x%x - no mbuf - vlan %u\n", fos->rcv_nxt, orig_vlan);
#endif
		return;
	}

// PQA - we are setting all fields.
//	memset(m + 1, 0x00, sizeof (struct fn_mbuf_priv));
	pkt_len = sizeof (struct rte_ether_hdr) +
		(orig_vlan ? sizeof(struct rte_vlan_hdr) : 0) +
		sizeof (struct rte_ipv4_hdr) +
		sizeof (struct rte_tcp_hdr) +
// Allow for SACK here
		(ef->flags & TFO_EF_FL_TIMESTAMP ? sizeof(struct tcp_timestamp_option) + 2 : 0);
	eh = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, pkt_len);

	m->port = p->m->port;
	m->vlan_tci = orig_vlan;

	eh_in = rte_pktmbuf_mtod(p->m, struct rte_ether_hdr *);
	rte_ether_addr_copy(&eh_in->dst_addr, &eh->dst_addr);
	rte_ether_addr_copy(&eh_in->src_addr, &eh->src_addr);

	if (orig_vlan) {
		eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
		vl = (struct rte_vlan_hdr *)(eh + 1);
		vl->vlan_tci = orig_vlan;
		vl->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		ipv4 = (struct rte_ipv4_hdr *)((struct rte_vlan_hdr *)(eh + 1) + 1);
	} else {
		eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		ipv4 = (struct rte_ipv4_hdr *)(eh + 1);
	}

	ipv4->version_ihl = 0x45;
	ipv4->type_of_service = 0;
ipv4->type_of_service = 0x10;
	ipv4->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof (*eh) - (orig_vlan ? sizeof(*vl) : 0));
// See RFC6864 re identification
	ipv4->packet_id = 0;
// A random!! number
ipv4->packet_id =rte_cpu_to_be_16(w->ts.tv_nsec);
	ipv4->fragment_offset = 0;
ipv4->fragment_offset = rte_cpu_to_be_16(0x4000);
// Should match what we receive
	ipv4->time_to_live = 60;	// Check what we observe on packets
// Learn TTL from SYN/SYN+ACK
ipv4->time_to_live=62;
	ipv4->next_proto_id = IPPROTO_TCP;
	ipv4->hdr_checksum = 0;
	ipv4->src_addr = p->ip4h->dst_addr;
	ipv4->dst_addr = p->ip4h->src_addr;
// Checksum offload?
	ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
// Should we copy IPv4 options ?

	tcp = (struct rte_tcp_hdr *)(ipv4 + 1);
	tcp->src_port = p->tcp->dst_port;
	tcp->dst_port = p->tcp->src_port;
	tcp->sent_seq = rte_cpu_to_be_32(fos->snd_nxt);
	tcp->recv_ack = rte_cpu_to_be_32(fos->rcv_nxt);
	tcp->data_off = 5 << 4;
	tcp->tcp_flags = RTE_TCP_ACK_FLAG;
	tcp->rx_win = rte_cpu_to_be_16(fos->rcv_win);
	tcp->cksum = 0;
	tcp->tcp_urp = 0;

	/* Need tcp options - timestamp and SACK */
	if (ef->flags & TFO_EF_FL_TIMESTAMP) {
		ptr = (uint32_t *)(tcp + 1);
		*ptr = rte_cpu_to_be_32(TCPOPT_TSTAMP_HDR);
		ts_opt = (struct tcp_timestamp_option *)((uint8_t *)ptr + 2);
		ts_opt->ts_val = rte_cpu_to_be_32(fos->latest_ts_val_sent);
		ts_opt->ts_ecr = rte_cpu_to_be_32(fos->ts_recent);
		tcp->data_off += ((1 + 1 + TCPOLEN_TIMESTAMP) / 4) << 4;
	}

// Checksum offload?
	tcp->cksum = rte_ipv4_udptcp_cksum(ipv4, tcp);

#ifdef DEBUG_ACK
	printf("Sending ack %p seq 0x%x ack 0x%x ts_val %u ts_ecr %u vlan %u\n",
		m, fos->snd_nxt, fos->rcv_nxt,
		(ef->flags & TFO_EF_FL_TIMESTAMP) ? fos->latest_ts_val_sent : 0,
		(ef->flags & TFO_EF_FL_TIMESTAMP) ? fos->ts_recent : 0,
		orig_vlan);
#endif

#ifndef TFO_UNDER_TEST
// We need to return the ack packet for sending
//	fn_pipe_output(g_tfo->a, w->aw.id, -1, m);
	add_tx_buf(w, m, tx_bufs, !p->from_priv, (union tfo_ip_p)ipv4);
#else
	rte_pktmbuf_free(m);
#endif
}

static inline uint32_t
_flow_alloc(struct tcp_worker *w)
{
	struct tfo* fo;

	/* Allocated when decide to optimze flow (following SYN ACK) */

	/* alloc flow */
	fo = list_first_entry(&w->f_free, struct tfo, list);
	list_del_init(&fo->list);
	fo->priv.srtt = 0;
	fo->priv.rto = 1000;
//	fo->priv.is_priv = true;
	INIT_LIST_HEAD(&fo->priv.pktlist);
	fo->pub.srtt = 0;
	fo->pub.rto = 1000;
	INIT_LIST_HEAD(&fo->pub.pktlist);
//	fo->pub.is_priv = false;
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
pkt_free(struct tcp_worker *w, struct tfo_pkt *pkt)
{
	list_del(&pkt->list);
// Is there an issue here that the packets might be in use within DPDK while being sent?

	/* We might have already freed the mbuf if using SACK */
	if (pkt->m)
		rte_pktmbuf_free(pkt->m);
	list_add(&pkt->list, &w->p_free);
	--w->p_use;
}

static inline void
pkt_free_mbuf(struct tfo_pkt *pkt)
{
	if (pkt->m) {
		rte_pktmbuf_free(pkt->m);
		pkt->m = NULL;
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
		pkt_free(w, pkt);
	list_for_each_entry_safe(pkt, pkt_tmp, &f->pub.pktlist, list)
		pkt_free(w, pkt);

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
	if (ef->state != TCP_STATE_NONE)
		printf("Allocating eflow %p in state %u\n", ef, ef->state);
	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		printf("Allocating eflow %p with tfo %u\n", ef, ef->tfo_idx);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}
	if (ef->u)
		printf("Allocating eflow %p with user %p\n", ef, ef->u);
#endif

	ef->state = TCP_STATE_CLOSED;
	ef->u = u;
	ef->priv_snd_wind_shift = EF_WIN_SCALE_UNSET;
	ef->pub_snd_wind_shift = EF_WIN_SCALE_UNSET;

	__hlist_del(&ef->flist);
	hlist_add_head(&ef->hlist, &w->hef[h]);
	hlist_add_head(&ef->flist, &u->flow_list);

	++w->ef_use;
	++u->flow_n;
	++w->st.flow_state[TCP_STATE_CLOSED];

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

	if (ef->flags & TFO_EF_FL_OPTIMIZE)
		--w->st.flow_state[10];

	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		_flow_free(w, &w->f[ef->tfo_idx]);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}

	--w->ef_use;
	--u->flow_n;
	--w->st.flow_state[ef->state];
	ef->state = TCP_STATE_NONE;

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
	case TCP_STATE_CLOSED ... TCP_STATE_SYN_ACK:
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
	unsigned opt_off = sizeof (struct rte_tcp_hdr);
	uint8_t opt_size = (p->tcp->data_off & 0xf0) >> 2;
	uint8_t *opt_ptr = (uint8_t *)p->tcp;
	struct tcp_option *opt;
	uint8_t wind_shift;
	struct tcp_timestamp_option *ts_opt;


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

		/* Check we have all of the option */
		if (opt_off + sizeof(*opt) > opt_size ||
		    opt_off + opt->opt_len > opt_size)
			return false;

		switch (opt->opt_code) {
		case TCPOPT_WINDOW:
			if (opt->opt_len != TCPOLEN_WINDOW)
				return false;

			if (p->tcp->tcp_flags & RTE_TCP_SYN_FLAG) {
				wind_shift = min(TCP_MAX_WINSHIFT, opt->opt_data[0]);
				if (p->from_priv)
					ef->priv_snd_wind_shift = wind_shift;
				else
					ef->pub_snd_wind_shift = wind_shift;
			}
			break;
		case TCPOPT_SACK_PERMITTED:
			if (opt->opt_len != TCPOLEN_SACK_PERMITTED)
				return false;

			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_SACK;
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

// Should we set a pointer to the options - a TS of 0 is valid
			ts_opt = (void *)opt;
			p->ts_val = rte_be_to_cpu_32(ts_opt->ts_val);
			p->ts_ecr = rte_be_to_cpu_32(ts_opt->ts_ecr);

#ifdef DEBUG_TCP_OPT
			printf("ts_val %u ts_ecr %u\n", p->ts_val, p->ts_ecr);
#endif

			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG))
				ef->flags |= TFO_EF_FL_TIMESTAMP;
			break;
		}

		opt_off += opt->opt_len;
	}

	return (opt_off == opt_size);
}

static inline void
set_estab_options(struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
// We might want to optimise this and not use set_tcp_options
	set_tcp_options(p, ef);
}

static void
remove_sack_option(struct tfo_pkt_in *p)
{
	uint8_t sack_len = p->sack_opt->opt_len + 2;
	uint8_t *pkt_start = rte_pktmbuf_mtod(p->m, uint8_t *);

	p->ip4h->total_length = rte_cpu_to_be_16(rte_be_to_cpu_16(p->ip4h->total_length) - sack_len);
	p->ip4h->hdr_checksum = 0;
	p->ip4h->hdr_checksum = rte_ipv4_cksum(p->ip4h);

	if ((uint8_t *)p->sack_opt + sack_len - 2 == pkt_start + p->m->data_len) {
		/* The SACK option is the last item in the packet - can't happen since we don't forward packets with no data */
		rte_pktmbuf_trim(p->m, sack_len);
	} else if ((uint8_t *)p->sack_opt - pkt_start < p->m->data_len - ((uint8_t *)p->sack_opt + sack_len - pkt_start)) {
		/* The header is shorter than the data */
		memmove(rte_pktmbuf_adj(p->m, sack_len), pkt_start, (uint8_t *)p->sack_opt - pkt_start);
		p->ip4h = (struct rte_ipv4_hdr*)((uint8_t *)p->ip4h + sack_len);
		p->tcp = (struct rte_tcp_hdr*)((uint8_t *)p->tcp + sack_len);
	} else {
		/* The data is shorter than the header */
		memmove(p->sack_opt, (uint8_t *)p->sack_opt + sack_len, p->m->data_len - ((uint8_t *)p->sack_opt + sack_len - pkt_start));
		rte_pktmbuf_trim(p->m, sack_len);
	}

	p->tcp->data_off -= (sack_len / 4) << 4;
	p->tcp->cksum = 0;
	p->tcp->cksum = rte_ipv4_udptcp_cksum(p->ip4h, p->tcp);
}

/*
 * called at SYN+ACK. decide if we'll optimize this tcp connection
 */
static void
check_do_optimize(struct tcp_worker *w, const struct tfo_pkt_in *p, struct tfo_eflow *ef)
{
	struct tfo *fo;
	struct tfo_side *client_fo, *server_fo;
	uint8_t client_snd_wind_shift;
	uint8_t server_snd_wind_shift;

	/* should not happen */
	if (unlikely(list_empty(&w->f_free)))
		return;

	/* will optimize if have enough flows / packets */
	if (w->f_use >= config->f_n)
		return;
// Surely we can go higher than 3/4 of p_n
	if (w->p_use >= config->p_n * 3 / 4)
		return;

	/* alloc flow */
	ef->tfo_idx = _flow_alloc(w);
	ef->flags |= TFO_EF_FL_OPTIMIZE;
	++w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

	fo = &w->f[ef->tfo_idx];

	/* Clear window scaling if either side didn't send it */
	if (ef->priv_snd_wind_shift == EF_WIN_SCALE_UNSET ||
	    ef->pub_snd_wind_shift == EF_WIN_SCALE_UNSET) {
		ef->priv_snd_wind_shift = 0;
		ef->pub_snd_wind_shift = 0;
	}

	if (unlikely(p->from_priv)) {
		/* original SYN from public */
		client_fo = &fo->pub;
		server_fo = &fo->priv;
		client_snd_wind_shift = ef->pub_snd_wind_shift;
		server_snd_wind_shift = ef->priv_snd_wind_shift;
	} else {
		/* original SYN from private */
		client_fo = &fo->priv;
		server_fo = &fo->pub;
		client_snd_wind_shift = ef->priv_snd_wind_shift;
		server_snd_wind_shift = ef->pub_snd_wind_shift;
	}

	client_fo->rcv_nxt = rte_be_to_cpu_32(p->tcp->recv_ack);
	client_fo->snd_una = rte_be_to_cpu_32(p->tcp->sent_seq);
	client_fo->snd_nxt = rte_be_to_cpu_32(p->tcp->sent_seq) + 1 + p->seglen;
	client_fo->snd_win = ((ef->client_snd_win - 1) >> client_snd_wind_shift) + 1;
	server_fo->rcv_win = client_fo->snd_win;
	client_fo->ts_recent = p->ts_ecr;
	client_fo->latest_ts_val_sent = p->ts_val;

// We might get stuck with client implementations that don't receive data with SYN+ACK. Adjust when go to established state
	server_fo->rcv_nxt = client_fo->snd_nxt;
	server_fo->snd_una = rte_be_to_cpu_32(p->tcp->recv_ack);
	server_fo->snd_nxt = ef->client_rcv_nxt;
	server_fo->snd_win = ((rte_be_to_cpu_16(p->tcp->rx_win) - 1) >> server_snd_wind_shift) + 1;
	client_fo->rcv_win = server_fo->snd_win;
	server_fo->ts_recent = p->ts_val;
	server_fo->latest_ts_val_sent = p->ts_ecr;

#ifdef DEBUG_OPTIMIZE
	printf("priv rx/tx win 0x%x:0x%x pub rx/tx 0x%x:0x%x, priv send win 0x%x, pub 0x%x\n",
		fo->priv.rcv_win, fo->priv.snd_win, fo->pub.rcv_win, fo->pub.snd_win,
		fo->priv.snd_nxt + (fo->priv.snd_win << ef->priv_snd_wind_shift),
		fo->pub.snd_nxt + (fo->pub.snd_win << ef->pub_snd_wind_shift));
	printf("clnt ts_recent = svr latest = %1$u (0x%1$x) svr ts_recent = clnt latest = %2$u (0x%2$x)\n", p->ts_ecr, p->ts_val);
	printf("WE WILL optimize pub s:n 0x%x:0x%x priv 0x%x:0x%x\n", fo->pub.snd_una, fo->pub.rcv_nxt, fo->priv.snd_una, fo->priv.rcv_nxt);
#endif
}

static void
send_tcp_pkt(struct tcp_worker *w, struct tfo_pkt *pkt, struct tfo_tx_bufs *tx_bufs, struct tfo_side *fo)
{
	if (!pkt->m) {
		printf("Request to send sack'd packet %p\n", pkt);
		return;
	}

	if (pkt->tcp->rx_win != rte_cpu_to_be_16(fo->rcv_win)) {
// Do incremental
		pkt->tcp->cksum = 0;
		pkt->tcp->cksum = rte_ipv4_udptcp_cksum(pkt->ipv4, pkt->tcp);
	}


// Update:
//    ack
//    rcv_win
	if (pkt->flags & TFO_PKT_FL_SENT)
		pkt->flags |= TFO_PKT_FL_RESENT;
	else {
// update foos snd_nxt
		pkt->flags |= TFO_PKT_FL_SENT;
	}

// Check how timestamps are handled
	if (pkt->ts_val > fo->latest_ts_val_sent)
		fo->latest_ts_val_sent = pkt->ts_val;

	rte_pktmbuf_refcnt_update(pkt->m, 1);	/* so we keep it after it is sent */

	pkt->ns = w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec;

	add_tx_buf(w, pkt->m, tx_bufs, pkt->flags & TFO_PKT_FL_FROM_PRIV, (union tfo_ip_p)pkt->ipv4);
}

static inline struct tfo_pkt *
find_previous_pkt(struct list_head *pktlist, uint32_t seq)
{
	struct tfo_pkt *pkt;

	pkt = list_first_entry(pktlist, struct tfo_pkt, list);
	if (seq == pkt->seq)
		return pkt;

	/* Iterate backward through the list */
	list_for_each_entry_reverse(pkt, pktlist, list) {
		if (pkt->seq <= seq)
			return pkt;
	}

	return NULL;
}

static inline bool
set_vlan(struct rte_mbuf* m)
{
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
	uint16_t vlan_cur;
	uint16_t vlan_new;
	uint8_t *p;
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
		p = (uint8_t *)rte_pktmbuf_prepend(m, sizeof(struct rte_vlan_hdr));

		if (unlikely(p == NULL)) {
			p = (uint8_t *)rte_pktmbuf_append(m, sizeof(struct rte_vlan_hdr));
			if (unlikely(!p))
				return false;

			/* This is so unlikely, just move the whole packet to
			 * make room at the beginning to move the ether hdr */
			memmove(eh + sizeof(struct rte_vlan_hdr), eh, m->data_len - sizeof (struct rte_vlan_hdr));
			p = rte_pktmbuf_mtod(m, uint8_t *);
			eh = (struct rte_ether_hdr *)(p + sizeof(struct rte_vlan_hdr));
		}

		/* move ethernet header at the start */
		memmove(p, eh, sizeof (struct rte_ether_hdr));		// we could do sizeof - 2
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
update_pkt(struct rte_mbuf *m)
{
	if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
		if (unlikely(!set_vlan(m))) {
			/* The Vlan header could not be added. */
			return false;
		}
	}

	if (!(option_flags & TFO_CONFIG_FL_NO_MAC_CHG))
		swap_mac_addr(m);

	return true;
}

static struct tfo_pkt *
queue_pkt(struct tcp_worker *w, struct tfo_side *foos, struct tfo_pkt_in *p, uint32_t seq)
{
	struct tfo_pkt *pkt;
	struct tfo_pkt *prev_pkt;
	struct tfo_pkt *next_pkt, *cur_pkt, *last_pkt;
	uint32_t seg_end, cur_end;
	bool reusing_pkt;

	seg_end = seq + p->seglen;

	if (seg_end <= foos->snd_una) {
#ifdef DEBUG_QUEUE_PKTS
		printf("queue_pkt seq 0x%x, len %u before our window\n", seq, p->seglen);
#endif
		return PKT_IN_LIST;
	}

	if (!list_empty(&foos->pktlist))
		prev_pkt = find_previous_pkt(&foos->pktlist, seq);
	else
		prev_pkt = NULL;

	/* We might already have this packet queued, or it could have been SACK'd */
	if (prev_pkt &&
	    seq >= list_first_entry(&foos->pktlist, struct tfo_pkt, list)->seq &&
	    (last_pkt = list_last_entry(&foos->pktlist, struct tfo_pkt, list)) &&
	    seg_end <= last_pkt->seq + last_pkt->seglen) {
		if (prev_pkt->seq + prev_pkt->seglen >= seg_end) {
			/* We already have all the data in the list */
#ifdef DEBUG_QUEUE_PKTS
			printf("seq 0x%x -> 0x%x already in pktlist\n", seq, seq + p->seglen);
#endif
			return PKT_IN_LIST;
		}

#if 0	// check duplicate-extended-packet.log and also check logic
		/* Do the previous packet and the next packet span
		 * this new packet? */
// We should iterate forward over multiple packets
		if (prev_pkt != last_pkt) {
			next_pkt = list_next_entry(prev_pkt, list);
			if (prev_pkt->seq + prev_pkt->seglen >= next_pkt->seq &&
			    seg_end <= next_pkt->seq + next_pkt->seglen) {
#ifdef DEBUG_QUEUE_PKTS
				printf("seq 0x%x -> 0x%x already covered by pktlist\n", seq, seq + p->seglen);
#endif
				return PKT_IN_LIST;
			}
		}

		/* Does this packet extend a packet? */
// We should iterate forward over multiple packets
		if (prev_pkt->seq == seq &&
		    seg_end > prev_pkt->seq + prev_pkt->seglen &&
		    (prev_pkt == last_pkt ||
		     prev_pkt->seg + prev_pkt->seglen < next_pkt->seg)) {
#ifdef DEBUG_QUEUE_PKTS
			printf("seq 0x%x -> 0x%x extends 0x%x\n", seq, seq + p->seglen, prev_pkt->seq);
#endif
			pkt_free(prev_pkt);
		}
#endif

		cur_pkt = prev_pkt;
		cur_end = cur_pkt->seq + cur_pkt->seglen;

		next_pkt = cur_pkt;
		list_for_each_entry_continue(next_pkt, &foos->pktlist, list) {
			if (next_pkt->seq > cur_pkt->seq + cur_pkt->seglen ||
			    cur_end >= seg_end)
				break;
			cur_pkt = next_pkt;
			cur_end = cur_pkt->seq + cur_pkt->seglen;
		}

		if (cur_end >= seg_end) {
#ifdef DEBUG_QUEUE_PKTS
			printf("seq 0x%x -> 0x%x covered by pktlist\n", seq, seq + p->seglen);
#endif
			return PKT_IN_LIST;
		}
	}

#ifdef DEBUG_QUEUE_PKTS
	if (prev_pkt)
		printf("prev_pkt 0x%x len %u, seq 0x%x len %u\n", prev_pkt->seq, prev_pkt->seglen, seq, p->seglen);
	else
		printf("No prev pkt\n");
#endif

	if (!update_pkt(p->m))
		return PKT_VLAN_ERR;

	if (unlikely(prev_pkt && seq <= prev_pkt->seq && prev_pkt->seq + prev_pkt->seglen < seg_end)) {
#ifdef DEBUG_QUEUE_PKTS
		printf("Replacing shorter 0x%x %u\n", prev_pkt->seq, prev_pkt->seglen);
#endif
		if (prev_pkt->m)
			rte_pktmbuf_free(prev_pkt->m);
		pkt = prev_pkt;
		reusing_pkt = true;
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

		reusing_pkt = false;
	}

	pkt->m = p->m;
// I don't like this - find a better way
	p->m->vlan_tci = p->m->vlan_tci == pub_vlan_tci ? priv_vlan_tci : pub_vlan_tci;

	pkt->seq = seq;
	pkt->seglen = p->seglen;
	pkt->ipv4 = p->ip4h;
	pkt->tcp = p->tcp;
	pkt->ts_val = p->ts_val;
	pkt->flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
	pkt->ns = 0;

	if (!reusing_pkt) {
		if (list_empty(&foos->pktlist) ||
		    seq < list_first_entry(&foos->pktlist, struct tfo_pkt, list)->seq) {
#ifdef DEBUG_QUEUE_PKTS
			printf("Adding pkt at head %p m %p seq 0x%x to fo %p, vlan %u\n", pkt, pkt->m, seq, foos, p->m->vlan_tci);
#endif
			list_add(&pkt->list, &foos->pktlist);
		} else if (!prev_pkt)
			list_add_tail(&pkt->list, &foos->pktlist);
		else {
#ifdef DEBUG_QUEUE_PKTS
			printf("Adding packet not at head\n");
#endif
			list_add(&pkt->list, &prev_pkt->list);
		}
	}

	foos->pktcount++;

	return pkt;
}

static inline void
clear_optimize(struct tcp_worker *w, struct tfo_eflow *ef)
{
	if (unlikely(!(ef->flags & TFO_EF_FL_OPTIMIZE)))
		return;

	/* XXX stop current optimization */
	ef->flags &= ~TFO_EF_FL_OPTIMIZE;
	--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

// No - we need to check all buffered packets have been ack'd
	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		_flow_free(w, &w->f[ef->tfo_idx]);
		ef->tfo_idx = TFO_IDX_UNUSED;
	}
}

static void
_eflow_set_state(struct tcp_worker *w, struct tfo_eflow *ef, uint8_t new_state)
{
	--w->st.flow_state[ef->state];
	++w->st.flow_state[new_state];
	ef->state = new_state;
}

static enum tfo_pkt_state
tfo_handle_pkt(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo *fo;
	struct tfo_side *fos, *foos;
	struct tfo_pkt *pkt, *pkt_tmp;
	struct tfo_pkt *next_pkt;
	uint64_t newest_send_time;
	bool duplicate;
	uint32_t seq;
	uint32_t ack;
	bool seq_ok = false;
	uint32_t snd_nxt;
	uint64_t win_end;
	struct rte_tcp_hdr* tcp = p->tcp;
	uint32_t rtt;
	bool rcv_nxt_updated = false;
	bool snd_win_updated = false;
	uint8_t snd_wind_shift;
	uint8_t rcv_wind_shift;
	bool ack_needed;
	uint16_t orig_vlan;
	enum tfo_pkt_state ret = TFO_PKT_HANDLED;
	bool fin_set;
	bool fin_rx;
	uint32_t nxt_seq;
	uint32_t last_seq;

// Need:
//    If syn+ack does not have window scaling, set scale to 0 on original side
//   window from last rx packet (also get from SYN/SYN+ACK/ACK
	if (ef->tfo_idx == TFO_IDX_UNUSED) {
		printf("tfo_handle_pkt called without flow\n");
		return TFO_PKT_FORWARD;
	}

	fo = &w->f[ef->tfo_idx];

	/* If we have received a FIN on this side, we must not receive any
	 * later data. */
	fin_rx = ((ef->state == TCP_STATE_FIN1 &&
		   !!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) == !!(p->from_priv)) ||
		  ef->state == TCP_STATE_FIN2 ||
		  ef->state == TCP_STATE_TIMED_WAIT);

	orig_vlan = p->m->vlan_tci;

	if (p->from_priv) {
		fos = &fo->priv;
		foos = &fo->pub;
		rcv_wind_shift = ef->priv_rcv_wind_shift;
		snd_wind_shift = ef->priv_snd_wind_shift;

		p->m->vlan_tci = pub_vlan_tci;
	} else {
		fos = &fo->pub;
		foos = &fo->priv;
		rcv_wind_shift = ef->pub_rcv_wind_shift;
		snd_wind_shift = ef->pub_snd_wind_shift;

		p->m->vlan_tci = priv_vlan_tci;
	}

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
	if (ef->flags & (TFO_EF_FL_TIMESTAMP | TFO_EF_FL_SACK))
		set_estab_options(p, ef);

	ack = rte_be_to_cpu_32(tcp->recv_ack);

	/* ack obviously out of range. stop optimizing this connection */
// See RFC7232 2.3 for this

// 64 bit todo
	/* This may be a duplicate */
	if (fos->snd_una < ack && ack <= fos->snd_nxt) {
#ifdef DEBUG_ACK
		printf("Looking to remove ack'd packet\n");
#endif

		fos->snd_una = ack;

		/* remove acked buffered packets. We want the time the
		 * most recent packet was sent to update the RTT. */
		newest_send_time = 0;
		list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
// list is oldest first
// 64 bit
#ifdef DEBUG_ACK_PKT_LIST
			printf("  pkt->seq 0x%x pkt->seglen 0x%x, ack 0x%x\n", pkt->seq, pkt->seglen, ack);
#endif

			if (unlikely(pkt->seq + pkt->seglen > ack))
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
			pkt_free(w, pkt);
		}

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
			rtt = (w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec - newest_send_time) / 1000000;
			if (!fos->srtt) {
				fos->srtt = rtt;
				fos->rttvar = rtt / 2;
			} else {
				fos->rttvar = (fos->rttvar * 3 + (fos->srtt > rtt ? (fos->srtt - rtt) : (rtt - fos->srtt))) / 4;
				fos->srtt = (fos->srtt * 7 + rtt) / 8;
			}
			fos->rto = fos->srtt + max(1000, fos->rttvar * 4);

			if (fos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
				printf("New running rto %u, reducing to 60000\n", fos->rto);
#endif
				fos->rto = 60 * 1000;
			}
		}
	}

	if (p->sack_opt) {
		/* Remove all packets ACK'd via SACK */
		uint32_t left_edge, right_edge;
		uint8_t i, num_sack_ent;
		struct tfo_pkt *sack_pkt;
		struct tfo_pkt *resend = NULL;

// For elsewhere - if get SACK and !resent snd_una packet recently (whatever that means), resent unack'd packets not recently resent.
// If don't have them, send ACK to other side if not sending packets
		num_sack_ent = (p->sack_opt->opt_len - sizeof (struct tcp_sack_option)) / sizeof(struct sack_edges);
#ifdef DEBUG_SACK_RX
		printf("Handling SACK with %u entries\n", num_sack_ent);
#endif

		for (i = 0; i < num_sack_ent; i++) {
			left_edge = rte_be_to_cpu_32(p->sack_opt->edges[i].left_edge);
			right_edge = rte_be_to_cpu_32(p->sack_opt->edges[i].right_edge);
#ifdef DEBUG_SACK_RX
			printf("  %u: 0x%x -> 0x%x\n", i,
				rte_be_to_cpu_32(p->sack_opt->edges[i].left_edge),
				rte_be_to_cpu_32(p->sack_opt->edges[i].right_edge));
#endif

			sack_pkt = NULL;
			last_seq = fos->snd_una;
			list_for_each_entry_safe(pkt, pkt_tmp, &fos->pktlist, list) {
				if (pkt->seq + pkt->seglen > right_edge) {
#ifdef DEBUG_SACK_RX
					printf("     0x%x + %u (0x%x) after window\n",
						pkt->seq, pkt->seglen, pkt->seq + pkt->seglen);
#endif
					break;
				}

				if (pkt->seq >= left_edge) {
#ifdef DEBUG_SACK_RX
					printf("     0x%x + %u (0x%x) in window, resend %p\n",
						pkt->seq, pkt->seglen, pkt->seq + pkt->seglen, resend);
#endif

					if (resend) {
						/* Resend the packets before this block */
						list_for_each_entry_from(resend, &fos->pktlist, list) {
							if (resend == pkt)
								break;

							/* If we have already queued it in a previous run
							 * but it is not yet sent, refcnt > 1 */
							if (resend->m->refcnt > 1) {
#ifdef DEBUG_SACK_RX
								printf("Resend packet 0x%x already queued to send\n", resend->seq);
#endif
								continue;
							}

							/* Don't queue a packet more than once */
// We need to optimize this
							for (uint16_t i = 0; i < tx_bufs->nb_tx; i++) {
								if (tx_bufs->m[i] == resend->m) {
#ifdef DEBUG_SACK_RX
									printf("Not queuing resend packet 0x%x again\n", resend->seq);
#endif
									continue;
								}
							}

							if (w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec > resend->ns + fos->rto * 1000000UL) {
								send_tcp_pkt(w, resend, tx_bufs, fos);
#ifdef DEBUG_SACK_RX
								printf("Resending 0x%x following SACK\n", resend->seq);
#endif
							}
#ifdef DEBUG_SACK_RX
							else
								printf("Not resending 0x%x following SACK\n", resend->seq);
#endif
						}
						resend = NULL;
					}

					if (pkt->m) {
						/* This is being "ack'd" for the first time */
// Maybe shouldn't do this - is there a delay before SACK is sent?
						if (pkt->ns > newest_send_time) {
							newest_send_time = pkt->ns;
							duplicate = !!(pkt->flags & TFO_PKT_FL_RESENT);
						}
					}

					if (pkt->seq > last_seq)
						sack_pkt = NULL;
					last_seq = pkt->seq + pkt->seglen;

					if (!sack_pkt) {
						sack_pkt = pkt;
						if (pkt->m)
							pkt_free_mbuf(pkt);
#ifdef DEBUG_SACK_RX
						printf("sack pkt now 0x%x, len %u\n", pkt->seq, pkt->seglen);
#endif
					} else {
						sack_pkt->seglen = pkt->seq + pkt->seglen - sack_pkt->seq;
						pkt_free(w, pkt);
#ifdef DEBUG_SACK_RX
						printf("sack pkt updated 0x%x, len %u\n", sack_pkt->seq, sack_pkt->seglen);
#endif
					}
				} else {
#ifdef DEBUG_SACK_RX
					printf("pkt->m %p, resend %p", pkt->m, resend);
#endif
					if (!pkt->m) {
						sack_pkt = pkt;
						resend = NULL;
					} else {
						sack_pkt = NULL;
						if (!resend)
							resend = pkt;
					}
#ifdef DEBUG_SACK_RX
					printf(" now %p\n", resend);
#endif
				}
			}
		}

		/* Remove SACK option if we will forward packet */
		if (p->seglen)
			remove_sack_option(p);
	}

// should the following only happen if not sack?
	if (fos->snd_una == ack && !list_empty(&fos->pktlist)) {
		pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
		if (pkt->flags & TFO_PKT_FL_SENT &&
		    w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec > pkt->ns + fos->rto * 1000000UL &&
		    pkt->m) {
#ifdef DEBUG_ACK
			printf("Resending seq 0x%x due to repeat ack and timeout, now %lu, rto %u, pkt tmo %lu\n",
				ack, w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec, fos->rto, pkt->ns + fos->rto * 1000000UL);
#endif
// .002 BUG BUG BUG Resending seq 0x7ed1b1d4 due to repeat ack and timeout, now 1646644839128637493, rto 2154, pkt tmo 1646644838737418667
			send_tcp_pkt(w, list_first_entry(&fos->pktlist, typeof(*pkt), list), tx_bufs, fos);
		}
	}

// If have timestamp option, we just compare pkt->TSecr against w->rs.tv_sec, except TSecr is only 32 bits long.

// NOTE: RFC793 says SEQ + WIN should never be reduced - i.e. once a window is given
//  it will be able to be filled.
	seq = rte_be_to_cpu_32(p->tcp->sent_seq);

	if (unlikely(!fin_rx && fin_set))
		fos->fin_seq = seq + p->seglen + 1;

// See RFC 7232 2.3
	/* Window scaling is rfc7323 */
	win_end = fos->rcv_nxt + (fos->rcv_win << rcv_wind_shift);

	/* Check seq is in valid range */
	if (p->seglen == 0) {
	       	if (fos->rcv_win == 0) {
			if (seq == fos->rcv_nxt)
				seq_ok = true;
		} else if (fos->rcv_nxt <= seq && seq < win_end)
			seq_ok = true;
	} else if (fos->rcv_win != 0 &&
		   ((fos->rcv_nxt <= seq && seq < win_end) ||
		    (fos->rcv_nxt <= seq + p->seglen - 1 &&
		     seq + p->seglen - 1 < win_end)))
		seq_ok = true;

	if (!seq_ok) {
		/* Packet is either bogus or duplicate */
// Sort out duplicate behind our window
//		return NULL;
#ifdef DEBUG_TCP_WINDOW
		printf("seq 0x%x len %u is outside rx window fos->rcv_nxt 0x%x -> 0x%x (+0x%x << %u)\n", seq, p->seglen, fos->rcv_nxt, win_end, fos->rcv_win, rcv_wind_shift);
#endif
	} else {
		/* Check no data received after FIN */
		if (unlikely(fin_rx) && seq > fos->fin_seq)
			ret = TFO_PKT_FORWARD;

		/* Update the send window - window end can't go backwards */
#ifdef DEBUG_TCP_WINDOW
		printf("fos->rcv_nxt 0x%x, fos->rcv_win 0x%x rcv_wind_shift %u = 0x%x: seg 0x%x p->seglen 0x%x, tcp->rx_win 0x%x = 0x%x\n", 
			fos->rcv_nxt, fos->rcv_win , rcv_wind_shift, fos->rcv_nxt + (fos->rcv_win << rcv_wind_shift),
			seq , p->seglen , rte_be_to_cpu_16(tcp->rx_win), seq + p->seglen + (rte_be_to_cpu_16(tcp->rx_win) << rcv_wind_shift));
#endif

// This is merely reflecting the same window though.
// This should be optimised to allow a larger window that we buffer.
		if (fos->snd_una + (fos->snd_win << snd_wind_shift) <
		    ack + (rte_be_to_cpu_16(tcp->rx_win) << snd_wind_shift)) {
			snd_win_updated = true;
			fos->snd_win = rte_be_to_cpu_16(tcp->rx_win);

			foos->rcv_win = (ack + (fos->snd_win << snd_wind_shift) - foos->rcv_nxt) >> snd_wind_shift;

#ifdef DEBUG_TCP_WINDOW
			printf("fos->rcv_win updated to 0x%x\n", fos->rcv_win);
#endif
		}

		/* RFC 7323 4.3 (2) */
		if (ef->flags & TFO_EF_FL_TIMESTAMP) {
			if (p->ts_val >= fos->ts_recent &&
			    seq <= fos->rcv_nxt)
				fos->ts_recent = p->ts_val;
		}

		/* If there is no gap before this packet, update rcv_nxt */
		if (seq <= fos->rcv_nxt && seq + p->seglen + (fin_set ? 1 : 0) > fos->rcv_nxt) {
			fos->rcv_nxt = seq + p->seglen;
			if (unlikely(fin_set))
				fos->rcv_nxt++;
			rcv_nxt_updated = true;

			/* Now update for any further contiguous packets we have received */
			if (list_empty(&foos->pktlist)) {
				if (foos->snd_una > fos->rcv_nxt)
					fos->rcv_nxt = foos->snd_una;
			} else {
				nxt_seq = fos->rcv_nxt;
				list_for_each_entry(pkt, &foos->pktlist, list) {
					if (pkt->seq > nxt_seq)
						break;
					if (pkt->seq + pkt->seglen > nxt_seq)
						nxt_seq = pkt->seq + pkt->seglen;

				}

				/* Now update for any further contiguous packets we hae received */
				fos->rcv_nxt = nxt_seq;
			}
		}
	}

	if (seq_ok && (p->seglen || fin_set)) {
		/* Queue the packet, and see if we can advance fos->rcv_nxt further */
		pkt = queue_pkt(w, foos, p, seq);
		if (unlikely(pkt == PKT_IN_LIST)) {
			/* The packet has already been received */
			rte_pktmbuf_free(p->m);
			return TFO_PKT_HANDLED;
		}
		if (unlikely(pkt == PKT_VLAN_ERR)) {
			/* The Vlan header could not be added */
			clear_optimize(w, ef);
			_eflow_set_state(w, ef, TCP_STATE_BAD);

			/* The packet can't be forwarded, so don't return TFO_PKT_FORWARD */
			return TFO_PKT_HANDLED;
		}

		if (pkt) {
#ifdef DEBUG_SND_NXT
			printf("Queued packet m %p seq 0x%x, len %u, rcv_nxt_updated %u\n",
				pkt->m, pkt->seq, pkt->seglen, rcv_nxt_updated);
#endif

			if (rcv_nxt_updated) {
				list_for_each_entry_continue(pkt, &pkt->list, list) {
#ifdef DEBUG_SND_NXT
				printf("Checking pkt m %p, seq 0x%x, seglen %u, fos->rcv_nxt 0x%x\n",
					pkt->m, pkt->seq, pkt->seglen, fos->rcv_nxt);
#endif

					if (list_is_last(&pkt->list, &foos->pktlist))
						break;
					next_pkt = list_next_entry(pkt, list);
// Should we update fos->rcv_win from later packets?
#ifdef DEBUG_SND_NXT
					printf("Checking pkt m %p, seq 0x%x, seglen %u, fos->rcv_nxt 0x%x, next %p seq 0x%x\n",
						pkt->m, pkt->seq, pkt->seglen, fos->rcv_nxt, next_pkt->m, next_pkt->seq);
#endif
					if (pkt->seq + pkt->seglen >= next_pkt->seq)
						fos->rcv_nxt = pkt->seq + pkt->seglen;
				}
			} else {
				struct tfo_pkt_in p;
				struct rte_ether_hdr *eh;

#ifdef DEBUG_SND_NXT
				printf("rcv_nxt_updated = false, resending ack for 0x%x\n", fos->rcv_nxt);
#endif

				p.m = pkt->m;
				p.tcp = pkt->tcp;
				eh = rte_pktmbuf_mtod(pkt->m, struct rte_ether_hdr *);
				if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
					p.ip4h = (struct rte_ipv4_hdr *)((uint8_t *)(eh + 1) + sizeof(struct rte_vlan_hdr));
				else
					p.ip4h = (struct rte_ipv4_hdr *)((uint8_t *)(eh + 1));
				_send_ack_pkt(w, ef, fos, &p, orig_vlan, tx_bufs);
			}
		} else if (fo->flags & TFO_FL_OPTIMIZE) {
			fo->flags &= ~TFO_FL_OPTIMIZE;
// Should this be foos ??? - I haven't thought it through yet
			fos->optim_until_seq = seq;

			ret = TFO_PKT_FORWARD;
		} 
	}

	ack_needed = rcv_nxt_updated;

// COMBINE THE NEXT TWO blocks
// What is limit of no of timeouted packets to send?
	/* Are there sent packets whose timeout has expired */
	if (!list_empty(&fos->pktlist)) {
		pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
// Sort out this check
		if (pkt->m &&
		    pkt->ns + fos->rto * 1000000U < w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec) {
#ifdef DEBUG_RTO
			printf("Resending m %p pkt %p timeout pkt->ns %lu fos->rto %u w->ts %ld.%9.9ld\n",
				pkt->m, pkt, pkt->ns, fos->rto, w->ts.tv_sec, w->ts.tv_nsec);
#endif

			send_tcp_pkt(w, pkt, tx_bufs, fos);
			fos->rto *= 2;		/* See RFC6928 5.5 */
			if (fos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
				printf("rto fos resend after timeout double %u - reducing to 60000\n", fos->rto);
#endif
				fos->rto = 60 * 1000;
			}
			ack_needed = false;
		}
	}

// This needs some optimization. ? keep a pointer to last pkt in window which must be invalidated
	if (snd_win_updated) {
		uint64_t new_win = fos->snd_nxt + (fos->snd_win << snd_wind_shift);
#ifdef DEBUG_SND_NXT
		printf("Considering packets to send, win 0x%lx\n", new_win);
#endif

		list_for_each_entry(pkt, &fos->pktlist, list) {
#ifdef DEBUG_SND_NXT
			printf("pkt_seq 0x%x, seg_len 0x%x sent 0x%x\n", pkt->seq, pkt->seglen, pkt->flags & TFO_PKT_FL_SENT);
#endif

			if (pkt->seq >= new_win)
				break;
			if (!(pkt->flags & TFO_PKT_FL_SENT)) {
				snd_nxt = seq + pkt->seglen;
				if (pkt->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
					snd_nxt++;
#ifdef DEBUG_SND_NXT
				printf("snd_next 0x%x, foos->snd_nxt 0x%x\n", snd_nxt, foos->snd_nxt);
#endif

				if (snd_nxt > fos->snd_nxt)
					fos->snd_nxt = snd_nxt;

				send_tcp_pkt(w, pkt, tx_bufs, fos);
				ack_needed = false;
			}
		}
	}

	/* Are there sent packets on other side whose timeout has expired */
	if (!list_empty(&foos->pktlist)) {
		pkt = list_first_entry(&foos->pktlist, typeof(*pkt), list);

// Sort out this check
		if (!(pkt->flags & TFO_PKT_FL_SENT)) {
			snd_nxt = pkt->seq + pkt->seglen;
			if (pkt->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
				snd_nxt++;

#ifdef DEBUG_RTO
			printf("snd_next 0x%x, foos->snd_nxt 0x%x\n", snd_nxt, foos->snd_nxt);
#endif

			if (snd_nxt > foos->snd_nxt)
				foos->snd_nxt = snd_nxt;
		} else if (pkt->m &&
			   pkt->ns + foos->rto * 1000000 < w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec) {
#ifdef DEBUG_RTO
			printf("Resending packet %p on foos for timeout, pkt flags 0x%x ns %lu foos->rto %u w time %ld.%9.9ld\n",
				pkt->m, pkt->flags, pkt->ns, foos->rto, w->ts.tv_sec, w->ts.tv_nsec);
#endif

			send_tcp_pkt(w, pkt, tx_bufs, foos);
			foos->rto *= 2;		/* See RFC6928 5.5 */

			if (fos->rto > 60 * 1000) {
#ifdef DEBUG_RTO
				printf("rto foos resend after timeout double %u - reducing to 60000\n", foos->rto);
#endif
				fos->rto = 60 * 1000;
			}
		}
	}

// This should only be the packet we have received
	/* Is there anything to send on other side? */
	uint64_t new_win = foos->snd_nxt + (foos->snd_win << snd_wind_shift);

#ifdef DEBUG_TCP_WINDOW
	printf("new_win 0x%llx rcv_nxt 0x%x, rcv_win 0x%x wind_shift %u\n", new_win, foos->rcv_nxt, foos->rcv_win, rcv_wind_shift);
#endif

// Optimise this - ? point to last_sent ??
	list_for_each_entry(pkt, &foos->pktlist, list) {
#ifdef DEBUG_TCP_WINDOW
		printf("  pkt->seq 0x%x, flags 0x%x pkt->seglen %u tcp flags 0x%x foos->snd_nxt 0x%x\n",
			pkt->seq, pkt->flags,pkt->seglen, ((pkt->tcp->data_off << 8) | pkt->tcp->tcp_flags) & 0xfff, foos->snd_nxt);
#endif

		if (pkt->seq >= new_win)
			break;
		if (!(pkt->flags & TFO_PKT_FL_SENT)) {
			snd_nxt = pkt->seq + pkt->seglen;
			if (pkt->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
				snd_nxt++;

			if (snd_nxt > foos->snd_nxt) {
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

			send_tcp_pkt(w, pkt, tx_bufs, foos);
		}
	}

	if (ack_needed)
		_send_ack_pkt(w, ef, fos, p, orig_vlan, tx_bufs);

	if (fin_set && !fin_rx) {
		fos->fin_seq = seq + p->seglen + 1;
#ifdef DEBUG_FIN
		printf("Set fin_seq 0x%x - seq 0x%x seglen %u\n", fos->fin_seq, seq, p->seglen);
#endif
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
 *   TCP_STATE_CLOSED: closed
 *   TCP_STATE_SYN: syn seen	// See RFC793 for strange connection setup sequences
 *   TCP_STATE_SYN_ACK: syn+ack seen
 *   TCP_STATE_ESTABLISHED: established
 *   TCP_STATE_FIN1: connection closing (fin seen in 1 way)
 *   TCP_STATE_FIN2: connection closing (fin seen in 2 way)
 *   TCP_STATE_TIMED_WAIT: connection closed, time_wait
 *   TCP_STATE_RESET: reset state
 *   TCP_STATE_BAD: bad state
 */
static enum tfo_pkt_state
tfo_tcp_sm(struct tcp_worker *w, struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	uint8_t flags = p->tcp->tcp_flags;
	struct tfo_side *server_fo, *client_fo;
	uint32_t ack;
	uint32_t seq;
	struct tfo *fo;
	uint8_t wind_shift;
	uint32_t win_end;
	bool seq_ok;
	bool ok;
	enum tfo_pkt_state ret;

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
	printf("State %u, pkt flags 0x%x, flow flags 0x%x, seq 0x%x, ack 0x%lx, data_len 0x%lx\n", ef->state, flags, ef->flags,
#endif

	rte_be_to_cpu_32(p->tcp->sent_seq), (flags | RTE_TCP_ACK_FLAG ? 0UL : 0xffff00000000UL) + rte_be_to_cpu_32(p->tcp->recv_ack), 
	rte_pktmbuf_mtod(p->m, uint8_t *) + p->m->pkt_len - ((uint8_t *)p->tcp + (p->tcp->data_off >> 2)));

	/* Most packets will be in established state with ACK set */
	if ((likely(ef->state == TCP_STATE_ESTABLISHED) ||
	     unlikely(ef->state == TCP_STATE_FIN1) ||
	     unlikely(ef->state == TCP_STATE_FIN2)) &&
	    (likely((flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_RST_FLAG)) == RTE_TCP_ACK_FLAG))) {
		set_estb_pkt_counts(w, flags);

		if (ef->flags & TFO_EF_FL_OPTIMIZE)
			return tfo_handle_pkt(w, p, ef, tx_bufs);

		return TFO_PKT_FORWARD;
	}

// What if ESTABLISHED and ACK not set?

	/* reset flag, stop everything */
	if (flags & RTE_TCP_RST_FLAG) {
// if (ef->state == TCP_STATE_SYN) connection is being rejected
// connection can also be rejected with ICMP, which will contain TCP header
		++w->st.rst_pkt;
		clear_optimize(w, ef);
//		if (ef->flags & TFO_EF_FL_OPTIMIZE) {
//			/* XXX stop current optimization */
//			ef->flags &= ~TFO_EF_FL_OPTIMIZE;
//			--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];
//		}
// How do we get out of reset state?
		_eflow_set_state(w, ef, TCP_STATE_RESET);
		return TFO_PKT_FORWARD;
	}

	/* RST flag unset */

// Assume SYN and FIN packets can contain data - see last para p26 of RFC793,
//   i.e. before sequence number selection
	/* syn flag */
	if (flags & RTE_TCP_SYN_FLAG) {
		/* invalid packet, won't optimize */
		if (flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) {
// Should only have ACK, ECE (and ? PSH, URG)
// We should delay forwarding FIN until have received ACK for all data we have ACK'dorig_vlan;
// Not sure about RST
			_eflow_set_state(w, ef, TCP_STATE_BAD);
			++w->st.syn_bad_flag_pkt;
			return TFO_PKT_FORWARD;
		}

		switch (ef->state) {
		case TCP_STATE_SYN_ACK:
			if ((flags & RTE_TCP_ACK_FLAG)) {
				/* duplicate syn+ack */
				++w->st.syn_ack_dup_pkt;
				break;
			}
			/* fallthrough */

		case TCP_STATE_ESTABLISHED:
			if (flags & RTE_TCP_ACK_FLAG)
				++w->st.syn_ack_on_eflow_pkt;
			else
				++w->st.syn_on_eflow_pkt;

			/* already optimizing, this is a new flow ? free current */
			/* XXX todo */
			_eflow_set_state(w, ef, TCP_STATE_CLOSED);
			clear_optimize(w, ef);
//			if (ef->flags & TFO_EF_FL_OPTIMIZE) {
//				ef->flags &= ~TFO_EF_FL_OPTIMIZE;
//				--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];
//			}

			/* fallthrough */

		case TCP_STATE_CLOSED:
			/* syn+ack first, we didn't see syn */

#ifdef DEBUG_SM
			printf("Received SYN, flags 0x%x, send_seq %x seglen %u rx_win %u\n",
				flags, rte_be_to_cpu_32(p->tcp->sent_seq), p->seglen, rte_be_to_cpu_16(p->tcp->rx_win));
#endif
			if (flags & RTE_TCP_ACK_FLAG) {
				_eflow_set_state(w, ef, TCP_STATE_BAD);
				++w->st.syn_ack_first_pkt;
				break;
			}

// Bad if FIN, URG, PSH, CWR  set ? if NS set
			if (!set_tcp_options(p, ef)) {
				_eflow_set_state(w, ef, TCP_STATE_BAD);
				++w->st.syn_bad_pkt;
				break;
			}

			/* ok, wait for syn+ack */
			_eflow_set_state(w, ef, TCP_STATE_SYN);
			ef->server_snd_una = rte_be_to_cpu_32(p->tcp->sent_seq);
			ef->client_rcv_nxt = ef->server_snd_una + 1 + p->seglen;
			ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
			if (p->from_priv)
				ef->flags |= TFO_EF_FL_SYN_FROM_PRIV;
			++w->st.syn_pkt;

// If data, queue packet. Also, when sent the timestamp needs updating
			break;

		case TCP_STATE_SYN:
			/* syn flag alone */
			if (!(flags & RTE_TCP_ACK_FLAG)) {
				if (!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) ==
				    !!p->from_priv) {
					/* duplicate of first syn */
					++w->st.syn_dup_pkt;
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
// 64 bit
				ack = rte_be_to_cpu_32(p->tcp->recv_ack);
				if (unlikely(!(ef->server_snd_una < ack && ack <= ef->client_rcv_nxt))) {
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
		return TFO_PKT_FORWARD;
	}

	/* SYN and RST flags unset */

	/* fin flag */
	if (flags & RTE_TCP_FIN_FLAG) {
		switch (ef->state) {
		case TCP_STATE_CLOSED:
		case TCP_STATE_SYN:
		case TCP_STATE_SYN_ACK:
		default:
// Setting state BAD should stop optimisation
			_eflow_set_state(w, ef, TCP_STATE_BAD);
			++w->st.fin_unexpected_pkt;

			return TFO_PKT_FORWARD;

		case TCP_STATE_ESTABLISHED:
			ok = true;
			if (ef->flags & TFO_EF_FL_OPTIMIZE) {
				ret = tfo_handle_pkt(w, p, ef, tx_bufs);
				if (ret != TFO_PKT_HANDLED)
					ok = false;
			}

			if (ok) {
				_eflow_set_state(w, ef, TCP_STATE_FIN1);
				if (p->from_priv)
					ef->flags |= TFO_EF_FL_FIN_FROM_PRIV;
			}

			++w->st.fin_pkt;

			if (ef->flags & TFO_EF_FL_OPTIMIZE)
				return ret;

			break;

		case TCP_STATE_FIN1:
			ok = true;
			if (ef->flags & TFO_EF_FL_OPTIMIZE) {
				ret = tfo_handle_pkt(w, p, ef, tx_bufs);
				if (ret != TFO_PKT_HANDLED)
					ok = false;
			}

			if (!!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) != !!p->from_priv) {
				if (ok)
					_eflow_set_state(w, ef, TCP_STATE_FIN2);

				++w->st.fin_pkt;
			} else
				++w->st.fin_dup_pkt;

			if (ef->flags & TFO_EF_FL_OPTIMIZE)
				return ret;

			break;

		case TCP_STATE_FIN2:
			++w->st.fin_dup_pkt;
			break;
		}
	}

	/* SYN, FIN and RST flags unset */

	if (ef->state == TCP_STATE_SYN_ACK && (flags & RTE_TCP_ACK_FLAG) &&
	    !!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) == !!p->from_priv) {
// We should just call handle_pkt, which detects state SYN_ACK and if pkt ok transitions to ESTABLISHED
		fo = &w->f[ef->tfo_idx];
		if (p->from_priv) {
			server_fo = &fo->pub;
			client_fo = &fo->priv;
			wind_shift = ef->priv_rcv_wind_shift;
		} else {
			server_fo = &fo->priv;
			client_fo = &fo->pub;
			wind_shift = ef->pub_rcv_wind_shift;
		}

// We should only receive more data from server after we have forwarded 3rd ACK unless arrive out of sequence,
//  in which case 3rd ACK can be dropped when receive
		ack = rte_be_to_cpu_32(p->tcp->recv_ack);
		seq = rte_be_to_cpu_32(p->tcp->sent_seq);

// See RFC 7232 2.3
		/* Window scaling is rfc7323 */
		win_end = client_fo->rcv_nxt + (client_fo->rcv_win << wind_shift);
#ifdef DEBUG_TCP_WINDOW
		printf("rcv_win 0x%x cl rcv_nxt 0x%x rcv_win 0x%x wind_shift %u\n",
			win_end, client_fo->rcv_nxt, client_fo->rcv_win, wind_shift);
#endif

// We are duplicating code from handle_pkt here
		/* Check seq is in valid range */
		seq_ok = false;
		if (p->seglen == 0) {
			if (client_fo->rcv_win == 0) {
				if (seq == client_fo->rcv_nxt)
					seq_ok = true;
			} else if (client_fo->rcv_nxt <= seq && seq < win_end)
				seq_ok = true;
		} else if (client_fo->rcv_win != 0 &&
			   ((client_fo->rcv_nxt <= seq && seq < win_end) ||
			    (client_fo->rcv_nxt <= seq + p->seglen - 1 &&
			     seq + p->seglen - 1 < win_end)))
			seq_ok = true;

		if (likely(client_fo->snd_una < ack && ack <= client_fo->snd_nxt &&
			   seq_ok)) {
			/* last ack of 3way handshake, go to established state */
			_eflow_set_state(w, ef, TCP_STATE_ESTABLISHED);
// Set next in send_pkt
			client_fo->snd_una = ack;
			server_fo->rcv_nxt = rte_be_to_cpu_32(p->tcp->recv_ack);
			set_estab_options(p, ef);
			server_fo->latest_ts_val_sent = p->ts_val;
set_estb_pkt_counts(w, flags);

			return TFO_PKT_FORWARD;
		} else {
#ifdef DEBUG_SM
			printf("ACK to SYN_ACK%s%s mismatch, seq:ack packet 0x%x:0x%x saved rn 0x%x rw 0x%x su 0x%x sn 0x%x\n",
				!(client_fo->snd_una < ack && ack <= client_fo->snd_nxt) ? " ack" : "",
				seq_ok ? "" : " seq",
				rte_be_to_cpu_32(p->tcp->sent_seq),
				rte_be_to_cpu_32(p->tcp->recv_ack),
				client_fo->rcv_nxt, client_fo->rcv_win,
				client_fo->snd_una, client_fo->snd_nxt);
#endif

			_eflow_set_state(w, ef, TCP_STATE_BAD);
		}
	} else if (ef->state == TCP_STATE_FIN2 && (flags & RTE_TCP_ACK_FLAG)) {
		/* ack in fin2 state, go to time_wait state if all pkts ack'd */
		ok = true;
		ret = TFO_PKT_FORWARD;

		if (ef->flags & TFO_EF_FL_OPTIMIZE) {
			fo = &w->f[ef->tfo_idx];
			ret = tfo_handle_pkt(w, p, ef, tx_bufs);
#ifdef DEBUG_SM
			printf("FIN2 - cl rcv_nxt 0x%x fin_seq 0x%x, sv rcv_nxt 0x%x fin_seq 0x%x ret %u\n",
				fo->priv.rcv_nxt, fo->priv.fin_seq, fo->pub.rcv_nxt, fo->pub.fin_seq, ret);
#endif
			if (ret == TFO_PKT_HANDLED) {
				if (fo->priv.rcv_nxt == fo->priv.fin_seq &&
				    fo->pub.rcv_nxt == fo->pub.fin_seq)
					clear_optimize(w, ef);
				else {
#ifdef DEBUG_SM
					printf("FIN2 check failed - cl rcv_nxt 0x%x fin_seq 0x%x, sv rcv_nxt 0x%x fin_seq 0x%x\n",
						fo->priv.rcv_nxt, fo->priv.fin_seq, fo->pub.rcv_nxt, fo->pub.fin_seq);
#endif

					ok = false;
				}
			} else
				ok = false;
		}

		if (ok)
			_eflow_set_state(w, ef, TCP_STATE_TIMED_WAIT);

		return ret;
	}

	if (likely(ef->state == TCP_STATE_ESTABLISHED)) {
		set_estb_pkt_counts(w, flags);
	} else if (ef->state < TCP_STATE_ESTABLISHED) {
		++w->st.syn_state_pkt;
	} else if (ef->state == TCP_STATE_RESET) {
		++w->st.rst_state_pkt;
	} else if (ef->state == TCP_STATE_BAD) {
		++w->st.bad_state_pkt;
	} else if (ef->state != TCP_STATE_TIMED_WAIT) {
		++w->st.fin_state_pkt;
	}

// tfo_handle_pkt should only be called if data or ack. ? Not for SYN with data ? What about FIN with data
// This is probably OK since we only optimize when in EST, FIN1 or FIN2 state
// We need to handle stopping optimisation - we can stop on a side once see an ack for the last packet we have
	if (ef->flags & TFO_EF_FL_OPTIMIZE)
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
				- ((p->tcp->data_off & 0xf0) >> 2);
#ifdef DEBUG_PKT_RX
	printf("pkt_len %u tcp %p tcp_offs %lu, tcp_len %u, mtod %p, seg_len %u\n",
		p->m->pkt_len, p->tcp, (uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *),
		(p->tcp->data_off & 0xf0) >> 2, rte_pktmbuf_mtod(p->m, uint8_t *), p->seglen);
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
		if (p->tcp->tcp_flags & RTE_TCP_RST_FLAG)
			return TFO_PKT_FORWARD;

// If we see data w/o syn, and see data in both directions, we could start optimizing
// Even for a CGN it may have split traffic, e.g. in on Wifi, out on mobile network
if ((p->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG | RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)) != RTE_TCP_SYN_FLAG) {
	/* This is not a new flow  - it might have existed before we started */
	return TFO_PKT_FORWARD;
}

		hu = tfo_user_v4_hash(config, priv_addr);
		u = tfo_user_v4_lookup(w, priv_addr, hu);
#ifdef DEBUG_USER
		printf("hu = %u, u = %p\n", hu, u);
#endif

		if (u == NULL) {
			u = _user_alloc(w, hu, 0);
			if (u == NULL)
				return TFO_PKT_NO_RESOURCE;
			u->priv_addr.v4 = priv_addr;

#ifdef DEBUG_USER
			printf("u now %p\n", u);
#endif
		}
		ef = _eflow_alloc(w, u, h);
		if (ef == NULL) {
// Free user
			return TFO_PKT_NO_RESOURCE;
		}
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v4 = pub_addr;
		ef->client_rcv_nxt = rte_be_to_cpu_32(p->tcp->sent_seq) + p->seglen;
	}

	ef->last_use = w->ts.tv_sec;
// We should only call tfo_tcp_sm if we haven't allocated the ef, since then we know the state 
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
				- ((p->tcp->data_off & 0xf0) << 2);

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

// If we see data w/o syn, and see data in both directions, we could start optimizing
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
	uint16_t hdr_len;
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
		vlan_tci = rte_be_to_cpu_16(vl->vlan_tci);
		if (m->vlan_tci && m->vlan_tci != vlan_tci)
			printf("vlan id mismatch - m %u pkt %u\n", m->vlan_tci, vlan_tci);
		m->vlan_tci = vlan_tci;
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
tfo_packet_no_room_for_vlan(struct rte_mbuf *) {
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
	int ret;
	struct timespec ts_local;
	struct rte_mbuf *m;
	bool from_priv;
#ifdef DEBUG_BURST
	struct tm tm;
	char str[24];
	unsigned long gap;
#endif

	if (!ts) {
		ts = &ts_local;
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts_local);
	}

#ifdef DEBUG_BURST
	gap = (ts->tv_sec - w->ts.tv_sec) * 1000000000UL + (ts->tv_nsec - w->ts.tv_nsec);
	localtime_r(&ts->tv_sec, &tm);
	strftime(str, 24, "%T", &tm);
	printf("\n%s.%9.9ld Burst received %u pkts time %ld.%9.9ld gap %lu\n", str, ts->tv_nsec, nb_rx, ts->tv_sec, ts->tv_nsec, gap);
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
		m = rx_buf[i];
		from_priv = !!(rx_buf[i]->ol_flags & config->dynflag_in_priv_mask);

		if ((m->packet_type & RTE_PTYPE_L4_MASK) != RTE_PTYPE_L4_TCP ||
		    ((ret = tcp_worker_mbuf_pkt(w, m, from_priv, tx_bufs)) != TFO_PKT_HANDLED &&
		     ret != TFO_PKT_INVALID)) {
			m->vlan_tci = from_priv ? pub_vlan_tci : priv_vlan_tci;
			if (update_pkt(m)) {
#ifndef DEBUG_PKTS
				printf("adding tx_buf %p, vlan %u, ret %d\n", m, m->vlan_tci, ret);
#endif
				add_tx_buf(w, m, tx_bufs, from_priv, (union tfo_ip_p)(struct rte_ipv4_hdr *)NULL);
			} else
				printf("dropping tx_buf %p, vlan %u, ret %d, no room for vlan header\n", m, m->vlan_tci, ret);
		}
		dump_details(w);
	}

	if (!tx_bufs->nb_tx) {
		if (tx_bufs->m)
			rte_free(tx_bufs->m);
		tx_bufs->nb_tx = 0;
	}

	return tx_bufs;
}

void
tcp_worker_mbuf_burst_send(struct rte_mbuf **rx_buf, uint16_t nb_rx, struct timespec *ts)
{
	struct tfo_tx_bufs tx_bufs = { .nb_inc = nb_rx };

	tcp_worker_mbuf_burst(rx_buf, nb_rx, ts, &tx_bufs);

	tfo_send_burst(&tx_bufs);
}

struct tfo_tx_bufs *
tcp_worker_mbuf(struct rte_mbuf *m, int from_priv, struct timespec *ts, struct tfo_tx_bufs *tx_bufs)
{
	if (from_priv)
		m->ol_flags |= config->dynflag_in_priv_mask;

	return tcp_worker_mbuf_burst(&m, 1, ts, tx_bufs);
}

void
tcp_worker_mbuf_send(struct rte_mbuf *m, int from_priv, struct timespec *ts)
{
	if (from_priv)
		m->ol_flags |= config->dynflag_in_priv_mask;

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
	uint16_t i;
	struct tfo_side *s;
	struct tfo_pkt *p;
	struct tfo_user *u;
	struct tfo *fo;
	bool pkt_resent;
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

	clock_gettime(CLOCK_REALTIME, &w->ts);
	now = w->ts.tv_sec * 1000000000UL + w->ts.tv_nsec;

	for (i = 0; i < config->hu_n; i++) {
		if (!hlist_empty(&w->hu[i])) {
			hlist_for_each_entry(u, &w->hu[i], hlist) {
				// print user
				hlist_for_each_entry(ef, &u->flow_list, flist) {
					if (ef->tfo_idx == TFO_IDX_UNUSED)
						continue;

					fo = &w->f[ef->tfo_idx];
					s = &fo->priv;

					while (s) {
						pkt_resent = false;
						list_for_each_entry(p, &s->pktlist, list) {
//printf("Checking packet %p seq 0x%x ns %lu rto %u now %" PRIu64 " cal %lu\n", p->m, p->seq, p->ns, s->rto, now, p->ns + s->rto * 1000000UL);
							if (p->m && (p->ns + s->rto * 1000000UL < now)) {
								if (p->flags & TFO_PKT_FL_SENT)
									pkt_resent = true;
								send_tcp_pkt(w, p, tx_bufs, s);

#ifdef DEBUG_GARBAGE
								printf("Resending 0x%x %u\n", p->seq, p->seglen);
								sent = true;
#endif
							}
						}

						if (pkt_resent) {
							s->rto *= 2;

							if (s->rto > 60 * 1000) {
#ifdef DEBUG_RTO
								printf("rto garbage resend after timeout double %u - reducing to 60000\n", s->rto);
#endif
								s->rto = 60 * 1000;
							}
						}

						s = s == &fo->priv ? &fo->pub : NULL;
					}
				}
			}
		}
	}

#ifdef DEBUG_GARBAGE
	if (sent) {
		printf("Resent packets at %ld.%9.9ld\n", w->ts.tv_sec, w->ts.tv_nsec);
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
		ef->state = TCP_STATE_NONE;
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

	return config->dynflag_in_priv_mask;
}

void
tcp_init(const struct tcp_config *c)
{
	global_config_data = *c;
	int flag;
	const struct rte_mbuf_dynflag dynflag = {
                .name = "dynflag-in-priv",
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
        global_config_data.dynflag_in_priv_mask = (1ULL << flag);
}

uint16_t
tfo_max_ack_pkt_size(void)
{
	return sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_vlan_hdr) +
		sizeof(struct rte_ipv6_hdr) +
		sizeof(struct rte_tcp_hdr) +
		((sizeof(struct tcp_timestamp_option) + 3) & ~3) +
		((sizeof(struct tcp_sack_option) + 3) & ~3);
}
