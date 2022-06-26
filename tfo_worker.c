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
 * -2. Make ACK after SYN+ACK normal packet processing
 * -1.9. We generate ACK to SYN+ACK and therefore queue it - this should be an option
 * -1. Timestamp, ack and win updating on send
 *  -0.95. Use timestamp along with seq/ack to ensure packet not 'old' - PAWS in RFC7323
 *  -0.94. Ensure seq/ack within 1GiB. Anythink more that 1GiB old is dubious (or at least old)
 * -0.9. Work out our policy for window size
 * 1. Tidy up code
 * 2. Optimize code
 * 2.1 See https://www.hamilton.ie/net/LinuxHighSpeed.pdf:
 * 	Order the SACK blocks by seq so walk pktlist once
 *	Walk the SACK holes
 *	Cache pointers for retransmission walk
 *	When number of holes becomes large, cache the SACK entries so walk fewer times
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
 * RFC 6937 - Proportional Rate Reduction for TCP - experimental
 * RFC 7323 - TCP Extensions for High Performance
 * RFC 7413 - TCP Fast Open
 * RFC 7414 - A list of the 8 required specifications and over 20 strongly encouraged enhancements, includes RFC 2581, TCP Congestion Control.
 * RFC 8312 - ? TCP CUBIC
 * RFC 8985 - The RACK-TLP Loss Detection Algorithm for TCP
		 see also https://datatracker.ietf.org/meeting/100/materials/slides-100-tcpm-draft-ietf-tcpm-rack-01

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
 *  0. DSACK - RFC2883
 *  1. RFC8985
 *  	Replaces loss recovery in RFCs 5681, 6675, 5827 and 4653.
 *  	Is compatible with RFCs 6298, 7765, 5682 and 3522.
 *  	Does not modify congestion control in RFCs 5681, 6937 (recommended)
 *  1a. RFC7323 - using timestamps - when send a packet send it with latest TS received, or use calculated clock to calculate own
 *  1b. ACK alternate packets with a timeout
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

#ifndef NO_DEBUG
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
#define DEBUG_GARBAGE
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
#define DEBUG_RACK_SACKED
#define DEBUG_TS_SPEED
#define DEBUG_QUEUED
#define DEBUG_POSTPROCESS
#define DEBUG_DELAYED_ACK
#define DEBUG_USERS_TX_CLOCK
//#define DEBUG_SEND_PKT
//#define DEBUG_SEND_PKT_LOCATION
//#define DEBUG_SEND_DSACK_CHECK
//#define DEBUG_THROUGHPUT
//#define DEBUG_DISABLE_TS
//#define DEBUG_DISABLE_SACK
#define DEBUG_RECOVERY


#define WRITE_PCAP
#ifdef WRITE_PCAP
// #define DEBUG_PCAP_MEMPOOL
#endif
#endif

// XXX - add code for not releasing
#define RELEASE_SACKED_PACKETS

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
	uint32_t src_addr;
	uint32_t dst_addr;
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
static thread_local uint64_t now;
static thread_local struct list_head send_failed_list;
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

#if defined DEBUG_STRUCTURES || defined DEBUG_PKTS || defined DEBUG_GARBAGE
#define	SI	"  "
#define	SIS	" "

static void
print_side(const struct tfo_side *s, bool using_rack)
{
	struct tfo_pkt *p;
	uint32_t next_exp;
	uint64_t time_diff;
	uint16_t num_gaps = 0;
	uint8_t *data_start;
	unsigned sack_entry, last_sack_entry;
	uint16_t num_in_flight = 0;
	uint16_t num_sacked = 0;
	uint16_t num_queued = 0;
	char flags[9];

	flags[0] = '\0';
	if (s->flags & TFO_SIDE_FL_IN_RECOVERY) strcat(flags, "R");
	if (s->flags & TFO_SIDE_FL_ENDING_RECOVERY) strcat(flags, "r");
	if (s->flags & TFO_SIDE_FL_RACK_REORDERING_SEEN) strcat(flags, "O");
	if (s->flags & TFO_SIDE_FL_DSACK_ROUND) strcat(flags, "D");
	if (s->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) strcat(flags, "P");
	if (s->flags & TFO_SIDE_FL_TLP_IS_RETRANS) strcat(flags, "t");
	if (s->flags & TFO_SIDE_FL_RTT_CALC) strcat(flags, "C");
	if (s->flags & TFO_SIDE_FL_NEW_RTT) strcat(flags, "n");

	printf(SI SI SI "rcv_nxt 0x%x snd_una 0x%x snd_nxt 0x%x snd_win 0x%x rcv_win 0x%x ssthresh 0x%x"
		" cwnd 0x%x dup_ack %u\n"
		SI SI SI SIS "last_rcv_win_end 0x%x snd_win_shift %u rcv_win_shift %u mss 0x%x flags-%s rtt_min %u packet_type 0x%x in_flight %u queued %u",
		s->rcv_nxt, s->snd_una, s->snd_nxt, s->snd_win, s->rcv_win, s->ssthresh, s->cwnd, s->dup_ack,
		s->last_rcv_win_end, s->snd_win_shift, s->rcv_win_shift, s->mss, flags, minmax_get(&s->rtt_min), s->packet_type, s->pkts_in_flight, s->pkts_queued_send);
	if (!list_empty(&s->xmit_ts_list))
		printf(" 0x%x 0x%x",
			list_first_entry(&s->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->seq,
			list_last_entry(&s->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->seq);
	printf("\n");
	if (s->sack_entries || s->sack_gap) {
		printf(SI SI SI SIS "sack_gaps %u sack_entries %u, first_entry %u", s->sack_gap, s->sack_entries, s->first_sack_entry);
		last_sack_entry = (s->first_sack_entry + s->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
		for (sack_entry = s->first_sack_entry; ; sack_entry = (sack_entry + 1) % MAX_SACK_ENTRIES) {
			printf(" [%u]: 0x%x -> 0x%x", sack_entry, s->sack_edges[sack_entry].left_edge, s->sack_edges[sack_entry].right_edge);
			if (sack_entry == last_sack_entry)
				break;
		}
		printf("\n");
	}
	printf(SI SI SI SIS "srtt %u rttvar %u rto %u #pkt %u, ttl %u snd_win_end 0x%x rcv_win_end 0x%x",
		s->srtt_us, s->rttvar_us, s->rto_us, s->pktcount, s->rcv_ttl,
		s->snd_una + (s->snd_win << s->snd_win_shift),
		s->rcv_nxt + (s->rcv_win << s->rcv_win_shift));
#ifdef DEBUG_RTT_MIN
	printf(" rtt_min [0] %u,%u [1] %u,%u [2] %u,%u",
		s->rtt_min.s[0].v, s->rtt_min.s[0].t,
		s->rtt_min.s[1].v, s->rtt_min.s[1].t,
		s->rtt_min.s[2].v, s->rtt_min.s[2].t);
#endif
	printf("\n" SI SI SI SIS "ts_recent %1$u (0x%1$x), ack_sent_time %2$" PRIu64 ".%3$9.9" PRIu64,
		rte_be_to_cpu_32(s->ts_recent), NSEC_TIME_PRINT_PARAMS(s->ack_sent_time));
#ifdef CALC_USERS_TS_CLOCK
	printf(" TS start %u at " TIMESPEC_TIME_PRINT_FORMAT, s->ts_start, TIMESPEC_TIME_PRINT_PARAMS(&s->ts_start_time));
#endif
#ifdef CWND_USE_RECOMMENDED
	printf(" cum_ack 0x%x", s->cum_ack);
#endif
	if (s->ack_timeout == TFO_INFINITE_TS)
		printf(" ack timeout unset");
	else if (s->ack_timeout == TFO_ACK_NOW_TS)
		printf(" ack timeout 3WHS ACK");
	else
		printf (" ack timeout " NSEC_TIME_PRINT_FORMAT " in %lu", NSEC_TIME_PRINT_PARAMS(s->ack_timeout), s->ack_timeout - now);
#ifdef DEBUG_RACK
	if (using_rack) {
		printf("\n" SI SI SI SIS "RACK: xmit_ts " NSEC_TIME_PRINT_FORMAT " end_seq 0x%x segs_sacked %u fack 0x%x rtt %u reo_wnd %u dsack_round 0x%x reo_wnd_mult %u\n"
		       SI SI SI SIS "      reo_wnd_persist %u tlp_end_seq 0x%x tlp_max_ack_delay %u recovery_end_seq 0x%x cur_timer %u ",
			NSEC_TIME_PRINT_PARAMS(s->rack_xmit_ts), s->rack_end_seq, s->rack_segs_sacked, s->rack_fack,
			s->rack_rtt_us, s->rack_reo_wnd_us, s->rack_dsack_round, s->rack_reo_wnd_mult,
			s->rack_reo_wnd_persist, s->tlp_end_seq, s->tlp_max_ack_delay_us, s->recovery_end_seq, s->cur_timer);
		if (s->timeout == TFO_INFINITE_TS)
			printf("unset");
		else
			printf ("timeout " NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->timeout), NSEC_TIME_PRINT_PARAMS(s->timeout - now));
	}
#endif
	printf("\n");

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

			printf(SI SI SI "%4u:\tm %p, seq 0x%x%s len %u flags-%s tcp_flags-%s vlan %u ip %ld tcp %ld ts %ld sack %ld sackd segs %u refcnt %u",
				i, p->m, p->seq, segend(p) > s->snd_una + (s->snd_win << s->snd_win_shift) ? "*" : "",
				p->seglen, s_flags, tcp_flags, p->m->vlan_tci,
				(uint8_t *)p->ipv4 - data_start,
				(uint8_t *)p->tcp - data_start,
				p->ts ? (uint8_t *)p->ts - data_start : 0U,
				p->sack ? (uint8_t *)p->sack - data_start : 0U,
				p->rack_segs_sacked,
				p->m->refcnt);
		} else
			printf(SI SI SI "%4u:\tm %p, seq 0x%x%s len %u flags-%s sacked_segs %u",
				i, p->m, p->seq, segend(p) > s->snd_una + (s->snd_win << s->snd_win_shift) ? "*" : "",
				p->seglen, s_flags,
				p->rack_segs_sacked);
		if (p->ns != TFO_TS_NONE) {
			time_diff = now - p->ns;
			printf(" ns " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(time_diff));

			if (!(p->flags & TFO_PKT_FL_SENT))
				printf(" (%lu)", p->ns);
		}
		if (!list_empty(&p->xmit_ts_list)) {
			printf(" flgt 0x%x <-> 0x%x",
				list_is_first(&p->xmit_ts_list, &s->xmit_ts_list) ? 0 : list_prev_entry(p, xmit_ts_list)->seq,
				list_is_last(&p->xmit_ts_list, &s->xmit_ts_list) ? 0 : list_next_entry(p, xmit_ts_list)->seq);

			if (!(p->flags & TFO_PKT_FL_LOST))
				num_in_flight++;
		}

		if (p->flags & TFO_PKT_FL_QUEUED_SEND)
			num_queued++;

		if (!p->m)
			num_sacked += p->rack_segs_sacked;

		if (before(p->seq, next_exp))
			printf(" *** overlap = %ld", (int64_t)next_exp - (int64_t)p->seq);
		printf("\n");
		next_exp = segend(p);
	}

	if (num_gaps != s->sack_gap)
		printf("*** s->sack_gap %u, num_gaps %u\n", s->sack_gap, num_gaps);

	if (s->pkts_in_flight != num_in_flight)
		printf("*** NUM_IN_FLIGHT should be %u\n", num_in_flight);

	if (s->pkts_queued_send != num_queued)
		printf("*** NUM_QUEUED should be %u\n", num_queued);

	if (s->rack_segs_sacked != num_sacked)
		printf("*** NUM_SEGS_SACKED should be %u\n", num_sacked);
}

static void
dump_details(const struct tcp_worker *w)
{
	struct tfo_user *u;
	struct tfo_eflow *ef;
	struct tfo *fo;
	unsigned i;
	char flags[9];
#ifdef DEBUG_ETHDEV
	uint16_t port;
	struct rte_eth_stats eth_stats;
#endif

	printf("time: " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(now));
	printf("  In use: users %u, eflows %u, flows %u, packets %u, max_packets %u\n", w->u_use, w->ef_use, w->f_use, w->p_use, w->p_max_use);
	for (i = 0; i < config->hu_n; i++) {
		if (!hlist_empty(&w->hu[i])) {
			printf("\nUser hash %u\n", i);
			hlist_for_each_entry(u, &w->hu[i], hlist) {
				// print user
				flags[0] = '\0';
				if (u->flags & TFO_USER_FL_V6) strcat(flags, "6");
#ifdef DEBUG_MEM
				if (u->flags & TFO_USER_FL_USED) strcat(flags, "U");
#endif

				printf(SI "User: %p priv addr %x, flags-%s num flows %u\n", u, u->priv_addr.v4, flags, u->flow_n);
				hlist_for_each_entry(ef, &u->flow_list, flist) {
					// print eflow
					flags[0] = '\0';
					if (ef->flags & TFO_EF_FL_SYN_FROM_PRIV) strcat(flags, "P");
					if (ef->flags & TFO_EF_FL_FIN_FROM_PRIV) strcat(flags, "p");
					if (ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN) strcat(flags, "s");
					if (ef->flags & TFO_EF_FL_STOP_OPTIMIZE) strcat(flags, "o");
					if (ef->flags & TFO_EF_FL_SACK) strcat(flags, "S");
					if (ef->flags & TFO_EF_FL_TIMESTAMP) strcat(flags, "T");
					if (ef->flags & TFO_EF_FL_IPV6) strcat(flags, "6");
					if (ef->flags & TFO_EF_FL_DUPLICATE_SYN) strcat(flags, "D");

					printf(SI SI "ef %p state %u tfo_idx %u, ef->pub_addr.v4 %x port: priv %u pub %u flags-%s user %p last_use %u\n",
						ef, ef->state, ef->tfo_idx, ef->pub_addr.v4, ef->priv_port, ef->pub_port, flags, ef->u, ef->last_use);
					if (ef->state == TCP_STATE_SYN)
						printf(SI SI SIS "svr_snd_una 0x%x cl_snd_win 0x%x cl_rcv_nxt 0x%x cl_ttl %u\n", ef->server_snd_una, ef->client_snd_win, ef->client_rcv_nxt, ef->client_ttl);
					if (ef->tfo_idx != TFO_IDX_UNUSED) {
						// Print tfo
						fo = &w->f[ef->tfo_idx];
						printf(SI SI SIS "idx %u\n", fo->idx);
						printf(SI SI SIS "private: (%p)\n", &fo->priv);
						print_side(&fo->priv, using_rack(ef));
						printf(SI SI SIS "public: (%p)\n", &fo->pub);
						print_side(&fo->pub, using_rack(ef));
					}
					printf("\n");
				}
			}
		}
	}

	for (i = 0; i < config->hef_n; i++) {
		if (!hlist_empty(&w->hef[i])) {
			printf("Flow hash %u\n", i);
			hlist_for_each_entry(ef, &w->hef[i], hlist)
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
		config->capture_output_packet(w->param, IPPROTO_IP, m, &w->ts, from_priv, iph);
}

static inline bool
set_rcv_win(struct tfo_side *fos, struct tfo_side *foos) {
	uint32_t win_size = foos->snd_win << foos->snd_win_shift;
	uint32_t win_end;
	uint16_t old_rcv_win = fos->rcv_win;

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
	uint16_t new_len;
	uint16_t ph_old_len = rte_cpu_to_be_16(pkt->m->pkt_len - ((uint8_t *)pkt->tcp - pkt_start));

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
		pkt->ipv4 = (struct rte_ipv4_hdr *)((uint8_t *)pkt->ipv4 - len);
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
		uint16_t vlan_id, struct tfo_side *foos, uint32_t *dup_sack, struct tfo_tx_bufs *tx_bufs, bool from_queue, bool same_dirn, bool must_send)
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
	bool do_dup_sack = (dup_sack && dup_sack[0] != dup_sack[1]);

	if (unlikely(!ack_pool)) {
		if (unlikely(!pkt)) {
			/* This should never occur. We can't send an ACK
			 * without receiving a packet first. */
			return;
		}

		ack_pool = pkt->m->pool;
	}

	if (fos->ack_timeout == TFO_INFINITE_TS && !must_send && !do_dup_sack) {
		if (fos->tlp_max_ack_delay_us > fos->srtt_us) {
			/* We want to ensure the other end received the ACK before it
			 * times out and retransmits, so reduce the ack delay by
			 * 2 * (srtt / 2). srtt / 2 is best estimate of time for ack
			 * to reach the other end, and allow 2 of those intervals to
			 * be conservative. */
#ifdef DEBUG_DELAYED_ACK
			printf("Delaying ack for %u us, same_dirn %d\n", fos->tlp_max_ack_delay_us - fos->srtt_us, same_dirn);
#endif
			fos->ack_timeout = now + (fos->tlp_max_ack_delay_us - fos->srtt_us) * USEC_TO_NSEC;
			return;
		}
	}
#ifdef DEBUG_DELAYED_ACK
	printf("Not delaying ack_timeout ");
	if (fos->ack_timeout == TFO_INFINITE_TS)
		printf("unset");
	else
		printf("%lu", fos->ack_timeout);
	printf(" must_send %d dup_sack %p %u:%u, same_dirn %d\n",
		must_send, dup_sack, dup_sack ? dup_sack[0] : 1U, dup_sack ? dup_sack[1] : 0, same_dirn);
#endif

	fos->ack_timeout = TFO_INFINITE_TS;

	m = rte_pktmbuf_alloc(ack_pool);

// Handle not forwarding ACK somehow
	if (m == NULL) {
#ifdef DEBUG_NO_MBUF
		printf("Unable to ack 0x%x - no mbuf - vlan %u\n", fos->rcv_nxt, vlan_id);
#endif
		return;
	}

	/* If we haven't initialised the private area size, do so now */
	if (ack_pool_priv_size == UINT16_MAX)
		ack_pool_priv_size = rte_pktmbuf_priv_size(m->pool);

	if (ack_pool_priv_size) {
		/* We don't use the private area for ACKs, but the code using this library might */
		memset(rte_mbuf_to_priv(m), 0x00, sizeof(ack_pool_priv_size));
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
		   sizeof (struct rte_ipv4_hdr) +
		   sizeof (struct rte_tcp_hdr) +
		   (ef->flags & TFO_EF_FL_TIMESTAMP ? sizeof(struct tcp_timestamp_option) + 2 : 0) +
		   (sack_blocks ? (sizeof(struct tcp_sack_option) + 2 + sizeof(struct sack_edges) * sack_blocks) : 0);

	eh = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, pkt_len);

	if (unlikely(addr)) {
		m->port = port_id;

		if (eh) {	// This check is superfluous, but otherwise GCC generates a maybe-uninitialized warning
			rte_ether_addr_copy(&local_mac_addr, &eh->dst_addr);
			rte_ether_addr_copy(&remote_mac_addr, &eh->src_addr);
		}
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
	ipv4->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof (*eh) - (m->vlan_tci ? sizeof(*vl) : 0));
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

#ifdef DEBUG_DUP_SACK_SEND
	if (do_dup_sack)
		printf("ack with D-SACK 0x%x -> 0x%x\n", dup_sack[0], dup_sack[1]);
#endif

	if (sack_blocks) {
		add_sack_option(fos, ptr, sack_blocks, dup_sack);
		tcp->data_off += ((1 + 1 + sizeof(struct tcp_sack_option) + sack_blocks * sizeof(struct sack_edges)) / 4) << 4;
	}

// Checksum offload?
	tcp->cksum = rte_ipv4_udptcp_cksum(ipv4, tcp);

	fos->ack_sent_time = timespec_to_ns(&w->ts);

#ifdef DEBUG_ACK
	printf("Sending ack %p seq 0x%x ack 0x%x len %u ts_val %u ts_ecr %u vlan %u, packet_type 0x%x, sack_blocks %u dup_sack 0x%x:0x%x\n",
		m, fos->snd_nxt, fos->rcv_nxt, m->data_len,
		(ef->flags & TFO_EF_FL_TIMESTAMP) ? rte_be_to_cpu_32(foos->ts_recent) : 0,
		(ef->flags & TFO_EF_FL_TIMESTAMP) ? rte_be_to_cpu_32(fos->ts_recent) : 0,
		vlan_id, m->packet_type, sack_blocks, dup_sack ? dup_sack[0] : 0, dup_sack ? dup_sack[1] : 0);
#endif

	add_tx_buf(w, m, tx_bufs, pkt ? !(pkt->flags & TFO_PKT_FL_FROM_PRIV) : foos == &w->f[ef->tfo_idx].pub, (union tfo_ip_p)ipv4, true);
}

static inline void
_send_ack_pkt_in(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, const struct tfo_pkt_in *p,
		uint16_t vlan_id, struct tfo_side *foos, uint32_t *dup_sack, struct tfo_tx_bufs *tx_bufs, bool same_dirn)
{
	struct tfo_pkt pkt;

	pkt.m = p->m;
	pkt.ipv4 = p->ip4h;
	pkt.tcp = p->tcp;
	pkt.flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;

	_send_ack_pkt(w, ef, fos, &pkt, NULL, vlan_id, foos, dup_sack, tx_bufs, false, same_dirn, true);
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
		fos->tfo = fo;
		fos->srtt_us = 0;
		fos->rto_us = TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC;
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
	}

	if (unlikely(list_is_queued(&pkt->xmit_ts_list)))
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
		pkt->ipv4 = NULL;
		pkt->tcp = NULL;
		pkt->ts = NULL;
		pkt->sack = NULL;
		if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_LOST)) == TFO_PKT_FL_SENT) {
			s->pkts_in_flight--;
#ifdef DEBUG_IN_FLIGHT
			printf("pkt_free_mbuf(0x%x) pkts_in_flight decremented to %u\n", pkt->seq, s->pkts_in_flight);
#endif
		}

		if (unlikely(list_is_queued(&pkt->xmit_ts_list)))
			list_del_init(&pkt->xmit_ts_list);
		if (unlikely(list_is_queued(&pkt->send_failed_list)))
			list_del_init(&pkt->send_failed_list);
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

static void
_eflow_free(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_user *u = ef->u;

#ifdef DEBUG_FLOW
	printf("eflow_free w %p ef %p ef->tfo_idx %u flags 0x%x, state %u\n", w, ef, ef->tfo_idx, ef->flags, ef->state);
#endif

	if (!(ef->flags & TFO_EF_FL_STOP_OPTIMIZE))
		--w->st.flow_state[TCP_STATE_STAT_OPTIMIZED];

	if (ef->tfo_idx != TFO_IDX_UNUSED) {
		_flow_free(w, &w->f[ef->tfo_idx], tx_bufs);
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

#ifdef DEBUG_DISABLE_SACK
			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == RTE_TCP_SYN_FLAG) {
				struct tfo_pkt pkt;
				uint16_t nops[1] = { [0] = 0x0101 };

				pkt.m = p->m;
				pkt.ipv4 = p->ip4h;
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
			printf("ts_val %u ts_ecr %u\n", rte_be_to_cpu_32(p->ts_opt->ts_val), rte_be_to_cpu_32(p->ts_opt->ts_ecr));
#endif

#ifdef DEBUG_DISABLE_TS
			if ((p->tcp->tcp_flags & (RTE_TCP_ACK_FLAG | RTE_TCP_SYN_FLAG)) == RTE_TCP_SYN_FLAG) {
				struct tfo_pkt pkt;
				uint16_t nops[5] = { [0] = 0x0101, [1] = 0x0101, [2] = 0x0101, [3] = 0x0101, [4] = 0x0101 };

				pkt.m = p->m;
				pkt.ipv4 = p->ip4h;
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

#if defined DEBUG_DISABLE_SACK || defined DEBUG_DISABLE_TS
	struct tfo_pkt pkt;
	uint8_t *opt_start = (uint8_t *)p->tcp + sizeof(struct rte_tcp_hdr);
	uint8_t opt_len = ((p->tcp->data_off & 0xf0) >> 2) - sizeof(struct rte_tcp_hdr);
	bool updated = false;

	pkt.m = p->m;
	pkt.ipv4 = p->ip4h;
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
		p->ip4h = pkt.ipv4;
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
check_do_optimize(struct tcp_worker *w, const struct tfo_pkt_in *p, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo *fo;
	struct tfo_side *client_fo, *server_fo;

	/* should not happen */
	if (unlikely(list_empty(&w->f_free)) ||
	    w->p_use >= config->p_n * 3 / 4) {
		_eflow_free(w, ef, NULL);
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
#ifdef CALC_USERS_TS_CLOCK
		client_fo->ts_start = rte_be_to_cpu_32(client_fo->ts_recent);
		client_fo->ts_start_time = ef->start_time;

#ifdef DEBUG_TS_SPEED
		printf("Client TS start %u at " TIMESPEC_TIME_PRINT_FORMAT "\n", client_fo->ts_start, TIMESPEC_TIME_PRINT_PARAMS(&ef->start_time));
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
	server_fo->mss = p->mss_opt ? p->mss_opt : TCP_MSS_DEFAULT;
	if (p->ts_opt) {
		server_fo->ts_recent = p->ts_opt->ts_val;
#ifdef CALC_USERS_TS_CLOCK
		server_fo->ts_start = rte_be_to_cpu_32(server_fo->ts_recent);
		server_fo->ts_start_time = w->ts;
#ifdef DEBUG_TS_SPEED
		printf("Server TS start %u at " TIMESPEC_TIME_PRINT_FORMAT "\n", server_fo->ts_start, TIMESPEC_TIME_PRINT_PARAMS(&w->ts));
#endif
#endif
	}
	server_fo->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->ip6h->hop_limits : p->ip4h->time_to_live;
	server_fo->packet_type = p->m->packet_type;
	client_fo->rcv_ttl = ef->client_ttl;

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
	server_fo->cur_timer = TFO_TIMER_NONE;
	server_fo->timeout = TFO_INFINITE_TS;
	server_fo->ack_timeout = TFO_ACK_NOW_TS;	// Ensure the 3WHS ACK is sent immediately
	server_fo->tlp_max_ack_delay_us = TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC;
	client_fo->cur_timer = TFO_TIMER_NONE;
	client_fo->timeout = TFO_INFINITE_TS;
	client_fo->ack_timeout = TFO_INFINITE_TS;
	client_fo->tlp_max_ack_delay_us = TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC;
	client_fo->pkts_in_flight = 0;
	server_fo->pkts_in_flight = 0;
	client_fo->rack_segs_sacked = 0;
	server_fo->rack_segs_sacked = 0;
	server_fo->rack_xmit_ts = 0;
	client_fo->rack_xmit_ts = 0;
	server_fo->pkts_queued_send = 0;
	client_fo->pkts_queued_send = 0;

	/* We ACK the SYN+ACK to speed up startup */
// TODO - queue the SYN+ACK and enter ESTABLISHED
	_send_ack_pkt_in(w, ef, server_fo, p, p->from_priv ? priv_vlan_tci : pub_vlan_tci, client_fo, NULL, tx_bufs, false);

#ifdef DEBUG_OPTIMIZE
	printf("priv rx/tx win 0x%x:0x%x pub rx/tx 0x%x:0x%x, priv send win 0x%x, pub 0x%x\n",
		fo->priv.rcv_win, fo->priv.snd_win, fo->pub.rcv_win, fo->pub.snd_win,
		fo->priv.snd_nxt + (fo->priv.snd_win << fo->priv.snd_win_shift),
		fo->pub.snd_nxt + (fo->pub.snd_win << fo->pub.snd_win_shift));
	printf("clnt ts_recent = %1$u (0x%1$x) svr ts_recent = %2$u (0x%2$x)\n", rte_be_to_cpu_32(client_fo->ts_recent), rte_be_to_cpu_32(server_fo->ts_recent));
	printf("WE WILL optimize pub s:n 0x%x:0x%x priv 0x%x:0x%x\n", fo->pub.snd_una, fo->pub.rcv_nxt, fo->priv.snd_una, fo->priv.rcv_nxt);
#endif
}

static uint64_t
tlp_calc_pto(struct tfo_side *fos)
{
	uint64_t pto;
	uint64_t rto;
	struct tfo_pkt *oldest_pkt;

	if (unlikely(!fos->srtt_us))
		pto = TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC;
	else {
		pto = 2 * fos->srtt_us;
		if (fos->pkts_in_flight + fos->pkts_queued_send == 1)
			pto += fos->tlp_max_ack_delay_us;
	}

	pto *= USEC_TO_NSEC;

	if (!list_empty(&fos->xmit_ts_list)) {
		oldest_pkt = list_first_entry(&fos->xmit_ts_list, struct tfo_pkt, xmit_ts_list);
		if (!(oldest_pkt->flags & TFO_PKT_FL_QUEUED_SEND)) {
			rto = oldest_pkt->ns + fos->rto_us * USEC_TO_NSEC;
			if (now + pto > rto)
				pto = rto - now;
		}
	}

	return pto;
}

static void
tfo_reset_timer(struct tfo_side *fos, tfo_timer_t timer, uint32_t timeout)
{
	fos->cur_timer = timer;
	fos->timeout = now + timeout * USEC_TO_NSEC;
}

static inline void
tfo_cancel_xmit_timer(struct tfo_side *fos)
{
	fos->cur_timer = TFO_TIMER_NONE;
	fos->timeout = TFO_INFINITE_TS;
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
	    !(fos->flags & TFO_SIDE_FL_IN_RECOVERY) &&
	    !fos->rack_segs_sacked) {
		fos->cur_timer = TFO_TIMER_PTO;
		fos->timeout = now + tlp_calc_pto(fos);
#ifdef DEBUG_RACK
		printf(" tlp_calc_pto %lu", fos->timeout - now);
#endif
	} else {
		fos->cur_timer = TFO_TIMER_RTO;
		fos->timeout = now + fos->rto_us * USEC_TO_NSEC;
	}

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

#ifdef OLD_SENT
		/* RFC8985 to make step 2 faster */
// This doesn't work with LOST at end
		if (list_is_queued(&pkt->xmit_ts_list))
			list_move_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);
		else
			list_add_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);
#endif

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

#ifdef OLD_SEND
	if (pkt->flags & TFO_PKT_FL_SENT) {
		pkt->flags |= TFO_PKT_FL_RESENT;
		if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
			/* Abort RTT calculation */
			fos->flags &= ~TFO_SIDE_FL_RTT_CALC;
			pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
		}

		if (pkt->flags & TFO_PKT_FL_LOST) {
			fos->pkts_in_flight++;
#ifdef DEBUG_IN_FLIGHT
			printf("send_tcp_pkt seq 0x%x incrementing pkts_in_flight to %u for lost pkt\n", pkt->seq, fos->pkts_in_flight);
#endif
		}
	} else {
// update foos snd_nxt
		pkt->flags |= TFO_PKT_FL_SENT;
		fos->pkts_in_flight++;
#ifdef DEBUG_IN_FLIGHT
		printf("send_tcp_pkt(0x%x) pkts_in_flight incremented to %u\n", pkt->seq, fos->pkts_in_flight);
#endif

		/* If not using timestamps and no RTT calculation in progress,
		 * start one, but we don't calculate RTT from a resent packet */
		if (!pkt->ts && !(fos->flags & TFO_SIDE_FL_RTT_CALC)) {
			fos->flags |= TFO_SIDE_FL_RTT_CALC;
			pkt->flags |= TFO_PKT_FL_RTT_CALC;
		}
	}

	/* RFC 8985 6.1 */
	pkt->flags &= ~TFO_PKT_FL_LOST;
#endif

#ifdef OLD_SEND
	pkt->ns = now;
#endif

	if (!(pkt->flags & TFO_PKT_FL_QUEUED_SEND)) {
		rte_pktmbuf_refcnt_update(pkt->m, 1);	/* so we keep it after it is sent */
		add_tx_buf(w, pkt->m, tx_bufs, pkt->flags & TFO_PKT_FL_FROM_PRIV, (union tfo_ip_p)pkt->ipv4, false);
		pkt->flags |= TFO_PKT_FL_QUEUED_SEND;
		fos->pkts_queued_send++;
		if (list_is_queued(&pkt->send_failed_list))
			list_del_init(&pkt->send_failed_list);
#ifdef DEBUG_SEND_PKT
		printf("Sending packet 0x%x\n", pkt->seq);
#endif
	}

#ifdef OLD_SEND
	if (after(segend(pkt), fos->snd_nxt))
		fos->snd_nxt = segend(pkt);
#endif

	/* No need to send an ACK if one is delayed */
	fos->ack_timeout = TFO_INFINITE_TS;

	tfo_reset_xmit_timer(fos, is_tail_loss_probe);

	return true;
}

static void
tlp_send_probe(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *probe_pkt = NULL;
	struct tfo_pkt *pkt;

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
			if (after(pkt->seq, fos->snd_nxt))
				continue;

			/* If we are before snd_nxt and there is a later packet within window, use that */
			if (pkt->seq != fos->snd_nxt &&
			    !list_is_last(&pkt->list, &fos->pktlist))
			    pkt = list_next_entry(pkt, list);

			if (!after(segend(pkt), fos->snd_una + (fos->snd_win << fos->snd_win_shift))) {
				probe_pkt = pkt;
#ifdef DEBUG_IN_FLIGHT
				printf("tlp_send_probe() pkts_in_flight not incremented to %u\n", fos->pkts_in_flight);
#endif
			} else if (!list_is_first(&pkt->list, &fos->pktlist))
				probe_pkt = list_prev_entry(pkt, list);

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

	if (fos->pkts_in_flight)
		tfo_reset_timer(fos, TFO_TIMER_RTO, fos->rto_us);
}

static inline struct tfo_pkt * __attribute__((pure))
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
// Do we need to handle pkt_in_flight or rack_segs_sacked ??
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
queue_pkt(struct tcp_worker *w, struct tfo_side *foos, struct tfo_pkt_in *p, uint32_t seq, uint32_t *dup_sack, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt;
	struct tfo_pkt *pkt_tmp;
	struct tfo_pkt *prev_pkt;
	uint32_t seg_end;
	uint32_t prev_end, next_seq;
	bool pkt_needed = false;
	uint16_t smaller_ent = 0;
	struct tfo_pkt *reusing_pkt = NULL;
	struct tfo_mbuf_priv *priv;


	seg_end = seq + p->seglen;

	if (!after(seg_end, foos->snd_una)) {
#ifdef DEBUG_QUEUE_PKTS
		printf("queue_pkt seq 0x%x, len %u before our window\n", seq, p->seglen);
#endif
		dup_sack[0] = seq;
		dup_sack[1] = seg_end;

		return PKT_IN_LIST;
	}

	if (!list_empty(&foos->pktlist)) {
		uint32_t next_byte_needed = seq;
		struct tfo_pkt *prev_prev_pkt;
		struct tfo_pkt *last_pkt;

		prev_pkt = find_previous_pkt(&foos->pktlist, seq);
		if (prev_pkt) {
			next_byte_needed = segend(prev_pkt);

			if (!before(next_byte_needed, seg_end)) {
				dup_sack[0] = seq;
				dup_sack[1] = seg_end;

				return PKT_IN_LIST;
			}

			if (after(next_byte_needed, seq)) {
				dup_sack[0] = seq;
				dup_sack[1] = next_byte_needed;
			}

			/* If the packet before prev_pkt reaches this packet, prev_pkt is not needed */
// We need to do something if prev_pkt is in flight with RFC8985. What about pkts_in_flight and reck_segs_sacked??
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

			if (dup_sack[0] != dup_sack[1]) {
				if (!before(pkt->seq, dup_sack[1]))
					dup_sack[1] = after(seg_end, segend(pkt)) ? segend(pkt) : seg_end;
			} else {
				if (after(segend(pkt), seq)) {
					dup_sack[0] = seq;
					dup_sack[1] = after(seg_end, segend(pkt)) ? segend(pkt) : seg_end;
				}
			}

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
// We need to do something in pkt is in flight with RFC8985 ?? and rack_segs_sacked
					list_del_init(&pkt->list);
				} else {
					pkt_free(w, foos, pkt, tx_bufs);
					foos->pktcount--;
				}
			}

			if (!after(seg_end, segend(pkt)))
				break;
		}

		if (!pkt_needed && smaller_ent <= 1) {
			dup_sack[0] = seq;
			dup_sack[1] = seg_end;

			return PKT_IN_LIST;
		}
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
_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
		if (pkt->m)
			rte_pktmbuf_free(pkt->m);
_Pragma("GCC diagnostic pop")

		// Take care - if we are reusing the packet it might have been in the xmit_ts_list - RFC8985
		if (list_is_queued(&pkt->xmit_ts_list))
			list_del_init(&pkt->xmit_ts_list);
	} else {
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

		INIT_LIST_HEAD(&pkt->xmit_ts_list);
		pkt->rack_segs_sacked = 0;
	}

	pkt->m = p->m;

	/* Update the mbuf private area so we can find the tfo_side and tfo_pkt from the mbuf */
	priv = rte_mbuf_to_priv(p->m);
	priv->fos = foos;
	priv->pkt = pkt;

	if (option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)
		p->m->ol_flags ^= config->dynflag_priv_mask;

	pkt->seq = seq;
	pkt->seglen = p->seglen;
	pkt->ipv4 = p->ip4h;
	pkt->tcp = p->tcp;
	pkt->flags = p->from_priv ? TFO_PKT_FL_FROM_PRIV : 0;
	pkt->ns = TFO_TS_NONE;
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
clear_optimize(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_tx_bufs *tx_bufs)
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
_eflow_set_state(struct tcp_worker *w, struct tfo_eflow *ef, uint8_t new_state, struct tfo_tx_bufs *tx_bufs)
{
	--w->st.flow_state[ef->state];
	++w->st.flow_state[new_state];
	ef->state = new_state;

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Winline\"")
	if (new_state == TCP_STATE_BAD)
		clear_optimize(w, ef, tx_bufs);
_Pragma("GCC diagnostic pop")
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
	printf("INVOKE_CONGESTION_CONTROL called\n");
}

static inline bool
rack_sent_after(uint64_t t1, uint64_t t2, uint32_t seq1, uint32_t seq2)
{
	return t1 > t2 || (t1 == t2 && after(seq1, seq2));
}

// Returns true if need to invoke congestion control 
static inline bool
tlp_process_ack(uint32_t ack, struct tfo_pkt_in *p, struct tfo_side *fos, bool dsack)
{
	if (!(fos->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) ||
	    before(ack, fos->tlp_end_seq))
		return false;

	if (!(fos->flags & TFO_SIDE_FL_TLP_IS_RETRANS)) {
		fos->flags &= ~TFO_SIDE_FL_TLP_IN_PROGRESS;
		return false;
	}

	if (dsack && rte_be_to_cpu_32(p->sack_opt->edges[0].right_edge) == fos->tlp_end_seq) {
		fos->flags &= ~TFO_SIDE_FL_TLP_IN_PROGRESS;
		return false;
	}

	if (after(ack, fos->tlp_end_seq)) {
		fos->flags &= ~TFO_SIDE_FL_TLP_IN_PROGRESS;
		invoke_congestion_control(fos);
		return true;
	}

	if (!after(ack, fos->snd_una) && !p->sack_opt) {
		fos->flags &= ~TFO_SIDE_FL_TLP_IN_PROGRESS;
		return false;
	}

	return false;
}

static void
update_rto(struct tfo_side *fos, uint64_t pkt_ns)
{
	uint32_t rtt = (now - pkt_ns) / USEC_TO_NSEC;

#ifdef DEBUG_RTO
	printf("update_rto() pkt_ns %lu rtt %u\n", pkt_ns, rtt);
#endif

	if (!fos->srtt_us) {
		fos->srtt_us = rtt;
		fos->rttvar_us = rtt / 2;
	} else {
		fos->rttvar_us = (fos->rttvar_us * 3 + (fos->srtt_us > rtt ? (fos->srtt_us - rtt) : (rtt - fos->srtt_us))) / 4;
		fos->srtt_us = (fos->srtt_us * 7 + rtt) / 8;
	}
	fos->rto_us = fos->srtt_us + max(1U, fos->rttvar_us * 4);

	if (fos->rto_us < TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC)
		fos->rto_us = TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC;
	else if (fos->rto_us > TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC) {
#ifdef DEBUG_RTO
		printf("New running rto %u us, reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC);
#endif
		fos->rto_us = TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC;
	}
}

static void
update_rto_ts(struct tfo_side *fos, uint64_t pkt_ns, uint32_t pkts_ackd)
{
	uint32_t rtt = (now - pkt_ns) / USEC_TO_NSEC;
	uint32_t new_rttvar;

#ifdef DEBUG_RACK
	printf("update_rto_ts() pkt_ns %lu rtt %u pkts in flight %u ackd %u\n", pkt_ns, rtt, fos->pkts_in_flight, pkts_ackd);
#endif

	/* RFC7323 Appendix G. However, we are using actual packet counts rather than the
	 * estimate of FlightSize / (MSS * 2). This is because we can't calculate FlightSize
	 * by using snd_nxt - snd_una since we can have gaps between pkts if we have
	 * not yet received some packets. */
	if (unlikely(!fos->srtt_us)) {
		fos->srtt_us = rtt;
		fos->rttvar_us = rtt / 2;
	} else {
		if (unlikely(!fos->pkts_in_flight))
			return;

		new_rttvar = fos->srtt_us > rtt ? (fos->srtt_us - rtt) : (rtt - fos->srtt_us);
		fos->rttvar_us = ((4 * fos->pkts_in_flight - pkts_ackd) * fos->rttvar_us + pkts_ackd * new_rttvar) / (fos->pkts_in_flight * 4);
		fos->srtt_us = ((8 * fos->pkts_in_flight - pkts_ackd) * fos->srtt_us + pkts_ackd * rtt) / (fos->pkts_in_flight * 8);
	}
	fos->rto_us = fos->srtt_us + max(1U, fos->rttvar_us * 4);

	if (fos->rto_us < TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC)
		fos->rto_us = TFO_TCP_RTO_MIN_MS * MSEC_TO_USEC;
	else if (fos->rto_us > TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC) {
#ifdef DEBUG_RTO
		printf("New running rto %u us, reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC);
#endif
		fos->rto_us = TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC;
	}

	fos->flags |= TFO_SIDE_FL_NEW_RTT;
}

static uint32_t max_segend;	// Make this a parameter
static bool dsack_seen;		// This must be returned too

static void
rack_resend_lost_packets(struct tcp_worker *w, struct tfo_side *fos, struct tfo_side *foos, struct tfo_pkt *last_lost, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_pkt *pkt, *pkt_tmp;

// Should we check send window and cwnd?
	list_for_each_entry_safe(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
		if (pkt->flags & TFO_PKT_FL_LOST) {
#ifdef DEBUG_SEND_PKT_LOCATION
			printf("send_tcp_pkt B\n");
#endif
			send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);
		}

		if (pkt == last_lost)
			break;
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
			/* RFC5681 Step 2 point 1 */
			if (after(rte_be_to_cpu_32(pkt->ts->ts_val), ack_ts_ecr))
				return;
		}

		/* RFC5681 Step 2 point 2 */
		if (after(pkt->ts->ts_val + minmax_get(&fos->rtt_min), now))
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
			fos->flags &= ~TFO_SIDE_FL_RTT_CALC;
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
					fos->flags &= ~TFO_SIDE_FL_RTT_CALC;
				}

				if (after(segend(pkt), max_segend))
					max_segend = segend(pkt);

				pkts_ackd++;
			}
		}
	}

// Why are we doing this here?
	if (tlp_process_ack(ack, p, fos, dsack_seen)) {
		invoke_congestion_control(fos);
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
		minmax_running_min(&fos->rtt_min, config->tcp_min_rtt_wlen * MSEC_TO_USEC, now / USEC_TO_NSEC, (now - most_recent_pkt->ns) / USEC_TO_NSEC);

		/* RFC8985 Step 2 */
		fos->rack_rtt_us = (now - most_recent_pkt->ns) / USEC_TO_NSEC;
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
mark_packet_lost(struct tfo_pkt *pkt, struct tfo_side *fos, struct tfo_pkt **last_lost)
{
	pkt->flags |= TFO_PKT_FL_LOST;
	pkt->ns = TFO_TS_NONE;		// Could remove this from xmit_ts_list (in which case need list_for_each_entry_safe())
	fos->pkts_in_flight--;
	list_move_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);
	*last_lost = pkt;
}
//
//#define DETECT_LOSS_MIN

/* RFC8985 Step 5 */
static uint32_t
rack_detect_loss(struct tfo_side *fos, uint32_t ack, struct tfo_pkt **last_lost)
{
#ifndef DETECT_LOSS_MIN
	uint64_t timeout = 0;
#else
	uint64_t timeout = UINT64_MAX;
#endif
	uint64_t first_timeout = now - (fos->rack_rtt_us + fos->rack_reo_wnd_us) * USEC_TO_NSEC;
	struct tfo_pkt *pkt, *pkt_tmp;
	bool pkt_lost = false;

	fos->rack_reo_wnd_us = rack_update_reo_wnd(fos, ack);

	list_for_each_entry_safe(pkt, pkt_tmp, &fos->xmit_ts_list, xmit_ts_list) {
		if (!rack_sent_after(fos->rack_xmit_ts, pkt->ns, fos->rack_end_seq, segend(pkt)))
			break;

		if (pkt->flags & (TFO_PKT_FL_ACKED | TFO_PKT_FL_SACKED))
			continue;

		if (pkt->flags & TFO_PKT_FL_LOST)
			break;

		if (pkt->ns <= first_timeout) {
			mark_packet_lost(pkt, fos, last_lost);
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
rack_detect_loss_and_arm_timer(struct tfo_side *fos, uint32_t ack, struct tfo_pkt **last_lost)
{
	uint32_t timeout;

	timeout = rack_detect_loss(fos, ack, last_lost);

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
	struct tfo_pkt *last_lost = NULL;

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
	rack_detect_loss_and_arm_timer(fos, ack, &last_lost);

#ifdef DEBUG_IN_FLIGHT
	printf("do_rack() pre_in_flight %u fos->pkts_in_flight %u\n", pre_in_flight, fos->pkts_in_flight);
#endif

	if (fos->pkts_in_flight < pre_in_flight) {
		/* Some packets have been lost */
		rack_resend_lost_packets(w, fos, foos, last_lost, tx_bufs);
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
rack_mark_losses_on_rto(struct tfo_side *fos, struct tfo_pkt **last_lost)
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
		if (pkt->ns + (fos->rack_rtt_us + fos->rack_reo_wnd_us) * USEC_TO_NSEC > now)
			break;

		if (pkt->flags & TFO_PKT_FL_LOST)
			break;

//		if (pkt->seq == fos->snd_una ||		// The first packet sent ??? Should be first pkt on xmit_ts_list
		mark_packet_lost(pkt, fos, last_lost);
		pkt_lost = true;

#ifdef DEBUG_IN_FLIGHT
		printf("rack_mark_losses_on_rto decremented pkts_in_flight to %u\n", fos->pkts_in_flight);
#endif

	}

	if (pkt_lost &&
	    !(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
		fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
		fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
		printf("Entering RTO recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
	}
}

static void
handle_rack_tlp_timeout(struct tcp_worker *w, struct tfo_eflow *ef, struct tfo_side *fos, struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs)
{
	bool set_timer = true;
	struct tfo_pkt *last_lost = NULL;

	if (fos->ack_timeout != TFO_INFINITE_TS) {
// Change send_ack_pkt to make up address if pkt == NULL
		struct tfo_addr_info addr;
		struct tfo *fo = &w->f[ef->tfo_idx];

		if (fos == &fo->pub) {
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

#ifdef DEBUG_DELAYED_ACK
		printf("Sending delayed ack 0x%x\n", fos->rcv_nxt);
#endif
		_send_ack_pkt(w, ef, fos, NULL, &addr, fos == &fo->pub ? pub_vlan_tci : priv_vlan_tci, foos, NULL, tx_bufs, false, false, true);
	}

	if (fos->cur_timer == TFO_TIMER_NONE)
		return;

#ifdef DEBUG_RACK
	printf("RACK timeout %s\n",
		fos->cur_timer == TFO_TIMER_REO ? "REO" :
		fos->cur_timer == TFO_TIMER_PTO ? "PTO" :
		fos->cur_timer == TFO_TIMER_RTO ? "RTO" :
		fos->cur_timer == TFO_TIMER_ZERO_WINDOW ? "ZW" :
		"unknown");
#endif

	switch(fos->cur_timer) {
	case TFO_TIMER_REO:
		set_timer = rack_detect_loss_and_arm_timer(fos, fos->snd_una, &last_lost);
		break;
	case TFO_TIMER_PTO:
// Must use RTO now. tlp_send_probe() can set timer - do we handle that properly?
		tlp_send_probe(w, fos, foos, tx_bufs);
		break;
	case TFO_TIMER_RTO:
		rack_mark_losses_on_rto(fos, &last_lost);
		break;
	case TFO_TIMER_ZERO_WINDOW:
		// TODO
		break;
	case TFO_TIMER_NONE:
		// Keep gcc happy
		break;
	}

	if (last_lost)
		rack_resend_lost_packets(w, fos, foos, last_lost, tx_bufs);

	if (set_timer)
		tfo_reset_xmit_timer(fos, false);

#ifdef DEBUG_STRUCTURES
	dump_details(w);
#endif
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
	bool fin_set;
	bool fin_rx;
	uint32_t last_seq;
	uint32_t new_win;
	bool fos_send_ack = false;
	bool fos_must_ack = false;
	bool fos_ack_from_queue = false;
	bool foos_send_ack = false;
	bool new_sack_info = false;
#ifndef CWND_USE_RECOMMENDED
	uint32_t incr;
#endif
	uint32_t bytes_sent;
	bool snd_wnd_increased = false;
	uint32_t dup_sack[2] = { 0, 0 };
	bool only_one_packet;

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

	/* I don't like the following bit of code, with two identical assignments to
	 * orig_vlan, but I can't think of anythiny better at the moment.
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
		fos = &fo->priv;
		foos = &fo->pub;

		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
			orig_vlan = p->m->vlan_tci;
			p->m->vlan_tci = pub_vlan_tci;
		} else
			orig_vlan = priv_vlan_tci;
	} else {
		fos = &fo->pub;
		foos = &fo->priv;

		if (!(option_flags & TFO_CONFIG_FL_NO_VLAN_CHG)) {
			orig_vlan = p->m->vlan_tci;
			p->m->vlan_tci = priv_vlan_tci;
		} else
			orig_vlan = pub_vlan_tci;
	}

	/* Save the ttl/hop_limit to use when generating acks */
	fos->rcv_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->ip6h->hop_limits : p->ip4h->time_to_live;

#ifdef DEBUG_PKT_RX
	printf("Handling packet, state %u, from %s, seq 0x%x, ack 0x%x, rx_win 0x%hx, fos: snd_una 0x%x, snd_nxt 0x%x rcv_nxt 0x%x foos 0x%x 0x%x 0x%x\n",
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
			_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
			return TFO_PKT_FORWARD;
		}
	}

	ack = rte_be_to_cpu_32(tcp->recv_ack);

	/* ack obviously out of range. stop optimizing this connection */
// See RFC7232 2.3 for this

	if (using_rack(ef))
		do_rack(p, ack, w, fos, foos, tx_bufs);

//CHECK ACK AND SEQ NOT OLD
	/* This may be a duplicate */
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

#ifdef DEBUG_ACK
		printf("Looking to remove ack'd packets\n");
#endif

		/* RFC5681 3.2 */
		if (fos->cwnd < fos->ssthresh) {
			/* Slow start */
			fos->cwnd += min(ack - fos->snd_una, fos->mss);
#ifdef CWND_USE_RECOMMENDED
			fos->cum_ack = 0;
#endif
		} else {
			/* Collision avoidance. */
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

		/* remove acked buffered packets. We want the time the
		 * most recent packet was sent to update the RTT. */
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
						fos->flags &= ~TFO_SIDE_FL_RTT_CALC;
					}
				}
			}

			/* acked, remove buffered packet */
#ifdef DEBUG_ACK
			printf("Calling pkt_free m %p, seq 0x%x\n", pkt->m, pkt->seq);
#endif
			pkt_free(w, fos, pkt, tx_bufs);
		}

		if ((ef->flags & TFO_EF_FL_SACK) && fos->sack_entries)
			update_sack_for_ack(fos);

#if 0
HERE HERE HERE -- REMOVE THIS BIT
		/* Do RTT calculation on newest_pkt */
		if (newest_send_time) {
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
		}
#endif

		/* RFC8985 7.2 */
		if (using_rack(ef))
			tfo_reset_xmit_timer(fos, false);

		/* Can we open up the send window for the other side?
		 * newest_send_time is set if we have removed a packet from the queue. */
		if (newest_send_time &&
		    set_rcv_win(foos, fos))
			foos_send_ack = true;
	} else if (fos->snd_una == ack &&
		   !list_empty(&fos->pktlist)) {
if (!using_rack(ef)) {
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
#ifdef DEBUG_SACK_RX
		struct tfo_pkt *resend = NULL;
#endif

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
// This duplicates code in ACK section
						/* This is being "ack'd" for the first time */
						if (pkt->ts) {
							if (pkt->ts->ts_val == p->ts_opt->ts_ecr &&
							    pkt->ns > newest_send_time)
								newest_send_time = pkt->ns;
#ifdef DEBUG_RTO
							else if (pkt->ts->ts_val != p->ts_opt->ts_ecr)
								printf("SACK tsecr 0x%x != tsval 0x%x\n", rte_be_to_cpu_32(p->ts_opt->ts_ecr), rte_be_to_cpu_32(pkt->ts->ts_val));
#endif
							pkts_ackd++;
						} else {
							if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
								update_rto(fos, pkt->ns);
								pkt->flags &= ~TFO_PKT_FL_RTT_CALC;
								fos->flags &= ~TFO_SIDE_FL_RTT_CALC;
							}
						}

						new_sack_info = true;
pkt->rack_segs_sacked = 1;
pkt->flags &= ~TFO_PKT_FL_SACKED;
					}

					if (after(pkt->seq, last_seq))
						sack_pkt = NULL;

					if (!sack_pkt) {
						sack_pkt = pkt;
						if (pkt->m) {
							pkt_free_mbuf(pkt, fos, tx_bufs);

//XXX							sack_pkt->rack_segs_sacked = 1;
//XXX							sack_pkt->flags &= ~TFO_PKT_FL_SACKED;
						}
#ifdef DEBUG_SACK_RX
						printf("sack pkt now 0x%x, len %u\n", pkt->seq, pkt->seglen);
#endif
					} else {
//XXX						if (after(segend(pkt), segend(sack_pkt))) {
							sack_pkt->rack_segs_sacked += pkt->rack_segs_sacked;
							sack_pkt->seglen = segend(pkt) - sack_pkt->seq;
//XXX						}

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
// Why does next packet need to go beyond right_edge?
					 * merge them */
					if (!list_is_last(&sack_pkt->list, &fos->pktlist)) {
						next_pkt = list_next_entry(sack_pkt, list);
						if (!next_pkt->m &&
						    !before(segend(sack_pkt), next_pkt->seq)) {
							sack_pkt->seglen = segend(next_pkt) - sack_pkt->seq;
							sack_pkt->rack_segs_sacked += next_pkt->rack_segs_sacked;
							next_pkt->rack_segs_sacked = 0;

							/* This isn't nice, but it is what we need */
							pkt_tmp = list_next_entry(next_pkt, list);

							pkt_free(w, fos, next_pkt, tx_bufs);
						}
					}
				} else {
#ifdef DEBUG_SACK_RX
					printf("pkt->m %p, resend %p", pkt->m, resend);
#endif
					if (!pkt->m) {
						sack_pkt = pkt;
#ifdef DEBUG_SACK_RX
						resend = NULL;
#endif
					} else
						sack_pkt = NULL;
#ifdef DEBUG_SACK_RX
					printf(" now %p\n", resend);
#endif
				}

				last_seq = segend(pkt);
			}
		}

if (!using_rack(ef)) {
		if (likely(!list_empty(&fos->pktlist))) {
			if (fos->dup_ack != 3)
				printf("NOT sending ACK/packet following SACK since dup_ack == %u\n", fos->dup_ack);
		}
}
	}

	if (newest_send_time && !using_rack(ef)) {
		/* We are using timestamps */
		update_rto_ts(fos, newest_send_time, pkts_ackd);

		/* 300 = /proc/sys/net/ipv4/tcp_min_rtt_wlen. Kernel passes 2nd and 3rd parameters in jiffies (1000 jiffies/sec on x86_64).
		   We record rtt_min in usecs  */
		minmax_running_min(&fos->rtt_min, config->tcp_min_rtt_wlen * MSEC_TO_USEC, now / USEC_TO_NSEC, (now - newest_send_time) / USEC_TO_NSEC);
	}

	/* The assignment to send_pkt is completely unnecessary due to the checks below,
	 * but otherwise GCC generates a maybe-unitialized warning re send_pkt in the
	 * printf below, even though it is happier with the intervening uses. */
if (!using_rack(ef)) {
	if (fos->dup_ack &&
	    fos->dup_ack < 3 &&
	    !list_empty(&fos->pktlist) &&
	    (!((send_pkt = list_last_entry(&fos->pktlist, struct tfo_pkt, list))->flags & TFO_PKT_FL_SENT)) &&
	    (!(ef->flags & TFO_EF_FL_SACK) || new_sack_info)) {
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
}

// See RFC 7323 2.3 - it says seq must be within 2^31 bytes of left edge of window,
//  otherwise it should be discarded as "old"
	/* Window scaling is rfc7323 */
	win_end = fos->rcv_nxt + (fos->rcv_win << fos->rcv_win_shift);

if (!using_rack(ef)) {
// should the following only happen if not sack?
	if (fos->snd_una == ack && !list_empty(&fos->pktlist)) {
		pkt = list_first_entry(&fos->pktlist, typeof(*pkt), list);
		if (pkt->flags & TFO_PKT_FL_SENT &&
		    now > packet_timeout(pkt->ns, fos->rto_us) &&
		    !after(segend(pkt), win_end) &&
		    pkt->m) {		/* first entry should never have been sack'd */
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

// This isn't right. dup_sack must be for seq, seq + seglen
// Can use dup_sack if segend(pkt) !after fos->rcv_nxt
// Also, if this duplicates SACK'd entries, we need seq, seq + seglen, then the SACK block for this
//   which we might already do
	if (p->seglen && before(seq, fos->rcv_nxt)) {
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
// Sort out duplicate behind our window
//		return NULL;
#ifdef DEBUG_TCP_WINDOW
		printf("seq 0x%x len %u is outside rx window fos->rcv_nxt 0x%x -> 0x%x (+0x%x << %u)\n", seq, p->seglen, fos->rcv_nxt, win_end, fos->rcv_win, fos->rcv_win_shift);
#endif
		if (before(seq, fos->rcv_nxt)) {
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
#ifdef DEBUG_ZERO_WINDOW
		if (!fos->snd_win || !tcp->rx_win)
			printf("Zero window %s - 0x%x -> 0x%x\n", fos->snd_win ? "freed" : "set", fos->snd_win, (unsigned)rte_be_to_cpu_16(tcp->rx_win));
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
		    !after(seq, fos->rcv_nxt)) { // NOTE: this needs updating when implement delayed ACKs
			fos->ts_recent = p->ts_opt->ts_val;

#ifdef CALC_USERS_TS_CLOCK
#ifdef DEBUG_USERS_TX_CLOCK
			unsigned long ts_delta = rte_be_to_cpu_32(fos->ts_recent) - fos->ts_start;
			unsigned long us_delta = (w->ts.tv_sec - fos->ts_start_time.tv_sec) * 1000000UL + (long)(w->ts.tv_nsec - fos->ts_start_time.tv_nsec) / 1000L;

			printf("TS clock %lu ns for %lu tocks - %lu us per tock\n", us_delta, ts_delta, (us_delta + ts_delta / 2) / ts_delta);
#endif
#endif
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
		if (unlikely(queued_pkt == PKT_IN_LIST)) {
			/* The packet has already been received */
			free_mbuf = true;
			ret = TFO_PKT_HANDLED;
		} else if (unlikely(queued_pkt == PKT_VLAN_ERR)) {
// We should split the packet and reduce receive MSS
			/* The Vlan header could not be added */
			_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);

			/* The packet can't be forwarded, so don't return TFO_PKT_FORWARD */
			ret = TFO_PKT_HANDLED;
		} else if (queued_pkt) {
			/* RFC5681 3.2 - filling all or part of a gap */
			if (!list_is_last(&queued_pkt->list, &foos->pktlist))
				fos_must_ack = true;

#ifdef DEBUG_SND_NXT
			printf("Queued packet m %p seq 0x%x, len %u, rcv_nxt_updated %d\n",
				queued_pkt->m, queued_pkt->seq, queued_pkt->seglen, rcv_nxt_updated);
#endif
		} else {
// This might confuse things later
			if (!(ef->flags & TFO_EF_FL_STOP_OPTIMIZE))
				_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);

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

	if (fos->rack_segs_sacked)
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
			if (fos->rto_us > TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC) {
#ifdef DEBUG_RTO
				printf("rto fos resend after timeout double %u - reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC);
#endif
				fos->rto_us = TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC;
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

				if (foos->rto_us > TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC) {
#ifdef DEBUG_RTO
					printf("rto foos resend after timeout double %u - reducing to %u\n", foos->rto_us, TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC);
#endif
					foos->rto_us = TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC;
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
				pkt->seq, pkt->flags, pkt->seglen, ((pkt->tcp->data_off << 8) | pkt->tcp->tcp_flags) & 0xfff, foos->snd_nxt);
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

			_send_ack_pkt(w, ef, fos, pkt_in, NULL, orig_vlan, foos, dup_sack, tx_bufs, true, false, fos_must_ack);
		} else
			_send_ack_pkt_in(w, ef, fos, p, orig_vlan, foos, dup_sack, tx_bufs, false);
	}

	if (foos_send_ack)
		_send_ack_pkt_in(w, ef, foos, p, p->from_priv ? pub_vlan_tci : priv_vlan_tci, fos, NULL, tx_bufs, true);

	if (fin_set && !fin_rx) {
		fos->fin_seq = seq + p->seglen;
#ifdef DEBUG_FIN
		printf("Set fin_seq 0x%x - seq 0x%x seglen %u\n", fos->fin_seq, seq, p->seglen);
#endif
	}

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
		_eflow_free(w, ef, tx_bufs);

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
			_eflow_free(w, ef, tx_bufs);
		}

		return TFO_PKT_FORWARD;
	}

	/* A duplicate SYN could have no ACK, otherwise it is an error */
	if (unlikely(!(tcp_flags & RTE_TCP_ACK_FLAG) &&
		     ef->state != TCP_STATE_SYN)) {
		++w->st.estb_noflag_pkt;
		_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);

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
			_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
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
			_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
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
				_eflow_set_state(w, ef, TCP_STATE_SYN_ACK, NULL);
// When allow this, look at normal code for going to SYN_ACK
_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
ef->client_snd_win = rte_be_to_cpu_16(p->tcp->rx_win);
				++w->st.syn_ack_pkt;
			} else if (likely(!!(ef->flags & TFO_EF_FL_SYN_FROM_PRIV) != !!p->from_priv)) {
				/* syn+ack from other side */
				ack = rte_be_to_cpu_32(p->tcp->recv_ack);
				if (unlikely(!between_beg_ex(ack, ef->server_snd_una, ef->client_rcv_nxt))) {
#ifdef DEBUG_SM
					printf("SYN seq does not match SYN+ACK recv_ack, snd_una %x ack %x client_rcv_nxt %x\n", ef->server_snd_una, ack, ef->client_rcv_nxt);
#endif

					_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
					++w->st.syn_bad_pkt;
					break;
				}

				if (!set_tcp_options(p, ef)) {
					_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
					++w->st.syn_bad_pkt;
					break;
				}

				_eflow_set_state(w, ef, TCP_STATE_SYN_ACK, NULL);
				check_do_optimize(w, p, ef, tx_bufs);
// Do initial RTT if none for user, otherwise ignore due to additional time for connection establishment
// RTT is per user on private side, per flow on public side
				++w->st.syn_ack_pkt;
// Reply to SYN+ACK with ACK - we essentially go to ESTABLISHED processing
// This means the SYN+ACK needs to be queued on client side - must not change timestamp though on that
			} else {
// Could be duplicate SYN+ACK
				/* bad sequence, won't optimize */
				_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
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
			_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);
			++w->st.fin_unexpected_pkt;

			return ret;

		case TCP_STATE_ESTABLISHED:
			if (ret == TFO_PKT_HANDLED) {
				_eflow_set_state(w, ef, TCP_STATE_FIN1, NULL);
				if (p->from_priv)
					ef->flags |= TFO_EF_FL_FIN_FROM_PRIV;
			}

			++w->st.fin_pkt;

			return ret;

		case TCP_STATE_FIN1:
			if (!!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) != !!p->from_priv) {
				if (ret == TFO_PKT_HANDLED)
					_eflow_set_state(w, ef, TCP_STATE_FIN2, NULL);

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

			_eflow_set_state(w, ef, TCP_STATE_BAD, tx_bufs);

			return TFO_PKT_FORWARD;
		}

		/* last ack of 3way handshake, go to established state */
// It might have data, so handle_pkt needs to be called
		_eflow_set_state(w, ef, TCP_STATE_ESTABLISHED, NULL);
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

		return TFO_PKT_HANDLED;
	}

	if (ef->state == TCP_STATE_FIN2 && (tcp_flags & RTE_TCP_ACK_FLAG)) {
		/* ack in fin2 state, go to time_wait state if all pkts ack'd */
		fo = &w->f[ef->tfo_idx];
#ifdef DEBUG_SM
		printf("FIN2 - cl rcv_nxt 0x%x fin_seq 0x%x, sv rcv_nxt 0x%x fin_seq 0x%x ret %u\n",
			fo->priv.rcv_nxt, fo->priv.fin_seq, fo->pub.rcv_nxt, fo->pub.fin_seq, ret);
#endif
		if (!!p->from_priv == !!(ef->flags & TFO_EF_FL_FIN_FROM_PRIV) &&
		    !payload_len(p)) {
			if (ret == TFO_PKT_HANDLED) {
// We should not need fin_seq - it will be seq of last packet on queue
				if (fo->priv.rcv_nxt == fo->priv.fin_seq &&
				    fo->pub.rcv_nxt == fo->pub.fin_seq) {
					_eflow_free(w, ef, tx_bufs);
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
	printf("pkt_len %u tcp %p tcp_offs %ld, tcp_len %u, mtod %p, seg_len %u tcp_flags 0x%x\n",
		p->m->pkt_len, p->tcp, (uint8_t *)p->tcp - rte_pktmbuf_mtod(p->m, uint8_t *),
		(p->tcp->data_off & 0xf0U) >> 2, rte_pktmbuf_mtod(p->m, uint8_t *), p->seglen, p->tcp->tcp_flags);
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
		printf("Received SYN, flags 0x%x, send_seq 0x%x seglen %u rx_win %hu\n",
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
		if (!ef)
			return TFO_PKT_NO_RESOURCE;
		ef->priv_port = priv_port;
		ef->pub_port = pub_port;
		ef->pub_addr.v4 = pub_addr;

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
		ef->client_ttl = ef->flags & TFO_EF_FL_IPV6 ? p->ip6h->hop_limits : p->ip4h->time_to_live;
		ef->last_use = w->ts.tv_sec;
		ef->client_packet_type = p->m->packet_type;
#ifdef CALC_USERS_TS_CLOCK
		ef->start_time = w->ts;
#endif
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

	/* Ensure the private area is initialised */
	((struct tfo_mbuf_priv *)rte_mbuf_to_priv(m))->pkt = NULL;

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
	uint16_t buf;

	for (buf = 0; buf < nb_tx; buf++) {
		/* We don't do anything with ACKs */
		if (ack_bit_is_set(tx_bufs, buf))
			continue;

		priv = rte_mbuf_to_priv(tx_bufs->m[buf]);
		if (!(pkt = priv->pkt))
			continue;

		fos = priv->fos;
		fos->pkts_queued_send--;

		if (pkt->flags & TFO_PKT_FL_SENT) {
			pkt->flags |= TFO_PKT_FL_RESENT;
			if (pkt->flags & TFO_PKT_FL_RTT_CALC) {
				/* Abort RTT calculation */
				fos->flags &= ~TFO_SIDE_FL_RTT_CALC;
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
			if (!pkt->ts && !(fos->flags & TFO_SIDE_FL_RTT_CALC)) {
				fos->flags |= TFO_SIDE_FL_RTT_CALC;
				pkt->flags |= TFO_PKT_FL_RTT_CALC;
			}
		}

		/* RFC 8985 6.1 for LOST */
		pkt->flags &= ~(TFO_PKT_FL_LOST | TFO_PKT_FL_QUEUED_SEND);

		pkt->ns = now;

		/* RFC8985 to make step 2 faster */
// This doesn't work with LOST at end
if (before(pkt->seq, fos->snd_una))
	printf("postprocess ERROR pkt->seq 0x%x before fos->snd_una 0x%x, xmit_ts_list %p:%p\n", pkt->seq, fos->snd_una, pkt->xmit_ts_list.prev, pkt->xmit_ts_list.next);

		if (list_is_queued(&pkt->xmit_ts_list))
			list_move_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);
		else
			list_add_tail(&pkt->xmit_ts_list, &fos->xmit_ts_list);

		if (after(segend(pkt), fos->snd_nxt))
			fos->snd_nxt = segend(pkt);
	}
}

static void
tfo_packets_not_sent(struct tfo_tx_bufs *tx_bufs, uint16_t nb_tx) {
	struct tfo_mbuf_priv *priv;
	struct tfo_pkt *pkt;

	for (uint16_t buf = nb_tx; buf < tx_bufs->nb_tx; buf++) {
#ifdef DEBUG_GARBAGE
		printf("\tm %p not sent\n", tx_bufs->m[buf]);
#endif
		if (ack_bit_is_set(tx_bufs, buf))
			rte_pktmbuf_free(tx_bufs->m[buf]);
		else {
			rte_pktmbuf_refcnt_update(tx_bufs->m[buf], -1);
			priv = rte_mbuf_to_priv(tx_bufs->m[buf]);
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

static inline void
tfo_send_burst(struct tfo_tx_bufs *tx_bufs)
{
	uint16_t nb_tx;

#ifdef DEBUG_SEND_BURST_ERRORS
	for (unsigned i = 0; i < tx_bufs->nb_tx; i++) {
		struct tfo_mbuf_priv *priv;

		if (!ack_bit_is_set(tx_bufs, i)) {
			priv = rte_mbuf_to_priv(tx_bufs->m[i]);
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
//		printf("Sending %u packets:\n", tx_bufs->nb_tx);
#endif

		for (int i = 0; i < tx_bufs->nb_tx; i++) {
			bool ack_error = !ack_bit_is_set(tx_bufs, i) == !strncmp("ack_pool_", tx_bufs->m[i]->pool->name, 9);
#ifdef DEBUG_SEND_BURST_ERRORS
			if (ack_error)
#endif
				printf("\t%3.3d: %p - ack 0x%x pool %s%s", i, tx_bufs->m[i], tx_bufs->acks[i / CHAR_BIT] & (1U << (i % CHAR_BIT)), tx_bufs->m[i]->pool->name, ack_error ? " *** ACK FLAG mismatch pool" : "");
#ifdef DEBUG_SEND_BURST_ERRORS
			if (!ack_bit_is_set(tx_bufs, i)) {
				struct tfo_mbuf_priv *priv;
				priv = rte_mbuf_to_priv(tx_bufs->m[i]);
				if (!priv->fos || !priv->pkt)
					printf(" fos %p pkt %p refcnt %u %s\n", priv->fos, priv->pkt, rte_mbuf_refcnt_read(tx_bufs->m[i]), !priv->fos || !priv->pkt ? " ***" : "");
			} else if (ack_error)
				printf("\n");
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
				priv = rte_mbuf_to_priv(tx_bufs->m[i]);
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
#ifdef DEBUG_GARBAGE
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
#ifdef DEBUG_BURST
	struct tm tm;
	char str[24];
	unsigned long gap;
	static thread_local struct timespec last_time;
#endif

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
	/* Ensure tv_sec does not overflow when multiplied by 1000 */

	now = timespec_to_ns(&w->ts);

#ifdef DEBUG_BURST
	struct timespec ts_wallclock;

	clock_gettime(CLOCK_REALTIME, &ts_wallclock);
	gap = (ts_wallclock.tv_sec - last_time.tv_sec) * SEC_TO_NSEC + (ts_wallclock.tv_nsec - last_time.tv_nsec);
	localtime_r(&ts_wallclock.tv_sec, &tm);
	strftime(str, 24, "%T", &tm);
	printf("\n%s.%9.9ld Burst received %u pkts time " TIMESPEC_TIME_PRINT_FORMAT " gap " NSEC_TIME_PRINT_FORMAT "\n", str, ts_wallclock.tv_nsec, nb_rx, NSEC_TIME_PRINT_PARAMS(now), NSEC_TIME_PRINT_PARAMS(gap));
	last_time = ts_wallclock;
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
		priv = rte_mbuf_to_priv(pkt->m);
		fo = priv->fos->tfo;
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

printf("Resending %u failed packets\n", tx_bufs.nb_tx);
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

static
#ifdef DEBUG_GARBAGE
	bool
#else
	void
#endif
handle_rto(struct tcp_worker *w, struct tfo *fo, struct tfo_eflow *ef, struct tfo_side *fos,
	   struct tfo_side *foos, struct tfo_tx_bufs *tx_bufs
#ifdef DEBUG_GARBAGE
							     , bool sent
#endif
									)
{
	bool pkt_resent;
	uint32_t win_end;
	struct tfo_pkt *pkt;

	win_end = get_snd_win_end(fos);
	pkt_resent = false;
	list_for_each_entry(pkt, &fos->pktlist, list) {
		if (after(segend(pkt), win_end))
			break;

		if (pkt->m &&
		    (!(pkt->flags & TFO_PKT_FL_SENT) ||
		     packet_timeout(pkt->ns, fos->rto_us) < now)) {
			if (pkt->flags & TFO_PKT_FL_SENT)
				pkt_resent = true;

			/* RFC5681 3.2 */
			if ((pkt->flags & (TFO_PKT_FL_SENT | TFO_PKT_FL_RESENT)) == TFO_PKT_FL_SENT) {
				fos->ssthresh = min((uint32_t)(fos->snd_nxt - fos->snd_una) / 2, 2 * fos->mss);
				fos->cwnd = fos->mss;
				win_end = get_snd_win_end(fos);
			}
#ifdef DEBUG_GARBAGE
			bool already_sent = !!(pkt->flags & TFO_PKT_FL_SENT);
#endif

#ifdef DEBUG_SEND_PKT_LOCATION
			printf("send_tcp_pkt L\n");
#endif
			send_tcp_pkt(w, pkt, tx_bufs, fos, foos, false);

#ifdef DEBUG_GARBAGE
			if (!sent) {
				printf("\nGarbage send at " NSEC_TIME_PRINT_FORMAT "\n", NSEC_TIME_PRINT_PARAMS(now));
				sent = true;
			}
			printf("  %sending 0x%x %u\n", already_sent? "Res" : "S", pkt->seq, pkt->seglen);
#endif
		}
	}

// Should we do this if using_rack()?
	if (pkt_resent) {
		fos->rto_us *= 2;

		if (fos->rto_us > TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC) {
#ifdef DEBUG_RTO
			printf("rto garbage resend after timeout double %u - reducing to %u\n", fos->rto_us, TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC);
#endif
			fos->rto_us = TFO_TCP_RTO_MAX_MS * MSEC_TO_USEC;
		}

		if (!(fos->flags & TFO_SIDE_FL_IN_RECOVERY)) {
			fos->flags |= TFO_SIDE_FL_IN_RECOVERY;
			fos->recovery_end_seq = fos->snd_nxt;

#ifdef DEBUG_RECOVERY
			printf("Entering RTO recovery, end 0x%x\n", fos->recovery_end_seq);
#endif
		}
	}

	/* If the first entry on the pktlist is a SACK entry, we are missing a
	 * packet before that entry, and we will have sent a duplicate ACK for
	 * it. If we have not received the packet within rto time, we need to
	 * resend the ACK. */
	if(!list_empty(&fos->pktlist) &&
	   !(pkt = list_first_entry(&fos->pktlist, struct tfo_pkt, list))->m &&
	   packet_timeout(foos->ack_sent_time, foos->rto_us) < now) {
#ifdef DEBUG_GARBAGE
		if (!sent) {
			printf("\nGarbage send at " NSEC_TIME_PRINT_FORMAT "\n", NSEC_TIME_PRINT_PARAMS(now));
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

		_send_ack_pkt(w, ef, foos, NULL, &addr, foos == &fo->pub ? pub_vlan_tci : priv_vlan_tci, fos, NULL, tx_bufs, false, false, true);
#else
		pkt = list_first_entry(&fos->pktlist, struct rte_pkt, list);

		_send_ack_pkt(w, ef, foos, pkt, NULL, foos == &fo->pub ? pub_vlan_tci : priv_vlan_tci, fos, NULL, tx_bufs, true, false, true);
#endif
// Should we double foos->rto ?
	}

#ifdef DEBUG_GARBAGE
	return sent;
#endif
}

/*
 * run every 2ms or 5ms.
 * do not spend more than 1ms here
 */
void
tfo_garbage_collect(const struct timespec *ts, struct tfo_tx_bufs *tx_bufs)
{
	struct tfo_eflow *ef;
	unsigned k, iter;
	struct tcp_worker *w = &worker;
	uint32_t i;
	struct tfo_side *fos, *foos;
	struct tfo_user *u;
	struct tfo *fo;
	uint16_t snow;
#ifdef DEBUG_PKTS
	bool removed_eflow = false;
#endif
#ifdef DEBUG_GARBAGE
	bool rto_sent = false;
	bool time_printed = false;
#endif

	if (ts)
		w->ts = *ts;
	else
		clock_gettime(CLOCK_MONOTONIC_RAW, &w->ts);
	now = timespec_to_ns(&w->ts);

	/* eflow garbage collection */
/* We run 500 times per second => 10 should be config->ef_n / 500 */
	snow = w->ts.tv_sec & 0xffff;
	iter = max(10, config->ef_n * config->slowpath_time / 1000);
	for (k = 0; k < iter; k++) {
		ef = &w->ef[w->ef_gc];
		if (ef->flags && _eflow_timeout_remain(ef, snow) <= 0) {
// This is too simple if we have ack'd data but not received the ack
// We need a timeout for not receiving an ack for data we have ack'd
//  - both to resend and drop connection
			_eflow_free(w, ef, tx_bufs);
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

	/* Linux does a first resend after 0.21s, then after 0.24s, then 0.48s, 0.96s ... */
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
// TFO_EF_FL_TIMESTAMP shouldn't matter, but RACK code needs updating to cope with that
						if (unlikely(!using_rack(ef))) {
#ifdef DEBUG_GARBAGE
							rto_sent |= handle_rto(w, fo, ef, fos, foos, tx_bufs, rto_sent);
#else
							handle_rto(w, fo, ef, fos, foos, tx_bufs);
#endif
						} else if (unlikely(fos->timeout <= now) || unlikely(fos->ack_timeout <= now)) {
#ifdef DEBUG_GARBAGE
							if (!time_printed) {
								time_printed = true;
								printf("Timer time: " NSEC_TIME_PRINT_FORMAT "\n", NSEC_TIME_PRINT_PARAMS(now));
							}
#endif
							handle_rack_tlp_timeout(w, ef, fos, foos, tx_bufs);
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
	if (rto_sent)
		dump_details(w);
#endif
}

void
tfo_garbage_collect_send(const struct timespec *ts)
{
	struct tfo_tx_bufs tx_bufs = { .nb_inc = 1024 };

	tfo_garbage_collect(ts, &tx_bufs);
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
		INIT_LIST_HEAD(&p->xmit_ts_list);
		INIT_LIST_HEAD(&p->send_failed_list);
	}

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

	global_config_data.hu_n = next_power_of_2(global_config_data.hu_n);
	global_config_data.hu_mask = global_config_data.hu_n - 1;
	global_config_data.hef_n = next_power_of_2(global_config_data.hef_n);
	global_config_data.hef_mask = global_config_data.hef_n - 1;
	global_config_data.option_flags = c->option_flags;
	global_config_data.tcp_min_rtt_wlen = c->tcp_min_rtt_wlen ? c->tcp_min_rtt_wlen : (300 * SEC_TO_MSEC);	// Linux default value is 300 seconds

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
//	return sizeof(struct tfo_pkt);
}
