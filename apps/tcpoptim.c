/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */


#ifdef PQA
#define _GNU_SOURCE
#endif

#include "tfo_options.h"
#include "tfo_app_config.h"

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <ev.h>
#include <threads.h>
#ifdef APP_DEBUG_PKT_DETAILS
#include <net/if.h>
#endif

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_telemetry.h>
#ifdef APP_DEBUG_PKT_DETAILS
#include <rte_ip.h>
#endif
#include <rte_malloc.h>


#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef APP_CLEAR_RX_BUFS
#include <string.h>
#endif

#include "tfo_options.h"
#include "tcp_process.h"
#include "tfo.h"
#include "util.h"
#if defined DEBUG_PRINT_TO_BUF || defined PER_THREAD_LOGS
#include "tfo_printf.h"
#endif

#define PROG_NAME "tcpoptim"

/* locals */
static uint16_t port_id[APP_MAX_IF];
static int sigint;
static int sigterm;
static struct ev_loop *loop;
static struct ev_signal ev_sigterm;
static struct ev_signal ev_sigint;
static pthread_t initial_pthread_id;
static volatile bool force_quit;
static uint16_t burst_size = APP_DEFAULT_BURST_SIZE;

static uint16_t vlan_idx;
// Redefine this to be struct { uint16_t pub_vlan, uint16_t priv_vlan };
static uint16_t vlan_id[APP_MAX_IF * 2];

static struct rte_mempool *ack_pool[RTE_MAX_NUMA_NODES];

static thread_local uint16_t priv_vlan;
static thread_local uint16_t gport_id;
static thread_local uint16_t gqueue_idx;
static thread_local struct rte_ether_addr our_mac_addr;
#ifdef APP_LOG_TIMER_SECS
static thread_local struct timespec last_ts;
#endif

/* Doesn't need to be thread_local if our impure D-space is on the right node */
static thread_local uint64_t priv_mask;


#ifdef APP_DEBUG_DUPLICATE_MBUFS
static uint16_t
check_duplicate_mbufs(struct rte_mbuf **bufs, uint16_t nb_rx)
{
	uint16_t i, j;
#ifdef APP_FIX_DUPLICATE_MBUFS
	bool found_duplicate = false;
#endif

	if (nb_rx <= 1)
		return nb_rx;

	for (i = 0; i + 1 < nb_rx; i++) {
		for (j = i + 1; j < nb_rx; j++) {
			if (bufs[i] == bufs[j]) {
				printf("ERROR: mbufs %u and %u out of %u are both %p\n", i, j, nb_rx, bufs[i]);

#ifdef APP_FIX_DUPLICATE_MBUFS
				found_duplicate = true;
#endif
			}
		}
	}

#ifdef APP_FIX_DUPLICATE_MBUFS
	/* We could do this in the previous loop, but we
	 * want to checks the bufs before they are modified. */
	if (found_duplicate) {
		for (i = 0; i + 1 < nb_rx; i++) {
			for (j = i + 1; j < nb_rx; j++) {
				if (bufs[i] == bufs[j]) {
					bufs[j] = bufs[--nb_rx];
					j--;		// We need to check the entry we have moved
				}
			}
		}
	}
#endif

	return nb_rx;
}
#endif

static void
do_shutdown(void)
{
	int retval = 0;
	int nb_ports = rte_eth_dev_count_avail();

	for (int i = 0; i < nb_ports; i++) {
		retval |= rte_eth_promiscuous_disable(port_id[i]);
		retval |= rte_eth_dev_stop(port_id[i]);
		retval |= rte_eth_dev_close(port_id[i]);
	}

	if (retval)
		printf("Port shutdown failed, retval = %d\n", retval);
}

static int
shutdown_cmd(__rte_unused const char *cmd, __rte_unused const char *params, __rte_unused struct rte_tel_data *info)
{
#ifdef APP_LOG_SHUTDOWN
	printf("Shutdown called for pid %d tid %d\n", getpid(), gettid());
#endif
	pthread_kill(initial_pthread_id, SIGTERM);

	return 0;
}

static void
sigint_hdl(struct ev_loop *loop_p, __rte_unused struct ev_signal *w, __rte_unused int revents)
{
	if (sigint >= 2) {
		fprintf(stderr, "ctrl-C pressed too much, dying hard\n");
		exit(1);
	}

	if (++sigint == 1) {
		force_quit = true;
		do_shutdown();
#ifdef APP_LOG_SHUTDOWN
		fprintf(stderr, "shutting down for INT\n");
#endif
		ev_break(loop_p, EVBREAK_ONE);
	}
}

static void
sigterm_hdl(struct ev_loop *loop_p, __rte_unused struct ev_signal *w, __rte_unused int revents)
{
	if (sigterm >= 2) {
		fprintf(stderr, "too many sigterm received, dying in great woe\n");
		exit(1);
	}

	if (++sigterm == 1) {
		force_quit = true;
		do_shutdown();
#ifdef APP_LOG_SHUTDOWN
		fprintf(stderr, "shutting down for TERM\n");
#endif
		ev_break(loop_p, EVBREAK_ONE);
	}
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, int ring_count)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = ring_count, tx_rings = ring_count;
	uint16_t nb_rxd = APP_RX_RING_SIZE;
	uint16_t nb_txd = APP_TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up x RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up x TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, &our_mac_addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: " RTE_ETHER_ADDR_PRT_FMT "\n",
			port, RTE_ETHER_ADDR_BYTES(&our_mac_addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static void
set_dir(struct rte_mbuf **bufs, uint16_t nb_rx)
{
	uint16_t i;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
	uint16_t vlan_tag;

	for (i = 0; i < nb_rx; i++) {
// Can we do bufs++; ?
		m = bufs[i];
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
//printf("m->vlan_tci %u, eh->ether_type %x, m->ol_flags 0x%x\n", m->vlan_tci, rte_be_to_cpu_16(eh->ether_type), m->ol_flags);

		if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
			vh = (struct rte_vlan_hdr *)(eh + 1);

			vlan_tag = rte_be_to_cpu_16(vh->vlan_tci);
		} else
			vlan_tag = 0;

		if (priv_vlan == vlan_tag)
			m->ol_flags |= priv_mask;
	}
}

#ifdef APP_UPDATES_VLAN
static inline void
update_vlan_ids(struct rte_mbuf** bufs,
		uint16_t nb_tx,
#ifndef APP_VLAN_SWAP
		__attribute__((unused))
#endif
					uint16_t port_vlan_idx)
{
	uint16_t i;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
	uint16_t vlan_tag;
	uint16_t vlan_new;
#ifdef APP_VLAN_SWAP
	uint16_t vlan0 = vlan_id[port_vlan_idx * 2];
	uint16_t vlan1 = vlan_id[port_vlan_idx * 2 + 1];
#endif
#ifdef APP_DEBUG_PKT_DETAILS
	struct rte_ipv4_hdr *iph = NULL;
	struct rte_ipv6_hdr *ip6h = NULL;
#endif

#ifdef APP_DEBUG_PKT_DETAILS
	printf("update_vlan_ids %u <=> %u\n", vlan0, vlan1);
#endif

	for (i = 0; i < nb_tx; i++) {
		m = bufs[i];
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
//printf("m->vlan_tci %u, eh->ether_type %x, m->ol_flags 0x%x\n", m->vlan_tci, rte_be_to_cpu_16(eh->ether_type), m->ol_flags);

		/* This swaps Vlan 1 and Vlan 2 */
		if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
			vh = (struct rte_vlan_hdr *)(eh + 1);

			vlan_tag = rte_be_to_cpu_16(vh->vlan_tci);
		} else
			vlan_tag = 0;

#ifdef APP_VLAN_SWAP
		if (vlan_tag == vlan0)
			vlan_new = vlan1;
		else if (vlan_tag == vlan1)
			vlan_new = vlan0;
		else {
			printf("Packet on unused vlan %u\n", vlan_tag);
			vlan_new = 4096;
		}
#else
		vlan_new = m->vlan_tci;
#endif

#ifdef APP_DEBUG_PKT_DETAILS
		if (vlan_tag) {
			if (vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
				iph = (struct rte_ipv4_hdr *)(vh + 1);
			else if (vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
				ip6h = (struct rte_ipv6_hdr *)(vh + 1);
#ifdef APP_DEBUG_PKT_TYPE_UNKNOWN
			else
				printf("vh->eth_proto = 0x%x\n", rte_be_to_cpu_16(vh->eth_proto));
#endif
		} else {
			if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
				iph = (struct rte_ipv4_hdr *)(eh + 1);
			else if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
				ip6h = (struct rte_ipv6_hdr *)(eh + 1);
#ifdef APP_DEBUG_PKT_TYPE_UNKNOWN
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
#ifdef APP_DEBUG_PKT_TYPE_UNKNOWN
			printf("Unknown layer 3 protocol mbuf %u\n", i);
#endif
		}
#endif

		if (vlan_new != 4096) {
			if (vlan_new && vlan_tag) {
				vh->vlan_tci = rte_cpu_to_be_16(vlan_new);
			} else if (!vlan_new && !vlan_tag) {
				/* Do nothing */
			} else if (!vlan_new) {
				/* remove vlan encapsulation */
				eh->ether_type = vh->eth_proto;		// We could avoid this, and copy sizeof - 2
//printf("Removing vlan encap memmove(%p, %p, %u\n", rte_pktmbuf_mtod_offset(m, uint8_t *, sizeof (struct rte_vlan_hdr)), eh, sizeof (struct rte_ether_hdr));
//fflush(stdout);
				memmove(rte_pktmbuf_adj(m, sizeof (struct rte_vlan_hdr)),
					eh, sizeof (struct rte_ether_hdr));
				eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			} else {
				/* add vlan encapsulation */
				uint8_t *p = (uint8_t *)rte_pktmbuf_prepend(m, sizeof (struct rte_vlan_hdr));

				if (unlikely(p == NULL)) {
					p = (uint8_t *)rte_pktmbuf_append(m, sizeof (struct rte_vlan_hdr));
					if (likely(p)) {
						/* This is so unlikely, just move the whole packet to
						 * make room at the beginning to move the ether hdr */
						memmove(eh + sizeof(struct rte_vlan_hdr), eh, m->data_len - sizeof (struct rte_vlan_hdr));
						p = rte_pktmbuf_mtod(m, uint8_t *);
						eh = (struct rte_ether_hdr *)(p + sizeof(struct rte_vlan_hdr));
					} else {
						tfo_packet_no_room_for_vlan(m);

						/* Send it nowhere */
						eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
// When sort out swapping MAC addresses, it is dst_addr we should set
						/* Set the address to a (non-existent) locally administered address */
//						memset(&eh->dst_addr, sizeof(eh->dst_addr), 2);
memset(&eh->src_addr, sizeof(eh->src_addr), 2);
					}
				}

				if (likely(p)) {
					/* move ethernet header at the start */
					memmove(p, eh, sizeof (struct rte_ether_hdr));		// we could do sizeof - 2
					eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

					vh = (struct rte_vlan_hdr *)(eh + 1);
					vh->vlan_tci = rte_cpu_to_be_16(vlan_new);
					vh->eth_proto = eh->ether_type;

					eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
				}
			}

			m->vlan_tci = vlan_new;

#ifdef APP_DEBUG_PKT_DETAILS
			printf("Moving packet from vlan %u to %u\n", vlan_tag, vlan_new);
#endif
		}
	}
}
#endif

#if defined APP_UPDATES_MAC_ADDR && !defined APP_SENDS_PKTS
static void
swap_mac_addr(struct rte_mbuf **bufs, uint16_t nb_tx)
{
	struct rte_ether_addr sav_src_addr;
	struct rte_ether_hdr *eh;
	uint16_t i;

	for (i = 0; i < nb_tx; i++) {
		eh = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
		if (memcmp(&eh->src_addr, &our_mac_addr, sizeof(our_mac_addr))) {
			rte_ether_addr_copy(&eh->src_addr, &sav_src_addr);
			rte_ether_addr_copy(&eh->dst_addr, &eh->src_addr);
			rte_ether_addr_copy(&sav_src_addr, &eh->dst_addr);
		}
	}
}
#endif

#ifndef APP_SENDS_PKTS
static uint16_t
burst_send(uint16_t port, uint16_t queue_idx, struct rte_mbuf **bufs, uint16_t nb_tx)
{
	if (!nb_tx)
		return 0;

#ifdef APP_UPDATES_VLAN
	update_vlan_ids(bufs, nb_tx, port);
#endif

#ifdef APP_UPDATES_MAC_ADDR
	swap_mac_addr(bufs, nb_tx);
#endif

#ifdef APP_LOG_ACTIONS
	printf("No to tx %u\n", nb_tx);
#endif

	/* send burst of TX packets, to second port of pair. */
#ifndef DEBUG_CHECK_PKTS
	return rte_eth_tx_burst(port, queue_idx, bufs, nb_tx);
#else
	check_packets("burst_send before rte_eth_tx_burst");
	nb_tx = rte_eth_tx_burst(port, queue_idx, bufs, nb_tx);
	check_packets("burst_send after rte_eth_tx_burst");

	return nb_tx;
#endif
}
#endif

static inline void
fwd_packet(uint16_t port, uint16_t queue_idx)
{
	/* Get burst of RX packets, from first port of pair. */
	struct rte_mbuf *bufs[burst_size];
#ifdef APP_DEBUG_PKT_DETAILS
	struct rte_eth_dev_info dev_info;
	char ifname[IF_NAMESIZE];
#endif
	struct timespec ts;
	uint16_t nb_rx;
#ifdef APP_SENDS_PKTS
	struct tfo_tx_bufs tx_bufs = { .nb_tx = 0 };
	uint16_t nb_tx;
#endif

#ifdef APP_CLEAR_RX_BUFS
	memset(bufs, 0, sizeof(bufs));
#endif
#ifdef DEBUG_CHECK_PKTS
	check_packets("fwd_packet before rte_eth_rx_burst");
#endif
	nb_rx = rte_eth_rx_burst(port, queue_idx, bufs, burst_size);
#ifdef DEBUG_CHECK_PKTS
	check_packets("fwd_packet after rte_eth_rx_burst");
#endif

	if (unlikely(nb_rx == 0))
		return;

#ifdef APP_SENDS_PKTS
	/* Allow for forwarding packet and ACK, but also set a minimum */
	tx_bufs.nb_inc = max(nb_rx * 2, 10);
#endif

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#ifdef APP_DEBUG_PKT_DETAILS
	char timestamp[24];
	char *p = timestamp;
	time_t t;
	struct tm tm;
	struct timespec ts_wallclock;

	t = ts_wallclock.tv_sec;
	localtime_r(&t, &tm);
	p += strftime(p, sizeof(timestamp), "%T", &tm);
	p += snprintf(p, timestamp + sizeof(timestamp) - p, ".%9.9ld", ts_wallclock.tv_nsec);

	rte_eth_dev_info_get(port, &dev_info);
	printf("%s (%d): %s %s(%d) ", timestamp, gettid(), dev_info.driver_name, if_indextoname(dev_info.if_index, ifname), dev_info.if_index);
#endif

#ifdef APP_LOG_ACTIONS
	printf("\nfwd %d packet(s) from port %d to port %d, lcore %u, queue_idx: %u\n",
	       nb_rx, port, port, rte_lcore_id(), queue_idx);
#endif

#ifdef APP_DEBUG_DUPLICATE_MBUFS
	nb_rx = check_duplicate_mbufs(bufs, nb_rx);
	if (!nb_rx)
		return;
#endif

	nb_rx = monitor_pkts(bufs, nb_rx);
	if (!nb_rx)
		return;

	set_dir(bufs, nb_rx);

#ifndef APP_SENDS_PKTS
	tcp_worker_mbuf_burst_send(bufs, nb_rx, &ts);
#else
	tcp_worker_mbuf_burst(bufs, nb_rx, &ts, &tx_bufs);

#ifdef APP_LOG_ACTIONS
	printf("No to tx %u\n", tx_bufs.nb_tx);
#endif

	if (tx_bufs.nb_tx) {
#ifdef APP_UPDATES_VLAN
		update_vlan_ids(tx_bufs.m, tx_bufs.nb_tx, port);
#endif

		/* send burst of TX packets, to second port of pair. */
#ifdef DEBUG_CHECK_PKTS
		check_packets("fwd_packets before rte_eth_tx_burst");
#endif
		nb_tx = rte_eth_tx_burst(port, queue_idx, tx_bufs.m, tx_bufs.nb_tx);
#ifdef DEBUG_CHECK_PKTS
		check_packets("fwd_packets after rte_eth_tx_burst");
#endif

		if (tfo_post_send(&tx_bufs, nb_tx)) {
			/* Some packets were not sent; try again */
			tfo_setup_failed_resend(&tx_bufs);

#ifdef DEBUG_CHECK_PKTS
			check_packets("fwd_packets before failed rte_eth_tx_burst");
#endif
			nb_tx = rte_eth_tx_burst(port, queue_idx, tx_bufs.m, tx_bufs.nb_tx);
#ifdef DEBUG_CHECK_PKTS
			check_packets("fwd_packets after failed rte_eth_tx_burst");
#endif
			tfo_post_send(&tx_bufs, nb_tx);
		}
	}

	if (tx_bufs.m)
		rte_free(tx_bufs.m);
#endif

#ifdef APP_LOG_ACTIONS
	printf("\n");
#endif
}


static void
process_timers(void)
{
	struct timespec ts;
#ifdef APP_SENDS_PKTS
	struct tfo_tx_bufs tx_bufs = { .m = NULL, .nb_inc = 1024 };
	uint16_t nb_tx;
#endif

	/* time is approx hz * seconds since boot */

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#ifdef APP_LOG_TIMER_SECS
	if (last_ts.tv_sec != ts.tv_sec)
		printf("Timer run " TIMESPEC_TIME_PRINT_FORMAT "\n", TIMESPEC_TIME_PRINT_PARAMS(ts));
	last_ts = ts;
#endif

#ifdef APP_SENDS_PKTS
	tfo_process_timers(&ts, &tx_bufs);

#ifdef APP_UPDATES_VLAN
	if (tx_bufs.nb_tx) {
		update_vlan_ids(tx_bufs.m, tx_bufs.nb_tx, gport_id);

#ifdef APP_LOG_TX_TIMER
		printf("No to tx on port %u queue %u: %u\n", gport_id, gqueue_idx, tx_bufs.nb_tx);
#endif
	}
#endif

	if (tx_bufs.nb_tx) {
		/* send burst of TX packets. */
#ifdef DEBUG_CHECK_PKTS
		check_packets("process_timers before rte_eth_tx_burst");
#endif
		nb_tx = rte_eth_tx_burst(gport_id, gqueue_idx, tx_bufs.m, tx_bufs.nb_tx);
#ifdef DEBUG_CHECK_PKTS
		check_packets("process_timers before rte_eth_tx_burst");
#endif

		tfo_post_send(&tx_bufs, nb_tx);
	}

	if (tx_bufs.m)
		rte_free(tx_bufs.m);
#else
	tfo_process_timers_send(&ts);
#endif

#if defined APP_LOG_TIMER_SECS || defined APP_LOG_TX_TIMER
	fflush(stdout);
#endif
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static int
lcore_main(__rte_unused void *arg)
{
	uint16_t port = rte_lcore_id() - 1;
	uint16_t queue_idx = 0;	// This would need to change if port_init were called with a ring_count > 1. For some reason this code used to be: queue_idx = rte_lcore_index(port + 1) - 1;
	struct tfo_worker_params params;

	gport_id = port;
	gqueue_idx = queue_idx;

// This is silly re rte_lcore_index()
	printf("Core %u queue_idx %d pid %d tid %d forwarding packets. [Ctrl+C to quit]\n",
	       port + 1U, queue_idx, getpid(), gettid());

#ifdef APP_DEBUG_PKT_DETAILS
	printf("tid %d\n", gettid());
#endif

	params.params = NULL;
	params.public_vlan_tci = vlan_id[port * 2];
	params.private_vlan_tci = vlan_id[port * 2 + 1];
	params.ack_pool = ack_pool[rte_socket_id()];
	params.port_id = gport_id;
	params.queue_idx = gqueue_idx;

	priv_mask = tcp_worker_init(&params);
	priv_vlan = vlan_id[port * 2 + 1];

	while (!force_quit) {
		fwd_packet(port, 0);

		process_timers();

#ifdef PQA
		usleep(1000);
#endif
	}

	return 0;
}

static void
print_help(const char *progname)
{
	printf("%s:\n", progname);
	printf("\t-H\t\tprint this\n");
	printf("\t-q vl[,vl]\tVlan id(s)\n");
	printf("\t-e flows\tMax flows\n");
	printf("\t-f flows\tMax optimised flows\n");
	printf("\t-p bufp\t\tMax buffered packets\n");
	printf("\t-X hash\t\tFlow hash size\n");
	printf("\t-t timeouts\tport:syn,est,fin TCP timeouts (port 0 = defaults)\n");
	printf("\t-r tcp_win_rtt_wlen\ttcp_win_rtt_wlen in seconds\n");
	printf("\t-b rx burst size\tmaximum no of packets to receive at once\n");
#ifdef PER_THREAD_LOGS
	printf("\t-l file_name\tper thread log file template name\n");
#endif
}

static int
get_val(const char *optarg)
{
	char *endptr;
	long val;

	val = strtol(optarg, &endptr, 10);
	if (*endptr || val < 0 || val > INT_MAX)
		return -1;

	return val;
}

static int
set_timeout(const char *optarg, struct tcp_config *c)
{
	char *endptr;
	long val;
	uint16_t port, to_syn, to_est, to_fin;
	struct tcp_timeouts *new_to;

	val = strtol(optarg, &endptr, 10);
	if (*endptr != ':' || val < 0 || val > UINT16_MAX)
		return -1;
	port = val;

	val = strtol(endptr + 1, &endptr, 10);
	if (*endptr != ',' || val <= 0 || val > 3600)
		return -1;
	to_syn = val;

	val = strtol(endptr + 1, &endptr, 10);
	if (*endptr != ',' || val <= 0 || val > 3600)
		return -1;
	to_est = val;

	val = strtol(endptr + 1, &endptr, 10);
	if (*endptr || val < 0 || val > UINT16_MAX)
		return -1;
	to_fin = val;

	if (port > c->max_port_to) {
		new_to = rte_realloc(c->tcp_to, (port + 1) * sizeof(*c->tcp_to), 0);
		if (!new_to) {
			fprintf(stderr, "Unable to allocate timeouts for port %u\n", port);
			return -2;
		}

		c->tcp_to = new_to;
		memset(&c->tcp_to[c->max_port_to + 1], 0, (port - c->max_port_to) * sizeof(*c->tcp_to));
		c->max_port_to = port;
	}

	c->tcp_to[port].to_syn = to_syn;
	c->tcp_to[port].to_est = to_est;
	c->tcp_to[port].to_fin = to_fin;

	return 0;
}

static void
set_default_timeouts(struct tcp_config *c)
{
	int i;

	for (i = 1; i < c->max_port_to; i++) {
		if (!c->tcp_to[i].to_syn) {
			c->tcp_to[i].to_syn = c->tcp_to[0].to_syn;
			c->tcp_to[i].to_est = c->tcp_to[0].to_est;
			c->tcp_to[i].to_fin = c->tcp_to[0].to_fin;
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool[RTE_MAX_NUMA_NODES];
	unsigned nb_ports, queue_count;
	const char *progname = argv[0];
	char opt;
	long vlan0, vlan1;
	int val;
	char *endptr;
	struct tcp_config c = { .ef_n = 10000, .f_n = 10000 };
	char packet_pool_name[] = "packet_pool_XXX";
	unsigned next_port_id;
	unsigned i;
	uint16_t node_ports[RTE_MAX_NUMA_NODES] = { 0 };
	uint16_t socket;
	sigset_t sigset;

	/* Block TERM and INT signals - they will be received via signalfd */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	c.tcp_to = rte_malloc("struct tcp_timeouts *", sizeof(*c.tcp_to), 0);
	c.max_port_to = 0;
	c.tcp_to[0].to_syn = 120;
	c.tcp_to[0].to_est = 600;
	c.tcp_to[0].to_fin = 60;
	c.option_flags = 0;
#ifndef APP_SENDS_PKTS
	c.tx_burst = burst_send;
#endif
#ifdef APP_UPDATES_VLAN
	c.option_flags |= TFO_CONFIG_FL_NO_VLAN_CHG;
#endif
#ifdef APP_UPDATES_MAC_ADDR
	c.option_flags |= TFO_CONFIG_FL_NO_MAC_CHG;
#endif

	while ((opt = getopt(argc, argv, ":Hq:e:f:p:X:t:r:b:"
#ifdef PER_THREAD_LOGS
				         "l:"
#endif
					 )) != -1) {
		switch(opt) {
		case 'H':
			print_help(progname);
			exit(0);
			break;
		case 'q':
			if (vlan_idx >= sizeof(vlan_id) / sizeof(vlan_id[0])) {
				fprintf(stderr, "Too many vlan ids specified\n");
				break;
			}
			vlan0 = strtol(optarg, &endptr, 10);
			if ((*endptr && endptr[0] != ',') ||
			    vlan0 < 0 || vlan0 > 4094) {
				fprintf(stderr, "Vlan '%s' invalid\n", optarg);
				break;
			}

			if (*endptr) {
				vlan1 = strtol(endptr + 1, &endptr, 10);
				if ((*endptr && endptr[0] != ',') ||
				    vlan1 < 0 || vlan1 > 4094) {
					fprintf(stderr, "Vlan '%s' invalid\n", optarg);
					break;
				}
			} else
				vlan1 = 0;
			vlan_id[vlan_idx++] = (uint16_t)vlan0;
			vlan_id[vlan_idx++] = (uint16_t)vlan1;

			break;
		case 'e':
			val = get_val(optarg);
			if (val == -1)
				fprintf(stderr, "Invalid max flows %s\n", optarg);
			else
				c.ef_n = val;
			break;
		case 'f':
			val = get_val(optarg);
			if (val == -1)
				fprintf(stderr, "Invalid max optimized flows %s\n", optarg);
			else
				c.f_n = val;
			break;
		case 'p':
			val = get_val(optarg);
			if (val == -1)
				fprintf(stderr, "Invalid max buffered packets %s\n", optarg);
			else
				c.p_n = val;
			break;
		case 'X':
			val = get_val(optarg);
			if (val == -1)
				fprintf(stderr, "Invalid flow hash size %s\n", optarg);
			else
				c.hef_n = val;
			break;
		case 't':
			if (set_timeout(optarg, &c) == -1)
				fprintf(stderr, "Invalid TCP timeout %s\n", optarg);
			break;
		case 'r':
			val = get_val(optarg);
			if (val == -1)
				fprintf(stderr, "Invalid tcp_win_rtt_wlen %s\n", optarg);
			else
				c.tcp_min_rtt_wlen = val * 1000U;
			break;
		case 'b':
			val = get_val(optarg);
			if (val == -1)
				fprintf(stderr, "Invalid burst size %s\n", optarg);
			else
				burst_size = val;
			break;
#ifdef PER_THREAD_LOGS
		case 'l':
			if (!freopen(optarg, "a", stdout))
				fprintf(stderr, "Unable to open log file %s, errno %d (%m)\n", optarg, errno);
			else
				c.log_file_name_template = optarg;
			break;
#endif
		case ':':
			fprintf(stderr, "Option '%c' is missing an argument\n", optopt);
			break;
		case '?':
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			break;
		}
	}

	/* check that there is at least 1 port available */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: should have at least 1 port\n");
	else if (nb_ports > APP_MAX_IF) {
		printf("Warning: only the first %d ports will be used\n", APP_MAX_IF);
		nb_ports = APP_MAX_IF;
	}

	/* Set defaults */
	if (!c.p_n)
		c.p_n = c.f_n * 10;
	if (!c.hef_n)
		c.hef_n = c.ef_n;
	if (c.f_n > c.ef_n) {
		fprintf(stderr, "Reducing number of optimized flows to %u (number of eflows)\n", c.ef_n);
		c.f_n = c.ef_n;
	}

	set_default_timeouts(&c);

	/* Share between workers */
	c.ef_n = (c.ef_n + nb_ports - 1) / nb_ports;
	c.f_n = (c.f_n + nb_ports - 1) / nb_ports;
	c.p_n = (c.p_n + nb_ports - 1) / nb_ports;

#ifdef APP_DEBUG_PKT_DETAILS
	printf("vlans");
	for (int i = 0; i < nb_ports * 2; i++)
		printf(" %u", vlan_id[i]);
	printf("\n");
#endif

	/* Creates mempools to hold the mbufs. */
	for (i = 0, next_port_id = 0; i < nb_ports; i++) {
		port_id[i] = rte_eth_find_next_owned_by(next_port_id, RTE_ETH_DEV_NO_OWNER);
		node_ports[rte_eth_dev_socket_id(port_id[i])]++;
		next_port_id = port_id[i] + 1;
	}

	/* We are the only user of the private mbuf area */
	c.mbuf_priv_offset = 0;

	/* We want 2 mempools per NUMA socket with a port on it - see rte_lcore.h */
	for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
		if (node_ports[i]) {
			snprintf(packet_pool_name, sizeof(packet_pool_name), "packet_pool_%u", i);
			mbuf_pool[i] = rte_pktmbuf_pool_create(packet_pool_name, (APP_NUM_MBUFS + 1) * node_ports[i] - 1, APP_MBUF_CACHE_SIZE,
					RTE_ALIGN(tfo_get_mbuf_priv_size(), RTE_MBUF_PRIV_ALIGN),
					RTE_MBUF_DEFAULT_BUF_SIZE, i);

			if (mbuf_pool[i] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

#ifdef APP_DEBUG_MEMPOOL_INIT
			printf("Creating mempool %s\n", packet_pool_name);
			show_mempool(packet_pool_name);
#endif

			/* For this to work, need to increase huge_pages to 7 or 13 (# echo 13 >/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages) */
			snprintf(packet_pool_name, sizeof(packet_pool_name), "ack_pool_%u", i);
			ack_pool[i] = rte_pktmbuf_pool_create(packet_pool_name, ((APP_NUM_MBUFS + 1) * node_ports[i] - 1 ) * 2 / 3,
				APP_MBUF_CACHE_SIZE, 0, tfo_max_ack_pkt_size(), i);
			if (ack_pool[i] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot create ack mbuf pool\n");

#ifdef APP_DEBUG_ACK_MEMPOOL_INIT
			printf("Creating mempool %s\n", packet_pool_name);
			show_mempool(packet_pool_name);
#endif
		}
	}

	/* Each thread should have its own tx and rx queue. We want to share
	 * threads (lcores) across NICs. This means that a thread reads its
	 * own rx queue and writes to its own tx queue.
	 * Each thread should run on same NUMA core as NIC it is handling. */
	/* open one rx/tx queue per lcore. */
	queue_count = rte_lcore_count() - 1;
	if (queue_count < 1)
		rte_exit(EXIT_FAILURE, "Error: should have at least 1 worker (check -l option)\n");
	if (queue_count < nb_ports)
		rte_exit(EXIT_FAILURE, "Error: should have at least 1 worker (check -l option) per port\n");
	if (queue_count > nb_ports)
		printf("Warning: queue count should be the same as the number of ports\n");

	/* initialize our ports. */
	for (i = 0; i < nb_ports; i++) {
		socket = rte_eth_dev_socket_id(port_id[i]);
		if (port_init(port_id[i], mbuf_pool[socket], 1) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port[%u] %u\n", i, port_id[i]);

#ifdef APP_DEBUG_MEMPOOL_INIT
		printf("Done port %u init, queue_count %u\n", port_id[i], queue_count);
		show_mempool(packet_pool_name);
#endif
	}

	/* create event loop for the main thread */
	loop = ev_default_loop(EVFLAG_AUTO | EVFLAG_SIGNALFD | EVFLAG_NOSIGMASK);
	if (loop == NULL)
		return 1;

	/* set sigint/sigterm handlers */
	if (isatty(STDIN_FILENO)) {
		ev_signal_init(&ev_sigint, &sigint_hdl, SIGINT);
		ev_signal_start(loop, &ev_sigint);
	}
	ev_signal_init(&ev_sigterm, &sigterm_hdl, SIGTERM);
	ev_signal_start(loop, &ev_sigterm);

	/* The library will take over "ownership" of c->tcp_to */
	tcp_init(&c);

	/* Used for telemetry shutdown command to signal this thread */
	initial_pthread_id = pthread_self();

	/* start all worker threads (but not us, return immediately) */
	rte_eal_mp_remote_launch(lcore_main, NULL, SKIP_MAIN);

	ret = rte_telemetry_register_cmd("/" PROG_NAME "/shutdown", shutdown_cmd, "Shuts down " PROG_NAME);
	printf("register shutdown returned %d for pid %d, tid %d\n", ret, getpid(), gettid());

	/* on this main core, you can run other service, like vty, ... */
	ev_run(loop, 0);

	/* program will exit. waiting for all cores */
	rte_eal_mp_wait_lcore();

#ifdef APP_DEBUG_PKT_DETAILS
	printf("Got here\n");
#endif

	ev_loop_destroy(loop);

	if (!force_quit)
		do_shutdown();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
