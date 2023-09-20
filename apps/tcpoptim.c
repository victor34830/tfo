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

#define TELEMETRY_FLAG_WRITE_BUF	0x0001
#ifdef EXPOSE_EFLOW_DUMP
#define TELEMETRY_FLAG_DUMP_EFLOWS	0x0002
#endif


/* locals */
static int sigint;
static int sigterm;
static struct ev_loop *loop;
static struct ev_signal ev_sigterm;
static struct ev_signal ev_sigint;
static pthread_t initial_pthread_id;
static volatile bool force_quit;
static uint16_t burst_size = APP_DEFAULT_BURST_SIZE;
static struct rte_mempool *ack_pool[RTE_MAX_NUMA_NODES];

static unsigned port_n;
static uint16_t port_id[APP_MAX_IF];
static struct rte_ether_addr port_mac_addr[APP_MAX_IF];
static struct rte_ether_addr remote_mac_addr[APP_MAX_IF];
static uint16_t vlan_pub, vlan_priv;
static int port_pub = -1, port_priv = -1;

#ifdef APP_LOG_TIMER_SECS
static thread_local struct timespec last_ts;
#endif

/* Doesn't need to be thread_local if our impure D-space is on the right node */
static thread_local uint64_t priv_mask;
static unsigned *telemetry_flag_address[RTE_MAX_LCORE];
static thread_local unsigned telemetry_flag;


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

	for (unsigned i = 0; i < port_n; i++) {
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
telemetry_set_flag(unsigned flag)
{
	unsigned i;
	unsigned queue_count = rte_lcore_count() - 1;

	for (i = 0; i < queue_count; i++)
		*telemetry_flag_address[i] |= flag;
}

#ifdef EXPOSE_EFLOW_DUMP
static int
dump_eflows_cmd(__rte_unused const char *cmd, __rte_unused const char *params, __rte_unused struct rte_tel_data *info)
{
	telemetry_set_flag(TELEMETRY_FLAG_DUMP_EFLOWS);

	return 0;
}
#endif

static int
write_buffer_cmd(__rte_unused const char *cmd, __rte_unused const char *params, __rte_unused struct rte_tel_data *info)
{
	telemetry_set_flag(TELEMETRY_FLAG_WRITE_BUF);

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
	retval = rte_eth_macaddr_get(port, &port_mac_addr[port]);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: " RTE_ETHER_ADDR_PRT_FMT " ring_count:%d\n",
	       port, RTE_ETHER_ADDR_BYTES(&port_mac_addr[port]), ring_count);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

/*
 * everything that must be done after receiving a packet,
 * and before calling tcp optimizer function.
 */
static uint16_t
set_dir_in(int in_port, struct rte_mbuf **bufs, uint16_t nb_rx)
{
	uint16_t i;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
	uint16_t vlan_tag;

	for (i = 0; i < nb_rx; i++) {
		m = bufs[i];

		/*
		 * we must initialize mbuf private area to 0.
		 */
		memset(rte_mbuf_to_priv(m), 0x00, tfo_get_mbuf_priv_size());

		/*
		 * we have to tell tcp optimizer if packet is coming from client (priv)
		 * or server (pub).
		 * in this app, depending on command-line options used, we can deduce it
		 * from incoming port or vlan id.
		 */
		if (vlan_priv && vlan_pub) {
			eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
				vh = (struct rte_vlan_hdr *)(eh + 1);

				vlan_tag = rte_be_to_cpu_16(vh->vlan_tci);
			} else
				vlan_tag = 0;

			if (vlan_tag == vlan_priv)
				m->ol_flags |= priv_mask;
			else if (vlan_tag != vlan_pub) {
				/* discard packet */
				bufs[i] = bufs[i + 1];
				nb_rx--;
				i--;
			}
		} else if (port_priv >= 0 && port_pub >= 0) {
			if (in_port == port_priv) {
				m->ol_flags |= priv_mask;
			} else if (in_port != port_pub) {
				/* discard packet */
				bufs[i] = bufs[i + 1];
				nb_rx--;
				i--;
			}
		}
	}

	/*
	 * remember remote mac address, for each port.
	 * this app can talk to at most one remote host (ie. mac address).
	 */
	if (likely(nb_rx > 0)) {
		eh = rte_pktmbuf_mtod(bufs[0], struct rte_ether_hdr *);
		rte_ether_addr_copy(&eh->src_addr, &remote_mac_addr[in_port]);

	}

	return nb_rx;
}


/*
 * everything that must be done on tcp optimizer send packet callback,
 * and before really sending this packet on wire.
 */
static inline void
set_dir_out(struct rte_mbuf** bufs, uint16_t nb_tx, int *port_out, uint16_t vlan_out)
{
	uint16_t i;
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
#ifdef APP_DEBUG_PKT_DETAILS
	struct rte_ipv4_hdr *iph = NULL;
	struct rte_ipv6_hdr *ip6h = NULL;
#endif

	for (i = 0; i < nb_tx; i++) {
		m = bufs[i];

		/* if we're not in port pair config, output on the same
		 * port the packet came */
		if (*port_out < 0)
			*port_out = m->port;

		/* set mac address */
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		rte_ether_addr_copy(&port_mac_addr[*port_out], &eh->src_addr);
		rte_ether_addr_copy(&remote_mac_addr[*port_out], &eh->dst_addr);

		/* set vlan, if working with vlan */
		if (vlan_out) {
			if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
				/* update vlan */
				vh = (struct rte_vlan_hdr *)(eh + 1);
				vh->vlan_tci = rte_cpu_to_be_16(vlan_out);
			} else {
				/* add vlan encapsulation */
				uint8_t *p = (uint8_t *)rte_pktmbuf_prepend(m, sizeof (struct rte_vlan_hdr));

				if (unlikely(p == NULL)) {
					fprintf(stderr, "rte_pktmbuf_prepend() error\n");
					exit(2);
				}

				/* move ethernet header at the start */
				memmove(p, eh, sizeof (struct rte_ether_hdr));		// we could do sizeof - 2
				eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

				vh = (struct rte_vlan_hdr *)(eh + 1);
				vh->vlan_tci = rte_cpu_to_be_16(vlan_out);
				vh->eth_proto = eh->ether_type;

				eh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
			}

		} else {
			/* remove vlan encapsulation */
			if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
				vh = (struct rte_vlan_hdr *)(eh + 1);
				eh->ether_type = vh->eth_proto;
				memmove(rte_pktmbuf_adj(m, sizeof (struct rte_vlan_hdr)),
					eh, sizeof (struct rte_ether_hdr));
			}

		}
	}
}

static uint16_t
burst_send(void *user_data, struct rte_mbuf **bufs, uint16_t nb_tx, int to_priv)
{
	uint16_t queue_idx = (uint64_t)user_data;
	uint16_t vlan_out;
	int port_out;

	if (to_priv) {
		port_out = port_priv;
		vlan_out = vlan_priv;
	} else {
		port_out = port_pub;
		vlan_out = vlan_pub;
	}

	set_dir_out(bufs, nb_tx, &port_out, vlan_out);

#ifdef APP_LOG_ACTIONS
	printf("Number to tx %d, to port %d queue_idx %d, vlan %u\n",
	       nb_tx, port_out, queue_idx, vlan_out);
#endif

#ifndef DEBUG_CHECK_PKTS
	nb_tx = rte_eth_tx_burst(port_out, queue_idx, bufs, nb_tx);
#else
	check_packets("burst_send before rte_eth_tx_burst");
	nb_tx = rte_eth_tx_burst(port_out, queue_idx, bufs, nb_tx);
	check_packets("burst_send after rte_eth_tx_burst");
#endif
	return nb_tx;
}

static inline void
fwd_packet(uint16_t port, uint16_t queue_idx)
{
	struct rte_mbuf *bufs[burst_size];
#ifdef APP_DEBUG_PKT_DETAILS
	struct rte_eth_dev_info dev_info;
	char ifname[IF_NAMESIZE];
#endif
	struct timespec ts;
	uint16_t nb_rx;

#ifdef APP_CLEAR_RX_BUFS
	memset(bufs, 0, sizeof(bufs));
#endif
#ifdef DEBUG_CHECK_PKTS
	check_packets("fwd_packet before rte_eth_rx_burst");
#endif
	/* Get burst of RX packets */
	nb_rx = rte_eth_rx_burst(port, queue_idx, bufs, burst_size);
#ifdef DEBUG_CHECK_PKTS
	check_packets("fwd_packet after rte_eth_rx_burst");
#endif

	if (unlikely(nb_rx == 0))
		return;

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

#ifdef APP_DEBUG_DUPLICATE_MBUFS
	nb_rx = check_duplicate_mbufs(bufs, nb_rx);
	if (!nb_rx)
		return;
#endif

	nb_rx = monitor_pkts(bufs, nb_rx);
	if (!nb_rx)
		return;

	/* mark pkts as coming from 'priv' or 'pub' side */
	nb_rx = set_dir_in(port, bufs, nb_rx);

#ifdef APP_LOG_ACTIONS
	printf("\nfwd %d packet(s) from port %d, lcore %u, queue_idx %u\n",
	       nb_rx, port, rte_lcore_id(), queue_idx);
#endif

	/* give packets to tcp optimizer library  */
	tcp_worker_mbuf_burst(bufs, nb_rx, &ts);

#ifdef APP_LOG_ACTIONS
	printf("\n");
#endif
}


static void
process_timers(void)
{
	struct timespec ts;

	/* time is approx hz * seconds since boot */

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#ifdef APP_LOG_TIMER_SECS
	if (last_ts.tv_sec != ts.tv_sec)
		printf("Timer run " TIMESPEC_TIME_PRINT_FORMAT "\n", TIMESPEC_TIME_PRINT_PARAMS(ts));
	last_ts = ts;
#endif

	tfo_process_timers(&ts);

#if defined APP_LOG_TIMER_SECS || defined APP_LOG_TX_TIMER
	fflush(stdout);
#endif
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * input ports and writing to an output port.
 */
static int
lcore_main(__rte_unused void *arg)
{
	struct tfo_worker_params params;
	uint16_t queue_idx;
	uint16_t port;

	/* queue id is our lcore id. because lcore_id=0 is main, it won't run here */
	queue_idx = rte_lcore_index(rte_lcore_id()) - 1;

	printf("Core %u queue_idx %d pid %d tid %d forwarding packets. [Ctrl+C to quit]\n",
	       rte_lcore_id(), queue_idx, getpid(), gettid());

#ifdef APP_DEBUG_PKT_DETAILS
	printf("tid %d\n", gettid());
#endif

	params.params = (void *)(uint64_t)queue_idx;
	params.ack_pool = ack_pool[rte_socket_id()];
	priv_mask = tcp_worker_init(&params);

	telemetry_flag_address[queue_idx] = &telemetry_flag;

	while (!force_quit) {
		for (port = 0; port < port_n; port++)
			fwd_packet(port, queue_idx);

		process_timers();

#ifdef PQA
		usleep(1000);
#endif

		if (telemetry_flag) {
			if (telemetry_flag & TELEMETRY_FLAG_WRITE_BUF) {
				telemetry_flag &= ~TELEMETRY_FLAG_WRITE_BUF;
#ifdef DEBUG_PRINT_TO_BUF
				/* Write the circular log buffer */
				tfo_fflush_buf("Telemetry request");
#elif defined PER_THREAD_LOGS
				/* Flush any buffered log output */
				tfo_fflush(stdout);
#endif
			}

#ifdef EXPOSE_EFLOW_DUMP
			if (telemetry_flag & TELEMETRY_FLAG_DUMP_EFLOWS) {
				telemetry_flag &= ~TELEMETRY_FLAG_DUMP_EFLOWS;
				char filename[128];
				sprintf(filename, "/tmp/eflow.%u.dmp", port);
				FILE *fp = fopen(filename, "a");
				tfo_eflow_dump_fp(fp);
				fclose(fp);
			}
#endif
		}
	}

	return 0;
}

static void
print_help(const char *progname)
{
	printf("%s:\n", progname);
	printf("\t-H\t\tprint this\n");
	printf("\t-q vl_pub,vl_priv\tVlan config\n");
	printf("\t-d port_pub,port_priv\tPort config\n");
	printf("\t-e flows\tMax flows\n");
	printf("\t-f flows\tMax optimised flows\n");
	printf("\t-p bufp\t\tMax buffered packets\n");
	printf("\t-X hash\t\tFlow hash size\n");
	printf("\t-t timeouts\tport:syn,est,fin TCP timeouts (port 0 = defaults)\n");
	printf("\t-r tcp_win_rtt_wlen\ttcp_win_rtt_wlen in seconds\n");
	printf("\t-b rx burst size\tmaximum no of packets to receive at once\n");
#ifdef DEBUG_STRUCTURES
	printf("\t-a\t\tDump all eflows after processing packet\n");
#endif
#ifdef PER_THREAD_LOGS
	printf("\t-l file_name\tper thread log file template name\n");
#endif
#ifdef DEBUG_PRINT_TO_BUF
	printf("\t-P [size]\tbuffer size in Mb (default 64)\n");
	printf("\t-k\t\twrite buffer before overflow\n");
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

static void
telemetry_cmd_register(const char *cmd, telemetry_cb tele_handler, const char *help)
{
	char cmd_str[1 + strlen(PROG_NAME) + 1 + strlen(cmd) + 1];
	int ret;

	sprintf(cmd_str, "/" PROG_NAME "/%s", cmd);

	if ((ret = rte_telemetry_register_cmd(cmd_str, tele_handler, help)))
		printf("register %s command returned %d for pid %d, tid %d\n", cmd, ret, getpid(), gettid());
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool[RTE_MAX_NUMA_NODES];
	unsigned queue_count;
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
	c.tx_burst = burst_send;

	while ((opt = getopt(argc, argv, ":Hq:d:e:f:p:X:t:r:b:"
#ifdef PER_THREAD_LOGS
					 "l:"
#endif
#ifdef DEBUG_PRINT_TO_BUF
					 "P::k"
#endif
#ifdef DEBUG_STRUCTURES
					 "a"
#endif
			     )) != -1) {
		switch(opt) {
		case 'H':
			print_help(progname);
			exit(0);
			break;
		case 'q':
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
			} else {
				fprintf(stderr, "Must provide priv and pub vlan\n");
				return 1;
			}
			vlan_priv = (uint16_t)vlan0;
			vlan_pub = (uint16_t)vlan1;
			break;
		case 'd':
			vlan0 = strtol(optarg, &endptr, 10);
			if ((*endptr && endptr[0] != ',') ||
			    vlan0 < 0 || vlan0 > APP_MAX_IF) {
				fprintf(stderr, "Port '%s' invalid\n", optarg);
				break;
			}

			if (*endptr) {
				vlan1 = strtol(endptr + 1, &endptr, 10);
				if ((*endptr && endptr[0] != ',') ||
				    vlan1 < 0 || vlan1 > APP_MAX_IF) {
					fprintf(stderr, "Port '%s' invalid\n", optarg);
					break;
				}
			} else {
				fprintf(stderr, "Must provide priv and pub port\n");
				return 1;
			}
			port_priv = vlan0;
			port_pub = vlan1;
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
#ifdef DEBUG_PRINT_TO_BUF
		case 'P':
			if (!optarg && optind < argc && argv[optind][0] != '-')
				optarg = argv[optind++];
			if (optarg)
				c.print_buf_size = strtoul(optarg, NULL, 10);
			else
				c.print_buf_size = 64;
			break;
		case 'k':
			c.option_flags |= TFO_CONFIG_FL_BUFFER_KEEP;
			break;
#endif
#ifdef DEBUG_STRUCTURES
		case 'a':
			c.option_flags |= TFO_CONFIG_FL_DUMP_ALL_EFLOWS;
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

	/*
	 * Relationship between thread (worker) and port (nic card) that is
	 * chosen for this app:
	 *
	 * Each thread should have its own tx and rx queue on every port.
	 * This means that a thread reads on its own rx queue and writes to
	 * its own tx queue, and that a thread will pick data on every port.
	 *
	 * This works best with NUMA node == 1. If not, then memory will be
	 * assigned locally to port, but it is not ideal.
	 */

	/* check that there is at least 1 port available */
	port_n = rte_eth_dev_count_avail();
	if (port_n < 1)
		rte_exit(EXIT_FAILURE, "Error: should have at least 1 port\n");
	else if (port_n > APP_MAX_IF) {
		printf("Warning: only the first %d ports will be used\n", APP_MAX_IF);
		port_n = APP_MAX_IF;
	}
	if (port_n < 2 && port_priv != -1)
		rte_exit(EXIT_FAILURE, "Error: should have at least 2 ports when using pair-port config\n");

	/* number of worker thread (== lcore) */
	queue_count = rte_lcore_count() - 1;	/* number of configured lcore minus main lcore */
	if (queue_count < 1)
		rte_exit(EXIT_FAILURE, "Error: should have at least 1 worker (check -l option)\n");

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
	c.ef_n = (c.ef_n + queue_count - 1) / queue_count;
	c.f_n = (c.f_n + queue_count - 1) / queue_count;
	c.p_n = (c.p_n + queue_count - 1) / queue_count;

#ifdef APP_DEBUG_PKT_DETAILS
	printf("vlan priv %d pub %d\n", vlan_priv, vlan_pub);
#endif

	/* Creates mempools to hold the mbufs. */
	for (i = 0, next_port_id = 0; i < port_n; i++) {
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

	/* initialize our ports. */
	for (i = 0; i < port_n; i++) {
		socket = rte_eth_dev_socket_id(port_id[i]);
		if (port_init(port_id[i], mbuf_pool[socket], queue_count) != 0)
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

	/* Register the telemetry commands */
	telemetry_cmd_register("shutdown", shutdown_cmd, "Shuts down " PROG_NAME);
	telemetry_cmd_register("write_buffer", write_buffer_cmd, "Write log buffers");
#ifdef EXPOSE_EFLOW_DUMP
	telemetry_cmd_register("dump_eflows", dump_eflows_cmd, "Dump eflows");
#endif

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
