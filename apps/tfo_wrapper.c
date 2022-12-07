/*
** tfo_wrapper.c for tcp flow optimizer
**
** Author: Olivier Gournet <ogournet@freebox.fr>
**
**	This program is part of the Freebox product line,
**	all right reserved to Freebox SA.
**
** Copyright (C) 2021, 2022 Freebox SA.
*/


#include "tfo_options.h"
#include "tfo_app_options.h"

#ifdef HAVE_FREE_HEADERS
#include <fmutils.h>
#include <fmlog.h>
#include <fmcfg.h>
#include <libfbxrbtree.h>

#include "fn_app.h"
#include "fn_capture.h"
#include "fn_ip_frag.h"
#include "fn.h"
#endif

#if 0
#include "free_funcs.h"
#include "tfo.h"
#include "util.h"
#else
//================================================================================
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <ev.h>

#if free_funcs
#include <fmutils.h>
#include <fmlog.h>
#include <fmcfg.h>
#include <libfbxrbtree.h>
#endif

#include "linux_list.h"

#ifdef free_funcs
#include "fn_app.h"
#include "fn_capture.h"
#include "fn_ip_frag.h"
#include "fn.h"
#endif
#include "tfo.h"
#include "tfo_worker.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>

#include <ev.h>

#include "util.h"
#endif
// ================================================================================

/* globals */
struct tfo_module *g_tfo;

/* locals */
static struct fmlog *log;
static struct ev_timer msg_timer;
static struct {			// PQA added
	int fastpath_time;
} *g_p;
static struct {			// PQA added
	struct fmlog_ctx *log_ctx;
	struct ev_loop *loop;
} *fnp;

static uint64_t in_priv_mask;


static void
_capture_output_packet(void *param, struct tfo_pkt_in *p, int from_priv)
{
	struct tfo_worker *w = param;
#ifdef free_funcs
	struct fn_capture *capt[4];
	uint32_t capt_n = 0;
	int side1, side2;

	if (from_priv) {
		side1 = FN_CAPTURE_F_PRIV;
		side2 = FN_CAPTURE_F_PUB;
	} else {
		side1 = FN_CAPTURE_F_PUB;
		side2 = FN_CAPTURE_F_PRIV;
	}

	if (p->ip6h != NULL) {
		fn_capture_addr_v6_get(&w->pcap, side1,
				       FN_CAPTURE_PUB_INTF, &p->ip6h->ip6_src,
				       capt, &capt_n, ARRAY_SIZE(capt));
		fn_capture_addr_v6_get(&w->pcap, side2,
				       FN_CAPTURE_PUB_INTF, &p->ip6h->ip6_dst,
				       capt, &capt_n, ARRAY_SIZE(capt));
	} else if (p->ip4h != NULL) {
		fn_capture_addr_v4_get(&w->pcap, side1,
				       FN_CAPTURE_PUB_INTF, p->ip4h->src_addr,
				       capt, &capt_n, ARRAY_SIZE(capt));
		fn_capture_addr_v4_get(&w->pcap, side2,
				       FN_CAPTURE_PUB_INTF, p->ip4h->dst_addr,
				       capt, &capt_n, ARRAY_SIZE(capt));
	}

	if (unlikely(capt_n > 0))
		fn_pipe_output_capture_next(g_tfo->a, w->aw.id, capt, capt_n,
					    &p->tv);
#endif
}

/* capture input tcp packet */
static void
_capture_input_packet(void *param, struct tfo_pkt_in *p, int from_priv)
{
	int side1, side2;
	int intf;
	struct tfo_worker *w = param;

	if (from_priv) {
		side1 = FN_CAPTURE_F_PRIV;
		side2 = FN_CAPTURE_F_PUB;
		intf = FN_CAPTURE_PRIV_INTF;
	} else {
		side1 = FN_CAPTURE_F_PUB;
		side2 = FN_CAPTURE_F_PRIV;
		intf = FN_CAPTURE_PUB_INTF;
	}

#ifdef free_funcs
	if (p->ip6h != NULL) {
		fn_capture_addr_v6(&w->pcap, side1, p->m, &p->tv,
				   intf, &p->ip6h->ip6_src);
		fn_capture_addr_v6(&w->pcap, side2, p->m, &p->tv,
				   intf, &p->ip6h->ip6_dst);
	} else if (p->iph != NULL) {
		fn_capture_addr_v4(&w->pcap, side1, p->m, &p->tv,
				   intf, p->ip4h->src_addr);
		fn_capture_addr_v4(&w->pcap, side2, p->m, &p->tv,
				   intf, p->ip4h->dst_addr);
	}
#endif
}

static void
tfo_wrapper_process_burst(struct tfo_worker *w, uint32_t nb_rx)
{
	struct rte_mbuf *m;
	struct tfo_tx_bufs tx_bufs = { .nb_tx = 0, .nb_inc = 16 };
	int r, from_priv;
	uint32_t k;
	uint16_t u;

	for (k = 0; k < nb_rx; k++) {
		m = w->aw.in_mbuf.mb[k];
		from_priv = fn_mbuf_flags(m) & FN_MBUF_UFL_FROM_PRIV;

		tcp_worker_mbuf_in(m, from_priv, &w->ts, &tx_bufs);
//		fn_pkt_stat_inc(&w->aw, r, from_priv);

// Should forward if TFO_PKT_NO_RESOURCE
//		if (likely(r == FN_PKT_FORWARDED ||
//			   r == TFO_PKT_NOT_TCP)) {
		if (likely(tx_bufs.nb_tx)) {
			for (u = 0; u < tx_bufs.nb_tx; u++)
				fn_pipe_output(g_tfo->a, w->aw.id, -1, tx_bufs.m[u]);
// Drop all cached data
		} else {
			rte_pktmbuf_free(m);
		}

		if (tx_bufs.m)
			rte_free(tx_bufs.m);
	}
}

static void
tfo_worker_process_msg(struct tfo_worker *w)
{
	uint8_t buf[2000];
	uint16_t size = sizeof (buf);
	int t;

	while ((t = fn_msg_dequeue(w->aw.msg_in, buf, &size)) >= 0) {
		switch (t) {
		case FN_MSG_CAPTURE_ADDR:
			fn_capture_addr_msg(&w->pcap, (void *)buf);
			break;
		case FN_MSG_CAPTURE_DEBUG:
			fn_capture_debug_msg(&w->pcap, (void *)buf);
			break;
		case FN_MSG_CAPTURE_DUMP:
			fn_capture_vty_dump(&w->pcap, (void *)buf);
			break;
		default:
			debug_fun(log, "unhandled message (0x%x)", t);
			break;
		}

		size = sizeof (buf);
	}
}


/*
 * run every 2ms or 5ms.
 * do not spend more than 1ms here
 */
static void
tfo_worker_slow_path(struct tfo_worker *w)
{
#ifdef TFO_UNDER_TEST
	tfo_self_test(w, fnp->test_id);
#endif

	tfo_worker_process_msg(w);

	/* eflow garbage collection */
	w->ns = w->aw.t->ns;
	w->ts = w->aw.t->ts;
// **** This needs updating to match tfooptim.c
	tfo_garbage_collect(w->ts.tv_sec & 0xffff, NULL);
}

// Somewhere we need to timeout connections.
// SYN followed by ACK - we only see one side
// SYN,ACK without SYN - we only see one side
// PQA - SYN,ACK without SYN we just pass data transparently
// SYN followed by data (i.e. no SYN,ACK) do likewise - we need to timeout SYN if no data.
// SYN followed by RST - connection refused
//
// Principle must be that if it is not in normal sequence, we just forward it.

/*
 * run every seconds
 */
static void
tfo_worker_periodic(struct tfo_worker *w)
{
	fn_capture_worker_periodic(&w->pcap);
}

static void
tfo_msg_dequeue(struct ev_loop *loop, struct ev_timer *wt, int revents)
{
	struct fn_app *a = g_tfo->a;
	struct tfo_worker *w;
	struct fn_msg_vty *cmd;
	uint8_t buf[2000];
	uint16_t size = sizeof (buf);
	unsigned wid;
	int t;

	/*
	 * dequeue messages from other application
	 */
	while ((t = fn_msg_dequeue(a->msg_in, buf, &size)) >= 0) {
		switch (t) {
		case FN_MSG_CAPTURE_ADDR:
		{
			struct fn_capture_addr_msg *cmd = (void *)buf;

			if (cmd->type == FN_CAPTURE_F_PRIV) {
				if (cmd->addr.family == AF_INET) {
					uint32_t addr =
						ntohl(cmd->addr.sin.sin_addr.s_addr);
					wid = fn_addr_index(addr, a->w_n);
				} else {
					wid = fn_addr6_index(0,
							     &cmd->addr.sin6.sin6_addr,
							     a->w_n);
				}
				fn_msg_enqueue(a->w[wid]->msg_in, t,
					       cmd, sizeof (*cmd));
			} else {
				for (wid = 0; wid < a->w_n; ++wid) {
					fn_msg_enqueue(a->w[wid]->msg_in, t,
						       cmd, sizeof (*cmd));
				}
			}
			break;
		}

		case FN_MSG_CAPTURE_DEBUG:
			/* forward command to all workers */
			for (wid = 0; wid < a->w_n; ++wid)
				fn_msg_enqueue(a->w[wid]->msg_in, t, buf, size);
			break;

		case FN_MSG_CAPTURE_DUMP:
			cmd = (struct fn_msg_vty *)buf;
			wid = cmd->param32[0];
			if (cmd->param32[0] >= a->w_n)
				wid = 0;
			fn_msg_enqueue(a->w[wid]->msg_in, t, buf, size);
			break;

		default:
			debug_fun(log, "unhandled message (0x%x)", t);
			break;
		}

		size = sizeof (buf);
	}

	/*
	 * dequeue message from tfo workers
	 */
	for (wid = 0; wid < a->w_n; wid++) {
		w = g_tfo->w[wid];
		while ((t = fn_msg_dequeue(w->aw.msg_out, buf, &size)) >= 0) {
			switch (t) {
			case FN_MSG_VTY_DONE:
				fn_vty_deferred_dump_done((void *)buf);
				break;
			case FN_MSG_STOP_RUNNING:
				fn_stop_running();
				break;
			default:
				debug_fun(log, "unhandled worker msg "
					  "(0x%x)", t);
				break;
			}

			size = sizeof (buf);
		}
	}
}

// When we start up/reload, we can't hook into existing connections

static void
tfo_reload(struct tcp_config *c, struct fmcfg *cfg)
{
	int def_est, def_syn, def_fin;
	const char *k;
	uint16_t v;
	int i;

	def_est = fmcfg_lookup_int_opt(cfg, "tcp.established", 600);
	def_syn = fmcfg_lookup_int_opt(cfg, "tcp.connecting", 120);
	def_fin = fmcfg_lookup_int_opt(cfg, "tcp.closing", 60);

	c->max_port_to = 0xffff;
	c->tcp_to = malloc(((int)c->max_port_to + 1) * sizeof(*c->tcp_to));

	for (i = 0; i <= UINT16_MAX; i++) {
		c->tcp_to[i].to_est = def_est;
		c->tcp_to[i].to_syn = def_syn;
		c->tcp_to[i].to_fin = def_fin;
	}

#ifdef free_funcs
	if (fmcfg_push(cfg, "tcp")) {
		for (fmcfg_hash_start(cfg); fmcfg_hash_next(cfg); ) {
			k = fmcfg_hash_key(cfg);
			v = fmcfg_hash_int(cfg);
			if (v)
				fn_parse_port_string(k, c->tcp_to, v);
// What about to_syn and to_fin ?
		}
	}
	fmcfg_pop(cfg);
#endif
}

// Need a tfo_shutdown:
// 1. Pass new requests transparently
// 2. Stop initiating ACKs
// 3. When ACKs on receive sides have caught up with what we have acked, drop out of connection
// 4. ? timeout
static int
tfo_init(struct fn_app *a, struct fmcfg *cfg)
{
	struct tfo_module *d;
	struct tcp_config c;

	c.capture_input_packet = _capture_input_packet;
	c.capture_output_packet = _capture_output_packet;
	c.fastpath_time = g_p->fastpath_time;

	log = fmlog_add_module(fnp->log_ctx, "tfo");

	d = g_tfo = calloc(1, sizeof (*g_tfo));
	d->a = a;

	/* packet capture */
	d->pcap = fn_capture_init(fnp->loop, fnp->log_ctx, cfg);
	fn_capture_addr_register(d->pcap);
	fn_capture_debug_register(d->pcap);

	/* alloc and init workers */
	d->w = malloc(a->w_n * sizeof (struct tfo_worker *));

	c.ef_n = fmcfg_lookup_int_opt(cfg, "tfo.flow_max", 10000);
	c.f_n = fmcfg_lookup_int_opt(cfg, "tfo.optimized_flow_max", 10000);
	c.p_n = fmcfg_lookup_int_opt(cfg, "tfo.buffered_pkt_max", c.f_n * 10);
	c.tcp_keepalive_time = fmcfg_lookup_int_opt(cfg, "tfo.keepalive_time", c.f_n * 7200);
	c.tcp_keepalive_probes = fmcfg_lookup_int_opt(cfg, "tfo.keepalive_probes", c.f_n * 9);
	c.tcp_keepalive_intvl = fmcfg_lookup_int_opt(cfg, "tfo.keepalive_interval", c.f_n * 75);

	/* Share between workers */
	c.ef_n = (c.ef_n + a->w_n - 1) / a->w_n;
	c.f_n = (c.f_n + a->w_n - 1) / a->w_n;
	c.p_n = (c.p_n + a->w_n - 1) / a->w_n;

	c.hef_n = fmcfg_lookup_int_opt(cfg, "tfo.flow_hash_size", c.ef_n);
	c.hef_n = next_power_of_2(c.hef_n);
	c.hef_mask = c.hef_n - 1;

	tfo_reload(&c, cfg);

	tcp_init(&c);

	in_priv_mask = c.dynflag_in_priv_mask;

	/* dequeue messages */
	ev_timer_init(&msg_timer, &tfo_msg_dequeue, 0, 0.005);
	ev_timer_start(fnp->loop, &msg_timer);

	return 0;
}

static int
tfo_worker_init(void)
{
	struct tfo_module *d = g_tfo;
	struct tfo_worker *w;
	struct tfo_worker_params params;
	int i;

	i = rte_lcore_index(-1);

	if (i == -1) {
		// Disaster
		return -1;
	}

	w = malloc(sizeof (struct tfo_worker));
	g_tfo->w[i] = w;
	g_tfo->a->w[i] = &w->aw;
	fn_capture_worker_init(d->pcap, &w->pcap, i);

	params.params = w;
	params.public_vlan_tci = 0;
	params.private_vlan_tci = 1;

	tcp_worker_init(&params);
}

static void
tfo_release(void *ud)
{
	struct tfo_module *d = ud;
	int i;

#ifdef free_funcs
	fn_capture_release(d->pcap);
#endif
	for (i = 1; i < d->a->w_n; i++)
		free(d->w[i]);
	free(d->w);
	free(d);

	g_tfo = NULL;
}


static struct fn_pkt_stat tfo_pkt[TFO_PKT_STAT_MAX] = {
	[TFO_PKT_NOT_TCP] = { "not tcp", FN_PKT_FORWARDED, true },
	[TFO_PKT_NO_RESOURCE] = { "alloc failed", FN_PKT_DROPPED, true },
};

#ifdef free_funcs
static const struct fn_app_config tfo_app_decl = {
	.name = "tfo",
	.worker_process_pkt = (appcfg_worker_process_pkt_t)&tfo_wrapper_process_burst,
	.worker_slow_path = (appcfg_worker_slow_path_t)&tfo_worker_slow_path,
	.worker_periodic = (appcfg_worker_periodic_t)&tfo_worker_periodic,
	.init = tfo_init,
	.worker_init = tfo_worker_init,
	.release = tfo_release,
	//.reload = (appcfg_reload_t)&tfo_reload,
	.vty_install = tfo_vty_install,
	.st_pkt_n = TFO_PKT_STAT_MAX,
	.st_pkt = tfo_pkt,
};


__attribute__((constructor))
static void tfo_register(void)
{
	fn_app_register(&tfo_app_decl);
}

__attribute__((destructor))
static void tfo_unregister(void)
{
	fn_app_unregister(&tfo_app_decl);
}
#endif
