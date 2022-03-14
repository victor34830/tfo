/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#ifndef _FREE_FUNCS_H_
#define _FREE_FUNCS_H_

#include <ev.h>
#include <rte_build_config.h>
#include <rte_ip.h>
#include <netinet/in.h>

#define FN_PKT_STATE_BASE_MAX	23

#define MAX_WORKERS	RTE_MAX_LCORE

typedef enum node {
	NODE_NONE,
	TFO_NODE,
} node_t;

enum stat_type {
	FN_PKT_INVALID,
	FN_PKT_FORWARDED,
	FN_PKT_DROPPED,
	FN_PKT_STAT_BASE_MAX
};

enum fn_msg_cmd {
	FN_MSG_CAPTURE_ADDR,
	FN_MSG_CAPTURE_DEBUG,
	FN_MSG_CAPTURE_DUMP,
	FN_MSG_VTY_DONE,
	FN_MSG_STOP_RUNNING,
};

enum fn_msg_type {
	FN_CAPTURE_F_PRIV,
	FN_CAPTURE_F_PUB,
};

enum fn_intf_type {
	FN_CAPTURE_PUB_INTF,
	FN_CAPTURE_PRIV_INTF,
};

/* fn_mbuf_flags bits */
#define FN_MBUF_UFL_FROM_PRIV	0x01

/* The following is probably using an mbuf dynamic flag (see rt_mbuf_dyn.h) */
#define fn_mbuf_flags(m)	0

typedef unsigned fn_id_t;

struct cmd_node {
	int node;
	const char *prompt;
	int vtysh;
};

struct vty_cmd {
	int (*func)(int, char **);
	const char *cmd;
	const char *format_str;
};

struct vty {
};

#define CMD_SUCCESS	0

#define DEFUN(a,b,cmd,format) \
	struct vty_cmd b = { a, cmd, format }; \
	static int a(struct vty *vty, int argc, char **argv)

typedef void (*app_loop_t)(void);
struct fn_ptrs {
	uint32_t test_id;
        void (*log_ctx)(void);
        app_loop_t loop;
};

struct fmcfg {
};

struct fmlog {
};

struct fmlog_ctx {
};

struct fn_pkt_stat {
	const char *name;
	enum stat_type stat;
	bool enabled;
};

struct fn_app_mbuf {
	struct rte_mbuf** mb;
};

struct fn_app_t {
	uint64_t	ns;
        struct timespec	ts;
};

struct fn_msg {
};

struct fn_app_worker {
	fn_id_t id;
	struct fn_app_t	*t;
	struct fn_app_mbuf in_mbuf;
	struct fn_msg	*msg_in;
	struct fn_msg	*msg_out;
};

struct fn_app {
	fn_id_t			w_n;    /* Number of workers */
	struct fn_app_worker	*w[MAX_WORKERS];
	struct fn_msg	*msg_in;
};

struct fn_capture_ctx {
};

struct fn_capture_worker {
};

struct fn_capture_addr_msg {
	uint8_t type;
	struct {
		uint8_t family;
		union {
			struct {
				struct in_addr sin_addr;
			} sin;
			struct {
				struct in6_addr sin6_addr;
			} sin6;
		};
	} addr;
};

struct fn_msg_vty {
	uint32_t	param32[2];
};

typedef void (*appcfg_worker_process_pkt_t)(void *, uint32_t);
typedef void (*appcfg_worker_slow_path_t)(void *);
typedef void (*appcfg_worker_periodic_t)(void *);
typedef void (*appcfg_init_t)(struct fn_app *, struct fmcfg *);
typedef void (*appcfg_reload_t)(void *, struct fmcfg *);
typedef void (*appcfg_release_t)(void *);

struct fn_app_config {
	const char *name;
	appcfg_worker_process_pkt_t *worker_process_pkt;
	appcfg_worker_slow_path_t *worker_slow_path;
	appcfg_worker_periodic_t *worker_periodic;
	appcfg_init_t init;
	appcfg_release_t release;
	appcfg_reload_t reload;
	void (*vty_install)(void);
	unsigned st_pkt_n;
	struct fn_pkt_stat *st_pkt;
};

extern void install_element_ve(struct vty_cmd *);
extern void install_node(struct cmd_node *, void *);
extern void fn_pipeline_vty_install_worker(node_t);
extern void install_element(node_t, struct vty_cmd *);
extern void fn_capture_addr_vty_install(const char *, node_t);
extern void fn_capture_debug_vty_install(const char *, node_t);
extern size_t vty_out(struct vty *, const char *format_str, ...);

static inline void debug_fun(struct fmlog *log, const char *fmt, ...) __attribute__((format (printf, 2, 3)));
static inline void
debug_fun(struct fmlog *log, const char *fmt, ...)
{
}

static inline int
fmcfg_lookup_int_opt(struct fmcfg *cfg, const char *name, int def_val)
{
	return def_val;
}

static inline int
fmcfg_push(struct fmcfg *cfg, const char *name)
{
	return 0;
}

static inline int
fmcfg_hash_start(struct fmcfg *cfg)
{
	return 0;
}

static inline int
fmcfg_hash_next(struct fmcfg *cfg)
{
	return 0;
}

static inline const char *
fmcfg_hash_key(struct fmcfg *cfg)
{
	return 0;
}

static inline int
fmcfg_hash_int(struct fmcfg *cfg)
{
	return 0;
}

static inline void
fmcfg_parse_port_string(const char *k, uint16_t *arr, uint16_t v)
{
}

static inline void
fmcfg_pop(struct fmcfg *cfg)
{
}

static inline struct fmlog *
fmlog_add_module(struct fmlog_ctx *ctx, const char *name)
{
}

static inline struct fn_capture_ctx *
fn_capture_init(struct ev_loop *loop, struct fmlog_ctx *ctx, struct fmcfg *cfg)
{
}

static inline void
fn_capture_worker_init(struct fn_capture_ctx *pcap, struct fn_capture_worker *pcap_w, unsigned wid)
{
}

static inline void
fn_capture_worker_periodic(struct fn_capture_worker *pcap_w)
{
}

static inline void
fn_msg_enqueue(struct fn_msg *msg_q, int t, void *buf, size_t size)
{
}

static inline int
fn_msg_dequeue(struct fn_msg *msg_q, uint8_t *buf, uint16_t *size)
{
	return *size;
}

static inline void
fn_capture_addr_msg(struct fn_capture_worker *pcap_w, void *buf)
{
}

static inline void
fn_capture_debug_msg(struct fn_capture_worker *pcap_w, void *buf)
{
}

static inline void
fn_capture_vty_dump(struct fn_capture_worker *pcap_w, void *buf)
{
}

static inline void
fn_vty_deferred_dump_done(void *buf)
{
}

static inline void
fn_stop_running(void)
{
}

static inline void
fn_capture_addr_register(struct fn_capture_ctx *pcap)
{
}

static inline void
fn_capture_debug_register(struct fn_capture_ctx *pcap)
{
}

static inline void
fn_capture_release(struct fn_capture_ctx *pcap)
{
}

static inline int
fn_ipv6_strip_header(struct rte_ipv6_hdr *hdr, size_t len, uint8_t *proto, struct ip6_frag *frag)
{
	return len;
}

static inline bool
fn_pipe_output(struct fn_app *a, fn_id_t id, int unknown, struct rte_mbuf *m)
{
	return true;
}

static inline void
fn_pkt_stat_inc(struct fn_app_worker *w, int r, int from_priv)
{
}

static inline unsigned
fn_addr_index(uint32_t addr, fn_id_t w_n)
{
	return addr % w_n;
}

static inline unsigned
fn_addr6_index(uint32_t offs, struct in6_addr *addr, fn_id_t w_n)
{
	return addr->s6_addr32[offs] % w_n;
}

#endif	/* defined _FREE_FUNCS_H_ */
