/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#ifndef _TFO_WORKER_H
#define _TFO_WORKER_H

#include "tfo.h"

#include <rte_mbuf_core.h>
#include <sys/time.h>


struct tfo_tx_bufs {
	struct rte_mbuf **m;
	uint16_t nb_tx;
	uint16_t max_tx;
	uint16_t nb_inc;
};

extern struct tfo_tx_bufs *tcp_worker_mbuf_burst(struct rte_mbuf **, uint16_t, struct timespec *, struct tfo_tx_bufs *);
extern struct tfo_tx_bufs *tcp_worker_mbuf_in(struct rte_mbuf *, int, struct timespec *, struct tfo_tx_bufs *);
extern void tfo_garbage_collect(uint16_t, struct tfo_tx_bufs *);
extern uint64_t tcp_worker_init(struct tfo_worker_params *);
extern void tcp_init(const struct tcp_config *);
extern uint16_t tfo_max_ack_pkt_size(void);

#endif	/* !defined _TFO_WORKER_H */
