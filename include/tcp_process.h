/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#ifndef TFO_PROCESS_H_
#define TFO_PROCESS_H_

#include "tfo_config.h"

#include <stdint.h>

#include <rte_mbuf.h>


extern uint16_t monitor_pkts(struct rte_mbuf **, uint16_t);

#endif
