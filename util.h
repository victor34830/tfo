/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#include <rte_common.h>


#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

static inline uint32_t
next_power_of_2(uint32_t x)
{
	return 1 << rte_fls_u32(x - 1);
}

