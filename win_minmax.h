/* SPDX-License-Identifier: GPL-3.0 */
/**
 * win_minmax.c: windowed min/max tracker by Kathleen Nichols.
 *
 */
#ifndef MINMAX_H
#define MINMAX_H

#include <stdint.h>

/* A single data point for our parameterized min-max tracker */
struct minmax_sample {
	uint32_t	t;	/* time measurement was taken */
	uint32_t	v;	/* value measured */
};

/* State for the parameterized min-max tracker */
struct minmax {
	struct minmax_sample s[3];
};

static inline uint32_t minmax_get(const struct minmax *m)
{
	return m->s[0].v;
}

static inline uint32_t minmax_reset(struct minmax *m, uint32_t t, uint32_t meas)
{
	struct minmax_sample val = { .t = t, .v = meas };

	m->s[2] = m->s[1] = m->s[0] = val;
	return m->s[0].v;
}

//uint32_t minmax_running_max(struct minmax *m, uint32_t win, uint32_t t, uint32_t meas);
uint32_t minmax_running_min(struct minmax *m, uint32_t win, uint32_t t, uint32_t meas);

#endif
