/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** tfo_printf.h for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/


#ifndef TFO_PRINTF_H_
#define TFO_PRINTF_H_

#include "tfo_config.h"

#include <stdbool.h>
#include <stddef.h>


extern void tfo_printf_init(size_t, bool);
extern int tfo_printf(const char *, ...) __attribute__((format (printf, 1, 2)));
extern int tfo_fprintf(FILE *fp, const char *, ...) __attribute__((format (printf, 2, 3)));
extern void tfo_printf_dump(const char *);


/* The definition needs to follow the declarations above */
#define printf(...)		tfo_printf(__VA_ARGS__)
#define fprintf(_FP, ...)	tfo_fprintf(_FP, ##__VA_ARGS__)

#endif
