/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#ifndef _TFO_LIST_H
#define _TFO_LIST_H

/*
** tfo_list.h additional list functions
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/

#include "tfo_config.h"

#include <stdbool.h>

static inline bool
list_is_queued(struct list_head *entry)
{
	return entry->next != entry;
}

#endif	/* defined _TFO_LIST_H */
