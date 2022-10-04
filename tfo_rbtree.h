/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
**
** tfo_rbtree.h for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**	   based on Linux Documentation/core-api/rbtree.rst
**
*/

#ifndef _TFO_RBTREE_H
#define _TFO_RBTREE_H

#include <stdbool.h>

#include "linux_rbtree.h"
#include "tfo_worker_types.h"

/* The current design is for one timer per eflow, although this could be increased
 * to one timer per eflow and one timer per side.
 *
 * The eflow needs a timer for no packets transferred, since it also times out
 * a no-response to a SYN packet, when no flow (and hence tfo_sides) are allocated.
 *
 * The tfo_sides use two timers. One is for PTO, RTO, ZW, REO, KEEPALIVE (and
 * SHUTDOWN), the other is for delayed acks.
 *
 * Using only one timer per eflow reduces the size of the rb tree, but means more
 * code needs to execute to calculate the next timeout, and also, when a timeout
 * occurs which timeout it is. This could be alleviated by extending struct timer_rb_node
 * to include a timer type (NO_DATA, PRIV_TMO, PUB_TMO, PRIV_DELAY_ACK, PUB_DELAY_ACK).
 *
 * It might be that after the initial implementation, we modify the code to add timer type,
 * and/or two timers per tfo_side (if the latter then timer_type is not needed).
 *
 * It could be that after the eflow is allocated, the private side handles the no data timer,
 * since it will be the lesser of the KEEPALIVE timer and the to_est.
 *
 * We need to ensure that keepalives do not reset the last_use timer. The solution to this is
 * to only update the timer if new data is received.
 */

struct timer_rb_node {
	struct rb_node node;
	time_ns_t time;
};

// Can we use rb_find()?
static inline struct timer_rb_node *
timer_search(struct rb_root_cached *root, time_ns_t time)
{
	struct rb_node *node = root->rb_root.rb_node;

	while (node) {
		struct timer_rb_node *data = container_of(node, struct timer_rb_node, node);

		if (time < data->time)
			node = node->rb_left;
		else if (time > data->time)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

/*
 * Inserting data into an rbtree
 * -----------------------------
 *
 * Inserting data in the tree involves first searching for the place to insert the
 * new node, then inserting the node and rebalancing ("recoloring") the tree.
 *
 * The search for insertion differs from the previous search by finding the
 * location of the pointer on which to graft the new node.  The new node also
 * needs a link to its parent node for rebalancing purposes.
 */

// Can we use rb_add_cached()? Will it inline the less() function?
static inline void
timer_insert(struct rb_root_cached *root, struct timer_rb_node *data)
{
	struct rb_node **new = &(root->rb_root.rb_node), *parent = NULL;
// Isn't leftmost just:
//   parent == root->rb_leftmost && new == parent->rb_left
	bool leftmost = true;

	/* Figure out where to put new node */
	while (*new) {
		struct timer_rb_node *this = container_of(*new, struct timer_rb_node, node);

		parent = *new;
		if (data->time < this->time)
			new = &((*new)->rb_left);
		else {
			new = &((*new)->rb_right);
			leftmost = false;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color_cached(&data->node, root, leftmost);
}

#endif
