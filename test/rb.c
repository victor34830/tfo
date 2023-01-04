#include <stdio.h>
#include "include/linux_rbtree.h"

struct ent {
	struct rb_node node;
	unsigned val;
};

struct rb_root_cached root;

#define NUM_ENTS 10
struct ent ents[NUM_ENTS];

static inline bool
less(struct rb_node *node_a, const struct rb_node *node_b)
{
	return container_of(node_a, struct ent, node)->val < const_container_of(node_b, struct ent, node)->val;
}

static void
print_tree(struct rb_node *node)
{
	if (node->rb_left)
		print_tree(node->rb_left);
	printf("val %u\n", container_of(node, struct ent, node)->val);
	if (node->rb_right)
		print_tree(node->rb_right);
}

static void
print_array(void)
{
	unsigned i;

	printf("root node %p first %p\n", root.rb_root.rb_node, root.rb_leftmost);
	for (i = 0; i < NUM_ENTS; i++) {
		printf("[%u]: addr %p l %p p %p r %p\n", i, &ents[i].node, ents[i].node.rb_left, rb_parent(&ents[i].node), ents[i].node.rb_right);
	}
}

int main(int argc, char **argv)
{
	unsigned i;

	for (i = 0; i < NUM_ENTS;i++) {
		ents[i].val = i * 2;
		RB_CLEAR_NODE(&ents[i].node);

		rb_add_cached(&ents[i].node, &root, less);
	}

	print_array();
	print_tree(root.rb_root.rb_node);

	rb_erase_cached(&ents[3].node, &root);
	printf("\nleft %p, right %p\n\n", ents[3].node.rb_left, ents[3].node.rb_right);

	print_array();
	print_tree(root.rb_root.rb_node);

	ents[3].val = 15;
	rb_add_cached(&ents[3].node, &root, less);

	print_array();
	print_tree(root.rb_root.rb_node);
}
