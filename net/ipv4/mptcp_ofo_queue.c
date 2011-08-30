/*
 *	MPTCP implementation
 *       Fast algorithm for MPTCP meta-reordering
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      date : Aug 11
 *
 *      This is a binary tree of subqueues. The nodes are wrappers
 *      for either one skb or a sequence of contiguous skbuffs.
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/mptcp.h>

/* Node abstraction: The node can be interchangeably an skb or
 * a sequence of skbuffs. We thus need to distinguish them.
 * We do that with the up pointer. It is always NULL in a node,
 * and always defined in an skbuff. The parent of a node is referenced
 * in the up pointer of the first skbuff in the sequence.
 * If the node is a sequence, the sequence is always of size > 1.
 *
 * In tree mode, the next and prev pointers mean resp. the right and left
 * child.
 */
struct node {
	struct node          *next;
	struct node          *prev;
	struct node          *up;
	struct sk_buff_head  queue;
};

#define low_dsn(n)						\
	((n)->up ? TCP_SKB_CB((struct sk_buff*)(n))->data_seq :	\
	 TCP_SKB_CB(skb_peek(&(n)->queue))->data_seq)
#define high_dsn(n)							\
	((n)->up ? TCP_SKB_CB((struct sk_buff*)(n))->end_data_seq :	\
	 TCP_SKB_CB(skb_peek_tail(&(n)->queue))->end_data_seq)
#define up(n)						\
	((n)->up ? (n)->up : (struct node *)skb_peek(&(n)->queue)->up)
#define up_ptr(n)						\
	((n)->up ? &(n)->up : (struct node **)&skb_peek(&(n)->queue)->up)

#ifdef DEBUG_MPTCP_OFO_TREE
/**
 * Debugging print of the ofo tree.
 * Note that this function is recursive and may fill the stack.
 * Use with caution and _never_ enable in a production environment.
 */
void print_ofo_tree(struct node *root, int offset)
{
	char spaces[30];
	int i;

	if (!root)
		return;
	BUG_ON(offset >= sizeof(spaces));
	for (i=0; i < offset; i++)
		spaces[i]=' ';
	spaces[i]='\0';
	printk(KERN_ERR "%s [%x,%x], queue_node: %d, up: %p\n",
	       spaces, low_dsn(root),
	       high_dsn(root), (root->up ? 0 : 1), up(root));
	printk(KERN_ERR "%s left:\n", spaces);
	if (root->prev)
		print_ofo_tree(root->prev, offset+1);
	printk(KERN_ERR "%s right:\n", spaces);
	if (root->next)
		print_ofo_tree(root->next, offset+1);
}
#endif

static void free_node(struct node *n)
{
	if (n->up) {
		__kfree_skb((struct sk_buff *)n);
	} else {
		struct sk_buff *skb, *tmp;
		skb_queue_walk_safe(&n->queue, skb, tmp) {
			__skb_unlink(skb, &n->queue);
			__kfree_skb(skb);
		}
		kfree(n);
	}
}

/**
 * if @free_old != 0, the memory of old and any skbuff inside is released.
 * @post: @new has replaced @old in the tree. WARNING: @new->up is NOT set
 *       It is the responsability of the caller to set it.
 *       (reason: replace_node() may be called on a list that is still empty,
 *       which implies that the normal up pointer for the list, in the first
 *       skb cannot be set yet).
 */
static void replace_node(struct node **old, struct node *new)
{
	/* set references in new */
	new->next = (*old)->next;
	new->prev = (*old)->prev;
	/* set references in childs */
	if ((*old)->prev)
		*up_ptr((*old)->prev) = new;
	if ((*old)->next)
		*up_ptr((*old)->next) = new;
	/* set reference in parent */
	*old = new;
}

/**
 * @pre: n1 must be before n2, and one cannot fully overlap the other, but
 *       they must be contiguous or partially overlapping.
 * @aggreg: either n1 or n2, depending on which one aggregates the other.
 *          the merged node will inherit the next,prev and up pointers from
 *          @aggreg.
 * @return: The node that contains the concatenation of n1 and n2.
 */
static struct node *concat(struct node *n1, struct node *n2,
			   struct node **aggreg)
{
	struct node *old = *aggreg;
	/* Note: segment enqueing _must_ be done after replace_node()
	 * in any case, otherwise replace_node sets wrong pointers.
	 */
	if (n1->up && n2->up) {
		struct node *n;
		/* No queue yet, create one */
		n = kmalloc(sizeof(struct node), GFP_ATOMIC);
		if (!n)
			return NULL;
		n->up = NULL;
		__skb_queue_head_init(&n->queue);
		replace_node(aggreg, n);
		__skb_queue_head(&n->queue, (struct sk_buff *)n2);
		__skb_queue_head(&n->queue, (struct sk_buff *)n1);
		n1->up = up(old);
		return n;
	} else if (n1->up && !n2->up) {
		/* expand n2 queue */
		if (old == n1)
			replace_node(aggreg, n2);
		else
			n1->up = up(n2);
		__skb_queue_head(&n2->queue, (struct sk_buff *)n1);
		return n2;
	} else if (!n1->up && n2->up) {
		/* expand n1 queue */
		if (old == n2) {
			replace_node(aggreg, n1);
			*up_ptr(n1) = n2->up;
		}
		/* no need to update n2->up as it is not put on the head
		 * of the queue.
		 */
		__skb_queue_tail(&n1->queue, (struct sk_buff *)n2);
		return n1;
	} else { /* both n1 and n2 are queues */
		struct sk_buff *skb;
		/* Prune duplicated segments */
		for (skb = skb_peek_tail(&n1->queue);
		     !before(TCP_SKB_CB(skb)->data_seq,
			     TCP_SKB_CB(skb_peek(&n2->queue))->end_data_seq);
		     skb = skb_peek_tail(&n1->queue)) {
			__skb_unlink(skb, &n1->queue);
			__kfree_skb(skb);
		}

		if (old == n1)
			replace_node(aggreg, n2);
		else
			*up_ptr(n1) = up(n2);

		/* Concat the queues and store in n2.
		 */
		skb_queue_splice(&n1->queue, &n2->queue);
		kfree(n1);
		return n2;
	}
}

/**
 * After a node has been replaced in the tree, this function is called
 * to remove any node that is covered by the new one, and merge nodes that
 * are now contiguous.
 * @pre: @root must be a valid node, that is, not the absolute root
 *       of the binary tree.
 * @root: The root of the tree to be considered. Merging is considered
 *        with the child branches of @root.
 */
static void compact_tree(struct node **root)
{
	struct node *left_cand = (*root)->prev;
	struct node *right_cand = (*root)->next;
	/* Left candidate : right-most child in the left branch */
	if (left_cand) {
		while(left_cand->next)
			left_cand = left_cand->next;
	}
	/* Right candidate : left-most child in the right branch */
	if (right_cand) {
		while(right_cand->prev)
			right_cand = right_cand->prev;
	}

	/* Can left candidate be merged ? */
	while (left_cand &&
	       !before(high_dsn(left_cand), low_dsn(*root))) {
		struct node *parent = up(left_cand);
		if (parent == *root)
			parent->prev = left_cand->prev;
		else
			parent->next = left_cand->prev;
		if (left_cand->prev)
			*up_ptr(left_cand->prev) = parent;
		if (!before(low_dsn(left_cand), low_dsn(*root))) {
			struct node *tofree;
			/* The root fully covers the child */
			tofree = left_cand;
			left_cand = parent;
			while (left_cand->next)
				left_cand = left_cand->next;
			free_node(tofree);
			if (left_cand == *root)
				break;
		} else {
			/* TODO: Graceful exit in case of failed
			 * kmalloc, we cannot just stop here, as the tree
			 * is not anymore consistent. Probably we need to freeze
			 * the tree and delay the operation for a workqueue,
			 * or we are more aggressive and we reset the meta-flow.
			 */
			if (!concat(left_cand, *root, root))
				BUG();
			break;
		}

	}
	/* Can right candidate be merged ? */
	while (right_cand &&
	       !before(high_dsn(*root), low_dsn(right_cand))) {
		struct node *tofree;
		struct node *parent = up(right_cand);
		if (parent == *root)
			parent->next = right_cand->next;
		else
			parent->prev = right_cand->next;
		if (right_cand->next)
			*up_ptr(right_cand->next) = parent;
		if (!before(high_dsn(*root), high_dsn(right_cand))) {
			/* The root fully covers the child */
			tofree = right_cand;
			right_cand = parent;
			while (right_cand->prev)
				right_cand = right_cand->prev;
			free_node(tofree);
			if (right_cand == *root)
				break;
		} else {
			/* TODO: Graceful exit in case of failed
			 * kmalloc.
			 */
			if (!concat(*root, right_cand, root))
				BUG();
			break;
		}
	}
}

/**
 * @parent: The parent of the current node being considered. It is
 *          used to fill the up pointer of the root if needed.
 * @root: The address of the current root being considered, that is,
 *        either the next or prev pointer of the parent.
 */
static int mptcp_ofo_insert(struct node **root, struct sk_buff *skb,
			    struct node *parent)
{
	while(*root) {
		if (before(TCP_SKB_CB(skb)->end_data_seq, low_dsn(*root))) {
			parent = *root;
			root = &((*root)->prev);
		} else if (after(TCP_SKB_CB(skb)->data_seq, high_dsn(*root))) {
			parent = *root;
			root = &((*root)->next);
		} else {
			break;
		}
	}

	if (!*root) {
		*root = (struct node *)skb;
		skb->up = (struct sk_buff *)parent;
		skb->next = skb->prev = NULL;
		return 0;
	}

	if (!before(TCP_SKB_CB(skb)->data_seq, low_dsn(*root)) &&
	    !after(TCP_SKB_CB(skb)->end_data_seq, high_dsn(*root))) {
		/* No new information */
		return 1;
	}
	if (!after(TCP_SKB_CB(skb)->data_seq, low_dsn(*root)) &&
	    !before(TCP_SKB_CB(skb)->end_data_seq, high_dsn(*root))) {
		struct node *old = *root;
		replace_node(root, (struct node *)skb);
		skb->up = (struct sk_buff *)up(old);
		free_node(old);
		compact_tree(root);
		return 0;
	}
	if (before(TCP_SKB_CB(skb)->data_seq, low_dsn(*root))) {
		if (!concat((struct node *)skb, *root, root))
			BUG();
		compact_tree(root);
		return 0;
	}
	/* Last option, right merge */
	if (!concat(*root, (struct node *)skb, root))
		BUG();
	compact_tree(root);
	return 0;
}


/**
 * @return: 1 if the skb must be dropped by the caller, otherwise 0
 */
int mptcp_add_meta_ofo_queue(struct sock *meta_sk, struct sk_buff *skb)
{
	int ans;
	struct sk_buff_head *head = &tcp_sk(meta_sk)->out_of_order_queue;
	skb->up = (struct sk_buff *)1; /* Otherwise it is mistaken for a
					* container.
					*/
	ans = mptcp_ofo_insert(
		(struct node **)&head->next, skb, (struct node *)head);
	/* set the prev pointer as well, for easier management in
	 * mptcp_ofo_queue
	 */
	head->prev = head->next;
	return ans;
}

void mptcp_ofo_queue(struct multipath_pcb *mpcb)
{
	struct node *head =
		(struct node *)&((struct tcp_sock *)mpcb)->out_of_order_queue;
	struct node *left_most = head;
	struct sk_buff *skb;
	struct sock *meta_sk = (struct sock *)mpcb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	while (left_most->prev)
		left_most = left_most->prev;

	while(left_most != head) {
		struct node *parent = up(left_most);

		if (after(low_dsn(left_most), meta_tp->rcv_nxt))
			break;

		if (!after(high_dsn(left_most), meta_tp->rcv_nxt)) {
			struct node *tofree = left_most;
			/* Already received, can be dropped */
			parent->prev = left_most->next;
			if (left_most->next)
				*up_ptr(left_most->next) = parent;
			left_most = parent;

			while (left_most->prev)
				left_most = left_most->prev;
			free_node(tofree);
			continue;
		}

		parent->prev = left_most->next;
		if (left_most->next)
			*up_ptr(left_most->next) = parent;

		if (left_most->up) { /* simple skb */
			skb = (struct sk_buff *)left_most;
			__skb_queue_tail(&meta_sk->sk_receive_queue, skb);
			meta_tp->rcv_nxt = TCP_SKB_CB(skb)->end_data_seq;
		} else { /* queue of skbuffs */
			skb = skb_peek_tail(&left_most->queue);
			meta_tp->rcv_nxt = high_dsn(left_most);
			__skb_queue_splice(
				&left_most->queue,
				meta_sk->sk_receive_queue.prev,
				(struct sk_buff *)&meta_sk->sk_receive_queue);
			meta_sk->sk_receive_queue.qlen += left_most->queue.qlen;
			kfree(left_most);
		}
		if (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN)
			mptcp_fin(mpcb);
		break;
	}
	/* update the right member of the head as it may have changed */
	head->next = head->prev;
}

void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp)
{
	struct sk_buff_head *head = &meta_tp->out_of_order_queue;
	struct node *root = (struct node *)head->next;
	struct node *parent;

	/* Slighty strange flushing algorithm, but we do so
	 * to avoid recursion
	 */
	while(head->next) {
		while (root->prev || root->next) {
			if (root->prev)
				root = root->prev;
			if (root->next)
				root = root->next;
		}
		parent = up(root);
		if (root == parent->next)
			parent->next = NULL;
		else
			parent->prev = NULL;
		free_node(root);
		root = parent;
	}

	/* set the prev pointer as well, for easier management in
	 * mptcp_ofo_queue
	 */
	head->prev = NULL;
}
