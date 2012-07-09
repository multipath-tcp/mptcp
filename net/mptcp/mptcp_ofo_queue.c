/*
 *	MPTCP implementation - Fast algorithm for MPTCP meta-reordering
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	TODO - update these comments
 *
 *      This is a binary tree of subqueues. The nodes are wrappers
 *      for either one skb or a sequence of contiguous skbuffs.
 *
 *      Goals:
 *      -We want to minimize the number of required pointers
 *      -We want to minimize the number of memory allocations
 *
 *      How this is achieved:
 *      -skb and nodes can be used interchangeably, the first three
 *       fields (next,prev,up) are the same in skb and nodes
 *      -A node needs to be alloc'ed. This is done only when we need
 *       to store several skbuffs in it. Otherwise the node is the skbuff
 *      -Sometimes we need to know whether a node is a struct node or
 *       an skbuff, but we don't want an additional pointer:
 *       ==a node is a struct node iff its up pointer is NULL==
 *       In that case the node _always_ contains at least two skbuffs,
 *       and the parent pointer (up) is stored in the up field of the
 *       first skbuff in the list. The up() macro hides that complexity.
 *      -Since this is a binary search tree, the semantics of next/prev pointers
 *       is changed:
 *       (i) when an skbuff is in the list of a struct node, its up pointer can
 *       be anything, and has meaning only for the head skb of the list.
 *       next/prev have the usual meaning and normal list handling functions
 *       are used.
 *       (ii) when an skbuff is used as a tree node, up is the parent node,
 *       prev is the left child, and next is the right child.
 *      -When moving inside the tree, we use double pointers. This allows
 *       easy replacement of child pointer. Should we use simple pointers,
 *       we would need to figure out whether we need to update the right or left
 *       pointer of the parent, and that would cost additional if statements.
 *
 *      WARNING: when touching this file, there is one thing to be careful with:
 *      Any modification to a struct node (that is, containing a list of
 *      skbuffs), must be done in a way that ensures the _head_ of the list has
 *      an up pointer to the correct parent. That is, any change of the head
 *      must ensure that the new head holds the correct pointer.
 *      Note that sometimes no up update is needed, i.e. when the skb set as the
 *      new head is known to already have the correct up pointer.
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/skbuff.h>
#include <linux/slab.h>
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
struct mptcp_node {
	struct mptcp_node          *next;
	struct mptcp_node          *prev;
	short                is_node;
	struct sock          *shortcut_owner; /* Owner of a shortcut pointer
					       * to this skb. Used by the
					       * out-of-order BST
					       */
	struct sk_buff_head  queue;
};

struct kmem_cache *node_cache;

static u32 low_dsn(struct mptcp_node *n)
{
	if (n->is_node)
		return TCP_SKB_CB(skb_peek(&n->queue))->seq;
	else
		return TCP_SKB_CB((struct sk_buff *)n)->seq;
}

static u32 high_dsn(struct mptcp_node *n)
{
	if (n->is_node)
		return TCP_SKB_CB(skb_peek_tail(&n->queue))->end_seq;
	else
		return TCP_SKB_CB((struct sk_buff *)n)->end_seq;
}

/* shortcut operations
 * invariant1: There is always a one-one relationship between
 *       a shortcut and its owner.
 * invariant2: An skb located in a node sequence is _never_ involved in a
 *      shortcut relationship (its container node is involved instead).
 * Policy: The case we optimize here is when a sequence of segments from
 *      a given sock arrive at the same node. For this reason, when we come
 *      to merging nodes, we just drop the shortcut.
 */

static void move_shortcut(struct mptcp_node *n_src, struct mptcp_node *n_dst)
{
	/* if n_dst has a shortcut, drop it */
	if (n_dst->shortcut_owner)
		tcp_sk(n_dst->shortcut_owner)->mptcp->shortcut_ofoqueue = NULL;
	if (n_src->shortcut_owner) {
		tcp_sk(n_src->shortcut_owner)->mptcp->shortcut_ofoqueue =
			(struct sk_buff *)n_dst;
		n_dst->shortcut_owner = n_src->shortcut_owner;
		n_src->shortcut_owner = NULL;
	} else {
		n_dst->shortcut_owner = NULL;
	}
}

static void drop_shortcut(struct mptcp_node *n)
{
	if (n->shortcut_owner) {
		tcp_sk(n->shortcut_owner)->mptcp->shortcut_ofoqueue = NULL;
		n->shortcut_owner = NULL;
	}
}

static void add_shortcut(struct tcp_sock *tp, struct mptcp_node *n)
{
	if ((struct mptcp_node *)tp->mptcp->shortcut_ofoqueue == n)
		return;
	/* remove any previous shortcut in the sock */
	if (tp->mptcp->shortcut_ofoqueue)
		tp->mptcp->shortcut_ofoqueue->shortcut_owner = NULL;
	/* remove any shortcut attachment in n */
	drop_shortcut(n);
	/* attach */
	n->shortcut_owner = (struct sock *)tp;
	tp->mptcp->shortcut_ofoqueue = (struct sk_buff *)n;
}

static void free_node(struct mptcp_node *n)
{
	if (!n->is_node) {
		drop_shortcut(n);
		__kfree_skb((struct sk_buff *)n);
	} else {
		struct sk_buff *skb, *tmp;
		skb_queue_walk_safe(&n->queue, skb, tmp) {
			__skb_unlink(skb, &n->queue);
			__kfree_skb(skb);
		}
		drop_shortcut(n);
		kmem_cache_free(node_cache, n);
	}
}

/**
 * @post: @new has replaced @old in the queue.
 */
static void replace_node(struct mptcp_node *old, struct mptcp_node *new)
{
	/* set references in new */
	new->next = old->next;
	new->prev = old->prev;

	/* set reference in the neighbours */
	new->next->prev = new;
	new->prev->next = new;

	/* move shortcut pointer to new node */
	move_shortcut(old, new);
}

/**
 * @pre: @n1 must be before @n2, and one cannot fully overlap the other, but
 *       they must be contiguous or partially overlapping.
 *       Only @aggreg is assumed to be
 *       in the queue. Should the other node be in the queue as well, it must
 *       have been removed by the caller before calling.
 * @aggreg: either @n1 or @n2, depending on which one aggregates the other.
 *          the merged node will inherit the next and prev pointers from
 *          @aggreg.
 * @return: The node that contains the concatenation of @n1 and @n2.
 */
static struct mptcp_node *concat(struct mptcp_node *n1, struct mptcp_node *n2,
				 struct mptcp_node *aggreg)
{
	/* Concatenating necessarily results in using a sequence of skbuffs.
	 * If one of n1 or n2 is already a sequence, we reuse the allocated
	 * memory. If both are a sequence, we drop one. If none is a sequence,
	 * we alloc one.
	 *
	 * Note: segment enqueing _must_ be done after replace_node()
	 * in any case, otherwise replace_node sets wrong pointers.
	 */
	if (!n1->is_node && !n2->is_node) {
		struct mptcp_node *n;
		/* No queue yet, create one */
		n = kmem_cache_alloc(node_cache, GFP_ATOMIC);
		if (!n)
			return NULL;
		n->is_node = 1;
		n->shortcut_owner = NULL;
		__skb_queue_head_init(&n->queue);
		replace_node(aggreg, n);
		/* Enforce invariant 2
		 * (shortcut inherited by node in replace_node)
		 */
		drop_shortcut(n1);
		drop_shortcut(n2);
		__skb_queue_head(&n->queue, (struct sk_buff *)n2);
		__skb_queue_head(&n->queue, (struct sk_buff *)n1);
		return n;
	} else if (!n1->is_node && n2->is_node) {
		/* expand n2 queue */
		if (aggreg == n1)
			replace_node(aggreg, n2);
		else
			drop_shortcut(n1); /* invariant 2 */
		__skb_queue_head(&n2->queue, (struct sk_buff *)n1);
		return n2;
	} else if (n1->is_node && !n2->is_node) {
		/* expand n1 queue */
		if (aggreg == n2)
			replace_node(aggreg, n1);
		else
			drop_shortcut(n2); /* invariant 2 */
		__skb_queue_tail(&n1->queue, (struct sk_buff *)n2);
		return n1;
	} else { /* both n1 and n2 are nodes with a queue inside */
		struct sk_buff *skb;
		/* Prune duplicated segments */
		for (skb = skb_peek_tail(&n1->queue);
		     !before(TCP_SKB_CB(skb)->seq,
			     TCP_SKB_CB(skb_peek(&n2->queue))->end_seq);
		     skb = skb_peek_tail(&n1->queue)) {
			__skb_unlink(skb, &n1->queue);
			__kfree_skb(skb);
		}

		if (aggreg == n1)
			replace_node(aggreg, n2);
		else
			drop_shortcut(n1); /* invariant 2 */

		/* Concat the queues and store in n2.
		 */
		skb_queue_splice(&n1->queue, &n2->queue);
		kmem_cache_free(node_cache, n1);
		return n2;
	}
}

/**
 * @head: The parent of the absolute root, which is not a real node and
 *        has both prev and next pointers pointing to the absolute root.
 *        used to fill the up pointer of the root if needed.
 * @container: Used to return the node in which the skb has been inserted
 *             (either the skb itself of its containing node)
 */
static int try_shortcut(struct mptcp_node *shortcut, struct sk_buff *skb,
			struct sk_buff_head *head,
			struct mptcp_node **container)
{
	struct mptcp_node *n = (struct mptcp_node *) skb;
	struct sk_buff *skb1;
	struct mptcp_node *n1;
	u32 seq = TCP_SKB_CB(skb)->seq;
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	/* If there is no overlap with the shortcut, we need
	 * to examine the full queue
	 */

	if (!shortcut) {
		n1 = (struct mptcp_node *)(skb1 = skb_peek_tail(head));
		if (!skb1) {
			__skb_queue_head(head, skb);
			*container = (struct mptcp_node *)skb;
			return 0;
		}
	} else {
		/* fast path */
		if (seq == high_dsn(shortcut)) {
			*container = concat(shortcut, n, shortcut);
			skb = (struct sk_buff *)(n = *container);
			goto clean_covered;
		}
		skb1 = (struct sk_buff *)(n1 = shortcut);
		/* If the shortcut is _before_ skb1, we need to
		 * traverse the list from shortcut to right, which is the
		 * reverse compared to the default
		 */
		while (!skb_queue_is_last(head, skb1) &&
		       before(high_dsn(n1), seq)) {
			n1 = (struct mptcp_node *)(skb1 = skb_queue_next(head, skb1));
		}
	}

	/* Find the insertion point */
	while (1) {
		if (!after(low_dsn(n1), seq))
			break;
		if (skb_queue_is_first(head, skb1)) {
			n1 = (struct mptcp_node *)(skb1 = NULL);
			break;
		}
		n1 = (struct mptcp_node *)(skb1 = skb_queue_prev(head, skb1));
	}
	/* Do skb overlap to previous one? */
	if (n1 && !after(seq, high_dsn(n1))) {
		if (!after(end_seq, high_dsn(n1))) {
			/* All the bits are present. Drop. */
			*container = NULL;
			return 1;
		}
		if (seq == low_dsn(n1)) {
			/* Here, n1 is fully covered by skb1,
			 * we add n1 before skb1 so that code later
			 * eats n1 and maybe subsequent segments that
			 * are also covered.
			 */
			if (skb_queue_is_first(head, skb1))
				n1 = (struct mptcp_node *)(skb1 = NULL);
			else
				n1 = (struct mptcp_node *)(skb1 =
						     skb_queue_prev(head, skb1));
		} else {
			/* We can concat them */
			*container = concat(n1, n, n1);
			skb = (struct sk_buff *)(n = *container);
			goto clean_covered;
		}
	}
	if (!skb1)
		__skb_queue_head(head, skb);
	else
		__skb_queue_after(head, skb1, skb);
	*container = n;
clean_covered:
	/* And clean segments covered by new one as whole. */
	while (!skb_queue_is_last(head, skb)) {
		n1 = (struct mptcp_node *)(skb1 = skb_queue_next(head, skb));

		if (before(end_seq, low_dsn(n1)))
			break;
		if (before(end_seq, high_dsn(n1))) {
			/* We can concat them */
			__skb_unlink(skb1, head);
			*container = concat(n, n1, n);
			break;
		}
		__skb_unlink(skb1, head);
		free_node(n1);
	}
	return 0;
}

/**
 * @sk: the subflow that received this skb.
 * @return: 1 if the skb must be dropped by the caller, otherwise 0
 */
int mptcp_add_meta_ofo_queue(struct sock *meta_sk, struct sk_buff *skb,
			     struct sock *sk)
{
	int ans;
	struct mptcp_node *container = NULL;
	struct tcp_sock *tp = tcp_sk(sk);

	skb->is_node = 0;
	skb->shortcut_owner = 0;
	ans = try_shortcut((struct mptcp_node *)tp->mptcp->shortcut_ofoqueue, skb,
			   &tcp_sk(meta_sk)->out_of_order_queue, &container);

	/* update the shortcut pointer in @sk */
	if (container)
		add_shortcut(tp, container);

	return ans;
}

void mptcp_ofo_queue(struct mptcp_cb *mpcb)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb);
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb;
	struct mptcp_node *n;

	while ((n = (struct mptcp_node *)(skb =
				    skb_peek(&meta_tp->out_of_order_queue)))
	       != NULL) {
		if (after(low_dsn(n), meta_tp->rcv_nxt))
			break;

		if (!after(high_dsn(n), meta_tp->rcv_nxt)) {
			__skb_unlink(skb, &meta_tp->out_of_order_queue);
			free_node(n);
			continue;
		}

		__skb_unlink(skb, &meta_tp->out_of_order_queue);
		drop_shortcut(n);

		if (!n->is_node) { /* simple skb */
			__skb_queue_tail(&meta_sk->sk_receive_queue, skb);
			mptcp_check_rcvseq_wrap(meta_tp,
						TCP_SKB_CB(skb)->end_seq -
						meta_tp->rcv_nxt);
			meta_tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		} else { /* queue of skbuffs */
			skb = skb_peek_tail(&n->queue);
			mptcp_check_rcvseq_wrap(meta_tp,
						high_dsn(n) - meta_tp->rcv_nxt);
			meta_tp->rcv_nxt = high_dsn(n);
			__skb_queue_splice(&n->queue,
					   meta_sk->sk_receive_queue.prev,
					   (struct sk_buff *)
					   &meta_sk->sk_receive_queue);
			meta_sk->sk_receive_queue.qlen += n->queue.qlen;
			kmem_cache_free(node_cache, n);
		}

		if (mptcp_is_data_fin(skb))
			mptcp_fin(mpcb);
	}
}

void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp)
{
	struct sk_buff_head *head = &meta_tp->out_of_order_queue;
	struct sk_buff *skb, *tmp;
	skb_queue_walk_safe(head, skb, tmp) {
		__skb_unlink(skb, head);
		free_node((struct mptcp_node *)skb);
	}
}

void mptcp_ofo_queue_init()
{
	node_cache = kmem_cache_create("mptcp_ofo_queue", sizeof(struct mptcp_node),
				       0, 0, NULL);
}

