/* MPTCP Scheduler for redundant transmission.
 *
 * The scheduler will transmit information replicated through all the available
 * active (non-backup) subflows. When backup subflows are used no replication
 * is performed
 *
 * The code is highly inspired in mptcp_sched.c
 *
 * Design:
 * Christian Pinedo <christian.pinedo@ehu.eus> <chr.pinedo@gmail.com>
 * Igor Lopez <igor.lopez@ehu.eus>
 *
 * Implementation:
 * Christian Pinedo <christian.pinedo@ehu.eus> <chr.pinedo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>	/* Needed by all modules */
#include <net/mptcp.h>

/* Modified __mptcp_next_segment from mptcp_sched.c to re-send skbs through
 * other paths
 */
static struct sk_buff *__redundant_next_segment(struct sock *meta_sk, int *reinject)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

begin:
	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		// Reinjected or Redundant skb
		*reinject = 1;

		if (TCP_SKB_CB(skb)->dss[1] == 1) {
			// Additional checks for a redundant skb
			struct sock *subsk = get_available_subflow(meta_sk,
								   skb,
								   false);
			struct tcp_sock *tp;

			if (!subsk) {
				skb_unlink(skb, &mpcb->reinject_queue);
				__kfree_skb(skb);
				goto begin;
			}

			tp = tcp_sk(subsk);
			if (TCP_SKB_CB(skb)->path_mask == 0 ||
			    TCP_SKB_CB(skb)->path_mask &
			    mptcp_pi_to_flag(tp->mptcp->path_index)) {
				skb_unlink(skb, &mpcb->reinject_queue);
				__kfree_skb(skb);
				goto begin;
			}

		}
	} else {
		// Normal skb
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = get_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

/* Modified mptcp_next_segment from mptcp_sched.c to re-send skbs through other paths */
static struct sk_buff *redundant_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
	struct sk_buff *skb = __redundant_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	/* Redundant mechanism.
	 * Only for non-reinjected/non-redundant skbs and for skbs that are
	 * going through active sk.
	 * Inspired in __mptcp_reinject_data() of mptcp_output.c file
	 */
	if (subflow_is_active(subtp) &&
	    (!*reinject || (*reinject && TCP_SKB_CB(skb)->dss[1] != 1 ))) {
		const struct tcp_sock *meta_tp = tcp_sk(meta_sk);
		struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
		struct sock *sk;
		mptcp_for_each_sk(mpcb, sk) {
			struct tcp_sock *tp = tcp_sk(sk);
			struct sk_buff *copy_skb;
			if ((sk != *subsk) && subflow_is_active(tp)) {
				/* This is an additional active sk!! */
				copy_skb = pskb_copy_for_clone(skb, GFP_ATOMIC);
				if (unlikely(!copy_skb))
					continue;
				copy_skb->sk = meta_sk;
				if (!after(TCP_SKB_CB(copy_skb)->end_seq, meta_tp->snd_una)) {
					__kfree_skb(copy_skb);
					break;
				}
				memset(TCP_SKB_CB(copy_skb)->dss, 0 , mptcp_dss_len);
				/* Set the path_mask for this copy_skb blocking
				 * all the other active paths...
				 */
				TCP_SKB_CB(copy_skb)->path_mask = mptcp_pi_to_flag(tp->mptcp->path_index);
				TCP_SKB_CB(copy_skb)->path_mask ^= -1u;
				/* Set one to mark this packet as a redundant
				 * one and not a normal reinjection
				 */
				TCP_SKB_CB(copy_skb)->dss[1] = 1;
				/* Enqueue */
				skb_queue_tail(&mpcb->reinject_queue, copy_skb);
			}
		}
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	/* The following is similar to tcp_mss_split_point, but
	 * we do not care about nagle, because we will anyways
	 * use TCP_NAGLE_PUSH, which overrides this.
	 *
	 * So, we first limit according to the cwnd/gso-size and then according
	 * to the subflow's window.
	 */

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;
	max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
	if (!max_segs)
		return NULL;

	max_len = mss_now * max_segs;
	window = tcp_wnd_end(subtp) - subtp->write_seq;

	needed = min(skb->len, window);
	if (max_len <= skb->len)
		/* Take max_win, which is actually the cwnd/gso-size */
		*limit = max_len;
	else
		/* Or, take the window */
		*limit = needed;

	return skb;
}

static struct mptcp_sched_ops mptcp_sched_redundant = {
	.get_subflow = get_available_subflow,
	.next_segment = redundant_next_segment,
	.init = defsched_init,
	.name = "redundant",
	.owner = THIS_MODULE,
};

static int __init redundant_register(void)
{
	BUILD_BUG_ON(sizeof(struct defsched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_redundant))
		return -1;

	return 0;
}

static void __exit redundant_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_redundant);
}

module_init(redundant_register);
module_exit(redundant_unregister);

MODULE_AUTHOR("Christian Pinedo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("REDUNDANT MPTCP");
MODULE_VERSION("0.89");
