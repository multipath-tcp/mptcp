/*
 *	MPTCP Scheduler to reduce latency and jitter.
 *
 *	This scheduler sends all packets redundantly on all available subflows.
 *
 *	Initial Design & Implementation:
 *	Tobias Erbshaeusser <erbshauesser@dvs.tu-darmstadt.de>
 *	Alexander Froemmgen <froemmge@dvs.tu-darmstadt.de>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <net/mptcp.h>

/* Struct to store a reference to a skb in the send or reinject queue */
struct rempsched_skb {
	/* The skb or NULL */
	struct sk_buff *skb;
	/* End sequence number of the skb. This number should be checked
	 * to be valid before the skb field is used
	 */
	u32 skb_end_seq;
};

/* Struct to store the data of a single subflow */
struct rempsched_sock_data {
	/* Reference to the last sent skb of the send queue */
	struct rempsched_skb send_skb;
};

/* Struct to store the data of the control block */
struct rempsched_cb_data {
	/* The next subflow where a skb should be sent or NULL */
	struct tcp_sock *next_subflow;
};

/* Returns the socket data from a given subflow socket */
static struct rempsched_sock_data *rempsched_get_sock_data(struct tcp_sock *tp)
{
	return (struct rempsched_sock_data *)&tp->mptcp->mptcp_sched[0];
}

/* Returns the control block data from a given meta socket */
static struct rempsched_cb_data *rempsched_get_cb_data(struct tcp_sock *tp)
{
	return (struct rempsched_cb_data *)&tp->mpcb->mptcp_sched[0];
}

static struct sock *remp_get_subflow(struct sock *meta_sk,
				     struct sk_buff *skb,
				     bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct rempsched_cb_data *cb_data = rempsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct sock *sk;
	struct tcp_sock *tp;

	/* Answer data_fin on same subflow */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index ==
				mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	if (!first_tp)
		first_tp = mpcb->connection_list;
	tp = first_tp;

	/* Search for any subflow to send it */
	do {
		if (mptcp_is_available((struct sock *) tp, skb,
				       zero_wnd_test)) {
			cb_data->next_subflow = tp->mptcp->next;
			return (struct sock *) tp;
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* No space */
	return NULL;
}

/* Corrects the stored skb pointers if they are invalid */
static void rempsched_correct_skb_pointers(struct sock *meta_sk,
					   struct rempsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	if (sk_data->send_skb.skb && !after(sk_data->send_skb.skb_end_seq,
					    meta_tp->snd_una))
		sk_data->send_skb.skb = NULL;
}

/* Returns the next skb from the queue */
static struct sk_buff *remp_next_skb_from_queue(struct sk_buff_head *queue,
						struct sk_buff *previous)
{
	if (skb_queue_empty(queue))
		return NULL;

	if (!previous)
		return skb_peek(queue);

	if (skb_queue_is_last(queue, previous))
		return NULL;

	return skb_queue_next(queue, previous);
}

static struct sk_buff *remp_next_segment(struct sock *meta_sk,
					 int *reinject,
					 struct sock **subsk,
					 unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct rempsched_cb_data *cb_data = rempsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct rempsched_sock_data *sk_data;
	struct sk_buff *skb;

	if (!first_tp)
		first_tp = mpcb->connection_list;
	tp = first_tp;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
	    skb_queue_empty(&meta_sk->sk_write_queue))
		/* Nothing to send */
		return NULL;

	do {
		/* Correct the skb pointers of the current subflow */
		sk_data = rempsched_get_sock_data(tp);
		rempsched_correct_skb_pointers(meta_sk, sk_data);

		/* Check if there are skbs that must be sent ...
		 * ... in the reinject queue
		 */
		skb = skb_peek(&mpcb->reinject_queue);
		if (skb)
			*reinject = 1;
		else {
			/* ... in the send queue */
			skb = remp_next_skb_from_queue(&meta_sk->sk_write_queue,
						       sk_data->send_skb.skb);
			*reinject = 0;
		}

		if (skb && mptcp_is_available((struct sock *) tp, skb, false)) {
			/* Found */
			if (!*reinject) {
				sk_data->send_skb.skb = skb;
				sk_data->send_skb.skb_end_seq =
					TCP_SKB_CB(skb)->end_seq;
			}

			cb_data->next_subflow = tp->mptcp->next;
			*subsk = (struct sock *) tp;
			return skb;
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	return NULL;
}

static void remp_init(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct rempsched_sock_data *sk_data = rempsched_get_sock_data(tsk);

	sk_data->send_skb.skb = NULL;
}

static void remp_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct rempsched_cb_data *cb_data = rempsched_get_cb_data(tp);

	/* Check if the next subflow would be the released one. If yes correct
	   the pointer */
	if (cb_data->next_subflow == tp)
		cb_data->next_subflow = tp->mptcp->next;
}

struct mptcp_sched_ops mptcp_sched_remp = {
	.get_subflow = remp_get_subflow,
	.next_segment = remp_next_segment,
	.init = remp_init,
	.release = remp_release,
	.name = "remp",
	.owner = THIS_MODULE,
};

static int __init remp_register(void)
{
	BUILD_BUG_ON(sizeof(struct rempsched_sock_data) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct rempsched_cb_data) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_remp))
		return -1;

	return 0;
}

static void remp_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_remp);
}

module_init(remp_register);
module_exit(remp_unregister);

MODULE_AUTHOR("Tobias Erbshaeusser, Alexander Froemmgen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ReMP MPTCP");
MODULE_VERSION("0.90");
