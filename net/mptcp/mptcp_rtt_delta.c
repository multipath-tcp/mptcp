#include <linux/module.h>
#include <net/mptcp.h>

extern bool mptcp_is_def_unavailable(struct sock * sk);
extern bool mptcp_is_available(struct sock * sk,const struct sk_buff * skb,bool zero_wnd_test);
extern struct sock* get_available_subflow(struct sock * meta_sk,struct sk_buff * skb,bool zero_wnd_test);

extern int sysctl_mptcp_rtt_delta_threshold;

#define ctoh_rtt(x)  (x >> 13)

enum SCHED_STATE
{
	SCHED_INIT = 0,
	SCHED_REDUN,
	SCHED_DEFAULT,
	SCHED_UNDEFINED,
};

struct rtt_delta_redsched_sock_data
{
	struct sk_buff* skb;
	u32 skb_end_seq;
};

struct rtt_delta_redsched_cb_data
{
	struct tcp_sock* next_subflow;
};

struct rtt_delta_sched_cb_data
{
	enum SCHED_STATE sched_state;
	struct rtt_delta_redsched_cb_data redsched_cb_data;
};

static u32 count_can_sched_subflow(const struct mptcp_cb* mpcb)
{
	u32 cnt_sched_subflow = 0;
	struct sock* sk_it = NULL;

	mptcp_for_each_sk(mpcb, sk_it)
	{
		if(!mptcp_is_def_unavailable(sk_it))
		{
			cnt_sched_subflow++;
		}
	}

	return cnt_sched_subflow;
}

static struct rtt_delta_redsched_sock_data* rtt_delta_redsched_get_sock_data(struct tcp_sock* tp)
{
	return (struct rtt_delta_redsched_sock_data*)&tp->mptcp->mptcp_sched[0];
}

static struct rtt_delta_sched_cb_data* rtt_delta_sched_get_cb_data(struct tcp_sock* tp)
{
	return ((struct rtt_delta_sched_cb_data *)&tp->mpcb->mptcp_sched[0]);
}


static struct rtt_delta_redsched_cb_data* rtt_delta_redsched_get_cb_data(struct tcp_sock* tp)
{
	struct rtt_delta_sched_cb_data* rtt_del_sched_cb_data = rtt_delta_sched_get_cb_data(tp);
	return &(rtt_del_sched_cb_data->redsched_cb_data);
}

static bool rtt_delta_redsched_get_active_valid_sks(struct sock* meta_sk)
{
	struct tcp_sock* meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb* mpcb = meta_tp->mpcb;
	struct sock* sk;
	int active_valid_sks = 0;

	mptcp_for_each_sk(mpcb, sk)
	{
		if(subflow_is_active((struct tcp_sock*)sk) &&
			!mptcp_is_def_unavailable(sk))
			{active_valid_sks++;}
	}

	return active_valid_sks;
}

static bool rtt_delta_redsched_use_subflow(struct sock* meta_sk,
	int active_valid_sks,
	struct tcp_sock* tp,
	struct sk_buff* skb)
{
	if(!skb || !mptcp_is_available((struct sock*)tp, skb, false))
		{return false;}

	if (TCP_SKB_CB(skb)->path_mask == 0) {
		if (active_valid_sks == -1)
			active_valid_sks = rtt_delta_redsched_get_active_valid_sks(meta_sk);

		if (subflow_is_backup(tp) && active_valid_sks > 0)
			return false;
		else
			return true;
	}

	return true;
}

static struct sock* rtt_delta_redundant_get_subflow(struct sock *meta_sk,
						  struct sk_buff *skb,
						  bool zero_wnd_test)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct rtt_delta_redsched_cb_data *cb_data = rtt_delta_redsched_get_cb_data(meta_tp);
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
		if (mptcp_is_available((struct sock *)tp, skb,
					   zero_wnd_test)) {
			cb_data->next_subflow = tp->mptcp->next;
			return (struct sock *)tp;
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* No space */
	return NULL;
}

static struct sock* rtt_delta_get_subflow(struct sock *meta_sk,
						  struct sk_buff *skb,
						  bool zero_wnd_test)
{
	struct tcp_sock* meta_tp = tcp_sk(meta_sk);
	struct rtt_delta_sched_cb_data* cb_data = rtt_delta_sched_get_cb_data(meta_tp);

	if(SCHED_REDUN == cb_data->sched_state)
	{
		return rtt_delta_redundant_get_subflow(meta_sk, skb, zero_wnd_test);
	}

	if(SCHED_DEFAULT == cb_data->sched_state)
	{
		return get_available_subflow(meta_sk, skb, zero_wnd_test);
	}

	return NULL;
}


static void rtt_delta_redsched_correct_skb_pointers(struct sock *meta_sk,
					  struct rtt_delta_redsched_sock_data *sk_data)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	if (sk_data->skb && !after(sk_data->skb_end_seq, meta_tp->snd_una))
		sk_data->skb = NULL;
}

static struct sk_buff* rtt_delta_redundant_next_skb_from_queue(struct sk_buff_head *queue,
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

static struct sk_buff* rtt_delta_redundant_next_segment(struct sock *meta_sk,
							  int *reinject,
							  struct sock **subsk,
							  unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct rtt_delta_redsched_cb_data *cb_data = rtt_delta_redsched_get_cb_data(meta_tp);
	struct tcp_sock *first_tp = cb_data->next_subflow;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int active_valid_sks = -1;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (skb_queue_empty(&mpcb->reinject_queue) &&
		skb_queue_empty(&meta_sk->sk_write_queue))
		/* Nothing to send */
		return NULL;

	/* First try reinjections */
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		*subsk = get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;
		*reinject = 1;
		return skb;
	}

	/* Then try indistinctly redundant and normal skbs */

	if (!first_tp)
		first_tp = mpcb->connection_list;
	tp = first_tp;

	*reinject = 0;
	active_valid_sks = rtt_delta_redsched_get_active_valid_sks(meta_sk);
	do {
		struct rtt_delta_redsched_sock_data *sk_data;

		/* Correct the skb pointers of the current subflow */
		sk_data = rtt_delta_redsched_get_sock_data(tp);
		rtt_delta_redsched_correct_skb_pointers(meta_sk, sk_data);

		skb = rtt_delta_redundant_next_skb_from_queue(&meta_sk->sk_write_queue,
							sk_data->skb);
		if (skb && rtt_delta_redsched_use_subflow(meta_sk, active_valid_sks, tp,
						skb)) {
			sk_data->skb = skb;
			sk_data->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
			cb_data->next_subflow = tp->mptcp->next;
			*subsk = (struct sock *)tp;

			if (TCP_SKB_CB(skb)->path_mask)
				*reinject = -1;
			return skb;
		}

		tp = tp->mptcp->next;
		if (!tp)
			tp = mpcb->connection_list;
	} while (tp != first_tp);

	/* Nothing to send */
	return NULL;
}

static struct sk_buff* __rtt_delta_defsched_next_segment(struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = get_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			//skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff* rtt_delta_defsched_next_segment(struct sock *meta_sk,
						  int *reinject,
						  struct sock **subsk,
						  unsigned int *limit)
{
	struct sk_buff *skb = __rtt_delta_defsched_next_segment(meta_sk, reinject);
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
/*
	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}
	*/

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


#define DELTAED_SUBFLOW_NUM  2
static struct sk_buff* rtt_delta_next_segment(struct sock* meta_sk,
	int* reinject,
	struct sock** subsk,
	unsigned int* limit)
{
	const struct mptcp_cb* mpcb = tcp_sk(meta_sk)->mpcb;
	struct tcp_sock* subtp = NULL;
	struct sock* sk_it = NULL;
	struct tcp_sock* meta_tp = tcp_sk(meta_sk);
	struct rtt_delta_sched_cb_data* cb_data = rtt_delta_sched_get_cb_data(meta_tp);

	u32 rtt_delta_threshold_offset = sysctl_mptcp_rtt_delta_threshold >> 3;
	u32 rtt_delta_r2d_threshold = sysctl_mptcp_rtt_delta_threshold - rtt_delta_threshold_offset;
	u32 rtt_delta_d2r_threshold = sysctl_mptcp_rtt_delta_threshold + rtt_delta_threshold_offset;
	
	u32 rtt1 = 0;
	u32 rtt2 = 0;
	u32 delta_rtt = 0;
	struct sk_buff* skb = NULL;
	int cnt_sched_subflow;

	*limit = 0;
	cnt_sched_subflow = count_can_sched_subflow(mpcb);

	if(DELTAED_SUBFLOW_NUM != cnt_sched_subflow)
	{
		skb = rtt_delta_defsched_next_segment(meta_sk, reinject, subsk, limit);
		return skb;
	}

	if(SCHED_INIT == cb_data->sched_state)
	{
		skb = rtt_delta_redundant_next_segment(meta_sk, reinject, subsk, limit);
		cb_data->sched_state = SCHED_REDUN;
		return skb;
	}

	mptcp_for_each_sk(mpcb, sk_it)
	{
		if(mptcp_is_def_unavailable(sk_it))
		{
			continue;
		}

		subtp = tcp_sk(sk_it);

		if(0 == rtt1)
		{
			rtt1 = ctoh_rtt(subtp->srtt_us);
		}
		else
		{
			rtt2 = ctoh_rtt(subtp->srtt_us);
		}
	}

	delta_rtt = rtt1 > rtt2 ? (rtt1- rtt2) : (rtt2 - rtt1);

	if(SCHED_REDUN == cb_data->sched_state)
	{
		if(delta_rtt < rtt_delta_r2d_threshold)
		{
			cb_data->sched_state = SCHED_DEFAULT;
		}

		skb= rtt_delta_redundant_next_segment(meta_sk, reinject, subsk, limit);
		return skb;
	}

	if(SCHED_DEFAULT == cb_data->sched_state)
	{
		if(delta_rtt > rtt_delta_d2r_threshold)
		{
			cb_data->sched_state = SCHED_REDUN;
		}

		skb = rtt_delta_defsched_next_segment(meta_sk, reinject, subsk, limit);
		return skb;
	}

	return NULL;
}

static struct mptcp_sched_ops mptcp_rtt_delta = 
{
	.get_subflow = rtt_delta_get_subflow,
	.next_segment = rtt_delta_next_segment,
	.name = "rttdelta",
	.owner = THIS_MODULE,
};

static int __init rtt_delta_register(void)
{
	if (mptcp_register_scheduler(&mptcp_rtt_delta))
		return -1;

	return 0;
}

static void rtt_delta_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_rtt_delta);
}

module_init(rtt_delta_register);
module_exit(rtt_delta_unregister);

MODULE_AUTHOR("everysmile123@163.com");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RTT_DELTA MPTCP");
MODULE_VERSION("0.92");


