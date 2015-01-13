/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>

static DEFINE_SPINLOCK(mptcp_sched_list_lock);
static LIST_HEAD(mptcp_sched_list);

enum sk_groups {
	ACTIVE_NOT_USED,
	ACTIVE_USED,
	BACKUP_NOT_USED,
	BACKUP_USED
};

struct defsched_priv {
	u32	last_rbuf_opti;
};

static struct defsched_priv *defsched_get_priv(const struct tcp_sock *tp)
{
	return (struct defsched_priv *)&tp->mptcp->mptcp_sched[0];
}

static bool mptcp_is_def_unavailable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Set of TCP states for which we are not allowed to send data
	 * "definetively"
	 */
	if ((1 << sk->sk_state) & (TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 |
				   TCPF_CLOSE | TCPF_CLOSING | TCPF_LISTEN))
		return true;

	/* The socket failed */
	if (tp->pf)
		return true;

	return false;
}

static bool mptcp_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

	/* Set of TCP states for which we are not allowed to send data
	 * "temporally"
	 */
	if (sk->sk_state == TCPF_SYN_SENT && !tcp_passive_fastopen(sk))
		return true;

	if ((1 << sk->sk_state) &
	    (TCPF_SYN_RECV | TCPF_TIME_WAIT | TCPF_LAST_ACK))
		return true;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return true;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return true;
		else if (tp->snd_una != tp->high_seq)
			return true;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return true;
	}

	/* If TSQ is already throttling us, do not send on this subflow. When
	 * TSQ gets cleared the subflow becomes eligible again.
	 */
	if (test_bit(TSQ_THROTTLED, &tp->tsq_flags))
		return true;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return true;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return true;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return true;

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return true;

	return false;
}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_is_available(struct sock *sk, const struct sk_buff *skb,
			       bool zero_wnd_test)
{
	if (mptcp_is_def_unavailable(sk) ||
	    mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
		return false;
	}

	return true;
}

static bool subflow_is_backup(const struct tcp_sock *tp)
{
	return tp->mptcp->rcv_low_prio || tp->mptcp->low_prio;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

static bool subflow_is_selected(struct tcp_sock *tp, struct sk_buff *skb,
				enum sk_groups sk_group)
{
	switch (sk_group) {
	case ACTIVE_NOT_USED:
		if (!subflow_is_backup(tp) && !mptcp_dont_reinject_skb(tp, skb))
			return true;
		return false;
	case ACTIVE_USED:
		if (!subflow_is_backup(tp) && mptcp_dont_reinject_skb(tp, skb))
			return true;
		return false;
	case BACKUP_NOT_USED:
		if (subflow_is_backup(tp) && !mptcp_dont_reinject_skb(tp, skb))
			return true;
		return false;
	case BACKUP_USED:
		if (subflow_is_backup(tp) && mptcp_dont_reinject_skb(tp, skb))
			return true;
		return false;
	default:
		return false;
	}
}

static struct sock *get_subflow_from_group(struct mptcp_cb *mpcb,
					   struct sk_buff *skb,
					   enum sk_groups sk_group,
					   bool zero_wnd_test, u8 *cnt,
					   u8 *cnt_def_una, u8 *cnt_temp_una)
{
	struct sock *selected_sk = NULL;
	u32 min_srtt = 0xffffffff;
	struct sock *sk;
	struct tcp_sock *tp;

	mptcp_for_each_sk(mpcb, sk) {
		tp = tcp_sk(sk);
		if (!subflow_is_selected(tp, skb, sk_group))
			continue;
		(*cnt)++;
		if (mptcp_is_def_unavailable(sk)) {
			(*cnt_def_una)++;
			continue;
		}
		if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			(*cnt_temp_una)++;
			continue;
		}
		if (tp->srtt_us < min_srtt) {
			min_srtt = tp->srtt_us;
			selected_sk = sk;
		}
	}

	return selected_sk;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *get_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	u8 cnt, cnt_def_una, cnt_temp_una;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_available(sk, skb, zero_wnd_test))
			sk = NULL;
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find the best subflow */
	cnt = 0;
	cnt_def_una = 0;
	cnt_temp_una = 0;

	sk = get_subflow_from_group(mpcb, skb, ACTIVE_NOT_USED, zero_wnd_test,
				    &cnt, &cnt_def_una, &cnt_temp_una);
	if (sk)
		return sk;

	sk = get_subflow_from_group(mpcb, skb, ACTIVE_USED, zero_wnd_test,
				    &cnt, &cnt_def_una, &cnt_temp_una);
	if (sk) {
		TCP_SKB_CB(skb)->path_mask = 0;
		return sk;
	} else if (cnt != 0 || cnt != cnt_def_una) {
		/* we will wait for an available active subflow to send the skb
		 * we won't use a backup subflow
		 */
		return NULL;
	}

	sk = get_subflow_from_group(mpcb, skb, BACKUP_NOT_USED, zero_wnd_test,
				    &cnt, &cnt_def_una, &cnt_temp_una);
	if (sk)
		return sk;

	sk = get_subflow_from_group(mpcb, skb, BACKUP_USED, zero_wnd_test,
				    &cnt, &cnt_def_una, &cnt_temp_una);
	if (sk) {
		TCP_SKB_CB(skb)->path_mask = 0;
		return sk;
	}

	/* By default return NULL subflow */
	return NULL;
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sock *tp_it;
	struct sk_buff *skb_head;
	struct defsched_priv *dsp = defsched_get_priv(tp);

	if (tp->mpcb->cnt_subflows == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_write_queue_head(meta_sk);

	if (!skb_head || skb_head == tcp_send_head(meta_sk))
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	/* Only penalize again after an RTT has elapsed */
	if (tcp_time_stamp - dsp->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				dsp->last_rbuf_opti = tcp_time_stamp;
			}
			break;
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_tp(tp->mpcb, tp_it) {
			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = true;
					break;
				}

				if (4 * tp->srtt_us >= tp_it->srtt_us) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans && mptcp_is_available(sk, skb_head, false))
			return skb_head;
	}
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_next_segment(struct sock *meta_sk, int *reinject)
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

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *mptcp_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
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

static void defsched_init(struct sock *sk)
{
	struct defsched_priv *dsp = defsched_get_priv(tcp_sk(sk));

	dsp->last_rbuf_opti = tcp_time_stamp;
}

struct mptcp_sched_ops mptcp_sched_default = {
	.get_subflow = get_available_subflow,
	.next_segment = mptcp_next_segment,
	.init = defsched_init,
	.name = "default",
	.owner = THIS_MODULE,
};

static struct mptcp_sched_ops *mptcp_sched_find(const char *name)
{
	struct mptcp_sched_ops *e;

	list_for_each_entry_rcu(e, &mptcp_sched_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

int mptcp_register_scheduler(struct mptcp_sched_ops *sched)
{
	int ret = 0;

	if (!sched->get_subflow || !sched->next_segment)
		return -EINVAL;

	spin_lock(&mptcp_sched_list_lock);
	if (mptcp_sched_find(sched->name)) {
		pr_notice("%s already registered\n", sched->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&sched->list, &mptcp_sched_list);
		pr_info("%s registered\n", sched->name);
	}
	spin_unlock(&mptcp_sched_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(mptcp_register_scheduler);

void mptcp_unregister_scheduler(struct mptcp_sched_ops *sched)
{
	spin_lock(&mptcp_sched_list_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&mptcp_sched_list_lock);
}
EXPORT_SYMBOL_GPL(mptcp_unregister_scheduler);

void mptcp_get_default_scheduler(char *name)
{
	struct mptcp_sched_ops *sched;

	BUG_ON(list_empty(&mptcp_sched_list));

	rcu_read_lock();
	sched = list_entry(mptcp_sched_list.next, struct mptcp_sched_ops, list);
	strncpy(name, sched->name, MPTCP_SCHED_NAME_MAX);
	rcu_read_unlock();
}

int mptcp_set_default_scheduler(const char *name)
{
	struct mptcp_sched_ops *sched;
	int ret = -ENOENT;

	spin_lock(&mptcp_sched_list_lock);
	sched = mptcp_sched_find(name);
#ifdef CONFIG_MODULES
	if (!sched && capable(CAP_NET_ADMIN)) {
		spin_unlock(&mptcp_sched_list_lock);

		request_module("mptcp_%s", name);
		spin_lock(&mptcp_sched_list_lock);
		sched = mptcp_sched_find(name);
	}
#endif

	if (sched) {
		list_move(&sched->list, &mptcp_sched_list);
		ret = 0;
	} else {
		pr_info("%s is not available\n", name);
	}
	spin_unlock(&mptcp_sched_list_lock);

	return ret;
}

void mptcp_init_scheduler(struct mptcp_cb *mpcb)
{
	struct mptcp_sched_ops *sched;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &mptcp_sched_list, list) {
		if (try_module_get(sched->owner)) {
			mpcb->sched_ops = sched;
			break;
		}
	}
	rcu_read_unlock();
}

/* Manage refcounts on socket close. */
void mptcp_cleanup_scheduler(struct mptcp_cb *mpcb)
{
	module_put(mpcb->sched_ops->owner);
}

/* Set default value from kernel configuration at bootup */
static int __init mptcp_scheduler_default(void)
{
	BUILD_BUG_ON(sizeof(struct defsched_priv) > MPTCP_SCHED_SIZE);

	return mptcp_set_default_scheduler(CONFIG_DEFAULT_MPTCP_SCHED);
}
late_initcall(mptcp_scheduler_default);
