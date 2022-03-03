/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>
#include <linux/jiffies.h>
// swetankk
#include <linux/inet.h>

// shivanga
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)

static unsigned int num_segments __read_mostly = 100;
module_param(num_segments, uint, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 0;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

struct ratio_sched_priv {
	u16 quota;
	u32 write_seq_saved;
	//u32 write_seq_jiffies;
	struct timeval write_seq_tv, snd_una_tv;
	u64 completion_time;
	u8 is_accounting, is_init_accounted;
	u32 snd_una_saved, buffer_size;
	u32 delivered;
};

static struct ratio_sched_priv *ratio_sched_get_priv(const struct tcp_sock *tp)
{
	return (struct ratio_sched_priv *)&tp->mptcp->mptcp_sched[0];
}

//u64 prev_tx_bytes = 0, prev_tstamp = 0;
u8 sample_skip_ad = 2, sample_skip_ac = 2;
struct sock *blocked_sk = NULL;
//struct sock* write_seq_sk = NULL;
//u32 write_seq_saved, write_seq_jiffies;
unsigned int num_segments_flow_one; //WILL THIS BE CREATED FOR EACH COPY?
//unsigned int ratio_search_step;

/* If the sub-socket sk available to send the skb? */
static bool mptcp_ratio_is_available(struct sock *sk, const struct sk_buff *skb,
		bool zero_wnd_test, bool cwnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int space, in_flight;

	/* shivanga */
	if (blocked_sk && blocked_sk == sk) {
		//printk("sk is blocked");
		return false;
	}


	/* end: shivanga */

	/* swetankk */
	if (subflow_is_backup(tp)) {
		//printk("subflow is backup");
		return false;
	}    /* swetankk: end*/

	// shivanga
	/*struct net *net;
	  struct net_device *dev;	
	  struct inet_sock *inet;
	  const struct inet_connection_sock *icsk = inet_csk(sk);

	  net = sock_net(sk);
	  inet = inet_sk(sk);
	  if(net && inet) {
	  dev = __ip_dev_find(net, inet->inet_saddr, true);
	  if (dev && dev->operstate==6 && tp->pf) {
	  tp->pf = 0;
	  tp->snd_cwnd = icsk->icsk_ca_ops->undo_cwnd(sk);
	  if (tp->prior_ssthresh > tp->snd_ssthresh) 
	  tp->snd_ssthresh = tp->prior_ssthresh;
	  tcp_set_ca_state(sk, TCP_CA_Recovery);
	  tp->ops->write_wakeup(sk, LINUX_MIB_TCPKEEPALIVE);
	//printk("name: %s operstate: %ul state: %lu flags: %ul\n", dev->name, dev->operstate, dev->state, dev->flags);
	} 
	}
	*/
	/* swetankk */
	/*if (subflow_is_backup(tp)) {
	  printk("backup\n");
	  return false;
	  }*/
	/* end: swetankk */

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk)) {
		//printk("mptcp_sk cannot send");
		return false;
	}
	//printk("mptcp_sk can send");

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established) {
		//printk("tp is in PRE_ESTABLISHED state");
		return false;
	}
	//printk("tp is not in PRE_ESTABLISHED state");

	if (tp->pf) {
		//printk("tp->pf is set");
		return false;
	}


	//printk("tp->pf is not set");

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp)) {
			printk("tcp_is_reno");
			return false;
		}
		else if (tp->snd_una != tp->high_seq) {
			printk("tp->snd_una != tp->high_seq");
			return false;
		}
	}

	//printk("TCP_CA_Loss");

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
				tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq) {
			printk("tp->mptcp->fully_established is false");
			return false;
		}
	}

	//printk("tp->mptcp->fully_established is true");

	if (!cwnd_test)
		goto zero_wnd_test;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

zero_wnd_test:
	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp))) {
		printk("zero_wnd_test");
		return false;
	}

	//printk("mptcp_ratio_is_available: true\n");
	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_ratio_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* We just look for any subflow that as available */
static struct sock *ratio_get_available_subflow(struct sock *meta_sk,
		struct sk_buff *skb,
		bool zero_wnd_test)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	//struct sock *sk, *bestsk = NULL, *backupsk = NULL;
	/*Phuc*/
	struct sock *sk=NULL, *bestsk = NULL, *backupsk = NULL;
	struct mptcp_tcp_sock *mptcp;
	/****/

#ifdef MPTCP_SCHED_PROBE
	//struct sock *sk_it;
	/*Phuc*/
	struct mptcp_tcp_sock *mptcp_it;
	struct mptcp_sched_probe sprobe;
	unsigned long sched_probe_id;

	mptcp_sched_probe_init(&sprobe);
	get_random_bytes(&sched_probe_id, sizeof(sched_probe_id));
#endif

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_ratio_is_available(sk, skb, false, cwnd_limited))
			sk = NULL;
		return sk;
	}    

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
			skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sub(mpcb, mptcp) {
			sk = mptcp_to_sock(mptcp);
#ifdef MPTCP_SCHED_PROBE
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
					mptcp_ratio_is_available(sk, skb, zero_wnd_test, true)) {
				if (sk) mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk);
				return sk;
			}
#else
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
					mptcp_ratio_is_available(sk, skb, zero_wnd_test, true))
				return sk;
#endif
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sub(mpcb, mptcp) {
		/*Phuc*/
		//sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(mptcp_to_sock(mptcp));
		if (!mptcp_ratio_is_available(mptcp_to_sock(mptcp), skb, zero_wnd_test, true))
			continue;

		if (mptcp_ratio_dont_reinject_skb(tp, skb)) {
			backupsk = mptcp_to_sock(mptcp);
			continue;
		}

		bestsk = mptcp_to_sock(mptcp);
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}
#ifdef MPTCP_SCHED_PROBE
	mptcp_for_each_sub(mpcb, mptcp_it) {
		struct sock *sk_it = mptcp_to_sock(mptcp_it);
		if (sk && sk_it == sk) mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk);
		else mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk);
	}
#endif
	return sk;
}

u32 get_queue_size(struct sock *sk, struct tcp_sock *meta_tp){
	struct dst_entry *dst;
	struct netdev_queue *txq0;
	struct dql *dql0;
	struct Qdisc *qdisc;
	struct rtnl_link_stats64 temp;
	//const struct rtnl_link_stats64 *stats;
	u32 packets_in_queue;
	u64 tput = 0;

	dst = sk_dst_get(sk);

	if (dst->dev) {
		const struct rtnl_link_stats64 *stats = dev_get_stats(dst->dev, &temp);

		txq0 = netdev_get_tx_queue(dst->dev, 0); //get txqueueu from dst
		dql0 = &txq0->dql;
		qdisc = txq0->qdisc;

		if (!meta_tp->prev_tx_bytes) meta_tp->prev_tx_bytes = stats->tx_bytes;
		if (!meta_tp->prev_tstamp) meta_tp->prev_tstamp = txq0->trans_start;

		if (meta_tp->prev_tx_bytes && meta_tp->prev_tstamp && txq0->trans_start != meta_tp->prev_tstamp) {
			tput = ((stats->tx_bytes - meta_tp->prev_tx_bytes)*8)/(jiffies_to_msecs(txq0->trans_start - meta_tp->prev_tstamp));
			//printk("rate: %llu\n", tput);
			meta_tp->prev_tx_bytes = stats->tx_bytes;
			meta_tp->prev_tstamp = txq0->trans_start;
		}

		packets_in_queue = dql0->num_queued - dql0->num_completed; //number of packets in DQL

	}

	//printk("tx_packets: %llu, trans_start: %lu, num_tx_queues: %u, real_num_tx_queues: %u, path index: %u\n", stats->tx_packets, txq0->trans_start, dst->dev->num_tx_queues, dst->dev->real_num_tx_queues, tcp_sk(sk)->mptcp->path_index); 
	//printk(KERN_INFO "Packets in queue %u, path index: %u, dql_avail: %d", packets_in_queue, tcp_sk(sk)->mptcp->path_index, dql_avail(dql0));
	//printk(KERN_INFO "qdisc len: %d, path index: %u\n", qdisc_qlen(qdisc), tcp_sk(sk)->mptcp->path_index);
	return tput;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_ratio_next_segment(const struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb)
		*reinject = 1;
	else
		skb = tcp_send_head(meta_sk);

	return skb;
}

#define tcp_probe_copy_fl_to_si4(inet, si4, mem)        \
	do {                            \
		si4.sin_family = AF_INET;           \
		si4.sin_port = inet->inet_##mem##port;      \
		si4.sin_addr.s_addr = inet->inet_##mem##addr;   \
	} while (0)                     \


static struct sk_buff *mptcp_ratio_next_segment(struct sock *meta_sk,
		int *reinject,
		struct sock **subsk,
		unsigned int *limit)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	//struct sock *sk_it, *choose_sk = NULL;
	struct sock *choose_sk=NULL;
	/*phuc*/
	struct mptcp_tcp_sock *mptcp;
	/***/
	struct sk_buff *skb = __mptcp_ratio_next_segment(meta_sk, reinject);
	unsigned int split = num_segments;
	unsigned char iter = 0, full_subs = 0, counter = 0, i = 0;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	char *ip_60 = "192.168.2.11";
	char *ip_5 = "192.168.2.10";

	u32 total_rate, rate_ad, rate_ac, ref_rate, last_rate, best_rate, best_ratio, in_search, last_trigger_tstamp, thresh_cnt_reset, qSize, curr_diff, count_set_init_rate, init_rate;
	u32 rate_search_0, rate_search_100, buffer_total, init_buffer_total, trigger_threshold;
	int rate_diff, buffer_diff;
	u32 last_buffer_size[2] = {0, 0}, init_buffer_size[2] = {0, 0}, tput[2] = {0, 0};
	int diff_ref, diff_last, threshold_cnt;
	u8 buffer_threshold_cnt;
	unsigned int time_diff, loop_counter = 0;
	int completion_times[2] = {0, 0};

	//struct inet_sock *inet;
	//struct net_device *dev;
	//struct net *net;
#ifdef MPTCP_SCHED_PROBE
	struct mptcp_sched_probe sprobe;
	unsigned long sched_probe_id;

	get_random_bytes(&sched_probe_id, sizeof(sched_probe_id));
	mptcp_sched_probe_init(&sprobe);

#endif
	if (meta_tp->run_started == 0) {
		meta_tp->run_started = 1;
		num_segments_flow_one = meta_tp->num_segments_flow_one = sysctl_num_segments_flow_one;
		meta_tp->ratio_search_step = sysctl_mptcp_ratio_search_step;
		meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
		if(inet_sk(meta_sk)->inet_daddr)
			printk("MPTCP Run Started, destination: %pI4", &inet_sk(meta_sk)->inet_daddr);
		else
			printk("MPTCP Run Started");
		//meta_tp->dest_ip_any = inet_sk(meta_sk)->inet_daddr;
		//mptcp_for_each_sk(mpcb, sk_it) {
		//    meta_tp->dest_ip_any = inet_sk(sk_it)->inet_daddr;
		//    break;
		//}
	}

	/* swetankk */
	/*mptcp_for_each_sk(mpcb, sk_it) {
	  struct tcp_sock *tp = tcp_sk(sk_it);
	//printk("low:%u, send:%u\n", tp->mptcp->low_prio, tp->mptcp->send_mp_prio); 
	inet = inet_sk(sk_it);
	if (inet) {// && inet->inet_saddr == in_aton("192.168.1.4")) {
	net = sock_net(sk_it);
	if (net) {
	if (sysctl_mptcp_set_backup) {
	if (!tp->mptcp->low_prio) {
	rtnl_lock();
	//printk("set\n");
	choose_sk                dev = __ip_dev_find(net, inet->inet_saddr, false);
	printk("%s set\n", dev->name);
	dev_change_flags(dev, dev->flags | IFF_MPBACKUP);
	rtnl_unlock();
	}
	break;
	} 
	else {
	if (tp->mptcp->low_prio) {
	rtnl_lock();
	printk("unset\n");
	dev = __ip_dev_find(net, inet->inet_saddr, false);
	dev_change_flags(dev, dev->flags & ~IFF_MPBACKUP);
	rtnl_unlock();
	break;
	}
	}
	}
	}
	}*/
	/* swetankk: end*/
	/*
	   mptcp_for_each_sk(mpcb, sk_it) {
	   struct tcp_sock *tp_it = tcp_sk(sk_it);
	   struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);

	   loop_counter++;

	   completion_times[loop_counter-1] = rsp->completion_time;
	   }
	   if (loop_counter == 2) {    
	   loop_counter = 0;
	   mptcp_for_each_sk(mpcb, sk_it) {
	   struct tcp_sock *tp_it = tcp_sk(sk_it);
	   struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
	   uint mss_now = tcp_current_mss(sk_it);
	   loop_counter++;

	//printk("%u: meta_tp->write_seq: %u, snd_una: %u, saved: %u, %u", loop_counter, meta_tp->snd_nxt, meta_tp->snd_una, rsp->write_seq_saved, mpcb->cnt_established); 

	if(loop_counter % 2) {
	if (rsp->write_seq_tv.tv_usec && after(meta_tp->snd_una, rsp->write_seq_saved)) {
	//printk("loop_counter %% 2");
	if (!after(meta_tp->snd_una, rsp->write_seq_saved + num_segments_flow_one * mss_now) && !rsp->snd_una_tv.tv_sec) {
	do_gettimeofday(&rsp->snd_una_tv);    
	} else if (after(meta_tp->snd_una, rsp->write_seq_saved + num_segments_flow_one * mss_now)){
	u32 sub_snd_una[2] = {0,0};
	int snd_una_loop = 0;
	struct sock *local_sk_it;
	if (!rsp->snd_una_tv.tv_sec) {
	//printk("!rsp->snd_una_tv.tv_sec");
	rsp->completion_time = rsp->write_seq_tv.tv_sec*1000000 + rsp->write_seq_tv.tv_usec;
	} else {
	//printk("rsp->snd_una_tv.tv_sec");
	struct timeval tv, tv_diff;
	do_gettimeofday(&tv);
	//printk("subtraction 2");
	timersub(&tv, &rsp->snd_una_tv, &tv_diff);
	//rsp->completion_time = jiffies_to_msecs(jiffies - rsp->write_seq_jiffies);
	rsp->completion_time = (tv_diff.tv_sec  + rsp->write_seq_tv.tv_sec)*1000000 + (tv_diff.tv_usec + rsp->write_seq_tv.tv_usec);
	}
	mptcp_for_each_sk(mpcb, local_sk_it) {
	sub_snd_una[snd_una_loop++] = tcp_sk(local_sk_it)->snd_una;
	}
	//printk("%u: jiffies: %lu, time taken %llu us, ratio: %u, meta->snd_una: %u, tp_ad->snd_una: %u, tp_ac->snd_una: %u", loop_counter, jiffies, rsp->completion_time, num_segments_flow_one, meta_tp->snd_una, sub_snd_una[0], sub_snd_una[1]);
	rsp->write_seq_tv.tv_sec = 0;
	rsp->write_seq_tv.tv_usec = 0;
	rsp->snd_una_tv.tv_sec = 0;
	rsp->snd_una_tv.tv_usec = 0;
	rsp->write_seq_saved = 0;
	}
	}
	} else {
	if (rsp->write_seq_tv.tv_usec && after(meta_tp->snd_una, rsp->write_seq_saved)) {
	//printk("!loop_counter %% 2");
	if (!after(meta_tp->snd_una, rsp->write_seq_saved + (num_segments - num_segments_flow_one) * mss_now) && !rsp->snd_una_tv.tv_sec) {
	do_gettimeofday(&rsp->snd_una_tv);   
	} else if (after(meta_tp->snd_una, rsp->write_seq_saved + (num_segments - num_segments_flow_one) * mss_now)) {
	u32 sub_snd_una[2] = {0,0};
	int snd_una_loop = 0;
	struct sock *local_sk_it;
	if (!rsp->snd_una_tv.tv_sec) {
	//printk("!rsp->snd_una_tv.tv_sec");
	rsp->completion_time = rsp->write_seq_tv.tv_sec*1000000 + rsp->write_seq_tv.tv_usec;
	} else {
	//printk("rsp->snd_una_tv.tv_sec");
	struct timeval tv, tv_diff;
	do_gettimeofday(&tv);
	//printk("subtraction 2");
	timersub(&tv, &rsp->snd_una_tv, &tv_diff);
	//rsp->completion_time = jiffies_to_msecs(jiffies - rsp->write_seq_jiffies);
	rsp->completion_time = (tv_diff.tv_sec  + rsp->write_seq_tv.tv_sec)*1000000 + (tv_diff.tv_usec + rsp->write_seq_tv.tv_usec);
}
mptcp_for_each_sk(mpcb, local_sk_it) {
	sub_snd_una[snd_una_loop++] = tcp_sk(local_sk_it)->snd_una;
}
//printk("%u: jiffies: %lu, time taken %llu us, ratio: %u, meta->snd_una: %u, tp_ad->snd_una: %u, tp_ac->snd_una: %u", loop_counter, jiffies, rsp->completion_time, num_segments_flow_one, meta_tp->snd_una, sub_snd_una[0], sub_snd_una[1]);
rsp->write_seq_tv.tv_sec = 0;
rsp->write_seq_tv.tv_usec = 0;
rsp->snd_una_tv.tv_sec = 0;
rsp->snd_una_tv.tv_usec = 0;
rsp->write_seq_saved = 0;
}
}
}
}
loop_counter = 0;
mptcp_for_each_sk(mpcb, sk_it) { 
	struct tcp_sock *tp_it = tcp_sk(sk_it);
	struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
	if (rsp->completion_time) loop_counter++;
} 

if (loop_counter == 2) {
	loop_counter = 0;
	mptcp_for_each_sk(mpcb, sk_it) {
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
		completion_times[loop_counter++] = rsp->completion_time;
		//printk("%u: time taken %u ms, ratio: %u", loop_counter, rsp->last_completion_time, sysctl_num_segments_flow_one);
		rsp->completion_time = 0;
		rsp->is_accounting = false;
		rsp->is_init_accounted = false;
	}

	//printk("diff: %d", completion_times[0] - completion_times[1]);
}   
} else {
	completion_times[0] = 0;
	completion_times[1] = 0;
}

mptcp_for_each_sk(mpcb, sk_it) {
	//struct tcp_sock *tp = tcp_sk(sk_it);
	//if (!i) { i++; continue; }
	//i = 0;
	if (i) { i = 0; break; }
	i++;
	if (sysctl_mptcp_set_backup) {
		if (!blocked_sk) {
			printk("set blocked_sk\n");
			//tp->pf = 1;
			blocked_sk = sk_it;
		}
		break;
	}
	if (!sysctl_mptcp_set_backup) {
		if (blocked_sk) {
			printk("unset blocked_sk\n");
			blocked_sk = NULL;
		}
		break;
	}
}
*/
/* As we set it, we have to reset it as well. */
*limit = 0;

if (!skb)
	return NULL;

if (*reinject) {
	*subsk = ratio_get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	return skb;
}


retry:
/* First, we look for a subflow who is currently being used */
//mptcp_for_each_sk(mpcb, mk_it) {
mptcp_for_each_sub(mpcb, mptcp) {
	struct sock *sk_it = mptcp_to_sock(mptcp);
	struct tcp_sock *tp_it = tcp_sk(sk_it);
	struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
	const struct inet_sock *inet = inet_sk(sk_it);
	union {
		struct sockaddr     raw;
		struct sockaddr_in  v4;
		struct sockaddr_in6 v6;
	} dst;

	counter++;

	tcp_probe_copy_fl_to_si4(inet, dst.v4, d);
	if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited)){
		//printk("flow rejected");
		continue;
	}

	//printk("pass %u: quota: %u snd_nxt: %u snd_una: %u write_seq: %u copied_seq: %u", counter, rsp->quota, tp_it->snd_nxt, tp_it->snd_una, tp_it->write_seq, tp_it->copied_seq);

	iter++;

	if (counter % 2) {
		if (meta_tp->num_segments_flow_one == 0) {
			full_subs++;
			continue;
		}

		/* Is this subflow currently being used? */
		if (rsp->quota > 0 && rsp->quota < meta_tp->num_segments_flow_one) {
			split = meta_tp->num_segments_flow_one - rsp->quota;
			choose_sk = sk_it;
			goto found;
		}

		/* Or, it's totally unused */
		if (!rsp->quota) {
			split = meta_tp->num_segments_flow_one;
			choose_sk = sk_it;
		}

		/* Or, it must then be fully used  */
		if (rsp->quota >= meta_tp->num_segments_flow_one)
			full_subs++;
	} 
	else {
		if (num_segments - meta_tp->num_segments_flow_one == 0) {
			full_subs++;
			continue;
		}  

		/* Is this subflow currently being used? */
		if (rsp->quota > 0 && rsp->quota < (num_segments - meta_tp->num_segments_flow_one)) {
			split = (num_segments - meta_tp->num_segments_flow_one) - rsp->quota;
			choose_sk = sk_it;
			goto found;
		}

		/* Or, it's totally unused */
		if (!rsp->quota) {
			split = num_segments - meta_tp->num_segments_flow_one;
			choose_sk = sk_it;
		}

		/* Or, it must then be fully used  */
		if (rsp->quota >= (num_segments - meta_tp->num_segments_flow_one))
			full_subs++;
	}
}

/* All considered subflows have a full quota, and we considered at
 * least one.
 */
if (iter && iter == full_subs) {
	/* So, we restart this round by setting quota to 0 and retry
	 * to find a subflow.
	 */
	//mptcp_for_each_sk(mpcb, sk_it) {
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);

		if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited))
			continue;

		rsp->quota = 0;
	}
	//num_segments_flow_one = meta_tp->num_segments_flow_one;
	goto retry;
}

found:
if (choose_sk) {
	unsigned int mss_now;
	struct tcp_sock *choose_tp = tcp_sk(choose_sk);
	struct ratio_sched_priv *rsp = ratio_sched_get_priv(choose_tp);
	const struct inet_sock *inet = inet_sk(choose_sk);

	union {
		struct sockaddr     raw;
		struct sockaddr_in  v4;
		struct sockaddr_in6 v6;
	} dst;

	/*if (mpcb->cnt_established == 2) {

	  if (choose_sk != meta_tp->prev_sk) {
	//printk("choose_sk != meta_tp->prev_sk");
	if (meta_tp->prev_sk) {
	struct tcp_sock *prev_tp = tcp_sk(meta_tp->prev_sk);
	struct ratio_sched_priv *prev_rsp = ratio_sched_get_priv(prev_tp);
	//printk("prev_accounted: %u prev_accounting: %u", prev_rsp->is_init_accounted, prev_rsp->is_accounting);
	if (!prev_rsp->is_init_accounted && prev_rsp->is_accounting) {
	struct timeval tv_now, tv_diff;
	do_gettimeofday(&tv_now);
	//printk("%pI4 subtraction 1", &inet_sk(meta_tp->prev_sk)->inet_daddr);
	timersub(&tv_now, &prev_rsp->write_seq_tv, &tv_diff);
	prev_rsp->write_seq_tv = tv_diff;
	prev_rsp->is_init_accounted = true;
	//printk("is_init_accounted");
	} 
	}
	if (!rsp->is_accounting) {
	//printk("%pI4 init", &inet_sk(choose_sk)->inet_daddr);
	u32 sub_write_seq[2] = {0,0}, sub_snd_nxt[2] = {0,0}, sub_snd_una[2] = {0,0};
	u32 loop_counter = 0;
	do_gettimeofday(&rsp->write_seq_tv);
	rsp->write_seq_saved = meta_tp->snd_nxt;
	mptcp_for_each_sk(mpcb, sk_it) {
	struct tcp_sock *tp = tcp_sk(sk_it);
	sub_write_seq[loop_counter] = tp->write_seq;
	sub_snd_nxt[loop_counter] = tp->snd_nxt;
	sub_snd_una[loop_counter] = tp->snd_una;
	loop_counter++;
	}

	//printk("usecs: %lu, meta->snd_nxt: %u, meta->write_seq: %u, meta->snd_una: %u, snd_nxt_ad: %u, write_seq_ad: %u, snd_una_ad: %u, snd_nxt_ac: %u, write_seq_ac: %u, snd_una_ac: %u, is_init_accounted: %u", rsp->write_seq_tv.tv_sec*1000000 + rsp->write_seq_tv.tv_usec, meta_tp->snd_nxt, meta_tp->write_seq, meta_tp->snd_una, sub_snd_nxt[0], sub_write_seq[0], sub_snd_una[0], sub_snd_nxt[1], sub_write_seq[1], sub_snd_una[1], rsp->is_init_accounted);


	meta_tp->prev_sk = choose_sk;
	rsp->is_accounting = true;
	}

	}*/

	//printk("%d %d", completion_times[0], completion_times[1]);
	/*if (!rsp->is_accounting && choose_sk != meta_tp->prev_sk) {
	  u32 sub_write_seq[2] = {0,0}, sub_snd_nxt[2] = {0,0}, sub_snd_una[2] = {0,0};
	  u32 loop_counter = 0;
	  do_gettimeofday(&rsp->write_seq_tv);
	  rsp->write_seq_saved = meta_tp->snd_nxt;
	  mptcp_for_each_sk(mpcb, sk_it) {
	  struct tcp_sock *tp = tcp_sk(sk_it);
	  sub_write_seq[loop_counter] = tp->write_seq;
	  sub_snd_nxt[loop_counter] = tp->snd_nxt;
	  sub_snd_una[loop_counter] = tp->snd_una;
	  loop_counter++; 
	  }

	  printk("usecs: %lu, meta->snd_nxt: %u, meta->write_seq: %u, meta->snd_una: %u, snd_nxt_ad: %u, write_seq_ad: %u, snd_una_ad: %u, snd_nxt_ac: %u, write_seq_ac: %u, snd_una_ac: %u", rsp->write_seq_tv.tv_sec*1000000 + rsp->write_seq_tv.tv_usec, meta_tp->snd_nxt, meta_tp->write_seq, meta_tp->snd_una, sub_snd_nxt[0], sub_write_seq[0], sub_snd_una[0], sub_snd_nxt[1], sub_write_seq[1], sub_snd_una[1]);


	  meta_tp->prev_sk = choose_sk;
	  rsp->is_accounting = true;
	  }*/
	//}

	if (!mptcp_ratio_is_available(choose_sk, skb, false, true))
		return NULL;

	//printk("pass quota: %u snd_nxt: %u snd_una: %u write_seq: %u copied_seq: %u", rsp->quota, choose_tp->snd_nxt, choose_tp->snd_una, choose_tp->write_seq, choose_tp->copied_seq);

	tcp_probe_copy_fl_to_si4(inet, dst.v4, d);
	*subsk = choose_sk;
	mss_now = tcp_current_mss(*subsk);
	*limit = split * mss_now;

	if (skb->len > mss_now)
		rsp->quota += DIV_ROUND_UP(skb->len, mss_now);
	else
		rsp->quota++;

#ifdef MPTCP_SCHED_PROBE
	iter = total_rate = rate_ad = rate_ac = 0;
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		u32 subflow_rate, subflow_intv;
		u64 subflow_rate64 = 0;
		//struct dst_entry *dst;
		//struct netdev_queue *txq0;
		//struct rtnl_link_stats64 temp;
		//struct rtnl_link_stats64 *stats;

		mptcp_sched_probe_init(&sprobe);
		iter++;

		subflow_rate = READ_ONCE(tp_it->rate_delivered);
		subflow_intv = READ_ONCE(tp_it->rate_interval_us);
		if (subflow_rate && subflow_intv) {
			subflow_rate64 = (u64)subflow_rate * tp_it->mss_cache * USEC_PER_SEC;
			do_div(subflow_rate64, subflow_intv);
			subflow_rate64 *= 8;
			/*if (iter == 1) {
			  rate_ad += subflow_rate64;
			  } else {
			  rate_ac += subflow_rate64;
			  }*/

			if (subflow_rate64 != tp_it->last_ac_rate) { // Using last_ac_rate as last ac or ad rate
				if (iter == 1) {
					rate_ad += subflow_rate64;
					//printk("ad %pI4: %llu, %u, %u, count %u", &inet_sk(meta_sk)->inet_daddr, subflow_rate64, subflow_rate, subflow_intv, tp_it->in_probe);
				} else {
					rate_ac += subflow_rate64;
					//printk("ac %pI4: %llu, %u, %u, count %u", &inet_sk(meta_sk)->inet_daddr, subflow_rate64, subflow_rate, subflow_intv, tp_it->in_probe);
				} 
				tp_it->last_ac_rate = subflow_rate64;
				do_div(subflow_rate64, 1000000);
				tp_it->rate_est_val += subflow_rate64;
				tp_it->rate_est_cnt++;
				tp_it->in_probe = 0;
				total_rate += subflow_rate64;
			} else
				tp_it->in_probe++;
			//total_rate += subflow_rate64;
		}

		//qSize = get_queue_size(sk_it, meta_tp);
		/*dst = sk_dst_get(sk_it);

		//if (dst->dev) {
		stats = dev_get_stats(dst->dev, &temp);

		txq0 = netdev_get_tx_queue(dst->dev, 0); //get txqueueu from dst

		sprobe.tx_bytes = stats->tx_bytes;
		sprobe.trans_start = txq0->trans_start;*/

		if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited)) sprobe.temp_unavailable = true;

		if (choose_sk == sk_it) {
			mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk_it);
		}
		else mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk_it);
	}

	/* AUTO-RATE search */
	do_div(total_rate, 1000000);
	//do_div(rate_ad, 1000000);
	//do_div(rate_ac, 1000000);
	//meta_tp->high_seq += rate_ad;
	//meta_tp->undo_marker += rate_ac;
	meta_tp->rate_delivered += total_rate;
	meta_tp->delivered++;

	/*if (meta_tp->ratio_rate_sample == 800) {
	  printk("Total_rate yo: %u, Rate_delivered also: %u", total_rate, meta_tp->rate_delivered);
	  }*/

	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
		struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
		rsp_temp->buffer_size += (tp_it_temp->write_seq - tp_it_temp->snd_una);
		rsp_temp->delivered++;
	}

	time_diff = jiffies_to_msecs(jiffies - meta_tp->rate_interval_us);    
	if (time_diff >= meta_tp->ratio_rate_sample) {
		//do_div(meta_tp->rate_delivered, meta_tp->delivered);
		//do_div(meta_tp->high_seq, meta_tp->delivered);
		//do_div(meta_tp->undo_marker, meta_tp->delivered);

		// Recycle unused variables in the meta_tp struct
		//last_rate = meta_tp->snd_cwnd;
		last_rate = meta_tp->prr_out;
		//ref_rate = meta_tp->prior_cwnd; // <- FOR MEAN OF RUNNING DIFFERENCE (PUT BACK FOR OLD REFERENCE SCHEDULER)
		//best_rate = meta_tp->prr_delivered;
		//best_ratio = meta_tp->prr_out;
		trigger_threshold = meta_tp->prr_delivered;
		// rate_search_0 = meta_tp->prr_delivered;
		// rate_search_100 = meta_tp->prr_out;
		in_search = meta_tp->lost;
		threshold_cnt = (meta_tp->snd_ssthresh == INT_MAX) ? 0 : meta_tp->snd_ssthresh;
		buffer_threshold_cnt = meta_tp->buffer_threshold_cnt;
		last_trigger_tstamp = meta_tp->prior_ssthresh;
		//thresh_cnt_reset = meta_tp->snd_cwnd_used;
		//last_buffer_size = meta_tp->snd_cwnd_used;

		// RUNNING DIFFERENCE
		//curr_diff = meta_tp->undo_retrans;
		count_set_init_rate = meta_tp->total_retrans;
		init_rate = meta_tp->prior_cwnd;
		memcpy(init_buffer_size, meta_tp->init_buffer_size, 2*sizeof(u32));
		//init_buffer_size = &(meta_tp->init_buffer_size);
		memcpy(last_buffer_size, meta_tp->last_buffer_size, 2*sizeof(u32));
		//last_buffer_size = &(meta_tp->last_buffer_size);

		// Queue-based rate estimate
		/*mptcp_for_each_sk(mpcb, sk_it) {
		  meta_tp->rate_delivered = get_queue_size(sk_it, meta_tp);
		  meta_tp->high_seq = meta_tp->rate_delivered;
		  meta_tp->undo_marker = meta_tp->rate_delivered;
		  break;
		//printk("cwnd: %u, packets: %u, app_limited:%u\n", tcp_sk(sk_it)->snd_cwnd, tcp_packets_in_flight(tcp_sk(sk_it)), sk_wmem_alloc_get(sk_it) < SKB_TRUESIZE(1));
		}*/

		iter = 0;
		//u32 tput[2] = {0, 0};
		meta_tp->rate_delivered = 0; 
		mptcp_for_each_sub(mpcb, mptcp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);
			struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
			struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
			u32 subflow_rate, subflow_intv, curr_tstamp;
			u64 subflow_rate64 = 0;
			do_div(rsp_temp->buffer_size, meta_tp->delivered);
			curr_tstamp = jiffies;
			subflow_rate = tp_it_temp->delivered - tp_it_temp->prev_tx_bytes;
			tp_it_temp->prev_tx_bytes = tp_it_temp->delivered;
			subflow_intv = jiffies_to_msecs(curr_tstamp - tp_it_temp->prev_tstamp);
			tp_it_temp->prev_tstamp = curr_tstamp;
			subflow_rate64 = (u64)subflow_rate * tp_it_temp->mss_cache * 8 * MSEC_PER_SEC;
			do_div(subflow_rate64, subflow_intv);
			do_div(subflow_rate64, 1000000);
			//if (tp_it_temp->rate_est_cnt != 0)
			//do_div(tp_it_temp->rate_est_val, tp_it_temp->rate_est_cnt);
			//tput[iter] = tp_it_temp->rate_est_val;
			tput[iter] = subflow_rate64;
			meta_tp->rate_delivered += tput[iter];
			//tput[loop_counter] = (tp_it_temp->snd_una - rsp_temp->snd_una_saved)*8;
			//do_div(tput[loop_counter], 100000);
			//printk("%u: snd_una_tput: %u", loop_counter+1, tput[loop_counter]);
			rsp_temp->snd_una_saved = tp_it_temp->snd_una;
			//rsp_temp->buffer_size = 0;
			iter++;

			//printk("write_seq_saved: %u, write_seq: %u, snd_una: %u", rsp_temp->write_seq_saved, tp_it_temp->write_seq, tp_it_temp->snd_una);
		}

		for (iter = 0; iter < 3; iter++) {
			if (iter == 2)
				meta_tp->last_rate_search_start[iter] = meta_tp->rate_delivered;
			else
				meta_tp->last_rate_search_start[iter] = meta_tp->last_rate_search_start[iter+1];
		}
		//if (tput[0] && tput[1]) {
		//    printk("tput ratio: %u", 100*tput[0]/(tput[0]+tput[1]));
		//}
		//loop_counter = 0;
		if (inet_sk(meta_sk)->inet_daddr)
			printk("daddr: %pI4, num_samples: %u, ratio: %d, rate_ad: %u, rate_ac: %u, rate_total: %u\n", &inet_sk(meta_sk)->inet_daddr, meta_tp->delivered, meta_tp->num_segments_flow_one, tput[0], tput[1], meta_tp->rate_delivered);
		else
			printk("daddr NULL, num_samples: %u, ratio: %d, rate_ad: %u, rate_ac: %u, rate_total: %u\n", meta_tp->delivered, meta_tp->num_segments_flow_one, tput[0], tput[1], meta_tp->rate_delivered);

		printk("rate_thresh_cnt: %d, buffer_thresh_cnt: %d, count_init: %u, last_rate: %u, last_trigger_tstamp: %u\n", threshold_cnt, buffer_threshold_cnt, count_set_init_rate, last_rate, last_trigger_tstamp);
		//else
		//printk("ratio:%u, meta_rate: %u, cnt: %d, curr_diff: %d, rate_ad: %u, rate_ac: %u, count_init: %u, last_rate: %u, last_trigger_tstamp: %u\n", sysctl_num_segments_flow_one, meta_tp->rate_delivered, threshold_cnt, meta_tp->undo_retrans, meta_tp->high_seq, meta_tp->undo_marker, count_set_init_rate, last_rate, last_trigger_tstamp);

		/*if (meta_tp->in_probe) {
		  if (num_segments_flow_one == 100) {
		  printk("ubwins: in probe 100\n");
		  if (rate_search_100 < sample_skip_ad)
		  rate_search_100++;
		  else if (rate_search_100 == sample_skip_ad)
		  rate_search_100 = meta_tp->high_seq;
		  else {
		  rate_search_100 += meta_tp->high_seq;
		  num_segments_flow_one = (rate_search_100 * 100) / (rate_search_100 + rate_search_0);
		  printk("New ratio: %u\n", num_segments_flow_one);
		  meta_tp->in_probe = 0;
		  meta_tp->last_ac_rate = rate_search_0/2;
		  best_rate = 0;
		  best_ratio = 0;
		  last_rate = 0;
		  threshold_cnt = 0;
		  thresh_cnt_reset = 0;
		  curr_diff = 0;
		  count_set_init_rate = 0;
		  init_rate = 0;
		  rate_search_0 = 0;
		  rate_search_100 = 0;

		  goto reset;
		  }
		  }
		  else if (num_segments_flow_one == 0) {
		  printk("ubwins: in probe 0\n");
		  if (rate_search_0 < sample_skip_ac)
		  rate_search_0++;
		  else if (rate_search_0 == sample_skip_ac)
		  rate_search_0 = meta_tp->undo_marker;
		  else {
		  rate_search_0 += meta_tp->undo_marker;
		  if (abs(meta_tp->last_ac_rate - rate_search_0/2) > sysctl_mptcp_trigger_threshold) {
		  printk("last_ac_rate: %u, current rate: %u, difference: %d\n", meta_tp->last_ac_rate, rate_search_0/2, meta_tp->last_ac_rate - rate_search_0/2);
		  num_segments_flow_one = 100;
		  } else {
		  num_segments_flow_one = meta_tp->last_ratio;
		  rate_search_0 = 0;
		  meta_tp->in_probe = 0; 
		  }
		  }
		  }
		  }*/

		/*if (!in_search && !(meta_tp->in_probe) && jiffies_to_msecs(jiffies - meta_tp->last_probe_tstamp)/1000 > sysctl_mptcp_probe_interval && last_trigger_tstamp) {
		  meta_tp->in_probe = true;
		  last_trigger_tstamp = meta_tp->last_probe_tstamp = jiffies;
		  meta_tp->last_ratio = num_segments_flow_one;
		  num_segments_flow_one = 0;
		  }*/



		//if (!in_search && !(meta_tp->in_probe) && !last_rate && last_trigger_tstamp) {
		//if (!in_search && !last_rate && last_trigger_tstamp) {
		if (!in_search && !last_rate) {
			count_set_init_rate++;
			printk("Entered: In search = 0, last rate = 0");
			if (count_set_init_rate == 5) {
				//printk("");
				last_rate = init_rate;
				trigger_threshold = 15 * last_rate / 100;
				loop_counter = 0;
				meta_tp->buffer_trigger_threshold = 0;
				mptcp_for_each_sub(mpcb, mptcp) {
					//struct sock *sk_it = mptcp_to_sock(mptcp);
					//struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
					//struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
					meta_tp->buffer_trigger_threshold += init_buffer_size[loop_counter]; 
					last_buffer_size[loop_counter] = init_buffer_size[loop_counter];
					loop_counter++;
				}
				meta_tp->buffer_trigger_threshold = -15 * meta_tp->buffer_trigger_threshold / 100;
				count_set_init_rate = 0;
			} else {
				init_rate = (init_rate * (count_set_init_rate - 1) + meta_tp->rate_delivered) / count_set_init_rate;
				loop_counter = 0;
				mptcp_for_each_sub(mpcb, mptcp) {
					struct sock *sk_it = mptcp_to_sock(mptcp);
					struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
					struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
					init_buffer_size[loop_counter] = (init_buffer_size[loop_counter] * (count_set_init_rate - 1) + rsp_temp->buffer_size) / count_set_init_rate;
					loop_counter++;
				}
				goto reset; 
			}
		}


		// AUTO TRIGGER 
		/*if (!in_search && !(meta_tp->in_probe) && last_rate) {

		  curr_diff += (meta_tp->rate_delivered - last_rate);

		  if (abs(curr_diff) >= sysctl_mptcp_trigger_threshold)
		  threshold_cnt++;
		  else 
		  threshold_cnt = 0;

		  if (threshold_cnt == 5) {
		  mptcp_for_each_sk(mpcb, sk_it) {
		  if (tcp_in_slow_start(tcp_sk(sk_it))) {
		  printk("in slow start\n");
		  goto nosearch;
		  }
		  }

		  if (jiffies_to_msecs(jiffies - last_trigger_tstamp) <= 5000) {
		  printk("less than 3 seconds\n");
		  goto nosearch;
		  }

		  printk("Search triggered\n");
		  in_search = true;
		  meta_tp->last_probe_tstamp = last_trigger_tstamp = jiffies;
		// sysctl_num_segments_flow_one = 5; // FOR OLD REFERENCE BASED ALGORITHM
		sysctl_num_segments_flow_one = 100; // FOR 100/0 RATIO
		goto reset;
nosearch:
printk("Search skipped\n");
last_rate = 0;
curr_diff = 0;
threshold_cnt = 0;
count_set_init_rate = 0;
init_rate = 0;
goto reset;
}

}*/

// Manual Trigger 
/*if (sysctl_mptcp_ratio_trigger_search) {
  in_search = true;
  meta_tp->last_probe_tstamp = last_trigger_tstamp = jiffies;
  sysctl_mptcp_ratio_trigger_search = 0;
  sysctl_num_segments_flow_one = 5; // FOR OLD REFERENCE BASED ALGORITHM
//sysctl_num_segments_flow_one = 100; // FOR 100/0 RATIO SEARCH
//mptcp_for_each_sk(mpcb, sk_it) {
//struct tcp_sock *tp = tcp_sk(sk_it);
if (!i) { i++; continue; }
i = 0;
printk("setting ac pf 1\n");
//tp->pf = 1;
blocked_sk = sk_it;
break;
}
last_rate = 0;

goto reset;
}*/
if (sysctl_mptcp_ratio_trigger_search) {//Manual trigger
	sysctl_mptcp_ratio_trigger_search = 0;
	goto search_start;
}


if (sysctl_mptcp_probe_interval_secs && last_trigger_tstamp && (jiffies_to_msecs(jiffies - last_trigger_tstamp) >= sysctl_mptcp_probe_interval_secs*1000)) {
	printk("Periodic Search\n");
	goto search_start;
}
/*if (in_search) {
  int flag = 0;
  mptcp_for_each_sk(mpcb, sk_it) {
//struct tcp_sock *tp = tcp_sk(sk_it);
if (blocked_sk == sk_it) { flag = 1; }
printk("flag: %d\n", flag);
break;
//if (!tp->pf) printk("pf not set\n");
}
printk("flag: %d\n", flag);
if (!flag) {
//if (sysctl_num_segments_flow_one == 100) {
if (rate_search_100 < sample_skip_ad) {
printk("skipping ad samples...\n");
rate_search_100++;
}
else if (rate_search_100 == sample_skip_ad) {
printk("ad sample 1\n");
rate_search_100 = meta_tp->high_seq;
}
else {
int j = 0;
printk("ad sample 2\n");
rate_search_100 += meta_tp->high_seq;
//sysctl_num_segments_flow_one = 0;
mptcp_for_each_sk(mpcb, sk_it) {
//struct tcp_sock *tp = tcp_sk(sk_it);
if (!j) {
printk("set ad pf 1\n"); 
blocked_sk = sk_it;
//tp->pf = 1;
j++;
continue; 
}
//printk("set ac pf 0\n");
//tp->pf = 0;
break;
}
}
} else {//if (!sysctl_num_segments_flow_one) {
if (rate_search_0 < sample_skip_ac)
rate_search_0++;
else if (rate_search_0 == sample_skip_ac)
rate_search_0 = meta_tp->undo_marker;
else {
rate_search_0 += meta_tp->undo_marker;
sysctl_num_segments_flow_one = (rate_search_100 * 100) / (rate_search_100 + rate_search_0);
printk("New ratio: %u\n", num_segments_flow_one);
in_search = false;
meta_tp->last_ac_rate = rate_search_0/2;
best_rate = 0;
best_ratio = 0;
last_rate = 0;
threshold_cnt = 0;
thresh_cnt_reset = 0;
curr_diff = 0;
count_set_init_rate = 0;
init_rate = 0;
rate_search_0 = 0;
rate_search_100 = 0;
//mptcp_for_each_sk(mpcb, sk_it) {
//    struct tcp_sock *tp = tcp_sk(sk_it);
//    tp->pf = 0;
//}
blocked_sk = NULL;

goto reset;

}
}


if (meta_tp->rate_delivered > best_rate) {
	best_rate = meta_tp->rate_delivered;
	best_ratio = sysctl_num_segments_flow_one;
}

sysctl_num_segments_flow_one += sysctl_mptcp_ratio_search_step;

if (sysctl_num_segments_flow_one >= 100) {
	printk("Search ended with %u\n", best_ratio);

	in_search = false;
	sysctl_num_segments_flow_one = best_ratio;
	best_rate = 0;
	best_ratio = 0;
	last_rate = 0;
	threshold_cnt = 0;
	thresh_cnt_reset = 0;
	curr_diff = 0;
	count_set_init_rate = 0;

	goto reset;
}
}*/

// OLD REFERENCE-RATE BASED ALGORITHM
//printk("thresh_cnt_reset: %u\n", thresh_cnt_reset); 

/*mptcp_for_each_sk(mpcb, sk_it) {
  meta_tp->rate_delivered = get_queue_size(sk_it);
  break;
//printk("cwnd: %u, packets: %u, app_limited:%u\n", tcp_sk(sk_it)->snd_cwnd, tcp_packets_in_flight(tcp_sk(sk_it)), sk_wmem_alloc_get(sk_it) < SKB_TRUESIZE(1));
}*/

//printk("ratio:%u, meta_rate: %u, cnt: %d, ref_rate: %u, rate_ad: %u, rate_ac: %u\n", sysctl_num_segments_flow_one, meta_tp->rate_delivered, threshold_cnt, ref_rate, meta_tp->high_seq, meta_tp->undo_marker);


if (!meta_tp->rate_delivered && !last_rate) {
	in_search = false;
	goto reset;
}

// Trigger search or not
//printk("in_search:%d",in_search);
//printk("last_rate: %d", last_rate);
//printk("sysctl_mptcp_ratio_static %d",sysctl_mptcp_ratio_static);
if (!in_search && last_rate && !sysctl_mptcp_ratio_static) {
	//diff_last = (int)last_rate - (int)meta_tp->rate_delivered;

	rate_diff = (int)meta_tp->rate_delivered - (int)init_rate;
	//printk("Rate diff yo : %d, systhresh: %d", rate_diff,sysctl_mptcp_trigger_threshold);
	//printk("Cur rate - init_rate: %d - %f", meta_tp->rate_delivered, init_rate);
	//if (abs(diff_last) > sysctl_mptcp_trigger_threshold || !threshold_cnt)

	buffer_total = 0, init_buffer_total = 0;
	loop_counter = 0;
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
		struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
		buffer_total += rsp_temp->buffer_size;
		init_buffer_total += init_buffer_size[loop_counter++];
	}
	buffer_diff = (int)buffer_total - (int)init_buffer_total;
	//printk("Curr_diff: %d, Buffer_diff: %d, Rate Trigger Threshold: %u", rate_diff, buffer_diff, trigger_threshold);
	//if (abs(rate_diff) > sysctl_mptcp_trigger_threshold) {
if (abs(rate_diff) > trigger_threshold) {
	buffer_threshold_cnt = 0;
	//printk("Cur rate - init_rate: %d - %f", meta_tp->rate_delivered, init_rate);
	threshold_cnt++;
	//} else if (buffer_diff < -75000) {
} else if (buffer_diff < meta_tp->buffer_trigger_threshold) {
	threshold_cnt = 0;
	buffer_threshold_cnt++;
} else {
	buffer_threshold_cnt = 0;
	threshold_cnt = 0;
}
/*diff_ref = (int)ref_rate - (int)meta_tp->rate_delivered;

  if (abs(diff_ref) > sysctl_mptcp_trigger_threshold) {
  if (diff_ref > 0) threshold_cnt--;
  else threshold_cnt++;
  }*/

/*if (abs(diff_last) > sysctl_mptcp_trigger_threshold && abs(threshold_cnt) > 1) {
  ref_rate = meta_tp->rate_delivered;
  threshold_cnt = 0;
  }*/

/*if (threshold_cnt && abs(diff_last) < sysctl_mptcp_trigger_threshold) thresh_cnt_reset++;

  if (!threshold_cnt) thresh_cnt_reset = 0;

  if (thresh_cnt_reset == 7) {
  threshold_cnt = 0;
  thresh_cnt_reset = 0;
  }*/

if (!meta_tp->init_search) {
	printk("INITIAL SEARCH\n");
	meta_tp->init_search = true;
	goto search_start;
}

// YES
if (buffer_threshold_cnt == 5 || threshold_cnt == 3) {
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		if (tcp_in_slow_start(tcp_sk(sk_it))) {
			printk("in slow start\n");
			goto nosearch;
		}
	}

	if (jiffies_to_msecs(jiffies - last_trigger_tstamp) <= 2000) {
		printk("less than 2 seconds\n");
		goto nosearch;
	}
search_start:
	printk("SEARCH START:\n");
	if(buffer_threshold_cnt==5)
	{
		printk("DECREASED SEND QUEUE\n");
	}
	else if(threshold_cnt==3)
	{
		printk("DECREASED THROUGHPUT\n");
	}
	else 
	{
		printk("INITIAL or PERIODIC SEARCH\n");
	}
	in_search = true;
	threshold_cnt = 0;
	buffer_threshold_cnt = 0;
	//meta_tp->ratio_rate_sample = 200;
	meta_tp->ratio_rate_sample = meta_tp->ratio_rate_sample*2;
	last_trigger_tstamp = jiffies;
	if (meta_tp->num_segments_flow_one < (100 - abs(meta_tp->ratio_search_step))) {
		meta_tp->search_state = RIGHT_RATIO_SET;
		meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
	}
	else {
		meta_tp->search_state = SEARCH_RATE;
		meta_tp->ratio_search_step = -1*abs(meta_tp->ratio_search_step);
		meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
	}
	last_rate = 0;
	for (iter = 0; iter < 3; iter++)
		last_rate += meta_tp->last_rate_search_start[iter];
	do_div(last_rate, 3);
	goto reset;
nosearch:
	printk("NO SEARCH\n");
	last_rate = 0;
	threshold_cnt = 0;
	buffer_threshold_cnt = 0;
	goto reset;
}

}

// Manual Trigger 
/*if (sysctl_mptcp_ratio_trigger_search) {
  in_search = true;
  sysctl_mptcp_ratio_trigger_search = 0;
  meta_tp->num_segments_flow_one = 1;
  last_rate = 0;

  goto reset;
  }*/


if (in_search) {
	switch(meta_tp->search_state) {
		case RIGHT_RATIO_SET:
			printk("RIGHT_RATIO_SET");
			if (meta_tp->rate_delivered > last_rate + 5) {
				if (meta_tp->num_segments_flow_one + meta_tp->ratio_search_step < 100) {
					meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
					meta_tp->search_state = SEARCH_RATE;
				} else {
					last_rate = 0;
					in_search = false;
					//meta_tp->ratio_rate_sample = 100;
					meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
					goto reset;
				}
			} else if (meta_tp->num_segments_flow_one - 2*meta_tp->ratio_search_step > 0) {
				meta_tp->num_segments_flow_one -= 2*meta_tp->ratio_search_step;
				meta_tp->search_state = LEFT_RATIO_SET;
				goto reset;
			} else {
				meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step;
				last_rate = 0;
				//meta_tp->ratio_rate_sample = 100;
				meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
				in_search = false;
				goto reset;
			}
			break;
		case LEFT_RATIO_SET:
			printk("LEFT_RATIO_SET");
			if (meta_tp->rate_delivered > last_rate + 5) {
				meta_tp->ratio_search_step = -1*abs(meta_tp->ratio_search_step);
				if (meta_tp->num_segments_flow_one > abs(meta_tp->ratio_search_step)) {
					meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
					meta_tp->search_state = SEARCH_RATE;
				} else {
					last_rate = 0;
					in_search = false;
					//meta_tp->ratio_rate_sample = 100;
					meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
					goto reset;
				}
			} else {
				meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
				last_rate = 0;
				//meta_tp->ratio_rate_sample = 100;
				meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
				in_search = false;
				goto reset;
			}
			break;
		case SEARCH_RATE:
			printk("SEARCH_RATE");
			if (meta_tp->rate_delivered < last_rate) {
				//printk("meta_tp->rate_delivered < last_rate"); 
				meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step;
				meta_tp->ratio_search_step = abs(meta_tp->ratio_search_step);
				if (meta_tp->num_segments_flow_one + meta_tp->ratio_search_step/2 < 100) {
					meta_tp->num_segments_flow_one += meta_tp->ratio_search_step/2;
					meta_tp->search_state = RIGHT_RATIO_FINE;
				} else {
					meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step/2;
					meta_tp->search_state = LEFT_RATIO_FINE;
				}
				goto reset;
			} else {
				//printk("meta_tp->rate_delivered > last_rate");
				if (meta_tp->num_segments_flow_one + meta_tp->ratio_search_step < 100 && meta_tp->num_segments_flow_one + meta_tp->ratio_search_step > 0)
					meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
				else {
					last_rate = 0;
					in_search = false;
					//meta_tp->ratio_rate_sample = 100;
					meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
					goto reset;
				}
			}
			break;
		case RIGHT_RATIO_FINE:
			printk("RIGHT_RATIO_FINE");
			if (meta_tp->rate_delivered > last_rate + 5) {
				last_rate = 0;
				in_search = false;
				//meta_tp->ratio_rate_sample = 100;
				meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
			} else {
				if (meta_tp->num_segments_flow_one > meta_tp->ratio_search_step) {
					meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step;
					meta_tp->search_state = LEFT_RATIO_FINE;
				} else {
					meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step/2;
					last_rate = 0;
					in_search = false;
					//meta_tp->ratio_rate_sample = 100;
					meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
				}
			}
			goto reset;
			break;
		case LEFT_RATIO_FINE:
			printk("LEFT_RATIO_FINE");
			if (meta_tp->rate_delivered <= last_rate + 5) {
				meta_tp->num_segments_flow_one += meta_tp->ratio_search_step/2;
			}
			last_rate = 0;
			in_search = false;
			//meta_tp->ratio_rate_sample = 100;
			meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
			goto reset;
			break;
	}
	/*if (meta_tp->rate_delivered > best_rate) {
	  best_rate = meta_tp->rate_delivered;
	  best_ratio = meta_tp->num_segments_flow_one;
	  }

	  meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;

	  if (num_segments_flow_one >= 100) {
	  printk("Search ended with %u\n", best_ratio);

	  in_search = false;
	  meta_tp->num_segments_flow_one = best_ratio;
	  best_rate = 0;
	  best_ratio = 0;
	  last_rate = 0;
	  threshold_cnt = 0;
	//thresh_cnt_reset = 0;

	goto reset;
	}*/
}

last_rate = meta_tp->rate_delivered;
reset:
//meta_tp->snd_cwnd = last_rate;
meta_tp->prr_out = last_rate;
// meta_tp->prior_cwnd = ref_rate;
// meta_tp->prr_delivered = best_rate;
// meta_tp->prr_out = best_ratio;
meta_tp->prr_delivered = trigger_threshold;
//meta_tp->prr_delivered = rate_search_0;
//meta_tp->prr_out = rate_search_100;
meta_tp->lost = in_search;
meta_tp->snd_ssthresh = threshold_cnt;
meta_tp->buffer_threshold_cnt = buffer_threshold_cnt;
meta_tp->prior_ssthresh = last_trigger_tstamp;
//meta_tp->snd_cwnd_used = thresh_cnt_reset;
//meta_tp->snd_cwnd_used = last_buffer_size;
//meta_tp->undo_retrans = curr_diff;
meta_tp->total_retrans = count_set_init_rate;
meta_tp->prior_cwnd = init_rate;
//meta_tp->init_buffer_size = &init_buffer_size;
memcpy(meta_tp->init_buffer_size, init_buffer_size, 2*sizeof(u32));
//meta_tp->last_buffer_size = &last_buffer_size;
memcpy(meta_tp->last_buffer_size, last_buffer_size, 2*sizeof(u32));
meta_tp->delivered = 0;
meta_tp->rate_delivered = 0;
meta_tp->high_seq = 0;
meta_tp->undo_marker = 0;
mptcp_for_each_sub(mpcb, mptcp) {
	struct sock *sk_it = mptcp_to_sock(mptcp);
	struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
	tp_it_temp->rate_est_val = 0;
	tp_it_temp->rate_est_cnt = 0;
}
meta_tp->rate_interval_us = jiffies;

}
// AUTO-RATE search 

mptcp_for_each_sub(mpcb, mptcp) {
	struct sock *sk_it = mptcp_to_sock(mptcp);
	mptcp_sched_probe_init(&sprobe);
	sched_probe_id = ULONG_MAX;
	if (choose_sk == sk_it) {
		sprobe.split = split;
		sprobe.skblen = DIV_ROUND_UP(skb->len, mss_now);
		mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk_it);
		break;
	}
}
#endif
return skb;
}
#ifdef MPTCP_SCHED_PROBE
iter = 0;
mptcp_for_each_sub(mpcb, mptcp) {
	struct sock *sk_it = mptcp_to_sock(mptcp);
	mptcp_sched_probe_init(&sprobe);
	iter++;

	if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited)) sprobe.temp_unavailable = true;

	if (choose_sk == sk_it) {
		mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk_it);
	}
	else mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk_it);
}
#endif
return NULL;
}

static struct mptcp_sched_ops mptcp_sched_ratio = {
	.get_subflow = ratio_get_available_subflow,
	.next_segment = mptcp_ratio_next_segment,
	.name = "ratio",
	.owner = THIS_MODULE,
};

static int __init ratio_register(void)
{
	BUILD_BUG_ON(sizeof(struct ratio_sched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_ratio))
		return -1;

	num_segments_flow_one = sysctl_num_segments_flow_one;
	printk("ratio scheduler init. with params: num_segments: %u, cwnd_limited: %u\n", num_segments, cwnd_limited);

	return 0;
}


static void ratio_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_ratio);
}

module_init(ratio_register);
module_exit(ratio_unregister);

MODULE_AUTHOR("Swetank Kumar Saha");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RATIO MPTCP");
MODULE_VERSION("0.02");
