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

u8 sample_skip_ad = 2, sample_skip_ac = 2;
struct sock *blocked_sk = NULL;
unsigned int num_segments_flow_one; //WILL THIS BE CREATED FOR EACH COPY?

/* If the sub-socket sk available to send the skb? */
static bool mptcp_ratio_is_available(struct sock *sk, const struct sk_buff *skb,
		bool zero_wnd_test, bool cwnd_test)
{
/*Availabity: in_flight<cwnd*/
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
	struct sock *sk=NULL, *bestsk = NULL, *backupsk = NULL;
	struct mptcp_tcp_sock *mptcp;
	/****/

#ifdef MPTCP_SCHED_PROBE
	struct mptcp_tcp_sock *mptcp_it;
	struct mptcp_sched_probe sprobe;
	unsigned long sched_probe_id;

	mptcp_sched_probe_init(&sprobe);
	get_random_bytes(&sched_probe_id, sizeof(sched_probe_id));
#endif

	if (mpcb->cnt_subflows == 1) {
	/* if there is only one subflow, bypass the scheduling function */
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_ratio_is_available(sk, skb, false, cwnd_limited))
			sk = NULL;
		return sk;
	}    

	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
			skb && mptcp_is_data_fin(skb)) {
	/* Answer data_fin on same subflow!!! */
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
	} 
	else if (backupsk) {
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
			meta_tp->prev_tx_bytes = stats->tx_bytes;
			meta_tp->prev_tstamp = txq0->trans_start;
		}

		packets_in_queue = dql0->num_queued - dql0->num_completed; //number of packets in DQL

	}
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
	struct sock *choose_sk=NULL;//chosen socket
	struct mptcp_tcp_sock *mptcp;//an mptcp_socket
	struct sk_buff *skb = __mptcp_ratio_next_segment(meta_sk, reinject);
	unsigned int split = num_segments;//
	unsigned char iter = 0, full_subs = 0, counter = 0;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	u32 total_rate, rate_ad, rate_ac; 
	u32 last_rate, in_search, last_trigger_tstamp, count_set_init_rate, init_rate;
	u32 buffer_total, init_buffer_total, trigger_threshold;
	u32 srtt[2]={0xffffffff,0xffffffff};
	u32 min_rtt[2]={0xffffffff,0xffffffff};
	u32 num_acks[2]={0,0};
	u32 num_acks_head[2]={0,0};
	int rate_diff, buffer_diff;
	int rate_diff_sub[2] = {0,0};
	int buffer_sub[2] = {0,0};
	u32 last_buffer_size[2] = {0, 0}, init_buffer_size[2] = {0, 0}, tput[2] = {0, 0};
	u16 head_length;
	u8 threshold_cnt;
	u8 buffer_threshold_cnt;
	unsigned int time_diff, loop_counter = 0;

#ifdef MPTCP_SCHED_PROBE
	struct mptcp_sched_probe sprobe;
	unsigned long sched_probe_id;

	get_random_bytes(&sched_probe_id, sizeof(sched_probe_id));
	mptcp_sched_probe_init(&sprobe);

#endif
	/*Intial parameter setup for meta_tp*/
	if (meta_tp->run_started == 0) {
		meta_tp->run_started = 1;
		num_segments_flow_one = meta_tp->num_segments_flow_one = sysctl_num_segments_flow_one;
		meta_tp->ratio_search_step = sysctl_mptcp_ratio_search_step;
		meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
		if(inet_sk(meta_sk)->inet_daddr)
			printk("MPTCP Run Started, destination: %pI4", &inet_sk(meta_sk)->inet_daddr);
		else
			printk("MPTCP Run Started");
	}


	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	if (*reinject) {
		/*Reinjected segment*/
		*subsk = ratio_get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;
	
		return skb;
	}

/*Schedule the next segment*/

retry:
	mptcp_for_each_sub(mpcb, mptcp) {
		/*Get scheduler private information*/
		struct sock *sk_it = mptcp_to_sock(mptcp);
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
		/***********************************/

		const struct inet_sock *inet = inet_sk(sk_it);
		union {
			struct sockaddr     raw;
			struct sockaddr_in  v4;
			struct sockaddr_in6 v6;
		} dst;

		
		counter++;//this is to keep track of subflow index
		tcp_probe_copy_fl_to_si4(inet, dst.v4, d); //useless

		/*Sanity check*/
		if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited)){
			//printk("flow rejected");
			continue;
		}

		/*Counter to compare with full_subs for round restart*/
		iter++;

		/* Check  subflow with odd index
		 * full_sub > 0: subflow reached full quota*/
		if (counter % 2) {
			if (meta_tp->num_segments_flow_one == 0) {
				full_subs++;
				continue;
			}

			/*This subflow is being used but not yet reached the quota*/
			if (rsp->quota > 0 && rsp->quota < meta_tp->num_segments_flow_one) {
				split = meta_tp->num_segments_flow_one - rsp->quota;
				choose_sk = sk_it;//choose this subflow
				goto found;
			}

			/*Nothing scheduled on this subflow yet: choose it*/
			if (!rsp->quota) {
				split = meta_tp->num_segments_flow_one;
				choose_sk = sk_it;
			}

			/* Or, it must then be fully used*/
			if (rsp->quota >= meta_tp->num_segments_flow_one)
				full_subs++;
		} 
		/* Consider the even-indexed subflows*/
		else {
			/*This subflow has reached full quota*/
			if (num_segments - meta_tp->num_segments_flow_one == 0) {
				full_subs++;
				continue;
			}  

			/*This subflow is being used but not yet reached the quota*/
			if (rsp->quota > 0 && rsp->quota < (num_segments - meta_tp->num_segments_flow_one)) {
				split = (num_segments - meta_tp->num_segments_flow_one) - rsp->quota;
				choose_sk = sk_it;
				goto found;
			}

			/*Nothing scheduled on this subflow yet*/
			if (!rsp->quota) {
				split = num_segments - meta_tp->num_segments_flow_one;
				choose_sk = sk_it;
			}

			/* Or, it must then be fully used  */
			if (rsp->quota >= (num_segments - meta_tp->num_segments_flow_one))
				full_subs++;
		}
	}

	/* All subflows reach quota, we restart this round by setting quota to 0 and retry
	 * to find a subflow.
	 */
	if (iter && iter == full_subs) {
		mptcp_for_each_sub(mpcb, mptcp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);

			if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited))
				continue;

			rsp->quota = 0;
		}
		goto retry;
	}

found:
	/*We have fould the chosen socket*/
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

		if (!mptcp_ratio_is_available(choose_sk, skb, false, true))
			return NULL;

		tcp_probe_copy_fl_to_si4(inet, dst.v4, d);
		*subsk = choose_sk;
		mss_now = tcp_current_mss(*subsk);
		*limit = split * mss_now;

		/*The number of quota would be how many segements that we decided to send
		 * on the choose_sk*/
		if (skb->len > mss_now)
			rsp->quota += DIV_ROUND_UP(skb->len, mss_now);
		else
			rsp->quota++;

		//printk("skb->len: %u, mss_now: %u, mss_cache: %u",skb->len , mss_now, choose_tp->mss_cache);
#ifdef MPTCP_SCHED_PROBE
		iter = total_rate = rate_ad = rate_ac = 0;
		
		/*Supposedly useless*/
		mptcp_for_each_sub(mpcb, mptcp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			u32 subflow_rate, subflow_intv;
			u64 subflow_rate64 = 0;

			mptcp_sched_probe_init(&sprobe);
			iter++;

			subflow_rate = READ_ONCE(tp_it->rate_delivered);
			subflow_intv = READ_ONCE(tp_it->rate_interval_us);
			if (subflow_rate && subflow_intv) {
				subflow_rate64 = (u64)subflow_rate * tp_it->mss_cache * USEC_PER_SEC;
				do_div(subflow_rate64, subflow_intv);
				subflow_rate64 *= 8;

				if (subflow_rate64 != tp_it->last_ac_rate) {
					if (iter == 1) {
						rate_ad += subflow_rate64;
					} else {
						rate_ac += subflow_rate64;
					} 
					tp_it->last_ac_rate = subflow_rate64;
					do_div(subflow_rate64, 1000000);
					tp_it->rate_est_val += subflow_rate64;
					tp_it->rate_est_cnt++;
					tp_it->in_probe = 0;
					total_rate += subflow_rate64;
				} else
					tp_it->in_probe++;
			}


			if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited)) sprobe.temp_unavailable = true;

			if (choose_sk == sk_it) {
				mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk_it);
			}
			else mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk_it);
		}/*Supposedly useless*/

		/* AUTO-RATE search */
		do_div(total_rate, 1000000);
		meta_tp->rate_delivered += total_rate;//no use
		meta_tp->delivered++;

		
		iter = 0;
		mptcp_for_each_sub(mpcb, mptcp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);
			struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
			struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
			rsp_temp->buffer_size += (tp_it_temp->write_seq - tp_it_temp->snd_una);
			buffer_sub[iter] = rsp_temp->buffer_size;
			rsp_temp->delivered++;
			iter++;
		}
		

		time_diff = jiffies_to_msecs(jiffies - meta_tp->rate_interval_us);    
		meta_tp->head_length = meta_tp->ratio_rate_sample/2;
		if(time_diff== meta_tp->head_length && meta_tp->lost){
			in_search = meta_tp->lost;
			//printk("Time elapsed since last change: %u", time_diff);
			iter = 0;
			mptcp_for_each_sub(mpcb, mptcp) {
				struct sock *sk_it = mptcp_to_sock(mptcp);
				struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
				u32 subflow_rate;
				subflow_rate = tp_it_temp->delivered - tp_it_temp->prev_tx_bytes;
				meta_tp->num_acks_head[iter] = subflow_rate;
				iter++;
			}
			//	printk("Number of ACKs collected: %u", 
			//		meta_tp->num_acks_head[0] + meta_tp->num_acks_head[1]);
		}

		/*start dynamic ratio search*/
		if (time_diff >= meta_tp->ratio_rate_sample) {
			/*Load parameter from previous probe interval*/
			last_rate = meta_tp->prr_out;//get last_rate from the container
			trigger_threshold = meta_tp->prr_delivered;
			in_search = meta_tp->lost;
			threshold_cnt = (meta_tp->snd_ssthresh == INT_MAX) ? 0 : meta_tp->snd_ssthresh;
			buffer_threshold_cnt = meta_tp->buffer_threshold_cnt;
			last_trigger_tstamp = meta_tp->prior_ssthresh;
			count_set_init_rate = meta_tp->total_retrans;
			init_rate = meta_tp->prior_cwnd;

			num_acks_head[0] = (in_search==0)? 0: meta_tp->num_acks_head[0];
			num_acks_head[1] = (in_search==0)? 0: meta_tp->num_acks_head[1];
			head_length = (num_acks_head[0]==0)? 0:meta_tp->head_length;
			//printk("head_length this period: %u, since search is %d",
			//	       	head_length, in_search);
			memcpy(init_buffer_size, meta_tp->init_buffer_size, 2*sizeof(u32));
			memcpy(last_buffer_size, meta_tp->last_buffer_size, 2*sizeof(u32));
			/*End loading*/

			iter = 0;
			meta_tp->rate_delivered = 0; //reset this container so that we can use it to calculate rate

			/*Value estimation for each interface*/
			mptcp_for_each_sub(mpcb, mptcp) {
				struct sock *sk_it = mptcp_to_sock(mptcp);
				struct tcp_sock *tp_it_temp = tcp_sk(sk_it);
				struct ratio_sched_priv *rsp_temp = ratio_sched_get_priv(tp_it_temp);
				u32 subflow_rate, subflow_intv, curr_tstamp;
				u64 subflow_rate64 = 0;
				do_div(rsp_temp->buffer_size, meta_tp->delivered);
				do_div(buffer_sub[iter], 1000);//KB
				curr_tstamp = jiffies;
				//printk("Original ACKs %llu", tp_it_temp->delivered-
				//		tp_it_temp->prev_tx_bytes);
				subflow_rate = abs(tp_it_temp->delivered - tp_it_temp->prev_tx_bytes - num_acks_head[iter]);//number of ACKs came back
				//printk("Deducted ACKs: %u", subflow_rate);
				num_acks[iter] = subflow_rate;
				tp_it_temp->prev_tx_bytes = tp_it_temp->delivered;
				subflow_intv = jiffies_to_msecs(curr_tstamp 
						- tp_it_temp->prev_tstamp)-head_length;
				tp_it_temp->prev_tstamp = curr_tstamp;
				subflow_rate64 = (u64)subflow_rate * tp_it_temp->mss_cache * 8 * MSEC_PER_SEC;
				do_div(subflow_rate64, subflow_intv);
				do_div(subflow_rate64, 1000000);//subflow_intv is in us
				srtt[iter] = tp_it_temp->srtt_us>>3;
				min_rtt[iter] = tcp_min_rtt(tp_it_temp);
				tput[iter] = subflow_rate64;
				meta_tp->rate_delivered += tput[iter];//cummulate rate on both interface
				rsp_temp->snd_una_saved = tp_it_temp->snd_una;
				iter++;
			}/*Value estimation for each interface*/

			for (iter = 0; iter < 5; iter++) {
				if (iter == 4)
					meta_tp->last_rate_search_start[iter] = meta_tp->rate_delivered;
				else
					meta_tp->last_rate_search_start[iter] = meta_tp->last_rate_search_start[iter+1];//keep shifting to get the updated rate
			}

			if (inet_sk(meta_sk)->inet_daddr)
			{
				printk("ratio: %d"
					", rate_ad: %u"
					", rate_ac: %u"
					", srtt_ad: %u"
					", srtt_ac: %u"
					", num_acks_ad: %u"
					", num_acks_ac: %u\n",
				       	meta_tp->num_segments_flow_one, 
					tput[0], 
					tput[1], 
					srtt[0], 
					srtt[1], 
					num_acks[0], 
					num_acks[1]);
				printk("rate_thresh_cnt: %d"
					", buffer_thresh_cnt: %d\n", 
					threshold_cnt, 
					buffer_threshold_cnt);
			}

			if (!in_search && !last_rate) {
				/*Calculate the initial rate got started*/
				count_set_init_rate++;//how many count do we like to average out for init rate
				printk("Entered: In search = 0, last rate = 0");//
				if (count_set_init_rate == 5) {
					last_rate = init_rate;
					trigger_threshold = 25 * last_rate / 100;
					loop_counter = 0;
					meta_tp->buffer_trigger_threshold = 0;
					mptcp_for_each_sub(mpcb, mptcp) {
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


			if (sysctl_mptcp_ratio_trigger_search) {
				/*Manual trigger using sysctl*/
				sysctl_mptcp_ratio_trigger_search = 0;
				goto search_start;
			}


			if (sysctl_mptcp_probe_interval_secs && last_trigger_tstamp && (jiffies_to_msecs(jiffies - last_trigger_tstamp) >= sysctl_mptcp_probe_interval_secs*1000)) {
				printk("Periodic Search\n");
				goto search_start;
			}


			if (!meta_tp->rate_delivered && !last_rate) {
				in_search = false;
				goto reset;
			}

			if (!in_search && last_rate && !sysctl_mptcp_ratio_static) {
				/*Not in search but last rate !=0:*/
				rate_diff = (int)meta_tp->rate_delivered - (int)init_rate;
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

				if (rate_diff > trigger_threshold) {
					threshold_cnt++;
				} else if (buffer_diff < meta_tp->buffer_trigger_threshold) {
					buffer_threshold_cnt++;
				} else {
					buffer_threshold_cnt = 0;
					threshold_cnt = 0;
				}

				if (!meta_tp->init_search) {
					printk("INITIAL SEARCH\n");
					meta_tp->init_search = true;
					goto search_start;
				}

				if (buffer_threshold_cnt == 5 || threshold_cnt == 5) {
					/*Search trigger condition met*/
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
					/*Triggering conditions*/
					if(buffer_threshold_cnt==5)
					{
						printk("DECREASED SEND QUEUE\n");
					}
					else if(threshold_cnt==5)
					{
						printk("DECREASED THROUGHPUT\n");
					}
					else 
					{
						printk("INITIAL or PERIODIC SEARCH\n");
					}

					/*Set search state and reset counter for the next interval*/
					in_search = true;
					threshold_cnt = 0;
					buffer_threshold_cnt = 0;

					/*Increase sampling interval*/
					meta_tp->ratio_rate_sample = meta_tp->ratio_rate_sample*4;
					last_trigger_tstamp = jiffies;

					if (meta_tp->num_segments_flow_one <= (100 - abs(meta_tp->ratio_search_step))) {
						meta_tp->search_state = RIGHT_RATIO_SET;
						meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
					}
					else {
						meta_tp->search_state = SEARCH_RATE;
						meta_tp->ratio_search_step = -1*abs(meta_tp->ratio_search_step);
						meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
					}


					last_rate = 0;
					/*When search starts, get the average of of the last iter*sampling_time ms for comparable*/
					for (iter = 0; iter < 5; iter++)
						last_rate += meta_tp->last_rate_search_start[iter];
					do_div(last_rate, 5);
					goto reset;
nosearch:
					printk("NO SEARCH\n");
					last_rate = 0;
					threshold_cnt = 0;
					buffer_threshold_cnt = 0;
					goto reset;
				}

			}


			/*Start ratio searching*/
			if (in_search) {
				switch(meta_tp->search_state) {
					case RIGHT_RATIO_SET:
						printk("RIGHT_RATIO_SET");
						if (meta_tp->rate_delivered > last_rate) {
							if (meta_tp->num_segments_flow_one + meta_tp->ratio_search_step <= 100) {
								meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
								meta_tp->search_state = SEARCH_RATE;
							} else {
								last_rate = 0;
								in_search = false;
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
							meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
							in_search = false;
							goto reset;
						}
						break;
					case LEFT_RATIO_SET:
						printk("LEFT_RATIO_SET");
						if (meta_tp->rate_delivered > last_rate) {
							meta_tp->ratio_search_step = -1*abs(meta_tp->ratio_search_step);
							if (meta_tp->num_segments_flow_one > abs(meta_tp->ratio_search_step)) {
								meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
								meta_tp->search_state = SEARCH_RATE;
							} else {
								last_rate = 0;
								in_search = false;
								meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
								goto reset;
							}
						} else {
							meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
							last_rate = 0;
							meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
							in_search = false;
							goto reset;
						}
						break;
					case SEARCH_RATE:
						printk("SEARCH_RATE");
						if (meta_tp->rate_delivered < last_rate) {
							meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step;
							meta_tp->ratio_search_step = abs(meta_tp->ratio_search_step);
							if (meta_tp->num_segments_flow_one + meta_tp->ratio_search_step/2 <= 100) {
								meta_tp->num_segments_flow_one += meta_tp->ratio_search_step/2;
								meta_tp->search_state = RIGHT_RATIO_FINE;
							} else {
								meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step/2;
								meta_tp->search_state = LEFT_RATIO_FINE;
							}
							goto reset;
						} else {
							if (meta_tp->num_segments_flow_one + meta_tp->ratio_search_step <= 100 && meta_tp->num_segments_flow_one + meta_tp->ratio_search_step > 0)
								meta_tp->num_segments_flow_one += meta_tp->ratio_search_step;
							else {
								last_rate = 0;
								in_search = false;
								meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
								goto reset;
							}
						}
						break;
					case RIGHT_RATIO_FINE:
						printk("RIGHT_RATIO_FINE");
						if (meta_tp->rate_delivered > last_rate) {
							last_rate = 0;
							in_search = false;
							meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
						} else {
							if (meta_tp->num_segments_flow_one > meta_tp->ratio_search_step) {
								meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step;
								meta_tp->search_state = LEFT_RATIO_FINE;
							} else {
								meta_tp->num_segments_flow_one -= meta_tp->ratio_search_step/2;
								last_rate = 0;
								in_search = false;
								meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
							}
						}
						goto reset;
						break;
					case LEFT_RATIO_FINE:
						printk("LEFT_RATIO_FINE");
						if (meta_tp->rate_delivered <= last_rate) {
							meta_tp->num_segments_flow_one += meta_tp->ratio_search_step/2;
						}
						last_rate = 0;
						in_search = false;
						meta_tp->ratio_rate_sample = sysctl_mptcp_rate_sample;
						goto reset;
						break;
				}
			}/*End ratio searching*/

			last_rate = meta_tp->rate_delivered;//if we are not in_search, last_rate is what we collected this interval
reset:
			/*Save the calculated parameters this interval*/
			meta_tp->prr_out = last_rate;//rate delivered this interval
			meta_tp->prr_delivered = trigger_threshold;
			meta_tp->lost = in_search;
			meta_tp->snd_ssthresh = threshold_cnt;
			meta_tp->buffer_threshold_cnt = buffer_threshold_cnt;
			meta_tp->prior_ssthresh = last_trigger_tstamp;
			meta_tp->total_retrans = count_set_init_rate;
			meta_tp->prior_cwnd = init_rate;
			memcpy(meta_tp->init_buffer_size, init_buffer_size, 2*sizeof(u32));
			memcpy(meta_tp->last_buffer_size, last_buffer_size, 2*sizeof(u32));
			
			/*Reset the containers for the next intervals*/
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

		}/*end dynamic ratio search*/
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
	}/*Schedule the chosen socket*/
#ifdef MPTCP_SCHED_PROBE
	iter = 0;
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);
		mptcp_sched_probe_init(&sprobe);//initialize sprobe
		iter++;

		if (!mptcp_ratio_is_available(sk_it, skb, false, cwnd_limited)) sprobe.temp_unavailable = true;

		//Probe the chosen subflow
		if (choose_sk == sk_it) {
			mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk_it);
		}
		//Don't probe the current subflow
		else mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk_it);
	}
#endif
	return NULL;
}/*End scheduling next segment*/

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
