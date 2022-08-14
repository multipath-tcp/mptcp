/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>


/* Mirrored from net/ipv4/tcp_outpt.c */
/* Does at least the first segment of SKB fit into the send window? */
//bool tcp_snd_wnd_test(const struct tcp_sock *tp, const struct sk_buff *skb,
//              unsigned int cur_mss)
//{
//    u32 end_seq = TCP_SKB_CB(skb)->end_seq;
//
//    if (skb->len > cur_mss)
//        end_seq = TCP_SKB_CB(skb)->seq + cur_mss;
//
//    return !after(end_seq, tcp_wnd_end(tp));
//}

/* Mirrored from net/ipv4/tcp_outpt.c */
/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
//unsigned int tcp_cwnd_test(const struct tcp_sock *tp,
//               const struct sk_buff *skb)
//{
//    u32 in_flight, cwnd, halfcwnd;
//
//    /* Don't be strict about the congestion window for the final FIN.  */
//    if (skb &&
//        (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
//        tcp_skb_pcount(skb) == 1)
//        return 1;
//
//    in_flight = tcp_packets_in_flight(tp);
//    cwnd = tp->snd_cwnd;
//    if (in_flight >= cwnd)
//        return 0;
//
//    /* For better scheduling, ensure we have at least
//     * 2 GSO packets in flight.
//     */
//    halfcwnd = max(cwnd >> 1, 1U);
//    return min(halfcwnd, cwnd - in_flight);
//}

struct defsched_priv {
	u32	last_rbuf_opti;
};

static struct defsched_priv *defsched_get_priv(const struct tcp_sock *tp)
{
	return (struct defsched_priv *)&tp->mptcp->mptcp_sched[0];
}

static bool mptcp_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
        if (!tcp_is_reno(tp)) {
            //printk("shivanga: not is reno\n");
			return true;
        }
		else if (tp->snd_una != tp->high_seq) {
            //printk("shivanga: una != high_seq\n");
			return true;
        }
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq) {
            //printk("shivanga: fully established\n");
			return true;
        }
	}

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd) {
        //printk("no spot in cwnd, in_flight: %d, snd_cwnd: %d\n", in_flight, tp->snd_cwnd);
		return true;
    }

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space) {
        //printk("shivanga: no space 1\n");
		return true;
    }

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp))) {
        //printk("shivanga: no space 2\n");
		return true;
    }

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp))) {
        //printk("shivanga: passed allowed snd wnd\n");
		return true;
    }

	return false;
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

/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
#ifdef MPTCP_SCHED_PROBE
static struct sock
*rtt_get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
                bool (*selector)(const struct tcp_sock *),
                bool zero_wnd_test, bool *force, unsigned long sched_probe_id)
#else
static struct sock
*rtt_get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
#endif
{
	struct sock *bestsk = NULL;
	u32 min_srtt = 0xffffffff;
	bool found_unused = false;
	bool found_unused_una = false;
	//struct sock *sk;
	struct mptcp_tcp_sock *mptcp;
#ifdef MPTCP_SCHED_PROBE
	struct mptcp_sched_probe sprobe;
#endif

	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(mptcp_to_sock(mptcp));
		bool unused = false;
#ifdef MPTCP_SCHED_PROBE
		mptcp_sched_probe_init(&sprobe);
#endif

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp)) {
#ifdef MPTCP_SCHED_PROBE
			sprobe.selector_reject = true;
			mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk);
#endif			
            continue;
	    }

		if (!mptcp_dont_reinject_skb(tp, skb))
			unused = true;
		else if (found_unused) {
#ifdef MPTCP_SCHED_PROBE
            sprobe.found_unused_reject = true;
			mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk);
#endif			
			/* If a unused sk was found previously, we continue -
			 * no need to check used sks anymore.
			 */
			continue;
		}

		if (mptcp_is_def_unavailable(sk)) {
#ifdef MPTCP_SCHED_PROBE
            sprobe.def_unavailable = true;
			mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk);
#endif
			continue;
		}

		if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (unused)
				found_unused_una = true;
#ifdef MPTCP_SCHED_PROBE
            sprobe.temp_unavailable = true;
			mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk);
#endif
			continue;		
		}
		
		if (unused) {
			if (!found_unused) {
				/* It's the first time we encounter an unused
				 * sk - thus we reset the bestsk (which might
				 * have been set to a used sk).
				 */
				min_srtt = 0xffffffff;
				bestsk = NULL;
			}
			found_unused = true;
		}

		if (tp->srtt_us < min_srtt) {
			min_srtt = tp->srtt_us;
			bestsk = sk;
		}
#ifdef MPTCP_SCHED_PROBE
		else {
			sprobe.srtt_reject = true;
			mptcp_sched_probe_log_hook(&sprobe, false, sched_probe_id, sk);
		}
#endif
	}
	
	if (bestsk) {
		/* The force variable is used to mark the returned sk as
		 * previously used or not-used.
		 */
		if (found_unused)
			*force = true;
		else
			*force = false;
	} else {
		/* The force variable is used to mark if there are temporally
		 * unavailable not-used sks.
		 */
		if (found_unused_una)
			*force = true;
		else
			*force = false;
	}

#ifdef MPTCP_SCHED_PROBE
    mptcp_sched_probe_init(&sprobe);
    if(bestsk) {
        //sprobe.skblen = DIV_ROUND_UP(skb->len, tcp_current_mss(bestsk));
        mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, bestsk);
    }
#endif
	return bestsk;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
struct sock *rtt_get_available_subflow(struct sock *meta_sk, struct sk_buff *skb,
				   bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	/*Phuc*/
	struct sock *sk=NULL;
	struct mptcp_tcp_sock *mptcp;
	/****/
	bool force;
#ifdef MPTCP_SCHED_PROBE
	struct mptcp_sched_probe sprobe;
	unsigned long sched_probe_id;
	
	mptcp_sched_probe_init(&sprobe);
	get_random_bytes(&sched_probe_id, sizeof(sched_probe_id));
#endif

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_available(sk, skb, zero_wnd_test))
			sk = NULL;
#ifdef MPTCP_SCHED_PROBE
		if(sk) {
            //sprobe.skblen = DIV_ROUND_UP(skb->len, tcp_current_mss(sk));
            mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk);
        }
#endif
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sub(mpcb, mptcp) {
			struct sock *sk = mptcp_to_sock(mptcp);
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, zero_wnd_test)) {
#ifdef MPTCP_SCHED_PROBE
    			if(sk) {
                    //sprobe.skblen = DIV_ROUND_UP(skb->len, tcp_current_mss(sk));
                    mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, sk);
                }
#endif
				return sk;
			}
		}
	}

#ifdef MPTCP_SCHED_PROBE
	/* Find the best subflow */
    sk = rtt_get_subflow_from_selectors(mpcb, skb, &subflow_is_active,
                    zero_wnd_test, &force, sched_probe_id);
    if (force)
        /* one unused active sk or one NULL sk when there is at least
         * one temporally unavailable unused active sk
         */
        return sk;
	
    sk = rtt_get_subflow_from_selectors(mpcb, skb, &subflow_is_backup,
                    zero_wnd_test, &force, sched_probe_id);
#else
	/* Find the best subflow */
	sk = rtt_get_subflow_from_selectors(mpcb, skb, &subflow_is_active,
					zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = rtt_get_subflow_from_selectors(mpcb, skb, &subflow_is_backup,
					zero_wnd_test, &force);
#endif
	if (!force && skb)
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;
	return sk;
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	//struct tcp_sock *tp_it;
	struct mptcp_tcp_sock *mptcp;
	struct sk_buff *skb_head;
	struct defsched_priv *dsp = defsched_get_priv(tp);

	if (tp->mpcb->cnt_subflows == 1)
		return NULL;

    if (sysctl_mptcp_scheduler_optimizations_disabled > 2) return NULL;

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
	if (tcp_jiffies32 - dsp->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
		goto retrans;

    if (sysctl_mptcp_scheduler_optimizations_disabled > 1)
	    goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_sub(tp->mpcb, mptcp) {
		struct tcp_sock *tp_it = mptcp->tp;
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

                if (sysctl_mptcp_scheduler_optimizations_disabled && tcp_in_slow_start(tp_it))
                    continue;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				dsp->last_rbuf_opti = tcp_jiffies32;
			}
			break;
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_sub(tp->mpcb, mptcp) {
			struct tcp_sock *tp_it = mptcp->tp;
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
			struct sock *subsk = rtt_get_available_subflow(meta_sk, NULL,
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

#define tcp_probe_copy_fl_to_si4(inet, si4, mem)        \
    do {                            \
        si4.sin_family = AF_INET;           \
        si4.sin_port = inet->inet_##mem##port;      \
        si4.sin_addr.s_addr = inet->inet_##mem##addr;   \
    } while (0)                     \

static struct sk_buff *mptcp_rtt_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;
    //shivanga 
    /*struct inet_sock *inet;
    union {
        struct sockaddr     raw;
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } dst;*/
#ifdef MPTCP_SCHED_PROBE
    struct mptcp_sched_probe sprobe;
    unsigned long sched_probe_id = ULONG_MAX;

    mptcp_sched_probe_init(&sprobe);
    //get_random_bytes(&sched_probe_id, sizeof(sched_probe_id));
#endif   
    //if (inet==NULL) printk("shivanga: inet null\n");
	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;
	
	*subsk = rtt_get_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

    //inet = inet_sk(*subsk);
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
    //tcp_probe_copy_fl_to_si4(inet, dst.v4, d);
    //printk("shivanga: %pISpc\n",&dst); 
    //printk("%d %d %d\n",DIV_ROUND_UP(*limit, mss_now), DIV_ROUND_UP(skb->len, mss_now), DIV_ROUND_UP(window,mss_now));
   
#ifdef MPTCP_SCHED_PROBE
    if (*subsk) {
        sprobe.split = DIV_ROUND_UP(*limit, mss_now);
        sprobe.skblen = DIV_ROUND_UP(skb->len, mss_now);
        mptcp_sched_probe_log_hook(&sprobe, true, sched_probe_id, *subsk);
    } 
#endif
    return skb;
}

static void rtt_init(struct sock *sk)
{
	struct defsched_priv *dsp = defsched_get_priv(tcp_sk(sk));

	dsp->last_rbuf_opti = tcp_jiffies32;
}

static struct mptcp_sched_ops mptcp_sched_rtt = {
	.get_subflow = rtt_get_available_subflow,
	.next_segment = mptcp_rtt_next_segment,
	.init = rtt_init,
	.name = "rtt",
	.owner = THIS_MODULE,
};

static int __init rtt_register(void)
{
	BUILD_BUG_ON(sizeof(struct defsched_priv) > MPTCP_SCHED_SIZE);
	
	if (mptcp_register_scheduler(&mptcp_sched_rtt))
		return -1;
	
	return 0;
}

static void rtt_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_rtt);
}

module_init(rtt_register);
module_exit(rtt_unregister);

MODULE_AUTHOR("Swetank Kumar Saha");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RTT MPTCP");
MODULE_VERSION("0.01");
