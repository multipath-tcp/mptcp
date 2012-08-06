/*
 *	MPTCP implementation - Sending side
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
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kconfig.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

#include <net/mptcp.h>
#include <net/sock.h>

/* If the sub-socket sk available to send the skb? */
static int mptcp_is_available(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return 0;

	if (tp->pf || (tp->mpcb->noneligible & mptcp_pi_to_flag(tp->mptcp->path_index)) ||
	    inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
		return 0;

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && after(tp->write_seq + skb->len, tcp_wnd_end(tp)))
		return 0;

	return tcp_cwnd_test(tp, skb);
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 * An exception is a DATA_FIN without data. These ones are not
	 * reinjected at the subflow-level as they do not consume
	 * subflow-sequence-number space.
	 */
	return skb &&
		/* We either have a data_fin with data or not a data_fin */
		((mptcp_is_data_fin(skb) && TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq  > 1) ||
		!mptcp_is_data_fin(skb)) &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/**
 * This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the shortest RTT.
 * If all paths have full cong windows, we simply return NULL.
 *
 * Additionally, this function is aware of the backup-subflows.
 */
static struct sock *get_available_subflow(struct mptcp_cb *mpcb,
					  struct sk_buff *skb)
{
	struct sock *sk;
	struct sock *bestsk = NULL, *lowpriosk = NULL, *backupsk = NULL;
	u32 min_time_to_peer = 0xffffffff, lowprio_min_time_to_peer = 0xffffffff;
	int cnt_backups = 0;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *) mpcb->connection_list;
		if (!mptcp_is_available(bestsk, skb))
			bestsk = NULL;
		return bestsk;
	}

	/* Answer data_fin on same subflow!!! */
	if (mpcb_meta_sk(mpcb)->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->rx_opt.low_prio || tp->mptcp->low_prio)
			cnt_backups++;

		if (mptcp_dont_reinject_skb(tp, skb))
			continue;

		if (!mptcp_is_available(sk, skb))
			continue;

		if ((tp->rx_opt.low_prio || tp->mptcp->low_prio) &&
		    tp->srtt < lowprio_min_time_to_peer &&
		    !(skb && mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask)) {
			lowprio_min_time_to_peer = tp->srtt;
			lowpriosk = sk;
		} else if (!(tp->rx_opt.low_prio || tp->mptcp->low_prio) &&
		    tp->srtt < min_time_to_peer &&
		    !(skb && mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask)) {
			min_time_to_peer = tp->srtt;
			bestsk = sk;
		}

		if (skb && mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask)
			backupsk = sk;
	}

	if (mpcb->cnt_established == cnt_backups && lowpriosk)
		return lowpriosk;
	if (bestsk)
		return bestsk;
	return backupsk;
}

static struct mp_dss *mptcp_skb_find_dss(const struct sk_buff *skb)
{
	if (!mptcp_is_data_seq(skb))
		return NULL;

	return (struct mp_dss *)(skb->data - (MPTCP_SUB_LEN_DSS_ALIGN +
			      	      	      MPTCP_SUB_LEN_ACK_ALIGN +
			      	      	      MPTCP_SUB_LEN_SEQ_ALIGN));
}

/* Reinject data from one TCP subflow to the meta_sk. If sk == NULL, we are
 * coming from the meta-retransmit-timer
 */
static int __mptcp_reinject_data(struct sk_buff *orig_skb, struct sock *meta_sk,
				 struct sock *sk, int clone_it)
{
	struct sk_buff *skb, *skb1;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	u32 seq, end_seq;

	if (clone_it) {
		/* pskb_copy is necessary here, because the TCP/IP-headers
		 * will be changed when it's going to be reinjected on another
		 * subflow.
		 */
		skb = pskb_copy(orig_skb, GFP_ATOMIC);
	} else {
		skb_unlink(orig_skb, &sk->sk_write_queue);
		skb_get(orig_skb);
		mptcp_wmem_free_skb(sk, orig_skb);
		skb = orig_skb;
	}
	if (unlikely(!skb))
		return -ENOBUFS;

	/* get the data-seq and end-data-seq and store them again in the
	 * tcp_skb_cb
	 */
	if (sk) {
		struct mp_dss *mpdss = mptcp_skb_find_dss(orig_skb);
		u32 *p32;
		u16 *p16;

		if (!mpdss || !mpdss->M) {
			if (clone_it)
				__kfree_skb(skb);

			return -1;
		}

		/* Move the pointer to the data-seq */
		p32 = (u32 *)mpdss;
		p32++;
		if (mpdss->A) {
			p32++;
			if (mpdss->a)
				p32++;
		}

		TCP_SKB_CB(skb)->seq = ntohl(*p32);

		/* Get the data_len to calculate the end_data_seq */
		p32++;
		p32++;
		p16 = (u16 *)p32;
		TCP_SKB_CB(skb)->end_seq = ntohs(*p16) + TCP_SKB_CB(skb)->seq;
	}

	skb->sk = meta_sk;

	/* If it reached already the destination, we don't have to reinject it */
	if (!after(TCP_SKB_CB(skb)->end_seq, meta_tp->snd_una)) {
		if (clone_it)
			__kfree_skb(skb);
		return -1;
	}

	/* If it's empty, just add */
	if (skb_queue_empty(&mpcb->reinject_queue)) {
		skb_queue_head(&mpcb->reinject_queue, skb);
		return 0;
	}

	/* Find place to insert skb - or even we can 'drop' it, as the
	 * data is already covered by other skb's in the reinject-queue.
	 *
	 * This is inspired by code from tcp_data_queue.
	 */

	skb1 = skb_peek_tail(&mpcb->reinject_queue);
	seq = TCP_SKB_CB(skb)->seq;
	end_seq = TCP_SKB_CB(skb)->end_seq;
	while (1) {
		if (!after(TCP_SKB_CB(skb1)->seq, seq))
			break;
		if (skb_queue_is_first(&mpcb->reinject_queue, skb1)) {
			skb1 = NULL;
			break;
		}
		skb1 = skb_queue_prev(&mpcb->reinject_queue, skb1);
	}

	/* Do skb overlap to previous one? */
	if (skb1 && before(seq, TCP_SKB_CB(skb1)->end_seq)) {
		if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			/* All the bits are present. Don't reinject */
			__kfree_skb(skb);
			return 0;
		}
		if (seq == TCP_SKB_CB(skb1)->seq)
			skb1 = skb_queue_prev(&mpcb->reinject_queue, skb1);
	}
	if (!skb1)
		__skb_queue_head(&mpcb->reinject_queue, skb);
	else
		__skb_queue_after(&mpcb->reinject_queue, skb1, skb);

	/* And clean segments covered by new one as whole. */
	while (!skb_queue_is_last(&mpcb->reinject_queue, skb)) {
		skb1 = skb_queue_next(&mpcb->reinject_queue, skb);

		if (!after(end_seq, TCP_SKB_CB(skb1)->seq))
			break;

		__skb_unlink(skb1, &mpcb->reinject_queue);
		__kfree_skb(skb1);
	}
	return 0;
}

/* Inserts data into the reinject queue */
void mptcp_reinject_data(struct sock *sk, int clone_it)
{
	struct sk_buff *skb_it, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct sock *meta_sk = (struct sock *) mpcb;

	skb_queue_walk_safe(&sk->sk_write_queue, skb_it, tmp) {
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb_it);
		/* seq >= reinjected_seq , to avoid reinjecting several times
		 * the same segment. This does not duplicate functionality with
		 * TCP_SKB_CB(skb)->path_mask, because the path_mask ensures the skb is not
		 * scheduled twice to the same subflow. OTOH, the seq
		 * check ensures that at any time, _one_ subflow exactly
		 * is allowed to reinject it, not all of them. That one
		 * subflow is the one that received it last.
		 * Also, subflow syn's and fin's are not reinjected
		 */
		if (before(tcb->seq, tp->mptcp->reinjected_seq) ||
		    tcb->tcp_flags & TCPHDR_SYN ||
		    (tcb->tcp_flags & TCPHDR_FIN && !mptcp_is_data_fin(skb_it)))
			continue;

		/* Go to next segment, if it failed */
		if (__mptcp_reinject_data(skb_it, meta_sk, sk, clone_it))
			continue;

		/* If clone_it == 0, then the socket will get destroyed soon
		 * and we don't care about reinjected_seq.
		 *
		 * It's very important to then not change reinjected_seq, because
		 * tcb->end_seq got changed to end_data_seq and this may block
		 * further reinjection.
		 */
		if (clone_it)
			tp->mptcp->reinjected_seq = tcb->end_seq;
	}

	skb_it = tcp_write_queue_tail(meta_sk);
	/* If sk has sent the empty data-fin, we have to reinject it too. */
	if (skb_it && mptcp_is_data_fin(skb_it) && skb_it->len == 0 &&
	    TCP_SKB_CB(skb_it)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index)) {
		__mptcp_reinject_data(skb_it, meta_sk, NULL, 1);
	}

	tcp_push_pending_frames(meta_sk);

	tp->pf = 1;
}

void mptcp_retransmit_timer(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);

	if (unlikely(meta_tp->send_mp_fclose))
		goto send_mp_fclose;

	/* In fallback, retransmission is handled at the subflow-level */
	if (!meta_tp->packets_out ||
	    mpcb->infinite_mapping || mpcb->send_infinite_mapping)
		return;

	if (!tcp_write_queue_head(meta_sk)) {
		printk(KERN_ERR"%s no skb in meta write queue but packets_out: %u\n",
				__func__, meta_tp->packets_out);
		goto out;
	}

	__mptcp_reinject_data(tcp_write_queue_head(meta_sk), meta_sk, NULL, 1);
	tcp_push_pending_frames(meta_sk);

out:
	meta_icsk->icsk_rto = min(meta_icsk->icsk_rto << 1, TCP_RTO_MAX);
	inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS,
			meta_icsk->icsk_rto, TCP_RTO_MAX);

	return;

send_mp_fclose:
	mptcp_send_active_reset(meta_sk, GFP_ATOMIC);

	goto out;
}

/* Inspired by tcp_write_wakeup */
int mptcp_write_wakeup(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb;

	skb = tcp_send_head(meta_sk);
	if (skb && before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(meta_tp))) {
		/* Currently, zero-window-probes are still handled on a
		 * subflow-level */
		mptcp_debug("%s INSIDE - zero-window-probes on the meta-sk\n",
				__func__);
		BUG();
	} else {
		struct sock *sk_it;
		int ans = 0;

		if (between(meta_tp->snd_up, meta_tp->snd_una + 1,
			    meta_tp->snd_una + 0xFFFF)) {
			mptcp_for_each_sk(meta_tp->mpcb, sk_it)
					tcp_xmit_probe_skb(sk_it, 1);
		}

		/* At least on of the tcp_xmit_probe_skb's has to succeed */
		mptcp_for_each_sk(meta_tp->mpcb, sk_it) {
			int ret = tcp_xmit_probe_skb(sk_it, 0);
			if (unlikely(ret > 0))
				ans = ret;
		}
		return ans;
	}
}

/**** static functions, used by mptcp_write_xmit ****/
static void mptcp_mark_reinjected(struct sock *sk, struct sk_buff *skb)
{
	struct sock *meta_sk;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb_it;

	meta_sk = mptcp_meta_sk(sk);
	skb_it = tcp_write_queue_head(meta_sk);

	tcp_for_write_queue_from(skb_it, meta_sk) {
		if (skb_it == tcp_send_head(meta_sk))
			break;

		if (TCP_SKB_CB(skb_it)->seq == TCP_SKB_CB(skb)->seq) {
			TCP_SKB_CB(skb_it)->path_mask |= mptcp_pi_to_flag(tp->mptcp->path_index);
			break;
		}
	}
}

static void mptcp_find_and_set_pathmask(struct sock *meta_sk, struct sk_buff *skb)
{
	struct sk_buff *skb_it;

	skb_it = tcp_write_queue_head(meta_sk);

	tcp_for_write_queue_from(skb_it, meta_sk) {
		if (skb_it == tcp_send_head(meta_sk))
			break;

		if (TCP_SKB_CB(skb_it)->seq == TCP_SKB_CB(skb)->seq) {
			TCP_SKB_CB(skb)->path_mask = TCP_SKB_CB(skb_it)->path_mask;
			break;
		}
	}
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	struct tcp_sock *tp = tcp_sk(sk), *tp_it;
	struct sk_buff *skb_it;

	if (tp->mpcb->cnt_established == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_it = tcp_write_queue_head(meta_sk);

	if (!skb_it || skb_it == tcp_send_head(meta_sk))
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_it)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			/* Only update every subflow rtt */
			if (tcp_time_stamp - tp_it->mptcp->last_rbuf_opti < tp_it->srtt >> 3)
				break;

			if ((u64)tp_it->snd_cwnd * tp->srtt <
			    (u64) tp->snd_cwnd * tp_it->srtt) {
				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);
				tp_it->snd_ssthresh = max(tp_it->snd_cwnd, 2U);
				tp_it->mptcp->last_rbuf_opti = tcp_time_stamp;
			}
			break;
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_it)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		int do_retrans = 0;
		mptcp_for_each_tp(tp->mpcb, tp_it) {
			if (tp_it != tp && TCP_SKB_CB(skb_it)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = 1;
					break;
				}

				if (4 * tp->srtt >= tp_it->srtt) {
					do_retrans = 0;
					break;
				} else {
					do_retrans = 1;
				}
			}
		}

		if (do_retrans)
			return skb_it;
	}
	return NULL;
}

/**
 * specific version of skb_entail (tcp.c),that allows appending to any
 * subflow.
 * Here, we do not set the data seq, since it remains the same. However,
 * we do change the subflow seqnum.
 *
 * Note that we make the assumption that, within the local system, every
 * segment has tcb->sub_seq == tcb->seq, that is, the dataseq is not shifted
 * compared to the subflow seqnum. Put another way, the dataseq referenced
 * is actually the number of the first data byte in the segment.
 */
static void mptcp_skb_entail(struct sock *sk, struct sk_buff *skb)
{
	__be32 *ptr;
	__u16 data_len;
	struct mp_dss *mdss;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	int fin = (tcb->tcp_flags & TCPHDR_FIN) ? 1 : 0;

	/**** Write MPTCP DSS-option to the packet. ****/

	ptr = (__be32 *)(skb->data - (MPTCP_SUB_LEN_DSS_ALIGN +
				      MPTCP_SUB_LEN_ACK_ALIGN +
				      MPTCP_SUB_LEN_SEQ_ALIGN));

	/* Then we start writing it from the start */
	mdss = (struct mp_dss *) ptr;

	mdss->kind = TCPOPT_MPTCP;
	mdss->sub = MPTCP_SUB_DSS;
	mdss->rsv1 = 0;
	mdss->rsv2 = 0;
	mdss->F = (mptcp_is_data_fin(skb) ? 1 : 0);
	mdss->m = 0;
	mdss->M = 1;
	mdss->a = 0;
	mdss->A = 1;
	mdss->len = mptcp_sub_len_dss(mdss, tp->mpcb->rx_opt.dss_csum);

	if (tp->mpcb->send_infinite_mapping &&
	    tcb->seq >= mpcb_meta_tp(tp->mpcb)->snd_nxt) {
		tp->mptcp->fully_established = 1;
		tp->mpcb->infinite_mapping = 1;
		tp->mptcp->infinite_cutoff_seq = tp->write_seq;
		tcb->mptcp_flags |= MPTCPHDR_INF;
		data_len = 0;
	} else {
		data_len = tcb->end_seq - tcb->seq;
	}

	ptr++;
	ptr++; /* data_ack will be set in mptcp_options_write */
	*ptr++ = htonl(tcb->seq); /* data_seq */

	/* If it's a non-data DATA_FIN, we set subseq to 0 (draft v7) */
	if (mptcp_is_data_fin(skb) && skb->len == 0)
		*ptr++ = 0; /* subseq */
	else
		*ptr++ = htonl(tp->write_seq - tp->mptcp->snt_isn); /* subseq */

	if (tp->mpcb->rx_opt.dss_csum && data_len) {
		__be16 *p16 = (__be16 *)ptr;
		__be32 hdseq = mptcp_get_highorder_sndbits(skb, tp->mpcb);
		__wsum csum;
		*ptr = htonl(((data_len) << 16) |
				(TCPOPT_EOL << 8) |
				(TCPOPT_EOL));

		csum = csum_partial(ptr - 2, 12, skb->csum);
		p16++;
		*p16++ = csum_fold(csum_partial(&hdseq, sizeof(hdseq), csum));
	} else {
		*ptr++ = htonl(((data_len) << 16) |
				(TCPOPT_NOP << 8) |
				(TCPOPT_NOP));
	}

	tcb->seq = tp->write_seq;
	tcb->sacked = 0; /* reset the sacked field: from the point of view
			  * of this subflow, we are sending a brand new
			  * segment */
	/* Take into account seg len */
	tp->write_seq += skb->len + fin;
	tcb->end_seq = tp->write_seq;

	/* If it's a non-payload DATA_FIN (also no subflow-fin), the
	 * segment is not part of the subflow but on a meta-only-level
	 */
	if (!mptcp_is_data_fin(skb) || tcb->end_seq != tcb->seq) {
		tcp_add_write_queue_tail(sk, skb);
		sk->sk_wmem_queued += skb->truesize;
		sk_mem_charge(sk, skb->truesize);
	}
}

static void mptcp_combine_dfin(struct sk_buff *skb, struct mptcp_cb *mpcb,
			       struct sock *subsk)
{
	struct sock *sk_it, *meta_sk = mpcb_meta_sk(mpcb);
	struct tcp_sock *meta_tp = mpcb_meta_tp(mpcb);
	int all_empty = 1, all_acked;

	/* Don't combine, if they didn't combine - otherwise we end up in
	 * TIME_WAIT, even if our app is smart enough to avoid it */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN) {
		if (!mpcb->dfin_combined)
			return;
	}

	/* If no other subflow has data to send, we can combine */
	mptcp_for_each_sk(mpcb, sk_it) {
		if (!tcp_write_queue_empty(sk_it))
			all_empty = 0;
	}

	/* If all data has been DATA_ACKed, we can combine.
	 * -1, because the data_fin consumed one byte
	 */
	all_acked = (meta_tp->snd_una == (meta_tp->write_seq - 1));

	if ((all_empty || all_acked) && tcp_close_state(subsk))
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
}

int mptcp_write_xmit(struct sock *meta_sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;
	int reinject = 0;

	if (mss_now != mptcp_sysctl_mss()) {
		printk(KERN_ERR "write xmit-mss_now %d, mptcp mss:%d\n",
		       mss_now, mptcp_sysctl_mss());
		BUG();
	}
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and all
	 * will be happy.
	 */
	if (unlikely(meta_sk->sk_state == TCP_CLOSE))
		return 0;

	sent_pkts = 0;

	if (!push_one) {
		/* Do MTU probing. */
		result = tcp_mtu_probe(meta_sk);
		if (!result) {
			return 0;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	while ((skb = mptcp_next_segment(meta_sk, &reinject))) {
		unsigned int limit;
		struct sock *subsk;
		struct tcp_sock *subtp;
		struct sk_buff *subskb = NULL;
		int err;

		if (reinject == 1) {
			if (!after(TCP_SKB_CB(skb)->end_seq, meta_tp->snd_una)) {
				/* Segment already reached the peer, take the next one */
				skb_unlink(skb, &mpcb->reinject_queue);
				__kfree_skb(skb);
				continue;
			}

			/* Reinjection and it is coming from a subflow? We need
			 * to find out the path-mask from the meta-write-queue
			 * to properly select a subflow.
			 */
			if (!TCP_SKB_CB(skb)->path_mask)
				mptcp_find_and_set_pathmask(meta_sk, skb);
		}

		/* This must be invoked even if we don't want
		 * to support TSO at the moment
		 */
		tso_segs = tcp_init_tso_segs(meta_sk, skb, mss_now);
		BUG_ON(!tso_segs);
		/* At the moment we do not support tso, hence
		 * tso_segs must be 1
		 */
		BUG_ON(tso_segs != 1);

		subsk = get_available_subflow(mpcb, skb);
		if (!subsk)
			break;
		subtp = tcp_sk(subsk);

		/* Since all subsocks are locked before calling the scheduler,
		 * the tcp_send_head should not change.
		 */
		BUG_ON(!reinject && tcp_send_head(meta_sk) != skb);
retry:
		cwnd_quota = tcp_cwnd_test(subtp, skb);
		if (!cwnd_quota) {
			/* May happen, if at the first selection we circumvented
			 * the test due to a DATA_FIN (and got rejected at
			 * tcp_snd_wnd_test), but the reinjected segment is not
			 * a DATA_FIN.
			 */
			BUG_ON(reinject != -1);
			break;
		}

		if (!reinject && unlikely(!tcp_snd_wnd_test(meta_tp, skb, mss_now))) {
			skb = mptcp_rcv_buf_optimization(subsk, 1);
			if (skb) {
				reinject = -1;
				goto retry;
			}
			break;
		}

		if (tso_segs == 1) {
			if (unlikely(!tcp_nagle_test(meta_tp, skb, mss_now,
						     (tcp_skb_is_last(meta_sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
		} else {
			if (!push_one && tcp_tso_should_defer(meta_sk, skb))
				break;
		}

		limit = mss_now;
		if (!meta_tp->mpc && tso_segs > 1 && !tcp_urg_mode(meta_tp))
			limit = tcp_mss_split_point(meta_sk, skb, mss_now,
						    cwnd_quota);

		if (skb->len > limit &&
		    unlikely(tso_fragment(meta_sk, skb, limit, mss_now, gfp)))
			break;

		/* If the segment is reinjected, the clone is done
		 * already
		 */
		if (reinject <= 0) {
			if (!reinject) {
				TCP_SKB_CB(skb)->mptcp_flags |=
						(mpcb->snd_hiseq_index ?
						 MPTCPHDR_SEQ64_INDEX : 0);
			}
			/* The segment may be a meta-level
			 * retransmission. In this case, we also have to
			 * copy the TCP/IP-headers. (pskb_copy)
			 */
			if (unlikely(TCP_SKB_CB(skb)->path_mask & ~mptcp_pi_to_flag(subtp->mptcp->path_index)))
				subskb = pskb_copy(skb, GFP_ATOMIC);
			else
				subskb = skb_clone(skb, GFP_ATOMIC);
		} else {
			if (!skb->cloned)
				/* pskb_copy has been called in
				 * __mptcp_reinject_data -
				 * the dataref == 1 now, but we need to
				 * increase it, because for mptcp
				 * dataref is always == 2 when entering
				 * tcp_transmit_skb (only if the packet
				 * is still in the lower-layer
				 * transmit-queue it may be > 2
				 */
				atomic_inc(&(skb_shinfo(skb)->dataref));

			skb_unlink(skb, &mpcb->reinject_queue);
			subskb = skb;
		}
		if (!subskb)
			break;

		TCP_SKB_CB(skb)->path_mask |= mptcp_pi_to_flag(subtp->mptcp->path_index);

		/* The subskb is going in the subflow send-queue. It's path-mask
		 * is not needed anymore and MUST be set to 0, as the path-mask
		 * is a union with inet_skb_param.
		 */
		TCP_SKB_CB(subskb)->path_mask = 0;

		if (!(subsk->sk_route_caps & NETIF_F_ALL_CSUM) &&
		    skb->ip_summed == CHECKSUM_PARTIAL) {
			subskb->csum = skb->csum = skb_checksum(skb, 0, skb->len, 0);
			subskb->ip_summed = skb->ip_summed = CHECKSUM_NONE;
		}

		if (mptcp_is_data_fin(subskb))
			mptcp_combine_dfin(subskb, mpcb, subsk);
		BUG_ON(tcp_send_head(subsk));

		mptcp_skb_entail(subsk, subskb);

		TCP_SKB_CB(subskb)->when = tcp_time_stamp;
		err = tcp_transmit_skb(subsk, subskb, 1, gfp);
		if (unlikely(err)) {
			/* there are three cases of failure of
			 * tcp_transmit_skb:
			 * 1. err != -ENOBUFS && err < 0
			 *    Thus, the failure is due to ip_write_xmit and may
			 *    be a routing-issue. We should not immediatly
			 *    schedule again this subflow and reinject the skb
			 *    on another subflow.
			 *
			 * 2. err == -ENOBUFS && err < 0
			 *    Thus, the failure is due to a failed skb_clone due
			 *    to GFP_ATOMIC.
			 *
			 * 3. err > 0
			 *    The device has not enough space in the queues.
			 *    Select another subflow and mark
			 *    the current subflow as non-eligible.
			 *    When exiting tcp_write_xmit, he will become
			 *    eligible again and we may try him again.
			 *
			 * All this can correctly be handled, by setting
			 * mpcb->noneligible. If all the subflows have become
			 * non-eligible, we just exit tcp_write_xmit in
			 * get_available_subflow. Later, we will try again.
			 */

			/* Remove the skb from the subsock */
			if (!mptcp_is_data_fin(subskb) ||
			    (TCP_SKB_CB(subskb)->end_seq != TCP_SKB_CB(subskb)->seq)) {
				tcp_advance_send_head(subsk, subskb);
				tcp_unlink_write_queue(subskb, subsk);
				subtp->write_seq -= subskb->len;
				mptcp_wmem_free_skb(subsk, subskb);
			} else {
				kfree_skb(subskb);
			}

			/* If it is a reinjection, we cannot modify the path-mask
			 * of the skb, because subskb == skb. And subskb has been
			 * freed above.
			 *
			 * TODO - we have to put back the skb in the
			 * reinject-queue if tcp_transmit_skb fails.
			 */
			if (reinject <= 0)
				TCP_SKB_CB(skb)->path_mask &= ~mptcp_pi_to_flag(subtp->mptcp->path_index);
			mpcb->noneligible |= mptcp_pi_to_flag(subtp->mptcp->path_index);

			continue;
		}

		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		if (!reinject && tcp_send_head(meta_sk) != skb) {
			printk(KERN_ERR "sock_owned_by_user:%d\n",
			       sock_owned_by_user(meta_sk));
			BUG();
		}

		/* If it's a non-payload DATA_FIN (also no subflow-fin), the
		 * segment is not part of the subflow but on a meta-only-level
		 *
		 * We free it, because it has been queued nowhere.
		 */
		if (!mptcp_is_data_fin(subskb) ||
		    (TCP_SKB_CB(subskb)->end_seq != TCP_SKB_CB(subskb)->seq))
			tcp_event_new_data_sent(subsk, subskb);
		else
			kfree_skb(subskb);

		BUG_ON(tcp_send_head(subsk));
		if (!reinject) {
			BUG_ON(tcp_send_head(meta_sk) != skb);
			mptcp_check_sndseq_wrap(meta_tp,
					TCP_SKB_CB(skb)->end_seq -
					TCP_SKB_CB(skb)->seq);
			tcp_event_new_data_sent(meta_sk, skb);
		}
		if (reinject > 0)
			mptcp_mark_reinjected(subsk, skb);

		tcp_minshall_update(meta_tp, mss_now, skb);
		sent_pkts++;

		tcp_cwnd_validate(subsk);
		if (push_one)
			break;
	}

	mpcb->noneligible = 0;

	if (likely(sent_pkts))
		return 0;

	return !meta_tp->packets_out && tcp_send_head(meta_sk);
}

u32 __mptcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	int mss, free_space, full_space, window;

	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	mss = icsk->icsk_ack.rcv_mss;
	free_space = tcp_space(sk);
	full_space = min_t(int, mpcb_meta_tp(mpcb)->window_clamp,
			tcp_full_space(sk));

	if (mss > full_space)
		mss = full_space;

	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		if (tcp_memory_pressure) {
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);
			mptcp_update_window_clamp(tp);
		}

		if (free_space < mss)
			return 0;
	}

	if (free_space > mpcb_meta_tp(mpcb)->rcv_ssthresh)
		free_space = mpcb_meta_tp(mpcb)->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = mpcb_meta_tp(mpcb)->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		if (((window >> tp->rx_opt.rcv_wscale) << tp->
		     rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = (free_space / mss) * mss;
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

void mptcp_skb_entail_init(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* in MPTCP mode, the subflow seqnum is given later */
	if (tp->mpc) {
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
		struct tcp_sock *meta_tp = (struct tcp_sock *)tp->mpcb;

		tcb->seq = tcb->end_seq = meta_tp->write_seq;
		tcb->mptcp_flags = MPTCPHDR_SEQ;
	}
}

void mptcp_syn_options(struct sock *sk, struct tcp_out_options *opts,
		       unsigned *remaining)
{
	struct tcp_sock *tp = tcp_sk(sk);

	opts->options |= OPTION_MPTCP;
	if (is_master_tp(tp)) {
		opts->mptcp_options |= OPTION_MP_CAPABLE | OPTION_TYPE_SYN;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
		opts->mp_capable.sender_key = tp->mptcp_loc_key;
		opts->dss_csum = sysctl_mptcp_checksum;

		/* We arrive here either when sending a SYN or a
		 * SYN+ACK when in SYN_SENT state (that is, tcp_synack_options
		 * is only called for syn+ack replied by a server, while this
		 * function is called when SYNs are sent by both parties and
		 * are crossed)
		 * Due to this possibility, a slave subsocket may arrive here,
		 * and does not need to set the dataseq options, since
		 * there is no data in the segment
		 */
	} else {
		struct mptcp_cb *mpcb = mpcb_from_tcpsock(tp);

		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_SYN;
		*remaining -= MPTCP_SUB_LEN_JOIN_SYN_ALIGN;
		opts->mp_join_syns.token = mpcb->rx_opt.mptcp_rem_token;
		opts->addr_id = mptcp_get_loc_addrid(mpcb, sk);

		if (!tp->mptcp->mptcp_loc_nonce)
			get_random_bytes(&tp->mptcp->mptcp_loc_nonce, 4);

		opts->mp_join_syns.sender_nonce = tp->mptcp->mptcp_loc_nonce;
	}
}

void mptcp_synack_options(struct request_sock *req,
			  struct tcp_out_options *opts, unsigned *remaining)
{
	struct mptcp_request_sock *mtreq;
	mtreq = mptcp_rsk(req);

	opts->options |= OPTION_MPTCP;
	/* MPCB not yet set - thus it's a new MPTCP-session */
	if (!mtreq->mpcb) {
		opts->mptcp_options |= OPTION_MP_CAPABLE | OPTION_TYPE_SYNACK;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
		opts->mp_capable.sender_key = mtreq->mptcp_loc_key;
		opts->dss_csum = sysctl_mptcp_checksum || mtreq->dss_csum;
	} else {
		struct inet_request_sock *ireq = inet_rsk(req);
		int i;

		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_SYNACK;
		opts->mp_join_syns.sender_truncated_mac =
				mtreq->mptcp_hash_tmac;
		opts->mp_join_syns.sender_nonce = mtreq->mptcp_loc_nonce;
		opts->addr_id = 0;

		/* Finding Address ID */
		if (req->rsk_ops->family == AF_INET)
			mptcp_for_each_bit_set(mtreq->mpcb->loc4_bits, i) {
				struct mptcp_loc4 *addr =
						&mtreq->mpcb->addr4[i];
				if (addr->addr.s_addr == ireq->loc_addr)
					opts->addr_id = addr->id;
			}
#if IS_ENABLED(CONFIG_IPV6)
		else /* IPv6 */
			mptcp_for_each_bit_set(mtreq->mpcb->loc6_bits, i) {
				struct mptcp_loc6 *addr =
						&mtreq->mpcb->addr6[i];
				if (ipv6_addr_equal(&addr->addr,
						    &inet6_rsk(req)->loc_addr))
					opts->addr_id = addr->id;
			}
#endif /* CONFIG_IPV6 */
		*remaining -= MPTCP_SUB_LEN_JOIN_SYNACK_ALIGN;
	}
}

void mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       struct tcp_out_options *opts, unsigned *size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;

	/* In fallback mp_fail-mode, we have to repeat it until the fallback
	 * has been done by the sender
	 */
	if (unlikely(mpcb->send_mp_fail)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_FAIL;
		opts->data_ack = (__u32)(mpcb->csum_cutoff_seq >> 32);
		opts->data_seq = (__u32)mpcb->csum_cutoff_seq;
		*size += MPTCP_SUB_LEN_FAIL;
		return;
	}

	if (unlikely(tp->send_mp_fclose)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_FCLOSE;
		opts->mp_capable.receiver_key = mpcb->rx_opt.mptcp_rem_key;
		*size += MPTCP_SUB_LEN_FCLOSE_ALIGN;
		return;
	}

	/* 1. If we are the sender of the infinite-mapping, we need the
	 *    MPTCPHDR_INF-flag, because a retransmission of the
	 *    infinite-announcment still needs the mptcp-option.
	 *
	 *    We need infinite_cutoff_seq, because retransmissions from before
	 *    the infinite-cutoff-moment still need the MPTCP-signalling to stay
	 *    consistent.
	 *
	 * 2. If we are the receiver of the infinite-mapping, we always skip
	 *    mptcp-options, because acknowledgments from before the
	 *    infinite-mapping point have already been sent out.
	 *
	 * I know, the whole infinite-mapping stuff is ugly...
	 *
	 * TODO: Handle wrapped data-sequence numbers
	 *       (even if it's very unlikely)
	 */
	if (mpcb->infinite_mapping && tp->mptcp->fully_established &&
	    ((mpcb->send_infinite_mapping && tcb &&
	      !(tcb->mptcp_flags & MPTCPHDR_INF) &&
	      !before(tcb->seq, tp->mptcp->infinite_cutoff_seq)) ||
	     !mpcb->send_infinite_mapping)) {
		return;
	}

	if (unlikely(tp->mptcp->include_mpc)) {
		opts->options |= OPTION_MPTCP;
		if (is_master_tp(tp)) {
			opts->mptcp_options |= OPTION_MP_CAPABLE |
					       OPTION_TYPE_ACK;
			*size += MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN;
			opts->mp_capable.sender_key = mpcb->mptcp_loc_key;
			opts->mp_capable.receiver_key =
					mpcb->rx_opt.mptcp_rem_key;
			opts->dss_csum = mpcb->rx_opt.dss_csum;
		} else {
			opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_ACK;
			*size += MPTCP_SUB_LEN_JOIN_ACK_ALIGN;

			mptcp_hmac_sha1((u8 *)&mpcb->mptcp_loc_key,
					(u8 *)&mpcb->rx_opt.mptcp_rem_key,
					(u8 *)&tp->mptcp->mptcp_loc_nonce,
					(u8 *)&mpcb->rx_opt.mptcp_recv_nonce,
					(u32 *)opts->mp_join_ack.sender_mac);
		}
	}

	if (!tp->mptcp_add_addr_ack && !tp->mptcp->include_mpc) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_DATA_ACK;
		if (!skb || (skb && !mptcp_is_data_seq(skb))) {
			opts->data_ack = mpcb_meta_tp(mpcb)->rcv_nxt;

			*size += MPTCP_SUB_LEN_ACK_ALIGN;
		} else {
			opts->data_ack = mpcb_meta_tp(mpcb)->rcv_nxt;

			/* Doesn't matter, if csum included or not. It will be
			 * either 10 or 12, and thus aligned = 12 */
			*size += MPTCP_SUB_LEN_ACK_ALIGN +
				 MPTCP_SUB_LEN_SEQ_ALIGN;
		}

		*size += MPTCP_SUB_LEN_DSS_ALIGN;
	}

	if (unlikely(tp->mptcp->add_addr4) &&
			MAX_TCP_OPTION_SPACE - *size >=
			MPTCP_SUB_LEN_ADD_ADDR4_ALIGN) {
		int ind = mptcp_find_free_index(~(tp->mptcp->add_addr4));
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->addr4 = &mpcb->addr4[ind];
		if (skb)
			tp->mptcp->add_addr4 &= ~(1 << ind);
		*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN;
	} else if (unlikely(tp->mptcp->add_addr6) &&
		 MAX_TCP_OPTION_SPACE - *size >=
		 MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) {
		int ind = mptcp_find_free_index(~(tp->mptcp->add_addr6));
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->addr6 = &mpcb->addr6[ind];
		if (skb)
			tp->mptcp->add_addr6 &= ~(1 << ind);
		*size += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN;
	} else if (unlikely(mpcb->remove_addrs) &&
		   MAX_TCP_OPTION_SPACE - *size >=
		   mptcp_sub_len_remove_addr_align(mpcb->remove_addrs)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_REMOVE_ADDR;
		opts->remove_addrs = mpcb->remove_addrs;
		*size += mptcp_sub_len_remove_addr_align(opts->remove_addrs);

		if (skb)
			mpcb->remove_addrs = 0;
	} else if (!(opts->mptcp_options & OPTION_MP_CAPABLE) &&
		   !(opts->mptcp_options & OPTION_MP_JOIN) &&
		   ((unlikely(tp->mptcp->add_addr6) &&
		     MAX_TCP_OPTION_SPACE - *size <=
		     MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) ||
		    (unlikely(tp->mptcp->add_addr4) &&
		     MAX_TCP_OPTION_SPACE - *size >=
		     MPTCP_SUB_LEN_ADD_ADDR4_ALIGN))) {
		mptcp_debug("no space for add addr. unsent IPv4: %#x,IPv6: %#x\n",
				tp->mptcp->add_addr4, tp->mptcp->add_addr6);
		tp->mptcp_add_addr_ack = 1;
		tcp_send_ack(sk);
		tp->mptcp_add_addr_ack = 0;
	}

	if (unlikely(tp->mptcp->send_mp_prio) &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_PRIO_ALIGN) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_PRIO;
		if (skb)
			tp->mptcp->send_mp_prio = 0;
		*size += MPTCP_SUB_LEN_PRIO_ALIGN;
	}

	tp->mptcp->include_mpc = 0;
	return;
}

void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			 struct tcp_out_options *opts,
			 struct sk_buff *skb)
{
	if (unlikely(OPTION_MP_CAPABLE & opts->mptcp_options)) {
		struct mp_capable *mpc = (struct mp_capable *) ptr;

		mpc->kind = TCPOPT_MPTCP;

		if ((OPTION_TYPE_SYN & opts->mptcp_options) ||
		    (OPTION_TYPE_SYNACK & opts->mptcp_options)) {
			mpc->sender_key = opts->mp_capable.sender_key;
			mpc->len = MPTCP_SUB_LEN_CAPABLE_SYN;
			ptr += MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN >> 2;
		} else if (OPTION_TYPE_ACK & opts->mptcp_options) {
			mpc->sender_key = opts->mp_capable.sender_key;
			mpc->receiver_key = opts->mp_capable.receiver_key;
			mpc->len = MPTCP_SUB_LEN_CAPABLE_ACK;
			ptr += MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN >> 2;
		}

		mpc->sub = MPTCP_SUB_CAPABLE;
		mpc->ver = 0;
		mpc->c = opts->dss_csum ? 1 : 0;
		mpc->rsv = 0;
		mpc->s = 1;
	}

	if (unlikely(OPTION_MP_JOIN & opts->mptcp_options)) {
		struct mp_join *mpj = (struct mp_join *) ptr;

		mpj->kind = TCPOPT_MPTCP;
		mpj->sub = MPTCP_SUB_JOIN;
		mpj->rsv = 0;
		mpj->addr_id = opts->addr_id;

		if (OPTION_TYPE_SYN & opts->mptcp_options) {
			mpj->len = MPTCP_SUB_LEN_JOIN_SYN;
			mpj->u.syn.token = opts->mp_join_syns.token;
			mpj->u.syn.nonce = opts->mp_join_syns.sender_nonce;
			mpj->b = tp->mptcp->low_prio;
			ptr += MPTCP_SUB_LEN_JOIN_SYN_ALIGN >> 2;
		} else if (OPTION_TYPE_SYNACK & opts->mptcp_options) {
			mpj->len = MPTCP_SUB_LEN_JOIN_SYNACK;
			mpj->u.synack.mac =
				opts->mp_join_syns.sender_truncated_mac;
			mpj->u.synack.nonce = opts->mp_join_syns.sender_nonce;
			mpj->b = tp->mptcp->low_prio;
			ptr += MPTCP_SUB_LEN_JOIN_SYNACK_ALIGN >> 2;
		} else if (OPTION_TYPE_ACK & opts->mptcp_options) {
			mpj->len = MPTCP_SUB_LEN_JOIN_ACK;
			memcpy(mpj->u.ack.mac,
					opts->mp_join_ack.sender_mac, 20);
			ptr += MPTCP_SUB_LEN_JOIN_ACK_ALIGN >> 2;
		}
	}
	if (unlikely(OPTION_ADD_ADDR & opts->mptcp_options)) {
		struct mp_add_addr *mpadd = (struct mp_add_addr *) ptr;

		mpadd->kind = TCPOPT_MPTCP;
		if (opts->addr4) {
			mpadd->len = MPTCP_SUB_LEN_ADD_ADDR4;
			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 4;
			mpadd->addr_id = opts->addr4->id;
			mpadd->u.v4.addr = opts->addr4->addr;
			ptr += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN >> 2;
		} else if (opts->addr6) {
			mpadd->len = MPTCP_SUB_LEN_ADD_ADDR6;
			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 6;
			mpadd->addr_id = opts->addr6->id;
			memcpy(&mpadd->u.v6.addr, &opts->addr6->addr,
			       sizeof(mpadd->u.v6.addr));
			ptr += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN >> 2;
		} else {
			BUG();
		}
	}
	if (unlikely(OPTION_REMOVE_ADDR & opts->mptcp_options)) {
		struct mp_remove_addr *mprem = (struct mp_remove_addr *) ptr;
		u8 *addrs_id, id;

		mprem->kind = TCPOPT_MPTCP;
		mprem->len = mptcp_sub_len_remove_addr(opts->remove_addrs);
		mprem->sub = MPTCP_SUB_REMOVE_ADDR;
		mprem->rsv = 0;
		addrs_id = &mprem->addrs_id;

		mptcp_for_each_bit_set(opts->remove_addrs, id)
			*(addrs_id++) = id;

		ptr += mptcp_sub_len_remove_addr_align(opts->remove_addrs) >> 2;
	}
	if (unlikely(OPTION_MP_FAIL & opts->mptcp_options)) {
		struct mp_fail *mpfail = (struct mp_fail *) ptr;

		mpfail->kind = TCPOPT_MPTCP;
		mpfail->len = MPTCP_SUB_LEN_FAIL;
		mpfail->sub = MPTCP_SUB_FAIL;
		mpfail->rsv1 = 0;
		mpfail->rsv2 = 0;
		mpfail->data_seq = htonll(((u64)opts->data_ack << 32) | opts->data_seq);

		ptr += MPTCP_SUB_LEN_FAIL_ALIGN >> 2;
	}
	if (unlikely(OPTION_MP_FCLOSE & opts->mptcp_options)) {
		struct mp_fclose *mpfclose = (struct mp_fclose *) ptr;

		mpfclose->kind = TCPOPT_MPTCP;
		mpfclose->len = MPTCP_SUB_LEN_FCLOSE;
		mpfclose->sub = MPTCP_SUB_FCLOSE;
		mpfclose->rsv1 = 0;
		mpfclose->rsv2 = 0;
		mpfclose->key = opts->mp_capable.receiver_key;

		ptr += MPTCP_SUB_LEN_FCLOSE_ALIGN >> 2;
	}

	if (OPTION_DATA_ACK & opts->mptcp_options) {
		if (!mptcp_is_data_seq(skb)) {
			struct mp_dss *mdss = (struct mp_dss *) ptr;

			mdss->kind = TCPOPT_MPTCP;
			mdss->sub = MPTCP_SUB_DSS;
			mdss->rsv1 = 0;
			mdss->rsv2 = 0;
			mdss->F = 0;
			mdss->m = 0;
			mdss->M = 0;
			mdss->a = 0;
			mdss->A = 1;
			mdss->len = mptcp_sub_len_dss(mdss, tp->mpcb->rx_opt.dss_csum);

			ptr++;
			*ptr++ = htonl(opts->data_ack);
		} else {
			/**** Just update the data_ack ****/

			/* Get pointer to data_ack-field. MPTCP is always at
			 * the end of the TCP-options.
			 */
			/* TODO if we allow sending 64-bit dseq's we have to change "16" */
			__be32 *dack = (__be32 *)(skb->data + (tcp_hdr(skb)->doff << 2) - 16);

			*dack = htonl(opts->data_ack);
		}
	}
	if (unlikely(OPTION_MP_PRIO & opts->mptcp_options)) {
		struct mp_prio *mpprio = (struct mp_prio *)ptr;

		mpprio->kind = TCPOPT_MPTCP;
		mpprio->len = MPTCP_SUB_LEN_PRIO;
		mpprio->sub = MPTCP_SUB_PRIO;
		mpprio->rsv = 0;
		mpprio->b = tp->mptcp->low_prio;
		mpprio->addr_id = TCPOPT_NOP;

		ptr += MPTCP_SUB_LEN_PRIO_ALIGN >> 2;
	}
}

/**
 * Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
struct sk_buff *mptcp_next_segment(struct sock *meta_sk, int *reinject)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;
	if (reinject)
		*reinject = 0;

	/* If it is the meta-sk and we are in fallback-mode, just take from
	 * the meta-send-queue */
	if (!is_meta_sk(meta_sk) ||
	    mpcb->infinite_mapping || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		if (reinject)
			*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_write_pending &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = get_available_subflow(mpcb, NULL);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb && reinject)
				*reinject = -1;
		}
	}
	return skb;
}

/* Sends the datafin */
void mptcp_send_fin(struct sock *meta_sk)
{
	struct sk_buff *skb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	if ((1 << meta_sk->sk_state) & (TCPF_CLOSE_WAIT | TCPF_LAST_ACK))
		meta_tp->mpcb->passive_close = 1;

	if (tcp_send_head(meta_sk)) {
		skb = tcp_write_queue_tail(meta_sk);
		TCP_SKB_CB(skb)->end_seq++;
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN | MPTCPHDR_SEQ;
		meta_tp->write_seq++;
	} else {
		for (;;) {
			skb = alloc_skb_fclone(MAX_TCP_HEADER, GFP_KERNEL);
			if (skb)
				break;
			yield();
		}
		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);
		tcp_init_nondata_skb(skb, 0, TCPHDR_ACK);
		TCP_SKB_CB(skb)->seq = meta_tp->write_seq;
		TCP_SKB_CB(skb)->end_seq = meta_tp->write_seq + 1;
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN | MPTCPHDR_SEQ;
		/* FIN eats a sequence byte, write_seq advanced by
		 * tcp_queue_skb().
		 */
		tcp_queue_skb(meta_sk, skb);
	}
	__tcp_push_pending_frames(meta_sk, mptcp_sysctl_mss(), TCP_NAGLE_OFF);
}

void mptcp_send_active_reset(struct sock *meta_sk, gfp_t priority)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk = NULL, *sk_it = NULL, *sk_tmp;

	if (!mpcb->cnt_subflows)
		return;

	/* First - select a socket */
	if (!mptcp_test_any_sk(mpcb, sk_it, tcp_sk(sk_it)->send_mp_fclose)) {
		sk = mptcp_select_ack_sock(mpcb, 0);

		tcp_sk(sk)->send_mp_fclose = 1;
	}

	/** Reset all other subflows */

	/* tcp_done must be handled with bh disabled */
	if (!in_serving_softirq())
		local_bh_disable();
	mptcp_for_each_sk_safe(mpcb, sk_it, sk_tmp) {
		if (tcp_sk(sk_it)->send_mp_fclose) {
			sk = sk_it;
			continue;
		}

		sk_it->sk_err = ECONNRESET;
		tcp_send_active_reset(sk_it, GFP_ATOMIC);
		mptcp_sub_force_close(sk_it);
	}
	if (!in_serving_softirq())
		local_bh_enable();

	tcp_send_ack(sk);

	if (!mpcb_meta_tp(mpcb)->send_mp_fclose) {
		struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);

		meta_icsk->icsk_rto = min(inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
		inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS,
					  meta_icsk->icsk_rto, TCP_RTO_MAX);
	}

	mpcb_meta_tp(mpcb)->send_mp_fclose = 1;
}

void mptcp_send_reset(struct sock *sk, struct sk_buff *skb)
{
	if (!sock_flag(sk, SOCK_DEAD))
		mptcp_sub_close(sk, 0);
	tcp_sk(sk)->mptcp->teardown = 1;

	if (sk->sk_family == AF_INET)
		tcp_v4_send_reset(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6)
		tcp_v6_send_reset(sk, skb);
#endif
}
