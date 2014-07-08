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
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>
#include <net/sock.h>

const int mptcp_dss_len = MPTCP_SUB_LEN_DSS_ALIGN + MPTCP_SUB_LEN_ACK_ALIGN +
	MPTCP_SUB_LEN_SEQ_ALIGN;

static inline int mptcp_pi_to_flag(int pi)
{
	return 1 << (pi - 1);
}

static inline int mptcp_sub_len_remove_addr(u16 bitfield)
{
	unsigned int c;
	for (c = 0; bitfield; c++)
		bitfield &= bitfield - 1;
	return MPTCP_SUB_LEN_REMOVE_ADDR + c - 1;
}

int mptcp_sub_len_remove_addr_align(u16 bitfield)
{
	return ALIGN(mptcp_sub_len_remove_addr(bitfield), 4);
}
EXPORT_SYMBOL(mptcp_sub_len_remove_addr_align);

/* If the sub-socket sk available to send the skb? */
static int mptcp_is_available(struct sock *sk, struct sk_buff *skb,
			      unsigned int *mss, bool zero_wnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now;

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return 0;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return 0;

	if (tp->pf ||
	    (tp->mpcb->noneligible & mptcp_pi_to_flag(tp->mptcp->path_index)))
		return 0;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return 0;
		else if (tp->snd_una != tp->high_seq)
			return 0;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return 0;
	}

	if (!tcp_cwnd_test(tp, skb))
		return 0;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return 0;

	mss_now = tcp_current_mss(sk);
	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return 0;

	if (mss)
		*mss = mss_now;

	return 1;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
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
					  unsigned int *mss_now,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *lowpriosk = NULL, *backupsk = NULL;
	unsigned int mss = 0, mss_lowprio = 0, mss_backup = 0;
	u32 min_time_to_peer = 0xffffffff, lowprio_min_time_to_peer = 0xffffffff;
	int cnt_backups = 0;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *)mpcb->connection_list;
		if (!mptcp_is_available(bestsk, skb, mss_now, zero_wnd_test))
			bestsk = NULL;
		return bestsk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(sk, skb, mss_now, zero_wnd_test))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		int this_mss;

		if (tp->mptcp->rcv_low_prio || tp->mptcp->low_prio)
			cnt_backups++;

		if ((tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) &&
		    tp->srtt < lowprio_min_time_to_peer) {

			if (!mptcp_is_available(sk, skb, &this_mss, zero_wnd_test))
				continue;

			if (mptcp_dont_reinject_skb(tp, skb)) {
				mss_backup = this_mss;
				backupsk = sk;
				continue;
			}

			lowprio_min_time_to_peer = tp->srtt;
			lowpriosk = sk;
			mss_lowprio = this_mss;
		} else if (!(tp->mptcp->rcv_low_prio || tp->mptcp->low_prio) &&
			   tp->srtt < min_time_to_peer) {
			if (!mptcp_is_available(sk, skb, &this_mss, zero_wnd_test))
				continue;

			if (mptcp_dont_reinject_skb(tp, skb)) {
				mss_backup = this_mss;
				backupsk = sk;
				continue;
			}

			min_time_to_peer = tp->srtt;
			bestsk = sk;
			mss = this_mss;
		}
	}

	if (mpcb->cnt_established == cnt_backups && lowpriosk) {
		mss = mss_lowprio;
		sk = lowpriosk;
	} else if (bestsk) {
		sk = bestsk;
	} else if (backupsk){
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		mss = mss_backup;
		sk = backupsk;
	}

	if (mss_now)
		*mss_now = mss;

	return sk;
}

/* get the data-seq and end-data-seq and store them again in the
 * tcp_skb_cb
 */
static int mptcp_reconstruct_mapping(struct sk_buff *skb, struct sk_buff *orig_skb)
{
	struct mp_dss *mpdss = (struct mp_dss *)TCP_SKB_CB(skb)->dss;
	u32 *p32;
	u16 *p16;

	if (!mpdss || !mpdss->M)
		return 1;

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

	return 0;
}

/* Reinject data from one TCP subflow to the meta_sk. If sk == NULL, we are
 * coming from the meta-retransmit-timer
 */
static void __mptcp_reinject_data(struct sk_buff *orig_skb, struct sock *meta_sk,
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
		skb = pskb_copy_for_clone(orig_skb, GFP_ATOMIC);
	} else {
		__skb_unlink(orig_skb, &sk->sk_write_queue);
		sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
		sk->sk_wmem_queued -= orig_skb->truesize;
		sk_mem_uncharge(sk, orig_skb->truesize);
		skb = orig_skb;
	}
	if (unlikely(!skb))
		return;

	if (sk && mptcp_reconstruct_mapping(skb, orig_skb)) {
		__kfree_skb(skb);
		return;
	}

	skb->sk = meta_sk;

	/* If it reached already the destination, we don't have to reinject it */
	if (!after(TCP_SKB_CB(skb)->end_seq, meta_tp->snd_una)) {
		__kfree_skb(skb);
		return;
	}

	/* Only reinject segments that are fully covered by the mapping */
	if (skb->len + (mptcp_is_data_fin(skb) ? 1 : 0) !=
	    TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq) {
		u32 seq = TCP_SKB_CB(skb)->seq;
		u32 end_seq = TCP_SKB_CB(skb)->end_seq;

		__kfree_skb(skb);

		/* Ok, now we have to look for the full mapping in the meta
		 * send-queue :S
		 */
		tcp_for_write_queue(skb, meta_sk) {
			/* Not yet at the mapping? */
			if (before(TCP_SKB_CB(skb)->seq, seq))
				continue;
			/* We have passed by the mapping */
			if (after(TCP_SKB_CB(skb)->end_seq, end_seq))
				return;

			__mptcp_reinject_data(skb, meta_sk, NULL, 1);
		}
		return;
	}

	/* Segment goes back to the MPTCP-layer. So, we need to zero the
	 * path_mask/dss.
	 */
	memset(TCP_SKB_CB(skb)->dss, 0 , mptcp_dss_len);

	/* If it's empty, just add */
	if (skb_queue_empty(&mpcb->reinject_queue)) {
		skb_queue_head(&mpcb->reinject_queue, skb);
		return;
	}

	/* Find place to insert skb - or even we can 'drop' it, as the
	 * data is already covered by other skb's in the reinject-queue.
	 *
	 * This is inspired by code from tcp_data_queue.
	 */

	skb1 = skb_peek_tail(&mpcb->reinject_queue);
	seq = TCP_SKB_CB(skb)->seq;
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
	end_seq = TCP_SKB_CB(skb)->end_seq;
	if (skb1 && before(seq, TCP_SKB_CB(skb1)->end_seq)) {
		if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			/* All the bits are present. Don't reinject */
			__kfree_skb(skb);
			return;
		}
		if (seq == TCP_SKB_CB(skb1)->seq) {
			if (skb_queue_is_first(&mpcb->reinject_queue, skb1))
				skb1 = NULL;
			else
				skb1 = skb_queue_prev(&mpcb->reinject_queue, skb1);
		}
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
	return;
}

/* Inserts data into the reinject queue */
void mptcp_reinject_data(struct sock *sk, int clone_it)
{
	struct sk_buff *skb_it, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = tp->meta_sk;

	/* It has already been closed - there is really no point in reinjecting */
	if (meta_sk->sk_state == TCP_CLOSE)
		return;

	skb_queue_walk_safe(&sk->sk_write_queue, skb_it, tmp) {
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb_it);
		/* Subflow syn's and fin's are not reinjected.
		 *
		 * As well as empty subflow-fins with a data-fin.
		 * They are reinjected below (without the subflow-fin-flag)
		 */
		if (tcb->tcp_flags & TCPHDR_SYN ||
		    (tcb->tcp_flags & TCPHDR_FIN && !mptcp_is_data_fin(skb_it)) ||
		    (tcb->tcp_flags & TCPHDR_FIN && mptcp_is_data_fin(skb_it) && !skb_it->len))
			continue;

		__mptcp_reinject_data(skb_it, meta_sk, sk, clone_it);
	}

	skb_it = tcp_write_queue_tail(meta_sk);
	/* If sk has sent the empty data-fin, we have to reinject it too. */
	if (skb_it && mptcp_is_data_fin(skb_it) && skb_it->len == 0 &&
	    TCP_SKB_CB(skb_it)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index)) {
		__mptcp_reinject_data(skb_it, meta_sk, NULL, 1);
	}

	mptcp_push_pending_frames(meta_sk);

	tp->pf = 1;
}
EXPORT_SYMBOL(mptcp_reinject_data);

static void mptcp_combine_dfin(struct sk_buff *skb, struct sock *meta_sk,
			       struct sock *subsk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk_it;
	int all_empty = 1, all_acked;

	/* In infinite mapping we always try to combine */
	if (mpcb->infinite_mapping_snd && tcp_close_state(subsk)) {
		subsk->sk_shutdown |= SEND_SHUTDOWN;
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
		return;
	}

	/* Don't combine, if they didn't combine - otherwise we end up in
	 * TIME_WAIT, even if our app is smart enough to avoid it
	 */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN) {
		if (!mpcb->dfin_combined)
			return;
	}

	/* If no other subflow has data to send, we can combine */
	mptcp_for_each_sk(mpcb, sk_it) {
		if (!mptcp_sk_can_send(sk_it))
			continue;

		if (!tcp_write_queue_empty(sk_it))
			all_empty = 0;
	}

	/* If all data has been DATA_ACKed, we can combine.
	 * -1, because the data_fin consumed one byte
	 */
	all_acked = (meta_tp->snd_una == (meta_tp->write_seq - 1));

	if ((all_empty || all_acked) && tcp_close_state(subsk)) {
		subsk->sk_shutdown |= SEND_SHUTDOWN;
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
	}
}

static int mptcp_write_dss_mapping(struct tcp_sock *tp, struct sk_buff *skb,
				   __be32 *ptr)
{
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	__be32 *start = ptr;
	__u16 data_len;

	*ptr++ = htonl(tcb->seq); /* data_seq */

	/* If it's a non-data DATA_FIN, we set subseq to 0 (draft v7) */
	if (mptcp_is_data_fin(skb) && skb->len == 0)
		*ptr++ = 0; /* subseq */
	else
		*ptr++ = htonl(tp->write_seq - tp->mptcp->snt_isn); /* subseq */

	if (tcb->mptcp_flags & MPTCPHDR_INF)
		data_len = 0;
	else
		data_len = tcb->end_seq - tcb->seq;

	if (tp->mpcb->dss_csum && data_len) {
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

	return ptr - start;
}

static int mptcp_write_dss_data_ack(struct tcp_sock *tp, struct sk_buff *skb,
				    __be32 *ptr)
{
	struct mp_dss *mdss = (struct mp_dss *)ptr;
	__be32 *start = ptr;

	mdss->kind = TCPOPT_MPTCP;
	mdss->sub = MPTCP_SUB_DSS;
	mdss->rsv1 = 0;
	mdss->rsv2 = 0;
	mdss->F = mptcp_is_data_fin(skb) ? 1 : 0;
	mdss->m = 0;
	mdss->M = mptcp_is_data_seq(skb) ? 1 : 0;
	mdss->a = 0;
	mdss->A = 1;
	mdss->len = mptcp_sub_len_dss(mdss, tp->mpcb->dss_csum);
	ptr++;

	*ptr++ = htonl(mptcp_meta_tp(tp)->rcv_nxt);

	return ptr - start;
}

/* RFC6824 states that once a particular subflow mapping has been sent
 * out it must never be changed. However, packets may be split while
 * they are in the retransmission queue (due to SACK or ACKs) and that
 * arguably means that we would change the mapping (e.g. it splits it,
 * our sends out a subset of the initial mapping).
 *
 * Furthermore, the skb checksum is not always preserved across splits
 * (e.g. mptcp_fragment) which would mean that we need to recompute
 * the DSS checksum in this case.
 *
 * To avoid this we save the initial DSS mapping which allows us to
 * send the same DSS mapping even for fragmented retransmits.
 */
static void mptcp_save_dss_data_seq(struct tcp_sock *tp, struct sk_buff *skb)
{
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	__be32 *ptr = (__be32 *)tcb->dss;

	tcb->mptcp_flags |= MPTCPHDR_SEQ;

	ptr += mptcp_write_dss_data_ack(tp, skb, ptr);
	ptr += mptcp_write_dss_mapping(tp, skb, ptr);
}

/* Write the saved DSS mapping to the header */
static int mptcp_write_dss_data_seq(struct tcp_sock *tp, struct sk_buff *skb,
				     __be32 *ptr)
{
	__be32 *start = ptr;

	memcpy(ptr, TCP_SKB_CB(skb)->dss, mptcp_dss_len);

	/* update the data_ack */
	start[1] = htonl(mptcp_meta_tp(tp)->rcv_nxt);

	/* dss is in a union with inet_skb_parm and
	 * the IP layer expects zeroed IPCB fields.
	 */
	memset(TCP_SKB_CB(skb)->dss, 0 , mptcp_dss_len);

	return mptcp_dss_len/sizeof(*ptr);
}

static struct sk_buff *mptcp_skb_entail(struct sock *sk, struct sk_buff *skb,
					int reinject)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct tcp_skb_cb *tcb;
	struct sk_buff *subskb = NULL;

	if (!reinject)
		TCP_SKB_CB(skb)->mptcp_flags |= (mpcb->snd_hiseq_index ?
						  MPTCPHDR_SEQ64_INDEX : 0);

	subskb = pskb_copy_for_clone(skb, GFP_ATOMIC);
	if (!subskb)
		return NULL;

	TCP_SKB_CB(skb)->path_mask |= mptcp_pi_to_flag(tp->mptcp->path_index);

	if (!(sk->sk_route_caps & NETIF_F_ALL_CSUM) &&
	    skb->ip_summed == CHECKSUM_PARTIAL) {
		subskb->csum = skb->csum = skb_checksum(skb, 0, skb->len, 0);
		subskb->ip_summed = skb->ip_summed = CHECKSUM_NONE;
	}

	tcb = TCP_SKB_CB(subskb);

	if (mptcp_is_data_fin(subskb))
		mptcp_combine_dfin(subskb, meta_sk, sk);

	if (tp->mpcb->infinite_mapping_snd)
		goto no_data_seq;

	if (tp->mpcb->send_infinite_mapping &&
	    !before(tcb->seq, mptcp_meta_tp(tp)->snd_nxt)) {
		tp->mptcp->fully_established = 1;
		tp->mpcb->infinite_mapping_snd = 1;
		tp->mptcp->infinite_cutoff_seq = tp->write_seq;
		tcb->mptcp_flags |= MPTCPHDR_INF;
	}

	mptcp_save_dss_data_seq(tp, subskb);

no_data_seq:
	tcb->seq = tp->write_seq;
	tcb->sacked = 0; /* reset the sacked field: from the point of view
			  * of this subflow, we are sending a brand new
			  * segment */
	/* Take into account seg len */
	tp->write_seq += subskb->len + ((tcb->tcp_flags & TCPHDR_FIN) ? 1 : 0);
	tcb->end_seq = tp->write_seq;

	/* If it's a non-payload DATA_FIN (also no subflow-fin), the
	 * segment is not part of the subflow but on a meta-only-level
	 */
	if (!mptcp_is_data_fin(subskb) || tcb->end_seq != tcb->seq) {
		tcp_add_write_queue_tail(sk, subskb);
		sk->sk_wmem_queued += subskb->truesize;
		sk_mem_charge(sk, subskb->truesize);
	}

	return subskb;
}

static void mptcp_sub_event_new_data_sent(struct sock *sk,
					  struct sk_buff *subskb,
					  struct sk_buff *skb)
{
	/* If it's a non-payload DATA_FIN (also no subflow-fin), the
	 * segment is not part of the subflow but on a meta-only-level
	 *
	 * We free it, because it has been queued nowhere.
	 */
	if (!mptcp_is_data_fin(subskb) ||
	    (TCP_SKB_CB(subskb)->end_seq != TCP_SKB_CB(subskb)->seq)) {
		tcp_event_new_data_sent(sk, subskb);
		tcp_sk(sk)->mptcp->second_packet = 1;
		tcp_sk(sk)->mptcp->last_end_data_seq = TCP_SKB_CB(skb)->end_seq;
	} else {
		kfree_skb(subskb);
	}
}

/* Handle the packets and sockets after a tcp_transmit_skb failed */
static void mptcp_transmit_skb_failed(struct sock *sk, struct sk_buff *skb,
				      struct sk_buff *subskb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;

	/* No work to do if we are in infinite mapping mode
	 * There is only one subflow left and we cannot send this segment on
	 * another subflow.
	 */
	if (mpcb->infinite_mapping_snd)
		return;

	TCP_SKB_CB(skb)->path_mask &= ~mptcp_pi_to_flag(tp->mptcp->path_index);

	if (TCP_SKB_CB(subskb)->tcp_flags & TCPHDR_FIN) {
		/* If it is a subflow-fin we must leave it on the
		 * subflow-send-queue, so that the probe-timer
		 * can retransmit it.
		 */
		if (!tp->packets_out && !inet_csk(sk)->icsk_pending)
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
						  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	} else if (mptcp_is_data_fin(subskb) &&
		   TCP_SKB_CB(subskb)->end_seq == TCP_SKB_CB(subskb)->seq) {
		/* An empty data-fin has not been enqueued on the subflow
		 * and thus we free it.
		 */

		kfree_skb(subskb);
	} else {
		/* In all other cases we remove it from the sub-queue.
		 * Other subflows may send it, or the probe-timer will
		 * handle it.
		 */
		tcp_advance_send_head(sk, subskb);

		/* tcp_add_write_queue_tail initialized highest_sack. We have
		 * to reset it, if necessary.
		 */
		if (tp->highest_sack == subskb)
			tp->highest_sack = NULL;

		tcp_unlink_write_queue(subskb, sk);
		tp->write_seq -= subskb->len;
		sk_wmem_free_skb(sk, subskb);
	}
}

/* Fragment an skb and update the mptcp meta-data. Due to reinject, we
 * might need to undo some operations done by tcp_fragment.
 */
static int mptcp_fragment(struct sock *meta_sk, struct sk_buff *skb, u32 len,
			  unsigned int mss_now, gfp_t gfp, int reinject)
{
	int ret, diff, old_factor;
	struct sk_buff *buff;
	u8 flags;

	if (skb_headlen(skb) < len)
		diff = skb->len - len;
	else
		diff = skb->data_len;
	old_factor = tcp_skb_pcount(skb);

	ret = tcp_fragment(meta_sk, skb, len, mss_now, gfp);
	if (ret)
		return ret;

	buff = skb->next;

	flags = TCP_SKB_CB(skb)->mptcp_flags;
	TCP_SKB_CB(skb)->mptcp_flags = flags & ~(MPTCPHDR_FIN);
	TCP_SKB_CB(buff)->mptcp_flags = flags;

	/* If reinject == 1, the buff will be added to the reinject
	 * queue, which is currently not part of memory accounting. So
	 * undo the changes done by tcp_fragment and update the
	 * reinject queue. Also, undo changes to the packet counters.
	 */
	if (reinject == 1) {
		int undo = buff->truesize - diff;
		meta_sk->sk_wmem_queued -= undo;
		sk_mem_uncharge(meta_sk, undo);

		tcp_sk(meta_sk)->mpcb->reinject_queue.qlen++;
		meta_sk->sk_write_queue.qlen--;

		if (!before(tcp_sk(meta_sk)->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
			undo = old_factor - tcp_skb_pcount(skb) -
				tcp_skb_pcount(buff);
			if (undo)
				tcp_adjust_pcount(meta_sk, skb, -undo);
		}
	}

	return 0;
}

/* Inspired by tcp_write_wakeup */
int mptcp_write_wakeup(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb, *subskb;
	struct sock *sk_it;
	int ans = 0;

	if (meta_sk->sk_state == TCP_CLOSE)
		return -1;

	skb = tcp_send_head(meta_sk);
	if (skb &&
	    before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(meta_tp))) {
		int err;
		unsigned int mss;
		unsigned int seg_size = tcp_wnd_end(meta_tp) - TCP_SKB_CB(skb)->seq;
		struct sock *subsk = get_available_subflow(meta_sk, skb, &mss,
							   true);
		struct tcp_sock *subtp;
		if (!subsk)
			goto window_probe;
		subtp = tcp_sk(subsk);

		seg_size = min(tcp_wnd_end(meta_tp) - TCP_SKB_CB(skb)->seq,
			       tcp_wnd_end(subtp) - subtp->write_seq);

		if (before(meta_tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			meta_tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
			if (mptcp_fragment(meta_sk, skb, seg_size, mss,
					   GFP_ATOMIC, 0))
				return -1;
		} else if (!tcp_skb_pcount(skb)) {
			tcp_set_skb_tso_segs(meta_sk, skb, mss);
		}

		subskb = mptcp_skb_entail(subsk, skb, 0);
		if (!subskb)
			return -1;

		TCP_SKB_CB(subskb)->tcp_flags |= TCPHDR_PSH;
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		TCP_SKB_CB(subskb)->when = tcp_time_stamp;
		err = tcp_transmit_skb(subsk, subskb, 1, GFP_ATOMIC);
		if (unlikely(err)) {
			mptcp_transmit_skb_failed(subsk, skb, subskb);
			return err;
		}

		mptcp_check_sndseq_wrap(meta_tp, TCP_SKB_CB(skb)->end_seq -
						 TCP_SKB_CB(skb)->seq);
		tcp_event_new_data_sent(meta_sk, skb);
		mptcp_sub_event_new_data_sent(subsk, subskb, skb);

		return 0;
	} else {
window_probe:
		if (between(meta_tp->snd_up, meta_tp->snd_una + 1,
			    meta_tp->snd_una + 0xFFFF)) {
			mptcp_for_each_sk(meta_tp->mpcb, sk_it) {
				if (mptcp_sk_can_send_ack(sk_it))
					tcp_xmit_probe_skb(sk_it, 1);
			}
		}

		/* At least one of the tcp_xmit_probe_skb's has to succeed */
		mptcp_for_each_sk(meta_tp->mpcb, sk_it) {
			int ret;

			if (!mptcp_sk_can_send_ack(sk_it))
				continue;

			ret = tcp_xmit_probe_skb(sk_it, 0);
			if (unlikely(ret > 0))
				ans = ret;
		}
		return ans;
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
	struct sk_buff *skb_head;

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
	if (tcp_time_stamp - tp->mptcp->last_rbuf_opti < tp->srtt >> 3)
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt < tp_it->srtt && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);
				if (tp_it->snd_ssthresh != TCP_INFINITE_SSTHRESH)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				tp->mptcp->last_rbuf_opti = tcp_time_stamp;
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

				if (4 * tp->srtt >= tp_it->srtt) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans)
			return skb_head;
	}
	return NULL;
}

bool mptcp_write_xmit(struct sock *meta_sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk), *subtp;
	struct sock *subsk;
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	unsigned int tso_segs, old_factor, sent_pkts;
	int cwnd_quota;
	int result;
	int reinject = 0;

	sent_pkts = 0;

	/* Currently mtu-probing is not done in MPTCP */
	if (!push_one && 0) {
		/* Do MTU probing. */
		result = tcp_mtu_probe(meta_sk);
		if (!result)
			return 0;
		else if (result > 0)
			sent_pkts = 1;
	}

	while ((skb = mptcp_next_segment(meta_sk, &reinject))) {
		unsigned int limit;
		struct sk_buff *subskb = NULL;
		u32 noneligible = mpcb->noneligible;

		if (reinject == 1) {
			if (!after(TCP_SKB_CB(skb)->end_seq, meta_tp->snd_una)) {
				/* Segment already reached the peer, take the next one */
				__skb_unlink(skb, &mpcb->reinject_queue);
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

subflow:
		subsk = get_available_subflow(meta_sk, skb, &mss_now, false);
		if (!subsk)
			break;
		subtp = tcp_sk(subsk);

		/* Since all subsocks are locked before calling the scheduler,
		 * the tcp_send_head should not change.
		 */
		BUG_ON(!reinject && tcp_send_head(meta_sk) != skb);
retry:
		/* If the segment was cloned (e.g. a meta retransmission),
		 * the header must be expanded/copied so that there is no
		 * corruption of TSO information.
		 */
		if (skb_unclone(skb, GFP_ATOMIC))
			break;

		old_factor = tcp_skb_pcount(skb);
		tcp_set_skb_tso_segs(meta_sk, skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);

		if (reinject == -1) {
			/* The packet has already once been sent, so if we
			 * change the pcount here we have to adjust packets_out
			 * in the meta-sk
			 */
			int diff = old_factor - tso_segs;

			if (diff)
				tcp_adjust_pcount(meta_sk, skb, diff);
		}

		cwnd_quota = tcp_cwnd_test(subtp, skb);
		if (!cwnd_quota) {
			/* May happen due to two cases:
			 *
			 * - if at the first selection we circumvented
			 *   the test due to a DATA_FIN (and got rejected at
			 *   tcp_snd_wnd_test), but the reinjected segment is not
			 *   a DATA_FIN.
			 * - if we take a DATA_FIN with data, but
			 *   tcp_set_skb_tso_segs() increases the number of
			 *   tso_segs to something > 1. Then, cwnd_test might
			 *   reject it.
			 */
			mpcb->noneligible |= mptcp_pi_to_flag(subtp->mptcp->path_index);
			continue;
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
			/* Do not try to defer the transmission of a reinjected
			 * segment. Send it directly.
			 * If it is not possible to send the TSO segment on the
			 * best subflow right now try to look for another subflow.
			 * If there is no subflow available defer the segment to avoid
			 * the call to mptcp_fragment.
			 */
			if (!push_one && !reinject && tcp_tso_should_defer(subsk, skb)) {
				mpcb->noneligible |= mptcp_pi_to_flag(subtp->mptcp->path_index);
				goto subflow;
			}
		}

		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(meta_tp))
			limit = tcp_mss_split_point(subsk, skb, mss_now,
						    min_t(unsigned int,
							  cwnd_quota,
							  subsk->sk_gso_max_segs),
						    nonagle);

		if (skb->len > limit &&
		    unlikely(mptcp_fragment(meta_sk, skb, limit, mss_now, gfp, reinject)))
			break;

		subskb = mptcp_skb_entail(subsk, skb, reinject);
		if (!subskb)
			break;

		mpcb->noneligible = noneligible;
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		TCP_SKB_CB(subskb)->when = tcp_time_stamp;
		if (unlikely(tcp_transmit_skb(subsk, subskb, 1, gfp))) {
			mptcp_transmit_skb_failed(subsk, skb, subskb);
			mpcb->noneligible |= mptcp_pi_to_flag(subtp->mptcp->path_index);
			continue;
		}

		if (!reinject) {
			mptcp_check_sndseq_wrap(meta_tp,
						TCP_SKB_CB(skb)->end_seq -
						TCP_SKB_CB(skb)->seq);
			tcp_event_new_data_sent(meta_sk, skb);
		}

		tcp_minshall_update(meta_tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb);
		tcp_sk(subsk)->mptcp->sent_pkts += tcp_skb_pcount(skb);

		mptcp_sub_event_new_data_sent(subsk, subskb, skb);

		if (reinject > 0) {
			__skb_unlink(skb, &mpcb->reinject_queue);
			kfree_skb(skb);
		}

		if (push_one)
			break;
	}

	mpcb->noneligible = 0;

	if (likely(sent_pkts)) {
		mptcp_for_each_sk(mpcb, subsk) {
			subtp = tcp_sk(subsk);
			if (subtp->mptcp->sent_pkts) {
				if (tcp_in_cwnd_reduction(subsk))
					subtp->prr_out += subtp->mptcp->sent_pkts;
				tcp_cwnd_validate(subsk);
				subtp->mptcp->sent_pkts = 0;
			}
		}
		return 0;
	}

	return !meta_tp->packets_out && tcp_send_head(meta_sk);
}

void mptcp_write_space(struct sock *sk)
{
	mptcp_push_pending_frames(mptcp_meta_sk(sk));
}

u32 __mptcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk), *meta_tp = mptcp_meta_tp(tp);
	int mss, free_space, full_space, window;

	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	mss = icsk->icsk_ack.rcv_mss;
	free_space = tcp_space(sk);
	full_space = min_t(int, meta_tp->window_clamp,
			tcp_full_space(sk));

	if (mss > full_space)
		mss = full_space;

	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		if (tcp_memory_pressure)
			/* TODO this has to be adapted when we support different
			 * MSS's among the subflows.
			 */
			meta_tp->rcv_ssthresh = min(meta_tp->rcv_ssthresh,
						    4U * meta_tp->advmss);

		if (free_space < mss)
			return 0;
	}

	if (free_space > meta_tp->rcv_ssthresh)
		free_space = meta_tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = meta_tp->rcv_wnd;
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

void mptcp_syn_options(struct sock *sk, struct tcp_out_options *opts,
		       unsigned *remaining)
{
	struct tcp_sock *tp = tcp_sk(sk);

	opts->options |= OPTION_MPTCP;
	if (is_master_tp(tp)) {
		opts->mptcp_options |= OPTION_MP_CAPABLE | OPTION_TYPE_SYN;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
		opts->mp_capable.sender_key = tp->mptcp_loc_key;
		opts->dss_csum = !!sysctl_mptcp_checksum;
	} else {
		struct mptcp_cb *mpcb = tp->mpcb;

		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_SYN;
		*remaining -= MPTCP_SUB_LEN_JOIN_SYN_ALIGN;
		opts->mp_join_syns.token = mpcb->mptcp_rem_token;
		opts->addr_id = tp->mptcp->loc_id;
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
		opts->mp_capable.sender_key = mtreq->mptcp_loc_key;
		opts->dss_csum = !!sysctl_mptcp_checksum || mtreq->dss_csum;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
	} else {
		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_SYNACK;
		opts->mp_join_syns.sender_truncated_mac =
				mtreq->mptcp_hash_tmac;
		opts->mp_join_syns.sender_nonce = mtreq->mptcp_loc_nonce;
		opts->addr_id = mtreq->loc_id;
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
	if (unlikely(tp->mptcp->send_mp_fail)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_FAIL;
		*size += MPTCP_SUB_LEN_FAIL;
		return;
	}

	if (unlikely(tp->send_mp_fclose)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_FCLOSE;
		opts->mp_capable.receiver_key = mpcb->mptcp_rem_key;
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
	if (unlikely(mpcb->infinite_mapping_snd) &&
	    tp->mptcp->fully_established &&
	    ((mpcb->send_infinite_mapping && tcb &&
	      !(tcb->mptcp_flags & MPTCPHDR_INF) &&
	      !before(tcb->seq, tp->mptcp->infinite_cutoff_seq)) ||
	     !mpcb->send_infinite_mapping))
		return;

	if (unlikely(tp->mptcp->include_mpc)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_CAPABLE |
				       OPTION_TYPE_ACK;
		*size += MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN;
		opts->mp_capable.sender_key = mpcb->mptcp_loc_key;
		opts->mp_capable.receiver_key = mpcb->mptcp_rem_key;
		opts->dss_csum = mpcb->dss_csum;

		if (skb)
			tp->mptcp->include_mpc = 0;
	}
	if (unlikely(tp->mptcp->pre_established)) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_ACK;
		*size += MPTCP_SUB_LEN_JOIN_ACK_ALIGN;
	}

	if (!tp->mptcp->include_mpc && !tp->mptcp->pre_established) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_DATA_ACK;
		/* If !skb, we come from tcp_current_mss and thus we always
		 * assume that the DSS-option will be set for the data-packet.
		 */
		if (skb && !mptcp_is_data_seq(skb)) {
			*size += MPTCP_SUB_LEN_ACK_ALIGN;
		} else {
			/* Doesn't matter, if csum included or not. It will be
			 * either 10 or 12, and thus aligned = 12
			 */
			*size += MPTCP_SUB_LEN_ACK_ALIGN +
				 MPTCP_SUB_LEN_SEQ_ALIGN;
		}

		*size += MPTCP_SUB_LEN_DSS_ALIGN;
	}

	if (mpcb->pm_ops->addr_signal)
		mpcb->pm_ops->addr_signal(sk, size, opts, skb);

	if (unlikely(tp->mptcp->send_mp_prio) &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_PRIO_ALIGN) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_MP_PRIO;
		if (skb)
			tp->mptcp->send_mp_prio = 0;
		*size += MPTCP_SUB_LEN_PRIO_ALIGN;
	}

	return;
}

u16 mptcp_select_window(struct sock *sk)
{
	u16 new_win		= tcp_select_window(sk);
	struct tcp_sock *tp	= tcp_sk(sk);
	struct tcp_sock *meta_tp = mptcp_meta_tp(tp);

	meta_tp->rcv_wnd	= tp->rcv_wnd;
	meta_tp->rcv_wup	= meta_tp->rcv_nxt;

	return new_win;
}

void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			 struct tcp_out_options *opts,
			 struct sk_buff *skb)
{
	if (unlikely(OPTION_MP_CAPABLE & opts->mptcp_options)) {
		struct mp_capable *mpc = (struct mp_capable *)ptr;

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
		mpc->a = opts->dss_csum;
		mpc->b = 0;
		mpc->rsv = 0;
		mpc->h = 1;
	}

	if (unlikely(OPTION_MP_JOIN & opts->mptcp_options)) {
		struct mp_join *mpj = (struct mp_join *)ptr;

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
			memcpy(mpj->u.ack.mac, &tp->mptcp->sender_mac[0], 20);
			ptr += MPTCP_SUB_LEN_JOIN_ACK_ALIGN >> 2;
		}
	}
	if (unlikely(OPTION_ADD_ADDR & opts->mptcp_options)) {
		struct mp_add_addr *mpadd = (struct mp_add_addr *)ptr;

		mpadd->kind = TCPOPT_MPTCP;
		if (opts->add_addr_v4) {
			mpadd->len = MPTCP_SUB_LEN_ADD_ADDR4;
			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 4;
			mpadd->addr_id = opts->add_addr4.addr_id;
			mpadd->u.v4.addr = opts->add_addr4.addr;
			ptr += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN >> 2;
		} else if (opts->add_addr_v6) {
			mpadd->len = MPTCP_SUB_LEN_ADD_ADDR6;
			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 6;
			mpadd->addr_id = opts->add_addr6.addr_id;
			memcpy(&mpadd->u.v6.addr, &opts->add_addr6.addr,
			       sizeof(mpadd->u.v6.addr));
			ptr += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN >> 2;
		}
	}
	if (unlikely(OPTION_REMOVE_ADDR & opts->mptcp_options)) {
		struct mp_remove_addr *mprem = (struct mp_remove_addr *)ptr;
		u8 *addrs_id;
		int id, len, len_align;

		len = mptcp_sub_len_remove_addr(opts->remove_addrs);
		len_align = mptcp_sub_len_remove_addr_align(opts->remove_addrs);

		mprem->kind = TCPOPT_MPTCP;
		mprem->len = len;
		mprem->sub = MPTCP_SUB_REMOVE_ADDR;
		mprem->rsv = 0;
		addrs_id = &mprem->addrs_id;

		mptcp_for_each_bit_set(opts->remove_addrs, id)
			*(addrs_id++) = id;

		/* Fill the rest with NOP's */
		if (len_align > len) {
			int i;
			for (i = 0; i < len_align - len; i++)
				*(addrs_id++) = TCPOPT_NOP;
		}

		ptr += len_align >> 2;
	}
	if (unlikely(OPTION_MP_FAIL & opts->mptcp_options)) {
		struct mp_fail *mpfail = (struct mp_fail *)ptr;

		mpfail->kind = TCPOPT_MPTCP;
		mpfail->len = MPTCP_SUB_LEN_FAIL;
		mpfail->sub = MPTCP_SUB_FAIL;
		mpfail->rsv1 = 0;
		mpfail->rsv2 = 0;
		mpfail->data_seq = htonll(tp->mpcb->csum_cutoff_seq);

		ptr += MPTCP_SUB_LEN_FAIL_ALIGN >> 2;
	}
	if (unlikely(OPTION_MP_FCLOSE & opts->mptcp_options)) {
		struct mp_fclose *mpfclose = (struct mp_fclose *)ptr;

		mpfclose->kind = TCPOPT_MPTCP;
		mpfclose->len = MPTCP_SUB_LEN_FCLOSE;
		mpfclose->sub = MPTCP_SUB_FCLOSE;
		mpfclose->rsv1 = 0;
		mpfclose->rsv2 = 0;
		mpfclose->key = opts->mp_capable.receiver_key;

		ptr += MPTCP_SUB_LEN_FCLOSE_ALIGN >> 2;
	}

	if (OPTION_DATA_ACK & opts->mptcp_options) {
		if (!mptcp_is_data_seq(skb))
			ptr += mptcp_write_dss_data_ack(tp, skb, ptr);
		else
			ptr += mptcp_write_dss_data_seq(tp, skb, ptr);
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

/* Returns the next segment to be sent from the mptcp meta-queue.
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

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		if (reinject)
			*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = get_available_subflow(meta_sk, NULL,
								   NULL, false);
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
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb = tcp_write_queue_tail(meta_sk);
	int mss_now;

	if ((1 << meta_sk->sk_state) & (TCPF_CLOSE_WAIT | TCPF_LAST_ACK))
		meta_tp->mpcb->passive_close = 1;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = mptcp_current_mss(meta_sk);

	if (tcp_send_head(meta_sk) != NULL) {
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		meta_tp->write_seq++;
	} else {
		/* Socket is locked, keep trying until memory is available. */
		for (;;) {
			skb = alloc_skb_fclone(MAX_TCP_HEADER,
					       meta_sk->sk_allocation);
			if (skb)
				break;
			yield();
		}
		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);

		tcp_init_nondata_skb(skb, meta_tp->write_seq, TCPHDR_ACK);
		TCP_SKB_CB(skb)->end_seq++;
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN;
		tcp_queue_skb(meta_sk, skb);
	}
	__tcp_push_pending_frames(meta_sk, mss_now, TCP_NAGLE_OFF);
}

void mptcp_send_active_reset(struct sock *meta_sk, gfp_t priority)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk = NULL, *sk_it = NULL, *tmpsk;

	if (!mpcb->cnt_subflows)
		return;

	WARN_ON(meta_tp->send_mp_fclose);

	/* First - select a socket */
	sk = mptcp_select_ack_sock(meta_sk);

	/* May happen if no subflow is in an appropriate state */
	if (!sk)
		return;

	/* We are in infinite mode - just send a reset */
	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv) {
		sk->sk_err = ECONNRESET;
		if (tcp_need_reset(sk->sk_state))
			tcp_send_active_reset(sk, priority);
		mptcp_sub_force_close(sk);
		return;
	}


	tcp_sk(sk)->send_mp_fclose = 1;
	/** Reset all other subflows */

	/* tcp_done must be handled with bh disabled */
	if (!in_serving_softirq())
		local_bh_disable();

	mptcp_for_each_sk_safe(mpcb, sk_it, tmpsk) {
		if (tcp_sk(sk_it)->send_mp_fclose)
			continue;

		sk_it->sk_err = ECONNRESET;
		if (tcp_need_reset(sk_it->sk_state))
			tcp_send_active_reset(sk_it, GFP_ATOMIC);
		mptcp_sub_force_close(sk_it);
	}

	if (!in_serving_softirq())
		local_bh_enable();

	tcp_send_ack(sk);
	inet_csk_reset_keepalive_timer(sk, inet_csk(sk)->icsk_rto);

	meta_tp->send_mp_fclose = 1;
}

static void mptcp_ack_retransmit_timer(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		goto out; /* Routing failure or similar */

	if (!tp->retrans_stamp)
		tp->retrans_stamp = tcp_time_stamp ? : 1;

	if (tcp_write_timeout(sk)) {
		tp->mptcp->pre_established = 0;
		sk_stop_timer(sk, &tp->mptcp->mptcp_ack_timer);
		tp->send_active_reset(sk, GFP_ATOMIC);
		goto out;
	}

	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (skb == NULL) {
		sk_reset_timer(sk, &tp->mptcp->mptcp_ack_timer,
			       jiffies + icsk->icsk_rto);
		return;
	}

	/* Reserve space for headers and prepare control bits */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tp->snd_una, TCPHDR_ACK);

	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	if (tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		sk_reset_timer(sk, &tp->mptcp->mptcp_ack_timer,
			       jiffies + icsk->icsk_rto);
		return;
	}


	icsk->icsk_retransmits++;
	icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	sk_reset_timer(sk, &tp->mptcp->mptcp_ack_timer,
		       jiffies + icsk->icsk_rto);
	if (retransmits_timed_out(sk, sysctl_tcp_retries1 + 1, 0, 0)) {
		__sk_dst_reset(sk);
	}

out:;
}

void mptcp_ack_handler(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct sock *meta_sk = mptcp_meta_sk(sk);

	bh_lock_sock(meta_sk);
	if (sock_owned_by_user(meta_sk)) {
		/* Try again later */
		sk_reset_timer(sk, &tcp_sk(sk)->mptcp->mptcp_ack_timer,
			       jiffies + (HZ / 20));
		goto out_unlock;
	}

	if (sk->sk_state == TCP_CLOSE)
		goto out_unlock;

	mptcp_ack_retransmit_timer(sk);

	sk_mem_reclaim(sk);

out_unlock:
	bh_unlock_sock(meta_sk);
	sock_put(sk);
}

/* Similar to tcp_retransmit_skb
 *
 * The diff is that we handle the retransmission-stats (retrans_stamp) at the
 * meta-level.
 */
int mptcp_retransmit_skb(struct sock *meta_sk, struct sk_buff *skb)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sock *subsk;
	struct sk_buff *subskb;
	unsigned int limit, tso_segs, mss_now;
	int err = -1, oldpcount;

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 *
	 * This is a meta-retransmission thus we check on the meta-socket.
	 */
	if (atomic_read(&meta_sk->sk_wmem_alloc) >
	    min(meta_sk->sk_wmem_queued + (meta_sk->sk_wmem_queued >> 2), meta_sk->sk_sndbuf)) {
		return -EAGAIN;
	}

	/* We need to make sure that the retransmitted segment can be sent on a
	 * subflow right now. If it is too big, it needs to be fragmented.
	 */
	subsk = get_available_subflow(meta_sk, skb, &mss_now, false);
	if (!subsk) {
		/* We want to increase icsk_retransmits, thus return 0, so that
		 * mptcp_retransmit_timer enters the desired branch.
		 */
		err = 0;
		goto failed;
	}

	/* If the segment was cloned (e.g. a meta retransmission), the header
	 * must be expanded/copied so that there is no corruption of TSO
	 * information.
	 */
	if (skb_unclone(skb, GFP_ATOMIC)) {
		err = -ENOMEM;
		goto failed;
	}

	oldpcount = tcp_skb_pcount(skb);
	tcp_set_skb_tso_segs(meta_sk, skb, mss_now);
	tso_segs = tcp_skb_pcount(skb);
	BUG_ON(!tso_segs);

	/* The MSS might have changed and so the number of segments. We
	 * need to account for this change.
	 */
	if (unlikely(oldpcount != tso_segs))
		tcp_adjust_pcount(meta_sk, skb, oldpcount - tso_segs);

	limit = mss_now;
	if (tso_segs > 1 && !tcp_urg_mode(meta_tp))
		limit = tcp_mss_split_point(subsk, skb, mss_now,
					    min_t(unsigned int,
						  tcp_cwnd_test(tcp_sk(subsk), skb),
						  subsk->sk_gso_max_segs),
					          TCP_NAGLE_OFF);

	if (skb->len > limit &&
	    unlikely(mptcp_fragment(meta_sk, skb, limit, mss_now,
				    GFP_ATOMIC, 0)))
		goto failed;

	subskb = mptcp_skb_entail(subsk, skb, -1);
	if (!subskb)
		goto failed;

	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	TCP_SKB_CB(subskb)->when = tcp_time_stamp;
	err = tcp_transmit_skb(subsk, subskb, 1, GFP_ATOMIC);
	if (!err) {
		/* Update global TCP statistics. */
		TCP_INC_STATS(sock_net(meta_sk), TCP_MIB_RETRANSSEGS);

		/* Diff to tcp_retransmit_skb */

		/* Save stamp of the first retransmit. */
		if (!meta_tp->retrans_stamp)
			meta_tp->retrans_stamp = TCP_SKB_CB(subskb)->when;
		mptcp_sub_event_new_data_sent(subsk, subskb, skb);
	} else {
		mptcp_transmit_skb_failed(subsk, skb, subskb);
	}

failed:
	return err;
}

/* Similar to tcp_retransmit_timer
 *
 * The diff is that we have to handle retransmissions of the FAST_CLOSE-message
 * and that we don't have an srtt estimation at the meta-level.
 */
void mptcp_retransmit_timer(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);
	int err;

	/* In fallback, retransmission is handled at the subflow-level */
	if (!meta_tp->packets_out || mpcb->infinite_mapping_snd ||
	    mpcb->send_infinite_mapping)
		return;

	WARN_ON(tcp_write_queue_empty(meta_sk));

	if (!meta_tp->snd_wnd && !sock_flag(meta_sk, SOCK_DEAD) &&
	    !((1 << meta_sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
		struct inet_sock *meta_inet = inet_sk(meta_sk);
		if (meta_sk->sk_family == AF_INET) {
			LIMIT_NETDEBUG(KERN_DEBUG "MPTCP: Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
				       &meta_inet->inet_daddr,
				       ntohs(meta_inet->inet_dport),
				       meta_inet->inet_num, meta_tp->snd_una,
				       meta_tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (meta_sk->sk_family == AF_INET6) {
			LIMIT_NETDEBUG(KERN_DEBUG "MPTCP: Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
				       &meta_sk->sk_v6_daddr,
				       ntohs(meta_inet->inet_dport),
				       meta_inet->inet_num, meta_tp->snd_una,
				       meta_tp->snd_nxt);
		}
#endif
		if (tcp_time_stamp - meta_tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(meta_sk);
			return;
		}

		mptcp_retransmit_skb(meta_sk, tcp_write_queue_head(meta_sk));
		goto out_reset_timer;
	}

	if (tcp_write_timeout(meta_sk))
		return;

	if (meta_icsk->icsk_retransmits == 0)
		NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_TCPTIMEOUTS);

	meta_icsk->icsk_ca_state = TCP_CA_Loss;

	err = mptcp_retransmit_skb(meta_sk, tcp_write_queue_head(meta_sk));
	if (err > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!meta_icsk->icsk_retransmits)
			meta_icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS,
					  min(meta_icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		return;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	meta_icsk->icsk_backoff++;
	meta_icsk->icsk_retransmits++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (meta_sk->sk_state == TCP_ESTABLISHED &&
	    (meta_tp->thin_lto || sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(meta_tp) &&
	    meta_icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		meta_icsk->icsk_backoff = 0;
		/* We cannot do the same as in tcp_write_timer because the
		 * srtt is not set here.
		 */
		mptcp_set_rto(meta_sk);
	} else {
		/* Use normal (exponential) backoff */
		meta_icsk->icsk_rto = min(meta_icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
	inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS, meta_icsk->icsk_rto, TCP_RTO_MAX);

	return;
}

/* Modify values to an mptcp-level for the initial window of new subflows */
void mptcp_select_initial_window(int __space, __u32 mss, __u32 *rcv_wnd,
				__u32 *window_clamp, int wscale_ok,
				__u8 *rcv_wscale, __u32 init_rcv_wnd,
				 const struct sock *sk)
{
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;

	*window_clamp = mpcb->orig_window_clamp;
	__space = tcp_win_from_space(mpcb->orig_sk_rcvbuf);

	tcp_select_initial_window(__space, mss, rcv_wnd, window_clamp,
				  wscale_ok, rcv_wscale, init_rcv_wnd, sk);
}

unsigned int mptcp_current_mss(struct sock *meta_sk)
{
	unsigned int mss = 0;
	struct sock *sk;

	mptcp_for_each_sk(tcp_sk(meta_sk)->mpcb, sk) {
		int this_mss;

		if (!mptcp_sk_can_send(sk))
			continue;

		this_mss = tcp_current_mss(sk);
		if (this_mss > mss)
			mss = this_mss;
	}

	/* If no subflow is available, we take a default-mss from the
	 * meta-socket.
	 */
	return !mss ? tcp_current_mss(meta_sk) : mss;
}

int mptcp_select_size(const struct sock *meta_sk, bool sg)
{
	int mss = 0; /* We look for the smallest MSS */
	struct sock *sk;

	mptcp_for_each_sk(tcp_sk(meta_sk)->mpcb, sk) {
		int this_mss;

		if (!mptcp_sk_can_send(sk))
			continue;

		this_mss = tcp_sk(sk)->mss_cache;
		if (this_mss > mss)
			mss = this_mss;
	}

	if (sg) {
		if (mptcp_sk_can_gso(meta_sk)) {
			mss = SKB_WITH_OVERHEAD(2048 - MAX_TCP_HEADER);
		} else {
			int pgbreak = SKB_MAX_HEAD(MAX_TCP_HEADER);

			if (mss >= pgbreak &&
			    mss <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
				mss = pgbreak;
		}
	}

	return !mss ? tcp_sk(meta_sk)->mss_cache : mss;
}

int mptcp_check_snd_buf(const struct tcp_sock *tp)
{
	struct sock *sk;
	u32 rtt_max = tp->srtt;
	u64 bw_est;

	if (!tp->srtt)
		return tp->reordering + 1;

	mptcp_for_each_sk(tp->mpcb, sk) {
		if (!mptcp_sk_can_send(sk))
			continue;

		if (rtt_max < tcp_sk(sk)->srtt)
			rtt_max = tcp_sk(sk)->srtt;
	}

	bw_est = div64_u64(((u64)tp->snd_cwnd * rtt_max) << 16,
				(u64)tp->srtt);

	return max_t(unsigned int, (u32)(bw_est >> 16),
			tp->reordering + 1);

}

unsigned int mptcp_xmit_size_goal(struct sock *meta_sk, u32 mss_now,
				  int large_allowed)
{
	struct sock *sk;
	u32 xmit_size_goal = 0;

	if (large_allowed && mptcp_sk_can_gso(meta_sk)) {
		mptcp_for_each_sk(tcp_sk(meta_sk)->mpcb, sk) {
			int this_size_goal;

			if (!mptcp_sk_can_send(sk))
				continue;

			this_size_goal = tcp_xmit_size_goal(sk, mss_now, 1);
			if (this_size_goal > xmit_size_goal)
				xmit_size_goal = this_size_goal;
		}
	}

	return max(xmit_size_goal, mss_now);
}

/* Similar to tcp_trim_head - but we correctly copy the DSS-option */
int mptcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{

	if (skb_cloned(skb)) {
		if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
			return -ENOMEM;
	}

	__pskb_trim_head(skb, len);

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);

	/* Any change of skb->len requires recalculation of tso factor. */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(sk, skb, tcp_skb_mss(skb));

	return 0;
}
