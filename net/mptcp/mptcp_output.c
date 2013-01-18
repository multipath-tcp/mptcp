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

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
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
static struct sock *get_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *lowpriosk = NULL, *backupsk = NULL;
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
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
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
		if (tp->mptcp->rx_opt.low_prio || tp->mptcp->low_prio)
			cnt_backups++;

		if (mptcp_dont_reinject_skb(tp, skb))
			continue;

		if (!mptcp_is_available(sk, skb))
			continue;

		if ((tp->mptcp->rx_opt.low_prio || tp->mptcp->low_prio) &&
		    tp->srtt < lowprio_min_time_to_peer &&
		    !(skb && mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask)) {
			lowprio_min_time_to_peer = tp->srtt;
			lowpriosk = sk;
		} else if (!(tp->mptcp->rx_opt.low_prio || tp->mptcp->low_prio) &&
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
		skb = __pskb_copy(orig_skb, MAX_TCP_HEADER, GFP_ATOMIC);
	} else {
		__skb_unlink(orig_skb, &sk->sk_write_queue);
		sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
		sk->sk_wmem_queued -= orig_skb->truesize;
		sk_mem_uncharge(sk, orig_skb->truesize);
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
		__kfree_skb(skb);
		return -1;
	}

	/* Only reinject segments that are fully covered by the mapping */
	if (skb->len + (mptcp_is_data_fin(skb) ? 1 : 0) !=
	    TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq) {
		__kfree_skb(skb);
		return 0;
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
			return 0;
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
	return 0;
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

		/* Go to next segment, if it failed */
		if (__mptcp_reinject_data(skb_it, meta_sk, sk, clone_it))
			continue;
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


static void mptcp_combine_dfin(struct sk_buff *skb, struct sock *meta_sk,
			       struct sock *subsk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk_it;
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
static struct sk_buff *mptcp_skb_entail(struct sock *sk, struct sk_buff *skb,
					int reinject)
{
	__be32 *ptr;
	__u16 data_len;
	struct mp_dss *mdss;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct tcp_skb_cb *tcb;
	struct sk_buff *subskb;

	/* If the segment is reinjected, the clone is done already */
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
		if (reinject == -1)
			subskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
		else
			subskb = skb_clone(skb, GFP_ATOMIC);
	} else {
		/* It may still be a clone from tcp_transmit_skb of the old
		 * subflow during address-removal.
		 */
		if (skb_cloned(skb)) {
			subskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
			if (subskb) {
				__skb_unlink(skb, &mpcb->reinject_queue);
				kfree_skb(skb);
				skb = subskb;
			}
		} else {
			__skb_unlink(skb, &mpcb->reinject_queue);
			subskb = skb;
		}
	}
	if (!subskb)
		return NULL;

	TCP_SKB_CB(skb)->path_mask |= mptcp_pi_to_flag(tp->mptcp->path_index);

	if (!(sk->sk_route_caps & NETIF_F_ALL_CSUM) &&
	      skb->ip_summed == CHECKSUM_PARTIAL) {
		subskb->csum = skb->csum = skb_checksum(skb, 0, skb->len, 0);
		subskb->ip_summed = skb->ip_summed = CHECKSUM_NONE;
	}

	/* The subskb is going in the subflow send-queue. Its path-mask
	 * is not needed anymore and MUST be set to 0, as the path-mask
	 * is a union with inet_skb_param.
	 */
	tcb = TCP_SKB_CB(subskb);
	tcb->path_mask = 0;

	if (mptcp_is_data_fin(subskb))
		mptcp_combine_dfin(subskb, meta_sk, sk);


	/**** Write MPTCP DSS-option to the packet. ****/
	ptr = (__be32 *)(subskb->data - (MPTCP_SUB_LEN_DSS_ALIGN +
				      MPTCP_SUB_LEN_ACK_ALIGN +
				      MPTCP_SUB_LEN_SEQ_ALIGN));

	/* Then we start writing it from the start */
	mdss = (struct mp_dss *) ptr;

	mdss->kind = TCPOPT_MPTCP;
	mdss->sub = MPTCP_SUB_DSS;
	mdss->rsv1 = 0;
	mdss->rsv2 = 0;
	mdss->F = (mptcp_is_data_fin(subskb) ? 1 : 0);
	mdss->m = 0;
	mdss->M = 1;
	mdss->a = 0;
	mdss->A = 1;
	mdss->len = mptcp_sub_len_dss(mdss, tp->mpcb->dss_csum);

	if (tp->mpcb->send_infinite_mapping &&
	    tcb->seq >= mptcp_meta_tp(tp)->snd_nxt) {
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
	if (mptcp_is_data_fin(subskb) && subskb->len == 0)
		*ptr++ = 0; /* subseq */
	else
		*ptr++ = htonl(tp->write_seq - tp->mptcp->snt_isn); /* subseq */

	if (tp->mpcb->dss_csum && data_len) {
		__be16 *p16 = (__be16 *)ptr;
		__be32 hdseq = mptcp_get_highorder_sndbits(subskb, tp->mpcb);
		__wsum csum;
		*ptr = htonl(((data_len) << 16) |
				(TCPOPT_EOL << 8) |
				(TCPOPT_EOL));

		csum = csum_partial(ptr - 2, 12, subskb->csum);
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

static void mptcp_sub_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	/* If it's a non-payload DATA_FIN (also no subflow-fin), the
	 * segment is not part of the subflow but on a meta-only-level
	 *
	 * We free it, because it has been queued nowhere.
	 */
	if (!mptcp_is_data_fin(skb) ||
	    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq))
		tcp_event_new_data_sent(sk, skb);
	else
		kfree_skb(skb);
}

/* Handle the packets and sockets after a tcp_transmit_skb failed */
static void mptcp_transmit_skb_failed(struct sock *sk, struct sk_buff *skb,
				      struct sk_buff *subskb, int reinject)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;

	/* If it is a reinjection, we cannot modify the path-mask
	 * of the skb, because subskb == skb. And subskb has been
	 * freed above.
	 */
	if (reinject <= 0)
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
		tcp_unlink_write_queue(subskb, sk);
		tp->write_seq -= subskb->len;
		if (reinject <= 0) {
			sk_wmem_free_skb(sk, subskb);
		} else {
			/* Reinjections have not been cloned,
			 * we have to put them back on the queue.
			 */
			sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
			sk->sk_wmem_queued -= subskb->truesize;
			sk_mem_uncharge(sk, subskb->truesize);
			__skb_queue_head(&mpcb->reinject_queue, subskb);
		}
	}
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
static int mptcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
			  unsigned int mss_now, int reinject)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;

	if (WARN_ON(len > skb->len))
		return -EINVAL;

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	if (skb_cloned(skb) &&
	    skb_is_nonlinear(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */

	/* See below - if reinject == 1, the buff will be added to the reinject-
	 * queue, which is currently not part of the memory-accounting.
	 */
	if (reinject != 1) {
		sk->sk_wmem_queued += buff->truesize;
		sk_mem_charge(sk, buff->truesize);
	}
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;

	flags = TCP_SKB_CB(skb)->mptcp_flags;
	TCP_SKB_CB(skb)->mptcp_flags = flags & ~(MPTCPHDR_FIN);
	TCP_SKB_CB(buff)->mptcp_flags = flags;

	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
						       skb_put(buff, nsize),
						       nsize, 0);

		skb_trim(skb, len);

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_split(skb, buff, len);
	}

	buff->ip_summed = skb->ip_summed;

	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;
	buff->tstamp = skb->tstamp;

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	if (reinject == 1)
		__skb_queue_after(&tcp_sk(sk)->mpcb->reinject_queue, skb, buff);
	else
		tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

static int mptso_fragment(struct sock *sk, struct sk_buff *skb,
			  unsigned int len, unsigned int mss_now, gfp_t gfp,
			  int reinject)
{
	struct sk_buff *buff;
	int nlen = skb->len - len;
	u8 flags;

	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)
		return mptcp_fragment(sk, skb, len, mss_now, reinject);

	buff = sk_stream_alloc_skb(sk, 0, gfp);
	if (unlikely(buff == NULL))
		return -ENOMEM;

	/* See below - if reinject == 1, the buff will be added to the reinject-
	 * queue, which is currently not part of the memory-accounting.
	 */
	if (reinject != 1) {
		sk->sk_wmem_queued += buff->truesize;
		sk_mem_charge(sk, buff->truesize);
	}
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	flags = TCP_SKB_CB(skb)->mptcp_flags;
	TCP_SKB_CB(skb)->mptcp_flags = flags & ~(MPTCPHDR_FIN);
	TCP_SKB_CB(buff)->mptcp_flags = flags;

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;

	buff->ip_summed = skb->ip_summed = CHECKSUM_PARTIAL;
	skb_split(skb, buff, len);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	if (reinject == 1)
		__skb_queue_after(&tcp_sk(sk)->mpcb->reinject_queue, skb, buff);
	else
		tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

/* Inspired by tcp_write_wakeup */
int mptcp_write_wakeup(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb, *subskb;

	if ((skb = tcp_send_head(meta_sk)) != NULL &&
	    before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(meta_tp))) {
		int err;
		unsigned int mss;
		unsigned int seg_size = tcp_wnd_end(meta_tp) - TCP_SKB_CB(skb)->seq;
		struct sock *subsk = get_available_subflow(meta_sk, skb);
		if (!subsk)
			return -1;
		mss = tcp_current_mss(subsk);

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
			if (mptcp_fragment(meta_sk, skb, seg_size, mss, 0))
				return -1;
		} else if (!tcp_skb_pcount(skb)) {
			printk(KERN_ERR"%s should not happen with MPTCP!\n", __func__);
			BUG();
		}

		subskb = mptcp_skb_entail(subsk, skb, 0);
		if (!subskb)
			return -1;

		TCP_SKB_CB(subskb)->tcp_flags |= TCPHDR_PSH;
		TCP_SKB_CB(subskb)->when = tcp_time_stamp;
		err = tcp_transmit_skb(subsk, subskb, 1, GFP_ATOMIC);
		if (unlikely(err)) {
			mptcp_transmit_skb_failed(subsk, skb, subskb, 0);
			return err;
		}

		mptcp_check_sndseq_wrap(meta_tp, TCP_SKB_CB(skb)->end_seq -
						 TCP_SKB_CB(skb)->seq);
		tcp_event_new_data_sent(meta_sk, skb);
		mptcp_sub_event_new_data_sent(subsk, subskb);

		return 0;
	} else {
		struct sock *sk_it;
		int ans = 0;

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

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
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
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		int do_retrans = 0;
		mptcp_for_each_tp(tp->mpcb, tp_it) {
			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
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
			return skb_head;
	}
	return NULL;
}

int mptcp_write_xmit(struct sock *meta_sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk), *subtp;
	struct sock *subsk;
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;
	int reinject = 0;

	sent_pkts = 0;

	/* Currently mtu-probing is not done in MPTCP */
	if (!push_one && 0) {
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
		struct sk_buff *subskb = NULL;

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

		subsk = get_available_subflow(meta_sk, skb);
		if (!subsk)
			break;
		subtp = tcp_sk(subsk);
		mss_now = tcp_current_mss(subsk);

		/* This must be invoked even if we don't want
		 * to support TSO at the moment
		 */
		tso_segs = tcp_init_tso_segs(meta_sk, skb, mss_now);
		BUG_ON(!tso_segs);

		/* At the moment we do not support tso, hence
		 * tso_segs must be 1
		 */
		BUG_ON(tso_segs != 1);

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
		    unlikely(mptso_fragment(meta_sk, skb, limit, mss_now, gfp, reinject)))
			break;

		subskb = mptcp_skb_entail(subsk, skb, reinject);
		if (!subskb)
			break;

		TCP_SKB_CB(subskb)->when = tcp_time_stamp;
		if (unlikely(tcp_transmit_skb(subsk, subskb, 1, gfp))) {
			mptcp_transmit_skb_failed(subsk, skb, subskb, reinject);
			mpcb->noneligible |= mptcp_pi_to_flag(subtp->mptcp->path_index);
			continue;
		}

		if (!reinject) {
			mptcp_check_sndseq_wrap(meta_tp,
					TCP_SKB_CB(skb)->end_seq -
					TCP_SKB_CB(skb)->seq);
			tcp_event_new_data_sent(meta_sk, skb);
		}
		if (reinject > 0)
			mptcp_mark_reinjected(subsk, skb);

		tcp_minshall_update(meta_tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb);
		tcp_sk(subsk)->mptcp->sent_pkts += tcp_skb_pcount(skb);

		mptcp_sub_event_new_data_sent(subsk, subskb);

		if (push_one)
			break;
	}

	mpcb->noneligible = 0;

	if (likely(sent_pkts)) {
		mptcp_for_each_sk(mpcb, subsk) {
			subtp = tcp_sk(subsk);
			if (subtp->mptcp->sent_pkts) {
				if (inet_csk(subsk)->icsk_ca_state == TCP_CA_Recovery)
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
		struct mptcp_cb *mpcb = tp->mpcb;

		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_SYN;
		*remaining -= MPTCP_SUB_LEN_JOIN_SYN_ALIGN;
		opts->mp_join_syns.token = mpcb->mptcp_rem_token;
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
						&mtreq->mpcb->locaddr4[i];
				if (addr->addr.s_addr == ireq->loc_addr)
					opts->addr_id = addr->id;
			}
#if IS_ENABLED(CONFIG_IPV6)
		else /* IPv6 */
			mptcp_for_each_bit_set(mtreq->mpcb->loc6_bits, i) {
				struct mptcp_loc6 *addr =
						&mtreq->mpcb->locaddr6[i];
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
	struct tcp_sock *tp = tcp_sk(sk), *meta_tp = mptcp_meta_tp(tp);
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
	if (mpcb->infinite_mapping && tp->mptcp->fully_established &&
	    ((mpcb->send_infinite_mapping && tcb &&
	      !(tcb->mptcp_flags & MPTCPHDR_INF) &&
	      !before(tcb->seq, tp->mptcp->infinite_cutoff_seq)) ||
	     !mpcb->send_infinite_mapping))
		return;

	if (unlikely(tp->mptcp->include_mpc)) {
		opts->options |= OPTION_MPTCP;
		if (is_master_tp(tp)) {
			opts->mptcp_options |= OPTION_MP_CAPABLE |
					       OPTION_TYPE_ACK;
			*size += MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN;
			opts->mp_capable.sender_key = mpcb->mptcp_loc_key;
			opts->mp_capable.receiver_key = mpcb->mptcp_rem_key;
			opts->dss_csum = mpcb->dss_csum;
		} else {
			opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_ACK;
			*size += MPTCP_SUB_LEN_JOIN_ACK_ALIGN;

			if (skb)
				mptcp_hmac_sha1((u8 *)&mpcb->mptcp_loc_key,
						(u8 *)&mpcb->mptcp_rem_key,
						(u8 *)&tp->mptcp->mptcp_loc_nonce,
						(u8 *)&tp->mptcp->rx_opt.mptcp_recv_nonce,
						(u32 *)opts->mp_join_ack.sender_mac);
		}
	}

	if (!tp->mptcp_add_addr_ack && !tp->mptcp->include_mpc) {
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_DATA_ACK;
		/* If !skb, we come from tcp_current_mss and thus we always
		 * assume that the DSS-option will be set for the data-packet.
		 */
		if (skb && !mptcp_is_data_seq(skb)) {
			opts->data_ack = meta_tp->rcv_nxt;

			*size += MPTCP_SUB_LEN_ACK_ALIGN;
		} else {
			opts->data_ack = meta_tp->rcv_nxt;

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
		opts->addr4 = &mpcb->locaddr4[ind];
		if (skb)
			tp->mptcp->add_addr4 &= ~(1 << ind);
		*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN;
	} else if (unlikely(tp->mptcp->add_addr6) &&
		 MAX_TCP_OPTION_SPACE - *size >=
		 MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) {
		int ind = mptcp_find_free_index(~(tp->mptcp->add_addr6));
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->addr6 = &mpcb->locaddr6[ind];
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

	if (skb)
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
			mdss->len = mptcp_sub_len_dss(mdss, tp->mpcb->dss_csum);

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

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		if (reinject)
			*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_write_pending &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = get_available_subflow(meta_sk, NULL);
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
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN | MPTCPHDR_SEQ;
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

	/* First - select a socket */

	/* Socket already selected? */
	mptcp_for_each_sk(mpcb, sk_it) {
		if (tcp_sk(sk_it)->send_mp_fclose) {
			sk = sk_it;
			goto found;
		}
	}

	sk = mptcp_select_ack_sock(meta_sk, 0);
	/* May happen if no subflow is in an appropriate state */
	if (!sk)
		return;
	tcp_sk(sk)->send_mp_fclose = 1;

	/** Reset all other subflows */

found:
	/* tcp_done must be handled with bh disabled */
	if (!in_serving_softirq())
		local_bh_disable();
	mptcp_for_each_sk_safe(mpcb, sk_it, tmpsk) {
		if (tcp_sk(sk_it)->send_mp_fclose)
			continue;

		sk_it->sk_err = ECONNRESET;
		tcp_send_active_reset(sk_it, GFP_ATOMIC);
		mptcp_sub_force_close(sk_it);
	}
	if (!in_serving_softirq())
		local_bh_enable();

	tcp_send_ack(sk);

	if (!meta_tp->send_mp_fclose) {
		struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);

		meta_icsk->icsk_rto = min(inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
		inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS,
					  meta_icsk->icsk_rto, TCP_RTO_MAX);
	}

	meta_tp->send_mp_fclose = 1;
}

void mptcp_send_reset(struct sock *sk, struct sk_buff *skb)
{
	skb_dst_set(skb, sk_dst_get(sk));
	if (sk->sk_family == AF_INET)
		tcp_v4_send_reset(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6)
		tcp_v6_send_reset(sk, skb);
#endif

	mptcp_sub_force_close(sk);
}

void mptcp_ack_retransmit_timer(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		goto out; /* Routing failure or similar */

	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (skb == NULL) {
		sk_reset_timer(sk, &tp->mptcp->mptcp_ack_timer,
			       jiffies + icsk->icsk_rto);
		return;
	}

	/* Reserve space for headers and prepare control bits */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tp->snd_una, TCPHDR_ACK);

	tp->mptcp->include_mpc = 1;
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	if (tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff. */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		sk_reset_timer(sk, &tp->mptcp->mptcp_ack_timer,
			       jiffies + icsk->icsk_rto);
		return;
	}

out:
	icsk->icsk_retransmits++;
	if (icsk->icsk_retransmits == sysctl_tcp_retries1 + 1) {
		sk_stop_timer(sk, &tp->mptcp->mptcp_ack_timer);
		tcp_send_active_reset(sk, GFP_ATOMIC);
		mptcp_sub_force_close(sk);
		return;
	}

	icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	sk_reset_timer(sk, &tp->mptcp->mptcp_ack_timer,
		       jiffies + icsk->icsk_rto);
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
static int mptcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk), *meta_tp = tcp_sk(meta_sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int cur_mss;
	int err;

	/* Inconslusive MTU probe */
	if (icsk->icsk_mtup.probe_size) {
		icsk->icsk_mtup.probe_size = 0;
	}

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 *
	 * This is a meta-retransmission thus we check on the meta-socket.
	 */
	if (atomic_read(&meta_sk->sk_wmem_alloc) >
	    min(meta_sk->sk_wmem_queued + (meta_sk->sk_wmem_queued >> 2), meta_sk->sk_sndbuf)) {
		return -EAGAIN;
	}

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			BUG();
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	if (skb->len > cur_mss) {
		if (mptcp_fragment(sk, skb, cur_mss, cur_mss, 0))
			return -ENOMEM; /* We'll try again later. */
	} else {
		int oldpcount = tcp_skb_pcount(skb);

		if (unlikely(oldpcount > 1)) {
			tcp_init_tso_segs(sk, skb, cur_mss);
			tcp_adjust_pcount(sk, skb, oldpcount - tcp_skb_pcount(skb));
		}
	}

	/* Diff to tcp_retransmit_skb */

	/* Some Solaris stacks overoptimize and ignore the FIN on a
	 * retransmit when old data is attached.  So strip it off
	 * since it is cheap to do so and saves bytes on the network.
	 */
	if (skb->len > 0 &&
	    (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tp->snd_una == (TCP_SKB_CB(skb)->end_seq - 1)) {
		if (!pskb_trim(skb, 0)) {
			/* Reuse, even though it does some unnecessary work */
			tcp_init_nondata_skb(skb, TCP_SKB_CB(skb)->end_seq - 1,
					     TCP_SKB_CB(skb)->tcp_flags);
			skb->ip_summed = CHECKSUM_NONE;
		}
	}


	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	if (err == 0) {
		/* Update global TCP statistics. */
		TCP_INC_STATS(sock_net(meta_sk), TCP_MIB_RETRANSSEGS);

		/* Diff to tcp_retransmit_skb */

		/* Save stamp of the first retransmit. */
		if (!meta_tp->retrans_stamp)
			meta_tp->retrans_stamp = TCP_SKB_CB(skb)->when;
	}
	return err;
}

/* Similar to tcp_retransmit_timer
 *
 * The diff is that we have to handle retransmissions of the FAST_CLOSE-message
 * and that we don't have an srtt estimation at the meta-level.
 */
void mptcp_retransmit_timer(struct sock *meta_sk)
{
	struct sock *sk;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);
	struct sk_buff *subskb;
	int err;

	if (unlikely(meta_tp->send_mp_fclose))
		goto send_mp_fclose;

	/* In fallback, retransmission is handled at the subflow-level */
	if (!meta_tp->packets_out ||
	    mpcb->infinite_mapping || mpcb->send_infinite_mapping)
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
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &meta_inet->inet_daddr, ntohs(meta_inet->inet_dport),
			       meta_inet->inet_num, meta_tp->snd_una, meta_tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (meta_sk->sk_family == AF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(meta_sk);
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &np->daddr, ntohs(meta_inet->inet_dport),
			       meta_inet->inet_num, meta_tp->snd_una, meta_tp->snd_nxt);
		}
#endif
		if (tcp_time_stamp - meta_tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(meta_sk);
			return;
		}

		sk = get_available_subflow(meta_sk, tcp_write_queue_head(meta_sk));
		if (!sk)
			goto out_reset_timer;

		subskb = mptcp_skb_entail(sk, tcp_write_queue_head(meta_sk), -1);
		if (!subskb)
			goto out_reset_timer;
		err = mptcp_retransmit_skb(sk, subskb);
		if (!err)
			mptcp_sub_event_new_data_sent(sk, subskb);
		else
			mptcp_transmit_skb_failed(sk, tcp_write_queue_head(meta_sk), subskb, 0);
		__sk_dst_reset(meta_sk);
		goto out_reset_timer;
	}

	if (tcp_write_timeout(meta_sk))
		return;

	if (meta_icsk->icsk_retransmits == 0)
		NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_TCPTIMEOUTS);

	sk = get_available_subflow(meta_sk, tcp_write_queue_head(meta_sk));
	if (!sk)
		goto out_reset_timer;

	subskb = mptcp_skb_entail(sk, tcp_write_queue_head(meta_sk), -1);
	if (!subskb)
		goto out_reset_timer;
	err = mptcp_retransmit_skb(sk, subskb);
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
	if (!err)
		mptcp_sub_event_new_data_sent(sk, subskb);
	else
		mptcp_transmit_skb_failed(sk, tcp_write_queue_head(meta_sk), subskb, 0);

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
	if (retransmits_timed_out(meta_sk, sysctl_tcp_retries1 + 1, 0, 0))
		__sk_dst_reset(meta_sk);

	return;

send_mp_fclose:
	mptcp_send_active_reset(meta_sk, GFP_ATOMIC);

	goto out_reset_timer;
}

/* Modify values to an mptcp-level for the initial window of new subflows */
void mptcp_select_initial_window(int *__space, __u32 *window_clamp,
			         const struct sock *sk)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);

	/* If the user has set a limit - take this one. Else we take the
	 * maximum. Per-destination metrics don't make sense as the window
	 * is at the meta-level.
	 */
	if (meta_sk->sk_userlocks & SOCK_RCVBUF_LOCK)
		*window_clamp = tcp_full_space(meta_sk);
	else
		*window_clamp = (65535 << 14);

	*__space = tcp_space(meta_sk);
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
		if (!mss || this_mss < mss)
			mss = this_mss;
	}

	/* If no subflow is available, we take a default-mss from the
	 * meta-socket.
	 */
	return !mss ? tcp_current_mss(meta_sk) : mss;
}

int mptcp_select_size(const struct sock *meta_sk)
{
	int mss = 0; /* We look for the smallest MSS */
	struct sock *sk;

	mptcp_for_each_sk(tcp_sk(meta_sk)->mpcb, sk) {
		int this_mss;

		if (!mptcp_sk_can_send(sk))
			continue;

		this_mss = tcp_sk(sk)->mss_cache;
		if (!mss || this_mss < mss)
			mss = this_mss;
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
