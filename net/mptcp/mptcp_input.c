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

#include <asm/unaligned.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>

#include <linux/kconfig.h>

static inline void mptcp_become_fully_estab(struct tcp_sock *tp)
{
	tp->mptcp->fully_established = 1;

	if (is_master_tp(tp))
		mptcp_send_updatenotif(tp->mpcb);
}

/**
 * Cleans the meta-socket retransmission queue and the reinject-queue.
 * @sk must be the metasocket.
 */
static void mptcp_clean_rtx_queue(struct sock *meta_sk)
{
	struct sk_buff *skb, *tmp;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = (struct mptcp_cb *)meta_tp;
	int acked = 0;

	while ((skb = tcp_write_queue_head(meta_sk)) &&
	       skb != tcp_send_head(meta_sk)) {
		if (before(meta_tp->snd_una, TCP_SKB_CB(skb)->end_seq))
			break;

		tcp_unlink_write_queue(skb, meta_sk);

		if (mptcp_is_data_fin(skb)) {
			struct sock *sk_it;

			/* DATA_FIN has been acknowledged - now we can close
			 * the subflows */
			mptcp_for_each_sk(meta_tp->mpcb, sk_it) {
				unsigned long delay = 0;

				/* If we are the passive closer, don't trigger
				 * subflow-fin until the subflow has been finned
				 * by the peer - thus we add a delay. */
				if (mpcb->passive_close && sk_it->sk_state == TCP_ESTABLISHED)
					delay = inet_csk(sk_it)->icsk_rto << 3;

				mptcp_sub_close(sk_it, delay);
			}
		}

		meta_tp->packets_out -= tcp_skb_pcount(skb);
		sk_wmem_free_skb(meta_sk, skb);

		acked = 1;
	}
	/* Remove acknowledged data from the reinject queue */
	skb_queue_walk_safe(&mpcb->reinject_queue, skb, tmp) {
		if (before(meta_tp->snd_una, TCP_SKB_CB(skb)->end_seq))
			break;

		skb_unlink(skb, &mpcb->reinject_queue);
		kfree_skb(skb);
	}

	if (acked)
		mptcp_reset_xmit_timer(meta_sk);
}

/* Inspired by tcp_rcv_state_process */
static void mptcp_rcv_state_process(struct sock *meta_sk, struct sock *sk,
				    const struct sk_buff *skb)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct tcphdr *th = tcp_hdr(skb);

	/* State-machine handling if FIN has been enqueued and he has
	 * been acked (snd_una == write_seq) - it's important that this
	 * here is after sk_wmem_free_skb because otherwise
	 * sk_forward_alloc is wrong upon inet_csk_destroy_sock()
	 */
	switch (meta_sk->sk_state) {
	case TCP_FIN_WAIT1:
		if (meta_tp->snd_una == meta_tp->write_seq) {
			tcp_set_state(meta_sk, TCP_FIN_WAIT2);
			meta_sk->sk_shutdown |= SEND_SHUTDOWN;
			dst_confirm(__sk_dst_get(meta_sk));

			if (!sock_flag(meta_sk, SOCK_DEAD)) {
				/* Wake up lingering close() */
				meta_sk->sk_state_change(meta_sk);
			}
		}
		break;
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		if (meta_tp->snd_una == meta_tp->write_seq)
			tcp_done(meta_sk);
		break;
	}

	/* step 7: process the segment text */
	switch (meta_sk->sk_state) {
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* RFC 793 says to queue data in these states,
		 * RFC 1122 says we MUST send a reset.
		 * BSD 4.4 also does reset.
		 */
		if (meta_sk->sk_shutdown & RCV_SHUTDOWN) {
			if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
			    after(TCP_SKB_CB(skb)->end_seq - th->fin, tcp_sk(sk)->rcv_nxt) &&
			    !mptcp_is_data_fin(skb)) {
				NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_TCPABORTONDATA);

				mptcp_send_active_reset(meta_sk, GFP_ATOMIC);
			}
		}
		break;
	}
}

/**
 * @return:
 *  i) 1: Everything's fine.
 *  ii) -1: A reset has been sent on the subflow - csum-failure
 *  iii) 0: csum-failure but no reset sent, because it's the last subflow.
 *	 Last packet should not be destroyed by the caller because it has
 *	 been done here.
 */
static int mptcp_verif_dss_csum(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *tmp, *last = NULL;
	__wsum csum_tcp = 0; /* cumulative checksum of pld + mptcp-header */
	int ans = 1, overflowed = 0, offset = 0, dss_csum_added = 0;
	int iter = 0;

	skb_queue_walk(&sk->sk_receive_queue, tmp) {
		unsigned int csum_len;

		/* tp->map_data_len may be 0 in case of a data-fin */
		if ((tp->mptcp->map_data_len &&
		     !after(tp->mptcp->map_subseq + tp->mptcp->map_data_len, ntohl(tcp_hdr(tmp)->seq))) ||
		    (!tp->mptcp->map_data_len && before(tp->mptcp->map_subseq, ntohl(tcp_hdr(tmp)->seq))))
			break;

		if (before(tp->mptcp->map_subseq + tp->mptcp->map_data_len, mptcp_skb_sub_end_seq(tmp)))
			/* Mapping ends in the middle of the packet -
			 * csum only these bytes */
			csum_len = tp->mptcp->map_subseq + tp->mptcp->map_data_len -
					ntohl(tcp_hdr(tmp)->seq);
		else
			csum_len = tmp->len;

		offset = 0;
		if (overflowed) {
			char first_word[4];
			first_word[0] = 0;
			first_word[1] = 0;
			first_word[2] = 0;
			first_word[3] = *(tmp->data);
			csum_tcp = csum_partial(first_word, 4, csum_tcp);
			offset = 1;
			csum_len--;
			overflowed = 0;
		}

		csum_tcp = skb_checksum(tmp, offset, csum_len, csum_tcp);

		/* Was it on an odd-length?  Then we have to merge the next byte
		 * correctly (see above)*/
		if (csum_len != (csum_len & (~1)))
			overflowed = 1;

		if (mptcp_is_data_seq(tmp) && !dss_csum_added) {
			__be32 data_seq = htonl((u32)(tp->mptcp->map_data_seq >> 32));
			csum_tcp = skb_checksum(tmp, skb_transport_offset(tmp) +
						TCP_SKB_CB(tmp)->dss_off,
						MPTCP_SUB_LEN_SEQ_CSUM,
						csum_tcp);
			csum_tcp = csum_partial(&data_seq, sizeof(data_seq), csum_tcp);

			dss_csum_added = 1; /* Just do it once */
		}
		last = tmp;
		iter++;
	}

	/* Now, checksum must be 0 */
	if (unlikely(csum_fold(csum_tcp))) {
		mptcp_debug("%s csum is wrong: %#x data_seq %u "
			    "dss_csum_added %d overflowed %d iterations %d\n",
			    __func__, csum_fold(csum_tcp),
			    TCP_SKB_CB(last)->seq, dss_csum_added,
			    overflowed, iter);

		tp->mptcp->csum_error = 1;
		/* map_data_seq is the data-seq number of the
		 * mapping we are currently checking
		 */
		tp->mpcb->csum_cutoff_seq = tp->mptcp->map_data_seq;

		if (tp->mpcb->cnt_established > 1) {
			mptcp_send_reset(sk, last);
			ans = -1;
		} else {
			tp->mpcb->send_mp_fail = 1;
			tp->copied_seq = mptcp_skb_sub_end_seq(last);
			/* Need to purge the rcv-queue as it's no more valid */
			__skb_queue_purge(&sk->sk_receive_queue);

			last = NULL; /* prevent skb_dst_drop later in here */
			ans = 0;
		}
	}

	/* We would have needed the rtable entry for sending the reset */
	if (last)
		skb_dst_drop(last);

	return ans;
}

static inline void mptcp_prepare_skb(struct sk_buff *skb, struct sk_buff *next,
				     struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	/* Adapt data-seq's to the packet itself. We kinda transform the
	 * dss-mapping to a per-packet granularity. This is necessary to
	 * correctly handle overlapping mappings coming from different
	 * subflows. Otherwise it would be a complete mess.
	 */
	tcb->seq = ((u32)tp->mptcp->map_data_seq) + ntohl(tcp_hdr(skb)->seq) - tp->mptcp->map_subseq;
	tcb->mp_data_len = skb->len;
	tcb->sub_seq = tcb->seq;
	tcb->end_seq = tcb->seq + tcb->mp_data_len;

	/* If cur is the last one in the rcv-queue (or the last one for this
	 * mapping), and data_fin is enqueued, the end_data_seq is +1 */
	if (skb_queue_is_last(&sk->sk_receive_queue, skb) ||
	    after(mptcp_skb_sub_end_seq(next), tp->mptcp->map_subseq + tp->mptcp->map_data_len))
		tcb->end_seq += tp->mptcp->map_data_fin;
}

/**
 * @return: 1 if the segment has been eaten and can be suppressed,
 *          otherwise 0.
 */
static inline int mptcp_direct_copy(struct sk_buff *skb, struct tcp_sock *tp,
				    struct tcp_sock *meta_tp)
{
	int chunk = min_t(unsigned int, skb->len, meta_tp->ucopy.len);
	int eaten = 0;

	__set_current_state(TASK_RUNNING);

	local_bh_enable();
	if (!skb_copy_datagram_iovec(skb, 0, meta_tp->ucopy.iov, chunk)) {
		meta_tp->ucopy.len -= chunk;
		meta_tp->copied_seq += chunk;
		eaten = (chunk == skb->len && !mptcp_is_data_fin(skb));
	}
	local_bh_disable();
	return eaten;
}

static inline void mptcp_reset_mapping(struct tcp_sock *tp)
{
	tp->mptcp->map_data_len = 0;
	tp->mptcp->map_data_seq = 0;
	tp->mptcp->map_subseq = 0;
	tp->mptcp->map_data_fin = 0;
	tp->mptcp->mapping_present = 0;
}

/* The DSS-mapping received on the sk only covers the second half of the skb
 * (cut at seq). We trim the head from the skb.
 * Data will be freed upon kfree().
 *
 * Inspired by tcp_trim_head().
 */
static void mptcp_skb_trim_head(struct sk_buff *skb, struct sock *sk, u32 seq)
{
	int len = seq - ntohl(tcp_hdr(skb)->seq);
	u32 new_seq = ntohl(tcp_hdr(skb)->seq) + len;

	if (len < skb_headlen(skb))
		__skb_pull(skb, len);
	else
		__pskb_trim_head(skb, len - skb_headlen(skb));

	tcp_hdr(skb)->seq = htonl(new_seq);

	skb->truesize -= len;
	atomic_sub(len, &sk->sk_rmem_alloc);
	sk_mem_uncharge(sk, len);
}

/* The DSS-mapping received on the sk only covers the first half of the skb
 * (cut at seq). We create a second skb (@return), and queue it in the rcv-queue
 * as further packets may resolve the mapping of the second half of data.
 *
 * Inspired by tcp_fragment().
 */
static int mptcp_skb_split_tail(struct sk_buff *skb, struct sock *sk, u32 seq)
{
	struct sk_buff *buff;
	int nsize;
	int nlen, len;
	u8 flags;

	len = seq - ntohl(tcp_hdr(skb)->seq);
	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	/* Get a new skb... force flag on. */
	buff = alloc_skb(nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM;

	/* We absolutly need to call skb_set_owner_r before refreshing the
	 * truesize of buff, otherwise the moved data will account twice.
	 */
	skb_set_owner_r(buff, sk);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	tcp_hdr(buff)->seq = htonl(ntohl(tcp_hdr(skb)->seq) + len);

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	skb_split(skb, buff, len);

	/* buff has no TCP/IP-header - thus drop the reference */
	skb_header_release(buff);

	/* It is guaranteed that skb is the last packet in the rcv-queue.
	 * Thus, it is safe to enqueue buff just at the end.
	 */
	__skb_queue_tail(&sk->sk_receive_queue, buff);

	return 0;
}

/**
 * @return:
 *  i) -2: the caller should wakeup the application
 *  ii) 1: the segment can be destroyed by the caller
 *  iii) -1: A reset has been sent on the subflow
 *  iiii) 0: The segment has been enqueued.
 */
int mptcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = mpcb_from_tcpsock(tcp_sk(sk));
	struct sock *meta_sk = (struct sock *) mpcb;
	struct tcp_sock *tp = tcp_sk(sk), *meta_tp = tcp_sk(meta_sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	struct sk_buff *tmp, *tmp1;
	u32 old_copied = tp->copied_seq;
	u32 sub_end_seq = tcb->end_seq;
	u32 sub_seq = tcb->seq;
	int ans = 0;

	/* Already closed, or a pure subflow FIN ? */
	if (meta_sk->sk_state == TCP_CLOSE ||
	    (!skb->len && tcp_hdr(skb)->fin && !mptcp_is_data_fin(skb))) {
		/* We have to queue it, so that later handling of the socket
		 * is done correctly (e.g., inet_csk_destroy_sock from tcp_fin)
		 */
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		skb_set_owner_r(skb, sk);
		tp->copied_seq++;
		tp->rcv_nxt = sub_end_seq;
		return 0;
	}

	/* Record it, because we want to send our data_fin on the same path */
	if (mptcp_is_data_fin(skb)) {
		mpcb->dfin_path_index = tp->mptcp->path_index;
		mpcb->dfin_combined = tcp_hdr(skb)->fin;
	}

	/* If we are not yet fully established and do not know the mapping for
	 * this segment, this path has to fallback to infinite or be torn down.
	 */
	if (!tp->mptcp->fully_established && !mptcp_is_data_seq(skb) &&
	    !tp->mptcp->mapping_present) {
		int ret = mptcp_fallback_infinite(tp, skb);

		if (ret & MPTCP_FLAG_SEND_RESET) {
			mptcp_send_reset(sk, skb);
			__kfree_skb(skb);
			return -1;
		} else {
			mpcb->infinite_mapping = 1;
			tp->mptcp->fully_established = 1;
		}
	}

	/* Receiver-side becomes fully established when a whole rcv-window has
	 * been received without the need to fallback due to the previous
	 * condition. */
	if (!tp->mptcp->fully_established) {
		tp->mptcp->init_rcv_wnd -= skb->len;
		if (tp->mptcp->init_rcv_wnd < 0)
			mptcp_become_fully_estab(tp);
	}

	/* If we are in infinite-mapping-mode, the subflow is guaranteed to be
	 * in-order at the data-level. Thus data-seq-numbers can be inferred
	 * from what is expected at the data-level.
	 *
	 * draft v04, Section 3.5
	 */
	if (mpcb->infinite_mapping) {
		tcb->seq = meta_tp->rcv_nxt;
		tp->mptcp->map_data_seq = mptcp_get_rcv_nxt_64(mpcb);
		tp->mptcp->map_subseq = tcb->sub_seq = tcb->seq;
		tp->mptcp->map_data_len = tcb->mp_data_len = skb->len;
		tp->mptcp->mapping_present = 1;
		tcb->end_seq = tcb->seq + tcb->mp_data_len;
	} else if (mptcp_is_data_seq(skb)) {
		__u32 *ptr = mptcp_skb_set_data_seq(skb, &tcb->seq);
		ptr++;
		tcb->sub_seq = get_unaligned_be32(ptr) + tp->rx_opt.rcv_isn;
		ptr++;
		tcb->mp_data_len = get_unaligned_be16(ptr);
		tcb->end_seq = tcb->seq + tcb->mp_data_len;

		/* If it's an empty skb with DATA_FIN, sub_seq must get fixed.
		 * The draft sets it to 0, but we really would like to have the
		 * real value, to have an easy handling afterwards here in this
		 * function.
		 */
		if (mptcp_is_data_fin(skb) && skb->len == 0)
			tcb->sub_seq = sub_seq;
	}

	/* If there is a DSS-mapping, check if it is ok with the current
	 * expected mapping. If anything is wrong, reset the subflow
	 */
	if (mptcp_is_data_seq(skb) && !mpcb->infinite_mapping) {
		if (!(tcb->mp_data_len)) {
			mpcb->infinite_mapping = 1;
			tp->mptcp->fully_established = 1;
			/* We need to repeat mp_fail's until the sender felt
			 * back to infinite-mapping - here we stop repeating it.
			 */
			mpcb->send_mp_fail = 0;

			/* TODO kill all other subflows than this one */
			/* data_seq and so on are set correctly */

			/* At this point, the meta-ofo-queue has to be emptied,
			 * as the following data is guaranteed to be in-order at
			 * the data and subflow-level
			 */
			mptcp_purge_ofo_queue(meta_tp);
		}

		/* We are sending mp-fail's and thus are in fallback mode.
		 * Ignore packets which do not announce the fallback and still
		 * want to provide a mapping.
		 */
		if (mpcb->send_mp_fail) {
			tp->rcv_nxt = sub_end_seq;
			return 1;
		}

		/* FIN increased the mapping-length by 1 */
		if (mptcp_is_data_fin(skb))
			tcb->mp_data_len--;

		if (tp->mptcp->mapping_present &&
		    (tcb->seq != (u32)tp->mptcp->map_data_seq ||
		     tcb->sub_seq != tp->mptcp->map_subseq ||
		     tcb->mp_data_len != tp->mptcp->map_data_len)) {
			/* Mapping in packet is different from what we want */
			mptcp_debug("%s destroying subflow with pi %d from mpcb "
				    "with token %#x\n", __func__,
				    tp->mptcp->path_index, mpcb->mptcp_loc_token);
			mptcp_debug("%s missing rest of the already present "
				    "mapping: data_seq %llu, subseq %u, data_len "
				    "%u - new mapping: data_seq %u, subseq %u, "
				    "data_len %u\n", __func__, tp->mptcp->map_data_seq,
				    tp->mptcp->map_subseq, tp->mptcp->map_data_len,
				    tcb->seq, tcb->ack_seq, tcb->mp_data_len);
			mptcp_send_reset(sk, skb);
			__kfree_skb(skb);
			return -1;
		}

		if (!tp->mptcp->mapping_present) {
			/* Subflow-sequences of packet must be
			 * (at least partially) be part of the DSS-mapping's
			 * subflow-sequence-space.
			 *
			 * Basically the mapping is not valid, if either of the
			 * following conditions is true:
			 *
			 * 1. It's not a data_fin and
			 *    MPTCP-sub_seq >= TCP-end_seq
			 *
			 * 2. It's a data_fin and TCP-end_seq > TCP-seq and
			 *    MPTCP-sub_seq >= TCP-end_seq
			 *
			 * The previous two can be merged into:
			 *    TCP-end_seq > TCP-seq and MPTCP-sub_seq >= TCP-end_seq
			 *    Because if it's not a data-fin, TCP-end_seq > TCP-seq
			 *
			 * 3. It's a data_fin and skb->len == 0 and
			 *    MPTCP-sub_seq > TCP-end_seq
			 *
			 * 4. MPTCP-sub_seq + MPTCP-data_len < TCP-seq
			 *
			 * TODO - in case of data-fin, mptcp-data_len is + 1
			 */
			if ((!before(tcb->sub_seq, sub_end_seq) && after(sub_end_seq, sub_seq)) ||
			    (mptcp_is_data_fin(skb) && skb->len == 0 && after(tcb->sub_seq, sub_end_seq)) ||
			    before(tcb->sub_seq + tcb->mp_data_len, sub_seq)) {
				/* Subflow-sequences of packet is different from
				 * what is in the packet's dss-mapping.
				 * The peer is misbehaving - reset
				 */
				mptcp_debug("%s destroying subflow with pi %d "
					    "from mpcb with token %#x\n",
					    __func__, tp->mptcp->path_index,
					    mpcb->mptcp_loc_token);
				mptcp_debug("%s seq %u end_seq %u, sub_seq %u "
					    "data_len %u dseq %u\n", __func__,
					    sub_seq, sub_end_seq,
					    tcb->sub_seq, tcb->mp_data_len,
					    tcb->seq);
				mptcp_send_reset(sk, skb);
				return 1;
			}

			/* Does the DSS had 64-bit seqnum's ? */
			if (!(tcb->mptcp_flags & MPTCPHDR_SEQ64_SET)) {
				/* Wrapped around? */
				if (unlikely(after(tcb->seq, meta_tp->rcv_nxt) &&
					     tcb->seq < meta_tp->rcv_nxt)) {
					tp->mptcp->map_data_seq = mptcp_get_data_seq_64(mpcb, !mpcb->rcv_hiseq_index, tcb->seq);
				} else {
					/* Else, access the default high-order bits */
					tp->mptcp->map_data_seq = mptcp_get_data_seq_64(mpcb, mpcb->rcv_hiseq_index, tcb->seq);
				}
			} else {
				tp->mptcp->map_data_seq = mptcp_get_data_seq_64(mpcb, (tcb->mptcp_flags & MPTCPHDR_SEQ64_INDEX) ? 1 : 0, tcb->seq);

				if (unlikely(tcb->mptcp_flags & MPTCPHDR_SEQ64_OFO)) {
					/* We make sure that the data_seq is invalid.
					 * It will be dropped later.
					 */
					tp->mptcp->map_data_seq += 0xFFFFFFFF;
					tp->mptcp->map_data_seq += 0xFFFFFFFF;
				}
			}

			tp->mptcp->map_data_len = tcb->mp_data_len;
			tp->mptcp->map_subseq = tcb->sub_seq;
			tp->mptcp->map_data_fin = mptcp_is_data_fin(skb) ? 1 : 0;
			tp->mptcp->mapping_present = 1;
		}
	}

	/* The skb goes into the sub-rcv queue in all cases.
	 * This allows more generic skb management in the next lines although
	 * it may be removed in few lines (direct copy to the app).
	 */
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	skb_set_owner_r(skb, sk);

	/* If the mapping is known, we have to split coalesced segments */
	if (tp->mptcp->mapping_present) {
		int sub_end_seq1;
		/* either, the new skb gave us the mapping and the first segment
		 * in the sub-rcv-queue has to be split, or the new skb (tail)
		 * has to be split at the end.
		 */
		tmp = skb_peek(&sk->sk_receive_queue);
		if (before(ntohl(tcp_hdr(tmp)->seq), tp->mptcp->map_subseq) &&
		    after(mptcp_skb_sub_end_seq(tmp), tp->mptcp->map_subseq)) {
			mptcp_skb_trim_head(tmp, sk, tp->mptcp->map_subseq);
		}

		sub_end_seq1 = sub_end_seq - tcp_hdr(skb)->fin;

		if (after(sub_end_seq1, tp->mptcp->map_subseq + tp->mptcp->map_data_len)) {
			int ret;
			ret = mptcp_skb_split_tail(skb, sk,
					tp->mptcp->map_subseq + tp->mptcp->map_data_len);
			if (ret) { /* Allocation failed */

				/* TODO : maybe handle this here better.
				 * We now just force retransmission, as rcv_nxt
				 * is only advanced after this here.
				 *
				 * How could we do it more cleanly?
				 */
				__skb_unlink(skb, &sk->sk_receive_queue);
				__kfree_skb(skb);
				return -1;
			}
		}
	}

	tp->rcv_nxt = sub_end_seq;

	/* Now, remove old sk_buff's from the receive-queue.
	 * This may happen if the mapping has been lost for these segments and
	 * the next mapping has already been received.
	 */
	if (tp->mptcp->mapping_present &&
	    before(ntohl(tcp_hdr(skb_peek(&sk->sk_receive_queue))->seq), tp->mptcp->map_subseq)) {
		mptcp_debug("%s remove packets not covered by mapping: "
			    "data_len %u, tp->copied_seq %u, "
			    "tp->map_subseq %u\n", __func__,
			    tp->mptcp->map_data_len, tp->copied_seq,
			    tp->mptcp->map_subseq);
		skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
			if (!before(ntohl(tcp_hdr(tmp1)->seq), tp->mptcp->map_subseq)) {
				mptcp_debug("%s Not removing packet seq %u\n",
					    __func__, ntohl(tcp_hdr(tmp1)->seq));
				break;
			}
			mptcp_debug("%s remove packet seq %u\n",
				    __func__, ntohl(tcp_hdr(tmp1)->seq));
			__skb_unlink(tmp1, &sk->sk_receive_queue);

			tp->copied_seq = mptcp_skb_sub_end_seq(tmp1);

			/* Impossible that we could free skb here, because his
			 * mapping is known to be valid from previous checks
			 */
			__kfree_skb(tmp1);
		}
	}

	/* Have we received the full mapping ? Then push further */
	if (tp->mptcp->mapping_present &&
	    !before(tp->rcv_nxt, tp->mptcp->map_subseq + tp->mptcp->map_data_len)) {
		u64 rcv_nxt64 = mptcp_get_rcv_nxt_64(mpcb);

		/* Is this an overlapping mapping? rcv_nxt >= end_data_seq
		 * OR
		 * This mapping is out of window */
		if (!before64(rcv_nxt64,
			      tp->mptcp->map_data_seq + tp->mptcp->map_data_len + tp->mptcp->map_data_fin) ||
		    !mptcp_sequence(meta_tp, tp->mptcp->map_data_seq,
				    tp->mptcp->map_data_seq + tp->mptcp->map_data_len + tp->mptcp->map_data_fin)) {
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				/* seq >= end_sub_mapping if data_len OR
				 * seq > end_sub_mapping if not data_len
				 * (data_fin without data)
				 */
				if ((tp->mptcp->map_data_len && !before(ntohl(tcp_hdr(tmp1)->seq),
						tp->mptcp->map_subseq + tp->mptcp->map_data_len)) ||
				    (!tp->mptcp->map_data_len && after(ntohl(tcp_hdr(tmp1)->seq),
						tp->mptcp->map_subseq + tp->mptcp->map_data_len)))
					break;
				__skb_unlink(tmp1, &sk->sk_receive_queue);

				tp->copied_seq = mptcp_skb_sub_end_seq(tmp1);

				if (mptcp_is_data_fin(tmp1))
					mptcp_fin(mpcb);

				/* the callers of mptcp_queue_skb still
				 * need the skb
				 */
				if (skb != tmp1)
					__kfree_skb(tmp1);
			}

			mptcp_reset_mapping(tp);

			/* We want tcp_data(/ofo)_queue to free skb. */
			return 1;
		}

		/* Verify the checksum */
		if (mpcb->rx_opt.dss_csum && !mpcb->infinite_mapping) {
			int ret = mptcp_verif_dss_csum(sk);

			if (ret <= 0) {
				mptcp_reset_mapping(tp);
				ans = ret;
				goto exit;
			}
		}

		if (before64(rcv_nxt64, tp->mptcp->map_data_seq)) {
			/* Seg's have to go to the meta-ofo-queue */
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				if (after(mptcp_skb_sub_end_seq(tmp1),
					  tp->mptcp->map_subseq + tp->mptcp->map_data_len + tp->mptcp->map_data_fin))
					break;

				mptcp_prepare_skb(tmp1, tmp, sk);

				__skb_unlink(tmp1, &sk->sk_receive_queue);
				tp->copied_seq = mptcp_skb_sub_end_seq(tmp1);
				skb_set_owner_r(tmp1, meta_sk);

				if (mptcp_add_meta_ofo_queue(meta_sk, tmp1, sk)) {
					if (tmp1 == skb)
						ans = 1;
					else
						__kfree_skb(tmp1);
				}
			}
		} else {
			int eaten = 0;
			/* Ready for the meta-rcv-queue */
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				if (after(mptcp_skb_sub_end_seq(tmp1),
					  tp->mptcp->map_subseq + tp->mptcp->map_data_len + tp->mptcp->map_data_fin)) {
					break;
				}

				mptcp_prepare_skb(tmp1, tmp, sk);

				/* Is direct copy possible ? */
				if (TCP_SKB_CB(tmp1)->seq ==
				    meta_tp->rcv_nxt &&
				    meta_tp->ucopy.task == current &&
				    meta_tp->copied_seq == meta_tp->rcv_nxt &&
				    meta_tp->ucopy.len &&
				    sock_owned_by_user(meta_sk)) {
					eaten = mptcp_direct_copy(tmp1, tp, meta_tp);
				}
				mptcp_check_rcvseq_wrap(meta_tp,
							TCP_SKB_CB(tmp1)->end_seq -
							meta_tp->rcv_nxt);
				meta_tp->rcv_nxt = TCP_SKB_CB(tmp1)->end_seq;

				tp->copied_seq = mptcp_skb_sub_end_seq(tmp1);

				if (mptcp_is_data_fin(tmp1)) {
					/* If mptcp_fin tcp_done'd the meta_sk,
					 * he flushed the rcv-queue. However,
					 * tcp_data_queue() may still need the
					 * skb.
					 * Thus, we skip the rest of
					 * mptcp_queue_skb and exit.
					 */
					if (mptcp_fin(mpcb)) {
						ans = 0;
						goto rcvd_fin;
					}
				}

				/* It is important that we unlink after mptcp_fin.
				 * Otherwise, if mptcp_fin returns 1, and tcp_fin
				 * will later also call tcp_done, we have a problem,
				 * because sk_forward_alloc will be wrong.
				 */
				__skb_unlink(tmp1, &sk->sk_receive_queue);

				if (!eaten)
					__skb_queue_tail(
						&meta_sk->sk_receive_queue,
						tmp1);

				/* Check if this fills a gap in the ofo queue */
				if (!skb_queue_empty(
					    &meta_tp->out_of_order_queue))
					mptcp_ofo_queue(mpcb);

				if (!eaten)
					skb_set_owner_r(tmp1, meta_sk);

				if (eaten) {
					if (tmp1 != skb)
						__kfree_skb(tmp1);
					else
						ans = 1;
				} else {
					ans = -2;
				}
			}
		}

rcvd_fin:
		inet_csk(meta_sk)->icsk_ack.lrcvtime = tcp_time_stamp;
		tp->mptcp->last_data_seq = tp->mptcp->map_data_seq;
		mptcp_reset_mapping(tp);
	}

exit:
	if (old_copied != tp->copied_seq)
		tcp_rcv_space_adjust(sk);

	return ans;
}


/**
 * Equivalent of tcp_fin() for MPTCP
 * Can be called only when the FIN is validly part
 * of the data seqnum space. Not before when we get holes.
 */
int mptcp_fin(struct mptcp_cb *mpcb)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb), *sk = NULL, *sk_it;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	int ans = 0;

	mptcp_for_each_sk(mpcb, sk_it) {
		if (tcp_sk(sk_it)->mptcp->path_index == mpcb->dfin_path_index) {
			sk = sk_it;
			break;
		}
	}

	if (!sk)
		sk = mptcp_select_ack_sock(mpcb, 0);

	inet_csk_schedule_ack(sk);

	meta_sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(meta_sk, SOCK_DONE);

	switch (meta_sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		/* Move to CLOSE_WAIT */
		tcp_set_state(meta_sk, TCP_CLOSE_WAIT);
		inet_csk(sk)->icsk_ack.pingpong = 1;
		break;

	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
		/* Received a retransmission of the FIN, do
		 * nothing.
		 */
		break;
	case TCP_LAST_ACK:
		/* RFC793: Remain in the LAST-ACK state. */
		break;

	case TCP_FIN_WAIT1:
		/* This case occurs when a simultaneous close
		 * happens, we must ack the received FIN and
		 * enter the CLOSING state.
		 */
		tcp_send_ack(sk);
		tcp_set_state(meta_sk, TCP_CLOSING);
		break;
	case TCP_FIN_WAIT2:
		/* Received a FIN -- send ACK and enter TIME_WAIT. */
		tcp_send_ack(sk);
		ans = sock_flag(sk, SOCK_DEAD);
		tcp_time_wait(meta_sk, TCP_TIME_WAIT, 0);
		break;
	default:
		/* Only TCP_LISTEN and TCP_CLOSE are left, in these
		 * cases we should never reach this piece of code.
		 */
		printk(KERN_ERR "%s: Impossible, meta_sk->sk_state=%d\n",
		       __func__, meta_sk->sk_state);
		break;
	}

	/* It _is_ possible, that we have something out-of-order _after_ FIN.
	 * Probably, we should reset in this case. For now drop them.
	 */
	mptcp_purge_ofo_queue(meta_tp);
	sk_mem_reclaim(meta_sk);

	if (!sock_flag(meta_sk, SOCK_DEAD)) {
		meta_sk->sk_state_change(meta_sk);

		/* Do not send POLL_HUP for half duplex close. */
		if (meta_sk->sk_shutdown == SHUTDOWN_MASK ||
		    meta_sk->sk_state == TCP_CLOSE)
			sk_wake_async(meta_sk, SOCK_WAKE_WAITD, POLL_HUP);
		else
			sk_wake_async(meta_sk, SOCK_WAKE_WAITD, POLL_IN);
	}

	return ans;
}

/* Handle the DATA_ACK */
int mptcp_data_ack(struct sock *sk, const struct sk_buff *skb)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct tcp_sock *meta_tp = tcp_sk(meta_sk), *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	int flag = 0;
	u32 nwin, data_ack, data_seq;
	__u32 *ptr;

	if (!tp->mpc)
		return 0;

	/* Something got acked - subflow is operational again */
	tp->pf = 0;

	if (!(tcb->mptcp_flags & MPTCPHDR_ACK))
		return 0;

	ptr = (__u32 *)(skb_transport_header(skb) + tcb->dss_off);
	ptr--;

	if (tcb->mptcp_flags & MPTCPHDR_ACK64_SET) {
		/* 64-bit data_ack - thus we have to go one step higher */
		ptr--;

		data_ack = (u32) get_unaligned_be64(ptr);
	} else {
		data_ack = get_unaligned_be32(ptr);
	}

	if (unlikely(!tp->mptcp->fully_established) &&
	    (data_ack != meta_tp->mptcp->snt_isn ||
	    tp->mptcp->snt_isn + 1 != tp->snd_una))
		/* As soon as data has been data-acked,
		 * or a subflow-data-ack (not acking syn - thus snt_isn + 1)
		 * includes a data-ack, we are fully established
		 */
		mptcp_become_fully_estab(tp);

	/* Get the data_seq */
	if (mptcp_is_data_seq(skb)) {
		mptcp_skb_set_data_seq(skb, &data_seq);
	} else {
		data_seq = meta_tp->snd_wl1;
	}

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	if (before(data_ack, meta_tp->snd_una))
		return 0;

	/* If the ack includes data we haven't sent yet, discard
	 * this segment (RFC793 Section 3.9).
	 */
	if (after(data_ack, meta_tp->snd_nxt))
		return 0;

	/*** Now, update the window  - inspired by tcp_ack_update_window ***/
	nwin = ntohs(tcp_hdr(skb)->window);

	if (likely(!tcp_hdr(skb)->syn))
		nwin <<= tp->rx_opt.snd_wscale;

	if (tcp_may_update_window(meta_tp, data_ack, data_seq, nwin)) {
		flag |= FLAG_WIN_UPDATE;
		tcp_update_wl(meta_tp, data_seq);
		tcp_update_wl(tp, tcb->seq);

		/* Draft v09, Section 3.3.5:
		 * [...] It should only update its local receive window values
		 * when the largest sequence number allowed (i.e.  DATA_ACK +
		 * receive window) increases. [...]
		 */
		if (meta_tp->snd_wnd != nwin &&
		    !before(data_ack + nwin, tcp_wnd_end(meta_tp))) {
			meta_tp->snd_wnd = nwin;
			tp->snd_wnd = nwin;

			/* Diff to tcp_ack_update_window - fast_path */

			if (nwin > meta_tp->max_window) {
				meta_tp->max_window = nwin;
				tp->max_window = nwin;

				/* Diff to tcp_ack_update_window - mss */
			}
		}
	}
	/*** Done, update the window ***/

	if (after(data_ack, meta_tp->snd_una)) {
		meta_tp->snd_una = data_ack;

		mptcp_clean_rtx_queue(meta_sk);
	}
	if (meta_sk->sk_state != TCP_ESTABLISHED)
		mptcp_rcv_state_process(meta_sk, sk, skb);

	meta_tp->rcv_tstamp = tcp_time_stamp;
	inet_csk(meta_sk)->icsk_probes_out = 0;

	return flag;
}

void mptcp_clean_rtx_infinite(struct sk_buff *skb, struct sock *sk)
{
	struct mptcp_cb *mpcb;
	struct sock *meta_sk;

	if (!tcp_sk(sk)->mpc)
		return;

	mpcb = tcp_sk(sk)->mpcb;
	meta_sk = mpcb_meta_sk(mpcb);

	if (!mpcb->infinite_mapping)
		return;

	/* skb->data is pointing to the head of the MPTCP-option. We still assume
	 * 32-bit data-acks.
	 *
	 * 20 is MPTCP_SUB_LEN_DSS_ALIGN + MPTCP_SUB_LEN_ACK_ALIGN + MPTCP_SUB_LEN_SEQ_ALIGN
	 */
	tcp_sk(meta_sk)->snd_una = ntohl(*(skb->data + 8)) + skb->len - 20 +
				   mptcp_is_data_fin(skb) ? 1 : 0;
	mptcp_clean_rtx_queue(meta_sk);
}

/**** static functions used by mptcp_parse_options */

static inline u8 mptcp_get_64_bit(u64 data_seq, struct multipath_options *mopt)
{
	u8 ret = 0;
	u64 data_seq_high = (u32)(data_seq >> 32);

	if (!mopt->mpcb)
		return 0;

	ret |= MPTCPHDR_SEQ64_SET;

	if (mopt->mpcb->rcv_high_order[0] == data_seq_high)
		return ret;
	else if (mopt->mpcb->rcv_high_order[1] == data_seq_high)
		return ret | MPTCPHDR_SEQ64_INDEX;
	else
		return ret | MPTCPHDR_SEQ64_OFO;
}

static inline int mptcp_rem_raddress(struct multipath_options *mopt, u8 rem_id)
{
	if (mptcp_v4_rem_raddress(mopt, rem_id) < 0) {
#if IS_ENABLED(CONFIG_IPV6)
		if (mptcp_v6_rem_raddress(mopt, rem_id) < 0)
			return -1;
#else
		return -1;
#endif /* CONFIG_IPV6 */
	}
	return 0;
}

static void mptcp_send_reset_rem_id(const struct mptcp_cb *mpcb, u8 rem_id)
{
	struct sock *sk_it, *sk_tmp;

	mptcp_for_each_sk_safe(mpcb, sk_it, sk_tmp) {
		if (tcp_sk(sk_it)->mptcp->rem_id == rem_id) {
			mptcp_reinject_data(sk_it, 0);
			sk_it->sk_err = ECONNRESET;
			tcp_send_active_reset(sk_it, GFP_ATOMIC);
			mptcp_sub_force_close(sk_it);
		}
	}
}

/* Same as tcp_parse_options but only parse MPTCP options. */
void mptcp_post_parse_options(struct tcp_sock *tp,
			      const struct sk_buff *skb)
{
	const struct tcphdr *th = tcp_hdr(skb);
	int length = (th->doff * 4) - sizeof(struct tcphdr);
	const unsigned char *ptr = (const unsigned char *)(th + 1);
	struct mptcp_cb *mpcb = mpcb_from_tcpsock(tp);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			if (opcode == TCPOPT_MPTCP)
				mptcp_parse_options(ptr - 2, opsize, &tp->rx_opt,
						    &mpcb->rx_opt, skb);
			ptr += opsize-2;
			length -= opsize;
		}
	}
}

void mptcp_parse_options(const uint8_t *ptr, int opsize,
			 struct tcp_options_received *opt_rx,
			 struct multipath_options *mopt,
			 const struct sk_buff *skb)
{
	struct mptcp_option *mp_opt = (struct mptcp_option *) ptr;

	/* If the socket is mp-capable we would have a mopt. */
	if (!mopt)
		return;

	switch (mp_opt->sub) {
	case MPTCP_SUB_CAPABLE:
	{
		struct mp_capable *mpcapable = (struct mp_capable *) ptr;

		if (opsize != MPTCP_SUB_LEN_CAPABLE_SYN &&
		    opsize != MPTCP_SUB_LEN_CAPABLE_ACK) {
			mptcp_debug("%s: mp_capable: bad option size %d\n",
					__func__, opsize);
			break;
		}

		if (!sysctl_mptcp_enabled)
			break;

		/* MPTCP-Draft v06:
		 * "If none of these flags are set, the MP_CAPABLE option MUST
		 * be treated as invalid and ignored (i.e. it must be treated
		 * as a regular TCP handshake)."
		 */
		if (!mpcapable->s)
			break;

		opt_rx->saw_mpc = 1;
		mopt->list_rcvd = 1;
		mopt->dss_csum = sysctl_mptcp_checksum || mpcapable->c;
		mopt->mptcp_opt_type = MPTCP_MP_CAPABLE_TYPE_SYN;

		if (opsize >= MPTCP_SUB_LEN_CAPABLE_SYN) {
			mopt->mptcp_rem_key = mpcapable->sender_key;
			mopt->mptcp_opt_type = MPTCP_MP_CAPABLE_TYPE_SYN;
		}

		if (opsize == MPTCP_SUB_LEN_CAPABLE_ACK) {
			/* This only necessary for SYN-cookies */
			mopt->mptcp_opt_type = MPTCP_MP_CAPABLE_TYPE_ACK;
		}

		break;
	}
	case MPTCP_SUB_JOIN:
	{
		struct mp_join *mpjoin = (struct mp_join *) ptr;

		if (opsize != MPTCP_SUB_LEN_JOIN_SYN &&
		    opsize != MPTCP_SUB_LEN_JOIN_SYNACK &&
		    opsize != MPTCP_SUB_LEN_JOIN_ACK) {
			mptcp_debug("%s: mp_join: bad option size %d\n",
					__func__, opsize);
			break;
		}

		switch (opsize) {
		case MPTCP_SUB_LEN_JOIN_SYN:
			mopt->mptcp_rem_token = mpjoin->u.syn.token;
			mopt->mptcp_recv_nonce = mpjoin->u.syn.nonce;
			mopt->mptcp_opt_type = MPTCP_MP_JOIN_TYPE_SYN;
			opt_rx->saw_mpc = 1;
			opt_rx->low_prio = mpjoin->b;
			break;
		case MPTCP_SUB_LEN_JOIN_SYNACK:
			mopt->mptcp_recv_tmac = mpjoin->u.synack.mac;
			mopt->mptcp_recv_nonce = mpjoin->u.synack.nonce;
			mopt->mptcp_opt_type = MPTCP_MP_JOIN_TYPE_SYNACK;
			opt_rx->low_prio = mpjoin->b;
			break;
		case MPTCP_SUB_LEN_JOIN_ACK:
			memcpy(mopt->mptcp_recv_mac, mpjoin->u.ack.mac, 20);
			mopt->mptcp_opt_type = MPTCP_MP_JOIN_TYPE_ACK;
			break;
		}
		opt_rx->rem_id = mpjoin->addr_id;
		break;
	}
	case MPTCP_SUB_DSS:
	{
		struct mp_dss *mdss = (struct mp_dss *) ptr;
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

		/* We check opsize for the csum and non-csum case. We do this,
		 * because the draft says that the csum SHOULD be ignored if
		 * it has not been negotiated in the MP_CAPABLE but still is
		 * present in the data.
		 *
		 * It will get ignored later in mptcp_queue_skb.
		 */
		if (opsize != mptcp_sub_len_dss(mdss, 0) &&
		    opsize != mptcp_sub_len_dss(mdss, 1)) {
			mptcp_debug("%s: mp_dss: bad option size %d\n",
					__func__, opsize);
			break;
		}

		ptr += 4;

		if (mdss->A) {
			tcb->mptcp_flags |= MPTCPHDR_ACK;

			if (mdss->a) {
				tcb->mptcp_flags |= MPTCPHDR_ACK64_SET;
				ptr += MPTCP_SUB_LEN_ACK_64;
			} else {
				ptr += MPTCP_SUB_LEN_ACK;
			}
		}

		tcb->dss_off = (ptr - skb_transport_header(skb));

		if (mdss->M) {
			if (mdss->m) {
				u64 data_seq64 = get_unaligned_be64(ptr);

				tcb->mptcp_flags |= mptcp_get_64_bit(data_seq64, mopt);

				ptr += MPTCP_SUB_LEN_SEQ_64;
			} else {
				ptr += MPTCP_SUB_LEN_SEQ;
			}

			tcb->mptcp_flags |= MPTCPHDR_SEQ;
		}

		if (mdss->F)
			tcb->mptcp_flags |= MPTCPHDR_FIN;

		break;
	}
	case MPTCP_SUB_ADD_ADDR:
	{
		struct mp_add_addr *mpadd = (struct mp_add_addr *) ptr;

#if IS_ENABLED(CONFIG_IPV6)
		if ((mpadd->ipver == 4 && opsize != MPTCP_SUB_LEN_ADD_ADDR4 &&
		     opsize != MPTCP_SUB_LEN_ADD_ADDR4 + 2) ||
		    (mpadd->ipver == 6 && opsize != MPTCP_SUB_LEN_ADD_ADDR6 &&
		     opsize != MPTCP_SUB_LEN_ADD_ADDR6 + 2)) {
#else
		if (opsize != MPTCP_SUB_LEN_ADD_ADDR4 &&
		    opsize != MPTCP_SUB_LEN_ADD_ADDR4 + 2) {
#endif /* CONFIG_IPV6 */
			mptcp_debug("%s: mp_add_addr: bad option size %d\n",
					__func__, opsize);
			break;
		}

		if (mpadd->ipver == 4) {
			__be16 port = 0;
			if (opsize == MPTCP_SUB_LEN_ADD_ADDR4 + 2)
				port = mpadd->u.v4.port;

			mptcp_v4_add_raddress(mopt, &mpadd->u.v4.addr, port,
					      mpadd->addr_id);
#if IS_ENABLED(CONFIG_IPV6)
		} else if (mpadd->ipver == 6) {
			__be16 port = 0;
			if (opsize == MPTCP_SUB_LEN_ADD_ADDR6 + 2)
				port = mpadd->u.v6.port;

			mptcp_v6_add_raddress(mopt, &mpadd->u.v6.addr, port,
					      mpadd->addr_id);
#endif /* CONFIG_IPV6 */
		}
		break;
	}
	case MPTCP_SUB_REMOVE_ADDR:
	{
		struct mp_remove_addr *mprem = (struct mp_remove_addr *) ptr;
		u8 rem_id;
		int i;

		if ((opsize - MPTCP_SUB_LEN_REMOVE_ADDR) < 0) {
			mptcp_debug("%s: mp_remove_addr: bad option size %d\n",
					__func__, opsize);
			break;
		}

		for (i = 0; i <= opsize - MPTCP_SUB_LEN_REMOVE_ADDR; i++) {
			rem_id = (&mprem->addrs_id)[i];
			if (!mptcp_rem_raddress(mopt, rem_id))
				mptcp_send_reset_rem_id(mopt->mpcb, rem_id);
		}
		break;
	}
	case MPTCP_SUB_PRIO:
	{
		struct mp_prio *mpprio = (struct mp_prio *) ptr;

		if (opsize == MPTCP_SUB_LEN_PRIO) {
			/* change priority of this subflow */
			opt_rx->low_prio = mpprio->b;
		} else if (opsize == MPTCP_SUB_LEN_PRIO_ADDR) {
			struct sock *sk;
			/* change priority of all subflow using this addr_id */
			mptcp_for_each_sk(mopt->mpcb, sk) {
				if (tcp_sk(sk)->mptcp->rem_id == mpprio->addr_id)
					tcp_sk(sk)->rx_opt.low_prio = mpprio->b;
			}
		} else {
			mptcp_debug("%s: mp_prio: bad option size %d\n",
					__func__, opsize);
		}
		break;
	}
	case MPTCP_SUB_FAIL:
		if (opsize != MPTCP_SUB_LEN_FAIL) {
			mptcp_debug("%s: mp_fail: bad option size %d\n",
					__func__, opsize);
			break;
		}
		mopt->mp_fail = 1;
		break;
	case MPTCP_SUB_FCLOSE:
		if (opsize != MPTCP_SUB_LEN_FCLOSE) {
			mptcp_debug("%s: mp_fclose: bad option size %d\n",
					__func__, opsize);
			break;
		}

		mopt->mp_fclose = 1;
		if (mopt->mpcb &&
		    mopt->mpcb->mptcp_loc_key != ((struct mp_fclose *)ptr)->key)
			mopt->mp_fclose = 0;

		break;
	default:
		mptcp_debug("%s: Received unkown subtype: %d\n", __func__,
				mp_opt->sub);
		break;
	}
}

