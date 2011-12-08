/*
 *	MPTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      date : Aug 11
 *
 *      Important note:
 *            When one wants to add support for closing subsockets *during*
 *             a communication, he must ensure that all skbs belonging to
 *             that socket are removed from the meta-queues. Failing
 *             to do this would lead to General Protection Fault.
 *             See also comment in function mptcp_destroy_mpcb().
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <asm/unaligned.h>

#include <crypto/sha.h>

#include <net/inet_common.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/transp_v6.h>

#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/random.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#define AF_INET6_FAMILY(fam) ((fam) == AF_INET6)
#else
#define AF_INET_FAMILY(fam) 1
#define AF_INET6_FAMILY(fam) 0
#endif

/* ===================================== */
/* DEBUGGING */

#ifdef MPTCP_RCV_QUEUE_DEBUG
struct mptcp_debug mptcp_debug_array1[1000];
struct mptcp_debug mptcp_debug_array2[1000];

void print_debug_array(void)
{
	int i;
	printk(KERN_ERR "debug array, path index 1:\n");
	for (i = 0; i < 1000 && mptcp_debug_array1[i-1].end == 0; i++) {
		printk(KERN_ERR "\t%s:skb %x, len %d\n",
			mptcp_debug_array1[i].func_name,
			mptcp_debug_array1[i].seq,
			mptcp_debug_array1[i].len);
	}
	printk(KERN_ERR "debug array, path index 2:\n");

	for (i = 0; i < 1000 && mptcp_debug_array2[i-1].end == 0; i++) {
		printk(KERN_ERR "\t%s:skb %x, len %d\n",
			mptcp_debug_array2[i].func_name,
			mptcp_debug_array2[i].seq,
			mptcp_debug_array2[i].len);
	}
}

void freeze_rcv_queue(struct sock *sk, const char *func_name)
{
	int i;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	int path_index = tp->path_index;
	struct mptcp_debug *mptcp_debug_array;

	if (path_index == 0 || path_index == 1)
		mptcp_debug_array = mptcp_debug_array1;
	else
		mptcp_debug_array = mptcp_debug_array2;

	for (skb = skb_peek(&sk->sk_receive_queue), i = 0;
	     skb && skb != (struct sk_buff *) &sk->sk_receive_queue;
	     skb = skb->next, i++) {
		mptcp_debug_array[i].func_name = func_name;
		mptcp_debug_array[i].seq = TCP_SKB_CB(skb)->seq;
		mptcp_debug_array[i].len = skb->len;
		mptcp_debug_array[i].end = 0;
		BUG_ON(i >= 999);
	}

	if (i > 0) {
		mptcp_debug_array[i-1].end = 1;
	} else {
		mptcp_debug_array[0].func_name = "NO_FUNC";
		mptcp_debug_array[0].end = 1;
	}
}

#endif

#ifdef DEBUG_WQUEUES
void verif_wqueues(struct multipath_pcb *mpcb)
{
	struct sock *sk;
	struct sock *meta_sk = (struct sock *)mpcb;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int sum;

	local_bh_disable();
	mptcp_for_each_sk(mpcb, sk, tp) {
		sum = 0;
		tcp_for_write_queue(skb, sk) {
			sum += skb->truesize;
		}
		if (sum != sk->sk_wmem_queued) {
			printk(KERN_ERR "wqueue leak_1: enqueued:%d, recorded "
					"value:%d\n",
					sum, sk->sk_wmem_queued);

			tcp_for_write_queue(skb, sk) {
				printk(KERN_ERR "skb truesize:%d\n",
						skb->truesize);
			}

			local_bh_enable();
			BUG();
		}
	}
	sum = 0;
	tcp_for_write_queue(skb, meta_sk)
	sum += skb->truesize;
	BUG_ON(sum != meta_sk->sk_wmem_queued);
	local_bh_enable();
}
#else
static inline void verif_wqueues(struct multipath_pcb *mpcb)
{
	return;
}
#endif

#ifdef DEBUG_RQUEUES
void verif_rqueues(struct multipath_pcb *mpcb)
{
	struct sock *sk;
	struct sock *meta_sk = (struct sock *)mpcb;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int sum;

	local_bh_disable();
	mptcp_for_each_sk(mpcb, sk, tp) {
		sum = 0;
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			sum += skb->truesize;
		}
		/* TODO: add meta-rcv and meta-ofo-queues */
		if (sum != atomic_read(&sk->sk_rmem_alloc)) {
			printk(KERN_ERR "rqueue leak: enqueued:%d, recorded "
					"value:%d\n",
					sum, sk->sk_rmem_alloc);

			local_bh_enable();
			BUG();
		}
	}
	local_bh_enable();
}
#endif

static struct kmem_cache *mpcb_cache __read_mostly;

/* ===================================== */

static inline int mptcp_is_available(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp;

	/* Set of states for which we are allowed to send data */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		return 0;

	tp = tcp_sk(sk);
	if (tp->pf || (tp->mpcb->noneligible & mptcp_pi_to_flag(tp->path_index)) ||
	    inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
		return 0;
	if (tcp_cwnd_test(tp, skb))
		return 1;
	return 0;
}

static inline int mptcp_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 * An exception is a DATA_FIN without data. These ones are not
	 * retransmitted at the subflow-level as they do not consume
	 * subflow-sequence-number space.
	 */
	return skb &&
		/* We either have a data_fin with data or not a data_fin */
		((mptcp_is_data_fin(skb) && TCP_SKB_CB(skb)->data_len > 1) ||
		!mptcp_is_data_fin(skb))&&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->path_index) & skb->path_mask;
}

/**
 * This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the estimation of how much time will be
 * needed to send the segment. If all paths have full cong windows, we
 * simply block. The flow able to send the segment the soonest get it.
 */
static struct sock *get_available_subflow(struct multipath_pcb *mpcb,
					  struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sock *bestsk = NULL, *backup = NULL;
	u32 min_time_to_peer = 0xffffffff;

	if (!mpcb)
		return NULL;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *) mpcb->connection_list;
		if (!mptcp_is_available(bestsk, skb))
			bestsk = NULL;
		goto out;
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk, tp) {
		if (mptcp_dont_reinject_skb(tp, skb))
			continue;

		if (!mptcp_is_available(sk, skb))
			continue;

		if (tp->srtt < min_time_to_peer &&
		    !(skb && mptcp_pi_to_flag(tp->path_index) & skb->path_mask)) {
			min_time_to_peer = tp->srtt;
			bestsk = sk;
		}

		if (skb && mptcp_pi_to_flag(tp->path_index) & skb->path_mask)
			backup = sk;
	}

out:
	if (!bestsk)
		return backup;

	return bestsk;
}

/**
 * Round-robin scheduler (if flow is available)
 */
static struct sock *rr_scheduler(struct multipath_pcb *mpcb,
				   struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct sock *sk, *bestsk = NULL;
	int found = 0;

	if (!mpcb)
		return NULL;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *) mpcb->connection_list;
		if (!mptcp_is_available(bestsk, skb))
			bestsk = NULL;
		goto out;
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk, tp) {
		/* Looking for the last pi that has been selected. */
		if (!found && mpcb->last_pi_selected != tp->path_index) {
			continue;
		} else {
			found = 1;
			/* Go one further */
			if (mpcb->last_pi_selected == tp->path_index)
				continue;
		}

		/* If the skb has already been enqueued in this sk, try to find
		 * another one
		 */
		if (unlikely(mptcp_pi_to_flag(tp->path_index) & skb->path_mask))
			continue;

		if (!mptcp_is_available(sk, skb))
			continue;

		bestsk = sk;
		mpcb->last_pi_selected = tp->path_index;
		break;
	}

	if (!bestsk) {
		/* We may need to restart from the beginning to find a subflow */
		mptcp_for_each_sk(mpcb, sk, tp)	{
			/* If the skb has already been enqueued in this sk,
			 * try to find another one.
			 */
			if (unlikely(mptcp_pi_to_flag(tp->path_index) & skb->path_mask))
				continue;

			if (!mptcp_is_available(sk, skb))
				continue;

			bestsk = sk;
			mpcb->last_pi_selected = tp->path_index;
			break;
		}
	}

out:
	return bestsk;
}

static int mptcp_sched_min = 1;
static int mptcp_sched_max = MPTCP_SCHED_MAX;

struct sock *(*mptcp_schedulers[MPTCP_SCHED_MAX])
		(struct multipath_pcb *, struct sk_buff *) = {
				&get_available_subflow,
				&rr_scheduler,
		};

/* Sysctl data */

#ifdef CONFIG_SYSCTL

int sysctl_mptcp_mss __read_mostly = MPTCP_MSS;
int sysctl_mptcp_ndiffports __read_mostly = 1;
int sysctl_mptcp_enabled __read_mostly = 1;
int sysctl_mptcp_scheduler __read_mostly = 1;
int sysctl_mptcp_checksum __read_mostly = 1;
int sysctl_mptcp_rbuf_opti __read_mostly = 1;
int sysctl_mptcp_rbuf_retr __read_mostly = 1;
int sysctl_mptcp_rbuf_penal __read_mostly = 1;

static ctl_table mptcp_table[] = {
	{
		.procname = "mptcp_mss",
		.data = &sysctl_mptcp_mss,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_ndiffports",
		.data = &sysctl_mptcp_ndiffports,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_enabled",
		.data = &sysctl_mptcp_enabled,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_checksum",
		.data = &sysctl_mptcp_checksum,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname	= "mptcp_scheduler",
		.data		= &sysctl_mptcp_scheduler,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= &mptcp_sched_min,
		.extra2		= &mptcp_sched_max
	},
	{
		.procname = "mptcp_rbuf_opti",
		.data = &sysctl_mptcp_rbuf_opti,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_rbuf_retr",
		.data = &sysctl_mptcp_rbuf_retr,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_rbuf_penal",
		.data = &sysctl_mptcp_rbuf_penal,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{ }
};

static ctl_table mptcp_net_table[] = {
	{
		.procname = "mptcp",
		.maxlen = 0,
		.mode = 0555,
		.child = mptcp_table
	},
	{ }
};

static ctl_table mptcp_root_table[] = {
	{
		.procname = "net",
		.mode = 0555,
		.child = mptcp_net_table
	},
	{ }
};
#endif

static struct sock *mptcp_select_ack_sock(const struct multipath_pcb *mpcb,
					  int copied)
{
	struct sock *sk, *subsk = NULL;
	struct tcp_sock *tp, *meta_tp = mpcb_meta_tp(mpcb);
	u32 max_data_seq = 0;
	/* max_data_seq initialized to correct compiler-warning.
	 * But the initialization is handled by max_data_seq_set */
	short max_data_seq_set = 0;
	u32 min_time = 0xffffffff;

	/* How do we select the subflow to send the window-update on?
	 *
	 * 1. He has to be in a state where he can send an ack.
	 * 2. He has to be one of those subflow who recently
	 *    contributed to the received stream
	 *    (this guarantees a working subflow)
	 *    a) its latest data_seq received is after the original
	 *       copied_seq.
	 *       We select the one with the lowest rtt, so that the
	 *       window-update reaches our peer the fastest.
	 *    b) if no subflow has this kind of data_seq (e.g., very
	 *       strange meta-level retransmissions going on), we take
	 *       the subflow who last sent the highest data_seq.
	 */
	mptcp_for_each_sk(mpcb, sk, tp) {
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV |
					   TCPF_CLOSE | TCPF_LISTEN))
			continue;

		/* Select among those who contributed to the
		 * current receive-queue. */
		if (copied && after(tp->last_data_seq, meta_tp->copied_seq - copied)) {
			if (tp->srtt < min_time) {
				min_time = tp->srtt;
				subsk = sk;
				max_data_seq_set = 0;
			}
			continue;
		}

		if (!subsk && !max_data_seq_set) {
			max_data_seq = tp->last_data_seq;
			max_data_seq_set = 1;
			subsk = sk;
		}

		/* Otherwise, take the one with the highest data_seq */
		if ((!subsk || max_data_seq_set) &&
		    after(tp->last_data_seq, max_data_seq)) {
			max_data_seq = tp->last_data_seq;
			subsk = sk;
		}
	}

	if (!subsk) {
		mptcp_debug("%s subsk is null, copied %d, cseq %u\n", __func__,
			    copied, meta_tp->copied_seq);
		mptcp_for_each_sk(mpcb, sk, tp) {
			mptcp_debug("%s pi %d state %u last_dseq %u\n",
				    __func__, tp->path_index, sk->sk_state,
				    tp->last_data_seq);
		}
	}

	return subsk;
}

/**
 * Equivalent of tcp_fin() for MPTCP
 * Can be called only when the FIN is validly part
 * of the data seqnum space. Not before when we get holes.
 */
int mptcp_fin(struct multipath_pcb *mpcb, struct sock *sk)
{
	struct sock *meta_sk = (struct sock*)mpcb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	int ans = 0;

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

static void mptcp_sock_def_error_report(struct sock *sk)
{
	/* If there exists more than one working subflow, we don't wake up the
	 * application, as the mptcp-connection is still alive */
	if (tcp_sk(sk)->mpc &&
	    tcp_sk(sk)->mpcb->cnt_established > mptcp_sk_can_send(sk) ? 1 : 0) {
		sk->sk_err = 0;
		sock_orphan(sk);
		return;
	}

	sock_def_error_report(sk);

	/* Always orphan a mptcp-subsocket, because we are allowed to destroy
	 * it, as the master will still stay alive and thus be accessible for
	 * the application.
	 */
	if (tcp_sk(sk)->mpc)
		sock_orphan(sk);
}

/**
 * Creates as many sockets as path indices announced by the Path Manager.
 * The first path indices are (re)allocated to existing sockets.
 * New sockets are created if needed.
 * Note that this is called only at client side.
 * Server calls mptcp_subflow_attach()
 *
 * WARNING: We make the assumption that this function is run in user context
 *      (we use sock_create_kern, that reserves ressources with GFP_KERNEL)
 */
int mptcp_init_subsockets(struct multipath_pcb *mpcb, u32 path_indices)
{
	int i;
	struct tcp_sock *tp;

	/* First, ensure that we keep existing path indices. */
	mptcp_for_each_tp(mpcb, tp)
		/* disable the corresponding bit of the existing subflow */
		path_indices &= ~mptcp_pi_to_flag(tp->path_index);

	for (i = 0; i < sizeof(path_indices) * 8; i++) {
		struct sock *sk, *meta_sk = (struct sock *)mpcb;
		struct socket sock;
		struct sockaddr *loculid, *remulid;
		struct mptcp_path4 *pa4 = NULL;
		struct mptcp_path6 *pa6 = NULL;
		int ulid_size = 0, newpi = i + 1, family, ret;

		if (!((1 << i) & path_indices))
			continue;

		family = mptcp_get_path_family(mpcb, newpi);

		sock.type = meta_sk->sk_socket->type;
		sock.state = SS_UNCONNECTED;
		sock.wq = meta_sk->sk_socket->wq;
		sock.file = meta_sk->sk_socket->file;
		sock.ops = NULL;
		if (family == AF_INET) {
			ret = inet_create(&init_net, &sock, IPPROTO_TCP, 1);
		} else {
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			ret = inet6_create(&init_net, &sock, IPPROTO_TCP, 1);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
		}

		if (ret < 0) {
			mptcp_debug("%s inet_create failed ret: %d, "
					"family %d\n", __func__, ret, family);
			continue;
		}

		sk = sock.sk;

		/* Binding the new socket to the local ulid
		 * (except if we use the MPTCP default PM, in which
		 * case we bind the new socket, directly to its
		 * corresponding locators)
		 */
		switch (family) {
		case AF_INET:
			pa4 = mptcp_v4_get_path(mpcb, newpi);

			BUG_ON(!pa4);

			loculid = (struct sockaddr *) &pa4->loc;

			if (!pa4->rem.sin_port)
				pa4->rem.sin_port =
						inet_sk(meta_sk)->inet_dport;
			remulid = (struct sockaddr *) &pa4->rem;
			ulid_size = sizeof(pa4->loc);
			inet_sk(sk)->loc_id = pa4->loc_id;
			inet_sk(sk)->rem_id = pa4->rem_id;
			break;
		case AF_INET6:
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			pa6 = mptcp_get_path6(mpcb, newpi);

			BUG_ON(!pa6);

			loculid = (struct sockaddr *) &pa6->loc;

			if (!pa6->rem.sin6_port)
				pa6->rem.sin6_port =
						inet_sk(meta_sk)->inet_dport;
			remulid = (struct sockaddr *) &pa6->rem;
			ulid_size = sizeof(pa6->loc);
			inet_sk(sk)->loc_id = pa6->loc_id;
			inet_sk(sk)->rem_id = pa6->rem_id;
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
			break;
		default:
			BUG();
		}
		tp = tcp_sk(sk);
		tp->path_index = newpi;
		tp->mpc = 1;
		tp->slave_sk = 1;

		sk->sk_error_report = mptcp_sock_def_error_report;

		mptcp_add_sock(mpcb, tp);

		if (family == AF_INET) {
			struct sockaddr_in *loc, *rem;
			loc = (struct sockaddr_in *) loculid;
			rem = (struct sockaddr_in *) remulid;
			mptcp_debug("%s: token %#x pi %d src_addr:"
				"%pI4:%d dst_addr:%pI4:%d\n", __func__,
				mpcb->mptcp_loc_token, newpi,
				&loc->sin_addr,
				ntohs(loc->sin_port),
				&rem->sin_addr,
				ntohs(rem->sin_port));
		} else {
			struct sockaddr_in6 *loc, *rem;
			loc = (struct sockaddr_in6 *) loculid;
			rem = (struct sockaddr_in6 *) remulid;
			mptcp_debug("%s: token %#x pi %d src_addr:"
				"%pI6:%d dst_addr:%pI6:%d\n", __func__,
				mpcb->mptcp_loc_token, newpi,
				&loc->sin6_addr,
				ntohs(loc->sin6_port),
				&rem->sin6_addr,
				ntohs(rem->sin6_port));
		}

		ret = sock.ops->bind(&sock, loculid, ulid_size);
		if (ret < 0) {
			printk(KERN_ERR "%s: MPTCP subsocket bind() failed, "
					"error %d\n", __func__, ret);
			goto cont_error;
		}

		ret = sock.ops->connect(&sock, remulid, ulid_size, O_NONBLOCK);
		if (ret < 0 && ret != -EINPROGRESS) {
			printk(KERN_ERR "%s: MPTCP subsocket connect() failed, "
					"error %d\n", __func__, ret);
			goto cont_error;
		}

		sk_set_socket(sk, meta_sk->sk_socket);
		sk->sk_wq = meta_sk->sk_wq;

		if (family == AF_INET)
			pa4->loc.sin_port = inet_sk(sk)->inet_sport;
		else
			pa6->loc.sin6_port = inet_sk(sk)->inet_sport;

		continue;

cont_error:
		sock_orphan(sk);
		tcp_done(sk);
	}

	return 0;
}

void mptcp_key_sha1(u64 key, u32 *token) {
	u32 workspace[SHA_WORKSPACE_WORDS];
	u32 mptcp_hashed_key[SHA_DIGEST_WORDS];
	u8 input[64];

	memset(workspace, 0, sizeof(workspace));

	/* Initialize input with appropriate padding */
	memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too */
	memcpy(input, &key, sizeof(key)); /* Copy key to the msg beginning */
	input[8] = 0x80; /* Padding: First bit after message = 1 */
	input[63] = 0x40; /* Padding: Length of the message = 64 bits */

	sha_init(mptcp_hashed_key);
	sha_transform(mptcp_hashed_key, input, workspace);

	*token = mptcp_hashed_key[0];
}

void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		     u32 *hash_out)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u8 input[128]; /* 2 512-bit blocks */
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], rand_1, 4);
	memcpy(&input[68], rand_2, 4);
	input[72] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[73], 0, 53);

	/* Padding: Length of the message = 512 + 64 bits */
	input[126] = 0x02;
	input[127] = 0x40;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
}


/**
 * Reinject data from one TCP subflow to the meta_sk
 * The @skb given pertains to the original tp, that keeps it
 * because the skb is still sent on the original tp. But additionnally,
 * it is sent on the other subflow.
 *
 * @pre : @sk must be the meta_sk
 */
static int __mptcp_reinject_data(struct sk_buff *orig_skb, struct sock *meta_sk,
		struct sock *sk, int clone_it)
{
	struct sk_buff *skb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk), *tp_it;
	struct sock *sk_it;

	/* A segment can be added to the reinject queue only if
	 * there is at least one working subflow that has never sent
	 * this data */
	mptcp_for_each_sk(meta_tp->mpcb, sk_it, tp_it) {
		if (!mptcp_sk_can_send(sk_it) || tp_it->pf)
			continue;

		if (mptcp_dont_reinject_skb(tp_it, orig_skb))
			continue;

		/* candidate subflow found, we can reinject */
		break;
	}

	if (!sk_it) {
		mptcp_debug("%s: skb already injected to all paths - dseq %u "
			    "dlen %u pi %d reinjseq %u mptcp_flags %#x tcp_flags %#x\n",
			    __func__,
			    TCP_SKB_CB(orig_skb)->data_seq,
			    TCP_SKB_CB(orig_skb)->data_len,
			    sk ? tcp_sk(sk)->path_index : -1,
			    sk ? tcp_sk(sk)->reinjected_seq : 0xFFFFFFFF,
			    TCP_SKB_CB(orig_skb)->mptcp_flags,
			    TCP_SKB_CB(orig_skb)->flags);
		return 1; /* no candidate found */
	}

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
	skb->sk = meta_sk;

	skb_queue_tail(&meta_tp->mpcb->reinject_queue, skb);
	return 0;
}

/* Inserts data into the reinject queue */
void mptcp_reinject_data(struct sock *sk, int clone_it)
{
	struct sk_buff *skb_it, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);
	struct multipath_pcb *mpcb = tp->mpcb;
	struct sock *meta_sk = (struct sock *) mpcb;

	BUG_ON(is_meta_sk(sk));

	verif_wqueues(mpcb);

	skb_queue_walk_safe(&sk->sk_write_queue, skb_it, tmp) {
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb_it);
		/* seq > reinjected_seq , to avoid reinjecting several times
		 * the same segment. This does not duplicate functionality with
		 * skb->path_mask, because the path_mask ensures the skb is not
		 * scheduled twice to the same subflow. OTOH, the seq
		 * check ensures that at any time, _one_ subflow exactly
		 * is allowed to reinject it, not all of them. That one
		 * subflow is the one that received it last.
		 * Also, subflow syn's and fin's are not reinjected
		 */
		if (before(tcb->seq, tp->reinjected_seq) ||
		    tcb->flags & TCPHDR_SYN ||
		    (tcb->flags & TCPHDR_FIN && !mptcp_is_data_fin(skb_it)))
			continue;
		skb_it->path_mask |= mptcp_pi_to_flag(tp->path_index);
		if (__mptcp_reinject_data(skb_it, meta_sk, sk, clone_it) < 0)
			break;
		tp->reinjected_seq = tcb->end_seq;
	}

	tcp_push(meta_sk, 0, mptcp_sysctl_mss(), TCP_NAGLE_PUSH);

	tp->pf = 1;

	verif_wqueues(mpcb);
}

void mptcp_retransmit_timer(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct multipath_pcb *mpcb = meta_tp->mpcb;
	struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);

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
	tcp_push(meta_sk, 0, mptcp_sysctl_mss(), TCP_NAGLE_PUSH);

out:
	meta_icsk->icsk_rto = min(meta_icsk->icsk_rto << 1, TCP_RTO_MAX * 2);
	inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS,
			meta_icsk->icsk_rto, TCP_RTO_MAX * 2);
}

/* Inspired by tcp_write_wakeup */
int mptcp_write_wakeup(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb;

	if ((skb = tcp_send_head(meta_sk)) != NULL &&
	    before(mptcp_skb_data_seq(skb), tcp_wnd_end(meta_tp, 1))) {
		/* Currently, zero-window-probes are still handled on a
		 * subflow-level */
		mptcp_debug("%s INSIDE - zero-window-probes on the meta-sk\n",
				__func__);
		BUG();
	} else {
		struct sock *sk_it;
		struct tcp_sock *tp_it;
		int ans = 0;

		if (between(meta_tp->snd_up, meta_tp->snd_una + 1,
			    meta_tp->snd_una + 0xFFFF)) {
			mptcp_for_each_sk(meta_tp->mpcb, sk_it, tp_it)
					tcp_xmit_probe_skb(sk_it, 1);
		}

		/* At least on of the tcp_xmit_probe_skb's has to succeed */
		mptcp_for_each_sk(meta_tp->mpcb, sk_it, tp_it) {
			int ret = tcp_xmit_probe_skb(sk_it, 0);
			if (unlikely(ret > 0))
				ans = ret;
		}
		return ans;
	}
}


void mptcp_mark_reinjected(struct sock *sk, struct sk_buff *skb)
{
	struct sock *meta_sk;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb_it;

	if (!tp->mpc)
		return;

	meta_sk = mptcp_meta_sk(sk);
	skb_it = tcp_write_queue_head(meta_sk);

	tcp_for_write_queue_from(skb_it, meta_sk) {
		if (skb_it == tcp_send_head(meta_sk))
			break;

		if (TCP_SKB_CB(skb_it)->data_seq == TCP_SKB_CB(skb)->data_seq) {
			skb_it->path_mask |= mptcp_pi_to_flag(tp->path_index);
			break;
		}
	}
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk)
{
	struct sock *meta_sk, *sk_it;
	struct tcp_sock *tp = tcp_sk(sk), *tp_it;
	struct sk_buff *skb_it;

	if (!tp->mpc || !sysctl_mptcp_rbuf_opti)
		return NULL;

	if (tp->mpcb->cnt_established == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_it = tcp_write_queue_head(meta_sk);

	if (!skb_it || skb_it == tcp_send_head(meta_sk))
		return NULL;

	if (!sysctl_mptcp_rbuf_penal)
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_sk(tp->mpcb, sk_it, tp_it) {
		if (tp_it != tp &&
		    skb_it->path_mask & mptcp_pi_to_flag(tp_it->path_index)) {
			u64 bw1, bw2;

			/* Only update every subflow rtt */
			if (tcp_time_stamp - tp_it->last_rbuf_opti < tp_it->srtt >> 3)
				break;

			bw1 = (u64) tp_it->snd_cwnd << 32;
			bw1 = div64_u64(bw1, tp_it->srtt);
			bw2 = (u64) tp->snd_cwnd << 32;
			bw2 = div64_u64(bw2, tp->srtt);

			if (bw1 < bw2) {
				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);
				tp_it->snd_ssthresh = max(tp_it->snd_cwnd, 2U);
				tp_it->last_rbuf_opti = tcp_time_stamp;
			}
			break;
		}
	}

retrans:
	if (!sysctl_mptcp_rbuf_retr)
		return NULL;

	/* Segment not yet injected into this path? Take it!!! */
	if (!(skb_it->path_mask & mptcp_pi_to_flag(tp->path_index))) {
		int do_retrans = 0;
		mptcp_for_each_sk(tp->mpcb, sk_it, tp_it) {
			if (tp_it != tp && skb_it->path_mask & mptcp_pi_to_flag(tp_it->path_index)) {
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

		if (do_retrans) {
			return skb_it;
		}
	}
	return NULL;
}

int mptcp_write_xmit(struct sock *meta_sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct multipath_pcb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;
	int reinject = 0;

	if (meta_sk->sk_in_write_xmit) {
		printk(KERN_ERR "sk in write xmit, meta_sk: %d\n",
		       is_meta_sk(meta_sk));
		BUG();
	}

	/* We can be recursively called only in TCP_FIN_WAIT1 state (because
	 * the very last segment calls tcp_send_fin() on all subflows)
	 */
	if (meta_sk->sk_in_write_xmit &&
	    ((1 << meta_sk->sk_state) & ~(TCPF_FIN_WAIT1 | TCPF_LAST_ACK))) {
		printk(KERN_ERR "meta-sk in write xmit, meta-sk:%d, state of "
		       "meta_sk:%d\n", is_meta_sk(meta_sk), meta_sk->sk_state);
		BUG();
	}

	meta_sk->sk_in_write_xmit = 1;

	if (mss_now != mptcp_sysctl_mss()) {
		printk(KERN_ERR "write xmit-mss_now %d, mptcp mss:%d\n",
		       mss_now, mptcp_sysctl_mss());
		BUG();
	}
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and all
	 * will be happy.
	 */
	if (unlikely(meta_sk->sk_state == TCP_CLOSE)) {
		meta_sk->sk_in_write_xmit = 0;
		return 0;
	}

	sent_pkts = 0;

	if (!push_one) {
		/* Do MTU probing. */
		result = tcp_mtu_probe(meta_sk);
		if (!result) {
			meta_sk->sk_in_write_xmit = 0;
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

		if (reinject > 0 && !after(mptcp_skb_end_data_seq(skb),
				       meta_tp->snd_una)) {
			/* another copy of the segment already reached
			 * the peer, just discard this one
			 */
			skb_unlink(skb, &mpcb->reinject_queue);
			kfree_skb(skb);
			continue;
		}

		subsk = mptcp_schedulers[sysctl_mptcp_scheduler - 1](mpcb, skb);
		if (!subsk)
			break;
		subtp = tcp_sk(subsk);

		/* Since all subsocks are locked before calling the scheduler,
		 * the tcp_send_head should not change.
		 */
		BUG_ON(!reinject && tcp_send_head(meta_sk) != skb);
retry:

		/* This must be invoked even if we don't want
		 * to support TSO at the moment
		 */
		tso_segs = tcp_init_tso_segs(meta_sk, skb, mss_now);
		BUG_ON(!tso_segs);
		/* At the moment we do not support tso, hence
		 * tso_segs must be 1
		 */
		BUG_ON(tso_segs != 1);

		/* decide to which subsocket we give the skb */
		cwnd_quota = tcp_cwnd_test(subtp, skb);
		if (!cwnd_quota) {
			/* Should not happen, since mptcp must have
			 * chosen a subsock with open cwnd
			 */
			BUG();
			break;
		}

		if (!reinject && unlikely(!tcp_snd_wnd_test(subtp, skb, mss_now))) {
			skb = mptcp_rcv_buf_optimization(subsk);
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
			/* tso not supported in MPTCP */
			BUG();
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
			/* The segment may be a meta-level
			 * retransmission. In this case, we also have to
			 * copy the TCP/IP-headers. (pskb_copy)
			 */
			if (unlikely(skb->path_mask & ~mptcp_pi_to_flag(subtp->path_index)))
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

		if (subtp->path_index)
			skb->path_mask |= mptcp_pi_to_flag(subtp->path_index);

		if (!(subsk->sk_route_caps & NETIF_F_ALL_CSUM) &&
		    skb->ip_summed == CHECKSUM_PARTIAL) {
			skb->csum = skb_checksum_complete(subskb);
			skb->ip_summed = CHECKSUM_NONE;
		}

		if (mptcp_is_data_fin(subskb))
			mptcp_combine_dfin(subskb, meta_tp, subsk);
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
			tcp_advance_send_head(subsk, subskb);
			tcp_unlink_write_queue(subskb, subsk);
			subtp->write_seq -= subskb->len;
			mptcp_wmem_free_skb(subsk, subskb);

			mpcb->noneligible |= mptcp_pi_to_flag(subtp->path_index);

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
		tcp_event_new_data_sent(subsk, subskb);

		BUG_ON(tcp_send_head(subsk));
		if (!reinject) {
			BUG_ON(tcp_send_head(meta_sk) != skb);
			tcp_event_new_data_sent(meta_sk, skb);
		}
		if (reinject > 0) {
			mptcp_mark_reinjected(subsk, skb);
		}

		tcp_minshall_update(meta_tp, mss_now, skb);
		sent_pkts++;

		tcp_cwnd_validate(subsk);
		if (push_one)
			break;
	}

	mpcb->noneligible = 0;

	if (likely(sent_pkts)) {
		meta_sk->sk_in_write_xmit = 0;
		return 0;
	}
	meta_sk->sk_in_write_xmit = 0;
	return !meta_tp->packets_out && tcp_send_head(meta_sk);
}

static void mptcp_mpcb_inherit_sockopts(struct sock *meta_sk, struct sock *master_sk) {
	/* Socket-options handled by mptcp_inherit_sk while creating the meta-sk.
	 * ======
	 * SO_SNDBUF, SO_SNDBUFFORCE, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT,
	 * SO_RCVTIMEO, SO_SNDTIMEO, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	 * TCP_NODELAY, TCP_CORK
	 *
	 * Socket-options handled in this function here
	 * ======
	 * SO_KEEPALIVE
	 * TCP_KEEP*
	 *
	 * Socket-options on the todo-list
	 * ======
	 * SO_BINDTODEVICE - should probably prevent creation of new subsocks
	 * 		     across other devices. - what about the api-draft?
	 * SO_DEBUG
	 * SO_REUSEADDR - probably we don't care about this
	 * SO_DONTROUTE, SO_BROADCAST
	 * SO_OOBINLINE
	 * SO_LINGER
	 * SO_TIMESTAMP* - I don't think this is of concern for a SOCK_STREAM
	 * SO_PASSSEC - I don't think this is of concern for a SOCK_STREAM
	 * SO_RXQ_OVFL
	 * TCP_COOKIE_TRANSACTIONS
	 * TCP_MAXSEG
	 * TCP_THIN_* - Handled by mptcp_inherit_sk, but we need to support this
	 * 		in mptcp_retransmit_timer. AND we need to check what is
	 * 		about the subsockets.
	 * TCP_LINGER2
	 * TCP_WINDOW_CLAMP
	 * TCP_USER_TIMEOUT
	 * TCP_MD5SIG
	 *
	 * Socket-options of no concern for the meta-socket (but for the subsocket)
	 * ======
	 * SO_PRIORITY
	 * SO_MARK
	 * TCP_CONGESTION
	 * TCP_SYNCNT
	 * TCP_DEFER_ACCEPT
	 * TCP_QUICKACK
	 */
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	/****** KEEPALIVE-handler ******/

	/* Keepalive-timer has been started in tcp_rcv_synsent_state_process or
	 * tcp_create_openreq_child */
	if (sock_flag(meta_sk, SOCK_KEEPOPEN)) {
		inet_csk_reset_keepalive_timer(meta_sk, keepalive_time_when(meta_tp));

		/* Prevent keepalive-reset in tcp_rcv_synsent_state_process */
		sock_reset_flag(master_sk, SOCK_KEEPOPEN);
	}
}

static void mptcp_sub_inherit_sockopts(struct sock *meta_sk, struct sock *sub_sk) {
	/* Keepalive is handled at the meta-level */
	if (sock_flag(meta_sk, SOCK_KEEPOPEN)) {
		inet_csk_delete_keepalive_timer(sub_sk);
	}
}

int mptcp_alloc_mpcb(struct sock *master_sk)
{
	struct multipath_pcb *mpcb;
	struct tcp_sock *meta_tp, *master_tp = tcp_sk(master_sk);
	struct sock *meta_sk;
	struct inet_connection_sock *meta_icsk;

	mpcb = kmem_cache_alloc(mpcb_cache, GFP_ATOMIC);
	/* Memory allocation failed. Stopping here. */
	if (!mpcb)
		return -ENOBUFS;

	meta_sk = mpcb_meta_sk(mpcb);
	meta_tp = mpcb_meta_tp(mpcb);
	meta_icsk = inet_csk(meta_sk);

	memset(mpcb, 0, sizeof(struct multipath_pcb));

	/* meta_sk inherits master sk */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	mptcp_inherit_sk(master_sk, meta_sk, AF_INET6, GFP_ATOMIC);
#else
	mptcp_inherit_sk(master_sk, meta_sk, AF_INET, GFP_ATOMIC);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (AF_INET_FAMILY(master_sk->sk_family)) {
		mpcb->icsk_af_ops_alt = &ipv6_specific;
		mpcb->sk_prot_alt = &tcpv6_prot;
	} else {
		mpcb->icsk_af_ops_alt = &ipv4_specific;
		mpcb->sk_prot_alt = &tcp_prot;
	}
	init_timer(&mpcb->dad_waiter);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	/* Will be replaced by the IDSN later. Currently the IDSN is zero */
	meta_tp->copied_seq = meta_tp->rcv_nxt = meta_tp->rcv_wup = 0;
	meta_tp->snd_sml = meta_tp->snd_una = meta_tp->snd_nxt = 0;
	meta_tp->write_seq = 0;
	meta_tp->packets_out = 0;
	meta_tp->snt_isn = meta_tp->write_seq; /* Initial data-sequence-number */
	meta_tp->window_clamp = tcp_sk(master_sk)->window_clamp;
	meta_tp->rcv_ssthresh = tcp_sk(master_sk)->rcv_ssthresh;
	meta_icsk->icsk_probes_out = 0;

	meta_tp->mss_cache = mptcp_sysctl_mss();

	meta_tp->mpcb = mpcb;
	meta_tp->mpc = 1;
	meta_tp->attached = 0;

	skb_queue_head_init(&mpcb->reinject_queue);
	skb_queue_head_init(&meta_tp->out_of_order_queue);

	/* Redefine function-pointers to wake up application */
	master_sk->sk_error_report = mptcp_sock_def_error_report;
	meta_sk->sk_error_report = mptcp_sock_def_error_report;

	/* Init the accept_queue structure, we support a queue of 4 pending
	 * connections, it does not need to be huge, since we only store
	 * here pending subflow creations.
	 */
	reqsk_queue_alloc(&meta_icsk->icsk_accept_queue, 32, GFP_ATOMIC);

	/* Store the keys and generate the peer's token */
	mpcb->mptcp_loc_key = master_tp->mptcp_loc_key;
	mpcb->mptcp_loc_token = master_tp->mptcp_loc_token;

	mpcb->rx_opt.mptcp_rem_key = meta_tp->mptcp_rem_key;
	mptcp_key_sha1(mpcb->rx_opt.mptcp_rem_key, &mpcb->rx_opt.mptcp_rem_token);

	/* Pi 1 is reserved for the master subflow */
	mpcb->next_unused_pi = 2;
	master_tp->path_index = 1;
	master_tp->mpcb = mpcb;
	mpcb->master_sk = master_sk;

	/* Meta-level retransmit timer */
	meta_icsk->icsk_rto *= 2; /* Double of master - rto */
	tcp_init_xmit_timers(meta_sk);

	/* Adding the mpcb in the token hashtable */
	mptcp_hash_insert(mpcb, mpcb->mptcp_loc_token);

	mptcp_mpcb_inherit_sockopts(meta_sk, master_sk);

	mptcp_debug("%s: created mpcb with token %#x\n",
		    __func__, mpcb->mptcp_loc_token);

	return 0;
}

void mptcp_release_mpcb(struct multipath_pcb *mpcb)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb);

	/* Must have been destroyed previously */
	if (!sock_flag(meta_sk, SOCK_DEAD)) {
		printk(KERN_ERR "%s Trying to free mpcb %#x without having "
		       "called mptcp_destroy_mpcb()\n",
		       __func__, mpcb->mptcp_loc_token);
		BUG();
	}

	/* Ensure that all queues are empty. Later, we can find more
	 * appropriate places to do this, maybe reusing existing code.
	 * But this at least ensures that we are safe when destroying
	 * the mpcb.
	 */
	tcp_write_queue_purge(meta_sk);
	mptcp_purge_ofo_queue(tcp_sk(meta_sk));
	sk_stream_kill_queues(meta_sk);

	inet_csk(meta_sk)->icsk_pending = 0;
	sk_stop_timer(meta_sk, &inet_csk(meta_sk)->icsk_retransmit_timer);

	mptcp_pm_release(mpcb);
	security_sk_free(meta_sk);
	percpu_counter_dec(meta_sk->sk_prot->orphan_count);

	mptcp_debug("%s: Will free mpcb %#x\n", __func__, mpcb->mptcp_loc_token);
	kmem_cache_free(mpcb_cache, mpcb);
}

void mptcp_release_sock(struct sock *sk)
{
	struct sock *sk_it;
	struct tcp_sock *tp_it;
	struct multipath_pcb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *meta_sk = (struct sock *)mpcb;

	/* We need to do the following, because as far
	 * as the master-socket is locked, every received segment is
	 * put into the backlog queue.
	 */
	while (meta_sk->sk_backlog.tail ||
	       mptcp_test_any_sk(mpcb, sk_it, sk_it->sk_backlog.tail)) {
		/* process incoming join requests */
		if (meta_sk->sk_backlog.tail)
			__release_sock(meta_sk, mpcb);

		mptcp_for_each_sk(mpcb, sk_it, tp_it) {
			if (sk_it->sk_backlog.tail)
				__release_sock(sk_it, mpcb);
		}
	}
}

static void mptcp_destroy_mpcb(struct multipath_pcb *mpcb)
{
	/* Detach the mpcb from the token hashtable */
	mptcp_hash_remove(mpcb);
}

void mptcp_add_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb);
	struct sock *sk = (struct sock *) tp;

	/* We should not add a non-mpc socket */
	BUG_ON(!tp->mpc);

	tp->mpcb = mpcb;

	/* The corresponding sock_put is in inet_sock_destruct(). It cannot be
	 * included in mptcp_del_sock(), because the mpcb must remain alive
	 * until the last subsocket is completely destroyed. */
	sock_hold(meta_sk);

	tp->next = mpcb->connection_list;
	mpcb->connection_list = tp;
	tp->attached = 1;

	mpcb->cnt_subflows++;
	mptcp_update_window_clamp(tcp_sk(meta_sk));
	atomic_add(atomic_read(&((struct sock *)tp)->sk_rmem_alloc),
		   &meta_sk->sk_rmem_alloc);

	/* The socket is already established if it was in the
	 * accept queue of the mpcb
	 */
	if (sk->sk_state == TCP_ESTABLISHED) {
		mpcb->cnt_established++;
		mptcp_update_sndbuf(mpcb);
		if ((1 << meta_sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV))
			meta_sk->sk_state = TCP_ESTABLISHED;
	}

	mptcp_sub_inherit_sockopts(meta_sk, sk);

	if (sk->sk_family == AF_INET)
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI4:%d dst_addr:"
				"%pI4:%d, cnt_subflows now %d\n", __func__ ,
				mpcb->mptcp_loc_token,
				tp->path_index,
				&((struct inet_sock *) tp)->inet_saddr,
				ntohs(((struct inet_sock *) tp)->inet_sport),
				&((struct inet_sock *) tp)->inet_daddr,
				ntohs(((struct inet_sock *) tp)->inet_dport),
				mpcb->cnt_subflows);
	else
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI6:%d dst_addr:"
				"%pI6:%d, cnt_subflows now %d\n", __func__ ,
				mpcb->mptcp_loc_token,
				tp->path_index, &inet6_sk(sk)->saddr,
				ntohs(((struct inet_sock *) tp)->inet_sport),
				&inet6_sk(sk)->daddr,
				ntohs(((struct inet_sock *) tp)->inet_dport),
				mpcb->cnt_subflows);
}

void mptcp_del_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk), *tp_prev;
	struct multipath_pcb *mpcb;
	int done = 0;

	/* Need to check for protocol here, because we may enter here for
	 * non-tcp sockets. (coming from inet_csk_destroy_sock) */
	if (sk->sk_type != SOCK_STREAM || sk->sk_protocol != IPPROTO_TCP ||
	    !tp->mpc || !tp->attached)
		return;

	mpcb = tp->mpcb;
	tp_prev = mpcb->connection_list;

	mptcp_debug("%s: Removing subsock tok %#x pi:%d state %d is_meta? %d\n",
		    __func__, mpcb->mptcp_loc_token, tp->path_index,
		    sk->sk_state, is_meta_sk(sk));

	if (tp_prev == tp) {
		mpcb->connection_list = tp->next;
		mpcb->cnt_subflows--;
		done = 1;
	} else {
		for (; tp_prev && tp_prev->next; tp_prev = tp_prev->next) {
			if (tp_prev->next == tp) {
				tp_prev->next = tp->next;
				mpcb->cnt_subflows--;
				done = 1;
				break;
			}
		}
	}

	tp->next = NULL;
	tp->attached = 0;

	if (!skb_queue_empty(&sk->sk_write_queue) && mpcb->cnt_established > 0)
		mptcp_reinject_data(sk, 0);

	if (is_master_tp(tp))
		mpcb->master_sk = NULL;

	BUG_ON(!done);
}

/**
 * Updates the metasocket ULID/port data, based on the given sock.
 * The argument sock must be the sock accessible to the application.
 * In this function, we update the meta socket info, based on the changes
 * in the application socket (bind, address allocation, ...)
 */
void mptcp_update_metasocket(struct sock *sk, struct multipath_pcb *mpcb)
{
	struct sock *meta_sk;

	if (sk->sk_protocol != IPPROTO_TCP || !is_master_tp(tcp_sk(sk)))
		return;

	meta_sk = (struct sock *) mpcb;

	inet_sk(meta_sk)->inet_dport = inet_sk(sk)->inet_dport;
	inet_sk(meta_sk)->inet_sport = inet_sk(sk)->inet_sport;

	switch (sk->sk_family) {
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	case AF_INET6:
		if (!ipv6_addr_loopback(&(inet6_sk(sk))->saddr) &&
				!ipv6_addr_loopback(&(inet6_sk(sk))->daddr)) {
			mptcp_set_addresses(mpcb);
		}
		/* If the socket is v4 mapped, we continue with v4 operations */
		if (!mptcp_v6_is_v4_mapped(sk))
			break;
#endif
	case AF_INET:
		inet_sk(meta_sk)->inet_daddr = inet_sk(sk)->inet_daddr;
		inet_sk(meta_sk)->inet_saddr = inet_sk(sk)->inet_saddr;

		/* Searching for suitable local addresses,
		 * except is the socket is loopback, in which case we simply
		 * don't do multipath */
		if (!ipv4_is_loopback(inet_sk(sk)->inet_saddr) &&
			!ipv4_is_loopback(inet_sk(sk)->inet_daddr))
			mptcp_set_addresses(mpcb);
		break;
	}

	/* If this added new local addresses, build new paths with them */
	if (mpcb->num_addr4 || mpcb->num_addr6)
		mptcp_update_patharray(mpcb);
}

static inline void mptcp_become_fully_estab(struct tcp_sock *tp)
{
	tp->fully_established = 1;

	if (is_master_tp(tp))
		mptcp_send_updatenotif(tp->mpcb);
}

static void mptcp_rcv_state_process(struct sock *meta_sk,
				    const struct sk_buff *skb)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

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
			} else if (!mptcp_is_data_fin(skb)) {
				/* TODO - here we will have to move the
				 * meta-sk into TIME-WAIT. Let's wait
				 * for draft v05.
				 *
				 * In case of data-fin mptcp_fin will
				 * move the socket to tcp_done(). */
				tcp_done(meta_sk);
			}
		}
		break;
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		if (meta_tp->snd_una == meta_tp->write_seq)
			tcp_done(meta_sk);
		break;
	}
}

void mptcp_data_ack(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = mpcb_meta_sk(tp->mpcb);
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	u32 data_ack;

	/* Something got acked - subflow is operational again */
	tp->pf = 0;

	if (!(TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_ACK))
		return;

	data_ack = TCP_SKB_CB(skb)->data_ack;

	if (unlikely(!tp->fully_established) &&
	    data_ack != meta_tp->snt_isn &&
	    tp->snt_isn + 1 != tp->snd_una)
		/* As soon as data has been data-acked,
		 * or a subflow-data-ack (not acking syn - thus snt_isn + 1)
		 * includes a data-ack, we are fully established
		 */
		mptcp_become_fully_estab(tp);

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	if (before(data_ack, meta_tp->snd_una))
		return;

	/* If the ack includes data we haven't sent yet, discard
	 * this segment (RFC793 Section 3.9).
	 */
	if (after(data_ack, meta_tp->snd_nxt))
		return;

	if (after(data_ack, meta_tp->snd_una)) {
		meta_tp->snd_una = data_ack;

		mptcp_clean_rtx_queue(meta_sk);
		mptcp_rcv_state_process(mpcb_meta_sk(tp->mpcb), skb);
	}

	meta_tp->rcv_tstamp = tcp_time_stamp;
	inet_csk(meta_sk)->icsk_probes_out = 0;
}

u32 __mptcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct multipath_pcb *mpcb = tp->mpcb;
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

#ifdef CONFIG_MPTCP_DEBUG
static void mptcp_check_buffers(struct multipath_pcb *mpcb)
{
	struct sock *sk, *meta_sk = (struct sock *) mpcb;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int rcv_size = 0;

	for (skb = skb_peek(&meta_sk->sk_receive_queue); skb;
	     skb = (skb_queue_is_last(&meta_sk->sk_receive_queue, skb) ?
		    NULL :
		    skb_queue_next(&meta_sk->sk_receive_queue, skb)))
		rcv_size += skb->truesize;

	mptcp_for_each_sk(mpcb, sk, tp) {
		if (sk->sk_state != TCP_ESTABLISHED)
			continue;

		skb = skb_peek(&meta_sk->sk_receive_queue);
		mptcp_debug("pi %d, rcv_size:%d, next dsn:%#x\n",
			    tp->path_index, rcv_size,
			    (skb ? mptcp_skb_data_seq(skb) : 0));
	}
}
#endif

int mptcp_try_rmem_schedule(struct sock *sk, unsigned int size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sock *meta_tp = mpcb_meta_tp(tp->mpcb);
	struct sock *meta_sk = (struct sock *) meta_tp;
	if (atomic_read(&meta_sk->sk_rmem_alloc) >
			meta_sk->sk_rcvbuf) {
#ifdef CONFIG_MPTCP_DEBUG
		struct sk_buff *skb;
		mptcp_debug("%s: not enough rcvbuf: mpcb rcvbuf:%d,"
				"rmem_alloc:%d\n", __func__,
				meta_sk->sk_rcvbuf,
				atomic_read(&meta_sk->sk_rmem_alloc));

		mptcp_check_buffers(tp->mpcb);
		mptcp_debug("%s: mpcb copied seq:%#x\n", __func__,
				meta_tp->copied_seq);

		mptcp_for_each_sk(tp->mpcb, sk, tp) {
			if (sk->sk_state != TCP_ESTABLISHED)
				continue;
			mptcp_debug("%s: pi:%d, rcvbuf:%d, "
				"rmem_alloc:%d\n",
				__func__, tp->path_index,
				sk->sk_rcvbuf,
				atomic_read(&sk->sk_rmem_alloc));
			mptcp_debug("%s: used mss for wnd "
				"computation:%d\n",
				__func__,
				inet_csk(sk)->icsk_ack.rcv_mss);
			mptcp_debug("%s: --- receive-queue:\n",
				__func__);
			skb_queue_walk(&sk->sk_receive_queue, skb) {
				mptcp_debug("%s: dsn:%#x, skb->len:%d,"
					    "truesize:%d, "
					    "prop:%d /1000\n", __func__,
					    TCP_SKB_CB(skb)->data_seq,
					    skb->len, skb->truesize,
					    skb->len * 1000 /
					    skb->truesize);
			}
		}
		mptcp_debug("%s: --- meta-receive queue:\n",
			__func__);
		skb_queue_walk(&meta_sk->sk_receive_queue, skb) {
			mptcp_debug("%s: dsn:%#x, "
				    "skb->len:%d, truesize:%d, "
				    "prop:%d /1000\n", __func__,
				    TCP_SKB_CB(skb)->data_seq,
				    skb->len, skb->truesize,
				    skb->len * 1000 / skb->truesize);
		}
#endif /* CONFIG_MPTCP_DEBUG */
		return 0;
	} else if (!sk_rmem_schedule(sk, size)) {
		printk(KERN_ERR "impossible to alloc memory\n");
	}
	if (atomic_read(&meta_sk->sk_rmem_alloc) <= meta_sk->sk_rcvbuf
			&& sk_rmem_schedule(sk, size)) {
		return 0;
	}
	if (tcp_prune_queue(sk) < 0)
		return -1;

	if (!sk_rmem_schedule(sk, size)) {
		if (!tcp_prune_ofo_queue(sk))
			return -1;

		if (!sk_rmem_schedule(sk, size))
			return -1;
	}
	return 0;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct multipath_pcb *mpcb = meta_tp->mpcb;
	struct sock *sk, *subsk;
	struct tcp_sock *tp;
	int time_to_ack = 0;

	mptcp_for_each_sk(mpcb, sk, tp) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		if (!inet_csk_ack_scheduled(sk))
			continue;
		/* Delayed ACKs frequently hit locked sockets during bulk
		 * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 && ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2)
				|| ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED)
				&& !icsk->icsk_ack.pingpong))
				&& !atomic_read(&meta_sk->sk_rmem_alloc))) {
			time_to_ack = 1;
			tcp_send_ack(sk);
		}
	}

	if (time_to_ack)
		return;

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack
			&& !(meta_sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(meta_tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2 * rcv_window_now <= meta_tp->window_clamp) {
			__u32 new_window;
			subsk = mptcp_select_ack_sock(mpcb, copied);
			new_window = __tcp_select_window(subsk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than
			 * current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}

	if (time_to_ack) {
		if (subsk)
			tcp_send_ack(subsk);
		else
			printk(KERN_ERR "%s did not find a subsk! "
					"Should not happen.\n", __func__);
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
		if ((tp->map_data_len &&
		     !after(tp->map_subseq + tp->map_data_len, TCP_SKB_CB(tmp)->seq)) ||
		    (!tp->map_data_len && before(tp->map_subseq, TCP_SKB_CB(tmp)->seq)))
			break;

		if (before(tp->map_subseq + tp->map_data_len, TCP_SKB_CB(tmp)->end_seq))
			/* Mapping ends in the middle of the packet -
			 * csum only these bytes */
			csum_len = tp->map_subseq + tp->map_data_len -
					TCP_SKB_CB(tmp)->seq;
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

		if (TCP_SKB_CB(tmp)->dss_off && !dss_csum_added) {
			csum_tcp = skb_checksum(tmp, skb_transport_offset(tmp) +
						(TCP_SKB_CB(tmp)->dss_off << 2),
						MPTCP_SUB_LEN_SEQ_CSUM,
						csum_tcp);
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
			    TCP_SKB_CB(last)->data_seq, dss_csum_added,
			    overflowed, iter);

		tp->csum_error = 1;
		/* map_data_seq is the data-seq number of the
		 * mapping we are currently checking
		 */
		tp->mpcb->csum_cutoff_seq = tp->map_data_seq;

		if (tp->mpcb->cnt_established > 1) {
			mptcp_send_reset(sk, last);
			ans = -1;
		} else {
			tp->mpcb->send_mp_fail = 1;
			tp->copied_seq = TCP_SKB_CB(last)->end_seq;
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
	tcb->data_seq = tp->map_data_seq + tcb->seq - tp->map_subseq;
	tcb->data_len = tcb->end_seq - tcb->seq - (tcp_hdr(skb)->fin ? 1: 0);
	tcb->sub_seq = tcb->seq;
	tcb->end_data_seq = tcb->data_seq + tcb->data_len;

	/* If cur is the last one in the rcv-queue (or the last one for this
	 * mapping), and data_fin is enqueued, the end_data_seq is +1 */
	if (skb_queue_is_last(&sk->sk_receive_queue, skb) ||
	    after(TCP_SKB_CB(next)->end_seq, tp->map_subseq + tp->map_data_len))
		tcb->end_data_seq += tp->map_data_fin;
}

/**
 * @return: 1 if the segment has been eaten and can be suppressed,
 *          otherwise 0.
 */
static inline int direct_copy(struct sk_buff *skb, struct tcp_sock *tp,
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
	tp->map_data_len = 0;
	tp->map_data_seq = 0;
	tp->map_subseq = 0;
	tp->map_data_fin = 0;
	tp->mapping_present = 0;
}

/* The DSS-mapping received on the sk only covers the second half of the skb
 * (cut at seq). We trim the head from the skb.
 * Data will be freed upon kfree().
 *
 * Inspired by tcp_trim_head().
 */
static void mptcp_skb_trim_head(struct sk_buff *skb, struct sock *sk, u32 seq)
{
	int len = seq - TCP_SKB_CB(skb)->seq;

	if (len < skb_headlen(skb))
		__skb_pull(skb, len);
	else
		__pskb_trim_head(skb, len - skb_headlen(skb));

	TCP_SKB_CB(skb)->seq += len;

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

	len = seq - TCP_SKB_CB(skb)->seq;
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
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;
	TCP_SKB_CB(skb)->flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->flags = flags;

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
 *  i) 1: the segment can be destroyed by the caller
 *  ii) -1: A reset has been sent on the subflow
 *  iii) 0: The segment has been enqueued.
 */
int mptcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct multipath_pcb *mpcb = mpcb_from_tcpsock(tcp_sk(sk));
	struct sock *meta_sk = (struct sock *) mpcb;
	struct tcp_sock *tp = tcp_sk(sk), *meta_tp = tcp_sk(meta_sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	struct sk_buff *tmp, *tmp1;
	u32 old_copied = tp->copied_seq;
	int ans = 0;

	if (meta_sk->sk_state == TCP_CLOSE)
		return 1;

	if (!skb->len && tcp_hdr(skb)->fin && !mptcp_is_data_fin(skb)) {
		/* Pure subflow FIN (without DFIN)
		 * just update subflow and return
		 */
		tp->copied_seq++;
		return 1;
	}

	/* If we are not yet fully established and do not know the mapping for
	 * this segment, this path has to fallback to infinite or be torn down.
	 */
	if (!tp->fully_established && !(tcb->mptcp_flags & MPTCPHDR_SEQ) &&
	    !tp->mapping_present) {
		int ret = mptcp_fallback_infinite(tp, skb);

		if (ret & MPTCP_FLAG_SEND_RESET) {
			mptcp_send_reset(sk, skb);
			return -1;
		} else {
			mpcb->infinite_mapping = 1;
			tp->fully_established = 1;
		}
	}

	/* Receiver-side becomes fully established when a whole rcv-window has
	 * been received without the need to fallback due to the previous
	 * condition. */
	if (!tp->fully_established) {
		tp->init_rcv_wnd -= skb->len;
		if (tp->init_rcv_wnd < 0)
			mptcp_become_fully_estab(tp);
	}

	/* If we are in infinite-mapping-mode, the subflow is guaranteed to be
	 * in-order at the data-level. Thus data-seq-numbers can be inferred
	 * from what is expected at the data-level.
	 *
	 * draft v04, Section 3.5
	 */
	if (mpcb->infinite_mapping) {
		tp->map_data_seq = tcb->data_seq = meta_tp->rcv_nxt;
		tp->map_subseq = tcb->sub_seq = tcb->seq;
		tp->map_data_len = tcb->data_len = skb->len;
		tp->mapping_present = 1;
		tcb->end_data_seq = tcb->data_seq + tcb->data_len;
	}

	/* If there is a DSS-mapping, check if it is ok with the current
	 * expected mapping. If anything is wrong, reset the subflow
	 */
	if (tcb->mptcp_flags & MPTCPHDR_SEQ && !mpcb->infinite_mapping) {
		if (!tcb->data_len) {
			mpcb->infinite_mapping = 1;
			tp->fully_established = 1;
			/* We need to repeat mp_fail's until the sender felt
			 * back to infinite-mapping - here we stop repeating it.
			 */
			mpcb->send_mp_fail = 0;
			tcb->data_len = skb->len;
			tcb->sub_seq = tcb->seq;
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
		if (mpcb->send_mp_fail)
			return 1;

		/* FIN increased the mapping-length by 1 */
		if (mptcp_is_data_fin(skb))
			tcb->data_len--;

		if (tp->mapping_present &&
		    (tcb->data_seq != tp->map_data_seq ||
		     tcb->sub_seq != tp->map_subseq ||
		     tcb->data_len != tp->map_data_len)) {
			/* Mapping in packet is different from what we want */
			mptcp_debug("%s destroying subflow with pi %d from mpcb "
				    "with token %#x\n", __func__,
				    tp->path_index, mpcb->mptcp_loc_token);
			mptcp_debug("%s missing rest of the already present "
				    "mapping: data_seq %u, subseq %u, data_len "
				    "%u - new mapping: data_seq %u, subseq %u, "
				    "data_len %u\n", __func__, tp->map_data_seq,
				    tp->map_subseq, tp->map_data_len,
				    tcb->data_seq, tcb->sub_seq, tcb->data_len);
			mptcp_send_reset(sk, skb);
			__kfree_skb(skb);
			return -1;
		}

		if (!tp->mapping_present) {
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
			if ((!before(tcb->sub_seq, tcb->end_seq) && after(tcb->end_seq, tcb->seq)) ||
			    (mptcp_is_data_fin(skb) && skb->len == 0 && after(tcb->sub_seq, tcb->end_seq)) ||
			    before(tcb->sub_seq + tcb->data_len, tcb->seq)) {
				/* Subflow-sequences of packet is different from
				 * what is in the packet's dss-mapping.
				 * The peer is misbehaving - reset
				 */
				mptcp_debug("%s destroying subflow with pi %d "
					    "from mpcb with token %#x\n",
					    __func__, tp->path_index,
					    mpcb->mptcp_loc_token);
				mptcp_debug("%s seq %u end_seq %u, sub_seq %u "
					    "data_len %u\n", __func__,
					    tcb->seq, tcb->end_seq,
					    tcb->sub_seq, tcb->data_len);
				mptcp_send_reset(sk, skb);
				return 1;
			}

			tp->map_data_seq = tcb->data_seq;
			tp->map_data_len = tcb->data_len;
			tp->map_subseq = tcb->sub_seq;
			tp->map_data_fin = mptcp_is_data_fin(skb) ? 1 : 0;
			tp->mapping_present = 1;
		}
	}

	/* The skb goes into the sub-rcv queue in all cases.
	 * This allows more generic skb management in the next lines although
	 * it may be removed in few lines (direct copy to the app).
	 */
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	skb_set_owner_r(skb, sk);

	/* If the mapping is known, we have to split coalesced segments */
	if (tp->mapping_present) {
		int sub_end_seq;
		/* either, the new skb gave us the mapping and the first segment
		 * in the sub-rcv-queue has to be split, or the new skb (tail)
		 * has to be split at the end.
		 */
		tmp = skb_peek(&sk->sk_receive_queue);
		if (before(TCP_SKB_CB(tmp)->seq, tp->map_subseq) &&
		    after(TCP_SKB_CB(tmp)->end_seq, tp->map_subseq)) {
			mptcp_skb_trim_head(tmp, sk, tp->map_subseq);
		}

		sub_end_seq = TCP_SKB_CB(skb)->end_seq -
				(tcp_hdr(skb)->fin ? 1 : 0);

		if (after(sub_end_seq, tp->map_subseq + tp->map_data_len)) {
			int ret;
			ret = mptcp_skb_split_tail(skb, sk,
					tp->map_subseq + tp->map_data_len);
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

	tp->rcv_nxt = TCP_SKB_CB(skb_peek_tail(&sk->sk_receive_queue))->end_seq;

	/* Now, remove old sk_buff's from the receive-queue.
	 * This may happen if the mapping has been lost for these segments and
	 * the next mapping has already been received.
	 */
	if (tp->mapping_present &&
	    before(TCP_SKB_CB(skb_peek(&sk->sk_receive_queue))->seq, tp->map_subseq)) {
		mptcp_debug("%s remove packets not covered by mapping: "
			    "data_len %u, tp->copied_seq %u, "
			    "tp->map_subseq %u\n", __func__,
			    tp->map_data_len, tp->copied_seq,
			    tp->map_subseq);
		skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
			if (!before(TCP_SKB_CB(tmp1)->seq, tp->map_subseq)) {
				mptcp_debug("%s Not removing packet seq %u, "
					    "end_seq %u\n", __func__,
					    TCP_SKB_CB(tmp1)->seq,
					    TCP_SKB_CB(tmp1)->end_seq);
				break;
			}
			mptcp_debug("%s remove packet seq %u, end_seq %u\n",
				    __func__, TCP_SKB_CB(tmp1)->seq,
				    TCP_SKB_CB(tmp1)->end_seq);
			__skb_unlink(tmp1, &sk->sk_receive_queue);

			tp->copied_seq = TCP_SKB_CB(tmp1)->end_seq;

			/* Impossible that we could free skb here, because his
			 * mapping is known to be valid from previous checks
			 */
			__kfree_skb(tmp1);
		}
	}

	/* Have we received the full mapping ? Then push further */
	if (tp->mapping_present &&
	    !before(tp->rcv_nxt, tp->map_subseq + tp->map_data_len)) {
		/* Is this an overlapping mapping? rcv_nxt >= end_data_seq */
		if (!before(meta_tp->rcv_nxt, tp->map_data_seq +
			    tp->map_data_len + tp->map_data_fin)) {
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				/* seq >= end_sub_mapping if data_len OR
				 * seq > end_sub_mapping if not data_len
				 * (data_fin without data)
				 */
				if ((tp->map_data_len && !before(TCP_SKB_CB(tmp1)->seq,
						tp->map_subseq + tp->map_data_len)) ||
				    (!tp->map_data_len && after(TCP_SKB_CB(tmp1)->seq,
						tp->map_subseq + tp->map_data_len)))
					break;
				__skb_unlink(tmp1, &sk->sk_receive_queue);

				tp->copied_seq = TCP_SKB_CB(tmp1)->end_seq;

				if (mptcp_is_data_fin(tmp1))
					mptcp_fin(mpcb, sk);

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

		if (before(meta_tp->rcv_nxt, tp->map_data_seq)) {
			/* Seg's have to go to the meta-ofo-queue */
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				if (after(TCP_SKB_CB(tmp1)->end_seq,
					  tp->map_subseq + tp->map_data_len + tp->map_data_fin))
					break;

				mptcp_prepare_skb(tmp1, tmp, sk);

				__skb_unlink(tmp1, &sk->sk_receive_queue);
				tp->copied_seq = TCP_SKB_CB(tmp1)->end_seq;
				skb_set_owner_r(tmp1, meta_sk);

				if (mptcp_add_meta_ofo_queue(meta_sk, tmp1,
							     sk)) {
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
				if (after(TCP_SKB_CB(tmp1)->end_seq,
					  tp->map_subseq + tp->map_data_len + tp->map_data_fin)) {
					break;
				}

				mptcp_prepare_skb(tmp1, tmp, sk);

				/* Is direct copy possible ? */
				if (TCP_SKB_CB(tmp1)->data_seq ==
				    meta_tp->rcv_nxt &&
				    meta_tp->ucopy.task == current &&
				    meta_tp->copied_seq == meta_tp->rcv_nxt &&
				    meta_tp->ucopy.len &&
				    sock_owned_by_user(meta_sk)) {
					eaten = direct_copy(tmp1, tp, meta_tp);
				}
				meta_tp->rcv_nxt =
					TCP_SKB_CB(tmp1)->end_data_seq;

				tp->copied_seq = TCP_SKB_CB(tmp1)->end_seq;

				if (mptcp_is_data_fin(tmp1)) {
					/* If mptcp_fin tcp_done'd the meta_sk,
					 * he flushed the rcv-queue. However,
					 * tcp_data_queue() may still need the
					 * skb.
					 * Thus, we skip the rest of
					 * mptcp_queue_skb and exit.
					 */
					if (mptcp_fin(mpcb, sk)) {
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
				}
			}
			if (!sock_flag(meta_sk, SOCK_DEAD))
				sk->sk_data_ready(sk, 0);
		}

rcvd_fin:
		inet_csk(meta_sk)->icsk_ack.lrcvtime = tcp_time_stamp;
		tp->last_data_seq = tp->map_data_seq;
		mptcp_reset_mapping(tp);
	}

exit:
	if (old_copied != tp->copied_seq)
		tcp_rcv_space_adjust(sk);

	return ans;
}

void mptcp_skb_entail_init(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* in MPTCP mode, the subflow seqnum is given later */
	if (tp->mpc) {
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
		struct multipath_pcb *mpcb = mpcb_from_tcpsock(tp);
		struct tcp_sock *meta_tp = (struct tcp_sock *)mpcb;
		tcb->seq      = tcb->end_seq = tcb->sub_seq = 0;
		tcb->data_seq = tcb->end_data_seq = meta_tp->write_seq;
		tcb->data_len = 0;
		tcb->mptcp_flags = MPTCPHDR_SEQ;
	}
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
void mptcp_skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	int fin = (tcb->flags & TCPHDR_FIN) ? 1 : 0;

	tcb->seq = tp->write_seq;
	tcb->sub_seq = tcb->seq - tp->snt_isn;
	tcb->sacked = 0; /* reset the sacked field: from the point of view
			  * of this subflow, we are sending a brand new
			  * segment
			  */
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);

	/* Calculate dss-csum */
	if (tp->mpc && tp->mpcb->rx_opt.dss_csum) {
		char mptcp_pshdr[MPTCP_SUB_LEN_SEQ_CSUM];
		__be32 data_seq = htonl(tcb->data_seq);
		__be32 sub_seq = htonl(tcb->sub_seq);
		__be16 data_len = htons(tcb->data_len);

		memcpy(&mptcp_pshdr[0], &data_seq, 4);
		memcpy(&mptcp_pshdr[4], &sub_seq, 4);
		memcpy(&mptcp_pshdr[8], &data_len, 2);
		memset(&mptcp_pshdr[10], 0, 2);

		tcb->dss_csum = csum_fold(csum_partial(mptcp_pshdr,
					     MPTCP_SUB_LEN_SEQ_CSUM,
					     skb->csum));
	}

	/* Take into account seg len */
	tp->write_seq += skb->len + fin;
	tcb->end_seq = tp->write_seq;
}

void mptcp_combine_dfin(struct sk_buff *skb, struct tcp_sock *meta_tp,
			struct sock *subsk)
{
	struct sock *sk_it;
	struct tcp_sock *tp_it;
	int all_empty = 1, all_acked = 1;

	/* If no other subflow still has data to send, we can combine */
	mptcp_for_each_sk(meta_tp->mpcb, sk_it, tp_it) {
		if (!tcp_write_queue_empty(sk_it))
			all_empty = 0;
	}

	/* If all data has been DATA_ACKed, we can combine
	 * -1, because the data_fin consumed one byte
	 */
	if (meta_tp->snd_una != meta_tp->write_seq - 1)
		all_acked = 0;

	if ((all_empty || all_acked) && tcp_close_state(subsk)) {
		TCP_SKB_CB(skb)->flags |= TCPHDR_FIN;
	}
}

void mptcp_set_data_size(struct tcp_sock *tp, struct sk_buff *skb, int copy)
{
	if (tp->mpc) {
		TCP_SKB_CB(skb)->data_len += copy;
		TCP_SKB_CB(skb)->end_data_seq += copy;
	}
}

int mptcp_push(struct sock *sk, int flags, int mss_now, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = (tp->mpc) ? (struct sock *) (tp->mpcb) : sk;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	if (mptcp_next_segment(meta_sk, NULL)) {
		struct sk_buff *skb = tcp_write_queue_tail(meta_sk);
		if (!skb)
			skb = skb_peek_tail(&tp->mpcb->reinject_queue);

		if (!(flags & MSG_MORE) || forced_push(meta_tp))
			tcp_mark_push(meta_tp, skb);
		tcp_mark_urg(meta_tp, flags);
		__tcp_push_pending_frames(meta_sk, mss_now,
					  (flags & MSG_MORE) ?
					  TCP_NAGLE_CORK : nonagle);
	}
	return 1;
}

void mptcp_parse_options(uint8_t *ptr, int opsize,
		struct tcp_options_received *opt_rx,
		struct multipath_options *mopt,
		struct sk_buff *skb)
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

		opt_rx->saw_mpc = 1;
		mopt->list_rcvd = 1;
		mopt->dss_csum = sysctl_mptcp_checksum || mpcapable->c;
		mopt->mptcp_opt_type = MPTCP_MP_CAPABLE_TYPE_SYN;

		if (opsize >= MPTCP_SUB_LEN_CAPABLE_SYN) {
			ptr += 2;
			mopt->mptcp_rem_key = *((__u64*)ptr);
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
				mopt->mptcp_rem_token = *((u32*)(ptr + 2));
				mopt->mptcp_recv_random_number = *((u32*)(ptr + 6));
				mopt->mptcp_opt_type = MPTCP_MP_JOIN_TYPE_SYN;
				opt_rx->saw_mpc = 1;
				break;
			case MPTCP_SUB_LEN_JOIN_SYNACK:
				ptr += 2;
				mopt->mptcp_recv_tmac = *((__u64 *)ptr);
				ptr += 8;
				mopt->mptcp_recv_random_number = *((u32 *)ptr);
				mopt->mptcp_opt_type = MPTCP_MP_JOIN_TYPE_SYNACK;
				break;
			case MPTCP_SUB_LEN_JOIN_ACK:
				ptr += 2;
				memcpy(mopt->mptcp_recv_mac, ptr, 20);
				mopt->mptcp_opt_type = MPTCP_MP_JOIN_TYPE_ACK;
				break;
		}
		opt_rx->rem_id = mpjoin->addr_id;
		break;
	}
	case MPTCP_SUB_DSS:
	{
		struct mp_dss *mdss = (struct mp_dss *) ptr;

		ptr += 2;

		if (mdss->A) {
			TCP_SKB_CB(skb)->data_ack = get_unaligned_be32(ptr);
			TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_ACK;
			ptr += MPTCP_SUB_LEN_ACK;
		}

		if (mdss->M) {
			/* TODO_cpaasch check for the correct length of the DSS
			 * option */
			if (mopt && mopt->dss_csum) {
				TCP_SKB_CB(skb)->dss_off =
					(ptr - skb_transport_header(skb)) >> 2;
			} else {
				TCP_SKB_CB(skb)->dss_off = 0;
			}
			TCP_SKB_CB(skb)->data_seq = get_unaligned_be32(ptr);
			TCP_SKB_CB(skb)->sub_seq = get_unaligned_be32(ptr + 4) +
						   opt_rx->rcv_isn;
			TCP_SKB_CB(skb)->data_len = get_unaligned_be16(ptr + 8);
			TCP_SKB_CB(skb)->end_data_seq =
				TCP_SKB_CB(skb)->data_seq +
				TCP_SKB_CB(skb)->data_len;
			TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_SEQ;

			ptr += MPTCP_SUB_LEN_SEQ;
		}

		if (mdss->F)
			TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN;

		break;
	}
	case MPTCP_SUB_ADD_ADDR:
	{
		struct mp_add_addr *mpadd = (struct mp_add_addr *) ptr;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if ((mpadd->ipver == 4 && opsize != MPTCP_SUB_LEN_ADD_ADDR4 &&
		     opsize != MPTCP_SUB_LEN_ADD_ADDR4 + 2) ||
		    (mpadd->ipver == 6 && opsize != MPTCP_SUB_LEN_ADD_ADDR6 &&
		     opsize != MPTCP_SUB_LEN_ADD_ADDR6 + 2)) {
#else
		if (opsize != MPTCP_SUB_LEN_ADD_ADDR4 &&
		    opsize != MPTCP_SUB_LEN_ADD_ADDR4 + 2) {
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
			mptcp_debug("%s: mp_add_addr: bad option size %d\n",
					__func__, opsize);
			break;
		}

		ptr += 2; /* Move the pointer to the addr */
		if (mpadd->ipver == 4) {
			__be16 port = 0;
			if (opsize == MPTCP_SUB_LEN_ADD_ADDR4 + 2)
				port = (__be16) *(ptr + 4);

			mptcp_v4_add_raddress(mopt, (struct in_addr *) ptr,
					port, mpadd->addr_id);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		} else if (mpadd->ipver == 6) {
			__be16 port = 0;
			if (opsize == MPTCP_SUB_LEN_ADD_ADDR6 + 2)
				port = (__be16) *(ptr + 16);

			mptcp_v6_add_raddress(mopt, (struct in6_addr *) ptr,
					port, mpadd->addr_id);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
		}
		break;
	}
	case MPTCP_SUB_FAIL:
		mopt->mp_fail = 1;
		break;
	default:
		mptcp_debug("%s: Received unkown subtype: %d\n", __func__,
				mp_opt->sub);
		break;
	}
}

void mptcp_syn_options(struct sock *sk, struct tcp_out_options *opts,
		       unsigned *remaining)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (is_master_tp(tp)) {
		opts->options |= OPTION_MP_CAPABLE;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
		opts->sender_key = tp->mptcp_loc_key;
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
		struct multipath_pcb *mpcb = mpcb_from_tcpsock(tp);

		opts->options |= OPTION_MP_JOIN;
		*remaining -= MPTCP_SUB_LEN_JOIN_ALIGN_SYN;
		opts->token = mpcb->rx_opt.mptcp_rem_token;
		opts->addr_id = mptcp_get_loc_addrid(mpcb, sk);

		if (!tp->mptcp_loc_random_number)
			get_random_bytes(&tp->mptcp_loc_random_number, 4);

		opts->sender_random_number = tp->mptcp_loc_random_number;
		opts->mp_join_type = MPTCP_MP_JOIN_TYPE_SYN;
	}
}

void mptcp_synack_options(struct request_sock *req,
			  struct tcp_out_options *opts,
			  unsigned *remaining)
{
	/* MPCB not yet set - thus it's a new MPTCP-session */
	if (!req->mpcb) {
		opts->options |= OPTION_MP_CAPABLE;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
		opts->sender_key = req->mptcp_loc_key;
		opts->dss_csum = sysctl_mptcp_checksum || req->dss_csum;
	} else {
		struct inet_request_sock *ireq = inet_rsk(req);
		int i;

		opts->options |= OPTION_MP_JOIN;
		opts->sender_truncated_mac = req->mptcp_hash_tmac;
		opts->sender_random_number = req->mptcp_loc_random_number;
		opts->mp_join_type = MPTCP_MP_JOIN_TYPE_SYNACK;
		opts->addr_id = 0;

		/* Finding Address ID */
		if (req->rsk_ops->family == AF_INET)
			for (i = 0; i < req->mpcb->num_addr4; i++) {
				if (req->mpcb->addr4[i].addr.s_addr == ireq->loc_addr)
					opts->addr_id = req->mpcb->addr4[i].id;
			}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else /* IPv6 */
			for (i = 0; i < req->mpcb->num_addr6; i++) {
				if (ipv6_addr_equal(&req->mpcb->addr6[i].addr,
						&inet6_rsk(req)->loc_addr))
					opts->addr_id = req->mpcb->addr6[i].id;
			}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
		*remaining -= MPTCP_SUB_LEN_JOIN_ALIGN_SYNACK;
	}
}

void mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       struct tcp_out_options *opts, unsigned *size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct multipath_pcb *mpcb = tp->mpcb;
	struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;

	/* In fallback mp_fail-mode, we have to repeat it until the fallback
	 * has been done by the sender
	 */
	if (mpcb->send_mp_fail) {
		opts->options |= OPTION_MP_FAIL;
		opts->data_ack = mpcb->csum_cutoff_seq;
		*size += MPTCP_SUB_LEN_FAIL;
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
	if (mpcb->infinite_mapping && tp->fully_established &&
	    ((mpcb->send_infinite_mapping && !(tcb->mptcp_flags & MPTCPHDR_INF) &&
	      !before(tcb->seq, tp->infinite_cutoff_seq)) ||
	     !mpcb->send_infinite_mapping)) {
		return;
	}

	if (tcb && unlikely(tp->include_mpc)) {
		if (is_master_tp(tp)) {
			opts->options |= OPTION_MP_CAPABLE;
			*size += MPTCP_SUB_LEN_CAPABLE_ALIGN_ACK;
			opts->sender_key = mpcb->mptcp_loc_key;
			opts->receiver_key = mpcb->rx_opt.mptcp_rem_key;
			opts->dss_csum = mpcb->rx_opt.dss_csum;
		} else {
			opts->options |= OPTION_MP_JOIN;
			*size += MPTCP_SUB_LEN_JOIN_ALIGN_ACK;
			opts->mp_join_type = MPTCP_MP_JOIN_TYPE_ACK;

			mptcp_hmac_sha1((u8 *)&mpcb->mptcp_loc_key,
					(u8 *)&mpcb->rx_opt.mptcp_rem_key,
					(u8 *)&tp->mptcp_loc_random_number,
					(u8 *)&mpcb->rx_opt.mptcp_recv_random_number,
					(u32 *)opts->sender_mac);
		}
		tp->include_mpc = 0;
		return;
	}

	if (!tp->mptcp_add_addr_ack && !tp->include_mpc) {
		int dss = 0;

		if (1/* data_to_ack */ ) {
			dss = 1;

			opts->data_ack = mpcb_meta_tp(mpcb)->rcv_nxt;
			opts->options |= OPTION_DATA_ACK;
			*size += MPTCP_SUB_LEN_ACK_ALIGN;
		}

		if (!skb || skb->len != 0 || mptcp_is_data_fin(skb)) {
			dss = 1;

			/* Send infinite mapping only on "new" data,
			 * not for retransmissions */
			if (mpcb->send_infinite_mapping &&
			    tcb->seq >= tp->snd_nxt) {
				tp->fully_established = 1;
				mpcb->infinite_mapping = 1;
				tp->infinite_cutoff_seq = tcb->seq;
				tcb->mptcp_flags |= MPTCPHDR_INF;
				tcb->data_len = 0;
			}

			if (tcb) {
				opts->data_seq = tcb->data_seq;
				opts->data_len = tcb->data_len;
				opts->sub_seq = tcb->sub_seq;
				if (mpcb->rx_opt.dss_csum)
					opts->dss_csum = tcb->dss_csum;
				else
					opts->dss_csum = 0;
			}
			opts->options |= OPTION_DSN_MAP;
			/* Doesn't matter, if csum included or not. It will be
			 * either 10 or 12, and thus aligned = 12 */
			*size += MPTCP_SUB_LEN_SEQ_ALIGN;
		}

		if (skb && mptcp_is_data_fin(skb)) {
			dss = 1;
			opts->options |= OPTION_DATA_FIN;
		}

		if (dss)
			*size += MPTCP_SUB_LEN_DSS_ALIGN;
	}

	if (unlikely(mpcb->addr4_unsent) &&
			MAX_TCP_OPTION_SPACE - *size >=
			MPTCP_SUB_LEN_ADD_ADDR4_ALIGN) {
		opts->options |= OPTION_ADD_ADDR;
		opts->addr4 = mpcb->addr4 + mpcb->num_addr4 -
				mpcb->addr4_unsent;
		opts->addr6 = NULL;
		if (skb)
			mpcb->addr4_unsent--;
		*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN;
	} else if (unlikely(mpcb->addr6_unsent) &&
		 MAX_TCP_OPTION_SPACE - *size >=
		 MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) {
		opts->options |= OPTION_ADD_ADDR;
		opts->addr6 = mpcb->addr6 + mpcb->num_addr6 -
				mpcb->addr6_unsent;
		opts->addr4 = NULL;
		if (skb)
			mpcb->addr6_unsent--;
		*size += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN;
	} else if (!(opts->options & OPTION_MP_CAPABLE) &&
		    !(opts->options & OPTION_MP_JOIN) &&
		    ((unlikely(mpcb->addr6_unsent) &&
		    MAX_TCP_OPTION_SPACE - *size <=
		    MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) ||
		    (unlikely(mpcb->addr4_unsent) &&
		    MAX_TCP_OPTION_SPACE - *size >=
		    MPTCP_SUB_LEN_ADD_ADDR4_ALIGN))) {
		mptcp_debug("no space for add addr. unsent IPv4: %d,"
				"IPv6: %d\n",
				mpcb->addr4_unsent, mpcb->addr6_unsent);
		tp->mptcp_add_addr_ack = 1;
		tcp_send_ack(sk);
		tp->mptcp_add_addr_ack = 0;
	}
}

void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			 struct tcp_out_options *opts)
{
	if (unlikely(OPTION_MP_CAPABLE & opts->options)) {
		struct mp_capable *mpc;
		__u8 *p8 = (__u8 *)ptr;
		__u64 *p64;

		*p8++ = TCPOPT_MPTCP;

		if (!opts->receiver_key)
			*p8++ = MPTCP_SUB_LEN_CAPABLE_SYN;
		else
			*p8++ = MPTCP_SUB_LEN_CAPABLE_ACK;

		mpc = (struct mp_capable *)p8;

		mpc->sub = MPTCP_SUB_CAPABLE;
		mpc->ver = 0;
		mpc->c = opts->dss_csum ? 1 : 0;
		mpc->rsv = 0;
		mpc->s = 1;

		ptr++;
		p64 = (__u64 *)ptr;

		if (opts->sender_key) {
			*p64++ = opts->sender_key;
			ptr += 2;
		}

		if (opts->receiver_key) {
			*p64 = opts->receiver_key;
			ptr += 2;
		}
	}

	if (unlikely(OPTION_MP_JOIN & opts->options)) {
		struct mp_join *mpj;
		__u8 *p8 = (__u8 *)ptr;

		*p8++ = TCPOPT_MPTCP;

		switch (opts->mp_join_type) {
			case MPTCP_MP_JOIN_TYPE_SYN:
				*p8++ = MPTCP_SUB_LEN_JOIN_SYN;
				break;
			case MPTCP_MP_JOIN_TYPE_SYNACK:
				*p8++ = MPTCP_SUB_LEN_JOIN_SYNACK;
				break;
			case MPTCP_MP_JOIN_TYPE_ACK:
				*p8++ = MPTCP_SUB_LEN_JOIN_ACK;
				break;
			default:
				*p8++ = MPTCP_SUB_LEN_JOIN_ACK;
				break;
		}

		mpj = (struct mp_join *)p8;

		mpj->sub = MPTCP_SUB_JOIN;
		mpj->rsv = 0;
		mpj->b = 0;
		mpj->addr_id = opts->addr_id;

		switch (opts->mp_join_type) {
			case MPTCP_MP_JOIN_TYPE_SYN:
				ptr++;
				*ptr++ = opts->token;
				*ptr++ = opts->sender_random_number;
				break;
			case MPTCP_MP_JOIN_TYPE_SYNACK:
			{
				__u64 *p64;
				ptr++;
				p64 = (__u64 *) ptr;
				*p64 = opts->sender_truncated_mac;
				ptr += 2;
				*ptr++ = opts->sender_random_number;
				break;
			}
			case MPTCP_MP_JOIN_TYPE_ACK:
				ptr++;
				memcpy(ptr, opts->sender_mac, 20);

				ptr+=5;
				break;
			default:
				ptr++;
				*ptr++ = opts->token;
				break;
		}

	}
	if (unlikely(OPTION_ADD_ADDR & opts->options)) {
		struct mp_add_addr *mpadd;
		__u8 *p8 = (__u8 *)ptr;

		*p8++ = TCPOPT_MPTCP;
		if (opts->addr4) {
			*p8++ = MPTCP_SUB_LEN_ADD_ADDR4;
			mpadd = (struct mp_add_addr *) p8;

			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 4;
			mpadd->addr_id = opts->addr4->id;
			p8 += 2;
			*((__be32 *) p8) = opts->addr4->addr.s_addr;
			p8 += sizeof(struct in_addr);
		} else if (opts->addr6) {
			*p8++ = MPTCP_SUB_LEN_ADD_ADDR6;
			mpadd = (struct mp_add_addr *) p8;

			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 6;
			mpadd->addr_id = opts->addr6->id;
			p8 += 2;
			memcpy((char *)p8, &(opts->addr6->addr),
					sizeof(struct in6_addr));
			p8 += sizeof(struct in6_addr);
		} else {
			BUG();
		}

		ptr = (__be32 *) p8;
	}
	if (unlikely(OPTION_MP_FAIL & opts->options)) {
		struct mp_fail *mpfail;
		__u8 *p8 = (__u8 *)ptr;

		*p8++ = TCPOPT_MPTCP;
		*p8++ = MPTCP_SUB_LEN_FAIL;

		mpfail = (struct mp_fail *)p8;

		mpfail->sub = MPTCP_SUB_FAIL;
		mpfail->rsv1 = 0;
		mpfail->rsv2 = 0;
		mpfail->data_seq = htonl(opts->data_ack);
	}

	if (OPTION_DSN_MAP & opts->options ||
	    OPTION_DATA_ACK & opts->options ||
	    OPTION_DATA_FIN & opts->options) {
		struct mp_dss *mdss;
		__u8 *p8 = (__u8 *)ptr;

		*p8++ = TCPOPT_MPTCP;
		*p8++ = MPTCP_SUB_LEN_DSS +
			((OPTION_DATA_ACK & opts->options) ?
			 MPTCP_SUB_LEN_ACK : 0) +
			((OPTION_DSN_MAP & opts->options) ?
			 (tp->mpcb->rx_opt.dss_csum ?
			  MPTCP_SUB_LEN_SEQ_CSUM : MPTCP_SUB_LEN_SEQ) : 0);
		mdss = (struct mp_dss *)p8;

		mdss->sub = MPTCP_SUB_DSS;
		mdss->rsv1 = 0;
		mdss->rsv2 = 0;
		mdss->F = (OPTION_DATA_FIN & opts->options ? 1 : 0);
		mdss->m = 0;
		mdss->M = (OPTION_DSN_MAP & opts->options ? 1 : 0);
		mdss->a = 0;
		mdss->A = (OPTION_DATA_ACK & opts->options ? 1 : 0);

		ptr++;
		if (OPTION_DATA_ACK & opts->options)
			*ptr++ = htonl(opts->data_ack);
		if (OPTION_DSN_MAP & opts->options) {
			*ptr++ = htonl(opts->data_seq);
			*ptr++ = htonl(opts->sub_seq);
			if (tp->mpcb->rx_opt.dss_csum) {
				__u16 *p16 = (__u16 *)ptr;
				*p16++ = htons(opts->data_len);
				*p16++ = opts->dss_csum;
				ptr++;
			} else {
				*ptr++ = htonl((opts->data_len << 16) |
						(TCPOPT_NOP << 8) |
						(TCPOPT_NOP));
			}
		}
	}
}

/* Inspired by tcp_close - specific for subflows as mptcp_sub_close may get
 * called from softirq (mptcp_clean_rtx_queue) and/or already has been orphaned
 * (by mptcp_close) */
static void mptcp_sub_close(struct sock *sk)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	/* If socket has been already reset (e.g. in tcp_reset()) - kill it. */
	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	/* As outlined in RFC 2525, section 2.17, we send a RST here because
	 * data was lost. To witness the awful effects of the old behavior of
	 * always doing a FIN, run an older 2.1.x kernel or 2.0.x, start a bulk
	 * GET in an FTP client, suspend the process, wait for the client to
	 * advertise a zero window, then kill -9 the FTP client, wheee...
	 * Note: timeout is always zero in such a case.
	 */
	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, (in_interrupt()) ?
				      GFP_ATOMIC : sk->sk_allocation);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(sk)) {
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TCP_ESTABLISHED, TCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 */
		tcp_send_fin(sk);
	}

	if (!tcp_sk(sk)->mpc)
		sk_stream_wait_close(sk, 0);

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);

	/* The sock *may* have been orphaned by mptcp_close(), if
	 * we are called from mptcp_clean__rtx_queue().
	 */
	if (!sock_flag(sk, SOCK_DEAD)) {
		sock_orphan(sk);
		percpu_counter_inc(sk->sk_prot->orphan_count);
	}

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (sk->sk_state == TCP_FIN_WAIT2) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->linger2 < 0) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
			} else {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_too_many_orphans(sk, 0)) {
			if (net_ratelimit())
				printk(KERN_INFO "TCP: too many of orphaned "
				       "sockets\n");
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPABORTONMEMORY);
		}
	}

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	sock_put(sk);
}

/**
 * Cleans the meta-socket retransmission queue.
 * @sk must be the metasocket.
 */
void mptcp_clean_rtx_queue(struct sock *meta_sk)
{
	struct sk_buff *skb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	int acked = 0;

	BUG_ON(!is_meta_tp(meta_tp));

	while ((skb = tcp_write_queue_head(meta_sk)) &&
	       skb != tcp_send_head(meta_sk)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		if (before(meta_tp->snd_una, scb->end_data_seq))
			break;

		tcp_unlink_write_queue(skb, meta_sk);

		if (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN) {
			struct sock *sk_it, *sk_tmp;
			/* DATA_FIN has been acknowledged - now we can close
			 * the subflows */
			mptcp_for_each_sk_safe(meta_tp->mpcb, sk_it, sk_tmp) {
				if (meta_sk->sk_shutdown == SHUTDOWN_MASK)
					mptcp_sub_close(sk_it);
				else if (tcp_close_state(sk_it))
					tcp_send_fin(sk_it);
			}
		}

		meta_tp->packets_out -= tcp_skb_pcount(skb);
		sk_wmem_free_skb(meta_sk, skb);

		acked = 1;
	}
	if (acked)
		mptcp_reset_xmit_timer(meta_sk);
}

void mptcp_clean_rtx_infinite(struct sk_buff *skb, struct sock *sk)
{
	struct multipath_pcb *mpcb;

	if (!tcp_sk(sk)->mpc)
		return;

	mpcb = tcp_sk(sk)->mpcb;

	if (!mpcb->infinite_mapping)
		return;

	mpcb_meta_tp(mpcb)->snd_una = TCP_SKB_CB(skb)->end_data_seq;
	mptcp_clean_rtx_queue(mpcb_meta_sk(mpcb));
	mptcp_rcv_state_process(mpcb_meta_sk(mpcb), skb);
}

/**
 * At the moment we apply a simple addition algorithm.
 * We will complexify later
 */
void mptcp_update_window_clamp(struct tcp_sock *tp)
{
	struct sock *meta_sk, *tmpsk;
	struct tcp_sock *meta_tp, *tmptp;
	struct multipath_pcb *mpcb;
	u32 new_clamp = 0, new_rcv_ssthresh = 0;
	int new_rcvbuf = 0;

	/* Can happen if called from non mpcb sock. */
	if (!tp->mpc)
		return;

	mpcb = tp->mpcb;
	meta_tp = mpcb_meta_tp(mpcb);
	meta_sk = (struct sock *)mpcb;

	mptcp_for_each_sk(mpcb, tmpsk, tmptp) {
		new_clamp += tmptp->window_clamp;
		new_rcv_ssthresh += tmptp->rcv_ssthresh;
		new_rcvbuf += tmpsk->sk_rcvbuf;
	}
	meta_tp->window_clamp = new_clamp;
	meta_tp->rcv_ssthresh = new_rcv_ssthresh;
	meta_sk->sk_rcvbuf = min(new_rcvbuf, sysctl_tcp_rmem[2]);
}

/**
 * Update the mpcb send window, based on the contributions
 * of each subflow
 */
void mptcp_update_sndbuf(struct multipath_pcb *mpcb)
{
	struct sock *meta_sk = (struct sock *) mpcb, *sk;
	struct tcp_sock *tp;
	int new_sndbuf = 0;
	mptcp_for_each_sk(mpcb, sk, tp)
		new_sndbuf += sk->sk_sndbuf;
	meta_sk->sk_sndbuf = min(new_sndbuf, sysctl_tcp_wmem[2]);
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
struct sk_buff *mptcp_next_segment(struct sock *sk, int *reinject)
{
	struct multipath_pcb *mpcb = tcp_sk(sk)->mpcb;
	struct sk_buff *skb = NULL;
	if (reinject)
		*reinject = 0;

	/* If it is the meta-sk and we are in fallback-mode, just take from
	 * the meta-send-queue */
	if (!is_meta_sk(sk) ||
	    mpcb->infinite_mapping || mpcb->send_infinite_mapping)
		return tcp_send_head(sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		if (reinject)
			*reinject = 1;
		return skb;
	} else {
		skb = tcp_send_head(sk);

		if (!skb && !sk_stream_memory_free(sk)) {
			struct sock *subsk;
			subsk = mptcp_schedulers[sysctl_mptcp_scheduler - 1](mpcb, NULL);

			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk);
			if (skb) {
				if (reinject)
					*reinject = -1;
			}
		}
		return skb;
	}
}

/**
 * Sets the socket pointer of the meta_sk after an accept at the socket level
 * Set also the sk_wq pointer, because it has just been copied by
 * sock_graft()
 */
void mptcp_check_socket(struct sock *sk)
{
	if (sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP &&
	    tcp_sk(sk)->mpc) {
		struct sock *meta_sk = mpcb_meta_sk(tcp_sk(sk)->mpcb);
		sk_set_socket(meta_sk, sk->sk_socket);
		meta_sk->sk_wq = sk->sk_wq;
		sk->sk_socket->sk = meta_sk;
	}
}
EXPORT_SYMBOL(mptcp_check_socket);

/* Sends the datafin */
void mptcp_send_fin(struct sock *meta_sk)
{
	struct sk_buff *skb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	if (tcp_send_head(meta_sk)) {
		skb = tcp_write_queue_tail(meta_sk);
		TCP_SKB_CB(skb)->data_len++;
		TCP_SKB_CB(skb)->end_data_seq++;
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
		TCP_SKB_CB(skb)->data_seq = meta_tp->write_seq;
		TCP_SKB_CB(skb)->data_len = 1;
		TCP_SKB_CB(skb)->end_data_seq = meta_tp->write_seq + 1;
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
	/* NOTE: here will come the MPTCP-specific DATA_RST of the upcoming
	 * draft v05.
	 *
	 * Left empty for now, as a subflow-RST on all subflows will anyways not
	 * really close the MPTCP-connection.*/
}

void mptcp_send_reset(struct sock *sk, struct sk_buff *skb)
{
	sock_orphan(sk);
	tcp_sk(sk)->teardown = 1;

	if (sk->sk_family == AF_INET)
		tcp_v4_send_reset(sk, skb);
#if defined(CONFIG_IPV6) || defined(CONFIG_MODULE_IPV6)
	else if (sk->sk_family == AF_INET6)
		tcp_v6_send_reset(sk, skb);
#endif
}

void mptcp_close(struct sock *meta_sk, long timeout)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct multipath_pcb *mpcb = meta_tp->mpcb;
	struct sock *subsk;
	struct tcp_sock *subtp;
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	mptcp_debug("%s: Close of meta_sk with tok %#x\n", __func__,
			mpcb->mptcp_loc_token);

	lock_sock(meta_sk);

	mptcp_destroy_mpcb(mpcb);

	meta_sk->sk_shutdown = SHUTDOWN_MASK;
	/* We need to flush the recv. buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&meta_sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_data_seq
			- TCP_SKB_CB(skb)->data_seq
			- (mptcp_is_data_fin(skb) ? 1 : 0);
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(meta_sk);

	/* If socket has been already reset (e.g. in tcp_reset()) - kill it. */
	if (meta_sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	if (tcp_close_state(meta_sk)) {
		mptcp_send_fin(meta_sk);
	} else if (meta_tp->snd_una == meta_tp->write_seq) {
		struct sock *sk_it, *sk_tmp;
		/* The DATA_FIN has been sent and acknowledged
		 * (e.g., by sk_shutdown). Close all the other subflows */
		mptcp_for_each_sk_safe(mpcb, sk_it, sk_tmp)
			mptcp_sub_close(sk_it);
	}

	sk_stream_wait_close(meta_sk, timeout);

adjudge_to_death:
	state = meta_sk->sk_state;
	sock_hold(meta_sk);
	sock_orphan(meta_sk);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(meta_sk);

	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(meta_sk);
	WARN_ON(sock_owned_by_user(meta_sk));

	percpu_counter_inc(meta_sk->sk_prot->orphan_count);

	mptcp_for_each_sk(mpcb, subsk, subtp) {
		/* The socket may have been orphaned by the tcp_close()
		 * above, in that case SOCK_DEAD is set already
		 */
		if (!sock_flag(subsk, SOCK_DEAD)) {
			sock_orphan(subsk);
			percpu_counter_inc(subsk->sk_prot->orphan_count);
		}
	}

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && meta_sk->sk_state == TCP_CLOSE)
		goto out;

	if (meta_sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(meta_sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(meta_sk);
	local_bh_enable();
	sock_put(meta_sk); /* Taken by sock_hold */
}

/**
 * When a listening sock is closed with established children still pending,
 * those children have created already an mpcb (tcp_check_req()).
 * Moreover, that mpcb has possibly received additional children,
 * from JOIN subflows. All this must be cleaned correctly, which is done
 * here. Later we should use a more generic approach, reusing more of
 * the regular TCP stack.
 */
void mptcp_detach_unused_child(struct sock *sk)
{
	struct multipath_pcb *mpcb;
	struct sock *child;
	struct tcp_sock *child_tp;
	if (!sk->sk_protocol == IPPROTO_TCP)
		return;
	mpcb = tcp_sk(sk)->mpcb;
	if (!mpcb)
		return;
	mptcp_destroy_mpcb(mpcb);
	/* Now all subflows of the mpcb are attached, so we can destroy them,
	 * being sure that the mpcb will be correctly destroyed last.
	 */
	mptcp_for_each_sk(mpcb, child, child_tp) {
		if (child == sk)
			continue; /* master_sk will be freed last
				   * as part of the normal
				   * net_csk_listen_stop() function
				   */
		/* This section is copied from
		 * inet_csk_listen_stop()
		 */
		local_bh_disable();
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		percpu_counter_inc(sk->sk_prot->orphan_count);

		inet_csk_destroy_sock(child);

		local_bh_enable();
		sock_put(child);
	}
}

void mptcp_set_bw_est(struct tcp_sock *tp, u32 now)
{
	if (!tp->mpc)
		return;

	if (!tp->bw_est.time)
		goto new_bw_est;

	if (after(tp->snd_una, tp->bw_est.seq)) {
		if (now - tp->bw_est.time == 0) {
			/* The interval was to small - shift one more */
			tp->bw_est.shift++;
		} else {
			tp->cur_bw_est = (tp->snd_una -
				(tp->bw_est.seq - tp->bw_est.space)) /
				(now - tp->bw_est.time);
		}
		goto new_bw_est;
	}
	return;

new_bw_est:
	tp->bw_est.space = (tp->snd_cwnd * tp->mss_cache) << tp->bw_est.shift;
	tp->bw_est.seq = tp->snd_una + tp->bw_est.space;
	tp->bw_est.time = now;
}

/**
 * Returns 1 if we should enable MPTCP for that socket.
 */
int do_mptcp(struct sock *sk)
{
	/* Socket may already be established (e.g., called from tcp_recvmsg) */
	if (tcp_sk(sk)->mpc || tcp_sk(sk)->request_mptcp)
		return 1;

	if (!sysctl_mptcp_enabled)
		return 0;
	if (!tcp_sk(sk)->mptcp_enabled)
		return 0;

	/* Don't do mptcp over loopback or local addresses */
	if (sk->sk_family == AF_INET && ipv4_is_loopback(inet_sk(sk)->inet_daddr))
		return 0;
	if (sk->sk_family == AF_INET6 && ipv6_addr_loopback(&inet6_sk(sk)->daddr))
		return 0;
	if (mptcp_v6_is_v4_mapped(sk) && ipv4_is_loopback(inet_sk(sk)->inet_saddr))
		return 0;

	/* We should try to speed this up - is_local_addr4 takes a read_lock and
	 * iterates over all devices and addresses
	 * May we allow mptcp over local addresses? */
	if (is_local_addr4(inet_sk(sk)->inet_daddr))
		return 0;
	return 1;
}

void mptcp_set_state(struct sock *sk, int state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int oldstate = sk->sk_state;

	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED && tp->mpc) {
			struct sock *meta_sk = mptcp_meta_sk(sk);
			tcp_sk(sk)->mpcb->cnt_established++;
			mptcp_update_sndbuf(tp->mpcb);
			if ((1 << meta_sk->sk_state) &
				(TCPF_SYN_SENT | TCPF_SYN_RECV))
				meta_sk->sk_state = TCP_ESTABLISHED;
		}
		break;
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		/* We set the mpcb state to SYN_SENT even if the peer
		 * has no support for MPTCP. This is the only option
		 * as we don't know yet if he is MP_CAPABLE.
		 */
		if (tp->mpcb && is_master_tp(tp))
			mptcp_meta_sk(sk)->sk_state = state;
		break;
	case TCP_CLOSE:
		if (tcp_sk(sk)->mpcb && oldstate != TCP_SYN_SENT &&
		    oldstate != TCP_SYN_RECV && oldstate != TCP_LISTEN)
			tcp_sk(sk)->mpcb->cnt_established--;
	}
}

int mptcp_check_req_master(struct sock *child, struct request_sock *req,
		struct multipath_options *mopt)
{
	struct tcp_sock *child_tp = tcp_sk(child);

	/* Copy mptcp related info from req to child
	 * we do this here because this is shared between
	 * ipv4 and ipv6
	 */
	child_tp->rx_opt.saw_mpc = req->saw_mpc;
	if (child_tp->rx_opt.saw_mpc) {
		struct multipath_pcb *mpcb;

		child_tp->rx_opt.saw_mpc = 0;
		child_tp->mpc = 1;
		child_tp->slave_sk = 0;
		child_tp->path_index = 1;

		/* Just set this values to pass them to mptcp_alloc_mpcb */
		child_tp->mptcp_loc_key = req->mptcp_loc_key;
		child_tp->mptcp_loc_token = req->mptcp_loc_token;
		child_tp->mptcp_rem_key = req->mptcp_rem_key;

		if (mptcp_alloc_mpcb(child)) {
			/* The allocation of the mpcb failed!
			 * Destroy the child and go to listen_overflow
			 */
			tcp_done(child);
			return -ENOBUFS;
		}
		mpcb = child_tp->mpcb;

		inet_sk(child)->loc_id = 0;
		inet_sk(child)->rem_id = 0;

		mptcp_add_sock(mpcb, child_tp);

		if (mopt->list_rcvd)
			memcpy(&mpcb->rx_opt, mopt, sizeof(*mopt));

		mpcb->rx_opt.dss_csum = sysctl_mptcp_checksum || req->dss_csum;

		set_bit(MPCB_FLAG_SERVER_SIDE, &mpcb->flags);
		/* Will be moved to ESTABLISHED by
		 * tcp_rcv_state_process()
		 */
		mpcb_meta_sk(mpcb)->sk_state = TCP_SYN_RECV;
		mptcp_update_metasocket(child, mpcb);

		 /* hold in mptcp_inherit_sk due to initialization to 2 */
		sock_put(mpcb_meta_sk(mpcb));
	} else {
		child_tp->mpcb = NULL;
	}

	return 0;
}

struct sock *mptcp_check_req_child(struct sock *meta_sk, struct sock *child,
		struct request_sock *req, struct request_sock **prev)
{
	struct tcp_sock *child_tp = tcp_sk(child);
	struct multipath_pcb *mpcb = req->mpcb;
	u8 hash_mac_check[20];

	BUG_ON(!mpcb);

	if (!mpcb->rx_opt.mptcp_opt_type == MPTCP_MP_JOIN_TYPE_ACK)
		goto teardown;

	mptcp_hmac_sha1((u8 *)&mpcb->rx_opt.mptcp_rem_key,
			(u8 *)&mpcb->mptcp_loc_key,
			(u8 *)&req->mptcp_rem_random_number,
			(u8 *)&req->mptcp_loc_random_number,
			(u32 *)hash_mac_check);

	if (memcmp(hash_mac_check, (char *)&mpcb->rx_opt.mptcp_recv_mac, 20))
		goto teardown;

	/* The child is a clone of the meta socket, we must now reset
	 * some of the fields
	 */
	child_tp->mpc = 1;
	child_tp->slave_sk = 1;
	child_tp->bw_est.time = 0;
	child->sk_sndmsg_page = NULL;

	inet_sk(child)->loc_id = mptcp_get_loc_addrid(mpcb, child);
	inet_sk(child)->rem_id = req->rem_id;

	/* Deleting from global hashtable */
	mptcp_hash_request_remove(req);

	/* Subflows do not use the accept queue, as they
	 * are attached immediately to the mpcb.
	 */
	inet_csk_reqsk_queue_drop(meta_sk, req, prev);
	return child;

teardown:
	sock_orphan(child);
	tcp_done(child);
	return meta_sk;
}

void mptcp_select_window(struct tcp_sock *tp, u32 new_win)
{
	struct sock *tmp_sk;
	struct tcp_sock *tmp_tp, *meta_tp = mpcb_meta_tp(tp->mpcb);
	meta_tp->rcv_wnd = new_win;
	meta_tp->rcv_wup = meta_tp->rcv_nxt;

	/* The receive-window is the same for all the subflows */
	mptcp_for_each_sk(tp->mpcb, tmp_sk, tmp_tp) {
		tmp_tp->rcv_wnd = new_win;
	}
	/* the subsock rcv_wup must still be updated,
	 * because it is used to decide when to echo the timestamp
	 * and when to delay the acks */
	tp->rcv_wup = tp->rcv_nxt;
}

#ifdef MPTCP_DEBUG_PKTS_OUT
int check_pkts_out(struct sock *sk)
{
	int cnt = 0;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	/* TODEL: sanity check on packets_out */
	if (tp->mpc && !is_meta_tp(tp)) {
		tcp_for_write_queue(skb, sk) {
			if (skb == tcp_send_head(sk))
				break;
			else
				cnt += tcp_skb_pcount(skb);
		}
		BUG_ON(tp->packets_out != cnt);
	} else {
		cnt = -10;
	}

	return cnt;
}

void check_send_head(struct sock *sk, int num)
{
	struct sk_buff *head = tcp_send_head(sk);
	struct sk_buff *skb;
	int found = 0;
	if (head) {
		tcp_for_write_queue(skb, sk) {
			if (skb == head) {
				found = 1;
				break;
			}
		}
	} else {
		found = 1;
	}

	if (!found) {
		printk(KERN_ERR "num:%d\n", num);
		BUG();
	}
}
#endif

/* General initialization of mptcp */
static int __init mptcp_init(void)
{
#ifdef CONFIG_SYSCTL
	register_sysctl_table(mptcp_root_table);
#endif
	mpcb_cache = kmem_cache_create("mptcp_mpcb", sizeof(struct multipath_pcb),
				       0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	mptcp_ofo_queue_init();
	return 0;
}
module_init(mptcp_init);

MODULE_LICENSE("GPL");
