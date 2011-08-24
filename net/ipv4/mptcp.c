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

#include <crypto/sha.h>

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
/* ===================================== */

/**
 * This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the estimation of how much time will be
 * needed to send the segment. If all paths have full cong windows, we
 * simply block. The flow able to send the segment the soonest get it.
 */
struct sock *get_available_subflow(struct multipath_pcb *mpcb,
				   struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sock *bestsk = NULL;
	u32 min_time_to_peer = 0xffffffff;

	if (!mpcb)
		return NULL;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *) mpcb->connection_list;
		if (!mptcp_is_available(bestsk))
			bestsk = NULL;
		goto out;
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk, tp) {
		if (!mptcp_is_available(sk))
			continue;

		/* If the skb has already been enqueued in this sk, try to find
		 * another one
		 */
		if (PI_TO_FLAG(tp->path_index) & skb->path_mask)
			continue;

		if (tp->srtt < min_time_to_peer) {
			min_time_to_peer = tp->srtt;
			bestsk = sk;
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
		};

/* Sysctl data */

#ifdef CONFIG_SYSCTL

int sysctl_mptcp_mss __read_mostly = MPTCP_MSS;
int sysctl_mptcp_ndiffports __read_mostly = 1;
int sysctl_mptcp_enabled __read_mostly = 1;
int sysctl_mptcp_scheduler __read_mostly = 1;
int sysctl_mptcp_checksum __read_mostly = 1;

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

/**
 * Equivalent of tcp_fin() for MPTCP
 * Can be called only when the FIN is validly part
 * of the data seqnum space. Not before when we get holes.
 */
static inline void mptcp_fin(struct multipath_pcb *mpcb)
{
	struct sock *meta_sk = (struct sock *) mpcb;

	meta_sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(meta_sk, SOCK_DONE);
	if (meta_sk->sk_state == TCP_ESTABLISHED)
		tcp_set_state(meta_sk, TCP_CLOSE_WAIT);
}

static void mptcp_sock_def_error_report(struct sock *sk)
{
	/* If there exists more than one working subflow, we don't wake up the
	 * application, as the mptcp-connection is still alive */
	if (tcp_sk(sk)->mpc &&
	    tcp_sk(sk)->mpcb->cnt_established >
				((sk->sk_state == TCP_ESTABLISHED) ? 1 : 0)) {
		sk->sk_err = 0;
		sock_orphan(sk);
		return;
	}

	sock_def_error_report(sk);
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

	BUG_ON(!tcp_sk(mpcb->master_sk)->mpc);

	/* First, ensure that we keep existing path indices. */
	mptcp_for_each_tp(mpcb, tp)
		/* disable the corresponding bit of the existing subflow */
		path_indices &= ~PI_TO_FLAG(tp->path_index);

	for (i = 0; i < sizeof(path_indices) * 8; i++) {
		struct sock *sk, *meta_sk = (struct sock *)mpcb;
		struct socket sock;
		struct sockaddr *loculid, *remulid;
		struct path4 *pa4 = NULL;
		struct path6 *pa6 = NULL;
		int ulid_size = 0, newpi = i + 1, family, ret;

		if (!((1 << i) & path_indices))
			continue;

		family = mptcp_get_path_family(mpcb, newpi);

		sock.type = mpcb->master_sk->sk_socket->type;
		sock.state = SS_UNCONNECTED;
		sock.wq = mpcb->master_sk->sk_socket->wq;
		sock.file = mpcb->master_sk->sk_socket->file;
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
			mptcp_debug("%s: token %08x pi %d src_addr:"
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
			mptcp_debug("%s: token %08x pi %d src_addr:"
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

		sk_set_socket(sk, mpcb->master_sk->sk_socket);
		sk->sk_wq = mpcb->master_sk->sk_wq;

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

	memset(workspace, 0, SHA_WORKSPACE_WORDS * sizeof(u32));

	/* Initialize input with appropriate padding */
	memset(input, 0, 64);
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

	memset(workspace, 0, SHA_WORKSPACE_WORDS * sizeof(u32));

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
	memset(workspace, 0, SHA_WORKSPACE_WORDS * sizeof(u32));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, SHA_WORKSPACE_WORDS * sizeof(u32));

	/* Prepare second hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 64 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, SHA_WORKSPACE_WORDS * sizeof(u32));

	sha_transform(hash_out, &input[64], workspace);
}


int mptcp_alloc_mpcb(struct sock *master_sk, struct request_sock *req,
		gfp_t flags)
{
	struct multipath_pcb *mpcb;
	struct tcp_sock *meta_tp;
	struct sock *meta_sk;
	struct inet_connection_sock *meta_icsk;

	/* May happen, when coming from mptcp_init_subsockets */
	if (tcp_sk(master_sk)->slave_sk)
		return 0;

	mpcb = kmalloc(sizeof(struct multipath_pcb), flags);
	/* Memory allocation failed. Stopping here. */
	if (!mpcb)
		return -ENOBUFS;

	meta_tp = mpcb_meta_tp(mpcb);
	meta_sk = (struct sock *)meta_tp;
	meta_icsk = inet_csk(meta_sk);

	memset(mpcb, 0, sizeof(struct multipath_pcb));
	BUG_ON(mpcb->connection_list);

	/* meta_sk inherits master sk */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	mptcp_inherit_sk(master_sk, meta_sk, AF_INET6, flags);
#else
	mptcp_inherit_sk(master_sk, meta_sk, AF_INET, flags);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	BUG_ON(mpcb->connection_list);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (AF_INET_FAMILY(master_sk->sk_family)) {
		mpcb->icsk_af_ops_alt = &ipv6_specific;
		mpcb->sk_prot_alt = &tcpv6_prot;
	} else {
		mpcb->icsk_af_ops_alt = &ipv4_specific;
		mpcb->sk_prot_alt = &tcp_prot;
	}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	/* Will be replaced by the IDSN later. Currently the IDSN is zero */
	meta_tp->copied_seq = meta_tp->rcv_nxt = meta_tp->rcv_wup = 0;
	meta_tp->snd_sml = meta_tp->snd_una = meta_tp->snd_nxt = 0;
	meta_tp->write_seq = 0;

	meta_tp->mpcb = mpcb;
	meta_tp->mpc = 1;
	meta_tp->mss_cache = mptcp_sysctl_mss();

	skb_queue_head_init(&meta_tp->out_of_order_queue);
	skb_queue_head_init(&mpcb->reinject_queue);

	meta_sk->sk_rcvbuf = sysctl_rmem_default;
	meta_sk->sk_sndbuf = sysctl_wmem_default;
	meta_sk->sk_state = TCP_SYN_SENT;

	/* Inherit locks the meta_sk, so we must release it here. */
	bh_unlock_sock(meta_sk);
	sock_put(meta_sk);

	mpcb->master_sk = master_sk;
	sock_hold(master_sk);

	meta_tp->window_clamp = tcp_sk(master_sk)->window_clamp;
	meta_tp->rcv_ssthresh = tcp_sk(master_sk)->rcv_ssthresh;

	/* Redefine function-pointers to wake up application */
	master_sk->sk_error_report = mptcp_sock_def_error_report;
	meta_sk->sk_error_report = mptcp_sock_def_error_report;

	/* Init the accept_queue structure, we support a queue of 4 pending
	 * connections, it does not need to be huge, since we only store
	 * here pending subflow creations.
	 */
	reqsk_queue_alloc(&meta_icsk->icsk_accept_queue, 32, flags);
	/* Pi 1 is reserved for the master subflow */
	mpcb->next_unused_pi = 2;

	/* For the server side, the local token has already been allocated.
	 * Later, we should replace this strange condition (quite a quick hack)
	 * with a test_bit on the server flag. But this requires passing
	 * the server flag in arg of mptcp_alloc_mpcb(), so that we know here if
	 * we are at server or client side. At the moment the only way to know
	 * that is to check for uninitialized token (see tcp_check_req()).
	 */
	if (!req) {
		do {
			/* Creating a new key for the server */
			do {
				get_random_bytes(&mpcb->mptcp_loc_key,
						sizeof(mpcb->mptcp_loc_key));
			} while (!mpcb->mptcp_loc_key);

			mptcp_key_sha1(mpcb->mptcp_loc_key,
				       &mpcb->mptcp_loc_token);
		} while (mptcp_find_token(mpcb->mptcp_loc_token));
	} else {
		mpcb->mptcp_loc_key = req->mptcp_loc_key;
		mpcb->mptcp_loc_token = req->mptcp_loc_token;

		mpcb->rx_opt.mptcp_rem_key = req->mptcp_rem_key;
		mptcp_key_sha1(mpcb->rx_opt.mptcp_rem_key,
			       &mpcb->rx_opt.mptcp_rem_token);
	}

	/* Adding the mpcb in the token hashtable */
	mptcp_hash_insert(mpcb, mpcb->mptcp_loc_token);

	tcp_sk(master_sk)->path_index = 0;
	tcp_sk(master_sk)->mpcb = mpcb;

	mpcb->rx_opt.dss_csum = sysctl_mptcp_checksum;

	return 0;
}

void mpcb_release(struct multipath_pcb *mpcb)
{
	struct sock *meta_sk = (struct sock *)mpcb;

	/* Must have been destroyed previously */
	if (!sock_flag((struct sock *)mpcb, SOCK_DEAD)) {
		printk(KERN_ERR "Trying to free mpcb without having called "
		       "mptcp_destroy_mpcb()\n");
		BUG();
	}

	/* Ensure that all queues are empty. Later, we can find more
	 * appropriate places to do this, maybe reusing existing code.
	 * But this at least ensures that we are safe when destroying
	 * the mpcb.
	 */
	tcp_write_queue_purge(meta_sk);
	__skb_queue_purge(&tcp_sk(meta_sk)->out_of_order_queue);
	sk_stream_kill_queues(meta_sk);

#ifdef CONFIG_MPTCP_PM
	mptcp_pm_release(mpcb);
#endif
	mptcp_debug("%s: Will free mpcb\n", __func__);
	security_sk_free((struct sock *)mpcb);
	percpu_counter_dec(meta_sk->sk_prot->orphan_count);

	kfree(mpcb);
}

void mptcp_release_sock(struct sock *sk)
{

	struct sock *sk_it;
	struct tcp_sock *tp_it;
	struct multipath_pcb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *meta_sk = (struct sock *)mpcb;

	BUG_ON(!is_master_tp(tcp_sk(sk)));

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
	mptcp_debug("%s: Destroying mpcb with token:%08x\n", __func__,
			mpcb->mptcp_loc_token);

	/* Detach the mpcb from the token hashtable */
	mptcp_hash_remove(mpcb);
	/* Accept any subsock waiting in the pending queue
	 * This is needed because those subsocks are established
	 * and still reachable by incoming packets. They will hence
	 * try to reference the mpcb, and need to take a ref
	 * to it to ensure the mpcb does not die before any of its
	 * childs.
	 */
	release_sock(mpcb->master_sk);
	lock_sock(mpcb->master_sk);

	sock_set_flag((struct sock *)mpcb, SOCK_DEAD);

	sock_put(mpcb->master_sk); /* grabbed by mptcp_alloc_mpcb */
}

void mptcp_add_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp)
{
	struct sock *meta_sk = (struct sock *) mpcb;
	struct sock *sk = (struct sock *) tp;

	/* We should not add a non-mpc socket */
	BUG_ON(!tp->mpc);

	/* first subflow */
	if (!tp->path_index)
		tp->path_index = 1;

	/* Adding new node to head of connection_list */
	if (!tp->mpcb) {
		tp->mpcb = mpcb;
		if (!is_master_tp(tp)) {
			/* The corresponding sock_put is in
			 * inet_sock_destruct(). It cannot be included in
			 * mptcp_del_sock(), because the mpcb must remain alive
			 * until the last subsocket is completely destroyed.
			 * The master_sk cannot sock_hold on itself,
			 * otherwise it will never be released.
			 */
			sock_hold(mpcb->master_sk);
		}
	}
	tp->next = mpcb->connection_list;
	mpcb->connection_list = tp;
	tp->attached = 1;

	mpcb->cnt_subflows++;
	mptcp_update_window_clamp(tcp_sk(meta_sk));
	atomic_add(
		atomic_read(&((struct sock *)tp)->sk_rmem_alloc),
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

	if (sk->sk_family == AF_INET)
		mptcp_debug("%s: token %08x pi %d, src_addr:%pI4:%d dst_addr:"
				"%pI4:%d, cnt_subflows now %d\n", __func__ ,
				mpcb->mptcp_loc_token,
				tp->path_index,
				&((struct inet_sock *) tp)->inet_saddr,
				ntohs(((struct inet_sock *) tp)->inet_sport),
				&((struct inet_sock *) tp)->inet_daddr,
				ntohs(((struct inet_sock *) tp)->inet_dport),
				mpcb->cnt_subflows);
	else
		mptcp_debug("%s: token %08x pi %d, src_addr:%pI6:%d dst_addr:"
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
	struct multipath_pcb *mpcb = tp->mpcb;
	int done = 0;

	/* Need to check for protocol here, because we may enter here for
	 * non-tcp sockets. (coming from inet_csk_destroy_sock) */
	if (sk->sk_protocol != IPPROTO_TCP || !tp->mpc)
		return;

	mptcp_debug("%s: Removing subsocket - pi:%d\n", __func__,
			tp->path_index);

	tp_prev = mpcb->connection_list;
	if (!tp->attached)
		return;

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

	/* Is there still data to be sent and more subflows available? */
	if (tcp_send_head(sk) && mpcb->cnt_established > 0)
		mptcp_reinject_data(sk, 0);

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
	struct tcp_sock *tp;
	struct sock *meta_sk;

	if (sk->sk_protocol != IPPROTO_TCP || !is_master_tp(tcp_sk(sk)))
		return;
	tp = tcp_sk(sk);
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
		if (!tcp_v6_is_v4_mapped(sk))
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
#ifdef CONFIG_MPTCP_PM

	/* If this added new local addresses, build new paths with them */
	if (mpcb->num_addr4 || mpcb->num_addr6)
		mptcp_update_patharray(mpcb);
#endif
}

void mptcp_update_window_check(struct tcp_sock *meta_tp, struct sk_buff *skb,
		u32 data_ack)
{
	if (meta_tp->mpc && (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_ACK) &&
		after(data_ack, meta_tp->snd_una)) {
		meta_tp->snd_una = data_ack;
		mptcp_clean_rtx_queue((struct sock *) meta_tp);
	}
}

/* copied from tcp_output.c */
static inline unsigned int tcp_cwnd_test(struct tcp_sock *tp)
{
	u32 in_flight, cwnd;

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return cwnd - in_flight;

	return 0;
}

void mptcp_check_buffers(struct multipath_pcb *mpcb)
{
	struct sock *sk, *meta_sk = (struct sock *) mpcb;
	struct tcp_sock *tp, *meta_tp = (struct tcp_sock *) mpcb;
	struct sk_buff *skb;
	int rcv_size = 0, meta_ofo_size = 0;

	for (skb = skb_peek(&meta_tp->out_of_order_queue);
			skb;
			skb =
			(skb_queue_is_last(&meta_tp->out_of_order_queue, skb) ?
					NULL :
				skb_queue_next(&meta_tp->out_of_order_queue,
						skb)))
		meta_ofo_size += skb->truesize;

	for (skb = skb_peek(&meta_sk->sk_receive_queue);
			skb;
			skb =
			(skb_queue_is_last(&meta_sk->sk_receive_queue, skb) ?
				NULL :
				skb_queue_next(&meta_sk->sk_receive_queue,
					skb)))
		rcv_size += skb->truesize;

	mptcp_for_each_sk(mpcb, sk, tp) {
		int ofo_size = 0;

		if (sk->sk_state != TCP_ESTABLISHED)
			continue;
		for (skb = skb_peek(&tp->out_of_order_queue);
			skb;
			skb = (skb_queue_is_last(&tp->out_of_order_queue,
				skb) ? NULL :
				skb_queue_next(&tp->out_of_order_queue, skb)))
			ofo_size += skb->truesize;

		skb = skb_peek(&meta_sk->sk_receive_queue);
		mptcp_debug("pi %d, ofo_size:%d,meta_ofo_size:%d,"
			"rcv_size:%d, next dsn:%#x\n",
			tp->path_index, ofo_size, meta_ofo_size, rcv_size,
			(skb ? mptcp_skb_data_seq(skb) : 0));
	}
}

int mptcp_try_rmem_schedule(struct sock *sk, unsigned int size)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sock *meta_tp = mpcb_meta_tp(tp->mpcb);
	struct sock *meta_sk = (struct sock *) meta_tp;
	if (atomic_read(&meta_sk->sk_rmem_alloc) >
			meta_sk->sk_rcvbuf) {
		tcpprobe_logmsg(meta_sk, "PROBLEM NOW");
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
			mptcp_debug("%s: --- ofo-queue:\n",
				__func__);
			skb_queue_walk(&tp->out_of_order_queue, skb) {
				mptcp_debug("%s: dsn:%#x, "
					"skb->len:%d, truesize:%d, "
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
		mptcp_debug("%s: --- meta-ofo queue:\n", __func__);
		skb_queue_walk(&meta_tp->out_of_order_queue, skb) {
			mptcp_debug("%s: dsn:%#x, "
				"skb->len:%d,truesize:%d,"
				"prop:%d /1000\n", __func__,
				TCP_SKB_CB(skb)->data_seq,
				skb->len, skb->truesize,
				skb->len * 1000 / skb->truesize);
		}
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

int mptcp_is_available(struct sock *sk)
{
	/* Set of states for which we are allowed to send data */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		return 0;
	if (tcp_sk(sk)->pf || (tcp_sk(sk)->mpcb->noneligible
			& PI_TO_FLAG(tcp_sk(sk)->path_index))
			|| inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
		return 0;
	if (tcp_cwnd_test(tcp_sk(sk)))
		return 1;
	return 0;
}

int mptcp_sendmsg(struct kiocb *iocb, struct sock *master_sk,
		struct msghdr *msg, size_t size)
{
	struct tcp_sock *master_tp = tcp_sk(master_sk);
	struct multipath_pcb *mpcb = mpcb_from_tcpsock(tcp_sk(master_sk));
	struct sock *meta_sk = (struct sock *) mpcb;
	int copied = 0;
	int err;
	int flags = msg->msg_flags;
	long timeo = sock_sndtimeo(master_sk, flags & MSG_DONTWAIT);

	lock_sock(master_sk);

	/* If the master sk is not yet established, we need to wait
	 * until the establishment, so as to know whether the mpc option
	 * is present.
	 */
	if (!master_tp->mpc) {
		if ((1 << master_sk->sk_state) & ~(TCPF_ESTABLISHED
				| TCPF_CLOSE_WAIT)) {
			err = sk_stream_wait_connect(master_sk, &timeo);
			if (err) {
				printk(KERN_ERR "err is %d, state %d\n", err,
						master_sk->sk_state);
				goto out_err_nompc;
			}
			/* The flag must be re-checked, because it may have
			 * appeared during sk_stream_wait_connect
			 */
			if (!tcp_sk(master_sk)->mpc) {
				copied = tcp_sendmsg(iocb, master_sk, msg,
							size);
				goto out;
			}

		} else {
			copied = tcp_sendmsg(iocb, master_sk, msg, size);
			goto out;
		}
	}

	verif_wqueues(mpcb);

	copied = tcp_sendmsg(NULL, meta_sk, msg, 0);
	if (copied < 0) {
		printk(KERN_ERR "%s: returning error "
		"to app:%d\n", __func__, (int) copied);
		goto out;
	}

out:
	release_sock(master_sk);
	return copied;

out_err_nompc:
	err = sk_stream_error(master_sk, flags, err);
	TCP_CHECK_TIMER(master_sk);
	release_sock(master_sk);
	return err;
}
EXPORT_SYMBOL(mptcp_sendmsg);

void mptcp_ofo_queue(struct multipath_pcb *mpcb)
{
	struct sk_buff *skb = NULL;
	struct sock *meta_sk = (struct sock *) mpcb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	while ((skb = skb_peek(&meta_tp->out_of_order_queue)) != NULL) {
		if (after(TCP_SKB_CB(skb)->data_seq, meta_tp->rcv_nxt))
			break;

		if (!after(TCP_SKB_CB(skb)->end_data_seq, meta_tp->rcv_nxt)) {
			struct sk_buff *skb_tail = skb_peek_tail(
					&meta_sk->sk_receive_queue);
			printk(KERN_ERR "ofo packet was already received."
					"skb->end_data_seq:%#x,exp. rcv_nxt:%#x, "
					"skb->dsn:%#x,skb->len:%d\n",
					TCP_SKB_CB(skb)->end_data_seq,
					meta_tp->rcv_nxt,
					TCP_SKB_CB(skb)->data_seq,
					skb->len);
			if (skb_tail)
				printk(KERN_ERR "last packet of the rcv queue:"
					"dsn %#x, last dsn %#x, len %d\n",
					TCP_SKB_CB(skb_tail)->data_seq,
					TCP_SKB_CB(skb_tail)->end_data_seq,
					skb_tail->len);
			/* Should not happen in the current design */
			BUG();
		}

		__skb_unlink(skb, &meta_tp->out_of_order_queue);

		__skb_queue_tail(&meta_sk->sk_receive_queue, skb);
		meta_tp->rcv_nxt = TCP_SKB_CB(skb)->end_data_seq;

		if (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN)
			mptcp_fin(mpcb);
	}
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
	struct sock *sk;
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
		}
	}

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
			__u32 new_window = __tcp_select_window(mpcb->master_sk);

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
	/* If we need to send an explicit window update, we need to choose
	   some subflow to send it. At the moment, we use the master subsock
	   for this. */
	if (time_to_ack) {
		/* We send it on all the subflows
		 * that are able to receive data.*/
		mptcp_for_each_sk(mpcb, sk, tp) {
			if (sk->sk_state == TCP_ESTABLISHED ||
			    sk->sk_state == TCP_FIN_WAIT1 ||
			    sk->sk_state == TCP_FIN_WAIT2)
				tcp_send_ack(sk);
		}
	}
}

/* Eats data from the meta-receive queue */
int mptcp_check_rcv_queue(struct multipath_pcb *mpcb, struct msghdr *msg,
		size_t *len, u32 *data_seq, int *copied, int flags)
{
	struct sk_buff *skb;
	struct sock *meta_sk = (struct sock *) mpcb;
	int err;
	struct tcp_sock *tp;

	do {
		u32 data_offset = 0;
		unsigned long used;
		int dfin = 0;

		skb = skb_peek(&meta_sk->sk_receive_queue);

		do {
			if (!skb)
				goto exit;

			tp = tcp_sk(skb->sk);

			if (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN)
				dfin = 1;

			if (before(*data_seq, TCP_SKB_CB(skb)->data_seq)) {
				printk(KERN_ERR "%s bug: copied %X "
				       "dataseq %X\n", __func__, *data_seq,
				       TCP_SKB_CB(skb)->data_seq);
				BUG();
			}
			data_offset = *data_seq - TCP_SKB_CB(skb)->data_seq;
			if (data_offset < skb->len)
				goto found_ok_skb;
			if (dfin)
				goto found_fin_ok;

			if (skb->len + dfin != TCP_SKB_CB(skb)->end_data_seq
					- TCP_SKB_CB(skb)->data_seq) {
				printk(KERN_ERR "skb->len:%d, should be %d\n",
						skb->len,
						TCP_SKB_CB(skb)->end_data_seq
						- TCP_SKB_CB(skb)->data_seq);
				BUG();
			}
			WARN_ON(!(flags & MSG_PEEK));
			skb = skb->next;
		} while (skb != (struct sk_buff *) &meta_sk->sk_receive_queue);

found_ok_skb:
		if (skb == (struct sk_buff *) &meta_sk->sk_receive_queue)
			goto exit;

		used = skb->len - data_offset;
		if (*len < used)
			used = *len;

		err = skb_copy_datagram_iovec(skb, data_offset, msg->msg_iov,
				used);
		if (err) {
			int iovlen = msg->msg_iovlen;
			struct iovec *iov = msg->msg_iov;
			int msg_size = 0;
			while (iovlen-- > 0) {
				msg_size += iov->iov_len;
				iov++;
			}
			printk(KERN_ERR "err in skb_copy_datagram_iovec:"
			"skb:%p,data_offset:%d, iov:%p,used:%lu,"
			"msg_size:%d,err:%d,skb->len:%ul,*len:%d,"
			"dfin:%d\n", skb, data_offset, iov, used, msg_size,
					err, skb->len, (int) *len, dfin);
			BUG();
		}

		*data_seq += used;
		*copied += used;
		*len -= used;

		if (dfin)
			goto found_fin_ok;

		if (*data_seq == TCP_SKB_CB(skb)->end_data_seq &&
		    !(flags & MSG_PEEK)) {
			sk_eat_skb(meta_sk, skb, 0);
		} else if (!(flags & MSG_PEEK) && *len != 0) {
			printk(KERN_ERR
			"%s bug: copied %#x "
			"dataseq %#x, *len %d, used:%d\n", __func__,
			       *data_seq, TCP_SKB_CB(skb)->data_seq,
			       (int) *len, (int) used);
			BUG();
		}
		continue;

found_fin_ok:
		/* Process the FIN. */
		++*data_seq;
		if (!(flags & MSG_PEEK))
			sk_eat_skb(meta_sk, skb, 0);
		break;
	} while (*len > 0);
	/* This checks whether an explicit window update is needed to unblock
	 * the receiver
	 */
exit:
	mptcp_cleanup_rbuf(meta_sk, *copied);
	return 0;
}

static inline void mptcp_send_reset(struct sock *sk, struct sk_buff *skb)
{
	if (sk->sk_family == AF_INET)
		tcp_v4_send_reset(sk, skb);
#if defined(CONFIG_IPV6) || defined(CONFIG_MODULE_IPV6)
	else if (sk->sk_family == AF_INET6)
		tcp_v6_send_reset(sk, skb);
	else
		BUG();
#endif
}

static int mptcp_verif_dss_csum(struct sock *sk)
{
	struct sk_buff *tmp, *last = NULL;
	__wsum csum_tcp = 0; /* cumulative checksum of pld + mptcp-header */
	int ans = 0, overflowed = 0, offset = 0, dss_csum_added = 0;
	char last_byte = 0; /* byte to be added to the next csum */

	skb_queue_walk(&sk->sk_receive_queue, tmp) {
		unsigned int csum_len = tmp->len;
		unsigned int len;

		offset = 0;
		if (overflowed) {
			char first_word[4];
			first_word[0] = 0;
			first_word[1] = 0;
			first_word[2] = last_byte;
			first_word[3] = *(tmp->data);
			csum_tcp = csum_partial(first_word, 4, csum_tcp);
			offset = 1;
			csum_len--;
			overflowed = 0;
		}

		len = csum_len & (~1); /* len is tmp->len but even */

		csum_tcp = skb_checksum(tmp, offset, len, csum_tcp);

		if (len != csum_len) {
			last_byte = *(tmp->data + tmp->len - 1);
			overflowed = 1;
		}

		if (TCP_SKB_CB(tmp)->dss_off && !dss_csum_added) {
			csum_tcp = skb_checksum(tmp, skb_transport_offset(tmp) +
						(TCP_SKB_CB(tmp)->dss_off << 2),
						MPTCP_SUB_LEN_SEQ_CSUM,
						csum_tcp);
			dss_csum_added = 1; /* Just do it once */
		}
		last = tmp;
	}
	if (overflowed) {
		char first_word[4];
		first_word[0] = 0;
		first_word[1] = 0;
		first_word[2] = last_byte;
		first_word[3] = 0;
		csum_tcp = csum_partial(first_word, 4, csum_tcp);
	}

	/* Now, checksum must be 0 */
	if (unlikely(csum_fold(csum_tcp))) {
		mptcp_debug("%s csum is wrong: %#x data_seq %u\n", __func__,
			    csum_fold(csum_tcp), TCP_SKB_CB(last)->data_seq);
		tcp_sk(sk)->csum_error = 1;
		sock_orphan(sk);
		mptcp_send_reset(sk, last);
		ans = 1;
	}

	/* We would have needed the rtable entry for sending the reset */
	if (last)
		skb_dst_drop(last);

	return ans;
}

static inline void mptcp_prepare_skb(struct sk_buff *skb, struct tcp_sock *tp)
{
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	/* Adapt data-seq's to the packet itself. We kinda transform the
	 * dss-mapping to a per-packet granularity. This is necessary to
	 * correctly handle overlapping mappings coming from different
	 * subflows. Otherwise it would be a complete mess.
	 */
	tcb->data_seq = tp->map_data_seq + tcb->seq - tp->map_subseq;
	tcb->data_len = tcb->end_seq - tcb->seq;
	tcb->sub_seq = tcb->seq;
	tcb->end_data_seq = tcb->data_seq + tcb->data_len;
}

/**
 * @return: 1 if the skb must be dropped by the caller, otherwise 0
 */
static int mptcp_add_meta_ofo_queue(struct sock *meta_sk, struct tcp_sock *tp,
				    struct sk_buff *skb)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	if (!skb_peek(&meta_tp->out_of_order_queue)) {
		/* Initial out of order segment */
		__skb_queue_head(&meta_tp->out_of_order_queue, skb);
	} else {
		/* TODO_cpaasch - this code is heavily copied from tcp_input.c,
		 * tcp_data_queue(). Maybe it could get merged. */
		struct sk_buff *skb1 = skb_peek_tail(&meta_tp->out_of_order_queue);

		/* Find place to insert this segment. */
		while (1) {
			/* skb1->data_seq <= skb->data_seq -- found place */
			if (!after(TCP_SKB_CB(skb1)->data_seq,
				   TCP_SKB_CB(skb)->data_seq))
				break;
			/* Reached end */
			if (skb_queue_is_first(&meta_tp->out_of_order_queue, skb1)) {
				skb1 = NULL;
				break;
			}
			skb1 = skb_queue_prev(&meta_tp->out_of_order_queue, skb1);
		}

		/* Do skb overlap to previous one? */
		if (skb1 && before(TCP_SKB_CB(skb)->data_seq,
				   TCP_SKB_CB(skb1)->end_data_seq)) {
			/* skb->end_data_seq <= old_skb->end_data_seq ->
			 * All bits already present
			 */
			if (!after(TCP_SKB_CB(skb)->end_data_seq,
				   TCP_SKB_CB(skb1)->end_data_seq)) {
				/* All the bits are present. Drop. */
				return 1;
			}
			/* Is the new skb before or after skb1? */
			if (!after(TCP_SKB_CB(skb)->data_seq,
				   TCP_SKB_CB(skb1)->data_seq)) {
				/* It's before, thus update skb1 */
				if (skb_queue_is_first(&meta_tp->out_of_order_queue, skb1))
					skb1 = NULL;
				else
					skb1 = skb_queue_prev(&meta_tp->out_of_order_queue, skb1);
			}
		}

		if (!skb1)
			__skb_queue_head(&meta_tp->out_of_order_queue, skb);
		else
			__skb_queue_after(&meta_tp->out_of_order_queue, skb1, skb);


		/* And clean segments covered by new one as whole. */
		while (!skb_queue_is_last(&meta_tp->out_of_order_queue, skb)) {
			skb1 = skb_queue_next(&meta_tp->out_of_order_queue, skb);

			if (!after(TCP_SKB_CB(skb)->end_data_seq,
				   TCP_SKB_CB(skb1)->data_seq))
				break;
			if (before(TCP_SKB_CB(skb)->end_data_seq,
				   TCP_SKB_CB(skb1)->end_data_seq))
				break;

			__skb_unlink(skb1, &meta_tp->out_of_order_queue);
			__kfree_skb(skb1);
		}
	}

	return 0;
}

/**
 * @return: 1 if the segment has been eaten and can be suppressed,
 *          otherwise 0.
 */
inline int direct_copy(struct sk_buff *skb, struct tcp_sock *tp,
		       struct tcp_sock *meta_tp)
{
	int chunk = min_t(unsigned int, skb->len, meta_tp->ucopy.len);
	int eaten = 0;

	__set_current_state(TASK_RUNNING);

	local_bh_enable();
	if (!skb_copy_datagram_iovec(skb, 0, meta_tp->ucopy.iov, chunk)) {
		meta_tp->ucopy.len -= chunk;
		meta_tp->copied_seq += chunk;
		eaten = (chunk == skb->len);
	}
	local_bh_disable();
	return eaten;
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

	if (!skb->len && tcp_hdr(skb)->fin &&
	    !(TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN)) {
		/* Pure subflow FIN (without DFIN)
		 * just update subflow and return
		 */
		tp->copied_seq++;
		return 1;
	}

	/* If there is a DSS-mapping, check if it is ok with the current
	 * expected mapping. If anything is wrong, reset the subflow
	 */
	if (tcb->mptcp_flags & MPTCPHDR_SEQ) {
		if (tp->map_data_len &&
		    (tcb->data_seq != tp->map_data_seq ||
		     tcb->sub_seq != tp->map_subseq ||
		     tcb->data_len != tp->map_data_len)) {
			/* Mapping in packet is different from what we want */
			mptcp_debug("%s destroying subflow with pi %d from mpcb "
				    "with token %08x\n", __func__,
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

		if (!tp->map_data_len) {
			if (!before(tcb->sub_seq, tcb->end_seq) ||
			    before(tcb->sub_seq + tcb->data_len, tcb->seq)) {
				/* Subflow-sequences of packet is different from
				 * what is in the packet's dss-mapping.
				 * The peer is misbehaving - reset
				 */
				mptcp_debug("%s destroying subflow with pi %d "
					    "from mpcb with token %08x\n",
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
		}
	}

	/* The skb goes into the sub-rcv queue in all cases.
	 * This allows more generic skb management in the next lines although
	 * it may be removed in few lines (direct copy to the app).
	 */
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	skb_set_owner_r(skb, sk);
	tp->rcv_nxt = tcb->end_seq;

	/* Now, remove old sk_buff's from the receive-queue.
	 * This may happen if the mapping has been lost for these segments and
	 * the next mapping has already been received.
	 */
	if (tp->map_data_len && before(tp->copied_seq, tp->map_subseq)) {
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
	if (tp->map_data_len &&
	    !before(tp->rcv_nxt, tp->map_subseq + tp->map_data_len)) {
		/* Verify the checksum first */
		if (mpcb->rx_opt.dss_csum && mptcp_verif_dss_csum(sk))
			return -1;

		/* Is this an overlapping mapping? rcv_nxt >= end_data_seq */
		if (!before(meta_tp->rcv_nxt, tp->map_data_seq +
			    tp->map_data_len)) {
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				/* seq >= end_sub_mapping */
				if (!before(TCP_SKB_CB(tmp1)->seq,
					    tp->map_subseq + tp->map_data_len))
					break;
				__skb_unlink(tmp1, &sk->sk_receive_queue);

				tp->copied_seq = TCP_SKB_CB(tmp1)->end_seq;

				/* the callers of mptcp_queue_skb still
				 * need the skb
				 */
				if (skb != tmp1)
					__kfree_skb(tmp1);
			}

			tp->map_data_len = 0;
			tp->map_data_seq = 0;
			tp->map_subseq = 0;

			/* We want tcp_data(/ofo)_queue to free skb. */
			return 1;
		}

		if (before(meta_tp->rcv_nxt, tp->map_data_seq)) {
			/* Seg's have to go to the meta-ofo-queue */
			skb_queue_walk_safe(&sk->sk_receive_queue, tmp1, tmp) {
				if (after(TCP_SKB_CB(tmp1)->end_seq,
					  tp->map_subseq + tp->map_data_len))
					break;

				mptcp_prepare_skb(tmp1, tp);

				__skb_unlink(tmp1, &sk->sk_receive_queue);
				tp->copied_seq = TCP_SKB_CB(tmp1)->end_seq;
				skb_set_owner_r(tmp1, meta_sk);

				if (mptcp_add_meta_ofo_queue(meta_sk, tp,
							     tmp1)) {
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
					  tp->map_subseq + tp->map_data_len))
					break;

				mptcp_prepare_skb(tmp1, tp);
				__skb_unlink(tmp1, &sk->sk_receive_queue);

				/* Is direct copy possible ? */
				if (TCP_SKB_CB(tmp1)->data_seq ==
				    meta_tp->rcv_nxt &&
				    meta_tp->ucopy.task == current &&
				    meta_tp->copied_seq == meta_tp->rcv_nxt &&
				    meta_tp->ucopy.len &&
				    sock_owned_by_user(mpcb->master_sk)) {
					eaten = direct_copy(tmp1, tp, meta_tp);
				}
				if (!eaten)
					__skb_queue_tail(
						&meta_sk->sk_receive_queue,
						tmp1);
				meta_tp->rcv_nxt =
					TCP_SKB_CB(tmp1)->end_data_seq;

				if (TCP_SKB_CB(tmp1)->mptcp_flags & MPTCPHDR_FIN)
					mptcp_fin(mpcb);

				/* Check if this fills a gap in the ofo queue */
				if (!skb_queue_empty(
					    &meta_tp->out_of_order_queue))
					mptcp_ofo_queue(mpcb);

				tp->copied_seq =
					TCP_SKB_CB(tmp1)->end_seq;
				if (!eaten)
					skb_set_owner_r(tmp1, meta_sk);
				else if (tmp1 != skb)
					__kfree_skb(tmp1);
				else
					ans = 1;
			}
			if (!sock_flag(meta_sk, SOCK_DEAD))
				sk->sk_data_ready(sk, 0);
		}

		tp->map_data_len = 0;
		tp->map_data_seq = 0;
		tp->map_subseq = 0;
	}

	if (old_copied != tp->copied_seq)
		tcp_rcv_space_adjust(sk);

	return ans;
}

void mptcp_skb_entail_init(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* in MPTCP mode, the subflow seqnum is given later */
	if (tp->mpc) {
		struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
		struct multipath_pcb *mpcb = mpcb_from_tcpsock(tp);
		struct tcp_sock *meta_tp = (struct tcp_sock *)mpcb;
		tcb->seq      = tcb->end_seq = tcb->sub_seq = 0;
		tcb->data_seq = tcb->end_data_seq = meta_tp->write_seq;
		tcb->data_len = 0;
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

void mptcp_set_data_size(struct tcp_sock *tp, struct sk_buff *skb, int copy)
{
	if (tp->mpc) {
		TCP_SKB_CB(skb)->data_len += copy;
		TCP_SKB_CB(skb)->end_data_seq += copy;
	}
}

/* From net/ipv4/tcp.c */
static inline void tcp_mark_push(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPHDR_PSH;
	tp->pushed_seq = tp->write_seq;
}

/* From net/ipv4/tcp.c */
static inline int forced_push(struct tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

/* From net/ipv4/tcp.c */
static inline void tcp_mark_urg(struct tcp_sock *tp, int flags)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;
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

/* Algorithm by Bryan Kernighan to count bits in a word */
static inline int count_bits(unsigned int v)
{
	unsigned int c; /* c accumulates the total bits set in v */
	for (c = 0; v; c++)
		v &= v - 1; /* clear the least significant bit set */
	return c;
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
		int clone_it)
{
	struct sk_buff *skb;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk), *tmp_tp;
	struct sock *sk_it;

	/* A segment can be added to the reinject queue only if
	 * there is at least one working subflow that has never sent
	 * this data */
	mptcp_for_each_sk(meta_tp->mpcb, sk_it, tmp_tp) {
		if (sk_it->sk_state != TCP_ESTABLISHED)
			continue;
		/* If the skb has already been enqueued in this sk, try to find
		 * another one */
		if (PI_TO_FLAG(tmp_tp->path_index) & orig_skb->path_mask)
			continue;

		/* candidate subflow found, we can reinject */
		break;
	}

	if (!sk_it) {
		mptcp_debug("%s: skb already injected to all paths\n",
				__func__);
		return 1; /* no candidate found */
	}

	if (clone_it)
		skb = skb_clone(orig_skb, GFP_ATOMIC);
	else {
		skb_unlink(orig_skb, &orig_skb->sk->sk_write_queue);
		mptcp_wmem_free_skb(orig_skb->sk, orig_skb);
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
	struct sk_buff *skb_it;
	struct tcp_sock *tp = tcp_sk(sk);
	struct multipath_pcb *mpcb = tp->mpcb;
	struct sock *meta_sk = (struct sock *) mpcb;

	BUG_ON(is_meta_sk(sk));

	verif_wqueues(mpcb);

	tcp_for_write_queue(skb_it, sk) {
		/* seq > reinjected_seq , to avoid reinjecting several times
		 * the same segment */
		if (!after(TCP_SKB_CB(skb_it)->seq, tp->reinjected_seq))
			continue;
		skb_it->path_mask |= PI_TO_FLAG(tp->path_index);
		if (__mptcp_reinject_data(skb_it, meta_sk, clone_it) < 0)
			break;
		tp->reinjected_seq = TCP_SKB_CB(skb_it)->seq;
	}

	tcpprobe_logmsg(sk, "after reinj, reinj queue size:%d",
			skb_queue_len(&mpcb->reinject_queue));

	tcp_push(meta_sk, 0, mptcp_sysctl_mss(), TCP_NAGLE_PUSH);

	if (tp->pf == 0)
		tcpprobe_logmsg(sk, "pi %d: entering pf state",
				tp->path_index);
	tp->pf = 1;

	verif_wqueues(mpcb);
}

void mptcp_parse_options(uint8_t *ptr, int opsize,
		struct tcp_options_received *opt_rx,
		struct multipath_options *mopt,
		struct sk_buff *skb)
{
	struct mptcp_option *mp_opt = (struct mptcp_option *) ptr;

	switch (mp_opt->sub) {
	case MPTCP_SUB_CAPABLE:
	{
		struct mp_capable *mpcapable = (struct mp_capable *) ptr;

		if (opsize != MPTCP_SUB_LEN_CAPABLE_SYN &&
		    opsize != MPTCP_SUB_LEN_CAPABLE_SYNACK &&
		    opsize != MPTCP_SUB_LEN_CAPABLE_ACK) {
			mptcp_debug("%s: mp_capable: bad option size %d\n",
					__func__, opsize);
			break;
		}

		if (!sysctl_mptcp_enabled)
			break;

		if (!mopt) {
			mptcp_debug("%s Saw MP_CAPABLE but no mopt provided\n",
					__func__);
			break;
		}

		opt_rx->saw_mpc = 1;
		mopt->list_rcvd = 1;
		mopt->dss_csum = sysctl_mptcp_checksum || mpcapable->c;

		if (opsize >= MPTCP_SUB_LEN_CAPABLE_SYNACK) {
			ptr += 2;
			mopt->mptcp_rem_key = *((__u64*)ptr);
		}

		if (opsize == MPTCP_SUB_LEN_CAPABLE_ACK) {
			/* This only necessary for SYN-cookies */
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

		if (!mopt) {
			mptcp_debug("%s Saw MP_JOIN but no mopt provided\n",
					__func__);
			break;
		}

		switch (opsize) {
			case MPTCP_SUB_LEN_JOIN_SYN:
				mopt->mptcp_rem_token = *((u32*)(ptr + 2));
				mopt->mptcp_recv_random_number = *((u32*)(ptr + 6));
				break;
			case MPTCP_SUB_LEN_JOIN_SYNACK:
				ptr += 2;
				mopt->mptcp_recv_tmac = *((__u64 *)ptr);
				ptr += 8;
				mopt->mptcp_recv_random_number = *((u32 *)ptr);
				break;
			case MPTCP_SUB_LEN_JOIN_ACK:
				ptr += 2;
				memcpy(mopt->mptcp_recv_mac, ptr, 20);
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
			TCP_SKB_CB(skb)->data_ack = ntohl(*(uint32_t *)ptr);
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
			TCP_SKB_CB(skb)->data_seq = ntohl(*(uint32_t *) ptr);
			TCP_SKB_CB(skb)->sub_seq =
					ntohl(*(uint32_t *)(ptr + 4)) +
					opt_rx->rcv_isn;
			TCP_SKB_CB(skb)->data_len =
					ntohs(*(uint16_t *)(ptr + 8));
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
	default:
		mptcp_debug("%s: Received unkown subtype: %d\n", __func__,
				mp_opt->sub);
		break;
	}
}

/**
 * Cleans the meta-socket retransmission queue.
 * @sk must be the metasocket.
 */
void mptcp_clean_rtx_queue(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	BUG_ON(!is_meta_tp(tp));

	while ((skb = tcp_write_queue_head(sk)) && skb != tcp_send_head(sk)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		if (before(tp->snd_una, scb->end_data_seq))
			break;

		tcp_unlink_write_queue(skb, sk);
		tp->packets_out -= tcp_skb_pcount(skb);
		sk_wmem_free_skb(sk, skb);
	}
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
	u32 new_clamp = 0, new_rcv_ssthresh = 0, new_rcvbuf = 0;

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
	meta_sk->sk_rcvbuf = new_rcvbuf;
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
	meta_sk->sk_sndbuf = new_sndbuf;
}

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
void verif_wqueues(struct multipath_pcb *mpcb)
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
		skb_queue_walk(&tp->out_of_order_queue, skb) {
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
#else
void verif_rqueues(struct multipath_pcb *mpcb)
{
	return;
}
#endif

/**
 * Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Otherwise sets @reinject to 0.
 */
struct sk_buff *mptcp_next_segment(struct sock *sk, int *reinject)
{
	struct multipath_pcb *mpcb = tcp_sk(sk)->mpcb;
	struct sk_buff *skb;
	if (reinject)
		*reinject = 0;
	if (!is_meta_sk(sk))
		return tcp_send_head(sk);
	skb = skb_peek(&mpcb->reinject_queue);
	if (skb) {
		if (reinject)
			*reinject = 1;
		return skb;
	} else {
		return tcp_send_head(sk);
	}
}

/**
 * Sets the socket pointer of the meta_sk after an accept at the socket level
 * Set also the sk_wq pointer, because it has just been copied by
 * sock_graft()
 */
void mptcp_check_socket(struct sock *sk)
{
	if (sk->sk_protocol == IPPROTO_TCP && tcp_sk(sk)->mpcb) {
		struct sock *meta_sk = (struct sock *) (tcp_sk(sk)->mpcb);
		sk_set_socket(meta_sk, sk->sk_socket);
		meta_sk->sk_wq = sk->sk_wq;
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
		TCP_SKB_CB(skb)->flags |= TCPHDR_FIN;
		TCP_SKB_CB(skb)->data_len++;
		TCP_SKB_CB(skb)->end_data_seq++;
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN;
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
		tcp_init_nondata_skb(skb, 0, TCPHDR_ACK | TCPHDR_FIN);
		TCP_SKB_CB(skb)->data_seq = meta_tp->write_seq;
		TCP_SKB_CB(skb)->data_len = 1;
		TCP_SKB_CB(skb)->end_data_seq = meta_tp->write_seq + 1;
		TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FIN;
		/* FIN eats a sequence byte, write_seq advanced by
		 * tcp_queue_skb().
		 */
		tcp_queue_skb(meta_sk, skb);
	}
	__tcp_push_pending_frames(meta_sk, mptcp_sysctl_mss(), TCP_NAGLE_OFF);
}

void mptcp_close(struct sock *master_sk, long timeout)
{
	struct multipath_pcb *mpcb;
	struct sock *meta_sk = NULL;
	struct tcp_sock *meta_tp = NULL;
	struct sock *subsk;
	struct tcp_sock *subtp;
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	mptcp_debug("%s: Close of meta_sk\n", __func__);

	lock_sock(master_sk);
	mpcb = (tcp_sk(master_sk)->mpc) ? tcp_sk(master_sk)->mpcb : NULL;

	/* destroy the mpcb, it will really disappear when the last subsock
	 * is destroyed
	 */
	if (mpcb) {
		meta_sk = (struct sock *) mpcb;
		meta_tp = tcp_sk(meta_sk);
		sock_hold(master_sk);
		mptcp_destroy_mpcb(mpcb);
	} else {
		sock_hold(master_sk); /* needed to keep the pointer until the
				       * release_sock()
				       */
		tcp_close(master_sk, timeout);
		release_sock(master_sk);
		sock_put(master_sk);
		return;
	}

	meta_sk->sk_shutdown = SHUTDOWN_MASK;

	/* We need to flush the recv. buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&meta_sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_data_seq
				- TCP_SKB_CB(skb)->data_seq
				- ((TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN) ? 1 : 0);
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(meta_sk);

	if (tcp_close_state(meta_sk)) {
		mptcp_send_fin(meta_sk);
	} else if (meta_tp->snd_nxt == meta_tp->write_seq) {
		struct sock *sk_it, *sk_tmp;
		/* The FIN has been sent already, we need to
		 * call tcp_close() on the subsocks
		 * ourselves.
		 */
		mptcp_for_each_sk_safe(mpcb, sk_it, sk_tmp)
			tcp_close(sk_it, 0);
	}

	sk_stream_wait_close(meta_sk, timeout);

	state = meta_sk->sk_state;
	sock_orphan(meta_sk);
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

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(master_sk);
	sock_put(master_sk); /* Taken by sock_hold */
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
	if (!sysctl_mptcp_enabled)
		return 0;
	if ((sk->sk_family == AF_INET &&
	     ipv4_is_loopback(inet_sk(sk)->inet_daddr)) ||
	    (sk->sk_family == AF_INET6 &&
	     ipv6_addr_loopback(&inet6_sk(sk)->daddr)))
		return 0;
	if (is_local_addr4(inet_sk(sk)->inet_daddr))
		return 0;
	return 1;
}

/**
 * Prepares fallback to regular TCP.
 * The master sk is detached and the mpcb structure is destroyed.
 */
static void __mptcp_fallback(struct sock *master_sk)
{
	struct tcp_sock *master_tp = tcp_sk(master_sk);
	struct multipath_pcb *mpcb = mpcb_from_tcpsock(master_tp);
	struct sock *meta_sk = (struct sock *)mpcb;

	if (!mpcb)
		return; /* Fallback is already done */

	if (sock_flag(meta_sk, SOCK_DEAD))
		/* mptcp_destroy_mpcb() already called. No need to fallback. */
		return;

	sock_hold(master_sk);
	master_sk->sk_error_report = sock_def_error_report;
	mptcp_destroy_mpcb(mpcb);
	mpcb_release(mpcb);
	master_tp->mpcb = NULL;
	sock_put(master_sk);
}

void mptcp_fallback_wq(struct work_struct *work)
{
	struct sock *master_sk = *(struct sock **)(work + 1);
	lock_sock(master_sk);
	__mptcp_fallback(master_sk);
	release_sock(master_sk);
	sock_put(master_sk);
	kfree(work);
}

void mptcp_fallback(struct sock *master_sk)
{
	if (in_interrupt()) {
		struct work_struct *work = kmalloc(sizeof(*work) +
						sizeof(struct sock *),
						GFP_ATOMIC);
		struct sock **sk = (struct sock **)(work + 1);

		*sk = master_sk;
		sock_hold(master_sk);
		INIT_WORK(work, mptcp_fallback_wq);
		schedule_work(work);
	} else {
		__mptcp_fallback(master_sk);
	}
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
			oldstate != TCP_SYN_RECV && oldstate != TCP_LISTEN) {
			mptcp_debug("%s - before minus --- tcp_sk(sk)->mpcb->"
					"cnt_established:%d pi:%d\n", __func__,
					tcp_sk(sk)->mpcb->cnt_established,
					tp->path_index);
			tcp_sk(sk)->mpcb->cnt_established--;
		}
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

		req->mptcp_rem_key = mopt->mptcp_rem_key;

		if (mptcp_alloc_mpcb(child, req, GFP_ATOMIC)) {
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

		mpcb->rx_opt.dss_csum =
				sysctl_mptcp_checksum || req->dss_csum;

		set_bit(MPCB_FLAG_SERVER_SIDE, &mpcb->flags);
		/* Will be moved to ESTABLISHED by
		 * tcp_rcv_state_process()
		 */
		((struct sock *)mpcb)->sk_state = TCP_SYN_RECV;
		mptcp_update_metasocket(child, mpcb);
	} else
		child_tp->mpcb = NULL;

	return 0;
}

struct sock *mptcp_check_req_child(struct sock *sk, struct sock *child,
		struct request_sock *req, struct request_sock **prev)
{
	struct tcp_sock *child_tp = tcp_sk(child);
	struct multipath_pcb *mpcb = req->mpcb;
	u8 hash_mac_check[20];

	BUG_ON(!mpcb);

	mptcp_hmac_sha1((u8 *)&mpcb->rx_opt.mptcp_rem_key,
			(u8 *)&mpcb->mptcp_loc_key,
			(u8 *)&req->mptcp_rem_random_number,
			(u8 *)&req->mptcp_loc_random_number,
			(u32 *)hash_mac_check);

	if (memcmp(hash_mac_check, (char *)&mpcb->rx_opt.mptcp_recv_mac, 20)) {
		sock_orphan(child);
		child_tp->teardown = 1;
		return sk;
	}

	/* The child is a clone of the meta socket, we must now reset
	 * some of the fields
	 */
	child_tp->mpc = 1;
	child_tp->slave_sk = 1;
	child_tp->bw_est.time = 0;
	child->sk_sndmsg_page = NULL;

	inet_sk(child)->loc_id = mptcp_get_loc_addrid(mpcb, child);
	inet_sk(child)->rem_id = req->rem_id;

	/* Child_tp->mpcb has been cloned from the master_sk
	 * We need to increase the master_sk refcount
	 */
	sock_hold(mpcb->master_sk);

	/* Deleting from global hashtable */
	mptcp_hash_request_remove(req);

	/* Subflows do not use the accept queue, as they
	 * are attached immediately to the mpcb.
	 */
	inet_csk_reqsk_queue_drop(sk, req, prev);
	return child;
}

void mptcp_select_window(struct tcp_sock *tp, u32 new_win)
{
	struct sock *tmp_sk;
	struct tcp_sock *tmp_tp, *meta_tp = (struct tcp_sock *)(tp->mpcb);
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
	return 0;
}
module_init(mptcp_init);

MODULE_LICENSE("GPL");
