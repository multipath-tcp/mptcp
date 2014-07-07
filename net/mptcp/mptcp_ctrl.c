/*
 *	MPTCP implementation - MPTCP-control
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

#include <net/inet_common.h>
#include <net/inet6_hashtables.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <net/mptcp_v6.h>
#endif
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/transp_v6.h>
#include <net/xfrm.h>

#include <linux/cryptohash.h>
#include <linux/kconfig.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/random.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/sysctl.h>

static struct kmem_cache *mptcp_sock_cache __read_mostly;
static struct kmem_cache *mptcp_cb_cache __read_mostly;
static struct kmem_cache *mptcp_tw_cache __read_mostly;

int sysctl_mptcp_enabled __read_mostly = 1;
int sysctl_mptcp_checksum __read_mostly = 1;
int sysctl_mptcp_debug __read_mostly;
EXPORT_SYMBOL(sysctl_mptcp_debug);
int sysctl_mptcp_syn_retries __read_mostly = 3;

bool mptcp_init_failed __read_mostly;

struct static_key mptcp_static_key = STATIC_KEY_INIT_FALSE;
EXPORT_SYMBOL(mptcp_static_key);

static int proc_mptcp_path_manager(ctl_table *ctl, int write,
				   void __user *buffer, size_t *lenp,
				   loff_t *ppos)
{
	char val[MPTCP_PM_NAME_MAX];
	ctl_table tbl = {
		.data = val,
		.maxlen = MPTCP_PM_NAME_MAX,
	};
	int ret;

	mptcp_get_default_path_manager(val);

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = mptcp_set_default_path_manager(val);
	return ret;
}

static struct ctl_table mptcp_table[] = {
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
		.procname = "mptcp_debug",
		.data = &sysctl_mptcp_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_syn_retries",
		.data = &sysctl_mptcp_syn_retries,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname	= "mptcp_path_manager",
		.mode		= 0644,
		.maxlen		= MPTCP_PM_NAME_MAX,
		.proc_handler	= proc_mptcp_path_manager,
	},
	{ }
};

static inline u32 mptcp_hash_tk(u32 token)
{
	return token % MPTCP_HASH_SIZE;
}

struct hlist_nulls_head tk_hashtable[MPTCP_HASH_SIZE];
EXPORT_SYMBOL(tk_hashtable);

/* This second hashtable is needed to retrieve request socks
 * created as a result of a join request. While the SYN contains
 * the token, the final ack does not, so we need a separate hashtable
 * to retrieve the mpcb.
 */
struct list_head mptcp_reqsk_htb[MPTCP_HASH_SIZE];
spinlock_t mptcp_reqsk_hlock;	/* hashtable protection */

/* The following hash table is used to avoid collision of token */
static struct hlist_nulls_head mptcp_reqsk_tk_htb[MPTCP_HASH_SIZE];
spinlock_t mptcp_tk_hashlock;	/* hashtable protection */

static int mptcp_reqsk_find_tk(u32 token)
{
	u32 hash = mptcp_hash_tk(token);
	struct mptcp_request_sock *mtreqsk;
	const struct hlist_nulls_node *node;

	hlist_nulls_for_each_entry_rcu(mtreqsk, node,
				       &mptcp_reqsk_tk_htb[hash], collide_tk) {
		if (token == mtreqsk->mptcp_loc_token)
			return 1;
	}
	return 0;
}

static void mptcp_reqsk_insert_tk(struct request_sock *reqsk, u32 token)
{
	u32 hash = mptcp_hash_tk(token);

	hlist_nulls_add_head_rcu(&mptcp_rsk(reqsk)->collide_tk,
				 &mptcp_reqsk_tk_htb[hash]);
}

static void mptcp_reqsk_remove_tk(struct request_sock *reqsk)
{
	rcu_read_lock();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_init_rcu(&mptcp_rsk(reqsk)->collide_tk);
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock();
}

void mptcp_reqsk_destructor(struct request_sock *req)
{
	if (!mptcp_rsk(req)->mpcb) {
		if (in_softirq()) {
			mptcp_reqsk_remove_tk(req);
		} else {
			rcu_read_lock_bh();
			spin_lock(&mptcp_tk_hashlock);
			hlist_nulls_del_init_rcu(&mptcp_rsk(req)->collide_tk);
			spin_unlock(&mptcp_tk_hashlock);
			rcu_read_unlock_bh();
		}
	} else {
		mptcp_hash_request_remove(req);
	}
}

static void __mptcp_hash_insert(struct tcp_sock *meta_tp, u32 token)
{
	u32 hash = mptcp_hash_tk(token);
	hlist_nulls_add_head_rcu(&meta_tp->tk_table, &tk_hashtable[hash]);
	meta_tp->inside_tk_table = 1;
}

static int mptcp_find_token(u32 token)
{
	u32 hash = mptcp_hash_tk(token);
	struct tcp_sock *meta_tp;
	const struct hlist_nulls_node *node;

	hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[hash], tk_table) {
		if (token == meta_tp->mptcp_loc_token)
			return 1;
	}
	return 0;
}

static void mptcp_set_key_reqsk(struct request_sock *req,
				const struct sk_buff *skb)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);

	if (skb->protocol == htons(ETH_P_IP)) {
		mtreq->mptcp_loc_key = mptcp_v4_get_key(ip_hdr(skb)->saddr,
						        ip_hdr(skb)->daddr,
						        htons(ireq->ir_num),
						        ireq->ir_rmt_port);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		mtreq->mptcp_loc_key = mptcp_v6_get_key(ipv6_hdr(skb)->saddr.s6_addr32,
							ipv6_hdr(skb)->daddr.s6_addr32,
							htons(ireq->ir_num),
							ireq->ir_rmt_port);
#endif
	}

	mptcp_key_sha1(mtreq->mptcp_loc_key, &mtreq->mptcp_loc_token, NULL);
}

/* New MPTCP-connection request, prepare a new token for the meta-socket that
 * will be created in mptcp_check_req_master(), and store the received token.
 */
void mptcp_reqsk_new_mptcp(struct request_sock *req,
			   const struct mptcp_options_received *mopt,
			   const struct sk_buff *skb)
{
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);

	tcp_rsk(req)->saw_mpc = 1;

	rcu_read_lock();
	spin_lock(&mptcp_tk_hashlock);
	do {
		mptcp_set_key_reqsk(req, skb);
	} while (mptcp_reqsk_find_tk(mtreq->mptcp_loc_token) ||
		 mptcp_find_token(mtreq->mptcp_loc_token));

	mptcp_reqsk_insert_tk(req, mtreq->mptcp_loc_token);
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock();
	mtreq->mptcp_rem_key = mopt->mptcp_key;
}

static void mptcp_set_key_sk(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *isk = inet_sk(sk);

	if (sk->sk_family == AF_INET)
		tp->mptcp_loc_key = mptcp_v4_get_key(isk->inet_saddr,
						     isk->inet_daddr,
						     isk->inet_sport,
						     isk->inet_dport);
#if IS_ENABLED(CONFIG_IPV6)
	else
		tp->mptcp_loc_key = mptcp_v6_get_key(inet6_sk(sk)->saddr.s6_addr32,
						     sk->sk_v6_daddr.s6_addr32,
						     isk->inet_sport,
						     isk->inet_dport);
#endif

	mptcp_key_sha1(tp->mptcp_loc_key,
		       &tp->mptcp_loc_token, NULL);
}

void mptcp_connect_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	rcu_read_lock_bh();
	spin_lock(&mptcp_tk_hashlock);
	do {
		mptcp_set_key_sk(sk);
	} while (mptcp_reqsk_find_tk(tp->mptcp_loc_token) ||
		 mptcp_find_token(tp->mptcp_loc_token));

	__mptcp_hash_insert(tp, tp->mptcp_loc_token);
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock_bh();
}

/**
 * This function increments the refcount of the mpcb struct.
 * It is the responsibility of the caller to decrement when releasing
 * the structure.
 */
struct sock *mptcp_hash_find(struct net *net, u32 token)
{
	u32 hash = mptcp_hash_tk(token);
	struct tcp_sock *meta_tp;
	struct sock *meta_sk = NULL;
	struct hlist_nulls_node *node;

	rcu_read_lock();
	hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[hash],
				       tk_table) {
		meta_sk = (struct sock *)meta_tp;
		if (token == meta_tp->mptcp_loc_token &&
		    net_eq(net, sock_net(meta_sk)) &&
		    atomic_inc_not_zero(&meta_sk->sk_refcnt))
			break;
		meta_sk = NULL;
	}
	rcu_read_unlock();
	return meta_sk;
}

void mptcp_hash_remove_bh(struct tcp_sock *meta_tp)
{
	/* remove from the token hashtable */
	rcu_read_lock_bh();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_init_rcu(&meta_tp->tk_table);
	meta_tp->inside_tk_table = 0;
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock_bh();
}

void mptcp_hash_remove(struct tcp_sock *meta_tp)
{
	rcu_read_lock();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_init_rcu(&meta_tp->tk_table);
	meta_tp->inside_tk_table = 0;
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock();
}

static struct sock *mptcp_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
					struct request_sock *req,
					struct dst_entry *dst)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return tcp_v6_syn_recv_sock(sk, skb, req, dst);

	/* sk->sk_family == AF_INET */
	if (req->rsk_ops->family == AF_INET6)
		return mptcp_v6v4_syn_recv_sock(sk, skb, req, dst);
#endif

	/* sk->sk_family == AF_INET && req->rsk_ops->family == AF_INET */
	return tcp_v4_syn_recv_sock(sk, skb, req, dst);
}

struct sock *mptcp_select_ack_sock(const struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sock *sk, *rttsk = NULL, *lastsk = NULL;
	u32 min_time = 0, last_active = 0;

	mptcp_for_each_sk(meta_tp->mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		u32 elapsed;

		if (!mptcp_sk_can_send_ack(sk) || tp->pf)
			continue;

		elapsed = keepalive_time_elapsed(tp);

		/* We take the one with the lowest RTT within a reasonable
		 * (meta-RTO)-timeframe
		 */
		if (elapsed < inet_csk(meta_sk)->icsk_rto) {
			if (!min_time || tp->srtt < min_time) {
				min_time = tp->srtt;
				rttsk = sk;
			}
			continue;
		}

		/* Otherwise, we just take the most recent active */
		if (!rttsk && (!last_active || elapsed < last_active)) {
			last_active = elapsed;
			lastsk = sk;
		}
	}

	if (rttsk)
		return rttsk;

	return lastsk;
}
EXPORT_SYMBOL(mptcp_select_ack_sock);

static void mptcp_sock_def_error_report(struct sock *sk)
{
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;

	if (!sock_flag(sk, SOCK_DEAD))
		mptcp_sub_close(sk, 0);

	if (mpcb->infinite_mapping_rcv || mpcb->infinite_mapping_snd ||
	    mpcb->send_infinite_mapping) {
		struct sock *meta_sk = mptcp_meta_sk(sk);

		meta_sk->sk_err = sk->sk_err;
		meta_sk->sk_err_soft = sk->sk_err_soft;

		if (!sock_flag(meta_sk, SOCK_DEAD))
			meta_sk->sk_error_report(meta_sk);

		tcp_done(meta_sk);
	}

	sk->sk_err = 0;
	return;
}

static void mptcp_mpcb_put(struct mptcp_cb *mpcb)
{
	if (atomic_dec_and_test(&mpcb->mpcb_refcnt)) {
		mptcp_cleanup_path_manager(mpcb);
		kmem_cache_free(mptcp_cb_cache, mpcb);
	}
}

static void mptcp_sock_destruct(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	inet_sock_destruct(sk);

	BUG_ON(!list_empty(&tp->mptcp->cb_list));

	kmem_cache_free(mptcp_sock_cache, tp->mptcp);
	tp->mptcp = NULL;

	if (!is_meta_sk(sk) && !tp->was_meta_sk) {
		/* Taken when mpcb pointer was set */
		sock_put(mptcp_meta_sk(sk));
		mptcp_mpcb_put(tp->mpcb);
	} else {
		struct mptcp_cb *mpcb = tp->mpcb;
		struct mptcp_tw *mptw;

		/* The mpcb is disappearing - we can make the final
		 * update to the rcv_nxt of the time-wait-sock and remove
		 * its reference to the mpcb.
		 */
		spin_lock_bh(&mpcb->tw_lock);
		list_for_each_entry_rcu(mptw, &mpcb->tw_list, list) {
			list_del_rcu(&mptw->list);
			mptw->in_list = 0;
			mptcp_mpcb_put(mpcb);
			rcu_assign_pointer(mptw->mpcb, NULL);
		}
		spin_unlock_bh(&mpcb->tw_lock);

		mptcp_mpcb_put(mpcb);

		mptcp_debug("%s destroying meta-sk\n", __func__);
	}

	WARN_ON(!static_key_false(&mptcp_static_key));
	/* Must be the last call, because is_meta_sk() above still needs the
	 * static key
	 */
	static_key_slow_dec(&mptcp_static_key);

}

void mptcp_destroy_sock(struct sock *sk)
{
	if (is_meta_sk(sk)) {
		struct sock *sk_it, *tmpsk;

		__skb_queue_purge(&tcp_sk(sk)->mpcb->reinject_queue);
		mptcp_purge_ofo_queue(tcp_sk(sk));

		/* We have to close all remaining subflows. Normally, they
		 * should all be about to get closed. But, if the kernel is
		 * forcing a closure (e.g., tcp_write_err), the subflows might
		 * not have been closed properly (as we are waiting for the
		 * DATA_ACK of the DATA_FIN).
		 */
		mptcp_for_each_sk_safe(tcp_sk(sk)->mpcb, sk_it, tmpsk) {
			/* Already did call tcp_close - waiting for graceful
			 * closure, or if we are retransmitting fast-close on
			 * the subflow. The reset (or timeout) will kill the
			 * subflow..
			 */
			if (tcp_sk(sk_it)->closing ||
			    tcp_sk(sk_it)->send_mp_fclose)
				continue;

			/* Allow the delayed work first to prevent time-wait state */
			if (delayed_work_pending(&tcp_sk(sk_it)->mptcp->work))
				continue;

			mptcp_sub_close(sk_it, 0);
		}
	} else {
		mptcp_del_sock(sk);
	}
}

static void mptcp_set_state(struct sock *sk)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);

	/* Meta is not yet established - wake up the application */
	if ((1 << meta_sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV) &&
	    sk->sk_state == TCP_ESTABLISHED) {
		tcp_set_state(meta_sk, TCP_ESTABLISHED);

		if (!sock_flag(meta_sk, SOCK_DEAD)) {
			meta_sk->sk_state_change(meta_sk);
			sk_wake_async(meta_sk, SOCK_WAKE_IO, POLL_OUT);
		}
	}

	if (sk->sk_state == TCP_ESTABLISHED) {
		tcp_sk(sk)->mptcp->establish_increased = 1;
		tcp_sk(sk)->mpcb->cnt_established++;
	}
}

u32 mptcp_secret[MD5_MESSAGE_BYTES / 4] ____cacheline_aligned;
u32 mptcp_seed = 0;

void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u32 mptcp_hashed_key[SHA_DIGEST_WORDS];
	u8 input[64];
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Initialize input with appropriate padding */
	memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too */
	memcpy(input, &key, sizeof(key)); /* Copy key to the msg beginning */
	input[8] = 0x80; /* Padding: First bit after message = 1 */
	input[63] = 0x40; /* Padding: Length of the message = 64 bits */

	sha_init(mptcp_hashed_key);
	sha_transform(mptcp_hashed_key, input, workspace);

	for (i = 0; i < 5; i++)
		mptcp_hashed_key[i] = cpu_to_be32(mptcp_hashed_key[i]);

	if (token)
		*token = mptcp_hashed_key[0];
	if (idsn)
		*idsn = *((u64 *)&mptcp_hashed_key[3]);
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

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);

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

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);
}

static void mptcp_mpcb_inherit_sockopts(struct sock *meta_sk, struct sock *master_sk)
{
	/* Socket-options handled by mptcp_inherit_sk while creating the meta-sk.
	 * ======
	 * SO_SNDBUF, SO_SNDBUFFORCE, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT,
	 * SO_RCVTIMEO, SO_SNDTIMEO, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	 * TCP_NODELAY, TCP_CORK
	 *
	 * Socket-options handled in this function here
	 * ======
	 * TCP_DEFER_ACCEPT
	 *
	 * Socket-options on the todo-list
	 * ======
	 * SO_BINDTODEVICE - should probably prevent creation of new subsocks
	 *		     across other devices. - what about the api-draft?
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
	 *		in mptcp_retransmit_timer. AND we need to check what is
	 *		about the subsockets.
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
	 * TCP_QUICKACK
	 * SO_KEEPALIVE
	 */

	/****** DEFER_ACCEPT-handler ******/

	/* DEFER_ACCEPT is not of concern for new subflows - we always accept
	 * them
	 */
	inet_csk(meta_sk)->icsk_accept_queue.rskq_defer_accept = 0;
}

static void mptcp_sub_inherit_sockopts(struct sock *meta_sk, struct sock *sub_sk)
{
	/* IP_TOS also goes to the subflow. */
	if (inet_sk(sub_sk)->tos != inet_sk(meta_sk)->tos) {
		inet_sk(sub_sk)->tos = inet_sk(meta_sk)->tos;
		sub_sk->sk_priority = meta_sk->sk_priority;
		sk_dst_reset(sub_sk);
	}

	/* Inherit SO_REUSEADDR */
	sub_sk->sk_reuse = meta_sk->sk_reuse;

	/* Inherit snd/rcv-buffer locks */
	sub_sk->sk_userlocks = meta_sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;
}

int mptcp_backlog_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	/* skb-sk may be NULL if we receive a packet immediatly after the
	 * SYN/ACK + MP_CAPABLE.
	 */
	struct sock *sk = skb->sk ? skb->sk : meta_sk;
	int ret = 0;

	skb->sk = NULL;

	if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt))) {
		kfree_skb(skb);
		return 0;
	}

	if (sk->sk_family == AF_INET)
		ret = tcp_v4_do_rcv(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	else
		ret = tcp_v6_do_rcv(sk, skb);
#endif

	sock_put(sk);
	return ret;
}

struct lock_class_key meta_key;
struct lock_class_key meta_slock_key;

/* Code heavily inspired from sk_clone() */
static int mptcp_inherit_sk(const struct sock *sk, struct sock *newsk,
			    int family, const gfp_t flags)
{
	struct sk_filter *filter;
	struct proto *prot = newsk->sk_prot;
	const struct inet_connection_sock_af_ops *af_ops = inet_csk(newsk)->icsk_af_ops;
#ifdef CONFIG_SECURITY_NETWORK
	void *sptr = newsk->sk_security;
#endif

	if (sk->sk_family == AF_INET) {
		memcpy(newsk, sk, offsetof(struct sock, sk_dontcopy_begin));
		memcpy(&newsk->sk_dontcopy_end, &sk->sk_dontcopy_end,
		       sizeof(struct tcp_sock) - offsetof(struct sock, sk_dontcopy_end));
	} else {
		memcpy(newsk, sk, offsetof(struct sock, sk_dontcopy_begin));
		memcpy(&newsk->sk_dontcopy_end, &sk->sk_dontcopy_end,
		       sizeof(struct tcp6_sock) - offsetof(struct sock, sk_dontcopy_end));
	}

#ifdef CONFIG_SECURITY_NETWORK
	newsk->sk_security = sptr;
	security_sk_clone(sk, newsk);
#endif

	/* Has been changed by sock_copy above - we may need an IPv6-socket */
	newsk->sk_family = family;
	newsk->sk_prot = prot;
	newsk->sk_prot_creator = prot;
	inet_csk(newsk)->icsk_af_ops = af_ops;

	/* We don't yet have the mptcp-point. Thus we still need inet_sock_destruct */
	newsk->sk_destruct = inet_sock_destruct;

	/* SANITY */
	get_net(sock_net(newsk));
	sk_node_init(&newsk->sk_node);
	sock_lock_init_class_and_name(newsk, "slock-AF_INET-MPTCP",
				      &meta_slock_key, "sk_lock-AF_INET-MPTCP",
				      &meta_key);

	/* Unlocks are in:
	 *
	 * 1. If we are creating the master-sk
	 *	* on client-side in tcp_rcv_state_process, "case TCP_SYN_SENT"
	 *	* on server-side in tcp_child_process
	 * 2. If we are creating another subsock
	 *	* Also in tcp_child_process
	 */
	bh_lock_sock(newsk);
	newsk->sk_backlog.head = NULL;
	newsk->sk_backlog.tail = NULL;
	newsk->sk_backlog.len = 0;

	atomic_set(&newsk->sk_rmem_alloc, 0);
	atomic_set(&newsk->sk_wmem_alloc, 1);
	atomic_set(&newsk->sk_omem_alloc, 0);

	skb_queue_head_init(&newsk->sk_receive_queue);
	skb_queue_head_init(&newsk->sk_write_queue);
#ifdef CONFIG_NET_DMA
	skb_queue_head_init(&newsk->sk_async_wait_queue);
#endif

	spin_lock_init(&newsk->sk_dst_lock);
	rwlock_init(&newsk->sk_callback_lock);
	lockdep_set_class_and_name(&newsk->sk_callback_lock,
				   af_callback_keys + newsk->sk_family,
				   af_family_clock_key_strings[newsk->sk_family]);
	newsk->sk_dst_cache	= NULL;
	newsk->sk_rx_dst	= NULL;
	newsk->sk_wmem_queued	= 0;
	newsk->sk_forward_alloc = 0;
	newsk->sk_send_head	= NULL;
	newsk->sk_userlocks	= sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;

	tcp_sk(newsk)->mptcp = NULL;

	sock_reset_flag(newsk, SOCK_DONE);
	skb_queue_head_init(&newsk->sk_error_queue);

	filter = rcu_dereference_protected(newsk->sk_filter, 1);
	if (filter != NULL)
		sk_filter_charge(newsk, filter);

	if (unlikely(xfrm_sk_clone_policy(newsk))) {
		/* It is still raw copy of parent, so invalidate
		 * destructor and make plain sk_free()
		 */
		newsk->sk_destruct = NULL;
		bh_unlock_sock(newsk);
		sk_free(newsk);
		newsk = NULL;
		return -ENOMEM;
	}

	newsk->sk_err	   = 0;
	newsk->sk_priority = 0;
	/* Before updating sk_refcnt, we must commit prior changes to memory
	 * (Documentation/RCU/rculist_nulls.txt for details)
	 */
	smp_wmb();
	atomic_set(&newsk->sk_refcnt, 2);

	/* Increment the counter in the same struct proto as the master
	 * sock (sk_refcnt_debug_inc uses newsk->sk_prot->socks, that
	 * is the same as sk->sk_prot->socks, as this field was copied
	 * with memcpy).
	 *
	 * This _changes_ the previous behaviour, where
	 * tcp_create_openreq_child always was incrementing the
	 * equivalent to tcp_prot->socks (inet_sock_nr), so this have
	 * to be taken into account in all callers. -acme
	 */
	sk_refcnt_debug_inc(newsk);
	sk_set_socket(newsk, NULL);
	newsk->sk_wq = NULL;

	if (newsk->sk_prot->sockets_allocated)
		sk_sockets_allocated_inc(newsk);

	if (newsk->sk_flags & SK_FLAGS_TIMESTAMP)
		net_enable_timestamp();

	return 0;
}

static int mptcp_alloc_mpcb(struct sock *meta_sk, __u64 remote_key, u32 window)
{
	struct mptcp_cb *mpcb;
	struct sock *master_sk;
	struct inet_connection_sock *master_icsk, *meta_icsk = inet_csk(meta_sk);
	struct tcp_sock *master_tp, *meta_tp = tcp_sk(meta_sk);
	struct sk_buff *skb, *tmp;
	u64 idsn;

	master_sk = sk_prot_alloc(meta_sk->sk_prot, GFP_ATOMIC | __GFP_ZERO,
				  meta_sk->sk_family);
	if (!master_sk)
		return -ENOBUFS;

	master_tp = tcp_sk(master_sk);
	master_icsk = inet_csk(master_sk);

	/* Need to set this here - it is needed by mptcp_inherit_sk */
	master_sk->sk_prot = meta_sk->sk_prot;
	master_sk->sk_prot_creator = meta_sk->sk_prot;
	master_icsk->icsk_af_ops = meta_icsk->icsk_af_ops;

	mpcb = kmem_cache_zalloc(mptcp_cb_cache, GFP_ATOMIC);
	if (!mpcb) {
		sk_free(master_sk);
		return -ENOBUFS;
	}

	/* master_sk inherits from meta_sk */
	if (mptcp_inherit_sk(meta_sk, master_sk, meta_sk->sk_family, GFP_ATOMIC)) {
		kmem_cache_free(mptcp_cb_cache, mpcb);
		return -ENOBUFS;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (meta_icsk->icsk_af_ops == &mptcp_v6_mapped) {
		struct ipv6_pinfo *newnp, *np = inet6_sk(meta_sk);

		inet_sk(master_sk)->pinet6 = &((struct tcp6_sock *)master_sk)->inet6;

		newnp = inet6_sk(master_sk);
		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		newnp->ipv6_mc_list = NULL;
		newnp->ipv6_ac_list = NULL;
		newnp->ipv6_fl_list = NULL;
		newnp->opt = NULL;
		newnp->pktoptions = NULL;
		(void)xchg(&newnp->rxpmtu, NULL);
	} else if (meta_sk->sk_family == AF_INET6) {
		struct ipv6_pinfo *newnp, *np = inet6_sk(meta_sk);

		inet_sk(master_sk)->pinet6 = &((struct tcp6_sock *)master_sk)->inet6;

		newnp = inet6_sk(master_sk);
		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		newnp->hop_limit	= -1;
		newnp->mcast_hops	= IPV6_DEFAULT_MCASTHOPS;
		newnp->mc_loop	= 1;
		newnp->pmtudisc	= IPV6_PMTUDISC_WANT;
		newnp->ipv6only	= sock_net(master_sk)->ipv6.sysctl.bindv6only;
	}
#endif

	meta_tp->mptcp = kmem_cache_zalloc(mptcp_sock_cache, GFP_ATOMIC);
	if (!meta_tp->mptcp) {
		kmem_cache_free(mptcp_cb_cache, mpcb);
		sk_free(master_sk);
		return -ENOBUFS;
	}

	INIT_LIST_HEAD(&meta_tp->mptcp->cb_list);

	/* Store the keys and generate the peer's token */
	mpcb->mptcp_loc_key = meta_tp->mptcp_loc_key;
	mpcb->mptcp_loc_token = meta_tp->mptcp_loc_token;

	/* Generate Initial data-sequence-numbers */
	mptcp_key_sha1(mpcb->mptcp_loc_key, NULL, &idsn);
	idsn = ntohll(idsn) + 1;
	mpcb->snd_high_order[0] = idsn >> 32;
	mpcb->snd_high_order[1] = mpcb->snd_high_order[0] - 1;

	meta_tp->write_seq = (u32)idsn;
	meta_tp->snd_sml = meta_tp->write_seq;
	meta_tp->snd_una = meta_tp->write_seq;
	meta_tp->snd_nxt = meta_tp->write_seq;
	meta_tp->pushed_seq = meta_tp->write_seq;
	meta_tp->snd_up = meta_tp->write_seq;

	mpcb->mptcp_rem_key = remote_key;
	mptcp_key_sha1(mpcb->mptcp_rem_key, &mpcb->mptcp_rem_token, &idsn);
	idsn = ntohll(idsn) + 1;
	mpcb->rcv_high_order[0] = idsn >> 32;
	mpcb->rcv_high_order[1] = mpcb->rcv_high_order[0] + 1;
	meta_tp->copied_seq = (u32) idsn;
	meta_tp->rcv_nxt = (u32) idsn;
	meta_tp->rcv_wup = (u32) idsn;

	meta_tp->snd_wl1 = meta_tp->rcv_nxt - 1;
	meta_tp->snd_wnd = window;
	meta_tp->retrans_stamp = 0; /* Set in tcp_connect() */

	meta_tp->packets_out = 0;
	meta_tp->mptcp->snt_isn = meta_tp->write_seq; /* Initial data-sequence-number */
	meta_icsk->icsk_probes_out = 0;

	/* Set mptcp-pointers */
	master_tp->mpcb = mpcb;
	master_tp->meta_sk = meta_sk;
	meta_tp->mpcb = mpcb;
	meta_tp->meta_sk = meta_sk;
	mpcb->meta_sk = meta_sk;
	mpcb->master_sk = master_sk;

	meta_tp->mptcp->attached = 0;
	meta_tp->was_meta_sk = 0;

	/* Initialize the queues */
	skb_queue_head_init(&mpcb->reinject_queue);
	skb_queue_head_init(&master_tp->out_of_order_queue);
	tcp_prequeue_init(master_tp);
	INIT_LIST_HEAD(&master_tp->tsq_node);

	master_tp->tsq_flags = 0;

	/* Copy the write-queue from the meta down to the master.
	 * This is necessary to get the SYN to the master-write-queue.
	 * No other data can be queued, before tcp_sendmsg waits for the
	 * connection to finish.
	 */
	skb_queue_walk_safe(&meta_sk->sk_write_queue, skb, tmp) {
		skb_unlink(skb, &meta_sk->sk_write_queue);
		skb_queue_tail(&master_sk->sk_write_queue, skb);

		master_sk->sk_wmem_queued += skb->truesize;
		sk_mem_charge(master_sk, skb->truesize);
	}

	meta_sk->sk_wmem_queued = 0;
	meta_sk->sk_forward_alloc = 0;

	mutex_init(&mpcb->mpcb_mutex);

	/* Init the accept_queue structure, we support a queue of 32 pending
	 * connections, it does not need to be huge, since we only store  here
	 * pending subflow creations.
	 */
	if (reqsk_queue_alloc(&meta_icsk->icsk_accept_queue, 32, GFP_ATOMIC)) {
		inet_put_port(master_sk);
		kmem_cache_free(mptcp_sock_cache, meta_tp->mptcp);
		kmem_cache_free(mptcp_cb_cache, mpcb);
		sk_free(master_sk);
		return -ENOMEM;
	}

	/* Redefine function-pointers as the meta-sk is now fully ready */
	set_mpc(meta_tp);
	set_meta_funcs(meta_tp);
	meta_sk->sk_backlog_rcv = mptcp_backlog_rcv;
	meta_sk->sk_destruct = mptcp_sock_destruct;
	mpcb->syn_recv_sock = mptcp_syn_recv_sock;

	/* Meta-level retransmit timer */
	meta_icsk->icsk_rto *= 2; /* Double of initial - rto */

	tcp_init_xmit_timers(master_sk);
	/* Has been set for sending out the SYN */
	inet_csk_clear_xmit_timer(meta_sk, ICSK_TIME_RETRANS);

	if (!meta_tp->inside_tk_table) {
		/* Adding the meta_tp in the token hashtable - coming from server-side */
		rcu_read_lock();
		spin_lock(&mptcp_tk_hashlock);

		__mptcp_hash_insert(meta_tp, mpcb->mptcp_loc_token);

		spin_unlock(&mptcp_tk_hashlock);
		rcu_read_unlock();
	}
	master_tp->inside_tk_table = 0;

	/* Init time-wait stuff */
	INIT_LIST_HEAD(&mpcb->tw_list);
	spin_lock_init(&mpcb->tw_lock);

	INIT_LIST_HEAD(&mpcb->callback_list);

	mptcp_mpcb_inherit_sockopts(meta_sk, master_sk);

	mpcb->orig_sk_rcvbuf = meta_sk->sk_rcvbuf;
	mpcb->orig_sk_sndbuf = meta_sk->sk_sndbuf;
	mpcb->orig_window_clamp = meta_tp->window_clamp;

	/* The meta is directly linked - set refcnt to 1 */
	atomic_set(&mpcb->mpcb_refcnt, 1);

	mptcp_init_path_manager(mpcb);

	mptcp_debug("%s: created mpcb with token %#x\n",
		    __func__, mpcb->mptcp_loc_token);

	return 0;
}

struct sock *mptcp_sk_clone(const struct sock *sk, int family,
			    const gfp_t priority)
{
	struct sock *newsk = NULL;

	if (family == AF_INET && sk->sk_family == AF_INET) {
		newsk = sk_prot_alloc(&tcp_prot, priority, family);
		if (!newsk)
			return NULL;

		/* Set these pointers - they are needed by mptcp_inherit_sk */
		newsk->sk_prot = &tcp_prot;
		newsk->sk_prot_creator = &tcp_prot;
		inet_csk(newsk)->icsk_af_ops = &mptcp_v4_specific;
		newsk->sk_family = AF_INET;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else {
		newsk = sk_prot_alloc(&tcpv6_prot, priority, family);
		if (!newsk)
			return NULL;

		newsk->sk_prot = &tcpv6_prot;
		newsk->sk_prot_creator = &tcpv6_prot;
		if (family == AF_INET)
			inet_csk(newsk)->icsk_af_ops = &mptcp_v6_mapped;
		else
			inet_csk(newsk)->icsk_af_ops = &mptcp_v6_specific;
		newsk->sk_family = AF_INET6;
	}
#endif

	if (mptcp_inherit_sk(sk, newsk, family, priority))
		return NULL;

	return newsk;
}

void mptcp_fallback_meta_sk(struct sock *meta_sk)
{
	kfree(inet_csk(meta_sk)->icsk_accept_queue.listen_opt);
	kmem_cache_free(mptcp_sock_cache, tcp_sk(meta_sk)->mptcp);
	kmem_cache_free(mptcp_cb_cache, tcp_sk(meta_sk)->mpcb);
}

int mptcp_add_sock(struct sock *meta_sk, struct sock *sk, u8 loc_id, u8 rem_id,
		   gfp_t flags)
{
	struct mptcp_cb *mpcb	= tcp_sk(meta_sk)->mpcb;
	struct tcp_sock *tp	= tcp_sk(sk);

	tp->mptcp = kmem_cache_zalloc(mptcp_sock_cache, flags);
	if (!tp->mptcp)
		return -ENOMEM;

	tp->mptcp->path_index = mptcp_set_new_pathindex(mpcb);
	/* No more space for more subflows? */
	if (!tp->mptcp->path_index) {
		kmem_cache_free(mptcp_sock_cache, tp->mptcp);
		return -EPERM;
	}

	INIT_LIST_HEAD(&tp->mptcp->cb_list);

	tp->mptcp->tp = tp;
	tp->mpcb = mpcb;
	tp->meta_sk = meta_sk;
	set_mpc(tp);
	tp->mptcp->loc_id = loc_id;
	tp->mptcp->rem_id = rem_id;
	tp->mptcp->last_rbuf_opti = tcp_time_stamp;

	/* The corresponding sock_put is in mptcp_sock_destruct(). It cannot be
	 * included in mptcp_del_sock(), because the mpcb must remain alive
	 * until the last subsocket is completely destroyed.
	 */
	sock_hold(meta_sk);
	atomic_inc(&mpcb->mpcb_refcnt);

	tp->mptcp->next = mpcb->connection_list;
	mpcb->connection_list = tp;
	tp->mptcp->attached = 1;

	mpcb->cnt_subflows++;
	atomic_add(atomic_read(&((struct sock *)tp)->sk_rmem_alloc),
		   &meta_sk->sk_rmem_alloc);

	mptcp_sub_inherit_sockopts(meta_sk, sk);
	INIT_DELAYED_WORK(&tp->mptcp->work, mptcp_sub_close_wq);

	/* As we successfully allocated the mptcp_tcp_sock, we have to
	 * change the function-pointers here (for sk_destruct to work correctly)
	 */
	sk->sk_error_report = mptcp_sock_def_error_report;
	sk->sk_data_ready = mptcp_data_ready;
	sk->sk_write_space = mptcp_write_space;
	sk->sk_state_change = mptcp_set_state;
	sk->sk_destruct = mptcp_sock_destruct;

	if (sk->sk_family == AF_INET)
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI4:%d dst_addr:%pI4:%d, cnt_subflows now %d\n",
			    __func__ , mpcb->mptcp_loc_token,
			    tp->mptcp->path_index,
			    &((struct inet_sock *)tp)->inet_saddr,
			    ntohs(((struct inet_sock *)tp)->inet_sport),
			    &((struct inet_sock *)tp)->inet_daddr,
			    ntohs(((struct inet_sock *)tp)->inet_dport),
			    mpcb->cnt_subflows);
#if IS_ENABLED(CONFIG_IPV6)
	else
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI6:%d dst_addr:%pI6:%d, cnt_subflows now %d\n",
			    __func__ , mpcb->mptcp_loc_token,
			    tp->mptcp->path_index, &inet6_sk(sk)->saddr,
			    ntohs(((struct inet_sock *)tp)->inet_sport),
			    &sk->sk_v6_daddr,
			    ntohs(((struct inet_sock *)tp)->inet_dport),
			    mpcb->cnt_subflows);
#endif

	return 0;
}

void mptcp_del_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk), *tp_prev;
	struct mptcp_cb *mpcb;

	if (!tp->mptcp || !tp->mptcp->attached)
		return;

	mpcb = tp->mpcb;
	tp_prev = mpcb->connection_list;

	mptcp_debug("%s: Removing subsock tok %#x pi:%d state %d is_meta? %d\n",
		    __func__, mpcb->mptcp_loc_token, tp->mptcp->path_index,
		    sk->sk_state, is_meta_sk(sk));

	if (tp_prev == tp) {
		mpcb->connection_list = tp->mptcp->next;
	} else {
		for (; tp_prev && tp_prev->mptcp->next; tp_prev = tp_prev->mptcp->next) {
			if (tp_prev->mptcp->next == tp) {
				tp_prev->mptcp->next = tp->mptcp->next;
				break;
			}
		}
	}
	mpcb->cnt_subflows--;
	if (tp->mptcp->establish_increased)
		mpcb->cnt_established--;

	tp->mptcp->next = NULL;
	tp->mptcp->attached = 0;
	mpcb->path_index_bits &= ~(1 << tp->mptcp->path_index);

	if (!skb_queue_empty(&sk->sk_write_queue))
		mptcp_reinject_data(sk, 0);

	if (is_master_tp(tp))
		mpcb->master_sk = NULL;
	else if (tp->mptcp->pre_established)
		sk_stop_timer(sk, &tp->mptcp->mptcp_ack_timer);

	rcu_assign_pointer(inet_sk(sk)->inet_opt, NULL);
}

/* Updates the metasocket ULID/port data, based on the given sock.
 * The argument sock must be the sock accessible to the application.
 * In this function, we update the meta socket info, based on the changes
 * in the application socket (bind, address allocation, ...)
 */
void mptcp_update_metasocket(struct sock *sk, struct sock *meta_sk)
{
	if (tcp_sk(sk)->mpcb->pm_ops->new_session)
		tcp_sk(sk)->mpcb->pm_ops->new_session(meta_sk);

	tcp_sk(sk)->mptcp->send_mp_prio = tcp_sk(sk)->mptcp->low_prio;
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
	struct sock *sk;
	__u32 rcv_window_now = 0;

	if (copied > 0 && !(meta_sk->sk_shutdown & RCV_SHUTDOWN)) {
		rcv_window_now = tcp_receive_window(meta_tp);

		if (2 * rcv_window_now > meta_tp->window_clamp)
			rcv_window_now = 0;
	}

	mptcp_for_each_sk(meta_tp->mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		const struct inet_connection_sock *icsk = inet_csk(sk);

		if (!mptcp_sk_can_send_ack(sk))
			continue;

		if (!inet_csk_ack_scheduled(sk))
			goto second_part;
		/* Delayed ACKs frequently hit locked sockets during bulk
		 * receive.
		 */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /* If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		     !atomic_read(&meta_sk->sk_rmem_alloc))) {
			tcp_send_ack(sk);
			continue;
		}

second_part:
		/* This here is the second part of tcp_cleanup_rbuf */
		if (rcv_window_now) {
			__u32 new_window = tp->__select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than
			 * current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				tcp_send_ack(sk);
		}
	}
}

static int mptcp_sub_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_write_queue_tail(sk);
	int mss_now;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = tcp_current_mss(sk);

	if (tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		skb = alloc_skb_fclone(MAX_TCP_HEADER, GFP_ATOMIC);
		if (!skb)
			return 1;

		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPHDR_ACK | TCPHDR_FIN);
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);

	return 0;
}

void mptcp_sub_close_wq(struct work_struct *work)
{
	struct tcp_sock *tp = container_of(work, struct mptcp_tcp_sock, work.work)->tp;
	struct sock *sk = (struct sock *)tp;
	struct sock *meta_sk = mptcp_meta_sk(sk);

	mutex_lock(&tp->mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	if (sock_flag(sk, SOCK_DEAD))
		goto exit;

	/* We come from tcp_disconnect. We are sure that meta_sk is set */
	if (!mptcp(tp)) {
		tp->closing = 1;
		sock_rps_reset_flow(sk);
		tcp_close(sk, 0);
		goto exit;
	}

	if (meta_sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE) {
		tp->closing = 1;
		sock_rps_reset_flow(sk);
		tcp_close(sk, 0);
	} else if (tcp_close_state(sk)) {
		sk->sk_shutdown |= SEND_SHUTDOWN;
		tcp_send_fin(sk);
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&tp->mpcb->mpcb_mutex);
	sock_put(sk);
}

void mptcp_sub_close(struct sock *sk, unsigned long delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct delayed_work *work = &tcp_sk(sk)->mptcp->work;

	/* We are already closing - e.g., call from sock_def_error_report upon
	 * tcp_disconnect in tcp_close.
	 */
	if (tp->closing)
		return;

	/* Work already scheduled ? */
	if (work_pending(&work->work)) {
		/* Work present - who will be first ? */
		if (jiffies + delay > work->timer.expires)
			return;

		/* Try canceling - if it fails, work will be executed soon */
		if (!cancel_delayed_work(work))
			return;
		sock_put(sk);
	}

	if (!delay) {
		unsigned char old_state = sk->sk_state;

		/* If we are in user-context we can directly do the closing
		 * procedure. No need to schedule a work-queue.
		 */
		if (!in_softirq()) {
			if (sock_flag(sk, SOCK_DEAD))
				return;

			if (!mptcp(tp)) {
				tp->closing = 1;
				sock_rps_reset_flow(sk);
				tcp_close(sk, 0);
				return;
			}

			if (mptcp_meta_sk(sk)->sk_shutdown == SHUTDOWN_MASK ||
			    sk->sk_state == TCP_CLOSE) {
				tp->closing = 1;
				sock_rps_reset_flow(sk);
				tcp_close(sk, 0);
			} else if (tcp_close_state(sk)) {
				sk->sk_shutdown |= SEND_SHUTDOWN;
				tcp_send_fin(sk);
			}

			return;
		}

		/* We directly send the FIN. Because it may take so a long time,
		 * untile the work-queue will get scheduled...
		 *
		 * If mptcp_sub_send_fin returns 1, it failed and thus we reset
		 * the old state so that tcp_close will finally send the fin
		 * in user-context.
		 */
		if (!sk->sk_err && old_state != TCP_CLOSE &&
		    tcp_close_state(sk) && mptcp_sub_send_fin(sk)) {
			if (old_state == TCP_ESTABLISHED)
				TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
			sk->sk_state = old_state;
		}
	}

	sock_hold(sk);
	queue_delayed_work(mptcp_wq, work, delay);
}

void mptcp_sub_force_close(struct sock *sk)
{
	/* The below tcp_done may have freed the socket, if he is already dead.
	 * Thus, we are not allowed to access it afterwards. That's why
	 * we have to store the dead-state in this local variable.
	 */
	int sock_is_dead = sock_flag(sk, SOCK_DEAD);

	tcp_sk(sk)->mp_killed = 1;

	if (sk->sk_state != TCP_CLOSE)
		tcp_done(sk);

	if (!sock_is_dead)
		mptcp_sub_close(sk, 0);
}
EXPORT_SYMBOL(mptcp_sub_force_close);

/* Update the mpcb send window, based on the contributions
 * of each subflow
 */
void mptcp_update_sndbuf(struct mptcp_cb *mpcb)
{
	struct sock *meta_sk = mpcb->meta_sk, *sk;
	int new_sndbuf = 0, old_sndbuf = meta_sk->sk_sndbuf;
	mptcp_for_each_sk(mpcb, sk) {
		if (!mptcp_sk_can_send(sk))
			continue;

		new_sndbuf += sk->sk_sndbuf;

		if (new_sndbuf > sysctl_tcp_wmem[2] || new_sndbuf < 0) {
			new_sndbuf = sysctl_tcp_wmem[2];
			break;
		}
	}
	meta_sk->sk_sndbuf = max(min(new_sndbuf, sysctl_tcp_wmem[2]), meta_sk->sk_sndbuf);

	/* The subflow's call to sk_write_space in tcp_new_space ends up in
	 * mptcp_write_space.
	 * It has nothing to do with waking up the application.
	 * So, we do it here.
	 */
	if (old_sndbuf != meta_sk->sk_sndbuf)
		meta_sk->sk_write_space(meta_sk);
}

void mptcp_close(struct sock *meta_sk, long timeout)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sock *sk_it, *tmpsk;
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	mptcp_debug("%s: Close of meta_sk with tok %#x\n",
		    __func__, mpcb->mptcp_loc_token);

	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock(meta_sk);

	if (meta_tp->inside_tk_table) {
		/* Detach the mpcb from the token hashtable */
		mptcp_hash_remove_bh(meta_tp);
		reqsk_queue_destroy(&inet_csk(meta_sk)->icsk_accept_queue);
	}

	meta_sk->sk_shutdown = SHUTDOWN_MASK;
	/* We need to flush the recv. buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&meta_sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(meta_sk);

	/* If socket has been already reset (e.g. in tcp_reset()) - kill it. */
	if (meta_sk->sk_state == TCP_CLOSE) {
		mptcp_for_each_sk_safe(mpcb, sk_it, tmpsk) {
			if (tcp_sk(sk_it)->send_mp_fclose)
				continue;
			mptcp_sub_close(sk_it, 0);
		}
		goto adjudge_to_death;
	}

	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(sock_net(meta_sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(meta_sk, TCP_CLOSE);
		tcp_sk(meta_sk)->send_active_reset(meta_sk,
						   meta_sk->sk_allocation);
	} else if (sock_flag(meta_sk, SOCK_LINGER) && !meta_sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		meta_sk->sk_prot->disconnect(meta_sk, 0);
		NET_INC_STATS_USER(sock_net(meta_sk), LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(meta_sk)) {
		mptcp_send_fin(meta_sk);
	} else if (meta_tp->snd_una == meta_tp->write_seq) {
		/* The DATA_FIN has been sent and acknowledged
		 * (e.g., by sk_shutdown). Close all the other subflows
		 */
		mptcp_for_each_sk_safe(mpcb, sk_it, tmpsk) {
			unsigned long delay = 0;
			/* If we are the passive closer, don't trigger
			 * subflow-fin until the subflow has been finned
			 * by the peer. - thus we add a delay
			 */
			if (mpcb->passive_close &&
			    sk_it->sk_state == TCP_ESTABLISHED)
				delay = inet_csk(sk_it)->icsk_rto << 3;

			mptcp_sub_close(sk_it, delay);
		}
	}

	sk_stream_wait_close(meta_sk, timeout);

adjudge_to_death:
	state = meta_sk->sk_state;
	sock_hold(meta_sk);
	sock_orphan(meta_sk);

	/* socket will be freed after mptcp_close - we have to prevent
	 * access from the subflows.
	 */
	mptcp_for_each_sk(mpcb, sk_it) {
		/* Similar to sock_orphan, but we don't set it DEAD, because
		 * the callbacks are still set and must be called.
		 */
		write_lock_bh(&sk_it->sk_callback_lock);
		sk_set_socket(sk_it, NULL);
		sk_it->sk_wq  = NULL;
		write_unlock_bh(&sk_it->sk_callback_lock);
	}

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(meta_sk);

	/* Now socket is owned by kernel and we acquire BH lock
	 * to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(meta_sk);
	WARN_ON(sock_owned_by_user(meta_sk));

	percpu_counter_inc(meta_sk->sk_prot->orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && meta_sk->sk_state == TCP_CLOSE)
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

	if (meta_sk->sk_state == TCP_FIN_WAIT2) {
		if (meta_tp->linger2 < 0) {
			tcp_set_state(meta_sk, TCP_CLOSE);
			meta_tp->send_active_reset(meta_sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(meta_sk),
					 LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(meta_sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(meta_sk,
							       tmo - TCP_TIMEWAIT_LEN);
			} else {
				meta_tp->time_wait(meta_sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (meta_sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(meta_sk);
		if (tcp_too_many_orphans(meta_sk, 0)) {
			if (net_ratelimit())
				pr_info("MPTCP: too many of orphaned sockets\n");
			tcp_set_state(meta_sk, TCP_CLOSE);
			meta_tp->send_active_reset(meta_sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(meta_sk),
					 LINUX_MIB_TCPABORTONMEMORY);
		}
	}


	if (meta_sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(meta_sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(meta_sk);
	local_bh_enable();
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk); /* Taken by sock_hold */
}

void mptcp_disconnect(struct sock *sk)
{
	struct sock *subsk, *tmpsk;
	struct tcp_sock *tp = tcp_sk(sk);

	__skb_queue_purge(&tp->mpcb->reinject_queue);

	if (tp->inside_tk_table) {
		mptcp_hash_remove_bh(tp);
		reqsk_queue_destroy(&inet_csk(tp->meta_sk)->icsk_accept_queue);
	}

	local_bh_disable();
	mptcp_for_each_sk_safe(tp->mpcb, subsk, tmpsk) {
		/* The socket will get removed from the subsocket-list
		 * and made non-mptcp by setting mpc to 0.
		 *
		 * This is necessary, because tcp_disconnect assumes
		 * that the connection is completly dead afterwards.
		 * Thus we need to do a mptcp_del_sock. Due to this call
		 * we have to make it non-mptcp.
		 *
		 * We have to lock the socket, because we set mpc to 0.
		 * An incoming packet would take the subsocket's lock
		 * and go on into the receive-path.
		 * This would be a race.
		 */

		bh_lock_sock(subsk);
		mptcp_del_sock(subsk);
		reset_mpc(tcp_sk(subsk));
		mptcp_sub_force_close(subsk);
		bh_unlock_sock(subsk);
	}
	local_bh_enable();

	tp->was_meta_sk = 1;
	reset_mpc(tp);
	reset_meta_funcs(tp);
}


/* Returns 1 if we should enable MPTCP for that socket. */
int mptcp_doit(struct sock *sk)
{
	/* Do not allow MPTCP enabling if the MPTCP initialization failed */
	if (mptcp_init_failed)
		return 0;

	if (sysctl_mptcp_enabled == MPTCP_APP && !tcp_sk(sk)->mptcp_enabled)
		return 0;

	/* Socket may already be established (e.g., called from tcp_recvmsg) */
	if (mptcp(tcp_sk(sk)) || tcp_sk(sk)->request_mptcp)
		return 1;

	/* Don't do mptcp over loopback */
	if (sk->sk_family == AF_INET &&
	    (ipv4_is_loopback(inet_sk(sk)->inet_daddr) ||
	     ipv4_is_loopback(inet_sk(sk)->inet_saddr)))
		return 0;
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6 &&
	    (ipv6_addr_loopback(&sk->sk_v6_daddr) ||
	     ipv6_addr_loopback(&inet6_sk(sk)->saddr)))
		return 0;
#endif
	if (mptcp_v6_is_v4_mapped(sk) &&
	    ipv4_is_loopback(inet_sk(sk)->inet_saddr))
		return 0;

#ifdef CONFIG_TCP_MD5SIG
	/* If TCP_MD5SIG is enabled, do not do MPTCP - there is no Option-Space */
	if (tcp_sk(sk)->af_specific->md5_lookup(sk, sk))
		return 0;
#endif

	return 1;
}

int mptcp_create_master_sk(struct sock *meta_sk, __u64 remote_key, u32 window)
{
	struct tcp_sock *master_tp;
	struct sock *master_sk;

	if (mptcp_alloc_mpcb(meta_sk, remote_key, window))
		goto err_alloc_mpcb;

	master_sk = tcp_sk(meta_sk)->mpcb->master_sk;
	master_tp = tcp_sk(master_sk);

	if (mptcp_add_sock(meta_sk, master_sk, 0, 0, GFP_ATOMIC))
		goto err_add_sock;

	if (__inet_inherit_port(meta_sk, master_sk) < 0)
		goto err_add_sock;

	meta_sk->sk_prot->unhash(meta_sk);

	if (master_sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(master_sk))
		__inet_hash_nolisten(master_sk, NULL);
#if IS_ENABLED(CONFIG_IPV6)
	else
		__inet6_hash(master_sk, NULL);
#endif

	master_tp->mptcp->init_rcv_wnd = master_tp->rcv_wnd;

	return 0;

err_add_sock:
	mptcp_fallback_meta_sk(meta_sk);

	inet_csk_prepare_forced_close(master_sk);
	tcp_done(master_sk);
	inet_csk_prepare_forced_close(meta_sk);
	tcp_done(meta_sk);

err_alloc_mpcb:
	return -ENOBUFS;
}

int mptcp_check_req_master(struct sock *sk, struct sock *child,
			   struct request_sock *req,
			   struct request_sock **prev,
			   struct mptcp_options_received *mopt)
{
	struct tcp_sock *child_tp = tcp_sk(child);
	struct sock *meta_sk = child;
	struct mptcp_cb *mpcb;
	struct mptcp_request_sock *mtreq;

	if (!tcp_rsk(req)->saw_mpc)
		return 1;

	/* Just set this values to pass them to mptcp_alloc_mpcb */
	mtreq = mptcp_rsk(req);
	child_tp->mptcp_loc_key = mtreq->mptcp_loc_key;
	child_tp->mptcp_loc_token = mtreq->mptcp_loc_token;

	if (mptcp_create_master_sk(meta_sk, mtreq->mptcp_rem_key,
				   child_tp->snd_wnd))
		return -ENOBUFS;

	child = tcp_sk(child)->mpcb->master_sk;
	child_tp = tcp_sk(child);
	mpcb = child_tp->mpcb;

	child_tp->mptcp->snt_isn = tcp_rsk(req)->snt_isn;
	child_tp->mptcp->rcv_isn = tcp_rsk(req)->rcv_isn;

	mpcb->dss_csum = mtreq->dss_csum;
	mpcb->server_side = 1;

	/* Will be moved to ESTABLISHED by  tcp_rcv_state_process() */
	mptcp_update_metasocket(child, meta_sk);

	/* Needs to be done here additionally, because when accepting a
	 * new connection we pass by __reqsk_free and not reqsk_free.
	 */
	mptcp_reqsk_remove_tk(req);

	 /* Hold when creating the meta-sk in tcp_vX_syn_recv_sock. */
	sock_put(meta_sk);

	inet_csk_reqsk_queue_unlink(sk, req, prev);
	inet_csk_reqsk_queue_removed(sk, req);
	inet_csk_reqsk_queue_add(sk, req, meta_sk);

	return 0;
}

struct sock *mptcp_check_req_child(struct sock *meta_sk, struct sock *child,
				   struct request_sock *req,
				   struct request_sock **prev,
				   struct mptcp_options_received *mopt)
{
	struct tcp_sock *child_tp = tcp_sk(child);
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);
	struct mptcp_cb *mpcb = mtreq->mpcb;
	u8 hash_mac_check[20];

	child_tp->inside_tk_table = 0;

	if (!mopt->join_ack)
		goto teardown;

	mptcp_hmac_sha1((u8 *)&mpcb->mptcp_rem_key,
			(u8 *)&mpcb->mptcp_loc_key,
			(u8 *)&mtreq->mptcp_rem_nonce,
			(u8 *)&mtreq->mptcp_loc_nonce,
			(u32 *)hash_mac_check);

	if (memcmp(hash_mac_check, (char *)&mopt->mptcp_recv_mac, 20))
		goto teardown;

	/* Point it to the same struct socket and wq as the meta_sk */
	sk_set_socket(child, meta_sk->sk_socket);
	child->sk_wq = meta_sk->sk_wq;

	if (mptcp_add_sock(meta_sk, child, mtreq->loc_id, mtreq->rem_id, GFP_ATOMIC)) {
		reset_mpc(child_tp); /* Has been inherited, but now
				      * child_tp->mptcp is NULL
				      */
		/* TODO when we support acking the third ack for new subflows,
		 * we should silently discard this third ack, by returning NULL.
		 *
		 * Maybe, at the retransmission we will have enough memory to
		 * fully add the socket to the meta-sk.
		 */
		goto teardown;
	}

	/* The child is a clone of the meta socket, we must now reset
	 * some of the fields
	 */
	child_tp->mptcp->rcv_low_prio = mtreq->low_prio;
	reset_meta_funcs(child_tp);

	/* We should allow proper increase of the snd/rcv-buffers. Thus, we
	 * use the original values instead of the bloated up ones from the
	 * clone.
	 */
	child->sk_sndbuf = mpcb->orig_sk_sndbuf;
	child->sk_rcvbuf = mpcb->orig_sk_rcvbuf;

	child_tp->mptcp->slave_sk = 1;
	child_tp->mptcp->snt_isn = tcp_rsk(req)->snt_isn;
	child_tp->mptcp->rcv_isn = tcp_rsk(req)->rcv_isn;
	child_tp->mptcp->init_rcv_wnd = req->rcv_wnd;

	child_tp->tsq_flags = 0;

	/* Subflows do not use the accept queue, as they
	 * are attached immediately to the mpcb.
	 */
	inet_csk_reqsk_queue_unlink(meta_sk, req, prev);
	reqsk_queue_removed(&inet_csk(meta_sk)->icsk_accept_queue, req);
	reqsk_free(req);
	return child;

teardown:
	/* Drop this request - sock creation failed. */
	inet_csk_reqsk_queue_unlink(meta_sk, req, prev);
	reqsk_queue_removed(&inet_csk(meta_sk)->icsk_accept_queue, req);
	reqsk_free(req);
	inet_csk_prepare_forced_close(child);
	tcp_done(child);
	return meta_sk;
}

int mptcp_init_tw_sock(struct sock *sk, struct tcp_timewait_sock *tw)
{
	struct mptcp_tw *mptw;
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;

	/* Alloc MPTCP-tw-sock */
	mptw = kmem_cache_alloc(mptcp_tw_cache, GFP_ATOMIC);
	if (!mptw)
		return -ENOBUFS;

	atomic_inc(&mpcb->mpcb_refcnt);

	tw->mptcp_tw = mptw;
	mptw->loc_key = mpcb->mptcp_loc_key;
	mptw->meta_tw = mpcb->in_time_wait;
	if (mptw->meta_tw) {
		mptw->rcv_nxt = mptcp_get_rcv_nxt_64(mptcp_meta_tp(tp));
		if (mpcb->mptw_state != TCP_TIME_WAIT)
			mptw->rcv_nxt++;
	}
	rcu_assign_pointer(mptw->mpcb, mpcb);

	spin_lock(&mpcb->tw_lock);
	list_add_rcu(&mptw->list, &tp->mpcb->tw_list);
	mptw->in_list = 1;
	spin_unlock(&mpcb->tw_lock);

	return 0;
}

void mptcp_twsk_destructor(struct tcp_timewait_sock *tw)
{
	struct mptcp_cb *mpcb;

	rcu_read_lock();
	mpcb = rcu_dereference(tw->mptcp_tw->mpcb);

	/* If we are still holding a ref to the mpcb, we have to remove ourself
	 * from the list and drop the ref properly.
	 */
	if (mpcb && atomic_inc_not_zero(&mpcb->mpcb_refcnt)) {
		spin_lock(&mpcb->tw_lock);
		if (tw->mptcp_tw->in_list) {
			list_del_rcu(&tw->mptcp_tw->list);
			tw->mptcp_tw->in_list = 0;
		}
		spin_unlock(&mpcb->tw_lock);

		/* Twice, because we increased it above */
		mptcp_mpcb_put(mpcb);
		mptcp_mpcb_put(mpcb);
	}

	rcu_read_unlock();

	kmem_cache_free(mptcp_tw_cache, tw->mptcp_tw);
}

/* Updates the rcv_nxt of the time-wait-socks and allows them to ack a
 * data-fin.
 */
void mptcp_time_wait(struct sock *sk, int state, int timeo)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_tw *mptw;

	/* Used for sockets that go into tw after the meta
	 * (see mptcp_init_tw_sock())
	 */
	tp->mpcb->in_time_wait = 1;
	tp->mpcb->mptw_state = state;

	/* Update the time-wait-sock's information */
	rcu_read_lock_bh();
	list_for_each_entry_rcu(mptw, &tp->mpcb->tw_list, list) {
		mptw->meta_tw = 1;
		mptw->rcv_nxt = mptcp_get_rcv_nxt_64(tp);

		/* We want to ack a DATA_FIN, but are yet in FIN_WAIT_2 -
		 * pretend as if the DATA_FIN has already reached us, that way
		 * the checks in tcp_timewait_state_process will be good as the
		 * DATA_FIN comes in.
		 */
		if (state != TCP_TIME_WAIT)
			mptw->rcv_nxt++;
	}
	rcu_read_unlock_bh();

	tcp_done(sk);
}

void mptcp_tsq_flags(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = mptcp_meta_sk(sk);

	/* It will be handled as a regular deferred-call */
	if (is_meta_sk(sk))
		return;

	if (list_empty(&tp->mptcp->cb_list)) {
		list_add(&tp->mptcp->cb_list, &tp->mpcb->callback_list);
		/* We need to hold it here, as the sock_hold is not assured
		 * by the release_sock as it is done in regular TCP.
		 *
		 * The subsocket may get inet_csk_destroy'd while it is inside
		 * the callback_list.
		 */
		sock_hold(sk);
	}

	if (!test_and_set_bit(MPTCP_SUB_DEFERRED, &tcp_sk(meta_sk)->tsq_flags))
		sock_hold(meta_sk);
}

void mptcp_tsq_sub_deferred(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_tcp_sock *mptcp, *tmp;

	BUG_ON(!is_meta_sk(meta_sk) && !meta_tp->was_meta_sk);

	__sock_put(meta_sk);
	list_for_each_entry_safe(mptcp, tmp, &meta_tp->mpcb->callback_list, cb_list) {
		struct tcp_sock *tp = mptcp->tp;
		struct sock *sk = (struct sock *)tp;

		list_del_init(&mptcp->cb_list);
		sk->sk_prot->release_cb(sk);
		/* Final sock_put (cfr. mptcp_tsq_flags */
		sock_put(sk);
	}
}

void mptcp_reqsk_init(struct request_sock *req, struct sk_buff *skb)
{
	struct mptcp_options_received mopt;
	struct mptcp_request_sock *mreq = mptcp_rsk(req);

	mptcp_init_mp_opt(&mopt);
	tcp_parse_mptcp_options(skb, &mopt);

	mreq->mpcb = NULL;
	mreq->dss_csum = mopt.dss_csum;
	mreq->collide_tk.pprev = NULL;

	mptcp_reqsk_new_mptcp(req, &mopt, skb);
}

int mptcp_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct mptcp_options_received mopt;
	struct tcp_sock *tp = tcp_sk(sk);
#ifdef CONFIG_SYN_COOKIES
	__u32 isn = TCP_SKB_CB(skb)->when;
#endif
	bool want_cookie = false;

#ifdef CONFIG_SYN_COOKIES
	if ((sysctl_tcp_syncookies == 2 ||
	     inet_csk_reqsk_queue_is_full(sk)) && !isn)
		want_cookie = sysctl_tcp_syncookies;
#endif

	mptcp_init_mp_opt(&mopt);
	tcp_parse_mptcp_options(skb, &mopt);

	if (mopt.is_mp_join)
		return mptcp_do_join_short(skb, &mopt, sock_net(sk));
	if (mopt.drop_me)
		goto drop;

	if (sysctl_mptcp_enabled == MPTCP_APP && !tp->mptcp_enabled)
		mopt.saw_mpc = 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (mopt.saw_mpc && !want_cookie) {
			if (skb_rtable(skb)->rt_flags &
			    (RTCF_BROADCAST | RTCF_MULTICAST))
				goto drop;

			return tcp_conn_request(&mptcp_request_sock_ops,
						&mptcp_request_sock_ipv4_ops,
						sk, skb);
		}

		return tcp_v4_conn_request(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		if (mopt.saw_mpc && !want_cookie) {
			if (!ipv6_unicast_destination(skb))
				goto drop;

			return tcp_conn_request(&mptcp6_request_sock_ops,
						&mptcp_request_sock_ipv6_ops,
						sk, skb);
		}

		return tcp_v6_conn_request(sk, skb);
#endif
	}
drop:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return 0;
}

struct workqueue_struct *mptcp_wq;
EXPORT_SYMBOL(mptcp_wq);

/* Output /proc/net/mptcp */
static int mptcp_pm_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_sock *meta_tp;
	struct net *net = seq->private;
	int i, n = 0;

	seq_printf(seq, "  sl  loc_tok  rem_tok  v6 "
		   "local_address                         "
		   "remote_address                        "
		   "st ns tx_queue rx_queue inode");
	seq_putc(seq, '\n');

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node,
					       &tk_hashtable[i], tk_table) {
			struct mptcp_cb *mpcb = meta_tp->mpcb;
			struct sock *meta_sk = (struct sock *)meta_tp;
			struct inet_sock *isk = inet_sk(meta_sk);

			if (!mptcp(meta_tp) || !net_eq(net, sock_net(meta_sk)))
				continue;

			seq_printf(seq, "%4d: %04X %04X ", n++,
				   mpcb->mptcp_loc_token,
				   mpcb->mptcp_rem_token);
			if (meta_sk->sk_family == AF_INET ||
			    mptcp_v6_is_v4_mapped(meta_sk)) {
				seq_printf(seq, " 0 %08X:%04X                         %08X:%04X                        ",
					   isk->inet_rcv_saddr,
					   ntohs(isk->inet_sport),
					   isk->inet_daddr,
					   ntohs(isk->inet_dport));
#if IS_ENABLED(CONFIG_IPV6)
			} else if (meta_sk->sk_family == AF_INET6) {
				struct in6_addr *src = &meta_sk->sk_v6_rcv_saddr;
				struct in6_addr *dst = &meta_sk->sk_v6_daddr;
				seq_printf(seq, " 1 %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X",
					   src->s6_addr32[0], src->s6_addr32[1],
					   src->s6_addr32[2], src->s6_addr32[3],
					   ntohs(isk->inet_sport),
					   dst->s6_addr32[0], dst->s6_addr32[1],
					   dst->s6_addr32[2], dst->s6_addr32[3],
					   ntohs(isk->inet_dport));
#endif
			}
			seq_printf(seq, " %02X %02X %08X:%08X %lu",
				   meta_sk->sk_state, mpcb->cnt_subflows,
				   meta_tp->write_seq - meta_tp->snd_una,
				   max_t(int, meta_tp->rcv_nxt -
					 meta_tp->copied_seq, 0),
				   sock_i_ino(meta_sk));
			seq_putc(seq, '\n');
		}
		rcu_read_unlock_bh();
	}

	return 0;
}

static int mptcp_pm_seq_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, mptcp_pm_seq_show);
}

static const struct file_operations mptcp_pm_seq_fops = {
	.owner = THIS_MODULE,
	.open = mptcp_pm_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release_net,
};

static int mptcp_pm_init_net(struct net *net)
{
	if (!proc_create("mptcp", S_IRUGO, net->proc_net, &mptcp_pm_seq_fops))
		return -ENOMEM;

	return 0;
}

static void mptcp_pm_exit_net(struct net *net)
{
	remove_proc_entry("mptcp", net->proc_net);
}

static struct pernet_operations mptcp_pm_proc_ops = {
	.init = mptcp_pm_init_net,
	.exit = mptcp_pm_exit_net,
};

/* General initialization of mptcp */
void __init mptcp_init(void)
{
	int i;
	struct ctl_table_header *mptcp_sysctl;

	mptcp_sock_cache = kmem_cache_create("mptcp_sock",
					     sizeof(struct mptcp_tcp_sock),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL);
	if (!mptcp_sock_cache)
		goto mptcp_sock_cache_failed;

	mptcp_cb_cache = kmem_cache_create("mptcp_cb", sizeof(struct mptcp_cb),
					   0, SLAB_DESTROY_BY_RCU|SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!mptcp_cb_cache)
		goto mptcp_cb_cache_failed;

	mptcp_tw_cache = kmem_cache_create("mptcp_tw", sizeof(struct mptcp_tw),
					   0, SLAB_DESTROY_BY_RCU|SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!mptcp_tw_cache)
		goto mptcp_tw_cache_failed;

	get_random_bytes(mptcp_secret, sizeof(mptcp_secret));

	mptcp_wq = alloc_workqueue("mptcp_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 8);
	if (!mptcp_wq)
		goto alloc_workqueue_failed;

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		INIT_HLIST_NULLS_HEAD(&tk_hashtable[i], i);
		INIT_LIST_HEAD(&mptcp_reqsk_htb[i]);
		INIT_HLIST_NULLS_HEAD(&mptcp_reqsk_tk_htb[i], i);
	}

	spin_lock_init(&mptcp_reqsk_hlock);
	spin_lock_init(&mptcp_tk_hashlock);

	if (register_pernet_subsys(&mptcp_pm_proc_ops))
		goto pernet_failed;

#if IS_ENABLED(CONFIG_IPV6)
	if (mptcp_pm_v6_init())
		goto mptcp_pm_v6_failed;
#endif
	if (mptcp_pm_v4_init())
		goto mptcp_pm_v4_failed;

	mptcp_sysctl = register_net_sysctl(&init_net, "net/mptcp", mptcp_table);
	if (!mptcp_sysctl)
		goto register_sysctl_failed;

	if (mptcp_register_path_manager(&mptcp_pm_default))
		goto register_pm_failed;

	pr_info("MPTCP: Stable release v0.89.0-rc");

	mptcp_init_failed = false;

	return;

register_pm_failed:
	unregister_net_sysctl_table(mptcp_sysctl);
register_sysctl_failed:
	mptcp_pm_v4_undo();
mptcp_pm_v4_failed:
#if IS_ENABLED(CONFIG_IPV6)
	mptcp_pm_v6_undo();
mptcp_pm_v6_failed:
#endif
	unregister_pernet_subsys(&mptcp_pm_proc_ops);
pernet_failed:
	destroy_workqueue(mptcp_wq);
alloc_workqueue_failed:
	kmem_cache_destroy(mptcp_tw_cache);
mptcp_tw_cache_failed:
	kmem_cache_destroy(mptcp_cb_cache);
mptcp_cb_cache_failed:
	kmem_cache_destroy(mptcp_sock_cache);
mptcp_sock_cache_failed:
	mptcp_init_failed = true;
}
