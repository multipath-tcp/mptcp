/*
 *	MPTCP implementation - MPTCP-subflow-management
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
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>	/* Needed by proc_net_fops_create */
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_pm.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/if_inet6.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/inet6_connection_sock.h>
#include <net/mptcp_v6.h>
#include <net/addrconf.h>
#endif

static inline u32 mptcp_hash_tk(u32 token)
{
	return token % MPTCP_HASH_SIZE;
}

static struct hlist_nulls_head tk_hashtable[MPTCP_HASH_SIZE];

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

void mptcp_reqsk_remove_tk(struct request_sock *reqsk)
{
	rcu_read_lock();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_rcu(&mptcp_rsk(reqsk)->collide_tk);
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock();
}

void __mptcp_hash_insert(struct tcp_sock *meta_tp, u32 token)
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
						        ireq->loc_port,
						        ireq->rmt_port);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		mtreq->mptcp_loc_key = mptcp_v6_get_key(ipv6_hdr(skb)->saddr.s6_addr32,
							ipv6_hdr(skb)->daddr.s6_addr32,
							ireq->loc_port,
							ireq->rmt_port);
#endif
	}

	mptcp_key_sha1(mtreq->mptcp_loc_key, &mtreq->mptcp_loc_token, NULL);
}

/* New MPTCP-connection request, prepare a new token for the meta-socket that
 * will be created in mptcp_check_req_master(), and store the received token.
 */
void mptcp_reqsk_new_mptcp(struct request_sock *req,
			   const struct tcp_options_received *rx_opt,
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
						     inet6_sk(sk)->daddr.s6_addr32,
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
	hlist_nulls_del_rcu(&meta_tp->tk_table);
	meta_tp->inside_tk_table = 0;
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock_bh();
}

void mptcp_hash_remove(struct tcp_sock *meta_tp)
{
	rcu_read_lock();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_rcu(&meta_tp->tk_table);
	meta_tp->inside_tk_table = 0;
	spin_unlock(&mptcp_tk_hashlock);
	rcu_read_unlock();
}

void mptcp_announce_addresses(struct sock *meta_sk)
{
	struct mptcp_local_addresses *mptcp_local;
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct net *net = sock_net(meta_sk);
	int i;

	/* if multiports is requested, we work with the main address
	 * and play only with the ports
	 */
	if (sysctl_mptcp_ndiffports > 1)
		return;

	rcu_read_lock();
	mptcp_local = rcu_dereference(net->mptcp.local);

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
		__be32 ifa_address = mptcp_local->locaddr4[i].addr.s_addr;

		/* We do not need to announce the initial subflow's address again */
		if ((meta_sk->sk_family == AF_INET ||
		     mptcp_v6_is_v4_mapped(meta_sk)) &&
		    inet_sk(meta_sk)->inet_saddr == ifa_address)
			continue;

		mptcp_v4_send_add_addr(i, mpcb);
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
		struct in6_addr *ifa6 = &mptcp_local->locaddr6[i].addr;
		if (meta_sk->sk_family == AF_INET6 &&
		    ipv6_addr_equal(&inet6_sk(meta_sk)->saddr, ifa6))
			continue;

		mptcp_v6_send_add_addr(i, mpcb);
	}
#endif

	rcu_read_unlock();
}

int mptcp_check_req(struct sk_buff *skb, struct net *net)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct sock *meta_sk = NULL;

	/* MPTCP structures not initialized */
	if (mptcp_init_failed)
		return 0;

	if (skb->protocol == htons(ETH_P_IP))
		meta_sk = mptcp_v4_search_req(th->source, ip_hdr(skb)->saddr,
					      ip_hdr(skb)->daddr, net);
#if IS_ENABLED(CONFIG_IPV6)
	else /* IPv6 */
		meta_sk = mptcp_v6_search_req(th->source, &ipv6_hdr(skb)->saddr,
					      &ipv6_hdr(skb)->daddr, net);
#endif /* CONFIG_IPV6 */

	if (!meta_sk)
		return 0;

	TCP_SKB_CB(skb)->mptcp_flags = MPTCPHDR_JOIN;

	bh_lock_sock_nested(meta_sk);
	if (sock_owned_by_user(meta_sk)) {
		skb->sk = meta_sk;
		if (unlikely(sk_add_backlog(meta_sk, skb,
					    meta_sk->sk_rcvbuf + meta_sk->sk_sndbuf))) {
			bh_unlock_sock(meta_sk);
			NET_INC_STATS_BH(net, LINUX_MIB_TCPBACKLOGDROP);
			sock_put(meta_sk); /* Taken by mptcp_search_req */
			kfree_skb(skb);
			return 1;
		}
	} else if (skb->protocol == htons(ETH_P_IP)) {
		tcp_v4_do_rcv(meta_sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	} else { /* IPv6 */
		tcp_v6_do_rcv(meta_sk, skb);
#endif /* CONFIG_IPV6 */
	}
	bh_unlock_sock(meta_sk);
	sock_put(meta_sk); /* Taken by mptcp_vX_search_req */
	return 1;
}

struct mp_join *mptcp_find_join(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	unsigned char *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);

	/* Jump through the options to check whether JOIN is there */
	ptr = (unsigned char *)(th + 1);
	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return NULL;
			if (opsize > length)
				return NULL;  /* don't parse partial options */
			if (opcode == TCPOPT_MPTCP &&
			    ((struct mptcp_option *)(ptr - 2))->sub == MPTCP_SUB_JOIN) {
				return (struct mp_join *)(ptr - 2);
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
	return NULL;
}

int mptcp_lookup_join(struct sk_buff *skb, struct inet_timewait_sock *tw)
{
	struct mptcp_cb *mpcb;
	struct sock *meta_sk;
	u32 token;
	struct mp_join *join_opt = mptcp_find_join(skb);
	if (!join_opt)
		return 0;

	/* MPTCP structures were not initialized, so return error */
	if (mptcp_init_failed)
		return -1;

	token = join_opt->u.syn.token;
	meta_sk = mptcp_hash_find(dev_net(skb_dst(skb)->dev), token);
	if (!meta_sk) {
		mptcp_debug("%s:mpcb not found:%x\n", __func__, token);
		return -1;
	}

	mpcb = tcp_sk(meta_sk)->mpcb;
	if (mpcb->infinite_mapping_rcv || mpcb->send_infinite_mapping) {
		/* We are in fallback-mode on the reception-side -
		 * no new subflows!
		 */
		sock_put(meta_sk); /* Taken by mptcp_hash_find */
		return -1;
	}

	/* Coming from time-wait-sock processing in tcp_v4_rcv.
	 * We have to deschedule it before continuing, because otherwise
	 * mptcp_v4_do_rcv will hit again on it inside tcp_v4_hnd_req.
	 */
	if (tw) {
		inet_twsk_deschedule(tw, &tcp_death_row);
		inet_twsk_put(tw);
	}

	TCP_SKB_CB(skb)->mptcp_flags = MPTCPHDR_JOIN;
	/* OK, this is a new syn/join, let's create a new open request and
	 * send syn+ack
	 */
	bh_lock_sock_nested(meta_sk);
	if (sock_owned_by_user(meta_sk)) {
		skb->sk = meta_sk;
		if (unlikely(sk_add_backlog(meta_sk, skb,
					    meta_sk->sk_rcvbuf + meta_sk->sk_sndbuf))) {
			bh_unlock_sock(meta_sk);
			NET_INC_STATS_BH(sock_net(meta_sk),
					 LINUX_MIB_TCPBACKLOGDROP);
			sock_put(meta_sk); /* Taken by mptcp_hash_find */
			kfree_skb(skb);
			return 1;
		}
	} else if (skb->protocol == htons(ETH_P_IP)) {
		tcp_v4_do_rcv(meta_sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		tcp_v6_do_rcv(meta_sk, skb);
#endif /* CONFIG_IPV6 */
	}
	bh_unlock_sock(meta_sk);
	sock_put(meta_sk); /* Taken by mptcp_hash_find */
	return 1;
}

int mptcp_do_join_short(struct sk_buff *skb, struct mptcp_options_received *mopt,
			struct tcp_options_received *tmp_opt, struct net *net)
{
	struct sock *meta_sk;
	u32 token;

	token = mopt->mptcp_rem_token;
	meta_sk = mptcp_hash_find(net, token);
	if (!meta_sk) {
		mptcp_debug("%s:mpcb not found:%x\n", __func__, token);
		return -1;
	}

	TCP_SKB_CB(skb)->mptcp_flags = MPTCPHDR_JOIN;

	/* OK, this is a new syn/join, let's create a new open request and
	 * send syn+ack
	 */
	bh_lock_sock(meta_sk);

	/* This check is also done in mptcp_vX_do_rcv. But, there we cannot
	 * call tcp_vX_send_reset, because we hold already two socket-locks.
	 * (the listener and the meta from above)
	 *
	 * And the send-reset will try to take yet another one (ip_send_reply).
	 * Thus, we propagate the reset up to tcp_rcv_state_process.
	 */
	if (tcp_sk(meta_sk)->mpcb->infinite_mapping_rcv ||
	    tcp_sk(meta_sk)->mpcb->send_infinite_mapping ||
	    meta_sk->sk_state == TCP_CLOSE || !tcp_sk(meta_sk)->inside_tk_table) {
		bh_unlock_sock(meta_sk);
		sock_put(meta_sk); /* Taken by mptcp_hash_find */
		return -1;
	}

	if (sock_owned_by_user(meta_sk)) {
		skb->sk = meta_sk;
		if (unlikely(sk_add_backlog(meta_sk, skb,
					    meta_sk->sk_rcvbuf + meta_sk->sk_sndbuf)))
			NET_INC_STATS_BH(net, LINUX_MIB_TCPBACKLOGDROP);
		else
			/* Must make sure that upper layers won't free the
			 * skb if it is added to the backlog-queue.
			 */
			skb_get(skb);
	} else {
		/* mptcp_v4_do_rcv tries to free the skb - we prevent this, as
		 * the skb will finally be freed by tcp_v4_do_rcv (where we are
		 * coming from)
		 */
		skb_get(skb);
		if (skb->protocol == htons(ETH_P_IP)) {
			tcp_v4_do_rcv(meta_sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
		} else { /* IPv6 */
			tcp_v6_do_rcv(meta_sk, skb);
#endif /* CONFIG_IPV6 */
		}
	}

	bh_unlock_sock(meta_sk);
	sock_put(meta_sk); /* Taken by mptcp_hash_find */
	return 0;
}

void mptcp_retry_subflow_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct mptcp_cb *mpcb =
		container_of(delayed_work, struct mptcp_cb, subflow_retry_work);
	struct sock *meta_sk = mpcb->meta_sk;
	struct mptcp_local_addresses *mptcp_local;
	int iter = 0, i;

	/* We need a local (stable) copy of the address-list. Really, it is not
	 * such a big deal, if the address-list is not 100% up-to-date.
	 */
	rcu_read_lock_bh();
	mptcp_local = rcu_dereference(sock_net(meta_sk)->mptcp.local);
	mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local), GFP_ATOMIC);
	rcu_read_unlock_bh();

	if (!mptcp_local)
		return;

next_subflow:
	if (iter) {
		release_sock(meta_sk);
		mutex_unlock(&mpcb->mutex);

		yield();
	}
	mutex_lock(&mpcb->mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	iter++;

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		struct mptcp_rem4 *rem = &mpcb->remaddr4[i];
		/* Do we need to retry establishing a subflow ? */
		if (rem->retry_bitfield) {
			int i = mptcp_find_free_index(~rem->retry_bitfield);
			mptcp_init4_subsockets(meta_sk, &mptcp_local->locaddr4[i], rem);
			rem->retry_bitfield &= ~(1 << mptcp_local->locaddr4[i].id);
			goto next_subflow;
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		struct mptcp_rem6 *rem = &mpcb->remaddr6[i];

		/* Do we need to retry establishing a subflow ? */
		if (rem->retry_bitfield) {
			int i = mptcp_find_free_index(~rem->retry_bitfield);
			mptcp_init6_subsockets(meta_sk, &mptcp_local->locaddr6[i], rem);
			rem->retry_bitfield &= ~(1 << mptcp_local->locaddr6[i].id);
			goto next_subflow;
		}
	}
#endif

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mutex);
	sock_put(meta_sk);
}

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
void mptcp_create_subflow_worker(struct work_struct *work)
{
	struct mptcp_cb *mpcb = container_of(work, struct mptcp_cb, subflow_work);
	struct sock *meta_sk = mpcb->meta_sk;
	struct mptcp_local_addresses *mptcp_local;
	int iter = 0, retry = 0;
	int i;

	/* We need a local (stable) copy of the address-list. Really, it is not
	 * such a big deal, if the address-list is not 100% up-to-date.
	 */
	rcu_read_lock_bh();
	mptcp_local = rcu_dereference(sock_net(meta_sk)->mptcp.local);
	mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local), GFP_ATOMIC);
	rcu_read_unlock_bh();

next_subflow:
	if (iter) {
		release_sock(meta_sk);
		mutex_unlock(&mpcb->mutex);

		yield();
	}
	mutex_lock(&mpcb->mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	iter++;

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		goto exit;

	if (sysctl_mptcp_ndiffports > iter &&
	    sysctl_mptcp_ndiffports > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			mptcp_init4_subsockets(meta_sk, &mptcp_local->locaddr4[0],
					       &mpcb->remaddr4[0]);
		} else {
#if IS_ENABLED(CONFIG_IPV6)
			mptcp_init6_subsockets(meta_sk, &mptcp_local->locaddr6[0],
					       &mpcb->remaddr6[0]);
#endif
		}
		goto next_subflow;
	}
	if (sysctl_mptcp_ndiffports > 1 &&
	    sysctl_mptcp_ndiffports == mpcb->cnt_subflows)
		goto exit;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		struct mptcp_rem4 *rem;
		u8 remaining_bits;

		rem = &mpcb->remaddr4[i];
		remaining_bits = ~(rem->bitfield) & mptcp_local->loc4_bits;

		/* Are there still combinations to handle? */
		if (remaining_bits) {
			int i = mptcp_find_free_index(~remaining_bits);
			/* If a route is not yet available then retry once */
			if (mptcp_init4_subsockets(meta_sk, &mptcp_local->locaddr4[i],
						   rem) == -ENETUNREACH)
				retry = rem->retry_bitfield |=
					(1 << mptcp_local->locaddr4[i].id);
			goto next_subflow;
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		struct mptcp_rem6 *rem;
		u8 remaining_bits;

		rem = &mpcb->remaddr6[i];
		remaining_bits = ~(rem->bitfield) & mptcp_local->loc6_bits;

		/* Are there still combinations to handle? */
		if (remaining_bits) {
			int i = mptcp_find_free_index(~remaining_bits);
			/* If a route is not yet available then retry once */
			if (mptcp_init6_subsockets(meta_sk, &mptcp_local->locaddr6[i],
						   rem) == -ENETUNREACH)
				retry = rem->retry_bitfield |=
					(1 << mptcp_local->locaddr6[i].id);
			goto next_subflow;
		}
	}
#endif

	if (retry && !delayed_work_pending(&mpcb->subflow_retry_work)) {
		sock_hold(meta_sk);
		queue_delayed_work(mptcp_wq, &mpcb->subflow_retry_work,
				   msecs_to_jiffies(MPTCP_SUBFLOW_RETRY_DELAY));
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mutex);
	sock_put(meta_sk);
}

void mptcp_create_subflows(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&mpcb->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &mpcb->subflow_work);
	}
}

void mptcp_address_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work = container_of(work,
							 struct delayed_work, work);
	struct netns_mptcp *mptcpns = container_of(delayed_work, struct netns_mptcp,
						   address_worker);
	struct net *net = container_of(mptcpns, struct net, mptcp);
	struct mptcp_address_events *event = NULL;
	int i;

next_event:
	kfree(event);

	/* First, let's dequeue an event from our event-list */
	spin_lock_bh(&net->mptcp.local_lock);

	event = list_first_entry_or_null(&net->mptcp.events,
					 struct mptcp_address_events, list);
	if (!event) {
		spin_unlock_bh(&net->mptcp.local_lock);
		return;
	}

	list_del(&event->list);

	spin_unlock_bh(&net->mptcp.local_lock);

	/* Now we iterate over the MPTCP-sockets and apply the event. */
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		struct tcp_sock *meta_tp;

		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[i],
					       tk_table) {
			struct mptcp_cb *mpcb = meta_tp->mpcb;
			struct sock *meta_sk = (struct sock *)meta_tp;

			if (sock_net(meta_sk) != net)
				continue;

			if (unlikely(!atomic_inc_not_zero(&meta_sk->sk_refcnt)))
				continue;

			bh_lock_sock(meta_sk);

			if (!meta_tp->mpc || !is_meta_sk(meta_sk) ||
			    mpcb->infinite_mapping_snd ||
			    mpcb->infinite_mapping_rcv ||
			    mpcb->send_infinite_mapping)
				goto next;

			if (sock_owned_by_user(meta_sk)) {
				if (!test_and_set_bit(MPTCP_PATH_MANAGER,
						      &meta_tp->tsq_flags))
					sock_hold(meta_sk);

				goto next;
			}

			if (event->code == MPTCP_EVENT_ADD) {
				if (event->family == AF_INET)
					mptcp_v4_send_add_addr(event->id, mpcb);
#if IS_ENABLED(CONFIG_IPV6)
				if (event->family == AF_INET6)
					mptcp_v6_send_add_addr(event->id, mpcb);
#endif

				mptcp_create_subflows(mpcb->meta_sk);
			}

			if (event->code == MPTCP_EVENT_DEL) {
				struct sock *sk, *tmpsk;
				int j, id = event->id;
				struct mptcp_local_addresses *mptcp_local;

				/* Look for the socket and remove him */
				mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
					if (event->family == AF_INET &&
					    (sk->sk_family == AF_INET ||
					     mptcp_v6_is_v4_mapped(sk)) &&
					     inet_sk(sk)->inet_saddr != event->u.addr4.s_addr)
						continue;

					if (event->family == AF_INET6 &&
					    sk->sk_family == AF_INET6 &&
					    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &event->u.addr6))
						continue;

					id = tcp_sk(sk)->mptcp->loc_id;
					mptcp_reinject_data(sk, 0);
					mptcp_sub_force_close(sk);
				}

				mpcb->remove_addrs |= (1 << id);
				sk = mptcp_select_ack_sock(meta_sk, 0);
				if (sk)
					tcp_send_ack(sk);

				mptcp_local = rcu_dereference(net->mptcp.local);
				if (event->family == AF_INET) {
					mptcp_for_each_bit_set(mpcb->rem4_bits, j) {
						mpcb->remaddr4[j].bitfield &= mptcp_local->loc4_bits;
						mpcb->remaddr4[j].retry_bitfield &= mptcp_local->loc4_bits;
					}
				} else {
					mptcp_for_each_bit_set(mpcb->rem6_bits, j) {
						mpcb->remaddr6[j].bitfield &= mptcp_local->loc6_bits;
						mpcb->remaddr6[j].retry_bitfield &= mptcp_local->loc6_bits;
					}
				}
			}

			if (event->code == MPTCP_EVENT_MOD) {
				struct sock *sk;

				mptcp_for_each_sk(mpcb, sk) {
					struct tcp_sock *tp = tcp_sk(sk);
					if (event->family == AF_INET &&
					    (sk->sk_family == AF_INET ||
					     mptcp_v6_is_v4_mapped(sk)) &&
					     inet_sk(sk)->inet_saddr == event->u.addr4.s_addr) {
						if (event->low_prio != tp->mptcp->low_prio) {
							tp->mptcp->send_mp_prio = 1;
							tp->mptcp->low_prio = event->low_prio;

							tcp_send_ack(sk);
						}
					}

					if (event->family == AF_INET6 &&
					    sk->sk_family == AF_INET6 &&
					    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &event->u.addr6)) {
						if (event->low_prio != tp->mptcp->low_prio) {
							tp->mptcp->send_mp_prio = 1;
							tp->mptcp->low_prio = event->low_prio;

							tcp_send_ack(sk);
						}
					}
				}
			}
next:
			bh_unlock_sock(meta_sk);
			sock_put(meta_sk);
		}
		rcu_read_unlock_bh();
	}
	goto next_event;
}

/**
 * React on IPv4+IPv6-addr add/rem-events
 */
int mptcp_pm_addr_event_handler(unsigned long event, void *ptr, int family)
{
	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (sysctl_mptcp_ndiffports > 1)
		return NOTIFY_DONE;

	if (family == AF_INET) {
		struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
		struct net *net = dev_net(ifa->ifa_dev->dev);

		mptcp_pm_addr4_event_handler(ifa, event, net);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)ptr;
		struct net *net = dev_net(ifa->idev->dev);

		mptcp_pm_addr6_event_handler(ifa, event, net);
#endif
	}

	return NOTIFY_DONE;
}

/* Called upon release_sock, if the socket was owned by the user during
 * a path-management event.
 */
void mptcp_path_manager(struct sock *meta_sk)
{
	struct mptcp_local_addresses *mptcp_local;
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *tmpsk;
	int i;

	rcu_read_lock();
	mptcp_local = rcu_dereference(sock_net(meta_sk)->mptcp.local);

	/* First, detect modifications or additions */
	mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
		struct in_addr ifa = mptcp_local->locaddr4[i].addr;
		bool found = false;

		mptcp_for_each_sk(mpcb, sk) {
			struct tcp_sock *tp = tcp_sk(sk);

			if (sk->sk_family == AF_INET6 &&
			    !mptcp_v6_is_v4_mapped(sk))
				continue;

			if (inet_sk(sk)->inet_saddr != ifa.s_addr)
				continue;

			found = true;

			if (mptcp_local->locaddr4[i].low_prio != tp->mptcp->low_prio) {
				tp->mptcp->send_mp_prio = 1;
				tp->mptcp->low_prio = mptcp_local->locaddr4[i].low_prio;

				tcp_send_ack(sk);
			}
		}

		if (!found) {
			mptcp_v4_send_add_addr(i, mpcb);
			mptcp_create_subflows(meta_sk);
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
		struct in6_addr ifa = mptcp_local->locaddr6[i].addr;
		bool found = false;

		mptcp_for_each_sk(mpcb, sk) {
			struct tcp_sock *tp = tcp_sk(sk);

			if (sk->sk_family == AF_INET ||
			    mptcp_v6_is_v4_mapped(sk))
				continue;

			if (!ipv6_addr_equal(&inet6_sk(sk)->saddr, &ifa))
				continue;

			found = true;

			if (mptcp_local->locaddr6[i].low_prio != tp->mptcp->low_prio) {
				tp->mptcp->send_mp_prio = 1;
				tp->mptcp->low_prio = mptcp_local->locaddr6[i].low_prio;

				tcp_send_ack(sk);
			}
		}

		if (!found) {
			mptcp_v6_send_add_addr(i, mpcb);
			mptcp_create_subflows(meta_sk);
		}
	}
#endif

	/* Now, detect address-removals */
	mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
		bool shall_remove = true;

		if (sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(sk)) {
			mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
				if (inet_sk(sk)->inet_saddr == mptcp_local->locaddr4[i].addr.s_addr) {
					shall_remove = false;
					break;
				}
			}
		} else {
			mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
				if (ipv6_addr_equal(&inet6_sk(sk)->saddr, &mptcp_local->locaddr6[i].addr)) {
					shall_remove = false;
					break;
				}
			}
		}

		if (shall_remove) {
			int j;

			mptcp_reinject_data(sk, 0);
			mptcp_sub_force_close(sk);

			mpcb->remove_addrs |= (1 << tcp_sk(sk)->mptcp->loc_id);
			sk = mptcp_select_ack_sock(meta_sk, 0);
			if (sk)
				tcp_send_ack(sk);

			if (sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(sk)) {
				mptcp_for_each_bit_set(mpcb->rem4_bits, j) {
					mpcb->remaddr4[j].bitfield &= mptcp_local->loc4_bits;
					mpcb->remaddr4[j].retry_bitfield &= mptcp_local->loc4_bits;
				}
			} else {
				mptcp_for_each_bit_set(mpcb->rem6_bits, j) {
					mpcb->remaddr6[j].bitfield &= mptcp_local->loc6_bits;
					mpcb->remaddr6[j].retry_bitfield &= mptcp_local->loc6_bits;
				}
			}
		}
	}
	rcu_read_unlock();
}

static struct mptcp_address_events *mptcp_lookup_similar_event(struct net *net,
							       struct mptcp_address_events *event)
{
	struct mptcp_address_events *eventq;

	list_for_each_entry(eventq, &net->mptcp.events, list) {
		if (eventq->family != event->family)
			continue;
		if (eventq->id != event->id)
			continue;
		if (event->family == AF_INET) {
			if (eventq->u.addr4.s_addr == event->u.addr4.s_addr)
				return eventq;
		} else {
			if (ipv6_addr_equal(&eventq->u.addr6, &event->u.addr6))
				return eventq;
		}
	}
	return NULL;
}

/* We already hold the net-namespace MPTCP-lock */
void mptcp_add_pm_event(struct net *net, struct mptcp_address_events *event)
{
	struct mptcp_address_events *eventq = mptcp_lookup_similar_event(net, event);

	if (eventq) {
		/* Add -> Remove. So, no event at all */
		switch (event->code) {
		case MPTCP_EVENT_DEL:
			if (eventq->code == MPTCP_EVENT_ADD) {
				list_del(&eventq->list);
				kfree(eventq);
			}
			break;
		case MPTCP_EVENT_ADD:
			eventq->low_prio = event->low_prio;
			eventq->code = MPTCP_EVENT_ADD;
			break;
		case MPTCP_EVENT_MOD:
			eventq->low_prio = event->low_prio;
			break;
		}

		return;
	}

	/* OK, we have to add the new address to the wait queue */
	eventq = kmemdup(event, sizeof(struct mptcp_address_events), GFP_ATOMIC);
	if (!eventq)
		return;

	list_add_tail(&eventq->list, &net->mptcp.events);

	/* Create work-queue */
	if (!delayed_work_pending(&net->mptcp.address_worker))
		queue_delayed_work(mptcp_wq, &net->mptcp.address_worker,
				   msecs_to_jiffies(500));
}

#ifdef CONFIG_PROC_FS

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

			if (!meta_tp->mpc || !net_eq(net, sock_net(meta_sk)))
				continue;

			seq_printf(seq, "%4d: %04X %04X ", n++,
				   mpcb->mptcp_loc_token,
				   mpcb->mptcp_rem_token);
			if (meta_sk->sk_family == AF_INET ||
			    mptcp_v6_is_v4_mapped(meta_sk)) {
				seq_printf(seq, " 0 %08X:%04X                         %08X:%04X                        ",
					   isk->inet_saddr,
					   ntohs(isk->inet_sport),
					   isk->inet_daddr,
					   ntohs(isk->inet_dport));
#if IS_ENABLED(CONFIG_IPV6)
			} else if (meta_sk->sk_family == AF_INET6) {
				struct in6_addr *src = &isk->pinet6->saddr;
				struct in6_addr *dst = &isk->pinet6->daddr;
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
	struct mptcp_local_addresses *mptcp_local;

	if (!proc_create("mptcp", S_IRUGO, net->proc_net, &mptcp_pm_seq_fops))
		return -ENOMEM;

	mptcp_local = kzalloc(sizeof(*mptcp_local), GFP_KERNEL);
	if (!mptcp_local)
		goto kzalloc_err;

	mptcp_local->next_v4_index = 1;

	rcu_assign_pointer(net->mptcp.local, mptcp_local);
	INIT_DELAYED_WORK(&net->mptcp.address_worker, mptcp_address_worker);
	INIT_LIST_HEAD(&net->mptcp.events);
	spin_lock_init(&net->mptcp.local_lock);

	return 0;

kzalloc_err:
	remove_proc_entry("mptcp", net->proc_net);

	return 1;
}

static void mptcp_pm_exit_net(struct net *net)
{
	remove_proc_entry("mptcp", net->proc_net);
}

static struct pernet_operations mptcp_pm_proc_ops = {
	.init = mptcp_pm_init_net,
	.exit = mptcp_pm_exit_net,
};
#endif

/* General initialization of MPTCP_PM */
int mptcp_pm_init(void)
{
	int i, ret;
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		INIT_HLIST_NULLS_HEAD(&tk_hashtable[i], i);
		INIT_LIST_HEAD(&mptcp_reqsk_htb[i]);
		INIT_HLIST_NULLS_HEAD(&mptcp_reqsk_tk_htb[i], i);
	}

	spin_lock_init(&mptcp_reqsk_hlock);
	spin_lock_init(&mptcp_tk_hashlock);

#ifdef CONFIG_PROC_FS
	ret = register_pernet_subsys(&mptcp_pm_proc_ops);
	if (ret)
		goto out;
#endif

#if IS_ENABLED(CONFIG_IPV6)
	ret = mptcp_pm_v6_init();
	if (ret)
		goto mptcp_pm_v6_failed;
#endif
	ret = mptcp_pm_v4_init();
	if (ret)
		goto mptcp_pm_v4_failed;

out:
	return ret;

mptcp_pm_v4_failed:
#if IS_ENABLED(CONFIG_IPV6)
	mptcp_pm_v6_undo();

mptcp_pm_v6_failed:
#endif
#ifdef CONFIG_PROC_FS
	unregister_pernet_subsys(&mptcp_pm_proc_ops);
#endif
	goto out;
}

void mptcp_pm_undo(void)
{
#if IS_ENABLED(CONFIG_IPV6)
	mptcp_pm_v6_undo();
#endif
	mptcp_pm_v4_undo();
#ifdef CONFIG_PROC_FS
	unregister_pernet_subsys(&mptcp_pm_proc_ops);
#endif
}
