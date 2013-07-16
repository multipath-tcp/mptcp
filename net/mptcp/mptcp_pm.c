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

u8 mptcp_get_loc_addrid(struct mptcp_cb *mpcb, struct sock *sk)
{
	int i;

	if (sk->sk_family == AF_INET) {
		mptcp_for_each_bit_set(mpcb->loc4_bits, i) {
			if (mpcb->locaddr4[i].addr.s_addr ==
					inet_sk(sk)->inet_saddr)
				return mpcb->locaddr4[i].id;
		}

		mptcp_debug("%s %pI4 not locally found\n", __func__,
			    &inet_sk(sk)->inet_saddr);
		BUG();
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6) {
		mptcp_for_each_bit_set(mpcb->loc6_bits, i) {
			if (ipv6_addr_equal(&mpcb->locaddr6[i].addr,
					    &inet6_sk(sk)->saddr))
				return mpcb->locaddr6[i].id;
		}

		mptcp_debug("%s %pI6 not locally found\n", __func__,
			    &inet6_sk(sk)->saddr);
		BUG();
	}
#endif /* CONFIG_IPV6 */

	BUG();
	return 0;
}

void mptcp_set_addresses(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct net *netns = sock_net(meta_sk);
	struct net_device *dev;

	/* if multiports is requested, we work with the main address
	 * and play only with the ports
	 */
	if (sysctl_mptcp_ndiffports > 1)
		return;

	rcu_read_lock();
	read_lock_bh(&dev_base_lock);

	for_each_netdev(netns, dev) {
		if (netif_running(dev)) {
			struct in_device *in_dev = __in_dev_get_rcu(dev);
			struct in_ifaddr *ifa;
			__be32 ifa_address;
#if IS_ENABLED(CONFIG_IPV6)
			struct inet6_dev *in6_dev = __in6_dev_get(dev);
			struct inet6_ifaddr *ifa6;
#endif

			if (dev->flags & (IFF_LOOPBACK | IFF_NOMULTIPATH))
				continue;

			if (!in_dev)
				goto cont_ipv6;

			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				int i;
				ifa_address = ifa->ifa_local;

				if (ifa->ifa_scope == RT_SCOPE_HOST)
					continue;

				if ((meta_sk->sk_family == AF_INET ||
				     mptcp_v6_is_v4_mapped(meta_sk)) &&
				    inet_sk(meta_sk)->inet_saddr == ifa_address) {
					mpcb->locaddr4[0].low_prio = dev->flags &
								IFF_MPBACKUP ? 1 : 0;
					continue;
				}

				i = __mptcp_find_free_index(mpcb->loc4_bits, -1,
							    mpcb->next_v4_index);
				if (i < 0) {
					mptcp_debug("%s: At max num of local addresses: %d --- not adding address: %pI4\n",
						    __func__, MPTCP_MAX_ADDR,
						    &ifa_address);
					goto out;
				}
				mpcb->locaddr4[i].addr.s_addr = ifa_address;
				mpcb->locaddr4[i].port = 0;
				mpcb->locaddr4[i].id = i;
				mpcb->locaddr4[i].low_prio = (dev->flags & IFF_MPBACKUP) ?
								1 : 0;
				mpcb->loc4_bits |= (1 << i);
				mpcb->next_v4_index = i + 1;
				mptcp_v4_send_add_addr(i, mpcb);
			}

cont_ipv6:
; /* This ; is necessary to fix build-errors when IPv6 is disabled */
#if IS_ENABLED(CONFIG_IPV6)
			if (!in6_dev)
				continue;

			list_for_each_entry(ifa6, &in6_dev->addr_list, if_list) {
				int addr_type = ipv6_addr_type(&ifa6->addr);
				int i;

				if (addr_type == IPV6_ADDR_ANY ||
				    addr_type & IPV6_ADDR_LOOPBACK ||
				    addr_type & IPV6_ADDR_LINKLOCAL)
					continue;

				if (meta_sk->sk_family == AF_INET6 &&
				    ipv6_addr_equal(&inet6_sk(meta_sk)->saddr,
						    &(ifa6->addr))) {
					mpcb->locaddr6[0].low_prio = dev->flags &
								IFF_MPBACKUP ? 1 : 0;
					continue;
				}

				i = __mptcp_find_free_index(mpcb->loc6_bits, -1,
							    mpcb->next_v6_index);
				if (i < 0) {
					mptcp_debug("%s: At max num of local addresses: %d --- not adding address: %pI6\n",
						    __func__, MPTCP_MAX_ADDR,
						    &ifa6->addr);
					goto out;
				}

				mpcb->locaddr6[i].addr = ifa6->addr;
				mpcb->locaddr6[i].port = 0;
				mpcb->locaddr6[i].id = i + MPTCP_MAX_ADDR;
				mpcb->locaddr6[i].low_prio = (dev->flags & IFF_MPBACKUP) ?
								1 : 0;
				mpcb->loc6_bits |= (1 << i);
				mpcb->next_v6_index = i + 1;
				mptcp_v6_send_add_addr(i, mpcb);
			}
#endif
		}
	}

out:
	read_unlock_bh(&dev_base_lock);
	rcu_read_unlock();
}

int mptcp_check_req(struct sk_buff *skb, struct net *net)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct sock *meta_sk = NULL;

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

	token = join_opt->u.syn.token;
	meta_sk = mptcp_hash_find(dev_net(skb_dst(skb)->dev), token);
	if (!meta_sk) {
		mptcp_debug("%s:mpcb not found:%x\n", __func__, token);
		return -1;
	}

	mpcb = tcp_sk(meta_sk)->mpcb;
	if (mpcb->infinite_mapping_rcv) {
		/* We are in fallback-mode on the reception-side -
		 * noe new subflows!
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
	int iter = 0, i;

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
			mptcp_init4_subsockets(meta_sk, &mpcb->locaddr4[i], rem);
			rem->retry_bitfield &= ~(1 << mpcb->locaddr4[i].id);
			goto next_subflow;
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		struct mptcp_rem6 *rem = &mpcb->remaddr6[i];

		/* Do we need to retry establishing a subflow ? */
		if (rem->retry_bitfield) {
			int i = mptcp_find_free_index(~rem->retry_bitfield);
			mptcp_init6_subsockets(meta_sk, &mpcb->locaddr6[i], rem);
			rem->retry_bitfield &= ~(1 << mpcb->locaddr6[i].id);
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
	int iter = 0, retry = 0;
	int i;

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

	if (sysctl_mptcp_ndiffports > iter &&
	    sysctl_mptcp_ndiffports > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			mptcp_init4_subsockets(meta_sk, &mpcb->locaddr4[0],
					       &mpcb->remaddr4[0]);
		} else {
#if IS_ENABLED(CONFIG_IPV6)
			mptcp_init6_subsockets(meta_sk, &mpcb->locaddr6[0],
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
		remaining_bits = ~(rem->bitfield) & mpcb->loc4_bits;

		/* Are there still combinations to handle? */
		if (remaining_bits) {
			int i = mptcp_find_free_index(~remaining_bits);
			/* If a route is not yet available then retry once */
			if (mptcp_init4_subsockets(meta_sk, &mpcb->locaddr4[i],
						   rem) == -ENETUNREACH)
				retry = rem->retry_bitfield |=
					(1 << mpcb->locaddr4[i].id);
			goto next_subflow;
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		struct mptcp_rem6 *rem;
		u8 remaining_bits;

		rem = &mpcb->remaddr6[i];
		remaining_bits = ~(rem->bitfield) & mpcb->loc6_bits;

		/* Are there still combinations to handle? */
		if (remaining_bits) {
			int i = mptcp_find_free_index(~remaining_bits);
			/* If a route is not yet available then retry once */
			if (mptcp_init6_subsockets(meta_sk, &mpcb->locaddr6[i],
						   rem) == -ENETUNREACH)
				retry = rem->retry_bitfield |=
					(1 << mpcb->locaddr6[i].id);
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

	if ((mpcb->master_sk &&
	     !tcp_sk(mpcb->master_sk)->mptcp->fully_established) ||
	    mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&mpcb->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &mpcb->subflow_work);
	}
}

void mptcp_address_worker(struct work_struct *work)
{
	struct mptcp_cb *mpcb = container_of(work, struct mptcp_cb, address_work);
	struct sock *meta_sk = mpcb->meta_sk, *sk, *tmpsk;
	struct net *netns = sock_net(meta_sk);
	struct net_device *dev;
	int i;

	mutex_lock(&mpcb->mutex);
	lock_sock(meta_sk);

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	/* The following is meant to run with bh disabled */
	local_bh_disable();

	/* First, we iterate over the interfaces to find addresses not yet
	 * in our local list.
	 */

	rcu_read_lock();
	read_lock_bh(&dev_base_lock);

	for_each_netdev(netns, dev) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);
		struct in_ifaddr *ifa;
#if IS_ENABLED(CONFIG_IPV6)
		struct inet6_dev *in6_dev = __in6_dev_get(dev);
		struct inet6_ifaddr *ifa6;
#endif

		if (dev->flags & (IFF_LOOPBACK | IFF_NOMULTIPATH))
			continue;

		if (!in_dev)
			goto cont_ipv6;

		for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
			unsigned long event;

			if (!netif_running(in_dev->dev)) {
				event = NETDEV_DOWN;
			} else {
				/* If it's up, it may have been changed or came up.
				 * We set NETDEV_CHANGE, to take the good
				 * code-path in mptcp_pm_addr4_event_handler
				 */
				event = NETDEV_CHANGE;
			}

			mptcp_pm_addr4_event_handler(ifa, event, mpcb);
		}
cont_ipv6:
; /* This ; is necessary to fix build-errors when IPv6 is disabled */
#if IS_ENABLED(CONFIG_IPV6)
		if (!in6_dev)
			continue;

		read_lock(&in6_dev->lock);
		list_for_each_entry(ifa6, &in6_dev->addr_list, if_list) {
			unsigned long event;

			if (!netif_running(in_dev->dev)) {
				event = NETDEV_DOWN;
			} else {
				/* If it's up, it may have been changed or came up.
				 * We set NETDEV_CHANGE, to take the good
				 * code-path in mptcp_pm_addr4_event_handler
				 */
				event = NETDEV_CHANGE;
			}

			mptcp_pm_addr6_event_handler(ifa6, event, mpcb);
		}
		read_unlock(&in6_dev->lock);
#endif
	}

	/* Second, we iterate over our local addresses and check if they
	 * still exist in the interface-list.
	 */

	/* MPCB-Local IPv4 Addresses */
	mptcp_for_each_bit_set(mpcb->loc4_bits, i) {
		int j;

		for_each_netdev(netns, dev) {
			struct in_device *in_dev = __in_dev_get_rcu(dev);
			struct in_ifaddr *ifa;

			if (dev->flags & (IFF_LOOPBACK | IFF_NOMULTIPATH) ||
			    !in_dev)
				continue;

			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_address == mpcb->locaddr4[i].addr.s_addr &&
				    netif_running(dev))
					goto next_loc_addr;
			}
		}

		/* We did not find the address or the interface became NOMULTIPATH.
		 * We thus have to remove it.
		 */

		/* Look for the socket and remove him */
		mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
			if (sk->sk_family != AF_INET ||
			    inet_sk(sk)->inet_saddr != mpcb->locaddr4[i].addr.s_addr)
				continue;

			mptcp_reinject_data(sk, 0);
			mptcp_sub_force_close(sk);
		}

		/* Now, remove the address from the local ones */
		mpcb->loc4_bits &= ~(1 << i);

		mpcb->remove_addrs |= (1 << mpcb->locaddr4[i].id);
		sk = mptcp_select_ack_sock(meta_sk, 0);
		if (sk)
			tcp_send_ack(sk);

		mptcp_for_each_bit_set(mpcb->rem4_bits, j)
			mpcb->remaddr4[j].bitfield &= mpcb->loc4_bits;

next_loc_addr:
		continue; /* necessary here due to the previous label */
	}

#if IS_ENABLED(CONFIG_IPV6)
	/* MPCB-Local IPv6 Addresses */
	mptcp_for_each_bit_set(mpcb->loc6_bits, i) {
		int j;

		for_each_netdev(netns, dev) {
			struct inet6_dev *in6_dev = __in6_dev_get(dev);
			struct inet6_ifaddr *ifa6;

			if (dev->flags & (IFF_LOOPBACK | IFF_NOMULTIPATH) ||
			    !in6_dev)
				continue;

			read_lock(&in6_dev->lock);
			list_for_each_entry(ifa6, &in6_dev->addr_list, if_list) {
				if (ipv6_addr_equal(&mpcb->locaddr6[i].addr, &ifa6->addr) &&
				    netif_running(dev)) {
					read_unlock(&in6_dev->lock);
					goto next_loc6_addr;
				}
			}
			read_unlock(&in6_dev->lock);
		}

		/* We did not find the address or the interface became NOMULTIPATH.
		 * We thus have to remove it.
		 */

		/* Look for the socket and remove him */
		mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
			if (sk->sk_family != AF_INET6 ||
			    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &mpcb->locaddr6[i].addr))
				continue;

			mptcp_reinject_data(sk, 0);
			mptcp_sub_force_close(sk);
		}

		/* Now, remove the address from the local ones */
		mpcb->loc6_bits &= ~(1 << i);

		/* Force sending directly the REMOVE_ADDR option */
		mpcb->remove_addrs |= (1 << mpcb->locaddr6[i].id);
		sk = mptcp_select_ack_sock(meta_sk, 0);
		if (sk)
			tcp_send_ack(sk);

		mptcp_for_each_bit_set(mpcb->rem6_bits, j)
			mpcb->remaddr6[j].bitfield &= mpcb->loc6_bits;

next_loc6_addr:
		continue; /* necessary here due to the previous label */
	}
#endif

	read_unlock_bh(&dev_base_lock);
	rcu_read_unlock();

	local_bh_enable();
exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mutex);
	sock_put(meta_sk);
}

static void mptcp_address_create_worker(struct mptcp_cb *mpcb)
{
	if (!work_pending(&mpcb->address_work)) {
		sock_hold(mpcb->meta_sk);
		queue_work(mptcp_wq, &mpcb->address_work);
	}
}

/**
 * React on IPv4+IPv6-addr add/rem-events
 */
int mptcp_pm_addr_event_handler(unsigned long event, void *ptr, int family)
{
	struct tcp_sock *meta_tp;
	int i;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (sysctl_mptcp_ndiffports > 1)
		return NOTIFY_DONE;

	/* Now we iterate over the mpcb's */
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[i],
					       tk_table) {
			struct mptcp_cb *mpcb = meta_tp->mpcb;
			struct sock *meta_sk = (struct sock *)meta_tp;

			if (unlikely(!atomic_inc_not_zero(&meta_sk->sk_refcnt)))
				continue;

			if (!meta_tp->mpc || !is_meta_sk(meta_sk) ||
			    mpcb->infinite_mapping_snd ||
			    mpcb->infinite_mapping_rcv) {
				sock_put(meta_sk);
				continue;
			}

			bh_lock_sock(meta_sk);
			if (sock_owned_by_user(meta_sk)) {
				mptcp_address_create_worker(mpcb);
			} else {
				if (family == AF_INET)
					mptcp_pm_addr4_event_handler(
							(struct in_ifaddr *)ptr, event, mpcb);
#if IS_ENABLED(CONFIG_IPV6)
				else
					mptcp_pm_addr6_event_handler(
							(struct inet6_ifaddr *)ptr, event, mpcb);
#endif
			}

			bh_unlock_sock(meta_sk);
			sock_put(meta_sk);
		}
		rcu_read_unlock_bh();
	}
	return NOTIFY_DONE;
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

static int mptcp_pm_proc_init_net(struct net *net)
{
	if (!proc_create("mptcp", S_IRUGO, net->proc_net, &mptcp_pm_seq_fops))
		return -ENOMEM;

	return 0;
}

static void mptcp_pm_proc_exit_net(struct net *net)
{
	remove_proc_entry("mptcp", net->proc_net);
}

static struct pernet_operations mptcp_pm_proc_ops = {
	.init = mptcp_pm_proc_init_net,
	.exit = mptcp_pm_proc_exit_net,
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
