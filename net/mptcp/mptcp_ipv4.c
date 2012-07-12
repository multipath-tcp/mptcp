/*
 *	MPTCP implementation - IPv4-specific functions
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer:
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

#include <linux/ip.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>

#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>
#include <net/request_sock.h>
#include <net/tcp.h>

#if IS_ENABLED(CONFIG_IPV6)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

static void mptcp_v4_reqsk_queue_hash_add(struct request_sock *req,
					  unsigned long timeout)
{
	struct inet_connection_sock *meta_icsk =
	    (struct inet_connection_sock *)(mptcp_rsk(req)->mpcb);
	struct listen_sock *lopt = meta_icsk->icsk_accept_queue.listen_opt;
	const u32 h_local = inet_synq_hash(inet_rsk(req)->rmt_addr,
					   inet_rsk(req)->rmt_port,
					   lopt->hash_rnd,
					   lopt->nr_table_entries);
	const u32 h_global = inet_synq_hash(inet_rsk(req)->rmt_addr,
					    inet_rsk(req)->rmt_port,
					    0,
					    MPTCP_HASH_SIZE);
	spin_lock_bh(&mptcp_reqsk_hlock);
	reqsk_queue_hash_req(&meta_icsk->icsk_accept_queue,
			     h_local, req, timeout);
	list_add(&mptcp_rsk(req)->collide_tuple, &mptcp_reqsk_htb[h_global]);
	lopt->qlen++;
	spin_unlock_bh(&mptcp_reqsk_hlock);
}

/* from tcp_v4_conn_request() */
static void mptcp_v4_join_request(struct mptcp_cb *mpcb, struct sk_buff *skb)
{
	struct inet_request_sock *ireq;
	struct request_sock *req;
	struct mptcp_request_sock *mtreq;
	struct tcp_options_received tmp_opt;
	u8 mptcp_hash_mac[20];
	const u8 *hash_location;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;

	req = inet_reqsk_alloc(&mptcp_request_sock_ops);
	if (!req)
		return;

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss = mpcb_meta_tp(mpcb)->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &hash_location, &mpcb->rx_opt, 0);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

	mtreq = mptcp_rsk(req);
	mtreq->mpcb = mpcb;
	mtreq->mptcp_rem_nonce = mpcb->rx_opt.mptcp_recv_nonce;
	mtreq->mptcp_rem_key = mpcb->rx_opt.mptcp_rem_key;
	mtreq->mptcp_loc_key = mpcb->mptcp_loc_key;

	get_random_bytes(&mtreq->mptcp_loc_nonce,
			 sizeof(mtreq->mptcp_loc_nonce));

	mptcp_hmac_sha1((u8 *)&mtreq->mptcp_loc_key,
			(u8 *)&mtreq->mptcp_rem_key,
			(u8 *)&mtreq->mptcp_loc_nonce,
			(u8 *)&mtreq->mptcp_rem_nonce, (u32 *)mptcp_hash_mac);
	mtreq->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;

	mtreq->rem_id = tmp_opt.rem_id;
	mtreq->low_prio = tmp_opt.low_prio;
	tcp_openreq_init(req, &tmp_opt, NULL, skb);

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->opt = tcp_v4_save_options(NULL, skb);

	/* Todo: add the sanity checks here. See tcp_v4_conn_request */

	isn = tcp_v4_init_sequence(skb);

	tcp_rsk(req)->snt_isn = isn;

	/* Adding to request queue in metasocket */
	mptcp_v4_reqsk_queue_hash_add(req, TCP_TIMEOUT_INIT);

	if (tcp_v4_send_synack(mpcb_meta_sk(mpcb), NULL, req, NULL))
		goto drop_and_free;

	return;

drop_and_free:
	inet_csk_reqsk_queue_removed(mpcb_meta_sk(mpcb), req);
	reqsk_free(req);
	return;
}

int mptcp_v4_rem_raddress(struct multipath_options *mopt, u8 id)
{
	int i;
	struct mptcp_rem4 *rem4;

	for (i = 0; i < MPTCP_MAX_ADDR; i++) {
		if (!((1 << i) & mopt->rem4_bits))
			continue;

		rem4 = &mopt->addr4[i];

		if (rem4->id == id) {
			/* remove address from bitfield */
			mopt->rem4_bits &= ~(1 << i);

			return 0;
		}
	}

	return -1;
}

/**
 * Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 */
int mptcp_v4_add_raddress(struct multipath_options *mopt,
			  const struct in_addr *addr, __be16 port, u8 id)
{
	int i;
	struct mptcp_rem4 *rem4;

	mptcp_for_each_bit_set(mopt->rem4_bits, i) {
		rem4 = &mopt->addr4[i];

		/* Address is already in the list --- continue */
		if (rem4->addr.s_addr == addr->s_addr && rem4->port == port)
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it. */
		if (rem4->id == id && rem4->addr.s_addr != addr->s_addr) {
			/* update the address */
			mptcp_debug("%s: updating old addr:%pI4"
				   " to addr %pI4 with id:%d\n",
				   __func__, &rem4->addr.s_addr,
				   &addr->s_addr, id);
			rem4->addr.s_addr = addr->s_addr;
			rem4->port = port;
			mopt->list_rcvd = 1;
			return 0;
		}
	}

	i = mptcp_find_free_index(mopt->rem4_bits);
	/* Do we have already the maximum number of local/remote addresses? */
	if (i < 0) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not "
			   "adding address: %pI4\n",
			   __func__, MPTCP_MAX_ADDR, &addr->s_addr);
		return -1;
	}

	rem4 = &mopt->addr4[i];

	/* Address is not known yet, store it */
	rem4->addr.s_addr = addr->s_addr;
	rem4->port = port;
	rem4->bitfield = 0;
	rem4->id = id;
	mopt->list_rcvd = 1;
	mopt->rem4_bits |= (1 << i);

	return 0;
}

/* Sets the bitfield of the remote-address field
 * local address is not set as it will disappear with the global address-list */
void mptcp_v4_set_init_addr_bit(struct mptcp_cb *mpcb, __be32 daddr)
{
	int i;

	mptcp_for_each_bit_set(mpcb->rx_opt.rem4_bits, i) {
		if (mpcb->rx_opt.addr4[i].addr.s_addr == daddr) {
			/* It's the initial flow - thus local index == 0 */
			mpcb->rx_opt.addr4[i].bitfield |= 1;
			return;
		}
	}
}

/**
 * Currently we can only process join requests here.
 * (either the SYN or the final ACK)
 */
int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	struct mptcp_cb *mpcb = (struct mptcp_cb *)meta_sk;
	struct request_sock **prev, *req;
	struct sock *child;

	/* Socket is in the process of destruction - we don't accept
	 * new subflows */
	if (sock_flag(meta_sk, SOCK_DEAD) || meta_sk->sk_state == TCP_CLOSE)
		goto reset_and_discard;

	req = inet_csk_search_req(meta_sk, &prev, th->source,
				  iph->saddr, iph->daddr);

	if (!req) {
		if (th->syn) {
			struct mp_join *join_opt = mptcp_find_join(skb);
			/* Currently we make two calls to mptcp_find_join(). This
			 * can probably be optimized. */
			if (mptcp_v4_add_raddress(&mpcb->rx_opt,
					(struct in_addr *)&iph->saddr, 0,
					join_opt->addr_id) < 0)
				goto reset_and_discard;
			if (mpcb->rx_opt.list_rcvd)
				mpcb->rx_opt.list_rcvd = 0;

			mptcp_v4_join_request(mpcb, skb);
		}
		goto discard;
	}

	child = tcp_check_req(meta_sk, skb, req, prev);
	if (!child)
		goto discard;

	if (child != meta_sk) {
		tcp_child_process(meta_sk, child, skb);
	} else {
		goto reset_and_discard;
	}
	return 0;

reset_and_discard:
	tcp_v4_send_reset(NULL, skb);
discard:
	kfree_skb(skb);
	return 0;
}

/**
 * Inspired from inet_csk_search_req
 * After this, the ref count of the meta_sk associated with the request_sock
 * is incremented. Thus it is the responsibility of the caller
 * to call sock_put() when the reference is not needed anymore.
 */
struct request_sock *mptcp_v4_search_req(const __be16 rport, const __be32 raddr,
					 const __be32 laddr)
{
	struct mptcp_request_sock *mtreq;
	int found = 0;

	spin_lock(&mptcp_reqsk_hlock);
	list_for_each_entry(mtreq,
			    &mptcp_reqsk_htb[inet_synq_hash
					(raddr, rport, 0, MPTCP_HASH_SIZE)],
			    collide_tuple) {
		struct request_sock *req = rev_mptcp_rsk(mtreq);
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			WARN_ON(req->sk);
			found = 1;
			break;
		}
	}

	if (found)
		sock_hold(mpcb_meta_sk(mtreq->mpcb));
	spin_unlock(&mptcp_reqsk_hlock);

	if (!found)
		return NULL;

	return rev_mptcp_rsk(mtreq);
}

/**
 * Create a new IPv4 subflow.
 *
 * We are in user-context and meta-sock-lock is hold.
 */
void mptcp_init4_subsockets(struct mptcp_cb *mpcb,
			    const struct mptcp_loc4 *loc,
			    struct mptcp_rem4 *rem)
{
	struct tcp_sock *tp;
	struct sock *sk, *meta_sk = mpcb_meta_sk(mpcb);
	struct sockaddr_in loc_in, rem_in;
	struct socket sock;
	int ulid_size = 0, ret, newpi;

	/* Don't try again - even if it fails */
	rem->bitfield |= (1 << loc->id);

	newpi = mptcp_set_new_pathindex(mpcb);
	if (!newpi)
		return;

	/** First, create and prepare the new socket */

	sock.type = meta_sk->sk_socket->type;
	sock.state = SS_UNCONNECTED;
	sock.wq = meta_sk->sk_socket->wq;
	sock.file = meta_sk->sk_socket->file;
	sock.ops = NULL;

	ret = inet_create(sock_net(meta_sk), &sock, IPPROTO_TCP, 1);

	if (unlikely(ret < 0)) {
		mptcp_debug("%s inet_create failed ret: %d\n", __func__, ret);
		return;
	}

	sk = sock.sk;
	sk->sk_error_report = mptcp_sock_def_error_report;

	tp = tcp_sk(sk);
	if (mptcp_add_sock(mpcb, tp, GFP_KERNEL))
		goto error;

	tp->mptcp->rem_id = rem->id;
	tp->mptcp->path_index = newpi;
	tp->mpc = 1;
	tp->mptcp->slave_sk = 1;
	tp->mptcp->low_prio = loc->low_prio;

	/** Then, connect the socket to the peer */

	ulid_size = sizeof(struct sockaddr_in);
	loc_in.sin_family = AF_INET;
	rem_in.sin_family = AF_INET;
	loc_in.sin_port = 0;
	if (rem->port)
		rem_in.sin_port = rem->port;
	else
		rem_in.sin_port = inet_sk(meta_sk)->inet_dport;
	loc_in.sin_addr = loc->addr;
	rem_in.sin_addr = rem->addr;

	mptcp_debug("%s: token %#x pi %d src_addr:%pI4:%d dst_addr:%pI4:%d\n",
		    __func__, mpcb->mptcp_loc_token, newpi, &loc_in.sin_addr,
		    ntohs(loc_in.sin_port), &rem_in.sin_addr,
		    ntohs(rem_in.sin_port));

	ret = sock.ops->bind(&sock, (struct sockaddr *)&loc_in, ulid_size);
	if (ret < 0) {
		mptcp_debug(KERN_ERR "%s: MPTCP subsocket bind() "
				"failed, error %d\n", __func__, ret);
		goto error;
	}

	ret = sock.ops->connect(&sock, (struct sockaddr *)&rem_in,
				ulid_size, O_NONBLOCK);
	if (ret < 0 && ret != -EINPROGRESS) {
		mptcp_debug(KERN_ERR "%s: MPTCP subsocket connect() "
				"failed, error %d\n", __func__, ret);
		goto error;
	}

	sk_set_socket(sk, meta_sk->sk_socket);
	sk->sk_wq = meta_sk->sk_wq;

	return;

error:
	sock_orphan(sk);

	/* tcp_done must be handled with bh disabled */
	local_bh_disable();
	tcp_done(sk);
	local_bh_enable();

	return;
}

/****** IPv4-Address event handler ******/

/**
 * React on IP-addr add/rem-events
 */
static int mptcp_pm_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	return mptcp_pm_addr_event_handler(event, ptr, AF_INET);
}

/**
 * React on ifup/down-events
 */
static int mptcp_pm_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct in_device *in_dev;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	if (dev->flags & IFF_NOMULTIPATH)
		return NOTIFY_DONE;

	/* Iterate over the addresses of the interface, then we go over the
	 * mpcb's to modify them - that way we take tk_hash_lock for a shorter
	 * time at each iteration. - otherwise we would need to take it from the
	 * beginning till the end.
	 */
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);

	if (in_dev) {
		for_primary_ifa(in_dev) {
			mptcp_pm_inetaddr_event(NULL, event, ifa);
		} endfor_ifa(in_dev);
	}

	rcu_read_unlock();
	return NOTIFY_DONE;
}

void mptcp_pm_addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				  struct mptcp_cb *mpcb)
{
	int i;
	struct sock *sk;

	if (ifa->ifa_scope > RT_SCOPE_LINK ||
	    (ifa->ifa_dev->dev->flags & IFF_NOMULTIPATH))
		return;

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mpcb->loc4_bits, i) {
		if (mpcb->addr4[i].addr.s_addr == ifa->ifa_local)
			goto found;
	}

	/* Not yet in address-list */
	if (event == NETDEV_UP && netif_running(ifa->ifa_dev->dev)) {
		i = __mptcp_find_free_index(mpcb->loc4_bits, 0, mpcb->next_v4_index);
		if (i < 0) {
			mptcp_debug("MPTCP_PM: NETDEV_UP Reached max "
				    "number of local IPv4 addresses: %d\n",
				    MPTCP_MAX_ADDR);
			return;
		}

		/* update this mpcb */
		mpcb->addr4[i].addr.s_addr = ifa->ifa_local;
		mpcb->addr4[i].id = i;
		mpcb->loc4_bits |= (1 << i);
		mpcb->next_v4_index = i + 1;
		/* re-send addresses */
		mptcp_v4_send_add_addr(i, mpcb);
		/* re-evaluate paths */
		mptcp_send_updatenotif(mpcb);
	}
	return;
found:
	/* Address already in list. Reactivate/Deactivate the
	 * concerned paths. */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (sk->sk_family != AF_INET ||
		    inet_sk(sk)->inet_saddr != ifa->ifa_local)
			continue;

		if (event == NETDEV_DOWN) {
			mptcp_retransmit_queue(sk);

			mptcp_sub_force_close(sk);
		} else if (event == NETDEV_CHANGE) {
			int new_low_prio = (ifa->ifa_dev->dev->flags & IFF_MPBACKUP) ?
						1 : 0;
			if (new_low_prio != tp->mptcp->low_prio)
				tp->mptcp->send_mp_prio = 1;
			tp->mptcp->low_prio = new_low_prio;
		} else {
			printk(KERN_DEBUG "MPTCP_PM: NETDEV_UP %pI4, pi %d\n",
					&ifa->ifa_local, tp->mptcp->path_index);
			BUG();
		}
	}

	if (event == NETDEV_DOWN) {
		mpcb->loc4_bits &= ~(1 << i);

		/* Force sending directly the REMOVE_ADDR option */
		mpcb->remove_addrs |= (1 << mpcb->addr4[i].id);
		sk = mptcp_select_ack_sock(mpcb, 0);
		if (sk)
			tcp_send_ack(sk);

		mptcp_for_each_bit_set(mpcb->rx_opt.rem4_bits, i)
			mpcb->rx_opt.addr4[i].bitfield &= mpcb->loc4_bits;
	}
}

/*
 * Send ADD_ADDR for loc_id on all available subflows
 */
void mptcp_v4_send_add_addr(int loc_id, struct mptcp_cb *mpcb)
{
	struct tcp_sock *tp;

	mptcp_for_each_tp(mpcb, tp)
		tp->mptcp->add_addr4 |= (1 << loc_id);
}

static struct notifier_block mptcp_pm_inetaddr_notifier = {
		.notifier_call = mptcp_pm_inetaddr_event,
};

static struct notifier_block mptcp_pm_netdev_notifier = {
		.notifier_call = mptcp_pm_netdev_event,
};

/****** End of IPv4-Address event handler ******/

/*
 * General initialization of IPv4 for MPTCP
 */
void mptcp_pm_v4_init(void)
{
	register_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	register_netdevice_notifier(&mptcp_pm_netdev_notifier);
}

