/*
 *	MPTCP implementation
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *      date : June 09
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/in6.h>
#include <linux/kernel.h>

#include <net/flow.h>
#include <net/inet6_connection_sock.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v6.h>
#include <net/tcp.h>
#include <net/addrconf.h>

#define AF_INET6_FAMILY(fam) ((fam) == AF_INET6)

/*
 * Copied from net/ipv6/inet6_connection_sock.c
 */
static u32 inet6_synq_hash(const struct in6_addr *raddr, const __be16 rport,
			   const u32 rnd, const u16 synq_hsize)
{
	u32 c;

	c = jhash_3words((__force u32)raddr->s6_addr32[0],
			 (__force u32)raddr->s6_addr32[1],
			 (__force u32)raddr->s6_addr32[2],
			 rnd);

	c = jhash_2words((__force u32)raddr->s6_addr32[3],
			 (__force u32)rport,
			 c);

	return c & (synq_hsize - 1);
}

static void mptcp_v6_reqsk_queue_hash_add(struct request_sock *req,
				      unsigned long timeout)
{

	struct inet_connection_sock *meta_icsk =
		(struct inet_connection_sock *)(req->mpcb);
	struct listen_sock *lopt = meta_icsk->icsk_accept_queue.listen_opt;
	const u32 h_local = inet6_synq_hash(&inet6_rsk(req)->rmt_addr,
					   inet_rsk(req)->rmt_port,
					   lopt->hash_rnd,
					   lopt->nr_table_entries);
	const u32 h_global = inet6_synq_hash(&inet6_rsk(req)->rmt_addr,
					    inet_rsk(req)->rmt_port,
					    0,
					    MPTCP_HASH_SIZE);
	spin_lock_bh(&mptcp_reqsk_hlock);
	reqsk_queue_hash_req(&meta_icsk->icsk_accept_queue,
			     h_local, req, timeout);
	list_add(&req->collide_tuple, &mptcp_reqsk_htb[h_global]);
	lopt->qlen++;
	spin_unlock_bh(&mptcp_reqsk_hlock);
}

/* Copied from tcp_ipv6.c */
static __u32 tcp_v6_init_sequence(struct sk_buff *skb)
{
	return secure_tcpv6_sequence_number(ipv6_hdr(skb)->daddr.s6_addr32,
					    ipv6_hdr(skb)->saddr.s6_addr32,
					    tcp_hdr(skb)->dest,
					    tcp_hdr(skb)->source);
}

static int mptcp_v6_join_request(struct multipath_pcb *mpcb,
		struct sk_buff *skb)
{
	struct inet6_request_sock *treq;
	struct request_sock *req;
	struct tcp_options_received tmp_opt;
	u8 mptcp_hash_mac[20];
	struct in6_addr saddr;
	struct in6_addr daddr;
	u8 *hash_location;
	__u32 isn = TCP_SKB_CB(skb)->when;

	ipv6_addr_copy(&saddr, &ipv6_hdr(skb)->saddr);
	ipv6_addr_copy(&daddr, &ipv6_hdr(skb)->daddr);

	req = inet6_reqsk_alloc(&tcp6_request_sock_ops);
	if (!req)
		return -1;

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = mpcb_meta_tp(mpcb)->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &hash_location, &mpcb->rx_opt, 0);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

	req->mpcb = mpcb;
	req->mptcp_rem_nonce = mpcb->rx_opt.mptcp_recv_nonce;
	req->mptcp_rem_key = mpcb->rx_opt.mptcp_rem_key;
	req->mptcp_loc_key = mpcb->mptcp_loc_key;

	get_random_bytes(&req->mptcp_loc_nonce,
			sizeof(req->mptcp_loc_nonce));

	mptcp_hmac_sha1((u8 *)&req->mptcp_loc_key, (u8 *)&req->mptcp_rem_key,
			(u8 *)&req->mptcp_loc_nonce,
			(u8 *)&req->mptcp_rem_nonce,
			(u32 *)mptcp_hash_mac);
	req->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;

	req->rem_id = tmp_opt.rem_id;
	req->saw_mpc = tmp_opt.saw_mpc;
	tcp_openreq_init(req, &tmp_opt, NULL, skb);

	treq = inet6_rsk(req);
	ipv6_addr_copy(&treq->loc_addr, &daddr);
	ipv6_addr_copy(&treq->rmt_addr, &saddr);

	atomic_inc(&skb->users);
	treq->pktopts = skb;

	/*Todo: add the sanity checks here. See tcp_v6_conn_request*/


	treq->iif = inet6_iif(skb);
	isn = tcp_v6_init_sequence(skb);

	tcp_rsk(req)->snt_isn = isn;

	if (mptcp_v6_send_synack((struct sock *)mpcb, req))
		goto drop_and_free;

	/*Adding to request queue in metasocket*/
	mptcp_v6_reqsk_queue_hash_add(req, TCP_TIMEOUT_INIT);
	return 0;

drop_and_free:
	if (req)
		reqsk_free(req);
	return -1;
}

int mptcp_v6_rem_raddress(struct multipath_options *mopt, u8 id)
{
	int i;
	struct mptcp_rem6 *rem6;

	for (i = 0; i < MPTCP_MAX_ADDR; i++) {
		if (!((1 << i) & mopt->rem6_bits))
			continue;

		rem6 = &mopt->addr6[i];

		if (rem6->id == id) {
			/* remove address from bitfield */
			mopt->rem6_bits &= ~(1 << i);

			return 0;
		}
	}

	return -1;
}

/**
 * Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 *
 */
int mptcp_v6_add_raddress(struct multipath_options *mopt,
			  const struct in6_addr *addr, __be16 port, u8 id)
{
	int i;
	struct mptcp_rem6 *rem6;

	mptcp_for_each_bit_set(mopt->rem6_bits, i) {
		rem6 = &mopt->addr6[i];

		/* Address is already in the list --- continue */
		if (ipv6_addr_equal(&rem6->addr, addr))
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it. */
		if (rem6->id == id && !ipv6_addr_equal(&rem6->addr, addr)) {
			/* update the address */
			mptcp_debug("%s: updating old addr: %pI6 \
					to addr %pI6 with id:%d\n",
					__func__, &rem6->addr,
					addr, id);
			ipv6_addr_copy(&rem6->addr, addr);
			rem6->port = port;
			mopt->list_rcvd = 1;
			return 0;
		}
	}

	i = mptcp_find_free_index(mopt->rem6_bits);
	/* Do we have already the maximum number of local/remote addresses? */
	if (i < 0) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not "
				"adding address: %pI6\n",
				__func__, MPTCP_MAX_ADDR, addr);
		return -1;
	}

	rem6 = &mopt->addr6[i];

	/* Address is not known yet, store it */
	ipv6_addr_copy(&rem6->addr, addr);
	rem6->port = port;
	rem6->bitfield = 0;
	rem6->id = id;
	mopt->list_rcvd = 1;
	mopt->rem6_bits |= (1 << i);

	return 0;
}

/* Sets the bitfield of the remote-address field
 * local address is not set as it will disappear with the global address-list */
void mptcp_v6_set_init_addr_bit(struct multipath_pcb *mpcb,
				const struct in6_addr *daddr)
{
	int i;
	mptcp_for_each_bit_set(mpcb->rx_opt.rem6_bits, i) {
		if (ipv6_addr_equal(&mpcb->rx_opt.addr6[i].addr, daddr)) {
			/* It's the initial flow - thus local index == 0 */
			mpcb->rx_opt.addr6[i].bitfield |= 1;
			return;
		}
	}
}

/**
 * Currently we can only process join requests here.
 * (either the SYN or the final ACK)
 */
int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	struct multipath_pcb *mpcb = (struct multipath_pcb *)meta_sk;
	struct request_sock **prev, *req;
	struct sock *child;

	req = inet6_csk_search_req(meta_sk, &prev, th->source,
			&iph->saddr, &iph->daddr, inet6_iif(skb));

	if (!req) {
		if (th->syn) {
			struct mp_join *join_opt = mptcp_find_join(skb);

			if (mptcp_v6_add_raddress(&mpcb->rx_opt,
					(struct in6_addr *)&iph->saddr, 0,
					join_opt->addr_id) < 0)
				goto discard;
			if (mpcb->rx_opt.list_rcvd)
				mpcb->rx_opt.list_rcvd = 0;

			mptcp_v6_join_request(mpcb, skb);
		}
		goto discard;
	}

	child = tcp_check_req(meta_sk, skb, req, prev);
	if (!child)
		goto discard;

	if (child != meta_sk) {
		tcp_child_process(meta_sk, child, skb);
	} else {
		req->rsk_ops->send_reset(NULL, skb);
		goto discard;
	}
	return 0;

discard:
	kfree_skb(skb);
	return 0;
}

/*inspired from inet_csk_search_req
 * After this, the kref count of the mpcb associated with the request_sock
 * is incremented. Thus it is the responsibility of the caller
 * to call mpcb_put() when the reference is not needed anymore.
 */
struct request_sock *mptcp_v6_search_req(const __be16 rport,
					const struct in6_addr *raddr,
					const struct in6_addr *laddr)
{
	struct request_sock *req;
	int found = 0;

	spin_lock(&mptcp_reqsk_hlock);
	list_for_each_entry(req, &mptcp_reqsk_htb[
				inet6_synq_hash(raddr, rport, 0,
				MPTCP_HASH_SIZE)],
				collide_tuple) {
		const struct inet6_request_sock *treq = inet6_rsk(req);

		if (inet_rsk(req)->rmt_port == rport &&
			AF_INET6_FAMILY(req->rsk_ops->family) &&
			ipv6_addr_equal(&treq->rmt_addr, raddr) &&
			ipv6_addr_equal(&treq->loc_addr, laddr)) {
			WARN_ON(req->sk);
			found = 1;
			break;
		}
	}

	if (found)
		sock_hold(mpcb_meta_sk(req->mpcb));
	spin_unlock(&mptcp_reqsk_hlock);

	if (!found)
		return NULL;

	return req;
}

int mptcp_v6_send_synack(struct sock *meta_sk,
				 struct request_sock *req)
{
	struct inet6_request_sock *treq = inet6_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(meta_sk);
	struct sk_buff *skb;
	struct ipv6_txoptions *opt = NULL;
	struct in6_addr *final_p, final;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int err = -1;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_TCP;
	ipv6_addr_copy(&fl6.daddr, &treq->rmt_addr);
	ipv6_addr_copy(&fl6.saddr, &treq->loc_addr);
	fl6.flowlabel = 0;
	fl6.flowi6_oif = treq->iif;
	fl6.flowi6_mark = meta_sk->sk_mark;
	fl6.fl6_dport = inet_rsk(req)->rmt_port;
	fl6.fl6_sport = inet_rsk(req)->loc_port;
	security_req_classify_flow(req, flowi6_to_flowi(&fl6));

	opt = np->opt;
	final_p = fl6_update_dst(&fl6, opt, &final);

	dst = ip6_dst_lookup_flow(meta_sk, &fl6, final_p, false);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto done;
	}
	skb = tcp_make_synack(meta_sk, dst, req, NULL);
	err = -ENOMEM;
	if (skb) {
		__tcp_v6_send_check(skb, &treq->loc_addr, &treq->rmt_addr);

		ipv6_addr_copy(&fl6.daddr, &treq->rmt_addr);
		err = ip6_xmit(meta_sk, skb, &fl6, opt);
		err = net_xmit_eval(err);
	}

done:
	if (opt && opt != np->opt)
		sock_kfree_s(meta_sk, opt, opt->tot_len);
	dst_release(dst);
	return err;
}

/**
 * Create a new IPv6 subflow.
 *
 * We are in user-context and meta-sock-lock is hold.
 */
void mptcp_init6_subsockets(struct multipath_pcb *mpcb,
			    const struct mptcp_loc6 *loc,
			    struct mptcp_rem6 *rem)
{
	struct tcp_sock *tp;
	struct sock *sk, *meta_sk = mpcb_meta_sk(mpcb);
	struct sockaddr_in6 loc_in, rem_in;
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
	ret = inet6_create(&init_net, &sock, IPPROTO_TCP, 1);

	if (unlikely(ret < 0)) {
		mptcp_debug("%s inet6_create failed ret: %d\n", __func__, ret);
		return;
	}

	sk = sock.sk;

	inet_sk(sk)->loc_id = loc->id;
	inet_sk(sk)->rem_id = rem->id;

	tp = tcp_sk(sk);
	tp->path_index = newpi;
	tp->mpc = 1;
	tp->slave_sk = 1;

	sk->sk_error_report = mptcp_sock_def_error_report;

	mptcp_add_sock(mpcb, tp);

	/** Then, connect the socket to the peer */

	ulid_size = sizeof(struct sockaddr_in6);
	loc_in.sin6_family= AF_INET6;
	rem_in.sin6_family = AF_INET6;
	loc_in.sin6_port = 0;
	if (rem->port)
		rem_in.sin6_port = rem->port;
	else
		rem_in.sin6_port = inet_sk(meta_sk)->inet_dport;
	loc_in.sin6_addr = loc->addr;
	rem_in.sin6_addr = rem->addr;

	mptcp_debug("%s: token %#x pi %d src_addr:%pI6:%d dst_addr:%pI6:%d\n",
		    __func__, mpcb->mptcp_loc_token, newpi, &loc_in.sin6_addr,
		    ntohs(loc_in.sin6_port), &rem_in.sin6_addr,
		    ntohs(rem_in.sin6_port));

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

/****** IPv6-Address event handler ******/

struct dad_waiter_data {
	struct multipath_pcb *mpcb;
	struct inet6_ifaddr *ifa;
};

/**
 * React on IPv6-addr add/rem-events
 */
static int mptcp_pm_inet6_addr_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	return mptcp_pm_addr_event_handler(event, ptr, AF_INET6);
}

static int mptcp_ipv6_is_in_dad_state(struct inet6_ifaddr *ifa)
{
	if ((ifa->flags&IFA_F_TENTATIVE) &&
			ifa->state == INET6_IFADDR_STATE_DAD)
		return 1;
	else
		return 0;
}

static void dad_wait_timer(unsigned long data);

static void mptcp_ipv6_setup_dad_timer(struct multipath_pcb *mpcb,
	struct inet6_ifaddr *ifa)
{
	struct dad_waiter_data *data;

	if (timer_pending(&mpcb->dad_waiter))
		return;

	data = kmalloc(sizeof(struct dad_waiter_data), GFP_ATOMIC);

	if (!data)
		return;

	data->mpcb = mpcb;
	data->ifa = ifa;

	mpcb->dad_waiter.data = (unsigned long)data;
	mpcb->dad_waiter.function = dad_wait_timer;
	if (ifa->idev->cnf.rtr_solicit_delay)
		mpcb->dad_waiter.expires = jiffies +
			ifa->idev->cnf.rtr_solicit_delay;
	else
		mpcb->dad_waiter.expires = jiffies +
			MPTCP_IPV6_DEFAULT_DAD_WAIT;

	/* In order not to lose mpcb before the timer expires. */
	sock_hold(mpcb_meta_sk(mpcb));

	add_timer(&mpcb->dad_waiter);
}

static void dad_wait_timer(unsigned long arg_data)
{

	struct dad_waiter_data *data = (struct dad_waiter_data *)arg_data;

	if (!mptcp_ipv6_is_in_dad_state(data->ifa))
		mptcp_pm_inet6_addr_event(NULL, NETDEV_UP, (void *)data->ifa);
	else
		mptcp_ipv6_setup_dad_timer(data->mpcb, data->ifa);

	sock_put(mpcb_meta_sk(data->mpcb));
	kfree(data);
}

/**
 * React on ifup/down-events
 */
static int mptcp_pm_v6_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct inet6_dev *in6_dev = NULL;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN))
		return NOTIFY_DONE;

	/* Iterate over the addresses of the interface, then we go over the
	 * mpcb's to modify them - that way we take tk_hash_lock for a shorter
	 * time at each iteration. - otherwise we would need to take it from the
	 * beginning till the end.
	 */
	rcu_read_lock();
	in6_dev = __in6_dev_get(dev);

	if (in6_dev) {
		struct inet6_ifaddr *ifa6;
		list_for_each_entry(ifa6, &in6_dev->addr_list, if_list)
			mptcp_pm_inet6_addr_event(NULL, event, ifa6);
	}

	rcu_read_unlock();
	return NOTIFY_DONE;
}

void mptcp_pm_addr6_event_handler(struct inet6_ifaddr *ifa, unsigned long event,
		struct multipath_pcb *mpcb)
{
	int i;
	struct sock *sk;
	struct tcp_sock *tp;
	int addr_type = ipv6_addr_type(&ifa->addr);

	/* Checks on interface and address-type */
	if (ifa->scope > RT_SCOPE_LINK ||
	    (ifa->idev->dev->flags & IFF_NOMULTIPATH) ||
	    addr_type == IPV6_ADDR_ANY ||
	    (addr_type & IPV6_ADDR_LOOPBACK) ||
	    (addr_type & IPV6_ADDR_LINKLOCAL))
		return;

	if (mptcp_ipv6_is_in_dad_state(ifa)) {
		mptcp_ipv6_setup_dad_timer(mpcb, ifa);
		return;
	}

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mpcb->loc6_bits, i) {
		if (ipv6_addr_equal(&mpcb->addr6[i].addr, &ifa->addr))
			goto found;
	}

	/* Not yet in address-list */
	if (event == NETDEV_UP && netif_running(ifa->idev->dev)) {
		i = mptcp_find_free_index(mpcb->loc6_bits);
		if (i < 0) {
			printk(KERN_DEBUG "MPTCP_PM: NETDEV_UP Reached max "
					"number of local IPv6 addresses: %d\n",
					MPTCP_MAX_ADDR);
			return;
		}

		printk(KERN_DEBUG "MPTCP_PM: NETDEV_UP adding "
			"address %pI6 to existing connection with mpcb: %d\n",
			&ifa->addr, mpcb->mptcp_loc_token);

		/* update this mpcb */
		ipv6_addr_copy(&mpcb->addr6[i].addr, &ifa->addr);
		mpcb->addr6[i].id = i + MPTCP_MAX_ADDR;
		mpcb->loc6_bits |= (1 << i);
		/* re-send addresses */
		mpcb->add_addr6 |= (1 << i);
		/* re-evaluate paths */
		mptcp_send_updatenotif(mpcb);
	}
	return;
found:
	/* remove this address id from loc_id */
	mpcb->loc6_bits &= ~(1 << i);
	/* send a remove_addr */
	mpcb->remove_addrs |= (1 << i);

	/* Address already in list. Reactivate/Deactivate the
	 * concerned paths. */
	mptcp_for_each_sk(mpcb, sk, tp) {
		if (sk->sk_family != AF_INET6 ||
		    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &ifa->addr))
			continue;

		if (event == NETDEV_DOWN) {
			printk(KERN_DEBUG "MPTCP_PM: NETDEV_DOWN %pI6, "
					"path %d, id %u\n", &ifa->addr,
					tp->path_index, inet_sk(sk)->loc_id);
			mptcp_retransmit_queue(sk);

			mptcp_sub_force_close(sk);

		} else {
			printk(KERN_DEBUG "MPTCP_PM: NETDEV_UP %pI6, path %d\n",
					&ifa->addr,
					tp->path_index);
			BUG();
		}
	}

	if (mpcb->remove_addrs) {
		/* force sending an ACK */
		struct sock *ssk = mptcp_select_loc_sock(mpcb, mpcb->remove_addrs);
		if (ssk != NULL)
			tcp_send_ack(ssk);
	}

}

static struct notifier_block mptcp_pm_inet6_addr_notifier = {
		.notifier_call = mptcp_pm_inet6_addr_event,
};

static struct notifier_block mptcp_pm_v6_netdev_notifier = {
		.notifier_call = mptcp_pm_v6_netdev_event,
};

/****** End of IPv6-Address event handler ******/

/*
 * General initialization of IPv6 for MPTCP
 */
void mptcp_pm_v6_init(void)
{
	register_inet6addr_notifier(&mptcp_pm_inet6_addr_notifier);
	register_netdevice_notifier(&mptcp_pm_v6_netdev_notifier);
}
