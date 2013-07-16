/*
 *	MPTCP implementation - IPv6-specific functions
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
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

#include <linux/export.h>
#include <linux/in6.h>
#include <linux/kernel.h>

#include <net/addrconf.h>
#include <net/flow.h>
#include <net/inet6_connection_sock.h>
#include <net/inet6_hashtables.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v6.h>
#include <net/tcp.h>
#include <net/transp_v6.h>

static int mptcp_v6v4_send_synack(struct sock *meta_sk, struct request_sock *req,
				  u16 queue_mapping);

__u32 mptcp_v6_get_nonce(const __be32 *saddr, const __be32 *daddr,
			 __be16 sport, __be16 dport, u32 seq)
{
	u32 secret[MD5_MESSAGE_BYTES / 4];
	u32 hash[MD5_DIGEST_WORDS];
	u32 i;

	memcpy(hash, saddr, 16);
	for (i = 0; i < 4; i++)
		secret[i] = mptcp_secret[i] + (__force u32)daddr[i];
	secret[4] = mptcp_secret[4] +
		    (((__force u16)sport << 16) + (__force u16)dport);
	secret[5] = seq;
	for (i = 6; i < MD5_MESSAGE_BYTES / 4; i++)
		secret[i] = mptcp_secret[i];

	md5_transform(hash, secret);

	return hash[0];
}

u64 mptcp_v6_get_key(const __be32 *saddr, const __be32 *daddr,
		     __be16 sport, __be16 dport)
{
	u32 secret[MD5_MESSAGE_BYTES / 4];
	u32 hash[MD5_DIGEST_WORDS];
	u32 i;

	memcpy(hash, saddr, 16);
	for (i = 0; i < 4; i++)
		secret[i] = mptcp_secret[i] + (__force u32)daddr[i];
	secret[4] = mptcp_secret[4] +
		    (((__force u16)sport << 16) + (__force u16)dport);
	secret[5] = mptcp_key_seed++;
	for (i = 5; i < MD5_MESSAGE_BYTES / 4; i++)
		secret[i] = mptcp_secret[i];

	md5_transform(hash, secret);

	return *((u64 *)hash);
}

static void mptcp_v6_reqsk_destructor(struct request_sock *req)
{
	mptcp_reqsk_destructor(req);

	tcp_v6_reqsk_destructor(req);
}

/* Similar to tcp_v6_rtx_synack */
static int mptcp_v6_rtx_synack(struct sock *meta_sk, struct request_sock *req)
{
	if (meta_sk->sk_family == AF_INET6)
		return tcp_v6_rtx_synack(meta_sk, req);

	TCP_INC_STATS_BH(sock_net(meta_sk), TCP_MIB_RETRANSSEGS);
	return mptcp_v6v4_send_synack(meta_sk, req, 0);
}

/* Similar to tcp6_request_sock_ops */
struct request_sock_ops mptcp6_request_sock_ops __read_mostly = {
	.family		=	AF_INET6,
	.obj_size	=	sizeof(struct mptcp6_request_sock),
	.rtx_syn_ack	=	mptcp_v6_rtx_synack,
	.send_ack	=	tcp_v6_reqsk_send_ack,
	.destructor	=	mptcp_v6_reqsk_destructor,
	.send_reset	=	tcp_v6_send_reset,
	.syn_ack_timeout =	tcp_syn_ack_timeout,
};

static void mptcp_v6_reqsk_queue_hash_add(struct sock *meta_sk,
					  struct request_sock *req,
					  unsigned long timeout)
{
	const u32 h = inet6_synq_hash(&inet6_rsk(req)->rmt_addr,
				      inet_rsk(req)->rmt_port,
				      0, MPTCP_HASH_SIZE);

	inet6_csk_reqsk_queue_hash_add(meta_sk, req, timeout);

	spin_lock(&mptcp_reqsk_hlock);
	list_add(&mptcp_rsk(req)->collide_tuple, &mptcp_reqsk_htb[h]);
	spin_unlock(&mptcp_reqsk_hlock);
}

/* Similar to tcp_v6_send_synack
 *
 * The meta-socket is IPv4, but a new subsocket is IPv6
 */
static int mptcp_v6v4_send_synack(struct sock *meta_sk, struct request_sock *req,
				  u16 queue_mapping)
{
	struct inet6_request_sock *treq = inet6_rsk(req);
	struct sk_buff *skb;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int err;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_TCP;
	fl6.daddr = treq->rmt_addr;
	fl6.saddr = treq->loc_addr;
	fl6.flowlabel = 0;
	fl6.flowi6_oif = treq->iif;
	fl6.flowi6_mark = meta_sk->sk_mark;
	fl6.fl6_dport = inet_rsk(req)->rmt_port;
	fl6.fl6_sport = inet_rsk(req)->loc_port;
	security_req_classify_flow(req, flowi6_to_flowi(&fl6));

	dst = ip6_dst_lookup_flow(meta_sk, &fl6, NULL, false);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto done;
	}
	skb = tcp_make_synack(meta_sk, dst, req, NULL);
	err = -ENOMEM;
	if (skb) {
		__tcp_v6_send_check(skb, &treq->loc_addr, &treq->rmt_addr);

		fl6.daddr = treq->rmt_addr;
		skb_set_queue_mapping(skb, queue_mapping);
		err = ip6_xmit(meta_sk, skb, &fl6, NULL, 0);
		err = net_xmit_eval(err);
	}

done:
	dst_release(dst);
	return err;
}

/* Similar to tcp_v6_syn_recv_sock
 *
 * The meta-socket is IPv4, but a new subsocket is IPv6
 */
struct sock *mptcp_v6v4_syn_recv_sock(struct sock *meta_sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst)
{
	struct inet6_request_sock *treq;
	struct ipv6_pinfo *newnp;
	struct tcp6_sock *newtcp6sk;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;

	treq = inet6_rsk(req);

	if (sk_acceptq_is_full(meta_sk))
		goto out_overflow;

	if (!dst) {
		/* This code is similar to inet6_csk_route_req, but as we
		 * don't have a np-pointer in the meta, we have to do it
		 * manually.
		 */
		struct flowi6 fl6;

		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_TCP;
		fl6.daddr = treq->rmt_addr;
		fl6.saddr = treq->loc_addr;
		fl6.flowi6_oif = meta_sk->sk_bound_dev_if;
		fl6.flowi6_mark = meta_sk->sk_mark;
		fl6.fl6_dport = inet_rsk(req)->rmt_port;
		fl6.fl6_sport = inet_rsk(req)->loc_port;
		security_req_classify_flow(req, flowi6_to_flowi(&fl6));

		dst = ip6_dst_lookup_flow(meta_sk, &fl6, NULL, false);
		if (IS_ERR(dst))
			goto out;
	}

	newsk = tcp_create_openreq_child(meta_sk, req, skb);
	if (newsk == NULL)
		goto out_nonewsk;

	/*
	 * No need to charge this sock to the relevant IPv6 refcnt debug socks
	 * count here, tcp_create_openreq_child now does this for us, see the
	 * comment in that function for the gory details. -acme
	 */

	newsk->sk_gso_type = SKB_GSO_TCPV6;
	/* We cannot call __ip6_dst_store, because we don't have the np-pointer */
	sk_setup_caps(newsk, dst);

	newtcp6sk = (struct tcp6_sock *)newsk;
	inet_sk(newsk)->pinet6 = &newtcp6sk->inet6;

	newtp = tcp_sk(newsk);
	newinet = inet_sk(newsk);
	newnp = inet6_sk(newsk);

	newnp->daddr = treq->rmt_addr;
	newnp->saddr = treq->loc_addr;
	newnp->rcv_saddr = treq->loc_addr;
	newsk->sk_bound_dev_if = treq->iif;

	/* Now IPv6 options...

	   First: no IPv4 options.
	 */
	newinet->inet_opt = NULL;
	newnp->ipv6_ac_list = NULL;
	newnp->ipv6_fl_list = NULL;
	newnp->rxopt.all = 0;

	/* Clone pktoptions received with SYN */
	newnp->pktoptions = NULL;
	if (treq->pktopts != NULL) {
		newnp->pktoptions = skb_clone(treq->pktopts, GFP_ATOMIC);
		kfree_skb(treq->pktopts);
		treq->pktopts = NULL;
		if (newnp->pktoptions)
			skb_set_owner_r(newnp->pktoptions, newsk);
	}
	newnp->opt	  = NULL;
	newnp->mcast_oif  = inet6_iif(skb);
	newnp->mcast_hops = ipv6_hdr(skb)->hop_limit;

	/* Initialization copied from inet6_create - normally this should have
	 * been handled by the memcpy as in tcp_v6_syn_recv_sock
	 */
	newnp->hop_limit  = -1;
	newnp->mc_loop	  = 1;
	newnp->pmtudisc	  = IPV6_PMTUDISC_WANT;
	(void)xchg(&newnp->rxpmtu, NULL);

	inet_csk(newsk)->icsk_ext_hdr_len = 0;

	tcp_mtup_init(newsk);
	tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = dst_metric_advmss(dst);
	tcp_initialize_rcv_mss(newsk);
	if (tcp_rsk(req)->snt_synack)
		tcp_valid_rtt_meas(newsk,
				   tcp_time_stamp - tcp_rsk(req)->snt_synack);
	newtp->total_retrans = req->num_retrans;

	newinet->inet_daddr = LOOPBACK4_IPV6;
	newinet->inet_saddr = LOOPBACK4_IPV6;
	newinet->inet_rcv_saddr = LOOPBACK4_IPV6;

	if (__inet_inherit_port(meta_sk, newsk) < 0) {
		inet_csk_prepare_forced_close(newsk);
		tcp_done(newsk);
		goto out;
	}
	__inet6_hash(newsk, NULL);

	return newsk;

out_overflow:
	NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_LISTENOVERFLOWS);
out_nonewsk:
	dst_release(dst);
out:
	NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_LISTENDROPS);
	return NULL;
}

/* Similar to tcp_v6_conn_request */
static void mptcp_v6_join_request(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct tcp_options_received tmp_opt;
	struct mptcp_options_received mopt;
	struct ipv6_pinfo *np = inet6_sk(meta_sk);
	struct request_sock *req;
	struct inet6_request_sock *treq;
	struct mptcp_request_sock *mtreq;
	u8 mptcp_hash_mac[20];
	__u32 isn = TCP_SKB_CB(skb)->when;
	struct dst_entry *dst = NULL;
	struct flowi6 fl6;
	int want_cookie = 0;

	tcp_clear_options(&tmp_opt);
	mptcp_init_mp_opt(&mopt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = tcp_sk(meta_sk)->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &mopt, 0, NULL);

	req = inet6_reqsk_alloc(&mptcp6_request_sock_ops);
	if (!req)
		return;

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	treq = inet6_rsk(req);
	treq->rmt_addr = ipv6_hdr(skb)->saddr;
	treq->loc_addr = ipv6_hdr(skb)->daddr;

	if (!want_cookie || tmp_opt.tstamp_ok)
		TCP_ECN_create_request(req, skb, sock_net(meta_sk));

	treq->iif = meta_sk->sk_bound_dev_if;

	/* So that link locals have meaning */
	if (!meta_sk->sk_bound_dev_if &&
	    ipv6_addr_type(&treq->rmt_addr) & IPV6_ADDR_LINKLOCAL)
		treq->iif = inet6_iif(skb);

	if (!isn) {
		if (meta_sk->sk_family == AF_INET6 &&
		    (ipv6_opt_accepted(meta_sk, skb) ||
		    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
		    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim)) {
			atomic_inc(&skb->users);
			treq->pktopts = skb;
		}

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet6_csk_route_req(meta_sk, &fl6, req)) != NULL) {
			if (!tcp_peer_is_proven(req, dst, true)) {
				NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(meta_sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 !tcp_peer_is_proven(req, dst, false)) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: drop open request from %pI6/%u\n",
				       &treq->rmt_addr, ntohs(tcp_hdr(skb)->source));
			goto drop_and_release;
		}

		isn = tcp_v6_init_sequence(skb);
	}

	tcp_rsk(req)->snt_isn = isn;
	tcp_rsk(req)->snt_synack = tcp_time_stamp;

	mtreq = mptcp_rsk(req);
	mtreq->mpcb = mpcb;
	INIT_LIST_HEAD(&mtreq->collide_tuple);
	mtreq->mptcp_rem_nonce = mopt.mptcp_recv_nonce;
	mtreq->mptcp_rem_key = mpcb->mptcp_rem_key;
	mtreq->mptcp_loc_key = mpcb->mptcp_loc_key;
	mtreq->mptcp_loc_nonce = mptcp_v6_get_nonce(ipv6_hdr(skb)->daddr.s6_addr32,
						    ipv6_hdr(skb)->saddr.s6_addr32,
						    tcp_hdr(skb)->dest,
						    tcp_hdr(skb)->source, isn);
	mptcp_hmac_sha1((u8 *)&mtreq->mptcp_loc_key,
			(u8 *)&mtreq->mptcp_rem_key,
			(u8 *)&mtreq->mptcp_loc_nonce,
			(u8 *)&mtreq->mptcp_rem_nonce, (u32 *)mptcp_hash_mac);
	mtreq->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;
	mtreq->rem_id = mopt.rem_id;
	mtreq->low_prio = mopt.low_prio;
	tcp_rsk(req)->saw_mpc = 1;

	if (meta_sk->sk_family == AF_INET6) {
		if (tcp_v6_send_synack(meta_sk, dst, &fl6, req,
				       skb_get_queue_mapping(skb)))
			goto drop_and_free;
	} else {
		if (mptcp_v6v4_send_synack(meta_sk, req, skb_get_queue_mapping(skb)))
			goto drop_and_free;
	}

	/* Adding to request queue in metasocket */
	mptcp_v6_reqsk_queue_hash_add(meta_sk, req, TCP_TIMEOUT_INIT);

	return;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
	return;
}

int mptcp_v6_rem_raddress(struct mptcp_cb *mpcb, u8 id)
{
	int i;

	for (i = 0; i < MPTCP_MAX_ADDR; i++) {
		if (!((1 << i) & mpcb->rem6_bits))
			continue;

		if (mpcb->remaddr6[i].id == id) {
			/* remove address from bitfield */
			mpcb->rem6_bits &= ~(1 << i);

			return 0;
		}
	}

	return -1;
}

/* Returns -1 if there is no space anymore to store an additional
 * address
 */
int mptcp_v6_add_raddress(struct mptcp_cb *mpcb, const struct in6_addr *addr,
			  __be16 port, u8 id)
{
	int i;
	struct mptcp_rem6 *rem6;

	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		rem6 = &mpcb->remaddr6[i];

		/* Address is already in the list --- continue */
		if (rem6->id == id &&
		    ipv6_addr_equal(&rem6->addr, addr) && rem6->port == port)
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it.
		 */
		if (rem6->id == id) {
			/* update the address */
			mptcp_debug("%s: updating old addr: %pI6 to addr %pI6 with id:%d\n",
				    __func__, &rem6->addr, addr, id);
			rem6->addr = *addr;
			rem6->port = port;
			mpcb->list_rcvd = 1;
			return 0;
		}
	}

	i = mptcp_find_free_index(mpcb->rem6_bits);
	/* Do we have already the maximum number of local/remote addresses? */
	if (i < 0) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not adding address: %pI6\n",
			    __func__, MPTCP_MAX_ADDR, addr);
		return -1;
	}

	rem6 = &mpcb->remaddr6[i];

	/* Address is not known yet, store it */
	rem6->addr = *addr;
	rem6->port = port;
	rem6->bitfield = 0;
	rem6->retry_bitfield = 0;
	rem6->id = id;
	mpcb->list_rcvd = 1;
	mpcb->rem6_bits |= (1 << i);

	return 0;
}

/* Sets the bitfield of the remote-address field
 * local address is not set as it will disappear with the global address-list
 */
void mptcp_v6_set_init_addr_bit(struct mptcp_cb *mpcb,
				const struct in6_addr *daddr)
{
	int i;
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		if (ipv6_addr_equal(&mpcb->remaddr6[i].addr, daddr)) {
			/* It's the initial flow - thus local index == 0 */
			mpcb->remaddr6[i].bitfield |= 1;
			return;
		}
	}
}

int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *child, *rsk = NULL;
	int ret;

	if (!(TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_JOIN)) {
		struct tcphdr *th = tcp_hdr(skb);
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);
		struct sock *sk;

		sk = __inet6_lookup_established(sock_net(meta_sk),
						&tcp_hashinfo,
						&ip6h->saddr, th->source,
						&ip6h->daddr, ntohs(th->dest),
						inet6_iif(skb));

		if (!sk) {
			kfree_skb(skb);
			return 0;
		}
		if (is_meta_sk(sk)) {
			WARN("%s Did not find a sub-sk!\n", __func__);
			kfree_skb(skb);
			sock_put(sk);
			return 0;
		}

		if (sk->sk_state == TCP_TIME_WAIT) {
			inet_twsk_put(inet_twsk(sk));
			kfree_skb(skb);
			return 0;
		}

		ret = tcp_v6_do_rcv(sk, skb);
		sock_put(sk);

		return ret;
	}
	TCP_SKB_CB(skb)->mptcp_flags = 0;

	/* Has been removed from the tk-table. Thus, no new subflows.
	 * Check for close-state is necessary, because we may have been closed
	 * without passing by mptcp_close().
	 */
	if (meta_sk->sk_state == TCP_CLOSE || !tcp_sk(meta_sk)->inside_tk_table)
		goto reset_and_discard;

	child = tcp_v6_hnd_req(meta_sk, skb);

	if (!child)
		goto discard;

	if (child != meta_sk) {
		sock_rps_save_rxhash(child, skb);
		/* We don't call tcp_child_process here, because we hold
		 * already the meta-sk-lock and are sure that it is not owned
		 * by the user.
		 */
		ret = tcp_rcv_state_process(child, skb, tcp_hdr(skb), skb->len);
		bh_unlock_sock(child);
		sock_put(child);
		if (ret) {
			rsk = child;
			goto reset_and_discard;
		}
	} else {
		if (tcp_hdr(skb)->syn) {
			struct mp_join *join_opt = mptcp_find_join(skb);
			/* Currently we make two calls to mptcp_find_join(). This
			 * can probably be optimized. */
			if (mptcp_v6_add_raddress(mpcb,
						  (struct in6_addr *)&ipv6_hdr(skb)->saddr,
						  0,
						  join_opt->addr_id) < 0)
				goto reset_and_discard;
			mpcb->list_rcvd = 0;

			mptcp_v6_join_request(meta_sk, skb);
			goto discard;
		}
		goto reset_and_discard;
	}
	return 0;

reset_and_discard:
	tcp_v6_send_reset(rsk, skb);
discard:
	kfree_skb(skb);
	return 0;
}

/* After this, the ref count of the meta_sk associated with the request_sock
 * is incremented. Thus it is the responsibility of the caller
 * to call sock_put() when the reference is not needed anymore.
 */
struct sock *mptcp_v6_search_req(const __be16 rport, const struct in6_addr *raddr,
				 const struct in6_addr *laddr, const struct net *net)
{
	struct mptcp_request_sock *mtreq;
	struct sock *meta_sk = NULL;

	spin_lock(&mptcp_reqsk_hlock);
	list_for_each_entry(mtreq,
			    &mptcp_reqsk_htb[inet6_synq_hash(raddr, rport, 0,
							     MPTCP_HASH_SIZE)],
			    collide_tuple) {
		struct inet6_request_sock *treq = inet6_rsk(rev_mptcp_rsk(mtreq));
		meta_sk = mtreq->mpcb->meta_sk;

		if (inet_rsk(rev_mptcp_rsk(mtreq))->rmt_port == rport &&
		    rev_mptcp_rsk(mtreq)->rsk_ops->family == AF_INET6 &&
		    ipv6_addr_equal(&treq->rmt_addr, raddr) &&
		    ipv6_addr_equal(&treq->loc_addr, laddr) &&
		    net_eq(net, sock_net(meta_sk)))
			break;
		meta_sk = NULL;
	}

	if (meta_sk && unlikely(!atomic_inc_not_zero(&meta_sk->sk_refcnt)))
		meta_sk = NULL;
	spin_unlock(&mptcp_reqsk_hlock);

	return meta_sk;
}

/* Create a new IPv6 subflow.
 *
 * We are in user-context and meta-sock-lock is hold.
 */
int mptcp_init6_subsockets(struct sock *meta_sk, const struct mptcp_loc6 *loc,
			   struct mptcp_rem6 *rem)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sockaddr_in6 loc_in, rem_in;
	struct socket sock;
	int ulid_size = 0, ret;

	/* Don't try again - even if it fails.
	 * There is a special case as the IPv6 address of the initial subflow
	 * has an id = 0. The other ones have id's in the range [8, 16[.
	 */
	rem->bitfield |= (1 << (loc->id - min_t(u8, loc->id, MPTCP_MAX_ADDR)));

	/** First, create and prepare the new socket */

	sock.type = meta_sk->sk_socket->type;
	sock.state = SS_UNCONNECTED;
	sock.wq = meta_sk->sk_socket->wq;
	sock.file = meta_sk->sk_socket->file;
	sock.ops = NULL;

	ret = inet6_create(sock_net(meta_sk), &sock, IPPROTO_TCP, 1);
	if (unlikely(ret < 0)) {
		mptcp_debug("%s inet6_create failed ret: %d\n", __func__, ret);
		return ret;
	}

	sk = sock.sk;
	tp = tcp_sk(sk);

	/* All subsockets need the MPTCP-lock-class */
	lockdep_set_class_and_name(&(sk)->sk_lock.slock, &meta_slock_key, "slock-AF_INET-MPTCP");
	lockdep_init_map(&(sk)->sk_lock.dep_map, "sk_lock-AF_INET-MPTCP", &meta_key, 0);

	if (mptcp_add_sock(meta_sk, sk, rem->id, GFP_KERNEL))
		goto error;

	tp->mptcp->slave_sk = 1;
	tp->mptcp->low_prio = loc->low_prio;

	/* Initializing the timer for an MPTCP subflow */
	setup_timer(&tp->mptcp->mptcp_ack_timer, mptcp_ack_handler, (unsigned long)sk);

	/** Then, connect the socket to the peer */

	ulid_size = sizeof(struct sockaddr_in6);
	loc_in.sin6_family = AF_INET6;
	rem_in.sin6_family = AF_INET6;
	loc_in.sin6_port = 0;
	if (rem->port)
		rem_in.sin6_port = rem->port;
	else
		rem_in.sin6_port = inet_sk(meta_sk)->inet_dport;
	loc_in.sin6_addr = loc->addr;
	rem_in.sin6_addr = rem->addr;

	ret = sock.ops->bind(&sock, (struct sockaddr *)&loc_in, ulid_size);
	if (ret < 0) {
		mptcp_debug("%s: MPTCP subsocket bind()failed, error %d\n",
			    __func__, ret);
		goto error;
	}

	mptcp_debug("%s: token %#x pi %d src_addr:%pI6:%d dst_addr:%pI6:%d\n",
		    __func__, tcp_sk(meta_sk)->mpcb->mptcp_loc_token,
		    tp->mptcp->path_index, &loc_in.sin6_addr,
		    ntohs(loc_in.sin6_port), &rem_in.sin6_addr,
		    ntohs(rem_in.sin6_port));

	ret = sock.ops->connect(&sock, (struct sockaddr *)&rem_in,
				ulid_size, O_NONBLOCK);
	if (ret < 0 && ret != -EINPROGRESS) {
		mptcp_debug("%s: MPTCP subsocket connect() failed, error %d\n",
			    __func__, ret);
		goto error;
	}

	sk_set_socket(sk, meta_sk->sk_socket);
	sk->sk_wq = meta_sk->sk_wq;

	return 0;

error:
	/* May happen if mptcp_add_sock fails first */
	if (!tp->mpc) {
		tcp_close(sk, 0);
	} else {
		local_bh_disable();
		mptcp_sub_force_close(sk);
		local_bh_enable();
	}
	return ret;
}

struct mptcp_dad_data {
	struct timer_list timer;
	struct inet6_ifaddr *ifa;
};

static int mptcp_ipv6_is_in_dad_state(struct inet6_ifaddr *ifa)
{
	return ((ifa->flags & IFA_F_TENTATIVE) &&
		ifa->state == INET6_IFADDR_STATE_DAD);
}

static void mptcp_dad_callback(unsigned long arg);
static int mptcp_pm_inet6_addr_event(struct notifier_block *this,
				     unsigned long event, void *ptr);

static inline void mptcp_dad_init_timer(struct mptcp_dad_data *data,
					struct inet6_ifaddr *ifa)
{
	data->ifa = ifa;
	data->timer.data = (unsigned long)data;
	data->timer.function = mptcp_dad_callback;
	if (ifa->idev->cnf.rtr_solicit_delay)
		data->timer.expires = jiffies + ifa->idev->cnf.rtr_solicit_delay;
	else
		data->timer.expires = jiffies + MPTCP_IPV6_DEFAULT_DAD_WAIT;
}

static void mptcp_dad_callback(unsigned long arg)
{
	struct mptcp_dad_data *data = (struct mptcp_dad_data *)arg;

	if (mptcp_ipv6_is_in_dad_state(data->ifa)) {
		mptcp_dad_init_timer(data, data->ifa);
		add_timer(&data->timer);
	} else {
		mptcp_pm_inet6_addr_event(NULL, NETDEV_UP, data->ifa);
		in6_ifa_put(data->ifa);
		kfree(data);
	}
}

static inline void mptcp_dad_setup_timer(struct inet6_ifaddr *ifa)
{
	struct mptcp_dad_data *data;

	data = kmalloc(sizeof(*data), GFP_ATOMIC);

	if (!data)
		return;

	init_timer(&data->timer);
	mptcp_dad_init_timer(data, ifa);
	add_timer(&data->timer);
	in6_ifa_hold(ifa);
}

/* React on IPv6-addr add/rem-events */
static int mptcp_pm_inet6_addr_event(struct notifier_block *this,
				     unsigned long event, void *ptr)
{
	if (mptcp_ipv6_is_in_dad_state((struct inet6_ifaddr *)ptr)) {
		mptcp_dad_setup_timer((struct inet6_ifaddr *)ptr);
		return NOTIFY_DONE;
	} else {
		return mptcp_pm_addr_event_handler(event, ptr, AF_INET6);
	}
}

/* React on ifup/down-events */
static int mptcp_pm_v6_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct inet6_dev *in6_dev = NULL;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
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
				  struct mptcp_cb *mpcb)
{
	int i;
	struct sock *sk, *tmpsk;
	int addr_type = ipv6_addr_type(&ifa->addr);

	/* Checks on interface and address-type */
	if (ifa->scope > RT_SCOPE_LINK ||
	    addr_type == IPV6_ADDR_ANY ||
	    (addr_type & IPV6_ADDR_LOOPBACK) ||
	    (addr_type & IPV6_ADDR_LINKLOCAL))
		return;

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mpcb->loc6_bits, i) {
		if (ipv6_addr_equal(&mpcb->locaddr6[i].addr, &ifa->addr))
			goto found;
	}

	/* Not yet in address-list */
	if ((event == NETDEV_UP || event == NETDEV_CHANGE) &&
	    netif_running(ifa->idev->dev) &&
	    !(ifa->idev->dev->flags & IFF_NOMULTIPATH)) {
		i = __mptcp_find_free_index(mpcb->loc6_bits, 0, mpcb->next_v6_index);
		if (i < 0) {
			mptcp_debug("MPTCP_PM: NETDEV_UP Reached max number of local IPv6 addresses: %d\n",
				    MPTCP_MAX_ADDR);
			return;
		}

		/* update this mpcb */
		mpcb->locaddr6[i].addr = ifa->addr;
		mpcb->locaddr6[i].id = i + MPTCP_MAX_ADDR;
		mpcb->loc6_bits |= (1 << i);
		mpcb->next_v6_index = i + 1;
		/* re-send addresses */
		mptcp_v6_send_add_addr(i, mpcb);
		/* re-evaluate paths */
		mptcp_create_subflows(mpcb->meta_sk);
	}
	return;
found:
	/* Address already in list. Reactivate/Deactivate the
	 * concerned paths. */
	mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (sk->sk_family != AF_INET6 ||
		    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &ifa->addr))
			continue;

		if (event == NETDEV_DOWN ||
		    (ifa->idev->dev->flags & IFF_NOMULTIPATH)) {
			mptcp_reinject_data(sk, 0);
			mptcp_sub_force_close(sk);
		} else if (event == NETDEV_CHANGE) {
			int new_low_prio = (ifa->idev->dev->flags & IFF_MPBACKUP) ?
						1 : 0;
			if (new_low_prio != tp->mptcp->low_prio)
				tp->mptcp->send_mp_prio = 1;
			tp->mptcp->low_prio = new_low_prio;
		}
	}

	if (event == NETDEV_DOWN ||
	    (ifa->idev->dev->flags & IFF_NOMULTIPATH)) {
		mpcb->loc6_bits &= ~(1 << i);

		/* Force sending directly the REMOVE_ADDR option */
		mpcb->remove_addrs |= (1 << mpcb->locaddr6[i].id);
		sk = mptcp_select_ack_sock(mpcb->meta_sk, 0);
		if (sk)
			tcp_send_ack(sk);

		mptcp_for_each_bit_set(mpcb->rem6_bits, i)
			mpcb->remaddr6[i].bitfield &= mpcb->loc6_bits;
	}
}

/* Send ADD_ADDR for loc_id on all available subflows */
void mptcp_v6_send_add_addr(int loc_id, struct mptcp_cb *mpcb)
{
	struct tcp_sock *tp;

	mptcp_for_each_tp(mpcb, tp)
		tp->mptcp->add_addr6 |= (1 << loc_id);
}


static struct notifier_block mptcp_pm_inet6_addr_notifier = {
		.notifier_call = mptcp_pm_inet6_addr_event,
};

static struct notifier_block mptcp_pm_v6_netdev_notifier = {
		.notifier_call = mptcp_pm_v6_netdev_event,
};

/****** End of IPv6-Address event handler ******/

int mptcp_pm_v6_init(void)
{
	int ret;
	struct request_sock_ops *ops = &mptcp6_request_sock_ops;

	ops->slab_name = kasprintf(GFP_KERNEL, "request_sock_%s", "MPTCP6");
	if (ops->slab_name == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ops->slab = kmem_cache_create(ops->slab_name, ops->obj_size, 0,
				      SLAB_HWCACHE_ALIGN, NULL);

	if (ops->slab == NULL) {
		ret =  -ENOMEM;
		goto err_reqsk_create;
	}

	ret = register_inet6addr_notifier(&mptcp_pm_inet6_addr_notifier);
	if (ret)
		goto err_reg_inet6addr;
	ret = register_netdevice_notifier(&mptcp_pm_v6_netdev_notifier);
	if (ret)
		goto err_reg_netdev6;

out:
	return ret;

err_reg_netdev6:
	unregister_inet6addr_notifier(&mptcp_pm_inet6_addr_notifier);
err_reg_inet6addr:
	kmem_cache_destroy(ops->slab);
err_reqsk_create:
	kfree(ops->slab_name);
	ops->slab_name = NULL;
	goto out;
}

void mptcp_pm_v6_undo(void)
{
	kmem_cache_destroy(mptcp6_request_sock_ops.slab);
	kfree(mptcp6_request_sock_ops.slab_name);
	unregister_inet6addr_notifier(&mptcp_pm_inet6_addr_notifier);
	unregister_netdevice_notifier(&mptcp_pm_v6_netdev_notifier);
}
