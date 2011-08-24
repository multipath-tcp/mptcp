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

#include <net/inet6_connection_sock.h>
#include <net/ipv6.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v6.h>
#include <net/tcp.h>

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
	tmp_opt.mss_clamp = 536;
	tmp_opt.user_mss  = tcp_sk(mpcb->master_sk)->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &hash_location,
				  &mpcb->rx_opt, 0);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

	req->mpcb = mpcb;
	req->mptcp_rem_random_number = mpcb->rx_opt.mptcp_recv_random_number;
	req->mptcp_rem_key = mpcb->rx_opt.mptcp_rem_key;
	req->mptcp_loc_key = mpcb->mptcp_loc_key;

	get_random_bytes(&req->mptcp_loc_random_number,
			sizeof(req->mptcp_loc_random_number));

	mptcp_hmac_sha1((u8 *)&req->mptcp_loc_key, (u8 *)&req->mptcp_rem_key,
			(u8 *)&req->mptcp_loc_random_number,
			(u8 *)&req->mptcp_rem_random_number,
			(u32 *)mptcp_hash_mac);
	req->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;

	req->rem_id = tmp_opt.rem_id;
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

struct path6 *mptcp_get_path6(struct multipath_pcb *mpcb, int path_index)
{
	int i;
	for (i = 0; i < mpcb->pa6_size; i++)
		if (mpcb->pa6[i].path_index == path_index)
			return &mpcb->pa6[i];
	return NULL;
}

struct path6 *mptcp_v6_find_path(struct mptcp_loc6 *loc, struct mptcp_loc6 *rem,
				 struct multipath_pcb *mpcb)
{
	int i;
	for (i = 0; i < mpcb->pa6_size; i++) {
		if (mpcb->pa6[i].loc_id != loc->id ||
		    mpcb->pa6[i].rem_id != rem->id)
			continue;

		/* Addresses are equal - now check the port numbers
		 * (0 means wildcard) */
		if (mpcb->pa6[i].loc.sin6_port && loc->port &&
		    mpcb->pa6[i].loc.sin6_port != loc->port)
			continue;

		if (mpcb->pa6[i].rem.sin6_port && rem->port &&
		    mpcb->pa6[i].rem.sin6_port != rem->port)
			continue;

		return &mpcb->pa6[i];
	}
	return NULL;
}

/**
 * Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 *
 */
int mptcp_v6_add_raddress(struct multipath_options *mopt,
			 struct in6_addr *addr, __be16 port, u8 id)
{
	int i;
	int num_addr6 = mopt->num_addr6;
	struct mptcp_loc6 *loc6 = &mopt->addr6[0];

	/* If the id is zero, this is the ULID, do not add it. */
	if (!id)
		return 0;

	BUG_ON(num_addr6 > MPTCP_MAX_ADDR);

	for (i = 0; i < num_addr6; i++) {
		loc6 = &mopt->addr6[i];

		/* Address is already in the list --- continue */
		if (ipv6_addr_equal(&loc6->addr, addr))
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it. */
		if (loc6->id == id &&
			!ipv6_addr_equal(&loc6->addr, addr)) {
			/* update the address */
			mptcp_debug("%s: updating old addr: %pI6 \
					to addr %pI6 with id:%d\n",
					__func__, &loc6->addr,
					addr, id);
			ipv6_addr_copy(&loc6->addr, addr);
			loc6->port = port;
			mopt->list_rcvd = 1;
			return 0;
		}
	}

	/* Do we have already the maximum number of local/remote addresses? */
	if (num_addr6 == MPTCP_MAX_ADDR) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not "
				"adding address: %pI6\n",
				__func__, MPTCP_MAX_ADDR, addr);
		return -1;
	}

	loc6 = &mopt->addr6[i];

	/* Address is not known yet, store it */
	ipv6_addr_copy(&loc6->addr, addr);
	loc6->port = port;
	loc6->id = id;
	mopt->list_rcvd = 1;
	mopt->num_addr6++;

	return 0;
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
	struct request_sock **prev;
	struct sock *child;
	struct request_sock *req;

	req = inet6_csk_search_req(meta_sk, &prev, th->source,
			&iph->saddr, &iph->daddr, inet6_iif(skb));

	if (!req) {
		if (th->syn) {
			struct mp_join *join_opt = mptcp_find_join(skb);
			/* Currently we make two calls to mptcp_find_join(). This
			 * can probably be optimized. */
			if (mptcp_v6_add_raddress(&mpcb->rx_opt,
					(struct in6_addr *)&iph->saddr, 0,
					join_opt->addr_id) < 0)
				goto discard;
			if (unlikely(mpcb->rx_opt.list_rcvd)) {
				mpcb->rx_opt.list_rcvd = 0;
				mptcp_update_patharray(mpcb);
			}
			mptcp_v6_join_request(mpcb, skb);
		}
		goto discard;
	}

	child = tcp_check_req(meta_sk, skb, req, prev);
	if (!child)
		goto discard;

	if (child != meta_sk) {
		mptcp_subflow_attach(mpcb, child);
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
		sock_hold(req->mpcb->master_sk);
	spin_unlock(&mptcp_reqsk_hlock);

	if (!found)
		return NULL;

	return req;
}

int mptcp_v6_send_synack(struct sock *meta_sk,
				 struct request_sock *req)
{
	struct sock *master_sk = ((struct multipath_pcb *)meta_sk)->master_sk;
	struct inet6_request_sock *treq = inet6_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(meta_sk);
	struct sk_buff *skb;
	struct ipv6_txoptions *opt = NULL;
	struct in6_addr *final_p, final;
	struct flowi fl;
	struct dst_entry *dst;
	int err = -1;

	memset(&fl, 0, sizeof(fl));
	fl.proto = IPPROTO_TCP;
	ipv6_addr_copy(&fl.fl6_dst, &treq->rmt_addr);
	ipv6_addr_copy(&fl.fl6_src, &treq->loc_addr);
	fl.fl6_flowlabel = 0;
	fl.oif = treq->iif;
	fl.mark = meta_sk->sk_mark;
	fl.fl_ip_dport = inet_rsk(req)->rmt_port;
	fl.fl_ip_sport = inet_rsk(req)->loc_port;
	security_req_classify_flow(req, &fl);

	opt = np->opt;
	final_p = fl6_update_dst(&fl, opt, &final);

	err = ip6_dst_lookup(meta_sk, &dst, &fl);
	if (err)
		goto done;
	if (final_p)
		ipv6_addr_copy(&fl.fl6_dst, final_p);
	err = xfrm_lookup(sock_net(meta_sk), &dst, &fl, meta_sk, 0);
	if (err < 0)
		goto done;

	skb = mptcp_make_synack(master_sk, dst, req);

	if (skb) {
		__tcp_v6_send_check(skb, &treq->loc_addr, &treq->rmt_addr);

		ipv6_addr_copy(&fl.fl6_dst, &treq->rmt_addr);
		err = ip6_xmit(meta_sk, skb, &fl, opt);
		err = net_xmit_eval(err);
	}

done:
	if (opt && opt != np->opt)
		sock_kfree_s(meta_sk, opt, opt->tot_len);
	dst_release(dst);
	return err;
}

/*This is the MPTCP PM IPV6 mapping table*/
void mptcp_v6_update_patharray(struct multipath_pcb *mpcb)
{
	struct path6 *new_pa6, *old_pa6;
	int i, j, newpa_idx = 0;
	struct sock *meta_sk = (struct sock *)mpcb;

	/* Count how many paths are available
	 * We add 1 to size of local and remote set, to include the
	 * ULID */
	int ulid_v6 = (meta_sk->sk_family == AF_INET6) ? 1 : 0;
	int pa6_size = (mpcb->num_addr6 + ulid_v6) *
		(mpcb->rx_opt.num_addr6 + ulid_v6) - ulid_v6;

	new_pa6 = kmalloc(pa6_size * sizeof(struct path6), GFP_ATOMIC);

	if (ulid_v6) {
		struct mptcp_loc6 loc_ulid, rem_ulid;
		loc_ulid.id = 0;
		loc_ulid.port = 0;
		rem_ulid.id = 0;
		rem_ulid.port = 0;
		/* ULID src with other dest */
		for (j = 0; j < mpcb->rx_opt.num_addr6; j++) {
			struct path6 *p = mptcp_v6_find_path(&loc_ulid,
				&mpcb->rx_opt.addr6[j], mpcb);
			if (p) {
				memcpy(&new_pa6[newpa_idx++], p,
				       sizeof(struct path6));
			} else {
				p = &new_pa6[newpa_idx++];

				p->loc.sin6_family = AF_INET6;
				ipv6_addr_copy(&p->loc.sin6_addr,
						&inet6_sk(meta_sk)->saddr);
				p->loc.sin6_port = 0;
				p->loc_id = 0;

				p->rem.sin6_family = AF_INET6;
				ipv6_addr_copy(&p->rem.sin6_addr,
					&mpcb->rx_opt.addr6[j].addr);
				p->rem.sin6_port = 0;
				p->rem_id = mpcb->rx_opt.addr6[j].id;

				p->path_index = mpcb->next_unused_pi++;
			}
		}
		/* ULID dest with other src */
		for (i = 0; i < mpcb->num_addr6; i++) {
			struct path6 *p = mptcp_v6_find_path(&mpcb->addr6[i],
					&rem_ulid, mpcb);
			if (p) {
				memcpy(&new_pa6[newpa_idx++], p,
				       sizeof(struct path6));
			} else {
				p = &new_pa6[newpa_idx++];

				p->loc.sin6_family = AF_INET6;
				ipv6_addr_copy(&p->loc.sin6_addr,
						&mpcb->addr6[i].addr);
				p->loc.sin6_port = 0;
				p->loc_id = mpcb->addr6[i].id;

				p->rem.sin6_family = AF_INET6;
				ipv6_addr_copy(&p->rem.sin6_addr,
						&inet6_sk(meta_sk)->daddr);
				p->rem.sin6_port = 0;
				p->rem_id = 0;

				p->path_index = mpcb->next_unused_pi++;
			}
		}
	}
	/* Try all other combinations now */
	for (i = 0; i < mpcb->num_addr6; i++)
		for (j = 0; j < mpcb->rx_opt.num_addr6; j++) {
			struct path6 *p =
			    mptcp_v6_find_path(&mpcb->addr6[i],
					    &mpcb->rx_opt.addr6[j],
					    mpcb);
			if (p) {
				memcpy(&new_pa6[newpa_idx++], p,
				       sizeof(struct path6));
			} else {
				p = &new_pa6[newpa_idx++];

				p->loc.sin6_family = AF_INET6;
				ipv6_addr_copy(&p->loc.sin6_addr,
						&mpcb->addr6[i].addr);
				p->loc.sin6_port = 0;
				p->loc_id = mpcb->addr6[i].id;

				p->rem.sin6_family = AF_INET6;
				ipv6_addr_copy(&p->rem.sin6_addr,
					&mpcb->rx_opt.addr6[j].addr);
				p->rem.sin6_port =
					mpcb->rx_opt.addr6[j].port;
				p->rem_id = mpcb->rx_opt.addr6[j].id;

				p->path_index = mpcb->next_unused_pi++;
			}
		}

	/* Replacing the mapping table */
	old_pa6 = mpcb->pa6;
	mpcb->pa6 = new_pa6;
	mpcb->pa6_size = pa6_size;
	kfree(old_pa6);
}
