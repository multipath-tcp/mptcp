/*
 *	MPTCP implementation
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *      date : March 2010
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
#include <linux/tcp_options.h>
#include <linux/tcp.h>

#include <net/inet_connection_sock.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>
#include <net/request_sock.h>
#include <net/tcp.h>

/*Copied from net/ipv4/inet_connection_sock.c*/
static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return jhash_2words((__force u32) raddr, (__force u32) rport,
			    rnd) & (synq_hsize - 1);
}

/* Copied from tcp_ipv4.c */
static inline __u32 tcp_v4_init_sequence(struct sk_buff *skb)
{
	return secure_tcp_sequence_number(ip_hdr(skb)->daddr,
					  ip_hdr(skb)->saddr,
					  tcp_hdr(skb)->dest,
					  tcp_hdr(skb)->source);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

static void mptcp_v4_reqsk_queue_hash_add(struct request_sock *req,
				      unsigned long timeout)
{
	struct inet_connection_sock *meta_icsk =
	    (struct inet_connection_sock *)(req->mpcb);
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
	list_add(&req->collide_tuple, &mptcp_reqsk_htb[h_global]);
	spin_unlock_bh(&mptcp_reqsk_hlock);
}

/* from tcp_v4_conn_request() */
static int mptcp_v4_join_request(struct multipath_pcb *mpcb,
		struct sk_buff *skb)
{
	struct inet_request_sock *ireq;
	struct request_sock *req;
	struct tcp_options_received tmp_opt;
	u8 mptcp_hash_mac[20];
	u8 *hash_location;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;

	req = inet_reqsk_alloc(&tcp_request_sock_ops);
	if (!req)
		return -1;

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss = tcp_sk(mpcb->master_sk)->rx_opt.user_mss;
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

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->opt = tcp_v4_save_options(NULL, skb);

	/* Todo: add the sanity checks here. See tcp_v4_conn_request */

	isn = tcp_v4_init_sequence(skb);

	tcp_rsk(req)->snt_isn = isn;

	if (mptcp_v4_send_synack((struct sock *)mpcb, req, NULL))
		goto drop_and_free;

	/*Adding to request queue in metasocket */
	mptcp_v4_reqsk_queue_hash_add(req, TCP_TIMEOUT_INIT);
	return 0;

drop_and_free:
	reqsk_free(req);
	return -1;
}

struct path4 *mptcp_v4_find_path(struct mptcp_loc4 *loc, struct mptcp_loc4 *rem,
				 struct multipath_pcb *mpcb)
{
	int i;
	for (i = 0; i < mpcb->pa4_size; i++) {
		if (mpcb->pa4[i].loc_id != loc->id ||
		    mpcb->pa4[i].rem_id != rem->id)
			continue;

		/* Addresses are equal - now check the port numbers
		 * (0 means wildcard) */
		if (mpcb->pa4[i].loc.sin_port && loc->port &&
		    mpcb->pa4[i].loc.sin_port != loc->port)
			continue;

		if (mpcb->pa4[i].rem.sin_port && rem->port &&
		    mpcb->pa4[i].rem.sin_port != rem->port)
			continue;

		return &mpcb->pa4[i];
	}
	return NULL;
}

struct path4 *mptcp_v4_get_path(struct multipath_pcb *mpcb, int path_index)
{
	int i;
	for (i = 0; i < mpcb->pa4_size; i++)
		if (mpcb->pa4[i].path_index == path_index)
			return &mpcb->pa4[i];
	return NULL;
}

/**
 * Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 */
int mptcp_v4_add_raddress(struct multipath_options *mopt,
			struct in_addr *addr, __be16 port, u8 id)
{
	int i;
	int num_addr4 = mopt->num_addr4;
	struct mptcp_loc4 *loc4 = &mopt->addr4[0];

	/* If the id is zero, this is the ULID, do not add it. */
	if (!id)
		return 0;

	BUG_ON(num_addr4 > MPTCP_MAX_ADDR);

	for (i = 0; i < num_addr4; i++) {
		loc4 = &mopt->addr4[i];

		/* Address is already in the list --- continue */
		if (loc4->addr.s_addr == addr->s_addr && loc4->port == port)
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it. */
		if (loc4->id == id && loc4->addr.s_addr != addr->s_addr) {
			/* update the address */
			mptcp_debug("%s: updating old addr:%pI4"
				   " to addr %pi4 with id:%d\n",
				   __func__, &loc4->addr.s_addr,
				   &addr->s_addr, id);
			loc4->addr.s_addr = addr->s_addr;
			loc4->port = port;
			mopt->list_rcvd = 1;
			return 0;
		}
	}

	/* Do we have already the maximum number of local/remote addresses? */
	if (num_addr4 == MPTCP_MAX_ADDR) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not "
			   "adding address: %pI4\n",
			   __func__, MPTCP_MAX_ADDR, &addr->s_addr);
		return -1;
	}

	loc4 = &mopt->addr4[i];

	/* Address is not known yet, store it */
	loc4->addr.s_addr = addr->s_addr;
	loc4->port = port;
	loc4->id = id;
	mopt->list_rcvd = 1;
	mopt->num_addr4++;

	return 0;
}

/**
 * Currently we can only process join requests here.
 * (either the SYN or the final ACK)
 */
int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	struct multipath_pcb *mpcb = (struct multipath_pcb *)meta_sk;
	struct request_sock **prev;
	struct sock *child;
	struct request_sock *req;

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
				goto discard;
			if (unlikely(mpcb->rx_opt.list_rcvd)) {
				mpcb->rx_opt.list_rcvd = 0;
				mptcp_update_patharray(mpcb);
			}
			mptcp_v4_join_request(mpcb, skb);
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

/**
 * Inspired from inet_csk_search_req
 * After this, the ref count of the master_sk associated with the request_sock
 * is incremented. Thus it is the responsibility of the caller
 * to call sock_put() when the reference is not needed anymore.
 */
struct request_sock *mptcp_v4_search_req(const __be16 rport,
					    const __be32 raddr,
					    const __be32 laddr)
{
	struct request_sock *req;
	int found = 0;

	spin_lock(&mptcp_reqsk_hlock);
	list_for_each_entry(req,
			    &mptcp_reqsk_htb[inet_synq_hash
					(raddr, rport, 0, MPTCP_HASH_SIZE)],
			    collide_tuple) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (!req->collide_tuple.next) {
			printk(KERN_ERR
			       "tuple hashtable corrupted! (bug 66)\n");
			printk("bad node %pI4:%d->%pI4:%d\n", &ireq->loc_addr,
			       ntohs(ireq->loc_port), &ireq->rmt_addr,
			       ntohs(ireq->rmt_port));
			BUG();
		}

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
		sock_hold(req->mpcb->master_sk);
	spin_unlock(&mptcp_reqsk_hlock);

	if (!found)
		return NULL;

	return req;
}

/**
 * Send a SYN-ACK after having received a SYN.
 * This is to be used for JOIN subflows only.
 * Initial subflows use the regular tcp_v4_rtx_synack() function.
 * This still operates on a request_sock only, not on a big
 * socket.
 */
int mptcp_v4_send_synack(struct sock *meta_sk,
			struct request_sock *req,
			struct request_values *rvp)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct sock *master_sk = ((struct multipath_pcb *)meta_sk)->master_sk;
	int err = -1;
	struct sk_buff *skb;
	struct dst_entry *dst;

	/* First, grab a route. */
	dst = mptcp_route_req(req);
	if (!dst)
		return -1;

	skb = mptcp_make_synack(master_sk, dst, req);

	if (skb) {
		__tcp_v4_send_check(skb, ireq->loc_addr, ireq->rmt_addr);

		err = ip_build_and_send_pkt(skb, meta_sk, ireq->loc_addr,
					    ireq->rmt_addr, ireq->opt);
		err = net_xmit_eval(err);
	}

	dst_release(dst);
	return err;
}

/* This is the MPTCP PM mapping table */
void mptcp_v4_update_patharray(struct multipath_pcb *mpcb)
{
	struct path4 *new_pa4, *old_pa4;
	int i, j, newpa_idx = 0;
	struct sock *meta_sk = (struct sock *)mpcb;
	/* Count how many paths are available
	 * We add 1 to size of local and remote set, to include the
	 * ULID
	 */
	int ulid_v4;
	int pa4_size;

	if (sysctl_mptcp_ndiffports > 1)
		return __mptcp_update_patharray_ports(mpcb);

	ulid_v4 = (meta_sk->sk_family == AF_INET ||
		   (meta_sk->sk_family == AF_INET6 &&
		    tcp_v6_is_v4_mapped(meta_sk))) ? 1 : 0;
	pa4_size = (mpcb->num_addr4 + ulid_v4) *
	    (mpcb->rx_opt.num_addr4 + ulid_v4) - ulid_v4;

	new_pa4 = kmalloc(pa4_size * sizeof(struct path4), GFP_ATOMIC);

	if (ulid_v4) {
		struct mptcp_loc4 loc_ulid, rem_ulid;
		loc_ulid.id = 0;
		loc_ulid.port = 0;
		rem_ulid.id = 0;
		rem_ulid.port = 0;
		/* ULID src with other dest */
		for (j = 0; j < mpcb->rx_opt.num_addr4; j++) {
			struct path4 *p = mptcp_v4_find_path(&loc_ulid,
				&mpcb->rx_opt.addr4[j], mpcb);
			if (p) {
				memcpy(&new_pa4[newpa_idx++], p,
				       sizeof(struct path4));
			} else {
				p = &new_pa4[newpa_idx++];

				p->loc.sin_family = AF_INET;
				p->loc.sin_addr.s_addr =
						inet_sk(meta_sk)->inet_saddr;
				p->loc.sin_port = 0;
				p->loc_id = 0;

				p->rem.sin_family = AF_INET;
				p->rem.sin_addr =
					mpcb->rx_opt.addr4[j].addr;
				p->rem.sin_port = 0;
				p->rem_id = mpcb->rx_opt.addr4[j].id;

				p->path_index = mpcb->next_unused_pi++;
			}
		}

		/* ULID dest with other src */
		for (i = 0; i < mpcb->num_addr4; i++) {
			struct path4 *p = mptcp_v4_find_path(&mpcb->addr4[i],
					&rem_ulid, mpcb);
			if (p) {
				memcpy(&new_pa4[newpa_idx++], p,
				       sizeof(struct path4));
			} else {
				p = &new_pa4[newpa_idx++];

				p->loc.sin_family = AF_INET;
				p->loc.sin_addr = mpcb->addr4[i].addr;
				p->loc.sin_port = 0;
				p->loc_id = mpcb->addr4[i].id;

				p->rem.sin_family = AF_INET;
				p->rem.sin_addr.s_addr =
						inet_sk(meta_sk)->inet_daddr;
				p->rem.sin_port = 0;
				p->rem_id = 0;

				p->path_index = mpcb->next_unused_pi++;
			}
		}
	}

	/* Try all other combinations now */
	for (i = 0; i < mpcb->num_addr4; i++)
		for (j = 0; j < mpcb->rx_opt.num_addr4; j++) {
			struct path4 *p =
			    mptcp_v4_find_path(&mpcb->addr4[i],
					    &mpcb->rx_opt.addr4[j],
					    mpcb);
			if (p) {
				memcpy(&new_pa4[newpa_idx++], p,
				       sizeof(struct path4));
			} else {
				p = &new_pa4[newpa_idx++];

				p->loc.sin_family = AF_INET;
				p->loc.sin_addr = mpcb->addr4[i].addr;
				p->loc.sin_port = 0;
				p->loc_id = mpcb->addr4[i].id;

				p->rem.sin_family = AF_INET;
				p->rem.sin_addr =
					mpcb->rx_opt.addr4[j].addr;
				p->rem.sin_port =
					mpcb->rx_opt.addr4[j].port;
				p->rem_id = mpcb->rx_opt.addr4[j].id;

				p->path_index = mpcb->next_unused_pi++;
			}
		}

	/* Replacing the mapping table */
	old_pa4 = mpcb->pa4;
	mpcb->pa4 = new_pa4;
	mpcb->pa4_size = pa4_size;
	kfree(old_pa4);
}

