/*
 *	MPTCP PM implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      date : May 11
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

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
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/if_inet6.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/inet6_connection_sock.h>
#include <net/mptcp_v6.h>
#include <net/addrconf.h>
#endif

#define hash_tk(token) \
	(jhash_1word(token, 0) % MPTCP_HASH_SIZE)

static struct list_head tk_hashtable[MPTCP_HASH_SIZE];
static rwlock_t tk_hash_lock;	/* hashtable protection */

/* This second hashtable is needed to retrieve request socks
 * created as a result of a join request. While the SYN contains
 * the token, the final ack does not, so we need a separate hashtable
 * to retrieve the mpcb.
 */
struct list_head mptcp_reqsk_htb[MPTCP_HASH_SIZE];
spinlock_t mptcp_reqsk_hlock;	/* hashtable protection */


void mptcp_hash_insert(struct multipath_pcb *mpcb, u32 token)
{
	int hash = hash_tk(token);

	mptcp_debug("%s: add mpcb to hash-table with loc_token %#x\n",
			__func__, mpcb->mptcp_loc_token);

	write_lock_bh(&tk_hash_lock);
	list_add(&mpcb->collide_tk, &tk_hashtable[hash]);
	write_unlock_bh(&tk_hash_lock);
}

int mptcp_find_token(u32 token) {
       int hash = hash_tk(token);
       struct multipath_pcb *mpcb;

       read_lock_bh(&tk_hash_lock);
       list_for_each_entry(mpcb, &tk_hashtable[hash], collide_tk) {
               if (token == mpcb->mptcp_loc_token) {
                       read_unlock(&tk_hash_lock);
                       return 1;
               }
       }
       read_unlock_bh(&tk_hash_lock);
       return 0;
}

/**
 * This function increments the refcount of the mpcb struct.
 * It is the responsibility of the caller to decrement when releasing
 * the structure.
 */
struct multipath_pcb *mptcp_hash_find(u32 token)
{
	u32 hash = hash_tk(token);
	struct multipath_pcb *mpcb;

	read_lock(&tk_hash_lock);
	list_for_each_entry(mpcb, &tk_hashtable[hash], collide_tk) {
		if (token == mpcb->mptcp_loc_token) {
			sock_hold(mpcb->master_sk);
			read_unlock(&tk_hash_lock);
			return mpcb;
		}
	}
	read_unlock(&tk_hash_lock);
	return NULL;
}

void mptcp_hash_remove(struct multipath_pcb *mpcb)
{
	struct inet_connection_sock *meta_icsk =
	    (struct inet_connection_sock *)mpcb;
	struct listen_sock *lopt = meta_icsk->icsk_accept_queue.listen_opt;

	mptcp_debug("%s: remove mpcb from hash-table with loc_token %08x\n",
			__func__, mpcb->mptcp_loc_token);

	/* remove from the token hashtable */
	write_lock_bh(&tk_hash_lock);
	list_del(&mpcb->collide_tk);
	write_unlock_bh(&tk_hash_lock);

	/* Remove all pending request socks. */
	spin_lock_bh(&mptcp_reqsk_hlock);
	if (lopt->qlen != 0) {
		unsigned int i;
		for (i = 0; i < lopt->nr_table_entries; i++) {
			struct request_sock *cur_ref;
			cur_ref = lopt->syn_table[i];
			while (cur_ref) {
				/* Remove from global tuple hashtable
				 * We use list_del_init because that
				 * function supports multiple deletes, with
				 * only the first one actually deleting.
				 * This is useful since mptcp_check_req()
				 * might try to remove it as well
				 */
				list_del_init(&cur_ref->collide_tuple);
				/* next element in collision list.
				 * we don't remove yet the request_sock
				 * from the local hashtable. This will be done
				 * by mptcp_pm_release()
				 */
				cur_ref = cur_ref->dl_next;
			}
		}
	}
	spin_unlock_bh(&mptcp_reqsk_hlock);
}

void mptcp_hash_request_remove(struct request_sock *req)
{
	spin_lock_bh(&mptcp_reqsk_hlock);
	/* list_del_init: see comment in mptcp_hash_remove() */
	list_del_init(&req->collide_tuple);
	spin_unlock_bh(&mptcp_reqsk_hlock);
}

void mptcp_pm_release(struct multipath_pcb *mpcb)
{
	struct inet_connection_sock *meta_icsk =
	    (struct inet_connection_sock *)mpcb;
	struct listen_sock *lopt = meta_icsk->icsk_accept_queue.listen_opt;

	/* Remove all pending request socks. */
	if (lopt->qlen != 0) {
		unsigned int i;
		for (i = 0; i < lopt->nr_table_entries; i++) {
			struct request_sock **cur_ref;
			cur_ref = &lopt->syn_table[i];
			while (*cur_ref) {
				struct request_sock *todel;

				lopt->qlen--;
				todel = *cur_ref;
				/* Remove from local hashtable, it has
				 * been removed already from the global one by
				 * mptcp_hash_remove()
				 */
				*cur_ref = (*cur_ref)->dl_next;
				reqsk_free(todel);
			}
		}
	}

	/* Normally we should have
	 * accepted all the child socks in destroy_mpcb, after
	 * having removed the mpcb from the hashtable. So having this queue
	 * non-empty can only be a bug.
	 */
	BUG_ON(!reqsk_queue_empty(&meta_icsk->icsk_accept_queue));
}

u8 mptcp_get_loc_addrid(struct multipath_pcb *mpcb, struct sock* sk)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb);
	int i;

	if (sk->sk_family == AF_INET) {
		for (i = 0; i < mpcb->num_addr4; i++) {
			if (mpcb->addr4[i].addr.s_addr ==
					inet_sk(sk)->inet_saddr)
				return mpcb->addr4[i].id;
		}
		/* thus it must be the master-socket */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (mpcb->master_sk->sk_family == AF_INET6 &&
		    mptcp_v6_is_v4_mapped(mpcb->master_sk) &&
		    inet_sk(mpcb->master_sk)->inet_saddr ==
				    inet_sk(sk)->inet_saddr)
			return 0;
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
		if (mpcb->master_sk->sk_family == AF_INET &&
		    inet_sk(mpcb->master_sk)->inet_saddr ==
				    inet_sk(sk)->inet_saddr) {
			return 0;
		}

		mptcp_debug("%s %pI4 not locally found\n", __func__,
					&inet_sk(sk)->inet_saddr);
		BUG();
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (sk->sk_family == AF_INET6) {
		for (i = 0; i < mpcb->num_addr6; i++) {
			if (ipv6_addr_equal(&mpcb->addr6[i].addr,
					&inet6_sk(sk)->saddr))
				return mpcb->addr6[i].id;
		}
		/* thus it must be the master-socket - id = 0 */
		if (mpcb->master_sk->sk_family == AF_INET6 &&
		    ipv6_addr_equal(&inet6_sk(mpcb->master_sk)->saddr,
				&inet6_sk(sk)->saddr))
			return 0;

		mptcp_debug("%s %pI6 not locally found\n", __func__,
				&inet6_sk(sk)->saddr);
		BUG();
	}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	BUG();
}

void __mptcp_update_patharray_ports(struct multipath_pcb *mpcb)
{
	int pa4_size = sysctl_mptcp_ndiffports - 1; /* -1 because the initial
						     * flow counts for one.
						     */
	struct path4 *new_pa4;
	int newpa_idx = 0;
	struct sock *meta_sk = (struct sock *)mpcb;

	if (mpcb->pa4)
		return; /* path allocation already done */

	new_pa4 = kmalloc(pa4_size * sizeof(struct path4), GFP_ATOMIC);

	for (newpa_idx = 0; newpa_idx < pa4_size; newpa_idx++) {
		new_pa4[newpa_idx].loc.sin_family = AF_INET;
		new_pa4[newpa_idx].loc.sin_addr.s_addr =
				inet_sk(meta_sk)->inet_saddr;
		new_pa4[newpa_idx].loc.sin_port = 0;
		new_pa4[newpa_idx].loc_id = 0; /* ulid has id 0 */
		new_pa4[newpa_idx].rem.sin_family = AF_INET;
		new_pa4[newpa_idx].rem.sin_addr.s_addr =
			inet_sk(meta_sk)->inet_daddr;
		new_pa4[newpa_idx].rem.sin_port = inet_sk(meta_sk)->inet_dport;
		new_pa4[newpa_idx].rem_id = 0; /* ulid has id 0 */

		new_pa4[newpa_idx].path_index = mpcb->next_unused_pi++;
	}

	mpcb->pa4 = new_pa4;
	mpcb->pa4_size = pa4_size;
}
void mptcp_update_patharray(struct multipath_pcb *mpcb)
{
	mptcp_v4_update_patharray(mpcb);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	mptcp_v6_update_patharray(mpcb);
#endif

}

void mptcp_set_addresses(struct multipath_pcb *mpcb)
{
	struct net_device *dev;
	struct sock *meta_sk = mpcb_meta_sk(mpcb);
	int id = 1;
	int num_addr4 = 0;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	int num_addr6 = 0;
#endif

	/* if multiports is requested, we work with the main address
	 * and play only with the ports
	 */
	if (sysctl_mptcp_ndiffports != 1)
		return;

	read_lock_bh(&dev_base_lock);

	for_each_netdev(&init_net, dev) {
		if (netif_running(dev)) {
			struct in_device *in_dev = dev->ip_ptr;
			struct in_ifaddr *ifa;
			__be32 ifa_address;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			struct inet6_dev *in6_dev = dev->ip6_ptr;
			struct inet6_ifaddr *ifa6;
#endif

			if (dev->flags & IFF_LOOPBACK)
				continue;

			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				ifa_address = ifa->ifa_local;

				if (num_addr4 == MPTCP_MAX_ADDR) {
					mptcp_debug ("%s: At max num of local "
						"addresses: %d --- not adding "
						"address: %pI4\n",
						__func__, MPTCP_MAX_ADDR,
						&ifa_address);
					goto out;
				}

				if (mpcb->master_sk->sk_family == AF_INET &&
				    inet_sk(mpcb->master_sk)->inet_saddr == ifa->ifa_address)
					continue;
				/* master is IPv4 mapped IPv6 sk */
				if (mpcb->master_sk->sk_family == AF_INET6 &&
				    mptcp_v6_is_v4_mapped(mpcb->master_sk) &&
				    inet_sk(mpcb->master_sk)->inet_saddr == ifa->ifa_address )
					continue;
				if (ifa->ifa_scope == RT_SCOPE_HOST)
					continue;
				mpcb->addr4[num_addr4].addr.s_addr =
				    ifa_address;
				mpcb->addr4[num_addr4].port = 0;
				mpcb->addr4[num_addr4++].id = id++;
			}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)

			list_for_each_entry(ifa6, &in6_dev->addr_list,
					if_list) {
				int addr_type = ipv6_addr_type(&ifa6->addr);
				if (num_addr6 == MPTCP_MAX_ADDR) {
					mptcp_debug("%s: At max num of local"
						"addresses: %d --- not adding"
						"address: %pI6\n",
						__func__,
						MPTCP_MAX_ADDR, &ifa6->addr);
					goto out;
				}
				if (mpcb->master_sk->sk_family == AF_INET6 &&
					!mptcp_v6_is_v4_mapped(mpcb->master_sk) &&
					ipv6_addr_equal(&(ifa6->addr),
					&(inet6_sk(mpcb->master_sk)->saddr)))
					continue;
				if (addr_type == IPV6_ADDR_ANY ||
				    addr_type & IPV6_ADDR_LOOPBACK ||
				    addr_type & IPV6_ADDR_LINKLOCAL)
					continue;
				ipv6_addr_copy(&(mpcb->addr6[num_addr6].addr),
					&(ifa6->addr));
				mpcb->addr6[num_addr6].port = 0;
				mpcb->addr6[num_addr6++].id = id++;
			}
#endif
		}
	}

out:
	read_unlock_bh(&dev_base_lock);

	/* We update num_addr4 at the end to avoid racing with the ADDR option
	 * trigger (in tcp_established_options()),
	 * which can interrupt us in the middle of this function,
	 * and decide to already send the set of addresses, even though all
	 * addresses have not yet been read.
	 */
	mpcb->num_addr4 = mpcb->addr4_unsent = num_addr4;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	mpcb->num_addr6 = mpcb->addr6_unsent = num_addr6;
#endif
}

struct dst_entry *mptcp_route_req(const struct request_sock *req,
				  struct sock *meta_sk)
{
	struct rtable *rt;
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options_rcu *opt = inet_rsk(req)->opt;
	struct flowi4 fl4;

	flowi4_init_output(&fl4, 0, meta_sk->sk_mark,
			   RT_CONN_FLAGS(meta_sk), RT_SCOPE_UNIVERSE,
			   meta_sk->sk_protocol, inet_sk_flowi_flags(meta_sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->rmt_addr,
			   ireq->loc_addr, ireq->rmt_port, inet_sk(meta_sk)->inet_sport);

	security_req_classify_flow(req, flowi4_to_flowi(&fl4));
	rt = ip_route_output_flow(&init_net, &fl4, NULL);

	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && fl4.daddr != rt->rt_gateway)
		goto route_err;
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	IP_INC_STATS_BH(&init_net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}

void mptcp_synack_options(struct request_sock *req,
			  struct tcp_out_options *opts,
			  unsigned *remaining)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	if (req->saw_mpc && !req->mpcb) {
		opts->options |= OPTION_MP_CAPABLE;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYNACK_ALIGN;
		opts->sender_key = req->mptcp_loc_key;
		opts->dss_csum = sysctl_mptcp_checksum || req->dss_csum;
	}

	if (req->saw_mpc && req->mpcb) {
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

/*copied from net/ipv4/tcp_minisocks.c*/
static inline int tcp_in_window(u32 seq, u32 end_seq, u32 s_win, u32 e_win)
{
	if (seq == s_win)
		return 1;
	if (after(end_seq, s_win) && before(seq, e_win))
		return 1;
	return (seq == e_win && seq == end_seq);
}

int mptcp_syn_recv_sock(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct request_sock *req = NULL;
	struct sock *meta_sk, *master_sk;

	if (skb->protocol == htons(ETH_P_IP))
		req = mptcp_v4_search_req(th->source, ip_hdr(skb)->saddr,
						ip_hdr(skb)->daddr);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else /* IPv6 */
		req = mptcp_v6_search_req(th->source, &ipv6_hdr(skb)->saddr,
						&ipv6_hdr(skb)->daddr);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	if (!req)
		return 0;
	meta_sk = (struct sock *)req->mpcb;
	master_sk = req->mpcb->master_sk;
	bh_lock_sock_nested(master_sk);
	if (sock_owned_by_user(master_sk)) {
		if (unlikely(sk_add_backlog(meta_sk, skb))) {
			bh_unlock_sock(master_sk);
			NET_INC_STATS_BH(dev_net(skb->dev),
					LINUX_MIB_TCPBACKLOGDROP);
			sock_put(master_sk); /* Taken by mptcp_search_req */
			kfree_skb(skb);
			return 1;
		}
	} else if (skb->protocol == htons(ETH_P_IP))
		tcp_v4_do_rcv(meta_sk, skb);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else /* IPv6 */
		tcp_v6_do_rcv(meta_sk, skb);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	bh_unlock_sock(master_sk);
	sock_put(master_sk); /* Taken by mptcp_search_req */
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
			return 0;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return NULL;
			if (opsize > length)
				return NULL;  /* don't parse partial options */
			if (opcode == TCPOPT_MPTCP) {
				struct mptcp_option *mp_opt =
						(struct mptcp_option *) ptr;

				if (mp_opt->sub == MPTCP_SUB_JOIN)
					return (struct mp_join *) ptr;
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
	return NULL;
}

/*
 * @return:
 */
int mptcp_lookup_join(struct sk_buff *skb)
{
	struct multipath_pcb *mpcb;
	struct sock *meta_sk;
	u32 token;
	struct mp_join *join_opt = mptcp_find_join(skb);
	if (!join_opt)
		return 0;

	join_opt++; /* the token is at the end of struct mp_join */
	token = *(u32 *) join_opt;
	mpcb = mptcp_hash_find(token);
	meta_sk = mpcb_meta_sk(mpcb);
	if (!mpcb) {
		mptcp_debug("%s:mpcb not found:%x\n", __func__, token);
		return -1;
	}

	if (mpcb->infinite_mapping)
		/* We are in fallback-mode - thus no new subflows!!! */
		return -1;

	/* OK, this is a new syn/join, let's create a new open request and
	 * send syn+ack
	 */
	bh_lock_sock(mpcb->master_sk);
	if (sock_owned_by_user(mpcb->master_sk)) {
		if (unlikely(sk_add_backlog(meta_sk, skb))) {
			bh_unlock_sock(mpcb->master_sk);
			NET_INC_STATS_BH(dev_net(skb->dev),
					LINUX_MIB_TCPBACKLOGDROP);
			sock_put(mpcb->master_sk); /*Taken by mptcp_hash_find*/
			kfree_skb(skb);
			return 1;
		}
	} else if (skb->protocol == htons(ETH_P_IP))
		tcp_v4_do_rcv(meta_sk, skb);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else /* IPv6 */
		tcp_v6_do_rcv(meta_sk, skb);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	bh_unlock_sock(mpcb->master_sk);
	sock_put(mpcb->master_sk); /* Taken by mptcp_hash_find */
	return 1;
}

/**
 * Sends an update notification to the MPS
 * Since this particular PM works in the TCP layer, that is, the same
 * as the MPS, we "send" the notif through function call, not message
 * passing.
 * Warning: this can be called only from user context, not soft irq
 **/
static void __mptcp_send_updatenotif(struct multipath_pcb *mpcb)
{
	int i;
	u32 path_indices = 1;	/* Path index 1 is reserved for master sk. */

	if (sock_flag(mpcb_meta_sk(mpcb), SOCK_DEAD))
		return;

	for (i = 0; i < mpcb->pa4_size; i++)
		path_indices |= mptcp_pi_to_flag(mpcb->pa4[i].path_index);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	for (i = 0; i < mpcb->pa6_size; i++)
		path_indices |= mptcp_pi_to_flag(mpcb->pa6[i].path_index);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	mptcp_init_subsockets(mpcb, path_indices);
}

static void mptcp_send_updatenotif_wq(struct work_struct *work)
{
	struct multipath_pcb *mpcb = *(struct multipath_pcb **)(work + 1);
	lock_sock_nested(mpcb->master_sk, SINGLE_DEPTH_NESTING);
	__mptcp_send_updatenotif(mpcb);
	release_sock(mpcb->master_sk);
	sock_put(mpcb->master_sk);
	kfree(work);
}

void mptcp_send_updatenotif(struct multipath_pcb *mpcb)
{
	if (!tcp_sk(mpcb->master_sk)->fully_established ||
	    mpcb->infinite_mapping ||
	    test_bit(MPCB_FLAG_SERVER_SIDE, &mpcb->flags) ||
	    sock_flag(mpcb_meta_sk(mpcb), SOCK_DEAD))
		return;

	if (in_interrupt()) {
		struct work_struct *work = kmalloc(sizeof(*work) +
						sizeof(struct multipath_pcb *),
						GFP_ATOMIC);
		struct multipath_pcb **mpcbp = (struct multipath_pcb **)
			(work + 1);
		*mpcbp = mpcb;
		sock_hold(mpcb->master_sk); /* Needed to ensure we can take
					     * the lock
					     */
		INIT_WORK(work, mptcp_send_updatenotif_wq);
		schedule_work(work);
	} else {
		__mptcp_send_updatenotif(mpcb);
	}
}

void mptcp_subflow_attach(struct multipath_pcb *mpcb, struct sock *subsk)
{
	struct path4 *p4 = NULL;
	struct path6 *p6 = NULL;
	struct mptcp_loc4 loc, rem;
	struct mptcp_loc6 loc6, rem6;
	loc.id = inet_sk(subsk)->loc_id;
	loc.port = inet_sk(subsk)->inet_sport;
	rem.id = inet_sk(subsk)->rem_id;
	rem.port = inet_sk(subsk)->inet_dport;
	loc6.id = inet_sk(subsk)->loc_id;
	loc6.port = inet_sk(subsk)->inet_sport;
	rem6.id = inet_sk(subsk)->rem_id;
	rem6.port = inet_sk(subsk)->inet_dport;
	/* Apply correct path index to that subflow
	 * (we bypass the patharray if in multiports mode)
	 */
	if (sysctl_mptcp_ndiffports > 1)
		goto diffPorts;

	if (subsk->sk_family == AF_INET)
		p4 = mptcp_v4_find_path(&loc, &rem, mpcb);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else
		p6 = mptcp_v6_find_path(&loc6, &rem6, mpcb);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	if (!p4 && !p6) {
		/* It is possible that we don't find the mapping,
		 * if we have not yet updated our set of local
		 * addresses.
		 */
		mptcp_set_addresses(mpcb);

		/* If this added new local addresses, build new paths
		 * with them
		 */
		if (mpcb->num_addr4 || mpcb->num_addr6)
			mptcp_update_patharray(mpcb);


		if (subsk->sk_family == AF_INET)
			p4 = mptcp_v4_find_path(&loc, &rem, mpcb);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else
			p6 = mptcp_v6_find_path(&loc6, &rem6, mpcb);
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	}

	if (p4 || p6) {
		if (subsk->sk_family == AF_INET) {
			tcp_sk(subsk)->path_index = p4->path_index;
			p4->loc.sin_port = loc.port;
			p4->rem.sin_port = rem.port;
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else {
			tcp_sk(subsk)->path_index = p6->path_index;
			p6->loc.sin6_port = loc6.port;
			p6->rem.sin6_port = rem6.port;
		}
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */
	} else {
diffPorts:
		tcp_sk(subsk)->path_index = mpcb->next_unused_pi++;
	}

	/* Point it to the same struct socket and wq as the master */
	sk_set_socket(subsk, mpcb->master_sk->sk_socket);
	subsk->sk_wq = mpcb->master_sk->sk_wq;

	mptcp_add_sock(mpcb, tcp_sk(subsk));
}

/**
 * React on IPv4+IPv6-addr add/rem-events
 */
int mptcp_pm_addr_event_handler(unsigned long event, void *ptr, int family)
{
	struct multipath_pcb *mpcb;
	int i;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN))
		return NOTIFY_DONE;

	/* Now we iterate over the mpcb's */
	read_lock_bh(&tk_hash_lock);

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		list_for_each_entry(mpcb, &tk_hashtable[i], collide_tk) {
			if (!tcp_sk(mpcb->master_sk)->mpc ||
			    mpcb->infinite_mapping)
				continue;

			bh_lock_sock(mpcb->master_sk);

			if (family == AF_INET)
				mptcp_pm_addr4_event_handler((struct in_ifaddr *)ptr, event, mpcb);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			else
				mptcp_pm_addr6_event_handler((struct inet6_ifaddr *)ptr, event, mpcb);
#endif

			bh_unlock_sock(mpcb->master_sk);
		}
	}
	read_unlock_bh(&tk_hash_lock);
	return NOTIFY_DONE;
}

/*
 *	Output /proc/net/mptcp_pm
 */
static int mptcp_pm_seq_show(struct seq_file *seq, void *v)
{
	struct multipath_pcb *mpcb;
	int i;

	seq_puts(seq, "Multipath TCP (path manager):");
	seq_putc(seq, '\n');

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		read_lock_bh(&tk_hash_lock);
		list_for_each_entry(mpcb, &tk_hashtable[i], collide_tk) {
			seq_printf(seq, "[%d] %d (%d): %d",
					mpcb->mptcp_loc_token,
					mpcb->num_addr4, mpcb->pa4_size,
					mpcb->cnt_subflows);
			seq_putc(seq, '\n');
		}
		read_unlock_bh(&tk_hash_lock);
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

static __net_init int mptcp_pm_proc_init_net(struct net *net)
{
	if (!proc_net_fops_create(net, "mptcp_pm", S_IRUGO, &mptcp_pm_seq_fops))
		return -ENOMEM;

	return 0;
}

static __net_exit void mptcp_pm_proc_exit_net(struct net *net)
{
	proc_net_remove(net, "mptcp_pm");
}

static __net_initdata struct pernet_operations mptcp_pm_proc_ops = {
	.init = mptcp_pm_proc_init_net,
	.exit = mptcp_pm_proc_exit_net,
};

/* General initialization of MPTCP_PM
 */
static int __init mptcp_pm_init(void)
{
	int i;
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&tk_hashtable[i]);
		INIT_LIST_HEAD(&mptcp_reqsk_htb[i]);
	}

	rwlock_init(&tk_hash_lock);
	spin_lock_init(&mptcp_reqsk_hlock);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	mptcp_pm_v6_init();
#endif
	mptcp_pm_v4_init();

	return register_pernet_subsys(&mptcp_pm_proc_ops);
}

module_init(mptcp_pm_init);

MODULE_LICENSE("GPL");
