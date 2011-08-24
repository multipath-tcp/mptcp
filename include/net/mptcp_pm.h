/*
 *	MPTCP PM implementation
 *
 *	Authors:
 *      Sébastien Barré           <sebastien.barre@uclouvain.be>
 *
 *      date : March 09
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _MPTCP_PM_H
#define _MPTCP_PM_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock_types.h>
#include <linux/tcp_options.h>
#include <linux/types.h>

#include <net/request_sock.h>
#include <net/sock.h>

#define MPTCP_MAX_ADDR 12	/* Max number of local or remote addresses we
				 * can store.
				 */

struct multipath_pcb;
struct multipath_options;

#ifdef CONFIG_MPTCP_PM

#define MPTCP_HASH_SIZE                16

/* This second hashtable is needed to retrieve request socks
 * created as a result of a join request. While the SYN contains
 * the token, the final ack does not, so we need a separate hashtable
 * to retrieve the mpcb.
 */
extern struct list_head mptcp_reqsk_htb[MPTCP_HASH_SIZE];
extern spinlock_t mptcp_reqsk_hlock;	/* hashtable protection */

/* Functions and structures defined elsewhere but needed in mptcp_pm.c */
struct tcp_out_options;
struct tcp_sock;
extern void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
		struct tcp_out_options *opts, struct sk_buff *skb);
extern void __tcp_v4_send_check(struct sk_buff *skb,
		__be32 saddr, __be32 daddr);
extern struct ip_options *tcp_v4_save_options(struct sock *sk,
		struct sk_buff *skb);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
extern void	__tcp_v6_send_check(struct sk_buff *skb, struct in6_addr *saddr,
		struct in6_addr *daddr);
extern int tcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb);
#endif

struct mptcp_loc4 {
	u8		id;
	struct in_addr	addr;
	__be16		port;
};

struct mptcp_loc6 {
	u8		id;
	struct in6_addr	addr;
	__be16		port;
};

struct path4 {
	struct sockaddr_in	loc; /* local address */
	u8			loc_id;
	struct sockaddr_in	rem; /* remote address */
	u8			rem_id;
	int			path_index;
};

struct path6 {
	struct sockaddr_in6	loc; /* local address */
	u8			loc_id;
	struct sockaddr_in6	rem; /* remote address */
	u8			rem_id;
	int			path_index;
};

struct mp_join *mptcp_find_join(struct sk_buff *skb);
u8 mptcp_get_loc_addrid(struct multipath_pcb *mpcb, struct sock *sk);
void mptcp_hash_insert(struct multipath_pcb *mpcb, u32 token);
void mptcp_hash_remove(struct multipath_pcb *mpcb);
void mptcp_hash_request_remove(struct request_sock *req);
struct multipath_pcb *mptcp_hash_find(u32 token);
int mptcp_lookup_join(struct sk_buff *skb);
struct sk_buff *mptcp_make_synack(struct sock *master_sk,
					struct dst_entry *dst,
					struct request_sock *req);
int mptcp_find_token(u32 token);
void mptcp_pm_release(struct multipath_pcb *mpcb);
struct dst_entry *mptcp_route_req(const struct request_sock *req);
void mptcp_send_updatenotif(struct multipath_pcb *mpcb);
void mptcp_set_addresses(struct multipath_pcb *mpcb);
void mptcp_subflow_attach(struct multipath_pcb *mpcb, struct sock *subsk);
int mptcp_syn_recv_sock(struct sk_buff *skb);
void mptcp_update_patharray(struct multipath_pcb *mpcb);
void __mptcp_update_patharray_ports(struct multipath_pcb *mpcb);

#else /* CONFIG_MPTCP_PM */

#define mptcp_tp_recv_token(__tp) (0)

static inline void mptcp_update_patharray(struct multipath_pcb *mpcb)
{
}

static inline void mptcp_hash_insert(struct multipath_pcb *mpcb, u32 token)
{
}

static inline void mptcp_hash_remove(struct multipath_pcb *mpcb)
{
}

static inline void mptcp_hash_request_remove(struct request_sock *req)
{
}

static inline struct multipath_pcb *mptcp_hash_find(u32 token)
{
	return NULL;
}

static inline void mptcp_set_addresses(struct multipath_pcb *mpcb)
{
}

static inline struct in_addr *mptcp_get_loc_addr4(struct multipath_pcb *mpcb,
		int path_index)
{
	return NULL;
}

static inline u8 mptcp_get_loc_addrid(struct multipath_pcb *mpcb,
		struct sock *sk)
{
	return 0;
}

static inline int mptcp_lookup_join(struct sk_buff *skb)
{
	return 0;
}

static inline int mptcp_syn_recv_sock(struct sk_buff *skb)
{
	return 0;
}

static inline void mptcp_pm_release(struct multipath_pcb *mpcb)
{
}


static inline void mptcp_send_updatenotif(struct multipath_pcb *mpcb)
{
}

#if (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	return 0;
}

static inline int mptcp_v6_send_synack(struct sock *meta_sk,
		struct request_sock *req)
{
	return 0;
}
#endif /* (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)) */

#endif /* CONFIG_MPTCP_PM */

#endif /*_MPTCP_PM_H*/
