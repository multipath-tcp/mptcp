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
#include <linux/types.h>

#include <net/request_sock.h>
#include <net/sock.h>
#include <net/tcp.h>

#define MPTCP_MAX_ADDR 12	/* Max number of local or remote addresses we
				 * can store.
				 */

struct multipath_pcb;

struct mptcp_loc4 {
	u8		id;
	__be16		port;
	struct in_addr	addr;
};

struct mptcp_loc6 {
	u8		id;
	__be16		port;
	struct in6_addr	addr;
};

#ifdef CONFIG_MPTCP

#define MPTCP_HASH_SIZE                16

/* This second hashtable is needed to retrieve request socks
 * created as a result of a join request. While the SYN contains
 * the token, the final ack does not, so we need a separate hashtable
 * to retrieve the mpcb.
 */
extern struct list_head mptcp_reqsk_htb[MPTCP_HASH_SIZE];
extern spinlock_t mptcp_reqsk_hlock;	/* hashtable protection */

struct mptcp_path4 {
	struct sockaddr_in	loc; /* local address */
	struct sockaddr_in	rem; /* remote address */
	int			path_index;
	u8			loc_id;
	u8			rem_id;
	u8			tried:1;
};

struct mptcp_path6 {
	struct sockaddr_in6	loc; /* local address */
	struct sockaddr_in6	rem; /* remote address */
	int			path_index;
	u8			loc_id;
	u8			rem_id;
	u8			tried:1;
};

struct mp_join *mptcp_find_join(struct sk_buff *skb);
u8 mptcp_get_loc_addrid(struct multipath_pcb *mpcb, struct sock *sk);
void mptcp_hash_insert(struct multipath_pcb *mpcb, u32 token);
void mptcp_hash_remove(struct multipath_pcb *mpcb);
void mptcp_hash_request_remove(struct request_sock *req);
struct multipath_pcb *mptcp_hash_find(u32 token);
int mptcp_lookup_join(struct sk_buff *skb);
int mptcp_find_token(u32 token);
struct dst_entry *mptcp_route_req(const struct request_sock *req,
				  struct sock *meta_sk);
void mptcp_send_updatenotif(struct multipath_pcb *mpcb);
void mptcp_set_addresses(struct multipath_pcb *mpcb);
void mptcp_subflow_attach(struct multipath_pcb *mpcb, struct sock *subsk);
int mptcp_syn_recv_sock(struct sk_buff *skb);
void mptcp_update_patharray(struct multipath_pcb *mpcb);
void __mptcp_update_patharray_ports(struct multipath_pcb *mpcb);
int mptcp_pm_addr_event_handler(unsigned long event, void *ptr, int family);

#else /* CONFIG_MPTCP */

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


static inline void mptcp_send_updatenotif(struct multipath_pcb *mpcb)
{
}

#endif /* CONFIG_MPTCP */

#endif /*_MPTCP_PM_H*/
