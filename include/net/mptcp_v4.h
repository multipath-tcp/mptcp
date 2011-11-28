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

#ifndef MPTCP_V4_H_
#define MPTCP_V4_H_


#include <linux/in.h>
#include <linux/skbuff.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/request_sock.h>
#include <net/sock.h>

#ifdef CONFIG_MPTCP

int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb);
struct mptcp_path4 *mptcp_v4_find_path(struct mptcp_loc4 *loc, struct mptcp_loc4 *rem,
				 struct multipath_pcb *mpcb);
struct mptcp_path4 *mptcp_v4_get_path(struct multipath_pcb *mpcb, int path_index);
int mptcp_v4_add_raddress(struct multipath_options *mopt, struct in_addr *addr,
			__be16 port, u8 id);
struct request_sock *mptcp_v4_search_req(const __be16 rport,
					const __be32 raddr,
					const __be32 laddr);
int mptcp_v4_send_synack(struct sock *meta_sk,
			struct request_sock *req,
			struct request_values *rvp);
void mptcp_v4_update_patharray(struct multipath_pcb *mpcb);
void mptcp_pm_addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
		struct multipath_pcb *mpcb);
void mptcp_pm_v4_init(void);

#else

static inline int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	return 0;
}

static inline struct mptcp_path4 *mptcp_v4_get_path(struct multipath_pcb *mpcb,
		int path_index)
{
	return NULL;
}

static inline int mptcp_v4_add_raddress(struct multipath_options *mopt,
		struct in_addr *addr, __be16 port, u8 id)
{
	return 0;
}

struct request_sock *mptcp_v4_search_req(const __be16 rport,
					const __be32 raddr,
					const __be32 laddr)
{
	return NULL;
}

static inline int mptcp_v4_send_synack(struct sock *meta_sk,
			struct request_sock *req,
			struct request_values *rvp)
{
	return 0;
}

static inline void mptcp_v4_update_patharray(struct multipath_pcb *mpcb)
{
}

#endif /* CONFIG_MPTCP */

#endif /* MPTCP_V4_H_ */
