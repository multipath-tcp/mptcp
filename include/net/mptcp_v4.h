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
int mptcp_v4_send_synack(struct sock *meta_sk, struct request_sock *req,
			 struct request_values *rvp);
int mptcp_v4_rem_raddress(struct multipath_options *mopt, u8 id);
int mptcp_v4_add_raddress(struct multipath_options *mopt,
			  const struct in_addr *addr, __be16 port, u8 id);
void mptcp_v4_set_init_addr_bit(struct mptcp_cb *mpcb, __be32 daddr);
struct request_sock *mptcp_v4_search_req(const __be16 rport,
					 const __be32 raddr,
					 const __be32 laddr);
void mptcp_init4_subsockets(struct mptcp_cb *mpcb,
			    const struct mptcp_loc4 *loc,
			    struct mptcp_rem4 *rem);
void mptcp_pm_addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				  struct mptcp_cb *mpcb);
void mptcp_pm_v4_init(void);
void mptcp_v4_send_add_addr(int loc_id, struct mptcp_cb *mpcb);

#else

static inline int mptcp_v4_do_rcv(const struct sock *meta_sk,
				  const struct sk_buff *skb)
{
	return 0;
}

static inline int mptcp_v4_send_synack(const struct sock *meta_sk,
				       const struct request_sock *req,
				       const struct request_values *rvp)
{
	return 0;
}

#endif /* CONFIG_MPTCP */

#endif /* MPTCP_V4_H_ */
