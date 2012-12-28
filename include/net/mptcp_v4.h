/*
 *	MPTCP implementation
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
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

#ifndef MPTCP_V4_H_
#define MPTCP_V4_H_


#include <linux/in.h>
#include <linux/skbuff.h>
#include <net/mptcp.h>
#include <net/mptcp_pm.h>
#include <net/request_sock.h>
#include <net/sock.h>

extern struct request_sock_ops mptcp_request_sock_ops;
extern struct proto mptcp_prot;

#ifdef CONFIG_MPTCP

int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb);
int mptcp_v4_rem_raddress(struct mptcp_cb *mpcb, u8 id);
int mptcp_v4_add_raddress(struct mptcp_cb *mpcb, const struct in_addr *addr,
			  __be16 port, u8 id);
void mptcp_v4_set_init_addr_bit(struct mptcp_cb *mpcb, __be32 daddr);
struct sock *mptcp_v4_search_req(const __be16 rport, const __be32 raddr,
				 const __be32 laddr, const struct net *net);
int mptcp_init4_subsockets(struct sock *meta_sk, const struct mptcp_loc4 *loc,
			   struct mptcp_rem4 *rem);
void mptcp_pm_addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				  struct mptcp_cb *mpcb);
int mptcp_pm_v4_init(void);
void mptcp_pm_v4_undo(void);
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
