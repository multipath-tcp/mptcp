/*
 *	MPTCP implementation
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
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

#ifndef _MPTCP_V6_H
#define _MPTCP_V6_H

#include <linux/in6.h>
#include <net/if_inet6.h>

#include <net/mptcp.h>
#include <net/mptcp_pm.h>

extern struct request_sock_ops mptcp6_request_sock_ops;
extern struct proto mptcpv6_prot;

struct mptcp6_request_sock {
	struct mptcp_request_sock	mptcp6rsk_tcp;
	struct inet6_request_sock	mptcp6rsk_inet6;
};

#ifdef CONFIG_MPTCP

/*
 * Used to wait for DAD to finish. If rtr_solicit_delay is set, we use it
 * instead
 */
#define MPTCP_IPV6_DEFAULT_DAD_WAIT (HZ/10)

int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb);
int mptcp_v6_rem_raddress(struct multipath_options *mopt, u8 id);
int mptcp_v6_add_raddress(struct multipath_options *mopt,
			  const struct in6_addr *addr, __be16 port, u8 id);
void mptcp_v6_set_init_addr_bit(struct mptcp_cb *mpcb,
				const struct in6_addr *daddr);
struct sock *mptcp_v6_search_req(const __be16 rport, const struct in6_addr *raddr,
				 const struct in6_addr *laddr, const struct net *net);
int mptcp_init6_subsockets(struct sock *meta_sk, const struct mptcp_loc6 *loc,
			   struct mptcp_rem6 *rem);
void mptcp_pm_addr6_event_handler(struct inet6_ifaddr *ifa, unsigned long event,
				  struct mptcp_cb *mpcb);
int mptcp_pm_v6_init(void);
void mptcp_pm_v6_undo(void);
void mptcp_v6_send_add_addr(int loc_id, struct mptcp_cb *mpcb);
struct sock *mptcp_v6v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst);

#else /* CONFIG_MPTCP */

static inline int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	return 0;
}

#endif /* CONFIG_MPTCP */

#endif /* _MPTCP_V6_H */
