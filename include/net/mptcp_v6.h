/*
 *	MPTCP implementation
 *      IPv6-related functions
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      date : June 09
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

#ifdef CONFIG_MPTCP

/*
 * Used to wait for DAD to finish. If rtr_solicit_delay is set, we use it
 * instead
 */
#define MPTCP_IPV6_DEFAULT_DAD_WAIT (HZ/10)

int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb);
int mptcp_v6_send_synack(struct sock *meta_sk, struct request_sock *req);
int mptcp_v6_rem_raddress(struct multipath_options *mopt, u8 id);
int mptcp_v6_add_raddress(struct multipath_options *mopt,
			  const struct in6_addr *addr, __be16 port, u8 id);
void mptcp_v6_set_init_addr_bit(struct multipath_pcb *mpcb,
				const struct in6_addr *daddr);
struct request_sock *mptcp_v6_search_req(const __be16 rport,
					 const struct in6_addr *raddr,
					 const struct in6_addr *laddr);
void mptcp_init6_subsockets(struct multipath_pcb *mpcb,
			    const struct mptcp_loc6 *loc,
			    struct mptcp_rem6 *rem);
void mptcp_pm_addr6_event_handler(struct inet6_ifaddr *ifa, unsigned long event,
				  struct multipath_pcb *mpcb);
void mptcp_pm_v6_init(void);
void mptcp_v6_send_add_addr(int loc_id, struct multipath_pcb *mpcb);

#else /* CONFIG_MPTCP */

static inline int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	return 0;
}
int mptcp_v6_send_synack(struct sock *meta_sk, struct request_sock *req)
{
	return 0;
}

#endif /* CONFIG_MPTCP */

#endif /* _MPTCP_V6_H */
