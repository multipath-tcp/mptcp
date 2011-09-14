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

/*
 * Used to wait for DAD to finish. If rtr_solicit_delay is set, we use it
 * instead
 */
#define MPTCP_IPV6_DEFAULT_DAD_WAIT (HZ/10)

/* TODO: make this part of the IPv6 module
 * At the moment this will break if IPv6 is compiled as a module */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
extern int tcp_v6_is_v4_mapped(struct sock *sk);
extern struct proto mptcpsubv6_prot;
#else
#define tcp_v6_is_v4_mapped(sk) (0)
#endif

int mptcp_v6_add_raddress(struct multipath_options *mopt, struct in6_addr *addr,
			__be16 port, u8 id);
int mptcp_v6_do_rcv(struct sock *meta_sk, struct sk_buff *skb);
struct path6 *mptcp_v6_find_path(struct mptcp_loc6 *loc, struct mptcp_loc6 *rem,
				 struct multipath_pcb *mpcb);
struct path6 *mptcp_get_path6(struct multipath_pcb *mpcb, int path_index);
struct request_sock *mptcp_v6_search_req(const __be16 rport,
					const struct in6_addr *raddr,
					const struct in6_addr *laddr);
int mptcp_v6_send_synack(struct sock *meta_sk, struct request_sock *req);
void mptcp_v6_update_patharray(struct multipath_pcb *mpcb);
void mptcp_pm_addr6_event_handler(struct inet6_ifaddr *ifa, unsigned long event,
		struct multipath_pcb *mpcb);
void mptcp_pm_v6_init(void);

#endif /* _MPTCP_V6_H */
