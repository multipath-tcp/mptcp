/*
 *	Path Manager implementation - netlink communication with user space.
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *      Support for the Generic Multipath Architecture (GMA).
 *
 *      date : June 2009
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netevent.h>

#include <linux/pm_netlink.h>

struct sock *pmnl_sk;

static void pm_netlink_rcv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int skblen,nlmsglen;
	struct nl_ulid_pair *data;
	struct ulid_pair up;
		
	skblen = skb->len;
	if (skblen < sizeof(*nlh))
		return;
	
	nlh = nlmsg_hdr(skb);
	nlmsglen = nlh->nlmsg_len;
	if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
		return;

	switch(nlh->nlmsg_type) {
	case PM_NL_PATHUPDATE:
		if (nlmsglen!=sizeof(*data)) 
			return;
		data=nlmsg_data(nlh);
		up.local=&data->local;
		up.remote=&data->remote;
		up.path_indices=data->path_indices;
		call_netevent_notifiers(NETEVENT_PATH_UPDATEV6, &up);
		break;
	}       
}



int __init pm_netlink_init(void)
{
	
	printk(KERN_INFO "Initializing PM netlink socket\n");
	
	pmnl_sk = netlink_kernel_create(&init_net,NETLINK_PM, 
					PMNLGRP_MAX, 
					pm_netlink_rcv, NULL,THIS_MODULE);
	if (!pmnl_sk) {
		printk(KERN_ERR "PM: failed to create netlink socket\n");
		return -ENOMEM;
	}
	
	return 0;
}

module_init(pm_netlink_init);
