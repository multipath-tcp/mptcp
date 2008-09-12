/*
 *	Shim6 layer implementation - netlink communication with user space.
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Based on draft-ietf-shim6-proto-08
 *
 *      date : June 2007
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <net/reap.h>
#include <net/shim6.h>
#include <net/netlink.h>

#include <linux/shim6_netlink.h>

struct sock *shim6nl_sk;


/* Allocates an sk_buff for multicast sending to shim6 group
 *
 * - pld_len is the payload length
 * - type is some of the REAP_NL_* or SHIM6_NL_* message types 
 *   (see linux/shim6.h)
 * - GFP is either GFP_ATOMIC or GFP_KERNEL
 *
 * returns NULL in case of failure
 */
struct sk_buff* shim6_alloc_netlink_skb(int pld_len,int type,int gfp)
{
	struct sk_buff* skb;
	int len=NLMSG_SPACE(pld_len);
	skb=alloc_skb(len,gfp);
	if (!skb) {
		printk(KERN_ERR "shim6_alloc_netlink_skb : alloc_skb,"
		       "not enough memory\n");
		goto failure;
	}
	if (!nlmsg_put(skb,0,0,type,
		       pld_len,0)) {
		printk(KERN_ERR "shim6_alloc_netlink_skb : nlmsg_put,"
		       "not enough memory\n");
		goto failure2;
	}

	NETLINK_CB(skb).dst_group = SHIM6NLGRP_DEFAULT;

	return skb;
 failure2:
	kfree_skb(skb);
 failure:
	return NULL;
}


/*Netlink initialization. This may be called ONLY
  by shim6_init (shim6.c) */
int __init shim6_netlink_init(void) 
{

	printk(KERN_INFO "Initializing shim6 netlink socket\n");
	
	shim6nl_sk = netlink_kernel_create(&init_net,NETLINK_SHIM6, 
					   SHIM6NLGRP_MAX, 
					   NULL, NULL,THIS_MODULE);
	if (!shim6nl_sk) {
		printk(KERN_ERR "shim6: failed to create netlink socket\n");
		return -ENOMEM;
	}
	
	return 0;
}
