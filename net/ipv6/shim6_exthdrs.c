/*
 *	Shim6 layer implementation
 *
 *      Adds a new handler to the ones defined in exthdrs.c
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Based on draft-ietf-shim6-proto-10
 *
 *      date : Feb 08
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/shim6.h>
#include <net/protocol.h>

/********************************
  Shim6 header.
 ********************************/

static int ipv6_shim6_rcv(struct sk_buff *skb)
{
	struct inet6_skb_parm *opt = IP6CB(skb);
	/*We only use the P and ct fields of the messages, which are common
	  to keepalive and probe*/
	struct reaphdr_ka *hdr_ka;
	struct shim6hdr_pld *hdr_pld;
	__u64 ct;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + 8) ||
	    !pskb_may_pull(skb, (skb_transport_offset(skb) +
				 ((skb_transport_header(skb)[1] + 1) << 3)))) {
		
		IP6_INC_STATS_BH(ip6_dst_idev(skb->dst),
				 IPSTATS_MIB_INHDRERRORS);
		kfree_skb(skb);
		return -1;
	}
	
	opt->lastopt = opt->shim6 = skb_network_header_len(skb);
	
	hdr_ka=(struct reaphdr_ka *) skb_transport_header(skb);
	hdr_pld=(struct shim6hdr_pld *) skb_transport_header(skb);
	
	if (hdr_ka->common.P==SHIM6_MSG_CONTROL) {
		/*Only those messages are used by the kernel*/
		if (hdr_ka->common.type!=SHIM6_TYPE_KEEPALIVE &&
		    hdr_ka->common.type!=SHIM6_TYPE_PROBE) {
			kfree_skb(skb);
			return -1;
			
		}
		if (unlikely(ip_compute_csum(
				     (unsigned char*)hdr_ka,
				     (hdr_ka->common.hdrlen+1)*8) != 0 )) {
			IP6_INC_STATS_BH(ip6_dst_idev(skb->dst),
					 IPSTATS_MIB_INHDRERRORS);
			kfree_skb(skb);
			return -1;
		}
		get_ct(&ct,hdr_ka->ct_1,hdr_ka->ct_2,hdr_ka->ct_3);
	}
	else get_ct(&ct,hdr_pld->ct_1,hdr_pld->ct_2,hdr_pld->ct_3);
	/*This will find the xfrm/shim6 state and call shim6_input*/
	if (shim6_xfrm_input_ct(skb,ct) <0 ) {
		IP6_INC_STATS_BH(ip6_dst_idev(skb->dst),
				 IPSTATS_MIB_INADDRERRORS);
		kfree_skb(skb);
		return -1;		
	}
	
	skb->transport_header += (skb_transport_header(skb)[1] + 1) << 3;
	opt->nhoff = opt->shim6;
	return 1;
}

static struct inet6_protocol shim6_protocol = {
	.handler	=	ipv6_shim6_rcv,
	.flags		=	INET6_PROTO_NOPOLICY,
};


void __init ipv6_shim6_init(void)
{
	if (inet6_add_protocol(&shim6_protocol, IPPROTO_SHIM6) < 0)
		printk(KERN_ERR 
		       "ipv6_shim6_init: Could not register protocol\n");
}
