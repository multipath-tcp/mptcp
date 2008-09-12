/*
 *	Linux SHIM6 implementation
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : October 2007
 *
 *      TODO : - add icmpv6 support for messages to transmit to upper layers.
 *               for now, icmpv6 messages never travel across the shim layer.
 *             - Add support for context recovery
 *             - Take TCP states into account for garbage collection
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License 
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#ifndef _NET_SHIM6_H
#define _NET_SHIM6_H


#include <linux/ipv6.h>


#include <net/flow.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/shim6.h>
#include <net/reap.h>
#include <net/shim6_types.h>
#include <net/xfrm.h>
#include <linux/in6.h>

/*Macro for activation/deactivation of debug messages*/

#undef PDEBUG
#ifdef CONFIG_IPV6_SHIM6_DEBUG
# define PDEBUG(fmt,args...) printk( KERN_DEBUG __FILE__ ": " fmt,##args)
#else
# define PDEBUG(fmt,args...)
#endif


#define MAX_SHIM6_HEADER (24+sizeof(struct ipv6hdr)+MAX_HEADER)


struct shim6hdr_pld 
{
	__u8      nexthdr;
	__u8      hdrlen;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8      ct_1:7,		  
                  P:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8      P:1,
		  ct_1:7;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8      ct_2;
	__u32     ct_3;
};


/*This function is to be called for every other packet (when we are sure that 
  we will not find the shim6 header in a further extension, that is, when every
  extension (mentioned in the draft as being possibly located before shim6)
  has been parsed*/
void shim6_input_std(struct sk_buff* skb);

/* Global locators table management
 */
void shim6_add_glob_locator(struct inet6_ifaddr* loc);
void shim6_del_glob_locator(struct inet6_ifaddr* loc);


/*This function is the one to pass to kref_put
  It should NEVER be run directly*/
void shim6_ctx_release(struct kref* kref);


/* This is a wrapper to allow hiding an implementation 
 * specific lookup method.
 * This function increments a refcnt. For this reason, we MUST
 * call loc_l_put when we have finished with this address.
 */

#define lookup_loc_l(addr) (shim6_loc_l*)ipv6_get_ifaddr(addr,NULL,0)
#define loc_l_put(loc_l) in6_ifa_put((struct inet6_ifaddr*)loc_l)
#define loc_l_hold(loc_l) in6_ifa_hold((struct inet6_ifaddr*)loc_l)
#define refcnt(loc_l) atomic_read(&((struct inet6_ifaddr*)loc_l)->refcnt)

/*Input function for shim6 packets that do not have the ext header*/
void shim6_input_std(struct sk_buff* skb);


int shim6_xmit(struct sk_buff* skb, struct flowi* fl);

/*Reap functions not defined in reap.h*/

extern int reap_input(struct shim6hdr_ctl* ctl, struct reap_ctx* rctx);

/* Allocates an skb for a shim6/reap control message and pushes the exact 
 * necessary space for the message and options (according to msg_len and
 * opt_len), with skb->transport_header pointing to the beginning of the 
 * space allocated
 * for the message. The common part (struct shim6hdr_ctl) of the message is
 * is initialized, according to lengths and message type. 
 *
 * Only the csum field in the struct shim6hdr_ctl is not initialized since
 * it can only be computed after having filled all fields.
 *
 * -@msg_len is the length of the message (example : sizeof(struct reaphdr_ka))
 * -@opt_len is the the sum of all lengths for each option. 
 *           (computed using the TOTAL_LENGTH() macro for each
 *            option). This is zero if no option is used.
 * -@type    is the message type, ex. REAP_TYPE_KEEPALIVE
 * -@skbp    the address of the skb pointer to be allocated.
 *           
 *
 * returns a negative error code in case of failure (currently only -ENOMEM)
 *         0 in case of success.
 */

static inline int shim6_alloc_skb(int msg_len, int opt_len, int type,
				  struct sk_buff** skbp)
{
	struct shim6hdr_ctl* common;
	struct sk_buff* skb;

	*skbp = skb = alloc_skb(MAX_SHIM6_HEADER+opt_len, 
				GFP_ATOMIC);
	if (!skb) {
		printk(KERN_ERR "shim6_alloc_skb : no buffer available\n");
		return -ENOMEM;
	}
	
	
	skb_reserve(skb,MAX_SHIM6_HEADER+opt_len);
	skb->transport_header = skb_push(skb,msg_len+opt_len);
	common=(struct shim6hdr_ctl*) skb_transport_header(skb);
	
	memset(common, 0, sizeof(struct shim6hdr_ctl));
	common->nexthdr=NEXTHDR_NONE;
	common->hdrlen=(msg_len+opt_len-8)>>3;
	common->P=SHIM6_MSG_CONTROL;
	common->type=type;
	return 0;
}


/*Adds/remove a locator from the global locator list in the daemon*/
void shim6_new_daemon_loc(struct in6_addr* addr, int ifidx);
void shim6_del_daemon_loc(struct in6_addr* addr, int ifidx);

/*Filter for shim6 messages to be used by raw sockets, this separates
  control and data messages*/
extern int shim6_filter(struct sock *sk, struct sk_buff *skb);

/*Modified version of xfrm6_input_addr (include/net/xfrm.h)
  That does the xfrm lookup based on the shim6 context tag*/
extern int shim6_xfrm_input_ct(struct sk_buff *skb, __u64 ct);

/*Modified version of xfrm6_input_addr (net/ipv6/xfrm6_input.c)
  That does the xfrm lookup based on saddr=ulid_peer, daddr=ulid_local
  Unfortunately we cannot use xfrm6_input_addr here because the function must
  be aware of the fact that xany is used as the hash key for daddr, which is
  needed by the spi lookup (where daddr is part of the key, thus need to be 
  xany)*/
int shim6_xfrm_input_ulid(struct sk_buff *skb,  xfrm_address_t *daddr, xfrm_address_t *saddr);

static inline int is_shim6_inbound(struct xfrm_state* x)
{
	return (x->id.proto==IPPROTO_SHIM6 && x->shim6 &&
		(x->shim6->flags & SHIM6_DATA_INBOUND));
}

#endif /* _NET_SHIM6_H */
