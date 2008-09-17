/*
 *	Shim6 layer implementation
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

#include <linux/shim6.h>
#include <linux/shim6_netlink.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/in.h>
#include <linux/kref.h>
#include <linux/seq_file.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <asm/semaphore.h>
#include <asm/errno.h>

#include <net/ipv6.h>
#include <net/shim6.h>
#include <net/reap.h>
#include <net/checksum.h>
#include <net/addrconf.h>
#include <net/protocol.h>
#include <net/xfrm.h>
#include <net/transp_v6.h>


int sysctl_shim6_enabled = 0; /*Will be enabled at the end of shim6 init*/

/*Sysctl data*/

#ifdef CONFIG_SYSCTL

static ctl_table shim6_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "enabled",
		.data		= &sysctl_shim6_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ .ctl_name = 0 },
};

static ctl_table shim6_ipv6_table[] = {
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname       = "shim6",
		.maxlen         = 0,
		.mode           = 0555,
		.child          = shim6_table
	},
	{.ctl_name = 0},
};

static ctl_table shim6_net_table[] = {
	{
		.ctl_name	= NET_IPV6,
		.procname	= "ipv6",
		.mode		= 0555,
		.child		= shim6_ipv6_table
	},
        { .ctl_name = 0 }
};

static ctl_table shim6_root_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= shim6_net_table
	},
        { .ctl_name = 0 }
};
#endif


static int shim6_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct reap_ctx* rctx=(struct reap_ctx*) x->data;
	struct inet6_skb_parm *opt = IP6CB(skb);
	struct shim6hdr_ctl* hdr=(struct shim6hdr_ctl*) skb->data;
	struct ipv6hdr* iph=ipv6_hdr(skb);
	
	if (opt->shim6 && hdr->P==SHIM6_MSG_CONTROL)
		return reap_input(hdr,rctx);

#ifndef CONFIG_IPV6_SHIM6_MULTIPATH
	/*If the message is a data message notify the reap module*/
	reap_notify_in(rctx);
#endif

	/*update the use time*/
	x->curlft.use_time = (unsigned long)xtime.tv_sec;
	
	if (!opt->shim6) return 1;

	/*Rewriting the addresses*/
	ipv6_addr_copy(&iph->saddr,&x->shim6->paths[0].remote);
	ipv6_addr_copy(&iph->daddr,&x->shim6->paths[0].local);

	return hdr->nexthdr;
}

/* Here, we are in the situation of an entering packet that is possibly
 * a shim6 packet, possibly not. If it is a shim6 packet (that is, a packet 
 * belonging to an existing shim6 session), then it corresponds to session
 * with ulids=locators (that's why we do not have any shim6 extension)
 * So we'll lookup using the locators, which are in fact the ulids.
 * If no context is found, then nothing is done, the packet can continue
 * to go up.
 */
void shim6_input_std(struct sk_buff* skb) 
{
	struct ipv6hdr* iph=ipv6_hdr(skb);
	if (!sysctl_shim6_enabled) return;

	/*Since the shim6 extension header is not there, we don't know the
	  ct, so we can only access through the special ulid_in lookup
	  function.
	*/
	shim6_xfrm_input_ulid(skb,(xfrm_address_t *)&iph->daddr, 
			      (xfrm_address_t *)&iph->saddr);
}

/* Shim6 Header is inserted, if necessary.
 * IP Header's dst address and src address (ULIDs) are replaced with
 * current dst and src locators.
 */
static int shim6_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct ipv6hdr* iph;
	u8 nexthdr;
	struct shim6hdr_pld* shim6h;
	int path_idx=x->shim6->cur_path_idx;

#ifndef CONFIG_IPV6_SHIM6_MULTIPATH
	struct reap_ctx* rctx=(struct reap_ctx*) x->data;		
	reap_notify_out(rctx);
#endif

	skb_push(skb, -skb_network_offset(skb));
	iph = ipv6_hdr(skb);

	x->curlft.use_time = (unsigned long)xtime.tv_sec;       

	if (!(x->shim6->paths[path_idx].flags & SHIM6_DATA_TRANSLATE)) 
		goto finish;

	/*ok, packet needs translation and shim6 ext header*/
	nexthdr = *skb_mac_header(skb);
	*skb_mac_header(skb) = IPPROTO_SHIM6;
	shim6h = (struct shim6hdr_pld *)skb_transport_header(skb);
	shim6h->nexthdr=nexthdr;
	shim6h->hdrlen = (x->props.header_len >> 3) - 1;
	shim6h->P=SHIM6_MSG_PAYLOAD;
	set_ct(x->shim6->ct,shim6h->ct_1,shim6h->ct_2,shim6h->ct_3);

	/*Rewriting the addresses*/
	ipv6_addr_copy(&iph->saddr,&x->shim6->paths[path_idx].local);
	ipv6_addr_copy(&iph->daddr,&x->shim6->paths[path_idx].remote);

finish:
	return 0;
}


/*TODO : verify that this offset is the correct one.*/
static int shim6_offset(struct xfrm_state *x, struct sk_buff *skb,
			     u8 **nexthdr)
{
	u16 offset = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *exthdr = 
		(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	const unsigned char *nh = skb_network_header(skb);
	unsigned int packet_len = skb->tail - skb->network_header;
	int found_rhdr = 0;

	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset + 1 <= packet_len) {

		switch (**nexthdr) {
		case NEXTHDR_HOP:
			break;
		case NEXTHDR_ROUTING:
			if (offset + 3 <= packet_len) {
				struct ipv6_rt_hdr *rt;
				rt = (struct ipv6_rt_hdr *)(nh + offset);
				if (rt->type != 0)
					return offset;
			}
			found_rhdr = 1;
			break;
		case NEXTHDR_DEST:
			if (ipv6_find_tlv(skb, offset, IPV6_TLV_HAO) >= 0)
				return offset;
			
			if (found_rhdr)
				return offset;
			
			break;
		default:
			return offset;
		}
		
		offset += ipv6_optlen(exthdr);
		*nexthdr = &exthdr->nexthdr;
		exthdr = (struct ipv6_opt_hdr *)(nh + offset);
	}
	
	return offset;
}

/*The shim6 state for the outgoing direction MUST be the first one created.
 * This is to avoid mixing src and dst addresses
 *
 * This function may be called in two case :
 * -> Normal context creation (first outbound, then inbound)
 * -> Context update. In this case it is not necessary to completely initialize
 *    the context, since @x is just a temporary state that must hold the 
 *    data that will be updated next in the existing context 
 *    (by xfrm_state_update)
 *
 **/
static int shim6_init_state(struct xfrm_state *x)
{
	struct reap_ctx* rctx;
	struct xfrm_state* rev_x;

	PDEBUG("Initializing context at address %p\n",x);

	x->data=NULL;
	if ((x->shim6->flags & SHIM6_DATA_INBOUND) && !x->id.spi) {
		printk(KERN_INFO "%s: spi is 0 for inbound ctx\n", 
		       __FUNCTION__);
		return -EINVAL;
	}
	if (!(x->shim6->flags & SHIM6_DATA_INBOUND) && x->id.spi) {
		printk(KERN_INFO "%s: spi is not 0 for outbound ctx: %u\n", 
		       __FUNCTION__, x->id.spi);
		return -EINVAL;
	}
	if (x->props.mode != XFRM_MODE_SHIM6) {
		printk(KERN_INFO "%s: state's mode is not %u: %u\n",
		       __FUNCTION__, XFRM_MODE_SHIM6, x->props.mode);
		return -EINVAL;
	}

	x->props.header_len = sizeof(struct shim6hdr_pld);
	
	/*Trying to find an xfrm state for the reverse direction*/
	if (x->shim6->flags & SHIM6_DATA_INBOUND) {
		rev_x=xfrm_state_lookup_byaddr(
			(xfrm_address_t*)&x->shim6->paths[0].remote,
			(xfrm_address_t*)&x->shim6->paths[0].local,
			IPPROTO_SHIM6,AF_INET6);
		if (!rev_x) {
			printk(KERN_ERR "%s: Trying to create a shim6 inbound"
			       " ctx, but outbound ctx not found\n",
			       __FUNCTION__);
			return -1;
		}

		PDEBUG("reverse context found (0x%p), setting the shim6" 
		       " pointer to it\n",rev_x);
		x->data=rev_x->data;
		
		rctx=(struct reap_ctx*)rev_x->data;
		if (x->shim6->flags & SHIM6_DATA_UPD) {
			/*Upon updates, the REAP state must always be 
			  operational*/
			rctx->state=REAP_OPERATIONAL;
		}
		else {
			kref_get(&rctx->kref);
			memcpy(&rctx->ct_local,&x->shim6->ct,
			       sizeof(x->shim6->ct));
		}
		xfrm_state_put(rev_x);
		PDEBUG("\tkref is now : %d\n",rctx->kref.refcount.counter);
	}
	else if (!(x->shim6->flags & SHIM6_DATA_UPD)) {		
		/*Alloc new memory for the REAP context and initialize it*/
		PDEBUG("Allocating new reap context\n");
		rctx=x->data=kmalloc(sizeof(struct reap_ctx),GFP_KERNEL);
		if (!x->data) {
			printk(KERN_ERR "%s: buffer allocation failed\n",
			       __FUNCTION__);
			return -ENOMEM;
		}
		init_reap_ctx(rctx);
	}
	return 0;
}

static void ctx_release(struct kref* kref) {
	struct reap_ctx* rctx;	
	PDEBUG("Freeing memory for old reap context\n");
	rctx=container_of(kref,struct reap_ctx,kref);
	kfree(rctx);
}

static void shim6_destroy(struct xfrm_state *x)
{	
	struct reap_ctx* rctx=(struct reap_ctx*) x->data;
	if (!rctx) return;
	PDEBUG("Destroying Shim6 context : %p\n",x);
	del_reap_ctx(rctx);
	x->data=NULL;
	kref_put(&rctx->kref,ctx_release);
}

static xfrm_address_t *shim6_local_addr(struct xfrm_state *x, 
					xfrm_address_t *addr)
{
	return (xfrm_address_t*)&x->shim6->paths[x->shim6->cur_path_idx].local;
}

static xfrm_address_t *shim6_remote_addr(struct xfrm_state *x, 
					xfrm_address_t *addr)
{
	return (xfrm_address_t*)&x->shim6->paths[x->shim6->cur_path_idx].remote;
}

static struct xfrm_type shim6_type =
{
	.description	= "SHIM6",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_SHIM6,
	.flags          = XFRM_TYPE_NON_FRAGMENT,
	.init_state	= shim6_init_state,
	.destructor	= shim6_destroy,
	.input		= shim6_input,
	.output		= shim6_output,
	.hdr_offset	= shim6_offset,
	.local_addr     = shim6_local_addr,
	.remote_addr    = shim6_remote_addr,
};


/*General initialization of the shim6 mechanism
 *(this is executed in user context)
 */
static int __init shim6_init(void) 
{
	int err;

	printk("shim6 global initialization...\n");

	/*netlink initialization*/
	if ((err=shim6_netlink_init())<0) goto fail;

	/*Shim6 ext header registration*/
	ipv6_shim6_init();

	/*Now we can make shim6 available*/
	
	sysctl_shim6_enabled=1;

	/*...and allow user to play with (de)activation*/
#ifdef CONFIG_SYSCTL
	register_sysctl_table(shim6_root_table);
#endif

	/*Register the shim6 packet listener*/
	shim6_listener_init();

	/*Register shim6 xfrm type*/
	if (xfrm_register_type(&shim6_type, AF_INET6) < 0) {
		printk(KERN_INFO "%s: can't add xfrm type(shim6)\n", 
		       __FUNCTION__);
		return -EAGAIN;		
	}

	return 0;

 fail:
	return err;
}
module_init(shim6_init);

static void __exit shim6_exit(void)
{
	reap_exit();
	/*shim6 specific still to be completed.*/
	shim6_listener_exit();
	
	if (xfrm_unregister_type(&shim6_type, AF_INET6) < 0)
		printk(KERN_INFO "%s: can't remove xfrm type(shim6)\n", 
		       __FUNCTION__);
}

module_exit(shim6_exit);


/* If @loc is a suitable locator for 
 * use inside shim6, notifies the daemon that it is now available.
 */

void shim6_add_glob_locator(struct inet6_ifaddr* loc) 
{
	/*The loopback address cannot be sent as a locator.*/
	if (ipv6_addr_equal(&loc->addr,&in6addr_loopback)) return;

	/*Loopback addresses are currently not used as locators*/
	if (ipv6_addr_scope(&loc->addr) == IPV6_ADDR_LINKLOCAL) return;
		
	if (unlikely(!loc->idev || !loc->idev->dev)) return;

	shim6_new_daemon_loc(&loc->addr, loc->idev->dev->ifindex);
	return;
}

/*Deletes a shim6 glob locator
 */
void shim6_del_glob_locator(struct inet6_ifaddr* loc)
{
	/*The loopback address cannot be sent as a locator.*/
	if (ipv6_addr_equal(&loc->addr,&in6addr_loopback)) return;

	/*Loopback addresses are currently not used as locators*/
	if (ipv6_addr_scope(&loc->addr) == IPV6_ADDR_LINKLOCAL) return;

	shim6_del_daemon_loc(&loc->addr,loc->idev->dev->ifindex);	
}


/*
 * Announces a new prefix to the shim6d daemon.
 *
 * Format for the message :
 *
 *  ---------------------------------------------------------------
 * |      IPv6 addr. (128 bits)        | interface index (32 bits) |
 *  ---------------------------------------------------------------
 */
void shim6_new_daemon_loc(struct in6_addr* addr, int ifidx)
{
	struct sk_buff* skb;
	int pld_len=sizeof(struct in6_addr)+sizeof(int);
	struct in6_addr* skb_addr;
	int* skb_ifidx;
	int err;
	
	PDEBUG("Entering %s\n",__FUNCTION__);

	if (!(skb=shim6_alloc_netlink_skb(pld_len,SHIM6_NL_NEW_LOC_ADDR,GFP_ATOMIC)))
		return;
	
	skb_addr=NLMSG_DATA((struct nlmsghdr*)skb->data);
	ipv6_addr_copy(skb_addr,addr);
	skb_ifidx=(int*)(skb_addr+1);
	*skb_ifidx=ifidx;
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC)))
		printk(KERN_INFO "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", 
		       __FUNCTION__, err);
}

/*
 * Removes a locator from the global locator list in the shim6d daemon.
 *
 * Format for the message :
 *
 *  ---------------------------------------------------------------
 * |      IPv6 addr. (128 bits)        | interface index (32 bits) |
 *  ---------------------------------------------------------------
 */
void shim6_del_daemon_loc(struct in6_addr* addr, int ifidx)
{
	struct sk_buff* skb;
	int pld_len=sizeof(struct in6_addr)+sizeof(int);
	struct in6_addr* skb_addr;
	int err;
	int* msg_ifidx;
	
	PDEBUG("Entering %s\n",__FUNCTION__);
	
	if (!(skb=shim6_alloc_netlink_skb(pld_len,SHIM6_NL_DEL_LOC_ADDR,
					  GFP_ATOMIC)))
		return;
	
	skb_addr=NLMSG_DATA((struct nlmsghdr*)skb->data);
	msg_ifidx=(int*)(skb_addr+1);
	ipv6_addr_copy(skb_addr,addr);
	*msg_ifidx=ifidx;
	
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC)))
		printk(KERN_INFO "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", 
		       __FUNCTION__, err);
}

static inline void shim6_param_prob(struct sk_buff *skb, int code, int pos)
{
	icmpv6_send(skb, ICMPV6_PARAMPROB, code, pos, skb->dev);
}

int shim6_filter(struct sock *sk, struct sk_buff *skb)
{
	struct shim6hdr_ctl *hdr;
	int type_src,type_dst;
	/*length of IPv6 header*/
	int hdr_len=skb_network_header_len(skb);
	struct ipv6hdr* iph=ipv6_hdr(skb);

	/*Drop malformed packets*/
	if (!pskb_may_pull(skb, (skb_transport_offset(skb)) + 8) ||
	    !pskb_may_pull(skb, (skb_transport_offset(skb) +
				 ((skb_transport_header(skb)[1] + 1) << 3))))
		return -1;

	hdr = (struct shim6hdr_ctl *)skb_transport_header(skb);

	/*Only send Control messages to user space*/
	if (hdr->P==SHIM6_MSG_PAYLOAD) return -1;

	/*Checking if the type is known*/
	if (!hdr->type || 
	    !(hdr->type<SHIM6_TYPE_INIT_MAX ||
	      (hdr->type & 0xBF) < SHIM6_TYPE_COMM_MAX)) {
		shim6_param_prob(skb,ICMPV6_UNK_OPTION,2+hdr_len);
		return -1;
	}

	/*Verifying the checksum (draft v9, section 12.3)*/
	if(ip_compute_csum(hdr,(skb_transport_header(skb)[1] + 1) << 3)) {
		PDEBUG("Recvd shim6 ctrl msg with invalid checksum\n");
		return -1;
	}
	
	/*Verifying src and dst addresses (draft v9, section 12.3)*/
	type_src=ipv6_addr_type(&iph->saddr);
	type_dst=ipv6_addr_type(&iph->daddr);
	if (type_src & IPV6_ADDR_MULTICAST || type_dst & IPV6_ADDR_MULTICAST
	    || type_src==IPV6_ADDR_ANY || type_src==IPV6_ADDR_ANY) {
		PDEBUG("Recvd shim6 ctrl msg with invalid address(es)\n");
		return -1;
	}		
	
	return 0;
}

/*Modified version of xfrm6_input_addr (net/ipv6/xfrm6_input.c)
  That does the xfrm lookup based on the shim6 context tag*/
int shim6_xfrm_input_ct(struct sk_buff *skb, __u64 ct)
{
	struct xfrm_state *x = NULL;
	int nh = 0;

	x = xfrm_state_lookup_byct(ct);
	if (!x) goto drop;

	spin_lock(&x->lock);
	
	if (unlikely(x->km.state != XFRM_STATE_VALID)) {
		spin_unlock(&x->lock);
		xfrm_state_put(x);
		x = NULL;
		goto drop;
	}
	if (xfrm_state_check_expire(x)) {
		spin_unlock(&x->lock);
		xfrm_state_put(x);
		x = NULL;
		goto drop;
	}
	nh = x->type->input(x, skb);
	if (nh <= 0) {
		spin_unlock(&x->lock);
		xfrm_state_put(x);
		x = NULL;
		goto drop;
	}
	
	x->curlft.bytes += skb->len;
	x->curlft.packets++;
	
	spin_unlock(&x->lock);
	
	/* Allocate new secpath or COW existing one. */
	if (!skb->sp || atomic_read(&skb->sp->refcnt) != 1) {
		struct sec_path *sp;
		sp = secpath_dup(skb->sp);
		if (!sp)
			goto drop;
		if (skb->sp)
			secpath_put(skb->sp);
		skb->sp = sp;
	}
	
	if (1 + skb->sp->len > XFRM_MAX_DEPTH)
		goto drop;

	skb->sp->xvec[skb->sp->len] = x;
	skb->sp->len ++;
	
	return 1;
drop:
	if (x)
		xfrm_state_put(x);
	return -1;
}

/*Modified version of xfrm6_input_addr (net/ipv6/xfrm6_input.c)
  That does the xfrm lookup based on saddr=ulid_peer, daddr=ulid_local
  Unfortunately we cannot use xfrm6_input_addr here because the function must
  be aware of the fact that xany is used as the hash key for daddr, which is
  needed by the spi lookup (where daddr is part of the key, thus need to be 
  xany)*/
int shim6_xfrm_input_ulid(struct sk_buff *skb,  xfrm_address_t *daddr, xfrm_address_t *saddr)
{
	struct xfrm_state *x = NULL;
	int nh = 0;

	
	x = xfrm_state_lookup_byulid_in(daddr, saddr);
	if (!x) goto error;

	spin_lock(&x->lock);
	
	if (unlikely(x->km.state != XFRM_STATE_VALID)) {
		spin_unlock(&x->lock);
		xfrm_state_put(x);
		x = NULL;
		goto error;
	}
	if (xfrm_state_check_expire(x)) {
		spin_unlock(&x->lock);
		xfrm_state_put(x);
		x = NULL;
		goto error;
	}
	nh = x->type->input(x, skb);
	if (nh <= 0) {
		spin_unlock(&x->lock);
		xfrm_state_put(x);
		x = NULL;
		goto error;
	}
	
	x->curlft.bytes += skb->len;
	x->curlft.packets++;
	
	spin_unlock(&x->lock);
	
	/* Allocate new secpath or COW existing one. */
	if (!skb->sp || atomic_read(&skb->sp->refcnt) != 1) {
		struct sec_path *sp;
		sp = secpath_dup(skb->sp);
		if (!sp)
			goto error;
		if (skb->sp)
			secpath_put(skb->sp);
		skb->sp = sp;
	}
	
	if (1 + skb->sp->len > XFRM_MAX_DEPTH)
		goto error;

	skb->sp->xvec[skb->sp->len] = x;
	skb->sp->len ++;
	
	return 1;
error:
	if (x)
		xfrm_state_put(x);
	return -1;
}

MODULE_LICENSE("GPL");
