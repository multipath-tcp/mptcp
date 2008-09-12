/*
 *	Shim6 layer implementation
 *
 *      Listens for IPv6 packets, in order to start a shim6 negotiation
 *      when some number of packets have been exchanged.
 *
 *
 *      TO DISCUSS : Why not put this code as a patch to xfrm_lookup ?  we
 *      would have access on the decision to use IPsec or MIPv6 or something
 *      else. Above all, we would have access to the address used in case of
 *      IPsec tunnelling.
 *
 *      Also, the current approach supposes to skip the hop by hop header
 *      if any to find if there is an ICMP message below (in which case
 *      the packet is not taken into account).
 *
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Based on draft-ietf-shim6-proto-09
 *
 *      date : March 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netfilter_ipv6.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/shim6_netlink.h>
#include <linux/jhash.h>

#include <net/shim6.h>
#include <net/addrconf.h>

#define PKT_CNT_TIMEOUT 30*HZ
#define FLOW_SIZE_TRIGGER 2048 /*2KB*/
#define FLOW_TIME_TRIGGER 60*HZ /*1 minute*/

#define DNS_PORT 53

/*Number of packets exchanged before a shim6 negotiation is started*/
int nb_pkts_trigger = 1;  

/*Locks definition*/

static spinlock_t new_ctx_lock; /*for access from soft irq*/
static rwlock_t shim6_hash_lock; /*hashtable protection*/


#define SHIM6_HASH_SIZE                16
struct list_head ulid_hashtable[SHIM6_HASH_SIZE];

#define hash_ulid(ulid_peer) \
jhash(ulid_peer,sizeof(struct in6_addr),0)%SHIM6_HASH_SIZE

/*Small context used to count packets and trigger a context establishment*/
struct shim6_ctx_count {
	/*Collision resolution for the ulid hashtable*/
	struct list_head    collide_ulid;
	struct in6_addr     ulid_peer;
	struct in6_addr     ulid_local;
	int                 ifidx;
	struct timer_list   timer; /*Timer for deleting the entry*/
	int                 in_pkts;
	int                 out_pkts;
	int                 triggered:1; /*1 if the trigger message has 
					   been sent to the daemon*/
	unsigned long       timestamp; /*values of jiffies when creating the 
					 entry*/
	int                 bytes; /*Total number of bytes seen during the 
				     exchange*/
	spinlock_t          lock;
	struct kref         kref;
};


static void ctxc_release(struct kref* kref) {
	struct shim6_ctx_count* ctxc;
	ctxc=container_of(kref,struct shim6_ctx_count,kref);
	kfree(ctxc);
}

/*
 * Returns the context if it exists, else NULL
 * If a context is found, the reference count is incremented.
 * For this reason, anybody who calls this function
 * MUST do a kref_put() when it no longer needs the reference
 * to the shim6_ctx.
 *
 * if ulid_local is ::, we return the first context, if any, with 
 * matching ulid_peer, and any ulid_local
 */
static struct shim6_ctx_count* shim6_lookup_ulid(struct in6_addr* ulid_peer,
						 struct in6_addr* ulid_local) 
{
	struct shim6_ctx_count* ctxc;
	int ulid_hash=hash_ulid(ulid_peer);
	
	/*lookup*/
	read_lock_bh(&shim6_hash_lock);
	list_for_each_entry(ctxc,&ulid_hashtable[ulid_hash],
			    collide_ulid) {
		if ((ipv6_addr_any(ulid_local) ||
		     ipv6_addr_equal(&ctxc->ulid_local,ulid_local)) &&
		    ipv6_addr_equal(&ctxc->ulid_peer,ulid_peer)) {
			kref_get(&ctxc->kref);
			read_unlock_bh(&shim6_hash_lock);
			return ctxc;
		}
	}
	read_unlock_bh(&shim6_hash_lock);
	return NULL;
}


static void shim6_register_ctx_ulid(struct shim6_ctx_count* ctxc)
{
	int ulid_hash=hash_ulid(&ctxc->ulid_peer);
	write_lock_bh(&shim6_hash_lock); 
	list_add(&ctxc->collide_ulid,
		 &ulid_hashtable[ulid_hash]);
	write_unlock_bh(&shim6_hash_lock);
}

static void shim6_unregister_ctx_ulid(struct shim6_ctx_count* ctxc) 
{
	write_lock_bh(&shim6_hash_lock); 
	list_del(&ctxc->collide_ulid);
	write_unlock_bh(&shim6_hash_lock);
}

static void entry_timeout(unsigned long data)
{
	struct shim6_ctx_count* ctxc=(struct shim6_ctx_count*) data;

	shim6_unregister_ctx_ulid(ctxc);
	kref_put(&ctxc->kref,ctxc_release);
}


/*This sends a netlink message to the daemon, to ask a new context
 *establishment for context @ctxc
 *
 * Format for the message :
 *  --------------------------------------------------------------
 * |local ulid (128 bits) | peer ulid (128 bits) | ifidx (32bits) |
 *  --------------------------------------------------------------
 */
static int shim6_trigger(struct shim6_ctx_count* ctxc)
{
	int pld_len = 2*sizeof(struct in6_addr)+sizeof(int);
	struct in6_addr* pld;
	int err;
	struct sk_buff* skb;
	int* ifidx;

	PDEBUG("Entering shim6_trigger\n");

	if (!(skb=shim6_alloc_netlink_skb(pld_len,SHIM6_NL_NEW_CTX,
					  GFP_ATOMIC)))
		return -1;
	pld=NLMSG_DATA((struct nlmsghdr*)skb->data);
	ipv6_addr_copy(pld++,&ctxc->ulid_local);
	ipv6_addr_copy(pld++,&ctxc->ulid_peer);
	ifidx=(int*)pld;
	*ifidx=ctxc->ifidx;
	
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC))) {
		printk(KERN_INFO "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", __FUNCTION__,err);
		return -1;
	}
	
	return 0;
}


/*Returns 1 if the packet must be taken into account,
 * Else 0.
 *
 * Are not taken into account as negotiation triggers :
 *    - ICMP packets
 *    - Multicast packets
 *    - Shim6 control packets
 */
static int check_packet(struct sk_buff* skb)
{
	struct ipv6hdr* nh=ipv6_hdr(skb);
	u8 nexthdr=nh->nexthdr;
	int offset=skb_network_offset(skb); /*Beginning of IPv6 hdr*/	
	
	offset+=sizeof(struct ipv6hdr); /*Beginning of first option*/
	
	if (nexthdr==IPPROTO_SHIM6) return 0;
	
	/* Do not take into account ICMP packets*/
	ipv6_skip_exthdr(skb,offset,&nexthdr); /*Skip any extension header*/
	if (nexthdr==IPPROTO_ICMPV6) return 0;
	
	/*Do not take into account multicast packets*/
	if (ipv6_addr_is_multicast(&nh->daddr))
		return 0;
	
	return 1;
}

/*Heuristic for starting a context establishment
  Returns 1 if we must trigger an establishment, else 0*/
static int check_trigger(struct shim6_ctx_count* ctxc)
{
	if (!ctxc->triggered &&
	    (ctxc->bytes >= FLOW_SIZE_TRIGGER ||
	     jiffies-ctxc->timestamp >= FLOW_TIME_TRIGGER)) {
		PDEBUG("trigger ctx establishment :"
		       "bytes=%d, time=%ld seconds\n",ctxc->bytes,
		       (jiffies-ctxc->timestamp)/HZ);
		ctxc->triggered=1;
		return 1;
	}
	return 0;
}

/*TODO : Before to do a ulid lookup, search for shim6 ext header
  and make a ct lookup if the ext header is present*/
static unsigned int shim6list_local_in(unsigned int hooknum,
				       struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out,
				       int (*okfn)(struct sk_buff *))
{
	struct shim6_ctx_count* ctxc;
	struct ipv6hdr* nh=ipv6_hdr(skb);
	int trigger=0; /*1 if we need to trigger a ctx establishment*/

	if (!check_packet(skb)) return NF_ACCEPT;

	ctxc=shim6_lookup_ulid(&nh->saddr,&nh->daddr);
	if (!ctxc) return NF_ACCEPT;

	/*Restart timer*/
	mod_timer(&ctxc->timer,jiffies+PKT_CNT_TIMEOUT);
		
	spin_lock(&ctxc->lock);
	ctxc->in_pkts++;
	ctxc->bytes+=skb->len;
	trigger=check_trigger(ctxc);
	spin_unlock(&ctxc->lock);

	
	if (trigger) shim6_trigger(ctxc);

	kref_put(&ctxc->kref,ctxc_release);
	return NF_ACCEPT;
}

static unsigned int shim6list_local_out(unsigned int hooknum,
					struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *))
{
	struct shim6_ctx_count* ctxc; 
	struct ipv6hdr* nh=ipv6_hdr(skb);
	int trigger=0; /*1 if we need to trigger a ctx establishment*/
	
	if (!check_packet(skb)) return NF_ACCEPT;

	/*Lookup and creation must be atomic because several packets
	  (from different applications)
	  may trigger a creation in the same time*/
	spin_lock(&new_ctx_lock);
	ctxc=shim6_lookup_ulid(&nh->daddr,&nh->saddr);
	if (!ctxc) { /*Then create it*/
		ctxc=kmalloc(sizeof(struct shim6_ctx_count), GFP_ATOMIC);
		if (!ctxc) {
			printk(KERN_ERR
			       "shim6list_local_out : Not enough memory\n");
			spin_unlock(&new_ctx_lock);
			return NF_ACCEPT;
		}
		kref_init(&ctxc->kref);
		ipv6_addr_copy(&ctxc->ulid_local,&nh->saddr);
		ipv6_addr_copy(&ctxc->ulid_peer,&nh->daddr);
		ctxc->ifidx=out->ifindex;
		init_timer(&ctxc->timer);
		ctxc->timer.data=(unsigned long)ctxc;
		ctxc->timer.function=entry_timeout;
		ctxc->timer.expires=jiffies+PKT_CNT_TIMEOUT;
		add_timer(&ctxc->timer);
		ctxc->in_pkts=0;
		ctxc->out_pkts=1;
		ctxc->bytes=skb->len;
		ctxc->timestamp=jiffies;
		spin_lock_init(&ctxc->lock);
		
		trigger=check_trigger(ctxc);
      		shim6_register_ctx_ulid(ctxc);
		kref_get(&ctxc->kref);
		spin_unlock(&new_ctx_lock);		
	}
	else { /*A context was found */
		spin_unlock(&new_ctx_lock);
		/*Restart timer*/
		mod_timer(&ctxc->timer,jiffies+PKT_CNT_TIMEOUT);
		/*Update pkt count*/
		spin_lock_bh(&ctxc->lock); /*must be _bh, to avoid deadlock
					     with shim6list_local_in*/
		ctxc->out_pkts++;
		ctxc->bytes+=skb->len;
		trigger=check_trigger(ctxc);
		spin_unlock_bh(&ctxc->lock);
	}
	
	if (trigger) {
		PDEBUG("context creation triggered by pkt with nh %d\n",
		       nh->nexthdr);
		shim6_trigger(ctxc);
	}
	kref_put(&ctxc->kref,ctxc_release);			
	return NF_ACCEPT;
}


static struct nf_hook_ops shim6_hook_ops[] = {
	{.hook=shim6list_local_in,
	 .owner=THIS_MODULE,
	 .pf=PF_INET6,
	 .hooknum=NF_IP6_LOCAL_IN,
	 .priority=NF_IP6_PRI_CONNTRACK-1 /*Just before connection tracking*/,
	},
	{.hook=shim6list_local_out,
	 .owner=THIS_MODULE,
	 .pf=PF_INET6,
	 .hooknum=NF_IP6_LOCAL_OUT,
	 .priority=NF_IP6_PRI_CONNTRACK-1 /*Just before connection tracking*/,
	},
};


void __init shim6_listener_init(void) 
{
	int i;
	PDEBUG("Entering %s\n",__FUNCTION__);
	spin_lock_init(&new_ctx_lock);
	rwlock_init(&shim6_hash_lock);
	nf_register_hooks(shim6_hook_ops,2);
	/*hashtable initialization*/
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		INIT_LIST_HEAD(&ulid_hashtable[i]);
	}

}

void __exit shim6_listener_exit(void)
{
	nf_unregister_hooks(shim6_hook_ops,2);
}
