/*
 *	Linux REAP implementation
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : May 2008
 *
 *      Based on draft-ietf-shim6-failure-detection-11
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <net/reap.h>
#include <net/shim6.h>
#include <net/addrconf.h>
#include <net/netlink.h>


#include <linux/module.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/shim6.h>
#include <linux/shim6_netlink.h>
#include <linux/list.h>

#include <linux/jiffies.h>

/*Various function declarations*/
static void send_handler(unsigned long data);
static void ka_handler(unsigned long data);



/*This stops the ka (conceptual and real) *and* the send timer*/
static void stop_ka_send_timer(struct reap_ctx* rctx) 
{
	rctx->stop_timer=1;
	spin_lock_bh(&rctx->stop_timer_lock);
	del_timer_sync(&rctx->timer);
	rctx->ka_timestamp=0; /*Means that the conceptual timer is also 
				stopped*/
	spin_unlock_bh(&rctx->stop_timer_lock);
}

/*Starts the send timer if it was not yet running
 * If the keepalive timer was running, it is stopped
 *
 * IMPORTANT : The ctx lock cannot be held while calling this function, since
 *             it makes use of it.
 */
inline void send_start(struct reap_ctx* rctx)
{
	int lock_hold;

	spin_lock_bh(&rctx->lock);
/*	if (ctx->dead) goto out;*/
	
	if (rctx->ka_timestamp) { /*Stop keepalive timer if necessary*/
		del_timer(&rctx->timer);
		rctx->ka_timestamp=0;
	}

	if (!timer_pending(&rctx->timer)) {
		rctx->timer.expires=jiffies+rctx->send_timeout*HZ;
		rctx->timer.function=&send_handler;
		lock_hold=spin_trylock_bh(&rctx->stop_timer_lock);
		if (!rctx->stop_timer) add_timer(&rctx->timer);
		if (lock_hold) spin_unlock_bh(&rctx->stop_timer_lock);
	}
/* out:*/
	spin_unlock_bh(&rctx->lock);
}

/*Starts the keepalive timer if it was not yet running
 * if the send timer was running it is stopped.
 *
 * @rearmed is 1 if the keepalive timer is rearmed (ka_start called
 * from ka_handler). Else @rearmed is 0.
 *
 * IMPORTANT : The ctx lock cannot be held while calling this function, since
 *             it makes use of it.
 */
inline void ka_start(struct reap_ctx* rctx, int rearmed)
{
	int lock_hold;
	
	spin_lock(&rctx->lock);
	
	if (!rearmed) { /*Trying to start the ka timer from outside */
		if (rctx->ka_timestamp) goto out; /*The conceptual timer is 
						    already running*/
		/*Maybe the send timer was running*/
		del_timer(&rctx->timer); 
		
		/*the timer is not running, initialize it*/
		rctx->ka_timestamp=jiffies; /*Save the current time
					      for the conceptual timer*/
		rctx->timer.function=&ka_handler;
	}
	
	rctx->timer.expires=jiffies+rctx->ka_timeout*HZ/3;
 	lock_hold=spin_trylock(&rctx->stop_timer_lock);
	if (!rctx->stop_timer) add_timer(&rctx->timer);
	if (lock_hold) spin_unlock(&rctx->stop_timer_lock);

out:
	spin_unlock(&rctx->lock);
}

/* data is a pointer to a struct reap_ctx
 * Sends a netlink message to user space to ask sending a keepalive.
 * Format the message :
 *  ----------------
 * |  ct_local      |
 *  ----------------
 */
static void ka_handler(unsigned long data) 
{
	struct reap_ctx* rctx=(struct reap_ctx*)data;
	struct sk_buff* skb;
	int err;
	__u64* ct;
       
	
	/*Tell the daemon to send a keepalive message*/
	
	if (!(skb=shim6_alloc_netlink_skb(sizeof(__u64),REAP_NL_SEND_KA,
					  GFP_ATOMIC)))
		return;
	
	ct=NLMSG_DATA((struct nlmsghdr*)skb->data);
	
	*ct=rctx->ct_local;
	
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC))) {
		printk(KERN_ERR "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", 
		       __FUNCTION__, err);
		return;
	}
	
	/*Rearm the timer if the next expiry will fall before the keepalive
	 * timeout*/

	if (jiffies+rctx->ka_timeout*HZ/3<
	    rctx->ka_timestamp+rctx->ka_timeout*HZ)
		ka_start(rctx,1);
	else rctx->ka_timestamp=0; /*Also disable the conceptual timer*/
	
	return;
}

/* Asks the daemon to start a new exploration.
 * This function can either be called upon send timer expiry
 * or from any other place.
 * This last case is to allow starting an exploration quicker, for example,
 * when the current locator becomes locally unavailable.
 *
 * format for the netlink message :
 *  ---------------------------------------
 * |  local context tag (64 bits, 47 used) |
 *  ---------------------------------------
 */
void reap_init_explore(struct reap_ctx* rctx) 
{
	struct sk_buff* skb;
	int pld_len;
	u64* ct;
	int err;
	
	/*This lock is to make the function reentrant*/
	spin_lock_bh(&rctx->lock);
	if (rctx->state!=REAP_OPERATIONAL) {
		spin_unlock_bh(&rctx->lock);
		return;
	}
	rctx->state=REAP_EXPLORING;
	spin_unlock_bh(&rctx->lock);

	/*Starting exploration process*/
	
	pld_len=sizeof(rctx->ct_local);
	if (!(skb=shim6_alloc_netlink_skb(pld_len,REAP_NL_START_EXPLORE,
					  GFP_ATOMIC)))
		return;
	ct=NLMSG_DATA((struct nlmsghdr*)skb->data);
	*ct=rctx->ct_local;
	
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC)))
		printk(KERN_INFO "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", 
		       __FUNCTION__, err);
}


/* Send timer expiry : we need to start an exploration. 
 */

static void send_handler(unsigned long data)
{
	struct reap_ctx* rctx=(struct reap_ctx*) data;
	reap_init_explore(rctx);
}

void __exit reap_exit(void)
{
	/*Closing the netlink socket*/
	sock_release(shim6nl_sk->sk_socket);
}



/**
 * @pre The corresponding Shim6 is in state ESTABLISHED.
 * This initializes the reap context pointed to by rctx
 */
void init_reap_ctx(struct reap_ctx* rctx) {

	memset(rctx,0,sizeof(struct reap_ctx));
	spin_lock_init(&rctx->lock);
	kref_init(&rctx->kref);
	
        /*Timers initialization*/
	init_timer(&rctx->timer);
	rctx->timer.data=(unsigned long)rctx;
	
	rctx->state=REAP_OPERATIONAL;

	/*Init the timeouts to default values*/
	rctx->ka_timeout=REAP_SEND_TIMEOUT;
	rctx->send_timeout=REAP_SEND_TIMEOUT;
	
	rctx->started=1;

	rctx->stop_timer=0;
	spin_lock_init(&rctx->stop_timer_lock);	
}

/* This deletes a reap context 
 */
void del_reap_ctx(struct reap_ctx* rctx) {
	/*Stopping keepalive/send timer*/
	stop_ka_send_timer(rctx);
}



/* If state is OPERATIONAL, just start the keepalive timer.
 * If not, we inform the daemon, with the following message.
 *  ------------------------------
 * |context tag (64 bits, 47 used)|
 *  ------------------------------
 */
void reap_notify_in(struct reap_ctx* rctx)
{
	int pld_len;
	struct sk_buff* skb;
	u64* ct;
	int err;


	if (rctx->state==REAP_OPERATIONAL) {
		ka_start(rctx,0);
		return;
	}

	PDEBUG("Received data packet while exploring\n");
	/*We are inside an exploration process, inform the daemon*/
	pld_len=sizeof(rctx->ct_local);
	if (!(skb=shim6_alloc_netlink_skb(pld_len,REAP_NL_NOTIFY_IN,
					  GFP_ATOMIC))) 
		return;
	ct=NLMSG_DATA((struct nlmsghdr*)skb->data);
	*ct=rctx->ct_local;
	
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC)))
		printk(KERN_ERR "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", 
		       __FUNCTION__, err);
	return;
}

/* If state is OPERATIONAL, just start the keepalive timer.
 * If not, we inform the daemon, with the following message.
 *  ------------------------------
 * |context tag (64 bits, 47 used)|
 *  ------------------------------
 */

void reap_notify_out(struct reap_ctx* rctx)
{
	int pld_len;
	struct sk_buff* skb;
	u64* ct;
	int err;
	
	if (rctx->state==REAP_OPERATIONAL) {
		send_start(rctx);
		return;
	}
	
	/*We are inside an exploration process, inform the daemon*/
	pld_len=sizeof(rctx->ct_local);
	if (!(skb=shim6_alloc_netlink_skb(pld_len,REAP_NL_NOTIFY_OUT,
					  GFP_ATOMIC))) 
		return;
	ct=NLMSG_DATA((struct nlmsghdr*)skb->data);
	*ct=rctx->ct_local;
	
	if ((err=netlink_broadcast(shim6nl_sk,skb,0,SHIM6NLGRP_DEFAULT,
				   GFP_ATOMIC)))
		printk(KERN_ERR "shim6, %s : nl broadcast, error %d,"
		       "daemon down ?\n", 
		       __FUNCTION__, err);	
	return;
}

static int reap_rcv_ka(struct reaphdr_ka* hdr,struct reap_ctx* rctx)
{
	if (hdr->common.hdrlen<1) {
		printk(KERN_ERR "reap : keepalive length < 1\n");
		return -1;
	}

	spin_lock(&rctx->lock);
	
	if(rctx->state==REAP_OPERATIONAL &&
	   rctx->timer.function==&send_handler) {
		del_timer(&rctx->timer);
	}
	spin_unlock(&rctx->lock);
	
	return 1;
}

static int reap_rcv_probe(reaphdr_probe* hdr,struct reap_ctx* rctx)
{
	int probe_len; /*Total length of the message, without IPv6 hdr*/
	
	probe_len=(hdr->common.hdrlen+1)<<3;
	
	if (probe_len<MIN_PROBE_LEN || probe_len > MAX_PROBE_LEN) {
		printk(KERN_ERR "reap_rcv_probe : invalid probe length\n");
		return -1;
	}
	
	if (rctx->state==REAP_OPERATIONAL) {
		switch(hdr->sta) {
		case REAP_EXPLORING:
			/*This triggers an exploration in the daemon. In the 
			  kernel, we just need to stop the timer and update 
			  the state. */
			rctx->state=REAP_INBOUND_OK;
			PDEBUG("Stopping send and ka timers\n");
			del_timer(&rctx->timer);
			break;
		case REAP_INBOUND_OK:
			del_timer(&rctx->timer);
			send_start(rctx);
			break;
		case REAP_OPERATIONAL:
			ka_start(rctx,0);
			break;
		}
		
	}
	
	return 1;
}

int reap_input(struct shim6hdr_ctl* ctl, struct reap_ctx* rctx)
{
	/*Verifying the checksum (draft v9, section 12.3)*/
	if(ip_compute_csum(ctl,(ctl->hdrlen + 1) << 3)) {
		PDEBUG("Recvd shim6 ctrl msg with invalid checksum\n");
		return -1;
	}
	
	switch (ctl->type) {
	case REAP_TYPE_KEEPALIVE:
		PDEBUG("Received reap keepalive\n");			
		return reap_rcv_ka((reaphdr_ka*)ctl,rctx);
	case REAP_TYPE_PROBE:
		PDEBUG("Received reap probe\n");			
		return reap_rcv_probe((reaphdr_probe*)ctl,rctx);
	}
	printk(KERN_ERR "reap.c, reap_input : unexpected exec path\n");
	return -1;
}

