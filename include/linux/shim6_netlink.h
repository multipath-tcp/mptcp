/*
 *	Shim6 layer implementation - netlink communication with user space.
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Based on draft-ietf-shim6-proto-09
 *
 *      date : December 2007
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_SHIM6_NETLINK_H
#define _LINUX_SHIM6_NETLINK_H

#include <linux/netlink.h>

#define MAX_NL_PAYLOAD 50 

/*Netlink message types (from kernel to the shim6 multicast group)*/

/*The current version of libc has an old version of linux/netlink.h
  with this field undefined.*/

#ifndef NLMSG_MIN_TYPE
#define NLMSG_MIN_TYPE 0x10
#endif


/*Shim6 Multicast groups, currently only one.*/
enum shim6_nlgroups {
	SHIM6NLGRP_NONE,
	SHIM6NLGRP_DEFAULT,
	__SHIM6NLGRP_MAX
};
#define SHIM6NLGRP_MAX (__SHIM6NLGRP_MAX-1)


enum shim6_nl_type_t {
/*Messages for REAP*/
	REAP_NL_NEW_CTX = 1+NLMSG_MIN_TYPE, /*Create new ctx*/
	REAP_NL_START_EXPLORE, /*Start exploration*/
	REAP_NL_NOTIFY_IN, /*Notify incoming packet (only 
			     during an exploration process)*/
	REAP_NL_NOTIFY_OUT, /*Notify outgoing packet (only 
			      during an exploration process)*/
	REAP_NL_SEND_KA, /*Tells the daemon that a ka must be sent*/	      

/*Messages for shim6 */
	SHIM6_NL_NEW_CTX, /*Ask the shim6 daemon to start a 
			    context establishment*/
	SHIM6_NL_NEW_LOC_ADDR, /*New address available in the 
				 kernel*/
	SHIM6_NL_DEL_LOC_ADDR, /*address not anymore available 
				in the kernel*/
};

#ifdef __KERNEL__ /*definitions for kernel space*/

#include <net/netlink.h>

extern struct sock *shim6nl_sk;

/*Netlink initialization. This may be called ONLY
  by shim6_init (shim6.c) */
int __init shim6_netlink_init(void);

/* Allocates an sk_buff for unicast sending to shim6d.
 *
 * - pld_len is the payload length
 * - type is some of the REAP_NL_* messsage types (see linux/shim6.h)
 * - GFP is either GFP_ATOMIC or GFP_KERNEL
 *
 * returns NULL in case of failure
 */
struct sk_buff* shim6_alloc_netlink_skb(int pld_len,int type,int gfp);

#else /*definitions for user space*/

/*NETLINK INFORMATION*/

#ifndef NETLINK_SHIM6 /*May be already defined if
			/usr/include/linux/netlink.h is up to date*/
#define NETLINK_SHIM6 20
#endif

extern int nlsd; /*Netlink socket descriptor*/

/*Alloc @size bytes in a new netlink message. @data is filled with a pointer
 * to the data part of the message; @msg is filled with a pointer to the
 * message header.
 * @data may be NULL if we want to send an empty message.
 * @type is the message type, for example REAP_NL_GET_LOC_ADDRS 
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int netlink_alloc_send(int size, int type, void** data, struct nlmsghdr** msg);

/*Allocate memory for reception from the kernel
 * @size is the only parameter to know in advance
 * @nlhdr is a pointer which will be set to the allocated memory
 * @msg and @iov point to empty structures. They will be filled in.
 */
int netlink_alloc_rcv(int size, struct nlmsghdr** nlhdr, struct msghdr* msg,
		      struct iovec* iov);

int netlink_init(void);

#endif /*__KERNEL__*/

#endif /*_LINUX_SHIM6_NETLINK_H*/
