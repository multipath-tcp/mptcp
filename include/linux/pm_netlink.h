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

#ifndef _LINUX_PM_NETLINK_H
#define _LINUX_PM_NETLINK_H

#ifndef __KERNEL__
#include <sys/types.h>
#include <netinet/in.h>
#else
#include <linux/in6.h>
#include <asm/byteorder.h>
#include <asm/types.h>
#include <net/if_inet6.h>
#endif /*__KERNEL__*/

#include <linux/netlink.h>

#define MAX_NL_PAYLOAD 50 

/*The current version of libc has an old version of linux/netlink.h
  with this field undefined.*/

#ifndef NLMSG_MIN_TYPE
#define NLMSG_MIN_TYPE 0x10
#endif


/*PM Multicast groups, currently only one.*/
enum pm_nlgroups {
	PMNLGRP_NONE,
	PMNLGRP_DEFAULT,
	__PMNLGRP_MAX
};
#define PMNLGRP_MAX (__PMNLGRP_MAX-1)


enum pm_nl_type_t {	
	PM_NL_PATHUPDATE = 1+NLMSG_MIN_TYPE, /*Announce new paths indices*/
};

/*Data part of the Netlink message for Netlink code PM_NL_PATHUPDATE
  For the moment this is only supported for IPv6 */
struct nl_ulid_pair {
	struct in6_addr local;
	struct in6_addr remote;
	uint32_t        path_indices; /*bitmap of paths that can be used
					 For example, if bit 3 is set, then
					 3 is currently a valid path index
					 that can be understood by a Path 
					 Manager*/
};

#ifdef __KERNEL__ /*definitions for kernel space*/

#include <net/netlink.h>

extern struct sock *pmnl_sk;

#endif /*__KERNEL__*/

#endif /*_LINUX_PM_NETLINK_H*/
