/*
 *	MTCP PM implementation
 *
 *	Authors:
 *      Costin Raiciu           <c.raiciu@cs.ucl.ac.uk>
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *      date : March 09
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _MTCP_PM_H
#define _MTCP_PM_H

#include <linux/list.h>
#include <linux/jhash.h>

#define hash_tk(token) \
	jhash_1word(fd,0)%MTCP_HASH_SIZE


#define MTCP_PM_MAX_IP 5 /*Max number of supported IP addresses*/

struct mtcp_pm_ctx {
	struct list_head    collide_token;

/*token information*/
	//tokens
	u32                 tk_local, tk_remote;

/*locator information*/	
	__u8                cnt_local_addr;
	__u8                cnt_remote_addr;
	__u32               remote_ips[MTCP_PM_MAX_IP];
	__u32	            local_ips[MTCP_PM_MAX_IP];

/*connection identifier*/
	__u32 remote_app_ip, local_app_ip;
	__u16 remote_port,local_port;
}

#endif /*_MTCP_PM_H*/
