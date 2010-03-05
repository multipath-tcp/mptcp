/*
 *	MTCP PM implementation
 *
 *	Authors:
 *      Sébastien Barré           <sebastien.barre@uclouvain.be>
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

#ifdef CONFIG_MTCP_PM

#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>

#define MTCP_HASH_SIZE                16
#define hash_tk(token) \
	jhash_1word(fd,0)%MTCP_HASH_SIZE

#define MTCP_MAX_ADDR 3 /*Max number of local or remote addresses we can store*/

struct multipath_pcb;

struct mtcp_loc4 {
	int               id;
	struct in_addr    addr;
};

struct mtcp_loc6 {
	int                id;
	struct in6_addr    addr;
};

struct path4 {
	struct mtcp_loc4  loc; /*local address*/
	struct mtcp_loc4  rem; /*remote address*/
	int               path_index;
};

struct path6 {
	struct mtcp_loc6  loc; /*local address*/
	struct mtcp_loc6  rem; /*remote address*/
	int               path_index;
};

struct mtcp_pm_ctx {
	struct list_head    collide_token;

/*token information*/
	u32                 tk_local, tk_remote;

/*connection identifier*/
	__u32 remote_app_ip, local_app_ip;
	__u16 remote_port,local_port;
};

u32 mtcp_new_token(void);
void mtcp_set_addresses(struct multipath_pcb *mpcb);
void mtcp_update_patharray(struct multipath_pcb *mpcb);
#endif /* CONFIG_MTCP_PM */
#endif /*_MTCP_PM_H*/
