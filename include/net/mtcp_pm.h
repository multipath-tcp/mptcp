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
#include <linux/skbuff.h>

#define MTCP_MAX_ADDR 12 /*Max number of local or remote addresses we can store*/

struct multipath_pcb;

struct mtcp_loc4 {
	u8                id;
	struct in_addr    addr;
};

struct mtcp_loc6 {
	u8                 id;
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
	u32                 tk_local;

	struct multipath_pcb *mpcb;
};

#define loc_token(mpcb)				\
	(mpcb->tp.mtcp_loc_token)

u32 mtcp_new_token(void);
void mtcp_hash_insert(struct multipath_pcb *mpcb,u32 token);
void mtcp_hash_remove(struct multipath_pcb *mpcb);
struct multipath_pcb* mtcp_hash_find(u32 token);
void mtcp_set_addresses(struct multipath_pcb *mpcb);
void mtcp_update_patharray(struct multipath_pcb *mpcb);
struct in_addr *mtcp_get_loc_addr(struct multipath_pcb *mpcb, int path_index);
struct in_addr *mtcp_get_rem_addr(struct multipath_pcb *mpcb, int path_index);
u8 mtcp_get_loc_addrid(struct multipath_pcb *mpcb, int path_index);
int mtcp_lookup_join(struct sk_buff *skb);
int mtcp_syn_recv_sock(struct sk_buff *skb);
int mtcp_check_new_subflow(struct multipath_pcb *mpcb);
void mtcp_pm_release(struct multipath_pcb *mpcb);
#endif /* CONFIG_MTCP_PM */
#endif /*_MTCP_PM_H*/
