#ifndef _NET_EVENT_H
#define _NET_EVENT_H

/*
 *	Generic netevent notifiers
 *
 *	Authors:
 *      Tom Tucker              <tom@opengridcomputing.com>
 *      Steve Wise              <swise@opengridcomputing.com>
 *
 * 	Changes:
 */
#ifdef __KERNEL__

#include <linux/in6.h>

struct dst_entry;

struct netevent_redirect {
	struct dst_entry *old;
	struct dst_entry *new;
};

/*For the moment this is only supported for IPv6
  This indicates that new paths are available for the given
  local and remote ulids. */
struct ulid_pair {
	struct in6_addr* local;
	struct in6_addr* remote;
	uint32_t         path_indices; /*bitmap of paths that can be used
					 For example, if bit 3 is set, then
					 3 is currently a valid path index
					 that can be understood by a Path
					 Manager*/
};

enum netevent_notif_type {
	NETEVENT_NEIGH_UPDATE = 1, /* arg is struct neighbour ptr */
	NETEVENT_PMTU_UPDATE,	   /* arg is struct dst_entry ptr */
	NETEVENT_REDIRECT,	   /* arg is struct netevent_redirect ptr */
	NETEVENT_PATH_UPDATEV6,    /* arg is struct ulid_pair ptr*/
	NETEVENT_MPS_UPDATEME,     /* arg is struct ulid_pair ptr*/
};

extern int register_netevent_notifier(struct notifier_block *nb);
extern int unregister_netevent_notifier(struct notifier_block *nb);
extern int call_netevent_notifiers(unsigned long val, void *v);

#endif
#endif
