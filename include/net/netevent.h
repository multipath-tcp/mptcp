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

#include <net/dst.h>
#include <linux/in6.h>

struct netevent_redirect {
	struct dst_entry *old;
	struct dst_entry *new;
};

/*For the moment this is only supported for IPv6, the path update
  notification indicates that the path underlying a given ULID pair
  (the IP address pair used as identifiers at the socket layer) has
  changed. */
struct ulid_pair {
	struct in6_addr* local;
	struct in6_addr* remote;
};

enum netevent_notif_type {
	NETEVENT_NEIGH_UPDATE = 1, /* arg is struct neighbour ptr */
	NETEVENT_PMTU_UPDATE,	   /* arg is struct dst_entry ptr */
	NETEVENT_REDIRECT,	   /* arg is struct netevent_redirect ptr */
	NETEVENT_PATH_UPDATE,      /* arg is struct ulid_pair ptr*/
};

extern int register_netevent_notifier(struct notifier_block *nb);
extern int unregister_netevent_notifier(struct notifier_block *nb);
extern int call_netevent_notifiers(unsigned long val, void *v);

#endif
#endif
