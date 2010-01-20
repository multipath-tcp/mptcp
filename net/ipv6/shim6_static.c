/*
 *	Shim6 layer implementation
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Based on draft-ietf-shim6-proto-11
 *      This is the static part of Shim6, that must be statically compiled
 *      in the kernel.
 *
 *      date : Jan 09
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/shim6.h>
#include <net/if_inet6.h>
#include <net/sock.h>

int sysctl_shim6_enabled = 0; /*Will be enabled at the end of shim6 init*/

static struct shim6_ops *shim6_fcts=NULL;

int shim6_register_ops(struct shim6_ops *ops)
{
	if (shim6_fcts) return -1; /*Only one heuristic is allowed at a time*/
	shim6_fcts=ops;
	return 0;
}
EXPORT_SYMBOL(shim6_register_ops);
int shim6_unregister_ops(struct shim6_ops *ops)
{
	if (shim6_fcts!=ops) return -1; /*trying to unregister something 
					      else, probably a bug*/
	shim6_fcts=NULL;
	return 0;
}
EXPORT_SYMBOL(shim6_unregister_ops);


/*Wrappers for functions that are registered in the Shim6 module.*/
void shim6_input_std(struct sk_buff* skb)
{
	if (!shim6_fcts) return;
	shim6_fcts->input_std(skb);
}
EXPORT_SYMBOL(shim6_input_std);

void shim6_add_glob_locator(struct inet6_ifaddr* loc)
{
	if (!shim6_fcts) return;
	shim6_fcts->add_glob_locator(loc);
}
EXPORT_SYMBOL(shim6_add_glob_locator);

void shim6_del_glob_locator(struct inet6_ifaddr* loc)
{
	if (!shim6_fcts) return;
	shim6_fcts->del_glob_locator(loc);
}
EXPORT_SYMBOL(shim6_del_glob_locator);

int shim6_filter(struct sock *sk, struct sk_buff *skb)
{
	if (!shim6_fcts) return 0;
	return shim6_fcts->filter(sk, skb);
}
EXPORT_SYMBOL(shim6_filter);

int shim6_xfrm_input_ct(struct sk_buff *skb, __u64 ct)
{
	if (!shim6_fcts) return 0;
	return shim6_fcts->xfrm_input_ct(skb,ct);
}
EXPORT_SYMBOL(shim6_xfrm_input_ct);


EXPORT_SYMBOL(sysctl_shim6_enabled);
