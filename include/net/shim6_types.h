/*
 *	Linux SHIM6 implementation
 *
 *	Author:
 *	Sébastien Barré		<sbarre@info.ucl.ac.be>
 *
 *	date : november 2006
 */

#ifndef _NET_SHIM6_TYPES_H
#define _NET_SHIM6_TYPES_H

#include <linux/list.h>
#include <linux/in6.h>
#include <net/if_inet6.h>

/*Locator structure : One structure per locator*/
struct shim6_loc_p {
	struct in6_addr   addr;
	__u8              valid_method; /*validation method*/
	__u8              valid_done:1,
			  probe_done:1;     
};

/* shim6_loc_p and shim6_loc_l correspond to different structures,
 * but every field disponible in struct shim6_loc_p is also disponible
 * in shim6_loc_l : So it may be used as if it were the same thing. The only
 * thing we need to care about is to use shim6_loc_p when working with peer
 * locators, and shim6_loc_l when working with local locators.
 */
typedef struct shim6_loc_p shim6_loc_p;
typedef struct inet6_ifaddr shim6_loc_l;

#endif
