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

int sysctl_shim6_enabled = 0; /*Will be enabled at the end of shim6 init*/
int sysctl_shim6_tcphint = 0; /*if 0, disables TCP hint, by default it is
				enabled at the end of shim6 init*/
EXPORT_SYMBOL(sysctl_shim6_enabled);
EXPORT_SYMBOL(sysctl_shim6_tcphint);
