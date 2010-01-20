/*
 *	MTCP PM implementation
 *
 *	Authors:
 *      Costin Raiciu           <c.raiciu@cs.ucl.ac.uk>
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
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

#include <net/mtcp.h>


static struct list_head tk_hashtable[MTCP_HASH_SIZE];

/*General initialization of MTCP_PM
 */
static int __init mtcp_pm_init(void) 
{
	for (i=0;i<MTCP_HASH_SIZE;i++)
		INIT_LIST_HEAD(&tk_hashtable[i]);		
	return 0;
}


module_init(mtcp_pm_init);

MODULE_LICENSE("GPL");
