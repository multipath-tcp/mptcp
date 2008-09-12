/*
 * xfrm6_mode_shim6.c - Shim6 mode for IPv6.
 *
 * Copyright (C)2007 Université Catholique de Louvain
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Authors:
 *      Sébastien Barré (using xfrm6_mode_* as template)
 *
 *  Date : September 2007
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <net/xfrm.h>
#include <net/shim6.h>

/* Add shim6 header space if necessary.
 *
 * The IP header and mutable extension headers will be moved forward (in case 
 * ulids differ from locators) to make
 * space for the shim6 header.
 *
 * On exit, skb->h will be set to the start of the encapsulation header to be
 * filled in by x->type->output and skb->nh will be set to the nextheader field
 * of the extension header directly preceding the encapsulation header, or in
 * its absence, that of the top IP header.  The value of skb->data will always
 * point to the top IP header.
 */
static int xfrm6_shim6_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct ipv6hdr *iph=ipv6_hdr(skb);
	u8 *prevhdr;
	int hdr_len;

	if (x->shim6->flags & SHIM6_DATA_TRANSLATE) {	
		hdr_len = x->type->hdr_offset(x, skb, &prevhdr);
		skb_set_mac_header(skb, (prevhdr - x->props.header_len) - 
				   skb->data);
		skb_set_network_header(skb, -x->props.header_len);
		skb->transport_header = skb->network_header + hdr_len;
		__skb_pull(skb, hdr_len);
		memmove(ipv6_hdr(skb), iph, hdr_len);

		x->lastused = get_seconds();
	}
	
	return 0;
}

/*
 * Do nothing about shim6 header unlike IPsec.
 */
static int xfrm6_shim6_input(struct xfrm_state *x, struct sk_buff *skb)
{
	return 0;
}

static struct xfrm_mode xfrm6_shim6_mode = {
	.input = xfrm6_shim6_input,
	.output = xfrm6_shim6_output,
	.owner = THIS_MODULE,
	.encap = XFRM_MODE_SHIM6,
};

static int __init xfrm6_shim6_init(void)
{
	return xfrm_register_mode(&xfrm6_shim6_mode,AF_INET6);
}

static void __exit xfrm6_shim6_exit(void) 
{
	int err;
	err = xfrm_unregister_mode(&xfrm6_shim6_mode,AF_INET6);
	BUG_ON(err);
}

module_init(xfrm6_shim6_init);
module_exit(xfrm6_shim6_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_XFRM_MODE(AF_INET6, XFRM_MODE_SHIM6);
