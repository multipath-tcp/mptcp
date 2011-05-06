/*
 *	MTCP implementation
 *      IPv6-related functions  
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      date : June 09
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */


#ifndef _MTCP_V6_H
#define _MTCP_V6_H

/*TODO: make this part of the IPv6 module
  At the moment this will break if IPv6 is compiled as a module*/
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
extern int tcp_v6_is_v4_mapped(struct sock *sk);
#else
#define tcp_v6_is_v4_mapped(sk) (0)
#endif

#endif /* _MTCP_V6_H */
