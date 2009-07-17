/*
 *	MTCP implementation
 *      IPv6-related functions  
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *      Costin Raiciu           <c.raiciu@cs.ucl.ac.uk>
 *
 *
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

#include <net/inet6_hashtables.h>

/*Lookup for socket, taking into account the path index*/

struct sock *__mtcpv6_lookup_established(struct net *net,
					 struct inet_hashinfo *hashinfo,
					 const struct in6_addr *saddr,
					 const __be16 sport,
					 const struct in6_addr *daddr,
					 const u16 hnum,
					 const int dif, const int path_index);

struct sock *mtcpv6_lookup_listener(struct net *net,
				    struct inet_hashinfo *hashinfo, 
				    const struct in6_addr *daddr,
				    const unsigned short hnum, const int dif, 
				    const int path_index);

static inline struct sock *__mtcpv6_lookup(struct net *net,
					   struct inet_hashinfo *hashinfo,
					   const struct in6_addr *saddr,
					   const __be16 sport,
					   const struct in6_addr *daddr,
					   const u16 hnum,
					   const int dif, const int path_index)
{
	struct sock *sk = __mtcpv6_lookup_established(net, hashinfo, saddr,
						      sport, daddr, hnum, dif,
						      path_index);
	if (sk)
		return sk;
	
	/*For listening socket, we use the standard function, simply ignoring
	  the path index, since no MTCP slave socket is listening. (we do never
	  call listen on those kinds of sockets)*/
	sk=mtcpv6_lookup_listener(net, hashinfo, daddr, hnum, dif,path_index);

	return sk;
}

extern struct sock *mtcpv6_lookup(struct net *net, 
				  struct inet_hashinfo *hashinfo,
				  const struct in6_addr *saddr, 
				  const __be16 sport,
				  const struct in6_addr *daddr, 
				  const __be16 dport,
				  const int dif, const int path_index);

#endif /* _MTCP_V6_H */
