/*
 *	MTCP implementation
 *
 *      Specific hashtables for MTCP
 *      Essentially copied from inet6_hashtables.c
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
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

#include <linux/types.h>
#include <linux/in6.h>

#include <net/inet_hashtables.h>
#include <net/inet6_hashtables.h>
#include <net/mtcp_v6.h>

/*
 * Sockets in TCP_CLOSE state are _always_ taken out of the hash, so
 * we need not check it for TCP lookups anymore, thanks Alexey. -DaveM
 *
 * The sockhash lock must be held as a reader here.
 */
struct sock *__mtcpv6_lookup_established(struct net *net,
					 struct inet_hashinfo *hashinfo,
					 const struct in6_addr *saddr,
					 const __be16 sport,
					 const struct in6_addr *daddr,
					 const u16 hnum,
					 const int dif, const int path_index)
{
	struct sock *sk;
	struct tcp_sock *tp;
	const struct hlist_node *node;
	const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	unsigned int hash = inet6_ehashfn(net, daddr, hnum, saddr, sport);
	struct inet_ehash_bucket *head = inet_ehash_bucket(hashinfo, hash);
	rwlock_t *lock = inet_ehash_lockp(hashinfo, hash);

	prefetch(head->chain.first);
	read_lock(lock);
	sk_for_each(sk, node, &head->chain) {
		tp=tcp_sk(sk);
		/* For IPV6 do the cheaper port and family tests first. */
		if (INET6_MATCH(sk, net, hash, saddr, daddr, ports, dif) &&
		    (!path_index || tp->path_index==path_index))
			goto hit; /* You sunk my battleship! */
	}
	/* Must check for a TIME_WAIT'er before going to listener hash. */
	sk_for_each(sk, node, &head->twchain) {
		tp=tcp_sk(sk);
		if (INET6_TW_MATCH(sk, net, hash, saddr, daddr, ports, dif) &&
		    (!path_index || tp->path_index==path_index))
			goto hit;
	}
	read_unlock(lock);
	return NULL;

hit:
	sock_hold(sk);
	read_unlock(lock);
	return sk;
}

struct sock *mtcpv6_lookup_listener(struct net *net,
				    struct inet_hashinfo *hashinfo, 
				    const struct in6_addr *daddr,
				    const unsigned short hnum, const int dif, 
				    const int path_index)
{
	struct sock *sk;
	struct tcp_sock *tp;
	const struct hlist_node *node;
	struct sock *result = NULL;
	int score, hiscore = 0;

	read_lock(&hashinfo->lhash_lock);
	sk_for_each(sk, node,
		    &hashinfo->listening_hash[inet_lhashfn(net, hnum)]) {
		tp=tcp_sk(sk);
		
		if (net_eq(sock_net(sk), net) && inet_sk(sk)->num == hnum &&
		    sk->sk_family == PF_INET6 && 
		    (!path_index || tp->path_index==path_index
		     || !tp->path_index)) {
			const struct ipv6_pinfo *np = inet6_sk(sk);
			
			score = 1;
			if (!ipv6_addr_any(&np->rcv_saddr)) {
				if (!ipv6_addr_equal(&np->rcv_saddr, daddr))
					continue;
				score++;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score++;
			}
			if (score == 3) {
				result = sk;
				break;
			}
			if (score > hiscore) {
				hiscore = score;
				result = sk;
			}
		}
	}
	if (result)
		sock_hold(result);
	read_unlock(&hashinfo->lhash_lock);
	return result;
}

struct sock *mtcpv6_lookup(struct net *net, struct inet_hashinfo *hashinfo,
			   const struct in6_addr *saddr, const __be16 sport,
			   const struct in6_addr *daddr, const __be16 dport,
			   const int dif, const int path_index)
{
	struct sock *sk;

	local_bh_disable();
	sk = __mtcpv6_lookup(net, hashinfo, saddr, sport, daddr, ntohs(dport), 
			     dif, path_index);
	local_bh_enable();

	return sk;
}
