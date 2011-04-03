/*
 *	MTCP implementation
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

#include <net/sock.h>
#include <net/mtcp.h>
#include <net/tcp.h>
#include <net/protocol.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/addrconf.h>

/*Functions and structures defined in tcp_ipv6.c*/
extern struct inet_connection_sock_af_ops ipv6_specific;
extern int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr,
			  int addr_len);
extern int tcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb);
extern void tcp_v6_hash(struct sock *sk);
extern void tcp_v6_destroy_sock(struct sock *sk);
extern struct timewait_sock_ops tcp6_timewait_sock_ops;
extern struct request_sock_ops tcp6_request_sock_ops;


/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
static int mtcpsub_v6_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_head_init(&tp->out_of_order_queue);
	tcp_init_xmit_timers(sk);
	tcp_prequeue_init(tp);

	icsk->icsk_rto = TCP_TIMEOUT_INIT;
	tp->mdev = TCP_TIMEOUT_INIT;

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = TCP_MSS_DEFAULT;

	tp->reordering = sysctl_tcp_reordering;

	sk->sk_state = TCP_CLOSE;

	icsk->icsk_af_ops = &ipv6_specific;
	icsk->icsk_ca_ops = &tcp_init_congestion_ops;
	icsk->icsk_sync_mss = tcp_sync_mss;
	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

#ifdef CONFIG_TCP_MD5SIG
	tp->af_specific = &tcp_sock_ipv6_specific;
#endif
	/* TCP Cookie Transactions */
        if (sysctl_tcp_cookie_size > 0) {
                /* Default, cookies without s_data_payload. */
                tp->cookie_values =
                        kzalloc(sizeof(*tp->cookie_values),
                                sk->sk_allocation);
                if (tp->cookie_values != NULL)
                        kref_init(&tp->cookie_values->kref);
        }
        /* Presumed zeroed, in order of appearance:
         *      cookie_in_always, cookie_out_never,
         *      s_data_constant, s_data_in, s_data_out
         */
	sk->sk_sndbuf = sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_tcp_rmem[1];

	local_bh_disable();
        percpu_counter_inc(&tcp_sockets_allocated);
        local_bh_enable();

	return 0;
}



struct proto mtcpsubv6_prot = {
	.name			= "MTCPSUBv6",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v6_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= mtcpsub_v6_init_sock,
	.destroy		= tcp_v6_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.sendmsg		= mtcp_sendmsg,
	.recvmsg		= tcp_recvmsg,
	.backlog_rcv		= tcp_v6_do_rcv,
	.hash			= tcp_v6_hash,
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.sockets_allocated	= &tcp_sockets_allocated,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.orphan_count		= &tcp_orphan_count,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcp6_sock),
	.twsk_prot		= &tcp6_timewait_sock_ops,
	.rsk_prot		= &tcp6_request_sock_ops,
	.h.hashinfo		= &tcp_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt	= compat_tcp_setsockopt,
	.compat_getsockopt	= compat_tcp_getsockopt,
#endif
};

static struct inet_protosw mtcpsubv6_protosw = {
	.type		=	SOCK_STREAM,
	.protocol	=	IPPROTO_MTCPSUB,
	.prot		=	&mtcpsubv6_prot,
	.ops		=	&inet6_stream_ops,
	.no_check	=	0,
	.flags		=	INET_PROTOSW_PERMANENT |
				INET_PROTOSW_ICSK,
};

int __init mtcpv6_init(void)
{
	int ret;
	/* register inet6 protocol */
	ret = inet6_register_protosw(&mtcpsubv6_protosw);

	/*Although the protocol is not used as such, it is necessary to register
	  it, so that slab memory is allocated for it.*/
	if (ret==0)
		ret=proto_register(&mtcpsubv6_prot, 1);
	return ret;
}

void mtcpv6_exit(void)
{
	inet6_unregister_protosw(&mtcpsubv6_protosw);
}
