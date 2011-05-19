/*
 *	MTCP implementation
 *
 *	Author:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *      date : March 2010
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
#include <net/transp_v6.h>

extern struct timewait_sock_ops tcp_timewait_sock_ops;

/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
static int mtcpsub_v4_init_sock(struct sock *sk)
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
	icsk->icsk_ca_ops = &tcp_init_congestion_ops;

	sk->sk_state = TCP_CLOSE;

	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	icsk->icsk_af_ops = &ipv4_specific;
	icsk->icsk_sync_mss = tcp_sync_mss;
#ifdef CONFIG_TCP_MD5SIG
	tp->af_specific = &tcp_sock_ipv4_specific;
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

/* While the metasocket (seen by applications as a normal TCP socket) is
 * dealt with as a TCP socket, we define a specific protocol for MTCP subflows.
 * The new protocol is mostly based on normal TCP functions, and mainly serves
 * for disambiguating whether we are inside a subflow or a metaflow.
 */
struct proto mtcpsub_prot = {
	.name			= "MTCPSUB",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= mtcpsub_v4_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.sendmsg		= mtcp_sendmsg,
	.recvmsg		= tcp_recvmsg,
	.backlog_rcv		= tcp_v4_do_rcv,
	.hash			= inet_hash,
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcp_sock),
	.twsk_prot		= &tcp_timewait_sock_ops,
	.rsk_prot		= &tcp_request_sock_ops,
	.h.hashinfo		= &tcp_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt	= compat_tcp_setsockopt,
	.compat_getsockopt	= compat_tcp_getsockopt,
#endif
};


EXPORT_SYMBOL(mtcpsub_prot);
