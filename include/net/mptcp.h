/*
 *	MPTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Part of this code is inspired from an early version for linux 2.4 by
 *      Costin Raiciu.
 *
 *      date : Aug 10
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _MPTCP_H
#define _MPTCP_H

#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp.h>

#include <crypto/hash.h>
#include <net/mptcp_pm.h>
#include <net/tcp.h>

#ifdef CONFIG_MPTCP_DEBUG
#define mptcp_debug(fmt, args...) printk(KERN_DEBUG __FILE__ ": " fmt, ##args)
#else
#define mptcp_debug(fmt, args...)
#endif

extern int sysctl_mptcp_scheduler;
#define MPTCP_SCHED_MAX 2
extern struct sock *(*mptcp_schedulers[MPTCP_SCHED_MAX])
		(struct multipath_pcb *, struct sk_buff *);

#ifdef MPTCP_RCV_QUEUE_DEBUG
struct mptcp_debug {
	const char *func_name;
	u32 seq;
	int len;
	int end;		/* 1 if this is the last debug info */
};

void print_debug_array(void);
void freeze_rcv_queue(struct sock *sk, const char *func_name);
#endif

#ifdef MPTCP_DEBUG_TIMER
static void mptcp_debug_timeout(unsigned long data)
{
	printk(KERN_ERR "MPTCP debug timeout ! Function %s\n", (char *)data);
	BUG();
}

static DEFINE_TIMER(mptcp_debug_timer, mptcp_debug_timeout, 0, 0);
#define mptcp_start_debug_timer(delay)					\
	do {								\
		mptcp_debug_timer.expires = jiffies + delay * HZ;	\
		mptcp_debug_timer.data = (unsigned long)__func_;	\
		add_timer(&mptcp_debug_timer);				\
	} while (0)

static void mptcp_stop_debug_timer(void)
{
	del_timer(&mptcp_debug_timer);
}
#endif

#define MPCB_FLAG_SERVER_SIDE	0  /* This mpcb belongs to a server side
				    * connection. (obtained through a listen)
				    */

struct multipath_options {
	int	num_addr4;
	int	num_addr6;
	struct	mptcp_loc4 addr4[MPTCP_MAX_ADDR];
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct	mptcp_loc6 addr6[MPTCP_MAX_ADDR];
#endif
	__u32	mptcp_rem_token;	/* Received token */
	__u32	mptcp_recv_random_number;
	__u64	mptcp_rem_key;	/* Remote key */
	__u64	mptcp_recv_tmac;
	u32	fin_dsn; /* DSN of the byte  FOLLOWING the Data FIN */
	__u8	mptcp_recv_mac[20];
	__u8	mptcp_opt_type;
	u8	list_rcvd:1, /* 1 if IP list has been received */
		dfin_rcvd:1,
		mp_fail:1,
		dss_csum:1;
};

struct multipath_pcb {

	/* The meta socket is used to create the subflow sockets. Thus, if we
	 * need to support IPv6 socket creation, the meta socket should be a
	 * tcp6_sock.
	 * The function pointers are set specifically. */

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct tcp6_sock tp;
#else
	struct tcp_sock tp;
#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

	/* list of sockets in this multipath connection */
	struct tcp_sock *connection_list;

	/* Master socket, also part of the connection_list, this
	 * socket is the one that the application sees.
	 */
	struct sock *master_sk;

	struct multipath_options rx_opt;

	/* socket count in this connection */
	int cnt_subflows;
	int cnt_established;
	int last_pi_selected;

	struct sk_buff_head reinject_queue;
	unsigned long flags;	/* atomic, for bits see
				 * MPCB_FLAG_XXX
				 */
	u32 noneligible;	/* Path mask of temporarily non
				 * eligible subflows by the
				 * scheduler
				 */
	u8	send_infinite_mapping:1,
		infinite_mapping:1,
		send_mp_fail:1;
	u32	csum_cutoff_seq;

	__u32	mptcp_loc_token;
	__u64	mptcp_loc_key;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	/* Alternative option pointers. If master sk is IPv4 these are IPv6 and
	 * vice versa. Used to setup correct function pointers for sub sks of
	 * different address family than the master socket.
	 */
	const struct inet_connection_sock_af_ops *icsk_af_ops_alt;
	struct proto *sk_prot_alt;
	struct timer_list dad_waiter;
#endif

	struct list_head collide_tk;
	uint8_t addr4_unsent;	/* num of IPv4 addrs not yet sent to our peer */
	uint8_t addr6_unsent;	/* num of IPv6 addrs not yet sent to our peer */

	/* We need to store the set of local addresses, so that we have a stable
	   view of the available addresses. Playing with the addresses directly
	   in the system would expose us to concurrency problems */
	struct mptcp_loc4 addr4[MPTCP_MAX_ADDR];
	int num_addr4;		/* num of addresses actually stored above. */

	struct mptcp_loc6 addr6[MPTCP_MAX_ADDR];
	int num_addr6;

	struct path4 *pa4;
	int pa4_size;
	struct path6 *pa6;
	int pa6_size;

	/* Next pi to pick up in case a new path becomes available */
	int next_unused_pi;
};

static inline int mptcp_pi_to_flag(int pi)
{
	BUG_ON(!pi);
	return 1 << (pi - 1);
}

/* Possible return values from mptcp_queue_skb */
#define MPTCP_EATEN 1  /* The skb has been (fully or partially) eaten by
		       * the app
		       */
#define MPTCP_QUEUED 2 /* The skb has been queued in the mpcb ofo queue */

/* Another flag as in tcp_input.c - put it here because otherwise we need to
 * export all the flags from tcp_input.c to a header file.
 */
#define MPTCP_FLAG_SEND_RESET	0x4000

#ifdef CONFIG_MPTCP

#define MPTCP_SUB_CAPABLE			0
#define MPTCP_SUB_LEN_CAPABLE_SYN		12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN		12
#define MPTCP_SUB_LEN_CAPABLE_ACK		20
#define MPTCP_SUB_LEN_CAPABLE_ALIGN_ACK		20
#define MPTCP_MP_CAPABLE_TYPE_SYN		1
#define MPTCP_MP_CAPABLE_TYPE_ACK		2

#define MPTCP_SUB_JOIN			1
#define MPTCP_SUB_LEN_JOIN_SYN		12
#define MPTCP_SUB_LEN_JOIN_ALIGN_SYN	12
#define MPTCP_SUB_LEN_JOIN_SYNACK	16
#define MPTCP_SUB_LEN_JOIN_ALIGN_SYNACK	16
#define MPTCP_SUB_LEN_JOIN_ACK		24
#define MPTCP_SUB_LEN_JOIN_ALIGN_ACK	24
#define MPTCP_MP_JOIN_TYPE_SYN		1
#define MPTCP_MP_JOIN_TYPE_SYNACK	2
#define MPTCP_MP_JOIN_TYPE_ACK		3

#define MPTCP_SUB_DSS		2
#define MPTCP_SUB_LEN_DSS	4
#define MPTCP_SUB_LEN_DSS_ALIGN	4

/* Lengths for seq and ack are the ones without the generic MPTCP-option header,
 * as they are part of the DSS-option.
 * To get the total length, just add the different options together.
 */
#define MPTCP_SUB_LEN_SEQ	10
#define MPTCP_SUB_LEN_SEQ_CSUM	12
#define MPTCP_SUB_LEN_SEQ_ALIGN	12

#define MPTCP_SUB_LEN_ACK	4
#define MPTCP_SUB_LEN_ACK_ALIGN	4

#define MPTCP_SUB_ADD_ADDR		3
#define MPTCP_SUB_LEN_ADD_ADDR4		8
#define MPTCP_SUB_LEN_ADD_ADDR6		20
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN	8
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN	20

#define MPTCP_SUB_FAIL		6
#define MPTCP_SUB_LEN_FAIL	8
#define MPTCP_SUB_LEN_FAIL_ALIGN	8

#define OPTION_MP_CAPABLE       (1 << 5)
#define OPTION_DSN_MAP          (1 << 6)
#define OPTION_DATA_FIN         (1 << 7)
#define OPTION_DATA_ACK         (1 << 8)
#define OPTION_ADD_ADDR         (1 << 9)
#define OPTION_MP_JOIN          (1 << 10)
#define OPTION_MP_FAIL		(1 << 11)

struct mptcp_option {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_capable {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
	__u8	s:1,
		rsv:6,
		c:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
	__u8	c:1,
		rsv:6,
		s:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_join {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:3,
		b:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
};

struct mp_dss {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		A:1,
		a:1,
		M:1,
		m:1,
		F:1,
		rsv2:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:3,
		F:1,
		m:1,
		M:1,
		a:1,
		A:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_add_addr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ipver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ipver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
};

struct mp_fail {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u32	data_seq;
};

/* Two separate cases must be handled:
 * -a mapping option has been received. Then data_seq and end_data_seq are
 *  defined, and we disambiguate based on data_len (if not zero, the mapping
 *  if received but not applied by get_dataseq_mapping().
 * -no mapping option has been received. Then data_len is not defined, and we
 *  disambiguate based on data_seq and end_data_seq (if they are still zero,
 *  the stored mapping has not been applied by get_dataseq_mapping())
 */
#define is_mapping_applied(skb) BUG_ON(TCP_SKB_CB(skb)->data_len ||	\
				       (!TCP_SKB_CB(skb)->data_seq &&	\
					!TCP_SKB_CB(skb)->end_data_seq))

/* Default MSS for MPTCP
 * All subflows will be using that MSS. If any subflow has a lower MSS, it is
 * just not used. */
#define MPTCP_MSS 1400
extern int sysctl_mptcp_mss;
extern int sysctl_mptcp_ndiffports;
extern int sysctl_mptcp_enabled;
extern int sysctl_mptcp_checksum;

static inline int mptcp_sysctl_mss(void)
{
	return sysctl_mptcp_mss;
}

static inline __u32 mptcp_skb_data_ack(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->data_ack;
}

static inline __u32 mptcp_skb_data_seq(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->data_seq;
}

static inline __u32 mptcp_skb_end_data_seq(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->end_data_seq;
}

/* Iterates over all subflows */
#define mptcp_for_each_tp(mpcb, tp)					\
	for ((tp) = (mpcb)->connection_list; (tp); (tp) = (tp)->next)

#define mptcp_for_each_sk(mpcb, sk, tp)					\
	for ((sk) = (struct sock *)(mpcb)->connection_list,		\
		     (tp) = tcp_sk(sk);					\
	     sk;							\
	     sk = (struct sock *) tcp_sk(sk)->next, tp = tcp_sk(sk))

#define mptcp_for_each_sk_safe(__mpcb, __sk, __temp)			\
	for (__sk = (struct sock *)(__mpcb)->connection_list,		\
		     __temp = __sk ? (struct sock *)tcp_sk(__sk)->next : NULL; \
	     __sk;							\
	     __sk = __temp,						\
		     __temp = __sk ? (struct sock *)tcp_sk(__sk)->next : NULL)

/**
 * Returns 1 if any subflow meets the condition @cond,
 * else return 0. Moreover, if 1 is returned, sk points to the
 * first subsocket that verified the condition.
 * - non MPTCP behaviour: If MPTCP is NOT supported for this connection,
 *   @mpcb must be set to NULL and sk to the struct sock. In that
 *   case the condition is tested against this unique socket.
 */
#define mptcp_test_any_sk(mpcb, sk, cond)			\
	({	int __ans = 0;					\
		struct tcp_sock *__tp;				\
		if (!mpcb) {					\
			if (cond)				\
				__ans = 1;			\
		} else {					\
			mptcp_for_each_sk(mpcb, sk, __tp) {	\
				if (cond) {			\
					__ans = 1;		\
					break;			\
				}				\
			}					\
		}						\
		__ans;						\
	})

int mptcp_queue_skb(struct sock *sk, struct sk_buff *skb);
int mptcp_add_meta_ofo_queue(struct sock *meta_sk, struct sk_buff *skb,
			     struct sock *sk);
void mptcp_ofo_queue(struct multipath_pcb *mpcb);
void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp);
void mptcp_ofo_queue_init(void);
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied);
int mptcp_alloc_mpcb(struct sock *master_sk);
void mptcp_add_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mptcp_del_sock(struct sock *sk);
void mptcp_update_metasocket(struct sock *sock, struct multipath_pcb *mpcb);
void mptcp_reinject_data(struct sock *orig_sk, int clone_it);
int mptcp_get_dataseq_mapping(struct tcp_sock *tp, struct sk_buff *skb);
int mptcp_init_subsockets(struct multipath_pcb *mpcb, u32 path_indices);
void mptcp_update_window_clamp(struct tcp_sock *tp);
void mptcp_update_sndbuf(struct multipath_pcb *mpcb);
void mptcp_set_state(struct sock *sk, int state);
void mptcp_push_frames(struct sock *sk);
void mptcp_skb_entail_init(struct sock *sk, struct sk_buff *skb);
void mptcp_skb_entail(struct sock *sk, struct sk_buff *skb);
struct sk_buff *mptcp_next_segment(struct sock *sk, int *reinject);
void mpcb_release(struct multipath_pcb *mpcb);
void mptcp_release_sock(struct sock *sk);
void mptcp_clean_rtx_queue(struct sock *meta_sk);
void mptcp_send_fin(struct sock *meta_sk);
void mptcp_send_reset(struct sock *sk, struct sk_buff *skb);
void mptcp_parse_options(uint8_t *ptr, int opsize,
		struct tcp_options_received *opt_rx,
		struct multipath_options *mopt,
		struct sk_buff *skb);
void mptcp_syn_options(struct sock *sk, struct tcp_out_options *opts,
		       unsigned *remaining);
void mptcp_synack_options(struct request_sock *req,
			  struct tcp_out_options *opts,
			  unsigned *remaining);
void mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       struct tcp_out_options *opts, unsigned *size);
void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			 struct tcp_out_options *opts);
void mptcp_close(struct sock *meta_sk, long timeout);
void mptcp_detach_unused_child(struct sock *sk);
void mptcp_set_bw_est(struct tcp_sock *tp, u32 now);
int do_mptcp(struct sock *sk);
int mptcp_check_req_master(struct sock *child, struct request_sock *req,
		struct multipath_options *mopt);
struct sock *mptcp_check_req_child(struct sock *sk, struct sock *child,
		struct request_sock *req, struct request_sock **prev);
void mptcp_select_window(struct tcp_sock *tp, u32 new_win);
u32 __mptcp_select_window(struct sock *sk);
int mptcp_try_rmem_schedule(struct sock *tp, unsigned int size);
void mptcp_update_window_check(struct tcp_sock *meta_tp,
			       const struct sk_buff *skb, u32 data_ack);
void mptcp_combine_dfin(struct sk_buff *skb, struct tcp_sock *meta_tp,
			struct sock *subsk);
void mptcp_set_data_size(struct tcp_sock *tp, struct sk_buff *skb, int copy);
int mptcp_push(struct sock *sk, int flags, int mss_now, int nonagle);
void mptcp_key_sha1(u64 key, u32 *token);
void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		     u32 *hash_out);
void mptcp_clean_rtx_infinite(struct sk_buff *skb, struct sock *sk);
int mptcp_fin(struct multipath_pcb *mpcb, struct sock *sk);
void mptcp_retransmit_timer(struct sock *meta_sk);
void mptcp_mark_reinjected(struct sock *sk, struct sk_buff *skb);
struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk);

static inline int mptcp_skb_cloned(const struct sk_buff *skb,
				   const struct tcp_sock *tp)
{
	/* If it does not has a DSS-mapping (MPTCPHDR_SEQ), it does not come
	 * from the meta-level send-queue and thus dataref is as usual.
	 * If it has a DSS-mapping dataref is at least 2
	 */
	return tp->mpc &&
	       ((!(TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_SEQ) && skb_cloned(skb)) ||
		((TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_SEQ) && skb->cloned &&
		 (atomic_read(&skb_shinfo(skb)->dataref) & SKB_DATAREF_MASK) > 2));
}

static inline int mptcp_is_data_fin(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN;
}

static inline struct multipath_pcb *mpcb_from_tcpsock(const struct tcp_sock *tp)
{
	return tp->mpcb;
}

static inline struct sock *mptcp_meta_sk(struct sock *sk)
{
	return (struct sock *)tcp_sk(sk)->mpcb;
}

static inline
struct multipath_pcb *mptcp_mpcb_from_req_sk(const struct request_sock *req)
{
	return req->mpcb;
}

static inline int is_meta_tp(const struct tcp_sock *tp)
{
	return tp->mpcb && mpcb_meta_tp(mpcb_from_tcpsock(tp)) == tp;
}

static inline int is_meta_sk(const struct sock *sk)
{
	return sk->sk_protocol == IPPROTO_TCP && tcp_sk(sk)->mpcb &&
	       (struct tcp_sock *)tcp_sk(sk)->mpcb == tcp_sk(sk);
}

static inline int is_master_tp(const struct tcp_sock *tp)
{
	return !tp->slave_sk && !is_meta_tp(tp);
}

static inline int mptcp_req_sk_saw_mpc(const struct request_sock *req)
{
	return req->saw_mpc;
}

static inline int mptcp_sk_attached(const struct sock *sk)
{
	return tcp_sk(sk)->attached;
}

static inline void mptcp_init_mp_opt(struct multipath_options *mopt)
{
	mopt->list_rcvd = mopt->num_addr4 = mopt->num_addr6 = 0;
	mopt->mptcp_opt_type = 0;
	mopt->mp_fail = 0;
	mopt->mptcp_rem_key = 0;
}

/**
 * This function is almost exactly the same as sk_wmem_free_skb.
 * The only difference is that we call kfree_skb instead of __kfree_skb.
 * This is important because a subsock may want to remove an skb,
 * while the meta-sock still has a reference to it.
 */
static inline void mptcp_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);
	kfree_skb(skb);
}

static inline int is_local_addr4(const u32 addr)
{
	struct net_device *dev;
	int ans = 0;
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		if (netif_running(dev)) {
			struct in_device *in_dev = dev->ip_ptr;
			struct in_ifaddr *ifa;

			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_address == addr) {
					ans = 1;
					goto out;
				}
			}
		}
	}

out:
	read_unlock(&dev_base_lock);
	return ans;
}

static inline int mptcp_sock_destruct(struct sock *sk)
{
	if (sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP &&
	    tcp_sk(sk)->mpcb) {
		if (is_meta_sk(sk)) {
			mpcb_release(tcp_sk(sk)->mpcb);
			return 1;
		} else {
			/* It must have been detached by
			 * inet_csk_destroy_sock()
			 */
			BUG_ON(mptcp_sk_attached(sk));
			/* Taken when mpcb pointer was set */
			sock_put(mpcb_meta_sk(tcp_sk(sk)->mpcb));
		}
	}
	return 0;
}

static inline void mptcp_update_pointers(struct sock **sk,
		struct tcp_sock **tp, struct multipath_pcb **mpcb)
{
	/* The following happens if we entered the function without
	 * being established, then received the mpc flag while
	 * inside the function.
	 */
	if (((mpcb && !(*mpcb)) || !is_meta_sk(*sk)) && (*tp)->mpc) {
		*sk = mptcp_meta_sk(*sk);
		*tp = tcp_sk(*sk);

		if (mpcb)
			*mpcb = (*tp)->mpcb;
	}
}

static inline int mptcp_check_rtt(struct tcp_sock *tp, int time)
{
	struct multipath_pcb *mpcb = tp->mpcb;
	struct tcp_sock *tp_tmp;
	u32 rtt_max = 0;

	/* In MPTCP, we take the max delay across all flows,
	 * in order to take into account meta-reordering buffers.
	 */
	mptcp_for_each_tp(mpcb, tp_tmp) {
		if (rtt_max < (tp_tmp->rcv_rtt_est.rtt >> 3))
			rtt_max = (tp_tmp->rcv_rtt_est.rtt >> 3);
	}
	if (time < rtt_max || !rtt_max)
		return 1;

	return 0;
}

static inline void mptcp_path_array_check(struct multipath_pcb *mpcb)
{
	if (unlikely(mpcb && mpcb->rx_opt.list_rcvd)) {
		mpcb->rx_opt.list_rcvd = 0;
		mptcp_update_patharray(mpcb);
		mptcp_send_updatenotif(mpcb);
	}
}

static inline int mptcp_check_snd_buf(struct tcp_sock *tp)
{
	struct multipath_pcb *mpcb = (tp->mpc) ? tp->mpcb : NULL;
	struct tcp_sock *tp_it;
	u32 rtt_max = tp->srtt;

	mptcp_for_each_tp(mpcb, tp_it)
		if (rtt_max < tp_it->srtt)
			rtt_max = tp_it->srtt;

	return max_t(unsigned int, tp->cur_bw_est * (rtt_max >> 3),
			tp->reordering + 1);
}

static inline void mptcp_retransmit_queue(struct sock *sk)
{
	/* Do not reinject, if tp->pf == 1, because this means we have already
	 * reinjected the packets. And as long as tp->pf == 1, no new data could
	 * have gone on the send-queue. */
	if (tcp_sk(sk)->mpc && !tcp_sk(sk)->pf &&
	    sk->sk_state == TCP_ESTABLISHED && tcp_sk(sk)->mpcb->cnt_established > 0)
		mptcp_reinject_data(sk, 1);
}

static inline int mptcp_sk_can_send(struct sock *sk)
{
	return sk->sk_state == TCP_ESTABLISHED ||
	       sk->sk_state == TCP_CLOSE_WAIT;
}

static inline void mptcp_set_rto(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk), *tp_it;
	struct sock *sk_it;
	__u32 max_rto = 0;

	if (!tp->mpc || !tp->mpcb)
		return;

	mptcp_for_each_sk(tp->mpcb, sk_it, tp_it) {
		if (mptcp_sk_can_send(sk_it) &&
		    inet_csk(sk_it)->icsk_rto > max_rto)
			max_rto = inet_csk(sk_it)->icsk_rto;
	}
	if(max_rto)
		inet_csk((struct sock *)tp->mpcb)->icsk_rto = max_rto * 2;
}

/* Maybe we could merge this with tcp_rearm_rto().
 * But then we will have to add if's in the tcp-stack.
 */
static inline void mptcp_reset_xmit_timer(struct sock *meta_sk)
{
	if (!is_meta_sk(meta_sk))
		return;

	if (!tcp_sk(meta_sk)->packets_out)
		inet_csk_clear_xmit_timer(meta_sk, ICSK_TIME_RETRANS);
	else
		inet_csk_reset_xmit_timer(meta_sk, ICSK_TIME_RETRANS,
				  inet_csk(meta_sk)->icsk_rto, TCP_RTO_MAX);
}

static inline void mptcp_include_mpc(struct tcp_sock *tp)
{
	if (tp->mpc) {
		tp->include_mpc = 1;
	}
}

static inline int mptcp_fallback_infinite(struct tcp_sock *tp,
		struct sk_buff *skb)
{
	/* If data has been acknowleged on the meta-level, fully_established
	 * will have been set before and thus we will not fall back to infinite
	 * mapping. */
	if (likely(tp->fully_established))
		return 0;

	if (TCP_SKB_CB(skb)->flags & (TCPHDR_SYN | TCPHDR_FIN))
		return 0;

	mptcp_debug("%s %#x will fallback - pi %d\n", __func__,
		    tp->mpcb->mptcp_loc_token, tp->path_index);
	if (is_master_tp(tp))
		tp->mpcb->send_infinite_mapping = 1;
	else
		return MPTCP_FLAG_SEND_RESET;

	return 0;
}

static inline void mptcp_mp_fail_rcvd(struct multipath_pcb *mpcb,
				      struct tcphdr *th)
{
	if (!mpcb)
		return;

	if (unlikely(mpcb->rx_opt.mp_fail)) {
		struct sock *meta_sk = (struct sock *)mpcb;

		mpcb->rx_opt.mp_fail = 0;

		if (!th->rst && !mpcb->infinite_mapping) {
			mpcb->send_infinite_mapping = 1;
			/* We resend everything that has not been acknowledged */
			meta_sk->sk_send_head = tcp_write_queue_head(meta_sk);

			/* We artificially restart the whole send-queue. Thus,
			 * it is as if no packets are in flight */
			tcp_sk(meta_sk)->packets_out = 0;
		}
	}
}

#if (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline int mptcp_get_path_family(struct multipath_pcb *mpcb,
					int path_index)
{
	int i;

	for (i = 0; i < mpcb->pa4_size; i++) {
		if (mpcb->pa4[i].path_index == path_index)
			return AF_INET;
	}
	for (i = 0; i < mpcb->pa6_size; i++) {
		if (mpcb->pa6[i].path_index == path_index)
			return AF_INET6;
	}
	return -1;
}

static inline struct sock *mptcp_sk_clone(struct sock *sk, int family,
		int priority)
{
	struct sock *newsk;
	struct multipath_pcb *mpcb = (struct multipath_pcb *) sk;

	newsk = sk_prot_alloc(mpcb->sk_prot_alt, priority, family);

	if (newsk != NULL) {
		mptcp_inherit_sk(sk, newsk, family, priority);
		inet_csk(newsk)->icsk_af_ops = mpcb->icsk_af_ops_alt;
	}

	return newsk;
}

static inline int mptcp_v6_is_v4_mapped(struct sock *sk)
{
	return sk->sk_family == AF_INET6 &&
		ipv6_addr_type(&inet6_sk(sk)->saddr) == IPV6_ADDR_MAPPED;
}

#else /* (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)) */

static inline int mptcp_get_path_family(struct multipath_pcb *mpcb,
					int path_index)
{
	return AF_INET;
}
static inline struct sock *mptcp_sk_clone(struct sock *sk, int family,
		int priority)
{
	return sk_clone(sk, priority);
}

static inline int mptcp_v6_is_v4_mapped(struct sock *sk)
{
	return 0;
}

#endif /* (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)) */

#else /* CONFIG_MPTCP */

#define is_mapping_applied(skb) (0))

static inline int mptcp_sysctl_mss(void)
{
	return 0;
}

static inline __u32 mptcp_skb_data_ack(const struct sk_buff *skb)
{
	return 0;
}

static inline __u32 mptcp_skb_data_seq(const struct sk_buff *skb)
{
	return 0;
}

static inline __u32 mptcp_skb_end_data_seq(const struct sk_buff *skb)
{
	return 0;
}


/* Without MPTCP, we just do one iteration
 * over the only socket available. This assumes that
 * the sk/tp arg is the socket in that case.
 */
#define mptcp_for_each_tp(mpcb, tp)
#define mptcp_for_each_sk(mpcb, sk, tp)
#define mptcp_for_each_sk_safe(__mpcb, __sk, __temp)

/* If MPTCP is not supported, we just need to evaluate the condition
 * against sk, which is the single socket in use.
 */
#define mptcp_test_any_sk(mpcb, sk, cond)				\
	({								\
		int __ans = 0;						\
		if (cond)						\
			__ans = 1;					\
		__ans;							\
	})

static inline int mptcp_skb_cloned(const struct sk_buff *skb,
				   const struct tcp_sock *tp)
{
	return 0;
}
static inline int mptcp_is_data_fin(const struct sk_buff *skb)
{
	return 0;
}
static inline struct multipath_pcb *mpcb_from_tcpsock(const struct tcp_sock *tp)
{
	return NULL;
}
static inline struct sock *mptcp_meta_sk(const struct sock *sk)
{
	return NULL;
}
static inline
struct multipath_pcb *mptcp_mpcb_from_req_sk(const struct request_sock *req)
{
	return NULL;
}
static inline int is_meta_tp(const struct tcp_sock *tp)
{
	return 0;
}
static inline int is_meta_sk(const struct sock *tp)
{
	return 0;
}
static inline int is_master_tp(const struct tcp_sock *tp)
{
	return 0;
}
static inline int mptcp_req_sk_saw_mpc(const struct request_sock *req)
{
	return 0;
}
static inline int mptcp_sk_attached(const struct sock *sk)
{
	return 0;
}
static inline int mptcp_queue_skb(const struct sock *sk,
				  const struct sk_buff *skb)
{
	return 0;
}
static inline void mptcp_ofo_queue(const struct multipath_pcb *mpcb) {}
static inline void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp) {}
static inline void mptcp_cleanup_rbuf(const struct sock *meta_sk, int copied) {}
static inline void mptcp_add_sock(const struct multipath_pcb *mpcb,
				  const struct tcp_sock *tp) {}
static inline void mptcp_del_sock(const struct sock *sk) {}
static inline void mptcp_update_metasocket(const struct sock *sock,
					   const struct multipath_pcb *mpcb) {}
static inline void mptcp_reinject_data(const struct sock *orig_sk,
				       int clone_it) {}
static inline int mptcp_get_dataseq_mapping(const struct tcp_sock *tp,
					    const struct sk_buff *skb)
{
	return 0;
}
static inline int mptcp_init_subsockets(const struct multipath_pcb *mpcb,
					u32 path_indices)
{
	return 0;
}
static inline void mptcp_update_window_clamp(const struct tcp_sock *tp) {}
static inline void mptcp_update_sndbuf(const struct multipath_pcb *mpcb) {}
static inline void mptcp_set_state(const struct sock *sk, int state) {}
static inline void mptcp_push_frames(const struct sock *sk) {}
static inline void mptcp_skb_entail_init(const struct sock *sk,
					 const struct sk_buff *skb) {}
static inline void mptcp_skb_entail(const struct sock *sk,
				    const struct sk_buff *skb) {}
static inline struct sk_buff *mptcp_next_segment(const struct sock *sk,
						 const int *reinject)
{
	return NULL;
}
static inline void mpcb_release(const struct multipath_pcb *mpcb) {}
static inline void mptcp_release_sock(const struct sock *sk) {}
static inline void mptcp_clean_rtx_queue(const struct sock *meta_sk) {}
static inline void mptcp_clean_rtx_infinite(const struct sk_buff *skb,
					    const struct sock *sk) {}
static inline void mptcp_retransmit_timer(const struct sock *meta_sk) {}
static inline void mptcp_mark_reinjected(const struct sock *sk,
					 const struct sk_buff *skb) {}
static inline struct sk_buff *mptcp_rcv_buf_optimization(const struct sock *sk)
{
	return NULL;
}
static inline void mptcp_set_rto(const struct sock *sk) {}
static inline void mptcp_reset_xmit_timer(const struct sock *meta_sk) {}
static inline void mptcp_send_fin(const struct sock *meta_sk) {}
static inline void mptcp_parse_options(const uint8_t *ptr, const int opsize,
				       const struct tcp_options_received *opt_rx,
				       const struct multipath_options *mopt,
				       const struct sk_buff *skb) {}
static inline void mptcp_close(const struct sock *meta_sk, long timeout) {}
static inline void mptcp_detach_unused_child(const struct sock *sk) {}
static inline void mptcp_set_bw_est(const struct tcp_sock *tp, u32 now) {}
static inline int do_mptcp(const struct sock *sk)
{
	return 0;
}
static inline int mptcp_check_req_master(const struct sock *child,
					 const struct request_sock *req,
					 const struct multipath_options *mopt)
{
	return 0;
}
static inline struct sock *mptcp_check_req_child(const struct sock *sk,
						 const struct sock *child,
						 const struct request_sock *req,
						 struct request_sock **prev)
{
	return 0;
}
static inline void mptcp_select_window(const struct tcp_sock *tp, u32 new_win) {}
static inline u32 __mptcp_select_window(const struct sock *sk)
{
	return 0;
}
static inline int mptcp_try_rmem_schedule(const struct sock *tp,
					  unsigned int size)
{
	return 0;
}
static inline void mptcp_update_window_check(const struct tcp_sock *meta_tp,
					     const struct sk_buff *skb,
					     u32 data_ack) {}
static inline void mptcp_set_data_size(const struct tcp_sock *tp,
				       const struct sk_buff *skb, int copy) {}
static inline int mptcp_push(const struct sock *sk, int flags,
			     int mss_now, int nonagle)
{
	return 0;
}
static inline void mptcp_fallback(const struct sock *master_sk) {}
static inline int mptcp_fallback_infinite(const struct tcp_sock *tp,
					  const struct sk_buff *skb)
{
	return 0;
}
static inline void mptcp_mp_fail_rcvd(const struct multipath_pcb *mpcb,
				      const struct tcphdr *th) {}
static inline void mptcp_init_mp_opt(const struct multipath_options *mopt) {}
static inline void mptcp_wmem_free_skb(const struct sock *sk,
				       const struct sk_buff *skb) {}
static inline int is_local_addr4(u32 addr)
{
	return 0;
}
static inline int mptcp_sock_destruct(const struct sock *sk)
{
	return 0;
}
static inline void mptcp_update_pointers(struct sock **sk,
					 struct tcp_sock **tp,
					 struct multipath_pcb **mpcb) {}
static inline int mptcp_check_rtt(const struct tcp_sock *tp, int time)
{
	return 0;
}
static inline void mptcp_path_array_check(const struct multipath_pcb *mpcb) {}
static inline int mptcp_check_snd_buf(const struct tcp_sock *tp)
{
	return 0;
}
static inline void mptcp_retransmit_queue(const struct sock *sk) {}
static inline void mptcp_include_mpc(const struct tcp_sock *tp) {}
static inline void mptcp_send_reset(const struct sock *sk,
				    const struct sk_buff *skb) {}
static inline int mptcp_get_path_family(const struct multipath_pcb *mpcb,
					int path_index)
{
	return 0;
}
static inline struct sock *mptcp_sk_clone(const struct sock *sk,
					  int family, int priority)
{
	return NULL;
}
#endif /* CONFIG_MPTCP */

#endif /* _MPTCP_H */
