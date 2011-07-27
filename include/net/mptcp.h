/*
 *	MPTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Part of this code is inspired from an early version for linux 2.4 by
 *      Costin Raiciu.
 *
 *      date : May 10
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _MPTCP_H
#define _MPTCP_H

#include <linux/aio.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp_options.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>

#include <net/mptcp_pm.h>

#ifdef CONFIG_MPTCP_DEBUG
#define mptcp_debug(fmt, args...) printk(KERN_DEBUG __FILE__ ": " fmt, ##args)
#else
#define mptcp_debug(fmt, args...)
#endif

extern int sysctl_mptcp_scheduler;
#define MPTCP_SCHED_MAX 1
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

extern struct proto mptcpsub_prot;

#define MPCB_FLAG_SERVER_SIDE	0  /* This mpcb belongs to a server side
				    * connection. (obtained through a listen)
				    */

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
	/* socket count in this connection */
	int cnt_subflows;
	int cnt_established;

	struct multipath_options received_options;
	struct tcp_options_received tcp_opt;

	struct sk_buff_head reinject_queue;
	unsigned long flags;	/* atomic, for bits see
				 * MPCB_FLAG_XXX
				 */
	u32 noneligible;	/* Path mask of temporarily non
				 * eligible subflows by the
				 * scheduler
				 */

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	/* Alternative option pointers. If master sk is IPv4 these are IPv6 and
	 * vice versa. Used to setup correct function pointers for sub sks of
	 * different address family than the master socket.
	 */
	const struct inet_connection_sock_af_ops *icsk_af_ops_alt;
	struct proto *sk_prot_alt;
#endif

#ifdef CONFIG_MPTCP_PM
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
#endif
};

#define	MPTCP_SUB_CAPABLE	0
#define MPTCP_SUB_LEN_CAPABLE	8
#define MPTCP_SUB_LEN_CAPABLE_ALIGN	8

#define	MPTCP_SUB_JOIN		1
#define MPTCP_SUB_LEN_JOIN	8
#define MPTCP_SUB_LEN_JOIN_ALIGN	8

#define	MPTCP_SUB_DSS		2
#define MPTCP_SUB_LEN_DSS	4
#define MPTCP_SUB_LEN_DSS_ALIGN		4

/* Lengths for seq and ack are the ones without the generic MPTCP-option header,
 * as they are part of the DSS-option.
 * To get the total length, just add the different options together.
 */
#define MPTCP_SUB_LEN_SEQ	10
#define MPTCP_SUB_LEN_SEQ_CSUM	12
#define MPTCP_SUB_LEN_SEQ_ALIGN		12

#define MPTCP_SUB_LEN_ACK	4
#define MPTCP_SUB_LEN_ACK_ALIGN		4

#define MPTCP_SUB_ADD_ADDR	3
#define MPTCP_SUB_LEN_ADD_ADDR4	8
#define MPTCP_SUB_LEN_ADD_ADDR6	20
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN	8
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN	20

#define MPTCP_SUB_FAIL		6
#define MPTCP_SUB_LEN_FAIL	12

#ifdef DEBUG_PITOFLAG
static inline int PI_TO_FLAG(int pi)
{
	BUG_ON(!pi);
	return 1 << (pi - 1);
}
#else
#define PI_TO_FLAG(pi) (1 << (pi - 1))
#endif

/* Possible return values from mptcp_queue_skb */
#define MPTCP_EATEN 1  /* The skb has been (fully or partially) eaten by
		       * the app
		       */
#define MPTCP_QUEUED 2 /* The skb has been queued in the mpcb ofo queue */

#ifdef CONFIG_MPTCP


/* Functions and structures defined elsewhere but needed in mptcp.c */
extern int inet_create(struct net *net, struct socket *sock, int protocol,
		int kern);
extern void tcp_queue_skb(struct sock *sk, struct sk_buff *skb);
extern void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags);
extern int tcp_close_state(struct sock *sk);
extern struct timewait_sock_ops tcp_timewait_sock_ops;
extern void __release_sock(struct sock *sk, struct multipath_pcb *mpcb);
extern int tcp_prune_queue(struct sock *sk);
extern int tcp_prune_ofo_queue(struct sock *sk);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
extern int inet6_create(struct net *net, struct socket *sock, int protocol,
		int kern);
extern const struct inet_connection_sock_af_ops ipv4_specific;
extern const struct inet_connection_sock_af_ops ipv6_specific;
extern struct proto mptcpsub_prot;
extern int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr,
			  int addr_len);
extern void tcp_v6_hash(struct sock *sk);
extern void tcp_v6_destroy_sock(struct sock *sk);
extern struct timewait_sock_ops tcp6_timewait_sock_ops;
extern struct sock *sk_prot_alloc(struct proto *prot, gfp_t priority,
		int family);
extern void mptcp_inherit_sk(struct sock *sk, struct sock *newsk, int family,
		gfp_t flags);

#endif /* CONFIG_IPV6 || CONFIG_IPV6_MODULE */

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

#define mpcb_from_tcpsock(__tp) ((__tp)->mpcb)
#define mptcp_mpcb_from_req_sk(__req) ((__req)->mpcb)
#define mptcp_meta_sk(sk) ((struct sock *)tcp_sk(sk)->mpcb)
#define is_meta_tp(__tp) ((__tp)->mpcb && (struct tcp_sock *)((__tp)->mpcb) \
			  == __tp)
#define is_meta_sk(sk) (sk->sk_protocol == IPPROTO_TCP &&	\
			(tcp_sk(sk))->mpcb &&			\
			((struct tcp_sock *)tcp_sk(sk)->mpcb) == tcp_sk(sk))
#define is_master_tp(__tp) (!(__tp)->slave_sk && !is_meta_tp(__tp))
#define mptcp_req_sk_saw_mpc(__req) (req->saw_mpc)
#define mptcp_sk_attached(__sk) (tcp_sk(sk)->attached)

#define is_dfin_seg(mpcb, skb) (mpcb->received_options.dfin_rcvd &&	\
				mpcb->received_options.fin_dsn ==	\
				TCP_SKB_CB(skb)->end_data_seq)

#define is_dfin_seg(mpcb, skb) (mpcb->received_options.dfin_rcvd &&	\
				mpcb->received_options.fin_dsn ==	\
				TCP_SKB_CB(skb)->end_data_seq)
#define mptcp_skb_data_ack(skb) (TCP_SKB_CB(skb)->data_ack)
#define mptcp_skb_data_seq(skb) (TCP_SKB_CB(skb)->data_seq)
#define mptcp_skb_end_data_seq(skb) (TCP_SKB_CB(skb)->end_data_seq)

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
void mptcp_ofo_queue(struct multipath_pcb *mpcb);
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied);
int mptcp_check_rcv_queue(struct multipath_pcb *mpcb, struct msghdr *msg,
			size_t *len, u32 *data_seq, int *copied, int flags);
int mptcp_alloc_mpcb(struct sock *master_sk, gfp_t flags);
void mptcp_add_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mptcp_del_sock(struct sock *sk);
void mptcp_update_metasocket(struct sock *sock, struct multipath_pcb *mpcb);
int mptcp_sendmsg(struct kiocb *iocb, struct sock *master_sk,
		struct msghdr *msg, size_t size);
int mptcp_is_available(struct sock *sk);
void mptcp_reinject_data(struct sock *orig_sk, int clone_it);
int mptcp_get_dataseq_mapping(struct tcp_sock *tp, struct sk_buff *skb);
int mptcp_init_subsockets(struct multipath_pcb *mpcb, u32 path_indices);
void mptcp_update_window_clamp(struct tcp_sock *tp);
void mptcp_update_sndbuf(struct multipath_pcb *mpcb);
void mptcp_update_dsn_ack(struct multipath_pcb *mpcb, u32 start, u32 end);
void mptcp_set_state(struct sock *sk, int state);
void mptcp_push_frames(struct sock *sk);
void verif_wqueues(struct multipath_pcb *mpcb);
void mptcp_skb_entail_init(struct sock *sk, struct sk_buff *skb);
void mptcp_skb_entail(struct sock *sk, struct sk_buff *skb);
struct sk_buff *mptcp_next_segment(struct sock *sk, int *reinject);
void mpcb_release(struct multipath_pcb *mpcb);
void mptcp_release_sock(struct sock *sk);
void mptcp_clean_rtx_queue(struct sock *sk);
void mptcp_send_fin(struct sock *meta_sk);
void mptcp_parse_options(uint8_t *ptr, int opsize,
		struct tcp_options_received *opt_rx,
		struct multipath_options *mopt,
		struct sk_buff *skb);
void mptcp_close(struct sock *master_sk, long timeout);
void mptcp_detach_unused_child(struct sock *sk);
void mptcp_set_bw_est(struct tcp_sock *tp, u32 now);
int do_mptcp(struct sock *sk);
int mptcp_check_req_master(struct sock *child, struct request_sock *req,
		struct multipath_options *mopt);
int mptcp_check_req_child(struct sock *sk, struct sock *child,
		struct request_sock *req, struct request_sock **prev);
void mptcp_select_window(struct tcp_sock *tp, u32 new_win);
int mptcp_try_rmem_schedule(struct sock *tp, unsigned int size);
void mptcp_check_buffers(struct multipath_pcb *mpcb);
void mptcp_update_window_check(struct tcp_sock *meta_tp, struct sk_buff *skb,
		u32 data_ack);
void mptcp_set_data_size(struct tcp_sock *tp, struct sk_buff *skb, int copy);
int mptcp_push(struct sock *sk, int flags, int mss_now, int nonagle);
void mptcp_fallback(struct sock *master_sk);

static inline int mptcp_snd_buf_demand(struct tcp_sock *tp, u32 rtt_max)
{
	if (!tp->cur_bw_est)
		return 0;
	else
		return max_t(unsigned int,
				 (tp->cur_bw_est >>
				  tp->bw_est.shift) *
				 (rtt_max >> 3),
				 tp->reordering + 1);
}

static inline void mptcp_init_addr_list(struct multipath_options *mopt)
{
	mopt->list_rcvd = mopt->num_addr4 = mopt->num_addr6 = 0;
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

static inline int is_local_addr4(u32 addr)
{
	struct net_device *dev;
	int ans = 0;
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		if (netif_running(dev)) {
			struct in_device *in_dev = dev->ip_ptr;
			struct in_ifaddr *ifa;

			if (dev->flags & IFF_LOOPBACK)
				continue;

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

static inline struct tcp_sock *mpcb_meta_tp(const struct multipath_pcb *mpcb)
{
	return (struct tcp_sock *)mpcb;
}

static inline void mptcp_sock_destruct(struct sock *sk)
{
	if (sk->sk_protocol == IPPROTO_TCP && tcp_sk(sk)->mpcb) {
		if (is_master_tp(tcp_sk(sk)))
			mpcb_release(tcp_sk(sk)->mpcb);
		else {
			/* It must have been detached by
			 * inet_csk_destroy_sock()
			 */
			BUG_ON(mptcp_sk_attached(sk));
			sock_put(tcp_sk(sk)->mpcb->master_sk); /* Taken when
								* mpcb pointer
								* was set
								*/
		}
	}
}

static inline int mptcp_skip_offset(struct tcp_sock *tp,
		unsigned char __user **from, size_t *seglen, size_t *size)
{
	/* Skipping the offset (stored in the size argument) */
	if (tp->mpc) {
#ifdef DEBUG_TCP
		printk(KERN_ERR __FILE__ "seglen:%d\n", *seglen);
#endif
		if (*seglen >= *size) {
			*seglen -= *size;
			*from += *size;
			*size = 0;
			return 0;
		} else {
			*size -= *seglen;
			return 1;
		}
	}
	return 0;
}

static inline void mptcp_update_pointers(struct tcp_sock *tp,
		struct sock **meta_sk, struct tcp_sock **meta_tp,
		struct multipath_pcb **mpcb)
{
	/* The following happens if we entered the function without
	 * being established, then received the mpc flag while
	 * inside the function.
	 */
	if (!(*mpcb) && tp->mpc) {
		*meta_sk = (struct sock *)tp->mpcb;
		*meta_tp = tcp_sk(*meta_sk);
		*mpcb = tp->mpcb;
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
	if (unlikely(mpcb && mpcb->received_options.list_rcvd)) {
		mpcb->received_options.list_rcvd = 0;
		mptcp_update_patharray(mpcb);
		/* The server uses additional subflows
		 * only on request
		 * from the client.
		 */
		if (!test_bit(MPCB_FLAG_SERVER_SIDE, &mpcb->flags))
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

	/* Normally the send buffer is computed as twice the BDP
	 * However in multipath, a fast path may need more
	 * buffer for the following reason:
	 * Imagine 2 flows with same bw b, and delay 10 and 100,
	 * resp. Normally flow 10 will have send buffer 2*b*10
	 *                     100 will have send buffer 2*b*100
	 * In order to minimize reordering at the receiver,
	 * the sender must ensure that all consecutive packets
	 * are sent as close to each other as possible, even
	 * when spread across several subflows. If we represent
	 * a buffer as having a "height" in time units, and a
	 * "width" in bandwidth units, we must ensure
	 * that each segment is sent on the buffer with smallest
	 * "current height". (lowest filling related to his
	 * height). The subflow max height, given that its
	 * width is its bw, is computed as 2d traditionnally,
	 * thus 20 and 200 resp. here.
	 * The problem is that if buffer with delay 10 is kept
	 * at size 2*b*10, the scheduler will be able to
	 * schedule segments until height=20 maximum. In
	 * summary, the use of all buffers is reduced to the
	 * hight of the smallest one. This is why all buffers
	 * must be arranged to have equal height, that height
	 * being the highest height needed by the network, that
	 * is 2*max(delays).
	 */
	return mptcp_snd_buf_demand(tp, rtt_max);
}

static inline void mptcp_retransmit_queue(struct sock *sk)
{
	/* Do not reinject, if tp->pf == 1, because this means we have already
	 * reinjected the packets. And as long as tp->pf == 1, no new data could
	 * have gone on the send-queue. */
	if (tcp_sk(sk)->mpc && !tcp_sk(sk)->pf &&
	    sk->sk_state == TCP_ESTABLISHED)
		mptcp_reinject_data(sk, 1);
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

#endif /* (defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)) */
#else /* CONFIG_MPTCP */

#define is_mapping_applied(skb) (0))

static inline int mptcp_sysctl_mss(void)
{
	return 0;
}

#define mpcb_from_tcpsock(__tp) (NULL)
#define mptcp_mpcb_from_req_sk(__req) (NULL)
#define mptcp_meta_sk(sk) (NULL)
#define is_meta_tp(__tp) (0)
#define is_meta_sk(sk) (0)
#define is_master_tp(__tp) (0)
#define tp_path_index(__tp) (0)
#define tp_cur_bw_est(__tp) (0)
#define tp_bw_est(__tp) (0)
#define mptcp_req_sk_saw_mpc(__req) (0)
#define mptcp_sk_attached(__sk) (0)
#define is_dfin_seg(mpcb, skb) (0)
#define mptcp_skb_data_ack(skb) (0)
#define mptcp_skb_data_seq(skb) (0)
#define mptcp_skb_end_data_seq(skb) (0)

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

static inline int mptcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}
static inline void mptcp_ofo_queue(struct multipath_pcb *mpcb) {}
static inline void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied) {}
static inline int mptcp_check_rcv_queue(struct multipath_pcb *mpcb,
		struct msghdr *msg, size_t *len, u32 *data_seq, int *copied,
		int flags)
{
	return 0;
}
static inline int mptcp_alloc_mpcb(struct sock *master_sk, gfp_t flags)
{
	return 0;
}
static inline void mptcp_add_sock(struct multipath_pcb *mpcb,
		struct tcp_sock *tp) {}
static inline void mptcp_del_sock(struct sock *sk) {}
static inline void mptcp_update_metasocket(struct sock *sock,
		struct multipath_pcb *mpcb) {}
static inline int mptcp_sendmsg(struct kiocb *iocb, struct sock *master_sk,
		struct msghdr *msg, size_t size)
{
	return 0;
}
static inline int mptcp_is_available(struct sock *sk)
{
	return 0;
}
static inline void mptcp_reinject_data(struct sock *orig_sk, int clone_it) {}
static inline int mptcp_get_dataseq_mapping(struct tcp_sock *tp,
		struct sk_buff *skb)
{
	return 0;
}
static inline int mptcp_init_subsockets(struct multipath_pcb *mpcb,
		u32 path_indices)
{
	return 0;
}
static inline void mptcp_update_window_clamp(struct tcp_sock *tp) {}
static inline void mptcp_update_sndbuf(struct multipath_pcb *mpcb) {}
static inline void mptcp_update_dsn_ack(struct multipath_pcb *mpcb, u32 start,
		u32 end) {}
static inline void mptcp_set_state(struct sock *sk, int state) {}
static inline void mptcp_push_frames(struct sock *sk) {}
static inline void verif_wqueues(struct multipath_pcb *mpcb) {}
static inline void mptcp_skb_entail_init(struct sock *sk,
		struct sk_buff *skb) {}
static inline void mptcp_skb_entail(struct sock *sk, struct sk_buff *skb) {}
static inline struct sk_buff *mptcp_next_segment(struct sock *sk,
		int *reinject)
{
	return NULL;
}
static inline void mpcb_release(struct multipath_pcb *mpcb) {}
static inline void mptcp_release_sock(struct sock *sk) {}
static inline void mptcp_clean_rtx_queue(struct sock *sk) {}
static inline void mptcp_send_fin(struct sock *meta_sk) {}
static inline void mptcp_parse_options(uint8_t *ptr, int opsize,
		struct tcp_options_received *opt_rx,
		struct multipath_options *mopt,
		struct sk_buff *skb) {}
static inline void mptcp_close(struct sock *master_sk, long timeout) {}
static inline void mptcp_detach_unused_child(struct sock *sk) {}
static inline void mptcp_set_bw_est(struct tcp_sock *tp, u32 now) {}
static inline int do_mptcp(struct sock *sk)
{
	return 0;
}
static inline int mptcp_check_req_master(struct sock *child,
		struct request_sock *req, struct multipath_options *mopt)
{
	return 0;
}
static inline int mptcp_check_req_child(struct sock *sk, struct sock *child,
		struct request_sock *req, struct request_sock **prev)
{
	return 0;
}
static inline void mptcp_select_window(struct tcp_sock *tp, u32 new_win) {}
static inline int mptcp_try_rmem_schedule(struct sock *tp, unsigned int size)
{
	return 0;
}
static inline void mptcp_check_buffers(struct multipath_pcb *mpcb) {}
static inline void mptcp_update_window_check(struct tcp_sock *meta_tp,
		struct sk_buff *skb, u32 data_ack) {}
static inline void mptcp_set_data_size(struct tcp_sock *tp,
		struct sk_buff *skb, int copy) {}
static inline int mptcp_push(struct sock *sk, int flags, int mss_now,
		int nonagle)
{
	return 0;
}
static inline void mptcp_fallback(struct sock *master_sk) {}
static inline int mptcp_snd_buf_demand(struct tcp_sock *tp, u32 rtt_max)
{
	return 0;
}
static inline void mptcp_init_addr_list(struct multipath_options *mopt) {}
static inline void mptcp_wmem_free_skb(struct sock *sk, struct sk_buff *skb) {}
static inline int is_local_addr4(u32 addr)
{
	return 0;
}
static inline struct tcp_sock *mpcb_meta_tp(const struct multipath_pcb *mpcb)
{
	return NULL;
}
static inline void mptcp_sock_destruct(struct sock *sk) {}
static inline int mptcp_skip_offset(struct tcp_sock *tp,
		unsigned char __user **from, size_t *seglen, size_t *size)
{
	return 0;
}
static inline void mptcp_update_pointers(struct tcp_sock *tp,
		struct sock **meta_sk, struct tcp_sock **meta_tp,
		struct multipath_pcb **mpcb) {}
static inline int mptcp_check_rtt(struct tcp_sock *tp, int time)
{
	return 0;
}
static inline void mptcp_path_array_check(struct multipath_pcb *mpcb) {}
static inline int mptcp_check_snd_buf(struct tcp_sock *tp)
{
	return 0;
}
static inline void mptcp_retransmit_queue(struct sock *sk) {}
static inline int mptcp_get_path_family(struct multipath_pcb *mpcb,
					int path_index)
{
	return 0;
}
static inline struct sock *mptcp_sk_clone(struct sock *sk, int family,
		int priority)
{
	return NULL;
}
#endif /* CONFIG_MPTCP */

#endif /* _MPTCP_H */
