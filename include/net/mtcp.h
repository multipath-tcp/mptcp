/*
 *	MTCP implementation
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

#ifndef _MTCP_H
#define _MTCP_H

#include <linux/aio.h>
#include <linux/inetdevice.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp_options.h>
#include <linux/tcp.h>

#include <net/mtcp_pm.h>

#ifdef CONFIG_MTCP_DEBUG
#define mtcp_debug(fmt,args...) printk( KERN_DEBUG __FILE__ ": " fmt,##args)
#else
#define mtcp_debug(fmt,args...)
#endif

/* Default MSS for MPTCP
 * All subflows will be using that MSS. If any subflow has a lower MSS, it is
 * just not used. */
#define MPTCP_MSS 1400
extern int sysctl_mptcp_mss;
extern int sysctl_mptcp_ndiffports;
extern int sysctl_mptcp_enabled;

#ifdef MTCP_RCV_QUEUE_DEBUG
struct mtcp_debug {
	const char *func_name;
	u32 seq;
	int len;
	int end;		/* 1 if this is the last debug info */
};

void print_debug_array(void);
void freeze_rcv_queue(struct sock *sk, const char *func_name);
#endif

#ifdef MTCP_DEBUG_TIMER
static void mtcp_debug_timeout(unsigned long data)
{
	printk(KERN_ERR "MPTCP debug timeout ! Function %s\n", (char *)data);
	BUG();
}

static DEFINE_TIMER(mtcp_debug_timer, mtcp_debug_timeout, 0, 0);
#define mtcp_start_debug_timer(delay)					\
	do {								\
		mtcp_debug_timer.expires = jiffies + delay * HZ;	\
		mtcp_debug_timer.data=(unsigned long)__FUNCTION__;	\
		add_timer(&mtcp_debug_timer);				\
	} while (0)

static void mtcp_stop_debug_timer(void)
{
	del_timer(&mtcp_debug_timer);
}
#endif

extern struct proto mtcpsub_prot;

#define MPCB_FLAG_SERVER_SIDE	0  /* This mpcb belongs to a server side
				    * connection. (obtained through a listen)
				    */
#define MPCB_FLAG_FIN_ENQUEUED  1  /* A dfin has been enqueued on the meta-send
				     * queue.
				     */

struct multipath_pcb {
	struct tcp_sock           tp;

	/* list of sockets in this multipath connection */
	struct tcp_sock           *connection_list;

	/* Master socket, also part of the connection_list, this
	 * socket is the one that the application sees. 
	 */
	struct sock               *master_sk;
	/* socket count in this connection */
	int                       cnt_subflows;
	int                       syn_sent;
	int                       cnt_established;
	int                       err;

	char                      done;
	unsigned short            shutdown;

	struct multipath_options received_options;
	struct tcp_options_received tcp_opt;

	struct sk_buff_head reinject_queue;
	spinlock_t lock;
	struct mutex mutex;
	struct kref kref;
	unsigned long flags; /* atomic, for bits see MPCB_FLAG_XXX */
	u32 noneligible; /* Path mask of temporarily non eligible
			  * subflows by the scheduler
			  */
	
#ifdef CONFIG_MTCP_PM
	struct list_head collide_tk;
	uint8_t addr_unsent;	/* num of addrs not yet sent to our peer */

	/* We need to store the set of local addresses, so that we have a stable
	   view of the available addresses. Playing with the addresses directly
	   in the system would expose us to concurrency problems */
	struct mtcp_loc4 addr4[MTCP_MAX_ADDR];
	int num_addr4;		/* num of addresses actually stored above. */

	struct mtcp_loc6 addr6[MTCP_MAX_ADDR];
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
#define MPTCP_SUB_LEN_SEQ_ALIGN		12

#define MPTCP_SUB_LEN_ACK	4
#define MPTCP_SUB_LEN_ACK_ALIGN		4

#define MPTCP_SUB_ADD_ADDR	3
#define MPTCP_SUB_LEN_ADD_ADDR	8
#define MPTCP_SUB_LEN_ADD_ADDR_ALIGN	8

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
		rsv:7,
		c:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
	__u8	c:1,
		rsv:7,
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

#define mpcb_from_tcpsock(tp) ((tp)->mpcb)
#define is_master_sk(tp) (!(tp)->slave_sk)
#define is_meta_tp(__tp) ((__tp)->mpcb && &(__tp)->mpcb->tp == __tp)
#define is_meta_sk(sk) ((tcp_sk(sk))->mpcb &&				\
			&(tcp_sk(sk))->mpcb->tp == tcp_sk(sk))
#define is_dfin_seg(mpcb, skb) (mpcb->received_options.dfin_rcvd &&	\
			       mpcb->received_options.fin_dsn ==	\
			       TCP_SKB_CB(skb)->end_data_seq)
#define mtcp_meta_sk(sk) ((struct sock*)tcp_sk(sk)->mpcb)

/* Iterates overs all subflows */
#define mtcp_for_each_tp(mpcb, tp)					\
	for ((tp) = (mpcb)->connection_list; (tp); (tp) = (tp)->next)

/* Iterates over new subflows. prevnum is the number
   of flows already known by the caller.
   Note that prevnum is altered by this macro */
#define mtcp_for_each_newtp(mpcb, tp, prevnum)		\
	for ((tp) = (mpcb)->connection_list,		\
	     prevnum = (mpcb)->cnt_subflows-prevnum;	\
	     prevnum;					\
	     (tp) = (tp)->next, prevnum--)

#define mtcp_for_each_sk(mpcb, sk, tp)					       \
	for ((sk) = (struct sock *) (mpcb)->connection_list, (tp) = tcp_sk(sk);\
	     sk;							       \
	     sk = (struct sock *) tcp_sk(sk)->next, tp = tcp_sk(sk))

#define mtcp_for_each_sk_safe(__mpcb, __sk, __temp)			\
	for (__sk = (struct sock *) (__mpcb)->connection_list,		\
	     __temp = __sk ? (struct sock *) tcp_sk(__sk)->next : NULL;	\
	     __sk;							\
	     __sk = __temp,						\
	     __temp = __sk ? (struct sock *) tcp_sk(__sk)->next : NULL)

/* Returns 1 if any subflow meets the condition @cond
   Else return 0. Moreover, if 1 is returned, sk points to the
   first subsocket that verified the condition */
#define mtcp_test_any_sk(mpcb, sk, cond)		\
	({	int __ans = 0;				\
		struct tcp_sock *__tp;			\
		mtcp_for_each_sk(mpcb, sk, __tp) {	\
			if (cond) {			\
				__ans = 1;		\
				break;			\
			}				\
		}					\
		__ans;					\
	})

/* Idem here with tp in lieu of sk */
#define mtcp_test_any_tp(mpcb, tp, cond)		\
	({      int __ans = 0;				\
		mtcp_for_each_tp(mpcb, tp) {		\
			if (cond){			\
				__ans = 1;		\
				break;			\
			}				\
		}					\
		__ans;					\
	})						\

#define mtcp_test_any_sk_tp(mpcb, sk, tp, cond)		\
	({						\
		int __ans = 0;				\
		mtcp_for_each_sk(mpcb, sk, tp) {	\
			if (cond){			\
				__ans = 1;		\
				break;			\
			}				\
		}					\
		__ans;					\
	})

/* Returns 1 if all subflows meet the condition @cond
   Else return 0. */
#define mtcp_test_all_sk(mpcb, sk, cond)		\
	({						\
		int __ans = 1;				\
		struct tcp_sock *__tp;			\
		mtcp_for_each_sk(mpcb, sk, __tp) {	\
			if (!(cond)) {			\
				__ans = 0;		\
				break;			\
			}				\
		}					\
		__ans;					\
	})

/* Wait for event @__condition to happen on any subsocket,
   or __timeo to expire
   This is the MPTCP equivalent of sk_wait_event */
#define mtcp_wait_event_any_sk(__mpcb, __sk, __tp, __timeo, __condition)\
	({								\
		int __rc;						\
		mtcp_for_each_sk(__mpcb, __sk, __tp) {			\
			release_sock(__sk);				\
		}							\
		__rc = mtcp_test_any_sk_tp(__mpcb, __sk, __tp,		\
					   __condition);		\
		if (!__rc)  						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		mtcp_for_each_sk(__mpcb, __sk, __tp)			\
			lock_sock(__sk);				\
		__rc = mtcp_test_any_sk_tp(__mpcb, __sk, __tp,		\
					   __condition);		\
		__rc;							\
	})

#ifdef DEBUG_PITOFLAG
static inline int PI_TO_FLAG(int pi)
{
	BUG_ON(!pi);
	return (1 << (pi - 1));
}
#else
#define PI_TO_FLAG(pi) (1 << (pi - 1))
#endif

/* For debugging only. Verifies consistency between subsock seqnums
   and metasock seqnums */
#ifdef MTCP_DEBUG_SEQNUMS
void mtcp_check_seqnums(struct multipath_pcb *mpcb, int before);
#else
#define mtcp_check_seqnums(mpcb, before)
#endif

#ifdef MTCP_DEBUG_PKTS_OUT
int mtcp_check_pkts_out(struct sock* sk);
void mtcp_check_send_head(struct sock *sk,int num);
#else
#define mtcp_check_pkts_out(sk)
#define mtcp_check_send_head(sk,num)
#endif

static inline void mtcp_init_addr_list(struct multipath_options *mopt)
{
	mopt->list_rcvd = mopt->num_addr4 = mopt->num_addr6 = 0;
}

/**
 * This function is almost exactly the same as sk_wmem_free_skb.
 * The only difference is that we call kfree_skb instead of __kfree_skb.
 * This is important because a subsock may want to remove an skb,
 * while the meta-sock still has a reference to it.
 */
static inline void mtcp_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
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

int mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk,
			long *timeo, int flags);
int mtcp_queue_skb(struct sock *sk, struct sk_buff *skb);
void mtcp_ofo_queue(struct multipath_pcb *mpcb);
void mtcp_cleanup_rbuf(struct sock *meta_sk, int copied);
int mtcp_check_rcv_queue(struct multipath_pcb *mpcb, struct msghdr *msg,
			 size_t * len, u32 * data_seq, int *copied, int flags);
/* Possible return values from mtcp_queue_skb */
#define MTCP_EATEN 1		/* The skb has been (fully or partially) eaten by the app */
#define MTCP_QUEUED 2		/* The skb has been queued in the mpcb ofo queue */

struct multipath_pcb *mtcp_alloc_mpcb(struct sock *master_sk, gfp_t flags);
void mtcp_add_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mtcp_del_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mtcp_update_metasocket(struct sock *sock, struct multipath_pcb *mpcb);
int mtcp_sendmsg(struct kiocb *iocb, struct sock *master_sk, struct msghdr *msg,
		size_t size);
int mtcp_is_available(struct sock *sk);
struct sock *get_available_subflow(struct multipath_pcb *mpcb,
				   struct sk_buff *skb, int *pf);
void mtcp_reinject_data(struct sock *orig_sk);
int mtcp_get_dataseq_mapping(struct tcp_sock *tp, struct sk_buff *skb);
int mtcp_init_subsockets(struct multipath_pcb *mpcb, u32 path_indices);
void mtcp_update_window_clamp(struct multipath_pcb *mpcb);
void mtcp_update_sndbuf(struct multipath_pcb *mpcb);
void mtcp_update_dsn_ack(struct multipath_pcb *mpcb, u32 start, u32 end);
int mtcpv6_init(void);
void mtcp_data_ready(struct sock *sk);
int mtcp_v4_add_raddress(struct multipath_options *mopt, struct in_addr *addr,
		u8 id);

void verif_wqueues(struct multipath_pcb *mpcb);

void mtcp_skb_entail(struct sock *sk, struct sk_buff *skb);
void mpcb_release(struct kref* kref);
struct sk_buff *mtcp_next_segment(struct sock *sk, int *reinject);
void mtcp_clean_rtx_queue(struct sock *sk);
void mtcp_send_fin(struct sock *mpcb_sk);
void mtcp_parse_options(uint8_t *ptr, int opsize,
		struct tcp_options_received *opt_rx,
		struct multipath_options *mopt,
		struct sk_buff *skb);
void mtcp_close(struct sock *master_sk, long timeout);
struct multipath_pcb *mtcp_attach_master_sk(struct sock *sk);
void mtcp_detach_unused_child(struct sock *sk);
int do_mptcp(struct sock *sk);

static void inline mpcb_get(struct multipath_pcb *mpcb) {
	kref_get(&mpcb->kref);
}

static void inline mpcb_put(struct multipath_pcb *mpcb) {
	kref_put(&mpcb->kref, mpcb_release);
}

#endif /* _MTCP_H */
