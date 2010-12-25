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

#include <linux/tcp_options.h>
#include <linux/notifier.h>
#include <linux/xfrm.h>
#include <linux/aio.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>

#include <net/request_sock.h>
#include <net/mtcp_pm.h>

#ifdef CONFIG_MTCP_DEBUG
# define mtcp_debug(fmt,args...) printk( KERN_DEBUG __FILE__ ": " fmt,##args)
#else
# define mtcp_debug(fmt,args...)
#endif

/* Default MSS for MPTCP
 All subflows will be using that MSS. If any subflow has a lower MSS, it is
 just not used. */
#define MPTCP_MSS 1400
extern int sysctl_mptcp_mss;

#ifdef MTCP_RCV_QUEUE_DEBUG
struct mtcp_debug {
	const char* func_name;
	u32 seq;
	int len;
	int end; /* 1 if this is the last debug info */
};

void print_debug_array(void);
void freeze_rcv_queue(struct sock *sk, const char *func_name);
#endif

extern struct proto mtcpsub_prot;

#define MPCB_FLAG_SERVER_SIDE 	0 /* This mpcb belongs to a server side
				     connection. (obtained through a listen) */
#define MPCB_FLAG_FIN_ENQUEUED  1 /* A dfin has been enqueued on the meta-send
				     queue. */

struct multipath_pcb {
	struct tcp_sock           tp;

	/* list of sockets in this multipath connection */
	struct tcp_sock*          connection_list;

	/* Master socket, also part of the connection_list, this
	   socket is the one that the application sees. */
	struct sock*              master_sk;
	/* socket count in this connection */
	int                       cnt_subflows;
	int                       syn_sent;
	int                       cnt_established;
	int                       err;

	char                      done;
	unsigned short            shutdown;
	
	struct {
		struct task_struct *task;
		struct iovec *iov;
		/* The length field is initialized by mtcp_recvmsg, and decremented by
		   each subsocket separately, upon data reception. That's why each subsocket
		   must do the copies with appropriate locks.
		   Whenever a subsocket decrements this field, it must increment its
		   tp->copied field, so that we can track later how many bytes have been
		   eaten by which subsocket. */
		int len;
	} ucopy; /* Fields moved from tcp_sock struct to this one */

	struct multipath_options received_options;
	struct tcp_options_received tcp_opt;

	struct sk_buff_head reinject_queue;
	spinlock_t lock;
	struct mutex mutex;
	struct kref kref;
	struct notifier_block nb; /* For listening to PM events */
	unsigned long flags; /* atomic, for bits see MPCB_FLAG_XXX */
	u32 noneligible; /* Path mask of temporarily non eligible
			    subflows by the scheduler */

#ifdef CONFIG_MTCP_PM
	struct list_head collide_tk;
	uint8_t addr_unsent; /* num of addrs not yet sent to our peer */

	/* We need to store the set of local addresses, so that we have a stable
	   view of the available addresses. Playing with the addresses directly
	   in the system would expose us to concurrency problems */
	struct mtcp_loc4 addr4[MTCP_MAX_ADDR];
	int num_addr4; /* num of addresses actually stored above. */

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

#define mpcb_from_tcpsock(tp) ((tp)->mpcb)
#define is_master_sk(tp) (!(tp)->slave_sk)
#define is_meta_tp(tp) ((tp)->mpcb && &(tp)->mpcb->tp == tp)
#define is_meta_sk(sk) ((tcp_sk(sk))->mpcb && 				\
			&(tcp_sk(sk))->mpcb->tp == tcp_sk(sk))
#define is_dfin_seg(mpcb, skb) (mpcb->received_options.dfin_rcvd &&	\
			       mpcb->received_options.fin_dsn ==	\
			       TCP_SKB_CB(skb)->end_data_seq)

/* Iterates overs all subflows */
#define mtcp_for_each_tp(mpcb, tp) 					\
	for ((tp) = (mpcb)->connection_list; (tp); (tp) = (tp)->next)

/* Iterates over new subflows. prevnum is the number
   of flows already known by the caller.
   Note that prevnum is altered by this macro */
#define mtcp_for_each_newtp(mpcb, tp, prevnum)		\
	for ((tp) = (mpcb)->connection_list,		\
	     prevnum = (mpcb)->cnt_subflows-prevnum;	\
	     prevnum;					\
	     (tp) = (tp)->next, prevnum--)

#define mtcp_for_each_sk(mpcb, sk, tp)					     \
	for ((sk) = (struct sock *) (mpcb)->connection_list, (tp)=tcp_sk(sk); \
	     sk;							     \
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
	({ 	int __ans = 0;				\
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
		int __ans = 1; 				\
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
/*#ifdef MTCP_DEBUG_SEQNUMS
void mtcp_check_seqnums(struct multipath_pcb *mpcb, int before);
#else
#define mtcp_check_seqnums(mpcb, before)
#endif

#ifdef MTCP_DEBUG_PKTS_OUT
int check_pkts_out(struct sock* sk);
void check_send_head(struct sock *sk,int num);
#else
#define check_pkts_out(sk)
#define check_send_head(sk,num)
#endif*/

static inline void mtcp_init_addr_list(struct multipath_options *mopt) {
	mopt->list_rcvd = mopt->num_addr4 = mopt->num_addr6 = 0;
}

/**
 * This function is almost exactly the same as sk_wmem_free_skb.
 * The only difference is that we call kfree_skb instead of __kfree_skb.
 * This is important because a subsock may want to remove an skb,
 * while the meta-sock still has a reference to it.
 */
static inline void mtcp_wmem_free_skb(struct sock *sk, struct sk_buff *skb) {
	skb_truesize_check(skb);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);
	kfree_skb(skb);
}

int mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk,
		long *timeo, int flags);
int mtcp_queue_skb(struct sock *sk, struct sk_buff *skb);
void mtcp_ofo_queue(struct multipath_pcb *mpcb);
int mtcp_check_rcv_queue(struct multipath_pcb *mpcb, struct msghdr *msg,
		size_t *len, u32 *data_seq, int *copied, int flags);
/* Possible return values from mtcp_queue_skb */
#define MTCP_EATEN 1 /* The skb has been (fully or partially) eaten by the app */
#define MTCP_QUEUED 2 /* The skb has been queued in the mpcb ofo queue */

struct multipath_pcb* mtcp_alloc_mpcb(struct sock *master_sk, gfp_t flags);
void mtcp_ask_update(struct sock *sk);
void mtcp_destroy_mpcb(struct multipath_pcb *mpcb);
void mtcp_add_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mtcp_del_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mtcp_reset_options(struct multipath_options* mopt);
void mtcp_update_metasocket(struct sock *sock, struct multipath_pcb *mpcb);
int mtcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		size_t size);
int mtcp_is_available(struct sock *sk);
struct sock* get_available_subflow(struct multipath_pcb *mpcb,
		struct sk_buff *skb, int *pf);
void mtcp_reinject_data(struct sock *orig_sk);
int mtcp_get_dataseq_mapping(struct tcp_sock *tp, struct sk_buff *skb);
int mtcp_init_subsockets(struct multipath_pcb *mpcb, uint32_t path_indices);
int mtcpsub_get_port(struct sock *sk, unsigned short snum);
void mtcp_update_window_clamp(struct multipath_pcb *mpcb);
void mtcp_update_sndbuf(struct multipath_pcb *mpcb);
void mtcp_update_dsn_ack(struct multipath_pcb *mpcb, u32 start, u32 end);
int mtcpv6_init(void);
void mpcb_get(struct multipath_pcb *mpcb);
void mpcb_put(struct multipath_pcb *mpcb);
void mtcp_data_ready(struct sock *sk);
void mtcp_push_frames(struct sock *sk);
int mtcp_v4_add_raddress(struct multipath_options *mopt, struct in_addr *addr,
		u8 id);

void verif_wqueues(struct multipath_pcb *mpcb);

void mtcp_skb_entail(struct sock *sk, struct sk_buff *skb);
struct sk_buff* mtcp_next_segment(struct sock *sk, int *reinject);
void mpcb_release(struct kref* kref);
void mtcp_clean_rtx_queue(struct sock *sk);
void mtcp_send_fin(struct sock *mpcb_sk);
void mtcp_close(struct sock *master_sk, long timeout);

#endif /* _MTCP_H */
