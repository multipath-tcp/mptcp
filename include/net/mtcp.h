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

#include <net/request_sock.h>
#include <net/mtcp_pm.h>


/*DEBUG - TODEL*/

#define MTCP_DEBUG_OFO_QUEUE 0x1
#define MTCP_DEBUG_QUEUE_SKB 0x2
#define MTCP_DEBUG_CHECK_RCV_QUEUE 0x4
#define MTCP_DEBUG_DATA_QUEUE 0x8
#define MTCP_DEBUG_COPY_TO_IOVEC 0x10


struct multipath_options {	
#ifdef CONFIG_MTCP_PM
	int    num_addr4; 
	int    num_addr6;
	struct mtcp_loc4 addr4[MTCP_MAX_ADDR];
	struct mtcp_loc6 addr6[MTCP_MAX_ADDR];
	u8     list_rcvd:1; /*1 if IP list has been received*/	
#endif
};


#ifdef MTCP_RCV_QUEUE_DEBUG
struct mtcp_debug {
	const char* func_name;
	u32 seq;
	int len;
	int end; /*1 if this is the last debug info*/
};

void print_debug_array(void);
void freeze_rcv_queue(struct sock *sk, const char *func_name);
#endif

extern struct proto mtcpsub_prot;

struct tcp_sock;

struct dsn_sack {
	struct list_head list;
	u32 start;
	u32 end;
};

#define dsack_first(mpcb) (list_first_entry(&mpcb->dsack_list,		\
					    struct dsn_sack,list))
#define dsack_next(dsack) (list_entry(dsack->list.next,struct dsn_sack,list))
#define dsack_prev(dsack) (list_entry(dsack->list.prev,struct dsn_sack,list))
#define dsack_is_last(dsack,mpcb) (list_is_last(&dsack->list,&mpcb->dsack_list))
#define dsack_is_first(dsack,mpcb) (dsack==dsack_first(mpcb))

struct multipath_pcb {
	/*receive and send buffer sizing*/
	int                       rcvbuf, sndbuf;
	atomic_t                  rmem_alloc;       
	
	/*connection identifier*/
	sa_family_t               sa_family;
	xfrm_address_t            remote_ulid, local_ulid;
	__be16                    remote_port,local_port;
	
	/*list of sockets in this multipath connection*/
	struct tcp_sock*          connection_list;
	
	/*Master socket, also part of the connection_list, this
	  socket is the one that the application sees.*/
	struct sock*              master_sk;
	/*Last scheduled subsocket. If this pointer is not NULL, 
	  then the last scheduled subsocket has remaining space 
	  in it tail skb. This means we should reschedule it, to avoid
	  that Nagle blocks it.*/
	struct sock*              last_sk;
	/*socket count in this connection*/
	int                       cnt_subflows;    
	int                       syn_sent;
	int                       cnt_established;
	
	/*state, for faster tests in code*/
	int                       state;
	int                       err;
	
	char                      done;
	unsigned short            shutdown;
	
	struct {
		struct task_struct	*task;
		struct iovec		*iov;
/*The length field is initialized by mtcp_recvmsg, and decremented by 
  each subsocket separately, upon data reception. That's why each subsocket
  must do the copies with appropriate locks.
  Whenever a subsocket decrements this field, it must increment its 
  tp->copied field, so that we can track later how many bytes have been
  eaten by which subsocket.*/
		int                     len;
	} ucopy; /*Fields moved from tcp_sock struct to this one*/

	struct multipath_options  received_options;
	struct tcp_options_received tcp_opt;

	u32    write_seq;  /*data sequence number, counts the number of 
			     bytes the user has written so far */
	u32    copied_seq; /* Head of yet unread data*/

	u32    snd_una;
	u32    snd_wnd;	    /* The window we expect to receive	*/
	u32    max_window;  /* Maximal window ever seen from peer */
	struct list_head          dsack_list;
	
	struct sk_buff_head       receive_queue;/*received data*/
	struct sk_buff_head       out_of_order_queue; /* Out of order segments 
							 go here */
	struct sk_buff_head       realloc_queue; /*Realloc sending queue*/
	int                       ofo_bytes; /*Counts the number of bytes 
					       waiting to be eaten by the app
					       in the meta-ofo queue or the
					       meta-receive queue.*/
	
	spinlock_t                lock;
	struct mutex              mutex;
	struct kref               kref;	
	struct completion         liberate_subflow;
	struct notifier_block     nb; /*For listening to PM events*/

	/*Receive window management*/
	u32                       window_clamp;
	u32                       rcv_ssthresh;

	uint8_t                   server_side:1, /*1 if this mpcb belongs
						   to a server side connection.
						   (obtained through a listen)*/
	                          pending_data:1, /*1 is at least one byte
						    of data is available for
						    eating by the app.*/
		                  need_realloc:1, /*realloc window*/
		                  reallocating:1, /*1 if realloc function is 
						    running*/
	                          sndbuf_grown:1; /*sndbuf has grown
						    for one of our
						    subflows*/

#ifdef CONFIG_MTCP_PM
	/*accept queue (to store join requests)*/
	struct request_sock_queue accept_queue;
	struct list_head          collide_tk;
	uint8_t                   addr_unsent; /* num of addrs not yet
				                  sent to our peer */
	
	struct mtcp_loc4          addr4[MTCP_MAX_ADDR]; /*We need to store
							  the set of local
							  addresses, so 
							  that we have 
							  a stable view
							  of the available
							  addresses. 
							  Playing with the
							  addresses directly
							  in the system
							  would expose us
							  to concurrency
							  problems*/
	int                       num_addr4; /*num of addresses actually
					       stored above.*/
	struct mtcp_loc6          addr6[MTCP_MAX_ADDR];
	int                       num_addr6;

	struct path4             *pa4;
	int                       pa4_size;
	struct path6             *pa6;
	int                       pa6_size;

	int                       next_unused_pi; /*Next pi to pick up
						    in case a new path
						    becomes available*/
#endif
};

#define mpcb_from_tcpsock(tp) ((tp)->mpcb)
#define is_master_sk(tp) ((tp)->mpcb && tcp_sk((tp)->mpcb->master_sk)==tp)

/*Iterates overs all subflows*/
#define mtcp_for_each_tp(mpcb,tp)			\
	for (tp=mpcb->connection_list;tp;tp=tp->next)

/*Iterates over new subflows. prevnum is the number
  of flows already known by the caller.
  Note that prevnum is altered by this macro*/
#define mtcp_for_each_newtp(mpcb,tp,prevnum)				\
	for (tp=mpcb->connection_list,prevnum=mpcb->cnt_subflows-prevnum; \
	     prevnum;tp=tp->next,prevnum--)

#define mtcp_for_each_sk(mpcb,sk,tp)					\
	for (sk=(struct sock*)mpcb->connection_list,tp=tcp_sk(sk);	\
	     sk;							\
	     sk=(struct sock*)tcp_sk(sk)->next,tp=tcp_sk(sk))

#define mtcp_for_each_sk_safe(__mpcb,__sk,__temp)			\
	for (__sk=(struct sock*)__mpcb->connection_list,		\
		     __temp=(__sk)?(struct sock*)tcp_sk(__sk)->next:NULL; \
	     __sk;							\
	     __sk=__temp,						\
		     __temp=(__sk)?(struct sock*)tcp_sk(__sk)->next:NULL)

/*Returns 1 if any subflow meets the condition @cond
  Else return 0. Moreover, if 1 is returned, sk points to the
  first subsocket that verified the condition*/
#define mtcp_test_any_sk(mpcb,sk,cond)			\
	({int __ans=0; struct tcp_sock *__tp;		\
		mtcp_for_each_sk(mpcb,sk,__tp) {	\
			if (cond)  {			\
				__ans=1;		\
				break;			\
			}				\
		}					\
		__ans;})				\
	
/*Idem here with tp in lieu of sk*/	
#define mtcp_test_any_tp(mpcb,tp,cond)			\
	({      int __ans=0;				\
		mtcp_for_each_tp(mpcb,tp) {		\
			if (cond) {			\
				__ans=1;		\
				break;			\
			}				\
		}					\
		__ans;					\
	})						\
	
#define mtcp_test_any_sk_tp(mpcb,sk,tp,cond)		\
	({int __ans=0;					\
		mtcp_for_each_sk(mpcb,sk,tp) {		\
			if (cond) {			\
				__ans=1;		\
				break;			\
			}				\
		}					\
		__ans;})				\
	
/*Returns 1 if all subflows meet the condition @cond
  Else return 0. */
#define mtcp_test_all_sk(mpcb,sk,cond)			\
	({int __ans=1; struct tcp_sock *__tp;		\
		mtcp_for_each_sk(mpcb,sk,__tp) {	\
			if (!(cond)) {			\
				__ans=0;		\
				break;			\
			}				\
		}					\
		__ans;})				\
	
/*Wait for event @__condition to happen on any subsocket, 
  or __timeo to expire
  This is the MPTCP equivalent of sk_wait_event */
#define mtcp_wait_event_any_sk(__mpcb,__sk, __tp, __timeo, __condition)	\
	({	int __rc;						\
		mtcp_for_each_sk(__mpcb,__sk,__tp) {			\
			release_sock(__sk);				\
		}							\
		__rc = mtcp_test_any_sk_tp(__mpcb,__sk,__tp,		\
					   __condition);		\
		if (!__rc)  						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		mtcp_for_each_sk(__mpcb,__sk,__tp)			\
			lock_sock(__sk);				\
		__rc = mtcp_test_any_sk_tp(__mpcb,__sk,__tp,		\
					   __condition);		\
		__rc;							\
	})

#define DEBUG_PITOFLAG

#ifdef DEBUG_PITOFLAG
static inline int PI_TO_FLAG(int pi)
{
	BUG_ON(!pi);
	return (1<<(pi-1));
}
#else
#define PI_TO_FLAG(pi) (1<<(pi-1))
#endif

/*For debugging only. Verifies consistency between subsock seqnums
  and metasock seqnums*/
#ifdef MTCP_DEBUG_SEQNUMS
void mtcp_check_seqnums(struct multipath_pcb *mpcb, int before);
#else
#define mtcp_check_seqnums(mpcb, before)
#endif


int mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk, 
		   long *timeo,int flags);
int mtcp_queue_skb(struct sock *sk,struct sk_buff *skb, u32 offset,
		   unsigned long *used, struct msghdr *msg, size_t *len,   
		   u32 *data_seq, int *copied, int flags);
void mtcp_ofo_queue(struct multipath_pcb *mpcb, struct msghdr *msg, size_t *len,
		    u32 *data_seq, int *copied, int flags);
int mtcp_check_rcv_queue(struct multipath_pcb *mpcb,struct msghdr *msg, 
			 size_t *len, u32 *data_seq, int *copied, int flags);
/*Possible return values from mtcp_queue_skb*/
#define MTCP_EATEN 1 /*The skb has been (fully or partially) eaten by the app*/
#define MTCP_QUEUED 2 /*The skb has been queued in the mpcb ofo queue*/
#define MTCP_DROPPED 3 /*The skb has been dropped by the meta-flow.
			 This happens if a copy of the same data has been 
			 received on another subflow*/

struct multipath_pcb* mtcp_alloc_mpcb(struct sock *master_sk);
void mtcp_ask_update(struct sock *sk);
void mtcp_destroy_mpcb(struct multipath_pcb *mpcb);
void mtcp_add_sock(struct multipath_pcb *mpcb,struct tcp_sock *tp);
void mtcp_del_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp);
void mtcp_reset_options(struct multipath_options* mopt);
void mtcp_update_metasocket(struct sock *sock);
int mtcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size);
int mtcp_is_available(struct sock *sk);
void mtcp_reinject_data(struct sock *orig_sk, struct sock *retrans_sk);
int mtcp_get_dataseq_mapping(struct tcp_sock *tp, struct sk_buff *skb);
int mtcp_init_subsockets(struct multipath_pcb *mpcb, 
			 uint32_t path_indices);
int mtcpsub_get_port(struct sock *sk, unsigned short snum);
void mtcp_update_window_clamp(struct multipath_pcb *mpcb);
void mtcp_update_dsn_ack(struct multipath_pcb *mpcb, u32 start, u32 end);
int mtcpv6_init(void);
void mpcb_get(struct multipath_pcb *mpcb);
void mpcb_put(struct multipath_pcb *mpcb);
void mtcp_data_ready(struct sock *sk);
int mtcp_bh_sndwnd_full(struct multipath_pcb *mpcb, struct sock *cursk);
int mtcp_reallocate(struct multipath_pcb *mpcb);
void mtcp_push_frames(struct sock *sk);
int mtcp_v4_add_raddress(struct multipath_options *mopt,			
			 struct in_addr *addr, u8 id);

void verif_wqueues(struct multipath_pcb *mpcb);
void mtcp_check_eat_old_seg(struct sock *sk, struct sk_buff *skb);
#endif /*_MTCP_H*/
