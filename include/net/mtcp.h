/*
 *	MTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *      Costin Raiciu           <c.raiciu@cs.ucl.ac.uk>
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

/*DEBUG - TODEL*/

#define MTCP_DEBUG_OFO_QUEUE 0x1
#define MTCP_DEBUG_QUEUE_SKB 0x2
#define MTCP_DEBUG_CHECK_RCV_QUEUE 0x4
#define MTCP_DEBUG_DATA_QUEUE 0x8
#define MTCP_DEBUG_COPY_TO_IOVEC 0x10

/*hashtable Not used currently -- To delete ?*/
#define MTCP_HASH_SIZE                16
#define hash_fd(fd) \
	jhash_1word(fd,0)%MTCP_HASH_SIZE

struct multipath_options {	
#ifdef CONFIG_MTCP_PM
	u8     ip_count;
	u32*   ip_list;
	u8     list_rcvd:1; /*1 if IP list has been received*/
#endif
	u8     saw_dsn:1;
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

struct multipath_pcb {
	struct list_head          collide_sd;
	
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
	u32    copied_seq; /* Head of yet unread data		*/
 	u32    snd_una;	/* First dataseq we want an ack for */
	
	/*user data, unpacketized
	  This is a circular buffer, data is stored in the "subbuffer"
	  starting at byte index wb_start with the write_buffer,
	  with length wb_length. Uppon mpcb init, the size
	  of the write buffer is stored in wb_size */
	char*                     write_buffer;
	/*wb_size: size of the circular sending buffer
	  wb_start: index of the first byte of pending data in the buffer
	  wb_length: number of bytes occupied by the pending data.
	  of course, it never exceeds wb_size*/
	int                       wb_size,wb_start,wb_length;
	
	uint8_t                   mpc_sent:1; /*MPC option has been sent, do 
						not send it anymore*/
	struct sk_buff_head       receive_queue;/*received data*/
	struct sk_buff_head       write_queue;/*sent stuff, waiting for ack*/
	struct sk_buff_head       retransmit_queue;/*need to rexmit*/
	struct sk_buff_head       error_queue;
	struct sk_buff_head       out_of_order_queue; /* Out of order segments 
							 go here */
	int                       ofo_bytes; /*Counts the number of bytes 
					       waiting to be eaten by the app
					       in the meta-ofo queue or the
					       meta-receive queue.*/
	
	spinlock_t                lock;
	struct mutex              mutex;
	struct kref               kref;	
	struct completion         liberate_subflow;
	struct notifier_block     nb; /*For listening to PM events*/
};

#define mpcb_from_tcpsock(tp) ((tp)->mpcb)
#define is_master_sk(tp) ((tp)->mpcb && tcp_sk((tp)->mpcb->master_sk)==tp)

/*Iterates overs all subflows*/
#define mtcp_for_each_tp(mpcb,tp)			\
	for (tp=mpcb->connection_list;tp;tp=tp->next)

/*Iterates over new subflows prevnum is the number
  of flows already known by the caller
  Note that prevnum is altered by this macro*/
#define mtcp_for_each_newtp(mpcb,tp,prevnum)				\
	for (tp=mpcb->connection_list,prevnum=mpcb->cnt_subflows-prevnum; \
	     tp && prevnum;tp=tp->next,prevnum--)

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
			if (cond) __ans=1;		\
			break;				\
		}					\
		__ans;})				\

/*Idem here with tp in lieu of sk*/	
#define mtcp_test_any_tp(mpcb,tp,cond)			\
	({      int __ans=0;				\
		mtcp_for_each_tp(mpcb,tp) {		\
			if (cond) __ans=1;		\
			break;				\
		}					\
		__ans;					\
	})						\


/*Wait for event @__condition to happen on any subsocket, 
  or __timeo to expire
  This is the MPTCP equivalent of sk_wait_event */
#define mtcp_wait_event_any_sk(__mpcb,__sk, __timeo, __condition)	\
	({	int __rc; struct tcp_sock *__tp;			\
		mtcp_for_each_sk(__mpcb,__sk,__tp) {			\
			release_sock(__sk);				\
			__tp->wait_event_any_sk_released=1;		\
		}							\
		__rc = mtcp_test_any_sk(__mpcb,__sk,__condition);	\
		if (!__rc)  						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		mtcp_for_each_sk(__mpcb,__sk,__tp)			\
			if (__tp->wait_event_any_sk_released) {		\
				/*Lock only those socks we have released*/ \
				lock_sock(__sk);			\
				__tp->wait_event_any_sk_released=0;	\
			}						\
		__rc = mtcp_test_any_sk(__mpcb,__sk,__condition);	\
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
void mtcp_check_seqnums(struct multipath_pcb *mpcb, int before);


int mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk, 
			  long *timeo);
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
int mtcp_is_available(struct tcp_sock *tp);
void mtcp_reinject_data(struct sock *orig_sk, struct sock *retrans_sk);
int mtcp_get_dataseq_mapping(struct multipath_pcb *mpcb, struct tcp_sock *tp, 
			     struct sk_buff *skb);
int mtcpv6_init(void);


#ifdef CONFIG_MTCP_PM
u32 mtcp_new_token(void);
#endif

#endif /*_MTCP_H*/
