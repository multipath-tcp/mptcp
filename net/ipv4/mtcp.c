/*
 *	MTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Partially inspired from initial user space MTCP stack by Costin Raiciu.
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
#include <net/tcp_states.h>
#include <net/mtcp.h>
#include <net/netevent.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/shim6.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/random.h>
#include <asm/atomic.h>

#undef DEBUG_MTCP /*set to define if you want debugging messages*/

#undef PDEBUG
#ifdef DEBUG_MTCP
#define PDEBUG(fmt,args...) printk( KERN_DEBUG __FILE__ ": " fmt,##args)
#else
#define PDEBUG(fmt,args...)
#endif /*DEBUG_MTCP*/


inline void mtcp_reset_options(struct multipath_options* mopt){
#ifdef CONFIG_MTCP_PM
	mopt->remote_token = -1;
	mopt->local_token = -1;
	if (mopt->ip_count>0){
		if (mopt->ip_list){
			mopt->ip_list = NULL;
		}
	}
	mopt->ip_count = 0;
	mopt->first = 0;
#endif
}

/*This function can only be called with *slave* subsockets 
  as argument.*/
static void mtcp_def_readable(struct sock *sk, int len)
{
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tcp_sk(sk));
	struct sock *msk=mpcb->master_sk;
	
	BUG_ON(!mpcb);

	PDEBUG("Waking up master subsock...\n");
	
	read_lock(&msk->sk_callback_lock);
	if (msk->sk_sleep && waitqueue_active(msk->sk_sleep))
		wake_up_interruptible_sync(msk->sk_sleep);
	sk_wake_async(msk, SOCK_WAKE_WAITD, POLL_IN);
	read_unlock(&msk->sk_callback_lock);
}

/**
 * Creates as many sockets as path indices announced by the Path Manager.
 * The first path indices are (re)allocated to existing sockets.
 * New sockets are created if needed.
 *
 * WARNING: We make the assumption that this function is run in user context
 *      (we use sock_create_kern, that reserves ressources with GFP_KERNEL)
 *      AND only one user process can trigger the sending of a PATH_UPDATE
 *      notification. This is in conformance with the fact that only one PM
 *      can send messages to the MPS, according to our multipath arch.
 *      (further PMs are cascaded and use the depth attribute).
 */
static int mtcp_init_subsockets(struct multipath_pcb *mpcb, 
				uint32_t path_indices)
{
	int i;
	int retval;
	struct socket *sock;
	struct tcp_sock *tp=mpcb->connection_list;
	struct tcp_sock *newtp;

	PDEBUG("Entering %s, path_indices:%x\n",__FUNCTION__,path_indices);

	/*First, ensure that we keep existing path indices.*/
	while (tp!=NULL) {
		/*disable the corresponding bit*/
		if (tp->path_index==0) tp->path_index=1;
		path_indices&=~(1<<(tp->path_index-1));
		tp=tp->next;
	}

	for (i=0;i<sizeof(path_indices)*8;i++) {
		if (!((1<<i) & path_indices))
			continue;
		else {
			struct sockaddr *loculid,*remulid=NULL;
			int ulid_size=0;
			struct sockaddr_in loculid_in,remulid_in;
			struct sockaddr_in6 loculid_in6,remulid_in6;
			/*a new socket must be created*/
			retval = sock_create_kern(mpcb->sa_family, SOCK_STREAM, 
						  IPPROTO_MTCPSUB, &sock);
			
			if (retval<0) {
				printk(KERN_ERR "%s:sock_create failed\n",
				       __FUNCTION__);
				return retval;
			}
			newtp=tcp_sk(sock->sk);

			/*Binding the new socket to the local ulid*/
			switch(mpcb->sa_family) {
			case AF_INET:
				memset(&loculid,0,sizeof(loculid));
				loculid_in.sin_family=mpcb->sa_family;
				
				memcpy(&remulid_in,&loculid_in,
				       sizeof(remulid_in));
				
				loculid_in.sin_port=mpcb->local_port;
				remulid_in.sin_port=mpcb->remote_port;
				memcpy(&loculid_in.sin_addr,
				       (struct in_addr*)&mpcb->local_ulid.a4,
				       sizeof(struct in_addr));
				memcpy(&remulid_in.sin_addr,
				       (struct in_addr*)&mpcb->remote_ulid.a4,
				       sizeof(struct in_addr));
				loculid=(struct sockaddr *)&loculid_in;
				remulid=(struct sockaddr *)&remulid_in;
				ulid_size=sizeof(loculid_in);
				break;
			case AF_INET6:
				memset(&loculid,0,sizeof(loculid));
				loculid_in6.sin6_family=mpcb->sa_family;
				
				memcpy(&remulid_in6,&loculid_in6,
				       sizeof(remulid_in6));

				loculid_in6.sin6_port=mpcb->local_port;
				remulid_in6.sin6_port=mpcb->remote_port;
				ipv6_addr_copy(&loculid_in6.sin6_addr,
					       (struct in6_addr*)&mpcb->
					       local_ulid.a6);
				ipv6_addr_copy(&remulid_in6.sin6_addr,
					       (struct in6_addr*)&mpcb->
					       remote_ulid.a6);
				
				loculid=(struct sockaddr *)&loculid_in6;
				remulid=(struct sockaddr *)&remulid_in6;
				ulid_size=sizeof(loculid_in6);
				break;
			default:
				BUG();
			}
			newtp->path_index=i+1;
			newtp->mpcb = mpcb;
			newtp->mtcp_flags=0;
			newtp->mpc=1;
			mtcp_add_sock(mpcb,newtp);

			/*Redefine the sk_data_ready function*/
			((struct sock*)newtp)->sk_data_ready=mtcp_def_readable;
			
       
			retval = sock->ops->bind(sock, loculid, ulid_size);
			if (retval<0) goto fail_bind;
			
			PDEBUG("%s:About to connect\n",__FUNCTION__);
			retval = sock->ops->connect(sock,remulid,
						    ulid_size,O_NONBLOCK);
			if (retval<0 && retval != -EINPROGRESS) 
				goto fail_connect;
			
			PDEBUG("New MTCP subsocket created, pi %d\n",i+1);
		}
	}
	return 0;
fail_bind:
	printk(KERN_ERR "MTCP subsocket bind() failed\n");
fail_connect:
	printk(KERN_ERR "MTCP subsocket connect() failed, error %d\n", 
	       retval);
	/*sock_release will indirectly call mtcp_del_sock()*/
	sock_release(sock);
	return -1;
}

static int netevent_callback(struct notifier_block *self, unsigned long event,
			     void *ctx)
{	
	struct multipath_pcb *mpcb;
	struct ulid_pair *up;
	PDEBUG("Received path update event\n");
	switch(event) {
	case NETEVENT_PATH_UPDATEV6:
		mpcb=container_of(self,struct multipath_pcb,nb);
		up=ctx;
		PDEBUG("mpcb is %p\n",mpcb);
		if (mpcb->sa_family!=AF_INET6) break;
		
		PDEBUG("ev loc ulid:" NIP6_FMT "\n",NIP6(*up->local));
		PDEBUG("ev loc ulid:" NIP6_FMT "\n",NIP6(*up->remote));
		PDEBUG("ev loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->local_ulid.a6));
		PDEBUG("ev loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->remote_ulid.a6));
		if (ipv6_addr_equal(up->local,
				    (struct in6_addr*)&mpcb->local_ulid) &&
		    ipv6_addr_equal(up->remote,
				    (struct in6_addr*)&mpcb->remote_ulid))
			mtcp_init_subsockets(mpcb,
					     up->path_indices);
		break;
        }
        return 0;
}

/*Ask to the PM to be updated about available path indices
 *
 * The argument must be any TCP socket in established state
 */
void mtcp_ask_update(struct sock *sk)
{
	struct ulid_pair up;
	struct tcp_sock *tp=tcp_sk(sk);

	PDEBUG("Entering %s\n",__FUNCTION__); /*TODEL*/

	if (!is_master_sk(tp)) return;
	/*Currently we only support AF_INET6*/
	if (sk->sk_family!=AF_INET6) return;

	up.local=&inet6_sk(sk)->saddr;
	up.remote=&inet6_sk(sk)->daddr;
	up.path_indices=0; /*This is what we ask for*/
	call_netevent_notifiers(NETEVENT_MPS_UPDATEME, &up);
}

struct multipath_pcb* mtcp_alloc_mpcb(struct sock *master_sk)
{
	struct multipath_pcb * mpcb = kmalloc(
		sizeof(struct multipath_pcb),GFP_KERNEL);
	
	memset(mpcb,0,sizeof(struct multipath_pcb));
	
	skb_queue_head_init(&mpcb->receive_queue);
	skb_queue_head_init(&mpcb->write_queue);
	skb_queue_head_init(&mpcb->retransmit_queue);
	skb_queue_head_init(&mpcb->error_queue);
	skb_queue_head_init(&mpcb->out_of_order_queue);
	
	mpcb->rcvbuf = sysctl_rmem_default;
	mpcb->sndbuf = sysctl_wmem_default;
	
	mpcb->state = TCPF_CLOSE;

	mpcb->master_sk=master_sk;

	kref_init(&mpcb->kref);
	spin_lock_init(&mpcb->lock);
	mutex_init(&mpcb->mutex);
	init_completion(&mpcb->liberate_subflow);
	
	mpcb->nb.notifier_call=netevent_callback;
	register_netevent_notifier(&mpcb->nb);
		
	return mpcb;
}

static void mpcb_release(struct kref* kref)
{
	struct multipath_pcb *mpcb;
	mpcb=container_of(kref,struct multipath_pcb,kref);
	mutex_destroy(&mpcb->mutex);
	PDEBUG("about to kfree\n");
	kfree(mpcb);
}

/*Warning: can only be called in user context
  (due to unregister_netevent_notifier)*/
void mtcp_destroy_mpcb(struct multipath_pcb *mpcb)
{
	/*Stop listening to PM events*/
	unregister_netevent_notifier(&mpcb->nb);
	/*Remove any remaining skb from the queues*/
	skb_queue_purge(&mpcb->receive_queue);
	skb_queue_purge(&mpcb->out_of_order_queue);
	kref_put(&mpcb->kref,mpcb_release);
}

/*MUST be called in user context
 */
void mtcp_add_sock(struct multipath_pcb *mpcb,struct tcp_sock *tp)
{
	/*Adding new node to head of connection_list*/
	mutex_lock(&mpcb->mutex); /*To protect against concurrency with
				    mtcp_recvmsg and mtcp_sendmsg*/
	local_bh_disable(); /*To protect against concurrency with
			      mtcp_del_sock*/
	tp->mpcb = mpcb;
	tp->next=mpcb->connection_list;
	mpcb->connection_list=tp;
	
	if (tp->path_index==2) ((struct sock*)tp)->sk_debug=1; /*TODEL*/

	mpcb->cnt_subflows++;
	kref_get(&mpcb->kref);	
	local_bh_enable();
	mutex_unlock(&mpcb->mutex);
	PDEBUG("Added subsocket with pi %d, cnt_subflows now %d\n",
	       tp->path_index,mpcb->cnt_subflows);
}

void mtcp_del_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp)
{
	struct tcp_sock *tp_prev=mpcb->connection_list;	
	int done=0;
	
	if (!in_interrupt()) {
		/*Then we must take the mutex to avoid racing
		  with mtcp_add_sock*/
		mutex_lock(&mpcb->mutex);
	}

	if (tp_prev==tp) {
		mpcb->connection_list=tp->next;
		mpcb->cnt_subflows--;
		done=1;
	}
	else for (;tp_prev && tp_prev->next;tp_prev=tp_prev->next) {
			if (tp_prev->next==tp) {
				tp_prev->next=tp->next;
				mpcb->cnt_subflows--;
				done=1;
				break;
			}
		}
	tp->mpcb=NULL; tp->next=NULL;
	if (!in_interrupt()) {
		/*Then we must take the mutex to avoid racing
		  with mtcp_add_sock*/
		mutex_unlock(&mpcb->mutex);
	}
	kref_put(&mpcb->kref,mpcb_release);
	BUG_ON(!done);
}

/**
 * Updates the metasocket ULID/port data, based on the given sock.
 * The argument sock must be the sock accessible to the application.
 * In this function, we update the meta socket info, based on the changes 
 * in the application socket (bind, address allocation, ...)
 */
void mtcp_update_metasocket(struct sock *sk)
{
	struct tcp_sock *tp;
	struct multipath_pcb *mpcb;
	if (sk->sk_protocol != IPPROTO_TCP) return;
	tp=tcp_sk(sk);
	mpcb=mpcb_from_tcpsock(tp);

	PDEBUG("Entering %s, mpcb %p\n",__FUNCTION__,mpcb);

	mpcb->sa_family=sk->sk_family;
	mpcb->remote_port=inet_sk(sk)->dport;
	mpcb->local_port=inet_sk(sk)->sport;
	
	switch (sk->sk_family) {
	case AF_INET:
		mpcb->remote_ulid.a4=inet_sk(sk)->daddr;
		mpcb->local_ulid.a4=inet_sk(sk)->saddr;
		break;
	case AF_INET6:
		ipv6_addr_copy((struct in6_addr*)&mpcb->remote_ulid,
			       &inet6_sk(sk)->daddr);
		ipv6_addr_copy((struct in6_addr*)&mpcb->local_ulid,
			       &inet6_sk(sk)->saddr);

		PDEBUG("mum loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->local_ulid.a6));
		PDEBUG("mum loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->remote_ulid.a6));

		break;
	}
}

int mtcp_is_available(struct tcp_sock *tp)
{
	/*The following code is inspired from tcp_cwnd_test (tcp_output.c)
	  We consider a subflow to be available if it has remaining space in 
	  its congestion window*/
	
	u32 in_flight, cwnd;

	if (((struct sock*)tp)->sk_state!=TCP_ESTABLISHED) return 0;
	
	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return (cwnd - in_flight);
	
	return 0;
}

/*This is the scheduler. This function decides on which flow to send
  a given MSS. Currently we choose a simple round-robin policy.
  If all subflows are found to be busy, NULL is returned*/
static struct tcp_sock* get_available_subflow(struct multipath_pcb *mpcb) 
{
	struct tcp_sock *tp;
	struct tcp_sock *cursubflow=NULL;
	
	/*if there is only one subflow, bypass the scheduling function*/
	mutex_lock(&mpcb->mutex);
	if (mpcb->cnt_subflows==1) {
		tp=mpcb->connection_list;
		goto out;
	}
	
	/*First, find the current subflow*/
	mtcp_for_each_tp(mpcb,tp)
		if (tp->mtcp_flags & MTCP_CURRENT_SUBFLOW) {
			/*Remove the flag*/
			tp->mtcp_flags&=~MTCP_CURRENT_SUBFLOW;
			cursubflow=tp;
			break;
		}
	
	/*Flag is not yet set on any subflow*/
	if (unlikely(!cursubflow)) {
		tp=mpcb->connection_list;
		cursubflow=tp;
	}
	/*Now try to find the next available flow*/

	for (tp=(tp->next)?tp->next:mpcb->connection_list;
	     tp!=cursubflow && !mtcp_is_available(tp);
	     tp=(tp->next)?tp->next:mpcb->connection_list);
	
	if (tp==cursubflow && !mtcp_is_available(tp)) {
		tp=NULL;
		goto out; /*All flows are busy currently*/
	}

	/*Set the flag to it*/
	tp->mtcp_flags|=MTCP_CURRENT_SUBFLOW;
out:
	mutex_unlock(&mpcb->mutex);
	return tp;		
}

int mtcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *master_sk = sock->sk;
	struct tcp_sock *tp;
	struct iovec *iov;
	struct multipath_pcb *mpcb;
	size_t iovlen,copied,msg_size;
	int i;
	int nberr;		
	
	if (!tcp_sk(master_sk)->mpc)
		return tcp_sendmsg(iocb,sock, msg, size);
	
	PDEBUG("Entering %s\n",__FUNCTION__);

	mpcb=mpcb_from_tcpsock(tcp_sk(master_sk));
	if (mpcb==NULL){
		BUG();
	}
	
	/* Compute the total number of bytes stored in the message*/
	iovlen=msg->msg_iovlen;
	iov=msg->msg_iov;
	msg_size=0;
	while(iovlen-- > 0) {
		msg_size+=iov->iov_len;
		iov++;
	}
	
	/*Until everything is sent, we round-robin on the subsockets
	  TODO: This part MUST be able to sleep.(to avoid looping forever)
	  Currently it sleeps inside tcp_sendmsg, but it is not the most
	  efficient, since during that time, we could try sending on other
	  subsockets*/
	copied=0;i=0;nberr=0;
	while (copied<msg_size) {		
		int ret;
		/*Find a candidate socket for eating data*/

		INIT_COMPLETION(mpcb->liberate_subflow);
		
		tp=get_available_subflow(mpcb);
		
		while (!tp) {
			/*Go sleeping until one of the subflows at least
			  becomes ready to eat data*/
			wait_for_completion(&mpcb->liberate_subflow);
			tp=get_available_subflow(mpcb);			
		}

		PDEBUG("%s:copied %d,msg_size %d, i %d, pi %d\n",
		       __FUNCTION__,
		       (int)copied,
		       (int)msg_size,i,tp->path_index);
		
		/*Let the selected socket eat*/
		ret=tcp_sendmsg(NULL,((struct sock*)tp)->sk_socket, 
				msg, copied);
		if (ret<0) {
			/*If this subflow refuses to send our data, try
			  another one. If no subflow accepts to send it
			  send the error code from the last subflow to the
			  app. If no subflow can send the data, but a part of 
			  the message has been sent already, then we tell the 
			  application about the copied bytes, instead
			  of returning the error code. The error code would be
			  returned on a subsequent call anyway.*/
			nberr++;
			if (nberr==mpcb->cnt_subflows) {
				PDEBUG("%s: returning error "
				       "to app:%d, copied %d\n",__FUNCTION__,
				       ret,(int)copied);
				return (copied)?copied:ret;
			}
			continue;
		}
		copied+=ret;
		BUG_ON(i++==30);
	}

	PDEBUG("Leaving %s, copied %d, next data seq %x\n",
	       __FUNCTION__,
	       (int) copied,mpcb->write_seq);
	return copied;
}

/**
 * mtcp_wait_data - wait for data to arrive at sk_receive_queue
 * on any of the subsockets attached to the mpcb
 * @mpcb:  the mpcb to wait on
 * @sk:    its master socket
 * @timeo: for how long
 *
 * Now socket state including sk->sk_err is changed only under lock,
 * hence we may omit checks after joining wait queue.
 * We check receive queue before schedule() only as optimization;
 * it is very likely that release_sock() added new data.
 */
int mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk,
		   long *timeo)
{
	int rc; struct sock *sk; struct tcp_sock *tp;
	DEFINE_WAIT(wait);

	prepare_to_wait(master_sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	mtcp_for_each_sk(mpcb,sk,tp) {
		set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
		tp->wait_data_bit_set=1;
	}
	rc = mtcp_wait_event_any_sk(mpcb, sk, timeo, 
				    !skb_queue_empty(&sk->sk_receive_queue));

	mtcp_for_each_sk(mpcb,sk,tp)
		if (tp->wait_data_bit_set) {
			clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
			tp->wait_data_bit_set=0;
		}
	finish_wait(master_sk->sk_sleep, &wait);
	return rc;
}

void mtcp_ofo_queue(struct multipath_pcb *mpcb, struct msghdr *msg, size_t *len,
		    u32 *data_seq, int *copied, int flags)
{
	struct sk_buff *skb;
	int err;
	u32 data_offset;
	unsigned long used;
	u32 rcv_nxt=0;
	int enqueue=0; /*1 if we must enqueue from ofo to rcv queue
			 to insufficient space in app buffer*/
	struct tcp_sock *tp;
	
	while ((skb = skb_peek(&mpcb->out_of_order_queue)) != NULL) {
		tp=tcp_sk(skb->sk);
		if (after(TCP_SKB_CB(skb)->data_seq, *data_seq))
			break;
				
		if (!after(TCP_SKB_CB(skb)->end_data_seq, *data_seq)) {
			printk(KERN_ERR "ofo packet was already received."
			       "skb->end_data_seq:%x,exp. data_seq:%x\n",
			       TCP_SKB_CB(skb)->end_data_seq,*data_seq);
			/*Should not happen in the current design*/
			printk(KERN_ERR "debug:%d,count:%d\n",skb->debug,
			       skb->debug_count);
			printk(KERN_ERR "init data_seq:%x,*copied:%x\n",
			       skb->data_seq,*copied);
			console_loglevel=8;
			
			BUG();
			__skb_unlink(skb, &mpcb->out_of_order_queue);
			__kfree_skb(skb);
			continue;
		}
		PDEBUG("ofo delivery : "
		       "nxt_data_seq %X data_seq %X - %X, enqueue is %d\n",
		       *data_seq, TCP_SKB_CB(skb)->data_seq,
		       TCP_SKB_CB(skb)->end_data_seq,enqueue);
		
		__skb_unlink(skb, &mpcb->out_of_order_queue);

		/*if enqueue is 1, than the app buffer is full and we must
		  enqueue the buff into the receive queue*/
		if (enqueue) {
			__skb_queue_tail(&mpcb->receive_queue, skb);
			rcv_nxt+=skb->len;
			continue;
		}
		
		/*The skb can be read by the app*/
		data_offset= *data_seq - TCP_SKB_CB(skb)->data_seq;

		BUG_ON(data_offset != 0);

		used = skb->len - data_offset;
		if (*len < used)
			used = *len;
				
		err=skb_copy_datagram_iovec(skb, data_offset,
					    msg->msg_iov, used);
		
		
		BUG_ON(err);

		skb->debug|=MTCP_DEBUG_OFO_QUEUE;
		skb->debug_count++;
		
		mtcp_check_seqnums(mpcb,1);

		*copied+=used;
		*data_seq+=used;
		*len-=used;
		mpcb->ofo_bytes-=used;

		mtcp_check_seqnums(mpcb,0);
		
		/*We can free the skb only if it has been completely eaten
		  Else we queue it in the mpcb receive queue, for reading by
		  the app on next call to tcp_recvmsg().*/
 		if (*data_seq==TCP_SKB_CB(skb)->end_data_seq)
			__kfree_skb(skb);
		else {
			__skb_queue_tail(&mpcb->receive_queue, skb);
			BUG_ON(*len!=0);
			/*Now we must also enqueue all subsequent contigues 
			  skbs*/
			enqueue=1;
			rcv_nxt=TCP_SKB_CB(skb)->end_data_seq;
			data_seq=&rcv_nxt;
		}
	}
}

static inline void mtcp_eat_skb(struct multipath_pcb *mpcb, struct sk_buff *skb)
{
	__skb_unlink(skb,&mpcb->receive_queue);
	__kfree_skb(skb);
}

/*This verifies if any skbuff has been let on the mpcb 
  receive queue due app buffer being full.
  This only needs to be called when starting tcp_recvmsg, since 
  during immediate segment reception from TCP subsockets, segments reach
  the receive queue only when the app buffer becomes full.*/
int mtcp_check_rcv_queue(struct multipath_pcb *mpcb,struct msghdr *msg, 
			 size_t *len, u32 *data_seq, int *copied, int flags)
{
	struct sk_buff *skb;
	struct tcp_sock *tp;
	int err;
	if (skb_queue_empty(&mpcb->receive_queue)) 
		return 0;

	do {
		u32 offset;
		unsigned long used;
		skb = skb_peek(&mpcb->receive_queue);

		if (!skb) return 0;

		tp=tcp_sk(skb->sk);

		if (before(*data_seq,TCP_SKB_CB(skb)->data_seq)) {
			printk(KERN_ERR 
			       "%s bug: copied %X "
			       "dataseq %X\n", __FUNCTION__, *data_seq, 
			       TCP_SKB_CB(skb)->data_seq);
			console_loglevel=8;
			BUG();
		}
		skb->data_seq=*data_seq; /*TODEL*/
		offset = *data_seq - TCP_SKB_CB(skb)->data_seq;
		BUG_ON(offset >= skb->len);

		if (skb->len != 
		    TCP_SKB_CB(skb)->end_data_seq - TCP_SKB_CB(skb)->data_seq) {
			printk(KERN_ERR "skb->len:%d, should be %d\n",
			       skb->len,
			       TCP_SKB_CB(skb)->end_data_seq - 
			       TCP_SKB_CB(skb)->data_seq);
			console_loglevel=8;
			BUG();
		}
		used = skb->len - offset;
		if (*len < used)
			used = *len;
		
		err=skb_copy_datagram_iovec(skb, offset,
					    msg->msg_iov, used);		
		BUG_ON(err);
		if (err) return err;
		
		skb->debug|=MTCP_DEBUG_CHECK_RCV_QUEUE;
		skb->debug_count++;;

		mtcp_check_seqnums(mpcb,1);

		*copied+=used;
		*data_seq+=used;
		*len-=used;
		mpcb->ofo_bytes-=used;	   

		mtcp_check_seqnums(mpcb,0);    

/*		PDEBUG("copied %d bytes, from dataseq %x to %x, "
		       "len %d, skb->len %d\n",*copied,
		       TCP_SKB_CB(skb)->data_seq+(u32)offset,
		       TCP_SKB_CB(skb)->data_seq+(u32)used+(u32)offset,
		       (int)*len,(int)skb->len);*/
		
 		if (*data_seq==TCP_SKB_CB(skb)->end_data_seq && 
		    !(flags & MSG_PEEK))
			mtcp_eat_skb(mpcb, skb);
		else if (!(flags & MSG_PEEK) && *len!=0) {
				printk(KERN_ERR 
				       "%s bug: copied %X "
				       "dataseq %X, *len %d\n", __FUNCTION__, 
				       *data_seq, 
				       TCP_SKB_CB(skb)->data_seq, (int)*len);
				printk(KERN_ERR "debug:%d,count:%d\n",skb->debug,
				       skb->debug_count);
				printk(KERN_ERR "init data_seq:%x,used:%d\n",
				       skb->data_seq,(int)used);
				BUG();
		}			
		
	} while (*len>0);
	return 0;
}

void mtcp_check_seqnums(struct multipath_pcb *mpcb, int before)
{
	int subsock_bytes=0;
	struct sock *sk;
	struct tcp_sock *tp;

	mtcp_for_each_sk(mpcb,sk,tp)
		subsock_bytes+=tp->bytes_eaten;
	/*The number bytes received by the metasocket must always
	  be equal to the sum of the number of bytes received by the
	  subsockets, minus the number of bytes waiting in the meta-ofo
	  and meta-receive queue*/
	if (unlikely(subsock_bytes!=mpcb->copied_seq+mpcb->ofo_bytes)) {
		struct sk_buff *first_ofo=skb_peek(&mpcb->out_of_order_queue);
		printk(KERN_ERR "subsock_bytes:%d,mpcb bytes:%d, "
		       "meta-ofo bytes:%d, "
		       "before: %d\n",
		       subsock_bytes,
		       mpcb->copied_seq,mpcb->ofo_bytes,before);
		console_loglevel=8;
		printk(KERN_ERR "mpcb next exp. dataseq:%x\n"
		       "  meta-recv queue:%d\n"
		       "  meta-ofo queue:%d\n"
		       "  first seq,dataseq in meta-ofo-queue:%x,%x\n",
		       mpcb->copied_seq,
		       skb_queue_len(&mpcb->receive_queue),
		       skb_queue_len(&mpcb->out_of_order_queue),
		       first_ofo?TCP_SKB_CB(first_ofo)->seq:0,
		       first_ofo?TCP_SKB_CB(first_ofo)->data_seq:0);
		mtcp_for_each_sk(mpcb,sk,tp) {
			struct sk_buff *first_ofosub=skb_peek(
				&tp->out_of_order_queue);
			printk(KERN_ERR "pi:%d\n"
			       "  recv queue:%d\n"
			       "  ofo queue:%d\n"
			       "  first seq,dataseq in ofo queue:%x,%x\n"
			       "  state:%d\n"
			       "  next exp. seq num:%x\n"
			       "  bytes_eaten:%d\n",tp->path_index,
			       skb_queue_len(&sk->sk_receive_queue),
			       skb_queue_len(&tp->out_of_order_queue),
			       first_ofosub?TCP_SKB_CB(first_ofosub)->seq:0,
			       first_ofosub?TCP_SKB_CB(first_ofosub)->
			       data_seq:0,
			       sk->sk_state,
			       *tp->seq,
			       tp->bytes_eaten);
		}
		
		BUG();
	}
}

int mtcp_queue_skb(struct sock *sk,struct sk_buff *skb, u32 offset,
		   unsigned long *used, struct msghdr *msg, size_t *len,
		   u32 *data_seq, int *copied, int flags)
{
	struct tcp_sock *tp=tcp_sk(sk);
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tp);
	u32 data_offset;
	int err;

	if (skb->len>1500) BUG();      
	
	/*Is this a duplicate segment ?*/
	if (after(*data_seq,TCP_SKB_CB(skb)->data_seq+skb->len)) {
		/*In the current implementation, we do not 
		  retransmit skbs on other queues, so we cannot have any
		  duplicate here. Duplicates are managed by each subflow 
		  individually.*/
		printk(KERN_ERR "debug:%d,count:%d\n",skb->debug,
		       skb->debug_count);
		printk(KERN_ERR "init data_seq:%x,len:%d,copied:%x,"
		       "data_seq:%x, skb->len : %d,ucopy.task:%p\n",
		       skb->data_seq,(int)*len,*data_seq,
		       TCP_SKB_CB(skb)->data_seq,(int)skb->len,
		       mpcb->ucopy.task);
		console_loglevel=8;
		BUG();
		return MTCP_EATEN;
	}

	if (before(*data_seq,TCP_SKB_CB(skb)->data_seq)) {
		/*the skb must be queued in the ofo queue*/
		__skb_unlink(skb, &sk->sk_receive_queue);
		
		/*Since the skb is removed from the receive queue
		  we must advance the seq num in the corresponding
		  tp*/
		mtcp_check_seqnums(mpcb,1);
		*tp->seq +=skb->len;
		tp->copied+=skb->len;		
		tp->bytes_eaten+=skb->len;
		mpcb->ofo_bytes+=skb->len;
		mtcp_check_seqnums(mpcb,0);
		
		/*TODEL*/
		PDEBUG("exp. data_seq:%x, skb->data_seq:%x\n",
		       *data_seq,TCP_SKB_CB(skb)->data_seq);
		
		if (!skb_peek(&mpcb->out_of_order_queue)) {
			/* Initial out of order segment */
			PDEBUG("First meta-ofo segment\n");
			__skb_queue_head(&mpcb->out_of_order_queue, skb);
			return MTCP_QUEUED;
		}
		else {	
			struct sk_buff *skb1 = mpcb->out_of_order_queue.prev;
			/* Find place to insert this segment. */
			do {
				if (!after(TCP_SKB_CB(skb1)->data_seq, 
					   TCP_SKB_CB(skb)->data_seq))
					break;
			} while ((skb1 = skb1->prev) !=
				 (struct sk_buff *)&mpcb->out_of_order_queue);

			/* Do skb overlap to previous one? */
			if (skb1 != 
			    (struct sk_buff *)&mpcb->out_of_order_queue &&
			    before(TCP_SKB_CB(skb)->data_seq, 
				   TCP_SKB_CB(skb1)->end_data_seq)) {
				if (!after(TCP_SKB_CB(skb)->end_data_seq, 
					   TCP_SKB_CB(skb1)->end_data_seq)) {
					/* All the bits are present. Drop. */
					BUG();
					return MTCP_EATEN;
				}
				if (!after(TCP_SKB_CB(skb)->data_seq, 
					   TCP_SKB_CB(skb1)->data_seq)) {
					/*skb and skb1 have the same starting 
					  point, but skb terminates after skb1*/
					BUG();
					skb1 = skb1->prev;
				}
			}
			__skb_insert(skb, skb1, skb1->next, 
				     &mpcb->out_of_order_queue);
			/* And clean segments covered by new one as whole. */
			while ((skb1 = skb->next) !=
			       (struct sk_buff *)&mpcb->out_of_order_queue &&
			       after(TCP_SKB_CB(skb)->end_data_seq, 
				     TCP_SKB_CB(skb1)->data_seq)) {
				if (!before(TCP_SKB_CB(skb)->end_data_seq, 
					    TCP_SKB_CB(skb1)->end_data_seq)) {
					__skb_unlink(skb1, 
						     &mpcb->out_of_order_queue);
					__kfree_skb(skb1);
				}
			}
			return MTCP_QUEUED;
		}
	}

	else {
		/*The skb can be read by the app*/
		data_offset= *data_seq - TCP_SKB_CB(skb)->data_seq;
		*used = skb->len - data_offset;
		/*In the current implementation, we do not 
		  retransmit skbs on other queues, so we cannot have any
		  duplicate here. Duplicates are managed by each subflow 
		  individually.*/
		if (*used==0) {
			printk(KERN_ERR "debug:%d,count:%d\n",skb->debug,
			       skb->debug_count);
			printk(KERN_ERR "init data_seq:%x,used:%d\n",
			       skb->data_seq,(int)*used);
			printk(KERN_ERR "init data_seq:%x,len:%d,copied:%x,"
			       "data_seq:%x, skb->len : %d,ucopy.task:%p\n",
			       skb->data_seq,(int)*len,*data_seq,
			       TCP_SKB_CB(skb)->data_seq,(int)skb->len,
			       mpcb->ucopy.task);
			console_loglevel=8;
			BUG();
		}

		if (data_offset != offset) {
			console_loglevel=8;
			printk(KERN_ERR "metasocket and subsocket don't agree"
			       "on offset value\n");
			BUG();
		}
		if (*len < *used)
			*used = *len;
		
		err=skb_copy_datagram_iovec(skb, data_offset,
					    msg->msg_iov, *used);
		BUG_ON(err);
		if (err) return err;
		
		skb->debug|=MTCP_DEBUG_QUEUE_SKB;
		skb->debug_count++;

		mtcp_check_seqnums(mpcb,1);

		*tp->seq += *used;
		*data_seq += *used;
		*len -= *used;
		*copied+=*used;
		tp->copied+=*used;
		tp->bytes_eaten+=*used;

		mtcp_check_seqnums(mpcb,0);
		
		/*Check if this fills a gap in the ofo queue*/
		if (!skb_queue_empty(&mpcb->out_of_order_queue))
			mtcp_ofo_queue(mpcb,msg,len,data_seq,copied, flags);
		/*If the skb has been partially eaten, tcp_recvmsg
		  will see it anyway thanks to the @used pointer.*/
		return MTCP_EATEN;
	}
}

MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mtcp_sendmsg);
