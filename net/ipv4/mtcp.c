
/*
 *	MTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Partially inspired from initial user space MTCP stack by Costin Raiciu.
 *
 *      date : December 09
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

/*=====================================*/
/*DEBUGGING*/

#ifdef MTCP_RCV_QUEUE_DEBUG
struct mtcp_debug mtcp_debug_array1[1000];
struct mtcp_debug mtcp_debug_array2[1000];

void print_debug_array(void)
{
	int i;
	printk(KERN_ERR "debug array, path index 1:\n");
	for (i=0;i<1000 && mtcp_debug_array1[i-1].end==0;i++) {
		printk(KERN_ERR "\t%s:skb %x, len %d\n",
		       mtcp_debug_array1[i].func_name,
		       mtcp_debug_array1[i].seq,
		       mtcp_debug_array1[i].len);
	}
	printk(KERN_ERR "debug array, path index 2:\n");
	for (i=0;i<1000 && mtcp_debug_array2[i-1].end==0;i++) {
		printk(KERN_ERR "\t%s:skb %x, len %d\n",
		       mtcp_debug_array2[i].func_name,
		       mtcp_debug_array2[i].seq,
		       mtcp_debug_array2[i].len);
	}
}

void freeze_rcv_queue(struct sock *sk, const char *func_name)
{
	int i;
	struct sk_buff *skb;	
	struct tcp_sock *tp=tcp_sk(sk);
	int path_index=tp->path_index;
	struct mtcp_debug *mtcp_debug_array;

	if (path_index==0 || path_index==1)
		mtcp_debug_array=mtcp_debug_array1;
	else
		mtcp_debug_array=mtcp_debug_array2;
	for (skb=skb_peek(&sk->sk_receive_queue),i=0;
	     skb && skb!=(struct sk_buff*)&sk->sk_receive_queue;
	     skb=skb->next,i++) {
		mtcp_debug_array[i].func_name=func_name;
		mtcp_debug_array[i].seq=TCP_SKB_CB(skb)->seq;
		mtcp_debug_array[i].len=skb->len;			
		mtcp_debug_array[i].end=0;
		BUG_ON(i>=999);
	}
	if (i>0) mtcp_debug_array[i-1].end=1;
	else {
		mtcp_debug_array[0].func_name="NO_FUNC";
		mtcp_debug_array[0].end=1;
	}
}

#endif
/*=====================================*/

inline void mtcp_reset_options(struct multipath_options* mopt){
#ifdef CONFIG_MTCP_PM
	mopt->remote_token = -1;
	if (mopt->ip_count>0){
		if (mopt->ip_list){
			mopt->ip_list = NULL;
		}
	}
	mopt->ip_count = 0;
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
		path_indices&=~PI_TO_FLAG(tp->path_index);
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
	/*We consider a subflow to be available if it has remaining space in 
	  its sending buffers, and it is established*/
	
	if (((struct sock*)tp)->sk_state!=TCP_ESTABLISHED) return 0;
	
	return sk_stream_memory_free((struct sock*)tp);
}

/*This is the scheduler. This function decides on which flow to send
  a given MSS. Currently we choose a simple round-robin policy.
  If all subflows are found to be busy, NULL is returned*/
static struct tcp_sock* get_available_subflow(struct multipath_pcb *mpcb) 
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct tcp_sock *besttp;
	unsigned int min_fill_ratio=0xffffffff;
	
	/*if there is only one subflow, bypass the scheduling function*/
	mutex_lock(&mpcb->mutex);
	if (mpcb->cnt_subflows==1) {
		besttp=mpcb->connection_list;
		goto out;
	}
	
	besttp=mpcb->connection_list;
	/*First, find the best subflow*/
	mtcp_for_each_sk(mpcb,sk,tp) {
		/*The shift is to avoid having to deal with a float*/
		unsigned int fill_ratio=(sk->sk_wmem_queued<<4)/sk->sk_sndbuf;
		if (!mtcp_is_available(tp)) 
			continue;
		if (fill_ratio<min_fill_ratio) {
			min_fill_ratio=fill_ratio;
			besttp=tp;
		}
	}

out:		
	/*Now, even the best subflow may be uneligible for sending.
	  In that case, we must return NULL.*/
	if (!mtcp_is_available(besttp))
		besttp=NULL;
	
	mutex_unlock(&mpcb->mutex);
	return besttp;		
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
	
	copied=0;i=0;nberr=0;
	while (copied<msg_size) {		
		int ret;
		/*Find a candidate socket for eating data*/

		INIT_COMPLETION(mpcb->liberate_subflow);
		
		tp=get_available_subflow(mpcb);
		
		while (!tp) {
			int err;
			/*Go sleeping until one of the subflows at least
			  becomes ready to eat data.
			  Note that we must be interruptible, because else we
			  cannot be killed*/
			err=wait_for_completion_interruptible(
				&mpcb->liberate_subflow);
			if (err<0) return err;
			
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
			/*Now we must also enqueue all subsequent contiguous
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
  receive queue due to app buffer being full.
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
	/*The number of bytes received by the metasocket must always
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

	/*First, derive the dataseq if it is not yet done*/
	if (mtcp_get_dataseq_mapping(mpcb, tp, skb)<0)
		return -1;

	/*Is this a duplicate segment ?*/
	if (after(*data_seq,TCP_SKB_CB(skb)->end_data_seq)) {
		/*Duplicate segment. We can arrive here only if a segment 
		  has been retransmitted by the sender on another subflow.
		  Retransmissions on the same subflow are handled at the
		  subflow level.*/

		/* We do not read the skb, since it was already received on
		   another subflow, but we advance the seqnum so that the
		   subflow can continue */
		*used=skb->len; /*We must also tell that the whole
				  skb has been used, else it will be kept
				  in the subsocket.*/
		tp->copied+=*used; /*tp->copied is used by tcp_recvmsg
				      to know that it can evaluate again
				      receive buffer, and maybe recompute
				      the receive window, since memory is
				      freed.*/
		*tp->seq +=*used;		
		
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
					/* We do not read the skb, since it was
					   already received on
					   another subflow */
					/* first cancel counters we
					   have incremented before, since
					   the skb is finally not read*/
					BUG_ON(!(TCP_SKB_CB(skb)->data_seq==
						 TCP_SKB_CB(skb1)->data_seq &&
						 TCP_SKB_CB(skb)->end_data_seq==
						 TCP_SKB_CB(skb1)->end_data_seq
						       ));
					tp->bytes_eaten-=skb->len;
					mpcb->ofo_bytes-=skb->len;
					__kfree_skb(skb);
					return MTCP_DROPPED;
				}
				if (!after(TCP_SKB_CB(skb)->data_seq, 
					   TCP_SKB_CB(skb1)->data_seq)) {
					/*skb and skb1 have the same starting 
					  point, but skb terminates after skb1*/
					printk(KERN_ERR "skb->data_seq:%x,"
					       "skb->end_data_seq:%x,"
					       "skb1->data_seq:%x,"
					       "skb1->end_data_seq:%x\n",
					       TCP_SKB_CB(skb)->data_seq,
					       TCP_SKB_CB(skb)->end_data_seq,
					       TCP_SKB_CB(skb1)->data_seq,
					       TCP_SKB_CB(skb1)->end_data_seq);
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
		/*duplicate segment*/
		if (*used==0) {
			/*Since this segment has already been received on
			  another subflow, we can just ignore it, and advance
			  the subflow seqnum of this subsocket.
			  Note that we do not advance tp->bytes_eaten, since 
			  this particular data is not eaten by the app.*/
			*used=skb->len;
			*tp->seq += *used;
			tp->copied+=*used;			
			return MTCP_EATEN;
		}

		if (data_offset != offset) {
			/*This can happen if the segment has been already
			  received on another subflow, and partly read by the
			  app. The original subflow that received the segment
			  is aware of the offset, but not the new one.
			  Here, for the purpose of debugging, we check 
			  our assertion that indeed the data already arrived.
			  Since it has only be partly read, the only place
			  it can be is at the head of one of the subflow
			  receive queues, or at the head of the meta-receive
			  queue.*/

			struct sk_buff *skb1=skb_peek(&mpcb->receive_queue);
			struct sock *search_sk;
			struct tcp_sock *search_tp;
			int found_duplicate=0;

			/*Is the segment in one of the subflows ?*/
			mtcp_for_each_sk(mpcb,search_sk,search_tp) {
				struct sk_buff *search_skb=
					skb_peek(&sk->sk_receive_queue);
				if (search_skb && 
				    TCP_SKB_CB(search_skb)->data_seq
				    ==TCP_SKB_CB(skb)->data_seq && 
				    TCP_SKB_CB(search_skb)->end_data_seq
				    ==TCP_SKB_CB(skb)->end_data_seq) {
					found_duplicate=1;
					break;
				}
			}
			
			/*If it is not in one of the subflow,
			  we check the receive queue of the meta-flow*/
			if (!found_duplicate && skb1 && 
			    TCP_SKB_CB(skb1)->data_seq
			    ==TCP_SKB_CB(skb)->data_seq &&
			    TCP_SKB_CB(skb1)->end_data_seq ==
			    TCP_SKB_CB(skb)->end_data_seq)
				found_duplicate=1;
			
			if (!found_duplicate)
			{
				
				console_loglevel=8;
				printk(KERN_ERR "metasocket and subsocket "
				       "don't agree "
				       "on offset value\n");
				printk(KERN_ERR "offset:%d,"
				       "data_offset:%d, skb->data_seq:%x,"
				       "skb->end_data_seq:%x,skb1:%p\n",offset,
				       data_offset,TCP_SKB_CB(skb)->data_seq,
				       TCP_SKB_CB(skb)->end_data_seq,skb1);
				if (skb1) {
					printk(KERN_ERR "skb1->data_seq:%x,"
					       "skb1->end_data_seq:%x\n",
					       TCP_SKB_CB(skb1)->data_seq,
					       TCP_SKB_CB(skb1)->end_data_seq);
				}
				BUG();
			}
			else {
				/*OK our assertion is verified, we can
				  safely drop the new segment*/
				/* We do not read the skb, since it was 
				   already received on
				   another subflow, but we advance the seqnum 
				   so that the
				   subflow can continue */
				*used=skb->len;				
				*tp->seq +=*used;
				tp->copied+=*used;
				
				return MTCP_EATEN;
			}
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

/**
 * specific version of skb_entail (tcp.c), that handles segment reinjection
 * in other subflow.
 * Here, we do not set the data seq, since it remains the same. However, 
 * we do change the subflow seqnum.
 *
 * Note that we make the assumption that, within the local system, every
 * segment has tcb->sub_seq==tcb->seq, that is, the dataseq is not shifted
 * compared to the subflow seqnum. Put another way, the dataseq referenced
 * is actually the number of the first data byte in the segment.
 */
static inline void mtcp_skb_entail_reinj(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	
	tcb->seq      = tcb->end_seq = tcb->sub_seq = tp->write_seq;
	tcb->sacked = 0; /*reset the sacked field: from the point of view
			   of this subflow, we are sending a brand new
			   segment*/
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/*Algorithm by Bryan Kernighan to count bits in a word*/
static inline int count_bits(unsigned int v)
{
	unsigned int c; /* c accumulates the total bits set in v*/
	for (c = 0; v; c++)
	{
		v &= v - 1; /* clear the least significant bit set*/
	}
	return c;
}

/**
 * Reinject data from one TCP subflow to another one. 
 * The @skb given pertains to the original tp, that keeps it
 * because the skb is still sent on the original tp. But additionnally,
 * it is sent on the other subflow. 
 *
 * @pre : @sk must be a tcp subsocket in ESTABLISHED state
 */
void __mtcp_reinject_data(struct sk_buff *orig_skb, struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th;

	/*If the skb has already been enqueued in this sk, just 
	  return immediately*/
	if (PI_TO_FLAG(tp->path_index) & orig_skb->path_mask)
		return;
	
	/*Remember that we have enqueued this skb on this path*/
	BUG_ON(count_bits(orig_skb->path_mask)!=1);

	orig_skb->path_mask|=PI_TO_FLAG(tp->path_index);

	BUG_ON(count_bits(orig_skb->path_mask)!=2);

	skb=skb_copy(orig_skb,GFP_ATOMIC);
	skb->sk=sk;

	th=tcp_hdr(skb);
	
	BUG_ON(!skb);
	BUG_ON(skb->path_mask!=orig_skb->path_mask);
	
	skb->debug2=25;              

	mtcp_skb_entail_reinj(sk, skb);
	tp->write_seq += skb->len;
	tp->last_write_seq=TCP_SKB_CB(skb)->end_data_seq;
	TCP_SKB_CB(skb)->end_seq += skb->len;
}

void mtcp_reinject_data(struct sock *orig_sk, struct sock *retrans_sk)
{
	struct sk_buff *skb_it;
	struct tcp_sock *orig_tp = tcp_sk(orig_sk);
	struct tcp_sock *retrans_tp = tcp_sk(retrans_sk);
	int mss_now;	
	
	bh_lock_sock(retrans_sk);

	for(skb_it=orig_sk->sk_write_queue.next;
	    skb_it != (struct sk_buff*)&orig_sk->sk_write_queue;
	    skb_it=skb_it->next) {
		skb_it->path_mask|=PI_TO_FLAG(orig_tp->path_index);
		__mtcp_reinject_data(skb_it,retrans_sk);
	}
	mss_now = tcp_current_mss(retrans_sk, 0);
	tcp_push(retrans_sk, 0, mss_now, retrans_tp->nonagle);

	bh_unlock_sock(retrans_sk);
}

/**
 * To be called when a segment is in order. That is, either when it is received 
 * and is immediately in subflow-order, or when it is stored in the ofo-queue
 * and becomes in-order. This function retrieves the data_seq and end_data_seq
 * values, needed for that segment to be transmitted to the meta-flow.
 * *If the segment already holds a mapping, the current mapping is replaced 
 *  with the one provided in the segment.
 * *If the segment contains no mapping, we check if its dataseq can be derived 
 *  from the currently stored mapping. If it cannot, then there is an error,
 *  and it must be dropped.
 *
 * - If the mapping has been correctly updated, or the skb has correctly 
 *   been given its dataseq, we then check if the segment is in meta-order.
 *   i) if it is: we return 1
 *   ii) if it is not in meta-order (keep in mind that the precondition requires
 *       that it is in subflow order): we return 0
 * - If the skb is faulty (does not contain a dataseq option, and seqnum
 *   not contained in currently stored mapping), we return -1
 * 
 */
int mtcp_get_dataseq_mapping(struct multipath_pcb *mpcb, struct tcp_sock *tp, 
			     struct sk_buff *skb)
{
	int changed=0;

	if (TCP_SKB_CB(skb)->data_len) {
		tp->map_data_seq=TCP_SKB_CB(skb)->data_seq;
		tp->map_data_len=TCP_SKB_CB(skb)->data_len;
		tp->map_subseq=TCP_SKB_CB(skb)->sub_seq;
		changed=1;
	}

	/*data len does not count for the subflow FIN,
	  include the FIN in the mapping now.*/
	if (tcp_hdr(skb)->fin)
		tp->map_data_len++;

	/*Even if we have received a mapping update, it may differ from
	  the seqnum contained in the
	  TCP header. In that case we must recompute the data_seq and 
	  end_data_seq accordingly. This is what happens in case of TSO, because
	  the NIC keeps the option as is.*/
	
	if (before(TCP_SKB_CB(skb)->seq,tp->map_subseq) ||
	    after(TCP_SKB_CB(skb)->end_seq,
		  tp->map_subseq+tp->map_data_len)) {
		printk(KERN_ERR "seq:%x,tp->map_subseq:%x,"
		       "end_seq:%x,tp->map_data_len:%d,changed:%d\n",
		       TCP_SKB_CB(skb)->seq,tp->map_subseq,
		       TCP_SKB_CB(skb)->end_seq,tp->map_data_len,
		       changed);
		BUG(); /*If we only speak with our own implementation,
			 reaching this point can only be a bug, later we
			 can remove this.*/
		return -1;
	}
	/*OK, the segment is inside the mapping, we can
	  derive the dataseq. Note that we maintain 
	  TCP_SKB_CB(skb)->data_len to zero, so as not to mix
	  received mappings and derived dataseqs.*/
	TCP_SKB_CB(skb)->data_seq=tp->map_data_seq+
		(TCP_SKB_CB(skb)->seq-tp->map_subseq);
	TCP_SKB_CB(skb)->end_data_seq=
		TCP_SKB_CB(skb)->data_seq+skb->len;
	TCP_SKB_CB(skb)->data_len=0; /*To indicate that there is not anymore
				       general mapping information in that 
				       segment (the mapping info is now 
				       consumed)*/
		
	/*Check now if the segment is in meta-order*/
	
	if (TCP_SKB_CB(skb)->data_seq==mpcb->copied_seq)
		return 1;
	else return 0;
}

#ifdef CONFIG_MTCP_PM
/* Generates a token for a new MPTCP connection
 * Currently we assign sequential tokens to
 * successive MPTCP connections. In the future we
 * will need to define random tokens, while avoiding
 * collisions.
 */
u32 mtcp_new_token(void)
{
	static u32 latest_token=0;
	latest_token++;
	return latest_token;
}
#endif

MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mtcp_sendmsg);
