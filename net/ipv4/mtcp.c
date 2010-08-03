/*
 *	MPTCP implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *      Partially inspired from initial user space MPTCP stack by Costin Raiciu.
 *
 *      date : June 10
 *
 *      Important note:
 *            When one wants to add support for closing subsockets *during*
 *             a communication, he must ensure that all skbs belonging to
 *             that socket are removed from the meta-queues. Failing
 *             to do this would lead to General Protection Fault.
 *             See also comment in function mtcp_destroy_mpcb().
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
#include <linux/inetdevice.h>
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
 * Sets the pending_data flag in the mpcb structure, and wakes it up.
 *
 * Working of the pending_data flag:
 *  Whenever there is data ready to be copied to the app, (thus, in meta-order)
 *  the flag must be set to one. So 
 *    -when new data becomes available, we must 
 *     set the flag. New data is available if it just appeared in one of the 
 *     subsock receive queues (either because it was in order, or it left the
 *     ofo queue to enter the receive queue) AND it is in meta-order.
 *    -When the flag is set, and we finish copying data to the app, we check
 *     whether further data is available. If there is further data, the flag 
 *     remains set, if there is no data anymore, we reset the flag, until
 *     the data arrives. In theory, the check should be done at every 
 *     increment of mpcb->copied_seq, that is, each time data is eaten
 *     by the app. However, although there are quite diverse places where
 *     data is copied to the app, all are performed in the context of the
 *     tcp_recvmsg call. (even the one in tcp_data_queue, since the ucopy
 *     structure used there is defined only by tcp_recvmsg).
 *     So it is completely sufficient to do the check just before to return 
 *     to the app, from tcp_recvmsg.
 *
 *  Note that the intent of that pending_data flag is to enable tcp_poll to
 *  determine whether there is pending data. This job is made more difficult,
 *  because in-order data arriving on a subsock does not mean that this data
 *  is in meta-order. If it is not, and we wake-up the app, the app can crash
 *  because the subsequent read call will fail. 
 *  Note also that while single-path tcp uses the difference rcv_nxt-copied_seq
 *  to determine how many bytes are available for the app, we instead use
 *  a single flag, that just tells "at least one byte is available".
 *  This implies that the socket option SO_RCVLOWAT is currently not supported.
 *  rcvlowat is kept at its default value of 1 byte.
 */
void mtcp_data_ready(struct sock *sk)
{
	struct tcp_sock *tp=tcp_sk(sk);
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tp);

	if (mpcb) {
		mpcb->pending_data=1;
		mpcb->master_sk->sk_data_ready(mpcb->master_sk, 0);
	}
#ifdef CONFIG_MTCP_PM
	else {
		/*This tp is not yet attached to the mpcb*/
		BUG_ON(!tp->pending);
		mpcb=mtcp_hash_find(tp->mtcp_loc_token);
		BUG_ON(!mpcb);
		mpcb->pending_data=1;
		mpcb->master_sk->sk_data_ready(mpcb->master_sk, 0);
		mpcb_put(mpcb);
	}
#endif
}

/**
 * Creates as many sockets as path indices announced by the Path Manager.
 * The first path indices are (re)allocated to existing sockets.
 * New sockets are created if needed.
 * Note that this is called only at client side.
 * Server calls mtcp_check_new_subflow().
 *
 *
 * WARNING: We make the assumption that this function is run in user context
 *      (we use sock_create_kern, that reserves ressources with GFP_KERNEL)
 *      AND only one user process can trigger the sending of a PATH_UPDATE
 *      notification. This is in conformance with the fact that only one PM
 *      can send messages to the MPS, according to our multipath arch.
 *      (further PMs are cascaded and use the depth attribute).
 */
int mtcp_init_subsockets(struct multipath_pcb *mpcb, 
			 uint32_t path_indices)
{
	int i;
	int retval;
	struct socket *sock;
	struct tcp_sock *tp=mpcb->connection_list;
	struct tcp_sock *newtp;

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
			int newpi=i+1;
			/*a new socket must be created*/
			retval = sock_create_kern(mpcb->sa_family, SOCK_STREAM, 
						  IPPROTO_MTCPSUB, &sock);
			if (retval<0) {
				printk(KERN_ERR "%s:sock_create failed\n",
				       __FUNCTION__);
				return retval;
			}
			newtp=tcp_sk(sock->sk);

			/*Binding the new socket to the local ulid
			  (except if we use the MPTCP default PM, in which
			  case we bind the new socket, directly to its
			  corresponding locators)*/
			switch(mpcb->sa_family) {
			case AF_INET:
				memset(&loculid,0,sizeof(loculid));
				loculid_in.sin_family=mpcb->sa_family;
				
				memcpy(&remulid_in,&loculid_in,
				       sizeof(remulid_in));
				
				loculid_in.sin_port=mpcb->local_port;
				remulid_in.sin_port=mpcb->remote_port;
#ifdef CONFIG_MTCP_PM
				/*If the MPTCP PM is used, we use the locators 
				  as subsock ids, while with other PMs, the
				  ULIDs are those of the master subsock
				  for all subsocks.*/
				memcpy(&loculid_in.sin_addr,
				       mtcp_get_loc_addr(mpcb,newpi),
				       sizeof(struct in_addr));
				memcpy(&remulid_in.sin_addr,
				       mtcp_get_rem_addr(mpcb,newpi),
				       sizeof(struct in_addr));
#else
				memcpy(&loculid_in.sin_addr,
				       (struct in_addr*)&mpcb->local_ulid.a4,
				       sizeof(struct in_addr));
				memcpy(&remulid_in.sin_addr,
				       (struct in_addr*)&mpcb->remote_ulid.a4,
				       sizeof(struct in_addr));
#endif
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
			newtp->path_index=newpi;
			newtp->mpc=1;
			
			mtcp_add_sock(mpcb,newtp);
						
			/*Redefine the sk_data_ready function*/
			((struct sock*)newtp)->sk_data_ready=mtcp_def_readable;
						
			retval = sock->ops->bind(sock, loculid, ulid_size);
			if (retval<0) goto fail_bind;
			
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

/*Defined in net/core/sock.c*/
void mtcp_inherit_sk(struct sock *sk,struct sock *newsk);

struct multipath_pcb* mtcp_alloc_mpcb(struct sock *master_sk)
{
	struct multipath_pcb * mpcb = kmalloc(
		sizeof(struct multipath_pcb),GFP_KERNEL);
	struct tcp_sock *mpcb_tp = &mpcb->tp;
	struct sock *mpcb_sk = (struct sock *) mpcb_tp;
	struct inet_connection_sock *mpcb_icsk = inet_csk(mpcb_sk);
	
	memset(mpcb,0,sizeof(struct multipath_pcb));
	
	/*mpcb_sk inherits master sk*/
	mtcp_inherit_sk(master_sk,mpcb_sk);

	mpcb_tp->mpcb=mpcb;
	mpcb_tp->mpc=1;
	
	skb_queue_head_init(&mpcb_tp->out_of_order_queue);
	
	mpcb_sk->sk_rcvbuf = sysctl_rmem_default;
	mpcb_sk->sk_sndbuf = sysctl_wmem_default;
	
	mpcb_sk->sk_state = TCPF_CLOSE;
	
	mpcb->master_sk=master_sk;

	kref_init(&mpcb->kref);

	spin_lock_init(&mpcb->lock);
	mutex_init(&mpcb->mutex);
	INIT_LIST_HEAD(&mpcb->dsack_list);
	mpcb->nb.notifier_call=netevent_callback;
	register_netevent_notifier(&mpcb->nb);

	mpcb_tp->window_clamp=tcp_sk(master_sk)->window_clamp;
	mpcb_tp->rcv_ssthresh=tcp_sk(master_sk)->rcv_ssthresh;
	
#ifdef CONFIG_MTCP_PM
	/*Init the accept_queue structure, we support a queue of 4 pending
	  connections, it does not need to be huge, since we only store 
	  here pending subflow creations*/
	reqsk_queue_alloc(&mpcb_icsk->icsk_accept_queue,32);
	/*Pi 1 is reserved for the master subflow*/
	mpcb->next_unused_pi=2;
	/*For the server side, the local token has already been allocated*/
	if (!tcp_sk(master_sk)->mtcp_loc_token)
		tcp_sk(master_sk)->mtcp_loc_token=mtcp_new_token();

	/*Adding the mpcb in the token hashtable*/
	mtcp_hash_insert(mpcb,loc_token(mpcb));
#endif
		
	return mpcb;
}

static void mpcb_release(struct kref* kref)
{
	struct multipath_pcb *mpcb;
	mpcb=container_of(kref,struct multipath_pcb,kref);
	mutex_destroy(&mpcb->mutex);
#ifdef CONFIG_MTCP_PM
	mtcp_pm_release(mpcb);
#endif
	printk(KERN_ERR 
	       "will free mpcb\n");
#ifdef CONFIG_SECURITY_NETWORK
	security_sk_free((struct sock *)mpcb);
#endif
	kfree(mpcb);
}

void mpcb_get(struct multipath_pcb *mpcb)
{
	kref_get(&mpcb->kref);
}
void mpcb_put(struct multipath_pcb *mpcb)
{
	kref_put(&mpcb->kref,mpcb_release);
}

/*Warning: can only be called in user context
  (due to unregister_netevent_notifier)*/
void mtcp_destroy_mpcb(struct multipath_pcb *mpcb)
{
	struct sock *mpcb_sk=(struct sock *) mpcb;
	struct tcp_sock *mpcb_tp=tcp_sk(mpcb_sk);
	printk(KERN_ERR "Destroying mpcb\n");
#ifdef CONFIG_MTCP_PM
	/*Detach the mpcb from the token hashtable*/
	mtcp_hash_remove(mpcb);
#endif
	/*Stop listening to PM events*/
	unregister_netevent_notifier(&mpcb->nb);
	/*The meta-queues must all be empty when arriving here, because
	  we have removed all subsocks. Removing an skb here would lead
	  to a general protection fault. 
	  The rule to avoid this is that when any subsock is destroyed
	  (whether when destroying everything, or when just stopping
	  one subflow, one MUST ensure that no skb belonging to that
	  subsock is still living in any of the meta-queues. 
	  Currently we only suppress meta-flows when closing the connection,
	  so purging the queues at the right place is sufficient. When we want
	  to implement subsock suppression during communication, we should
	  devise some mechanism to enforce that skb suppression from the meta-
	  queues.
	*/
	BUG_ON(!skb_queue_empty(&mpcb_sk->sk_receive_queue));
	BUG_ON(!skb_queue_empty(&mpcb_tp->out_of_order_queue));
	kref_put(&mpcb->kref,mpcb_release);
}

/*MUST be called in user context
 */
void mtcp_add_sock(struct multipath_pcb *mpcb,struct tcp_sock *tp)
{
	struct sock *mpcb_sk=(struct sock*)mpcb;
	/*Adding new node to head of connection_list*/
	mutex_lock(&mpcb->mutex); /*To protect against concurrency with
				    mtcp_recvmsg and mtcp_sendmsg*/
	local_bh_disable(); /*To protect against concurrency with
			      mtcp_del_sock*/
	tp->mpcb = mpcb;
	tp->next=mpcb->connection_list;
	mpcb->connection_list=tp;

#ifdef CONFIG_MTCP_PM
	/*Same token for all subflows*/
	tp->rx_opt.mtcp_rem_token=
		tcp_sk(mpcb->master_sk)->rx_opt.mtcp_rem_token;
	tp->pending=0;
#endif
	
	mpcb->cnt_subflows++;
	mtcp_update_window_clamp(mpcb);
	atomic_add(atomic_read(&((struct sock *)tp)->sk_rmem_alloc),
		   &mpcb_sk->sk_rmem_alloc);
	
	/*The socket is already established if it was in the
	  accept queue of the mpcb*/
	if (((struct sock*)tp)->sk_state==TCP_ESTABLISHED) {
		mpcb->cnt_established++;
		mpcb->sndbuf_grown=1;
	}

	kref_get(&mpcb->kref);	
	local_bh_enable();
	mutex_unlock(&mpcb->mutex);

	PDEBUG("Added subsocket with pi %d, cnt_subflows now %d\n",
	       tp->path_index,mpcb->cnt_subflows);
}

void mtcp_del_sock(struct multipath_pcb *mpcb, struct tcp_sock *tp)
{
	struct tcp_sock *tp_prev;
	int done=0;

	if (!in_interrupt()) {
		/*Then we must take the mutex to avoid racing
		  with mtcp_add_sock*/
		mutex_lock(&mpcb->mutex);
	}

	tp_prev=mpcb->connection_list;	

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
	if (!in_interrupt())
		mutex_unlock(&mpcb->mutex);
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
#ifdef CONFIG_MTCP_PM
	/*Searching for suitable local addresses,
	  except is the socket is loopback, in which case we simply
	  don't do multipath*/
	if (!ipv4_is_loopback(inet_sk(sk)->daddr) &&
	    !ipv4_is_loopback(inet_sk(sk)->daddr))
		mtcp_set_addresses(mpcb);
	/*If this added new local addresses, build new paths with them*/
	if (mpcb->num_addr4 || mpcb->num_addr6) mtcp_update_patharray(mpcb);
#endif	
}

/*copied from tcp_output.c*/
static inline unsigned int tcp_cwnd_test(struct tcp_sock *tp,
					 struct sk_buff *skb)
{
	u32 in_flight, cwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return (cwnd - in_flight);

	return 0;
}

int mtcp_is_available(struct sock *sk, struct sk_buff *skb)
{
	/*We consider a subflow to be available if it has remaining space in 
	  its */	
	if (sk->sk_state!=TCP_ESTABLISHED || tcp_sk(sk)->pf) return 0;
	if (tcp_cwnd_test(tcp_sk(sk),skb)) return 1;
	return 0;
}

/*This is the scheduler. This function decides on which flow to send
 *  a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the estimation of how much time will be
 * needed to send the segment. If all paths have full send buffers, we
 * simply block. The flow able to send the segment the soonest get it. 
 */
struct sock* get_available_subflow(struct multipath_pcb *mpcb, 
				   struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sock *bestsk=NULL;
	unsigned int min_fill_ratio=0xffffffff;
	int bh=in_interrupt(); 

	if (!mpcb) return NULL;
	
	/*if there is only one subflow, bypass the scheduling function*/
	if (!bh) {
		mutex_lock(&mpcb->mutex);
		mtcp_for_each_sk(mpcb,sk,tp) lock_sock(sk);
	}

	if (mpcb->cnt_subflows==1) {
		bestsk=(struct sock *)mpcb->connection_list;
		goto out;
	}

	/*First, find the best subflow*/
	mtcp_for_each_sk(mpcb,sk,tp) {
		unsigned int fill_ratio;
		/*If in bh, we cannot select a non-available subflow,
		  since this would make us block, and we cannot block in bh*/
		if (bh && !mtcp_is_available(sk,skb)) continue;
		if (sk->sk_state!=TCP_ESTABLISHED || tp->pf) continue;
		
		/*If there is no bw estimation available currently, 
		  we only give it data when it has available space in the
		  cwnd (see above)*/
		if (!tp->cur_bw_est) {
			/*If a subflow is available, send immediately*/
			if (tcp_packets_in_flight(tp)<tp->snd_cwnd) {
				bestsk=sk;
				break;
			}
			else continue;
		}
		
		fill_ratio=sk->sk_wmem_queued/tp->cur_bw_est;
		
		if (fill_ratio<min_fill_ratio) {
			min_fill_ratio=fill_ratio;
			bestsk=sk;
		}
	}
	
out:
	/*Now, even the best subflow may be uneligible for sending.
	  In that case, we must return NULL (only in user ctx, though) */
	if (!bh && bestsk && !mtcp_is_available(bestsk,skb))
		bestsk=NULL;

	/*The following can happen only when the result of a reinjection is
	  filling all buffers. Since the original distribution of segments
	  can go higher than sndbuf by one MSS max., the redistribution can 
	  in the worse case go higher by MSS*nb_subflows max. So it is not
	  critical here to choose the best subflow*/
	if (bh && !bestsk)
		bestsk=(struct sock *)mpcb->connection_list;
	
	if (!bh) {
		mtcp_for_each_sk(mpcb,sk,tp) release_sock(sk);
		mutex_unlock(&mpcb->mutex);		
	}

	return bestsk;
}

int mtcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *master_sk = sock->sk;
	struct iovec *iov;
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tcp_sk(master_sk));
	struct sock *mpcb_sk = (struct sock *) mpcb;
	size_t iovlen,copied,msg_size;
	int i;
	int nberr;		

	if (!tcp_sk(master_sk)->mpc)
		return subtcp_sendmsg(iocb,master_sk, msg, size);
	
	PDEBUG("Entering %s\n",__FUNCTION__);

	BUG_ON(!mpcb);

	verif_wqueues(mpcb);

#ifdef CONFIG_MTCP_PM
	/*Any new subsock we can use ?*/
	BUG_ON(in_atomic());
	mtcp_check_new_subflow(mpcb);
	BUG_ON(in_atomic());
#endif
	
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

		ret=subtcp_sendmsg(NULL,mpcb_sk,msg, copied);
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
				printk(KERN_ERR "%s: returning error "
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
	       (int) copied,mpcb_tp->write_seq);
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
static int __mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk,
			    long *timeo)
{
	int rc; struct sock *sk; struct tcp_sock *tp;
	DEFINE_WAIT(wait);

	prepare_to_wait(master_sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	mtcp_for_each_sk(mpcb,sk,tp) {
		set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
		tp->wait_data_bit_set=1;
	}
	rc = mtcp_wait_event_any_sk(mpcb, sk, tp, timeo, 
				    (!skb_queue_empty(&sk->sk_receive_queue) ||
				     !skb_queue_empty(&tp->ucopy.prequeue)));

	mtcp_for_each_sk(mpcb,sk,tp)
		if (tp->wait_data_bit_set) {
			clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
			tp->wait_data_bit_set=0;
		}
	finish_wait(master_sk->sk_sleep, &wait);
	return rc;
}

/**
 * mtcp_rcv_check_subflows, check for arrival of new subflows
 * while waiting for arriving data
 * WARNING: that function assumes that the mutex lock is held.
 * @return: the number of newly added subflows
 */
static int mtcp_rcv_check_subflows(struct multipath_pcb *mpcb, int flags)
{
	int cnt_subflows,new_subflows=0;
	struct tcp_sock *tp;	
	cnt_subflows=mpcb->cnt_subflows;
#ifdef CONFIG_MTCP_PM
	/*TODO: do something similar for other path managers*/
	mutex_unlock(&mpcb->mutex);
	new_subflows=mtcp_check_new_subflow(mpcb);
	mutex_lock(&mpcb->mutex);
#endif
	/*We may have received data on a newly created
	  subsocket, check if the list has grown*/
	if (cnt_subflows!=mpcb->cnt_subflows) {
		/*We must ensure  that for each new tp, 
		  the seq pointer is correctly set. In 
		  particular we'll get a segfault if
		  the pointer is NULL*/
		mtcp_for_each_newtp(mpcb,tp,
				    cnt_subflows) {
			if (flags & MSG_PEEK) {
				tp->peek_seq=tp->copied_seq;
				tp->seq=&tp->peek_seq;
			}
			else 
				tp->seq=&tp->copied_seq;
			
			BUG_ON(sock_owned_by_user(
				       (struct sock*)tp));
			/*Here, all subsocks are locked
			  so we must also lock
			  new subsocks*/
			lock_sock((struct sock*)tp);
		}
	}
	return new_subflows;
}

int mtcp_wait_data(struct multipath_pcb *mpcb, struct sock *master_sk,
		   long *timeo, int flags) {
	int rc;
	int new_subflows=0;

	new_subflows=mtcp_rcv_check_subflows(mpcb, flags);		
	/*If no data is received but a new subflow appears,
	  we attach the new subflow and wait again for data.*/
	do {
		rc=__mtcp_wait_data(mpcb,master_sk,timeo);
		new_subflows=mtcp_rcv_check_subflows(mpcb, flags);
	} while(!rc && new_subflows); /*if a new subflow appeared, and no data,
					loop to check if data appeared in the
					newly arrived subsock.*/
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
	int enqueue=0; /*1 if we must enqueue from ofo to rcv queue due
			 to insufficient space in app buffer*/
	struct tcp_sock *tp;
	struct sock *mpcb_sk=(struct sock *) mpcb;
	struct tcp_sock *mpcb_tp=tcp_sk(mpcb_sk);
	
	while ((skb = skb_peek(&mpcb_tp->out_of_order_queue)) != NULL) {
		tp=tcp_sk(skb->sk);
		if (after(TCP_SKB_CB(skb)->data_seq, *data_seq))
			break;
				
		if (!after(TCP_SKB_CB(skb)->end_data_seq, *data_seq)) {
			printk(KERN_ERR "ofo packet was already received."
			       "skb->end_data_seq:%x,exp. data_seq:%x\n",
			       TCP_SKB_CB(skb)->end_data_seq,*data_seq);
			/*Should not happen in the current design*/
			printk(KERN_ERR "init data_seq:%x,*copied:%x\n",
			       skb->data_seq,*copied);
			console_loglevel=8;
			
			BUG();
			__skb_unlink(skb, &mpcb_tp->out_of_order_queue);
			__kfree_skb(skb);
			continue;
		}
		PDEBUG("ofo delivery : "
		       "nxt_data_seq %X data_seq %X - %X, enqueue is %d\n",
		       *data_seq, TCP_SKB_CB(skb)->data_seq,
		       TCP_SKB_CB(skb)->end_data_seq,enqueue);
		
		__skb_unlink(skb, &mpcb_tp->out_of_order_queue);
		
		/*if enqueue is 1, than the app buffer is full and we must
		  enqueue the buff into the receive queue*/
		if (enqueue) {
			__skb_queue_tail(&mpcb_sk->sk_receive_queue, skb);
			rcv_nxt+=skb->len;
			continue;
		}
		
		/*The skb can be read by the app*/
		data_offset= *data_seq - TCP_SKB_CB(skb)->data_seq;

		BUG_ON(data_offset != 0);

		if (tcp_hdr(skb)->fin) {
			used=1;
		}
		else {
			used = skb->len - data_offset;
			if (*len < used)
				used = *len;
				
			err=skb_copy_datagram_iovec(skb, data_offset,
						    msg->msg_iov, used);
			BUG_ON(err);
		}

		mtcp_check_seqnums(mpcb,1);

		*data_seq+=used;
		if (!tcp_hdr(skb)->fin) {
			*copied+=used;
			*len-=used;
		}
		mpcb->ofo_bytes-=used;

		mtcp_check_seqnums(mpcb,0);
		
		/*We can free the skb only if it has been completely eaten
		  Else we queue it in the mpcb receive queue, for reading by
		  the app on next call to tcp_recvmsg().*/
 		if (*data_seq==TCP_SKB_CB(skb)->end_data_seq)
			__kfree_skb(skb);
		else {
			__skb_queue_tail(&mpcb_sk->sk_receive_queue, skb);
			BUG_ON(*len!=0);
			BUG_ON(tcp_hdr(skb)->fin);
			/*Now we must also enqueue all subsequent contiguous
			  skbs*/
			enqueue=1;
			rcv_nxt=TCP_SKB_CB(skb)->end_data_seq;
			data_seq=&rcv_nxt;
		}
	}
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
	struct sock *mpcb_sk=(struct sock*)mpcb;
	int err;
	if (skb_queue_empty(&mpcb_sk->sk_receive_queue)) 
		return 0;

	do {
		u32 data_offset;
		unsigned long used;
		skb = skb_peek(&mpcb_sk->sk_receive_queue);

		if (!skb) break;

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
		data_offset = *data_seq - TCP_SKB_CB(skb)->data_seq;
		BUG_ON(data_offset >= skb->len && !tcp_hdr(skb)->fin);

		if (!tcp_hdr(skb)->fin && skb->len != 
		    TCP_SKB_CB(skb)->end_data_seq - TCP_SKB_CB(skb)->data_seq) {
			printk(KERN_ERR "skb->len:%d, should be %d\n",
			       skb->len,
			       TCP_SKB_CB(skb)->end_data_seq - 
			       TCP_SKB_CB(skb)->data_seq);
			console_loglevel=8;
			BUG();
		}

		if (tcp_hdr(skb)->fin) {
			used=1;
		}
		else {
			used = skb->len - data_offset;
			if (*len < used)
				used = *len;
				
			err=skb_copy_datagram_iovec(skb, data_offset,
						    msg->msg_iov, used);
			BUG_ON(err);
		}
		
		mtcp_check_seqnums(mpcb,1);

		*data_seq+=used;
		if (!tcp_hdr(skb)->fin) {
			*copied+=used;
			*len-=used;
		}
		
		if (!(flags & MSG_PEEK)) 
			mpcb->ofo_bytes-=used;
		
		mtcp_check_seqnums(mpcb,0);
		
 		if (*data_seq==TCP_SKB_CB(skb)->end_data_seq && 
		    !(flags & MSG_PEEK))
			sk_eat_skb(mpcb_sk, skb, 0);
		else if (!(flags & MSG_PEEK) && *len!=0) {
				printk(KERN_ERR 
				       "%s bug: copied %X "
				       "dataseq %X, *len %d\n", __FUNCTION__, 
				       *data_seq, 
				       TCP_SKB_CB(skb)->data_seq, (int)*len);
				printk(KERN_ERR "init data_seq:%x,used:%d\n",
				       skb->data_seq,(int)used);
				BUG();
		}				
	} while (*len>0);
	/*Check if this fills a gap in the ofo queue*/
	if (!skb_queue_empty(&mpcb->tp.out_of_order_queue))
		mtcp_ofo_queue(mpcb,msg,len,data_seq,copied,flags);
	return 0;
}

#ifdef MTCP_DEBUG_SEQNUMS

void mtcp_check_seqnums(struct multipath_pcb *mpcb, int before)
{
	int subsock_bytes=0;
	struct sock *sk;
	struct tcp_sock *tp;
	struct sock *mpcb_sk=(struct sock*)mpcb;
	struct tcp_sock *mpcb_tp=tcp_sk(mpcb_sk);
			     

	mtcp_for_each_sk(mpcb,sk,tp)
		subsock_bytes+=tp->bytes_eaten;
	/*The number of bytes received by the metasocket must always
	  be equal to the sum of the number of bytes received by the
	  subsockets, minus the number of bytes waiting in the meta-ofo
	  and meta-receive queue*/
	if (unlikely(subsock_bytes!=mpcb->copied_seq+mpcb->ofo_bytes)) {
		struct sk_buff *first_ofo=skb_peek(
			&mpcb_tp->out_of_order_queue);
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
		       skb_queue_len(&mpcb_sk->receive_queue),
		       skb_queue_len(&mpcb_tp->out_of_order_queue),
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
#endif

int mtcp_queue_skb(struct sock *sk,struct sk_buff *skb, u32 offset,
		   unsigned long *used, struct msghdr *msg, size_t *len,
		   u32 *data_seq, int *copied, int flags)
{
	struct tcp_sock *tp=tcp_sk(sk);
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tp);
	u32 data_offset;
	int err;	
	int moved=0;
	int fin=tcp_hdr(skb)->fin;
	struct sock *mpcb_sk=(struct sock *) mpcb;
	struct tcp_sock *mpcb_tp=tcp_sk(mpcb_sk);

	/*Verify that the mapping info has been read*/
	if(TCP_SKB_CB(skb)->data_len) {
		mtcp_get_dataseq_mapping(tp,skb);
	}
	
	/*Is this a duplicate segment ?*/
	if (after(*data_seq,TCP_SKB_CB(skb)->end_data_seq)) {
		/*Duplicate segment. We can arrive here only if a segment 
		  has been retransmitted by the sender on another subflow.
		  Retransmissions on the same subflow are handled at the
		  subflow level.*/
		BUG_ON(fin);

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
		
		*tp->seq +=skb->len+fin;
		tp->copied+=skb->len+fin;		
		tp->bytes_eaten+=skb->len+fin;
		mpcb->ofo_bytes+=skb->len+fin;
		mtcp_check_seqnums(mpcb,0);
		
		if (!skb_peek(&mpcb_tp->out_of_order_queue)) {
			/* Initial out of order segment */
			PDEBUG("First meta-ofo segment\n");
			__skb_queue_head(&mpcb_tp->out_of_order_queue, skb);
			return MTCP_QUEUED;
		}
		else {
			struct sk_buff *skb1 = mpcb_tp->out_of_order_queue.prev;
			/* Find place to insert this segment. */
			do {
				if (!after(TCP_SKB_CB(skb1)->data_seq, 
					   TCP_SKB_CB(skb)->data_seq))
					break;
			} while ((skb1 = skb1->prev) !=
				 (struct sk_buff *)
				 &mpcb_tp->out_of_order_queue);

			/* Do skb overlap to previous one? */
			if (skb1 != 
			    (struct sk_buff *)&mpcb_tp->out_of_order_queue &&
			    before(TCP_SKB_CB(skb)->data_seq, 
				   TCP_SKB_CB(skb1)->end_data_seq)) {
				if (!after(TCP_SKB_CB(skb)->end_data_seq, 
					   TCP_SKB_CB(skb1)->end_data_seq)) {
					/* All the bits are present. Drop. */
					/* We do not read the skb, since it was
					   already received on
					   another subflow */
					BUG_ON(fin);
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
					       "skb1->end_data_seq:%x,"
					       "skb->seq:%x,"
					       "skb1->seq:%x""\n",
					       TCP_SKB_CB(skb)->data_seq,
					       TCP_SKB_CB(skb)->end_data_seq,
					       TCP_SKB_CB(skb1)->data_seq,
					       TCP_SKB_CB(skb1)->end_data_seq,
					       TCP_SKB_CB(skb)->seq,
					       TCP_SKB_CB(skb1)->seq);
					BUG();
					skb1 = skb1->prev;
				}
			}
			__skb_insert(skb, skb1, skb1->next, 
				     &mpcb_tp->out_of_order_queue);

			if (fin) return MTCP_QUEUED;

			/* And clean segments covered by new one as whole. */
			while ((skb1 = skb->next) !=
			       (struct sk_buff *)&mpcb_tp->out_of_order_queue &&
			       after(TCP_SKB_CB(skb)->end_data_seq, 
				     TCP_SKB_CB(skb1)->data_seq)) {
				if (!before(TCP_SKB_CB(skb)->end_data_seq, 
					    TCP_SKB_CB(skb1)->end_data_seq)) {
					__skb_unlink(skb1, 
						     &mpcb_tp->
						     out_of_order_queue);
					__kfree_skb(skb1);
				}
				else break;
			}
			return MTCP_QUEUED;
		}
	}

	else {
		data_offset= *data_seq - TCP_SKB_CB(skb)->data_seq;
		/*The skb can be read by the app*/
		if (fin) {
			BUG_ON(data_offset); /*data_offset should be 0 here*/
			mtcp_check_seqnums(mpcb,1);
			(*data_seq)++;
			(*tp->seq)++;
			tp->copied++;
			if (!(flags & MSG_PEEK)) tp->bytes_eaten++;
			mtcp_check_seqnums(mpcb,0);
			/*Check if this fills a gap in the ofo queue*/
			if (!skb_queue_empty(&mpcb_tp->out_of_order_queue))
				mtcp_ofo_queue(mpcb,msg,len,data_seq,copied,flags);
			return MTCP_EATEN;
		}

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

		if (*len < *used) {
			/*Store the segment in the mpcb queue, so 
			  that it is known that further data is ready
			  for the app*/
			__skb_unlink(skb, &sk->sk_receive_queue);
			/*Since the skb is removed from the receive queue
			  we must advance the seq num in the corresponding
			  tp (by skb->len-offset, which is *used))*/
			mtcp_check_seqnums(mpcb,1);
			*tp->seq +=*used;
			tp->copied+=*used;
			tp->bytes_eaten+=*used;
			mpcb->ofo_bytes+=*used;
			mtcp_check_seqnums(mpcb,0);	
			BUG_ON(!skb_queue_empty(&mpcb_sk->sk_receive_queue));
			__skb_queue_tail(&mpcb_sk->sk_receive_queue, skb);
			/*Now, redefine *used to what we can already eat now*/
			*used = *len;
			moved=1;
		}

		/*Happens if the app has been fed already, but we were
		  searching one more byte of pending data. Reaching
		  this point means that this byte has been found.
		  We can leave*/
		if (!*len) return MTCP_QUEUED;		
		
		err=skb_copy_datagram_iovec(skb, data_offset,
					    msg->msg_iov, *used);
		BUG_ON(err);
		if (err) return err;
		
		mtcp_check_seqnums(mpcb,1);
		*copied+=*used;
		*data_seq+=*used;
		*len-=*used;			
		if (moved)
			mpcb->ofo_bytes-=*used;
		else {
			*tp->seq += *used;
			tp->copied+=*used;
			if (!(flags & MSG_PEEK)) tp->bytes_eaten+=*used;
		}
		mtcp_check_seqnums(mpcb,0);

		/*Update subflow counters if data_offset differs from offset*/
		if (data_offset!=offset) {
			/*If data has been eaten by the subflow, 
			  it has also been eaten by the meta-flow.
			  if this does not hold, we have a bug*/
			if(data_offset<offset) {
				printk(KERN_ERR "data_offset<offset:"
				       "data_offset:%d,offset:%d\n",
				       data_offset,offset);
				BUG();
			}
			/*Otherwise, just advance the subflow counters*/
			*used+=data_offset-offset;
			*tp->seq += data_offset-offset;
			tp->copied += data_offset-offset;						
		}

		
		/*Check if this fills a gap in the ofo queue*/
		if (!skb_queue_empty(&mpcb_tp->out_of_order_queue))
			mtcp_ofo_queue(mpcb,msg,len,data_seq,copied, flags);
		if (moved) return MTCP_QUEUED;
		else return MTCP_EATEN;
	}
}

/**
 * specific version of skb_entail (tcp.c),that allows appending to any
 * subflow.
 * Here, we do not set the data seq, since it remains the same. However, 
 * we do change the subflow seqnum.
 *
 * Note that we make the assumption that, within the local system, every
 * segment has tcb->sub_seq==tcb->seq, that is, the dataseq is not shifted
 * compared to the subflow seqnum. Put another way, the dataseq referenced
 * is actually the number of the first data byte in the segment.
 */
void mtcp_skb_entail(struct sock *sk, struct sk_buff *skb)
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

	/*Take into account seg len*/
	tp->write_seq += skb->len;
	tcb->end_seq += skb->len;
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
	
	orig_skb->path_mask|=PI_TO_FLAG(tp->path_index);

	skb=skb_copy(orig_skb,GFP_ATOMIC);
	skb->sk=sk;

	th=tcp_hdr(skb);
	
	BUG_ON(!skb);
	BUG_ON(skb->path_mask!=orig_skb->path_mask);
	
	mtcp_skb_entail(sk, skb);
}

void mtcp_reinject_data(struct sock *orig_sk, struct sock *retrans_sk)
{
	struct sk_buff *skb_it;
	struct tcp_sock *orig_tp = tcp_sk(orig_sk);
	struct tcp_sock *retrans_tp = tcp_sk(retrans_sk);
	struct multipath_pcb *mpcb=orig_tp->mpcb;
	int mss_now;	
	
	verif_wqueues(mpcb);

	bh_lock_sock(retrans_sk);

	tcp_for_write_queue(skb_it,orig_sk) {
		if (skb_it==tcp_send_head(orig_sk))
			break;
		skb_it->path_mask|=PI_TO_FLAG(orig_tp->path_index);
		__mtcp_reinject_data(skb_it,retrans_sk);
	}

	mss_now = tcp_current_mss(retrans_sk, 0);
	tcp_push(retrans_sk, 0, mss_now, retrans_tp->nonagle);

	bh_unlock_sock(retrans_sk);

	orig_tp->pf=1;

	verif_wqueues(mpcb);
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
 *   ii) it its end_data_seq is older then mpcb->copied_seq, it is a 
 *       reinjected segment arrived late. We return 2, to indicate to the 
 *       caller that the segment can be eaten by the subflow immediately.
 *   iii) if it is not in meta-order (keep in mind that the precondition 
 *        requires that it is in subflow order): we return 0
 * - If the skb is faulty (does not contain a dataseq option, and seqnum
 *   not contained in currently stored mapping), we return -1
 * - If the tp is a pending tp, and the mpcb is destroyed (not anymore
 *   in the hashtable), we return -1.
 */
int mtcp_get_dataseq_mapping(struct tcp_sock *tp, struct sk_buff *skb)
{
	int changed=0;
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tp);
	int ans;

	BUG_ON(!mpcb && !tp->pending);
	/*We must be able to find the mapping even for a pending
	  subsock, because that pending subsock can trigger the wake up of
	  the application. (it is holds the next DSN)*/
	if (tp->pending) {
		mpcb=mtcp_hash_find(tp->mtcp_loc_token);
		if(!mpcb) return -1;
	}

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
		ans=1;
		goto out;
	}
	/*OK, the segment is inside the mapping, we can
	  derive the dataseq. Note that we maintain 
	  TCP_SKB_CB(skb)->data_len to zero, so as not to mix
	  received mappings and derived dataseqs.*/
	TCP_SKB_CB(skb)->data_seq=tp->map_data_seq+
		(TCP_SKB_CB(skb)->seq-tp->map_subseq);
	TCP_SKB_CB(skb)->end_data_seq=
		TCP_SKB_CB(skb)->data_seq+skb->len+tcp_hdr(skb)->fin;
	TCP_SKB_CB(skb)->data_len=0; /*To indicate that there is not anymore
				       general mapping information in that 
				       segment (the mapping info is now 
				       consumed)*/
		
	/*Check now if the segment is in meta-order, it is considered
	  in meta-order if the next expected DSN is contained in the
	  segment*/
	
	if (!before(mpcb->tp.copied_seq,TCP_SKB_CB(skb)->data_seq) &&
	    before(mpcb->tp.copied_seq,TCP_SKB_CB(skb)->end_data_seq))
		ans=1;
	else if (!before(mpcb->tp.copied_seq,TCP_SKB_CB(skb)->end_data_seq))
		ans=2;
	else ans=0;
	
out:
	if (tp->pending)
		mpcb_put(mpcb);
	return ans;
}

/* Obtain a reference to a local port for the given sock,
 * snum MUST have a valid port number, since it must be a copy 
 * of the snum from a master TCP socket.
 */
int mtcpsub_get_port(struct sock *sk, unsigned short snum)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_bind_hashbucket *head;
	struct hlist_node *node;
	struct inet_bind_bucket *tb;
	int ret;
	struct net *net = sock_net(sk);

	local_bh_disable();
	if (!snum) {
		ret=-1;
		goto fail; /*snum is required in MTCPSUB, since it must be
			     the copy of the originating socket*/
	} else {
		head = &hashinfo->bhash[inet_bhashfn(net, snum,
				hashinfo->bhash_size)];
		spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, node, &head->chain)
			if (tb->ib_net == net && tb->port == snum)
				goto success;
	}
	tb = NULL;
	ret = 1;
	goto fail_unlock;
success:
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, snum);
	BUG_ON(inet_csk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}


void mtcp_update_dsn_ack(struct multipath_pcb *mpcb, u32 start, u32 end) {
	struct dsn_sack *dsack, *new_block, *todel, *tmp;
	int inserted=0;
	struct tcp_sock *mpcb_tp=(struct tcp_sock *)mpcb;
	
	BUG_ON(!after(end,start));

	spin_lock(&mpcb->lock);
	/*Normal case*/
	if (!after(start,mpcb_tp->snd_una)) {
		/*This block has already been acked*/
		if (!after(end,mpcb_tp->snd_una))
			goto out;
		mpcb_tp->snd_una=end;
		/*Update the sack block list if needed*/
		list_for_each_entry_safe(dsack,tmp,&mpcb->dsack_list,list) {
			if (!before(mpcb_tp->snd_una,dsack->end)) {
				list_del(&dsack->list);
				kfree(dsack);
				continue;
			}
			else if (!before(mpcb_tp->snd_una,dsack->start)) {
				mpcb_tp->snd_una=dsack->end;
				list_del(&dsack->list);
				kfree(dsack);
			}
			break;
		}
		goto out;
	}
	/*there is a hole, use the dsack list*/
	list_for_each_entry(dsack,&mpcb->dsack_list,list) {
		if (after(start,dsack->end)) 
			continue;
		if (inserted && !dsack_is_first(dsack,mpcb) && 
		    !before(dsack_prev(dsack)->end,dsack->start)) {
			/*A previous update has extended the end of block*/
			dsack->start=dsack_prev(dsack)->start;
			if (after(dsack_prev(dsack)->end, dsack->end))
				dsack->end=dsack_prev(dsack)->end;
			todel=dsack_prev(dsack);
			/*It is safe to delete here, because we are deleting the 
			  previous node, not the current one.*/
			list_del(&todel->list);
			kfree(todel);		       
			/*Need to continue to see if this new extension covers next segment
			  as well.*/
			continue;
		}
		if (before(end,dsack->start)) {
			if (dsack_is_first(dsack,mpcb) || 
			    after(start,dsack_prev(dsack)->end)) {
				new_block=kmalloc(sizeof(struct dsn_sack),GFP_ATOMIC);
				new_block->start=start;
				new_block->end=end;
				__list_add(&new_block->list,&dsack_prev(dsack)->list,&dsack->list);
				goto out;
			}
			if (after(end,dsack_prev(dsack)->end))
				dsack_prev(dsack)->end=end;
			goto out;
		}
		if (before(start,dsack->start)) {
			/*This cannot create an overlap with previous block, because if
			  this would have been the case, we would have extended instead 
			  the end of the previous block, then deleted one block at the beginning
			  of this iteration*/
			dsack->start=start;
		}
		
		if (after(end,dsack->end)) {
			dsack->end=end;
			/*Maybe this makes the current block overlap with the next one*/
			inserted=1;
			continue;
		}

		goto out;
	}
	/*The acked block matches nothing, append it to the sack list*/
	if (!inserted) {
		new_block=kmalloc(sizeof(struct dsn_sack),GFP_ATOMIC);
		new_block->start=start;
		new_block->end=end;
		list_add_tail(&new_block->list,&mpcb->dsack_list);
	}
out:
	spin_unlock(&mpcb->lock);
}


/*At the moment we apply a simple addition algorithm.
  We will complexify later*/
void mtcp_update_window_clamp(struct multipath_pcb *mpcb)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct tcp_sock *mpcb_tp = (struct tcp_sock *) mpcb;
	struct sock *mpcb_sk = (struct sock *)mpcb;
	u32 new_clamp=0;
	u32 new_rcv_ssthresh=0;
	u32 new_rcvbuf=0;

	/*Can happen if called from non mpcb sock.*/
	if (!mpcb) return;

	mtcp_for_each_sk(mpcb,sk,tp) {
		new_clamp += tp->window_clamp;
		new_rcv_ssthresh += tp->rcv_ssthresh;
		new_rcvbuf += sk->sk_rcvbuf;
	}
	mpcb_tp->window_clamp = new_clamp;
	mpcb_tp->rcv_ssthresh = new_rcv_ssthresh;
	mpcb_sk->sk_rcvbuf = new_rcvbuf;
}

extern void tcp_check_space(struct sock *sk);

void mtcp_push_frames(struct sock *sk)
{
	struct tcp_sock *tp=tcp_sk(sk);
	
	tp->push_frames=0;
	lock_sock(sk);
	tcp_push_pending_frames(sk);
	tcp_check_space(sk);
	/*Note release sock can call us again, which is correct because 
	  it would mean that we received new acks while we were pushing.*/
	release_sock(sk);
}

#ifdef DEBUG_WQUEUES
void verif_wqueues(struct multipath_pcb *mpcb) 
{
	struct sock *sk;
	struct tcp_sock *tp;
	struct sk_buff *skb;

	local_bh_disable();
	mtcp_for_each_sk(mpcb,sk,tp) {
		int sum=0;
		tcp_for_write_queue(skb,sk) {
			sum+=skb->truesize;
		}
		if (sum!=sk->sk_wmem_queued) {
			printk(KERN_ERR "wqueue leak_1: enqueued:%d, recorded "
			       "value:%d\n",
			       sum,sk->sk_wmem_queued);
			
			tcp_for_write_queue(skb,sk) {
				printk(KERN_ERR "skb truesize:%d\n",
				       skb->truesize);
			}
			
			local_bh_enable();
			BUG();
		}
	}
	local_bh_enable();
	
}
#else
void verif_wqueues(struct multipath_pcb *mpcb)
{
	return;
}
#endif

void mtcp_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	if (sk->sk_protocol==IPPROTO_TCP && tcp_sk(sk)->mpc &&
	    tcp_sk(sk)->mpcb)
		atomic_add(skb->truesize, 
			   &((struct sock*)(tcp_sk(sk)->mpcb))->sk_rmem_alloc);
}

/*Removes a segment received on one subflow, but containing DSNs
  that were already received on another subflow
  Note that if the segment is not the head of the receive queue,
  we keep it in the list for future removal, because we cannot advance
  the tcp counters.
  WARNING: this may remove the skb, so no further reference to it
  should happen after calling this function.
*/
void mtcp_check_eat_old_seg(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (skb!=skb_peek(&sk->sk_receive_queue))
		return;
	/*OK, eat the segment, and advance tcp counters*/
	tp->copied_seq += skb->len;
	sk_eat_skb(sk,skb,0);
}

MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mtcp_sendmsg);
