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
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

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

/*Sysctl data*/

#ifdef CONFIG_SYSCTL

int sysctl_mptcp_mss = MPTCP_MSS; /*Will be enabled at the end of shim6 init*/

static ctl_table mptcp_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "mptcp_mss",
		.data		= &sysctl_mptcp_mss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ .ctl_name = 0 },
};

static ctl_table mptcp_net_table[] = {
	{
		.ctl_name       = CTL_UNNUMBERED,
		.procname       = "mptcp",
		.maxlen         = 0,
		.mode           = 0555,
		.child          = mptcp_table
	},
	{.ctl_name = 0},
};

static ctl_table mptcp_root_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= mptcp_net_table
	},
        { .ctl_name = 0 }
};
#endif


static void mtcp_def_readable(struct sock *sk, int len)
{
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tcp_sk(sk));
	struct sock *msk=mpcb->master_sk;
	
	BUG_ON(!mpcb);

	mtcp_debug("Waking up master subsock...\n");
	
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

	if (mpcb)
		mpcb->master_sk->sk_data_ready(mpcb->master_sk, 0);
#ifdef CONFIG_MTCP_PM
	else {
		/*This tp is not yet attached to the mpcb*/
		BUG_ON(!tp->pending);
		mpcb=mtcp_hash_find(tp->mtcp_loc_token);
		BUG_ON(!mpcb);
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
	struct sock *mpcb_sk=(struct sock *)mpcb;
	struct tcp_sock *newtp;

	BUG_ON(!tcp_sk(mpcb->master_sk)->mpc);
	
	/*First, ensure that we keep existing path indices.*/
	while (tp!=NULL) {
		/*disable the corresponding bit*/
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
			retval = sock_create_kern(mpcb_sk->sk_family, 
						  SOCK_STREAM, 
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
			switch(mpcb_sk->sk_family) {
			case AF_INET:
				memset(&loculid,0,sizeof(loculid));
				loculid_in.sin_family=mpcb_sk->sk_family;
				
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
				loculid_in6.sin6_family=mpcb_sk->sk_family;
				
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
			newtp->slave_sk=1;
			
			mtcp_add_sock(mpcb,newtp);
						
			/*Redefine the sk_data_ready function*/
			((struct sock*)newtp)->sk_data_ready=mtcp_def_readable;
						
			retval = sock->ops->bind(sock, loculid, ulid_size);
			if (retval<0) goto fail_bind;
			
			retval = sock->ops->connect(sock,remulid,
						    ulid_size,O_NONBLOCK);
			if (retval<0 && retval != -EINPROGRESS) 
				goto fail_connect;
			
			mtcp_debug("New MTCP subsocket created, pi %d\n",i+1);
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
	struct sock *mpcb_sk;
	struct ulid_pair *up;
	switch(event) {
	case NETEVENT_PATH_UPDATEV6:
		mtcp_debug("%s: Received path update event: %lu\n",__FUNCTION__, event);
		mpcb=container_of(self,struct multipath_pcb,nb);
		mpcb_sk=(struct sock*)mpcb;
		up=ctx;
		mtcp_debug("mpcb is %p\n",mpcb);
		if (mpcb_sk->sk_family!=AF_INET6) break;
		
		mtcp_debug("ev loc ulid:" NIP6_FMT "\n",NIP6(*up->local));
		mtcp_debug("ev loc ulid:" NIP6_FMT "\n",NIP6(*up->remote));
		mtcp_debug("ev loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->local_ulid.a6));
		mtcp_debug("ev loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->remote_ulid.a6));
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

	mtcp_debug("Entering %s\n",__FUNCTION__); /*TODEL*/

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
	BUG_ON(mpcb->connection_list);

	/*mpcb_sk inherits master sk*/
	mtcp_inherit_sk(master_sk,mpcb_sk);
	BUG_ON(mpcb->connection_list);

	/*Will be replaced by the IDSN later. Currently the 
	  IDSN is zero*/
	mpcb_tp->copied_seq = mpcb_tp->rcv_nxt = mpcb_tp->rcv_wup = 0;
	mpcb_tp->snd_sml = mpcb_tp->snd_una = mpcb_tp->snd_nxt = 0;
	
	mpcb_tp->mpcb=mpcb;
	mpcb_tp->mpc=1;
	mpcb_tp->mss_cache=sysctl_mptcp_mss;

	skb_queue_head_init(&mpcb_tp->out_of_order_queue);
	skb_queue_head_init(&mpcb->reinject_queue);
	
	mpcb_sk->sk_rcvbuf = sysctl_rmem_default;
	mpcb_sk->sk_sndbuf = sysctl_wmem_default;
	mpcb_sk->sk_state = TCPF_CLOSE;
	/*inherit locks the mpcb_sk, so we must release it here.*/
	bh_unlock_sock(mpcb_sk);
	sock_put(mpcb_sk);
	
	mpcb->master_sk=master_sk;

	kref_init(&mpcb->kref);

	spin_lock_init(&mpcb->lock);
	mutex_init(&mpcb->mutex);
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

void mpcb_release(struct kref* kref)
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

	skb_queue_purge(&mpcb_sk->sk_receive_queue);
	skb_queue_purge(&mpcb_tp->out_of_order_queue);

	kref_put(&mpcb->kref,mpcb_release);
}

/*MUST be called in user context
 */
void mtcp_add_sock(struct multipath_pcb *mpcb,struct tcp_sock *tp)
{
	struct sock *mpcb_sk=(struct sock*)mpcb;
	struct sock *sk=(struct sock*)tp;
	struct sk_buff *skb;

	/*first subflow*/
	if (!tp->path_index) tp->path_index=1;

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
		mtcp_update_sndbuf(mpcb);
		mpcb_sk->sk_state=TCP_ESTABLISHED;
	}
	
	kref_get(&mpcb->kref);

	/*Empty the receive queue of the added new subsocket
	  we do it with bh disabled, because before the mpcb is attached,
	  all segs are received in subflow queue,and after the mpcb is 
	  attached, all segs are received in meta-queue. So moving segments
	  from subflow to meta-queue must be done atomically with the 
	  setting of tp->mpcb.*/
	if (tp->mpc)
		while ((skb = skb_peek(&sk->sk_receive_queue))) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			if (mtcp_queue_skb(sk,skb)==MTCP_EATEN)
				__kfree_skb(skb);
		}
	local_bh_enable();
	mutex_unlock(&mpcb->mutex);
	
	mtcp_debug("Added subsocket with pi %d, cnt_subflows now %d\n",
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
	struct sock *mpcb_sk;
	if (sk->sk_protocol != IPPROTO_TCP) return;
	tp=tcp_sk(sk);
	mpcb=mpcb_from_tcpsock(tp);
	mpcb_sk=(struct sock*)mpcb;

	mtcp_debug("Entering %s, mpcb %p\n",__FUNCTION__,mpcb);

	mpcb_sk->sk_family=sk->sk_family;
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

		mtcp_debug("mum loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->local_ulid.a6));
		mtcp_debug("mum loc ulid:" NIP6_FMT "\n",NIP6(*(struct in6_addr*)mpcb->remote_ulid.a6));

		break;
	}
#ifdef CONFIG_MTCP_PM
	/*Searching for suitable local addresses,
	  except is the socket is loopback, in which case we simply
	  don't do multipath*/
	if (!ipv4_is_loopback(inet_sk(sk)->saddr) &&
	    !ipv4_is_loopback(inet_sk(sk)->daddr))
		mtcp_set_addresses(mpcb);
	/*If this added new local addresses, build new paths with them*/
	if (mpcb->num_addr4 || mpcb->num_addr6) mtcp_update_patharray(mpcb);
#endif	
}

/*copied from tcp_output.c*/
static inline unsigned int tcp_cwnd_test(struct tcp_sock *tp)
{
	u32 in_flight, cwnd;

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return (cwnd - in_flight);

	return 0;
}

int mtcp_is_available(struct sock *sk)
{
	if (sk->sk_state!=TCP_ESTABLISHED || tcp_sk(sk)->pf ||
	    (tcp_sk(sk)->mpcb->noneligible & 
	     PI_TO_FLAG(tcp_sk(sk)->path_index)) ||
	    inet_csk(sk)->icsk_ca_state==TCP_CA_Loss)
		return 0;
	if (tcp_cwnd_test(tcp_sk(sk))) return 1;
	return 0;
}

/**
 *This is the scheduler. This function decides on which flow to send
 *  a given MSS. If all subflows are found to be busy, NULL is returned
 * The flow is selected based on the estimation of how much time will be
 * needed to send the segment. If all paths have full cong windows, we
 * simply block. The flow able to send the segment the soonest get it. 
 * All subsocked must be locked before calling this function.
 */
struct sock* get_available_subflow(struct multipath_pcb *mpcb, 
				   struct sk_buff *skb, int *pf)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sock *bestsk=NULL;
	unsigned int min_time_to_peer=0xffffffff;
	int bh=in_interrupt(); 

	if (!mpcb) return NULL;
	
	if (!bh)
		mutex_lock(&mpcb->mutex);

	/*if there is only one subflow, bypass the scheduling function*/
	if (mpcb->cnt_subflows==1) {
		bestsk=(struct sock *)mpcb->connection_list;
		if (!mtcp_is_available(bestsk))
			bestsk=NULL;
		goto out;
	}

	/*First, find the best subflow*/
	mtcp_for_each_sk(mpcb,sk,tp) {
		unsigned int time_to_peer;
		if (pf && tp->pf) *pf|=PI_TO_FLAG(tp->path_index);
		if (!mtcp_is_available(sk)) continue;
		/*If the skb has already been enqueued in this sk, try to find
		  another one*/
		if (PI_TO_FLAG(tp->path_index) & skb->path_mask) continue;
		
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
		
		/*Time to reach peer, estimated in units of jiffies*/
		time_to_peer=
			((sk->sk_wmem_queued/tp->cur_bw_est)<<
			 tp->bw_est.shift)+ /*time to reach network*/
			(tp->srtt>>3); /*Time to reach peer*/
		
		if (time_to_peer<min_time_to_peer) {
			min_time_to_peer=time_to_peer;
			bestsk=sk;
		}
	}
	
out:
	if (!bh)
		mutex_unlock(&mpcb->mutex);
	return bestsk;
}

int mtcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *master_sk = sock->sk;
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tcp_sk(master_sk));
	struct sock *mpcb_sk = (struct sock *) mpcb;
	size_t copied = 0;

	if (!tcp_sk(master_sk)->mpc)
		return subtcp_sendmsg(iocb,master_sk, msg, size);
	
	BUG_ON(!mpcb);

	verif_wqueues(mpcb);

#ifdef CONFIG_MTCP_PM
	/*Any new subsock we can use ?*/
	mtcp_check_new_subflow(mpcb);
#endif
	
	/* Compute the total number of bytes stored in the message*/	
	copied = subtcp_sendmsg(NULL,mpcb_sk,msg, 0);
	if (copied<0)
		printk(KERN_ERR "%s: returning error "
		       "to app:%d\n",__FUNCTION__,(int)copied);

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
	struct sock *mpcb_sk=(struct sock*)mpcb;
	DEFINE_WAIT(wait);

	prepare_to_wait(master_sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	mtcp_for_each_sk(mpcb,sk,tp) {
		set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
		tp->wait_data_bit_set=1;
	}
	rc = mtcp_wait_event_any_sk(mpcb, sk, tp, timeo, 
				    (!skb_queue_empty(
					    &mpcb_sk->sk_receive_queue) ||
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
		/*We must ensure that for each new tp, 
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

void mtcp_ofo_queue(struct multipath_pcb *mpcb)
{
	struct sk_buff *skb=NULL;
	struct tcp_sock *tp;
	struct sock *mpcb_sk=(struct sock *) mpcb;
	struct tcp_sock *mpcb_tp=tcp_sk(mpcb_sk);
	
	while ((skb = skb_peek(&mpcb_tp->out_of_order_queue)) != NULL) {
		tp=tcp_sk(skb->sk);
		if (after(TCP_SKB_CB(skb)->data_seq, mpcb_tp->rcv_nxt))
			break;
				
		if (!after(TCP_SKB_CB(skb)->end_data_seq, mpcb_tp->rcv_nxt)) {
			printk(KERN_ERR "ofo packet was already received."
			       "skb->end_data_seq:%x,exp. rcv_nxt:%x\n",
			       TCP_SKB_CB(skb)->end_data_seq,mpcb_tp->rcv_nxt);
			/*Should not happen in the current design*/
			BUG();
		}
		
		__skb_unlink(skb, &mpcb_tp->out_of_order_queue);

		__skb_queue_tail(&mpcb_sk->sk_receive_queue, skb);
		mpcb_tp->rcv_nxt=TCP_SKB_CB(skb)->end_data_seq;
	}
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
static void mtcp_cleanup_rbuf(struct sock *mpcb_sk, int copied)
{
	struct tcp_sock *mpcb_tp = tcp_sk(mpcb_sk);
	struct multipath_pcb *mpcb=mpcb_tp->mpcb;
	struct sock *sk;
	struct tcp_sock *tp;
	int time_to_ack = 0;
	
	mtcp_for_each_sk(mpcb,sk,tp) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		if (!inet_csk_ack_scheduled(sk))
			continue;
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&mpcb_sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && 
	    !(mpcb_sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(mpcb_tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= mpcb_tp->window_clamp) {
			__u32 new_window = __tcp_select_window(mpcb->master_sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than 
			 * current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}
	/*If we need to send an explicit window update, we need to choose
	  some subflow to send it. At the moment, we use the master subsock 
	  for this.*/
	if (time_to_ack)
		tcp_send_ack(mpcb->master_sk);
}

/*Eats data from the meta-receive queue*/
int mtcp_check_rcv_queue(struct multipath_pcb *mpcb,struct msghdr *msg, 
			 size_t *len, u32 *data_seq, int *copied, int flags)
{
	struct sk_buff *skb;
	struct tcp_sock *tp;
	struct sock *mpcb_sk=(struct sock*)mpcb;
	int err;

	do {
		u32 data_offset = 0;
		unsigned long used;
		int fin = 0;

		skb = skb_peek(&mpcb_sk->sk_receive_queue);
		
		do {
			if (!skb) goto exit;

			fin=tcp_hdr(skb)->fin;
		
			tp=tcp_sk(skb->sk);

			if (before(*data_seq,TCP_SKB_CB(skb)->data_seq)) {
				printk(KERN_ERR "%s bug: copied %X "
				       "dataseq %X\n", __FUNCTION__, *data_seq,
				       TCP_SKB_CB(skb)->data_seq);
				BUG();
			}
			data_offset = *data_seq - TCP_SKB_CB(skb)->data_seq;
			if (data_offset < skb->len || fin)
				break;

			if (!tcp_hdr(skb)->fin && skb->len !=
			    TCP_SKB_CB(skb)->end_data_seq - TCP_SKB_CB(skb)->data_seq) {
				printk(KERN_ERR "skb->len:%d, should be %d\n",
				       skb->len,
				       TCP_SKB_CB(skb)->end_data_seq -
				       TCP_SKB_CB(skb)->data_seq);
				BUG();
			}
			WARN_ON(!(flags & MSG_PEEK));
			skb = skb->next;
		} while (skb != (struct sk_buff *)&mpcb_sk->sk_receive_queue);

		if (skb == (struct sk_buff *)&mpcb_sk->sk_receive_queue) goto exit;

		used = skb->len - data_offset;
		if (*len < used)
			used = *len;
		
		err=skb_copy_datagram_iovec(skb, data_offset,
					    msg->msg_iov, used);
		BUG_ON(err);
		
		*data_seq+=used+fin;
		*copied+=used;
		*len-=used;
		
 		if (*data_seq==TCP_SKB_CB(skb)->end_data_seq && 
		    !(flags & MSG_PEEK)) {
			sock_put(skb->sk);
			sk_eat_skb(mpcb_sk, skb, 0);
		}
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
	/*This checks whether an explicit window update is needed to unblock
	  the receiver*/
exit:
	mtcp_cleanup_rbuf(mpcb_sk,*copied);
	return 0;
}

int mtcp_queue_skb(struct sock *sk,struct sk_buff *skb)
{
	struct tcp_sock *tp=tcp_sk(sk);
	struct multipath_pcb *mpcb;
	int fin=tcp_hdr(skb)->fin;
	struct sock *mpcb_sk;
	struct tcp_sock *mpcb_tp;
	int ans;

	mpcb=mpcb_from_tcpsock(tp);
	if (tp->pending)
		mpcb=mtcp_hash_find(tp->mtcp_loc_token);
	mpcb_sk=(struct sock *) mpcb;
	mpcb_tp=tcp_sk(mpcb_sk);

	if (!tp->mpc || !mpcb) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		sock_hold(skb->sk);
		return MTCP_QUEUED;
	}
	
	/*In all cases, we remove it from the subsock, so copied_seq
	  must be advanced*/
	tp->copied_seq=TCP_SKB_CB(skb)->end_seq+fin;
	tcp_rcv_space_adjust(sk);
	
	/*Verify that the mapping info has been read*/
	if(TCP_SKB_CB(skb)->data_len) {
		mtcp_get_dataseq_mapping(tp,skb);
	}
	
	/*Is this a duplicate segment ?*/
	if (!before(mpcb_tp->rcv_nxt,TCP_SKB_CB(skb)->end_data_seq)) {
		/*Duplicate segment. We can arrive here only if a segment 
		  has been retransmitted by the sender on another subflow.
		  Retransmissions on the same subflow are handled at the
		  subflow level.*/

		/* We do not read the skb, since it was already received on
		   another subflow*/
		ans=MTCP_EATEN;
		goto out;
	}
	
	if (before(mpcb_tp->rcv_nxt,TCP_SKB_CB(skb)->data_seq)) {
		
		if (!skb_peek(&mpcb_tp->out_of_order_queue)) {
			/* Initial out of order segment */
			mtcp_debug("First meta-ofo segment\n");
			__skb_queue_head(&mpcb_tp->out_of_order_queue, skb);
			sock_hold(skb->sk);
			ans=MTCP_QUEUED;
			goto out;
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
					ans=MTCP_EATEN;
					goto out;
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
			sock_hold(skb->sk);
			/* And clean segments covered by new one as whole. */
			while ((skb1 = skb->next) !=
			       (struct sk_buff *)&mpcb_tp->out_of_order_queue &&
			       after(TCP_SKB_CB(skb)->end_data_seq, 
				     TCP_SKB_CB(skb1)->data_seq)) {
				if (!before(TCP_SKB_CB(skb)->end_data_seq, 
					    TCP_SKB_CB(skb1)->end_data_seq)) {
					skb_unlink(skb1, 
						     &mpcb_tp->
						     out_of_order_queue);
					__kfree_skb(skb1);
				}
				else break;
			}
			ans=MTCP_QUEUED;
			goto out;
		}
	}
	else {
		__skb_queue_tail(&mpcb_sk->sk_receive_queue, skb);
		sock_hold(skb->sk);
		mpcb_tp->rcv_nxt=TCP_SKB_CB(skb)->end_data_seq;

		/*Check if this fills a gap in the ofo queue*/
		if (!skb_queue_empty(&mpcb_tp->out_of_order_queue))
			mtcp_ofo_queue(mpcb);

		ans=MTCP_QUEUED;
		goto out;
	}
out:
	if (tp->pending) 
		mpcb_put(mpcb);
	return ans;
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
 * Reinject data from one TCP subflow to the mpcb_sk 
 * The @skb given pertains to the original tp, that keeps it
 * because the skb is still sent on the original tp. But additionnally,
 * it is sent on the other subflow. 
 *
 * @pre : @sk must be the mpcb_sk
 */
int __mtcp_reinject_data(struct sk_buff *orig_skb, struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th;
	struct sock *sk_it;
	struct tcp_sock *tp_it;
	
	/*A segment can be added to the reinject queue only if 
	  there is at least one working subflow that has never sent
	  this data*/
	mtcp_for_each_sk(tp->mpcb,sk_it,tp_it) {
		if (sk_it->sk_state!=TCP_ESTABLISHED)
			continue;
		/*If the skb has already been enqueued in this sk, try to find
		  another one*/
		if (PI_TO_FLAG(tp_it->path_index) & orig_skb->path_mask) 
			continue;
		
		/*candidate subflow found, we can reinject*/
		break;
	}
	
	if (!sk_it) {
		if ((PI_TO_FLAG(1) & orig_skb->path_mask) &&
		    (PI_TO_FLAG(9) & orig_skb->path_mask))
			tcpprobe_logmsg(sk,"skb already injected to all "
					"paths");
		return 0; /*no candidate found*/
	}

	skb=skb_clone(orig_skb,GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOBUFS;
	skb->sk=sk;

	th=tcp_hdr(skb);
	
	BUG_ON(!skb);
	BUG_ON(skb->path_mask!=orig_skb->path_mask);
	
	skb_queue_tail(&tp->mpcb->reinject_queue,skb);
	return 0;
}

/*Inserts data into the reinject queue*/
void mtcp_reinject_data(struct sock *orig_sk)
{
	struct sk_buff *skb_it;
	struct tcp_sock *orig_tp = tcp_sk(orig_sk);
	struct multipath_pcb *mpcb=orig_tp->mpcb;
	struct sock *mpcb_sk=(struct sock*)mpcb;

	BUG_ON(is_meta_sk(orig_sk));
	
	verif_wqueues(mpcb);
	
	tcp_for_write_queue(skb_it,orig_sk) {
		skb_it->path_mask|=PI_TO_FLAG(orig_tp->path_index);
		if (unlikely(__mtcp_reinject_data(skb_it,mpcb_sk)<0))
			break;
	}
	
	tcpprobe_logmsg(orig_sk,"after reinj, reinj queue size:%d",
			skb_queue_len(&mpcb->reinject_queue));
	

	tcp_push(mpcb_sk, 0, sysctl_mptcp_mss, TCP_NAGLE_PUSH);

	if (orig_tp->pf==0)
		tcpprobe_logmsg(orig_sk,"pi %d: entering pf state",
				orig_tp->path_index);
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
 *   ii) if its end_data_seq is older then mpcb->copied_seq, it is a 
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

/*Cleans the meta-socket retransmission queue.
  @sk must be the metasocket.*/
void mtcp_clean_rtx_queue(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp=tcp_sk(sk);
	
	BUG_ON(!is_meta_tp(tp));
	
	check_send_head(sk,0);
	
	while ((skb = tcp_write_queue_head(sk)) && skb != tcp_send_head(sk)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		if (before(tp->snd_una,scb->end_data_seq))
			break;
		if(skb==tcp_send_head(sk)) {
			printk(KERN_ERR "removing the send head !\n");
			printk(KERN_ERR "was it ever transmitted ?\n");
			printk(KERN_ERR "dsn is %#x\n",
			       TCP_SKB_CB(skb)->data_seq);
			BUG();
		}
		tcp_unlink_write_queue(skb, sk);
		tp->packets_out-=tcp_skb_pcount(skb);
		sk_wmem_free_skb(sk, skb);
	}
	check_send_head(sk,1);
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

/*Update the mpcb send window, based on the contributions
  of each subflow*/
void mtcp_update_sndbuf(struct multipath_pcb *mpcb)
{
	struct sock *mpcb_sk=(struct sock*)mpcb;
	struct tcp_sock *tp;
	struct sock *sk;
	int new_sndbuf=0;
	mtcp_for_each_sk(mpcb,sk,tp)
		new_sndbuf += sk->sk_sndbuf;
	mpcb_sk->sk_sndbuf = new_sndbuf;
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

//#define DEBUG_WQUEUES 1
#ifdef DEBUG_WQUEUES
void verif_wqueues(struct multipath_pcb *mpcb) 
{
	struct sock *sk;
	struct sock *mpcb_sk=(struct sock*)mpcb;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int sum;

	local_bh_disable();
	mtcp_for_each_sk(mpcb,sk,tp) {
		sum=0;
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
	sum=0;
	tcp_for_write_queue(skb,mpcb_sk)
		sum+=skb->truesize;		
	BUG_ON(sum!=mpcb_sk->sk_wmem_queued);
	local_bh_enable();
}
#else
void verif_wqueues(struct multipath_pcb *mpcb)
{
	return;
}
#endif

//#define DEBUG_RQUEUES 1
#ifdef DEBUG_RQUEUES
void verif_rqueues(struct multipath_pcb *mpcb) 
{
	struct sock *sk;
	struct sock *mpcb_sk=(struct sock*)mpcb;
	struct tcp_sock *tp;
	struct sk_buff *skb;
	int sum;

	local_bh_disable();
	mtcp_for_each_sk(mpcb,sk,tp) {
		sum=0;
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			sum+=skb->truesize;
		}
		skb_queue_walk(&tp->out_of_order_queue, skb) {
			sum+=skb->truesize;
		}
		/*TODO: add meta-rcv and meta-ofo-queues*/
		if (sum!=atomic_read(&sk->sk_rmem_alloc)) {
			printk(KERN_ERR "rqueue leak: enqueued:%d, recorded "
			       "value:%d\n",
			       sum,sk->sk_rmem_alloc);
			
			local_bh_enable();
			BUG();
		}
	}
	local_bh_enable();
}
#else
void verif_rqueues(struct multipath_pcb *mpcb)
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
EXPORT_SYMBOL(mtcp_set_owner_r);

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
	struct tcphdr *th = tcp_hdr(skb);
	if (skb!=skb_peek(&sk->sk_receive_queue))
		return;
	BUG_ON(tp->copied_seq!=TCP_SKB_CB(skb)->seq);
	/*OK, eat the segment, and advance tcp counters*/
	tp->copied_seq += skb->len;
	tcp_rcv_space_adjust(sk);
	if (tp->copied_seq!=TCP_SKB_CB(skb)->end_seq && !th->fin) {
		printk(KERN_ERR "corrupted seg: seq:%#x,end_seq:%#x,len:%d\n",
		       TCP_SKB_CB(skb)->seq,TCP_SKB_CB(skb)->end_seq,skb->len);
		BUG();
	}
	inet_csk_schedule_ack(sk);
	sk_eat_skb(sk,skb,0);
}

/**
 * Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the 
 * reinject queue. Otherwise sets @reinject to 0.
 */
struct sk_buff* mtcp_next_segment(struct sock *sk, int *reinject)
{	
	struct multipath_pcb *mpcb=tcp_sk(sk)->mpcb;
	struct sk_buff *skb;
	if (reinject) *reinject=0;
	if (!is_meta_sk(sk))
		return tcp_send_head(sk);
	if ((skb=skb_peek(&mpcb->reinject_queue))) {
 		if (reinject) *reinject=1; /*Segments in reinject queue are 
					     already cloned*/
		return skb;
	}
	else return tcp_send_head(sk);
}

/*Sets the socket pointer of the mpcb_sk after an accept at the socket level
 * Set also the sk_sleep pointer, because it has just been copied by
 * sock_graft() */
void mtcp_check_socket(struct sock *sk)
{
	if (sk->sk_protocol==IPPROTO_TCP && tcp_sk(sk)->mpcb) {
		struct sock *mpcb_sk=(struct sock*)(tcp_sk(sk)->mpcb);
		sk_set_socket(mpcb_sk,sk->sk_socket);
		mpcb_sk->sk_sleep=sk->sk_sleep;
	}
}
EXPORT_SYMBOL(mtcp_check_socket);

#ifdef MTCP_DEBUG_PKTS_OUT
int check_pkts_out(struct sock* sk) {
	int cnt=0;
	struct sk_buff *skb;
	struct tcp_sock *tp=tcp_sk(sk);
	/*TODEL: sanity check on packets_out*/
	if (tp->mpc && !is_meta_tp(tp)) {
		tcp_for_write_queue(skb,sk) {
			if (skb == tcp_send_head(sk))
				break;
			else cnt+=tcp_skb_pcount(skb);
		}
		BUG_ON(tp->packets_out!=cnt);
	}
	else cnt=-10;

	return cnt;
}

void check_send_head(struct sock *sk, int num) {
	struct sk_buff *head=tcp_send_head(sk);
	struct sk_buff *skb;
	int found=0;
	if (head) {
		tcp_for_write_queue(skb,sk) {
			if (skb==head) {
				found=1;
				break;
			}			
		}
	}
	else found=1;
	if(!found) {
		printk(KERN_ERR "num:%d\n",num);
		BUG();
	}
}
#endif

/*General initialization of mptcp
 */
static int __init mptcp_init(void)
{
#ifdef CONFIG_SYSCTL
	register_sysctl_table(mptcp_root_table);
#endif
	return 0;
}
module_init(mptcp_init);

MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mtcp_sendmsg);
