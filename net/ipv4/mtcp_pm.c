/*
 *	MTCP PM implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *
 *      date : March 10
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <net/mtcp.h>
#include <net/mtcp_pm.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

#define MTCP_HASH_SIZE                16
#define hash_tk(token) \
	jhash_1word(token,0)%MTCP_HASH_SIZE


extern struct ip_options *tcp_v4_save_options(struct sock *sk,
					      struct sk_buff *skb);
extern void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags);
extern void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
		       const struct tcp_out_options *opts,
		       __u8 **md5_hash);


static struct list_head tk_hashtable[MTCP_HASH_SIZE];
static rwlock_t tk_hash_lock; /*hashtable protection*/


/* General initialization of MTCP_PM
 */
static int __init mtcp_pm_init(void) 
{
	int i;
	for (i=0;i<MTCP_HASH_SIZE;i++)
		INIT_LIST_HEAD(&tk_hashtable[i]);		
	rwlock_init(&tk_hash_lock);
	return 0;
}

void mtcp_hash_insert(struct multipath_pcb *mpcb,u32 token)
{
	int hash=hash_tk(token);
	write_lock_bh(&tk_hash_lock);
	list_add(&mpcb->collide_tk,&tk_hashtable[hash]);
	write_unlock_bh(&tk_hash_lock);
}

struct multipath_pcb* mtcp_hash_find(u32 token)
{
	int hash=hash_tk(token);
	struct multipath_pcb *mpcb;
	read_lock(&tk_hash_lock);
	list_for_each_entry(mpcb,&tk_hashtable[hash],collide_tk) {
		if (token==loc_token(mpcb))
			return mpcb;
	}
	read_unlock(&tk_hash_lock);
	return NULL;
}

void mtcp_hash_remove(struct multipath_pcb *mpcb)
{
	write_lock_bh(&tk_hash_lock);
	list_del(&mpcb->collide_tk);
	write_unlock_bh(&tk_hash_lock);
}


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



struct path4 *find_path_mapping4(struct in_addr *loc,struct in_addr *rem,
				 struct multipath_pcb *mpcb)
{
	int i;
	for (i=0;i<mpcb->pa4_size;i++)
		if (mpcb->pa4[i].loc.addr.s_addr == loc->s_addr &&
		    mpcb->pa4[i].rem.addr.s_addr == rem->s_addr)
			return &mpcb->pa4[i];
	return NULL;
}

struct in_addr *mtcp_get_loc_addr(struct multipath_pcb *mpcb, int path_index)
{
	int i;
 	if (path_index<=1)
		return (struct in_addr*)&mpcb->local_ulid.a4;
	for (i=0;i<mpcb->pa4_size;i++) {
		if (mpcb->pa4[i].path_index==path_index)
			return &mpcb->pa4[i].loc.addr;
	}
	BUG();
	return NULL;
}

struct in_addr *mtcp_get_rem_addr(struct multipath_pcb *mpcb, int path_index)
{
	int i;
 	if (path_index<=1)
		return (struct in_addr*)&mpcb->remote_ulid.a4;
	for (i=0;i<mpcb->pa4_size;i++) {
		if (mpcb->pa4[i].path_index==path_index)
			return &mpcb->pa4[i].rem.addr;
	}
	BUG();
	return NULL;
}

u8 mtcp_get_loc_addrid(struct multipath_pcb *mpcb, int path_index)
{
	int i;
	/*master subsocket has both addresses with id 0*/
	if (path_index<=1) return 0;
	for (i=0;i<mpcb->pa4_size;i++) {
		if (mpcb->pa4[i].path_index==path_index)
			return mpcb->pa4[i].loc.id;
	}
	BUG();
	return -1;
}


/*For debugging*/
void print_patharray(struct path4 *pa, int size)
{
	int i;
	printk(KERN_ERR "==================\n");
	for (i=0;i<size;i++) {
		printk(KERN_ERR NIPQUAD_FMT "/%d->"
		       NIPQUAD_FMT "/%d, pi %d\n",
		       NIPQUAD(pa[i].loc.addr),pa[i].loc.id,
		       NIPQUAD(pa[i].rem.addr),pa[i].rem.id,
		       pa[i].path_index);
	}
}



/*This is the MPTCP PM mapping table*/
void mtcp_update_patharray(struct multipath_pcb *mpcb)
{
	struct path4 *new_pa4, *old_pa4;
	int i,j,newpa_idx=0;
	/*Count how many paths are available
	  We add 1 to size of local and remote set, to include the 
	  ULID*/
	int ulid_v4=(mpcb->sa_family==AF_INET)?1:0;
	int pa4_size=(mpcb->num_addr4+ulid_v4)*
		(mpcb->received_options.num_addr4+ulid_v4)-ulid_v4;
	
	new_pa4=kmalloc(pa4_size*sizeof(struct path4),GFP_ATOMIC);
	
	if (ulid_v4) {
		/*ULID src with other dest*/
		for (j=0;j<mpcb->received_options.num_addr4;j++) {
			struct path4 *p=find_path_mapping4(
				(struct in_addr*)&mpcb->local_ulid.a4,
				&mpcb->received_options.addr4[j].addr,mpcb);
			if (p)
				memcpy(&new_pa4[newpa_idx++],p,
				       sizeof(struct path4));
			else {
				/*local addr*/
				new_pa4[newpa_idx].loc.addr.s_addr=
					mpcb->local_ulid.a4;
				new_pa4[newpa_idx].loc.id=0; /*ulid has id 0*/
				/*remote addr*/
				memcpy(&new_pa4[newpa_idx].rem,
				       &mpcb->received_options.addr4[j],
				       sizeof(struct mtcp_loc4));
				/*new path index to be given*/
				new_pa4[newpa_idx++].path_index=
					mpcb->next_unused_pi++;
			}			
		}
		/*ULID dest with other src*/
		for (i=0;i<mpcb->num_addr4;i++) {
			struct path4 *p=find_path_mapping4(
				&mpcb->addr4[i].addr,
				(struct in_addr*)&mpcb->remote_ulid.a4,mpcb);
			if (p)
				memcpy(&new_pa4[newpa_idx++],p,
				       sizeof(struct path4));
			else {
				/*local addr*/
				memcpy(&new_pa4[newpa_idx].loc,
				       &mpcb->addr4[i],
				       sizeof(struct mtcp_loc4));
				
				/*remote addr*/
				new_pa4[newpa_idx].rem.addr.s_addr=
					mpcb->remote_ulid.a4;
				new_pa4[newpa_idx].rem.id=0; /*ulid has id 0*/
				/*new path index to be given*/
				new_pa4[newpa_idx++].path_index=
					mpcb->next_unused_pi++;
			}
		}
	}
	/*Try all other combinations now*/
	for (i=0;i<mpcb->num_addr4;i++)
		for (j=0;j<mpcb->received_options.num_addr4;j++) {
			struct path4 *p=find_path_mapping4(
				&mpcb->addr4[i].addr,
				&mpcb->received_options.addr4[j].addr,mpcb);
			if (p)
				memcpy(&new_pa4[newpa_idx++],p,
				       sizeof(struct path4));	
			else {
				/*local addr*/
				memcpy(&new_pa4[newpa_idx].loc,
				       &mpcb->addr4[i],
				       sizeof(struct mtcp_loc4));
				/*remote addr*/
				memcpy(&new_pa4[newpa_idx].rem,
				       &mpcb->received_options.addr4[j],
				       sizeof(struct mtcp_loc4));
				
				/*new path index to be given*/
				new_pa4[newpa_idx++].path_index=
					mpcb->next_unused_pi++;
			}
		}
	
	
	/*Replacing the mapping table*/
	old_pa4=mpcb->pa4;
	mpcb->pa4=new_pa4;
	mpcb->pa4_size=pa4_size;
	if (old_pa4) kfree(old_pa4);
	print_patharray(mpcb->pa4, mpcb->pa4_size);
}


void mtcp_set_addresses(struct multipath_pcb *mpcb)
{
	struct net_device *dev;
	int id=1;

	mpcb->num_addr4=0;

	read_lock(&dev_base_lock); 

	for_each_netdev(&init_net,dev) {
		if(netif_running(dev)) {
			struct in_device *in_dev=dev->ip_ptr;
			struct in_ifaddr *ifa;
			
			if (!strcmp(dev->name,"lo"))
				continue;

			if (mpcb->num_addr4==MTCP_MAX_ADDR) {
				printk(KERN_ERR "Reached max number of local"
				       "IPv4 addresses : %d\n", MTCP_MAX_ADDR);
				break;
			}
			
			for (ifa = in_dev->ifa_list; ifa; 
			     ifa = ifa->ifa_next) {
				if (ifa->ifa_address==
				    inet_sk(mpcb->master_sk)->saddr)
					continue;
				mpcb->addr4[mpcb->num_addr4].addr.s_addr=
					ifa->ifa_address;
				mpcb->addr4[mpcb->num_addr4++].id=id++;
			}
		}
	}
	
	read_unlock(&dev_base_lock); 
}

/**
 * Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional 
 * address
 */
static int mtcp_v4_add_raddress(struct multipath_pcb *mpcb, 
				struct in_addr *addr, u8 id)
{
	int i;
	int num_addr4=mpcb->received_options.num_addr4;
	for (i=0;i<mpcb->received_options.num_addr4;i++) {
		if (mpcb->received_options.addr4[i].addr.s_addr==
		    addr->s_addr) {
			mpcb->received_options.addr4[i].id=id; /*update the 
								 id*/
			return 0;
		}
	}
	if (mpcb->received_options.num_addr4==MTCP_MAX_ADDR)
		return -1;

	/*Address is not known yet, store it*/
	mpcb->received_options.addr4[num_addr4].addr.s_addr=
		addr->s_addr;
	mpcb->received_options.addr4[num_addr4].id=id;
	mpcb->received_options.num_addr4++;
	return 0;
}


static struct dst_entry* mtcp_route_req(const struct request_sock *req)
{
	struct rtable *rt;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options *opt = inet_rsk(req)->opt;
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = ((opt && opt->srr) ?
						  opt->faddr :
						  ireq->rmt_addr),
					.saddr = ireq->loc_addr } },
			    .proto = IPPROTO_TCP,
			    .flags = 0,
			    .uli_u = { .ports =
				       { .sport = ireq->loc_port,
					 .dport = ireq->rmt_port } } };
	security_req_classify_flow(req, &fl);
	if (ip_route_output_flow(&init_net, &rt, &fl, NULL, 0)) {
		IP_INC_STATS_BH(&init_net, IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway) {
		ip_rt_put(rt);
		IP_INC_STATS_BH(&init_net, IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	return &rt->u.dst;
}

static unsigned mtcp_synack_options(struct request_sock *req,
				    unsigned mss, struct sk_buff *skb,
				    struct tcp_out_options *opts,
				    struct tcp_md5sig_key **md5)
{
	unsigned size = 0;
	struct inet_request_sock *ireq = inet_rsk(req);
	char doing_ts;

	*md5 = NULL;

	printk(KERN_ERR "Entering %s\n",__FUNCTION__);

	/* we can't fit any SACK blocks in a packet with MD5 + TS
	   options. There was discussion about disabling SACK rather than TS in
	   order to fit in better with old, buggy kernels, but that was deemed
	   to be unnecessary. */
	doing_ts = ireq->tstamp_ok && !(*md5 && ireq->sack_ok);

	opts->mss = mss;
	size += TCPOLEN_MSS_ALIGNED;

	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		if(likely(opts->ws))
			size += TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(doing_ts)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = req->ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!doing_ts))
			size += TCPOLEN_SACKPERM_ALIGNED;
	}

	return size;
}

static __inline__ void
TCP_ECN_make_synack(struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/*
 * Prepare a SYN-ACK, for JOINed subflows
 */
static struct sk_buff *mtcp_make_synack(struct sock *master_sk, 
					struct dst_entry *dst,
					struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_sock *master_tp = tcp_sk(master_sk);
	struct tcphdr *th;
	int tcp_header_size;
	struct tcp_out_options opts;
	struct sk_buff *skb;
	struct tcp_md5sig_key *md5;
	__u8 *md5_hash_location;
	int mss;

	printk(KERN_ERR "Entering %s\n",__FUNCTION__);

	skb = alloc_skb(MAX_TCP_HEADER + 15, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_TCP_HEADER);

	skb->dst = dst_clone(dst);

	mss = dst_metric(dst, RTAX_ADVMSS);
	if (master_tp->rx_opt.user_mss && master_tp->rx_opt.user_mss < mss)
		mss = master_tp->rx_opt.user_mss;

	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns */
		__u8 rcv_wscale;
		/* Set this up on the first call only */
		req->window_clamp = dst_metric(dst, RTAX_WINDOW);
		/* tcp_full_space because it is guaranteed to be the first 
		   packet */
		tcp_select_initial_window(
			tcp_win_from_space(sysctl_rmem_default),
			mss - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
			&req->rcv_wnd,
			&req->window_clamp,
			ireq->wscale_ok,
			&rcv_wscale);
		ireq->rcv_wscale = rcv_wscale;
	}

	memset(&opts, 0, sizeof(opts));

	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	tcp_header_size = mtcp_synack_options(req, mss,
					      skb, &opts, &md5) +
		sizeof(struct tcphdr);       
	
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	th = tcp_hdr(skb);
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	TCP_ECN_make_synack(req, th);
	th->source = ireq->loc_port;
	th->dest = ireq->rmt_port;
	/* Setting of flags are superfluous here for callers (and ECE is
	 * not even correctly set)
	 */
	tcp_init_nondata_skb(skb, tcp_rsk(req)->snt_isn,
			     TCPCB_FLAG_SYN | TCPCB_FLAG_ACK);
	th->seq = htonl(TCP_SKB_CB(skb)->seq);
	th->ack_seq = htonl(tcp_rsk(req)->rcv_isn + 1);
	
	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rcv_wnd, 65535U));
	tcp_options_write((__be32 *)(th + 1), NULL, &opts, &md5_hash_location);
	th->doff = (tcp_header_size >> 2);

	return skb;
}

/*
 *	Send a SYN-ACK after having received a SYN.
 *	This still operates on a request_sock only, not on a big
 *	socket.
 */
static int __mtcp_v4_send_synack(struct sock *master_sk,
				 struct request_sock *req,
				 struct dst_entry *dst)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int err = -1;
	struct sk_buff * skb;

	printk(KERN_ERR "Entering %s\n",__FUNCTION__);

	/* First, grab a route. */
	if (!dst && (dst = mtcp_route_req(req)) == NULL)
		return -1;

	skb = mtcp_make_synack(master_sk, dst, req);

	if (skb) {
		struct tcphdr *th = tcp_hdr(skb);

		th->check = tcp_v4_check(skb->len,
					 ireq->loc_addr,
					 ireq->rmt_addr,
					 csum_partial((char *)th, skb->len,
						      skb->csum));

		err = ip_build_and_send_pkt(skb, master_sk, ireq->loc_addr,
					    ireq->rmt_addr,
					    ireq->opt);
		err = net_xmit_eval(err);
	}

	dst_release(dst);
	return err;
}

/*Copied from tcp_ipv4.c*/
static inline __u32 tcp_v4_init_sequence(struct sk_buff *skb)
{
	return secure_tcp_sequence_number(ip_hdr(skb)->daddr,
					  ip_hdr(skb)->saddr,
					  tcp_hdr(skb)->dest,
					  tcp_hdr(skb)->source);
}

static int mtcp_v4_join_request(struct multipath_pcb *mpcb, struct sk_buff *skb)
{
	struct inet_request_sock *ireq;
	struct request_sock *req;
	struct tcp_options_received tmp_opt;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;	

	printk(KERN_ERR "Entering %s\n",__FUNCTION__);

	req = inet_reqsk_alloc(mpcb->master_sk->sk_prot->rsk_prot);
	if (!req)
		return -1;
		
	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = 536;
	tmp_opt.user_mss  = tcp_sk(mpcb->master_sk)->rx_opt.user_mss;
	
	tcp_parse_options(skb, &tmp_opt, &mpcb->received_options, 0);
	
	if (tmp_opt.saw_tstamp && !tmp_opt.rcv_tsval) {
		/* Some OSes (unknown ones, but I see them on web server, which
		 * contains information interesting only for windows'
		 * users) do not send their stamp in SYN. It is easy case.
		 * We simply do not advertise TS support.
		 */
		tmp_opt.saw_tstamp = 0;
		tmp_opt.tstamp_ok  = 0;
	}
	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->opt = tcp_v4_save_options(NULL, skb);

	/*Todo: add the sanity checks here. See tcp_v4_conn_request*/

	isn = tcp_v4_init_sequence(skb);

	tcp_rsk(req)->snt_isn = isn;

 	if (__mtcp_v4_send_synack(mpcb->master_sk, req, NULL))
		goto drop_and_free;

	/*Adding to synqueue in metasocket*/
	req->dl_next=mpcb->synqueue;
	mpcb->synqueue=req;

	return 0;

drop_and_free:
	reqsk_free(req);
	return -1;
}


/*Checker whether there is already a subsock created for that 
  skb*/
static struct sock *existing_sock(struct multipath_pcb *mpcb,
				  struct sk_buff *skb)
{
	struct path4 *path;
	struct tcp_sock *tp;
	struct iphdr *iph=ip_hdr(skb);
	path=find_path_mapping4((struct in_addr*)&iph->daddr,
				(struct in_addr*)&iph->saddr,
				mpcb);
	if (!path) return NULL;
	for (tp=mpcb->connection_list;tp;tp=tp->next) {
		if (tp->path_index==path->path_index)
			return (struct sock*)tp;
	}
	return NULL;
}


/**
 * skb is a received SYN
 * Returns the corresponding open request if found.
 * If such a request is found, we reply to the syn with a syn+ack
 * (retransmission)
 */
static struct request_sock *existing_request(struct multipath_pcb *mpcb,
					     struct sk_buff *skb)
{
	struct request_sock *req;
	
	for (req=mpcb->synqueue;req;req=req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);
		if (ireq->loc_addr==ip_hdr(skb)->daddr &&
		    ireq->rmt_addr==ip_hdr(skb)->saddr &&
		    ireq->loc_port==tcp_hdr(skb)->dest &&
		    ireq->rmt_port==tcp_hdr(skb)->source) {
			__mtcp_v4_send_synack(mpcb->master_sk,
					      req,NULL);
			return req;
		}
	}
	return NULL;
}

/**
 * If *sk is non-NULL, we have found an mpcb, and a subsocket was already
 * present for that subflow. If it is NULL, either we have found an mpcb
 * and sent a notification to MPS so that a new subsocket is created, or we 
 * have * not found it, and the normal lookup must take place. 
 * Doing or not the normal lookup is decided by the return value of this
 * function.
 *
 * Returns 0 if standard lookup must still be performed.
 * Returns 1 if no standard lookup is necessary anymore, even if *sk
 * NULL.*/
int mtcp_lookup_join(struct sk_buff *skb, struct sock **sk)
{
	struct tcphdr *th=tcp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);
	unsigned char *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);
	u32 token;
	struct multipath_pcb *mpcb;
	int ans;

	*sk=NULL;
	
	/*Jump through the options to check whether JOIN is there*/
	ptr = (unsigned char *)(th + 1);
	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return 0;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return 0;
			if (opsize > length)
				return 0; /* don't parse partial options */
			if (opcode==TCPOPT_JOIN) {
				token=ntohl(*(u32*)ptr);
				mpcb=mtcp_hash_find(token);			
				if (!mpcb) {
					printk(KERN_ERR "not found\n");
					return 0;
				}
				/*Is there already a subflow for that path ?*/
				*sk=existing_sock(mpcb,skb);
				if (*sk) goto finished;
				/*Is there already an open request for that
				  path ?*/
				if (existing_request(mpcb,skb))
					goto finished;
				/*OK, this is a new syn/join, let's 
				  create a new open request and 
				  send syn+ack*/
				ans=mtcp_v4_add_raddress(mpcb, 
							 (struct in_addr*)
							 &iph->saddr, *(ptr+4));
				if (ans<0) goto finished;
				mtcp_v4_join_request(mpcb, skb);		
				goto finished;
			}
			ptr += opsize-2;
			length -= opsize;
		}
	}

	return 0;
finished:
	kfree_skb(skb);
	return 1;
}


/**
 *Sends an update notification to the MPS
 *Since this particular PM works in the TCP layer, that is, the same
 *as the MPS, we "send" the notif through function call, not message
 *passing.
 * Warning: this can be called only from user context, not soft irq
 **/
void mtcp_send_updatenotif(struct multipath_pcb *mpcb)
{
	int i;
	u32 path_indices=1; /*Path index 1 is reserved for master sk.*/
	for (i=0;i<mpcb->pa4_size;i++) {
		path_indices|=PI_TO_FLAG(mpcb->pa4[i].path_index);
	}
	mtcp_init_subsockets(mpcb,path_indices);
}

module_init(mtcp_pm_init);

MODULE_LICENSE("GPL");

