/*
 *      MTCP implementation
 *
 *      Authors:
 *      Costin Raiciu           <c.raiciu@cs.ucl.ac.uk>
 *      Sébastien Barré         <sebastien.barre@uclouvain.be>
 *
 *      date : March 09
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <net/multipath.h>

hash_table_t 	*multipath_pcbs = NULL;
hash_table_t 	*token_pcbs = NULL;
int conn_no;

extern __u32 sysctl_rmem_default;
extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_max;
extern __u32 sysctl_wmem_max;

int get_interface_loc(__u32 ip);

struct user_pcb* pcb_from_fd(int _s);


void print_ip(int ip){
  printf("%d.%d.%d.%d",(ip)&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF);
}

char* sprint_ip(__u32 ip){
  char * ret = (char*)malloc(30*sizeof(char));
  sprintf(ret,"%d.%d.%d.%d",(ip)&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF);
  return ret;
}

void add_sock(struct multipath_pcb* mpcb,struct user_pcb* sock){
  subflow_t last = mpcb->connection_list;
  subflow_t tmp = (subflow_t)malloc(sizeof(struct subflow));
  tmp->pcb = sock;

  tmp->first = 0;
  //on sent stuff, do not need to remember id!
 
  //printf("%d pcb is %d\n",tmp->local_id,sock);

  //tmp->next = mpcb->connection_list;		
  //mpcb->connection_list = tmp;			

  tmp->next = NULL;
  if (last==NULL)
    mpcb->connection_list = tmp;
  else{
    while (last->next!=NULL)
      last = last->next;
    last->next = tmp;
  }

  mpcb->cnt_subflows ++;	
  insert_hash_entry(multipath_pcbs,sock->uid,mpcb);
  sock->sk->socket->mpcb = mpcb;
}

void multipath_add_address(struct multipath_pcb* mpcb, __u32 ip){
  int id;
  /*Too many bound addresses*/
  BUG_ON(mpcb->cnt_local_addr>=MAX_LOCAL_ADDR)

  mpcb->local_ips[mpcb->cnt_local_addr] = ip;
  printf("Add ip to advertise %s\n",sprint_ip(mpcb->local_ips[mpcb->cnt_local_addr]));

  id = get_interface_loc(ip);

  BUG_ON(id<0); /*Can't find that interface*/

  init_interface(id);

  mpcb->cnt_local_addr++;
}

void print_sock_list(struct multipath_pcb* mpcb)
{ 
  subflow_t tmp;
  tmp = mpcb->connection_list;	
  while (tmp!=NULL){								
    printf("[descriptor %d,socket state %d,first %d,local address %s, remote address %s]",tmp->pcb->uid,tmp->pcb->sk->state,tmp->first,sprint_ip(tmp->pcb->sk->rcv_saddr),sprint_ip(tmp->pcb->sk->daddr));
    tmp = tmp->next;							
  }
}

void print_mpcb(struct multipath_pcb* mpcb){
  printf("MPCB tk_local %d tk_remote %d cnt_subflows %d ",mpcb->tk_local,mpcb->tk_remote,mpcb->cnt_subflows);
  print_sock_list(mpcb);
  printf("\n");
}

void add_ip_list(__u32* ptr,struct multipath_pcb* mpcb)
{
  int i;
  int aligned = 1;

  for (i = 0;i<mpcb->cnt_local_addr;i++){
    //    printf("Adding ");
    //    print_ip(mpcb->local_ips[i]);

    *ptr = htonl(mpcb->local_ips[i]);
    ptr ++;
  }
}

static int __init multipath_init(void) 
{
  int i;
  if ( (multipath_pcbs = init_hash_table(MTCP_HASH_SIZE)) == NULL ) 
	  return -1;
  
  
  if ( (token_pcbs = init_hash_table(MTCP_HASH_SIZE)) == NULL ) 
	  return -1;

  conn_no = 1;
  return 0;
}

static void __exit multipath_exit(void)
{
  destroy_hash_table(multipath_pcbs);
}

void push_flags(struct multipath_pcb* mpcb,int flag,int size){
  struct flag_stack* n = (struct flag_stack*)malloc(sizeof(struct flag_stack));

  BUG_ON(!n);  /*kmalloc failed*/

  n->flags = flag;
  n->bytes_left = size;
  n->next = mpcb->flags;
  mpcb->flags = n;
}

int pop_flags(struct multipath_pcb* mpcb){
  struct flag_stack* n;
  if (mpcb->flags==NULL){
    return -1;
  }
  n = mpcb->flags;
  mpcb->flags = mpcb->flags->next;
  free(n);
  
  return 0;
}

struct multipath_pcb* alloc_mpcb(){
  struct multipath_pcb * mpcb = (struct multipath_pcb*)malloc(sizeof(struct multipath_pcb));
	
  memset(mpcb,sizeof(struct multipath_pcb),0);

  skb_queue_head_init(&mpcb->receive_queue);
  skb_queue_head_init(&mpcb->write_queue);
  skb_queue_head_init(&mpcb->retransmit_queue);
  skb_queue_head_init(&mpcb->error_queue);
  skb_queue_head_init(&mpcb->out_of_order_queue);

  mpcb->write_buffer = (char*)malloc(sysctl_wmem_max);
  mpcb->wb_size = sysctl_wmem_max;
  mpcb->wb_start = 0;
  mpcb->wb_end = 0;
  mpcb->flags = NULL;

  //should do the timer only when we want to implement keep alive at connection level.
  //init_timer(&mpcb->timer);
  
  //init_waitqueue_head(&sleep);
  //need to init lock too. How?

  mpcb->rcvbuf = sysctl_rmem_default;
  mpcb->sndbuf = sysctl_wmem_default;
  
  mpcb->state = TCPF_CLOSE;
  
  mpcb->tk_local = conn_no++;
  insert_hash_entry(token_pcbs,mpcb->tk_local,mpcb);

  mpcb->tk_remote = -1;

  mpcb->subflow_id = 1;
  mpcb->connection_list = NULL;
  mpcb->cnt_subflows = 0;
  mpcb->cnt_established = 0;
  mpcb->syn_sent = 0;

  mpcb->cnt_local_addr = 0;
  mpcb->cnt_remote_addr = 0;

  mpcb->local_port = mpcb->remote_port = 0;
  mpcb->local_app_ip = mpcb->remote_app_ip = 0;
  
  //initial data seq no, should be random but zero will do for now
  mpcb->opt.write_seq = 0;
  mpcb->opt.snd_nxt = 0;
  mpcb->opt.snd_una = 0;

  mpcb->opt.rcv_nxt = 0;
  mpcb->opt.copied_seq = 0;

  mpcb->opt.rcv_wup = 0;
  mpcb->opt.rcv_wnd = 0;
  //  mpcb->opt.

  return mpcb;
}

void set_remote_token(struct multipath_pcb* mpcb, int tk){
  mpcb->tk_remote = tk;
}

struct multipath_pcb* lookup_mpcb(int s){
  return element_for_key(multipath_pcbs,s);
}

/*struct multipath_pcb* mpcb_from_sock(struct socket* sk){
  struct user_pcb* pcb = pcb_from_sock(sk);
  struct multipath_pcb* mpcb = element_for_key(multipath_pcbs,pcb->uid);
  return mpcb;
  }*/

struct multipath_pcb* mpcb_from_token(__u32 token){
  struct multipath_pcb* mpcb = element_for_key(token_pcbs,token);
  return mpcb;
}

subflow_t get_subflow(struct multipath_pcb* mpcb,struct socket* sk){
  subflow_t tmp = mpcb->connection_list;
  struct user_pcb* pcb = pcb_from_sock(sk);
  
  while (tmp!=NULL){
    if (tmp->pcb==pcb)
      return tmp;
    tmp = tmp->next;
  }
  return NULL;
}

/*struct sock* get_available_subflow_1(struct multipath_pcb* mpcb, int max_len){
	subflow_t tmp;
	struct tcp_opt* tp;

	while (1){
		tmp = mpcb->connection_list;			
		while (tmp!=NULL){
			tp = &(tmp->pcb->sk->tp_pinfo.af_tcp);
			
			if (tp->send_head==NULL){
			        int seq, end_seq,len;
			        len = tp->mss_cache>max_len?max_len:tp->mss_cache;
				seq = tp->write_seq;
				end_seq = tp->write_seq + len;
				if (tcp_snd_test_multipath(tmp->pcb->sk,len,end_seq))
					break;
			}			
			else {
			  //what about if send test is not null? Perhaps we are buffering waiting for more data, i.e. Nagle 
			  //we could end up stalling!
			  //copy data to connection skbuff & merge if possible with other data. I.e. high level nagle?
			  printf("get available subflow nagle check!\n");
			}
			tmp = tmp->next;
		}
		if (tmp!=NULL)
			break;
			
		else
		;//should wait here for events
	}
	return tmp->pcb->sk;
}
*/
//used for round robin of available subflows
int crt_no = 0;

int is_available(struct user_pcb* pcb, int max_len){
  return select_check(pcb->uid,POLLOUT) && slim_tcp_snd_test(pcb->sk,max_len);
}

struct sock* get_available_subflow(struct multipath_pcb* mpcb,int max_len,struct sock* avoid){
  struct tcp_opt* tp;
  subflow_t tmp = NULL;
  subflow_t ret;
  int choices = 0,crt_choice;
  int established = 0;
  int copy;
  
  tmp = mpcb->connection_list;
  
  while (tmp!=NULL){
    if (tcp_established(tmp->pcb->sk->state)){
      established ++;
      if (avoid!=tmp->pcb->sk &&
	  is_available(tmp->pcb,max_len))
	choices++;
    }
    tmp = tmp->next;
  }
  
  //printf("[est. %d choices %d total %d]",established,choices,mpcb->cnt_subflows);
  
  if (choices==0){
    //printf("No choices to send a packet on mpcb %x:",mpcb);
    //print_sock_list(mpcb);
    //printf("\n");
    return NULL;
  }
  

  tmp = mpcb->connection_list;
  choices = ++crt_no%choices;
  mpcb->cnt_established = established;

  crt_choice = 0;
  while (1){
    if (tmp==NULL)
      tmp = mpcb->connection_list;
    
    if (//tcp_established(tmp->pcb->sk->state) &&
	avoid!=tmp->pcb->sk &&
	is_available(tmp->pcb,max_len)&&crt_choice++==choices){
      //printf("Select %d",tmp->pcb->uid);
      return tmp->pcb->sk;
    }
    tmp = tmp->next;
  }
  
/*printf("Null after choice select in mpcb %x:",mpcb);
  print_sock_list(mpcb);
  printf("\n");*/
  //	return NULL;
  BUG_ON(1); /*Should never reach this point*/
}

static int check_state_exists(struct multipath_pcb* mpcb, int flags)
{
  subflow_t tmp;
  tmp = mpcb->connection_list;			
  while (tmp!=NULL){
    
    if ((1 << tmp->pcb->sk->state) & flags)
      return 1;
    
    tmp = tmp->next;			
  }
  return 0;
}

/*call only with lock held*/
int wait_for_mtcp_connect(struct multipath_pcb * mpcb, int flags)
{
  while(!check_state_exists(mpcb,(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))) {
    //if(sk->err)
    //  return sock_error(sk);
    //if((1 << sk->state) &
    // ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) { ... }
    if(flags & MSG_DONTWAIT)
      return -EAGAIN;
    if(signal_pending(current))
      return -ERESTARTSYS;
    
    mpcb->opt.write_pending++;
    printf("Multipath sleep\n");
    multipath_socket_sleep(mpcb);
    mpcb->opt.write_pending--;
  }
  return 0;
}

void reset_options(struct multipath_options* opt){
  opt->remote_token = -1;
  opt->local_token = -1;

  if (opt->ip_count>0){
    if (opt->ip_list){
      free(opt->ip_list);
      opt->ip_list = NULL;
    }
  }
  opt->ip_count = 0;
  opt->first = 0;

  //put data seq in cb?
  //  data_seq = -1;
}

void initialize_multipath_subflow(struct socket * sk){
  struct multipath_pcb* mpcb = mpcb_from_sock(sk);
  subflow_t subflow;
  
  BUG_ON(!mpcb); /*mpcv null in in_m_s*/

  if (mpcb->local_port == 0){
    mpcb->local_port = sk->sk->num;
    mpcb->remote_port = sk->sk->dport;
    mpcb->local_app_ip = sk->sk->rcv_saddr;
    mpcb->remote_app_ip = sk->sk->daddr;
  }

  if (mpcb->tk_remote<0)
    mpcb->tk_remote = mpcb->received_options.remote_token;
  else if (mpcb->tk_local!=mpcb->received_options.local_token){
    printf("Local token changed. Have %d received %d!",mpcb->tk_local,mpcb->received_options.local_token);
    BUG_ON(1);/*Should not reach that point*/
  }

  subflow = get_subflow(mpcb,sk);

  BUG_ON(!subflow); /*subflow null in i_m_s*/

  if (subflow->first){
    struct tcp_opt *tp = &(sk->sk->tp_pinfo.af_tcp);
    printf("Init wscale, clamp\n!");
    mpcb->opt.rcv_wscale = tp->rcv_wscale;
    mpcb->opt.snd_wscale = tp->snd_wscale;
    mpcb->opt.window_clamp = tp->window_clamp;
  }

  print_mpcb(mpcb);
}


void mpcb_inherit(struct multipath_pcb* listen,struct multipath_pcb* new){
  int i;

  new->cnt_local_addr = listen->cnt_local_addr;
  for (i = 0;i<new->cnt_local_addr;i++){
    new->local_ips[i] = listen->local_ips[i];
  }
}

void multipath_open_connections(struct multipath_pcb* mpcb){
  subflow_t existing;
  int i,j,found;
  struct user_pcb* pcb;
  struct sockaddr_in addr = {0};
  int sock = -1;
  //check all combinations
  //see if they are taken
  //...
  printf("Open connections for connection(%d,%d)\n",mpcb->cnt_local_addr,mpcb->cnt_remote_addr);

  for (i=0;i<mpcb->cnt_local_addr;i++)
    for (j=0;j<mpcb->cnt_remote_addr;j++){
      //find combination

      found = 0;
      for (existing = mpcb->connection_list;existing!=NULL;existing = existing->next){
	//closed!
	sock = existing->pcb->uid;
	if (mpcb->local_ips[i]==existing->pcb->sk->rcv_saddr&&
	    mpcb->remote_ips[j]==existing->pcb->sk->daddr){
	  found = 1;
	  break;
	}
      }

      if (found){
	if (existing->pcb->sk->daddr!=0||existing->pcb->sk->state!=7)
	  continue;

	//use existing bound socket!
	sock = existing->pcb->uid;
	addr.sin_family = AF_INET;
      }
      else {
	//create new socket
	addr.sin_addr.s_addr = mpcb->local_ips[i];
	addr.sin_port = 0;
	addr.sin_family = AF_INET;
	
	sock = user_socket(AF_INET,SOCK_STREAM,0);
	pcb = pcb_from_fd(sock);
	add_sock(mpcb,pcb);
	
	//      addr.sin_port        = htons(port);
	if (vanilla_bind(sock,&addr,sizeof(struct sockaddr_in))<0){
	  printf("Failed user bind!!!");
	}
      }

      //now connect
      addr.sin_addr.s_addr = mpcb->remote_ips[j];
      addr.sin_port = mpcb->remote_port;

      printf("Opening new connection %s - %s\n",sprint_ip(mpcb->local_ips[i]),sprint_ip(mpcb->remote_ips[j]));

      if (user_connect(sock,(struct sockaddr*)&addr,sizeof(struct sockaddr_in))<0){
	printf("Failed user connect!!!");
      }
    }
}

void multipath_save_remote_addr(struct multipath_pcb* mpcb){
  int i;

  if (!mpcb->received_options.ip_count){
    printf("ZERO ips rcvd");
  }
    
  mpcb->cnt_remote_addr = mpcb->received_options.ip_count;
  for (i=0;i<mpcb->received_options.ip_count;i++){
    mpcb->remote_ips[i] = mpcb->received_options.ip_list[i];
  }
}

int get_total_cwnd(struct multipath_pcb* mpcb){
  subflow_t tmp;
  int cwnd = 0;
  tmp = mpcb->connection_list;

  while (tmp!=NULL){
    struct tcp_opt * tp = &tmp->pcb->sk->tp_pinfo.af_tcp;
    //if (!tp->in_fast_recovery)
    {
      u32 FlightSize = (tp->snd_nxt - tp->snd_una)/tp->mss_cache;
      FlightSize = min(FlightSize, tcp_packets_in_flight(tp));

      cwnd += min(FlightSize, tp->snd_cwnd);
      //cwnd += tp->snd_cwnd;
    }
    //else
      //don't use inflated windows!
      //cwnd += tp->snd_ssthresh;
    tmp = tmp->next;			
  }
  //printf("CWND %d\n",cwnd);
  return cwnd;
}

int get_total_cwnd_simple(struct multipath_pcb* mpcb){
  subflow_t tmp;
  int cwnd = 0;
  tmp = mpcb->connection_list;

  while (tmp!=NULL){
    struct tcp_opt * tp = &tmp->pcb->sk->tp_pinfo.af_tcp;
    {
      cwnd += tp->snd_cwnd;
    }
    //else
      //don't use inflated windows!
      //cwnd += tp->snd_ssthresh;
    tmp = tmp->next;			
  }

  return cwnd;
}

module_init(multipath_init);
module_exit(multipath_exit);
MODULE_LICENSE("GPL");
