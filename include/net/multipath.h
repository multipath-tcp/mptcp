
#ifndef _MULTIPATH_H
#define _MULTIPATH_H

#define MAX_LOCAL_ADDR 5
#include "hash.h"

#ifndef _PRIVATE_H_
typedef struct mem_block_st mem_block_t;
struct mem_block_st { mem_block_t *next; };

/*MTCP Hash table size*/
#define MTCP_HASH_SIZE 16


struct user_pcb
{
    /* Miscellaneous state. */
    int uid;         /* Unique identifier for this socket.                */
    int type;        /* The type of socket that we are.                   */
    u32 state;       /* What state we are in.                             */
    int fcntl_flags; /* State returned/set by the `fcntl' interface call. */
    
    /* Information for our yielding algorithm. */
#define PACKETS_PER_YIELD 5
    int recvs_since_upcall;   /* Packets received by BH since call to TH. */
    int sends_since_downcall; /* Packets queued by TH since call to BH.   */

    /* Our view of the data path to the user-safe device. */
//    usd_device_conn_t *usd_conn; -P2
    int usd_conn; // control socket - P2
    caddr_t     shared_data_area;

    /* Our view of the Linux stack. */
    struct socket sock; /* connection to top    */
    struct sock *sk;    /* connection to bottom */

    /* Buffer management. */
    mem_block_t *tx_free_hdr_list;
    mem_block_t *tx_free_data_list; 
    struct sk_buff_head tx_queued_skbuffs;
};

#else
//#define u_sk_buff sk_buff
//#define u_sk_buff_head sk_buff_head
struct socket;
#endif

//struct sk_buff_head;
//struct sk_buff;
//struct sock;


typedef struct subflow* subflow_t;

struct multipath_options {
  __u32 remote_token;
  __u32 local_token;
  __u8 first;

  //ip list
  __u8 ip_count;
  __u32* ip_list;

  __u32 data_seq;
};

struct mtcp_opt {
  __u32	rcv_nxt;	/* What we want to receive next 	*/
  __u32	snd_nxt;	/* Next sequence we send		*/

  __u32	snd_una;	/* First byte we want an ack for	*/
  __u32	snd_wl1;	/* Sequence for window update		*/
  
  __u32	snd_wl2;	/* Ack sequence for update		*/
  __u32	snd_wnd;	/* The window we expect to receive	*/
    __u32	max_window;
  
  __u8	pending;	/* pending events			*/
  __u8	retransmits;
  __u32	last_ack_sent;	/* last ack we sent			*/
  
  __u32	backoff;	/* backoff				*/

  __u32	packets_out;	/* Packets which are "in flight"	*/
  
  __u16	user_mss;  	/* mss requested by user in ioctl */
  __u16	rcv_mss;  	
  __u16 mss_cache;

  __u32	rcv_wnd;	/* Current receiver window		*/
  __u32	rcv_wup;	/* rcv_nxt on last window update sent	*/

  __u8  snd_wscale;     /* Window scaling received from sender  */
  __u8  rcv_wscale;     /* Window scaling to send to receiver   */

  //data sequence number, counts the number of bytes the user has written so far
  __u32	write_seq;
  __u32	copied_seq;

  __u32       urg_seq;
  __u32       urg_data;

/*
 *      Options received (usually on last packet, some only on SYN packets).
 */

  __u32 old_ack; // The cumulative ack from previous time... 
  
//  struct timer_list*	probe_timer;		/* Probes	*/
  __u32	window_clamp;	/* XXX Document this... -DaveM		*/
  __u32	probes_out;	/* unanswered 0 window probes		*/
  __u32	last_seg_size;	/* Size of last incoming segment */
  
  int syn_backlog;	/* Backlog of received SYNs */
  int write_pending;
	
  unsigned int		keepalive_time;	  /* time before keep alive takes place */
  unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
  unsigned char  		keepalive_probes; /* num of allowed keep alive probes */
  
};

struct subflow {
  int local_id;
  int remote_id;
  int first;
  struct user_pcb* pcb;
  subflow_t next;
}; 

struct flag_stack {
  int flags;
  int bytes_left;
  struct flag_stack * next;
};

struct multipath_pcb {
  //receive and write queues

  //receive and send buffer sizing
  int rcvbuf, sndbuf;
  atomic_t rmem_alloc;

  __u8 cnt_local_addr,cnt_remote_addr;
  __u32 remote_ips[5], local_ips[5];

  //connection identifier!
  __u32 remote_app_ip, local_app_ip;
  __u16 remote_port,local_port;
  
  //list of sockets in this multipath connection
  subflow_t connection_list;
  //socket count in this connection
  int cnt_subflows;    
  int syn_sent;
  int cnt_established;
 
  //state, for faster tests in code
  int state;
  int err;

  char done;
  unsigned short shutdown;
  
  //tokens
  int tk_local, tk_remote,tk_connection;
  int subflow_id;
  
  struct multipath_options received_options;
  struct mtcp_opt opt;

  //user data, unpacketized
  char* write_buffer;
  //user data counters;
  int wb_size,wb_start,wb_end;

  //remember user flags
  struct flag_stack* flags;

#ifndef _PRIVATE_H_
  struct sk_buff_head receive_queue;//received data
  struct sk_buff_head write_queue;//sent stuff, waiting for ack
  struct sk_buff_head retransmit_queue;//need to rexmit
  struct sk_buff_head error_queue;
  struct sk_buff_head out_of_order_queue; /* Out of order segments go here */

  socket_lock_t lock;
  wait_queue_head_t   sleep;         /* Sock wait queue                 */    
#else
  struct u_sk_buff_head receive_queue;
  struct u_sk_buff_head write_queue;
  struct u_sk_buff_head retransmit_queue;//need to rexmit
  struct u_sk_buff_head error_queue;
  struct u_sk_buff_head out_of_order_queue; /* Out of order segments go here */
 
  u_socket_lock_t        lock;  /* Synchronizer...*/
  u_wait_queue_head_t   sleep;         /* Sock wait queue                 */    
#endif

  int guard[1000];
};

#define mpcb_from_sock(sk) (sk->mpcb)

#define multipath_wake_up(sk)              			\
        {							\
          struct multipath_pcb* t = mpcb_from_sock(sk);		\
		  if (t)  wake_up(t->sleep);					\
        }
        
#define multipath_socket_sleep(sk)	sock_sleep(sk)

struct multipath_pcb* alloc_mpcb();

void add_sock(struct multipath_pcb* mpcb, struct user_pcb* sock);
void multipath_add_address(struct multipath_pcb* mpcb, __u32 ip);
void mpcb_inherit(struct multipath_pcb* listen,struct multipath_pcb* new);
struct multipath_pcb* lookup_mpcb(int s);
//struct multipath_pcb* mpcb_from_sock(struct socket* sk);
struct multipath_pcb* mpcb_from_token(__u32 token);

void print_ip(int ip);
char* sprint_ip(__u32 ip);

subflow_t get_subflow(struct multipath_pcb* mpcb,struct socket* sk);
void print_sock_list(struct multipath_pcb* mpcb);
void print_mpcb(struct multipath_pcb* mpcb);
void add_ip_list(__u32* ptr,struct multipath_pcb* mpcb);
struct sock* get_available_subflow(struct multipath_pcb* mpcb,int max_seq, struct sock* avoid);

void initialize_multipath_subflow(struct socket* sk);
void multipath_open_connections(struct multipath_pcb* mpcb);
void multipath_save_remote_addr(struct multipath_pcb* mpcb);
//synchornization fns
int wait_for_mtcp_connect(struct multipath_pcb * mpcb, int flags);

int get_total_cwnd(struct multipath_pcb* mpcb);
int get_total_cwnd_simple(struct multipath_pcb* mpcb);

#endif /*_MULTIPATH_H*/
