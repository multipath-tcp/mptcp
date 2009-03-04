/******************************************************************************
 * socketcall.c
 * 
 * BSD sockets interface to TCP/IP stack, modified to allow binding on multiple interfaces
 * 
 * Copyright (c) 1999-2000, K A Fraser
 * 
 * $Id: socketcall.c,v 1.2 2003/03/24 18:46:17 echu Exp $
 *
 */
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include "thread.h"
#include "private.h"

#include <sys/mman.h>
#include <sys/time.h>
//#include <sched.h>
#include "nd.h"
hash_table_t   *pcbs = NULL;

#include "defines.h"

#include "libusernet.h"
#include "multipath.h"

#undef printf
#undef fprintf

//#include "lowlevel.h"
#include "af_user.h"

// Begin Manpreet... 
//#define NO_THREADS
extern void init_aggregate(void); 
extern int tp_count; 
extern int icmp_quench_count[100]; 
extern int clear_fast_retrans_count[100]; 
extern int fast_retransmit_count[100]; 
extern int snd_test_count[100];
// End Manpreet... 


short select_check(int fd, short events);

#define SOCKET_FD_BASE 512

/******************************************************************************
 * If given condition is false, quit with given error.
 */
#define ERROR_CHECK(_cond, _errnum, _errstr)                         \
    if( !(_cond) ) {                                                 \
        DB_ERR(_errstr "(errno str: %s)", strerror(_errnum));        \
        errno = (_errnum);                                           \
        return(-1);                                                  \
    }
#define FERROR_CHECK(_cond, _errnum, _errstr)                        \
    if( !(_cond) ) {                                                 \
        printf(_errstr "(errno str: %s)", strerror(_errnum));       \
        errno = (_errnum);                                           \
        return(-1);                                                  \
    }

/******************************************************************************
 * Get pcb associated with socket, and lock it for exclusive access.
 */
#define PCB_FROM_FD(_s, _pcb)                                        \
    if ( (_pcb = element_for_key(pcbs, _s)) == NULL )                \
    { errno = EBADF; return(-1); }

struct user_pcb* pcb_from_fd(int _s){
  return element_for_key(pcbs,_s);
}
    
/******************************************************************************
 * Unique identifier for next connection we create.
 */
int next_connection_id = SOCKET_FD_BASE;
/* used connection id table -P2 */
int conn_in_use[1024];

/* XXX KAF -- test vars */
unsigned int histogram[NUM_BUCKETS];

/* Wen -- indicate when user_kill has already been called */
unsigned char already_killed = 0;

/* Nice fast gettimeofday(). However, it may be up to 10ms behind wall clock */
struct { unsigned long volatile *jiffies; struct timeval *tv; } tmaps;
unsigned long myjiffies;
struct timeval myxtime;
struct timeval begining_of_time;
int fast_gettimeofday(struct timeval *__tv, struct timezone *__tz)
{
    *__tv = *tmaps.tv; return(0);
}

/******************************************************************************
 * user_init:
 *   Initialises the protocol stack. Should be called at start-of-day and
 *   never called again!
 */
int initialised = 0;

static void clearup(void) { user_kill(); }
static void *clearup_and_exit(void *arg) { user_kill(); exit(0);}

#ifdef USE_PTH
pthread_t death_thread;
#endif

static void sigint_handler(int ignored) 
{ 
#ifdef USE_PTH
    pthread_create(&death_thread, NULL, clearup_and_exit, NULL);
#endif
}

extern struct net_device** ultcp_interface;
extern char ultcp_cnt;

extern void handleAlarm(int t);

void user_init(void)
{
#ifdef USE_PTH
    struct sigaction act;
#endif

    struct itimerval timer;
    int res, i;

    // Begin Manpreet. 

    int temp; 

    //    printf("\nGoing to initialize aggregate from socketcall.c... ATCP is defined !!!\n\n"); 
    //    init_aggregate(); 
    
    srand(time(NULL));
    
    /*    
	  tp_count = 0; 
	  for (temp=0; temp<100; temp++){
	  icmp_quench_count[temp] = 0; 
	  clear_fast_retrans_count[temp] = 0; 
	  fast_retransmit_count[temp] = 0; 
	  snd_test_count[temp] = 0; 
	  }
    */

    // End Manpreet 

    if ( !test_and_set_bit(0, &initialised) )
    {
        /* The first thing we do is get the timer mappings! */
	/* Oh no you don't :-) We now implement timers in user-space - P2 */ 

	// ensure everytime we access the tmaps data struct, 
	// we get the right guys
	tmaps.jiffies = &(myjiffies);
	tmaps.tv = &(myxtime);

	// setup the signal handler
	timer.it_interval.tv_usec = 10000;
	timer.it_interval.tv_sec = 0;

	timer.it_value.tv_usec = 10000;
	timer.it_value.tv_sec = 0;

	myjiffies = 0;
	myxtime.tv_sec = myxtime.tv_usec = 0;
	if ((res = gettimeofday(&begining_of_time,NULL)) != 0) {
	    perror("gettimeofday");
	    exit(2);
	}

	signal(SIGALRM, handleAlarm);

	// flag all socket conn ids unused -P2
	for (i=0;i<SOCKET_FD_BASE;i++)
		conn_in_use[i] = 1;
	
	for (i=SOCKET_FD_BASE; i<1024; i++)
		conn_in_use[i] = 0;

	// let it rip ...
	if((res = setitimer(ITIMER_REAL, &timer, 0)) != 0) {
	    perror("setitimer");
	    exit(2);
	}

/*
        {
            FILE *f = fopen("/proc/afuser_tmap", "rb");
            if ( !f || (fread(&tmaps, 1, sizeof(tmaps), f) != sizeof(tmaps)) ||
                 !tmaps.jiffies || !tmaps.tv )
            {
                fprintf(stderr, "Could not read from /proc/afuser_tmap\n");
                fprintf(stderr, "Are the required kernel modules installed?\n");
                exit(1);
            }
            fclose(f);
        }
*/

#ifdef USE_PTH
        if ( !pth_init() )
        {
            fprintf(stderr, "FATAL ERROR initialising thread scheduler\n");
            exit(1);
        }
#endif 

        TRC_INIT();
        PROF_INIT();
        //next_connection_id = SOCKET_FD_BASE; now we look for it in the array - P2
        if ( (pcbs = init_hash_table(16)) == NULL ) exit(1);

        multipath_init();
        
#ifndef NO_THREADS
	init_upcalls();
#endif
        inet_proto_init(NULL);

        if ( !test_and_set_bit(1, &initialised) ) atexit(clearup);

#ifdef USE_PTH
        /* Register signal handlers for proper cleanup. */
        act.sa_handler = sigint_handler;
        sigemptyset(&act.sa_mask);
        act.sa_flags = 0;
	
        //sigaction(SIGINT, &act, NULL);
#endif
    }
}


/******************************************************************************
 * user_kill:
 *   Kills the protocol stack.
 */
void user_kill(void)
{
    int i;
    struct user_pcb *pcb;

    if ( test_and_clear_bit(0, &initialised) )
    {
        /* Force every connection to start closing down. NB. This code sucks.*/
        for ( i = SOCKET_FD_BASE; i < 1024; i++ ) 
	    if (conn_in_use[i])
		user_close(i);

        /* Wait for all connections to go away. */
        //wait_for_usd_conns_to_close(); - P2

        /* This guarantees us that the stack is inactive. */
        kill_upcalls();

        /* Noone will attempt to access hash table now -- time to kill it. */
        destroy_hash_table(pcbs);
        
        multipath_destroy();

        /* Now we knock the stack itself on the head. */
        inet_proto_shutdown();
        PROF_CLOSE();
        TRC_CLOSE();
#ifdef USE_PTH
        pth_kill();
#endif
        already_killed = 1;
    }
    else
    {
        /*
         * Should still wait for all connections to go away, or caller may
         * simply exit() as soon as we return!
         */
        // wait_for_usd_conns_to_close(); - P2
    }
}


/******************************************************************************
 * create_new_socket:
 *   Allocates a new pcb for a connection of <type>.
 *
 *   NOTE: No connection to the NIC is made until listen() or connect() is
 *   called. Also, this function does not call into the stack core: it is
 *   up to the caller to do inet_create().
 */
struct u_socket *create_new_socket(int type)
{
    struct user_pcb *pcb;
    caddr_t          buf;
    int              ret, i;
    struct u_proto *prot;

    DB("entered");

    if ( (pcb = malloc(sizeof(struct user_pcb))) == NULL ) 
	{
		fprintf(stderr," Out of memory, malloc failed in create_new_socket \n");
		exit(-1);
		return(NULL);
	}

    memset(pcb, 0, sizeof(struct user_pcb));
    
/* We do not create any connection in the card */
/* and we do not setup shared memory with the card - P2 */
#if 0
    if ( (pcb->usd_conn = usd_setup_device_connection(type, getpid(), pcb)) 
         == NULL )
    {
        DB_ERR("leaving, could not create connection to usd device");
        goto e3;
    }
    pcb->uid = next_connection_id++;

    if ( usd_get_shared_data_area(pcb->usd_conn, &pcb->shared_data_area) <
         SHARED_DATA_SIZE )
    {
        DB_ERR("leaving, insufficient shared data area");
        errno = ENOMEM;
        goto e2;
    }
#endif

/* instead, we allocate a buffer to mimic the "shared data area" */
/* setup with the card - P2 */
/*
not doing this because there is a single, global AF_USER socket
called "tcp_socket" created at tcp initialization time. we will
use that as our control socket. - P2
    if ( (pcb->usd_conn = socket(AF_USER, SOCK_STREAM, 0)) < 0 )
    {   
        fprintf(stderr, "leaving, could not create socket");
	fflush(stdout);
        goto e2;
    }
*/
    pcb->shared_data_area = (caddr_t)malloc(SHARED_DATA_SIZE); //AF_USER
	if (pcb->shared_data_area == NULL)
		{ free(pcb);            /* DMF */
		fprintf(stderr," Out of memory, malloc failed in create_new_socket \n");
		exit(-1);
		  return(NULL);       /* DMF*/
		}

    // look for the next available id, this is slow -P2
    for (i=SOCKET_FD_BASE;i<1024;i++)
	if (!conn_in_use[i]) break;
    if (i==1024) {
	fprintf(stderr,"OUT OF AVAILABLE SOCKET FDS ! \n");
	user_kill(); 
	exit(1);
    }
    conn_in_use[i] = 1;
    pcb->uid = i;
    // pcb->uid = next_connection_id++;

    if ( init_locked_tx_mem(pcb, 
                            BUFFERS_PER_RING, 
                            MAX_HEADER_LEN, 
                            pcb->shared_data_area + TX_HEADER,
                            TCP_FIFO_SIZE + TCP_FIFO_GRANULARITY,
                            pcb->shared_data_area + TX_DATA) < 0 )
    {
        FDB_ERR("leaving, no skbuff memory");
        goto e2;
    }
    
    /* Setup pcb here */
    pcb->type = type;

    /* Socket setup -- massively cutdown version of code from socket.c */
    pcb->sock.type = pcb->type;
    init_waitqueue_head(&(pcb->sock.wait));

    FDB("leaving, succeeded");
    return(&(pcb->sock));

    /*
     * Clean up what has been created when an error occurs.
     */
e2: //usd_close_device_connection(pcb->usd_conn); - P2
    free(pcb->shared_data_area);
e3: free(pcb);
    return(NULL);
}


/******************************************************************************
 * free_socket:
 *   Reverses the good work of 'create_new_socket'.
 */
void free_socket(struct u_socket *sock)
{
    struct user_pcb *pcb = PCB_FROM_SOCKET(sock);
    // they close the socket opened for this usd. we use a single raw sock for all conns. - P2
    //usd_close_device_connection(pcb->usd_conn); 
	if(pcb->shared_data_area != NULL) /* DMF*/
		free(pcb->shared_data_area); /* DMF */
    free(pcb);
}


/******************************************************************************
 * bind_new_socket:
 *   Binds <sock> to the local address <saddr>:<sport> which should be
 *   specified in NETWORK BYTE ORDER.
 *
 *   NOTE: It is the caller's responsibility to do inet_bind() -- this call
 *   simply calls into the NIC interface code and sets up a local filter.
 */
int bind_new_socket(struct u_socket *sock, u32 *saddr, u16 *sport)
{
    struct user_pcb *pcb = PCB_FROM_SOCKET(sock);
    struct sockaddr_in inaddr;

    inaddr.sin_family      = AF_INET;
    inaddr.sin_addr.s_addr = *saddr;
    inaddr.sin_port        = *sport;
/* We have no notion of connection with the card - P2 */
#if 0
    if ( usd_bind_to_local_address(pcb->usd_conn, &inaddr, NULL) )
    {
        FDB_ERR("leaving, could not bind to local address");
	return(-1);        
    }
#endif
    
    *saddr = inaddr.sin_addr.s_addr;
    *sport = inaddr.sin_port;
    set_bit(STATE_LOCAL_BOUND, &(pcb->state));

    FDB("bound to %d.%d.%d.%d:%d",
        *saddr&0xff, (*saddr>>8)&0xff, (*saddr>>16)&0xff, (*saddr>>24)&0xff, 
        ntohs(*sport));
        
    return(0);
}


/******************************************************************************
 * connect_new_socket:
 *   Connects <sock> to the remote address <daddr>:<dport> which should be
 *   specified in NETWORK BYTE ORDER.
 *
 *   NOTE: It is the caller's responsibility to do inet_connect() -- this
 *   call simply calls into the NIC interface code and sets up a local
 *   filter for the given remote address.
 */
int connect_new_socket(struct u_socket *sock, u32 daddr, u16 dport)
{
    struct user_pcb *pcb = PCB_FROM_SOCKET(sock);
    struct sockaddr_in inaddr;
    int i;

    inaddr.sin_family      = AF_INET;
    inaddr.sin_addr.s_addr = daddr;
    inaddr.sin_port        = dport;
/* We have no notion of connection with the card - P2 */
#if 0
    if ( usd_connect_to_remote_address(pcb->usd_conn, &inaddr) )
    {
	FDB_ERR("leaving, failed to connect to remote address");
	return(-1);
    }
#endif
/* This will be done by our whatever-card's driver - P2 */
#if 0
    /* Immediately after connecting, we set up the rx ring. */
    for ( i = 0; i < BUFFERS_PER_RING; i++ )
    {
#ifndef HDR_SPLIT
        usd_add_to_rx_queue(pcb->usd_conn, 
                            pcb->shared_data_area + RX_DATA + 2 + 4 +  
                            i * BYTES_PER_BUFFER,
                            BYTES_PER_BUFFER, TRUE);
#else
        usd_add_hdr_to_rx_queue(pcb->usd_conn,
                                pcb->shared_data_area + RX_HEADER + 2 +
                                i * MAX_HEADER_LEN,
                                MAX_HEADER_LEN);
        usd_add_data_to_rx_queue(pcb->usd_conn,
                                 pcb->shared_data_area + RX_DATA +
                                 i * BYTES_PER_BUFFER,
                                 BYTES_PER_BUFFER, TRUE);
#endif
    }
    usd_push_new_rx_bufs_to_nic(pcb->usd_conn);
#ifndef HDR_SPLIT
    usd_rx_req_callback(pcb->usd_conn, 1);
#else
    usd_rx_req_callback(pcb->usd_conn, 2);
#endif
    usd_tx_req_callback(pcb->usd_conn, 1);
#endif 

/* We have no filters in the card - P2 */
#if 0
    if ( usd_enable_connection_filtering(pcb->usd_conn) ) return(-1);
#endif

    set_bit(STATE_CONNECTED, &(pcb->state));

    FDB("connected to %d.%d.%d.%d:%d",
        daddr&0xff, (daddr>>8)&0xff,
        (daddr>>16)&0xff, (daddr>>24)&0xff, ntohs(dport));

    return(0);
}


/******************************************************************************
 * bind_and_connect_new_socket:
 *   Does the work of 'bind_new_socket' and 'connect_new_socket', all in
 *   one neat package! This is only called from within the Linux stack, to
 *   create a new active connection from a listener.
 */
int bind_and_connect_new_socket(struct u_socket *sock, 
                                u32 saddr, 
                                u16 sport, 
                                u32 daddr, 
                                u16 dport)
{
    int ret;
    
    if ( (ret = bind_new_socket(sock, &saddr, &sport)) < 0 ) return(ret);

    return(connect_new_socket(sock, daddr, dport));
}


int user_accept(int s_orig, void *addr, int *addrlen)
{
    struct user_pcb *pcb;
    struct user_pcb *newpcb;
    struct u_socket *newsock;
    struct sockaddr_in *inaddr = addr;
    struct multipath_pcb* mpcb;
    int s;
    subflow_t tmp;
    int err;
    int listen = 0, ready = 0;
    
    DB("entered");

    FERROR_CHECK(*addrlen >= sizeof(struct sockaddr_in),
		 EFAULT, "leaving, failed");

    mpcb = lookup_mpcb(s_orig);
    if (!mpcb) {
      printf("NULL mpcb in accept!");exit(1);
    }

    tmp = mpcb->connection_list;

    while (tmp){
      if (already_killed) return -1; 

      s = tmp->pcb->uid;
      PCB_FROM_FD(s, pcb);

      if (pcb->type==SOCK_STREAM && test_bit(STATE_LISTENING, &pcb->state)){
	listen++;
	if (select_check(s,POLLIN)){
	  ready ++;
	  break;
	}
      }
      tmp = tmp->next;
    }

    if (ready==0){
      if (listen==0){
	printf("Called listen on sockets not listening!");
	return -1;
      }
      return -EAGAIN;
    }

                 
    if ( (err = inet_accept(&(pcb->sock), &newsock, pcb->fcntl_flags)) < 0 )
    {
        FDB_ERR("user_accept() failed: %d (%s)", -err, strerror(-err));
        return(-1);
    }
    newpcb = PCB_FROM_SOCKET(newsock);

    if ( !insert_hash_entry(pcbs, newpcb->uid, newpcb) )
    {
        errno = ENOMEM;
        FDB_ERR("leaving, couldn't add socket to hash table");
        inet_release(&(newpcb->sock));
        return(-1);
    }

    inaddr->sin_family      = AF_INET;
    inaddr->sin_addr.s_addr = newpcb->sk->daddr;
    inaddr->sin_port        = newpcb->sk->dport;

    FDB("leaving, succeeded");
    return(newpcb->uid);
}


int vanilla_bind(int s, struct sockaddr_in* inaddr, int addrlen){
  struct user_pcb* pcb;
  int err;

  PCB_FROM_FD(s,pcb);

  FERROR_CHECK(addrlen >= sizeof(struct sockaddr_in), 
	       EFAULT, "leaving, bad addrlen");
  FERROR_CHECK(inaddr->sin_family == AF_INET, 
	       EINVAL, "leaving, address family must be AF_INET");
  FERROR_CHECK(!test_and_set_bit(STATE_LOCAL_BOUND, &(pcb->state)), 
	       EINVAL, "leaving, already bound");

  if ( bind_new_socket(&(pcb->sock), 
		       &(inaddr->sin_addr.s_addr), 
		       &(inaddr->sin_port)) < 0 ){
    clear_bit(STATE_LOCAL_BOUND, &(pcb->state));
    printf("bind_new_socket failed, error %d: %s", 
	   errno, strerror(errno));
    
	return(-1);
  }
  
  if ( (err = inet_bind(&(pcb->sock), 
			(struct sockaddr *)inaddr, 
			sizeof(struct sockaddr_in))) < 0 ){
    clear_bit(STATE_LOCAL_BOUND, &(pcb->state));
    printf("inet_bind failed, error %d: %s", -err, strerror(-err));
    errno = -err;
    return(-1);
  }
  
  if (inaddr->sin_port){
    filter_local(ntohs(inaddr->sin_port),inaddr->sin_addr.s_addr);
    //printf("Listen on %s:%d\n",sprint_ip(inaddr->sin_addr.s_addr),ntohs(inaddr->sin_port));
  }
  else if (pcb->sk->num) {
    filter_local(pcb->sk->num,inaddr->sin_addr.s_addr);
  }

  return 0;
}

int user_bind(int s_orig, const void *addr, int  addrlen)
{
    struct user_pcb      *pcb;
    int s = s_orig;
    struct multipath_pcb *mpcb;
    struct sockaddr_in    inaddr;
    struct sockaddr_in    ouraddr;
    int                   ouraddrlen, err;
    int sock_cnt,i;

    DB("entered");
    
    if (already_killed) return -1;

//multipath check if we have a multipath entry for this socket already; if so, create new socket and bind it.
//if not, create a multipath pcb, and add this socket to it.

    mpcb = lookup_mpcb(s);
    
    PCB_FROM_FD(s, pcb);
    /* Copy address, as not supposed to modify. */
    memcpy(&inaddr, addr, sizeof(struct sockaddr_in));
    printf("Bind called for %s:%d\n",sprint_ip(inaddr.sin_addr.s_addr),ntohs(inaddr.sin_port));

    if (mpcb==NULL)
    {
        //just create mpcb and insert multipath entry for it; otherwise, create new socket and bind it.      
        mpcb = alloc_mpcb(s);
    }
    else if (inaddr.sin_addr.s_addr==0) {
      //should not complain here!
      printf("Bind called twice, but with no address!\n");
      exit(1);
    }
    else {
      s = user_socket(AF_INET,SOCK_STREAM,0);
      PCB_FROM_FD(s,pcb);
    }
    add_sock(mpcb,pcb);

    //should set sock opt to opt out of multipath!

    if (mpcb->cnt_local_addr==0&&inaddr.sin_addr.s_addr==0){
      if (ultcp_cnt==0){
	printf("Interface cnt is 0\n");
	exit(1);
      }
      for (i = 0;i<ultcp_cnt;i++){
	//add addr
	multipath_add_address(mpcb,ultcp_interface[i]->ip_addr);
      }
    }
    
    if (inaddr.sin_addr.s_addr!=0){
      //first look for this address
      int found = 0;
      for (i=0;i<mpcb->cnt_local_addr;i++)
	if (inaddr.sin_addr.s_addr==mpcb->local_ips[i]){
	  found = 1;
	  break;
	}
      if (!found)
	multipath_add_address(mpcb,inaddr.sin_addr.s_addr);
    }

    /*
     * Note that this will modify address and port if they haven't been
     * specified by caller (ie. set to zero).
     */

      //print_sock_list(mpcb);
      //printf("\n");
    return vanilla_bind(s,&inaddr,addrlen);
}


int user_connect(int s, void *addr, int addrlen)
{
    struct user_pcb    *pcb;
    struct multipath_pcb * mpcb;
    struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
    int                 err;
    subflow_t tmp;


    DB("entered");

    if (already_killed) return -1;
    
    //multipath: connect should only be called on first socket, i.e. the one that is explicit

    mpcb = lookup_mpcb(s);  
    PCB_FROM_FD(s, pcb);

    if (mpcb==NULL){
      struct sockaddr_in dummy_addr = {0};
      FDB("binding to default local address and port, i.e. first interface");
      dummy_addr.sin_family = AF_INET;
      dummy_addr.sin_addr.s_addr = ultcp_interface[0]->ip_addr;
      
      if ( user_bind(s, &dummy_addr, sizeof(struct sockaddr_in)) < 0 ){
	//	printf("4\n");	
	clear_bit(STATE_LOCAL_BOUND, &(pcb->state));
	clear_bit(STATE_CONNECTED,   &(pcb->state));
	return(-1);
      }

      mpcb = lookup_mpcb(s);

      if (mpcb==NULL){
	printf("mpcb null after user_bind");
	exit(1);
      }
    }

    FERROR_CHECK(addrlen == sizeof(struct sockaddr_in),
                 EFAULT, "leaving, bad addrlen");
    FERROR_CHECK(inaddr->sin_family == AF_INET,
                 EINVAL, "leaving, address family must be AF_INET");
    FERROR_CHECK(!(test_bit(STATE_LISTENING, &(pcb->state)) || 
                   test_and_set_bit(STATE_CONNECTED, &(pcb->state))),
                   EINVAL, "leaving, already bound/listening");

    if ( !test_bit(STATE_LOCAL_BOUND, &(pcb->state)) )
    {
      printf("MPath connect should be bound!\n");
      exit(1);
    }

    if ( connect_new_socket(&(pcb->sock), 
                            inaddr->sin_addr.s_addr, 
                            inaddr->sin_port) < 0 )
    {
        clear_bit(STATE_CONNECTED,   &(pcb->state));
        FDB_ERR("connect_new_socket failed, error %d; %s", 
                errno, strerror(errno));
        return(-1);
    } 

    //MULTIPATH connect all the sockets here!
    filter_remote(ntohs(inaddr->sin_port),0);    
    //add_listening_interface(mpcb,pcb);
    /*
    if (!mpcb->syn_sent){
      //create listening socket!
      //create listening sock
      printf("Local port is %d\n",pcb->sk->num);
      int orig_port = pcb->sk->num;
      int new_sock;
      struct sockaddr_in addr = {0};

      if ((new_sock = user_socket(AF_INET,SOCK_STREAM,0))<0){
	printf("Socket failed in user_connect\n");exit(1);	
      };
	
      addr.sin_addr.s_addr =  0;
      addr.sin_port = htons(orig_port);
      addr.sin_family = AF_INET;

      printf("Adding **listen all** socket on port %d\n",orig_port);

      if (user_bind(new_sock,(struct sockaddr*)&addr,sizeof(struct sockaddr_in))<0){
	printf("Bind failed in user_connect\n");exit(1);
      }

      if (user_listen(new_sock,5)<0){
	printf("Listen failed in user_connect\n");exit(1);
      }
      }*/


    if ( (err = ((pcb->type == SOCK_STREAM) ? 
                 inet_stream_connect : inet_dgram_connect)
          (&(pcb->sock), addr, sizeof(struct sockaddr_in), pcb->fcntl_flags)) < 0 )
    {
        clear_bit(STATE_CONNECTED,   &(pcb->state));
        FDB_ERR("inet_???_connect failed, error %d: %s",
                -err, strerror(-err));
        errno = -err;

	if (errno!=115){
	  printf("Error Connecting:%s\n",strerror(errno));
	  return(-1);
	}
    }
    return(0);
}

int user_getpeername(int s, void *addr, int *addrlen)
{
    struct user_pcb    *pcb;
    struct sockaddr_in *inaddr;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    FERROR_CHECK(pcb->state == STATE_CONNECTED, ENOTCONN, "leaving, not connected");
    FERROR_CHECK(addrlen && *addrlen >= sizeof(struct sockaddr_in),
                 EFAULT, "leaving, bad addrlen");

    inaddr   = (struct sockaddr_in *)addr;
    *addrlen = sizeof(struct sockaddr_in);

    inaddr->sin_family = AF_INET;
    /* pcb->sk->daddr and pcb->sk->dport are set in tcp_v4_connect or udp_connect */
    inaddr->sin_addr.s_addr = pcb->sk->daddr;
    inaddr->sin_port        = pcb->sk->dport;

    FDB("leaving, succeeded");
    return(0);
}

int user_getsockname(int s, void *addr, int *addrlen)
{
    struct user_pcb    *pcb;
    struct sockaddr_in *inaddr;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    FERROR_CHECK(pcb->state == STATE_CONNECTED, ENOTCONN, "leaving, not connected");
    FERROR_CHECK(addrlen && *addrlen >= sizeof(struct sockaddr_in),
                 EFAULT, "leaving, bad addrlen");

    inaddr   = (struct sockaddr_in *)addr;
    *addrlen = sizeof(struct sockaddr_in);

    inaddr->sin_family = AF_INET;
    inaddr->sin_addr.s_addr = pcb->sk->rcv_saddr;
    inaddr->sin_port        = pcb->sk->sport;

    FDB("leaving, succeeded");
    return(0);
}

int user_getsockopt(int s, int level, int optname, void *optval, int *optlen)
{
    struct user_pcb    *pcb;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    if (level == SOL_SOCKET)
      return sock_getsockopt(&(pcb->sock), level, optname, optval, optlen);
    else 
      return inet_getsockopt(&(pcb->sock), level, optname, optval, optlen);
}


int user_setsockopt(int s, int level, int optname, void *optval, int optlen)
{
    struct user_pcb    *pcb;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    if (level == SOL_SOCKET)
      return sock_setsockopt(&(pcb->sock), level, optname, optval, optlen);
    else 
      return inet_setsockopt(&(pcb->sock), level, optname, optval, optlen);
}

int user_listen(int s_orig, int backlog)
{
    struct user_pcb    *pcb;
    struct multipath_pcb* mpcb;
    subflow_t tmp;
    int                 i;
    int s = s_orig;

    DB("entered");

    if (already_killed) return -1;

    mpcb = lookup_mpcb(s_orig);
    if (mpcb==NULL){
      printf("NULL mpcb in listen!\n");
      exit(1);
    }

    //    while (tmp){
    //s = tmp->pcb->uid;


 again:
    PCB_FROM_FD(s, pcb);

      //unclear how to deal with errors in this case...
    FERROR_CHECK(pcb->type == SOCK_STREAM,
		   EOPNOTSUPP, "leaving, wrong sort of socket");
    FERROR_CHECK(test_bit(STATE_LOCAL_BOUND, &(pcb->state)) && 
		 !test_bit(STATE_CONNECTED, &(pcb->state)) &&
		   !test_and_set_bit(STATE_LISTENING, &(pcb->state)),
		   ENOTCONN, "leaving, unbound/listening/connected");

    if ( (i = inet_listen(&(pcb->sock), backlog)) < 0 )	{
      clear_bit(STATE_LISTENING, &(pcb->state));
      printf("inet_listen() failed, error %d: %s", -i, strerror(-i));
      errno = -i;
	return(-1);
    }

    /*if (pcb->sk->rcv_saddr!=0) {
      //create listening sock
      
	int orig_port = pcb->sk->num;
      struct sockaddr_in addr = {0};

      if ((s = user_socket(AF_INET,SOCK_STREAM,0))<0){
	printf("Socket failed in user_listen\n");exit(1);	
      };
	

      addr.sin_addr.s_addr =  0;
      addr.sin_port = htons(orig_port);
      addr.sin_family = AF_INET;

      printf("Adding **listen all** socket on port %d\n",orig_port);

      if (user_bind(s,(struct sockaddr*)&addr,sizeof(struct sockaddr_in))<0){
	printf("Bind failed in user_listen\n");exit(1);
	}

      goto again;
      }*/
    
      //tmp = tmp->next;
      //    }

//multipath listen on all sockets.

    //add stuff to local_ips and local_ports



/* We have no notion of connection with the card - P2 */
#if 0
    if ( usd_listen_for_incoming_connections(pcb->usd_conn, backlog) != 0 )
    {
        clear_bit(STATE_LISTENING, &(pcb->state));
	FDB_ERR("leaving, usd_listen failed");
	return(-1);
    }
#endif

/* This will be done by our whatever-card's driver - P2 */
#if 0
    /* Immediately after connecting, we set up the rx ring. */
    for ( i = 0; i < BUFFERS_PER_RING; i++ )
    {
#ifndef HDR_SPLIT
        usd_add_to_rx_queue(pcb->usd_conn, 
                            pcb->shared_data_area + RX_DATA + 2 + 4 +  
                            i * BYTES_PER_BUFFER,
                            BYTES_PER_BUFFER, TRUE);
#else
        usd_add_hdr_to_rx_queue(pcb->usd_conn,
                                pcb->shared_data_area + RX_HEADER + 2 +
                                i * MAX_HEADER_LEN,
                                MAX_HEADER_LEN);
        usd_add_data_to_rx_queue(pcb->usd_conn,
                                 pcb->shared_data_area + RX_DATA +
                                 i * BYTES_PER_BUFFER,
                                 BYTES_PER_BUFFER, TRUE);
#endif
    }
    usd_push_new_rx_bufs_to_nic(pcb->usd_conn);
#ifndef HDR_SPLIT
    usd_rx_req_callback(pcb->usd_conn, 1);
#else
    usd_rx_req_callback(pcb->usd_conn, 2);
#endif
    usd_tx_req_callback(pcb->usd_conn, 1);
#endif

/* We have no filters in the card - P2 */
#if 0
    if ( usd_enable_connection_filtering(pcb->usd_conn) ) return(-1);
#endif

    FDB("leaving, succeeded");
    return(0);
}


int user_shutdown(int s, volatile int how)
{
    int err;
    struct user_pcb    * volatile pcb;

    DB("entered");

    PCB_FROM_FD(s, pcb);

    if ( (err = inet_shutdown(&(pcb->sock), how)) < 0 )
    {
        FDB_WRN("inet_shutdown, %d: %s", -err, strerror(-err));
        errno = -err;
        return(-1);
    }

    clean_pcap_ipchains();
    FDB("leaving, succeeded");
    return(0);
}


int user_socket(int af, int type, int protocol)
{
    struct u_socket *sock;
    struct user_pcb *pcb;
    int              ret;

    DB("entered");

    if (already_killed) return -1;

    ERROR_CHECK(af == AF_INET, EINVAL, "incorrect address family");

    if ( (sock = create_new_socket(type)) == NULL )
    {
        DB_ERR("create_new_socket failed, error %d: %s", 
               errno, strerror(errno));
        return(-1);
    }
    pcb = PCB_FROM_SOCKET(sock);

    if ( (ret = inet_create(sock, protocol)) < 0 )
    {
        FDB_ERR("inet_create failed, error %d: %s", -ret, strerror(-ret));
        free_socket(sock);
        errno = -ret;
        return(-1);
    }

    /* All done setting up the pcb. Store it away in the global hash table. */
    if ( !insert_hash_entry(pcbs, pcb->uid, pcb) )
    {
	FDB_ERR("leaving, could not insert new socket in hash table");
        inet_release(sock);
        free_socket(sock);
	errno = ENOMEM;
	return(-1);
    }

    //should fcntl here!
    user_fcntl(pcb->uid, F_SETFL, O_NONBLOCK); // Make the socket non-blocking

    FDB("leaving, succeeded");
    return(pcb->uid);
}


int user_socketpair(int af, int type, int protocol, int sv[2])
{
    DB_ERR("operation not supported");
    errno = EOPNOTSUPP;
    return(-1);
}


int user_close(int s)
{
    int err;
    struct user_pcb    * volatile pcb;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    if ( test_and_set_bit(STATE_CLOSING, &(pcb->state)) ) return(0);

    if ( (err = inet_release(&(pcb->sock))) < 0 )
    {
        FDB_WRN("inet_release, %d: %s", -err, strerror(-err));
        errno = -err;
        return(-1);
    }

    /* Okay, user can longer use this socket. */
    conn_in_use[pcb->uid] = 0;
    remove_hash_entry(pcbs, pcb->uid);
/* - P2
    if ( pcb->usd_conn == NULL ) free(pcb); // only if not attached to NIC!
*/

    DB("leaving, succeeded");
    return(0);
}


int user_send(int s, void *msg, int len, int flags)
{
    int              err;
    struct iovec     iov;
    struct msghdr    msgh;
    struct user_pcb *pcb;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    iov.iov_base = msg;
    iov.iov_len  = len;

    msgh.msg_name       = NULL;
    msgh.msg_namelen    = 0;
    msgh.msg_control    = NULL;
    msgh.msg_controllen = 0;
    msgh.msg_iov        = &iov;
    msgh.msg_iovlen     = 1;
    msgh.msg_flags      = flags;

    if ( (err = inet_sendmsg(&(pcb->sock), &msgh, len, NULL)) < 0 )
    {
        FDB_ERR("inet_sendmsg, %d: %s", -err, strerror(-err));
        errno = -err;
        return(-1);
    }

#ifdef USE_PTH
    pth_yield(NULL);
#endif

    FDB("leaving, succeeded");
    if ( ++pcb->sends_since_downcall == PACKETS_PER_YIELD )
    {
        pcb->sends_since_downcall = 0;
#ifdef USE_PTH
        sched_yield();
#endif
    }
    return(err);
}


int user_recv(int s, void *msg, int len, int flags)
{
    struct iovec     iov;
    struct msghdr    msgh;
    int              err, i;
    char *buf = msg;
    struct user_pcb *pcb;

    DB("entered");

    if (already_killed) return -1;

    PCB_FROM_FD(s, pcb);

    iov.iov_base = msg;
    iov.iov_len  = len;
    
    msgh.msg_name       = NULL;
    msgh.msg_namelen    = 0;
    msgh.msg_control    = NULL;
    msgh.msg_controllen = 0;
    msgh.msg_iov        = &iov;
    msgh.msg_iovlen     = 1;
    msgh.msg_flags      = flags;

    if ( (err = inet_recvmsg(&(pcb->sock), &msgh, len, flags, NULL)) < 0 )
    {
        FDB_WRN("inet_recvmsg, %d: %s", -err, strerror(-err));
        errno = -err;
        return(-1);
    }
    FDB("leaving, succeeded");
    return(err);
}


/******************************************************************************
 * user_fcntl:
 *   Partially implemented descriptor-related hacks.
 */
int user_fcntl(int fd, int cmd, int arg)
{
    struct user_pcb * volatile pcb;
    int ret;

    DB("entered");
    if (already_killed) return -1;

    PCB_FROM_FD(fd, pcb);
    
    switch ( cmd )
    {
    case F_GETFL:
    {
        /*
         * GETFLAGS: get the current set of fcntl flags.
         */
        ret = pcb->fcntl_flags;
        break;
    }
    case F_SETFL:
    {
        /*
         * SETFLAGS: set the fcntl flags for this socket. Currently
         * supported: O_NONBLOCK.
         */
        pcb->fcntl_flags = arg;
	//printf("\nSetting flag inside fcntl to %d", arg); fflush(stdout); 
        ret = 0;
        break;
    }
    default:
    {
        /*
         * Nothing else supported as yet!
         */
        errno = EINVAL;
        FDB_ERR("invalid command %d", cmd);
        ret = -1;
        break;
    }
    }

    FDB("leaving, succeeded");
    return(ret);
}


/******************************************************************************
 * user_poll:
 *   Block on multiple sockets at the same time, waiting for work to do.
 */
#ifdef USE_PTH
pthread_mutex_t global_poll_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  global_poll_cond  = PTHREAD_COND_INITIALIZER;
#else
int global_poll_mutex; 
int global_poll_cond; 
#endif

/* Modified by Wen Xu
 * Quote: we just worry about TCP protocols for now, don't worry about timeout
 *   So I hard-coded tcp_poll here. If you want to change that, just try to
 *   call pcb->sk->proto->poll().
 * We are doing the work of do_pollfd() in fs/select.c here. We are in the
 * user space and no timeout so we skipped the things in sys_poll() and do_poll()
 * in the same file. If you want to implement timeout, you can consider wait on
 * the global_socket.
 */

/* defined in ipv4/tcp.c */
extern unsigned int tcp_poll(void * file, struct u_socket *sock, void *wait);

static long poll_check(struct pollfd *fdarray, unsigned long nfds)
{
    unsigned long  i;
    struct pollfd *fdent;
    struct user_pcb * volatile pcb;
    long ready_socks = -1;

    for ( i = 0, fdent = fdarray; i < nfds; i++, fdent++ )
    {
        if ( fdent->fd < 0 || fdent->revents == POLLNVAL )
        {
            DB("invalid socket %d", fdent->fd);
            continue;
        }
	if ( fdent->fd < SOCKET_FD_BASE )
	{
	    poll(fdent, 1, 0);
	    continue;
	}
        if ( (pcb = element_for_key(pcbs, fdent->fd)) == NULL )
        {
            DB("socket %d not in table, setting POLLNVAL", fdent->fd);
            fdent->revents = POLLNVAL;
            continue;
        }

        /*
         * NB. We don't bother locking the pcb as we change nothing. We can
         * be certain that the pcb won't disappear from underneath us, as
         * the global poll mutex is required to removbe a hash table entry.
         */
        switch ( pcb->type )
        {
        case SOCK_STREAM:
	  /* Currently file and wait argument of tcp_poll() is not used.
	     casting won't be a problem because only flags and sk member are used,
	     and sk member is really allocated as (struct sock *) rather than
	     (struct u_sock *)
	  */
	  fdent->revents = tcp_poll(NULL, &(pcb->sock), NULL);
	  break;
        case SOCK_DGRAM:
	  /* udp polling not supported */
	  DB("udp polling not supported for socket %d", fdent->fd);
	  fdent->revents = POLLNVAL;
	  break;
        default:
	  DB("socket %d not of supported type", fdent->fd);
	  fdent->revents = POLLNVAL;
	  continue;
        }
        if ( ready_socks == -1 ) ready_socks = 0;
        if ( fdent->revents ) ready_socks++;
    }

#ifdef USE_PTH
    pth_yield(NULL);
#endif

    /*
     * Caller should sleep only if there is work to wait for and nothing to
     * wake up for yet.
     */
    return(ready_socks);
}

int user_poll(struct pollfd *fdarray, unsigned long nfds, int timeout)
{
    unsigned long i;
    struct pollfd *fdent;
    struct user_pcb * volatile pcb;
    long ready;

    DB("entered");

    if (already_killed) return -1;

    /* XXX -- we don't support timeouts yet!!! */
//    ERROR_CHECK(timeout == INFTIM, EINVAL, "timeout not supported!");
    ERROR_CHECK(timeout == 0, EINVAL, "timeout not supported!");

    /* Clear out return bitmasks. */
    for ( i = 0, fdent = fdarray; i < nfds; i++, fdent++ ) fdent->revents = 0;

    /* Wait for work to return. */
    pthread_mutex_lock(&(global_poll_mutex));
/*
    WAIT_NO_PCB(ready = poll_check(fdarray, nfds), 
                global_poll_cond, 
                global_poll_mutex);
*/
    ready = poll_check(fdarray, nfds);
    pthread_mutex_unlock(&(global_poll_mutex));


    DB("leaving, succeeded");
    return((ready == -1) ? 0 : ready);
}

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
short select_check(int fd, short events)
{
    struct user_pcb * volatile pcb;

    if ( fd < SOCKET_FD_BASE ) {
        DB("invalid socket %d", fd);
        return (events == POLLNVAL);
    }
    if ( (pcb = element_for_key(pcbs, fd)) == NULL ) {
        DB("socket %d not in table, setting POLLNVAL", fdent->fd);
	return (events == POLLNVAL);
    }

#ifdef USE_PTH
    pth_yield(NULL);
#endif

    /*
     * NB. We don't bother locking the pcb as we change nothing. We can
     * be certain that the pcb won't disappear from underneath us, as
     * the global poll mutex is required to removbe a hash table entry.
     */
    switch ( pcb->type ) {
    case SOCK_STREAM:
      /* Currently file and wait argument of tcp_poll() is not used.
         casting won't be a problem because only flags and sk member are used,
         and sk member is really allocated as (struct sock *) rather than
         (struct u_sock *)
       */
	  return (tcp_poll(NULL, &(pcb->sock), NULL) & events);
    case SOCK_DGRAM:
      /* udp polling not supported */
         DB("udp polling not supported for socket %d", fdent->fd);
         return (events == POLLNVAL);
    default:
         DB("socket %d not of supported type", fdent->fd);
         return (events == POLLNVAL);
    }
}

static void fdset_copy(fd_set *newfds, fd_set *oldfds, int low_fd, int high_fd)
{
    int i;

    if (oldfds == NULL)
      return;
    for (i=low_fd; i<high_fd; i++) {
      FD_CLR(i, newfds);
      if (FD_ISSET(i, oldfds))
        FD_SET(i, newfds);
    }
}

int user_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		struct timeval *timeout)
{
    int i, ready_socks = 0, largest_realfd;
    fd_set new_readfds, new_writefds, new_exceptfds;
    struct multipath_pcb* mpcb;
    subflow_t tmp = NULL;
    int ok;

    if (already_killed) return -1;

    if (n <= SOCKET_FD_BASE)
      return select(n, readfds, writefds, exceptfds, timeout);
    /* clear all socket fds and poll other fds through system */
/*    for (largest_realfd=SOCKET_FD_BASE-1; largest_realfd>=0; largest_realfd--)
      if ((readfds && FD_ISSET(largest_realfd, readfds))
          || (writefds && FD_ISSET(largest_realfd, writefds))
          || (exceptfds && FD_ISSET(largest_realfd, exceptfds)))
	break;
*/
    largest_realfd = SOCKET_FD_BASE-1;
    if (largest_realfd >= 0) {
      FD_ZERO(&new_readfds);
      FD_ZERO(&new_writefds);
      FD_ZERO(&new_exceptfds);
      if (readfds)
        fdset_copy(&new_readfds, readfds, 0, largest_realfd+1);
      if (writefds)
        fdset_copy(&new_writefds, writefds, 0, largest_realfd+1);
      if (exceptfds)
        fdset_copy(&new_exceptfds, exceptfds, 0, largest_realfd+1);
      ready_socks = select(largest_realfd+1, &new_readfds, &new_writefds,
                           &new_exceptfds, timeout);
    }
    for (i=n-1; i>=SOCKET_FD_BASE; i--) {

      if (readfds && FD_ISSET(i, readfds)) {
	mpcb = lookup_mpcb(i);
	if (mpcb==NULL){
	  printf("NULL MPCB in user_select!");
	  exit(1);
	}

	ok = 0;
	if ((mpcb->opt.rcv_nxt != mpcb->opt.copied_seq))
	  ok = 1;

	if (!ok){
	//iterate all the socks in this mpcb connection
	  tmp = mpcb->connection_list;
	  while (tmp!=NULL){
	    if (tmp->pcb->sk->state!=1&&select_check(tmp->pcb->uid,POLLIN)){
	      ok = 1;
	      break;
	    }
	    tmp = tmp->next;
	  }
	}

        if (ok)
	  ready_socks ++;
        else
          FD_CLR(i, readfds);
      }

      if (writefds && FD_ISSET(i, writefds)) {
	mpcb = lookup_mpcb(i);
	if (mpcb==NULL){
	  printf("NULL MPCB in user_select!");
	  exit(1);
	}

	//iterate all the socks in this mpcb connection
        tmp = mpcb->connection_list;
	ok = 0;
        while (tmp!=NULL){
	  if ( ((1 << tmp->pcb->sk->state) & 2) //is established?
	       && select_check(tmp->pcb->uid,POLLOUT)){
	    ok = 1;
	    break;
	  }
	  tmp = tmp->next;
        }

        if (ok)
	  ready_socks ++;
        else
          FD_CLR(i, writefds);
      }

      if (exceptfds && FD_ISSET(i, exceptfds)) {
        if (select_check(i, POLLNVAL))
	  ready_socks ++;
        else
          FD_CLR(i, exceptfds);
      }
    }
    if (largest_realfd >= 0) {
      if (readfds)
        fdset_copy(readfds, &new_readfds, 0, largest_realfd+1);
      if (writefds)
        fdset_copy(writefds, &new_writefds, 0, largest_realfd+1);
      if (exceptfds)
        fdset_copy(exceptfds, &new_exceptfds, 0, largest_realfd+1);
    }
    return ready_socks;
}

ssize_t user_read   (int s, void       *buf, size_t nbyte)
{
    if (already_killed) return -1;

    return user_recv(s, buf, nbyte, 0);
}

ssize_t user_write  (int s, const void *buf, size_t nbyte)
{
    if (already_killed) return -1;

    return user_send(s, buf, nbyte, 0);
}

#include <sys/uio.h>

ssize_t user_writev  (int s, const struct iovec *vector, int count)
{
    int i;
    ssize_t bytes_written = 0, total = 0;

    if (already_killed) return -1;

    if (vector == NULL)
      return -1;
    for (i=0; i<count; i++)
      if ((bytes_written = user_send(s, vector[i].iov_base, vector[i].iov_len,
                                     0)) < vector[i].iov_len) {
	if (bytes_written > 0)
          total += bytes_written;
        break;
      } else
      	total += bytes_written;
    if (bytes_written < 0)
      return -1;
    return total;
}

#define SENDFILE_BUFSIZE 2920

#include <sys/sendfile.h>
ssize_t  user_sendfile(int  out_fd,  int  in_fd, off_t *offset, size_t count)
{
/* first we have to check whether out_fd is a socket or in_fd is. :( Let's just
 * assume out_fd is while in_fd is not now
 */
  off_t orig_offset, newoffset;
  size_t sendsize, leftcount;
  ssize_t real_count;
  char *buf = (char *)malloc(SENDFILE_BUFSIZE);
  int result;

    if (already_killed) return -1;

  if (buf == NULL)
    return -1;

  if (orig_offset = lseek(in_fd, 0, SEEK_CUR)) {
    free(buf);
    return -1;
  }

  if (lseek(in_fd, *offset, SEEK_SET) < 0) {
    free(buf);
    return -1;
  }

  for (leftcount = count; leftcount > 0;) {
    if (leftcount > SENDFILE_BUFSIZE)
      sendsize = SENDFILE_BUFSIZE;
    else
      sendsize = leftcount;
    real_count = read(in_fd, buf, sendsize);
    real_count = user_send(out_fd, buf, real_count, 0);
    if (real_count > 0)
      leftcount -= real_count;
    if (real_count < sendsize)
      break;
  }
  lseek(in_fd, orig_offset, SEEK_SET);
  free(buf);
  return (count - leftcount);
}

