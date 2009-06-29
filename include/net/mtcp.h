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

/*Macro for activation/deactivation of debug messages*/

#undef PDEBUG
#ifdef CONFIG_MTCP_DEBUG
# define PDEBUG(fmt,args...) printk( KERN_DEBUG __FILE__ ": " fmt,##args)
#else
# define PDEBUG(fmt,args...)
#endif

/*hashtable Not used currently -- To delete ?*/
#define MTCP_HASH_SIZE                16
#define hash_fd(fd) \
	jhash_1word(fd,0)%MTCP_HASH_SIZE

struct multipath_options {
#ifdef CONFIG_MTCP_PM
	__u32    remote_token;
	__u32    local_token;
	__u8     ip_count;
	__u32*   ip_list;
	__u8     list_rcvd:1; /*1 if IP list has been received*/
#endif
	__u32    data_seq;
};

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
	/*socket count in this connection*/
	int                       cnt_subflows;    
	int                       syn_sent;
	int                       cnt_established;
	
	/*state, for faster tests in code*/
	int                       state;
	int                       err;
	
	char                      done;
	unsigned short            shutdown;
	

	struct multipath_options  received_options;
	struct tcp_options_received tcp_opt;

	__u32    write_seq;  /*data sequence number, counts the number of 
			       bytes the user has written so far */

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
	
	/*remember user flags*/
	struct flag_stack*        flags;
	uint8_t                   mtcp_flags;
#define MTCP_ACCEPT 0x1  /*the user socket is in accept mode
			   keep accept mode for subsockets
			   (that is, we don't make a connect)*/
	
	struct sk_buff_head       receive_queue;/*received data*/
	struct sk_buff_head       write_queue;/*sent stuff, waiting for ack*/
	struct sk_buff_head       retransmit_queue;/*need to rexmit*/
	struct sk_buff_head       error_queue;
	struct sk_buff_head       out_of_order_queue; /* Out of order segments 
							 go here */
	
	spinlock_t                lock;
	wait_queue_head_t         sleep;         /* Sock wait queue*/
	struct kref               kref;
	struct notifier_block     nb; /*For listening to PM events*/
};

#define mpcb_from_tcpsock(tp) (tp->mpcb)

struct multipath_pcb* mtcp_alloc_mpcb(void);
void mtcp_add_sock(struct multipath_pcb *mpcb,struct tcp_sock *tp);
struct multipath_pcb* mtcp_lookup_mpcb(int sd);
void mtcp_reset_options(struct multipath_options* mopt);
void mtcp_update_metasocket(struct sock *sock);
int mtcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size);
int mtcpv6_init(void);


#endif /*_MTCP_H*/
