/*
 *	MPTCP implementation
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _MPTCP_H
#define _MPTCP_H

#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/kernel.h>

#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <net/mptcp_pm.h>
#include <net/tcp.h>

#if defined(__LITTLE_ENDIAN_BITFIELD)
	#define ntohll(x)  be64_to_cpu(x)
	#define htonll(x)  cpu_to_be64(x)
#elif defined(__BIG_ENDIAN_BITFIELD)
	#define ntohll(x) (x)
	#define htonll(x) (x)
#endif

/* is seq1 < seq2 ? */
static inline int before64(const u64 seq1, const u64 seq2)
{
	return (s64)(seq1 - seq2) < 0;
}

/* is seq1 > seq2 ? */
#define after64(seq1, seq2)	before64(seq2, seq1)

struct mptcp_request_sock {
	struct tcp_request_sock		req;
	struct mptcp_cb			*mpcb;
	/* Collision list in the tuple hashtable. We need to find
	 * the req sock when receiving the third msg of the 3-way handshake,
	 * since that one does not contain the token. If this makes
	 * the request sock too long, we can use kmalloc'ed specific entries for
	 * that tuple hashtable. At the moment, though, I extend the
	 * request_sock.
	 */
	struct list_head		collide_tuple;
	struct hlist_nulls_node		collide_tk;
	u32				mptcp_rem_nonce;
	u32				mptcp_loc_token;
	u64				mptcp_loc_key;
	u64				mptcp_rem_key;
	u64				mptcp_hash_tmac;
	u32				mptcp_loc_nonce;
	__u8				rem_id; /* Address-id in the MP_JOIN */
	u8				dss_csum:1,
					low_prio:1;
};

static inline
struct mptcp_request_sock *mptcp_rsk(const struct request_sock *req)
{
	return (struct mptcp_request_sock *)req;
}

static inline
struct request_sock *rev_mptcp_rsk(const struct mptcp_request_sock *req)
{
	return (struct request_sock *)req;
}

struct mptcp_options_received {
	struct mptcp_cb *mpcb;
	u16	saw_mpc:1,
		dss_csum:1,

		is_mp_join:1,
		join_ack:1,

		saw_low_prio:2, /* 0x1 - low-prio set for this subflow
				 * 0x2 - low-prio set for another subflow
				 */
		low_prio:1,

		mp_fail:1,
		mp_fclose:1;
	u8	rem_id;		/* Address-id in the MP_JOIN */
	u8	prio_addr_id;	/* Address-id in the MP_PRIO */

	u32	mptcp_rem_token;/* Remote token */
	u64	mptcp_rem_key;	/* Remote key */

	u32	mptcp_recv_nonce;
	u64	mptcp_recv_tmac;
	u8	mptcp_recv_mac[20];
};

struct mptcp_tcp_sock {
	struct tcp_sock	*next;		/* Next subflow socket */
	struct mptcp_options_received rx_opt;

	 /* Those three fields record the current mapping */
	u64	map_data_seq;
	u32	map_subseq;
	u16	map_data_len;
	u16	slave_sk:1,
		fully_established:1,
		attached:1,
		csum_error:1,
		teardown:1,
		include_mpc:1,
		mapping_present:1,
		map_data_fin:1,
		low_prio:1, /* use this socket as backup */
		rcv_low_prio:1, /* Peer sent low-prio option to us */
		send_mp_prio:1, /* Trigger to send mp_prio on this socket */
		pre_established:1; /* State between sending 3rd ACK and receiving
		 	 	    * the fourth ack of new subflows.
		 	 	    */

	/* isn: needed to translate abs to relative subflow seqnums */
	u32	snt_isn;
	u32	rcv_isn;
	u32	last_data_seq;
	u8	path_index;
	u8	add_addr4; /* bit-field of addrs not yet sent to our peer */
	u8	add_addr6;
	u8	rem_id;

	u32	last_rbuf_opti;	/* Timestamp of last rbuf optimization */
	unsigned int sent_pkts;

	struct sk_buff  *shortcut_ofoqueue; /* Shortcut to the current modified
					     * skb in the ofo-queue.
					     */

	int	init_rcv_wnd;
	u32	infinite_cutoff_seq;
	struct delayed_work work;
	u32	mptcp_loc_nonce;
	struct tcp_sock *tp; /* Where is my daddy? */

	/* MP_JOIN subflow: timer for retransmitting the 3rd ack */
	struct timer_list mptcp_ack_timer;
};

struct mptcp_cb {
	struct sock *meta_sk;

	/* list of sockets in this multipath connection */
	struct tcp_sock *connection_list;

	/* High-order bits of 64-bit sequence numbers */
	u32 snd_high_order[2];
	u32 rcv_high_order[2];

	u16	send_infinite_mapping:1,
		list_rcvd:1, /* XXX TO REMOVE */
		dss_csum:1,
		server_side:1,
		infinite_mapping:1,
		send_mp_fail:1,
		dfin_combined:1,   /* Does the DFIN received was combined with a subflow-fin? */
		passive_close:1,
		snd_hiseq_index:1, /* Index in snd_high_order of snd_nxt */
		rcv_hiseq_index:1; /* Index in rcv_high_order of rcv_nxt */

	/* socket count in this connection */
	u8 cnt_subflows;
	u8 cnt_established;
	u8 last_pi_selected;

	u32 noneligible;	/* Path mask of temporarily non
				 * eligible subflows by the scheduler
				 */

	struct sk_buff_head reinject_queue;

	u16 remove_addrs;

	u8 dfin_path_index;
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;
	struct delayed_work subflow_retry_work;
	/* Worker to handle interface/address changes if socket is owned */
	struct work_struct address_work;
	/* Mutex needed, because otherwise mptcp_close will complain that the
	 * socket is owned by the user.
	 * E.g., mptcp_sub_close_wq is taking the meta-lock.
	 */
	struct mutex mutex;

	/* Master socket, also part of the connection_list, this
	 * socket is the one that the application sees.
	 */
	struct sock *master_sk;

	u64	csum_cutoff_seq;

	__u64	mptcp_loc_key;
	__u32	mptcp_loc_token;
	__u64	mptcp_rem_key;
	__u32	mptcp_rem_token;

	/* Create a new subflow - necessary because the meta-sk may be IPv4, but
	 * the new subflow can be IPv6
	 */
	struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst);

	/* Local addresses */
	struct mptcp_loc4 locaddr4[MPTCP_MAX_ADDR];
	u8 loc4_bits; /* Bitfield, indicating which of the above indexes are set */
	u8 next_v4_index;

	struct mptcp_loc6 locaddr6[MPTCP_MAX_ADDR];
	u8 loc6_bits;
	u8 next_v6_index;

	/* Remove addresses */
	struct mptcp_rem4 remaddr4[MPTCP_MAX_ADDR];
	u8 rem4_bits;

	struct mptcp_rem6 remaddr6[MPTCP_MAX_ADDR];
	u8 rem6_bits;

	u32 path_index_bits;
	/* Next pi to pick up in case a new path becomes available */
	u8 next_path_index;
};

static inline int mptcp_pi_to_flag(int pi)
{
	return 1 << (pi - 1);
}

#define MPTCP_SUB_CAPABLE			0
#define MPTCP_SUB_LEN_CAPABLE_SYN		12
#define MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN		12
#define MPTCP_SUB_LEN_CAPABLE_ACK		20
#define MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN		20

#define MPTCP_SUB_JOIN			1
#define MPTCP_SUB_LEN_JOIN_SYN		12
#define MPTCP_SUB_LEN_JOIN_SYN_ALIGN	12
#define MPTCP_SUB_LEN_JOIN_SYNACK	16
#define MPTCP_SUB_LEN_JOIN_SYNACK_ALIGN	16
#define MPTCP_SUB_LEN_JOIN_ACK		24
#define MPTCP_SUB_LEN_JOIN_ACK_ALIGN	24

#define MPTCP_SUB_DSS		2
#define MPTCP_SUB_LEN_DSS	4
#define MPTCP_SUB_LEN_DSS_ALIGN	4

/* Lengths for seq and ack are the ones without the generic MPTCP-option header,
 * as they are part of the DSS-option.
 * To get the total length, just add the different options together.
 */
#define MPTCP_SUB_LEN_SEQ	10
#define MPTCP_SUB_LEN_SEQ_CSUM	12
#define MPTCP_SUB_LEN_SEQ_ALIGN	12

#define MPTCP_SUB_LEN_SEQ_64		14
#define MPTCP_SUB_LEN_SEQ_CSUM_64	16
#define MPTCP_SUB_LEN_SEQ_64_ALIGN	16

#define MPTCP_SUB_LEN_ACK	4
#define MPTCP_SUB_LEN_ACK_ALIGN	4

#define MPTCP_SUB_LEN_ACK_64		8
#define MPTCP_SUB_LEN_ACK_64_ALIGN	8

/* This is the "default" option-length we will send out most often.
 * MPTCP DSS-header
 * 32-bit data sequence number
 * 32-bit data ack
 *
 * It is necessary to calculate the effective MSS we will be using when
 * sending data.
 */
#define MPTCP_SUB_LEN_DSM_ALIGN  MPTCP_SUB_LEN_DSS_ALIGN + 		\
				 MPTCP_SUB_LEN_SEQ_ALIGN + 		\
				 MPTCP_SUB_LEN_ACK_ALIGN

#define MPTCP_SUB_ADD_ADDR		3
#define MPTCP_SUB_LEN_ADD_ADDR4		8
#define MPTCP_SUB_LEN_ADD_ADDR6		20
#define MPTCP_SUB_LEN_ADD_ADDR4_ALIGN	8
#define MPTCP_SUB_LEN_ADD_ADDR6_ALIGN	20

#define MPTCP_SUB_REMOVE_ADDR	4
#define MPTCP_SUB_LEN_REMOVE_ADDR	4

#define MPTCP_SUB_PRIO		5
#define MPTCP_SUB_LEN_PRIO	3
#define MPTCP_SUB_LEN_PRIO_ADDR	4
#define MPTCP_SUB_LEN_PRIO_ALIGN	4

#define MPTCP_SUB_FAIL		6
#define MPTCP_SUB_LEN_FAIL	12
#define MPTCP_SUB_LEN_FAIL_ALIGN	12

#define MPTCP_SUB_FCLOSE	7
#define MPTCP_SUB_LEN_FCLOSE	12
#define MPTCP_SUB_LEN_FCLOSE_ALIGN	12


#define OPTION_MPTCP		(1 << 5)

#ifdef CONFIG_MPTCP

/* MPTCP options */
#define OPTION_TYPE_SYN		(1 << 0)
#define OPTION_TYPE_SYNACK	(1 << 1)
#define OPTION_TYPE_ACK		(1 << 2)
#define OPTION_MP_CAPABLE	(1 << 3)
#define OPTION_DATA_ACK		(1 << 4)
#define OPTION_ADD_ADDR		(1 << 5)
#define OPTION_MP_JOIN		(1 << 6)
#define OPTION_MP_FAIL		(1 << 7)
#define OPTION_MP_FCLOSE	(1 << 8)
#define OPTION_REMOVE_ADDR	(1 << 9)
#define OPTION_MP_PRIO		(1 << 10)

struct mptcp_option {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_capable {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
	__u8	s:1,
		rsv:6,
		c:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
	__u8	c:1,
		rsv:6,
		s:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u64	sender_key;
	__u64	receiver_key;
} __attribute__((__packed__));

struct mp_join {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:3,
		b:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
	union {
		struct {
			u32	token;
			u32	nonce;
		} syn;
		struct {
			__u64	mac;
			u32	nonce;
		} synack;
		struct {
			__u8	mac[20];
		} ack;
	} u;
} __attribute__((__packed__));

struct mp_dss {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		A:1,
		a:1,
		M:1,
		m:1,
		F:1,
		rsv2:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:3,
		F:1,
		m:1,
		M:1,
		a:1,
		A:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_add_addr {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ipver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ipver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
	union {
		struct {
			struct in_addr	addr;
			__be16		port;
		} v4;
		struct {
			struct in6_addr	addr;
			__be16		port;
		} v6;
	} u;
} __attribute__((__packed__));

struct mp_remove_addr {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	rsv:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	/* list of addr_id */
	__u8	addrs_id;
};

struct mp_fail {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be64	data_seq;
} __attribute__((__packed__));

struct mp_fclose {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u64	key;
} __attribute__((__packed__));

struct mp_prio {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:3,
		b:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
} __attribute__((__packed__));

static inline int mptcp_sub_len_remove_addr(u16 bitfield)
{
	unsigned int c;
	for (c = 0; bitfield; c++)
		bitfield &= bitfield - 1;
	return MPTCP_SUB_LEN_REMOVE_ADDR + c - 1;
}

static inline int mptcp_sub_len_remove_addr_align(u16 bitfield)
{
	return ALIGN(mptcp_sub_len_remove_addr(bitfield), 4);
}

static inline int mptcp_sub_len_dss(struct mp_dss *m, int csum)
{
	return 4 + m->A * (4 + m->a * 4) + m->M * (10  +m->m * 4 + csum * 2);
}

/* Default MSS for MPTCP
 * All subflows will be using that MSS. If any subflow has a lower MSS, it is
 * just not used. */
#define MPTCP_MSS 1400
#define MPTCP_SYN_RETRIES 3
extern int sysctl_mptcp_ndiffports;
extern int sysctl_mptcp_enabled;
extern int sysctl_mptcp_checksum;
extern int sysctl_mptcp_debug;
extern int sysctl_mptcp_syn_retries;

extern struct workqueue_struct *mptcp_wq;

#define mptcp_debug(fmt, args...)					\
	do {								\
		if (unlikely(sysctl_mptcp_debug))			\
			printk(KERN_DEBUG __FILE__ ": " fmt, ##args);	\
	} while (0)

/* Iterates over all subflows */
#define mptcp_for_each_tp(mpcb, tp)					\
	for ((tp) = (mpcb)->connection_list; (tp); (tp) = (tp)->mptcp->next)

#define mptcp_for_each_sk(mpcb, sk)					\
	for ((sk) = (struct sock *)(mpcb)->connection_list;		\
	     sk;							\
	     sk = (struct sock *) tcp_sk(sk)->mptcp->next)

#define mptcp_for_each_sk_safe(__mpcb, __sk, __temp)			\
	for (__sk = (struct sock *)(__mpcb)->connection_list,		\
		     __temp = __sk ? (struct sock *)tcp_sk(__sk)->mptcp->next : NULL; \
	     __sk;							\
	     __sk = __temp,						\
		     __temp = __sk ? (struct sock *)tcp_sk(__sk)->mptcp->next : NULL)

/* Iterates over all bit set to 1 in a bitset */
#define mptcp_for_each_bit_set(b, i)					\
	for (i = ffs(b) - 1; i >= 0; i = ffs(b >> (i + 1) << (i + 1)) - 1)

#define mptcp_for_each_bit_unset(b, i)					\
	mptcp_for_each_bit_set(~b, i)

void mptcp_data_ready(struct sock *sk, int bytes);
void mptcp_write_space(struct sock *sk);

void mptcp_add_meta_ofo_queue(struct sock *meta_sk, struct sk_buff *skb,
			      struct sock *sk);
void mptcp_ofo_queue(struct sock *meta_sk);
void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp);
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied);
int mptcp_alloc_mpcb(struct sock *master_sk, __u64 remote_key, u32 window);
int mptcp_add_sock(struct sock *meta_sk, struct sock *sk, u8 rem_id, gfp_t flags);
void mptcp_del_sock(struct sock *sk);
void mptcp_update_metasocket(struct sock *sock, struct sock *meta_sk);
void mptcp_reinject_data(struct sock *orig_sk, int clone_it);
void mptcp_update_sndbuf(struct mptcp_cb *mpcb);
struct sk_buff *mptcp_next_segment(struct sock *sk, int *reinject);
void mptcp_send_fin(struct sock *meta_sk);
void mptcp_send_reset(struct sock *sk, struct sk_buff *skb);
void mptcp_send_active_reset(struct sock *meta_sk, gfp_t priority);
int mptcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp);
void mptcp_parse_options(const uint8_t *ptr, int opsize,
			 struct tcp_options_received *opt_rx,
			 struct mptcp_options_received *mopt,
			 const struct sk_buff *skb);
void mptcp_syn_options(struct sock *sk, struct tcp_out_options *opts,
		       unsigned *remaining);
void mptcp_synack_options(struct request_sock *req,
			  struct tcp_out_options *opts,
			  unsigned *remaining);
void mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       struct tcp_out_options *opts, unsigned *size);
void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			 struct tcp_out_options *opts,
			 struct sk_buff *skb);
void mptcp_close(struct sock *meta_sk, long timeout);
int mptcp_doit(struct sock *sk);
int mptcp_create_master_sk(struct sock *meta_sk, __u64 remote_key, u32 window);
int mptcp_check_req_master(struct sock *sk, struct sock *child,
			   struct request_sock *req,
			   struct request_sock **prev,
			   struct mptcp_options_received *mopt);
struct sock *mptcp_check_req_child(struct sock *sk, struct sock *child,
		struct request_sock *req, struct request_sock **prev,
		struct mptcp_options_received *mopt);
u32 __mptcp_select_window(struct sock *sk);
void mptcp_select_initial_window(int *__space, __u32 *window_clamp,
			         const struct sock *sk);
unsigned int mptcp_current_mss(struct sock *meta_sk);
int mptcp_select_size(const struct sock *meta_sk);
int mptcp_data_ack(struct sock *sk, const struct sk_buff *skb);
void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn);
void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		     u32 *hash_out);
void mptcp_clean_rtx_infinite(struct sk_buff *skb, struct sock *sk);
void mptcp_fin(struct sock *meta_sk);
void mptcp_retransmit_timer(struct sock *meta_sk);
int mptcp_write_wakeup(struct sock *meta_sk);
void mptcp_sub_close_wq(struct work_struct *work);
void mptcp_sub_close(struct sock *sk, unsigned long delay);
struct sock *mptcp_select_ack_sock(const struct sock *meta_sk, int copied);
void mptcp_fallback_meta_sk(struct sock *meta_sk);
int mptcp_backlog_rcv(struct sock *meta_sk, struct sk_buff *skb);
struct sock *mptcp_sk_clone(const struct sock *sk, int family, const gfp_t priority);
struct sock *mptcp_sk_clone(const struct sock *sk, int family, const gfp_t priority);
void mptcp_ack_handler(unsigned long);
void mptcp_set_keepalive(struct sock *sk, int val);
int mptcp_check_rtt(const struct tcp_sock *tp, int time);
int mptcp_check_snd_buf(const struct tcp_sock *tp);

static inline void mptcp_push_pending_frames(struct sock *meta_sk)
{
	if (mptcp_next_segment(meta_sk, NULL)) {
		struct tcp_sock *tp = tcp_sk(meta_sk);

		__tcp_push_pending_frames(meta_sk, mptcp_current_mss(meta_sk), tp->nonagle);
	}
}

static inline void mptcp_sub_force_close(struct sock *sk)
{
	/* The below tcp_done may have freed the socket, if he is already dead.
	 * Thus, we are not allowed to access it afterwards. That's why
	 * we have to store the dead-state in this local variable.
	 */
	int sock_is_dead = sock_flag(sk, SOCK_DEAD);

	tcp_sk(sk)->mp_killed = 1;

	if (sk->sk_state != TCP_CLOSE)
		tcp_done(sk);

	if (!sock_is_dead)
		mptcp_sub_close(sk, 0);
}

static inline int mptcp_is_data_fin(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN;
}

static inline int mptcp_is_data_seq(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_SEQ;
}

static inline void mptcp_skb_entail_init(const struct tcp_sock *tp,
					 struct sk_buff *skb)
{
	if (tp->mpc)
		TCP_SKB_CB(skb)->mptcp_flags = MPTCPHDR_SEQ;
}

/* Sets the data_seq and returns pointer to the in-skb field of the data_seq.
 * If the packet has a 64-bit dseq, the pointer points to the last 32 bits.
 */
static inline __u32 *mptcp_skb_set_data_seq(const struct sk_buff *skb,
					    u32 *data_seq)
{
	__u32 *ptr = (__u32 *)(skb_transport_header(skb) + TCP_SKB_CB(skb)->dss_off);

	if (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_SEQ64_SET) {
		*data_seq = (u32)get_unaligned_be64(ptr);
		ptr++;
	} else {
		*data_seq = get_unaligned_be32(ptr);
	}

	return ptr;
}

static inline struct sock *mptcp_meta_sk(const struct sock *sk)
{
	return tcp_sk(sk)->meta_sk;
}

static inline struct tcp_sock *mptcp_meta_tp(const struct tcp_sock *tp)
{
	return tcp_sk(tp->meta_sk);
}

static inline int is_meta_tp(const struct tcp_sock *tp)
{
	return tp->mpcb && mptcp_meta_tp(tp) == tp;
}

static inline int is_meta_sk(const struct sock *sk)
{
	return sk->sk_type == SOCK_STREAM  && sk->sk_protocol == IPPROTO_TCP &&
	       tcp_sk(sk)->mpc && mptcp_meta_sk(sk) == sk;
}

static inline int is_master_tp(const struct tcp_sock *tp)
{
	return !tp->mpc || (!tp->mptcp->slave_sk && !is_meta_tp(tp));
}

static inline void mptcp_hash_request_remove(struct request_sock *req)
{
	int in_softirq = 0;

	if (list_empty(&mptcp_rsk(req)->collide_tuple))
		return;

	if (in_softirq()) {
		spin_lock(&mptcp_reqsk_hlock);
		in_softirq = 1;
	} else {
		spin_lock_bh(&mptcp_reqsk_hlock);
	}

	list_del(&mptcp_rsk(req)->collide_tuple);

	if (in_softirq)
		spin_unlock(&mptcp_reqsk_hlock);
	else
		spin_unlock_bh(&mptcp_reqsk_hlock);
}

static inline void mptcp_reqsk_destructor(struct request_sock *req)
{
	if (!mptcp_rsk(req)->mpcb) {
		if (hlist_nulls_unhashed(&mptcp_rsk(req)->collide_tk))
			return;

		if (in_softirq()) {
			mptcp_reqsk_remove_tk(req);
		} else {
			rcu_read_lock_bh();
			spin_lock(&mptcp_tk_hashlock);
			hlist_nulls_del_rcu(&mptcp_rsk(req)->collide_tk);
			spin_unlock(&mptcp_tk_hashlock);
			rcu_read_unlock_bh();
		}
	} else {
		mptcp_hash_request_remove(req);
	}
}

static inline void mptcp_init_mp_opt(struct mptcp_options_received *mopt)
{
	mopt->saw_mpc = 0;
	mopt->dss_csum = 0;

	mopt->is_mp_join = 0;
	mopt->join_ack = 0;

	mopt->saw_low_prio = 0;
	mopt->low_prio = 0;

	mopt->mp_fail = 0;
	mopt->mp_fclose = 0;
	mopt->mpcb = NULL;
}

static inline __be32 mptcp_get_highorder_sndbits(const struct sk_buff *skb,
						 const struct mptcp_cb *mpcb)
{
	return htonl(mpcb->snd_high_order[(TCP_SKB_CB(skb)->mptcp_flags &
			MPTCPHDR_SEQ64_INDEX) ? 1 : 0]);
}

static inline u64 mptcp_get_data_seq_64(const struct mptcp_cb *mpcb, int index,
					u32 data_seq_32)
{
	return ((u64)mpcb->rcv_high_order[index] << 32) | data_seq_32;
}

static inline u64 mptcp_get_rcv_nxt_64(const struct tcp_sock *meta_tp)
{
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	return mptcp_get_data_seq_64(mpcb, mpcb->rcv_hiseq_index,
				     meta_tp->rcv_nxt);
}

static inline void mptcp_check_sndseq_wrap(struct tcp_sock *meta_tp, int inc)
{
	if (unlikely(meta_tp->snd_nxt > meta_tp->snd_nxt + inc)) {
		struct mptcp_cb *mpcb = meta_tp->mpcb;
		mpcb->snd_hiseq_index = mpcb->snd_hiseq_index ? 0 : 1;
		mpcb->snd_high_order[mpcb->snd_hiseq_index] += 2;
	}
}

static inline void mptcp_check_rcvseq_wrap(struct tcp_sock *meta_tp, int inc)
{
	if (unlikely(meta_tp->rcv_nxt > meta_tp->rcv_nxt + inc)) {
		struct mptcp_cb *mpcb = meta_tp->mpcb;
		mpcb->rcv_high_order[mpcb->rcv_hiseq_index] += 2;
		mpcb->rcv_hiseq_index = mpcb->rcv_hiseq_index ? 0 : 1;
	}
}

static inline void mptcp_path_array_check(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;

	if (unlikely(mpcb->list_rcvd)) {
		mpcb->list_rcvd = 0;
		mptcp_create_subflows(meta_sk);
	}
}

static inline int mptcp_sk_can_send(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT);
}

static inline int mptcp_sk_can_recv(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCP_FIN_WAIT1 | TCP_FIN_WAIT2);
}

static inline int mptcp_sk_can_send_ack(const struct sock *sk)
{
	return !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV |
					TCPF_CLOSE | TCPF_LISTEN));
}

/* Adding a new subflow to the rcv-buffer space. We make a simple addition,
 * to give some space to allow traffic on the new subflow. Autotuning will
 * increase it further later on.
 */
static inline void mptcp_init_buffer_space(struct sock *sk)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);
	int space = min(meta_sk->sk_rcvbuf + sk->sk_rcvbuf, sysctl_tcp_rmem[2]);

	if (space > meta_sk->sk_rcvbuf) {
		tcp_sk(meta_sk)->window_clamp += tcp_sk(sk)->window_clamp;
		meta_sk->sk_rcvbuf = space;
	}
}

static inline void mptcp_set_rto(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *sk_it;
	__u32 max_rto = 0;

	if (!tp->mpc)
		return;

	mptcp_for_each_sk(tp->mpcb, sk_it) {
		if (mptcp_sk_can_send(sk_it) &&
		    inet_csk(sk_it)->icsk_rto > max_rto)
			max_rto = inet_csk(sk_it)->icsk_rto;
	}
	if (max_rto)
		inet_csk(mptcp_meta_sk(sk))->icsk_rto = max_rto << 1;
}

static inline int mptcp_sysctl_syn_retries(void)
{
	return sysctl_mptcp_syn_retries;
}

static inline void mptcp_sub_close_passive(struct sock *sk)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk), *meta_tp = tcp_sk(meta_sk);

	/* Only close, if the app did a send-shutdown (passive close), and we
	 * received the data-ack of the data-fin.
	 */
	if (tp->mpcb->passive_close &&
	    meta_tp->snd_una == meta_tp->write_seq)
		mptcp_sub_close(sk, 0);
}

static inline int mptcp_fallback_infinite(struct tcp_sock *tp,
					  const struct sk_buff *skb)
{
	/* If data has been acknowleged on the meta-level, fully_established
	 * will have been set before and thus we will not fall back to infinite
	 * mapping.
	 */
	if (likely(tp->mptcp->fully_established))
		return 0;

	if (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN))
		return 0;

	printk(KERN_ERR"%s %#x will fallback - pi %d from %pS, seq %u\n", __func__,
		    tp->mpcb->mptcp_loc_token, tp->mptcp->path_index,
		    __builtin_return_address(0), TCP_SKB_CB(skb)->seq);
	if (is_master_tp(tp))
		tp->mpcb->send_infinite_mapping = 1;
	else
		return MPTCP_FLAG_SEND_RESET;

	return 0;
}

static inline int mptcp_mp_fail_rcvd(struct sock *sk, const struct tcphdr *th)
{
	struct mptcp_tcp_sock *mptcp = tcp_sk(sk)->mptcp;
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;

	if (unlikely(mptcp->rx_opt.mp_fail)) {
		mptcp->rx_opt.mp_fail = 0;

		if (!th->rst && !mpcb->infinite_mapping) {
			mpcb->send_infinite_mapping = 1;
			/* We resend everything that has not been acknowledged */
			meta_sk->sk_send_head = tcp_write_queue_head(meta_sk);

			/* We artificially restart the whole send-queue. Thus,
			 * it is as if no packets are in flight */
			tcp_sk(meta_sk)->packets_out = 0;
		}

		return 0;
	}

	if (unlikely(mptcp->rx_opt.mp_fclose)) {
		struct sock *sk_it, *tmpsk;
		mptcp->rx_opt.mp_fclose = 0;

		tcp_send_active_reset(sk, GFP_ATOMIC);

		mptcp_for_each_sk_safe(mpcb, sk_it, tmpsk)
			mptcp_sub_force_close(sk_it);

		tcp_reset(meta_sk);

		return 1;
	}

	return 0;
}

/* Find the first free index in the bitfield */
static inline int __mptcp_find_free_index(u8 bitfield, int j, u8 base)
{
	int i;
	mptcp_for_each_bit_unset(bitfield >> base, i) {
		/* We wrapped at the bitfield - try from 0 on */
		if (i + base >= sizeof(bitfield) * 8) {
			mptcp_for_each_bit_unset(bitfield, i) {
				if (i != j)
					return i;
			}
			goto exit;
		}
		if (i + base != j)
			return i + base;
	}
exit:
	return -1;
}

static inline int mptcp_find_free_index(u8 bitfield)
{
	return __mptcp_find_free_index(bitfield, -1, 0);
}

/* Find the first index whose bit in the bit-field == 0 */
static inline u8 mptcp_set_new_pathindex(struct mptcp_cb *mpcb)
{
	u8 base = mpcb->next_path_index;
	int i;

	/* Start at 1, because 0 is reserved for the meta-sk */
	mptcp_for_each_bit_unset(mpcb->path_index_bits >> base, i) {
		if (i + base < 1)
			continue;
		if (i + base >= sizeof(mpcb->path_index_bits) * 8)
			break;
		i += base;
		mpcb->path_index_bits |= (1 << i);
		mpcb->next_path_index = i + 1;
		return i;
	}
	mptcp_for_each_bit_unset(mpcb->path_index_bits, i) {
		if (i < 1)
			continue;
		mpcb->path_index_bits |= (1 << i);
		mpcb->next_path_index = i + 1;
		return i;
	}

	return 0;
}

static inline int mptcp_v6_is_v4_mapped(struct sock *sk)
{
	return sk->sk_family == AF_INET6 &&
		ipv6_addr_type(&inet6_sk(sk)->saddr) == IPV6_ADDR_MAPPED;
}

#else /* CONFIG_MPTCP */
#define mptcp_debug(fmt, args...)	\
	do {				\
	} while(0)

/* Without MPTCP, we just do one iteration
 * over the only socket available. This assumes that
 * the sk/tp arg is the socket in that case.
 */
#define mptcp_for_each_tp(mpcb, tp)
#define mptcp_for_each_sk(mpcb, sk)
#define mptcp_for_each_sk_safe(__mpcb, __sk, __temp)

static inline __u32 *mptcp_skb_set_data_seq(const struct sk_buff *skb,
					    u32 *data_seq)
{
	return 0;
}
static inline int mptcp_is_data_fin(const struct sk_buff *skb)
{
	return 0;
}
static inline int mptcp_is_data_seq(const struct sk_buff *skb)
{
	return 0;
}
static inline struct sock *mptcp_meta_sk(const struct sock *sk)
{
	return NULL;
}
static inline struct tcp_sock *mptcp_meta_tp(const struct tcp_sock *tp)
{
	return NULL;
}
static inline int is_meta_sk(const struct sock *sk)
{
	return 0;
}
static inline int is_master_tp(const struct tcp_sock *tp)
{
	return 0;
}
static inline void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp) {}
static inline void mptcp_cleanup_rbuf(const struct sock *meta_sk, int copied) {}
static inline void mptcp_del_sock(const struct sock *sk) {}
static inline void mptcp_reinject_data(struct sock *orig_sk, int clone_it) {}
static inline void mptcp_init_buffer_space(const struct sock *sk) {}
static inline void mptcp_update_sndbuf(const struct mptcp_cb *mpcb) {}
static inline void mptcp_skb_entail_init(const struct tcp_sock *tp,
					 const struct sk_buff *skb) {}
static inline struct sk_buff *mptcp_next_segment(const struct sock *sk,
						 const int *reinject)
{
	return NULL;
}
static inline void mptcp_clean_rtx_infinite(const struct sk_buff *skb,
					    const struct sock *sk) {}
static inline void mptcp_retransmit_timer(const struct sock *meta_sk) {}
static inline int mptcp_write_wakeup(struct sock *meta_sk)
{
	return 0;
}
static inline void mptcp_sub_close(struct sock *sk, unsigned long delay) {}
static inline void mptcp_set_rto(const struct sock *sk) {}
static inline void mptcp_send_fin(const struct sock *meta_sk) {}
static inline void mptcp_parse_options(const uint8_t *ptr, const int opsize,
				       const struct tcp_options_received *opt_rx,
				       const struct mptcp_options_received *mopt,
				       const struct sk_buff *skb) {}
static inline void mptcp_syn_options(struct sock *sk,
				     struct tcp_out_options *opts,
				     unsigned *remaining) {}
static inline void mptcp_synack_options(struct request_sock *req,
					struct tcp_out_options *opts,
					unsigned *remaining) {}

static inline void mptcp_established_options(struct sock *sk,
					     struct sk_buff *skb,
					     struct tcp_out_options *opts,
					     unsigned *size) {}
static inline void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
				       struct tcp_out_options *opts,
				       struct sk_buff *skb) {}
static inline void mptcp_close(struct sock *meta_sk, long timeout) {}
static inline int mptcp_doit(struct sock *sk)
{
	return 0;
}
static inline int mptcp_check_req_master(const struct sock *sk,
					 const struct sock *child,
					 struct request_sock *req,
					 struct request_sock **prev,
					 const struct mptcp_options_received *mopt)
{
	return 1;
}
static inline struct sock *mptcp_check_req_child(const struct sock *sk,
						 const struct sock *child,
						 const struct request_sock *req,
						 struct request_sock **prev,
						 const struct tcp_options_received *rx_opt)
{
	return 0;
}
static inline u32 __mptcp_select_window(const struct sock *sk)
{
	return 0;
}
static inline void mptcp_select_initial_window(int *__space,
					       __u32 *window_clamp,
					       const struct sock *sk) {}
static inline unsigned int mptcp_current_mss(struct sock *meta_sk)
{
	return 0;
}
static inline int mptcp_select_size(const struct sock *meta_sk)
{
	return 0;
}
static inline int mptcp_data_ack(struct sock *sk, const struct sk_buff *skb)
{
	return 0;
}
static inline void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn) {}
static inline void mptcp_sub_close_passive(struct sock *sk) {}
static inline int mptcp_fallback_infinite(const struct tcp_sock *tp,
					  const struct sk_buff *skb)
{
	return 0;
}
static inline int mptcp_mp_fail_rcvd(struct sock *sk, struct tcphdr *th)
{
	return 0;
}
static inline void mptcp_init_mp_opt(const struct mptcp_options_received *mopt) {}
static inline int mptcp_check_rtt(const struct tcp_sock *tp, int time)
{
	return 0;
}
static inline void mptcp_path_array_check(const struct sock *meta_sk) {}
static inline int mptcp_check_snd_buf(const struct tcp_sock *tp)
{
	return 0;
}
static inline int mptcp_sysctl_syn_retries(void)
{
	return 0;
}
static inline void mptcp_send_reset(const struct sock *sk,
				    const struct sk_buff *skb) {}
static inline void mptcp_send_active_reset(struct sock *meta_sk,
					   gfp_t priority) {}
static inline int mptcp_write_xmit(struct sock *sk, unsigned int mss_now,
				   int nonagle, int push_one, gfp_t gfp)
{
	return 0;
}
static inline struct sock *mptcp_sk_clone(const struct sock *sk,
					  int family, int priority)
{
	return NULL;
}
static inline void mptcp_set_keepalive(struct sock *sk, int val) {}
#endif /* CONFIG_MPTCP */

#endif /* _MPTCP_H */
