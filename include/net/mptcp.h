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
#include <linux/netpoll.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/kernel.h>

#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <net/tcp.h>

#if defined(__LITTLE_ENDIAN_BITFIELD)
	#define ntohll(x)  be64_to_cpu(x)
	#define htonll(x)  cpu_to_be64(x)
#elif defined(__BIG_ENDIAN_BITFIELD)
	#define ntohll(x) (x)
	#define htonll(x) (x)
#endif

struct mptcp_loc4 {
	u8		loc4_id;
	u8		low_prio:1;
	struct in_addr	addr;
};

struct mptcp_rem4 {
	u8		rem4_id;
	__be16		port;
	struct in_addr	addr;
};

struct mptcp_loc6 {
	u8		loc6_id;
	u8		low_prio:1;
	struct in6_addr	addr;
};

struct mptcp_rem6 {
	u8		rem6_id;
	__be16		port;
	struct in6_addr	addr;
};

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
	u8				loc_id;
	u8				rem_id; /* Address-id in the MP_JOIN */
	u8				dss_csum:1,
					low_prio:1;
};

struct mptcp_options_received {
	u16	saw_mpc:1,
		dss_csum:1,
		drop_me:1,

		is_mp_join:1,
		join_ack:1,

		saw_low_prio:2, /* 0x1 - low-prio set for this subflow
				 * 0x2 - low-prio set for another subflow
				 */
		low_prio:1,

		saw_add_addr:2, /* Saw at least one add_addr option:
				 * 0x1: IPv4 - 0x2: IPv6
				 */
		more_add_addr:1, /* Saw one more add-addr. */

		saw_rem_addr:1, /* Saw at least one rem_addr option */
		more_rem_addr:1, /* Saw one more rem-addr. */

		mp_fail:1,
		mp_fclose:1;
	u8	rem_id;		/* Address-id in the MP_JOIN */
	u8	prio_addr_id;	/* Address-id in the MP_PRIO */

	const unsigned char *add_addr_ptr; /* Pointer to add-address option */
	const unsigned char *rem_addr_ptr; /* Pointer to rem-address option */

	u32	data_ack;
	u32	data_seq;
	u16	data_len;

	u32	mptcp_rem_token;/* Remote token */

	/* Key inside the option (from mp_capable or fast_close) */
	u64	mptcp_key;

	u32	mptcp_recv_nonce;
	u64	mptcp_recv_tmac;
	u8	mptcp_recv_mac[20];
};

struct mptcp_tcp_sock {
	struct tcp_sock	*next;		/* Next subflow socket */
	struct list_head cb_list;
	struct mptcp_options_received rx_opt;

	 /* Those three fields record the current mapping */
	u64	map_data_seq;
	u32	map_subseq;
	u16	map_data_len;
	u16	slave_sk:1,
		fully_established:1,
		establish_increased:1,
		second_packet:1,
		attached:1,
		send_mp_fail:1,
		include_mpc:1,
		mapping_present:1,
		map_data_fin:1,
		low_prio:1, /* use this socket as backup */
		rcv_low_prio:1, /* Peer sent low-prio option to us */
		send_mp_prio:1, /* Trigger to send mp_prio on this socket */
		pre_established:1; /* State between sending 3rd ACK and
				    * receiving the fourth ack of new subflows.
				    */

	/* isn: needed to translate abs to relative subflow seqnums */
	u32	snt_isn;
	u32	rcv_isn;
	u8	path_index;
	u8	loc_id;
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
	u32	last_end_data_seq;

	/* MP_JOIN subflow: timer for retransmitting the 3rd ack */
	struct timer_list mptcp_ack_timer;

	/* HMAC of the third ack */
	char sender_mac[20];
};

struct mptcp_tw {
	struct list_head list;
	u64 loc_key;
	u64 rcv_nxt;
	struct mptcp_cb __rcu *mpcb;
	u8 meta_tw:1,
	   in_list:1;
};

#define MPTCP_PM_NAME_MAX 16
struct mptcp_pm_ops {
	struct list_head list;

	/* Signal the creation of a new MPTCP-session. */
	void (*new_session)(struct sock *meta_sk);
	void (*release_sock)(struct sock *meta_sk);
	void (*fully_established)(struct sock *meta_sk);
	void (*new_remote_address)(struct sock *meta_sk);
	int  (*get_local_id)(sa_family_t family, union inet_addr *addr,
			     struct net *net);
	void (*addr_signal)(struct sock *sk, unsigned *size,
			    struct tcp_out_options *opts, struct sk_buff *skb);
	void (*add_raddr)(struct mptcp_cb *mpcb, const union inet_addr *addr, 
			  sa_family_t family, __be16 port, u8 id);
	void (*rem_raddr)(struct mptcp_cb *mpcb, u8 rem_id);
	void (*init_subsocket_v4)(struct sock *sk, struct in_addr addr);
	void (*init_subsocket_v6)(struct sock *sk, struct in6_addr addr);

	char 		name[MPTCP_PM_NAME_MAX];
	struct module 	*owner;
};

struct mptcp_cb {
	struct sock *meta_sk;

	/* list of sockets in this multipath connection */
	struct tcp_sock *connection_list;
	/* list of sockets that need a call to release_cb */
	struct list_head callback_list;

	spinlock_t	 tw_lock;
	struct list_head tw_list;
	unsigned char	 mptw_state;

	atomic_t	mpcb_refcnt;

	/* High-order bits of 64-bit sequence numbers */
	u32 snd_high_order[2];
	u32 rcv_high_order[2];

	u16	send_infinite_mapping:1,
		in_time_wait:1,
		list_rcvd:1, /* XXX TO REMOVE */
		dss_csum:1,
		server_side:1,
		infinite_mapping_rcv:1,
		infinite_mapping_snd:1,
		dfin_combined:1,   /* Was the DFIN combined with subflow-fin? */
		passive_close:1,
		snd_hiseq_index:1, /* Index in snd_high_order of snd_nxt */
		rcv_hiseq_index:1; /* Index in rcv_high_order of rcv_nxt */

	/* socket count in this connection */
	u8 cnt_subflows;
	u8 cnt_established;

	u32 noneligible;	/* Path mask of temporarily non
				 * eligible subflows by the scheduler
				 */

	struct sk_buff_head reinject_queue;

	u8 dfin_path_index;

#define MPTCP_PM_SIZE 608
	u8 mptcp_pm[MPTCP_PM_SIZE] __aligned(8);
	struct mptcp_pm_ops *pm_ops;

	/* Mutex needed, because otherwise mptcp_close will complain that the
	 * socket is owned by the user.
	 * E.g., mptcp_sub_close_wq is taking the meta-lock.
	 */
	struct mutex mpcb_mutex;

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

	u32 path_index_bits;
	/* Next pi to pick up in case a new path becomes available */
	u8 next_path_index;

	/* Original snd/rcvbuf of the initial subflow.
	 * Used for the new subflows on the server-side to allow correct
	 * autotuning
	 */
	int orig_sk_rcvbuf;
	int orig_sk_sndbuf;
	u32 orig_window_clamp;
};

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
#define MPTCP_SUB_LEN_DSM_ALIGN  (MPTCP_SUB_LEN_DSS_ALIGN +		\
				  MPTCP_SUB_LEN_SEQ_ALIGN +		\
				  MPTCP_SUB_LEN_ACK_ALIGN)

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

static inline void reset_mpc(struct tcp_sock *tp)
{
	tp->mpc	= 0;

	tp->__select_window		= __tcp_select_window;
	tp->select_window		= tcp_select_window;
	tp->select_initial_window	= tcp_select_initial_window;
	tp->init_buffer_space		= tcp_init_buffer_space;
	tp->set_rto			= tcp_set_rto;
	tp->should_expand_sndbuf	= tcp_should_expand_sndbuf;
}

static void reset_meta_funcs(struct tcp_sock *tp)
{
	tp->send_fin		= tcp_send_fin;
	tp->write_xmit		= tcp_write_xmit;
	tp->send_active_reset	= tcp_send_active_reset;
	tp->write_wakeup	= tcp_write_wakeup;
	tp->prune_ofo_queue	= tcp_prune_ofo_queue;
	tp->retransmit_timer	= tcp_retransmit_timer;
	tp->time_wait		= tcp_time_wait;
	tp->cleanup_rbuf	= tcp_cleanup_rbuf;
}

/* Initializes MPTCP flags in tcp_sock (and other tcp_sock members that depend
 * on those flags).
 */
static inline void mptcp_init_tcp_sock(struct tcp_sock *tp)
{
	reset_mpc(tp);
	reset_meta_funcs(tp);
}

#ifdef CONFIG_MPTCP

/* Used for checking if the mptcp initialization has been successful */
extern bool mptcp_init_failed;

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

/* MPTCP flags: both TX and RX */
#define MPTCPHDR_SEQ		0x01 /* DSS.M option is present */
#define MPTCPHDR_FIN		0x02 /* DSS.F option is present */
#define MPTCPHDR_SEQ64_INDEX	0x04 /* index of seq in mpcb->snd_high_order */
/* MPTCP flags: RX only */
#define MPTCPHDR_ACK		0x08
#define MPTCPHDR_SEQ64_SET	0x10 /* Did we received a 64-bit seq number?  */
#define MPTCPHDR_SEQ64_OFO	0x20 /* Is it not in our circular array? */
#define MPTCPHDR_DSS_CSUM	0x40
#define MPTCPHDR_JOIN		0x80
/* MPTCP flags: TX only */
#define MPTCPHDR_INF		0x08

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
	__u8	h:1,
		rsv:5,
		b:1,
		a:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
	__u8	a:1,
		b:1,
		rsv:5,
		h:1;
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

static inline int mptcp_sub_len_dss(struct mp_dss *m, int csum)
{
	return 4 + m->A * (4 + m->a * 4) + m->M * (10 + m->m * 4 + csum * 2);
}

#define MPTCP_APP	2

extern int sysctl_mptcp_enabled;
extern int sysctl_mptcp_checksum;
extern int sysctl_mptcp_debug;
extern int sysctl_mptcp_syn_retries;

extern struct workqueue_struct *mptcp_wq;

#define mptcp_debug(fmt, args...)					\
	do {								\
		if (unlikely(sysctl_mptcp_debug))			\
			pr_err(__FILE__ ": " fmt, ##args);	\
	} while (0)

/* Iterates over all subflows */
#define mptcp_for_each_tp(mpcb, tp)					\
	for ((tp) = (mpcb)->connection_list; (tp); (tp) = (tp)->mptcp->next)

#define mptcp_for_each_sk(mpcb, sk)					\
	for ((sk) = (struct sock *)(mpcb)->connection_list;		\
	     sk;							\
	     sk = (struct sock *)tcp_sk(sk)->mptcp->next)

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

extern struct lock_class_key meta_key;
extern struct lock_class_key meta_slock_key;
extern u32 mptcp_secret[MD5_MESSAGE_BYTES / 4];

/* This is needed to ensure that two subsequent key-generation result in
 * different keys if the IPs and ports are the same.
 */
extern u32 mptcp_key_seed;

#define MPTCP_HASH_SIZE                1024

extern struct hlist_nulls_head tk_hashtable[MPTCP_HASH_SIZE];

/* This second hashtable is needed to retrieve request socks
 * created as a result of a join request. While the SYN contains
 * the token, the final ack does not, so we need a separate hashtable
 * to retrieve the mpcb.
 */
extern struct list_head mptcp_reqsk_htb[MPTCP_HASH_SIZE];
extern spinlock_t mptcp_reqsk_hlock;	/* hashtable protection */

/* Lock, protecting the two hash-tables that hold the token. Namely,
 * mptcp_reqsk_tk_htb and tk_hashtable
 */
extern spinlock_t mptcp_tk_hashlock;	/* hashtable protection */

void mptcp_data_ready(struct sock *sk, int bytes);
void mptcp_write_space(struct sock *sk);

void mptcp_add_meta_ofo_queue(struct sock *meta_sk, struct sk_buff *skb,
			      struct sock *sk);
void mptcp_ofo_queue(struct sock *meta_sk);
void mptcp_purge_ofo_queue(struct tcp_sock *meta_tp);
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied);
int mptcp_add_sock(struct sock *meta_sk, struct sock *sk, u8 loc_id, u8 rem_id,
		   gfp_t flags);
void mptcp_del_sock(struct sock *sk);
void mptcp_update_metasocket(struct sock *sock, struct sock *meta_sk);
void mptcp_reinject_data(struct sock *orig_sk, int clone_it);
void mptcp_update_sndbuf(struct mptcp_cb *mpcb);
struct sk_buff *mptcp_next_segment(struct sock *sk, int *reinject);
void mptcp_send_fin(struct sock *meta_sk);
void mptcp_send_active_reset(struct sock *meta_sk, gfp_t priority);
bool mptcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp);
void tcp_parse_mptcp_options(const struct sk_buff *skb,
			     struct mptcp_options_received *mopt);
void mptcp_parse_options(const uint8_t *ptr, int opsize,
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
				   struct request_sock *req,
				   struct request_sock **prev,
				   struct mptcp_options_received *mopt);
u32 __mptcp_select_window(struct sock *sk);
void mptcp_select_initial_window(int __space, __u32 mss, __u32 *rcv_wnd,
					__u32 *window_clamp, int wscale_ok,
					__u8 *rcv_wscale, __u32 init_rcv_wnd,
					const struct sock *sk);
unsigned int mptcp_current_mss(struct sock *meta_sk);
int mptcp_select_size(const struct sock *meta_sk, bool sg);
void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn);
void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		     u32 *hash_out);
void mptcp_clean_rtx_infinite(struct sk_buff *skb, struct sock *sk);
void mptcp_fin(struct sock *meta_sk);
void mptcp_retransmit_timer(struct sock *meta_sk);
int mptcp_write_wakeup(struct sock *meta_sk);
void mptcp_sub_close_wq(struct work_struct *work);
void mptcp_sub_close(struct sock *sk, unsigned long delay);
struct sock *mptcp_select_ack_sock(const struct sock *meta_sk);
void mptcp_fallback_meta_sk(struct sock *meta_sk);
int mptcp_backlog_rcv(struct sock *meta_sk, struct sk_buff *skb);
struct sock *mptcp_sk_clone(const struct sock *sk, int family, const gfp_t priority);
void mptcp_ack_handler(unsigned long);
int mptcp_check_rtt(const struct tcp_sock *tp, int time);
int mptcp_check_snd_buf(const struct tcp_sock *tp);
int mptcp_handle_options(struct sock *sk, const struct tcphdr *th, struct sk_buff *skb);
void __init mptcp_init(void);
int mptcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len);
void mptcp_destroy_sock(struct sock *sk);
int mptcp_rcv_synsent_state_process(struct sock *sk, struct sock **skptr,
				    struct sk_buff *skb,
				    struct mptcp_options_received *mopt);
unsigned int mptcp_xmit_size_goal(struct sock *meta_sk, u32 mss_now,
				  int large_allowed);
int mptcp_init_tw_sock(struct sock *sk, struct tcp_timewait_sock *tw);
void mptcp_twsk_destructor(struct tcp_timewait_sock *tw);
void mptcp_time_wait(struct sock *sk, int state, int timeo);
void mptcp_disconnect(struct sock *sk);
bool mptcp_should_expand_sndbuf(const struct sock *sk);
int mptcp_retransmit_skb(struct sock *meta_sk, struct sk_buff *skb);
void mptcp_tsq_flags(struct sock *sk);
void mptcp_tsq_sub_deferred(struct sock *meta_sk);
struct mp_join *mptcp_find_join(struct sk_buff *skb);
void mptcp_hash_remove_bh(struct tcp_sock *meta_tp);
void mptcp_hash_remove(struct tcp_sock *meta_tp);
struct sock *mptcp_hash_find(struct net *net, u32 token);
int mptcp_lookup_join(struct sk_buff *skb, struct inet_timewait_sock *tw);
int mptcp_do_join_short(struct sk_buff *skb, struct mptcp_options_received *mopt,
			struct net *net);
void mptcp_reqsk_destructor(struct request_sock *req);
void mptcp_reqsk_new_mptcp(struct request_sock *req,
			   const struct mptcp_options_received *mopt,
			   const struct sk_buff *skb);
int mptcp_check_req(struct sk_buff *skb, struct net *net);
void mptcp_connect_init(struct sock *sk);
void mptcp_sub_force_close(struct sock *sk);
int mptcp_sub_len_remove_addr_align(u16 bitfield);
void mptcp_remove_shortcuts(const struct mptcp_cb *mpcb,
			    const struct sk_buff *skb);
void mptcp_init_buffer_space(struct sock *sk);
void mptcp_reqsk_init(struct request_sock *req, struct sk_buff *skb);
int mptcp_conn_request(struct sock *sk, struct sk_buff *skb);

/* MPTCP-path-manager registration/initialization functions */
int mptcp_register_path_manager(struct mptcp_pm_ops *pm);
void mptcp_unregister_path_manager(struct mptcp_pm_ops *pm);
void mptcp_init_path_manager(struct mptcp_cb *mpcb);
void mptcp_cleanup_path_manager(struct mptcp_cb *mpcb);
void mptcp_fallback_default(struct mptcp_cb *mpcb);
void mptcp_get_default_path_manager(char *name);
int mptcp_set_default_path_manager(const char *name);
extern struct mptcp_pm_ops mptcp_pm_default;

static inline int is_mptcp_enabled(void)
{
	return sysctl_mptcp_enabled && !mptcp_init_failed;
}

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

static inline bool mptcp_can_sendpage(struct sock *sk)
{
	struct sock *sk_it;

	if (tcp_sk(sk)->mpcb->dss_csum)
		return false;

	mptcp_for_each_sk(tcp_sk(sk)->mpcb, sk_it) {
		if (!(sk_it->sk_route_caps & NETIF_F_SG) ||
		    !(sk_it->sk_route_caps & NETIF_F_ALL_CSUM))
			return false;
	}

	return true;
}

static inline void mptcp_push_pending_frames(struct sock *meta_sk)
{
	if (mptcp_next_segment(meta_sk, NULL)) {
		struct tcp_sock *tp = tcp_sk(meta_sk);

		/* We don't care about the MSS, because it will be set in
		 * mptcp_write_xmit.
		 */
		__tcp_push_pending_frames(meta_sk, 0, tp->nonagle);
	}
}

static inline void mptcp_send_reset(struct sock *sk)
{
	tcp_sk(sk)->send_active_reset(sk, GFP_ATOMIC);
	mptcp_sub_force_close(sk);
}

static inline bool mptcp_is_data_seq(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_SEQ;
}

static inline bool mptcp_is_data_fin(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_FIN;
}

/* Is it a data-fin while in infinite mapping mode?
 * In infinite mode, a subflow-fin is in fact a data-fin.
 */
static inline bool mptcp_is_data_fin2(const struct sk_buff *skb,
				     const struct tcp_sock *tp)
{
	return mptcp_is_data_fin(skb) ||
	       (tp->mpcb->infinite_mapping_rcv && tcp_hdr(skb)->fin);
}

static inline u8 mptcp_get_64_bit(u64 data_seq, struct mptcp_cb *mpcb)
{
	u64 data_seq_high = (u32)(data_seq >> 32);

	if (mpcb->rcv_high_order[0] == data_seq_high)
		return 0;
	else if (mpcb->rcv_high_order[1] == data_seq_high)
		return MPTCPHDR_SEQ64_INDEX;
	else
		return MPTCPHDR_SEQ64_OFO;
}

/* Sets the data_seq and returns pointer to the in-skb field of the data_seq.
 * If the packet has a 64-bit dseq, the pointer points to the last 32 bits.
 */
static inline __u32 *mptcp_skb_set_data_seq(const struct sk_buff *skb,
					    u32 *data_seq,
					    struct mptcp_cb *mpcb)
{
	__u32 *ptr = (__u32 *)(skb_transport_header(skb) + TCP_SKB_CB(skb)->dss_off);

	if (TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_SEQ64_SET) {
		u64 data_seq64 = get_unaligned_be64(ptr);

		if (mpcb)
			TCP_SKB_CB(skb)->mptcp_flags |= mptcp_get_64_bit(data_seq64, mpcb);

		*data_seq = (u32)data_seq64 ;
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
	       mptcp(tcp_sk(sk)) && mptcp_meta_sk(sk) == sk;
}

static inline int is_master_tp(const struct tcp_sock *tp)
{
	return !mptcp(tp) || (!tp->mptcp->slave_sk && !is_meta_tp(tp));
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

static inline void mptcp_init_mp_opt(struct mptcp_options_received *mopt)
{
	mopt->saw_mpc = 0;
	mopt->dss_csum = 0;
	mopt->drop_me = 0;

	mopt->is_mp_join = 0;
	mopt->join_ack = 0;

	mopt->saw_low_prio = 0;
	mopt->low_prio = 0;

	mopt->saw_add_addr = 0;
	mopt->more_add_addr = 0;

	mopt->saw_rem_addr = 0;
	mopt->more_rem_addr = 0;

	mopt->mp_fail = 0;
	mopt->mp_fclose = 0;
}

static inline void mptcp_reset_mopt(struct tcp_sock *tp)
{
	struct mptcp_options_received *mopt = &tp->mptcp->rx_opt;

	mopt->saw_low_prio = 0;
	mopt->saw_add_addr = 0;
	mopt->more_add_addr = 0;
	mopt->saw_rem_addr = 0;
	mopt->more_rem_addr = 0;
	mopt->join_ack = 0;
	mopt->mp_fail = 0;
	mopt->mp_fclose = 0;
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

static inline void mptcp_check_rcvseq_wrap(struct tcp_sock *meta_tp,
					   u32 old_rcv_nxt)
{
	if (unlikely(old_rcv_nxt > meta_tp->rcv_nxt)) {
		struct mptcp_cb *mpcb = meta_tp->mpcb;
		mpcb->rcv_high_order[mpcb->rcv_hiseq_index] += 2;
		mpcb->rcv_hiseq_index = mpcb->rcv_hiseq_index ? 0 : 1;
	}
}

static inline int mptcp_sk_can_send(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
	       !tcp_sk(sk)->mptcp->pre_established;
}

static inline int mptcp_sk_can_recv(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCP_FIN_WAIT1 | TCP_FIN_WAIT2);
}

static inline int mptcp_sk_can_send_ack(const struct sock *sk)
{
	return !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV |
					TCPF_CLOSE | TCPF_LISTEN)) &&
	       !tcp_sk(sk)->mptcp->pre_established;
}

/* Only support GSO if all subflows supports it */
static inline bool mptcp_sk_can_gso(const struct sock *meta_sk)
{
	struct sock *sk;

	if (tcp_sk(meta_sk)->mpcb->dss_csum)
		return false;

	mptcp_for_each_sk(tcp_sk(meta_sk)->mpcb, sk) {
		if (!mptcp_sk_can_send(sk))
			continue;
		if (!sk_can_gso(sk))
			return false;
	}
	return true;
}

static inline bool mptcp_can_sg(const struct sock *meta_sk)
{
	struct sock *sk;

	if (tcp_sk(meta_sk)->mpcb->dss_csum)
		return false;

	mptcp_for_each_sk(tcp_sk(meta_sk)->mpcb, sk) {
		if (!mptcp_sk_can_send(sk))
			continue;
		if (!(sk->sk_route_caps & NETIF_F_SG))
			return false;
	}
	return true;
}

static inline void mptcp_set_rto(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *sk_it;
	struct inet_connection_sock *micsk = inet_csk(mptcp_meta_sk(sk));
	__u32 max_rto = 0;

	/* We are in recovery-phase on the MPTCP-level. Do not update the
	 * RTO, because this would kill exponential backoff.
	 */
	if (micsk->icsk_retransmits)
		return;

	mptcp_for_each_sk(tp->mpcb, sk_it) {
		if (mptcp_sk_can_send(sk_it) &&
		    inet_csk(sk_it)->icsk_rto > max_rto)
			max_rto = inet_csk(sk_it)->icsk_rto;
	}
	if (max_rto) {
		micsk->icsk_rto = max_rto << 1;

		/* A successfull rto-measurement - reset backoff counter */
		micsk->icsk_backoff = 0;
	}
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
	if (tp->mpcb->passive_close && meta_tp->snd_una == meta_tp->write_seq)
		mptcp_sub_close(sk, 0);
}

static inline bool mptcp_fallback_infinite(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* If data has been acknowleged on the meta-level, fully_established
	 * will have been set before and thus we will not fall back to infinite
	 * mapping.
	 */
	if (likely(tp->mptcp->fully_established))
		return false;

	if (!(flag & MPTCP_FLAG_DATA_ACKED))
		return false;

	/* Don't fallback twice ;) */
	if (tp->mpcb->infinite_mapping_snd)
		return false;

	pr_err("%s %#x will fallback - pi %d, src %pI4 dst %pI4 from %pS\n",
	       __func__, tp->mpcb->mptcp_loc_token, tp->mptcp->path_index,
	       &inet_sk(sk)->inet_saddr, &inet_sk(sk)->inet_daddr,
	       __builtin_return_address(0));
	if (!is_master_tp(tp))
		return true;

	tp->mpcb->infinite_mapping_snd = 1;
	tp->mpcb->infinite_mapping_rcv = 1;
	tp->mptcp->fully_established = 1;

	return false;
}

/* Find the first free index in the bitfield */
static inline int __mptcp_find_free_index(u8 bitfield, u8 base)
{
	int i;
	mptcp_for_each_bit_unset(bitfield >> base, i) {
		/* We wrapped at the bitfield - try from 0 on */
		if (i + base >= sizeof(bitfield) * 8) {
			mptcp_for_each_bit_unset(bitfield, i) {
				if (i >= sizeof(bitfield) * 8)
					goto exit;
				return i;
			}
			goto exit;
		}
		if (i + base >= sizeof(bitfield) * 8)
			break;

		return i + base;
	}
exit:
	return -1;
}

static inline int mptcp_find_free_index(u8 bitfield)
{
	return __mptcp_find_free_index(bitfield, 0);
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
		if (i >= sizeof(mpcb->path_index_bits) * 8)
			break;
		if (i < 1)
			continue;
		mpcb->path_index_bits |= (1 << i);
		mpcb->next_path_index = i + 1;
		return i;
	}

	return 0;
}

static inline bool mptcp_v6_is_v4_mapped(struct sock *sk)
{
	return sk->sk_family == AF_INET6 &&
	       ipv6_addr_type(&inet6_sk(sk)->saddr) == IPV6_ADDR_MAPPED;
}

/* TCP and MPTCP mpc flag-depending functions */
u16 mptcp_select_window(struct sock *sk);
void mptcp_init_buffer_space(struct sock *sk);
void mptcp_tcp_set_rto(struct sock *sk);

/* TCP and MPTCP flag-depending functions */
bool mptcp_prune_ofo_queue(struct sock *sk);

static inline void set_mpc(struct tcp_sock *tp)
{
	static_key_slow_inc(&mptcp_static_key);
	tp->mpc	= 1;

	tp->__select_window		= __mptcp_select_window;
	tp->select_window		= mptcp_select_window;
	tp->select_initial_window	= mptcp_select_initial_window;
	tp->init_buffer_space		= mptcp_init_buffer_space;
	tp->set_rto			= mptcp_tcp_set_rto;
	tp->should_expand_sndbuf	= mptcp_should_expand_sndbuf;
}

static inline void set_meta_funcs(struct tcp_sock *tp)
{
	tp->send_fin		= mptcp_send_fin;
	tp->write_xmit		= mptcp_write_xmit;
	tp->send_active_reset	= mptcp_send_active_reset;
	tp->write_wakeup	= mptcp_write_wakeup;
	tp->prune_ofo_queue	= mptcp_prune_ofo_queue;
	tp->retransmit_timer	= mptcp_retransmit_timer;
	tp->time_wait		= mptcp_time_wait;
	tp->cleanup_rbuf	= mptcp_cleanup_rbuf;
}

#else /* CONFIG_MPTCP */
#define mptcp_debug(fmt, args...)	\
	do {				\
	} while (0)

/* Without MPTCP, we just do one iteration
 * over the only socket available. This assumes that
 * the sk/tp arg is the socket in that case.
 */
#define mptcp_for_each_sk(mpcb, sk)
#define mptcp_for_each_sk_safe(__mpcb, __sk, __temp)

static inline bool mptcp_is_data_fin(const struct sk_buff *skb)
{
	return 0;
}
static inline bool mptcp_is_data_seq(const struct sk_buff *skb)
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
static inline void mptcp_del_sock(const struct sock *sk) {}
static inline void mptcp_reinject_data(struct sock *orig_sk, int clone_it) {}
static inline void mptcp_update_sndbuf(const struct mptcp_cb *mpcb) {}
static inline void mptcp_clean_rtx_infinite(const struct sk_buff *skb,
					    const struct sock *sk) {}
static inline void mptcp_sub_close(struct sock *sk, unsigned long delay) {}
static inline void mptcp_set_rto(const struct sock *sk) {}
static inline void mptcp_send_fin(const struct sock *meta_sk) {}
static inline void mptcp_parse_options(const uint8_t *ptr, const int opsize,
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
static inline struct sock *mptcp_check_req_child(struct sock *sk,
						 struct sock *child,
						 struct request_sock *req,
						 struct request_sock **prev,
						 struct mptcp_options_received *mopt)
{
	return NULL;
}
static inline unsigned int mptcp_current_mss(struct sock *meta_sk)
{
	return 0;
}
static inline int mptcp_select_size(const struct sock *meta_sk, bool sg)
{
	return 0;
}
static inline void mptcp_sub_close_passive(struct sock *sk) {}
static inline bool mptcp_fallback_infinite(const struct sock *sk, int flag)
{
	return false;
}
static inline void mptcp_init_mp_opt(const struct mptcp_options_received *mopt) {}
static inline int mptcp_check_rtt(const struct tcp_sock *tp, int time)
{
	return 0;
}
static inline int mptcp_check_snd_buf(const struct tcp_sock *tp)
{
	return 0;
}
static inline int mptcp_sysctl_syn_retries(void)
{
	return 0;
}
static inline void mptcp_send_reset(const struct sock *sk) {}
static inline struct sock *mptcp_sk_clone(const struct sock *sk, int family,
					  const gfp_t priority)
{
	return NULL;
}
static inline int mptcp_handle_options(struct sock *sk,
				       const struct tcphdr *th,
				       struct sk_buff *skb)
{
	return 0;
}
static inline void mptcp_reset_mopt(struct tcp_sock *tp) {}
static inline void  __init mptcp_init(void) {}
static inline int mptcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	return 0;
}
static inline bool mptcp_sk_can_gso(const struct sock *sk)
{
	return false;
}
static inline bool mptcp_can_sg(const struct sock *meta_sk)
{
	return false;
}
static inline unsigned int mptcp_xmit_size_goal(struct sock *meta_sk,
						u32 mss_now, int large_allowed)
{
	return 0;
}
static inline void mptcp_destroy_sock(struct sock *sk) {}
static inline int mptcp_rcv_synsent_state_process(struct sock *sk,
						  struct sock **skptr,
						  struct sk_buff *skb,
						  struct mptcp_options_received *mopt)
{
	return 0;
}
static inline bool mptcp_can_sendpage(struct sock *sk)
{
	return false;
}
static inline int mptcp_init_tw_sock(struct sock *sk,
				     struct tcp_timewait_sock *tw)
{
	return 0;
}
static inline void mptcp_twsk_destructor(struct tcp_timewait_sock *tw) {}
static inline void mptcp_disconnect(struct sock *sk) {}
static inline void mptcp_tsq_flags(struct sock *sk) {}
static inline void mptcp_tsq_sub_deferred(struct sock *meta_sk) {}
static inline void mptcp_hash_remove_bh(struct tcp_sock *meta_tp) {}
static inline void mptcp_hash_remove(struct tcp_sock *meta_tp) {}
static inline void mptcp_reqsk_new_mptcp(struct request_sock *req,
					 const struct tcp_options_received *rx_opt,
					 const struct mptcp_options_received *mopt,
					 const struct sk_buff *skb) {}
static inline void mptcp_remove_shortcuts(const struct mptcp_cb *mpcb,
					  const struct sk_buff *skb) {}
#endif /* CONFIG_MPTCP */

#endif /* _MPTCP_H */
