/*
 *	MPTCP implementation - MPTCP-control
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

#include <net/inet_common.h>
#include <net/inet6_hashtables.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <net/mptcp_v6.h>
#endif
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/transp_v6.h>
#include <net/xfrm.h>

#include <linux/cryptohash.h>
#include <linux/kconfig.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/random.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/sysctl.h>

static struct kmem_cache *mptcp_sock_cache __read_mostly;
static struct kmem_cache *mptcp_cb_cache __read_mostly;
static struct kmem_cache *mptcp_tw_cache __read_mostly;

int sysctl_mptcp_enabled __read_mostly = 1;
int sysctl_mptcp_version __read_mostly = 0;
static int min_mptcp_version;
static int max_mptcp_version = 1;
int sysctl_mptcp_checksum __read_mostly = 1;
int sysctl_mptcp_debug __read_mostly;
EXPORT_SYMBOL(sysctl_mptcp_debug);
int sysctl_mptcp_syn_retries __read_mostly = 3;

/* swetankk */
int sysctl_mptcp_scheduler_optimizations_disabled __read_mostly = 0;
EXPORT_SYMBOL(sysctl_mptcp_scheduler_optimizations_disabled);
/* end: swetankk */

/* shivanga */
int sysctl_num_segments_flow_one __read_mostly = 77;
EXPORT_SYMBOL(sysctl_num_segments_flow_one);

int sysctl_mptcp_rate_sample __read_mostly = 100;
EXPORT_SYMBOL(sysctl_mptcp_rate_sample);

int sysctl_mptcp_ratio_static = 0;
EXPORT_SYMBOL(sysctl_mptcp_ratio_static);

int sysctl_mptcp_ratio_trigger_search = 0;
EXPORT_SYMBOL(sysctl_mptcp_ratio_trigger_search);

int sysctl_mptcp_ratio_search_step = 5;
EXPORT_SYMBOL(sysctl_mptcp_ratio_search_step);

int sysctl_mptcp_trigger_threshold = 100000; //Kbps
EXPORT_SYMBOL(sysctl_mptcp_trigger_threshold);

int sysctl_mptcp_set_backup = 0;
EXPORT_SYMBOL(sysctl_mptcp_set_backup);

int sysctl_mptcp_probe_interval_secs = 0; //seconds, 0 = probe disabled
EXPORT_SYMBOL(sysctl_mptcp_probe_interval_secs);

//int sysctl_mptcp_rate = 0;
//EXPORT_SYMBOL(sysctl_mptcp_rate);

#define REPORT_BUF_SIZE_MAX 500
u64 prev_tx_bytes = 0, prev_tstamp = 0;

struct ratio_sched_priv {
    u16 quota;
    u32 write_seq_saved;
    //u32 write_seq_jiffies;
    struct timeval write_seq_tv, snd_una_tv;
    u64 completion_time;
    u8 is_accounting, is_init_accounted;
    u32 snd_una_saved, buffer_size;
    u32 delivered;
};

static struct ratio_sched_priv *ratio_sched_get_priv(const struct tcp_sock *tp)
{
    return (struct ratio_sched_priv *)&tp->mptcp->mptcp_sched[0];
}

/* end: shivanga */
bool mptcp_init_failed __read_mostly;

DEFINE_STATIC_KEY_FALSE(mptcp_static_key);
EXPORT_SYMBOL(mptcp_static_key);

static void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn);

static int proc_mptcp_path_manager(struct ctl_table *ctl, int write,
				   void __user *buffer, size_t *lenp,
				   loff_t *ppos)
{
	char val[MPTCP_PM_NAME_MAX];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = MPTCP_PM_NAME_MAX,
	};
	int ret;

	mptcp_get_default_path_manager(val);

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = mptcp_set_default_path_manager(val);
	return ret;
}

static int proc_mptcp_scheduler(struct ctl_table *ctl, int write,
				void __user *buffer, size_t *lenp,
				loff_t *ppos)
{
	char val[MPTCP_SCHED_NAME_MAX];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = MPTCP_SCHED_NAME_MAX,
	};
	int ret;

	mptcp_get_default_scheduler(val);

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = mptcp_set_default_scheduler(val);
	return ret;
}

/* shivanga */

#define tcp_probe_copy_fl_to_si4(inet, si4, mem)        \
    do {                            \
        si4.sin_family = AF_INET;           \
        si4.sin_port = inet->inet_##mem##port;      \
        si4.sin_addr.s_addr = inet->inet_##mem##addr;   \
    } while (0)                     \

static int proc_mptcp_bytes_not_sent(struct ctl_table *ctl, int write,
                                   void __user *buffer, size_t *lenp, loff_t *ppos)
{
    char val[MPTCP_BYTES_NOT_SENT_MAX];
    int val_length = 0;
    struct ctl_table tbl = {
       .data = val,
       .maxlen = MPTCP_BYTES_NOT_SENT_MAX,
    };
    int ret;

    struct tcp_sock *meta_tp;
	int i;

    memset(val, 0, MPTCP_BYTES_NOT_SENT_MAX);
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node,
					       &tk_hashtable[i], tk_table) {
			//struct sock *sk_it;
			struct mptcp_tcp_sock *mptcp_sock;
			struct mptcp_cb *mpcb = meta_tp->mpcb;
            int iter;

	    /*Ask shivang whaht this is*/
			if (!mptcp(meta_tp))
				continue;

			if (!mpcb)
				continue;

            iter = 0;
	    /*Phuc*/
	    /*Double check with Shivang for these type casts*/
            mptcp_for_each_sub(mpcb, mptcp_sock) {
                //struct tcp_sock *tp_it = tcp_sk(sk_it);
		const struct sock *sk = mptcp_to_sock(mptcp_sock);
		const struct tcp_sock *tp_it = tcp_sk(sk);
                const struct inet_sock *inet = inet_sk(sk);//do we need const?
                union {
                    struct sockaddr     raw;
                    struct sockaddr_in  v4;
                    struct sockaddr_in6 v6;
                } dst;

                tcp_probe_copy_fl_to_si4(inet, dst.v4, d);
                val_length += sprintf(val + val_length, "%pISpc ", &dst);
                val_length += sprintf(val + val_length, "%u\n", tp_it->write_seq - tp_it->snd_una); 
                iter++;
            }
	    /*******/
            val_length += sprintf(val + val_length, "\n");
		}

		rcu_read_unlock_bh();
	}

    ret = proc_dostring(&tbl, write, buffer, lenp, ppos);

    return ret;
}
/*
static int proc_mptcp_num_segments_flow_one(struct ctl_table *ctl, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{
    int val = 0;
    struct ctl_table tbl = {
        .data = &val,
        .maxlen = sizeof(int),
    };
    int ret;

    val = sysctl_num_segments_flow_one;

    ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
    if (write && ret == 0) {
        struct tcp_sock *meta_tp;
        int i;
        sysctl_num_segments_flow_one = val;

        for (i = 0; i < MPTCP_HASH_SIZE; i++) {
            struct hlist_nulls_node *node;
            rcu_read_lock_bh();
            hlist_nulls_for_each_entry_rcu(meta_tp, node,
                               &tk_hashtable[i], tk_table) {
                struct sock *sk_it;
                struct mptcp_cb *mpcb = meta_tp->mpcb;
                int iter;

                if (!mptcp(meta_tp))
                    continue;

                if (!mpcb)
                    continue;

                iter = 0;
                mptcp_for_each_sk(mpcb, sk_it) {
                    struct tcp_sock *tp_it = tcp_sk(sk_it);
                    struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
                    //rsp->quota = 0;
                    iter++;
                }
            }

            rcu_read_unlock_bh();
        }

    }  
    return ret;
}
*/
static int proc_mptcp_set_pf(struct ctl_table *ctl, int write,
                void __user *buffer, size_t *lenp,
                loff_t *ppos)
{
    int val = 0, tempval = 0;
    struct ctl_table tbl = {
        .data = &val,
        .maxlen = sizeof(int),
    };
    int ret;
    
    int i;
    struct tcp_sock *meta_tp;
    for (i = 0; i < MPTCP_HASH_SIZE; i++) {
            struct hlist_nulls_node *node;
            rcu_read_lock_bh();
            hlist_nulls_for_each_entry_rcu(meta_tp, node,
                               &tk_hashtable[i], tk_table) {
                //struct sock *sk_it;
                struct mptcp_tcp_sock *mptcp_sock;
                struct mptcp_cb *mpcb = meta_tp->mpcb;

                if (!mptcp(meta_tp))
                    continue;

                if (!mpcb)
                    continue;

		/*Phuc*/
                mptcp_for_each_sub(mpcb, mptcp_sock) {
		
		    struct sock *sk_it = mptcp_to_sock(mptcp_sock);
                    struct tcp_sock *tp_it = tcp_sk(sk_it);
                    if (tp_it->pf) {
                        tempval = 1;
                        break;
                    }
                        
                }
		/*****/
                if (tempval == 1)
                    break;
            }

            rcu_read_unlock_bh();
            if (tempval == 1)
                break;
        }

    val = tempval;

    ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);
    if (write && ret == 0) {
        struct tcp_sock *meta_tp;
        int i;

        for (i = 0; i < MPTCP_HASH_SIZE; i++) {
            struct hlist_nulls_node *node;
            rcu_read_lock_bh();
            hlist_nulls_for_each_entry_rcu(meta_tp, node,
                               &tk_hashtable[i], tk_table) {
                //struct sock *sk_it;
		struct mptcp_tcp_sock *mptcp_sock;
                struct mptcp_cb *mpcb = meta_tp->mpcb;
                int iter = 0;

                if (!mptcp(meta_tp))
                    continue;

                if (!mpcb)
                    continue;
		/*phuc*/
                mptcp_for_each_sub(mpcb, mptcp_sock) {
		    struct sock *sk_it = mptcp_to_sock(mptcp_sock);
                    struct tcp_sock *tp_it = tcp_sk(sk_it);
                    tp_it->pf = val;
                    iter++;
                    if (tp_it->prior_ssthresh) {
                        const struct inet_connection_sock *icsk = inet_csk(sk_it);

                        tp_it->snd_cwnd = icsk->icsk_ca_ops->undo_cwnd(sk_it);
                        if (tp_it->prior_ssthresh > tp_it->snd_ssthresh) {
                            tp_it->snd_ssthresh = tp_it->prior_ssthresh;
                        }
                        tcp_set_ca_state(sk_it, TCP_CA_Recovery);
                    }
                }
		/*****/
            }

            rcu_read_unlock_bh();
        }

    }
    return ret;
}

static int proc_mptcp_rate(struct ctl_table *ctl, int write,
                                   void __user *buffer, size_t *lenp, loff_t *ppos)
{
    u32 val = 0, tempval = 0;
    struct ctl_table tbl = {
        .data = &val,
        .maxlen = sizeof(u32),
    };

    int ret;

    struct tcp_sock *meta_tp;
    int i;

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node,
					       &tk_hashtable[i], tk_table) {
			struct mptcp_cb *mpcb = meta_tp->mpcb;
            struct sock *sk = NULL;
            struct dst_entry *dst;
                
            struct netdev_queue *txq0;
            struct rtnl_link_stats64 temp;
            //const struct rtnl_link_stats64 *stats;
            u32 tput = 0;
            
			if (!mptcp(meta_tp))
				continue;

			if (!mpcb)
				continue;
            
            sk = &((meta_tp->inet_conn).icsk_inet.sk);

            if (sk) {
                //printk("if sk\n");
                dst = sk_dst_get(sk);

                if (dst && dst->dev) {
                    const struct rtnl_link_stats64 *stats = dev_get_stats(dst->dev, &temp);
                    //printk("if dst->dev\n");
                    //printk("%s\n", dst->dev->name);
                    if (strcmp(dst->dev->name, "enp5s0")) continue;
                    txq0 = netdev_get_tx_queue(dst->dev, 0); //get txqueueu from dst

                    if (stats && txq0) {
                        //printk("if stats && txq0\n");
                        if (!prev_tx_bytes) prev_tx_bytes = stats->tx_bytes;
                        if (!prev_tstamp) prev_tstamp = txq0->trans_start;

                        if (prev_tx_bytes && prev_tstamp && txq0->trans_start != prev_tstamp && jiffies_to_msecs(txq0->trans_start - prev_tstamp)) {
                            //printk("prev_bytes: %llu, prev_tstamp: %llu, cur_bytes: %llu, cur_tstamp: %lu", prev_tx_bytes, prev_tstamp, stats->tx_bytes, txq0->trans_start);
                            tput = ((stats->tx_bytes - prev_tx_bytes)*8)/(jiffies_to_msecs(txq0->trans_start - prev_tstamp));
                            //printk("rate: %llu\n", tput);
                            prev_tx_bytes = stats->tx_bytes;
                            prev_tstamp = txq0->trans_start;
                            if (!tempval) {
                                tempval = tput;
                                //printk("tempval = tput: %u\n", tempval);
                            } //else printk("tempval again\n"); 
                            break;
                        }
                    }
                }
            }
        }

        rcu_read_unlock_bh();

        //if (tempval) break;

	}

    val = tempval;

    //printk("ret: %u\n", val);

    ret = proc_douintvec(&tbl, write, buffer, lenp, ppos);

    return ret;
}


static int proc_mptcp_buffer_size(struct ctl_table *ctl, int write,
                                   void __user *buffer, size_t *lenp, loff_t *ppos)
{
    char val[REPORT_BUF_SIZE_MAX];
    int val_length = 0;
    struct ctl_table tbl = {
       .data = val,
       .maxlen = REPORT_BUF_SIZE_MAX,
    };
    int ret;

    struct tcp_sock *meta_tp;
	int i;

    memset(val, 0, REPORT_BUF_SIZE_MAX);
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node,
					       &tk_hashtable[i], tk_table) {
			//struct sock *sk_it, *sk;
			struct sock *sk;
			struct mptcp_tcp_sock *mptcp_sock;
			struct mptcp_cb *mpcb = meta_tp->mpcb;
            int iter;

			if (!mptcp(meta_tp))
				continue;

			if (!mpcb)
				continue;

            sk = &((meta_tp->inet_conn).icsk_inet.sk);
            if (sk) {
                struct dst_entry *dst = sk_dst_get(sk);

                if (dst && dst->dev) {
                    if (strcmp(dst->dev->name, "enp5s0")) continue;
                    iter = 0;
		    /*phuc*/
                    mptcp_for_each_sub(mpcb, mptcp_sock) {
			struct sock *sk_it = mptcp_to_sock(mptcp_sock);
                        struct tcp_sock *tp_it = tcp_sk(sk_it);
                        struct ratio_sched_priv *rsp = ratio_sched_get_priv(tp_it);
		    /*****/
                        if (rsp->delivered) {
                            do_div(rsp->buffer_size, rsp->delivered);
                            val_length += sprintf(val + val_length, "%u ", rsp->buffer_size);
                            rsp->buffer_size = 0;
                            rsp->delivered = 0;
                            //val_length += sprintf(val + val_length, "%u\n", tp_it->write_seq - tp_it->snd_una); 
                        }
                        iter++;
                    }
                    if (meta_tp->delivered) { 
                        val_length += sprintf(val + val_length, "\n");
                        break;
                    }
                }
            }
		}

		rcu_read_unlock_bh();
	}

    ret = proc_dostring(&tbl, write, buffer, lenp, ppos);

    return ret;
}

static struct ctl_table mptcp_table[] = {
	{
		.procname = "mptcp_enabled",
		.data = &sysctl_mptcp_enabled,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_version",
		.data = &sysctl_mptcp_version,
		.mode = 0644,
		.maxlen = sizeof(int),
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &min_mptcp_version,
		.extra2 = &max_mptcp_version,
	},
	{
		.procname = "mptcp_checksum",
		.data = &sysctl_mptcp_checksum,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_debug",
		.data = &sysctl_mptcp_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_syn_retries",
		.data = &sysctl_mptcp_syn_retries,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname	= "mptcp_path_manager",
		.mode		= 0644,
		.maxlen		= MPTCP_PM_NAME_MAX,
		.proc_handler	= proc_mptcp_path_manager,
	},
	{
		.procname	= "mptcp_scheduler",
		.mode		= 0644,
		.maxlen		= MPTCP_SCHED_NAME_MAX,
		.proc_handler	= proc_mptcp_scheduler,
	},
    /* swetankk */
 	{
        .procname     = "mptcp_scheduler_optimizations_disabled",
        .data         = &sysctl_mptcp_scheduler_optimizations_disabled,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname     = "mptcp_set_backup",
        .data         = &sysctl_mptcp_set_backup,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    /* end: swetankk */
    /* shivanga */
    {
        .procname     = "num_segments_flow_one",
        .data         = &sysctl_num_segments_flow_one,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname       = "mptcp_bytes_not_sent",
        .maxlen         = MPTCP_BYTES_NOT_SENT_MAX,
        .mode           = 0644,
        .proc_handler   = proc_mptcp_bytes_not_sent,
    },
    {
        .procname     = "mptcp_pf",
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = proc_mptcp_set_pf,
    },
    {
        .procname       = "mptcp_rate",
        .maxlen         = sizeof(u32),
        .mode           = 0644,
        .proc_handler   = proc_mptcp_rate,
    },
    {
        .procname     = "mptcp_rate_sample",
        .data         = &sysctl_mptcp_rate_sample,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname     = "mptcp_ratio_static",
        .data         = &sysctl_mptcp_ratio_static,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname     = "mptcp_ratio_trigger_search",
        .data         = &sysctl_mptcp_ratio_trigger_search,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname     = "mptcp_ratio_search_step",
        .data         = &sysctl_mptcp_ratio_search_step,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname     = "mptcp_trigger_threshold",
        .data         = &sysctl_mptcp_trigger_threshold,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname     = "mptcp_probe_interval_secs",
        .data         = &sysctl_mptcp_probe_interval_secs,
        .maxlen       = sizeof(int),
        .mode         = 0644,
        .proc_handler = &proc_dointvec,
    },
    {
        .procname       = "mptcp_buffer_size",
        .maxlen         = REPORT_BUF_SIZE_MAX,
        .mode           = 0644,
        .proc_handler   = proc_mptcp_buffer_size,
    },
    /* end: shivanga */
	{ }
};

static inline u32 mptcp_hash_tk(u32 token)
{
	return token % MPTCP_HASH_SIZE;
}

struct hlist_nulls_head tk_hashtable[MPTCP_HASH_SIZE];
EXPORT_SYMBOL(tk_hashtable);

/* The following hash table is used to avoid collision of token */
static struct hlist_nulls_head mptcp_reqsk_tk_htb[MPTCP_HASH_SIZE];

/* Lock, protecting the two hash-tables that hold the token. Namely,
 * mptcp_reqsk_tk_htb and tk_hashtable
 */
static spinlock_t mptcp_tk_hashlock;

static bool mptcp_reqsk_find_tk(const u32 token)
{
	const u32 hash = mptcp_hash_tk(token);
	const struct mptcp_request_sock *mtreqsk;
	const struct hlist_nulls_node *node;

begin:
	hlist_nulls_for_each_entry_rcu(mtreqsk, node,
				       &mptcp_reqsk_tk_htb[hash], hash_entry) {
		if (token == mtreqsk->mptcp_loc_token)
			return true;
	}
	/* A request-socket is destroyed by RCU. So, it might have been recycled
	 * and put into another hash-table list. So, after the lookup we may
	 * end up in a different list. So, we may need to restart.
	 *
	 * See also the comment in __inet_lookup_established.
	 */
	if (get_nulls_value(node) != hash)
		goto begin;
	return false;
}

static void mptcp_reqsk_insert_tk(struct request_sock *reqsk, const u32 token)
{
	u32 hash = mptcp_hash_tk(token);

	hlist_nulls_add_head_rcu(&mptcp_rsk(reqsk)->hash_entry,
				 &mptcp_reqsk_tk_htb[hash]);
}

static void mptcp_reqsk_remove_tk(const struct request_sock *reqsk)
{
	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_init_rcu(&mptcp_rsk(reqsk)->hash_entry);
	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();
}

void mptcp_reqsk_destructor(struct request_sock *req)
{
	if (!mptcp_rsk(req)->is_sub)
		mptcp_reqsk_remove_tk(req);
}

static void __mptcp_hash_insert(struct tcp_sock *meta_tp, const u32 token)
{
	u32 hash = mptcp_hash_tk(token);
	hlist_nulls_add_head_rcu(&meta_tp->tk_table, &tk_hashtable[hash]);
	meta_tp->inside_tk_table = 1;
}

static bool mptcp_find_token(u32 token)
{
	const u32 hash = mptcp_hash_tk(token);
	const struct tcp_sock *meta_tp;
	const struct hlist_nulls_node *node;

begin:
	hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[hash], tk_table) {
		if (token == meta_tp->mptcp_loc_token)
			return true;
	}
	/* A TCP-socket is destroyed by RCU. So, it might have been recycled
	 * and put into another hash-table list. So, after the lookup we may
	 * end up in a different list. So, we may need to restart.
	 *
	 * See also the comment in __inet_lookup_established.
	 */
	if (get_nulls_value(node) != hash)
		goto begin;
	return false;
}

static void mptcp_set_key_reqsk(struct request_sock *req,
				const struct sk_buff *skb,
				u32 seed)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);

	if (skb->protocol == htons(ETH_P_IP)) {
		mtreq->mptcp_loc_key = mptcp_v4_get_key(ip_hdr(skb)->saddr,
							ip_hdr(skb)->daddr,
							htons(ireq->ir_num),
							ireq->ir_rmt_port,
							seed);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		mtreq->mptcp_loc_key = mptcp_v6_get_key(ipv6_hdr(skb)->saddr.s6_addr32,
							ipv6_hdr(skb)->daddr.s6_addr32,
							htons(ireq->ir_num),
							ireq->ir_rmt_port,
							seed);
#endif
	}

	mptcp_key_sha1(mtreq->mptcp_loc_key, &mtreq->mptcp_loc_token, NULL);
}

/* New MPTCP-connection request, prepare a new token for the meta-socket that
 * will be created in mptcp_check_req_master(), and store the received token.
 */
static void mptcp_reqsk_new_mptcp(struct request_sock *req,
				  const struct sock *sk,
				  const struct mptcp_options_received *mopt,
				  const struct sk_buff *skb)
{
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);
	const struct tcp_sock *tp = tcp_sk(sk);

	inet_rsk(req)->saw_mpc = 1;

	/* MPTCP version agreement */
	if (mopt->mptcp_ver >= tp->mptcp_ver)
		mtreq->mptcp_ver = tp->mptcp_ver;
	else
		mtreq->mptcp_ver = mopt->mptcp_ver;

	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);
	do {
		mptcp_set_key_reqsk(req, skb, mptcp_seed++);
	} while (mptcp_reqsk_find_tk(mtreq->mptcp_loc_token) ||
		 mptcp_find_token(mtreq->mptcp_loc_token));
	mptcp_reqsk_insert_tk(req, mtreq->mptcp_loc_token);
	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();
	mtreq->mptcp_rem_key = mopt->mptcp_sender_key;
}

static int mptcp_reqsk_new_cookie(struct request_sock *req,
				  const struct sock *sk,
				  const struct mptcp_options_received *mopt,
				  const struct sk_buff *skb)
{
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);

	/* MPTCP version agreement */
	if (mopt->mptcp_ver >= tcp_sk(sk)->mptcp_ver)
		mtreq->mptcp_ver = tcp_sk(sk)->mptcp_ver;
	else
		mtreq->mptcp_ver = mopt->mptcp_ver;

	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);

	mptcp_set_key_reqsk(req, skb, tcp_rsk(req)->snt_isn);

	if (mptcp_reqsk_find_tk(mtreq->mptcp_loc_token) ||
	    mptcp_find_token(mtreq->mptcp_loc_token)) {
		spin_unlock(&mptcp_tk_hashlock);
		local_bh_enable();
		rcu_read_unlock();
		return false;
	}

	inet_rsk(req)->saw_mpc = 1;

	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();

	mtreq->mptcp_rem_key = mopt->mptcp_sender_key;

	return true;
}

static void mptcp_set_key_sk(const struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isk = inet_sk(sk);

	if (sk->sk_family == AF_INET)
		tp->mptcp_loc_key = mptcp_v4_get_key(isk->inet_saddr,
						     isk->inet_daddr,
						     isk->inet_sport,
						     isk->inet_dport,
						     mptcp_seed++);
#if IS_ENABLED(CONFIG_IPV6)
	else
		tp->mptcp_loc_key = mptcp_v6_get_key(inet6_sk(sk)->saddr.s6_addr32,
						     sk->sk_v6_daddr.s6_addr32,
						     isk->inet_sport,
						     isk->inet_dport,
						     mptcp_seed++);
#endif

	mptcp_key_sha1(tp->mptcp_loc_key,
		       &tp->mptcp_loc_token, NULL);
}

static void mptcp_enable_static_key(void)
{
	if (!static_branch_unlikely(&mptcp_static_key)) {
		static int __mptcp_static_key = 0;

		if (cmpxchg(&__mptcp_static_key, 0, 1) == 0)
			static_branch_enable(&mptcp_static_key);
	}
}

void mptcp_enable_sock(struct sock *sk)
{
	if (!sock_flag(sk, SOCK_MPTCP)) {
		sock_set_flag(sk, SOCK_MPTCP);
		tcp_sk(sk)->mptcp_ver = sysctl_mptcp_version;

		/* Necessary here, because MPTCP can be enabled/disabled through
		 * a setsockopt.
		 */
		if (sk->sk_family == AF_INET)
			inet_csk(sk)->icsk_af_ops = &mptcp_v4_specific;
#if IS_ENABLED(CONFIG_IPV6)
		else if (mptcp_v6_is_v4_mapped(sk))
			inet_csk(sk)->icsk_af_ops = &mptcp_v6_mapped;
		else
			inet_csk(sk)->icsk_af_ops = &mptcp_v6_specific;
#endif

		mptcp_enable_static_key();
	}
}

void mptcp_disable_sock(struct sock *sk)
{
	if (sock_flag(sk, SOCK_MPTCP)) {
		sock_reset_flag(sk, SOCK_MPTCP);

		/* Necessary here, because MPTCP can be enabled/disabled through
		 * a setsockopt.
		 */
		if (sk->sk_family == AF_INET)
			inet_csk(sk)->icsk_af_ops = &ipv4_specific;
#if IS_ENABLED(CONFIG_IPV6)
		else if (mptcp_v6_is_v4_mapped(sk))
			inet_csk(sk)->icsk_af_ops = &ipv6_mapped;
		else
			inet_csk(sk)->icsk_af_ops = &ipv6_specific;
#endif
	}
}

void mptcp_connect_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);
	do {
		mptcp_set_key_sk(sk);
	} while (mptcp_reqsk_find_tk(tp->mptcp_loc_token) ||
		 mptcp_find_token(tp->mptcp_loc_token));

	__mptcp_hash_insert(tp, tp->mptcp_loc_token);
	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();

	MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEACTIVE);
}

/**
 * This function increments the refcount of the mpcb struct.
 * It is the responsibility of the caller to decrement when releasing
 * the structure.
 */
struct sock *mptcp_hash_find(const struct net *net, const u32 token)
{
	const u32 hash = mptcp_hash_tk(token);
	const struct tcp_sock *meta_tp;
	struct sock *meta_sk = NULL;
	const struct hlist_nulls_node *node;

	rcu_read_lock();
	local_bh_disable();
begin:
	hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[hash],
				       tk_table) {
		meta_sk = (struct sock *)meta_tp;
		if (token == meta_tp->mptcp_loc_token &&
		    net_eq(net, sock_net(meta_sk))) {
			if (unlikely(!refcount_inc_not_zero(&meta_sk->sk_refcnt)))
				goto out;
			if (unlikely(token != meta_tp->mptcp_loc_token ||
				     !net_eq(net, sock_net(meta_sk)))) {
				sock_gen_put(meta_sk);
				goto begin;
			}
			goto found;
		}
	}
	/* A TCP-socket is destroyed by RCU. So, it might have been recycled
	 * and put into another hash-table list. So, after the lookup we may
	 * end up in a different list. So, we may need to restart.
	 *
	 * See also the comment in __inet_lookup_established.
	 */
	if (get_nulls_value(node) != hash)
		goto begin;
out:
	meta_sk = NULL;
found:
	local_bh_enable();
	rcu_read_unlock();
	return meta_sk;
}
EXPORT_SYMBOL_GPL(mptcp_hash_find);

void mptcp_hash_remove_bh(struct tcp_sock *meta_tp)
{
	/* remove from the token hashtable */
	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);
	hlist_nulls_del_init_rcu(&meta_tp->tk_table);
	meta_tp->inside_tk_table = 0;
	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();
}

struct sock *mptcp_select_ack_sock(const struct sock *meta_sk)
{
	const struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sock *rttsk = NULL, *lastsk = NULL;
	u32 min_time = 0, last_active = 0;
	struct mptcp_tcp_sock *mptcp;

	mptcp_for_each_sub(meta_tp->mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(sk);
		u32 elapsed;

		if (!mptcp_sk_can_send_ack(sk) || tp->pf)
			continue;

		elapsed = keepalive_time_elapsed(tp);

		/* We take the one with the lowest RTT within a reasonable
		 * (meta-RTO)-timeframe
		 */
		if (elapsed < inet_csk(meta_sk)->icsk_rto) {
			if (!min_time || tp->srtt_us < min_time) {
				min_time = tp->srtt_us;
				rttsk = sk;
			}
			continue;
		}

		/* Otherwise, we just take the most recent active */
		if (!rttsk && (!last_active || elapsed < last_active)) {
			last_active = elapsed;
			lastsk = sk;
		}
	}

	if (rttsk)
		return rttsk;

	return lastsk;
}
EXPORT_SYMBOL(mptcp_select_ack_sock);

static void mptcp_sock_def_error_report(struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct tcp_sock *tp = tcp_sk(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		if (tp->send_mp_fclose && sk->sk_err == ETIMEDOUT) {
			/* Called by the keep alive timer (tcp_write_timeout),
			 * when the limit of fastclose retransmissions has been
			 * reached. Send a TCP RST to clear the status of any
			 * stateful firewall (typically conntrack) which are
			 * not aware of mptcp and cannot understand the
			 * fastclose option.
			 */
			tp->ops->send_active_reset(sk, GFP_ATOMIC);
		}
	}

	/* record this info that can be used by PM after the sf close */
	tp->mptcp->sk_err = sk->sk_err;

	if (!tp->tcp_disconnect && mptcp_in_infinite_mapping_weak(mpcb)) {
		struct sock *meta_sk = mptcp_meta_sk(sk);

		meta_sk->sk_err = sk->sk_err;
		meta_sk->sk_err_soft = sk->sk_err_soft;

		if (!sock_flag(meta_sk, SOCK_DEAD))
			meta_sk->sk_error_report(meta_sk);

		WARN(meta_sk->sk_state == TCP_CLOSE,
		     "Meta already closed i_rcv %u i_snd %u send_i %u flags %#lx\n",
		     mpcb->infinite_mapping_rcv, mpcb->infinite_mapping_snd,
		     mpcb->send_infinite_mapping, meta_sk->sk_flags);

		if (meta_sk->sk_state != TCP_CLOSE)
			tcp_done(meta_sk);
	}

	sk->sk_err = 0;
	return;
}

void mptcp_mpcb_put(struct mptcp_cb *mpcb)
{
	if (refcount_dec_and_test(&mpcb->mpcb_refcnt)) {
		mptcp_cleanup_path_manager(mpcb);
		mptcp_cleanup_scheduler(mpcb);
		kfree(mpcb->master_info);
		kmem_cache_free(mptcp_cb_cache, mpcb);
	}
}
EXPORT_SYMBOL(mptcp_mpcb_put);

static void mptcp_mpcb_cleanup(struct mptcp_cb *mpcb)
{
	struct mptcp_tw *mptw;

	/* The mpcb is disappearing - we can make the final
	 * update to the rcv_nxt of the time-wait-sock and remove
	 * its reference to the mpcb.
	 */
	spin_lock_bh(&mpcb->mpcb_list_lock);
	list_for_each_entry_rcu(mptw, &mpcb->tw_list, list) {
		list_del_rcu(&mptw->list);
		mptw->in_list = 0;
		mptcp_mpcb_put(mpcb);
		rcu_assign_pointer(mptw->mpcb, NULL);
	}
	spin_unlock_bh(&mpcb->mpcb_list_lock);

	mptcp_mpcb_put(mpcb);
}

static void mptcp_sock_destruct(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!is_meta_sk(sk)) {
		BUG_ON(!hlist_unhashed(&tp->mptcp->cb_list));

		kmem_cache_free(mptcp_sock_cache, tp->mptcp);
		tp->mptcp = NULL;

		/* Taken when mpcb pointer was set */
		sock_put(mptcp_meta_sk(sk));
		mptcp_mpcb_put(tp->mpcb);
	} else {
		mptcp_debug("%s destroying meta-sk token %#x\n", __func__,
			    tcp_sk(sk)->mpcb->mptcp_loc_token);

		mptcp_mpcb_cleanup(tp->mpcb);
	}

	/* Must be called here, because this will decrement the jump-label. */
	inet_sock_destruct(sk);
}

void mptcp_destroy_sock(struct sock *sk)
{
	if (is_meta_sk(sk)) {
		struct mptcp_tcp_sock *mptcp;
		struct hlist_node *tmp;

		__skb_queue_purge(&tcp_sk(sk)->mpcb->reinject_queue);

		/* We have to close all remaining subflows. Normally, they
		 * should all be about to get closed. But, if the kernel is
		 * forcing a closure (e.g., tcp_write_err), the subflows might
		 * not have been closed properly (as we are waiting for the
		 * DATA_ACK of the DATA_FIN).
		 */
		mptcp_for_each_sub_safe(tcp_sk(sk)->mpcb, mptcp, tmp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);

			/* Already did call tcp_close - waiting for graceful
			 * closure, or if we are retransmitting fast-close on
			 * the subflow. The reset (or timeout) will kill the
			 * subflow..
			 */
			if (tcp_sk(sk_it)->closing ||
			    tcp_sk(sk_it)->send_mp_fclose)
				continue;

			/* Allow the delayed work first to prevent time-wait state */
			if (delayed_work_pending(&tcp_sk(sk_it)->mptcp->work))
				continue;

			mptcp_sub_close(sk_it, 0);
		}
	} else {
		mptcp_del_sock(sk);
	}
}

static void mptcp_set_state(struct sock *sk)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);

	/* Meta is not yet established - wake up the application */
	if ((1 << meta_sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV) &&
	    sk->sk_state == TCP_ESTABLISHED) {
		tcp_set_state(meta_sk, TCP_ESTABLISHED);

		if (!sock_flag(meta_sk, SOCK_DEAD)) {
			meta_sk->sk_state_change(meta_sk);
			sk_wake_async(meta_sk, SOCK_WAKE_IO, POLL_OUT);
		}

		tcp_sk(meta_sk)->lsndtime = tcp_jiffies32;
	}

	if (sk->sk_state == TCP_CLOSE) {
		if (!sock_flag(sk, SOCK_DEAD))
			mptcp_sub_close(sk, 0);
	}
}

static int mptcp_set_congestion_control(struct sock *meta_sk, const char *name,
					bool load, bool reinit, bool cap_net_admin)
{
	struct mptcp_tcp_sock *mptcp;
	int err, result = 0;

	result = __tcp_set_congestion_control(meta_sk, name, load, reinit, cap_net_admin);

	tcp_sk(meta_sk)->mpcb->tcp_ca_explicit_set = true;

	mptcp_for_each_sub(tcp_sk(meta_sk)->mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);

		err = __tcp_set_congestion_control(sk_it, name, load, reinit, cap_net_admin);
		if (err)
			result = err;
	}
	return result;
}

static void mptcp_assign_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_connection_sock *meta_icsk = inet_csk(mptcp_meta_sk(sk));
	const struct tcp_congestion_ops *ca = meta_icsk->icsk_ca_ops;

	/* Congestion control is the same as meta. Thus, it has been
	 * try_module_get'd by tcp_assign_congestion_control.
	 * Congestion control on meta was not explicitly configured by
	 * application, leave default or route based.
	 */
	if (icsk->icsk_ca_ops == ca ||
	    !tcp_sk(mptcp_meta_sk(sk))->mpcb->tcp_ca_explicit_set)
		return;

	/* Use the same congestion control as set on the meta-sk */
	if (!try_module_get(ca->owner)) {
		/* This should never happen. The congestion control is linked
		 * to the meta-socket (through tcp_assign_congestion_control)
		 * who "holds" the refcnt on the module.
		 */
		WARN(1, "Could not get the congestion control!");
		return;
	}
	module_put(icsk->icsk_ca_ops->owner);
	icsk->icsk_ca_ops = ca;

	/* Clear out private data before diag gets it and
	 * the ca has not been initialized.
	 */
	if (ca->get_info)
		memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));

	return;
}

siphash_key_t mptcp_secret __read_mostly;
u32 mptcp_seed = 0;

static void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u32 mptcp_hashed_key[SHA_DIGEST_WORDS];
	u8 input[64];
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Initialize input with appropriate padding */
	memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too
						   */
	memcpy(input, &key, sizeof(key)); /* Copy key to the msg beginning */
	input[8] = 0x80; /* Padding: First bit after message = 1 */
	input[63] = 0x40; /* Padding: Length of the message = 64 bits */

	sha_init(mptcp_hashed_key);
	sha_transform(mptcp_hashed_key, input, workspace);

	for (i = 0; i < 5; i++)
		mptcp_hashed_key[i] = (__force u32)cpu_to_be32(mptcp_hashed_key[i]);

	if (token)
		*token = mptcp_hashed_key[0];
	if (idsn)
		*idsn = ntohll(*((__be64 *)&mptcp_hashed_key[3]));
}

void mptcp_hmac_sha1(const u8 *key_1, const u8 *key_2, u32 *hash_out,
		     int arg_num, ...)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u8 input[128]; /* 2 512-bit blocks */
	int i;
	int index;
	int length;
	u8 *msg;
	va_list list;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	va_start(list, arg_num);
	index = 64;
	for (i = 0; i < arg_num; i++) {
		length = va_arg(list, int);
		msg = va_arg(list, u8 *);
		BUG_ON(index + length > 125); /* Message is too long */
		memcpy(&input[index], msg, length);
		index += length;
	}
	va_end(list);

	input[index] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[index + 1], 0, (126 - index));

	/* Padding: Length of the message = 512 + message length (bits) */
	input[126] = 0x02;
	input[127] = ((index - 64) * 8); /* Message length (bits) */

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
		hash_out[i] = (__force u32)cpu_to_be32(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = (__force u32)cpu_to_be32(hash_out[i]);
}
EXPORT_SYMBOL(mptcp_hmac_sha1);

static void mptcp_mpcb_inherit_sockopts(struct sock *meta_sk, struct sock *master_sk)
{
	/* Socket-options handled by sk_clone_lock while creating the meta-sk.
	 * ======
	 * SO_SNDBUF, SO_SNDBUFFORCE, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT,
	 * SO_RCVTIMEO, SO_SNDTIMEO, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	 * TCP_NODELAY, TCP_CORK
	 *
	 * Socket-options handled in this function here
	 * ======
	 * TCP_DEFER_ACCEPT
	 * SO_KEEPALIVE
	 *
	 * Socket-options on the todo-list
	 * ======
	 * SO_BINDTODEVICE - should probably prevent creation of new subsocks
	 *		     across other devices. - what about the api-draft?
	 * SO_DEBUG
	 * SO_REUSEADDR - probably we don't care about this
	 * SO_DONTROUTE, SO_BROADCAST
	 * SO_OOBINLINE
	 * SO_LINGER
	 * SO_TIMESTAMP* - I don't think this is of concern for a SOCK_STREAM
	 * SO_PASSSEC - I don't think this is of concern for a SOCK_STREAM
	 * SO_RXQ_OVFL
	 * TCP_COOKIE_TRANSACTIONS
	 * TCP_MAXSEG
	 * TCP_THIN_* - Handled by sk_clone_lock, but we need to support this
	 *		in mptcp_meta_retransmit_timer. AND we need to check
	 *		what is about the subsockets.
	 * TCP_LINGER2
	 * TCP_WINDOW_CLAMP
	 * TCP_USER_TIMEOUT
	 * TCP_MD5SIG
	 *
	 * Socket-options of no concern for the meta-socket (but for the subsocket)
	 * ======
	 * SO_PRIORITY
	 * SO_MARK
	 * TCP_CONGESTION
	 * TCP_SYNCNT
	 * TCP_QUICKACK
	 */

	/* DEFER_ACCEPT should not be set on the meta, as we want to accept new subflows directly */
	inet_csk(meta_sk)->icsk_accept_queue.rskq_defer_accept = 0;

	/* Keepalives are handled entirely at the MPTCP-layer */
	if (sock_flag(meta_sk, SOCK_KEEPOPEN)) {
		inet_csk_reset_keepalive_timer(meta_sk,
					       keepalive_time_when(tcp_sk(meta_sk)));
		sock_reset_flag(master_sk, SOCK_KEEPOPEN);
		inet_csk_delete_keepalive_timer(master_sk);
	}

	/* Do not propagate subflow-errors up to the MPTCP-layer */
	inet_sk(master_sk)->recverr = 0;
}

/* Called without holding lock on meta_sk */
static void mptcp_sub_inherit_sockopts(const struct sock *meta_sk, struct sock *sub_sk)
{
	__u8 meta_tos;

	/* IP_TOS also goes to the subflow. */
	meta_tos = READ_ONCE(inet_sk(meta_sk)->tos);
	if (inet_sk(sub_sk)->tos != meta_tos) {
		inet_sk(sub_sk)->tos = meta_tos;
		sub_sk->sk_priority = meta_sk->sk_priority;
		sk_dst_reset(sub_sk);
	}

	/* Inherit SO_REUSEADDR */
	sub_sk->sk_reuse = meta_sk->sk_reuse;

	/* Inherit SO_MARK: can be used for routing or filtering */
	sub_sk->sk_mark = meta_sk->sk_mark;

	/* Inherit snd/rcv-buffer locks */
	sub_sk->sk_userlocks = meta_sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;

	/* Nagle/Cork is forced off on the subflows. It is handled at the meta-layer */
	tcp_sk(sub_sk)->nonagle = TCP_NAGLE_OFF|TCP_NAGLE_PUSH;

	/* Keepalives are handled entirely at the MPTCP-layer */
	if (sock_flag(sub_sk, SOCK_KEEPOPEN)) {
		sock_reset_flag(sub_sk, SOCK_KEEPOPEN);
		inet_csk_delete_keepalive_timer(sub_sk);
	}

	/* Do not propagate subflow-errors up to the MPTCP-layer */
	inet_sk(sub_sk)->recverr = 0;
}

void mptcp_prepare_for_backlog(struct sock *sk, struct sk_buff *skb)
{
	/* In case of success (in mptcp_backlog_rcv) and error (in kfree_skb) of
	 * sk_add_backlog, we will decrement the sk refcount.
	 */
	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = sock_efree;
}

int mptcp_backlog_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	/* skb-sk may be NULL if we receive a packet immediatly after the
	 * SYN/ACK + MP_CAPABLE.
	 */
	struct sock *sk = skb->sk ? skb->sk : meta_sk;
	int ret = 0;

	if (unlikely(!refcount_inc_not_zero(&sk->sk_refcnt))) {
		kfree_skb(skb);
		return 0;
	}

	/* Decrement sk refcnt when calling the skb destructor.
	 * Refcnt is incremented and skb destructor is set in tcp_v{4,6}_rcv via
	 * mptcp_prepare_for_backlog() here above.
	 */
	skb_orphan(skb);

	if (sk->sk_family == AF_INET)
		ret = tcp_v4_do_rcv(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	else
		ret = tcp_v6_do_rcv(sk, skb);
#endif

	sock_put(sk);
	return ret;
}

static void mptcp_init_buffer_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	int space;

	tcp_init_buffer_space(sk);

	if (is_master_tp(tp)) {
		meta_tp->rcvq_space.space = meta_tp->rcv_wnd;
		tcp_mstamp_refresh(meta_tp);
		meta_tp->rcvq_space.time = meta_tp->tcp_mstamp;
		meta_tp->rcvq_space.seq = meta_tp->copied_seq;

		/* If there is only one subflow, we just use regular TCP
		 * autotuning. User-locks are handled already by
		 * tcp_init_buffer_space
		 */
		meta_tp->window_clamp = tp->window_clamp;
		meta_tp->rcv_ssthresh = tp->rcv_ssthresh;
		meta_sk->sk_rcvbuf = sk->sk_rcvbuf;
		meta_sk->sk_sndbuf = sk->sk_sndbuf;

		return;
	}

	if (meta_sk->sk_userlocks & SOCK_RCVBUF_LOCK)
		goto snd_buf;

	/* Adding a new subflow to the rcv-buffer space. We make a simple
	 * addition, to give some space to allow traffic on the new subflow.
	 * Autotuning will increase it further later on.
	 */
	space = min(meta_sk->sk_rcvbuf + sk->sk_rcvbuf,
		    sock_net(meta_sk)->ipv4.sysctl_tcp_rmem[2]);
	if (space > meta_sk->sk_rcvbuf) {
		meta_tp->window_clamp += tp->window_clamp;
		meta_tp->rcv_ssthresh += tp->rcv_ssthresh;
		meta_sk->sk_rcvbuf = space;
	}

snd_buf:
	if (meta_sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return;

	/* Adding a new subflow to the send-buffer space. We make a simple
	 * addition, to give some space to allow traffic on the new subflow.
	 * Autotuning will increase it further later on.
	 */
	space = min(meta_sk->sk_sndbuf + sk->sk_sndbuf,
		    sock_net(meta_sk)->ipv4.sysctl_tcp_wmem[2]);
	if (space > meta_sk->sk_sndbuf) {
		meta_sk->sk_sndbuf = space;
		meta_sk->sk_write_space(meta_sk);
	}
}

struct lock_class_key meta_key;
char *meta_key_name = "sk_lock-AF_INET-MPTCP";
struct lock_class_key meta_slock_key;
char *meta_slock_key_name = "slock-AF_INET-MPTCP";

static const struct tcp_sock_ops mptcp_meta_specific = {
	.__select_window		= __mptcp_select_window,
	.select_window			= mptcp_select_window,
	.select_initial_window		= mptcp_select_initial_window,
	.select_size			= mptcp_select_size,
	.init_buffer_space		= mptcp_init_buffer_space,
	.set_rto			= mptcp_tcp_set_rto,
	.should_expand_sndbuf		= mptcp_should_expand_sndbuf,
	.send_fin			= mptcp_send_fin,
	.write_xmit			= mptcp_write_xmit,
	.send_active_reset		= mptcp_send_active_reset,
	.write_wakeup			= mptcp_write_wakeup,
	.retransmit_timer		= mptcp_meta_retransmit_timer,
	.time_wait			= mptcp_time_wait,
	.cleanup_rbuf			= mptcp_cleanup_rbuf,
	.set_cong_ctrl                  = mptcp_set_congestion_control,
};

static const struct tcp_sock_ops mptcp_sub_specific = {
	.__select_window		= __mptcp_select_window,
	.select_window			= mptcp_select_window,
	.select_initial_window		= mptcp_select_initial_window,
	.select_size			= mptcp_select_size,
	.init_buffer_space		= mptcp_init_buffer_space,
	.set_rto			= mptcp_tcp_set_rto,
	.should_expand_sndbuf		= mptcp_should_expand_sndbuf,
	.send_fin			= tcp_send_fin,
	.write_xmit			= tcp_write_xmit,
	.send_active_reset		= tcp_send_active_reset,
	.write_wakeup			= tcp_write_wakeup,
	.retransmit_timer		= mptcp_sub_retransmit_timer,
	.time_wait			= tcp_time_wait,
	.cleanup_rbuf			= tcp_cleanup_rbuf,
	.set_cong_ctrl                  = __tcp_set_congestion_control,
};

/* Inspired by inet_csk_prepare_forced_close */
static void mptcp_icsk_forced_close(struct sock *sk)
{
	/* The problem with inet_csk_prepare_forced_close is that it unlocks
	 * before calling tcp_done. That is fine for sockets that are not
	 * yet in the ehash table. But for us we already are there. Thus,
	 * if we unlock we run the risk of processing packets while inside
	 * tcp_done() and friends. That can cause all kind of problems...
	 */

	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	percpu_counter_inc(sk->sk_prot->orphan_count);

	tcp_done(sk);

	/* sk_clone_lock locked the socket and set refcnt to 2 */
	bh_unlock_sock(sk);
	sock_put(sk);
}

static int mptcp_alloc_mpcb(struct sock *meta_sk, __u64 remote_key,
			    __u8 mptcp_ver, u32 window)
{
	struct mptcp_cb *mpcb;
	struct sock *master_sk;
	struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);
	struct tcp_sock *master_tp, *meta_tp = tcp_sk(meta_sk);
	u64 snd_idsn, rcv_idsn;

	dst_release(meta_sk->sk_rx_dst);
	meta_sk->sk_rx_dst = NULL;
	/* This flag is set to announce sock_lock_init to
	 * reclassify the lock-class of the master socket.
	 */
	meta_tp->is_master_sk = 1;
	master_sk = sk_clone_lock(meta_sk, GFP_ATOMIC | __GFP_ZERO);
	meta_tp->is_master_sk = 0;
	if (!master_sk) {
		net_err_ratelimited("%s Could not allocate master_sk on meta %p\n",
				    __func__, meta_sk);
		goto err_alloc_master;
	}

	/* Same as in inet_csk_clone_lock - need to init to 0 */
	memset(&inet_csk(master_sk)->icsk_accept_queue, 0,
	       sizeof(inet_csk(master_sk)->icsk_accept_queue));

	/* icsk_bind_hash inherited from the meta, but it will be properly set
	 * in mptcp_create_master_sk. Same operation is done in
	 * inet_csk_clone_lock.
	 */
	inet_csk(master_sk)->icsk_bind_hash = NULL;

	master_tp = tcp_sk(master_sk);
	master_tp->inside_tk_table = 0;

	master_tp->mptcp = kmem_cache_zalloc(mptcp_sock_cache, GFP_ATOMIC);
	if (!master_tp->mptcp) {
		net_err_ratelimited("%s Could not allocate mptcp_tcp_sock on meta %p\n",
				    __func__, meta_sk);
		goto err_alloc_mptcp;
	}

	mpcb = kmem_cache_zalloc(mptcp_cb_cache, GFP_ATOMIC);
	if (!mpcb) {
		net_err_ratelimited("%s Could not allocate mpcb on meta %p\n",
				    __func__, meta_sk);
		goto err_alloc_mpcb;
	}

	if (__inet_inherit_port(meta_sk, master_sk) < 0) {
		net_err_ratelimited("%s Could not inherit port on meta %p\n",
				    __func__, meta_sk);
		goto err_inherit_port;
	}

	/* Store the mptcp version agreed on initial handshake */
	mpcb->mptcp_ver = mptcp_ver;

	/* Store the keys and generate the peer's token */
	mpcb->mptcp_loc_key = meta_tp->mptcp_loc_key;
	mpcb->mptcp_loc_token = meta_tp->mptcp_loc_token;

	/* Generate Initial data-sequence-numbers */
	mptcp_key_sha1(mpcb->mptcp_loc_key, NULL, &snd_idsn);
	snd_idsn++;
	mpcb->snd_high_order[0] = snd_idsn >> 32;
	mpcb->snd_high_order[1] = mpcb->snd_high_order[0] - 1;

	mpcb->mptcp_rem_key = remote_key;
	mptcp_key_sha1(mpcb->mptcp_rem_key, &mpcb->mptcp_rem_token, &rcv_idsn);
	rcv_idsn++;
	mpcb->rcv_high_order[0] = rcv_idsn >> 32;
	mpcb->rcv_high_order[1] = mpcb->rcv_high_order[0] + 1;

	mpcb->meta_sk = meta_sk;
	mpcb->master_sk = master_sk;

	skb_queue_head_init(&mpcb->reinject_queue);
	mutex_init(&mpcb->mpcb_mutex);

	/* Init time-wait stuff */
	INIT_LIST_HEAD(&mpcb->tw_list);

	INIT_HLIST_HEAD(&mpcb->callback_list);
	INIT_HLIST_HEAD(&mpcb->conn_list);
	spin_lock_init(&mpcb->mpcb_list_lock);

	mpcb->orig_sk_rcvbuf = meta_sk->sk_rcvbuf;
	mpcb->orig_sk_sndbuf = meta_sk->sk_sndbuf;
	mpcb->orig_window_clamp = meta_tp->window_clamp;

	/* The meta is directly linked - set refcnt to 1 */
	refcount_set(&mpcb->mpcb_refcnt, 1);

	if (!meta_tp->inside_tk_table) {
		/* Adding the meta_tp in the token hashtable - coming from server-side */
		rcu_read_lock();
		local_bh_disable();
		spin_lock(&mptcp_tk_hashlock);

		/* With lockless listeners, we might process two ACKs at the
		 * same time. With TCP, inet_csk_complete_hashdance takes care
		 * of this. But, for MPTCP this would be too late if we add
		 * this MPTCP-socket in the token table (new subflows might
		 * come in and match on this socket here.
		 * So, we need to check if someone else already added the token
		 * and revert in that case. The other guy won the race...
		 */
		if (mptcp_find_token(mpcb->mptcp_loc_token)) {
			spin_unlock(&mptcp_tk_hashlock);
			local_bh_enable();
			rcu_read_unlock();

			goto err_insert_token;
		}
		__mptcp_hash_insert(meta_tp, mpcb->mptcp_loc_token);

		spin_unlock(&mptcp_tk_hashlock);
		local_bh_enable();
		rcu_read_unlock();
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (meta_icsk->icsk_af_ops == &mptcp_v6_mapped) {
		struct tcp6_sock *master_tp6 = (struct tcp6_sock *)master_sk;
		struct ipv6_pinfo *newnp, *np = inet6_sk(meta_sk);

		inet_sk(master_sk)->pinet6 = &master_tp6->inet6;

		newnp = inet6_sk(master_sk);
		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		newnp->ipv6_mc_list = NULL;
		newnp->ipv6_ac_list = NULL;
		newnp->ipv6_fl_list = NULL;
		newnp->pktoptions = NULL;
		newnp->opt = NULL;

		newnp->rxopt.all = 0;
		newnp->repflow = 0;
		np->rxopt.all = 0;
		np->repflow = 0;
	} else if (meta_sk->sk_family == AF_INET6) {
		struct tcp6_sock *master_tp6 = (struct tcp6_sock *)master_sk;
		struct ipv6_pinfo *newnp, *np = inet6_sk(meta_sk);
		struct ipv6_txoptions *opt;

		inet_sk(master_sk)->pinet6 = &master_tp6->inet6;

		/* The following heavily inspired from tcp_v6_syn_recv_sock() */
		newnp = inet6_sk(master_sk);
		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		newnp->ipv6_mc_list = NULL;
		newnp->ipv6_ac_list = NULL;
		newnp->ipv6_fl_list = NULL;
		newnp->pktoptions = NULL;
		newnp->opt = NULL;

		newnp->rxopt.all = 0;
		newnp->repflow = 0;
		np->rxopt.all = 0;
		np->repflow = 0;

		opt = rcu_dereference(np->opt);
		if (opt) {
			opt = ipv6_dup_options(master_sk, opt);
			RCU_INIT_POINTER(newnp->opt, opt);
		}
		inet_csk(master_sk)->icsk_ext_hdr_len = 0;
		if (opt)
			inet_csk(master_sk)->icsk_ext_hdr_len = opt->opt_nflen +
								opt->opt_flen;
	}
#endif

	meta_tp->mptcp = NULL;

	meta_tp->write_seq = (u32)snd_idsn;
	meta_tp->snd_sml = meta_tp->write_seq;
	meta_tp->snd_una = meta_tp->write_seq;
	meta_tp->snd_nxt = meta_tp->write_seq;
	meta_tp->pushed_seq = meta_tp->write_seq;
	meta_tp->snd_up = meta_tp->write_seq;

	meta_tp->copied_seq = (u32)rcv_idsn;
	meta_tp->rcv_nxt = (u32)rcv_idsn;
	meta_tp->rcv_wup = (u32)rcv_idsn;
	meta_tp->rcv_right_edge = meta_tp->rcv_wup + meta_tp->rcv_wnd;

	meta_tp->snd_wl1 = meta_tp->rcv_nxt - 1;
	meta_tp->snd_wnd = window;
	meta_tp->retrans_stamp = 0; /* Set in tcp_connect() */

	meta_tp->packets_out = 0;
	meta_icsk->icsk_probes_out = 0;

	rcu_assign_pointer(inet_sk(meta_sk)->inet_opt, NULL);

	/* Set mptcp-pointers */
	master_tp->mpcb = mpcb;
	master_tp->meta_sk = meta_sk;
	meta_tp->mpcb = mpcb;
	meta_tp->meta_sk = meta_sk;

	/* Initialize the queues */
	master_tp->out_of_order_queue = RB_ROOT;
	master_sk->tcp_rtx_queue = RB_ROOT;
	INIT_LIST_HEAD(&master_tp->tsq_node);
	INIT_LIST_HEAD(&master_tp->tsorted_sent_queue);

	master_tp->fastopen_req = NULL;

	master_sk->sk_tsq_flags = 0;

	/* Init the accept_queue structure, we support a queue of 32 pending
	 * connections, it does not need to be huge, since we only store  here
	 * pending subflow creations.
	 */
	reqsk_queue_alloc(&meta_icsk->icsk_accept_queue);
	meta_sk->sk_max_ack_backlog = 32;
	meta_sk->sk_ack_backlog = 0;

	if (!sock_flag(meta_sk, SOCK_MPTCP))
		sock_set_flag(meta_sk, SOCK_MPTCP);

	/* Redefine function-pointers as the meta-sk is now fully ready */
	meta_tp->mpc = 1;
	meta_tp->ops = &mptcp_meta_specific;

	meta_sk->sk_backlog_rcv = mptcp_backlog_rcv;
	meta_sk->sk_destruct = mptcp_sock_destruct;

	/* Meta-level retransmit timer */
	meta_icsk->icsk_rto *= 2; /* Double of initial - rto */

	tcp_init_xmit_timers(master_sk);
	/* Has been set for sending out the SYN */
	inet_csk_clear_xmit_timer(meta_sk, ICSK_TIME_RETRANS);

	mptcp_mpcb_inherit_sockopts(meta_sk, master_sk);

	mptcp_init_path_manager(mpcb);
	mptcp_init_scheduler(mpcb);

	if (!try_module_get(inet_csk(master_sk)->icsk_ca_ops->owner))
		tcp_assign_congestion_control(master_sk);

	master_tp->saved_syn = NULL;

	mptcp_debug("%s: created mpcb with token %#x\n",
		    __func__, mpcb->mptcp_loc_token);

	return 0;

err_insert_token:
	kmem_cache_free(mptcp_cb_cache, mpcb);

	kmem_cache_free(mptcp_sock_cache, master_tp->mptcp);
	master_tp->mptcp = NULL;

	mptcp_icsk_forced_close(master_sk);
	return -EINVAL;

err_inherit_port:
	kmem_cache_free(mptcp_cb_cache, mpcb);

err_alloc_mpcb:
	kmem_cache_free(mptcp_sock_cache, master_tp->mptcp);
	master_tp->mptcp = NULL;

err_alloc_mptcp:
	inet_sk(master_sk)->inet_opt = NULL;
	master_sk->sk_state = TCP_CLOSE;
	sock_orphan(master_sk);
	bh_unlock_sock(master_sk);
	sk_free(master_sk);

err_alloc_master:
	return -ENOBUFS;
}

/*  Called without holding lock on mpcb */
static u8 mptcp_set_new_pathindex(struct mptcp_cb *mpcb)
{
	int i;

	/* Start at 1, because 0 is reserved for the meta-sk */
	for (i = 1; i < sizeof(mpcb->path_index_bits) * 8; i++) {
		if (!test_and_set_bit(i, &mpcb->path_index_bits))
			break;
	}

	if (i == sizeof(mpcb->path_index_bits) * 8)
		return 0;
	return i;
}

/* May be called without holding the meta-level lock */
int mptcp_add_sock(struct sock *meta_sk, struct sock *sk, u8 loc_id, u8 rem_id,
		   gfp_t flags)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct tcp_sock *tp = tcp_sk(sk);

	/* Could have been allocated by mptcp_alloc_mpcb */
	if (!tp->mptcp) {
		tp->mptcp = kmem_cache_zalloc(mptcp_sock_cache, flags);

		if (!tp->mptcp)
			return -ENOMEM;
	}

	tp->mptcp->path_index = mptcp_set_new_pathindex(mpcb);
	/* No more space for more subflows? */
	if (!tp->mptcp->path_index) {
		kmem_cache_free(mptcp_sock_cache, tp->mptcp);
		tp->mptcp = NULL;
		return -EPERM;
	}

	INIT_HLIST_NODE(&tp->mptcp->cb_list);

	tp->mptcp->tp = tp;
	tp->mpcb = mpcb;
	tp->meta_sk = meta_sk;

	if (!sock_flag(sk, SOCK_MPTCP))
		sock_set_flag(sk, SOCK_MPTCP);

	tp->mpc = 1;
	tp->ops = &mptcp_sub_specific;

	tp->mptcp->loc_id = loc_id;
	tp->mptcp->rem_id = rem_id;
	if (mpcb->sched_ops->init)
		mpcb->sched_ops->init(sk);

	/* The corresponding sock_put is in mptcp_sock_destruct(). It cannot be
	 * included in mptcp_del_sock(), because the mpcb must remain alive
	 * until the last subsocket is completely destroyed.
	 */
	sock_hold(meta_sk);
	refcount_inc(&mpcb->mpcb_refcnt);

	spin_lock_bh(&mpcb->mpcb_list_lock);
	hlist_add_head_rcu(&tp->mptcp->node, &mpcb->conn_list);
	spin_unlock_bh(&mpcb->mpcb_list_lock);

	tp->mptcp->attached = 1;

	mptcp_sub_inherit_sockopts(meta_sk, sk);
	INIT_DELAYED_WORK(&tp->mptcp->work, mptcp_sub_close_wq);

	/* Properly inherit CC from the meta-socket */
	mptcp_assign_congestion_control(sk);

	/* As we successfully allocated the mptcp_tcp_sock, we have to
	 * change the function-pointers here (for sk_destruct to work correctly)
	 */
	sk->sk_error_report = mptcp_sock_def_error_report;
	sk->sk_data_ready = mptcp_data_ready;
	sk->sk_write_space = mptcp_write_space;
	sk->sk_state_change = mptcp_set_state;
	sk->sk_destruct = mptcp_sock_destruct;

	if (sk->sk_family == AF_INET)
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI4:%d dst_addr:%pI4:%d\n",
			    __func__ , mpcb->mptcp_loc_token,
			    tp->mptcp->path_index,
			    &((struct inet_sock *)tp)->inet_saddr,
			    ntohs(((struct inet_sock *)tp)->inet_sport),
			    &((struct inet_sock *)tp)->inet_daddr,
			    ntohs(((struct inet_sock *)tp)->inet_dport));
#if IS_ENABLED(CONFIG_IPV6)
	else
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI6:%d dst_addr:%pI6:%d\n",
			    __func__ , mpcb->mptcp_loc_token,
			    tp->mptcp->path_index, &inet6_sk(sk)->saddr,
			    ntohs(((struct inet_sock *)tp)->inet_sport),
			    &sk->sk_v6_daddr,
			    ntohs(((struct inet_sock *)tp)->inet_dport));
#endif

	return 0;
}

void mptcp_del_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb;

	if (!tp->mptcp || !tp->mptcp->attached)
		return;

	mpcb = tp->mpcb;

	if (mpcb->sched_ops->release)
		mpcb->sched_ops->release(sk);

	if (mpcb->pm_ops->delete_subflow)
		mpcb->pm_ops->delete_subflow(sk);

	mptcp_debug("%s: Removing subsock tok %#x pi:%d state %d is_meta? %d\n",
		    __func__, mpcb->mptcp_loc_token, tp->mptcp->path_index,
		    sk->sk_state, is_meta_sk(sk));

	spin_lock_bh(&mpcb->mpcb_list_lock);
	hlist_del_init_rcu(&tp->mptcp->node);
	spin_unlock_bh(&mpcb->mpcb_list_lock);

	tp->mptcp->attached = 0;
	mpcb->path_index_bits &= ~(1 << tp->mptcp->path_index);

	if (!tcp_write_queue_empty(sk) || !tcp_rtx_queue_empty(sk))
		mptcp_reinject_data(sk, 0);

	if (is_master_tp(tp)) {
		struct sock *meta_sk = mptcp_meta_sk(sk);
		struct tcp_sock *meta_tp = tcp_sk(meta_sk);

		if (meta_tp->record_master_info &&
		    !sock_flag(meta_sk, SOCK_DEAD)) {
			mpcb->master_info = kmalloc(sizeof(*mpcb->master_info),
						    GFP_ATOMIC);

			if (mpcb->master_info)
				tcp_get_info(sk, mpcb->master_info, true);
		}

		mpcb->master_sk = NULL;
	} else if (tp->mptcp->pre_established) {
		sk_stop_timer(sk, &tp->mptcp->mptcp_ack_timer);
	}
}

/* Updates the MPTCP-session based on path-manager information (e.g., addresses,
 * low-prio flows,...).
 */
void mptcp_update_metasocket(const struct sock *meta_sk)
{
	if (tcp_sk(meta_sk)->mpcb->pm_ops->new_session)
		tcp_sk(meta_sk)->mpcb->pm_ops->new_session(meta_sk);
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 * (inspired from tcp_cleanup_rbuf())
 */
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	bool recheck_rcv_window = false;
	struct mptcp_tcp_sock *mptcp;
	__u32 rcv_window_now = 0;

	if (copied > 0 && !(meta_sk->sk_shutdown & RCV_SHUTDOWN)) {
		rcv_window_now = tcp_receive_window_now(meta_tp);

		/* Optimize, __mptcp_select_window() is not cheap. */
		if (2 * rcv_window_now <= meta_tp->window_clamp)
			recheck_rcv_window = true;
	}

	mptcp_for_each_sub(meta_tp->mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);
		struct tcp_sock *tp = tcp_sk(sk);
		const struct inet_connection_sock *icsk = inet_csk(sk);

		if (!mptcp_sk_can_send_ack(sk))
			continue;

		if (!inet_csk_ack_scheduled(sk))
			goto second_part;
		/* Delayed ACKs frequently hit locked sockets during bulk
		 * receive.
		 */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /* If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		     !atomic_read(&meta_sk->sk_rmem_alloc))) {
			tcp_send_ack(sk);
			continue;
		}

second_part:
		/* This here is the second part of tcp_cleanup_rbuf */
		if (recheck_rcv_window) {
			__u32 new_window = tp->ops->__select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than
			 * current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				tcp_send_ack(sk);
		}
	}
}

static int mptcp_sub_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_write_queue_tail(sk);
	int mss_now;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = tcp_current_mss(sk);

	if (tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		skb = alloc_skb_fclone(MAX_TCP_HEADER, GFP_ATOMIC);
		if (!skb)
			return 1;

		INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		skb_reserve(skb, MAX_TCP_HEADER);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPHDR_ACK | TCPHDR_FIN);
		sk_forced_mem_schedule(sk, skb->truesize);
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);

	return 0;
}

static void mptcp_sub_close_doit(struct sock *sk)
{
	struct sock *meta_sk = mptcp_meta_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (sock_flag(sk, SOCK_DEAD))
		return;

	if (meta_sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE) {
		tp->closing = 1;
		tcp_close(sk, 0);
	} else if (tcp_close_state(sk)) {
		sk->sk_shutdown |= SEND_SHUTDOWN;
		tcp_send_fin(sk);
	}
}

void mptcp_sub_close_wq(struct work_struct *work)
{
	struct tcp_sock *tp = container_of(work, struct mptcp_tcp_sock, work.work)->tp;
	struct sock *sk = (struct sock *)tp;
	struct mptcp_cb *mpcb = tp->mpcb;
	struct sock *meta_sk = mptcp_meta_sk(sk);

	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	mptcp_sub_close_doit(sk);

	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	mptcp_mpcb_put(mpcb);
	sock_put(sk);
}

void mptcp_sub_close(struct sock *sk, unsigned long delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct delayed_work *work = &tcp_sk(sk)->mptcp->work;

	/* We are already closing - e.g., call from sock_def_error_report upon
	 * tcp_disconnect in tcp_close.
	 */
	if (tp->closing)
		return;

	/* Work already scheduled ? */
	if (work_pending(&work->work)) {
		/* Work present - who will be first ? */
		if (jiffies + delay > work->timer.expires)
			return;

		/* Try canceling - if it fails, work will be executed soon */
		if (!cancel_delayed_work(work))
			return;
		sock_put(sk);
		mptcp_mpcb_put(tp->mpcb);
	}

	if (!delay) {
		unsigned char old_state = sk->sk_state;

		/* We directly send the FIN. Because it may take so a long time,
		 * untile the work-queue will get scheduled...
		 *
		 * If mptcp_sub_send_fin returns 1, it failed and thus we reset
		 * the old state so that tcp_close will finally send the fin
		 * in user-context.
		 */
		if (!sk->sk_err && old_state != TCP_CLOSE &&
		    tcp_close_state(sk) && mptcp_sub_send_fin(sk)) {
			if (old_state == TCP_ESTABLISHED)
				TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
			sk->sk_state = old_state;
		}
	}

	sock_hold(sk);
	refcount_inc(&tp->mpcb->mpcb_refcnt);
	queue_delayed_work(mptcp_wq, work, delay);
}

void mptcp_sub_force_close(struct sock *sk)
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
EXPORT_SYMBOL(mptcp_sub_force_close);

/* Update the mpcb send window, based on the contributions
 * of each subflow
 */
void mptcp_update_sndbuf(const struct tcp_sock *tp)
{
	struct sock *meta_sk = tp->meta_sk;
	int new_sndbuf = 0, old_sndbuf = meta_sk->sk_sndbuf;
	struct mptcp_tcp_sock *mptcp;

	mptcp_for_each_sub(tp->mpcb, mptcp) {
		struct sock *sk = mptcp_to_sock(mptcp);

		if (!mptcp_sk_can_send(sk))
			continue;

		new_sndbuf += sk->sk_sndbuf;

		if (new_sndbuf > sock_net(meta_sk)->ipv4.sysctl_tcp_wmem[2] ||
		    new_sndbuf < 0) {
			new_sndbuf = sock_net(meta_sk)->ipv4.sysctl_tcp_wmem[2];
			break;
		}
	}
	meta_sk->sk_sndbuf = max(min(new_sndbuf,
				     sock_net(meta_sk)->ipv4.sysctl_tcp_wmem[2]),
				 meta_sk->sk_sndbuf);

	/* The subflow's call to sk_write_space in tcp_new_space ends up in
	 * mptcp_write_space.
	 * It has nothing to do with waking up the application.
	 * So, we do it here.
	 */
	if (old_sndbuf != meta_sk->sk_sndbuf)
		meta_sk->sk_write_space(meta_sk);
}

/* Similar to: tcp_close */
void mptcp_close(struct sock *meta_sk, long timeout)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct mptcp_tcp_sock *mptcp;
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	mptcp_debug("%s: Close of meta_sk with tok %#x state %u\n",
		    __func__, mpcb->mptcp_loc_token, meta_sk->sk_state);

	WARN_ON(refcount_inc_not_zero(&mpcb->mpcb_refcnt) == 0);
	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	if (meta_tp->inside_tk_table)
		/* Detach the mpcb from the token hashtable */
		mptcp_hash_remove_bh(meta_tp);

	meta_sk->sk_shutdown = SHUTDOWN_MASK;
	/* We need to flush the recv. buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&meta_sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;

		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			len--;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(meta_sk);

	/* If socket has been already reset (e.g. in tcp_reset()) - kill it. */
	if (meta_sk->sk_state == TCP_CLOSE) {
		struct mptcp_tcp_sock *mptcp;
		struct hlist_node *tmp;

		mptcp_for_each_sub_safe(mpcb, mptcp, tmp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);

			if (tcp_sk(sk_it)->send_mp_fclose)
				continue;

			mptcp_sub_close(sk_it, 0);
		}
		goto adjudge_to_death;
	}

	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS(sock_net(meta_sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(meta_sk, TCP_CLOSE);
		tcp_sk(meta_sk)->ops->send_active_reset(meta_sk,
							meta_sk->sk_allocation);
	} else if (sock_flag(meta_sk, SOCK_LINGER) && !meta_sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		meta_sk->sk_prot->disconnect(meta_sk, 0);
		NET_INC_STATS(sock_net(meta_sk), LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(meta_sk)) {
		mptcp_send_fin(meta_sk);
	} else if (meta_tp->snd_una == meta_tp->write_seq) {
		struct mptcp_tcp_sock *mptcp;
		struct hlist_node *tmp;

		/* The DATA_FIN has been sent and acknowledged
		 * (e.g., by sk_shutdown). Close all the other subflows
		 */
		mptcp_for_each_sub_safe(mpcb, mptcp, tmp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);
			unsigned long delay = 0;
			/* If we are the passive closer, don't trigger
			 * subflow-fin until the subflow has been finned
			 * by the peer. - thus we add a delay
			 */
			if (mpcb->passive_close &&
			    sk_it->sk_state == TCP_ESTABLISHED)
				delay = inet_csk(sk_it)->icsk_rto << 3;

			mptcp_sub_close(sk_it, delay);
		}
	}

	sk_stream_wait_close(meta_sk, timeout);

adjudge_to_death:
	state = meta_sk->sk_state;
	sock_hold(meta_sk);
	sock_orphan(meta_sk);

	/* socket will be freed after mptcp_close - we have to prevent
	 * access from the subflows.
	 */
	mptcp_for_each_sub(mpcb, mptcp) {
		struct sock *sk_it = mptcp_to_sock(mptcp);

		/* Similar to sock_orphan, but we don't set it DEAD, because
		 * the callbacks are still set and must be called.
		 */
		write_lock_bh(&sk_it->sk_callback_lock);
		sk_set_socket(sk_it, NULL);
		sk_it->sk_wq  = NULL;
		write_unlock_bh(&sk_it->sk_callback_lock);
	}

	if (mpcb->pm_ops->close_session)
		mpcb->pm_ops->close_session(meta_sk);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(meta_sk);

	/* Now socket is owned by kernel and we acquire BH lock
	 * to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(meta_sk);
	WARN_ON(sock_owned_by_user(meta_sk));

	percpu_counter_inc(meta_sk->sk_prot->orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && meta_sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (meta_sk->sk_state == TCP_FIN_WAIT2) {
		if (meta_tp->linger2 < 0) {
			tcp_set_state(meta_sk, TCP_CLOSE);
			meta_tp->ops->send_active_reset(meta_sk, GFP_ATOMIC);
			__NET_INC_STATS(sock_net(meta_sk),
					LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(meta_sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(meta_sk,
							       tmo - TCP_TIMEWAIT_LEN);
			} else {
				meta_tp->ops->time_wait(meta_sk, TCP_FIN_WAIT2,
							tmo);
				goto out;
			}
		}
	}
	if (meta_sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(meta_sk);
		if (tcp_check_oom(meta_sk, 0)) {
			if (net_ratelimit())
				pr_info("MPTCP: out of memory: force closing socket\n");
			tcp_set_state(meta_sk, TCP_CLOSE);
			meta_tp->ops->send_active_reset(meta_sk, GFP_ATOMIC);
			__NET_INC_STATS(sock_net(meta_sk),
					LINUX_MIB_TCPABORTONMEMORY);
		}
	}


	if (meta_sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(meta_sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(meta_sk);
	local_bh_enable();
	mutex_unlock(&mpcb->mpcb_mutex);
	mptcp_mpcb_put(mpcb);
	sock_put(meta_sk); /* Taken by sock_hold */
}

void mptcp_disconnect(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_tcp_sock *mptcp;
	struct hlist_node *tmp;

	__skb_queue_purge(&meta_tp->mpcb->reinject_queue);

	if (meta_tp->inside_tk_table)
		mptcp_hash_remove_bh(meta_tp);

	local_bh_disable();
	mptcp_for_each_sub_safe(meta_tp->mpcb, mptcp, tmp) {
		struct sock *subsk = mptcp_to_sock(mptcp);

		if (spin_is_locked(&subsk->sk_lock.slock))
			bh_unlock_sock(subsk);

		tcp_sk(subsk)->tcp_disconnect = 1;

		meta_sk->sk_prot->disconnect(subsk, O_NONBLOCK);

		sock_orphan(subsk);

		percpu_counter_inc(meta_sk->sk_prot->orphan_count);

		inet_csk_destroy_sock(subsk);
	}
	local_bh_enable();

	mptcp_mpcb_cleanup(meta_tp->mpcb);
	meta_tp->meta_sk = NULL;

	meta_tp->send_mp_fclose = 0;
	meta_tp->mpc = 0;
	meta_tp->ops = &tcp_specific;
#if IS_ENABLED(CONFIG_IPV6)
	if (meta_sk->sk_family == AF_INET6)
		meta_sk->sk_backlog_rcv = tcp_v6_do_rcv;
	else
		meta_sk->sk_backlog_rcv = tcp_v4_do_rcv;
#else
	meta_sk->sk_backlog_rcv = tcp_v4_do_rcv;
#endif
	meta_sk->sk_destruct = inet_sock_destruct;
}


/* Returns True if we should enable MPTCP for that socket. */
bool mptcp_doit(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);

	/* Don't do mptcp over loopback */
	if (sk->sk_family == AF_INET &&
	    (ipv4_is_loopback(inet_sk(sk)->inet_daddr) ||
	     ipv4_is_loopback(inet_sk(sk)->inet_saddr)))
		return false;
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6 &&
	    (ipv6_addr_loopback(&sk->sk_v6_daddr) ||
	     ipv6_addr_loopback(&inet6_sk(sk)->saddr)))
		return false;
#endif
	if (mptcp_v6_is_v4_mapped(sk) &&
	    ipv4_is_loopback(inet_sk(sk)->inet_saddr))
		return false;

#ifdef CONFIG_TCP_MD5SIG
	/* If TCP_MD5SIG is enabled, do not do MPTCP - there is no Option-Space */
	if (tcp_sk(sk)->af_specific->md5_lookup(sk, sk))
		return false;
#endif

	if (dst->dev && (dst->dev->flags & IFF_NOMULTIPATH))
		return false;

	return true;
}

int mptcp_create_master_sk(struct sock *meta_sk, __u64 remote_key,
			   __u8 mptcp_ver, u32 window)
{
	struct tcp_sock *master_tp;
	struct sock *master_sk;

	if (mptcp_alloc_mpcb(meta_sk, remote_key, mptcp_ver, window))
		goto err_alloc_mpcb;

	master_sk = tcp_sk(meta_sk)->mpcb->master_sk;
	master_tp = tcp_sk(master_sk);

	if (mptcp_add_sock(meta_sk, master_sk, 0, 0, GFP_ATOMIC)) {
		WARN_ON(1);
		return -EINVAL;
	}

	meta_sk->sk_prot->unhash(meta_sk);
	inet_ehash_nolisten(master_sk, NULL, NULL);

	master_tp->mptcp->init_rcv_wnd = master_tp->rcv_wnd;

	return 0;

err_alloc_mpcb:
	return -ENOBUFS;
}

static int __mptcp_check_req_master(struct sock *child,
				    struct request_sock *req)
{
	struct tcp_sock *child_tp = tcp_sk(child);
	struct sock *meta_sk = child;
	struct mptcp_cb *mpcb;
	struct mptcp_request_sock *mtreq;

	/* Never contained an MP_CAPABLE */
	if (!inet_rsk(req)->mptcp_rqsk)
		return 1;

	if (!inet_rsk(req)->saw_mpc) {
		/* Fallback to regular TCP, because we saw one SYN without
		 * MP_CAPABLE. In tcp_check_req we continue the regular path.
		 * But, the socket has been added to the reqsk_tk_htb, so we
		 * must still remove it.
		 */
		MPTCP_INC_STATS(sock_net(meta_sk), MPTCP_MIB_MPCAPABLEPASSIVEFALLBACK);
		mptcp_reqsk_remove_tk(req);
		return 1;
	}

	MPTCP_INC_STATS(sock_net(meta_sk), MPTCP_MIB_MPCAPABLEPASSIVEACK);

	/* Just set this values to pass them to mptcp_alloc_mpcb */
	mtreq = mptcp_rsk(req);
	child_tp->mptcp_loc_key = mtreq->mptcp_loc_key;
	child_tp->mptcp_loc_token = mtreq->mptcp_loc_token;

	if (mptcp_create_master_sk(meta_sk, mtreq->mptcp_rem_key,
				   mtreq->mptcp_ver, child_tp->snd_wnd)) {
		mptcp_icsk_forced_close(meta_sk);

		return -ENOBUFS;
	}

	child = tcp_sk(child)->mpcb->master_sk;
	child_tp = tcp_sk(child);
	mpcb = child_tp->mpcb;

	child_tp->mptcp->snt_isn = tcp_rsk(req)->snt_isn;
	child_tp->mptcp->rcv_isn = tcp_rsk(req)->rcv_isn;

	mpcb->dss_csum = mtreq->dss_csum;
	mpcb->server_side = 1;

	/* Needs to be done here additionally, because when accepting a
	 * new connection we pass by __reqsk_free and not reqsk_free.
	 */
	mptcp_reqsk_remove_tk(req);

	/* Hold when creating the meta-sk in tcp_vX_syn_recv_sock. */
	sock_put(meta_sk);

	return 0;
}

int mptcp_check_req_fastopen(struct sock *child, struct request_sock *req)
{
	struct sock *meta_sk = child, *master_sk;
	struct sk_buff *skb;
	u32 new_mapping;
	int ret;

	ret = __mptcp_check_req_master(child, req);
	if (ret)
		return ret;

	master_sk = tcp_sk(meta_sk)->mpcb->master_sk;

	/* We need to rewind copied_seq as it is set to IDSN + 1 and as we have
	 * pre-MPTCP data in the receive queue.
	 */
	tcp_sk(meta_sk)->copied_seq -= tcp_sk(master_sk)->rcv_nxt -
				       tcp_rsk(req)->rcv_isn - 1;

	/* Map subflow sequence number to data sequence numbers. We need to map
	 * these data to [IDSN - len - 1, IDSN[.
	 */
	new_mapping = tcp_sk(meta_sk)->copied_seq - tcp_rsk(req)->rcv_isn - 1;

	/* There should be only one skb: the SYN + data. */
	skb_queue_walk(&meta_sk->sk_receive_queue, skb) {
		TCP_SKB_CB(skb)->seq += new_mapping;
		TCP_SKB_CB(skb)->end_seq += new_mapping;
	}

	/* With fastopen we change the semantics of the relative subflow
	 * sequence numbers to deal with middleboxes that could add/remove
	 * multiple bytes in the SYN. We chose to start counting at rcv_nxt - 1
	 * instead of the regular TCP ISN.
	 */
	tcp_sk(master_sk)->mptcp->rcv_isn = tcp_sk(master_sk)->rcv_nxt - 1;

	/* We need to update copied_seq of the master_sk to account for the
	 * already moved data to the meta receive queue.
	 */
	tcp_sk(master_sk)->copied_seq = tcp_sk(master_sk)->rcv_nxt;

	/* Handled by the master_sk */
	tcp_sk(meta_sk)->fastopen_rsk = NULL;

	return 0;
}

int mptcp_check_req_master(struct sock *sk, struct sock *child,
			   struct request_sock *req, const struct sk_buff *skb,
			   int drop, u32 tsoff)
{
	struct sock *meta_sk = child;
	int ret;

	ret = __mptcp_check_req_master(child, req);
	if (ret)
		return ret;
	child = tcp_sk(child)->mpcb->master_sk;

	sock_rps_save_rxhash(child, skb);

	/* drop indicates that we come from tcp_check_req and thus need to
	 * handle the request-socket fully.
	 */
	if (drop) {
		tcp_synack_rtt_meas(child, req);

		inet_csk_reqsk_queue_drop(sk, req);
		reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req);
		if (!inet_csk_reqsk_queue_add(sk, req, meta_sk)) {
			bh_unlock_sock(meta_sk);
			/* No sock_put() of the meta needed. The reference has
			 * already been dropped in __mptcp_check_req_master().
			 */
			sock_put(child);
			return -1;
		}
	} else {
		/* Thus, we come from syn-cookies */
		refcount_set(&req->rsk_refcnt, 1);
		tcp_sk(meta_sk)->tsoffset = tsoff;
		if (!inet_csk_reqsk_queue_add(sk, req, meta_sk)) {
			bh_unlock_sock(meta_sk);
			/* No sock_put() of the meta needed. The reference has
			 * already been dropped in __mptcp_check_req_master().
			 */
			sock_put(child);
			reqsk_put(req);
			return -1;
		}
	}

	return 0;
}

/* May be called without holding the meta-level lock */
struct sock *mptcp_check_req_child(struct sock *meta_sk,
				   struct sock *child,
				   struct request_sock *req,
				   struct sk_buff *skb,
				   const struct mptcp_options_received *mopt)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);
	struct tcp_sock *child_tp = tcp_sk(child);
	u8 hash_mac_check[20];

	if (!mopt->join_ack) {
		MPTCP_INC_STATS(sock_net(meta_sk), MPTCP_MIB_JOINACKFAIL);
		goto teardown;
	}

	mptcp_hmac_sha1((u8 *)&mpcb->mptcp_rem_key,
			(u8 *)&mpcb->mptcp_loc_key,
			(u32 *)hash_mac_check, 2,
			4, (u8 *)&mtreq->mptcp_rem_nonce,
			4, (u8 *)&mtreq->mptcp_loc_nonce);

	if (memcmp(hash_mac_check, (char *)&mopt->mptcp_recv_mac, 20)) {
		MPTCP_INC_STATS(sock_net(meta_sk), MPTCP_MIB_JOINACKMAC);
		goto teardown;
	}

	/* Point it to the same struct socket and wq as the meta_sk */
	sk_set_socket(child, meta_sk->sk_socket);
	child->sk_wq = meta_sk->sk_wq;

	if (mptcp_add_sock(meta_sk, child, mtreq->loc_id, mtreq->rem_id, GFP_ATOMIC)) {
		/* Has been inherited, but now child_tp->mptcp is NULL */
		child_tp->mpc = 0;
		child_tp->ops = &tcp_specific;

		/* TODO when we support acking the third ack for new subflows,
		 * we should silently discard this third ack, by returning NULL.
		 *
		 * Maybe, at the retransmission we will have enough memory to
		 * fully add the socket to the meta-sk.
		 */
		goto teardown;
	}

	/* The child is a clone of the meta socket, we must now reset
	 * some of the fields
	 */
	child_tp->mptcp->rcv_low_prio = mtreq->rcv_low_prio;
	child_tp->mptcp->low_prio = mtreq->low_prio;

	/* We should allow proper increase of the snd/rcv-buffers. Thus, we
	 * use the original values instead of the bloated up ones from the
	 * clone.
	 */
	child->sk_sndbuf = mpcb->orig_sk_sndbuf;
	child->sk_rcvbuf = mpcb->orig_sk_rcvbuf;

	child_tp->mptcp->slave_sk = 1;
	child_tp->mptcp->snt_isn = tcp_rsk(req)->snt_isn;
	child_tp->mptcp->rcv_isn = tcp_rsk(req)->rcv_isn;
	child_tp->mptcp->init_rcv_wnd = req->rsk_rcv_wnd;

	child->sk_tsq_flags = 0;

	sock_rps_save_rxhash(child, skb);
	tcp_synack_rtt_meas(child, req);

	if (mpcb->pm_ops->established_subflow)
		mpcb->pm_ops->established_subflow(child);

	/* Subflows do not use the accept queue, as they
	 * are attached immediately to the mpcb.
	 */
	inet_csk_reqsk_queue_drop(meta_sk, req);
	reqsk_queue_removed(&inet_csk(meta_sk)->icsk_accept_queue, req);

	/* The refcnt is initialized to 2, because regular TCP will put him
	 * in the socket's listener queue. However, we do not have a listener-queue.
	 * So, we need to make sure that this request-sock indeed gets destroyed.
	 */
	reqsk_put(req);

	MPTCP_INC_STATS(sock_net(meta_sk), MPTCP_MIB_JOINACKRX);
	return child;

teardown:
	req->rsk_ops->send_reset(meta_sk, skb);

	/* Drop this request - sock creation failed. */
	inet_csk_reqsk_queue_drop(meta_sk, req);
	reqsk_queue_removed(&inet_csk(meta_sk)->icsk_accept_queue, req);

	mptcp_icsk_forced_close(child);

	bh_unlock_sock(meta_sk);

	return meta_sk;
}

int mptcp_init_tw_sock(struct sock *sk, struct tcp_timewait_sock *tw)
{
	struct mptcp_tw *mptw;
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;

	/* A subsocket in tw can only receive data. So, if we are in
	 * infinite-receive, then we should not reply with a data-ack or act
	 * upon general MPTCP-signaling. We prevent this by simply not creating
	 * the mptcp_tw_sock.
	 */
	if (mpcb->infinite_mapping_rcv) {
		tw->mptcp_tw = NULL;
		return 0;
	}

	/* Alloc MPTCP-tw-sock */
	mptw = kmem_cache_alloc(mptcp_tw_cache, GFP_ATOMIC);
	if (!mptw) {
		tw->mptcp_tw = NULL;
		return -ENOBUFS;
	}

	refcount_inc(&mpcb->mpcb_refcnt);

	tw->mptcp_tw = mptw;
	mptw->loc_key = mpcb->mptcp_loc_key;
	mptw->meta_tw = mpcb->in_time_wait;
	mptw->rcv_nxt = mptcp_get_rcv_nxt_64(mptcp_meta_tp(tp));
	if (mptw->meta_tw && mpcb->mptw_state != TCP_TIME_WAIT)
		mptw->rcv_nxt++;
	rcu_assign_pointer(mptw->mpcb, mpcb);

	spin_lock_bh(&mpcb->mpcb_list_lock);
	list_add_rcu(&mptw->list, &tp->mpcb->tw_list);
	mptw->in_list = 1;
	spin_unlock_bh(&mpcb->mpcb_list_lock);

	return 0;
}

void mptcp_twsk_destructor(struct tcp_timewait_sock *tw)
{
	struct mptcp_cb *mpcb;

	rcu_read_lock();
	local_bh_disable();
	mpcb = rcu_dereference(tw->mptcp_tw->mpcb);

	/* If we are still holding a ref to the mpcb, we have to remove ourself
	 * from the list and drop the ref properly.
	 */
	if (mpcb && refcount_inc_not_zero(&mpcb->mpcb_refcnt)) {
		spin_lock(&mpcb->mpcb_list_lock);
		if (tw->mptcp_tw->in_list) {
			list_del_rcu(&tw->mptcp_tw->list);
			tw->mptcp_tw->in_list = 0;
			/* Put, because we added it to the list */
			mptcp_mpcb_put(mpcb);
		}
		spin_unlock(&mpcb->mpcb_list_lock);

		/* Second time, because we increased it above */
		mptcp_mpcb_put(mpcb);
	}

	local_bh_enable();
	rcu_read_unlock();

	kmem_cache_free(mptcp_tw_cache, tw->mptcp_tw);
}

/* Updates the rcv_nxt of the time-wait-socks and allows them to ack a
 * data-fin.
 */
void mptcp_time_wait(struct sock *meta_sk, int state, int timeo)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_tw *mptw;

	if (mptcp_in_infinite_mapping_weak(meta_tp->mpcb)) {
		struct mptcp_tcp_sock *mptcp;
		struct hlist_node *tmp;

		mptcp_for_each_sub_safe(meta_tp->mpcb, mptcp, tmp) {
			struct sock *sk_it = mptcp_to_sock(mptcp);

			if (sk_it->sk_state == TCP_CLOSE)
				continue;

			tcp_sk(sk_it)->ops->time_wait(sk_it, state, timeo);
		}
	}

	/* Used for sockets that go into tw after the meta
	 * (see mptcp_init_tw_sock())
	 */
	meta_tp->mpcb->in_time_wait = 1;
	meta_tp->mpcb->mptw_state = state;

	/* Update the time-wait-sock's information */
	rcu_read_lock();
	local_bh_disable();
	list_for_each_entry_rcu(mptw, &meta_tp->mpcb->tw_list, list) {
		mptw->meta_tw = 1;
		mptw->rcv_nxt = mptcp_get_rcv_nxt_64(meta_tp);

		/* We want to ack a DATA_FIN, but are yet in FIN_WAIT_2 -
		 * pretend as if the DATA_FIN has already reached us, that way
		 * the checks in tcp_timewait_state_process will be good as the
		 * DATA_FIN comes in.
		 */
		if (state != TCP_TIME_WAIT)
			mptw->rcv_nxt++;
	}
	local_bh_enable();
	rcu_read_unlock();

	if (meta_sk->sk_state != TCP_CLOSE)
		tcp_done(meta_sk);
}

void mptcp_tsq_flags(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = mptcp_meta_sk(sk);

	/* It will be handled as a regular deferred-call */
	if (is_meta_sk(sk))
		return;

	if (hlist_unhashed(&tp->mptcp->cb_list)) {
		hlist_add_head(&tp->mptcp->cb_list, &tp->mpcb->callback_list);
		/* We need to hold it here, as the sock_hold is not assured
		 * by the release_sock as it is done in regular TCP.
		 *
		 * The subsocket may get inet_csk_destroy'd while it is inside
		 * the callback_list.
		 */
		sock_hold(sk);
	}

	if (!test_and_set_bit(MPTCP_SUB_DEFERRED, &meta_sk->sk_tsq_flags))
		sock_hold(meta_sk);
}

void mptcp_tsq_sub_deferred(struct sock *meta_sk)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_tcp_sock *mptcp;
	struct hlist_node *tmp;

	__sock_put(meta_sk);
	hlist_for_each_entry_safe(mptcp, tmp, &meta_tp->mpcb->callback_list, cb_list) {
		struct tcp_sock *tp = mptcp->tp;
		struct sock *sk = (struct sock *)tp;

		hlist_del_init(&mptcp->cb_list);
		sk->sk_prot->release_cb(sk);
		/* Final sock_put (cfr. mptcp_tsq_flags) */
		sock_put(sk);
	}
}

/* May be called without holding the meta-level lock */
void mptcp_join_reqsk_init(const struct mptcp_cb *mpcb,
			   const struct request_sock *req,
			   struct sk_buff *skb)
{
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);
	struct mptcp_options_received mopt;
	u8 mptcp_hash_mac[20];

	mptcp_init_mp_opt(&mopt);
	tcp_parse_mptcp_options(skb, &mopt);

	mtreq->is_sub = 1;
	inet_rsk(req)->mptcp_rqsk = 1;

	mtreq->mptcp_rem_nonce = mopt.mptcp_recv_nonce;

	mptcp_hmac_sha1((u8 *)&mpcb->mptcp_loc_key,
			(u8 *)&mpcb->mptcp_rem_key,
			(u32 *)mptcp_hash_mac, 2,
			4, (u8 *)&mtreq->mptcp_loc_nonce,
			4, (u8 *)&mtreq->mptcp_rem_nonce);
	mtreq->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;

	mtreq->rem_id = mopt.rem_id;
	mtreq->rcv_low_prio = mopt.low_prio;
	inet_rsk(req)->saw_mpc = 1;

	MPTCP_INC_STATS(sock_net(mpcb->meta_sk), MPTCP_MIB_JOINSYNRX);
}

void mptcp_reqsk_init(struct request_sock *req, const struct sock *sk,
		      const struct sk_buff *skb, bool want_cookie)
{
	struct mptcp_options_received mopt;
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);

	mptcp_init_mp_opt(&mopt);
	tcp_parse_mptcp_options(skb, &mopt);

	mtreq->dss_csum = mopt.dss_csum;

	if (want_cookie) {
		if (!mptcp_reqsk_new_cookie(req, sk, &mopt, skb))
			/* No key available - back to regular TCP */
			inet_rsk(req)->mptcp_rqsk = 0;
		return;
	}

	mptcp_reqsk_new_mptcp(req, sk, &mopt, skb);
}

void mptcp_cookies_reqsk_init(struct request_sock *req,
			      struct mptcp_options_received *mopt,
			      struct sk_buff *skb)
{
	struct mptcp_request_sock *mtreq = mptcp_rsk(req);

	/* Absolutely need to always initialize this. */
	mtreq->hash_entry.pprev = NULL;

	mtreq->mptcp_rem_key = mopt->mptcp_sender_key;
	mtreq->mptcp_loc_key = mopt->mptcp_receiver_key;

	/* Generate the token */
	mptcp_key_sha1(mtreq->mptcp_loc_key, &mtreq->mptcp_loc_token, NULL);

	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);

	/* Check, if the key is still free */
	if (mptcp_reqsk_find_tk(mtreq->mptcp_loc_token) ||
	    mptcp_find_token(mtreq->mptcp_loc_token))
		goto out;

	inet_rsk(req)->saw_mpc = 1;
	mtreq->is_sub = 0;
	inet_rsk(req)->mptcp_rqsk = 1;
	mtreq->dss_csum = mopt->dss_csum;

out:
	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();
}

int mptcp_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct mptcp_options_received mopt;

	mptcp_init_mp_opt(&mopt);
	tcp_parse_mptcp_options(skb, &mopt);

	if (mopt.is_mp_join)
		return mptcp_do_join_short(skb, &mopt, sock_net(sk));
	if (mopt.drop_me)
		goto drop;

	if (!sock_flag(sk, SOCK_MPTCP))
		mopt.saw_mpc = 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (mopt.saw_mpc) {
			if (skb_rtable(skb)->rt_flags &
			    (RTCF_BROADCAST | RTCF_MULTICAST))
				goto drop;

			MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEPASSIVE);
			return tcp_conn_request(&mptcp_request_sock_ops,
						&mptcp_request_sock_ipv4_ops,
						sk, skb);
		}

		return tcp_v4_conn_request(sk, skb);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		if (mopt.saw_mpc) {
			if (!ipv6_unicast_destination(skb))
				goto drop;

			MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEPASSIVE);
			return tcp_conn_request(&mptcp6_request_sock_ops,
						&mptcp_request_sock_ipv6_ops,
						sk, skb);
		}

		return tcp_v6_conn_request(sk, skb);
#endif
	}
drop:
	NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return 0;
}

int mptcp_finish_handshake(struct sock *child, struct sk_buff *skb)
	__releases(&child->sk_lock.slock)
{
	int ret;

	/* We don't call tcp_child_process here, because we hold
	 * already the meta-sk-lock and are sure that it is not owned
	 * by the user.
	 */
	tcp_sk(child)->segs_in += max_t(u16, 1, skb_shinfo(skb)->gso_segs);
	ret = tcp_rcv_state_process(child, skb);
	bh_unlock_sock(child);
	sock_put(child);

	return ret;
}

static void __mptcp_get_info(const struct sock *meta_sk,
			     struct mptcp_meta_info *info)
{
	const struct inet_connection_sock *meta_icsk = inet_csk(meta_sk);
	const struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	u32 now = tcp_jiffies32;

	memset(info, 0, sizeof(*info));

	info->mptcpi_state = meta_sk->sk_state;
	info->mptcpi_retransmits = meta_icsk->icsk_retransmits;
	info->mptcpi_probes = meta_icsk->icsk_probes_out;
	info->mptcpi_backoff = meta_icsk->icsk_backoff;

	info->mptcpi_rto = jiffies_to_usecs(meta_icsk->icsk_rto);

	info->mptcpi_unacked = meta_tp->packets_out;

	info->mptcpi_last_data_sent = jiffies_to_msecs(now - meta_tp->lsndtime);
	info->mptcpi_last_data_recv = jiffies_to_msecs(now - meta_icsk->icsk_ack.lrcvtime);
	info->mptcpi_last_ack_recv = jiffies_to_msecs(now - meta_tp->rcv_tstamp);

	info->mptcpi_total_retrans = meta_tp->total_retrans;

	info->mptcpi_bytes_acked = meta_tp->bytes_acked;
	info->mptcpi_bytes_received = meta_tp->bytes_received;
}

static void mptcp_get_sub_info(struct sock *sk, struct mptcp_sub_info *info)
{
	struct inet_sock *inet = inet_sk(sk);

	memset(info, 0, sizeof(*info));

	if (sk->sk_family == AF_INET) {
		info->src_v4.sin_family = AF_INET;
		info->src_v4.sin_port = inet->inet_sport;

		info->src_v4.sin_addr.s_addr = inet->inet_rcv_saddr;
		if (!info->src_v4.sin_addr.s_addr)
			info->src_v4.sin_addr.s_addr = inet->inet_saddr;

		info->dst_v4.sin_family = AF_INET;
		info->dst_v4.sin_port = inet->inet_dport;
		info->dst_v4.sin_addr.s_addr = inet->inet_daddr;
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct ipv6_pinfo *np = inet6_sk(sk);

		info->src_v6.sin6_family = AF_INET6;
		info->src_v6.sin6_port = inet->inet_sport;

		if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
			info->src_v6.sin6_addr = np->saddr;
		else
			info->src_v6.sin6_addr = sk->sk_v6_rcv_saddr;

		info->dst_v6.sin6_family = AF_INET6;
		info->dst_v6.sin6_port = inet->inet_dport;
		info->dst_v6.sin6_addr = sk->sk_v6_daddr;
#endif
	}
}

int mptcp_get_info(const struct sock *meta_sk, char __user *optval, int optlen)
{
	const struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	struct mptcp_meta_info meta_info;
	struct mptcp_info m_info;

	unsigned int info_len;

	/* Check again with the lock held */
	if (!mptcp(meta_tp))
		return -EINVAL;

	if (copy_from_user(&m_info, optval, optlen))
		return -EFAULT;

	if (m_info.meta_info) {
		unsigned int len;

		__mptcp_get_info(meta_sk, &meta_info);

		/* Need to set this, if user thinks that tcp_info is bigger than ours */
		len = min_t(unsigned int, m_info.meta_len, sizeof(meta_info));
		m_info.meta_len = len;

		if (copy_to_user((void __user *)m_info.meta_info, &meta_info, len))
			return -EFAULT;
	}

	/* Need to set this, if user thinks that tcp_info is bigger than ours */
	info_len = min_t(unsigned int, m_info.tcp_info_len, sizeof(struct tcp_info));
	m_info.tcp_info_len = info_len;

	if (m_info.initial) {
		struct mptcp_cb *mpcb = meta_tp->mpcb;

		if (mpcb->master_sk) {
			struct tcp_info info;

			tcp_get_info(mpcb->master_sk, &info, true);
			if (copy_to_user((void __user *)m_info.initial, &info, info_len))
				return -EFAULT;
		} else if (meta_tp->record_master_info && mpcb->master_info) {
			if (copy_to_user((void __user *)m_info.initial, mpcb->master_info, info_len))
				return -EFAULT;
		} else {
			return meta_tp->record_master_info ? -ENOMEM : -EINVAL;
		}
	}

	if (m_info.subflows) {
		unsigned int len, sub_len = 0;
		struct mptcp_tcp_sock *mptcp;
		char __user *ptr;

		ptr = (char __user *)m_info.subflows;
		len = m_info.sub_len;

		mptcp_for_each_sub(meta_tp->mpcb, mptcp) {
			struct tcp_info t_info;
			unsigned int tmp_len;

			tcp_get_info(mptcp_to_sock(mptcp), &t_info, true);

			tmp_len = min_t(unsigned int, len, info_len);
			len -= tmp_len;

			if (copy_to_user(ptr, &t_info, tmp_len))
				return -EFAULT;

			ptr += tmp_len;
			sub_len += tmp_len;

			if (len == 0)
				break;
		}

		m_info.sub_len = sub_len;
	}

	if (m_info.subflow_info) {
		unsigned int len, sub_info_len, total_sub_info_len = 0;
		struct mptcp_tcp_sock *mptcp;
		char __user *ptr;

		ptr = (char __user *)m_info.subflow_info;
		len = m_info.total_sub_info_len;

		sub_info_len = min_t(unsigned int, m_info.sub_info_len,
				     sizeof(struct mptcp_sub_info));
		m_info.sub_info_len = sub_info_len;

		mptcp_for_each_sub(meta_tp->mpcb, mptcp) {
			struct mptcp_sub_info m_sub_info;
			unsigned int tmp_len;

			mptcp_get_sub_info(mptcp_to_sock(mptcp), &m_sub_info);

			tmp_len = min_t(unsigned int, len, sub_info_len);
			len -= tmp_len;

			if (copy_to_user(ptr, &m_sub_info, tmp_len))
				return -EFAULT;

			ptr += tmp_len;
			total_sub_info_len += tmp_len;

			if (len == 0)
				break;
		}

		m_info.total_sub_info_len = total_sub_info_len;
	}

	if (copy_to_user(optval, &m_info, optlen))
		return -EFAULT;

	return 0;
}

void mptcp_clear_sk(struct sock *sk, int size)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* we do not want to clear tk_table field, because of RCU lookups */
	sk_prot_clear_nulls(sk, offsetof(struct tcp_sock, tk_table.next));

	size -= offsetof(struct tcp_sock, tk_table.pprev);
	memset((char *)&tp->tk_table.pprev, 0, size);
}

static const struct snmp_mib mptcp_snmp_list[] = {
	SNMP_MIB_ITEM("MPCapableSYNRX", MPTCP_MIB_MPCAPABLEPASSIVE),
	SNMP_MIB_ITEM("MPCapableSYNTX", MPTCP_MIB_MPCAPABLEACTIVE),
	SNMP_MIB_ITEM("MPCapableSYNACKRX", MPTCP_MIB_MPCAPABLEACTIVEACK),
	SNMP_MIB_ITEM("MPCapableACKRX", MPTCP_MIB_MPCAPABLEPASSIVEACK),
	SNMP_MIB_ITEM("MPCapableFallbackACK", MPTCP_MIB_MPCAPABLEPASSIVEFALLBACK),
	SNMP_MIB_ITEM("MPCapableFallbackSYNACK", MPTCP_MIB_MPCAPABLEACTIVEFALLBACK),
	SNMP_MIB_ITEM("MPCapableRetransFallback", MPTCP_MIB_MPCAPABLERETRANSFALLBACK),
	SNMP_MIB_ITEM("MPTCPCsumEnabled", MPTCP_MIB_CSUMENABLED),
	SNMP_MIB_ITEM("MPTCPRetrans", MPTCP_MIB_RETRANSSEGS),
	SNMP_MIB_ITEM("MPFailRX", MPTCP_MIB_MPFAILRX),
	SNMP_MIB_ITEM("MPCsumFail", MPTCP_MIB_CSUMFAIL),
	SNMP_MIB_ITEM("MPFastcloseRX", MPTCP_MIB_FASTCLOSERX),
	SNMP_MIB_ITEM("MPFastcloseTX", MPTCP_MIB_FASTCLOSETX),
	SNMP_MIB_ITEM("MPFallbackAckSub", MPTCP_MIB_FBACKSUB),
	SNMP_MIB_ITEM("MPFallbackAckInit", MPTCP_MIB_FBACKINIT),
	SNMP_MIB_ITEM("MPFallbackDataSub", MPTCP_MIB_FBDATASUB),
	SNMP_MIB_ITEM("MPFallbackDataInit", MPTCP_MIB_FBDATAINIT),
	SNMP_MIB_ITEM("MPRemoveAddrSubDelete", MPTCP_MIB_REMADDRSUB),
	SNMP_MIB_ITEM("MPJoinNoTokenFound", MPTCP_MIB_JOINNOTOKEN),
	SNMP_MIB_ITEM("MPJoinAlreadyFallenback", MPTCP_MIB_JOINFALLBACK),
	SNMP_MIB_ITEM("MPJoinSynTx", MPTCP_MIB_JOINSYNTX),
	SNMP_MIB_ITEM("MPJoinSynRx", MPTCP_MIB_JOINSYNRX),
	SNMP_MIB_ITEM("MPJoinSynAckRx", MPTCP_MIB_JOINSYNACKRX),
	SNMP_MIB_ITEM("MPJoinSynAckHMacFailure", MPTCP_MIB_JOINSYNACKMAC),
	SNMP_MIB_ITEM("MPJoinAckRx", MPTCP_MIB_JOINACKRX),
	SNMP_MIB_ITEM("MPJoinAckHMacFailure", MPTCP_MIB_JOINACKMAC),
	SNMP_MIB_ITEM("MPJoinAckMissing", MPTCP_MIB_JOINACKFAIL),
	SNMP_MIB_ITEM("MPJoinAckRTO", MPTCP_MIB_JOINACKRTO),
	SNMP_MIB_ITEM("MPJoinAckRexmit", MPTCP_MIB_JOINACKRXMIT),
	SNMP_MIB_ITEM("NoDSSInWindow", MPTCP_MIB_NODSSWINDOW),
	SNMP_MIB_ITEM("DSSNotMatching", MPTCP_MIB_DSSNOMATCH),
	SNMP_MIB_ITEM("InfiniteMapRx", MPTCP_MIB_INFINITEMAPRX),
	SNMP_MIB_ITEM("DSSNoMatchTCP", MPTCP_MIB_DSSTCPMISMATCH),
	SNMP_MIB_ITEM("DSSTrimHead", MPTCP_MIB_DSSTRIMHEAD),
	SNMP_MIB_ITEM("DSSSplitTail", MPTCP_MIB_DSSSPLITTAIL),
	SNMP_MIB_ITEM("DSSPurgeOldSubSegs", MPTCP_MIB_PURGEOLD),
	SNMP_MIB_ITEM("AddAddrRx", MPTCP_MIB_ADDADDRRX),
	SNMP_MIB_ITEM("AddAddrTx", MPTCP_MIB_ADDADDRTX),
	SNMP_MIB_ITEM("RemAddrRx", MPTCP_MIB_REMADDRRX),
	SNMP_MIB_ITEM("RemAddrTx", MPTCP_MIB_REMADDRTX),
	SNMP_MIB_SENTINEL
};

struct workqueue_struct *mptcp_wq;
EXPORT_SYMBOL(mptcp_wq);

/* Output /proc/net/mptcp */
static int mptcp_pm_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_sock *meta_tp;
	const struct net *net = seq->private;
	int i, n = 0;

	seq_printf(seq, "  sl  loc_tok  rem_tok  v6 local_address                         remote_address                        st ns tx_queue rx_queue inode");
	seq_putc(seq, '\n');

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		rcu_read_lock();
		local_bh_disable();
		hlist_nulls_for_each_entry_rcu(meta_tp, node,
					       &tk_hashtable[i], tk_table) {
			struct sock *meta_sk = (struct sock *)meta_tp;
			struct inet_sock *isk = inet_sk(meta_sk);
			struct mptcp_cb *mpcb = meta_tp->mpcb;

			if (!mptcp(meta_tp) || !net_eq(net, sock_net(meta_sk)))
				continue;

			if (!mpcb)
				continue;

			if (capable(CAP_NET_ADMIN)) {
				seq_printf(seq, "%4d: %04X %04X ", n++,
						mpcb->mptcp_loc_token,
						mpcb->mptcp_rem_token);
			} else {
				seq_printf(seq, "%4d: %04X %04X ", n++, -1, -1);
			}
			if (meta_sk->sk_family == AF_INET ||
			    mptcp_v6_is_v4_mapped(meta_sk)) {
				seq_printf(seq, " 0 %08X:%04X                         %08X:%04X                        ",
					   isk->inet_rcv_saddr,
					   ntohs(isk->inet_sport),
					   isk->inet_daddr,
					   ntohs(isk->inet_dport));
#if IS_ENABLED(CONFIG_IPV6)
			} else if (meta_sk->sk_family == AF_INET6) {
				struct in6_addr *src = &meta_sk->sk_v6_rcv_saddr;
				struct in6_addr *dst = &meta_sk->sk_v6_daddr;
				seq_printf(seq, " 1 %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X",
					   src->s6_addr32[0], src->s6_addr32[1],
					   src->s6_addr32[2], src->s6_addr32[3],
					   ntohs(isk->inet_sport),
					   dst->s6_addr32[0], dst->s6_addr32[1],
					   dst->s6_addr32[2], dst->s6_addr32[3],
					   ntohs(isk->inet_dport));
#endif
			}

			seq_printf(seq, " %02X %02X %08X:%08X %lu",
				   meta_sk->sk_state, mptcp_subflow_count(mpcb),
				   meta_tp->write_seq - meta_tp->snd_una,
				   max_t(int, meta_tp->rcv_nxt -
					 meta_tp->copied_seq, 0),
				   sock_i_ino(meta_sk));
			seq_putc(seq, '\n');
		}

		local_bh_enable();
		rcu_read_unlock();
	}

	return 0;
}

static int mptcp_snmp_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq->private;
	int i;

	for (i = 0; mptcp_snmp_list[i].name != NULL; i++)
		seq_printf(seq, "%-32s\t%ld\n", mptcp_snmp_list[i].name,
			   snmp_fold_field(net->mptcp.mptcp_statistics,
				      mptcp_snmp_list[i].entry));

	return 0;
}

static int mptcp_pm_init_net(struct net *net)
{
	net->mptcp.mptcp_statistics = alloc_percpu(struct mptcp_mib);
	if (!net->mptcp.mptcp_statistics)
		goto out_mptcp_mibs;

#ifdef CONFIG_PROC_FS
	net->mptcp.proc_net_mptcp = proc_net_mkdir(net, "mptcp_net", net->proc_net);
	if (!net->mptcp.proc_net_mptcp)
		goto out_proc_net_mptcp;
	if (!proc_create_net_single("mptcp", S_IRUGO, net->mptcp.proc_net_mptcp,
				    mptcp_pm_seq_show, NULL))
		goto out_mptcp_net_mptcp;
	if (!proc_create_net_single("snmp", S_IRUGO, net->mptcp.proc_net_mptcp,
				    mptcp_snmp_seq_show, NULL))
		goto out_mptcp_net_snmp;
#endif

	return 0;

#ifdef CONFIG_PROC_FS
out_mptcp_net_snmp:
	remove_proc_entry("mptcp", net->mptcp.proc_net_mptcp);
out_mptcp_net_mptcp:
	remove_proc_subtree("mptcp_net", net->proc_net);
	net->mptcp.proc_net_mptcp = NULL;
out_proc_net_mptcp:
	free_percpu(net->mptcp.mptcp_statistics);
#endif
out_mptcp_mibs:
	return -ENOMEM;
}

static void mptcp_pm_exit_net(struct net *net)
{
	remove_proc_entry("snmp", net->mptcp.proc_net_mptcp);
	remove_proc_entry("mptcp", net->mptcp.proc_net_mptcp);
	remove_proc_subtree("mptcp_net", net->proc_net);
	free_percpu(net->mptcp.mptcp_statistics);
}

static struct pernet_operations mptcp_pm_proc_ops = {
	.init = mptcp_pm_init_net,
	.exit = mptcp_pm_exit_net,
};

/* General initialization of mptcp */
void __init mptcp_init(void)
{
	int i;
	struct ctl_table_header *mptcp_sysctl;

	mptcp_sock_cache = kmem_cache_create("mptcp_sock",
					     sizeof(struct mptcp_tcp_sock),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL);
	if (!mptcp_sock_cache)
		goto mptcp_sock_cache_failed;

	mptcp_cb_cache = kmem_cache_create("mptcp_cb", sizeof(struct mptcp_cb),
					   0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!mptcp_cb_cache)
		goto mptcp_cb_cache_failed;

	mptcp_tw_cache = kmem_cache_create("mptcp_tw", sizeof(struct mptcp_tw),
					   0, SLAB_TYPESAFE_BY_RCU|SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!mptcp_tw_cache)
		goto mptcp_tw_cache_failed;

	get_random_bytes(&mptcp_secret, sizeof(mptcp_secret));

	mptcp_wq = alloc_workqueue("mptcp_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 8);
	if (!mptcp_wq)
		goto alloc_workqueue_failed;

	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		INIT_HLIST_NULLS_HEAD(&tk_hashtable[i], i);
		INIT_HLIST_NULLS_HEAD(&mptcp_reqsk_tk_htb[i], i);
	}

	spin_lock_init(&mptcp_tk_hashlock);

	if (register_pernet_subsys(&mptcp_pm_proc_ops))
		goto pernet_failed;

#if IS_ENABLED(CONFIG_IPV6)
	if (mptcp_pm_v6_init())
		goto mptcp_pm_v6_failed;
#endif
	if (mptcp_pm_v4_init())
		goto mptcp_pm_v4_failed;

	mptcp_sysctl = register_net_sysctl(&init_net, "net/mptcp", mptcp_table);
	if (!mptcp_sysctl)
		goto register_sysctl_failed;

	if (mptcp_register_path_manager(&mptcp_pm_default))
		goto register_pm_failed;

	if (mptcp_register_scheduler(&mptcp_sched_default))
		goto register_sched_failed;

	pr_info("MPTCP: Stable release v0.95.2");

	mptcp_init_failed = false;

	return;

register_sched_failed:
	mptcp_unregister_path_manager(&mptcp_pm_default);
register_pm_failed:
	unregister_net_sysctl_table(mptcp_sysctl);
register_sysctl_failed:
	mptcp_pm_v4_undo();
mptcp_pm_v4_failed:
#if IS_ENABLED(CONFIG_IPV6)
	mptcp_pm_v6_undo();
mptcp_pm_v6_failed:
#endif
	unregister_pernet_subsys(&mptcp_pm_proc_ops);
pernet_failed:
	destroy_workqueue(mptcp_wq);
alloc_workqueue_failed:
	kmem_cache_destroy(mptcp_tw_cache);
mptcp_tw_cache_failed:
	kmem_cache_destroy(mptcp_cb_cache);
mptcp_cb_cache_failed:
	kmem_cache_destroy(mptcp_sock_cache);
mptcp_sock_cache_failed:
	mptcp_init_failed = true;
}
