// SPDX-License-Identifier: GPL-2.0
/*	MPTCP ECF Scheduler
 *
 *	Algorithm Design:
 *	Yeon-sup Lim <ylim@cs.umass.edu>
 *	Don Towsley <towsley@cs.umass.edu>
 *	Erich M. Nahum <nahum@us.ibm.com>
 *	Richard J. Gibbens <richard.gibbens@cl.cam.ac.uk>
 *
 *	Initial Implementation:
 *	Yeon-sup Lim <ylim@cs.umass.edu>
 *
 *	Additional Authors:
 *	Daniel Weber <weberd@cs.uni-bonn.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned int mptcp_ecf_r_beta __read_mostly = 4; /* beta = 1/r_beta = 0.25 */
module_param(mptcp_ecf_r_beta, int, 0644);
MODULE_PARM_DESC(mptcp_ecf_r_beta, "beta for ECF");

struct ecfsched_priv {
	u32 last_rbuf_opti;
};

struct ecfsched_cb {
	u32 switching_margin; /* this is "waiting" in algorithm description */
};

static struct ecfsched_priv *ecfsched_get_priv(const struct tcp_sock *tp)
{
	return (struct ecfsched_priv *)&tp->mptcp->mptcp_sched[0];
}

static struct ecfsched_cb *ecfsched_get_cb(const struct tcp_sock *tp)
{
	return (struct ecfsched_cb *)&tp->mpcb->mptcp_sched[0];
}

/* This is the ECF scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy or the currently best
 * subflow is estimated to be slower than waiting for minsk, NULL is returned.
 */
static struct sock *ecf_get_available_subflow(struct sock *meta_sk,
					      struct sk_buff *skb,
					      bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *bestsk, *minsk = NULL;
	struct tcp_sock *besttp;
	struct mptcp_tcp_sock *mptcp;
	struct ecfsched_cb *ecf_cb = ecfsched_get_cb(tcp_sk(meta_sk));
	u32 min_srtt = U32_MAX;
	u32 sub_sndbuf = 0;
	u32 sub_packets_out = 0;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sub(mpcb, mptcp) {
			bestsk = mptcp_to_sock(mptcp);

			if (tcp_sk(bestsk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_is_available(bestsk, skb, zero_wnd_test))
				return bestsk;
		}
	}

	/* First, find the overall best (fastest) subflow */
	mptcp_for_each_sub(mpcb, mptcp) {
		bestsk = mptcp_to_sock(mptcp);
		besttp = tcp_sk(bestsk);

		/* Set of states for which we are allowed to send data */
		if (!mptcp_sk_can_send(bestsk))
			continue;

		/* We do not send data on this subflow unless it is
		 * fully established, i.e. the 4th ack has been received.
		 */
		if (besttp->mptcp->pre_established)
			continue;

		sub_sndbuf += bestsk->sk_wmem_queued;
		sub_packets_out += besttp->packets_out;

		/* record minimal rtt */
		if (besttp->srtt_us < min_srtt) {
			min_srtt = besttp->srtt_us;
			minsk = bestsk;
		}
	}

	/* find the current best subflow according to the default scheduler */
	bestsk = get_available_subflow(meta_sk, skb, zero_wnd_test);

	/* if we decided to use a slower flow, we have the option of not using it at all */
	if (bestsk && minsk && bestsk != minsk) {
		u32 mss = tcp_current_mss(bestsk); /* assuming equal MSS */
		u32 sndbuf_meta = meta_sk->sk_wmem_queued;
		u32 sndbuf_minus = sub_sndbuf;
		u32 sndbuf = 0;

		u32 cwnd_f = tcp_sk(minsk)->snd_cwnd;
		u32 srtt_f = tcp_sk(minsk)->srtt_us >> 3;
		u32 rttvar_f = tcp_sk(minsk)->rttvar_us >> 1;

		u32 cwnd_s = tcp_sk(bestsk)->snd_cwnd;
		u32 srtt_s = tcp_sk(bestsk)->srtt_us >> 3;
		u32 rttvar_s = tcp_sk(bestsk)->rttvar_us >> 1;

		u32 delta = max(rttvar_f, rttvar_s);

		u32 x_f;
		u64 lhs, rhs; /* to avoid overflow, using u64 */

		if (tcp_sk(meta_sk)->packets_out > sub_packets_out)
			sndbuf_minus += (tcp_sk(meta_sk)->packets_out - sub_packets_out) * mss;

		if (sndbuf_meta > sndbuf_minus)
			sndbuf = sndbuf_meta - sndbuf_minus;

		/* we have something to send.
		 * at least one time tx over fastest subflow is required
		 */
		x_f = sndbuf > cwnd_f * mss ? sndbuf : cwnd_f * mss;
		lhs = srtt_f * (x_f + cwnd_f * mss);
		rhs = cwnd_f * mss * (srtt_s + delta);

		if (mptcp_ecf_r_beta * lhs < mptcp_ecf_r_beta * rhs + ecf_cb->switching_margin * rhs) {
			u32 x_s = sndbuf > cwnd_s * mss ? sndbuf : cwnd_s * mss;
			u64 lhs_s = srtt_s * x_s;
			u64 rhs_s = cwnd_s * mss * (2 * srtt_f + delta);

			if (lhs_s >= rhs_s) {
				/* too slower than fastest */
				ecf_cb->switching_margin = 1;
				return NULL;
			}
		} else {
			/* use slower one */
			ecf_cb->switching_margin = 0;
		}
	}

	return bestsk;
}

static void ecfsched_init(struct sock *sk)
{
	struct ecfsched_priv *ecf_p = ecfsched_get_priv(tcp_sk(sk));
	struct ecfsched_cb *ecf_cb = ecfsched_get_cb(tcp_sk(mptcp_meta_sk(sk)));

	ecf_p->last_rbuf_opti = tcp_jiffies32;
	ecf_cb->switching_margin = 0;
}

struct mptcp_sched_ops mptcp_sched_ecf = {
	.get_subflow = ecf_get_available_subflow,
	.next_segment = mptcp_next_segment,
	.init = ecfsched_init,
	.name = "ecf",
	.owner = THIS_MODULE,
};

static int __init ecf_register(void)
{
	BUILD_BUG_ON(sizeof(struct ecfsched_priv) > MPTCP_SCHED_SIZE);
	BUILD_BUG_ON(sizeof(struct ecfsched_cb) > MPTCP_SCHED_DATA_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_ecf))
		return -1;

	return 0;
}

static void ecf_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_ecf);
}

module_init(ecf_register);
module_exit(ecf_unregister);

MODULE_AUTHOR("Yeon-sup Lim, Daniel Weber");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ECF (Earliest Completion First) scheduler for MPTCP, based on default minimum RTT scheduler");
MODULE_VERSION("0.95");
