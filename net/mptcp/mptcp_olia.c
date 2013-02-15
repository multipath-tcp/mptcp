/*
 * MPTCP implementation - OPPORTUNISTIC LINKED INCREASES CONGESTION CONTROL:
 *
 * Algorithm design:
 * Ramin Khalili <ramin.khalili@epfl.ch>
 * Nicolas Gast <nicolas.gast@epfl.ch>
 * Jean-Yves Le Boudec <jean-yves.leboudec@epfl.ch>
 *
 * Implementation:
 * Ramin Khalili <ramin.khalili@epfl.ch>
 *
 * Ported to the official MPTCP-kernel:
 * Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/module.h>

static int scale = 10;

struct mptcp_olia {
	u32	mptcp_loss1;
	u32	mptcp_loss2;
	u32	mptcp_loss3;
	int	epsilon_num;
	u32	epsilon_den;
	int	mptcp_snd_cwnd_cnt;
	u32	mptcp_previous_cwnd;
	u32	mptcp_ssthresh;
};

static inline int mptcp_olia_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt;
}

static inline u64 mptcp_olia_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

/* take care of artificially inflate (see RFC5681)
 * of cwnd during fast-retransmit phase
 */
static u32 mptcp_get_crt_cwnd(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_state == TCP_CA_Recovery)
		return tcp_sk(sk)->snd_ssthresh;
	else
		return tcp_sk(sk)->snd_cwnd;
}

/* return the dominator of the first term of  the increasing term */
static u64 mptcp_get_rate(struct mptcp_cb *mpcb , u32 path_rtt)
{
	struct sock *sk;
	u64 rate = 1; /* We have to avoid a zero-rate because it is used as a divisor */

	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		u64 scaled_num;
		u32 tmp_cwnd;

		if (!mptcp_olia_sk_can_send(sk))
			continue;

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		scaled_num = mptcp_olia_scale(tmp_cwnd, scale) * path_rtt;
		rate += div_u64(scaled_num , tp->srtt);
	}
	rate *= rate;
	return rate;
}

/* find the maximum cwnd, used to find set M */
static u32 mptcp_get_max_cwnd(struct mptcp_cb *mpcb)
{
	struct sock *sk;
	u32 best_cwnd = 0;

	mptcp_for_each_sk(mpcb, sk) {
		u32 tmp_cwnd;

		if (!mptcp_olia_sk_can_send(sk))
			continue;

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		if (tmp_cwnd > best_cwnd)
			best_cwnd = tmp_cwnd;
	}
	return best_cwnd;
}

static void mptcp_get_epsilon(struct mptcp_cb *mpcb)
{
	struct mptcp_olia *ca;
	struct tcp_sock *tp;
	struct sock *sk;
	u64 tmp_int, tmp_rtt, best_int = 0, best_rtt = 1;
	u32 max_cwnd = 1, best_cwnd = 1, tmp_cwnd;
	u8 M = 0, B_not_M = 0;

	/* TODO - integrate this in the following loop - we just want to iterate once */

	max_cwnd = mptcp_get_max_cwnd(mpcb);

	/* find the best path */
	mptcp_for_each_sk(mpcb, sk) {
		tp = tcp_sk(sk);
		ca = inet_csk_ca(sk);

		if (!mptcp_olia_sk_can_send(sk))
			continue;

		tmp_rtt = tp->srtt * tp->srtt;
		/* TODO - check here and rename variables */
		tmp_int = max(ca->mptcp_loss3 - ca->mptcp_loss2,
			      ca->mptcp_loss2 - ca->mptcp_loss1);

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		if (tmp_int * best_rtt >= best_int * tmp_rtt) {
			best_rtt = tmp_rtt;
			best_int = tmp_int;
			best_cwnd = tmp_cwnd;
		}
	}

	/* TODO - integrate this here in mptcp_get_max_cwnd and in the previous loop */
	/* find the size of M and B_not_M */
	mptcp_for_each_sk(mpcb, sk) {
		tp = tcp_sk(sk);
		ca = inet_csk_ca(sk);

		if (!mptcp_olia_sk_can_send(sk))
			continue;

		tmp_cwnd = mptcp_get_crt_cwnd(sk);
		if (tmp_cwnd == max_cwnd) {
			M++;
		} else {
			tmp_rtt = tp->srtt * tp->srtt;
			tmp_int = max(ca->mptcp_loss3 - ca->mptcp_loss2,
				      ca->mptcp_loss2 - ca->mptcp_loss1);

			if (tmp_int * best_rtt == best_int * tmp_rtt)
				B_not_M++;
		}
	}

	/* check if the path is in M or B_not_M and set the value of epsilon accordingly */
	mptcp_for_each_sk(mpcb, sk) {
		tp = tcp_sk(sk);
		ca = inet_csk_ca(sk);

		if (!mptcp_olia_sk_can_send(sk))
			continue;

		if (B_not_M == 0) {
			ca->epsilon_num = 0;
			ca->epsilon_den = 1;
		} else {
			tmp_rtt = tp->srtt * tp->srtt;
			tmp_int = max(ca->mptcp_loss3 - ca->mptcp_loss2,
				      ca->mptcp_loss2 - ca->mptcp_loss1);
			tmp_cwnd = mptcp_get_crt_cwnd(sk);

			if (tmp_cwnd < max_cwnd &&
			    tmp_int * best_rtt == best_int * tmp_rtt){
				ca->epsilon_num = 1;
				ca->epsilon_den = mpcb->cnt_established * B_not_M;
			} else if (tmp_cwnd == max_cwnd) {
				ca->epsilon_num = -1;
				ca->epsilon_den = mpcb->cnt_established  * M;
			} else {
				ca->epsilon_num = 0;
				ca->epsilon_den = 1;
			}
		}
	}

}

/* setting the initial values */
static void mptcp_olia_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_olia *ca = inet_csk_ca(sk);

	if (tp->mpc) {
		ca->mptcp_loss1 = tp->snd_una;
		ca->mptcp_loss2 = tp->snd_una;
		ca->mptcp_loss3 = tp->snd_una;
		ca->mptcp_ssthresh = tp->snd_ssthresh;
		ca->mptcp_previous_cwnd = 1;
		ca->mptcp_snd_cwnd_cnt = 0;
		ca->epsilon_num = 0;
		ca->epsilon_den = 1;
	}
}

/* updating inter-loss distance and ssthresh */
static void mptcp_olia_set_state(struct sock *sk, u8 new_state)
{

	if (!tcp_sk(sk)->mpc)
		return;

	if (new_state == TCP_CA_Loss ||
	    new_state == TCP_CA_Recovery || new_state == TCP_CA_CWR) {
		struct mptcp_olia *ca = inet_csk_ca(sk);
		struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;

		if (ca->mptcp_loss3 != ca->mptcp_loss2 && !inet_csk(sk)->icsk_retransmits) {
			ca->mptcp_loss1 = ca->mptcp_loss2;
			ca->mptcp_loss2 = ca->mptcp_loss3;

			if (mpcb->cnt_established == 1)
				ca->mptcp_ssthresh =
				    max(ca->mptcp_previous_cwnd >> 1U, 2U);
			else
				ca->mptcp_ssthresh =
				    max(ca->mptcp_previous_cwnd >> 1U, 1U);
		}
	}

}

/* main algorithm */
static void mptcp_olia_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_olia *ca = inet_csk_ca(sk);
	struct mptcp_cb *mpcb = tp->mpcb;

	u64 inc_num, inc_den, rate, cwnd_scaled;
	u32 ssthresh;

	if (!tp->mpc) {
		tcp_reno_cong_avoid(sk, ack, in_flight);
		return;
	}

	ssthresh = min(tp->snd_ssthresh , ca->mptcp_ssthresh);
	if (mpcb->cnt_established > 1)
		ssthresh--;

	ca->mptcp_loss3 = tp->snd_una;

	if (!tcp_is_cwnd_limited(sk, in_flight)) {
		ca->mptcp_previous_cwnd = tp->snd_cwnd;
		return;
	}

	/* slow start if it is in the safe area */
	if (tp->snd_cwnd <= ssthresh) {
		tcp_slow_start(tp);
		ca->mptcp_previous_cwnd = tp->snd_cwnd;
		return;
	}

	mptcp_get_epsilon(mpcb);
	rate = mptcp_get_rate(mpcb, tp->srtt);
	cwnd_scaled = mptcp_olia_scale(tp->snd_cwnd, scale);
	inc_den = ca->epsilon_den * tp->snd_cwnd * rate;

	/* calculate the increasing term, scaling is used to reduce the rounding effect */
	if (ca->epsilon_num == -1) {
		if (ca->epsilon_den * cwnd_scaled * cwnd_scaled < rate) {
			inc_num = rate - ca->epsilon_den *
				cwnd_scaled * cwnd_scaled;
			ca->mptcp_snd_cwnd_cnt -= div64_u64(
			    mptcp_olia_scale(inc_num , scale) , inc_den);
		} else {
			inc_num = ca->epsilon_den *
			    cwnd_scaled * cwnd_scaled - rate;
			ca->mptcp_snd_cwnd_cnt += div64_u64(
			    mptcp_olia_scale(inc_num , scale) , inc_den);
		}
	} else {
		inc_num = ca->epsilon_num * rate +
		    ca->epsilon_den * cwnd_scaled * cwnd_scaled;
		ca->mptcp_snd_cwnd_cnt += div64_u64(
		    mptcp_olia_scale(inc_num , scale) , inc_den);
	}


	if (sysctl_tcp_abc) {
		if (tp->bytes_acked >= tp->snd_cwnd * tp->mss_cache) {
			tp->bytes_acked -= tp->snd_cwnd * tp->mss_cache;
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
		}
	} else {
		if (ca->mptcp_snd_cwnd_cnt >= (1 << scale) - 1) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
			ca->mptcp_snd_cwnd_cnt = 0;
		} else if (ca->mptcp_snd_cwnd_cnt <= 0 - (1 << scale) + 1) {
			tp->snd_cwnd = max((int) 1 , (int) tp->snd_cwnd - 1);
			ca->mptcp_snd_cwnd_cnt = 0;
		}
	}
	ca->mptcp_previous_cwnd = tp->snd_cwnd;

}

static struct tcp_congestion_ops mptcp_olia = {
	.init		= mptcp_olia_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mptcp_olia_cong_avoid,
	.set_state	= mptcp_olia_set_state,
	.min_cwnd	= tcp_reno_min_cwnd,
	.owner		= THIS_MODULE,
	.name		= "olia",
};

static int __init mptcp_olia_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_olia) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mptcp_olia);
}

static void __exit mptcp_olia_unregister(void)
{
	tcp_unregister_congestion_control(&mptcp_olia);
}

module_init(mptcp_olia_register);
module_exit(mptcp_olia_unregister);

MODULE_AUTHOR("Ramin Khalili, Nicolas Gast, Jean-Yves Le Boudec");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP COUPLED CONGESTION CONTROL");
MODULE_VERSION("0.1");
