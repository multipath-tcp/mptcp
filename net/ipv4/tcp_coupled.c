/*
 * TCP COUPLED CONGESTION CONTROL:
 * 
 * Algorithm: Costin Raiciu, Daemon Wischik, Mark Handley
 * Implementation: user space by Costin Raiciu.
 *           ported to kernel by Sébastien Barré & Christoph Paasch.
 */

#include <net/tcp.h>
#include <net/mtcp.h>

/* Scaling is done in the numerator with alpha_scale_num and in the denominator
 * with alpha_scale_den.
 *
 * To downscale, we just need to use alpha_scale.
 *
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den ^ 2)
 */
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

struct mtcp_ccc {
	u64 alpha;
};

static inline int mtcp_sk_not_estab(struct sock *sk)
{
	return sk->sk_state == TCP_SYN_SENT ||
	       sk->sk_state == TCP_SYN_RECV ||
	       sk->sk_state == TCP_CLOSE;
}

u32 mtcp_get_crt_cwnd(struct tcp_sock* tp)
{
	struct inet_connection_sock *icsk = inet_csk((struct sock *) tp);

	/* If we are in fast-retransmit, the cwnd is "artificially inflated" (see
	 * RFC5681), thus we use ssthresh as an indication of the cwnd. */
	if (icsk->icsk_ca_state == TCP_CA_Recovery)
		return min(tcp_packets_in_flight(tp), tp->snd_ssthresh);
	else
		return min(tcp_packets_in_flight(tp), tp->snd_cwnd);
}

u32 mtcp_get_total_cwnd(struct multipath_pcb* mpcb) {
	struct tcp_sock *tp;
	struct sock *sub_sk;
	u32 cwnd = 0;
	tp = mpcb->connection_list;

	mtcp_for_each_sk(mpcb,sub_sk,tp) {
		if (mtcp_sk_not_estab(sub_sk))
			continue;
		cwnd += mtcp_get_crt_cwnd(tp);
	}
	return cwnd;
}

static inline u64 mtcp_get_alpha(struct multipath_pcb *mpcb)
{
	struct mtcp_ccc * mtcp_ccc = inet_csk_ca((struct sock *) mpcb);
	return mtcp_ccc->alpha;
}

static inline void mtcp_set_alpha(struct multipath_pcb *mpcb, u64 alpha)
{
	struct mtcp_ccc * mtcp_ccc = inet_csk_ca((struct sock *) mpcb);
	mtcp_ccc->alpha = alpha;
}

static inline u64 mtcp_ccc_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static void mtcp_recalc_alpha(struct sock *sk)
{
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tcp_sk(sk));

	if (!mpcb)
		return;
	if (mpcb->cnt_established > 1) {
		struct tcp_sock *tp;
		struct sock *sub_sk;
		int best_cwnd = 0, best_rtt = 0, tot_cwnd;
		u64 max_numerator = 0, sum_denominator = 0, tmp, alpha;

		/* The total congestion window might be zero, if the flighsize is 0 */
		if (!(tot_cwnd = mtcp_get_total_cwnd(mpcb)))
			tot_cwnd = 1;

		/* Find the max numerator of the alpha-calculation */
		mtcp_for_each_sk(mpcb,sub_sk,tp) {
			/* This socket is not established and thus srtt is 0 */
			if (mtcp_sk_not_estab(sub_sk))
				continue;

			/* We need to look for the path, that provides the max-
			 * value.
			 * Integer-overflow is not possible here, because
			 * tmp will be in u64.
			 */
			tmp = div64_u64 (mtcp_ccc_scale(tp->snd_cwnd, alpha_scale_num),
					 (u64) tp->srtt * tp->srtt);

			if (tmp >= max_numerator) {
				max_numerator = tmp;
				best_cwnd = tp->snd_cwnd;
				best_rtt = tp->srtt;
			}
		}

		/* Calculate the denominator */
		mtcp_for_each_sk(mpcb,sub_sk,tp) {
			/* This socket is not established and thus srtt is 0 */
			if (mtcp_sk_not_estab(sub_sk))
				continue;

			sum_denominator += div_u64(
					mtcp_ccc_scale(tp->snd_cwnd, alpha_scale_den) *
					best_rtt, tp->srtt);
		}
		sum_denominator *= sum_denominator;

		BUG_ON(!sum_denominator || !best_cwnd || !best_rtt);

		alpha = div64_u64(mtcp_ccc_scale(tot_cwnd, alpha_scale_num) *
				best_cwnd, sum_denominator);

		if (!alpha) alpha = 1;

		mtcp_set_alpha(mpcb, alpha);
	} else {
		/* Only one subflow left - fall back to normal reno-behavior */
		mtcp_set_alpha(mpcb, 1);
	}
}

static void mtcp_cc_init(struct sock *sk)
{
	if (mpcb_from_tcpsock(tcp_sk(sk))) {
		mtcp_set_alpha(mpcb_from_tcpsock(tcp_sk(sk)), 1);
	} /* If we do not mptcp, behave like reno: return */
}

static void mtcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (!mpcb_from_tcpsock(tcp_sk(sk)))
		return;

	if (event == CA_EVENT_LOSS)
		mtcp_recalc_alpha(sk);
}

static void mtcp_fc_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct multipath_pcb *mpcb = mpcb_from_tcpsock(tp);

	if (!mpcb)
		tcp_reno_cong_avoid(sk, ack, in_flight);

	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		/* In "safe" area, increase. */		
		tp->snd_cwnd++;
		mtcp_recalc_alpha(sk);
		
	} else {
		/* In dangerous area, increase slowly.
		 * In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd
		 */
		int snd_cwnd;

		if (mpcb && mpcb->cnt_established > 1){
			u64 alpha = mtcp_get_alpha(mpcb);

			snd_cwnd = mtcp_get_total_cwnd(mpcb);

			snd_cwnd = (int) div_u64 ((u64) mtcp_ccc_scale(snd_cwnd,
					alpha_scale), alpha);
		}
		else {
			snd_cwnd = tp->snd_cwnd;
		}
		
		if (tp->snd_cwnd_cnt >= snd_cwnd) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp){
				tp->snd_cwnd++;
				mtcp_recalc_alpha(sk);
			}
			
			tp->snd_cwnd_cnt=0;
			
		} else {
			tp->snd_cwnd_cnt++;
		}
	}
}

static struct tcp_congestion_ops mtcp_fc = {
	.init		= mtcp_cc_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mtcp_fc_cong_avoid,
	.cwnd_event	= mtcp_cwnd_event,
	.min_cwnd	= tcp_reno_min_cwnd,
	.owner		= THIS_MODULE,
	.name		= "coupled",
};

static int __init mtcp_fc_register(void)
{
	BUILD_BUG_ON(sizeof(struct mtcp_ccc) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mtcp_fc);
}

static void __exit mtcp_fc_unregister(void)
{
	tcp_unregister_congestion_control(&mtcp_fc);
}

module_init(mtcp_fc_register);
module_exit(mtcp_fc_unregister);

MODULE_AUTHOR("Costin Raiciu, Sébastien Barré, Christoph Paasch");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP COUPLED CONGESTION CONTROL");
MODULE_VERSION("0.1");
