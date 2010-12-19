/*
 * TCP COUPLED CONGESTION CONTROL:
 * 
 * Algorithm: Costin Raiciu, Daemon Wischik, Mark Handley
 * Implementation: user space by Costin Raiciu.
 *           ported to kernel by Sébastien Barré & Christoph Paasch.
 */

#include <net/tcp.h>
#include <net/mtcp.h>

struct mtcp_ccc {
	u64 alpha;
	u32 alpha_scale;
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

static inline u32 mtcp_get_alpha_scale(struct multipath_pcb *mpcb)
{
	struct mtcp_ccc * mtcp_ccc = inet_csk_ca((struct sock *) mpcb);
	return mtcp_ccc->alpha_scale;
}

static inline void mtcp_set_alpha_scale(struct multipath_pcb *mpcb, u32 alpha_scale)
{
	struct mtcp_ccc * mtcp_ccc = inet_csk_ca((struct sock *) mpcb);
	mtcp_ccc->alpha_scale = alpha_scale;
}

static inline u64 mtcp_ccc_scale(u32 val, u32 alpha_scale)
{
	return (u64) val * alpha_scale;
}

static inline u64 mtcp_ccc_scale_down(u64 val, u32 alpha_scale)
{
	return div_u64(val,alpha_scale);
}

static void mtcp_recalc_alpha(struct sock *sk)
{
	struct multipath_pcb *mpcb=mpcb_from_tcpsock(tcp_sk(sk));

	if (!mpcb)
		return;
	if (mpcb->cnt_established > 1) {
		int iter = 0;
		struct tcp_sock *tp;
		struct sock *sub_sk;
		u64 alpha;
		u32 alpha_scale = 512; // TODO select another value?
		u64 max_numerator = 0;
		u64 sum_denominator = 0;
		u64 rtt_product = 1;
		u32 tot_cwnd;
		char use_max_numerator = 0; /* If we had integer-overflow on the
					       numerator, we just use the
					       maximum value */
		char use_max_denominator = 0;
		u64 numerator, denominator;
		int best_cwnd = 0;
		int best_pi = 0;

		/* tp->srtt does not need a shift >> 3, because the units of the rtt get "deleted" */

		/* Get the best alpha_scale-value (based on the numerator)
		 * This will also be the best one for the denominator, because
		 * this one is cwnd_i/rtt_i and thus rtt_i < rtt_i² */
		mtcp_for_each_sk(mpcb,sub_sk,tp) {
			u32 new_val;

			/* This socket is not established and thus srtt is 0 */
			if (mtcp_sk_not_estab(sub_sk))
				continue;

			if (! tp->srtt || ! tp->snd_cwnd) {
				printk(KERN_ERR "%s: tp->srtt == %d and tp->snd_cwnd == %d for pi:%d in state: %d\n",
					__FUNCTION__,tp->srtt, tp->snd_cwnd, tp->path_index, sub_sk->sk_state);
				BUG();
			}

			/* The srtt is that big, that srtt * srtt would result
			 * in an integer-overflow. Thus, we set alpha_scale to
			 * it's maximum value.
			 */
			if (tp->srtt >= 0xFFFF) {
				alpha_scale = 0xFFFFFFFF;
				break;
			}

			new_val = (tp->srtt * tp->srtt) / tp->snd_cwnd;

			for ( ; alpha_scale < new_val * 2 ; alpha_scale *= 2);
		}

recalc_alpha:
		mtcp_set_alpha_scale(mpcb, alpha_scale);

		/* Find the numerator of the alpha-calculation */
		mtcp_for_each_sk(mpcb,sub_sk,tp) {
			u64 new_val;

			/* This socket is not established and thus srtt is 0 */
			if (mtcp_sk_not_estab(sub_sk))
				continue;

			/* We need to look for the path, that provides the max-
			 * value.
			 * Integer-overflow is not possible here, because
			 * new_val will be in u64.
			 */
			new_val = div64_u64 (mtcp_ccc_scale(tp->snd_cwnd, alpha_scale),
					(u64) tp->srtt * tp->srtt);

			if (new_val >= max_numerator) {
				max_numerator = new_val;
				best_pi = tp->path_index;
				best_cwnd = tp->snd_cwnd;
			}
		}

		BUG_ON(!best_pi || !best_cwnd);

		/* The total congestion window might be zero, if the flighsize is 0 */
		if ( !(tot_cwnd = mtcp_get_total_cwnd(mpcb)))
			tot_cwnd = 1;

		mtcp_for_each_sk(mpcb, sub_sk, tp) {
			/* This socket is not established and thus srtt is 0 */
			if (mtcp_sk_not_estab(sub_sk) || tp->path_index == best_pi)
				continue;

			/* Potential integer-overflow. We have to use the maximum
			 * value at the numerator.
			 */
			if (rtt_product > div_u64((u64) 0xFFFFFFFFFFFFFFFFLLU, tp->srtt) ||
			    rtt_product * tp->srtt > div_u64((u64) 0xFFFFFFFFFFFFFFFFLLU, tp->srtt)) {
				mtcp_debug(KERN_ERR "will use max numerator - rtt_prod: %llu tp->srtt %d\n", rtt_product, tp->srtt);
				use_max_numerator = 1;
				break;
			}

			rtt_product *= ((u64) tp->srtt) * tp->srtt;
		}

		/* Find the denominator of the alpha-calculation */
		mtcp_for_each_sk(mpcb,sub_sk,tp) {
			struct tcp_sock *tp_tmp;
			struct sock *sub_sk_tmp;
			u64 rtt_product_tmp = 1;

			/* This socket is not established and thus srtt is 0 */
			if (mtcp_sk_not_estab(sub_sk))
				continue;

			mtcp_for_each_sk(mpcb, sub_sk_tmp, tp_tmp) {
				/* This socket is not established and thus srtt is 0 */
				if (mtcp_sk_not_estab(sub_sk_tmp) ||
				    tp_tmp->path_index == tp->path_index)
					continue;

				/* Potential integer-overflow. We have to use
				 * the maximum value at the denominator.
				 */
				if (rtt_product_tmp > div_u64((u64) 0xFFFFFFFFFFFFFFFFLLU, tp->srtt)) {
					mtcp_debug(KERN_ERR "will use max denominator - rtt_prod_tmp: %llu tp_tmp->srtt %d\n", rtt_product_tmp, tp_tmp->srtt);
					use_max_denominator = 1;
					break;
				}

				rtt_product_tmp *= tp_tmp->srtt;
			}

			if (use_max_denominator ||
			    rtt_product_tmp > div_u64((u64) 0xFFFFFFFFFFFFFFFFLLU,  tp->snd_cwnd)||
			    sum_denominator > ((u64) 0xFFFFFFFFFFFFFFFFLLU) - tp->snd_cwnd * rtt_product_tmp) {
				mtcp_debug(KERN_ERR "will use max denominator - rtt_prod_tmp: %llu tp->snd_cwnd %d sum_denominator %llu\n", rtt_product_tmp, tp->snd_cwnd, sum_denominator);
				use_max_denominator = 1;
				break;
			}


			sum_denominator += tp->snd_cwnd * rtt_product_tmp;
		}

		if (use_max_numerator ||
		    ((u64) mtcp_ccc_scale(tot_cwnd, alpha_scale)) > div64_u64((u64) 0xFFFFFFFFFFFFFFFFLLU, rtt_product) ||
		    ((u64) mtcp_ccc_scale(tot_cwnd, alpha_scale)) * rtt_product > div_u64((u64) 0xFFFFFFFFFFFFFFFFLLU, best_cwnd)) {
			mtcp_debug(KERN_ERR "using max nominator - scaled_windos %llu, rtt_product %llu, best_cwnd %d\n", mtcp_ccc_scale(tot_cwnd, alpha_scale),rtt_product, best_cwnd);
			numerator = (u64) 0xFFFFFFFFFFFFFFFFLLU;
		} else
			numerator = ((u64) mtcp_ccc_scale(tot_cwnd, alpha_scale)) * rtt_product * best_cwnd;

		if (use_max_denominator ||
		    sum_denominator > div64_u64((u64) 0xFFFFFFFFFFFFFFFFLLU, sum_denominator)) {
			mtcp_debug(KERN_ERR "using max denominator - sum_denominator %llu\n", sum_denominator);
			denominator = (u64) 0xFFFFFFFFFFFFFFFFLLU;
		} else
			denominator = sum_denominator * sum_denominator;


		alpha = div64_u64(numerator, denominator);

		/* We need to improve the scaling-factor */
		if (!alpha) {
			u32 new_scale;

			new_scale = div64_u64(denominator,
				    mtcp_ccc_scale_down(numerator, alpha_scale));

			/* This may happen, if the difference is minimal and
			 * falls into the category of fixed-number caluclation
			 * errors. */
			if (alpha_scale >= new_scale)
				alpha_scale *= 2;

			/* If we have integer-overflow for alpha_scaling, we use
			 * alpha = 0
			 */
			if (!alpha_scale) {
				printk(KERN_ERR "alpha_scale == 0, numerator: %llu denominator: %llu\n", numerator, denominator);
				goto exit;
			}

			for ( ; alpha_scale < new_scale * 2 ; alpha_scale *= 2);

			/* If we have integer-overflow for alpha_scaling, we use
			 * alpha = 0
			 */
			if (!alpha_scale) {
				printk(KERN_ERR "alpha_scale == 0, numerator: %llu denominator: %llu\n", numerator, denominator);
				goto exit;
			}

			if (iter)
				printk(KERN_ERR "%s scaling up for the second time!!! iter:%d alpha_scale: %du  new_scale: %d\n", __FUNCTION__, iter, alpha_scale, new_scale);
			iter++;

			goto recalc_alpha;
		}
exit:
		mtcp_set_alpha(mpcb, alpha);
	} else {
		/* Only one subflow left - fall back to normal reno-behavior */
		mtcp_set_alpha(mpcb, 1);
		mtcp_set_alpha_scale(mpcb_from_tcpsock(tcp_sk(sk)), 1);
	}
}

static void mtcp_cc_init(struct sock *sk)
{
	if (mpcb_from_tcpsock(tcp_sk(sk))) {
		mtcp_set_alpha(mpcb_from_tcpsock(tcp_sk(sk)), 1);
		mtcp_set_alpha_scale(mpcb_from_tcpsock(tcp_sk(sk)), 1);
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
			u32 alpha_scale = mtcp_get_alpha_scale(mpcb);

			/* TODO What, if tot_cwnd is 0, due to flightsize == 0? */
			snd_cwnd = mtcp_get_total_cwnd(mpcb);

			snd_cwnd = (int) div_u64 ((u64) snd_cwnd * alpha_scale, alpha);
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
