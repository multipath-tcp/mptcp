#ifndef __TCP_PROBE_H__
#define __TCP_PROBE_H__ 1

#include <linux/tcp.h>

struct tcpprobe_ops {
	int (*rcv_established)(struct sock *sk, struct sk_buff *skb,
			       struct tcphdr *th, unsigned len);
	int (*transmit_skb)(struct sock *sk, struct sk_buff *skb, 
			    int clone_it, gfp_t gfp_mask);
	int (*logmsg)(struct sock *sk,char *msg, va_list args);
};


int register_probe(struct tcpprobe_ops* ops, unsigned char ipversion);
int unregister_probe(struct tcpprobe_ops* ops, unsigned char ipversion);

int tcpprobe_rcv_established(struct sock *sk, struct sk_buff *skb,
			     struct tcphdr *th, unsigned len);
int tcpprobe_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			  gfp_t gfp_mask);
int tcpprobe_logmsg(struct sock *sk,char *fmt,...);
#endif /*__TCP_PROBE_H__*/
