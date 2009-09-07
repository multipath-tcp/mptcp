#ifndef __TCP_PROBE_H__
#define __TCP_PROBE_H__ 1

#include<linux/tcp.h>

struct tcpprobe_ops {
	int (*rcv_established)(struct sock *sk, struct sk_buff *skb,
			       struct tcphdr *th, unsigned len);
};


int register_probe(struct tcpprobe_ops* ops);
int unregister_probe(struct tcpprobe_ops* ops);

int tcpprobe_rcv_established(struct sock *sk, struct sk_buff *skb,
			     struct tcphdr *th, unsigned len);
#endif /*__TCP_PROBE_H__*/
