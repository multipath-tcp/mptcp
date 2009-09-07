#include <linux/tcp_probe.h>

static struct tcpprobe_ops *tcpprobe_fcts=NULL;

int register_probe(struct tcpprobe_ops* ops)
{
	if (tcpprobe_fcts) return -1; /*Already registered*/
	tcpprobe_fcts=ops;
	return 0;
}
EXPORT_SYMBOL(register_probe);

int unregister_probe(struct tcpprobe_ops* ops)
{
	if (tcpprobe_fcts!=ops) return -1; /*trying to unregister something 
					     else, probably a bug*/
	tcpprobe_fcts=NULL;
	return 0;
}
EXPORT_SYMBOL(unregister_probe);

int tcpprobe_rcv_established(struct sock *sk, struct sk_buff *skb,
			     struct tcphdr *th, unsigned len) 
{
	if (!tcpprobe_fcts) return 0;
	return tcpprobe_fcts->rcv_established(sk,skb,th,len);
}
