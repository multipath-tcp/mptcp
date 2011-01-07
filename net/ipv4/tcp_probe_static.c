#include <linux/tcp_probe.h>
#include <linux/ip.h>

static struct tcpprobe_ops *tcpprobe_fcts=NULL;
static struct tcpprobe_ops *tcpprobe6_fcts=NULL;

static struct tcpprobe_ops **select_family(unsigned short family)
{
	switch (family) {
	case 4:
		return &tcpprobe_fcts;
	case 6:
		return &tcpprobe6_fcts;
	default:
		return NULL;
	}
}

/* @ipversion is 4 or 6
 */
int register_probe(struct tcpprobe_ops* ops, unsigned char ipversion)
{
	struct tcpprobe_ops **vops=select_family(ipversion);
	/*return -1 if incorrect family, or ops already registered*/
	if (!vops || *vops) return -1;
	*vops=ops;
	return 0;
}
EXPORT_SYMBOL(register_probe);

int unregister_probe(struct tcpprobe_ops* ops, unsigned char ipversion)
{
	struct tcpprobe_ops **vops=select_family(ipversion);
	/*return -1 if incorrect family*/
	if (!vops) return -1;
	if (*vops!=ops) return -1; /*trying to unregister something 
				     else, probably a bug*/
	*vops=NULL;
	return 0;
}
EXPORT_SYMBOL(unregister_probe);

int tcpprobe_rcv_established(struct sock *sk, struct sk_buff *skb,
			     struct tcphdr *th, unsigned len) 
{
	int ipversion=ip_hdr(skb)->version;
	struct tcpprobe_ops **vops=select_family(ipversion);
	
	/*return -1 if incorrect family*/
	if (!vops) return -1;
	if (!*vops) return 0;
	return (*vops)->rcv_established(sk,skb,th,len);
}

int tcpprobe_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			  gfp_t gfp_mask)
{
	int ipversion=(sk->sk_family==AF_INET6)?6:4;
	struct tcpprobe_ops **vops=select_family(ipversion);
	
	/*return -1 if incorrect family*/
	if (!vops) return -1;
	if (!*vops) return 0;
	return (*vops)->transmit_skb(sk,skb,clone_it,gfp_mask);
}

int tcpprobe_logmsg(struct sock *sk,char *fmt,...)
{
	int ipversion=(sk->sk_family==AF_INET6)?6:4;
	struct tcpprobe_ops **vops=select_family(ipversion);
	va_list args;
	int i;
	
	return 0; /*bypassed at the moment*/

	/*return -1 if incorrect family*/

	if (!vops) return -1;
	if (!*vops) return 0;
	va_start(args,fmt);
	i=(*vops)->logmsg(sk,fmt,args);
	va_end(args);
	return i;
}
