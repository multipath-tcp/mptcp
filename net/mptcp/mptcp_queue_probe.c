/*
 * mptcp_queue_probe - Observe the MPTCP meta ofo and recv queues with kretprobes.
 *
 * The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <net/net_namespace.h>
#include <linux/version.h>

#include <net/tcp.h>
#include <net/mptcp.h>

MODULE_AUTHOR("Swetank Kumar Saha <swetankk@buffalo.edu>");
MODULE_DESCRIPTION("MPTCP meta queues snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

static int port __read_mostly;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

static unsigned int bufsize __read_mostly = 4096;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (4096)");
module_param(bufsize, uint, 0);

static const char procname[] = "mptcp_queue_probe";

struct tcp_log {
	ktime_t tstamp;	

	u8 queue;
	u32 queue_size;
	u32 ofo_tstamp;
    u32 seq;
    u32 end_seq;
	u8 operation;
};

static struct {
	spinlock_t	lock;
	wait_queue_head_t wait;
	ktime_t		start;
	u32		lastcwnd;

	unsigned long	head, tail;
	struct tcp_log	*log;
} tcp_probe;

static inline int tcp_probe_used(void)
{
	return (tcp_probe.head - tcp_probe.tail) & (bufsize - 1);
}

static inline int tcp_probe_avail(void)
{
	return bufsize - tcp_probe_used() - 1;
}

#define tcp_probe_copy_fl_to_si4(inet, si4, mem)		\
	do {							\
		si4.sin_family = AF_INET;			\
		si4.sin_port = inet->inet_##mem##port;		\
		si4.sin_addr.s_addr = inet->inet_##mem##addr;	\
	} while (0)						\

static void log_tcp_params(struct mptcp_queue_probe* qprobe) 
{
	//const struct tcp_sock *meta_tp = qprobe->meta_tp;
	//const struct mptcp_cb *mpcb = meta_tp->mpcb;
    
    spin_lock(&tcp_probe.lock);
    /* If log fills, just silently drop*/ 
    if (tcp_probe_avail() > 1){			 
        struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			
        p->tstamp = ktime_get();

		p->queue = qprobe->q_id; /* 0: RCV_Q, 1: OFO_Q */
        p->queue_size = qprobe->q_size;
        p->operation = qprobe->op_id;
        p->seq = qprobe->skb_seq;
        p->end_seq = qprobe->skb_end_seq;      
	    
        tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
	}
    spin_unlock(&tcp_probe.lock);
	wake_up(&tcp_probe.wait);
}

static int kmptcp_queue_probe_log_hook(struct kretprobe_instance *ri, struct pt_regs *regs) {
	struct mptcp_queue_probe* qprobe;
    
	qprobe = (struct mptcp_queue_probe*) regs_return_value(regs); 
	log_tcp_params(qprobe);
	return 0;
}

static struct kretprobe mptcp_kprobe = {
	.kp = {
		.symbol_name	= "mptcp_queue_probe_log_hook",
	},
	.handler	= kmptcp_queue_probe_log_hook,
};

static int tcpprobe_open(struct inode *inode, struct file *file)
{
	/* Reset (empty) log */
	spin_lock_bh(&tcp_probe.lock);
	tcp_probe.head = tcp_probe.tail = 0;
	tcp_probe.start = ktime_get();
	spin_unlock_bh(&tcp_probe.lock);

	return 0;
}

static int tcpprobe_sprint(char *tbuf, int n)
{
	const struct tcp_log *p
		= tcp_probe.log + tcp_probe.tail;
	struct timespec tv
		= ktime_to_timespec(ktime_sub(p->tstamp, tcp_probe.start));
	
	return scnprintf(tbuf, n,
            "%lu.%09lu %x %u %u %u %x\n",
            (unsigned long)tv.tv_sec,
            (unsigned long)tv.tv_nsec, p->queue, p->seq, p->end_seq, p->queue_size, p->operation);
}

static ssize_t tcpprobe_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	int error = 0;
	size_t cnt = 0;

	if (!buf)
		return -EINVAL;

	while (cnt < len) {
		char tbuf[256];
		int width;

		/* Wait for data in buffer */
		error = wait_event_interruptible(tcp_probe.wait,
						 tcp_probe_used() > 0);
		
		if (error)
			break;

		spin_lock_bh(&tcp_probe.lock);
		if (tcp_probe.head == tcp_probe.tail) {
			/* multiple readers race? */
			spin_unlock_bh(&tcp_probe.lock);
			continue;
		}

		width = tcpprobe_sprint(tbuf, sizeof(tbuf));

		if (cnt + width < len)
			tcp_probe.tail = (tcp_probe.tail + 1) & (bufsize - 1);
	
		spin_unlock_bh(&tcp_probe.lock);
		
		/* if record greater than space available
		   return partial buffer (so far) */
		if (cnt + width >= len)
			break;
		
		if (copy_to_user(buf + cnt, tbuf, width))
			return -EFAULT;
		
		cnt += width;
	}

	return cnt == 0 ? error : cnt;
}

static const struct file_operations tcpprobe_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tcpprobe_open,
	.read    = tcpprobe_read,
	.llseek  = noop_llseek,
};

static __init int tcpprobe_init(void)
{
	int ret = -ENOMEM;

	/* Warning: if the function signature of tcp_rcv_established,
	 * has been changed, you also have to change the signature of
	 * jtcp_rcv_established, otherwise you end up right here!
	 */
		
	init_waitqueue_head(&tcp_probe.wait);
	spin_lock_init(&tcp_probe.lock);

	if (bufsize == 0)
		return -EINVAL;

	bufsize = roundup_pow_of_two(bufsize);
    tcp_probe.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
	if (!tcp_probe.log)
		goto err0;
    
	if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcpprobe_fops))
		goto err0;
    
	ret = register_kretprobe(&mptcp_kprobe);

	if (ret)
		goto err1;
	
    pr_info("probe registered bufsize=%u\n", bufsize);
	return 0;
 err1:
	remove_proc_entry(procname, init_net.proc_net);
 err0:
	kfree(tcp_probe.log);
	return ret;
}
module_init(tcpprobe_init);

static __exit void tcpprobe_exit(void)
{
	remove_proc_entry(procname, init_net.proc_net);
	unregister_kretprobe(&mptcp_kprobe);
	kfree(tcp_probe.log);
}
module_exit(tcpprobe_exit);
