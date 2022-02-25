#include <net/mptcp.h>

void mptcp_sched_probe_init(struct mptcp_sched_probe *sprobe)
{
    sprobe->id = 0;
    sprobe->sk = NULL;
    sprobe->selector_reject = false;
    sprobe->found_unused_reject = false;
    sprobe->def_unavailable = false;
    sprobe->temp_unavailable = false;
    sprobe->srtt_reject = false;
    sprobe->selected = false;
    sprobe->split = 0;
    sprobe->skblen = 0;
    sprobe->tx_bytes = 0;
    sprobe->trans_start = 0;
}
EXPORT_SYMBOL_GPL(mptcp_sched_probe_init);

/* This exists only for kretprobe to hook on to and read sprobe */
noinline struct mptcp_sched_probe* mptcp_sched_probe_log_hook(struct mptcp_sched_probe* sprobe, bool selected, unsigned long sched_probe_id, struct sock *sk) {
    sprobe->selected = selected;
    sprobe->id = sched_probe_id;
    sprobe->sk = sk;

    return sprobe;
}
EXPORT_SYMBOL_GPL(mptcp_sched_probe_log_hook);
