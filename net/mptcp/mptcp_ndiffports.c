#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#endif

struct ndiffports_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;

	struct mptcp_cb *mpcb;
};

static int sysctl_mptcp_ndiffports __read_mostly = 2;

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
static void create_subflow_worker(struct work_struct *work)
{
	struct ndiffports_priv *pm_priv = container_of(work,
						     struct ndiffports_priv,
						     subflow_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	int iter = 0;

next_subflow:
	if (iter) {
		release_sock(meta_sk);
		mutex_unlock(&mpcb->mpcb_mutex);

		yield();
	}
	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	iter++;

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		goto exit;

	if (sysctl_mptcp_ndiffports > iter &&
	    sysctl_mptcp_ndiffports > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct mptcp_loc4 loc;

			loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
			loc.id = 0;
			loc.low_prio = 0;

			mptcp_init4_subsockets(meta_sk, &loc, &mpcb->remaddr4[0]);
		} else {
#if IS_ENABLED(CONFIG_IPV6)
			struct mptcp_loc6 loc;

			loc.addr = inet6_sk(meta_sk)->saddr;
			loc.id = 0;
			loc.low_prio = 0;

			mptcp_init6_subsockets(meta_sk, &loc, &mpcb->remaddr6[0]);
#endif
		}
		goto next_subflow;
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

static void ndiffports_new_session(struct sock *meta_sk, u8 id)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct ndiffports_priv *fmp = (struct ndiffports_priv *)&mpcb->mptcp_pm[0];

	/* Initialize workqueue-struct */
	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;
}

static void ndiffports_create_subflows(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct ndiffports_priv *pm_priv = (struct ndiffports_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

static int ndiffports_get_local_id(sa_family_t family, union inet_addr *addr,
				  struct net *net)
{
	return 0;
}

static struct mptcp_pm_ops ndiffports __read_mostly = {
	.new_session = ndiffports_new_session,
	.fully_established = ndiffports_create_subflows,
	.get_local_id = ndiffports_get_local_id,
	.name = "ndiffports",
	.owner = THIS_MODULE,
};

static struct ctl_table ndiff_table[] = {
	{
		.procname = "mptcp_ndiffports",
		.data = &sysctl_mptcp_ndiffports,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{ }
};

struct ctl_table_header *mptcp_sysctl;

/* General initialization of MPTCP_PM */
static int __init ndiffports_register(void)
{
	BUILD_BUG_ON(sizeof(struct ndiffports_priv) > MPTCP_PM_SIZE);

	mptcp_sysctl = register_net_sysctl(&init_net, "net/mptcp", ndiff_table);
	if (!mptcp_sysctl)
		goto exit;

	if (mptcp_register_path_manager(&ndiffports))
		goto pm_failed;

	return 0;

pm_failed:
	unregister_net_sysctl_table(mptcp_sysctl);
exit:
	return -1;
}

static void ndiffports_unregister(void)
{
	mptcp_unregister_path_manager(&ndiffports);
	unregister_net_sysctl_table(mptcp_sysctl);
}

module_init(ndiffports_register);
module_exit(ndiffports_unregister);

MODULE_AUTHOR("Christoph Paasch");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NDIFF-PORTS MPTCP");
MODULE_VERSION("0.88");
