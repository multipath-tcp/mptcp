#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#include <net/addrconf.h>
#endif

enum {
	MPTCP_EVENT_ADD = 1,
	MPTCP_EVENT_DEL,
	MPTCP_EVENT_MOD,
};

struct mptcp_loc_addr {
	struct mptcp_loc4 locaddr4[MPTCP_MAX_ADDR];
	u8 loc4_bits;
	u8 next_v4_index;

	struct mptcp_loc6 locaddr6[MPTCP_MAX_ADDR];
	u8 loc6_bits;
	u8 next_v6_index;
};

struct mptcp_addr_event {
	struct list_head list;
	unsigned short	family;
	u8	code:7,
		low_prio:1;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	}u;
};

struct fullmesh_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;
	/* Delayed worker, when the routing-tables are not yet ready. */
	struct delayed_work subflow_retry_work;

	struct mptcp_cb *mpcb;

	u16 remove_addrs; /* Addresses to remove */
	u8 announced_addrs_v4; /* IPv4 Addresses we did announce */
	u8 announced_addrs_v6; /* IPv4 Addresses we did announce */

	u8	add_addr; /* Are we sending an add_addr? */
};

struct mptcp_fm_ns {
	struct mptcp_loc_addr __rcu *local;
	spinlock_t local_lock; /* Protecting the above pointer */
	struct list_head events;
	struct delayed_work address_worker;

	struct net *net;
};

static struct mptcp_fm_ns *fm_get_ns(struct net *net)
{
	return (struct mptcp_fm_ns *)net->mptcp.path_managers[MPTCP_PM_FULLMESH];
}

static void full_mesh_create_subflows(struct sock *meta_sk);

static void retry_subflow_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work = container_of(work,
							 struct delayed_work,
							 work);
	struct fullmesh_priv *pm_priv = container_of(delayed_work,
						     struct fullmesh_priv,
						     subflow_retry_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_fm_ns *fm_ns = fm_get_ns(sock_net(meta_sk));
	int iter = 0, i;

	/* We need a local (stable) copy of the address-list. Really, it is not
	 * such a big deal, if the address-list is not 100% up-to-date.
	 */
	rcu_read_lock_bh();
	mptcp_local = rcu_dereference_bh(fm_ns->local);
	mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local), GFP_ATOMIC);
	rcu_read_unlock_bh();

	if (!mptcp_local)
		return;

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

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		struct mptcp_rem4 *rem = &mpcb->remaddr4[i];
		/* Do we need to retry establishing a subflow ? */
		if (rem->retry_bitfield) {
			int i = mptcp_find_free_index(~rem->retry_bitfield);
			mptcp_init4_subsockets(meta_sk, &mptcp_local->locaddr4[i], rem);
			rem->retry_bitfield &= ~(1 << i);
			goto next_subflow;
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		struct mptcp_rem6 *rem = &mpcb->remaddr6[i];

		/* Do we need to retry establishing a subflow ? */
		if (rem->retry_bitfield) {
			int i = mptcp_find_free_index(~rem->retry_bitfield);
			mptcp_init6_subsockets(meta_sk, &mptcp_local->locaddr6[i], rem);
			rem->retry_bitfield &= ~(1 << i);
			goto next_subflow;
		}
	}
#endif

exit:
	kfree(mptcp_local);
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
static void create_subflow_worker(struct work_struct *work)
{
	struct fullmesh_priv *pm_priv = container_of(work,
						     struct fullmesh_priv,
						     subflow_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_fm_ns *fm_ns = fm_get_ns(sock_net(meta_sk));
	int iter = 0, retry = 0;
	int i;

	/* We need a local (stable) copy of the address-list. Really, it is not
	 * such a big deal, if the address-list is not 100% up-to-date.
	 */
	rcu_read_lock_bh();
	mptcp_local = rcu_dereference_bh(fm_ns->local);
	mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local), GFP_ATOMIC);
	rcu_read_unlock_bh();

	if (!mptcp_local)
		return;

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

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		struct mptcp_rem4 *rem;
		u8 remaining_bits;

		rem = &mpcb->remaddr4[i];
		remaining_bits = ~(rem->bitfield) & mptcp_local->loc4_bits;

		/* Are there still combinations to handle? */
		if (remaining_bits) {
			int i = mptcp_find_free_index(~remaining_bits);
			/* If a route is not yet available then retry once */
			if (mptcp_init4_subsockets(meta_sk, &mptcp_local->locaddr4[i],
						   rem) == -ENETUNREACH)
				retry = rem->retry_bitfield |= (1 << i);
			goto next_subflow;
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
		struct mptcp_rem6 *rem;
		u8 remaining_bits;

		rem = &mpcb->remaddr6[i];
		remaining_bits = ~(rem->bitfield) & mptcp_local->loc6_bits;

		/* Are there still combinations to handle? */
		if (remaining_bits) {
			int i = mptcp_find_free_index(~remaining_bits);
			/* If a route is not yet available then retry once */
			if (mptcp_init6_subsockets(meta_sk, &mptcp_local->locaddr6[i],
						   rem) == -ENETUNREACH)
				retry = rem->retry_bitfield |= (1 << i);
			goto next_subflow;
		}
	}
#endif

	if (retry && !delayed_work_pending(&pm_priv->subflow_retry_work)) {
		sock_hold(meta_sk);
		queue_delayed_work(mptcp_wq, &pm_priv->subflow_retry_work,
				   msecs_to_jiffies(MPTCP_SUBFLOW_RETRY_DELAY));
	}

exit:
	kfree(mptcp_local);
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

static void update_remove_addrs(u8 addr_id, struct sock *meta_sk,
				struct mptcp_loc_addr *mptcp_local)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct fullmesh_priv *fmp = (struct fullmesh_priv *)&mpcb->mptcp_pm[0];
	struct sock *sk;
	int i;

	fmp->remove_addrs |= (1 << addr_id);
	/* v4 goes from 0 to MPTCP_MAX_ADDR, v6 beyond */
	if (addr_id < MPTCP_MAX_ADDR) {
		fmp->announced_addrs_v4 &= ~(1 << addr_id);

		mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
			mpcb->remaddr4[i].bitfield &= mptcp_local->loc4_bits;
			mpcb->remaddr4[i].retry_bitfield &= mptcp_local->loc4_bits;
		}
	} else {
		fmp->announced_addrs_v6 &= ~(1 << (addr_id - MPTCP_MAX_ADDR));

		mptcp_for_each_bit_set(mpcb->rem6_bits, i) {
			mpcb->remaddr6[i].bitfield &= mptcp_local->loc6_bits;
			mpcb->remaddr6[i].retry_bitfield &= mptcp_local->loc6_bits;
		}
	}

	sk = mptcp_select_ack_sock(meta_sk, 0);
	if (sk)
		tcp_send_ack(sk);
}

static int mptcp_find_address(struct mptcp_loc_addr *mptcp_local,
			      struct mptcp_addr_event *event)
{
	int i;
	u8 loc_bits;
	bool found = false;

	if (event->family == AF_INET)
		loc_bits = mptcp_local->loc4_bits;
	else
		loc_bits = mptcp_local->loc6_bits;

	mptcp_for_each_bit_set(loc_bits, i) {
		if (event->family == AF_INET &&
		    mptcp_local->locaddr4[i].addr.s_addr == event->u.addr4.s_addr) {
			found = true;
			break;
		}
		if (event->family == AF_INET6 &&
		    ipv6_addr_equal(&mptcp_local->locaddr6[i].addr,
				    &event->u.addr6)) {
			found = true;
			break;
		}
	}

	if (!found)
		return -1;

	return i;
}

static void mptcp_address_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work = container_of(work,
							 struct delayed_work,
							 work);
	struct mptcp_fm_ns *fm_ns = container_of(delayed_work,
						 struct mptcp_fm_ns,
						 address_worker);
	struct net *net = fm_ns->net;
	struct mptcp_addr_event *event = NULL;
	struct mptcp_loc_addr *mptcp_local, *old;
	int i, id = -1; /* id is used in the socket-code on a delete-event */
	bool success; /* Used to indicate if we succeeded handling the event */

next_event:
	success = false;
	kfree(event);

	/* First, let's dequeue an event from our event-list */
	rcu_read_lock_bh();
	spin_lock(&fm_ns->local_lock);

	event = list_first_entry_or_null(&fm_ns->events,
					 struct mptcp_addr_event, list);
	if (!event) {
		spin_unlock(&fm_ns->local_lock);
		rcu_read_unlock_bh();
		return;
	}

	list_del(&event->list);

	mptcp_local = rcu_dereference_bh(fm_ns->local);

	if (event->code == MPTCP_EVENT_DEL) {
		id = mptcp_find_address(mptcp_local, event);

		/* Not in the list - so we don't care */
		if (id < 0)
			goto duno;

		old = mptcp_local;
		mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local),
				      GFP_ATOMIC);
		if (!mptcp_local)
			goto duno;

		if (event->family == AF_INET)
			mptcp_local->loc4_bits &= ~(1 << id);
		else
			mptcp_local->loc6_bits &= ~(1 << id);

		rcu_assign_pointer(fm_ns->local, mptcp_local);
		kfree(old);
	} else {
		int i = mptcp_find_address(mptcp_local, event);
		int j = i;

		if (j < 0) {
			/* Not in the list, so we have to find an empty slot */
			if (event->family == AF_INET)
				i = __mptcp_find_free_index(mptcp_local->loc4_bits, 0,
							    mptcp_local->next_v4_index);
			if (event->family == AF_INET6)
				i = __mptcp_find_free_index(mptcp_local->loc6_bits, 0,
							    mptcp_local->next_v6_index);

			if (i < 0)
				goto duno;

			/* It might have been a MOD-event. */
			event->code = MPTCP_EVENT_ADD;
		} else {
			/* Let's check if anything changes */
			if (event->family == AF_INET && 
			    event->low_prio == mptcp_local->locaddr4[i].low_prio)
				goto duno;

			if (event->family == AF_INET6 && 
			    event->low_prio == mptcp_local->locaddr6[i].low_prio)
				goto duno;
		}

		old = mptcp_local;
		mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local),
				      GFP_ATOMIC);
		if (!mptcp_local)
			goto duno;

		if (event->family == AF_INET) {
			mptcp_local->locaddr4[i].addr.s_addr = event->u.addr4.s_addr;
			mptcp_local->locaddr4[i].id = i;
			mptcp_local->locaddr4[i].low_prio = event->low_prio;
		} else {
			mptcp_local->locaddr6[i].addr = event->u.addr6;
			mptcp_local->locaddr6[i].id = i + MPTCP_MAX_ADDR;
			mptcp_local->locaddr6[i].low_prio = event->low_prio;
		}

		if (j < 0) {
			if (event->family == AF_INET) {
				mptcp_local->loc4_bits |= (1 << i);
				mptcp_local->next_v4_index = i + 1;
			} else {
				mptcp_local->loc6_bits |= (1 << i);
				mptcp_local->next_v6_index = i + 1;
			}
		}

		rcu_assign_pointer(fm_ns->local, mptcp_local);
		kfree(old);
	}
	success = true;

duno:
	spin_unlock(&fm_ns->local_lock);
	rcu_read_unlock_bh();

	if (!success)
		goto next_event;

	/* Now we iterate over the MPTCP-sockets and apply the event. */
	for (i = 0; i < MPTCP_HASH_SIZE; i++) {
		struct hlist_nulls_node *node;
		struct tcp_sock *meta_tp;

		rcu_read_lock_bh();
		hlist_nulls_for_each_entry_rcu(meta_tp, node, &tk_hashtable[i],
					       tk_table) {
			struct mptcp_cb *mpcb = meta_tp->mpcb;
			struct sock *meta_sk = (struct sock *)meta_tp, *sk;
			struct fullmesh_priv *fmp = (struct fullmesh_priv *)&mpcb->mptcp_pm[0];

			if (sock_net(meta_sk) != net)
				continue;

			if (unlikely(!atomic_inc_not_zero(&meta_sk->sk_refcnt)))
				continue;

			bh_lock_sock(meta_sk);

			if (!meta_tp->mpc || !is_meta_sk(meta_sk) ||
			    mpcb->infinite_mapping_snd ||
			    mpcb->infinite_mapping_rcv ||
			    mpcb->send_infinite_mapping)
				goto next;

			if (sock_owned_by_user(meta_sk)) {
				if (!test_and_set_bit(MPTCP_PATH_MANAGER,
						      &meta_tp->tsq_flags))
					sock_hold(meta_sk);

				goto next;
			}

			if (event->code == MPTCP_EVENT_ADD) {
				if (event->family == AF_INET)
					fmp->add_addr++;
#if IS_ENABLED(CONFIG_IPV6)
				if (event->family == AF_INET6)
					fmp->add_addr++;
#endif

				sk = mptcp_select_ack_sock(meta_sk, 0);
				if (sk)
					tcp_send_ack(sk);

				full_mesh_create_subflows(meta_sk);
			}

			if (event->code == MPTCP_EVENT_DEL) {
				struct sock *sk, *tmpsk;
				struct mptcp_loc_addr *mptcp_local;
				bool found = false;

				mptcp_local = rcu_dereference_bh(fm_ns->local);

				/* Look for the socket and remove him */
				mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
					if ((event->family == AF_INET6 &&
					     (sk->sk_family == AF_INET ||
					      mptcp_v6_is_v4_mapped(sk))) ||
					    (event->family == AF_INET &&
					     (sk->sk_family == AF_INET6 &&
					      !mptcp_v6_is_v4_mapped(sk))))
						continue;

					if (event->family == AF_INET &&
					    (sk->sk_family == AF_INET ||
					     mptcp_v6_is_v4_mapped(sk)) &&
					     inet_sk(sk)->inet_saddr != event->u.addr4.s_addr)
						continue;

					if (event->family == AF_INET6 &&
					    sk->sk_family == AF_INET6 &&
					    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &event->u.addr6))
						continue;

					/* Reinject, so that pf = 1 and so we
					 * won't select this one as the
					 * ack-sock.
					 */
					mptcp_reinject_data(sk, 0);

					/* A master is special, it has
					 * address-id 0
					 */
					if (!tcp_sk(sk)->mptcp->loc_id)
						update_remove_addrs(0, meta_sk, mptcp_local);
					else if (tcp_sk(sk)->mptcp->loc_id != id)
						update_remove_addrs(tcp_sk(sk)->mptcp->loc_id, meta_sk, mptcp_local);

					mptcp_sub_force_close(sk);
					found = true;
				}

				if (!found)
					goto next;

				/* The id may have been given by the event,
				 * matching on a local address. And it may not
				 * have matched on one of the above sockets,
				 * because the client never created a subflow.
				 * So, we have to finally remove it here.
				 */
				if (id > 0)
					update_remove_addrs(id, meta_sk, mptcp_local);
			}

			if (event->code == MPTCP_EVENT_MOD) {
				struct sock *sk;

				mptcp_for_each_sk(mpcb, sk) {
					struct tcp_sock *tp = tcp_sk(sk);
					if (event->family == AF_INET &&
					    (sk->sk_family == AF_INET ||
					     mptcp_v6_is_v4_mapped(sk)) &&
					     inet_sk(sk)->inet_saddr == event->u.addr4.s_addr) {
						if (event->low_prio != tp->mptcp->low_prio) {
							tp->mptcp->send_mp_prio = 1;
							tp->mptcp->low_prio = event->low_prio;

							tcp_send_ack(sk);
						}
					}

					if (event->family == AF_INET6 &&
					    sk->sk_family == AF_INET6 &&
					    !ipv6_addr_equal(&inet6_sk(sk)->saddr, &event->u.addr6)) {
						if (event->low_prio != tp->mptcp->low_prio) {
							tp->mptcp->send_mp_prio = 1;
							tp->mptcp->low_prio = event->low_prio;

							tcp_send_ack(sk);
						}
					}
				}
			}
next:
			bh_unlock_sock(meta_sk);
			sock_put(meta_sk);
		}
		rcu_read_unlock_bh();
	}
	goto next_event;
}

static struct mptcp_addr_event *lookup_similar_event(struct net *net,
						     struct mptcp_addr_event *event)
{
	struct mptcp_addr_event *eventq;
	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);

	list_for_each_entry(eventq, &fm_ns->events, list) {
		if (eventq->family != event->family)
			continue;
		if (event->family == AF_INET) {
			if (eventq->u.addr4.s_addr == event->u.addr4.s_addr)
				return eventq;
		} else {
			if (ipv6_addr_equal(&eventq->u.addr6, &event->u.addr6))
				return eventq;
		}
	}
	return NULL;
}

/* We already hold the net-namespace MPTCP-lock */
static void add_pm_event(struct net *net, struct mptcp_addr_event *event)
{
	struct mptcp_addr_event *eventq = lookup_similar_event(net, event);
	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);

	if (eventq) {
		switch (event->code) {
		case MPTCP_EVENT_DEL:
			list_del(&eventq->list);
			kfree(eventq);
			break;
		case MPTCP_EVENT_ADD:
			eventq->low_prio = event->low_prio;
			eventq->code = MPTCP_EVENT_ADD;
			return;
		case MPTCP_EVENT_MOD:
			eventq->low_prio = event->low_prio;
			return;
		}
	}

	/* OK, we have to add the new address to the wait queue */
	eventq = kmemdup(event, sizeof(struct mptcp_addr_event), GFP_ATOMIC);
	if (!eventq)
		return;

	list_add_tail(&eventq->list, &fm_ns->events);

	/* Create work-queue */
	if (!delayed_work_pending(&fm_ns->address_worker))
		queue_delayed_work(mptcp_wq, &fm_ns->address_worker,
				   msecs_to_jiffies(500));
}

static void addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				struct net *net)
{
	struct net_device *netdev = ifa->ifa_dev->dev;
	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);
	struct mptcp_addr_event mpevent;

	if (ifa->ifa_scope > RT_SCOPE_LINK ||
	    ipv4_is_loopback(ifa->ifa_local))
		return;

	spin_lock_bh(&fm_ns->local_lock);

	mpevent.family = AF_INET;
	mpevent.u.addr4.s_addr = ifa->ifa_local;
	mpevent.low_prio = (netdev->flags & IFF_MPBACKUP) ? 1 : 0;

	if (event == NETDEV_DOWN || !netif_running(netdev) ||
	    (netdev->flags & IFF_NOMULTIPATH))
		mpevent.code = MPTCP_EVENT_DEL;
	else if (event == NETDEV_UP)
		mpevent.code = MPTCP_EVENT_ADD;
	else if (event == NETDEV_CHANGE)
		mpevent.code = MPTCP_EVENT_MOD;

	add_pm_event(net, &mpevent);

	spin_unlock_bh(&fm_ns->local_lock);
	return;
}

/* React on IPv4-addr add/rem-events */
static int mptcp_pm_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net *net = dev_net(ifa->ifa_dev->dev);

	addr4_event_handler(ifa, event, net);

	return NOTIFY_DONE;
}

static struct notifier_block mptcp_pm_inetaddr_notifier = {
		.notifier_call = mptcp_pm_inetaddr_event,
};

#if IS_ENABLED(CONFIG_IPV6)

/* IPV6-related address/interface watchers */
struct mptcp_dad_data {
	struct timer_list timer;
	struct inet6_ifaddr *ifa;
};

static void dad_callback(unsigned long arg);
static int inet6_addr_event(struct notifier_block *this,
				     unsigned long event, void *ptr);

static int ipv6_is_in_dad_state(struct inet6_ifaddr *ifa)
{
	return ((ifa->flags & IFA_F_TENTATIVE) &&
		ifa->state == INET6_IFADDR_STATE_DAD);
}

static void dad_init_timer(struct mptcp_dad_data *data,
				 struct inet6_ifaddr *ifa)
{
	data->ifa = ifa;
	data->timer.data = (unsigned long)data;
	data->timer.function = dad_callback;
	if (ifa->idev->cnf.rtr_solicit_delay)
		data->timer.expires = jiffies + ifa->idev->cnf.rtr_solicit_delay;
	else
		data->timer.expires = jiffies + (HZ/10);
}

static void dad_callback(unsigned long arg)
{
	struct mptcp_dad_data *data = (struct mptcp_dad_data *)arg;

	if (ipv6_is_in_dad_state(data->ifa)) {
		dad_init_timer(data, data->ifa);
		add_timer(&data->timer);
	} else {
		inet6_addr_event(NULL, NETDEV_UP, data->ifa);
		in6_ifa_put(data->ifa);
		kfree(data);
	}
}

static inline void dad_setup_timer(struct inet6_ifaddr *ifa)
{
	struct mptcp_dad_data *data;

	data = kmalloc(sizeof(*data), GFP_ATOMIC);

	if (!data)
		return;

	init_timer(&data->timer);
	dad_init_timer(data, ifa);
	add_timer(&data->timer);
	in6_ifa_hold(ifa);
}

static void addr6_event_handler(struct inet6_ifaddr *ifa, unsigned long event,
				struct net *net)
{
	struct net_device *netdev = ifa->idev->dev;
	int addr_type = ipv6_addr_type(&ifa->addr);
	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);
	struct mptcp_addr_event mpevent;

	if (ifa->scope > RT_SCOPE_LINK ||
	    addr_type == IPV6_ADDR_ANY ||
	    (addr_type & IPV6_ADDR_LOOPBACK) ||
	    (addr_type & IPV6_ADDR_LINKLOCAL))
		return;

	spin_lock_bh(&fm_ns->local_lock);

	mpevent.family = AF_INET6;
	mpevent.u.addr6 = ifa->addr;
	mpevent.low_prio = (netdev->flags & IFF_MPBACKUP) ? 1 : 0;

	if (event == NETDEV_DOWN ||!netif_running(netdev) ||
	    (netdev->flags & IFF_NOMULTIPATH))
		mpevent.code = MPTCP_EVENT_DEL;
	else if (event == NETDEV_UP)
		mpevent.code = MPTCP_EVENT_ADD;
	else if (event == NETDEV_CHANGE)
		mpevent.code = MPTCP_EVENT_MOD;

	add_pm_event(net, &mpevent);

	spin_unlock_bh(&fm_ns->local_lock);
	return;
}

/* React on IPv6-addr add/rem-events */
static int inet6_addr_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net *net = dev_net(ifa6->idev->dev);

	if (ipv6_is_in_dad_state(ifa6))
		dad_setup_timer(ifa6);
	else
		addr6_event_handler(ifa6, event, net);

	return NOTIFY_DONE;
}

static struct notifier_block inet6_addr_notifier = {
		.notifier_call = inet6_addr_event,
};

#endif

/* React on ifup/down-events */
static int netdev_event(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
#endif

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	rcu_read_lock();
	in_dev = __in_dev_get_rtnl(dev);

	if (in_dev) {
		for_ifa(in_dev) {
			mptcp_pm_inetaddr_event(NULL, event, ifa);
		} endfor_ifa(in_dev);
	}

#if IS_ENABLED(CONFIG_IPV6)
	in6_dev = __in6_dev_get(dev);

	if (in6_dev) {
		struct inet6_ifaddr *ifa6;
		list_for_each_entry(ifa6, &in6_dev->addr_list, if_list)
			inet6_addr_event(NULL, event, ifa6);
	}
#endif

	rcu_read_unlock();
	return NOTIFY_DONE;
}

static struct notifier_block mptcp_pm_netdev_notifier = {
		.notifier_call = netdev_event,
};

static void full_mesh_new_session(struct sock *meta_sk, u8 id)
{
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct fullmesh_priv *fmp = (struct fullmesh_priv *)&mpcb->mptcp_pm[0];
	struct net *net = sock_net(meta_sk);
	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);
	struct sock *sk;
	int i;

	/* Initialize workqueue-struct */
	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	INIT_DELAYED_WORK(&fmp->subflow_retry_work, retry_subflow_worker);
	fmp->mpcb = mpcb;

	sk = mptcp_select_ack_sock(meta_sk, 0);

	rcu_read_lock();
	mptcp_local = rcu_dereference(fm_ns->local);

	/* Look for the address among the local addresses */
	mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
		__be32 ifa_address = mptcp_local->locaddr4[i].addr.s_addr;

		/* We do not need to announce the initial subflow's address again */
		if ((meta_sk->sk_family == AF_INET ||
		     mptcp_v6_is_v4_mapped(meta_sk)) &&
		    inet_sk(meta_sk)->inet_saddr == ifa_address)
			continue;

		fmp->add_addr++;

		if (sk)
			tcp_send_ack(sk);
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
		struct in6_addr *ifa6 = &mptcp_local->locaddr6[i].addr;

		/* We do not need to announce the initial subflow's address again */
		if (meta_sk->sk_family == AF_INET6 &&
		    ipv6_addr_equal(&inet6_sk(meta_sk)->saddr, ifa6))
			continue;

		fmp->add_addr++;

		if (sk)
			tcp_send_ack(sk);
	}
#endif

	rcu_read_unlock();

	if (meta_sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(meta_sk))
		fmp->announced_addrs_v4 |= (1 << id);
	else
		fmp->announced_addrs_v6 |= (1 << (id - MPTCP_MAX_ADDR));
}

static void full_mesh_create_subflows(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct fullmesh_priv *pm_priv = (struct fullmesh_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	/* The master may not yet be fully established (address added through
	 * mptcp_update_metasocket). Then, we should not attempt to create new
	 * subflows.
	 */
	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

/* Called upon release_sock, if the socket was owned by the user during
 * a path-management event.
 */
static void full_mesh_release_sock(struct sock *meta_sk)
{
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct fullmesh_priv *fmp = (struct fullmesh_priv *)&mpcb->mptcp_pm[0];
	struct mptcp_fm_ns *fm_ns = fm_get_ns(sock_net(meta_sk));
	struct sock *sk, *tmpsk;
	int i;

	rcu_read_lock();
	mptcp_local = rcu_dereference(fm_ns->local);

	/* First, detect modifications or additions */
	mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
		struct in_addr ifa = mptcp_local->locaddr4[i].addr;
		bool found = false;

		mptcp_for_each_sk(mpcb, sk) {
			struct tcp_sock *tp = tcp_sk(sk);

			if (sk->sk_family == AF_INET6 &&
			    !mptcp_v6_is_v4_mapped(sk))
				continue;

			if (inet_sk(sk)->inet_saddr != ifa.s_addr)
				continue;

			found = true;

			if (mptcp_local->locaddr4[i].low_prio != tp->mptcp->low_prio) {
				tp->mptcp->send_mp_prio = 1;
				tp->mptcp->low_prio = mptcp_local->locaddr4[i].low_prio;

				tcp_send_ack(sk);
			}
		}

		if (!found) {
			fmp->add_addr++;

			sk = mptcp_select_ack_sock(meta_sk, 0);
			if (sk)
				tcp_send_ack(sk);
			full_mesh_create_subflows(meta_sk);
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
		struct in6_addr ifa = mptcp_local->locaddr6[i].addr;
		bool found = false;

		mptcp_for_each_sk(mpcb, sk) {
			struct tcp_sock *tp = tcp_sk(sk);

			if (sk->sk_family == AF_INET ||
			    mptcp_v6_is_v4_mapped(sk))
				continue;

			if (!ipv6_addr_equal(&inet6_sk(sk)->saddr, &ifa))
				continue;

			found = true;

			if (mptcp_local->locaddr6[i].low_prio != tp->mptcp->low_prio) {
				tp->mptcp->send_mp_prio = 1;
				tp->mptcp->low_prio = mptcp_local->locaddr6[i].low_prio;

				tcp_send_ack(sk);
			}
		}

		if (!found) {
			fmp->add_addr++;

			sk = mptcp_select_ack_sock(meta_sk, 0);
			if (sk)
				tcp_send_ack(sk);
			full_mesh_create_subflows(meta_sk);
		}
	}
#endif

	/* Now, detect address-removals */
	mptcp_for_each_sk_safe(mpcb, sk, tmpsk) {
		bool shall_remove = true;

		if (sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(sk)) {
			mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
				if (inet_sk(sk)->inet_saddr == mptcp_local->locaddr4[i].addr.s_addr) {
					shall_remove = false;
					break;
				}
			}
		} else {
			mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
				if (ipv6_addr_equal(&inet6_sk(sk)->saddr, &mptcp_local->locaddr6[i].addr)) {
					shall_remove = false;
					break;
				}
			}
		}

		if (shall_remove) {
			/* Reinject, so that pf = 1 and so we
			 * won't select this one as the
			 * ack-sock.
			 */
			mptcp_reinject_data(sk, 0);

			update_remove_addrs(tcp_sk(sk)->mptcp->loc_id, meta_sk,
					    mptcp_local);

			if (mpcb->master_sk == sk)
				update_remove_addrs(0, meta_sk, mptcp_local);

			mptcp_sub_force_close(sk);
		}
	}
	rcu_read_unlock();
}

static int full_mesh_get_local_id(sa_family_t family, union inet_addr *addr,
				  struct net *net)
{
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);
	int id = 0, i;

	/* Handle the backup-flows */
	rcu_read_lock();
	mptcp_local = rcu_dereference(fm_ns->local);

	if (family == AF_INET) {
		mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
			if (addr->in.s_addr == mptcp_local->locaddr4[i].addr.s_addr) {
				id = mptcp_local->locaddr4[i].id;
				break;
			}
		}
	} else {
		mptcp_for_each_bit_set(mptcp_local->loc6_bits, i) {
			if (ipv6_addr_equal(&addr->in6, &mptcp_local->locaddr6[i].addr)) {
				id = mptcp_local->locaddr6[i].id;
				break;
			}
		}
	}
	rcu_read_unlock();

	return id;
}

static void full_mesh_addr_signal(struct sock *sk, unsigned *size,
				  struct tcp_out_options *opts,
				  struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct fullmesh_priv *fmp = (struct fullmesh_priv *)&mpcb->mptcp_pm[0];
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_fm_ns *fm_ns = fm_get_ns(sock_net(sk));
	int remove_addr_len;
	u8 unannouncedv4, unannouncedv6;

	if (likely(!fmp->add_addr))
		goto remove_addr;

	rcu_read_lock();
	mptcp_local = rcu_dereference(fm_ns->local);

	/* IPv4 */
	unannouncedv4 = (~fmp->announced_addrs_v4) & mptcp_local->loc4_bits;
	if (unannouncedv4 &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR4_ALIGN) {
		int ind = mptcp_find_free_index(~unannouncedv4);

		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->add_addr4.addr_id = mptcp_local->locaddr4[ind].id;
		opts->add_addr4.addr = mptcp_local->locaddr4[ind].addr;
		opts->add_addr_v4 = 1;

		if (skb) {
			fmp->announced_addrs_v4 |= (1 << ind);
			fmp->add_addr--;
		}
		*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN;
	}

	/* IPv6 */
	unannouncedv6 = (~fmp->announced_addrs_v6) & mptcp_local->loc6_bits;
	if (unannouncedv6 &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) {
		int ind = mptcp_find_free_index(~unannouncedv6);

		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->add_addr6.addr_id = mptcp_local->locaddr6[ind].id;
		opts->add_addr6.addr = mptcp_local->locaddr6[ind].addr;
		opts->add_addr_v6 = 1;

		if (skb) {
			fmp->announced_addrs_v6 |= (1 << ind);
			fmp->add_addr--;
		}
		*size += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN;
	}

	rcu_read_unlock();

	if (!unannouncedv4 && !unannouncedv6 && skb) {
		fmp->add_addr--;
	}

remove_addr:
	if (likely(!fmp->remove_addrs))
		return;

	remove_addr_len = mptcp_sub_len_remove_addr_align(fmp->remove_addrs);
	if (MAX_TCP_OPTION_SPACE - *size < remove_addr_len)
		return;

	opts->options |= OPTION_MPTCP;
	opts->mptcp_options |= OPTION_REMOVE_ADDR;
	opts->remove_addrs = fmp->remove_addrs;
	*size += remove_addr_len;
	if (skb)
		fmp->remove_addrs = 0;
}

static int mptcp_fm_init_net(struct net *net)
{
	struct mptcp_loc_addr *mptcp_local;
	struct mptcp_fm_ns *fm_ns;

	fm_ns = kzalloc(sizeof(*fm_ns), GFP_KERNEL);
	if (!fm_ns)
		return -ENOBUFS;

	mptcp_local = kzalloc(sizeof(*mptcp_local), GFP_KERNEL);
	if (!mptcp_local) {
		kfree(fm_ns);
		return -ENOBUFS;
	}

	mptcp_local->next_v4_index = 1;

	rcu_assign_pointer(fm_ns->local, mptcp_local);
	INIT_DELAYED_WORK(&fm_ns->address_worker, mptcp_address_worker);
	INIT_LIST_HEAD(&fm_ns->events);
	spin_lock_init(&fm_ns->local_lock);
	fm_ns->net = net;
	net->mptcp.path_managers[MPTCP_PM_FULLMESH] = fm_ns;

	return 0;
}

static void mptcp_fm_exit_net(struct net *net)
{
	struct mptcp_addr_event *eventq, *tmp;
	struct mptcp_fm_ns *fm_ns;
	struct mptcp_loc_addr *mptcp_local;

	fm_ns = fm_get_ns(net);
	cancel_delayed_work_sync(&fm_ns->address_worker);

	rcu_read_lock_bh();

	mptcp_local = rcu_dereference_bh(fm_ns->local);
	kfree(mptcp_local);

	spin_lock(&fm_ns->local_lock);
	list_for_each_entry_safe(eventq, tmp, &fm_ns->events, list) {
		list_del(&eventq->list);
		kfree(eventq);
	}
	spin_unlock(&fm_ns->local_lock);

	rcu_read_unlock_bh();

	kfree(fm_ns);
}

static struct pernet_operations full_mesh_net_ops = {
	.init = mptcp_fm_init_net,
	.exit = mptcp_fm_exit_net,
};

static struct mptcp_pm_ops full_mesh __read_mostly = {
	.new_session = full_mesh_new_session,
	.release_sock = full_mesh_release_sock,
	.fully_established = full_mesh_create_subflows,
	.new_remote_address = full_mesh_create_subflows,
	.get_local_id = full_mesh_get_local_id,
	.addr_signal = full_mesh_addr_signal,
	.name = "fullmesh",
	.owner = THIS_MODULE,
};

/* General initialization of MPTCP_PM */
static int __init full_mesh_register(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct fullmesh_priv) > MPTCP_PM_SIZE);

	ret = register_pernet_subsys(&full_mesh_net_ops);
	if (ret)
		goto out;

	ret = register_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	if (ret)
		goto err_reg_inetaddr;
	ret = register_netdevice_notifier(&mptcp_pm_netdev_notifier);
	if (ret)
		goto err_reg_netdev;

#if IS_ENABLED(CONFIG_IPV6)
	ret = register_inet6addr_notifier(&inet6_addr_notifier);
	if (ret)
		goto err_reg_inet6addr;
#endif

	ret = mptcp_register_path_manager(&full_mesh);
	if (ret)
		goto err_reg_pm;

out:
	return ret;


err_reg_pm:
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&inet6_addr_notifier);
err_reg_inet6addr:
#endif
	unregister_netdevice_notifier(&mptcp_pm_netdev_notifier);
err_reg_netdev:
	unregister_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
err_reg_inetaddr:
	unregister_pernet_subsys(&full_mesh_net_ops);
	goto out;
}

static void full_mesh_unregister(void)
{
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&inet6_addr_notifier);
#endif
	unregister_netdevice_notifier(&mptcp_pm_netdev_notifier);
	unregister_inetaddr_notifier(&mptcp_pm_inetaddr_notifier);
	unregister_pernet_subsys(&full_mesh_net_ops);
	mptcp_unregister_path_manager(&full_mesh);
}

module_init(full_mesh_register);
module_exit(full_mesh_unregister);

MODULE_AUTHOR("Christoph Paasch");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Full-Mesh MPTCP");
MODULE_VERSION("0.88");
