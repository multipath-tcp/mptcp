/*
 *	MTCP PM implementation
 *
 *	Authors:
 *      Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *
 *
 *      date : March 10
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <net/mtcp.h>
#include <net/mtcp_pm.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>

#define MTCP_HASH_SIZE                16
#define hash_tk(token) \
	jhash_1word(token,0)%MTCP_HASH_SIZE


static struct list_head tk_hashtable[MTCP_HASH_SIZE];
static rwlock_t tk_hash_lock; /*hashtable protection*/

/* General initialization of MTCP_PM
 */
static int __init mtcp_pm_init(void) 
{
	int i;
	for (i=0;i<MTCP_HASH_SIZE;i++)
		INIT_LIST_HEAD(&tk_hashtable[i]);		
	rwlock_init(&tk_hash_lock);
	return 0;
}

void mtcp_hash_insert(struct multipath_pcb *mpcb,u32 token)
{
	int hash=hash_tk(token);
	write_lock_bh(&tk_hash_lock);
	list_add(&mpcb->collide_tk,&tk_hashtable[hash]);
	write_unlock_bh(&tk_hash_lock);
}

struct multipath_pcb* mtcp_hash_find(u32 token)
{
	int hash=hash_tk(token);
	struct multipath_pcb *mpcb;
	read_lock(&tk_hash_lock);
	list_for_each_entry(mpcb,&tk_hashtable[hash],collide_tk) {
		if (token==loc_token(mpcb))
			return mpcb;
	}
	read_unlock(&tk_hash_lock);
	return NULL;
}

void mtcp_hash_remove(struct multipath_pcb *mpcb)
{
	write_lock_bh(&tk_hash_lock);
	list_del(&mpcb->collide_tk);
	write_unlock_bh(&tk_hash_lock);
}


/* Generates a token for a new MPTCP connection
 * Currently we assign sequential tokens to
 * successive MPTCP connections. In the future we
 * will need to define random tokens, while avoiding
 * collisions.
 */
u32 mtcp_new_token(void)
{
	static u32 latest_token=0;
	latest_token++;
	return latest_token;
}



struct path4 *find_path_mapping4(struct in_addr *loc,struct in_addr *rem,
				 struct multipath_pcb *mpcb)
{
	int i;
	for (i=0;i<mpcb->pa4_size;i++)
		if (mpcb->pa4[i].loc.addr.s_addr == loc->s_addr &&
		    mpcb->pa4[i].rem.addr.s_addr == rem->s_addr)
			return &mpcb->pa4[i];
	return NULL;
}

struct in_addr *mtcp_get_loc_addr(struct multipath_pcb *mpcb, int path_index)
{
	int i;
 	if (path_index<=1)
		return (struct in_addr*)&mpcb->local_ulid.a4;
	for (i=0;i<mpcb->pa4_size;i++) {
		if (mpcb->pa4[i].path_index==path_index)
			return &mpcb->pa4[i].loc.addr;
	}
	BUG();
	return NULL;
}

struct in_addr *mtcp_get_rem_addr(struct multipath_pcb *mpcb, int path_index)
{
	int i;
 	if (path_index<=1)
		return (struct in_addr*)&mpcb->remote_ulid.a4;
	for (i=0;i<mpcb->pa4_size;i++) {
		if (mpcb->pa4[i].path_index==path_index)
			return &mpcb->pa4[i].rem.addr;
	}
	BUG();
	return NULL;
}

u8 mtcp_get_loc_addrid(struct multipath_pcb *mpcb, int path_index)
{
	int i;
	/*master subsocket has both addresses with id 0*/
	if (path_index<=1) return 0;
	for (i=0;i<mpcb->pa4_size;i++) {
		if (mpcb->pa4[i].path_index==path_index)
			return mpcb->pa4[i].loc.id;
	}
	BUG();
	return -1;
}


/*For debugging*/
void print_patharray(struct path4 *pa, int size)
{
	int i;
	printk(KERN_ERR "==================\n");
	for (i=0;i<size;i++) {
		printk(KERN_ERR NIPQUAD_FMT "/%d->"
		       NIPQUAD_FMT "/%d, pi %d\n",
		       NIPQUAD(pa[i].loc.addr),pa[i].loc.id,
		       NIPQUAD(pa[i].rem.addr),pa[i].rem.id,
		       pa[i].path_index);
	}
}



/*This is the MPTCP PM mapping table*/
void mtcp_update_patharray(struct multipath_pcb *mpcb)
{
	struct path4 *new_pa4, *old_pa4;
	int i,j,newpa_idx=0;
	/*Count how many paths are available
	  We add 1 to size of local and remote set, to include the 
	  ULID*/
	int ulid_v4=(mpcb->sa_family==AF_INET)?1:0;
	int pa4_size=(mpcb->num_addr4+ulid_v4)*
		(mpcb->received_options.num_addr4+ulid_v4)-ulid_v4;
	
	new_pa4=kmalloc(pa4_size*sizeof(struct path4),GFP_ATOMIC);
	
	if (ulid_v4) {
		/*ULID src with other dest*/
		for (j=0;j<mpcb->received_options.num_addr4;j++) {
			struct path4 *p=find_path_mapping4(
				(struct in_addr*)&mpcb->local_ulid.a4,
				&mpcb->received_options.addr4[j].addr,mpcb);
			if (p)
				memcpy(&new_pa4[newpa_idx++],p,
				       sizeof(struct path4));
			else {
				/*local addr*/
				new_pa4[newpa_idx].loc.addr.s_addr=
					mpcb->local_ulid.a4;
				new_pa4[newpa_idx].loc.id=0; /*ulid has id 0*/
				/*remote addr*/
				memcpy(&new_pa4[newpa_idx].rem,
				       &mpcb->received_options.addr4[j],
				       sizeof(struct mtcp_loc4));
				/*new path index to be given*/
				new_pa4[newpa_idx++].path_index=
					mpcb->next_unused_pi++;
			}			
		}
		/*ULID dest with other src*/
		for (i=0;i<mpcb->num_addr4;i++) {
			struct path4 *p=find_path_mapping4(
				&mpcb->addr4[i].addr,
				(struct in_addr*)&mpcb->remote_ulid.a4,mpcb);
			if (p)
				memcpy(&new_pa4[newpa_idx++],p,
				       sizeof(struct path4));
			else {
				/*local addr*/
				memcpy(&new_pa4[newpa_idx].loc,
				       &mpcb->addr4[i],
				       sizeof(struct mtcp_loc4));
				
				/*remote addr*/
				new_pa4[newpa_idx].rem.addr.s_addr=
					mpcb->remote_ulid.a4;
				new_pa4[newpa_idx].rem.id=0; /*ulid has id 0*/
				/*new path index to be given*/
				new_pa4[newpa_idx++].path_index=
					mpcb->next_unused_pi++;
			}
		}
	}
	/*Try all other combinations now*/
	for (i=0;i<mpcb->num_addr4;i++)
		for (j=0;j<mpcb->received_options.num_addr4;j++) {
			struct path4 *p=find_path_mapping4(
				&mpcb->addr4[i].addr,
				&mpcb->received_options.addr4[j].addr,mpcb);
			if (p)
				memcpy(&new_pa4[newpa_idx++],p,
				       sizeof(struct path4));	
			else {
				/*local addr*/
				memcpy(&new_pa4[newpa_idx].loc,
				       &mpcb->addr4[i],
				       sizeof(struct mtcp_loc4));
				/*remote addr*/
				memcpy(&new_pa4[newpa_idx].rem,
				       &mpcb->received_options.addr4[j],
				       sizeof(struct mtcp_loc4));
				
				/*new path index to be given*/
				new_pa4[newpa_idx++].path_index=
					mpcb->next_unused_pi++;
			}
		}
	
	
	/*Replacing the mapping table*/
	old_pa4=mpcb->pa4;
	mpcb->pa4=new_pa4;
	mpcb->pa4_size=pa4_size;
	if (old_pa4) kfree(old_pa4);
	print_patharray(mpcb->pa4, mpcb->pa4_size);
}


void mtcp_set_addresses(struct multipath_pcb *mpcb)
{
	struct net_device *dev;
	int id=1;

	mpcb->num_addr4=0;

	read_lock(&dev_base_lock); 

	for_each_netdev(&init_net,dev) {
		if(netif_running(dev)) {
			struct in_device *in_dev=dev->ip_ptr;
			struct in_ifaddr *ifa;
			
			if (!strcmp(dev->name,"lo"))
				continue;

			if (mpcb->num_addr4==MTCP_MAX_ADDR) {
				printk(KERN_ERR "Reached max number of local"
				       "IPv4 addresses : %d\n", MTCP_MAX_ADDR);
				break;
			}
			
			for (ifa = in_dev->ifa_list; ifa; 
			     ifa = ifa->ifa_next) {
				if (ifa->ifa_address==
				    inet_sk(mpcb->master_sk)->saddr)
					continue;
				mpcb->addr4[mpcb->num_addr4].addr.s_addr=
					ifa->ifa_address;
				mpcb->addr4[mpcb->num_addr4++].id=id++;
			}
		}
	}
	
	read_unlock(&dev_base_lock); 
}


/**
 *Sends an update notification to the MPS
 *Since this particular PM works in the TCP layer, that is, the same
 *as the MPS, we "send" the notif through function call, not message
 *passing.
 * Warning: this can be called only from user context, not soft irq
 **/
void mtcp_send_updatenotif(struct multipath_pcb *mpcb)
{
	int i;
	u32 path_indices=1; /*Path index 1 is reserved for master sk.*/
	for (i=0;i<mpcb->pa4_size;i++) {
		path_indices|=PI_TO_FLAG(mpcb->pa4[i].path_index);
	}
	mtcp_init_subsockets(mpcb,path_indices);
}

module_init(mtcp_pm_init);

MODULE_LICENSE("GPL");

