// SPDX-License-Identifier: GPL-3.0
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>

#define SCOPE_HASH_BITS 10
#define SCOPE_BUCKETS   (1 << SCOPE_HASH_BITS)

struct scope_node {
	uid_t uid;
	u32 flags;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(g_scope_table, SCOPE_HASH_BITS);

static spinlock_t g_bucket_locks[SCOPE_BUCKETS];

static atomic64_t scope_version ____cacheline_aligned_in_smp = ATOMIC64_INIT(1);

struct scope_cache_cpu {
	u64 version;
	uid_t uid;
	u32 flags;
};

static DEFINE_PER_CPU(struct scope_cache_cpu, scope_cpu_l0);

static void scope_node_free_rcu(struct rcu_head *rcu)
{
	struct scope_node *node = container_of(rcu, struct scope_node, rcu);
	kfree(node);
}

u32 scope_lookup(uid_t uid)
{
	struct scope_cache_cpu *pc;
	struct scope_node *node;
	u64 current_version;
	u32 flags = 0;

	preempt_disable();
	
	pc = this_cpu_ptr(&scope_cpu_l0);
	current_version = atomic64_read(&scope_version);

	if (likely(pc->version == current_version && pc->uid == uid)) {
		flags = pc->flags;
		preempt_enable();
		return flags;
	}
	preempt_enable();

	rcu_read_lock();
	hash_for_each_possible_rcu(g_scope_table, node, hnode, uid) {
		if (node->uid == uid) {
			flags = READ_ONCE(node->flags);
			break;
		}
	}
	rcu_read_unlock();

	preempt_disable();
	pc = this_cpu_ptr(&scope_cpu_l0);
	pc->uid = uid;
	pc->flags = flags;
	pc->version = current_version;
	preempt_enable();

	return flags;
}

static int scope_update(uid_t uid, u32 flags)
{
	struct scope_node *node, *new_node = NULL;
	u32 bkt = hash_32(uid, SCOPE_HASH_BITS);
	int found = 0;

	if (flags != 0) {
		new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
		if (!new_node)
			return -ENOMEM;
		new_node->uid = uid;
		new_node->flags = flags;
	}

	spin_lock(&g_bucket_locks[bkt]);

	hash_for_each_possible_rcu(g_scope_table, node, hnode, uid) {
		if (node->uid == uid) {
			if (new_node) {
				hlist_replace_rcu(&node->hnode, &new_node->hnode);
			} else {
				hash_del_rcu(&node->hnode);
			}
			call_rcu(&node->rcu, scope_node_free_rcu);
			found = 1;
			break;
		}
	}

	if (!found && new_node) {
		hash_add_rcu(g_scope_table, &new_node->hnode, uid);
	} else if (!found && !new_node) {
		/* nothing todo */
	}

	atomic64_inc(&scope_version);
	
	spin_unlock(&g_bucket_locks[bkt]);

	if (!found && !new_node && new_node) {
	    kfree(new_node); 
	}

	return 0;
}

int fmac_scope_set(uid_t uid, u32 flags)
{
	if (unlikely(flags == 0))
		return -EINVAL; 
	return scope_update(uid, flags);
}

void fmac_scope_clear(uid_t uid)
{
	scope_update(uid, 0);
}

void fmac_scope_clear_all(void)
{
	struct scope_node *node;
	struct hlist_node *tmp;
	int bkt;

	for (bkt = 0; bkt < SCOPE_BUCKETS; bkt++) {
		spin_lock(&g_bucket_locks[bkt]);
		hlist_for_each_entry_safe(node, tmp, &g_scope_table[bkt], hnode) {
			hash_del_rcu(&node->hnode);
			call_rcu(&node->rcu, scope_node_free_rcu);
		}
		
		spin_unlock(&g_bucket_locks[bkt]);
	}
	atomic64_inc(&scope_version);
}


 int __init scope_init(void)
{
	int i;
	for (i = 0; i < SCOPE_BUCKETS; i++) {
		spin_lock_init(&g_bucket_locks[i]);
	}
	return 0;
}
