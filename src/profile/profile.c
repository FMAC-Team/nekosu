// SPDX-License-Identifier: GPL-3.0
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/bitmap.h>
#include <linux/string.h>

#include "klog.h"
#include "profile.h"

#define NKSU_PROFILE_HASHBITS 10
#define PROFILE_BUCKETS   (1 << NKSU_PROFILE_HASHBITS)

#define NKSU_BITMAP_MAX_UID 32768

#define NKSU_SET_CAPS   BIT(0)
#define NKSU_SET_DOMAIN BIT(1)

struct nksu_profile {
	uid_t uid;
	kernel_cap_t caps;
	char selinux_domain[64];
	struct hlist_node hnode;
	struct rcu_head rcu;
};

struct profile_cache_cpu {
	uid_t uid;
	struct nksu_profile *profile;
	u64 version;
};

static DECLARE_BITMAP(nksu_profile_bitmap, NKSU_BITMAP_MAX_UID);
static struct hlist_head g_profile_table[PROFILE_BUCKETS];
static spinlock_t g_bucket_locks[PROFILE_BUCKETS];
static u64 g_profile_version = 0;

static DEFINE_PER_CPU(struct profile_cache_cpu, profile_cpu_l0);

static inline void profile_commit_version(void)
{
	smp_store_release(&g_profile_version, g_profile_version + 1);
}

static struct nksu_profile *nksu_profile_lookup(uid_t uid)
{
	struct profile_cache_cpu *pc;
	struct nksu_profile *node = NULL;
	u64 ver;
	u32 bkt;

	if (uid < NKSU_BITMAP_MAX_UID && !test_bit(uid, nksu_profile_bitmap))
		return NULL;

	preempt_disable();
	pc = this_cpu_ptr(&profile_cpu_l0);
	ver = smp_load_acquire(&g_profile_version);

	if (likely(pc->version == ver && pc->uid == uid)) {
		struct nksu_profile *cached = pc->profile;
		preempt_enable();
		return cached;
	}
	preempt_enable();

	rcu_read_lock();
	bkt = hash_32(uid, NKSU_PROFILE_HASHBITS);
	hlist_for_each_entry_rcu(node, &g_profile_table[bkt], hnode) {
		if (node->uid == uid) {
			goto found;
		}
	}
	node = NULL;

found:
	preempt_disable();
	pc = this_cpu_ptr(&profile_cpu_l0);
	pc->uid     = uid;
	pc->profile = node;
	pc->version = ver;
	preempt_enable();
	
	rcu_read_unlock();
	return node;
}

int nksu_profile_get_dup(uid_t uid, struct profile *out_buf)
{
    struct nksu_profile *ptr;
    int ret = -ENOENT;

    rcu_read_lock();
    ptr = nksu_profile_lookup(uid);
    if (ptr) {
        out_buf->caps = ptr->caps;
		strscpy(out_buf->selinux_domain, ptr->selinux_domain, sizeof(out_buf->selinux_domain));
        ret = 0;
    }
    rcu_read_unlock();
    return ret;
}

bool nksu_profile_has_uid(uid_t uid)
{
		return test_bit(uid, nksu_profile_bitmap);
}

int nksu_profile_set_ext(uid_t uid, kernel_cap_t caps, const char *domain, u32 flags)
{
	struct nksu_profile *new_node = NULL;
	struct nksu_profile *old_node = NULL, *pos;
	u32 bkt = hash_32(uid, NKSU_PROFILE_HASHBITS);
	int ret = 0;

	if (unlikely(flags == 0))
		return 0;

	spin_lock(&g_bucket_locks[bkt]);

	hlist_for_each_entry(pos, &g_profile_table[bkt], hnode) {
		if (pos->uid == uid) {
			old_node = pos;
			break;
		}
	}

	if (old_node) {
		new_node = kmemdup(old_node, sizeof(*new_node), GFP_ATOMIC);
	} else {
		new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
	}

	if (!new_node) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	new_node->uid = uid;
	INIT_HLIST_NODE(&new_node->hnode);

	if (flags & NKSU_SET_CAPS) {
		new_node->caps = caps;
	}
	if (flags & NKSU_SET_DOMAIN) {
		if (domain)
			strscpy(new_node->selinux_domain, domain, sizeof(new_node->selinux_domain));
		else
			new_node->selinux_domain[0] = '\0';
	}

	if (old_node) {
		hlist_replace_rcu(&old_node->hnode, &new_node->hnode);
		kfree_rcu(old_node, rcu);
	} else {
		if (uid < NKSU_BITMAP_MAX_UID)
			set_bit(uid, nksu_profile_bitmap);
		hlist_add_head_rcu(&new_node->hnode, &g_profile_table[bkt]);
	}

	profile_commit_version();

out_unlock:
	spin_unlock(&g_bucket_locks[bkt]);
	return ret;
}

int nksu_profile_set(uid_t uid, kernel_cap_t caps, const char *domain)
{
	return nksu_profile_set_ext(uid, caps, domain, NKSU_SET_CAPS | NKSU_SET_DOMAIN);
}

int nksu_profile_set_caps(uid_t uid, kernel_cap_t caps)
{
	return nksu_profile_set_ext(uid, caps, NULL, NKSU_SET_CAPS);
}

int nksu_profile_set_domain(uid_t uid, const char *domain)
{
	kernel_cap_t dummy = {0}; 
	return nksu_profile_set_ext(uid, dummy, domain, NKSU_SET_DOMAIN);
}

void nksu_profile_clear(uid_t uid)
{
	struct nksu_profile *node = NULL, *pos;
	u32 bkt = hash_32(uid, NKSU_PROFILE_HASHBITS);

	spin_lock(&g_bucket_locks[bkt]);

	hlist_for_each_entry(pos, &g_profile_table[bkt], hnode) {
		if (pos->uid == uid) {
			node = pos;
			break;
		}
	}

	if (node) {
		hash_del_rcu(&node->hnode);
		if (uid < NKSU_BITMAP_MAX_UID)
			clear_bit(uid, nksu_profile_bitmap);
		kfree_rcu(node, rcu);
		profile_commit_version();
	}

	spin_unlock(&g_bucket_locks[bkt]);
}

void nksu_profile_clear_all(void)
{
	struct nksu_profile *node;
	struct hlist_node *tmp;
	int bkt;

	profile_commit_version();
	bitmap_zero(nksu_profile_bitmap, NKSU_BITMAP_MAX_UID);

	for (bkt = 0; bkt < PROFILE_BUCKETS; bkt++) {
		spin_lock(&g_bucket_locks[bkt]);
		hlist_for_each_entry_safe(node, tmp, &g_profile_table[bkt], hnode) {
			hlist_del_rcu(&node->hnode);
			kfree_rcu(node, rcu); 
		}
		spin_unlock(&g_bucket_locks[bkt]);
	}
}

int __init nksu_profile_init(void)
{
	int i;
	bitmap_zero(nksu_profile_bitmap, NKSU_BITMAP_MAX_UID);
	for (i = 0; i < PROFILE_BUCKETS; i++) {
		INIT_HLIST_HEAD(&g_profile_table[i]);
		spin_lock_init(&g_bucket_locks[i]);
	}
	return 0;
}
