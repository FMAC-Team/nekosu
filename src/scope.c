// SPDX-License-Identifier: GPL-3.0
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <fmac.h>

#define SCOPE_HASH_BITS 6

struct scope_entry {
	uid_t uid;
	u32 flags;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(scope_table, SCOPE_HASH_BITS);
static DEFINE_SPINLOCK(scope_lock);

u32 scope_lookup(uid_t uid)
{
	struct scope_entry *e;
	u32 flags = 0;
	unsigned long irqf;

	spin_lock_irqsave(&scope_lock, irqf);
	hash_for_each_possible(scope_table, e, node, uid) {
		if (e->uid == uid) {
			flags = e->flags;
			break;
		}
	}
	spin_unlock_irqrestore(&scope_lock, irqf);
	return flags;
}

int fmac_scope_set(uid_t uid, u32 flags)
{
	struct scope_entry *e, *found = NULL;
	unsigned long irqf;

	if (!flags) {
		fmac_scope_clear(uid);
		return 0;
	}

	spin_lock_irqsave(&scope_lock, irqf);
	hash_for_each_possible(scope_table, e, node, uid) {
		if (e->uid == uid) {
			found = e;
			break;
		}
	}
	if (found) {
		found->flags = flags;
		spin_unlock_irqrestore(&scope_lock, irqf);
		return 0;
	}
	spin_unlock_irqrestore(&scope_lock, irqf);

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;
	e->uid = uid;
	e->flags = flags;

	spin_lock_irqsave(&scope_lock, irqf);
	hash_for_each_possible(scope_table, found, node, uid) {
		if (found->uid == uid) {
			found->flags = flags;
			spin_unlock_irqrestore(&scope_lock, irqf);
			kfree(e);
			return 0;
		}
	}
	hash_add(scope_table, &e->node, uid);
	spin_unlock_irqrestore(&scope_lock, irqf);
	return 0;
}

void fmac_scope_clear(uid_t uid)
{
	struct scope_entry *e;
	struct hlist_node *tmp;
	unsigned long irqf;

	spin_lock_irqsave(&scope_lock, irqf);
	hash_for_each_possible_safe(scope_table, e, tmp, node, uid) {
		if (e->uid == uid) {
			hash_del(&e->node);
			kfree(e);
			break;
		}
	}
	spin_unlock_irqrestore(&scope_lock, irqf);
}

void fmac_scope_clear_all(void)
{
	struct scope_entry *e;
	struct hlist_node *tmp;
	unsigned long irqf;
	unsigned int bkt;

	spin_lock_irqsave(&scope_lock, irqf);
	hash_for_each_safe(scope_table, bkt, tmp, e, node) {
		hash_del(&e->node);
		kfree(e);
	}
	spin_unlock_irqrestore(&scope_lock, irqf);
}