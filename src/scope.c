// SPDX-License-Identifier: GPL-3.0
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/compiler.h>

#include <fmac.h>

#define MAX_SCOPE 32

struct scope_entry {
	uid_t uid;
	u32 flags;
};

struct scope_table {
	u32 count;
	struct scope_entry entries[MAX_SCOPE];
	struct rcu_head rcu;
};

struct scope_cache_entry {
	uid_t uid;
	u32 flags;
	struct rcu_head rcu;
};

struct scope_cache_cpu {
	uid_t uid;
	u32 flags;
	bool valid;
};

static struct scope_table __rcu *g_scope;
static struct scope_cache_entry __rcu *g_scope_l0;
static DEFINE_PER_CPU(struct scope_cache_cpu, scope_cpu_l0);

static void scope_table_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct scope_table, rcu));
}

static void scope_cache_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct scope_cache_entry, rcu));
}

u32 scope_lookup(uid_t uid)
{
	struct scope_cache_cpu *pc;
	struct scope_cache_entry *c;
	struct scope_table *t;
	u32 flags = 0;

	pc = this_cpu_ptr(&scope_cpu_l0);
	if (likely(pc->valid && pc->uid == uid))
		return pc->flags;

	rcu_read_lock();

	c = rcu_dereference(g_scope_l0);
	if (likely(c && c->uid == uid)) {
		flags = READ_ONCE(c->flags);
		goto fill_cpu;
	}

	t = rcu_dereference(g_scope);
	if (likely(t)) {
		for (u32 i = 0; i < t->count; i++) {
			if (likely(t->entries[i].uid == uid)) {
				flags = READ_ONCE(t->entries[i].flags);
				goto fill_cpu;
			}
		}
	}

	rcu_read_unlock();
	return 0;

fill_cpu:
	rcu_read_unlock();

	pc->uid = uid;
	pc->flags = flags;
	pc->valid = true;

	return flags;
}

static void scope_update_l0(uid_t uid, u32 flags)
{
	struct scope_cache_entry *old, *new;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return;

	new->uid = uid;
	new->flags = flags;

	old = rcu_dereference_protected(g_scope_l0, 1);
	rcu_assign_pointer(g_scope_l0, new);

	if (old)
		call_rcu(&old->rcu, scope_cache_free_rcu);
}

int fmac_scope_set(uid_t uid, u32 flags)
{
	struct scope_table *old, *new;
	int i, found = -1;
	u32 new_count;

	rcu_read_lock();
	old = rcu_dereference(g_scope);
	rcu_read_unlock();

	if (old) {
		for (i = 0; i < old->count; i++) {
			if (old->entries[i].uid == uid) {
				found = i;
				break;
			}
		}
	}

	if (!flags) {
		new_count = old ? (found >= 0 ? old->count - 1 : old->count) : 0;
	} else {
		new_count = (old && found >= 0) ?
			old->count : (old ? old->count : 0) + 1;
	}

	if (new_count > MAX_SCOPE)
		return -ENOSPC;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	if (old)
		memcpy(new, old, sizeof(*new));
	else
		new->count = 0;

	if (!flags) {
		if (old && found >= 0) {
			new->entries[found] =
				new->entries[new->count - 1];
			new->count--;
		}
	} else {
		if (old && found >= 0) {
			new->entries[found].flags = flags;
		} else {
			new->entries[new->count].uid = uid;
			new->entries[new->count].flags = flags;
			new->count++;
		}
	}

	rcu_assign_pointer(g_scope, new);

	if (old)
		call_rcu(&old->rcu, scope_table_free_rcu);

	scope_update_l0(uid, flags);

	for_each_possible_cpu(i) {
		struct scope_cache_cpu *pc =
			per_cpu_ptr(&scope_cpu_l0, i);
		pc->valid = false;
	}

	return 0;
}

void fmac_scope_clear(uid_t uid)
{
	fmac_scope_set(uid, 0);
}

void fmac_scope_clear_all(void)
{
	struct scope_table *old_t;
	struct scope_cache_entry *old_c;
	int cpu;

	rcu_read_lock();
	old_t = rcu_dereference(g_scope);
	old_c = rcu_dereference(g_scope_l0);
	rcu_read_unlock();

	RCU_INIT_POINTER(g_scope, NULL);
	RCU_INIT_POINTER(g_scope_l0, NULL);

	if (old_t)
		call_rcu(&old_t->rcu, scope_table_free_rcu);
	if (old_c)
		call_rcu(&old_c->rcu, scope_cache_free_rcu);

	for_each_possible_cpu(cpu) {
		struct scope_cache_cpu *pc =
			per_cpu_ptr(&scope_cpu_l0, cpu);
		pc->valid = false;
	}
}