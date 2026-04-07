#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "uid_caps.h"

uid_caps_table_t g_uid_caps_table;

int uid_caps_init(void)
{
	spin_lock_init(&g_uid_caps_table.lock);
	hash_init(g_uid_caps_table.table);

	pr_info("[uid_caps] Hashtable initialized\n");
	return 0;
}

void uid_caps_exit(void)
{
	uid_caps_clear_all();
	pr_info("[uid_caps] Hashtable destroyed\n");
}

int uid_caps_add(uid_t uid, uint64_t caps)
{
	uid_cap_entry_t *entry, *existing;
	unsigned long flags;

	if (uid == 0) {
		pr_err("[uid_caps] Cannot add UID 0 (root)\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	hash_for_each_possible(g_uid_caps_table.table, existing, node, uid) {
		if (existing->uid == uid) {
			pr_warn
			    ("[uid_caps] UID %u already exists, use update instead\n",
			     uid);
			spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
			return -EEXIST;
		}
	}

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		pr_err("[uid_caps] Failed to allocate memory for UID %u\n",
		       uid);
		return -ENOMEM;
	}

	entry->uid = uid;
	entry->caps = caps;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);
	hash_add(g_uid_caps_table.table, &entry->node, uid);
	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

	pr_debug("[uid_caps] Added UID %u with caps 0x%llx\n", uid, caps);
	return 0;
}

int uid_caps_remove(uid_t uid)
{
	uid_cap_entry_t *entry;
	unsigned long flags;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	hash_for_each_possible(g_uid_caps_table.table, entry, node, uid) {
		if (entry->uid == uid) {
			hash_del(&entry->node);
			spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

			kfree(entry);
			pr_debug("[uid_caps] Removed UID %u\n", uid);
			return 0;
		}
	}

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
	pr_warn("[uid_caps] UID %u not found\n", uid);
	return -ENOENT;
}

int uid_caps_update(uid_t uid, uint64_t caps)
{
	uid_cap_entry_t *entry;
	unsigned long flags;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	hash_for_each_possible(g_uid_caps_table.table, entry, node, uid) {
		if (entry->uid == uid) {
			entry->caps = caps;
			spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

			pr_debug("[uid_caps] Updated UID %u caps to 0x%llx\n",
				 uid, caps);
			return 0;
		}
	}

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
	pr_warn("[uid_caps] UID %u not found for update\n", uid);
	return -ENOENT;
}

uint64_t uid_caps_get(uid_t uid)
{
	uid_cap_entry_t *entry;
	uint64_t caps = 0;
	unsigned long flags;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	hash_for_each_possible(g_uid_caps_table.table, entry, node, uid) {
		if (entry->uid == uid) {
			caps = entry->caps;
			break;
		}
	}

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
	return caps;
}

int uid_caps_has_uid(uid_t uid)
{
	uid_cap_entry_t *entry;
	unsigned long flags;
	int found = 0;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	hash_for_each_possible(g_uid_caps_table.table, entry, node, uid) {
		if (entry->uid == uid) {
			found = 1;
			break;
		}
	}

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
	return found;
}

int uid_caps_clear_all(void)
{
	uid_cap_entry_t *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	hash_for_each_safe(g_uid_caps_table.table, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
	pr_info("[uid_caps] Cleared all entries\n");
	return 0;
}

void uid_caps_debug_dump(void)
{
	uid_cap_entry_t *entry;
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&g_uid_caps_table.lock, flags);

	pr_info("[uid_caps] ========== UID Capabilities Table ==========\n");
	hash_for_each(g_uid_caps_table.table, bkt, entry, node) {
		pr_info("[uid_caps] UID: %u, Caps: 0x%016llx\n", entry->uid,
			entry->caps);
	}
	pr_info("[uid_caps] ===========================================\n");

	spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
}
