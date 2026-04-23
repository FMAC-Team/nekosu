#include "uid_caps.h"
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

uid_caps_table_t g_uid_caps_table;

static uid_cap_entry_t *__find_entry(uid_t uid) {
  uid_cap_entry_t *entry;

  hash_for_each_possible(g_uid_caps_table.table, entry, node, uid) {
    if (entry->uid == uid)
      return entry;
  }
  return NULL;
}

int uid_caps_init(void) {
  spin_lock_init(&g_uid_caps_table.lock);
  hash_init(g_uid_caps_table.table);
  pr_info("[uid_caps] hashtable initialized (bits=%d, buckets=%u)\n",
          UID_CAPS_HASH_BITS, 1u << UID_CAPS_HASH_BITS);
  return 0;
}

void uid_caps_exit(void) {
  uid_caps_clear_all();
  pr_info("[uid_caps] hashtable destroyed\n");
}

int uid_caps_add(uid_t uid, uint64_t caps) {
  uid_cap_entry_t *entry, *existing;
  unsigned long flags;

  if (uid == 0) {
    pr_err("[uid_caps] refusing to add UID 0 (root)\n");
    return -EINVAL;
  }

  entry = kmalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry)
    return -ENOMEM;

  entry->uid = uid;
  entry->caps = caps;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);

  existing = __find_entry(uid);
  if (existing) {
    spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
    kfree(entry);
    pr_warn("[uid_caps] UID %u already exists, use update\n", uid);
    return -EEXIST;
  }

  hash_add(g_uid_caps_table.table, &entry->node, uid);
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  pr_debug("[uid_caps] added UID %u caps=0x%016llx\n", uid, caps);
  return 0;
}

int uid_caps_remove(uid_t uid) {
  uid_cap_entry_t *entry;
  unsigned long flags;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  entry = __find_entry(uid);
  if (!entry) {
    spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
    pr_warn("[uid_caps] UID %u not found (remove)\n", uid);
    return -ENOENT;
  }
  hash_del(&entry->node);
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  kfree(entry);
  pr_debug("[uid_caps] removed UID %u\n", uid);
  return 0;
}

int uid_caps_update(uid_t uid, uint64_t caps) {
  uid_cap_entry_t *entry;
  unsigned long flags;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  entry = __find_entry(uid);
  if (!entry) {
    spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
    pr_warn("[uid_caps] UID %u not found (update)\n", uid);
    return -ENOENT;
  }
  entry->caps = caps;
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  pr_debug("[uid_caps] updated UID %u caps=0x%016llx\n", uid, caps);
  return 0;
}

int uid_caps_set(uid_t uid, uint64_t caps) {
  uid_cap_entry_t *entry, *newentry;
  unsigned long flags;

  if (uid == 0) {
    pr_err("[uid_caps] refusing to set UID 0 (root)\n");
    return -EINVAL;
  }

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  entry = __find_entry(uid);
  if (entry) {
    entry->caps = caps;
    spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
    pr_debug("[uid_caps] set (update) UID %u caps=0x%016llx\n", uid, caps);
    return 0;
  }
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  newentry = kmalloc(sizeof(*newentry), GFP_KERNEL);
  if (!newentry)
    return -ENOMEM;

  newentry->uid = uid;
  newentry->caps = caps;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  entry = __find_entry(uid);
  if (entry) {
    entry->caps = caps;
    spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
    kfree(newentry);
  } else {
    hash_add(g_uid_caps_table.table, &newentry->node, uid);
    spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);
  }

  pr_debug("[uid_caps] set (insert) UID %u caps=0x%016llx\n", uid, caps);
  return 0;
}

int uid_caps_get_safe(uid_t uid, uint64_t *out_caps) {
  uid_cap_entry_t *entry;
  unsigned long flags;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  entry = __find_entry(uid);
  if (entry)
    *out_caps = entry->caps;
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  return entry ? 0 : -ENOENT;
}

uint64_t uid_caps_get(uid_t uid) {
  uint64_t caps = 0;
  uid_caps_get_safe(uid, &caps);
  return caps;
}

int uid_caps_has_uid(uid_t uid) {
  uid_cap_entry_t *entry;
  unsigned long flags;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  entry = __find_entry(uid);
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  return entry ? 1 : 0;
}

int uid_caps_clear_all(void) {
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

  pr_info("[uid_caps] cleared all entries\n");
  return 0;
}

int uid_caps_for_each(uid_caps_iter_fn fn, void *data) {
  uid_cap_entry_t *entry;
  unsigned long flags;
  int bkt, ret = 0;

  spin_lock_irqsave(&g_uid_caps_table.lock, flags);
  hash_for_each(g_uid_caps_table.table, bkt, entry, node) {
    ret = fn(entry->uid, entry->caps, data);
    if (ret)
      break;
  }
  spin_unlock_irqrestore(&g_uid_caps_table.lock, flags);

  return ret;
}

static int __dump_one(uid_t uid, uint64_t caps, void *data) {
  (void)data;
  pr_info("[uid_caps]   UID=%-10u caps=0x%016llx\n", uid, caps);
  return 0;
}

void uid_caps_debug_dump(void) {
  pr_info("[uid_caps] ========== UID Capabilities Table ==========\n");
  uid_caps_for_each(__dump_one, NULL);
  pr_info("[uid_caps] =============================================\n");
}