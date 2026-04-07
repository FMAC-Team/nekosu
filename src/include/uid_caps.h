// uid_caps.h
#ifndef UID_CAPS_H
#define UID_CAPS_H

#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <fmac.h>

#define UID_CAPS_HASH_BITS 8

typedef struct {
    uid_t uid;
    uint64_t caps;
    struct hlist_node node;
} uid_cap_entry_t;

typedef struct {
    DECLARE_HASHTABLE(table, UID_CAPS_HASH_BITS);
    spinlock_t lock;
} uid_caps_table_t;

extern uid_caps_table_t g_uid_caps_table;

int uid_caps_init(void);
void uid_caps_exit(void);
int uid_caps_add(uid_t uid, uint64_t caps);
int uid_caps_remove(uid_t uid);
int uid_caps_update(uid_t uid, uint64_t caps);
uint64_t uid_caps_get(uid_t uid);
int uid_caps_has_uid(uid_t uid);
int uid_caps_clear_all(void);

#endif // UID_CAPS_H