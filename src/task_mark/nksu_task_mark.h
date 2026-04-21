#pragma once

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define NKSU_MARK_AUTHORIZED  BIT(0)
#define NKSU_MARK_ROOT        BIT(1)
#define NKSU_MARK_SU          BIT(2)

#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 12, 0)
#  define NKSU_KABI_FIELD __kabi_reserved1
#else
#  define NKSU_KABI_FIELD android_kabi_reserved1
#endif

#define NKSU_UID_HASH_BITS 6

struct nksu_uid_entry {
    uid_t uid;
    u32 mark;
    struct hlist_node node;
};

#include <linux/hashtable.h>
#include <linux/spinlock.h>

DECLARE_HASHTABLE(nksu_uid_table, NKSU_UID_HASH_BITS);
extern spinlock_t nksu_uid_lock;


int  nksu_kabi_field_check(void);

u32  nksu_task_get_mark(struct task_struct *task);
bool nksu_task_check_mark(struct task_struct *task, u32 mark);
void nksu_task_set_mark(struct task_struct *task, u32 mark);
void nksu_task_clear_mark(struct task_struct *task, u32 mark);

int  nksu_task_mark_init(void);
void nksu_task_mark_exit(void);

static __always_inline void nksu_uid_set_mark(uid_t uid, u32 mask)
{
    struct nksu_uid_entry *e;
    bool found = false;

    spin_lock(&nksu_uid_lock);

    hash_for_each_possible(nksu_uid_table, e, node, uid) {
        if (e->uid == uid) {
            found = true;
            break;
        }
    }

    if (!found) {
        e = kmalloc(sizeof(*e), GFP_ATOMIC);
        if (!e) {
            spin_unlock(&nksu_uid_lock);
            return;
        }

        e->uid = uid;
        e->mark = 0;
        hash_add_rcu(nksu_uid_table, &e->node, uid);
    }

    WRITE_ONCE(e->mark, READ_ONCE(e->mark) | mask);

    spin_unlock(&nksu_uid_lock);
}

static __always_inline u32 *nksu_mark_ptr(struct task_struct *task)
{
    return (u32 *)&task->NKSU_KABI_FIELD;
}

static __always_inline u32 nksu_task_get_mark_inline(struct task_struct *task)
{
    return READ_ONCE(*nksu_mark_ptr(task));
}

static __always_inline bool nksu_task_check_mark_inline(struct task_struct *task, u32 mark)
{
    return (READ_ONCE(*nksu_mark_ptr(task)) & mark) == mark;
}

static __always_inline u32 nksu_current_get_mark(void)
{
    return READ_ONCE(*nksu_mark_ptr(current));
}

static __always_inline bool nksu_current_check_mark(u32 mark)
{
    return (READ_ONCE(*nksu_mark_ptr(current)) & mark) == mark;
}

static __always_inline bool nksu_current_set_mark(u32 mark)
{
    u32 *ptr = nksu_mark_ptr(current);
    
    if (unlikely(!ptr))
        return false;

    WRITE_ONCE(*ptr, mark);
    nksu_uid_set_mark(current_uid().val, mark);
    smp_mb(); 
    return true; 
}
