// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/android_kabi.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/uidgid.h>
#include <linux/spinlock.h>
#include <trace/events/sched.h>

#include <fmac.h>

#define NKSU_UID_HASH_BITS 6

struct nksu_uid_entry {
    uid_t uid;
    u32 mark;
    struct hlist_node node;
};

DEFINE_HASHTABLE(nksu_uid_table, NKSU_UID_HASH_BITS);
DEFINE_SPINLOCK(nksu_uid_lock);

static __always_inline u32 nksu_uid_get_mark(uid_t uid)
{
    struct nksu_uid_entry *e;
    u32 mark = 0;

    rcu_read_lock();

    hash_for_each_possible_rcu(nksu_uid_table, e, node, uid) {
        if (e->uid == uid) {
            mark = READ_ONCE(e->mark);
            break;
        }
    }

    rcu_read_unlock();
    return mark;
}

static __always_inline void nksu_uid_clear_mark(uid_t uid, u32 mask)
{
    struct nksu_uid_entry *e;

    rcu_read_lock();

    hash_for_each_possible_rcu(nksu_uid_table, e, node, uid) {
        if (e->uid == uid) {
            u32 old = READ_ONCE(e->mark);
            WRITE_ONCE(e->mark, old & ~mask);
            break;
        }
    }

    rcu_read_unlock();
}

u32 nksu_task_get_mark(struct task_struct *task)
{
    u32 v = READ_ONCE(*nksu_mark_ptr(task));

    if (likely(v))
        return v;

    return nksu_uid_get_mark(task_uid(task).val);
}

bool nksu_task_check_mark(struct task_struct *task, u32 mark)
{
    u32 v = READ_ONCE(*nksu_mark_ptr(task));

    if (likely(v))
        return (v & mark) == mark;

    return (nksu_uid_get_mark(task_uid(task).val) & mark) == mark;
}

void nksu_task_set_mark(struct task_struct *task, u32 mark)
{
    u32 *ptr = nksu_mark_ptr(task);
    u32 old, new;

    do {
        old = READ_ONCE(*ptr);
        new = old | mark;
    } while (cmpxchg(ptr, old, new) != old);

    nksu_uid_set_mark(task_uid(task).val, mark);
}

void nksu_task_clear_mark(struct task_struct *task, u32 mark)
{
    u32 *ptr = nksu_mark_ptr(task);
    u32 old, new;

    do {
        old = READ_ONCE(*ptr);
        new = old & ~mark;
    } while (cmpxchg(ptr, old, new) != old);

    nksu_uid_clear_mark(task_uid(task).val, mark);
}

static void nksu_on_fork(void *data,
                          struct task_struct *parent,
                          struct task_struct *child)
{
    uid_t uid = task_uid(child).val;
    u32 mark = nksu_uid_get_mark(uid);

    WRITE_ONCE(*nksu_mark_ptr(child), mark);
}

static void nksu_on_exec(void *data, 
                         struct task_struct *p, 
                         pid_t old_pid, 
                         struct linux_binprm *bprm)
{
    uid_t uid = task_uid(p).val;
    u32 mark = nksu_uid_get_mark(uid);

    u32 *m_ptr = nksu_mark_ptr(p);
    if (likely(m_ptr)) {
        WRITE_ONCE(*m_ptr, mark);
    }
}


int nksu_task_mark_init(void)
{
    int ret;

    ret = register_trace_sched_process_fork(nksu_on_fork, NULL);
    if (ret)
        return ret;

    register_trace_sched_process_exec(nksu_on_exec, NULL);

    pr_info("nksu: UID-based task mark system initialized\n");
    return 0;
}

void nksu_task_mark_exit(void)
{
    unregister_trace_sched_process_fork(nksu_on_fork, NULL);
    unregister_trace_sched_process_exec(nksu_on_exec, NULL);
}