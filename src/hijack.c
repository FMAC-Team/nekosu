// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/trace_events.h>
#include <asm/syscall.h>

#include <fmac.h>
#include "hijack.h"

#define REDIRECT_TARGET     "/data/adb/ncore"
#define REDIRECT_TARGET_LEN (sizeof(REDIRECT_TARGET))

#define SH_PATH             "/system/bin/sh"
#define SH_PATH_LEN         (sizeof(SH_PATH))

#define SU_PATH             "/system/bin/su"
#define SU_PATH_LEN         (sizeof(SU_PATH))

#define SCOPE_HASH_BITS 6

// no export
struct scope_entry {
    uid_t           uid;
    u32             flags;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(scope_table, SCOPE_HASH_BITS);
static DEFINE_SPINLOCK(scope_lock);

static u32 scope_lookup(uid_t uid)
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
    e->uid   = uid;
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

u32 fmac_scope_get(uid_t uid)
{
    return scope_lookup(uid);
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

static inline u32 current_scope(void)
{
    return scope_lookup(current_uid().val);
}

static inline bool path_is_su(const char *p)
{
    return memcmp(p, SU_PATH, SU_PATH_LEN) == 0;
}

static unsigned long push_str(unsigned long sp,
                               const char *str, size_t len)
{
    unsigned long addr = (sp - 128 - len) & ~15UL;

    if (copy_to_user((void __user *)addr, str, len))
        return 0;
    return addr;
}

static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_sys_exit;

static void probe_sys_enter(void *data, struct pt_regs *regs, long id)
{
    char kpath[MAX_PATH_LEN];
    unsigned long uaddr;
    unsigned long sp;
    u32 scope;
    const char __user *upath;

    switch (id) {
    case __NR_execve:
    case __NR_execveat:
    case __NR_faccessat:
    case __NR_newfstatat:
        break;
    default:
        return;
    }

    scope = current_scope();
    if (!scope)
        return;

    switch (id) {
    case __NR_execve:
        upath = (const char __user *)regs->regs[0];
        break;
    default:
        upath = (const char __user *)regs->regs[1];
        break;
    }

    if (!upath)
        return;
    if (strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
        return;
    kpath[sizeof(kpath) - 1] = '\0';

    if (!path_is_su(kpath))
        return;

    sp = (unsigned long)current->mm
             ? user_stack_pointer(regs)
             : 0;
    if (!sp)
        return;

    switch (id) {
    case __NR_execve:
        if (!(scope & FMAC_SCOPE_EXEC))
            return;
        uaddr = push_str(sp, REDIRECT_TARGET, REDIRECT_TARGET_LEN);
        if (!uaddr) return;
        pr_info("fmac: execve %s -> " REDIRECT_TARGET "\n", kpath);
        regs->regs[0] = uaddr;
        elevate_to_root();
        break;

    case __NR_execveat:
        if (!(scope & FMAC_SCOPE_EXEC))
            return;
        uaddr = push_str(sp, REDIRECT_TARGET, REDIRECT_TARGET_LEN);
        if (!uaddr) return;
        pr_info("fmac: execveat %s -> " REDIRECT_TARGET "\n", kpath);
        regs->regs[1] = uaddr;
        elevate_to_root();
        break;

    case __NR_faccessat:
        if (!(scope & FMAC_SCOPE_ACCESS))
            return;
        uaddr = push_str(sp, SH_PATH, SH_PATH_LEN);
        if (!uaddr) return;
        pr_info("fmac: faccessat %s -> " SH_PATH "\n", kpath);
        regs->regs[1] = uaddr;
        break;

    case __NR_newfstatat:
        if (!(scope & FMAC_SCOPE_STAT))
            return;
        uaddr = push_str(sp, SH_PATH, SH_PATH_LEN);
        if (!uaddr) return;
        pr_info("fmac: newfstatat %s -> " SH_PATH "\n", kpath);
        regs->regs[1] = uaddr;
        break;
    }
}

// no export
struct tp_find_ctx {
    const char      *name;
    struct tracepoint **out;
};

static void tp_find_cb(struct tracepoint *tp, void *priv)
{
    struct tp_find_ctx *ctx = priv;

    if (*ctx->out)
        return;
    if (strcmp(tp->name, ctx->name) == 0)
        *ctx->out = tp;
}

static struct tracepoint *find_tracepoint(const char *name)
{
    struct tracepoint *result = NULL;
    struct tp_find_ctx ctx2  = { .name = name, .out = &result };

    for_each_kernel_tracepoint(tp_find_cb, &ctx2);
    return result;
}

static struct tracepoint *tp_sched_fork;

static void probe_sched_fork(void *data,
                              struct task_struct *parent,
                              struct task_struct *child)
{
    if (!scope_lookup(parent->cred->uid.val))
        return;

    set_tsk_thread_flag(child, TIF_SYSCALL_TRACEPOINT);
}

int load_hijack_hook(void)
{
    int ret;

    tp_sys_enter = find_tracepoint("sys_enter");
    if (!tp_sys_enter) {
        pr_err("fmac: cannot find sys_enter tracepoint\n");
        return -ENOENT;
    }

    tp_sched_fork = find_tracepoint("sched_process_fork");
    if (!tp_sched_fork) {
        pr_err("fmac: cannot find sched_process_fork tracepoint\n");
        return -ENOENT;
    }

    ret = tracepoint_probe_register(tp_sys_enter, probe_sys_enter, NULL);
    if (ret) {
        pr_err("fmac: register sys_enter probe failed: %d\n", ret);
        return ret;
    }

    ret = tracepoint_probe_register(tp_sched_fork, probe_sched_fork, NULL);
    if (ret) {
        pr_err("fmac: register sched_process_fork probe failed: %d\n", ret);
        tracepoint_probe_unregister(tp_sys_enter, probe_sys_enter, NULL);
        return ret;
    }

    pr_info("fmac: hijack hooks loaded (tracepoint)\n");
    return 0;
}

void unload_hijack_hook(void)
{
    if (tp_sys_enter)
        tracepoint_probe_unregister(tp_sys_enter, probe_sys_enter, NULL);
    if (tp_sched_fork)
        tracepoint_probe_unregister(tp_sched_fork, probe_sched_fork, NULL);

    tracepoint_synchronize_unregister();

    fmac_scope_clear_all();

    pr_info("fmac: hijack hooks unloaded\n");
}
