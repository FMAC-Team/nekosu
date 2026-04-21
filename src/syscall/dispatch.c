// SPDX-License-Identifier: GPL-3.0
/*
 * dispatch.c - nksu virtual syscall dispatcher
 *
 * Maintains a shadow table of original syscall function pointers.
 * If a handler returns 0 the original syscall is invoked (passthrough).
 */

#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "type.h"
#include <fmac.h>

syscall_fn_t nksu_orig_table[__NR_syscalls];

static int nksu_syscall_nr = -1;

#define VIRT_HASH_BITS 8

struct virt_entry {
    u32               nr;
    nksu_handler_t    fn;
    struct hlist_node node;
    struct rcu_head   rcu;
};

static DEFINE_HASHTABLE(virt_hash, VIRT_HASH_BITS);
static DEFINE_SPINLOCK(virt_lock);

static int hook_and_save(int nr, syscall_fn_t new_fn, const char *tag)
{
    syscall_fn_t orig = NULL;
    int ret;

    if ((unsigned int)nr >= (unsigned int)__NR_syscalls) {
        pr_err("[syscall]: hook_and_save: nr %d out of range\n", nr);
        return -EINVAL;
    }

    ret = hook_one(nr, new_fn, &orig, tag);
    if (ret) {
        pr_err("[syscall]: hook_and_save: hook_one(%d) failed: %d\n",
               nr, ret);
        return ret;
    }

    WRITE_ONCE(nksu_orig_table[nr], orig);
    pr_info("[syscall]: slot %d hooked: orig=%ps new=%ps\n",
            nr, orig, new_fn);
    return 0;
}

static __always_inline long call_orig(int nr, const struct pt_regs *regs)
{
    syscall_fn_t orig;

    if (unlikely((unsigned int)nr >= (unsigned int)__NR_syscalls))
        return -ENOSYS;

    orig = READ_ONCE(nksu_orig_table[nr]);
    if (unlikely(!orig))
        return -ENOSYS;

    return orig(regs);
}

int nksu_register_handler(u32 nr, nksu_handler_t fn)
{
    struct virt_entry *entry, *existing;
    unsigned long flags;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    entry->nr = nr;
    entry->fn = fn;

    spin_lock_irqsave(&virt_lock, flags);
    hash_for_each_possible(virt_hash, existing, node, nr) {
        if (existing->nr == nr) {
            spin_unlock_irqrestore(&virt_lock, flags);
            kfree(entry);
            return -EEXIST;
        }
    }
    hash_add_rcu(virt_hash, &entry->node, nr);
    spin_unlock_irqrestore(&virt_lock, flags);

    pr_info("[syscall]: registered virtual syscall 0x%x\n", nr);
    return 0;
}

static void virt_entry_free(struct rcu_head *head)
{
    kfree(container_of(head, struct virt_entry, rcu));
}

void nksu_unregister_handler(u32 nr)
{
    struct virt_entry *entry;
    unsigned long flags;

    spin_lock_irqsave(&virt_lock, flags);
    hash_for_each_possible(virt_hash, entry, node, nr) {
        if (entry->nr == nr) {
            hash_del_rcu(&entry->node);
            call_rcu(&entry->rcu, virt_entry_free);
            break;
        }
    }
    spin_unlock_irqrestore(&virt_lock, flags);
}

static __always_inline nksu_handler_t virt_lookup(u32 nr)
{
    struct virt_entry *entry;
    nksu_handler_t fn = NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(virt_hash, entry, node, nr) {
        if (entry->nr == nr) {
            fn = entry->fn;
            break;
        }
    }
    rcu_read_unlock();
    return fn;
}

static long nksu_cmd_ping(void)
{
    return 0xDEADBEEF;
}

static long nksu_cmd_check_uid(uid_t uid)
{
    return nksu_task_check_mark(current, NKSU_MARK_AUTHORIZED) ? 1 : 0;
}

static long __always_inline do_dispatch_cmd(struct nksu_args *args)
{
    nksu_handler_t fn;

    switch (args->cmd) {
    case NKSU_CMD_PING:
        return nksu_cmd_ping();
    case NKSU_CMD_CHECK_UID:
        return nksu_cmd_check_uid((uid_t)args->arg0);
    case NKSU_CMD_SYSCALL_CALL:
        fn = virt_lookup(args->nr);
        if (unlikely(!fn))
            return -ENOSYS;
        return fn(args);
    default:
        return -ENOSYS;
    }
}

static long nksu_dispatch(const struct pt_regs *regs)
{
    struct nksu_args args;
    nksu_handler_t fn;
    long ret;
    int nr;

    nr = syscall_get_nr(current, (struct pt_regs *)regs);

    if (likely(nr == nksu_syscall_nr)) {
        if (copy_from_user(&args, (void __user *)regs->regs[0], sizeof(args)))
            return -EFAULT;

        ret = do_dispatch_cmd(&args);
        if (ret == 0)
            return call_orig(nr, regs);
        return ret;
    }

    fn = virt_lookup((u32)nr);
    if (!fn)
        return call_orig(nr, regs); 

    args.cmd  = NKSU_CMD_SYSCALL_CALL;
    args.nr   = (u32)nr;
    args.regs = &regs;
    args.arg0 = regs->regs[0];
    args.arg1 = regs->regs[1];
    args.arg2 = regs->regs[2];
    args.arg3 = regs->regs[3];
    args.arg4 = regs->regs[4];
    args.arg5 = regs->regs[5];

    ret = fn(&args);
    if (ret == 0)
        return call_orig(nr, regs);
    return ret;
}

int nksu_redirect_syscall(int real_nr)
{
    return hook_and_save(real_nr, (syscall_fn_t)nksu_dispatch, "nksu_redirect");
}

int nksu_get_syscall_nr(void)
{
    return nksu_syscall_nr;
}

static unsigned long resolve_ni_syscall(void)
{
    static const char * const names[] = {
        "__arm64_sys_ni_syscall.cfi_jt",
        "__arm64_sys_ni_syscall",
        "sys_ni_syscall",
        "__sys_ni_syscall",
        NULL,
    };
    unsigned long addr;
    int i;

    for (i = 0; names[i]; i++) {
        addr = (unsigned long)kallsyms_lookup_name(names[i]);
        if (addr) {
            pr_info("[syscall]: ni_syscall resolved via '%s' = %px\n",
                    names[i], (void *)addr);
            return addr;
        }
    }

    pr_err("[syscall]: failed to resolve ni_syscall\n");
    return 0;
}

static int find_random_ni_slot(void)
{
    unsigned long ni_addr;
    int selected = -1, count = 0, i;

    ni_addr = resolve_ni_syscall();
    if (!ni_addr)
        return -ENOENT;

    pr_info("[syscall]: scanning %d slots, ni_addr=0x%lx\n",
            __NR_syscalls, ni_addr);

    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long slot = (unsigned long)READ_ONCE(syscall_table[i]);
#ifdef CONFIG_NKSU_DEBUG
        if (i < 8)
            pr_info("nksu: [debug] slot[%d] = 0x%lx\n", i, slot);
#endif
        if (slot != ni_addr)
            continue;
        count++;
        if ((get_random_u32() % (unsigned int)count) == 0)
            selected = i;
    }

    pr_info("[syscall]: scan done: %d ni slots found, selected=%d\n",
            count, selected);

    if (selected < 0) {
        pr_err("[syscall]: no ni slot found\n");
        return -ENOENT;
    }

    pr_info("[syscall]: selected ni slot %d (0x%x)\n", selected, selected);
    return selected;
}

int nksu_dispatch_init(void)
{
    int rc, ret;

    rc = syscalltable_init();
    if (rc < 0) {
        pr_err("nksu: failed to init syscall table: %d\n", rc);
        return rc;
    }

    memset(nksu_orig_table, 0, sizeof(nksu_orig_table));

    hash_init(virt_hash);

    nksu_syscall_nr = find_random_ni_slot();
    if (nksu_syscall_nr < 0) {
        pr_err("[syscall]: no unused syscall slot found\n");
        syscalltable_exit();
        return -ENOENT;
    }

    pr_info("[syscall]: using slot %d (0x%x)\n",
            nksu_syscall_nr, nksu_syscall_nr);

    ret = hook_and_save(nksu_syscall_nr,
                        (syscall_fn_t)nksu_dispatch,
                        "nksu_dispatch");
    if (ret) {
        nksu_syscall_nr = -1;
        syscalltable_exit();
    }

    return ret;
}

void nksu_dispatch_exit(void)
{
    struct virt_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    if (nksu_syscall_nr < 0)
        return;

    syscalltable_exit();

    spin_lock_irqsave(&virt_lock, flags);
    hash_for_each_safe(virt_hash, bkt, tmp, entry, node) {
        hash_del_rcu(&entry->node);
        call_rcu(&entry->rcu, virt_entry_free);
    }
    spin_unlock_irqrestore(&virt_lock, flags);
    rcu_barrier();
    memset(nksu_orig_table, 0, sizeof(nksu_orig_table));

    nksu_syscall_nr = -1;
}