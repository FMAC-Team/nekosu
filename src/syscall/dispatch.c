#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "type.h"

#include <fmac.h>

static syscall_fn_t orig_dispatch;
static int nksu_syscall_nr = -1;

#define VIRT_HASH_BITS 8

struct virt_entry {
    u32              nr;
    nksu_handler_t   fn;
    struct hlist_node node;
    struct rcu_head   rcu;
};

static DEFINE_HASHTABLE(virt_hash, VIRT_HASH_BITS);
static DEFINE_SPINLOCK(virt_lock);

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
    int nr;

    nr = syscall_get_nr(current, (struct pt_regs *)regs);

    if (likely(nr == nksu_syscall_nr)) {
        if (copy_from_user(&args, (void __user *)regs->regs[0], sizeof(args)))
            return -EFAULT;
        return do_dispatch_cmd(&args);
    }

    fn = virt_lookup((u32)nr);
    if (unlikely(!fn))
        return -ENOSYS;

    args.cmd  = NKSU_CMD_SYSCALL_CALL;
    args.nr   = (u32)nr;
    args.arg0 = regs->regs[0];
    args.arg1 = regs->regs[1];
    args.arg2 = regs->regs[2];
    args.arg3 = regs->regs[3];
    args.arg4 = regs->regs[4];
    args.arg5 = regs->regs[5];

    return fn(&args);
}

int nksu_redirect_syscall(int real_nr)
{
    syscall_fn_t dummy;
    return hook_one(real_nr,
                    (syscall_fn_t)nksu_dispatch,
                    &dummy,
                    "nksu_redirect");
}

int nksu_get_syscall_nr(void)
{
    return nksu_syscall_nr;
}

static int find_random_ni_slot(void)
{
    unsigned long ni_addr;
    int selected = -1, count = 0, i;
    ni_addr = (unsigned long)kallsyms_lookup_name("__arm64_sys_ni_syscall");

    if (!ni_addr) {
        pr_err("nksu: [syscall] can't resolve ni_syscall symbol\n");
        return -ENOENT;
    }

    for (i = 0; i < __NR_syscalls; i++) {
        if ((unsigned long)READ_ONCE(syscall_table[i]) != ni_addr)
            continue;
        count++;
        if ((get_random_u32() % count) == 0)
            selected = i;
    }

    if (selected < 0)
        pr_err("nksu: [syscall] no ni slot found\n");
    else
        pr_info("nksu: [syscall] selected ni slot %d (0x%x) from %d candidates\n",
                selected, selected, count);

    return selected < 0 ? -ENOENT : selected;
}

int nksu_dispatch_init(void)
{
    int ret;
    
    int rc = syscalltable_init();
    if( rc < 0 )
    {
      pr_err("failed to init syscall table\n");
      return rc;
    }

    hash_init(virt_hash);

    nksu_syscall_nr = find_random_ni_slot();
    if (nksu_syscall_nr < 0) {
        pr_err("[syscall]: no unused syscall slot found above 0x100\n");
        return -ENOENT;
    }

    pr_info("[syscall]: using syscall slot %d (0x%x)\n",
            nksu_syscall_nr, nksu_syscall_nr);

    ret = hook_one(nksu_syscall_nr,
                   (syscall_fn_t)nksu_dispatch,
                   &orig_dispatch,
                   "nksu_dispatch");
    if (ret)
        nksu_syscall_nr = -1;

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

    orig_dispatch = NULL;
    nksu_syscall_nr = -1;
}
