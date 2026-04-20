#include <linux/kallsyms.h>
#include <asm/syscall.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/stop_machine.h>

#include <fmac.h>

static struct mm_struct *init_mm_ptr;
syscall_fn_t *syscall_table;

#define MAX_HOOKS 256

struct hook_entry {
    unsigned long addr;
    syscall_fn_t  original;
};

static struct hook_entry hook_table[MAX_HOOKS];
static int               hook_count = 0;
static DEFINE_SPINLOCK(hook_lock);

static DEFINE_RAW_SPINLOCK(patching_lock);

static void *patch_map(void *addr, int fixmap_idx)
{
    unsigned long uaddr = (unsigned long)addr;
    phys_addr_t phys    = __pa_symbol(addr);

    set_fixmap(fixmap_idx, phys);
    return (void *)(fix_to_virt(fixmap_idx) + (uaddr & ~PAGE_MASK));
}

static void patch_unmap(int fixmap_idx)
{
    clear_fixmap(fixmap_idx);
}

#ifndef FIX_TEXT_POKE0
#  define FIX_TEXT_POKE0 FIX_HOLE
#endif

struct patch_insn {
    void         *addr;
    syscall_fn_t  newval;
};

static int do_patch(void *data)
{
    struct patch_insn *p = data;
    syscall_fn_t *mapped;

    mapped = patch_map(p->addr, FIX_TEXT_POKE0);
    WRITE_ONCE(*mapped, p->newval);
    dsb(ish);
    isb();
    patch_unmap(FIX_TEXT_POKE0);
    return 0;
}

static int patch_syscall_slot(void *addr, syscall_fn_t newval)
{
    struct patch_insn p = { .addr = addr, .newval = newval };
    return stop_machine(do_patch, &p, NULL);
}

static int syscalltable_hook(unsigned long addr, syscall_fn_t hook_fn)
{
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&hook_lock, flags);

    if (hook_count >= MAX_HOOKS) {
        spin_unlock_irqrestore(&hook_lock, flags);
        return -ENOMEM;
    }

    hook_table[hook_count].addr     = addr;
    hook_table[hook_count].original = *(syscall_fn_t *)addr;
    hook_count++;

    spin_unlock_irqrestore(&hook_lock, flags);

    ret = patch_syscall_slot((void *)addr, hook_fn);
    if (ret) {
        spin_lock_irqsave(&hook_lock, flags);
        hook_count--;
        spin_unlock_irqrestore(&hook_lock, flags);
        pr_err("[syscall]: patch_syscall_slot failed: %d\n", ret);
    }
    return ret;
}

static int syscalltable_unhook(unsigned long addr)
{
    unsigned long flags;
    int i, ret;
    syscall_fn_t orig;

    spin_lock_irqsave(&hook_lock, flags);
    for (i = 0; i < hook_count; i++) {
        if (hook_table[i].addr == addr)
            break;
    }
    if (i == hook_count) {
        spin_unlock_irqrestore(&hook_lock, flags);
        pr_err("[syscall]: addr not found\n");
        return -ENOENT;
    }
    orig = hook_table[i].original;
    hook_table[i] = hook_table[--hook_count];
    spin_unlock_irqrestore(&hook_lock, flags);

    ret = patch_syscall_slot((void *)addr, orig);
    if (ret)
        pr_err("[syscall]: unhook patch failed: %d\n", ret);
    return ret;
}

static syscall_fn_t syscalltable_get_original(unsigned long addr)
{
    unsigned long flags;
    syscall_fn_t orig = NULL;
    int i;

    spin_lock_irqsave(&hook_lock, flags);
    for (i = 0; i < hook_count; i++) {
        if (hook_table[i].addr == addr) {
            orig = hook_table[i].original;
            break;
        }
    }
    spin_unlock_irqrestore(&hook_lock, flags);
    return orig;
}

int hook_one(int nr, syscall_fn_t fn, syscall_fn_t *orig, const char *name)
{
    unsigned long addr = (unsigned long)&syscall_table[nr];
    int ret = syscalltable_hook(addr, fn);

    if (ret) {
        pr_err("failed to hook %s: %d\n", name, ret);
        return ret;
    }
    *orig = syscalltable_get_original(addr);
    pr_info("hooked %s\n", name);
    return 0;
}

int syscalltable_init(void)
{
    init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
    if (!init_mm_ptr) {
        pr_err("failed to find init_mm\n");
        return -ENOENT;
    }

    syscall_table = (syscall_fn_t *)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        pr_err("failed to find sys_call_table\n");
        return -ENOENT;
    }

    pr_info("[syscall]: syscall table at %px\n", syscall_table);
    return 0;
}

void syscalltable_exit(void)
{
    while (hook_count > 0)
        syscalltable_unhook(hook_table[hook_count - 1].addr);
}