// SPDX-License-Identifier: GPL-3.0
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "type.h"
#include <fmac.h>

#if defined(CONFIG_ARM64)
#define PT_REGS_SYSCALLNO offsetof(struct pt_regs, syscallno)
#else
#error unsupported arch
#endif

syscall_fn_t nksu_orig_table[__NR_syscalls];
static nksu_handler_t virt_table[__NR_syscalls];

static int nksu_syscall_nr = -1;

static int hook_and_save(int nr, syscall_fn_t new_fn, const char *tag)
{
    syscall_fn_t orig = NULL;
    int ret;

    if ((unsigned int)nr >= (unsigned int)__NR_syscalls)
        return -EINVAL;

    ret = hook_one(nr, new_fn, &orig, tag);
    if (ret)
        return ret;

    WRITE_ONCE(nksu_orig_table[nr], orig);

    pr_info("[syscall]: slot %d hooked: orig=%ps new=%ps\n",
            nr, orig, new_fn);

    return 0;
}

int nksu_register_handler(u32 nr, nksu_handler_t fn)
{
    if (nr >= __NR_syscalls)
        return -EINVAL;

    if (cmpxchg(&virt_table[nr], NULL, fn) != NULL)
        return -EEXIST;

    return 0;
}

void nksu_unregister_handler(u32 nr)
{
    if (nr < __NR_syscalls)
        WRITE_ONCE(virt_table[nr], NULL);
}

static long nksu_dispatch_fast(const struct pt_regs *regs)
{
    register long ret asm("x0") = (long)regs;

    asm volatile(
        "ldr w8, [%0, %[off_nr]]\n"

        "cmp w8, #0\n"
        "b.lt 1f\n"
        "cmp w8, %w[nr_max]\n"
        "b.hs 1f\n"

        "adrp x2, virt_table\n"
        "add  x2, x2, :lo12:virt_table\n"
        "ldr  x3, [x2, x8, lsl #3]\n"
        "cbz  x3, 2f\n" 

        "stp  x0, x8, [sp, #-16]!\n"
        "blr  x3\n"
        "ldp  x1, x8, [sp], #16\n"

        "cbnz x0, 3f\n"
        "mov  x0, x1\n"
    "2:\n" 
        "adrp x2, nksu_orig_table\n"
        "add  x2, x2, :lo12:nksu_orig_table\n"
        "ldr  x3, [x2, x8, lsl #3]\n"
        "cbz  x3, 1f\n"

        "blr  x3\n"
        "b    3f\n"

    "1:\n"
        "mov x0, #-38\n" /* -ENOSYS */

    "3:\n"

        : "+r"(ret)
        : [nr_max]"i"(__NR_syscalls),
          [off_nr]"i"(PT_REGS_SYSCALLNO)
        : "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x18", "lr", "memory", "cc"
    );

    return ret;
}


int nksu_redirect_syscall(int real_nr)
{
    return hook_and_save(real_nr, nksu_dispatch_fast, "nksu_redirect");
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

    int i;

    for (i = 0; names[i]; i++) {
        unsigned long addr = kallsyms_lookup_name(names[i]);
        if (addr)
            return addr;
    }

    return 0;
}

static int find_random_ni_slot(void)
{
    unsigned long ni_addr = resolve_ni_syscall();
    int selected = -1, count = 0, i;

    if (!ni_addr)
        return -ENOENT;

    for (i = 0; i < __NR_syscalls; i++) {
        syscall_fn_t fn = READ_ONCE(syscall_table[i]);
        unsigned long slot = (unsigned long)fn;

        if (slot != ni_addr)
            continue;

        count++;
        if ((get_random_u32() % count) == 0)
            selected = i;
    }

    return selected;
}

int nksu_dispatch_init(void)
{
    int rc, ret;

    rc = syscalltable_init();
    if (rc < 0)
        return rc;

    memset(nksu_orig_table, 0, sizeof(nksu_orig_table));
    memset(virt_table, 0, sizeof(virt_table));

    nksu_syscall_nr = find_random_ni_slot();
    if (nksu_syscall_nr < 0) {
        syscalltable_exit();
        return -ENOENT;
    }

    ret = hook_and_save(nksu_syscall_nr,
                        nksu_dispatch_fast,
                        "nksu_dispatch_fast");

    if (ret) {
        nksu_syscall_nr = -1;
        syscalltable_exit();
    }

    return ret;
}

void nksu_dispatch_exit(void)
{
    if (nksu_syscall_nr < 0)
        return;

    syscalltable_exit();

    memset(nksu_orig_table, 0, sizeof(nksu_orig_table));
    memset(virt_table, 0, sizeof(virt_table));

    nksu_syscall_nr = -1;
}