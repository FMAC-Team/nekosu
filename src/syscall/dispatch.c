// SPDX-License-Identifier: GPL-3.0
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "type.h"
#include <fmac.h>

#define PT_REGS_REG0   offsetof(struct pt_regs, regs[0])
#define PT_REGS_REG1   offsetof(struct pt_regs, regs[1])
#define PT_REGS_REG2   offsetof(struct pt_regs, regs[2])
#define PT_REGS_REG3   offsetof(struct pt_regs, regs[3])
#define PT_REGS_REG4   offsetof(struct pt_regs, regs[4])
#define PT_REGS_REG5   offsetof(struct pt_regs, regs[5])

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

static __always_inline long
nksu_dispatch_fast(const struct pt_regs *regs)
{
    register const struct pt_regs *r0 asm("x0") = regs;
    register long ret asm("x0");

    asm volatile(
        /* nr = regs->syscallno */
        "ldr w1, [%x0, %[off_nr]]\n"
        "mov w8, w1\n"

        /* bounds */
        "cmp w1, %w[nr_max]\n"
        "b.hs 1f\n"

        /* fn = virt_table[nr] */
        "adrp x2, virt_table\n"
        "add  x2, x2, :lo12:virt_table\n"
        "ldr  x3, [x2, x1, lsl #3]\n"
        "cbz  x3, 1f\n"

        /* load args */
        "ldr x1, [%x0, %[off0]]\n"
        "ldr x2, [%x0, %[off1]]\n"
        "ldr x4, [%x0, %[off2]]\n"
        "ldr x5, [%x0, %[off3]]\n"
        "ldr x6, [%x0, %[off4]]\n"
        "ldr x7, [%x0, %[off5]]\n"

        /* call handler */
        "blr x3\n"
        "cbnz x0, 2f\n"

        /* fallback */
        "1:\n"
        "adrp x2, nksu_orig_table\n"
        "add  x2, x2, :lo12:nksu_orig_table\n"
        "ldr  x3, [x2, x8, lsl #3]\n"
        "cbz  x3, 9f\n"
        "mov  x0, %x[regs]\n"
        "blr  x3\n"
        "b 3f\n"

        /* no syscall */
        "9:\n"
        "mov x0, #-38\n"

        "2:\n"
        "3:\n"

        : "+r"(ret)
        : "r"(r0),
          [regs]"r"(r0),
          [nr_max]"i"(__NR_syscalls),
          [off_nr]"i"(PT_REGS_SYSCALLNO),
          [off0]"i"(PT_REGS_REG0),
          [off1]"i"(PT_REGS_REG1),
          [off2]"i"(PT_REGS_REG2),
          [off3]"i"(PT_REGS_REG3),
          [off4]"i"(PT_REGS_REG4),
          [off5]"i"(PT_REGS_REG5)
        : "x1","x2","x3","x4","x5","x6","x7","x8","memory","cc"
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