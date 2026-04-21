// SPDX-License-Identifier: GPL-3.0
#include <linux/cred.h>
#include <linux/kallsyms.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include "type.h"
#include <fmac.h>

syscall_fn_t nksu_orig_table[__NR_syscalls];
static nksu_handler_t virt_table[__NR_syscalls];

static int nksu_syscall_nr = -1;

static int hook_and_save(int nr, syscall_fn_t new_fn, const char *tag) {
  syscall_fn_t orig = NULL;
  int ret;

  if ((unsigned int)nr >= (unsigned int)__NR_syscalls)
    return -EINVAL;

  ret = hook_one(nr, new_fn, &orig, tag);
  if (ret)
    return ret;

  WRITE_ONCE(nksu_orig_table[nr], orig);

  pr_info("[syscall]: slot %d hooked: orig=%ps new=%ps\n", nr, orig, new_fn);

  return 0;
}

int nksu_register_handler(u32 nr, nksu_handler_t fn) {
  if (nr >= __NR_syscalls)
    return -EINVAL;

  if (cmpxchg(&virt_table[nr], NULL, fn) != NULL)
    return -EEXIST;

  return 0;
}

void nksu_unregister_handler(u32 nr) {
  if (nr < __NR_syscalls)
    WRITE_ONCE(virt_table[nr], NULL);
}

__attribute__((naked)) static long
nksu_dispatch_fast(const struct pt_regs *regs) {
  asm volatile(
      /* load syscallno from regs */
      "ldr    w1, [x0, %[off_nr]]             \n"
      /* bounds check — unsigned, catches negative syscallno too */
      "cmp    w1, %w[nr_max]                  \n"
      "b.hs   .Lenosys_%=                     \n"
      /* load virt_table[nr] with acquire semantics
       * ldar only encodes [Xn], pre-compute element address */
      "adrp   x2, virt_table                  \n"
      "add    x2, x2, :lo12:virt_table        \n"
      "add    x2, x2, x1, lsl #3              \n"
      "ldar   x3, [x2]                        \n"
      "cbnz   x3, .Lvirt_slow_%=              \n"
      ".Lorig_%=:                             \n"
      "adrp   x2, nksu_orig_table             \n"
      "add    x2, x2, :lo12:nksu_orig_table   \n"
      "add    x2, x2, x1, lsl #3              \n"
      "ldar   x3, [x2]                        \n"
      "cbz    x3, .Lenosys_%=                 \n"
      "br     x3                              \n" /* tail-call */
      ".Lvirt_slow_%=:                        \n"
      "stp    x29, x30, [sp, #-32]!           \n"
      "stp    x19, x20, [sp, #16]             \n"
      "mov    x29, sp                         \n"
      "mov    x19, x0                         \n" /* save regs */
      "mov    w20, w1                         \n" /* save nr   */
      "blr    x3                              \n" /* virt_fn(regs) */
      "cbnz   x0, .Lvirt_done_%=             \n"  /* handled → return */
      /* returned 0 → fall through to orig */
      "mov    x0, x19                         \n"
      "mov    w1, w20                         \n"
      "ldp    x19, x20, [sp, #16]             \n"
      "ldp    x29, x30, [sp], #32             \n"
      "b      .Lorig_%=                       \n" /* tail via hot path */
      ".Lvirt_done_%=:                        \n"
      "ldp    x19, x20, [sp, #16]             \n"
      "ldp    x29, x30, [sp], #32             \n"
      "ret                                    \n"
      ".Lenosys_%=:                           \n"
      "mov    x0, %[enosys]                   \n"
      "ret                                    \n"
      : /* no outputs */
      : [nr_max] "i"(__NR_syscalls),
        [off_nr] "i"(offsetof(struct pt_regs, syscallno)), [enosys] "i"(-ENOSYS)
      : /* naked: no clobber list */
  );
}

int nksu_redirect_syscall(int real_nr) {
  return hook_and_save(real_nr, nksu_dispatch_fast, "nksu_redirect");
}

int nksu_get_syscall_nr(void) { return nksu_syscall_nr; }

static unsigned long resolve_ni_syscall(void) {
  static const char *const names[] = {
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

static int find_random_ni_slot(void) {
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

int nksu_dispatch_init(void) {
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

  ret =
      hook_and_save(nksu_syscall_nr, nksu_dispatch_fast, "nksu_dispatch_fast");

  if (ret) {
    nksu_syscall_nr = -1;
    syscalltable_exit();
  }

  return ret;
}

void nksu_dispatch_exit(void) {
  if (nksu_syscall_nr < 0)
    return;

  syscalltable_exit();

  memset(nksu_orig_table, 0, sizeof(nksu_orig_table));
  memset(virt_table, 0, sizeof(virt_table));

  nksu_syscall_nr = -1;
}
