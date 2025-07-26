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

#define MAGIC_TOKEN "123456"

#include "fmac.h"
#include "objsec.h"

static void elevate_to_root(void) {
  struct cred *cred;
  u32 sid;
  int err;

  cred = prepare_creds();
  if (!cred) {
    pr_warn("[FMAC] prepare_creds failed!\n");
    return;
  }

  // 判断是否已是 root，避免重复提权
  if (cred->euid.val == 0) {
    pr_info("[FMAC] Already root, skip.\n");
    abort_creds(cred);
    return;
  }

  // 获取 su 的 SELinux SID（可选）
  err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &sid);
  if (err) {
    fmac_append_to_log("[FMAC] Failed to get SELinux SID: %d\n", err);
  }

  // 设置 UID/GID
  cred->uid.val = 0;
  cred->euid.val = 0;
  cred->suid.val = 0;
  cred->fsuid.val = 0;

  cred->gid.val = 0;
  cred->egid.val = 0;
  cred->sgid.val = 0;
  cred->fsgid.val = 0;

  ((struct task_security_struct *)cred->security)->sid = sid;

  // 清除 securebits
  cred->securebits = 0;

  // 赋予所有 Capabilities（支持 CAP_DAC_OVERRIDE / SETUID 等）
  cap_raise(cred->cap_effective, CAP_SYS_ADMIN);
  cap_raise(cred->cap_effective, CAP_DAC_OVERRIDE);
  cap_raise(cred->cap_effective, CAP_SETUID);
  cap_raise(cred->cap_effective, CAP_SETGID);
  cap_raise(cred->cap_effective, CAP_NET_ADMIN);
  cap_raise(cred->cap_effective, CAP_SYS_PTRACE);
  cap_raise(cred->cap_effective, CAP_SYS_MODULE);
  cap_raise(cred->cap_effective, CAP_DAC_READ_SEARCH);

  // 让其他集合与 effective 相同（可调）
  cred->cap_permitted = cred->cap_effective;
  cred->cap_bset = cred->cap_effective;
  // cap_inheritable 留空可防 exec 继承

  // 提交 cred
  commit_creds(cred);

  // 关闭 seccomp（参考 KernelSU 的实现）
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
    current->seccomp.mode = SECCOMP_MODE_DISABLE;
    spin_unlock_irq(&current->sighand->siglock);
  }
#endif
#endif

  pr_info("[FMAC] Root escalation success: PID=%d\n", current->pid);
}

ssize_t fmac_environ_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos) {
  char kbuf[64] = {0};

  if (count >= sizeof(kbuf))
    return -EINVAL;

  if (copy_from_user(kbuf, buf, count))
    return -EFAULT;

  kbuf[count] = '\0';

  if (memcmp(kbuf, MAGIC_TOKEN, 6) == 0) {
    elevate_to_root();
    fmac_append_to_log("[FMAC] root triggered via /proc/self/environ\n");
  }

  return count;
}