// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    #include <linux/sched/signal.h>
#else
    #include <linux/sched.h>
#endif

#include <fmac.h>
#include "objsec.h"

int transive_to_domain(const char *domain)
{
    const struct cred *cred;
    struct task_security_struct *tsec;
    size_t domain_len;
    u32 sid;
    int error;

    cred = __task_cred(current);
    if (unlikely(!cred))
    {
        fmac_log("Failed to get task credentials!\n");
        return -EINVAL;
    }

    tsec = cred->security;
    if (unlikely(!tsec))
    {
        fmac_log("Task security struct is NULL!\n");
        return -ENOENT;
    }

    domain_len = strlen(domain);

    error = security_secctx_to_secid(domain, domain_len, &sid);
    if (error)
    {
        fmac_log("Failed to convert secctx '%s' (len=%zu) to SID: error=%d\n", domain, domain_len,
              error);
        return error;
    }

    tsec->sid = sid;
    tsec->create_sid = 0;
    tsec->keycreate_sid = 0;
    tsec->sockcreate_sid = 0;

#ifdef CONFIG_FMAC_DEBUG
    fmac_log("Successfully transitioned to domain '%s' (SID=%u)\n", domain, sid);
#endif
    return 0;
} /*Thanks for ksu*/

void elevate_to_root(void)
{
    struct cred *cred;
    int err;

    cred = prepare_creds();
    if (!cred)
    {
        fmac_log("[FMAC] prepare_creds failed!\n");
        return;
    }

    if (cred->euid.val == 0)
    {
        fmac_log("[FMAC] Already root, skip.\n");
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

    err = transive_to_domain("u:r:su:s0");
    if (err)
    {
        fmac_log("SELinux domain transition failed: %d\n", err);
    }

#ifdef CONFIG_SECCOMP
    #ifdef CONFIG_SECCOMP_FILTER
    if (current->seccomp.mode != 0)
    {
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

    fmac_log("Root escalation success: PID=%d\n", current->pid);
}