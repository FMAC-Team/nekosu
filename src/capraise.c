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
#include <linux/nsproxy.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    #include <linux/sched/signal.h>
#else
    #include <linux/sched.h>
#endif

#include <fmac.h>
#include "objsec.h"

#define FMAC_PRIV_ROOT      (1 << 0)
#define FMAC_PRIV_CAPS      (1 << 1)
#define FMAC_PRIV_SELINUX   (1 << 2)
#define FMAC_PRIV_SECCOMP   (1 << 3)
#define FMAC_PRIV_ALL       (FMAC_PRIV_ROOT | FMAC_PRIV_CAPS | FMAC_PRIV_SELINUX | FMAC_PRIV_SECCOMP)

static int apply_selinux_domain(struct cred *new_cred, const char *domain)
{
    struct task_security_struct *tsec;
    size_t domain_len;
    u32 sid;
    int error;

    if (!new_cred || !domain)
        return -EINVAL;

    tsec = new_cred->security;
    if (unlikely(!tsec))
    {
        fmac_log("[FMAC] Warning: new_cred->security is NULL. SELinux disabled?\n");
        return -EOPNOTSUPP;
    }

    domain_len = strlen(domain);

    error = security_secctx_to_secid(domain, domain_len, &sid);
    if (error)
    {
        fmac_log("[FMAC] Failed to resolve context '%s': err=%d\n", domain, error);
        return error;
    }

    tsec->sid = sid;
    
    tsec->create_sid = 0;
    tsec->keycreate_sid = 0;
    tsec->sockcreate_sid = 0;

    fmac_log("[FMAC] Prepared SELinux transition to SID %u (%s)\n", sid, domain);
    return 0;
}

static void disable_seccomp(void)
{
#ifdef CONFIG_SECCOMP
    struct task_struct *task = current;

    if (task->seccomp.mode == SECCOMP_MODE_DISABLED)
        return;

    spin_lock_irq(&task->sighand->siglock);

#ifdef CONFIG_SECCOMP_FILTER
    if (task->seccomp.mode != SECCOMP_MODE_DISABLED)
    {
        task->seccomp.mode = SECCOMP_MODE_DISABLED;
        
        #if defined(TIF_SECCOMP)
        clear_thread_flag(TIF_SECCOMP);
        #endif

        #if defined(_TIF_SECCOMP)
        clear_thread_flag(_TIF_SECCOMP);
        #endif
        
        fmac_log("[FMAC] Seccomp disabled for PID %d\n", task->pid);
    }
#endif

    spin_unlock_irq(&task->sighand->siglock);
#endif
}

void fmac_grant_privileges(unsigned int flags, kernel_cap_t caps_to_raise, const char *target_domain)
{
    struct cred *new_cred;
    int err;
    bool needs_commit = false;

    if ((flags & FMAC_PRIV_SECCOMP) && !(flags & (FMAC_PRIV_ROOT | FMAC_PRIV_CAPS | FMAC_PRIV_SELINUX))) {
        disable_seccomp();
        return;
    }

    new_cred = prepare_creds();
    if (!new_cred)
    {
        fmac_log("[FMAC] prepare_creds failed! OOM?\n");
        return;
    }

    if (flags & FMAC_PRIV_ROOT)
    {
        if (new_cred->euid.val != 0) 
        {
            new_cred->uid.val = 0;
            new_cred->euid.val = 0;
            new_cred->suid.val = 0;
            new_cred->fsuid.val = 0;

            new_cred->gid.val = 0;
            new_cred->egid.val = 0;
            new_cred->sgid.val = 0;
            new_cred->fsgid.val = 0;
            
            new_cred->securebits = 0;
            
            needs_commit = true;
        }
    }

    if (flags & FMAC_PRIV_CAPS)
    {
        new_cred->cap_effective = cap_combine(new_cred->cap_effective, caps_to_raise);
        new_cred->cap_permitted = cap_combine(new_cred->cap_permitted, caps_to_raise);
        new_cred->cap_bset      = cap_combine(new_cred->cap_bset, caps_to_raise);
        
        needs_commit = true;
    }

    if ((flags & FMAC_PRIV_SELINUX) && target_domain)
    {
        err = apply_selinux_domain(new_cred, target_domain);
        if (err)
        {
            fmac_log("[FMAC] SELinux setup failed (%d), aborting privilege escalation.\n", err);
            abort_creds(new_cred);
            return;
        }
        needs_commit = true;
    }

    if (needs_commit)
    {
        commit_creds(new_cred);
        fmac_log("[FMAC] Privileges committed for PID %d.\n", current->pid);
    }
    else
    {
        abort_creds(new_cred);
    }

    if (flags & FMAC_PRIV_SECCOMP)
    {
        disable_seccomp();
    }
}

void elevate_to_root(void)
{
    kernel_cap_t all_caps;
    CAP_EMPTY(all_caps);
    CAP_RAISE(all_caps, CAP_SYS_ADMIN);
    CAP_RAISE(all_caps, CAP_DAC_OVERRIDE);
    CAP_RAISE(all_caps, CAP_SETUID);
    CAP_RAISE(all_caps, CAP_SETGID);
    CAP_RAISE(all_caps, CAP_NET_ADMIN);
    CAP_RAISE(all_caps, CAP_SYS_PTRACE);
    CAP_RAISE(all_caps, CAP_SYS_MODULE);
    CAP_RAISE(all_caps, CAP_DAC_READ_SEARCH);

    fmac_grant_privileges(FMAC_PRIV_ALL, all_caps, "u:r:su:s0");
}
