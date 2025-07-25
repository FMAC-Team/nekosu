// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/selinux.h>
#include <linux/security.h>
#include "objsec.h"

#include "fmac.h"

#define FMAC_ROOT_KEY "123456"

int elevate_to_root(void)
{
    struct cred *cred;
    u32 sid = 0;
    int err;

    // 获取 su 的 SELinux SID（可选）
    err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &sid);
    if (err) {
        fmac_append_to_log("[FMAC] Failed to get SELinux SID: %d\n", err);
        return -EINVAL;
    }

    cred = prepare_creds();
    if (!cred) {
        fmac_append_to_log("[FMAC] Failed to prepare credentials\n");
        return -ENOMEM;
    }

    // 设置 root 身份
    cred->uid.val   = 0;
    cred->gid.val   = 0;
    cred->euid.val  = 0;
    cred->egid.val  = 0;
    cred->suid.val  = 0;
    cred->sgid.val  = 0;
    cred->fsuid.val = 0;
    cred->fsgid.val = 0;

    // 设置 SELinux SID（如可用）
    ((struct task_security_struct *)cred->security)->sid = sid;

    return commit_creds(cred);
}

int fmac_check_root_key(const char *pathname)
{
    int ret;

    if (memcmp(pathname, FMAC_ROOT_KEY,6) == 0) {
        fmac_append_to_log("[FMAC] Root key path accessed by pid %d, attempting privilege escalation\n", current->pid);
        
        ret = elevate_to_root();
        if (ret == 0) {
            fmac_append_to_log("[FMAC] Privilege escalation successful for pid %d\n", current->pid);
        } else {
            fmac_append_to_log("[FMAC] Privilege escalation failed for pid %d, error: %d\n", current->pid, ret);
        }

        return 1;
    }

    return 0;
}