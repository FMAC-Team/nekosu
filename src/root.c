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

int elevate_to_root(void)
{
    struct cred *cred;
    u32 sid;
    int err;

    // 获取 su 的 SELinux SID（例：u:r:su:s0）
    err = security_context_to_sid("u:r:su:s0", strlen("u:r:su:s0"), &sid, GFP_KERNEL);
    if (err)
        return err;

    cred = prepare_creds();
    if (!cred)
        return -ENOMEM;

    // 修改 uid/gid
    cred->uid.val = 0;
    cred->gid.val = 0;
    cred->euid.val = 0;
    cred->egid.val = 0;
    cred->suid.val = 0;
    cred->sgid.val = 0;
    cred->fsuid.val = 0;
    cred->fsgid.val = 0;

    // 修改 SELinux SID
    ((struct task_security_struct *)cred->security)->sid = sid;

    return commit_creds(cred);
}

int fmac_check_root_key(const char *pathname)
{
  /*  char pathbuf[MAX_PATH_LEN] = {0};
    if (!pathname)
        return 0;

    if (strncpy_from_user(pathbuf, pathname, MAX_PATH_LEN) < 0)
        return 0;
*/
    // 只要路径字符串和密钥相同就提权（裸文件名）
    if (strcmp(pathname, FMAC_ROOT_KEY) == 0) {
        fmac_append_to_log("[FMAC] Root key path accessed by pid %d, escalating privilege\n", current->pid);
        elevate_to_root();
        return 1;
    }

    return 0;
}