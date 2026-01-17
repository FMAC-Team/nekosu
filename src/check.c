// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <fmac.h>

static bool fmac_check_access(const char *path, uid_t uid, int op_type)
{
    struct fmac_rule *rule;
    bool deny = false;
    u32 key;

    char norm_path[MAX_PATH_LEN];
    size_t path_len = strscpy(norm_path, path, MAX_PATH_LEN);

    while (path_len > 1 && norm_path[path_len - 1] == '/')
        norm_path[--path_len] = '\0';

    key = jhash(norm_path, path_len, 0);

    rcu_read_lock();
    hash_for_each_possible_rcu(fmac_rule_ht, rule, node, key)
    {
        if (rule->uid != 0 && rule->uid != uid)
        {
            continue;
        }

        if (rule->op_type != -1 && rule->op_type != op_type)
        {
            continue;
        }

        if (rule->path_len == path_len && strncmp(norm_path, rule->path_prefix, path_len) == 0)
        {
            deny = rule->deny;
            break;
        }
    }
    rcu_read_unlock();

    return deny;
}

static int __fmac_check_path(const char __user *pathname, int op_type, const char *op_name)
{
    char path[MAX_PATH_LEN] = {0};
    uid_t uid = current_euid().val;

    if (!pathname)
    {
        return -EINVAL;
    }

    if (strncpy_from_user(path, pathname, MAX_PATH_LEN) < 0)
    {
        return -EFAULT;
    }

    if (fmac_check_access(path, uid, op_type))
    {
        if (fmac_printk)
        {
            f_log("Denied %s: %s by UID %u (pid %d)\n", op_name, path, uid, current->pid);
        }
        return -EACCES;
    }

    return 0;
}

int fmac_check_mkdirat(const char __user *pathname)
{
    return __fmac_check_path(pathname, FMAC_OP_MKDIRAT, "mkdirat");
}

int fmac_check_openat(const char __user *pathname)
{
    return __fmac_check_path(pathname, FMAC_OP_OPENAT, "openat");
}