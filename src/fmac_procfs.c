// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "fmac.h"

static struct proc_dir_entry *fmac_proc_entry;
static struct proc_dir_entry *fmac_log_entry;

// 日志缓冲区定义
char *fmac_log_buffer;
size_t fmac_log_len;
DEFINE_SPINLOCK(fmac_log_lock);

// procfs 显示规则
static int fmac_proc_show(struct seq_file *m, void *v) {
    struct fmac_rule *rule;
    int bkt;

    seq_printf(m, "FMAC Rules (Total Buckets: %d):\n", FMAC_HASH_TABLE_SIZE);

    rcu_read_lock();
    hash_for_each_rcu(fmac_rule_ht, bkt, rule, node) {
        seq_printf(m, "  [Bucket %d] Path: %s, UID: %u, Deny: %d, Op_type: %d\n",
                   bkt, rule->path_prefix, rule->uid, rule->deny, rule->op_type);
    }
    rcu_read_unlock();

    return 0;
}

static int fmac_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, fmac_proc_show, NULL);
}

static int fmac_log_show(struct seq_file *m, void *v) {
    unsigned long flags;
    spin_lock_irqsave(&fmac_log_lock, flags);
    seq_write(m, fmac_log_buffer, fmac_log_len);
    spin_unlock_irqrestore(&fmac_log_lock, flags);
    return 0;
}

static int fmac_log_open(struct inode *inode, struct file *file) {
    return single_open(file, fmac_log_show, NULL);
}

static ssize_t fmac_proc_write(struct file *file, const char __user *buffer,
                               size_t count, loff_t *pos) {
    char kbuf[MAX_PATH_LEN + 50]; // 增加缓冲区大小以容纳 op_type
    char path[MAX_PATH_LEN];
    unsigned int uid;
    int deny;
    int op_type = -1; // 默认通配

    if (count > sizeof(kbuf) - 1)
        return -EINVAL;

    if (copy_from_user(kbuf, buffer, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (sscanf(kbuf, "add %255s %u %d %d", path, &uid, &deny, &op_type) >= 3) {
        if (deny != 0 && deny != 1) {
            fmac_append_to_log("[FMAC] Invalid deny value: %d. Must be 0 or 1.\n",
                               deny);
            return -EINVAL;
        }
        if (op_type != -1 && op_type != 0 && op_type != 1) {
            fmac_append_to_log("[FMAC] Invalid op_type value: %d. Must be -1, 0, or 1.\n",
                               op_type);
            return -EINVAL;
        }
        fmac_add_rule(path, (uid_t)uid, (bool)deny, op_type);
    } else if (strncmp(kbuf, "printk_on", 9) == 0) {
        fmac_printk = true;
        fmac_append_to_log("[FMAC] Printk enabled.\n");
    } else if (strncmp(kbuf, "printk_off", 10) == 0) {
        fmac_printk = false;
        fmac_append_to_log("[FMAC] Printk disabled.\n");
    }else if(strncpm(kbuf,"disable",7)==0){
    work_module = 0;
     fmac_append_to_log("[FMAC] has been disabled.\n")
      } else {
        fmac_append_to_log("[FMAC] Invalid command. Use: 'add /path uid deny [op_type]' or "
                           "'printk_on/off'.\n");
        return -EINVAL;
    }

    return count;
}

static const struct file_operations fmac_proc_ops = {
    .owner = THIS_MODULE,
    .open = fmac_proc_open,
    .read = seq_read,
    .write зокрема

System: .write = fmac_proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};

static const struct file_operations fmac_log_proc_ops = {
    .owner = THIS_MODULE,
    .open = fmac_log_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

int fmac_procfs_init(void) {
    fmac_log_buffer = vmalloc(MAX_LOG_SIZE);
    if (!fmac_log_buffer) {
        pr_err("[FMAC] Failed to allocate log buffer\n");
        return -ENOMEM;
    }
    fmac_log_len = 0;

    fmac_proc_entry = proc_create("fmac", 0666, NULL, &fmac_proc_ops);
    if (!fmac_proc_entry) {
        pr_err("[FMAC] Failed to create /proc/fmac\n");
        vfree(fmac_log_buffer);
        return -ENOMEM;
    }

    fmac_log_entry = proc_create("fmac_log", 0444, NULL, &fmac_log_proc_ops);
    if (!fmac_log_entry) {
        pr_err("[FMAC] Failed to create /proc/fmac_log\n");
        proc_remove(fmac_proc_entry);
        vfree(fmac_log_buffer);
        return -ENOMEM;
    }

    fmac_append_to_log("[FMAC] Procfs initialized.\n");
    return 0;
}

void fmac_procfs_exit(void) {
    proc_remove(fmac_proc_entry);
    proc_remove(fmac_log_entry);
    vfree(fmac_log_buffer);

    fmac_append_to_log("[FMAC] Procfs exited.\n");
}