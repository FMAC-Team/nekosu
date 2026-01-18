// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <fmac.h>

static struct proc_dir_entry *fmac_proc_entry;
static struct proc_dir_entry *fmac_log_entry;
struct proc_dir_entry *fmac_proc_dir;

char *fmac_log_buffer;
size_t fmac_log_len;
DEFINE_SPINLOCK(fmac_log_lock);

static int fmac_proc_show(struct seq_file *m, void *v)
{
    struct fmac_rule *rule;
    int bkt;

    seq_printf(m, "FMAC Rules (Total Buckets: %d):\n", FMAC_HASH_TABLE_SIZE);

    rcu_read_lock();
    hash_for_each_rcu(fmac_rule_ht, bkt, rule, node)
    {
        seq_printf(m, "  [Bucket %d] Path: %s, UID: %u, Deny: %d, Op_type: %d\n", bkt,
                   rule->path_prefix, rule->uid, rule->deny, rule->op_type);
    }
    rcu_read_unlock();

    return 0;
}

static int fmac_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, fmac_proc_show, NULL);
}

static int fmac_log_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    spin_lock_irqsave(&fmac_log_lock, flags);
    seq_write(m, fmac_log_buffer, fmac_log_len);
    spin_unlock_irqrestore(&fmac_log_lock, flags);
    return 0;
}

static int fmac_log_open(struct inode *inode, struct file *file)
{
    return single_open(file, fmac_log_show, NULL);
}

static ssize_t fmac_proc_write(struct file *file, const char __user *buffer, size_t count,
                               loff_t *pos)
{
    char kbuf[MAX_PATH_LEN + 50];
    char path[MAX_PATH_LEN];
    unsigned int uid;
    int deny;
    int op_type = -1;

    if (count > sizeof(kbuf) - 1)
        return -EINVAL;

    if (copy_from_user(kbuf, buffer, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (sscanf(kbuf, "add %255s %u %d %d", path, &uid, &deny, &op_type) >= 3)
    {
        if (deny != 0 && deny != 1)
        {
            f_log("Invalid deny value: %d. Must be 0 or 1.\n", deny);
            return -EINVAL;
        }
        if (op_type != -1 && op_type != 0 && op_type != 1)
        {
            f_log("Invalid op_type value: %d. Must be -1, 0, or 1.\n", op_type);
            return -EINVAL;
        }
        fmac_add_rule(path, (uid_t)uid, (bool)deny, op_type);
    } else if (strncmp(kbuf, "printk_on", 9) == 0)
    {
        fmac_printk = true;
        f_log("Printk enabled.\n");
    } else if (strncmp(kbuf, "printk_off", 10) == 0)
    {
        fmac_printk = false;
        f_log("Printk disabled.\n");
    } else if (strncmp(kbuf, "disable", 7) == 0)
    {
        work_module = 0;
        f_log("has been disabled.\n");
    } else
    {
        f_log("Invalid command. Use: 'add /path uid deny [op_type]', "
              "'printk_on/off', or 'disable'.\n");
        return -EINVAL;
    }

    return count;
}

#ifdef FMAC_USE_PROC_OPS
static const struct proc_ops fmac_proc_ops = {
    .proc_open = fmac_proc_open,
    .proc_read = seq_read,
    .proc_write = fmac_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops fmac_log_proc_ops = {
    .proc_open = fmac_log_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations fmac_proc_ops = {
    .owner = THIS_MODULE,
    .open = fmac_proc_open,
    .read = seq_read,
    .write = fmac_proc_write,
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
#endif

int fmac_procfs_init(void)
{
    fmac_log_buffer = vmalloc(MAX_LOG_SIZE);
    if (!fmac_log_buffer)
    {
        pr_err("Failed to allocate log buffer\n");
        return -ENOMEM;
    }
    fmac_log_len = 0;

    fmac_proc_dir = proc_mkdir("fmac", NULL);
    if (!fmac_proc_dir)
    {
        pr_err("Failed to create /proc/fmac directory\n");
        fmac_procfs_exit();
        return -ENOMEM;
    }

    fmac_proc_entry = proc_create("rules", 0600, fmac_proc_dir, &fmac_proc_ops);
    if (!fmac_proc_entry)
    {
        pr_err("Failed to create /proc/fmac\n");
        fmac_procfs_exit();
        return -ENOMEM;
    }

    fmac_log_entry = proc_create("log", 0400, fmac_proc_dir, &fmac_log_proc_ops);
    if (!fmac_log_entry)
    {
        pr_err("Failed to create /proc/fmac_log\n");
        fmac_procfs_exit();
        return -ENOMEM;
    }
#ifdef CONFIG_FMAC_ROOT
    fmac_uid_proc_init();
#endif
    f_log("Procfs initialized.\n");
    return 0;
}

void fmac_procfs_exit(void)
{
    if (fmac_proc_dir)
    {
        if (fmac_proc_entry)
        {
            remove_proc_entry("rules", fmac_proc_dir);
            fmac_proc_entry = NULL;
        }
        if (fmac_log_entry)
        {
            remove_proc_entry("log", fmac_proc_dir);
            fmac_log_entry = NULL;
        }

        remove_proc_entry("fmac", NULL);
        fmac_proc_dir = NULL;
    }

    if (fmac_log_buffer)
    {
        vfree(fmac_log_buffer);
        fmac_log_buffer = NULL;
        fmac_log_len = 0;
    }
#ifdef FMAC_ROOT
    fmac_uid_proc_exit();
#endif
    pr_info("Procfs removed.\n");
}