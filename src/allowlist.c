// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/xarray.h>
#include <fmac.h>

DEFINE_XARRAY(fmac_uid_xa);

bool fmac_uid_allowed(void)
{
    kuid_t uid = current_uid();
    return xa_load(&fmac_uid_xa, __kuid_val(uid)) != NULL;
}

static int fmac_uids_show(struct seq_file *m, void *v)
{
    unsigned long id;
    void *entry;
    bool first = true;

    xa_for_each(&fmac_uid_xa, id, entry)
    {
        seq_printf(m, "%s%lu", first ? "" : ",", id);
        first = false;
    }

    if (!first)
    {
        seq_puts(m, "\n");
    }

    return 0;
}

static int fmac_uid_open(struct inode *inode, struct file *file)
{
    return single_open(file, fmac_uids_show, NULL);
}

static ssize_t proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char *kbuf, *tok, *p;

    if (count == 0 || count > 1024)
    {
        return -EINVAL;
    }

    kbuf = memdup_user_nul(buf, count);
    if (IS_ERR(kbuf))
    {
        return PTR_ERR(kbuf);
    }

    tok = strstrip(kbuf);

    while ((p = strsep(&tok, ",")) != NULL)
    {
        unsigned int id;
        kuid_t uid;

        if (*p == '\0')
        {
            continue;
        }

        if (kstrtouint(p, 10, &id) < 0)
        {
            continue;
        }

        uid = make_kuid(&init_user_ns, id);
        if (!uid_valid(uid))
        {
            continue;
        }

        xa_store(&fmac_uid_xa, id, xa_mk_value(id), GFP_KERNEL);
    }

    kfree(kbuf);
    return count;
}

#ifdef FMAC_USE_PROC_OPS
static const struct proc_ops fmac_uid_proc_ops = {
    .proc_open = fmac_uid_open,
    .proc_read = seq_read,
    .proc_write = proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations fmac_uid_proc_ops = {
    .owner = THIS_MODULE,
    .open = fmac_uid_open,
    .read = seq_read,
    .write = proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

int fmac_uid_proc_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create("uids", 0600, fmac_proc_dir, &fmac_uid_proc_ops);
    if (!entry)
    {
        return -ENOMEM;
    }

    xa_store(&fmac_uid_xa, 2000, xa_mk_value(2000), GFP_KERNEL);

    return 0;
}

void fmac_uid_proc_exit(void)
{
    remove_proc_entry("uids", fmac_proc_dir);
    xa_destroy(&fmac_uid_xa);
}
