// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "fmac.h"

#define MAX_UIDS 128

static DEFINE_MUTEX(fmac_uid_mutex);
static kuid_t *fmac_uid_list;
static size_t fmac_uid_count;

bool fmac_uid_allowed(void)
{
    size_t i;
    kuid_t uid = current_uid();

    mutex_lock(&fmac_uid_mutex);
    for (i = 0; i < fmac_uid_count; i++) {
        if (uid_eq(fmac_uid_list[i], uid)) {
            mutex_unlock(&fmac_uid_mutex);
            return true;
        }
    }
    mutex_unlock(&fmac_uid_mutex);
    return false;
}

static ssize_t proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    char *kbuf;
    size_t i, len = 0;
    ssize_t ret = 0;

    kbuf = kzalloc(1024, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mutex_lock(&fmac_uid_mutex);
    for (i = 0; i < fmac_uid_count; i++) {
        len += scnprintf(kbuf + len, 1024 - len, "%u%c", __kuid_val(fmac_uid_list[i]),
                         i == fmac_uid_count - 1 ? '\n' : ',');
    }
    mutex_unlock(&fmac_uid_mutex);

    ret = simple_read_from_buffer(buf, count, ppos, kbuf, len);
    kfree(kbuf);
    return ret;
}

static ssize_t proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char *kbuf, *tok, *p;
    size_t i;

    if (count == 0 || count > 1024)
        return -EINVAL;

    kbuf = memdup_user_nul(buf, count);
    if (IS_ERR(kbuf))
        return PTR_ERR(kbuf);

    tok = strstrip(kbuf);

    mutex_lock(&fmac_uid_mutex);

    while ((p = strsep(&tok, ",")) != NULL) {
        unsigned int id;
        kuid_t uid;
        bool exists = false;

        if (*p == '\0')
            continue;

        if (kstrtouint(p, 10, &id) < 0)
            continue;

        uid = make_kuid(&init_user_ns, id);
        if (!uid_valid(uid))
            continue;

        for (i = 0; i < fmac_uid_count; i++) {
            if (uid_eq(fmac_uid_list[i], uid)) {
                exists = true;
                break;
            }
        }

        if (exists)
            continue;

        if (fmac_uid_count < MAX_UIDS) {
            fmac_uid_list[fmac_uid_count++] = uid;
        } else {
            break;
        }
    }

    mutex_unlock(&fmac_uid_mutex);
    kfree(kbuf);
    return count;
}

#ifdef FMAC_USE_PROC_OPS
static const struct proc_ops fmac_uid_proc_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};
#else
static const struct file_operations fmac_uid_proc_ops = {
    .owner = THIS_MODULE,
    .read = proc_read,
    .write = proc_write,
};
#endif

int fmac_uid_proc_init(void)
{
    proc_create("uids", 0600, fmac_proc_dir, &fmac_uid_proc_ops);

    mutex_lock(&fmac_uid_mutex);

    if (!fmac_uid_list) {
        fmac_uid_list = kzalloc(sizeof(kuid_t) * MAX_UIDS, GFP_KERNEL);
        if (!fmac_uid_list) {
            mutex_unlock(&fmac_uid_mutex);
            remove_proc_entry("uids", fmac_proc_dir);
            return -ENOMEM;
        }
    }

    fmac_uid_list[0] = make_kuid(&init_user_ns, 2000);
    fmac_uid_count = 1;

    mutex_unlock(&fmac_uid_mutex);

    return 0;
}

void fmac_uid_proc_exit(void)
{
    remove_proc_entry("uids", fmac_proc_dir);
    mutex_lock(&fmac_uid_mutex);
    kfree(fmac_uid_list);
    fmac_uid_list = NULL;
    fmac_uid_count = 0;
    mutex_unlock(&fmac_uid_mutex);
}