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

static DEFINE_XARRAY(fmac_uid_xa);

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

	xa_for_each(&fmac_uid_xa, id, entry) {
		seq_printf(m, "%s%lu", first ? "" : ",", id);
		first = false;
	}

	if (!first)
		seq_puts(m, "\n");

	return 0;
}

static int fmac_uid_open(struct inode *inode, struct file *file)
{
	return single_open(file, fmac_uids_show, NULL);
}

static ssize_t proc_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
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

int nksu_add_uid(void)
{
	kuid_t uid = current_uid();
	unsigned long id = __kuid_val(uid);

	void *old = xa_store(&fmac_uid_xa, id, xa_mk_value(id), GFP_KERNEL);

	if (xa_is_err(old))
		return xa_err(old);

	return 0;
}

int fmac_uid_proc_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create("uids", 0600, fmac_proc_dir, &fmac_uid_proc_ops);
	if (!entry) {
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
