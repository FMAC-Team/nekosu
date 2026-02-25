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
struct proc_dir_entry *fmac_proc_dir;

static int fmac_proc_show(struct seq_file *m, void *v)
{
	struct fmac_rule *rule;
	int bkt;

	seq_printf(m, "FMAC Rules (Total Buckets: %d):\n",
		   FMAC_HASH_TABLE_SIZE);

	rcu_read_lock();
	hash_for_each_rcu(fmac_rule_ht, bkt, rule, node) {
		seq_printf(m,
			   "  [Bucket %d] Path: %s, UID: %u, Deny: %d, Op_type: %d\n",
			   bkt, rule->path_prefix, rule->uid, rule->deny,
			   rule->op_type);
	}
	rcu_read_unlock();

	return 0;
}

static int fmac_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, fmac_proc_show, NULL);
}

static ssize_t fmac_proc_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *pos)
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

	if (sscanf(kbuf, "add %255s %u %d %d", path, &uid, &deny, &op_type) >=
	    3) {
		if (deny != 0 && deny != 1) {
			pr_info("Invalid deny value: %d. Must be 0 or 1.\n",
				deny);
			return -EINVAL;
		}
		if (op_type != -1 && op_type != 0 && op_type != 1) {
			pr_info
			    ("Invalid op_type value: %d. Must be -1, 0, or 1.\n",
			     op_type);
			return -EINVAL;
		}
		fmac_add_rule(path, (uid_t) uid, (bool)deny, op_type);
	} else if (strncmp(kbuf, "disable", 7) == 0) {
		work_module = 0;
		pr_info("has been disabled.\n");
	} else {
		pr_info("Invalid command. Use: 'add /path uid deny [op_type]', "
			"'printk_on/off', or 'disable'.\n");
		return -EINVAL;
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops fmac_proc_ops = {
	.proc_open = fmac_proc_open,
	.proc_read = seq_read,
	.proc_write = fmac_proc_write,
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
#endif

int fmac_procfs_init(void)
{

	fmac_proc_dir = proc_mkdir("fmac", NULL);
	if (!fmac_proc_dir) {
		pr_err("Failed to create /proc/fmac directory\n");
		fmac_procfs_exit();
		return -ENOMEM;
	}

	fmac_proc_entry =
	    proc_create("rules", 0600, fmac_proc_dir, &fmac_proc_ops);
	if (!fmac_proc_entry) {
		pr_err("Failed to create /proc/fmac\n");
		fmac_procfs_exit();
		return -ENOMEM;
	}

	fmac_uid_proc_init();
	pr_info("Procfs initialized.\n");
	return 0;
}

void fmac_procfs_exit(void)
{
	if (fmac_proc_dir) {
		if (fmac_proc_entry) {
			remove_proc_entry("rules", fmac_proc_dir);
			fmac_proc_entry = NULL;
		}

		remove_proc_entry("fmac", NULL);
		fmac_proc_dir = NULL;
	}
#ifdef FMAC_ROOT
	fmac_uid_proc_exit();
#endif
	pr_info("Procfs removed.\n");
}
