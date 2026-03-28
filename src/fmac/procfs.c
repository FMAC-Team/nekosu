// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <fmac.h>

int fmac_procfs_init(void)
{

	fmac_proc_dir = proc_mkdir("fmac", NULL);
	if (!fmac_proc_dir) {
		pr_err("Failed to create /proc/fmac directory\n");
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
		remove_proc_entry("fmac", NULL);
		fmac_proc_dir = NULL;
	}
#ifdef FMAC_ROOT
	fmac_uid_proc_exit();
#endif
	pr_info("Procfs removed.\n");
}
