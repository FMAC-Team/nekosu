// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <fmac.h>

DEFINE_HASHTABLE(fmac_rule_ht, FMAC_HASH_BITS);
DEFINE_SPINLOCK(fmac_lock);
int work_module = 1;

static void fmac_rule_free_rcu(struct rcu_head *head)
{
	struct fmac_rule *rule = container_of(head, struct fmac_rule, rcu);
	kfree(rule);
}

static int __init fmac_init(void)
{
	int ret;
	hash_init(fmac_rule_ht);

	ret = init_selinux_hook();
	if (ret) {
		pr_err("failed to initialize SELinux\n");
		return ret;
	}

	ret = fmac_procfs_init();
	if (ret) {
		pr_err("Failed to initialize procfs\n");
		return ret;
	}
	ret = fmac_anonfd_init();
	if (ret) {
		pr_err("Failed to initialize anonfd\n");
		return ret;
	}
	ret = init_totp_crypto();
	if (ret) {
		pr_err("Failed to initialize crypto\n");
		return ret;
	}
	ret = fmac_hook_init();
	if (ret) {
		pr_err("Failed to initialize kprobe hook\n");
		return ret;
	}
	ret = syscalltable_init();
	if (ret) {
		pr_err("Failed to initialize syscalltable\n");
		return ret;
	}

	ret = load_hijack_hook();
	if (ret) {
		pr_err("Failed to initialize hijack\n");
		return ret;
	}
	return 0;
}

static void __exit fmac_exit(void)
{
	struct fmac_rule *rule;
	struct hlist_node *tmp;
	int bkt;

	fmac_anonfd_exit();
	cleanup_totp_crypto();
	fmac_hook_exit();
	syscalltable_exit();

	fmac_procfs_exit();

	spin_lock(&fmac_lock);
	hash_for_each_safe(fmac_rule_ht, bkt, tmp, rule, node) {
		hash_del_rcu(&rule->node);
		call_rcu(&rule->rcu, fmac_rule_free_rcu);
	}
	spin_unlock(&fmac_lock);

	synchronize_rcu();

	pr_info("File Monitoring and Access Control exited.\n");
}

module_init(fmac_init);
module_exit(fmac_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aqnya");
MODULE_DESCRIPTION("nekosu");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
