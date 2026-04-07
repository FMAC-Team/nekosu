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

static int __init nekosu_init(void)
{
	int ret;

	ret = init_selinux_hook();
	if (ret) {
		pr_err("failed to initialize SELinux\n");
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
		ret = uid_caps_init();
	if (ret) {
		pr_err("Failed to load caplist\n");
		return ret;
	}
	ret = fmac_hook_init();
	if (ret) {
		pr_err("Failed to initialize kprobe hook\n");
		return ret;
	}
#if IS_ENABLED(CONFIG_FMAC_SYSCALL) 
	ret = syscalltable_init();
	if (ret) {
		pr_err("Failed to initialize syscalltable\n");
		return ret;
	}
#endif
	ret = load_hijack_hook();
	if (ret) {
		pr_err("Failed to initialize hijack\n");
		return ret;
	}
#if IS_ENABLED(CONFIG_FMAC_SYSCALL) 
		ret = fmac_init()
		    if (ret) {
			pr_err("Failed to load fmac\n");
			return ret;
		}
#endif
	return 0;
}

static void __exit nekosu_exit(void)
{
	fmac_anonfd_exit();
	cleanup_totp_crypto();
	uid_caps_exit();
	fmac_hook_exit();
#if IS_ENABLED(CONFIG_FMAC_SYSCALL) 
	syscalltable_exit();
#endif
	unload_hijack_hook();
}

module_init(nekosu_init);
module_exit(nekosu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aqnya");
MODULE_DESCRIPTION("nekosu");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
