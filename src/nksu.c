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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aqnya");
MODULE_DESCRIPTION("nekosu");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

typedef struct {
	const char *name;
	int (*init)(void);
	void (*exit)(void);
} module_component_t;

static const module_component_t core_components[] = {
	{
	 .name = "SELinux Hook",
	 .init = init_selinux_hook,
	 .exit = NULL,
	  },
	{
	 .name = "Anonymous FD",
	 .init = fmac_anonfd_init,
	 .exit = fmac_anonfd_exit,
	  },
	{
	 .name = "TOTP Crypto",
	 .init = init_totp_crypto,
	 .exit = cleanup_totp_crypto,
	  },
	{
	 .name = "UID Capabilities",
	 .init = uid_caps_init,
	 .exit = uid_caps_exit,
	  },
	/*
	   {
	   .name = "FMAC Hook",
	   .init = fmac_hook_init,
	   .exit = fmac_hook_exit,
	   }, */
	{
	 .name = "Hijack Hook",
	 .init = load_hijack_hook,
	 .exit = unload_hijack_hook,
	  },
	{
	 .name = "manager scan",
	 .init = appscan_init,
	 .exit = NULL,
	  },
};

#if IS_ENABLED(CONFIG_FMAC_SYSCALL)
static const module_component_t syscall_components[] = {
	{
	 .name = "Syscall Table",
	 .init = syscalltable_init,
	 .exit = syscalltable_exit,
	  },
	{
	 .name = "FMAC Core",
	 .init = fmac_init,
	 .exit = NULL,
	  },
};

#define SYSCALL_COMPONENTS_COUNT ARRAY_SIZE(syscall_components)
#else
#define SYSCALL_COMPONENTS_COUNT 0
#endif

#define CORE_COMPONENTS_COUNT ARRAY_SIZE(core_components)

static int nekosu_init_component(const module_component_t *comp, int index)
{
	int ret;

	if (!comp->init) {
		pr_debug("Skipping %s (no init function)\n", comp->name);
		return 0;
	}

	pr_info("Initializing %s...\n", comp->name);
	ret = comp->init();
	if (ret) {
		pr_err("Failed to initialize %s: %d\n", comp->name, ret);
		return ret;
	}

	pr_debug("%s initialized successfully (index: %d)\n", comp->name,
		 index);
	return 0;
}

static void nekosu_cleanup_components(const module_component_t *comps,
				      int count)
{
	int i;
	for (i = count - 1; i >= 0; i--) {
		if (comps[i].exit) {
			pr_debug("Cleaning up %s...\n", comps[i].name);
			comps[i].exit();
		}
	}
}

static int nekosu_init_all_components(void)
{
	int ret, i;
	for (i = 0; i < CORE_COMPONENTS_COUNT; i++) {
		ret = nekosu_init_component(&core_components[i], i);
		if (ret) {
			nekosu_cleanup_components(core_components, i);
			return ret;
		}
	}

#if IS_ENABLED(CONFIG_FMAC_SYSCALL)
	for (i = 0; i < SYSCALL_COMPONENTS_COUNT; i++) {
		ret = nekosu_init_component(&syscall_components[i], i);
		if (ret) {
			nekosu_cleanup_components(syscall_components, i);
			nekosu_cleanup_components(core_components,
						  CORE_COMPONENTS_COUNT);
			return ret;
		}
	}
#endif

	pr_info("All components initialized successfully\n");
	return 0;
}

static void nekosu_cleanup_all_components(void)
{
#if IS_ENABLED(CONFIG_FMAC_SYSCALL)
	nekosu_cleanup_components(syscall_components, SYSCALL_COMPONENTS_COUNT);
#endif
	nekosu_cleanup_components(core_components, CORE_COMPONENTS_COUNT);

	pr_info("All components cleaned up\n");
}

static int __init nekosu_init(void)
{
	int ret;

	pr_info("Loading nekosu module...\n");

	ret = nekosu_init_all_components();
	if (ret) {
		pr_err("Failed to initialize nekosu: %d\n", ret);
		return ret;
	}

	pr_info("nekosu module loaded successfully\n");
	return 0;
}

static void __exit nekosu_exit(void)
{
	pr_info("Unloading nekosu module...\n");

	nekosu_cleanup_all_components();

	pr_info("nekosu module unloaded\n");
}

module_init(nekosu_init);
module_exit(nekosu_exit);
