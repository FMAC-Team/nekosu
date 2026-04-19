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
	 .exit = selinux_exit,
	  },
	{
	 .name = "Anonymous FD",
	 .init = fmac_anonfd_init,
	 .exit = fmac_anonfd_exit,
	  },
	{
	 .name = "UID Capabilities",
	 .init = uid_caps_init,
	 .exit = uid_caps_exit,
	  },
	  {
	  .name = "task mark",
	  .init = nksu_task_mark_init,
	  .exit = nksu_task_mark_exit,
	  },
	{
	 .name = "tracepoint hook",
	 .init = load_tracepoint_hook,
	 .exit = unload_tracepoint_hook,
	  },
	{
	 .name = "manager scan",
	 .init = appscan_init,
	 .exit = NULL,
	  },
};

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

	pr_info("All components initialized successfully\n");
	return 0;
}

static void nekosu_cleanup_all_components(void)
{
	nekosu_cleanup_components(core_components, CORE_COMPONENTS_COUNT);

	pr_info("All components cleaned up\n");
}

static int __init nekosu_init(void)
{
	int ret;

	pr_info("Loading nekosu module...\n");
	
#ifdef CONFIG_NKSU_DEBUG
	pr_alert("The current build is in debug mode, and security may be compromised.\n");
#endif
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
