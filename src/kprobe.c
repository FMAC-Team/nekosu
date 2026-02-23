// SPDX-License-Identifier: GPL-3.0-or-later
/*
 FMAC - File Monitoring and Access Control Kernel Module
 Copyright (C) 2025 Aqnya
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <asm/syscall.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <fmac.h>

struct {
	int authenticate;
	int get_root;
} const opcode = { 1, 2 };

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	int fd;
#ifdef CONFIG_X86_64
	unsigned long option = regs->di;
	unsigned long arg2 = regs->si;
	unsigned long arg3 = regs->dx;
#elif defined(CONFIG_ARM64)
	unsigned long option = regs->regs[0];
	unsigned long arg2 = regs->regs[1];
	unsigned long arg3 = regs->regs[2];
#else
#error Unsupported architecture
#endif

	if (option != 201)
		return 0;

	if (!access_ok((void __user *)arg3, sizeof(int)))
		return 0;

	pr_alert("prctl hit: option=0x%lx arg2=0x%lx arg3=0x%lx\n", option, arg2,
		arg3);

	if (check(arg2) == false)
		return 0;

	fd = fmac_anonfd_get();
	if (fd < 0)
		return 0;

	if (copy_to_user((int __user *)arg3, &fd, sizeof(fd)) == 0)
		pr_alert("fmac fd %d delivered via copy_to_user\n", fd);

	return 0;
}

static struct kprobe kp = {
	.symbol_name = "__arm64_sys_prctl",
	.pre_handler = handler_pre,
};

int fmac_hook_init(void)
{
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed: %d\n", ret);
		return ret;
	}

	pr_alert("kprobe registered at %p (%s)\n", kp.addr, kp.symbol_name);
	return 0;
}

void fmac_hook_exit(void)
{
	unregister_kprobe(&kp);
	pr_alert("kprobe at %p unregistered\n", kp.addr);
}
