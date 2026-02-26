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
	unsigned long option, arg2, arg3;
	struct pt_regs *real_regs;

#if defined(__aarch64__)
	real_regs = (struct pt_regs *)regs->regs[0];
#elif defined(__x86_64__)
	real_regs = (struct pt_regs *)regs->di;
#else
	return 0;
#endif

	if (!real_regs)
		return 0;

#if defined(__aarch64__)
	option = real_regs->regs[0];
	arg2 = real_regs->regs[1];
	arg3 = real_regs->regs[2];
#elif defined(__x86_64__)
	option = real_regs->di;
	arg2 = real_regs->si;
	arg3 = real_regs->dx;
#endif

	if ((int)option != 201) {
		return 0;
	}

	if (!access_ok((void __user *)arg3, sizeof(int)))
		return 0;

	pr_info("prctl hit: option=0x%lx arg2=%d arg3=0x%lx\n", option,
		 arg2, arg3);

	if (check((int)arg2) == false) {
		pr_err("check failed\n");
		return 0;
	}

	fd = fmac_anonfd_get();
	if (fd < 0)
		return 0;

	if (copy_to_user((int __user *)arg3, &fd, sizeof(fd)) == 0)
		pr_info("fmac fd %d delivered via copy_to_user\n", fd);

	return 0;
}

static struct kprobe kp = {
#if defined(__aarch64__)
	.symbol_name = "__arm64_sys_prctl",
#elif defined(__x86_64__)
	.symbol_name = "__x64_sys_prctl",
#endif
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

	pr_info("kprobe registered at %p (%s)\n", kp.addr, kp.symbol_name);
	return 0;
}

void fmac_hook_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}
