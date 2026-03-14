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
#include <linux/syscalls.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <fmac.h>

static int authenticate(int key, int __user *ufd, int efd)
{
	int fd;
#ifdef CONFIG_FMAC_DEBUG
	pr_info("prctl hit: option=201 arg2=%lu arg3=0x%lx\n", key, ufd);
#endif
	if (fmac_uid_allowed()) {
		goto LOAD;
	}

	if (check((int)key) == false) {
		pr_err("check failed\n");
		return 0;
	}
LOAD:
	if (bind_eventfd(efd))
		return 0;

	fd = fmac_anonfd_get();
	if (fd < 0)
		return 0;

	if (put_user(fd, ufd) != 0) {
		pr_err("copy fd to user failed, closing fd\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
		close_fd(fd);
#else
		ksys_close(fd);
#endif
		return -EFAULT;
	} else {
		pr_info("fmac fd %d delivered via copy_to_user\n", fd);
	}

	notify_user();

	if (nksu_add_uid()) {
		pr_err("failed to save uid");
	}
	return 0;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long option, arg2, arg3, arg4;
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
	arg4 = real_regs->regs[3];
#elif defined(__x86_64__)
	option = real_regs->di;
	arg2 = real_regs->si;
	arg3 = real_regs->dx;
	arg4 = real_regs->cx;
#endif

	if (!access_ok((void __user *)arg3, sizeof(int)))
		return 0;

	switch (option) {
	case 201:
		authenticate((int)arg2, (void __user *)arg3, (int)arg4);
		break;
	case 202:
		if (fmac_uid_allowed()) {
			elevate_to_root();
		}
		break;
	default:
		break;
	}
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
