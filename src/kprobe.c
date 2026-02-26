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

struct fmac_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static void fmac_fd_tw_func(struct callback_head *cb)
{
	struct fmac_fd_tw *tw = container_of(cb, struct fmac_fd_tw, cb);
	int fd;
	struct file *file;

	file = fmac_anonfd_get();
	if (IS_ERR(file)) {
		pr_err("fmac: failed to get anon file\n");
		goto out;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		goto out;
	}

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("copy fd err");
		put_unused_fd(fd);
		fput(file);
	} else {
		fd_install(fd, file);
		pr_info("fmac fd %d delivered safely\n", fd);
	}

out:
	kfree(tw);
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
//      int fd;
	unsigned long option, arg2, arg3;
	struct pt_regs *real_regs;
	struct fmac_fd_tw *tw;

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

	pr_info("prctl hit: option=0x%lx arg2=%lu arg3=0x%lx\n", option,
		arg2, arg3);

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->outp = (int __user *)arg3;
	tw->cb.func = fmac_fd_tw_func;
	
	// direct install fd will ramoops

	if (task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		pr_warn("task_work_add failed\n");
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
