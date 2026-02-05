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

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long args[6], option, arg2, arg3, arg4;
    int fd;
    struct nksu_reply reply = {
        .fd = fd,
        .version = NKSU_API_VERSION,
        .flags = 0,
    };

    syscall_get_arguments(current, regs, args);

    option = args[0];
    arg2 = args[1];
    arg3 = args[2];
    arg4 = args[3];

    if (option != AU_MANAGER)
        return 0;

    fmac_log("prctl hit: option=0x%lx arg2=0x%lx arg3=0x%lx\n", option, arg2, arg3);

    if (check_totp_ecc((const char __user *)arg2, arg3) != 1)
        return 0;

    if (!access_ok((void __user *)arg3, sizeof(struct nksu_reply)))
    {
        fmac_log("invalid user pointer: %lx\n", arg3);
        return 0;
    }

    fd = fmac_anonfd_get();
    if (fd < 0)
        return 0;

    if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)) == 0)
    {

        fmac_log("fmac fd %d delivered via copy_to_user\n", fd);
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__arm64_sys_prctl",
    .pre_handler = handler_pre,
};

int fmac_kprobe_hook_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0)
    {
        fmac_log("register_kprobe failed: %d\n", ret);
        return ret;
    }

    fmac_log("kprobe registered at %p (%s)\n", kp.addr, kp.symbol_name);
    return 0;
}

void fmac_hook_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}