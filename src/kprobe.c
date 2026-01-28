// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
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

static char *shared_buffer;
#define SHM_SIZE PAGE_SIZE

static int anon_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;

    if (!shared_buffer)
    {
        return -ENODEV;
    }

    if (size > SHM_SIZE)
    {
        return -EINVAL;
    }
    return remap_vmalloc_range(vma, shared_buffer, 0);
}

static const struct file_operations anon_fops = {
    .owner = THIS_MODULE,
    .mmap = anon_mmap,
};

static int handler_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long args[6], option, arg2, arg3;

    syscall_get_arguments(current, regs, args);

    option = args[0];
    arg2 = args[1];
    arg3 = args[2];

    if (option == AU_MANAGER)
    {
        f_log("kprobe hit prctl! option=0x%lx, arg2=0x%lx\n", option, arg2);

        if (check_totp_ecc((const char __user *)arg2, arg3) == 1)
        {
            int fd = anon_inode_getfd("[fmac_shm]", &anon_fops, NULL, O_RDWR | O_CLOEXEC);
            if (fd >= 0)
            {
                f_log("returning fd %d\n", fd);
                regs_set_return_value(regs, (unsigned long)fd);
            }
        }
    }

    return 0;
}

static struct kretprobe kp = {
    .kp.symbol_name = "__arm64_sys_prctl",
    .handler = handler_ret,
    .maxactive = 20,
};

int fmac_kprobe_hook_init(void)
{
    int ret;
    shared_buffer = vmalloc_user(SHM_SIZE);
    if (!shared_buffer)
    {
        return -ENOMEM;
    }
    ret = register_kretprobe(&kp);
    if (ret < 0)
    {
        vfree(shared_buffer);
        f_log("register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    f_log("kprobe registered at %p (%s)\n", kp.kp.addr, kp.kp.symbol_name);
    return 0;
}

void fmac_hook_exit(void)
{
    unregister_kretprobe(&kp);
    if (shared_buffer)
    {
        vfree(shared_buffer);
    }
    pr_info("kprobe at %p unregistered\n", kp.kp.addr);
}