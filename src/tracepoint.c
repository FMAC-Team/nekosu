// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <trace/events/syscalls.h>

#include <fmac.h>

static void fmac_sys_enter_prctl(void *data, struct pt_regs *regs, long id)
{
    int auth_ret;
    unsigned long args[6], option, arg2, arg3;
    // ARM64 prctl syscall ID = 167
    if (id != 167)
    {
        return;
    }

    syscall_get_arguments(current, regs, args);

    /*
     * in sys_enter ：
     * arg0 (option) = regs->regs[0]
     * arg1 (arg2)   = regs->regs[1]
     */

#if defined(CONFIG_ARM64)
    if (id != 167) /* __NR_prctl */
        return;
#elif defined(CONFIG_X86_64)
    if (id != 157) /* __NR_prctl */
        return;
#endif

    option = args[0];
    arg2 = args[1];
    arg3 = args[2];

    // option = regs->regs[0];
    //   arg2 = regs->regs[1];
    //  arg3 = regs->regs[2]; // user space lenght

    if (option == CODE_AUTH)
    {
        f_log("Tracepoint: prctl detected! option=0x%lx, arg2=0x%lx\n", option, arg2);
        auth_ret = check_totp_ecc((const char __user *)arg2, arg3);

        if (auth_ret == 1)
        {
            f_log("FMAC: >>> AUTH SUCCESS <<<\n");
            elevate_to_root();
        }
    }
}

int fmac_hook_init(void)
{
    int ret;

    ret = register_trace_sys_enter(fmac_sys_enter_prctl, NULL);
    if (ret)
    {
        pr_err("FMAC: Failed to register sys_enter tracepoint\n");
        return ret;
    }

    pr_info("FMAC: Tracepoint hook on sys_enter registered\n");
    return 0;
}

void fmac_hook_exit(void)
{
    unregister_trace_sys_enter(fmac_sys_enter_prctl, NULL);
    tracepoint_synchronize_unregister();
}
