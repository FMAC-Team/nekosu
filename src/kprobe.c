#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <asm/syscall.h>

#include <fmac.h>

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long args[6];
    
    syscall_get_arguments(current, regs, args);

    unsigned long option = args[0];
    unsigned long arg2   = args[1];
    unsigned long arg3   = args[2];

    if (option == AUTH_OPTION)
    {
        pr_info("FMAC: Kprobe hit prctl! option=0x%lx, arg2=0x%lx\n", option, arg2);

        if (check_totp_ecc((const char __user *)arg2, arg3) == 1)
        {
            pr_info("FMAC: Authentication Success. Elevating to root...\n");
            elevate_to_root();
        }
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__arm64_sys_prctl",
    .pre_handler = handler_pre,
};

int fmac_kprobe_init(void)
{
    int ret;
    ret = register_kprobe(&kp);
    if (ret < 0)
    {
        pr_err("FMAC: register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("FMAC: Kprobe registered at %p (%s)\n", kp.addr, kp.symbol_name);
    return 0;
}

void fmac_kprobe_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("FMAC: Kprobe at %p unregistered\n", kp.addr);
}