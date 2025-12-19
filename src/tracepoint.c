#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>

#include <asm/syscall.h>

static void fmac_sys_enter_prctl(void *data, struct pt_regs *regs, long id)
{
    // ARM64 prctl syscall ID = 167
    if (id != 167)
        return;

    /*
     * in sys_enter ：
     * arg0 (option) = regs->regs[0]
     * arg1 (arg2)   = regs->regs[1]
     */
    long option = regs->regs[0];
    unsigned long arg2 = regs->regs[1];

    if (option == 0xCAFEBABE) {
        pr_info("FMAC Tracepoint: prctl detected! option=0x%lx, arg2=0x%lx\n", option, arg2);
    }
}

int fmac_tracepoint_init(void)
{
    int ret;

    ret = register_trace_sys_enter(fmac_sys_enter_prctl, NULL);
    if (ret) {
        pr_err("FMAC: Failed to register sys_enter tracepoint\n");
        return ret;
    }

    pr_info("FMAC: Tracepoint hook on sys_enter registered\n");
    return 0;
}

void fmac_tracepoint_exit(void)
{
    unregister_trace_sys_enter(fmac_sys_enter_prctl, NULL);
    tracepoint_synchronize_unregister();
}

#endif
