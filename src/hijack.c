#include <asm/unistd.h>
#include <linux/ptrace.h>
#include <asm/syscall.h>
#include <fmac.h>

static syscall_fn_t orig_prctl = NULL;

static long my_hook_prctl(const struct pt_regs *regs)
{
    pr_info("FMAC: prctl hooked! PID: %d\n", current->pid);

    if (orig_prctl)
        return orig_prctl(regs);

    return -ENOSYS;
}


int init_hijack(void){
    int ret;
    unsigned long oprctl;

    oprctl = (unsigned long)&syscall_table[__NR_prctl];

    orig_prctl = syscalltable_get_original(oprctl);
    ret = syscalltable_hook(oprctl,my_hook_prctl);
    
    if (ret == 0) {
        pr_info("successfully hooked prctl\n");
    }

    return ret;

}