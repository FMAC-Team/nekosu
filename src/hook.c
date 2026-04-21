#include <fmac.h>

long hook_faccess(struct nksu_args *args)
{
	char buf[64];
	if (!current->mm)
		return 0;

	unsigned long sp = user_stack_pointer(args->regs);
	if (!sp)
		return 0;

	int ret =
	    strncpy_from_user(buf, (char __user *)args->arg1, sizeof(buf));
	if (ret < 0) {
		return 0;
	}
	if (!path_is_su(buf)) {
		return 0;
	}
	unsigned long new_sp = PUSH_STR(sp, SH_PATH, SH_PATH_LEN);

	if (new_sp) {
		args->regs->regs[1] = new_sp;
	}
	return 0;
}

int init_syscall_hook(void) {
    int ret;
    ret = nksu_redirect_syscall(__NR_faccessat);
    if (ret) {
        pr_err("[hook]: can't redirect faccessat ret %d\n", ret);
        return ret;
    }
    
    ret = nksu_redirect_syscall(__NR_newfstatat);
    if (ret) {
        pr_err("[hook]: can't redirect newfstatat ret %d\n", ret);
        return ret;
    }

    ret = nksu_register_handler(__NR_faccessat, hook_faccess);
    if (ret) {
        pr_err("[hook]: can't register faccessat,ret %d\n", ret);
        return ret;
    }

    pr_info("[hook]: loaded syscall hook\n");
    return 0;
}