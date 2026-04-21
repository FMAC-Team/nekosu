#include <fmac.h>

static long handle_prctl_hooks(struct nksu_args *args)
{
	unsigned long option = args->regs->regs[0];

	switch (option) {
	case 201:
		if (is_manager())
			fmac_anonfd_get();
		return 0;

	case 202:
		if (is_manager())
			elevate_to_root();
		return 0;

	case 203:
		if (is_manager())
			fmac_ctlfd_get();
		return 0;

	default:
		return 0;
	}
}

static long hook_faccess(struct nksu_args *args)
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

int init_syscall_hook(void)
{
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

	ret = nksu_redirect_syscall(__NR_prctl);
	if (ret) {
		pr_err("[hook]: can't redirect prctl ret %d\n", ret);
		return ret;
	}

	ret = nksu_register_handler(__NR_faccessat, hook_faccess);
	if (ret) {
		pr_err("[hook]: can't register faccessat,ret %d\n", ret);
		return ret;
	}

	ret = nksu_register_handler(__NR_newfstatat, hook_faccess);
	if (ret) {
		pr_err("[hook]: can't register newfstatat,ret %d\n", ret);
		return ret;
	}

	ret = nksu_register_handler(__NR_prctl, handle_prctl_hooks);
	if (ret) {
		pr_err("[hook]: can't register prctl,ret %d\n", ret);
		return ret;
	}

	pr_info("[hook]: loaded syscall hook\n");
	return 0;
}
