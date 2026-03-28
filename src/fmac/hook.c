#include <linux/uaccess.h>
#include <fmac.h>

syscall_fn_t orig_openat = NULL;

long hooked_openat(const struct pt_regs *regs)
{
	char kpath[MAX_PATH_LEN];
	const char __user *upath = (const char __user *)regs->regs[1];
	int ret = 0;

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		ret = fmac_check_openat(kpath);
	if (ret != 0) {
		return ret;
	}

	return orig_openat(regs);
}

int load_hook(void)
{
	int ret;
	ret = hook_one(__NR_openat, hooked_openat, &orig_openat, "openat");
	if (ret)
		return ret;
	return 0;
}
