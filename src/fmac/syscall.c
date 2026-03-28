#include <linux/uaccess.h>
#include <fmac.h>

syscall_fn_t orig_openat = NULL;

long hooked_openat(const struct pt_regs *regs)
{
	char kpath[MAX_PATH_LEN];
	const char __user *upath = (const char __user *)regs->regs[1];
	int ret;

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		ret = fmac_check_openat(kpath);
	if (ret)
		return ret;

	return orig_openat(regs);
}
