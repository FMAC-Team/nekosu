#include <linux/uaccess.h>
#include <fmac.h>

static syscall_fn_t orig_openat = NULL;
static long hooked_openat(const struct pt_regs *regs)
{
	const char __user *pathname = (const char __user *)regs->regs[1];
	int ret;

	ret = fmac_check_openat(pathname);
	if (ret)
		return ret;

	return orig_openat(regs);
}
