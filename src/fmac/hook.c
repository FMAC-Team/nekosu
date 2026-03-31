#include <linux/uaccess.h>
#include <linux/fs.h>
#include <fmac.h>

syscall_fn_t orig_openat = NULL;

long hooked_openat(const struct pt_regs *regs)
{
    int dfd          = (int)regs->regs[0];
    const char __user *upath = (const char __user *)regs->regs[1];
    int flags        = (int)regs->regs[2];
    umode_t mode     = (umode_t)regs->regs[3];

  //  struct path path;
  //  unsigned long ino;
    long ret;
    char kpath[MAX_PATH_LEN];

    if (upath && strncpy_from_user(kpath, upath, sizeof(kpath)) > 0) {
        kpath[MAX_PATH_LEN - 1] = '\0';
        ret = fmac_check_openat(kpath);
        if (ret != 0)
            return ret;
    }

	if (force_o_largefile())
		flags |= O_LARGEFILE;
    ret = do_sys_open(dfd, upath, flags, mode);
    return ret;
}

int load_hook(void)
{
	int ret;
	ret = hook_one(__NR_openat, hooked_openat, &orig_openat, "openat");
	if (ret)
		return ret;
	return 0;
}
