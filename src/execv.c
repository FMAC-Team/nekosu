#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <fmac.h>

#define REDIRECT_TARGET     "/data/adb/ncore"
#define REDIRECT_TARGET_LEN (sizeof(REDIRECT_TARGET))

#define SH_PATH     "/system/bin/sh"
#define SH_PATH_LEN (sizeof(SH_PATH))

// no export
#define MAX_PATH_LEN 256

static const char *const exact_paths[] = {
	"/system/bin/su",
	"/system/xbin/su",
	"/sbin/su",
	NULL,
};

static syscall_fn_t orig_execveat = NULL;
static syscall_fn_t orig_faccessat = NULL;
static syscall_fn_t orig_newfstatat = NULL;

static bool is_exact_match(const char *path)
{
	const char *const *p;
	for (p = exact_paths; *p; p++)
		if (strcmp(path, *p) == 0)
			return true;
	return false;
}

static unsigned long push_to_stack(const struct pt_regs *regs,
				   const char *str, size_t len)
{
	unsigned long addr = (regs->sp - 128 - len) & ~(unsigned long)15;

	if (copy_to_user((void __user *)addr, str, len))
		return 0;
	return addr;
}

static unsigned long push_redirect(const struct pt_regs *regs)
{
	return push_to_stack(regs, REDIRECT_TARGET, REDIRECT_TARGET_LEN);
}

static unsigned long push_sh(const struct pt_regs *regs)
{
	return push_to_stack(regs, SH_PATH, SH_PATH_LEN);
}

static long hooked_execveat(const struct pt_regs *regs)
{
	if (!fmac_uid_allowed()) {
		goto passthrough;
	}
	const char __user *upath = (const char __user *)regs->regs[1];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_redirect(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("execveat_redirect: %s -> " REDIRECT_TARGET " (stack @%lx)\n",
		kpath, uaddr);

	patched = *regs;
	patched.regs[1] = uaddr;
	elevate_to_root();
	return orig_execveat(&patched);

passthrough:
	return orig_execveat(regs);
}

static long hooked_faccessat(const struct pt_regs *regs)
{
	if (!fmac_uid_allowed()) {
		goto passthrough;
	}
	const char __user *upath = (const char __user *)regs->regs[1];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_sh(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("faccessat_redirect: %s -> " SH_PATH " (stack @%lx)\n",
		kpath, uaddr);

	patched = *regs;
	patched.regs[1] = uaddr;
	return orig_faccessat(&patched);

passthrough:
	return orig_faccessat(regs);
}

static long hooked_newfstatat(const struct pt_regs *regs)
{
	if (!fmac_uid_allowed()) {
		goto passthrough;
	}
	const char __user *upath = (const char __user *)regs->regs[1];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_sh(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("newfstatat_redirect: %s -> " SH_PATH " (stack @%lx)\n",
		kpath, uaddr);

	patched = *regs;
	patched.regs[1] = uaddr;
	return orig_newfstatat(&patched);

passthrough:
	return orig_newfstatat(regs);
}

static int hook_one(int nr, syscall_fn_t fn, syscall_fn_t *orig,
		    const char *name)
{
	unsigned long addr = (unsigned long)&syscall_table[nr];
	int ret = syscalltable_hook(addr, fn);

	if (ret) {
		pr_err("failed to hook %s: %d\n", name, ret);
		return ret;
	}
	*orig = syscalltable_get_original(addr);
	pr_info("hooked %s\n", name);
	return 0;
}

int load_execv_hook(void)
{
	int ret;

	if (!syscall_table) {
		pr_err("FMAC: syscall_table is NULL!\n");
		return -EFAULT;
	}

	ret =
	    hook_one(__NR_execveat, hooked_execveat, &orig_execveat,
		     "execveat");
	if (ret)
		return ret;

	ret =
	    hook_one(__NR_faccessat, hooked_faccessat, &orig_faccessat,
		     "faccessat");
	if (ret)
		return ret;

	ret =
	    hook_one(__NR_newfstatat, hooked_newfstatat, &orig_newfstatat,
		     "newfstatat");
	if (ret)
		return ret;

	return 0;
}

void unload_execv_hook(void)
{
	if (orig_execveat)
		syscalltable_unhook((unsigned long)
				    &syscall_table[__NR_execveat]);

	if (orig_faccessat)
		syscalltable_unhook((unsigned long)
				    &syscall_table[__NR_faccessat]);

	if (orig_newfstatat)
		syscalltable_unhook((unsigned long)
				    &syscall_table[__NR_newfstatat]);
}
