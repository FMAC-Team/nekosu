#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/compiler.h>
#include <linux/string.h>

#include <fmac.h>

#define REDIRECT_TARGET     "/data/adb/ncore"
#define REDIRECT_TARGET_LEN (sizeof(REDIRECT_TARGET))

#define SH_PATH     "/system/bin/sh"
#define SH_PATH_LEN (sizeof(SH_PATH))

// no export
#define MAX_PATH_LEN 256

static const char exact_paths[] = "/system/bin/su";

static syscall_fn_t orig_execveat = NULL;
static syscall_fn_t orig_execve = NULL;
static syscall_fn_t orig_faccessat = NULL;
static syscall_fn_t orig_newfstatat = NULL;

static bool is_exact_match(const char *path)
{
	if (!path)
		return false;

	if (unlikely(memcmp(path, exact_paths, sizeof(exact_paths) - 1) == 0)) {
		if (path[sizeof(exact_paths) - 1] == '\0') {
			return true;
		}
	}

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
	const char __user *upath = (const char __user *)regs->regs[1];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (likely(!fmac_uid_allowed())) {
		return orig_execveat(regs);
	}

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_redirect(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("execveat: %s -> " REDIRECT_TARGET " (stack @%lx)\n",
		kpath, uaddr);

	patched = *regs;
	patched.regs[1] = uaddr;
	elevate_to_root();
	return orig_execveat(&patched);

passthrough:
	return orig_execveat(regs);
}

static long hooked_execve(const struct pt_regs *regs)
{
	const char __user *upath = (const char __user *)regs->regs[0];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (likely(!fmac_uid_allowed())) {
		return orig_execve(regs);
	}

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_redirect(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("execve: %s -> " REDIRECT_TARGET " (stack @%lx)\n",
		kpath, uaddr);

	patched = *regs;
	patched.regs[0] = uaddr;
	elevate_to_root();
	return orig_execve(&patched);

passthrough:
	return orig_execve(regs);
}

static long hooked_faccessat(const struct pt_regs *regs)
{
	const char __user *upath = (const char __user *)regs->regs[1];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (likely(!fmac_uid_allowed())) {
		return orig_faccessat(regs);
	}

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_sh(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("faccessat: %s -> " SH_PATH " (stack @%lx)\n", kpath, uaddr);

	patched = *regs;
	patched.regs[1] = uaddr;
	return orig_faccessat(&patched);

passthrough:
	return orig_faccessat(regs);
}

static long hooked_newfstatat(const struct pt_regs *regs)
{
	const char __user *upath = (const char __user *)regs->regs[1];
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (likely(!fmac_uid_allowed())) {
		return orig_newfstatat(regs);
	}

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_sh(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("newfstatat: %s -> " SH_PATH " (stack @%lx)\n", kpath, uaddr);

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

int load_hijack_hook(void)
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

	ret = hook_one(__NR_execve, hooked_execve, &orig_execve, "execve");
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
		
	ret =
	    hook_one(__NR_openat, hooked_openat, &orig_openat,
		     "openat");
	if (ret)
		return ret;

	return 0;
}
