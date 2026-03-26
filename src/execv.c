#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <fmac.h>

#define REDIRECT_TARGET     "/data/adb/ncore"
#define REDIRECT_TARGET_LEN (sizeof(REDIRECT_TARGET))	/* includes NUL */

static const char *const exact_paths[] = {
	"/system/bin/su",
	"/system/xbin/su",
	"/sbin/su",
	NULL,
};

static syscall_fn_t orig_execve = NULL;

#define MAX_PATH_LEN 256

static bool is_exact_match(const char *path)
{
	const char *const *p;
	for (p = exact_paths; *p; p++)
		if (strcmp(path, *p) == 0)
			return true;
	return false;
}

/*
 * Write REDIRECT_TARGET onto the current task's user stack, below SP,
 * in the red-zone / scratch area that the ABI guarantees won't be
 * clobbered before the next call.
 *
 * arm64 ABI: 128-byte red zone below SP (same as x86-64 System V).
 * We only need REDIRECT_TARGET_LEN (16) bytes so this is safe.
 *
 *   scratch = (sp - 128 - REDIRECT_TARGET_LEN) & ~15
 *
 * Returns the address written, or 0 on copy failure.
 * No mapping is created — the stack page is already present.
 */
static unsigned long push_redirect_to_stack(const struct pt_regs *regs)
{
	unsigned long sp = regs->sp;
	unsigned long addr =
	    (sp - 128 - REDIRECT_TARGET_LEN) & ~(unsigned long)15;

	if (copy_to_user
	    ((void __user *)addr, REDIRECT_TARGET, REDIRECT_TARGET_LEN))
		return 0;

	return addr;
}

static inline const char __user *regs_filename(const struct pt_regs *regs)
{
	return (const char __user *)regs->regs[0];
}

static inline void regs_set_filename(struct pt_regs *regs, unsigned long addr)
{
	regs->regs[0] = addr;
}

static long hooked_execve(const struct pt_regs *regs)
{
	const char __user *upath = regs_filename(regs);
	char kpath[MAX_PATH_LEN];
	unsigned long uaddr;
	struct pt_regs patched;

	if (!upath || strncpy_from_user(kpath, upath, sizeof(kpath)) < 0)
		goto passthrough;
	kpath[sizeof(kpath) - 1] = '\0';

	if (!is_exact_match(kpath))
		goto passthrough;

	uaddr = push_redirect_to_stack(regs);
	if (!uaddr)
		goto passthrough;

	pr_info("exec_redirect: %s -> " REDIRECT_TARGET " (stack @%lx)\n",
		kpath, uaddr);

	patched = *regs;
	regs_set_filename(&patched, uaddr);
	elevate_to_root();
	return orig_execve(&patched);

passthrough:
	return orig_execve(regs);
}

int load_execv_hook()
{
	int ret;
	unsigned long oexecve;
	if (!syscall_table) {
		pr_err("FMAC: syscall_table is NULL!\n");
		return -EFAULT;
	}
	oexecve = (unsigned long)&syscall_table[__NR_execve];

	ret = syscalltable_hook(oexecve, hooked_execve);

	if (ret == 0) {
		orig_execve = syscalltable_get_original(oprctl);
		pr_info("successfully hooked prctl\n");
	} else {
		pr_err("failed to hook prctl, ret: %d\n", ret);
	}

	return ret;
}
