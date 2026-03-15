// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/uidgid.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif

#include <fmac.h>
#include "objsec.h"

#define PRIV_ROOT (1 << 0)
#define PRIV_CAPS (1 << 1)
#define PRIV_SELINUX (1 << 2)
#define PRIV_SECCOMP (1 << 3)
#define PRIV_ALL (PRIV_ROOT | PRIV_CAPS | PRIV_SELINUX | PRIV_SECCOMP)

static void disable_seccomp(void)
{
#ifdef CONFIG_SECCOMP
	struct task_struct *task = current;

	if (task->seccomp.mode == SECCOMP_MODE_DISABLED)
		return;

	spin_lock_irq(&task->sighand->siglock);

#ifdef CONFIG_SECCOMP_FILTER
	if (task->seccomp.mode != SECCOMP_MODE_DISABLED) {
		task->seccomp.mode = SECCOMP_MODE_DISABLED;

#if defined(TIF_SECCOMP)
		clear_thread_flag(TIF_SECCOMP);
#endif

#if defined(_TIF_SECCOMP)
		clear_thread_flag(_TIF_SECCOMP);
#endif

		pr_info("seccomp disabled for PID %d\n", task->pid);
	}
#endif

	spin_unlock_irq(&task->sighand->siglock);
#endif
}

static void reset_groups(struct cred *cred)
{
	struct group_info *gi;

	gi = groups_alloc(1);
	if (!gi)
		return;

	gi->gid[0] = GLOBAL_ROOT_GID;

	set_groups(cred, gi);
	put_group_info(gi);
}

void grant_privileges(unsigned int flags, kernel_cap_t caps_to_raise,
		      const char *target_domain)
{
	struct cred *new_cred;
	bool needs_commit = false;

	if ((flags & PRIV_SECCOMP) &&
	    !(flags & (PRIV_ROOT | PRIV_CAPS | PRIV_SELINUX))) {
		disable_seccomp();
		return;
	}

	new_cred = prepare_creds();
	if (!new_cred) {
		pr_err("prepare_creds failed! OOM?\n");
		return;
	}

	if (flags & PRIV_ROOT) {
		if (new_cred->euid.val != 0) {
			new_cred->uid.val = 0;
			new_cred->euid.val = 0;
			new_cred->suid.val = 0;
			new_cred->fsuid.val = 0;

			new_cred->gid.val = 0;
			new_cred->egid.val = 0;
			new_cred->sgid.val = 0;
			new_cred->fsgid.val = 0;
			
			reset_groups(new_cred);

			new_cred->securebits = 0;

			needs_commit = true;
		}
	}

	if (flags & PRIV_CAPS) {
		new_cred->cap_effective =
		    cap_combine(new_cred->cap_effective, caps_to_raise);
		new_cred->cap_permitted =
		    cap_combine(new_cred->cap_permitted, caps_to_raise);
		new_cred->cap_bset =
		    cap_combine(new_cred->cap_bset, caps_to_raise);

		needs_commit = true;
	}

	if ((flags & PRIV_SELINUX) && target_domain) {
		setup_selinux(target_domain, new_cred);
		needs_commit = true;
	}

	if (needs_commit) {
		commit_creds(new_cred);
		pr_info("privileges committed for PID %d.\n", current->pid);
	} else {
		abort_creds(new_cred);
	}

	if (flags & PRIV_SECCOMP) {
		disable_seccomp();
	}
}

void elevate_to_root(void)
{
	kernel_cap_t all_caps = CAP_EMPTY_SET;
	cap_raise(all_caps, CAP_SYS_ADMIN);
	cap_raise(all_caps, CAP_DAC_OVERRIDE);
	cap_raise(all_caps, CAP_SETUID);
	cap_raise(all_caps, CAP_SETGID);
	cap_raise(all_caps, CAP_NET_ADMIN);
	cap_raise(all_caps, CAP_SYS_PTRACE);
	cap_raise(all_caps, CAP_SYS_MODULE);
	cap_raise(all_caps, CAP_DAC_READ_SEARCH);
	cap_raise(all_caps, CAP_MAC_ADMIN);

	grant_privileges(PRIV_ALL, all_caps, "u:r:su:s0");
}
