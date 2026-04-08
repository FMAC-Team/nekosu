// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#ifndef _LINUX_FMAC_H
#define _LINUX_FMAC_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[ncore]: " fmt

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/version.h>
#include <asm/syscall.h>

#include "anonfd.h"
#include "allowlist.h"
#include "selinux.h"
#include "totp.h"
#include "profile.h"
#include "check.h"
#include "hijack.h"
#include "ioctl.h"
#include "procfs.h"
#include "uid_caps.h"
#include "manager.h"

#if IS_ENABLED(CONFIG_FMAC_SYSCALL) 
#include "syscall.h"
extern syscall_fn_t *syscall_table;

#include "fmac/hashtable.h"
#include "fmac/init.h"
#include "fmac/hook.h"
#include "fmac/openat.h"
#endif

extern struct proc_dir_entry *fmac_proc_dir;

#define MAX_PATH_LEN 1024

#include <linux/types.h>

#define FMAC_SCOPE_EXEC      BIT(0)
#define FMAC_SCOPE_STAT      BIT(1)
#define FMAC_SCOPE_ACCESS    BIT(2)
#define FMAC_SCOPE_ALL       (FMAC_SCOPE_EXEC | FMAC_SCOPE_STAT | FMAC_SCOPE_ACCESS)


#endif /* _LINUX_FMAC_H */
