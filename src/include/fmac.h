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
#include "syscall.h"
extern syscall_fn_t *syscall_table;
#include "totp.h"
#include "profile.h"
#include "kprobe.h"
#include "check.h"
#include "hijack.h"
#include "ioctl.h"

#include "fmac/procfs.h"
#include "fmac/hashtable.h"
#include "fmac/init.h"
#include "fmac/syscall.h"
#include "fmac/openat.h"

extern struct proc_dir_entry *fmac_proc_dir;

#define MAX_PATH_LEN 1024

#endif /* _LINUX_FMAC_H */
