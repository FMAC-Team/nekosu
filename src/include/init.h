// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#ifndef _LINUX_FMAC_INIT_H
#define _LINUX_FMAC_INIT_H

// procfs.c
int fmac_procfs_init(void);
void fmac_procfs_exit(void);

// allowlist.c
int fmac_uid_proc_init(void);
void fmac_uid_proc_exit(void);
bool fmac_uid_allowed(void);

// tracepoint.c
int fmac_tracepoint_init(void);

// kprobe.c
int fmac_kprobe_init(void);

#endif