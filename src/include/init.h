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

// tracepoint.c and kprobe.c
int fmac_tp_hook_init(void);
int fmac_kprobe_hook_init(void);

#endif