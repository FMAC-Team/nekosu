// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _LINUX_FMAC_H
#define _LINUX_FMAC_H

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/version.h>

#include "init.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define FMAC_USE_PROC_OPS
#endif

#define MAX_PATH_LEN 256
#define MAX_LOG_SIZE (PAGE_SIZE * 1024)
#define FMAC_HASH_BITS 8
#define FMAC_HASH_TABLE_SIZE (1 << FMAC_HASH_BITS)

enum fmac_op_type {
    FMAC_OP_MKDIRAT = 0,
    FMAC_OP_OPENAT  = 1,
    FMAC_OP_UNLINK  = 2,
    FMAC_OP_RENAME  = 3,
};

struct fmac_rule {
  char path_prefix[MAX_PATH_LEN];
  size_t path_len;
  uid_t uid;
  bool deny;
  enum fmac_op_type op_type;
  struct hlist_node node;
  struct rcu_head rcu;
};

// 全局规则哈希表和锁
extern DECLARE_HASHTABLE(fmac_rule_ht, FMAC_HASH_BITS);
extern spinlock_t fmac_lock;
extern bool fmac_printk;
extern int work_module;

// 日志缓冲区（供 fmac_procfs.c 使用）
extern struct proc_dir_entry *fmac_proc_dir;
extern char *fmac_log_buffer;
extern size_t fmac_log_len;
extern spinlock_t fmac_log_lock;

// 全局函数
void fmac_add_rule(const char *path_prefix, uid_t uid, bool deny, int op_type);
void fmac_append_to_log(const char *fmt, ...);

#endif /* _LINUX_FMAC_H */