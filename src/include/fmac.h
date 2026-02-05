// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
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
#include "op_code.h"
#include "anonfd.h"
#include "allowlist.h"
#include "log.h"

#define MAX_PATH_LEN 256
#define MAX_LOG_SIZE (PAGE_SIZE * 1024)
#define FMAC_HASH_BITS 8
#define FMAC_HASH_TABLE_SIZE (1 << FMAC_HASH_BITS)

#define NKSU_API_VERSION 1

enum fmac_op_type
{
    FMAC_OP_MKDIRAT = 0,
    FMAC_OP_OPENAT = 1,
    FMAC_OP_UNLINK = 2,
    FMAC_OP_RENAME = 3,
};

struct nksu_reply {
    int fd;
    u32 version;
    u32 flags;
};

struct fmac_rule
{
    char path_prefix[MAX_PATH_LEN];
    size_t path_len;
    uid_t uid;
    bool deny;
    enum fmac_op_type op_type;
    struct hlist_node node;
    struct rcu_head rcu;
};

extern DECLARE_HASHTABLE(fmac_rule_ht, FMAC_HASH_BITS);
extern spinlock_t fmac_lock;
extern bool fmac_printk;
extern int work_module;

extern struct proc_dir_entry *fmac_proc_dir;
extern char *fmac_log_buffer;
extern size_t fmac_log_len;
extern spinlock_t fmac_log_lock;

void fmac_add_rule(const char *path_prefix, uid_t uid, bool deny, int op_type);

int transive_to_domain(const char *domain);

// totp.c
u32 generate_totp_base32(const char *base32_secret);

// rsa_pub.c
int check_totp_ecc(const char __user *user_buf, size_t user_len);

// root.c
void elevate_to_root(void);

#endif /* _LINUX_FMAC_H */