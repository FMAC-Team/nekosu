// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "fmac.h"

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("Aqnya");
MODULE_DESCRIPTION("FMAC");

DEFINE_HASHTABLE(fmac_rule_ht, FMAC_HASH_BITS);
DEFINE_SPINLOCK(fmac_lock);
bool fmac_printk = false;
int work_module = 1;

// RCU 释放规则
static void fmac_rule_free_rcu(struct rcu_head *head)
{
    struct fmac_rule *rule = container_of(head, struct fmac_rule, rcu);
    kfree(rule);
}

void fmac_add_rule(const char *path_prefix, uid_t uid, bool deny, int op_type)
{
    struct fmac_rule *rule;
    u32 key;

    rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule) {
        fmac_append_to_log("Failed to allocate rule\n");
        return;
    }

    strlcpy(rule->path_prefix, path_prefix, MAX_PATH_LEN);
    rule->path_len = strlen(path_prefix);
    rule->uid = uid;
    rule->deny = deny;
    rule->op_type = op_type;

    key = jhash(rule->path_prefix, rule->path_len, 0);

    spin_lock(&fmac_lock);
    hash_add_rcu(fmac_rule_ht, &rule->node, key);
    spin_unlock(&fmac_lock);

    fmac_append_to_log("added rule: path=%s, uid=%u, deny=%d, op_type=%d\n", path_prefix, uid, deny,
                       op_type);
}

void __fmac_append_to_log(const char *fmt, ...)
{
    va_list args;
    char buf[256];
    int len;
    unsigned long flags;

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    spin_lock_irqsave(&fmac_log_lock, flags);
    if (fmac_log_len + len < MAX_LOG_SIZE) {
        memcpy(fmac_log_buffer + fmac_log_len, buf, len);
        fmac_log_len += len;
    } else {
        fmac_log_len = 0;
        memcpy(fmac_log_buffer, buf, len);
        fmac_log_len = len;
    }
    spin_unlock_irqrestore(&fmac_log_lock, flags);
}

static int __init fmac_init(void)
{
    int ret;

    hash_init(fmac_rule_ht);

    ret = fmac_procfs_init();
    if (ret) {
        fmac_append_to_log("Failed to initialize procfs\n");
        return ret;
    }

#ifdef CONFIG_FMAC_ROOT
    fmac_tracepoint_init();
#endif

    fmac_append_to_log("File Monitoring and Access Control initialized.\n");
    return 0;
}

static void __exit fmac_exit(void)
{
    struct fmac_rule *rule;
    struct hlist_node *tmp;
    int bkt;

    fmac_procfs_exit();

    spin_lock(&fmac_lock);
    hash_for_each_safe(fmac_rule_ht, bkt, tmp, rule, node)
    {
        hash_del_rcu(&rule->node);
        call_rcu(&rule->rcu, fmac_rule_free_rcu);
    }
    spin_unlock(&fmac_lock);

    synchronize_rcu();

    pr_info("File Monitoring and Access Control exited.\n");
}

module_init(fmac_init);
module_exit(fmac_exit);