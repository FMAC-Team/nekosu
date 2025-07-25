/* FMAC - File Monitoring and Access Control Kernel Module
    Copyright (C) 2025 Aqnya

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include "fmac.h"

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("Aqnya");
MODULE_DESCRIPTION("FMAC");

DEFINE_HASHTABLE(fmac_rule_ht, FMAC_HASH_BITS);
DEFINE_SPINLOCK(fmac_lock);
bool fmac_printk = false;
int work_module=1;

// RCU 释放规则
static void fmac_rule_free_rcu(struct rcu_head *head) {
  struct fmac_rule *rule = container_of(head, struct fmac_rule, rcu);
  kfree(rule);
}

bool fmac_check_access(const char *path, uid_t uid, int op_type) {
    struct fmac_rule *rule;
    bool deny = false;
    u32 key;

    char norm_path[MAX_PATH_LEN];
    size_t path_len = strlcpy(norm_path, path, MAX_PATH_LEN);

    while (path_len > 1 && norm_path[path_len - 1] == '/')
        norm_path[--path_len] = '\0';

    key = jhash(norm_path, path_len, 0);

    rcu_read_lock();
    hash_for_each_possible_rcu(fmac_rule_ht, rule, node, key) {
        if (rule->uid == 0 || rule->uid == uid) {
            if (strncmp(norm_path, rule->path_prefix, rule->path_len) == 0) {
                if (rule->op_type == -1 || rule->op_type == op_type) {
                    deny = rule->deny;
                    break;
                }
            }
        }
    }
    rcu_read_unlock();

    return deny;
}

void fmac_add_rule(const char *path_prefix, uid_t uid, bool deny, int op_type) {
    struct fmac_rule *rule;
    u32 key;

    rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule) {
        fmac_append_to_log("[FMAC] Failed to allocate rule\n");
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

    fmac_append_to_log("[FMAC] Added rule: path=%s, uid=%u, deny=%d, op_type=%d\n",
                       path_prefix, uid, deny, op_type);
}

void fmac_append_to_log(const char *fmt, ...) {
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
  
  
int fmac_check(const char __user *pathname, int op_type) {
if (work_module){
    char fmac_path[MAX_PATH_LEN] = {0};
    uid_t uid = current_euid().val;
    
    if(fmac_check_root_key(pathname) != 0){
    return 0;
    }

    if (pathname && strncpy_from_user(fmac_path, pathname, MAX_PATH_LEN) >= 0) {
        if (fmac_check_access(fmac_path, uid, op_type)) {
            if (fmac_printk) {
                if (op_type == 0) {
                    fmac_append_to_log("[FMAC] Denied mkdirat: %s by UID %u (pid %d)\n",
                                       fmac_path, uid, current->pid);
                } else if (op_type == 1) {
                    fmac_append_to_log("[FMAC] Denied openat: %s by UID %u (pid %d)\n",
                                       fmac_path, uid, current->pid);
                }
            }
            return -EACCES;
        }
    }
  }
    return 0;
}

  static int __init fmac_init(void) {
    int ret;

    hash_init(fmac_rule_ht);

    ret = fmac_procfs_init();
    if (ret) {
      pr_err("[FMAC] Failed to initialize procfs\n");
      return ret;
    }

    fmac_append_to_log(
        "[FMAC] File Monitoring and Access Control initialized.\n");
    return 0;
  }

  static void __exit fmac_exit(void) {
    struct fmac_rule *rule;
    struct hlist_node *tmp;
    int bkt;

    fmac_procfs_exit();

    spin_lock(&fmac_lock);
    hash_for_each_safe(fmac_rule_ht, bkt, tmp, rule, node) {
      hash_del_rcu(&rule->node);
      call_rcu(&rule->rcu, fmac_rule_free_rcu);
    }
    spin_unlock(&fmac_lock);

    synchronize_rcu();

    pr_info("[FMAC] File Monitoring and Access Control exited.\n");
  }

  module_init(fmac_init);
  module_exit(fmac_exit);