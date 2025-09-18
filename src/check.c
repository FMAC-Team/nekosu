// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/errno.h>

#include "fmac.h"

static bool fmac_check_access(const char *path, uid_t uid, int op_type) {
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

int fmac_check_mkdirat(const char __user *pathname) {
  char path[MAX_PATH_LEN] = {0};
  uid_t uid = current_euid().val;

  if (!pathname || strncpy_from_user(path, pathname, MAX_PATH_LEN) < 0) {
    return 0;
  }

  if (fmac_check_access(path, uid, FMAC_OP_MKDIRAT)) {
    if (fmac_printk)
      fmac_append_to_log("[FMAC] Denied mkdirat: %s by UID %u (pid %d)\n", path,
                         uid, current->pid);
    return -EACCES;
  }

  return 0;
}

int fmac_check_openat(const char __user *pathname) {
  char path[MAX_PATH_LEN] = {0};
  uid_t uid = current_euid().val;

  if (!pathname || strncpy_from_user(path, pathname, MAX_PATH_LEN) < 0) {
    return 0;
  }

  if (fmac_check_access(path, uid, FMAC_OP_OPENAT)) {
    if (fmac_printk)
      fmac_append_to_log("[FMAC] Denied openat: %s by UID %u (pid %d)\n", path,
                         uid, current->pid);
    return -EACCES;
  }

  return 0;
}