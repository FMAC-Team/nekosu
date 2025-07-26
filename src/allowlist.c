// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
 
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/string.h>

#define UID_DELIMITER ","
#define MAX_UID_STR_LEN 12
#define MAX_UID_LIST_DEFAULT 32
#define FMAC_PROC_FILENAME "fmac_uid"

typedef struct {
  kuid_t *uids;
  int count;
  int capacity;
} fmac_uid_list_t;

static fmac_uid_list_t fmac_global_uid_list;
static DEFINE_MUTEX(fmac_uid_lock);
static struct proc_dir_entry *fmac_proc_entry;

static int fmac_resize_uid_list(int new_capacity);
static int parse_uid_list(const char *buf, size_t len);

bool fmac_uid_allowed(void) {
  kuid_t uid = current_uid();
  int i;
  bool allowed = false;

  mutex_lock(&fmac_uid_lock);
  for (i = 0; i < fmac_global_uid_list.count; i++) {
    if (uid_eq(uid, fmac_global_uid_list.uids[i])) {
      allowed = true;
      break;
    }
  }
  mutex_unlock(&fmac_uid_lock);
  return allowed;
}

static int fmac_resize_uid_list(int new_capacity) {
  kuid_t *new_uids;
  if (new_capacity < 0)
    return -EINVAL;
  if (new_capacity == 0) {
    kfree(fmac_global_uid_list.uids);
    fmac_global_uid_list.uids = NULL;
    fmac_global_uid_list.count = 0;
    fmac_global_uid_list.capacity = 0;
    return 0;
  }
  if (new_capacity == fmac_global_uid_list.capacity)
    return 0;
  new_uids = krealloc(fmac_global_uid_list.uids, new_capacity * sizeof(kuid_t), GFP_KERNEL);
  if (!new_uids)
    return -ENOMEM;
  fmac_global_uid_list.uids = new_uids;
  fmac_global_uid_list.capacity = new_capacity;
  if (fmac_global_uid_list.count > new_capacity)
    fmac_global_uid_list.count = new_capacity;
  return 0;
}

static int parse_uid_list(const char *buf, size_t len) {
  const char *p = buf;
  char *end;
  unsigned long val;
  int current_parsed_count = 0;
  kuid_t *temp_uids = NULL;
  int temp_capacity = MAX_UID_LIST_DEFAULT;

  if (len == 0) {
    mutex_lock(&fmac_uid_lock);
    fmac_resize_uid_list(0);
    mutex_unlock(&fmac_uid_lock);
    return 0;
  }

  temp_uids = kmalloc(temp_capacity * sizeof(kuid_t), GFP_KERNEL);
  if (!temp_uids)
    return -ENOMEM;

  while (p < buf + len) {
    while (p < buf + len && (*p == *UID_DELIMITER || *p == ' ' || *p == '\n' || *p == '\r'))
      p++;
    if (p >= buf + len)
      break;

    val = simple_strtoul(p, &end, 10);
    if (end == p) {
      p++;
      continue;
    }

    if ((val > 1999999999UL || val < 0) && val != 0 && val != 1000) {
      p = end;
      continue;
    }

    if (current_parsed_count >= temp_capacity) {
      int new_temp_capacity = temp_capacity * 2;
      kuid_t *reallocated_uids = krealloc(temp_uids, new_temp_capacity * sizeof(kuid_t), GFP_KERNEL);
      if (!reallocated_uids) {
        kfree(temp_uids);
        return -ENOMEM;
      }
      temp_uids = reallocated_uids;
      temp_capacity = new_temp_capacity;
    }

    temp_uids[current_parsed_count++] = KUIDT_INIT(val);
    p = end;
  }

  mutex_lock(&fmac_uid_lock);
  kfree(fmac_global_uid_list.uids);
  fmac_global_uid_list.uids = temp_uids;
  fmac_global_uid_list.count = current_parsed_count;
  fmac_global_uid_list.capacity = temp_capacity;
  mutex_unlock(&fmac_uid_lock);

  return current_parsed_count;
}

ssize_t fmac_uid_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
  char *kbuf;
  int len = 0, i;
  ssize_t ret;

  if (*ppos > 0)
    return 0;

  mutex_lock(&fmac_uid_lock);
  len = fmac_global_uid_list.count * (MAX_UID_STR_LEN + strlen(UID_DELIMITER)) + 2;
  if (len > PAGE_SIZE * 4)
    len = PAGE_SIZE * 4;

  kbuf = kmalloc(len, GFP_KERNEL);
  if (!kbuf) {
    mutex_unlock(&fmac_uid_lock);
    return -ENOMEM;
  }

  len = 0;
  for (i = 0; i < fmac_global_uid_list.count; i++) {
    if (len + MAX_UID_STR_LEN + strlen(UID_DELIMITER) + 2 > (PAGE_SIZE * 4))
      break;
    len += scnprintf(kbuf + len, (PAGE_SIZE * 4) - len, "%u%s",
                     fmac_global_uid_list.uids[i].val,
                     (i < fmac_global_uid_list.count - 1) ? UID_DELIMITER : "");
  }
  mutex_unlock(&fmac_uid_lock);

  kbuf[len++] = '\n';
  kbuf[len] = '\0';

  if (len > count) {
    ret = -EINVAL;
  } else if (copy_to_user(buf, kbuf, len)) {
    ret = -EFAULT;
  } else {
    *ppos = len;
    ret = len;
  }

  kfree(kbuf);
  return ret;
}

ssize_t fmac_uid_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
  char *kbuf;
  ssize_t ret;

  if (count == 0)
    return 0;

  if (count >= PAGE_SIZE)
    count = PAGE_SIZE - 1;

  kbuf = kmalloc(count + 1, GFP_KERNEL);
  if (!kbuf)
    return -ENOMEM;

  if (copy_from_user(kbuf, ubuf, count)) {
    kfree(kbuf);
    return -EFAULT;
  }
  kbuf[count] = '\0';

  parse_uid_list(kbuf, count);
  ret = count;
  kfree(kbuf);
  return ret;
}

static const struct proc_ops fmac_proc_fops = {
  .proc_read = fmac_uid_proc_read,
  .proc_write = fmac_uid_proc_write,
  .proc_open = nonseekable_open,
};

int fmac_uid_proc_init(void) {
  fmac_global_uid_list.uids = NULL;
  fmac_global_uid_list.count = 0;
  fmac_global_uid_list.capacity = 0;
  fmac_proc_entry = proc_create(FMAC_PROC_FILENAME, 0600, NULL, &fmac_proc_fops);
  return fmac_proc_entry ? 0 : -ENOMEM;
}

void fmac_uid_proc_exit(void) {
  if (fmac_proc_entry)
    remove_proc_entry(FMAC_PROC_FILENAME, NULL);

  mutex_lock(&fmac_uid_lock);
  kfree(fmac_global_uid_list.uids);
  fmac_global_uid_list.uids = NULL;
  fmac_global_uid_list.count = 0;
  fmac_global_uid_list.capacity = 0;
  mutex_unlock(&fmac_uid_lock);
}
