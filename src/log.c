// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <stdarg.h>
#include <linux/string.h>

#include "fmac.h"

enum fmac_log_mode
{
    FMAC_LOG_BUFFER = 0,
    FMAC_LOG_KLOG = 1,
};

#ifdef CONFIG_FMAC_DEBUG
static enum fmac_log_mode fmac_log_mode = FMAC_LOG_KLOG;
#else
static enum fmac_log_mode fmac_log_mode = FMAC_LOG_BUFFER;
#endif

void __fmac_append_to_log(const char *fmt, ...)
{
    va_list args;
    char buf[256];
    int len;
    unsigned long flags;

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len <= 0)
        return;

    if (unlikely(len >= sizeof(buf)))
        len = sizeof(buf) - 1;

    if (READ_ONCE(fmac_log_mode) == FMAC_LOG_KLOG) {
        printk(KERN_INFO "fmac: %s", buf);
        return;
    }

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