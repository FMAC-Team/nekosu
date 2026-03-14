// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <linux/types.h>

int fmac_anonfd_init(void);
void fmac_anonfd_exit(void);

/* 获取一个可 mmap 的 anon fd，失败返回负值 */
int fmac_anonfd_get(void);
