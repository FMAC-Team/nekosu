// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <linux/types.h>

int fmac_anonfd_init(void);
void fmac_anonfd_exit(void);

struct file *fmac_anonfd_get(void);
