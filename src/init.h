// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
 
 #ifndef _LINUX_FMAC_INIT_H
#define _LINUX_FMAC_INIT_H
// procfs 初始化和清理函数
int fmac_procfs_init(void);
void fmac_procfs_exit(void);


int fmac_uid_proc_init(void);
void fmac_uid_proc_exit(void);
bool fmac_uid_allowed(void);

void get_apk_path(struct task_struct *task);

 int packages_parser_init(void);

#endif 