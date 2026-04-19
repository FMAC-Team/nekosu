/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NKSU_SEPOLICY_BACKUP_H
#define _NKSU_SEPOLICY_BACKUP_H

int  sepolicy_dup_and_apply(void);
void sepolicy_restore(void);

#endif /* _NKSU_SEPOLICY_BACKUP_H */