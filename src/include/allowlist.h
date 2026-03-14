#ifndef _ALLOWLIST_H_
#define _ALLOWLIST_H_

int nksu_add_uid(void);
bool fmac_uid_allowed(void);
int fmac_uid_proc_init(void);
void fmac_uid_proc_exit(void);

#endif
