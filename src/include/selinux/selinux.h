#ifndef SELINUX_H
#define SELINUX_H

void setenforce(bool status);
bool getenforce(void);
int set_domain(const char *domain, struct cred *new_cred);
int init_selinux_hook(void);

#endif /* SELINUX_H */