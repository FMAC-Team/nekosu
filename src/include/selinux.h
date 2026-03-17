void setenforce(bool status);
void init_selinux_hook(void);
int set_domain(const char *domain, struct cred *new_cred);