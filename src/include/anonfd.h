#ifndef ANONFD_H
#define ANONFD_H

#define FMAC_SHM_SIZE PAGE_SIZE

int fmac_anonfd_get(void);
int bind_eventfd(int fd);
void notify_user(void);
void eventfd_cleanup(void);
bool check_mmap_write(void);
int fmac_anonfd_init(void);
void fmac_anonfd_exit(void);

#endif /* ANONFD_H */