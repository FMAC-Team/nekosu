int syscalltable_init(void);
void syscalltable_exit(void);
int hook_one(int nr, syscall_fn_t fn, syscall_fn_t *orig, const char *name);

extern syscall_fn_t *syscall_table;