// init
int syscalltable_init(void);
void syscalltable_exit(void);
// hook
int syscalltable_hook(unsigned long addr, syscall_fn_t hook_fn);
int syscalltable_unhook(unsigned long addr);