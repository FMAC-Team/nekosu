 int __init scope_init(void);
 u32 scope_lookup(uid_t uid);
int fmac_scope_set(uid_t uid, u32 flags);
void fmac_scope_clear(uid_t uid);
void fmac_scope_clear_all(void);