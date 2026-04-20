#ifndef TRACEPOINT_H
#define TRACEPOINT_H

u32 scope_lookup(uid_t uid);
int fmac_scope_set(uid_t uid, u32 flags);
void fmac_scope_clear(uid_t uid);
void fmac_scope_clear_all(void);
void mark_threads_by_uid(uid_t uid);
void mark_threads_by_pid(pid_t pid);
int load_tracepoint_hook(void);
void unload_tracepoint_hook(void);

#endif /* TRACEPOINT_H */