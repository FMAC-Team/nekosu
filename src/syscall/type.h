#pragma once
#include <linux/types.h>

struct nksu_args {
    __u32 cmd;
    __u32 nr;
    __u64 arg0;
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    __u64 arg4;
    __u64 arg5;
};

typedef long (*nksu_handler_t)(struct nksu_args *args);