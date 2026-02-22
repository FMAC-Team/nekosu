#ifndef _LOG_H_
#define _LOG_H_
#include <linux/string.h>

#define __FILENAME__                                                                               \
    (strrchr(__FILE__, '/')    ? strrchr(__FILE__, '/') + 1                                        \
     : strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1                                       \
                               : __FILE__)

void __fmac_append_to_log(const char *fmt, ...);
#define fmac_log(fmt, ...)                                                                            \
    __fmac_append_to_log("%s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)

#endif
