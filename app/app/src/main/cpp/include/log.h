#ifndef NATIVE_LOG_HPP
#define NATIVE_LOG_HPP

#include <android/log.h>
#include <openssl/err.h>

#ifndef LOG_TAG
#define LOG_TAG "nekosu"
#endif

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : \
                     strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#define LOGI(fmt, ...) \
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG,  "[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,  "[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,  "[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)

inline void print_openssl_errors() {
    ERR_print_errors_cb([](const char *str, size_t len, void *u) -> int {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "OpenSSL Error: %s", str);
        return 1;
    }, nullptr);
}

#endif // NATIVE_LOG_HPP
