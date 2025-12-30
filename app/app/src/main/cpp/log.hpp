#ifndef NATIVE_LOG_HPP
#define NATIVE_LOG_HPP

#include <android/log.h>
#include <openssl/err.h>

#ifndef LOG_TAG
#define LOG_TAG "NKSU_NATIVE"
#endif

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

inline void print_openssl_errors() {
    ERR_print_errors_cb([](const char *str, size_t len, void *u) -> int {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "OpenSSL Error: %s", str);
        return 1;
    }, nullptr);
}

#endif // NATIVE_LOG_HPP
