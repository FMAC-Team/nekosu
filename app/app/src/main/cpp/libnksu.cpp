#include <jni.h>
#include <string>
#include <iostream>

#include "log.hpp"
#include "su.hpp"

extern "C"
JNIEXPORT jint JNICALL
Java_me_neko_nksu_NativeBridge_authenticate(
        JNIEnv* env,
        jobject /* this */,
        jstring jKey,
        jstring jToken) {


    const char *nativeKey = env->GetStringUTFChars(jKey, nullptr);
    const char *nativeToken = env->GetStringUTFChars(jToken, nullptr);

    std::string key(nativeKey);
    std::string token(nativeToken);

    int result = 0;

    // 3. 校验逻辑
    if (key.empty() || token.empty()) {
        LOGE("need args");
        result = -2;
    } else {
        if (AuthenticationManager(key, token) == -1) {
            LOGE("AuthenticationManager falied!");
            print_openssl_errors();
            result = -1;
        }
    }

    env->ReleaseStringUTFChars(jKey, nativeKey);
    env->ReleaseStringUTFChars(jToken, nativeToken);

    return result; 
}
