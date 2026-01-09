#include <iostream>
#include <jni.h>
#include <string>

#include "log.h"
#include "su.h"
#include "sigcheck.h"

extern "C" JNIEXPORT jint JNICALL Java_me_neko_nksu_Native_authenticate(
    JNIEnv *env, jobject /* this */, jstring jKey, jstring jToken) {

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

extern "C"
JNIEXPORT jboolean JNICALL
Java_me_neko_nksu_Native_Sigcheck(JNIEnv *env, jobject thiz, jobject context) {
    // 获取 context.getApplicationInfo().sourceDir
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getAppInfoMethod = env->GetMethodID(contextClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject appInfo = env->CallObjectMethod(context, getAppInfoMethod);

    jclass appInfoClass = env->GetObjectClass(appInfo);
    jfieldID sourceDirField = env->GetFieldID(appInfoClass, "sourceDir", "Ljava/lang/String;");
    jstring sourceDirJStr = (jstring)env->GetObjectField(appInfo, sourceDirField);

    const char* path = env->GetStringUTFChars(sourceDirJStr, nullptr);
    bool result = SigCheck::validate(path);
    env->ReleaseStringUTFChars(sourceDirJStr, path);

    return result ? JNI_TRUE : JNI_FALSE;
}
