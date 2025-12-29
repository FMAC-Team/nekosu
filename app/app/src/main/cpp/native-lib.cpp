#include <jni.h>
#include <string>

extern "C"
JNIEXPORT jstring JNICALL
Java_me_neko_nksu_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from native C++!";
    return env->NewStringUTF(hello.c_str());
}