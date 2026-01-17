#ifndef NKSU_SU_HPP
#define NKSU_SU_HPP

#include <jni.h>
#include <string>

extern int AuthenticationManager(const std::string key, const std::string totp);

#endif