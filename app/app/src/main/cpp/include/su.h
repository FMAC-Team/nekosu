#ifndef NKSU_SU_HPP
#define NKSU_SU_HPP

#include <jni.h>
#include <string>

struct nksu_reply {
    int fd;
    uint32_t version;
    uint32_t flags;
};

extern int AuthenticationManager(const std::string key, const std::string totp);

#endif