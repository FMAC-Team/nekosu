#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <syscall.h>
#include <unistd.h>
#include <vector>

#include "log.hpp"

#define AU_MANAGER 0xCAFEBABE
#define GE_ROOT 0xBAADBABE

int prctl(int option, void *arg2, void *arg3, void *arg4, void *arg5) {
  // option -> code
  // arg2 -> address
  // arg3 -> lenght
  LOGI("option: %x\narg2: %p\narg3: %zu\n",option,arg2,(size_t)arg3);
  return syscall(SYS_prctl, option, arg2, arg3, arg4, arg5);
}

int get_root(void) {
int uid1=getuid();
    prctl(GE_ROOT,NULL,NULL,NULL,NULL);
if(uid1 == getuid()){
    LOGE("Permission denied");
    return -1;
}else{
    return 0;
}
}


std::vector<unsigned char> sign_data(const std::string &data, EVP_PKEY *priv_key) {
    std::vector<unsigned char> sig;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return sig;
    }
    bool success = false;
    do {
        if (1 != EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, priv_key)) {
            break;
        }
        if (1 != EVP_DigestSignUpdate(ctx, data.data(), data.size())) {
            break;
        }
        size_t sig_len = 0;
        if (1 != EVP_DigestSignFinal(ctx, nullptr, &sig_len) || sig_len <= 0) {
            break;
        }
        sig.resize(sig_len);
        if (1 != EVP_DigestSignFinal(ctx, sig.data(), &sig_len)) {
            sig.clear();
            break;
        }
        sig.resize(sig_len);
        success = true;

    } while (false);

    if (!success) {
        ERR_print_errors_fp(stderr);
    }
    EVP_MD_CTX_free(ctx);
    return sig;
}


 int AuthenticationManager(const std::string key,
                                 const std::string totp) {
  FILE *fp = fopen(key.c_str(), "r");
  if (!fp) {
    LOGE("Can't open ecc key");
    return -1;
  }
  EVP_PKEY *priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if (!priv_key) {
    LOGE("Error: Unable to parse the private key file.");
    {
      ERR_print_errors_fp(stderr);
    }
    return -1;
  }

  std::vector<unsigned char> signature = sign_data(totp.c_str(), priv_key);

  LOGI("Success!\nsize: %zu bytes\n", signature.size());
  printf("signed: ");
  std::vector<unsigned char> signature = sign_data(totp.c_str(), priv_key);

  std::string sig_hex;
  sig_hex.reserve(signature.size() * 2);
  for (unsigned char b : signature) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", b);
    sig_hex += buf;
  }

  LOGI("Sig success! size: %zu bytes", signature.size());
  LOGI("signed: %s", sig_hex.c_str());
  prctl(AU_MANAGER,&signature,(void*)signature.size(),NULL,NULL);
  LOGI("please check manager!");
  EVP_PKEY_free(priv_key);
  return get_root();
}