#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <syscall.h>
#include <unistd.h>
#include <vector>

#define AU_MANAGER 0xCAFEBABE
#define GE_ROOT 0xBAADBABE

int prctl(int option, void *arg2, void *arg3, void *arg4, void *arg5) {
  // option -> code
  // arg2 -> address
  // arg3 -> lenght
  printf("option: %x\narg2: %p\narg3: %zu\n",option,arg2,(size_t)arg3);
  return syscall(SYS_prctl, option, arg2, arg3, arg4, arg5);
}

void get_root(void) {
int uid1=getuid();
    prctl(GE_ROOT,NULL,NULL,NULL,NULL);
if(uid1 == getuid()){
    std::cerr<<"Permission denied"<<std::endl;
}else{
    execl("/system/bin/sh", "sh", NULL);
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


static int AuthenticationManager(const std::string key,
                                 const std::string totp) {
  FILE *fp = fopen(key.c_str(), "r");
  if (!fp) {
    std::cerr<< "Can't open ecc key"<<std::endl;
    return -1;
  }
  EVP_PKEY *priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if (!priv_key) {
    std::cerr << "Error: Unable to parse the private key file."<<std::endl;
    {
      ERR_print_errors_fp(stderr);
    }
    return -1;
  }

  std::vector<unsigned char> signature = sign_data(totp.c_str(), priv_key);

  printf("Success!\nsize: %zu bytes\n", signature.size());
  printf("signed: ");
  for (size_t i = 0; i < signature.size(); i++) {
            printf("%02x", signature[i]);
        }
  printf("\n");
  std::cout <<"u_addr: "<< &signature <<std::endl;
  prctl(AU_MANAGER,&signature,(void*)signature.size(),NULL,NULL);
  std::cout<< "please check manager!"<<std::endl;
  EVP_PKEY_free(priv_key);
  return 0;
}

/*
int main(int argc, char **argv) {
  CLI::App app{"nksu userspace tool"};

  std::string key, token;
  bool id_enabled = false;

  auto opt_id =
      app.add_flag("-i,--id", id_enabled, "Apply manager authentication.");

  auto opt_key = app.add_option("-k,--key", key, "Authentication key");
  auto opt_token = app.add_option("-t,--token", token, "totp key");

  opt_key->needs(opt_id);
  opt_token->needs(opt_id);

  CLI11_PARSE(app, argc, argv);

if(argc==1){
  get_root();
}
  if (id_enabled) {
    if (key.empty()||token.empty()) {
      std::cerr << " need: -k " << std::endl;
      std::cerr << " need: -t " << std::endl;
    }else
    if ((AuthenticationManager(key, token)) == -1) {
      ERR_print_errors_fp(stderr);
    }
  }

  return 0;
}
*/