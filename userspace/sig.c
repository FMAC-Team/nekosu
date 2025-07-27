// signelf.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define SIGN_MAGIC "SIGN:"
#define SIGN_LEN 256

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <input_elf> <private_key.pem> <output_elf>\n", argv[0]);
    return 1;
  }

  const char *elf_path = argv[1];
  const char *priv_key_path = argv[2];
  const char *output_path = argv[3];

  // 读取 ELF 文件
  FILE *f = fopen(elf_path, "rb");
  fseek(f, 0, SEEK_END);
  size_t elf_size = ftell(f);
  rewind(f);

  unsigned char *elf_data = malloc(elf_size);
  fread(elf_data, 1, elf_size, f);
  fclose(f);

  // 计算 SHA256
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(elf_data, elf_size, hash);

  // 加载私钥
  FILE *keyf = fopen(priv_key_path, "r");
  RSA *rsa = PEM_read_RSAPrivateKey(keyf, NULL, NULL, NULL);
  fclose(keyf);

  if (!rsa) {
    fprintf(stderr, "Failed to read private key\n");
    free(elf_data);
    return 1;
  }

  // 执行签名
  unsigned char sig[SIGN_LEN];
  unsigned int sig_len = 0;

  if (!RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &sig_len, rsa)) {
    fprintf(stderr, "RSA_sign failed\n");
    RSA_free(rsa);
    free(elf_data);
    return 1;
  }

  RSA_free(rsa);

  // 写入新文件：原 ELF + MAGIC + 签名
  FILE *out = fopen(output_path, "wb");
  fwrite(elf_data, 1, elf_size, out);
  fwrite(SIGN_MAGIC, 1, strlen(SIGN_MAGIC), out);
  fwrite(sig, 1, SIGN_LEN, out);
  fclose(out);

  printf("Signed ELF written to %s (appended %zu bytes)\n", output_path,
         strlen(SIGN_MAGIC) + SIGN_LEN);

  free(elf_data);
  return 0;
}