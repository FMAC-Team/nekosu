// SPDX-License-Identifier: GPL-3.0-or-later
/* FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <linux/hash.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <crypto/public_key.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define USERSPACE_SIGN_MAGIC "SIGN:"
#define USERSPACE_SIGN_MAGIC_LEN 5
#define USERSPACE_SIGN_LEN 256
#define TOTAL_SIGN_TRAILER_SIZE                                                \
  (USERSPACE_SIGN_MAGIC_LEN + USERSPACE_SIGN_LEN) // 5 + 256 = 261

static u8 rsa_modulus[] = {
    0x00, 0xf7, 0xfd, 0xe3, 0x51, 0xed, 0x8e, 0x3c, 0x90, 0x79, 0xb8, 0x5f,
    0x42, 0x13, 0x32, 0x11, 0x44, 0x1e, 0x4c, 0x2b, 0xea, 0x24, 0x7d, 0x12,
    0x22, 0xc2, 0x01, 0xd2, 0xe1, 0xd8, 0x3d, 0xee, 0x54, 0x5e, 0x7c, 0xe7,
    0x22, 0x24, 0xfb, 0xcc, 0x5f, 0x6f, 0x1c, 0xab, 0x0a, 0xca, 0xe9, 0xf9,
    0xc2, 0x7b, 0x3e, 0x27, 0xb7, 0xdf, 0x8f, 0xa9, 0x20, 0x27, 0xea, 0x85,
    0x21, 0x33, 0x40, 0x51, 0xe5, 0x79, 0xe3, 0xfd, 0x46, 0xa3, 0xcd, 0x22,
    0x5e, 0xf8, 0x1f, 0x3c, 0x05, 0x46, 0x5e, 0x0d, 0xde, 0x27, 0x8e, 0xbe,
    0x49, 0x40, 0xaf, 0xfd, 0x78, 0x72, 0x07, 0xfb, 0x10, 0x93, 0x9b, 0xf5,
    0xa2, 0x94, 0x0d, 0xc7, 0xb9, 0x98, 0x76, 0x54, 0x46, 0xbe, 0xec, 0xdd,
    0xa3, 0x27, 0xd5, 0x50, 0xcf, 0xe3, 0x26, 0xbc, 0xc7, 0x8c, 0x58, 0x43,
    0x25, 0x1a, 0xec, 0x9b, 0x59, 0x4f, 0xa7, 0xfa, 0x2f, 0x8a, 0xb1, 0x41,
    0x25, 0x5f, 0xc1, 0x9a, 0x8a, 0xe2, 0x15, 0xf6, 0x23, 0x7e, 0x91, 0x29,
    0xbb, 0xf2, 0x75, 0x55, 0x46, 0xe8, 0x01, 0xbe, 0x9a, 0xa3, 0x72, 0x9c,
    0xd1, 0xd3, 0xee, 0xa2, 0x83, 0x91, 0xc8, 0xeb, 0xdd, 0x10, 0xf7, 0x33,
    0x72, 0x47, 0x73, 0x50, 0xbe, 0xbf, 0x9d, 0xae, 0x85, 0x55, 0x3b, 0x17,
    0x5c, 0x69, 0xa6, 0x30, 0xe4, 0x51, 0xbd, 0xe9, 0x56, 0xa2, 0x6a, 0xd9,
    0x26, 0xbd, 0x85, 0xbb, 0x68, 0x0a, 0x5f, 0xfe, 0x27, 0x02, 0x05, 0xb9,
    0x6d, 0x83, 0xca, 0xd7, 0x30, 0xcb, 0x08, 0xa8, 0x1c, 0x4f, 0xca, 0x0b,
    0x65, 0x2f, 0x5c, 0x25, 0x0b, 0x27, 0x81, 0xfc, 0x65, 0x4b, 0x35, 0x4c,
    0x09, 0x0f, 0x3b, 0xa5, 0xe6, 0x76, 0xd0, 0x3a, 0x1c, 0xe9, 0xc8, 0x3a,
    0xb7, 0x84, 0x40, 0x71, 0xff, 0x6e, 0xe8, 0x97, 0x82, 0x85, 0xdc, 0x62,
    0xf9, 0xac, 0xb5, 0xdc, 0x67};
static const u8 rsa_exponent[] = {0x01, 0x00, 0x01}; // 65537

static int calc_sha256(const u8 *data, size_t len, u8 *out) {
  struct crypto_shash *tfm;
  struct shash_desc *desc;
  int ret;

  tfm = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(tfm))
    return PTR_ERR(tfm);

  desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
  if (!desc) {
    crypto_free_shash(tfm);
    return -ENOMEM;
  }

  desc->tfm = tfm;
  desc->flags = 0;

  ret = crypto_shash_init(desc);
  if (ret)
    goto out_free_desc;
  ret = crypto_shash_update(desc, data, len);
  if (ret)
    goto out_free_desc;
  ret = crypto_shash_final(desc, out);

out_free_desc:
  kfree(desc);
  crypto_free_shash(tfm);
  return ret;
}

static int sigcheck_verify_signature(const u8 *digest, const u8 *sig, size_t sig_len) {
  struct public_key_signature sig_info = {
      .digest = (u8 *)digest,
      .digest_size = SHA256_DIGEST_SIZE,
      .s = (u8 *)sig,
      .s_size = sig_len,
      .hash_algo = "sha256",
      .pkey_algo = "rsa",
  };

  struct public_key pub = {
      .key = rsa_modulus,
      .keylen = sizeof(rsa_modulus),
      .pkey_algo = "rsa",
  };

  return public_key_verify_signature(&pub, &sig_info);
}


bool sigcheck_verify_file(struct file *filp) {
    loff_t file_size;
    mm_segment_t old_fs;
    u8 *file_content_buf = NULL;
    u8 digest[SHA256_DIGEST_SIZE];
    u8 magic_buffer[USERSPACE_SIGN_MAGIC_LEN];
    u8 *signature_buffer = NULL;
    loff_t content_len;
    bool ret = false;

    file_size = i_size_read(file_inode(filp));
    if (file_size < TOTAL_SIGN_TRAILER_SIZE) {
        printk(KERN_DEBUG "FMAC: File too small (%lld bytes) for signature check (min %d bytes)\n",
               file_size, TOTAL_SIGN_TRAILER_SIZE);
        return false;
    }

    content_len = file_size - TOTAL_SIGN_TRAILER_SIZE;
    if (content_len <= 0) {
        printk(KERN_DEBUG "FMAC: Content length is zero or negative.\n");
        return false;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    if (kernel_read(filp, file_size - TOTAL_SIGN_TRAILER_SIZE, magic_buffer,
                    USERSPACE_SIGN_MAGIC_LEN) != USERSPACE_SIGN_MAGIC_LEN) {
        printk(KERN_ERR "FMAC: Failed to read magic.\n");
        goto out;
    }

    if (memcmp(magic_buffer, USERSPACE_SIGN_MAGIC, USERSPACE_SIGN_MAGIC_LEN) != 0) {
        printk(KERN_DEBUG "FMAC: Magic mismatch. Expected '%s', got '%*phN'\n",
               USERSPACE_SIGN_MAGIC, USERSPACE_SIGN_MAGIC_LEN, magic_buffer);
        goto out;
    }

    signature_buffer = vmalloc(USERSPACE_SIGN_LEN);
    if (!signature_buffer) {
        printk(KERN_ERR "FMAC: Failed to allocate memory for signature.\n");
        goto out;
    }
    if (kernel_read(filp, file_size - USERSPACE_SIGN_LEN,
                    signature_buffer, USERSPACE_SIGN_LEN) != USERSPACE_SIGN_LEN) {
        printk(KERN_ERR "FMAC: Failed to read signature.\n");
        goto out;
    }

    file_content_buf = vmalloc(content_len);
    if (!file_content_buf) {
        printk(KERN_ERR "FMAC: Failed to allocate memory for file content.\n");
        goto out;
    }
    if (kernel_read(filp, 0, file_content_buf, content_len) != content_len) {
        printk(KERN_ERR "FMAC: Failed to read file content.\n");
        goto out;
    }

    if (calc_sha256(file_content_buf, content_len, digest) != 0) {
        printk(KERN_ERR "FMAC: Failed to calculate SHA256.\n");
        goto out;
    }

    if (sigcheck_verify_signature(digest, signature_buffer, USERSPACE_SIGN_LEN) == 0) {
        printk(KERN_INFO "FMAC: File signature VERIFIED successfully.\n");
        ret = true;
    } else {
        printk(KERN_WARNING "FMAC: File signature VERIFICATION FAILED.\n");
    }

out:
    if (file_content_buf)
        vfree(file_content_buf);
    if (signature_buffer)
        vfree(signature_buffer);
    set_fs(old_fs);
    return ret;
}