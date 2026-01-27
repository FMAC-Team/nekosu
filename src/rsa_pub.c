// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/akcipher.h>
#include <crypto/hash.h>

#include <fmac.h>
#include <key.h>

static const u8 ecc_public_key_der[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x7c, 0x47, 0xba, 0x6d, 0xa3,
    0x8d, 0xd4, 0x24, 0x2b, 0xfa, 0xc3, 0xd9, 0x86, 0x64, 0x55, 0x40, 0xdb, 0x9b, 0x01, 0x46, 0x49,
    0x19, 0x8d, 0x92, 0xdb, 0xe2, 0x38, 0x24, 0x2a, 0x99, 0x9c, 0xec, 0x46, 0xa6, 0x83, 0x6b, 0x5b,
    0x91, 0x41, 0x5f, 0x05, 0x9a, 0x86, 0x5f, 0x91, 0x76, 0x76, 0xf1, 0xa4, 0xa9, 0xf1, 0x25, 0x53,
    0x84, 0x6d, 0xea, 0xf8, 0x72, 0x41, 0x53, 0x08, 0x68, 0x28, 0xe8};

static const char totp_secret_key[] = "P2U6KVKZKSFKXGXO7XN6S6X62X6M6NE7";

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
const struct keys key __ro_after_init = {
#else
const struct keys key = {
#endif
    .ecc_public_key_der = ecc_public_key_der,
    .ecc_public_key_der_len = sizeof(ecc_public_key_der),
    .totp_secret_key = totp_secret_key,
};

static int compute_sha256(const u8 *data, unsigned int data_len, u8 *hash)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, data, data_len, hash);

    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

int ecc_verify_signature(const u8 *signature, unsigned int sig_len, u32 totp_code)
{
    struct crypto_akcipher *tfm = NULL;
    struct akcipher_request *req = NULL;
    struct crypto_wait cwait;
    struct scatterlist src, dst;
    u8 hash[32]; /* SHA-256 hash */
    u8 *sig_der = NULL;
    unsigned int sig_der_len;
    int ret;

    u8 totp_str[12];
    int totp_len = snprintf(totp_str, sizeof(totp_str), "%u", totp_code);

    ret = compute_sha256(totp_str, totp_len, hash);
    if (ret)
    {
        f_log("FMAC: SHA-256 computation failed: %d\n", ret);
        return ret;
    }

    /* Allocate ECDSA cipher */
    tfm = crypto_alloc_akcipher("ecdsa", 0, 0);
    if (IS_ERR(tfm))
    {
        f_log("FMAC: Failed to allocate ECDSA cipher\n");
        return PTR_ERR(tfm);
    }

    /* Set public key */
    ret = crypto_akcipher_set_pub_key(tfm, key.ecc_public_key_der, key.ecc_public_key_der_len);
    if (ret)
    {
        f_log("FMAC: Failed to set ECC public key: %d\n", ret);
        goto out;
    }

    /* Allocate request */
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req)
    {
        ret = -ENOMEM;
        goto out;
    }

    sig_der = kmalloc(sig_len, GFP_KERNEL);
    if (!sig_der)
    {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(sig_der, signature, sig_len);
    sig_der_len = sig_len;

    sg_init_one(&src, sig_der, sig_der_len);
    sg_init_one(&dst, hash, sizeof(hash));

    crypto_init_wait(&cwait);
    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);

    akcipher_request_set_crypt(req, &src, &dst, sig_der_len, sizeof(hash));

    ret = crypto_wait_req(crypto_akcipher_verify(req), &cwait);
    if (ret)
    {
        f_log("FMAC: ECDSA signature verification failed: %d\n", ret);
    } else
    {
        f_log("FMAC: ECDSA signature verification succeeded\n");
    }

out:
    if (sig_der)
        kfree(sig_der);
    if (req)
        akcipher_request_free(req);
    if (tfm)
        crypto_free_akcipher(tfm);

    return ret;
}

int check_totp_ecc(const char __user *user_buf, size_t user_len)
{
    u8 *buffer = NULL;
    u32 k_totp;
    int ret = 0;

    if (user_len < 64 || user_len > 96)
    {
        f_log("FMAC: Invalid input length: %zu\n", user_len);
        return -EINVAL;
    }

    buffer = kmalloc(user_len, GFP_KERNEL);
    if (!buffer)
    {
        ret = -ENOMEM;
        goto out;
    }

    if (copy_from_user(buffer, user_buf, user_len))
    {
        ret = -EFAULT;
        goto out;
    }

    k_totp = generate_totp_base32(key.totp_secret_key);

    ret = ecc_verify_signature(buffer, user_len, k_totp);
    if (ret)
    {
        f_log("FMAC: ECDSA signature verification failed\n");
        ret = -1;
        goto out;
    }

out:
    if (buffer)
    {
        memzero_explicit(buffer, user_len);
        kfree(buffer);
    }
    return ret;
}
