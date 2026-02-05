#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <linux/jiffies.h>

#include <fmac.h>
#include <key.h>

static struct crypto_shash *tfm_sha256;
static struct crypto_akcipher *tfm_ecdsa;

static struct
{
    u32 code;
    unsigned long expires; /* jiffies */
    spinlock_t lock;
} totp_cache;

static const u8 ecc_public_key_der[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x7c, 0x47, 0xba, 0x6d, 0xa3,
    0x8d, 0xd4, 0x24, 0x2b, 0xfa, 0xc3, 0xd9, 0x86, 0x64, 0x55, 0x40, 0xdb, 0x9b, 0x01, 0x46, 0x49,
    0x19, 0x8d, 0x92, 0xdb, 0xe2, 0x38, 0x24, 0x2a, 0x99, 0x9c, 0xec, 0x46, 0xa6, 0x83, 0x6b, 0x5b,
    0x91, 0x41, 0x5f, 0x05, 0x9a, 0x86, 0x5f, 0x91, 0x76, 0x76, 0xf1, 0xa4, 0xa9, 0xf1, 0x25, 0x53,
    0x84, 0x6d, 0xea, 0xf8, 0x72, 0x41, 0x53, 0x08, 0x68, 0x28, 0xe8};

static const char totp_secret_key[] = "P2U6KVKZKSFKXGXO7XN6S6X62X6M6NE7";

int fmac_crypto_init(void)
{
    int ret;

    tfm_sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm_sha256))
    {
        pr_err("FMAC: Failed to alloc sha256 tfm\n");
        return PTR_ERR(tfm_sha256);
    }

    tfm_ecdsa = crypto_alloc_akcipher("ecdsa", 0, 0);
    if (IS_ERR(tfm_ecdsa))
    {
        pr_err("FMAC: Failed to alloc ecdsa tfm\n");
        crypto_free_shash(tfm_sha256);
        return PTR_ERR(tfm_ecdsa);
    }

    ret = crypto_akcipher_set_pub_key(tfm_ecdsa, ecc_public_key_der, sizeof(ecc_public_key_der));
    if (ret)
    {
        pr_err("FMAC: Failed to set public key\n");
        crypto_free_akcipher(tfm_ecdsa);
        crypto_free_shash(tfm_sha256);
        return ret;
    }

    spin_lock_init(&totp_cache.lock);
    totp_cache.expires = 0;

    return 0;
}

void fmac_crypto_exit(void)
{
    if (tfm_ecdsa)
        crypto_free_akcipher(tfm_ecdsa);
    if (tfm_sha256)
        crypto_free_shash(tfm_sha256);
}

static inline u32 get_cached_totp(void)
{
    unsigned long now = jiffies;
    u32 code;

    if (time_before(now, totp_cache.expires))
        return totp_cache.code;

    spin_lock(&totp_cache.lock);
    if (time_after_eq(now, totp_cache.expires))
    {
        totp_cache.code = generate_totp_base32(totp_secret_key);
        totp_cache.expires = now + msecs_to_jiffies(5000);
    }
    code = totp_cache.code;
    spin_unlock(&totp_cache.lock);

    return code;
}

static int compute_sha256_fast(const u8 *data, unsigned int data_len, u8 *hash)
{
    SHASH_DESC_ON_STACK(desc, tfm_sha256);
    int ret;

    desc->tfm = tfm_sha256;

    ret = crypto_shash_digest(desc, data, data_len, hash);

    shash_desc_zero(desc);
    return ret;
}

int ecc_verify_signature(const u8 *signature, unsigned int sig_len, u32 totp_code)
{
    struct akcipher_request *req = NULL;
    struct crypto_wait cwait;
    struct scatterlist src, dst;
    u8 hash[32];
    u8 sig_stack[96];
    int ret;
    u8 totp_str[12];
    int totp_len;

    totp_len = snprintf(totp_str, sizeof(totp_str), "%u", totp_code);

    ret = compute_sha256_fast(totp_str, totp_len, hash);
    if (ret)
        return ret;

    if (sig_len > sizeof(sig_stack))
        return -EINVAL;

    memcpy(sig_stack, signature, sig_len);

    req = akcipher_request_alloc(tfm_ecdsa, GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    sg_init_one(&src, sig_stack, sig_len);
    sg_init_one(&dst, hash, sizeof(hash));

    crypto_init_wait(&cwait);
    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &cwait);
    akcipher_request_set_crypt(req, &src, &dst, sig_len, sizeof(hash));

    ret = crypto_wait_req(crypto_akcipher_verify(req), &cwait);

    akcipher_request_free(req);

    if (ret)
        fmac_log("FMAC: ECDSA verify failed: %d\n", ret);

    return ret;
}

int check_totp_ecc(const char __user *user_buf, size_t user_len)
{
    u8 buffer[96];
    u32 k_totp;
    int ret;

    if (user_len < 64 || user_len > sizeof(buffer))
    {
        fmac_log("FMAC: Invalid length: %zu\n", user_len);
        return -EINVAL;
    }

    if (copy_from_user(buffer, user_buf, user_len))
        return -EFAULT;

    k_totp = get_cached_totp();
    ret = ecc_verify_signature(buffer, user_len, k_totp);
    memzero_explicit(buffer, sizeof(buffer));
    return (ret == 0) ? 1 : 0;
}
