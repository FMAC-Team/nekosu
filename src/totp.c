// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * FMAC - File Monitoring and Access Control Kernel Module
 * Copyright (C) 2025 Aqnya
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/version.h>
#include <crypto/hash.h>

#define TOTP_STEP        30
#define SHA1_DIGEST_SIZE 20

static char *totp_secret_key = "Hello!..........";
static int totp_secret_len = 16;

static u64 get_kernel_current_time(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    struct timespec ts;
    getnstimeofday(&ts);
    return (u64)ts.tv_sec;
#else
    return (u64)ktime_get_real_seconds();
#endif
}

static int calc_hmac_sha1(const u8 *key, int key_len, const u8 *data, int data_len, u8 *output)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "TOTP: Failed to allocate transform for hmac(sha1)\n");
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    ret = crypto_shash_setkey(tfm, key, key_len);
    if (ret) {
        printk(KERN_ERR "TOTP: Fail to set key\n");
        goto out;
    }

    ret = crypto_shash_digest(desc, data, data_len, output);

out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

static u32 generate_totp(const u8 *key, int key_len)
{
    u64 current_time;
    u64 time_counter;
    u64 time_counter_be; // Big Endian
    u8 hash[SHA1_DIGEST_SIZE];
    int offset;
    u32 binary;
    u32 otp;

    current_time = get_kernel_current_time();
    time_counter = current_time / TOTP_STEP;

    printk(KERN_INFO "TOTP: Unix Time: %llu, Counter: %llu\n", current_time, time_counter);

    time_counter_be = cpu_to_be64(time_counter);

    if (calc_hmac_sha1(key, key_len, (u8 *)&time_counter_be, sizeof(time_counter_be), hash) != 0) {
        return 0;
    }

    offset = hash[SHA1_DIGEST_SIZE - 1] & 0x0F;

    binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) |
             ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

    otp = binary % 1000000;

    return otp;
}

int totp_init(void)
{
    u32 code;

    printk(KERN_INFO "TOTP: Module Loaded\n");

    code = generate_totp((u8 *)totp_secret_key, totp_secret_len);

    printk(KERN_INFO "TOTP: Generated Code: %06u\n", code);

    return 0;
}