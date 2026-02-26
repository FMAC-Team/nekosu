#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/types.h>

#include <fmac.h>
#include <key.h>

static struct {
	u32 code;
	unsigned long expires;
	bool used;
	spinlock_t lock;
} totp_cache;

static const char totp_secret_key[] = "P2U6KVKZKSFKXGXO7XN6S6X62X6M6NE7";

static inline u32 get_cached_totp(void)
{
    unsigned long now = jiffies;
    u32 code;

    spin_lock(&totp_cache.lock);

    if (time_after_eq(now, totp_cache.expires)) {
        totp_cache.code = generate_totp_base32(totp_secret_key);
        totp_cache.expires = now + msecs_to_jiffies(5000);
        totp_cache.used = false;
    }

    code = totp_cache.code;

    spin_unlock(&totp_cache.lock);

    return code;
}
bool check(size_t code)
{
    bool ok = false;
    u32 real = get_cached_totp();

    spin_lock(&totp_cache.lock);

    if (!totp_cache.used &&
        real == code &&
        time_before(jiffies, totp_cache.expires)) {

        totp_cache.used = true;
        ok = true;
    }

    spin_unlock(&totp_cache.lock);

    if (!ok)
        pr_info("real totp code: %u\n", real);

    return ok;
}