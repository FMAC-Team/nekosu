#ifndef _KEY_H_
#define _KEY_H_

#include <linux/types.h>

struct keys {
	const u8 *ecc_public_key_der;
	size_t ecc_public_key_der_len;
	const char *totp_secret_key;
};

extern const struct keys key;

#endif
