/* SPDX-License-Identifier: GPL-3.0 */
#ifndef __NKSU_PROFILE_H
#define __NKSU_PROFILE_H

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/list.h>
#include <linux/rcupdate.h>

struct profile {
	kernel_cap_t caps;
	char selinux_domain[64];
	int namespace;
};

int nksu_profile_init(void);

int nksu_profile_get_dup(uid_t uid, struct profile *out_buf);

int nksu_profile_set(uid_t uid, kernel_cap_t caps, const char *domain, int ns);

int nksu_profile_set_caps(uid_t uid, kernel_cap_t caps);

int nksu_profile_set_domain(uid_t uid, const char *domain);

int nksu_profile_set_ns(uid_t uid, int ns);

int nksu_profile_set_default(uid_t uid);

bool nksu_profile_has_uid(uid_t uid);

void nksu_profile_clear(uid_t uid);

void nksu_profile_clear_all(void);

#endif /* __NKSU_PROFILE_H */
