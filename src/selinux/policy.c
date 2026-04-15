// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <fmac.h>

#include "ss/avtab.h"

struct sepolicy_rule {
	const char *src;
	const char *tgt;
	const char *cls;
	const char *perm;
	int effect;
	bool invert;
};

#define RULE(_src, _tgt, _cls, _perm, _effect) \
    { .src = (_src), .tgt = (_tgt), .cls = (_cls), .perm = (_perm), \
      .effect = (_effect), .invert = false }

#define ALLOW(_src, _tgt, _cls, _perm) \
    RULE(_src, _tgt, _cls, _perm, AVTAB_ALLOWED)

#define DENY(_src, _tgt, _cls, _perm) \
    RULE(_src, _tgt, _cls, _perm, AVTAB_ALLOWED)	/* invert handled separately if needed */

struct sepolicy_group {
	const char *name;
	const struct sepolicy_rule *rules;
	size_t count;
};

static const struct sepolicy_rule pkg_rules[] = {
	ALLOW("nksu", "package_service", "service_manager", "find"),
	ALLOW("nksu", "system_server", "binder", "call"),
	ALLOW("nksu", "system_server", "binder", "transfer"),
	ALLOW("system_server", "nksu", "binder", "call"),
};

static const struct sepolicy_rule su_rules[] = {
	ALLOW("nksu", "nksu", "process", "fork"),
	ALLOW("nksu", "nksu", "process", "sigchld"),
	ALLOW("nksu", "shell_data_file", "file", "read"),
	ALLOW("nksu", "shell_data_file", "file", "write"),
	ALLOW("nksu", "shell_data_file", "file", "open"),
};

#define GROUP(_name, _rules) \
    { .name = (_name), .rules = (_rules), .count = ARRAY_SIZE(_rules) }

static const struct sepolicy_group policy_groups[] = {
	GROUP("package_manager", pkg_rules),
	GROUP("su_basic", su_rules),
};

static int apply_group(const struct sepolicy_group *grp)
{
	size_t i;
	int ret;
	int failed = 0;

	for (i = 0; i < grp->count; i++) {
		const struct sepolicy_rule *r = &grp->rules[i];

		ret = sepolicy_add_rule(r->src, r->tgt, r->cls, r->perm,
					r->effect, r->invert);
		if (ret) {
			pr_warn
			    ("[selinux:%s]: %s %s:%s %s -> err %d (skipped)\n",
			     grp->name, r->src, r->tgt, r->cls, r->perm, ret);
			failed++;
		}
	}

	if (failed) {
		pr_warn("[selinux:%s]: %d/%zu rule(s) failed\n",
			grp->name, failed, grp->count);
		return -ENOEXEC;
	}

	pr_info("[selinux:%s]: %zu rule(s) applied\n", grp->name, grp->count);
	return 0;
}

int load_policy(void)
{
	size_t i;
	int ret;
	int failed_groups = 0;

	pr_info("[selinux]: loading %zu policy group(s)\n",
		ARRAY_SIZE(policy_groups));

	for (i = 0; i < ARRAY_SIZE(policy_groups); i++) {
		ret = apply_group(&policy_groups[i]);
		if (ret)
			failed_groups++;
	}

	if (failed_groups) {
		pr_err("[selinux]: %d group(s) had failures\n", failed_groups);
		return -ENOEXEC;
	}

	pr_info("[selinux]: all policy groups applied successfully\n");
	return 0;
}

int __init sepolicy_init(void)
{
	int ret;

	pr_info("[selinux]: sepolicy init\n");

	ret = load_policy();
	if (ret)
		pr_err("[selinux]: load_policy failed: %d\n", ret);

	return ret;
}

void __exit sepolicy_exit(void)
{
	pr_info("[selinux]: sepolicy exit\n");
}
