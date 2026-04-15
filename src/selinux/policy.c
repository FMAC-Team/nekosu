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

#define RULE(_src, _tgt, _cls, _perm, _effect, _invert) \
    { .src = (_src), .tgt = (_tgt), .cls = (_cls), .perm = (_perm), \
      .effect = (_effect), .invert = (_invert) }

#define ALLOW(_src, _tgt, _cls, _perm) \
    RULE(_src, _tgt, _cls, _perm, AVTAB_ALLOWED, false)

#define DENY(_src, _tgt, _cls, _perm) \
    RULE(_src, _tgt, _cls, _perm, AVTAB_AUDITDENY, true)

struct sepolicy_group {
	const char *name;
	const struct sepolicy_rule *rules;
	size_t count;
	bool required;
};

static const struct sepolicy_rule pkg_rules[] = {
	ALLOW("nksu", "package_native_service",  "service_manager", "find"),
	ALLOW("nksu", "activity_service",        "service_manager", "find"),
	ALLOW("nksu",          "system_server", "binder", "call"),
	ALLOW("nksu",          "system_server", "binder", "transfer"),
	ALLOW("system_server", "nksu",          "binder", "call"),
	ALLOW("system_server", "nksu",          "binder", "transfer"),
};

static const struct sepolicy_rule svc_rules[] = {
	ALLOW("nksu", "servicemanager", "service_manager", "list"),
	ALLOW("nksu", "servicemanager", "service_manager", "find"),
	ALLOW("nksu", "service_manager_type", "service_manager", "find"),
};

static const struct sepolicy_rule binder_rules[] = {
	ALLOW("nksu", "servicemanager", "binder", "call"),
	ALLOW("nksu", "servicemanager", "binder", "transfer"),

	ALLOW("nksu", "system_server", "binder", "call"),
	ALLOW("nksu", "system_server", "binder", "transfer"),

	ALLOW("system_server", "nksu", "binder", "call"),
	ALLOW("system_server", "nksu", "binder", "transfer"),
};

static const struct sepolicy_rule prop_rules[] = {
	ALLOW("nksu", "default_prop", "file", "read"),
	ALLOW("nksu", "default_prop", "file", "open"),
	ALLOW("nksu", "default_prop", "file", "getattr"),
	ALLOW("nksu", "default_prop", "file", "map"),

	ALLOW("nksu", "system_prop", "file", "read"),
	ALLOW("nksu", "system_prop", "file", "open"),
	ALLOW("nksu", "system_prop", "file", "getattr"),
	ALLOW("nksu", "system_prop", "file", "map"),

	ALLOW("nksu", "vendor_prop", "file", "read"),
	ALLOW("nksu", "vendor_prop", "file", "open"),
	ALLOW("nksu", "vendor_prop", "file", "getattr"),
	ALLOW("nksu", "vendor_prop", "file", "map"),
};

static const struct sepolicy_rule exec_rules[] = {
	ALLOW("nksu", "zygote_exec", "file", "read"),
	ALLOW("nksu", "zygote_exec", "file", "open"),
	ALLOW("nksu", "zygote_exec", "file", "execute"),
	ALLOW("nksu", "zygote_exec", "file", "map"),

	ALLOW("nksu", "toolbox_exec", "file", "execute"),
	ALLOW("nksu", "shell_exec",   "file", "execute"),
};

static const struct sepolicy_rule cap_rules[] = {
	ALLOW("nksu", "nksu", "capability", "dac_override"),
	ALLOW("nksu", "nksu", "capability", "dac_read_search"),
	ALLOW("nksu", "nksu", "capability", "setuid"),
	ALLOW("nksu", "nksu", "capability", "setgid"),
};

static const struct sepolicy_rule fd_rules[] = {
	ALLOW("nksu", "untrusted_app", "fd", "use"),
};

static const struct sepolicy_rule su_rules[] = {
	ALLOW("nksu", "nksu", "process", "fork"),
	ALLOW("nksu", "nksu", "process", "sigchld"),
	ALLOW("nksu", "nksu", "process", "transition"),
	ALLOW("nksu", "nksu",           "fd",        "use"),
	ALLOW("nksu", "nksu",           "fifo_file", "read"),
	ALLOW("nksu", "nksu",           "fifo_file", "write"),
	ALLOW("nksu", "nksu",           "fifo_file", "open"),
	ALLOW("nksu", "nksu",           "fifo_file", "getattr"),
	ALLOW("nksu", "system_file", "file", "read"),
	ALLOW("nksu", "system_file", "file", "open"),
	ALLOW("nksu", "system_file", "file", "execute"),
	ALLOW("nksu", "system_file", "file", "getattr"),
	ALLOW("nksu", "shell_data_file", "file", "read"),
	ALLOW("nksu", "shell_data_file", "file", "write"),
	ALLOW("nksu", "shell_data_file", "file", "open"),
};

#define GROUP(_name, _rules, _required) \
    { .name = (_name), .rules = (_rules), .count = ARRAY_SIZE(_rules), \
      .required = (_required) }

static const struct sepolicy_group policy_groups[] = {
	GROUP("package_manager", pkg_rules, true),
	GROUP("su_basic",        su_rules,  true),
	GROUP("service", svc_rules, true),
	GROUP("binder",  binder_rules, true),
	GROUP("prop",    prop_rules, true),
	GROUP("exec",    exec_rules, true),
	GROUP("cap",     cap_rules, true),
	GROUP("fd",      fd_rules, false),
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
			pr_warn("[selinux:%s]: %s %s:%s %s -> err %d (skipped)\n",
				grp->name, r->src, r->tgt, r->cls, r->perm, ret);
			failed++;
		}
	}

	if (failed) {
		pr_warn("[selinux:%s]: %d/%zu rule(s) failed\n",
			grp->name, failed, grp->count);
		if (grp->required)
			return -ENOEXEC;
	}

	pr_info("[selinux:%s]: %zu rule(s) applied (%d failed)\n",
		grp->name, grp->count - failed, failed);
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
	if (ret) {
		pr_err("[selinux]: load_policy failed: %d, continuing with partial policy\n", ret);
	}

	return 0;
}

void __exit sepolicy_exit(void)
{
	pr_info("[selinux]: sepolicy exit\n");
}
