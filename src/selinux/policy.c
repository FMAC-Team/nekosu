#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <fmac.h>

#include "ss/avtab.h"
#include "security.h"

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

static const struct sepolicy_rule su_rules[] = {
	ALLOW(DOMAIN, NULL, NULL, NULL),
};

static const struct sepolicy_rule ksu_rules[] = {
   ALLOW("servicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ALLOW("servicemanager", KERNEL_SU_DOMAIN, "dir", "read");
    ALLOW("servicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ALLOW("servicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ALLOW("servicemanager", KERNEL_SU_DOMAIN, "process", "getattr");
    ALLOW("domain", KERNEL_SU_DOMAIN, "process", "sigchld");

    // allowLog
    ALLOW("logd", KERNEL_SU_DOMAIN, "dir", "search");
    ALLOW("logd", KERNEL_SU_DOMAIN, "file", "read");
    ALLOW("logd", KERNEL_SU_DOMAIN, "file", "open");
    ALLOW("logd", KERNEL_SU_DOMAIN, "file", "getattr");

    // dumpsys, send fd
    ALLOW("domain", KERNEL_SU_DOMAIN, "fd", "use");
    ALLOW("domain", KERNEL_SU_DOMAIN, "fifo_file", "write");
    ALLOW("domain", KERNEL_SU_DOMAIN, "fifo_file", "read");
    ALLOW("domain", KERNEL_SU_DOMAIN, "fifo_file", "open");
    ALLOW("domain", KERNEL_SU_DOMAIN, "fifo_file", "getattr");

    // bootctl
    ALLOW("hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ALLOW("hwservicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ALLOW("hwservicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ALLOW("hwservicemanager", KERNEL_SU_DOMAIN, "process", "getattr");

    // Allow all binder transactions
    ALLOW("domain", KERNEL_SU_DOMAIN, "binder", ALL);

    // Allow system server kill su process
    ALLOW("system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
    ALLOW("system_server", KERNEL_SU_DOMAIN, "process", "sigkill");
};

#define GROUP(_name, _rules, _required) \
    { .name = (_name), .rules = (_rules), .count = ARRAY_SIZE(_rules), \
      .required = (_required) }

static const struct sepolicy_group policy_groups[] = {
	GROUP("su_basic", su_rules, true),
	GROUP("ksu_rules",ksu_rules,true),
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

	sepolicy_add_typeattribute(DOMAIN, "mlstrustedsubject");
	sepolicy_add_typeattribute(DOMAIN, "netdomain");
	sepolicy_add_typeattribute(DOMAIN, "bluetoothdomain");

		sepolicy_add_xperm(DOMAIN, NULL, "blk_file", NULL,
				   AVTAB_XPERMS_ALLOWED, false);
		sepolicy_add_xperm(DOMAIN, NULL, "fifo_file", NULL,
				   AVTAB_XPERMS_ALLOWED, false);
		sepolicy_add_xperm(DOMAIN, NULL, "chr_file", NULL,
				   AVTAB_XPERMS_ALLOWED, false);
		sepolicy_add_xperm(DOMAIN, NULL, "file", NULL,
				   AVTAB_XPERMS_ALLOWED, false);

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
		pr_err
		    ("[selinux]: load_policy failed: %d, continuing with partial policy\n",
		     ret);
	}
	return 0;
}

void __exit sepolicy_exit(void)
{
	pr_info("[selinux]: sepolicy exit\n");
}
