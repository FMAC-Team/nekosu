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

static const struct sepolicy_rule global_file_access_rules[] = {
	ALLOW(DOMAIN, NULL, "file", "read"),
	ALLOW(DOMAIN, NULL, "file", "open"),
	ALLOW(DOMAIN, NULL, "file", "getattr"),
	ALLOW(DOMAIN, NULL, "file", "execute"),
	ALLOW(DOMAIN, NULL, "file", "execute_no_trans"),
	ALLOW(DOMAIN, NULL, "file", "map"),
	ALLOW(DOMAIN, NULL, "dir", "read"),
	ALLOW(DOMAIN, NULL, "dir", "open"),
	ALLOW(DOMAIN, NULL, "dir", "search"),
	ALLOW(DOMAIN, NULL, "dir", "getattr"),
	ALLOW(DOMAIN, NULL, "lnk_file", "read"),
	ALLOW(DOMAIN, NULL, "lnk_file", "getattr"),
};

static const struct sepolicy_rule pkg_rules[] = {
	ALLOW(DOMAIN, "package_native_service", "service_manager", "find"),
	ALLOW(DOMAIN, "activity_service", "service_manager", "find"),
	ALLOW(DOMAIN, "system_server", "fd", "use"),
    ALLOW(DOMAIN, "servicemanager", "fd", "use"),
    ALLOW("system_server", DOMAIN, "fd", "use"), 
};

static const struct sepolicy_rule transition_rules[] = {
	ALLOW("shell", DOMAIN, "process", "transition"),
	ALLOW("untrusted_app", DOMAIN, "process", "sigchld"),
	ALLOW("untrusted_app", DOMAIN, "process", "setpgid"),
	ALLOW("untrusted_app", DOMAIN, "process", "getpgid"),
	ALLOW("untrusted_app", DOMAIN, "process", "signull"),
};

static const struct sepolicy_rule debug_rules[] = {
	ALLOW(DOMAIN, "domain", "process", "ptrace"),
	ALLOW(DOMAIN, "domain", "process", "signull"),
	ALLOW(DOMAIN, "domain", "process", "signal"),
	ALLOW(DOMAIN, "domain", "process", "sigkill"),
	ALLOW(DOMAIN, "domain", "process", "getpgid"),
	ALLOW(DOMAIN, "domain", "process", "setsched"),
};

static const struct sepolicy_rule fs_rules[] = {
	ALLOW(DOMAIN, "device", "dir", "write"),
	ALLOW(DOMAIN, "null_device", "chr_file", "read"),
	ALLOW(DOMAIN, "null_device", "chr_file", "write"),
	ALLOW(DOMAIN, "zero_device", "chr_file", "read"),
	ALLOW(DOMAIN, "kmsg_device", "chr_file", "write"),
	ALLOW(DOMAIN, "adb_data_file", "file", "write"),
	ALLOW(DOMAIN, "adb_data_file", "file", "create"),
};

static const struct sepolicy_rule svc_rules[] = {
	ALLOW(DOMAIN, "servicemanager", "service_manager", "list"),
	ALLOW(DOMAIN, "servicemanager", "service_manager", "find"),
	ALLOW(DOMAIN, "service_manager_type", "service_manager", "find"),
};

static const struct sepolicy_rule binder_rules[] = {
	ALLOW(DOMAIN, "binder_device", "chr_file", NULL),
	ALLOW(DOMAIN, NULL, "binder", NULL),
	ALLOW("servicemanager", DOMAIN, "binder", NULL),
	ALLOW("system_server", DOMAIN, "binder", "call"),
	ALLOW("system_server", DOMAIN, "binder", "transfer"),
    ALLOW("installd", DOMAIN, "binder", "call"),
};

static const struct sepolicy_rule prop_ext_rules[] = {
	ALLOW(DOMAIN, "property_socket", "sock_file", "write"),
	ALLOW(DOMAIN, "init", "unix_stream_socket", "connectto"),
	ALLOW(DOMAIN, "default_prop", "property_service", "set"),
	ALLOW(DOMAIN, "system_prop", "property_service", "set"),
	ALLOW(DOMAIN, "exported_config_prop", "property_service", "set"),
};

static const struct sepolicy_rule net_rules[] = {
	ALLOW(DOMAIN, DOMAIN, "udp_socket", NULL),
	ALLOW(DOMAIN, DOMAIN, "tcp_socket", NULL),
	ALLOW(DOMAIN, "node", "tcp_socket", "node_bind"),
	ALLOW(DOMAIN, "port", "tcp_socket", "name_connect"),
	ALLOW(DOMAIN, DOMAIN, "unix_dgram_socket", NULL),
	ALLOW(DOMAIN, DOMAIN, "unix_stream_socket", NULL),
};

static const struct sepolicy_rule cap_rules[] = {
	ALLOW(DOMAIN, DOMAIN, "capability", NULL),
};

static const struct sepolicy_rule su_rules[] = {
	ALLOW(DOMAIN, DOMAIN, "fd", "use"),
	ALLOW(DOMAIN, NULL, "fifo_file", NULL),
	ALLOW(DOMAIN, "shell_data_file", "file", "write"),
	ALLOW(DOMAIN, NULL, "process", NULL),
};

static const struct sepolicy_rule su_fix_rules[] = {
	ALLOW(DOMAIN, "system_file", "file", "entrypoint"),
	ALLOW(DOMAIN, "shell", "fd", "use"),
	ALLOW("shell", DOMAIN, "fd", "use"),
	ALLOW(DOMAIN, "devpts", "chr_file", "read"),
	ALLOW(DOMAIN, "devpts", "chr_file", "write"),
	ALLOW(DOMAIN, "devpts", "chr_file", "ioctl"),
	ALLOW(DOMAIN, "devpts", "chr_file", "open"),
	ALLOW("shell", DOMAIN, "process", "sigchld"),
	ALLOW(DOMAIN, "untrusted_app_all_devpts", "chr_file", "write"),
	ALLOW(DOMAIN, "untrusted_app_all_devpts", "chr_file", "read"),
	ALLOW(DOMAIN, "untrusted_app_all_devpts", "chr_file", "open"),
	ALLOW(DOMAIN, "untrusted_app_all_devpts", "chr_file", "ioctl"),
	ALLOW(DOMAIN, "untrusted_app_all_devpts", "chr_file", "getattr"),
	ALLOW(DOMAIN, DOMAIN, "lockdown", NULL),
};

static const struct sepolicy_rule klog_rules[] = {
	ALLOW(DOMAIN, "kernel", "system", "syslog_read"),
	ALLOW(DOMAIN, "kmsg_device", "chr_file", NULL),
};

#define GROUP(_name, _rules, _required) \
    { .name = (_name), .rules = (_rules), .count = ARRAY_SIZE(_rules), \
      .required = (_required) }

static const struct sepolicy_group policy_groups[] = {
	GROUP("global_file_access", global_file_access_rules, true),
	GROUP("package_manager", pkg_rules, true),
	GROUP("su_basic", su_rules, true),
	GROUP("su_fix", su_fix_rules, true),
	GROUP("service", svc_rules, true),
	GROUP("binder", binder_rules, true),
	GROUP("prop_ext", prop_ext_rules, false),
	GROUP("cap", cap_rules, true),
	GROUP("fs_access", fs_rules, false),
	GROUP("debug", debug_rules, false),
	GROUP("net", net_rules, false),
	GROUP("transition", transition_rules, true),
	GROUP("klog", klog_rules, true),
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
