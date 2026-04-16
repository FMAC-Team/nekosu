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
	ALLOW("nksu", "package_native_service", "service_manager", "find"),
	ALLOW("nksu", "activity_service", "service_manager", "find"),
};

static const struct sepolicy_rule transition_rules[] = {
	ALLOW("shell", "nksu", "process", "transition"),
	ALLOW("nksu", "nksu", "process", "dyntransition"),
ALLOW("untrusted_app", "nksu", "process", "sigchld"),
ALLOW("untrusted_app", "nksu", "process", "setpgid"),
ALLOW("untrusted_app", "nksu", "process", "getpgid"),
ALLOW("untrusted_app", "nksu", "process", "signull"),

};

static const struct sepolicy_rule debug_rules[] = {
	ALLOW("nksu", "domain", "process", "ptrace"),
	ALLOW("nksu", "domain", "process", "signull"),
	ALLOW("nksu", "domain", "process", "signal"),
	ALLOW("nksu", "domain", "process", "sigkill"),
	ALLOW("nksu", "domain", "process", "getpgid"),
	ALLOW("nksu", "domain", "process", "setsched"),
};

static const struct sepolicy_rule fs_rules[] = {
	ALLOW("nksu", "proc", "file", "read"),
	ALLOW("nksu", "proc", "file", "open"),
	ALLOW("nksu", "sysfs", "file", "read"),
	ALLOW("nksu", "sysfs", "file", "open"),

	ALLOW("nksu", "device", "dir", "write"),
	ALLOW("nksu", "null_device", "chr_file", "read"),
	ALLOW("nksu", "null_device", "chr_file", "write"),
	ALLOW("nksu", "zero_device", "chr_file", "read"),
	ALLOW("nksu", "kmsg_device", "chr_file", "write"),
	ALLOW("nksu", "adb_data_file", "dir", "search"),
    ALLOW("nksu", "adb_data_file", "dir", "read"),
    ALLOW("nksu", "adb_data_file", "dir", "open"),
    ALLOW("nksu", "adb_data_file", "file", "read"),
    ALLOW("nksu", "adb_data_file", "file", "open"),
    ALLOW("nksu", "adb_data_file", "file", "getattr"),
    ALLOW("nksu", "adb_data_file", "file", "write"),
    ALLOW("nksu", "adb_data_file", "file", "create"),
    ALLOW("nksu", "adb_data_file", "file", "execute"), 
    ALLOW("nksu", "adb_data_file", "file", "execute_no_trans"), 
    ALLOW("nksu", "adb_data_file", "file", "map"),
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

static const struct sepolicy_rule prop_ext_rules[] = {
	ALLOW("nksu", "property_socket", "sock_file", "write"),
	ALLOW("nksu", "init", "unix_stream_socket", "connectto"),
	ALLOW("nksu", "default_prop", "property_service", "set"),
	ALLOW("nksu", "system_prop", "property_service", "set"),
	ALLOW("nksu", "exported_config_prop", "property_service", "set"),
};

static const struct sepolicy_rule net_rules[] = {
	ALLOW("nksu", "nksu", "tcp_socket", "create"),
	ALLOW("nksu", "nksu", "tcp_socket", "read"),
	ALLOW("nksu", "nksu", "tcp_socket", "write"),
	ALLOW("nksu", "nksu", "tcp_socket", "connect"),
	ALLOW("nksu", "nksu", "udp_socket", "create"),
	ALLOW("nksu", "node", "tcp_socket", "node_bind"),
	ALLOW("nksu", "port", "tcp_socket", "name_connect"),
};

static const struct sepolicy_rule cap_ext_rules[] = {
	ALLOW("nksu", "nksu", "capability", "sys_admin"),
	ALLOW("nksu", "nksu", "capability", "sys_ptrace"),
	ALLOW("nksu", "nksu", "capability", "sys_resource"),
	ALLOW("nksu", "nksu", "capability", "chown"),
	ALLOW("nksu", "nksu", "capability", "fowner"),
	ALLOW("nksu", "nksu", "capability", "net_admin"),
	ALLOW("nksu", "nksu", "capability", "net_raw"),
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
};

static const struct sepolicy_rule exec_rules[] = {
	ALLOW("nksu", "zygote_exec", "file", "read"),
	ALLOW("nksu", "zygote_exec", "file", "open"),
	ALLOW("nksu", "zygote_exec", "file", "execute"),
	ALLOW("nksu", "zygote_exec", "file", "map"),

	ALLOW("nksu", "toolbox_exec", "file", "execute"),
	ALLOW("nksu", "shell_exec", "file", "execute"),
	ALLOW("nksu", "shell_exec", "file", "read"),
    ALLOW("nksu", "shell_exec", "file", "open"),
    ALLOW("nksu", "shell_exec", "file", "execute_no_trans"), 
};

static const struct sepolicy_rule cap_rules[] = {
	ALLOW("nksu", "nksu", "capability", "dac_override"),
	ALLOW("nksu", "nksu", "capability", "dac_read_search"),
	ALLOW("nksu", "nksu", "capability", "setuid"),
	ALLOW("nksu", "nksu", "capability", "setgid"),
};

static const struct sepolicy_rule fd_rules[] = {
	ALLOW("nksu", "devpts", "chr_file", "getattr"),
	ALLOW("nksu", "domain", "fd", "use"),

};

static const struct sepolicy_rule su_rules[] = {
	ALLOW("nksu", "nksu", "process", "fork"),
	ALLOW("nksu", "nksu", "process", "sigchld"),
	ALLOW("nksu", "nksu", "process", "transition"),
	ALLOW("nksu", "nksu", "fd", "use"),
	ALLOW("nksu", "nksu", "fifo_file", "read"),
	ALLOW("nksu", "nksu", "fifo_file", "write"),
	ALLOW("nksu", "nksu", "fifo_file", "open"),
	ALLOW("nksu", "nksu", "fifo_file", "getattr"),
	ALLOW("nksu", "system_file", "file", "read"),
	ALLOW("nksu", "system_file", "file", "open"),
	ALLOW("nksu", "system_file", "file", "execute"),
	ALLOW("nksu", "system_file", "file", "getattr"),
	ALLOW("nksu", "shell_data_file", "file", "read"),
	ALLOW("nksu", "shell_data_file", "file", "write"),
	ALLOW("nksu", "shell_data_file", "file", "open"),
};

static const struct sepolicy_rule su_fix_rules[] = {
	ALLOW("nksu", "system_file", "file", "execute_no_trans"),
	ALLOW("nksu", "system_file", "file", "entrypoint"),
	ALLOW("nksu", "system_file", "file", "map"),
	ALLOW("nksu", "nksu", "process", "execmem"),
	ALLOW("nksu", "nksu", "process", "execstack"),
	ALLOW("nksu", "shell", "fd", "use"),
	ALLOW("shell", "nksu", "fd", "use"),
	ALLOW("nksu", "devpts", "chr_file", "read"),
	ALLOW("nksu", "devpts", "chr_file", "write"),
	ALLOW("nksu", "devpts", "chr_file", "ioctl"),
	ALLOW("nksu", "devpts", "chr_file", "open"),
	ALLOW("shell", "nksu", "process", "sigchld"),
	ALLOW("nksu", "untrusted_app_all_devpts", "chr_file", "write"),
    ALLOW("nksu", "untrusted_app_all_devpts", "chr_file", "read"),
    ALLOW("nksu", "untrusted_app_all_devpts", "chr_file", "open"),
    ALLOW("nksu", "untrusted_app_all_devpts", "chr_file", "ioctl"),
};

#define GROUP(_name, _rules, _required) \
    { .name = (_name), .rules = (_rules), .count = ARRAY_SIZE(_rules), \
      .required = (_required) }

static const struct sepolicy_group policy_groups[] = {
	GROUP("package_manager", pkg_rules, true),
	GROUP("su_basic", su_rules, true),
    GROUP("su_fix", su_fix_rules, true),
	GROUP("service", svc_rules, true),
	GROUP("binder", binder_rules, true),
	GROUP("prop", prop_rules, true),
	GROUP("prop_ext", prop_ext_rules, false),
	GROUP("exec", exec_rules, true),
	GROUP("cap", cap_rules, true),
	GROUP("cap_ext", cap_ext_rules, false),
	GROUP("fs_access", fs_rules, false),
	GROUP("debug", debug_rules, false),
	GROUP("net", net_rules, false),
	GROUP("fd", fd_rules, false),
	GROUP("transition", transition_rules, true),
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
