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

static int apply_rule(const struct sepolicy_rule *rule)
{
    int ret;

    ret = sepolicy_add_rule(
        rule->src,
        rule->tgt,
        rule->cls,
        rule->perm,
        rule->effect,
        rule->invert
    );

    if (ret) {
        pr_err("[selinux]: allow %s %s:%s %s failed: %d\n",
               rule->src, rule->tgt, rule->cls, rule->perm, ret);
        return ret;
    }

    pr_info("[selinux]: allow %s %s:%s %s success\n",
            rule->src, rule->tgt, rule->cls, rule->perm);

    return 0;
}

static int apply_rules(const struct sepolicy_rule *rules, size_t count)
{
    size_t i;
    int ret;

    for (i = 0; i < count; i++) {
        ret = apply_rule(&rules[i]);
        if (ret)
            return ret;
    }

    return 0;
}

static struct sepolicy_rule pkg_rules[] = {
    {
        .src = "su",
        .tgt = "package_service",
        .cls = "service_manager",
        .perm = "find",
        .effect = AVTAB_ALLOWED,
        .invert = false,
    },
};

static int policy_package_manager(void)
{
    return apply_rules(pkg_rules, ARRAY_SIZE(pkg_rules));
}

typedef int (*policy_fn_t)(void);

static policy_fn_t policy_table[] = {
    policy_package_manager,
};

int load_policy(void)
{
    int i, ret;

    pr_info("[selinux]: dynamic policy loading start\n");

    for (i = 0; i < ARRAY_SIZE(policy_table); i++) {
        ret = policy_table[i]();
        if (ret) {
            pr_err("[selinux]: policy[%d] failed: %d\n", i, ret);
            return ret;
        }
    }

    pr_info("[selinux]: dynamic policy loading success\n");
    return 0;
}

 int __init sepolicy_init(void)
{
    int ret;

    pr_info("[selinux]: sepolicy init\n");

    ret = load_policy();
    if (ret) {
        pr_err("[selinux]: load_policy failed: %d\n", ret);
        return ret;
    }

    return 0;
}

 void __exit sepolicy_exit(void)
{
    pr_info("[selinux]: sepolicy exit\n");
}