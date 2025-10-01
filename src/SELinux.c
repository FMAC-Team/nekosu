#include <linux/string.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/selinux.h>
#include <linux/errno.h>

#include "fmac.h"

int set_task_selinux_domain(struct task_struct *task, const char *ctx)
{
    u32 sid;
    int err;

    if (!ctx)
        return -EINVAL;

    if (task == NULL || task == current) {
        struct cred *new;

        new = prepare_creds();
        if (!new) {
            pr_warn("[FMAC] prepare_creds failed in set_task_selinux_domain\n");
            return -ENOMEM;
        }

        err = security_secctx_to_secid(ctx, strlen(ctx), &sid);
        if (err) {
            fmac_append_to_log("[FMAC] secctx_to_secid failed for '%s': %d\n", ctx, err);
            abort_creds(new);
            return err;
        }

        if (!new->security) {
            fmac_append_to_log("[FMAC] cred->security is NULL!\n");
            abort_creds(new);
            return -EINVAL;
        }

        ((struct task_security_struct *)new->security)->sid = sid;

        pr_info("[FMAC] set current cred SELinux sid=%u for ctx='%s'\n", sid, ctx);

        commit_creds(new);
        return 0;
    }
}