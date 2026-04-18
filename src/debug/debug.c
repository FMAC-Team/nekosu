#include <linux/kprobes.h>
#include <linux/version.h>
#include <fmac.h>

#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/avtab.h"
#include "avc.h"
#include "ss/symtab.h"
#include "ss/policydb.h"
#include "security.h"
#include "avc_ss.h"
#include "xfrm.h"
#include "ss/hashtab.h"
#include "ss/constraint.h"

static u32 nksu_sid;

struct noaudit_data {
    u32        ssid;
    u32        tsid;
    u16        tclass;
    u32        requested;
    uintptr_t  avd;
};

static int avc_noaudit_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs)
{
    struct noaudit_data *d = (struct noaudit_data *)ri->data;
    d->ssid      = (u32)regs->regs[1];
    d->tsid      = (u32)regs->regs[2];
    d->tclass    = (u16)regs->regs[3];
    d->requested = (u32)regs->regs[4];
    d->avd       = (uintptr_t)regs->regs[6]; /* struct av_decision * */
    return 0;
}

static int avc_noaudit_ret(struct kretprobe_instance *ri,
                           struct pt_regs *regs)
{
    struct noaudit_data *d = (struct noaudit_data *)ri->data;

    if (d->ssid != nksu_sid && d->tsid != nksu_sid)
        return 0;

    struct av_decision *avd = (struct av_decision *)d->avd;
    if (!avd)
        return 0;

    u32 denied      = d->requested & ~avd->allowed;
    u32 dontaudited = denied & ~avd->auditdeny;

    if (!denied)
        return 0;

    pr_warn("[nksu/avc] ssid=%u tsid=%u tclass=%u "
            "denied=0x%x silenced_by_dontaudit=0x%x\n",
            d->ssid, d->tsid, d->tclass, denied, dontaudited);
    return 0;
}

static struct kretprobe avc_rp = {
    .kp.symbol_name = "avc_has_perm_noaudit",
    .entry_handler  = avc_noaudit_entry,
    .handler        = avc_noaudit_ret,
    .data_size      = sizeof(struct noaudit_data),
    .maxactive      = 20,
};

int debug_tracing(void)
{
    int rc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    rc = security_context_to_sid(DOMAIN_CTX, strlen(DOMAIN_CTX),
                                 &nksu_sid, GFP_KERNEL);
#else
    rc = security_context_to_sid(&selinux_state, DOMAIN_CTX, strlen(DOMAIN_CTX),
                                 &nksu_sid, GFP_KERNEL);
#endif
    if (rc) {
        pr_err("[nksu/debug] failed to resolve SID for '%s': %d\n",
               DOMAIN_CTX, rc);
        return rc;
    }

    rc = register_kretprobe(&avc_rp);
    if (rc) {
        pr_err("[nksu/debug] register_kretprobe failed: %d\n", rc);
        return rc;
    }

    pr_info("[nksu/debug] tracing enabled, domain='%s' sid=%u\n",
            DOMAIN_CTX, nksu_sid);
    return 0;
}

void debug_exit(void)
{
    unregister_kretprobe(&avc_rp);
    pr_info("[nksu/debug] tracing disabled\n");
}
