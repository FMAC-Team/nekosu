#include <trace/events/selinux.h>
#include <linux/lsm_audit.h>
#include <fmac.h>

static u32 nksu_sid;

static void on_selinux_audited(void *data,
                               u32 requested, u32 audited, u32 denied,
                               int result,
                               struct lsm_audit_data *ad,
                               u32 ssid, u32 tsid, u16 tclass)
{
    char *sctx = NULL, *tctx = NULL;
    u32 slen, tlen;

    if (ssid != nksu_sid && tsid != nksu_sid)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    security_sid_to_context(ssid, &sctx, &slen);
    security_sid_to_context(tsid, &tctx, &tlen);
#else
    security_sid_to_context(&selinux_state, ssid, &sctx, &slen);
    security_sid_to_context(&selinux_state, tsid, &tctx, &tlen);
#endif

    pr_warn("[nksu/avc] %s sctx=%s tsid=%s tclass=%u "
            "req=0x%x audited=0x%x denied=0x%x result=%d\n",
            denied ? "DENIED" : "AUDIT",
            sctx  ? sctx  : "(unknown)",
            tctx  ? tctx  : "(unknown)",
            tclass, requested, audited, denied, result);

    kfree(sctx);
    kfree(tctx);
}

 int debug_tracing(void)
{
    int rc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    rc = security_context_to_sid(DOMAIN, strlen(DOMAIN),
                                 &nksu_sid, GFP_KERNEL);
#else
    rc = security_context_to_sid(&selinux_state, DOMAIN, strlen(DOMAIN),
                                 &nksu_sid, GFP_KERNEL);
#endif
    if (rc) {
        pr_err("[nksu/debug] failed to resolve SID for '%s': %d\n",
               DOMAIN, rc);
        return rc;
    }

    pr_info("[nksu/debug] tracing enabled, domain='%s' sid=%u\n",
            DOMAIN, nksu_sid);

    return register_trace_selinux_audited(on_selinux_audited, NULL);
}

 void debug_exit(void)
{
    unregister_trace_selinux_audited(on_selinux_audited, NULL);
    tracepoint_synchronize_unregister();
    pr_info("[nksu/debug] tracing disabled\n");
}