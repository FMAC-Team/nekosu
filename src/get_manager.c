#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/selinux.h>

#include "fmac.h"
#include "objsec.h"

#define PACKAGES_PATH "/data/system/packages.xml"
#define MAX_BUFFER_SIZE (1024 * 1024)  // 1MB
#define POLL_DELAY (3 * HZ)  // 1 second polling interval

static char *target_pkg = "com.android.shell";

static struct delayed_work poll_work;

static int parse_packages_xml(const char *buffer, size_t len, char *apk_path, size_t path_size, int *uid) {
    char *tag_start, *tmp,*end;

    // prase <package name="com.example.app"
    char search_str[256];
    snprintf(search_str, sizeof(search_str), "<package name=\"%s", target_pkg);
    tag_start = strstr(buffer, search_str);
    if (!tag_start) {
        fmac_append_to_log("Package '%s' not found in packages.xml\n", target_pkg);
        return -1;
    }

    // get codePath
    tmp = strstr(tag_start, "codePath=\"");
    if (tmp) {
        tmp += strlen("codePath=\"");
        end = strchr(tmp, '"');
        if (end) {
            size_t copy_len = min((size_t)(end - tmp), path_size - 1);
            strncpy(apk_path, tmp, copy_len);
            apk_path[copy_len] = '\0';
        }
    }

    // get userId
    tmp = strstr(tag_start, "userId=\"");
    if (tmp) {
        tmp += strlen("userId=\"");
        sscanf(tmp, "%d", uid);
    }

    return 0;
}

static void poll_work_func(struct work_struct *work) {
    struct file *filp;
    loff_t pos = 0;
    char *buffer;
    char apk_path[PATH_MAX] = {0};
    int uid = -1;
    ssize_t bytes_read;
    int ret = -1;

    buffer = vmalloc(MAX_BUFFER_SIZE);
    if (!buffer) {
        goto reschedule;
    }

    filp = filp_open(PACKAGES_PATH, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        fmac_append_to_log("Failed to open %s: %ld\n", PACKAGES_PATH, PTR_ERR(filp));
        vfree(buffer);
        goto reschedule;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    // 新内核 (>=4.14)
    bytes_read = kernel_read(filp, buffer, MAX_BUFFER_SIZE - 1, &pos);
#else
    // 老内核 (<4.14)
    bytes_read = kernel_read(filp, pos, buffer, MAX_BUFFER_SIZE - 1);
#endif
    if (bytes_read < 0) {
        fmac_append_to_log( "Failed to read file: %zd\n", bytes_read);
        filp_close(filp, NULL);
        vfree(buffer);
        goto reschedule;
    }
    buffer[bytes_read] = '\0';

    ret = parse_packages_xml(buffer, bytes_read, apk_path, sizeof(apk_path), &uid);
    filp_close(filp, NULL);
    vfree(buffer);

    if (ret == 0) {
        fmac_append_to_log( "Package '%s': APK Path='%s', UID=%d\n",
               target_pkg, apk_path[0] ? apk_path : "N/A", uid);
        return;  // Success, do not reschedule
    }

reschedule:
    schedule_delayed_work(&poll_work, POLL_DELAY);
}

static int k_cred(void)
{
    struct cred *new;
    int err;
    u32 sid = 0;

    new = prepare_kernel_cred(NULL);
    if (!new)
        return -ENOMEM;

    err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &sid);
    if (err) {
        fmac_append_to_log("[FMAC] Failed to get SELinux SID for 'u:r:su:s0': %d\n", err);
    return -1;
    } else {
        struct task_security_struct *tsec = (struct task_security_struct *)new->security;
        if (tsec) {
            tsec->sid = sid;
            fmac_append_to_log("[FMAC] SELinux domain switched to 'u:r:su:s0' (SID=%u)\n", sid);
        }
    }

    commit_creds(new);

    pr_info("[FMAC] Elevated to kernel root credentials with SELinux domain switch.\n");
    return 0;
}

int packages_parser_init(void) {
if ((k_cred())!=0){
return 0;
}
    INIT_DELAYED_WORK(&poll_work, poll_work_func);
    schedule_delayed_work(&poll_work, 0);  // Start immediately
    return 0;
}

void packages_parser_exit(void) {
    cancel_delayed_work_sync(&poll_work);
    fmac_append_to_log( "Module unloaded\n");
}