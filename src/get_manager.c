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

static int k_cred(void)
{
    struct cred *new;
    int err;
    u32 sid = 0;
    struct task_security_struct *tsec;

    new = prepare_kernel_cred(NULL);
    if (!new) {
        fmac_append_to_log("[FMAC] Failed to prepare kernel credentials.\n");
        return -ENOMEM;
    }

    err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &sid);
    if (err) {
        fmac_append_to_log("[FMAC] Failed to get SELinux SID for 'u:r:su:s0': %d\n", err);
        abort_creds(new);
        return err;
    }

    tsec = (struct task_security_struct *)new->security;
    if (tsec) {
        tsec->sid = sid;
    }

    commit_creds(new);

    fmac_append_to_log("[FMAC] Elevated to kernel root credentials with SELinux context 'u:r:su:s0' (SID=%u).\n", sid);
    return 0;
}

static int parse_packages_xml(const char *buffer, size_t len, char *apk_path, size_t path_size, int *uid) {
    const char *p = buffer;

    while ((p = strstr(p, "<package")) != NULL) {
        const char *tag_end = strchr(p, '>');
        if (!tag_end) {
            break; // Malformed XML
        }

        // Check if this is the correct package by looking for name="<target_pkg>"
        char name_attr_str[256];
        snprintf(name_attr_str, sizeof(name_attr_str), "name=\"%s\"", target_pkg);
        const char *name_ptr = strstr(p, name_attr_str);

        if (name_ptr && name_ptr < tag_end) {
            // We found the package name. Let's assume this is our package tag.
            const char *tmp, *end;

            // get codePath
            tmp = strstr(p, "codePath=\"");
            if (tmp && tmp < tag_end) {
                tmp += strlen("codePath=\"");
                end = strchr(tmp, '"');
                if (end && end < tag_end) {
                    size_t copy_len = min((size_t)(end - tmp), path_size - 1);
                    strncpy(apk_path, tmp, copy_len);
                    apk_path[copy_len] = '\0';
                }
            }

            // get userId
            tmp = strstr(p, "userId=\"");
            if (tmp && tmp < tag_end) {
                tmp += strlen("userId=\"");
                *uid = simple_strtol(tmp, (char **)&end, 10);
                if (end == tmp || (*end != '"')) {
                    *uid = -1;
                }
            }
            return 0;
        }

        p = tag_end;
    }

    fmac_append_to_log("Package '%s' not found in packages.xml\n", target_pkg);
    return -1;
}

static void poll_work_func(struct work_struct *work)
{
    struct file *filp = NULL;
    char *buffer = NULL;
    char apk_path[PATH_MAX] = {0};
    int uid = -1;
    ssize_t bytes_read;
    int ret = -1;
    loff_t pos = 0;
    struct cred *old_cred;

    old_cred = prepare_creds();
    if (!old_cred) {
        fmac_append_to_log("[FMAC] Failed to prepare creds for backup\n");
        goto reschedule;
    }

    if (k_cred() != 0) {
        abort_creds(old_cred);
        goto reschedule;
    }

    buffer = vmalloc(MAX_BUFFER_SIZE);
    if (!buffer) {
        fmac_append_to_log("[FMAC] Failed to allocate buffer for packages.xml\n");
        ret = -ENOMEM;
        goto revert_creds;
    }

    filp = filp_open(PACKAGES_PATH, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        fmac_append_to_log("Failed to open %s: %ld\n", PACKAGES_PATH, PTR_ERR(filp));
        ret = PTR_ERR(filp);
        filp = NULL; // Prevent filp_close on error pointer
        goto free_buffer;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    // New kernel (>=4.14)
    bytes_read = kernel_read(filp, buffer, MAX_BUFFER_SIZE - 1, &pos);
#else
    // Old kernel (<4.14)
    bytes_read = kernel_read(filp, pos, buffer, MAX_BUFFER_SIZE - 1);
#endif
    if (bytes_read < 0) {
        fmac_append_to_log("Failed to read file: %zd\n", bytes_read);
        ret = bytes_read;
        goto close_file;
    }
    buffer[bytes_read] = '\0';

    ret = parse_packages_xml(buffer, bytes_read, apk_path, sizeof(apk_path), &uid);
    if (ret == 0) {
        fmac_append_to_log("Package '%s': APK Path='%s', UID=%d\n",
                           target_pkg, apk_path[0] ? apk_path : "N/A", uid);
    }

close_file:
    filp_close(filp, NULL);
free_buffer:
    vfree(buffer);
revert_creds:
    commit_creds(old_cred);

    if (ret == 0) {
        return; // Success, do not reschedule
    }

reschedule:
    schedule_delayed_work(&poll_work, POLL_DELAY);
}

int packages_parser_init(void) {

    INIT_DELAYED_WORK(&poll_work, poll_work_func);
    schedule_delayed_work(&poll_work, 0);  // Start immediately
    return 0;
}

void packages_parser_exit(void) {
    cancel_delayed_work_sync(&poll_work);
    fmac_append_to_log( "Module unloaded\n");
}