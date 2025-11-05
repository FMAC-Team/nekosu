#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/security.h>

#include "fmac.h"
#include "objsec.h"
#include "apksig.h"

#define PACKAGES_PATH "/data/system/packages.xml"
#define READ_CHUNK_SIZE (4096)  // 4KB chunks for streaming
#define POLL_DELAY (3 * HZ)

#ifdef CONFIG_FMAC_DEBUG
static char *target_pkg = "com.android.shell";
#elif
static char *target_pkg = "me.neko.nksu";
#endif

static struct delayed_work poll_work;

typedef enum {
    STATE_SEARCHING, 
    STATE_IN_TAG,   
    STATE_FOUND,   
    STATE_NOT_FOUND 
} parse_state_t;

typedef struct {
    parse_state_t state;
    char *residual;  
    size_t residual_len;
    char apk_path[PATH_MAX];
    int uid;
    bool found_name;
    bool found_codepath;
    bool found_uid;
} xml_parser_ctx_t;

static int k_cred(void)
{
    transive_to_domain("u:r:su:s0");
    return 0;
}

static void init_parser_ctx(xml_parser_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(xml_parser_ctx_t));
    ctx->state = STATE_SEARCHING;
    ctx->uid = -1;
    ctx->residual = NULL;
    ctx->residual_len = 0;
}

static void cleanup_parser_ctx(xml_parser_ctx_t *ctx)
{
    if (ctx->residual) {
        kfree(ctx->residual);
        ctx->residual = NULL;
    }
}

static bool extract_attribute(const char *data, size_t len, 
                             const char *attr_name, 
                             char *output, size_t output_size)
{
    char search_str[128];
    const char *start, *end;
    size_t attr_len;

    snprintf(search_str, sizeof(search_str), "%s=\"", attr_name);
    start = strnstr(data, search_str, len);
    
    if (!start)
        return false;

    start += strlen(search_str);
    end = strchr(start, '"');
    
    if (!end || (end - data) > len)
        return false;

    attr_len = min((size_t)(end - start), output_size - 1);
    strncpy(output, start, attr_len);
    output[attr_len] = '\0';
    
    return true;
}


static int parse_chunk(xml_parser_ctx_t *ctx, const char *chunk, size_t chunk_len)
{
    char *work_buf = NULL;
    char *data = NULL;
    size_t data_len;
    const char *p, *tag_start, *tag_end;
    char name_buf[256];
    char temp_buf[PATH_MAX];
    int ret = 0;

    if (ctx->residual_len > 0) {
        data_len = ctx->residual_len + chunk_len;
        work_buf = kmalloc(data_len + 1, GFP_KERNEL);
        if (!work_buf)
            return -ENOMEM;
        
        memcpy(work_buf, ctx->residual, ctx->residual_len);
        memcpy(work_buf + ctx->residual_len, chunk, chunk_len);
        work_buf[data_len] = '\0';
        data = work_buf;
        
        kfree(ctx->residual);
        ctx->residual = NULL;
        ctx->residual_len = 0;
    } else {
        data = (char *)chunk;
        data_len = chunk_len;
    }

    p = data;
    
    while (p < data + data_len) {
        if (ctx->state == STATE_SEARCHING || ctx->state == STATE_IN_TAG) {
            tag_start = strnstr(p, "<package", data + data_len - p);
            
            if (!tag_start) {
                size_t tail_size = min((size_t)512, (size_t)(data + data_len - p));
                if (tail_size > 0) {
                    ctx->residual = kmalloc(tail_size, GFP_KERNEL);
                    if (ctx->residual) {
                        memcpy(ctx->residual, data + data_len - tail_size, tail_size);
                        ctx->residual_len = tail_size;
                    }
                }
                break;
            }

            tag_end = strchr(tag_start, '>');
            
            if (!tag_end || tag_end >= data + data_len) {
                size_t incomplete_len = data + data_len - tag_start;
                ctx->residual = kmalloc(incomplete_len, GFP_KERNEL);
                if (ctx->residual) {
                    memcpy(ctx->residual, tag_start, incomplete_len);
                    ctx->residual_len = incomplete_len;
                }
                break;
            }

            if (extract_attribute(tag_start, tag_end - tag_start, 
                                "name", name_buf, sizeof(name_buf))) {
                
                if (strcmp(name_buf, target_pkg) == 0) {
                    ctx->found_name = true;
                    ctx->state = STATE_IN_TAG;

                    if (extract_attribute(tag_start, tag_end - tag_start,
                                        "codePath", temp_buf, sizeof(temp_buf))) {
                        strncpy(ctx->apk_path, temp_buf, sizeof(ctx->apk_path) - 1);
                        ctx->found_codepath = true;
                    }

                    if (extract_attribute(tag_start, tag_end - tag_start,
                                        "userId", temp_buf, sizeof(temp_buf))) {
                        ctx->uid = simple_strtol(temp_buf, NULL, 10);
                        ctx->found_uid = true;
                    }

                    if (ctx->found_codepath && ctx->found_uid) {
                        ctx->state = STATE_FOUND;
                        ret = 0;
                        goto out;
                    }
                }
            }

            p = tag_end + 1;
        } else {
            break;
        }
    }

out:
    if (work_buf)
        kfree(work_buf);
    
    return ret;
}

static int parse_packages_xml_streaming(struct file *filp, 
                                       char *apk_path, 
                                       size_t path_size, 
                                       int *uid)
{
    xml_parser_ctx_t ctx;
    char *chunk_buf = NULL;
    loff_t pos = 0;
    ssize_t bytes_read;
    int ret = -1;

    init_parser_ctx(&ctx);

    chunk_buf = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
    if (!chunk_buf) {
        fmac_append_to_log("[FMAC] Failed to allocate chunk buffer\n");
        return -ENOMEM;
    }

    while (1) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
        bytes_read = kernel_read(filp, chunk_buf, READ_CHUNK_SIZE, &pos);
#else
        bytes_read = kernel_read(filp, pos, chunk_buf, READ_CHUNK_SIZE);
        if (bytes_read > 0)
            pos += bytes_read;
#endif

        if (bytes_read < 0) {
            fmac_append_to_log("[FMAC] Failed to read file: %zd\n", bytes_read);
            ret = bytes_read;
            break;
        }

        if (bytes_read == 0) {
            if (ctx.state == STATE_FOUND) {
                ret = 0;
            } else {
                fmac_append_to_log("[FMAC] Package '%s' not found\n", target_pkg);
                ret = -ENOENT;
            }
            break;
        }

        ret = parse_chunk(&ctx, chunk_buf, bytes_read);
        
        if (ctx.state == STATE_FOUND) {
            strncpy(apk_path, ctx.apk_path, path_size - 1);
            apk_path[path_size - 1] = '\0';
            *uid = ctx.uid;
            ret = 0;
            break;
        }
    }

    cleanup_parser_ctx(&ctx);
    kfree(chunk_buf);

    return ret;
}

static void poll_work_func(struct work_struct *work)
{
    struct file *filp = NULL;
    char apk_path[PATH_MAX] = {0};
    int uid = -1;
    int ret = -1;
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

    filp = filp_open(PACKAGES_PATH, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        fmac_append_to_log("[FMAC] Failed to open %s: %ld\n", PACKAGES_PATH, PTR_ERR(filp));
        ret = PTR_ERR(filp);
        filp = NULL;
        goto revert_creds;
    }

    ret = parse_packages_xml_streaming(filp, apk_path, sizeof(apk_path), &uid);
    
    if (ret == 0) {
        fmac_append_to_log("[FMAC] Package '%s': APK Path='%s', UID=%d\n",
                           target_pkg, apk_path[0] ? apk_path : "N/A", uid);
         struct apk_signature_digest digest;
int ret = extract_apk_signature_digest(target_pkg, &digest);
if (ret == 0 && digest.found) {
  fmac_append_to_log("[APK SIG] Find out manager\n");
}              
    }

    filp_close(filp, NULL);

revert_creds:
    commit_creds(old_cred);

    if (ret == 0) {
        return; // Success, do not reschedule
    }

reschedule:
    schedule_delayed_work(&poll_work, POLL_DELAY);
}

int packages_parser_init(void) 
{
    INIT_DELAYED_WORK(&poll_work, poll_work_func);
    schedule_delayed_work(&poll_work, 0);
    return 0;
}

void packages_parser_exit(void) 
{
    cancel_delayed_work_sync(&poll_work);
    fmac_append_to_log("[FMAC] Module unloaded\n");
}