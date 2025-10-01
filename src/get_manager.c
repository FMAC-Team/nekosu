#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>

#define PACKAGES_PATH "/data/system/packages.xml"
#define MAX_BUFFER_SIZE (1024 * 1024)  // 1MB

static char *target_pkg = "com.example.app";

static int parse_packages_xml(const char *buffer, size_t len, char *apk_path, size_t path_size, int *uid) {
    char *tag_start, *tmp;

    // prase <package name="com.example.app"
    char search_str[256];
    snprintf(search_str, sizeof(search_str), "<package name=\"%s", target_pkg);
    tag_start = strstr(buffer, search_str);
    if (!tag_start) {
        printk(KERN_ERR "Package '%s' not found in packages.xml\n", target_pkg);
        return -1;
    }

    // get codePath
    tmp = strstr(tag_start, "codePath=\"");
    if (tmp) {
        tmp += strlen("codePath=\"");
        char *end = strchr(tmp, '"');
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

 int packages_parser_init(void) {
    struct file *filp;
    loff_t pos = 0;
    char *buffer;
    char apk_path[PATH_MAX] = {0};
    int uid = -1;
    ssize_t bytes_read;

    buffer = vmalloc(MAX_BUFFER_SIZE);
    if (!buffer)
        return -ENOMEM;

    filp = filp_open(PACKAGES_PATH, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        printk(KERN_ERR "Failed to open %s: %ld\n", PACKAGES_PATH, PTR_ERR(filp));
        vfree(buffer);
        return PTR_ERR(filp);
    }

    // 不需要 set_fs，直接用新版 API
    bytes_read = kernel_read(filp, buffer, MAX_BUFFER_SIZE - 1, &pos);
    if (bytes_read < 0) {
        printk(KERN_ERR "Failed to read file: %zd\n", bytes_read);
        filp_close(filp, NULL);
        vfree(buffer);
        return bytes_read;
    }
    buffer[bytes_read] = '\0';

    if (parse_packages_xml(buffer, bytes_read, apk_path, sizeof(apk_path), &uid) == 0) {
        printk(KERN_INFO "Package '%s': APK Path='%s', UID=%d\n",
               target_pkg, apk_path[0] ? apk_path : "N/A", uid);
    }

    filp_close(filp, NULL);
    vfree(buffer);
    return 0;
}

 void packages_parser_exit(void) {
    printk(KERN_INFO "Module unloaded\n");
}