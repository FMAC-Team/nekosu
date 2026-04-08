#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/list.h>
#include <linux/version.h>
#include <fmac.h>

#define TARGET_PACKAGE "me.nekosu.aqnya"
#define TARGET_HASH "\x80\xb7\x5c\x8d\x50\xc8\x76\x02\xed\x9b\xb0\x6d\x88\xee\xcf\x9e\x66\x51\xa3\x3c\xd5\xc8\x7a\x2a\x9e\xf5\x10\x24\xf2\xa1\x04\xfc"

#define APK_PATH_MAX 512
#define BUF_SIZE 65536
#define EOCD_SEARCH_SIZE 65557

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
# define FILLDIR_RETURN_TYPE      bool
# define FILLDIR_ACTOR_CONTINUE   true
# define FILLDIR_ACTOR_STOP       false
#else
# define FILLDIR_RETURN_TYPE      int
# define FILLDIR_ACTOR_CONTINUE   0
# define FILLDIR_ACTOR_STOP       (-EINVAL)
#endif

#define DATA_PATH_LEN APK_PATH_MAX

struct data_path {
	char dirpath[DATA_PATH_LEN];
	int depth;
	struct list_head list;
};

struct apk_scan_ctx {
	struct dir_context ctx;
	struct list_head *data_path_list; /* pending dirs to visit */
	char *parent_dir;
	const char *target_pkg;
	char *found_path;
	int depth;
	int *stop;
};

static ssize_t safe_read_file(const char *path, loff_t offset, char *buf, size_t len)
{
	struct file *file;
	ssize_t ret;
	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);
	ret = kernel_read(file, buf, len, &offset);
	filp_close(file, NULL);
	return ret;
}

static loff_t get_file_size(const char *path)
{
	struct kstat stat;
	if (vfs_stat(path, &stat))
		return -1;
	return stat.size;
}

static FILLDIR_RETURN_TYPE apk_actor(struct dir_context *ctx,
				     const char *name, int namelen,
				     loff_t off, u64 ino, unsigned int d_type)
{
	struct apk_scan_ctx *s =
		container_of(ctx, struct apk_scan_ctx, ctx);
	char fullpath[DATA_PATH_LEN];

	if (!s)
		return FILLDIR_ACTOR_STOP;

	/* Bail early if already found */
	if (s->stop && *s->stop)
		return FILLDIR_ACTOR_STOP;

	/* Skip "." and ".." */
	if (!strncmp(name, ".",  namelen) || !strncmp(name, "..", namelen))
		return FILLDIR_ACTOR_CONTINUE;

	/*
	 * Skip vmdl-*.tmp staging directories (same as throne_tracker).
	 * These are temporary dirs created by PackageManager during install.
	 */
	if (d_type == DT_DIR && namelen >= 8 &&
	    !strncmp(name, "vmdl", 4) &&
	    !strncmp(name + namelen - 4, ".tmp", 4))
		return FILLDIR_ACTOR_CONTINUE;

	if (snprintf(fullpath, DATA_PATH_LEN, "%s/%.*s",
		     s->parent_dir, namelen, name) >= DATA_PATH_LEN) {
		pr_err("[manager] path too long: %s/%.*s\n",
		       s->parent_dir, namelen, name);
		return FILLDIR_ACTOR_CONTINUE;
	}

if (d_type == DT_DIR && s->depth == 2) {
		struct data_path *dp = kzalloc(sizeof(*dp), GFP_ATOMIC);
		if (!dp)
			return FILLDIR_ACTOR_CONTINUE;
		strscpy(dp->dirpath, fullpath, DATA_PATH_LEN);
		dp->depth = 1;
		list_add_tail(&dp->list, s->data_path_list);
	} else if (d_type == DT_DIR && s->depth == 1) {
		if (strnstr(name, s->target_pkg, namelen)) {
			struct data_path *dp = kzalloc(sizeof(*dp), GFP_ATOMIC);
			if (!dp)
				return FILLDIR_ACTOR_CONTINUE;
			strscpy(dp->dirpath, fullpath, DATA_PATH_LEN);
			dp->depth = 0;
			list_add_tail(&dp->list, s->data_path_list);
		}
	} else if (d_type == DT_REG && s->depth == 0) {
		if (namelen == 8 && !strncmp(name, "base.apk", 8)) {
			strscpy(s->found_path, fullpath, DATA_PATH_LEN);
			if (s->stop)
				*s->stop = 1;
		}
	}

	return FILLDIR_ACTOR_CONTINUE;
}

static int find_apk_path(const char *package_name, char *apk_path)
{
	int stop = 0;
	int depth = 2; /* /data/app (depth 2) -> pkg dir (depth 1) -> base.apk */
	unsigned long data_app_magic = 0;
	struct list_head data_path_list;
	struct data_path root_entry;
	struct data_path *pos, *n;

	INIT_LIST_HEAD(&data_path_list);
	strscpy(root_entry.dirpath, "/data/app", DATA_PATH_LEN);
	root_entry.depth = depth;
	list_add_tail(&root_entry.list, &data_path_list);

	list_for_each_entry_safe(pos, n, &data_path_list, list) {
		struct apk_scan_ctx ctx = {
			.ctx.actor    = apk_actor,
			.data_path_list = &data_path_list,
			.parent_dir   = pos->dirpath,
			.target_pkg   = package_name,
			.found_path   = apk_path,
			.depth        = pos->depth,
			.stop         = &stop,
		};
		struct file *dir;

		if (stop)
			goto del;

		dir = filp_open(pos->dirpath, O_RDONLY | O_NOFOLLOW, 0);
		if (IS_ERR(dir)) {
			pr_err("[manager] open failed: %s (%ld)\n",
			       pos->dirpath, PTR_ERR(dir));
			goto del;
		}

		/* Verify all dirs share the same filesystem (anti-bind-mount) */
		if (!data_app_magic) {
			data_app_magic = dir->f_inode->i_sb->s_magic;
			pr_info("[manager] /data/app fs magic: 0x%lx\n",
				data_app_magic);
		} else if (dir->f_inode->i_sb->s_magic != data_app_magic) {
			pr_info("[manager] skipping cross-fs dir: %s\n",
				pos->dirpath);
			filp_close(dir, NULL);
			goto del;
		}

		iterate_dir(dir, &ctx.ctx);
		filp_close(dir, NULL);

del:
		list_del(&pos->list);
		if (pos != &root_entry)
			kfree(pos);
	}

	return stop ? 0 : -1;
}

static uid_t get_uid_from_packages_list(const char *package_name)
{
	struct file *file;
	char *buf, *line, *p, *token;
	loff_t pos = 0;
	uid_t target_uid = (uid_t)-1;
	ssize_t read_size;

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return (uid_t)-1;

	file = filp_open("/data/system/packages.list", O_RDONLY, 0);
	if (IS_ERR(file)) {
		kfree(buf);
		return (uid_t)-1;
	}

	read_size = kernel_read(file, buf, BUF_SIZE - 1, &pos);
	if (read_size > 0) {
		buf[read_size] = '\0';
		p = buf;
		while ((line = strsep(&p, "\n")) != NULL) {
			token = strsep(&line, " ");
			if (token && strcmp(token, package_name) == 0) {
				token = strsep(&line, " ");
				if (token && kstrtouint(token, 10, &target_uid) == 0)
					break;
			}
		}
	}

	filp_close(file, NULL);
	kfree(buf);
	return target_uid;
}

static int find_signature_block(const char *apk_path,
				loff_t *sig_offset, uint32_t *sig_size)
{
	char *buf;
	loff_t file_size, eocd_search_start;
	ssize_t read_size;
	int i, ret = -1;

	file_size = get_file_size(apk_path);
	if (file_size < 100)
		return -1;

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -1;

	eocd_search_start = max_t(loff_t, 0, file_size - EOCD_SEARCH_SIZE);
	read_size = safe_read_file(apk_path, eocd_search_start, buf, BUF_SIZE);
	if (read_size < 22)
		goto out;

	/* Scan backwards for EOCD magic 0x06054b50 */
	for (i = (int)read_size - 22; i >= 0; i--) {
		if (*(uint32_t *)(buf + i) == 0x06054b50U) {
			uint32_t cd_offset =
				le32_to_cpu(*(uint32_t *)(buf + i + 16));

			if (cd_offset < 24)
				break;

			read_size = safe_read_file(apk_path,
						   (loff_t)cd_offset - 24,
						   buf, 24);
			if (read_size != 24)
				break;

			/* magic is at buf[8..23] */
			if (memcmp(buf + 8, "APK Sig Block 42", 16) != 0)
				break;

			{
				uint64_t block_size =
					le64_to_cpu(*(uint64_t *)buf);
				if (block_size < 32 ||
				    block_size > (uint64_t)cd_offset ||
				    block_size > (100ULL * 1024 * 1024))
					break;

				*sig_offset = (loff_t)cd_offset - 24 -
					      (loff_t)block_size;
				*sig_size   = (uint32_t)block_size;
				ret = 0;
			}
			break;
		}
	}
out:
	kfree(buf);
	return ret;
}

static int calculate_hash(const char *path, loff_t offset,
			  uint32_t size, u8 *hash)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	char *buf;
	int ret = -1;
	uint32_t remain = size;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return -1;

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	buf  = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!desc || !buf)
		goto out;

	desc->tfm = tfm;
	crypto_shash_init(desc);

	while (remain > 0) {
		size_t to_read = min_t(size_t, BUF_SIZE, remain);
		ssize_t n = safe_read_file(path, offset, buf, to_read);
		if (n <= 0)
			break;
		crypto_shash_update(desc, buf, n);
		offset += n;
		remain -= (uint32_t)n;
	}

	if (remain == 0)
		ret = crypto_shash_final(desc, hash);
out:
	kfree(buf);
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static bool verify_apk_signature(const char *path, const u8 *expected_hash)
{
	loff_t   sig_offset;
	uint32_t sig_size;
	u8       calc_hash[32];

	if (find_signature_block(path, &sig_offset, &sig_size) != 0)
		return false;
	if (calculate_hash(path, sig_offset, sig_size, calc_hash) != 0)
		return false;

	return memcmp(calc_hash, expected_hash, 32) == 0;
}

static int scan_and_apply(void)
{
	uid_t  uid;
	char  *apk_path;
	int    ret = -1;

	uid = get_uid_from_packages_list(TARGET_PACKAGE);
	if (uid == (uid_t)-1) {
		pr_err("[manager] Could not find UID for %s\n", TARGET_PACKAGE);
		return -1;
	}

	apk_path = kmalloc(APK_PATH_MAX, GFP_KERNEL);
	if (!apk_path)
		return -ENOMEM;

	if (find_apk_path(TARGET_PACKAGE, apk_path) == 0) {
		pr_info("[manager] Found APK: %s\n", apk_path);
		if (verify_apk_signature(apk_path, (const u8 *)TARGET_HASH)) {
			pr_info("[manager] Verification passed. "
				"Granting privileges to UID %u\n", uid);
			fmac_scope_set(uid, FMAC_SCOPE_ALL);
			ret = 0;
		} else {
			pr_err("[manager] Signature mismatch!\n");
		}
	} else {
		pr_err("[manager] Could not find APK for %s\n", TARGET_PACKAGE);
	}

	kfree(apk_path);
	return ret;
}

int appscan_init(void)
{
	pr_info("[manager] Module starting scan...\n");
	return scan_and_apply();
}