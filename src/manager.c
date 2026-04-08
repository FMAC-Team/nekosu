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
#include <fmac.h>

#define TARGET_PACKAGE "me.nekosu.aqnya"
#define TARGET_HASH "\x80\xb7\x5c\x8d\x50\xc8\x76\x02\xed\x9b\xb0\x6d\x88\xee\xcf\x9e\x66\x51\xa3\x3c\xd5\xc8\x7a\x2a\x9e\xf5\x10\x24\xf2\xa1\x04\xfc"

#define APK_PATH_MAX 512
#define BUF_SIZE 65536
#define MAX_SCAN_SIZE (100 * 1024 * 1024)
#define EOCD_SEARCH_SIZE 65557

struct my_dir_ctx {
	struct dir_context dctx;
	char   *buf;
	size_t  buf_size;
	size_t  pos;
};

static int my_filldir(struct dir_context *dctx, const char *name, int namlen,
		      loff_t offset, u64 ino, unsigned int d_type)
{
	struct my_dir_ctx *ctx = (struct my_dir_ctx *)dctx;
	struct linux_dirent64 *de;
	size_t reclen = ALIGN(
		offsetof(struct linux_dirent64, d_name) + namlen + 1, 8);

	if (ctx->pos + reclen > ctx->buf_size)
		return 0;

	de = (struct linux_dirent64 *)(ctx->buf + ctx->pos);
	de->d_ino    = ino;
	de->d_off    = offset;
	de->d_reclen = (unsigned short)reclen;
	de->d_type   = (unsigned char)d_type;
	memcpy(de->d_name, name, namlen);
	de->d_name[namlen] = '\0';

	ctx->pos += reclen;
	return 1;
}

static ssize_t read_dir_entries(struct file *dir, char *buf, size_t buf_size)
{
	struct my_dir_ctx ctx = {
		.dctx.actor = my_filldir,
		.buf      = buf,
		.buf_size = buf_size,
		.pos      = 0,
	};
	int ret;

	ret = iterate_dir(dir, &ctx.dctx);
	if (ret < 0)
		return ret;

	return (ssize_t)ctx.pos;
}

static ssize_t safe_read_file(const char *path, loff_t offset,
			      char *buf, size_t len)
{
	struct file *file;
	ssize_t ret;

	if (!path || !buf || len == 0)
		return -EINVAL;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file)) {
		pr_err("[manager] Failed to open: %s (errno: %ld)\n",
		       path, PTR_ERR(file));
		return PTR_ERR(file);
	}

	ret = kernel_read(file, buf, len, &offset);

	filp_close(file, NULL);

	return ret;
}

static loff_t get_file_size(const char *path)
{
	struct kstat stat;
	int ret;

	ret = vfs_stat(path, &stat);
	if (ret) {
		pr_err("[manager] Failed to stat: %s\n", path);
		return -1;
	}

	if (stat.size > MAX_SCAN_SIZE) {
		pr_warn("[manager] File too large: %lld bytes\n", stat.size);
		return -1;
	}

	return stat.size;
}

static uid_t get_uid_from_packages_list(const char *package_name)
{
	struct file *file;
	char *buf, *line, *p, *token;
	loff_t pos = 0;
	uid_t target_uid = -1;
	ssize_t read_size;
	int uid;

	if (!package_name || strlen(package_name) == 0)
		return -1;

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -1;

	file = filp_open("/data/system/packages.list", O_RDONLY, 0);
	if (IS_ERR(file)) {
		pr_err("[manager] Cannot open packages.list\n");
		kfree(buf);
		return -1;
	}

	read_size = kernel_read(file, buf, BUF_SIZE - 1, &pos);
	if (read_size > 0) {
		buf[read_size] = '\0';
		p = buf;

		while ((line = strsep(&p, "\n")) != NULL) {
			if (strlen(line) == 0)
				continue;

			token = strsep(&line, " ");
			if (token && strcmp(token, package_name) == 0) {
				token = strsep(&line, " ");
				if (token && kstrtoint(token, 10, &uid) == 0) {
					target_uid = (uid_t) uid;
					pr_info
					    ("[manager] Found package %s, UID: %u\n",
					     package_name, target_uid);
					break;
				}
			}
		}
	}

	filp_close(file, NULL);
	kfree(buf);

	return target_uid;
}

static int check_apk_exists(const char *base_path)
{
	char *apk_path;
	struct kstat stat;
	int ret;

	apk_path = kmalloc(APK_PATH_MAX, GFP_KERNEL);
	if (!apk_path)
		return -1;

	snprintf(apk_path, APK_PATH_MAX, "%s/base.apk", base_path);
	ret = (vfs_stat(apk_path, &stat) == 0 && S_ISREG(stat.mode)) ? 0 : -1;

	kfree(apk_path);
	return ret;
}

struct scan_context {
	char *buf;
	char *buf2;
	char level1_path[APK_PATH_MAX];
	char level2_path[APK_PATH_MAX];
	char apk_path[APK_PATH_MAX];
	int found;
};

static int find_apk_in_two_level_dirs(const char *package_name, char *apk_path)
{
	struct file *dir1, *dir2;
	struct scan_context *ctx;
	struct linux_dirent64 *dirent, *dirent2;
	unsigned int offset, offset2;
	ssize_t read_size, read_size2;
	int ret = -1;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -1;

	ctx->buf  = kmalloc(BUF_SIZE, GFP_KERNEL);
	ctx->buf2 = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!ctx->buf || !ctx->buf2) {
		kfree(ctx->buf);
		kfree(ctx->buf2);
		kfree(ctx);
		return -1;
	}

	ctx->found = 0;

	pr_info("[manager] Scanning /data/app for package: %s\n", package_name);

	dir1 = filp_open("/data/app", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(dir1)) {
		pr_err("[manager] Cannot open /data/app\n");
		goto out_free;
	}

	read_size = read_dir_entries(dir1, ctx->buf, BUF_SIZE);
	if (read_size <= 0)
		goto out_dir1;

	offset = 0;
	while (offset < (unsigned int)read_size) {
		dirent = (struct linux_dirent64 *)(ctx->buf + offset);
		if (dirent->d_reclen == 0) break;

		if (dirent->d_name[0] == '~' || dirent->d_type == DT_DIR || dirent->d_type == DT_UNKNOWN) {
			if (dirent->d_name[0] == '.') goto next_l1;

			snprintf(ctx->level1_path, APK_PATH_MAX, "/data/app/%s", dirent->d_name);

			dir2 = filp_open(ctx->level1_path, O_RDONLY | O_DIRECTORY, 0);
			if (!IS_ERR(dir2)) {
				read_size2 = read_dir_entries(dir2, ctx->buf2, BUF_SIZE);

				offset2 = 0;
				while (read_size2 > 0 && offset2 < (unsigned int)read_size2) {
					dirent2 = (struct linux_dirent64 *)(ctx->buf2 + offset2);
					if (dirent2->d_reclen == 0) break;
					if (strstr(dirent2->d_name, package_name) != NULL) {
						snprintf(ctx->level2_path, APK_PATH_MAX, "%s/%s", 
							ctx->level1_path, dirent2->d_name);

						if (check_apk_exists(ctx->level2_path) == 0) {
							snprintf(ctx->apk_path, APK_PATH_MAX, "%s/base.apk", 
								ctx->level2_path);
							strlcpy(apk_path, ctx->apk_path, APK_PATH_MAX);
							ctx->found = 1;
							filp_close(dir2, NULL);
							goto out_dir1;
						}
					}
					offset2 += dirent2->d_reclen;
				}
				filp_close(dir2, NULL);
			}
		}

next_l1:
		offset += dirent->d_reclen;
	}

out_dir1:
	filp_close(dir1, NULL);
out_free:
	if (ctx->found) ret = 0;
	kfree(ctx->buf);
	kfree(ctx->buf2);
	kfree(ctx);
	return ret;
}

static int find_apk_path(const char *package_name, char *apk_path)
{
	char *search_path;
	int ret;

	search_path = kmalloc(APK_PATH_MAX, GFP_KERNEL);
	if (!search_path)
		return -1;

	snprintf(search_path, APK_PATH_MAX, "/data/app/%s/base.apk",
		 package_name);

	if (vfs_stat(search_path, NULL) == 0) {
		strlcpy(apk_path, search_path, APK_PATH_MAX);
		pr_info("[manager] Found APK at standard path\n");
		kfree(search_path);
		return 0;
	}

	pr_info("[manager] Standard path not found, scanning two-level encrypted dirs\n");
	ret = find_apk_in_two_level_dirs(package_name, apk_path);
	kfree(search_path);
	return ret;
}

struct sig_context {
	char *buf;
	loff_t sig_offset;
	uint32_t sig_size;
};

static int find_signature_block(const char *apk_path, loff_t *sig_offset,
				uint32_t *sig_size)
{
	struct sig_context *ctx;
	loff_t file_size, eocd_pos;
	ssize_t read_size;
	uint32_t cd_offset;
	uint64_t block_size;
	int i, ret = -1;

	file_size = get_file_size(apk_path);
	if (file_size < 0)
		return -1;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -1;

	ctx->buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!ctx->buf) {
		kfree(ctx);
		return -1;
	}

	eocd_pos = max(0LL, file_size - EOCD_SEARCH_SIZE);
	read_size = safe_read_file(apk_path, eocd_pos, ctx->buf, BUF_SIZE);

	if (read_size < 22) {
		pr_err("[manager] File too small\n");
		goto out;
	}

	for (i = read_size - 22; i >= 0; i--) {
		uint32_t *sig = (uint32_t *) (ctx->buf + i);
		if (*sig == 0x06054b50) {
			uint32_t *cd_off_ptr = (uint32_t *) (ctx->buf + i + 16);
			cd_offset = le32_to_cpu(*cd_off_ptr);

			pr_info("[manager] EOCD found, CD offset: %u\n",
				cd_offset);

			if (cd_offset >= 24) {
				loff_t pos = cd_offset - 24;
				read_size =
				    safe_read_file(apk_path, pos, ctx->buf, 24);

				if (read_size == 24) {
					uint64_t *size_ptr = (uint64_t *) ctx->buf;
					block_size = le64_to_cpu(*size_ptr);

					if (block_size > 8
					    && block_size < 16 * 1024 * 1024) {
						*sig_offset =
						    cd_offset - block_size;
						*sig_size =
						    (uint32_t) block_size;
						pr_info
						    ("[manager] Signature block at offset: %lld, size: %u bytes\n",
						     *sig_offset, *sig_size);
						ret = 0;
						break;
					}
				}
			}
			break;
		}
	}

out:
	kfree(ctx->buf);
	kfree(ctx);
	return ret;
}

struct hash_context {
	struct crypto_shash *tfm;
	struct shash_desc *shash;
	char *buf;
	u8 hash[32];
};

static int calculate_sig_block_sha256(const char *path, loff_t sig_offset,
				      uint32_t sig_size, u8 *hash)
{
	struct hash_context *ctx;
	loff_t offset = sig_offset;
	loff_t end_offset = sig_offset + sig_size;
	ssize_t read_size;
	int ret = 0;

	pr_info("[manager] Calculating hash for signature block\n");

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -1;

	ctx->tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(ctx->tfm)) {
		pr_err("[manager] Failed to allocate SHA256\n");
		kfree(ctx);
		return -1;
	}

	ctx->shash = kmalloc(sizeof(*ctx->shash) + crypto_shash_descsize(ctx->tfm),
			GFP_KERNEL);
	if (!ctx->shash) {
		crypto_free_shash(ctx->tfm);
		kfree(ctx);
		return -1;
	}

	ctx->shash->tfm = ctx->tfm;

	ctx->buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!ctx->buf) {
		ret = -1;
		goto out;
	}

	crypto_shash_init(ctx->shash);

	while (offset < end_offset) {
		size_t to_read = min((size_t)BUF_SIZE,
				     (size_t)(end_offset - offset));
		read_size = safe_read_file(path, offset, ctx->buf, to_read);

		if (read_size <= 0) {
			pr_err("[manager] Failed to read signature block\n");
			ret = -1;
			break;
		}

		crypto_shash_update(ctx->shash, (u8 *) ctx->buf, read_size);
		offset += read_size;
	}

	if (ret == 0) {
		crypto_shash_final(ctx->shash, ctx->hash);
		memcpy(hash, ctx->hash, 32);
		pr_info("[manager] Signature block hash calculated\n");
	}

out:
	kfree(ctx->buf);
	kfree(ctx->shash);
	crypto_free_shash(ctx->tfm);
	kfree(ctx);

	return ret;
}

static bool verify_apk_signature(const char *path, const u8 *expected_hash)
{
	loff_t sig_offset;
	uint32_t sig_size;
	u8 *calculated_hash;
	int i;
	bool result = false;

	if (!path || !expected_hash)
		return false;

	calculated_hash = kmalloc(32, GFP_KERNEL);
	if (!calculated_hash)
		return false;

	if (find_signature_block(path, &sig_offset, &sig_size) != 0) {
		pr_err("[manager] Failed to find signature block\n");
		kfree(calculated_hash);
		return false;
	}

	if (calculate_sig_block_sha256(path, sig_offset, sig_size,
				       calculated_hash) != 0) {
		pr_err("[manager] Failed to calculate signature hash\n");
		kfree(calculated_hash);
		return false;
	}

	if (memcmp(calculated_hash, expected_hash, 32) == 0) {
		pr_info("[manager] Signature verification succeeded\n");
		result = true;
	} else {
		pr_warn("[manager] Signature hash mismatch\n");
		pr_warn("[manager] Calculated: ");
		for (i = 0; i < 32; i++)
			pr_cont("%02x", calculated_hash[i]);
		pr_cont("\n[manager] Expected: ");
		for (i = 0; i < 32; i++)
			pr_cont("%02x", expected_hash[i]);
		pr_cont("\n");
	}

	kfree(calculated_hash);
	return result;
}

static int scan_and_apply(void)
{
	uid_t uid;
	char *apk_path;
	int ret = -1;

	pr_info("[manager] Starting scan for %s\n", TARGET_PACKAGE);

	uid = get_uid_from_packages_list(TARGET_PACKAGE);
	if (uid == (uid_t) - 1) {
		pr_err("[manager] Package not found: %s\n", TARGET_PACKAGE);
		return -1;
	}

	apk_path = kmalloc(APK_PATH_MAX, GFP_KERNEL);
	if (!apk_path)
		return -1;

	memset(apk_path, 0, APK_PATH_MAX);
	if (find_apk_path(TARGET_PACKAGE, apk_path) != 0) {
		pr_err("[manager] APK not found\n");
		kfree(apk_path);
		return -1;
	}

	pr_info("[manager] APK path: %s\n", apk_path);

	if (verify_apk_signature(apk_path, (const u8 *)TARGET_HASH)) {
		pr_info("[manager] Granting manager privileges to UID %u\n",
			uid);
		fmac_scope_set(uid, FMAC_SCOPE_ALL);
		ret = 0;
	} else {
		pr_err("[manager] APK verification failed\n");
	}

	kfree(apk_path);
	return ret;
}

int appscan_init(void)
{
	pr_info("[manager] Module loaded\n");
	return scan_and_apply();
}