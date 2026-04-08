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

struct apk_search_ctx {
	struct dir_context ctx;
	const char *target_pkg;
	char *found_path;
	char current_l1_path[APK_PATH_MAX];
	bool found;
};

static ssize_t safe_read_file(const char *path, loff_t offset, char *buf, size_t len)
{
	struct file *file;
	ssize_t ret;
	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file)) return PTR_ERR(file);
	ret = kernel_read(file, buf, len, &offset);
	filp_close(file, NULL);
	return ret;
}

static loff_t get_file_size(const char *path)
{
	struct kstat stat;
	if (vfs_stat(path, &stat)) return -1;
	return stat.size;
}


static int filldir_level2(struct dir_context *ctx, const char *name, int len,
			  loff_t offset, u64 ino, unsigned int type)
{
	struct apk_search_ctx *s_ctx = container_of(ctx, struct apk_search_ctx, ctx);
	char full_path[APK_PATH_MAX];
	struct kstat stat;

	if (s_ctx->found || name[0] == '.') return 0;

	if (strnstr(name, s_ctx->target_pkg, len)) {
		snprintf(full_path, APK_PATH_MAX, "%s/%.*s/base.apk", 
			 s_ctx->current_l1_path, len, name);

		if (vfs_stat(full_path, &stat) == 0 && S_ISREG(stat.mode)) {
			strlcpy(s_ctx->found_path, full_path, APK_PATH_MAX);
			s_ctx->found = true;
			return -1; 
		}
	}
	return 0;
}

static int filldir_level1(struct dir_context *ctx, const char *name, int len,
			  loff_t offset, u64 ino, unsigned int type)
{
	struct apk_search_ctx *s_ctx = container_of(ctx, struct apk_search_ctx, ctx);
	struct file *sub_dir;

	if (s_ctx->found || name[0] == '.') return 0;

	if (name[0] != '~') return 0;

	snprintf(s_ctx->current_l1_path, APK_PATH_MAX, "/data/app/%.*s", len, name);

	sub_dir = filp_open(s_ctx->current_l1_path, O_RDONLY | O_DIRECTORY, 0);
	if (!IS_ERR(sub_dir)) {
		struct apk_search_ctx inner_ctx = {
			.ctx.actor = filldir_level2,
			.target_pkg = s_ctx->target_pkg,
			.found_path = s_ctx->found_path,
			.found = false
		};
		memcpy(inner_ctx.current_l1_path, s_ctx->current_l1_path, APK_PATH_MAX);
		
		iterate_dir(sub_dir, &inner_ctx.ctx);
		if (inner_ctx.found) s_ctx->found = true;
		
		filp_close(sub_dir, NULL);
	}

	return s_ctx->found ? -1 : 0;
}

static int find_apk_path(const char *package_name, char *apk_path)
{
	struct file *root_dir;
	struct apk_search_ctx s_ctx = {
		.ctx.actor = filldir_level1,
		.target_pkg = package_name,
		.found_path = apk_path,
		.found = false
	};

	snprintf(apk_path, APK_PATH_MAX, "/data/app/%s/base.apk", package_name);
	if (vfs_stat(apk_path, NULL) == 0) return 0;

	root_dir = filp_open("/data/app", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(root_dir)) return -1;

	iterate_dir(root_dir, &s_ctx.ctx);
	filp_close(root_dir);

	return s_ctx.found ? 0 : -1;
}

static uid_t get_uid_from_packages_list(const char *package_name)
{
	struct file *file;
	char *buf, *line, *p, *token;
	loff_t pos = 0;
	uid_t target_uid = -1;
	ssize_t read_size;

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf) return -1;

	file = filp_open("/data/system/packages.list", O_RDONLY, 0);
	if (IS_ERR(file)) {
		kfree(buf);
		return -1;
	}

	read_size = kernel_read(file, buf, BUF_SIZE - 1, &pos);
	if (read_size > 0) {
		buf[read_size] = '\0';
		p = buf;
		while ((line = strsep(&p, "\n")) != NULL) {
			token = strsep(&line, " ");
			if (token && strcmp(token, package_name) == 0) {
				token = strsep(&line, " ");
				if (token && kstrtouint(token, 10, &target_uid) == 0) break;
			}
		}
	}
	filp_close(file, NULL);
	kfree(buf);
	return target_uid;
}

static int find_signature_block(const char *apk_path, loff_t *sig_offset, uint32_t *sig_size)
{
	char *buf;
	loff_t file_size, eocd_pos;
	ssize_t read_size;
	int i, ret = -1;

	file_size = get_file_size(apk_path);
	if (file_size < 100) return -1;

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf) return -1;

	eocd_pos = max(0LL, file_size - EOCD_SEARCH_SIZE);
	read_size = safe_read_file(apk_path, eocd_pos, buf, BUF_SIZE);

	for (i = (int)read_size - 22; i >= 0; i--) {
		if (*(uint32_t *)(buf + i) == 0x06054b50) { // EOCD Magic
			uint32_t cd_offset = le32_to_cpu(*(uint32_t *)(buf + i + 16));
			if (cd_offset >= 24) {
				read_size = safe_read_file(apk_path, cd_offset - 24, buf, 24);
				if (read_size == 24 && memcmp(buf + 8, "APK Sig Block 42", 16) == 0) {
					uint64_t block_size = le64_to_cpu(*(uint64_t *)buf);
					*sig_offset = cd_offset - block_size - 8;
					*sig_size = (uint32_t)block_size;
					ret = 0;
				}
			}
			break;
		}
	}
	kfree(buf);
	return ret;
}

static int calculate_hash(const char *path, loff_t offset, uint32_t size, u8 *hash)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	char *buf;
	int ret = -1;
	uint32_t remain = size;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) return -1;

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!desc || !buf) goto out;

	desc->tfm = tfm;
	crypto_shash_init(desc);

	while (remain > 0) {
		size_t to_read = min((size_t)BUF_SIZE, (size_t)remain);
		ssize_t n = safe_read_file(path, offset, buf, to_read);
		if (n <= 0) break;
		crypto_shash_update(desc, buf, n);
		offset += n;
		remain -= n;
	}

	if (remain == 0) ret = crypto_shash_final(desc, hash);

out:
	kfree(buf);
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static bool verify_apk_signature(const char *path, const u8 *expected_hash)
{
	loff_t sig_offset;
	uint32_t sig_size;
	u8 calc_hash[32];

	if (find_signature_block(path, &sig_offset, &sig_size) != 0) return false;
	if (calculate_hash(path, sig_offset, sig_size, calc_hash) != 0) return false;

	return memcmp(calc_hash, expected_hash, 32) == 0;
}

static int scan_and_apply(void)
{
	uid_t uid;
	char *apk_path;
	int ret = -1;

	uid = get_uid_from_packages_list(TARGET_PACKAGE);
	if (uid == (uid_t)-1) return -1;

	apk_path = kmalloc(APK_PATH_MAX, GFP_KERNEL);
	if (!apk_path) return -1;

	if (find_apk_path(TARGET_PACKAGE, apk_path) == 0) {
		pr_info("[manager] Found APK: %s\n", apk_path);
		if (verify_apk_signature(apk_path, (const u8 *)TARGET_HASH)) {
			pr_info("[manager] Verification passed. Granting privileges to UID %u\n", uid);
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