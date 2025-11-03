#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/string.h>

#define ZIP_END_CENTRAL_DIR_SIG     0x06054b50
#define ZIP_EOCD_MIN_SIZE           22

#define APK_SIG_BLOCK_MAGIC         "APK Sig Block 42"
#define APK_SIG_BLOCK_MAGIC_LEN     16
#define APK_SIG_BLOCK_MIN_SIZE      32
#define APK_SIG_V2_SCHEME_ID        0x7109871a

#define CONTENT_DIGEST_CHUNKED_SHA256       0x0103
#define CONTENT_DIGEST_CHUNKED_SHA512       0x0104
#define CONTENT_DIGEST_VERITY_CHUNKED_SHA256 0x0105

#define STREAM_BUFFER_SIZE          (64 * 1024)   // 64KB
#define EOCD_SEARCH_BUFFER          (16 * 1024)   // 16KB
#define MAX_SIGNATURE_SIZE          (10 * 1024 * 1024)  // 10MB

struct zip_eocd {
    __le32 signature;     
    __le16 disk_number;
    __le16 cd_start_disk;
    __le16 cd_entries_disk;
    __le16 cd_entries_total;
    __le32 cd_size;
    __le32 cd_offset;
    __le16 comment_len;
} __attribute__((packed));

struct apk_sig_block_footer {
    __le64 size;
    char magic[16];      
} __attribute__((packed));

struct apk_signature_digest {
    u8 sha256[32];          
    u32 digest_algorithm;  
    u32 num_signers;    
    bool found;
};

static int read_file_at_offset(struct file *filp, loff_t offset, 
                               void *buf, size_t len)
{
    ssize_t ret;

    if (!filp || !buf || len == 0)
        return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ret = kernel_read(filp, buf, len, &offset);
#else
    {
        mm_segment_t old_fs = get_fs();
        set_fs(KERNEL_DS);
        ret = vfs_read(filp, (char __user *)buf, len, &offset);
        set_fs(old_fs);
    }
#endif

    return (ret == (ssize_t)len) ? 0 : -EIO;
}

static int find_eocd(struct file *filp, loff_t file_size, 
                     struct zip_eocd *eocd, loff_t *eocd_offset)
{
    u8 *buf;
    loff_t offset, search_start;
    int i, ret = -ENOENT;
    size_t read_size;

    buf = kmalloc(EOCD_SEARCH_BUFFER, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    search_start = max_t(loff_t, 0, file_size - 65536);

    for (offset = file_size - ZIP_EOCD_MIN_SIZE; 
         offset >= search_start; 
         offset -= (EOCD_SEARCH_BUFFER - ZIP_EOCD_MIN_SIZE)) {
        
        read_size = min_t(size_t, EOCD_SEARCH_BUFFER, 
                         (size_t)(file_size - offset));
        
        if (read_file_at_offset(filp, offset, buf, read_size))
            continue;

        for (i = (int)read_size - ZIP_EOCD_MIN_SIZE; i >= 0; i--) {
            if (*((__le32 *)(buf + i)) == cpu_to_le32(ZIP_END_CENTRAL_DIR_SIG)) {
                memcpy(eocd, buf + i, sizeof(*eocd));
                *eocd_offset = offset + i;
                ret = 0;
                goto out;
            }
        }
    }

out:
    kfree(buf);
    return ret;
}

static int parse_v2_signer_block(struct file *filp, loff_t signer_offset,
                                 u64 signer_len,
                                 struct apk_signature_digest *result)
{
    u8 *buf;
    loff_t current_offset = signer_offset;
    u32 signed_data_len, digests_len;
    u32 algorithm, digest_len;
    u64 remaining_digests;
    int ret = -ENOENT;
    bool found_sha256 = false;

    if (signer_len < 16) {
        pr_err("Signer block too small: %llu bytes\n", signer_len);
        return -EINVAL;
    }

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    ret = read_file_at_offset(filp, current_offset, &signed_data_len, 4);
    if (ret)
        goto out;

    signed_data_len = le32_to_cpu(signed_data_len);
    current_offset += 4;

    if (signed_data_len < 8 || signed_data_len > signer_len - 4) {
        pr_err("Invalid signed_data_len: %u (signer_len=%llu)\n", 
               signed_data_len, signer_len);
        ret = -EINVAL;
        goto out;
    }

    ret = read_file_at_offset(filp, current_offset, &digests_len, 4);
    if (ret)
        goto out;

    digests_len = le32_to_cpu(digests_len);
    current_offset += 4;

    if (digests_len < 8 || digests_len > signed_data_len - 4) {
        pr_err("Invalid digests_len: %u\n", digests_len);
        ret = -EINVAL;
        goto out;
    }

    remaining_digests = digests_len;
    
    while (remaining_digests >= 8 && !found_sha256) {
        ret = read_file_at_offset(filp, current_offset, buf, 8);
        if (ret) {
            pr_err("Failed to read digest header\n");
            goto out;
        }

        memcpy(&algorithm, buf, 4);
        memcpy(&digest_len, buf + 4, 4);
        algorithm = le32_to_cpu(algorithm);
        digest_len = le32_to_cpu(digest_len);

        current_offset += 8;
        remaining_digests -= 8;

        if (digest_len > remaining_digests || digest_len > 1024) {
            pr_err("Invalid digest_len: %u (remaining=%llu)\n", 
                   digest_len, remaining_digests);
            ret = -EINVAL;
            goto out;
        }

        if ((algorithm == CONTENT_DIGEST_CHUNKED_SHA256 ||
             algorithm == CONTENT_DIGEST_VERITY_CHUNKED_SHA256) &&
            digest_len == 32) {
            
            ret = read_file_at_offset(filp, current_offset, 
                                     result->sha256, 32);
            if (ret) {
                pr_err("Failed to read SHA256 digest bytes\n");
                goto out;
            }

            result->digest_algorithm = algorithm;
            result->found = true;
            found_sha256 = true;
            ret = 0;
            break;
        }

        current_offset += digest_len;
        remaining_digests -= digest_len;
    }

    if (!found_sha256) {
        pr_warn("No SHA256 content digest found in signer block\n");
        ret = -ENOENT;
    }

out:
    kfree(buf);
    return ret;
}

static int stream_parse_sig_block(struct file *filp, loff_t pairs_offset,
                                  u64 pairs_size,
                                  struct apk_signature_digest *digest)
{
    u8 *buffer;
    loff_t file_offset = pairs_offset;
    u64 processed = 0;
    size_t buffer_pos = 0;
    size_t buffer_valid = 0;
    u64 pair_len;
    u32 id;
    int ret = -ENOENT;
    u32 signers_length, first_signer_len;
    u64 value_len;
    loff_t value_offset;

    buffer = kmalloc(STREAM_BUFFER_SIZE, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    while (processed < pairs_size) {
        if (buffer_valid - buffer_pos < 12) {
            size_t to_read;
            
            if (buffer_pos > 0 && buffer_valid > buffer_pos) {
                size_t remaining = buffer_valid - buffer_pos;
                memmove(buffer, buffer + buffer_pos, remaining);
                buffer_valid = remaining;
            } else {
                buffer_valid = 0;
            }
            buffer_pos = 0;

            to_read = min_t(size_t, STREAM_BUFFER_SIZE - buffer_valid,
                           (size_t)(pairs_size - processed));
            
            if (to_read > 0) {
                ret = read_file_at_offset(filp, file_offset, 
                                         buffer + buffer_valid, to_read);
                if (ret) {
                    pr_err("Failed to read at offset %lld\n", file_offset);
                    ret = -EIO;
                    goto out;
                }
                file_offset += to_read;
                buffer_valid += to_read;
            }
        }

        if (buffer_valid - buffer_pos < 12) {
            break;
        }

        memcpy(&pair_len, buffer + buffer_pos, 8);
        memcpy(&id, buffer + buffer_pos + 8, 4);
        
        pair_len = le64_to_cpu(pair_len);
        id = le32_to_cpu(id);

        if (pair_len < 4 || pair_len > pairs_size - processed) {
            pr_err("Invalid pair length: %llu at offset %llu\n", 
                   pair_len, processed);
            ret = -EINVAL;
            goto out;
        }

        value_len = pair_len - 4;
        value_offset = pairs_offset + processed + 12;

        if (id == APK_SIG_V2_SCHEME_ID) {
            if (value_len < 12) {
                pr_err("V2 value too small: %llu\n", value_len);
                ret = -EINVAL;
                goto out;
            }

            ret = read_file_at_offset(filp, value_offset, &signers_length, 4);
            if (ret) {
                pr_err("Failed to read signers_length\n");
                goto out;
            }
            signers_length = le32_to_cpu(signers_length);
            
            if (signers_length < 8 || signers_length > value_len - 4) {
                pr_err("Invalid signers_length: %u (value_len=%llu)\n", 
                       signers_length, value_len);
                ret = -EINVAL;
                goto out;
            }

            ret = read_file_at_offset(filp, value_offset + 4, 
                                     &first_signer_len, 4);
            if (ret) {
                pr_err("Failed to read first signer length\n");
                goto out;
            }
            first_signer_len = le32_to_cpu(first_signer_len);

            if (first_signer_len < 12 || first_signer_len > signers_length - 4) {
                pr_err("Invalid first_signer_len: %u\n", first_signer_len);
                ret = -EINVAL;
                goto out;
            }

            digest->num_signers = 1;
            ret = parse_v2_signer_block(filp, value_offset + 8, 
                                       first_signer_len, digest);
            goto out;
        }

        u64 entry_total_size = 8 + pair_len;
        processed += entry_total_size;

        if (entry_total_size <= buffer_valid - buffer_pos) {
            buffer_pos += entry_total_size;
        } else {
            u64 skip_in_buffer = buffer_valid - buffer_pos;
            u64 skip_in_file = entry_total_size - skip_in_buffer;
            file_offset += skip_in_file;
            buffer_pos = 0;
            buffer_valid = 0;
        }
    }

    if (ret == -ENOENT) {
        pr_debug("No APK Signature Scheme V2 block found\n");
    }

out:
    kfree(buffer);
    return ret;
}

static int find_apk_sig_block(struct file *filp, loff_t eocd_offset,
                              struct apk_signature_digest *digest)
{
    struct apk_sig_block_footer footer;
    loff_t footer_offset, block_offset, pairs_offset;
    u64 pairs_size, initial_size;
    int ret;

    footer_offset = eocd_offset - sizeof(footer);
    if (footer_offset < 0) {
        return -ENOENT;
    }

    ret = read_file_at_offset(filp, footer_offset, &footer, sizeof(footer));
    if (ret) {
        return ret;
    }

    if (memcmp(footer.magic, APK_SIG_BLOCK_MAGIC, APK_SIG_BLOCK_MAGIC_LEN) != 0) {
        return -ENOENT;
    }

    pairs_size = le64_to_cpu(footer.size);
    
    if (pairs_size < APK_SIG_BLOCK_MIN_SIZE || pairs_size > MAX_SIGNATURE_SIZE) {
        pr_err("Invalid APK sig block size: %llu\n", pairs_size);
        return -EINVAL;
    }

    block_offset = footer_offset - pairs_size - 8;
    if (block_offset < 0) {
        return -EINVAL;
    }

    ret = read_file_at_offset(filp, block_offset, &initial_size, 8);
    if (ret) {
        return ret;
    }

    initial_size = le64_to_cpu(initial_size);
    if (initial_size != pairs_size) {
        pr_err("Size mismatch in APK sig block\n");
        return -EINVAL;
    }

    pairs_offset = block_offset + 8;
    return stream_parse_sig_block(filp, pairs_offset, pairs_size, digest);
}

int extract_apk_signature_digest(const char *path, 
                                 struct apk_signature_digest *digest)
{
    struct file *filp;
    loff_t file_size, eocd_offset;
    struct zip_eocd eocd;
    int ret;

    if (!path || !digest)
        return -EINVAL;

    memset(digest, 0, sizeof(*digest));

    filp = filp_open(path, O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(filp)) {
        pr_err("Failed to open APK file: %s (error: %ld)\n", path, PTR_ERR(filp));
        return PTR_ERR(filp);
    }

    file_size = i_size_read(file_inode(filp));
    if (file_size < ZIP_EOCD_MIN_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    ret = find_eocd(filp, file_size, &eocd, &eocd_offset);
    if (ret) {
        goto out;
    }

    ret = find_apk_sig_block(filp, eocd_offset, digest);

out:
    filp_close(filp, NULL);
    return ret;
}
