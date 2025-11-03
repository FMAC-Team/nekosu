#ifndef _APK_SIG_PARSER_H
#define _APK_SIG_PARSER_H

#include <linux/types.h>
#include <linux/fs.h>

/* APK Signing Block V2 Scheme ID */
#define APK_SIG_V2_SCHEME_ID        0x7109871a

/* Content digest algorithms */
#define CONTENT_DIGEST_CHUNKED_SHA256       0x0103
#define CONTENT_DIGEST_CHUNKED_SHA512       0x0104
#define CONTENT_DIGEST_VERITY_CHUNKED_SHA256 0x0105

/* Maximum signature size to prevent DoS attacks */
#define MAX_SIGNATURE_SIZE          (10 * 1024 * 1024)  // 10MB

/**
 * struct apk_signature_digest - Structure to hold APK signature digest information
 * @sha256: SHA256 digest bytes (32 bytes)
 * @digest_algorithm: Algorithm used (CONTENT_DIGEST_CHUNKED_SHA256, etc.)
 * @num_signers: Number of signers found (currently only first signer is processed)
 * @found: Boolean indicating if a valid digest was found
 */
struct apk_signature_digest {
    u8 sha256[32];          /* SHA256 digest */
    u32 digest_algorithm;   /* Algorithm ID */
    u32 num_signers;        /* Number of signers in block */
    bool found;             /* True if digest was successfully extracted */
};

/**
 * extract_apk_signature_digest - Extract APK V2 signature content digest
 * @path: Path to the APK file (kernel-accessible path)
 * @digest: Output structure to store the digest information
 *
 * This function extracts the content digest from an APK file's V2 signature block.
 * It supports both chunked SHA256 and verity chunked SHA256 algorithms.
 *
 * Return values:
 *   0 - Success, digest->found will be true if a valid digest was extracted
 *  -ENOENT - No APK V2 signature block found
 *  -EINVAL - Invalid arguments or file format
 *  -ENOMEM - Memory allocation failure
 *  -EIO - I/O error reading the file
 *  Other negative error codes from kernel filesystem operations
 *
 * Note: This function must be called from process context as it may sleep
 *       during file operations and memory allocation.
 */
int extract_apk_signature_digest(const char *path, 
                                struct apk_signature_digest *digest);

#endif /* _APK_SIG_PARSER_H */