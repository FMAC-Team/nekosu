#include "sigcheck.h"

const std::string SigCheck::DEBUG_EXPECTED_SIGNATURE = "1692015C04AA6CEA61B9E3FBF6CBC9FA5933E6A6A5788C12D1289A6D9E51D45E";
const std::string SigCheck::RELEASE_EXPECTED_SIGNATURE = "1C9CEAC6A82DE20EF909103926C296B2882653B4C9189360FCA9F081FCD663B1";

const std::vector<uint8_t> SigCheck::APK_SIGNING_BLOCK_MAGIC = {
    0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
    0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
};

bool SigCheck::validate(const std::string& apkPath) {
    std::ifstream raf(apkPath, std::ios::binary | std::ios::ate);
    if (!raf.is_open()) return false;

    try {
        long eocdOffset = findEOCD(raf);
        if (eocdOffset == -1) return false;

        // 获取中央目录偏移
        raf.seekg(eocdOffset + 16);
        uint32_t cdOffset32;
        raf.read(reinterpret_cast<char*>(&cdOffset32), 4);
        long centralDirOffset = static_cast<long>(cdOffset32);

        // 验证 Magic
        raf.seekg(centralDirOffset - 16);
        std::vector<uint8_t> magicBuf(16);
        raf.read(reinterpret_cast<char*>(magicBuf.data()), 16);
        if (magicBuf != APK_SIGNING_BLOCK_MAGIC) return false;

        // 读取 Block Size
        raf.seekg(centralDirOffset - 24);
        uint64_t blockSize;
        raf.read(reinterpret_cast<char*>(&blockSize), 8);

        long pairsSize = static_cast<long>(blockSize - 24);
        long sizeHeaderOffset = centralDirOffset - (blockSize + 8);
        
        std::vector<uint8_t> pairs(pairsSize);
        raf.seekg(sizeHeaderOffset + 8);
        raf.read(reinterpret_cast<char*>(pairs.data()), pairsSize);

        const uint8_t* p = pairs.data();
        const uint8_t* end = p + pairsSize;
        const uint8_t* targetBlock = nullptr;
        size_t targetBlockLen = 0;

        // 寻找 V3(0xf05368c0) 或 V2(0x7109871a)
        while (p + 12 <= end) {
            uint64_t len = *reinterpret_cast<const uint64_t*>(p);
            uint32_t id = *reinterpret_cast<const uint32_t*>(p + 8);
            if (id == 0xf05368c0 || (id == 0x7109871a && !targetBlock)) {
                targetBlock = p + 12;
                targetBlockLen = static_cast<size_t>(len - 4);
                if (id == 0xf05368c0) break; 
            }
            p += (len + 8);
        }

        if (!targetBlock) return false;

        // 解析证书
        const uint8_t* cursor = targetBlock;
        const uint8_t* blockEnd = targetBlock + targetBlockLen;

        std::vector<uint8_t> signers = getLengthPrefixedSlice(&cursor, blockEnd);
        const uint8_t* sCursor = signers.data();
        const uint8_t* sEnd = sCursor + signers.size();

        while (sCursor < sEnd) {
            std::vector<uint8_t> signer = getLengthPrefixedSlice(&sCursor, sEnd);
            const uint8_t* signerPtr = signer.data();
            const uint8_t* signerEnd = signerPtr + signer.size();

            std::vector<uint8_t> signedData = getLengthPrefixedSlice(&signerPtr, signerEnd);
            const uint8_t* sdPtr = signedData.data();
            
            // 跳过 Digests
            uint32_t digestsLen = *reinterpret_cast<const uint32_t*>(sdPtr);
            sdPtr += (4 + digestsLen);

            // 获取 Certificates
            const uint8_t* certsPtr = sdPtr; 
            std::vector<uint8_t> certsWrap = getLengthPrefixedSlice(&certsPtr, signedData.data() + signedData.size());
            
            const uint8_t* cPtr = certsWrap.data();
            const uint8_t* cEnd = cPtr + certsWrap.size();
            while (cPtr < cEnd) {
                std::vector<uint8_t> cert = getLengthPrefixedSlice(&cPtr, cEnd);
                std::string currentSig = getSHA256(cert.data(), cert.size());
                if (currentSig == DEBUG_EXPECTED_SIGNATURE || currentSig == RELEASE_EXPECTED_SIGNATURE) {
                    return true;
                }
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

long SigCheck::findEOCD(std::ifstream& file) {
    file.seekg(0, std::ios::end);
    long fileLen = file.tellg();
    if (fileLen < 22) return -1;

    size_t scanLen = std::min((long)65557, fileLen);
    std::vector<uint8_t> buffer(scanLen);
    file.seekg(fileLen - scanLen);
    file.read(reinterpret_cast<char*>(buffer.data()), scanLen);

    for (int i = scanLen - 22; i >= 0; i--) {
        if (buffer[i] == 0x50 && buffer[i+1] == 0x4B && buffer[i+2] == 0x05 && buffer[i+3] == 0x06) {
            return fileLen - scanLen + i;
        }
    }
    return -1;
}

std::vector<uint8_t> SigCheck::getLengthPrefixedSlice(const uint8_t** cursor, const uint8_t* end) {
    if (*cursor + 4 > end) return {};
    uint32_t len = *reinterpret_cast<const uint32_t*>(*cursor);
    *cursor += 4;
    if (*cursor + len > end) return {};
    std::vector<uint8_t> res(*cursor, *cursor + len);
    *cursor += len;
    return res;
}

std::string SigCheck::getSHA256(const uint8_t* data, size_t len) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)hash[i];
    }
    return ss.str();
}
