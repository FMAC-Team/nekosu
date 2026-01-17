#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>

class SigCheck {
public:
    static bool validate(const std::string& apkPath);

private:
    static const std::string DEBUG_EXPECTED_SIGNATURE;
    static const std::string RELEASE_EXPECTED_SIGNATURE;
    static const std::vector<uint8_t> APK_SIGNING_BLOCK_MAGIC;

    static long findEOCD(std::ifstream& file);
    static std::string getSHA256(const uint8_t* data, size_t len);
    static std::vector<uint8_t> getLengthPrefixedSlice(const uint8_t** cursor, const uint8_t* end);
};
