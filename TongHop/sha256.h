#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <cstdint>

// Kích thước đầu ra chuẩn của SHA-256 là 32 bytes (256 bits)
const size_t SHA256_DIGEST_LENGTH = 32;
// Kích thước khối (Block size) dùng cho HMAC và Padding
const size_t SHA256_BLOCK_SIZE = 64; 

// Hàm băm SHA-256 tự triển khai từ A-Z
std::vector<uint8_t> computeSHA256(const std::vector<uint8_t>& data);

#endif // SHA256_H