#ifndef HMAC_H
#define HMAC_H

#include <vector>
#include <cstdint>
#include <string>

// ==========================================
// Định nghĩa hằng số và Bad MAC
// ==========================================
const uint8_t IPAD_VAL = 0x36;
const uint8_t OPAD_VAL = 0x5C;

// Hàm băm đơn giản bị lỗi Length Extension Attack
// ==========================================
// Chuẩn bị khóa
// ==========================================
// Hàm chuẩn hóa Khóa K thành K' dài đúng 64 bytes
std::vector<uint8_t> prepare_key(const std::vector<uint8_t>& key);

// ==========================================
// Lắp ráp lõi HMAC
// ==========================================
// Hàm thực thi công thức HMAC an toàn
std::vector<uint8_t> generate_hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message);

#endif // HMAC_H