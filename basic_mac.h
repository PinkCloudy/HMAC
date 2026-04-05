#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>

// ── HẰNG SỐ DÙNG CHUNG TOÀN PROJECT ──────────────────────
constexpr int HMAC_KEY_SIZE = 16;   // 16 byte = 128 bit
constexpr int AES_KEY_SIZE  = 16;   // AES-128

// Khóa demo (dùng chung cho tất cả thành viên)
extern const uint8_t SHARED_KEY_MAC[16];  // khóa HMAC
extern const uint8_t SHARED_KEY_ENC[16];  // khóa mã hóa

// bad_mac = SHA256(Key || Message)  [DỄ BỊ TẤN CÔNG]
std::array<uint8_t,32> bad_mac(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message
);

// Demo giải thích lỗ hổng
void demo_length_extension_attack();

// Tiện ích: chuyển chuỗi ký tự sang vector<uint8_t>
std::vector<uint8_t> str_to_bytes(const std::string& s);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);