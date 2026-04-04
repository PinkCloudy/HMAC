#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>

// SHA-256 cho ra 32 byte (256 bit)
constexpr int SHA256_DIGEST_BYTES = 32;
constexpr int SHA256_BLOCK_BYTES  = 64;   // 512 bit = 64 byte mỗi block

// Tính SHA-256 của một dãy byte
std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data);

// Tiện ích: chuyển bytes sang chuỗi hex để in ra màn hình
std::string bytes_to_hex(const uint8_t* data, size_t len);
std::string bytes_to_hex(const std::array<uint8_t,32>& a);
std::string bytes_to_hex(const std::vector<uint8_t>& v);