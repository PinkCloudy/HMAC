/*
 * ============================================================
 *  TV2 – TIỀN XỬ LÝ KHÓA HMAC
 *  File: key_processing.h
 * ============================================================
 */

#pragma once
#include "Sha256.h"      // << ĐÚNG TÊN FILE: Sha256.h (chữ S hoa)
#include <vector>
#include <array>
#include <iostream>

constexpr uint8_t IPAD = 0x36;
constexpr uint8_t OPAD = 0x5C;

// Chuẩn hóa khóa → K' (64 byte)
inline std::array<uint8_t,64> process_key(const std::vector<uint8_t>& key) {
    std::array<uint8_t,64> k_prime = {};
    if (key.size() > 64) {
        auto hashed = sha256(key);
        std::copy(hashed.begin(), hashed.end(), k_prime.begin());
    } else {
        std::copy(key.begin(), key.end(), k_prime.begin());
    }
    return k_prime;
}

// K' XOR ipad → dùng cho Inner Hash
inline std::array<uint8_t,64> make_inner_key(const std::array<uint8_t,64>& k_prime) {
    std::array<uint8_t,64> result;
    for (int i = 0; i < 64; i++)
        result[i] = k_prime[i] ^ IPAD;
    return result;
}

// K' XOR opad → dùng cho Outer Hash
inline std::array<uint8_t,64> make_outer_key(const std::array<uint8_t,64>& k_prime) {
    std::array<uint8_t,64> result;
    for (int i = 0; i < 64; i++)
        result[i] = k_prime[i] ^ OPAD;
    return result;
}

inline void show_key_details(const std::vector<uint8_t>& key) {
    std::cout << "  [TV2] Key goc (" << key.size() << "B): "
              << bytes_to_hex(key) << "\n";
    auto k  = process_key(key);
    auto ki = make_inner_key(k);
    auto ko = make_outer_key(k);
    std::cout << "  [TV2] K'         : " << bytes_to_hex(k.data(),16)  << "...\n";
    std::cout << "  [TV2] K' XOR 0x36: " << bytes_to_hex(ki.data(),16) << "...\n";
    std::cout << "  [TV2] K' XOR 0x5C: " << bytes_to_hex(ko.data(),16) << "...\n";
}