#include "hmac.h"
#include "sha256.h"
#include "utils.h"
#include <iostream>

// ==========================================
// THÀNH VIÊN 1: HÀM BAD MAC (ĐỂ SO SÁNH)
// ==========================================
std::vector<uint8_t> bad_mac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
    // Chỉ đơn giản nối Key và Message lại rồi băm (Rất nguy hiểm)
    std::vector<uint8_t> data_to_hash;
    data_to_hash.insert(data_to_hash.end(), key.begin(), key.end());
    data_to_hash.insert(data_to_hash.end(), message.begin(), message.end());
    
    return computeSHA256(data_to_hash);
}

// ==========================================
// THÀNH VIÊN 2: TIỀN XỬ LÝ KHÓA
// ==========================================
std::vector<uint8_t> prepare_key(const std::vector<uint8_t>& key) {
    std::vector<uint8_t> k_prime = key;

    // Nếu khóa dài hơn Block Size (64 bytes), phải băm nhỏ lại thành 32 bytes
    if (k_prime.size() > SHA256_BLOCK_SIZE) {
        k_prime = computeSHA256(k_prime);
    }
    
    // Nếu khóa ngắn hơn 64 bytes, thêm các byte 0x00 vào cuối cho đủ
    if (k_prime.size() < SHA256_BLOCK_SIZE) {
        k_prime.insert(k_prime.end(), SHA256_BLOCK_SIZE - k_prime.size(), 0x00);
    }
    
    return k_prime; // Luôn trả về độ dài chính xác 64 bytes
}

// ==========================================
// THÀNH VIÊN 3: LẮP RÁP LÕI HMAC & IN LOG
// ==========================================
std::vector<uint8_t> generate_hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
    std::cout << "\n--- [DEBUG HMAC CORE] THEO DOI GIA TRI TRUNG GIAN ---\n";

    // Bước 1: Gọi hàm của TV2 để chuẩn hóa khóa
    std::vector<uint8_t> k_prime = prepare_key(key);
    printHex("[TV3 in log] Khoa K' (64 bytes)    : ", k_prime);

    // Bước 2: Tạo Inner Key và Outer Key (TV2 thiết kế logic, TV3 gọi)
    std::vector<uint8_t> inner_key(SHA256_BLOCK_SIZE);
    std::vector<uint8_t> outer_key(SHA256_BLOCK_SIZE);
    
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        inner_key[i] = k_prime[i] ^ IPAD_VAL;
        outer_key[i] = k_prime[i] ^ OPAD_VAL;
    }
    
    // printHex("[TV3 in log] Inner Key (K' ^ 36) : ", inner_key); // Tùy chọn in ra nếu thích dài
    // printHex("[TV3 in log] Outer Key (K' ^ 5C) : ", outer_key);

    // Bước 3: Thực hiện Inner Hash -> H( Inner_Key || Message )
    std::vector<uint8_t> inner_data;
    inner_data.insert(inner_data.end(), inner_key.begin(), inner_key.end());
    inner_data.insert(inner_data.end(), message.begin(), message.end());
    
    std::vector<uint8_t> inner_hash = computeSHA256(inner_data);
    printHex("[TV3 in log] Inner Hash (32 bytes) : ", inner_hash);

    // Bước 4: Thực hiện Outer Hash -> H( Outer_Key || Inner_Hash )
    std::vector<uint8_t> outer_data;
    outer_data.insert(outer_data.end(), outer_key.begin(), outer_key.end());
    outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());
    
    std::vector<uint8_t> mac_tag = computeSHA256(outer_data);
    printHex("[TV3 in log] MAC TAG CUOI CUNG     : ", mac_tag);
    std::cout << "-----------------------------------------------------\n";

    return mac_tag;
}