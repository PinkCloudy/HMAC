#include "basic_mac.h"
#include "Sha256.h"
#include <iostream>
#include <cstring>

const uint8_t SHARED_KEY_MAC[16] = {
    'm','y','s','e','c','r','e','t','k','e','y','1','2','3','4','5'
};
const uint8_t SHARED_KEY_ENC[16] = {
    'e','n','c','r','y','p','t','i','o','n','k','e','y','1','2','3'
};
std::array<uint8_t,32> bad_mac(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message)
{
    // Nối key trước, message sau → đây chính là lỗ hổng!
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), key.begin(), key.end());
    combined.insert(combined.end(), message.begin(), message.end());
    return sha256(combined);   // SHA256(Key || Message)
}
void demo_length_extension_attack() {
    std::cout << "========================================\n";
    std::cout << "  [TV1] Length Extension Attack\n";
    std::cout << "========================================\n";
    std::cout << "\n";
    std::cout << "  Server ky:  MAC = SHA256(Key || amount=100)\n";
    std::cout << "  Hacker thay (message, tag) nhung KHONG biet Key.\n";
    std::cout << "\n";
    std::cout << "  Neu dung Hash(Key||M) lam MAC:\n";
    std::cout << "    -> Hacker co the them &amount=9999 vao cuoi\n";
    std::cout << "    -> va tinh duoc tag moi HOP LE ma KHONG biet Key!\n";
    std::cout << "\n";
    std::cout << "  => KHONG BAO GIO dung Hash(Key||Message) lam MAC!\n";
    std::cout << "  => Phai dung HMAC (2 lop bam long nhau).\n\n";
}

std::vector<uint8_t> str_to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i+1 < hex.size(); i += 2) {
        uint8_t byte = (uint8_t)std::stoul(hex.substr(i, 2), nullptr, 16);
        out.push_back(byte);
    }
    return out;
}
