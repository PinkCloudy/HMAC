#include "tv5_receiver.h"
#include <iostream>
extern std::string compute_hmac_logic(const std::string& key, const std::string& data);
/**
 * Giai thich: Ham nay duyet qua moi byte de thoi gian xu ly luon bang nhau,
 * ngan chan ke tan cong do doan ma (Timing Attack).
 */
bool safe_compare(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) {
        return false;
    }
    int diff = 0;
    for (size_t i = 0; i < a.length(); ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return (diff == 0);
}
/**
 * Giai thich: Logic thuc hien theo mo hinh Encrypt-then-MAC.
 * Kiem tra 'tem' HMAC truoc, neu on moi cho phep giai ma.
 */
bool verify_and_decrypt(const std::string& key,
                        const std::string& iv,
                        const std::string& ciphertext,
                        const std::string& received_tag)
{
    std::cout << "[TV5] Dang bat dau qua trinh xac thuc..." << std::endl;)
    std::string data_to_verify = iv + ciphertext;
    std::string computed_tag = compute_hmac_logic(key, data_to_verify);
    if (safe_compare(computed_tag, received_tag)) {
        std::cout << "[SUCCESS] HMAC khop! Du lieu toan ven." << std::endl;
        std::cout << "[ACTION] Chuyen du lieu sang module giai ma AES..." << std::endl;
        return true;
    } else {
        std::cout << "[WARNING] HMAC SAI LECH! Phat hien can thiep vao goi tin." << std::endl;
        return false;
    }
}
}
