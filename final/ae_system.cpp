#include "ae_system.h"
#include "aes_crypto.h"
#include "hmac.h"
#include "sha256.h"
#include "utils.h"
#include <iostream>

std::vector<uint8_t> createSecurePacket(const std::vector<uint8_t>& plaintext, 
                                        const std::vector<uint8_t>& aesKey, 
                                        const std::vector<uint8_t>& hmacKey) {
    std::cout << "\n[SENDER] BAT DAU DONG GOI ENCRYPT-THEN-MAC...\n";
    
    // 1. Mã hóa AES
    std::vector<uint8_t> iv, ciphertext;
    encryptAES(plaintext, aesKey, iv, ciphertext);
    
    // 2. Nối IV và Ciphertext để chuẩn bị xác thực
    std::vector<uint8_t> data_to_mac = iv;
    data_to_mac.insert(data_to_mac.end(), ciphertext.begin(), ciphertext.end());
    
    // 3. Tính MAC Tag bằng hàm HMAC
    std::vector<uint8_t> mac_tag = generate_hmac(hmacKey, data_to_mac);
    
    // 4. Tạo Payload: [IV] + [Ciphertext] + [MAC Tag]
    std::vector<uint8_t> payload = data_to_mac;
    payload.insert(payload.end(), mac_tag.begin(), mac_tag.end());
    
    return payload;
}

bool verifyAndExtractPacket(const std::vector<uint8_t>& payload, 
                            const std::vector<uint8_t>& aesKey, 
                            const std::vector<uint8_t>& hmacKey,
                            std::vector<uint8_t>& out_plaintext) {
    std::cout << "\n[RECEIVER] BAT DAU KIEM TRA GOI TIN...\n";

    // Chiều dài tối thiểu = 16 (IV) + 16 (1 block Ciphertext) + 32 (MAC) = 64
    if (payload.size() < AES_BLOCK_SIZE + AES_BLOCK_SIZE + SHA256_DIGEST_LENGTH) {
        std::cerr << " [!] Loi: Goi tin qua ngan!\n";
        return false;
    }

    size_t mac_start_idx = payload.size() - SHA256_DIGEST_LENGTH;
    std::vector<uint8_t> received_data_to_mac(payload.begin(), payload.begin() + mac_start_idx);
    std::vector<uint8_t> received_mac(payload.begin() + mac_start_idx, payload.end());
    
    // Tách IV và Ciphertext
    std::vector<uint8_t> iv(received_data_to_mac.begin(), received_data_to_mac.begin() + AES_BLOCK_SIZE);
    std::vector<uint8_t> ciphertext(received_data_to_mac.begin() + AES_BLOCK_SIZE, received_data_to_mac.end());

    // Tính lại MAC từ dữ liệu nhận được
    std::vector<uint8_t> computed_mac = generate_hmac(hmacKey, received_data_to_mac);

    // Chống Timing Attack
    if (!constantTimeCompare(computed_mac, received_mac)) {
        std::cerr << " [!] XAC THUC THAT BAI! MAC Tag khong khop. Du lieu da bi can thiep!\n";
        return false; // TỪ CHỐI GIẢI MÃ
    }

    std::cout << " [RECEIVER] MAC Tag HOP LE. Du lieu toan ven! Tien hanh giai ma...\n";
    try {
        out_plaintext = decryptAES(ciphertext, aesKey, iv);
        return true;
    } catch (const std::exception& e) {
        std::cerr << " [!] Loi giai ma: " << e.what() << "\n";
        return false;
    }
}