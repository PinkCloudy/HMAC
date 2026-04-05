#include <iostream>
#include <vector>
#include <string>
#include "ae_system.h"
#include "hmac.h"
#include "utils.h"

int main() {
    std::cout << "=========================================================\n";
    std::cout << "    DO AN: AUTHENTICATED ENCRYPTION (HMAC) - NHOM 6      \n";
    std::cout << "=========================================================\n";

    // ==========================================================
    // KỊCH BẢN 1: TEST VECTOR CHUẨN QUỐC TẾ (RFC 4231 - Test Case 1)
    // Chứng minh hàm HMAC tự code chạy chuẩn xác 100%
    // ==========================================================
    std::cout << "\n>>> KICH BAN 1: KIEM THU HMAC VOI CHUAN RFC 4231 <<<\n";
    
    // Khóa chuẩn: 20 bytes 0x0b
    std::vector<uint8_t> testKey(20, 0x0b); 
    // Thông điệp chuẩn: "Hi There"
    std::string testMsgStr = "Hi There";
    std::vector<uint8_t> testMsg(testMsgStr.begin(), testMsgStr.end());
    
    std::vector<uint8_t> testMac = generate_hmac(testKey, testMsg);
    
    printHex("\n[+] Ket qua nhom tu code : ", testMac);
    std::cout << "[+] Chuan quoc te RFC4231: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7\n";


    // ==========================================================
    // KỊCH BẢN 2: GIẢ LẬP TRUYỀN DỮ LIỆU & BỊ TẤN CÔNG (ENCRYPT-THEN-MAC)
    // ==========================================================
    std::cout << "\n\n>>> KICH BAN 2: MO PHONG HE THONG AE VA TAN CONG <<<\n";

    // 1. Thống nhất khóa
    std::vector<uint8_t> aesKey(32, 0xA1); // Khóa AES 32 bytes (Giả lập)
    std::string hmacKeyStr = "Toitaigioibancungthe";
    std::vector<uint8_t> hmacKey(hmacKeyStr.begin(), hmacKeyStr.end());

    // 2. Alice gửi tin
    std::string secretMessage = "Loideptrai";
    std::vector<uint8_t> plaintext(secretMessage.begin(), secretMessage.end());
    
    std::vector<uint8_t> packet = createSecurePacket(plaintext, aesKey, hmacKey);
    printHex("\n[NETWORK] Goi tin dang truyen di tren mang:\n", packet);

    // --- KỊCH BẢN 2.1: NHẬN TIN BÌNH THƯỜNG ---
    std::cout << "\n--- TRUONG HOP A: DU LIEU AN TOAN (Khong bi tan cong) ---";
    std::vector<uint8_t> decryptedText_A;
    if (verifyAndExtractPacket(packet, aesKey, hmacKey, decryptedText_A)) {
        std::string recoveredMsg(decryptedText_A.begin(), decryptedText_A.end());
        std::cout << "[!] NGUOI NHAN DOC DUOC TIN: " << recoveredMsg << "\n";
    }

    // --- KỊCH BẢN 2.2: BỊ HACKER TẤN CÔNG ĐƯỜNG TRUYỀN ---
    std::cout << "\n--- TRUONG HOP B: HACKER SUA DOI DU LIEU ---";
    std::cout << "\n[HACKER] Dang bat goi tin va dao bit tai Byte thu 20...\n";
    
    std::vector<uint8_t> tamperedPacket = packet;
    tamperedPacket[20] ^= 0xFF; // Cố tình làm hỏng (đảo bit) 1 byte trong Ciphertext

    std::vector<uint8_t> decryptedText_B;
    if (verifyAndExtractPacket(tamperedPacket, aesKey, hmacKey, decryptedText_B)) {
        std::string recoveredMsg(decryptedText_B.begin(), decryptedText_B.end());
        std::cout << "[!] NGUOI NHAN DOC DUOC TIN: " << recoveredMsg << "\n";
    } else {
        std::cout << "[!] He thong da tu choi xac thuc thanh cong.\n";
    }

    return 0;
}