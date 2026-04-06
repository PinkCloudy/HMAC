#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>   

using namespace std; // Đã thêm theo ý Kiệt niisan nè!

// Hàm in mã Hex gọn gàng hơn
void print_hex(const string& label, const vector<uint8_t>& data) {
    cout << label << ": ";
    for (auto b : data) cout << hex << setw(2) << setfill('0') << (int)b;
    cout << dec << endl;
}

/**
 * NHIỆM VỤ: tv4_ae_sender
 * Mô hình: Encrypt-then-MAC (EtM)
 */
vector<uint8_t> tv4_ae_sender(const vector<uint8_t>& plaintext, 
                              const vector<uint8_t>& enc_key, 
                              const vector<uint8_t>& hmac_key) {
    
    // --- BƯỚC 1: MÃ HÓA (AES-256-CTR) ---
    vector<uint8_t> iv(16);
    RAND_bytes(iv.data(), iv.size()); 

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, enc_key.data(), iv.data());

    vector<uint8_t> ciphertext(plaintext.size());
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    // Ghép IV + Ciphertext
    vector<uint8_t> full_ciphertext = iv;
    full_ciphertext.insert(full_ciphertext.end(), ciphertext.begin(), ciphertext.end());

    // --- BƯỚC 2: XÁC THỰC (HMAC-SHA256) trên bản mã ---
    unsigned int mac_len = 32; 
    vector<uint8_t> mac_tag(mac_len);
    
    HMAC(EVP_sha256(), hmac_key.data(), hmac_key.size(), 
         full_ciphertext.data(), full_ciphertext.size(), 
         mac_tag.data(), &mac_len);

    // --- BƯỚC 3: ĐÓNG GÓI [IV + Ciphertext + MAC Tag] ---
    vector<uint8_t> final_packet = full_ciphertext;
    final_packet.insert(final_packet.end(), mac_tag.begin(), mac_tag.end());

    return final_packet;
}

int main() {
    // Khóa giả định (32 bytes)
    vector<uint8_t> enc_key(32, 0x41); 
    vector<uint8_t> hmac_key(32, 0x42);
    string message = "Thong diep da duoc rut gon code!";
    vector<uint8_t> plaintext(message.begin(), message.end());

    vector<uint8_t> packet = tv4_ae_sender(plaintext, enc_key, hmac_key);

    cout << "--- AE Sender Result ---" << endl;
    print_hex("Final Packet", packet);
    cout << "Packet size: " << packet.size() << " bytes" << endl;

    return 0;
}