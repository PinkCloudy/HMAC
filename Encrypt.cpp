#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
using namespace std;

struct Packet {
    vector<unsigned char> ciphertext_with_iv;
    vector<unsigned char> mac_tag;
};

class EncryptThenMacSender {
private:
    vector<unsigned char> enc_key;
    vector<unsigned char> mac_key;

public:
    EncryptThenMacSender(const vector<unsigned char>& enc_k, const vector<unsigned char>& mac_k)
        : enc_key(enc_k), mac_key(mac_k) {}
    vector<unsigned char> aes_encrypt_blackbox(const vector<unsigned char>& plaintext) {
        // 1. Tạo IV ngẫu nhiên (16 bytes cho AES)
        vector<unsigned char> iv(16);
        RAND_bytes(iv.data(), 16); 
        // 2. Setup thuật toán mã hóa
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key.data(), iv.data());
        vector<unsigned char> ciphertext(plaintext.size() + 16);
        int len = 0;
        int ciphertext_len = 0;

        // 3. Thực hiện mã hóa (Update và Final)
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len); 
        EVP_CIPHER_CTX_free(ctx);

        // 4. Ghép IV vào đầu Bản mã
        vector<unsigned char> result;
        result.reserve(iv.size() + ciphertext.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());

        return result;
    }
    vector<unsigned char> hmac_tv3(const vector<unsigned char>& data) {
        unsigned char mac_out[EVP_MAX_MD_SIZE];
        unsigned int mac_len = 0;

        HMAC(EVP_sha256(), mac_key.data(), mac_key.size(), data.data(), data.size(), mac_out, &mac_len);

        return vector<unsigned char>(mac_out, mac_out + mac_len);
    }

        // Hàm chính thực hiện mô hình ENCRYPT-THEN-MAC
    Packet generate_packet(const string& message) {
        // Chuyển chuỗi string thành byte array
        vector<unsigned char> plaintext_bytes(message.begin(), message.end());

        // BƯỚC 1: MÃ HÓA (Encrypt)
        vector<unsigned char> ciphertext_with_iv = aes_encrypt_blackbox(plaintext_bytes);

        // BƯỚC 2: TÍNH MAC TRÊN BẢN MÃ (then-MAC)
        // Băm chính cái `ciphertext_with_iv` vừa tạo ra
        vector<unsigned char> mac_tag = hmac_tv3(ciphertext_with_iv);

        // BƯỚC 3: TRẢ VỀ GÓI TIN [Ciphertext + MAC]
        return {ciphertext_with_iv, mac_tag};
    }
};

// HÀM PHỤ TRỢ IN RA MÀN HÌNH CHUỖI HEX
void print_hex(const string& label, const vector<unsigned char>& data) {
    cout << label;
    for (unsigned char c : data) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << dec << endl; // Reset dòng cout về hệ thập phân
}
int main() {
    vector<unsigned char> aes_key(32); // Khóa AES-256
    vector<unsigned char> mac_key(32); // Khóa HMAC
    RAND_bytes(aes_key.data(), 32);
    RAND_bytes(mac_key.data(), 32);
    EncryptThenMacSender sender(aes_key, mac_key);
    string secret_message = "Xin chao, day la do an cua Nhom chung ta!";
    cout << "[-] Ban ro ban dau: '" << secret_message << "'\n\n";
    Packet packet = sender.generate_packet(secret_message);
    cout << "[+] Da ap dung mo hinh Encrypt-then-MAC:\n";
    print_hex(" -> Ciphertext (kem IV): ", packet.ciphertext_with_iv);
    print_hex(" -> MAC Tag (SHA-256)  : ", packet.mac_tag);
    cout << "\n[!] Goi tin truyen di tren mang se ghep 2 chuoi nay lai voi nhau.\n";

    return 0;
}