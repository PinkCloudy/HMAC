#include <iostream>
#include <vector>
#include <string>

using namespace std;

// Hàm bổ trợ để chuyển 1 byte sang chuỗi Hex 
void printHex(unsigned char b) {
    const char hex_chars[] = "0123456789ABCDEF";
    // Chia byte thành 4 bit cao và 4 bit thấp
    unsigned char high = (b >> 4) & 0x0F;
    unsigned char low = b & 0x0F;
    cout << hex_chars[high] << hex_chars[low] << " ";
}

class RC4 {
private:
    unsigned char S[256];
    int i, j;

public:
    RC4(const string& key) {
        for (int i = 0; i < 256; i++)
            S[i] = (unsigned char)i;

        j = 0;
        int key_len = key.length();
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + (unsigned char)key[i % key_len]) % 256;
            unsigned char temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }
        this->i = 0;
        this->j = 0;
    }

    unsigned char next_byte() {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        unsigned char t = (S[i] + S[j]) % 256;
        return S[t];
    }
};

int main() {
    string key = "2417";
    string message = "cybersecurity";

    RC4 encoder(key);

    cout << "--- RC4 Cipher ---" << endl;
    cout << "Plaintext: " << message << endl;
    cout << "Ciphertext (Hex): ";

    for (int k = 0; k < message.length(); k++) {
        unsigned char c = (unsigned char)message[k];
        unsigned char cipher_byte = c ^ encoder.next_byte();
        
        // Gọi hàm in Hex thủ công
        printHex(cipher_byte);
    }
    
    cout << endl;

    return 0;
}