#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <vector>
#include <cstdint>

// Kích thước Block và IV của AES luôn là 16 bytes (128 bits)
const size_t AES_BLOCK_SIZE = 16;
// Trong bài này dùng AES-256, nên khóa yêu cầu là 32 bytes (256 bits)
const size_t AES_KEY_SIZE = 32;

// Hàm mã hóa AES-256-CBC. Hàm này sẽ tự động sinh IV ngẫu nhiên.
void encryptAES(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, 
                std::vector<uint8_t>& out_iv, std::vector<uint8_t>& out_ciphertext);

// Hàm giải mã AES-256-CBC.
std::vector<uint8_t> decryptAES(const std::vector<uint8_t>& ciphertext, 
                                const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

#endif // AES_CRYPTO_H