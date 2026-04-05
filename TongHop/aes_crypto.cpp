#include "aes_crypto.h"
#include <stdexcept>
#include <random>
#include <cstring>

// ======================================================================
// CÁC BẢNG TRA CỨU CHUẨN CỦA AES (S-Box, Inverse S-Box, Rcon)
// ======================================================================
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ======================================================================
// CÁC HÀM TOÁN HỌC CỐT LÕI CỦA AES
// ======================================================================

// Nhân 2 trong trường Galois GF(2^8)
uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

// Nhân 2 số trong trường GF(2^8)
uint8_t Multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (y & 1) result ^= x;
        uint8_t high_bit = x & 0x80;
        x <<= 1;
        if (high_bit) x ^= 0x1b;
        y >>= 1;
    }
    return result;
}

// ======================================================================
// THUẬT TOÁN AES-256 CORE (1 KHỐI 16 BYTES)
// ======================================================================
class AES256 {
private:
    uint8_t RoundKey[240]; // Đủ chứa 60 Words (15 Round Keys * 16 bytes)

    void KeyExpansion(const uint8_t* Key) {
        // Sao chép 32 bytes khóa gốc vào đầu mảng RoundKey
        for (int i = 0; i < 32; ++i) {
            RoundKey[i] = Key[i];
        }

        int bytesGenerated = 32;
        int rconIteration = 1;
        uint8_t temp[4];

        while (bytesGenerated < 240) {
            // Lấy 4 bytes trước đó
            for (int i = 0; i < 4; ++i) temp[i] = RoundKey[bytesGenerated - 4 + i];

            if (bytesGenerated % 32 == 0) {
                // RotWord
                uint8_t k0 = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = k0;
                // SubWord & XOR Rcon
                for (int i = 0; i < 4; ++i) temp[i] = sbox[temp[i]];
                temp[0] ^= Rcon[rconIteration++];
            } else if (bytesGenerated % 32 == 16) {
                // Đặc thù của AES-256: SubWord ở giữa khóa
                for (int i = 0; i < 4; ++i) temp[i] = sbox[temp[i]];
            }

            for (int i = 0; i < 4; ++i) {
                RoundKey[bytesGenerated] = RoundKey[bytesGenerated - 32] ^ temp[i];
                bytesGenerated++;
            }
        }
    }

    void AddRoundKey(uint8_t round, uint8_t* state) {
        for (int i = 0; i < 16; ++i) {
            state[i] ^= RoundKey[(round * 16) + i];
        }
    }

    void SubBytes(uint8_t* state) {
        for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
    }

    void ShiftRows(uint8_t* state) {
        uint8_t temp;
        // Hàng 1: Dịch trái 1
        temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
        // Hàng 2: Dịch trái 2
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        // Hàng 3: Dịch trái 3
        temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
    }

    void MixColumns(uint8_t* state) {
        uint8_t tmp, tm, t;
        for (int i = 0; i < 16; i += 4) {
            t   = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
            tmp = state[i];
            tm  = state[i] ^ state[i+1]; tm = xtime(tm); state[i]   ^= tm ^ t;
            tm  = state[i+1] ^ state[i+2]; tm = xtime(tm); state[i+1] ^= tm ^ t;
            tm  = state[i+2] ^ state[i+3]; tm = xtime(tm); state[i+2] ^= tm ^ t;
            tm  = state[i+3] ^ tmp;      tm = xtime(tm); state[i+3] ^= tm ^ t;
        }
    }

    void InvSubBytes(uint8_t* state) {
        for (int i = 0; i < 16; ++i) state[i] = rsbox[state[i]];
    }

    void InvShiftRows(uint8_t* state) {
        uint8_t temp;
        // Hàng 1: Dịch phải 1
        temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
        // Hàng 2: Dịch phải 2
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        // Hàng 3: Dịch phải 3
        temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
    }

    void InvMixColumns(uint8_t* state) {
        for (int i = 0; i < 16; i += 4) {
            uint8_t a = state[i], b = state[i+1], c = state[i+2], d = state[i+3];
            state[i]   = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
            state[i+1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
            state[i+2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
            state[i+3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
        }
    }

public:
    AES256(const std::vector<uint8_t>& key) {
        KeyExpansion(key.data());
    }

    void EncryptBlock(const uint8_t* in, uint8_t* out) {
        uint8_t state[16];
        memcpy(state, in, 16);

        AddRoundKey(0, state);
        for (uint8_t round = 1; round < 14; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(round, state);
        }
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(14, state);

        memcpy(out, state, 16);
    }

    void DecryptBlock(const uint8_t* in, uint8_t* out) {
        uint8_t state[16];
        memcpy(state, in, 16);

        AddRoundKey(14, state);
        for (uint8_t round = 13; round > 0; --round) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(round, state);
            InvMixColumns(state);
        }
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(0, state);

        memcpy(out, state, 16);
    }
};

// ======================================================================
// CHẾ ĐỘ CBC VÀ PADDING (WRAPPER CHO HÀM CHÍNH)
// ======================================================================

void encryptAES(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, 
                std::vector<uint8_t>& out_iv, std::vector<uint8_t>& out_ciphertext) {
    if (key.size() != AES_KEY_SIZE) {
        throw std::invalid_argument("Loi: Khoa AES-256 phai dai 32 bytes!");
    }

    // 1. Sinh IV ngẫu nhiên an toàn bằng thư viện C++ chuẩn <random>
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    out_iv.resize(AES_BLOCK_SIZE);
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        out_iv[i] = dis(gen);
    }

    // 2. PKCS7 Padding
    std::vector<uint8_t> padded_text = plaintext;
    uint8_t padding_len = AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
    padded_text.insert(padded_text.end(), padding_len, padding_len);

    // 3. Khởi tạo đối tượng AES và chuẩn bị biến CBC
    AES256 aes(key);
    out_ciphertext.resize(padded_text.size());
    uint8_t previous_block[AES_BLOCK_SIZE];
    memcpy(previous_block, out_iv.data(), AES_BLOCK_SIZE); // Block trước đó ban đầu là IV

    // 4. Mã hóa từng khối 16 bytes (CBC Mode: XOR Plaintext với Ciphertext trước đó)
    for (size_t i = 0; i < padded_text.size(); i += AES_BLOCK_SIZE) {
        uint8_t current_block[AES_BLOCK_SIZE];
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            current_block[j] = padded_text[i + j] ^ previous_block[j];
        }
        
        aes.EncryptBlock(current_block, &out_ciphertext[i]);
        memcpy(previous_block, &out_ciphertext[i], AES_BLOCK_SIZE); // Cập nhật cho vòng lặp sau
    }
}

std::vector<uint8_t> decryptAES(const std::vector<uint8_t>& ciphertext, 
                                const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    if (ciphertext.size() % AES_BLOCK_SIZE != 0 || ciphertext.empty()) {
        throw std::invalid_argument("Loi Giai Ma: Ciphertext bi loi do dai!");
    }

    AES256 aes(key);
    std::vector<uint8_t> padded_text(ciphertext.size());
    uint8_t previous_block[AES_BLOCK_SIZE];
    memcpy(previous_block, iv.data(), AES_BLOCK_SIZE);

    // 1. Giải mã từng khối 16 bytes (CBC Mode: XOR Plaintext sinh ra với Ciphertext trước đó)
    for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE) {
        uint8_t decrypted_block[AES_BLOCK_SIZE];
        aes.DecryptBlock(&ciphertext[i], decrypted_block);
        
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            padded_text[i + j] = decrypted_block[j] ^ previous_block[j];
        }
        memcpy(previous_block, &ciphertext[i], AES_BLOCK_SIZE);
    }

    // 2. Kiểm tra và Gỡ Padding (PKCS7 Unpad)
    uint8_t padding_len = padded_text.back();
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE) {
        throw std::runtime_error("Loi Giai Ma: Padding khong hop le (Du lieu bi hong)!");
    }

    // Kiểm tra tính hợp lệ của toàn bộ byte padding
    for (size_t i = padded_text.size() - padding_len; i < padded_text.size(); ++i) {
        if (padded_text[i] != padding_len) {
            throw std::runtime_error("Loi Giai Ma: Padding PKCS7 bi loi!");
        }
    }

    // Xóa byte padding
    padded_text.resize(padded_text.size() - padding_len);
    return padded_text;
}