/*
 * ============================================================
 *  SHA-256 – Tự cài đặt từ đầu, từng bước có giải thích
 *  File: sha256.cpp
 * ============================================================
 *  SHA-256 nhận đầu vào bất kỳ, cho ra 32 byte (256 bit).
 *  Được dùng làm hàm băm H bên trong HMAC.
 * ============================================================
 */

#include "Sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>

// ─── HẰNG SỐ SHA-256 ───────────────────────────────────────
// 8 giá trị khởi tạo: lấy phần thập phân của căn bậc 2
// của 8 số nguyên tố đầu tiên (2, 3, 5, 7, 11, 13, 17, 19)
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// 64 hằng số vòng: lấy phần thập phân của căn bậc 3
// của 64 số nguyên tố đầu tiên
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// ─── CÁC PHÉP TOÁN BIT SHA-256 ────────────────────────────
// Xoay phải n bit (Rotate Right)
static inline uint32_t ROTR(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// Hàm sigma dùng trong lịch trình thông điệp
static inline uint32_t sigma0(uint32_t x) { return ROTR(x,7)  ^ ROTR(x,18) ^ (x>>3);  }
static inline uint32_t sigma1(uint32_t x) { return ROTR(x,17) ^ ROTR(x,19) ^ (x>>10); }

// Hàm Sigma dùng trong vòng nén
static inline uint32_t Sigma0(uint32_t x) { return ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22); }
static inline uint32_t Sigma1(uint32_t x) { return ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25); }

// Hàm lựa chọn: nếu bit e=1 chọn f, ngược lại chọn g
static inline uint32_t Ch(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }

// Hàm đa số: bit nào xuất hiện nhiều hơn trong (a,b,c)
static inline uint32_t Maj(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }

// ─── HÀM CHÍNH: sha256 ────────────────────────────────────
std::array<uint8_t,32> sha256(const std::vector<uint8_t>& data) {

    // ── BƯỚC 1: ĐỆM (Padding) ────────────────────────────
    // SHA-256 xử lý từng block 512 bit (64 byte).
    // Nếu message không đủ, phải đệm thêm:
    //   - 1 bit '1' (= byte 0x80)
    //   - Nhiều bit '0'
    //   - 64 bit cuối = độ dài message gốc tính bằng bit

    uint64_t bit_len = (uint64_t)data.size() * 8;

    std::vector<uint8_t> msg(data);
    msg.push_back(0x80);  // thêm bit 1 (và 7 bit 0)

    // đệm 0x00 cho đến khi message_len ≡ 56 (mod 64)
    while (msg.size() % 64 != 56)
        msg.push_back(0x00);

    // thêm 8 byte = độ dài gốc (big-endian)
    for (int i = 7; i >= 0; i--)
        msg.push_back((uint8_t)(bit_len >> (i * 8)));

    // ── BƯỚC 2: KHỞI TẠO TRẠNG THÁI ─────────────────────
    uint32_t h[8];
    memcpy(h, H0, sizeof(H0));

    // ── BƯỚC 3: XỬ LÝ TỪNG BLOCK 64 BYTE ────────────────
    for (size_t blk = 0; blk < msg.size(); blk += 64) {

        // Lịch trình thông điệp W[0..63]
        uint32_t W[64];

        // W[0..15]: nạp trực tiếp từ block (big-endian)
        for (int i = 0; i < 16; i++) {
            W[i] = ((uint32_t)msg[blk+4*i  ] << 24)
                 | ((uint32_t)msg[blk+4*i+1] << 16)
                 | ((uint32_t)msg[blk+4*i+2] <<  8)
                 | ((uint32_t)msg[blk+4*i+3]      );
        }

        // W[16..63]: mở rộng bằng phép sigma
        for (int i = 16; i < 64; i++)
            W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];

        // Sao lưu trạng thái hiện tại
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3];
        uint32_t e=h[4], f=h[5], g=h[6], hh=h[7];

        // 64 vòng nén
        for (int i = 0; i < 64; i++) {
            uint32_t T1 = hh + Sigma1(e) + Ch(e,f,g) + K[i] + W[i];
            uint32_t T2 = Sigma0(a) + Maj(a,b,c);
            hh = g;  g = f;  f = e;  e = d + T1;
            d  = c;  c = b;  b = a;  a = T1 + T2;
        }

        // Cộng vào trạng thái tích lũy
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    // ── BƯỚC 4: GHÉP KẾT QUẢ (32 byte, big-endian) ───────
    std::array<uint8_t,32> digest;
    for (int i = 0; i < 8; i++) {
        digest[4*i  ] = (h[i] >> 24) & 0xFF;
        digest[4*i+1] = (h[i] >> 16) & 0xFF;
        digest[4*i+2] = (h[i] >>  8) & 0xFF;
        digest[4*i+3] = (h[i]      ) & 0xFF;
    }
    return digest;
}

// ─── TIỆN ÍCH: in hex ─────────────────────────────────────
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
        ss << std::setw(2) << (int)data[i];
    return ss.str();
}

std::string bytes_to_hex(const std::array<uint8_t,32>& a) {
    return bytes_to_hex(a.data(), 32);
}

std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    return bytes_to_hex(v.data(), v.size());
}