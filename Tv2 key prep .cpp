/*
 * tv2_key_prep.cpp
 * Thành viên 2 – Cấu trúc toán học & Tiền xử lý khóa HMAC
 * ─────────────────────────────────────────────────────────
 * Biên dịch:
 *   g++ -std=c++17 tv2_key_prep.cpp -lssl -lcrypto -o tv2_key_prep
 * Chạy:
 *   ./tv2_key_prep
 * ─────────────────────────────────────────────────────────
 * Nhiệm vụ:
 *   1. Chuẩn hóa khóa K  →  K'
 *        - Băm K nếu len(K) > block_size  (RFC 2104)
 *        - Đệm 0x00 bên phải đến đúng block_size
 *   2. Tính Inner Key  =  K' ⊕ ipad  (0x36 × block_size)
 *   3. Tính Outer Key  =  K' ⊕ opad  (0x5C × block_size)
 *   4. In tất cả giá trị dưới dạng Hex
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <stdexcept>
#include <openssl/evp.h>   // EVP_MD_CTX, EVP_sha256, …
#include <openssl/sha.h>


//   HẰNG SỐ & KIỂU DỮ LIỆU

static constexpr uint8_t IPAD_BYTE = 0x36;
static constexpr uint8_t OPAD_BYTE = 0x5C;

using Bytes = std::vector<uint8_t>;

// Thông số cho từng hàm băm 
struct HashParams {
    std::string  name;
    size_t       block_size;   // bytes
    size_t       output_size;  // bytes
    const EVP_MD* (*evp_fn)(); // con trỏ hàm trả về EVP_MD*
};

static const HashParams HASH_TABLE[] = {
    { "SHA-256", 64,  32, EVP_sha256 },
    { "SHA-512", 128, 64, EVP_sha512 },
    { "SHA-1",   64,  20, EVP_sha1   },
    { "MD5",     64,  16, EVP_md5    },
};


//   HÀM TIỆN ÍCH


//Chuyển std::string sang Bytes 
Bytes to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

// In dữ liệu dạng hex, bytes_per_line byte mỗi dòng 
void hex_dump(const std::string& label, const Bytes& data,
              size_t bytes_per_line = 16)
{
    std::string sep(60, '-');
    std::cout << "\n" << sep << "\n";
    std::cout << "  " << label << "  [" << data.size() << " bytes]\n";
    std::cout << sep << "\n";

    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0 && i % bytes_per_line == 0)
            std::cout << "\n";
        std::cout << "  " << std::hex << std::setw(2)
                  << std::setfill('0') << static_cast<int>(data[i]);
    }
    if (!data.empty()) std::cout << "\n";
    std::cout << std::dec; // reset về decimal
}


//   HÀM BĂNG (wrapper dùng OpenSSL EVP)

Bytes hash_data(const Bytes& data, const EVP_MD* md) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new() thất bại");

    unsigned int len = 0;
    Bytes digest(EVP_MD_size(md));

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Hàm băm thất bại");
    }
    EVP_MD_CTX_free(ctx);
    digest.resize(len);
    return digest;
}


//   HÀM 1: Chuẩn hóa khóa K → K'  (RFC 2104)

/*
 * Quy tắc:
 *   - Nếu len(K) > block_size  →  K' = H(K)   (băm để thu gọn)
 *   - Nếu len(K) <= block_size →  K' = K
 *   - Đệm 0x00 bên phải cho đến len(K') = block_size
 */
Bytes prepare_key(const Bytes& key, const HashParams& params) {
    Bytes k = key;

    if (k.size() > params.block_size) {
        std::cout << "\n  [!] Khóa dài hơn block_size ("
                  << k.size() << " > " << params.block_size << ")\n";
        std::cout << "  [!] Tiến hành băm khóa K trước...\n";
        k = hash_data(k, params.evp_fn());
        std::cout << "  [!] Sau khi băm: len(K) = " << k.size() << " bytes\n";
    }

    // Đệm 0x00 bên phải
    k.resize(params.block_size, 0x00);
    return k;
}


//   HÀM 2: Inner Key  =  K' ⊕ ipad

Bytes compute_inner_key(const Bytes& key_prime, size_t block_size) {
    Bytes inner(block_size);
    for (size_t i = 0; i < block_size; ++i)
        inner[i] = key_prime[i] ^ IPAD_BYTE;
    return inner;
}


//   HÀM 3: Outer Key  =  K' ⊕ opad

Bytes compute_outer_key(const Bytes& key_prime, size_t block_size) {
    Bytes outer(block_size);
    for (size_t i = 0; i < block_size; ++i)
        outer[i] = key_prime[i] ^ OPAD_BYTE;
    return outer;
}


//   HÀM TỔNG HỢP: chạy toàn bộ và in kết quả

void key_prep_demo(const std::string& key_str,
                   const HashParams&  params)
{
    std::string sep(60, '=');
    std::cout << "\n" << sep << "\n";
    std::cout << "  HMAC KEY PREPARATION  –  Hàm băm: " << params.name << "\n";
    std::cout << sep << "\n";
    std::cout << "  Block size  : " << params.block_size
              << " bytes (" << params.block_size * 8 << " bits)\n";
    std::cout << "  Output size : " << params.output_size
              << " bytes (" << params.output_size * 8 << " bits)\n";
    std::cout << "  ipad        : 0x"
              << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(IPAD_BYTE) << std::dec
              << "  (lặp " << params.block_size << " lần)\n";
    std::cout << "  opad        : 0x"
              << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(OPAD_BYTE) << std::dec
              << "  (lặp " << params.block_size << " lần)\n";

    Bytes key = to_bytes(key_str);

    //  Khóa gốc K 
    hex_dump("K (khóa gốc)", key);

    // Bước 1: K → K' 
    std::cout << "\n>>> BƯỚC 1: Chuẩn hóa K → K'\n";
    Bytes key_prime = prepare_key(key, params);
    hex_dump("K' (sau khi đệm đến block_size)", key_prime);

    // Bước 2: Inner Key
    std::cout << "\n>>> BƯỚC 2: Inner Key  =  K' ⊕ ipad (0x"
              << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(IPAD_BYTE) << std::dec << ")\n";
    Bytes inner_key = compute_inner_key(key_prime, params.block_size);
    hex_dump("Inner Key  (K' ⊕ ipad)", inner_key);

    //  Bước 3: Outer Key 
    std::cout << "\n>>> BƯỚC 3: Outer Key  =  K' ⊕ opad (0x"
              << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(OPAD_BYTE) << std::dec << ")\n";
    Bytes outer_key = compute_outer_key(key_prime, params.block_size);
    hex_dump("Outer Key  (K' ⊕ opad)", outer_key);

    std::cout << "\n" << sep << "\n";
    std::cout << "  Hoàn tất tiền xử lý khóa.\n";
    std::cout << "  Inner Key và Outer Key sẵn sàng cho bước tính HMAC.\n";
    std::cout << sep << "\n";
}


//   MAIN – CHẠY 4 TEST CASE THEO BÁO CÁO

int main() {
    const HashParams& sha256 = HASH_TABLE[0]; // SHA-256

    auto banner = [](const std::string& msg) {
        std::string line(60, 0x23); // '#'
        std::cout << "\n" << line << "\n  " << msg << "\n" << line << "\n";
    };

    //  Test 1 
    banner("TEST CASE 1 - Khoa ngan: \"key\"  |  SHA-256");
    key_prep_demo("key", sha256);

    //  Test 2 
    banner("TEST CASE 2 - Khoa rong: \"\"  |  SHA-256");
    key_prep_demo("", sha256);

    // Test 3 – khóa 100 bytes > block_size=64 
    banner("TEST CASE 3 - Khoa qua dai (100 bytes)  |  SHA-256");
    key_prep_demo(std::string(100, 'A'), sha256);

    //  Test 4 
    banner("TEST CASE 4 - Khoa \"secret\"  |  SHA-256");
    key_prep_demo("secret", sha256);

    return 0;
}
