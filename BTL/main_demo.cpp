#include <iostream>
#include <string>
#include <vector>
#include <cstring>

// ── INCLUDE ĐÚNG TÊN FILE THỰC TẾ ────────────────────────
#include "Sha256.h"           // sha256()
#include "basic_mac.h"        // bad_mac(), SHARED_KEY_MAC, SHARED_KEY_ENC
#include "key_processing.h"   // process_key(), make_inner_key(), make_outer_key()
#include "hmac_core.h"        // hmac_sha256(), run_rfc_tests()
#include "ae_sender.h"        // encrypt_then_mac(), parse_packet()
#include "ae_receiver.h"      // verify_and_decrypt()

// ─── TIỆN ÍCH ─────────────────────────────────────────────
static void section(const std::string& title) {
    std::cout << "\n============================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "============================================\n";
}

static std::vector<uint8_t> key_mac_vec() {
    return std::vector<uint8_t>(SHARED_KEY_MAC, SHARED_KEY_MAC + 16);
}
static std::vector<uint8_t> key_enc_vec() {
    return std::vector<uint8_t>(SHARED_KEY_ENC, SHARED_KEY_ENC + 16);
}

// ─── TEST CASE 1: RFC TEST VECTORS ────────────────────────
bool tc1_rfc_vectors() {
    section("TEST CASE 1: RFC 4231 TEST VECTORS");
    std::cout << "\n  Bo so lieu chuan quoc te – neu PASS -> HMAC dung.\n\n";
    return run_rfc_tests();
}

// ─── TEST CASE 2: GIẢ LẬP TAMPER ATTACK ──────────────────
bool tc2_tamper_attack() {
    section("TEST CASE 2: GIA LAP TAMPER ATTACK");
    std::cout << "\n"
              << "  Kich ban:\n"
              << "    Alice gui 'Transfer $100 to Bob'\n"
              << "    Eve sua 1 byte trong Ciphertext\n"
              << "    He thong phai phat hien va tu choi.\n\n";

    auto key_enc = key_enc_vec();
    auto key_mac = key_mac_vec();

    // Alice gửi
    auto plaintext = str_to_bytes("Transfer $100 to Bob");
    auto packet    = encrypt_then_mac(key_enc, key_mac, plaintext);
    std::cout << "  Alice gui: 'Transfer $100 to Bob'\n";
    std::cout << "  Packet (" << packet.size() << " bytes): "
              << bytes_to_hex(packet.data(), 16) << "...\n\n";

    // Eve sửa 1 byte ở vị trí 20
    auto tampered = packet;
    uint8_t orig  = tampered[20];
    tampered[20] ^= 0xFF;
    std::cout << "  Eve sua byte[20]: 0x" << std::hex << (int)orig
              << " -> 0x" << (int)tampered[20] << std::dec << "\n\n";

    // Bob nhận gói giả
    std::cout << "  Bob nhan goi gia mao:\n";
    auto result = verify_and_decrypt(key_enc, key_mac, tampered);

    bool detected = result.empty();
    std::cout << "\n  " << (detected ? "PASS: He thong phat hien tamper!"
                                     : "FAIL: Giai ma duoc -> loi!") << "\n";
    return detected;
}

// ─── TEST CASE 3: BAD MAC vs HMAC ─────────────────────────
void tc3_bad_vs_hmac() {
    section("TEST CASE 3: BAD_MAC vs HMAC-SHA256");

    auto key = key_mac_vec();
    auto msg = str_to_bytes("Pay Alice $1000");

    auto bad  = bad_mac(key, msg);
    auto good = hmac_sha256(key, msg);

    std::cout << "\n  Message : 'Pay Alice $1000'\n";
    std::cout << "  bad_mac : " << bytes_to_hex(bad)  << "\n";
    std::cout << "  hmac    : " << bytes_to_hex(good) << "\n\n";
    std::cout << "  bad_mac -> Length Extension Attack  NGUY HIEM\n";
    std::cout << "  HMAC    -> 2 lop bam long nhau      AN TOAN\n";

    demo_length_extension_attack();
}

// ─── TEST CASE 4: END-TO-END ──────────────────────────────
bool tc4_end_to_end() {
    section("TEST CASE 4: END-TO-END (Alice -> Bob)");

    auto key_enc = key_enc_vec();
    auto key_mac = key_mac_vec();

    std::vector<std::string> messages = {
        "Hello Bob! Secure message.",
        "Transfer $9999 to Alice.",
        std::string(80, 'A')
    };

    bool all_ok = true;
    int idx = 1;
    for (auto& m : messages) {
        auto pt  = str_to_bytes(m);
        std::cout << "\n  [" << idx++ << "] Gui: '"
                  << m.substr(0, 35) << (m.size() > 35 ? "..." : "") << "'\n";

        auto packet = encrypt_then_mac(key_enc, key_mac, pt);
        auto result = verify_and_decrypt(key_enc, key_mac, packet);

        bool ok = (result == pt);
        if (!ok) all_ok = false;
        std::cout << "       " << (ok ? "PASS: Khop hoan toan." : "FAIL!")
                  << " (" << m.size() << " bytes)\n";
    }

    std::cout << "\n  Ket qua: " << (all_ok ? "TAT CA PASS" : "CO LOI") << "\n";
    return all_ok;
}

// ─── MAIN ─────────────────────────────────────────────────
int main() {
    std::cout << "\n";
    std::cout << "+------------------------------------------+\n";
    std::cout << "|  HMAC PROJECT – C++ Demo                |\n";
    std::cout << "|  Mon: ET3311 Introduction to CyberSec   |\n";
    std::cout << "+------------------------------------------+\n";

    bool r1 = tc1_rfc_vectors();
    bool r2 = tc2_tamper_attack();
         tc3_bad_vs_hmac();
    bool r4 = tc4_end_to_end();

    section("TONG KET");
    std::cout << "\n";
    std::cout << "  " << (r1 ? "[PASS]" : "[FAIL]") << "  TC1: RFC Test Vectors\n";
    std::cout << "  " << (r2 ? "[PASS]" : "[FAIL]") << "  TC2: Tamper Attack\n";
    std::cout << "  [INFO]  TC3: bad_mac vs HMAC\n";
    std::cout << "  " << (r4 ? "[PASS]" : "[FAIL]") << "  TC4: End-to-End\n";
    std::cout << "\n  " << (r1 && r2 && r4 ? "TAT CA PASS!" : "CO CASE FAIL!") << "\n\n";

    return (r1 && r2 && r4) ? 0 : 1;
}