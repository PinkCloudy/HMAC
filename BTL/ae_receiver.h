/*
 * ============================================================
 *  TV5 – NGƯỜI NHẬN: VERIFY & DECRYPT
 *  File: ae_receiver.h
 * ============================================================
 */

#pragma once
#include "Sha256.h"      // << Sha256.h (chữ S hoa)
#include "hmac_core.h"   // << hmac_core.h (tên mới)
#include "ae_sender.h"   // << ae_sender.h (tên mới)
#include <vector>
#include <array>
#include <iostream>
#include <cstring>

// ─── SO SÁNH HẰNG THỜI GIAN (Chống Timing Attack) ────────
inline bool constant_time_compare(
    const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (a[i] ^ b[i]);   // tích lũy XOR, không dừng sớm
    return (diff == 0);
}

// ─── VERIFY-THEN-DECRYPT ─────────────────────────────────
inline std::vector<uint8_t> verify_and_decrypt(
    const std::vector<uint8_t>& key_enc,
    const std::vector<uint8_t>& key_mac,
    const std::vector<uint8_t>& packet,
    bool verbose = false)
{
    std::cout << "    [TV5] Kich thuoc packet: " << packet.size() << " bytes\n";

    auto p = parse_packet(packet);
    if (!p.valid) {
        std::cout << "    [TV5] FAIL: Packet khong hop le.\n";
        return {};
    }

    // Tính lại HMAC trên (IV || Ciphertext)
    std::vector<uint8_t> auth;
    auth.insert(auth.end(), p.iv, p.iv + IV_SIZE);
    auth.insert(auth.end(), p.ciphertext.begin(), p.ciphertext.end());

    std::cout << "    [TV5] Tinh lai HMAC de verify:\n";
    auto computed = hmac_sha256(key_mac, auth, verbose);

    if (verbose) {
        std::cout << "    [TV5] Tag nhan : " << bytes_to_hex(p.mac_tag) << "\n";
        std::cout << "    [TV5] Tag tinh : " << bytes_to_hex(computed)  << "\n";
    }

    // So sánh hằng thời gian (KHÔNG dùng == hay memcmp)
    bool ok = constant_time_compare(computed.data(), p.mac_tag.data(), MAC_TAG_SIZE);
    if (!ok) {
        std::cout << "    [TV5] FAIL: MAC KHONG KHOP! Tu choi giai ma.\n";
        return {};
    }

    std::cout << "    [TV5] PASS: MAC hop le. Giai ma...\n";
    auto pt = stream_encrypt(key_enc, p.iv, p.ciphertext);
    std::cout << "    [TV5] Giai ma thanh cong!\n";
    return pt;
}