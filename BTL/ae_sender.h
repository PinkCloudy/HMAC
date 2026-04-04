/*
 * ============================================================
 *  TV4 – NGƯỜI GỬI: Encrypt-then-MAC
 *  File: ae_sender.h
 * ============================================================
 */

#pragma once
#include "Sha256.h"          // << Sha256.h (chữ S hoa)
#include "hmac_core.h"       // << hmac_core.h (tên mới)
#include <vector>
#include <array>
#include <iostream>
#include <ctime>
#include <cstring>

constexpr int IV_SIZE      = 16;
constexpr int MAC_TAG_SIZE = 32;

// ─── SINH KEYSTREAM (thay AES, dùng SHA-256 cho đơn giản) ─
static std::vector<uint8_t> make_keystream(
    const std::vector<uint8_t>& key,
    const uint8_t iv[IV_SIZE],
    size_t length)
{
    std::vector<uint8_t> ks;
    uint32_t ctr = 0;
    while (ks.size() < length) {
        std::vector<uint8_t> blk;
        blk.insert(blk.end(), key.begin(), key.end());
        blk.insert(blk.end(), iv, iv + IV_SIZE);
        blk.push_back((ctr >> 24) & 0xFF);
        blk.push_back((ctr >> 16) & 0xFF);
        blk.push_back((ctr >>  8) & 0xFF);
        blk.push_back((ctr      ) & 0xFF);
        auto h = sha256(blk);
        ks.insert(ks.end(), h.begin(), h.end());
        ctr++;
    }
    ks.resize(length);
    return ks;
}

// ─── MÃ HÓA XOR STREAM ───────────────────────────────────
static std::vector<uint8_t> stream_encrypt(
    const std::vector<uint8_t>& key,
    const uint8_t iv[IV_SIZE],
    const std::vector<uint8_t>& pt)
{
    auto ks = make_keystream(key, iv, pt.size());
    std::vector<uint8_t> ct(pt.size());
    for (size_t i = 0; i < pt.size(); i++)
        ct[i] = pt[i] ^ ks[i];
    return ct;
}

// ─── SINH IV ─────────────────────────────────────────────
static void generate_iv(uint8_t iv[IV_SIZE]) {
    static uint64_t ctr = 0;
    for (int i = 0; i < IV_SIZE; i++)
        iv[i] = (uint8_t)((ctr * 6364136223846793005ULL + i * 2891336453ULL
                           + (uint64_t)time(nullptr)) >> (i % 8));
    ctr++;
}

// ─── ENCRYPT-THEN-MAC ────────────────────────────────────
inline std::vector<uint8_t> encrypt_then_mac(
    const std::vector<uint8_t>& key_enc,
    const std::vector<uint8_t>& key_mac,
    const std::vector<uint8_t>& plaintext,
    bool verbose = false)
{
    uint8_t iv[IV_SIZE];
    generate_iv(iv);

    auto ciphertext = stream_encrypt(key_enc, iv, plaintext);

    std::vector<uint8_t> auth;
    auth.insert(auth.end(), iv, iv + IV_SIZE);
    auth.insert(auth.end(), ciphertext.begin(), ciphertext.end());

    std::cout << "    [TV4] Tinh HMAC tren (IV || Ciphertext):\n";
    auto tag = hmac_sha256(key_mac, auth, verbose);

    std::vector<uint8_t> packet;
    packet.insert(packet.end(), iv, iv + IV_SIZE);
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    packet.insert(packet.end(), tag.begin(), tag.end());

    if (verbose) {
        std::cout << "    [TV4] IV        : " << bytes_to_hex(iv, IV_SIZE) << "\n";
        std::cout << "    [TV4] Ciphertext: " << bytes_to_hex(ciphertext) << "\n";
        std::cout << "    [TV4] MAC Tag   : " << bytes_to_hex(tag) << "\n";
    }
    return packet;
}

// ─── TÁCH PACKET ─────────────────────────────────────────
struct ParsedPacket {
    uint8_t              iv[IV_SIZE];
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t,32> mac_tag;
    bool valid = false;
};

static ParsedPacket parse_packet(const std::vector<uint8_t>& pkt) {
    ParsedPacket p;
    if (pkt.size() < (size_t)(IV_SIZE + MAC_TAG_SIZE + 1)) return p;
    memcpy(p.iv, pkt.data(), IV_SIZE);
    p.ciphertext = std::vector<uint8_t>(pkt.begin()+IV_SIZE, pkt.end()-MAC_TAG_SIZE);
    memcpy(p.mac_tag.data(), pkt.data()+pkt.size()-MAC_TAG_SIZE, MAC_TAG_SIZE);
    p.valid = true;
    return p;
}