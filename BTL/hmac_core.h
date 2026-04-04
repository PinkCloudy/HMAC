/*
 * ============================================================
 *  TV3 – LÕI HMAC
 *  File: hmac_core.h
 * ============================================================
 */

#pragma once
#include "Sha256.h"           // << Sha256.h (chữ S hoa)
#include "key_processing.h"   // << key_processing.h (tên mới)
#include "basic_mac.h"        // << basic_mac.h (tên mới, để dùng str_to_bytes)
#include <vector>
#include <array>
#include <string>
#include <iostream>

// ─── HMAC-SHA256 (tự cài, không dùng thư viện) ────────────
inline std::array<uint8_t,32> hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message,
    bool verbose = false)
{
    // Bước 1: tiền xử lý khóa
    auto k_prime   = process_key(key);
    auto inner_key = make_inner_key(k_prime);
    auto outer_key = make_outer_key(k_prime);

    // Bước 2: Inner Hash = SHA256( inner_key || message )
    std::vector<uint8_t> inner_input;
    inner_input.insert(inner_input.end(), inner_key.begin(), inner_key.end());
    inner_input.insert(inner_input.end(), message.begin(),   message.end());
    auto inner_hash = sha256(inner_input);

    // ★ BẮT BUỘC IN INNER HASH
    std::cout << "    [TV3] Inner Hash: " << bytes_to_hex(inner_hash) << "\n";

    if (verbose) {
        std::cout << "    [TV3] inner_key: " << bytes_to_hex(inner_key.data(),16) << "...\n";
        std::cout << "    [TV3] outer_key: " << bytes_to_hex(outer_key.data(),16) << "...\n";
    }

    // Bước 3: Outer Hash = SHA256( outer_key || inner_hash )
    std::vector<uint8_t> outer_input;
    outer_input.insert(outer_input.end(), outer_key.begin(), outer_key.end());
    outer_input.insert(outer_input.end(), inner_hash.begin(), inner_hash.end());
    return sha256(outer_input);
}

// ─── RFC 4231 TEST VECTORS ────────────────────────────────
inline bool run_rfc_tests() {
    struct TC { const char* name; std::vector<uint8_t> key, msg; const char* exp; };

    std::vector<TC> tests = {
        { "RFC 4231 TC1",
          std::vector<uint8_t>(20, 0x0b),
          {'H','i',' ','T','h','e','r','e'},
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
        { "RFC 4231 TC2",
          {'J','e','f','e'},
          {'w','h','a','t',' ','d','o',' ','y','a',' ','w','a','n','t',
           ' ','f','o','r',' ','n','o','t','h','i','n','g','?'},
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
        { "RFC 4231 TC3 (key>64B)",
          std::vector<uint8_t>(131, 0xaa),
          str_to_bytes("Test Using Larger Than Block-Size Key - Hash Key First"),
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" }
    };

    std::cout << "==============================================\n";
    std::cout << "  [TV3] KIEM TRA RFC TEST VECTORS\n";
    std::cout << "==============================================\n\n";

    bool all_pass = true;
    for (auto& t : tests) {
        std::cout << "  > " << t.name << "\n";
        auto tag = hmac_sha256(t.key, t.msg, false);
        std::string got = bytes_to_hex(tag);
        bool ok = (got == std::string(t.exp));
        if (!ok) all_pass = false;
        std::cout << "    Expected: " << t.exp << "\n";
        std::cout << "    Got     : " << got  << "\n";
        std::cout << "    Status  : " << (ok ? "PASS" : "FAIL") << "\n\n";
    }
    std::cout << "  Ket qua: " << (all_pass ? "TAT CA PASS" : "CO CASE FAIL") << "\n\n";
    return all_pass;
}