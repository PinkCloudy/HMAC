#include "basic_mac.h"
#include "sha256.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

using namespace std;

// Khai báo khóa bí mật chung (dùng cho MAC)
const uint8_t SHARED_KEY_MAC[16] = {
    'm','y','s','e','c','r','e','t','k','e','y','1','2','3','4','5'
};

// Khai báo khóa bí mật chung (dùng cho Mã hóa)
const uint8_t SHARED_KEY_ENC[32] = {
    'e','n','c','r','y','p','t','i','o','n','k','e','y','1','2','3',
    '4','5','6','7','8','9','0','a','b','c','d','e','f','g','h','i'
};

// Hàm tính MAC không an toàn (dễ bị tấn công Length Extension)
vector<uint8_t> bad_mac(const vector<uint8_t>& key, const vector<uint8_t>& message) {
    vector<uint8_t> combined;
    
    // Nối key và message lại với nhau (Key || Message)
    combined.insert(combined.end(), key.begin(), key.end());
    combined.insert(combined.end(), message.begin(), message.end());
    
    // Gọi hàm băm SHA256 cho chuỗi vừa nối
    return computeSHA256(combined);   
}

// Hàm in ra màn hình giải thích về lỗi Length Extension Attack
void demo_length_extension_attack() {
    cout << "========================================" << endl;
    cout << "  [TV1] Length Extension Attack" << endl;
    cout << "========================================" << endl;
    cout << endl;
    cout << "  Server ky:  MAC = SHA256(Key || amount=100)" << endl;
    cout << "  Hacker thay (message, tag) nhung KHONG biet Key." << endl;
    cout << endl;
    cout << "  Neu dung Hash(Key||M) lam MAC:" << endl;
    cout << "    -> Hacker co the them &amount=9999 vao cuoi" << endl;
    cout << "    -> va tinh duoc tag moi HOP LE ma KHONG biet Key!" << endl;
    cout << endl;
    cout << "  => KHONG BAO GIO dung Hash(Key||Message) lam MAC!" << endl;
    cout << "  => Phai dung HMAC (2 lop bam long nhau)." << endl;
    cout << endl;
}

// Hàm hỗ trợ: Chuyển chuỗi (string) thành mảng byte
vector<uint8_t> str_to_bytes(const string& s) {
    vector<uint8_t> result;
    // Lặp qua từng ký tự của chuỗi và ép kiểu sang byte
    for (char c : s) {
        result.push_back((uint8_t)c);
    }
    return result;
}

// Hàm hỗ trợ: Chuyển chuỗi Hex (hệ cơ số 16) thành mảng byte
vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> out;
    
    // Cứ 2 ký tự hex thì tạo thành 1 byte
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        // Lấy ra 2 ký tự
        string hex_byte = hex.substr(i, 2);
        
        // Chuyển đổi 2 ký tự đó thành số nguyên hệ 16
        uint8_t byte_val = (uint8_t) stoul(hex_byte, nullptr, 16);
        
        out.push_back(byte_val);
    }
    
    return out;
}
