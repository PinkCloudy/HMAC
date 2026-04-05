#include "utils.h"
#include <iostream>
#include <iomanip>

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label;
    // Cấu hình luồng cout để in ra định dạng Hex, độ rộng 2 ký tự, lấp đầy bằng '0'
    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    std::cout << std::dec << "\n"; // Trả luồng cout về hệ thập phân bình thường
}

bool constantTimeCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    // Nếu độ dài đã khác nhau thì chắc chắn sai
    if (a.size() != b.size()) {
        return false;
    }

    uint8_t result = 0;
    
    // Thuật toán Constant-time: 
    // Duyệt qua TẤT CẢ các byte dù có phát hiện lỗi sớm hay không.
    // Dùng phép toán XOR (^), nếu 2 byte giống nhau thì XOR = 0.
    // Dùng phép OR (|) để tích lũy lỗi. Chỉ cần 1 cặp byte lệch nhau, result sẽ khác 0.
    for (size_t i = 0; i < a.size(); ++i) {
        result |= (a[i] ^ b[i]);
    }

    // Nếu result vẫn bằng 0 nghĩa là mọi cặp byte đều giống nhau y hệt
    return result == 0;
}