#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <cstdint>
#include <string>

// Hàm in mảng byte ra màn hình dưới dạng Hexadecimal (Cơ số 16)
// label: Tên dán nhãn để dễ nhìn (Ví dụ: "Inner Hash: ")
void printHex(const std::string& label, const std::vector<uint8_t>& data);

// Hàm so sánh 2 mảng byte an toàn (Chống tấn công Timing Attack)
// Trả về true nếu giống nhau hoàn toàn, false nếu có ít nhất 1 bit khác biệt
bool constantTimeCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

#endif // UTILS_H