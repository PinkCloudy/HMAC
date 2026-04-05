# HMA# 🛡️ Đồ Án An Toàn Thông Tin: Authenticated Encryption (HMAC & AES-256)

**Thực hiện bởi:** Nhóm 6  
**Môn học:** An Toàn Thông Tin  

## 📖 Giới thiệu đồ án
Dự án này mô phỏng một hệ thống **Authenticated Encryption (Mã hóa có xác thực)** sử dụng mô hình an toàn nhất: **Encrypt-then-MAC**. 
Điểm đặc biệt của đồ án là toàn bộ các thuật toán lõi bao gồm **SHA-256, HMAC, và AES-256-CBC** đều được **tự lập trình 100% bằng C++ thuần**, không sử dụng bất kỳ thư viện mật mã bên ngoài nào (như OpenSSL).

## ✨ Các tính năng nổi bật
1. **Demo Lỗ hổng Hash Length Extension Attack:** Trình diễn trực quan lý do tại sao `MAC = Hash(Key || Message)` là không an toàn.
2. **HMAC Core:** Triển khai chính xác phương trình toán học của HMAC. Vượt qua bộ Test Vector chuẩn quốc tế **RFC 4231**.
3. **AES-256-CBC:** Tự lập trình hộp đen mã hóa AES-256, hỗ trợ sinh IV ngẫu nhiên an toàn và gỡ/đệm (padding) PKCS7 chuẩn xác.
4. **Chống Timing Attack:** Sử dụng thuật toán so sánh chuỗi hằng số thời gian (`Constant-time Compare`) khi xác thực chữ ký MAC.
5. **Mô phỏng Hệ thống AE:** Giả lập 2 kịch bản mạng:
   - Dữ liệu truyền đi an toàn và được giải mã thành công.
   - Dữ liệu bị Hacker can thiệp (đảo bit) trên đường truyền và bị hệ thống phát hiện, từ chối giải mã.

## 📂 Cấu trúc mã nguồn
- `main.cpp` : File chạy chính, chứa các kịch bản demo (Test Vector, Hacker Attack).
- `basic_mac.h/cpp` : Hàm băm đơn giản chứa lỗ hổng (dùng để so sánh) & Khóa dùng chung.
- `sha256.h/cpp` : Thuật toán băm SHA-256 (Tự code từ A-Z).
- `hmac.h/cpp` : Thuật toán xác thực HMAC.
- `aes_crypto.h/cpp` : Thuật toán mã hóa AES-256 chế độ CBC.
- `ae_system.h/cpp` : Hệ thống đóng gói và bóc tách gói tin (Encrypt-then-MAC).
- `utils.h/cpp` : Các hàm tiện ích in chuỗi Hex và so sánh an toàn.

## 🚀 Hướng dẫn Cài đặt & Sử dụng

### 1. Yêu cầu hệ thống
- Trình biên dịch C++ (GCC/MinGW, Clang, hoặc MSVC).
- Hỗ trợ chuẩn C++11 trở lên.

### 2. Biên dịch (Compile)
Mở Terminal/Command Prompt tại thư mục chứa source code và chạy lệnh sau để gom tất cả các file `.cpp` và biên dịch:

```bash
g++ *.cpp -o do_an_hmacC
