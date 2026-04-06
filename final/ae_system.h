#ifndef AE_SYSTEM_H
#define AE_SYSTEM_H

#include <vector>
#include <cstdint>

// TV4: Người gửi (Mã hóa và Tạo MAC)
std::vector<uint8_t> createSecurePacket(const std::vector<uint8_t>& plaintext, 
                                        const std::vector<uint8_t>& aesKey, 
                                        const std::vector<uint8_t>& hmacKey);

// TV5: Người nhận (Xác thực MAC và Giải mã)
bool verifyAndExtractPacket(const std::vector<uint8_t>& payload, 
                            const std::vector<uint8_t>& aesKey, 
                            const std::vector<uint8_t>& hmacKey,
                            std::vector<uint8_t>& out_plaintext);

#endif // AE_SYSTEM_H