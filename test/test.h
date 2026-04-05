#ifndef TV5_RECEIVER_H
#define TV5_RECEIVER_H
#include <string>
#include <vector>
/**
 * Khai bao cac ham cua Thanh vien 5
 */
bool safe_compare(const std::string& a, const std::string& b);
bool verify_and_decrypt(const std::string& key,
                        const std::string& iv,
                        const std::string& ciphertext,
                        const std::string& received_tag);

#endif
}
