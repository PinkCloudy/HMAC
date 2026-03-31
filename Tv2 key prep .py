"""
tv2_key_prep.py
Thành viên 2 - Cấu trúc toán học & Tiền xử lý khóa HMAC
--------------------------------------------------------------
Nhiệm vụ:
  1. Chuẩn hóa khóa K  →  K'  (băm nếu quá dài, đệm 0x00 nếu quá ngắn)
  2. Tính Inner Key  =  K' ⊕ ipad  (0x36 lặp block_size lần)
  3. Tính Outer Key  =  K' ⊕ opad  (0x5C lặp block_size lần)
  4. In tất cả kết quả dưới dạng Hex
"""

import hashlib

#Hằng số

IPAD_BYTE = 0x36
OPAD_BYTE = 0x5C

#Bảng thông số cho từng hàm băm được hỗ trợ
HASH_PARAMS = {
    "sha256": {"block_size": 64,  "output_size": 32,  "fn": hashlib.sha256},
    "sha512": {"block_size": 128, "output_size": 64,  "fn": hashlib.sha512},
    "sha1":   {"block_size": 64,  "output_size": 20,  "fn": hashlib.sha1},
    "md5":    {"block_size": 64,  "output_size": 16,  "fn": hashlib.md5},
}

#Hàm tiện ích

def to_bytes(data) -> bytes:
    """Chuyển string hoặc bytes sang bytes."""
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def hex_dump(label: str, data: bytes, bytes_per_line: int = 16) -> None:
    """In dữ liệu dạng hex có nhãn, mỗi dòng bytes_per_line byte."""
    hex_str = data.hex()
#Nhóm thành từng cặp(1 byte)
    pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    lines = [" ".join(pairs[i:i+bytes_per_line])
             for i in range(0, len(pairs), bytes_per_line)]
    print(f"\n{'─'*60}")
    print(f"  {label}  [{len(data)} bytes]")
    print(f"{'─'*60}")
    for line in lines:
        print(f"  {line}")

#Hàm 1 : Chuẩn hóa khóa K  → K'

def prepare_key(key: bytes, block_size: int, hash_fn) -> bytes:
    """
    Chuẩn hóa khóa K thành K' có độ dài đúng bằng block_size.

    Quy tắc (RFC 2104):
      - Nếu len(K) > block_size  →  K' = H(K)        (băm để thu gọn)
      - Nếu len(K) <= block_size →  K' = K            (giữ nguyên)
      - Sau đó đệm 0x00 bên phải cho đến khi len(K') = block_size
    """
    if len(key) > block_size:
        print(f"\n  [!] Khóa dài hơn block_size ({len(key)} > {block_size})")
        print(f"  [!] Tiến hành băm khóa K trước...")
        key = hash_fn(key).digest()
        print(f"  [!] Sau khi băm: len(K) = {len(key)} bytes")

#Đệm 0x00 bên phải
    key_prime = key.ljust(block_size, b"\x00")
    return key_prime

#Hàm 2 : Tính Inner Key = K' ⊕ ipad

def compute_inner_key(key_prime: bytes, block_size: int) -> bytes:
    """
    Tính inner_key = K' XOR ipad.
    ipad = byte 0x36 lặp lại block_size lần.
    """
    ipad = bytes([IPAD_BYTE] * block_size)
    inner_key = bytes(k ^ i for k, i in zip(key_prime, ipad))
    return inner_key

#Hàm 3 : Tính Outer Key = K' ⊕ opad

def compute_outer_key(key_prime: bytes, block_size: int) -> bytes:
    """
    Tính outer_key = K' XOR opad.
    opad = byte 0x5C lặp lại block_size lần.
    """
    opad = bytes([OPAD_BYTE] * block_size)
    outer_key = bytes(k ^ o for k, o in zip(key_prime, opad))
    return outer_key

#Hàm tổng hợp : chạy toàn bộ bước tiền xử lý và in kết quả

def key_prep_demo(key, hash_name: str = "sha256"):
    """
    Chạy toàn bộ bước tiền xử lý khóa của HMAC và in ra kết quả.

    Tham số:
        key       : str hoặc bytes – khóa bí mật K
        hash_name : str – tên hàm băm ("sha256", "sha512", "sha1", "md5")
    """
    if hash_name not in HASH_PARAMS:
        raise ValueError(f"Hàm băm '{hash_name}' chưa được hỗ trợ. "
                         f"Chọn một trong: {list(HASH_PARAMS.keys())}")

    params     = HASH_PARAMS[hash_name]
    block_size = params["block_size"]
    hash_fn    = params["fn"]
    key_bytes  = to_bytes(key)

    print("=" * 60)
    print(f"  HMAC KEY PREPARATION  –  Hàm băm: {hash_name.upper()}")
    print("=" * 60)
    print(f"  Block size  : {block_size} bytes ({block_size * 8} bits)")
    print(f"  Output size : {params['output_size']} bytes ({params['output_size'] * 8} bits)")
    print(f"  ipad        : 0x{IPAD_BYTE:02X}  (lặp {block_size} lần)")
    print(f"  opad        : 0x{OPAD_BYTE:02X}  (lặp {block_size} lần)")

#Khóa gốc K
    hex_dump("K (khóa gốc)", key_bytes)

#Bước 1 : Chuẩn hóa K → K'
    print(f"\n>>> BƯỚC 1: Chuẩn hóa K → K'")
    key_prime = prepare_key(key_bytes, block_size, hash_fn)
    hex_dump("K' (sau khi đệm đến block_size)", key_prime)

#Bước 2 : Inner Key
    print(f"\n>>> BƯỚC 2: Inner Key  =  K' ⊕ ipad (0x{IPAD_BYTE:02X})")
    inner_key = compute_inner_key(key_prime, block_size)
    hex_dump("Inner Key  (K' ⊕ ipad)", inner_key)

#Bước 3 : Outer Key
    print(f"\n>>> BƯỚC 3: Outer Key  =  K' ⊕ opad (0x{OPAD_BYTE:02X})")
    outer_key = compute_outer_key(key_prime, block_size)
    hex_dump("Outer Key  (K' ⊕ opad)", outer_key)

    print("\n" + "=" * 60)
    print("  Hoàn tất tiền xử lý khóa.")
    print("  Inner Key và Outer Key sẵn sàng cho bước tính HMAC.")
    print("=" * 60)

    return key_prime, inner_key, outer_key

#Demo với các test case từ báo cáo

if __name__ == "__main__":

    print("\n" + "█" * 60)
    print("  TEST CASE 1 – Khóa ngắn: 'key'  |  SHA-256")
    print("█" * 60)
    key_prep_demo("key", "sha256")

    print("\n" + "█" * 60)
    print("  TEST CASE 2 – Khóa rỗng: ''  |  SHA-256")
    print("█" * 60)
    key_prep_demo("", "sha256")

    print("\n" + "█" * 60)
    print("  TEST CASE 3 – Khóa quá dài (100 bytes)  |  SHA-256")
    print("█" * 60)
    long_key = "A" * 100      # 100 bytes > block_size=64 → phải băm
    key_prep_demo(long_key, "sha256")

    print("\n" + "█" * 60)
    print("  TEST CASE 4 – Khóa 'secret'  |  SHA-256")
    print("█" * 60)
    key_prep_demo("secret", "sha256")