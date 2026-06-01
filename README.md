***

```markdown
# 🛡️ Authenticated Encryption System (HMAC & AES-256)

**Developed by:** Group 6  
**Course:** Information Security  

---

## 📖 Introduction
This project implements a secure **Authenticated Encryption (AE)** system adhering to the gold standard paradigm: **Encrypt-then-MAC (EtM)**. 

The defining characteristic of this project is that all core cryptographic primitives—including **SHA-256, HMAC, and AES-256-CBC**—were **implemented completely from scratch (100% pure C++)**. No external cryptographic libraries (such as OpenSSL, LibreSSL, or Crypto++) were utilized. This approach provides a transparent, deep dive into the inner mathematical workings of low-level cryptographic construction.

## ✨ Key Features
1. **Hash Length Extension Attack Demo:** A practical, visual demonstration showing why the naive approach `MAC = Hash(Key || Message)` is inherently broken, illustrating the absolute cryptographic necessity of HMAC.
2. **HMAC Core:** A mathematically precise implementation of the Hash-based Message Authentication Code. It successfully passes the standard international test vectors defined in **RFC 4231**.
3. **AES-256-CBC:** A native block-cipher implementation of AES-256 in Cipher Block Chaining (CBC) mode. Includes secure Initialization Vector (IV) handling and accurate PKCS7 padding/unpadding validation.
4. **Timing Attack Mitigation:** Implements a `constant-time string comparison` algorithm for MAC verification, eliminating side-channel timing leaks.
5. **End-to-End AE Simulation:** Simulates network communication via two primary test scenarios:
   * **Secure Transmission:** The ciphertext and MAC arrive unaltered, resulting in successful verification and decryption.
   * **Tampered Transmission (Hacker Scenario):** An adversary intercepts and alters bits within the ciphertext or MAC during transit. The system detects the modification immediately and rejects the packet *before* triggering any decryption routines, preventing padding oracle vulnerabilities.

## 📂 Repository Structure
* `main.cpp` : The central driver containing the execution flows (RFC test vectors, secure transmission simulation, and hacker attack simulation).
* `basic_mac.h/cpp` : Implementation of the flawed simple MAC function (used to demonstrate the length extension attack) & shared key definitions.
* `sha256.h/cpp` : Custom implementation of the SHA-256 cryptographic hash function from scratch.
* `hmac.h/cpp` : Implementation of the Hash-based Message Authentication Code (HMAC-SHA256) algorithm.
* `aes_crypto.h/cpp` : AES-256 encryption and decryption routines operating in CBC mode.
* `ae_system.h/cpp` : The Authenticated Encryption system orchestrator, handling packet packing and unpacking (Encrypt-then-MAC logic).
* `utils.h/cpp` : Helper utilities for Hex string conversions and constant-time comparisons.

## 🚀 Getting Started

### 1. Prerequisites
- A modern C++ compiler supporting **C++11** or higher (e.g., GCC/MinGW, Clang, or MSVC).
- Command-line interface / Terminal.

### 2. Compilation
Navigate to the root directory containing the source files and execute the following command to compile the project:

```bash
g++ *.cpp -o do_an_hmac
