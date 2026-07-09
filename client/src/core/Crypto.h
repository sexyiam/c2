#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

// PBKDF2-HMAC-SHA256, 100k iters, 32-byte key — matches Python hashlib.pbkdf2_hmac.
std::vector<std::uint8_t> derive_key(std::string_view psk,
                                     const std::uint8_t* salt, std::size_t salt_len);

// AES-256-GCM -> base64(nonce[12] || tag[16] || ct); matches Python crypto.encrypt().
std::string encrypt(std::string_view plaintext, const std::uint8_t key[32]);

// Inverse of encrypt(); ok=false on auth failure / bad input.
std::string decrypt(std::string_view b64_blob, const std::uint8_t key[32], bool* ok = nullptr);

std::string random_nonce_hex();

} // namespace crypto
