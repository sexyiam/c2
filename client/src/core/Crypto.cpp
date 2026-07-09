#include "Crypto.h"
#include "Base64.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace crypto {

namespace {

constexpr auto kA = BCRYPT_AES_ALGORITHM;
constexpr auto kG = BCRYPT_CHAIN_MODE_GCM;
constexpr ULONG kI = 100000;

BCRYPT_ALG_HANDLE agh() {
    BCRYPT_ALG_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&h, kA, nullptr, 0) != 0) return nullptr;
    BCryptSetProperty(h, BCRYPT_CHAINING_MODE,
                      reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(kG)),
                      sizeof(kG), 0);
    return h;
}

bool hmac_sha256(const std::uint8_t* key, std::size_t key_len,
                 const std::uint8_t* data, std::size_t data_len,
                 std::uint8_t out[32]) {
    BCRYPT_ALG_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return false;
    }
    BCRYPT_HASH_HANDLE hh = nullptr;
    NTSTATUS st = BCryptCreateHash(h, &hh, nullptr, 0,
                                   const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(h, 0);
        return false;
    }
    st = BCryptHashData(hh, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
    if (st == 0) st = BCryptFinishHash(hh, out, 32, 0);
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(h, 0);
    return st == 0;
}

// RFC 2898 PBKDF2-HMAC-SHA256, matches Python hashlib.pbkdf2_hmac("sha256", ...)
bool pbkdf2_sha256(const std::uint8_t* password, std::size_t password_len,
                   const std::uint8_t* salt, std::size_t salt_len,
                   ULONG iterations, std::uint8_t* out, std::size_t out_len) {
    if (!out || out_len == 0) return false;
    std::size_t produced = 0;
    ULONG block = 1;
    while (produced < out_len) {
        // U1 = HMAC(password, salt || INT(block))
        std::vector<std::uint8_t> msg(salt, salt + salt_len);
        msg.push_back(static_cast<std::uint8_t>((block >> 24) & 0xFF));
        msg.push_back(static_cast<std::uint8_t>((block >> 16) & 0xFF));
        msg.push_back(static_cast<std::uint8_t>((block >> 8) & 0xFF));
        msg.push_back(static_cast<std::uint8_t>(block & 0xFF));

        std::uint8_t u[32];
        std::uint8_t t[32];
        if (!hmac_sha256(password, password_len, msg.data(), msg.size(), u)) return false;
        std::memcpy(t, u, 32);

        for (ULONG i = 1; i < iterations; ++i) {
            if (!hmac_sha256(password, password_len, u, 32, u)) return false;
            for (int j = 0; j < 32; ++j) t[j] ^= u[j];
        }

        std::size_t n = out_len - produced;
        if (n > 32) n = 32;
        std::memcpy(out + produced, t, n);
        produced += n;
        ++block;
    }
    return true;
}

} // namespace

std::vector<std::uint8_t> derive_key(std::string_view p, const std::uint8_t* s, std::size_t l) {
    std::vector<std::uint8_t> o(32);
    if (!pbkdf2_sha256(reinterpret_cast<const std::uint8_t*>(p.data()), p.size(),
                       s, l, kI, o.data(), o.size())) {
        o.clear();
    }
    return o;
}

std::string encrypt(std::string_view pt, const std::uint8_t k[32]) {
    static auto h = agh();
    if (!h) return {};
    BCRYPT_KEY_HANDLE kh = nullptr;
    if (BCryptGenerateSymmetricKey(h, &kh, nullptr, 0, const_cast<PUCHAR>(k), 32, 0) != 0) return {};

    std::uint8_t n[12];
    BCryptGenRandom(nullptr, n, sizeof(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::vector<std::uint8_t> ct(pt.size());
    std::uint8_t t[16];

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = n; ai.cbNonce = sizeof(n);
    ai.pbTag = t;   ai.cbTag = sizeof(t);

    ULONG ol = 0;
    NTSTATUS r = BCryptEncrypt(kh,
        reinterpret_cast<PUCHAR>(const_cast<char*>(pt.data())), static_cast<ULONG>(pt.size()),
        &ai, nullptr, 0, ct.data(), static_cast<ULONG>(ct.size()), &ol, 0);
    BCryptDestroyKey(kh);
    if (r != 0) return {};

    std::vector<std::uint8_t> b;
    b.reserve(sizeof(n) + sizeof(t) + ct.size());
    b.insert(b.end(), n, n + sizeof(n));
    b.insert(b.end(), t, t + sizeof(t));
    b.insert(b.end(), ct.begin(), ct.end());
    return b64::encode(b.data(), b.size());
}

std::string decrypt(std::string_view b, const std::uint8_t k[32], bool* ok) {
    if (ok) *ok = false;
    bool g = false;
    auto r = b64::decode(b, &g);
    if (!g || r.size() < 28) return {};

    const std::uint8_t* n = reinterpret_cast<const std::uint8_t*>(r.data());
    const std::uint8_t* t = n + 12;
    const std::uint8_t* c = n + 28;
    std::size_t cl = r.size() - 28;

    static auto h = agh();
    if (!h) return {};
    BCRYPT_KEY_HANDLE kh = nullptr;
    if (BCryptGenerateSymmetricKey(h, &kh, nullptr, 0, const_cast<PUCHAR>(k), 32, 0) != 0) return {};

    std::vector<std::uint8_t> pt(cl);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = const_cast<PUCHAR>(n); ai.cbNonce = 12;
    ai.pbTag = const_cast<PUCHAR>(t);   ai.cbTag = 16;

    ULONG ol = 0;
    NTSTATUS st = BCryptDecrypt(kh, const_cast<PUCHAR>(c), static_cast<ULONG>(cl),
        &ai, nullptr, 0, pt.data(), static_cast<ULONG>(pt.size()), &ol, 0);
    BCryptDestroyKey(kh);
    if (st != 0) return {};
    if (ok) *ok = true;
    return std::string(reinterpret_cast<char*>(pt.data()), ol);
}

std::string random_nonce_hex() {
    std::uint8_t n[16];
    BCryptGenRandom(nullptr, n, sizeof(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    static const char* hex = "0123456789abcdef";
    std::string o(32, '0');
    for (int i = 0; i < 16; ++i) {
        o[i * 2] = hex[n[i] >> 4];
        o[i * 2 + 1] = hex[n[i] & 0xF];
    }
    return o;
}

} // namespace crypto
