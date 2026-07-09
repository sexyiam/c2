#include "Strings.h"
#include "MemGuard.h"

#include <windows.h>

#include <cstring>

namespace rse {

namespace {

// ChaCha20 for at-rest string blobs; key/nonce from build seed.
constexpr std::uint32_t rotl(std::uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void qr(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

void chacha_block(std::uint32_t state[16], std::uint8_t out[64]) {
    std::uint32_t w[16];
    std::memcpy(w, state, 64);
    for (int i = 0; i < 10; ++i) {
        qr(w[0], w[4], w[8],  w[12]);
        qr(w[1], w[5], w[9],  w[13]);
        qr(w[2], w[6], w[10], w[14]);
        qr(w[3], w[7], w[11], w[15]);
        qr(w[0], w[5], w[10], w[15]);
        qr(w[1], w[6], w[11], w[12]);
        qr(w[2], w[7], w[8],  w[13]);
        qr(w[3], w[4], w[9],  w[14]);
    }
    for (int i = 0; i < 16; ++i) w[i] += state[i];
    for (int i = 0; i < 16; ++i) {
        out[i*4]     = static_cast<std::uint8_t>(w[i] & 0xFF);
        out[i*4 + 1] = static_cast<std::uint8_t>((w[i] >> 8) & 0xFF);
        out[i*4 + 2] = static_cast<std::uint8_t>((w[i] >> 16) & 0xFF);
        out[i*4 + 3] = static_cast<std::uint8_t>((w[i] >> 24) & 0xFF);
    }
}

void chacha_crypt(std::uint8_t* data, std::size_t len) {
    // Build-seed key/nonce (override per campaign if needed).
    std::uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x12345678, 0x9abcdef0, 0x11223344, 0x55667788,
        0xaabbccdd, 0xeeff0011, 0x22334455, 0x66778899,
        0x00000000, 0x00000000, 0x00000000, 0x00000000
    };
    std::uint8_t block[64];
    std::size_t counter = 0;
    for (std::size_t i = 0; i < len; ++i) {
        if (i % 64 == 0) {
            state[12] = static_cast<std::uint32_t>(counter & 0xFFFFFFFF);
            state[13] = static_cast<std::uint32_t>((counter >> 32) & 0xFFFFFFFF);
            chacha_block(state, block);
            ++counter;
        }
        data[i] ^= block[i % 64];
    }
}

} // namespace

GuardedStr::GuardedStr(const std::uint8_t* blob, std::size_t len) : len_(len) {
    mg::Guarded g = mg::alloc(len + 1);
    mg::unlock(g);
    ptr_ = g.ptr;
    std::memcpy(ptr_, blob, len);
    static_cast<char*>(ptr_)[len] = '\0';
    chacha_crypt(static_cast<std::uint8_t*>(ptr_), len);
    mg::lock(g);
}

GuardedStr::~GuardedStr() {
    if (!ptr_) return;
    mg::Guarded g{ptr_, len_ + 1, false};
    mg::unlock(g);
    std::memset(ptr_, 0, len_ + 1);
    mg::free(g);
}

} // namespace rse
