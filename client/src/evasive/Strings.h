#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace obf {

#ifdef C2_OBF_SEED
constexpr std::uint32_t seed = static_cast<std::uint32_t>(C2_OBF_SEED);
#else
constexpr std::uint32_t seed = 0x9E3779B9u;
#endif

template <std::size_t N>
constexpr std::uint8_t kc(std::size_t i) {
    std::uint32_t x = seed ^ static_cast<std::uint32_t>(i * 2654435761u);
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    return static_cast<std::uint8_t>(x & 0xFF);
}

// consteval so MSVC does not emit the plaintext constructor argument into .rdata.
template <std::size_t N>
struct EncString {
    std::array<std::uint8_t, N> enc{};
    consteval EncString(const char (&raw)[N]) {
        for (std::size_t i = 0; i < N; ++i)
            enc[i] = static_cast<std::uint8_t>(raw[i]) ^ kc<N>(i);
    }
};

template <std::size_t N>
class ObfStr {
public:
    ObfStr(const EncString<N>& s) {
        for (std::size_t i = 0; i < N; ++i) buf_[i] = s.enc[i] ^ kc<N>(i);
    }
    ~ObfStr() { for (auto& c : buf_) c = 0; }
    ObfStr(const ObfStr&) = delete;
    ObfStr& operator=(const ObfStr&) = delete;
    const char* c_str() const { return reinterpret_cast<const char*>(buf_.data()); }
    std::size_t size() const { return N - 1; }
private:
    std::array<std::uint8_t, N> buf_{};
};

#define OBF(s) (::obf::ObfStr<sizeof(s)>{::obf::EncString<sizeof(s)>{s}}).c_str()
#define OBF_KEEP(s) (::obf::ObfStr<sizeof(s)>{::obf::EncString<sizeof(s)>{s}})

} // namespace obf

namespace rse {

class GuardedStr {
public:
    GuardedStr(const std::uint8_t* blob, std::size_t len);
    ~GuardedStr();
    GuardedStr(const GuardedStr&) = delete;
    GuardedStr& operator=(const GuardedStr&) = delete;
    const char* c_str() const { return reinterpret_cast<const char*>(ptr_); }
    std::size_t size() const { return len_; }
private:
    void* ptr_;
    std::size_t len_;
};

#define RSE(s) (::rse::GuardedStr(reinterpret_cast<const std::uint8_t*>(s), sizeof(s) - 1))

} // namespace rse
