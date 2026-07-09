#pragma once
#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace api {

constexpr std::uint32_t hash(const char* s) {
    std::uint32_t h = 0x811c9dc5u;
    for (; *s; ++s) {
        char c = *s;
        if (c >= 'a' && c <= 'z') c -= 32;
        h ^= static_cast<std::uint8_t>(c);
        h *= 0x01000193u;
    }
    return h;
}

#define API_HASH(name) ::api::hash(name)

void* module_by_hash(std::uint32_t dll_hash);

void* export_by_hash(std::uint32_t dll_hash, std::uint32_t func_hash);

template <typename T>
inline T resolve(std::uint32_t dll_hash, std::uint32_t func_hash) {
    return reinterpret_cast<T>(export_by_hash(dll_hash, func_hash));
}

void* ldr_load_dll(const wchar_t* name);

} // namespace api
