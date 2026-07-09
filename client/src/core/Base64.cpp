#include "Base64.h"

namespace b64 {

namespace {
constexpr char e[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int d(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
}

std::string encode(const std::uint8_t* p, std::size_t n) {
    std::string o;
    o.reserve(((n + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        std::uint32_t v = (p[i] << 16) | (p[i + 1] << 8) | p[i + 2];
        o.push_back(e[(v >> 18) & 0x3F]);
        o.push_back(e[(v >> 12) & 0x3F]);
        o.push_back(e[(v >> 6) & 0x3F]);
        o.push_back(e[v & 0x3F]);
    }
    if (i < n) {
        std::uint32_t v = p[i] << 16;
        if (i + 1 < n) v |= p[i + 1] << 8;
        o.push_back(e[(v >> 18) & 0x3F]);
        o.push_back(e[(v >> 12) & 0x3F]);
        o.push_back(i + 1 < n ? e[(v >> 6) & 0x3F] : '=');
        o.push_back('=');
    }
    return o;
}

std::string encode(std::string_view r) {
    return encode(reinterpret_cast<const std::uint8_t*>(r.data()), r.size());
}

std::string decode(std::string_view s, bool* ok) {
    std::string o;
    if (ok) *ok = true;
    std::uint32_t a = 0;
    int b = 0;
    for (char c : s) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int v = d(c);
        if (v < 0) { if (ok) *ok = false; return {}; }
        a = (a << 6) | static_cast<std::uint32_t>(v);
        b += 6;
        if (b >= 8) {
            b -= 8;
            o.push_back(static_cast<char>((a >> b) & 0xFF));
        }
    }
    return o;
}

} // namespace b64
