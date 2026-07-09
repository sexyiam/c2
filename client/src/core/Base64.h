#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace b64 {

std::string encode(const std::uint8_t* data, std::size_t len);
std::string encode(std::string_view raw);

// ok=false on invalid input.
std::string decode(std::string_view b64, bool* ok = nullptr);

} // namespace b64
