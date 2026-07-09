#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace inject {

std::string remote_map(std::uint32_t pid, const std::uint8_t* payload, std::size_t len);

// Relocs are ImageBase-only — prefer /FIXED or matching preferred base.
std::string hollowing(const std::uint8_t* payload, std::size_t len, const wchar_t* host_path);

std::string hijack_thread(std::uint32_t pid, const std::uint8_t* payload, std::size_t len);

} // namespace inject
