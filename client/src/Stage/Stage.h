#pragma once
#include <cstdint>
#include <string_view>

namespace stage {

bool load_and_run(std::string_view url, const std::uint8_t key[32]);

} // namespace stage
