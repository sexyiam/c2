#pragma once
#include <string>

namespace tokens {

// Impersonates briefly, then reverts before return.
std::string steal_from_process(std::uint32_t pid);
std::string whoami();

} // namespace tokens
