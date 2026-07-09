#pragma once
#include <string>

namespace keylog {

// GetAsyncKeyState poll — no global hook.
std::string capture(std::uint32_t seconds);

} // namespace keylog
