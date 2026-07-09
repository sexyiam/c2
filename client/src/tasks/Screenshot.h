#pragma once
#include <string>

namespace shot {

// Base64 BMP; large — use chunked::send_result on the caller.
std::string capture();

} // namespace shot
