#pragma once
#include <cstdint>

namespace cspoof {

// Fake CONTEXT with RIP/Rsp on a benign ntdll idle path.
bool init();
void spoof_context(void* ctx);

} // namespace cspoof
