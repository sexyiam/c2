#include "Obf.h"

#include <cstddef>
#include <cstdint>

namespace obf {

void flat_xor(std::uint8_t* data, std::size_t n, const std::uint8_t k[16]) {
    enum class S : std::uint8_t { start, loop, end };
    volatile S s = S::start;
    std::size_t i = 0;
    while (s != S::end) {
        switch (s) {
        case S::start:
            i = 0;
            s = S::loop;
            break;
        case S::loop:
            if (i >= n) { s = S::end; break; }
            data[i] ^= k[i & 15];
            ++i;
            break;
        case S::end:
            break;
        }
    }
}

} // namespace obf
