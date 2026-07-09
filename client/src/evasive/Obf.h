#pragma once
#include <cstdint>

namespace obf {

#define FLATTEN_BEGIN() \
    enum class __f : std::uint32_t { __start = 0,
#define FLATTEN_STATE(name) name,
#define FLATTEN_END() __end }; \
    volatile __f __s = __f::__start; \
    while (__s != __f::__end) { \
        switch (__s) {
#define CASE(name) case __f::name: \
        __s = __f::__end; // default: finish after this block unless reassigned

#define NEXT(name) __s = __f::name; break;
#define FLATTEN_FINISH() } } break;

} // namespace obf
