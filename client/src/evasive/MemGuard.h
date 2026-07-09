#pragma once
#include <cstddef>
#include <cstdint>

namespace mg {

struct Guarded {
    void* ptr;
    std::size_t sz;
    bool locked;
};

// PAGE_NOACCESS; unlock/lock around access.
Guarded alloc(std::size_t n);
void free(Guarded& g);
void unlock(Guarded& g);
void lock(Guarded& g);

} // namespace mg
