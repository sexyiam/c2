#include "MemGuard.h"
#include "ApiHash.h"
#include "Syscalls.h"

#include <windows.h>
#include <cstring>

namespace mg {

namespace {

void* k32(const char* n) {
    return api::export_by_hash(API_HASH("kernel32.dll"), API_HASH(n));
}

}

Guarded alloc(std::size_t n) {
    Guarded g{nullptr, 0, false};
    if (!n) return g;
    void* p = nullptr;
    std::size_t s = n;
    NTSTATUS st = syscalls::ScAllocVm((void*)-1, &p, 0, &s,
        MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (st < 0) return g;
    g.ptr = p; g.sz = n;
    return g;
}

void free(Guarded& g) {
    if (!g.ptr) return;
    if (g.locked) lock(g);
    std::size_t s = 0;
    syscalls::ScFreeVm((void*)-1, &g.ptr, &s, MEM_RELEASE);
    g.ptr = nullptr; g.sz = 0;
}

void unlock(Guarded& g) {
    if (!g.ptr || g.locked) return;
    std::size_t s = g.sz;
    std::uint32_t old = 0;
    syscalls::ScProtectVm((void*)-1, &g.ptr, &s, PAGE_READWRITE, &old);
    g.locked = true;
}

void lock(Guarded& g) {
    if (!g.ptr || !g.locked) return;
    std::memset(g.ptr, 0, g.sz);
    std::size_t s = g.sz;
    std::uint32_t old = 0;
    syscalls::ScProtectVm((void*)-1, &g.ptr, &s, PAGE_NOACCESS, &old);
    g.locked = false;
}

} // namespace mg
