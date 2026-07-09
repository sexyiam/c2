#include "HwbpClean.h"
#include "Syscalls.h"

#include <windows.h>

namespace hwbp {

namespace {

void zero_ctx(void* h) {
    CONTEXT c{};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (syscalls::ScGetCtx(h, &c) < 0) return;
    c.Dr0 = c.Dr1 = c.Dr2 = c.Dr3 = 0;
    c.Dr6 = 0;
    c.Dr7 = 0;
    syscalls::ScSetCtx(h, &c);
}

} // namespace

void clear_self() {
    zero_ctx((void*)-2);
}

void clear_thread(void* h) {
    if (h) zero_ctx(h);
}

} // namespace hwbp
