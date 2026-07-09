#include "ApiHash.h"

#include <windows.h>
#include <winternl.h>

namespace api {

namespace {

using LIST_ENTRY = _LIST_ENTRY;

struct UnicodeString_X {
    std::uint16_t Length;
    std::uint16_t MaximumLength;
    wchar_t* Buffer;
};

struct PEB_LDR_DATA_X {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY_X {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UnicodeString_X FullDllName;
    UnicodeString_X BaseDllName;
};

struct LdrWalk {
    LIST_ENTRY* sentinel;
    LIST_ENTRY* first;
};

LdrWalk ldr_head() {
    auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
    LdrWalk w{};
    if (!peb || !peb->Ldr) return w;
    auto ldr = reinterpret_cast<PEB_LDR_DATA_X*>(peb->Ldr);
    w.sentinel = &ldr->InLoadOrderModuleList;
    w.first = w.sentinel->Flink;
    return w;
}

std::uint32_t hash_wide(const wchar_t* s, std::size_t len) {
    std::uint32_t h = 0x811c9dc5u;
    for (std::size_t i = 0; i < len; ++i) {
        wchar_t c = s[i];
        if (c >= L'a' && c <= L'z') c -= 32;
        h ^= static_cast<std::uint8_t>(c & 0xFF);
        h *= 0x01000193u;
    }
    return h;
}

void* find_export(void* dll_base, std::uint32_t func_hash) {
    if (!dll_base) return nullptr;
    auto base = reinterpret_cast<std::uint8_t*>(dll_base);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto& expdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expdir.VirtualAddress) return nullptr;
    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + expdir.VirtualAddress);
    auto names = reinterpret_cast<std::uint32_t*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<std::uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<std::uint32_t*>(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* nm = reinterpret_cast<const char*>(base + names[i]);
        if (hash(nm) == func_hash) {
            DWORD fn = funcs[ordinals[i]];
            if (fn >= expdir.VirtualAddress &&
                fn < expdir.VirtualAddress + expdir.Size) {
                return nullptr;
            }
            return base + fn;
        }
    }
    return nullptr;
}

} // namespace

void* module_by_hash(std::uint32_t dll_hash) {
    auto w = ldr_head();
    if (!w.sentinel) return nullptr;
    for (LIST_ENTRY* p = w.first; p && p != w.sentinel; p = p->Flink) {
        auto e = reinterpret_cast<LDR_DATA_TABLE_ENTRY_X*>(p);
        if (e->BaseDllName.Length == 0) continue;
        if (hash_wide(e->BaseDllName.Buffer, e->BaseDllName.Length / sizeof(wchar_t)) == dll_hash) {
            return e->DllBase;
        }
    }
    return nullptr;
}

void* export_by_hash(std::uint32_t dll_hash, std::uint32_t func_hash) {
    return find_export(module_by_hash(dll_hash), func_hash);
}

void* ldr_load_dll(const wchar_t* name) {
    auto ntdll = module_by_hash(API_HASH("ntdll.dll"));
    if (!ntdll) return nullptr;
    auto LdrLoadDll = reinterpret_cast<NTSTATUS(NTAPI*)(void*, void*, UNICODE_STRING*, void*)>(
        find_export(ntdll, API_HASH("LdrLoadDll")));
    auto LdrGetDllHandle = reinterpret_cast<NTSTATUS(NTAPI*)(void*, void*, UNICODE_STRING*, void**)>(
        find_export(ntdll, API_HASH("LdrGetDllHandleByName")));
    if (!LdrLoadDll || !LdrGetDllHandle) return nullptr;

    void* base = nullptr;
    UNICODE_STRING us{};
    us.Buffer = const_cast<wchar_t*>(name);
    us.Length = static_cast<USHORT>(wcslen(name) * sizeof(wchar_t));
    us.MaximumLength = us.Length;
    if (LdrGetDllHandle(nullptr, nullptr, &us, &base) == 0 && base) return base;
    if (LdrLoadDll(nullptr, nullptr, &us, &base) == 0) return base;
    return nullptr;
}

} // namespace api
