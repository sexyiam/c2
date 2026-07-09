#pragma once
#include <cstddef>
#include <cstdint>

namespace stackspoof {

// Locates `add rsp, 0x20 ; ret` in clean ntdll .text for the spoofed retaddr.
bool init();

// 4-arg Win64 call with ntdll gadget as return address + planted continuation.
void* call4(void* target, std::uintptr_t a0, std::uintptr_t a1,
            std::uintptr_t a2, std::uintptr_t a3);

// NtSetInformationThread(ThreadHideFromDebugger) via call4.
bool hide_thread();

} // namespace stackspoof
