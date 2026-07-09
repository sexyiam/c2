#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace pps {

struct SpawnCtx {
    void* hProc;
    void* hThread;
};

// Suspended child; optional parent spoof + BLOCK_NON_MICROSOFT_BINARIES.
SpawnCtx spawn(const std::wstring& cmd, std::uint32_t parent_pid,
               bool block_dlls, bool mitigation);

} // namespace pps
