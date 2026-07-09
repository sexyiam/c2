#pragma once
#include <windows.h>

// Debug / C2_DEBUG only; release is a no-op.
#if defined(_DEBUG) || defined(C2_DEBUG)
inline void c2_stage_log(const char* s) {
    char path[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, path)) return;
    lstrcatA(path, "diag.tmp");
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char line[256];
    int n = wsprintfA(line, "%u %s\r\n", GetTickCount(), s);
    DWORD w = 0;
    WriteFile(h, line, static_cast<DWORD>(n), &w, nullptr);
    CloseHandle(h);
}
#define C2_STAGE(s) ::c2_stage_log(s)
#else
#define C2_STAGE(s) ((void)0)
#endif
