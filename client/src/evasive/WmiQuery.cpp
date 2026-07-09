#include "WmiQuery.h"
#include "ApiHash.h"

#include <windows.h>

#include <cstring>

namespace wmi {

namespace {

void* r(const char* dll, const char* fn) {
    return api::export_by_hash(API_HASH(dll), API_HASH(fn));
}

typedef HRESULT (WINAPI* CoInitializeEx_t)(LPVOID, DWORD);
typedef HRESULT (WINAPI* CoCreateInstance_t)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef void (WINAPI* CoUninitialize_t)();
typedef HRESULT (WINAPI* SysAllocString_t)(const wchar_t*);

bool check_property(void* svc, const wchar_t* query, const wchar_t* prop, const wchar_t* needle) {
    (void)svc; (void)query; (void)prop; (void)needle;
    return false;
}

} // namespace

bool is_vm() {
    auto ci = reinterpret_cast<CoInitializeEx_t>(r("ole32.dll", "CoInitializeEx"));
    auto cu = reinterpret_cast<CoUninitialize_t>(r("ole32.dll", "CoUninitialize"));
    if (!ci || !cu) return false;
    ci(nullptr, COINIT_APARTMENTTHREADED);

    // Not wired to IWbemServices yet — always false.
    bool vm = false;

    cu();
    return vm;
}

} // namespace wmi
