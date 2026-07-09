#include "NtTypes.h"
#include "ApiHash.h"

#include <windows.h>

namespace nt {

namespace {
void* (WINAPI* g_HeapAlloc)(HANDLE, DWORD, SIZE_T) = nullptr;
HANDLE g_heap = nullptr;
void init_heap() {
    if (g_heap) return;
    g_heap = GetProcessHeap();
    constexpr std::uint32_t k32 = API_HASH("kernel32.dll");
    g_HeapAlloc = api::resolve<decltype(&::HeapAlloc)>(k32, API_HASH("HeapAlloc"));
}
}

UnicodeString* make_unicode(const wchar_t* path) {
    init_heap();
    std::size_t chars = wcslen(path);
    std::size_t bytes = chars * sizeof(wchar_t);
    // allocate UnicodeString struct + buffer together
    auto* us = static_cast<UnicodeString*>(
        g_HeapAlloc(g_heap, 0, sizeof(UnicodeString) + bytes + sizeof(wchar_t)));
    if (!us) return nullptr;
    us->Length = static_cast<std::uint16_t>(bytes);
    us->MaxLength = static_cast<std::uint16_t>(bytes + sizeof(wchar_t));
    us->Buffer = reinterpret_cast<wchar_t*>(us + 1);
    memcpy(us->Buffer, path, bytes);
    us->Buffer[chars] = L'\0';
    return us;
}

void init_object(ObjectAttributes& oa, UnicodeString* name, std::uint32_t attrs) {
    oa.Length = sizeof(ObjectAttributes);
    oa.RootDirectory = nullptr;
    oa.ObjectName = name;
    oa.Attributes = attrs;
    oa.SecurityDescriptor = nullptr;
    oa.SecurityQualityOfService = nullptr;
}

} // namespace nt
