#pragma once
#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace nt {

struct UnicodeString {
    std::uint16_t Length;
    std::uint16_t MaxLength;
    wchar_t* Buffer;
};

struct ObjectAttributes {
    std::uint32_t Length;
    void* RootDirectory;
    UnicodeString* ObjectName;
    std::uint32_t Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
};

struct IoStatusBlock {
    union { NTSTATUS Status; void* Pointer; };
    std::uintptr_t Information;
};

constexpr std::uint32_t OBJ_CASE_INSENSITIVE = 0x00000040;

// "\??\C:\path" — caller frees Buffer.
UnicodeString* make_unicode(const wchar_t* path);
void init_object(ObjectAttributes& oa, UnicodeString* name,
                 std::uint32_t attrs = OBJ_CASE_INSENSITIVE);

} // namespace nt
