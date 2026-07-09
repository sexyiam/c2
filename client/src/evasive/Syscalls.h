#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>

namespace syscalls {

bool init();

std::uint32_t ssn_for(std::uint32_t name_hash);
void* gadget();

// Sets SSN/gadget then jumps through the MASM stub. Up to 12 ULONG_PTR args.
NTSTATUS invoke(std::uint32_t ssn,
                std::uintptr_t a0,  std::uintptr_t a1,
                std::uintptr_t a2,  std::uintptr_t a3,
                std::uintptr_t a4,  std::uintptr_t a5,
                std::uintptr_t a6,  std::uintptr_t a7,
                std::uintptr_t a8,  std::uintptr_t a9,
                std::uintptr_t a10, std::uintptr_t a11);

// ---- syscalls ----

NTSTATUS ScAllocVm(void* ProcessHandle, void** BaseAddress,
    std::uint32_t ZeroBits, std::size_t* RegionSize, std::uint32_t AllocationType,
    std::uint32_t Protect);
NTSTATUS ScProtectVm(void* ProcessHandle, void** BaseAddress,
    std::size_t* RegionSize, std::uint32_t NewProtect, std::uint32_t* OldProtect);
NTSTATUS ScFreeVm(void* ProcessHandle, void** BaseAddress,
    std::size_t* RegionSize, std::uint32_t FreeType);
NTSTATUS ScWriteVm(void* ProcessHandle, void* BaseAddress,
    const void* Buffer, std::size_t NumberOfBytesToWrite, std::size_t* NumberOfBytesWritten);
NTSTATUS ScCreateFile(void** FileHandle, std::uint32_t DesiredAccess,
    void* ObjectAttributes, void* IoStatusBlock, void* AllocationSize,
    std::uint32_t FileAttributes, std::uint32_t ShareAccess,
    std::uint32_t CreateDisposition, std::uint32_t CreateOptions, void* EaBuffer,
    std::uint32_t EaLength);
NTSTATUS ScReadFile(void* FileHandle, void* Event, void* ApcRoutine,
    void* ApcContext, void* IoStatusBlock, void* Buffer, std::uint32_t Length,
    void* ByteOffset, void* Key);
NTSTATUS ScWriteFile(void* FileHandle, void* Event, void* ApcRoutine,
    void* ApcContext, void* IoStatusBlock, void* Buffer, std::uint32_t Length,
    void* ByteOffset, void* Key);
NTSTATUS ScClose(void* Handle);
NTSTATUS ScQuerySysInfo(int Class, void* Buffer,
    std::uint32_t Length, std::uint32_t* ResultLength);
NTSTATUS ScQueryProcInfo(void* ProcessHandle, int Class, void* Buffer,
    std::uint32_t Length, std::uint32_t* ResultLength);
NTSTATUS ScSetThreadInfo(void* ThreadHandle, int Class,
    void* Info, std::uint32_t Length);
NTSTATUS ScGetCtx(void* ThreadHandle, CONTEXT* Context);
NTSTATUS ScSetCtx(void* ThreadHandle, CONTEXT* Context);
NTSTATUS ScQueueApc(void* ThreadHandle, void* ApcRoutine,
    void* Argument1, void* Argument2, void* Argument3);
NTSTATUS ScResume(void* ThreadHandle, std::uint32_t* SuspendCount);
NTSTATUS ScContinue(CONTEXT* Context, BOOLEAN RaiseAlert);
NTSTATUS ScAlert(void* ThreadHandle);
NTSTATUS ScTestAlert();
NTSTATUS ScCreateSection(void** SectionHandle, std::uint32_t DesiredAccess, void* ObjectAttributes,
    void* MaximumSize, std::uint32_t PageAttributes, std::uint32_t SectionAttributes, void* FileHandle);
NTSTATUS ScCreateProcessEx(void** ProcessHandle, std::uint32_t DesiredAccess, void* ObjectAttributes,
    void* ParentProcess, std::uint32_t Flags, void* SectionHandle, void* DebugPort, void* ExceptionPort,
    std::uint32_t JobMemberLevel);
NTSTATUS ScCreateThreadEx(void** ThreadHandle, std::uint32_t DesiredAccess, void* ObjectAttributes,
    void* ProcessHandle, void* StartRoutine, void* Argument, BOOLEAN CreateSuspended, std::size_t StackZeroBits,
    std::size_t SizeOfStackCommit, std::size_t SizeOfStackReserve, void* BytesBuffer);
NTSTATUS ScExitProcess(NTSTATUS Status);

} // namespace syscalls
