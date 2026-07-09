#pragma once
#include <cstdint>
namespace nthash {
  constexpr std::uint32_t NtAllocateVirtualMemory = 0xD58D5A18;
  constexpr std::uint32_t NtProtectVirtualMemory = 0x069FF566;
  constexpr std::uint32_t NtFreeVirtualMemory = 0x8A45BA47;
  constexpr std::uint32_t NtWriteVirtualMemory = 0x6D78ACB2;
  constexpr std::uint32_t NtCreateFile = 0xB64D91F9;
  constexpr std::uint32_t NtReadFile = 0xCC5FECBD;
  constexpr std::uint32_t NtWriteFile = 0x3F271324;
  constexpr std::uint32_t NtClose = 0x1498D8A5;
  constexpr std::uint32_t NtQuerySystemInformation = 0x37072D8A;
  constexpr std::uint32_t NtQueryInformationProcess = 0x69925B6A;
  constexpr std::uint32_t NtSetInformationThread = 0x458F3221;
  constexpr std::uint32_t NtGetContextThread = 0x85F22D70;
  constexpr std::uint32_t NtSetContextThread = 0xA1E2C124;
  constexpr std::uint32_t NtQueueApcThread = 0xBED494AC;
  constexpr std::uint32_t NtResumeThread = 0x5A3C3E5C;
  constexpr std::uint32_t NtCreateSection = 0xCE7FA4E2;
  constexpr std::uint32_t NtCreateProcessEx = 0xE6CF3FC1;
  constexpr std::uint32_t NtCreateThreadEx = 0xC00335DA;
  constexpr std::uint32_t NtContinue = 0x3239F036;
  constexpr std::uint32_t NtAlertThread = 0x30EAE23B;
  constexpr std::uint32_t NtTestAlert = 0xF586CF8F;
  constexpr std::uint32_t RtlExitUserProcess = 0xE9A68C87;
}