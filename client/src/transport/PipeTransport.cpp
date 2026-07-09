#include "PipeTransport.h"

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace tx {

bool PipeTransport::send(std::string_view path, std::string_view body,
                         std::string_view agent_id, Reply& out) {
    std::string name = "\\\\" + host_ + "\\" + pipename_;
    std::wstring wname(name.begin(), name.end());

    HANDLE h = CreateFileW(wname.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { out.ok = false; return false; }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

    // Server expects: 4-byte LE length + "path\nagent_id\nbody"
    std::string msg = std::string(path) + "\n" + std::string(agent_id) + "\n" + std::string(body);
    std::uint32_t len = static_cast<std::uint32_t>(msg.size());
    std::vector<char> frame(4 + msg.size());
    frame[0] = static_cast<char>(len & 0xFF);
    frame[1] = static_cast<char>((len >> 8) & 0xFF);
    frame[2] = static_cast<char>((len >> 16) & 0xFF);
    frame[3] = static_cast<char>((len >> 24) & 0xFF);
    memcpy(frame.data() + 4, msg.data(), msg.size());

    DWORD wn = 0;
    if (!WriteFile(h, frame.data(), static_cast<DWORD>(frame.size()), &wn, nullptr)) {
        CloseHandle(h); out.ok = false; return false;
    }

    // Reply: 4-byte LE length + body
    char hdr[4];
    DWORD rn = 0;
    if (!ReadFile(h, hdr, 4, &rn, nullptr) || rn != 4) {
        CloseHandle(h); out.ok = false; return false;
    }
    std::uint32_t rlen = static_cast<std::uint8_t>(hdr[0])
        | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(hdr[1])) << 8)
        | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(hdr[2])) << 16)
        | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(hdr[3])) << 24);
    if (rlen > 1u << 20) { CloseHandle(h); out.ok = false; return false; }

    std::string buf(rlen, '\0');
    rn = 0;
    if (!ReadFile(h, buf.data(), rlen, &rn, nullptr) || rn != rlen) {
        CloseHandle(h); out.ok = false; return false;
    }
    out.body = std::move(buf);
    out.ok = true;
    CloseHandle(h);
    return true;
}

} // namespace tx
