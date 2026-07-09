#include "Malleable.h"
#include "core/Base64.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace malleable {

namespace {

std::string trim(std::string_view s) {
    auto a = s.begin();
    while (a != s.end() && std::isspace(*a)) ++a;
    auto z = s.end();
    while (z != a && std::isspace(*(z - 1))) --z;
    return std::string(a, z);
}

std::string unquote(std::string_view s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return std::string(s.substr(1, s.size() - 2));
    }
    return std::string(s);
}

std::string b64url(std::string_view s) {
    auto r = b64::encode(s);
    for (auto& c : r) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    r.erase(std::remove(r.begin(), r.end(), '='), r.end());
    return r;
}

std::string unb64url(std::string_view s) {
    std::string r(s);
    for (auto& c : r) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (r.size() % 4) r.push_back('=');
    return b64::decode(r);
}

} // namespace

bool parse(const std::string& text, Profile& out) {
    out = {};
    out.enabled = true;
    std::string cur_block;
    Block* cur = nullptr;

    std::size_t pos = 0;
    while (pos < text.size()) {
        auto nl = text.find('\n', pos);
        std::string line = trim(text.substr(pos, nl - pos));
        pos = nl == std::string::npos ? text.size() : nl + 1;
        if (line.empty() || line[0] == '#') continue;

        auto sp = line.find(' ');
        std::string key = sp == std::string::npos ? line : line.substr(0, sp);
        std::string rest = sp == std::string::npos ? "" : trim(line.substr(sp + 1));

        if (key == "set") {
            auto eq = rest.find(' ');
            std::string k = eq == std::string::npos ? rest : trim(rest.substr(0, eq));
            std::string v = eq == std::string::npos ? "" : unquote(trim(rest.substr(eq + 1)));
            if (k == "useragent") out.user_agent = v;
            else if (k == "Host") out.host = v;
        } else if (key == "http-get") {
            cur_block = "get"; cur = &out.http_get;
        } else if (key == "http-post") {
            cur_block = "post"; cur = &out.http_post;
        } else if (cur && key == "uri") {
            cur->uri = unquote(rest);
        } else if (cur && key == "header") {
            auto sp2 = rest.find(' ');
            if (sp2 != std::string::npos) {
                cur->headers.push_back({ unquote(trim(rest.substr(0, sp2))),
                                         unquote(trim(rest.substr(sp2 + 1))) });
            }
        } else if (cur && key == "block") {
            auto sp2 = rest.find(' ');
            std::string t = sp2 == std::string::npos ? rest : trim(rest.substr(0, sp2));
            std::string v = sp2 == std::string::npos ? "" : unquote(trim(rest.substr(sp2 + 1)));
            Transform tr;
            if (t == "base64") tr.type = Transform::Base64;
            else if (t == "base64url") tr.type = Transform::Base64Url;
            else if (t == "prepend") { tr.type = Transform::Prepend; tr.value = v; }
            else if (t == "append") { tr.type = Transform::Append; tr.value = v; }
            else if (t == "header") { tr.type = Transform::Header; tr.value = v; }
            else if (t == "parameter") { tr.type = Transform::Parameter; tr.value = v; }
            else continue;
            cur->transforms.push_back(tr);
        }
    }
    return !out.http_get.uri.empty() || !out.http_post.uri.empty();
}

std::string encode_payload(const std::vector<Transform>& t, std::string_view payload,
                           std::string& out_param_name) {
    std::string r(payload);
    for (const auto& tr : t) {
        switch (tr.type) {
        case Transform::Base64: r = b64::encode(r); break;
        case Transform::Base64Url: r = b64url(r); break;
        case Transform::Prepend: r = tr.value + r; break;
        case Transform::Append: r = r + tr.value; break;
        case Transform::Parameter: out_param_name = tr.value; break;
        default: break;
        }
    }
    return r;
}

std::string decode_payload(const std::vector<Transform>& t, std::string_view data) {
    std::string r(data);
    for (auto it = t.rbegin(); it != t.rend(); ++it) {
        switch (it->type) {
        case Transform::Base64: r = b64::decode(r); break;
        case Transform::Base64Url: r = unb64url(r); break;
        case Transform::Prepend: if (r.size() >= it->value.size()) r = r.substr(it->value.size()); break;
        case Transform::Append: if (r.size() >= it->value.size()) r = r.substr(0, r.size() - it->value.size()); break;
        default: break;
        }
    }
    return r;
}

} // namespace malleable
