#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace malleable {

struct Transform {
    enum Type { Base64, Base64Url, Prepend, Append, Header, Parameter };
    Type type;
    std::string value;
};

struct Block {
    std::string uri;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<Transform> transforms;
};

struct Profile {
    std::string name;
    Block http_get;
    Block http_post;
    std::string user_agent;
    std::string host; // for domain fronting
    bool enabled;
};

bool parse(const std::string& text, Profile& out);

std::string encode_payload(const std::vector<Transform>& t, std::string_view payload,
                           std::string& out_param_name);
std::string decode_payload(const std::vector<Transform>& t, std::string_view data);

} // namespace malleable
