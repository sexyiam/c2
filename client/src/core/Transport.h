#pragma once
#include <string>
#include <string_view>
#include <unordered_map>

namespace transport {

struct Response {
    int status;
    std::string body;
    bool ok;
};

// use_tls => WINHTTP_FLAG_SECURE; false => plain HTTP.
Response https_post(std::string_view host, std::uint16_t port,
                    std::string_view path, std::string_view body,
                    const std::unordered_map<std::string, std::string>& headers,
                    bool ignore_cert_errors, bool use_tls = true);

Response https_get(std::string_view url, bool ignore_cert_errors);

} // namespace transport
