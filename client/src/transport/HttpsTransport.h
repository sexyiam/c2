#pragma once
#include "Profile.h"
#include "Malleable.h"
#include <cstdint>
#include <string>

namespace tx {

class HttpsTransport : public Profile {
public:
    HttpsTransport(std::string host, std::uint16_t port, bool ignore_cert,
                   const malleable::Profile& mp, bool use_tls = true)
        : host_(std::move(host)), port_(port), ignore_cert_(ignore_cert),
          use_tls_(use_tls), mp_(mp) {}
    bool send(std::string_view path, std::string_view body, std::string_view agent_id, Reply& out) override;
    const char* name() const override { return use_tls_ ? "https" : "http"; }
private:
    std::string host_;
    std::uint16_t port_;
    bool ignore_cert_;
    bool use_tls_;
    malleable::Profile mp_;
};

} // namespace tx
