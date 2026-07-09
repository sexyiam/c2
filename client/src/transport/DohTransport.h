#pragma once
#include "Profile.h"
#include <string>

namespace tx {

class DohTransport : public Profile {
public:
    DohTransport(std::string resolver, std::string type, bool ignore_cert)
        : resolver_(std::move(resolver)), type_(std::move(type)), ignore_cert_(ignore_cert) {}
    bool send(std::string_view path, std::string_view body, std::string_view agent_id, Reply& out) override;
    const char* name() const override { return "doh"; }
private:
    std::string resolver_;
    std::string type_;
    bool ignore_cert_;
};

} // namespace tx
