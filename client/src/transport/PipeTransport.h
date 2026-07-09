#pragma once
#include "Profile.h"
#include <string>

namespace tx {

class PipeTransport : public Profile {
public:
    PipeTransport(std::string host, std::string pipename)
        : host_(std::move(host)), pipename_(std::move(pipename)) {}
    bool send(std::string_view path, std::string_view body, std::string_view agent_id, Reply& out) override;
    const char* name() const override { return "pipe"; }
private:
    std::string host_;
    std::string pipename_;
};

} // namespace tx
