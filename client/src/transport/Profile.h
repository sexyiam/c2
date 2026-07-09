#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace tx {

struct Reply {
    bool ok;
    std::string body;
};

class Profile {
public:
    virtual ~Profile() = default;
    virtual bool send(std::string_view path, std::string_view body,
                        std::string_view agent_id, Reply& out) = 0;
    virtual const char* name() const = 0;
};

// First enabled profile; falls back after consecutive failures.
bool init();
Profile* active();
void report_failure();
void report_success();
std::size_t profile_count();
Profile* profile_at(std::size_t i);

} // namespace tx
