#pragma once
#include <string>
#include <vector>

namespace runner {

// true => EXIT (self-terminate)
bool dispatch(std::string_view agent_id, const std::string& cmd,
              const std::vector<std::string>& args, std::string& result,
              std::uint32_t& interval, std::uint8_t key[32]);

} // namespace runner
