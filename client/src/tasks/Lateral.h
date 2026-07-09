#pragma once
#include <string>
#include <string_view>

namespace lateral {

std::string smb_check(std::string_view target, std::string_view share);
std::string wmi_exec(std::string_view target, std::string_view command);
std::string dcom_trigger(std::string_view target);

} // namespace lateral
