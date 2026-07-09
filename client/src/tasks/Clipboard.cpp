#include "Clipboard.h"

#include <windows.h>

#include <string>

namespace clip {

std::string get_text() {
    if (!OpenClipboard(nullptr)) return "error: OpenClipboard";
    std::string out;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        auto* p = static_cast<wchar_t*>(GlobalLock(h));
        if (p) {
            int n = WideCharToMultiByte(CP_UTF8, 0, p, -1, nullptr, 0, nullptr, nullptr);
            if (n > 1) {
                out.resize(n - 1);
                WideCharToMultiByte(CP_UTF8, 0, p, -1, out.data(), n, nullptr, nullptr);
            }
            GlobalUnlock(h);
        }
    } else {
        h = GetClipboardData(CF_TEXT);
        if (h) {
            auto* p = static_cast<char*>(GlobalLock(h));
            if (p) out = p;
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    return out.empty() ? "(empty)" : out;
}

} // namespace clip
