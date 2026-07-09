#include "Screenshot.h"
#include "core/Base64.h"

#include <windows.h>

#include <cstring>
#include <vector>

namespace shot {

std::string capture() {
    HDC dc = GetDC(nullptr);
    if (!dc) return "error: GetDC";
    int w = GetDeviceCaps(dc, HORZRES);
    int h = GetDeviceCaps(dc, VERTRES);

    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, w, h);
    if (!bmp) { DeleteDC(mem); ReleaseDC(nullptr, dc); return "error: bitmap"; }
    SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, dc, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    DWORD row = ((w * 3 + 3) & ~3);
    std::vector<std::uint8_t> bits(row * h);
    GetDIBits(mem, bmp, 0, h, bits.data(), reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);

    BITMAPFILEHEADER fh{};
    fh.bfType = 'MB';
    fh.bfOffBits = sizeof(fh) + sizeof(bi);
    fh.bfSize = fh.bfOffBits + static_cast<DWORD>(bits.size());
    std::vector<std::uint8_t> out(sizeof(fh) + sizeof(bi) + bits.size());
    std::memcpy(out.data(), &fh, sizeof(fh));
    std::memcpy(out.data() + sizeof(fh), &bi, sizeof(bi));
    std::memcpy(out.data() + sizeof(fh) + sizeof(bi), bits.data(), bits.size());

    DeleteObject(bmp); DeleteDC(mem); ReleaseDC(nullptr, dc);
    return b64::encode(out.data(), out.size());
}

} // namespace shot
