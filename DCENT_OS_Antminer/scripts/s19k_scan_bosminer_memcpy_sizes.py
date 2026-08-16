#!/usr/bin/env python3
"""Hunt AArch64 MOVZ immediates used as likely memcpy/slice lengths in bosminer.

Ghidra-free complement to packed_struct pack() hunting. Looks for
MOVZ Wd,#N where N is a job-frame size (54/82/84/86/88), then a nearby
BL (call) within 48 bytes. Prints VA candidates. Does not close T1.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

# AArch64 MOVZ Wd, #imm16  = 0x52800000 | (imm << 5) | rd
# BL imm26 (from here)

SIZES = {
    0x36: "len_field_or_54",
    0x52: "82_esp_payload",
    0x54: "84_crc_cover",
    0x56: "86_body",
    0x58: "88_wire",
}


def movz_wd(imm: int, rd: int) -> bytes:
    return struct.pack("<I", 0x52800000 | ((imm & 0xFFFF) << 5) | (rd & 0x1F))


def is_bl(word: int) -> bool:
    return (word & 0xFC000000) == 0x94000000


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    args = ap.parse_args()
    data = args.elf.read_bytes()
    print(f"FILE {args.elf} BYTES {len(data)}")
    for imm, name in SIZES.items():
        hits = 0
        bl_near = 0
        for rd in range(32):
            pat = movz_wd(imm, rd)
            start = 0
            while True:
                off = data.find(pat, start)
                if off < 0:
                    break
                hits += 1
                window = data[off : off + 48]
                words = [
                    struct.unpack_from("<I", window, i)[0]
                    for i in range(0, len(window) - 3, 4)
                ]
                if any(is_bl(w) for w in words[1:]):
                    bl_near += 1
                    if bl_near <= 8:
                        print(f"CAND file=0x{off:X} va_guess=file_off MOVZ_W{rd},#{imm:#x} ({name}) +BL")
                start = off + 4
        print(f"COUNT imm={imm:#x} ({name}) movz={hits} movz_then_bl48={bl_near}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
