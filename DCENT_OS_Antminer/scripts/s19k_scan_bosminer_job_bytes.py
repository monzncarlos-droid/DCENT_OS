#!/usr/bin/env python3
"""Byte-scan Braiins bosminer.unpacked for BM1366 job-frame literals.

ELF has NULs — do not use ripgrep. Prints offsets + context. Clean-room:
offsets and hex only, no decompilation.

Default input:
  
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

DEFAULT_REL = Path(
    ""
)

PATTERNS = {
    "55AA2136": bytes.fromhex("55AA2136"),
    "55AA2156": bytes.fromhex("55AA2156"),
    "2136": bytes.fromhex("2136"),
    "2156": bytes.fromhex("2156"),
}

# AArch64 MOV (wide immediate), Rd in bits 4:0 of first byte.
# movz Wd, #imm16  =>  0x52800000 | (imm16 << 5) | Rd
def movz_w(imm: int) -> list[bytes]:
    hits = []
    for rd in range(8):  # w0..w7 are the interesting ones
        word = 0x52800000 | ((imm & 0xFFFF) << 5) | rd
        hits.append(word.to_bytes(4, "little"))
    return hits


def find_all(blob: bytes, pat: bytes, limit: int = 64) -> list[int]:
    out = []
    start = 0
    while len(out) < limit:
        i = blob.find(pat, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def ctx(blob: bytes, off: int, n: int = 32) -> str:
    a = max(0, off - n)
    b = min(len(blob), off + len(blob[off : off + 4]) + n)
    return blob[a:b].hex(" ")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="?", default=None)
    args = p.parse_args()

    path = Path(args.path) if args.path else None
    if path is None:
        # Walk up from cwd / this file to repo root.
        here = Path(__file__).resolve()
        for root in [Path.cwd(), *here.parents]:
            cand = root / DEFAULT_REL
            if cand.is_file():
                path = cand
                break
    if path is None or not path.is_file():
        print("ERROR: bosminer.unpacked not found", file=sys.stderr)
        return 2

    blob = path.read_bytes()
    print(f"FILE {path}")
    print(f"SIZE {len(blob)}")

    for name, pat in PATTERNS.items():
        offs = find_all(blob, pat)
        print(f"PATTERN {name} hits={len(offs)}")
        for off in offs[:16]:
            print(f"  @{off:#x} ctx={ctx(blob, off)}")

    for imm, label in ((0x21, "movz_w_0x21"), (0x36, "movz_w_0x36"), (0x56, "movz_w_0x56")):
        total = 0
        near_pair = 0
        for enc in movz_w(imm):
            offs = find_all(blob, enc, limit=200)
            total += len(offs)
        print(f"IMM {label} encodings_w0..w7 hits={total} (common; not a template)")

    # Proximity: 0x21-immediate within 32 bytes of 0x36 or 0x56 immediate.
    enc21 = b"".join([])  # unused
    mov21 = movz_w(0x21)
    mov36 = movz_w(0x36)
    mov56 = movz_w(0x56)
    offs21 = []
    for e in mov21:
        offs21.extend(find_all(blob, e, limit=400))
    offs36 = []
    for e in mov36:
        offs36.extend(find_all(blob, e, limit=400))
    offs56 = []
    for e in mov56:
        offs56.extend(find_all(blob, e, limit=400))
    pair36 = 0
    pair56 = 0
    for a in offs21:
        if any(abs(a - b) <= 32 for b in offs36):
            pair36 += 1
        if any(abs(a - b) <= 32 for b in offs56):
            pair56 += 1
    print(f"PROXIMITY mov#0x21 within 32B of mov#0x36: {pair36}")
    print(f"PROXIMITY mov#0x21 within 32B of mov#0x56: {pair56}")

    # AArch64 CMP Wn, #imm12 (SUBS Wd=xzr). Ghidra-free size-check hunt.
    def cmp_w_imm(imm: int) -> list[bytes]:
        encs = []
        for rn in range(32):
            word = 0x7100001F | ((imm & 0xFFF) << 10) | (rn << 5)
            encs.append(word.to_bytes(4, "little"))
        return encs

    for imm, label in (
        (0x36, "cmp_w_0x36"),
        (0x56, "cmp_w_0x56"),
        (0x58, "cmp_w_0x58"),
        (0x54, "cmp_w_0x54"),
        (88, "cmp_w_88"),
    ):
        total = 0
        for enc in cmp_w_imm(imm):
            total += blob.count(enc)
        print(f"CMP {label} hits={total}")

    for imm, label in ((0x54, "movz_w_0x54"), (0x58, "movz_w_0x58"), (88, "movz_w_88")):
        total = 0
        for enc in movz_w(imm):
            total += blob.count(enc)
        print(f"IMM {label} encodings_w0..w7 hits={total}")

    needles = [
        b"Midstates work type",
        b"Unexpected size",
        b"Failed to send work",
        b"FRAME_BUFFER",
        b"bm1398_6x",
        b"antminer_aml",
        b"bad CRC",
        b"/dev/ttyS",
        b"/dev/uart_trans",
        b"packed_struct",
    ]
    for n in needles:
        offs = find_all(blob, n)
        print(f"STRING {n!r} hits={len(offs)} first={[hex(x) for x in offs[:4]]}")

    print(
        "BM136X packed_struct-0.10.1 @ 0xf256e0 adjacent to "
        "bosminer-antminer/src/bm136x.rs (not a length-field literal)"
    )
    print(
        "Unexpected size @ 0xf25468 is bm1398_6x.rs FPGA midstate path, not bm136x"
    )
    print(
        "Wave-13: see s19k_scan_bosminer_pack_body.py — "
        "all-reg MOVZ+STRB 21+36 candidates=0 (0xEDE73C is ASCII '6')"
    )
    print("T1_LENGTH_FIELD not closed as fact (Ghidra Docker down this wave)")
    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
