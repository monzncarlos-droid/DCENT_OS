#!/usr/bin/env python3
"""Byte-scan the held S19k BM1366 jig for job-length immediates.

Does not close Braiins on-wire identity. Prints offsets + context only.
"""
from __future__ import annotations

from pathlib import Path

DEFAULT = Path(
    ""
)


def find_all(blob: bytes, pat: bytes, limit: int = 32) -> list[int]:
    out: list[int] = []
    start = 0
    while len(out) < limit:
        i = blob.find(pat, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def main() -> int:
    here = Path(__file__).resolve()
    path = None
    for root in [Path.cwd(), *here.parents]:
        cand = root / DEFAULT
        if cand.is_file():
            path = cand
            break
    if path is None:
        print("ERROR: jig binary not found")
        return 2
    blob = path.read_bytes()
    print(f"FILE {path}")
    print(f"SIZE {len(blob)}")
    print(f"ELF class={blob[4]} machine={int.from_bytes(blob[18:20], 'little')}")
    pats = {
        "55AA2136": bytes.fromhex("55AA2136"),
        "55AA2156": bytes.fromhex("55AA2156"),
        "55AA5205": bytes.fromhex("55AA5205"),
        "55AA5305": bytes.fromhex("55AA5305"),
        "2136": bytes.fromhex("2136"),
        "2156": bytes.fromhex("2156"),
        "3621": bytes.fromhex("3621"),
        "5621": bytes.fromhex("5621"),
    }
    for name, pat in pats.items():
        offs = find_all(blob, pat)
        print(f"PATTERN {name} hits={blob.count(pat)} shown={len(offs)}")
        for off in offs[:8]:
            a = max(0, off - 12)
            e = min(len(blob), off + 16)
            print(f"  {off:08X} {blob[a:e].hex(' ')}")
    for s in (b"crc5", b"CRC5", b"BM1366", b"job"):
        print(f"STR {s!r} first={blob.find(s)} cnt={blob.count(s)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
