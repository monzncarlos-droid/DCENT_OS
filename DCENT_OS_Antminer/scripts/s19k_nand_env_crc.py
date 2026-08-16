#!/usr/bin/env python3
"""Admit a 64 KiB U-Boot env blob (ISO-HDLC CRC32 over bytes[4:]).

Host-side only. Does not write NAND. Exit 0 iff size is 65536 and CRC matches.
"""
from __future__ import annotations

import argparse
import sys

S19K_NAND_ENV_LEN = 65536
POLY = 0xEDB88320


def crc32_iso_hdlc(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            mask = (-(crc & 1)) & 0xFFFFFFFF
            crc = ((crc >> 1) ^ (POLY & mask)) & 0xFFFFFFFF
    return (~crc) & 0xFFFFFFFF


def admit_nand_env_crc(blob: bytes) -> None:
    if len(blob) != S19K_NAND_ENV_LEN:
        raise SystemExit(f"nand_env must be {S19K_NAND_ENV_LEN} bytes, got {len(blob)}")
    stored = int.from_bytes(blob[:4], "little")
    got = crc32_iso_hdlc(blob[4:])
    if stored != got:
        raise SystemExit(f"CRC32 mismatch stored=0x{stored:08X} computed=0x{got:08X}")


def emit_nandrecovery_env_fixture() -> bytes:
    body = b"recover=1\0\0"
    body = body + b"\0" * (S19K_NAND_ENV_LEN - 4 - len(body))
    crc = crc32_iso_hdlc(body)
    return crc.to_bytes(4, "little") + body


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", nargs="?", help="64 KiB nand_env or nandrecovery_env blob")
    p.add_argument(
        "--emit",
        metavar="PATH",
        help="write a CRC-valid 64 KiB nandrecovery_env fixture (no NAND write)",
    )
    args = p.parse_args(argv)
    if args.emit:
        blob = emit_nandrecovery_env_fixture()
        with open(args.emit, "wb") as fh:
            fh.write(blob)
        admit_nand_env_crc(blob)
        print("S19K_NAND_ENV_CRC_OK")
        print(f"emitted={args.emit}")
        return 0
    if not args.path:
        p.error("path is required unless --emit is set")
    with open(args.path, "rb") as fh:
        blob = fh.read()
    admit_nand_env_crc(blob)
    print("S19K_NAND_ENV_CRC_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
