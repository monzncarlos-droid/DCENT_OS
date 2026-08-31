#!/usr/bin/env python3
"""Host-only tests for the K210 safe-idle candidate build boundary."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import build_k210_candidate as builder  # noqa: E402


def synthetic_elf(
    *, entry: int = builder.K210_ROM_LOAD_BASE, machine: int = 243
) -> bytes:
    data = bytearray(64 + 56 + 8)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHI", data, 16, 2, machine, 1)
    struct.pack_into("<QQQ", data, 24, entry, 64, 0)
    struct.pack_into("<HHHHHH", data, 52, 64, 56, 1, 0, 0, 0)
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        builder.ELF_PT_LOAD,
        5,
        120,
        builder.K210_ROM_LOAD_BASE,
        builder.K210_ROM_LOAD_BASE,
        8,
        8,
        8,
    )
    data[120:128] = b"sentinel"
    return bytes(data)


class K210CandidateBuildTests(unittest.TestCase):
    def test_accepts_expected_riscv_load_contract(self) -> None:
        observed = builder.inspect_k210_elf(synthetic_elf())
        self.assertEqual(observed["entry"], "0x0000000080000000")
        self.assertEqual(observed["machine"], "RISC-V")
        self.assertEqual(len(observed["load_segments"]), 1)

    def test_rejects_wrong_entry(self) -> None:
        with self.assertRaisesRegex(builder.BuildError, "ELF entry"):
            builder.inspect_k210_elf(synthetic_elf(entry=0x8000_1000))

    def test_rejects_wrong_machine(self) -> None:
        with self.assertRaisesRegex(builder.BuildError, "ELF machine"):
            builder.inspect_k210_elf(synthetic_elf(machine=62))

    def test_rejects_load_outside_cached_ram_contract(self) -> None:
        corrupt = bytearray(synthetic_elf())
        address = builder.K210_ROM_LOAD_BASE + builder.K210_CACHED_RAM_BYTES
        struct.pack_into("<Q", corrupt, 64 + 16, address)
        struct.pack_into("<Q", corrupt, 64 + 24, address)
        with self.assertRaisesRegex(builder.BuildError, "cached-RAM contract"):
            builder.inspect_k210_elf(bytes(corrupt))

    def test_rejects_truncated_load_segment(self) -> None:
        corrupt = bytearray(synthetic_elf())
        struct.pack_into("<Q", corrupt, 64 + 32, 64)
        struct.pack_into("<Q", corrupt, 64 + 40, 64)
        with self.assertRaisesRegex(builder.BuildError, "exceeds the file"):
            builder.inspect_k210_elf(bytes(corrupt))

    def test_cli_requires_explicit_aes0_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate"
            code = builder.main(
                [
                    "--model",
                    "a1346",
                    "--firmware-version",
                    "20260823_dcent_test",
                    "--out-dir",
                    str(output),
                ]
            )
            self.assertEqual(code, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
