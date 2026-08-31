from __future__ import annotations

import tempfile
from pathlib import Path
import struct
import unittest

from verify_elf import ElfContractError, inspect_elf, verify_file, write_receipt


def synthetic_elf(elf_class: int, machine: int, segment_types: list[int]) -> bytes:
    if elf_class == 32:
        ehsize, phentsize, phoff = 52, 32, 52
        header = bytearray(ehsize + phentsize * len(segment_types))
        header[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into(
            "<HHIIIIIHHHHHH",
            header,
            16,
            2,
            machine,
            1,
            1,
            phoff,
            0,
            0,
            ehsize,
            phentsize,
            len(segment_types),
            0,
            0,
            0,
        )
    elif elf_class == 64:
        ehsize, phentsize, phoff = 64, 56, 64
        header = bytearray(ehsize + phentsize * len(segment_types))
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            header,
            16,
            2,
            machine,
            1,
            1,
            phoff,
            0,
            0,
            ehsize,
            phentsize,
            len(segment_types),
            0,
            0,
            0,
        )
    else:
        raise AssertionError("unsupported synthetic class")
    for index, segment_type in enumerate(segment_types):
        struct.pack_into("<I", header, phoff + index * phentsize, segment_type)
    return bytes(header)


class InspectElfTests(unittest.TestCase):
    def test_accepts_exact_arm32_static_contract(self) -> None:
        result = inspect_elf(synthetic_elf(32, 40, [1, 4]), 32, 40)
        self.assertEqual(result["elf_machine_name"], "ARM")
        self.assertEqual(result["pt_load_count"], "1")
        self.assertEqual(result["static_contract"], "pass")

    def test_accepts_exact_aarch64_static_contract(self) -> None:
        result = inspect_elf(synthetic_elf(64, 183, [1, 1, 7]), 64, 183)
        self.assertEqual(result["elf_machine_name"], "AArch64")
        self.assertEqual(result["pt_load_count"], "2")

    def test_rejects_pt_interp(self) -> None:
        with self.assertRaisesRegex(ElfContractError, "PT_INTERP"):
            inspect_elf(synthetic_elf(32, 40, [1, 3]), 32, 40)

    def test_rejects_pt_dynamic(self) -> None:
        with self.assertRaisesRegex(ElfContractError, "PT_DYNAMIC"):
            inspect_elf(synthetic_elf(64, 183, [1, 2]), 64, 183)

    def test_rejects_wrong_class_machine_and_endianness(self) -> None:
        arm = synthetic_elf(32, 40, [1])
        with self.assertRaisesRegex(ElfContractError, "class mismatch"):
            inspect_elf(arm, 64, 183)
        wrong_machine = synthetic_elf(32, 183, [1])
        with self.assertRaisesRegex(ElfContractError, "machine mismatch"):
            inspect_elf(wrong_machine, 32, 40)
        big_endian = bytearray(arm)
        big_endian[5] = 2
        with self.assertRaisesRegex(ElfContractError, "little-endian"):
            inspect_elf(bytes(big_endian), 32, 40)

    def test_rejects_truncated_program_header_table(self) -> None:
        truncated = synthetic_elf(64, 183, [1, 1])[:-1]
        with self.assertRaisesRegex(ElfContractError, "out of bounds"):
            inspect_elf(truncated, 64, 183)

    def test_rejects_missing_load_and_wrong_entry_size(self) -> None:
        with self.assertRaisesRegex(ElfContractError, "no PT_LOAD"):
            inspect_elf(synthetic_elf(32, 40, [4, 7]), 32, 40)
        malformed = bytearray(synthetic_elf(64, 183, [1]))
        struct.pack_into("<H", malformed, 54, 55)
        with self.assertRaisesRegex(ElfContractError, "entry size mismatch"):
            inspect_elf(bytes(malformed), 64, 183)

    def test_rejects_out_of_bounds_segment_and_zero_entry(self) -> None:
        malformed = bytearray(synthetic_elf(32, 40, [1]))
        struct.pack_into("<I", malformed, 52 + 16, len(malformed) + 1)
        struct.pack_into("<I", malformed, 52 + 20, len(malformed) + 1)
        with self.assertRaisesRegex(ElfContractError, "file range is out of bounds"):
            inspect_elf(bytes(malformed), 32, 40)
        zero_entry = bytearray(synthetic_elf(64, 183, [1]))
        struct.pack_into("<Q", zero_entry, 24, 0)
        with self.assertRaisesRegex(ElfContractError, "entry point is zero"):
            inspect_elf(bytes(zero_entry), 64, 183)

    def test_file_receipt_is_exact_and_no_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = root / "fixture-aarch64-static"
            receipt = root / "fixture.elf.receipt"
            elf.write_bytes(synthetic_elf(64, 183, [1]))
            fields = verify_file(elf.absolute(), 64, 183)
            write_receipt(receipt, "fixture", fields)
            lines = receipt.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(lines), 18)
            self.assertEqual(lines[0], "schema=s19k-ptrace-host-elf-v1")
            self.assertEqual(lines[1], "label=fixture")
            self.assertIn("elf_class=64", lines)
            self.assertIn("elf_machine=183", lines)
            self.assertIn("pt_interp=absent", lines)
            self.assertIn("pt_dynamic=absent", lines)
            self.assertEqual(lines[-1], "production_authority=false")
            with self.assertRaisesRegex(ElfContractError, "already exists"):
                write_receipt(receipt, "fixture", fields)


if __name__ == "__main__":
    unittest.main()
