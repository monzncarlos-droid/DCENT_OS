#!/usr/bin/env python3
"""Behavioral tests for the am3-s19kpro persistent executable ABI gate."""

from __future__ import annotations

import importlib.util
import gzip
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
BOARD = PROJECT / "br2_external_dcentos" / "board" / "amlogic" / "am3-s19kpro"
CHECKER = BOARD / "verify_aarch64_static_elf.py"
CPIO_CHECKER = BOARD / "verify_rootfs_cpio_elf.py"
POST_BUILD = BOARD / "post-build.sh"
POST_IMAGE = BOARD / "post-image.sh"

SPEC = importlib.util.spec_from_file_location("s19k_elf_contract", CHECKER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def synthetic_elf64(
    *,
    elf_class: int = 2,
    data: int = 1,
    elf_type: int = 2,
    machine: int = 183,
    entry: int = 0x400000,
    program_type: int = 1,
    program_flags: int = 5,
    segment_offset: int = 120,
    segment_vaddr: int = 0x400000,
    segment_filesz: int = 4,
    segment_memsz: int = 4,
) -> bytes:
    blob = bytearray(64 + 56 + 4)
    blob[:4] = b"\x7fELF"
    blob[4] = elf_class
    blob[5] = data
    blob[6] = 1
    struct.pack_into("<H", blob, 16, elf_type)
    struct.pack_into("<H", blob, 18, machine)
    struct.pack_into("<I", blob, 20, 1)
    struct.pack_into("<Q", blob, 24, entry)
    struct.pack_into("<Q", blob, 32, 64)
    struct.pack_into("<H", blob, 52, 64)
    struct.pack_into("<H", blob, 54, 56)
    struct.pack_into("<H", blob, 56, 1)
    struct.pack_into("<I", blob, 64, program_type)
    struct.pack_into("<I", blob, 68, program_flags)
    struct.pack_into("<Q", blob, 72, segment_offset)
    struct.pack_into("<Q", blob, 80, segment_vaddr)
    struct.pack_into("<Q", blob, 96, segment_filesz)
    struct.pack_into("<Q", blob, 104, segment_memsz)
    blob[120:124] = b"\x1f\x20\x03\xd5"  # AArch64 NOP; never executed by this test.
    return bytes(blob)


def synthetic_newc(
    entries: list[tuple[str, int, bytes]], *, link_count: int = 1
) -> bytes:
    """Build the small subset of newc used by the packaged-member tests."""

    output = bytearray()

    def append(name: str, mode: int, data: bytes) -> None:
        name_bytes = name.encode("utf-8") + b"\0"
        fields = [
            1, mode, 0, 0, link_count, 0, len(data), 0, 0, 0, 0, len(name_bytes), 0
        ]
        output.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
        output.extend(name_bytes)
        output.extend(b"\0" * ((-len(output)) % 4))
        output.extend(data)
        output.extend(b"\0" * ((-len(output)) % 4))

    for name, mode, data in entries:
        append(name, mode, data)
    append("TRAILER!!!", 0, b"")
    return gzip.compress(bytes(output))


class S19kPersistentElfContractTests(unittest.TestCase):
    def check_blob(self, blob: bytes) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(blob)
            return subprocess.run(
                [sys.executable, str(CHECKER), str(path), "fixture"],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_admits_elf64_lsb_aarch64_without_interp(self) -> None:
        result = self.check_blob(synthetic_elf64())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("runnable ELF64 LSB EM_AARCH64", result.stdout)

    def test_refuses_wrong_class_endian_machine_and_interp(self) -> None:
        cases = {
            "ELF32": synthetic_elf64(elf_class=1),
            "big-endian": synthetic_elf64(data=2),
            "EM_ARM": synthetic_elf64(machine=40),
            "PT_INTERP": synthetic_elf64(program_type=3),
            "not-ELF": b"not an executable",
        }
        for label, blob in cases.items():
            with self.subTest(label=label):
                result = self.check_blob(blob)
                self.assertEqual(result.returncode, 1)
                self.assertIn("contract refused", result.stderr)

    def test_refuses_non_runnable_or_malformed_load_contracts(self) -> None:
        cases = {
            "ET_REL": synthetic_elf64(elf_type=1),
            "zero entry": synthetic_elf64(entry=0),
            "non-executable load": synthetic_elf64(program_flags=4),
            "no PT_LOAD": synthetic_elf64(program_type=4),
            "load outside file": synthetic_elf64(segment_offset=124, segment_filesz=1),
            "file size exceeds memory size": synthetic_elf64(
                segment_filesz=4, segment_memsz=3
            ),
            "entry outside executable load": synthetic_elf64(entry=0x400004),
        }
        for label, blob in cases.items():
            with self.subTest(label=label):
                result = self.check_blob(blob)
                self.assertEqual(result.returncode, 1)
                self.assertIn("contract refused", result.stderr)

    def test_refuses_symlink_and_truncated_program_header_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(MODULE.ElfContractError):
                MODULE.verify_aarch64_static_elf(root)
            target = root / "target"
            target.write_bytes(synthetic_elf64())
            link = root / "link"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(MODULE.ElfContractError):
                    MODULE.verify_aarch64_static_elf(link)

        result = self.check_blob(synthetic_elf64()[:119])
        self.assertEqual(result.returncode, 1)
        self.assertIn("program-header table is outside the file", result.stderr)

    def test_post_build_checks_source_before_copy_and_checks_staged_bytes(self) -> None:
        source = POST_BUILD.read_text(encoding="utf-8")
        init_source = source.index(
            'verify_aarch64_static_elf "$DCENTOS_INIT" "source dcentos-init"'
        )
        init_replace = source.index('rm -f "${TARGET_DIR}/sbin/init"')
        init_staged = source.index(
            'verify_aarch64_static_elf "${TARGET_DIR}/sbin/init" "staged /sbin/init"'
        )
        daemon_source = source.index(
            'verify_aarch64_static_elf "$DCENTRALD_BIN" "source dcentrald"'
        )
        daemon_copy = source.index('cp "$DCENTRALD_BIN" "$STAGED_BIN"')
        daemon_staged = source.index(
            'verify_aarch64_static_elf "$STAGED_BIN" "staged /usr/local/bin/dcentrald"'
        )
        self.assertLess(init_source, init_replace)
        self.assertLess(init_replace, init_staged)
        self.assertLess(daemon_source, daemon_copy)
        self.assertLess(daemon_copy, daemon_staged)

    def check_cpio(self, blob: bytes) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rootfs.cpio.gz"
            path.write_bytes(blob)
            return subprocess.run(
                [
                    sys.executable,
                    str(CPIO_CHECKER),
                    str(path),
                    "usr/local/bin/dcentrald",
                    "fixture",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_final_cpio_requires_one_regular_canonical_runnable_daemon(self) -> None:
        regular = 0o100755
        valid = synthetic_newc(
            [("usr/local/bin/dcentrald", regular, synthetic_elf64())]
        )
        result = self.check_cpio(valid)
        self.assertEqual(result.returncode, 0, result.stderr)

        refused = {
            "missing": synthetic_newc([]),
            "duplicate": synthetic_newc(
                [
                    ("usr/local/bin/dcentrald", regular, synthetic_elf64()),
                    ("./usr/local/bin/dcentrald", regular, synthetic_elf64()),
                ]
            ),
            "symlink": synthetic_newc(
                [("usr/local/bin/dcentrald", 0o120777, b"elsewhere")]
            ),
            "regular but not executable": synthetic_newc(
                [("usr/local/bin/dcentrald", 0o100644, synthetic_elf64())]
            ),
            "hard-link ambiguous": synthetic_newc(
                [("usr/local/bin/dcentrald", regular, synthetic_elf64())],
                link_count=2,
            ),
            "traversal": synthetic_newc(
                [("usr/local/bin/../bin/dcentrald", regular, synthetic_elf64())]
            ),
            "malformed ELF": synthetic_newc(
                [("usr/local/bin/dcentrald", regular, b"not an ELF")]
            ),
            "concatenated later archive": valid
            + synthetic_newc(
                [("usr/local/bin/dcentrald", regular, b"later replacement")]
            ),
        }
        for label, archive in refused.items():
            with self.subTest(label=label):
                result = self.check_cpio(archive)
                self.assertEqual(result.returncode, 1)
                self.assertIn("packaged ELF contract refused", result.stderr)

    def test_post_image_verifies_packaged_daemon_before_mkimage(self) -> None:
        source = POST_IMAGE.read_text(encoding="utf-8")
        checker = source.index('python3 "$PACKAGED_ELF_CHECK"')
        mkimage = source.index('"$HOST_MKIMAGE" \\\n')
        self.assertIn('"usr/local/bin/dcentrald"', source[checker:mkimage])
        self.assertIn('[ -f "${TARGET_DIR}/sbin/init" ]', source[checker:mkimage])
        self.assertIn('[ ! -L "${TARGET_DIR}/sbin/init" ]', source[checker:mkimage])
        self.assertIn('"sbin/init"', source[checker:mkimage])
        self.assertIn('"packaged optional /sbin/init"', source[checker:mkimage])
        self.assertLess(checker, mkimage)


if __name__ == "__main__":
    unittest.main()
