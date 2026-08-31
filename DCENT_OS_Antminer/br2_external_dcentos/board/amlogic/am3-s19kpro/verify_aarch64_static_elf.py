#!/usr/bin/env python3
"""Fail-closed ELF contract check for am3-s19kpro rootfs executables."""

from __future__ import annotations

import os
from pathlib import Path
import struct
import sys


ELF64_HEADER_SIZE = 64
ELF64_PROGRAM_HEADER_SIZE = 56
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
EM_AARCH64 = 183
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_INTERP = 3
PF_X = 1
PN_XNUM = 0xFFFF


class ElfContractError(ValueError):
    """The input cannot be admitted as a static AArch64 executable."""


def verify_aarch64_static_elf_blob(blob: bytes) -> None:
    """Require runnable static AArch64 ELF bytes."""

    if len(blob) < ELF64_HEADER_SIZE:
        raise ElfContractError("truncated ELF64 header")
    if blob[:4] != b"\x7fELF":
        raise ElfContractError("missing ELF magic")
    if blob[4] != ELFCLASS64:
        raise ElfContractError("ELF class is not 64-bit")
    if blob[5] != ELFDATA2LSB:
        raise ElfContractError("ELF data encoding is not little-endian")
    if blob[6] != EV_CURRENT:
        raise ElfContractError("unsupported ELF ident version")

    elf_type = struct.unpack_from("<H", blob, 16)[0]
    if elf_type not in (ET_EXEC, ET_DYN):
        raise ElfContractError(
            f"ELF e_type={elf_type}, expected ET_EXEC={ET_EXEC} or ET_DYN={ET_DYN}"
        )
    machine = struct.unpack_from("<H", blob, 18)[0]
    if machine != EM_AARCH64:
        raise ElfContractError(
            f"ELF e_machine={machine}, expected EM_AARCH64={EM_AARCH64}"
        )
    elf_version = struct.unpack_from("<I", blob, 20)[0]
    if elf_version != EV_CURRENT:
        raise ElfContractError("unsupported ELF header version")

    entry = struct.unpack_from("<Q", blob, 24)[0]
    if entry == 0:
        raise ElfContractError("ELF entry point is zero")
    phoff = struct.unpack_from("<Q", blob, 32)[0]
    ehsize = struct.unpack_from("<H", blob, 52)[0]
    phentsize = struct.unpack_from("<H", blob, 54)[0]
    phnum = struct.unpack_from("<H", blob, 56)[0]
    if ehsize != ELF64_HEADER_SIZE:
        raise ElfContractError(f"unexpected ELF64 header size {ehsize}")
    if phnum in (0, PN_XNUM):
        raise ElfContractError("missing or extended program-header table")
    if phentsize != ELF64_PROGRAM_HEADER_SIZE:
        raise ElfContractError(f"unexpected ELF64 program-header size {phentsize}")
    table_size = phentsize * phnum
    table_end = phoff + table_size
    if phoff < ELF64_HEADER_SIZE or table_end > len(blob):
        raise ElfContractError("program-header table is outside the file")

    executable_load_ranges: list[tuple[int, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type = struct.unpack_from("<I", blob, offset)[0]
        if p_type == PT_INTERP:
            raise ElfContractError(
                "PT_INTERP is present; am3-s19kpro requires a static musl executable"
            )
        if p_type != PT_LOAD:
            continue
        p_flags = struct.unpack_from("<I", blob, offset + 4)[0]
        p_offset = struct.unpack_from("<Q", blob, offset + 8)[0]
        p_vaddr = struct.unpack_from("<Q", blob, offset + 16)[0]
        p_filesz = struct.unpack_from("<Q", blob, offset + 32)[0]
        p_memsz = struct.unpack_from("<Q", blob, offset + 40)[0]
        if p_filesz > p_memsz:
            raise ElfContractError(f"PT_LOAD[{index}] file size exceeds memory size")
        if p_offset > len(blob) or p_filesz > len(blob) - p_offset:
            raise ElfContractError(f"PT_LOAD[{index}] file range is outside the file")
        if p_flags & PF_X and p_filesz:
            executable_load_ranges.append((p_vaddr, p_vaddr + p_filesz))

    if not executable_load_ranges:
        raise ElfContractError("no non-empty executable PT_LOAD segment")
    if not any(start <= entry < end for start, end in executable_load_ranges):
        raise ElfContractError(
            "ELF entry point is outside every file-backed executable PT_LOAD segment"
        )


def verify_aarch64_static_elf(path: Path) -> None:
    """Require a regular ELF64 LSB EM_AARCH64 image without PT_INTERP."""

    if path.is_symlink() or not path.is_file():
        raise ElfContractError("input must be a regular non-symlink file")
    verify_aarch64_static_elf_blob(path.read_bytes())


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(f"Usage: {argv[0]} <elf> [label]", file=sys.stderr)
        return 64
    path = Path(argv[1])
    label = argv[2] if len(argv) == 3 else os.fspath(path)
    try:
        verify_aarch64_static_elf(path)
    except (OSError, ElfContractError) as error:
        print(f"ERROR: {label}: AArch64 static ELF contract refused: {error}", file=sys.stderr)
        return 1
    print(
        f"PASS: {label}: runnable ELF64 LSB EM_AARCH64, PT_INTERP absent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
