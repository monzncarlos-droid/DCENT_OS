#!/usr/bin/env python3
"""Strict stdlib-only ELF contract verifier for the S19k ptrace KAT."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
from typing import Final


SCHEMA: Final = "s19k-ptrace-host-elf-v1"
PT_LOAD: Final = 1
PT_DYNAMIC: Final = 2
PT_INTERP: Final = 3
ELF_CLASSES: Final = {32: (1, 52, 32), 64: (2, 64, 56)}
MACHINES: Final = {40: "ARM", 183: "AArch64"}


class ElfContractError(ValueError):
    """The input does not satisfy the exact static ELF contract."""


def _u16(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as error:
        raise ElfContractError(f"truncated ELF u16 at offset {offset}") from error


def _u32(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as error:
        raise ElfContractError(f"truncated ELF u32 at offset {offset}") from error


def _u64(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<Q", data, offset)[0]
    except struct.error as error:
        raise ElfContractError(f"truncated ELF u64 at offset {offset}") from error


def inspect_elf(
    data: bytes, expected_class: int, expected_machine: int
) -> dict[str, str]:
    if expected_class not in ELF_CLASSES:
        raise ElfContractError(f"unsupported expected ELF class: {expected_class}")
    if expected_machine not in MACHINES:
        raise ElfContractError(f"unsupported expected ELF machine: {expected_machine}")
    if (expected_class, expected_machine) not in {(32, 40), (64, 183)}:
        raise ElfContractError(
            "unsupported ELF class/machine pair: "
            f"class={expected_class} machine={expected_machine}"
        )

    class_byte, expected_ehsize, expected_phentsize = ELF_CLASSES[expected_class]
    if len(data) < expected_ehsize:
        raise ElfContractError("ELF header is truncated")
    if data[:4] != b"\x7fELF":
        raise ElfContractError("ELF magic mismatch")
    if data[4] != class_byte:
        raise ElfContractError(
            f"ELF class mismatch: expected {expected_class}, byte={data[4]}"
        )
    if data[5] != 1:
        raise ElfContractError("ELF is not little-endian")
    if data[6] != 1:
        raise ElfContractError("ELF ident version is not 1")
    if _u32(data, 20) != 1:
        raise ElfContractError("ELF header version is not 1")

    machine = _u16(data, 18)
    if machine != expected_machine:
        raise ElfContractError(
            f"ELF machine mismatch: expected {expected_machine}, actual {machine}"
        )
    elf_type = _u16(data, 16)
    if elf_type not in {2, 3}:
        raise ElfContractError(f"ELF is not executable/shared-object type: {elf_type}")

    if expected_class == 32:
        entry = _u32(data, 24)
        phoff = _u32(data, 28)
        ehsize = _u16(data, 40)
        phentsize = _u16(data, 42)
        phnum = _u16(data, 44)
    else:
        entry = _u64(data, 24)
        phoff = _u64(data, 32)
        ehsize = _u16(data, 52)
        phentsize = _u16(data, 54)
        phnum = _u16(data, 56)
    if entry == 0:
        raise ElfContractError("ELF entry point is zero")

    if ehsize != expected_ehsize:
        raise ElfContractError(
            f"ELF header size mismatch: expected {expected_ehsize}, actual {ehsize}"
        )
    if phentsize != expected_phentsize:
        raise ElfContractError(
            "ELF program-header entry size mismatch: "
            f"expected {expected_phentsize}, actual {phentsize}"
        )
    if phnum == 0 or phnum == 0xFFFF:
        raise ElfContractError("ELF program-header count is zero or extended")
    if phoff < ehsize:
        raise ElfContractError("ELF program-header table overlaps its header")

    table_size = phentsize * phnum
    table_end = phoff + table_size
    if table_end < phoff or table_end > len(data):
        raise ElfContractError("ELF program-header table is out of bounds")

    load_count = 0
    for index in range(phnum):
        offset = phoff + index * phentsize
        kind = _u32(data, offset)
        if expected_class == 32:
            file_offset = _u32(data, offset + 4)
            file_size = _u32(data, offset + 16)
            memory_size = _u32(data, offset + 20)
        else:
            file_offset = _u64(data, offset + 8)
            file_size = _u64(data, offset + 32)
            memory_size = _u64(data, offset + 40)
        file_end = file_offset + file_size
        if file_end < file_offset or file_end > len(data):
            raise ElfContractError(f"ELF segment {index} file range is out of bounds")
        if kind == PT_LOAD:
            if memory_size < file_size:
                raise ElfContractError(f"ELF PT_LOAD {index} has memsz below filesz")
            load_count += 1
        elif kind == PT_DYNAMIC:
            raise ElfContractError(f"ELF contains PT_DYNAMIC at index {index}")
        elif kind == PT_INTERP:
            raise ElfContractError(f"ELF contains PT_INTERP at index {index}")
    if load_count == 0:
        raise ElfContractError("ELF has no PT_LOAD segment")

    return {
        "elf_class": str(expected_class),
        "elf_data": "little-endian",
        "elf_machine": str(machine),
        "elf_machine_name": MACHINES[machine],
        "elf_type": str(elf_type),
        "entry_point": "nonzero",
        "elf_header_bytes": str(ehsize),
        "program_header_bytes": str(phentsize),
        "program_header_count": str(phnum),
        "pt_load_count": str(load_count),
        "pt_interp": "absent",
        "pt_dynamic": "absent",
        "static_contract": "pass",
    }


def verify_file(
    path: Path, expected_class: int, expected_machine: int
) -> dict[str, str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ElfContractError("ELF path must be a regular non-symlink file")
    if path.resolve(strict=True) != path.absolute():
        raise ElfContractError("ELF path is not canonical")
    data = path.read_bytes()
    fields = inspect_elf(data, expected_class, expected_machine)
    fields["bytes"] = str(len(data))
    fields["sha256"] = hashlib.sha256(data).hexdigest()
    return fields


def write_receipt(path: Path, label: str, fields: dict[str, str]) -> None:
    if not label or not label.replace("-", "").isalnum() or not label.isascii():
        raise ElfContractError("label must be nonempty ASCII alphanumeric/hyphen")
    if path.is_symlink() or path.exists():
        raise ElfContractError("receipt path already exists")
    lines = [
        f"schema={SCHEMA}",
        f"label={label}",
        f"sha256={fields['sha256']}",
        f"bytes={fields['bytes']}",
        f"elf_class={fields['elf_class']}",
        f"elf_data={fields['elf_data']}",
        f"elf_machine={fields['elf_machine']}",
        f"elf_machine_name={fields['elf_machine_name']}",
        f"elf_type={fields['elf_type']}",
        f"entry_point={fields['entry_point']}",
        f"elf_header_bytes={fields['elf_header_bytes']}",
        f"program_header_bytes={fields['program_header_bytes']}",
        f"program_header_count={fields['program_header_count']}",
        f"pt_load_count={fields['pt_load_count']}",
        f"pt_interp={fields['pt_interp']}",
        f"pt_dynamic={fields['pt_dynamic']}",
        f"static_contract={fields['static_contract']}",
        "production_authority=false",
    ]
    with path.open("x", encoding="ascii", newline="\n") as receipt:
        receipt.write("\n".join(lines) + "\n")
        receipt.flush()
        os.fsync(receipt.fileno())
    path.chmod(0o400)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument(
        "--elf-class", required=True, type=int, choices=sorted(ELF_CLASSES)
    )
    parser.add_argument("--machine", required=True, type=int, choices=sorted(MACHINES))
    parser.add_argument("--label", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    fields = verify_file(args.path, args.elf_class, args.machine)
    write_receipt(args.receipt, args.label, fields)
    print(f"ELF PASS: {args.receipt}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ElfContractError, OSError) as error:
        raise SystemExit(f"ELF verification refused: {error}") from error
