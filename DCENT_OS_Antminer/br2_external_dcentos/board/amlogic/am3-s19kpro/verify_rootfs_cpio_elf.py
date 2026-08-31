#!/usr/bin/env python3
"""Verify one executable member in the final gzip/newc rootfs payload."""

from __future__ import annotations

import gzip
from pathlib import Path, PurePosixPath
import stat
import sys

from verify_aarch64_static_elf import (
    ElfContractError,
    verify_aarch64_static_elf_blob,
)


NEWC_HEADER_SIZE = 110
NEWC_MAGICS = (b"070701", b"070702")


class CpioContractError(ValueError):
    """The archive cannot prove one canonical regular executable member."""


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _canonical_member_name(raw_name: str) -> str:
    while raw_name.startswith("./"):
        raw_name = raw_name[2:]
    path = PurePosixPath(raw_name)
    if (
        not raw_name
        or path.is_absolute()
        or "\\" in raw_name
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise CpioContractError(f"non-canonical archive member name {raw_name!r}")
    return path.as_posix()


def read_exact_newc_member(archive: Path, expected_member: str) -> bytes:
    """Return exactly one canonical regular newc member from a gzip archive."""

    if archive.is_symlink() or not archive.is_file():
        raise CpioContractError("rootfs archive must be a regular non-symlink file")
    expected_member = _canonical_member_name(expected_member)
    try:
        blob = gzip.decompress(archive.read_bytes())
    except (OSError, EOFError) as error:
        raise CpioContractError(f"invalid gzip rootfs: {error}") from error

    offset = 0
    matches: list[bytes] = []
    saw_trailer = False
    while offset < len(blob):
        if blob[offset:].strip(b"\0") == b"":
            break
        if len(blob) - offset < NEWC_HEADER_SIZE:
            raise CpioContractError("truncated newc header")
        header = blob[offset : offset + NEWC_HEADER_SIZE]
        magic = header[:6]
        if magic not in NEWC_MAGICS:
            raise CpioContractError(f"unsupported cpio magic {magic!r}")
        try:
            fields = [
                int(header[index : index + 8], 16)
                for index in range(6, NEWC_HEADER_SIZE, 8)
            ]
        except ValueError as error:
            raise CpioContractError("newc header contains non-hex fields") from error
        mode = fields[1]
        link_count = fields[4]
        file_size = fields[6]
        name_size = fields[11]
        checksum = fields[12]
        if name_size < 2:
            raise CpioContractError("newc member name is empty")

        name_start = offset + NEWC_HEADER_SIZE
        name_end = name_start + name_size
        if name_end > len(blob) or blob[name_end - 1] != 0:
            raise CpioContractError("truncated or unterminated newc member name")
        try:
            raw_name = blob[name_start : name_end - 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise CpioContractError("newc member name is not UTF-8") from error
        data_start = _align4(name_end)
        data_end = data_start + file_size
        if data_end > len(blob):
            raise CpioContractError(f"newc member {raw_name!r} extends beyond archive")
        data = blob[data_start:data_end]
        offset = _align4(data_end)

        if raw_name == "TRAILER!!!":
            if file_size != 0:
                raise CpioContractError("newc trailer unexpectedly has data")
            saw_trailer = True
            break
        canonical = _canonical_member_name(raw_name)
        if magic == b"070702" and sum(data) & 0xFFFFFFFF != checksum:
            raise CpioContractError(f"newc CRC mismatch for {canonical!r}")
        if canonical == expected_member:
            if stat.S_IFMT(mode) != stat.S_IFREG:
                raise CpioContractError(
                    f"required member {expected_member!r} is not a regular file"
                )
            if mode & 0o111 == 0:
                raise CpioContractError(
                    f"required member {expected_member!r} has no executable mode bit"
                )
            if link_count != 1:
                raise CpioContractError(
                    f"required member {expected_member!r} is hard-link ambiguous"
                )
            matches.append(data)

    if not saw_trailer:
        raise CpioContractError("newc archive has no TRAILER!!! record")
    if blob[offset:].strip(b"\0"):
        raise CpioContractError(
            "non-padding data follows the newc trailer (concatenated archive refused)"
        )
    if len(matches) != 1:
        raise CpioContractError(
            f"required member {expected_member!r} occurs {len(matches)} times, expected 1"
        )
    return matches[0]


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print(f"Usage: {argv[0]} <rootfs.cpio.gz> <member> [label]", file=sys.stderr)
        return 64
    archive = Path(argv[1])
    member = argv[2]
    label = argv[3] if len(argv) == 4 else member
    try:
        executable = read_exact_newc_member(archive, member)
        verify_aarch64_static_elf_blob(executable)
    except (OSError, CpioContractError, ElfContractError) as error:
        print(f"ERROR: {label}: packaged ELF contract refused: {error}", file=sys.stderr)
        return 1
    print(
        f"PASS: {label}: exactly one regular runnable ELF64 LSB EM_AARCH64 member, PT_INTERP absent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
