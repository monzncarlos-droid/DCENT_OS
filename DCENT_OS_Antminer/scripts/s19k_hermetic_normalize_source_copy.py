#!/usr/bin/env python3
"""Normalize and re-admit one private mutable copy of a sealed source tree."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import NoReturn, Sequence


class NormalizeError(RuntimeError):
    """The sealed-to-mutable source mapping was not exact."""


def fail(message: str) -> NoReturn:
    raise NormalizeError(message)


def _path(value: Path) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _regular_digest(path: Path) -> tuple[str, int]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        fail(f"expected regular file changed type: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            fail(f"regular file changed before open: {path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or size != opened.st_size:
            fail(f"regular file changed during read: {path}")
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _excluded(relative: str, exclusions: frozenset[str]) -> bool:
    return any(relative == item or relative.startswith(item + "/") for item in exclusions)


def normalize_source_copy(
    sealed_root: Path, mutable_root: Path, *, excluded: Sequence[str] = ()
) -> dict[str, int]:
    """Map 0500/0444|0555 sealed modes to private 0700/0600|0700 modes."""

    source = _path(sealed_root)
    destination = _path(mutable_root)
    for path, label in ((source, "sealed source"), (destination, "mutable copy")):
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} is not a direct directory")
    if os.path.samefile(source, destination):
        fail("sealed source and mutable copy must be distinct")
    exclusions: frozenset[str] = frozenset(
        PurePosixPath(item).as_posix().strip("/") for item in excluded
    )
    if "" in exclusions or any(
        item in (".", "..") or ".." in PurePosixPath(item).parts for item in exclusions
    ):
        fail("excluded source path is noncanonical")

    observed: dict[str, tuple[str, str | None]] = {}

    def visit(relative: PurePosixPath) -> None:
        current = destination.joinpath(*relative.parts) if relative.parts else destination
        source_current = source.joinpath(*relative.parts) if relative.parts else source
        if relative.parts:
            source_mode = stat.S_IMODE(source_current.lstat().st_mode)
            if source_mode != 0o500:
                fail(f"sealed source directory mode is not 0500: {relative.as_posix()}")
            os.chmod(current, 0o700, follow_symlinks=False)
            if stat.S_IMODE(current.lstat().st_mode) != 0o700:
                fail(f"mutable source directory mode did not normalize: {relative.as_posix()}")
            observed[relative.as_posix()] = ("directory", None)
        with os.scandir(current) as iterator:
            entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            child_relative = relative / entry.name
            child_name = child_relative.as_posix()
            target = Path(entry.path)
            counterpart = source.joinpath(*child_relative.parts)
            target_meta = target.lstat()
            source_meta = counterpart.lstat()
            if stat.S_ISDIR(target_meta.st_mode) and not stat.S_ISLNK(target_meta.st_mode):
                if not stat.S_ISDIR(source_meta.st_mode) or stat.S_ISLNK(source_meta.st_mode):
                    fail(f"mutable directory differs from sealed source: {child_name}")
                visit(child_relative)
            elif stat.S_ISREG(target_meta.st_mode) and not stat.S_ISLNK(target_meta.st_mode):
                if not stat.S_ISREG(source_meta.st_mode) or stat.S_ISLNK(source_meta.st_mode):
                    fail(f"mutable regular file differs from sealed source: {child_name}")
                source_mode = stat.S_IMODE(source_meta.st_mode)
                if source_mode not in (0o444, 0o555):
                    fail(f"sealed regular mode is not admitted: {child_name}")
                if _regular_digest(target) != _regular_digest(counterpart):
                    fail(f"mutable regular bytes differ from sealed source: {child_name}")
                expected_mode = 0o700 if source_mode == 0o555 else 0o600
                os.chmod(target, expected_mode, follow_symlinks=False)
                if stat.S_IMODE(target.lstat().st_mode) != expected_mode:
                    fail(f"mutable regular mode did not normalize: {child_name}")
                observed[child_name] = ("regular", None)
            elif stat.S_ISLNK(target_meta.st_mode):
                if not stat.S_ISLNK(source_meta.st_mode):
                    fail(f"mutable symlink differs from sealed source: {child_name}")
                target_link = os.readlink(target)
                source_link = os.readlink(counterpart)
                if target_link != source_link:
                    fail(f"mutable symlink target differs from sealed source: {child_name}")
                observed[child_name] = ("symlink", target_link)
            else:
                fail(f"mutable source contains unsupported file type: {child_name}")

    os.chmod(destination, 0o700, follow_symlinks=False)
    visit(PurePosixPath())

    expected: dict[str, tuple[str, str | None]] = {}
    for current, directories, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative_root = current_path.relative_to(source)
        directories.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        for name in list(directories):
            relative = (PurePosixPath(relative_root.as_posix()) / name).as_posix()
            if _excluded(relative, exclusions):
                directories.remove(name)
                continue
            path = current_path / name
            if path.is_symlink():
                expected[relative] = ("symlink", os.readlink(path))
                directories.remove(name)
            else:
                expected[relative] = ("directory", None)
        for name in files:
            relative = (PurePosixPath(relative_root.as_posix()) / name).as_posix()
            if _excluded(relative, exclusions):
                continue
            path = current_path / name
            expected[relative] = (
                ("symlink", os.readlink(path))
                if path.is_symlink()
                else ("regular", None)
            )
    if observed != expected:
        fail("mutable source exact entry/type/link ledger differs from sealed source")
    counts = {
        "directories": sum(kind == "directory" for kind, _ in observed.values()),
        "regular_files": sum(kind == "regular" for kind, _ in observed.values()),
        "symlinks": sum(kind == "symlink" for kind, _ in observed.values()),
    }
    return counts


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("sealed_root", type=Path)
    result.add_argument("mutable_root", type=Path)
    result.add_argument("--exclude", action="append", default=[])
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        counts = normalize_source_copy(
            args.sealed_root, args.mutable_root, excluded=args.exclude
        )
        print(
            "S19K_MUTABLE_SOURCE_NORMALIZED "
            + " ".join(f"{name}={value}" for name, value in sorted(counts.items()))
        )
        return 0
    except (NormalizeError, OSError, ValueError) as error:
        print(f"S19K_MUTABLE_SOURCE_REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
