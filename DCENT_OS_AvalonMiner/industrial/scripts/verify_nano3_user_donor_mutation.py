#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Verify a local Nano 3 rootfs-only mutation against an owned donor.

This verifier is offline and non-authorizing.  It proves that a KDIMG writes
exactly rootfs B/A geometry, that both padded streams differ from the exact
pinned donor slots, and that persistent data is absent.  It does not inspect
the rebuilt filesystems; run ``verify_nano3_coexistence_image.sh`` inside the
K230 build container for that independent content/metadata check.  The KDIMG
contains factory-derived rootfs bytes and is not a redistributable artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Optional


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
TOOLBOX_SRC = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
sys.path.insert(0, str(TOOLBOX_SRC))

from dcent_toolbox.core.k230_image_build import NAND_ERASE_BLOCK  # noqa: E402
from dcent_toolbox.core.k230_release_manifest import (  # noqa: E402
    K230_RELEASE_PROFILES,
)
from dcent_toolbox.core.kdimg import parse_kdimg  # noqa: E402


MODEL = "nano3"
RECEIPT_SCHEMA = "dcent.nano3.user-donor-rootfs-mutation-receipt.v1"
ROOTFS_SLOTS = (
    ("rootfs_1", 0x01400000, 0x01800000),
    ("rootfs_2", 0x02C00000, 0x01800000),
)
MAX_MUTATION_BYTES = 512 + len(ROOTFS_SLOTS) * 256 + sum(
    size for _name, _offset, size in ROOTFS_SLOTS
)
BUILD_SCRIPT = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "scripts"
    / "build_nano3_stock_chain_firstlight.sh"
)
IMAGE_VERIFIER = (
    WORKSPACE_ROOT
    / "projects"
    / "dcentos-avalon"
    / "scripts"
    / "verify_nano3_coexistence_image.sh"
)


class Nano3MutationError(ValueError):
    """A donor, mutation image, receipt, or boundary check failed closed."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular_stable(
    path: Path,
    label: str,
    *,
    expected_size: Optional[int] = None,
    maximum_size: Optional[int] = None,
) -> bytes:
    """Read a bounded regular non-symlink file without identity drift."""
    try:
        before_path = path.lstat()
    except OSError as exc:
        raise Nano3MutationError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise Nano3MutationError(f"{label} must be a regular, non-symlink file")
    if expected_size is not None and before_path.st_size != expected_size:
        raise Nano3MutationError(
            f"{label} has size {before_path.st_size}; expected {expected_size}"
        )
    if maximum_size is not None and not 0 < before_path.st_size <= maximum_size:
        raise Nano3MutationError(
            f"{label} size {before_path.st_size} is outside 1..{maximum_size}"
        )
    limit = expected_size if expected_size is not None else maximum_size
    if limit is None:
        raise Nano3MutationError("internal error: file read has no size bound")

    try:
        with path.open("rb") as handle:
            before_fd = os.fstat(handle.fileno())
            data = handle.read(limit + 1)
            after_fd = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError as exc:
        raise Nano3MutationError(f"cannot read {label}: {exc}") from exc

    identities = (
        (
            before_path.st_dev,
            before_path.st_ino,
            before_path.st_size,
            before_path.st_mtime_ns,
        ),
        (
            before_fd.st_dev,
            before_fd.st_ino,
            before_fd.st_size,
            before_fd.st_mtime_ns,
        ),
        (
            after_fd.st_dev,
            after_fd.st_ino,
            after_fd.st_size,
            after_fd.st_mtime_ns,
        ),
        (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_size,
            after_path.st_mtime_ns,
        ),
    )
    if len(set(identities)) != 1 or len(data) != before_path.st_size:
        raise Nano3MutationError(f"{label} changed while it was being read")
    return data


def load_accepted_donor(path: Path) -> bytes:
    """Load only the exact raw donor admitted by the release profile."""
    profile = K230_RELEASE_PROFILES[MODEL]
    donor = _read_regular_stable(
        path, "Nano 3 factory donor", expected_size=profile.capacity
    )
    if _sha256(donor) != profile.donor_sha256:
        raise Nano3MutationError(
            "Nano 3 factory donor SHA-256 mismatch; this is not the admitted donor"
        )
    return donor


def verify_mutation_bytes(donor: bytes, candidate: bytes) -> dict[str, Any]:
    """Verify exact rootfs-only geometry and return a payload-free receipt."""
    profile = K230_RELEASE_PROFILES[MODEL]
    if len(donor) != profile.capacity or _sha256(donor) != profile.donor_sha256:
        raise Nano3MutationError("caller supplied a non-admitted donor")
    image = parse_kdimg(candidate)
    if image.version != 2 or image.flag != 0 or image.chip_info != "k230":
        raise Nano3MutationError("mutation KDIMG header is not canonical K230 v2")
    if not image.image_info.startswith("DCENT Nano 3 rootfs-only "):
        raise Nano3MutationError("mutation KDIMG is not labeled rootfs-only")
    if image.board_info != "Canaan k230_heater + non-autostart DCENT userspace":
        raise Nano3MutationError("mutation KDIMG board/profile identity is not coexistence")
    if len(image.partitions) != len(ROOTFS_SLOTS):
        raise Nano3MutationError("mutation KDIMG must contain exactly two rootfs slots")

    next_content_offset = 512 + len(ROOTFS_SLOTS) * 256
    rows: list[dict[str, Any]] = []
    for part, (name, offset, size) in zip(image.partitions, ROOTFS_SLOTS):
        if (
            part.name != name
            or part.nand_offset != offset
            or part.part_size != size
            or part.erase_size != NAND_ERASE_BLOCK
            or part.max_size != size
            or part.flag != 0
            or part.content_offset != next_content_offset
            or not 0 < part.content_size <= size
        ):
            raise Nano3MutationError(f"mutation metadata differs from exact slot {name}")
        write_stream = image.read_part_data(part)
        donor_stream = donor[offset : offset + size]
        write_sha256 = _sha256(write_stream)
        donor_sha256 = _sha256(donor_stream)
        if write_sha256 == donor_sha256:
            raise Nano3MutationError(f"mutation slot {name} is donor-identical")
        next_content_offset += part.content_size
        rows.append(
            {
                "name": name,
                "nand_offset": offset,
                "slot_size": size,
                "erase_size": part.erase_size,
                "streamed_size": part.content_size,
                "streamed_sha256": part.content_sha256.hex(),
                "padded_write_sha256": write_sha256,
                "donor_slot_sha256": donor_sha256,
                "differs_from_donor": True,
            }
        )
    if next_content_offset != len(candidate):
        raise Nano3MutationError("mutation KDIMG has trailing or unaccounted bytes")
    if image.last_nand_end > profile.data_offset:
        raise Nano3MutationError("mutation KDIMG overlaps persistent data")

    entry_path = Path(__file__)
    return {
        "schema": RECEIPT_SCHEMA,
        "model": MODEL,
        "model_profile_revision": profile.model_profile_revision,
        "donor": {
            "revision": profile.donor_revision,
            "size_bytes": len(donor),
            "sha256": _sha256(donor),
        },
        "mutation": {
            "size_bytes": len(candidate),
            "sha256": _sha256(candidate),
            "exact_write_slots": [name for name, _offset, _size in ROOTFS_SLOTS],
            "partition_count": len(rows),
            "last_nand_end": image.last_nand_end,
            "persistent_data_offset": profile.data_offset,
            "persistent_data_included": False,
            "contains_factory_derived_rootfs_bytes": True,
            "filesystem_contents_verified_by_this_receipt": False,
        },
        "slots": rows,
        "tooling": {
            "entry_point": entry_path.name,
            "entry_point_sha256": _sha256(entry_path.read_bytes()),
            "local_builder": BUILD_SCRIPT.name,
            "local_builder_sha256": _sha256(BUILD_SCRIPT.read_bytes()),
            "filesystem_verifier": IMAGE_VERIFIER.name,
            "filesystem_verifier_sha256": _sha256(IMAGE_VERIFIER.read_bytes()),
        },
        "claims": {
            "receipt_contains_factory_payload_bytes": False,
            "receipt_contains_local_paths": False,
            "mutation_must_remain_operator_local": True,
            "redistribution_authorized": False,
            "release_signing_authorized": False,
            "hardware_contact_authorized": False,
            "flash_authorized": False,
            "reboot_authorized": False,
            "energization_authorized": False,
            "hardware_action_performed": False,
        },
    }


def canonical_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    """Encode a deterministic receipt without local paths or payload bytes."""
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _write_new(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise Nano3MutationError(f"refusing to overwrite existing receipt: {path}")
    if not path.parent.is_dir():
        raise Nano3MutationError(f"receipt parent directory does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise Nano3MutationError(f"cannot create receipt: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donor", type=Path, required=True)
    parser.add_argument("--mutation", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.receipt.exists() or args.receipt.is_symlink():
            raise Nano3MutationError(
                f"refusing to overwrite existing receipt: {args.receipt}"
            )
        donor = load_accepted_donor(args.donor)
        candidate = _read_regular_stable(
            args.mutation, "Nano 3 rootfs mutation", maximum_size=MAX_MUTATION_BYTES
        )
        receipt = verify_mutation_bytes(donor, candidate)
        encoded = canonical_receipt_bytes(receipt)
        _write_new(args.receipt, encoded)
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "receipt": str(args.receipt),
                    "receipt_sha256": _sha256(encoded),
                    "mutation_sha256": receipt["mutation"]["sha256"],
                    "exact_write_slots": receipt["mutation"]["exact_write_slots"],
                    "persistent_data_included": False,
                    "redistribution_authorized": False,
                    "hardware_action_performed": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, Nano3MutationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
