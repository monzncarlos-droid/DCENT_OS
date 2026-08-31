#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Build or verify a local-only Nano 3 factory restore from an owned donor.

The accepted input is the exact 128 MiB Canaan recovery master already pinned
by the Nano 3 release profile.  This command never opens USB, contacts a miner,
signs a release, or authorizes redistribution.  A built ``.kdimg`` contains
factory bytes and must remain in operator-controlled, untracked storage.  Its
canonical receipt contains only hashes, geometry, and negative authority
claims; it contains no factory payload bytes or local paths.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
TOOLBOX_SRC = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
sys.path.insert(0, str(TOOLBOX_SRC))

from dcent_toolbox.core.k230_image_build import (  # noqa: E402
    build_stock_restore_kdimg,
    image_map_for,
)
from dcent_toolbox.core.k230_release_manifest import (  # noqa: E402
    K230_RELEASE_PROFILES,
)
from dcent_toolbox.core.kdimg import KdImage, parse_kdimg  # noqa: E402


MODEL = "nano3"
RECEIPT_SCHEMA = "dcent.nano3.user-donor-restore-receipt.v1"
HISTORICAL_LIVE_PROVEN_RESTORE_SHA256 = (
    "8267651a8ebf5c63853a24dbd7bab639a732c9cef8a7a7da96348d9791aab9cc"
)
LOCAL_ONLY_ACKNOWLEDGEMENT = "user-owned-donor-local-only"


class Nano3DonorRestoreError(ValueError):
    """A donor, restore container, or requested output failed closed."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_exact_stable(path: Path, expected_size: int, label: str) -> bytes:
    """Read one exact-size regular file while rejecting identity changes."""
    try:
        before_path = path.lstat()
    except OSError as exc:
        raise Nano3DonorRestoreError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise Nano3DonorRestoreError(f"{label} must be a regular, non-symlink file")
    if before_path.st_size != expected_size:
        raise Nano3DonorRestoreError(
            f"{label} has size {before_path.st_size}; expected {expected_size}"
        )

    try:
        with path.open("rb") as handle:
            before_fd = os.fstat(handle.fileno())
            data = handle.read(expected_size + 1)
            after_fd = os.fstat(handle.fileno())
        after_path = path.lstat()
    except OSError as exc:
        raise Nano3DonorRestoreError(f"cannot read {label}: {exc}") from exc

    identity_before = (
        before_path.st_dev,
        before_path.st_ino,
        before_path.st_size,
        before_path.st_mtime_ns,
    )
    identity_fd_before = (
        before_fd.st_dev,
        before_fd.st_ino,
        before_fd.st_size,
        before_fd.st_mtime_ns,
    )
    identity_fd_after = (
        after_fd.st_dev,
        after_fd.st_ino,
        after_fd.st_size,
        after_fd.st_mtime_ns,
    )
    identity_after = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
    )
    if (
        identity_before != identity_fd_before
        or identity_fd_before != identity_fd_after
        or identity_fd_after != identity_after
        or len(data) != expected_size
    ):
        raise Nano3DonorRestoreError(f"{label} changed while it was being read")
    return data


def load_accepted_donor(path: Path) -> bytes:
    """Load only the exact donor admitted by the Nano 3 release profile."""
    profile = K230_RELEASE_PROFILES[MODEL]
    donor = _read_exact_stable(path, profile.capacity, "Nano 3 factory donor")
    digest = _sha256(donor)
    if digest != profile.donor_sha256:
        raise Nano3DonorRestoreError(
            "Nano 3 factory donor SHA-256 mismatch; this is not the admitted donor"
        )
    return donor


def _slot_rows(donor: bytes, image: KdImage) -> list[dict[str, Any]]:
    """Prove the exact KDIMG write stream against every admitted donor slice."""
    expected: list[tuple[str, int, int, int]] = []
    for logical in image_map_for(MODEL):
        for index, slot in enumerate(logical.slots, start=1):
            name = (
                f"{logical.name}_{index}"
                if len(logical.slots) > 1
                else logical.name
            )
            expected.append((name, slot.offset, slot.size, logical.erase_size()))

    if len(image.partitions) != len(expected):
        raise Nano3DonorRestoreError(
            f"restore has {len(image.partitions)} partitions; expected {len(expected)}"
        )
    if image.version != 2 or image.flag != 0:
        raise Nano3DonorRestoreError("restore KDIMG header profile is not canonical v2")
    if image.chip_info != "k230" or image.board_info != "stock nano3":
        raise Nano3DonorRestoreError("restore KDIMG target identity is not stock Nano 3")
    if not image.image_info.startswith("stock restore (nano3 "):
        raise Nano3DonorRestoreError("restore KDIMG image identity is not factory restore")

    next_content_offset = 512 + len(expected) * 256
    rows: list[dict[str, Any]] = []
    for part, (name, offset, size, erase_size) in zip(image.partitions, expected):
        if (
            part.name != name
            or part.nand_offset != offset
            or part.part_size != size
            or part.erase_size != erase_size
            or part.max_size != size
            or part.flag != 0
            or part.content_offset != next_content_offset
        ):
            raise Nano3DonorRestoreError(
                f"restore partition metadata differs from admitted slot {name}"
            )
        donor_slice = donor[offset : offset + size]
        trimmed_size = len(donor_slice.rstrip(b"\xff"))
        if trimmed_size == 0 or part.content_size != trimmed_size:
            raise Nano3DonorRestoreError(
                f"restore partition {name} has a noncanonical streamed size"
            )
        write_stream = image.read_part_data(part)
        if write_stream != donor_slice:
            raise Nano3DonorRestoreError(
                f"restore partition {name} is not the exact admitted donor slice"
            )
        next_content_offset += part.content_size
        rows.append(
            {
                "name": name,
                "nand_offset": offset,
                "slot_size": size,
                "erase_size": erase_size,
                "streamed_size": part.content_size,
                "streamed_sha256": part.content_sha256.hex(),
                "donor_slice_sha256": _sha256(donor_slice),
                "exact_donor_slice": True,
            }
        )
    if next_content_offset != len(image._data):  # noqa: SLF001 - exact framing proof
        raise Nano3DonorRestoreError("restore KDIMG has trailing or unaccounted bytes")
    if image.last_nand_end != K230_RELEASE_PROFILES[MODEL].data_offset:
        raise Nano3DonorRestoreError(
            "restore slot set does not end exactly before persistent data"
        )
    return rows


def verify_restore_bytes(donor: bytes, restore: bytes) -> dict[str, Any]:
    """Verify one historical or current canonical restore and return a receipt."""
    canonical = build_stock_restore_kdimg(donor, MODEL)
    canonical_sha256 = _sha256(canonical.data)
    restore_sha256 = _sha256(restore)
    if restore_sha256 == HISTORICAL_LIVE_PROVEN_RESTORE_SHA256:
        container_profile = "live-proven-2026-08-21"
    elif restore == canonical.data:
        container_profile = "current-tooling-canonical"
    else:
        raise Nano3DonorRestoreError(
            "restore is neither the live-proven container nor the current canonical build"
        )

    image = parse_kdimg(restore)
    rows = _slot_rows(donor, image)
    profile = K230_RELEASE_PROFILES[MODEL]
    script_bytes = Path(__file__).read_bytes()
    builder_path = Path(sys.modules[build_stock_restore_kdimg.__module__].__file__ or "")
    builder_bytes = builder_path.read_bytes()
    return {
        "schema": RECEIPT_SCHEMA,
        "model": MODEL,
        "model_profile_revision": profile.model_profile_revision,
        "donor": {
            "revision": profile.donor_revision,
            "size_bytes": len(donor),
            "sha256": _sha256(donor),
            "whole_master_embedded_in_restore": False,
        },
        "restore": {
            "size_bytes": len(restore),
            "sha256": restore_sha256,
            "container_profile": container_profile,
            "current_canonical_sha256": canonical_sha256,
            "partition_count": len(rows),
            "last_nand_end": image.last_nand_end,
            "contains_factory_bytes": True,
            "persistent_data_offset": profile.data_offset,
            "persistent_data_size": profile.data_size,
            "persistent_data_included": False,
        },
        "slots": rows,
        "tooling": {
            "entry_point": Path(__file__).name,
            "entry_point_sha256": _sha256(script_bytes),
            "image_builder": builder_path.name,
            "image_builder_sha256": _sha256(builder_bytes),
        },
        "claims": {
            "all_partition_payloads_exact_donor_slices": True,
            "receipt_contains_factory_payload_bytes": False,
            "receipt_contains_local_paths": False,
            "restore_must_remain_operator_local": True,
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
    """Encode a deterministic, payload-free receipt."""
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _refuse_existing(path: Path, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise Nano3DonorRestoreError(f"refusing to overwrite existing {label}: {path}")
    if not path.parent.is_dir():
        raise Nano3DonorRestoreError(f"{label} parent directory does not exist: {path.parent}")


def _write_new(path: Path, data: bytes, label: str) -> None:
    """Create a new file without an overwrite race, then durably flush it."""
    _refuse_existing(path, label)
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
        raise Nano3DonorRestoreError(f"cannot create {label}: {exc}") from exc


def _summary(receipt_path: Path, receipt: dict[str, Any]) -> str:
    return json.dumps(
        {
            "status": "PASS",
            "receipt": str(receipt_path),
            "receipt_sha256": _sha256(canonical_receipt_bytes(receipt)),
            "restore_sha256": receipt["restore"]["sha256"],
            "container_profile": receipt["restore"]["container_profile"],
            "partition_count": receipt["restore"]["partition_count"],
            "persistent_data_included": False,
            "redistribution_authorized": False,
            "hardware_action_performed": False,
        },
        sort_keys=True,
    )


def _build(args: argparse.Namespace) -> int:
    if args.acknowledge_local_only != LOCAL_ONLY_ACKNOWLEDGEMENT:
        raise Nano3DonorRestoreError(
            "build requires --acknowledge-local-only " + LOCAL_ONLY_ACKNOWLEDGEMENT
        )
    if args.output.resolve() == args.receipt.resolve():
        raise Nano3DonorRestoreError("restore output and receipt must be different files")
    _refuse_existing(args.output, "restore output")
    _refuse_existing(args.receipt, "receipt")
    donor = load_accepted_donor(args.donor)
    result = build_stock_restore_kdimg(donor, MODEL)
    receipt = verify_restore_bytes(donor, result.data)
    _write_new(args.output, result.data, "restore output")
    _write_new(args.receipt, canonical_receipt_bytes(receipt), "receipt")
    print(_summary(args.receipt, receipt))
    return 0


def _verify(args: argparse.Namespace) -> int:
    _refuse_existing(args.receipt, "receipt")
    donor = load_accepted_donor(args.donor)
    canonical_size = len(build_stock_restore_kdimg(donor, MODEL).data)
    restore = _read_exact_stable(args.restore, canonical_size, "Nano 3 restore")
    receipt = verify_restore_bytes(donor, restore)
    _write_new(args.receipt, canonical_receipt_bytes(receipt), "receipt")
    print(_summary(args.receipt, receipt))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser(
        "build", help="create a new local-only restore and payload-free receipt"
    )
    build.add_argument("--donor", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--receipt", type=Path, required=True)
    build.add_argument(
        "--acknowledge-local-only",
        metavar="TEXT",
        required=True,
        help=f"must be exactly {LOCAL_ONLY_ACKNOWLEDGEMENT!r}",
    )
    build.set_defaults(func=_build)

    verify = subparsers.add_parser(
        "verify", help="verify an existing restore and write a payload-free receipt"
    )
    verify.add_argument("--donor", type=Path, required=True)
    verify.add_argument("--restore", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.set_defaults(func=_verify)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        return args.func(args)
    except (OSError, Nano3DonorRestoreError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
