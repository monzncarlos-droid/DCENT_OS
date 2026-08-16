#!/usr/bin/env python3
"""Write a hash-bound, capability-scoped manifest for an SD boot image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


SLUG_RE = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(value: str, label: str) -> Path:
    path = Path(value).expanduser().absolute()
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    return path


def canonical_slug(value: str, label: str) -> str:
    if SLUG_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a canonical identifier: {value!r}")
    return value


def manifest_output_path(
    value: str | None, image: Path, donor: Path | None, runtime: Path | None = None
) -> Path:
    """Return a safe manifest destination distinct from every source artifact.

    ``os.replace`` is intentionally used below for atomic publication.  That
    also means an output alias to ``image`` or ``donor`` would atomically
    destroy the very artifact the manifest describes.  Refuse lexical/resolved
    aliases, existing symlinks, and existing hardlinks before creating a temp
    file or destination directory.
    """

    raw_path = (
        Path(value).expanduser().absolute()
        if value
        else Path(f"{image}.manifest.json")
    )
    if raw_path.is_symlink():
        raise ValueError(f"manifest output must not be a symlink: {raw_path}")

    path = raw_path.resolve(strict=False)
    for source, label in (
        (image, "SD image"),
        (donor, "donor boot image"),
        (runtime, "DCENT_OS runtime"),
    ):
        if source is None:
            continue
        source_resolved = source.resolve(strict=True)
        collision = path == source_resolved
        if not collision and path.exists():
            collision = os.path.samefile(path, source)
        if collision:
            raise ValueError(
                f"manifest output must not overwrite or alias the {label}: {path}"
            )
    return path


def write_manifest(args: argparse.Namespace) -> Path:
    image = regular_file(args.image, "SD image")
    donor = regular_file(args.donor, "donor boot image") if args.donor else None
    runtime = regular_file(args.runtime, "DCENT_OS runtime") if args.runtime else None
    target = canonical_slug(args.target, "target")
    board_target = canonical_slug(args.board_target, "board target")
    control_board_family = canonical_slug(
        args.control_board_family, "control-board family"
    )

    manifest_path = manifest_output_path(args.manifest, image, donor, runtime)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    artifacts = {
        "BOOT.bin": args.complete_zynq_boot_set,
        "uImage": args.complete_zynq_boot_set,
        "devicetree.dtb": args.complete_zynq_boot_set,
        "uEnv.txt": args.complete_zynq_boot_set,
        "bitstream": args.complete_zynq_boot_set,
        "rootfs": args.complete_zynq_boot_set,
    }
    document: dict[str, object] = {
        "schema": "dcentos.sd_boot_media_manifest.v1",
        "target": target,
        "board_target": board_target,
        "control_board_family": control_board_family,
        "image": image.name,
        "image_size_bytes": image.stat().st_size,
        "image_sha256": sha256_file(image),
        "artifact_kind": "sd_image",
        "artifact_maturity": "experimental",
        "install_scope": "external_media_boot",
        "native_runtime_support": args.native_runtime_support,
        "requires_sd_present": True,
        "persistent_install_authorized": False,
        "nand_mutation_authorized": False,
        "allow_incomplete": not args.complete_zynq_boot_set,
        "boot_artifacts_complete": args.complete_zynq_boot_set,
        "artifacts": artifacts,
    }
    if donor is not None:
        document["boot_chain_evidence"] = {
            "source": donor.name,
            "size_bytes": donor.stat().st_size,
            "sha256": sha256_file(donor),
        }
    if runtime is not None:
        document["runtime_provenance"] = {
            "source": runtime.name,
            "size_bytes": runtime.stat().st_size,
            "sha256": sha256_file(runtime),
            "required_current_build": True,
        }

    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{manifest_path.name}.", dir=manifest_path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, manifest_path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return manifest_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write an offline SD boot-media capability manifest."
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--manifest")
    parser.add_argument("--runtime")
    parser.add_argument("--target", required=True)
    parser.add_argument("--board-target", required=True)
    parser.add_argument("--control-board-family", required=True)
    parser.add_argument("--donor")
    parser.add_argument(
        "--native-runtime-support",
        choices=("management_only", "experimental", "supported", "not_implemented"),
        required=True,
    )
    parser.add_argument("--complete-zynq-boot-set", action="store_true")
    return parser.parse_args()


def main() -> int:
    try:
        manifest = write_manifest(parse_args())
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
