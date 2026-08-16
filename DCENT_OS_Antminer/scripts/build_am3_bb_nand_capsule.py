#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Build a DCENT AM335x/BeagleBone FIRST-INSTALL capsule (Wave 4, firmware side).

Packages operator-reviewed transition inputs into the typed capsule
contract enforced by ``dcent bb-nand-first-install inspect`` (toolbox
``core/am3_bb_nand_first_install.py`` — the single source of truth for
the contract). This script is the packager ONLY: it never invents payload
content, never contacts a miner, and never authorizes an install. Trust
comes exclusively from the release signature:

* the manifest is signed with the EXACT release signer
  (``sign_release_artifact.py`` → ``sign_release_receipt.py`` — the same
  durable no-replace ceremony as sysupgrade packages);
* the trusted public key must be supplied explicitly (``--pubkey`` or
  ``DCENT_RELEASE_PUBKEY_FILE``) — trust is never derived from the
  signing key;
* output is no-replace: an existing capsule path is an error.

Determinism: identical inputs produce a byte-identical capsule (sorted
members, mtime-0 tar, mtime-0 gzip, sorted manifest keys).

The lane has ONE transition mechanism (``nvdata_kernel_window``: DCENT
kernel+rootfs into the mtd11 nvdata window, factory kernel mtd7 and
factory recovery rootfs mtd8 preserved as the rollback rail) — there is
no ``--mechanism`` flag to get wrong, and ``transition/stage1.sh`` is
required for every capsule. One capsule may accept BOTH stock dialects
(``--source-layout`` is repeatable); the on-target stage1 preflight
selects the exact layout on the unit.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
TOOLBOX_SOURCE = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am3_bb_nand_first_install import (  # noqa: E402
    BB_NAND_TARGET,
    CAPSULE_PACKAGE_TYPE,
    CAPSULE_SCHEMA,
    MANIFEST_MEMBER,
    MECHANISM_NVDATA_KERNEL_WINDOW,
    SIGNATURE_MEMBER,
    STAGE1_MEMBER,
    bb_first_install_source_facts,
    canonical_bb_first_install_source,
    canonical_bb_first_install_target,
)

MAX_STAGE1_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 96 * 1024 * 1024  # the mtd11 nvdata window itself is 96 MiB
MAX_TOTAL_PAYLOAD_BYTES = 256 * 1024 * 1024
_RESERVED_MEMBER_NAMES = {MANIFEST_MEMBER, SIGNATURE_MEMBER}
_VERSION_CHARS = re.compile(r"^[A-Za-z0-9._+:-]+$")
_DEFAULT_NAME_PREFIX = "DCENT_FIRSTINSTALL_BB3_S19jPro_"


class CapsuleBuildError(ValueError):
    """Raised when capsule inputs violate the contract or cannot be packaged."""


def _fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise CapsuleBuildError(message)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _validate_member_name(name: str) -> str:
    if (
        not name
        or name != name.strip()
        or name.startswith("/")
        or name.startswith("\\")
        or "\\" in name
        or ":" in name.split("/")[0]
        or ".." in name.split("/")
        or "//" in name
    ):
        raise ValueError(f"unsafe member name: {name!r}")
    if name in _RESERVED_MEMBER_NAMES:
        raise ValueError(f"member name is reserved: {name!r}")
    if Path(name).is_absolute():
        raise ValueError(f"member name must be relative: {name!r}")
    return name


def _parse_member(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError(f"--member expects NAME=PATH, got {spec!r}")
    name, _, raw_path = spec.partition("=")
    return _validate_member_name(name.strip()), Path(raw_path.strip()).expanduser()


def _deterministic_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), compresslevel=9, mtime=0)


def _default_output_name(version: str) -> str:
    return f"{_DEFAULT_NAME_PREFIX}{version}.tar.gz"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Build a contract-conforming DCENT BB (AM335x BeagleBone) NAND "
            "first-install capsule (packager only; signed with the exact "
            "release signer)."
        )
    )
    result.add_argument("--board-target", required=True,
                        help="am3-bb-s19jpro (aliases am3-bb, s19jpro-bb)")
    result.add_argument("--source-layout", action="append", required=True,
                        metavar="LAYOUT",
                        help="accepted source dialect (repeatable; one capsule may accept "
                             "both stock-bbctrl-12part and luxos-bb-nvdata-rootfs)")
    result.add_argument("--version", required=True,
                        help="capsule version string ([A-Za-z0-9._+:-])")
    result.add_argument("--post-install-artifact", required=True,
                        help="DCENT BB artifact ID the capsule converges to (the sdcard payload family)")
    result.add_argument("--migration-scope", required=True,
                        help="declared persistent-state migration (explicit 'none' allowed)")
    result.add_argument("--stage1", type=Path,
                        help="on-target transition script (required for every BB capsule); packaged as "
                             + STAGE1_MEMBER)
    result.add_argument("--member", action="append", default=[], metavar="NAME=PATH",
                        help="additional payload member (repeatable; NAME is the in-capsule path)")
    result.add_argument("--key", default=os.environ.get("DCENT_RELEASE_SIGNING_KEY", ""),
                        help="Ed25519 private key PEM (default $DCENT_RELEASE_SIGNING_KEY)")
    result.add_argument("--pubkey", default=os.environ.get("DCENT_RELEASE_PUBKEY_FILE", ""),
                        help="trusted release public key (default $DCENT_RELEASE_PUBKEY_FILE); "
                             "trust is never derived from the signing key")
    result.add_argument("--output", type=Path,
                        help="output capsule path (default: " + _DEFAULT_NAME_PREFIX + "<version>.tar.gz)")
    result.add_argument("--plan", action="store_true",
                        help="print the exact manifest and member table; write nothing")
    result.add_argument("--json", action="store_true", help="emit JSON to stdout")
    return result


def build(args: argparse.Namespace) -> int:
    # --- validate against the toolbox contract (single source of truth) ---
    try:
        board_target = canonical_bb_first_install_target(args.board_target)
    except ValueError as exc:
        raise _fail(str(exc))
    sources: list[str] = []
    for raw in args.source_layout:
        try:
            source = canonical_bb_first_install_source(raw)
        except ValueError as exc:
            raise _fail(str(exc))
        if source not in sources:
            sources.append(source)
    sources.sort()
    facts = {source: bb_first_install_source_facts(source) for source in sources}
    mechanism = MECHANISM_NVDATA_KERNEL_WINDOW

    if not _VERSION_CHARS.match(args.version):
        raise _fail(f"version contains characters outside [A-Za-z0-9._+:-]: {args.version!r}")
    if not args.post_install_artifact or "/" in args.post_install_artifact or "\\" in args.post_install_artifact:
        raise _fail("post-install artifact must be a bare artifact ID (no path separators)")
    if not args.migration_scope.strip():
        raise _fail("migration scope must be declared (explicit 'none' allowed, never empty)")
    if args.stage1 is None:
        raise _fail(
            "every BB capsule requires the on-target transition script "
            f"(--stage1 PATH; packaged as {STAGE1_MEMBER}; single-mechanism "
            "contract)"
        )

    members: dict[str, Path] = {STAGE1_MEMBER: args.stage1.expanduser()}
    try:
        for spec in args.member:
            name, path = _parse_member(spec)
            if name in members:
                raise ValueError(f"duplicate member name: {name!r}")
            members[name] = path
    except ValueError as exc:
        raise _fail(str(exc))

    checksums: dict[str, str] = {}
    total = 0
    for name in sorted(members):
        path = members[name]
        if not path.is_file():
            raise _fail(f"member file is missing or not a regular file: {path}")
        if path.is_symlink():
            raise _fail(f"member file is a symlink (refused): {path}")
        limit = MAX_STAGE1_BYTES if name == STAGE1_MEMBER else MAX_MEMBER_BYTES
        size = path.stat().st_size
        if size <= 0:
            raise _fail(f"member file is empty: {path}")
        if size > limit:
            raise _fail(f"member exceeds its {limit}-byte bound: {name} ({size} bytes)")
        total += size
        checksums[name] = _sha256_file(path)
    if total > MAX_TOTAL_PAYLOAD_BYTES:
        raise _fail(f"total payload exceeds {MAX_TOTAL_PAYLOAD_BYTES} bytes")

    manifest = {
        "schema": CAPSULE_SCHEMA,
        "package_type": CAPSULE_PACKAGE_TYPE,
        "version": args.version,
        "board_target": board_target,
        "accepted_source_layouts": sources,
        "transition_mechanism": mechanism,
        "post_install_artifact": args.post_install_artifact,
        "migration_scope": args.migration_scope.strip(),
        "checksums": checksums,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    output = (args.output or Path(_default_output_name(args.version))).expanduser()

    if args.plan:
        plan = {
            "mode": "plan",
            "output": str(output),
            "board_target": board_target,
            "accepted_source_layouts": sources,
            "transition_mechanism": mechanism,
            "sources": [
                {
                    "source_layout": source,
                    "nvdata_mtd": facts[source]["nvdata_mtd"],
                    "preserved_mtds": facts[source]["preserved_mtds"],
                    "dialect_proven": facts[source]["dialect_proven"],
                }
                for source in sources
            ],
            "members": [
                {"name": name, "bytes": members[name].stat().st_size, "sha256": checksums[name]}
                for name in sorted(members)
            ],
            "manifest": manifest,
            "signing": {
                "key": str(Path(args.key).expanduser()) if args.key else "(not configured)",
                "trusted_pubkey": str(Path(args.pubkey).expanduser()) if args.pubkey else "(not configured)",
                "signer": str(SCRIPT_DIR / "sign_release_artifact.py"),
            },
        }
        print(json.dumps(plan, indent=2))
        return 0

    if output.exists() or output.is_symlink():
        raise _fail(f"output already exists (no-replace): {output}")
    if not args.key or not args.pubkey:
        raise _fail(
            "signing requires --key (or $DCENT_RELEASE_SIGNING_KEY) AND "
            "--pubkey (or $DCENT_RELEASE_PUBKEY_FILE); trust is never "
            "derived from the signing key"
        )

    key_path = Path(args.key).expanduser()
    pubkey_path = Path(args.pubkey).expanduser()
    for label, path in (("signing key", key_path), ("trusted public key", pubkey_path)):
        if not path.is_file():
            raise _fail(f"{label} is not a file: {path}")

    signer = SCRIPT_DIR / "sign_release_artifact.py"
    if not signer.is_file():
        raise _fail(f"exact release signer is missing: {signer}")

    with tempfile.TemporaryDirectory(prefix="bb-nand-first-install-") as staging_raw:
        staging = Path(staging_raw)
        manifest_path = staging / MANIFEST_MEMBER
        manifest_path.write_bytes(manifest_bytes)
        signature_path = staging / SIGNATURE_MEMBER
        run = subprocess.run(
            [
                sys.executable, str(signer), str(manifest_path),
                "--key", str(key_path),
                "--pubkey", str(pubkey_path),
                "--output-sig", str(signature_path),
            ],
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            print(run.stdout, file=sys.stderr)
            print(run.stderr, file=sys.stderr)
            raise _fail("exact release signer failed (see signer output above)")
        signature = signature_path.read_bytes()
        if len(signature) != 64:
            raise _fail(f"signer produced a {len(signature)}-byte signature (expected 64)")

        files: dict[str, bytes] = {MANIFEST_MEMBER: manifest_bytes, SIGNATURE_MEMBER: signature}
        for name in members:
            files[name] = members[name].read_bytes()
        capsule_bytes = _deterministic_tar(files)

        # write no-replace: create exclusively, then fsync
        try:
            descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o644)
        except FileExistsError:
            raise _fail(f"output appeared during build (no-replace): {output}")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(capsule_bytes)
            handle.flush()
            os.fsync(handle.fileno())

    payload = {
        "mode": "built",
        "capsule": str(output),
        "bytes": len(capsule_bytes),
        "sha256": hashlib.sha256(capsule_bytes).hexdigest(),
        "board_target": board_target,
        "accepted_source_layouts": sources,
        "transition_mechanism": mechanism,
        "version": args.version,
        "members": sorted(members),
        "verify_command": f"dcent bb-nand-first-install inspect --capsule {output}",
    }
    print(json.dumps(payload, indent=2) if args.json else (
        f"Built capsule: {output}\n"
        f"  board: {board_target} | sources: {', '.join(sources)} | mechanism: {mechanism}\n"
        f"  version: {args.version} | members: {', '.join(sorted(members))}\n"
        f"  size: {len(capsule_bytes)} bytes | sha256: {payload['sha256']}\n"
        f"  verify: dcent bb-nand-first-install inspect --capsule {output}"
    ))
    return 0


def main(argv: list[str] | None = None) -> int:
    if shutil.which("openssl") is None:
        print(
            "WARNING: openssl not found on PATH; the exact release signer "
            "requires it.",
            file=sys.stderr,
        )
    try:
        return build(parser().parse_args(argv))
    except CapsuleBuildError:
        return 2


if __name__ == "__main__":
    sys.exit(main())
