#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Build a DCENT S19k Pro (Amlogic A113D/AXG) AML TRANSITION capsule
(S19k Pro release wave 2026-08-29, firmware side).

Packages operator-reviewed transition inputs into the typed capsule
contract enforced by ``dcent s19k-aml-first-install inspect`` (toolbox
``core/s19k_aml_first_install.py`` — the single source of truth for the
contract). This script is the packager ONLY: it never invents payload
content, never contacts a miner, and never authorizes an install. Trust
comes exclusively from the release signature:

* the manifest is signed with the EXACT release signer
  (``sign_release_artifact.py`` -> ``sign_release_receipt.py`` — the same
  durable no-replace ceremony as sysupgrade/am2/BB/Whatsminer packages);
* the trusted public key must be supplied explicitly (``--pubkey`` or
  ``DCENT_RELEASE_PUBKEY_FILE``) — trust is never derived from the
  signing key;
* output is no-replace: an existing capsule path is an error.

Determinism: identical inputs produce a byte-identical capsule (sorted
members, mtime-0 tar, mtime-0 gzip, sorted manifest keys).

The lane has ONE transition mechanism (``mtd5_rootfs_window_flag_commit``:
flash_erase + nandwrite the DCENT rootfs into the mtd5 ``system`` window
at local 0x05100000 within the 0x02800000 window; COMMIT = the
recovery-flag eraseblock at local 0x04D00000 rewritten to 0x01) — there is
no ``--mechanism`` flag to get wrong, and ``transition/stage1.sh`` is
required for every capsule. The manifest ``nand_geometry`` block is
NEVER hand-entered: it is emitted from the toolbox geometry pins
(``s19k_aml_geometry_pins()``), which mirror the canonical dcentos
contract modules (``s19k_am3_install.rs`` + ``s19k_nand_env.rs``) and are
pinned by the toolbox convergence test. A test fixture may describe both
root-SSH source dialects (``--source-layout`` is repeatable), but production
custody is currently narrowed to Braiins; Bitmain stock is refused (it is the
Track-2 evidence gap, never an accepted source). Every capsule carries the
stage1, target authorizer, five install-custody members, and the canonical
DCENT rootfs image the mtd5-window writer consumes (today the uImage from
``build_amlogic_native_install.sh --variant s19kpro``). The rootfs alone is
bounded by the 0x02800000 NAND window; a separately signed staging budget
accounts for every member that coexists under target ``/tmp`` plus per-unit
inputs and working reserve.
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parents[2]
TOOLBOX_SOURCE = WORKSPACE_ROOT / "projects" / "dcent-toolbox" / "src"
if str(TOOLBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.s19k_aml_first_install import (  # noqa: E402
    CAPSULE_PACKAGE_TYPE,
    CAPSULE_SCHEMA,
    EXPECTED_CAPSULE_NAME,
    MANIFEST_MEMBER,
    MECHANISM_MTD5_ROOTFS_WINDOW_FLAG_COMMIT,
    SIGNATURE_MEMBER,
    STAGE1_MEMBER,
    S19K_AML_GEOMETRY,
    canonical_s19k_aml_source,
    canonical_s19k_aml_target,
    s19k_aml_geometry_pins,
    s19k_aml_source_facts,
)
from dcent_toolbox.core.install_package import (  # noqa: E402
    get_pinned_release_pubkey_hex,
)

import s19k_persistent_image_verify as persistent_image  # noqa: E402
import s19k_release_policy as release_policy  # noqa: E402
import s19k_signing_ceremony as signing_ceremony  # noqa: E402

MAX_STAGE1_BYTES = 4 * 1024 * 1024
MAX_STAGE1_AUTHORIZER_BYTES = 1024 * 1024
# The shared capsule reader (am2_xil_first_install._read_capsule_members)
# caps any single member at 64 MiB; S19k additionally bounds the rootfs member
# alone by the 0x02800000 mtd5 window and signs a separate /tmp coexistence
# budget for all eight target inputs.
MAX_MEMBER_BYTES = 64 * 1024 * 1024
ROOTFS_WINDOW_BYTES = S19K_AML_GEOMETRY.rootfs_window
ROOTFS_WINDOW_HEX = f"0x{ROOTFS_WINDOW_BYTES:08x}"
_RESERVED_MEMBER_NAMES = {MANIFEST_MEMBER, SIGNATURE_MEMBER}
_VERSION_CHARS = re.compile(r"^[A-Za-z0-9._+:-]+$")
#: The conventional member name for the mtd5-window rootfs payload (the
#: uImage ``build_amlogic_native_install.sh --variant s19kpro`` extracts).
#: Production and fixture capsules both use this exact rootfs member name.
CANONICAL_ROOTFS_MEMBER = "payload/dcent-rootfs.img"
PERSISTENT_IMAGE_MEMBER = release_policy.PERSISTENT_IMAGE_MEMBER
STAGE1_AUTHORIZER_MEMBER = "transition/s19k-stage1-authorizer"
CUSTODY_MEMBER_BY_ROLE = release_policy.CUSTODY_MEMBER_BY_ROLE


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


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"


def _public_key_hex(path: Path) -> str:
    """Read only the explicitly selected public key and return raw hex."""

    data = path.read_bytes()
    compact = b"".join(data.split())
    if re.fullmatch(rb"[0-9a-fA-F]{64}", compact):
        return compact.decode("ascii").lower()
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as exc:
        raise CapsuleBuildError(
            f"trusted public key is neither 64-hex nor usable PEM: {exc}"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise CapsuleBuildError("trusted public key is not Ed25519")
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def _load_production_image_receipt(
    evidence_dir: Path,
    rootfs_path: Path,
    trusted_pubkey_path: Path,
    selected_pubkey_hex: str,
) -> tuple[dict[str, object], bytes]:
    """Re-run the authoritative verifier and bind its canonical result."""

    try:
        expected_key_sha = hashlib.sha256(trusted_pubkey_path.read_bytes()).hexdigest()
        receipt = persistent_image.verify_evidence(
            evidence_dir,
            expected_release_key_sha256=expected_key_sha,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        raise CapsuleBuildError(
            f"persistent-image evidence did not verify: {exc}"
        ) from exc
    canonical = persistent_image.canonical_json(receipt)
    if set(receipt) != release_policy.PERSISTENT_IMAGE_RECEIPT_KEYS:
        raise CapsuleBuildError("persistent-image receipt key set is not exact v4")
    materialized = evidence_dir / persistent_image.VERIFICATION_FILE
    if materialized.is_symlink() or not materialized.is_file():
        raise CapsuleBuildError(
            "persistent-image verification.json is missing or unsafe; run "
            "the authoritative verifier with --write-receipt"
        )
    if materialized.read_bytes() != canonical:
        raise CapsuleBuildError(
            "materialized persistent-image verification.json differs from "
            "the current authoritative verifier result"
        )
    required_true = (
        "installable",
        "a_b_unsigned_equality_verified",
        "private_key_excluded_from_builds",
        "post_ab_derivation_and_runtime_metadata_verified",
        "reproducible_builds_verified",
        "signed_manifest_verified",
        "native_owner_artifact_bound",
        "stock_recovery_receipt_bound",
        "native_owner_source_artifact_build_binding_verified",
    )
    if receipt.get("schema") != release_policy.PERSISTENT_IMAGE_SCHEMA:
        raise CapsuleBuildError("persistent-image receipt schema is not v4")
    if receipt.get("classification") != "verified":
        raise CapsuleBuildError("persistent-image receipt is not classified verified")
    if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("release_key_id") or "")):
        raise CapsuleBuildError("persistent-image receipt release_key_id is not exact")
    if any(receipt.get(name) is not True for name in required_true):
        raise CapsuleBuildError(
            "persistent-image receipt is missing a required verified binding"
        )
    for name in (
        "install_authority_granted",
        "mutation_authority_granted",
        "nand_write_authorized",
        "live_hardware_contacted",
        "network_used",
    ):
        if receipt.get(name) is not False:
            raise CapsuleBuildError(
                f"persistent-image receipt authority/contact flag is not false: {name}"
            )
    if receipt.get("isolated_post_ab_signing_verified") is not False:
        raise CapsuleBuildError(
            "persistent-image receipt improperly claims isolated post-A/B signing"
        )
    if (
        receipt.get("isolated_post_ab_signing_nonclaim")
        != release_policy.PERSISTENT_IMAGE_SIGNING_ISOLATION_NONCLAIM
    ):
        raise CapsuleBuildError(
            "persistent-image receipt signing-isolation nonclaim is not exact"
        )
    root_sha = _sha256_file(rootfs_path)
    root_bytes = rootfs_path.stat().st_size
    if receipt.get("image_sha256") != root_sha or receipt.get("image_bytes") != root_bytes:
        raise CapsuleBuildError(
            "persistent-image receipt does not bind the exact capsule rootfs bytes"
        )
    expected_id = hashlib.sha256(
        persistent_image.canonical_json(
            {k: v for k, v in receipt.items() if k != "verification_id"}
        )
    ).hexdigest()
    if receipt.get("verification_id") != expected_id:
        raise CapsuleBuildError("persistent-image receipt verification_id is invalid")
    key_bytes = trusted_pubkey_path.read_bytes()
    if receipt.get("release_key_sha256") != hashlib.sha256(key_bytes).hexdigest():
        raise CapsuleBuildError(
            "persistent-image receipt does not bind the selected public-key file"
        )
    if receipt.get("release_manifest_public_key_hex") != selected_pubkey_hex:
        raise CapsuleBuildError(
            "persistent-image receipt release key differs from the selected identity"
        )
    return receipt, canonical


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
    return EXPECTED_CAPSULE_NAME.replace("<version>", version)


def _write_no_replace(path: Path, data: bytes) -> None:
    """Create a durable output without an exists/write TOCTOU window."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o644,
        )
    except FileExistsError as exc:
        raise CapsuleBuildError(f"output already exists (no-replace): {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        try:
            directory = os.open(
                path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass  # directory handles/fsync are unavailable on some host filesystems


def _git(args: list[str]) -> str:
    run = subprocess.run(
        ["git", *args],
        cwd=WORKSPACE_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if run.returncode != 0:
        detail = (run.stderr or run.stdout).strip().splitlines()
        raise CapsuleBuildError(
            f"authenticated source snapshot check failed: git {' '.join(args)}: "
            + (detail[0] if detail else f"exit {run.returncode}")
        )
    return run.stdout.strip()


def _verified_source_snapshot(expected_commit: str) -> dict[str, object]:
    """Require production packaging from one clean, signed, externally pinned commit."""

    commit = expected_commit.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise CapsuleBuildError("expected source commit must be exactly 40 lowercase hex")
    top = Path(_git(["rev-parse", "--show-toplevel"])).resolve()
    if top != WORKSPACE_ROOT.resolve():
        raise CapsuleBuildError(
            f"builder is not executing from the expected workspace Git root: {top}"
        )
    observed = _git(["rev-parse", "HEAD"]).lower()
    if observed != commit:
        raise CapsuleBuildError(
            f"workspace HEAD {observed} differs from externally expected {commit}"
        )
    status = _git(["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise CapsuleBuildError(
            "production packaging requires a completely clean Git worktree"
        )
    # This delegates identity authentication to Git's configured signature
    # trust. An unsigned or untrusted commit is a hard production blocker.
    _git(["verify-commit", commit])
    tree = _git(["rev-parse", f"{commit}^{{tree}}"]).lower()
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise CapsuleBuildError("Git tree identity is not canonical 40-hex")
    return {
        "schema": release_policy.SOURCE_SNAPSHOT_SCHEMA,
        "commit": commit,
        "tree": tree,
        "commit_signature_verified": True,
        "clean_worktree_verified": True,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Build a contract-conforming DCENT S19k Pro (Amlogic A113D/AXG) "
            "AML transition capsule (packager only; signed with the exact "
            "release signer)."
        )
    )
    result.add_argument("--board-target", required=True,
                        help="am3-s19kpro (aliases am3-s19k, am3-aml-s19kpro, s19kpro)")
    result.add_argument("--source-layout", action="append", required=True,
                        metavar="LAYOUT",
                        help="accepted root-SSH source dialect (repeatable; fixtures may "
                             "describe both Braiins and LuxOS, production custody is Braiins-"
                             "only; Bitmain stock is never accepted)")
    result.add_argument("--version", required=True,
                        help="capsule version string ([A-Za-z0-9._+:-])")
    result.add_argument("--post-install-artifact", required=True,
                        help="DCENT_OS S19k artifact ID the capsule converges to (the "
                             "sysupgrade-am3-s19k tar family)")
    result.add_argument("--migration-scope", required=True,
                        help="declared persistent-state migration (explicit 'none' allowed)")
    result.add_argument("--stage1", type=Path,
                        help="on-target nohup-safe transition script (required for every "
                             "capsule); packaged as " + STAGE1_MEMBER)
    result.add_argument(
        "--stage1-authorizer",
        type=Path,
        help=(
            "bounded target-side detached Ed25519 verifier (required for "
            "every capsule); packaged as " + STAGE1_AUTHORIZER_MEMBER
        ),
    )
    result.add_argument(
        "--safeoff-dcentrald",
        type=Path,
        help="install-custody SafeOff dcentrald; packaged as transition/safeoff/dcentrald",
    )
    result.add_argument(
        "--safeoff-runner",
        type=Path,
        help="install-custody handoff runner; packaged as transition/safeoff/run_trial",
    )
    result.add_argument(
        "--safeoff-custody-observer",
        type=Path,
        help=(
            "custody observer; packaged as "
            "transition/safeoff/supervisor_custody_observer"
        ),
    )
    result.add_argument(
        "--stock-restart-helper",
        type=Path,
        help=(
            "pre-mutation stock restart helper; packaged as "
            "transition/safeoff/stock_restart_helper"
        ),
    )
    result.add_argument(
        "--safeoff-config",
        type=Path,
        help=(
            "credential-free pool-free install-custody config; packaged as "
            "transition/safeoff/dcentrald_s19k.toml"
        ),
    )
    result.add_argument("--member", action="append", default=[], metavar="NAME=PATH",
                        help="payload member (repeatable, at least one required; the DCENT "
                             "rootfs image — conventionally "
                             + CANONICAL_ROOTFS_MEMBER)
    result.add_argument(
        "--artifact-class",
        required=True,
        choices=sorted(release_policy.ARTIFACT_CLASSES),
        help=(
            "production requires verified persistent-image evidence and an "
            "approved target-side stage1; synthetic/dev inputs must be "
            "classified test-fixture"
        ),
    )
    result.add_argument(
        "--signing-key-id",
        required=True,
        help="explicit non-secret identity label for the selected signing key",
    )
    result.add_argument(
        "--persistent-image-evidence-dir",
        type=Path,
        help=(
            "authoritative v4 persistent-image evidence directory; mandatory "
            "for artifact-class=production and re-verified, never trusted by "
            "receipt shape alone"
        ),
    )
    result.add_argument(
        "--signing-authorization-receipt",
        type=Path,
        help=(
            "pre-signing authorization receipt binding the exact canonical "
            "manifest and output basename; mandatory before production signing"
        ),
    )
    result.add_argument(
        "--expected-source-commit",
        help=(
            "externally selected signed Git commit; production packaging "
            "requires exact HEAD, a clean tree, and git verify-commit success"
        ),
    )
    result.add_argument(
        "--emit-unsigned-manifest",
        type=Path,
        help=(
            "write the exact canonical production manifest no-replace for the "
            "prepare/authorize ceremony, then stop without reading a private key"
        ),
    )
    result.add_argument("--key", default=os.environ.get("DCENT_RELEASE_SIGNING_KEY", ""),
                        help="Ed25519 private key PEM (default $DCENT_RELEASE_SIGNING_KEY)")
    result.add_argument("--pubkey", default=os.environ.get("DCENT_RELEASE_PUBKEY_FILE", ""),
                        help="trusted release public key (default $DCENT_RELEASE_PUBKEY_FILE); "
                             "trust is never derived from the signing key")
    result.add_argument("--output", type=Path,
                        help="output capsule path (default: " + EXPECTED_CAPSULE_NAME + ")")
    result.add_argument("--plan", action="store_true",
                        help="print the exact manifest and member table; write nothing")
    result.add_argument("--json", action="store_true", help="emit JSON to stdout")
    return result


def build(args: argparse.Namespace) -> int:
    # --- validate against the toolbox contract (single source of truth) ---
    try:
        board_target = canonical_s19k_aml_target(args.board_target)
    except ValueError as exc:
        raise _fail(str(exc))
    sources: list[str] = []
    for raw in args.source_layout:
        try:
            source = canonical_s19k_aml_source(raw)
        except ValueError as exc:
            raise _fail(str(exc))
        if source not in sources:
            sources.append(source)
    sources.sort()
    facts = {source: s19k_aml_source_facts(source) for source in sources}
    mechanism = MECHANISM_MTD5_ROOTFS_WINDOW_FLAG_COMMIT

    if not _VERSION_CHARS.match(args.version):
        raise _fail(f"version contains characters outside [A-Za-z0-9._+:-]: {args.version!r}")
    if not args.post_install_artifact or "/" in args.post_install_artifact or "\\" in args.post_install_artifact:
        raise _fail("post-install artifact must be a bare artifact ID (no path separators)")
    if not args.migration_scope.strip():
        raise _fail("migration scope must be declared (explicit 'none' allowed, never empty)")
    if args.stage1 is None:
        raise _fail(
            "every S19k AML capsule requires the on-target transition "
            f"script (--stage1 PATH; packaged as {STAGE1_MEMBER}; "
            "single-mechanism contract)"
        )
    if args.stage1_authorizer is None:
        raise _fail(
            "every S19k AML capsule requires --stage1-authorizer PATH; "
            f"packaged as {STAGE1_AUTHORIZER_MEMBER}"
        )
    missing_custody = [
        f"--{role.replace('_', '-')}"
        for role in CUSTODY_MEMBER_BY_ROLE
        if getattr(args, role) is None
    ]
    if missing_custody:
        raise _fail(
            "every S19k AML capsule requires the complete self-contained "
            "install-custody set; missing " + ", ".join(missing_custody)
        )
    if not args.member:
        raise _fail(
            "every S19k AML capsule requires the DCENT rootfs payload "
            f"(--member {CANONICAL_ROOTFS_MEMBER}=PATH) consumed by the "
            "mtd5-window writer"
        )
    if not args.signing_key_id.strip():
        raise _fail("signing key id must be non-empty")

    members: dict[str, Path] = {
        STAGE1_MEMBER: args.stage1.expanduser(),
        STAGE1_AUTHORIZER_MEMBER: args.stage1_authorizer.expanduser(),
    }
    members.update(
        {
            member: getattr(args, role).expanduser()
            for role, member in CUSTODY_MEMBER_BY_ROLE.items()
        }
    )
    try:
        for spec in args.member:
            name, path = _parse_member(spec)
            if name in members:
                raise ValueError(f"duplicate member name: {name!r}")
            members[name] = path
    except ValueError as exc:
        raise _fail(str(exc))

    if CANONICAL_ROOTFS_MEMBER not in members:
        raise _fail(
            f"every capsule must name its rootfs exactly {CANONICAL_ROOTFS_MEMBER}"
        )
    if (
        args.artifact_class == release_policy.ARTIFACT_CLASS_PRODUCTION
        and not set(sources).issubset(
            release_policy.INSTALL_CUSTODY_SOURCE_LAYOUTS
        )
    ):
        raise _fail(
            "production install custody is proven only for braiins-aml-s19k; "
            "LuxOS needs its own authenticated owner/stop/restart protocol"
        )
    if (
        args.artifact_class == release_policy.ARTIFACT_CLASS_PRODUCTION
        and set(members)
        != {
            STAGE1_MEMBER,
            STAGE1_AUTHORIZER_MEMBER,
            CANONICAL_ROOTFS_MEMBER,
            *CUSTODY_MEMBER_BY_ROLE.values(),
        }
    ):
        extras = sorted(
            set(members)
            - {
                STAGE1_MEMBER,
                STAGE1_AUTHORIZER_MEMBER,
                CANONICAL_ROOTFS_MEMBER,
                *CUSTODY_MEMBER_BY_ROLE.values(),
            }
        )
        raise _fail(
            "production capsules admit exactly stage1, its target authorizer, "
            "the five install-custody members, and the canonical rootfs; "
            f"unreviewed extra payload members are forbidden: {extras}"
        )

    key_path = Path(args.key).expanduser() if args.key else None
    pubkey_path = Path(args.pubkey).expanduser() if args.pubkey else None
    selected_pubkey_hex = ""
    if pubkey_path is not None:
        if not pubkey_path.is_file() or pubkey_path.is_symlink():
            raise _fail(f"trusted public key is not a regular file: {pubkey_path}")
        try:
            selected_pubkey_hex = _public_key_hex(pubkey_path)
        except CapsuleBuildError as exc:
            raise _fail(str(exc))

    rootfs_path = members[CANONICAL_ROOTFS_MEMBER]
    persistent_receipt: dict[str, object] | None = None
    persistent_receipt_bytes: bytes | None = None
    source_snapshot: dict[str, object] | None = None
    stage1_sha = _sha256_file(members[STAGE1_MEMBER]) if members[STAGE1_MEMBER].is_file() else ""
    authorizer_sha = (
        _sha256_file(members[STAGE1_AUTHORIZER_MEMBER])
        if members[STAGE1_AUTHORIZER_MEMBER].is_file()
        else ""
    )
    stage1_approval = None
    authorizer_approval = None
    if args.artifact_class == release_policy.ARTIFACT_CLASS_PRODUCTION:
        if args.persistent_image_evidence_dir is None:
            raise _fail(
                "production capsules require --persistent-image-evidence-dir; "
                "a signed structural fixture is not a production image"
            )
        if pubkey_path is None or not selected_pubkey_hex:
            raise _fail("production capsules require an explicit trusted public key")
        pinned = get_pinned_release_pubkey_hex()
        if selected_pubkey_hex != pinned:
            raise _fail(
                "production signing identity does not equal the baked D-Central release pin"
            )
        stage1_approval = release_policy.approved_stage1(
            stage1_sha, WORKSPACE_ROOT
        )
        if stage1_approval is None:
            raise _fail(
                "production stage1 is not in the reviewed target-side approval "
                "registry; the host-side writer and synthetic no-I/O fixture are "
                "not valid stage1 implementations"
            )
        try:
            persistent_receipt, persistent_receipt_bytes = (
                _load_production_image_receipt(
                    args.persistent_image_evidence_dir.expanduser(),
                    rootfs_path,
                    pubkey_path,
                    selected_pubkey_hex,
                )
            )
        except CapsuleBuildError as exc:
            raise _fail(str(exc))
        if args.signing_key_id.strip() != persistent_receipt.get("release_key_id"):
            raise _fail(
                "production --signing-key-id does not exact-join the "
                "persistent-image release_key_id"
            )
        if not args.expected_source_commit:
            raise _fail(
                "production capsules require --expected-source-commit; mutable "
                "or unauthenticated source checkouts are not release inputs"
            )
        try:
            source_snapshot = _verified_source_snapshot(args.expected_source_commit)
        except CapsuleBuildError as exc:
            raise _fail(str(exc))
        if persistent_receipt.get("source_commit") != source_snapshot.get("commit"):
            raise _fail(
                "authenticated packager source commit differs from the "
                "persistent-image v4 source_commit"
            )
        authorizer_approval = release_policy.approved_stage1_authorizer(
            authorizer_sha,
            WORKSPACE_ROOT,
            str(source_snapshot["commit"]),
        )
        if authorizer_approval is None:
            raise _fail(
                "production stage1 authorizer is not in the reviewed target-KAT "
                "approval registry for this authenticated source commit; the "
                "dirty/unsigned desk binary is test-only"
            )
        members[PERSISTENT_IMAGE_MEMBER] = (
            args.persistent_image_evidence_dir.expanduser()
            / persistent_image.VERIFICATION_FILE
        )
    elif args.persistent_image_evidence_dir is not None:
        raise _fail(
            "test-fixture capsules must not claim production persistent-image evidence"
        )
    elif args.expected_source_commit is not None:
        raise _fail("test-fixture capsules must not claim a production source snapshot")
    if (
        args.artifact_class == release_policy.ARTIFACT_CLASS_TEST_FIXTURE
        and args.signing_authorization_receipt is not None
    ):
        raise _fail("test-fixture capsules must not consume production authorization")
    if args.emit_unsigned_manifest is not None and args.artifact_class != (
        release_policy.ARTIFACT_CLASS_PRODUCTION
    ):
        raise _fail("--emit-unsigned-manifest is production-only")
    if args.emit_unsigned_manifest is not None and args.plan:
        raise _fail("--emit-unsigned-manifest and --plan are mutually exclusive")

    checksums: dict[str, str] = {}
    total = 0
    for name in sorted(members):
        path = members[name]
        if not path.is_file():
            raise _fail(f"member file is missing or not a regular file: {path}")
        if path.is_symlink():
            raise _fail(f"member file is a symlink (refused): {path}")
        limit = (
            MAX_STAGE1_BYTES
            if name == STAGE1_MEMBER
            else (
                MAX_STAGE1_AUTHORIZER_BYTES
                if name == STAGE1_AUTHORIZER_MEMBER
                else MAX_MEMBER_BYTES
            )
        )
        size = path.stat().st_size
        if size <= 0:
            raise _fail(f"member file is empty: {path}")
        if size > limit:
            raise _fail(f"member exceeds its {limit}-byte bound: {name} ({size} bytes)")
        if name == PERSISTENT_IMAGE_MEMBER and persistent_receipt_bytes is not None:
            size = len(persistent_receipt_bytes)
            checksums[name] = hashlib.sha256(persistent_receipt_bytes).hexdigest()
        else:
            checksums[name] = _sha256_file(path)
        total += size
    # The NAND window bounds the image that will be written, not unrelated
    # custody/authorization members which merely coexist under target /tmp.
    if rootfs_path.stat().st_size > ROOTFS_WINDOW_BYTES:
        raise _fail(
            f"rootfs payload exceeds the mtd5 rootfs window "
            f"{ROOTFS_WINDOW_HEX} ({ROOTFS_WINDOW_BYTES} bytes): "
            f"{rootfs_path.stat().st_size}"
        )

    # The geometry block is EMITTED from the toolbox pins — the exact
    # mirror the inspector demands (never hand-entered, never weakened).
    nand_geometry = s19k_aml_geometry_pins()
    rootfs_sha = checksums[CANONICAL_ROOTFS_MEMBER]
    rootfs_bytes = rootfs_path.stat().st_size
    custody_descriptors = {
        role: {
            "member": member,
            "sha256": checksums[member],
            "bytes": members[member].stat().st_size,
        }
        for role, member in CUSTODY_MEMBER_BY_ROLE.items()
    }
    custody_identities = tuple(
        (
            str(item["member"]),
            str(item["sha256"]),
            int(item["bytes"]),
        )
        for item in sorted(
            custody_descriptors.values(), key=lambda value: str(value["member"])
        )
    )
    if (
        args.artifact_class == release_policy.ARTIFACT_CLASS_PRODUCTION
        and release_policy.approved_install_custody(
            release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID,
            custody_identities,
        )
        is None
    ):
        raise _fail(
            "production install-custody bundle is absent from or differs from "
            "the reviewed five-member approval registry"
        )
    counted_member_names = {
        CANONICAL_ROOTFS_MEMBER,
        STAGE1_MEMBER,
        STAGE1_AUTHORIZER_MEMBER,
        *CUSTODY_MEMBER_BY_ROLE.values(),
    }
    counted_members = [
        {
            "member": name,
            "sha256": checksums[name],
            "bytes": members[name].stat().st_size,
        }
        for name in sorted(counted_member_names)
    ]
    coexisting_capsule_member_bytes = sum(
        int(descriptor["bytes"]) for descriptor in counted_members
    )
    required_tmp_free_bytes = (
        coexisting_capsule_member_bytes
        + release_policy.TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES
        + release_policy.TARGET_STAGING_WORKING_FREE_RESERVE_BYTES
    )
    manifest = {
        "schema": CAPSULE_SCHEMA,
        "package_type": CAPSULE_PACKAGE_TYPE,
        "version": args.version,
        "board_target": board_target,
        "accepted_source_layouts": sources,
        "transition_mechanism": mechanism,
        "nand_geometry": nand_geometry,
        "post_install_artifact": args.post_install_artifact,
        "migration_scope": args.migration_scope.strip(),
        "artifact_class": args.artifact_class,
        "source_snapshot": source_snapshot,
        "production_image_attestation": (
            {
                "member": PERSISTENT_IMAGE_MEMBER,
                "verification_id": persistent_receipt["verification_id"],
                "image_member": CANONICAL_ROOTFS_MEMBER,
                "image_sha256": rootfs_sha,
                "image_bytes": rootfs_bytes,
                "release_key_sha256": persistent_receipt["release_key_sha256"],
                "release_manifest_public_key_hex": selected_pubkey_hex,
            }
            if persistent_receipt is not None
            else None
        ),
        "transition_stage1": {
            "schema": release_policy.STAGE1_SCHEMA,
            "member": STAGE1_MEMBER,
            "sha256": stage1_sha,
            "bytes": members[STAGE1_MEMBER].stat().st_size,
            "implementation_id": (
                stage1_approval.implementation_id
                if stage1_approval is not None
                else "test-fixture-no-production-authority"
            ),
            "audit_receipt_sha256": (
                stage1_approval.audit_receipt_sha256
                if stage1_approval is not None
                else None
            ),
        },
        "transition_stage1_authorizer": {
            "schema": release_policy.STAGE1_AUTHORIZER_SCHEMA,
            "member": STAGE1_AUTHORIZER_MEMBER,
            "sha256": authorizer_sha,
            "bytes": members[STAGE1_AUTHORIZER_MEMBER].stat().st_size,
            "implementation_id": (
                authorizer_approval.implementation_id
                if authorizer_approval is not None
                else "test-fixture-no-production-authority"
            ),
            "target_kat_verified": authorizer_approval is not None,
            "source_snapshot_commit": (
                authorizer_approval.source_snapshot_commit
                if authorizer_approval is not None
                else None
            ),
        },
        "install_custody": {
            "schema": release_policy.INSTALL_CUSTODY_SCHEMA,
            "implementation_id": release_policy.INSTALL_CUSTODY_IMPLEMENTATION_ID,
            "protocol": release_policy.INSTALL_CUSTODY_PROTOCOL,
            "mode": release_policy.INSTALL_CUSTODY_MODE,
            "daemon_flag": release_policy.INSTALL_CUSTODY_DAEMON_FLAG,
            "physical_safeoff_contract": (
                release_policy.INSTALL_CUSTODY_PHYSICAL_SAFEOFF_CONTRACT
            ),
            "reset_contract": release_policy.INSTALL_CUSTODY_RESET_CONTRACT,
            "transcript_schema": release_policy.INSTALL_CUSTODY_TRANSCRIPT_SCHEMA,
            "terminal_receipt_schema": (
                release_policy.INSTALL_CUSTODY_TERMINAL_RECEIPT_SCHEMA
            ),
            "safeoff_receipt_schema": (
                release_policy.INSTALL_CUSTODY_SAFEOFF_RECEIPT_SCHEMA
            ),
            "pending_receipt_schema": (
                release_policy.INSTALL_CUSTODY_PENDING_RECEIPT_SCHEMA
            ),
            "target_reference_config_path": (
                release_policy.INSTALL_CUSTODY_TARGET_REFERENCE_CONFIG_PATH
            ),
            "staged_config_basename": (
                release_policy.INSTALL_CUSTODY_STAGED_CONFIG_BASENAME
            ),
            "source_layouts": list(release_policy.INSTALL_CUSTODY_SOURCE_LAYOUTS),
            "target_identity_profiles": list(
                release_policy.INSTALL_CUSTODY_TARGET_IDENTITY_PROFILES
            ),
            **custody_descriptors,
        },
        "target_staging_budget": {
            "schema": release_policy.TARGET_STAGING_BUDGET_SCHEMA,
            "rootfs_readback_mode": (
                release_policy.TARGET_STAGING_ROOTFS_READBACK_MODE
            ),
            "counted_members": counted_members,
            "coexisting_capsule_member_bytes": coexisting_capsule_member_bytes,
            "per_unit_inputs_budget_bytes": (
                release_policy.TARGET_STAGING_PER_UNIT_INPUTS_BUDGET_BYTES
            ),
            "working_free_reserve_bytes": (
                release_policy.TARGET_STAGING_WORKING_FREE_RESERVE_BYTES
            ),
            "required_tmp_free_bytes": required_tmp_free_bytes,
        },
        "signing_identity": {
            "profile": (
                release_policy.SIGNING_PROFILE_PRODUCTION
                if args.artifact_class == release_policy.ARTIFACT_CLASS_PRODUCTION
                else release_policy.SIGNING_PROFILE_TEST
            ),
            "key_id": args.signing_key_id.strip(),
            "public_key_hex": selected_pubkey_hex or None,
        },
        "checksums": checksums,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    output = (args.output or Path(_default_output_name(args.version))).expanduser()

    if args.emit_unsigned_manifest is not None:
        try:
            _write_no_replace(args.emit_unsigned_manifest.expanduser(), manifest_bytes)
        except CapsuleBuildError as exc:
            raise _fail(str(exc))
        payload = {
            "mode": "unsigned-manifest-emitted",
            "manifest": str(args.emit_unsigned_manifest.expanduser()),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "manifest_bytes": len(manifest_bytes),
            "expected_capsule_name": output.name,
            "private_key_read": False,
            "authority_granted": False,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if args.plan:
        plan = {
            "mode": "plan",
            "output": str(output),
            "board_target": board_target,
            "accepted_source_layouts": sources,
            "transition_mechanism": mechanism,
            "rootfs_window_hex": ROOTFS_WINDOW_HEX,
            "rootfs_window_bytes": ROOTFS_WINDOW_BYTES,
            "payload_bytes_total": total,
            "sources": [
                {
                    "source_layout": source,
                    "label": facts[source]["label"],
                    "dialect_proven": facts[source]["dialect_proven"],
                }
                for source in sources
            ],
            "members": [
                {"name": name, "bytes": members[name].stat().st_size, "sha256": checksums[name]}
                for name in sorted(members)
            ],
            "manifest": manifest,
            "artifact_class": args.artifact_class,
            "signing": {
                "profile": manifest["signing_identity"]["profile"],
                "key_id": args.signing_key_id.strip(),
                "public_key_hex": selected_pubkey_hex or "(not configured)",
                "signer": str(SCRIPT_DIR / "sign_release_artifact.py"),
            },
        }
        print(json.dumps(plan, indent=2))
        return 0

    if output.exists() or output.is_symlink():
        raise _fail(f"output already exists (no-replace): {output}")
    if args.artifact_class == release_policy.ARTIFACT_CLASS_PRODUCTION:
        if args.signing_authorization_receipt is None:
            raise _fail(
                "production signing requires preauthorization via "
                "--signing-authorization-receipt created before the signature"
            )
        try:
            signing_ceremony.verify_authorization(
                args.signing_authorization_receipt.expanduser(),
                manifest_bytes,
                output.name,
            )
        except (OSError, ValueError) as exc:
            raise _fail(f"production signing preauthorization failed: {exc}")
        if (
            persistent_receipt is None
            or persistent_receipt.get("isolated_post_ab_signing_verified")
            is not True
        ):
            raise _fail(
                release_policy.PERSISTENT_IMAGE_PRODUCTION_SIGNER_BOUNDARY_REFUSAL
            )
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

    # Snapshot every signed payload into memory before the signer runs. The
    # same bytes are used for the archive, closing a path-substitution/change
    # race between manifest hashing, signature creation, and tar assembly.
    payload_files: dict[str, bytes] = {}
    for name in members:
        data = (
            persistent_receipt_bytes
            if name == PERSISTENT_IMAGE_MEMBER
            and persistent_receipt_bytes is not None
            else members[name].read_bytes()
        )
        if len(data) != members[name].stat().st_size or hashlib.sha256(
            data
        ).hexdigest() != checksums[name]:
            raise _fail(f"member changed after manifest construction: {name}")
        payload_files[name] = data

    with tempfile.TemporaryDirectory(prefix="s19k-aml-transition-") as staging_raw:
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
        files.update(payload_files)
        capsule_bytes = _deterministic_tar(files)

        # write no-replace: create exclusively, then fsync (O_BINARY is
        # Windows-only; absent and unnecessary on the WSL/Linux runtime)
        try:
            _write_no_replace(output, capsule_bytes)
        except CapsuleBuildError as exc:
            raise _fail(str(exc))

    payload = {
        "mode": "built",
        "capsule": str(output),
        "bytes": len(capsule_bytes),
        "sha256": hashlib.sha256(capsule_bytes).hexdigest(),
        "board_target": board_target,
        "accepted_source_layouts": sources,
        "transition_mechanism": mechanism,
        "nand_geometry": {
            "mtd5_base_hex": nand_geometry["mtd5_base_hex"],
            "rootfs_local_offset_hex": nand_geometry["rootfs_local_offset_hex"],
            "rootfs_window_hex": nand_geometry["rootfs_window_hex"],
            "recovery_flag_local_offset_hex": nand_geometry["recovery_flag_local_offset_hex"],
        },
        "version": args.version,
        "artifact_class": args.artifact_class,
        "signing_identity": manifest["signing_identity"],
        "production_image_attestation": manifest["production_image_attestation"],
        "members": sorted(members),
        "payload_bytes": total,
        "verify_command": f"dcent s19k-aml-first-install inspect --capsule {output}",
    }
    print(json.dumps(payload, indent=2) if args.json else (
        f"Built capsule: {output}\n"
        f"  board: {board_target} | sources: {', '.join(sources)} | mechanism: {mechanism}\n"
        f"  version: {args.version} | members: {', '.join(sorted(members))}\n"
        f"  geometry: mtd5 window {nand_geometry['rootfs_local_offset_hex']}"
        f" + {nand_geometry['rootfs_window_hex']} | payload {total} bytes"
        f" | sha256: {payload['sha256']}\n"
        f"  verify: dcent s19k-aml-first-install inspect --capsule {output}"
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
