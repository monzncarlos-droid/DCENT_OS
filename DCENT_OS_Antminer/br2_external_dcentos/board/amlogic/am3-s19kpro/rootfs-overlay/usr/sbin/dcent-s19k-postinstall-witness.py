#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only

"""Fail-closed S19k first-boot witness signer and SSH-key admission helper.

This helper is the image-side half of the S19k post-install witness contract.
It deliberately cannot create its own install authority.  A separately
reviewed pre-install/stage1 transport must place an exact release-signed scope,
host-issued challenge, target-generated witness private key, and terminal
stage1 receipt in the persistent inbox.  Missing or mismatched inputs leave
SSH closed.

The helper performs no NAND, GPIO, process-control, network, or reboot action.
Its only mutations are credential/witness files below /data and the ephemeral
/root/.ssh/authorized_keys view needed by Dropbear.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final, Mapping, Optional, Sequence


BOARD_TARGET: Final = "am3-s19kpro"
RUNTIME_BOARD_TARGET: Final = "am3-s19k"
RUNTIME_PLATFORM: Final = "am3-aml-s19k"
SOURCE_LAYOUT: Final = "braiins-aml-s19k"
TARGET_IDENTITY_PROFILE: Final = "live88_two_bhb56903_slots_2_3"
HOST_KEY_ALGORITHM: Final = "ssh-ed25519"

SCOPE_SCHEMA: Final = "dcentos.s19k-postinstall-witness-scope/v1"
CHALLENGE_SCHEMA: Final = "dcentos.s19k-postinstall-witness-challenge/v1"
RESPONSE_SCHEMA: Final = "dcentos.s19k-postinstall-witness-response/v1"
STAGE1_RECEIPT_SCHEMA: Final = "dcentos.s19k-stage1-receipt/v1"
HOST_KEY_CLAIM_SCHEMA: Final = "dcentos.s19k-postinstall-host-key-claim/v1"
SIGNING_CLAIM_SCHEMA: Final = "dcentos.s19k-postinstall-target-signing-claim/v1"
ADMISSION_SCHEMA: Final = "dcentos.s19k-postinstall-target-admission/v1"
CONTRACT_SCHEMA: Final = "dcentos.s19k-postinstall-target-contract/v1"

MAX_SCOPE_LIFETIME_SECONDS: Final = 24 * 60 * 60
MAX_CHALLENGE_TTL_SECONDS: Final = 10 * 60
MAX_JSON_BYTES: Final = 16 * 1024
UTC_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
OBSERVER_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,127}")
ED25519_SPKI_PREFIX: Final = bytes.fromhex("302a300506032b6570032100")
SSH_ED25519_NAME: Final = b"ssh-ed25519"
DATA_MOUNT_HELPER: Final = "/usr/sbin/dcent-s19k-data-mount"

CommandRunner = Callable[[Sequence[str], Optional[bytes]], bytes]


class TargetWitnessError(RuntimeError):
    """Terminal target-side witness, custody, or exact-join refusal."""


@dataclass(frozen=True)
class TargetPaths:
    state_root: Path
    release_marker: Path
    board_target: Path
    platform: Path
    release_public_key: Path
    boot_id: Path
    dcent_dir: Path
    root_ssh_dir: Path

    @classmethod
    def production(cls) -> "TargetPaths":
        return cls(
            state_root=Path("/data/dcent/s19k-postinstall-witness"),
            release_marker=Path("/etc/dcentos/release-image"),
            board_target=Path("/etc/dcentos/board_target"),
            platform=Path("/etc/dcentos/platform"),
            release_public_key=Path("/etc/dcentos/release_ed25519.pub"),
            boot_id=Path("/proc/sys/kernel/random/boot_id"),
            dcent_dir=Path("/data/dcent"),
            root_ssh_dir=Path("/root/.ssh"),
        )

    @property
    def inbox(self) -> Path:
        return self.state_root / "inbox"

    @property
    def outbox(self) -> Path:
        return self.state_root / "outbox"

    @property
    def host_key(self) -> Path:
        return self.state_root / "dropbear_ed25519_host_key"

    @property
    def host_key_claim(self) -> Path:
        return self.state_root / "host-key-generation.claim.json"

    @property
    def signing_claim(self) -> Path:
        return self.state_root / "target-signing.claim.json"

    @property
    def admission(self) -> Path:
        return self.state_root / "ssh-admitted.json"

    @property
    def persistent_authorized_keys(self) -> Path:
        return self.dcent_dir / "authorized_keys"

    @property
    def ssh_enabled(self) -> Path:
        return self.dcent_dir / ".ssh-enabled"

    @property
    def ssh_disabled(self) -> Path:
        return self.dcent_dir / ".ssh-disabled"

    @property
    def root_authorized_keys(self) -> Path:
        return self.root_ssh_dir / "authorized_keys"


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_hex(value: object, byte_count: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 2 * byte_count
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
        or set(value) == {"0"}
    ):
        raise TargetWitnessError(f"{label} must be nonzero lowercase {byte_count}-byte hex")
    return value


def _require_sha256(value: object, label: str) -> str:
    return _require_hex(value, 32, label)


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise TargetWitnessError(f"{label} must be canonical RFC3339-Z")
    try:
        parsed = datetime.strptime(value, UTC_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TargetWitnessError(f"{label} must be canonical RFC3339-Z") from exc
    if parsed.strftime(UTC_FORMAT) != value:
        raise TargetWitnessError(f"{label} must be canonical RFC3339-Z")
    return parsed


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise TargetWitnessError("UTC time must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(UTC_FORMAT)


def _load_canonical_json(raw: bytes, label: str) -> dict[str, object]:
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise TargetWitnessError(f"{label} is missing or oversized")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetWitnessError(f"{label} is not ASCII JSON") from exc
    if not isinstance(value, dict) or raw != _canonical_json(value):
        raise TargetWitnessError(f"{label} is not canonical JSON")
    return value


def _mode(path_stat: os.stat_result) -> int:
    return stat.S_IMODE(path_stat.st_mode)


def _require_directory(
    path: Path,
    *,
    label: str,
    expected_uid: Optional[int],
    mode: int = 0o700,
) -> None:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise TargetWitnessError(f"{label} directory is missing") from exc
    if not stat.S_ISDIR(observed.st_mode) or path.is_symlink():
        raise TargetWitnessError(f"{label} is not a direct directory")
    if expected_uid is not None and observed.st_uid != expected_uid:
        raise TargetWitnessError(f"{label} is not owned by uid {expected_uid}")
    if _mode(observed) != mode:
        raise TargetWitnessError(f"{label} mode is not {mode:04o}")


def _mkdir_new(path: Path, *, expected_uid: Optional[int]) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _require_directory(path, label=str(path), expected_uid=expected_uid)


def _read_regular(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    expected_uid: Optional[int],
    allowed_modes: tuple[int, ...],
) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TargetWitnessError(f"{label} is missing") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_nlink != 1:
        raise TargetWitnessError(f"{label} is not a direct single-link regular file")
    if expected_uid is not None and before.st_uid != expected_uid:
        raise TargetWitnessError(f"{label} is not owned by uid {expected_uid}")
    if _mode(before) not in allowed_modes:
        raise TargetWitnessError(f"{label} has unsafe mode {_mode(before):04o}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise TargetWitnessError(f"{label} could not be pinned") from exc
    try:
        pinned = os.fstat(descriptor)
        if (pinned.st_dev, pinned.st_ino, pinned.st_nlink) != (
            before.st_dev,
            before.st_ino,
            1,
        ):
            raise TargetWitnessError(f"{label} changed while being pinned")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise TargetWitnessError(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise TargetWitnessError(f"{label} changed while being read")
        return payload
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _write_new(path: Path, payload: bytes, *, label: str, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise TargetWitnessError(f"{label} already exists; refusing replacement")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(str(path), flags, mode)
    except FileExistsError as exc:
        raise TargetWitnessError(f"{label} already exists; refusing replacement") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # A partial authority artifact is terminal evidence. Never unlink it.
        raise
    _fsync_directory(path.parent)


def _ensure_exact_file(
    path: Path,
    payload: bytes,
    *,
    label: str,
    expected_uid: Optional[int],
    mode: int = 0o600,
) -> None:
    if path.exists() or path.is_symlink():
        observed = _read_regular(
            path,
            label=label,
            max_bytes=max(len(payload), 1) + 1,
            expected_uid=expected_uid,
            allowed_modes=(mode,),
        )
        if observed != payload:
            raise TargetWitnessError(f"{label} differs from the admitted bytes")
        return
    _write_new(path, payload, label=label, mode=mode)


def _default_runner(args: Sequence[str], input_data: Optional[bytes]) -> bytes:
    try:
        completed = subprocess.run(
            list(args),
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TargetWitnessError(f"required command failed to execute: {args[0]}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()[:240]
        raise TargetWitnessError(f"{args[0]} refused target witness operation: {detail}")
    return completed.stdout


def _require_durable_data_mount(runner: CommandRunner) -> None:
    """Re-admit the exact persistent mtd4/UBI mount before state access."""

    runner([DATA_MOUNT_HELPER, "verify"], None)


def _extract_spki_raw(der: bytes, label: str) -> bytes:
    if len(der) != len(ED25519_SPKI_PREFIX) + 32 or not der.startswith(ED25519_SPKI_PREFIX):
        raise TargetWitnessError(f"{label} is not exact Ed25519 SubjectPublicKeyInfo")
    raw = der[len(ED25519_SPKI_PREFIX) :]
    if raw == b"\x00" * 32:
        raise TargetWitnessError(f"{label} Ed25519 key is all zero")
    return raw


def _public_from_private(
    private_key: Path, runner: CommandRunner
) -> tuple[bytes, bytes]:
    der = runner(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"],
        None,
    )
    pem = runner(["openssl", "pkey", "-in", str(private_key), "-pubout"], None)
    return _extract_spki_raw(der, "witness private key"), pem


def _release_public_raw(release_key: Path, runner: CommandRunner) -> bytes:
    der = runner(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-in",
            str(release_key),
            "-outform",
            "DER",
        ],
        None,
    )
    return _extract_spki_raw(der, "release public key")


def _verify_signature(
    public_key: Path,
    signature: Path,
    message: bytes,
    runner: CommandRunner,
) -> None:
    runner(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_key),
            "-sigfile",
            str(signature),
        ],
        message,
    )


def _sign(private_key: Path, message: bytes, runner: CommandRunner) -> bytes:
    signature = runner(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key)],
        message,
    )
    if len(signature) != 64:
        raise TargetWitnessError("target witness signer did not emit an exact Ed25519 signature")
    return signature


SCOPE_KEYS: Final = frozenset(
    {
        "schema",
        "board_target",
        "source_layout",
        "target_identity_profile",
        "capsule_sha256",
        "rootfs_sha256",
        "unit_identity_sha256",
        "preinstall_host_key_algorithm",
        "preinstall_host_key_sha256",
        "install_scope_id",
        "install_request_sha256",
        "witness_key_mode",
        "witness_public_key_hex",
        "authorized_client_public_key_hex",
        "first_boot_host_key_mode",
        "expected_first_boot_host_key_public_hex",
        "authorized_utc",
        "expires_utc",
        "release_private_key_loaded_by_toolbox",
        "authorizes_install",
        "authorizes_reboot",
        "scope_id",
    }
)


def _validate_scope(scope: Mapping[str, object]) -> None:
    if set(scope) != SCOPE_KEYS or scope.get("schema") != SCOPE_SCHEMA:
        raise TargetWitnessError("witness scope key set or schema is not exact v1")
    exact = {
        "board_target": BOARD_TARGET,
        "source_layout": SOURCE_LAYOUT,
        "target_identity_profile": TARGET_IDENTITY_PROFILE,
        "preinstall_host_key_algorithm": HOST_KEY_ALGORITHM,
        "witness_key_mode": "target-generated-ed25519-private-never-exported",
    }
    for name, expected in exact.items():
        if scope.get(name) != expected:
            raise TargetWitnessError(f"witness scope {name} is not exact")
    for name in (
        "capsule_sha256",
        "rootfs_sha256",
        "unit_identity_sha256",
        "preinstall_host_key_sha256",
        "install_scope_id",
        "install_request_sha256",
    ):
        _require_sha256(scope.get(name), name)
    witness = _require_hex(scope.get("witness_public_key_hex"), 32, "witness_public_key_hex")
    client = _require_hex(
        scope.get("authorized_client_public_key_hex"),
        32,
        "authorized_client_public_key_hex",
    )
    if witness == client:
        raise TargetWitnessError("witness and client keys must be independent")
    preinstall_sha = str(scope["preinstall_host_key_sha256"])
    for label, key_hex in (("witness", witness), ("client", client)):
        if _sha256(bytes.fromhex(key_hex)) == preinstall_sha:
            raise TargetWitnessError(f"{label} key reuses the preinstall host identity")
    expected_host = scope.get("expected_first_boot_host_key_public_hex")
    mode = scope.get("first_boot_host_key_mode")
    if expected_host is None:
        if mode != "signed-firstboot-binding":
            raise TargetWitnessError("deferred first-boot host-key mode mismatch")
    else:
        host = _require_hex(expected_host, 32, "expected_first_boot_host_key_public_hex")
        if mode != "preprovisioned-exact" or host in {witness, client}:
            raise TargetWitnessError("preprovisioned first-boot host-key role mismatch")
        if _sha256(bytes.fromhex(host)) == preinstall_sha:
            raise TargetWitnessError("first-boot host key reuses preinstall identity")
    authorized = _parse_utc(scope.get("authorized_utc"), "authorized_utc")
    expires = _parse_utc(scope.get("expires_utc"), "expires_utc")
    lifetime = int((expires - authorized).total_seconds())
    if lifetime <= 0 or lifetime > MAX_SCOPE_LIFETIME_SECONDS:
        raise TargetWitnessError("witness scope lifetime is empty or over 24 hours")
    if scope.get("release_private_key_loaded_by_toolbox") is not False:
        raise TargetWitnessError("Toolbox release-private-key claim is unsafe")
    if scope.get("authorizes_install") is not False or scope.get("authorizes_reboot") is not False:
        raise TargetWitnessError("witness scope must not authorize install or reboot")
    scope_id = _require_sha256(scope.get("scope_id"), "scope_id")
    unsigned = dict(scope)
    unsigned.pop("scope_id")
    if scope_id != _sha256(_canonical_json(unsigned)):
        raise TargetWitnessError("witness scope_id does not self-bind")


CHALLENGE_KEYS: Final = frozenset(
    {
        "schema",
        "scope_id",
        "capsule_sha256",
        "rootfs_sha256",
        "unit_identity_sha256",
        "preinstall_host_key_sha256",
        "witness_public_key_hex",
        "authorized_client_public_key_hex",
        "observer_id",
        "nonce_hex",
        "issued_utc",
        "expires_utc",
        "authorizes_reboot",
        "authorizes_mutation",
        "challenge_id",
    }
)


def _validate_challenge(challenge: Mapping[str, object]) -> None:
    if set(challenge) != CHALLENGE_KEYS or challenge.get("schema") != CHALLENGE_SCHEMA:
        raise TargetWitnessError("witness challenge key set or schema is not exact v1")
    for name in (
        "scope_id",
        "capsule_sha256",
        "rootfs_sha256",
        "unit_identity_sha256",
        "preinstall_host_key_sha256",
    ):
        _require_sha256(challenge.get(name), name)
    for name in ("witness_public_key_hex", "authorized_client_public_key_hex", "nonce_hex"):
        _require_hex(challenge.get(name), 32, name)
    observer = challenge.get("observer_id")
    if not isinstance(observer, str) or OBSERVER_RE.fullmatch(observer) is None:
        raise TargetWitnessError("observer_id is not a bounded stable identifier")
    issued = _parse_utc(challenge.get("issued_utc"), "issued_utc")
    expires = _parse_utc(challenge.get("expires_utc"), "expires_utc")
    ttl = int((expires - issued).total_seconds())
    if ttl <= 0 or ttl > MAX_CHALLENGE_TTL_SECONDS:
        raise TargetWitnessError("challenge TTL is empty or over ten minutes")
    if challenge.get("authorizes_reboot") is not False or challenge.get("authorizes_mutation") is not False:
        raise TargetWitnessError("challenge must not authorize reboot or mutation")
    challenge_id = _require_sha256(challenge.get("challenge_id"), "challenge_id")
    unsigned = dict(challenge)
    unsigned.pop("challenge_id")
    if challenge_id != _sha256(_canonical_json(unsigned)):
        raise TargetWitnessError("challenge_id does not self-bind")


def _join_challenge(scope: Mapping[str, object], challenge: Mapping[str, object]) -> None:
    joins = {
        "scope_id": scope["scope_id"],
        "capsule_sha256": scope["capsule_sha256"],
        "rootfs_sha256": scope["rootfs_sha256"],
        "unit_identity_sha256": scope["unit_identity_sha256"],
        "preinstall_host_key_sha256": scope["preinstall_host_key_sha256"],
        "witness_public_key_hex": scope["witness_public_key_hex"],
        "authorized_client_public_key_hex": scope["authorized_client_public_key_hex"],
    }
    for name, expected in joins.items():
        if challenge.get(name) != expected:
            raise TargetWitnessError(f"challenge {name} does not join release-signed scope")


def _validate_stage1_receipt(
    receipt: Mapping[str, object], scope: Mapping[str, object]
) -> None:
    exact = {
        "schema": STAGE1_RECEIPT_SCHEMA,
        "board_target": BOARD_TARGET,
        "source_layout": SOURCE_LAYOUT,
        "scope_id": scope["install_scope_id"],
        "request_sha256": scope["install_request_sha256"],
        "capsule_sha256": scope["capsule_sha256"],
        "rootfs_sha256": scope["rootfs_sha256"],
        "rootfs_readback_sha256": scope["rootfs_sha256"],
        "identity_record_sha256": scope["unit_identity_sha256"],
        "state": "installed_commit_verified_no_reboot",
        "terminal": True,
        "simulation": False,
        "clear_for_flash_internal": True,
        "clear_for_flash_request": True,
        "writes_authorized": True,
        "authorization_verified": True,
        "stage1_authorizer_verified": True,
        "stage1_authorizer_target_kat_verified": True,
        "transferred_inputs_verified": True,
        "identity_verified": True,
        "geometry_verified": True,
        "zero_bad_blocks_verified": True,
        "safeoff_verified": True,
        "mutation_started": True,
        "nand_erase_performed": True,
        "nand_write_performed": True,
        "install_commit_verified": True,
        "postboot_proof_required": True,
        "restore_required": False,
        "recovery_flag_readback": 1,
    }
    for name, expected in exact.items():
        if receipt.get(name) != expected:
            raise TargetWitnessError(f"stage1 receipt {name} is not terminal install proof")
    rootfs_bytes = receipt.get("rootfs_bytes")
    if (
        not isinstance(rootfs_bytes, int)
        or isinstance(rootfs_bytes, bool)
        or rootfs_bytes <= 0
        or receipt.get("rootfs_readback_bytes") != rootfs_bytes
    ):
        raise TargetWitnessError("stage1 receipt rootfs byte/readback join failed")


def _ssh_blob_public_hex(output: bytes) -> str:
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TargetWitnessError("dropbearkey public output is not ASCII") from exc
    candidates = [line.strip() for line in text.splitlines() if line.startswith("ssh-ed25519 ")]
    if len(candidates) != 1:
        raise TargetWitnessError("dropbearkey did not emit exactly one ssh-ed25519 public key")
    fields = candidates[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise TargetWitnessError("dropbearkey public key line is malformed")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TargetWitnessError("dropbearkey public key blob is invalid base64") from exc

    def take_string(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            raise TargetWitnessError("dropbearkey SSH blob is truncated")
        length = struct.unpack(">I", blob[offset : offset + 4])[0]
        start = offset + 4
        end = start + length
        if end > len(blob):
            raise TargetWitnessError("dropbearkey SSH blob field is truncated")
        return blob[start:end], end

    algorithm, cursor = take_string(0)
    public, cursor = take_string(cursor)
    if algorithm != SSH_ED25519_NAME or len(public) != 32 or cursor != len(blob):
        raise TargetWitnessError("dropbearkey SSH blob is not exact Ed25519")
    return _require_hex(public.hex(), 32, "first_boot_host_key_public_hex")


def _authorized_keys_line(public_hex: str) -> bytes:
    public = bytes.fromhex(_require_hex(public_hex, 32, "authorized_client_public_key_hex"))
    blob = (
        struct.pack(">I", len(SSH_ED25519_NAME))
        + SSH_ED25519_NAME
        + struct.pack(">I", len(public))
        + public
    )
    return b"ssh-ed25519 " + base64.b64encode(blob) + b" dcent-s19k-postinstall\n"


def _read_identity_text(
    path: Path,
    expected: str,
    label: str,
    expected_uid: Optional[int],
) -> None:
    raw = _read_regular(
        path,
        label=label,
        max_bytes=256,
        expected_uid=expected_uid,
        allowed_modes=(0o444, 0o644),
    )
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise TargetWitnessError(f"{label} is not ASCII") from exc
    if value != expected:
        raise TargetWitnessError(f"{label} is not exact S19k runtime identity")


def _require_runtime_identity(paths: TargetPaths, expected_uid: Optional[int]) -> None:
    _require_directory(paths.dcent_dir, label="persistent dcent state", expected_uid=expected_uid)
    marker = _read_regular(
        paths.release_marker,
        label="release-image marker",
        max_bytes=1024,
        expected_uid=expected_uid,
        allowed_modes=(0o444, 0o644),
    )
    if b"release_image=1\n" not in marker:
        raise TargetWitnessError("release-image marker is not canonical release posture")
    _read_identity_text(paths.board_target, RUNTIME_BOARD_TARGET, "board_target", expected_uid)
    _read_identity_text(paths.platform, RUNTIME_PLATFORM, "platform", expected_uid)


def _load_inputs(
    paths: TargetPaths,
    runner: CommandRunner,
    expected_uid: Optional[int],
) -> tuple[
    dict[str, object],
    bytes,
    dict[str, object],
    bytes,
    dict[str, object],
    bytes,
    Path,
    bytes,
]:
    _require_directory(paths.state_root, label="witness state", expected_uid=expected_uid)
    _require_directory(paths.inbox, label="witness inbox", expected_uid=expected_uid)
    expected_entries = {
        "scope.json",
        "scope.sig",
        "challenge.json",
        "witness-private.pem",
        "stage1-install-receipt.json",
    }
    observed_entries = {entry.name for entry in os.scandir(paths.inbox)}
    if observed_entries != expected_entries:
        raise TargetWitnessError("witness inbox member set is not exact v1")

    scope_raw = _read_regular(
        paths.inbox / "scope.json",
        label="witness scope",
        max_bytes=MAX_JSON_BYTES,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    signature = _read_regular(
        paths.inbox / "scope.sig",
        label="witness scope signature",
        max_bytes=64,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    if len(signature) != 64:
        raise TargetWitnessError(
            "witness scope signature must be exactly 64 raw bytes "
            f"(observed {len(signature)})"
        )
    challenge_raw = _read_regular(
        paths.inbox / "challenge.json",
        label="witness challenge",
        max_bytes=MAX_JSON_BYTES,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    receipt_raw = _read_regular(
        paths.inbox / "stage1-install-receipt.json",
        label="stage1 install receipt",
        max_bytes=MAX_JSON_BYTES,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    private_key = paths.inbox / "witness-private.pem"
    _read_regular(
        private_key,
        label="target witness private key",
        max_bytes=4096,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )

    scope = _load_canonical_json(scope_raw, "witness scope")
    challenge = _load_canonical_json(challenge_raw, "witness challenge")
    receipt = _load_canonical_json(receipt_raw, "stage1 install receipt")
    _validate_scope(scope)
    _validate_challenge(challenge)
    _join_challenge(scope, challenge)
    _validate_stage1_receipt(receipt, scope)

    _read_regular(
        paths.release_public_key,
        label="release public key",
        max_bytes=4096,
        expected_uid=expected_uid,
        allowed_modes=(0o444, 0o644),
    )
    release_raw = _release_public_raw(paths.release_public_key, runner)
    if release_raw == bytes.fromhex(str(scope["witness_public_key_hex"])):
        raise TargetWitnessError("release and target witness key roles are reused")
    _verify_signature(
        paths.release_public_key,
        paths.inbox / "scope.sig",
        scope_raw,
        runner,
    )
    witness_raw, witness_pem = _public_from_private(private_key, runner)
    if witness_raw.hex() != scope["witness_public_key_hex"]:
        raise TargetWitnessError("target witness private key does not join release-signed scope")
    return (
        scope,
        scope_raw,
        challenge,
        challenge_raw,
        receipt,
        receipt_raw,
        private_key,
        witness_pem,
    )


def _admit_host_key(
    paths: TargetPaths,
    scope: Mapping[str, object],
    challenge: Mapping[str, object],
    runner: CommandRunner,
    expected_uid: Optional[int],
) -> str:
    claim = {
        "schema": HOST_KEY_CLAIM_SCHEMA,
        "scope_id": scope["scope_id"],
        "challenge_id": challenge["challenge_id"],
        "key_algorithm": HOST_KEY_ALGORITHM,
        "key_path": "dropbear_ed25519_host_key",
        "one_key_only": True,
        "authorizes_install": False,
        "authorizes_reboot": False,
    }
    claim_raw = _canonical_json(claim)
    if paths.host_key_claim.exists() or paths.host_key_claim.is_symlink():
        observed = _read_regular(
            paths.host_key_claim,
            label="host-key generation claim",
            max_bytes=MAX_JSON_BYTES,
            expected_uid=expected_uid,
            allowed_modes=(0o600,),
        )
        if observed != claim_raw:
            raise TargetWitnessError("host-key generation claim does not join this scope")
        if not paths.host_key.exists():
            raise TargetWitnessError("host-key generation was claimed but no key was retained")
    else:
        if paths.host_key.exists() or paths.host_key.is_symlink():
            raise TargetWitnessError("unclaimed first-boot host key already exists")
        _write_new(paths.host_key_claim, claim_raw, label="host-key generation claim")
        runner(
            ["dropbearkey", "-t", "ed25519", "-f", str(paths.host_key)],
            None,
        )
    _read_regular(
        paths.host_key,
        label="first-boot Dropbear host key",
        max_bytes=4096,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    public_hex = _ssh_blob_public_hex(
        runner(["dropbearkey", "-y", "-f", str(paths.host_key)], None)
    )
    witness = str(scope["witness_public_key_hex"])
    client = str(scope["authorized_client_public_key_hex"])
    if public_hex in {witness, client}:
        raise TargetWitnessError("first-boot host key reuses witness/client key role")
    if _sha256(bytes.fromhex(public_hex)) == scope["preinstall_host_key_sha256"]:
        raise TargetWitnessError("first-boot host key reuses preinstall host identity")
    expected_host = scope.get("expected_first_boot_host_key_public_hex")
    if expected_host is not None and public_hex != expected_host:
        raise TargetWitnessError("first-boot host key differs from release-signed exact pin")
    return public_hex


RESPONSE_KEYS: Final = frozenset(
    {
        "schema",
        "challenge_id",
        "scope_id",
        "capsule_sha256",
        "rootfs_sha256",
        "unit_identity_sha256",
        "preinstall_host_key_sha256",
        "witness_public_key_hex",
        "authorized_client_public_key_hex",
        "challenge_nonce_hex",
        "observed_board_target",
        "observed_target_identity_profile",
        "first_boot_host_key_algorithm",
        "first_boot_host_key_public_hex",
        "boot_id_sha256",
        "stage1_install_receipt_sha256",
        "release_image_marker_observed",
        "ssh_gate_state",
        "postinstall_state",
        "reboot_initiated_by_witness",
        "mutation_performed_by_witness",
    }
)


def build_response_payload(
    scope: Mapping[str, object],
    challenge: Mapping[str, object],
    *,
    first_boot_host_key_public_hex: str,
    boot_id_sha256: str,
    stage1_install_receipt_sha256: str,
) -> bytes:
    """Reproduce the host contract's exact canonical response bytes."""

    _validate_scope(scope)
    _validate_challenge(challenge)
    _join_challenge(scope, challenge)
    host = _require_hex(first_boot_host_key_public_hex, 32, "first_boot_host_key_public_hex")
    _require_sha256(boot_id_sha256, "boot_id_sha256")
    _require_sha256(stage1_install_receipt_sha256, "stage1_install_receipt_sha256")
    if host in {
        scope["witness_public_key_hex"],
        scope["authorized_client_public_key_hex"],
    }:
        raise TargetWitnessError("first-boot host key reuses witness/client key role")
    if _sha256(bytes.fromhex(host)) == scope["preinstall_host_key_sha256"]:
        raise TargetWitnessError("first-boot host key reuses preinstall host identity")
    response = {
        "schema": RESPONSE_SCHEMA,
        "challenge_id": challenge["challenge_id"],
        "scope_id": challenge["scope_id"],
        "capsule_sha256": challenge["capsule_sha256"],
        "rootfs_sha256": challenge["rootfs_sha256"],
        "unit_identity_sha256": challenge["unit_identity_sha256"],
        "preinstall_host_key_sha256": challenge["preinstall_host_key_sha256"],
        "witness_public_key_hex": challenge["witness_public_key_hex"],
        "authorized_client_public_key_hex": challenge["authorized_client_public_key_hex"],
        "challenge_nonce_hex": challenge["nonce_hex"],
        "observed_board_target": BOARD_TARGET,
        "observed_target_identity_profile": TARGET_IDENTITY_PROFILE,
        "first_boot_host_key_algorithm": HOST_KEY_ALGORITHM,
        "first_boot_host_key_public_hex": host,
        "boot_id_sha256": boot_id_sha256,
        "stage1_install_receipt_sha256": stage1_install_receipt_sha256,
        "release_image_marker_observed": True,
        "ssh_gate_state": "enabled-by-keys",
        "postinstall_state": "dcentos-release-locked-firstboot",
        "reboot_initiated_by_witness": False,
        # Credential/witness state is explicitly outside install/hardware
        # mutation authority in the host v1 response contract.
        "mutation_performed_by_witness": False,
    }
    return _canonical_json(response)


def _validate_response(response: Mapping[str, object]) -> None:
    if set(response) != RESPONSE_KEYS or response.get("schema") != RESPONSE_SCHEMA:
        raise TargetWitnessError("target witness response key set/schema is not exact v1")
    for name in (
        "challenge_id",
        "scope_id",
        "capsule_sha256",
        "rootfs_sha256",
        "unit_identity_sha256",
        "preinstall_host_key_sha256",
        "boot_id_sha256",
        "stage1_install_receipt_sha256",
    ):
        _require_sha256(response.get(name), name)
    for name in (
        "witness_public_key_hex",
        "authorized_client_public_key_hex",
        "challenge_nonce_hex",
        "first_boot_host_key_public_hex",
    ):
        _require_hex(response.get(name), 32, name)
    exact = {
        "observed_board_target": BOARD_TARGET,
        "observed_target_identity_profile": TARGET_IDENTITY_PROFILE,
        "first_boot_host_key_algorithm": HOST_KEY_ALGORITHM,
        "release_image_marker_observed": True,
        "ssh_gate_state": "enabled-by-keys",
        "postinstall_state": "dcentos-release-locked-firstboot",
        "reboot_initiated_by_witness": False,
        "mutation_performed_by_witness": False,
    }
    for name, expected in exact.items():
        if response.get(name) != expected:
            raise TargetWitnessError(f"target witness response {name} is not exact")


ADMISSION_KEYS: Final = frozenset(
    {
        "schema",
        "scope_id",
        "challenge_id",
        "scope_sha256",
        "scope_signature_sha256",
        "challenge_sha256",
        "stage1_install_receipt_sha256",
        "witness_public_key_hex",
        "witness_public_pem_sha256",
        "authorized_client_public_key_hex",
        "first_boot_host_key_public_hex",
        "boot_id_sha256",
        "response_sha256",
        "response_signature_sha256",
        "recorded_utc",
        "target_response_signed_once",
        "ssh_host_key_eager_ed25519",
        "ssh_authorized_client_exact",
        "release_scope_verified",
        "stage1_terminal_receipt_verified",
        "release_ready",
        "install_authority_granted",
        "reboot_authority_granted",
        "hardware_mutation_authority_granted",
    }
)


def _verify_existing_admission(
    paths: TargetPaths,
    runner: CommandRunner,
    expected_uid: Optional[int],
) -> dict[str, object]:
    _require_durable_data_mount(runner)
    _require_runtime_identity(paths, expected_uid)
    (
        scope,
        scope_raw,
        challenge,
        challenge_raw,
        _receipt,
        receipt_raw,
        _private_key,
        witness_pem,
    ) = _load_inputs(paths, runner, expected_uid)
    _require_directory(paths.outbox, label="witness outbox", expected_uid=expected_uid)
    if {entry.name for entry in os.scandir(paths.outbox)} != {
        "response.json",
        "response.sig",
        "witness-public.pem",
    }:
        raise TargetWitnessError("witness outbox member set is not exact v1")
    admission_raw = _read_regular(
        paths.admission,
        label="SSH witness admission",
        max_bytes=MAX_JSON_BYTES,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    admission = _load_canonical_json(admission_raw, "SSH witness admission")
    if set(admission) != ADMISSION_KEYS or admission.get("schema") != ADMISSION_SCHEMA:
        raise TargetWitnessError("SSH witness admission key set/schema is not exact v1")
    response_path = paths.outbox / "response.json"
    response_sig_path = paths.outbox / "response.sig"
    witness_public_path = paths.outbox / "witness-public.pem"
    response_raw = _read_regular(
        response_path,
        label="target witness response",
        max_bytes=MAX_JSON_BYTES,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    response_signature = _read_regular(
        response_sig_path,
        label="target witness response signature",
        max_bytes=64,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    if len(response_signature) != 64:
        raise TargetWitnessError(
            "target witness response signature is not 64 bytes "
            f"(observed {len(response_signature)})"
        )
    public_pem = _read_regular(
        witness_public_path,
        label="target witness public key",
        max_bytes=4096,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    if public_pem != witness_pem:
        raise TargetWitnessError("retained witness public PEM differs from private-key derivation")
    response = _load_canonical_json(response_raw, "target witness response")
    _validate_response(response)
    joins = {
        "scope_id": scope["scope_id"],
        "challenge_id": challenge["challenge_id"],
        "capsule_sha256": scope["capsule_sha256"],
        "rootfs_sha256": scope["rootfs_sha256"],
        "unit_identity_sha256": scope["unit_identity_sha256"],
        "preinstall_host_key_sha256": scope["preinstall_host_key_sha256"],
        "witness_public_key_hex": scope["witness_public_key_hex"],
        "authorized_client_public_key_hex": scope["authorized_client_public_key_hex"],
        "challenge_nonce_hex": challenge["nonce_hex"],
        "stage1_install_receipt_sha256": _sha256(receipt_raw),
    }
    for name, expected in joins.items():
        if response.get(name) != expected:
            raise TargetWitnessError(f"retained response {name} no longer joins admitted inputs")
    _verify_signature(witness_public_path, response_sig_path, response_raw, runner)

    if not paths.host_key_claim.exists() or paths.host_key_claim.is_symlink():
        raise TargetWitnessError("durable host-key generation claim is missing")
    host_public = _admit_host_key(
        paths,
        scope,
        challenge,
        runner,
        expected_uid,
    )
    signing_claim_raw = _read_regular(
        paths.signing_claim,
        label="target signing claim",
        max_bytes=MAX_JSON_BYTES,
        expected_uid=expected_uid,
        allowed_modes=(0o600,),
    )
    signing_claim = _load_canonical_json(signing_claim_raw, "target signing claim")
    signing_exact = {
        "schema": SIGNING_CLAIM_SCHEMA,
        "scope_id": scope["scope_id"],
        "challenge_id": challenge["challenge_id"],
        "scope_sha256": _sha256(scope_raw),
        "challenge_sha256": _sha256(challenge_raw),
        "stage1_install_receipt_sha256": _sha256(receipt_raw),
        "first_boot_host_key_public_hex": host_public,
        "boot_id_sha256": response["boot_id_sha256"],
        "response_sha256": _sha256(response_raw),
        "signing_started_utc": signing_claim.get("signing_started_utc"),
        "one_use": True,
        "authorizes_install": False,
        "authorizes_reboot": False,
        "hardware_mutation_authority_granted": False,
    }
    _parse_utc(signing_claim.get("signing_started_utc"), "signing_started_utc")
    if signing_claim != signing_exact:
        raise TargetWitnessError("target signing claim exact join failed")
    expected_admission = {
        "schema": ADMISSION_SCHEMA,
        "scope_id": scope["scope_id"],
        "challenge_id": challenge["challenge_id"],
        "scope_sha256": _sha256(scope_raw),
        "scope_signature_sha256": _sha256(
            _read_regular(
                paths.inbox / "scope.sig",
                label="witness scope signature",
                max_bytes=64,
                expected_uid=expected_uid,
                allowed_modes=(0o600,),
            )
        ),
        "challenge_sha256": _sha256(challenge_raw),
        "stage1_install_receipt_sha256": _sha256(receipt_raw),
        "witness_public_key_hex": scope["witness_public_key_hex"],
        "witness_public_pem_sha256": _sha256(public_pem),
        "authorized_client_public_key_hex": scope["authorized_client_public_key_hex"],
        "first_boot_host_key_public_hex": host_public,
        "boot_id_sha256": response["boot_id_sha256"],
        "response_sha256": _sha256(response_raw),
        "response_signature_sha256": _sha256(response_signature),
        "recorded_utc": admission.get("recorded_utc"),
        "target_response_signed_once": True,
        "ssh_host_key_eager_ed25519": True,
        "ssh_authorized_client_exact": True,
        "release_scope_verified": True,
        "stage1_terminal_receipt_verified": True,
        "release_ready": False,
        "install_authority_granted": False,
        "reboot_authority_granted": False,
        "hardware_mutation_authority_granted": False,
    }
    _parse_utc(admission.get("recorded_utc"), "recorded_utc")
    if admission != expected_admission:
        raise TargetWitnessError("SSH witness admission exact hash join failed")
    if host_public != response["first_boot_host_key_public_hex"]:
        raise TargetWitnessError("retained Dropbear host key differs from signed response")

    authorized = _authorized_keys_line(str(scope["authorized_client_public_key_hex"]))
    _ensure_exact_file(
        paths.persistent_authorized_keys,
        authorized,
        label="persistent authorized_keys",
        expected_uid=expected_uid,
    )
    _ensure_exact_file(
        paths.ssh_enabled,
        b"",
        label="SSH enabled marker",
        expected_uid=expected_uid,
    )
    if paths.ssh_disabled.exists() or paths.ssh_disabled.is_symlink():
        raise TargetWitnessError("operator SSH-disabled marker overrides witness admission")
    _mkdir_new(paths.root_ssh_dir, expected_uid=expected_uid)
    _ensure_exact_file(
        paths.root_authorized_keys,
        authorized,
        label="Dropbear authorized_keys view",
        expected_uid=expected_uid,
    )
    return admission


def run_firstboot(
    paths: TargetPaths,
    *,
    runner: CommandRunner = _default_runner,
    now: Optional[datetime] = None,
    expected_uid: Optional[int] = 0,
) -> dict[str, object]:
    """Consume one preprovisioned envelope and publish one signed response."""

    _require_durable_data_mount(runner)
    if paths.admission.exists() or paths.admission.is_symlink():
        return _verify_existing_admission(paths, runner, expected_uid)
    _require_runtime_identity(paths, expected_uid)
    (
        scope,
        scope_raw,
        challenge,
        challenge_raw,
        _receipt,
        receipt_raw,
        private_key,
        witness_pem,
    ) = _load_inputs(paths, runner, expected_uid)
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    if moment < _parse_utc(scope["authorized_utc"], "authorized_utc"):
        raise TargetWitnessError("release-signed witness scope is not active yet")
    if moment > _parse_utc(scope["expires_utc"], "expires_utc"):
        raise TargetWitnessError("release-signed witness scope expired before first boot")
    if moment < _parse_utc(challenge["issued_utc"], "issued_utc"):
        raise TargetWitnessError("witness challenge is not active yet")
    if moment > _parse_utc(challenge["expires_utc"], "expires_utc"):
        raise TargetWitnessError("witness challenge expired before first boot")

    _mkdir_new(paths.outbox, expected_uid=expected_uid)
    host_public = _admit_host_key(paths, scope, challenge, runner, expected_uid)
    authorized = _authorized_keys_line(str(scope["authorized_client_public_key_hex"]))
    _ensure_exact_file(
        paths.persistent_authorized_keys,
        authorized,
        label="persistent authorized_keys",
        expected_uid=expected_uid,
    )
    if paths.ssh_disabled.exists() or paths.ssh_disabled.is_symlink():
        raise TargetWitnessError("operator SSH-disabled marker overrides witness admission")

    boot_id_raw = _read_regular(
        paths.boot_id,
        label="kernel boot_id",
        max_bytes=128,
        expected_uid=expected_uid,
        allowed_modes=(0o400, 0o440, 0o444, 0o600, 0o640, 0o644),
    )
    try:
        boot_id = boot_id_raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise TargetWitnessError("kernel boot_id is not ASCII") from exc
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot_id) is None:
        raise TargetWitnessError("kernel boot_id is not a canonical lowercase UUID")
    boot_id_sha = _sha256(boot_id.encode("ascii"))
    receipt_sha = _sha256(receipt_raw)
    response_raw = build_response_payload(
        scope,
        challenge,
        first_boot_host_key_public_hex=host_public,
        boot_id_sha256=boot_id_sha,
        stage1_install_receipt_sha256=receipt_sha,
    )
    signing_claim = {
        "schema": SIGNING_CLAIM_SCHEMA,
        "scope_id": scope["scope_id"],
        "challenge_id": challenge["challenge_id"],
        "scope_sha256": _sha256(scope_raw),
        "challenge_sha256": _sha256(challenge_raw),
        "stage1_install_receipt_sha256": receipt_sha,
        "first_boot_host_key_public_hex": host_public,
        "boot_id_sha256": boot_id_sha,
        "response_sha256": _sha256(response_raw),
        "signing_started_utc": _format_utc(moment),
        "one_use": True,
        "authorizes_install": False,
        "authorizes_reboot": False,
        "hardware_mutation_authority_granted": False,
    }
    # Claim before invoking the private-key operation. A crash after this point
    # is terminal fail-closed evidence and can never trigger a second signing.
    _write_new(paths.signing_claim, _canonical_json(signing_claim), label="target signing claim")
    signature = _sign(private_key, response_raw, runner)
    response_path = paths.outbox / "response.json"
    response_sig_path = paths.outbox / "response.sig"
    witness_public_path = paths.outbox / "witness-public.pem"
    _write_new(response_path, response_raw, label="target witness response")
    _write_new(response_sig_path, signature, label="target witness response signature")
    _write_new(witness_public_path, witness_pem, label="target witness public key")
    _verify_signature(witness_public_path, response_sig_path, response_raw, runner)

    admission = {
        "schema": ADMISSION_SCHEMA,
        "scope_id": scope["scope_id"],
        "challenge_id": challenge["challenge_id"],
        "scope_sha256": _sha256(scope_raw),
        "scope_signature_sha256": _sha256(
            _read_regular(
                paths.inbox / "scope.sig",
                label="witness scope signature",
                max_bytes=64,
                expected_uid=expected_uid,
                allowed_modes=(0o600,),
            )
        ),
        "challenge_sha256": _sha256(challenge_raw),
        "stage1_install_receipt_sha256": receipt_sha,
        "witness_public_key_hex": scope["witness_public_key_hex"],
        "witness_public_pem_sha256": _sha256(witness_pem),
        "authorized_client_public_key_hex": scope["authorized_client_public_key_hex"],
        "first_boot_host_key_public_hex": host_public,
        "boot_id_sha256": boot_id_sha,
        "response_sha256": _sha256(response_raw),
        "response_signature_sha256": _sha256(signature),
        "recorded_utc": _format_utc(moment),
        "target_response_signed_once": True,
        "ssh_host_key_eager_ed25519": True,
        "ssh_authorized_client_exact": True,
        "release_scope_verified": True,
        "stage1_terminal_receipt_verified": True,
        "release_ready": False,
        "install_authority_granted": False,
        "reboot_authority_granted": False,
        "hardware_mutation_authority_granted": False,
    }
    _write_new(paths.admission, _canonical_json(admission), label="SSH witness admission")
    _ensure_exact_file(
        paths.ssh_enabled,
        b"",
        label="SSH enabled marker",
        expected_uid=expected_uid,
    )
    _mkdir_new(paths.root_ssh_dir, expected_uid=expected_uid)
    _ensure_exact_file(
        paths.root_authorized_keys,
        authorized,
        label="Dropbear authorized_keys view",
        expected_uid=expected_uid,
    )
    return admission


def verify_ssh_gate(
    paths: TargetPaths,
    *,
    runner: CommandRunner = _default_runner,
    expected_uid: Optional[int] = 0,
) -> dict[str, object]:
    """Revalidate the durable admission before every Dropbear start."""

    return _verify_existing_admission(paths, runner, expected_uid)


def contract() -> dict[str, object]:
    return {
        "schema": CONTRACT_SCHEMA,
        "candidate_implemented": True,
        "production_approved": False,
        "target_firstboot_helper_implemented": True,
        "buildroot_image_integration_implemented": True,
        "persistent_data_mount_owner_implemented": True,
        "persistent_data_mount_live_verified": False,
        "missing_persistent_data_proof": (
            "independent S19k cold-boot mtd4/UBI/mountinfo capture and "
            "cross-reboot replay witness"
        ),
        "stage1_envelope_transport_implemented": False,
        "toolbox_executor_integration_complete": False,
        "release_gate_integration_complete": False,
        "target_known_answer_test_verified": False,
        "independent_cold_boot_witness_verified": False,
        "clear_for_flash": False,
        "production_execution_ready": False,
        "authorizes_install": False,
        "authorizes_nand_write": False,
        "authorizes_reboot": False,
        "contacts_network": False,
        "performs_hardware_mutation": False,
        "missing_preinstall_boundary": (
            "release-signed per-unit scope/challenge/witness-key/stage1-receipt "
            "transport into the exact persistent inbox"
        ),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] not in {"firstboot", "verify-ssh-gate", "contract"}:
        print(
            "usage: dcent-s19k-postinstall-witness.py "
            "{firstboot|verify-ssh-gate|contract}",
            file=sys.stderr,
        )
        return 2
    if args[0] == "contract":
        sys.stdout.buffer.write(_canonical_json(contract()))
        return 0
    paths = TargetPaths.production()
    try:
        result = (
            run_firstboot(paths)
            if args[0] == "firstboot"
            else verify_ssh_gate(paths)
        )
    except TargetWitnessError as exc:
        print(f"S19k postinstall witness: BLOCKED: {exc}", file=sys.stderr)
        return 1
    print(
        "S19k postinstall witness: admitted "
        f"scope={result['scope_id']} challenge={result['challenge_id']} "
        "release_ready=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
