#!/usr/bin/env python3
"""Offline, non-authorizing materialization of Nano 3 A PREPARE inputs.

This tool has no network, USB, UART, subprocess, process-control, power,
flash, reboot, or hardware path.  Checked-in production pins are empty, so it
can create only an explicitly incomplete synthetic staging tree.  It cannot
grant Authorization A or consume a global one-shot authority.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import stat
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SOURCE_SCHEMA = "dcent.nano3.a-authority-materialization-source.v1"
MANIFEST_SCHEMA = "dcent.nano3.a-authority-materialization-manifest.v1"
PUBLIC_RECEIPT_SCHEMA = "dcent.nano3.a-authority-materialization-public-receipt.v1"
TEMPLATE_SCHEMA = "dcent.nano3.a-authority-materialization-template.v1"
PURPOSE = "stage_exact_protected_w4_prepare_inputs_without_authority"
STATUS = "INCOMPLETE_NONPRODUCTION_NONAUTHORIZING_STAGING"

W4_NAME = "nano3_a_session_admission.py"
W4_BYTES = 45_118
W4_SHA256 = "0f7e1a168b7f99d08506ba60692cbb78556f858e81f289d8da12936f998b02d2"
W2_NAME = "nano3_stock_telemetry_contract.py"
W2_BYTES = 42_727
W2_SHA256 = "30947cb497737fbc2bd8222cf6ad8d0a0fb99ac9ef92e7b58d7ad4e09ed38fdd"
RECOVERY_VERIFIER_NAME = "k230_factory_recovery.py"
RECOVERY_VERIFIER_BYTES = 47_017
RECOVERY_VERIFIER_SHA256 = "930e31771d2fee0efc4bffc5273f904e5e42490b05060c4988462cc697c3b94c"

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_BYTES = 128 * 1024 * 1024
MAX_INPUT_FILES = 96
MAX_WINDOW_SECONDS = 30 * 60
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")

RECOVERY_SCHEMA = "dcent.k230.factory-recovery-authorization.v1"
RECOVERY_PURPOSE = "authorize-exact-nano3-stock-factory-recovery"
RECOVERY_CLASS = "factory-recovery-only"
RECOVERY_ENGINEERING_DOMAIN = (
    "DCENT-K230-FACTORY-RECOVERY-AUTHORIZATION-V1"
)
RECOVERY_OPERATOR_SCHEMA = (
    "dcent.k230.factory-recovery-operator-acknowledgement.v1"
)
RECOVERY_OPERATOR_PURPOSE = (
    "operator-consent-for-exact-nano3-stock-factory-recovery"
)
RECOVERY_OPERATOR_DOMAIN = (
    "DCENT-K230-FACTORY-RECOVERY-OPERATOR-ACKNOWLEDGEMENT-V1"
)
RECOVERY_FINGERPRINT_SHA256 = "5e3689b898baeee8db865eabf40148465dead75b8216027b41281bb0686af66b"
RECOVERY_ARTIFACT_SHA256 = "8267651a8ebf5c63853a24dbd7bab639a732c9cef8a7a7da96348d9791aab9cc"
RECOVERY_ARTIFACT_BYTES = 55_660_970
RECOVERY_DONOR_SHA256 = "b99a2358592224b07b4ef9428181715d0dd8ed15585044a94d01e8c78fb830be"
RECOVERY_FLASH_SHA256 = "b2ff897faca1a866fdf94524bbf66ecd4ae1ff6e6350bddfeaccc46806c51464"
RECOVERY_FLASH_BYTES = 109_727
RECOVERY_LOADER_SHA256 = "685215d34c1567e39f919b8dfd462e276c167061293bbce74fcfd62d28bb9c1f"
RECOVERY_SLOTS = [
    ("spl_1", 0x00000000, 0x00080000, 0),
    ("spl_2", 0x00080000, 0x00080000, 0),
    ("uboot_1", 0x00100000, 0x00100000, 0),
    ("uboot_2", 0x00200000, 0x00100000, 0),
    ("uboot_env_1", 0x00300000, 0x00080000, 0),
    ("uboot_env_2", 0x00380000, 0x00080000, 0),
    ("linux_1", 0x00400000, 0x00800000, 0),
    ("linux_2", 0x00C00000, 0x00800000, 0),
    ("rootfs_1", 0x01400000, 0x01800000, 0x00020000),
    ("rootfs_2", 0x02C00000, 0x01800000, 0x00020000),
    ("app_1", 0x04400000, 0x01000000, 0x00020000),
    ("app_2", 0x05400000, 0x01000000, 0x00020000),
]
RECOVERY_FLASH_COMPONENTS = [
    ("dcent_toolbox.cli.commands.flash", "622e964bc03780fdae7924c9b5dfc1b5a738b8e57e44902066e918f5afc96012", RECOVERY_FLASH_SHA256, 109_727),
    ("dcent_toolbox.core.k230_execution_contract", "520f5eac9b1683220e3de383213e1d50d1d93cd89cacca16b98d44b379f3d5e6", "96069fb2064fc2ba85d388ee5d1c7b64c8d1b697c590e0e92b81f44286e0acf1", 4_049),
    ("dcent_toolbox.core.k230_factory_recovery", "aaff02b89aa9d22db082b9876743e9dd9e7abf7b753ce6100759f2e77d94f60c", RECOVERY_VERIFIER_SHA256, RECOVERY_VERIFIER_BYTES),
    ("dcent_toolbox.core.k230_factory_recovery_consumption", "13e783c4b9ad7767ba214d1ce1690dacb2cb9ca6dd18100facf35caa1a203085", "7e0e602e3c1bf50828751e5601437a7cb0f4a7b39d98983697b5fb0a425d5d96", 9_057),
    ("dcent_toolbox.core.k230_fingerprint", "d2a2faa7752055e95990e921d5716da1630bffb94590a72070604662228c9747", "9bc1c06ba5592ed6cd13f722da1947c374cd7ffccb227a8f3fc4eb171a85c972", 16_639),
    ("dcent_toolbox.core.k230_flasher", "68052fdf22ce4b87bd5253b8e253b87c9081f55283b18fd80bb113197efbd8f7", "f84510fd4eea182eb937aa7d379ff78c2db96f25c7b7a14d00ef543e72029041", 24_487),
    ("dcent_toolbox.core.kdimg", "747942f27a3c55a275a7e6e9f2ce4c4b0a7206f441ce2730e419ec837a7a8cc4", "9b2057fc6f7de679a226e0bedf821e78a107852af8f8cd26eddf98a5511555d6", 14_108),
    ("dcent_toolbox.transport.k230_kburn", "78b5cffa5fddb5d7b474ccf9a5fe62bfeceeb4dae931c2cb69531da45db3c343", "47c98c8a68bd6355b63b48dc4d570efd062bc4327aeddbf7503f00c16cb72f6c", 51_887),
]

AUTHORITY_ROLES = (
    "materialization_reviewer",
    "recovery_engineering",
    "recovery_operator",
    "telemetry_authority",
    "post_cut_authority",
    "pool_topology_authority",
    "trusted_time_authority",
    "global_replay_authority",
    "operator_authorization_a",
)
AUTHORITY_DOMAINS = {
    role: f"DCENT:NANO3:A-MATERIALIZATION:{role.upper().replace('_', '-')}:V1"
    for role in AUTHORITY_ROLES
}
PRODUCTION_AUTHORITY_KEY_PINS = {role: "" for role in AUTHORITY_ROLES}
PRODUCTION_W4_KEY_PINS: dict[str, str] = {}
PRODUCTION_RECOVERY_KEY_PINS = {
    "recovery_engineering": "",
    "recovery_operator": "",
}

SUPPLEMENTAL_POLICY: dict[str, tuple[str, int]] = {
    "recovery_engineering_signature": ("ed25519.signature.raw64", 64),
    "recovery_operator_ack": (RECOVERY_OPERATOR_SCHEMA, MAX_JSON_BYTES),
    "recovery_operator_signature": ("ed25519.signature.raw64", 64),
    "telemetry_compiled_contract": (
        "dcent.nano3.stock-telemetry-contract.v1",
        MAX_JSON_BYTES,
    ),
    "telemetry_source_bundle": (
        "dcent.nano3.stock-telemetry-source-bundle.v1",
        MAX_JSON_BYTES,
    ),
    "telemetry_identity_receipt": ("opaque.protected.identity-receipt", MAX_JSON_BYTES),
    "telemetry_capture_receipt": ("opaque.protected.capture-receipt", MAX_JSON_BYTES),
    **{
        f"telemetry_raw_{index:02d}_{command}": (
            f"cgminer.raw-response.{command}",
            1024 * 1024,
        )
        for index, command in enumerate(
            (
                "version", "summary", "stats", "devs", "pools", "lcd",
                "version", "summary", "stats", "devs", "pools", "lcd",
            ),
            1,
        )
    },
    "post_cut_prior_receipt": ("dcent.nano3.post-cut-receipt.v2", MAX_JSON_BYTES),
    "post_cut_raw_evidence": ("opaque.protected.post-cut-evidence", MAX_FILE_BYTES),
    "pool_topology_raw_evidence": (
        "opaque.protected.pool-topology-evidence",
        MAX_FILE_BYTES,
    ),
}

EXTERNAL_STATE_POLICY = {
    "trusted_time": {
        "receipt_byte_bound": True,
        "cryptographically_bound_to_unpinned_key": True,
        "production_provider_pin_verified": False,
        "provider_identity_and_custody_proven": False,
        "trusted_time_verified": False,
        "freshness_verified": False,
    },
    "global_replay": {
        "receipt_byte_bound": True,
        "cryptographically_bound_to_unpinned_key": True,
        "production_provider_pin_verified": False,
        "provider_identity_and_durability_proven": False,
        "reservation_is_consumption": False,
        "global_one_shot_consumed": False,
    },
    "recovery": {
        "four_file_structure_and_signatures_verified": True,
        "production_recovery_pins_verified": False,
        "exact_restore_artifact_bytes_verified": False,
        "recovery_authority_proven": False,
        "recovery_execution_authorized": False,
    },
    "telemetry": {
        "source_bundle_recompiled_from_snapshotted_raw_bytes": True,
        "compiled_contract_bytes_matched": True,
        "production_source_authority_verified": False,
        "auto_mode_and_source_sample_freshness_proven": False,
        "authentic_live_capability_verified": False,
    },
    "physical_qualifications": {
        "post_cut_raw_bytes_bound": True,
        "pool_topology_raw_bytes_bound": True,
        "instrument_placement_and_calibration_proven": False,
        "network_observation_completeness_proven": False,
        "prior_physical_qualifications_verified": False,
    },
}

PUBLIC_STATE_POLICY = {
    "file_contract_valid": True,
    "production_pins_verified": False,
    "trusted_time_verified": False,
    "global_one_shot_consumed": False,
    "prior_physical_qualifications_verified": False,
    "operator_authorization_a_signature_verified": False,
    "precontact_admission_conditions_met": False,
    "live_session_performed": False,
    "postrun_result_accepted": False,
    "authorization_a_granted_by_compiler": False,
}


class MaterializationError(RuntimeError):
    """One exact file, signature, semantic join, or custody invariant failed."""


def fail(message: str) -> NoReturn:
    raise MaterializationError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MaterializationError("document is not finite canonical ASCII JSON") from exc


def canonical_recovery_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MaterializationError("recovery document is not canonical ASCII JSON") from exc


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite {token}")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise MaterializationError(f"malformed {label}") from exc


def mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        fail(f"{label} must be an object")
    return value


def exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} key set mismatch")


def text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value) < minimum:
        fail(f"{label} must be text")
    return value


def identifier(value: Any, label: str) -> str:
    result = text(value, label, 8)
    if not ID_RE.fullmatch(result):
        fail(f"{label} has invalid shape")
    return result


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        fail(f"{label} must be lowercase SHA-256")
    return value


def positive_int(value: Any, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
        fail(f"{label} must be a bounded positive integer")
    return value


def utc(value: Any, label: str) -> datetime:
    raw = text(value, label, 20)
    if not raw.endswith("Z"):
        fail(f"{label} must use UTC Z form")
    try:
        result = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as exc:
        raise MaterializationError(f"{label} is not RFC3339 UTC") from exc
    if result.tzinfo != timezone.utc or result.microsecond:
        fail(f"{label} must be whole-second UTC")
    return result


def is_alias(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def verify_dir(path: Path, label: str, *, private: bool = False) -> None:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except OSError as exc:
            raise MaterializationError(f"{label} path unavailable") from exc
        if is_alias(info) or not stat.S_ISDIR(info.st_mode):
            fail(f"{label} contains an alias or non-directory")
    if private and os.name != "nt" and stat.S_IMODE(path.lstat().st_mode) & 0o077:
        fail(f"{label} must be owner-only on POSIX")


def relative_name(value: Any, label: str) -> str:
    name = text(value, label)
    if not NAME_RE.fullmatch(name) or name in {".", ".."} or ":" in name:
        fail(f"{label} must be one normalized relative filename")
    return name


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise MaterializationError(f"{label} unavailable") from exc
    if is_alias(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a single-link non-alias regular file")
    if not 0 < before.st_size <= maximum:
        fail(f"{label} size outside bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MaterializationError(f"{label} open failed") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail(f"{label} changed type or link count during open")
        chunks: list[bytes] = []
        count = 0
        while True:
            chunk = os.read(fd, min(65_536, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > maximum:
                fail(f"{label} exceeds bound")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    before_id = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_id != after_id or after.st_nlink != 1 or count != after.st_size:
        fail(f"{label} changed while reading")
    return b"".join(chunks)


def fsync_dir(path: Path) -> bool:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return False
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def write_new(path: Path, raw: bytes) -> None:
    verify_dir(path.parent, "protected output parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MaterializationError("exclusive protected output creation failed") from exc
    try:
        offset = 0
        while offset < len(raw):
            amount = os.write(fd, raw[offset:])
            if amount <= 0:
                fail("protected output write made no progress")
            offset += amount
        os.fsync(fd)
        opened = os.fstat(fd)
    finally:
        os.close(fd)
    final = path.lstat()
    if (
        is_alias(final)
        or not stat.S_ISREG(final.st_mode)
        or final.st_nlink != 1
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (final.st_dev, final.st_ino, final.st_size)
        or final.st_size != len(raw)
    ):
        fail("protected output identity validation failed")
    fsync_dir(path.parent)


def mkdir_new_private(path: Path, label: str) -> None:
    verify_dir(path.parent, f"{label} parent")
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise MaterializationError(f"{label} exclusive creation failed") from exc
    info = path.lstat()
    if is_alias(info) or not stat.S_ISDIR(info.st_mode):
        fail(f"{label} is not a real directory")
    if os.name != "nt":
        path.chmod(0o700)
        if stat.S_IMODE(path.lstat().st_mode) & 0o077:
            fail(f"{label} is not owner-only")
    fsync_dir(path.parent)


def exact_membership(root: Path, expected: set[str], label: str) -> None:
    actual: set[str] = set()
    for index, child in enumerate(root.iterdir(), 1):
        if index > MAX_INPUT_FILES:
            fail(f"{label} has too many entries")
        info = child.lstat()
        if is_alias(info) or not (
            stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
        ):
            fail(f"{label} contains an alias")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            fail(f"{label} contains a hard-linked file")
        actual.add(child.name)
    if actual != expected:
        fail(f"{label} exact membership mismatch")


def assert_disjoint_roots(named: Mapping[str, Path]) -> None:
    normalized: dict[str, str] = {}
    identities: dict[str, tuple[int, int]] = {}
    for label, path in named.items():
        if not path.is_absolute():
            fail(f"{label} must be absolute")
        value = os.path.normcase(os.path.abspath(str(path)))
        normalized[label] = value
        if path.exists():
            info = path.lstat()
            if is_alias(info):
                fail(f"{label} is an alias")
            identities[label] = (info.st_dev, info.st_ino)
    labels = list(normalized)
    for index, left in enumerate(labels):
        for right in labels[index + 1 :]:
            left_value = normalized[left]
            right_value = normalized[right]
            try:
                common = os.path.commonpath((left_value, right_value))
            except ValueError as exc:
                raise MaterializationError("root comparison failed") from exc
            if common in {left_value, right_value}:
                fail("protected/public/code roots must be exact-disjoint and non-nested")
            if left in identities and right in identities and identities[left] == identities[right]:
                fail("protected/public/code roots share one directory identity")


def load_module_from_pinned_bytes(
    name: str, path: Path, expected_bytes: int, expected_sha: str
) -> types.ModuleType:
    raw = read_regular(path, expected_bytes, f"pinned {name} module")
    if len(raw) != expected_bytes or sha256(raw) != expected_sha:
        fail(f"pinned {name} module identity mismatch")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except Exception as exc:
        raise MaterializationError(f"pinned {name} module load failed") from exc
    return module


def decode_signature(raw: bytes, label: str) -> bytes:
    if len(raw) != 64:
        fail(f"{label} must be exactly 64 raw bytes")
    return raw


def verify_signature(
    key_raw: bytes, signature: bytes, domain: bytes, payload: bytes, label: str
) -> None:
    if len(key_raw) != 32 or len(signature) != 64:
        fail(f"{label} key/signature size mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(key_raw).verify(
            signature,
            domain + payload,
        )
    except (InvalidSignature, ValueError) as exc:
        raise MaterializationError(f"{label} signature invalid") from exc


def validate_ref(value: Any, label: str, maximum: int) -> Mapping[str, Any]:
    ref = mapping(value, label)
    exact_keys(ref, {"path", "bytes", "sha256", "schema"}, label)
    relative_name(ref.get("path"), f"{label} path")
    positive_int(ref.get("bytes"), f"{label} bytes", maximum)
    digest(ref.get("sha256"), f"{label} digest")
    text(ref.get("schema"), f"{label} schema")
    return ref


def snapshot_ref(
    root: Path,
    ref: Mapping[str, Any],
    label: str,
    maximum: int,
    expected_names: set[str],
) -> bytes:
    name = relative_name(ref.get("path"), f"{label} path")
    if name in expected_names:
        fail("duplicate protected input filename")
    expected_names.add(name)
    raw = read_regular(root / name, maximum, label)
    if len(raw) != ref["bytes"] or sha256(raw) != ref["sha256"]:
        fail(f"{label} size/digest mismatch")
    return raw


def validate_recovery_four_file(
    manifest_raw: bytes,
    engineering_signature: bytes,
    engineering_key: bytes,
    operator_ack_raw: bytes,
    operator_signature: bytes,
    operator_key: bytes,
    w4_plan: Mapping[str, Any],
) -> None:
    manifest = mapping(strict_json(manifest_raw, "recovery manifest"), "recovery manifest")
    if canonical_recovery_json(manifest) != manifest_raw:
        fail("recovery manifest is not canonical exact bytes")
    exact_keys(
        manifest,
        {
            "schema", "purpose", "authorization_class", "signature",
            "authorization", "target", "artifact", "geometry", "data_policy",
            "flasher", "scope", "w4_fixture_binding",
        },
        "recovery manifest",
    )
    if (
        manifest.get("schema") != RECOVERY_SCHEMA
        or manifest.get("purpose") != RECOVERY_PURPOSE
        or manifest.get("authorization_class") != RECOVERY_CLASS
    ):
        fail("recovery manifest schema/purpose/class mismatch")
    signature_fact = mapping(manifest.get("signature"), "recovery signature fact")
    exact_keys(
        signature_fact,
        {"algorithm", "domain", "trust_anchor", "key_id"},
        "recovery signature fact",
    )
    if (
        signature_fact.get("algorithm") != "ed25519"
        or signature_fact.get("domain") != RECOVERY_ENGINEERING_DOMAIN
        or signature_fact.get("trust_anchor")
        != "pinned-dcentral-k230-factory-recovery-key-v1"
        or signature_fact.get("key_id") != sha256(engineering_key)
    ):
        fail("recovery engineering key/domain binding mismatch")
    session = mapping(w4_plan.get("session"), "W4 session")
    authorization = mapping(manifest.get("authorization"), "recovery authorization")
    exact_keys(
        authorization,
        {
            "authorization_id", "operation_nonce", "issued_at_utc",
            "expires_at_utc", "one_shot", "attended",
            "recovery_rail_admission", "replay_enforcement",
        },
        "recovery authorization",
    )
    target = mapping(manifest.get("target"), "recovery target")
    if (
        authorization.get("operation_nonce") != session.get("nonce_sha256")
        or target.get("unit_asset_id") != session.get("unit_id")
        or session.get("unit_fingerprint_sha256") != RECOVERY_FINGERPRINT_SHA256
    ):
        fail("recovery manifest unit/nonce does not join W4")
    issued_at = authorization.get("issued_at_utc")
    expires_at = authorization.get("expires_at_utc")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or issued_at <= 0
        or not issued_at < expires_at <= issued_at + MAX_WINDOW_SECONDS
        or authorization.get("one_shot") is not True
        or authorization.get("attended") is not True
        or authorization.get("recovery_rail_admission") is not True
        or authorization.get("replay_enforcement")
        != "same-host-atomic-ledger-before-usb"
    ):
        fail("recovery authorization time/attendance/replay policy mismatch")
    exact_keys(
        target,
        {
            "model", "model_profile_revision", "unit_asset_id",
            "hardware_revision", "fingerprint_profile_revision",
            "fingerprint_revision", "expected_fingerprint_sha256",
            "capacity_bytes", "block_size", "erase_size",
        },
        "recovery target",
    )
    identifier(target.get("hardware_revision"), "recovery hardware revision")
    if {key: target.get(key) for key in target if key != "hardware_revision"} != {
        "model": "nano3",
        "model_profile_revision": "nano3-kdimg-release-r1-recovery-master",
        "unit_asset_id": session.get("unit_id"),
        "fingerprint_profile_revision": "nano3-r1-stock-chain",
        "fingerprint_revision": "heater-nano3-master-b99a2358",
        "expected_fingerprint_sha256": RECOVERY_FINGERPRINT_SHA256,
        "capacity_bytes": 0x08000000,
        "block_size": 0x00000800,
        "erase_size": 0x00020000,
    }:
        fail("recovery target/model/fingerprint/geometry identity mismatch")
    artifact = mapping(manifest.get("artifact"), "recovery artifact")
    if artifact != {
        "artifact_id": "historical-live-proven-stock-restore-2026-08-21",
        "sha256": RECOVERY_ARTIFACT_SHA256,
        "size_bytes": RECOVERY_ARTIFACT_BYTES,
        "donor_revision": "heater-nano3-master-b99a2358",
        "donor_sha256": RECOVERY_DONOR_SHA256,
        "partition_count": 12,
    }:
        fail("recovery exact restore artifact identity mismatch")
    geometry = mapping(manifest.get("geometry"), "recovery geometry")
    expected_geometry = {
        "slots": [
            {
                "name": name,
                "offset": offset,
                "size_bytes": size,
                "erase_size": erase,
            }
            for name, offset, size, erase in RECOVERY_SLOTS
        ],
        "system_interval": {"offset": 0, "end": 0x06400000},
        "persistent_data_interval": {"offset": 0x06400000, "end": 0x08000000},
    }
    if geometry != expected_geometry:
        fail("recovery exact twelve-slot/system/data geometry mismatch")
    data_policy = mapping(manifest.get("data_policy"), "recovery data policy")
    if data_policy != {
        "policy": "preserve",
        "required_cli_flag": "--no-data-erase",
        "erase_data": False,
        "factory_reset": False,
        "persistent_data_payload_included": False,
        "persistent_data_erase_or_write_forbidden": True,
    }:
        fail("recovery protected persistent-data policy mismatch")
    flasher = mapping(manifest.get("flasher"), "recovery flasher")
    expected_components = [
        {
            "module": module,
            "runtime_code_sha256": runtime_sha,
            "source_sha256": source_sha,
            "source_size_bytes": source_bytes,
        }
        for module, runtime_sha, source_sha, source_bytes in RECOVERY_FLASH_COMPONENTS
    ]
    if flasher != {
        "implementation": "dcent_toolbox.cli.commands.flash",
        "version": "2.5.0",
        "sha256": RECOVERY_FLASH_SHA256,
        "size_bytes": RECOVERY_FLASH_BYTES,
        "components": expected_components,
        "execution_profile": "nano3-factory-recovery-r1",
        "trusted_loader_sha256": RECOVERY_LOADER_SHA256,
        "transport": "kburn-usb-29f1:0230-bootrom-only",
    }:
        fail("recovery flasher/version/component/loader pins mismatch")
    scope = mapping(manifest.get("scope"), "recovery scope")
    if scope != {
        "factory_recovery_authorized": True,
        "mutation_release_authorized": False,
        "firmware_release_authorized": False,
        "persistent_data_reset_authorized": False,
    }:
        fail("recovery scope widened or persistence policy changed")
    verify_signature(
        engineering_key,
        decode_signature(engineering_signature, "recovery engineering signature"),
        RECOVERY_ENGINEERING_DOMAIN.encode("ascii") + b"\x00",
        manifest_raw,
        "recovery engineering",
    )
    ack = mapping(strict_json(operator_ack_raw, "recovery operator ack"), "recovery operator ack")
    if canonical_recovery_json(ack) != operator_ack_raw:
        fail("recovery operator acknowledgement is not canonical exact bytes")
    exact_keys(
        ack,
        {"schema", "purpose", "signature", "operator", "authorization_binding", "target", "action"},
        "recovery operator acknowledgement",
    )
    if ack.get("schema") != RECOVERY_OPERATOR_SCHEMA or ack.get("purpose") != RECOVERY_OPERATOR_PURPOSE:
        fail("recovery operator acknowledgement schema/purpose mismatch")
    ack_signature = mapping(ack.get("signature"), "recovery operator signature fact")
    exact_keys(
        ack_signature,
        {"algorithm", "domain", "trust_anchor", "key_id"},
        "recovery operator signature fact",
    )
    if (
        ack_signature.get("algorithm") != "ed25519"
        or ack_signature.get("domain") != RECOVERY_OPERATOR_DOMAIN
        or ack_signature.get("trust_anchor")
        != "pinned-operator-factory-recovery-key-v1"
        or ack_signature.get("key_id") != sha256(operator_key)
    ):
        fail("recovery operator key/domain binding mismatch")
    operator = mapping(ack.get("operator"), "recovery operator")
    binding = mapping(ack.get("authorization_binding"), "recovery authorization binding")
    ack_target = mapping(ack.get("target"), "recovery acknowledgement target")
    exact_keys(
        operator,
        {
            "operator_id", "attended", "exact_action_acknowledged",
            "one_shot_acknowledged",
        },
        "recovery operator",
    )
    exact_keys(
        binding,
        {
            "manifest_sha256", "authorization_id", "operation_nonce",
            "issued_at_utc", "expires_at_utc",
        },
        "recovery authorization binding",
    )
    exact_keys(
        ack_target,
        {
            "model", "unit_asset_id", "hardware_revision",
            "expected_fingerprint_sha256",
        },
        "recovery acknowledgement target",
    )
    if (
        operator.get("operator_id") != session.get("operator_id")
        or operator.get("attended") is not True
        or operator.get("exact_action_acknowledged") is not True
        or operator.get("one_shot_acknowledged") is not True
        or binding
        != {
            "manifest_sha256": sha256(manifest_raw),
            "authorization_id": authorization.get("authorization_id"),
            "operation_nonce": session.get("nonce_sha256"),
            "issued_at_utc": issued_at,
            "expires_at_utc": expires_at,
        }
        or ack_target
        != {
            "model": "nano3",
            "unit_asset_id": session.get("unit_id"),
            "hardware_revision": target.get("hardware_revision"),
            "expected_fingerprint_sha256": RECOVERY_FINGERPRINT_SHA256,
        }
    ):
        fail("recovery operator acknowledgement does not exactly join W4/manifest")
    action = mapping(ack.get("action"), "recovery action")
    if action != {
        "operation": "write-exact-stock-system-slots-and-reboot",
        "artifact_sha256": RECOVERY_ARTIFACT_SHA256,
        "artifact_size_bytes": RECOVERY_ARTIFACT_BYTES,
        "partition_count": 12,
        "geometry_sha256": sha256(canonical_recovery_json(geometry)),
        "data_policy_sha256": sha256(canonical_recovery_json(data_policy)),
        "required_cli_flag": "--no-data-erase",
        "persistent_data_reset_authorized": False,
        "mutation_release_authorized": False,
    }:
        fail("recovery acknowledgement widens scope")
    verify_signature(
        operator_key,
        decode_signature(operator_signature, "recovery operator signature"),
        RECOVERY_OPERATOR_DOMAIN.encode("ascii") + b"\x00",
        operator_ack_raw,
        "recovery operator",
    )
    if engineering_key == operator_key:
        fail("recovery engineering/operator keys must be distinct")


def validate_external_states(value: Any) -> None:
    states = mapping(value, "external states")
    if states != EXTERNAL_STATE_POLICY:
        fail("external typed states must remain exact and non-authorizing")


def validate_public_states(value: Mapping[str, Any], label: str) -> None:
    for key, expected in PUBLIC_STATE_POLICY.items():
        if value.get(key) is not expected:
            fail(f"{label} {key} typed state mismatch")


def load_source(path: Path) -> tuple[Mapping[str, Any], bytes, Path]:
    if not path.is_absolute():
        fail("source path must be absolute")
    root = path.parent
    verify_dir(root, "protected input root", private=True)
    raw = read_regular(path, MAX_JSON_BYTES, "materialization source")
    source = mapping(strict_json(raw, "materialization source"), "materialization source")
    return source, raw, root


def validate_manifest(
    manifest: Mapping[str, Any], *, fixture_only: bool, w4: types.ModuleType
) -> tuple[datetime, datetime]:
    exact_keys(
        manifest,
        {
            "schema", "purpose", "mode", "materialization_id", "issued_at_utc",
            "valid_from_utc", "expires_at_utc", "toolchain", "w4_plan",
            "w4_prepare_source_sha256", "component_inputs", "w4_key_inputs",
            "w4_signature_inputs", "supplemental_inputs", "authority_signers",
            "external_states", "claims",
        },
        "materialization manifest",
    )
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("purpose") != PURPOSE:
        fail("materialization manifest schema/purpose mismatch")
    expected_mode = "synthetic_fixture" if fixture_only else "production"
    if manifest.get("mode") != expected_mode:
        fail("materialization mode mismatch")
    identifier(manifest.get("materialization_id"), "materialization id")
    issued = utc(manifest.get("issued_at_utc"), "materialization issued time")
    valid_from = utc(manifest.get("valid_from_utc"), "materialization valid-from time")
    expires = utc(manifest.get("expires_at_utc"), "materialization expiry")
    if not issued <= valid_from < expires or (expires - valid_from).total_seconds() > MAX_WINDOW_SECONDS:
        fail("materialization time window invalid")
    toolchain = mapping(manifest.get("toolchain"), "toolchain")
    exact_keys(
        toolchain,
        {
            "materializer", "w4_compiler", "telemetry_compiler",
            "recovery_verifier", "python_runtime",
        },
        "toolchain",
    )
    for role, expected_name, expected_bytes, expected_sha in (
        ("w4_compiler", W4_NAME, W4_BYTES, W4_SHA256),
        ("telemetry_compiler", W2_NAME, W2_BYTES, W2_SHA256),
        (
            "recovery_verifier",
            RECOVERY_VERIFIER_NAME,
            RECOVERY_VERIFIER_BYTES,
            RECOVERY_VERIFIER_SHA256,
        ),
    ):
        record = mapping(toolchain.get(role), role)
        if record != {"name": expected_name, "bytes": expected_bytes, "sha256": expected_sha}:
            fail(f"{role} identity mismatch")
    materializer = mapping(toolchain.get("materializer"), "materializer identity")
    exact_keys(materializer, {"name", "bytes", "sha256"}, "materializer identity")
    if materializer.get("name") != Path(__file__).name:
        fail("materializer name mismatch")
    positive_int(materializer.get("bytes"), "materializer bytes", MAX_FILE_BYTES)
    digest(materializer.get("sha256"), "materializer digest")
    runtime = mapping(toolchain.get("python_runtime"), "Python runtime")
    exact_keys(
        runtime,
        {
            "implementation", "version", "path_lookup_used",
            "byte_identity_verified", "dependency_scope_complete",
        },
        "Python runtime",
    )
    if (
        runtime.get("implementation") != platform.python_implementation()
        or runtime.get("version") != platform.python_version()
        or runtime.get("path_lookup_used") is not False
        or runtime.get("byte_identity_verified") is not False
        or runtime.get("dependency_scope_complete") is not False
    ):
        fail("Python runtime identity mismatch")
    w4_plan = mapping(manifest.get("w4_plan"), "W4 plan")
    w4.validate_plan(w4_plan, fixture_only)
    digest(manifest.get("w4_prepare_source_sha256"), "W4 prepare source digest")
    validate_external_states(manifest.get("external_states"))
    claims = mapping(manifest.get("claims"), "materialization claims")
    if claims != {
        "authorization_a_granted": False,
        "device_contact_authorized": False,
        "global_one_shot_consumed": False,
        "operator_authority_proven": False,
        "physical_qualifications_proven": False,
        "production_materialization_complete": False,
    }:
        fail("materialization claims must remain exact and false")
    return valid_from, expires


def records_by_role(
    value: Any,
    roles: Sequence[str],
    label: str,
    maximum_by_role: Mapping[str, int],
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) != len(roles):
        fail(f"{label} count mismatch")
    result: dict[str, Mapping[str, Any]] = {}
    observed: list[str] = []
    for item in value:
        record = mapping(item, label)
        exact_keys(record, {"role", "path", "bytes", "sha256", "schema"}, label)
        role = text(record.get("role"), f"{label} role")
        observed.append(role)
        if role not in maximum_by_role:
            fail(f"unknown {label} role")
        validate_ref(
            {key: record[key] for key in ("path", "bytes", "sha256", "schema")},
            f"{label} {role}",
            maximum_by_role[role],
        )
        result[role] = record
    if observed != list(roles) or len(result) != len(roles):
        fail(f"{label} roles/order mismatch")
    return result


def signer_records(value: Any, roles: Sequence[str], domains: Mapping[str, str], label: str) -> dict[str, Mapping[str, Any]]:
    signers = mapping(value, label)
    if set(signers) != set(roles):
        fail(f"{label} role set mismatch")
    result: dict[str, Mapping[str, Any]] = {}
    for role in roles:
        record = mapping(signers[role], f"{label} {role}")
        exact_keys(record, {"path", "bytes", "sha256", "domain", "key_epoch", "signed_at_utc"}, f"{label} {role}")
        relative_name(record.get("path"), f"{label} {role} path")
        if record.get("bytes") != 32:
            fail(f"{label} public key must be 32 bytes")
        digest(record.get("sha256"), f"{label} {role} key digest")
        if record.get("domain") != domains[role]:
            fail(f"{label} {role} domain mismatch")
        identifier(record.get("key_epoch"), f"{label} {role} key epoch")
        utc(record.get("signed_at_utc"), f"{label} {role} signed time")
        result[role] = record
    return result


def consume_local(ledger: Path, source_sha: str) -> None:
    verify_dir(ledger, "local replay ledger", private=True)
    marker = ledger / f"nano3-a-materialization-{source_sha}.consumed"
    write_new(
        marker,
        canonical_json(
            {
                "schema": "dcent.nano3.a-materialization-local-consumption.v1",
                "source_sha256": source_sha,
                "local_only": True,
                "global_one_shot_consumed": False,
                "authority_refundable": False,
            }
        ),
    )


def materialize(
    source_path: Path,
    output_root: Path,
    public_receipt_path: Path,
    ledger: Path,
    *,
    fixture_only: bool,
    now: Optional[datetime] = None,
) -> Mapping[str, Any]:
    if not fixture_only:
        fail(
            "production materialization is disabled: production pins and "
            "authentic external states are absent"
        )
    for path, label in (
        (source_path, "source"),
        (output_root, "output root"),
        (public_receipt_path, "public receipt"),
        (ledger, "local ledger"),
    ):
        if not path.is_absolute():
            fail(f"{label} path must be absolute")
    relative_name(source_path.name, "source filename")
    relative_name(output_root.name, "output root name")
    relative_name(public_receipt_path.name, "public receipt filename")
    script_file = Path(__file__).absolute()
    script_dir = script_file.parent
    recovery_verifier_path = (
        script_dir.parents[2]
        / "projects"
        / "dcent-toolbox"
        / "src"
        / "dcent_toolbox"
        / "core"
        / RECOVERY_VERIFIER_NAME
    )
    verify_dir(source_path.parent, "protected input root", private=True)
    verify_dir(output_root.parent, "staging parent", private=True)
    verify_dir(public_receipt_path.parent, "public receipt parent")
    verify_dir(ledger, "local replay ledger", private=True)
    verify_dir(script_dir, "materializer module root")
    verify_dir(recovery_verifier_path.parent, "recovery verifier root")
    assert_disjoint_roots(
        {
            "protected input root": source_path.parent,
            "staging output root": output_root,
            "local replay ledger": ledger,
            "public receipt parent": public_receipt_path.parent,
            "materializer module root": script_dir,
            "recovery verifier root": recovery_verifier_path.parent,
        }
    )
    if public_receipt_path.exists() or public_receipt_path.is_symlink():
        fail("public receipt output already exists")
    intent = output_root.parent / f".{output_root.name}.materialization-intent"
    write_new(
        intent,
        canonical_json(
            {
                "schema": "dcent.nano3.a-materialization-parent-intent.v1",
                "terminal_if_output_missing_or_incomplete": True,
                "production_materialization_complete": False,
                "global_one_shot_consumed": False,
                "authorization_a_granted": False,
                "device_contact": "none",
            }
        ),
    )
    mkdir_new_private(output_root, "staging output root")
    incomplete = output_root / ".incomplete"
    write_new(
        incomplete,
        canonical_json(
            {
                "schema": "dcent.nano3.a-materialization-incomplete.v1",
                "status": STATUS,
                "authorization_a_granted": False,
                "device_contact": "none",
            }
        ),
    )
    source, source_raw, input_root = load_source(source_path)
    exact_keys(source, {"schema", "purpose", "manifest", "authority_signatures"}, "source")
    if source.get("schema") != SOURCE_SCHEMA or source.get("purpose") != PURPOSE:
        fail("source schema/purpose mismatch")

    w4 = load_module_from_pinned_bytes("nano3_w4_pinned", script_dir / W4_NAME, W4_BYTES, W4_SHA256)
    telemetry = load_module_from_pinned_bytes("nano3_w2_pinned", script_dir / W2_NAME, W2_BYTES, W2_SHA256)
    recovery_verifier_raw = read_regular(
        recovery_verifier_path,
        RECOVERY_VERIFIER_BYTES,
        "pinned recovery verifier",
    )
    if (
        len(recovery_verifier_raw) != RECOVERY_VERIFIER_BYTES
        or sha256(recovery_verifier_raw) != RECOVERY_VERIFIER_SHA256
    ):
        fail("pinned recovery verifier identity mismatch")
    manifest = mapping(source.get("manifest"), "materialization manifest")
    valid_from, expires = validate_manifest(manifest, fixture_only=fixture_only, w4=w4)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or not valid_from <= current <= expires:
        fail("materialization is stale, future, or outside its host-time window")

    expected_names = {source_path.name}
    snapshots: dict[str, bytes] = {}
    w4_plan = mapping(manifest.get("w4_plan"), "W4 plan")
    w4_components = list(w4.component_records(w4_plan))
    component_roles = [record["role"] for record in w4_components]
    component_inputs = records_by_role(
        manifest.get("component_inputs"),
        component_roles,
        "component input",
        {role: MAX_FILE_BYTES for role in component_roles},
    )
    plan_components = {record["role"]: record for record in w4_components}
    for role in component_roles:
        ref = component_inputs[role]
        if any(ref[key] != plan_components[role][key] for key in ("bytes", "sha256", "schema")):
            fail("component input does not exactly join W4 plan")
        raw = snapshot_ref(input_root, ref, f"component {role}", MAX_FILE_BYTES, expected_names)
        snapshots[f"component:{role}"] = raw
        w4.validate_fixture_component(role, plan_components[role], raw, w4_plan)

    w4_signers = w4.signer_records(w4_plan)
    w4_key_inputs = records_by_role(
        manifest.get("w4_key_inputs"),
        list(w4.SIGNER_ROLES),
        "W4 key input",
        {role: 32 for role in w4.SIGNER_ROLES},
    )
    w4_signature_inputs = records_by_role(
        manifest.get("w4_signature_inputs"),
        list(w4.SIGNER_ROLES),
        "W4 signature input",
        {role: 64 for role in w4.SIGNER_ROLES},
    )
    w4_signature_b64: dict[str, str] = {}
    all_key_hashes: list[str] = []
    w4_plan_raw = w4.canonical_json(w4_plan)
    for role in w4.SIGNER_ROLES:
        key_ref = w4_key_inputs[role]
        sig_ref = w4_signature_inputs[role]
        if key_ref["schema"] != "ed25519.public-key.raw32" or sig_ref["schema"] != "ed25519.signature.raw64":
            fail("W4 key/signature schema mismatch")
        if key_ref["sha256"] != w4_signers[role]["sha256"]:
            fail("W4 signer key does not join W4 plan")
        key_raw = snapshot_ref(input_root, key_ref, f"W4 key {role}", 32, expected_names)
        sig_raw = snapshot_ref(input_root, sig_ref, f"W4 signature {role}", 64, expected_names)
        verify_signature(
            key_raw,
            sig_raw,
            w4.SIGNER_DOMAINS[role].encode("ascii") + b"\x00",
            w4_plan_raw,
            f"W4 {role}",
        )
        all_key_hashes.append(sha256(key_raw))
        snapshots[f"w4-key:{role}"] = key_raw
        snapshots[f"w4-signature:{role}"] = sig_raw
        w4_signature_b64[role] = base64.b64encode(sig_raw).decode("ascii")

    supplemental = records_by_role(
        manifest.get("supplemental_inputs"),
        list(SUPPLEMENTAL_POLICY),
        "supplemental input",
        {role: policy[1] for role, policy in SUPPLEMENTAL_POLICY.items()},
    )
    for role, (schema, maximum) in SUPPLEMENTAL_POLICY.items():
        ref = supplemental[role]
        if ref["schema"] != schema:
            fail("supplemental schema mismatch")
        snapshots[f"supplemental:{role}"] = snapshot_ref(
            input_root, ref, f"supplemental {role}", maximum, expected_names
        )

    authority_signers = signer_records(
        manifest.get("authority_signers"), AUTHORITY_ROLES, AUTHORITY_DOMAINS, "authority signers"
    )
    authority_signature_refs = mapping(source.get("authority_signatures"), "authority signatures")
    if set(authority_signature_refs) != set(AUTHORITY_ROLES):
        fail("authority signature role set mismatch")
    manifest_raw = canonical_json(manifest)
    authority_keys: dict[str, bytes] = {}
    authority_signature_raw: dict[str, bytes] = {}
    authority_times: dict[str, datetime] = {}
    for role in AUTHORITY_ROLES:
        signer = authority_signers[role]
        key_ref = {key: signer[key] for key in ("path", "bytes", "sha256")}
        key_ref["schema"] = "ed25519.public-key.raw32"
        key_raw = snapshot_ref(input_root, key_ref, f"authority key {role}", 32, expected_names)
        sig_ref = validate_ref(authority_signature_refs[role], f"authority signature {role}", 64)
        if sig_ref["schema"] != "ed25519.signature.raw64":
            fail("authority signature schema mismatch")
        sig_raw = snapshot_ref(input_root, sig_ref, f"authority signature {role}", 64, expected_names)
        verify_signature(
            key_raw,
            sig_raw,
            AUTHORITY_DOMAINS[role].encode("ascii") + b"\x00",
            manifest_raw,
            f"authority {role}",
        )
        authority_keys[role] = key_raw
        authority_signature_raw[role] = sig_raw
        authority_times[role] = utc(signer["signed_at_utc"], f"{role} signed time")
        all_key_hashes.append(sha256(key_raw))
    if len(set(all_key_hashes)) != len(all_key_hashes):
        fail("all W4 and specialized authority keys must be distinct")
    operator_time = authority_times["operator_authorization_a"]
    if any(not valid_from <= signed <= expires for signed in authority_times.values()):
        fail("specialized signature time is outside the signed validity envelope")
    if any(operator_time <= signed for role, signed in authority_times.items() if role != "operator_authorization_a"):
        fail("operator Authorization-A signature must be the final pre-session signature")
    if operator_time > expires:
        fail("operator Authorization-A signature is outside materialization expiry")

    validate_recovery_four_file(
        snapshots["component:recovery_authority"],
        snapshots["supplemental:recovery_engineering_signature"],
        authority_keys["recovery_engineering"],
        snapshots["supplemental:recovery_operator_ack"],
        snapshots["supplemental:recovery_operator_signature"],
        authority_keys["recovery_operator"],
        w4_plan,
    )

    telemetry_source_raw = snapshots["supplemental:telemetry_source_bundle"]
    telemetry_source = mapping(strict_json(telemetry_source_raw, "telemetry source bundle"), "telemetry source bundle")
    if telemetry_source.get("provenance") != "synthetic_fixture":
        fail("fixture staging accepts synthetic telemetry bytes only")
    telemetry_files: dict[str, bytes] = {
        supplemental["telemetry_source_bundle"]["path"]: telemetry_source_raw,
        supplemental["telemetry_identity_receipt"]["path"]: snapshots["supplemental:telemetry_identity_receipt"],
        supplemental["telemetry_capture_receipt"]["path"]: snapshots["supplemental:telemetry_capture_receipt"],
    }
    target = mapping(telemetry_source.get("target"), "telemetry target")
    capture = mapping(telemetry_source.get("capture"), "telemetry capture")
    if (
        target.get("identity_receipt_path") != supplemental["telemetry_identity_receipt"]["path"]
        or capture.get("capture_receipt_path") != supplemental["telemetry_capture_receipt"]["path"]
    ):
        fail("telemetry receipt paths do not join exact supplemental slots")
    responses = telemetry_source.get("responses")
    if not isinstance(responses, list) or len(responses) != 12:
        fail("telemetry source must contain exactly twelve responses")
    for index, record_value in enumerate(responses, 1):
        record = mapping(record_value, f"telemetry response {index}")
        command = telemetry.EXPECTED_CAPTURE_SEQUENCE[index - 1][1]
        role = f"telemetry_raw_{index:02d}_{command}"
        ref = supplemental[role]
        if record.get("response_path") != ref["path"]:
            fail("telemetry raw response path does not join supplemental slot")
        telemetry_files[ref["path"]] = snapshots[f"supplemental:{role}"]
    custody = output_root / "custody"
    mkdir_new_private(custody, "custody directory")
    write_new(custody / source_path.name, source_raw)
    for name, raw in telemetry_files.items():
        write_new(custody / relative_name(name, "telemetry snapshot name"), raw)
    try:
        compiled = telemetry.compile_bundle(
            custody / supplemental["telemetry_source_bundle"]["path"]
        )
    except telemetry.ContractError as exc:
        raise MaterializationError(
            "snapshotted telemetry source/raw contract refused"
        ) from exc
    compiled_raw = telemetry.canonical_json(compiled)
    if compiled_raw != snapshots["supplemental:telemetry_compiled_contract"]:
        fail("telemetry compiled contract does not match snapshotted source/raw bytes")
    wrapper = mapping(strict_json(snapshots["component:telemetry_contract"], "W4 telemetry wrapper"), "W4 telemetry wrapper")
    wrapper_join = mapping(wrapper.get("w5_materialization_join"), "W4 telemetry wrapper join")
    if wrapper_join != {
        "compiled_contract_sha256": sha256(compiled_raw),
        "source_bundle_sha256": sha256(telemetry_source_raw),
        "authentic_live_capability_verified": False,
    }:
        fail("W4 telemetry wrapper does not join compiled telemetry evidence")

    w4_source = {
        "schema": w4.PREPARE_SOURCE_SCHEMA,
        "purpose": w4.PURPOSE,
        "plan": w4_plan,
        "signatures": w4_signature_b64,
    }
    w4_source_raw = w4.canonical_json(w4_source)
    if sha256(w4_source_raw) != manifest["w4_prepare_source_sha256"]:
        fail("W4 PREPARE source bytes do not match signed materialization manifest")

    self_raw = read_regular(script_file, MAX_FILE_BYTES, "materializer source identity")
    self_record = manifest["toolchain"]["materializer"]
    if len(self_raw) != self_record["bytes"] or sha256(self_raw) != self_record["sha256"]:
        fail("materializer executing source identity mismatch")
    source_recheck = read_regular(source_path, MAX_JSON_BYTES, "materialization source revalidation")
    if source_recheck != source_raw:
        fail("materialization source changed before local consumption")
    for module_name, module_bytes, module_sha in (
        (W4_NAME, W4_BYTES, W4_SHA256),
        (W2_NAME, W2_BYTES, W2_SHA256),
    ):
        module_recheck = read_regular(
            script_dir / module_name,
            module_bytes,
            "pinned verifier module revalidation",
        )
        if len(module_recheck) != module_bytes or sha256(module_recheck) != module_sha:
            fail("pinned verifier module changed before local consumption")
    recovery_recheck = read_regular(
        recovery_verifier_path,
        RECOVERY_VERIFIER_BYTES,
        "pinned recovery verifier revalidation",
    )
    if recovery_recheck != recovery_verifier_raw:
        fail("pinned recovery verifier changed before local consumption")
    exact_membership(input_root, expected_names, "protected input root")

    input_bindings: dict[str, tuple[int, str]] = {
        source_path.name: (len(source_raw), sha256(source_raw))
    }
    ref_groups: list[Mapping[str, Mapping[str, Any]]] = [
        component_inputs,
        w4_key_inputs,
        w4_signature_inputs,
        supplemental,
    ]
    for group in ref_groups:
        for ref in group.values():
            input_bindings[ref["path"]] = (ref["bytes"], ref["sha256"])
    for record in authority_signers.values():
        input_bindings[record["path"]] = (record["bytes"], record["sha256"])
    for role in AUTHORITY_ROLES:
        ref = authority_signature_refs[role]
        input_bindings[ref["path"]] = (ref["bytes"], ref["sha256"])
    if set(input_bindings) != expected_names:
        fail("protected input binding set mismatch")

    source_sha = sha256(source_raw)
    consume_local(ledger, source_sha)
    w4_root = output_root / "w4-prepare"
    mkdir_new_private(w4_root, "W4 PREPARE directory")
    final_source = read_regular(
        source_path,
        MAX_JSON_BYTES,
        "materialization source final revalidation",
    )
    if final_source != source_raw:
        fail("materialization source changed after local consumption")
    if read_regular(custody / source_path.name, MAX_JSON_BYTES, "retained source snapshot") != source_raw:
        fail("retained materialization source snapshot mismatch")
    for name in sorted(expected_names - {source_path.name}):
        raw = read_regular(input_root / name, MAX_FILE_BYTES, "revalidated protected input")
        expected_size, expected_sha = input_bindings[name]
        if len(raw) != expected_size or sha256(raw) != expected_sha:
            fail("protected input changed before custody write")
        custody_path = custody / name
        if name in telemetry_files:
            retained = read_regular(custody_path, MAX_FILE_BYTES, "retained telemetry snapshot")
            if retained != raw:
                fail("telemetry input differs from retained compiler snapshot")
        else:
            write_new(custody_path, raw)
    # Compare every input again by its signed descriptor, catching ordinary replacement.
    exact_membership(input_root, expected_names, "protected input root revalidation")
    for role, record in plan_components.items():
        write_new(w4_root / relative_name(record["path"], "W4 component output"), snapshots[f"component:{role}"])
    for role in w4.SIGNER_ROLES:
        write_new(w4_root / relative_name(w4_signers[role]["path"], "W4 key output"), snapshots[f"w4-key:{role}"])
    write_new(w4_root / "prepare-source.json", w4_source_raw)
    w4_expected = {"prepare-source.json"}
    w4_expected.update(record["path"] for record in plan_components.values())
    w4_expected.update(w4_signers[role]["path"] for role in w4.SIGNER_ROLES)
    exact_membership(w4_root, w4_expected, "materialized W4 PREPARE directory")
    exact_membership(custody, expected_names, "materialized custody directory")
    terminal = output_root / ".terminal-no-authority"
    write_new(
        terminal,
        canonical_json(
            {
                "schema": "dcent.nano3.a-materialization-terminal-no-authority.v1",
                "status": STATUS,
                "w4_prepare_byte_contract_staged": True,
                "production_materialization_complete": False,
                "global_one_shot_consumed": False,
                "authorization_a_granted": False,
                "device_contact": "none",
            }
        ),
    )
    # `.incomplete` intentionally remains: this repository cannot complete production A.
    exact_membership(
        output_root,
        {".incomplete", ".terminal-no-authority", "custody", "w4-prepare"},
        "staging output root",
    )
    fsync_supported = fsync_dir(output_root)
    public = {
        "schema": PUBLIC_RECEIPT_SCHEMA,
        "status": STATUS,
        "mode": "synthetic_fixture",
        "w4_prepare_byte_contract_staged": True,
        "production_materialization_complete": False,
        "cryptographic_fixture_signatures_verified": True,
        "local_replay_marker_consumed": True,
        "local_replay_is_global": False,
        "directory_fsync_supported": fsync_supported,
        "posix_owner_mode_verified": os.name != "nt",
        "windows_acl_privacy_verified": False,
        "preexecution_materializer_identity_verified": False,
        "external_crypto_dependency_identity_verified": False,
        "internal_code_byte_consistency_verified": True,
        **PUBLIC_STATE_POLICY,
        "authorization_a_granted": False,
        "device_contact": "none",
        "authority": "none; incomplete offline staging only",
    }
    validate_public_states(public, "public receipt")
    write_new(public_receipt_path, canonical_json(public))
    return public


def validate_template(path: Path) -> Mapping[str, Any]:
    raw = read_regular(path, MAX_JSON_BYTES, "invalid template")
    document = mapping(strict_json(raw, "invalid template"), "invalid template")
    exact_keys(
        document,
        {
            "schema", "status", "purpose", "production_authority_key_pins",
            "production_w4_key_pins", "required_supplemental_roles",
            "external_states", "public_states", "authorization_a_granted",
            "device_contact",
        },
        "invalid template",
    )
    if (
        document.get("schema") != TEMPLATE_SCHEMA
        or document.get("status") != "INTENTIONALLY_INVALID_NONAUTHORIZING_TEMPLATE"
        or document.get("purpose") != PURPOSE
        or document.get("production_authority_key_pins")
        != {role: None for role in AUTHORITY_ROLES}
        or document.get("production_w4_key_pins") != {}
        or document.get("required_supplemental_roles") != list(SUPPLEMENTAL_POLICY)
        or document.get("external_states") != EXTERNAL_STATE_POLICY
        or document.get("public_states") != PUBLIC_STATE_POLICY
        or document.get("authorization_a_granted") is not False
        or document.get("device_contact") != "none"
    ):
        fail("invalid template boundary mismatch")
    return {
        "status": document["status"],
        "production_materialization_complete": False,
        "authorization_a_granted": False,
        "device_contact": "none",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    template = sub.add_parser("validate-template")
    template.add_argument("--template", required=True, type=Path)
    materialize_parser = sub.add_parser("materialize")
    materialize_parser.add_argument("--source", required=True, type=Path)
    materialize_parser.add_argument("--output-root", required=True, type=Path)
    materialize_parser.add_argument("--public-receipt", required=True, type=Path)
    materialize_parser.add_argument("--ledger", required=True, type=Path)
    materialize_parser.add_argument("--fixture-only", action="store_true")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate-template":
            result = validate_template(args.template)
            print(
                f"{result['status']}: production=false authorization_a=false "
                "device_contact=none"
            )
            return 0
        for path, label in (
            (args.source, "source"),
            (args.output_root, "output root"),
            (args.public_receipt, "public receipt"),
            (args.ledger, "ledger"),
        ):
            if not path.is_absolute():
                fail(f"{label} path must be absolute")
        receipt = materialize(
            args.source,
            args.output_root,
            args.public_receipt,
            args.ledger,
            fixture_only=args.fixture_only,
        )
        print(
            f"{receipt['status']}: production=false authorization_a=false "
            "device_contact=none"
        )
        return 0
    except MaterializationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("REFUSED: bounded host I/O failure", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
