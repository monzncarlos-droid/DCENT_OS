#!/usr/bin/env python3
"""Offline PREPARE/FINALIZE compiler for one Nano 3 Authorization-A session.

The tool has no network, USB, UART, subprocess, power, flash, reboot, or live
process path. Production key pins are intentionally empty. Every emitted
record therefore keeps Authorization A false and device contact at none.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PREPARE_SOURCE_SCHEMA = "dcent.nano3.a-session-prepare-source.v1"
PLAN_SCHEMA = "dcent.nano3.a-session-plan.v1"
PREPARE_RECEIPT_SCHEMA = "dcent.nano3.a-session-prepare-receipt.v1"
FINALIZE_SOURCE_SCHEMA = "dcent.nano3.a-session-finalize-source.v1"
FINALIZE_STATEMENT_SCHEMA = "dcent.nano3.a-session-finalize-statement.v1"
FINALIZE_RECEIPT_SCHEMA = "dcent.nano3.a-session-finalize-receipt.v1"
TEMPLATE_SCHEMA = "dcent.nano3.a-session-admission-template.v1"
PURPOSE = "nano3_authorization_a_exact_session_composition_only"
TARGET_MODEL = "canaan-avalon-nano3-non-s"
BTCMINER_SHA256 = "e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751"

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 32
MAX_WINDOW_SECONDS = 30 * 60
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")

IMAGE_SHA256 = "3c80c1b5d58edb733a125ea5cc33399d5fbcf4e7051310a3a5a5da3199516951"
IMAGE_BYTES = 38_536_192
IMAGE_RECEIPT_SHA256 = "bf18ff8eb27dbfb8618bae2fe1accfbc827e1757ecb82278b165de4e26e4c266"
TELEMETRY_REQUEST_SHA256 = "e27c02f47c8c21cac41035fa5d5e0d51a7d34225df3401c32bed58986a075f0e"
ROLLBACK_CUSTODY_SHA256 = "fc6cd60d4845786dd1881b7d85c661cf4290e18b457e26ebca02d0481d3bb992"

CLASS_DESK = "desk_identity_only"
CLASS_PRIOR = "prior_live_qualification"
CLASS_AUTH = "pre_session_authority"
CLASS_RESULT = "current_session_result_only"

COMPONENT_POLICY: dict[str, tuple[str, str]] = {
    "image_candidate": (CLASS_DESK, "opaque.kdimg"),
    "image_receipt": (CLASS_DESK, "dcent.nano3.user-donor-rootfs-mutation-receipt.v1"),
    "recovery_authority": (CLASS_AUTH, "dcent.k230.factory-recovery-authorization.v1"),
    "telemetry_capture_request": (CLASS_DESK, "dcent.nano3.stock-telemetry-capture-request.v1"),
    "telemetry_contract": (CLASS_PRIOR, "dcent.nano3.stock-telemetry-contract.v1"),
    "post_cut_plan": (CLASS_AUTH, "dcent.nano3.post-cut-plan.v2"),
    "pool_plan": (CLASS_AUTH, "dcent.nano3.isolated-pool-session-plan.v1"),
    "pool_topology": (CLASS_PRIOR, "dcent.nano3.isolated-pool-topology-receipt.v1"),
    "safety_qualification": (CLASS_PRIOR, "dcent-nano3-interlock-production-qualification.v1"),
    "rollback_custody": (CLASS_DESK, "dcent.nano3.w1.rollback-custody-manifest.v1"),
    "trusted_time_record": (CLASS_PRIOR, "dcent.nano3.trusted-time-record.v1"),
    "global_replay_record": (CLASS_PRIOR, "dcent.nano3.global-one-shot-record.v1"),
}

SIGNER_ROLES = (
    "admission_reviewer",
    "operator",
    "recovery_authority",
    "telemetry_authority",
    "post_cut_authority",
    "pool_topology_authority",
    "trusted_time_authority",
)
SIGNER_DOMAINS = {
    role: f"DCENT:NANO3:A-SESSION:{role.upper().replace('_', '-')}:V1"
    for role in SIGNER_ROLES
}
PRODUCTION_KEY_PINS = {role: "" for role in SIGNER_ROLES}
PRODUCTION_RESULT_REVIEWER_KEY_PIN = ""
RESULT_DOMAIN = "DCENT:NANO3:A-SESSION:RESULT-REVIEWER:V1"

RESULT_POLICY: dict[str, tuple[str, str]] = {
    "pool_receipt": ("dcent.nano3.isolated-pool-receipt.v1", "always"),
    "post_cut_receipt": ("dcent.nano3.post-cut-receipt.v2", "manual_ac_invoked"),
    "restoration_receipt": ("dcent.nano3.a-session-restoration-result.v1", "always"),
}

ALLOWED_ACTIONS = [
    "flash_exact_v19_rootfs_only",
    "attended_reboot_and_energization",
    "host_to_target_tmpfs_load",
    "serialized_4028_hashoff_and_restore",
    "manual_whole_unit_ac_disconnect_on_abort",
    "bounded_evidence_collection",
]
EXCLUDED_ACTIONS = [
    "phase_4_watchdog_close",
    "kill_or_signal_btcminer",
    "uart_or_native_tx",
    "fixed_fan_duty",
    "persistent_data_erase",
    "rollback_without_separate_recovery_authorization",
    "unattended_operation",
]

FALSE_CLAIMS = {
    "authorization_a_granted",
    "device_contact_authorized",
    "energization_authorized",
    "flash_authorized",
    "hardware_action_performed",
    "post_session_results_can_retroactively_authorize",
    "production_authority_granted",
    "reboot_authorized",
    "rollback_authorized_by_a",
    "unattended_operation_authorized",
}

TYPED_STATE_POLICY = {
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


class AdmissionError(RuntimeError):
    """Fail-closed composition error."""


def fail(message: str) -> NoReturn:
    raise AdmissionError(message)


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
        raise AdmissionError("document is not finite canonical ASCII JSON") from exc


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
        raise AdmissionError(f"malformed {label}") from exc


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


def finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        fail(f"{label} must be finite")
    return result


def utc(value: Any, label: str) -> datetime:
    raw = text(value, label, 20)
    if not raw.endswith("Z"):
        fail(f"{label} must use UTC Z form")
    try:
        result = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as exc:
        raise AdmissionError(f"{label} is not RFC3339 UTC") from exc
    if result.tzinfo != timezone.utc or result.microsecond:
        fail(f"{label} must be whole-second UTC")
    return result


def is_alias(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def verify_dir(path: Path, label: str) -> None:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except OSError as exc:
            raise AdmissionError(f"{label} path unavailable") from exc
        if is_alias(info) or not stat.S_ISDIR(info.st_mode):
            fail(f"{label} contains an alias or non-directory")


def relative_file(root: Path, value: Any, label: str) -> Path:
    name = text(value, label)
    if not NAME_RE.fullmatch(name) or name in {".", ".."}:
        fail(f"{label} must be one normalized relative filename")
    path = root / name
    if path.parent != root:
        fail(f"{label} escapes bundle root")
    return path


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AdmissionError(f"{label} unavailable") from exc
    if is_alias(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a non-alias regular file")
    if not 0 < before.st_size <= maximum:
        fail(f"{label} size outside bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
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
    opened_id = (opened.st_dev, opened.st_ino, after.st_size, after.st_mtime_ns)
    if (
        before_id != opened_id
        or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        or after.st_nlink != 1
    ):
        fail(f"{label} changed while reading")
    if count != after.st_size:
        fail(f"{label} short read")
    return b"".join(chunks)


def fsync_dir(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path: Path, raw: bytes) -> None:
    verify_dir(path.parent, "output parent")
    if path.exists() or path.is_symlink():
        fail("refusing to overwrite output")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            amount = os.write(fd, raw[offset:])
            if amount <= 0:
                fail("output write made no progress")
            offset += amount
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)


def load_source(path: Path) -> tuple[Mapping[str, Any], bytes, Path]:
    if not path.is_absolute():
        fail("source path must be absolute")
    verify_dir(path.parent, "bundle root")
    raw = read_regular(path, MAX_JSON_BYTES, "source")
    return mapping(strict_json(raw, "source"), "source"), raw, path.parent


def exact_membership(root: Path, expected: set[str]) -> None:
    actual: set[str] = set()
    for index, child in enumerate(root.iterdir(), start=1):
        if index > MAX_FILES:
            fail("bundle has too many entries")
        info = child.lstat()
        if is_alias(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("bundle contains an alias, directory, or non-regular entry")
        actual.add(child.name)
    if actual != expected:
        fail("bundle exact file membership mismatch")


def false_claims(value: Any, label: str) -> Mapping[str, Any]:
    claims = mapping(value, label)
    if set(claims) != FALSE_CLAIMS or any(item is not False for item in claims.values()):
        fail(f"{label} must keep every claim false")
    return claims


def signature_results(*, cryptographically_verified: bool) -> dict[str, bool]:
    return {
        "cryptographically_verified": cryptographically_verified,
        "production_key_pin_verified": False,
        "authority_proven": False,
    }


def validate_signature_results(value: Any, label: str) -> None:
    results = mapping(value, label)
    if set(results) != set(SIGNER_ROLES):
        fail(f"{label} role set mismatch")
    expected = signature_results(cryptographically_verified=True)
    for role in SIGNER_ROLES:
        result = mapping(results[role], f"{label} {role}")
        if result != expected:
            fail(f"{label} {role} typed state mismatch")


def validate_typed_states(value: Mapping[str, Any], label: str) -> None:
    for key, expected in TYPED_STATE_POLICY.items():
        if value.get(key) is not expected:
            fail(f"{label} {key} typed state mismatch")


def component_records(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values = plan.get("components")
    if not isinstance(values, list) or len(values) != len(COMPONENT_POLICY):
        fail("component count mismatch")
    result: list[Mapping[str, Any]] = []
    roles: list[str] = []
    for item in values:
        record = mapping(item, "component")
        exact_keys(record, {"role", "classification", "schema", "path", "bytes", "sha256"}, "component")
        role = text(record.get("role"), "component role")
        roles.append(role)
        expected = COMPONENT_POLICY.get(role)
        if expected is None or (record.get("classification"), record.get("schema")) != expected:
            fail("component classification/schema mismatch")
        positive_int(record.get("bytes"), "component bytes", MAX_FILE_BYTES)
        digest(record.get("sha256"), "component digest")
        result.append(record)
    if roles != list(COMPONENT_POLICY) or len(set(roles)) != len(roles):
        fail("component roles/order mismatch")
    return result


def signer_records(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    signers = mapping(plan.get("signers"), "signers")
    if set(signers) != set(SIGNER_ROLES):
        fail("signer role set mismatch")
    hashes: list[str] = []
    for role in SIGNER_ROLES:
        record = mapping(signers[role], f"{role} signer")
        exact_keys(record, {"path", "bytes", "sha256", "domain", "key_epoch"}, f"{role} signer")
        if record.get("bytes") != 32:
            fail("signer public key must be 32 bytes")
        hashes.append(digest(record.get("sha256"), f"{role} key digest"))
        if record.get("domain") != SIGNER_DOMAINS[role]:
            fail(f"{role} domain mismatch")
        identifier(record.get("key_epoch"), f"{role} key epoch")
    if len(set(hashes)) != len(hashes):
        fail("all signer keys must be distinct")
    return signers


def result_expectations(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values = plan.get("expected_results")
    if not isinstance(values, list) or len(values) != len(RESULT_POLICY):
        fail("result expectation count mismatch")
    result: list[Mapping[str, Any]] = []
    roles: list[str] = []
    for item in values:
        record = mapping(item, "result expectation")
        exact_keys(
            record,
            {"role", "classification", "schema", "required_when", "output_name", "producer_sha256", "join"},
            "result expectation",
        )
        role = text(record.get("role"), "result role")
        roles.append(role)
        policy = RESULT_POLICY.get(role)
        if policy is None or (
            record.get("classification"), record.get("schema"), record.get("required_when")
        ) != (CLASS_RESULT, policy[0], policy[1]):
            fail("result expectation policy mismatch")
        if record.get("join") != "exact_prepare_plan_session_unit_nonce_and_role":
            fail("result join policy mismatch")
        output_name = text(record.get("output_name"), "result output name")
        if not NAME_RE.fullmatch(output_name) or output_name in {".", ".."}:
            fail("result output name must be one normalized relative filename")
        digest(record.get("producer_sha256"), "result producer digest")
        result.append(record)
    if roles != list(RESULT_POLICY) or len(set(roles)) != len(roles):
        fail("result roles/order mismatch")
    if len({item["output_name"] for item in result}) != len(result):
        fail("result output names must be distinct")
    return result


def validate_plan(plan: Mapping[str, Any], fixture_only: bool) -> tuple[datetime, datetime]:
    exact_keys(
        plan,
        {
            "schema", "purpose", "bundle_id", "mode", "issued_at_utc", "valid_from_utc",
            "expires_at_utc", "session", "actions", "components", "signers",
            "expected_results", "claims",
        },
        "plan",
    )
    if plan.get("schema") != PLAN_SCHEMA or plan.get("purpose") != PURPOSE:
        fail("plan schema/purpose mismatch")
    identifier(plan.get("bundle_id"), "bundle id")
    expected_mode = "synthetic_fixture" if fixture_only else "production"
    if plan.get("mode") != expected_mode:
        fail("plan mode mismatch")
    issued = utc(plan.get("issued_at_utc"), "issued time")
    valid_from = utc(plan.get("valid_from_utc"), "valid-from time")
    expires = utc(plan.get("expires_at_utc"), "expiry")
    if not issued <= valid_from < expires or (expires - valid_from).total_seconds() > MAX_WINDOW_SECONDS:
        fail("plan time ordering/window invalid")
    session = mapping(plan.get("session"), "session")
    exact_keys(
        session,
        {
            "session_id", "unit_id", "unit_model", "unit_fingerprint_sha256", "nonce_sha256",
            "operator_id", "authorization_reference", "btcminer_sha256", "trusted_time_record_sha256",
            "global_replay_record_sha256",
        },
        "session",
    )
    for key in ("session_id", "unit_id", "operator_id", "authorization_reference"):
        identifier(session.get(key), key)
    if session.get("unit_model") != TARGET_MODEL or session.get("btcminer_sha256") != BTCMINER_SHA256:
        fail("target model/btcminer mismatch")
    for key in (
        "unit_fingerprint_sha256", "nonce_sha256", "trusted_time_record_sha256",
        "global_replay_record_sha256",
    ):
        digest(session.get(key), key)
    actions = mapping(plan.get("actions"), "actions")
    exact_keys(actions, {"allowed", "excluded"}, "actions")
    if actions.get("allowed") != ALLOWED_ACTIONS or actions.get("excluded") != EXCLUDED_ACTIONS:
        fail("action allowlist/exclusions mismatch")
    if any(not isinstance(item, str) for item in actions["allowed"] + actions["excluded"]):
        fail("actions must be strings")
    if len(set(actions["allowed"])) != len(actions["allowed"]) or len(set(actions["excluded"])) != len(actions["excluded"]):
        fail("duplicate action")
    component_records(plan)
    signer_records(plan)
    result_expectations(plan)
    false_claims(plan.get("claims"), "plan claims")
    return valid_from, expires


def decode_signature(value: Any, label: str) -> bytes:
    try:
        result = base64.b64decode(text(value, label), validate=True)
    except ValueError as exc:
        raise AdmissionError(f"{label} is not strict base64") from exc
    if len(result) != 64:
        fail(f"{label} must be 64 bytes")
    return result


def public_key(raw: bytes, expected: str, label: str) -> Ed25519PublicKey:
    if len(raw) != 32 or sha256(raw) != expected:
        fail(f"{label} key binding mismatch")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise AdmissionError(f"{label} key invalid") from exc


def verify_signature(
    key: Ed25519PublicKey,
    signature: bytes,
    domain: str,
    document: Mapping[str, Any],
    label: str,
) -> None:
    try:
        key.verify(signature, domain.encode("ascii") + b"\x00" + canonical_json(document))
    except InvalidSignature as exc:
        raise AdmissionError(f"{label} signature invalid") from exc


def validate_fixture_component(
    role: str, record: Mapping[str, Any], raw: bytes, plan: Mapping[str, Any]
) -> None:
    if role == "image_candidate":
        return
    document = mapping(strict_json(raw, role), role)
    if role == "safety_qualification":
        schema_ok = document.get("schema_version") == 1 and document.get("record_type") == (
            "dcent-nano3-interlock-production-qualification"
        )
    else:
        schema_ok = document.get("schema") == record["schema"]
    if not schema_ok:
        fail(f"{role} embedded schema mismatch")
    expected = {
        "fixture_only": True,
        "role": role,
        "classification": record["classification"],
        "session_id": plan["session"]["session_id"],
        "unit_id": plan["session"]["unit_id"],
        "nonce_sha256": plan["session"]["nonce_sha256"],
        "authority_granted": False,
        "physical_authenticity_proven": False,
    }
    if document.get("w4_fixture_binding") != expected:
        fail(f"{role} fixture binding mismatch")


def validate_production_component(role: str, record: Mapping[str, Any], raw: bytes) -> None:
    if role == "image_candidate":
        if len(raw) != IMAGE_BYTES or sha256(raw) != IMAGE_SHA256:
            fail("image is not exact frozen v19")
        return
    if role == "image_receipt" and sha256(raw) != IMAGE_RECEIPT_SHA256:
        fail("image receipt differs from frozen W1 receipt")
    if role == "telemetry_capture_request" and sha256(raw) != TELEMETRY_REQUEST_SHA256:
        fail("telemetry request differs from frozen W2 request")
    if role == "rollback_custody" and sha256(raw) != ROLLBACK_CUSTODY_SHA256:
        fail("rollback custody differs from frozen W1 record")
    document = mapping(strict_json(raw, role), role)
    if role == "safety_qualification":
        if document.get("schema_version") != 1 or document.get("record_type") != (
            "dcent-nano3-interlock-production-qualification"
        ):
            fail("safety qualification schema mismatch")
        if document.get("qualification_status") != "QUALIFIED":
            fail("safety interlock is not qualified")
    elif document.get("schema") != record["schema"]:
        fail(f"{role} schema mismatch")
    if role == "telemetry_contract":
        capabilities = mapping(document.get("capabilities"), "telemetry capabilities")
        required = (
            "mhs_5s_mh_per_second", "accepted_counter", "rejected_counter",
            "hardware_error_counter", "all_required_temperature_sensors_covered",
            "stock_auto_mode_observable", "source_sensor_sample_freshness_observable",
            "current_pool_and_user", "lcd_pool_and_user_corroboration",
        )
        if document.get("soak_runtime_ready") is not True or any(capabilities.get(key) is not True for key in required):
            fail("telemetry contract is not authentic/live capable")
    if role == "post_cut_plan" and document.get("status") != "APPROVED_FOR_ONE_ATTENDED_SESSION":
        fail("post-cut plan is not approved")


def read_prepare_files(
    root: Path, source_name: str, plan: Mapping[str, Any], fixture_only: bool
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    expected = {source_name}
    components: dict[str, bytes] = {}
    for record in component_records(plan):
        role = record["role"]
        path = relative_file(root, record["path"], f"{role} path")
        if path.name in expected:
            fail("duplicate bundle filename")
        expected.add(path.name)
        raw = read_regular(path, MAX_FILE_BYTES, role)
        if len(raw) != record["bytes"] or sha256(raw) != record["sha256"]:
            fail(f"{role} size/digest mismatch")
        if fixture_only:
            validate_fixture_component(role, record, raw, plan)
        else:
            validate_production_component(role, record, raw)
        components[role] = raw
    keys: dict[str, bytes] = {}
    for role, record in signer_records(plan).items():
        path = relative_file(root, record["path"], f"{role} key path")
        if path.name in expected:
            fail("duplicate bundle filename")
        expected.add(path.name)
        raw = read_regular(path, 32, f"{role} key")
        if len(raw) != 32 or sha256(raw) != record["sha256"]:
            fail(f"{role} key binding mismatch")
        keys[role] = raw
    exact_membership(root, expected)
    return components, keys


def consume(ledger: Path, phase: str, key: str) -> Mapping[str, Any]:
    verify_dir(ledger, "replay ledger")
    if os.name != "nt" and stat.S_IMODE(ledger.lstat().st_mode) & 0o077:
        fail("replay ledger must be owner-only on POSIX")
    marker = ledger / f"nano3-a-{phase}-{key}.consumed"
    body = canonical_json(
        {
            "schema": "dcent.nano3.a-session-local-consumption.v1",
            "phase": phase,
            "key": key,
            "global_replay_prevention_proven": False,
        }
    )
    write_new(marker, body)
    return {
        "local_ledger_consumed": True,
        "marker_sha256": sha256(body),
        "global_replay_prevention_proven": False,
        "cross_host_replay_prevention_proven": False,
        "ledger_deletion_resistance_proven": False,
        "windows_acl_privacy_verified": False,
    }


def prepare(
    source_path: Path,
    ledger: Path,
    *,
    fixture_only: bool,
    now: Optional[datetime] = None,
) -> Mapping[str, Any]:
    source, source_raw, root = load_source(source_path)
    exact_keys(source, {"schema", "purpose", "plan", "signatures"}, "prepare source")
    if source.get("schema") != PREPARE_SOURCE_SCHEMA or source.get("purpose") != PURPOSE:
        fail("prepare source schema/purpose mismatch")
    plan = mapping(source.get("plan"), "plan")
    valid_from, expires = validate_plan(plan, fixture_only)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or not valid_from <= current <= expires:
        fail("plan is stale, future, or outside current window")
    components, keys = read_prepare_files(root, source_path.name, plan, fixture_only)
    records = {record["role"]: record for record in component_records(plan)}
    if (
        records["trusted_time_record"]["sha256"]
        != plan["session"]["trusted_time_record_sha256"]
        or records["global_replay_record"]["sha256"]
        != plan["session"]["global_replay_record_sha256"]
    ):
        fail("trusted-time/global-replay records do not join session plan")
    nonce_document = mapping(strict_json(components["pool_plan"], "pool plan"), "pool plan")
    if fixture_only:
        nonce_hash = nonce_document["w4_fixture_binding"]["nonce_sha256"]
    else:
        nonce_hash = plan["session"]["nonce_sha256"]
    if nonce_hash != plan["session"]["nonce_sha256"]:
        fail("pool plan/session nonce mismatch")
    signatures = mapping(source.get("signatures"), "signatures")
    if set(signatures) != set(SIGNER_ROLES):
        fail("signature role set mismatch")
    if not fixture_only:
        if any(not SHA_RE.fullmatch(PRODUCTION_KEY_PINS[role]) for role in SIGNER_ROLES):
            fail("production signer pins are not provisioned")
        if any(plan["signers"][role]["sha256"] != PRODUCTION_KEY_PINS[role] for role in SIGNER_ROLES):
            fail("plan signer does not match production pin")
    for role in SIGNER_ROLES:
        key = public_key(keys[role], plan["signers"][role]["sha256"], role)
        verify_signature(
            key,
            decode_signature(signatures[role], f"{role} signature"),
            SIGNER_DOMAINS[role],
            plan,
            role,
        )
    plan_raw = canonical_json(plan)
    plan_sha = sha256(plan_raw)
    replay = consume(ledger, "prepare", plan_sha)
    session = plan["session"]
    public_commitment_key = bytes.fromhex(session["nonce_sha256"])
    component_summary = [
        {key: record[key] for key in ("role", "classification", "schema", "bytes", "sha256")}
        for record in component_records(plan)
    ]
    return {
        "schema": PREPARE_RECEIPT_SCHEMA,
        "purpose": PURPOSE,
        "mode": plan["mode"],
        "bundle_id": plan["bundle_id"],
        "plan_sha256": plan_sha,
        "source_sha256": sha256(source_raw),
        "session": {
            "session_id": session["session_id"],
            "nonce_sha256": session["nonce_sha256"],
            "unit_id_hmac_sha256": hmac.new(
                public_commitment_key,
                session["unit_id"].encode(),
                hashlib.sha256,
            ).hexdigest(),
            "unit_fingerprint_hmac_sha256": hmac.new(
                public_commitment_key,
                session["unit_fingerprint_sha256"].encode(),
                hashlib.sha256,
            ).hexdigest(),
            "valid_from_utc": plan["valid_from_utc"],
            "expires_at_utc": plan["expires_at_utc"],
        },
        "components": component_summary,
        "expected_results": result_expectations(plan),
        "signatures": {
            role: signature_results(cryptographically_verified=True)
            for role in SIGNER_ROLES
        },
        "classification_policy": {
            "desk_identity_only_is_not_authority": True,
            "prior_live_qualification_precedes_session": True,
            "pre_session_authority_precedes_contact": True,
            "current_session_results_cannot_flow_backward": True,
        },
        "replay": replay,
        "machine_prepare_composition_valid": True,
        "precontact_admission_ready": False,
        "production_pins_provisioned": False,
        "trusted_time_provenance_independently_proven": False,
        "physical_authenticity_proven_by_composer": False,
        **TYPED_STATE_POLICY,
        "claims": {key: False for key in sorted(FALSE_CLAIMS)},
        "authorization_a_granted": False,
        "device_contact": "none",
        "authority": "offline composition only; authorizes no action",
    }


def validate_prepare_receipt(receipt: Mapping[str, Any]) -> None:
    if receipt.get("schema") != PREPARE_RECEIPT_SCHEMA or receipt.get("purpose") != PURPOSE:
        fail("prepare receipt schema/purpose mismatch")
    if receipt.get("authorization_a_granted") is not False or receipt.get("device_contact") != "none":
        fail("prepare receipt overclaims")
    if receipt.get("precontact_admission_ready") is not False:
        fail("prepare receipt cannot be ready in checked-in compiler")
    session = mapping(receipt.get("session"), "prepare receipt session")
    exact_keys(
        session,
        {
            "session_id", "nonce_sha256", "unit_id_hmac_sha256",
            "unit_fingerprint_hmac_sha256", "valid_from_utc", "expires_at_utc",
        },
        "prepare receipt session",
    )
    identifier(session.get("session_id"), "prepare receipt session id")
    for key in (
        "nonce_sha256", "unit_id_hmac_sha256", "unit_fingerprint_hmac_sha256"
    ):
        digest(session.get(key), f"prepare receipt {key}")
    validate_signature_results(receipt.get("signatures"), "prepare signature results")
    validate_typed_states(receipt, "prepare receipt")
    false_claims(receipt.get("claims"), "prepare receipt claims")


def result_required(condition: str, statement: Mapping[str, Any]) -> bool:
    return condition == "always" or (
        condition == "manual_ac_invoked" and statement.get("manual_ac_invoked") is True
    )


def finalize(
    source_path: Path,
    ledger: Path,
    *,
    fixture_only: bool,
    now: Optional[datetime] = None,
) -> Mapping[str, Any]:
    source, source_raw, root = load_source(source_path)
    exact_keys(
        source,
        {
            "schema", "purpose", "prepare_receipt", "statement", "result_reviewer_key",
            "result_reviewer_signature_base64", "results",
        },
        "finalize source",
    )
    if source.get("schema") != FINALIZE_SOURCE_SCHEMA or source.get("purpose") != PURPOSE:
        fail("finalize source schema/purpose mismatch")
    prepare_ref = mapping(source.get("prepare_receipt"), "prepare receipt reference")
    key_ref = mapping(source.get("result_reviewer_key"), "result reviewer key reference")
    for ref, label, maximum in (
        (prepare_ref, "prepare receipt", MAX_JSON_BYTES),
        (key_ref, "result reviewer key", 32),
    ):
        exact_keys(ref, {"path", "bytes", "sha256"}, label)
        positive_int(ref.get("bytes"), f"{label} bytes", maximum)
        digest(ref.get("sha256"), f"{label} digest")
    prepare_path = relative_file(root, prepare_ref["path"], "prepare receipt path")
    prepare_raw = read_regular(prepare_path, MAX_JSON_BYTES, "prepare receipt")
    if len(prepare_raw) != prepare_ref["bytes"] or sha256(prepare_raw) != prepare_ref["sha256"]:
        fail("prepare receipt binding mismatch")
    prepared = mapping(strict_json(prepare_raw, "prepare receipt"), "prepare receipt")
    validate_prepare_receipt(prepared)
    key_path = relative_file(root, key_ref["path"], "result reviewer key path")
    key_raw = read_regular(key_path, 32, "result reviewer key")
    if len(key_raw) != key_ref["bytes"] or sha256(key_raw) != key_ref["sha256"]:
        fail("result reviewer key binding mismatch")
    if not fixture_only:
        if not SHA_RE.fullmatch(PRODUCTION_RESULT_REVIEWER_KEY_PIN):
            fail("production result reviewer pin is not provisioned")
        if key_ref["sha256"] != PRODUCTION_RESULT_REVIEWER_KEY_PIN:
            fail("result reviewer key pin mismatch")
    reviewer = public_key(key_raw, key_ref["sha256"], "result reviewer")
    statement = mapping(source.get("statement"), "finalize statement")
    exact_keys(
        statement,
        {
            "schema", "purpose", "mode", "prepare_receipt_sha256", "prepare_plan_sha256",
            "session_id", "compiled_at_utc", "manual_ac_invoked",
            "results_manifest_sha256", "authorization_a_granted",
        },
        "finalize statement",
    )
    if statement.get("schema") != FINALIZE_STATEMENT_SCHEMA or statement.get("purpose") != PURPOSE:
        fail("finalize statement schema/purpose mismatch")
    expected_mode = "synthetic_fixture" if fixture_only else "production"
    if statement.get("mode") != expected_mode:
        fail("finalize mode mismatch")
    joins = {
        "prepare_receipt_sha256": prepare_ref["sha256"],
        "prepare_plan_sha256": prepared["plan_sha256"],
        "session_id": prepared["session"]["session_id"],
    }
    if any(statement.get(key) != value for key, value in joins.items()):
        fail("finalize statement mixes prepare/session inputs")
    if statement.get("authorization_a_granted") is not False:
        fail("finalize cannot grant Authorization A")
    values = source.get("results")
    if not isinstance(values, list) or len(values) != len(RESULT_POLICY):
        fail("finalize result count mismatch")
    manifest_sha = digest(
        statement.get("results_manifest_sha256"),
        "results manifest digest",
    )
    if manifest_sha != sha256(canonical_json(values)):
        fail("signed results manifest binding mismatch")
    compiled = utc(statement.get("compiled_at_utc"), "finalize time")
    current = now or datetime.now(timezone.utc)
    age_seconds = (current - compiled).total_seconds()
    if current.tzinfo is None or age_seconds < 0 or age_seconds > MAX_WINDOW_SECONDS:
        fail("finalize statement stale or future")
    verify_signature(
        reviewer,
        decode_signature(source.get("result_reviewer_signature_base64"), "result signature"),
        RESULT_DOMAIN,
        statement,
        "result reviewer",
    )
    expectations = {item["role"]: item for item in prepared["expected_results"]}
    expected_files = {source_path.name, prepare_path.name, key_path.name}
    summary: list[dict[str, Any]] = []
    roles: list[str] = []
    for item in values:
        record = mapping(item, "result")
        exact_keys(record, {"role", "status", "path", "bytes", "sha256", "schema", "producer_sha256"}, "result")
        role = text(record.get("role"), "result role")
        roles.append(role)
        policy = RESULT_POLICY.get(role)
        expected = expectations.get(role)
        if policy is None or expected is None:
            fail("unexpected result role")
        if record.get("schema") != policy[0] or record.get("producer_sha256") != expected["producer_sha256"]:
            fail("result schema/producer substitution")
        required = result_required(policy[1], statement)
        if record.get("status") == "not_performed":
            if required or any(record.get(key) is not None for key in ("path", "bytes", "sha256")):
                fail("required or malformed not-performed result")
            summary.append({"role": role, "status": "not_performed", "schema": policy[0]})
            continue
        if record.get("status") != "present":
            fail("unknown result status")
        path = relative_file(root, record.get("path"), f"{role} path")
        if path.name != expected["output_name"] or path.name in expected_files:
            fail("result path differs from prepare commitment")
        expected_files.add(path.name)
        size = positive_int(record.get("bytes"), f"{role} bytes", MAX_FILE_BYTES)
        expected_sha = digest(record.get("sha256"), f"{role} digest")
        raw = read_regular(path, MAX_FILE_BYTES, role)
        if len(raw) != size or sha256(raw) != expected_sha:
            fail(f"{role} binding mismatch")
        document = mapping(strict_json(raw, role), role)
        if document.get("schema") != policy[0]:
            fail(f"{role} embedded schema mismatch")
        result_join = mapping(document.get("a_session_join"), f"{role} session join")
        expected_join = {
            "prepare_plan_sha256": prepared["plan_sha256"],
            "session_id": prepared["session"]["session_id"],
            "unit_id_hmac_sha256": prepared["session"]["unit_id_hmac_sha256"],
            "unit_fingerprint_hmac_sha256": prepared["session"][
                "unit_fingerprint_hmac_sha256"
            ],
            "nonce_sha256": prepared["session"]["nonce_sha256"],
            "role": role,
            "authorization_a_granted": False,
        }
        if result_join != expected_join:
            fail(f"{role} plan/session/unit/nonce/role join mismatch")
        if fixture_only:
            exact_keys(
                document,
                {"schema", "a_session_join", "w4_fixture_result_binding"},
                f"{role} fixture document",
            )
            fixture_binding = {
                "fixture_only": True,
                "role": role,
                "authorization_a_granted": False,
            }
            if document.get("w4_fixture_result_binding") != fixture_binding:
                fail(f"{role} fixture join mismatch")
        elif document.get("authorization_a_granted") is not False:
            fail(f"{role} overclaims Authorization A")
        summary.append(
            {"role": role, "status": "present", "schema": policy[0], "bytes": size, "sha256": expected_sha}
        )
    if roles != list(RESULT_POLICY) or len(set(roles)) != len(roles):
        fail("finalize result roles/order mismatch")
    exact_membership(root, expected_files)
    replay = consume(ledger, "finalize", sha256(canonical_json(statement)))
    return {
        "schema": FINALIZE_RECEIPT_SCHEMA,
        "purpose": PURPOSE,
        "mode": expected_mode,
        "prepare_receipt_sha256": prepare_ref["sha256"],
        "prepare_plan_sha256": prepared["plan_sha256"],
        "session_id": prepared["session"]["session_id"],
        "source_sha256": sha256(source_raw),
        "results": summary,
        "temporal_boundary": {
            "prepare_decision_altered": False,
            "results_used_as_precontact_authority": False,
            "result_roles_joined_to_prepare_commitments": True,
        },
        "replay": replay,
        "machine_finalize_composition_valid": True,
        "physical_authenticity_proven_by_composer": False,
        "result_reviewer_signature": signature_results(
            cryptographically_verified=True
        ),
        **TYPED_STATE_POLICY,
        "authorization_a_granted": False,
        "device_contact": "none",
        "authority": "result composition only; cannot retroactively authorize or grant future action",
    }


def validate_template(path: Path) -> Mapping[str, Any]:
    raw = read_regular(path, MAX_JSON_BYTES, "template")
    document = mapping(strict_json(raw, "template"), "template")
    exact_keys(
        document,
        {
            "schema", "status", "purpose", "production_key_pins", "required_components",
            "required_results", "temporal_policy", "claims",
        },
        "template",
    )
    if document.get("schema") != TEMPLATE_SCHEMA or document.get("purpose") != PURPOSE:
        fail("template schema/purpose mismatch")
    if document.get("status") != "INTENTIONALLY_INVALID_NONAUTHORIZING_TEMPLATE":
        fail("template status mismatch")
    pins = mapping(document.get("production_key_pins"), "production pins")
    expected_pins = set(SIGNER_ROLES) | {"result_reviewer"}
    if set(pins) != expected_pins or any(value is not None for value in pins.values()):
        fail("template production pins must be null")
    if document.get("required_components") != list(COMPONENT_POLICY):
        fail("template component roles mismatch")
    if document.get("required_results") != list(RESULT_POLICY):
        fail("template result roles mismatch")
    if document.get("temporal_policy") != {
        "prior_live_qualification_must_precede_session": True,
        "pre_session_authority_must_precede_contact": True,
        "current_session_results_are_result_only": True,
        "finalize_cannot_rewrite_or_retroactively_grant_prepare": True,
    }:
        fail("template temporal policy mismatch")
    false_claims(document.get("claims"), "template claims")
    return {
        "status": document["status"],
        "sha256": sha256(raw),
        "authorization_a_granted": False,
        "device_contact": "none",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subs = result.add_subparsers(dest="command", required=True)
    template = subs.add_parser("validate-template")
    template.add_argument("--template", required=True, type=Path)
    for name in ("prepare", "finalize"):
        command = subs.add_parser(name)
        command.add_argument("--source", required=True, type=Path)
        command.add_argument("--ledger", required=True, type=Path)
        command.add_argument("--output", required=True, type=Path)
        command.add_argument("--fixture-only", action="store_true")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate-template":
            receipt = validate_template(args.template)
            print(
                f"{receipt['status']}: sha256={receipt['sha256']} "
                "authorization_a=false device_contact=none"
            )
            return 0
        if not args.output.is_absolute():
            fail("output path must be absolute")
        if args.command == "prepare":
            receipt = prepare(args.source, args.ledger, fixture_only=args.fixture_only)
        else:
            receipt = finalize(args.source, args.ledger, fixture_only=args.fixture_only)
        raw = canonical_json(receipt)
        write_new(args.output, raw)
        print(
            f"PASS_OFFLINE_{args.command.upper()}_ONLY: receipt_sha256={sha256(raw)} "
            "authorization_a=false device_contact=none"
        )
        return 0
    except (AdmissionError, OSError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
