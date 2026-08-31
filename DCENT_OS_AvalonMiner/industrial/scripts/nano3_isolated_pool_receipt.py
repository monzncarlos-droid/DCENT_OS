#!/usr/bin/env python3
"""Offline verifier for one isolated Nano 3 pool-disable/restore session.

The verifier has no socket, subprocess, USB, UART, power, or target mutation
path.  Its production key pins are intentionally empty.  Consequently the
checked-in CLI cannot promote a source bundle into live authority; fixture
mode proves parser/state-machine behavior only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SOURCE_SCHEMA = "dcent.nano3.isolated-pool-session-source.v1"
PLAN_SCHEMA = "dcent.nano3.isolated-pool-session-plan.v1"
OPERATOR_SCHEMA = "dcent.nano3.isolated-pool-session-operator-ack.v1"
TOPOLOGY_SCHEMA = "dcent.nano3.isolated-pool-topology-receipt.v1"
IDENTITY_SCHEMA = "dcent.nano3.isolated-pool-unit-identity.v1"
OBSERVER_SCHEMA = "dcent.nano3.isolated-pool-observer-envelope.v1"
CAPTURE_SCHEMA = "dcent.nano3.isolated-pool-raw-capture.v1"
TRANSCRIPT_SCHEMA = "dcent.nano3.isolated-pool-runner-transcript.v1"
RUNNER_EVIDENCE_SCHEMA = "dcent.nano3.isolated-pool-runner-evidence.v1"
WALL_SCHEMA = "dcent.nano3.isolated-pool-idle-power-proof.v1"
COMMITMENT_KEY_RECEIPT_SCHEMA = "dcent.nano3.pool-commitment-key-generation.v1"
ACCEPTANCE_CONTRACT_SCHEMA = "dcent.nano3.isolated-pool-acceptance-contract.v1"
RECEIPT_SCHEMA = "dcent.nano3.isolated-pool-receipt.v1"
PURPOSE = "nano3_attended_soak_isolated_pool_transaction_only"
TARGET_MODEL = "canaan-avalon-nano3-non-s"
HELD_BTCMINER_SHA256 = (
    "e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751"
)
DEAD_POOL_PARAMETER = "stratum+tcp://127.0.0.1:1,x,x"
DEAD_POOL_URL = "stratum+tcp://127.0.0.1:1"
READ_CODES = {
    "version": 22,
    "pools": 7,
    "summary": 11,
    "devs": 9,
    "stats": 70,
    "lcd": 125,
}
MUTATION_CODES = {
    "switchpool": 27,
    "enablepool": 47,
    "disablepool": 48,
    "addpool": 55,
    "removepool": 68,
    "poolpriority": 73,
}
ALLOWED_COMMANDS = frozenset(READ_CODES) | frozenset(MUTATION_CODES)
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,95}$")

# Provisioning these belongs to a separate reviewed custody ceremony.  Empty
# pins are a hard production refusal, not placeholders that accept any key.
PRODUCTION_REVIEWER_PUBLIC_KEY_SHA256 = ""
PRODUCTION_OPERATOR_PUBLIC_KEY_SHA256 = ""
PRODUCTION_OBSERVER_PUBLIC_KEY_SHA256 = ""
PRODUCTION_METER_PUBLIC_KEY_SHA256 = ""

PLAN_DOMAIN = b"DCENT:NANO3:ISOLATED-POOL:PLAN:V1\x00"
OPERATOR_DOMAIN = b"DCENT:NANO3:ISOLATED-POOL:OPERATOR:V1\x00"
OBSERVER_DOMAIN = b"DCENT:NANO3:ISOLATED-POOL:OBSERVER:V1\x00"
METER_DOMAIN = b"DCENT:NANO3:ISOLATED-POOL:METER:V1\x00"


class ReceiptError(RuntimeError):
    """Fail-closed input, signature, protocol, or state error."""


def _duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str, label: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_key,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON token {token}")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"malformed {label}: {exc}") from exc


def canonical_json(document: Any) -> bytes:
    try:
        return (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise ReceiptError("document is not canonical finite JSON") from exc


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        raise ReceiptError(
            f"{label} keys mismatch; missing={sorted(expected-observed)}, "
            f"unknown={sorted(observed-expected)}"
        )


def _text(value: Any, label: str, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ReceiptError(f"{label} must be a nonempty string")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _text(value, label, 8)
    if not ID_RE.fullmatch(result):
        raise ReceiptError(f"{label} has invalid shape")
    return result


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ReceiptError(f"{label} must be lowercase SHA-256")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ReceiptError(f"{label} must be an integer >= {minimum}")
    return value


def _finite(value: Any, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReceiptError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise ReceiptError(f"{label} must be finite and >= {minimum}")
    return result


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReceiptError(f"{label} must be RFC3339 UTC ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReceiptError(f"{label} is not valid RFC3339 UTC") from exc
    if parsed.tzinfo is None:
        raise ReceiptError(f"{label} lacks timezone")
    return parsed


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ReceiptError(f"cannot inspect {label}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ReceiptError(f"{label} must be a non-symlink regular file")
    if before.st_size > maximum:
        raise ReceiptError(f"{label} exceeds {maximum} bytes")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum:
                raise ReceiptError(f"opened {label} is not bounded regular input")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ReceiptError(f"cannot read {label}") from exc
    if len(raw) > maximum:
        raise ReceiptError(f"{label} exceeds {maximum} bytes")
    identity = lambda item: (  # noqa: E731
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
    )
    if identity(opened) != identity(after):
        raise ReceiptError(f"{label} changed while read")
    return raw


def _is_alias(stat_result: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return stat.S_ISLNK(stat_result.st_mode) or bool(attributes & reparse)


def _verify_real_directory_chain(path: Path, label: str) -> None:
    """Reject symlink/junction traversal in every existing path component."""

    absolute = path.absolute()
    chain = list(reversed(absolute.parents)) + [absolute]
    for component in chain:
        if not component.exists():
            continue
        try:
            observed = component.lstat()
        except OSError as exc:
            raise ReceiptError(f"cannot inspect {label} directory chain") from exc
        if _is_alias(observed) or not stat.S_ISDIR(observed.st_mode):
            raise ReceiptError(f"{label} directory chain contains alias/non-directory")


def _fsync_directory(path: Path) -> None:
    """Best-effort directory durability where the host supports directory fsync."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            # Windows and some filesystems reject directory fsync; file fsync
            # remains mandatory and the receipt discloses local-only replay.
            pass
    finally:
        os.close(descriptor)


def _load_json(path: Path, maximum: int, label: str) -> tuple[Mapping[str, Any], bytes]:
    raw = read_regular(path, maximum, label)
    try:
        document = strict_json_loads(raw.decode("utf-8"), label)
    except UnicodeError as exc:
        raise ReceiptError(f"{label} is not UTF-8") from exc
    return _mapping(document, label), raw


def _relative_input(bundle_path: Path, path_text: Any, label: str) -> Path:
    text = _text(path_text, label)
    path = Path(text)
    if path.is_absolute() or path.drive or any(part in {"", ".", ".."} for part in path.parts):
        raise ReceiptError(f"{label} must be a normalized relative evidence path")
    evidence_root = bundle_path.parent.absolute()
    _verify_real_directory_chain(evidence_root, "protected evidence root")
    candidate = evidence_root.joinpath(*path.parts)
    _verify_real_directory_chain(candidate.parent, "protected evidence input parent")
    try:
        candidate.relative_to(evidence_root)
    except ValueError as exc:
        raise ReceiptError(f"{label} escapes the protected evidence root") from exc
    return candidate


def _signature(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise ReceiptError(f"{label} must be base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ReceiptError(f"{label} must be strict base64") from exc
    if len(raw) != 64:
        raise ReceiptError(f"{label} must decode to 64 bytes")
    return raw


def _public_key(path: Path, expected_sha256: str, label: str) -> Ed25519PublicKey:
    _sha(expected_sha256, f"{label} key pin")
    if not path.is_absolute():
        raise ReceiptError(f"{label} public key path must be absolute")
    _verify_real_directory_chain(path.parent, f"{label} public key parent")
    raw = read_regular(path, 32, f"{label} public key")
    if len(raw) != 32 or sha256_bytes(raw) != expected_sha256:
        raise ReceiptError(f"{label} public key pin mismatch")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ReceiptError(f"{label} public key is invalid") from exc


def _verify_signature(
    key: Ed25519PublicKey, signature: bytes, domain: bytes, document: Mapping[str, Any], label: str
) -> None:
    try:
        key.verify(signature, domain + canonical_json(document))
    except InvalidSignature as exc:
        raise ReceiptError(f"{label} signature verification failed") from exc


def encode_request(command: str, parameter: Optional[str]) -> bytes:
    if command not in ALLOWED_COMMANDS:
        raise ReceiptError("runner transcript contains an unapproved command")
    document: dict[str, Any] = {"command": command}
    if parameter is not None:
        document["parameter"] = parameter
    return canonical_json(document).rstrip(b"\n") + b"\x00"


def decode_response(raw: bytes, command: str) -> Mapping[str, Any]:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ReceiptError("CGMiner response is empty or oversized")
    first_nul = raw.find(b"\x00")
    if first_nul < 0 or any(byte != 0 for byte in raw[first_nul:]):
        raise ReceiptError("CGMiner response framing is ambiguous")
    try:
        document = strict_json_loads(raw[:first_nul].decode("utf-8"), "CGMiner response")
    except UnicodeError as exc:
        raise ReceiptError("CGMiner response is not UTF-8") from exc
    document = _mapping(document, "CGMiner response")
    status = document.get("STATUS")
    if not isinstance(status, list) or len(status) != 1 or not isinstance(status[0], Mapping):
        raise ReceiptError("CGMiner response needs exactly one STATUS")
    entry = status[0]
    if entry.get("STATUS") != "S":
        raise ReceiptError("CGMiner response is not exact success")
    expected_code = READ_CODES.get(command, MUTATION_CODES.get(command))
    code = entry.get("Code")
    when = entry.get("When")
    response_id = document.get("id")
    if isinstance(code, bool) or not isinstance(code, int) or code != expected_code:
        raise ReceiptError("CGMiner response code mismatch")
    if isinstance(when, bool) or not isinstance(when, int) or when < 0:
        raise ReceiptError("CGMiner STATUS.When type mismatch")
    if isinstance(response_id, bool) or not isinstance(response_id, int) or response_id != 1:
        raise ReceiptError("CGMiner response id mismatch")
    payload_key = {
        "version": "VERSION",
        "pools": "POOLS",
        "summary": "SUMMARY",
        "stats": "STATS",
        "devs": "DEVS",
        "lcd": "LCD",
    }.get(command)
    if payload_key is not None:
        payload = document.get(payload_key)
        if not isinstance(payload, list) or not payload:
            raise ReceiptError(f"CGMiner {payload_key} payload is missing")
    return document


def _verify_mutation_ack(command: str, parameter: Optional[str], document: Mapping[str, Any]) -> None:
    message = document["STATUS"][0].get("Msg")
    if not isinstance(message, str):
        raise ReceiptError("mutation acknowledgement lacks Msg")
    if command == "poolpriority":
        if message != "Changed pool priorities":
            raise ReceiptError("poolpriority acknowledgement mismatch")
        return
    if command == "addpool":
        if not re.fullmatch(r"Added pool [0-9]+: '.+'", message):
            raise ReceiptError("addpool acknowledgement mismatch")
        return
    if parameter is None or not parameter.isdigit():
        raise ReceiptError("pool mutation parameter is not numeric")
    prefixes = {
        "switchpool": "Switching to pool",
        "enablepool": "Enabling pool",
        "disablepool": "Disabling pool",
        "removepool": "Removed pool",
    }
    prefix = prefixes.get(command)
    if prefix is None or not message.startswith(f"{prefix} {parameter}:"):
        raise ReceiptError("mutation acknowledgement does not bind requested pool")


def _validate_plan(plan: Mapping[str, Any]) -> tuple[datetime, datetime]:
    _exact_keys(
        plan,
        {
            "schema", "purpose", "plan_id", "session_id", "unit_id", "nonce",
            "valid_from_utc", "expires_at_utc", "target", "artifacts", "isolation",
            "protocol", "acceptance", "authority", "explicit_exclusions",
        },
        "reviewed plan",
    )
    if plan.get("schema") != PLAN_SCHEMA or plan.get("purpose") != PURPOSE:
        raise ReceiptError("reviewed plan schema/purpose mismatch")
    for key in ("plan_id", "session_id", "unit_id", "nonce"):
        _identifier(plan.get(key), f"plan.{key}")
    started = _utc(plan.get("valid_from_utc"), "plan.valid_from_utc")
    ended = _utc(plan.get("expires_at_utc"), "plan.expires_at_utc")
    if ended <= started or (ended - started).total_seconds() > 1800:
        raise ReceiptError("plan window is reversed or exceeds 30 minutes")
    target = _mapping(plan.get("target"), "plan.target")
    _exact_keys(
        target,
        {"model", "ipv4_sha256", "btcminer_sha256", "expected_version_fields", "unit_identity_receipt_sha256"},
        "plan.target",
    )
    if target.get("model") != TARGET_MODEL or target.get("btcminer_sha256") != HELD_BTCMINER_SHA256:
        raise ReceiptError("plan target identity mismatch")
    _sha(target.get("ipv4_sha256"), "plan.target.ipv4_sha256")
    _sha(target.get("unit_identity_receipt_sha256"), "plan.target.unit_identity_receipt_sha256")
    version = _mapping(target.get("expected_version_fields"), "expected_version_fields")
    _exact_keys(version, {"CGMiner", "VERSION", "PROD"}, "expected_version_fields")
    for key in version:
        _text(version[key], f"expected_version_fields.{key}")
    artifacts = _mapping(plan.get("artifacts"), "plan.artifacts")
    _exact_keys(
        artifacts,
        {
            "runner_sha256",
            "session_manifest_sha256",
            "telemetry_contract_sha256",
            "pool_acceptance_contract_sha256",
            "credential_commitment_key_receipt_sha256",
        },
        "plan.artifacts",
    )
    for key in artifacts:
        _sha(artifacts[key], f"plan.artifacts.{key}")
    isolation = _mapping(plan.get("isolation"), "plan.isolation")
    _exact_keys(
        isolation,
        {
            "subnet_cidr", "boundary_record_sha256", "permitted_source_ipv4_sha256",
            "observer_id", "interface_ids", "capture_filter", "topology_receipt_sha256",
            "same_host_monotonic_clock_domain", "only_permitted_source_can_reach_4028",
            "single_runner_client",
        },
        "plan.isolation",
    )
    try:
        network = ipaddress.ip_network(_text(isolation.get("subnet_cidr"), "subnet_cidr"), strict=True)
    except ValueError as exc:
        raise ReceiptError("isolated subnet is invalid") from exc
    if not network.is_private or network.version != 4:
        raise ReceiptError("isolated subnet must be exact private IPv4")
    for key in ("boundary_record_sha256", "permitted_source_ipv4_sha256", "topology_receipt_sha256"):
        _sha(isolation.get(key), f"plan.isolation.{key}")
    _identifier(isolation.get("observer_id"), "observer_id")
    _text(isolation.get("capture_filter"), "capture_filter")
    _text(isolation.get("same_host_monotonic_clock_domain"), "clock domain")
    interfaces = isolation.get("interface_ids")
    if not isinstance(interfaces, list) or not interfaces or any(not isinstance(item, str) or not item for item in interfaces) or len(set(interfaces)) != len(interfaces):
        raise ReceiptError("interface_ids must be unique nonempty strings")
    if isolation.get("only_permitted_source_can_reach_4028") is not True or isolation.get("single_runner_client") is not True:
        raise ReceiptError("plan does not assert the reviewed isolation boundary")
    protocol = _mapping(plan.get("protocol"), "plan.protocol")
    _exact_keys(
        protocol,
        {"port", "request_framing", "response_framing", "max_response_bytes", "connect_timeout_seconds", "read_timeout_seconds", "total_timeout_seconds"},
        "plan.protocol",
    )
    if protocol.get("port") != 4028 or protocol.get("request_framing") != "minified_json_plus_one_nul" or protocol.get("response_framing") != "one_json_object_then_nuls_read_to_eof" or protocol.get("max_response_bytes") != MAX_RESPONSE_BYTES:
        raise ReceiptError("plan CGMiner protocol mismatch")
    for key in ("connect_timeout_seconds", "read_timeout_seconds", "total_timeout_seconds"):
        _finite(protocol.get(key), f"plan.protocol.{key}", 0.001)
    acceptance = _mapping(plan.get("acceptance"), "plan.acceptance")
    _exact_keys(
        acceptance,
        {
            "zero_hash_mhs_5s_max",
            "zero_hash_proof_seconds",
            "zero_hash_sample_interval_seconds",
            "zero_hash_min_samples",
            "idle_watts_min",
            "idle_watts_max",
            "idle_meter_id",
            "restored_accepted_min_delta",
        },
        "plan.acceptance",
    )
    low = _finite(acceptance.get("idle_watts_min"), "idle watts min")
    high = _finite(acceptance.get("idle_watts_max"), "idle watts max")
    if low > high:
        raise ReceiptError("idle wall envelope is reversed")
    _finite(acceptance.get("zero_hash_mhs_5s_max"), "zero hash max")
    proof_seconds = _integer(
        acceptance.get("zero_hash_proof_seconds"), "zero hash proof seconds", 120
    )
    interval_seconds = _integer(
        acceptance.get("zero_hash_sample_interval_seconds"),
        "zero hash sample interval seconds",
        1,
    )
    minimum_samples = _integer(
        acceptance.get("zero_hash_min_samples"), "zero hash minimum samples", 3
    )
    if interval_seconds > 60:
        raise ReceiptError("zero hash sample cadence exceeds 60 seconds")
    if (minimum_samples - 1) * interval_seconds < proof_seconds:
        raise ReceiptError("zero hash sample count/cadence cannot cover proof duration")
    _identifier(acceptance.get("idle_meter_id"), "idle meter ID")
    _integer(acceptance.get("restored_accepted_min_delta"), "restored accepted delta", 1)
    authority = _mapping(plan.get("authority"), "plan.authority")
    _exact_keys(
        authority,
        {
            "reviewer_key_id",
            "operator_key_id",
            "observer_key_id",
            "meter_key_id",
            "distinct_roles",
        },
        "plan.authority",
    )
    key_ids = [
        _identifier(authority.get(key), f"authority.{key}")
        for key in (
            "reviewer_key_id",
            "operator_key_id",
            "observer_key_id",
            "meter_key_id",
        )
    ]
    if len(set(key_ids)) != 4 or authority.get("distinct_roles") is not True:
        raise ReceiptError("reviewer/operator/observer/meter roles are not distinct")
    exclusions = plan.get("explicit_exclusions")
    expected_exclusions = {"flash", "reboot", "watchdog_close_phase4", "process_signal", "fan_mutation", "uart_contact"}
    if not isinstance(exclusions, list) or any(not isinstance(item, str) for item in exclusions) or set(exclusions) != expected_exclusions or len(exclusions) != len(expected_exclusions):
        raise ReceiptError("plan exclusions are not exact")
    return started, ended


def _validate_operator_ack(ack: Mapping[str, Any], plan: Mapping[str, Any], plan_sha: str) -> None:
    _exact_keys(
        ack,
        {"schema", "purpose", "session_id", "unit_id", "nonce", "plan_sha256", "operator_id", "approved_actions", "approved", "acknowledged_at_utc", "authority"},
        "operator acknowledgement",
    )
    if ack.get("schema") != OPERATOR_SCHEMA or ack.get("purpose") != PURPOSE:
        raise ReceiptError("operator acknowledgement schema/purpose mismatch")
    for key in ("session_id", "unit_id", "nonce"):
        if ack.get(key) != plan.get(key):
            raise ReceiptError("operator acknowledgement session join mismatch")
    if ack.get("plan_sha256") != plan_sha or ack.get("approved") is not True:
        raise ReceiptError("operator acknowledgement does not approve exact plan")
    _identifier(ack.get("operator_id"), "operator_id")
    _utc(ack.get("acknowledged_at_utc"), "operator acknowledgement time")
    actions = ack.get("approved_actions")
    expected = ["isolated_4028_session", "all_live_pools_disable", "dead_pool_hash_off_proof", "exact_pool_restore"]
    if actions != expected:
        raise ReceiptError("operator approved actions are not exact ordered scope")
    if ack.get("authority") != "one session only; grants no future action":
        raise ReceiptError("operator acknowledgement authority boundary mismatch")


def _validate_acceptance_contract(
    bundle_path: Path, reference_value: Any, plan: Mapping[str, Any]
) -> None:
    reference = _mapping(reference_value, "pool acceptance contract reference")
    _exact_keys(
        reference,
        {"path", "bytes", "sha256"},
        "pool acceptance contract reference",
    )
    path = _relative_input(
        bundle_path, reference.get("path"), "pool acceptance contract path"
    )
    raw = read_regular(path, MAX_JSON_BYTES, "pool acceptance contract")
    if (
        reference.get("bytes") != len(raw)
        or reference.get("sha256") != sha256_bytes(raw)
        or reference.get("sha256")
        != plan["artifacts"]["pool_acceptance_contract_sha256"]
    ):
        raise ReceiptError("pool acceptance contract size/hash/plan join mismatch")
    try:
        contract = _mapping(
            strict_json_loads(raw.decode("utf-8"), "pool acceptance contract"),
            "pool acceptance contract",
        )
    except UnicodeError as exc:
        raise ReceiptError("pool acceptance contract is not UTF-8") from exc
    _exact_keys(
        contract,
        {
            "schema",
            "purpose",
            "contract_id",
            "target_model",
            "btcminer_sha256",
            "telemetry_contract_sha256",
            "acceptance",
            "authority",
        },
        "pool acceptance contract",
    )
    if (
        contract.get("schema") != ACCEPTANCE_CONTRACT_SCHEMA
        or contract.get("purpose") != PURPOSE
        or contract.get("target_model") != TARGET_MODEL
        or contract.get("btcminer_sha256") != HELD_BTCMINER_SHA256
        or contract.get("telemetry_contract_sha256")
        != plan["artifacts"]["telemetry_contract_sha256"]
        or contract.get("acceptance") != plan["acceptance"]
        or contract.get("authority")
        != "reviewer-signed through exact plan artifact hash; grants no Authorization A"
    ):
        raise ReceiptError("pool acceptance contract is not the exact reviewed contract")
    _identifier(contract.get("contract_id"), "pool acceptance contract ID")


def _validate_unit_identity(identity: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    _exact_keys(
        identity,
        {"schema", "purpose", "session_id", "unit_id", "nonce", "target_ipv4_sha256", "btcminer_sha256", "expected_version_fields", "unit_fingerprint_kind", "unit_fingerprint_sha256", "captured_at_utc"},
        "unit identity receipt",
    )
    if identity.get("schema") != IDENTITY_SCHEMA or identity.get("purpose") != PURPOSE:
        raise ReceiptError("unit identity receipt schema/purpose mismatch")
    joins = {
        "session_id": plan["session_id"], "unit_id": plan["unit_id"],
        "nonce": plan["nonce"], "target_ipv4_sha256": plan["target"]["ipv4_sha256"],
        "btcminer_sha256": plan["target"]["btcminer_sha256"],
        "expected_version_fields": plan["target"]["expected_version_fields"],
    }
    if any(identity.get(key) != value for key, value in joins.items()):
        raise ReceiptError("unit identity receipt exact target/session join mismatch")
    _text(identity.get("unit_fingerprint_kind"), "unit fingerprint kind", 8)
    _sha(identity.get("unit_fingerprint_sha256"), "unit fingerprint")
    _utc(identity.get("captured_at_utc"), "unit identity capture time")


def _validate_topology(topology: Mapping[str, Any], plan: Mapping[str, Any]) -> datetime:
    _exact_keys(
        topology,
        {"schema", "purpose", "session_id", "unit_id", "nonce", "observer_id", "clock_domain", "interface_ids", "capture_filter", "boundary_record_sha256", "firewall_ruleset_sha256", "only_permitted_source_path_to_target_4028", "no_bypass_route_to_target_4028", "reviewed_at_utc"},
        "topology receipt",
    )
    if topology.get("schema") != TOPOLOGY_SCHEMA or topology.get("purpose") != PURPOSE:
        raise ReceiptError("topology receipt schema/purpose mismatch")
    for key in ("session_id", "unit_id", "nonce"):
        if topology.get(key) != plan.get(key):
            raise ReceiptError("topology receipt session join mismatch")
    isolation = plan["isolation"]
    joins = {
        "observer_id": isolation["observer_id"],
        "clock_domain": isolation["same_host_monotonic_clock_domain"],
        "interface_ids": isolation["interface_ids"],
        "capture_filter": isolation["capture_filter"],
        "boundary_record_sha256": isolation["boundary_record_sha256"],
    }
    if any(topology.get(key) != value for key, value in joins.items()):
        raise ReceiptError("topology receipt differs from reviewed isolation plan")
    _sha(topology.get("firewall_ruleset_sha256"), "topology firewall ruleset")
    if topology.get("only_permitted_source_path_to_target_4028") is not True or topology.get("no_bypass_route_to_target_4028") is not True:
        raise ReceiptError("topology does not prevent bypass around observation point")
    return _utc(topology.get("reviewed_at_utc"), "topology review time")


def _validate_envelope(
    envelope: Mapping[str, Any], plan: Mapping[str, Any], plan_sha: str,
    ack_sha: str, runner_evidence_sha: str,
) -> None:
    _exact_keys(
        envelope,
        {"schema", "purpose", "session_id", "unit_id", "nonce", "plan_sha256", "operator_ack_sha256", "runner_evidence_sha256", "raw_capture_path", "raw_capture_bytes", "raw_capture_sha256", "clock_domain", "interface_ids", "capture_filter", "capture_started_monotonic_ns", "capture_ended_monotonic_ns", "dropped_packets", "capture_complete"},
        "observer envelope",
    )
    if envelope.get("schema") != OBSERVER_SCHEMA or envelope.get("purpose") != PURPOSE:
        raise ReceiptError("observer envelope schema/purpose mismatch")
    joins = {
        "session_id": plan["session_id"], "unit_id": plan["unit_id"],
        "nonce": plan["nonce"], "plan_sha256": plan_sha,
        "operator_ack_sha256": ack_sha,
        "runner_evidence_sha256": runner_evidence_sha,
        "clock_domain": plan["isolation"]["same_host_monotonic_clock_domain"],
        "interface_ids": plan["isolation"]["interface_ids"],
        "capture_filter": plan["isolation"]["capture_filter"],
    }
    if any(envelope.get(key) != value for key, value in joins.items()):
        raise ReceiptError("observer envelope exact join mismatch")
    start = _integer(envelope.get("capture_started_monotonic_ns"), "capture start")
    end = _integer(envelope.get("capture_ended_monotonic_ns"), "capture end")
    if end <= start:
        raise ReceiptError("observer capture monotonic window is reversed")
    if envelope.get("dropped_packets") != 0 or envelope.get("capture_complete") is not True:
        raise ReceiptError("observer capture is incomplete or dropped packets")
    _integer(envelope.get("raw_capture_bytes"), "raw capture bytes", 1)
    _sha(envelope.get("raw_capture_sha256"), "raw capture SHA-256")


def _validate_connection_record(record: Mapping[str, Any], index: int) -> None:
    _exact_keys(
        record,
        {"connection_id", "runner_event_id", "source_ipv4_sha256", "target_ipv4_sha256", "target_port", "syn_monotonic_ns", "closed_monotonic_ns", "outcome", "eof_observed", "request_bytes", "request_sha256", "response_bytes", "response_sha256"},
        f"capture.attempts[{index}]",
    )
    if record.get("connection_id") != index + 1 or record.get("runner_event_id") != f"api-{index + 1:04d}":
        raise ReceiptError("capture connection/event IDs are not exact contiguous sequence")
    for key in ("source_ipv4_sha256", "target_ipv4_sha256", "request_sha256", "response_sha256"):
        _sha(record.get(key), f"capture.{key}")
    if record.get("target_port") != 4028 or record.get("outcome") != "complete_eof" or record.get("eof_observed") is not True:
        raise ReceiptError("capture contains failed, incomplete, or non-4028 attempt")
    opened = _integer(record.get("syn_monotonic_ns"), "capture SYN time")
    closed = _integer(record.get("closed_monotonic_ns"), "capture close time")
    if closed < opened:
        raise ReceiptError("capture connection time is reversed")
    _integer(record.get("request_bytes"), "capture request bytes", 1)
    _integer(record.get("response_bytes"), "capture response bytes", 1)


def _validate_raw_capture(capture: Mapping[str, Any], plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    _exact_keys(
        capture,
        {
            "schema",
            "purpose",
            "session_id",
            "unit_id",
            "nonce",
            "clock_domain",
            "interface_ids",
            "capture_filter",
            "capture_started_monotonic_ns",
            "capture_ended_monotonic_ns",
            "dropped_packets",
            "packet_capture_path",
            "packet_capture_bytes",
            "packet_capture_sha256",
            "packet_capture_format",
            "attempts",
        },
        "raw observer capture",
    )
    if capture.get("schema") != CAPTURE_SCHEMA or capture.get("purpose") != PURPOSE:
        raise ReceiptError("raw observer capture schema/purpose mismatch")
    expected = {
        "session_id": plan["session_id"], "unit_id": plan["unit_id"],
        "nonce": plan["nonce"],
        "clock_domain": plan["isolation"]["same_host_monotonic_clock_domain"],
        "interface_ids": plan["isolation"]["interface_ids"],
        "capture_filter": plan["isolation"]["capture_filter"],
    }
    if any(capture.get(key) != value for key, value in expected.items()):
        raise ReceiptError("raw observer capture session/topology join mismatch")
    if capture.get("dropped_packets") != 0:
        raise ReceiptError("raw observer capture reports dropped packets")
    _text(capture.get("packet_capture_path"), "packet capture path")
    _integer(capture.get("packet_capture_bytes"), "packet capture bytes", 1)
    _sha(capture.get("packet_capture_sha256"), "packet capture SHA-256")
    if capture.get("packet_capture_format") != "opaque_observer_capture_bytes":
        raise ReceiptError("observer capture bytes must use the opaque format label")
    start = _integer(capture.get("capture_started_monotonic_ns"), "capture start")
    end = _integer(capture.get("capture_ended_monotonic_ns"), "capture end")
    attempts = capture.get("attempts")
    if end <= start or not isinstance(attempts, list) or not attempts:
        raise ReceiptError("raw observer capture window/attempts are invalid")
    previous_close = start
    for index, value in enumerate(attempts):
        record = _mapping(value, f"capture.attempts[{index}]")
        _validate_connection_record(record, index)
        if record["syn_monotonic_ns"] < previous_close or record["closed_monotonic_ns"] > end:
            raise ReceiptError("capture connections overlap or escape the capture window")
        previous_close = record["closed_monotonic_ns"]
    return attempts


def _validate_transcript_header(
    transcript: Mapping[str, Any], plan: Mapping[str, Any], plan_sha: str, ack_sha: str
) -> list[Mapping[str, Any]]:
    _exact_keys(
        transcript,
        {"schema", "purpose", "session_id", "unit_id", "nonce", "plan_sha256", "operator_ack_sha256", "runner_sha256", "session_manifest_sha256", "telemetry_contract_sha256", "target", "clock_domain", "started_at_utc", "ended_at_utc", "started_monotonic_ns", "ended_monotonic_ns", "connections", "transaction"},
        "runner transcript",
    )
    if transcript.get("schema") != TRANSCRIPT_SCHEMA or transcript.get("purpose") != PURPOSE:
        raise ReceiptError("runner transcript schema/purpose mismatch")
    joins = {
        "session_id": plan["session_id"], "unit_id": plan["unit_id"],
        "nonce": plan["nonce"], "plan_sha256": plan_sha,
        "operator_ack_sha256": ack_sha,
        "runner_sha256": plan["artifacts"]["runner_sha256"],
        "session_manifest_sha256": plan["artifacts"]["session_manifest_sha256"],
        "telemetry_contract_sha256": plan["artifacts"]["telemetry_contract_sha256"],
        "target": plan["target"],
        "clock_domain": plan["isolation"]["same_host_monotonic_clock_domain"],
    }
    if any(transcript.get(key) != value for key, value in joins.items()):
        raise ReceiptError("runner transcript exact session/artifact/target join mismatch")
    started = _utc(transcript.get("started_at_utc"), "runner start UTC")
    ended = _utc(transcript.get("ended_at_utc"), "runner end UTC")
    if ended < started:
        raise ReceiptError("runner UTC window is reversed")
    start_mono = _integer(transcript.get("started_monotonic_ns"), "runner start monotonic")
    end_mono = _integer(transcript.get("ended_monotonic_ns"), "runner end monotonic")
    if end_mono <= start_mono:
        raise ReceiptError("runner monotonic window is reversed")
    connections = transcript.get("connections")
    if not isinstance(connections, list) or not connections:
        raise ReceiptError("runner transcript has no connections")
    return connections


def _load_runner_evidence(
    bundle_path: Path,
    reference_value: Any,
    plan: Mapping[str, Any],
    plan_sha: str,
    ack_sha: str,
) -> tuple[dict[str, Any], bytes]:
    reference = _mapping(reference_value, "runner evidence reference")
    _exact_keys(reference, {"path", "bytes", "sha256"}, "runner evidence reference")
    path = _relative_input(bundle_path, reference.get("path"), "runner evidence path")
    fragment, raw = _load_json(path, MAX_EVIDENCE_BYTES, "runner evidence")
    if reference.get("bytes") != len(raw) or reference.get("sha256") != sha256_bytes(raw):
        raise ReceiptError("runner evidence size/hash mismatch")
    _exact_keys(
        fragment,
        {
            "schema",
            "purpose",
            "session_id",
            "manifest_sha256",
            "runner_sha256",
            "target_ipv4_sha256",
            "clock_domain",
            "started_at_utc",
            "ended_at_utc",
            "started_monotonic_ns",
            "ended_monotonic_ns",
            "connections",
            "connection_failures",
            "pending_intents",
            "mutation_effect_unknown",
            "acknowledged_mutation_count",
            "resolved_dead_pool_id",
            "transaction_outcome",
            "transaction",
        },
        "runner evidence",
    )
    if (
        fragment.get("schema") != RUNNER_EVIDENCE_SCHEMA
        or fragment.get("purpose") != PURPOSE
        or fragment.get("session_id") != plan["session_id"]
        or fragment.get("manifest_sha256")
        != plan["artifacts"]["session_manifest_sha256"]
        or fragment.get("runner_sha256") != plan["artifacts"]["runner_sha256"]
        or fragment.get("target_ipv4_sha256") != plan["target"]["ipv4_sha256"]
        or fragment.get("clock_domain")
        != plan["isolation"]["same_host_monotonic_clock_domain"]
    ):
        raise ReceiptError("runner evidence exact session/artifact/target join mismatch")
    connections = fragment.get("connections")
    failures = fragment.get("connection_failures")
    pending = fragment.get("pending_intents")
    acknowledged = fragment.get("acknowledged_mutation_count")
    if (
        not isinstance(connections, list)
        or not connections
        or failures != []
        or pending != []
        or fragment.get("mutation_effect_unknown") is not False
        or fragment.get("transaction_outcome") != "restored_exactly"
        or isinstance(acknowledged, bool)
        or not isinstance(acknowledged, int)
        or acknowledged
        != sum(
            1
            for item in connections
            if isinstance(item, Mapping) and item.get("command") in MUTATION_CODES
        )
    ):
        raise ReceiptError(
            "runner evidence contains failure, pending intent, or incomplete transaction"
        )
    _integer(fragment.get("resolved_dead_pool_id"), "resolved dead pool ID")
    transcript = {
        "schema": TRANSCRIPT_SCHEMA,
        "purpose": PURPOSE,
        "session_id": plan["session_id"],
        "unit_id": plan["unit_id"],
        "nonce": plan["nonce"],
        "plan_sha256": plan_sha,
        "operator_ack_sha256": ack_sha,
        "runner_sha256": fragment["runner_sha256"],
        "session_manifest_sha256": fragment["manifest_sha256"],
        "telemetry_contract_sha256": plan["artifacts"][
            "telemetry_contract_sha256"
        ],
        "target": dict(plan["target"]),
        "clock_domain": fragment["clock_domain"],
        "started_at_utc": fragment["started_at_utc"],
        "ended_at_utc": fragment["ended_at_utc"],
        "started_monotonic_ns": fragment["started_monotonic_ns"],
        "ended_monotonic_ns": fragment["ended_monotonic_ns"],
        "connections": connections,
        "transaction": fragment["transaction"],
    }
    return transcript, raw


def _load_runner_connections(
    bundle_path: Path, transcript: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[int, Mapping[str, Any]]]:
    checked: list[dict[str, Any]] = []
    documents: dict[int, Mapping[str, Any]] = {}
    previous_end = int(transcript["started_monotonic_ns"])
    for index, raw_value in enumerate(transcript["connections"]):
        value = _mapping(raw_value, f"runner.connections[{index}]")
        _exact_keys(
            value,
            {"connection_id", "runner_event_id", "opened_monotonic_ns", "closed_monotonic_ns", "command", "parameter", "request_bytes", "request_sha256", "response_path", "response_bytes", "response_sha256", "outcome", "eof_observed"},
            f"runner.connections[{index}]",
        )
        connection_id = index + 1
        if value.get("connection_id") != connection_id or value.get("runner_event_id") != f"api-{connection_id:04d}":
            raise ReceiptError("runner connection/event IDs are not exact contiguous sequence")
        opened = _integer(value.get("opened_monotonic_ns"), "runner connection open")
        closed = _integer(value.get("closed_monotonic_ns"), "runner connection close")
        if opened < previous_end or closed < opened or closed > transcript["ended_monotonic_ns"]:
            raise ReceiptError("runner connections overlap or escape its window")
        previous_end = closed
        command = value.get("command")
        if not isinstance(command, str) or command not in ALLOWED_COMMANDS:
            raise ReceiptError("runner transcript command is not allowlisted")
        parameter = value.get("parameter")
        if parameter is not None and not isinstance(parameter, str):
            raise ReceiptError("runner parameter type is invalid")
        if command in READ_CODES and parameter is not None:
            raise ReceiptError("read-only command unexpectedly has a parameter")
        request = encode_request(command, parameter)
        if value.get("request_bytes") != len(request) or value.get("request_sha256") != sha256_bytes(request):
            raise ReceiptError("runner request bytes/hash mismatch")
        if value.get("outcome") != "complete_eof" or value.get("eof_observed") is not True:
            raise ReceiptError("runner transcript contains incomplete connection")
        response_path = _relative_input(bundle_path, value.get("response_path"), "response_path")
        response = read_regular(response_path, MAX_RESPONSE_BYTES, "CGMiner raw response")
        if value.get("response_bytes") != len(response) or value.get("response_sha256") != sha256_bytes(response):
            raise ReceiptError("runner response size/hash mismatch")
        document = decode_response(response, command)
        if command in MUTATION_CODES:
            _verify_mutation_ack(command, parameter, document)
        documents[connection_id] = document
        checked.append(
            {
                "connection_id": connection_id,
                "runner_event_id": value["runner_event_id"],
                "opened_monotonic_ns": opened,
                "closed_monotonic_ns": closed,
                "command": command,
                "parameter": parameter,
                "request_bytes": len(request),
                "request_sha256": sha256_bytes(request),
                "response_bytes": len(response),
                "response_sha256": sha256_bytes(response),
            }
        )
    return checked, documents


def _match_capture(
    runner: Sequence[Mapping[str, Any]], attempts: Sequence[Mapping[str, Any]], plan: Mapping[str, Any]
) -> None:
    if len(runner) != len(attempts):
        raise ReceiptError("observer saw missing or extra 4028 connection attempts")
    source_hash = plan["isolation"]["permitted_source_ipv4_sha256"]
    target_hash = plan["target"]["ipv4_sha256"]
    for run, observed in zip(runner, attempts):
        exact = {
            "connection_id": run["connection_id"],
            "runner_event_id": run["runner_event_id"],
            "request_bytes": run["request_bytes"],
            "request_sha256": run["request_sha256"],
            "response_bytes": run["response_bytes"],
            "response_sha256": run["response_sha256"],
        }
        if any(observed.get(key) != value for key, value in exact.items()):
            raise ReceiptError("observer/runner connection accounting mismatch")
        if observed.get("source_ipv4_sha256") != source_hash or observed.get("target_ipv4_sha256") != target_hash:
            raise ReceiptError("observer connection tuple differs from reviewed plan")
        if (
            run["opened_monotonic_ns"] > observed["syn_monotonic_ns"]
            or run["closed_monotonic_ns"] < observed["closed_monotonic_ns"]
        ):
            raise ReceiptError("runner custody interval does not contain observed network interval")


def _pool_snapshot(
    pools_document: Mapping[str, Any], lcd_document: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], int]:
    entries = pools_document.get("POOLS")
    lcd_entries = lcd_document.get("LCD")
    if not isinstance(entries, list) or not entries or not isinstance(lcd_entries, list) or len(lcd_entries) != 1 or not isinstance(lcd_entries[0], Mapping):
        raise ReceiptError("pool/LCD snapshot shape mismatch")
    pools: list[dict[str, Any]] = []
    ids: set[int] = set()
    priorities: set[int] = set()
    for raw in entries:
        entry = _mapping(raw, "pool entry")
        pool_id = _integer(entry.get("POOL"), "pool id")
        priority = _integer(entry.get("Priority"), "pool priority")
        url = _text(entry.get("URL"), "pool URL")
        user = _text(entry.get("User"), "pool user")
        status = entry.get("Status")
        active = entry.get("Stratum Active")
        accepted = entry.get("Accepted")
        if status not in {"Alive", "Dead", "Disabled", "Rejecting"} or not isinstance(active, bool) or isinstance(accepted, bool) or not isinstance(accepted, int) or accepted < 0:
            raise ReceiptError("pool status/active/Accepted type is invalid")
        if pool_id in ids or priority in priorities:
            raise ReceiptError("pool IDs/priorities are duplicated")
        ids.add(pool_id)
        priorities.add(priority)
        pools.append(
            {"pool_id": pool_id, "priority": priority, "url": url, "user": user, "status": status, "enabled": status != "Disabled", "stratum_active": active, "accepted": accepted}
        )
    pools.sort(key=lambda item: item["priority"])
    if [item["priority"] for item in pools] != list(range(len(pools))):
        raise ReceiptError("pool priorities are not exact contiguous order")
    current_url = lcd_entries[0].get("Current Pool")
    current_user = lcd_entries[0].get("User")
    matches = [item["pool_id"] for item in pools if item["url"] == current_url and item["user"] == current_user]
    if len(matches) != 1:
        raise ReceiptError("LCD selected pool is ambiguous")
    return pools, matches[0]


def _summary(document: Mapping[str, Any]) -> tuple[float, int]:
    entries = document.get("SUMMARY")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], Mapping):
        raise ReceiptError("SUMMARY shape mismatch")
    return (
        _finite(entries[0].get("MHS 5s"), "SUMMARY MHS 5s"),
        _integer(entries[0].get("Accepted"), "SUMMARY Accepted"),
    )


def _connection_ids(value: Any, label: str) -> list[int]:
    if not isinstance(value, list) or not value or any(isinstance(item, bool) or not isinstance(item, int) for item in value):
        raise ReceiptError(f"{label} must be a nonempty integer list")
    if len(set(value)) != len(value):
        raise ReceiptError(f"{label} contains duplicate connection IDs")
    return value


def _ref_id(value: Mapping[str, Any], key: str, documents: Mapping[int, Mapping[str, Any]], command: str) -> int:
    connection_id = _integer(value.get(key), f"transaction.{key}", 1)
    document = documents.get(connection_id)
    if document is None:
        raise ReceiptError(f"transaction.{key} references missing connection")
    payload = {"pools": "POOLS", "lcd": "LCD", "summary": "SUMMARY"}[command]
    if payload not in document:
        raise ReceiptError(f"transaction.{key} references wrong command")
    return connection_id


def _expected_mutations(
    pre: Sequence[Mapping[str, Any]], selected: int, dead_id: int
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    enabled_ids = sorted(item["pool_id"] for item in pre if item["enabled"])
    hash_off = [("addpool", DEAD_POOL_PARAMETER), ("switchpool", str(dead_id))]
    hash_off.extend(("disablepool", str(pool_id)) for pool_id in enabled_ids)
    restore = [("enablepool", str(pool_id)) for pool_id in enabled_ids]
    restore.extend(
        [
            ("switchpool", str(selected)),
            ("removepool", str(dead_id)),
            ("poolpriority", ",".join(str(item["pool_id"]) for item in pre)),
        ]
    )
    return hash_off, restore


def _assert_mutations(
    ids: Sequence[int], expected: Sequence[tuple[str, str]], runner: Sequence[Mapping[str, Any]], label: str
) -> None:
    observed = []
    by_id = {item["connection_id"]: item for item in runner}
    for connection_id in ids:
        item = by_id.get(connection_id)
        if item is None:
            raise ReceiptError(f"{label} references missing connection")
        observed.append((item["command"], item["parameter"]))
    if observed != list(expected):
        raise ReceiptError(f"{label} is partial, reordered, or contains extra mutation")


def _credential_safe_state(
    pools: Sequence[Mapping[str, Any]], selected: int, key: bytes, session_id: str
) -> list[dict[str, Any]]:
    result = []
    for entry in pools:
        secret = canonical_json({"URL": entry["url"], "User": entry["user"]})
        commitment = hmac.new(
            key,
            b"DCENT:NANO3:POOL-IDENTITY:V1\x00" + session_id.encode("ascii") + b"\x00" + str(entry["pool_id"]).encode("ascii") + b"\x00" + secret,
            hashlib.sha256,
        ).hexdigest()
        result.append(
            {
                "pool_id": entry["pool_id"], "priority": entry["priority"],
                "status": entry["status"], "enabled": entry["enabled"],
                "stratum_active": entry["stratum_active"],
                "selected": entry["pool_id"] == selected,
                "credential_identity_hmac_sha256": commitment,
            }
        )
    return result


def _semantic_pool_state(pools: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "pool_id": item["pool_id"], "priority": item["priority"],
            "url": item["url"], "user": item["user"], "status": item["status"],
            "enabled": item["enabled"], "stratum_active": item["stratum_active"],
        }
        for item in pools
    ]


def _validate_wall_reference(
    bundle_path: Path,
    ref: Mapping[str, Any],
    plan: Mapping[str, Any],
    meter_key: Ed25519PublicKey,
    meter_signature: bytes,
) -> dict[str, Any]:
    _exact_keys(ref, {"path", "bytes", "sha256"}, "idle power reference")
    path = _relative_input(bundle_path, ref.get("path"), "idle power path")
    raw = read_regular(path, MAX_EVIDENCE_BYTES, "idle power proof")
    if ref.get("bytes") != len(raw) or ref.get("sha256") != sha256_bytes(raw):
        raise ReceiptError("idle power proof size/hash mismatch")
    try:
        document = _mapping(strict_json_loads(raw.decode("utf-8"), "idle power proof"), "idle power proof")
    except UnicodeError as exc:
        raise ReceiptError("idle power proof is not UTF-8") from exc
    _exact_keys(document, {"schema", "purpose", "session_id", "unit_id", "nonce", "meter_id", "captured_at_utc", "clock_domain", "captured_monotonic_ns", "watts"}, "idle power proof")
    if document.get("schema") != WALL_SCHEMA or document.get("purpose") != PURPOSE:
        raise ReceiptError("idle power proof schema/purpose mismatch")
    _verify_signature(
        meter_key,
        meter_signature,
        METER_DOMAIN,
        document,
        "idle power meter proof",
    )
    for key in ("session_id", "unit_id", "nonce"):
        if document.get(key) != plan.get(key):
            raise ReceiptError("idle power proof session join mismatch")
    if document.get("meter_id") != plan["acceptance"]["idle_meter_id"]:
        raise ReceiptError("idle power meter differs from reviewed plan")
    captured_at = _utc(document.get("captured_at_utc"), "idle power capture time")
    watts = _finite(document.get("watts"), "idle watts")
    acceptance = plan["acceptance"]
    if not acceptance["idle_watts_min"] <= watts <= acceptance["idle_watts_max"]:
        raise ReceiptError("idle power proof is outside reviewed envelope")
    if document.get("clock_domain") != plan["isolation"]["same_host_monotonic_clock_domain"]:
        raise ReceiptError("idle power proof clock domain mismatch")
    captured_mono = _integer(document.get("captured_monotonic_ns"), "idle power monotonic time")
    return {
        "watts": watts,
        "captured_at_utc": captured_at.isoformat().replace("+00:00", "Z"),
        "captured_monotonic_ns": captured_mono,
        "meter_id": document["meter_id"],
        "independent_meter_signature_verified": True,
    }


def _validate_transaction(
    bundle_path: Path, transcript: Mapping[str, Any], runner: Sequence[Mapping[str, Any]],
    documents: Mapping[int, Mapping[str, Any]], plan: Mapping[str, Any], commitment_key: bytes,
    meter_key: Ed25519PublicKey, meter_signature: bytes,
) -> dict[str, Any]:
    transaction = _mapping(transcript.get("transaction"), "transaction")
    _exact_keys(transaction, {"pre_state", "hash_off", "restore", "idle_power_reference"}, "transaction")
    pre_ref = _mapping(transaction.get("pre_state"), "transaction.pre_state")
    dead_ref = _mapping(transaction.get("hash_off"), "transaction.hash_off")
    restore_ref = _mapping(transaction.get("restore"), "transaction.restore")
    _exact_keys(pre_ref, {"pools_connection_id", "lcd_connection_id", "config_reference"}, "pre_state")
    _exact_keys(
        dead_ref,
        {
            "mutation_connection_ids",
            "pools_connection_id",
            "lcd_connection_id",
            "summary_connection_ids",
        },
        "hash_off",
    )
    _exact_keys(
        restore_ref,
        {
            "mutation_connection_ids",
            "pools_start_connection_id",
            "lcd_start_connection_id",
            "pools_connection_id",
            "lcd_connection_id",
            "config_reference",
        },
        "restore",
    )
    pre_pool_id = _ref_id(pre_ref, "pools_connection_id", documents, "pools")
    pre_lcd_id = _ref_id(pre_ref, "lcd_connection_id", documents, "lcd")
    dead_pool_id = _ref_id(dead_ref, "pools_connection_id", documents, "pools")
    dead_lcd_id = _ref_id(dead_ref, "lcd_connection_id", documents, "lcd")
    post_pool_id = _ref_id(restore_ref, "pools_connection_id", documents, "pools")
    post_start_pool_id = _ref_id(restore_ref, "pools_start_connection_id", documents, "pools")
    post_start_lcd_id = _ref_id(restore_ref, "lcd_start_connection_id", documents, "lcd")
    post_lcd_id = _ref_id(restore_ref, "lcd_connection_id", documents, "lcd")
    pre, selected = _pool_snapshot(documents[pre_pool_id], documents[pre_lcd_id])
    dead, dead_selected = _pool_snapshot(documents[dead_pool_id], documents[dead_lcd_id])
    post, post_selected = _pool_snapshot(documents[post_pool_id], documents[post_lcd_id])
    post_start, post_start_selected = _pool_snapshot(
        documents[post_start_pool_id], documents[post_start_lcd_id]
    )
    config_raw: list[bytes] = []
    config_times: list[int] = []
    for label, source in (("pre", pre_ref), ("post", restore_ref)):
        reference = _mapping(source.get("config_reference"), f"{label} config reference")
        _exact_keys(
            reference,
            {"path", "bytes", "sha256", "captured_monotonic_ns"},
            f"{label} config reference",
        )
        config_path = _relative_input(bundle_path, reference.get("path"), f"{label} config path")
        raw = read_regular(config_path, MAX_EVIDENCE_BYTES, f"protected {label} config snapshot")
        if reference.get("bytes") != len(raw) or reference.get("sha256") != sha256_bytes(raw):
            raise ReceiptError(f"protected {label} config snapshot size/hash mismatch")
        config_raw.append(raw)
        config_times.append(
            _integer(
                reference.get("captured_monotonic_ns"),
                f"protected {label} config capture time",
            )
        )
    if config_raw[0] != config_raw[1]:
        raise ReceiptError("protected config bytes differ after restore")
    original_ids = {item["pool_id"] for item in pre}
    new = [item for item in dead if item["pool_id"] not in original_ids]
    if len(new) != 1:
        raise ReceiptError("dead-only state does not contain exactly one new pool")
    dead_entry = new[0]
    dead_id = dead_entry["pool_id"]
    if dead_entry["url"] != DEAD_POOL_URL or dead_entry["user"] != "x":
        raise ReceiptError("dead pool identity differs from exact approved value")
    if dead_selected != dead_id or [item["pool_id"] for item in dead if item["enabled"]] != [dead_id]:
        raise ReceiptError("all live pools are not disabled with dead pool sole enabled/selected")
    if any(item["stratum_active"] for item in dead if item["pool_id"] in original_ids):
        raise ReceiptError("an original live pool remains Stratum Active")
    hash_ids = _connection_ids(dead_ref.get("mutation_connection_ids"), "hash-off mutations")
    restore_ids = _connection_ids(restore_ref.get("mutation_connection_ids"), "restore mutations")
    expected_hash, expected_restore = _expected_mutations(pre, selected, dead_id)
    _assert_mutations(hash_ids, expected_hash, runner, "hash-off transaction")
    _assert_mutations(restore_ids, expected_restore, runner, "restore transaction")
    if _semantic_pool_state(post) != _semantic_pool_state(pre) or post_selected != selected:
        raise ReceiptError("post-restore pool state is not exact original equality")
    zero_ids = _connection_ids(dead_ref.get("summary_connection_ids"), "zero hash summaries")
    acceptance = plan["acceptance"]
    if len(zero_ids) < acceptance["zero_hash_min_samples"]:
        raise ReceiptError("zero-hash proof has too few samples")
    zero_samples: list[tuple[float, int]] = []
    for connection_id in zero_ids:
        document = documents.get(connection_id)
        if document is None or "SUMMARY" not in document:
            raise ReceiptError("zero-hash proof references missing/wrong command")
        zero_samples.append(_summary(document))
    zero_start_id = zero_ids[0]
    zero_end_id = zero_ids[-1]
    zero_start_accepted = zero_samples[0][1]
    zero_end_mhs, zero_end_accepted = zero_samples[-1]
    if (
        any(accepted != zero_start_accepted for _, accepted in zero_samples)
        or any(
            mhs > acceptance["zero_hash_mhs_5s_max"]
            for mhs, _ in zero_samples
        )
    ):
        raise ReceiptError("zero-hash proof did not close Accepted/MHS 5s bounds")
    if _semantic_pool_state(post_start) != _semantic_pool_state(post) or post_start_selected != post_selected:
        raise ReceiptError("post-restore pool proof changed semantic state")
    selected_post = next(item for item in post if item["pool_id"] == post_selected)
    selected_start = next(item for item in post_start if item["pool_id"] == post_start_selected)
    accepted_delta = selected_post["accepted"] - selected_start["accepted"]
    if accepted_delta < plan["acceptance"]["restored_accepted_min_delta"]:
        raise ReceiptError("post-restore intended pool Accepted counter did not advance")
    if not selected_post["enabled"] or not selected_post["stratum_active"]:
        raise ReceiptError("post-restore intended pool is not enabled and Stratum Active")
    by_id = {item["connection_id"]: item for item in runner}
    if config_times[0] > by_id[pre_pool_id]["opened_monotonic_ns"]:
        raise ReceiptError("protected pre config was not captured before pre-state API")
    if not (
        by_id[post_start_lcd_id]["closed_monotonic_ns"]
        <= config_times[1]
        <= by_id[post_pool_id]["opened_monotonic_ns"]
    ):
        raise ReceiptError(
            "protected post config capture is outside restoration proof interval"
        )
    if zero_ids != sorted(zero_ids):
        raise ReceiptError("zero-hash sample connection order is invalid")
    proof_ns = acceptance["zero_hash_proof_seconds"] * 1_000_000_000
    cadence_ns = acceptance["zero_hash_sample_interval_seconds"] * 1_000_000_000
    if (
        by_id[zero_end_id]["closed_monotonic_ns"]
        - by_id[zero_start_id]["opened_monotonic_ns"]
        < proof_ns
    ):
        raise ReceiptError("zero-hash proof duration is shorter than reviewed bound")
    if any(
        by_id[current]["opened_monotonic_ns"]
        - by_id[previous]["opened_monotonic_ns"]
        > cadence_ns
        for previous, current in zip(zero_ids, zero_ids[1:])
    ):
        raise ReceiptError("zero-hash sample cadence has a coverage gap")
    wall = _validate_wall_reference(
        bundle_path,
        _mapping(transaction["idle_power_reference"], "idle power reference"),
        plan,
        meter_key,
        meter_signature,
    )
    all_mutations = [item["connection_id"] for item in runner if item["command"] in MUTATION_CODES]
    if all_mutations != hash_ids + restore_ids:
        raise ReceiptError("unreferenced or cross-phase mutation connection exists")
    ordered_ids = [
        pre_pool_id,
        pre_lcd_id,
        *hash_ids,
        dead_pool_id,
        dead_lcd_id,
        *zero_ids,
        *restore_ids,
        post_start_pool_id,
        post_start_lcd_id,
        post_pool_id,
        post_lcd_id,
    ]
    if ordered_ids != sorted(ordered_ids) or len(set(ordered_ids)) != len(ordered_ids):
        raise ReceiptError("transaction phase connection ordering is invalid")
    if not by_id[zero_start_id]["opened_monotonic_ns"] <= wall["captured_monotonic_ns"] <= by_id[zero_end_id]["closed_monotonic_ns"]:
        raise ReceiptError("idle power sample is outside the dead-pool zero-hash window")
    wall_utc = _utc(wall["captured_at_utc"], "idle power capture time")
    if not (
        _utc(transcript["started_at_utc"], "runner start UTC")
        <= wall_utc
        <= _utc(transcript["ended_at_utc"], "runner end UTC")
    ):
        raise ReceiptError("idle power UTC sample escapes the runner session window")
    safe_pre = _credential_safe_state(pre, selected, commitment_key, plan["session_id"])
    safe_post = _credential_safe_state(post, post_selected, commitment_key, plan["session_id"])
    return {
        "pre_state": safe_pre,
        "dead_pool_id": dead_id,
        "dead_pool_sole_enabled_and_selected": True,
        "all_original_pools_disabled_and_inactive": True,
        "zero_hash_observation_criteria_met": {
            "sample_count": len(zero_samples),
            "proof_seconds": acceptance["zero_hash_proof_seconds"],
            "maximum_sample_interval_seconds": acceptance[
                "zero_hash_sample_interval_seconds"
            ],
            "accepted_start": zero_start_accepted,
            "accepted_end": zero_end_accepted,
            "terminal_mhs_5s": zero_end_mhs,
        },
        "idle_power": wall,
        "post_state": safe_post,
        "post_state_exactly_equals_pre_state": safe_post == safe_pre,
        "protected_config_bytes_exactly_restored": True,
        "intended_pool": {"pool_id": post_selected, "enabled": True, "stratum_active": True, "pool_accepted_delta": accepted_delta},
    }


def _consume_local_replay(
    ledger_dir: Path,
    session_id: str,
    nonce: str,
    bundle_sha: str,
    commitment_key: bytes,
) -> str:
    if not ledger_dir.is_absolute():
        raise ReceiptError("replay ledger directory must be absolute")
    _verify_real_directory_chain(ledger_dir.parent, "replay ledger parent")
    if not ledger_dir.parent.is_dir():
        raise ReceiptError("replay ledger parent must already exist")
    created = not ledger_dir.exists()
    ledger_dir.mkdir(mode=0o700, exist_ok=True)
    if created:
        try:
            os.chmod(ledger_dir, 0o700)
        except OSError as exc:
            raise ReceiptError("cannot establish owner-only replay ledger mode") from exc
        _fsync_directory(ledger_dir.parent)
    _verify_real_directory_chain(ledger_dir, "replay ledger")
    before = ledger_dir.lstat()
    if _is_alias(before) or not stat.S_ISDIR(before.st_mode):
        raise ReceiptError("replay ledger must be a real directory")
    if os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077:
        raise ReceiptError("replay ledger must have owner-only POSIX mode")
    ledger_identity = (before.st_dev, before.st_ino)
    key = sha256_bytes(canonical_json({"session_id": session_id, "nonce": nonce, "bundle_sha256": bundle_sha}))
    key_reuse_marker = hmac.new(
        commitment_key,
        b"DCENT:NANO3:LOCAL-COMMITMENT-KEY-REUSE-MARKER:V1\x00",
        hashlib.sha256,
    ).hexdigest()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    records = (
        (
            ledger_dir / f"key-{key_reuse_marker}.consumed",
            canonical_json(
                {
                    "scope": "local commitment-key one-shot marker",
                    "session_id": session_id,
                }
            ),
            "credential commitment key already consumed in local ledger",
        ),
        (
            ledger_dir / f"session-{key}.consumed",
            canonical_json(
                {
                    "session_id": session_id,
                    "nonce": nonce,
                    "bundle_sha256": bundle_sha,
                }
            ),
            "isolated session bundle already consumed in local ledger",
        ),
    )
    for path, raw, failure in records:
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise ReceiptError(failure) from exc
        try:
            written = 0
            while written < len(raw):
                count = os.write(fd, raw[written:])
                if count <= 0:
                    raise ReceiptError("replay ledger write made no progress")
                written += count
            os.fsync(fd)
        finally:
            os.close(fd)
    _fsync_directory(ledger_dir)
    after = ledger_dir.lstat()
    if (
        _is_alias(after)
        or not stat.S_ISDIR(after.st_mode)
        or (after.st_dev, after.st_ino) != ledger_identity
    ):
        raise ReceiptError("replay ledger identity changed during consumption")
    if os.name != "nt" and stat.S_IMODE(after.st_mode) & 0o077:
        raise ReceiptError("replay ledger POSIX mode widened during consumption")
    return key


def compile_bundle(
    bundle_path: Path,
    *,
    reviewer_public_key_path: Path,
    operator_public_key_path: Path,
    observer_public_key_path: Path,
    meter_public_key_path: Path,
    reviewer_key_sha256: str,
    operator_key_sha256: str,
    observer_key_sha256: str,
    meter_key_sha256: str,
    ledger_dir: Path,
    fixture_only: bool,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    if not bundle_path.is_absolute():
        raise ReceiptError("source bundle path must be absolute")
    _verify_real_directory_chain(bundle_path.parent, "protected evidence root")
    bundle, bundle_raw = _load_json(bundle_path, MAX_JSON_BYTES, "isolated session source bundle")
    _exact_keys(
        bundle,
        {
            "schema",
            "purpose",
            "bundle_id",
            "provenance",
            "plan",
            "plan_signature_base64",
            "operator_ack",
            "operator_signature_base64",
            "unit_identity_receipt",
            "topology_receipt",
            "observer_envelope",
            "observer_signature_base64",
            "meter_signature_base64",
            "runner_evidence_reference",
            "pool_acceptance_contract_reference",
            "credential_commitment_key_path",
            "credential_commitment_key_receipt",
        },
        "source bundle",
    )
    if bundle.get("schema") != SOURCE_SCHEMA or bundle.get("purpose") != PURPOSE:
        raise ReceiptError("source bundle schema/purpose mismatch")
    _identifier(bundle.get("bundle_id"), "bundle_id")
    provenance = bundle.get("provenance")
    if provenance not in {"synthetic_fixture", "independently_signed_live_capture"}:
        raise ReceiptError("source bundle provenance is unknown")
    if fixture_only:
        if provenance != "synthetic_fixture":
            raise ReceiptError("fixture compiler rejects live-labelled source")
    else:
        if provenance != "independently_signed_live_capture":
            raise ReceiptError("production compiler rejects fixture source")
        production_pins = (
            PRODUCTION_REVIEWER_PUBLIC_KEY_SHA256,
            PRODUCTION_OPERATOR_PUBLIC_KEY_SHA256,
            PRODUCTION_OBSERVER_PUBLIC_KEY_SHA256,
            PRODUCTION_METER_PUBLIC_KEY_SHA256,
        )
        if not all(SHA256_RE.fullmatch(item) for item in production_pins):
            raise ReceiptError("production authority key pins are not provisioned")
        if (
            reviewer_key_sha256,
            operator_key_sha256,
            observer_key_sha256,
            meter_key_sha256,
        ) != production_pins:
            raise ReceiptError("provided keys do not match provisioned production pins")
    if len(
        {
            reviewer_key_sha256,
            operator_key_sha256,
            observer_key_sha256,
            meter_key_sha256,
        }
    ) != 4:
        raise ReceiptError(
            "reviewer/operator/observer/meter public keys must be distinct"
        )
    reviewer_key = _public_key(reviewer_public_key_path, reviewer_key_sha256, "reviewer")
    operator_key = _public_key(operator_public_key_path, operator_key_sha256, "operator")
    observer_key = _public_key(observer_public_key_path, observer_key_sha256, "observer")
    meter_key = _public_key(meter_public_key_path, meter_key_sha256, "meter")
    plan = _mapping(bundle.get("plan"), "reviewed plan")
    valid_from, expires = _validate_plan(plan)
    plan_sha = sha256_bytes(canonical_json(plan))
    _verify_signature(reviewer_key, _signature(bundle.get("plan_signature_base64"), "plan signature"), PLAN_DOMAIN, plan, "reviewed plan")
    _validate_acceptance_contract(
        bundle_path, bundle.get("pool_acceptance_contract_reference"), plan
    )
    ack = _mapping(bundle.get("operator_ack"), "operator acknowledgement")
    _validate_operator_ack(ack, plan, plan_sha)
    ack_sha = sha256_bytes(canonical_json(ack))
    _verify_signature(operator_key, _signature(bundle.get("operator_signature_base64"), "operator signature"), OPERATOR_DOMAIN, ack, "operator acknowledgement")
    topology = _mapping(bundle.get("topology_receipt"), "topology receipt")
    topology_reviewed = _validate_topology(topology, plan)
    if sha256_bytes(canonical_json(topology)) != plan["isolation"]["topology_receipt_sha256"]:
        raise ReceiptError("topology receipt hash differs from reviewed plan")
    unit_identity = _mapping(bundle.get("unit_identity_receipt"), "unit identity receipt")
    _validate_unit_identity(unit_identity, plan)
    if sha256_bytes(canonical_json(unit_identity)) != plan["target"]["unit_identity_receipt_sha256"]:
        raise ReceiptError("unit identity receipt hash differs from reviewed plan")
    transcript, runner_evidence_raw = _load_runner_evidence(
        bundle_path,
        bundle.get("runner_evidence_reference"),
        plan,
        plan_sha,
        ack_sha,
    )
    _validate_transcript_header(transcript, plan, plan_sha, ack_sha)
    envelope = _mapping(bundle.get("observer_envelope"), "observer envelope")
    _validate_envelope(
        envelope,
        plan,
        plan_sha,
        ack_sha,
        sha256_bytes(runner_evidence_raw),
    )
    _verify_signature(observer_key, _signature(bundle.get("observer_signature_base64"), "observer signature"), OBSERVER_DOMAIN, envelope, "observer envelope")
    capture_path = _relative_input(bundle_path, envelope.get("raw_capture_path"), "raw capture path")
    capture, capture_raw = _load_json(capture_path, MAX_EVIDENCE_BYTES, "raw observer capture")
    if envelope.get("raw_capture_bytes") != len(capture_raw) or envelope.get("raw_capture_sha256") != sha256_bytes(capture_raw):
        raise ReceiptError("observer envelope raw-capture size/hash mismatch")
    if envelope.get("capture_started_monotonic_ns") != capture.get("capture_started_monotonic_ns") or envelope.get("capture_ended_monotonic_ns") != capture.get("capture_ended_monotonic_ns") or envelope.get("dropped_packets") != capture.get("dropped_packets"):
        raise ReceiptError("observer envelope/capture window or drop counter mismatch")
    attempts = _validate_raw_capture(capture, plan)
    packet_capture_path = _relative_input(
        bundle_path,
        capture.get("packet_capture_path"),
        "packet capture path",
    )
    packet_capture_raw = read_regular(
        packet_capture_path, MAX_EVIDENCE_BYTES, "raw packet capture"
    )
    if (
        capture.get("packet_capture_bytes") != len(packet_capture_raw)
        or capture.get("packet_capture_sha256")
        != sha256_bytes(packet_capture_raw)
    ):
        raise ReceiptError("raw packet capture size/hash mismatch")
    runner, documents = _load_runner_connections(bundle_path, transcript)
    _match_capture(runner, attempts, plan)
    if capture["capture_started_monotonic_ns"] > transcript["started_monotonic_ns"] or capture["capture_ended_monotonic_ns"] < transcript["ended_monotonic_ns"]:
        raise ReceiptError("observer capture does not contain full runner session window")
    version_documents = [documents[item["connection_id"]] for item in runner if item["command"] == "version"]
    if len(version_documents) != 1:
        raise ReceiptError("session must contain exactly one VERSION identity response")
    version_payload = version_documents[0]["VERSION"]
    if len(version_payload) != 1 or not isinstance(version_payload[0], Mapping) or any(version_payload[0].get(key) != value for key, value in plan["target"]["expected_version_fields"].items()):
        raise ReceiptError("VERSION response does not bind exact reviewed target")
    key_path = _relative_input(
        bundle_path,
        bundle.get("credential_commitment_key_path"),
        "credential commitment key path",
    )
    commitment_key = read_regular(key_path, 32, "credential commitment key")
    key_receipt = _mapping(
        bundle.get("credential_commitment_key_receipt"),
        "credential commitment key receipt",
    )
    _exact_keys(
        key_receipt,
        {
            "schema",
            "purpose",
            "session_id",
            "unit_id",
            "nonce",
            "algorithm",
            "bytes",
            "key_sha256",
            "generated_at_utc",
        },
        "credential commitment key receipt",
    )
    if (
        key_receipt.get("schema") != COMMITMENT_KEY_RECEIPT_SCHEMA
        or key_receipt.get("purpose") != PURPOSE
        or any(
            key_receipt.get(key) != plan[key]
            for key in ("session_id", "unit_id", "nonce")
        )
        or key_receipt.get("algorithm") != "os_csprng_256"
        or key_receipt.get("bytes") != 32
        or key_receipt.get("key_sha256") != sha256_bytes(commitment_key)
    ):
        raise ReceiptError("credential commitment key generation receipt mismatch")
    if (
        sha256_bytes(canonical_json(key_receipt))
        != plan["artifacts"]["credential_commitment_key_receipt_sha256"]
    ):
        raise ReceiptError(
            "credential commitment key receipt differs from reviewed plan"
        )
    key_generated_at = _utc(
        key_receipt.get("generated_at_utc"),
        "credential commitment key generation time",
    )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ReceiptError("compiler now must be timezone-aware")
    if current < valid_from or current > expires:
        raise ReceiptError("isolated session plan is not currently valid")
    transcript_started = _utc(transcript["started_at_utc"], "runner start")
    transcript_ended = _utc(transcript["ended_at_utc"], "runner end")
    ack_time = _utc(ack["acknowledged_at_utc"], "operator acknowledgement time")
    identity_time = _utc(unit_identity["captured_at_utc"], "unit identity capture time")
    if not (
        valid_from
        <= identity_time
        <= topology_reviewed
        <= ack_time
        <= transcript_started
        <= transcript_ended
        <= expires
    ):
        raise ReceiptError("review/approval/session UTC ordering escapes signed plan")
    if key_generated_at > valid_from:
        raise ReceiptError("credential commitment key was not prepared before plan window")
    if not valid_from <= transcript_started <= transcript_ended <= expires:
        raise ReceiptError("runner UTC session escapes signed plan window")
    meter_signature = _signature(
        bundle.get("meter_signature_base64"), "idle power meter signature"
    )
    transaction = _validate_transaction(
        bundle_path,
        transcript,
        runner,
        documents,
        plan,
        commitment_key,
        meter_key,
        meter_signature,
    )
    bundle_sha = sha256_bytes(bundle_raw)
    local_replay_key = _consume_local_replay(
        ledger_dir,
        plan["session_id"],
        plan["nonce"],
        bundle_sha,
        commitment_key,
    )
    production = not fixture_only
    return {
        "schema": RECEIPT_SCHEMA,
        "purpose": PURPOSE,
        "receipt_id": f"{bundle['bundle_id']}.compiled-v1",
        "provenance": provenance,
        "source_bundle_hmac_sha256": hmac.new(commitment_key, bundle_raw, hashlib.sha256).hexdigest(),
        "session": {"session_id": plan["session_id"], "unit_id": plan["unit_id"], "nonce_sha256": sha256_bytes(plan["nonce"].encode("ascii")), "plan_sha256": plan_sha, "operator_ack_sha256": ack_sha},
        "target": {
            "model": plan["target"]["model"],
            "btcminer_sha256": plan["target"]["btcminer_sha256"],
            "expected_version_fields": plan["target"]["expected_version_fields"],
            "unit_id": plan["unit_id"],
            "target_ipv4_hmac_sha256": hmac.new(
                commitment_key,
                b"DCENT:NANO3:TARGET-IPV4:V1\x00"
                + plan["session_id"].encode("ascii")
                + b"\x00"
                + plan["target"]["ipv4_sha256"].encode("ascii"),
                hashlib.sha256,
            ).hexdigest(),
            "unit_fingerprint_hmac_sha256": hmac.new(
                commitment_key,
                b"DCENT:NANO3:UNIT-FINGERPRINT:V1\x00"
                + plan["session_id"].encode("ascii")
                + b"\x00"
                + unit_identity["unit_fingerprint_sha256"].encode("ascii"),
                hashlib.sha256,
            ).hexdigest(),
        },
        "artifacts": plan["artifacts"],
        "isolation": {
            "topology_and_filter_bound_by_reviewed_plan": True,
            "semantic_capture_hmac_sha256": hmac.new(
                commitment_key, capture_raw, hashlib.sha256
            ).hexdigest(),
            "raw_observer_capture_bytes_hmac_sha256": hmac.new(
                commitment_key, packet_capture_raw, hashlib.sha256
            ).hexdigest(),
            "capture_container_format_claimed_by_observer": (
                "opaque_observer_capture_bytes"
            ),
            "capture_container_format_validated_by_compiler": False,
            "connection_attempt_count": len(attempts),
            "observer_signed_semantic_attempts_matched_runner_events": True,
            "semantic_attempts_mechanically_derived_from_opaque_capture_by_compiler": False,
            "dropped_packets": 0,
            "same_clock_domain": plan["isolation"][
                "same_host_monotonic_clock_domain"
            ],
            "bypass_prevention_assertion_signature_verified": True,
            "network_observation_completeness_physically_proven": False,
        },
        "transaction": transaction,
        "credential_boundary": {
            "raw_urls_users_emitted": False,
            "stable_protected_config_or_raw_pool_hashes_emitted": False,
            "commitment_algorithm": "per-session HMAC-SHA256",
            "commitment_key_retained_only_in_operator_protected_input": True,
            "key_generation_receipt_shape_and_key_binding_verified": True,
            "commitment_key_entropy_independently_proven": False,
        },
        "signatures": {
            "reviewer_verified": True,
            "operator_verified": True,
            "observer_verified": True,
            "meter_verified": True,
            "distinct_authority_keys_verified": True,
        },
        "replay": {
            "local_ledger_consumed": True,
            "local_replay_key_sha256": local_replay_key,
            "owner_only_posix_mode_verified": os.name != "nt",
            "windows_acl_privacy_verified": False,
            "ledger_deletion_resistance_proven": False,
            "cross_host_replay_prevention_proven": False,
            "global_replay_prevention_proven": False,
        },
        "machine_verification_pass": True,
        "production_authority_keys_verified": production,
        "source_bundle_provenance_label": provenance,
        "physical_capture_authenticity_proven_by_compiler": False,
        "trust_limits": {
            "trusted_time_provenance_proven": False,
            "distinct_signer_person_identity_proven": False,
            "signing_key_custody_independently_proven": False,
            "directory_fsync_portability_proven": False,
            "windows_acl_privacy_verified": False,
        },
        "input_custody": {
            "all_references_confined_to_nonaliased_bundle_root": True,
            "descriptor_size_identity_rechecked_during_each_read": True,
            "concurrent_replace_between_separate_reads_excluded": False,
        },
        "authorization_a_granted": False,
        "authority": "receipt verifies one bounded transaction only; grants no contact, mutation, future action, or Authorization A",
    }


def _write_new(path: Path, raw: bytes) -> None:
    if path.exists():
        raise ReceiptError("refusing to overwrite output")
    _verify_real_directory_chain(path.parent, "output parent")
    if not path.parent.is_dir():
        raise ReceiptError("output parent must already exist")
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise ReceiptError("output parent must be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            if count <= 0:
                raise ReceiptError("output write made no progress")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(path.parent)


def generate_commitment_key(
    key_path: Path,
    receipt_path: Path,
    *,
    session_id: str,
    unit_id: str,
    nonce: str,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Create a one-session commitment key and protected generation record."""

    for value, label in (
        (session_id, "session_id"),
        (unit_id, "unit_id"),
        (nonce, "nonce"),
    ):
        _identifier(value, label)
    if not key_path.is_absolute() or not receipt_path.is_absolute():
        raise ReceiptError("key and receipt outputs must be absolute paths")
    if key_path == receipt_path:
        raise ReceiptError("key and receipt outputs must be distinct")
    if key_path.exists() or receipt_path.exists():
        raise ReceiptError("refusing to overwrite key or generation receipt")
    generated = now or datetime.now(timezone.utc)
    if generated.tzinfo is None:
        raise ReceiptError("key generation time must be timezone-aware")
    key = os.urandom(32)
    document = {
        "schema": COMMITMENT_KEY_RECEIPT_SCHEMA,
        "purpose": PURPOSE,
        "session_id": session_id,
        "unit_id": unit_id,
        "nonce": nonce,
        "algorithm": "os_csprng_256",
        "bytes": 32,
        "key_sha256": sha256_bytes(key),
        "generated_at_utc": generated.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    _write_new(key_path, key)
    _write_new(receipt_path, canonical_json(document))
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    compile_parser = sub.add_parser("compile", help="compile a protected session bundle offline")
    compile_parser.add_argument("--source-bundle", type=Path, required=True)
    compile_parser.add_argument("--reviewer-public-key", type=Path, required=True)
    compile_parser.add_argument("--reviewer-key-sha256", required=True)
    compile_parser.add_argument("--operator-public-key", type=Path, required=True)
    compile_parser.add_argument("--operator-key-sha256", required=True)
    compile_parser.add_argument("--observer-public-key", type=Path, required=True)
    compile_parser.add_argument("--observer-key-sha256", required=True)
    compile_parser.add_argument("--meter-public-key", type=Path, required=True)
    compile_parser.add_argument("--meter-key-sha256", required=True)
    compile_parser.add_argument("--ledger-dir", type=Path, required=True)
    compile_parser.add_argument("--output", type=Path, required=True)
    compile_parser.add_argument("--fixture-only", action="store_true")
    key_parser = sub.add_parser(
        "generate-commitment-key",
        help="create a protected one-session HMAC key and generation receipt",
    )
    key_parser.add_argument("--key-output", type=Path, required=True)
    key_parser.add_argument("--receipt-output", type=Path, required=True)
    key_parser.add_argument("--session-id", required=True)
    key_parser.add_argument("--unit-id", required=True)
    key_parser.add_argument("--nonce", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "generate-commitment-key":
            document = generate_commitment_key(
                args.key_output,
                args.receipt_output,
                session_id=args.session_id,
                unit_id=args.unit_id,
                nonce=args.nonce,
            )
            print(
                "COMMITMENT_KEY_GENERATED "
                f"receipt_sha256={sha256_bytes(canonical_json(document))} "
                "authorization_a=NO"
            )
            return 0
        receipt = compile_bundle(
            args.source_bundle,
            reviewer_public_key_path=args.reviewer_public_key,
            operator_public_key_path=args.operator_public_key,
            observer_public_key_path=args.observer_public_key,
            meter_public_key_path=args.meter_public_key,
            reviewer_key_sha256=args.reviewer_key_sha256,
            operator_key_sha256=args.operator_key_sha256,
            observer_key_sha256=args.observer_key_sha256,
            meter_key_sha256=args.meter_key_sha256,
            ledger_dir=args.ledger_dir,
            fixture_only=args.fixture_only,
        )
        raw = canonical_json(receipt)
        _write_new(args.output, raw)
        print(
            f"ISOLATED_POOL_RECEIPT_WRITTEN sha256={sha256_bytes(raw)} "
            f"fixture_only={int(args.fixture_only)} authorization_a=NO"
        )
        return 0
    except ReceiptError as exc:
        print(f"ISOLATED_POOL_RECEIPT_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
