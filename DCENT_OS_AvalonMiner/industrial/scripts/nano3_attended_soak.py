#!/usr/bin/env python3
"""Bounded host runner for an explicitly authorized Nano 3 W1 attended soak.

Invoking this file without the ``run`` subcommand never opens a socket or
starts a process.  ``fixture`` uses only a caller-supplied in-memory event
script.  A live run requires an operator-approved manifest, its exact SHA-256,
an independently repeated target, an authorization reference, and the literal
execution switch.  None of those values grants authority by itself.

This runner intentionally has no flash, reboot, target-process signal, fan, watchdog, UART,
SSH command escape hatch, or arbitrary miner-command path.  Phase 4 of the W1
draft is outside its vocabulary.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol, Sequence

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
import nano3_stock_telemetry_contract as stock_telemetry  # noqa: E402


SCHEMA = "dcent.nano3.w1-attended-soak.v1"
ISOLATED_POOL_PURPOSE = "nano3_attended_soak_isolated_pool_transaction_only"
ISOLATED_POOL_WALL_SCHEMA = "dcent.nano3.isolated-pool-idle-power-proof.v1"
HELD_BTCMINER_SHA256 = (
    "e6c11630a187d677f55178fa1dc7f2f1a52805856c538fae70cfbf0038ca6751"
)
LIVE_COMMS = ("API", "watchdog_thread", "watchpool_threa")
SOURCE_ONLY_IMPOSSIBLE_COMM = "watchpool_thread"
REQUIRED_ACTIONS = frozenset(
    {
        "target_lan_contact",
        "bounded_host_to_target_load",
        "read_only_ssh_http_cgminer_probes",
        "cgminer_pool_mutation",
        "exact_pool_state_restore",
        "restore_original_hashing_state",
        "manual_whole_unit_ac_disconnect_on_abort",
    }
)
REQUIRED_EXCLUSIONS = frozenset(
    {
        "flash",
        "reboot",
        "kill_or_signal_btcminer",
        "watchdog_close_probe_phase4",
        "fixed_fan_or_fan_spd_mutation",
        "uart_contact",
    }
)
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
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_RE = re.compile(r"(?i)(replace|placeholder|todo|tbd|example|<|>)")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LOCAL_JSON_BYTES = 256 * 1024
MAX_HTTP_HEADER_BYTES = 64 * 1024
MAX_SSH_STDOUT_BYTES = 64 * 1024
MAX_LOAD_PAYLOAD_BYTES = 1024 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_KEY_OR_HOSTS_BYTES = 4 * 1024 * 1024
MAX_CONTRACT_RECEIPT_BYTES = 1024 * 1024
PROBE_HOST_MARGIN_SECONDS = 1.0
TRANSACTION_HOST_MARGIN_SECONDS = 2.0
DEAD_POOL_PARAMETER = "stratum+tcp://127.0.0.1:1,x,x"
DEAD_POOL_URL = "stratum+tcp://127.0.0.1:1"
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(item) for item in ("203.0.113.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class SoakError(RuntimeError):
    """Fail-closed validation, protocol, or session error."""


class ManifestError(SoakError):
    pass


class ProtocolError(SoakError):
    pass


class TransportError(SoakError):
    pass


class ApiPlaneError(TransportError):
    pass


class SafetyAbort(SoakError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ManifestError(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ManifestError(f"{label} is not a valid UTC timestamp") from exc
    return parsed


def require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{label} must be an object")
    return value


def require_exact_keys(
    mapping: Mapping[str, Any], expected: set[str], label: str
) -> None:
    observed = set(mapping)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        raise ManifestError(
            f"{label} keys mismatch; missing={missing}, unknown={unknown}"
        )


def require_bool(mapping: Mapping[str, Any], key: str, expected: bool = True) -> None:
    if mapping.get(key) is not expected:
        raise ManifestError(f"{key} must be {str(expected).lower()}")


def require_text(mapping: Mapping[str, Any], key: str, *, min_len: int = 1) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or len(value.strip()) < min_len:
        raise ManifestError(f"{key} must be a nonempty string")
    if PLACEHOLDER_RE.search(value):
        raise ManifestError(f"{key} contains a placeholder")
    return value


def require_number(
    mapping: Mapping[str, Any], key: str, low: float, high: float
) -> float:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ManifestError(f"{key} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ManifestError(f"{key} must be finite")
    if result < low or result > high:
        raise ManifestError(f"{key} must be within {low}..{high}")
    return result


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            pass
    finally:
        os.close(descriptor)


def path_component_is_alias(metadata: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def verify_real_directory_chain(path: Path, label: str) -> None:
    absolute = path.absolute()
    for component in list(reversed(absolute.parents)) + [absolute]:
        if not component.exists():
            continue
        try:
            observed = component.lstat()
        except OSError as exc:
            raise SoakError(f"cannot inspect {label} directory chain") from exc
        if path_component_is_alias(observed) or not stat.S_ISDIR(observed.st_mode):
            raise SoakError(f"{label} directory chain contains alias/non-directory")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _open_pinned_regular_file(path: Path, maximum: int) -> tuple[int, os.stat_result]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ManifestError(f"cannot stat bounded file {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ManifestError(f"bounded input is not a non-symlink regular file: {path}")
    if metadata.st_size > maximum:
        raise ManifestError(f"bounded input exceeds {maximum} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ManifestError(f"cannot read bounded file {path}: {exc}") from exc
    if not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise ManifestError(f"opened input is not a regular file: {path}")
    identity_before = (metadata.st_dev, metadata.st_ino, metadata.st_size)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size)
    if identity_before != identity_opened:
        os.close(descriptor)
        raise ManifestError(f"bounded input changed while opening: {path}")
    return descriptor, opened


def read_bounded_regular_file(path: Path, maximum: int = MAX_LOCAL_JSON_BYTES) -> bytes:
    descriptor, opened = _open_pinned_regular_file(path, maximum)
    raw = bytearray()
    try:
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ManifestError(f"cannot read bounded file {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise ManifestError(f"bounded input exceeds {maximum} bytes: {path}")
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(raw) != opened.st_size:
        raise ManifestError(f"bounded input changed while reading: {path}")
    return bytes(raw)


def validate_pinned_file(
    path: Path, expected_sha256: Any, maximum: int, label: str,
    *, expected_size: Optional[int] = None,
) -> None:
    if not path.is_absolute():
        raise ManifestError(f"{label} must be an absolute path")
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ManifestError(f"{label} SHA-256 must be lowercase hexadecimal")
    descriptor, opened = _open_pinned_regular_file(path, maximum)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ManifestError(f"{label} exceeds its bounded size")
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ManifestError(f"cannot hash pinned file {label}: {exc}") from exc
    finally:
        os.close(descriptor)
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or total != opened.st_size:
        raise ManifestError(f"{label} changed while hashing")
    if expected_size is not None and total != expected_size:
        raise ManifestError(f"{label} byte count mismatch")
    if digest.hexdigest() != expected_sha256:
        raise ManifestError(f"{label} SHA-256 mismatch")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
        "ascii"
    )


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
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
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON token {token}")
            ),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        raise ManifestError(f"malformed {label}: {exc}") from exc


def finite_runtime_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProtocolError(f"{label} is not numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ProtocolError(f"{label} is not finite")
    return result


def runtime_counter(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(f"{label} is not a nonnegative integer")
    return value


def is_rfc1918(address: ipaddress.IPv4Address) -> bool:
    return any(address in network for network in RFC1918_NETWORKS)


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(
            read_bounded_regular_file(path).decode("utf-8"), label
        )
    except (OSError, UnicodeError, ManifestError) as exc:
        raise ManifestError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError(f"{label} root must be an object")
    return value


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ManifestError("JSON pointers must start with '/'")
    current = document
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                raise ProtocolError(f"JSON pointer missing list index: {pointer}")
            current = current[int(part)]
        elif isinstance(current, Mapping):
            if part not in current:
                raise ProtocolError(f"JSON pointer missing object field: {pointer}")
            current = current[part]
        else:
            raise ProtocolError(f"JSON pointer crosses scalar: {pointer}")
    return current


@dataclass(frozen=True)
class Timeouts:
    connect: float
    read: float
    total: float


@dataclass(frozen=True)
class PoolState:
    pool_id: int
    priority: int
    enabled: bool
    stratum_active: bool


@dataclass(frozen=True)
class ParsedResponse:
    document: dict[str, Any]
    raw_sha256: str
    raw_bytes: int
    code: int
    connection_id: int = 0


@dataclass
class ValidatedManifest:
    raw: dict[str, Any]
    path: Path
    raw_bytes: bytes
    sha256: str
    target: str
    timeouts: dict[str, Timeouts]
    cadence: float
    load_path: Path
    telemetry_contract: Mapping[str, Any]


def _validate_envelope(section: Mapping[str, Any], prefix: str) -> tuple[float, float]:
    low = require_number(section, "min", 0, 1_000_000_000)
    high = require_number(section, "max", 0, 1_000_000_000)
    if low > high:
        raise ManifestError(f"{prefix}.min exceeds {prefix}.max")
    return low, high


def validate_manifest(
    path: Path, *, live: bool, now: Optional[datetime] = None
) -> ValidatedManifest:
    raw_bytes = read_bounded_regular_file(path)
    try:
        raw = strict_json_loads(raw_bytes.decode("utf-8"), "session manifest")
    except (UnicodeError, ManifestError) as exc:
        raise ManifestError(f"malformed session manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("session manifest root must be an object")
    require_exact_keys(
        raw,
        {
            "schema",
            "session",
            "target",
            "isolated_lan",
            "attended_safety",
            "guard",
            "timeouts_seconds",
            "probe_cadence_seconds",
            "load",
            "thermal_acceptance",
            "wall_power_acceptance",
            "load_acceptance",
            "hash_off_proof",
            "cgminer_protocol",
            "isolated_pool_receipt",
        },
        "manifest",
    )
    if raw.get("schema") != SCHEMA:
        raise ManifestError(f"schema must equal {SCHEMA!r}")

    receipt_binding = require_mapping(
        raw.get("isolated_pool_receipt"), "isolated_pool_receipt"
    )
    require_exact_keys(
        receipt_binding, {"unit_id", "nonce"}, "isolated_pool_receipt"
    )
    for key in ("unit_id", "nonce"):
        value = require_text(receipt_binding, key, min_len=8)
        if not SESSION_ID_RE.fullmatch(value):
            raise ManifestError(f"isolated_pool_receipt.{key} has invalid shape")

    session = require_mapping(raw.get("session"), "session")
    require_exact_keys(
        session,
        {
            "id",
            "disposition",
            "operator",
            "authorization_reference",
            "approved_at_utc",
            "expires_at_utc",
            "exact_actions",
            "explicit_exclusions",
            "consumption_marker_path",
        },
        "session",
    )
    session_id = require_text(session, "id", min_len=8)
    if not SESSION_ID_RE.fullmatch(session_id):
        raise ManifestError("session.id has an invalid shape")
    disposition = session.get("disposition")
    expected_disposition = "operator_approved" if live else "fixture_only"
    if disposition != expected_disposition:
        raise ManifestError(
            f"session.disposition must be {expected_disposition!r} in this mode"
        )
    require_text(session, "operator", min_len=3)
    require_text(session, "authorization_reference", min_len=8)
    approved = parse_utc(session.get("approved_at_utc"), "approved_at_utc")
    expires = parse_utc(session.get("expires_at_utc"), "expires_at_utc")
    if expires <= approved:
        raise ManifestError("approval expiry must follow approval time")
    if (expires - approved).total_seconds() > 4 * 60 * 60:
        raise ManifestError("approval window may not exceed four hours")
    if live:
        instant = now or datetime.now(timezone.utc)
        if instant < approved or instant > expires:
            raise ManifestError("operator approval window is not currently open")
    actions = session.get("exact_actions")
    exclusions = session.get("explicit_exclusions")
    if (
        not isinstance(actions, list)
        or any(not isinstance(item, str) for item in actions)
        or len(actions) != len(set(actions))
        or set(actions) != REQUIRED_ACTIONS
    ):
        raise ManifestError("session.exact_actions must equal the fixed W1 action set")
    if (
        not isinstance(exclusions, list)
        or any(not isinstance(item, str) for item in exclusions)
        or len(exclusions) != len(set(exclusions))
        or set(exclusions) != REQUIRED_EXCLUSIONS
    ):
        raise ManifestError("session.explicit_exclusions omits a mandatory exclusion")
    marker_path = Path(require_text(session, "consumption_marker_path"))
    if not marker_path.is_absolute() or not marker_path.parent.is_dir():
        raise ManifestError("session consumption marker needs an existing absolute parent")
    marker_parent = marker_path.parent.lstat()
    if stat.S_ISLNK(marker_parent.st_mode) or not stat.S_ISDIR(marker_parent.st_mode):
        raise ManifestError("session consumption marker parent must be a real directory")

    target_section = require_mapping(raw.get("target"), "target")
    require_exact_keys(
        target_section,
        {
            "ipv4",
            "repeat_ipv4",
            "btcminer_sha256",
            "expected_version_fields",
            "api_port",
            "http_port",
            "ssh_port",
        },
        "target",
    )
    target = require_text(target_section, "ipv4")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ManifestError("target.ipv4 must be a literal IPv4 address") from exc
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise ManifestError("target.ipv4 is not an admissible unicast IPv4 literal")
    if target_section.get("repeat_ipv4") != target:
        raise ManifestError("target.repeat_ipv4 must exactly repeat target.ipv4")
    if live and not is_rfc1918(address):
        raise ManifestError("live target must be an explicit RFC1918 IPv4 address")
    if not live and not (address.is_loopback or address in ipaddress.ip_network("192.0.2.0/24")):
        raise ManifestError("fixture target must be loopback or TEST-NET-1")
    if target_section.get("btcminer_sha256") != HELD_BTCMINER_SHA256:
        raise ManifestError("target btcminer hash does not match the held Nano 3 binary")
    version_expectations = require_mapping(
        target_section.get("expected_version_fields"),
        "target.expected_version_fields",
    )
    if set(version_expectations) != {"CGMiner", "VERSION", "PROD"}:
        raise ManifestError("target version expectations must pin CGMiner/VERSION/PROD")
    for field in ("CGMiner", "VERSION", "PROD"):
        require_text(version_expectations, field)
    if target_section.get("api_port") != 4028:
        raise ManifestError("target.api_port must be the exact held port 4028")
    for key in ("http_port", "ssh_port"):
        value = target_section.get(key)
        if not isinstance(value, int) or not 1 <= value <= 65535:
            raise ManifestError(f"target.{key} must be a valid port")

    boundary = require_mapping(raw.get("isolated_lan"), "isolated_lan")
    require_exact_keys(
        boundary,
        {
            "boundary_record",
            "subnet_cidr",
            "operator_controlled",
            "only_permitted_hosts_can_reach_4028",
            "permitted_host_ipv4",
            "single_serialized_mutation_client",
            "receipt_observer_clock_domain",
        },
        "isolated_lan",
    )
    require_text(boundary, "boundary_record", min_len=12)
    subnet_text = require_text(boundary, "subnet_cidr")
    try:
        subnet = ipaddress.ip_network(subnet_text, strict=True)
    except ValueError as exc:
        raise ManifestError("isolated_lan.subnet_cidr is invalid/non-canonical") from exc
    if subnet.version != 4 or address not in subnet:
        raise ManifestError("isolated LAN subnet does not contain the target")
    if address in {subnet.network_address, subnet.broadcast_address}:
        raise ManifestError("target may not be the subnet network/broadcast address")
    if live and not all(
        any(endpoint in network for network in RFC1918_NETWORKS)
        for endpoint in (subnet.network_address, subnet.broadcast_address)
    ):
        raise ManifestError("live isolated LAN subnet must be wholly RFC1918")
    require_bool(boundary, "operator_controlled")
    require_bool(boundary, "only_permitted_hosts_can_reach_4028")
    hosts = boundary.get("permitted_host_ipv4")
    if (
        not isinstance(hosts, list)
        or not hosts
        or any(not isinstance(host, str) for host in hosts)
    ):
        raise ManifestError("isolated_lan.permitted_host_ipv4 must be nonempty")
    if len(hosts) != len(set(hosts)):
        raise ManifestError("permitted host list contains duplicates")
    for host in hosts:
        try:
            parsed_host = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ManifestError("permitted hosts must be literal IP addresses") from exc
        if (
            parsed_host.version != 4
            or parsed_host.is_unspecified
            or parsed_host.is_multicast
            or parsed_host == address
            or parsed_host not in subnet
            or parsed_host in {subnet.network_address, subnet.broadcast_address}
        ):
            raise ManifestError("permitted hosts must be safe, distinct IPv4s in the subnet")
        if live and not is_rfc1918(parsed_host):
            raise ManifestError("live permitted hosts must be explicit RFC1918 IPv4s")
    require_bool(boundary, "single_serialized_mutation_client")
    observer_clock_domain = require_text(
        boundary, "receipt_observer_clock_domain", min_len=8
    )
    if not SESSION_ID_RE.fullmatch(observer_clock_domain):
        raise ManifestError("receipt observer clock domain has invalid shape")

    attended = require_mapping(raw.get("attended_safety"), "attended_safety")
    require_exact_keys(
        attended,
        {
            "operator_at_bench_continuously",
            "manual_ac_disconnect_within_arm_reach",
            "manual_ac_is_not_independent_or_automatic",
            "acknowledges_ac_removes_fan_power",
            "external_post_cut_thermal_observation_required",
            "post_cut_observation_seconds",
            "stock_fan_remains_auto",
            "phase4_excluded",
        },
        "attended_safety",
    )
    for key in (
        "operator_at_bench_continuously",
        "manual_ac_disconnect_within_arm_reach",
        "manual_ac_is_not_independent_or_automatic",
        "acknowledges_ac_removes_fan_power",
        "external_post_cut_thermal_observation_required",
        "stock_fan_remains_auto",
        "phase4_excluded",
    ):
        require_bool(attended, key)
    require_number(attended, "post_cut_observation_seconds", 120, 3600)

    guard = require_mapping(raw.get("guard"), "guard")
    require_exact_keys(
        guard,
        {
            "expected_btcminer_sha256",
            "required_live_comms",
            "required_initial_fields",
        },
        "guard",
    )
    if guard.get("expected_btcminer_sha256") != HELD_BTCMINER_SHA256:
        raise ManifestError("guard hash is not the held btcminer hash")
    if guard.get("required_live_comms") != list(LIVE_COMMS):
        raise ManifestError("guard.required_live_comms must use exact live comm values")
    if SOURCE_ONLY_IMPOSSIBLE_COMM in guard.get("required_live_comms", []):
        raise ManifestError("the impossible 16-character comm is actionable")
    if guard.get("required_initial_fields") != {
        "guard_initial_admission": "success",
        "pass_1_btcminer_hash_admitted": "1",
        "pass_1_all_targets_nice_zero": "1",
    }:
        raise ManifestError("guard required initial fields are incomplete")

    timeout_root = require_mapping(raw.get("timeouts_seconds"), "timeouts_seconds")
    require_exact_keys(timeout_root, {"api", "http", "ssh"}, "timeouts_seconds")
    timeouts: dict[str, Timeouts] = {}
    for plane in ("api", "http", "ssh"):
        item = require_mapping(timeout_root.get(plane), f"timeouts_seconds.{plane}")
        require_exact_keys(item, {"connect", "read", "total"}, f"timeouts_seconds.{plane}")
        connect = require_number(item, "connect", 0.05, 10)
        read = require_number(item, "read", 0.05, 10)
        total = require_number(item, "total", max(connect, read), 10)
        timeouts[plane] = Timeouts(connect, read, total)
    cadence = require_number(raw, "probe_cadence_seconds", 1, 300)
    # One load probe is SSH + HTTP + summary/stats/devs/lcd (four API calls).
    serialized_total = (
        timeouts["ssh"].total
        + timeouts["http"].total
        + 4 * timeouts["api"].total
        + PROBE_HOST_MARGIN_SECONDS
    )
    if cadence < serialized_total:
        raise ManifestError(
            "probe cadence is shorter than the serialized hard total timeout budget"
        )

    load = require_mapping(raw.get("load"), "load")
    require_exact_keys(
        load,
        {
            "payload_path",
            "payload_bytes",
            "payload_sha256",
            "direction",
            "concurrency",
            "duration_seconds",
            "per_transfer_total_timeout_seconds",
            "remote_tmpfs_path",
            "scp_executable",
            "scp_executable_sha256",
            "ssh_executable",
            "ssh_executable_sha256",
            "ssh_identity_file",
            "ssh_identity_file_sha256",
            "known_hosts_file",
            "known_hosts_sha256",
        },
        "load",
    )
    load_path = Path(require_text(load, "payload_path"))
    expected_size = load.get("payload_bytes")
    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or not 1 <= expected_size <= MAX_LOAD_PAYLOAD_BYTES
    ):
        raise ManifestError("load.payload_bytes must be within the bounded payload limit")
    expected_sha = load.get("payload_sha256")
    validate_pinned_file(
        load_path,
        expected_sha,
        MAX_LOAD_PAYLOAD_BYTES,
        "load.payload_path",
        expected_size=expected_size,
    )
    if load.get("direction") != "host_to_target_tmpfs":
        raise ManifestError("load direction must be host_to_target_tmpfs")
    concurrency = load.get("concurrency")
    if not isinstance(concurrency, int) or not 1 <= concurrency <= 4:
        raise ManifestError("load.concurrency must be an integer within 1..4")
    load_duration = require_number(load, "duration_seconds", 30, 300)
    if load_duration < 2 * cadence:
        raise ManifestError(
            "load duration must cover two nonoverlapping serialized probe cadences"
        )
    require_number(load, "per_transfer_total_timeout_seconds", 1, 30)
    remote_path = require_text(load, "remote_tmpfs_path")
    if remote_path != f"/tmp/dcent-w1-{session_id}.payload":
        raise ManifestError("load remote path must be the session-bound /tmp path")
    for name in ("scp_executable", "ssh_executable", "ssh_identity_file"):
        executable_or_key = Path(require_text(load, name))
        expected_digest = load.get(f"{name}_sha256")
        maximum = (
            MAX_EXECUTABLE_BYTES
            if name in {"scp_executable", "ssh_executable"}
            else MAX_KEY_OR_HOSTS_BYTES
        )
        validate_pinned_file(executable_or_key, expected_digest, maximum, f"load.{name}")
    known_hosts = Path(require_text(load, "known_hosts_file"))
    known_hash = load.get("known_hosts_sha256")
    validate_pinned_file(
        known_hosts, known_hash, MAX_KEY_OR_HOSTS_BYTES, "load.known_hosts_file"
    )

    thermal = require_mapping(raw.get("thermal_acceptance"), "thermal_acceptance")
    require_exact_keys(
        thermal,
        {
            "contract_status",
            "contract_receipt_path",
            "contract_receipt_sha256",
            "engineering_basis",
            "qualified_limit_reference",
            "stock_90c_pid_target_is_not_a_safety_limit",
            "temperature_ceiling_c",
            "max_rise_c_per_minute",
            "telemetry_freshness_seconds",
            "auto_rpm",
            "temperature_pointers",
            "fan_rpm_pointers",
            "auto_mode_pointer",
            "sensor_sample_epoch_pointer",
        },
        "thermal_acceptance",
    )
    expected_contract = "target_capture_reviewed" if live else "fixture_only"
    if thermal.get("contract_status") != expected_contract:
        raise ManifestError(
            f"thermal contract_status must be {expected_contract!r} in this mode"
        )
    contract_path = Path(require_text(thermal, "contract_receipt_path"))
    contract_sha = thermal.get("contract_receipt_sha256")
    validate_pinned_file(
        contract_path,
        contract_sha,
        MAX_CONTRACT_RECEIPT_BYTES,
        "thermal contract receipt",
    )
    try:
        telemetry_contract = stock_telemetry.load_contract(
            contract_path, str(contract_sha), live=live
        )
    except stock_telemetry.ContractError as exc:
        raise ManifestError(f"stock telemetry contract refused: {exc}") from exc
    contract_target = require_mapping(telemetry_contract.get("target"), "contract target")
    if contract_target.get("btcminer_sha256") != target_section.get("btcminer_sha256"):
        raise ManifestError("stock telemetry contract btcminer binding mismatch")
    if contract_target.get("expected_version_fields") != version_expectations:
        raise ManifestError("stock telemetry contract VERSION binding mismatch")
    require_text(thermal, "engineering_basis", min_len=24)
    require_text(thermal, "qualified_limit_reference", min_len=12)
    require_bool(thermal, "stock_90c_pid_target_is_not_a_safety_limit")
    require_number(thermal, "temperature_ceiling_c", -20, 150)
    require_number(thermal, "max_rise_c_per_minute", 0.01, 50)
    require_number(thermal, "telemetry_freshness_seconds", 0.1, cadence)
    rpm = require_mapping(thermal.get("auto_rpm"), "thermal_acceptance.auto_rpm")
    require_exact_keys(rpm, {"min", "max", "stock_mode_must_equal_auto"}, "auto_rpm")
    _validate_envelope(rpm, "thermal_acceptance.auto_rpm")
    require_bool(rpm, "stock_mode_must_equal_auto")
    for key in (
        "temperature_pointers",
        "fan_rpm_pointers",
        "auto_mode_pointer",
        "sensor_sample_epoch_pointer",
    ):
        value = thermal.get(key)
        if key == "fan_rpm_pointers":
            if not isinstance(value, list) or not value:
                raise ManifestError("fan_rpm_pointers must be a nonempty list")
            if any(not isinstance(pointer, str) for pointer in value) or len(value) != len(set(value)):
                raise ManifestError("fan RPM pointers must be unique strings")
            for pointer in value:
                if not isinstance(pointer, str) or not pointer.startswith("/"):
                    raise ManifestError("fan RPM pointers must be JSON pointers")
        elif key == "temperature_pointers":
            if not isinstance(value, list) or not value:
                raise ManifestError("temperature_pointers must be a nonempty list")
            if any(not isinstance(pointer, str) or not pointer.startswith("/") for pointer in value):
                raise ManifestError("temperature pointers must be JSON pointers")
            if len(value) != len(set(value)):
                raise ManifestError("temperature pointers must be unique")
        elif not isinstance(value, str) or not value.startswith("/"):
            raise ManifestError(f"{key} must be a JSON pointer")
    runtime_mapping = require_mapping(
        telemetry_contract.get("runtime_mapping"), "contract runtime_mapping"
    )
    if not live:
        for key in (
            "temperature_pointers",
            "fan_rpm_pointers",
            "auto_mode_pointer",
            "sensor_sample_epoch_pointer",
        ):
            if runtime_mapping.get(key) != thermal.get(key):
                raise ManifestError(f"thermal {key} differs from pinned telemetry contract")

    wall = require_mapping(raw.get("wall_power_acceptance"), "wall_power_acceptance")
    require_exact_keys(
        wall,
        {
            "meter_id",
            "engineering_basis",
            "sample_freshness_seconds",
            "idle_watts",
            "hashing_watts",
            "hash_off_watts",
            "sample_file",
        },
        "wall_power_acceptance",
    )
    require_text(wall, "meter_id", min_len=4)
    require_text(wall, "engineering_basis", min_len=24)
    require_number(wall, "sample_freshness_seconds", 0.1, cadence)
    wall_envelopes = {}
    for name in ("idle_watts", "hashing_watts", "hash_off_watts"):
        envelope = require_mapping(wall.get(name), name)
        require_exact_keys(envelope, {"min", "max"}, name)
        wall_envelopes[name] = _validate_envelope(envelope, name)
    idle_min, idle_max = wall_envelopes["idle_watts"]
    hashing_min, _hashing_max = wall_envelopes["hashing_watts"]
    hash_off_min, hash_off_max = wall_envelopes["hash_off_watts"]
    if hashing_min <= max(idle_max, hash_off_max):
        raise ManifestError("hashing wall-power minimum must exceed idle/hash-off maximum")
    if hash_off_min < idle_min or hash_off_max > idle_max:
        raise ManifestError("hash-off wall envelope must be contained in idle envelope")
    wall_path = Path(require_text(wall, "sample_file"))
    if not wall_path.is_absolute():
        raise ManifestError("wall sample file must be absolute")
    if not wall_path.parent.is_dir():
        raise ManifestError("wall sample file parent directory does not exist")
    wall_parent = wall_path.parent.lstat()
    if stat.S_ISLNK(wall_parent.st_mode) or not stat.S_ISDIR(wall_parent.st_mode):
        raise ManifestError("wall sample parent must be a real directory")

    load_acceptance = require_mapping(raw.get("load_acceptance"), "load_acceptance")
    require_exact_keys(
        load_acceptance,
        {
            "short_window_pointer",
            "accepted_pointer",
            "rejected_pointer",
            "hardware_errors_pointer",
            "short_window_mhs",
            "accepted_min_delta",
            "rejected_max_delta",
            "hardware_errors_max_delta",
            "original_current_pool_must_remain_selected",
        },
        "load_acceptance",
    )
    if load_acceptance.get("short_window_pointer") != "/SUMMARY/0/MHS 5s":
        raise ManifestError("load acceptance must use MHS 5s")
    for key, exact in (
        ("accepted_pointer", "/SUMMARY/0/Accepted"),
        ("rejected_pointer", "/SUMMARY/0/Rejected"),
        ("hardware_errors_pointer", "/SUMMARY/0/Hardware Errors"),
    ):
        if load_acceptance.get(key) != exact:
            raise ManifestError(f"load acceptance {key} mismatch")
    load_mhs = require_mapping(load_acceptance.get("short_window_mhs"), "short_window_mhs")
    require_exact_keys(load_mhs, {"min", "max"}, "short_window_mhs")
    _validate_envelope(load_mhs, "short_window_mhs")
    for key in ("accepted_min_delta", "rejected_max_delta", "hardware_errors_max_delta"):
        value = load_acceptance.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ManifestError(f"load_acceptance.{key} must be a nonnegative integer")
    if load_acceptance["accepted_min_delta"] < 1:
        raise ManifestError("load accepted_min_delta must prove accepted-share progress")
    require_bool(load_acceptance, "original_current_pool_must_remain_selected")

    proof = require_mapping(raw.get("hash_off_proof"), "hash_off_proof")
    require_exact_keys(
        proof,
        {
            "proof_seconds",
            "sample_interval_seconds",
            "idle_settle_seconds",
            "short_window_pointer",
            "accepted_pointer",
            "short_window_mhs_max",
            "lcd_is_corroboration_only",
            "btcminer_and_telemetry_must_remain_alive",
            "lcd_observation_file",
        },
        "hash_off_proof",
    )
    if proof.get("proof_seconds") != 120:
        raise ManifestError("hash-off proof must be exactly 120 seconds")
    sample_interval = require_number(proof, "sample_interval_seconds", 1, cadence)
    if sample_interval < 3 * timeouts["api"].total + PROBE_HOST_MARGIN_SECONDS:
        raise ManifestError("hash-off sample interval is shorter than three API total bounds")
    if proof.get("short_window_pointer") != "/SUMMARY/0/MHS 5s":
        raise ManifestError("hash-off must use exact short-window MHS 5s")
    if proof.get("accepted_pointer") != "/SUMMARY/0/Accepted":
        raise ManifestError("hash-off must pin the Accepted counter")
    require_number(proof, "short_window_mhs_max", 0, 1000000)
    require_number(proof, "idle_settle_seconds", 0, 90)
    require_bool(proof, "lcd_is_corroboration_only")
    require_bool(proof, "btcminer_and_telemetry_must_remain_alive")
    lcd_path = Path(require_text(proof, "lcd_observation_file"))
    if not lcd_path.is_absolute() or not lcd_path.parent.is_dir():
        raise ManifestError("LCD observation file must have an existing absolute parent")
    lcd_parent = lcd_path.parent.lstat()
    if stat.S_ISLNK(lcd_parent.st_mode) or not stat.S_ISDIR(lcd_parent.st_mode):
        raise ManifestError("LCD observation parent must be a real directory")

    protocol = require_mapping(raw.get("cgminer_protocol"), "cgminer_protocol")
    require_exact_keys(
        protocol,
        {
            "request_framing",
            "response_framing",
            "response_id",
            "max_response_bytes",
            "dead_pool_parameter",
            "max_original_pools",
            "hash_off_total_timeout_seconds",
            "restore_total_timeout_seconds",
        },
        "cgminer_protocol",
    )
    if protocol.get("request_framing") != "minified_json_plus_one_nul":
        raise ManifestError("unexpected CGMiner request framing")
    if protocol.get("response_framing") != "one_json_object_then_nuls":
        raise ManifestError("unexpected CGMiner response framing")
    if protocol.get("response_id") != 1 or protocol.get("max_response_bytes") != MAX_RESPONSE_BYTES:
        raise ManifestError("CGMiner response id/size contract mismatch")
    if protocol.get("dead_pool_parameter") != DEAD_POOL_PARAMETER:
        raise ManifestError("dead pool request bytes are not pinned")
    max_pools = protocol.get("max_original_pools")
    if isinstance(max_pools, bool) or not isinstance(max_pools, int) or not 1 <= max_pools <= 3:
        raise ManifestError("max_original_pools must be an integer within 1..3")
    hash_off_total = require_number(protocol, "hash_off_total_timeout_seconds", 1, 120)
    restore_total = require_number(protocol, "restore_total_timeout_seconds", 1, 120)
    if hash_off_total < (
        (7 + max_pools) * timeouts["api"].total
        + TRANSACTION_HOST_MARGIN_SECONDS
    ):
        raise ManifestError("hash-off transaction timeout cannot cover admitted API calls")
    if restore_total < (
        (5 + max_pools) * timeouts["api"].total
        + TRANSACTION_HOST_MARGIN_SECONDS
    ):
        raise ManifestError("restore transaction timeout cannot cover admitted API calls")
    freshness = float(thermal["telemetry_freshness_seconds"])
    if hash_off_total > freshness or restore_total > freshness:
        raise ManifestError(
            "hash-off and restore totals must fit the reviewed telemetry-freshness bound"
        )

    return ValidatedManifest(
        raw=raw,
        path=path,
        raw_bytes=raw_bytes,
        sha256=sha256_bytes(raw_bytes),
        target=target,
        timeouts=timeouts,
        cadence=cadence,
        load_path=load_path,
        telemetry_contract=telemetry_contract,
    )


def encode_request(command: str, parameter: Optional[str] = None) -> bytes:
    if command not in ALLOWED_COMMANDS:
        raise ProtocolError(f"command is outside the fixed allowlist: {command!r}")
    request: dict[str, str] = {"command": command}
    if parameter is not None:
        request["parameter"] = parameter
    return json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    ) + b"\x00"


def decode_response(raw: bytes, expected_code: int, payload_key: Optional[str] = None) -> ParsedResponse:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError("empty or oversized CGMiner response")
    if b"\x00" not in raw:
        raise ProtocolError("CGMiner response is truncated (missing NUL terminator)")
    body, trailer = raw.split(b"\x00", 1)
    if any(byte != 0 for byte in trailer):
        raise ProtocolError("non-NUL bytes follow the first response terminator")
    try:
        document = json.loads(
            body.decode("utf-8"),
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON token {token}")
            ),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ProtocolError("CGMiner response is not one UTF-8 JSON object") from exc
    if not isinstance(document, dict):
        raise ProtocolError("CGMiner response root is not an object")
    response_id = document.get("id")
    if isinstance(response_id, bool) or not isinstance(response_id, int) or response_id != 1:
        raise ProtocolError("CGMiner response id is not exact 1 (truncated/wrong reply)")
    statuses = document.get("STATUS")
    if not isinstance(statuses, list) or len(statuses) != 1:
        raise ProtocolError("CGMiner response must contain exactly one STATUS entry")
    status = statuses[0]
    if not isinstance(status, dict) or status.get("STATUS") != "S":
        raise ProtocolError("CGMiner response is not an unambiguous success")
    status_code = status.get("Code")
    if (
        isinstance(status_code, bool)
        or not isinstance(status_code, int)
        or status_code != expected_code
    ):
        raise ProtocolError(
            f"CGMiner response code {status_code!r} does not equal {expected_code}"
        )
    when = status.get("When")
    if isinstance(when, bool) or not isinstance(when, int) or when < 0:
        raise ProtocolError("CGMiner STATUS.When is not an exact nonnegative integer")
    if payload_key is not None:
        payload = document.get(payload_key)
        if not isinstance(payload, list) or not payload:
            raise ProtocolError(f"CGMiner response lacks nonempty {payload_key} list")
    return ParsedResponse(document, sha256_bytes(raw), len(raw), expected_code)


def verify_http_response(raw: bytes) -> None:
    boundary = raw.find(b"\r\n\r\n")
    if boundary < 0:
        raise ProtocolError("HTTP response lacks a complete header terminator")
    if boundary + 4 > MAX_HTTP_HEADER_BYTES:
        raise ProtocolError("HTTP header block exceeds its bound")
    header_raw = raw[:boundary]
    body = raw[boundary + 4 :]
    try:
        lines = header_raw.decode("iso-8859-1").split("\r\n")
    except UnicodeError as exc:
        raise ProtocolError("HTTP headers are not decodable") from exc
    if not lines or lines[0] not in {"HTTP/1.0 200 OK", "HTTP/1.1 200 OK"}:
        raise ProtocolError("HTTP root did not return exact 200 OK")
    content_lengths: list[str] = []
    transfer_encodings: list[str] = []
    for line in lines[1:]:
        if not line or ":" not in line:
            raise ProtocolError("HTTP header line is malformed")
        name, value = line.split(":", 1)
        folded = name.strip().casefold()
        if folded == "content-length":
            content_lengths.append(value.strip())
        elif folded == "transfer-encoding":
            transfer_encodings.append(value.strip())
    if transfer_encodings:
        raise ProtocolError("HTTP Transfer-Encoding is not admitted")
    if len(content_lengths) != 1 or not content_lengths[0].isdigit():
        raise ProtocolError("HTTP requires exactly one numeric Content-Length")
    expected = int(content_lengths[0])
    if expected > MAX_RESPONSE_BYTES - (boundary + 4):
        raise ProtocolError("HTTP body length exceeds its configured bound")
    if len(body) != expected:
        raise ProtocolError("HTTP body length does not equal Content-Length")


def parse_pools(response: ParsedResponse) -> list[PoolState]:
    entries = response.document.get("POOLS")
    if not isinstance(entries, list) or not entries:
        raise ProtocolError("POOLS list missing or empty")
    parsed: list[PoolState] = []
    seen_ids: set[int] = set()
    seen_priorities: set[int] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProtocolError("pool entry is not an object")
        pool_id = entry.get("POOL")
        priority = entry.get("Priority")
        status = entry.get("Status")
        active = entry.get("Stratum Active")
        if isinstance(pool_id, bool) or not isinstance(pool_id, int) or pool_id < 0:
            raise ProtocolError("pool id is not a nonnegative integer")
        if isinstance(priority, bool) or not isinstance(priority, int) or priority < 0:
            raise ProtocolError("pool priority is not a nonnegative integer")
        if status not in {"Alive", "Dead", "Disabled", "Rejecting"}:
            raise ProtocolError("pool status is unknown")
        if not isinstance(active, bool):
            raise ProtocolError("Stratum Active must be boolean")
        if pool_id in seen_ids or priority in seen_priorities:
            raise ProtocolError("duplicate/ambiguous pool id or priority")
        seen_ids.add(pool_id)
        seen_priorities.add(priority)
        parsed.append(PoolState(pool_id, priority, status != "Disabled", active))
    return sorted(parsed, key=lambda item: item.pool_id)


def verify_version_identity(
    response: ParsedResponse, expected_fields: Mapping[str, Any]
) -> None:
    entries = response.document.get("VERSION")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise ProtocolError("VERSION payload must contain exactly one object")
    for field in ("CGMiner", "VERSION", "PROD"):
        if entries[0].get(field) != expected_fields.get(field):
            raise ProtocolError(f"target VERSION identity mismatch: {field}")


def verify_mutation_ack(
    command: str, parameter: Optional[str], response: ParsedResponse
) -> None:
    status = response.document["STATUS"][0]
    message = status.get("Msg")
    if not isinstance(message, str):
        raise ProtocolError("mutation acknowledgement lacks Msg")
    if command == "poolpriority":
        if message != "Changed pool priorities":
            raise ProtocolError("poolpriority acknowledgement mismatch")
        return
    if command == "addpool":
        if not re.fullmatch(r"Added pool [0-9]+: '.+'", message):
            raise ProtocolError("addpool acknowledgement mismatch")
        return
    if parameter is None or not parameter.isdigit():
        raise ProtocolError("pool mutation parameter is not an exact numeric ID")
    prefixes = {
        "switchpool": "Switching to pool",
        "enablepool": "Enabling pool",
        "disablepool": "Disabling pool",
        "removepool": "Removed pool",
    }
    prefix = prefixes.get(command)
    if prefix is None or not message.startswith(f"{prefix} {parameter}:"):
        raise ProtocolError(f"{command} acknowledgement does not bind requested pool ID")


def current_pool_id_from_lcd(
    pools_response: ParsedResponse, lcd_response: ParsedResponse
) -> int:
    lcd_entries = lcd_response.document.get("LCD")
    pool_entries = pools_response.document.get("POOLS")
    if (
        not isinstance(lcd_entries, list)
        or len(lcd_entries) != 1
        or not isinstance(lcd_entries[0], dict)
        or not isinstance(pool_entries, list)
    ):
        raise ProtocolError("LCD/current-pool response shape mismatch")
    current_url = lcd_entries[0].get("Current Pool")
    current_user = lcd_entries[0].get("User")
    if not isinstance(current_url, str) or not isinstance(current_user, str):
        raise ProtocolError("LCD current pool URL/user is missing")
    matches = [
        entry.get("POOL")
        for entry in pool_entries
        if isinstance(entry, dict)
        and entry.get("URL") == current_url
        and entry.get("User") == current_user
    ]
    if len(matches) != 1 or not isinstance(matches[0], int):
        raise ProtocolError("LCD current pool does not map to exactly one pool ID")
    return matches[0]


def protected_pool_identity_hashes(response: ParsedResponse) -> dict[int, str]:
    entries = response.document.get("POOLS")
    if not isinstance(entries, list):
        raise ProtocolError("POOLS identity list is missing")
    identities: dict[int, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProtocolError("POOLS identity entry is malformed")
        pool_id = entry.get("POOL")
        url = entry.get("URL")
        user = entry.get("User")
        if (
            isinstance(pool_id, bool)
            or not isinstance(pool_id, int)
            or not isinstance(url, str)
            or not isinstance(user, str)
            or pool_id in identities
        ):
            raise ProtocolError("POOLS stable identity fields are missing/ambiguous")
        identities[pool_id] = sha256_bytes(canonical_json({"URL": url, "User": user}))
    return identities


def verify_guard_receipt(raw: bytes) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise ProtocolError("priority guard receipt is not ASCII") from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            raise ProtocolError(f"duplicate priority guard field: {key}")
        fields[key] = value
    required = {
        "schema": "dcent-nano3-priority-guard-v2",
        "expected_btcminer_sha256": HELD_BTCMINER_SHA256,
        "target_set": ",".join(LIVE_COMMS),
        "pass_1_observed_btcminer_sha256": HELD_BTCMINER_SHA256,
        "pass_1_btcminer_hash_admitted": "1",
        "pass_1_all_targets_nice_zero": "1",
        "pass_1_target_api_post_nice": "0",
        "pass_1_target_watchdog_thread_post_nice": "0",
        "pass_1_target_watchpool_threa_post_nice": "0",
        "guard_initial_admission": "success",
    }
    for key, expected in required.items():
        if fields.get(key) != expected:
            raise ProtocolError(f"priority guard receipt mismatch: {key}")
    if SOURCE_ONLY_IMPOSSIBLE_COMM in fields.get("target_set", "").split(","):
        raise ProtocolError("priority guard receipt used the impossible full comm")


def verify_priority_state(raw: bytes) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise ProtocolError("independent priority state is not ASCII") from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            raise ProtocolError("independent priority state line is malformed")
        key, value = line.split("=", 1)
        if key in fields:
            raise ProtocolError("independent priority state has duplicate fields")
        fields[key] = value
    expected_keys = {"initial_pid", "initial_sha256", "final_pid", "final_sha256"}
    for name in LIVE_COMMS:
        expected_keys.update({f"{name}_count", f"{name}_tid", f"{name}_nice"})
    if set(fields) != expected_keys:
        raise ProtocolError("independent priority state field set mismatch")
    if (
        not fields["initial_pid"].isdigit()
        or fields["initial_pid"] != fields["final_pid"]
        or fields["initial_sha256"] != HELD_BTCMINER_SHA256
        or fields["final_sha256"] != HELD_BTCMINER_SHA256
    ):
        raise ProtocolError("independent priority state PID/hash mismatch")
    tids: set[str] = set()
    for name in LIVE_COMMS:
        if fields[f"{name}_count"] != "1" or fields[f"{name}_nice"] != "0":
            raise ProtocolError(f"independent priority state mismatch: {name}")
        tid = fields[f"{name}_tid"]
        if not tid.isdigit() or tid in tids:
            raise ProtocolError("independent priority state TID is invalid/duplicate")
        tids.add(tid)


class Transport(Protocol):
    def guard_receipt(self) -> bytes: ...

    def pool_config_digest(self) -> str: ...

    def pool_config_bytes(self) -> bytes: ...

    def priority_state(self) -> bytes: ...

    def tmpfs_available_bytes(self) -> int: ...

    def ssh_true(self) -> None: ...

    def http_get_root(self) -> bytes: ...

    def api(self, command: str, parameter: Optional[str] = None) -> bytes: ...


class FixtureTransport:
    """Strict offline event transport; mismatch or exhaustion is fatal."""

    def __init__(self, fixture: Mapping[str, Any]) -> None:
        receipt = fixture.get("guard_receipt_base64")
        priority = fixture.get("priority_state_base64")
        tmpfs_bytes = fixture.get("tmpfs_available_bytes")
        events = fixture.get("events")
        if (
            not isinstance(receipt, str)
            or not isinstance(priority, str)
            or isinstance(tmpfs_bytes, bool)
            or not isinstance(tmpfs_bytes, int)
            or not isinstance(events, list)
        ):
            raise ManifestError(
                "fixture must contain guard/priority/tmpfs evidence and events"
            )
        try:
            self._guard = base64.b64decode(receipt, validate=True)
            self._priority = base64.b64decode(priority, validate=True)
        except ValueError as exc:
            raise ManifestError("fixture guard receipt is not strict base64") from exc
        self._events = list(events)
        self._tmpfs_bytes = tmpfs_bytes
        self._index = 0

    def _next(self, operation: str, command: Optional[str] = None, parameter: Optional[str] = None) -> Mapping[str, Any]:
        if self._index >= len(self._events):
            raise TransportError("fixture event stream exhausted")
        event = self._events[self._index]
        self._index += 1
        if not isinstance(event, Mapping) or event.get("operation") != operation:
            raise TransportError("fixture operation ordering mismatch")
        if command is not None and event.get("command") != command:
            raise TransportError("fixture command mismatch")
        if command is not None and event.get("parameter") != parameter:
            raise TransportError("fixture parameter mismatch")
        failure = event.get("failure")
        if failure is not None:
            if failure not in {"connect_timeout", "read_timeout", "total_timeout", "stall", "failure"}:
                raise ManifestError("fixture failure kind is unknown")
            raise TransportError(f"fixture injected {failure}")
        return event

    def guard_receipt(self) -> bytes:
        return self._guard

    def pool_config_digest(self) -> str:
        event = self._next("pool_config_digest")
        value = event.get("sha256")
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise ManifestError("fixture pool config digest is invalid")
        return value

    def priority_state(self) -> bytes:
        return self._priority

    def tmpfs_available_bytes(self) -> int:
        return self._tmpfs_bytes

    def ssh_true(self) -> None:
        self._next("ssh")

    def http_get_root(self) -> bytes:
        event = self._next("http")
        raw = event.get("response_base64")
        if not isinstance(raw, str):
            raise ManifestError("fixture HTTP response missing")
        try:
            return base64.b64decode(raw, validate=True)
        except ValueError as exc:
            raise ManifestError("fixture HTTP response is not strict base64") from exc

    def api(self, command: str, parameter: Optional[str] = None) -> bytes:
        event = self._next("api", command, parameter)
        raw = event.get("response_base64")
        if not isinstance(raw, str):
            raise ManifestError("fixture API response missing")
        try:
            return base64.b64decode(raw, validate=True)
        except ValueError as exc:
            raise ManifestError("fixture API response is not strict base64") from exc

    def assert_consumed(self) -> None:
        if self._index != len(self._events):
            raise TransportError("fixture contains unconsumed events")


class SystemTransport:
    """The only class that can contact the target; constructed only by run."""

    _GUARD_REMOTE_COMMAND = "head -c 65537 /run/dcentos-priority-guard.txt"
    _PRIORITY_REMOTE_COMMAND = (
        "p=$(pidof btcminer 2>/dev/null); case \"$p\" in ''|*' '*|*[!0-9]*) exit 21;; esac; "
        "printf 'initial_pid=%s\\n' \"$p\"; sha256sum /proc/$p/exe | "
        "awk 'NF==2 {print \"initial_sha256=\"$1; ok=1} END {exit(ok?0:24)}'; "
        "for n in API watchdog_thread watchpool_threa; do c=0; tid=; nice=; "
        "for d in /proc/$p/task/*; do read x < \"$d/comm\" || exit 22; "
        "if [ \"$x\" = \"$n\" ]; then c=$((c+1)); tid=${d##*/}; "
        "nice=$(awk 'NR==1 {print $19}' \"$d/stat\") || exit 23; fi; done; "
        "printf '%s_count=%s\\n%s_tid=%s\\n%s_nice=%s\\n' \"$n\" \"$c\" "
        "\"$n\" \"$tid\" \"$n\" \"$nice\"; done; "
        "q=$(pidof btcminer 2>/dev/null); [ \"$q\" = \"$p\" ] || exit 25; "
        "printf 'final_pid=%s\\n' \"$q\"; sha256sum /proc/$q/exe | "
        "awk 'NF==2 {print \"final_sha256=\"$1; ok=1} END {exit(ok?0:26)}'"
    )

    def __init__(self, manifest: ValidatedManifest) -> None:
        self.manifest = manifest
        self.target = manifest.target
        self.target_section = require_mapping(manifest.raw["target"], "target")
        load = require_mapping(manifest.raw["load"], "load")
        self.identity = str(load["ssh_identity_file"])
        self.known_hosts = str(load["known_hosts_file"])
        self._api_lock = threading.Lock()

    def _ssh_argv(self, remote_command: str) -> list[str]:
        timeout = self.manifest.timeouts["ssh"]
        load = self.manifest.raw["load"]
        return [
            str(load["ssh_executable"]),
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            f"ConnectTimeout={max(1, int(timeout.connect))}",
            "-o",
            f"ServerAliveInterval={max(1, int(timeout.read))}",
            "-o",
            "ServerAliveCountMax=1",
            "-p",
            str(self.target_section["ssh_port"]),
            "-i",
            self.identity,
            f"admin@{self.target}",
            remote_command,
        ]

    def _run_ssh(self, command: str) -> bytes:
        timeout = self.manifest.timeouts["ssh"]
        try:
            result = subprocess.run(
                self._ssh_argv(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout.total,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError("SSH hard total timeout") from exc
        if result.returncode != 0:
            raise TransportError(f"SSH failed with exit code {result.returncode}")
        if len(result.stdout) > MAX_SSH_STDOUT_BYTES:
            raise TransportError("SSH fixed-command stdout exceeds its bound")
        return result.stdout

    def guard_receipt(self) -> bytes:
        return self._run_ssh(self._GUARD_REMOTE_COMMAND)

    def pool_config_digest(self) -> str:
        raw = self._run_ssh("sha256sum /data/usrcon/cgminer.ini")
        try:
            words = raw.decode("ascii").strip().split()
        except UnicodeError as exc:
            raise ProtocolError("pool config digest output is not ASCII") from exc
        if len(words) != 2 or words[1] != "/data/usrcon/cgminer.ini":
            raise ProtocolError("pool config digest output has unexpected shape")
        if not SHA256_RE.fullmatch(words[0]):
            raise ProtocolError("pool config digest is not lowercase SHA-256")
        return words[0]

    def pool_config_bytes(self) -> bytes:
        raw = self._run_ssh("head -c 65537 /data/usrcon/cgminer.ini")
        if len(raw) > 65536:
            raise ProtocolError("protected pool config exceeds 65536-byte bound")
        return raw

    def priority_state(self) -> bytes:
        return self._run_ssh(self._PRIORITY_REMOTE_COMMAND)

    def tmpfs_available_bytes(self) -> int:
        # The remote path is fixed by the validated session-id grammar. No
        # manifest-provided shell or arbitrary path is interpolated here.
        remote_path = str(self.manifest.raw["load"]["remote_tmpfs_path"])
        command = (
            "awk '$2==\"/tmp\" && $3==\"tmpfs\" {ok=1} END {exit(ok?0:31)}' "
            "/proc/mounts && set -- $(df -Pk /tmp | awk 'NR==2 {print $4}'); "
            "f='" + remote_path + "'; [ ! -e \"$f\" ] || exit 32; "
            "case \"$1\" in ''|*[!0-9]*) exit 33;; esac; printf '%s\\n' \"$1\""
        )
        raw = self._run_ssh(command)
        try:
            available_kib = int(raw.decode("ascii").strip())
        except (UnicodeError, ValueError) as exc:
            raise ProtocolError("remote /tmp capacity output is invalid") from exc
        if available_kib < 0:
            raise ProtocolError("remote /tmp capacity is negative")
        return available_kib * 1024

    def ssh_true(self) -> None:
        self._run_ssh("true")

    def _socket_exchange(self, port: int, request: bytes, timeout: Timeouts) -> bytes:
        started = time.monotonic()
        response = bytearray()
        try:
            connection = socket.create_connection((self.target, port), timeout=timeout.connect)
            with connection:
                remaining = timeout.total - (time.monotonic() - started)
                if remaining <= 0:
                    raise TransportError("hard total timeout before send")
                connection.settimeout(min(timeout.read, remaining))
                connection.sendall(request)
                while True:
                    remaining = timeout.total - (time.monotonic() - started)
                    if remaining <= 0:
                        raise TransportError("hard total timeout during read")
                    connection.settimeout(min(timeout.read, remaining))
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE_BYTES:
                        raise TransportError("response exceeds bounded size")
        except (OSError, socket.timeout) as exc:
            raise TransportError(f"bounded socket failure: {type(exc).__name__}") from exc
        return bytes(response)

    def http_get_root(self) -> bytes:
        request = (
            f"GET / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        raw = self._socket_exchange(
            int(self.target_section["http_port"]),
            request,
            self.manifest.timeouts["http"],
        )
        verify_http_response(raw)
        return raw

    def api(self, command: str, parameter: Optional[str] = None) -> bytes:
        # One lock is the serialized-mutation-client boundary for reads and writes.
        with self._api_lock:
            return self._socket_exchange(
                4028,
                encode_request(command, parameter),
                self.manifest.timeouts["api"],
            )


class EvidenceJournal:
    def __init__(self, root: Path, manifest: ValidatedManifest) -> None:
        if root.exists():
            raise SoakError(f"refusing to overwrite evidence directory: {root}")
        if not root.is_absolute() or not root.parent.is_dir():
            raise SoakError("evidence directory needs an existing absolute parent")
        verify_real_directory_chain(root.parent, "evidence parent")
        root.mkdir(mode=0o700)
        fsync_directory(root.parent)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
        self.root = root
        self.protected = root / "protected"
        self.protected.mkdir(mode=0o700)
        fsync_directory(self.root)
        self.events: list[dict[str, Any]] = []
        self.counter = 0
        self.api_counter = 0
        self.api_pending: dict[str, dict[str, Any]] = {}
        self.api_connections: list[dict[str, Any]] = []
        self.api_failures: list[dict[str, Any]] = []
        self.mutation_effect_unknown = False
        self.mutation_acknowledged = 0
        self.started_at_utc = utc_now()
        self.started_monotonic_ns = time.monotonic_ns()
        self.pool_transaction: dict[str, Any] = {}
        self.pool_config_references: dict[str, dict[str, Any]] = {}
        self.dead_pool_id: Optional[int] = None
        self.manifest = manifest
        self.write_protected_bytes("api-events.jsonl", b"")
        self.write_protected_bytes("session-manifest.json", manifest.raw_bytes)

    def _append_api_event(self, document: Mapping[str, Any]) -> None:
        raw = canonical_json(document)
        path = self.protected / "api-events.jsonl"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise SoakError("protected API journal write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(self.protected)

    def api_intent(
        self,
        command: str,
        parameter: Optional[str],
        request: bytes,
        phase: str,
    ) -> str:
        self.api_counter += 1
        event_id = f"api-{self.api_counter:04d}"
        record = {
            "schema": "dcent.nano3.runner-api-event.v1",
            "stage": "intent_before_send",
            "runner_event_id": event_id,
            "connection_id": self.api_counter,
            "at_utc": utc_now(),
            "monotonic_ns": time.monotonic_ns(),
            "phase": phase,
            "command": command,
            "parameter": parameter,
            "request_bytes": len(request),
            "request_sha256": sha256_bytes(request),
            "mutation": command in MUTATION_CODES,
        }
        self._append_api_event(record)
        self.api_pending[event_id] = dict(record)
        return event_id

    def api_response_received(
        self, event_id: str, command: str, request: bytes, response: bytes
    ) -> None:
        intent = self.api_pending.get(event_id)
        if intent is None:
            raise SoakError("API response has no durable intent")
        filename = f"{event_id}-{command}.bin"
        self.write_protected_bytes(filename, response)
        closed = time.monotonic_ns()
        intent.update(
            {
                "closed_monotonic_ns": closed,
                "response_path": f"protected/{filename}",
                "response_bytes": len(response),
                "response_sha256": sha256_bytes(response),
                "eof_observed": True,
            }
        )
        self._append_api_event(
            {
                "schema": "dcent.nano3.runner-api-event.v1",
                "stage": "response_received_before_validation",
                "runner_event_id": event_id,
                "connection_id": intent["connection_id"],
                "at_utc": utc_now(),
                "monotonic_ns": closed,
                "response_bytes": len(response),
                "response_sha256": sha256_bytes(response),
                "request_sha256": sha256_bytes(request),
            }
        )

    def api_acknowledged(self, event_id: str) -> int:
        intent = self.api_pending.get(event_id)
        if intent is None or "closed_monotonic_ns" not in intent:
            raise SoakError("API acknowledgement lacks durable response custody")
        acknowledged = time.monotonic_ns()
        connection = {
            "connection_id": intent["connection_id"],
            "runner_event_id": event_id,
            "opened_monotonic_ns": intent["monotonic_ns"],
            "closed_monotonic_ns": intent["closed_monotonic_ns"],
            "command": intent["command"],
            "parameter": intent["parameter"],
            "request_bytes": intent["request_bytes"],
            "request_sha256": intent["request_sha256"],
            "response_path": intent["response_path"],
            "response_bytes": intent["response_bytes"],
            "response_sha256": intent["response_sha256"],
            "outcome": "complete_eof",
            "eof_observed": True,
        }
        try:
            self._append_api_event(
                {
                    "schema": "dcent.nano3.runner-api-event.v1",
                    "stage": "acknowledged_after_validated_response",
                    "runner_event_id": event_id,
                    "connection_id": intent["connection_id"],
                    "at_utc": utc_now(),
                    "monotonic_ns": acknowledged,
                    "response_sha256": intent["response_sha256"],
                }
            )
        except BaseException:
            if intent["mutation"]:
                self.mutation_effect_unknown = True
            raise
        self.api_pending.pop(event_id)
        self.api_connections.append(connection)
        if intent["mutation"]:
            self.mutation_acknowledged += 1
        return int(intent["connection_id"])

    def api_failed(self, event_id: str, exc: BaseException) -> None:
        intent = self.api_pending.get(event_id)
        if intent is None:
            return
        effect_unknown = bool(intent["mutation"])
        self.mutation_effect_unknown |= effect_unknown
        record = {
            "runner_event_id": event_id,
            "connection_id": intent["connection_id"],
            "command": intent["command"],
            "phase": intent["phase"],
            "failure_type": type(exc).__name__,
            "mutation_effect_unknown": effect_unknown,
        }
        self._append_api_event(
            {
                "schema": "dcent.nano3.runner-api-event.v1",
                "stage": (
                    "mutation_effect_unknown"
                    if effect_unknown
                    else "read_connection_failed"
                ),
                "at_utc": utc_now(),
                "monotonic_ns": time.monotonic_ns(),
                **record,
            }
        )
        self.api_pending.pop(event_id)
        self.api_failures.append(record)

    def mutation_state(self, phase: str, stage: str, **fields: Any) -> None:
        if stage == "dead_pool_id_resolved":
            dead_id = fields.get("dead_pool_id")
            if isinstance(dead_id, int) and not isinstance(dead_id, bool):
                self.dead_pool_id = dead_id
        self._append_api_event(
            {
                "schema": "dcent.nano3.runner-api-event.v1",
                "stage": stage,
                "phase": phase,
                "at_utc": utc_now(),
                "monotonic_ns": time.monotonic_ns(),
                **fields,
            }
        )

    def write_protected_bytes(self, filename: str, raw: bytes) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,100}", filename):
            raise SoakError("invalid protected evidence filename")
        path = self.protected / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise SoakError("protected evidence write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(self.protected)

    def write_public_bytes(self, filename: str, raw: bytes) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,80}\.json", filename):
            raise SoakError("invalid public evidence filename")
        path = self.root / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise SoakError("public evidence write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(self.root)

    def protect_pool_config(self, label: str, raw: bytes) -> dict[str, Any]:
        if label not in {"before", "after"}:
            raise SoakError("protected pool config label is invalid")
        if len(raw) > 65536:
            raise SoakError("protected pool config exceeds 65536-byte bound")
        filename = f"pool-config-{label}.bin"
        path = self.protected / filename
        if path.exists():
            if path.read_bytes() != raw:
                raise SoakError("protected pool config snapshot changed")
        else:
            self.write_protected_bytes(filename, raw)
        reference = {
            "path": f"protected/{filename}",
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
            "captured_monotonic_ns": time.monotonic_ns(),
        }
        self.pool_config_references[label] = reference
        return reference

    def protect_idle_power_proof(
        self, document: Mapping[str, Any]
    ) -> dict[str, Any]:
        raw = canonical_json(document)
        digest = sha256_bytes(raw)
        filename = f"idle-power-proof-{digest[:16]}.json"
        path = self.protected / filename
        if not path.exists():
            self.write_protected_bytes(filename, raw)
        return {
            "path": f"protected/{filename}",
            "bytes": len(raw),
            "sha256": digest,
        }

    def set_pool_transaction_section(
        self, section: str, document: Mapping[str, Any]
    ) -> None:
        if section not in {"pre_state", "hash_off", "restore", "idle_power_reference"}:
            raise SoakError("pool transaction section is invalid")
        self.pool_transaction[section] = dict(document)
        self.mutation_state("pool_transaction", f"{section}_reference_bound")

    def write_runner_pool_evidence(self, result: str) -> None:
        if (self.protected / "runner-pool-evidence.json").exists():
            return
        complete_transaction = (
            set(self.pool_transaction)
            == {"pre_state", "hash_off", "restore", "idle_power_reference"}
            and set(self.pool_transaction.get("pre_state", {}))
            == {"pools_connection_id", "lcd_connection_id", "config_reference"}
            and set(self.pool_transaction.get("hash_off", {}))
            == {
                "mutation_connection_ids",
                "pools_connection_id",
                "lcd_connection_id",
                "summary_connection_ids",
            }
            and bool(
                self.pool_transaction.get("hash_off", {}).get(
                    "summary_connection_ids"
                )
            )
            and set(self.pool_transaction.get("restore", {}))
            == {
                "mutation_connection_ids",
                "pools_start_connection_id",
                "lcd_start_connection_id",
                "pools_connection_id",
                "lcd_connection_id",
                "config_reference",
            }
        )
        if result == "PASS" and (
            self.mutation_effect_unknown
            or self.api_failures
            or self.api_pending
            or not complete_transaction
        ):
            raise SoakError(
                "refusing PASS with pending/failed API custody or incomplete pool refs"
            )
        if result == "PASS":
            outcome = "restored_exactly"
        elif self.mutation_effect_unknown or self.mutation_acknowledged:
            outcome = "partial_mutation_unknown_or_unrestored"
        else:
            outcome = "not_started_or_no_mutation"
        ended_monotonic = time.monotonic_ns()
        fragment = {
            "schema": "dcent.nano3.isolated-pool-runner-evidence.v1",
            "purpose": "nano3_attended_soak_isolated_pool_transaction_only",
            "session_id": self.manifest.raw["session"]["id"],
            "manifest_sha256": self.manifest.sha256,
            "runner_sha256": sha256_file(Path(__file__).resolve()),
            "target_ipv4_sha256": sha256_bytes(
                self.manifest.target.encode("ascii")
            ),
            "clock_domain": self.manifest.raw["isolated_lan"][
                "receipt_observer_clock_domain"
            ],
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": utc_now(),
            "started_monotonic_ns": self.started_monotonic_ns,
            "ended_monotonic_ns": ended_monotonic,
            "connections": self.api_connections,
            "connection_failures": self.api_failures,
            "pending_intents": [
                {
                    "runner_event_id": event_id,
                    "connection_id": value["connection_id"],
                    "command": value["command"],
                    "phase": value["phase"],
                    "mutation": value["mutation"],
                }
                for event_id, value in sorted(self.api_pending.items())
            ],
            "mutation_effect_unknown": self.mutation_effect_unknown,
            "acknowledged_mutation_count": self.mutation_acknowledged,
            "resolved_dead_pool_id": self.dead_pool_id,
            "transaction_outcome": outcome,
            "transaction": self.pool_transaction,
        }
        self.write_protected_json("runner-pool-evidence.json", fragment)

    def record_raw(self, operation: str, request: bytes, response: bytes) -> None:
        self.counter += 1
        filename = f"{self.counter:04d}-{operation}.bin"
        self.write_protected_bytes(filename, response)
        self.events.append(
            {
                "at_utc": utc_now(),
                "operation": operation,
                "request_bytes": len(request),
                "request_sha256": sha256_bytes(request),
                "response_bytes": len(response),
                "response_sha256": sha256_bytes(response),
                "protected_file": filename,
            }
        )

    def note(self, event: str, **fields: Any) -> None:
        entry = {"at_utc": utc_now(), "event": event}
        entry.update(fields)
        self.events.append(entry)

    def write_protected_json(self, filename: str, document: Mapping[str, Any]) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,80}\.json", filename):
            raise SoakError("invalid protected evidence filename")
        path = self.protected / filename
        if path.exists():
            raise SoakError(f"refusing to overwrite protected evidence: {filename}")
        self.write_protected_bytes(filename, canonical_json(document))

    def finish(self, result: str, reason_code: str) -> None:
        if not re.fullmatch(r"[A-Z0-9_]{2,80}", reason_code):
            raise SoakError("public journal reason must be a sanitized code")
        self.write_runner_pool_evidence(result)
        public = {
            "schema": "dcent.nano3.w1-attended-soak-public-journal.v1",
            "session_id": self.manifest.raw["session"]["id"],
            "manifest_sha256": self.manifest.sha256,
            "target_identity_in_protected_evidence_only": True,
            "result": result,
            "reason_code": reason_code,
            "events": self.events,
            "credentials_in_public_log": False,
            "phase4_executed": False,
            "mutation_effect_unknown": self.mutation_effect_unknown,
            "acknowledged_mutation_count": self.mutation_acknowledged,
            "pending_api_intent_count": len(self.api_pending),
            "resolved_dead_pool_id": self.dead_pool_id,
            "pool_transaction_outcome": (
                "partial_mutation_unknown_or_unrestored"
                if self.mutation_effect_unknown or (
                    self.mutation_acknowledged and result != "PASS"
                )
                else "restored_exactly" if result == "PASS" else "not_started"
            ),
            "authority": "observation only; grants no future live action",
        }
        self.write_public_bytes("public-journal.json", canonical_json(public))

    def write_failure_detail(self, exc: BaseException, **extra: Any) -> None:
        document: dict[str, Any] = {
            "captured_at_utc": utc_now(),
            "exception_type": type(exc).__name__,
            "detail": str(exc),
        }
        document.update(extra)
        self.write_protected_json("failure-detail.json", document)


def read_fresh_observation(
    path: Path,
    *,
    schema: str,
    identity_key: str,
    identity_value: str,
    freshness_seconds: float,
    previous_sample_id: Optional[str],
) -> dict[str, Any]:
    document = load_json_object(path, "operator observation")
    if document.get("schema") != schema:
        raise ProtocolError(f"observation schema mismatch: {path}")
    if document.get(identity_key) != identity_value:
        raise ProtocolError(f"observation identity mismatch: {path}")
    sample_id = document.get("sample_id")
    if not isinstance(sample_id, str) or not SESSION_ID_RE.fullmatch(sample_id):
        raise ProtocolError("observation sample_id has invalid shape")
    if sample_id == previous_sample_id:
        raise ProtocolError("observation sample_id was reused/stale")
    captured = parse_utc(document.get("captured_at_utc"), "captured_at_utc")
    age = abs((datetime.now(timezone.utc) - captured).total_seconds())
    if age > freshness_seconds:
        raise ProtocolError("operator observation exceeded its freshness bound")
    return document


def read_wall_watts(
    manifest: ValidatedManifest, previous_sample_id: Optional[str]
) -> tuple[float, str]:
    watts, sample_id, _document = read_wall_power_proof(
        manifest, previous_sample_id
    )
    return watts, sample_id


def read_wall_power_proof(
    manifest: ValidatedManifest, previous_sample_id: Optional[str]
) -> tuple[float, str, dict[str, Any]]:
    section = require_mapping(
        manifest.raw["wall_power_acceptance"], "wall_power_acceptance"
    )
    document = load_json_object(Path(str(section["sample_file"])), "wall power proof")
    expected_keys = {
        "schema",
        "purpose",
        "session_id",
        "unit_id",
        "nonce",
        "meter_id",
        "captured_at_utc",
        "clock_domain",
        "captured_monotonic_ns",
        "watts",
    }
    if set(document) != expected_keys:
        raise ProtocolError("wall power proof keys are not exact")
    binding = manifest.raw["isolated_pool_receipt"]
    joins = {
        "schema": ISOLATED_POOL_WALL_SCHEMA,
        "purpose": ISOLATED_POOL_PURPOSE,
        "session_id": manifest.raw["session"]["id"],
        "unit_id": binding["unit_id"],
        "nonce": binding["nonce"],
        "meter_id": section["meter_id"],
        "clock_domain": manifest.raw["isolated_lan"][
            "receipt_observer_clock_domain"
        ],
    }
    if any(document.get(key) != value for key, value in joins.items()):
        raise ProtocolError("wall power proof exact session/meter/clock join mismatch")
    captured = parse_utc(document.get("captured_at_utc"), "captured_at_utc")
    age = abs((datetime.now(timezone.utc) - captured).total_seconds())
    if age > float(section["sample_freshness_seconds"]):
        raise ProtocolError("wall power proof exceeded its freshness bound")
    captured_mono = document.get("captured_monotonic_ns")
    if (
        isinstance(captured_mono, bool)
        or not isinstance(captured_mono, int)
        or captured_mono < 0
    ):
        raise ProtocolError("wall power proof monotonic timestamp is invalid")
    sample_id = sha256_bytes(canonical_json(document))
    if sample_id == previous_sample_id:
        raise ProtocolError("wall power proof was reused/stale")
    watts = document.get("watts")
    return finite_runtime_number(watts, "wall meter watts"), sample_id, dict(document)


def require_envelope(value: float, envelope: Mapping[str, Any], label: str) -> None:
    checked = finite_runtime_number(value, label)
    if checked < float(envelope["min"]) or checked > float(envelope["max"]):
        raise ProtocolError(f"{label} is outside its operator-approved envelope")


def load_summary_values(
    manifest: ValidatedManifest, summary: ParsedResponse
) -> tuple[float, int, int, int]:
    section = require_mapping(manifest.raw["load_acceptance"], "load_acceptance")
    mhs = finite_runtime_number(
        resolve_json_pointer(summary.document, str(section["short_window_pointer"])),
        "load MHS 5s",
    )
    require_envelope(
        mhs,
        require_mapping(section["short_window_mhs"], "short_window_mhs"),
        "load MHS 5s",
    )
    accepted = runtime_counter(
        resolve_json_pointer(summary.document, str(section["accepted_pointer"])),
        "load Accepted",
    )
    rejected = runtime_counter(
        resolve_json_pointer(summary.document, str(section["rejected_pointer"])),
        "load Rejected",
    )
    hardware_errors = runtime_counter(
        resolve_json_pointer(summary.document, str(section["hardware_errors_pointer"])),
        "load Hardware Errors",
    )
    return mhs, accepted, rejected, hardware_errors


def verify_load_progress(
    manifest: ValidatedManifest,
    baseline: tuple[float, int, int, int],
    current: tuple[float, int, int, int],
    *, final: bool,
) -> None:
    section = manifest.raw["load_acceptance"]
    for label, before, after in zip(
        ("Accepted", "Rejected", "Hardware Errors"), baseline[1:], current[1:]
    ):
        if after < before:
            raise ProtocolError(f"load {label} counter regressed")
    if current[2] - baseline[2] > int(section["rejected_max_delta"]):
        raise ProtocolError("load Rejected delta exceeds approved maximum")
    if current[3] - baseline[3] > int(section["hardware_errors_max_delta"]):
        raise ProtocolError("load Hardware Errors delta exceeds approved maximum")
    if final and current[1] - baseline[1] < int(section["accepted_min_delta"]):
        raise ProtocolError("load Accepted counter did not make approved progress")


def verify_thermal_sample(
    manifest: ValidatedManifest,
    stats: ParsedResponse,
    devs: ParsedResponse,
    previous: Optional[tuple[float, float, float]],
) -> tuple[float, float, float]:
    section = require_mapping(manifest.raw["thermal_acceptance"], "thermal")
    previous_epoch = previous[2] if previous is not None else None
    try:
        temperature, fan_values, sensor_epoch_value = (
            stock_telemetry.validate_fixture_runtime_sample(
                manifest.telemetry_contract,
                stats.document,
                devs.document,
                now_epoch=time.time(),
                freshness_seconds=float(section["telemetry_freshness_seconds"]),
                previous_sample_epoch=previous_epoch,
            )
        )
    except stock_telemetry.ContractError as exc:
        raise ProtocolError(f"stock telemetry sample refused: {exc}") from exc
    if temperature > float(section["temperature_ceiling_c"]):
        raise ProtocolError("temperature exceeds operator-approved ceiling")
    rpm_section = require_mapping(section["auto_rpm"], "auto_rpm")
    for value in fan_values:
        require_envelope(
            finite_runtime_number(value, "fan RPM field"), rpm_section, "AUTO fan RPM"
        )
    current = (time.monotonic(), temperature, sensor_epoch_value)
    if previous is not None:
        elapsed_minutes = (current[0] - previous[0]) / 60.0
        if elapsed_minutes > 0:
            rise = (current[1] - previous[1]) / elapsed_minutes
            if rise > float(section["max_rise_c_per_minute"]):
                raise ProtocolError("temperature trend exceeds operator-approved rate")
    return current


def verify_lcd_observation(
    manifest: ValidatedManifest, previous_sample_id: Optional[str]
) -> str:
    proof = require_mapping(manifest.raw["hash_off_proof"], "hash_off_proof")
    path = Path(str(proof["lcd_observation_file"]))
    document = read_fresh_observation(
        path,
        schema="dcent.nano3.lcd-observation.v1",
        identity_key="target_ipv4_sha256",
        identity_value=sha256_bytes(manifest.target.encode("ascii")),
        freshness_seconds=float(manifest.raw["thermal_acceptance"]["telemetry_freshness_seconds"]),
        previous_sample_id=previous_sample_id,
    )
    if document.get("state") not in {"pool_down", "idle"}:
        raise ProtocolError("LCD does not corroborate pool-down/idle")
    return str(document["sample_id"])


class LoadWorkers:
    def __init__(self, manifest: ValidatedManifest, journal: EvidenceJournal) -> None:
        self.manifest = manifest
        self.journal = journal
        self.stop = threading.Event()
        self.errors: list[str] = []
        self.counts: list[int] = []
        self.threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    def _argv(self) -> list[str]:
        load = self.manifest.raw["load"]
        ssh_timeout = self.manifest.timeouts["ssh"]
        target = self.manifest.target
        return [
            str(load["scp_executable"]),
            "-q",
            "-B",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={load['known_hosts_file']}",
            "-o",
            f"ConnectTimeout={max(1, int(ssh_timeout.connect))}",
            "-o",
            f"ServerAliveInterval={max(1, int(ssh_timeout.read))}",
            "-o",
            "ServerAliveCountMax=1",
            "-P",
            str(self.manifest.raw["target"]["ssh_port"]),
            "-i",
            str(load["ssh_identity_file"]),
            str(self.manifest.load_path),
            f"admin@{target}:{load['remote_tmpfs_path']}",
        ]

    def _worker(self, index: int) -> None:
        count = 0
        argv = self._argv()
        timeout = float(self.manifest.raw["load"]["per_transfer_total_timeout_seconds"])
        while not self.stop.is_set():
            try:
                result = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                with self._lock:
                    self.errors.append(f"load_worker_{index}_total_timeout")
                break
            except OSError:
                with self._lock:
                    self.errors.append(f"load_worker_{index}_os_error")
                break
            if result.returncode != 0:
                with self._lock:
                    self.errors.append(f"load_worker_{index}_exit_{result.returncode}")
                break
            count += 1
        with self._lock:
            self.counts.append(count)

    def start(self) -> None:
        concurrency = int(self.manifest.raw["load"]["concurrency"])
        for index in range(concurrency):
            thread = threading.Thread(target=self._worker, args=(index,), daemon=True)
            self.threads.append(thread)
            thread.start()
        self.journal.note(
            "bounded_load_started",
            payload_bytes=self.manifest.raw["load"]["payload_bytes"],
            payload_sha256=self.manifest.raw["load"]["payload_sha256"],
            direction=self.manifest.raw["load"]["direction"],
            concurrency=concurrency,
            argv_sha256=sha256_bytes("\x00".join(self._argv()).encode("utf-8")),
        )

    def request_stop(self) -> None:
        self.stop.set()

    def raise_if_failed(self) -> None:
        with self._lock:
            errors = list(self.errors)
        if errors:
            raise TransportError(";".join(sorted(errors)))

    def reap(self, *, require_completed_transfer: bool) -> None:
        join_bound = float(
            self.manifest.raw["load"]["per_transfer_total_timeout_seconds"]
        ) + 2
        for thread in self.threads:
            thread.join(join_bound)
            if thread.is_alive():
                self.errors.append("load_worker_join_timeout")
        self.raise_if_failed()
        if require_completed_transfer and (
            len(self.counts) != len(self.threads)
            or any(count < 1 for count in self.counts)
        ):
            raise TransportError("each load worker must complete at least one transfer")
        self.journal.note("bounded_load_finished", transfers=sum(self.counts))

    def finish(self) -> None:
        self.request_stop()
        self.reap(require_completed_transfer=True)


def _api_call(
    transport: Transport,
    journal: Optional[EvidenceJournal],
    command: str,
    parameter: Optional[str] = None,
    *,
    phase: str = "read_only",
) -> ParsedResponse:
    request = encode_request(command, parameter)
    event_id = (
        journal.api_intent(command, parameter, request, phase)
        if journal is not None
        else None
    )
    try:
        raw = transport.api(command, parameter)
    except BaseException as exc:
        if journal is not None and event_id is not None:
            journal.api_failed(event_id, exc)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        detail = str(exc) if isinstance(exc, TransportError) else type(exc).__name__
        raise ApiPlaneError(
            f"CGMiner {command} transport failed: {detail}"
        ) from exc
    if journal is not None and event_id is not None:
        try:
            journal.api_response_received(event_id, command, request, raw)
        except BaseException as exc:
            try:
                journal.api_failed(event_id, exc)
            except BaseException:
                if command in MUTATION_CODES:
                    journal.mutation_effect_unknown = True
            raise ApiPlaneError(
                f"CGMiner {command} response custody failed"
            ) from exc
    payload = {
        "pools": "POOLS",
        "summary": "SUMMARY",
        "stats": "STATS",
        "devs": "DEVS",
        "version": "VERSION",
        "lcd": "LCD",
    }.get(command)
    expected_code = READ_CODES.get(command, MUTATION_CODES.get(command))
    assert expected_code is not None
    try:
        response = decode_response(
            raw, expected_code, payload if command in READ_CODES else None
        )
        if command in MUTATION_CODES:
            verify_mutation_ack(command, parameter, response)
        try:
            connection_id = (
                journal.api_acknowledged(event_id)
                if journal is not None and event_id is not None
                else 0
            )
        except BaseException as exc:
            if journal is not None and command in MUTATION_CODES:
                journal.mutation_effect_unknown = True
            raise ApiPlaneError(
                f"CGMiner {command} validated acknowledgement custody failed"
            ) from exc
        return ParsedResponse(
            response.document,
            response.raw_sha256,
            response.raw_bytes,
            response.code,
            connection_id,
        )
    except ProtocolError as exc:
        if journal is not None and event_id is not None:
            journal.api_failed(event_id, exc)
        raise ApiPlaneError(
            f"CGMiner {command} response was ambiguous or invalid: {exc}"
        ) from exc


def capture_original_pool_state(
    transport: Transport, journal: Optional[EvidenceJournal]
) -> tuple[list[PoolState], int, ParsedResponse]:
    response = _api_call(transport, journal, "pools")
    pools = parse_pools(response)
    lcd = _api_call(transport, journal, "lcd")
    current = current_pool_id_from_lcd(response, lcd)
    return pools, current, response


def hash_off_transaction(
    transport: Transport,
    journal: Optional[EvidenceJournal],
    manifest: ValidatedManifest,
    expected_original: Optional[list[PoolState]] = None,
    expected_active: Optional[int] = None,
    expected_identity_hashes: Optional[Mapping[int, str]] = None,
) -> tuple[list[PoolState], int, int]:
    protocol = manifest.raw["cgminer_protocol"]
    deadline = time.monotonic() + float(protocol["hash_off_total_timeout_seconds"])

    def call(command: str, parameter: Optional[str] = None) -> ParsedResponse:
        if time.monotonic() + manifest.timeouts["api"].total > deadline:
            raise TransportError("hash-off whole-transaction deadline exhausted")
        result = _api_call(
            transport, journal, command, parameter, phase="hash_off"
        )
        if time.monotonic() > deadline:
            raise TransportError("hash-off whole-transaction deadline exceeded")
        return result

    before = call("pools")
    original = parse_pools(before)
    before_lcd = call("lcd")
    original_active = current_pool_id_from_lcd(before, before_lcd)
    if len(original) > int(protocol["max_original_pools"]):
        raise ProtocolError("original pool count exceeds admitted transaction maximum")
    if expected_original is not None:
        expected_semantic = [
            (item.pool_id, item.priority, item.enabled) for item in expected_original
        ]
        observed_semantic = [
            (item.pool_id, item.priority, item.enabled) for item in original
        ]
        if (
            observed_semantic != expected_semantic
            or original_active != expected_active
            or (
                expected_identity_hashes is not None
                and protected_pool_identity_hashes(before) != expected_identity_hashes
            )
        ):
            raise ProtocolError("pool state drifted between protected receipt and mutation")
    if journal is not None:
        config_reference = journal.pool_config_references.get("before")
        if config_reference is None:
            raise SoakError("protected pre-mutation config snapshot is missing")
        journal.set_pool_transaction_section(
            "pre_state",
            {
                "pools_connection_id": before.connection_id,
                "lcd_connection_id": before_lcd.connection_id,
                "config_reference": config_reference,
            },
        )
    before_entries = before.document["POOLS"]
    if any(entry.get("URL") == DEAD_POOL_URL for entry in before_entries):
        raise ProtocolError("the exact dead-pool URL already exists; ID would be ambiguous")
    mutation_ids: list[int] = []
    mutation_ids.append(call("addpool", DEAD_POOL_PARAMETER).connection_id)
    after_add = call("pools")
    after_states = parse_pools(after_add)
    old_ids = {item.pool_id for item in original}
    new_states = [item for item in after_states if item.pool_id not in old_ids]
    if len(new_states) != 1:
        raise ProtocolError("addpool did not create exactly one resolvable pool ID")
    dead_id = new_states[0].pool_id
    dead_entries = [
        entry for entry in after_add.document["POOLS"] if entry.get("POOL") == dead_id
    ]
    if (
        len(dead_entries) != 1
        or dead_entries[0].get("URL") != DEAD_POOL_URL
        or dead_entries[0].get("User") != "x"
    ):
        raise ProtocolError("added pool ID does not bind the exact dead-pool URL")
    if journal is not None:
        journal.mutation_state(
            "hash_off", "dead_pool_id_resolved", dead_pool_id=dead_id
        )
    mutation_ids.append(call("switchpool", str(dead_id)).connection_id)
    for state in original:
        if state.enabled:
            mutation_ids.append(
                call("disablepool", str(state.pool_id)).connection_id
            )
    verified_response = call("pools")
    verified = parse_pools(verified_response)
    enabled = [item.pool_id for item in verified if item.enabled]
    if enabled != [dead_id]:
        raise ProtocolError("dead pool is not the sole enabled pool")
    verified_lcd = call("lcd")
    if current_pool_id_from_lcd(verified_response, verified_lcd) != dead_id:
        raise ProtocolError("dead pool is not the selected current pool")
    if journal is not None:
        journal.set_pool_transaction_section(
            "hash_off",
            {
                "mutation_connection_ids": mutation_ids,
                "pools_connection_id": verified_response.connection_id,
                "lcd_connection_id": verified_lcd.connection_id,
                "summary_connection_ids": [],
            },
        )
    return original, original_active, dead_id


def restore_pool_transaction(
    transport: Transport,
    journal: Optional[EvidenceJournal],
    original: list[PoolState],
    original_active: int,
    dead_id: int,
    manifest: ValidatedManifest,
    expected_identity_hashes: Optional[Mapping[int, str]] = None,
) -> tuple[ParsedResponse, ParsedResponse, list[int]]:
    deadline = time.monotonic() + float(
        manifest.raw["cgminer_protocol"]["restore_total_timeout_seconds"]
    )

    def call(command: str, parameter: Optional[str] = None) -> ParsedResponse:
        if time.monotonic() + manifest.timeouts["api"].total > deadline:
            raise TransportError("restore whole-transaction deadline exhausted")
        result = _api_call(
            transport, journal, command, parameter, phase="restore"
        )
        if time.monotonic() > deadline:
            raise TransportError("restore whole-transaction deadline exceeded")
        return result

    mutation_ids: list[int] = []
    for state in original:
        if state.enabled:
            mutation_ids.append(
                call("enablepool", str(state.pool_id)).connection_id
            )
    mutation_ids.append(call("switchpool", str(original_active)).connection_id)
    mutation_ids.append(call("removepool", str(dead_id)).connection_id)
    priority_order = ",".join(
        str(item.pool_id) for item in sorted(original, key=lambda item: item.priority)
    )
    mutation_ids.append(call("poolpriority", priority_order).connection_id)
    restored_response = call("pools")
    restored = parse_pools(restored_response)
    expected = [(item.pool_id, item.priority, item.enabled) for item in original]
    observed = [(item.pool_id, item.priority, item.enabled) for item in restored]
    if observed != expected:
        raise ProtocolError("restored pool IDs/enabled/priorities differ from receipt")
    if (
        expected_identity_hashes is not None
        and protected_pool_identity_hashes(restored_response)
        != expected_identity_hashes
    ):
        raise ProtocolError("restored pool stable identities differ from receipt")
    restored_lcd = call("lcd")
    if current_pool_id_from_lcd(restored_response, restored_lcd) != original_active:
        raise ProtocolError("restored active pool differs from protected receipt")
    return restored_response, restored_lcd, mutation_ids


def verify_basic_planes(
    transport: Transport,
    journal: Optional[EvidenceJournal],
    manifest: ValidatedManifest,
) -> None:
    guard = transport.guard_receipt()
    if journal is not None:
        journal.record_raw("priority-guard", b"fixed-read-only-guard-receipt", guard)
    verify_guard_receipt(guard)
    priority = transport.priority_state()
    if journal is not None:
        journal.record_raw("independent-priority-state", b"fixed-read-only-proc", priority)
    verify_priority_state(priority)
    available = transport.tmpfs_available_bytes()
    required = (
        int(manifest.raw["load"]["payload_bytes"])
        * int(manifest.raw["load"]["concurrency"])
        * 2
    )
    if available < required:
        raise ProtocolError("remote /tmp tmpfs capacity is below the bounded load reserve")
    transport.ssh_true()
    http = transport.http_get_root()
    if journal is not None:
        journal.record_raw("http-root", b"fixed-GET-root", http)
    verify_http_response(http)
    version = _api_call(transport, journal, "version")
    verify_version_identity(
        version, manifest.raw["target"]["expected_version_fields"]
    )
    for command in ("summary", "stats", "devs"):
        _api_call(transport, journal, command)


def render_plan(manifest: ValidatedManifest) -> dict[str, Any]:
    load = manifest.raw["load"]
    requests = {
        command: {
            "bytes": len(encode_request(command)),
            "sha256": sha256_bytes(encode_request(command)),
        }
        for command in ("version", "summary", "stats", "devs", "pools")
    }
    addpool = encode_request("addpool", DEAD_POOL_PARAMETER)
    requests["addpool_exact"] = {"bytes": len(addpool), "sha256": sha256_bytes(addpool)}
    return {
        "schema": "dcent.nano3.w1-attended-soak-offline-plan.v1",
        "manifest_sha256": manifest.sha256,
        "target_ipv4_sha256": sha256_bytes(manifest.target.encode("ascii")),
        "payload": {
            "bytes": load["payload_bytes"],
            "sha256": load["payload_sha256"],
            "direction": load["direction"],
            "concurrency": load["concurrency"],
            "duration_seconds": load["duration_seconds"],
        },
        "requests": requests,
        "timeouts_seconds": manifest.raw["timeouts_seconds"],
        "probe_cadence_seconds": manifest.cadence,
        "pool_transaction": [
            "protected pools snapshot",
            "add exact dead pool",
            "fresh pools query resolves exactly one new ID",
            "switch resolved ID",
            "disable every originally enabled pool",
            "verify dead pool sole enabled",
            "120-second multi-signal proof",
            "enable original enabled set",
            "switch protected original active ID",
            "remove dead ID",
            "restore exact priority order",
            "verify IDs/enabled/priorities/active",
        ],
        "abort_boundary": (
            "first missed bound is FAIL; attempt the full pool transaction only "
            "while 4028 remains responsive; any failed/partial/ambiguous response "
            "means MANUAL AC DISCONNECT NOW; AC also stops fan power"
        ),
        "phase4_included": False,
        "authority": "offline compilation only; grants no target contact or mutation",
    }


def consume_session_marker(manifest: ValidatedManifest) -> None:
    """Atomically consume one live authorization without contacting the target."""
    marker = Path(str(manifest.raw["session"]["consumption_marker_path"]))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(marker, flags, 0o600)
    except FileExistsError as exc:
        raise ManifestError("approved session has already been consumed") from exc
    except OSError as exc:
        raise ManifestError("cannot atomically consume approved session") from exc
    receipt = canonical_json(
        {
            "schema": "dcent.nano3.w1-session-consumption.v1",
            "session_id": manifest.raw["session"]["id"],
            "manifest_sha256": manifest.sha256,
            "consumed_at_utc": utc_now(),
            "authority": "one-shot consumption only; grants no future action",
        }
    )
    try:
        os.write(descriptor, receipt)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def revalidate_approved_local_inputs(manifest: ValidatedManifest) -> None:
    """Rebind every approved local input immediately before live use."""
    load = manifest.raw["load"]
    validate_pinned_file(
        Path(str(load["payload_path"])),
        load["payload_sha256"],
        MAX_LOAD_PAYLOAD_BYTES,
        "load.payload_path",
        expected_size=int(load["payload_bytes"]),
    )
    for name in ("scp_executable", "ssh_executable", "ssh_identity_file"):
        maximum = (
            MAX_EXECUTABLE_BYTES
            if name in {"scp_executable", "ssh_executable"}
            else MAX_KEY_OR_HOSTS_BYTES
        )
        validate_pinned_file(
            Path(str(load[name])),
            load[f"{name}_sha256"],
            maximum,
            f"load.{name}",
        )
    validate_pinned_file(
        Path(str(load["known_hosts_file"])),
        load["known_hosts_sha256"],
        MAX_KEY_OR_HOSTS_BYTES,
        "load.known_hosts_file",
    )
    thermal = manifest.raw["thermal_acceptance"]
    validate_pinned_file(
        Path(str(thermal["contract_receipt_path"])),
        thermal["contract_receipt_sha256"],
        MAX_CONTRACT_RECEIPT_BYTES,
        "thermal contract receipt",
    )


def revalidate_load_payload(manifest: ValidatedManifest) -> None:
    load = manifest.raw["load"]
    validate_pinned_file(
        Path(str(load["payload_path"])),
        load["payload_sha256"],
        MAX_LOAD_PAYLOAD_BYTES,
        "load.payload_path",
        expected_size=int(load["payload_bytes"]),
    )


def run_fixture(manifest: ValidatedManifest, fixture_path: Path) -> None:
    fixture = load_json_object(fixture_path, "fixture")
    transport = FixtureTransport(fixture)
    verify_basic_planes(transport, None, manifest)
    original, active, dead = hash_off_transaction(transport, None, manifest)
    restore_pool_transaction(transport, None, original, active, dead, manifest)
    transport.assert_consumed()


def stop_load_then_safety_action_then_reap(
    load_workers: Optional[LoadWorkers], safety_action: Any
) -> Optional[BaseException]:
    """Enforce abort ordering: stop request, safety action, then bounded reap."""
    if load_workers is not None:
        load_workers.request_stop()
    safety_action()
    if load_workers is None:
        return None
    try:
        load_workers.reap(require_completed_transfer=False)
    except BaseException as exc:  # safety action has already happened
        return exc
    return None


def execute_live(manifest: ValidatedManifest, evidence_dir: Path) -> int:
    """Execute the exact attended W1 phases authorized by the manifest."""
    revalidate_approved_local_inputs(manifest)
    journal = EvidenceJournal(evidence_dir, manifest)
    transport = SystemTransport(manifest)
    load_workers: Optional[LoadWorkers] = None
    mutation_phase = "none"
    safe_to_try_hash_off = False
    wall_sample_id: Optional[str] = None
    thermal_previous: Optional[tuple[float, float, float]] = None
    config_before: Optional[str] = None
    config_before_bytes: Optional[bytes] = None
    original_preload: Optional[list[PoolState]] = None
    original_active_preload: Optional[int] = None
    original_identity_hashes: Optional[dict[int, str]] = None
    old_signal_handlers: dict[int, Any] = {}

    def signal_abort(signum: int, _frame: Any) -> None:
        raise SafetyAbort(f"attended session interrupted by signal {signum}")

    for signal_name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            old_signal_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, signal_abort)
    try:
        verify_basic_planes(transport, journal, manifest)
        config_before = transport.pool_config_digest()
        config_before_bytes = transport.pool_config_bytes()
        if sha256_bytes(config_before_bytes) != config_before:
            raise ProtocolError("protected pool config bytes/digest disagree")
        journal.protect_pool_config("before", config_before_bytes)
        original_preload, original_active_preload, pools_response = (
            capture_original_pool_state(transport, journal)
        )
        if len(original_preload) > int(
            manifest.raw["cgminer_protocol"]["max_original_pools"]
        ):
            raise ProtocolError(
                "initial pool count exceeds the admitted transaction maximum"
            )
        original_identity_hashes = protected_pool_identity_hashes(pools_response)
        safe_to_try_hash_off = True
        journal.write_protected_json(
            "original-pool-state-receipt.json",
            {
                "captured_at_utc": utc_now(),
                "config_sha256": config_before,
                "raw_pools_response_sha256": pools_response.raw_sha256,
                "pool_state": [
                    {
                        "pool_id": item.pool_id,
                        "priority": item.priority,
                        "enabled": item.enabled,
                        "stratum_active": item.stratum_active,
                    }
                    for item in original_preload
                ],
                "active_pool_id": original_active_preload,
                "pool_url_user_identity_sha256_by_id": {
                    str(key): value
                    for key, value in sorted(original_identity_hashes.items())
                },
                "credentials_present": False,
                "raw_credential_bearing_response_location": "protected/",
            },
        )

        wall_watts, wall_sample_id = read_wall_watts(manifest, wall_sample_id)
        require_envelope(
            wall_watts,
            require_mapping(
                manifest.raw["wall_power_acceptance"]["hashing_watts"],
                "hashing_watts",
            ),
            "baseline hashing wall power",
        )
        baseline_summary = _api_call(transport, journal, "summary")
        load_baseline = load_summary_values(manifest, baseline_summary)
        stats = _api_call(transport, journal, "stats")
        devs = _api_call(transport, journal, "devs")
        thermal_previous = verify_thermal_sample(
            manifest, stats, devs, thermal_previous
        )

        revalidate_approved_local_inputs(manifest)
        load_workers = LoadWorkers(manifest, journal)
        load_workers.start()
        load_duration = float(manifest.raw["load"]["duration_seconds"])
        load_started = time.monotonic()
        next_probe = load_started
        probe_index = 0
        last_load_values = load_baseline
        while True:
            now_mono = time.monotonic()
            if now_mono >= load_started + load_duration:
                break
            if now_mono < next_probe:
                load_workers.raise_if_failed()
                time.sleep(min(next_probe - now_mono, 0.25))
                continue
            probe_started = time.monotonic()
            load_workers.raise_if_failed()
            transport.ssh_true()
            http = transport.http_get_root()
            verify_http_response(http)
            journal.record_raw("http-root-load-probe", b"fixed-GET-root", http)
            summary = _api_call(transport, journal, "summary")
            stats = _api_call(transport, journal, "stats")
            devs = _api_call(transport, journal, "devs")
            lcd = _api_call(transport, journal, "lcd")
            thermal_previous = verify_thermal_sample(
                manifest, stats, devs, thermal_previous
            )
            wall_watts, wall_sample_id = read_wall_watts(
                manifest, wall_sample_id
            )
            require_envelope(
                wall_watts,
                require_mapping(
                    manifest.raw["wall_power_acceptance"]["hashing_watts"],
                    "hashing_watts",
                ),
                "load-soak wall power",
            )
            current_values = load_summary_values(manifest, summary)
            verify_load_progress(
                manifest, load_baseline, current_values, final=False
            )
            if current_pool_id_from_lcd(pools_response, lcd) != original_active_preload:
                raise ProtocolError("original current pool changed during bounded load")
            last_load_values = current_values
            elapsed = time.monotonic() - probe_started
            if elapsed > manifest.cadence:
                raise TransportError("serialized probe set exceeded cadence")
            journal.note(
                "serialized_load_probe_pass",
                index=probe_index,
                duration_ms=int(elapsed * 1000),
                short_window_mhs=current_values[0],
                accepted=current_values[1],
                rejected=current_values[2],
                hardware_errors=current_values[3],
                wall_watts=wall_watts,
            )
            probe_index += 1
            next_probe += manifest.cadence
        load_workers.raise_if_failed()
        if probe_index < 2:
            raise ProtocolError("bounded load did not complete two serialized probes")
        verify_load_progress(manifest, load_baseline, last_load_values, final=True)
        load_workers.finish()
        load_workers = None
        revalidate_load_payload(manifest)

        mutation_phase = "hashoff"
        config_at_mutation = transport.pool_config_bytes()
        if config_before_bytes is None or config_at_mutation != config_before_bytes:
            raise ProtocolError(
                "protected pool config drifted before mutation transaction"
            )
        journal.protect_pool_config("before", config_at_mutation)
        original, original_active, dead_id = hash_off_transaction(
            transport,
            journal,
            manifest,
            expected_original=original_preload,
            expected_active=original_active_preload,
            expected_identity_hashes=original_identity_hashes,
        )
        mutation_phase = "hashoff_verified"
        proof = require_mapping(manifest.raw["hash_off_proof"], "hash_off_proof")
        first_summary = _api_call(transport, journal, "summary")
        zero_summary_connection_ids = [first_summary.connection_id]
        accepted_start = resolve_json_pointer(
            first_summary.document, str(proof["accepted_pointer"])
        )
        if isinstance(accepted_start, bool) or not isinstance(accepted_start, int):
            raise ProtocolError("Accepted counter is not an integer")
        proof_started = time.monotonic()
        proof_deadline = proof_started + float(proof["proof_seconds"])
        proof_index = 0
        final_mhs: Optional[float] = None
        while True:
            sample_started = time.monotonic()
            summary = _api_call(transport, journal, "summary")
            zero_summary_connection_ids.append(summary.connection_id)
            stats = _api_call(transport, journal, "stats")
            devs = _api_call(transport, journal, "devs")
            thermal_previous = verify_thermal_sample(
                manifest, stats, devs, thermal_previous
            )
            accepted = resolve_json_pointer(
                summary.document, str(proof["accepted_pointer"])
            )
            mhs = resolve_json_pointer(
                summary.document, str(proof["short_window_pointer"])
            )
            if isinstance(accepted, bool) or not isinstance(accepted, int):
                raise ProtocolError("Accepted counter is not an integer")
            checked_mhs = finite_runtime_number(mhs, "hash-off MHS 5s")
            if accepted != accepted_start:
                raise ProtocolError("Accepted counter advanced during hash-off proof")
            final_mhs = checked_mhs
            wall_watts, wall_sample_id, wall_document = read_wall_power_proof(
                manifest, wall_sample_id
            )
            proof_elapsed = time.monotonic() - proof_started
            if proof_elapsed >= float(proof["idle_settle_seconds"]):
                require_envelope(
                    wall_watts,
                    require_mapping(
                        manifest.raw["wall_power_acceptance"]["hash_off_watts"],
                        "hash_off_watts",
                    ),
                    "hash-off wall power",
                )
                journal.set_pool_transaction_section(
                    "idle_power_reference",
                    journal.protect_idle_power_proof(wall_document),
                )
            journal.note(
                "hash_off_proof_sample",
                index=proof_index,
                elapsed_ms=int(proof_elapsed * 1000),
                short_window_mhs=final_mhs,
                accepted=accepted,
                wall_watts=wall_watts,
            )
            proof_index += 1
            if time.monotonic() >= proof_deadline:
                break
            next_sample = sample_started + float(proof["sample_interval_seconds"])
            remaining = next_sample - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
        terminal_summary = _api_call(
            transport, journal, "summary", phase="hash_off_proof"
        )
        zero_summary_connection_ids.append(terminal_summary.connection_id)
        terminal_accepted = resolve_json_pointer(
            terminal_summary.document, str(proof["accepted_pointer"])
        )
        if (
            isinstance(terminal_accepted, bool)
            or not isinstance(terminal_accepted, int)
            or terminal_accepted != accepted_start
        ):
            raise ProtocolError(
                "terminal Accepted counter invalid/advanced during hash-off proof"
            )
        final_mhs = finite_runtime_number(
            resolve_json_pointer(
                terminal_summary.document, str(proof["short_window_pointer"])
            ),
            "terminal hash-off MHS 5s",
        )
        if final_mhs is None or final_mhs > float(proof["short_window_mhs_max"]):
            raise ProtocolError("MHS 5s did not reach the approved idle threshold")
        hash_off_reference = journal.pool_transaction.get("hash_off")
        if not isinstance(hash_off_reference, dict):
            raise SoakError("hash-off transaction reference is missing")
        hash_off_reference["summary_connection_ids"] = zero_summary_connection_ids
        journal.set_pool_transaction_section("hash_off", hash_off_reference)
        if "idle_power_reference" not in journal.pool_transaction:
            raise SoakError("settled idle-power proof reference is missing")
        verify_lcd_observation(manifest, None)

        mutation_phase = "restore"
        restored_start_pools, restored_start_lcd, restore_mutation_ids = (
            restore_pool_transaction(
            transport,
            journal,
            original,
            original_active,
            dead_id,
            manifest,
            expected_identity_hashes=original_identity_hashes,
            )
        )
        mutation_phase = "restored"
        restored_wall, wall_sample_id = read_wall_watts(manifest, wall_sample_id)
        require_envelope(
            restored_wall,
            require_mapping(
                manifest.raw["wall_power_acceptance"]["hashing_watts"],
                "hashing_watts",
            ),
            "post-restore hashing wall power",
        )
        restored_stats = _api_call(transport, journal, "stats")
        restored_devs = _api_call(transport, journal, "devs")
        thermal_previous = verify_thermal_sample(
            manifest, restored_stats, restored_devs, thermal_previous
        )
        config_after = transport.pool_config_digest()
        config_after_bytes = transport.pool_config_bytes()
        if (
            config_after != config_before
            or config_before_bytes is None
            or config_after_bytes != config_before_bytes
            or sha256_bytes(config_after_bytes) != config_after
        ):
            raise ProtocolError("protected pool config digest changed across restore")
        config_after_reference = journal.protect_pool_config(
            "after", config_after_bytes
        )
        restored_end_pools = _api_call(
            transport, journal, "pools", phase="post_restore_proof"
        )
        restored_end_lcd = _api_call(
            transport, journal, "lcd", phase="post_restore_proof"
        )
        if parse_pools(restored_end_pools) != parse_pools(restored_start_pools):
            raise ProtocolError("post-restore pool semantic state changed")
        if current_pool_id_from_lcd(
            restored_end_pools, restored_end_lcd
        ) != current_pool_id_from_lcd(restored_start_pools, restored_start_lcd):
            raise ProtocolError("post-restore intended pool selection changed")
        def accepted_for(response: ParsedResponse, pool_id: int) -> int:
            matches = [
                entry.get("Accepted")
                for entry in response.document["POOLS"]
                if entry.get("POOL") == pool_id
            ]
            if (
                len(matches) != 1
                or isinstance(matches[0], bool)
                or not isinstance(matches[0], int)
                or matches[0] < 0
            ):
                raise ProtocolError(
                    "intended pool Accepted counter is missing or invalid"
                )
            return matches[0]

        accepted_delta = accepted_for(
            restored_end_pools, original_active
        ) - accepted_for(restored_start_pools, original_active)
        if accepted_delta < int(
            manifest.raw["load_acceptance"]["accepted_min_delta"]
        ):
            raise ProtocolError(
                "post-restore intended pool Accepted counter did not advance"
            )
        journal.set_pool_transaction_section(
            "restore",
            {
                "mutation_connection_ids": restore_mutation_ids,
                "pools_start_connection_id": restored_start_pools.connection_id,
                "lcd_start_connection_id": restored_start_lcd.connection_id,
                "pools_connection_id": restored_end_pools.connection_id,
                "lcd_connection_id": restored_end_lcd.connection_id,
                "config_reference": config_after_reference,
            },
        )
        journal.write_protected_json(
            "restored-pool-state-receipt.json",
            {
                "captured_at_utc": utc_now(),
                "config_sha256": config_after,
                "restored_pool_ids_enabled_priority_active_verified": True,
                "credentials_present": False,
            },
        )
        mutation_phase = "complete"
        journal.finish("PASS", "PHASES_0_TO_3_RESTORED")
        print(
            f"NANO3_W1_ATTENDED_PASS evidence_dir={evidence_dir.resolve()} "
            "phase4_executed=0 future_authority_granted=0"
        )
        return 0
    except BaseException as exc:
        caught_failure = exc
        outcome = "FAIL_MANUAL_AC_REQUIRED"
        reason_code = "POST_CONTACT_FAILURE_MANUAL_AC"
        hash_off_failure: Optional[BaseException] = None

        def safety_action() -> None:
            nonlocal outcome, reason_code, hash_off_failure, mutation_phase
            manual_required = (
                isinstance(caught_failure, ApiPlaneError)
                or mutation_phase in {"hashoff", "restore", "restored"}
                or not safe_to_try_hash_off
            )
            if mutation_phase == "hashoff_verified" and not isinstance(
                caught_failure, ApiPlaneError
            ):
                outcome = "FAIL_HASH_OFF_ACKNOWLEDGED"
                reason_code = "FAILURE_LEFT_HASH_OFF_ACKNOWLEDGED"
                journal.note(
                    "abort_hash_off_acknowledged_not_restored",
                    stock_fan_owner_expected_to_remain_alive=True,
                    exact_restoration_deferred_to_operator_recovery=True,
                )
                print(
                    "NANO3_W1_FAIL_HASH_OFF_ACKNOWLEDGED: leave the unit attended; "
                    "do not restore through an unsafe plane. Continue external "
                    "thermal and wall observation.",
                    file=sys.stderr,
                    flush=True,
                )
                return
            if not manual_required:
                if original_preload is None or original_active_preload is None:
                    manual_required = True
                else:
                    try:
                        hash_off_transaction(
                            transport,
                            journal,
                            manifest,
                            expected_original=original_preload,
                            expected_active=original_active_preload,
                            expected_identity_hashes=original_identity_hashes,
                        )
                        mutation_phase = "hashoff_verified"
                        outcome = "FAIL_HASH_OFF_ACKNOWLEDGED"
                        reason_code = "ABORT_HASH_OFF_ACKNOWLEDGED"
                        journal.note(
                            "abort_hash_off_acknowledged_not_restored",
                            stock_fan_owner_expected_to_remain_alive=True,
                            exact_restoration_deferred_to_operator_recovery=True,
                        )
                        print(
                            "NANO3_W1_FAIL_HASH_OFF_ACKNOWLEDGED: leave the unit "
                            "attended; do not restore through an unsafe plane. "
                            "Continue external thermal and wall observation.",
                            file=sys.stderr,
                            flush=True,
                        )
                        return
                    except BaseException as abort_exc:
                        hash_off_failure = abort_exc
                        manual_required = True
            if manual_required:
                journal.note(
                    "manual_ac_disconnect_required",
                    external_post_cut_thermal_observation_required=True,
                    post_cut_observation_seconds=manifest.raw["attended_safety"][
                        "post_cut_observation_seconds"
                    ],
                )
                print(
                    "MANUAL_AC_DISCONNECT_NOW: complete pool hash-off is not fully "
                    "acknowledged. AC also stops fan power; continue external "
                    "thermal observation for the approved interval.",
                    file=sys.stderr,
                    flush=True,
                )

        reap_failure = stop_load_then_safety_action_then_reap(
            load_workers, safety_action
        )
        protected_extra: dict[str, Any] = {
            "mutation_phase": mutation_phase,
            "hash_off_failure_type": (
                type(hash_off_failure).__name__ if hash_off_failure else None
            ),
            "hash_off_failure_detail": (
                str(hash_off_failure) if hash_off_failure else None
            ),
            "load_reap_failure_type": (
                type(reap_failure).__name__ if reap_failure else None
            ),
            "load_reap_failure_detail": str(reap_failure) if reap_failure else None,
        }
        try:
            journal.write_failure_detail(caught_failure, **protected_extra)
        except BaseException:
            journal.note("protected_failure_detail_write_failed")
        if reap_failure is not None:
            journal.note("load_reap_failed_after_safety_action")
        journal.finish(outcome, reason_code)
        return 1
    finally:
        for signum, old_handler in old_signal_handlers.items():
            signal.signal(signum, old_handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    validate = subparsers.add_parser("validate", help="offline manifest validation")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--fixture-only", action="store_true")

    plan = subparsers.add_parser("plan", help="offline exact plan compiler")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--fixture-only", action="store_true")

    fixture = subparsers.add_parser("fixture", help="offline fixture state-machine run")
    fixture.add_argument("--manifest", type=Path, required=True)
    fixture.add_argument("--fixture", type=Path, required=True)

    run = subparsers.add_parser("run", help="explicitly armed live preflight (fail-closed)")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--manifest-sha256", required=True)
    run.add_argument("--authorization-reference", required=True)
    run.add_argument("--evidence-dir", type=Path, required=True)
    run.add_argument("--execute-approved-session", action="store_true")
    run.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        if args.command in {"validate", "plan"}:
            manifest = validate_manifest(args.manifest, live=not args.fixture_only)
            if args.command == "validate":
                print(
                    f"NANO3_W1_MANIFEST_OK sha256={manifest.sha256} "
                    "offline_only=1 authority_granted=0"
                )
            else:
                print(json.dumps(render_plan(manifest), indent=2, sort_keys=True))
            return 0
        if args.command == "fixture":
            manifest = validate_manifest(args.manifest, live=False)
            run_fixture(manifest, args.fixture)
            print("NANO3_W1_FIXTURE_PASS network_opened=0 mutation_authority=0")
            return 0

        # Cheap command-line gates precede manifest loading.  This preserves a
        # fail-closed, no-contact refusal even when the deliberately blocked
        # stock telemetry contract cannot validate for live use.
        if not args.dry_run and not args.execute_approved_session:
            raise ManifestError("live run requires the literal --execute-approved-session switch")
        if (
            not args.evidence_dir.is_absolute()
            or args.evidence_dir.exists()
            or not args.evidence_dir.parent.is_dir()
        ):
            raise ManifestError(
                "--evidence-dir must be an absolute new path under an existing directory"
            )
        evidence_parent = args.evidence_dir.parent.lstat()
        if stat.S_ISLNK(evidence_parent.st_mode) or not stat.S_ISDIR(
            evidence_parent.st_mode
        ):
            raise ManifestError("evidence directory parent must be a real directory")

        manifest = validate_manifest(args.manifest, live=True)
        if args.target != manifest.target:
            raise ManifestError("--target does not exactly match the approved manifest")
        if args.manifest_sha256 != manifest.sha256:
            raise ManifestError("--manifest-sha256 does not bind the exact manifest bytes")
        if args.authorization_reference != manifest.raw["session"]["authorization_reference"]:
            raise ManifestError("authorization reference mismatch")
        if args.dry_run:
            print(json.dumps(render_plan(manifest), indent=2, sort_keys=True))
            return 0
        consume_session_marker(manifest)
        return execute_live(manifest, args.evidence_dir)
    except (OSError, SoakError) as exc:
        print(f"NANO3_W1_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
