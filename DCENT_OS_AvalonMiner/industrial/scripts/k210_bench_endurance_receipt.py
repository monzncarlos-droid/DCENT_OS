#!/usr/bin/env python3
"""Create and verify signed A1246 bench/endurance evidence bundles.

This tool is host-only. It has no miner, network, serial, USB, GPIO, power,
cooling, flash, install, process-control, pool-control, or fault-injection
transport. It snapshots evidence from separately authorized work that already
occurred. A verified bundle records past observations only and grants no
authority for future contact, installation, hashing, testing, or release.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 receipt primitive: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capture = _load_module("k210_capture_receipt.py", "k210_capture_receipt")
route_rollback = _load_module(
    "k210_route_rollback_receipt.py", "k210_route_rollback_receipt"
)
route_replacement = route_rollback.route_replacement
fixture = capture.fixture
boot = route_rollback.boot
recovery = route_rollback.recovery
discovery = route_rollback.discovery

SCHEMA_VERSION = 1
SCOPE = discovery.SCOPE
DESCRIPTOR_KIND = "dcent_k210_bench_endurance_descriptor"
RECEIPT_KIND = "dcent_k210_bench_endurance_receipt"
ROUTE_REPLACEMENT_RECEIPT_KIND = route_replacement.RECEIPT_KIND
ROUTE_REPLACEMENT_SCHEMA_VERSION = route_replacement.SCHEMA_VERSION
ROUTE_ROLLBACK_RECEIPT_KIND = route_rollback.RECEIPT_KIND
ROUTE_ROLLBACK_SCHEMA_VERSION = route_rollback.SCHEMA_VERSION
ROUTE_ROLLBACK_DISPOSITION = route_rollback.DISPOSITION
ROUTES = route_replacement.ROUTES

QUALIFICATION_FIRST_LIGHT = "first_light"
QUALIFICATION_BENCH = "bounded_bench_mining"
QUALIFICATION_ENDURANCE = "fault_endurance"
QUALIFICATION_CLASSES = {
    QUALIFICATION_FIRST_LIGHT,
    QUALIFICATION_BENCH,
    QUALIFICATION_ENDURANCE,
}
OUTCOMES = {"failed", "passed", "stopped"}

DISPOSITION = "past_bench_endurance_evidence_only_no_future_authority"
RECEIPT_NAME = "receipt.json"
OPERATOR_SIGNATURE_NAME = "operator.sig"
WITNESS_SIGNATURE_NAME = "witness.sig"
EVIDENCE_DIRECTORY = "evidence"
SIGNING_CONTRACTS = {
    QUALIFICATION_FIRST_LIGHT: {
        "operator": (
            "k210_first_light_operator",
            "dcent-k210-first-light-operator-v1",
        ),
        "protocol_reviewer": (
            "k210_first_light_protocol_reviewer",
            "dcent-k210-first-light-protocol-reviewer-v1",
        ),
        "safety_reviewer": (
            "k210_first_light_ee_safety_reviewer",
            "dcent-k210-first-light-ee-safety-reviewer-v1",
        ),
    },
    QUALIFICATION_BENCH: {
        "operator": (
            "k210_bench_mining_operator",
            "dcent-k210-bench-mining-operator-v1",
        ),
        "witness": (
            "k210_bench_mining_witness",
            "dcent-k210-bench-mining-witness-v1",
        ),
    },
    QUALIFICATION_ENDURANCE: {
        "operator": (
            "k210_endurance_operator",
            "dcent-k210-endurance-operator-v1",
        ),
        "witness": (
            "k210_endurance_witness",
            "dcent-k210-endurance-witness-v1",
        ),
    },
}
SIGNATURE_NAME_BY_ROLE = {
    "operator": OPERATOR_SIGNATURE_NAME,
    "protocol_reviewer": "protocol_reviewer.sig",
    "safety_reviewer": "safety_reviewer.sig",
    "witness": WITNESS_SIGNATURE_NAME,
}
SIGNATURE_ALGORITHM = discovery.SIGNATURE_ALGORITHM

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024
MIN_BENCH_DURATION_SECONDS = 60
MIN_ENDURANCE_DURATION_SECONDS = 6 * 60 * 60

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

PREDECESSOR_KINDS = {
    "boot_policy_receipt_copy",
    "capture_receipt_copy",
    "discovery_receipt_copy",
    "fixture_receipt_copy",
    "recovery_receipt_copy",
    "route_replacement_receipt_copy",
    "route_rollback_receipt_copy",
}
COMMON_SEMANTIC_KINDS = {
    "authorization_record",
    "cooling_telemetry_record",
    "cutoff_telemetry_record",
    "pool_session_record",
    "runtime_telemetry_record",
    "safety_record",
    "session_log",
    "share_accounting_record",
}
FIRST_LIGHT_ONLY_KINDS = {"first_light_record"}
BENCH_ONLY_KINDS = {"bounded_mining_record", "prior_first_light_receipt_copy"}
ENDURANCE_ONLY_KINDS = {
    "endurance_record",
    "fault_campaign_record",
    "prior_bench_receipt_copy",
}
ALL_EVIDENCE_KINDS = (
    PREDECESSOR_KINDS
    | COMMON_SEMANTIC_KINDS
    | FIRST_LIGHT_ONLY_KINDS
    | BENCH_ONLY_KINDS
    | ENDURANCE_ONLY_KINDS
)

MEDIA_TYPE_BY_KIND = {kind: "application/json" for kind in ALL_EVIDENCE_KINDS}
METHOD_BY_KIND = {
    **{kind: "offline_predecessor" for kind in PREDECESSOR_KINDS},
    "prior_bench_receipt_copy": "offline_predecessor",
    **{kind: "authorized_bench_session" for kind in COMMON_SEMANTIC_KINDS},
    **{kind: "authorized_first_light_session" for kind in FIRST_LIGHT_ONLY_KINDS},
    **{kind: "authorized_bench_session" for kind in BENCH_ONLY_KINDS},
    **{kind: "authorized_endurance_session" for kind in ENDURANCE_ONLY_KINDS},
}
METHOD_BY_KIND["prior_first_light_receipt_copy"] = "offline_predecessor"
METHOD_BY_KIND["prior_bench_receipt_copy"] = "offline_predecessor"
REDACTION_BY_KIND = {kind: "none" for kind in ALL_EVIDENCE_KINDS}
REDACTION_BY_KIND["pool_session_record"] = "credentials_removed"

FIRST_LIGHT_ACTIONS = {
    "boot_replacement",
    "connect_operator_controlled_pool",
    "enable_cooling",
    "first_light",
    "hash_enable_after_safety_prerequisites",
    "restore_stock_identity",
    "rollback_to_stock",
    "staged_safe_idle",
    "verify_independent_cutoff",
    "verify_watchdog_and_sensors",
}
BENCH_ACTIONS = {
    "boot_replacement",
    "bounded_mining",
    "connect_operator_controlled_pool",
    "controlled_reboot",
    "enable_cooling",
    "restore_stock_identity",
    "rollback_to_stock",
    "verify_independent_cutoff",
}
REQUIRED_FAULT_TYPES = {
    "cooling_loss",
    "network_disconnect",
    "overtemperature",
    "pool_disconnect",
    "psu_fault",
    "runtime_stall_watchdog",
    "sensor_stale",
}
ENDURANCE_ACTIONS = {
    "boot_replacement",
    "bounded_mining",
    "connect_operator_controlled_pool",
    "controlled_reboot",
    "enable_cooling",
    "restore_stock_identity",
    "rollback_to_stock",
    "run_endurance",
    "verify_independent_cutoff",
} | {f"inject_{fault}" for fault in REQUIRED_FAULT_TYPES}
ACTION_SEQUENCES = {
    QUALIFICATION_FIRST_LIGHT: (
        "boot_replacement",
        "staged_safe_idle",
        "enable_cooling",
        "verify_independent_cutoff",
        "verify_watchdog_and_sensors",
        "connect_operator_controlled_pool",
        "hash_enable_after_safety_prerequisites",
        "first_light",
        "rollback_to_stock",
        "restore_stock_identity",
    ),
    QUALIFICATION_BENCH: (
        "boot_replacement",
        "enable_cooling",
        "verify_independent_cutoff",
        "connect_operator_controlled_pool",
        "bounded_mining",
        "controlled_reboot",
        "rollback_to_stock",
        "restore_stock_identity",
    ),
    QUALIFICATION_ENDURANCE: (
        "boot_replacement",
        "enable_cooling",
        "verify_independent_cutoff",
        "connect_operator_controlled_pool",
        "bounded_mining",
        *tuple(f"inject_{fault}" for fault in sorted(REQUIRED_FAULT_TYPES)),
        "run_endurance",
        "controlled_reboot",
        "rollback_to_stock",
        "restore_stock_identity",
    ),
}

ACTIONS_PERFORMED_KEYS = {
    "bounded_mining_executed",
    "controlled_reboot_executed",
    "cooling_enabled",
    "cutoff_tested",
    "endurance_executed",
    "fault_injection_executed",
    "first_light_executed",
    "firmware_or_configuration_outside_authorization_changed",
    "pool_credentials_included",
    "production_release_performed",
    "replacement_booted",
    "rollback_executed",
    "stock_restored_at_end",
    "unbounded_mining_executed",
}
PROHIBITED_ACTIONS = {
    "firmware_or_configuration_outside_authorization_changed",
    "pool_credentials_included",
    "production_release_performed",
    "unbounded_mining_executed",
}
POSITIVE_ACTIONS = {
    QUALIFICATION_FIRST_LIGHT: {
        "bounded_mining_executed": False,
        "controlled_reboot_executed": False,
        "cooling_enabled": True,
        "cutoff_tested": True,
        "endurance_executed": False,
        "fault_injection_executed": False,
        "first_light_executed": True,
        "firmware_or_configuration_outside_authorization_changed": False,
        "pool_credentials_included": False,
        "production_release_performed": False,
        "replacement_booted": True,
        "rollback_executed": True,
        "stock_restored_at_end": True,
        "unbounded_mining_executed": False,
    },
    QUALIFICATION_BENCH: {
        "bounded_mining_executed": True,
        "controlled_reboot_executed": True,
        "cooling_enabled": True,
        "cutoff_tested": True,
        "endurance_executed": False,
        "fault_injection_executed": False,
        "first_light_executed": True,
        "firmware_or_configuration_outside_authorization_changed": False,
        "pool_credentials_included": False,
        "production_release_performed": False,
        "replacement_booted": True,
        "rollback_executed": True,
        "stock_restored_at_end": True,
        "unbounded_mining_executed": False,
    },
    QUALIFICATION_ENDURANCE: {
        "bounded_mining_executed": True,
        "controlled_reboot_executed": True,
        "cooling_enabled": True,
        "cutoff_tested": True,
        "endurance_executed": True,
        "fault_injection_executed": True,
        "first_light_executed": False,
        "firmware_or_configuration_outside_authorization_changed": False,
        "pool_credentials_included": False,
        "production_release_performed": False,
        "replacement_booted": True,
        "rollback_executed": True,
        "stock_restored_at_end": True,
        "unbounded_mining_executed": False,
    },
}

AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_fault_injection": False,
    "authorizes_future_power_or_cooling_control": False,
    "authorizes_future_read_or_write": False,
    "authorizes_install": False,
    "authorizes_pool_or_network_access": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_production": False,
}


class BenchEnduranceError(RuntimeError):
    """A descriptor, bundle, signature, join, or semantic invariant failed."""


def canonical_json_bytes(value: object) -> bytes:
    return discovery.canonical_json_bytes(value)


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str] | set[str], context: str
) -> None:
    actual = set(value)
    wanted = set(expected)
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing or extra:
        raise BenchEnduranceError(
            f"{context} keys invalid: missing={missing} unexpected={extra}"
        )


def _text(value: Any, context: str, maximum: int = 200) -> str:
    try:
        return discovery._observed_text(value, context, maximum)
    except discovery.DiscoveryError as exc:
        raise BenchEnduranceError(str(exc)) from exc


def _identifier(value: Any, context: str) -> str:
    text = _text(value, context, 96)
    if not IDENTIFIER_RE.fullmatch(text):
        raise BenchEnduranceError(f"{context} is not a canonical identifier")
    return text


def _principal(value: Any, context: str) -> str:
    try:
        return fixture._principal(value, context)
    except fixture.FixtureError as exc:
        raise BenchEnduranceError(str(exc)) from exc


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise BenchEnduranceError(f"{context} must be 64 lowercase hex characters")
    return value


def _utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise BenchEnduranceError(f"{context} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise BenchEnduranceError(f"{context} is not a valid UTC time") from exc


def _integer(
    value: Any, context: str, *, minimum: int = 0, maximum: int = 10**12
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BenchEnduranceError(f"{context} must be an integer")
    if not minimum <= value <= maximum:
        raise BenchEnduranceError(f"{context} is outside {minimum}..{maximum}")
    return value


def _bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise BenchEnduranceError(f"{context} must be boolean")
    return value


def _safe_path(value: Any, context: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise BenchEnduranceError(f"{context} must be a forward-slash relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BenchEnduranceError(f"{context} is not a canonical relative path")
    return path


def _source(root: Path, relative: PurePosixPath) -> Path:
    try:
        return discovery._evidence_source(root, relative)
    except discovery.DiscoveryError as exc:
        raise BenchEnduranceError(str(exc)) from exc


def _hash_source(path: Path, context: str) -> tuple[int, str]:
    try:
        data = discovery._read_regular(path, context, MAX_EVIDENCE_FILE_BYTES)
    except discovery.DiscoveryError as exc:
        raise BenchEnduranceError(str(exc)) from exc
    return len(data), hashlib.sha256(data).hexdigest()


def _load_json(path: Path, label: str, *, canonical: bool = True) -> dict[str, Any]:
    try:
        return discovery.load_json(path, label, require_canonical=canonical)
    except discovery.DiscoveryError as exc:
        raise BenchEnduranceError(str(exc)) from exc


def _required_kinds(qualification_class: str) -> set[str]:
    required = PREDECESSOR_KINDS | COMMON_SEMANTIC_KINDS
    if qualification_class == QUALIFICATION_FIRST_LIGHT:
        return required | FIRST_LIGHT_ONLY_KINDS
    if qualification_class == QUALIFICATION_BENCH:
        return required | BENCH_ONLY_KINDS
    return required | ENDURANCE_ONLY_KINDS


def _actions_for_class(qualification_class: str) -> set[str]:
    if qualification_class == QUALIFICATION_FIRST_LIGHT:
        return FIRST_LIGHT_ACTIONS
    if qualification_class == QUALIFICATION_BENCH:
        return BENCH_ACTIONS
    return ENDURANCE_ACTIONS


def _validate_evidence(value: Any, qualification_class: str, *, hashed: bool) -> None:
    required = _required_kinds(qualification_class)
    if not isinstance(value, list) or len(value) != len(required):
        raise BenchEnduranceError(
            f"evidence must contain exactly {len(required)} class-specific records"
        )
    ids: set[str] = set()
    paths: set[str] = set()
    kinds: list[str] = []
    keys = {
        "acquired_at_utc",
        "id",
        "kind",
        "media_type",
        "method",
        "path",
        "redaction",
    }
    if hashed:
        keys |= {"bytes", "sha256"}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise BenchEnduranceError(f"evidence[{index}] must be an object")
        _require_exact_keys(item, keys, f"evidence[{index}]")
        evidence_id = _identifier(item["id"], f"evidence[{index}].id")
        if evidence_id in ids:
            raise BenchEnduranceError("evidence IDs must be unique")
        ids.add(evidence_id)
        kind = _identifier(item["kind"], f"evidence[{index}].kind")
        kinds.append(kind)
        if kind not in required:
            raise BenchEnduranceError(f"evidence kind {kind!r} is not valid for class")
        if item["media_type"] != MEDIA_TYPE_BY_KIND[kind]:
            raise BenchEnduranceError(f"evidence {evidence_id} media type is invalid")
        if item["method"] != METHOD_BY_KIND[kind]:
            raise BenchEnduranceError(f"evidence {evidence_id} method is invalid")
        if item["redaction"] != REDACTION_BY_KIND[kind]:
            raise BenchEnduranceError(f"evidence {evidence_id} redaction is invalid")
        relative = str(_safe_path(item["path"], f"evidence[{index}].path"))
        if relative in paths:
            raise BenchEnduranceError("evidence paths must be unique")
        paths.add(relative)
        _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if hashed:
            _integer(
                item["bytes"],
                f"evidence[{index}].bytes",
                minimum=1,
                maximum=MAX_EVIDENCE_FILE_BYTES,
            )
            _sha(item["sha256"], f"evidence[{index}].sha256")
    if set(kinds) != required or len(kinds) != len(set(kinds)):
        raise BenchEnduranceError("evidence kinds must occur exactly once")


def _validate_authorization(value: Any, qualification_class: str) -> None:
    if not isinstance(value, dict):
        raise BenchEnduranceError("authorization must be an object")
    _require_exact_keys(
        value,
        {
            "authorized_actions",
            "emergency_stop_owner",
            "issued_at_utc",
            "maximum_duration_seconds",
            "maximum_hash_power_w",
            "maximum_temperature_millicelsius",
            "maximum_telemetry_gap_ms",
            "maximum_cutoff_response_ms",
            "operator_reference",
            "pool_endpoint_id",
            "valid_from_utc",
            "valid_until_utc",
        },
        "authorization",
    )
    actions = _actions_for_class(qualification_class)
    if value["authorized_actions"] != sorted(actions):
        raise BenchEnduranceError("authorization action set is not exact for class")
    _text(value["operator_reference"], "authorization.operator_reference", 160)
    _principal(value["emergency_stop_owner"], "authorization.emergency_stop_owner")
    _identifier(value["pool_endpoint_id"], "authorization.pool_endpoint_id")
    issued = _utc(value["issued_at_utc"], "authorization.issued_at_utc")
    valid_from = _utc(value["valid_from_utc"], "authorization.valid_from_utc")
    valid_until = _utc(value["valid_until_utc"], "authorization.valid_until_utc")
    if issued > valid_from or valid_from >= valid_until:
        raise BenchEnduranceError("authorization chronology is invalid")
    _integer(
        value["maximum_duration_seconds"],
        "authorization.maximum_duration_seconds",
        minimum=1,
    )
    _integer(
        value["maximum_hash_power_w"], "authorization.maximum_hash_power_w", minimum=1
    )
    _integer(
        value["maximum_temperature_millicelsius"],
        "authorization.maximum_temperature_millicelsius",
        minimum=1,
    )
    _integer(
        value["maximum_telemetry_gap_ms"],
        "authorization.maximum_telemetry_gap_ms",
        minimum=1,
    )
    _integer(
        value["maximum_cutoff_response_ms"],
        "authorization.maximum_cutoff_response_ms",
        minimum=1,
    )


def _validate_actions(value: Any, qualification_class: str, outcome: str) -> None:
    if not isinstance(value, dict):
        raise BenchEnduranceError("actions_performed must be an object")
    _require_exact_keys(value, ACTIONS_PERFORMED_KEYS, "actions_performed")
    for key, observed in value.items():
        _bool(observed, f"actions_performed.{key}")
    if any(value[key] for key in PROHIBITED_ACTIONS):
        raise BenchEnduranceError("a prohibited action was recorded")
    if outcome == "passed" and value != POSITIVE_ACTIONS[qualification_class]:
        raise BenchEnduranceError("passed outcome has an incomplete action record")


def _validate_signing(value: Any, qualification_class: str) -> None:
    if not isinstance(value, dict):
        raise BenchEnduranceError("signing must be an object")
    expected = SIGNING_CONTRACTS[qualification_class]
    _require_exact_keys(value, set(expected), "signing")
    key_ids = set()
    for role, (role_name, namespace) in expected.items():
        item = value[role]
        if not isinstance(item, dict):
            raise BenchEnduranceError(f"signing.{role} must be an object")
        _require_exact_keys(
            item, {"algorithm", "key_id_sha256", "namespace", "role"}, f"signing.{role}"
        )
        if (
            item["algorithm"] != SIGNATURE_ALGORITHM
            or item["namespace"] != namespace
            or item["role"] != role_name
        ):
            raise BenchEnduranceError(f"signing.{role} contract drifted")
        key_ids.add(_sha(item["key_id_sha256"], f"signing.{role}.key_id_sha256"))
    if len(key_ids) != len(expected):
        raise BenchEnduranceError("stage signing keys must be distinct")


def _stage_key_paths(
    qualification_class: str,
    operator_key: Path,
    witness_key: Path | None,
    protocol_reviewer_key: Path | None,
    safety_reviewer_key: Path | None,
) -> dict[str, Path]:
    supplied = {
        "operator": operator_key,
        "protocol_reviewer": protocol_reviewer_key,
        "safety_reviewer": safety_reviewer_key,
        "witness": witness_key,
    }
    expected = set(SIGNING_CONTRACTS[qualification_class])
    if {role for role, path in supplied.items() if path is not None} != expected:
        raise BenchEnduranceError(
            f"{qualification_class} requires exactly these signer keys: {sorted(expected)}"
        )
    return {role: path for role, path in supplied.items() if path is not None}


def _signer_principal(receipt: Mapping[str, Any], role: str) -> str:
    field = {
        "operator": "operator_id",
        "protocol_reviewer": "protocol_reviewer_id",
        "safety_reviewer": "safety_reviewer_id",
        "witness": "witness_id",
    }[role]
    value = receipt[field]
    if not isinstance(value, str):
        raise BenchEnduranceError(f"{field} is absent for required signer role")
    return value


def _results(qualification_class: str, outcome: str) -> dict[str, Any]:
    passed = outcome == "passed"
    first_light_eligible = passed or qualification_class in {
        QUALIFICATION_BENCH,
        QUALIFICATION_ENDURANCE,
    }
    bench_eligible = qualification_class == QUALIFICATION_ENDURANCE or (
        qualification_class == QUALIFICATION_BENCH and passed
    )
    return {
        "first_light": {
            "eligible": first_light_eligible,
            "state": (
                "verified_staged_first_light"
                if first_light_eligible
                else f"{qualification_class}_{outcome}"
            ),
        },
        "bench_mining": {
            "eligible": bench_eligible,
            "state": (
                "verified_bounded_first_light_and_bench_mining"
                if bench_eligible
                else f"{qualification_class}_{outcome}"
            ),
        },
        "endurance_faults": {
            "eligible": passed and qualification_class == QUALIFICATION_ENDURANCE,
            "state": (
                "verified_fault_and_endurance_qualification"
                if passed and qualification_class == QUALIFICATION_ENDURANCE
                else "not_qualified"
            ),
        },
    }


def _validate_core(value: Mapping[str, Any], *, receipt: bool) -> None:
    core_keys = {
        "actions_performed",
        "authorization",
        "boot_policy_receipt_id",
        "capture_receipt_id",
        "capture_set_sha256",
        "completed_at_utc",
        "controller_board_revision",
        "discovery_receipt_id",
        "evidence",
        "fixture_evidence_set_sha256",
        "fixture_receipt_id",
        "installed_artifact_sha256",
        "kind",
        "operator_id",
        "outcome",
        "prior_stage_receipt_id",
        "prior_stage_evidence_set_sha256",
        "qualification_class",
        "protocol_reviewer_id",
        "recovery_receipt_id",
        "artifact_set_sha256",
        "interface_qualification_sha256",
        "route_replacement_receipt_id",
        "replacement_firmware_version",
        "route_rollback_receipt_id",
        "route_adjudication_sha256",
        "schema_version",
        "scope",
        "session_id",
        "started_at_utc",
        "stock_backup_set_sha256",
        "no_clobber_sha256",
        "stock_restoration_sha256",
        "target_id",
        "unit_fingerprint_sha256",
        "unit_label",
        "variant_profile_id",
        "selected_route",
        "safety_reviewer_id",
        "witness_id",
    }
    receipt_only = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "evidence_set_sha256",
        "receipt_id",
        "results",
        "signing",
    }
    _require_exact_keys(
        value, core_keys | receipt_only if receipt else core_keys, "record"
    )
    if value["schema_version"] != SCHEMA_VERSION or value["scope"] != SCOPE:
        raise BenchEnduranceError("schema or scope mismatch")
    expected_kind = RECEIPT_KIND if receipt else DESCRIPTOR_KIND
    if value["kind"] != expected_kind:
        raise BenchEnduranceError("record kind mismatch")
    qualification_class = value["qualification_class"]
    if qualification_class not in QUALIFICATION_CLASSES:
        raise BenchEnduranceError("qualification_class is unsupported")
    if value["outcome"] not in OUTCOMES:
        raise BenchEnduranceError("outcome is unsupported")
    _identifier(value["target_id"], "target_id")
    _identifier(value["unit_label"], "unit_label")
    _identifier(value["variant_profile_id"], "variant_profile_id")
    _text(value["controller_board_revision"], "controller_board_revision", 120)
    _text(value["replacement_firmware_version"], "replacement_firmware_version", 96)
    _identifier(value["session_id"], "session_id")
    operator = _principal(value["operator_id"], "operator_id")
    if qualification_class == QUALIFICATION_FIRST_LIGHT:
        protocol_reviewer = _principal(
            value["protocol_reviewer_id"], "protocol_reviewer_id"
        )
        safety_reviewer = _principal(value["safety_reviewer_id"], "safety_reviewer_id")
        if value["witness_id"] is not None:
            raise BenchEnduranceError("first-light uses reviewers, not witness_id")
        if len({operator, protocol_reviewer, safety_reviewer}) != 3:
            raise BenchEnduranceError("first-light signer principals must be distinct")
    else:
        witness = _principal(value["witness_id"], "witness_id")
        if (
            value["protocol_reviewer_id"] is not None
            or value["safety_reviewer_id"] is not None
        ):
            raise BenchEnduranceError(
                "bench/endurance cannot carry first-light reviewers"
            )
        if operator == witness:
            raise BenchEnduranceError(
                "operator and witness principals must be distinct"
            )
    for key in (
        "boot_policy_receipt_id",
        "capture_receipt_id",
        "capture_set_sha256",
        "discovery_receipt_id",
        "fixture_evidence_set_sha256",
        "fixture_receipt_id",
        "installed_artifact_sha256",
        "recovery_receipt_id",
        "artifact_set_sha256",
        "interface_qualification_sha256",
        "route_replacement_receipt_id",
        "route_rollback_receipt_id",
        "route_adjudication_sha256",
        "stock_backup_set_sha256",
        "no_clobber_sha256",
        "stock_restoration_sha256",
        "unit_fingerprint_sha256",
    ):
        _sha(value[key], key)
    if qualification_class == QUALIFICATION_FIRST_LIGHT:
        if value["prior_stage_receipt_id"] is not None:
            raise BenchEnduranceError("first-light class cannot join a prior stage")
        if value["prior_stage_evidence_set_sha256"] is not None:
            raise BenchEnduranceError(
                "first-light class cannot join prior-stage evidence"
            )
    else:
        _sha(value["prior_stage_receipt_id"], "prior_stage_receipt_id")
        _sha(
            value["prior_stage_evidence_set_sha256"],
            "prior_stage_evidence_set_sha256",
        )
    if value["selected_route"] not in ROUTES:
        raise BenchEnduranceError("selected_route is unsupported")
    started = _utc(value["started_at_utc"], "started_at_utc")
    completed = _utc(value["completed_at_utc"], "completed_at_utc")
    if started >= completed:
        raise BenchEnduranceError("session chronology is invalid")
    _validate_authorization(value["authorization"], qualification_class)
    valid_from = _utc(
        value["authorization"]["valid_from_utc"], "authorization.valid_from_utc"
    )
    valid_until = _utc(
        value["authorization"]["valid_until_utc"], "authorization.valid_until_utc"
    )
    if started < valid_from or completed > valid_until:
        raise BenchEnduranceError("session is outside its authorization window")
    duration = int((completed - started).total_seconds())
    if duration > value["authorization"]["maximum_duration_seconds"]:
        raise BenchEnduranceError("session exceeds authorized duration")
    _validate_actions(value["actions_performed"], qualification_class, value["outcome"])
    _validate_evidence(value["evidence"], qualification_class, hashed=receipt)
    for index, item in enumerate(value["evidence"]):
        acquired = _utc(item["acquired_at_utc"], f"evidence[{index}].acquired_at_utc")
        if acquired > completed:
            raise BenchEnduranceError(f"evidence[{index}] is after session completion")
    if receipt:
        if value["authority_ceiling"] != AUTHORITY_CEILING:
            raise BenchEnduranceError("authority ceiling drifted")
        if value["disposition"] != DISPOSITION:
            raise BenchEnduranceError("disposition drifted")
        if value["results"] != _results(qualification_class, value["outcome"]):
            raise BenchEnduranceError("result projection drifted")
        for key in ("descriptor_sha256", "evidence_set_sha256", "receipt_id"):
            _sha(value[key], key)
        _validate_signing(value["signing"], qualification_class)


def _descriptor_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "authority_ceiling",
        "descriptor_sha256",
        "disposition",
        "evidence_set_sha256",
        "receipt_id",
        "results",
        "signing",
    }
    projection = json.loads(
        json.dumps(
            {key: value for key, value in receipt.items() if key not in excluded}
        )
    )
    projection["kind"] = DESCRIPTOR_KIND
    for item in projection["evidence"]:
        item.pop("bytes", None)
        item.pop("sha256", None)
    return projection


def _evidence_projection(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(item) for item in sorted(receipt["evidence"], key=lambda row: row["id"])
    ]


def _validate_receipt(receipt: Mapping[str, Any]) -> None:
    _validate_core(receipt, receipt=True)
    descriptor_sha = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    if descriptor_sha != receipt["descriptor_sha256"]:
        raise BenchEnduranceError("descriptor SHA-256 mismatch")
    evidence_sha = hashlib.sha256(
        b"DCENT-K210-BENCH-ENDURANCE-EVIDENCE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    if evidence_sha != receipt["evidence_set_sha256"]:
        raise BenchEnduranceError("evidence-set SHA-256 mismatch")
    without_id = {key: value for key, value in receipt.items() if key != "receipt_id"}
    receipt_id = hashlib.sha256(
        b"DCENT-K210-BENCH-ENDURANCE-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(without_id)
    ).hexdigest()
    if receipt_id != receipt["receipt_id"]:
        raise BenchEnduranceError("receipt ID mismatch")


def _evidence_by_kind(receipt: Mapping[str, Any], root: Path) -> dict[str, Path]:
    result = {}
    for item in receipt["evidence"]:
        result[item["kind"]] = _source(
            root, _safe_path(item["path"], f"evidence {item['id']} path")
        )
    return result


def _validate_route_rollback_receipt(
    value: Mapping[str, Any], manifest: Mapping[str, Any]
) -> None:
    try:
        route_rollback._validate_receipt(value, manifest)
    except route_rollback.RouteRollbackError as exc:
        raise BenchEnduranceError(
            f"route-rollback receipt copy is invalid: {exc}"
        ) from exc


def _installed_artifact_sha256(
    replacement_receipt: Mapping[str, Any], selected_route: str
) -> str:
    member, kind = {
        "native_aes0_flash": ("aup", "firmware_aup"),
        "rom_isp_sram_bootstrap": ("raw", "firmware_raw"),
        "jtag_sram_bootstrap": ("raw", "firmware_raw"),
        "clean_replacement_controller": (
            "controller",
            "controller_firmware_artifact",
        ),
    }[selected_route]
    evidence = {item["id"]: item for item in replacement_receipt["evidence"]}
    evidence_ids = [
        build["artifacts"][member] for build in replacement_receipt["builds"]
    ]
    try:
        artifacts = [evidence[evidence_id] for evidence_id in evidence_ids]
    except KeyError as exc:
        raise BenchEnduranceError(
            "route replacement build references an absent deployable artifact"
        ) from exc
    digests = {item["sha256"] for item in artifacts if item["kind"] == kind}
    if len(evidence_ids) != 2 or len(set(evidence_ids)) != 2 or len(digests) != 1:
        raise BenchEnduranceError(
            f"route replacement does not identify one reproducible {kind} digest"
        )
    return next(iter(digests))


def _join(value: Any, wanted: Any, context: str) -> None:
    if value != wanted:
        raise BenchEnduranceError(f"{context} does not exact-join")


def _validate_predecessors(
    manifest: Mapping[str, Any], receipt: Mapping[str, Any], paths: Mapping[str, Path]
) -> dict[str, Mapping[str, Any]]:
    documents = {
        kind: _load_json(paths[kind], kind.replace("_", " "))
        for kind in PREDECESSOR_KINDS
    }
    try:
        discovery._validate_receipt(documents["discovery_receipt_copy"], manifest)
        fixture._validate_receipt(documents["fixture_receipt_copy"], manifest)
        capture._validate_receipt(documents["capture_receipt_copy"], manifest)
        recovery._validate_receipt(documents["recovery_receipt_copy"], manifest)
        boot._validate_receipt(documents["boot_policy_receipt_copy"], manifest)
        route_replacement._validate_receipt(
            documents["route_replacement_receipt_copy"], manifest
        )
        _validate_route_rollback_receipt(
            documents["route_rollback_receipt_copy"], manifest
        )
    except (
        discovery.DiscoveryError,
        fixture.FixtureError,
        capture.CaptureReceiptError,
        recovery.RecoveryError,
        boot.BootPolicyError,
        route_replacement.RouteReplacementError,
    ) as exc:
        raise BenchEnduranceError(
            f"predecessor receipt copy is invalid: {exc}"
        ) from exc
    rollback_receipt = documents["route_rollback_receipt_copy"]
    common = {
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
    }
    for kind, document in documents.items():
        for field, wanted in common.items():
            _join(document[field], wanted, f"{kind}.{field}")
    discovery_receipt = documents["discovery_receipt_copy"]
    fixture_receipt = documents["fixture_receipt_copy"]
    capture_receipt = documents["capture_receipt_copy"]
    recovery_receipt = documents["recovery_receipt_copy"]
    boot_receipt = documents["boot_policy_receipt_copy"]
    replacement_receipt = documents["route_replacement_receipt_copy"]
    joins = (
        (
            discovery_receipt["receipt_id"],
            receipt["discovery_receipt_id"],
            "discovery receipt ID",
        ),
        (
            fixture_receipt["receipt_id"],
            receipt["fixture_receipt_id"],
            "fixture receipt ID",
        ),
        (
            fixture_receipt["fixture_evidence_set_sha256"],
            receipt["fixture_evidence_set_sha256"],
            "fixture evidence set",
        ),
        (
            capture_receipt["receipt_id"],
            receipt["capture_receipt_id"],
            "capture receipt ID",
        ),
        (
            capture_receipt["capture_set_sha256"],
            receipt["capture_set_sha256"],
            "capture set",
        ),
        (
            recovery_receipt["receipt_id"],
            receipt["recovery_receipt_id"],
            "recovery receipt ID",
        ),
        (
            recovery_receipt["stock_backup_set_sha256"],
            receipt["stock_backup_set_sha256"],
            "stock backup set",
        ),
        (
            boot_receipt["receipt_id"],
            receipt["boot_policy_receipt_id"],
            "boot-policy receipt ID",
        ),
        (
            replacement_receipt["receipt_id"],
            receipt["route_replacement_receipt_id"],
            "route-replacement receipt ID",
        ),
        (
            replacement_receipt["artifact_set_sha256"],
            receipt["artifact_set_sha256"],
            "route artifact set",
        ),
        (
            replacement_receipt["interface_qualification_sha256"],
            receipt["interface_qualification_sha256"],
            "route interface qualification",
        ),
        (
            rollback_receipt["receipt_id"],
            receipt["route_rollback_receipt_id"],
            "route-rollback receipt ID",
        ),
        (
            rollback_receipt["selected_route"],
            receipt["selected_route"],
            "rollback selected route",
        ),
        (
            rollback_receipt["route_adjudication_sha256"],
            receipt["route_adjudication_sha256"],
            "rollback route adjudication",
        ),
        (
            rollback_receipt["no_clobber_sha256"],
            receipt["no_clobber_sha256"],
            "rollback stock no-clobber",
        ),
        (
            rollback_receipt["stock_restoration_sha256"],
            receipt["stock_restoration_sha256"],
            "rollback stock restoration",
        ),
    )
    for observed, wanted, context in joins:
        _join(observed, wanted, context)
    chain_fields = {
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
    }
    for kind in (
        "boot_policy_receipt_copy",
        "route_replacement_receipt_copy",
        "route_rollback_receipt_copy",
    ):
        for field, wanted in chain_fields.items():
            if field in documents[kind]:
                _join(documents[kind][field], wanted, f"{kind}.{field}")
    _join(
        capture_receipt["fixture_receipt_id"],
        receipt["fixture_receipt_id"],
        "capture fixture receipt",
    )
    _join(
        capture_receipt["discovery_receipt_id"],
        receipt["discovery_receipt_id"],
        "capture discovery receipt",
    )
    _join(
        fixture_receipt["discovery_receipt_id"],
        receipt["discovery_receipt_id"],
        "fixture discovery receipt",
    )
    _join(
        recovery_receipt["discovery_receipt_id"],
        receipt["discovery_receipt_id"],
        "recovery discovery receipt",
    )
    _join(
        fixture_receipt["fixture_identity"]["variant_profile_id"],
        receipt["variant_profile_id"],
        "fixture variant profile",
    )
    _join(
        fixture_receipt["fixture_identity"]["controller_board_revision"],
        receipt["controller_board_revision"],
        "fixture controller board revision",
    )
    _join(
        capture_receipt["variant_profile_id"],
        receipt["variant_profile_id"],
        "capture variant profile",
    )
    _join(
        replacement_receipt["firmware"]["firmware_version"],
        receipt["replacement_firmware_version"],
        "replacement firmware version",
    )
    _join(
        replacement_receipt["route_selection"]["selected_route"],
        receipt["selected_route"],
        "replacement selected route",
    )
    _join(
        replacement_receipt["route_selection"]["adjudication_sha256"],
        receipt["route_adjudication_sha256"],
        "replacement route adjudication",
    )
    for field in ("artifact_set_sha256", "interface_qualification_sha256"):
        _join(rollback_receipt[field], receipt[field], f"rollback {field}")
    _join(
        rollback_receipt["route_replacement_receipt_id"],
        receipt["route_replacement_receipt_id"],
        "rollback route-replacement receipt",
    )
    _join(
        _installed_artifact_sha256(replacement_receipt, receipt["selected_route"]),
        receipt["installed_artifact_sha256"],
        "route-specific installed artifact",
    )
    return documents


def _validate_event_list(value: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise BenchEnduranceError(f"{context} must be a list")
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise BenchEnduranceError(f"{context}[{index}] must be an object")
        _require_exact_keys(item, {"code", "detail", "time_utc"}, f"{context}[{index}]")
        _identifier(item["code"], f"{context}[{index}].code")
        _text(item["detail"], f"{context}[{index}].detail", 300)
        _utc(item["time_utc"], f"{context}[{index}].time_utc")
        result.append(item)
    return result


def _validate_session_log(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "authorization_reference",
            "deviations",
            "events",
            "faults",
            "session_id",
            "stop_events",
        },
        "session_log",
    )
    _join(value["session_id"], receipt["session_id"], "session log ID")
    _join(
        value["authorization_reference"],
        receipt["authorization"]["operator_reference"],
        "session authorization",
    )
    events = value["events"]
    if not isinstance(events, list):
        raise BenchEnduranceError("session_log.events must be a list")
    allowed = _actions_for_class(receipt["qualification_class"])
    observed_actions = set()
    observed_sequence = []
    previous = None
    started = _utc(receipt["started_at_utc"], "started_at_utc")
    completed = _utc(receipt["completed_at_utc"], "completed_at_utc")
    for index, item in enumerate(events):
        if not isinstance(item, dict):
            raise BenchEnduranceError(f"session_log.events[{index}] must be an object")
        _require_exact_keys(
            item, {"action", "detail", "time_utc"}, f"session_log.events[{index}]"
        )
        action = _identifier(item["action"], f"session_log.events[{index}].action")
        if action not in allowed or action in observed_actions:
            raise BenchEnduranceError(
                "session log action is unauthorized or duplicated"
            )
        observed_actions.add(action)
        observed_sequence.append(action)
        _text(item["detail"], f"session_log.events[{index}].detail", 300)
        moment = _utc(item["time_utc"], f"session_log.events[{index}].time_utc")
        if previous is not None and moment <= previous:
            raise BenchEnduranceError(
                "session log events are not strictly chronological"
            )
        if moment < started or moment > completed:
            raise BenchEnduranceError("session log event is outside the session window")
        previous = moment
    faults = _validate_event_list(value["faults"], "session_log.faults")
    stops = _validate_event_list(value["stop_events"], "session_log.stop_events")
    deviations = _validate_event_list(value["deviations"], "session_log.deviations")
    if receipt["outcome"] == "passed":
        if (
            tuple(observed_sequence) != ACTION_SEQUENCES[receipt["qualification_class"]]
            or faults
            or stops
            or deviations
        ):
            raise BenchEnduranceError(
                "passed session log is incomplete or contains exceptions"
            )
    elif not faults and not stops:
        raise BenchEnduranceError(
            "failed/stopped outcome requires a fault or stop event"
        )


def _validate_safety(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "closed_chassis",
            "cooling_ready_before_hash_power",
            "cutoff_feedback_available",
            "emergency_stop_owner",
            "fixture_receipt_id",
            "independent_cutoff_available",
            "route_rollback_receipt_id",
            "safe_terminal_state_confirmed",
            "watchdog_active",
        },
        "safety_record",
    )
    _join(
        value["fixture_receipt_id"],
        receipt["fixture_receipt_id"],
        "safety fixture receipt",
    )
    _join(
        value["route_rollback_receipt_id"],
        receipt["route_rollback_receipt_id"],
        "safety rollback receipt",
    )
    _join(
        value["emergency_stop_owner"],
        receipt["authorization"]["emergency_stop_owner"],
        "emergency stop owner",
    )
    booleans = [
        key
        for key in value
        if key
        not in {
            "fixture_receipt_id",
            "route_rollback_receipt_id",
            "emergency_stop_owner",
        }
    ]
    for key in booleans:
        _bool(value[key], f"safety_record.{key}")
    if receipt["outcome"] == "passed" and any(
        value[key] is not True for key in booleans
    ):
        raise BenchEnduranceError("passed safety record is incomplete")


def _validate_cooling(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "cooling_faults",
            "cooling_ready_before_hash_power",
            "fan_or_pump_count",
            "fresh_throughout",
            "max_gap_ms",
            "max_temperature_millicelsius",
            "sample_count",
            "session_id",
            "temperature_limit_millicelsius",
        },
        "cooling_telemetry_record",
    )
    _join(value["session_id"], receipt["session_id"], "cooling session")
    for key in (
        "fan_or_pump_count",
        "max_gap_ms",
        "max_temperature_millicelsius",
        "sample_count",
        "temperature_limit_millicelsius",
    ):
        _integer(value[key], f"cooling.{key}", minimum=1)
    _bool(value["fresh_throughout"], "cooling.fresh_throughout")
    _bool(
        value["cooling_ready_before_hash_power"],
        "cooling.cooling_ready_before_hash_power",
    )
    if not isinstance(value["cooling_faults"], list):
        raise BenchEnduranceError("cooling_faults must be a list")
    if receipt["outcome"] == "passed" and (
        value["cooling_faults"]
        or value["fresh_throughout"] is not True
        or value["cooling_ready_before_hash_power"] is not True
        or value["max_gap_ms"] > receipt["authorization"]["maximum_telemetry_gap_ms"]
        or value["max_temperature_millicelsius"]
        >= value["temperature_limit_millicelsius"]
        or value["temperature_limit_millicelsius"]
        > receipt["authorization"]["maximum_temperature_millicelsius"]
    ):
        raise BenchEnduranceError(
            "passed cooling telemetry exceeds its custody envelope"
        )


def _validate_cutoff(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "assertion_tested_before_session",
            "cooling_continued_after_cutoff",
            "feedback_fresh_throughout",
            "hash_power_default_off",
            "independent_cutoff_available",
            "latched_faults",
            "measured_cutoff_response_ms",
            "rail_feedback_off_at_end",
            "session_id",
        },
        "cutoff_telemetry_record",
    )
    _join(value["session_id"], receipt["session_id"], "cutoff session")
    booleans = {
        "assertion_tested_before_session",
        "cooling_continued_after_cutoff",
        "feedback_fresh_throughout",
        "hash_power_default_off",
        "independent_cutoff_available",
        "rail_feedback_off_at_end",
    }
    for key in booleans:
        _bool(value[key], f"cutoff.{key}")
    _integer(value["measured_cutoff_response_ms"], "cutoff.measured_cutoff_response_ms")
    if not isinstance(value["latched_faults"], list):
        raise BenchEnduranceError("cutoff.latched_faults must be a list")
    if receipt["outcome"] == "passed" and (
        any(value[key] is not True for key in booleans)
        or value["latched_faults"]
        or value["measured_cutoff_response_ms"]
        > receipt["authorization"]["maximum_cutoff_response_ms"]
    ):
        raise BenchEnduranceError("passed cutoff evidence is incomplete")


def _validate_runtime(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "board_count",
            "firmware_artifact_sha256",
            "max_gap_ms",
            "sample_count",
            "sensor_read_errors",
            "session_id",
            "stale_samples",
            "unexpected_restarts",
            "uptime_seconds",
            "watchdog_faults",
        },
        "runtime_telemetry_record",
    )
    _join(value["session_id"], receipt["session_id"], "runtime session")
    _join(
        value["firmware_artifact_sha256"],
        receipt["installed_artifact_sha256"],
        "runtime artifact",
    )
    for key in ("board_count", "sample_count", "uptime_seconds"):
        _integer(value[key], f"runtime.{key}", minimum=1)
    for key in (
        "max_gap_ms",
        "sensor_read_errors",
        "stale_samples",
        "unexpected_restarts",
        "watchdog_faults",
    ):
        _integer(value[key], f"runtime.{key}")
    if receipt["outcome"] == "passed" and (
        value["max_gap_ms"] > receipt["authorization"]["maximum_telemetry_gap_ms"]
        or any(
            value[key] != 0
            for key in (
                "sensor_read_errors",
                "stale_samples",
                "unexpected_restarts",
                "watchdog_faults",
            )
        )
    ):
        raise BenchEnduranceError(
            "passed runtime telemetry contains a fault or stale gap"
        )


def _validate_pool(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "connected_at_utc",
            "credentials_redacted",
            "disconnected_at_utc",
            "endpoint_id",
            "jobs_received",
            "network_scope",
            "session_id",
            "transport_errors",
            "unexpected_reconnects",
        },
        "pool_session_record",
    )
    _join(value["session_id"], receipt["session_id"], "pool session")
    _join(
        value["endpoint_id"],
        receipt["authorization"]["pool_endpoint_id"],
        "pool endpoint",
    )
    if value["network_scope"] != "operator_controlled_isolated_bench":
        raise BenchEnduranceError(
            "pool network scope is not isolated/operator-controlled"
        )
    _bool(value["credentials_redacted"], "pool.credentials_redacted")
    connected = _utc(value["connected_at_utc"], "pool.connected_at_utc")
    disconnected = _utc(value["disconnected_at_utc"], "pool.disconnected_at_utc")
    if connected >= disconnected:
        raise BenchEnduranceError("pool chronology is invalid")
    for key in ("jobs_received", "transport_errors", "unexpected_reconnects"):
        _integer(value[key], f"pool.{key}")
    if receipt["outcome"] == "passed" and (
        value["credentials_redacted"] is not True
        or value["jobs_received"] < 1
        or value["transport_errors"] != 0
        or value["unexpected_reconnects"] != 0
    ):
        raise BenchEnduranceError("passed pool evidence is incomplete")


def _validate_shares(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "accepted",
            "duplicate",
            "endpoint_id",
            "first_accepted_at_utc",
            "invalid",
            "last_accepted_at_utc",
            "pool_accepted",
            "rejected",
            "session_id",
            "stale",
            "submitted",
        },
        "share_accounting_record",
    )
    _join(value["session_id"], receipt["session_id"], "share session")
    _join(
        value["endpoint_id"],
        receipt["authorization"]["pool_endpoint_id"],
        "share endpoint",
    )
    for key in (
        "accepted",
        "duplicate",
        "invalid",
        "pool_accepted",
        "rejected",
        "stale",
        "submitted",
    ):
        _integer(value[key], f"shares.{key}")
    if value["first_accepted_at_utc"] is not None:
        first = _utc(value["first_accepted_at_utc"], "shares.first_accepted_at_utc")
        last = _utc(value["last_accepted_at_utc"], "shares.last_accepted_at_utc")
        if first > last:
            raise BenchEnduranceError("share chronology is invalid")
    elif value["last_accepted_at_utc"] is not None:
        raise BenchEnduranceError("last accepted share exists without first")
    classified = sum(
        value[key] for key in ("accepted", "duplicate", "invalid", "rejected", "stale")
    )
    if value["submitted"] != classified:
        raise BenchEnduranceError("submitted shares do not equal classified shares")
    if receipt["outcome"] == "passed" and (
        value["accepted"] < 1
        or value["pool_accepted"] != value["accepted"]
        or value["first_accepted_at_utc"] is None
    ):
        raise BenchEnduranceError(
            "passed share accounting lacks pool-confirmed acceptance"
        )


def _validate_first_light(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "accepted_share_observed",
            "cooling_preceded_hash_power",
            "cutoff_feedback_confirmed_before_hash_power",
            "duration_seconds",
            "first_hash_at_utc",
            "first_share_at_utc",
            "hash_enable_after_prerequisites",
            "hash_power_started",
            "max_power_w",
            "max_temperature_millicelsius",
            "safe_idle_observed",
            "sensors_fresh_before_hash_power",
            "session_id",
            "watchdog_confirmed_before_hash_power",
        },
        "first_light_record",
    )
    _join(value["session_id"], receipt["session_id"], "first-light session")
    prerequisites = (
        "accepted_share_observed",
        "cooling_preceded_hash_power",
        "cutoff_feedback_confirmed_before_hash_power",
        "hash_enable_after_prerequisites",
        "hash_power_started",
        "safe_idle_observed",
        "sensors_fresh_before_hash_power",
        "watchdog_confirmed_before_hash_power",
    )
    for key in prerequisites:
        _bool(value[key], f"first_light.{key}")
    for key in ("duration_seconds", "max_power_w", "max_temperature_millicelsius"):
        _integer(value[key], f"first_light.{key}", minimum=1)
    _utc(value["first_hash_at_utc"], "first_light.first_hash_at_utc")
    _utc(value["first_share_at_utc"], "first_light.first_share_at_utc")
    if receipt["outcome"] == "passed" and (
        any(value[key] is not True for key in prerequisites)
        or value["max_power_w"] > receipt["authorization"]["maximum_hash_power_w"]
        or value["max_temperature_millicelsius"]
        >= receipt["authorization"]["maximum_temperature_millicelsius"]
    ):
        raise BenchEnduranceError("passed first-light evidence is incomplete")


def _validate_bounded(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "accepted_shares",
            "configuration_persisted_after_reboot",
            "controlled_reboot_passed",
            "duration_seconds",
            "max_power_w",
            "max_temperature_millicelsius",
            "session_id",
            "unexpected_errors",
        },
        "bounded_mining_record",
    )
    _join(value["session_id"], receipt["session_id"], "bounded-mining session")
    for key in ("configuration_persisted_after_reboot", "controlled_reboot_passed"):
        _bool(value[key], f"bounded.{key}")
    for key in (
        "accepted_shares",
        "duration_seconds",
        "max_power_w",
        "max_temperature_millicelsius",
        "unexpected_errors",
    ):
        _integer(value[key], f"bounded.{key}")
    if receipt["outcome"] == "passed" and (
        value["accepted_shares"] < 1
        or value["duration_seconds"] < MIN_BENCH_DURATION_SECONDS
        or value["duration_seconds"]
        > receipt["authorization"]["maximum_duration_seconds"]
        or value["max_power_w"] > receipt["authorization"]["maximum_hash_power_w"]
        or value["max_temperature_millicelsius"]
        >= receipt["authorization"]["maximum_temperature_millicelsius"]
        or value["unexpected_errors"] != 0
        or value["configuration_persisted_after_reboot"] is not True
        or value["controlled_reboot_passed"] is not True
    ):
        raise BenchEnduranceError("passed bounded-mining evidence is incomplete")


def _validate_fault_campaign(
    value: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    _require_exact_keys(value, {"faults", "session_id"}, "fault_campaign_record")
    _join(value["session_id"], receipt["session_id"], "fault campaign session")
    if not isinstance(value["faults"], list):
        raise BenchEnduranceError("fault campaign faults must be a list")
    observed = set()
    for index, item in enumerate(value["faults"]):
        if not isinstance(item, dict):
            raise BenchEnduranceError(f"faults[{index}] must be an object")
        _require_exact_keys(
            item,
            {
                "cutoff_confirmed",
                "detected",
                "fault_type",
                "latched",
                "recovered",
                "response_ms",
                "safe_state_reached",
            },
            f"faults[{index}]",
        )
        fault_type = _identifier(item["fault_type"], f"faults[{index}].fault_type")
        if fault_type not in REQUIRED_FAULT_TYPES or fault_type in observed:
            raise BenchEnduranceError("fault campaign type is unknown or duplicated")
        observed.add(fault_type)
        for key in (
            "cutoff_confirmed",
            "detected",
            "latched",
            "recovered",
            "safe_state_reached",
        ):
            _bool(item[key], f"faults[{index}].{key}")
        _integer(item["response_ms"], f"faults[{index}].response_ms")
        if receipt["outcome"] == "passed" and (
            any(
                item[key] is not True
                for key in (
                    "cutoff_confirmed",
                    "detected",
                    "latched",
                    "recovered",
                    "safe_state_reached",
                )
            )
            or item["response_ms"]
            > receipt["authorization"]["maximum_cutoff_response_ms"]
        ):
            raise BenchEnduranceError(
                "fault response did not reach the bounded safe state"
            )
    if receipt["outcome"] == "passed" and observed != REQUIRED_FAULT_TYPES:
        raise BenchEnduranceError("passed fault campaign is incomplete")


def _validate_endurance(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _require_exact_keys(
        value,
        {
            "accepted_shares",
            "duration_seconds",
            "max_power_w",
            "max_temperature_millicelsius",
            "memory_growth_bytes",
            "phase_names",
            "session_id",
            "unexpected_errors",
            "unexpected_restarts",
        },
        "endurance_record",
    )
    _join(value["session_id"], receipt["session_id"], "endurance session")
    for key in (
        "accepted_shares",
        "duration_seconds",
        "max_power_w",
        "max_temperature_millicelsius",
        "memory_growth_bytes",
        "unexpected_errors",
        "unexpected_restarts",
    ):
        _integer(value[key], f"endurance.{key}")
    if value["phase_names"] != ["cold", "steady", "hot_soak", "recovery"]:
        raise BenchEnduranceError("endurance thermal phases are not exact")
    if receipt["outcome"] == "passed" and (
        value["accepted_shares"] < 1
        or value["duration_seconds"] < MIN_ENDURANCE_DURATION_SECONDS
        or value["duration_seconds"]
        > receipt["authorization"]["maximum_duration_seconds"]
        or value["max_power_w"] > receipt["authorization"]["maximum_hash_power_w"]
        or value["max_temperature_millicelsius"]
        >= receipt["authorization"]["maximum_temperature_millicelsius"]
        or value["unexpected_errors"] != 0
        or value["unexpected_restarts"] != 0
    ):
        raise BenchEnduranceError("passed endurance evidence is incomplete")


def _validate_prior_stage(value: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    _validate_receipt(value)
    wanted_class = (
        QUALIFICATION_FIRST_LIGHT
        if receipt["qualification_class"] == QUALIFICATION_BENCH
        else QUALIFICATION_BENCH
    )
    wanted_result = (
        "first_light"
        if receipt["qualification_class"] == QUALIFICATION_BENCH
        else "bench_mining"
    )
    if (
        value["qualification_class"] != wanted_class
        or value["outcome"] != "passed"
        or value["results"][wanted_result]["eligible"] is not True
    ):
        raise BenchEnduranceError(
            "receipt does not join its passing immediate predecessor"
        )
    _join(value["receipt_id"], receipt["prior_stage_receipt_id"], "prior stage receipt")
    _join(
        value["evidence_set_sha256"],
        receipt["prior_stage_evidence_set_sha256"],
        "prior stage evidence set",
    )
    prior_keys = {item["key_id_sha256"] for item in value["signing"].values()}
    current_keys = {item["key_id_sha256"] for item in receipt["signing"].values()}
    if prior_keys & current_keys:
        raise BenchEnduranceError("adjacent stages must use distinct signing keys")
    for field in (
        "boot_policy_receipt_id",
        "capture_receipt_id",
        "capture_set_sha256",
        "controller_board_revision",
        "discovery_receipt_id",
        "fixture_evidence_set_sha256",
        "fixture_receipt_id",
        "artifact_set_sha256",
        "installed_artifact_sha256",
        "interface_qualification_sha256",
        "recovery_receipt_id",
        "route_replacement_receipt_id",
        "replacement_firmware_version",
        "route_rollback_receipt_id",
        "route_adjudication_sha256",
        "selected_route",
        "stock_backup_set_sha256",
        "no_clobber_sha256",
        "stock_restoration_sha256",
        "target_id",
        "unit_fingerprint_sha256",
        "unit_label",
        "variant_profile_id",
    ):
        _join(value[field], receipt[field], f"prior bench {field}")


def _validate_semantics(
    manifest: Mapping[str, Any], receipt: Mapping[str, Any], evidence_root: Path
) -> None:
    paths = _evidence_by_kind(receipt, evidence_root)
    _validate_predecessors(manifest, receipt, paths)
    records = {
        kind: _load_json(paths[kind], kind.replace("_", " "))
        for kind in _required_kinds(receipt["qualification_class"]) - PREDECESSOR_KINDS
    }
    if records["authorization_record"] != receipt["authorization"]:
        raise BenchEnduranceError("authorization evidence does not match receipt")
    _validate_session_log(records["session_log"], receipt)
    _validate_safety(records["safety_record"], receipt)
    _validate_cooling(records["cooling_telemetry_record"], receipt)
    _validate_cutoff(records["cutoff_telemetry_record"], receipt)
    _validate_runtime(records["runtime_telemetry_record"], receipt)
    _validate_pool(records["pool_session_record"], receipt)
    _validate_shares(records["share_accounting_record"], receipt)
    if receipt["qualification_class"] == QUALIFICATION_FIRST_LIGHT:
        _validate_first_light(records["first_light_record"], receipt)
    elif receipt["qualification_class"] == QUALIFICATION_BENCH:
        _validate_bounded(records["bounded_mining_record"], receipt)
        _validate_prior_stage(records["prior_first_light_receipt_copy"], receipt)
    else:
        _validate_fault_campaign(records["fault_campaign_record"], receipt)
        _validate_endurance(records["endurance_record"], receipt)
        _validate_prior_stage(records["prior_bench_receipt_copy"], receipt)


def build_receipt(
    manifest: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    evidence_root: Path,
    operator_private_key: Path,
    witness_private_key: Path | None = None,
    *,
    protocol_reviewer_private_key: Path | None = None,
    safety_reviewer_private_key: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Path]]:
    _validate_core(descriptor, receipt=False)
    evidence = []
    sources = {}
    total = 0
    for item in sorted(descriptor["evidence"], key=lambda row: row["id"]):
        source = _source(
            evidence_root, _safe_path(item["path"], f"evidence {item['id']} path")
        )
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise BenchEnduranceError("evidence exceeds the aggregate byte limit")
        evidence.append({**item, "bytes": size, "sha256": digest})
        sources[item["id"]] = source
    normalized = json.loads(json.dumps(descriptor))
    normalized["evidence"] = evidence
    normalized["kind"] = RECEIPT_KIND
    signing_contract = SIGNING_CONTRACTS[normalized["qualification_class"]]
    key_paths = _stage_key_paths(
        normalized["qualification_class"],
        operator_private_key,
        witness_private_key,
        protocol_reviewer_private_key,
        safety_reviewer_private_key,
    )
    try:
        signer_keys = {
            role: discovery.inspect_private_key(path)
            for role, path in key_paths.items()
        }
    except discovery.DiscoveryError as exc:
        raise BenchEnduranceError(f"signing key is invalid: {exc}") from exc
    if len({key["key_id_sha256"] for key in signer_keys.values()}) != len(signer_keys):
        raise BenchEnduranceError("stage signing keys must be distinct")
    receipt: dict[str, Any] = {
        **normalized,
        "authority_ceiling": dict(AUTHORITY_CEILING),
        "disposition": DISPOSITION,
        "results": _results(normalized["qualification_class"], normalized["outcome"]),
        "signing": {
            role: {
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id_sha256": signer_keys[role]["key_id_sha256"],
                "namespace": signing_contract[role][1],
                "role": signing_contract[role][0],
            }
            for role in signing_contract
        },
    }
    receipt["descriptor_sha256"] = hashlib.sha256(
        canonical_json_bytes(_descriptor_projection(receipt))
    ).hexdigest()
    receipt["evidence_set_sha256"] = hashlib.sha256(
        b"DCENT-K210-BENCH-ENDURANCE-EVIDENCE-SET-V1\x00"
        + canonical_json_bytes(_evidence_projection(receipt))
    ).hexdigest()
    receipt["receipt_id"] = hashlib.sha256(
        b"DCENT-K210-BENCH-ENDURANCE-RECEIPT-ID-V1\x00"
        + canonical_json_bytes(
            {key: value for key, value in receipt.items() if key != "receipt_id"}
        )
    ).hexdigest()
    _validate_receipt(receipt)
    _validate_semantics(manifest, receipt, evidence_root)
    return receipt, sources


def _verify_exact_members(bundle: Path, receipt: Mapping[str, Any]) -> None:
    expected = {RECEIPT_NAME}
    expected |= {SIGNATURE_NAME_BY_ROLE[role] for role in receipt["signing"]}
    expected |= {f"{EVIDENCE_DIRECTORY}/{item['path']}" for item in receipt["evidence"]}
    observed = set()
    try:
        entries = list(bundle.rglob("*"))
    except OSError as exc:
        raise BenchEnduranceError(f"cannot enumerate bundle: {exc}") from exc
    for entry in entries:
        relative = entry.relative_to(bundle).as_posix()
        metadata = entry.lstat()
        if discovery._is_link_or_reparse(metadata):
            raise BenchEnduranceError(f"bundle contains a linked member: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            observed.add(relative)
        elif not stat.S_ISDIR(metadata.st_mode):
            raise BenchEnduranceError(f"bundle contains a special member: {relative}")
    if observed != expected:
        raise BenchEnduranceError("bundle member set is not exact")


def create_bundle(
    manifest: Mapping[str, Any],
    descriptor_path: Path,
    evidence_root: Path,
    operator_private_key: Path,
    bundle_out: Path,
    witness_private_key: Path | None = None,
    *,
    protocol_reviewer_private_key: Path | None = None,
    safety_reviewer_private_key: Path | None = None,
) -> dict[str, Any]:
    if bundle_out.exists():
        raise BenchEnduranceError(
            f"refusing to overwrite existing bundle: {bundle_out}"
        )
    descriptor = _load_json(
        descriptor_path, "bench/endurance descriptor", canonical=False
    )
    receipt, sources = build_receipt(
        manifest,
        descriptor,
        evidence_root,
        operator_private_key,
        witness_private_key,
        protocol_reviewer_private_key=protocol_reviewer_private_key,
        safety_reviewer_private_key=safety_reviewer_private_key,
    )
    parent = bundle_out.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle_out.name}.", dir=parent))
    try:
        destination_root = temporary / EVIDENCE_DIRECTORY
        destination_root.mkdir()
        for item in receipt["evidence"]:
            relative = _safe_path(item["path"], f"evidence {item['id']} path")
            destination = destination_root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources[item["id"]], destination)
            size, digest = _hash_source(destination, f"copied evidence {item['id']}")
            if size != item["bytes"] or digest != item["sha256"]:
                raise BenchEnduranceError(
                    f"evidence {item['id']} changed during snapshot"
                )
        receipt_path = temporary / RECEIPT_NAME
        receipt_raw = canonical_json_bytes(receipt)
        receipt_path.write_bytes(receipt_raw)
        signing_contract = SIGNING_CONTRACTS[receipt["qualification_class"]]
        key_paths = _stage_key_paths(
            receipt["qualification_class"],
            operator_private_key,
            witness_private_key,
            protocol_reviewer_private_key,
            safety_reviewer_private_key,
        )
        for role, private_key in key_paths.items():
            namespace = signing_contract[role][1]
            signature_path = temporary / SIGNATURE_NAME_BY_ROLE[role]
            signature_path.write_bytes(
                discovery.sign_sshsig_file(receipt_path, private_key, namespace)
            )
            discovery.verify_sshsig_bytes(
                receipt_raw,
                signature_path,
                discovery.inspect_private_key(private_key)["canonical_line"],
                _signer_principal(receipt, role),
                namespace,
            )
        _verify_exact_members(temporary, receipt)
        os.replace(temporary, bundle_out.resolve())
    except discovery.DiscoveryError as exc:
        shutil.rmtree(temporary, ignore_errors=True)
        raise BenchEnduranceError(str(exc)) from exc
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return receipt


def verify_bundle(
    manifest: Mapping[str, Any],
    bundle: Path,
    operator_public_key: Path,
    witness_public_key: Path | None = None,
    expected_operator_key_id: str | None = None,
    expected_witness_key_id: str | None = None,
    *,
    protocol_reviewer_public_key: Path | None = None,
    safety_reviewer_public_key: Path | None = None,
    expected_protocol_reviewer_key_id: str | None = None,
    expected_safety_reviewer_key_id: str | None = None,
) -> dict[str, Any]:
    try:
        metadata = bundle.lstat()
    except OSError as exc:
        raise BenchEnduranceError(f"bundle cannot be inspected: {exc}") from exc
    if discovery._is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise BenchEnduranceError("bundle must be a non-symlink directory")
    receipt_path = bundle / RECEIPT_NAME
    receipt = _load_json(receipt_path, "bench/endurance receipt")
    _validate_receipt(receipt)
    signing_contract = SIGNING_CONTRACTS[receipt["qualification_class"]]
    key_paths = _stage_key_paths(
        receipt["qualification_class"],
        operator_public_key,
        witness_public_key,
        protocol_reviewer_public_key,
        safety_reviewer_public_key,
    )
    try:
        signer_keys = {
            role: discovery.inspect_public_key(path) for role, path in key_paths.items()
        }
        receipt_raw = discovery._read_regular(
            receipt_path, "bench/endurance receipt", MAX_JSON_BYTES
        )
    except discovery.DiscoveryError as exc:
        raise BenchEnduranceError(f"trust/signature input is invalid: {exc}") from exc
    if len({key["key_id_sha256"] for key in signer_keys.values()}) != len(signer_keys):
        raise BenchEnduranceError("stage trust keys must be distinct")
    pinned_ids = {
        "operator": expected_operator_key_id,
        "protocol_reviewer": expected_protocol_reviewer_key_id,
        "safety_reviewer": expected_safety_reviewer_key_id,
        "witness": expected_witness_key_id,
    }
    for role, key in signer_keys.items():
        pinned = pinned_ids[role]
        signature_name = SIGNATURE_NAME_BY_ROLE[role]
        namespace = signing_contract[role][1]
        if pinned is not None and key["key_id_sha256"] != pinned:
            raise BenchEnduranceError(
                f"{role} public key does not match its trust anchor"
            )
        if receipt["signing"][role]["key_id_sha256"] != key["key_id_sha256"]:
            raise BenchEnduranceError(f"receipt {role} signer is not trusted")
        try:
            discovery.verify_sshsig_bytes(
                receipt_raw,
                bundle / signature_name,
                key["canonical_line"],
                _signer_principal(receipt, role),
                namespace,
            )
        except discovery.DiscoveryError as exc:
            raise BenchEnduranceError(f"{role} signature is invalid: {exc}") from exc
    total = 0
    for item in receipt["evidence"]:
        source = _source(
            bundle / EVIDENCE_DIRECTORY,
            _safe_path(item["path"], f"evidence {item['id']} path"),
        )
        size, digest = _hash_source(source, f"evidence {item['id']}")
        total += size
        if total > MAX_TOTAL_EVIDENCE_BYTES:
            raise BenchEnduranceError("evidence exceeds the aggregate byte limit")
        if size != item["bytes"] or digest != item["sha256"]:
            raise BenchEnduranceError(f"evidence {item['id']} digest or size mismatch")
    _validate_semantics(manifest, receipt, bundle / EVIDENCE_DIRECTORY)
    _verify_exact_members(bundle, receipt)
    state_key = {
        QUALIFICATION_FIRST_LIGHT: "first_light",
        QUALIFICATION_BENCH: "bench_mining",
        QUALIFICATION_ENDURANCE: "endurance_faults",
    }[receipt["qualification_class"]]
    signer_key_ids = {role: key["key_id_sha256"] for role, key in signer_keys.items()}
    return {
        "authority_granted": False,
        "bench_mining_gate_eligible": receipt["results"]["bench_mining"]["eligible"],
        "boot_policy_receipt_id": receipt["boot_policy_receipt_id"],
        "capture_receipt_id": receipt["capture_receipt_id"],
        "capture_set_sha256": receipt["capture_set_sha256"],
        "controller_board_revision": receipt["controller_board_revision"],
        "discovery_receipt_id": receipt["discovery_receipt_id"],
        "endurance_faults_gate_eligible": receipt["results"]["endurance_faults"][
            "eligible"
        ],
        "evidence_set_sha256": receipt["evidence_set_sha256"],
        "first_light_gate_eligible": receipt["results"]["first_light"]["eligible"],
        "fixture_evidence_set_sha256": receipt["fixture_evidence_set_sha256"],
        "fixture_receipt_id": receipt["fixture_receipt_id"],
        "artifact_set_sha256": receipt["artifact_set_sha256"],
        "installed_artifact_sha256": receipt["installed_artifact_sha256"],
        "interface_qualification_sha256": receipt["interface_qualification_sha256"],
        "outcome": receipt["outcome"],
        "operator_key_id_sha256": signer_key_ids["operator"],
        "prior_stage_evidence_set_sha256": receipt["prior_stage_evidence_set_sha256"],
        "prior_stage_receipt_id": receipt["prior_stage_receipt_id"],
        "protocol_reviewer_key_id_sha256": signer_key_ids.get("protocol_reviewer"),
        "qualification_class": receipt["qualification_class"],
        "receipt_id": receipt["receipt_id"],
        "recovery_receipt_id": receipt["recovery_receipt_id"],
        "replacement_firmware_version": receipt["replacement_firmware_version"],
        "route_replacement_receipt_id": receipt["route_replacement_receipt_id"],
        "route_rollback_receipt_id": receipt["route_rollback_receipt_id"],
        "route_adjudication_sha256": receipt["route_adjudication_sha256"],
        "safety_reviewer_key_id_sha256": signer_key_ids.get("safety_reviewer"),
        "selected_route": receipt["selected_route"],
        "state": receipt["results"][state_key]["state"],
        "stock_backup_set_sha256": receipt["stock_backup_set_sha256"],
        "no_clobber_sha256": receipt["no_clobber_sha256"],
        "stock_restoration_sha256": receipt["stock_restoration_sha256"],
        "target_id": receipt["target_id"],
        "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
        "unit_label": receipt["unit_label"],
        "variant_profile_id": receipt["variant_profile_id"],
        "witness_key_id_sha256": signer_key_ids.get("witness"),
    }


def _template_evidence(qualification_class: str) -> list[dict[str, Any]]:
    paths = {
        "authorization_record": "records/authorization.json",
        "boot_policy_receipt_copy": "predecessors/boot-policy-receipt.json",
        "bounded_mining_record": "records/bounded-mining.json",
        "capture_receipt_copy": "predecessors/capture-receipt.json",
        "cooling_telemetry_record": "records/cooling-telemetry.json",
        "cutoff_telemetry_record": "records/cutoff-telemetry.json",
        "discovery_receipt_copy": "predecessors/discovery-receipt.json",
        "endurance_record": "records/endurance.json",
        "fault_campaign_record": "records/fault-campaign.json",
        "first_light_record": "records/first-light.json",
        "fixture_receipt_copy": "predecessors/fixture-receipt.json",
        "pool_session_record": "records/pool-session.json",
        "prior_first_light_receipt_copy": "predecessors/prior-first-light-receipt.json",
        "prior_bench_receipt_copy": "predecessors/prior-bench-receipt.json",
        "recovery_receipt_copy": "predecessors/recovery-receipt.json",
        "route_replacement_receipt_copy": (
            "predecessors/route-replacement-receipt.json"
        ),
        "route_rollback_receipt_copy": "predecessors/route-rollback-receipt.json",
        "runtime_telemetry_record": "records/runtime-telemetry.json",
        "safety_record": "records/safety.json",
        "session_log": "records/session-log.json",
        "share_accounting_record": "records/share-accounting.json",
    }
    return [
        {
            "acquired_at_utc": "2026-01-01T00:00:00Z",
            "id": kind.replace("_", "-"),
            "kind": kind,
            "media_type": MEDIA_TYPE_BY_KIND[kind],
            "method": METHOD_BY_KIND[kind],
            "path": paths[kind],
            "redaction": REDACTION_BY_KIND[kind],
        }
        for kind in sorted(_required_kinds(qualification_class))
    ]


def _template(
    manifest: Mapping[str, Any],
    qualification_class: str,
    discovery_path: Path,
    fixture_path: Path,
    capture_path: Path,
    recovery_path: Path,
    boot_path: Path,
    route_replacement_path: Path,
    route_rollback_path: Path,
    prior_stage_path: Path | None,
) -> dict[str, Any]:
    if qualification_class not in QUALIFICATION_CLASSES:
        raise BenchEnduranceError("template qualification class is unsupported")
    documents = {
        "discovery": _load_json(discovery_path, "discovery receipt"),
        "fixture": _load_json(fixture_path, "fixture receipt"),
        "capture": _load_json(capture_path, "capture receipt"),
        "recovery": _load_json(recovery_path, "recovery receipt"),
        "boot": _load_json(boot_path, "boot-policy receipt"),
        "route_replacement": _load_json(
            route_replacement_path, "route-replacement receipt"
        ),
        "route_rollback": _load_json(route_rollback_path, "route-rollback receipt"),
    }
    try:
        discovery._validate_receipt(documents["discovery"], manifest)
        fixture._validate_receipt(documents["fixture"], manifest)
        capture._validate_receipt(documents["capture"], manifest)
        recovery._validate_receipt(documents["recovery"], manifest)
        boot._validate_receipt(documents["boot"], manifest)
        route_replacement._validate_receipt(documents["route_replacement"], manifest)
        route_rollback._validate_receipt(documents["route_rollback"], manifest)
    except Exception as exc:
        raise BenchEnduranceError(f"template predecessor is invalid: {exc}") from exc
    prior_id = None
    prior_evidence_set = None
    if qualification_class != QUALIFICATION_FIRST_LIGHT:
        if prior_stage_path is None:
            raise BenchEnduranceError(
                "bench/endurance template requires --prior-stage-receipt"
            )
        prior = _load_json(prior_stage_path, "prior stage receipt")
        _validate_receipt(prior)
        wanted_class = (
            QUALIFICATION_FIRST_LIGHT
            if qualification_class == QUALIFICATION_BENCH
            else QUALIFICATION_BENCH
        )
        if prior["qualification_class"] != wanted_class or prior["outcome"] != "passed":
            raise BenchEnduranceError(
                "template prior stage is not the immediate passing predecessor"
            )
        prior_id = prior["receipt_id"]
        prior_evidence_set = prior["evidence_set_sha256"]
    elif prior_stage_path is not None:
        raise BenchEnduranceError(
            "first-light template cannot accept a prior stage receipt"
        )
    replacement_receipt = documents["route_replacement"]
    rollback_receipt = documents["route_rollback"]
    selected_route = rollback_receipt["selected_route"]
    template_joins = (
        (
            replacement_receipt["receipt_id"],
            rollback_receipt["route_replacement_receipt_id"],
            "template rollback route-replacement receipt",
        ),
        (
            replacement_receipt["route_selection"]["selected_route"],
            selected_route,
            "template selected route",
        ),
        (
            replacement_receipt["route_selection"]["adjudication_sha256"],
            rollback_receipt["route_adjudication_sha256"],
            "template route adjudication",
        ),
        (
            replacement_receipt["artifact_set_sha256"],
            rollback_receipt["artifact_set_sha256"],
            "template route artifact set",
        ),
        (
            replacement_receipt["interface_qualification_sha256"],
            rollback_receipt["interface_qualification_sha256"],
            "template interface qualification",
        ),
    )
    for observed, wanted, context in template_joins:
        _join(observed, wanted, context)
    common_chain = {
        "boot_policy_receipt_id": documents["boot"]["receipt_id"],
        "discovery_receipt_id": documents["discovery"]["receipt_id"],
        "recovery_receipt_id": documents["recovery"]["receipt_id"],
        "stock_backup_set_sha256": documents["recovery"]["stock_backup_set_sha256"],
        "target_id": documents["discovery"]["target_id"],
        "unit_fingerprint_sha256": documents["discovery"]["unit_fingerprint_sha256"],
        "unit_label": documents["discovery"]["unit_label"],
    }
    for label, document in (
        ("route replacement", replacement_receipt),
        ("route rollback", rollback_receipt),
    ):
        for field, wanted in common_chain.items():
            _join(document[field], wanted, f"template {label} {field}")
    installed_artifact = _installed_artifact_sha256(replacement_receipt, selected_route)
    fixture_receipt = documents["fixture"]
    return {
        "actions_performed": dict(POSITIVE_ACTIONS[qualification_class]),
        "authorization": {
            "authorized_actions": sorted(_actions_for_class(qualification_class)),
            "emergency_stop_owner": "replace-operator",
            "issued_at_utc": "2026-01-01T00:00:00Z",
            "maximum_cutoff_response_ms": 1000,
            "maximum_duration_seconds": (
                900
                if qualification_class == QUALIFICATION_FIRST_LIGHT
                else (
                    3600
                    if qualification_class == QUALIFICATION_BENCH
                    else MIN_ENDURANCE_DURATION_SECONDS
                )
            ),
            "maximum_hash_power_w": 1,
            "maximum_telemetry_gap_ms": 1000,
            "maximum_temperature_millicelsius": 1,
            "operator_reference": "replace-authorization",
            "pool_endpoint_id": "replace-pool",
            "valid_from_utc": "2026-01-01T00:00:01Z",
            "valid_until_utc": "2026-01-01T00:00:02Z",
        },
        "boot_policy_receipt_id": documents["boot"]["receipt_id"],
        "capture_receipt_id": documents["capture"]["receipt_id"],
        "capture_set_sha256": documents["capture"]["capture_set_sha256"],
        "completed_at_utc": "2026-01-01T00:00:02Z",
        "controller_board_revision": fixture_receipt["fixture_identity"][
            "controller_board_revision"
        ],
        "discovery_receipt_id": documents["discovery"]["receipt_id"],
        "evidence": _template_evidence(qualification_class),
        "fixture_evidence_set_sha256": fixture_receipt["fixture_evidence_set_sha256"],
        "fixture_receipt_id": fixture_receipt["receipt_id"],
        "artifact_set_sha256": replacement_receipt["artifact_set_sha256"],
        "installed_artifact_sha256": installed_artifact,
        "interface_qualification_sha256": replacement_receipt[
            "interface_qualification_sha256"
        ],
        "kind": DESCRIPTOR_KIND,
        "operator_id": "replace-operator",
        "outcome": "passed",
        "prior_stage_receipt_id": prior_id,
        "prior_stage_evidence_set_sha256": prior_evidence_set,
        "qualification_class": qualification_class,
        "protocol_reviewer_id": (
            "replace-protocol-reviewer"
            if qualification_class == QUALIFICATION_FIRST_LIGHT
            else None
        ),
        "recovery_receipt_id": documents["recovery"]["receipt_id"],
        "route_replacement_receipt_id": replacement_receipt["receipt_id"],
        "replacement_firmware_version": replacement_receipt["firmware"][
            "firmware_version"
        ],
        "route_rollback_receipt_id": rollback_receipt["receipt_id"],
        "route_adjudication_sha256": rollback_receipt["route_adjudication_sha256"],
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "safety_reviewer_id": (
            "replace-safety-reviewer"
            if qualification_class == QUALIFICATION_FIRST_LIGHT
            else None
        ),
        "session_id": "replace-session",
        "started_at_utc": "2026-01-01T00:00:01Z",
        "stock_backup_set_sha256": documents["recovery"]["stock_backup_set_sha256"],
        "no_clobber_sha256": rollback_receipt["no_clobber_sha256"],
        "stock_restoration_sha256": rollback_receipt["stock_restoration_sha256"],
        "target_id": documents["discovery"]["target_id"],
        "unit_fingerprint_sha256": documents["discovery"]["unit_fingerprint_sha256"],
        "unit_label": documents["discovery"]["unit_label"],
        "variant_profile_id": fixture_receipt["fixture_identity"]["variant_profile_id"],
        "selected_route": selected_route,
        "witness_id": (
            None
            if qualification_class == QUALIFICATION_FIRST_LIGHT
            else "replace-witness"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "gauntlet"
        / "k210_models.json",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser(
        "template", help="write a predecessor-bound descriptor template"
    )
    template.add_argument(
        "--qualification-class", choices=sorted(QUALIFICATION_CLASSES), required=True
    )
    for name in (
        "discovery",
        "fixture",
        "capture",
        "recovery",
        "boot-policy",
        "route-replacement",
        "route-rollback",
    ):
        template.add_argument(f"--{name}-receipt", type=Path, required=True)
    template.add_argument("--prior-stage-receipt", type=Path)
    template.add_argument("--out", type=Path, required=True)
    create = subparsers.add_parser(
        "create", help="snapshot and stage-sign completed evidence"
    )
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--evidence-root", type=Path, required=True)
    create.add_argument("--operator-private-key", type=Path, required=True)
    create.add_argument("--witness-private-key", type=Path)
    create.add_argument("--protocol-reviewer-private-key", type=Path)
    create.add_argument("--safety-reviewer-private-key", type=Path)
    create.add_argument("--bundle-out", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a signed evidence bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--operator-public-key", type=Path, required=True)
    verify.add_argument("--witness-public-key", type=Path)
    verify.add_argument("--protocol-reviewer-public-key", type=Path)
    verify.add_argument("--safety-reviewer-public-key", type=Path)
    verify.add_argument("--expected-operator-key-id")
    verify.add_argument("--expected-witness-key-id")
    verify.add_argument("--expected-protocol-reviewer-key-id")
    verify.add_argument("--expected-safety-reviewer-key-id")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = _load_json(args.manifest, "K210 model manifest", canonical=False)
        if args.command == "template":
            descriptor = _template(
                manifest,
                args.qualification_class,
                args.discovery_receipt,
                args.fixture_receipt,
                args.capture_receipt,
                args.recovery_receipt,
                args.boot_policy_receipt,
                args.route_replacement_receipt,
                args.route_rollback_receipt,
                args.prior_stage_receipt,
            )
            if args.out.exists():
                raise BenchEnduranceError(f"refusing to overwrite template: {args.out}")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_bytes(canonical_json_bytes(descriptor))
            print(
                f"K210_BENCH_ENDURANCE_TEMPLATE_WRITTEN class={args.qualification_class} path={args.out}"
            )
        elif args.command == "create":
            receipt = create_bundle(
                manifest,
                args.descriptor,
                args.evidence_root,
                args.operator_private_key,
                args.bundle_out,
                args.witness_private_key,
                protocol_reviewer_private_key=args.protocol_reviewer_private_key,
                safety_reviewer_private_key=args.safety_reviewer_private_key,
            )
            print(
                f"K210_BENCH_ENDURANCE_BUNDLE_CREATED class={receipt['qualification_class']} "
                f"outcome={receipt['outcome']} receipt={receipt['receipt_id']}"
            )
        else:
            result = verify_bundle(
                manifest,
                args.bundle,
                args.operator_public_key,
                args.witness_public_key,
                args.expected_operator_key_id,
                args.expected_witness_key_id,
                protocol_reviewer_public_key=args.protocol_reviewer_public_key,
                safety_reviewer_public_key=args.safety_reviewer_public_key,
                expected_protocol_reviewer_key_id=args.expected_protocol_reviewer_key_id,
                expected_safety_reviewer_key_id=args.expected_safety_reviewer_key_id,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (BenchEnduranceError, OSError) as exc:
        parser.exit(2, f"K210_BENCH_ENDURANCE_ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
