#!/usr/bin/env python3
"""Validate retained exact-SKU receipts before DCENTaxe production promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "hardware-evidence"
INDEX_PATH = EVIDENCE_ROOT / "index.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MINIMUM_PRODUCTION_SOAK_SECONDS = 259_200
GATE_ARTIFACT_AUTHORITY = "observed-exact-sku-hardware-gate"
SEMANTIC_GATES = {
    "exact-sku-identity",
    "safe-boot",
    "fail-safe-power-cut",
    "trusted-thermal",
    "accepted-share",
    "ota-rollback",
    "sustained-soak",
    "mqtt-command-roundtrip",
    "register-command-capture",
    "dual-fan-proof",
    "hardware-first-article",
    "accessory-first-article",
    "revision-identity",
}


class EvidenceError(ValueError):
    """The retained hardware evidence authority is invalid or incomplete."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_evidence_index(path: Path = INDEX_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise EvidenceError("hardware evidence index root must be an object")
    return data


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError(f"{label} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise EvidenceError(f"{label} must resolve to UTC")
    return parsed


def _finite_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(float(value))


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_gate_measurements(
    gate_name: str,
    measurements: dict[str, Any],
    target: dict[str, Any],
    contract: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    def require_true(field: str) -> None:
        require(measurements.get(field) is True, f"measurements.{field} must be true")

    def require_zero(field: str) -> None:
        require(measurements.get(field) == 0, f"measurements.{field} must be zero")

    if gate_name == "exact-sku-identity":
        require(
            measurements.get("reported_board_target") == target.get("board_target"),
            "measurements.reported_board_target must match the registry row",
        )
        require(
            measurements.get("reported_device_model") == target.get("device_model"),
            "measurements.reported_device_model must match the registry row",
        )
        require(
            measurements.get("reported_asic") == target.get("asic"),
            "measurements.reported_asic must match the registry row",
        )
        require(
            measurements.get("reported_chip_count") == target.get("chip_count"),
            "measurements.reported_chip_count must match the registry row",
        )
        require(
            _nonempty(str(measurements.get("reported_board_version", ""))),
            "measurements.reported_board_version is required",
        )
        require_true("physical_label_verified")
        require_true("runtime_identity_consistent")
    elif gate_name == "safe-boot":
        for field in (
            "identity_gate_passed",
            "boot_completed",
            "sensors_ok",
            "boot_log_retained",
        ):
            require_true(field)
        require_zero("unexpected_reboots")
        require(
            _finite_number(measurements.get("uptime_seconds"))
            and measurements["uptime_seconds"] > 0,
            "measurements.uptime_seconds must be positive",
        )
    elif gate_name == "fail-safe-power-cut":
        require(_nonempty(measurements.get("trigger")), "measurements.trigger is required")
        for field in (
            "hash_work_stopped",
            "rail_cut_observed",
            "independent_measurement",
            "within_board_limit",
            "recovery_required_owner_action",
        ):
            require_true(field)
        require(
            _finite_number(measurements.get("cut_latency_ms"))
            and measurements["cut_latency_ms"] >= 0,
            "measurements.cut_latency_ms must be non-negative",
        )
    elif gate_name == "trusted-thermal":
        require(_nonempty(measurements.get("sensor_source")), "measurements.sensor_source is required")
        for field in (
            "coverage_complete",
            "fault_injected",
            "mining_cut_observed",
            "rail_cut_observed",
            "full_fan_observed",
            "within_board_limit",
        ):
            require_true(field)
        require(
            _finite_number(measurements.get("max_temperature_c")),
            "measurements.max_temperature_c must be finite",
        )
    elif gate_name == "accepted-share":
        require(
            type(measurements.get("accepted_share_delta")) is int
            and measurements["accepted_share_delta"] >= 1,
            "measurements.accepted_share_delta must be at least one",
        )
        require(
            _finite_number(measurements.get("hashrate_5m_ghs"))
            and measurements["hashrate_5m_ghs"] > 0,
            "measurements.hashrate_5m_ghs must be positive",
        )
        require_true("pool_response_observed")
        require_true("post_update")
    elif gate_name == "ota-rollback":
        for field in (
            "signed_update_accepted",
            "bad_signature_rejected",
            "rollback_exercised",
            "previous_slot_restored",
            "recovery_boot_verified",
            "candidate_restored_after_test",
            "accepted_share_after_recovery",
        ):
            require_true(field)
    elif gate_name == "sustained-soak":
        minimum = contract["minimum_soak_seconds"]
        require(
            type(measurements.get("duration_seconds")) is int
            and measurements["duration_seconds"] >= minimum,
            f"measurements.duration_seconds must be at least {minimum}",
        )
        for field in ("uptime_reset_count", "sensor_failure_count", "thermal_cut_count"):
            require_zero(field)
        require(
            type(measurements.get("successful_samples")) is int
            and measurements["successful_samples"] >= 2,
            "measurements.successful_samples must be at least two",
        )
        require(
            type(measurements.get("accepted_share_delta")) is int
            and measurements["accepted_share_delta"] >= 1,
            "measurements.accepted_share_delta must be at least one",
        )
        require(
            _finite_number(measurements.get("rejection_rate_pct"))
            and 0 <= measurements["rejection_rate_pct"] <= 2.0,
            "measurements.rejection_rate_pct must be between zero and two",
        )
        require(
            _finite_number(measurements.get("absolute_heap_drift_bytes"))
            and 0 <= measurements["absolute_heap_drift_bytes"] < 15 * 1024,
            "measurements.absolute_heap_drift_bytes must be below 15 KiB",
        )
        require(
            _finite_number(measurements.get("minimum_hashrate_ghs"))
            and measurements["minimum_hashrate_ghs"] > 0,
            "measurements.minimum_hashrate_ghs must be positive",
        )
    elif gate_name == "mqtt-command-roundtrip":
        for field in (
            "telemetry_received",
            "target_watts_applied",
            "autotune_mode_applied",
            "target_temp_applied",
            "invalid_command_rejected",
            "denied_policy_read_only_verified",
            "stale_discovery_removed",
        ):
            require_true(field)
        require(_nonempty(measurements.get("broker")), "measurements.broker is required")
    elif gate_name == "register-command-capture":
        for field in (
            "command_capture_retained",
            "asic_init_observed",
            "reset_path_observed",
            "independent_decode_review",
        ):
            require_true(field)
        require(
            _nonempty(measurements.get("capture_format")),
            "measurements.capture_format is required",
        )
    elif gate_name == "dual-fan-proof":
        require(
            type(measurements.get("fan_count")) is int and measurements["fan_count"] >= 2,
            "measurements.fan_count must be at least two",
        )
        for field in (
            "fan_1_tach_observed",
            "fan_2_tach_observed",
            "fan_1_stall_safe_action",
            "fan_2_stall_safe_action",
        ):
            require_true(field)
    elif gate_name == "hardware-first-article":
        require(
            _nonempty(measurements.get("schematic_revision")),
            "measurements.schematic_revision is required",
        )
        for field in (
            "physical_article_inspected",
            "power_envelope_validated",
            "thermal_path_validated",
            "mining_path_validated",
        ):
            require_true(field)
    elif gate_name == "accessory-first-article":
        require(
            _nonempty(measurements.get("accessory_identity")),
            "measurements.accessory_identity is required",
        )
        for field in (
            "accessory_detected",
            "base_mining_unaffected",
            "disconnect_safe",
            "owner_safety_ack_verified",
        ):
            require_true(field)
    elif gate_name == "revision-identity":
        require(
            _nonempty(measurements.get("physical_revision")),
            "measurements.physical_revision is required",
        )
        require(
            _nonempty(measurements.get("reported_revision")),
            "measurements.reported_revision is required",
        )
        require_true("revision_match")
        require_true("ambiguous_revision_refused")
    else:
        errors.append(f"no semantic validator exists for gate {gate_name}")
    return errors


def _validate_gate_artifact(
    artifact: Path,
    gate_name: str,
    receipt: dict[str, Any],
    target: dict[str, Any],
    session_started: datetime | None,
    session_finished: datetime | None,
    contract: dict[str, Any],
) -> list[str]:
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"gate {gate_name} artifact must be valid JSON: {exc}"]
    if not isinstance(value, dict):
        return [f"gate {gate_name} artifact root must be an object"]
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(f"gate {gate_name} {message}")

    require(value.get("schema") == contract.get("artifact_schema"), "schema mismatch")
    require(value.get("authority") == contract.get("artifact_authority"), "authority mismatch")
    require(value.get("gate") == gate_name, "gate name mismatch")
    require(value.get("receipt_id") == receipt.get("receipt_id"), "receipt_id mismatch")
    require(value.get("board_target") == target.get("board_target"), "board_target mismatch")
    require(value.get("device_model") == target.get("device_model"), "device_model mismatch")
    require(
        value.get("unit_fingerprint_sha256") == receipt.get("unit_fingerprint_sha256"),
        "unit fingerprint mismatch",
    )
    require(value.get("firmware") == receipt.get("firmware"), "firmware binding mismatch")
    require(value.get("operator") == receipt.get("operator"), "operator mismatch")
    require(value.get("witness") == receipt.get("witness"), "witness mismatch")
    require(value.get("live_device_contact") is True, "live_device_contact must be true")
    require(value.get("passed") is True, "passed must be true")
    try:
        observed_at = _parse_utc(value.get("observed_at"), f"gate {gate_name} observed_at")
        if session_started is not None:
            require(observed_at >= session_started, "observed_at precedes the receipt session")
        if session_finished is not None:
            require(observed_at <= session_finished, "observed_at follows the receipt session")
    except EvidenceError as exc:
        errors.append(str(exc))
    measurements = value.get("measurements")
    require(isinstance(measurements, dict), "measurements must be an object")
    if isinstance(measurements, dict):
        if gate_name == "exact-sku-identity":
            require(
                measurements.get("reported_promotion_receipt_id")
                == receipt.get("receipt_id"),
                "measurements.reported_promotion_receipt_id must match the receipt",
            )
        errors.extend(
            f"gate {gate_name} {message}"
            for message in _validate_gate_measurements(gate_name, measurements, target, contract)
        )
    return errors


def _canonical_candidate_id(value: dict[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "candidate_id"}
    encoded = (json.dumps(body, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _validate_candidate_artifact(
    candidate: dict[str, Any],
    receipt: dict[str, Any],
    target: dict[str, Any],
    matrix: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(f"promotion candidate {message}")

    require(candidate.get("schema") == 1, "schema must be 1")
    require(
        candidate.get("authority") == "unreleased-exact-binary-promotion-candidate",
        "authority mismatch",
    )
    require(
        candidate.get("disposition") == "qualification-only-not-publishable",
        "disposition mismatch",
    )
    require(candidate.get("publishable") is False, "must be non-publishable")
    require(candidate.get("candidate_id") == _canonical_candidate_id(candidate), "ID mismatch")
    require(
        candidate.get("candidate_id")
        == receipt.get("promotion_candidate", {}).get("candidate_id"),
        "ID does not match the receipt",
    )
    require(candidate.get("receipt_id") == receipt.get("receipt_id"), "receipt ID mismatch")
    require(candidate.get("board_target") == target.get("board_target"), "board target mismatch")
    source = candidate.get("source")
    require(isinstance(source, dict), "source must be an object")
    if isinstance(source, dict):
        bindings = {
            "git_commit": "source_git_commit",
            "source_date_epoch": "source_date_epoch",
            "registry_sha256": "source_registry_sha256",
        }
        for source_field, receipt_field in bindings.items():
            require(
                source.get(source_field)
                == receipt.get("promotion_candidate", {}).get(receipt_field),
                f"{source_field} does not match the receipt",
            )
        require(source.get("firmware_version") == receipt.get("firmware", {}).get("version"), "firmware version mismatch")
        require(source.get("git_dirty") is False, "source must be clean")
    row = candidate.get("registry_row")
    require(isinstance(row, dict), "registry row must be an object")
    if isinstance(row, dict):
        for field in (
            "feature",
            "board_target",
            "device_model",
            "model_variant",
            "hardware_family",
            "asic",
            "chip_count",
            "flash_layout",
        ):
            require(row.get(field) == target.get(field), f"immutable field {field} mismatch")
        final = {
            "support_tier": "production",
            "evidence_level": "sustained-soak",
            "runtime_mode": "mining",
            "install_policy": "production",
            "release_scope": "public",
            "package_policy": "public",
            "blockers": [],
            "promotion_receipt_id": receipt.get("receipt_id"),
        }
        for field, expected in final.items():
            require(row.get(field) == expected, f"final field {field} mismatch")
    try:
        require(
            candidate.get("required_gates") == required_production_gates(matrix, target),
            "effective gate snapshot mismatch",
        )
    except EvidenceError as exc:
        errors.append(str(exc))
    return errors


def _safe_evidence_path(evidence_root: Path, value: Any, label: str, prefix: str) -> Path:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be a non-empty relative path")
    pure = PurePosixPath(value)
    if not pure.parts or pure.is_absolute() or ".." in pure.parts or pure.parts[0] != prefix:
        raise EvidenceError(f"{label} must stay under {prefix}/")
    resolved_root = evidence_root.resolve()
    resolved = (evidence_root / Path(*pure.parts)).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise EvidenceError(f"{label} escapes the hardware-evidence root") from exc
    return resolved


def required_production_gates(matrix: dict[str, Any], target: dict[str, Any]) -> list[str]:
    contract = matrix.get("production_gate_contract")
    if not isinstance(contract, dict):
        raise EvidenceError("esp-targets.json must define production_gate_contract")
    required = contract.get("required")
    family_additions = contract.get("family_additions")
    target_additions = contract.get("target_additions")
    if not isinstance(required, list) or not required:
        raise EvidenceError("production_gate_contract.required must be a non-empty array")
    if not isinstance(family_additions, dict) or not isinstance(target_additions, dict):
        raise EvidenceError("production gate additions must be objects")
    gates = [*required]
    gates.extend(family_additions.get(target.get("hardware_family"), []))
    gates.extend(target_additions.get(target.get("board_target"), []))
    if any(not isinstance(gate, str) or not gate for gate in gates):
        raise EvidenceError("all production gate names must be non-empty strings")
    if len(gates) != len(set(gates)):
        raise EvidenceError(f"{target.get('board_target')}: duplicate effective production gate")
    return gates


def _validate_contract(matrix: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    contract = matrix.get("production_gate_contract")
    if not isinstance(contract, dict):
        return ["esp-targets.json must define production_gate_contract"]
    if contract.get("artifact_schema") != 1:
        errors.append("production gate artifact schema must be 1")
    if contract.get("artifact_authority") != GATE_ARTIFACT_AUTHORITY:
        errors.append("production gate artifact authority mismatch")
    soak = contract.get("minimum_soak_seconds")
    if type(soak) is not int or soak < MINIMUM_PRODUCTION_SOAK_SECONDS:
        errors.append(
            f"production minimum soak must be at least {MINIMUM_PRODUCTION_SOAK_SECONDS} seconds"
        )
    try:
        for target in matrix.get("targets") or []:
            gates = required_production_gates(matrix, target)
            missing_semantics = sorted(set(gates) - SEMANTIC_GATES)
            if missing_semantics:
                errors.append(
                    f"{target.get('board_target')}: production gates lack semantic validators: "
                    f"{missing_semantics}"
                )
    except EvidenceError as exc:
        errors.append(str(exc))
    return errors


def _load_indexed_receipt(
    entry: dict[str, Any], evidence_root: Path
) -> tuple[dict[str, Any], Path]:
    receipt_id = entry.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        raise EvidenceError("receipt index entry needs a non-empty receipt_id")
    expected_sha = entry.get("sha256")
    if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha):
        raise EvidenceError(f"{receipt_id}: index sha256 must be lowercase hex")
    path = _safe_evidence_path(
        evidence_root, entry.get("path"), f"{receipt_id}: receipt path", "receipts"
    )
    if not path.is_file():
        raise EvidenceError(f"{receipt_id}: receipt file does not exist: {path}")
    actual_sha = sha256_file(path)
    if actual_sha != expected_sha:
        raise EvidenceError(
            f"{receipt_id}: receipt sha256 mismatch: index={expected_sha} actual={actual_sha}"
        )
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{receipt_id}: receipt JSON cannot be read: {exc}") from exc
    if not isinstance(receipt, dict):
        raise EvidenceError(f"{receipt_id}: receipt root must be an object")
    return receipt, path


def _validate_receipt(
    receipt: dict[str, Any],
    entry: dict[str, Any],
    matrix: dict[str, Any],
    evidence_root: Path,
) -> list[str]:
    receipt_id = entry["receipt_id"]
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(f"{receipt_id}: {message}")

    require(receipt.get("schema") == 1, "receipt schema must be 1")
    require(receipt.get("receipt_id") == receipt_id, "receipt_id does not match index")
    require(receipt.get("live_device_contact") is True, "live_device_contact must be true")
    unit_fingerprint = receipt.get("unit_fingerprint_sha256")
    require(
        isinstance(unit_fingerprint, str) and bool(SHA256_RE.fullmatch(unit_fingerprint)),
        "unit_fingerprint_sha256 must be lowercase hex",
    )
    operator = receipt.get("operator")
    witness = receipt.get("witness")
    require(isinstance(operator, str) and bool(operator.strip()), "operator is required")
    require(isinstance(witness, str) and bool(witness.strip()), "witness is required")
    require(operator != witness, "operator and witness must be distinct")

    targets = {
        target.get("board_target"): target
        for target in matrix.get("targets") or []
        if isinstance(target, dict)
    }
    target = targets.get(receipt.get("board_target"))
    require(target is not None, "board_target is not registered")
    if target is not None:
        require(
            receipt.get("device_model") == target.get("device_model"),
            "device_model does not match the exact registry row",
        )

    firmware = receipt.get("firmware")
    require(isinstance(firmware, dict), "firmware must be an object")
    if isinstance(firmware, dict):
        require(
            isinstance(firmware.get("version"), str) and bool(firmware.get("version")),
            "firmware.version is required",
        )
        update_sha = firmware.get("update_sha256")
        require(
            isinstance(update_sha, str) and bool(SHA256_RE.fullmatch(update_sha)),
            "firmware.update_sha256 must be lowercase hex",
        )

    candidate = receipt.get("promotion_candidate")
    require(isinstance(candidate, dict), "promotion_candidate must be an object")
    if isinstance(candidate, dict):
        require(
            isinstance(candidate.get("candidate_id"), str)
            and bool(SHA256_RE.fullmatch(candidate["candidate_id"])),
            "promotion_candidate.candidate_id must be lowercase hex",
        )
        require(
            isinstance(candidate.get("descriptor_sha256"), str)
            and bool(SHA256_RE.fullmatch(candidate["descriptor_sha256"])),
            "promotion_candidate.descriptor_sha256 must be lowercase hex",
        )
        descriptor_artifact = candidate.get("descriptor_artifact")
        require(
            isinstance(descriptor_artifact, str) and bool(descriptor_artifact),
            "promotion_candidate.descriptor_artifact is required",
        )
        require(
            isinstance(candidate.get("source_git_commit"), str)
            and bool(re.fullmatch(r"[0-9a-f]{40}", candidate["source_git_commit"])),
            "promotion_candidate.source_git_commit must be 40 lowercase hex characters",
        )
        require(
            isinstance(candidate.get("source_date_epoch"), str)
            and candidate["source_date_epoch"].isdigit(),
            "promotion_candidate.source_date_epoch must be a decimal string",
        )
        require(
            isinstance(candidate.get("source_registry_sha256"), str)
            and bool(SHA256_RE.fullmatch(candidate["source_registry_sha256"])),
            "promotion_candidate.source_registry_sha256 must be lowercase hex",
        )
        if target is not None and isinstance(descriptor_artifact, str):
            try:
                descriptor_path = _safe_evidence_path(
                    evidence_root,
                    descriptor_artifact,
                    f"{receipt_id}: promotion candidate descriptor",
                    "artifacts",
                )
                require(descriptor_path.is_file(), "promotion candidate descriptor does not exist")
                if descriptor_path.is_file():
                    actual_descriptor_sha = sha256_file(descriptor_path)
                    require(
                        actual_descriptor_sha == candidate.get("descriptor_sha256"),
                        "promotion candidate descriptor sha256 mismatch",
                    )
                    if actual_descriptor_sha == candidate.get("descriptor_sha256"):
                        try:
                            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError) as exc:
                            errors.append(
                                f"{receipt_id}: promotion candidate descriptor is invalid JSON: {exc}"
                            )
                        else:
                            if not isinstance(descriptor, dict):
                                errors.append(
                                    f"{receipt_id}: promotion candidate descriptor must be an object"
                                )
                            else:
                                errors.extend(
                                    f"{receipt_id}: {message}"
                                    for message in _validate_candidate_artifact(
                                        descriptor, receipt, target, matrix
                                    )
                                )
            except EvidenceError as exc:
                errors.append(str(exc))

    session = receipt.get("session")
    require(isinstance(session, dict), "session must be an object")
    duration = None
    started = None
    finished = None
    if isinstance(session, dict):
        try:
            started = _parse_utc(session.get("started_at"), f"{receipt_id}: session.started_at")
            finished = _parse_utc(session.get("finished_at"), f"{receipt_id}: session.finished_at")
            duration = session.get("duration_seconds")
            require(finished > started, "session.finished_at must be after started_at")
            require(type(duration) is int and duration > 0, "session duration must be positive")
            if type(duration) is int:
                observed = int((finished - started).total_seconds())
                require(abs(observed - duration) <= 5, "session duration does not match timestamps")
        except EvidenceError as exc:
            errors.append(str(exc))

    gates = receipt.get("gates")
    require(isinstance(gates, dict), "gates must be an object")
    if target is not None and isinstance(gates, dict):
        try:
            required = required_production_gates(matrix, target)
        except EvidenceError as exc:
            errors.append(f"{receipt_id}: {exc}")
            required = []
        artifact_paths: set[Path] = set()
        for gate_name in required:
            gate = gates.get(gate_name)
            require(isinstance(gate, dict), f"missing required gate {gate_name}")
            if not isinstance(gate, dict):
                continue
            require(gate.get("passed") is True, f"gate {gate_name} must pass")
            expected_sha = gate.get("sha256")
            require(
                isinstance(expected_sha, str) and bool(SHA256_RE.fullmatch(expected_sha)),
                f"gate {gate_name} sha256 must be lowercase hex",
            )
            try:
                artifact = _safe_evidence_path(
                    evidence_root,
                    gate.get("artifact"),
                    f"{receipt_id}: gate {gate_name} artifact",
                    "artifacts",
                )
                require(artifact.is_file(), f"gate {gate_name} artifact does not exist")
                require(
                    artifact not in artifact_paths,
                    f"gate {gate_name} artifact path is reused by another gate",
                )
                artifact_paths.add(artifact)
                if artifact.is_file() and isinstance(expected_sha, str):
                    require(
                        sha256_file(artifact) == expected_sha,
                        f"gate {gate_name} artifact sha256 mismatch",
                    )
                    if sha256_file(artifact) == expected_sha:
                        errors.extend(
                            f"{receipt_id}: {message}"
                            for message in _validate_gate_artifact(
                                artifact,
                                gate_name,
                                receipt,
                                target,
                                started,
                                finished,
                                matrix["production_gate_contract"],
                            )
                        )
            except EvidenceError as exc:
                errors.append(str(exc))

        if "sustained-soak" in required:
            minimum = matrix["production_gate_contract"]["minimum_soak_seconds"]
            require(
                type(duration) is int and duration >= minimum,
                f"sustained soak must be at least {minimum} seconds",
            )
    return errors


def validate_evidence_index(
    index: dict[str, Any], matrix: dict[str, Any], root: Path = ROOT
) -> list[str]:
    evidence_root = root / "hardware-evidence"
    errors = _validate_contract(matrix)
    if index.get("schema") != 1:
        errors.append("hardware evidence index schema must be 1")
    if index.get("product") != "DCENT_OS for ESP":
        errors.append("hardware evidence index product mismatch")
    if index.get("authority") != "retained-exact-sku-hardware-receipts":
        errors.append("hardware evidence index authority mismatch")
    entries = index.get("receipts")
    if not isinstance(entries, list):
        errors.append("hardware evidence index receipts must be an array")
        return errors

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"receipt index entry {position} must be an object")
            continue
        receipt_id = entry.get("receipt_id")
        path = entry.get("path")
        if isinstance(receipt_id, str):
            if receipt_id in seen_ids:
                errors.append(f"duplicate receipt_id {receipt_id}")
            seen_ids.add(receipt_id)
        if isinstance(path, str):
            if path in seen_paths:
                errors.append(f"duplicate receipt path {path}")
            seen_paths.add(path)
        try:
            receipt, _ = _load_indexed_receipt(entry, evidence_root)
            errors.extend(_validate_receipt(receipt, entry, matrix, evidence_root))
        except EvidenceError as exc:
            errors.append(str(exc))
    return errors


def promotion_status(
    index: dict[str, Any], matrix: dict[str, Any], target: dict[str, Any], root: Path = ROOT
) -> dict[str, Any]:
    receipt_id = target.get("promotion_receipt_id")
    required = required_production_gates(matrix, target)
    status = {
        "required_gates": required,
        "receipt_id": receipt_id,
        "qualified": False,
        "reason": "no exact-SKU promotion receipt is bound",
    }
    if not isinstance(receipt_id, str) or not receipt_id:
        return status
    entry = next(
        (
            item
            for item in index.get("receipts") or []
            if isinstance(item, dict) and item.get("receipt_id") == receipt_id
        ),
        None,
    )
    if entry is None:
        status["reason"] = "bound promotion receipt is absent from the evidence index"
        return status
    errors = validate_evidence_index(index, matrix, root)
    if errors:
        status["reason"] = "hardware evidence index is invalid"
        status["errors"] = errors
        return status
    receipt, _ = _load_indexed_receipt(entry, root / "hardware-evidence")
    if receipt.get("board_target") != target.get("board_target"):
        status["reason"] = "receipt is bound to a different board target"
        return status
    if receipt.get("device_model") != target.get("device_model"):
        status["reason"] = "receipt is bound to a different device model"
        return status
    status["qualified"] = True
    status["reason"] = "exact-SKU retained hardware receipt satisfies the production gate contract"
    status["unit_fingerprint_sha256"] = receipt.get("unit_fingerprint_sha256")
    status["firmware_version"] = receipt.get("firmware", {}).get("version")
    status["firmware_update_sha256"] = receipt.get("firmware", {}).get("update_sha256")
    status["promotion_candidate_id"] = receipt.get("promotion_candidate", {}).get(
        "candidate_id"
    )
    return status


def production_claim_errors(
    matrix: dict[str, Any], index: dict[str, Any], root: Path = ROOT
) -> list[str]:
    errors = validate_evidence_index(index, matrix, root)
    for target in matrix.get("targets") or []:
        if not isinstance(target, dict):
            continue
        label = target.get("board_target", "unknown")
        claims_production = (
            target.get("support_tier") == "production"
            or target.get("install_policy") == "production"
            or target.get("blockers") == []
        )
        if not claims_production:
            continue
        expected = {
            "support_tier": "production",
            "evidence_level": "sustained-soak",
            "runtime_mode": "mining",
            "install_policy": "production",
            "release_scope": "public",
            "package_policy": "public",
            "blockers": [],
        }
        for field, value in expected.items():
            if target.get(field) != value:
                errors.append(
                    f"{label}: production claim requires {field}={value!r}, got {target.get(field)!r}"
                )
        try:
            status = promotion_status(index, matrix, target, root)
            if not status["qualified"]:
                errors.append(f"{label}: production claim refused: {status['reason']}")
        except EvidenceError as exc:
            errors.append(f"{label}: production claim refused: {exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=INDEX_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Validate the index, receipt bindings, and artifact hashes")
    status_parser = sub.add_parser("status", help="Render exact-SKU promotion receipt status")
    status_parser.add_argument("--scope", choices=("public", "internal", "all"), default="all")
    args = parser.parse_args(argv)

    try:
        from target_matrix import load_manifest, require_valid, targets_for_scope

        matrix = load_manifest()
        index = load_evidence_index(args.index)
        errors = production_claim_errors(matrix, index, ROOT)
        if errors:
            raise EvidenceError("\n".join(f"- {error}" for error in errors))
        # Source bindings are checked after evidence to avoid a circular call to
        # require_valid from target_matrix's own evidence integration.
        if args.command == "validate":
            print(f"ESP hardware evidence valid: {len(index['receipts'])} retained receipts")
        else:
            require_valid(matrix, validate_evidence=False)
            rows = []
            for target in targets_for_scope(matrix, args.scope):
                status = promotion_status(index, matrix, target, ROOT)
                rows.append(
                    {
                        "board_target": target["board_target"],
                        "production_metadata": target.get("support_tier") == "production",
                        **status,
                    }
                )
            print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"hardware evidence error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
