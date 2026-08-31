#!/usr/bin/env python3
"""Plan, resume, and finalize authorization-gated exact-SKU hardware sessions.

This tool never opens a network or serial connection. It turns a verified,
signed qualification package into an operator-owned evidence workspace, then
admits a receipt only after every typed gate artifact passes the retained
hardware-evidence validator.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hardware_evidence import (
    EVIDENCE_ROOT,
    GATE_ARTIFACT_AUTHORITY,
    SHA256_RE,
    _parse_utc,
    _validate_gate_artifact,
    load_evidence_index,
    required_production_gates,
    sha256_file,
    validate_evidence_index,
)
from promotion_candidate import load_descriptor, require_valid_descriptor
from target_matrix import MANIFEST_PATH, ROOT, find_target, load_manifest, require_valid
from verify_ota_package import payload_map, resolve_payload, verify_manifest

AUTHORITY = "authorization-gated-exact-sku-hardware-session"


class SessionError(ValueError):
    """The hardware session is unsafe, incomplete, stale, or inconsistent."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path: Path, data: bytes) -> None:
    if path.exists():
        raise SessionError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def measurement_template(gate: str, target: dict[str, Any]) -> dict[str, Any]:
    templates: dict[str, dict[str, Any]] = {
        "exact-sku-identity": {
            "reported_board_target": target["board_target"],
            "reported_device_model": target["device_model"],
            "reported_asic": target["asic"],
            "reported_chip_count": target["chip_count"],
            "reported_board_version": None,
            "reported_promotion_receipt_id": None,
            "physical_label_verified": False,
            "runtime_identity_consistent": False,
        },
        "safe-boot": {
            "identity_gate_passed": False,
            "boot_completed": False,
            "sensors_ok": False,
            "boot_log_retained": False,
            "unexpected_reboots": None,
            "uptime_seconds": None,
        },
        "fail-safe-power-cut": {
            "trigger": None,
            "hash_work_stopped": False,
            "rail_cut_observed": False,
            "independent_measurement": False,
            "within_board_limit": False,
            "recovery_required_owner_action": False,
            "cut_latency_ms": None,
        },
        "trusted-thermal": {
            "sensor_source": None,
            "coverage_complete": False,
            "fault_injected": False,
            "mining_cut_observed": False,
            "rail_cut_observed": False,
            "full_fan_observed": False,
            "within_board_limit": False,
            "max_temperature_c": None,
        },
        "accepted-share": {
            "accepted_share_delta": None,
            "hashrate_5m_ghs": None,
            "pool_response_observed": False,
            "post_update": False,
        },
        "ota-rollback": {
            "signed_update_accepted": False,
            "bad_signature_rejected": False,
            "rollback_exercised": False,
            "previous_slot_restored": False,
            "recovery_boot_verified": False,
            "candidate_restored_after_test": False,
            "accepted_share_after_recovery": False,
        },
        "sustained-soak": {
            "duration_seconds": None,
            "uptime_reset_count": None,
            "sensor_failure_count": None,
            "thermal_cut_count": None,
            "successful_samples": None,
            "accepted_share_delta": None,
            "rejection_rate_pct": None,
            "absolute_heap_drift_bytes": None,
            "minimum_hashrate_ghs": None,
        },
        "mqtt-command-roundtrip": {
            "telemetry_received": False,
            "target_watts_applied": False,
            "autotune_mode_applied": False,
            "target_temp_applied": False,
            "invalid_command_rejected": False,
            "denied_policy_read_only_verified": False,
            "stale_discovery_removed": False,
            "broker": None,
        },
        "register-command-capture": {
            "command_capture_retained": False,
            "asic_init_observed": False,
            "reset_path_observed": False,
            "independent_decode_review": False,
            "capture_format": None,
        },
        "dual-fan-proof": {
            "fan_count": None,
            "fan_1_tach_observed": False,
            "fan_2_tach_observed": False,
            "fan_1_stall_safe_action": False,
            "fan_2_stall_safe_action": False,
        },
        "hardware-first-article": {
            "schematic_revision": None,
            "physical_article_inspected": False,
            "power_envelope_validated": False,
            "thermal_path_validated": False,
            "mining_path_validated": False,
        },
        "accessory-first-article": {
            "accessory_identity": None,
            "accessory_detected": False,
            "base_mining_unaffected": False,
            "disconnect_safe": False,
            "owner_safety_ack_verified": False,
        },
        "revision-identity": {
            "physical_revision": None,
            "reported_revision": None,
            "revision_match": False,
            "ambiguous_revision_refused": False,
        },
    }
    if gate not in templates:
        raise SessionError(f"no measurement template exists for gate {gate}")
    return templates[gate]


def new_session(
    matrix: dict[str, Any],
    descriptor: dict[str, Any],
    descriptor_sha256: str,
    manifest_path: Path,
    manifest: dict[str, Any],
    update_sha256: str,
    unit_fingerprint_sha256: str,
    operator: str,
    witness: str,
) -> dict[str, Any]:
    target = find_target(matrix, descriptor["board_target"])
    if not SHA256_RE.fullmatch(unit_fingerprint_sha256):
        raise SessionError("unit fingerprint must be 64 lowercase hex characters")
    if not operator.strip() or not witness.strip() or operator == witness:
        raise SessionError("operator and distinct witness are required")
    gates = required_production_gates(matrix, target)
    return {
        "schema": 1,
        "product": "DCENT_OS for ESP",
        "authority": AUTHORITY,
        "state": "planned-offline",
        "live_device_contact": False,
        "receipt_id": descriptor["receipt_id"],
        "board_target": target["board_target"],
        "device_model": target["device_model"],
        "unit_fingerprint_sha256": unit_fingerprint_sha256,
        "operator": operator,
        "witness": witness,
        "firmware": {
            "version": manifest["version"],
            "update_sha256": update_sha256,
        },
        "promotion_candidate": {
            "candidate_id": descriptor["candidate_id"],
            "descriptor_sha256": descriptor_sha256,
            "session_descriptor": "promotion-candidate.json",
            "source_git_commit": descriptor["source"]["git_commit"],
            "source_date_epoch": descriptor["source"]["source_date_epoch"],
            "source_registry_sha256": descriptor["source"]["registry_sha256"],
        },
        "package": {
            "manifest_source": str(manifest_path.resolve()),
            "manifest_sha256": sha256_file(manifest_path),
            "ota_key_id": manifest.get("otaKeyId"),
            "signatures_verified": True,
            "qualification_only": True,
        },
        "planned_at": utc_now(),
        "started_at": None,
        "finished_at": None,
        "authorization": None,
        "gates": {
            gate: {"state": "pending", "artifact": f"gates/{gate}.json"}
            for gate in gates
        },
        "next_actions": [
            f"Authorize with confirmation authorize-live-{descriptor['receipt_id']}.",
            "Run only the operator-approved serial/network gate commands from the bench runbook.",
            "Fill each gate JSON from observed evidence; never convert a planned value into an observation.",
            f"After at least {matrix['production_gate_contract']['minimum_soak_seconds']} seconds, finalize with a distinct witness.",
        ],
    }


def gate_artifact_template(
    session: dict[str, Any], gate: str, target: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema": 1,
        "authority": GATE_ARTIFACT_AUTHORITY,
        "gate": gate,
        "receipt_id": session["receipt_id"],
        "board_target": session["board_target"],
        "device_model": session["device_model"],
        "unit_fingerprint_sha256": session["unit_fingerprint_sha256"],
        "firmware": session["firmware"],
        "operator": session["operator"],
        "witness": session["witness"],
        "live_device_contact": session["live_device_contact"],
        "observed_at": None,
        "passed": False,
        "measurements": measurement_template(gate, target),
    }


def load_session(directory: Path) -> tuple[dict[str, Any], Path]:
    directory = directory.resolve()
    path = directory / "session.json"
    try:
        session = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"cannot read hardware session {path}: {exc}") from exc
    if not isinstance(session, dict) or session.get("authority") != AUTHORITY:
        raise SessionError("hardware session authority mismatch")
    return session, directory


def authorize_session(
    session: dict[str, Any],
    directory: Path,
    operator: str,
    confirmation: str,
    started_at: str,
) -> None:
    if session.get("state") != "planned-offline" or session.get("live_device_contact") is not False:
        raise SessionError("only a planned offline session can be authorized")
    if operator != session.get("operator"):
        raise SessionError("authorization operator does not match the planned operator")
    expected = f"authorize-live-{session['receipt_id']}"
    if confirmation != expected:
        raise SessionError(f"confirmation must be {expected}")
    _parse_utc(started_at, "session.started_at")
    session["state"] = "authorized-live"
    session["live_device_contact"] = True
    session["started_at"] = started_at
    session["authorization"] = {
        "operator": operator,
        "confirmed_at": utc_now(),
        "confirmation": expected,
        "scope": "exact-candidate exact-SKU bench qualification",
    }
    for gate in session["gates"]:
        path = directory / "gates" / f"{gate}.json"
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["live_device_contact"] = True
        write_atomic(path, json_bytes(artifact))
    write_atomic(directory / "session.json", json_bytes(session))


def receipt_from_session(
    session: dict[str, Any], directory: Path, finished_at: str
) -> dict[str, Any]:
    started = _parse_utc(session.get("started_at"), "session.started_at")
    finished = _parse_utc(finished_at, "session.finished_at")
    if finished <= started:
        raise SessionError("session finish must follow its start")
    duration = int((finished - started).total_seconds())
    gates: dict[str, Any] = {}
    for gate, record in session["gates"].items():
        path = (directory / record["artifact"]).resolve()
        try:
            path.relative_to(directory)
        except ValueError as exc:
            raise SessionError(f"gate {gate} escapes the session directory") from exc
        if not path.is_file():
            raise SessionError(f"gate {gate} artifact is missing")
        gates[gate] = {
            "passed": True,
            "artifact": f"artifacts/{session['receipt_id']}/{gate}.json",
            "sha256": sha256_file(path),
        }
    candidate = dict(session["promotion_candidate"])
    candidate.pop("session_descriptor", None)
    candidate["descriptor_artifact"] = (
        f"artifacts/{session['receipt_id']}/promotion-candidate.json"
    )
    return {
        "schema": 1,
        "receipt_id": session["receipt_id"],
        "board_target": session["board_target"],
        "device_model": session["device_model"],
        "unit_fingerprint_sha256": session["unit_fingerprint_sha256"],
        "firmware": session["firmware"],
        "promotion_candidate": candidate,
        "operator": session["operator"],
        "witness": session["witness"],
        "live_device_contact": True,
        "session": {
            "started_at": session["started_at"],
            "finished_at": finished_at,
            "duration_seconds": duration,
        },
        "gates": gates,
    }


def validate_completed_gates(
    session: dict[str, Any], directory: Path, matrix: dict[str, Any], receipt: dict[str, Any]
) -> list[str]:
    target = find_target(matrix, session["board_target"])
    started = _parse_utc(receipt["session"]["started_at"], "session.started_at")
    finished = _parse_utc(receipt["session"]["finished_at"], "session.finished_at")
    errors: list[str] = []
    for gate, record in session["gates"].items():
        artifact = directory / record["artifact"]
        errors.extend(
            _validate_gate_artifact(
                artifact,
                gate,
                receipt,
                target,
                started,
                finished,
                matrix["production_gate_contract"],
            )
        )
    return errors


def session_status(session: dict[str, Any], directory: Path, matrix: dict[str, Any]) -> dict[str, Any]:
    target = find_target(matrix, session["board_target"])
    completed: list[str] = []
    pending: list[str] = []
    invalid: dict[str, list[str]] = {}
    receipt = {
        "receipt_id": session["receipt_id"],
        "unit_fingerprint_sha256": session["unit_fingerprint_sha256"],
        "firmware": session["firmware"],
        "operator": session["operator"],
        "witness": session["witness"],
    }
    started = None
    if session.get("started_at"):
        started = _parse_utc(session["started_at"], "session.started_at")
    for gate, record in session["gates"].items():
        path = directory / record["artifact"]
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            invalid[gate] = [str(exc)]
            continue
        if artifact.get("passed") is not True:
            pending.append(gate)
            continue
        errors = _validate_gate_artifact(
            path,
            gate,
            receipt,
            target,
            started,
            None,
            matrix["production_gate_contract"],
        )
        if errors:
            invalid[gate] = errors
        else:
            completed.append(gate)
    return {
        "state": session["state"],
        "receipt_id": session["receipt_id"],
        "board_target": session["board_target"],
        "live_device_contact": session["live_device_contact"],
        "completed_gates": completed,
        "pending_gates": pending,
        "invalid_gates": invalid,
        "finalizable": session["state"] == "authorized-live" and not pending and not invalid,
    }


def finalize_session(
    session: dict[str, Any],
    directory: Path,
    matrix: dict[str, Any],
    evidence_root: Path,
    finished_at: str,
    confirmation: str,
) -> Path:
    if session.get("state") != "authorized-live" or session.get("live_device_contact") is not True:
        raise SessionError("session is not authorized for live evidence")
    expected = f"finalize-{session['receipt_id']}"
    if confirmation != expected:
        raise SessionError(f"confirmation must be {expected}")
    receipt = receipt_from_session(session, directory, finished_at)
    errors = validate_completed_gates(session, directory, matrix, receipt)
    if errors:
        raise SessionError("\n".join(f"- {error}" for error in errors))

    receipt_id = session["receipt_id"]
    evidence_root = evidence_root.resolve()
    artifact_target = evidence_root / "artifacts" / receipt_id
    receipt_target = evidence_root / "receipts" / f"{receipt_id}.json"
    if artifact_target.exists() or receipt_target.exists():
        raise SessionError("refusing to overwrite retained hardware evidence")
    index_path = evidence_root / "index.json"
    index = load_evidence_index(index_path)
    if any(entry.get("receipt_id") == receipt_id for entry in index["receipts"]):
        raise SessionError(f"receipt {receipt_id} is already indexed")

    with tempfile.TemporaryDirectory(prefix="dcentaxe-evidence-stage-") as temporary:
        stage_root = Path(temporary)
        stage_evidence = stage_root / "hardware-evidence"
        stage_artifacts = stage_evidence / "artifacts" / receipt_id
        stage_artifacts.mkdir(parents=True)
        session_descriptor = directory / session["promotion_candidate"]["session_descriptor"]
        if not session_descriptor.is_file():
            raise SessionError("retained promotion candidate descriptor is missing from the session")
        if sha256_file(session_descriptor) != session["promotion_candidate"]["descriptor_sha256"]:
            raise SessionError("retained promotion candidate descriptor SHA-256 mismatch")
        shutil.copy2(session_descriptor, stage_artifacts / "promotion-candidate.json")
        for gate, record in session["gates"].items():
            shutil.copy2(directory / record["artifact"], stage_artifacts / f"{gate}.json")
        stage_receipt = stage_evidence / "receipts" / f"{receipt_id}.json"
        stage_receipt.parent.mkdir(parents=True)
        stage_receipt.write_bytes(json_bytes(receipt))
        staged_index = json.loads(json.dumps(index))
        staged_index["receipts"].append(
            {
                "receipt_id": receipt_id,
                "path": f"receipts/{receipt_id}.json",
                "sha256": sha256_file(stage_receipt),
            }
        )
        (stage_evidence / "index.json").write_bytes(json_bytes(staged_index))
        validation_errors = validate_evidence_index(staged_index, matrix, stage_root)
        if validation_errors:
            raise SessionError("\n".join(f"- {error}" for error in validation_errors))

        artifact_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage_artifacts, artifact_target)
        write_new(receipt_target, stage_receipt.read_bytes())
        write_atomic(index_path, json_bytes(staged_index))

    session["state"] = "finalized-retained"
    session["finished_at"] = finished_at
    session["retained_receipt"] = f"receipts/{receipt_id}.json"
    write_atomic(directory / "session.json", json_bytes(session))
    return receipt_target


def plan_session(args: argparse.Namespace) -> None:
    matrix = load_manifest()
    require_valid(matrix)
    descriptor_path = args.candidate.resolve()
    descriptor = load_descriptor(descriptor_path)
    require_valid_descriptor(descriptor, matrix, sha256_file(MANIFEST_PATH))
    target = find_target(matrix, descriptor["board_target"])
    partitions = ROOT / (
        "partitions-16mb.csv" if target["flash_layout"] == "n16r8" else "partitions.csv"
    )
    if not args.public_key_hex:
        raise SessionError("a public key is required to verify the qualification package")
    verify_manifest(
        args.manifest,
        args.public_key_hex,
        True,
        partitions,
        False,
        False,
        True,
        descriptor_path,
    )
    manifest_path = args.manifest.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    _update_path, _update_data, update_sha = resolve_payload(
        manifest_path.parent, payload_map(manifest), "update"
    )
    session = new_session(
        matrix,
        descriptor,
        sha256_file(descriptor_path),
        manifest_path,
        manifest,
        update_sha,
        args.unit_fingerprint_sha256,
        args.operator,
        args.witness,
    )
    output = args.output.resolve()
    if output.exists():
        raise SessionError(f"refusing to overwrite session directory {output}")
    output.mkdir(parents=True)
    shutil.copy2(descriptor_path, output / "promotion-candidate.json")
    write_new(output / "session.json", json_bytes(session))
    for gate in session["gates"]:
        write_new(
            output / "gates" / f"{gate}.json",
            json_bytes(gate_artifact_template(session, gate, target)),
        )
    print(f"Offline hardware session planned: {output}")
    print(f"No device was contacted. Next confirmation: authorize-live-{session['receipt_id']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="Create an offline session from a signed candidate package")
    plan.add_argument("candidate", type=Path)
    plan.add_argument("manifest", type=Path)
    plan.add_argument("--unit-fingerprint-sha256", required=True)
    plan.add_argument("--operator", required=True)
    plan.add_argument("--witness", required=True)
    plan.add_argument("--public-key-hex", default=os.environ.get("DCENT_OTA_PUBLIC_KEY_HEX", ""))
    plan.add_argument("--output", type=Path, required=True)
    authorize = sub.add_parser("authorize", help="Record exact operator authorization; no I/O occurs")
    authorize.add_argument("session", type=Path)
    authorize.add_argument("--operator", required=True)
    authorize.add_argument("--started-at", default=utc_now())
    authorize.add_argument("--confirm", required=True)
    status = sub.add_parser("status", help="Validate completed artifacts and show remaining gates")
    status.add_argument("session", type=Path)
    finalize = sub.add_parser("finalize", help="Validate and atomically index a complete receipt")
    finalize.add_argument("session", type=Path)
    finalize.add_argument("--finished-at", required=True)
    finalize.add_argument("--evidence-root", type=Path, default=EVIDENCE_ROOT)
    finalize.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "plan":
            plan_session(args)
            return 0
        matrix = load_manifest()
        require_valid(matrix)
        session, directory = load_session(args.session)
        if args.command == "authorize":
            authorize_session(session, directory, args.operator, args.confirm, args.started_at)
            print("Authorization recorded. This tool made no network or serial contact.")
        elif args.command == "status":
            print(json.dumps(session_status(session, directory, matrix), indent=2, sort_keys=True))
        else:
            receipt = finalize_session(
                session,
                directory,
                matrix,
                args.evidence_root,
                args.finished_at,
                args.confirm,
            )
            print(f"Exact-SKU receipt retained: {receipt}")
            print("Registry production admission remains a separate reviewed step.")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"hardware session error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
