#!/usr/bin/env python3
"""Offline, evidence-derived S19k Pro complete-enablement workflow controller.

The controller reads a tracked campaign DAG and existing host evidence. It has
no network, SSH, serial, GPIO, power, flash, reboot, or miner-contact code. It
cannot grant operator authority or mark a phase complete by assertion: a phase
is VERIFIED only after its offline verifier accepts the exact evidence bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REPO_ROOT = PROJECT_ROOT.parent.parent
DEFAULT_MANIFEST = (
    REPO_ROOT
    / ""
)
DEFAULT_EVIDENCE_ROOT = REPO_ROOT / ".s19k-gauntlet-evidence"
SCHEMA = "dcentos.s19k-gauntlet-campaign/v1"
MAX_MANIFEST_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 4_194_304
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PHASE_KINDS = {"desk", "operator", "terminal"}
VERIFIER_KINDS = {
    "repo",
    "artifacts",
    "phase12",
    "bounded",
    "endurance",
    "module",
    "terminal",
}
ADOPTED_PHASE12_ARTIFACT_ID = "phase0-3"
ADOPTED_BOUNDED_ARTIFACT_ID = "phase0-3"
ADOPTED_ENDURANCE_ARTIFACT_ID = "endurance"
ADOPTED_REPO_PHASE_ID = "offline-repo-contract"
# This intentionally does not name dcentrald/dcentrald_s19k.toml: that mutable
# operator config may contain credentials.  A successor seal must add this
# reserved path only after reviewing a credential-free adopted-live fixture.
# The pool-free persistent install-custody fixture has different semantics and
# must not be substituted for the adopted no-work/bounded/endurance plan input.
ADOPTED_LIVE_CONFIG_REPO_PATH = (
    ""
    "dcentrald_s19k.no-work.toml"
)
COMMON_ADOPTED_PLAN_REPO_BINDINGS = (
    ("config", ADOPTED_LIVE_CONFIG_REPO_PATH),
    ("runner", "DCENT_OS_Antminer/scripts/dcentrald_s19k_tmp_remote_run.sh"),
    (
        "custody_observer",
        "DCENT_OS_Antminer/scripts/dcentrald_s19k_braiins_supervisor_custody.sh",
    ),
    (
        "stock_restart_helper",
        "DCENT_OS_Antminer/scripts/dcentrald_s19k_stock_restart_from_safeoff.sh",
    ),
)
ENDURANCE_ADOPTED_PLAN_REPO_BINDINGS = COMMON_ADOPTED_PLAN_REPO_BINDINGS + (
    ("endurance_collector", "DCENT_OS_Antminer/scripts/s19k_endurance_collect.py"),
    ("endurance_verifier", "DCENT_OS_Antminer/scripts/s19k_endurance_verify.py"),
)


class WorkflowError(Exception):
    """A malformed campaign or refused evidence set."""


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def safe_repo_path(raw: str, label: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise WorkflowError(f"{label} must be a non-empty repository-relative path")
    logical = PurePosixPath(raw)
    if logical.is_absolute() or ".." in logical.parts or "\\" in raw:
        raise WorkflowError(f"{label} must stay repository-relative: {raw!r}")
    candidate = (REPO_ROOT / Path(*logical.parts)).resolve()
    try:
        candidate.relative_to(REPO_ROOT.resolve())
    except ValueError as error:
        raise WorkflowError(f"{label} escapes the repository: {raw!r}") from error
    return candidate


def read_bounded(path: Path, maximum: int, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise WorkflowError(f"{label} must be a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise WorkflowError(f"{label} exceeds {maximum} bytes: {path}")
    return path.read_bytes()


def load_json_file(path: Path, maximum: int, label: str) -> Any:
    data = read_bounded(path, maximum, label)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkflowError(f"{label} is not canonical UTF-8 JSON: {error}") from error


def load_module(path: Path, label: str) -> Any:
    name = f"s19k_workflow_{label.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise WorkflowError(f"cannot load {label} verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    # Dataclass and annotation machinery resolves the defining module through
    # sys.modules while class bodies execute. Register the isolated verifier
    # before execution just as Python's normal import path does.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise WorkflowError(f"{label} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise WorkflowError(f"{label} contains duplicates")
    return value


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = read_bounded(path, MAX_MANIFEST_BYTES, "campaign manifest")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkflowError(f"campaign manifest is invalid JSON: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise WorkflowError(f"campaign manifest must use schema {SCHEMA}")
    policy = document.get("contact_policy")
    if not isinstance(policy, dict) or policy != {
        "controller_is_offline_only": True,
        "live_contact_requires_fresh_operator_authorization": True,
        "nand_write_requires_separate_explicit_authorization": True,
        "controller_may_grant_authority": False,
    }:
        raise WorkflowError("campaign contact policy is missing or not fail-closed")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise WorkflowError("campaign must define at least one sealed artifact")
    artifact_ids: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise WorkflowError("artifact entries must be objects")
        artifact_id = artifact.get("id")
        digest = artifact.get("sha256")
        size = artifact.get("bytes")
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in artifact_ids:
            raise WorkflowError("artifact ids must be unique non-empty strings")
        artifact_ids.add(artifact_id)
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise WorkflowError(f"artifact {artifact_id} has a noncanonical SHA-256")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise WorkflowError(f"artifact {artifact_id} has an invalid byte count")
        safe_repo_path(artifact.get("local_path"), f"artifact {artifact_id} local_path")
        portable = artifact.get("portable_path")
        expected_portable = f"sha256/{digest}/dcentrald"
        if portable != expected_portable:
            raise WorkflowError(
                f"artifact {artifact_id} portable_path must be {expected_portable}"
            )

    phases = document.get("phases")
    if not isinstance(phases, list) or not phases:
        raise WorkflowError("campaign phases must be a non-empty list")
    phase_ids: list[str] = []
    phase_by_id: dict[str, Mapping[str, Any]] = {}
    for phase in phases:
        if not isinstance(phase, dict):
            raise WorkflowError("phase entries must be objects")
        phase_id = phase.get("id")
        if not isinstance(phase_id, str) or not phase_id or phase_id in phase_by_id:
            raise WorkflowError("phase ids must be unique non-empty strings")
        if phase.get("kind") not in PHASE_KINDS:
            raise WorkflowError(f"phase {phase_id} has an invalid kind")
        _string_list(phase.get("depends_on"), f"phase {phase_id} depends_on")
        _string_list(phase.get("owns"), f"phase {phase_id} owns")
        verifier = phase.get("verifier")
        if not isinstance(verifier, dict) or verifier.get("kind") not in VERIFIER_KINDS:
            raise WorkflowError(f"phase {phase_id} has an invalid verifier")
        if verifier["kind"] == "repo":
            required_paths = _string_list(
                verifier.get("required_paths"), f"phase {phase_id} required_paths"
            )
            required_identities = verifier.get("required_identities")
            if not isinstance(required_identities, dict) or set(
                required_identities
            ) != set(required_paths):
                raise WorkflowError(
                    f"phase {phase_id} required_identities must exactly cover required_paths"
                )
            for required in required_paths:
                safe_repo_path(required, f"phase {phase_id} required path")
                identity = required_identities[required]
                if not isinstance(identity, dict):
                    raise WorkflowError(
                        f"phase {phase_id} identity for {required} must be an object"
                    )
                digest = identity.get("sha256")
                size = identity.get("bytes")
                if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                    raise WorkflowError(
                        f"phase {phase_id} identity for {required} has invalid SHA-256"
                    )
                if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                    raise WorkflowError(
                        f"phase {phase_id} identity for {required} has invalid bytes"
                    )
        if verifier["kind"] == "module":
            module_path = safe_repo_path(
                verifier.get("path"), f"phase {phase_id} module path"
            )
            if module_path.suffix != ".py" or module_path.parent != SCRIPT_DIR:
                raise WorkflowError(
                    f"phase {phase_id} module verifier must be a dcentos script"
                )
        if phase.get("kind") == "terminal" and verifier["kind"] != "terminal":
            raise WorkflowError(f"terminal phase {phase_id} must use terminal verifier")
        if not isinstance(phase.get("mission"), str) or not phase["mission"]:
            raise WorkflowError(f"phase {phase_id} mission is required")
        phase_ids.append(phase_id)
        phase_by_id[phase_id] = phase

    for phase_id, phase in phase_by_id.items():
        for dependency in phase["depends_on"]:
            if dependency not in phase_by_id:
                raise WorkflowError(f"phase {phase_id} has unknown dependency {dependency}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(phase_id: str) -> None:
        if phase_id in visiting:
            raise WorkflowError(f"phase dependency cycle includes {phase_id}")
        if phase_id in visited:
            return
        visiting.add(phase_id)
        for dependency in phase_by_id[phase_id]["depends_on"]:
            visit(dependency)
        visiting.remove(phase_id)
        visited.add(phase_id)

    for phase_id in phase_ids:
        visit(phase_id)
    if phases[-1].get("kind") != "terminal":
        raise WorkflowError("the final campaign phase must be terminal")
    return document, hashlib.sha256(canonical_json(document)).hexdigest()


def _absent(paths: list[Path]) -> list[str]:
    return [str(path) for path in paths if not path.exists()]


def _receipt_matches_json(path: Path, result: Mapping[str, Any], label: str) -> None:
    receipt = load_json_file(path, MAX_RECEIPT_BYTES, label)
    if receipt != result:
        raise WorkflowError(f"{label} does not match freshly recomputed evidence")


def _manifest_artifact(
    manifest: Mapping[str, Any], artifact_id: str
) -> Mapping[str, Any]:
    matches = [
        artifact
        for artifact in manifest["artifacts"]
        if artifact.get("id") == artifact_id
    ]
    if len(matches) != 1:
        raise WorkflowError(
            f"campaign must contain exactly one adopted artifact {artifact_id!r}"
        )
    return matches[0]


def _manifest_repo_identities(
    manifest: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    matches = [
        phase
        for phase in manifest["phases"]
        if phase.get("id") == ADOPTED_REPO_PHASE_ID
    ]
    if len(matches) != 1 or matches[0]["verifier"]["kind"] != "repo":
        raise WorkflowError(
            f"campaign must contain exactly one repository phase "
            f"{ADOPTED_REPO_PHASE_ID!r}"
        )
    return dict(matches[0]["verifier"]["required_identities"])


def _verify_adopted_plan_binding(
    plan: Mapping[str, str],
    manifest: Mapping[str, Any],
    artifact_id: str,
    repo_bindings: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    artifact = _manifest_artifact(manifest, artifact_id)
    expected_sha256 = artifact["sha256"]
    expected_bytes = str(artifact["bytes"])
    observed_artifact = {
        "sha256": plan.get("sha256"),
        "bytes": plan.get("bytes"),
        "expected_artifact_sha256": plan.get("expected_artifact_sha256"),
        "expected_artifact_bytes": plan.get("expected_artifact_bytes"),
    }
    if observed_artifact != {
        "sha256": expected_sha256,
        "bytes": expected_bytes,
        "expected_artifact_sha256": expected_sha256,
        "expected_artifact_bytes": expected_bytes,
    }:
        raise WorkflowError(
            f"adopted evidence plan does not match campaign artifact {artifact_id}: "
            f"expected sha256={expected_sha256} bytes={expected_bytes}; "
            f"got sha256={plan.get('sha256')!r} bytes={plan.get('bytes')!r} "
            f"expected_artifact_sha256={plan.get('expected_artifact_sha256')!r} "
            f"expected_artifact_bytes={plan.get('expected_artifact_bytes')!r}"
        )

    sealed_repo_identities = _manifest_repo_identities(manifest)
    verified_inputs: list[dict[str, Any]] = []
    for prefix, path in repo_bindings:
        identity = sealed_repo_identities.get(path)
        if identity is None:
            raise WorkflowError(
                f"campaign repository seal does not bind adopted plan input "
                f"{prefix}: {path}"
            )
        sha256_key = f"{prefix}_sha256"
        bytes_key = f"{prefix}_bytes"
        expected_input_sha256 = identity["sha256"]
        expected_input_bytes = str(identity["bytes"])
        if (
            plan.get(sha256_key) != expected_input_sha256
            or plan.get(bytes_key) != expected_input_bytes
        ):
            raise WorkflowError(
                f"adopted evidence plan input {prefix} does not match campaign "
                f"repository identity {path}: expected "
                f"sha256={expected_input_sha256} bytes={expected_input_bytes}; "
                f"got sha256={plan.get(sha256_key)!r} "
                f"bytes={plan.get(bytes_key)!r}"
            )
        verified_inputs.append(
            {
                "name": prefix,
                "path": path,
                "sha256": expected_input_sha256,
                "bytes": identity["bytes"],
            }
        )
    return {
        "scope": "controller-derived-transient-status-only",
        "artifact": {
            "id": artifact_id,
            "sha256": expected_sha256,
            "bytes": artifact["bytes"],
        },
        "repository_inputs": verified_inputs,
    }


def verify_phase12(phase_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    plan = phase_dir / "plan.kv"
    trial = phase_dir / "trial"
    instruments = phase_dir / "instrument"
    receipt = phase_dir / "verification.json"
    missing = _absent([plan, trial, instruments, receipt])
    if missing:
        raise FileNotFoundError(", ".join(missing))
    module = load_module(SCRIPT_DIR / "s19k_no_work_verify.py", "phase12")
    _, plan_fields = module.common._parse_kv_file(plan.resolve(), "deploy plan")
    module._verify_plan(plan_fields)
    binding = _verify_adopted_plan_binding(
        plan_fields,
        manifest,
        ADOPTED_PHASE12_ARTIFACT_ID,
        COMMON_ADOPTED_PLAN_REPO_BINDINGS,
    )
    result = module.verify(plan.resolve(), trial.resolve(), instruments.resolve())
    _receipt_matches_json(receipt, result, "Phase 1+2 verification receipt")
    facts = dict(result)
    facts["campaign_binding"] = binding
    return facts


def verify_bounded(phase_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    plan = phase_dir / "plan.kv"
    trial = phase_dir / "trial"
    physical = phase_dir / "physical"
    receipt = phase_dir / "verification.json"
    missing = _absent([plan, trial, physical, receipt])
    if missing:
        raise FileNotFoundError(", ".join(missing))
    bounded_module = load_module(
        SCRIPT_DIR / "s19k_bounded_transcript_verify.py", "bounded"
    )
    plan_data, plan_fields = bounded_module._parse_kv_file(
        plan.resolve(), "bounded-work deploy plan"
    )
    bounded_module._verify_plan(plan_fields)
    binding = _verify_adopted_plan_binding(
        plan_fields,
        manifest,
        ADOPTED_BOUNDED_ARTIFACT_ID,
        COMMON_ADOPTED_PLAN_REPO_BINDINGS,
    )
    bounded_result = bounded_module.verify(plan.resolve(), trial.resolve())
    phase12_module = load_module(SCRIPT_DIR / "s19k_no_work_verify.py", "phase12")
    dangerous_temp_millic = phase12_module._parse_config_dangerous_millic(
        read_bounded(
            trial.resolve() / "dcentrald_s19k.toml",
            2 * 1024 * 1024,
            "bounded-work staged config",
        )
    )
    physical_module = load_module(
        SCRIPT_DIR / "s19k_phase3_physical_verify.py", "phase3_physical"
    )
    physical_result = physical_module.verify_evidence(
        physical.resolve(),
        plan=plan_fields,
        plan_data=plan_data,
        bounded_result=bounded_result,
        dangerous_temp_millic=dangerous_temp_millic,
    )
    result: dict[str, Any] = {
        "schema": "dcentos.s19k-adopted-bounded-physical-verification/v1",
        "bounded": bounded_result,
        "physical_safeoff": physical_result,
    }
    result["verification_id"] = hashlib.sha256(canonical_json(result)).hexdigest()
    _receipt_matches_json(receipt, result, "bounded-work verification receipt")
    result["campaign_binding"] = binding
    return result


def verify_endurance(phase_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    evidence = phase_dir / "evidence"
    baseline = phase_dir / "baseline.kv"
    wall_power = phase_dir / "wall-power.csv"
    plan = phase_dir / "plan.kv"
    receipt = evidence / "HOST_ENDURANCE_VERIFICATION.kv"
    missing = _absent([evidence, baseline, wall_power, plan, receipt])
    if missing:
        raise FileNotFoundError(", ".join(missing))
    module = load_module(SCRIPT_DIR / "s19k_endurance_verify.py", "endurance")
    plan_fields, _ = module.parse_plan(plan.resolve())
    binding = _verify_adopted_plan_binding(
        plan_fields,
        manifest,
        ADOPTED_ENDURANCE_ARTIFACT_ID,
        ENDURANCE_ADOPTED_PLAN_REPO_BINDINGS,
    )
    result = module.verify_evidence(
        evidence.resolve(), baseline.resolve(), wall_power.resolve(), plan.resolve()
    )
    expected = module.receipt_bytes(result)
    actual = read_bounded(receipt, MAX_RECEIPT_BYTES, "endurance receipt")
    if actual != expected:
        raise WorkflowError(
            "endurance receipt does not match freshly recomputed evidence"
        )
    facts = dict(result)
    facts["campaign_binding"] = binding
    return facts


def verify_generic_module(phase: Mapping[str, Any], phase_dir: Path) -> dict[str, Any]:
    path = safe_repo_path(phase["verifier"]["path"], f"phase {phase['id']} module")
    if not path.exists():
        raise ModuleNotFoundError(str(path))
    receipt_path = phase_dir / "verification.json"
    if not phase_dir.is_dir() or not receipt_path.is_file():
        raise FileNotFoundError(str(phase_dir))
    module = load_module(path, phase["id"])
    verifier = getattr(module, "verify_workflow_evidence", None)
    if not callable(verifier):
        raise WorkflowError(
            f"{path} must export verify_workflow_evidence(evidence_dir)"
        )
    result = verifier(phase_dir.resolve())
    if not isinstance(result, dict):
        raise WorkflowError(f"phase {phase['id']} verifier did not return an object")
    _receipt_matches_json(
        receipt_path, result, f"phase {phase['id']} verification receipt"
    )
    return dict(result)


def audit_waiting_desk_module(phase: Mapping[str, Any]) -> dict[str, Any] | None:
    """Expose source-level desk blockers before their live dependencies finish.

    A readiness audit cannot verify the phase and cannot change DAG state.  It
    only lets the agent wave work on known source blockers concurrently with
    operator evidence collection.
    """
    if phase.get("kind") != "desk" or phase["verifier"].get("kind") != "module":
        return None
    path = safe_repo_path(phase["verifier"]["path"], f"phase {phase['id']} module")
    if not path.exists():
        return {
            "classification": "blocked_tooling",
            "reason": f"offline verifier missing: {path}",
        }
    module = load_module(path, f"{phase['id']}-readiness")
    auditor = getattr(module, "audit_source_tree", None)
    if not callable(auditor):
        auditor = getattr(module, "audit", None)
    if not callable(auditor):
        return None
    result = auditor()
    if not isinstance(result, dict):
        raise WorkflowError(f"phase {phase['id']} readiness auditor did not return an object")
    classification = result.get("classification")
    if classification not in ("blocked_tooling", "ready"):
        raise WorkflowError(
            f"phase {phase['id']} readiness auditor returned an invalid classification"
        )
    return {
        "classification": classification,
        "blocker": result.get("blocker"),
    }


def verify_repo_phase(phase: Mapping[str, Any]) -> dict[str, Any]:
    paths = [
        safe_repo_path(raw, f"phase {phase['id']} required path")
        for raw in phase["verifier"]["required_paths"]
    ]
    missing = [str(path.relative_to(REPO_ROOT)) for path in paths if not path.is_file()]
    symlinks = [str(path.relative_to(REPO_ROOT)) for path in paths if path.is_symlink()]
    if missing or symlinks:
        raise WorkflowError(
            f"required repository files missing={missing} symlinks={symlinks}"
        )
    verified: list[dict[str, Any]] = []
    for raw, path in zip(phase["verifier"]["required_paths"], paths):
        digest, size = sha256_file(path)
        expected = phase["verifier"]["required_identities"][raw]
        if digest != expected["sha256"] or size != expected["bytes"]:
            raise WorkflowError(
                f"required repository file identity mismatch: {raw} "
                f"sha256={digest} bytes={size}"
            )
        verified.append({"path": raw, "sha256": digest, "bytes": size})
    return {"required_file_count": len(paths), "required_files": verified}


def verify_artifacts(
    manifest: Mapping[str, Any], artifact_root: Path | None
) -> dict[str, Any]:
    verified: list[dict[str, Any]] = []
    if artifact_root is None:
        raise FileNotFoundError(
            "portable artifact root not supplied (--artifact-root or "
            "DCENT_S19K_ARTIFACT_ROOT)"
        )
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise WorkflowError(f"portable artifact root is not a directory: {root}")
    for artifact in manifest["artifacts"]:
        local = safe_repo_path(
            artifact["local_path"], f"artifact {artifact['id']} local path"
        )
        portable = root.joinpath(*PurePosixPath(artifact["portable_path"]).parts)
        for label, path in (("local", local), ("portable", portable)):
            if not path.is_file() or path.is_symlink():
                raise FileNotFoundError(f"{label} artifact absent: {path}")
            digest, size = sha256_file(path)
            if digest != artifact["sha256"] or size != artifact["bytes"]:
                raise WorkflowError(
                    f"{label} artifact {artifact['id']} identity mismatch: "
                    f"sha256={digest} bytes={size}"
                )
        verified.append(
            {
                "id": artifact["id"],
                "sha256": artifact["sha256"],
                "bytes": artifact["bytes"],
                "portable_path": str(portable),
            }
        )
    return {"artifacts": verified}


def evaluate(
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    evidence_root: Path,
    artifact_root: Path | None,
) -> dict[str, Any]:
    phases: list[dict[str, Any]] = []
    state_by_id: dict[str, str] = {}
    for phase in manifest["phases"]:
        phase_id = phase["id"]
        dependencies = phase["depends_on"]
        blocked_by = [dep for dep in dependencies if state_by_id.get(dep) != "verified"]
        item: dict[str, Any] = {
            "id": phase_id,
            "title": phase["title"],
            "kind": phase["kind"],
            "expert": phase["expert"],
            "depends_on": dependencies,
            "blocked_by": blocked_by,
        }
        if blocked_by:
            item.update(state="waiting", reason="dependency evidence is not verified")
            try:
                readiness = audit_waiting_desk_module(phase)
            except Exception as error:
                readiness = {
                    "classification": "blocked_tooling",
                    "reason": f"offline readiness audit refused: {error}",
                }
            if readiness is not None:
                item["tooling_readiness"] = readiness
            phases.append(item)
            state_by_id[phase_id] = item["state"]
            continue
        verifier_kind = phase["verifier"]["kind"]
        try:
            if verifier_kind == "repo":
                facts = verify_repo_phase(phase)
            elif verifier_kind == "artifacts":
                facts = verify_artifacts(manifest, artifact_root)
            elif verifier_kind == "phase12":
                facts = verify_phase12(evidence_root / phase_id, manifest)
            elif verifier_kind == "bounded":
                facts = verify_bounded(evidence_root / phase_id, manifest)
            elif verifier_kind == "endurance":
                facts = verify_endurance(evidence_root / phase_id, manifest)
            elif verifier_kind == "module":
                facts = verify_generic_module(phase, evidence_root / phase_id)
            elif verifier_kind == "terminal":
                facts = {"terminal_claim": manifest["terminal_claim"]}
            else:  # validated above; defensive for type checkers and drift
                raise WorkflowError(f"unsupported verifier kind {verifier_kind}")
        except ModuleNotFoundError as error:
            item.update(state="blocked_tooling", reason=f"offline verifier missing: {error}")
        except FileNotFoundError as error:
            readiness = (
                audit_waiting_desk_module(phase)
                if phase["kind"] == "desk"
                else None
            )
            if readiness is not None and readiness.get("classification") == "blocked_tooling":
                item.update(
                    state="blocked_tooling",
                    reason=readiness.get("blocker")
                    or f"offline source readiness is blocked: {error}",
                )
                item["tooling_readiness"] = readiness
            else:
                state = "awaiting_operator" if phase["kind"] == "operator" else "ready"
                item.update(state=state, reason=f"required evidence absent: {error}")
        except Exception as error:  # fail closed across verifier-specific errors
            item.update(state="refused", reason=f"offline verification refused: {error}")
        else:
            item.update(state="verified", reason="fresh offline verification passed")
            item["facts"] = facts
        phases.append(item)
        state_by_id[phase_id] = item["state"]

    frontier_states = {"ready", "awaiting_operator", "blocked_tooling", "refused"}
    frontier = [item["id"] for item in phases if item["state"] in frontier_states]
    terminal = phases[-1]
    latent_tooling_blockers = [
        {
            "phase_id": item["id"],
            **item["tooling_readiness"],
        }
        for item in phases
        if item.get("tooling_readiness", {}).get("classification") == "blocked_tooling"
    ]
    return {
        "schema": "dcentos.s19k-gauntlet-status/v1",
        "campaign_id": manifest["campaign_id"],
        "manifest_sha256": manifest_sha256,
        "evidence_root": str(evidence_root.resolve()),
        "artifact_root": str(artifact_root.resolve()) if artifact_root else None,
        "complete": terminal["state"] == "verified",
        "terminal_claim": manifest["terminal_claim"],
        "frontier": frontier,
        "latent_tooling_blockers": latent_tooling_blockers,
        "phases": phases,
    }


def emit_agent_tasks(
    manifest: Mapping[str, Any], report: Mapping[str, Any]
) -> dict[str, Any]:
    phase_by_id = {phase["id"]: phase for phase in manifest["phases"]}
    result_by_id = {phase["id"]: phase for phase in report["phases"]}
    tasks: list[dict[str, Any]] = []
    operator_gates: list[dict[str, Any]] = []
    scheduled_phases: set[str] = set()
    for phase_id in report["frontier"]:
        phase = phase_by_id[phase_id]
        result = result_by_id[phase_id]
        if result["state"] == "blocked_tooling":
            verifier_path = phase["verifier"].get("path")
            owns = [verifier_path] if isinstance(verifier_path, str) else list(
                phase["owns"]
            )
            owner_id = f"{phase_id}-verifier-owner"
            tasks.append(
                {
                    "task_id": owner_id,
                    "phase_id": phase_id,
                    "role": "verifier-owner",
                    "expert": phase["expert"],
                    "state": result["state"],
                    "reason": result["reason"],
                    "mission": (
                        "Implement and adversarially test the missing offline verifier; "
                        "do not collect or manufacture operator evidence."
                    ),
                    "owns": owns,
                    "authority": "offline repository work only within owned paths",
                    "forbidden": [
                        "miner/network contact",
                        "GPIO/power/serial access",
                        "flash/NAND mutation",
                        "manufacturing evidence or marking a gate complete",
                    ],
                }
            )
            tasks.append(
                {
                    "task_id": f"{phase_id}-verifier-independent-review",
                    "phase_id": phase_id,
                    "role": "independent-review",
                    "expert": "DCENT_QA",
                    "depends_on": [owner_id],
                    "mission": "Rerun adversarial offline verifier tests and reject any evidence-by-assertion path.",
                    "owns": [],
                    "authority": "read-only offline review",
                }
            )
            scheduled_phases.add(phase_id)
            continue
        if phase["kind"] == "operator":
            operator_gates.append(
                {
                    "phase_id": phase_id,
                    "expert": phase["expert"],
                    "state": result["state"],
                    "reason": result["reason"],
                    "mission": phase["mission"],
                    "authorization": "fresh exact operator authority required; controller grants none",
                }
            )
            continue
        owner_id = f"{phase_id}-owner"
        tasks.append(
            {
                "task_id": owner_id,
                "phase_id": phase_id,
                "role": "owner",
                "expert": phase["expert"],
                "state": result["state"],
                "reason": result["reason"],
                "mission": phase["mission"],
                "owns": phase["owns"],
                "authority": "offline repository work only within owned paths",
                "forbidden": [
                    "miner/network contact",
                    "GPIO/power/serial access",
                    "flash/NAND mutation",
                    "manufacturing evidence or marking a gate complete",
                ],
            }
        )
        scheduled_phases.add(phase_id)
        tasks.append(
            {
                "task_id": f"{phase_id}-independent-review",
                "phase_id": phase_id,
                "role": "independent-review",
                "expert": "DCENT_QA",
                "depends_on": [owner_id],
                "mission": (
                    "Independently rerun the phase verifier, challenge unsafe inference, "
                    "and report exact evidence gaps without editing owner outputs."
                ),
                "owns": [],
                "authority": "read-only offline review",
            }
        )
    for latent in report.get("latent_tooling_blockers", []):
        phase_id = latent["phase_id"]
        if phase_id in scheduled_phases:
            continue
        phase = phase_by_id[phase_id]
        owner_id = f"{phase_id}-latent-implementation-owner"
        tasks.append(
            {
                "task_id": owner_id,
                "phase_id": phase_id,
                "role": "latent-implementation-owner",
                "expert": phase["expert"],
                "state": "blocked_tooling",
                "reason": latent,
                "mission": phase["mission"],
                "owns": phase["owns"],
                "authority": "offline repository work only within owned paths",
                "forbidden": [
                    "miner/network contact",
                    "GPIO/power/serial access",
                    "flash/NAND mutation",
                    "manufacturing evidence or marking a gate complete",
                ],
            }
        )
        tasks.append(
            {
                "task_id": f"{phase_id}-latent-independent-review",
                "phase_id": phase_id,
                "role": "independent-review",
                "expert": "DCENT_QA",
                "depends_on": [owner_id],
                "mission": "Challenge the source-level blocker closure without treating it as live evidence.",
                "owns": [],
                "authority": "read-only offline review",
            }
        )
    return {
        "schema": "dcentos.s19k-agent-wave/v1",
        "campaign_id": report["campaign_id"],
        "manifest_sha256": report["manifest_sha256"],
        "max_parallel_agents": 3,
        "tasks": tasks,
        "operator_gates": operator_gates,
    }


def render_status(report: Mapping[str, Any]) -> str:
    lines = [
        f"campaign={report['campaign_id']}",
        f"manifest_sha256={report['manifest_sha256']}",
        f"complete={str(report['complete']).lower()}",
    ]
    for phase in report["phases"]:
        suffix = f" blocked_by={','.join(phase['blocked_by'])}" if phase["blocked_by"] else ""
        lines.append(
            f"{phase['id']}: {phase['state']} expert={phase['expert']}{suffix} -- {phase['reason']}"
        )
    lines.append(f"frontier={','.join(report['frontier'])}")
    lines.append(
        "latent_tooling="
        + ",".join(item["phase_id"] for item in report.get("latent_tooling_blockers", []))
    )
    return "\n".join(lines)


def verify_exit_code(report: Mapping[str, Any], expected_raw: str | None) -> int:
    """Return success only for completion or one explicitly admitted frontier."""
    bad_states = {"refused", "blocked_tooling"}
    if any(phase["state"] in bad_states for phase in report["phases"]):
        return 1
    if expected_raw is None:
        return 0 if report["complete"] else 1
    expected = expected_raw.split(",") if expected_raw else []
    if any(not item for item in expected) or len(expected) != len(set(expected)):
        return 1
    return 0 if expected == report["frontier"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=(
            Path(os.environ["DCENT_S19K_ARTIFACT_ROOT"])
            if os.environ.get("DCENT_S19K_ARTIFACT_ROOT")
            else None
        ),
        help="operator-controlled root containing sha256/<digest>/dcentrald",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "verify", "next", "emit-agent-tasks"):
        child = subparsers.add_parser(command)
        child.add_argument("--json", action="store_true")
        if command == "verify":
            child.add_argument(
                "--expect-frontier",
                help="comma-separated exact incomplete frontier admitted by this check",
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest_path = args.manifest.resolve(strict=True)
        manifest, manifest_sha256 = load_manifest(manifest_path)
        report = evaluate(
            manifest,
            manifest_sha256,
            args.evidence_root,
            args.artifact_root,
        )
    except (OSError, WorkflowError) as error:
        print(f"S19K_GAUNTLET_WORKFLOW_REFUSED: {error}", file=sys.stderr)
        return 1

    if args.command == "emit-agent-tasks":
        output: Mapping[str, Any] = emit_agent_tasks(manifest, report)
    elif args.command == "next":
        phase_by_id = {phase["id"]: phase for phase in report["phases"]}
        output = {
            "schema": "dcentos.s19k-next/v1",
            "campaign_id": report["campaign_id"],
            "complete": report["complete"],
            "frontier": [phase_by_id[phase_id] for phase_id in report["frontier"]],
        }
    else:
        output = report

    if args.json or args.command in {"next", "emit-agent-tasks"}:
        sys.stdout.buffer.write(canonical_json(output))
    else:
        print(render_status(report))

    if args.command == "verify":
        return verify_exit_code(report, args.expect_frontier)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
