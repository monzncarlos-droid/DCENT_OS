#!/usr/bin/env python3
"""Offline, evidence-derived Antminer S21-generation complete-enablement
workflow controller.

The controller reads a tracked campaign DAG and existing host evidence. It has
no network, SSH, serial, GPIO, power, flash, reboot, or miner-contact code. It
cannot grant operator authority or mark a phase complete by assertion: a phase
is VERIFIED only after its offline verifier accepts the exact evidence bytes.

The campaign spans every Antminer S21-generation "version" D-Central can
reach -- am3-s21, am3-s21pro, am3-s21xp, am3-t21, the S21+ generation
(amlogic-s21plus class), the S21 Hydro XIL (Zynq) class, and the CV1835
S21-class SKUs -- from locked stock firmware through unlock, staged bounded
mining, endurance, persistent install, and acceptance, mirroring the proven
S19k office-gauntlet and S19j Pro complete-enablement campaign patterns.
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
    "S21_ENABLEMENT_CAMPAIGN.json"
)
DEFAULT_EVIDENCE_ROOT = REPO_ROOT / ".s21-enablement-evidence"
SCHEMA = "dcentos.s21-enablement-campaign/v1"
MAX_MANIFEST_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 4_194_304
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PHASE_KINDS = {"desk", "operator", "terminal"}
VERIFIER_KINDS = {"repo", "artifacts", "module", "terminal"}


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
    name = f"s21_workflow_{label.replace('-', '_')}"
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
        "nand_or_emmc_write_requires_separate_explicit_authorization": True,
        "controller_may_grant_authority": False,
    }:
        raise WorkflowError("campaign contact policy is missing or not fail-closed")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise WorkflowError("campaign artifacts must be a list (may be empty)")
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
        local = safe_repo_path(
            artifact.get("local_path"), f"artifact {artifact_id} local_path"
        )
        expected_portable = f"sha256/{digest}/{local.name}"
        if artifact.get("portable_path") != expected_portable:
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
        return None
    result = auditor(phase["id"])
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
            "DCENT_S21_ARTIFACT_ROOT)"
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
        "schema": "dcentos.s21-enablement-status/v1",
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
                        "Close the reported source-side blocker (condition or pinned "
                        "deliverable), then stage the phase evidence receipt; do not "
                        "collect or manufacture operator evidence."
                    ),
                    "owns": owns,
                    "authority": "offline repository work only within owned paths",
                    "forbidden": [
                        "miner/network contact",
                        "GPIO/power/serial access",
                        "flash/NAND/eMMC mutation",
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
                    "flash/NAND/eMMC mutation",
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
                    "flash/NAND/eMMC mutation",
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
        "schema": "dcentos.s21-agent-wave/v1",
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
            Path(os.environ["DCENT_S21_ARTIFACT_ROOT"])
            if os.environ.get("DCENT_S21_ARTIFACT_ROOT")
            else None
        ),
        help="operator-controlled root containing sha256/<digest>/<artifact>",
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
        print(f"S21_WORKFLOW_REFUSED: {error}", file=sys.stderr)
        return 1

    if args.command == "emit-agent-tasks":
        output: Mapping[str, Any] = emit_agent_tasks(manifest, report)
    elif args.command == "next":
        phase_by_id = {phase["id"]: phase for phase in report["phases"]}
        output = {
            "schema": "dcentos.s21-next/v1",
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
