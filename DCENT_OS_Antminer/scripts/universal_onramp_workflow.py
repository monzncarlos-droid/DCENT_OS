#!/usr/bin/env python3
"""Offline, evidence-derived Antminer universal on-ramp campaign controller.

The controller reads the tracked campaign DAG
(ANTMINER_UNIVERSAL_ONRAMP_CAMPAIGN.json) and the evidence tree under
.universal-onramp-evidence/. It has no network, SSH, serial, GPIO, power,
flash, reboot, or miner-contact code, and it spawns no other program. It
cannot grant operator authority: the manifest must keep
contact_policy.controller_may_grant_authority false on load, operator lanes
are never verified by the controller (they render as awaiting-operator), and
no command here can mint live-contact or NAND-write authority.

Lane states: pending -> dispatchable -> verified. A lane becomes dispatchable
when every dependency is satisfied (a dependency is satisfied when it is
controller-verified, or when it is an operator lane with an externally
recorded bound receipt; the controller only ever READS those receipts).
A desk/code/reference lane becomes verified only through `verify <lane-id>`,
which recomputes machine checks fresh from disk and writes
<evidence-root>/<lane-id>/verification.json bound to the exact manifest bytes.

CLI:
  status               per-lane states, dispatchable-now set, operator-gate
                       readiness; always exits 0 on a loadable manifest
  verify <lane-id>     fresh machine verification + receipt write; exits
                       0 verified, 1 failed checks, 2 dependency/unknown lane,
                       3 operator lane (fresh operator authorization required)
  emit-agent-tasks     owner/reviewer task cards for dispatchable lanes plus
                       operator-gate cards, deterministic manifest order

Verifier-contract path resolution (conservative, fail-closed):
- verifier.required_paths may be a string or list of strings and often carries
  prose. Each string is split on " + "; the first whitespace-delimited token
  of a segment is a path candidate only when it contains "/", "*", or "{", or
  ends with a known file suffix. Segments without such a token are recorded
  as ignored prose.
- "{wave_docs}" is replaced by the manifest's wave_docs directory.
- Comma brace lists ("L{1,2,3,4}_*.md") expand to one candidate per option.
- Candidates containing "*" or "?" glob against the repository root; an empty
  glob stays as a missing pattern.
- A bare filename (no "/") in a spec that uses {wave_docs} resolves against
  the wave-docs directory first (this is how FINDINGS.md binds), then the
  repository root.
- Partial paths that are not repository-root relative (for example
  "dcentrald-api-types/src/deployed_eeprom.rs") resolve exactly as written
  and count as missing until the owning lane lands them; the controller
  never searches or guesses prefixes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REPO_ROOT = PROJECT_ROOT.parent.parent
DEFAULT_MANIFEST = (
    REPO_ROOT
    / ""
    "ANTMINER_UNIVERSAL_ONRAMP_CAMPAIGN.json"
)
DEFAULT_EVIDENCE_DIR = ".universal-onramp-evidence"
SCHEMA = "dcentos.antminer-universal-onramp/v1"
STATUS_SCHEMA = "dcentos.antminer-universal-onramp-status/v1"
WAVE_SCHEMA = "dcentos.antminer-universal-onramp-agent-wave/v1"
MAX_MANIFEST_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 4_194_304
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
LANE_KINDS = {
    "desk",
    "code",
    "operator",
    "reference",
    "desk-then-operator",
    "code-then-operator",
}
VERIFIER_KINDS = {
    "deliverable",
    "repo",
    "repo+hosttest",
    "assertion-free",
    "operator",
    "repo+hosttest-then-operator",
}
MACHINE_VERIFIER_KINDS = {"deliverable", "repo", "repo+hosttest"}
PATH_SUFFIXES = (
    ".md",
    ".py",
    ".rs",
    ".json",
    ".toml",
    ".kv",
    ".sh",
    ".js",
    ".ts",
    ".txt",
    ".csv",
    ".yaml",
    ".yml",
    ".swu",
    ".bin",
    ".img",
)
STANDING_PROHIBITIONS = [
    "no miner/network contact",
    "no GPIO/power/serial access",
    "no flash/NAND mutation",
    "no manufacturing evidence",
]
WAVE_DOCS_PLACEHOLDER = "{wave_docs}"
OPERATOR_AUTHORIZATION_NOTE = (
    "fresh exact operator authorization required; controller grants none; "
    "any NAND/eMMC write additionally needs separate explicit authorization"
)


class WorkflowError(Exception):
    """A malformed campaign or refused evidence set."""


class UnknownLaneError(WorkflowError):
    """The requested lane id is not in the campaign DAG."""


class DependencyGateError(WorkflowError):
    """The lane's dependencies are not satisfied yet."""


class OperatorAuthorityRefusal(WorkflowError):
    """Only a human operator with fresh authorization may proceed."""


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


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _safe_repo_relative(raw: Any, label: str) -> str:
    """Validate and normalize a repository-relative POSIX path string."""
    if not isinstance(raw, str) or not raw:
        raise WorkflowError(f"{label} must be a non-empty repository-relative path")
    logical = PurePosixPath(raw)
    if logical.is_absolute() or ".." in logical.parts or "\\" in raw:
        raise WorkflowError(f"{label} must stay repository-relative: {raw!r}")
    normalized = "/".join(part for part in logical.parts if part and part != ".")
    if not normalized:
        raise WorkflowError(f"{label} must name a path: {raw!r}")
    return normalized


def safe_repo_path(raw: str, label: str) -> Path:
    normalized = _safe_repo_relative(raw, label)
    candidate = (REPO_ROOT / Path(*PurePosixPath(normalized).parts)).resolve()
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


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise WorkflowError(f"{label} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise WorkflowError(f"{label} must not be empty")
    if len(value) != len(set(value)):
        raise WorkflowError(f"{label} contains duplicates")
    return value


def _required_path_texts(lane: Mapping[str, Any]) -> list[str]:
    spec = lane["verifier"].get("required_paths")
    if isinstance(spec, str):
        return [spec]
    if isinstance(spec, list) and all(
        isinstance(item, str) and item for item in spec
    ):
        return list(spec)
    raise WorkflowError(
        f"lane {lane['id']} required_paths must be a string or list of strings"
    )


def is_operator_lane(lane: Mapping[str, Any]) -> bool:
    """Operator lanes and operator-verifier lanes are never controller-verified."""
    return "operator" in lane["kind"] or "operator" in lane["verifier"]["kind"]


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = read_bounded(path, MAX_MANIFEST_BYTES, "campaign manifest")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkflowError(f"campaign manifest is invalid JSON: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise WorkflowError(f"campaign manifest must use schema {SCHEMA}")

    policy = document.get("contact_policy")
    if not isinstance(policy, dict):
        raise WorkflowError("campaign contact policy is missing")
    for flag in (
        "controller_is_offline_only",
        "live_contact_requires_fresh_operator_authorization",
        "nand_write_requires_separate_explicit_authorization",
    ):
        if policy.get(flag) is not True:
            raise WorkflowError(f"campaign contact policy flag {flag} must be true")
    if policy.get("controller_may_grant_authority") is not False:
        raise WorkflowError(
            "campaign contact policy must keep controller_may_grant_authority "
            "false; this controller never grants contact authority"
        )

    _string_list(
        document.get("epic_caveats_binding"),
        "epic_caveats_binding",
        allow_empty=True,
    )
    wave_docs = document.get("wave_docs")
    if wave_docs is not None:
        _safe_repo_relative(wave_docs, "wave_docs")
    evidence_root = document.get("evidence_root")
    if evidence_root is not None:
        _safe_repo_relative(evidence_root, "evidence_root")

    phases = document.get("phases")
    if not isinstance(phases, list) or not phases:
        raise WorkflowError("campaign phases must be a non-empty list")
    lane_ids: list[str] = []
    lane_by_id: dict[str, Mapping[str, Any]] = {}
    for lane in phases:
        if not isinstance(lane, dict):
            raise WorkflowError("phase entries must be objects")
        lane_id = lane.get("id")
        if not isinstance(lane_id, str) or not lane_id or lane_id in lane_by_id:
            raise WorkflowError("phase ids must be unique non-empty strings")
        if lane.get("kind") not in LANE_KINDS:
            raise WorkflowError(f"lane {lane_id} has an invalid kind")
        verifier = lane.get("verifier")
        if not isinstance(verifier, dict) or verifier.get("kind") not in VERIFIER_KINDS:
            raise WorkflowError(f"lane {lane_id} has an invalid verifier")
        _string_list(lane.get("depends_on"), f"lane {lane_id} depends_on", allow_empty=True)
        for field in ("title", "expert", "review"):
            if not isinstance(lane.get(field), str) or not lane[field]:
                raise WorkflowError(f"lane {lane_id} {field} is required")
        _required_path_texts(lane)
        lane_ids.append(lane_id)
        lane_by_id[lane_id] = lane

    for lane_id, lane in lane_by_id.items():
        for dependency in lane["depends_on"]:
            if dependency not in lane_by_id:
                raise WorkflowError(f"lane {lane_id} has unknown dependency {dependency}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(lane_id: str) -> None:
        if lane_id in visiting:
            raise WorkflowError(f"lane dependency cycle includes {lane_id}")
        if lane_id in visited:
            return
        visiting.add(lane_id)
        for dependency in lane_by_id[lane_id]["depends_on"]:
            visit(dependency)
        visiting.remove(lane_id)
        visited.add(lane_id)

    for lane_id in lane_ids:
        visit(lane_id)

    for lane_id, lane in lane_by_id.items():
        texts = _required_path_texts(lane)
        if any(WAVE_DOCS_PLACEHOLDER in text for text in texts) and not wave_docs:
            raise WorkflowError(
                f"lane {lane_id} uses {WAVE_DOCS_PLACEHOLDER} but the manifest "
                "defines no wave_docs directory"
            )
    # Bind receipts to the exact manifest bytes on disk (matches the receipts
    # the wave coordinator already wrote; any manifest edit invalidates them).
    return document, hashlib.sha256(raw).hexdigest()


def _first_path_token(segment: str) -> str | None:
    parts = segment.split()
    if not parts:
        return None
    token = parts[0].rstrip("/")
    if not token or token.startswith("-"):
        return None
    if "/" in token or "*" in token or "{" in token or token.lower().endswith(
        PATH_SUFFIXES
    ):
        return token
    return None


def _brace_expand(text: str) -> list[str]:
    match = re.search(r"\{([^{}]*,[^{}]*)\}", text)
    if match is None:
        return [text]
    head, tail = text[: match.start()], text[match.end() :]
    expanded: list[str] = []
    for option in match.group(1).split(","):
        expanded.extend(_brace_expand(head + option.strip() + tail))
    return expanded


def _glob_expand(pattern: str) -> list[str]:
    normalized = _safe_repo_relative(pattern, "required path pattern")
    if "*" not in normalized and "?" not in normalized:
        return [normalized]
    matches = sorted(REPO_ROOT.glob(normalized), key=lambda item: item.as_posix())
    if not matches:
        return [normalized]
    return [match.relative_to(REPO_ROOT).as_posix() for match in matches]


def resolve_required_paths(
    manifest: Mapping[str, Any], lane: Mapping[str, Any]
) -> dict[str, Any]:
    """Resolve a lane's verifier path contract against the repository root."""
    lane_id = lane["id"]
    kind = lane["verifier"]["kind"]
    if kind not in MACHINE_VERIFIER_KINDS:
        raise WorkflowError(
            f"lane {lane_id} verifier kind {kind} has no machine-checkable "
            "path contract"
        )
    wave_docs_raw = manifest.get("wave_docs")
    wave_docs = (
        _safe_repo_relative(wave_docs_raw, "wave_docs")
        if isinstance(wave_docs_raw, str)
        else None
    )
    texts = _required_path_texts(lane)
    uses_wave = any(WAVE_DOCS_PLACEHOLDER in text for text in texts)
    if uses_wave and wave_docs is None:
        raise WorkflowError(
            f"lane {lane_id} uses {WAVE_DOCS_PLACEHOLDER} but the manifest "
            "defines no wave_docs directory"
        )
    required: list[str] = []
    ignored: list[str] = []
    for text in texts:
        for segment in text.split(" + "):
            token = _first_path_token(segment)
            if token is None:
                ignored.append(" ".join(segment.split()))
                continue
            if WAVE_DOCS_PLACEHOLDER in token:
                if wave_docs is None:
                    raise WorkflowError(
                        f"lane {lane_id} uses {WAVE_DOCS_PLACEHOLDER} but the "
                        "manifest defines no wave_docs directory"
                    )
                token = token.replace(WAVE_DOCS_PLACEHOLDER, wave_docs)
            for candidate in _brace_expand(token):
                if (
                    "/" not in candidate
                    and uses_wave
                    and not set(candidate) & {"*", "?", "{"}
                    and safe_repo_path(f"{wave_docs}/{candidate}", "wave path").exists()
                ):
                    candidate = f"{wave_docs}/{candidate}"
                for concrete in _glob_expand(candidate):
                    safe_repo_path(concrete, f"lane {lane_id} required path")
                    if concrete not in required:
                        required.append(concrete)
    return {"required_paths": required, "ignored_prose": ignored}


def lane_machine_checks(
    manifest: Mapping[str, Any], lane: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Fresh-from-disk existence and identity checks for desk/code lanes."""
    lane_id = lane["id"]
    resolution = resolve_required_paths(manifest, lane)
    required = resolution["required_paths"]
    if not required:
        raise WorkflowError(
            f"lane {lane_id} resolved no required paths from its verifier contract"
        )
    checks: list[dict[str, Any]] = [
        {
            "check": "contract_resolution",
            "required_path_count": len(required),
            "ignored_prose": resolution["ignored_prose"],
        }
    ]
    missing: list[str] = []
    for rel in required:
        path = safe_repo_path(rel, f"lane {lane_id} required path")
        entry: dict[str, Any] = {"check": "path_exists", "path": rel}
        if path.is_symlink() or not path.exists():
            entry["present"] = False
            missing.append(rel)
        elif path.is_dir():
            entry.update(present=True, type="dir")
        else:
            digest, size = sha256_file(path)
            entry.update(present=True, type="file", sha256=digest, bytes=size)
        checks.append(entry)
    if missing:
        raise WorkflowError(f"lane {lane_id} required paths missing={missing}")
    if lane["verifier"]["kind"] == "repo+hosttest":
        checks.append(
            {
                "check": "hosttest_pending",
                "note": (
                    "host test pass is manual and outside controller authority; "
                    "record it in the lane evidence directory"
                ),
            }
        )
    return checks


def assertion_free_checks(
    lane: Mapping[str, Any], evidence_root: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Reference lanes verify from an attestation receipt only."""
    lane_id = lane["id"]
    receipt_path = evidence_root / lane_id / "verification.json"
    label = f"lane {lane_id} assertion-free receipt"
    attestation = load_json_file(receipt_path, MAX_RECEIPT_BYTES, label)
    if not isinstance(attestation, dict):
        raise WorkflowError(f"{label} must be a JSON object")
    if attestation.get("lane") != lane_id:
        raise WorkflowError(
            f"{label} must name lane {lane_id!r}, found {attestation.get('lane')!r}"
        )
    for field in ("verified_by", "method"):
        if not isinstance(attestation.get(field), str) or not attestation[field]:
            raise WorkflowError(f"{label} must carry a non-empty {field}")
    checks = [
        {
            "check": "assertion_free_receipt",
            "path": f"{evidence_root.name}/{lane_id}/verification.json",
            "verified_by": attestation["verified_by"],
            "method": attestation["method"],
        }
    ]
    return checks, attestation


def load_bound_receipt(
    evidence_root: Path, lane_id: str, manifest_sha256: str
) -> dict[str, Any] | None:
    """Read a lane receipt that binds this exact manifest; None otherwise."""
    path = evidence_root / lane_id / "verification.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = load_json_file(path, MAX_RECEIPT_BYTES, f"lane {lane_id} receipt")
    except WorkflowError:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("lane") != lane_id or data.get("manifest_sha256") != manifest_sha256:
        return None
    return data


def _receipt_is_controller_verified(receipt: Mapping[str, Any] | None) -> bool:
    return (
        receipt is not None
        and isinstance(receipt.get("checks"), list)
        and isinstance(receipt.get("verified_at"), str)
        and bool(receipt["verified_at"])
    )


def _receipt_is_operator_attested(receipt: Mapping[str, Any] | None) -> bool:
    return (
        receipt is not None
        and isinstance(receipt.get("verified_by"), str)
        and bool(receipt["verified_by"])
    )


def derive_status(
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    evidence_root: Path,
) -> dict[str, Any]:
    """Derive lane states from the DAG plus bound receipts. Never mutates.

    Manifest lane order is NOT topological (operator gates may appear after
    their dependents), so dependency satisfaction is computed from bound
    receipts directly instead of progressively in manifest order.
    """
    lane_by_id = {lane["id"]: lane for lane in manifest["phases"]}
    receipts = {
        lane["id"]: load_bound_receipt(evidence_root, lane["id"], manifest_sha256)
        for lane in manifest["phases"]
    }

    def satisfied(lane_id: str) -> bool:
        lane = lane_by_id[lane_id]
        receipt = receipts[lane_id]
        if is_operator_lane(lane):
            return _receipt_is_operator_attested(receipt)
        return _receipt_is_controller_verified(receipt)

    lanes_out: list[dict[str, Any]] = []
    operator_gates: list[dict[str, Any]] = []
    complete = True
    for lane in manifest["phases"]:
        lane_id = lane["id"]
        blocked_by = [
            dependency
            for dependency in lane["depends_on"]
            if not satisfied(dependency)
        ]
        item: dict[str, Any] = {
            "lane_id": lane_id,
            "track": lane.get("track"),
            "title": lane["title"],
            "kind": lane["kind"],
            "owner": lane["expert"],
            "reviewer": lane["review"],
            "depends_on": list(lane["depends_on"]),
            "verifier": dict(lane["verifier"]),
            "blocked_by": blocked_by,
        }
        receipt = receipts[lane_id]
        if is_operator_lane(lane):
            receipt_present = _receipt_is_operator_attested(receipt)
            item["state"] = "awaiting-operator"
            item["operator_receipt_present"] = receipt_present
            item["dependencies_satisfied"] = not blocked_by
            item["satisfies_dependents"] = receipt_present
            item["reason"] = (
                "operator receipt recorded; controller grants no authority"
                if receipt_present
                else (
                    "operator lane: the controller never verifies it; "
                    + OPERATOR_AUTHORIZATION_NOTE
                )
            )
            operator_gates.append(
                {
                    "lane_id": lane_id,
                    "dependencies_satisfied": not blocked_by,
                    "operator_receipt_present": receipt_present,
                }
            )
        elif blocked_by:
            item["state"] = "pending"
            item["satisfies_dependents"] = False
            item["reason"] = (
                "dependencies not satisfied: " + ",".join(blocked_by)
            )
            if receipt is not None:
                item["stale_receipt"] = True
        elif _receipt_is_controller_verified(receipt):
            item["state"] = "verified"
            item["satisfies_dependents"] = True
            item["reason"] = "controller receipt bound to the current manifest"
        else:
            item["state"] = "dispatchable"
            item["satisfies_dependents"] = False
            item["reason"] = (
                "dependencies satisfied; awaiting fresh machine verification "
                "by `verify`"
            )
            if receipt is not None:
                item["stale_receipt"] = True
        complete = complete and item["satisfies_dependents"]
        lanes_out.append(item)
    dispatchable_now = [item["lane_id"] for item in lanes_out if item["state"] == "dispatchable"]
    return {
        "schema": STATUS_SCHEMA,
        "campaign_id": manifest["campaign_id"],
        "manifest_sha256": manifest_sha256,
        "evidence_root": str(evidence_root.resolve()),
        "complete": complete,
        "terminal_claim": manifest.get("terminal_claim"),
        "dispatchable_now": dispatchable_now,
        "operator_gates": operator_gates,
        "lanes": lanes_out,
    }


def verify_lane(
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    lane_id: str,
    evidence_root: Path,
) -> dict[str, Any]:
    """Recompute one lane's evidence fresh from disk and write its receipt."""
    lane = next(
        (item for item in manifest["phases"] if item["id"] == lane_id), None
    )
    if lane is None:
        raise UnknownLaneError(f"unknown lane id: {lane_id}")
    if is_operator_lane(lane):
        raise OperatorAuthorityRefusal(
            f"lane '{lane_id}' (kind {lane['kind']}, verifier "
            f"{lane['verifier']['kind']}) is an operator lane: the controller "
            "never verifies it and grants no authority; "
            + OPERATOR_AUTHORIZATION_NOTE
        )
    report = derive_status(manifest, manifest_sha256, evidence_root)
    state_by_id = {item["lane_id"]: item for item in report["lanes"]}
    unsatisfied = [
        dependency
        for dependency in lane["depends_on"]
        if not state_by_id[dependency]["satisfies_dependents"]
    ]
    if unsatisfied:
        raise DependencyGateError(
            f"lane '{lane_id}' cannot verify until dependencies are satisfied: "
            + ",".join(unsatisfied)
        )
    kind = lane["verifier"]["kind"]
    if kind == "assertion-free":
        checks, attestation = assertion_free_checks(lane, evidence_root)
        base: dict[str, Any] = dict(attestation)
    elif kind in MACHINE_VERIFIER_KINDS:
        checks = lane_machine_checks(manifest, lane)
        base = {}
    else:  # defensive: manifest validation covers this
        raise WorkflowError(
            f"lane {lane_id} verifier kind {kind} is not controller-verifiable"
        )
    receipt = {
        **base,
        "lane": lane_id,
        "verifier_kind": kind,
        "verified_at": utc_now_iso(),
        "checks": checks,
        "manifest_sha256": manifest_sha256,
    }
    lane_dir = evidence_root / lane_id
    lane_dir.mkdir(parents=True, exist_ok=True)
    (lane_dir / "verification.json").write_bytes(canonical_json(receipt))
    return receipt


def _evidence_dir_name(manifest: Mapping[str, Any]) -> str:
    raw = manifest.get("evidence_root", f"{DEFAULT_EVIDENCE_DIR}/")
    return _safe_repo_relative(raw, "evidence_root")


def emit_agent_tasks(
    manifest: Mapping[str, Any], report: Mapping[str, Any]
) -> dict[str, Any]:
    """Deterministic owner/operator cards; grants no authority."""
    lane_by_id = {lane["id"]: lane for lane in manifest["phases"]}
    evidence_dir = _evidence_dir_name(manifest)
    tasks: list[dict[str, Any]] = []
    operator_gates: list[dict[str, Any]] = []
    for item in report["lanes"]:
        lane = lane_by_id[item["lane_id"]]
        lane_id = lane["id"]
        common: dict[str, Any] = {
            "lane_id": lane_id,
            "title": lane["title"],
            "kind": lane["kind"],
            "track": lane.get("track"),
            "owner": lane["expert"],
            "reviewer": lane["review"],
            "depends_on": list(lane["depends_on"]),
            "evidence_contract": dict(lane["verifier"]),
            "evidence_dir": f"{evidence_dir}/{lane_id}/",
            "standing_prohibitions": list(STANDING_PROHIBITIONS),
            "caveats": list(manifest["epic_caveats_binding"]),
        }
        if item["state"] == "dispatchable":
            tasks.append({"task_id": f"{lane_id}-owner", "role": "owner", **common})
        elif item["state"] == "awaiting-operator":
            operator_gates.append(
                {
                    "task_id": f"{lane_id}-operator-gate",
                    "role": "operator-gate",
                    "dependencies_satisfied": item["dependencies_satisfied"],
                    "operator_receipt_present": item["operator_receipt_present"],
                    "requires_fresh_operator_authorization": True,
                    "authorization": OPERATOR_AUTHORIZATION_NOTE,
                    **common,
                }
            )
    return {
        "schema": WAVE_SCHEMA,
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
        f"evidence_root={report['evidence_root']}",
        f"complete={str(report['complete']).lower()}",
    ]
    for lane in report["lanes"]:
        suffix = (
            f" blocked_by={','.join(lane['blocked_by'])}" if lane["blocked_by"] else ""
        )
        lines.append(
            f"{lane['lane_id']}: {lane['state']} kind={lane['kind']} "
            f"track={lane.get('track') or '-'} owner={lane['owner']} "
            f"reviewer={lane['reviewer']} verifier={lane['verifier']['kind']}"
            f"{suffix} -- {lane['reason']}"
        )
    lines.append("dispatchable_now=" + ",".join(report["dispatchable_now"]))
    lines.append(
        "operator_gates_ready="
        + ",".join(
            gate["lane_id"]
            for gate in report["operator_gates"]
            if gate["dependencies_satisfied"]
        )
    )
    return "\n".join(lines)


def render_receipt(
    receipt: Mapping[str, Any], evidence_root: Path
) -> str:
    lines = [
        f"VERIFIED lane={receipt['lane']} verifier={receipt['verifier_kind']} "
        f"manifest_sha256={receipt['manifest_sha256']}",
        f"receipt={evidence_root / receipt['lane'] / 'verification.json'}",
        "checks:",
    ]
    for check in receipt["checks"]:
        if check["check"] == "path_exists":
            detail = "MISSING" if not check.get("present") else check.get("type", "?")
            if "sha256" in check:
                detail += f" sha256={check['sha256']} bytes={check['bytes']}"
            lines.append(f"  [path_exists] {check['path']} ({detail})")
        elif check["check"] == "hosttest_pending":
            lines.append(f"  [hosttest_pending] {check['note']}")
        elif check["check"] == "assertion_free_receipt":
            lines.append(
                f"  [assertion_free_receipt] {check['path']} "
                f"verified_by={check['verified_by']}"
            )
        else:
            lines.append(f"  [{check['check']}] {json.dumps(check, sort_keys=True)}")
    return "\n".join(lines)


def render_wave(wave: Mapping[str, Any]) -> str:
    lines = [
        f"campaign={wave['campaign_id']}",
        f"manifest_sha256={wave['manifest_sha256']}",
        f"max_parallel_agents={wave['max_parallel_agents']}",
    ]
    for card in wave["tasks"]:
        lines.append(
            f"task {card['task_id']} owner={card['owner']} "
            f"reviewer={card['reviewer']} kind={card['kind']} "
            f"track={card.get('track') or '-'} evidence={card['evidence_dir']}"
        )
    for card in wave["operator_gates"]:
        lines.append(
            f"gate {card['task_id']} owner={card['owner']} "
            f"reviewer={card['reviewer']} kind={card['kind']} "
            f"deps_satisfied={str(card['dependencies_satisfied']).lower()} "
            "requires_fresh_operator_authorization=true"
        )
    return "\n".join(lines)


def resolve_evidence_root(
    manifest: Mapping[str, Any], override: Path | None
) -> Path:
    if override is not None:
        return Path(override)
    return REPO_ROOT / _evidence_dir_name(manifest)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=None,
        help="override the manifest-declared evidence root (repo-relative "
        f"{DEFAULT_EVIDENCE_DIR}/ by default)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("status", "verify", "emit-agent-tasks"):
        child = subparsers.add_parser(command)
        child.add_argument("--json", action="store_true")
        if command == "verify":
            child.add_argument("lane_id", help="lane id to verify fresh")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest_path = args.manifest.resolve(strict=True)
        manifest, manifest_sha256 = load_manifest(manifest_path)
        evidence_root = resolve_evidence_root(manifest, args.evidence_root)
    except (OSError, WorkflowError) as error:
        print(f"UNIVERSAL_ONRAMP_REFUSED: {error}", file=sys.stderr)
        return 1

    if args.command == "verify":
        try:
            receipt = verify_lane(
                manifest, manifest_sha256, args.lane_id, evidence_root
            )
        except OperatorAuthorityRefusal as error:
            print(f"OPERATOR_AUTHORITY_REQUIRED: {error}", file=sys.stderr)
            return 3
        except (UnknownLaneError, DependencyGateError) as error:
            print(f"VERIFY_REFUSED: {error}", file=sys.stderr)
            return 2
        except (OSError, WorkflowError) as error:
            print(f"VERIFY_FAILED: {error}", file=sys.stderr)
            return 1
        if args.json:
            sys.stdout.buffer.write(canonical_json(receipt))
        else:
            print(render_receipt(receipt, evidence_root))
        return 0

    try:
        report = derive_status(manifest, manifest_sha256, evidence_root)
    except (OSError, WorkflowError) as error:
        print(f"UNIVERSAL_ONRAMP_REFUSED: {error}", file=sys.stderr)
        return 1
    if args.command == "emit-agent-tasks":
        output = emit_agent_tasks(manifest, report)
        if args.json:
            sys.stdout.buffer.write(canonical_json(output))
        else:
            print(render_wave(output))
    elif args.json:
        sys.stdout.buffer.write(canonical_json(report))
    else:
        print(render_status(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
