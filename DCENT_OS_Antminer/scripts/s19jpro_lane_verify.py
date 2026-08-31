#!/usr/bin/env python3
"""Offline evidence verifier and source auditor for the S19j Pro
complete-enablement campaign.

Two jobs, both desk-only:

1. ``audit_source_tree(phase_id)`` answers "is this phase's *source-side*
   prerequisite work done?" from live repository bytes. The controller uses
   it to derive readiness for desk phases before their evidence exists.
2. ``verify_workflow_evidence(evidence_dir)`` accepts or refuses a phase
   evidence directory. A receipt is accepted only when the recorded file
   manifest equals a freshly recomputed digest of every evidence byte, every
   required leaf exists, every per-phase repository condition currently
   holds, and the receipt's verification_id matches its own content.

The module has no network, serial, GPIO, power, flash, process-spawning, or
miner-contact code. It cannot create operator authority; the
``operator_authorization`` field records authority granted elsewhere.

``prepare`` builds a receipt for an already-staged evidence directory so
operators and owner agents do not hand-write manifests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Callable, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REPO_ROOT = PROJECT_ROOT.parent.parent

CAMPAIGN_ID = "s19j-pro-complete-enablement-20260826"
RECEIPT_SCHEMA = "dcentos.s19jpro-phase-receipt/v1"
RECEIPT_NAME = "verification.json"
MAX_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 512
ARTIFACT_PREFIX = "artifacts/s19jpro-enablement/"
ACCEPTED_RE = re.compile(r"accepted", re.IGNORECASE)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

INSTALLER = (
    REPO_ROOT / "projects/dcent-toolbox/src/dcent_toolbox/core/installer.py"
)
SKUS = REPO_ROOT / "DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf"
SUPPORT_MATRIX = REPO_ROOT / "SUPPORT_MATRIX.md"
MODEL_RS = REPO_ROOT / "DCENT_OS_Antminer/dcentrald/dcentrald/src/model.rs"
WEB_PACKAGES = REPO_ROOT / "DCENT_OS_Antminer/web_packages"

INSTALL_ROUTES = (
    "braiinsos-am2-s19jpro-zynq-runtime",
    "dcentos-am2-s19jpro-zynq-runtime",
    "stock-am2-s19jpro-zynq-evidence-gap",
    "stock-am3-bb-sd_first_boot",
    "stock-am3-bb-nand-first-install-lab",
    "amlogic-s19jpro-stock-rootfs_window_lab",
    "amlogic-s19jproplus-stock-rootfs_window_lab",
    "amlogic-vnish-rootfs_window_lab",
    "bcb100-s19jpro-passthrough-lab",
)
WEB_UNLOCK_PACKAGES = (
    "dcentos-signature-bypass.tar.gz",
    "dcentos-ssh-enabler.tar.gz",
    "dcentos-api-enabler.tar.gz",
)
S19JPRO_FAMILY_TARGETS = (
    "am2-s19jpro-zynq",
    "am3-bb-s19jpro",
    "am3-s19jpro-aml",
    "am3-s19jproplus",
    "cv1835-s19jpro",
)


class LaneVerifyError(Exception):
    """Malformed evidence, a refused receipt, or a refused source audit."""


# --------------------------------------------------------------------------
# Phase registry
# --------------------------------------------------------------------------

# Leaf conventions ("dir" leaves must be non-empty directories, file leaves
# non-empty regular files):
#   authorization.txt   exact operator authorization statement (operator phases)
#   trial/              raw trial output from the unit
#   instrument/         instrument captures (scope/DMM/thermal/serial)
#   transcript.txt      run transcript; share-bearing phases must show accepts
#   serial-capture/     UART boot captures
#   endurance/          soak logs
#   wall-power.csv      wall power samples across the soak
#   custody.json + fingerprint.txt   unit custody + read-only board print
PHASE_SPECS: dict[str, dict[str, Any]] = {
    # -- foundation (desk) ---------------------------------------------------
    "variant-matrix-closure": {
        "kind": "desk",
        "leaves": ["variant-matrix.json", "analysis.md"],
        "conditions": ["skus_first_class_rows"],
    },
    "unlock-surface-closure": {
        "kind": "desk",
        "leaves": ["unlock-ladder.md", "analysis.md"],
        "conditions": ["unlock_routes_present", "web_unlock_packages_present"],
    },
    "hashboard-revision-atlas": {
        "kind": "desk",
        "leaves": ["hashboard-atlas.json", "analysis.md"],
        "conditions": [],
    },
    # -- XIL lane ------------------------------------------------------------
    "xil-full-chain-init": {
        "kind": "desk",
        "leaves": ["analysis.md"],
        "pin": {
            "repo_path": (
                "DCENT_OS_Antminer/dcentrald/dcentrald/tests/"
                "s19jpro_full_chain_init.rs"
            ),
            "marker": "S19JPRO_FULL_CHAIN_126",
        },
    },
    "xil-stock-first-install-plan": {
        "kind": "desk",
        "leaves": ["analysis.md"],
        "pin": {
            "repo_path": (
                ""
                "BENCH_CARDS/XIL_STOCK_FIRST_INSTALL.md"
            ),
            "marker": "OPERATOR BENCH CARD",
        },
    },
    "xil-stock-unlock-live": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
    },
    "xil-no-work-safeoff": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "instrument"],
    },
    "xil-bounded-work": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    "xil-endurance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "endurance", "wall-power.csv"],
    },
    "xil-persistent-install": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial"],
        "seal_artifact": True,
    },
    "xil-acceptance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    # -- BB lane -------------------------------------------------------------
    "bb-sd-coldboot-diagnosis": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "serial-capture"],
    },
    "bb-sd-first-boot": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial"],
        "seal_artifact": True,
    },
    "bb-safety-bench": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "instrument"],
    },
    "bb-stock-ssh-unlock-live": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
    },
    "bb-bounded-work": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    "bb-endurance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "endurance", "wall-power.csv"],
    },
    "bb-nand-first-install": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial"],
        "seal_artifact": True,
    },
    "bb-acceptance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    # -- Amlogic lane --------------------------------------------------------
    "aml-unit-custody": {
        "kind": "operator",
        "leaves": ["authorization.txt", "custody.json", "fingerprint.txt"],
    },
    "aml-otg-unlock-live": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
    },
    "aml-rootfs-window-bounded": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    "aml-endurance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "endurance", "wall-power.csv"],
    },
    "aml-persistent-install": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial"],
        "seal_artifact": True,
    },
    "aml-acceptance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    # -- S19j Pro+ lane ------------------------------------------------------
    "s19jproplus-td003-promotion": {
        "kind": "desk",
        "leaves": ["promotion-evidence.md"],
        "conditions": ["td003_s19jproplus_release", "skus_first_class_rows"],
        "pin": {
            "repo_path": (
                ""
                "S19JPROPLUS_TD003_PROMOTION_EVIDENCE.md"
            ),
            "marker": "TD-003 PROMOTION EVIDENCE",
        },
    },
    "s19jproplus-unit-custody": {
        "kind": "operator",
        "leaves": ["authorization.txt", "custody.json", "fingerprint.txt"],
    },
    "s19jproplus-no-work-safeoff": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "instrument"],
    },
    "s19jproplus-bounded-work": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    "s19jproplus-endurance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "endurance", "wall-power.csv"],
    },
    "s19jproplus-persistent-install": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial"],
        "seal_artifact": True,
    },
    "s19jproplus-acceptance": {
        "kind": "operator",
        "leaves": ["authorization.txt", "trial", "transcript.txt"],
        "require_accepted": True,
    },
    # -- CV1835 lane ---------------------------------------------------------
    "cv-unit-acquisition": {
        "kind": "operator",
        "leaves": ["authorization.txt", "custody.json", "fingerprint.txt"],
    },
    "cv-emmc-recovery-plan": {
        "kind": "desk",
        "leaves": ["analysis.md"],
        "pin": {
            "repo_path": (
                ""
                "CV1835_EMMC_RECOVERY_PLAN.md"
            ),
            "marker": "CV1835 EMMC RECOVERY PLAN",
        },
    },
    # -- closeout ------------------------------------------------------------
    "support-tier-promotion": {
        "kind": "desk",
        "leaves": ["promotion-ledger.md"],
        "conditions": ["skus_first_class_rows", "support_tiers_promoted"],
    },
}


# --------------------------------------------------------------------------
# Repository conditions (shared by audit + verify; both must stay truthful)
# --------------------------------------------------------------------------

def _read(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _td003_function_bodies(model_text: str) -> str:
    chunks = []
    for name in (
        "td003_management_only_model",
        "td003_management_only_board_target",
    ):
        match = re.search(
            rf"fn {name}\b.*?(?=\nfn |\Z)", model_text, re.DOTALL
        )
        if match:
            chunks.append(match.group(0))
    return "\n".join(chunks)


def condition_skus_first_class_rows() -> tuple[bool, str]:
    text = _read(SKUS)
    missing = [
        target
        for target in ("am3-s19jpro-aml", "am3-s19jproplus")
        if f"|{target}|" not in text
    ]
    if missing:
        return False, (
            "skus.conf lacks first-class rows for: " + ", ".join(missing)
        )
    return True, "skus.conf carries am3-s19jpro-aml and am3-s19jproplus rows"


def condition_td003_s19jproplus_release() -> tuple[bool, str]:
    body = _td003_function_bodies(_read(MODEL_RS))
    if not body:
        return False, "TD-003 refuse-list functions not found in model.rs"
    if "s19jpro" in body:
        return False, (
            "TD-003 refuse-list still intercepts s19jproplus in model.rs "
            "(td003_management_only_model / td003_management_only_board_target)"
        )
    return True, "TD-003 refuse-list no longer intercepts s19jproplus"


def condition_unlock_routes_present() -> tuple[bool, str]:
    text = _read(INSTALLER)
    missing = [route for route in INSTALL_ROUTES if route not in text]
    if missing:
        return False, "installer routes absent: " + ", ".join(missing)
    return True, f"all {len(INSTALL_ROUTES)} S19j Pro install routes present"


def condition_web_unlock_packages_present() -> tuple[bool, str]:
    missing = [
        name
        for name in WEB_UNLOCK_PACKAGES
        if not (WEB_PACKAGES / name).is_file()
    ]
    if missing:
        return False, "web unlock packages absent: " + ", ".join(missing)
    return True, "signature-bypass/ssh-enabler/api-enabler web packages built"


def condition_support_tiers_promoted() -> tuple[bool, str]:
    text = _read(SUPPORT_MATRIX)
    missing = [
        target
        for target in S19JPRO_FAMILY_TARGETS
        if f"| {target} |" not in text
    ]
    if missing:
        return False, (
            "SUPPORT_MATRIX.md lacks rows for: " + ", ".join(missing)
        )
    still_unsupported: list[str] = []
    for line in text.splitlines():
        if not line.startswith("| antminer |"):
            continue
        for target in S19JPRO_FAMILY_TARGETS:
            if target in line and "| unsupported |" in line:
                still_unsupported.append(target)
    if still_unsupported:
        return False, (
            "SUPPORT_MATRIX still marks unsupported: "
            + ", ".join(sorted(set(still_unsupported)))
        )
    return True, "all five S19j Pro family targets carry promoted rows"


CONDITIONS: dict[str, Callable[[], tuple[bool, str]]] = {
    "skus_first_class_rows": condition_skus_first_class_rows,
    "td003_s19jproplus_release": condition_td003_s19jproplus_release,
    "unlock_routes_present": condition_unlock_routes_present,
    "web_unlock_packages_present": condition_web_unlock_packages_present,
    "support_tiers_promoted": condition_support_tiers_promoted,
}


def failing_conditions(phase_id: str) -> list[str]:
    spec = PHASE_SPECS.get(phase_id)
    if spec is None:
        return []
    failures: list[str] = []
    for name in spec.get("conditions", []):
        ok, detail = CONDITIONS[name]()
        if not ok:
            failures.append(detail)
    return failures


def pin_state(phase_id: str) -> tuple[bool, str]:
    """A pinned deliverable exists on disk and contains its marker."""
    spec = PHASE_SPECS.get(phase_id)
    if spec is None or "pin" not in spec:
        return True, ""
    pin = spec["pin"]
    path = REPO_ROOT / Path(*PurePosixPath(pin["repo_path"]).parts)
    if not path.is_file():
        return False, f"pinned deliverable absent: {pin['repo_path']}"
    if pin["marker"] not in _read(path):
        return False, f"pinned deliverable lacks marker {pin['marker']!r}"
    return True, ""


def audit_source_tree(phase_id: str) -> dict[str, Any] | None:
    """Source-level readiness for one phase (never verifies evidence)."""
    spec = PHASE_SPECS.get(phase_id)
    if spec is None:
        return None
    blockers = failing_conditions(phase_id)
    pin_ok, pin_detail = pin_state(phase_id)
    if not pin_ok:
        blockers.append(pin_detail)
    if blockers:
        return {"classification": "blocked_tooling", "blocker": "; ".join(blockers)}
    return {"classification": "ready", "blocker": None}


# --------------------------------------------------------------------------
# Evidence verification
# --------------------------------------------------------------------------

def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def safe_repo_path(raw: str, label: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise LaneVerifyError(f"{label} must be a non-empty repository-relative path")
    logical = PurePosixPath(raw)
    if logical.is_absolute() or ".." in logical.parts or "\\" in raw:
        raise LaneVerifyError(f"{label} must stay repository-relative: {raw!r}")
    candidate = (REPO_ROOT / Path(*logical.parts)).resolve()
    try:
        candidate.relative_to(REPO_ROOT.resolve())
    except ValueError as error:
        raise LaneVerifyError(f"{label} escapes the repository: {raw!r}") from error
    return candidate


def _check_leaf(evidence_dir: Path, leaf: str) -> None:
    path = evidence_dir / leaf
    if path.is_symlink():
        raise LaneVerifyError(f"evidence leaf {leaf} must not be a symlink")
    if "/" not in leaf and "." not in Path(leaf).name:
        # directory leaf by convention (trial, instrument, ...)
        if not path.is_dir():
            raise LaneVerifyError(f"required evidence directory absent: {leaf}")
        entries = [p for p in path.iterdir() if not p.name.startswith(".")]
        if not entries:
            raise LaneVerifyError(f"evidence directory {leaf} is empty")
        for entry in entries:
            if entry.is_symlink():
                raise LaneVerifyError(f"evidence directory {leaf} contains a symlink")
        return
    if not path.is_file():
        raise LaneVerifyError(f"required evidence leaf absent: {leaf}")
    if path.stat().st_size == 0:
        raise LaneVerifyError(f"evidence leaf {leaf} is empty")
    if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise LaneVerifyError(f"evidence leaf {leaf} exceeds {MAX_EVIDENCE_FILE_BYTES} bytes")


def _recompute_manifest(evidence_dir: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for path in sorted(evidence_dir.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(evidence_dir).as_posix()
        if relative == RECEIPT_NAME:
            continue
        if path.is_symlink():
            raise LaneVerifyError(f"evidence tree contains a symlink: {relative}")
        if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
            raise LaneVerifyError(f"evidence file exceeds size bound: {relative}")
        manifest[relative] = sha256_file(path)
    if not manifest:
        raise LaneVerifyError("evidence directory holds no evidence files")
    if len(manifest) > MAX_MANIFEST_ENTRIES:
        raise LaneVerifyError(f"evidence manifest exceeds {MAX_MANIFEST_ENTRIES} entries")
    return manifest


def _require_fields(receipt: Mapping[str, Any], names: tuple[str, ...]) -> None:
    for name in names:
        value = receipt.get(name)
        if not isinstance(value, str) or not value.strip():
            raise LaneVerifyError(f"receipt field {name} must be a non-empty string")


def _check_operator_block(spec: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
    if spec.get("kind") != "operator":
        return
    _require_fields(receipt, ("operator_authorization", "recorded_utc"))
    if len(receipt["operator_authorization"]) < 40:
        raise LaneVerifyError(
            "operator_authorization must record who authorized what, when, and for which exact action"
        )
    identity = receipt.get("unit_identity")
    if not isinstance(identity, dict):
        raise LaneVerifyError("operator receipts must carry unit_identity")
    for field in ("ip_or_serial", "control_board", "firmware_state"):
        if not isinstance(identity.get(field), str) or not identity[field].strip():
            raise LaneVerifyError(f"unit_identity.{field} is required")


def _check_accepted(evidence_dir: Path) -> None:
    transcript = evidence_dir / "transcript.txt"
    text = transcript.read_text(encoding="utf-8", errors="replace")
    if ACCEPTED_RE.search(text) is None:
        raise LaneVerifyError(
            "share-bearing phases must show at least one accepted line in transcript.txt"
        )


def _check_artifact_seal(receipt: Mapping[str, Any]) -> None:
    artifact = receipt.get("artifact")
    if not isinstance(artifact, dict):
        raise LaneVerifyError("persistent-install receipts must seal their artifact")
    _require_fields(artifact, ("id", "sha256", "local_path", "portable_path"))
    digest = artifact["sha256"]
    if SHA256_RE.fullmatch(digest) is None:
        raise LaneVerifyError("sealed artifact sha256 is not canonical")
    if not artifact["local_path"].startswith(ARTIFACT_PREFIX):
        raise LaneVerifyError(
            f"sealed artifact local_path must live under {ARTIFACT_PREFIX}"
        )
    path = safe_repo_path(artifact["local_path"], "sealed artifact local_path")
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"sealed artifact absent: {path}")
    actual_digest = sha256_file(path)
    if actual_digest != digest:
        raise LaneVerifyError(
            f"sealed artifact identity mismatch: expected {digest}, found {actual_digest}"
        )
    expected_portable = f"sha256/{digest}/{path.name}"
    if artifact["portable_path"] != expected_portable:
        raise LaneVerifyError(
            f"sealed artifact portable_path must be {expected_portable}"
        )
    bytes_value = artifact.get("bytes")
    if not isinstance(bytes_value, int) or isinstance(bytes_value, bool):
        raise LaneVerifyError("sealed artifact bytes must be an integer")
    if path.stat().st_size != bytes_value:
        raise LaneVerifyError("sealed artifact byte count does not match the file")


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"evidence directory absent: {evidence_dir}")
    phase_id = evidence_dir.name
    spec = PHASE_SPECS.get(phase_id)
    if spec is None:
        raise LaneVerifyError(f"unknown campaign phase: {phase_id}")

    for leaf in spec["leaves"]:
        _check_leaf(evidence_dir, leaf)

    receipt_path = evidence_dir / RECEIPT_NAME
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise FileNotFoundError(f"receipt absent: {receipt_path}")
    if receipt_path.stat().st_size > MAX_RECEIPT_BYTES:
        raise LaneVerifyError("receipt exceeds byte bound")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaneVerifyError(f"receipt is not valid UTF-8 JSON: {error}") from error
    if not isinstance(receipt, dict):
        raise LaneVerifyError("receipt must be a JSON object")

    _require_fields(
        receipt, ("schema", "campaign_id", "phase_id", "recorded_utc")
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise LaneVerifyError(f"receipt schema must be {RECEIPT_SCHEMA}")
    if receipt["campaign_id"] != CAMPAIGN_ID:
        raise LaneVerifyError(f"receipt campaign_id must be {CAMPAIGN_ID}")
    if receipt["phase_id"] != phase_id:
        raise LaneVerifyError("receipt phase_id does not match its evidence directory")

    recomputed = _recompute_manifest(evidence_dir)
    if receipt.get("file_manifest") != recomputed:
        raise LaneVerifyError(
            "receipt file_manifest does not match freshly recomputed evidence bytes"
        )

    _check_operator_block(spec, receipt)
    if spec.get("require_accepted"):
        _check_accepted(evidence_dir)
    if spec.get("seal_artifact"):
        _check_artifact_seal(receipt)

    failures = failing_conditions(phase_id)
    if failures:
        raise LaneVerifyError("repository conditions not met: " + "; ".join(failures))

    if "pin" in spec:
        ok, detail = pin_state(phase_id)
        if not ok:
            raise LaneVerifyError(detail)

    payload = {key: value for key, value in receipt.items() if key != "verification_id"}
    expected_id = hashlib.sha256(canonical_json(payload)).hexdigest()
    if receipt.get("verification_id") != expected_id:
        raise LaneVerifyError(
            "receipt verification_id does not match its own content"
        )
    return dict(receipt)


# --------------------------------------------------------------------------
# Receipt preparation (for already-staged evidence directories)
# --------------------------------------------------------------------------

def prepare_receipt(
    phase_id: str,
    evidence_dir: Path,
    operator_authorization: str | None = None,
    unit_identity: Mapping[str, str] | None = None,
    artifact_local_path: str | None = None,
    artifact_id: str | None = None,
) -> dict[str, Any]:
    spec = PHASE_SPECS.get(phase_id)
    if spec is None:
        raise LaneVerifyError(f"unknown campaign phase: {phase_id}")
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir():
        raise LaneVerifyError(f"stage the evidence first: {evidence_dir} does not exist")
    for leaf in spec["leaves"]:
        _check_leaf(evidence_dir, leaf)

    import datetime as _dt

    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "campaign_id": CAMPAIGN_ID,
        "phase_id": phase_id,
        "recorded_utc": _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    if spec.get("kind") == "operator":
        if not operator_authorization or len(operator_authorization) < 40:
            raise LaneVerifyError(
                "--operator-authorization must state who authorized what, when, and for which exact action"
            )
        if not unit_identity or not all(
            isinstance(unit_identity.get(key), str) and unit_identity[key].strip()
            for key in ("ip_or_serial", "control_board", "firmware_state")
        ):
            raise LaneVerifyError(
                "operator receipts need --unit-ip-or-serial, --control-board, --firmware-state"
            )
        receipt["operator_authorization"] = operator_authorization
        receipt["unit_identity"] = dict(unit_identity)
    if spec.get("seal_artifact"):
        if not artifact_local_path or not artifact_id:
            raise LaneVerifyError(
                "sealing phases need --artifact-path (repo-relative) and --artifact-id"
            )
        path = safe_repo_path(artifact_local_path, "artifact local_path")
        if not artifact_local_path.startswith(ARTIFACT_PREFIX):
            raise LaneVerifyError(
                f"sealed artifact local_path must live under {ARTIFACT_PREFIX}"
            )
        if not path.is_file():
            raise FileNotFoundError(f"artifact to seal absent: {path}")
        digest = sha256_file(path)
        receipt["artifact"] = {
            "id": artifact_id,
            "sha256": digest,
            "bytes": path.stat().st_size,
            "local_path": artifact_local_path,
            "portable_path": f"sha256/{digest}/{path.name}",
        }
    receipt["file_manifest"] = _recompute_manifest(evidence_dir)
    receipt["verification_id"] = hashlib.sha256(
        canonical_json(receipt)
    ).hexdigest()
    (evidence_dir / RECEIPT_NAME).write_bytes(canonical_json(receipt))

    failures = failing_conditions(phase_id)
    ok, pin_detail = pin_state(phase_id)
    if not ok:
        failures.append(pin_detail)
    if failures:
        print(
            "WARNING: receipt written, but the phase will NOT verify until: "
            + "; ".join(failures),
            file=sys.stderr,
        )
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare", help="write a receipt for a staged evidence directory"
    )
    prepare.add_argument("--phase", required=True)
    prepare.add_argument("--evidence-dir", type=Path, default=None)
    prepare.add_argument("--operator-authorization", default=None)
    prepare.add_argument("--unit-ip-or-serial", default=None)
    prepare.add_argument("--control-board", default=None)
    prepare.add_argument("--firmware-state", default=None)
    prepare.add_argument("--artifact-path", default=None)
    prepare.add_argument("--artifact-id", default=None)

    audit = subparsers.add_parser("audit", help="print source readiness for a phase")
    audit.add_argument("--phase", required=True)

    verify = subparsers.add_parser(
        "verify", help="verify a staged evidence directory in place"
    )
    verify.add_argument("--evidence-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            result = audit_source_tree(args.phase)
            if result is None:
                print(f"unknown phase: {args.phase}", file=sys.stderr)
                return 1
            sys.stdout.buffer.write(canonical_json(result))
            return 0
        if args.command == "prepare":
            evidence_dir = args.evidence_dir or (
                REPO_ROOT / ".s19jpro-enablement-evidence" / args.phase
            )
            identity = (
                {
                    "ip_or_serial": args.unit_ip_or_serial,
                    "control_board": args.control_board,
                    "firmware_state": args.firmware_state,
                }
                if args.unit_ip_or_serial
                else None
            )
            receipt = prepare_receipt(
                args.phase,
                evidence_dir,
                operator_authorization=args.operator_authorization,
                unit_identity=identity,
                artifact_local_path=args.artifact_path,
                artifact_id=args.artifact_id,
            )
            sys.stdout.buffer.write(canonical_json(receipt))
            return 0
        verify_workflow_evidence(args.evidence_dir)
    except (LaneVerifyError, OSError) as error:
        print(f"S19JPRO_LANE_REFUSED: {error}", file=sys.stderr)
        return 1
    print("S19JPRO_LANE_VERIFIED", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
