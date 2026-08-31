#!/usr/bin/env python3
"""Fail closed until the S19k native owner covers every terminal population.

This is a source/readiness verifier only.  Controller-facing firmware evidence
supports three *logical* chains and BHB56902/BHB56903 profile selection, but it
does not prove connector-face geometry or electrical operation.  Runtime source
must therefore expose one opaque, profile-aware population admission before the
persistent product matrix can become reachable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, NoReturn


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent
HAL_PATH = "DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
OWNER_PATH = "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs"
RUNNER_PATH = "DCENT_OS_Antminer/scripts/dcentrald_s19k_tmp_remote_run.sh"
RECEIPT_NAME = "verification.json"
SCHEMA = "dcentos.s19k-native-population-coverage/v1"
PROFILES = (
    "bhb56902-only",
    "bhb56903-only",
    "mixed-bhb56902-bhb56903",
    "all-three-uarts-populated",
)
LOGICAL_ROUTES = (
    {"logical_chain": 0, "logical_board_address": 1, "uart": "/dev/ttyS3", "plug_gpio": 439, "reset_gpio": 454},
    {"logical_chain": 1, "logical_board_address": 2, "uart": "/dev/ttyS2", "plug_gpio": 440, "reset_gpio": 455},
    {"logical_chain": 2, "logical_board_address": 3, "uart": "/dev/ttyS1", "plug_gpio": 441, "reset_gpio": 456},
)
READY_MARKERS = {
    HAL_PATH: (
        "S19K_NATIVE_LOGICAL_CHAIN_ROUTES",
        "S19kNativePopulationAdmission",
        "/dev/ttyS3",
        "reset_gpio: 454",
    ),
    OWNER_PATH: (
        "S19K_NATIVE_SUPPORTED_POPULATION_PROFILES",
        "S19kNativePopulationAdmission",
        "BHB56902",
        "BHB56903",
        "mixed-bhb56902-bhb56903",
        "all-three-uarts-populated",
    ),
    RUNNER_PATH: (
        "PROFILE_SUMMARY",
        "BHB56902",
        "BHB56903",
        "mixed-bhb56902-bhb56903",
        "all-three-uarts-populated",
        "LIVE_IDENTITY_EXPECTED_MASK",
        "EEPROM_MASK",
    ),
}
FIXED_MARKERS = (
    "S19K_NATIVE_LOGICAL_UART_PAIR",
    "S19K_NATIVE_UART_CHAIN_RESET_MAP",
    "Live88TwoBhb56903Slots2_3",
)


class PopulationCoverageError(ValueError):
    """Runtime population coverage is absent, stale, or overclaimed."""


def fail(message: str) -> NoReturn:
    raise PopulationCoverageError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _source(repo_root: Path, relative: str) -> tuple[bytes, str]:
    path = repo_root.joinpath(*relative.split("/"))
    if not path.is_file() or path.is_symlink():
        fail(f"population owner source is absent or unsafe: {relative}")
    data = path.read_bytes()
    if len(data) > 4 * 1024 * 1024:
        fail(f"population owner source is unexpectedly large: {relative}")
    try:
        return data, data.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"population owner source is not UTF-8: {relative}: {error}")


def audit_source_tree(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    texts: dict[str, str] = {}
    for relative in READY_MARKERS:
        data, text = _source(repo_root, relative)
        texts[relative] = text
        sources.append(
            {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        )
    missing = {
        relative: [marker for marker in markers if marker not in texts[relative]]
        for relative, markers in READY_MARKERS.items()
    }
    missing = {relative: markers for relative, markers in missing.items() if markers}
    fixed = sorted(
        marker
        for marker in FIXED_MARKERS
        if any(marker in text for text in texts.values())
    )
    classification = "ready" if not missing and not fixed else "blocked_tooling"
    return {
        "schema": SCHEMA,
        "classification": classification,
        "blocker": (
            None
            if classification == "ready"
            else "native owner/runner lacks the complete profile-aware three-UART contract"
        ),
        "required_profiles": list(PROFILES),
        "logical_chain_routes": list(LOGICAL_ROUTES),
        "missing_runtime_markers": missing,
        "fixed_route_markers_present": fixed,
        "controller_facing_transport_supported": True,
        "physical_connector_geometry_proven": False,
        "electrical_interchangeability_proven": False,
        "source_files": sources,
        "live_hardware_contacted": False,
        "authority_granted": False,
    }


def audit(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    return audit_source_tree(repo_root)


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    audit_result = audit_source_tree()
    if audit_result["classification"] != "ready":
        fail(str(audit_result["blocker"]))
    receipt = evidence_dir / RECEIPT_NAME
    if not receipt.is_file() or receipt.is_symlink():
        raise FileNotFoundError(str(receipt))
    data = receipt.read_bytes()
    if len(data) > 1024 * 1024:
        fail("population coverage receipt is too large")
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"population coverage receipt is invalid: {error}")
    if value != audit_result or canonical_json(value) != data:
        fail("population coverage receipt is stale or noncanonical")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("evidence_dir", type=Path, nargs="?")
    args = parser.parse_args(argv)
    if not args.audit and args.evidence_dir is None:
        parser.error("evidence_dir is required unless --audit is used")
    try:
        result = (
            audit_source_tree()
            if args.audit
            else verify_workflow_evidence(args.evidence_dir.resolve(strict=True))
        )
    except (OSError, PopulationCoverageError) as error:
        print(f"S19K_NATIVE_POPULATION_COVERAGE_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0 if result["classification"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
