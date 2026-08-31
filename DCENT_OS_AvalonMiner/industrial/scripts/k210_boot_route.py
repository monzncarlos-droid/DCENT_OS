#!/usr/bin/env python3
"""Adjudicate the next A1246 engineering boot route from signed measurements.

This host-only tool verifies an already completed K210 boot-policy bundle with
manifest-pinned SSHSIG keys, then deterministically ranks four replacement
paths: native AES0 flash, ROM-ISP SRAM bootstrap, JTAG SRAM bootstrap, and a
clean replacement controller.  Its output is an engineering decision record,
not a deployment receipt.  It has no miner, network, serial, USB, JTAG, ISP,
GPIO, power, flash, block-device, install, or release transport.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional, Sequence


def _load_boot_policy_module():
    path = Path(__file__).with_name("k210_boot_policy_receipt.py")
    spec = importlib.util.spec_from_file_location("k210_boot_policy_receipt", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load K210 boot-policy primitives: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boot_policy = _load_boot_policy_module()
discovery = boot_policy.discovery

SCHEMA_VERSION = 1
KIND = "dcent_k210_boot_route_adjudication"
DISPOSITION = "next_engineering_route_only_no_install_authority"
ROUTE_ORDER = (
    "native_aes0_flash",
    "rom_isp_sram_bootstrap",
    "jtag_sram_bootstrap",
    "clean_replacement_controller",
)
ROUTE_STATES = {
    "measured_compatible",
    "eligible_for_controlled_sram_probe",
    "measured_blocked",
    "requires_external_qualification",
}
AUTHORITY_CEILING = {
    "authorizes_contact": False,
    "authorizes_debug_access": False,
    "authorizes_flash_write": False,
    "authorizes_install": False,
    "authorizes_jtag_or_isp_access": False,
    "authorizes_power_or_cooling_control": False,
    "authorizes_production_hashing": False,
    "authorizes_release": False,
    "qualifies_boot_policy": False,
    "qualifies_replacement_firmware": False,
}
MAX_OUTPUT_BYTES = 256 * 1024
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class BootRouteError(RuntimeError):
    """A route input, trust join, or decision invariant failed."""


def _exact_keys(value: Mapping[str, Any], expected: Sequence[str], context: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        missing = sorted(wanted - actual)
        extra = sorted(actual - wanted)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise BootRouteError(f"{context} keys invalid: {'; '.join(details)}")


def _identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise BootRouteError(f"{context} must be a bounded identifier")
    return value


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise BootRouteError(f"{context} must be lowercase SHA-256 hex")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise BootRouteError(f"{context} must be boolean")
    return value


def _capabilities(
    value: Any, expected: Sequence[str], context: str
) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise BootRouteError(f"{context} must be an object")
    _exact_keys(value, expected, context)
    return {name: _boolean(value[name], f"{context}.{name}") for name in expected}


def _validated_boot_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BootRouteError("verified boot-policy result must be an object")
    required = {
        "authority_granted",
        "boot_policy_gate_eligible",
        "candidate_load_contract_compatible",
        "discovery_receipt_id",
        "flash_policy_sha256",
        "force_decrypt_state",
        "jtag_capabilities",
        "jtag_state",
        "plaintext_boot_supported",
        "plaintext_probe_performed",
        "plaintext_probe_result",
        "receipt_id",
        "recovery_receipt_id",
        "rom_isp_capabilities",
        "rom_isp_state",
        "state",
        "stock_backup_set_sha256",
        "target_id",
        "unit_fingerprint_sha256",
        "unit_label",
    }
    missing = sorted(required - set(value))
    if missing:
        raise BootRouteError(
            f"verified boot-policy result is missing: {', '.join(missing)}"
        )
    if value["state"] != "verified_signed_boot_policy_measurement":
        raise BootRouteError("boot-policy result is not a verified signed measurement")
    if value["authority_granted"] is not False:
        raise BootRouteError("boot-policy result exceeds its authority ceiling")
    if value["boot_policy_gate_eligible"] is not True:
        raise BootRouteError("boot-policy result is not measurement-gate eligible")
    target_id = _identifier(value["target_id"], "target_id")
    unit_label = _identifier(value["unit_label"], "unit_label")
    for field in (
        "discovery_receipt_id",
        "flash_policy_sha256",
        "receipt_id",
        "recovery_receipt_id",
        "stock_backup_set_sha256",
        "unit_fingerprint_sha256",
    ):
        _sha(value[field], field)
    load_compatible = _boolean(
        value["candidate_load_contract_compatible"],
        "candidate_load_contract_compatible",
    )
    probe_performed = _boolean(
        value["plaintext_probe_performed"], "plaintext_probe_performed"
    )
    plaintext_supported = _boolean(
        value["plaintext_boot_supported"], "plaintext_boot_supported"
    )
    force_decrypt = value["force_decrypt_state"]
    if force_decrypt not in boot_policy.FORCE_DECRYPT_STATES:
        raise BootRouteError("force_decrypt_state is unsupported")
    probe_result = value["plaintext_probe_result"]
    if probe_result not in boot_policy.PLAINTEXT_RESULTS:
        raise BootRouteError("plaintext_probe_result is unsupported")
    if plaintext_supported != (probe_result == "booted"):
        raise BootRouteError(
            "plaintext_boot_supported does not match plaintext_probe_result"
        )
    if probe_result == "booted" and not probe_performed:
        raise BootRouteError("a booted plaintext probe must have been performed")
    rom_state = value["rom_isp_state"]
    jtag_state = value["jtag_state"]
    if rom_state not in boot_policy.ACCESS_STATES:
        raise BootRouteError("rom_isp_state is unsupported")
    if jtag_state not in boot_policy.ACCESS_STATES:
        raise BootRouteError("jtag_state is unsupported")
    rom = _capabilities(
        value["rom_isp_capabilities"],
        (
            "erase_capable",
            "existing_flash_independent",
            "read_capable",
            "write_capable",
        ),
        "rom_isp_capabilities",
    )
    jtag = _capabilities(
        value["jtag_capabilities"],
        ("halt_capable", "read_memory_capable", "write_memory_capable"),
        "jtag_capabilities",
    )
    if rom_state != "accessible" and any(rom.values()):
        raise BootRouteError("inaccessible ROM ISP cannot carry capabilities")
    if rom_state == "accessible" and not rom["existing_flash_independent"]:
        raise BootRouteError(
            "accessible ROM ISP must be existing-flash-independent"
        )
    if jtag_state != "accessible" and any(jtag.values()):
        raise BootRouteError("inaccessible JTAG cannot carry capabilities")
    return {
        "candidate_load_contract_compatible": load_compatible,
        "discovery_receipt_id": value["discovery_receipt_id"],
        "flash_policy_sha256": value["flash_policy_sha256"],
        "force_decrypt_state": force_decrypt,
        "jtag_capabilities": jtag,
        "jtag_state": jtag_state,
        "plaintext_boot_supported": plaintext_supported,
        "plaintext_probe_performed": probe_performed,
        "plaintext_probe_result": probe_result,
        "receipt_id": value["receipt_id"],
        "recovery_receipt_id": value["recovery_receipt_id"],
        "rom_isp_capabilities": rom,
        "rom_isp_state": rom_state,
        "stock_backup_set_sha256": value["stock_backup_set_sha256"],
        "target_id": target_id,
        "unit_fingerprint_sha256": value["unit_fingerprint_sha256"],
        "unit_label": unit_label,
    }


def _route(route_id: str, state: str, reasons: Sequence[str]) -> dict[str, Any]:
    if route_id not in ROUTE_ORDER or state not in ROUTE_STATES:
        raise BootRouteError("internal route policy is invalid")
    if (
        not isinstance(reasons, (list, tuple))
        or not reasons
        or any(
            not isinstance(reason, str)
            or not IDENTIFIER_RE.fullmatch(reason)
            for reason in reasons
        )
    ):
        raise BootRouteError("route reasons must be non-empty identifiers")
    return {
        "route_id": route_id,
        "state": state,
        "reasons": list(reasons),
        "install_ready": False,
        "authority_granted": False,
    }


def adjudicate(verified_boot_policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic, non-authorizing engineering route decision."""

    measured = _validated_boot_result(verified_boot_policy)
    load_compatible = measured["candidate_load_contract_compatible"]

    aes0_reasons = []
    if not load_compatible:
        aes0_reasons.append("candidate_load_contract_incompatible")
    if measured["force_decrypt_state"] != "disabled":
        aes0_reasons.append("force_decrypt_enabled")
    if not measured["plaintext_probe_performed"]:
        aes0_reasons.append("plaintext_probe_not_performed")
    if measured["plaintext_probe_result"] != "booted":
        aes0_reasons.append(
            f"plaintext_probe_{measured['plaintext_probe_result']}"
        )
    if not measured["plaintext_boot_supported"]:
        aes0_reasons.append("plaintext_boot_not_supported")
    aes0 = _route(
        "native_aes0_flash",
        "measured_blocked" if aes0_reasons else "measured_compatible",
        aes0_reasons or ("signed_plaintext_boot_and_load_contract_match",),
    )

    rom_reasons = []
    if not load_compatible:
        rom_reasons.append("candidate_load_contract_incompatible")
    if measured["rom_isp_state"] != "accessible":
        rom_reasons.append(f"rom_isp_{measured['rom_isp_state']}")
    rom = measured["rom_isp_capabilities"]
    if not rom["existing_flash_independent"]:
        rom_reasons.append("rom_isp_not_flash_independent")
    if not rom["write_capable"]:
        rom_reasons.append("rom_isp_write_unavailable")
    rom_route = _route(
        "rom_isp_sram_bootstrap",
        (
            "measured_blocked"
            if rom_reasons
            else "eligible_for_controlled_sram_probe"
        ),
        rom_reasons
        or (
            "signed_rom_isp_access_and_write_prerequisites_match",
            "sram_execution_still_requires_separate_proof",
        ),
    )

    jtag_reasons = []
    if not load_compatible:
        jtag_reasons.append("candidate_load_contract_incompatible")
    if measured["jtag_state"] != "accessible":
        jtag_reasons.append(f"jtag_{measured['jtag_state']}")
    jtag = measured["jtag_capabilities"]
    if not jtag["halt_capable"]:
        jtag_reasons.append("jtag_halt_unavailable")
    if not jtag["write_memory_capable"]:
        jtag_reasons.append("jtag_memory_write_unavailable")
    jtag_route = _route(
        "jtag_sram_bootstrap",
        (
            "measured_blocked"
            if jtag_reasons
            else "eligible_for_controlled_sram_probe"
        ),
        jtag_reasons
        or (
            "signed_jtag_halt_and_memory_write_prerequisites_match",
            "program_counter_and_resume_still_require_separate_proof",
        ),
    )

    replacement = _route(
        "clean_replacement_controller",
        "requires_external_qualification",
        (
            "exact_replacement_controller_contract_required",
            "connector_signal_power_cooling_mapping_required",
            "independent_recovery_and_cutoff_required",
        ),
    )
    routes = [aes0, rom_route, jtag_route, replacement]
    selected = next(
        (
            route
            for route in routes
            if route["state"]
            in {"measured_compatible", "eligible_for_controlled_sram_probe"}
        ),
        replacement,
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "disposition": DISPOSITION,
        "target_id": measured["target_id"],
        "unit_label": measured["unit_label"],
        "unit_fingerprint_sha256": measured["unit_fingerprint_sha256"],
        "discovery_receipt_id": measured["discovery_receipt_id"],
        "recovery_receipt_id": measured["recovery_receipt_id"],
        "boot_policy_receipt_id": measured["receipt_id"],
        "stock_backup_set_sha256": measured["stock_backup_set_sha256"],
        "flash_policy_sha256": measured["flash_policy_sha256"],
        "route_priority": list(ROUTE_ORDER),
        "routes": routes,
        "selected_route": selected["route_id"],
        "selected_route_state": selected["state"],
        "selected_route_is_deployment_ready": False,
        "authority_granted": False,
        "authority_ceiling": AUTHORITY_CEILING,
    }
    digest_payload = json.dumps(
        result, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    result["adjudication_sha256"] = hashlib.sha256(
        b"DCENT-K210-BOOT-ROUTE-V1\x00" + digest_payload
    ).hexdigest()
    return result


def _safe_repo_path(repo_root: Path, value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BootRouteError(f"{context} is not pinned")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or "." in parsed.parts:
        raise BootRouteError(f"{context} must be canonical repo-relative")
    if any(":" in part or "\\" in part or not part for part in parsed.parts):
        raise BootRouteError(f"{context} must be canonical repo-relative")
    root = repo_root.resolve()
    candidate = root.joinpath(*parsed.parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise BootRouteError(f"{context} escapes the repository") from exc
    return candidate


def _pinned_boot_keys(
    manifest: Mapping[str, Any], repo_root: Path
) -> tuple[Path, Path, str, str]:
    contract = manifest.get("boot_policy_contract")
    if not isinstance(contract, dict):
        raise BootRouteError("manifest boot_policy_contract is missing")
    anchors = contract.get("trust_anchors")
    if not isinstance(anchors, dict) or set(anchors) != {"operator", "witness"}:
        raise BootRouteError("manifest boot-policy trust anchors are invalid")
    resolved = []
    for role in ("operator", "witness"):
        anchor = anchors[role]
        if anchor is None:
            raise BootRouteError(f"boot-policy {role} trust anchor is not pinned")
        if not isinstance(anchor, dict):
            raise BootRouteError(f"boot-policy {role} trust anchor is invalid")
        key_id = _sha(
            anchor.get("key_id_sha256"),
            f"boot-policy {role} key_id_sha256",
        )
        path = _safe_repo_path(
            repo_root,
            anchor.get("path"),
            f"boot-policy {role} path",
        )
        try:
            key = discovery.inspect_public_key(path)
        except discovery.DiscoveryError as exc:
            raise BootRouteError(
                f"boot-policy {role} public key is invalid: {exc}"
            ) from exc
        if key["key_id_sha256"] != key_id:
            raise BootRouteError(
                f"boot-policy {role} public key does not match its pinned key id"
            )
        resolved.append((path, key_id))
    if resolved[0][1] == resolved[1][1]:
        raise BootRouteError("boot-policy operator and witness keys must be distinct")
    return resolved[0][0], resolved[1][0], resolved[0][1], resolved[1][1]


def _write_new(path: Path, data: bytes) -> None:
    if len(data) > MAX_OUTPUT_BYTES:
        raise BootRouteError("route adjudication exceeds the output byte limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise BootRouteError(f"refusing to overwrite route output: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        handle = os.open(str(path), flags, 0o600)
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise BootRouteError(f"cannot write route output: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parent.parent / "gauntlet" / "k210_models.json"
    )
    default_repo_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    parser.add_argument("--repo-root", type=Path, default=default_repo_root)
    subparsers = parser.add_subparsers(dest="command", required=True)
    adjudication = subparsers.add_parser(
        "adjudicate",
        help="verify a signed boot-policy bundle and rank engineering routes",
    )
    adjudication.add_argument("--boot-policy-bundle", type=Path, required=True)
    adjudication.add_argument("--json-out", type=Path)
    adjudication.add_argument("--format", choices=("json", "text"), default="text")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = boot_policy._load_json(
            args.manifest, "K210 model manifest", canonical=False
        )
        operator_key, witness_key, operator_id, witness_id = _pinned_boot_keys(
            manifest, args.repo_root
        )
        verified = boot_policy.verify_bundle(
            manifest,
            args.boot_policy_bundle,
            operator_key,
            witness_key,
            operator_id,
            witness_id,
        )
        result = adjudicate(verified)
        encoded = (
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        if args.json_out is not None:
            _write_new(args.json_out, encoded)
        if args.format == "json":
            sys.stdout.buffer.write(encoded)
        else:
            print(
                f"K210_BOOT_ROUTE_OK target={result['target_id']} "
                f"route={result['selected_route']} "
                f"state={result['selected_route_state']} "
                "deployment_ready=false authority_granted=false"
            )
        return 0
    except (
        BootRouteError,
        boot_policy.BootPolicyError,
        boot_policy.recovery.RecoveryError,
        discovery.DiscoveryError,
    ) as exc:
        print(f"K210_BOOT_ROUTE_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
