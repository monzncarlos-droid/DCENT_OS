#!/usr/bin/env python3
"""Create and validate non-publishable exact-binary DCENTaxe promotion candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hardware_evidence import (
    INDEX_PATH,
    SHA256_RE,
    load_evidence_index,
    promotion_status,
    required_production_gates,
    sha256_file,
)
from target_matrix import MANIFEST_PATH, ROOT, find_target, load_manifest, require_valid

AUTHORITY = "unreleased-exact-binary-promotion-candidate"
RECEIPT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
IMMUTABLE_HARDWARE_FIELDS = {
    "feature",
    "board_target",
    "device_model",
    "model_variant",
    "hardware_family",
    "asic",
    "chip_count",
    "flash_layout",
}
FINAL_POLICY = {
    "support_tier": "production",
    "evidence_level": "sustained-soak",
    "runtime_mode": "mining",
    "install_policy": "production",
    "release_scope": "public",
    "package_policy": "public",
    "blockers": [],
}


class CandidateError(ValueError):
    """The promotion candidate is unsafe, stale, or incomplete."""


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def candidate_id(value: dict[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "candidate_id"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_fact(format_string: str) -> str:
    result = subprocess.run(
        ["git", "log", "-1", f"--format={format_string}", "--", "."],
        cwd=ROOT,
        text=True,
        encoding="ascii",
        errors="strict",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        raise CandidateError(f"cannot derive git fact {format_string!r}")
    return value


def git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        encoding="ascii",
        errors="strict",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise CandidateError("cannot derive repository HEAD")
    return value


def candidate_source_is_clean() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise CandidateError("cannot inspect candidate source working tree")
    return not result.stdout.strip()


def workspace_version() -> str:
    for line in (ROOT / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r'version\s*=\s*"([^"]+)"', line.strip())
        if match:
            return match.group(1)
    raise CandidateError("cannot derive workspace firmware version")


def proposed_registry_row(target: dict[str, Any], receipt_id: str) -> dict[str, Any]:
    if not RECEIPT_ID_RE.fullmatch(receipt_id):
        raise CandidateError("receipt_id must be 8-128 lowercase letters, digits, dot, underscore, or dash")
    if target.get("runtime_mode") != "mining" or target.get("install_policy") == "blocked":
        raise CandidateError(
            f"{target.get('board_target')}: identity-only/blocked firmware cannot become a promotion "
            "candidate; close the engineering rail/thermal runtime gate first"
        )
    row = deepcopy(target)
    row.update(FINAL_POLICY)
    row["promotion_receipt_id"] = receipt_id
    return row


def create_descriptor(
    matrix: dict[str, Any],
    target: dict[str, Any],
    receipt_id: str,
    git_commit: str,
    source_date_epoch: str,
    registry_sha256: str,
    firmware_version: str,
) -> dict[str, Any]:
    row = proposed_registry_row(target, receipt_id)
    descriptor: dict[str, Any] = {
        "schema": 1,
        "product": "DCENT_OS for ESP",
        "authority": AUTHORITY,
        "disposition": "qualification-only-not-publishable",
        "publishable": False,
        "board_target": target["board_target"],
        "receipt_id": receipt_id,
        "source": {
            "git_commit": git_commit,
            "source_date_epoch": source_date_epoch,
            "registry_sha256": registry_sha256,
            "firmware_version": firmware_version,
            "git_dirty": False,
        },
        "registry_row": row,
        "required_gates": required_production_gates(matrix, target),
    }
    descriptor["candidate_id"] = candidate_id(descriptor)
    return descriptor


def validate_descriptor(
    descriptor: dict[str, Any],
    matrix: dict[str, Any],
    registry_sha256: str,
    git_commit: str | None = None,
    source_date_epoch: str | None = None,
    firmware_version: str | None = None,
    require_current_registry: bool = True,
) -> list[str]:
    errors: list[str] = []
    if descriptor.get("schema") != 1:
        errors.append("candidate schema must be 1")
    if descriptor.get("product") != "DCENT_OS for ESP":
        errors.append("candidate product mismatch")
    if descriptor.get("authority") != AUTHORITY:
        errors.append("candidate authority mismatch")
    if descriptor.get("disposition") != "qualification-only-not-publishable":
        errors.append("candidate disposition mismatch")
    if descriptor.get("publishable") is not False:
        errors.append("candidate must be explicitly non-publishable")
    if descriptor.get("candidate_id") != candidate_id(descriptor):
        errors.append("candidate_id does not match canonical descriptor content")

    board_target = descriptor.get("board_target")
    receipt_id = descriptor.get("receipt_id")
    try:
        target = find_target(matrix, board_target)
    except (KeyError, ValueError):
        errors.append(f"candidate board_target {board_target!r} is not registered")
        return errors
    if not isinstance(receipt_id, str) or not RECEIPT_ID_RE.fullmatch(receipt_id):
        errors.append("candidate receipt_id format is invalid")

    row = descriptor.get("registry_row")
    if not isinstance(row, dict):
        errors.append("candidate registry_row must be an object")
    else:
        for field in IMMUTABLE_HARDWARE_FIELDS:
            if row.get(field) != target.get(field):
                errors.append(f"candidate registry_row changes immutable hardware field {field}")
        for field, expected in FINAL_POLICY.items():
            if row.get(field) != expected:
                errors.append(
                    f"candidate registry_row requires {field}={expected!r}, got {row.get(field)!r}"
                )
        if row.get("promotion_receipt_id") != receipt_id:
            errors.append("candidate registry_row promotion_receipt_id mismatch")
        if target.get("runtime_mode") != "mining" or target.get("install_policy") == "blocked":
            errors.append("candidate source target is not engineering-ready for mining qualification")

    source = descriptor.get("source")
    if not isinstance(source, dict):
        errors.append("candidate source must be an object")
    else:
        commit = source.get("git_commit")
        epoch = source.get("source_date_epoch")
        digest = source.get("registry_sha256")
        version = source.get("firmware_version")
        git_dirty = source.get("git_dirty")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            errors.append("candidate source.git_commit must be 40 lowercase hex characters")
        if not isinstance(epoch, str) or not epoch.isdigit():
            errors.append("candidate source.source_date_epoch must be a decimal string")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            errors.append("candidate source.registry_sha256 must be lowercase hex")
        elif require_current_registry and digest != registry_sha256:
            errors.append("candidate source registry SHA-256 is stale")
        if not isinstance(version, str) or not version:
            errors.append("candidate source.firmware_version must be a non-empty string")
        if git_dirty is not False:
            errors.append("candidate source.git_dirty must be false")
        if git_commit is not None and commit != git_commit:
            errors.append("candidate source git commit does not match the build checkout")
        if source_date_epoch is not None and epoch != source_date_epoch:
            errors.append("SOURCE_DATE_EPOCH does not match the promotion candidate")
        if firmware_version is not None and version != firmware_version:
            errors.append("workspace firmware version does not match the promotion candidate")

    required = descriptor.get("required_gates")
    try:
        expected_gates = required_production_gates(matrix, target)
    except (KeyError, ValueError) as exc:
        errors.append(f"cannot derive candidate production gates: {exc}")
    else:
        if required != expected_gates:
            errors.append("candidate effective gate snapshot is stale")
    return errors


def load_descriptor(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateError(f"cannot read candidate descriptor {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateError("candidate descriptor root must be an object")
    return value


def require_valid_descriptor(
    descriptor: dict[str, Any],
    matrix: dict[str, Any],
    registry_sha256: str,
    git_commit: str | None = None,
    source_date_epoch: str | None = None,
    firmware_version: str | None = None,
    require_current_registry: bool = True,
) -> None:
    errors = validate_descriptor(
        descriptor,
        matrix,
        registry_sha256,
        git_commit,
        source_date_epoch,
        firmware_version,
        require_current_registry,
    )
    if errors:
        raise CandidateError("\n".join(f"- {error}" for error in errors))


def admission_errors(
    descriptor: dict[str, Any],
    matrix: dict[str, Any],
    registry_sha256: str,
    firmware_update_sha256: str,
    firmware_version: str,
) -> list[str]:
    """Require an admitted registry row and live receipt for the exact candidate payload."""
    errors = validate_descriptor(
        descriptor,
        matrix,
        registry_sha256,
        require_current_registry=False,
    )
    if not SHA256_RE.fullmatch(firmware_update_sha256):
        errors.append("admission update SHA-256 must be 64 lowercase hex characters")
        return errors

    try:
        target = find_target(matrix, descriptor.get("board_target"))
    except (KeyError, ValueError):
        return errors
    if target != descriptor.get("registry_row"):
        errors.append("admitted registry row is not byte-for-field identical to the candidate row")

    evidence_index = load_evidence_index()
    status = promotion_status(evidence_index, matrix, target, ROOT)
    if not status.get("qualified"):
        errors.append("exact-SKU hardware evidence does not qualify the admitted target")
    if status.get("receipt_id") != descriptor.get("receipt_id"):
        errors.append("admitted receipt ID does not match the promotion candidate")
    if status.get("firmware_update_sha256") != firmware_update_sha256:
        errors.append("admitted receipt does not bind the retained candidate update SHA-256")
    if status.get("firmware_version") != firmware_version:
        errors.append("admitted receipt does not bind the retained candidate firmware version")
    if (descriptor.get("source") or {}).get("firmware_version") != firmware_version:
        errors.append("candidate descriptor firmware version does not match the retained package")
    return errors


def admitted_manifest(
    qualification_manifest: dict[str, Any], hardware_evidence_index_sha256: str
) -> dict[str, Any]:
    if qualification_manifest.get("promotionState") != "qualification":
        raise CandidateError("source manifest is not a qualification package")
    if qualification_manifest.get("qualificationOnly") is not True:
        raise CandidateError("source manifest is not marked qualification-only")
    if not SHA256_RE.fullmatch(hardware_evidence_index_sha256):
        raise CandidateError("hardware evidence index SHA-256 is invalid")
    result = deepcopy(qualification_manifest)
    result["promotionState"] = "registry"
    result["promotionCandidateId"] = None
    result["promotionCandidateDescriptorSha256"] = None
    result["qualificationOnly"] = False
    result["hardwareEvidenceIndexSha256"] = hardware_evidence_index_sha256
    result["admittedAtUtc"] = utc_now()
    return result


def admit_package(
    descriptor_path: Path,
    manifest_path: Path,
    output: Path,
    public_key_hex: str,
    partitions_csv: Path | None = None,
) -> Path:
    """Create an admitted manifest around the retained, already-tested payload bytes."""
    from verify_ota_package import payload_map, resolve_payload, verify_manifest

    matrix = load_manifest()
    require_valid(matrix)
    registry_sha = sha256_file(MANIFEST_PATH)
    descriptor_path = descriptor_path.resolve()
    manifest_path = manifest_path.resolve()
    descriptor = load_descriptor(descriptor_path)
    target = find_target(matrix, descriptor.get("board_target"))
    if not public_key_hex:
        raise CandidateError("admitted package verification requires the production public key")
    partitions = partitions_csv or ROOT / (
        "partitions-16mb.csv" if target["flash_layout"] == "n16r8" else "partitions.csv"
    )
    verify_manifest(
        manifest_path,
        public_key_hex,
        True,
        partitions,
        False,
        False,
        True,
        descriptor_path,
        True,
    )
    qualification = json.loads(manifest_path.read_text(encoding="ascii"))
    payloads = payload_map(qualification)
    factory_path, _factory_data, _factory_sha = resolve_payload(
        manifest_path.parent, payloads, "factory"
    )
    update_path, _update_data, update_sha = resolve_payload(
        manifest_path.parent, payloads, "update"
    )
    errors = admission_errors(
        descriptor,
        matrix,
        registry_sha,
        update_sha,
        str(qualification.get("version") or ""),
    )
    if errors:
        raise CandidateError("\n".join(f"- {error}" for error in errors))

    output = output.resolve()
    if output.exists():
        raise CandidateError(f"refusing to overwrite admitted package directory {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dcentaxe-admit-", dir=output.parent) as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir()
        factory_target = stage / factory_path.name
        update_target = stage / update_path.name
        shutil.copy2(factory_path, factory_target)
        shutil.copy2(update_path, update_target)
        admitted = admitted_manifest(qualification, sha256_file(INDEX_PATH))
        for payload in admitted.get("payloads") or []:
            if payload.get("name") == "factory":
                payload["path"] = factory_target.name
            elif payload.get("name") == "update":
                payload["path"] = update_target.name
            elif payload.get("name") == "manifest":
                payload["path"] = manifest_path.name
        admitted_path = stage / manifest_path.name
        admitted_path.write_text(
            json.dumps(admitted, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        checksums_name = manifest_path.name.replace("-manifest.json", "-SHA256SUMS.txt")
        checksums = (
            f"{sha256_file(factory_target)}  {factory_target.name}\n"
            f"{sha256_file(update_target)}  {update_target.name}\n"
            f"{sha256_file(admitted_path)}  {admitted_path.name}\n"
        )
        (stage / checksums_name).write_text(checksums, encoding="ascii")
        verify_manifest(
            admitted_path,
            public_key_hex,
            True,
            partitions,
            False,
            True,
        )
        stage.replace(output)
    return output / manifest_path.name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="Create a reviewed qualification-only descriptor")
    create.add_argument("board_target")
    create.add_argument("receipt_id")
    create.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate", help="Validate a descriptor against this checkout")
    validate.add_argument("descriptor", type=Path)
    validate.add_argument("--for-build", action="store_true")
    lookup = sub.add_parser("lookup", help="Read one field from a validated candidate row")
    lookup.add_argument("descriptor", type=Path)
    lookup.add_argument("field")
    admit = sub.add_parser(
        "admit-check",
        help="Verify that the registry and retained exact binary now have qualifying live evidence",
    )
    admit.add_argument("descriptor", type=Path)
    admit.add_argument("--update-sha256", required=True)
    admit.add_argument("--version", required=True)
    admit_bundle = sub.add_parser(
        "admit-package",
        help="Re-manifest retained qualification payloads after exact receipt admission",
    )
    admit_bundle.add_argument("descriptor", type=Path)
    admit_bundle.add_argument("manifest", type=Path)
    admit_bundle.add_argument("--output", type=Path, required=True)
    admit_bundle.add_argument(
        "--public-key-hex",
        default=os.environ.get("DCENT_OTA_PUBLIC_KEY_HEX", ""),
    )
    admit_bundle.add_argument("--partitions-csv", type=Path)
    args = parser.parse_args(argv)

    try:
        matrix = load_manifest()
        require_valid(matrix)
        registry_sha = sha256_file(MANIFEST_PATH)
        commit = git_head()
        epoch = git_fact("%ct")
        version = workspace_version()
        if args.command == "create":
            if not candidate_source_is_clean():
                raise CandidateError(
                    "promotion candidates require a clean repository checkout"
                )
            target = find_target(matrix, args.board_target)
            descriptor = create_descriptor(
                matrix,
                target,
                args.receipt_id,
                commit,
                epoch,
                registry_sha,
                version,
            )
            if args.output.exists():
                raise CandidateError(f"refusing to overwrite existing descriptor {args.output}")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical_bytes(descriptor))
            print(
                f"Promotion candidate created (qualification only, not publishable): "
                f"{args.output.resolve()}"
            )
        elif args.command in {"validate", "lookup"}:
            descriptor = load_descriptor(args.descriptor)
            if args.for_build and not candidate_source_is_clean():
                raise CandidateError(
                    "promotion candidate builds require a clean repository checkout"
                )
            require_valid_descriptor(
                descriptor,
                matrix,
                registry_sha,
                commit if args.for_build else None,
                epoch if args.for_build else None,
                version if args.for_build else None,
            )
            if args.command == "validate":
                print(f"Promotion candidate valid: {descriptor['candidate_id']}")
            else:
                if "." in args.field:
                    value: Any = descriptor
                    for part in args.field.split("."):
                        if not isinstance(value, dict) or part not in value:
                            raise CandidateError(
                                f"candidate descriptor has no field path {args.field!r}"
                            )
                        value = value[part]
                else:
                    row = descriptor["registry_row"]
                    if args.field in row:
                        value = row[args.field]
                    elif args.field in descriptor:
                        value = descriptor[args.field]
                    else:
                        raise CandidateError(
                            f"candidate descriptor or registry row has no field {args.field!r}"
                        )
                print(json.dumps(value) if isinstance(value, (list, dict)) else value)
        elif args.command == "admit-check":
            descriptor = load_descriptor(args.descriptor)
            errors = admission_errors(
                descriptor,
                matrix,
                registry_sha,
                args.update_sha256,
                args.version,
            )
            if errors:
                raise CandidateError("\n".join(f"- {error}" for error in errors))
            print(f"Promotion candidate admitted for exact binary: {descriptor['candidate_id']}")
        else:
            manifest = admit_package(
                args.descriptor,
                args.manifest,
                args.output,
                args.public_key_hex.strip(),
                args.partitions_csv,
            )
            print(f"Admitted package created without rebuilding payloads: {manifest}")
        return 0
    except (CandidateError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
