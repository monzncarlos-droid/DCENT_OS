#!/usr/bin/env python3
"""Offline verifier for DCENT_OS-for-ESP OTA/factory package manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from hardware_evidence import production_claim_errors, sha256_file
from promotion_candidate import CandidateError, load_descriptor, require_valid_descriptor

ED25519_SPKI_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
SIGNATURE_ALGORITHM = "ed25519"
ROOT = Path(__file__).resolve().parents[1]
TARGET_MATRIX_PATH = ROOT / "esp-targets.json"
HARDWARE_EVIDENCE_INDEX_PATH = ROOT / "hardware-evidence" / "index.json"
with TARGET_MATRIX_PATH.open(encoding="utf-8") as target_matrix_handle:
    TARGET_MATRIX = json.load(target_matrix_handle)
    TARGETS_BY_BOARD = {
        target["board_target"]: target
        for target in TARGET_MATRIX["targets"]
    }
PUBLIC_TARGET_DEVICE_MODELS = {
    board_target: target["device_model"]
    for board_target, target in TARGETS_BY_BOARD.items()
    if target["package_policy"] == "public"
}


def fail(message: str) -> None:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    with path.open(encoding="ascii") as handle:
        return json.load(handle)


def parse_int(value: str) -> int:
    return int(value.strip(), 0)


def read_partition_table(path: Path) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            cols = [col.strip() for col in stripped.split(",")]
            if len(cols) >= 5:
                result[cols[0]] = (parse_int(cols[3]), parse_int(cols[4]))
    return result


def payload_map(manifest: dict) -> dict[str, dict]:
    return {
        str(entry.get("name")): entry
        for entry in manifest.get("payloads", [])
        if isinstance(entry, dict) and entry.get("name")
    }


def resolve_payload(base: Path, payloads: dict[str, dict], name: str) -> tuple[Path, bytes, str]:
    require(name in payloads, f"manifest missing {name} payload")
    rel = payloads[name].get("path")
    require(isinstance(rel, str) and rel, f"{name} payload path is required")
    path = (base / rel).resolve()
    require(
        os.path.commonpath([str(base), str(path)]) == str(base),
        f"{name} payload escapes manifest directory",
    )
    require(path.is_file(), f"{name} payload not found: {path}")
    data = path.read_bytes()
    digest = sha256_bytes(data)
    require(payloads[name].get("size") == len(data), f"{name} payload size mismatch")
    require(
        str(payloads[name].get("sha256", "")).lower() == digest,
        f"{name} payload sha256 mismatch",
    )
    return path, data, digest


def canonical_ota_message(manifest: dict, update_size: int, update_sha: str) -> bytes:
    return (
        "schema=2\n"
        f"board_target={manifest['boardTarget']}\n"
        f"device_model={str(manifest['deviceModel']).lower()}\n"
        f"version={manifest['version']}\n"
        f"size={update_size}\n"
        f"sha256={update_sha}\n"
    ).encode("ascii")


def canonical_bundle_message(
    manifest: dict, update_size: int, update_sha: str, factory_size: int, factory_sha: str
) -> bytes:
    return (
        "schema=2\n"
        f"board_target={manifest['boardTarget']}\n"
        f"device_model={str(manifest['deviceModel']).lower()}\n"
        f"version={manifest['version']}\n"
        f"update_size={update_size}\n"
        f"update_sha256={update_sha}\n"
        f"factory_size={factory_size}\n"
        f"factory_sha256={factory_sha}\n"
    ).encode("ascii")


def verify_ed25519(public_key_hex: str, message: bytes, signature_hex: str, label: str) -> None:
    require(shutil.which("openssl") is not None, f"openssl is required to verify {label} signature")
    public_key_hex = public_key_hex.strip().lower()
    signature_hex = signature_hex.strip().lower()
    require(len(public_key_hex) == 64, "public key must be 64 hex characters")
    require(len(signature_hex) == 128, f"{label} signature must be 128 hex characters")
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        fail(f"{label} signature/public key is not valid hex: {exc}")

    with tempfile.TemporaryDirectory(prefix="dcent-ota-verify-") as tmp:
        tmp_path = Path(tmp)
        pub_path = tmp_path / "ed25519-public.der"
        msg_path = tmp_path / "message.bin"
        sig_path = tmp_path / "signature.bin"
        pub_path.write_bytes(ED25519_SPKI_DER_PREFIX + public_key)
        msg_path.write_bytes(message)
        sig_path.write_bytes(signature)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(pub_path),
                "-sigfile",
                str(sig_path),
                "-in",
                str(msg_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    require(result.returncode == 0, f"{label} signature verification failed: {result.stderr.strip()}")


def verify_factory_flash_map(
    manifest: dict,
    factory_data: bytes,
    update_data: bytes,
    update_sha: str,
    partitions: dict[str, tuple[int, int]] | None,
) -> None:
    flash_map = manifest.get("factoryFlashMap")
    require(isinstance(flash_map, list) and flash_map, "manifest missing factoryFlashMap")
    entries = {str(entry.get("name")): entry for entry in flash_map if isinstance(entry, dict)}
    ota = manifest.get("ota") or {}
    app_partition = str(ota.get("appPartition") or "ota_0")
    update_offset = 0x20000
    update_slot_size = ota.get("slotSize")
    otadata_offset = 0xF000
    if partitions:
        require(app_partition in partitions, f"{app_partition} partition not found in partitions.csv")
        update_offset, partition_slot_size = partitions[app_partition]
        require(update_slot_size == partition_slot_size, "manifest OTA slot size differs from partitions.csv")
        require("otadata" in partitions, "otadata partition not found in partitions.csv")
        otadata_offset, _ = partitions["otadata"]
    expected_offsets = {
        "bootloader": 0x0,
        "partition-table": 0x8000,
        "ota-data-initial": otadata_offset,
        "update": update_offset,
    }
    for name, expected_offset in expected_offsets.items():
        require(name in entries, f"factoryFlashMap missing {name}")
        entry = entries[name]
        require(entry.get("offset") == expected_offset, f"{name} flash offset mismatch")
        size = entry.get("size")
        digest = str(entry.get("sha256", "")).lower()
        require(isinstance(size, int) and size > 0, f"{name} flash size must be positive")
        require(len(digest) == 64, f"{name} flash sha256 must be 64 hex characters")
        start = expected_offset
        end = start + size
        require(end <= len(factory_data), f"{name} flash slice exceeds factory image")
        slice_data = factory_data[start:end]
        require(sha256_bytes(slice_data) == digest, f"{name} factory slice sha256 mismatch")
        if name == "update":
            require(size == len(update_data), "update flash-map size does not match update payload")
            require(digest == update_sha, "update flash-map sha256 does not match update payload")
            require(slice_data == update_data, f"update payload bytes do not match factory image at 0x{update_offset:x}")


def verify_public_target_binding(
    manifest: dict,
    allow_internal_targets: bool,
    candidate_descriptor: dict | None = None,
    candidate_descriptor_path: Path | None = None,
) -> None:
    board_target = str(manifest.get("boardTarget") or "").strip()
    device_model = str(manifest.get("deviceModel") or "").strip().lower()
    require(board_target, "manifest boardTarget is required")
    require(device_model, "manifest deviceModel is required")

    registered_target = TARGETS_BY_BOARD.get(board_target)
    require(
        registered_target is not None,
        f"manifest boardTarget {board_target!r} is not in esp-targets.json",
    )
    if candidate_descriptor is not None:
        require(candidate_descriptor_path is not None, "candidate descriptor path is required")
        require(
            candidate_descriptor.get("board_target") == board_target,
            "promotion candidate board target does not match the package",
        )
        target = candidate_descriptor["registry_row"]
        require(manifest.get("promotionState") == "qualification", "candidate package must use promotionState=qualification")
        require(manifest.get("qualificationOnly") is True, "candidate package must be qualification-only")
        require(
            manifest.get("promotionCandidateId") == candidate_descriptor.get("candidate_id"),
            "manifest promotionCandidateId does not match the descriptor",
        )
        require(
            manifest.get("promotionCandidateDescriptorSha256")
            == sha256_file(candidate_descriptor_path),
            "manifest promotion candidate descriptor SHA-256 mismatch",
        )
        require(
            manifest.get("version")
            == (candidate_descriptor.get("source") or {}).get("firmware_version"),
            "candidate package version does not match the descriptor",
        )
    else:
        target = registered_target
        require(manifest.get("promotionState") == "registry", "registry package must use promotionState=registry")
        require(manifest.get("qualificationOnly") is False, "registry package cannot be qualification-only")
        require(manifest.get("promotionCandidateId") is None, "registry package cannot name a promotion candidate")
        require(
            manifest.get("promotionCandidateDescriptorSha256") is None,
            "registry package cannot bind a promotion candidate descriptor",
        )

    if candidate_descriptor is None and target["package_policy"] != "public":
        require(
            allow_internal_targets,
            (
                f"manifest boardTarget {board_target!r} is not a public "
                "DCENT_OS-for-ESP install target; pass --allow-internal-target "
                "only for lab/internal packages"
            ),
        )
    expected_model = target["device_model"]
    require(
        device_model == expected_model,
        (
            f"manifest deviceModel {device_model!r} does not match boardTarget "
            f"{board_target!r} (expected {expected_model!r})"
        ),
    )
    metadata_bindings = {
        "hardwareFamily": "hardware_family",
        "supportTier": "support_tier",
        "evidenceLevel": "evidence_level",
        "runtimeMode": "runtime_mode",
        "installPolicy": "install_policy",
        "packagePolicy": "package_policy",
        "flashLayout": "flash_layout",
        "productionBlockers": "blockers",
    }
    for manifest_field, target_field in metadata_bindings.items():
        require(
            manifest.get(manifest_field) == target[target_field],
            (
                f"manifest {manifest_field} does not match esp-targets.json for "
                f"{board_target!r}"
            ),
        )

    require(
        manifest.get("promotionReceiptId") == target.get("promotion_receipt_id"),
        f"manifest promotionReceiptId does not match the authoritative row for {board_target!r}",
    )
    if candidate_descriptor is None:
        evidence_index_bytes = HARDWARE_EVIDENCE_INDEX_PATH.read_bytes()
        evidence_index = json.loads(evidence_index_bytes.decode("utf-8"))
        authority_errors = production_claim_errors(TARGET_MATRIX, evidence_index, ROOT)
        require(
            not authority_errors,
            "hardware evidence authority is invalid: " + "; ".join(authority_errors),
        )
        require(
            manifest.get("hardwareEvidenceIndexSha256")
            == hashlib.sha256(evidence_index_bytes).hexdigest(),
            "manifest hardwareEvidenceIndexSha256 does not match retained evidence index",
        )
    else:
        evidence_sha = str(manifest.get("hardwareEvidenceIndexSha256") or "")
        require(
            len(evidence_sha) == 64 and all(char in "0123456789abcdef" for char in evidence_sha),
            "candidate manifest hardwareEvidenceIndexSha256 must be lowercase hex",
        )


def verify_signature_metadata(
    manifest: dict,
    public_key_hex: str | None,
    require_signatures: bool,
    ota_signature: str,
    bundle_signature: str,
) -> None:
    if require_signatures:
        require(ota_signature, "manifest missing otaSignature")
        require(bundle_signature, "manifest missing bundle signature")
        require(public_key_hex, "--require-signatures requires --public-key-hex")

    if require_signatures or ota_signature:
        require(
            manifest.get("otaSignatureAlgorithm") == SIGNATURE_ALGORITHM,
            f"manifest otaSignatureAlgorithm must be {SIGNATURE_ALGORITHM}",
        )
        require(manifest.get("otaKeyId"), "signed OTA manifest missing otaKeyId")

    if require_signatures or bundle_signature:
        require(
            manifest.get("signatureAlgorithm") == SIGNATURE_ALGORITHM,
            f"manifest signatureAlgorithm must be {SIGNATURE_ALGORITHM}",
        )
        require(manifest.get("keyId"), "signed bundle manifest missing keyId")


def warn_unsigned_public_target(
    manifest: dict,
    manifest_name: str,
    public_key_hex: str | None,
    require_signatures: bool,
    ota_signature: str,
    strict_public: bool,
) -> None:
    """Loudly flag a PUBLIC-target package that carries no Ed25519 signature.

    A public DCENT_OS-for-ESP install target (one of the six in
    PUBLIC_TARGET_DEVICE_MODELS) must ship signed for release. The CI PR path
    deliberately verifies unsigned packages WITHOUT --require-signatures /
    --public-key-hex (PRs cannot reach the signing secret), so this stays a
    warning by default and does NOT change the exit code — it must not break the
    existing unsigned-PR verifier path. `--strict-public` (default OFF, opt-in
    for the release workflow) escalates the same condition to a hard failure.
    """
    board_target = str(manifest.get("boardTarget") or "").strip()
    is_public_target = board_target in PUBLIC_TARGET_DEVICE_MODELS
    has_signature = bool(ota_signature)
    operator_asked_for_verification = bool(public_key_hex) or require_signatures
    if is_public_target and not has_signature and not operator_asked_for_verification:
        print(
            f"WARNING: public-target package {manifest_name!r} has NO Ed25519 "
            "signature and was verified UNSIGNED — not acceptable for release",
            file=sys.stderr,
        )
        if strict_public:
            fail(
                f"--strict-public: refusing to pass unsigned public-target "
                f"package {manifest_name!r} (no Ed25519 otaSignature present)"
            )


def verify_manifest(
    manifest_path: Path,
    public_key_hex: str | None,
    require_signatures: bool,
    partitions_csv: Path | None,
    allow_internal_targets: bool = False,
    strict_public: bool = False,
    allow_qualification_candidate: bool = False,
    candidate_path: Path | None = None,
    candidate_admission_mode: bool = False,
) -> None:
    manifest_path = manifest_path.resolve()
    base = manifest_path.parent.resolve()
    manifest = read_json(manifest_path)

    require(manifest.get("schema") == 1, "manifest schema must be 1")
    require(manifest.get("product") == "DCENT_axe", "manifest product mismatch")
    require(manifest.get("family") == "bitaxe", "manifest family mismatch")
    require(
        manifest.get("packageType") == "esp32-factory-and-ota-bundle",
        "manifest packageType mismatch",
    )
    qualification = manifest.get("promotionState") == "qualification"
    if qualification:
        require(
            allow_qualification_candidate,
            "qualification candidate packages are non-publishable; pass --allow-qualification-candidate",
        )
        require(candidate_path is not None, "qualification candidate verification requires --candidate")
        candidate_path = candidate_path.resolve()
        try:
            candidate_descriptor = load_descriptor(candidate_path)
            require_valid_descriptor(
                candidate_descriptor,
                TARGET_MATRIX,
                sha256_file(TARGET_MATRIX_PATH),
                require_current_registry=not candidate_admission_mode,
            )
        except CandidateError as exc:
            fail(f"invalid promotion candidate descriptor: {exc}")
        if candidate_admission_mode:
            require(
                TARGETS_BY_BOARD.get(candidate_descriptor["board_target"])
                == candidate_descriptor.get("registry_row"),
                "admission-mode registry row is not identical to the promotion candidate",
            )
    else:
        require(not allow_qualification_candidate, "--allow-qualification-candidate requires a qualification package")
        require(candidate_path is None, "--candidate is only valid for a qualification package")
        candidate_descriptor = None
    verify_public_target_binding(
        manifest,
        allow_internal_targets,
        candidate_descriptor,
        candidate_path,
    )
    require(manifest.get("version"), "manifest version is required")
    require(
        (manifest.get("ota") or {}).get("updateFitsSlot") is True,
        "manifest says OTA update does not fit slot",
    )

    payloads = payload_map(manifest)
    _factory_path, factory_data, factory_sha = resolve_payload(base, payloads, "factory")
    _update_path, update_data, update_sha = resolve_payload(base, payloads, "update")
    require(str(manifest.get("factorySha256", "")).lower() == factory_sha, "manifest factorySha256 mismatch")
    slot_size = (manifest.get("ota") or {}).get("slotSize")
    if slot_size is not None:
        require(len(update_data) <= int(slot_size), "update payload exceeds manifest OTA slot size")

    partitions = read_partition_table(partitions_csv.resolve()) if partitions_csv and partitions_csv.is_file() else None
    if partitions is not None:
        expected_slot_size = 0x400000 if manifest["flashLayout"] == "n16r8" else 0x300000
        require("ota_0" in partitions, "partition table is missing ota_0")
        require(
            partitions["ota_0"][1] == expected_slot_size,
            f"partition table does not match registered {manifest['flashLayout']} flash layout",
        )
        require(
            int((manifest.get("ota") or {}).get("slotSize") or 0) == expected_slot_size,
            "manifest OTA slot size does not match registered flash layout",
        )
    verify_factory_flash_map(manifest, factory_data, update_data, update_sha, partitions)

    ota_signature = str(manifest.get("otaSignature") or "")
    bundle_signature = str(manifest.get("signature") or "")
    effective_require_signatures = require_signatures or qualification
    verify_signature_metadata(
        manifest,
        public_key_hex,
        effective_require_signatures,
        ota_signature,
        bundle_signature,
    )
    if not qualification:
        warn_unsigned_public_target(
            manifest,
            manifest_path.name,
            public_key_hex,
            require_signatures,
            ota_signature,
            strict_public,
        )
    if public_key_hex and ota_signature:
        verify_ed25519(
            public_key_hex,
            canonical_ota_message(manifest, len(update_data), update_sha),
            ota_signature,
            "OTA",
        )
    if public_key_hex and bundle_signature:
        verify_ed25519(
            public_key_hex,
            canonical_bundle_message(manifest, len(update_data), update_sha, len(factory_data), factory_sha),
            bundle_signature,
            "bundle",
        )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", help="Path to the *-manifest.json file")
    parser.add_argument("--manifest", dest="manifest_option", help="Path to the *-manifest.json file")
    parser.add_argument("--public-key-hex", default=os.environ.get("DCENT_OTA_PUBLIC_KEY_HEX", ""))
    parser.add_argument(
        "--partitions-csv",
        default=os.environ.get("DCENT_PARTITIONS_CSV", str(Path(__file__).resolve().parents[1] / "partitions.csv")),
        help="Partition table used to verify factory flash-map offsets and OTA slot size",
    )
    parser.add_argument(
        "--allow-qualification-candidate",
        action="store_true",
        help="Explicitly verify a signed, non-publishable qualification package",
    )
    parser.add_argument(
        "--candidate",
        type=Path,
        help="Promotion candidate descriptor required with --allow-qualification-candidate",
    )
    parser.add_argument(
        "--require-signatures",
        action="store_true",
        default=os.environ.get("DCENT_OTA_REQUIRE_SIGNATURES", "") not in ("", "0", "false", "False"),
        help="Require both OTA and bundle signatures",
    )
    parser.add_argument(
        "--allow-internal-target",
        action="store_true",
        default=os.environ.get("DCENT_OTA_ALLOW_INTERNAL_TARGETS", "") not in ("", "0", "false", "False"),
        help="Allow non-public lab/internal boardTarget values",
    )
    parser.add_argument(
        "--strict-public",
        action="store_true",
        default=os.environ.get("DCENT_OTA_STRICT_PUBLIC", "") not in ("", "0", "false", "False"),
        help=(
            "Escalate the unsigned-public-target WARNING to a hard non-zero "
            "exit (default OFF). Lets the release workflow refuse an unsigned "
            "public package without affecting the existing unsigned-PR path."
        ),
    )
    args = parser.parse_args(argv)
    manifest = args.manifest_option or args.manifest
    require(bool(manifest), "manifest path is required")
    verify_manifest(
        Path(manifest),
        args.public_key_hex.strip() or None,
        args.require_signatures,
        Path(args.partitions_csv) if args.partitions_csv else None,
        args.allow_internal_target,
        args.strict_public,
        args.allow_qualification_candidate,
        args.candidate,
    )
    print(f"OTA package verification passed: {Path(manifest).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
