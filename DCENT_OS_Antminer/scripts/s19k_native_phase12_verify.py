#!/usr/bin/env python3
"""Verify an attended S19k native cold-start no-work/SafeOff capture.

The verifier only reads copied host evidence.  It never contacts a miner and
does not grant authority to energize hardware.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from pathlib import PurePosixPath
import re
import sys
from typing import Any

import s19k_native_live_common as common
import s19k_native_build_verify as native_build


SCHEMA = "dcentos.s19k-native-phase12-capture/v1"
RESULT_SCHEMA = "dcentos.s19k-native-phase12-verification/v1"
PHASE = "native-phase12"
OWNER_SCHEMA = "dcentos.s19k-native-owner-implementation/v7"
NATIVE_BUILD_SCHEMA = native_build.SCHEMA
NATIVE_BUILD_CLAIM = native_build.CLAIM
NATIVE_BUILD_COMMAND = native_build.CARGO_COMMAND
HARDWARE_SCHEMA = "dcentos.s19k-native-hardware-verification/v1"
HARDWARE_CLAIM = "reviewed-common-clock-native-hardware-contract"
OWNER_PREREQUISITES = {
    "native-secure-firmware-re",
    "native-hardware-contract",
    "adopted-endurance",
    "native-build-reproducibility",
}
OWNER_SOURCE_PATHS = native_build.SEMANTIC_SOURCE_PATHS
OWNER_COMPILE_CONTRACT = native_build.AARCH64_COMPILE_CONTRACT
LOCAL_PACKAGE_MANIFESTS = native_build.LOCAL_PACKAGE_MANIFESTS
CAPSULE_KEYS = {
    "binary", "build_inputs", "build_environment", "build_variant", "builder",
    "cargo_metadata", "claim", "compile_environment", "git", "profile",
    "release_capsule", "schema_version", "source_inventory",
    "source_inventory_sha256", "target_triple", "toolchain_context",
}
OWNER_CAPABILITIES = {
    "identity",
    "cooling",
    "gpio437",
    "resets",
    "watchdog",
    "population_uart_admission",
    "rollback",
    "terminal_safe_off",
}
FILES = (
    "owner-verification.json",
    "hardware-verification.json",
    "events.csv",
    "safety.csv",
    "uart.csv",
)
EXTRA_KEYS = (
    "target_identity_sha256",
    "artifact_sha256",
    "owner_verification_sha256",
    "hardware_verification_sha256",
    "rail_off_max",
    "rail_on_min",
    "dangerous_temp_millic",
)
EVENT_HEADER = ("sequence", "monotonic_ms", "event", "path", "value")
SAFETY_HEADER = (
    "monotonic_ms",
    "event",
    "rail_value",
    "gpio437_raw",
    "gpio454_raw",
    "gpio455_raw",
    "gpio456_raw",
    "fan0_rpm",
    "fan1_rpm",
    "fan2_rpm",
    "fan3_rpm",
    "temp0_millic",
    "temp1_millic",
    "temp2_millic",
    "temp3_millic",
)


def _verified_owner_receipt(
    owner: dict[str, Any], *, artifact_sha256: str, hardware_id: str
) -> None:
    common.verify_receipt_id(owner, "native owner verification")
    if (
        owner.get("schema") != OWNER_SCHEMA
        or owner.get("phase_id") != "native-cold-start-owner"
        or owner.get("classification") != "verified"
        or owner.get("source_readiness_classification") != "ready"
        or owner.get("production_owner_present") is not True
        or owner.get("dependency_evidence_bound") is not True
        or owner.get("host_only_source_audit") is not True
        or owner.get("live_hardware_contacted") is not False
        or owner.get("authority_minted") is not False
    ):
        common.fail("native live evidence lacks the exact verified production-owner receipt")
    prerequisites = owner.get("prerequisite_verification_ids")
    if not isinstance(prerequisites, dict) or set(prerequisites) != OWNER_PREREQUISITES:
        common.fail("native owner receipt does not bind the exact prerequisite set")
    for phase_id, verification_id in prerequisites.items():
        common.digest(verification_id, f"native owner prerequisite {phase_id}")
    if prerequisites["native-hardware-contract"] != hardware_id:
        common.fail("native owner receipt does not bind the embedded hardware receipt")
    artifact = owner.get("native_owner_artifact")
    if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "bytes"}:
        common.fail("native owner receipt lacks the exact artifact identity")
    if (
        artifact.get("path") != "usr/local/bin/dcentrald"
        or common.digest(artifact.get("sha256"), "native owner artifact")
        != artifact_sha256
        or common.canonical_uint(
            artifact.get("bytes"), "native owner artifact bytes", positive=True
        )
        > 64 * 1024 * 1024
    ):
        common.fail("native owner receipt targets a different or invalid artifact")
    source_files = owner.get("source_files")
    if not isinstance(source_files, list) or len(source_files) != len(OWNER_SOURCE_PATHS):
        common.fail("native owner receipt lacks the exact source identities")
    for expected_path, identity in zip(OWNER_SOURCE_PATHS, source_files):
        if not isinstance(identity, dict) or set(identity) != {"path", "sha256", "bytes"}:
            common.fail("native owner source identity is malformed")
        if identity.get("path") != expected_path:
            common.fail("native owner source identity order/path is not exact")
        common.digest(identity.get("sha256"), f"native owner source {expected_path}")
        common.canonical_uint(
            identity.get("bytes"), f"native owner source bytes {expected_path}", positive=True
        )
    if owner.get("aarch64_compile_contract") != OWNER_COMPILE_CONTRACT:
        common.fail("native owner receipt lacks the exact AArch64 compile contract")
    build_receipt = owner.get("native_build_receipt")
    if not isinstance(build_receipt, dict):
        common.fail("native owner receipt lacks the native build receipt")
    if set(build_receipt) != native_build.RECEIPT_KEYS:
        common.fail("native build receipt key set is not exact")
    build_id = common.verify_receipt_id(build_receipt, "native build receipt")
    build_artifact = build_receipt.get("artifact")
    capsule = build_receipt.get("capsule_build_receipt")
    if not isinstance(capsule, dict) or set(capsule) != CAPSULE_KEYS:
        common.fail("native build receipt lacks the exact capsule build receipt")
    if build_receipt.get("capsule_build_receipt_sha256") != common.sha256(
        common.canonical_json(capsule)
    ):
        common.fail("native build receipt does not bind exact capsule bytes")
    capsule_git = capsule.get("git")
    if (
        not isinstance(capsule_git, dict)
        or set(capsule_git) != {"commit", "source_kind"}
        or capsule_git.get("source_kind") != "exact-git-object-snapshot"
    ):
        common.fail("native build receipt lacks exact Git-snapshot provenance")
    source_commit = capsule_git.get("commit")
    if (
        not isinstance(source_commit, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_commit) is None
    ):
        common.fail("native build receipt has an invalid Git snapshot identity")
    lineage = capsule.get("release_capsule")
    if not isinstance(lineage, dict) or set(lineage) != {
        "schema",
        "release_invocation_descriptor_sha256",
        "release_invocation_id",
        "source_snapshot_descriptor_sha256",
        "source_snapshot_id",
    } or lineage.get("schema") != "org.dcentral.dcentos.release-capsule-lineage.v2":
        common.fail("native build receipt lacks exact capsule lineage")
    for field in (
        "release_invocation_descriptor_sha256",
        "release_invocation_id",
        "source_snapshot_descriptor_sha256",
        "source_snapshot_id",
    ):
        common.digest(lineage.get(field), f"capsule lineage {field}")
    cargo_metadata = capsule.get("cargo_metadata")
    if not isinstance(cargo_metadata, dict) or set(cargo_metadata) != {
        "path", "sha256", "size"
    }:
        common.fail("native build receipt lacks exact Cargo metadata identity")
    cargo_metadata_sha256 = common.digest(
        cargo_metadata.get("sha256"), "capsule Cargo metadata"
    )
    common.canonical_uint(
        cargo_metadata.get("size"), "capsule Cargo metadata bytes", positive=True
    )
    builder = capsule.get("builder")
    if (
        not isinstance(builder, dict)
        or set(builder) != {"kind", "base_reference", "image_id", "package_resolution"}
        or builder.get("kind") != "docker-cross"
        or re.fullmatch(
            r"(?:[^/@]+/)*[^/@]+@sha256:[0-9a-f]{64}",
            str(builder.get("base_reference", "")),
        ) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(builder.get("image_id", "")))
        is None
        or builder.get("package_resolution") != native_build.BUILDER_PACKAGE_RESOLUTION
    ):
        common.fail("native build receipt lacks an immutable pinned builder")
    closure = build_receipt.get("local_dependency_closure")
    if not isinstance(closure, dict) or set(closure) != {
        "cargo_metadata_sha256", "target_triple", "root_package_id", "packages",
        "external_local_paths_inside_snapshot",
    }:
        common.fail("native build receipt lacks the exact local dependency closure")
    packages = closure.get("packages")
    if not isinstance(packages, list) or len(packages) != len(LOCAL_PACKAGE_MANIFESTS):
        common.fail("native build receipt lacks the 16-package local dependency closure")
    observed_manifests: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict) or set(package) != {
            "name", "version", "manifest_path", "package_root"
        }:
            common.fail("native build receipt has a malformed local dependency")
        name = package.get("name")
        manifest_path = package.get("manifest_path")
        if not isinstance(name, str) or not isinstance(manifest_path, str):
            common.fail("native build receipt has an invalid local dependency identity")
        if package.get("package_root") != str(PurePosixPath(manifest_path).parent):
            common.fail("native build receipt has a stale local dependency root")
        observed_manifests[name] = manifest_path
    if (
        observed_manifests != LOCAL_PACKAGE_MANIFESTS
        or closure.get("cargo_metadata_sha256") != cargo_metadata_sha256
        or closure.get("target_triple") != native_build.TARGET
        or closure.get("external_local_paths_inside_snapshot") is not True
        or not str(closure.get("root_package_id", "")).startswith("dcentrald ")
    ):
        common.fail("native build receipt local dependency closure is not exact")
    if (
        build_receipt.get("schema") != NATIVE_BUILD_SCHEMA
        or build_receipt.get("claim") != NATIVE_BUILD_CLAIM
        or build_receipt.get("classification")
        != "exact-snapshot-capsule-linked-manifest-key-pinned-candidate"
        or build_receipt.get("target_triple") != native_build.TARGET
        or build_receipt.get("cargo_profile") != "release"
        or build_receipt.get("cargo_command") != NATIVE_BUILD_COMMAND
        or build_artifact
        != {"path": "dcentrald", "sha256": artifact_sha256, "bytes": artifact["bytes"]}
        or build_receipt.get("semantic_source_files") != source_files
        or build_receipt.get("semantic_source_files_sha256")
        != common.sha256(common.canonical_json(source_files))
        or build_receipt.get("aarch64_compile_contract") != OWNER_COMPILE_CONTRACT
        or build_receipt.get("compile_contract_sha256")
        != common.sha256(common.canonical_json(OWNER_COMPILE_CONTRACT))
        or capsule.get("schema_version") != 4
        or capsule.get("claim") != native_build.CAPSULE_RECEIPT_CLAIM
        or capsule.get("target_triple") != native_build.TARGET
        or capsule.get("profile") != native_build.PROFILE
        or capsule.get("build_variant") != native_build.BUILD_VARIANT
        or build_receipt.get("network_nonuse_proven") is not False
        or build_receipt.get("network_contract") != native_build.NETWORK_CONTRACT
        or build_receipt.get("release_authority_granted") is not False
        or build_receipt.get("installation_authority_granted") is not False
        or build_receipt.get("live_hardware_contacted") is not False
    ):
        common.fail("native build receipt does not bind the exact snapshot-capsule candidate")
    manifest_public_key_hex = common.digest(
        build_receipt.get("manifest_public_key_hex"),
        "native build manifest public key",
    )
    if build_receipt.get("manifest_public_key_sha256") != common.sha256(
        bytes.fromhex(manifest_public_key_hex)
    ):
        common.fail("native build manifest public-key hash is stale")
    if capsule.get("build_environment") != {
        "DCENT_MANIFEST_KEY_ID": "",
        "DCENT_MANIFEST_PUBLIC_KEY_HEX": manifest_public_key_hex,
    }:
        common.fail("native build capsule manifest key is not exact")
    compile_environment = capsule.get("compile_environment")
    if (
        not isinstance(compile_environment, dict)
        or not isinstance(compile_environment.get("entries"), dict)
        or compile_environment["entries"].get("DCENT_MANIFEST_KEY_ID") != ""
        or compile_environment["entries"].get("DCENT_MANIFEST_PUBLIC_KEY_HEX")
        != manifest_public_key_hex
    ):
        common.fail("native build compile manifest key differs from capsule key")
    build_binding = owner.get("native_owner_build_binding")
    observed_build_ids = (
        build_binding.get("observed_native_build_verification_ids")
        if isinstance(build_binding, dict)
        else None
    )
    observed_invocation_ids = (
        build_binding.get("observed_release_invocation_ids")
        if isinstance(build_binding, dict)
        else None
    )
    if (
        not isinstance(observed_build_ids, list)
        or len(observed_build_ids) != 2
        or len(set(observed_build_ids)) != 2
        or build_id not in observed_build_ids
        or not isinstance(observed_invocation_ids, list)
        or len(observed_invocation_ids) != 2
        or len(set(observed_invocation_ids)) != 2
        or lineage["release_invocation_id"] not in observed_invocation_ids
    ):
        common.fail("native owner receipt lacks two exact build observations")
    for value in observed_build_ids + observed_invocation_ids:
        common.digest(value, "native owner reproducibility observation")
    expected_build_binding = {
        "target_triple": "aarch64-unknown-linux-musl",
        "cargo_profile": "release",
        "artifact_role": "native-cold-start-owner",
        "source_files_sha256": common.sha256(common.canonical_json(source_files)),
        "compile_contract_sha256": common.sha256(
            common.canonical_json(OWNER_COMPILE_CONTRACT)
        ),
        "adopted_artifact_reused": False,
        "native_build_verification_id": build_id,
        "capsule_build_receipt_sha256": build_receipt[
            "capsule_build_receipt_sha256"
        ],
        "source_commit": source_commit,
        "source_snapshot_id": lineage["source_snapshot_id"],
        "release_invocation_id": lineage["release_invocation_id"],
        "cargo_metadata_sha256": cargo_metadata_sha256,
        "manifest_public_key_hex": manifest_public_key_hex,
        "manifest_public_key_sha256": build_receipt[
            "manifest_public_key_sha256"
        ],
        "native_reproducibility_verification_id": prerequisites[
            "native-build-reproducibility"
        ],
        "observed_native_build_verification_ids": observed_build_ids,
        "observed_release_invocation_ids": observed_invocation_ids,
    }
    if build_binding != expected_build_binding:
        common.fail("native owner receipt lacks the exact source/artifact build binding")
    capabilities = owner.get("capability_inventory")
    if not isinstance(capabilities, dict) or set(capabilities) != OWNER_CAPABILITIES:
        common.fail("native owner receipt lacks the exact joined capability inventory")
    if any(
        not isinstance(capability, dict)
        or capability.get("status") != "joined"
        or not isinstance(capability.get("evidence"), list)
        or not capability["evidence"]
        for capability in capabilities.values()
    ):
        common.fail("native owner receipt contains an unjoined capability")


def _verified_hardware_receipt(hardware: dict[str, Any], *, target: str) -> str:
    hardware_id = common.verify_receipt_id(hardware, "native hardware verification")
    if (
        hardware.get("schema") != HARDWARE_SCHEMA
        or hardware.get("claim") != HARDWARE_CLAIM
        or hardware.get("authority_granted") is not False
        or hardware.get("live_identity_sha256") != target
        or hardware.get("tty_to_physical_address")
        != {"/dev/ttyS1": 3, "/dev/ttyS2": 2}
        or hardware.get("reset_gpio_to_tty")
        != {"455": "/dev/ttyS2", "456": "/dev/ttyS1"}
        or hardware.get("absent_physical_address") != 1
        or hardware.get("absent_reset_gpio") != 454
        or hardware.get("unpopulated_uart") != "/dev/ttyS3"
        or hardware.get("gpio437_raw_energized") != 0
        or hardware.get("gpio437_raw_safeoff") != 1
    ):
        common.fail("native live evidence lacks the exact verified hardware contract")
    return hardware_id


def _events(path: Path) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, EVENT_HEADER, "native owner event capture")
    expected_global = {
        ("safeoff-initial", "checked"),
        ("cooling-ready", "four-channels"),
        ("rail-enabled", "gpio437-raw0"),
        ("owner-admitted", "opaque-production-owner"),
        ("no-work-window-complete", "zero-work"),
        ("safeoff-begin", "checked"),
        ("reset-asserted", "all"),
        ("rail-disabled", "gpio437-raw1"),
        ("owner-terminal", "checked"),
    }
    seen_global: set[tuple[str, str]] = set()
    enumerated: dict[str, int] = {}
    released: set[str] = set()
    timestamps: dict[str, int] = {}
    previous_time = -1
    for index, row in enumerate(rows):
        if common.csv_uint(row[0], f"event row {index + 2} sequence") != index:
            common.fail("native owner events are not a contiguous zero-based sequence")
        timestamp = common.csv_uint(row[1], f"event row {index + 2} timestamp")
        if timestamp <= previous_time:
            common.fail("native owner event timestamps are not strictly increasing")
        previous_time = timestamp
        event, path, value = row[2:]
        if path == "global":
            pair = (event, value)
            if pair not in expected_global or pair in seen_global:
                common.fail("native owner events contain an unexpected/repeated global event")
            seen_global.add(pair)
            timestamps[event] = timestamp
        elif path in common.UART_PATHS and event == "reset-released" and value == "mapped":
            if path in released:
                common.fail("native owner events repeat a reset release")
            released.add(path)
        elif path in common.UART_PATHS and event == "enumeration-complete":
            if path in enumerated:
                common.fail("native owner events repeat a chain enumeration")
            enumerated[path] = common.csv_uint(value, "native enumerated ASIC count", positive=True)
        else:
            common.fail("native owner events contain an inadmissible event")
    if seen_global != expected_global:
        common.fail("native owner event capture is incomplete")
    if released != set(common.UART_PATHS) or enumerated != {path: 77 for path in common.UART_PATHS}:
        common.fail("native owner did not prove mapped reset plus exact 77/77 enumeration")
    ordered = (
        "safeoff-initial",
        "cooling-ready",
        "rail-enabled",
        "owner-admitted",
        "no-work-window-complete",
        "safeoff-begin",
        "reset-asserted",
        "rail-disabled",
        "owner-terminal",
    )
    if [timestamps[name] for name in ordered] != sorted(timestamps[name] for name in ordered):
        common.fail("native owner global events violate the safety order")
    return data, {
        "native_event_count": len(rows),
        "enumerated_asics": enumerated,
        "owner_admitted_ms": timestamps["owner-admitted"],
        "owner_terminal_ms": timestamps["owner-terminal"],
    }


def _safety(
    path: Path, *, rail_off_max: int, rail_on_min: int, dangerous: int
) -> tuple[bytes, dict[str, Any]]:
    data, rows = common.csv_rows(path, SAFETY_HEADER, "native independent safety capture")
    parsed: list[tuple[int, str, int, tuple[int, int, int, int], tuple[int, ...], tuple[int, ...]]] = []
    for number, row in enumerate(rows, 2):
        timestamp = common.csv_uint(row[0], f"safety row {number} timestamp")
        if row[1] not in ("sample", "cold-baseline", "owner-start", "admission", "safeoff", "terminal"):
            common.fail(f"safety row {number} has an invalid event")
        rail = common.csv_uint(row[2], f"safety row {number} rail")
        gpios = tuple(common.csv_uint(value, f"safety row {number} GPIO") for value in row[3:7])
        if any(value not in (0, 1) for value in gpios):
            common.fail(f"safety row {number} has a non-binary GPIO")
        fans = tuple(common.csv_uint(value, f"safety row {number} fan RPM") for value in row[7:11])
        temps = tuple(common.csv_int(value, f"safety row {number} temperature") for value in row[11:15])
        if any(not -40_000 <= value < dangerous for value in temps):
            common.fail("native capture contains unsafe or implausible temperature evidence")
        parsed.append((timestamp, row[1], rail, gpios, fans, temps))
    if any(right[0] <= left[0] or right[0] - left[0] > 1_000 for left, right in zip(parsed, parsed[1:])):
        common.fail("native safety samples are not strictly increasing at <=1 second gaps")
    baselines = [row for row in parsed if row[1] == "cold-baseline"]
    if len(baselines) < 3 or baselines[-1][0] - baselines[0][0] < 2_000:
        common.fail("native capture lacks a two-second cold SafeOff baseline")
    if any(row[2] > rail_off_max or row[3] != (1, 0, 0, 0) for row in baselines):
        common.fail("native cold baseline is not rail-off/reset-asserted")
    owner = [row for row in parsed if row[1] == "owner-start"]
    admission = [row for row in parsed if row[1] == "admission"]
    safeoff = [row for row in parsed if row[1] == "safeoff"]
    terminal = [row for row in parsed if row[1] == "terminal"]
    if not (len(owner) == len(admission) == len(safeoff) == len(terminal) == 1):
        common.fail("native capture requires one owner-start/admission/SafeOff/terminal marker")
    owner_row, admission_row, safeoff_row, terminal_row = owner[0], admission[0], safeoff[0], terminal[0]
    if not owner_row[0] < admission_row[0] < safeoff_row[0] < terminal_row[0]:
        common.fail("native safety event order is invalid")
    energized = [row for row in parsed if owner_row[0] <= row[0] < safeoff_row[0]]
    if not energized or any(row[3][0] != 0 or row[2] < rail_on_min for row in energized[1:]):
        common.fail("native energized window lacks continuous raw0/high-rail evidence")
    if admission_row[3] != (0, 0, 1, 1):
        common.fail("native admission lacks exact populated reset tuple 454:0,455:1,456:1")
    if any(sum(rpm >= 1_000 for rpm in row[4]) != 4 for row in energized):
        common.fail("native energized window lacks four-channel cooling")
    after = [row for row in parsed if row[0] >= safeoff_row[0]]
    if not after or any(row[3] != (1, 0, 0, 0) for row in after):
        common.fail("native terminal window is not checked GPIO437/raw1 and all-reset")
    low = [row for row in after if row[2] <= rail_off_max]
    if len(low) < 2 or low[-1][0] - low[0][0] < 5_000:
        common.fail("native terminal rail decay lacks two low observations over five seconds")
    if any(sum(rpm >= 1_000 for rpm in row[4]) != 4 for row in parsed if owner_row[0] <= row[0] <= low[-1][0]):
        common.fail("four-channel cooling was lost before rail-decay confirmation")
    return data, {
        "safety_sample_count": len(parsed),
        "cold_baseline_start_ms": baselines[0][0],
        "admission_ms": admission_row[0],
        "safeoff_ms": safeoff_row[0],
        "rail_decay_confirmed_ms": low[-1][0],
        "terminal_ms": terminal_row[0],
    }


def verify_evidence(
    evidence_dir: Path, *, require_workflow_receipt: bool = True
) -> dict[str, Any]:
    manifest_data, manifest, payload = common.verify_manifest(
        evidence_dir,
        schema=SCHEMA,
        phase=PHASE,
        payload_files=FILES,
        extra_keys=EXTRA_KEYS,
    )
    target = common.digest(manifest["target_identity_sha256"], "target identity")
    artifact = common.digest(manifest["artifact_sha256"], "native artifact")
    owner_sha = common.digest(manifest["owner_verification_sha256"], "owner verification")
    hardware_sha = common.digest(manifest["hardware_verification_sha256"], "hardware verification")
    if common.sha256(payload["owner-verification.json"]) != owner_sha:
        common.fail("owner verification is not the manifest-bound receipt")
    if common.sha256(payload["hardware-verification.json"]) != hardware_sha:
        common.fail("hardware verification is not the manifest-bound receipt")
    owner = common.validate_embedded_receipt(
        payload["owner-verification.json"], "owner verification"
    )
    hardware = common.validate_embedded_receipt(
        payload["hardware-verification.json"], "hardware verification"
    )
    hardware_id = _verified_hardware_receipt(hardware, target=target)
    _verified_owner_receipt(
        owner, artifact_sha256=artifact, hardware_id=hardware_id
    )
    off_max = common.canonical_uint(manifest["rail_off_max"], "rail_off_max")
    on_min = common.canonical_uint(manifest["rail_on_min"], "rail_on_min", positive=True)
    dangerous = common.canonical_uint(manifest["dangerous_temp_millic"], "dangerous temperature", positive=True)
    if off_max >= on_min or not 40_000 <= dangerous <= 100_000:
        common.fail("native rail or temperature thresholds are not credible")
    _, events = _events(evidence_dir / "events.csv")
    _, safety = _safety(evidence_dir / "safety.csv", rail_off_max=off_max, rail_on_min=on_min, dangerous=dangerous)
    _, uart = common.parse_uart(evidence_dir / "uart.csv", require_work=False)
    if not safety["admission_ms"] <= events["owner_admitted_ms"] < safety["safeoff_ms"]:
        common.fail("owner admission is outside the independent energized window")
    if events["owner_terminal_ms"] > safety["terminal_ms"]:
        common.fail("owner terminal event is later than the independent terminal sample")
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "phase": PHASE,
        "claim": "native cold-start exact 77/77 no-work admission and checked independent SafeOff",
        "run_id": manifest["run_id"],
        "common_clock_id": manifest["common_clock_id"],
        "target_identity_sha256": target,
        "artifact_sha256": artifact,
        "capture_manifest_sha256": common.sha256(manifest_data),
        "owner_verification_sha256": owner_sha,
        "hardware_verification_sha256": hardware_sha,
        "persistent_mutation": False,
        **events,
        **safety,
        **uart,
    }
    result = common.add_verification_id(result)
    if require_workflow_receipt:
        common.verify_workflow_receipt(evidence_dir, result)
    return result


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    return verify_evidence(evidence_dir, require_workflow_receipt=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_workflow_evidence(args.evidence_dir.resolve(strict=True))
    except (OSError, common.NativeLiveEvidenceError) as error:
        print(f"S19K_NATIVE_PHASE12_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(common.canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
