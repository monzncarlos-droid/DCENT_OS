#!/usr/bin/env python3
"""Adversarial fixtures for the three chained S19k native live verifiers."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
common = importlib.import_module("s19k_native_live_common")
phase12 = importlib.import_module("s19k_native_phase12_verify")
bounded = importlib.import_module("s19k_native_bounded_verify")
endurance = importlib.import_module("s19k_native_endurance_verify")


TARGET = "1" * 64
ARTIFACT = "2" * 64
OWNER_SHA = ""
HARDWARE_SHA = ""


def cjson(value: object) -> bytes:
    return common.canonical_json(value)


def verified_receipt(value: dict[str, object]) -> dict[str, object]:
    return common.add_verification_id(dict(value))


def write(path: Path, data: bytes | str) -> None:
    path.write_bytes(data.encode("ascii") if isinstance(data, str) else data)


def reseal_manifest_file(directory: Path, name: str) -> None:
    _, value = common.load_canonical_json(
        directory / "capture-manifest.json", "test capture manifest"
    )
    data = (directory / name).read_bytes()
    value["files"][name] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
    if name == "owner-verification.json":
        value["owner_verification_sha256"] = hashlib.sha256(data).hexdigest()
    elif name == "hardware-verification.json":
        value["hardware_verification_sha256"] = hashlib.sha256(data).hexdigest()
    write(directory / "capture-manifest.json", cjson(value))


def manifest(directory: Path, schema: str, phase: str, extras: dict[str, object], names: tuple[str, ...]) -> None:
    files = {}
    for name in names:
        data = (directory / name).read_bytes()
        files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    value = {
        "schema": schema,
        "phase": phase,
        "run_id": "run-native-test-001",
        "common_clock_id": "clock-test-001",
        "files": files,
        **extras,
    }
    write(directory / "capture-manifest.json", cjson(value))
    write(directory / "verification.json", b"{}\n")


def phase12_fixture(root: Path) -> dict[str, object]:
    manifest_public_key_hex = "1" * 64
    hardware = verified_receipt(
        {
            "schema": phase12.HARDWARE_SCHEMA,
            "claim": phase12.HARDWARE_CLAIM,
            "authority_granted": False,
            "live_identity_sha256": TARGET,
            "tty_to_physical_address": {"/dev/ttyS1": 3, "/dev/ttyS2": 2},
            "reset_gpio_to_tty": {"455": "/dev/ttyS2", "456": "/dev/ttyS1"},
            "absent_physical_address": 1,
            "absent_reset_gpio": 454,
            "unpopulated_uart": "/dev/ttyS3",
            "gpio437_raw_energized": 0,
            "gpio437_raw_safeoff": 1,
        }
    )
    source_files = [
        {
            "path": path,
            "sha256": format(index % 16, "x") * 64,
            "bytes": index,
        }
        for index, path in enumerate(phase12.OWNER_SOURCE_PATHS, 5)
    ]
    cargo_metadata_sha256 = "7" * 64
    capsule = {
        "binary": {
            "name": "dcentrald",
            "path": "target/aarch64-unknown-linux-musl/release/dcentrald",
            "sha256": ARTIFACT,
            "size": 1024,
        },
        "build_inputs": {},
        "build_environment": {
            "DCENT_MANIFEST_KEY_ID": "",
            "DCENT_MANIFEST_PUBLIC_KEY_HEX": manifest_public_key_hex,
        },
        "build_variant": phase12.native_build.BUILD_VARIANT,
        "builder": {
            "kind": "docker-cross",
            "base_reference": "rust@sha256:" + "a" * 64,
            "image_id": "sha256:" + "b" * 64,
            "package_resolution": phase12.native_build.BUILDER_PACKAGE_RESOLUTION,
        },
        "cargo_metadata": {
            "path": "inventory/aarch64.metadata.json",
            "sha256": cargo_metadata_sha256,
            "size": 4096,
        },
        "claim": phase12.native_build.CAPSULE_RECEIPT_CLAIM,
        "compile_environment": {
            "entries": {
                "DCENT_MANIFEST_KEY_ID": "",
                "DCENT_MANIFEST_PUBLIC_KEY_HEX": manifest_public_key_hex,
            }
        },
        "git": {
            "commit": "a" * 40,
            "source_kind": "exact-git-object-snapshot",
        },
        "profile": phase12.native_build.PROFILE,
        "release_capsule": {
            "schema": "org.dcentral.dcentos.release-capsule-lineage.v2",
            "release_invocation_descriptor_sha256": "c" * 64,
            "release_invocation_id": "d" * 64,
            "source_snapshot_descriptor_sha256": "e" * 64,
            "source_snapshot_id": "f" * 64,
        },
        "schema_version": 4,
        "source_inventory": [],
        "source_inventory_sha256": "6" * 64,
        "target_triple": phase12.native_build.TARGET,
        "toolchain_context": {},
    }
    closure_packages = [
        {
            "name": name,
            "version": "0.9.0",
            "manifest_path": manifest_path,
            "package_root": Path(manifest_path).parent.as_posix(),
        }
        for name, manifest_path in phase12.LOCAL_PACKAGE_MANIFESTS.items()
    ]
    build_receipt = verified_receipt(
        {
            "schema": phase12.NATIVE_BUILD_SCHEMA,
            "claim": phase12.NATIVE_BUILD_CLAIM,
            "classification": (
                "exact-snapshot-capsule-linked-manifest-key-pinned-candidate"
            ),
            "target_triple": "aarch64-unknown-linux-musl",
            "cargo_profile": "release",
            "cargo_command": phase12.NATIVE_BUILD_COMMAND,
            "artifact": {"path": "dcentrald", "sha256": ARTIFACT, "bytes": 1024},
            "semantic_source_files": source_files,
            "semantic_source_files_sha256": hashlib.sha256(
                cjson(source_files)
            ).hexdigest(),
            "aarch64_compile_contract": phase12.OWNER_COMPILE_CONTRACT,
            "compile_contract_sha256": hashlib.sha256(
                cjson(phase12.OWNER_COMPILE_CONTRACT)
            ).hexdigest(),
            "capsule_build_receipt": capsule,
            "capsule_build_receipt_sha256": hashlib.sha256(cjson(capsule)).hexdigest(),
            "local_dependency_closure": {
                "cargo_metadata_sha256": cargo_metadata_sha256,
                "target_triple": phase12.native_build.TARGET,
                "root_package_id": "dcentrald 0.9.0 (path+file:///snapshot)",
                "packages": closure_packages,
                "external_local_paths_inside_snapshot": True,
            },
            "manifest_public_key_hex": manifest_public_key_hex,
            "manifest_public_key_sha256": hashlib.sha256(
                bytes.fromhex(manifest_public_key_hex)
            ).hexdigest(),
            "network_nonuse_proven": False,
            "network_contract": phase12.native_build.NETWORK_CONTRACT,
            "release_authority_granted": False,
            "installation_authority_granted": False,
            "live_hardware_contacted": False,
        }
    )
    owner = verified_receipt(
        {
            "schema": phase12.OWNER_SCHEMA,
            "phase_id": "native-cold-start-owner",
            "classification": "verified",
            "source_readiness_classification": "ready",
            "production_owner_present": True,
            "dependency_evidence_bound": True,
            "prerequisite_verification_ids": {
                "native-secure-firmware-re": "3" * 64,
                "native-hardware-contract": hardware["verification_id"],
                "adopted-endurance": "4" * 64,
                "native-build-reproducibility": "5" * 64,
            },
            "native_owner_artifact": {
                "path": "usr/local/bin/dcentrald",
                "sha256": ARTIFACT,
                "bytes": 1024,
            },
            "source_files": source_files,
            "aarch64_compile_contract": phase12.OWNER_COMPILE_CONTRACT,
            "native_build_receipt": build_receipt,
            "native_owner_build_binding": {
                "target_triple": "aarch64-unknown-linux-musl",
                "cargo_profile": "release",
                "artifact_role": "native-cold-start-owner",
                "source_files_sha256": hashlib.sha256(
                    cjson(source_files)
                ).hexdigest(),
                "compile_contract_sha256": hashlib.sha256(
                    cjson(phase12.OWNER_COMPILE_CONTRACT)
                ).hexdigest(),
                "adopted_artifact_reused": False,
                "native_build_verification_id": build_receipt["verification_id"],
                "capsule_build_receipt_sha256": build_receipt[
                    "capsule_build_receipt_sha256"
                ],
                "source_commit": capsule["git"]["commit"],
                "source_snapshot_id": capsule["release_capsule"][
                    "source_snapshot_id"
                ],
                "release_invocation_id": capsule["release_capsule"][
                    "release_invocation_id"
                ],
                "cargo_metadata_sha256": cargo_metadata_sha256,
                "manifest_public_key_hex": manifest_public_key_hex,
                "manifest_public_key_sha256": build_receipt[
                    "manifest_public_key_sha256"
                ],
                "native_reproducibility_verification_id": "5" * 64,
                "observed_native_build_verification_ids": sorted(
                    [build_receipt["verification_id"], "6" * 64]
                ),
                "observed_release_invocation_ids": sorted(
                    [capsule["release_capsule"]["release_invocation_id"], "7" * 64]
                ),
            },
            "capability_inventory": {
                capability: {
                    "status": "joined",
                    "evidence": [{"path": "source.rs", "line": 1, "symbol": capability}],
                }
                for capability in phase12.OWNER_CAPABILITIES
            },
            "inputs_sha256": "8" * 64,
            "host_only_source_audit": True,
            "live_hardware_contacted": False,
            "authority_minted": False,
        }
    )
    owner_data, hardware_data = cjson(owner), cjson(hardware)
    write(root / "owner-verification.json", owner_data)
    write(root / "hardware-verification.json", hardware_data)
    events = [
        "sequence,monotonic_ms,event,path,value",
        "0,100,safeoff-initial,global,checked",
        "1,200,cooling-ready,global,four-channels",
        "2,300,rail-enabled,global,gpio437-raw0",
        "3,400,reset-released,/dev/ttyS1,mapped",
        "4,500,enumeration-complete,/dev/ttyS1,77",
        "5,600,reset-released,/dev/ttyS2,mapped",
        "6,700,enumeration-complete,/dev/ttyS2,77",
        "7,5100,owner-admitted,global,opaque-production-owner",
        "8,5500,no-work-window-complete,global,zero-work",
        "9,6000,safeoff-begin,global,checked",
        "10,6100,reset-asserted,global,all",
        "11,6200,rail-disabled,global,gpio437-raw1",
        "12,12000,owner-terminal,global,checked",
    ]
    write(root / "events.csv", "\n".join(events) + "\n")
    header = ",".join(phase12.SAFETY_HEADER)
    safety = [header]
    for timestamp in (0, 1000, 2000):
        safety.append(f"{timestamp},cold-baseline,0,1,0,0,0,0,0,0,0,25000,25000,25000,25000")
    safety += [
        "3000,owner-start,0,1,0,0,0,2000,2000,2000,2000,25000,25000,25000,25000",
        "4000,sample,12000,0,0,0,0,2000,2000,2000,2000,26000,26000,26000,26000",
        "5000,admission,12000,0,0,1,1,2000,2000,2000,2000,27000,27000,27000,27000",
        "6000,safeoff,0,1,0,0,0,2000,2000,2000,2000,27000,27000,27000,27000",
    ]
    for timestamp in range(7000, 13000, 1000):
        safety.append(f"{timestamp},sample,0,1,0,0,0,2000,2000,2000,2000,26000,26000,26000,26000")
    safety.append("13000,terminal,0,1,0,0,0,2000,2000,2000,2000,25000,25000,25000,25000")
    write(root / "safety.csv", "\n".join(safety) + "\n")
    write(
        root / "uart.csv",
        "monotonic_ms,path,direction,frame_hex\n"
        "4000,/dev/ttyS1,tx,55AA510900\n4100,/dev/ttyS1,rx,AA55\n"
        "4200,/dev/ttyS2,tx,55AA510900\n4300,/dev/ttyS2,rx,AA55\n",
    )
    owner_sha = hashlib.sha256(owner_data).hexdigest()
    hardware_sha = hashlib.sha256(hardware_data).hexdigest()
    manifest(
        root,
        phase12.SCHEMA,
        phase12.PHASE,
        {
            "target_identity_sha256": TARGET,
            "artifact_sha256": ARTIFACT,
            "owner_verification_sha256": owner_sha,
            "hardware_verification_sha256": hardware_sha,
            "rail_off_max": 100,
            "rail_on_min": 10000,
            "dangerous_temp_millic": 90000,
        },
        phase12.FILES,
    )
    result = phase12.verify_evidence(root, require_workflow_receipt=False)
    write(root / "verification.json", cjson(result))
    return phase12.verify_workflow_evidence(root)


def bounded_fixture(root: Path, phase12_result: dict[str, object]) -> dict[str, object]:
    phase12_data = cjson(phase12_result)
    write(root / "phase12-verification.json", phase12_data)
    write(
        root / "events.csv",
        "sequence,monotonic_ms,event,path,job_id,value\n"
        "0,0,bounded-start,global,none,600-seconds-maximum\n"
        "1,100,work-tx,/dev/ttyS1,job-a,captured\n"
        "2,200,nonce-rx,/dev/ttyS1,job-a,captured\n"
        "3,300,pool-accepted,/dev/ttyS1,job-a,true\n"
        "4,400,work-tx,/dev/ttyS2,job-b,captured\n"
        "5,500,nonce-rx,/dev/ttyS2,job-b,captured\n"
        "6,600,pool-accepted,/dev/ttyS2,job-b,true\n"
        "7,1000,safeoff-begin,global,none,checked\n"
        "8,8000,owner-terminal,global,none,checked\n",
    )
    header = ",".join(bounded.SAFETY_HEADER)
    safety = [header, "0,pre-safeoff,12000,0,0,1,1,2000,2000,2000,2000"]
    for timestamp in range(1000, 8000, 1000):
        event = "safeoff" if timestamp == 1000 else "sample"
        safety.append(f"{timestamp},{event},0,1,0,0,0,2000,2000,2000,2000")
    safety.append("8000,terminal,0,1,0,0,0,2000,2000,2000,2000")
    write(root / "terminal-safety.csv", "\n".join(safety) + "\n")
    write(
        root / "uart.csv",
        "monotonic_ms,path,direction,frame_hex\n"
        "100,/dev/ttyS1,tx,55AA213600\n200,/dev/ttyS1,rx,AA55\n"
        "400,/dev/ttyS2,tx,55AA213600\n500,/dev/ttyS2,rx,AA55\n",
    )
    manifest(
        root,
        bounded.SCHEMA,
        bounded.PHASE,
        {
            "target_identity_sha256": TARGET,
            "artifact_sha256": ARTIFACT,
            "owner_verification_sha256": phase12_result["owner_verification_sha256"],
            "hardware_verification_sha256": phase12_result["hardware_verification_sha256"],
            "phase12_verification_id": phase12_result["verification_id"],
            "phase12_verification_sha256": hashlib.sha256(phase12_data).hexdigest(),
            "maximum_runtime_ms": 600000,
            "rail_off_max": 100,
        },
        bounded.FILES,
    )
    result = bounded.verify_evidence(root, require_workflow_receipt=False)
    write(root / "verification.json", cjson(result))
    return bounded.verify_workflow_evidence(root)


def endurance_fixture(root: Path, bounded_result: dict[str, object]) -> dict[str, object]:
    bounded_data = cjson(bounded_result)
    write(root / "bounded-verification.json", bounded_data)
    observations = [",".join(endurance.OBSERVATION_HEADER)]
    for timestamp in range(0, 86_400_001, 60_000):
        accepted = timestamp // 60_000
        for uart_path in common.UART_PATHS:
            observations.append(f"{timestamp},{uart_path},{accepted},0,1000,60000,2000,2000,2000,2000")
    write(root / "observations.csv", "\n".join(observations) + "\n")
    wall_start = 2_000_000_000_000
    wall = [",".join(endurance.WALL_HEADER)]
    wall.append(f"{wall_start},run-start,3000000")
    for offset in range(60_000, 86_400_000, 60_000):
        wall.append(f"{wall_start + offset},sample,3000000")
    wall.append(f"{wall_start + 86_400_000},safeoff,0")
    wall.append(f"{wall_start + 86_405_000},terminal,0")
    write(root / "wall-power.csv", "\n".join(wall) + "\n")
    faults = [",".join(endurance.FAULT_HEADER)]
    for index, fault in enumerate(sorted(endurance.REQUIRED_FAULTS), 1):
        faults.append(f"{fault},trial-{index},controlled-safeoff,true,true,false")
    write(root / "faults.csv", "\n".join(faults) + "\n")
    header = ",".join(bounded.SAFETY_HEADER)
    safety = [header, "0,pre-safeoff,12000,0,0,1,1,2000,2000,2000,2000"]
    for timestamp in range(1000, 8000, 1000):
        event = "safeoff" if timestamp == 1000 else "sample"
        safety.append(f"{timestamp},{event},0,1,0,0,0,2000,2000,2000,2000")
    safety.append("8000,terminal,0,1,0,0,0,2000,2000,2000,2000")
    write(root / "terminal-safety.csv", "\n".join(safety) + "\n")
    manifest(
        root,
        endurance.SCHEMA,
        endurance.PHASE,
        {
            "target_identity_sha256": TARGET,
            "artifact_sha256": ARTIFACT,
            "owner_verification_sha256": bounded_result["owner_verification_sha256"],
            "hardware_verification_sha256": bounded_result["hardware_verification_sha256"],
            "bounded_verification_id": bounded_result["verification_id"],
            "bounded_verification_sha256": hashlib.sha256(bounded_data).hexdigest(),
            "required_duration_ms": 86400000,
            "maximum_observation_gap_ms": 60000,
            "dangerous_temp_millic": 90000,
            "rail_off_max": 100,
            "safeoff_wall_power_max_mw": 1000,
        },
        endurance.FILES,
    )
    result = endurance.verify_evidence(root, require_workflow_receipt=False)
    write(root / "verification.json", cjson(result))
    return endurance.verify_workflow_evidence(root)


class NativeLiveVerifierTests(unittest.TestCase):
    def test_positive_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p12_dir, bounded_dir, endurance_dir = root / "p12", root / "bounded", root / "endurance"
            p12_dir.mkdir()
            bounded_dir.mkdir()
            endurance_dir.mkdir()
            p12 = phase12_fixture(p12_dir)
            bounded_result = bounded_fixture(bounded_dir, p12)
            endurance_result = endurance_fixture(endurance_dir, bounded_result)
            self.assertEqual(endurance_result["verified_duration_ms"], 86_400_000)
            self.assertEqual(endurance_result["fault_count"], 7)

    def test_all_public_verifiers_bind_exact_workflow_receipt_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p12_dir, bounded_dir, endurance_dir = (
                root / "p12",
                root / "bounded",
                root / "endurance",
            )
            p12_dir.mkdir()
            bounded_dir.mkdir()
            endurance_dir.mkdir()
            p12 = phase12_fixture(p12_dir)
            bounded_result = bounded_fixture(bounded_dir, p12)
            endurance_fixture(endurance_dir, bounded_result)

            for directory, verifier in (
                (p12_dir, phase12.verify_workflow_evidence),
                (bounded_dir, bounded.verify_workflow_evidence),
                (endurance_dir, endurance.verify_workflow_evidence),
            ):
                receipt = directory / "verification.json"
                expected = receipt.read_bytes()
                write(receipt, b"{}\n")
                with self.assertRaisesRegex(
                    common.NativeLiveEvidenceError,
                    "verification.json is stale",
                ):
                    verifier(directory)
                write(receipt, expected)
                self.assertEqual(verifier(directory)["verification_id"],
                                 common.validate_embedded_receipt(
                                     expected, "expected workflow receipt"
                                 )["verification_id"])

    def test_phase12_rejects_work_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase12_fixture(root)
            uart = root / "uart.csv"
            write(uart, uart.read_text(encoding="ascii").replace("55AA510900", "55AA213600", 1))
            reseal_manifest_file(root, "uart.csv")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "forbidden 55AA2136 work frame"
            ):
                phase12.verify_workflow_evidence(root)

    def test_phase12_rejects_owner_authority_dependency_and_compile_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase12_fixture(root)
            owner_path = root / "owner-verification.json"
            owner = common.validate_embedded_receipt(
                owner_path.read_bytes(), "owner verification"
            )
            owner.pop("verification_id")
            owner["authority_minted"] = True
            write(owner_path, cjson(verified_receipt(owner)))
            reseal_manifest_file(root, "owner-verification.json")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "exact verified production-owner"
            ):
                phase12.verify_workflow_evidence(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase12_fixture(root)
            owner_path = root / "owner-verification.json"
            owner = common.validate_embedded_receipt(
                owner_path.read_bytes(), "owner verification"
            )
            owner.pop("verification_id")
            owner["prerequisite_verification_ids"]["native-hardware-contract"] = (
                "9" * 64
            )
            write(owner_path, cjson(verified_receipt(owner)))
            reseal_manifest_file(root, "owner-verification.json")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "does not bind the embedded hardware"
            ):
                phase12.verify_workflow_evidence(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase12_fixture(root)
            owner_path = root / "owner-verification.json"
            owner = common.validate_embedded_receipt(
                owner_path.read_bytes(), "owner verification"
            )
            owner.pop("verification_id")
            owner["aarch64_compile_contract"]["cargo_offline"] = False
            write(owner_path, cjson(verified_receipt(owner)))
            reseal_manifest_file(root, "owner-verification.json")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "exact AArch64 compile contract"
            ):
                phase12.verify_workflow_evidence(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase12_fixture(root)
            owner_path = root / "owner-verification.json"
            owner = common.validate_embedded_receipt(
                owner_path.read_bytes(), "owner verification"
            )
            owner.pop("verification_id")
            native_build = dict(owner["native_build_receipt"])
            native_build.pop("verification_id")
            native_build["release_authority_granted"] = True
            native_build = verified_receipt(native_build)
            owner["native_build_receipt"] = native_build
            owner["native_owner_build_binding"]["native_build_verification_id"] = (
                native_build["verification_id"]
            )
            write(owner_path, cjson(verified_receipt(owner)))
            reseal_manifest_file(root, "owner-verification.json")
            with self.assertRaisesRegex(
                common.NativeLiveEvidenceError, "exact snapshot-capsule candidate"
            ):
                phase12.verify_workflow_evidence(root)

    def test_bounded_rejects_missing_second_share(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p12_dir = root / "p12"
            bounded_dir = root / "bounded"
            p12_dir.mkdir()
            bounded_dir.mkdir()
            p12 = phase12_fixture(p12_dir)
            bounded_fixture(bounded_dir, p12)
            events = bounded_dir / "events.csv"
            write(events, events.read_text(encoding="ascii").replace("pool-accepted,/dev/ttyS2,job-b,true", "nonce-rx,/dev/ttyS2,job-b,captured"))
            with self.assertRaises(common.NativeLiveEvidenceError):
                bounded.verify_workflow_evidence(bounded_dir)

    def test_endurance_rejects_incomplete_fault_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            p12_dir = root / "p12"
            bounded_dir = root / "bounded"
            end_dir = root / "end"
            p12_dir.mkdir()
            bounded_dir.mkdir()
            end_dir.mkdir()
            p12 = phase12_fixture(p12_dir)
            bounded_result = bounded_fixture(bounded_dir, p12)
            endurance_fixture(end_dir, bounded_result)
            faults = end_dir / "faults.csv"
            lines = faults.read_text(encoding="ascii").splitlines()
            write(faults, "\n".join(lines[:-1]) + "\n")
            with self.assertRaises(common.NativeLiveEvidenceError):
                endurance.verify_workflow_evidence(end_dir)


if __name__ == "__main__":
    unittest.main()
