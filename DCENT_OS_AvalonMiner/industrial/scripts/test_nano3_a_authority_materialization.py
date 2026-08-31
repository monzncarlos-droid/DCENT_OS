#!/usr/bin/env python3
"""Adversarial offline tests for Nano 3 A materialization staging."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCRIPT = Path(__file__).with_name("nano3_a_authority_materialization.py")
W4_SCRIPT = Path(__file__).with_name("nano3_a_session_admission.py")
W2_SCRIPT = Path(__file__).with_name("nano3_stock_telemetry_contract.py")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MAT = load("nano3_a_authority_materialization_test", SCRIPT)
W4 = load("nano3_a_session_admission_materialization_test", W4_SCRIPT)
W2 = load("nano3_stock_telemetry_materialization_test", W2_SCRIPT)
NOW = datetime(2026, 8, 24, 18, 0, tzinfo=timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def api_response(command: str, payload: list[dict], when: int) -> bytes:
    document = {
        "STATUS": [
            {
                "STATUS": "S",
                "Code": W2.READ_CODES[command],
                "When": when,
                "Msg": "fixture",
            }
        ],
        W2.PAYLOAD_KEYS[command]: payload,
        "id": 1,
    }
    return json.dumps(document, separators=(",", ":")).encode("ascii") + b"\x00"


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        base.mkdir(mode=0o700)
        self.input = base / "protected-input"
        self.ledger = base / "local-ledger"
        self.public = base / "public"
        self.staging_parent = base / "staging-parent"
        for path in (self.input, self.ledger, self.public, self.staging_parent):
            path.mkdir(mode=0o700)
            if os.name != "nt":
                path.chmod(0o700)
        self.output = self.staging_parent / "staging"
        self.public_receipt = self.public / "receipt.json"
        self.source_path = self.input / "materialization-source.json"
        self.session_id = "nano3-w5-fixture-session-0001"
        self.unit_id = "nano3-w5-fixture-unit-0001"
        self.operator_id = "operator-w5-fixture-0001"
        self.nonce_sha = MAT.sha256(bytes(range(32)))
        self.w4_keys = {
            role: Ed25519PrivateKey.generate() for role in W4.SIGNER_ROLES
        }
        self.authority_keys = {
            role: Ed25519PrivateKey.generate() for role in MAT.AUTHORITY_ROLES
        }
        self.files: dict[str, bytes] = {}
        self.telemetry_source: dict = {}
        self.recovery_manifest: dict = {}
        self.recovery_ack: dict = {}
        self.w4_plan: dict = {}
        self.manifest: dict = {}
        self.source: dict = {}
        self.build()

    def binding(self, role: str, classification: str) -> dict:
        return {
            "fixture_only": True,
            "role": role,
            "classification": classification,
            "session_id": self.session_id,
            "unit_id": self.unit_id,
            "nonce_sha256": self.nonce_sha,
            "authority_granted": False,
            "physical_authenticity_proven": False,
        }

    def put(self, name: str, raw: bytes) -> dict:
        self.files[name] = raw
        return {"path": name, "bytes": len(raw), "sha256": MAT.sha256(raw)}

    def ref(self, role: str, name: str, raw: bytes, schema: str) -> dict:
        result = {"role": role, **self.put(name, raw), "schema": schema}
        return result

    def build_telemetry(self) -> None:
        identity_raw = MAT.canonical_json({"unsigned_fixture_identity": True})
        capture_raw = MAT.canonical_json({"unsigned_fixture_capture": True})
        identity_name = "telemetry-identity.json"
        capture_name = "telemetry-capture.json"
        self.put(identity_name, identity_raw)
        self.put(capture_name, capture_raw)
        version_fields = {
            "CGMiner": "4.11.1",
            "VERSION": "24071801_42c628d",
            "PROD": "Avalon Nano 3",
        }
        payloads = {
            "version": [version_fields],
            "summary": [
                {
                    "MHS 5s": 2_200_000.0,
                    "Accepted": 10,
                    "Rejected": 0,
                    "Hardware Errors": 0,
                }
            ],
            "stats": [
                {
                    "MM Count": 1,
                    "MM ID0": (
                        "HashStatus[1] Temp[31] OTemp[34] TMax[70] TAvg[68] "
                        "TarT[80] Fan1[1740] FanR[25%] HW[0] SoftOFF[0]"
                    ),
                }
            ],
            "devs": [{"Name": "AVANANO", "Temperature": 0.0}],
            "pools": [
                {
                    "POOL": 0,
                    "URL": "stratum+tcp://protected.invalid:3333",
                    "User": "protected-worker",
                }
            ],
            "lcd": [
                {
                    "Current Pool": "stratum+tcp://protected.invalid:3333",
                    "User": "protected-worker",
                }
            ],
        }
        records = []
        for sequence, (round_number, command) in enumerate(
            W2.EXPECTED_CAPTURE_SEQUENCE, 1
        ):
            raw = api_response(command, payloads[command], sequence)
            name = f"telemetry-{sequence:02d}-r{round_number}-{command}.bin"
            self.put(name, raw)
            request = W2.encode_request(command)
            records.append(
                {
                    "sequence": sequence,
                    "round": round_number,
                    "command": command,
                    "captured_at_utc": f"2026-08-24T12:00:{sequence:02d}Z",
                    "request_bytes": len(request),
                    "request_sha256": W2.sha256_bytes(request),
                    "response_path": name,
                    "response_bytes": len(raw),
                    "response_sha256": W2.sha256_bytes(raw),
                }
            )
        self.telemetry_source = {
            "schema": W2.SOURCE_SCHEMA,
            "purpose": W2.PURPOSE,
            "bundle_id": "stock-capture-w5-fixture-0001",
            "provenance": "synthetic_fixture",
            "target": {
                "model": W2.TARGET_MODEL,
                "btcminer_sha256": W2.HELD_BTCMINER_SHA256,
                "expected_version_fields": version_fields,
                "identity_receipt_path": identity_name,
                "identity_receipt_sha256": MAT.sha256(identity_raw),
            },
            "capture": {
                "capture_id": "stock-capture-w5-fixture-0001",
                "started_at_utc": "2026-08-24T12:00:00Z",
                "ended_at_utc": "2026-08-24T12:00:12Z",
                "one_connection_per_command": True,
                "request_framing": "minified_json_plus_one_nul",
                "response_framing": "one_json_object_then_nuls_read_to_eof",
                "raw_response_bytes_retained": True,
                "capture_receipt_path": capture_name,
                "capture_receipt_sha256": MAT.sha256(capture_raw),
            },
            "responses": records,
        }
        source_raw = W2.canonical_json(self.telemetry_source)
        self.put("telemetry-source.json", source_raw)
        # Compile against the exact protected fixture files before outer signing.
        source_path = self.input / "telemetry-source.json"
        for name, raw in self.files.items():
            (self.input / name).write_bytes(raw)
        compiled_raw = W2.canonical_json(W2.compile_bundle(source_path))
        self.put("telemetry-compiled.json", compiled_raw)

    def build_recovery(self) -> None:
        engineering_key = public_bytes(self.authority_keys["recovery_engineering"])
        geometry = {
            "slots": [
                {
                    "name": name,
                    "offset": offset,
                    "size_bytes": size,
                    "erase_size": erase,
                }
                for name, offset, size, erase in MAT.RECOVERY_SLOTS
            ],
            "system_interval": {"offset": 0, "end": 0x06400000},
            "persistent_data_interval": {
                "offset": 0x06400000,
                "end": 0x08000000,
            },
        }
        data_policy = {
            "policy": "preserve",
            "required_cli_flag": "--no-data-erase",
            "erase_data": False,
            "factory_reset": False,
            "persistent_data_payload_included": False,
            "persistent_data_erase_or_write_forbidden": True,
        }
        self.recovery_manifest = {
            "schema": MAT.RECOVERY_SCHEMA,
            "purpose": MAT.RECOVERY_PURPOSE,
            "authorization_class": MAT.RECOVERY_CLASS,
            "signature": {
                "algorithm": "ed25519",
                "domain": MAT.RECOVERY_ENGINEERING_DOMAIN,
                "trust_anchor": "pinned-dcentral-k230-factory-recovery-key-v1",
                "key_id": MAT.sha256(engineering_key),
            },
            "authorization": {
                "authorization_id": "recovery-authorization-w5-0001",
                "operation_nonce": self.nonce_sha,
                "issued_at_utc": int((NOW - timedelta(minutes=2)).timestamp()),
                "expires_at_utc": int((NOW + timedelta(minutes=10)).timestamp()),
                "one_shot": True,
                "attended": True,
                "recovery_rail_admission": True,
                "replay_enforcement": "same-host-atomic-ledger-before-usb",
            },
            "target": {
                "model": "nano3",
                "model_profile_revision": "nano3-kdimg-release-r1-recovery-master",
                "unit_asset_id": self.unit_id,
                "hardware_revision": "nano3-fixture-hardware-r1",
                "fingerprint_profile_revision": "nano3-r1-stock-chain",
                "fingerprint_revision": "heater-nano3-master-b99a2358",
                "expected_fingerprint_sha256": MAT.RECOVERY_FINGERPRINT_SHA256,
                "capacity_bytes": 0x08000000,
                "block_size": 0x00000800,
                "erase_size": 0x00020000,
            },
            "artifact": {
                "artifact_id": "historical-live-proven-stock-restore-2026-08-21",
                "sha256": MAT.RECOVERY_ARTIFACT_SHA256,
                "size_bytes": MAT.RECOVERY_ARTIFACT_BYTES,
                "donor_revision": "heater-nano3-master-b99a2358",
                "donor_sha256": MAT.RECOVERY_DONOR_SHA256,
                "partition_count": 12,
            },
            "geometry": geometry,
            "data_policy": data_policy,
            "flasher": {
                "implementation": "dcent_toolbox.cli.commands.flash",
                "version": "2.5.0",
                "sha256": MAT.RECOVERY_FLASH_SHA256,
                "size_bytes": MAT.RECOVERY_FLASH_BYTES,
                "components": [
                    {
                        "module": module,
                        "runtime_code_sha256": runtime_sha,
                        "source_sha256": source_sha,
                        "source_size_bytes": source_bytes,
                    }
                    for module, runtime_sha, source_sha, source_bytes in (
                        MAT.RECOVERY_FLASH_COMPONENTS
                    )
                ],
                "execution_profile": "nano3-factory-recovery-r1",
                "trusted_loader_sha256": MAT.RECOVERY_LOADER_SHA256,
                "transport": "kburn-usb-29f1:0230-bootrom-only",
            },
            "scope": {
                "factory_recovery_authorized": True,
                "mutation_release_authorized": False,
                "firmware_release_authorized": False,
                "persistent_data_reset_authorized": False,
            },
            "w4_fixture_binding": self.binding(
                "recovery_authority", W4.CLASS_AUTH
            ),
        }
        self.refresh_recovery_files()

    def refresh_recovery_files(self) -> None:
        raw = MAT.canonical_recovery_json(self.recovery_manifest)
        self.put("recovery-manifest.json", raw)
        engineering_signature = self.authority_keys["recovery_engineering"].sign(
            MAT.RECOVERY_ENGINEERING_DOMAIN.encode("ascii") + b"\x00" + raw
        )
        self.put("recovery-engineering.sig", engineering_signature)
        authorization = self.recovery_manifest["authorization"]
        target = self.recovery_manifest["target"]
        geometry = self.recovery_manifest["geometry"]
        data_policy = self.recovery_manifest["data_policy"]
        operator_key = public_bytes(self.authority_keys["recovery_operator"])
        self.recovery_ack = {
            "schema": MAT.RECOVERY_OPERATOR_SCHEMA,
            "purpose": MAT.RECOVERY_OPERATOR_PURPOSE,
            "signature": {
                "algorithm": "ed25519",
                "domain": MAT.RECOVERY_OPERATOR_DOMAIN,
                "trust_anchor": "pinned-operator-factory-recovery-key-v1",
                "key_id": MAT.sha256(operator_key),
            },
            "operator": {
                "operator_id": self.operator_id,
                "attended": True,
                "exact_action_acknowledged": True,
                "one_shot_acknowledged": True,
            },
            "authorization_binding": {
                "manifest_sha256": MAT.sha256(raw),
                "authorization_id": authorization["authorization_id"],
                "operation_nonce": authorization["operation_nonce"],
                "issued_at_utc": authorization["issued_at_utc"],
                "expires_at_utc": authorization["expires_at_utc"],
            },
            "target": {
                "model": target["model"],
                "unit_asset_id": target["unit_asset_id"],
                "hardware_revision": target["hardware_revision"],
                "expected_fingerprint_sha256": target[
                    "expected_fingerprint_sha256"
                ],
            },
            "action": {
                "operation": "write-exact-stock-system-slots-and-reboot",
                "artifact_sha256": self.recovery_manifest["artifact"]["sha256"],
                "artifact_size_bytes": self.recovery_manifest["artifact"][
                    "size_bytes"
                ],
                "partition_count": self.recovery_manifest["artifact"][
                    "partition_count"
                ],
                "geometry_sha256": MAT.sha256(
                    MAT.canonical_recovery_json(geometry)
                ),
                "data_policy_sha256": MAT.sha256(
                    MAT.canonical_recovery_json(data_policy)
                ),
                "required_cli_flag": "--no-data-erase",
                "persistent_data_reset_authorized": False,
                "mutation_release_authorized": False,
            },
        }
        ack_raw = MAT.canonical_recovery_json(self.recovery_ack)
        self.put("recovery-operator-ack.json", ack_raw)
        operator_signature = self.authority_keys["recovery_operator"].sign(
            MAT.RECOVERY_OPERATOR_DOMAIN.encode("ascii") + b"\x00" + ack_raw
        )
        self.put("recovery-operator.sig", operator_signature)

    def component_raw(self, role: str, classification: str, schema: str) -> bytes:
        if role == "image_candidate":
            return b"synthetic W5 image candidate bytes\x00"
        if role == "recovery_authority":
            return self.files["recovery-manifest.json"]
        if role == "telemetry_contract":
            source_raw = self.files["telemetry-source.json"]
            compiled_raw = self.files["telemetry-compiled.json"]
            document = {
                "schema": schema,
                "w5_materialization_join": {
                    "compiled_contract_sha256": MAT.sha256(compiled_raw),
                    "source_bundle_sha256": MAT.sha256(source_raw),
                    "authentic_live_capability_verified": False,
                },
            }
        elif role == "safety_qualification":
            document = {
                "schema_version": 1,
                "record_type": "dcent-nano3-interlock-production-qualification",
            }
        else:
            document = {"schema": schema}
        document["w4_fixture_binding"] = self.binding(role, classification)
        return W4.canonical_json(document)

    def build_w4(self) -> None:
        components = []
        for role, (classification, schema) in W4.COMPONENT_POLICY.items():
            raw = self.component_raw(role, classification, schema)
            if role == "recovery_authority":
                name = "recovery-manifest.json"
            else:
                suffix = ".kdimg" if role == "image_candidate" else ".json"
                name = f"w4-{role}{suffix}"
            self.put(name, raw)
            components.append(
                {
                    "role": role,
                    "classification": classification,
                    "schema": schema,
                    "path": name,
                    "bytes": len(raw),
                    "sha256": MAT.sha256(raw),
                }
            )
        component_map = {record["role"]: record for record in components}
        signers = {}
        for role in W4.SIGNER_ROLES:
            raw = public_bytes(self.w4_keys[role])
            name = f"w4-{role}.pub"
            self.put(name, raw)
            signers[role] = {
                "path": name,
                "bytes": 32,
                "sha256": MAT.sha256(raw),
                "domain": W4.SIGNER_DOMAINS[role],
                "key_epoch": f"w4-{role}-epoch-0001",
            }
        expected_results = []
        for role, (schema, required_when) in W4.RESULT_POLICY.items():
            expected_results.append(
                {
                    "role": role,
                    "classification": W4.CLASS_RESULT,
                    "schema": schema,
                    "required_when": required_when,
                    "output_name": f"{role}.json",
                    "producer_sha256": MAT.sha256(f"producer:{role}".encode()),
                    "join": "exact_prepare_plan_session_unit_nonce_and_role",
                }
            )
        self.w4_plan = {
            "schema": W4.PLAN_SCHEMA,
            "purpose": W4.PURPOSE,
            "bundle_id": "nano3-w5-fixture-bundle-0001",
            "mode": "synthetic_fixture",
            "issued_at_utc": iso(NOW - timedelta(minutes=3)),
            "valid_from_utc": iso(NOW - timedelta(minutes=2)),
            "expires_at_utc": iso(NOW + timedelta(minutes=10)),
            "session": {
                "session_id": self.session_id,
                "unit_id": self.unit_id,
                "unit_model": W4.TARGET_MODEL,
                "unit_fingerprint_sha256": MAT.RECOVERY_FINGERPRINT_SHA256,
                "nonce_sha256": self.nonce_sha,
                "operator_id": self.operator_id,
                "authorization_reference": "authorization-a-w5-fixture-0001",
                "btcminer_sha256": W4.BTCMINER_SHA256,
                "trusted_time_record_sha256": component_map[
                    "trusted_time_record"
                ]["sha256"],
                "global_replay_record_sha256": component_map[
                    "global_replay_record"
                ]["sha256"],
            },
            "actions": {
                "allowed": list(W4.ALLOWED_ACTIONS),
                "excluded": list(W4.EXCLUDED_ACTIONS),
            },
            "components": components,
            "signers": signers,
            "expected_results": expected_results,
            "claims": {key: False for key in sorted(W4.FALSE_CLAIMS)},
        }
        self.refresh_w4_signatures()

    def refresh_w4_signatures(self) -> None:
        plan_raw = W4.canonical_json(self.w4_plan)
        self.w4_signatures = {}
        for role in W4.SIGNER_ROLES:
            raw = self.w4_keys[role].sign(
                W4.SIGNER_DOMAINS[role].encode("ascii") + b"\x00" + plan_raw
            )
            name = f"w4-{role}.sig"
            self.put(name, raw)
            self.w4_signatures[role] = raw

    def supplemental_records(self) -> list[dict]:
        file_by_role = {
            "recovery_engineering_signature": "recovery-engineering.sig",
            "recovery_operator_ack": "recovery-operator-ack.json",
            "recovery_operator_signature": "recovery-operator.sig",
            "telemetry_compiled_contract": "telemetry-compiled.json",
            "telemetry_source_bundle": "telemetry-source.json",
            "telemetry_identity_receipt": "telemetry-identity.json",
            "telemetry_capture_receipt": "telemetry-capture.json",
            "post_cut_prior_receipt": "post-cut-prior.json",
            "post_cut_raw_evidence": "post-cut-raw.bin",
            "pool_topology_raw_evidence": "pool-topology-raw.bin",
        }
        for sequence, (_round, command) in enumerate(
            W2.EXPECTED_CAPTURE_SEQUENCE, 1
        ):
            role = f"telemetry_raw_{sequence:02d}_{command}"
            file_by_role[role] = self.telemetry_source["responses"][sequence - 1][
                "response_path"
            ]
        records = []
        for role, (schema, _maximum) in MAT.SUPPLEMENTAL_POLICY.items():
            name = file_by_role[role]
            raw = self.files[name]
            records.append(
                {
                    "role": role,
                    "path": name,
                    "bytes": len(raw),
                    "sha256": MAT.sha256(raw),
                    "schema": schema,
                }
            )
        return records

    def build_manifest(self) -> None:
        self.put(
            "post-cut-prior.json",
            MAT.canonical_json({"schema": "dcent.nano3.post-cut-receipt.v2"}),
        )
        self.put("post-cut-raw.bin", b"opaque synthetic post-cut fixture\x00")
        self.put("pool-topology-raw.bin", b"opaque synthetic topology fixture\x00")
        component_inputs = [
            {
                "role": record["role"],
                "path": record["path"],
                "bytes": record["bytes"],
                "sha256": record["sha256"],
                "schema": record["schema"],
            }
            for record in self.w4_plan["components"]
        ]
        w4_key_inputs = []
        w4_signature_inputs = []
        for role in W4.SIGNER_ROLES:
            signer = self.w4_plan["signers"][role]
            w4_key_inputs.append(
                {
                    "role": role,
                    "path": signer["path"],
                    "bytes": 32,
                    "sha256": signer["sha256"],
                    "schema": "ed25519.public-key.raw32",
                }
            )
            signature_name = f"w4-{role}.sig"
            signature = self.files[signature_name]
            w4_signature_inputs.append(
                {
                    "role": role,
                    "path": signature_name,
                    "bytes": 64,
                    "sha256": MAT.sha256(signature),
                    "schema": "ed25519.signature.raw64",
                }
            )
        w4_source = {
            "schema": W4.PREPARE_SOURCE_SCHEMA,
            "purpose": W4.PURPOSE,
            "plan": self.w4_plan,
            "signatures": {
                role: base64.b64encode(self.w4_signatures[role]).decode("ascii")
                for role in W4.SIGNER_ROLES
            },
        }
        authority_signers = {}
        for index, role in enumerate(MAT.AUTHORITY_ROLES):
            raw = public_bytes(self.authority_keys[role])
            name = f"authority-{role}.pub"
            self.put(name, raw)
            signed_at = NOW - timedelta(seconds=40 - index)
            if role == "operator_authorization_a":
                signed_at = NOW - timedelta(seconds=5)
            authority_signers[role] = {
                "path": name,
                "bytes": 32,
                "sha256": MAT.sha256(raw),
                "domain": MAT.AUTHORITY_DOMAINS[role],
                "key_epoch": f"authority-{role}-epoch-0001",
                "signed_at_utc": iso(signed_at),
            }
        self_record = {
            "name": SCRIPT.name,
            "bytes": SCRIPT.stat().st_size,
            "sha256": MAT.sha256(SCRIPT.read_bytes()),
        }
        self.manifest = {
            "schema": MAT.MANIFEST_SCHEMA,
            "purpose": MAT.PURPOSE,
            "mode": "synthetic_fixture",
            "materialization_id": "nano3-w5-materialization-fixture-0001",
            "issued_at_utc": iso(NOW - timedelta(minutes=3)),
            "valid_from_utc": iso(NOW - timedelta(minutes=2)),
            "expires_at_utc": iso(NOW + timedelta(minutes=10)),
            "toolchain": {
                "materializer": self_record,
                "w4_compiler": {
                    "name": MAT.W4_NAME,
                    "bytes": MAT.W4_BYTES,
                    "sha256": MAT.W4_SHA256,
                },
                "telemetry_compiler": {
                    "name": MAT.W2_NAME,
                    "bytes": MAT.W2_BYTES,
                    "sha256": MAT.W2_SHA256,
                },
                "recovery_verifier": {
                    "name": MAT.RECOVERY_VERIFIER_NAME,
                    "bytes": MAT.RECOVERY_VERIFIER_BYTES,
                    "sha256": MAT.RECOVERY_VERIFIER_SHA256,
                },
                "python_runtime": {
                    "implementation": MAT.platform.python_implementation(),
                    "version": MAT.platform.python_version(),
                    "path_lookup_used": False,
                    "byte_identity_verified": False,
                    "dependency_scope_complete": False,
                },
            },
            "w4_plan": self.w4_plan,
            "w4_prepare_source_sha256": MAT.sha256(W4.canonical_json(w4_source)),
            "component_inputs": component_inputs,
            "w4_key_inputs": w4_key_inputs,
            "w4_signature_inputs": w4_signature_inputs,
            "supplemental_inputs": self.supplemental_records(),
            "authority_signers": authority_signers,
            "external_states": copy.deepcopy(MAT.EXTERNAL_STATE_POLICY),
            "claims": {
                "authorization_a_granted": False,
                "device_contact_authorized": False,
                "global_one_shot_consumed": False,
                "operator_authority_proven": False,
                "physical_qualifications_proven": False,
                "production_materialization_complete": False,
            },
        }

    def refresh_authority_signatures(self) -> None:
        manifest_raw = MAT.canonical_json(self.manifest)
        signatures = {}
        for role in MAT.AUTHORITY_ROLES:
            raw = self.authority_keys[role].sign(
                MAT.AUTHORITY_DOMAINS[role].encode("ascii")
                + b"\x00"
                + manifest_raw
            )
            name = f"authority-{role}.sig"
            self.put(name, raw)
            signatures[role] = {
                "path": name,
                "bytes": 64,
                "sha256": MAT.sha256(raw),
                "schema": "ed25519.signature.raw64",
            }
        self.source = {
            "schema": MAT.SOURCE_SCHEMA,
            "purpose": MAT.PURPOSE,
            "manifest": self.manifest,
            "authority_signatures": signatures,
        }

    def write_all(self) -> None:
        self.files[self.source_path.name] = MAT.canonical_json(self.source)
        for name, raw in self.files.items():
            (self.input / name).write_bytes(raw)
        if os.name != "nt":
            self.input.chmod(0o700)

    def build(self) -> None:
        self.build_telemetry()
        self.build_recovery()
        self.build_w4()
        self.build_manifest()
        self.refresh_authority_signatures()
        self.write_all()

    def resign_everything(self) -> None:
        self.refresh_recovery_files()
        # Recovery manifest is a W4 component; refresh its exact descriptor.
        recovery_raw = self.files["recovery-manifest.json"]
        component = next(
            item
            for item in self.w4_plan["components"]
            if item["role"] == "recovery_authority"
        )
        component.update(bytes=len(recovery_raw), sha256=MAT.sha256(recovery_raw))
        self.files[component["path"]] = recovery_raw
        self.refresh_w4_signatures()
        self.build_manifest()
        self.refresh_authority_signatures()
        self.write_all()

    def resign_outer(self) -> None:
        self.refresh_authority_signatures()
        self.write_all()

    def run(self, *, now: datetime = NOW):
        return MAT.materialize(
            self.source_path.absolute(),
            self.output.absolute(),
            self.public_receipt.absolute(),
            self.ledger.absolute(),
            fixture_only=True,
            now=now,
        )


class MaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root / "case")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fresh(self, name: str) -> Fixture:
        return Fixture(self.root / name)

    def test_valid_fixture_stages_w4_but_never_authorizes(self) -> None:
        receipt = self.fixture.run()
        self.assertTrue(receipt["file_contract_valid"])
        self.assertTrue(receipt["w4_prepare_byte_contract_staged"])
        self.assertTrue((self.fixture.output / ".incomplete").is_file())
        self.assertTrue((self.fixture.output / ".terminal-no-authority").is_file())
        for key, value in MAT.PUBLIC_STATE_POLICY.items():
            self.assertIs(receipt[key], value)
        self.assertFalse(receipt["production_materialization_complete"])
        self.assertFalse(receipt["local_replay_is_global"])
        self.assertEqual(receipt["device_contact"], "none")
        protected_w4 = self.fixture.output / "w4-prepare"
        w4_ledger = self.root / "w4-validation-ledger"
        w4_ledger.mkdir(mode=0o700)
        prepared = W4.prepare(
            protected_w4 / "prepare-source.json",
            w4_ledger.absolute(),
            fixture_only=True,
            now=NOW,
        )
        self.assertFalse(prepared["authorization_a_granted"])

    def test_production_refuses_before_input_read_or_output(self) -> None:
        nonexistent = (self.root / "missing" / "source.json").absolute()
        output = (self.root / "never-created" / "out").absolute()
        with self.assertRaisesRegex(MAT.MaterializationError, "production materialization is disabled"):
            MAT.materialize(
                nonexistent,
                output,
                (self.root / "never-public" / "receipt.json").absolute(),
                (self.root / "never-ledger").absolute(),
                fixture_only=False,
            )
        self.assertFalse(output.exists())

    def test_checked_in_template_is_intentionally_invalid(self) -> None:
        template = SCRIPT.with_name("nano3_a_authority_materialization.template.json")
        result = MAT.validate_template(template)
        self.assertFalse(result["production_materialization_complete"])
        self.assertFalse(result["authorization_a_granted"])
        self.assertEqual(result["device_contact"], "none")

    def test_external_authority_state_cannot_be_promoted_even_when_resigned(self) -> None:
        self.fixture.manifest["external_states"]["trusted_time"][
            "trusted_time_verified"
        ] = True
        self.fixture.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "external typed states"):
            self.fixture.run()

    def test_claim_cannot_be_promoted_even_when_resigned(self) -> None:
        self.fixture.manifest["claims"]["authorization_a_granted"] = True
        self.fixture.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "claims must remain"):
            self.fixture.run()

    def test_recovery_exact_policy_mutations_are_refused_after_both_resign(self) -> None:
        mutations = {
            "artifact": lambda doc: doc["artifact"].update(sha256="b" * 64),
            "model": lambda doc: doc["target"].update(model="nano4"),
            "fingerprint": lambda doc: doc["target"].update(
                expected_fingerprint_sha256="c" * 64
            ),
            "slot count": lambda doc: doc["geometry"]["slots"].pop(),
            "slot end": lambda doc: doc["geometry"]["system_interval"].update(
                end=0x06400001
            ),
            "data": lambda doc: doc["data_policy"].update(erase_data=True),
            "scope": lambda doc: doc["scope"].update(
                mutation_release_authorized=True
            ),
            "flasher": lambda doc: doc["flasher"].update(version="2.5.1"),
        }
        for index, (label, mutate) in enumerate(mutations.items()):
            with self.subTest(label=label):
                fixture = self.fresh(f"recovery-{index}")
                mutate(fixture.recovery_manifest)
                fixture.resign_everything()
                with self.assertRaises(MAT.MaterializationError):
                    fixture.run()

    def test_recovery_unknown_authorization_field_is_refused(self) -> None:
        self.fixture.recovery_manifest["authorization"]["waiver"] = True
        self.fixture.resign_everything()
        with self.assertRaisesRegex(MAT.MaterializationError, "authorization key set"):
            self.fixture.run()

    def test_recovery_wrong_trust_anchor_is_refused_after_resign(self) -> None:
        self.fixture.recovery_manifest["signature"]["trust_anchor"] = "fixture-waiver"
        self.fixture.resign_everything()
        with self.assertRaisesRegex(MAT.MaterializationError, "engineering key/domain"):
            self.fixture.run()

    def test_telemetry_trailer_is_refused_after_outer_resign(self) -> None:
        record = self.fixture.telemetry_source["responses"][0]
        name = record["response_path"]
        raw = self.fixture.files[name] + b"TRAILER"
        self.fixture.files[name] = raw
        record["response_bytes"] = len(raw)
        record["response_sha256"] = MAT.sha256(raw)
        source_raw = W2.canonical_json(self.fixture.telemetry_source)
        self.fixture.files["telemetry-source.json"] = source_raw
        for item in self.fixture.manifest["supplemental_inputs"]:
            if item["path"] == name:
                item.update(bytes=len(raw), sha256=MAT.sha256(raw))
            if item["path"] == "telemetry-source.json":
                item.update(bytes=len(source_raw), sha256=MAT.sha256(source_raw))
        self.fixture.resign_outer()
        with self.assertRaises(MAT.MaterializationError):
            self.fixture.run()

    def test_compiled_telemetry_substitution_is_refused(self) -> None:
        name = "telemetry-compiled.json"
        raw = self.fixture.files[name].replace(b'"schema":', b'"fixture":false,"schema":', 1)
        self.fixture.files[name] = raw
        for item in self.fixture.manifest["supplemental_inputs"]:
            if item["path"] == name:
                item.update(bytes=len(raw), sha256=MAT.sha256(raw))
        self.fixture.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "compiled contract"):
            self.fixture.run()

    def test_toolchain_module_substitution_is_refused_when_resigned(self) -> None:
        self.fixture.manifest["toolchain"]["w4_compiler"]["sha256"] = "d" * 64
        self.fixture.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "w4_compiler identity"):
            self.fixture.run()

    def test_signature_domain_and_key_reuse_are_refused(self) -> None:
        domain = self.fresh("wrong-domain")
        domain.manifest["authority_signers"]["telemetry_authority"]["domain"] = (
            MAT.AUTHORITY_DOMAINS["post_cut_authority"]
        )
        domain.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "domain mismatch"):
            domain.run()
        reused = self.fresh("key-reuse")
        reused.authority_keys["telemetry_authority"] = reused.authority_keys[
            "post_cut_authority"
        ]
        reused.build_manifest()
        reused.refresh_authority_signatures()
        reused.write_all()
        with self.assertRaisesRegex(MAT.MaterializationError, "must be distinct"):
            reused.run()

    def test_operator_must_be_strictly_last_and_inside_window(self) -> None:
        early = self.fresh("operator-early")
        early.manifest["authority_signers"]["operator_authorization_a"][
            "signed_at_utc"
        ] = iso(NOW - timedelta(minutes=1))
        early.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "final pre-session"):
            early.run()
        future = self.fresh("signer-future")
        future.manifest["authority_signers"]["operator_authorization_a"][
            "signed_at_utc"
        ] = iso(NOW + timedelta(minutes=11))
        future.resign_outer()
        with self.assertRaisesRegex(MAT.MaterializationError, "outside the signed validity"):
            future.run()

    def test_missing_and_extra_protected_inputs_are_refused(self) -> None:
        missing = self.fresh("missing-input")
        (missing.input / "post-cut-raw.bin").unlink()
        with self.assertRaises(MAT.MaterializationError):
            missing.run()
        extra = self.fresh("extra-input")
        (extra.input / "unlisted.bin").write_bytes(b"extra")
        with self.assertRaisesRegex(MAT.MaterializationError, "membership mismatch"):
            extra.run()

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hard_link_input_is_refused(self) -> None:
        target = self.fixture.input / "post-cut-raw.bin"
        alias = self.root / "post-cut-alias.bin"
        try:
            os.link(target, alias)
        except OSError as exc:
            self.skipTest(f"hard links unavailable: {exc}")
        with self.assertRaisesRegex(MAT.MaterializationError, "single-link"):
            self.fixture.run()

    def test_symlink_input_is_refused_when_supported(self) -> None:
        target = self.fixture.input / "post-cut-raw.bin"
        retained = target.read_bytes()
        target.unlink()
        actual = self.root / "outside.bin"
        actual.write_bytes(retained)
        try:
            target.symlink_to(actual)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaises(MAT.MaterializationError):
            self.fixture.run()

    def test_duplicate_json_key_and_nonfinite_are_refused(self) -> None:
        duplicate = self.fresh("duplicate-json")
        raw = duplicate.source_path.read_bytes()
        duplicate.source_path.write_bytes(raw.replace(b"{", b'{"schema":"duplicate",', 1))
        with self.assertRaises(MAT.MaterializationError):
            duplicate.run()
        nonfinite = self.fresh("nonfinite-json")
        raw = nonfinite.source_path.read_bytes()
        nonfinite.source_path.write_bytes(raw.replace(b'"manifest":{', b'"manifest":{"x":NaN,', 1))
        with self.assertRaises(MAT.MaterializationError):
            nonfinite.run()

    def test_expired_and_future_host_time_are_refused(self) -> None:
        with self.assertRaisesRegex(MAT.MaterializationError, "stale, future"):
            self.fixture.run(now=NOW + timedelta(hours=1))
        future = self.fresh("future-host")
        with self.assertRaisesRegex(MAT.MaterializationError, "stale, future"):
            future.run(now=NOW - timedelta(hours=1))

    def test_local_replay_is_consumed_but_never_global(self) -> None:
        self.fixture.run()
        second_parent = self.root / "second-parent"
        second_parent.mkdir(mode=0o700)
        second_public = self.root / "second-public"
        second_public.mkdir(mode=0o700)
        with self.assertRaisesRegex(MAT.MaterializationError, "exclusive protected output"):
            MAT.materialize(
                self.fixture.source_path.absolute(),
                (second_parent / "staging").absolute(),
                (second_public / "receipt.json").absolute(),
                self.fixture.ledger.absolute(),
                fixture_only=True,
                now=NOW,
            )
        self.assertTrue((second_parent / "staging" / ".incomplete").exists())

    def test_output_and_public_receipt_are_no_overwrite(self) -> None:
        existing = self.fresh("existing-output")
        existing.output.mkdir()
        with self.assertRaisesRegex(MAT.MaterializationError, "exclusive creation"):
            existing.run()
        public = self.fresh("existing-public")
        public.public_receipt.write_text("occupied", encoding="ascii")
        with self.assertRaisesRegex(MAT.MaterializationError, "already exists"):
            public.run()

    def test_roots_must_be_disjoint_and_non_nested(self) -> None:
        with self.assertRaisesRegex(MAT.MaterializationError, "disjoint"):
            MAT.materialize(
                self.fixture.source_path.absolute(),
                (self.fixture.input / "nested-output").absolute(),
                self.fixture.public_receipt.absolute(),
                self.fixture.ledger.absolute(),
                fixture_only=True,
                now=NOW,
            )

    def test_input_replacement_before_custody_write_is_refused(self) -> None:
        original = MAT.read_regular
        calls = 0

        def replace_on_revalidation(path, maximum, label):
            nonlocal calls
            if label == "revalidated protected input":
                calls += 1
                if calls == 1:
                    path.write_bytes(path.read_bytes() + b"changed")
            return original(path, maximum, label)

        with mock.patch.object(MAT, "read_regular", side_effect=replace_on_revalidation):
            with self.assertRaisesRegex(MAT.MaterializationError, "protected input changed"):
                self.fixture.run()
        self.assertTrue((self.fixture.output / ".incomplete").exists())
        self.assertFalse((self.fixture.output / ".terminal-no-authority").exists())
        self.assertFalse(self.fixture.public_receipt.exists())

    def test_terminal_write_failure_leaves_non_authority_custody(self) -> None:
        original = MAT.write_new

        def fail_terminal(path, raw):
            if path.name == ".terminal-no-authority":
                raise OSError("injected terminal durability failure")
            return original(path, raw)

        with mock.patch.object(MAT, "write_new", side_effect=fail_terminal):
            with self.assertRaisesRegex(OSError, "terminal durability"):
                self.fixture.run()
        self.assertTrue((self.fixture.output / ".incomplete").exists())
        self.assertFalse(self.fixture.public_receipt.exists())
        self.assertEqual(len(list(self.fixture.ledger.iterdir())), 1)

    def test_public_receipt_failure_does_not_promote_terminal(self) -> None:
        original = MAT.write_new

        def fail_public(path, raw):
            if path == self.fixture.public_receipt.absolute():
                raise OSError("injected public durability failure")
            return original(path, raw)

        with mock.patch.object(MAT, "write_new", side_effect=fail_public):
            with self.assertRaisesRegex(OSError, "public durability"):
                self.fixture.run()
        self.assertTrue((self.fixture.output / ".incomplete").exists())
        terminal = json.loads(
            (self.fixture.output / ".terminal-no-authority").read_text("ascii")
        )
        self.assertFalse(terminal["production_materialization_complete"])
        self.assertFalse(terminal["authorization_a_granted"])

    def test_public_receipt_has_no_stable_protected_identifiers_or_hashes(self) -> None:
        self.fixture.run()
        raw = self.fixture.public_receipt.read_text("ascii")
        for secret in (
            self.fixture.session_id,
            self.fixture.unit_id,
            self.fixture.nonce_sha,
            str(self.fixture.input),
            MAT.RECOVERY_ARTIFACT_SHA256,
            "sha256",
            "operator-w5-fixture",
        ):
            self.assertNotIn(secret, raw)


if __name__ == "__main__":
    unittest.main()
