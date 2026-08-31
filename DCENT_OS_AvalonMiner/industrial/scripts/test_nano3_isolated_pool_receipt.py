#!/usr/bin/env python3
"""Adversarial offline tests for the isolated Nano 3 pool receipt rail."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCRIPT = Path(__file__).with_name("nano3_isolated_pool_receipt.py")
SPEC = importlib.util.spec_from_file_location("nano3_isolated_pool_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = receipt
SPEC.loader.exec_module(receipt)


def response(command: str, payload: list[dict] | None = None, message: str = "fixture") -> bytes:
    status = {
        "STATUS": "S",
        "Code": receipt.READ_CODES.get(command, receipt.MUTATION_CODES.get(command)),
        "When": 1,
        "Msg": message,
    }
    document: dict = {"STATUS": [status], "id": 1}
    payload_key = {
        "version": "VERSION",
        "pools": "POOLS",
        "summary": "SUMMARY",
        "stats": "STATS",
        "devs": "DEVS",
        "lcd": "LCD",
    }.get(command)
    if payload_key is not None:
        document[payload_key] = payload
    return json.dumps(document, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\x00"


class IsolatedPoolReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bundle_path = self.root / "bundle.json"
        self.capture_path = self.root / "observer-capture.json"
        self.packet_capture_path = self.root / "observer-capture.opaque.bin"
        self.packet_capture_path.write_bytes(
            b"synthetic fixture pcapng bytes; not authentic capture\n"
        )
        self.runner_evidence_path = self.root / "runner-pool-evidence.json"
        self.wall_path = self.root / "idle-wall.json"
        self.ledger = self.root / "ledger"
        self.keys: dict[str, Ed25519PrivateKey] = {}
        self.key_paths: dict[str, Path] = {}
        self.key_hashes: dict[str, str] = {}
        for role in ("reviewer", "operator", "observer", "meter"):
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            path = self.root / f"{role}.pub"
            path.write_bytes(public)
            self.keys[role] = private
            self.key_paths[role] = path
            self.key_hashes[role] = receipt.sha256_bytes(public)
        self.commitment_key = self.root / "commitment.key"
        self.commitment_key.write_bytes(bytes(range(32)))
        self.key_receipt = {
            "schema": receipt.COMMITMENT_KEY_RECEIPT_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": "isolated-session-fixture-0001",
            "unit_id": "nano3-unit-fixture-0001",
            "nonce": "one-shot-nonce-fixture-0001",
            "algorithm": "os_csprng_256",
            "bytes": 32,
            "key_sha256": receipt.sha256_bytes(self.commitment_key.read_bytes()),
            "generated_at_utc": "2026-08-24T11:59:50Z",
        }
        self.target_hash = receipt.sha256_bytes(b"203.0.113.40")
        self.source_hash = receipt.sha256_bytes(b"203.0.113.2")
        self.version_fields = {
            "CGMiner": "4.11.1",
            "VERSION": "24071801_42c628d",
            "PROD": "Avalon Nano 3",
        }
        self.pre_pools = [
            {
                "POOL": 0,
                "Priority": 0,
                "URL": "stratum+tcp://private-one.invalid:3333",
                "User": "secret-worker-one",
                "Status": "Alive",
                "Stratum Active": True,
                "Accepted": 10,
            },
            {
                "POOL": 1,
                "Priority": 1,
                "URL": "stratum+tcp://private-two.invalid:4444",
                "User": "secret-worker-two",
                "Status": "Dead",
                "Stratum Active": False,
                "Accepted": 5,
            },
        ]
        self.dead_pools = [
            {**self.pre_pools[0], "Status": "Disabled", "Stratum Active": False},
            {**self.pre_pools[1], "Status": "Disabled", "Stratum Active": False},
            {
                "POOL": 2,
                "Priority": 2,
                "URL": receipt.DEAD_POOL_URL,
                "User": "x",
                "Status": "Dead",
                "Stratum Active": False,
                "Accepted": 0,
            },
        ]
        self.plan = self.make_plan()
        self.acceptance_contract_path = self.root / "pool-acceptance-contract.json"
        self.acceptance_contract = {
            "schema": receipt.ACCEPTANCE_CONTRACT_SCHEMA,
            "purpose": receipt.PURPOSE,
            "contract_id": "pool-acceptance-fixture-0001",
            "target_model": receipt.TARGET_MODEL,
            "btcminer_sha256": receipt.HELD_BTCMINER_SHA256,
            "telemetry_contract_sha256": self.plan["artifacts"][
                "telemetry_contract_sha256"
            ],
            "acceptance": copy.deepcopy(self.plan["acceptance"]),
            "authority": (
                "reviewer-signed through exact plan artifact hash; "
                "grants no Authorization A"
            ),
        }
        acceptance_raw = receipt.canonical_json(self.acceptance_contract)
        self.acceptance_contract_path.write_bytes(acceptance_raw)
        self.plan["artifacts"][
            "pool_acceptance_contract_sha256"
        ] = receipt.sha256_bytes(acceptance_raw)
        self.topology = self.make_topology()
        self.unit_identity = self.make_unit_identity()
        self.ack = self.make_ack()
        self.transcript = self.make_transcript()
        self.capture: dict = {}
        self.envelope: dict = {}
        self.bundle: dict = {}
        self.resign()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_plan(self) -> dict:
        return {
            "schema": receipt.PLAN_SCHEMA,
            "purpose": receipt.PURPOSE,
            "plan_id": "isolated-plan-fixture-0001",
            "session_id": "isolated-session-fixture-0001",
            "unit_id": "nano3-unit-fixture-0001",
            "nonce": "one-shot-nonce-fixture-0001",
            "valid_from_utc": "2026-08-24T12:00:00Z",
            "expires_at_utc": "2026-08-24T12:30:00Z",
            "target": {
                "model": receipt.TARGET_MODEL,
                "ipv4_sha256": self.target_hash,
                "btcminer_sha256": receipt.HELD_BTCMINER_SHA256,
                "expected_version_fields": dict(self.version_fields),
                "unit_identity_receipt_sha256": "0" * 64,
            },
            "artifacts": {
                "runner_sha256": "1" * 64,
                "session_manifest_sha256": "2" * 64,
                "telemetry_contract_sha256": "3" * 64,
                "pool_acceptance_contract_sha256": "0" * 64,
                "credential_commitment_key_receipt_sha256": receipt.sha256_bytes(
                    receipt.canonical_json(self.key_receipt)
                ),
            },
            "isolation": {
                "subnet_cidr": "203.0.113.0/24",
                "boundary_record_sha256": "4" * 64,
                "permitted_source_ipv4_sha256": self.source_hash,
                "observer_id": "observer-fixture-0001",
                "interface_ids": ["fixture-interface-1"],
                "capture_filter": "host 203.0.113.40 and tcp port 4028",
                "topology_receipt_sha256": "0" * 64,
                "same_host_monotonic_clock_domain": "fixture-host-boot-clock-0001",
                "only_permitted_source_can_reach_4028": True,
                "single_runner_client": True,
            },
            "protocol": {
                "port": 4028,
                "request_framing": "minified_json_plus_one_nul",
                "response_framing": "one_json_object_then_nuls_read_to_eof",
                "max_response_bytes": receipt.MAX_RESPONSE_BYTES,
                "connect_timeout_seconds": 1.0,
                "read_timeout_seconds": 2.0,
                "total_timeout_seconds": 3.0,
            },
            "acceptance": {
                "zero_hash_mhs_5s_max": 10.0,
                "zero_hash_proof_seconds": 120,
                "zero_hash_sample_interval_seconds": 60,
                "zero_hash_min_samples": 3,
                "idle_watts_min": 5.0,
                "idle_watts_max": 50.0,
                "idle_meter_id": "wall-meter-fixture-0001",
                "restored_accepted_min_delta": 1,
            },
            "authority": {
                "reviewer_key_id": "reviewer-fixture-key-0001",
                "operator_key_id": "operator-fixture-key-0001",
                "observer_key_id": "observer-fixture-key-0001",
                "meter_key_id": "meter-fixture-key-0001",
                "distinct_roles": True,
            },
            "explicit_exclusions": [
                "fan_mutation",
                "flash",
                "process_signal",
                "reboot",
                "uart_contact",
                "watchdog_close_phase4",
            ],
        }

    def make_topology(self) -> dict:
        return {
            "schema": receipt.TOPOLOGY_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "unit_id": self.plan["unit_id"],
            "nonce": self.plan["nonce"],
            "observer_id": self.plan["isolation"]["observer_id"],
            "clock_domain": self.plan["isolation"]["same_host_monotonic_clock_domain"],
            "interface_ids": self.plan["isolation"]["interface_ids"],
            "capture_filter": self.plan["isolation"]["capture_filter"],
            "boundary_record_sha256": self.plan["isolation"]["boundary_record_sha256"],
            "firewall_ruleset_sha256": "5" * 64,
            "only_permitted_source_path_to_target_4028": True,
            "no_bypass_route_to_target_4028": True,
            "reviewed_at_utc": "2026-08-24T12:00:10Z",
        }

    def make_unit_identity(self) -> dict:
        return {
            "schema": receipt.IDENTITY_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "unit_id": self.plan["unit_id"],
            "nonce": self.plan["nonce"],
            "target_ipv4_sha256": self.target_hash,
            "btcminer_sha256": receipt.HELD_BTCMINER_SHA256,
            "expected_version_fields": dict(self.version_fields),
            "unit_fingerprint_kind": "reviewed-nano3-device-fingerprint-v1",
            "unit_fingerprint_sha256": "9" * 64,
            "captured_at_utc": "2026-08-24T12:00:05Z",
        }

    def make_ack(self) -> dict:
        return {
            "schema": receipt.OPERATOR_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "unit_id": self.plan["unit_id"],
            "nonce": self.plan["nonce"],
            "plan_sha256": "0" * 64,
            "operator_id": "operator-fixture-0001",
            "approved_actions": [
                "isolated_4028_session",
                "all_live_pools_disable",
                "dead_pool_hash_off_proof",
                "exact_pool_restore",
            ],
            "approved": True,
            "acknowledged_at_utc": "2026-08-24T12:00:30Z",
            "authority": "one session only; grants no future action",
        }

    def make_transcript(self) -> dict:
        connections: list[dict] = []
        next_open = 1_000_000_000

        def add(
            command: str,
            parameter: str | None,
            raw: bytes,
            advance_seconds: int = 1,
        ) -> int:
            nonlocal next_open
            connection_id = len(connections) + 1
            path = self.root / f"response-{connection_id:02d}.bin"
            path.write_bytes(raw)
            request = receipt.encode_request(command, parameter)
            opened = next_open
            closed = opened + 100_000_000
            next_open = opened + advance_seconds * 1_000_000_000
            connections.append(
                {
                    "connection_id": connection_id,
                    "runner_event_id": f"api-{connection_id:04d}",
                    "opened_monotonic_ns": opened,
                    "closed_monotonic_ns": closed,
                    "command": command,
                    "parameter": parameter,
                    "request_bytes": len(request),
                    "request_sha256": receipt.sha256_bytes(request),
                    "response_path": path.name,
                    "response_bytes": len(raw),
                    "response_sha256": receipt.sha256_bytes(raw),
                    "outcome": "complete_eof",
                    "eof_observed": True,
                }
            )
            return connection_id

        add("version", None, response("version", [dict(self.version_fields)]))
        pre_pools = add("pools", None, response("pools", copy.deepcopy(self.pre_pools)))
        pre_lcd = add(
            "lcd",
            None,
            response("lcd", [{"Current Pool": self.pre_pools[0]["URL"], "User": self.pre_pools[0]["User"]}]),
        )
        addpool = add("addpool", receipt.DEAD_POOL_PARAMETER, response("addpool", message="Added pool 2: 'dead'"))
        add("pools", None, response("pools", copy.deepcopy(self.dead_pools)))
        switch = add("switchpool", "2", response("switchpool", message="Switching to pool 2: dead"))
        disable0 = add("disablepool", "0", response("disablepool", message="Disabling pool 0: one"))
        disable1 = add("disablepool", "1", response("disablepool", message="Disabling pool 1: two"))
        dead_pools = add("pools", None, response("pools", copy.deepcopy(self.dead_pools)))
        dead_lcd = add("lcd", None, response("lcd", [{"Current Pool": receipt.DEAD_POOL_URL, "User": "x"}]))
        zero_start = add(
            "summary",
            None,
            response("summary", [{"MHS 5s": 4.0, "Accepted": 20}]),
            advance_seconds=60,
        )
        zero_middle = add(
            "summary",
            None,
            response("summary", [{"MHS 5s": 0.0, "Accepted": 20}]),
            advance_seconds=60,
        )
        zero_end = add(
            "summary",
            None,
            response("summary", [{"MHS 5s": 0.0, "Accepted": 20}]),
        )
        enable0 = add("enablepool", "0", response("enablepool", message="Enabling pool 0: one"))
        enable1 = add("enablepool", "1", response("enablepool", message="Enabling pool 1: two"))
        switch_back = add("switchpool", "0", response("switchpool", message="Switching to pool 0: one"))
        remove = add("removepool", "2", response("removepool", message="Removed pool 2: dead"))
        priority = add("poolpriority", "0,1", response("poolpriority", message="Changed pool priorities"))
        post_start_payload = copy.deepcopy(self.pre_pools)
        post_end_payload = copy.deepcopy(self.pre_pools)
        post_end_payload[0]["Accepted"] = 12
        post_start_pools = add("pools", None, response("pools", post_start_payload))
        post_start_lcd = add(
            "lcd",
            None,
            response(
                "lcd",
                [
                    {
                        "Current Pool": self.pre_pools[0]["URL"],
                        "User": self.pre_pools[0]["User"],
                    }
                ],
            ),
        )
        post_pools = add("pools", None, response("pools", post_end_payload))
        post_lcd = add(
            "lcd",
            None,
            response("lcd", [{"Current Pool": self.pre_pools[0]["URL"], "User": self.pre_pools[0]["User"]}]),
        )
        pre_config = self.root / "protected-config-before.ini"
        post_config = self.root / "protected-config-after.ini"
        config_bytes = b"pool1=private-one.invalid\nuser1=secret-worker-one\n"
        pre_config.write_bytes(config_bytes)
        post_config.write_bytes(config_bytes)
        self.wall_path.write_bytes(
            receipt.canonical_json(
                {
                    "schema": receipt.WALL_SCHEMA,
                    "purpose": receipt.PURPOSE,
                    "session_id": self.plan["session_id"],
                    "unit_id": self.plan["unit_id"],
                    "nonce": self.plan["nonce"],
                    "meter_id": "wall-meter-fixture-0001",
                    "captured_at_utc": "2026-08-24T12:10:00Z",
                    "clock_domain": self.plan["isolation"]["same_host_monotonic_clock_domain"],
                    "captured_monotonic_ns": (
                        connections[zero_middle - 1]["opened_monotonic_ns"]
                    ),
                    "watts": 25.0,
                }
            )
        )
        wall_raw = self.wall_path.read_bytes()
        return {
            "schema": receipt.TRANSCRIPT_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "unit_id": self.plan["unit_id"],
            "nonce": self.plan["nonce"],
            "plan_sha256": "0" * 64,
            "operator_ack_sha256": "0" * 64,
            "runner_sha256": self.plan["artifacts"]["runner_sha256"],
            "session_manifest_sha256": self.plan["artifacts"]["session_manifest_sha256"],
            "telemetry_contract_sha256": self.plan["artifacts"]["telemetry_contract_sha256"],
            "target": copy.deepcopy(self.plan["target"]),
            "clock_domain": self.plan["isolation"]["same_host_monotonic_clock_domain"],
            "started_at_utc": "2026-08-24T12:01:00Z",
            "ended_at_utc": "2026-08-24T12:20:00Z",
            "started_monotonic_ns": 0,
            "ended_monotonic_ns": connections[-1]["closed_monotonic_ns"]
            + 1_000_000_000,
            "connections": connections,
            "transaction": {
                "pre_state": {
                    "pools_connection_id": pre_pools,
                    "lcd_connection_id": pre_lcd,
                    "config_reference": {
                        "path": pre_config.name,
                        "bytes": len(config_bytes),
                        "sha256": receipt.sha256_bytes(config_bytes),
                        "captured_monotonic_ns": connections[pre_pools - 1][
                            "opened_monotonic_ns"
                        ]
                        - 100_000_000,
                    },
                },
                "hash_off": {
                    "mutation_connection_ids": [addpool, switch, disable0, disable1],
                    "pools_connection_id": dead_pools,
                    "lcd_connection_id": dead_lcd,
                    "summary_connection_ids": [zero_start, zero_middle, zero_end],
                },
                "restore": {
                    "mutation_connection_ids": [enable0, enable1, switch_back, remove, priority],
                    "pools_start_connection_id": post_start_pools,
                    "lcd_start_connection_id": post_start_lcd,
                    "pools_connection_id": post_pools,
                    "lcd_connection_id": post_lcd,
                    "config_reference": {
                        "path": post_config.name,
                        "bytes": len(config_bytes),
                        "sha256": receipt.sha256_bytes(config_bytes),
                        "captured_monotonic_ns": connections[post_start_lcd - 1][
                            "closed_monotonic_ns"
                        ]
                        + 100_000_000,
                    },
                },
                "idle_power_reference": {
                    "path": self.wall_path.name,
                    "bytes": len(wall_raw),
                    "sha256": receipt.sha256_bytes(wall_raw),
                },
            },
        }

    def resign(self) -> None:
        self.plan["artifacts"][
            "credential_commitment_key_receipt_sha256"
        ] = receipt.sha256_bytes(receipt.canonical_json(self.key_receipt))
        self.plan["target"]["unit_identity_receipt_sha256"] = receipt.sha256_bytes(
            receipt.canonical_json(self.unit_identity)
        )
        self.plan["isolation"]["topology_receipt_sha256"] = receipt.sha256_bytes(
            receipt.canonical_json(self.topology)
        )
        plan_sha = receipt.sha256_bytes(receipt.canonical_json(self.plan))
        self.ack["plan_sha256"] = plan_sha
        ack_sha = receipt.sha256_bytes(receipt.canonical_json(self.ack))
        self.transcript["plan_sha256"] = plan_sha
        self.transcript["operator_ack_sha256"] = ack_sha
        self.transcript["target"] = copy.deepcopy(self.plan["target"])
        self.transcript["runner_sha256"] = self.plan["artifacts"]["runner_sha256"]
        self.transcript["session_manifest_sha256"] = self.plan["artifacts"]["session_manifest_sha256"]
        self.transcript["telemetry_contract_sha256"] = self.plan["artifacts"]["telemetry_contract_sha256"]
        attempts = []
        for item in self.transcript["connections"]:
            attempts.append(
                {
                    "connection_id": item["connection_id"],
                    "runner_event_id": item["runner_event_id"],
                    "source_ipv4_sha256": self.source_hash,
                    "target_ipv4_sha256": self.target_hash,
                    "target_port": 4028,
                    "syn_monotonic_ns": item["opened_monotonic_ns"],
                    "closed_monotonic_ns": item["closed_monotonic_ns"],
                    "outcome": item["outcome"],
                    "eof_observed": item["eof_observed"],
                    "request_bytes": item["request_bytes"],
                    "request_sha256": item["request_sha256"],
                    "response_bytes": item["response_bytes"],
                    "response_sha256": item["response_sha256"],
                }
            )
        self.capture = {
            "schema": receipt.CAPTURE_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "unit_id": self.plan["unit_id"],
            "nonce": self.plan["nonce"],
            "clock_domain": self.plan["isolation"]["same_host_monotonic_clock_domain"],
            "interface_ids": self.plan["isolation"]["interface_ids"],
            "capture_filter": self.plan["isolation"]["capture_filter"],
            "capture_started_monotonic_ns": 0,
            "capture_ended_monotonic_ns": self.transcript["ended_monotonic_ns"]
            + 1_000_000_000,
            "dropped_packets": 0,
            "packet_capture_path": self.packet_capture_path.name,
            "packet_capture_bytes": len(self.packet_capture_path.read_bytes()),
            "packet_capture_sha256": receipt.sha256_bytes(
                self.packet_capture_path.read_bytes()
            ),
            "packet_capture_format": "opaque_observer_capture_bytes",
            "attempts": attempts,
        }
        capture_raw = receipt.canonical_json(self.capture)
        self.capture_path.write_bytes(capture_raw)
        runner_evidence = {
            "schema": receipt.RUNNER_EVIDENCE_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "manifest_sha256": self.plan["artifacts"]["session_manifest_sha256"],
            "runner_sha256": self.plan["artifacts"]["runner_sha256"],
            "target_ipv4_sha256": self.target_hash,
            "clock_domain": self.plan["isolation"][
                "same_host_monotonic_clock_domain"
            ],
            "started_at_utc": self.transcript["started_at_utc"],
            "ended_at_utc": self.transcript["ended_at_utc"],
            "started_monotonic_ns": self.transcript["started_monotonic_ns"],
            "ended_monotonic_ns": self.transcript["ended_monotonic_ns"],
            "connections": self.transcript["connections"],
            "connection_failures": [],
            "pending_intents": [],
            "mutation_effect_unknown": False,
            "acknowledged_mutation_count": sum(
                1
                for item in self.transcript["connections"]
                if item["command"] in receipt.MUTATION_CODES
            ),
            "resolved_dead_pool_id": 2,
            "transaction_outcome": "restored_exactly",
            "transaction": self.transcript["transaction"],
        }
        runner_evidence_raw = receipt.canonical_json(runner_evidence)
        self.runner_evidence_path.write_bytes(runner_evidence_raw)
        self.envelope = {
            "schema": receipt.OBSERVER_SCHEMA,
            "purpose": receipt.PURPOSE,
            "session_id": self.plan["session_id"],
            "unit_id": self.plan["unit_id"],
            "nonce": self.plan["nonce"],
            "plan_sha256": plan_sha,
            "operator_ack_sha256": ack_sha,
            "runner_evidence_sha256": receipt.sha256_bytes(runner_evidence_raw),
            "raw_capture_path": self.capture_path.name,
            "raw_capture_bytes": len(capture_raw),
            "raw_capture_sha256": receipt.sha256_bytes(capture_raw),
            "clock_domain": self.plan["isolation"]["same_host_monotonic_clock_domain"],
            "interface_ids": self.plan["isolation"]["interface_ids"],
            "capture_filter": self.plan["isolation"]["capture_filter"],
            "capture_started_monotonic_ns": self.capture["capture_started_monotonic_ns"],
            "capture_ended_monotonic_ns": self.capture["capture_ended_monotonic_ns"],
            "dropped_packets": 0,
            "capture_complete": True,
        }
        self.bundle = {
            "schema": receipt.SOURCE_SCHEMA,
            "purpose": receipt.PURPOSE,
            "bundle_id": "isolated-pool-fixture-bundle-0001",
            "provenance": "synthetic_fixture",
            "plan": self.plan,
            "plan_signature_base64": base64.b64encode(
                self.keys["reviewer"].sign(receipt.PLAN_DOMAIN + receipt.canonical_json(self.plan))
            ).decode("ascii"),
            "operator_ack": self.ack,
            "operator_signature_base64": base64.b64encode(
                self.keys["operator"].sign(receipt.OPERATOR_DOMAIN + receipt.canonical_json(self.ack))
            ).decode("ascii"),
            "unit_identity_receipt": self.unit_identity,
            "topology_receipt": self.topology,
            "observer_envelope": self.envelope,
            "observer_signature_base64": base64.b64encode(
                self.keys["observer"].sign(receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope))
            ).decode("ascii"),
            "meter_signature_base64": base64.b64encode(
                self.keys["meter"].sign(
                    receipt.METER_DOMAIN
                    + self.wall_path.read_bytes()
                )
            ).decode("ascii"),
            "runner_evidence_reference": {
                "path": self.runner_evidence_path.name,
                "bytes": len(runner_evidence_raw),
                "sha256": receipt.sha256_bytes(runner_evidence_raw),
            },
            "pool_acceptance_contract_reference": {
                "path": self.acceptance_contract_path.name,
                "bytes": len(self.acceptance_contract_path.read_bytes()),
                "sha256": receipt.sha256_bytes(
                    self.acceptance_contract_path.read_bytes()
                ),
            },
            "credential_commitment_key_path": self.commitment_key.name,
            "credential_commitment_key_receipt": self.key_receipt,
        }
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))

    def compile(self, *, ledger: Path | None = None, fixture_only: bool = True) -> dict:
        return receipt.compile_bundle(
            self.bundle_path,
            reviewer_public_key_path=self.key_paths["reviewer"],
            operator_public_key_path=self.key_paths["operator"],
            observer_public_key_path=self.key_paths["observer"],
            meter_public_key_path=self.key_paths["meter"],
            reviewer_key_sha256=self.key_hashes["reviewer"],
            operator_key_sha256=self.key_hashes["operator"],
            observer_key_sha256=self.key_hashes["observer"],
            meter_key_sha256=self.key_hashes["meter"],
            ledger_dir=ledger or self.ledger,
            fixture_only=fixture_only,
            now=datetime(2026, 8, 24, 12, 5, tzinfo=timezone.utc),
        )

    def assert_refused(self, fragment: str) -> None:
        self.resign()
        with self.assertRaisesRegex(receipt.ReceiptError, fragment):
            self.compile(ledger=self.root / f"ledger-{len(list(self.root.glob('ledger-*')))}")

    def replace_response(self, connection_id: int, raw: bytes) -> None:
        item = self.transcript["connections"][connection_id - 1]
        (self.root / item["response_path"]).write_bytes(raw)
        item["response_bytes"] = len(raw)
        item["response_sha256"] = receipt.sha256_bytes(raw)

    def rebind_runner_evidence(self, fragment: dict) -> None:
        raw = receipt.canonical_json(fragment)
        self.runner_evidence_path.write_bytes(raw)
        self.bundle["runner_evidence_reference"].update(
            {"bytes": len(raw), "sha256": receipt.sha256_bytes(raw)}
        )
        self.envelope["runner_evidence_sha256"] = receipt.sha256_bytes(raw)
        self.bundle["observer_envelope"] = self.envelope
        self.bundle["observer_signature_base64"] = base64.b64encode(
            self.keys["observer"].sign(
                receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope)
            )
        ).decode("ascii")
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))

    def rebind_capture(self) -> None:
        raw = receipt.canonical_json(self.capture)
        self.capture_path.write_bytes(raw)
        self.envelope["raw_capture_bytes"] = len(raw)
        self.envelope["raw_capture_sha256"] = receipt.sha256_bytes(raw)
        self.envelope["capture_started_monotonic_ns"] = self.capture[
            "capture_started_monotonic_ns"
        ]
        self.envelope["capture_ended_monotonic_ns"] = self.capture[
            "capture_ended_monotonic_ns"
        ]
        self.bundle["observer_envelope"] = self.envelope
        self.bundle["observer_signature_base64"] = base64.b64encode(
            self.keys["observer"].sign(
                receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope)
            )
        ).decode("ascii")
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))

    def test_valid_fixture_receipt_is_credential_safe_and_non_authorizing(self):
        result = self.compile()
        self.assertTrue(result["machine_verification_pass"])
        self.assertTrue(result["transaction"]["post_state_exactly_equals_pre_state"])
        self.assertTrue(
            result["isolation"][
                "observer_signed_semantic_attempts_matched_runner_events"
            ]
        )
        self.assertFalse(
            result["isolation"][
                "semantic_attempts_mechanically_derived_from_opaque_capture_by_compiler"
            ]
        )
        self.assertFalse(result["production_authority_keys_verified"])
        self.assertFalse(result["physical_capture_authenticity_proven_by_compiler"])
        self.assertFalse(result["authorization_a_granted"])
        rendered = json.dumps(result)
        self.assertNotIn("private-one", rendered)
        self.assertNotIn("secret-worker", rendered)
        self.assertIn("credential_identity_hmac_sha256", rendered)
        self.assertNotIn("credential_commitment_key_sha256", rendered)
        self.assertNotIn("config_sha256", rendered)
        self.assertNotIn(self.target_hash, rendered)

    def test_production_mode_refuses_unprovisioned_authority(self):
        self.bundle["provenance"] = "independently_signed_live_capture"
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "production authority key pins"):
            self.compile(fixture_only=False)

    def test_replay_and_cross_session_splice_are_refused(self):
        self.compile()
        with self.assertRaisesRegex(receipt.ReceiptError, "already consumed"):
            self.compile()
        self.ack["nonce"] = "foreign-session-nonce-0001"
        self.assert_refused("session join")

    def test_wrong_signature_and_cross_role_key_are_refused(self):
        self.bundle["operator_signature_base64"] = self.bundle["plan_signature_base64"]
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "operator acknowledgement signature"):
            self.compile(ledger=self.root / "sig-ledger")
        with self.assertRaisesRegex(receipt.ReceiptError, "must be distinct"):
            receipt.compile_bundle(
                self.bundle_path,
                reviewer_public_key_path=self.key_paths["reviewer"],
                operator_public_key_path=self.key_paths["reviewer"],
                observer_public_key_path=self.key_paths["observer"],
                meter_public_key_path=self.key_paths["meter"],
                reviewer_key_sha256=self.key_hashes["reviewer"],
                operator_key_sha256=self.key_hashes["reviewer"],
                observer_key_sha256=self.key_hashes["observer"],
                meter_key_sha256=self.key_hashes["meter"],
                ledger_dir=self.root / "role-ledger",
                fixture_only=True,
                now=datetime(2026, 8, 24, 12, 5, tzinfo=timezone.utc),
            )

    def test_extra_missing_or_failed_4028_attempt_is_refused(self):
        self.resign()
        self.capture["attempts"].append(copy.deepcopy(self.capture["attempts"][-1]))
        self.capture["attempts"][-1]["connection_id"] += 1
        self.capture["attempts"][-1]["runner_event_id"] = (
            f"api-{self.capture['attempts'][-1]['connection_id']:04d}"
        )
        self.capture["attempts"][-1]["syn_monotonic_ns"] += 1_000_000_000
        self.capture["attempts"][-1]["closed_monotonic_ns"] += 1_000_000_000
        capture_raw = receipt.canonical_json(self.capture)
        self.capture_path.write_bytes(capture_raw)
        self.envelope["raw_capture_bytes"] = len(capture_raw)
        self.envelope["raw_capture_sha256"] = receipt.sha256_bytes(capture_raw)
        self.bundle["observer_envelope"] = self.envelope
        self.bundle["observer_signature_base64"] = base64.b64encode(
            self.keys["observer"].sign(receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope))
        ).decode("ascii")
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "missing or extra"):
            self.compile(ledger=self.root / "extra-ledger")

        self.resign()
        self.capture["attempts"][0]["outcome"] = "connect_timeout"
        self.capture["attempts"][0]["eof_observed"] = False
        capture_raw = receipt.canonical_json(self.capture)
        self.capture_path.write_bytes(capture_raw)
        self.envelope["raw_capture_bytes"] = len(capture_raw)
        self.envelope["raw_capture_sha256"] = receipt.sha256_bytes(capture_raw)
        self.bundle["observer_envelope"] = self.envelope
        self.bundle["observer_signature_base64"] = base64.b64encode(
            self.keys["observer"].sign(receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope))
        ).decode("ascii")
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "failed, incomplete"):
            self.compile(ledger=self.root / "failed-ledger")

    def test_drop_counter_clock_filter_and_topology_bypass_are_refused(self):
        self.resign()
        self.capture["dropped_packets"] = 1
        capture_raw = receipt.canonical_json(self.capture)
        self.capture_path.write_bytes(capture_raw)
        self.envelope["raw_capture_bytes"] = len(capture_raw)
        self.envelope["raw_capture_sha256"] = receipt.sha256_bytes(capture_raw)
        self.bundle["observer_envelope"] = self.envelope
        self.bundle["observer_signature_base64"] = base64.b64encode(
            self.keys["observer"].sign(receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope))
        ).decode("ascii")
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "drop counter mismatch|dropped packets"):
            self.compile(ledger=self.root / "drop-ledger")
        self.resign()
        fragment = strict_json(self.runner_evidence_path)
        fragment["clock_domain"] = "foreign-clock-domain"
        fragment_raw = receipt.canonical_json(fragment)
        self.runner_evidence_path.write_bytes(fragment_raw)
        self.bundle["runner_evidence_reference"].update(
            {
                "bytes": len(fragment_raw),
                "sha256": receipt.sha256_bytes(fragment_raw),
            }
        )
        self.envelope["runner_evidence_sha256"] = receipt.sha256_bytes(
            fragment_raw
        )
        self.bundle["observer_envelope"] = self.envelope
        self.bundle["observer_signature_base64"] = base64.b64encode(
            self.keys["observer"].sign(
                receipt.OBSERVER_DOMAIN + receipt.canonical_json(self.envelope)
            )
        ).decode("ascii")
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "exact session/artifact/target join"):
            self.compile(ledger=self.root / "clock-ledger")
        self.topology["no_bypass_route_to_target_4028"] = False
        self.assert_refused("prevent bypass")

    def test_duplicate_keys_nonfinite_and_wrong_response_types_are_refused(self):
        raw = (
            b'{"STATUS":[{"STATUS":"S","Code":11,"When":1,"Msg":"x"}],'
            b'"SUMMARY":[{"MHS 5s":0,"MHS 5s":1,"Accepted":20}],"id":1}\x00'
        )
        self.replace_response(11, raw)
        self.assert_refused("duplicate JSON")
        self.replace_response(11, response("summary", [{"MHS 5s": 4.0, "Accepted": 20}]))
        raw = response("summary", [{"MHS 5s": 0, "Accepted": 20}]).replace(b'"MHS 5s":0', b'"MHS 5s":NaN')
        self.replace_response(11, raw)
        self.assert_refused("non-finite")
        self.replace_response(11, response("summary", [{"MHS 5s": 4.0, "Accepted": 20}]))
        raw = response("summary", [{"MHS 5s": 0, "Accepted": 20}]).replace(b'"id":1', b'"id":1.0')
        self.replace_response(11, raw)
        self.assert_refused("response id")

    def test_wrong_version_target_and_artifact_hash_are_refused(self):
        wrong = copy.deepcopy(self.version_fields)
        wrong["VERSION"] = "wrong"
        self.replace_response(1, response("version", [wrong]))
        self.assert_refused("VERSION response")
        self.replace_response(1, response("version", [dict(self.version_fields)]))
        self.plan["artifacts"]["runner_sha256"] = "not-a-sha"
        self.assert_refused("lowercase SHA-256")

    def test_partial_reordered_duplicate_and_ambiguous_mutations_are_refused(self):
        self.transcript["transaction"]["hash_off"]["mutation_connection_ids"].pop()
        self.assert_refused("partial, reordered")
        self.transcript = self.make_transcript()
        self.transcript["transaction"]["hash_off"]["mutation_connection_ids"][1:3] = list(
            reversed(self.transcript["transaction"]["hash_off"]["mutation_connection_ids"][1:3])
        )
        self.assert_refused("partial, reordered")
        self.transcript = self.make_transcript()
        self.transcript["transaction"]["hash_off"]["mutation_connection_ids"].append(
            self.transcript["transaction"]["hash_off"]["mutation_connection_ids"][-1]
        )
        self.assert_refused("duplicate")

    def test_dead_only_state_and_exact_dead_identity_are_required(self):
        bad = copy.deepcopy(self.dead_pools)
        bad[0]["Status"] = "Alive"
        self.replace_response(9, response("pools", bad))
        self.assert_refused("sole enabled")
        self.replace_response(9, response("pools", copy.deepcopy(self.dead_pools)))
        bad = copy.deepcopy(self.dead_pools)
        bad[2]["URL"] = "stratum+tcp://wrong.invalid:1"
        self.replace_response(
            10,
            response("lcd", [{"Current Pool": bad[2]["URL"], "User": "x"}]),
        )
        self.replace_response(9, response("pools", bad))
        self.assert_refused("dead pool identity")

    def test_restore_state_config_and_intended_pool_proof_are_required(self):
        post = copy.deepcopy(self.pre_pools)
        post[1]["Priority"] = 0
        post[0]["Priority"] = 1
        post[0]["Accepted"] = 12
        self.replace_response(21, response("pools", post))
        self.assert_refused("exact original equality")
        good_post = copy.deepcopy(self.pre_pools)
        good_post[0]["Accepted"] = 12
        self.replace_response(21, response("pools", good_post))
        post_config = self.root / self.transcript["transaction"]["restore"]["config_reference"]["path"]
        post_config.write_bytes(b"different protected config\n")
        config_raw = post_config.read_bytes()
        self.transcript["transaction"]["restore"]["config_reference"].update(
            {"bytes": len(config_raw), "sha256": receipt.sha256_bytes(config_raw)}
        )
        self.assert_refused("config bytes differ")
        pre_config = self.root / self.transcript["transaction"]["pre_state"]["config_reference"]["path"]
        good_config = pre_config.read_bytes()
        post_config.write_bytes(good_config)
        self.transcript["transaction"]["restore"]["config_reference"].update(
            {"bytes": len(good_config), "sha256": receipt.sha256_bytes(good_config)}
        )
        no_progress = copy.deepcopy(self.pre_pools)
        self.replace_response(21, response("pools", no_progress))
        self.assert_refused("Accepted counter")

    def test_zero_hash_idle_power_and_wall_session_join_are_required(self):
        self.replace_response(13, response("summary", [{"MHS 5s": 0.0, "Accepted": 21}]))
        self.assert_refused("zero-hash proof")
        self.replace_response(13, response("summary", [{"MHS 5s": 0.0, "Accepted": 20}]))
        wall = strict_json(self.wall_path)
        wall["watts"] = 500.0
        self.wall_path.write_bytes(receipt.canonical_json(wall))
        wall_raw = self.wall_path.read_bytes()
        self.transcript["transaction"]["idle_power_reference"].update(
            {"bytes": len(wall_raw), "sha256": receipt.sha256_bytes(wall_raw)}
        )
        self.assert_refused("outside reviewed envelope")
        wall["watts"] = 25.0
        wall["nonce"] = "foreign-nonce-0001"
        self.wall_path.write_bytes(receipt.canonical_json(wall))
        wall_raw = self.wall_path.read_bytes()
        self.transcript["transaction"]["idle_power_reference"].update(
            {"bytes": len(wall_raw), "sha256": receipt.sha256_bytes(wall_raw)}
        )
        self.assert_refused("session join")

    def test_credential_key_tamper_and_raw_response_trailer_are_refused(self):
        self.key_receipt["key_sha256"] = "f" * 64
        self.assert_refused("key generation receipt mismatch")
        self.key_receipt["key_sha256"] = receipt.sha256_bytes(
            self.commitment_key.read_bytes()
        )
        self.resign()
        raw = (self.root / self.transcript["connections"][1]["response_path"]).read_bytes() + b"TRAILER"
        self.replace_response(2, raw)
        self.assert_refused("framing is ambiguous")

    def test_unknown_schema_fields_expiry_and_future_window_are_refused(self):
        self.plan["unexpected_authority"] = True
        self.assert_refused("keys mismatch")
        self.plan.pop("unexpected_authority")
        self.plan["expires_at_utc"] = "2026-08-24T12:04:00Z"
        self.assert_refused("not currently valid|escapes signed plan")

    def test_meter_authority_identity_order_and_acceptance_contract_are_bound(self):
        self.bundle["meter_signature_base64"] = self.bundle[
            "observer_signature_base64"
        ]
        self.bundle_path.write_bytes(receipt.canonical_json(self.bundle))
        with self.assertRaisesRegex(receipt.ReceiptError, "meter proof signature"):
            self.compile(ledger=self.root / "meter-ledger")

        self.unit_identity["captured_at_utc"] = "2026-08-24T12:00:11Z"
        self.assert_refused("ordering escapes")
        self.unit_identity["captured_at_utc"] = "2026-08-24T12:00:05Z"
        self.plan["acceptance"]["idle_watts_max"] = 500.0
        self.assert_refused("acceptance contract")

    def test_zero_hash_coverage_and_restore_start_lcd_are_required(self):
        zero_ids = self.transcript["transaction"]["hash_off"][
            "summary_connection_ids"
        ]
        self.transcript["transaction"]["hash_off"]["summary_connection_ids"] = (
            zero_ids[:2]
        )
        self.assert_refused("too few samples")

        self.transcript = self.make_transcript()
        middle = self.transcript["connections"][11]
        middle["opened_monotonic_ns"] += 1_000_000_000
        middle["closed_monotonic_ns"] += 1_000_000_000
        self.assert_refused("cadence has a coverage gap")

        self.transcript = self.make_transcript()
        self.replace_response(
            20,
            response(
                "lcd",
                [
                    {
                        "Current Pool": self.pre_pools[1]["URL"],
                        "User": self.pre_pools[1]["User"],
                    }
                ],
            ),
        )
        self.assert_refused("post-restore pool proof changed")

    def test_inputs_are_bundle_root_confined_and_alias_ancestors_refused(self):
        self.transcript["connections"][0]["response_path"] = str(
            (self.root / "response-01.bin").resolve()
        )
        self.assert_refused("normalized relative evidence path")

        self.transcript = self.make_transcript()
        self.transcript["connections"][0]["response_path"] = "../response-01.bin"
        self.assert_refused("normalized relative evidence path")

        self.transcript = self.make_transcript()
        alias = self.root / "aliased-inputs"
        alias.mkdir()
        source = self.root / self.transcript["connections"][0]["response_path"]
        (alias / source.name).write_bytes(source.read_bytes())
        self.transcript["connections"][0]["response_path"] = (
            f"{alias.name}/{source.name}"
        )
        alias_inode = alias.lstat().st_ino
        original_is_alias = receipt._is_alias
        with mock.patch.object(
            receipt,
            "_is_alias",
            side_effect=lambda observed: (
                observed.st_ino == alias_inode or original_is_alias(observed)
            ),
        ):
            self.assert_refused("directory chain contains alias")

    def test_commitment_key_generation_no_overwrite_and_local_reuse_boundary(self):
        key_path = self.root / "generated.key"
        key_receipt_path = self.root / "generated-key-receipt.json"
        generated = receipt.generate_commitment_key(
            key_path,
            key_receipt_path,
            session_id="isolated-session-generated-0001",
            unit_id="nano3-unit-generated-0001",
            nonce="one-shot-nonce-generated-0001",
            now=datetime(2026, 8, 24, 11, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(len(key_path.read_bytes()), 32)
        self.assertEqual(
            generated["key_sha256"], receipt.sha256_bytes(key_path.read_bytes())
        )
        with self.assertRaisesRegex(receipt.ReceiptError, "overwrite"):
            receipt.generate_commitment_key(
                key_path,
                self.root / "second-receipt.json",
                session_id="isolated-session-generated-0001",
                unit_id="nano3-unit-generated-0001",
                nonce="one-shot-nonce-generated-0001",
            )

        result = self.compile()
        first_commitment = result["transaction"]["pre_state"][0][
            "credential_identity_hmac_sha256"
        ]
        same_secret = receipt._credential_safe_state(
            [
                {
                    "pool_id": 0,
                    "priority": 0,
                    "url": self.pre_pools[0]["URL"],
                    "user": self.pre_pools[0]["User"],
                    "status": "Alive",
                    "enabled": True,
                    "stratum_active": True,
                }
            ],
            0,
            self.commitment_key.read_bytes(),
            "different-session-fixture-0001",
        )[0]["credential_identity_hmac_sha256"]
        self.assertNotEqual(first_commitment, same_secret)
        with self.assertRaisesRegex(receipt.ReceiptError, "key already consumed"):
            receipt._consume_local_replay(
                self.ledger,
                "different-session-fixture-0001",
                "different-nonce-fixture-0001",
                "f" * 64,
                self.commitment_key.read_bytes(),
            )

    def test_runner_fragment_failure_pending_and_unknown_effect_refuse_success(self):
        for field, value in (
            (
                "connection_failures",
                [
                    {
                        "runner_event_id": "api-9999",
                        "connection_id": 9999,
                        "command": "disablepool",
                        "phase": "hash_off",
                        "failure_type": "TimeoutError",
                        "mutation_effect_unknown": True,
                    }
                ],
            ),
            (
                "pending_intents",
                [
                    {
                        "runner_event_id": "api-9999",
                        "connection_id": 9999,
                        "command": "disablepool",
                        "phase": "hash_off",
                        "mutation": True,
                    }
                ],
            ),
            ("mutation_effect_unknown", True),
            ("transaction_outcome", "partial_mutation_unknown_or_unrestored"),
        ):
            with self.subTest(field=field):
                self.resign()
                fragment = strict_json(self.runner_evidence_path)
                fragment[field] = value
                self.rebind_runner_evidence(fragment)
                with self.assertRaisesRegex(
                    receipt.ReceiptError, "failure, pending intent, or incomplete"
                ):
                    self.compile(ledger=self.root / f"runner-{field}-ledger")

    def test_runner_custody_interval_contains_observed_network_interval(self):
        self.resign()
        for attempt, run in zip(
            self.capture["attempts"], self.transcript["connections"]
        ):
            attempt["syn_monotonic_ns"] = run["opened_monotonic_ns"] + 10_000_000
            attempt["closed_monotonic_ns"] = run["closed_monotonic_ns"] - 10_000_000
        self.rebind_capture()
        result = self.compile(ledger=self.root / "contained-network-ledger")
        self.assertTrue(
            result["isolation"][
                "observer_signed_semantic_attempts_matched_runner_events"
            ]
        )

        self.resign()
        self.capture["attempts"][0]["syn_monotonic_ns"] = (
            self.transcript["connections"][0]["opened_monotonic_ns"] - 1
        )
        self.rebind_capture()
        with self.assertRaisesRegex(
            receipt.ReceiptError, "runner custody interval does not contain"
        ):
            self.compile(ledger=self.root / "outside-network-ledger")

    def test_replay_ledger_mode_and_parent_directory_durability(self):
        ledger = self.root / "fresh-replay-ledger"
        fsync_calls: list[Path] = []
        with mock.patch.object(
            receipt,
            "_fsync_directory",
            side_effect=lambda path: fsync_calls.append(path),
        ):
            receipt._consume_local_replay(
                ledger,
                "isolated-session-fsync-0001",
                "isolated-nonce-fsync-0001",
                "a" * 64,
                b"k" * 32,
            )
        self.assertIn(ledger.parent, fsync_calls)
        self.assertIn(ledger, fsync_calls)
        self.assertLess(fsync_calls.index(ledger.parent), fsync_calls.index(ledger))

        widened = self.root / "widened-replay-ledger"
        widened.mkdir(mode=0o700)
        widened.chmod(0o777)
        with mock.patch.object(receipt.os, "name", "posix"):
            with self.assertRaisesRegex(receipt.ReceiptError, "owner-only POSIX"):
                receipt._consume_local_replay(
                    widened,
                    "isolated-session-wide-0001",
                    "isolated-nonce-wide-0001",
                    "b" * 64,
                    b"z" * 32,
                )

    def test_checked_in_source_template_is_invalid_and_non_authorizing(self):
        template = SCRIPT.with_name("nano3_isolated_pool_source.template.json")
        document = strict_json(template)
        self.assertEqual(document["provenance"], "draft_does_not_authorize")
        with self.assertRaisesRegex(
            receipt.ReceiptError, "bundle_id|provenance is unknown"
        ):
            receipt.compile_bundle(
                template,
                reviewer_public_key_path=self.key_paths["reviewer"],
                operator_public_key_path=self.key_paths["operator"],
                observer_public_key_path=self.key_paths["observer"],
                meter_public_key_path=self.key_paths["meter"],
                reviewer_key_sha256=self.key_hashes["reviewer"],
                operator_key_sha256=self.key_hashes["operator"],
                observer_key_sha256=self.key_hashes["observer"],
                meter_key_sha256=self.key_hashes["meter"],
                ledger_dir=self.root / "template-ledger",
                fixture_only=True,
                now=datetime(2026, 8, 24, 12, 5, tzinfo=timezone.utc),
            )

    def test_packet_capture_bytes_are_bound_but_not_semantically_promoted(self):
        result = self.compile()
        isolation = result["isolation"]
        self.assertRegex(
            isolation["raw_observer_capture_bytes_hmac_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertFalse(
            isolation["capture_container_format_validated_by_compiler"]
        )
        self.assertFalse(
            isolation[
                "semantic_attempts_mechanically_derived_from_opaque_capture_by_compiler"
            ]
        )
        rendered = json.dumps(result)
        self.assertNotIn(receipt.sha256_bytes(self.packet_capture_path.read_bytes()), rendered)

        self.resign()
        self.packet_capture_path.write_bytes(b"tampered pcapng bytes\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "packet capture size/hash"):
            self.compile(ledger=self.root / "pcap-tamper-ledger")


def strict_json(path: Path) -> dict:
    return receipt.strict_json_loads(path.read_text(encoding="ascii"), "test JSON")


if __name__ == "__main__":
    unittest.main()
