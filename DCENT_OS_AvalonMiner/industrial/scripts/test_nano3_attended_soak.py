#!/usr/bin/env python3
"""Offline adversarial tests for the Nano 3 W1 attended-soak host runner."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("nano3_attended_soak.py")
SPEC = importlib.util.spec_from_file_location("nano3_attended_soak", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
soak = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = soak
SPEC.loader.exec_module(soak)


def response(code: int, payload_key: str | None = None, payload=None, **status) -> bytes:
    status_entry = {"STATUS": "S", "Code": code, "When": 1, "Msg": "fixture"}
    status_entry.update(status)
    document = {"STATUS": [status_entry], "id": 1}
    if payload_key is not None:
        document[payload_key] = payload if payload is not None else [{"fixture": True}]
    return json.dumps(document, separators=(",", ":")).encode("ascii") + b"\x00"


def pool(pool_id: int, priority: int, status: str, active: bool, url: str) -> dict:
    return {
        "POOL": pool_id,
        "URL": url,
        "User": f"secret-worker-{pool_id}",
        "Status": status,
        "Priority": priority,
        "Stratum Active": active,
    }


def api_event(command: str, raw: bytes, parameter: str | None = None) -> dict:
    return {
        "operation": "api",
        "command": command,
        "parameter": parameter,
        "response_base64": base64.b64encode(raw).decode("ascii"),
    }


def mutation_response(command: str, pool_id: int | None = None) -> bytes:
    code = soak.MUTATION_CODES[command]
    if command == "poolpriority":
        message = "Changed pool priorities"
    elif command == "addpool":
        message = f"Added pool {pool_id}: '{soak.DEAD_POOL_URL}'"
    else:
        assert pool_id is not None
        prefix = {
            "switchpool": "Switching to pool",
            "enablepool": "Enabling pool",
            "disablepool": "Disabling pool",
            "removepool": "Removed pool",
        }[command]
        message = f"{prefix} {pool_id}:'fixture-url'"
    return response(code, Msg=message)


def guard_receipt() -> bytes:
    return (
        "schema=dcent-nano3-priority-guard-v2\n"
        f"expected_btcminer_sha256={soak.HELD_BTCMINER_SHA256}\n"
        "target_set=API,watchdog_thread,watchpool_threa\n"
        f"pass_1_observed_btcminer_sha256={soak.HELD_BTCMINER_SHA256}\n"
        "pass_1_btcminer_hash_admitted=1\n"
        "pass_1_all_targets_nice_zero=1\n"
        "pass_1_target_api_post_nice=0\n"
        "pass_1_target_watchdog_thread_post_nice=0\n"
        "pass_1_target_watchpool_threa_post_nice=0\n"
        "guard_initial_admission=success\n"
    ).encode("ascii")


def priority_state() -> bytes:
    return (
        "initial_pid=100\n"
        f"initial_sha256={soak.HELD_BTCMINER_SHA256}\n"
        "API_count=1\nAPI_tid=101\nAPI_nice=0\n"
        "watchdog_thread_count=1\nwatchdog_thread_tid=102\nwatchdog_thread_nice=0\n"
        "watchpool_threa_count=1\nwatchpool_threa_tid=103\nwatchpool_threa_nice=0\n"
        "final_pid=100\n"
        f"final_sha256={soak.HELD_BTCMINER_SHA256}\n"
    ).encode("ascii")


class SoakFixtureCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = self.root / "payload.bin"
        self.payload.write_bytes(b"bounded-payload\n" * 64)
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text(
            "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnly\n",
            encoding="ascii",
        )
        self.ssh_executable = self.root / "ssh.exe"
        self.ssh_executable.write_bytes(b"fixture ssh executable\n")
        self.scp_executable = self.root / "scp.exe"
        self.scp_executable.write_bytes(b"fixture scp executable\n")
        self.identity_file = self.root / "fixture-key"
        self.identity_file.write_bytes(b"fixture private key material\n")
        self.thermal_contract = self.root / "fixture-thermal-contract.json"
        fixture_contract = soak.stock_telemetry.fixture_contract(
            temperature_pointers=["/stats/STATS/0/Temperature"],
            fan_rpm_pointers=["/devs/DEVS/0/Fan RPM"],
            auto_mode_pointer="/devs/DEVS/0/Fan Mode",
            sensor_sample_epoch_pointer="/stats/STATS/0/Sensor Epoch",
        )
        fixture_contract["target"]["expected_version_fields"] = {
            "CGMiner": "4.11.1",
            "VERSION": "24071801_42c628d",
            "PROD": "Avalon Nano 3 fixture",
        }
        self.thermal_contract.write_bytes(
            soak.stock_telemetry.canonical_json(fixture_contract)
        )
        self.wall_sample = self.root / "wall-sample.json"
        self.manifest_path = self.root / "session.json"
        self.manifest = self.make_manifest()
        self.write_manifest()

    def make_manifest(self, *, live: bool = False) -> dict:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        target = "203.0.113.40" if live else "192.0.2.10"
        session_id = "fixture-session-0001"
        return {
            "schema": soak.SCHEMA,
            "isolated_pool_receipt": {
                "unit_id": "nano3-unit-fixture-0001",
                "nonce": "one-shot-nonce-fixture-0001",
            },
            "session": {
                "id": session_id,
                "disposition": "operator_approved" if live else "fixture_only",
                "operator": "Fixture Operator",
                "authorization_reference": "fixture-auth-ref-0001",
                "approved_at_utc": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                "expires_at_utc": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
                "exact_actions": sorted(soak.REQUIRED_ACTIONS),
                "explicit_exclusions": sorted(soak.REQUIRED_EXCLUSIONS),
                "consumption_marker_path": str((self.root / "consumed.marker").resolve()),
            },
            "target": {
                "ipv4": target,
                "repeat_ipv4": target,
                "btcminer_sha256": soak.HELD_BTCMINER_SHA256,
                "expected_version_fields": {
                    "CGMiner": "4.11.1",
                    "VERSION": "24071801_42c628d",
                    "PROD": "Avalon Nano 3 fixture",
                },
                "api_port": 4028,
                "http_port": 80,
                "ssh_port": 22,
            },
            "isolated_lan": {
                "boundary_record": "fixture isolated boundary record",
                "subnet_cidr": "192.0.2.0/24" if not live else "203.0.113.0/24",
                "operator_controlled": True,
                "only_permitted_hosts_can_reach_4028": True,
                "permitted_host_ipv4": ["192.0.2.20" if not live else "203.0.113.20"],
                "single_serialized_mutation_client": True,
                "receipt_observer_clock_domain": "fixture-host-clock-0001",
            },
            "attended_safety": {
                "operator_at_bench_continuously": True,
                "manual_ac_disconnect_within_arm_reach": True,
                "manual_ac_is_not_independent_or_automatic": True,
                "acknowledges_ac_removes_fan_power": True,
                "external_post_cut_thermal_observation_required": True,
                "post_cut_observation_seconds": 300,
                "stock_fan_remains_auto": True,
                "phase4_excluded": True,
            },
            "guard": {
                "expected_btcminer_sha256": soak.HELD_BTCMINER_SHA256,
                "required_live_comms": list(soak.LIVE_COMMS),
                "required_initial_fields": {
                    "guard_initial_admission": "success",
                    "pass_1_btcminer_hash_admitted": "1",
                    "pass_1_all_targets_nice_zero": "1",
                },
            },
            "timeouts_seconds": {
                "api": {"connect": 1, "read": 2, "total": 4},
                "http": {"connect": 1, "read": 2, "total": 5},
                "ssh": {"connect": 2, "read": 3, "total": 8},
            },
            "probe_cadence_seconds": 60,
            "load": {
                "payload_path": str(self.payload.resolve()),
                "payload_bytes": self.payload.stat().st_size,
                "payload_sha256": soak.sha256_file(self.payload),
                "direction": "host_to_target_tmpfs",
                "concurrency": 1,
                "duration_seconds": 120,
                "per_transfer_total_timeout_seconds": 10,
                "remote_tmpfs_path": f"/tmp/dcent-w1-{session_id}.payload",
                "scp_executable": str(self.scp_executable.resolve()),
                "scp_executable_sha256": soak.sha256_file(self.scp_executable),
                "ssh_executable": str(self.ssh_executable.resolve()),
                "ssh_executable_sha256": soak.sha256_file(self.ssh_executable),
                "ssh_identity_file": str(self.identity_file.resolve()),
                "ssh_identity_file_sha256": soak.sha256_file(self.identity_file),
                "known_hosts_file": str(self.known_hosts.resolve()),
                "known_hosts_sha256": soak.sha256_file(self.known_hosts),
            },
            "thermal_acceptance": {
                "contract_status": "target_capture_reviewed" if live else "fixture_only",
                "contract_receipt_path": str(self.thermal_contract.resolve()),
                "contract_receipt_sha256": soak.sha256_file(self.thermal_contract),
                "engineering_basis": "fixture-only reviewed thermal engineering basis",
                "qualified_limit_reference": "fixture qualification record",
                "stock_90c_pid_target_is_not_a_safety_limit": True,
                "temperature_ceiling_c": 70,
                "max_rise_c_per_minute": 2,
                "telemetry_freshness_seconds": 60,
                "auto_rpm": {
                    "min": 500,
                    "max": 7000,
                    "stock_mode_must_equal_auto": True,
                },
                "temperature_pointers": ["/stats/STATS/0/Temperature"],
                "fan_rpm_pointers": ["/devs/DEVS/0/Fan RPM"],
                "auto_mode_pointer": "/devs/DEVS/0/Fan Mode",
                "sensor_sample_epoch_pointer": "/stats/STATS/0/Sensor Epoch",
            },
            "wall_power_acceptance": {
                "meter_id": "fixture-meter",
                "engineering_basis": "fixture-only reviewed wall-power engineering basis",
                "sample_freshness_seconds": 10,
                "idle_watts": {"min": 5, "max": 30},
                "hashing_watts": {"min": 100, "max": 200},
                "hash_off_watts": {"min": 5, "max": 30},
                "sample_file": str(self.wall_sample.resolve()),
            },
            "load_acceptance": {
                "short_window_pointer": "/SUMMARY/0/MHS 5s",
                "accepted_pointer": "/SUMMARY/0/Accepted",
                "rejected_pointer": "/SUMMARY/0/Rejected",
                "hardware_errors_pointer": "/SUMMARY/0/Hardware Errors",
                "short_window_mhs": {"min": 1000000, "max": 3000000},
                "accepted_min_delta": 1,
                "rejected_max_delta": 0,
                "hardware_errors_max_delta": 0,
                "original_current_pool_must_remain_selected": True,
            },
            "hash_off_proof": {
                "proof_seconds": 120,
                "sample_interval_seconds": 15,
                "short_window_pointer": "/SUMMARY/0/MHS 5s",
                "accepted_pointer": "/SUMMARY/0/Accepted",
                "short_window_mhs_max": 1000,
                "idle_settle_seconds": 30,
                "lcd_is_corroboration_only": True,
                "btcminer_and_telemetry_must_remain_alive": True,
                "lcd_observation_file": str((self.root / "lcd-sample.json").resolve()),
            },
            "cgminer_protocol": {
                "request_framing": "minified_json_plus_one_nul",
                "response_framing": "one_json_object_then_nuls",
                "response_id": 1,
                "max_response_bytes": soak.MAX_RESPONSE_BYTES,
                "dead_pool_parameter": soak.DEAD_POOL_PARAMETER,
                "max_original_pools": 3,
                "hash_off_total_timeout_seconds": 42,
                "restore_total_timeout_seconds": 34,
            },
        }

    def write_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def fixture_document(self) -> dict:
        original = [
            pool(0, 0, "Alive", True, "stratum+tcp://live-a.invalid:3333"),
            pool(1, 1, "Disabled", False, "stratum+tcp://live-b.invalid:3333"),
        ]
        after_add = original + [
            pool(2, 2, "Dead", False, soak.DEAD_POOL_URL),
        ]
        after_add[-1]["User"] = "x"
        hash_off = [
            pool(0, 0, "Disabled", False, "stratum+tcp://live-a.invalid:3333"),
            pool(1, 1, "Disabled", False, "stratum+tcp://live-b.invalid:3333"),
            pool(2, 2, "Dead", False, soak.DEAD_POOL_URL),
        ]
        hash_off[-1]["User"] = "x"
        restored = original
        events = [
            {"operation": "ssh"},
            {
                "operation": "http",
                "response_base64": base64.b64encode(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                ).decode("ascii"),
            },
            api_event(
                "version",
                response(
                    22,
                    "VERSION",
                    [
                        {
                            "CGMiner": "4.11.1",
                            "VERSION": "24071801_42c628d",
                            "PROD": "Avalon Nano 3 fixture",
                        }
                    ],
                ),
            ),
            api_event("summary", response(11, "SUMMARY", [{"MHS 5s": 1, "Accepted": 1}])),
            api_event("stats", response(70, "STATS")),
            api_event("devs", response(9, "DEVS")),
            api_event("pools", response(7, "POOLS", original)),
            api_event(
                "lcd",
                response(
                    125,
                    "LCD",
                    [{"Current Pool": original[0]["URL"], "User": original[0]["User"]}],
                ),
            ),
            api_event("addpool", mutation_response("addpool", 2), soak.DEAD_POOL_PARAMETER),
            api_event("pools", response(7, "POOLS", after_add)),
            api_event("switchpool", mutation_response("switchpool", 2), "2"),
            api_event("disablepool", mutation_response("disablepool", 0), "0"),
            api_event("pools", response(7, "POOLS", hash_off)),
            api_event(
                "lcd",
                response(
                    125,
                    "LCD",
                    [{"Current Pool": soak.DEAD_POOL_URL, "User": "x"}],
                ),
            ),
            api_event("enablepool", mutation_response("enablepool", 0), "0"),
            api_event("switchpool", mutation_response("switchpool", 0), "0"),
            api_event("removepool", mutation_response("removepool", 2), "2"),
            api_event("poolpriority", mutation_response("poolpriority"), "0,1"),
            api_event("pools", response(7, "POOLS", restored)),
            api_event(
                "lcd",
                response(
                    125,
                    "LCD",
                    [{"Current Pool": restored[0]["URL"], "User": restored[0]["User"]}],
                ),
            ),
        ]
        return {
            "guard_receipt_base64": base64.b64encode(guard_receipt()).decode("ascii"),
            "priority_state_base64": base64.b64encode(priority_state()).decode("ascii"),
            "tmpfs_available_bytes": 1024 * 1024,
            "events": events,
        }

    def run_main(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = soak.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()


class OfflineBoundaryTests(SoakFixtureCase):
    def test_default_does_not_open_network_or_spawn(self):
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError), mock.patch.object(
            soak.subprocess, "run", side_effect=AssertionError
        ):
            code, stdout, _ = self.run_main([])
        self.assertEqual(code, 2)
        self.assertIn("usage:", stdout)

    def test_validate_and_plan_are_offline(self):
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError), mock.patch.object(
            soak.subprocess, "run", side_effect=AssertionError
        ):
            code, stdout, _ = self.run_main(
                ["validate", "--manifest", str(self.manifest_path), "--fixture-only"]
            )
            self.assertEqual(code, 0)
            self.assertIn("authority_granted=0", stdout)
            code, stdout, _ = self.run_main(
                ["plan", "--manifest", str(self.manifest_path), "--fixture-only"]
            )
            self.assertEqual(code, 0)
        plan = json.loads(stdout)
        self.assertFalse(plan["phase4_included"])
        self.assertEqual(plan["payload"]["sha256"], soak.sha256_file(self.payload))

    def test_live_missing_literal_arm_refuses_before_network(self):
        self.manifest = self.make_manifest(live=True)
        self.write_manifest()
        manifest_hash = soak.sha256_file(self.manifest_path)
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError), mock.patch.object(
            soak.subprocess, "run", side_effect=AssertionError
        ):
            code, _, stderr = self.run_main(
                [
                    "run",
                    "--manifest",
                    str(self.manifest_path),
                    "--target",
                    "203.0.113.40",
                    "--manifest-sha256",
                    manifest_hash,
                    "--authorization-reference",
                    "fixture-auth-ref-0001",
                    "--evidence-dir",
                    str(self.root / "evidence"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("literal --execute-approved-session", stderr)

    def test_relative_evidence_dir_refuses_before_marker_or_contact(self):
        self.manifest = self.make_manifest(live=True)
        self.write_manifest()
        manifest_hash = soak.sha256_file(self.manifest_path)
        marker = Path(self.manifest["session"]["consumption_marker_path"])
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError), mock.patch.object(
            soak.subprocess, "run", side_effect=AssertionError
        ):
            code, _, stderr = self.run_main(
                [
                    "run",
                    "--manifest",
                    str(self.manifest_path),
                    "--target",
                    "203.0.113.40",
                    "--manifest-sha256",
                    manifest_hash,
                    "--authorization-reference",
                    "fixture-auth-ref-0001",
                    "--evidence-dir",
                    "relative-evidence",
                    "--execute-approved-session",
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("absolute new path", stderr)
        self.assertFalse(marker.exists())

    def test_fixture_mode_never_uses_system_transport(self):
        fixture_path = self.root / "fixture.json"
        fixture_path.write_text(json.dumps(self.fixture_document()), encoding="ascii")
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError), mock.patch.object(
            soak.subprocess, "run", side_effect=AssertionError
        ):
            code, stdout, stderr = self.run_main(
                [
                    "fixture",
                    "--manifest",
                    str(self.manifest_path),
                    "--fixture",
                    str(fixture_path),
                ]
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("network_opened=0", stdout)


class ManifestAdversarialTests(SoakFixtureCase):
    def assert_manifest_refused(self, fragment: str) -> None:
        self.write_manifest()
        code, _, stderr = self.run_main(
            ["validate", "--manifest", str(self.manifest_path), "--fixture-only"]
        )
        self.assertEqual(code, 2)
        self.assertIn(fragment, stderr)

    def test_malformed_json_refused(self):
        self.manifest_path.write_text("{", encoding="ascii")
        code, _, stderr = self.run_main(
            ["validate", "--manifest", str(self.manifest_path), "--fixture-only"]
        )
        self.assertEqual(code, 2)
        self.assertIn("malformed session manifest", stderr)

    def test_missing_exclusion_refused(self):
        self.manifest["session"]["explicit_exclusions"].remove("watchdog_close_probe_phase4")
        self.assert_manifest_refused("mandatory exclusion")

    def test_impossible_untruncated_comm_refused(self):
        self.manifest["guard"]["required_live_comms"][-1] = "watchpool_thread"
        self.assert_manifest_refused("exact live comm")

    def test_cadence_cannot_overlap_serial_probes(self):
        self.manifest["probe_cadence_seconds"] = 10
        self.assert_manifest_refused("serialized hard total timeout")

    def test_load_hash_mismatch_refused(self):
        self.manifest["load"]["payload_sha256"] = "0" * 64
        self.assert_manifest_refused("payload_path SHA-256 mismatch")

    def test_stock_90c_is_not_accepted_as_limit(self):
        self.manifest["thermal_acceptance"]["stock_90c_pid_target_is_not_a_safety_limit"] = False
        self.assert_manifest_refused("stock_90c_pid_target_is_not_a_safety_limit")

    def test_strict_schema_and_malformed_array_types_refused(self):
        self.manifest["unexpected_authority"] = True
        self.assert_manifest_refused("keys mismatch")
        self.manifest = self.make_manifest()
        self.manifest["session"]["exact_actions"][0] = {"action": "target_lan_contact"}
        self.assert_manifest_refused("fixed W1 action set")
        self.manifest = self.make_manifest()
        self.manifest["isolated_lan"]["permitted_host_ipv4"][0] = ["192.0.2.20"]
        self.assert_manifest_refused("must be nonempty")

    def test_nonfinite_manifest_numbers_refused(self):
        self.manifest["thermal_acceptance"]["temperature_ceiling_c"] = float("nan")
        self.write_manifest()
        code, _, stderr = self.run_main(
            ["validate", "--manifest", str(self.manifest_path), "--fixture-only"]
        )
        self.assertEqual(code, 2)
        self.assertIn("non-finite JSON token", stderr)

    def test_transaction_totals_must_fit_telemetry_freshness(self):
        self.manifest["cgminer_protocol"]["hash_off_total_timeout_seconds"] = 61
        self.assert_manifest_refused("telemetry-freshness bound")
        self.manifest = self.make_manifest()
        self.manifest["cgminer_protocol"]["restore_total_timeout_seconds"] = 61
        self.assert_manifest_refused("telemetry-freshness bound")

    def test_hashoff_sample_schedule_and_load_duration_must_be_possible(self):
        self.manifest["hash_off_proof"]["sample_interval_seconds"] = 11
        self.assert_manifest_refused("three API total bounds")
        self.manifest = self.make_manifest()
        self.manifest["load"]["duration_seconds"] = 60
        self.assert_manifest_refused("two nonoverlapping")

    def test_duplicate_thermal_pointer_refused(self):
        pointer = self.manifest["thermal_acceptance"]["temperature_pointers"][0]
        self.manifest["thermal_acceptance"]["temperature_pointers"].append(pointer)
        self.assert_manifest_refused("must be unique")

    def test_non_rfc1918_live_targets_refused(self):
        for target in ("127.0.0.1", "169.254.1.1", "192.0.2.1", "0.0.0.1", "240.0.0.1"):
            with self.subTest(target=target):
                self.manifest = self.make_manifest(live=True)
                self.manifest["target"]["ipv4"] = target
                self.manifest["target"]["repeat_ipv4"] = target
                self.write_manifest()
                code, _, stderr = self.run_main(
                    ["validate", "--manifest", str(self.manifest_path)]
                )
                self.assertEqual(code, 2)
                self.assertNotEqual(stderr, "")

    def test_pinned_inputs_reject_directory_symlink_and_oversize(self):
        self.manifest["load"]["payload_path"] = str(self.root.resolve())
        self.assert_manifest_refused("non-symlink regular file")
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"{" + b" " * soak.MAX_LOCAL_JSON_BYTES + b"}")
        with self.assertRaises(soak.ManifestError):
            soak.load_json_object(oversized, "oversized")
        link = self.root / "payload-link.bin"
        try:
            os.symlink(self.payload, link)
        except (OSError, NotImplementedError):
            return
        self.manifest = self.make_manifest()
        self.manifest["load"]["payload_path"] = str(link.resolve(strict=False))
        # resolve() would erase the symlink identity, so use the absolute link spelling.
        self.manifest["load"]["payload_path"] = str(link.absolute())
        self.assert_manifest_refused("non-symlink regular file")

    def test_session_consumption_is_atomic_and_one_shot(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        soak.consume_session_marker(manifest)
        with self.assertRaisesRegex(soak.ManifestError, "already been consumed"):
            soak.consume_session_marker(manifest)

    def test_post_validation_input_replacement_is_detected(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        self.payload.write_bytes(b"replacement")
        with self.assertRaisesRegex(soak.ManifestError, "byte count mismatch"):
            soak.revalidate_approved_local_inputs(manifest)


class ProtocolAdversarialTests(SoakFixtureCase):
    def test_truncation_wrong_id_multiple_status_and_trailer_rejected(self):
        valid = response(11, "SUMMARY")
        bad_values = [
            valid.rstrip(b"\x00"),
            valid.replace(b'"id":1', b'"id":0'),
            valid.replace(b'"STATUS":[', b'"STATUS":[{"STATUS":"S","Code":11},'),
            valid + b"garbage",
        ]
        for raw in bad_values:
            with self.subTest(raw=raw[-20:]), self.assertRaises(soak.ProtocolError):
                soak.decode_response(raw, 11, "SUMMARY")

    def test_duplicate_keys_and_float_identity_fields_rejected(self):
        duplicate = (
            b'{"STATUS":[{"STATUS":"S","Code":11,"When":1}],'
            b'"id":1,"id":1,"SUMMARY":[{}]}\x00'
        )
        float_id = response(11, "SUMMARY").replace(b'"id":1', b'"id":1.0')
        float_code = response(11, "SUMMARY").replace(b'"Code":11', b'"Code":11.0')
        float_when = response(11, "SUMMARY").replace(b'"When":1', b'"When":1.0')
        for raw in (duplicate, float_id, float_code, float_when):
            with self.subTest(raw=raw), self.assertRaises(soak.ProtocolError):
                soak.decode_response(raw, 11, "SUMMARY")

    def test_error_status_and_wrong_code_rejected(self):
        with self.assertRaises(soak.ProtocolError):
            soak.decode_response(response(11, "SUMMARY", STATUS="E"), 11, "SUMMARY")
        with self.assertRaises(soak.ProtocolError):
            soak.decode_response(response(7, "SUMMARY"), 11, "SUMMARY")

    def test_nonfinite_cgminer_and_wall_values_rejected(self):
        raw = b'{"STATUS":[{"STATUS":"S","Code":11}],"id":1,"SUMMARY":[{"MHS 5s":NaN}]}\x00'
        with self.assertRaises(soak.ProtocolError):
            soak.decode_response(raw, 11, "SUMMARY")
        captured = datetime.now(timezone.utc).replace(microsecond=0)
        self.wall_sample.write_text(
            json.dumps(
                {
                    "schema": soak.ISOLATED_POOL_WALL_SCHEMA,
                    "purpose": soak.ISOLATED_POOL_PURPOSE,
                    "session_id": self.manifest["session"]["id"],
                    "unit_id": self.manifest["isolated_pool_receipt"]["unit_id"],
                    "nonce": self.manifest["isolated_pool_receipt"]["nonce"],
                    "meter_id": "fixture-meter",
                    "captured_at_utc": captured.isoformat().replace("+00:00", "Z"),
                    "clock_domain": self.manifest["isolated_lan"][
                        "receipt_observer_clock_domain"
                    ],
                    "captured_monotonic_ns": 100,
                    "watts": float("inf"),
                }
            ),
            encoding="ascii",
        )
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        with self.assertRaises(soak.SoakError):
            soak.read_wall_watts(manifest, None)

    def test_http_requires_complete_exact_content_length_framing(self):
        valid = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest"
        soak.verify_http_response(valid)
        bad = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nte",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ntest",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\ntest",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\ntest",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\ntrailing",
            b"HTTP/1.1 200 OK\r\nX-Fill: "
            + b"a" * soak.MAX_HTTP_HEADER_BYTES
            + b"\r\nContent-Length: 0\r\n\r\n",
        ]
        for raw in bad:
            with self.subTest(length=len(raw)), self.assertRaises(soak.ProtocolError):
                soak.verify_http_response(raw)

    def test_split_tcp_trailer_after_first_nul_is_read_and_rejected(self):
        first = response(11, "SUMMARY")

        class FakeSocket:
            def __init__(self) -> None:
                self.chunks = [first, b'{"second":"reply"}\x00', b""]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _value):
                pass

            def sendall(self, _request):
                pass

            def recv(self, _size):
                return self.chunks.pop(0)

        transport = soak.SystemTransport.__new__(soak.SystemTransport)
        transport.target = "192.0.2.10"
        with mock.patch.object(socket, "create_connection", return_value=FakeSocket()):
            raw = transport._socket_exchange(
                4028, soak.encode_request("summary"), soak.Timeouts(1, 1, 2)
            )
        with self.assertRaisesRegex(soak.ProtocolError, "Non-NUL|non-NUL"):
            soak.decode_response(raw, 11, "SUMMARY")

    def test_fixed_ssh_stdout_is_bounded_and_stderr_discarded(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        transport = soak.SystemTransport(manifest)
        completed = mock.Mock(returncode=0, stdout=b"x" * (soak.MAX_SSH_STDOUT_BYTES + 1))
        with mock.patch.object(soak.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(soak.TransportError, "stdout exceeds"):
                transport._run_ssh("true")
        self.assertIs(run.call_args.kwargs["stderr"], soak.subprocess.DEVNULL)

    def test_scp_worker_discards_stdout_and_stderr(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        journal = soak.EvidenceJournal(self.root / "scp-output-journal", manifest)
        worker = soak.LoadWorkers(manifest, journal)
        completed = mock.Mock(returncode=1)
        with mock.patch.object(soak.subprocess, "run", return_value=completed) as run:
            worker._worker(0)
        self.assertIs(run.call_args.kwargs["stdout"], soak.subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stderr"], soak.subprocess.DEVNULL)

    def test_version_fields_bind_exact_target_identity(self):
        parsed = soak.decode_response(
            response(
                22,
                "VERSION",
                [{"CGMiner": "4.11.1", "VERSION": "wrong", "PROD": "Nano"}],
            ),
            22,
            "VERSION",
        )
        with self.assertRaisesRegex(soak.ProtocolError, "VERSION identity mismatch"):
            soak.verify_version_identity(
                parsed,
                {"CGMiner": "4.11.1", "VERSION": "held", "PROD": "Nano"},
            )

    def test_independent_priority_state_requires_one_exact_tid_each(self):
        soak.verify_priority_state(priority_state())
        with self.assertRaises(soak.ProtocolError):
            soak.verify_priority_state(
                priority_state().replace(b"watchpool_threa_count=1", b"watchpool_threa_count=2")
            )

    def test_mutation_ack_must_bind_requested_pool_id(self):
        parsed = soak.decode_response(
            mutation_response("switchpool", 2), soak.MUTATION_CODES["switchpool"]
        )
        with self.assertRaises(soak.ProtocolError):
            soak.verify_mutation_ack("switchpool", "1", parsed)

    def test_duplicate_pool_id_or_priority_rejected(self):
        duplicates = [
            [pool(0, 0, "Alive", True, "a"), pool(0, 1, "Dead", False, "b")],
            [pool(0, 0, "Alive", True, "a"), pool(1, 0, "Dead", False, "b")],
        ]
        for pools in duplicates:
            parsed = soak.decode_response(response(7, "POOLS", pools), 7, "POOLS")
            with self.assertRaises(soak.ProtocolError):
                soak.parse_pools(parsed)

    def test_guard_requires_truncated_live_name_and_pass1(self):
        raw = guard_receipt().replace(b"watchpool_threa", b"watchpool_thread")
        with self.assertRaises(soak.ProtocolError):
            soak.verify_guard_receipt(raw)

    def test_wall_sample_requires_fresh_unique_meter_receipt(self):
        captured = datetime.now(timezone.utc).replace(microsecond=0)
        self.wall_sample.write_text(
            json.dumps(
                {
                    "schema": soak.ISOLATED_POOL_WALL_SCHEMA,
                    "purpose": soak.ISOLATED_POOL_PURPOSE,
                    "session_id": self.manifest["session"]["id"],
                    "unit_id": self.manifest["isolated_pool_receipt"]["unit_id"],
                    "nonce": self.manifest["isolated_pool_receipt"]["nonce"],
                    "meter_id": "fixture-meter",
                    "captured_at_utc": captured.isoformat().replace("+00:00", "Z"),
                    "clock_domain": self.manifest["isolated_lan"][
                        "receipt_observer_clock_domain"
                    ],
                    "captured_monotonic_ns": time.monotonic_ns(),
                    "watts": 150.5,
                }
            ),
            encoding="ascii",
        )
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        watts, sample_id = soak.read_wall_watts(manifest, None)
        self.assertEqual(watts, 150.5)
        self.assertRegex(sample_id, r"^[0-9a-f]{64}$")
        with self.assertRaises(soak.ProtocolError):
            soak.read_wall_watts(manifest, sample_id)

    def test_thermal_sample_checks_epoch_auto_rpm_ceiling_and_trend(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        epoch = datetime.now(timezone.utc).timestamp()
        stats = soak.decode_response(
            response(70, "STATS", [{"Temperature": 60.0, "Sensor Epoch": epoch}]),
            70,
            "STATS",
        )
        devs = soak.decode_response(
            response(9, "DEVS", [{"Fan RPM": 2000, "Fan Mode": "AUTO"}]),
            9,
            "DEVS",
        )
        first = soak.verify_thermal_sample(manifest, stats, devs, None)
        self.assertEqual(first[1], 60.0)
        bad_devs = soak.decode_response(
            response(9, "DEVS", [{"Fan RPM": 2000, "Fan Mode": "FIXED"}]),
            9,
            "DEVS",
        )
        with self.assertRaises(soak.ProtocolError):
            soak.verify_thermal_sample(manifest, stats, bad_devs, None)

    def test_load_acceptance_requires_hashrate_progress_and_error_bounds(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        good = soak.decode_response(
            response(
                11,
                "SUMMARY",
                [{"MHS 5s": 2_000_000, "Accepted": 11, "Rejected": 2, "Hardware Errors": 3}],
            ),
            11,
            "SUMMARY",
        )
        values = soak.load_summary_values(manifest, good)
        soak.verify_load_progress(manifest, (2_000_000, 10, 2, 3), values, final=True)
        with self.assertRaisesRegex(soak.ProtocolError, "Accepted counter"):
            soak.verify_load_progress(manifest, values, values, final=True)
        with self.assertRaisesRegex(soak.ProtocolError, "Rejected delta"):
            soak.verify_load_progress(
                manifest, (2_000_000, 10, 1, 3), values, final=False
            )

    def test_public_journal_never_contains_pool_credentials_or_target(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        journal = soak.EvidenceJournal(self.root / "journal", manifest)
        raw = response(
            7,
            "POOLS",
            [pool(0, 0, "Alive", True, "stratum+tcp://secret.pool:3333")],
        )
        journal.record_raw("cgminer-pools", soak.encode_request("pools"), raw)
        journal.finish("FIXTURE", "TEST_ONLY")
        public = (journal.root / "public-journal.json").read_text(encoding="ascii")
        protected = (journal.protected / "0001-cgminer-pools.bin").read_text(
            encoding="ascii"
        )
        self.assertNotIn("secret.pool", public)
        self.assertNotIn(manifest.target, public)
        self.assertIn("secret.pool", protected)
        raw = guard_receipt().replace(b"guard_initial_admission=success\n", b"")
        with self.assertRaises(soak.ProtocolError):
            soak.verify_guard_receipt(raw)

    def test_public_failure_reason_is_sanitized_and_detail_is_protected(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        journal = soak.EvidenceJournal(self.root / "failure-journal", manifest)
        secret_path = str(self.root / "secret-observation.json")
        journal.write_failure_detail(OSError(secret_path))
        journal.finish("FAIL", "SAFE_CODE_ONLY")
        public = (journal.root / "public-journal.json").read_text(encoding="ascii")
        protected = (journal.protected / "failure-detail.json").read_text(encoding="ascii")
        self.assertNotIn(secret_path, public)
        self.assertIn(secret_path.replace("\\", "\\\\"), protected)
        with self.assertRaises(soak.SoakError):
            soak.EvidenceJournal(self.root / "bad-reason", manifest).finish(
                "FAIL", secret_path
            )

    def test_api_intent_ack_and_invalid_mutation_custody_are_durable(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)

        class MutationTransport:
            def __init__(self, raw: bytes) -> None:
                self.raw = raw

            def api(self, _command, _parameter=None):
                return self.raw

        journal = soak.EvidenceJournal(self.root / "api-journal", manifest)
        parsed = soak._api_call(
            MutationTransport(mutation_response("switchpool", 2)),
            journal,
            "switchpool",
            "2",
            phase="hash_off",
        )
        self.assertEqual(parsed.connection_id, 1)
        lines = [
            json.loads(line)
            for line in (journal.protected / "api-events.jsonl")
            .read_text(encoding="ascii")
            .splitlines()
        ]
        self.assertEqual(
            [item["stage"] for item in lines],
            [
                "intent_before_send",
                "response_received_before_validation",
                "acknowledged_after_validated_response",
            ],
        )

        invalid = soak.EvidenceJournal(self.root / "invalid-ack-journal", manifest)
        with self.assertRaises(soak.ApiPlaneError):
            soak._api_call(
                MutationTransport(
                    response(soak.MUTATION_CODES["switchpool"], Msg="wrong ack")
                ),
                invalid,
                "switchpool",
                "2",
                phase="hash_off",
            )
        self.assertTrue(invalid.mutation_effect_unknown)
        self.assertEqual(invalid.api_pending, {})
        self.assertEqual(len(invalid.api_failures), 1)
        invalid.finish("FAIL_MANUAL_AC_REQUIRED", "MUTATION_ACK_INVALID")
        fragment = json.loads(
            (invalid.protected / "runner-pool-evidence.json").read_text(
                encoding="ascii"
            )
        )
        public = json.loads(
            (invalid.root / "public-journal.json").read_text(encoding="ascii")
        )
        self.assertTrue(fragment["mutation_effect_unknown"])
        self.assertEqual(
            fragment["transaction_outcome"],
            "partial_mutation_unknown_or_unrestored",
        )
        self.assertTrue(public["mutation_effect_unknown"])
        self.assertNotIn("target_ipv4_sha256", public)

    def test_ack_journal_failure_preserves_pending_mutation_unknown(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        journal = soak.EvidenceJournal(self.root / "ack-failure-journal", manifest)

        class MutationTransport:
            def api(self, _command, _parameter=None):
                return mutation_response("disablepool", 0)

        original_append = journal._append_api_event

        def fail_ack(document):
            if document.get("stage") == "acknowledged_after_validated_response":
                raise OSError("injected durable ack failure")
            original_append(document)

        with mock.patch.object(journal, "_append_api_event", side_effect=fail_ack):
            with self.assertRaisesRegex(soak.ApiPlaneError, "acknowledgement custody"):
                soak._api_call(
                    MutationTransport(),
                    journal,
                    "disablepool",
                    "0",
                    phase="hash_off",
                )
        self.assertTrue(journal.mutation_effect_unknown)
        self.assertEqual(list(journal.api_pending), ["api-0001"])
        journal.finish("FAIL_MANUAL_AC_REQUIRED", "ACK_CUSTODY_FAILED")
        fragment = json.loads(
            (journal.protected / "runner-pool-evidence.json").read_text(
                encoding="ascii"
            )
        )
        self.assertEqual(fragment["pending_intents"][0]["command"], "disablepool")
        self.assertEqual(
            fragment["transaction_outcome"],
            "partial_mutation_unknown_or_unrestored",
        )

    def test_protected_first_creation_short_write_and_directory_fsync(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        observed_fsyncs: list[Path] = []
        original_fsync_directory = soak.fsync_directory

        def observe_fsync(path: Path) -> None:
            observed_fsyncs.append(path)
            original_fsync_directory(path)

        root = self.root / "durable-journal"
        with mock.patch.object(
            soak, "fsync_directory", side_effect=observe_fsync
        ):
            journal = soak.EvidenceJournal(root, manifest)
        self.assertLess(
            observed_fsyncs.index(root), observed_fsyncs.index(root / "protected")
        )
        real_write = os.write

        def short_write(descriptor: int, raw: bytes) -> int:
            return real_write(descriptor, raw[: max(1, len(raw) // 2)])

        with mock.patch.object(os, "write", side_effect=short_write):
            journal.write_protected_bytes("short-write-proof.bin", b"x" * 257)
        self.assertEqual(
            (journal.protected / "short-write-proof.bin").read_bytes(), b"x" * 257
        )


class FixtureFailureTests(SoakFixtureCase):
    def run_fixture_doc(self, document: dict) -> tuple[int, str]:
        path = self.root / "adversarial-fixture.json"
        path.write_text(json.dumps(document), encoding="ascii")
        code, _, stderr = self.run_main(
            ["fixture", "--manifest", str(self.manifest_path), "--fixture", str(path)]
        )
        return code, stderr

    def test_timeout_stall_and_failure_stop(self):
        for failure in ("connect_timeout", "read_timeout", "total_timeout", "stall", "failure"):
            fixture = self.fixture_document()
            fixture["events"][0] = {"operation": "ssh", "failure": failure}
            code, stderr = self.run_fixture_doc(fixture)
            self.assertEqual(code, 2)
            self.assertIn(failure, stderr)

    def test_malformed_fixture_base64_refuses_without_traceback(self):
        fixture = self.fixture_document()
        fixture["events"][1]["response_base64"] = "%%%"
        code, stderr = self.run_fixture_doc(fixture)
        self.assertEqual(code, 2)
        self.assertIn("strict base64", stderr)

    def test_partial_hashoff_transaction_stops(self):
        fixture = self.fixture_document()
        disable = next(
            event
            for event in fixture["events"]
            if event.get("command") == "disablepool"
        )
        disable.pop("response_base64")
        disable["failure"] = "read_timeout"
        code, stderr = self.run_fixture_doc(fixture)
        self.assertEqual(code, 2)
        self.assertIn("read_timeout", stderr)

    def test_restore_mismatch_stops(self):
        fixture = self.fixture_document()
        final = [
            event
            for event in fixture["events"]
            if event.get("command") == "pools"
        ][-1]
        wrong = [
            pool(0, 1, "Alive", True, "stratum+tcp://live-a.invalid:3333"),
            pool(1, 0, "Disabled", False, "stratum+tcp://live-b.invalid:3333"),
        ]
        final["response_base64"] = base64.b64encode(response(7, "POOLS", wrong)).decode("ascii")
        code, stderr = self.run_fixture_doc(fixture)
        self.assertEqual(code, 2)
        self.assertIn("restored pool", stderr)

    def test_ambiguous_new_pool_id_stops(self):
        fixture = self.fixture_document()
        after_add = next(
            event
            for index, event in enumerate(fixture["events"])
            if event.get("command") == "pools" and index > 6
        )
        ambiguous = [
            pool(0, 0, "Alive", True, "a"),
            pool(1, 1, "Disabled", False, "b"),
            pool(2, 2, "Dead", False, soak.DEAD_POOL_URL),
            pool(3, 3, "Dead", False, soak.DEAD_POOL_URL),
        ]
        after_add["response_base64"] = base64.b64encode(
            response(7, "POOLS", ambiguous)
        ).decode("ascii")
        code, stderr = self.run_fixture_doc(fixture)
        self.assertEqual(code, 2)
        self.assertIn("exactly one resolvable", stderr)

    def test_initial_pool_cardinality_is_bounded(self):
        fixture = self.fixture_document()
        first_pools = next(
            event for event in fixture["events"] if event.get("command") == "pools"
        )
        too_many = [
            pool(
                index,
                index,
                "Alive" if index == 0 else "Disabled",
                index == 0,
                "stratum+tcp://live-a.invalid:3333" if index == 0 else f"pool-{index}",
            )
            for index in range(4)
        ]
        first_pools["response_base64"] = base64.b64encode(
            response(7, "POOLS", too_many)
        ).decode("ascii")
        code, stderr = self.run_fixture_doc(fixture)
        self.assertEqual(code, 2)
        self.assertIn("transaction maximum", stderr)

    def test_pool_state_drift_before_mutation_is_rejected(self):
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        transport = soak.FixtureTransport(self.fixture_document())
        soak.verify_basic_planes(transport, None, manifest)
        expected = [
            soak.PoolState(0, 1, True, True),
            soak.PoolState(1, 0, False, False),
        ]
        with self.assertRaisesRegex(soak.ProtocolError, "state drifted"):
            soak.hash_off_transaction(
                transport,
                None,
                manifest,
                expected_original=expected,
                expected_active=0,
            )


class AbortSafetyTests(SoakFixtureCase):
    def _execute_with_start_failure(self, failure: BaseException) -> tuple[list[str], int, str]:
        manifest = soak.validate_manifest(self.manifest_path, live=False)
        events: list[str] = []

        class FakeTransport:
            def pool_config_digest(self) -> str:
                return soak.sha256_bytes(b"fixture config")

            def pool_config_bytes(self) -> bytes:
                return b"fixture config"

        class FakeWorkers:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def start(self) -> None:
                raise failure

            def request_stop(self) -> None:
                events.append("stop")

            def reap(self, *, require_completed_transfer: bool) -> None:
                self.require_completed_transfer = require_completed_transfer
                events.append("reap")

        pools_document = {
            "POOLS": [pool(0, 0, "Alive", True, "stratum+tcp://fixture:1")]
        }
        pools_response = soak.ParsedResponse(pools_document, "b" * 64, 1, 7)
        parsed = soak.ParsedResponse({}, "c" * 64, 1, 11)

        def fake_api(_transport, _journal, command, parameter=None):
            del command, parameter
            return parsed

        def fake_hash_off(*_args, **_kwargs):
            events.append("hash_off")
            return [soak.PoolState(0, 0, True, True)], 0, 1

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(soak, "SystemTransport", return_value=FakeTransport()),
            mock.patch.object(soak, "verify_basic_planes"),
            mock.patch.object(
                soak,
                "capture_original_pool_state",
                return_value=([soak.PoolState(0, 0, True, True)], 0, pools_response),
            ),
            mock.patch.object(soak, "read_wall_watts", return_value=(150.0, "sample-0001")),
            mock.patch.object(soak, "require_envelope"),
            mock.patch.object(soak, "_api_call", side_effect=fake_api),
            mock.patch.object(soak, "load_summary_values", return_value=(2_000_000, 10, 0, 0)),
            mock.patch.object(soak, "verify_thermal_sample", return_value=(1.0, 50.0)),
            mock.patch.object(soak, "LoadWorkers", FakeWorkers),
            mock.patch.object(soak, "hash_off_transaction", side_effect=fake_hash_off),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = soak.execute_live(manifest, self.root / f"evidence-{type(failure).__name__}")
        return events, code, stderr.getvalue()

    def test_oserror_and_keyboard_interrupt_route_through_cut_before_reap(self):
        for failure in (OSError("fixture failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                events, code, stderr = self._execute_with_start_failure(failure)
                self.assertEqual(code, 1)
                self.assertEqual(events, ["stop", "hash_off", "reap"])
                self.assertIn("HASH_OFF_ACKNOWLEDGED", stderr)

    def test_api_plane_failure_routes_directly_to_manual_ac_before_reap(self):
        events, code, stderr = self._execute_with_start_failure(
            soak.ApiPlaneError("fixture API ambiguity")
        )
        self.assertEqual(code, 1)
        self.assertEqual(events, ["stop", "reap"])
        self.assertIn("MANUAL_AC_DISCONNECT_NOW", stderr)

    def test_manual_ac_decision_precedes_reap_when_hashoff_fails(self):
        order: list[str] = []

        class Worker:
            def request_stop(self) -> None:
                order.append("stop")

            def reap(self, *, require_completed_transfer: bool) -> None:
                del require_completed_transfer
                order.append("reap")

        soak.stop_load_then_safety_action_then_reap(
            Worker(), lambda: order.append("manual_ac_or_cut")
        )
        self.assertEqual(order, ["stop", "manual_ac_or_cut", "reap"])


if __name__ == "__main__":
    unittest.main()
