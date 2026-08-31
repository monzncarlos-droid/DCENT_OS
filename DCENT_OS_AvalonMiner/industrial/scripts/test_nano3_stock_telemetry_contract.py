#!/usr/bin/env python3
"""Offline adversarial tests for the stock Nano 3 telemetry contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("nano3_stock_telemetry_contract.py")
SPEC = importlib.util.spec_from_file_location("nano3_stock_telemetry_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
telemetry = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = telemetry
SPEC.loader.exec_module(telemetry)


def response(command: str, payload: list[dict], *, when: int = 1) -> bytes:
    document = {
        "STATUS": [
            {
                "STATUS": "S",
                "Code": telemetry.READ_CODES[command],
                "When": when,
                "Msg": "fixture",
            }
        ],
        telemetry.PAYLOAD_KEYS[command]: payload,
        "id": 1,
    }
    return json.dumps(document, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\x00"


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bundle_path = self.root / "bundle.json"
        self.version_fields = {
            "CGMiner": "4.11.1",
            "VERSION": "24071801_42c628d",
            "PROD": "Avalon Nano 3",
        }
        self.payloads = {
            "version": [dict(self.version_fields)],
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
        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        self.write_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_bundle(self, provenance: str) -> dict:
        identity_receipt = self.root / "identity-receipt.json"
        identity_receipt.write_text('{"unsigned_fixture_identity":true}\n', encoding="ascii")
        capture_receipt = self.root / "capture-receipt.json"
        capture_receipt.write_text('{"unsigned_fixture_capture":true}\n', encoding="ascii")
        records = []
        for sequence, (round_number, command) in enumerate(
            telemetry.EXPECTED_CAPTURE_SEQUENCE, 1
        ):
            raw = response(command, self.payloads[command], when=sequence)
            path = self.root / f"{sequence:02d}-r{round_number}-{command}.bin"
            path.write_bytes(raw)
            request = telemetry.encode_request(command)
            records.append(
                {
                    "sequence": sequence,
                    "round": round_number,
                    "command": command,
                    "captured_at_utc": f"2026-08-24T12:00:{sequence:02d}Z",
                    "request_bytes": len(request),
                    "request_sha256": telemetry.sha256_bytes(request),
                    "response_path": path.name,
                    "response_bytes": len(raw),
                    "response_sha256": telemetry.sha256_bytes(raw),
                }
            )
        return {
            "schema": telemetry.SOURCE_SCHEMA,
            "purpose": telemetry.PURPOSE,
            "bundle_id": "stock-capture-fixture-0001",
            "provenance": provenance,
            "target": {
                "model": telemetry.TARGET_MODEL,
                "btcminer_sha256": telemetry.HELD_BTCMINER_SHA256,
                "expected_version_fields": dict(self.version_fields),
                "identity_receipt_path": identity_receipt.name,
                "identity_receipt_sha256": telemetry.sha256_bytes(
                    identity_receipt.read_bytes()
                ),
            },
            "capture": {
                "capture_id": "stock-capture-fixture-0001",
                "started_at_utc": "2026-08-24T12:00:00Z",
                "ended_at_utc": "2026-08-24T12:00:12Z",
                "one_connection_per_command": True,
                "request_framing": "minified_json_plus_one_nul",
                "response_framing": "one_json_object_then_nuls_read_to_eof",
                "raw_response_bytes_retained": True,
                "capture_receipt_path": capture_receipt.name,
                "capture_receipt_sha256": telemetry.sha256_bytes(
                    capture_receipt.read_bytes()
                ),
            },
            "responses": records,
        }

    def write_bundle(self) -> None:
        self.bundle_path.write_bytes(telemetry.canonical_json(self.bundle))

    def replace_response(self, command: str, raw: bytes, *, round_number: int = 1) -> None:
        record = next(
            item
            for item in self.bundle["responses"]
            if item["command"] == command and item["round"] == round_number
        )
        path = self.root / record["response_path"]
        path.write_bytes(raw)
        record["response_bytes"] = len(raw)
        record["response_sha256"] = telemetry.sha256_bytes(raw)
        self.write_bundle()

    def assert_compile_refused(self, fragment: str) -> None:
        self.write_bundle()
        with self.assertRaisesRegex(telemetry.ContractError, fragment):
            telemetry.compile_bundle(self.bundle_path)

    def test_unsigned_raw_fields_are_observed_but_never_promoted(self):
        contract = telemetry.compile_bundle(self.bundle_path)
        capabilities = contract["capabilities"]
        self.assertFalse(any(capabilities.values()))
        observed = contract["observed_fields_non_load_bearing"]
        self.assertTrue(observed["summary_mhs_5s"])
        self.assertTrue(observed["stats_mm_id0_required_field_tokens"])
        self.assertFalse(contract["soak_runtime_ready"])
        with self.assertRaisesRegex(telemetry.ContractError, "cannot authorize live use"):
            telemetry.validate_contract_document(contract, live=True)

    def test_response_times_must_be_inside_capture_window(self):
        self.bundle["responses"][0]["captured_at_utc"] = "2026-08-24T11:59:59Z"
        self.assert_compile_refused("outside the declared capture window")

        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        self.bundle["responses"][-1]["captured_at_utc"] = "2026-08-24T12:00:13Z"
        self.assert_compile_refused("outside the declared capture window")

    def test_identical_static_response_bytes_across_rounds_are_permitted(self):
        first = next(
            item
            for item in self.bundle["responses"]
            if item["round"] == 1 and item["command"] == "version"
        )
        second = next(
            item
            for item in self.bundle["responses"]
            if item["round"] == 2 and item["command"] == "version"
        )
        raw = (self.root / first["response_path"]).read_bytes()
        (self.root / second["response_path"]).write_bytes(raw)
        second["response_bytes"] = len(raw)
        second["response_sha256"] = telemetry.sha256_bytes(raw)
        self.write_bundle()
        contract = telemetry.compile_bundle(self.bundle_path)
        version_hashes = [
            item["response_sha256"]
            for item in contract["source_responses"]
            if item["command"] == "version"
        ]
        self.assertEqual(version_hashes[0], version_hashes[1])

    def test_synthetic_fixture_never_promotes_live_capabilities(self):
        self.bundle = self.make_bundle("synthetic_fixture")
        self.write_bundle()
        contract = telemetry.compile_bundle(self.bundle_path)
        self.assertFalse(any(contract["capabilities"].values()))
        self.assertEqual(contract["provenance"], "synthetic_fixture")
        with self.assertRaisesRegex(telemetry.ContractError, "fixture/prose"):
            telemetry.validate_contract_document(contract, live=True)

    def test_duplicate_json_keys_and_nonfinite_values_are_refused(self):
        raw = (
            b'{"STATUS":[{"STATUS":"S","Code":11,"When":1,"Msg":"x"}],'
            b'"SUMMARY":[{"MHS 5s":1,"MHS 5s":2,"Accepted":1,"Rejected":0,'
            b'"Hardware Errors":0}],"id":1}\x00'
        )
        self.replace_response("summary", raw)
        with self.assertRaisesRegex(telemetry.ContractError, "duplicate JSON"):
            telemetry.compile_bundle(self.bundle_path)

        raw = (
            b'{"STATUS":[{"STATUS":"S","Code":11,"When":1,"Msg":"x"}],'
            b'"SUMMARY":[{"MHS 5s":NaN,"Accepted":1,"Rejected":0,'
            b'"Hardware Errors":0}],"id":1}\x00'
        )
        self.replace_response("summary", raw)
        with self.assertRaisesRegex(telemetry.ContractError, "non-finite"):
            telemetry.compile_bundle(self.bundle_path)

    def test_wrong_command_id_code_and_split_trailer_are_refused(self):
        self.bundle["responses"][0]["command"] = "summary"
        self.assert_compile_refused("duplicated|order")

        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        raw = response("summary", self.payloads["summary"]).replace(b'"id":1', b'"id":1.0')
        self.replace_response("summary", raw)
        with self.assertRaisesRegex(telemetry.ContractError, "id must be exact integer"):
            telemetry.compile_bundle(self.bundle_path)

        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        raw = response("summary", self.payloads["summary"]) + b"TRAILER"
        self.replace_response("summary", raw)
        with self.assertRaisesRegex(telemetry.ContractError, "followed only by NULs"):
            telemetry.compile_bundle(self.bundle_path)

    def test_source_hash_size_schema_and_target_binding_are_refused(self):
        self.bundle["responses"][0]["response_sha256"] = "f" * 64
        self.assert_compile_refused("SHA-256 mismatch")
        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        self.bundle["responses"][0]["response_bytes"] += 1
        self.assert_compile_refused("byte count mismatch")
        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        self.bundle["schema"] = "wrong"
        self.assert_compile_refused("schema/purpose")
        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        self.bundle["target"]["btcminer_sha256"] = "a" * 64
        self.assert_compile_refused("target/btcminer")

    def test_version_response_must_bind_exact_target(self):
        wrong = copy.deepcopy(self.payloads["version"])
        wrong[0]["VERSION"] = "wrong"
        self.replace_response("version", response("version", wrong))
        with self.assertRaisesRegex(telemetry.ContractError, "VERSION fields"):
            telemetry.compile_bundle(self.bundle_path)

    def test_unit_ambiguity_and_missing_sensor_coverage_are_refused_or_blocked(self):
        stats = copy.deepcopy(self.payloads["stats"])
        stats[0]["MM ID0"] = stats[0]["MM ID0"].replace("FanR[25%]", "FanR[25]")
        self.replace_response("stats", response("stats", stats))
        with self.assertRaisesRegex(telemetry.ContractError, "ambiguous/non-percent units"):
            telemetry.compile_bundle(self.bundle_path)

        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        stats = copy.deepcopy(self.payloads["stats"])
        stats[0]["MM ID0"] = stats[0]["MM ID0"].replace(" OTemp[34]", "")
        self.replace_response("stats", response("stats", stats))
        contract = telemetry.compile_bundle(self.bundle_path)
        self.assertFalse(
            contract["observed_fields_non_load_bearing"][
                "stats_mm_id0_required_field_tokens"
            ]
        )
        self.assertIn(
            "raw_stats_missing_required_board_die_or_fan_fields", contract["blockers"]
        )

    def test_mm_parser_rejects_duplicate_truncated_nested_and_junk(self):
        for value, fragment in (
            ("Temp[30] Temp[31]", "duplicate"),
            ("Temp[30", "truncated"),
            ("Temp[[30]]", "truncated or nested"),
            ("junk Temp[30]", "key is not exact"),
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(telemetry.ContractError, fragment):
                    telemetry.parse_mm_status(value)

    def test_response_integer_types_and_structural_bounds_are_exact(self):
        raw = response("summary", self.payloads["summary"]).replace(b'"Code":11', b'"Code":11.0')
        self.replace_response("summary", raw)
        with self.assertRaisesRegex(telemetry.ContractError, "Code mismatch"):
            telemetry.compile_bundle(self.bundle_path)

        self.bundle = self.make_bundle("operator_attested_live_raw_unsigned")
        stats = copy.deepcopy(self.payloads["stats"])
        stats[0]["MM ID0"] = stats[0]["MM ID0"].replace("Fan1[1740]", "Fan1[100001]")
        self.replace_response("stats", response("stats", stats))
        with self.assertRaisesRegex(telemetry.ContractError, "structural bounds"):
            telemetry.compile_bundle(self.bundle_path)

    def test_fixture_runtime_rejects_stale_future_replay_missing_and_nonfinite(self):
        contract = telemetry.fixture_contract(
            temperature_pointers=["/stats/STATS/0/Temperature"],
            fan_rpm_pointers=["/devs/DEVS/0/Fan RPM"],
            auto_mode_pointer="/devs/DEVS/0/Fan Mode",
            sensor_sample_epoch_pointer="/stats/STATS/0/Sensor Epoch",
        )
        stats = {"STATS": [{"Temperature": 70.0, "Sensor Epoch": 100.0}]}
        devs = {"DEVS": [{"Fan RPM": 1740, "Fan Mode": "AUTO"}]}
        temperature, rpms, epoch = telemetry.validate_fixture_runtime_sample(
            contract, stats, devs, now_epoch=101.0, freshness_seconds=2.0,
            previous_sample_epoch=None,
        )
        self.assertEqual((temperature, rpms, epoch), (70.0, [1740.0], 100.0))
        with self.assertRaisesRegex(telemetry.ContractError, "stale"):
            telemetry.validate_fixture_runtime_sample(
                contract, stats, devs, now_epoch=103.0, freshness_seconds=2.0,
                previous_sample_epoch=None,
            )
        with self.assertRaisesRegex(telemetry.ContractError, "future"):
            telemetry.validate_fixture_runtime_sample(
                contract, stats, devs, now_epoch=99.0, freshness_seconds=2.0,
                previous_sample_epoch=None,
            )
        with self.assertRaisesRegex(telemetry.ContractError, "replayed"):
            telemetry.validate_fixture_runtime_sample(
                contract, stats, devs, now_epoch=101.0, freshness_seconds=2.0,
                previous_sample_epoch=100.0,
            )
        bad = copy.deepcopy(stats)
        bad["STATS"][0]["Temperature"] = math.nan
        with self.assertRaisesRegex(telemetry.ContractError, "not finite"):
            telemetry.validate_fixture_runtime_sample(
                contract, bad, devs, now_epoch=101.0, freshness_seconds=2.0,
                previous_sample_epoch=None,
            )
        with self.assertRaisesRegex(telemetry.ContractError, "missing"):
            telemetry.validate_fixture_runtime_sample(
                contract, {}, devs, now_epoch=101.0, freshness_seconds=2.0,
                previous_sample_epoch=None,
            )

    def test_fixture_runtime_rejects_non_auto_and_empty_coverage(self):
        contract = telemetry.fixture_contract(
            temperature_pointers=[], fan_rpm_pointers=[],
            auto_mode_pointer="/devs/DEVS/0/Fan Mode",
            sensor_sample_epoch_pointer="/stats/STATS/0/Sensor Epoch",
        )
        with self.assertRaisesRegex(telemetry.ContractError, "lacks temperature/fan"):
            telemetry.validate_fixture_runtime_sample(
                contract, {"STATS": [{"Sensor Epoch": 100}]},
                {"DEVS": [{"Fan Mode": "AUTO"}]}, now_epoch=101,
                freshness_seconds=2, previous_sample_epoch=None,
            )

        contract = telemetry.fixture_contract(
            temperature_pointers=["/stats/STATS/0/Temperature"],
            fan_rpm_pointers=["/devs/DEVS/0/Fan RPM"],
            auto_mode_pointer="/devs/DEVS/0/Fan Mode",
            sensor_sample_epoch_pointer="/stats/STATS/0/Sensor Epoch",
        )
        with self.assertRaisesRegex(telemetry.ContractError, "not exact AUTO"):
            telemetry.validate_fixture_runtime_sample(
                contract, {"STATS": [{"Temperature": 70, "Sensor Epoch": 100}]},
                {"DEVS": [{"Fan RPM": 1740, "Fan Mode": "MANUAL"}]}, now_epoch=101,
                freshness_seconds=2, previous_sample_epoch=None,
            )

    def test_contract_file_hash_unknown_key_and_live_forgery_fail_closed(self):
        contract = telemetry.fixture_contract(
            temperature_pointers=["/stats/STATS/0/Temperature"],
            fan_rpm_pointers=["/devs/DEVS/0/Fan RPM"],
            auto_mode_pointer="/devs/DEVS/0/Fan Mode",
            sensor_sample_epoch_pointer="/stats/STATS/0/Sensor Epoch",
        )
        path = self.root / "contract.json"
        raw = telemetry.canonical_json(contract)
        path.write_bytes(raw)
        loaded = telemetry.load_contract(path, telemetry.sha256_bytes(raw), live=False)
        self.assertEqual(loaded["provenance"], "synthetic_fixture")
        with self.assertRaisesRegex(telemetry.ContractError, "SHA-256 mismatch"):
            telemetry.load_contract(path, "f" * 64, live=False)
        contract["unexpected_authority"] = True
        with self.assertRaisesRegex(telemetry.ContractError, "keys mismatch"):
            telemetry.validate_contract_document(contract, live=False)

        forged = telemetry.compile_bundle(self.bundle_path)
        forged["soak_runtime_ready"] = True
        with self.assertRaisesRegex(telemetry.ContractError, "cannot authorize live use"):
            telemetry.validate_contract_document(forged, live=True)

    def test_capture_request_pins_two_exact_rounds_and_never_authorizes(self):
        request = telemetry.capture_request()
        self.assertEqual(request["telemetry_authorization_a_status"], "NO_GO")
        self.assertEqual(len(request["requests"]), 12)
        for item in request["requests"]:
            raw = telemetry.encode_request(item["command"])
            self.assertEqual(item["request_bytes"], len(raw))
            self.assertEqual(item["request_sha256"], telemetry.sha256_bytes(raw))
        self.assertTrue(
            any("STATUS.When" in item for item in request["known_non_solutions"])
        )

    def test_write_new_loops_on_short_write_and_never_overwrites(self):
        output = self.root / "draft.json"
        raw = b"0123456789abcdef"
        real_write = telemetry.os.write
        calls = 0

        def short_write(fd: int, value: memoryview) -> int:
            nonlocal calls
            calls += 1
            limit = max(1, len(value) // 2)
            return real_write(fd, value[:limit])

        with mock.patch.object(telemetry.os, "write", side_effect=short_write):
            telemetry._write_new(output, raw)
        self.assertGreater(calls, 1)
        self.assertEqual(output.read_bytes(), raw)
        with self.assertRaisesRegex(telemetry.ContractError, "refusing to overwrite"):
            telemetry._write_new(output, b"replacement")


if __name__ == "__main__":
    unittest.main()
