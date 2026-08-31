#!/usr/bin/env python3
"""Host-only tests for dual-reviewed A1246 fixture qualification."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_fixture_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_fixture_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
discovery = fixture.discovery
MANIFEST = SCRIPT.parent.parent / "gauntlet" / "k210_models.json"
DISCOVERY_TEST_SCRIPT = Path(__file__).with_name("test_k210_discovery_receipt.py")
DISCOVERY_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_discovery_fixture_for_fixture_test", DISCOVERY_TEST_SCRIPT
)
assert DISCOVERY_TEST_SPEC is not None and DISCOVERY_TEST_SPEC.loader is not None
discovery_test = importlib.util.module_from_spec(DISCOVERY_TEST_SPEC)
DISCOVERY_TEST_SPEC.loader.exec_module(discovery_test)
GAUNTLET_SCRIPT = Path(__file__).with_name("k210_gauntlet.py")
GAUNTLET_SPEC = importlib.util.spec_from_file_location(
    "k210_gauntlet_for_fixture_test", GAUNTLET_SCRIPT
)
assert GAUNTLET_SPEC is not None and GAUNTLET_SPEC.loader is not None
gauntlet = importlib.util.module_from_spec(GAUNTLET_SPEC)
GAUNTLET_SPEC.loader.exec_module(gauntlet)


class K210FixtureReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_root = self.root / "fixture-evidence"
        self.evidence_root.mkdir()
        self.discovery_private, self.discovery_public = self._new_key("discovery")
        self.operator_private, self.operator_public = self._new_key("fixture-operator")
        self.reviewer_private, self.reviewer_public = self._new_key("fixture-reviewer")
        self.discovery_receipt = self._discovery_receipt()
        self.descriptor = self._descriptor()
        self.descriptor_path = self.root / "fixture-descriptor.json"
        self._write_descriptor()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _new_key(self, name: str) -> tuple[Path, Path]:
        private_key = self.root / name
        process = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"{name}@test.invalid",
                "-f",
                str(private_key),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        return private_key, Path(f"{private_key}.pub")

    def _discovery_receipt(self) -> dict[str, object]:
        evidence_root = self.root / "discovery-evidence"
        evidence_root.mkdir()
        capture = discovery_test.semantic_capture_fixture(
            self.manifest, evidence_root, "a1246"
        )
        capture_path = self.root / "discovery-capture.json"
        capture_path.write_bytes(discovery.canonical_json_bytes(capture))
        self.discovery_bundle = self.root / "discovery-bundle"
        return discovery.create_bundle(
            self.manifest,
            capture_path,
            evidence_root,
            self.discovery_private,
            self.discovery_bundle,
        )

    def _write_json(self, path: str, value: object) -> None:
        destination = self.evidence_root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(fixture.canonical_json_bytes(value))

    def _add_evidence(
        self,
        evidence: list[dict[str, object]],
        kind: str,
        path: str,
        value: object,
    ) -> None:
        destination = self.evidence_root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if kind in fixture.PHOTO_KINDS:
            destination.write_bytes(discovery_test.photo_png())
        else:
            destination.write_bytes(fixture.canonical_json_bytes(value))
        evidence.append(
            {
                "acquired_at_utc": "2026-08-23T17:15:00Z",
                "id": f"e-{kind.replace('_', '-')}",
                "kind": kind,
                "media_type": (
                    "image/png" if kind in fixture.PHOTO_KINDS else "application/json"
                ),
                "method": fixture.METHOD_BY_KIND[kind],
                "path": path,
                "redaction": "none",
            }
        )

    def _records(self) -> dict[str, object]:
        identity = self.discovery_receipt["identity"]
        read_sha = "1" * 64
        signals = []
        for interface_class, direction in (
            ("flash", "bidirectional"),
            ("hashboard", "controller_to_asic"),
            ("jtag", "bidirectional"),
            ("rom_isp", "input"),
            ("uart", "bidirectional"),
        ):
            signals.append(
                {
                    "direction": direction,
                    "idle_mv": 1800,
                    "interface_class": interface_class,
                    "max_probe_input_mv": 5000,
                    "name": f"measured-{interface_class}",
                    "probe_attenuation_x": 10,
                    "reference_ground": "controller-ground-test-point",
                }
            )
        instruments = []
        for index, role in enumerate(sorted(fixture.REQUIRED_INSTRUMENT_ROLES), 1):
            instruments.append(
                {
                    "calibration_id": f"cal-{index}",
                    "calibration_valid_until_utc": "2027-08-23T00:00:00Z",
                    "model": f"instrument-model-{index}",
                    "role": role,
                    "serial": f"instrument-serial-{index}",
                }
            )
        return {
            "completion_matrix": {
                "deviations": [],
                "dispositions": {
                    name: True for name in sorted(fixture.DISPOSITIONS)
                },
                "reviewed_at_utc": "2026-08-23T17:25:00Z",
                "unresolved_points": [],
            },
            "cooling_cutoff_record": {
                "airflow_direction": "front-to-back",
                "cooling_class": identity["cooling_class"],
                "cooling_controller": identity["cooling_controller"],
                "cutoff_asserted_during_controller_only": True,
                "fan_or_pump_count": identity["fan_or_pump_count"],
                "hash_rail_absent_verified": True,
                "independent_cutoff_method": "series-lockable-hash-rail-disconnect",
                "rail_feedback_method": "independent-dmm-at-hashboard-input",
                "stock_baseline_recorded": True,
                "watchdog_strategy": "operator-and-independent-overtemperature-cutoff",
            },
            "discovery_receipt_copy": self.discovery_receipt,
            "electrical_measurement_record": {
                "controller_input_connector": "controller-j1",
                "current_limit_ma": 1500,
                "inrush_ma": 700,
                "nominal_mv": 12000,
                "polarity": "negative_to_ground",
                "signals": signals,
                "signals_complete": True,
                "steady_state_ma": 350,
            },
            "flash_fixture_record": {
                "back_power_max_mv": 20,
                "capacity_bytes": 64,
                "chip_select_isolated": True,
                "device_id": "flash-test-001",
                "in_circuit_contention_excluded": True,
                "k210_held_in_reset": True,
                "manufacturer": "test-flash-vendor",
                "model": "test-flash-model",
                "package": "soic8",
                "primary_datasheet_sha256": "2" * 64,
                "programmer": {
                    "adapter": "isolated-test-clip",
                    "current_limit_ma": 100,
                    "firmware_version": "test-programmer-1.0",
                    "model": "test-programmer",
                    "output_mv": 1800,
                    "serial": "programmer-test-001",
                },
                "read_a_sha256": read_sha,
                "read_b_sha256": read_sha,
                "read_bytes": 64,
                "supply_mv": 1800,
                "technology": "spi_nor",
            },
            "identity_isolation_record": {
                "back_power_paths": [
                    {"interface": name, "max_observed_mv": 20, "tested": True}
                    for name in ("flash", "hashboard", "jtag", "rom-isp", "uart")
                ],
                "common_ground_point": "controller-ground-test-point",
                "controller_board_model": identity["controller_board_model"],
                "controller_board_revision": identity["controller_board_revision"],
                "hash_power_physically_disconnected": True,
                "hashboard_revisions": ["hashboard-rev-a", "hashboard-rev-b"],
                "rail_absence_feedback_method": "independent-dmm-at-hashboard-input",
                "rail_absent_verified": True,
                "stock_dna": identity["stock_dna"],
                "stock_firmware_version": identity["stock_firmware_version"],
                "stock_hwtype": identity["stock_hwtype"],
                "stock_swtype": identity["stock_swtype"],
            },
            "instrument_record": {
                "esd_controls_verified": True,
                "fused_current_limited_feed": True,
                "instruments": instruments,
                "isolated_supply": True,
                "probe_strain_relief": True,
            },
            "qualification_log": {
                "anomalies": [],
                "authorization_reference": "fixture-authorization-test-001",
                "events": [
                    {
                        "action": action,
                        "detail": f"completed authorized {action}",
                        "time_utc": f"2026-08-23T17:{10 + index:02d}:00Z",
                    }
                    for index, action in enumerate(sorted(fixture.FIXTURE_ACTIONS))
                ],
                "session": "exact-unit A1246 fixture qualification test",
                "stopped_reason": None,
            },
        }

    def _descriptor(self) -> dict[str, object]:
        records = self._records()
        evidence: list[dict[str, object]] = []
        paths = {
            "completion_matrix": "records/completion-matrix.json",
            "cooling_cutoff_record": "records/cooling-cutoff.json",
            "discovery_receipt_copy": "identity/discovery-receipt.json",
            "electrical_measurement_record": "records/electrical.json",
            "fixture_overview_photo": "photos/fixture-overview.png",
            "flash_fixture_record": "records/flash.json",
            "identity_isolation_record": "records/identity-isolation.json",
            "instrument_record": "records/instruments.json",
            "programmer_isolation_photo": "photos/programmer-isolation.png",
            "qualification_log": "records/qualification-log.json",
        }
        for kind in fixture.REQUIRED_EVIDENCE_KINDS:
            self._add_evidence(evidence, kind, paths[kind], records.get(kind))
        return {
            "actions_performed": dict(fixture.ACTIONS_PERFORMED),
            "authorization": {
                "authorized_actions": sorted(fixture.FIXTURE_ACTIONS),
                "operator_reference": "fixture-authorization-test-001",
                "valid_from_utc": "2026-08-23T17:00:00Z",
                "valid_until_utc": "2026-08-23T18:00:00Z",
            },
            "completed_at_utc": "2026-08-23T17:30:00Z",
            "discovery_receipt_id": self.discovery_receipt["receipt_id"],
            "evidence": evidence,
            "fixture_id": "fixture-test-001",
            "kind": fixture.DESCRIPTOR_KIND,
            "operator_id": "fixture-operator-test",
            "reviewer_id": "fixture-reviewer-test",
            "schema_version": fixture.SCHEMA_VERSION,
            "scope": fixture.SCOPE,
            "started_at_utc": "2026-08-23T17:05:00Z",
            "target_id": self.discovery_receipt["target_id"],
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
            "unit_label": self.discovery_receipt["unit_label"],
        }

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_bytes(fixture.canonical_json_bytes(self.descriptor))

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "fixture-bundle"
        fixture.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.operator_private,
            self.reviewer_private,
            bundle,
        )
        return bundle

    def _rewrite_record(self, kind: str, mutate) -> None:
        item = next(row for row in self.descriptor["evidence"] if row["kind"] == kind)
        path = self.evidence_root / item["path"]
        record = json.loads(path.read_bytes())
        mutate(record)
        path.write_bytes(fixture.canonical_json_bytes(record))

    def test_round_trip_is_dual_reviewed_exact_unit_and_non_authorizing(self) -> None:
        bundle = self._bundle()
        result = fixture.verify_bundle(
            self.manifest, bundle, self.operator_public, self.reviewer_public
        )
        self.assertEqual(result["state"], "verified_signed_fixture_qualification")
        self.assertTrue(result["fixture_qualification_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["discovery_receipt_id"], self.discovery_receipt["receipt_id"])
        self.assertEqual(set(result["dispositions"]), fixture.DISPOSITIONS)
        receipt_path = bundle / fixture.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_bytes())
        self.assertEqual(receipt_path.read_bytes(), fixture.canonical_json_bytes(receipt))
        self.assertEqual(receipt["authority_ceiling"], fixture.AUTHORITY_CEILING)

    def test_template_is_bound_to_discovery_and_remains_non_authorizing(self) -> None:
        descriptor = fixture._template(
            self.manifest, self.discovery_bundle / discovery.RECEIPT_NAME
        )
        self.assertEqual(descriptor["discovery_receipt_id"], self.discovery_receipt["receipt_id"])
        self.assertEqual(
            descriptor["unit_fingerprint_sha256"],
            self.discovery_receipt["unit_fingerprint_sha256"],
        )
        self.assertEqual(descriptor["actions_performed"], fixture.ACTIONS_PERFORMED)

    def test_false_disposition_deviation_stop_and_missing_signal_fail_closed(self) -> None:
        cases = (
            (
                "completion_matrix",
                lambda record: record["dispositions"].update(
                    {"jtag_probe_ready": False}
                ),
                "explicitly true",
            ),
            (
                "completion_matrix",
                lambda record: record["deviations"].append("unreviewed adapter"),
                "deviations or unresolved",
            ),
            (
                "qualification_log",
                lambda record: record.update({"stopped_reason": "unexpected heat"}),
                "stopped session",
            ),
            (
                "electrical_measurement_record",
                lambda record: record["signals"].pop(),
                "signals must contain",
            ),
        )
        for kind, mutate, expected in cases:
            with self.subTest(expected=expected):
                original = (self.evidence_root / next(
                    row["path"] for row in self.descriptor["evidence"] if row["kind"] == kind
                )).read_bytes()
                self._rewrite_record(kind, mutate)
                with self.assertRaisesRegex(fixture.FixtureError, expected):
                    fixture.build_receipt(
                        self.manifest,
                        self.descriptor,
                        self.evidence_root,
                        self.operator_private,
                        self.reviewer_private,
                    )
                target = self.evidence_root / next(
                    row["path"] for row in self.descriptor["evidence"] if row["kind"] == kind
                )
                target.write_bytes(original)

    def test_flash_read_identity_discovery_join_and_corrupt_photo_fail_closed(self) -> None:
        flash_path = self.evidence_root / "records" / "flash.json"
        original_flash = flash_path.read_bytes()
        self._rewrite_record(
            "flash_fixture_record",
            lambda record: record.update({"read_b_sha256": "3" * 64}),
        )
        with self.assertRaisesRegex(fixture.FixtureError, "not byte-identical"):
            fixture.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )
        flash_path.write_bytes(original_flash)
        original_fingerprint = self.descriptor["unit_fingerprint_sha256"]
        self.descriptor["unit_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(fixture.FixtureError, "does not match fixture"):
            fixture.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )
        self.descriptor["unit_fingerprint_sha256"] = original_fingerprint
        photo = self.evidence_root / "photos" / "fixture-overview.png"
        photo.write_bytes(discovery_test.photo_png()[:-8])
        with self.assertRaisesRegex(fixture.FixtureError, "inadmissible"):
            fixture.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )

    def test_tamper_extra_member_wrong_key_and_same_key_are_rejected(self) -> None:
        bundle = self._bundle()
        evidence = next((bundle / fixture.EVIDENCE_DIRECTORY).rglob("*.png"))
        evidence.write_bytes(evidence.read_bytes() + b"tamper")
        with self.assertRaisesRegex(fixture.FixtureError, "digest or size mismatch"):
            fixture.verify_bundle(
                self.manifest, bundle, self.operator_public, self.reviewer_public
            )
        evidence.write_bytes(evidence.read_bytes()[:-6])
        (bundle / "unsigned-note.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(fixture.FixtureError, "member set is not exact"):
            fixture.verify_bundle(
                self.manifest, bundle, self.operator_public, self.reviewer_public
            )
        (bundle / "unsigned-note.txt").unlink()
        _, wrong_public = self._new_key("wrong-reviewer")
        with self.assertRaisesRegex(fixture.FixtureError, "reviewer signer is not trusted"):
            fixture.verify_bundle(
                self.manifest, bundle, self.operator_public, wrong_public
            )
        with self.assertRaisesRegex(fixture.FixtureError, "keys must be distinct"):
            fixture.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.operator_private,
            )

    def test_unknown_fields_and_mutating_actions_are_rejected(self) -> None:
        descriptor = deepcopy(self.descriptor)
        descriptor["unexpected"] = True
        with self.assertRaisesRegex(fixture.FixtureError, "unexpected unexpected"):
            fixture.build_receipt(
                self.manifest,
                descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )
        descriptor = deepcopy(self.descriptor)
        descriptor["actions_performed"]["flash_written"] = True
        with self.assertRaisesRegex(fixture.FixtureError, "contract drifted"):
            fixture.build_receipt(
                self.manifest,
                descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )

    def test_gauntlet_admits_fixture_without_advancing_a_production_gate(self) -> None:
        bundle = self._bundle()
        repository = self.root / "repository"
        discovery_verifier = repository / gauntlet.DISCOVERY_VERIFIER
        fixture_verifier = repository / gauntlet.FIXTURE_VERIFIER
        discovery_verifier.parent.mkdir(parents=True)
        shutil.copyfile(discovery.__file__, discovery_verifier)
        shutil.copyfile(fixture.__file__, fixture_verifier)
        trust = repository / "trust"
        trust.mkdir()
        key_sources = {
            "discovery": self.discovery_public,
            "operator": self.operator_public,
            "reviewer": self.reviewer_public,
        }
        key_ids: dict[str, str] = {}
        for name, source in key_sources.items():
            destination = trust / f"{name}.pub"
            shutil.copyfile(source, destination)
            key_ids[name] = discovery.inspect_public_key(destination)["key_id_sha256"]
        manifest = deepcopy(self.manifest)
        manifest["discovery_contract"]["state"] = "signed_read_only_receipt_admission"
        manifest["discovery_contract"]["trust_anchor"] = {
            "key_id_sha256": key_ids["discovery"],
            "path": "trust/discovery.pub",
            "role": discovery.SIGNER_ROLE,
        }
        manifest["fixture_contract"]["state"] = "dual_signed_fixture_admission"
        manifest["fixture_contract"]["trust_anchors"] = {
            "operator": {
                "key_id_sha256": key_ids["operator"],
                "path": "trust/operator.pub",
                "role": fixture.OPERATOR_ROLE,
            },
            "reviewer": {
                "key_id_sha256": key_ids["reviewer"],
                "path": "trust/reviewer.pub",
                "role": fixture.REVIEWER_ROLE,
            },
        }
        gauntlet.validate_manifest(manifest)
        discoveries = gauntlet.verify_discovery_bundles(
            manifest, [self.discovery_bundle], repository
        )
        with self.assertRaisesRegex(gauntlet.GauntletError, "no admitted discovery"):
            gauntlet.verify_fixture_bundles(manifest, [bundle], {}, repository)
        fixtures = gauntlet.verify_fixture_bundles(
            manifest, [bundle], discoveries, repository
        )
        foreign_discovery = deepcopy(discoveries)
        foreign_discovery["a1246"]["unit_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(gauntlet.GauntletError, "does not join discovery"):
            gauntlet.verify_fixture_bundles(
                manifest, [bundle], foreign_discovery, repository
            )
        target = next(row for row in manifest["targets"] if row["id"] == "a1246")
        profiles = gauntlet.verify_profiles(manifest, corpus_policy="skip")
        model = gauntlet.evaluate_target(
            manifest,
            target,
            profiles,
            discoveries["a1246"],
            fixture_result=fixtures["a1246"],
        )
        self.assertIsNotNone(model["fixture_qualification"])
        self.assertTrue(model["gates"]["exact_model_identity"]["qualifies"])
        self.assertFalse(model["gates"]["thermal_power_safety"]["qualifies"])
        self.assertFalse(model["production_ready"])


if __name__ == "__main__":
    unittest.main()
