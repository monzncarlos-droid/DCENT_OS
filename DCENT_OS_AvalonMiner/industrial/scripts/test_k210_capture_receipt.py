#!/usr/bin/env python3
"""Host-only tests for signed A1246 P1 passive-capture admission."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_capture_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_capture_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
capture_receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture_receipt)
fixture = capture_receipt.fixture
discovery = capture_receipt.discovery
cap = capture_receipt.capture_ingest
MANIFEST = SCRIPT.parent.parent / "gauntlet" / "k210_models.json"
FIXTURE_TEST_SCRIPT = Path(__file__).with_name("test_k210_fixture_receipt.py")
FIXTURE_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_fixture_fixture_for_capture_test", FIXTURE_TEST_SCRIPT
)
assert FIXTURE_TEST_SPEC is not None and FIXTURE_TEST_SPEC.loader is not None
fixture_test = importlib.util.module_from_spec(FIXTURE_TEST_SPEC)
FIXTURE_TEST_SPEC.loader.exec_module(fixture_test)
gauntlet = fixture_test.gauntlet


class K210CaptureReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.upstream = fixture_test.K210FixtureReceiptTests(methodName="runTest")
        self.upstream.manifest = self.manifest
        self.upstream.setUp()
        self.addCleanup(self.upstream.tearDown)
        self.root = self.upstream.root
        self.discovery_receipt = self.upstream.discovery_receipt
        self.discovery_bundle = self.upstream.discovery_bundle
        self.fixture_bundle = self.upstream._bundle()
        self.fixture_receipt = json.loads(
            (self.fixture_bundle / fixture.RECEIPT_NAME).read_bytes()
        )
        self.evidence_root = self.root / "capture-evidence"
        self.evidence_root.mkdir()
        self.operator_private, self.operator_public = self._new_key("capture-operator")
        self.reviewer_private, self.reviewer_public = self._new_key("capture-reviewer")
        self.descriptor = self._descriptor()
        self.descriptor_path = self.root / "capture-descriptor.json"
        self._write_descriptor()

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

    def _write_json(self, relative: str, value: object) -> None:
        path = self.evidence_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(capture_receipt.canonical_json_bytes(value))

    def _add_evidence(
        self,
        evidence: list[dict[str, object]],
        evidence_id: str,
        kind: str,
        relative: str,
    ) -> None:
        evidence.append(
            {
                "acquired_at_utc": "2026-08-23T18:20:00Z",
                "id": evidence_id,
                "kind": kind,
                "media_type": capture_receipt.MEDIA_TYPE_BY_KIND[kind],
                "method": capture_receipt.METHOD_BY_KIND[kind],
                "path": relative,
                "redaction": "none",
            }
        )

    def _provenance(
        self, state: str, capture_id: str, sample_rate_hz: int = 100_000_000
    ) -> dict[str, object]:
        identity = self.discovery_receipt["identity"]
        qualified = self.fixture_receipt["fixture_identity"]
        return {
            "asic_family": identity["asic_family"],
            "authorization_reference": "capture-authorization-test-001",
            "capture_end_s": "0.000000100",
            "capture_session_id": capture_id,
            "capture_state": state,
            "controller_revision": qualified["controller_board_revision"],
            "hashboard_revision": "|".join(
                sorted(qualified["hashboard_revisions"])
            ),
            "model": identity["marketing_model"],
            "operator": "capture-operator-test",
            "sample_rate_hz": sample_rate_hz,
            "stock_aup_sha256": self.descriptor_profile["aup_sha256"],
            "stock_firmware_build": identity["stock_firmware_version"],
            "unit_serial": identity["miner_serial"],
        }

    def _write_capture(
        self,
        state: str,
        capture_id: str,
        prefix: str,
        *,
        channel_offset: int = 0,
        sample_rate_hz: int = 100_000_000,
        with_edges: bool = True,
    ) -> tuple[str, str, str]:
        signals = ("CI", "DI", "RI", "CKI", "CO", "DO", "RO", "CKO")
        channels = {
            signal: channel_offset + index for index, signal in enumerate(signals)
        }
        mapping = {
            "channels": channels,
            "format": cap.MAPPING_FORMAT,
            "provenance": self._provenance(state, capture_id, sample_rate_hz),
        }
        map_relative = f"captures/{prefix}-map.json"
        csv_relative = f"captures/{prefix}.csv"
        artifact_relative = f"captures/{prefix}.k210cap"
        self._write_json(map_relative, mapping)
        header = ["Time [s]", *[f"Channel {channels[name]}" for name in signals]]
        rows = [["0", *(["0"] * len(signals))]]
        if with_edges:
            for index in range(len(signals)):
                row = [f"0.0000000{index + 1}", *([""] * len(signals))]
                row[index + 1] = "1"
                rows.append(row)
        csv_text = "\n".join(",".join(row) for row in [header, *rows]) + "\n"
        csv_path = self.evidence_root / csv_relative
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text(csv_text, encoding="ascii")
        tracks = cap._parse_digital_csv(
            csv_text.encode("ascii"), csv_path, "test CSV", channels
        )
        normalized = cap._merge_and_normalize(
            tracks,
            cap._parse_seconds_to_ps(mapping["provenance"]["capture_end_s"]),
            sample_rate_hz,
            1,
        )
        artifact = cap.encode_artifact(mapping["provenance"], normalized)
        artifact_path = self.evidence_root / artifact_relative
        artifact_path.write_bytes(artifact)
        return map_relative, csv_relative, artifact_relative

    def _base_records(self, capture_ids: dict[str, str]) -> dict[str, object]:
        identity = self.discovery_receipt["identity"]
        qualified = self.fixture_receipt["fixture_identity"]
        exact_identity = {
            "asic_family": identity["asic_family"],
            "controller_board_model": qualified["controller_board_model"],
            "controller_board_revision": qualified["controller_board_revision"],
            "hashboard_revisions": qualified["hashboard_revisions"],
            "stock_dna": identity["stock_dna"],
            "stock_firmware_build": identity["stock_firmware_version"],
            "stock_hwtype": identity["stock_hwtype"],
            "stock_swtype": identity["stock_swtype"],
            "unit_serial": identity["miner_serial"],
        }
        return {
            "campaign_log": {
                "authorization_reference": "capture-authorization-test-001",
                "deviations": [],
                "events": [
                    {
                        "action": action,
                        "detail": f"completed authorized {action}",
                        "time_utc": f"2026-08-23T18:{10 + index:02d}:00Z",
                    }
                    for index, action in enumerate(
                        sorted(capture_receipt.CAPTURE_ACTIONS)
                    )
                ],
                "faults": [],
                "stop_events": [],
            },
            "cooling_telemetry_record": {
                "capture_ids": sorted(capture_ids.values()),
                "fan_or_pump_faults": [],
                "fans_or_pumps_operational": True,
                "limit_millicelsius": 85000,
                "max_observed_millicelsius": 62000,
                "sample_count": 20,
                "stock_baseline_after": True,
                "stock_baseline_before": True,
                "telemetry_gap": False,
            },
            "cutoff_feedback_record": {
                "continuous_monitoring": True,
                "independent_feedback_method": "isolated-dmm-rail-monitor",
                "loss_events": [],
                "rail_absent_for_full_capture": True,
                "safe_idle_capture_id": capture_ids["safe_idle_detection"],
            },
            "discovery_receipt_copy": self.discovery_receipt,
            "fixture_receipt_copy": self.fixture_receipt,
            "state_control_record": {
                "bounded_work_exchange": {
                    "closed_chassis": True,
                    "cooling_confirmed": True,
                    "independent_cutoff_available": True,
                    "stock_firmware_running": True,
                    "stock_work_bounded": True,
                },
                "safe_idle_detection": {
                    "closed_chassis": True,
                    "hash_power_requested": False,
                    "independent_cutoff_asserted": True,
                    "stock_firmware_running": True,
                },
            },
            "stock_identity_record": {
                "after": exact_identity,
                "before": exact_identity,
                "identity_drift": False,
                "stock_aup_sha256": self.descriptor_profile["aup_sha256"],
            },
            "work_exchange_record": {
                "authorization_reference": "capture-authorization-test-001",
                "capture_id": capture_ids["bounded_work_exchange"],
                "completed_work_units": 1,
                "duration_ms": 1000,
                "job_observed": True,
                "nonce_observed": True,
                "poolless_test_work": True,
                "requested_work_units": 1,
                "status_observed": True,
                "stopped": False,
            },
        }

    def _descriptor(self) -> dict[str, object]:
        profile_id = self.fixture_receipt["fixture_identity"]["variant_profile_id"]
        self.descriptor_profile = next(
            row for row in self.manifest["firmware_profiles"] if row["id"] == profile_id
        )
        capture_ids = {
            "safe_idle_detection": "p1-safe-idle-test-001",
            "bounded_work_exchange": "p1-bounded-work-test-001",
        }
        records = self._base_records(capture_ids)
        base_paths = {
            "campaign_log": "records/campaign-log.json",
            "cooling_telemetry_record": "records/cooling.json",
            "cutoff_feedback_record": "records/cutoff.json",
            "discovery_receipt_copy": "identity/discovery-receipt.json",
            "fixture_receipt_copy": "identity/fixture-receipt.json",
            "state_control_record": "records/state-control.json",
            "stock_identity_record": "records/stock-identity.json",
            "work_exchange_record": "records/work-exchange.json",
        }
        evidence: list[dict[str, object]] = []
        for kind in sorted(capture_receipt.SINGLE_EVIDENCE_KINDS):
            relative = base_paths[kind]
            self._write_json(relative, records[kind])
            self._add_evidence(evidence, f"e-{kind.replace('_', '-')}", kind, relative)
        captures = []
        for state, prefix in (
            ("safe_idle_detection", "idle"),
            ("bounded_work_exchange", "work"),
        ):
            map_path, csv_path, artifact_path = self._write_capture(
                state, capture_ids[state], prefix
            )
            ids = {
                "artifact": f"{prefix}-artifact",
                "map": f"{prefix}-map",
                "csv": f"{prefix}-csv",
            }
            self._add_evidence(
                evidence, ids["artifact"], "k210cap_artifact", artifact_path
            )
            self._add_evidence(
                evidence, ids["map"], "physical_channel_map", map_path
            )
            self._add_evidence(evidence, ids["csv"], "source_csv", csv_path)
            captures.append(
                {
                    "capture_id": capture_ids[state],
                    "k210cap_evidence_id": ids["artifact"],
                    "mapping_evidence_id": ids["map"],
                    "source_csv_evidence_ids": [ids["csv"]],
                    "state": state,
                }
            )
        return {
            "actions_performed": dict(capture_receipt.ACTIONS_PERFORMED),
            "admission_class": capture_receipt.ADMISSION_CLASS,
            "authorization": {
                "authorized_actions": sorted(capture_receipt.CAPTURE_ACTIONS),
                "operator_reference": "capture-authorization-test-001",
                "valid_from_utc": "2026-08-23T18:00:00Z",
                "valid_until_utc": "2026-08-23T19:00:00Z",
            },
            "campaign_id": "capture-campaign-test-001",
            "captures": captures,
            "completed_at_utc": "2026-08-23T18:40:00Z",
            "discovery_receipt_id": self.discovery_receipt["receipt_id"],
            "evidence": evidence,
            "fixture_evidence_set_sha256": self.fixture_receipt[
                "fixture_evidence_set_sha256"
            ],
            "fixture_receipt_id": self.fixture_receipt["receipt_id"],
            "kind": capture_receipt.DESCRIPTOR_KIND,
            "operator_id": "capture-operator-test",
            "reviewer_id": "capture-reviewer-test",
            "schema_version": capture_receipt.SCHEMA_VERSION,
            "scope": capture_receipt.SCOPE,
            "started_at_utc": "2026-08-23T18:05:00Z",
            "stock_aup_sha256": self.descriptor_profile["aup_sha256"],
            "target_id": self.discovery_receipt["target_id"],
            "unit_fingerprint_sha256": self.discovery_receipt[
                "unit_fingerprint_sha256"
            ],
            "unit_label": self.discovery_receipt["unit_label"],
            "variant_profile_id": profile_id,
        }

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_bytes(
            capture_receipt.canonical_json_bytes(self.descriptor)
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "capture-bundle"
        capture_receipt.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.operator_private,
            self.reviewer_private,
            bundle,
        )
        return bundle

    def _rewrite_json(self, kind: str, mutate) -> None:
        item = next(row for row in self.descriptor["evidence"] if row["kind"] == kind)
        path = self.evidence_root / item["path"]
        record = json.loads(path.read_bytes())
        mutate(record)
        path.write_bytes(capture_receipt.canonical_json_bytes(record))

    def _rewrite_capture(
        self,
        state: str,
        *,
        channel_offset: int = 0,
        sample_rate_hz: int = 100_000_000,
        with_edges: bool = True,
    ) -> None:
        row = next(item for item in self.descriptor["captures"] if item["state"] == state)
        prefix = "idle" if state == "safe_idle_detection" else "work"
        self._write_capture(
            state,
            row["capture_id"],
            prefix,
            channel_offset=channel_offset,
            sample_rate_hz=sample_rate_hz,
            with_edges=with_edges,
        )

    def test_round_trip_reproduces_both_states_and_grants_no_authority(self) -> None:
        bundle = self._bundle()
        result = capture_receipt.verify_bundle(
            self.manifest, bundle, self.operator_public, self.reviewer_public
        )
        self.assertEqual(result["state"], "verified_signed_p1_passive_capture")
        self.assertTrue(result["p1_capture_admission_eligible"])
        self.assertFalse(result["wire_contract_claimed"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(len(result["captures"]), 2)
        work = next(
            item for item in result["captures"] if item["state"] == "bounded_work_exchange"
        )
        self.assertGreater(work["controller_to_asic_events"], 0)
        self.assertGreater(work["asic_to_controller_events"], 0)
        receipt_path = bundle / capture_receipt.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_bytes())
        self.assertEqual(
            receipt_path.read_bytes(), capture_receipt.canonical_json_bytes(receipt)
        )
        self.assertEqual(receipt["authority_ceiling"], capture_receipt.AUTHORITY_CEILING)

    def test_zero_event_bounded_work_and_low_sample_rate_are_rejected(self) -> None:
        self._rewrite_capture("bounded_work_exchange", with_edges=False)
        with self.assertRaisesRegex(
            capture_receipt.CaptureReceiptError, "nonempty bidirectional"
        ):
            capture_receipt.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )
        self._rewrite_capture("bounded_work_exchange", sample_rate_hz=10_000_000)
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "50 MS/s"):
            capture_receipt.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )

    def test_source_reproduction_and_physical_map_stability_are_enforced(self) -> None:
        artifact = self.evidence_root / "captures" / "work.k210cap"
        artifact.write_bytes(artifact.read_bytes() + b"tamper")
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "invalid"):
            capture_receipt.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )
        self._rewrite_capture("bounded_work_exchange", channel_offset=10)
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "mapping drifted"):
            capture_receipt.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )

    def test_faults_identity_splice_and_mutating_actions_fail_closed(self) -> None:
        cases = (
            (
                "campaign_log",
                lambda record: record["faults"].append("fan fault"),
                "nonempty faults",
            ),
            (
                "stock_identity_record",
                lambda record: record["after"].update({"stock_dna": "foreign"}),
                "does not exact-join",
            ),
            (
                "cutoff_feedback_record",
                lambda record: record.update({"rail_absent_for_full_capture": False}),
                "cutoff feedback",
            ),
        )
        for kind, mutate, expected in cases:
            with self.subTest(kind=kind):
                item = next(
                    row for row in self.descriptor["evidence"] if row["kind"] == kind
                )
                path = self.evidence_root / item["path"]
                original = path.read_bytes()
                self._rewrite_json(kind, mutate)
                with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, expected):
                    capture_receipt.build_receipt(
                        self.manifest,
                        self.descriptor,
                        self.evidence_root,
                        self.operator_private,
                        self.reviewer_private,
                    )
                path.write_bytes(original)
        descriptor = deepcopy(self.descriptor)
        descriptor["actions_performed"]["configuration_changed"] = True
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "contract drifted"):
            capture_receipt.build_receipt(
                self.manifest,
                descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )
        descriptor = deepcopy(self.descriptor)
        descriptor["admission_class"] = "p3_chip_fixture_complement"
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "admission class"):
            capture_receipt.build_receipt(
                self.manifest,
                descriptor,
                self.evidence_root,
                self.operator_private,
                self.reviewer_private,
            )

    def test_tamper_wrong_key_same_key_and_extra_member_are_rejected(self) -> None:
        bundle = self._bundle()
        csv_path = next((bundle / capture_receipt.EVIDENCE_DIRECTORY).rglob("*.csv"))
        original = csv_path.read_bytes()
        csv_path.write_bytes(original + b"tamper")
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "digest or size"):
            capture_receipt.verify_bundle(
                self.manifest, bundle, self.operator_public, self.reviewer_public
            )
        csv_path.write_bytes(original)
        (bundle / "unsigned-note.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "member set"):
            capture_receipt.verify_bundle(
                self.manifest, bundle, self.operator_public, self.reviewer_public
            )
        (bundle / "unsigned-note.txt").unlink()
        _, wrong_public = self._new_key("wrong-capture-reviewer")
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "not trusted"):
            capture_receipt.verify_bundle(
                self.manifest, bundle, self.operator_public, wrong_public
            )
        with self.assertRaisesRegex(capture_receipt.CaptureReceiptError, "keys must be distinct"):
            capture_receipt.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.operator_private,
                self.operator_private,
            )

    def test_gauntlet_admits_capture_without_claiming_asic_control(self) -> None:
        bundle = self._bundle()
        repository = self.root / "repository"
        for relative, source in (
            (gauntlet.DISCOVERY_VERIFIER, discovery.__file__),
            (gauntlet.FIXTURE_VERIFIER, fixture.__file__),
            (gauntlet.CAPTURE_VERIFIER, capture_receipt.__file__),
        ):
            destination = repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        trust = repository / "trust"
        trust.mkdir()
        key_sources = {
            "discovery": self.upstream.discovery_public,
            "fixture-operator": self.upstream.operator_public,
            "fixture-reviewer": self.upstream.reviewer_public,
            "capture-operator": self.operator_public,
            "capture-reviewer": self.reviewer_public,
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
                "key_id_sha256": key_ids["fixture-operator"],
                "path": "trust/fixture-operator.pub",
                "role": fixture.OPERATOR_ROLE,
            },
            "reviewer": {
                "key_id_sha256": key_ids["fixture-reviewer"],
                "path": "trust/fixture-reviewer.pub",
                "role": fixture.REVIEWER_ROLE,
            },
        }
        manifest["capture_contract"]["state"] = "dual_signed_p1_capture_admission"
        manifest["capture_contract"]["trust_anchors"] = {
            "operator": {
                "key_id_sha256": key_ids["capture-operator"],
                "path": "trust/capture-operator.pub",
                "role": capture_receipt.OPERATOR_ROLE,
            },
            "reviewer": {
                "key_id_sha256": key_ids["capture-reviewer"],
                "path": "trust/capture-reviewer.pub",
                "role": capture_receipt.REVIEWER_ROLE,
            },
        }
        gauntlet.validate_manifest(manifest)
        discoveries = gauntlet.verify_discovery_bundles(
            manifest, [self.discovery_bundle], repository
        )
        fixtures = gauntlet.verify_fixture_bundles(
            manifest, [self.fixture_bundle], discoveries, repository
        )
        with self.assertRaisesRegex(gauntlet.GauntletError, "lacks admitted"):
            gauntlet.verify_capture_bundles(
                manifest, [bundle], discoveries, {}, repository
            )
        captures = gauntlet.verify_capture_bundles(
            manifest, [bundle], discoveries, fixtures, repository
        )
        foreign = deepcopy(fixtures)
        foreign["a1246"]["fixture_evidence_set_sha256"] = "0" * 64
        with self.assertRaisesRegex(gauntlet.GauntletError, "does not join fixture"):
            gauntlet.verify_capture_bundles(
                manifest, [bundle], discoveries, foreign, repository
            )
        target = next(row for row in manifest["targets"] if row["id"] == "a1246")
        profiles = gauntlet.verify_profiles(manifest, corpus_policy="skip")
        model = gauntlet.evaluate_target(
            manifest,
            target,
            profiles,
            discoveries["a1246"],
            fixture_result=fixtures["a1246"],
            capture_result=captures["a1246"],
        )
        self.assertIsNotNone(model["passive_capture_admission"])
        self.assertFalse(model["gates"]["asic_control"]["qualifies"])
        self.assertFalse(model["production_ready"])


if __name__ == "__main__":
    unittest.main()
