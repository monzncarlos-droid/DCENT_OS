#!/usr/bin/env python3
"""Host-only tests for signed Avalon K210 discovery bundles."""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_discovery_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_discovery_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discovery)

MANIFEST = SCRIPT.parent.parent / "gauntlet" / "k210_models.json"


def photo_png(width: int = 640, height: int = 480) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    scanline = b"\x00" + b"\x80\x80\x80" * width
    pixels = scanline * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(pixels))
        + chunk(b"IEND", b"")
    )


class K210DiscoveryReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence_root = self.root / "source-evidence"
        self.evidence_root.mkdir()
        self.private_key, self.public_key = self._new_key("observer")
        self.capture = self._capture("a1246")
        self.capture_path = self.root / "capture.json"
        self.capture_path.write_text(
            json.dumps(self.capture, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )

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

    def _capture(self, target_id: str) -> dict[str, object]:
        target = next(row for row in self.manifest["targets"] if row["id"] == target_id)
        profile = next(
            row
            for row in self.manifest["firmware_profiles"]
            if row["id"] == target["stock_profile"]
        )
        hashboard_count = int(profile["hw_list"][0].rsplit("_X", 1)[1])
        hashboard_identifiers = [
            f"hb-test-{index}" for index in range(1, hashboard_count + 1)
        ]
        evidence = []
        for index, kind in enumerate(discovery.REQUIRED_EVIDENCE_KINDS, 1):
            if kind in discovery.PHOTO_KINDS:
                method = "visual_inspection"
                media_type = "image/png"
                suffix = ".png"
                content = photo_png()
            elif kind in discovery.STOCK_RESPONSE_KINDS:
                method = "stock_read_only_management"
                media_type = "application/json"
                suffix = ".json"
                if kind == "stock_version_response":
                    content = json.dumps(
                        {
                            "STATUS": [{"Status": "S"}],
                            "VERSION": [
                                {
                                    "VERSION": profile["firmware_version"],
                                    "HWTYPE": profile["hw_list"][0],
                                    "SWTYPE": profile["sw_list"][0],
                                    "PROD": target["display_name"],
                                    "DNA": "dna-test-001",
                                    "MAC": "02:00:00:00:00:01",
                                    "UPAPI": 5,
                                }
                            ],
                        }
                    ).encode("ascii")
                else:
                    stats = {"MM Count": hashboard_count}
                    stats.update(
                        {
                            f"MM ID{module}": f"module-{module}"
                            for module in range(hashboard_count)
                        }
                    )
                    content = json.dumps(
                        {"STATUS": [{"Status": "S"}], "STATS": [stats]}
                    ).encode("ascii")
            else:
                method = "offline_record"
                media_type = "application/json"
                suffix = ".json"
                if kind == "collection_log":
                    content = json.dumps(
                        {
                            "session": "test read-only discovery",
                            "operator": "test-operator",
                            "authorization_reference": "test-authorization-read-only-001",
                            "events": [
                                {
                                    "time_utc": "2026-08-23T15:05:00Z",
                                    "event": "completed deenergized_visual_inspection_power_down, visual_identity_inspection, closed_chassis_stock_power_restoration, and stock_read_only_management_queries",
                                }
                            ],
                            "stopped_reason": None,
                            "anomalies": [],
                        }
                    ).encode("ascii")
                else:
                    content = json.dumps(
                        {
                            "hashboard_count": hashboard_count,
                            "hashboard_identifiers": hashboard_identifiers,
                        }
                    ).encode("ascii")
            path = f"records/{kind}{suffix}"
            source = self.evidence_root / Path(path)
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(content)
            evidence.append(
                {
                    "acquired_at_utc": "2026-08-23T15:05:00Z",
                    "id": f"e{index:02d}-{kind.replace('_', '-')}",
                    "kind": kind,
                    "media_type": media_type,
                    "method": method,
                    "path": path,
                    "redaction": "none",
                }
            )
        return {
            "actions_performed": dict(discovery.ACTIONS_PERFORMED),
            "authorization": {
                "authorized_actions": sorted(discovery.AUTHORIZED_ACTIONS),
                "operator_reference": "test-authorization-read-only-001",
                "valid_from_utc": "2026-08-23T15:00:00Z",
                "valid_until_utc": "2026-08-23T15:30:00Z",
            },
            "capture_session_id": "7b624544-cb80-4bd1-9e58-c97a9d8d1559",
            "evidence": evidence,
            "identity": {
                "asic_family": profile["asic_family"],
                "controller_board_model": "MM_TEST_K210",
                "controller_board_revision": "rev-test",
                "controller_serial": "controller-test-001",
                "controller_soc": "K210",
                "cooling_class": "air",
                "cooling_controller": "fan-controller-test",
                "fan_or_pump_count": 4,
                "hashboard_count": hashboard_count,
                "hashboard_identifiers": hashboard_identifiers,
                "manufacturer": "Canaan",
                "marketing_model": target["display_name"],
                "miner_serial": "miner-test-001",
                "psu_model": "PSU-TEST",
                "psu_rated_watts": 3500,
                "psu_serial": "psu-test-001",
                "stock_dna": "dna-test-001",
                "stock_firmware_version": profile["firmware_version"],
                "stock_hwtype": profile["hw_list"][0],
                "stock_swtype": profile["sw_list"][0],
            },
            "kind": discovery.CAPTURE_KIND,
            "observed_at_utc": "2026-08-23T15:10:00Z",
            "observer_id": "test-observer",
            "schema_version": discovery.SCHEMA_VERSION,
            "scope": discovery.SCOPE,
            "target_id": target_id,
            "unit_label": f"{target_id}-test-unit",
        }

    def _bundle(self) -> Path:
        bundle = self.root / "bundle"
        discovery.create_bundle(
            self.manifest,
            self.capture_path,
            self.evidence_root,
            self.private_key,
            bundle,
        )
        return bundle

    def test_signed_bundle_round_trip_is_canonical_and_non_authorizing(self) -> None:
        bundle = self._bundle()
        result = discovery.verify_bundle(self.manifest, bundle, self.public_key)
        self.assertEqual(result["state"], "verified_signed_exact_unit_discovery")
        self.assertEqual(result["target_id"], "a1246")
        self.assertTrue(result["identity_gate_eligible"])
        self.assertTrue(result["evidence_semantics_verified"])
        self.assertEqual(result["variant_profile_id"], "a1246-a3200lc-2hash")
        self.assertEqual(result["variant_asic_family"], "A3200LC-Plus")
        self.assertEqual(result["variant_hashboard_count"], 2)
        self.assertFalse(result["authority_granted"])
        receipt_raw = (bundle / discovery.RECEIPT_NAME).read_bytes()
        receipt = json.loads(receipt_raw)
        self.assertEqual(receipt_raw, discovery.canonical_json_bytes(receipt))
        self.assertEqual(receipt["authority_ceiling"], discovery.AUTHORITY_CEILING)
        self.assertEqual(
            receipt["actions_performed"], discovery.ACTIONS_PERFORMED
        )
        self.assertEqual(
            result["observer_key_id_sha256"],
            discovery.inspect_public_key(self.public_key)["key_id_sha256"],
        )

    def test_evidence_mutation_is_rejected(self) -> None:
        bundle = self._bundle()
        evidence_path = next((bundle / discovery.EVIDENCE_DIRECTORY).rglob("*.png"))
        evidence_path.write_bytes(evidence_path.read_bytes() + b"tamper")
        with self.assertRaisesRegex(
            discovery.DiscoveryError, "digest or size mismatch"
        ):
            discovery.verify_bundle(self.manifest, bundle, self.public_key)

    def test_signature_mutation_and_wrong_key_are_rejected(self) -> None:
        bundle = self._bundle()
        _, wrong_public = self._new_key("wrong-observer")
        with self.assertRaisesRegex(discovery.DiscoveryError, "trusted observer key"):
            discovery.verify_bundle(self.manifest, bundle, wrong_public)
        signature = bundle / discovery.SIGNATURE_NAME
        raw = bytearray(signature.read_bytes())
        offset = raw.find(b"U1NI")
        self.assertGreaterEqual(offset, 0)
        raw[offset] = ord("V")
        signature.write_bytes(raw)
        with self.assertRaisesRegex(discovery.DiscoveryError, "verification failed"):
            discovery.verify_bundle(self.manifest, bundle, self.public_key)

    def test_noncanonical_receipt_is_rejected_before_signature(self) -> None:
        bundle = self._bundle()
        receipt_path = bundle / discovery.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="ascii")
        with self.assertRaisesRegex(discovery.DiscoveryError, "not canonical JSON"):
            discovery.verify_bundle(self.manifest, bundle, self.public_key)

    def test_extra_bundle_member_is_rejected(self) -> None:
        bundle = self._bundle()
        (bundle / "unsigned-note.txt").write_text("confusing extra", encoding="ascii")
        with self.assertRaisesRegex(
            discovery.DiscoveryError, "member set is not exact"
        ):
            discovery.verify_bundle(self.manifest, bundle, self.public_key)

    def test_mutation_claim_or_missing_evidence_is_rejected(self) -> None:
        self.capture["actions_performed"]["firmware_written"] = True
        with self.assertRaisesRegex(discovery.DiscoveryError, "no mutations"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )
        self.capture = self._capture("a1246")
        self.capture["evidence"].pop()
        with self.assertRaisesRegex(discovery.DiscoveryError, "missing"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )

    def test_power_transition_and_exact_phase_authority_are_mandatory(self) -> None:
        self.capture["actions_performed"]["power_state_changed"] = False
        with self.assertRaisesRegex(discovery.DiscoveryError, "power transition"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )
        self.capture = self._capture("a1246")
        self.capture["authorization"]["authorized_actions"].remove(
            "closed_chassis_stock_power_restoration"
        )
        with self.assertRaisesRegex(discovery.DiscoveryError, "four exact"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )

    def test_collection_log_rejects_unknown_stop_fields_and_faults(self) -> None:
        log_path = self.evidence_root / "records" / "collection_log.json"
        log = json.loads(log_path.read_text(encoding="ascii"))
        log["deviations_or_stops"] = ["hidden stop"]
        log_path.write_text(json.dumps(log), encoding="ascii")
        with self.assertRaisesRegex(discovery.DiscoveryError, "keys invalid"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )

        log.pop("deviations_or_stops")
        log["anomalies"] = [
            {
                "code": "fan_failure",
                "command": "stats",
                "detail": "fan stopped",
                "severity": "fault",
            }
        ]
        log_path.write_text(json.dumps(log), encoding="ascii")
        with self.assertRaisesRegex(discovery.DiscoveryError, "validation fault"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )

    def test_corrupt_png_and_jpeg_photo_payloads_fail_closed(self) -> None:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return (
                struct.pack(">I", len(payload))
                + kind
                + payload
                + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
            )

        corrupt_png = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", b"not-a-zlib-stream" * 8)
            + chunk(b"IEND", b"")
        )
        with self.assertRaisesRegex(discovery.DiscoveryError, "IDAT stream"):
            discovery._inspect_photo(
                corrupt_png, "controller_front_photo", "image/png"
            )

        fake_jpeg = b"\xff\xd8" + b"plausible-but-not-decoded" * 12 + b"\xff\xd9"
        with self.assertRaisesRegex(discovery.DiscoveryError, "canonical image/png"):
            discovery._inspect_photo(
                fake_jpeg, "controller_front_photo", "image/jpeg"
            )

    def test_family_row_cannot_receive_an_exact_unit_receipt(self) -> None:
        capture = self._capture("a1246")
        family = next(row for row in self.manifest["targets"] if row["id"] == "a14xi")
        capture["target_id"] = "a14xi"
        capture["identity"]["marketing_model"] = family["display_name"]
        capture["identity"]["asic_family"] = family["asic_family"]
        with self.assertRaisesRegex(discovery.DiscoveryError, "physical-model row"):
            discovery.build_receipt(
                self.manifest, capture, self.evidence_root, self.private_key
            )

    def test_physical_row_with_unknown_asic_cannot_receive_a_receipt(self) -> None:
        with self.assertRaisesRegex(discovery.DiscoveryError, "no exact ASIC family"):
            discovery._template(self.manifest, "a1446")

    def test_recorded_authorization_chronology_is_strict(self) -> None:
        self.capture["observed_at_utc"] = "2026-08-23T16:00:00Z"
        with self.assertRaisesRegex(discovery.DiscoveryError, "authorization interval"):
            discovery.build_receipt(
                self.manifest, self.capture, self.evidence_root, self.private_key
            )


def semantic_capture_fixture(
    manifest: dict[str, object], evidence_root: Path, target_id: str = "a1246"
) -> dict[str, object]:
    """Build the shared semantically valid upstream discovery test fixture."""

    fixture = K210DiscoveryReceiptTests(methodName="runTest")
    fixture.manifest = manifest
    fixture.evidence_root = evidence_root
    return fixture._capture(target_id)


if __name__ == "__main__":
    unittest.main()
