#!/usr/bin/env python3
"""Adversarial tests for the S19k Phase-3 physical SafeOff verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import s19k_phase3_physical_verify as physical
import s19k_phase12_normalize as normalizer
from test_s19k_no_work_verify import (
    LIVE_SHA,
    instrument_csv,
    kv_bytes,
    normalization_config_data,
    preflight_data,
)


PLAN_DATA = b"phase3-plan-fixture\n"
PLAN = {
    "ssh_host_key_sha256": "SHA256:tvXAsrOvqpcajFIKHLOrpOgJAKl4RcK5YDTD01/OIWg"
}
BOUNDED_ID = "8" * 64


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.preflight = root / physical.PREFLIGHT_FILENAME
        self.normalization_config = root / physical.NORMALIZATION_CONFIG_FILENAME
        self.source = root / physical.SOURCE_FILENAME
        self.normalization_receipt = root / physical.NORMALIZATION_RECEIPT_FILENAME
        self.capture = root / physical.CAPTURE_FILENAME
        self.manifest = root / physical.MANIFEST_FILENAME
        self.preflight.write_bytes(preflight_data())
        self.normalization_config.write_bytes(normalization_config_data())
        self.source.write_bytes(instrument_csv())
        self.capture.write_bytes(instrument_csv())
        self.write_normalization_receipt()
        self.write_manifest()

    def write_normalization_receipt(self) -> None:
        config = json.loads(self.normalization_config.read_text(encoding="ascii"))
        receipt = normalizer._instrument_receipt_values(
            config_sha256=hashlib.sha256(self.normalization_config.read_bytes()).hexdigest(),
            config_bytes=self.normalization_config.stat().st_size,
            instrument_source_sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),
            instrument_source_bytes=self.source.stat().st_size,
            instrument_csv_sha256=hashlib.sha256(self.capture.read_bytes()).hexdigest(),
            instrument_csv_bytes=self.capture.stat().st_size,
            instrument_row_count=15,
            config=config,
        )
        self.normalization_receipt.write_bytes(
            normalizer._kv_bytes(normalizer.INSTRUMENT_ONLY_RECEIPT_KEYS, receipt)
        )

    def write_manifest(self, bounded_id: str = BOUNDED_ID) -> None:
        values = {
            "schema": physical.SCHEMA,
            "claim": "independent-terminal-safeoff-after-bounded-work",
            "plan_sha256": hashlib.sha256(PLAN_DATA).hexdigest(),
            "bounded_verification_id": bounded_id,
            "preflight_file": physical.PREFLIGHT_FILENAME,
            "preflight_sha256": hashlib.sha256(self.preflight.read_bytes()).hexdigest(),
            "preflight_bytes": str(self.preflight.stat().st_size),
            "normalization_config_file": physical.NORMALIZATION_CONFIG_FILENAME,
            "normalization_config_sha256": hashlib.sha256(
                self.normalization_config.read_bytes()
            ).hexdigest(),
            "normalization_config_bytes": str(self.normalization_config.stat().st_size),
            "instrument_source_file": physical.SOURCE_FILENAME,
            "instrument_source_sha256": hashlib.sha256(
                self.source.read_bytes()
            ).hexdigest(),
            "instrument_source_bytes": str(self.source.stat().st_size),
            "normalization_receipt_file": physical.NORMALIZATION_RECEIPT_FILENAME,
            "normalization_receipt_sha256": hashlib.sha256(
                self.normalization_receipt.read_bytes()
            ).hexdigest(),
            "normalization_receipt_bytes": str(self.normalization_receipt.stat().st_size),
            "capture_file": physical.CAPTURE_FILENAME,
            "capture_sha256": hashlib.sha256(self.capture.read_bytes()).hexdigest(),
            "capture_bytes": str(self.capture.stat().st_size),
            "common_clock_id": "scope-logic-common-clock-001",
            "rail_signal": "rail-millivolts",
            "created_utc": "2026-08-22T12:00:00Z",
            "publication": "post-run-content-manifest",
        }
        self.manifest.write_bytes(
            kv_bytes([(key, values[key]) for key in physical.MANIFEST_KEYS])
        )

    def verify(self) -> dict[str, object]:
        return physical.verify_evidence(
            self.root,
            plan=PLAN,
            plan_data=PLAN_DATA,
            bounded_result={
                "verification_id": BOUNDED_ID,
                "live_identity_sha256": LIVE_SHA,
            },
            dangerous_temp_millic=80_000,
        )


class Phase3PhysicalTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Fixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, Fixture(Path(temporary.name))

    def test_accepts_exact_preflight_and_continuous_safeoff(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = fixture.verify()
        self.assertEqual(result["bounded_verification_id"], BOUNDED_ID)
        self.assertEqual(result["capture_end_ms"], 14_000)

    def test_rejects_missing_preflight(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.preflight.unlink()
        with self.assertRaisesRegex(physical.PhysicalVerificationError, "inexact entry"):
            fixture.verify()

    def test_rejects_manifest_bound_to_another_bounded_trial(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.write_manifest("9" * 64)
        with self.assertRaisesRegex(Exception, "bounded_verification_id"):
            fixture.verify()

    def test_rejects_tail_rebound(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.capture.write_text(
            fixture.capture.read_text(encoding="ascii").replace(
                "14000,sample,300,", "14000,sample,9000,"
            ),
            encoding="ascii",
            newline="",
        )
        fixture.source.write_bytes(fixture.capture.read_bytes())
        fixture.write_normalization_receipt()
        fixture.write_manifest()
        with self.assertRaisesRegex(Exception, "rebounded"):
            fixture.verify()

    def test_rejects_raw_export_edit_even_when_manifest_is_rehashed(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.source.write_bytes(fixture.source.read_bytes().replace(b"14050", b"14051", 1))
        fixture.write_manifest()
        with self.assertRaisesRegex(Exception, "normalization.*derivation"):
            fixture.verify()

    def test_rejects_preflight_bound_to_another_miner(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.preflight.write_bytes(
            fixture.preflight.read_bytes().replace(LIVE_SHA.encode("ascii"), b"e" * 64, 1)
        )
        fixture.write_manifest()
        with self.assertRaisesRegex(Exception, "authorized_miner_identity_sha256"):
            fixture.verify()

    def test_rejects_sample_outside_reviewed_range_after_valid_replay(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        capture = fixture.capture.read_bytes().replace(b"14000,3050", b"20000,3050", 1)
        fixture.capture.write_bytes(capture)
        fixture.source.write_bytes(capture)
        fixture.write_normalization_receipt()
        fixture.write_manifest()
        with self.assertRaisesRegex(Exception, "reviewed range"):
            fixture.verify()


if __name__ == "__main__":
    unittest.main()
