#!/usr/bin/env python3
"""Adversarial tests for deterministic S19k Phase-1/Phase-2 bundle preparation."""

from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import s19k_no_work_prepare as preparer  # noqa: E402
import s19k_no_work_verify as verifier  # noqa: E402
from test_s19k_no_work_verify import EvidenceFixture  # noqa: E402


@unittest.skipUnless(os.name == "posix", "bundle publication requires Linux/WSL")
class BundlePreparationTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], EvidenceFixture, Path]:
        temporary = tempfile.TemporaryDirectory()
        fixture = EvidenceFixture(Path(temporary.name))
        return temporary, fixture, fixture.root / "sealed-phase12-bundle"

    def prepare(self, fixture: EvidenceFixture, output: Path) -> dict[str, object]:
        return preparer.prepare(
            plan_path=fixture.plan,
            trial_dir=fixture.trial,
            preflight=fixture.preflight,
            normalization_config=fixture.normalization_config,
            normalization_receipt=fixture.normalization_receipt,
            instrument_source=fixture.instrument_source,
            instrument_csv=fixture.instrument_canonical,
            uart_source=fixture.uart_source,
            uart_csv=fixture.uart_canonical,
            capture_contract=fixture.capture_contract,
            capture_blocks=fixture.capture_blocks,
            capture_verification=fixture.capture_verification,
            common_clock_id="scope-logic-common-clock-001",
            rail_signal="rail-millivolts",
            created_utc="2026-08-22T12:00:00Z",
            output_dir=output,
        )

    def test_prepares_exact_self_verifying_v2_bundle(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = self.prepare(fixture, output)
        fresh = verifier.verify(fixture.plan, fixture.trial, output)
        self.assertEqual(result, fresh)
        self.assertEqual(
            {entry.name for entry in output.iterdir()},
            {
                *preparer.FIXED_FILES.values(),
                "phase12_instrument_manifest",
                verifier.EMBEDDED_RESULT_FILENAME,
                verifier.BUNDLE_RECEIPT_FILENAME,
            },
        )
        for entry in output.iterdir():
            self.assertTrue(entry.is_file())
            self.assertFalse(entry.is_symlink())
            self.assertEqual(entry.stat().st_nlink, 1)

    def test_cli_publishes_both_required_success_sentinels(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = preparer.main(
                [
                    "--plan",
                    str(fixture.plan),
                    "--trial-dir",
                    str(fixture.trial),
                    "--preflight",
                    str(fixture.preflight),
                    "--normalization-config",
                    str(fixture.normalization_config),
                    "--normalization-receipt",
                    str(fixture.normalization_receipt),
                    "--instrument-source",
                    str(fixture.instrument_source),
                    "--instrument-csv",
                    str(fixture.instrument_canonical),
                    "--uart-source",
                    str(fixture.uart_source),
                    "--uart-csv",
                    str(fixture.uart_canonical),
                    "--capture-contract",
                    str(fixture.capture_contract),
                    "--capture-blocks",
                    str(fixture.capture_blocks),
                    "--capture-verification",
                    str(fixture.capture_verification),
                    "--common-clock-id",
                    "scope-logic-common-clock-001",
                    "--rail-signal",
                    "rail-millivolts",
                    "--created-utc",
                    "2026-08-22T12:00:00Z",
                    "--output-dir",
                    str(output),
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("S19K_PHASE12_NO_WORK_OK", stdout.getvalue())
        self.assertIn("S19K_PHASE12_BUNDLE_OK", stdout.getvalue())
        verifier.verify(fixture.plan, fixture.trial, output)

    def test_refuses_existing_output_without_clobbering_it(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        output.mkdir()
        marker = output / "operator-data"
        marker.write_text("preserve\n", encoding="ascii")
        with self.assertRaisesRegex(preparer.PreparationError, "already exists"):
            self.prepare(fixture, output)
        self.assertEqual(marker.read_text(encoding="ascii"), "preserve\n")

    def test_refuses_source_inode_alias(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.uart_source.unlink()
        os.link(fixture.instrument_source, fixture.uart_source)
        with self.assertRaisesRegex(preparer.PreparationError, "ten distinct inodes"):
            self.prepare(fixture, output)
        self.assertFalse(output.exists())

    def test_refuses_symlink_capture_input(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        actual = fixture.root / "actual-uart.raw"
        actual.write_bytes(fixture.uart_source.read_bytes())
        fixture.uart_source.unlink()
        fixture.uart_source.symlink_to(actual)
        with self.assertRaisesRegex(preparer.PreparationError, "regular non-link"):
            self.prepare(fixture, output)
        self.assertFalse(output.exists())

    def test_refuses_semantically_unsafe_uart_capture_before_publication(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.replace_uart(
            "55AA510900280000301112",
            "55AA213600000000000000",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "forbidden 55AA2136"):
            self.prepare(fixture, output)
        self.assertFalse(output.exists())

    def test_refuses_canonical_capture_over_size_limit(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        original_limit = preparer.MAX_CANONICAL_BYTES
        preparer.MAX_CANONICAL_BYTES = 64
        self.addCleanup(setattr, preparer, "MAX_CANONICAL_BYTES", original_limit)
        with self.assertRaisesRegex(preparer.PreparationError, "64 MiB canonical"):
            self.prepare(fixture, output)
        self.assertFalse(output.exists())

    def test_refuses_noncanonical_bundle_metadata(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(preparer.PreparationError, "created UTC"):
            preparer.prepare(
                plan_path=fixture.plan,
                trial_dir=fixture.trial,
                preflight=fixture.preflight,
                normalization_config=fixture.normalization_config,
                normalization_receipt=fixture.normalization_receipt,
                instrument_source=fixture.instrument_source,
                instrument_csv=fixture.instrument_canonical,
                uart_source=fixture.uart_source,
                uart_csv=fixture.uart_canonical,
                capture_contract=fixture.capture_contract,
                capture_blocks=fixture.capture_blocks,
                capture_verification=fixture.capture_verification,
                common_clock_id="scope-logic-common-clock-001",
                rail_signal="rail-millivolts",
                created_utc="2026-08-22 12:00:00",
                output_dir=output,
            )
        self.assertFalse(output.exists())

    def test_refuses_manifest_clock_that_disagrees_with_normalization(self) -> None:
        temporary, fixture, output = self.fixture()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(preparer.PreparationError, "common clock"):
            preparer.prepare(
                plan_path=fixture.plan,
                trial_dir=fixture.trial,
                preflight=fixture.preflight,
                normalization_config=fixture.normalization_config,
                normalization_receipt=fixture.normalization_receipt,
                instrument_source=fixture.instrument_source,
                instrument_csv=fixture.instrument_canonical,
                uart_source=fixture.uart_source,
                uart_csv=fixture.uart_canonical,
                capture_contract=fixture.capture_contract,
                capture_blocks=fixture.capture_blocks,
                capture_verification=fixture.capture_verification,
                common_clock_id="another-clock",
                rail_signal="rail-millivolts",
                created_utc="2026-08-22T12:00:00Z",
                output_dir=output,
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
