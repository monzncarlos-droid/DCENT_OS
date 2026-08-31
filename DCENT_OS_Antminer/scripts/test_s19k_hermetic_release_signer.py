#!/usr/bin/env python3
"""Adversarial tests for the equality-gated S19k release signer."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_s19k_persistent_image_verify import Fixture, image


SCRIPT = Path(__file__).with_name("s19k_hermetic_release_signer.py")
SPEC = importlib.util.spec_from_file_location("s19k_hermetic_release_signer_test", SCRIPT)
assert SPEC and SPEC.loader
signer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = signer
SPEC.loader.exec_module(signer)


class SignerFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "public-evidence"
        self.evidence.mkdir()
        self.package = Fixture(self.evidence)
        self.private_key = root / "release-private.pem"
        private_raw = self.package.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.private_key.write_bytes(private_raw)
        self.private_key.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.output = root / "signed-stage"

    def call(self) -> signer.SigningResult:
        return signer.sign_equal_unsigned_pair(
            self.evidence / image.BUILD_PACKAGE_FILES[0],
            self.evidence / image.BUILD_PACKAGE_FILES[1],
            self.evidence / image.BUILD_RECEIPT_FILES[0],
            self.evidence / image.BUILD_RECEIPT_FILES[1],
            self.evidence / image.TRUSTED_KEY_FILE,
            self.evidence / image.NATIVE_RECEIPT_FILE,
            self.evidence / image.RECOVERY_RECEIPT_FILE,
            self.private_key,
            self.output,
            expected_release_key_sha256=self.package.expected_key_sha,
            verifier=image,
            strict_durability=False,
        )


class HermeticReleaseSignerTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory, SignerFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, SignerFixture(Path(temporary.name))

    def test_signs_only_after_equal_public_pair_and_emits_v4_evidence(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            with mock.patch.object(
                signer,
                "_read_private_key_once",
                wraps=signer._read_private_key_once,
            ) as private_open:
                result = fixture.call()
            self.assertEqual(private_open.call_count, 1)
            self.assertEqual(
                {entry.name for entry in result.stage.iterdir()},
                {image.SIGNED_PACKAGE_FILE, image.SIGNING_RECEIPT_FILE},
            )
            receipt_raw = result.receipt.read_bytes()
            receipt = json.loads(receipt_raw)
            self.assertEqual(set(receipt), set(image.SIGNING_RECEIPT_KEYS))
            self.assertEqual(receipt["private_key_open_count"], 1)
            self.assertTrue(receipt["a_b_equality_verified_before_private_key_open"])
            self.assertTrue(receipt["public_inputs_verified_before_private_key_open"])
            self.assertFalse(receipt["network_used"])
            self.assertFalse(receipt["install_authority_granted"])
            self.assertFalse(receipt["flash_authority_granted"])
            self.assertFalse(receipt["mutation_authority_granted"])

            unsigned = image._parse_package(
                (fixture.evidence / image.BUILD_PACKAGE_FILES[0]).read_bytes(),
                image.BUILD_PACKAGE_FILES[0],
                signature_required=False,
            )
            signed = image._parse_package(
                result.package.read_bytes(),
                image.SIGNED_PACKAGE_FILE,
                signature_required=True,
            )
            image._verify_signed_derivation(
                unsigned, signed, source_date_epoch=fixture.package.manifest[
                    "provenance"
                ]["source_date_epoch"]
            )
            shutil.copy2(result.package, fixture.evidence / image.SIGNED_PACKAGE_FILE)
            shutil.copy2(result.receipt, fixture.evidence / image.SIGNING_RECEIPT_FILE)
            verified = image.verify_evidence(
                fixture.evidence,
                expected_release_key_sha256=fixture.package.expected_key_sha,
            )
            self.assertEqual(verified["schema"], image.RESULT_SCHEMA)
            self.assertTrue(verified["private_key_excluded_from_builds"])
            self.assertFalse(verified["isolated_post_ab_signing_verified"])
            self.assertTrue(
                verified["post_ab_derivation_and_runtime_metadata_verified"]
            )

    def test_every_public_or_output_failure_precedes_private_key_open(self) -> None:
        cases = (
            "ab-drift",
            "receipt-drift",
            "public-key-drift",
            "output-exists",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = SignerFixture(Path(temporary))
                if case == "ab-drift":
                    path = fixture.evidence / image.BUILD_PACKAGE_FILES[1]
                    path.write_bytes(path.read_bytes() + b"drift")
                elif case == "receipt-drift":
                    path = fixture.evidence / image.BUILD_RECEIPT_FILES[0]
                    receipt = json.loads(path.read_text())
                    receipt["network_used"] = True
                    path.write_bytes(image.canonical_json(receipt))
                elif case == "public-key-drift":
                    other = Ed25519PrivateKey.generate().public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    (fixture.evidence / image.TRUSTED_KEY_FILE).write_bytes(other)
                else:
                    fixture.output.mkdir()
                with mock.patch.object(
                    signer, "_read_private_key_once"
                ) as private_open, self.assertRaises(signer.SigningError):
                    fixture.call()
                private_open.assert_not_called()

    def test_mismatched_private_key_fails_without_published_output(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            other = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            fixture.private_key.write_bytes(other)
            fixture.private_key.chmod(stat.S_IRUSR | stat.S_IWUSR)
            with self.assertRaisesRegex(signer.SigningError, "does not match"):
                fixture.call()
            self.assertFalse(fixture.output.exists())

    def test_source_has_no_network_install_flash_or_target_primitives(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import subprocess",
            "requests.",
            "paramiko",
            "flash_erase",
            "nandwrite",
            "fw_setenv",
            "reboot(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

        self.assertNotIn("install_authority_granted\": True", source)
        self.assertNotIn("flash_authority_granted\": True", source)
        self.assertNotIn("mutation_authority_granted\": True", source)


if __name__ == "__main__":
    unittest.main()
