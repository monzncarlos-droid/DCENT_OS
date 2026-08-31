#!/usr/bin/env python3
"""Host-only tests for signed Avalon K210 replacement-firmware evidence."""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).with_name("k210_replacement_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_replacement_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
replacement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replacement)

BOOT_TEST_SCRIPT = Path(__file__).with_name("test_k210_boot_policy_receipt.py")
BOOT_TEST_SPEC = importlib.util.spec_from_file_location(
    "k210_boot_policy_receipt_test_fixture", BOOT_TEST_SCRIPT
)
assert BOOT_TEST_SPEC is not None and BOOT_TEST_SPEC.loader is not None
boot_test = importlib.util.module_from_spec(BOOT_TEST_SPEC)
BOOT_TEST_SPEC.loader.exec_module(boot_test)
gauntlet = boot_test.gauntlet


def synthetic_elf(raw: bytes) -> bytes:
    data = bytearray(120 + len(raw))
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHI", data, 16, 2, replacement.ELF_MACHINE_RISCV, 1)
    struct.pack_into("<QQQ", data, 24, replacement.K210_LOAD_BASE, 64, 0)
    struct.pack_into("<HHHHHH", data, 52, 64, 56, 1, 0, 0, 0)
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        replacement.ELF_PT_LOAD,
        5,
        120,
        replacement.K210_LOAD_BASE,
        replacement.K210_LOAD_BASE,
        len(raw),
        len(raw),
        8,
    )
    data[120:] = raw
    return bytes(data)


class K210ReplacementReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("ssh-keygen") is None:
            raise unittest.SkipTest("OpenSSH ssh-keygen is unavailable")
        boot_test.K210BootPolicyReceiptTests.setUpClass()

    def setUp(self) -> None:
        self.fixture = boot_test.K210BootPolicyReceiptTests(methodName="runTest")
        self.fixture.setUp()
        self.fixture._make_positive()
        self.boot_bundle = self.fixture._bundle()
        self.root = self.fixture.root
        self.manifest = self.fixture.manifest
        self.boot_receipt = json.loads(
            (self.boot_bundle / replacement.boot.RECEIPT_NAME).read_text(
                encoding="ascii"
            )
        )
        self.builder_private, self.builder_public = self.fixture.fixture._new_key(
            "replacement-builder"
        )
        self.reviewer_private, self.reviewer_public = self.fixture.fixture._new_key(
            "replacement-reviewer"
        )
        self.evidence_root = self.root / "replacement-evidence"
        self.evidence_root.mkdir()
        self.descriptor = replacement._template(
            self.manifest, self.boot_bundle / replacement.boot.RECEIPT_NAME
        )
        self.descriptor["builder_id"] = "replacement-test-builder"
        self.descriptor["reviewer_id"] = "replacement-test-reviewer"
        self.descriptor["firmware"]["source_commit"] = "1" * 40
        self.descriptor_path = self.root / "replacement-descriptor.json"
        self._populate_evidence()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _write_evidence(self, evidence_id: str, content: bytes) -> None:
        item = next(
            row for row in self.descriptor["evidence"] if row["id"] == evidence_id
        )
        destination = self.evidence_root / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    def _aup(self, raw: bytes) -> bytes:
        payload = gauntlet.build_k210_plain_boot_image(raw)
        return gauntlet.build_aup_v2(
            payload,
            self.descriptor["firmware"]["firmware_version"],
            self.descriptor["board_profile"]["aup_hw_list"],
            self.descriptor["board_profile"]["aup_sw_list"],
        )

    def _populate_evidence(self) -> None:
        source = b"synthetic clean source archive\n"
        profile = b'{"target":"a1246","bsp":"test"}\n'
        self._write_evidence(
            "boot-policy-receipt",
            replacement.canonical_json_bytes(self.boot_receipt),
        )
        self._write_evidence("board-profile", profile)
        self._write_evidence("source-archive", source)
        self._write_evidence("source-manifest", b'{"clean":true}\n')
        self._write_evidence("sbom", b'{"spdxVersion":"SPDX-2.3"}\n')
        self._write_evidence("license-review", b'{"passed":true}\n')
        self._write_evidence("clean-room-review", b'{"passed":true}\n')
        source_sha = replacement.hashlib.sha256(source).hexdigest()
        profile_sha = replacement.hashlib.sha256(profile).hexdigest()
        self.descriptor["firmware"]["source_archive_sha256"] = source_sha
        self.descriptor["board_profile"]["profile_sha256"] = profile_sha
        raw = b"sentinel"
        elf = synthetic_elf(raw)
        aup = self._aup(raw)
        for index, suffix in enumerate(("a", "b")):
            self._write_evidence(
                f"build-{suffix}-log",
                json.dumps({"build": suffix, "complete": True}).encode("ascii"),
            )
            self._write_evidence(
                f"build-{suffix}-toolchain",
                json.dumps({"rust": "1.90.0", "runner": suffix}).encode("ascii"),
            )
            self._write_evidence(f"build-{suffix}-elf", elf)
            self._write_evidence(f"build-{suffix}-raw", raw)
            self._write_evidence(f"build-{suffix}-aup", aup)
            self.descriptor["builds"][index]["source_archive_sha256"] = source_sha
            self.descriptor["builds"][index]["environment_sha256"] = str(index) * 64

    def _write_descriptor(self) -> None:
        self.descriptor_path.write_text(
            json.dumps(self.descriptor, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def _bundle(self) -> Path:
        self._write_descriptor()
        bundle = self.root / "replacement-bundle"
        replacement.create_bundle(
            self.manifest,
            self.descriptor_path,
            self.evidence_root,
            self.builder_private,
            self.reviewer_private,
            bundle,
        )
        return bundle

    def test_round_trip_is_reproducible_target_bound_and_non_authorizing(self) -> None:
        result = replacement.verify_bundle(
            self.manifest,
            self._bundle(),
            self.builder_public,
            self.reviewer_public,
        )
        self.assertEqual(result["state"], "verified_signed_replacement_firmware")
        self.assertTrue(result["replacement_firmware_gate_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["target_id"], "a1246")
        self.assertEqual(
            result["boot_policy_receipt_id"], self.boot_receipt["receipt_id"]
        )
        self.assertEqual(
            result["raw_sha256"], replacement.hashlib.sha256(b"sentinel").hexdigest()
        )

    def test_template_is_positive_boot_bound_and_defaults_fail_closed(self) -> None:
        self.assertEqual(
            self.descriptor["boot_policy_receipt_id"], self.boot_receipt["receipt_id"]
        )
        self.assertEqual(
            self.descriptor["board_profile"]["capabilities"],
            list(replacement.REQUIRED_BSP_CAPABILITIES),
        )
        self.assertEqual(
            self.descriptor["board_profile"]["default_posture"],
            replacement.SAFE_DEFAULTS,
        )

    def test_independent_build_bytes_must_match(self) -> None:
        raw = b"variant!"
        self._write_evidence("build-b-elf", synthetic_elf(raw))
        self._write_evidence("build-b-raw", raw)
        self._write_evidence("build-b-aup", self._aup(raw))
        with self.assertRaisesRegex(replacement.ReplacementError, "byte-identical"):
            replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )

    def test_sentinel_class_and_restricted_code_claims_are_rejected(self) -> None:
        self.descriptor["firmware"]["firmware_class"] = "safe_idle_pipeline_sentinel"
        with self.assertRaisesRegex(replacement.ReplacementError, "firmware class"):
            replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )
        self.descriptor["firmware"]["firmware_class"] = "target_bound_safe_idle_runtime"
        self.descriptor["firmware"]["restricted_vendor_code_included"] = True
        with self.assertRaisesRegex(replacement.ReplacementError, "must be false"):
            replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )

    def test_bsp_capabilities_and_boot_join_are_exact(self) -> None:
        self.descriptor["board_profile"]["capabilities"].pop()
        with self.assertRaisesRegex(replacement.ReplacementError, "exact BSP set"):
            replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )
        self.descriptor["board_profile"]["capabilities"] = list(
            replacement.REQUIRED_BSP_CAPABILITIES
        )
        self.descriptor["boot_policy_receipt_id"] = "0" * 64
        with self.assertRaisesRegex(replacement.ReplacementError, "does not match"):
            replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.reviewer_private,
            )

    def test_wrong_key_tamper_extra_member_and_same_role_key_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            replacement.ReplacementError, "keys must be distinct"
        ):
            replacement.build_receipt(
                self.manifest,
                self.descriptor,
                self.evidence_root,
                self.builder_private,
                self.builder_private,
            )
        bundle = self._bundle()
        _, wrong_public = self.fixture.fixture._new_key("wrong-replacement-reviewer")
        with self.assertRaisesRegex(
            replacement.ReplacementError, "reviewer signer is not trusted"
        ):
            replacement.verify_bundle(
                self.manifest, bundle, self.builder_public, wrong_public
            )
        review = (
            bundle / replacement.EVIDENCE_DIRECTORY / "review" / "license-review.json"
        )
        review.write_bytes(b'{"tampered":true}\n')
        with self.assertRaisesRegex(
            replacement.ReplacementError, "digest or size mismatch"
        ):
            replacement.verify_bundle(
                self.manifest, bundle, self.builder_public, self.reviewer_public
            )
        review.write_bytes(b'{"passed":true}\n')
        (bundle / "unsigned-note.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(
            replacement.ReplacementError, "member set is not exact"
        ):
            replacement.verify_bundle(
                self.manifest, bundle, self.builder_public, self.reviewer_public
            )

    def test_gauntlet_rejects_legacy_aes0_contract_after_route_migration(self) -> None:
        manifest = deepcopy(self.manifest)
        manifest["replacement_firmware_contract"].update(
            {
                "verifier": (
                    "DCENT_OS_AvalonMiner/scripts/"
                    "k210_replacement_receipt.py"
                ),
                "receipt_schema_version": replacement.SCHEMA_VERSION,
                "receipt_kind": replacement.RECEIPT_KIND,
                "signature_algorithm": replacement.SIGNATURE_ALGORITHM,
                "required_evidence_kinds": sorted(replacement.EVIDENCE_KINDS),
                "roles": {
                    "builder": {
                        "role": replacement.BUILDER_ROLE,
                        "namespace": replacement.BUILDER_NAMESPACE,
                    },
                    "reviewer": {
                        "role": replacement.REVIEWER_ROLE,
                        "namespace": replacement.REVIEWER_NAMESPACE,
                    },
                },
                "state": "dual_signed_schema_no_trust_anchors",
                "trust_anchors": {
                    "builder": None,
                    "reviewer": None,
                },
            }
        )
        with self.assertRaisesRegex(
            gauntlet.GauntletError, "replacement-firmware verifier path drifted"
        ):
            gauntlet.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
