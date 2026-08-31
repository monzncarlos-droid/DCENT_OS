#!/usr/bin/env python3
"""Regression tests for the ESP target registry and its release consumers."""

from __future__ import annotations

import importlib.util
import hashlib
import copy
import tempfile
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from target_matrix import (  # noqa: E402
    ROOT,
    load_manifest,
    require_valid,
    targets_for_scope,
    validate_manifest,
)
from promotion_candidate import create_descriptor, canonical_bytes  # noqa: E402
from hardware_evidence import sha256_file  # noqa: E402


def load_verifier():
    path = ROOT / "scripts" / "verify_ota_package.py"
    spec = importlib.util.spec_from_file_location("verify_ota_package", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TargetMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = load_manifest()
        require_valid(cls.data)

    def test_registry_has_every_compiled_board(self) -> None:
        self.assertEqual(len(self.data["targets"]), 37)
        self.assertEqual(len(targets_for_scope(self.data, "public")), 6)
        self.assertEqual(len(targets_for_scope(self.data, "internal")), 31)

    def test_hammer_is_fail_closed(self) -> None:
        hammer = [target for target in self.data["targets"] if target["board_target"].startswith("hammer-")]
        self.assertEqual(len(hammer), 7)
        for target in hammer:
            self.assertEqual(target["runtime_mode"], "identity-only")
            self.assertEqual(target["install_policy"], "blocked")
            self.assertEqual(target["package_policy"], "diagnostic")

    def test_hammer_can_only_leave_identity_mode_after_rail_and_thermal_blockers_close(self) -> None:
        data = copy.deepcopy(self.data)
        hammer = next(
            target for target in data["targets"] if target["board_target"] == "hammer-bc04"
        )
        hammer.update(
            runtime_mode="mining",
            install_policy="lab-only",
            package_policy="lab",
            blockers=["exact-sku-bench", "accepted-share", "ota-rollback", "sustained-soak"],
        )
        self.assertEqual(validate_manifest(data, validate_evidence=False), [])
        hammer["blockers"].append("trusted-thermal")
        self.assertTrue(
            any("trusted-thermal" in error for error in validate_manifest(data, validate_evidence=False))
        )

    def test_public_n16r8_requires_exact_receipt_production_policy(self) -> None:
        data = copy.deepcopy(self.data)
        lucky = next(
            target for target in data["targets"] if target["board_target"] == "lucky-lv08"
        )
        lucky.update(
            release_scope="public",
            support_tier="beta",
            evidence_level="host",
            install_policy="public-beta",
            package_policy="public",
        )
        self.assertTrue(
            any("public n16r8" in error for error in validate_manifest(data, validate_evidence=False))
        )

    def test_lucky_is_lab_only_without_bench_evidence(self) -> None:
        lucky = [target for target in self.data["targets"] if target["board_target"].startswith("lucky-")]
        self.assertEqual(len(lucky), 3)
        for target in lucky:
            self.assertEqual(target["evidence_level"], "none")
            self.assertEqual(target["install_policy"], "lab-only")
            self.assertIn("first-article", target["blockers"])

    def test_internal_binding_is_exact_when_explicitly_allowed(self) -> None:
        verifier = load_verifier()
        target = next(item for item in self.data["targets"] if item["board_target"] == "nerdqx")
        manifest = {
            "boardTarget": target["board_target"],
            "deviceModel": target["device_model"],
            "hardwareFamily": target["hardware_family"],
            "supportTier": target["support_tier"],
            "evidenceLevel": target["evidence_level"],
            "runtimeMode": target["runtime_mode"],
            "installPolicy": target["install_policy"],
            "packagePolicy": target["package_policy"],
            "flashLayout": target["flash_layout"],
            "productionBlockers": target["blockers"],
            "promotionReceiptId": target.get("promotion_receipt_id"),
            "promotionState": "registry",
            "promotionCandidateId": None,
            "promotionCandidateDescriptorSha256": None,
            "qualificationOnly": False,
            "hardwareEvidenceIndexSha256": hashlib.sha256(
                (ROOT / "hardware-evidence" / "index.json").read_bytes()
            ).hexdigest(),
        }
        verifier.verify_public_target_binding(manifest, True)
        manifest["promotionReceiptId"] = "forged-receipt"
        with self.assertRaises(SystemExit):
            verifier.verify_public_target_binding(manifest, True)
        manifest["promotionReceiptId"] = target.get("promotion_receipt_id")
        manifest["hardwareEvidenceIndexSha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            verifier.verify_public_target_binding(manifest, True)
        manifest["hardwareEvidenceIndexSha256"] = hashlib.sha256(
            (ROOT / "hardware-evidence" / "index.json").read_bytes()
        ).hexdigest()
        manifest["deviceModel"] = "gamma"
        with self.assertRaises(SystemExit):
            verifier.verify_public_target_binding(manifest, True)

    def test_both_partition_layouts_are_parseable(self) -> None:
        verifier = load_verifier()
        standard = verifier.read_partition_table(ROOT / "partitions.csv")
        n16r8 = verifier.read_partition_table(ROOT / "partitions-16mb.csv")
        self.assertEqual(standard["ota_0"][1], 0x300000)
        self.assertEqual(n16r8["ota_0"][1], 0x400000)

    def test_qualification_binding_is_explicit_and_descriptor_hashed(self) -> None:
        verifier = load_verifier()
        source = next(
            item for item in self.data["targets"] if item["board_target"] == "lucky-lv08"
        )
        descriptor = create_descriptor(
            self.data,
            source,
            "lucky-lv08-unit-a-20260823",
            "a" * 40,
            "1786482223",
            sha256_file(ROOT / "esp-targets.json"),
            "0.3.0",
        )
        row = descriptor["registry_row"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_bytes(canonical_bytes(descriptor))
            manifest = {
                "boardTarget": row["board_target"],
                "deviceModel": row["device_model"],
                "hardwareFamily": row["hardware_family"],
                "supportTier": row["support_tier"],
                "evidenceLevel": row["evidence_level"],
                "runtimeMode": row["runtime_mode"],
                "installPolicy": row["install_policy"],
                "packagePolicy": row["package_policy"],
                "flashLayout": row["flash_layout"],
                "productionBlockers": row["blockers"],
                "promotionReceiptId": row["promotion_receipt_id"],
                "promotionState": "qualification",
                "promotionCandidateId": descriptor["candidate_id"],
                "promotionCandidateDescriptorSha256": sha256_file(path),
                "qualificationOnly": True,
                "hardwareEvidenceIndexSha256": "b" * 64,
                "version": "0.3.0",
            }
            verifier.verify_public_target_binding(manifest, False, descriptor, path)
            manifest["promotionCandidateId"] = "forged"
            with self.assertRaises(SystemExit):
                verifier.verify_public_target_binding(manifest, False, descriptor, path)

    def test_packagers_consume_registry(self) -> None:
        shell = (ROOT / "scripts" / "package-firmware.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "package-firmware.ps1").read_text(encoding="utf-8")
        self.assertIn("target_matrix.py", shell)
        self.assertIn("esp-targets.json", powershell)
        self.assertIn("hardwareEvidenceIndexSha256", shell)
        self.assertIn("hardwareEvidenceIndexSha256", powershell)
        self.assertIn("promotionReceiptId", shell)
        self.assertIn("promotionReceiptId", powershell)
        for token in (
            "promotionState",
            "promotionCandidateId",
            "promotionCandidateDescriptorSha256",
            "qualificationOnly",
        ):
            self.assertIn(token, shell)
            self.assertIn(token, powershell)
        self.assertIn("compiled promotion receipt ID", shell)
        self.assertIn("compiled promotion receipt ID", powershell)
        self.assertNotIn("bitaxe-max) printf", shell)

    def test_release_build_paths_pin_source_date_epoch(self) -> None:
        build_rs = (ROOT / "dcentaxe" / "build.rs").read_text(encoding="utf-8")
        gauntlet = (ROOT / "scripts" / "production_gauntlet.py").read_text(encoding="utf-8")
        shell = (ROOT / "scripts" / "build-matrix.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "build-matrix.ps1").read_text(encoding="utf-8")
        self.assertIn('std::env::var("SOURCE_DATE_EPOCH")', build_rs)
        self.assertIn('env.setdefault("SOURCE_DATE_EPOCH", source_date_epoch())', gauntlet)
        self.assertIn("--candidate requires an explicit retained --dist-root", gauntlet)
        self.assertIn("export SOURCE_DATE_EPOCH", shell)
        self.assertIn("$env:SOURCE_DATE_EPOCH", powershell)
        release = (
            ROOT.parents[1] / ".github" / "workflows" / "dcentos-esp-release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("SOURCE_DATE_EPOCH=$(git log -1 --format=%ct -- .)", release)
        self.assertIn("qualification package cannot publish", release)
        self.assertNotIn('"bitaxe-max" { return', powershell)

    def test_running_workflows_consume_registry(self) -> None:
        workflows = ROOT.parents[1] / ".github" / "workflows"
        release = (workflows / "dcentos-esp-release.yml").read_text(encoding="utf-8")
        internal = (workflows / "dcentos-esp-internal-boards.yml").read_text(encoding="utf-8")
        gauntlet = (workflows / "dcentos-esp-production-gauntlet.yml").read_text(encoding="utf-8")
        self.assertIn("target_matrix.py list --scope public", release)
        self.assertIn("target_matrix.py list --scope internal", internal)
        self.assertIn("production_gauntlet.py", gauntlet)
        self.assertIn("hardware_evidence.py validate", gauntlet)
        self.assertIn("test_hardware_evidence.py", gauntlet)
        self.assertIn("test_promotion_candidate.py", gauntlet)
        self.assertIn("test_hardware_session.py", gauntlet)


if __name__ == "__main__":
    unittest.main()
