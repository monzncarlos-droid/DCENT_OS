#!/usr/bin/env python3
"""Desk-only tests for the exact-scope K210 release capstone."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("k210_release_receipt.py")
SPEC = importlib.util.spec_from_file_location("k210_release_receipt", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {MODULE_PATH}")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is required")
class ReleaseReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_temp = tempfile.TemporaryDirectory()
        cls.key_root = Path(cls.class_temp.name) / "keys"
        cls.key_root.mkdir()
        cls.keys = {}
        for role in ("preauthorizer", "reviewer", "installer", "witness"):
            key = cls.key_root / role
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    f"k210-release-{role}",
                    "-f",
                    str(key),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            cls.keys[role] = key

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_temp.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=self.class_temp.name)
        self.root = Path(self.temp.name)
        self.endurance = self.root / "endurance"
        self.endurance.mkdir()
        self.endurance_receipt = self._endurance_receipt()
        self._write_json(self.endurance / release.stage.RECEIPT_NAME, self.endurance_receipt)
        (self.endurance / "operator.sig").write_text("test fixture\n", encoding="ascii")
        self.stage_result = self._stage_result(self.endurance_receipt)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(release.canonical_json_bytes(value))

    @staticmethod
    def _endurance_receipt() -> dict[str, object]:
        return {
            "boot_policy_receipt_id": _digest("boot"),
            "capture_receipt_id": _digest("capture"),
            "capture_set_sha256": _digest("capture-set"),
            "completed_at_utc": "2026-01-01T01:00:00Z",
            "controller_board_revision": "a1246-controller-rev-a",
            "discovery_receipt_id": _digest("discovery"),
            "evidence_set_sha256": _digest("endurance-set"),
            "fixture_evidence_set_sha256": _digest("fixture-set"),
            "fixture_receipt_id": _digest("fixture"),
            "installed_artifact_sha256": _digest("installed-artifact"),
            "outcome": "passed",
            "prior_stage_evidence_set_sha256": _digest("bench-set"),
            "prior_stage_receipt_id": _digest("bench"),
            "qualification_class": release.stage.QUALIFICATION_ENDURANCE,
            "receipt_id": _digest("endurance"),
            "recovery_receipt_id": _digest("recovery"),
            "artifact_set_sha256": _digest("replacement-set"),
            "interface_qualification_sha256": _digest("interface-qualification"),
            "no_clobber_sha256": _digest("no-clobber"),
            "replacement_firmware_version": "dcent-k210-1.0.0",
            "results": {"endurance_faults": {"eligible": True}},
            "route_replacement_receipt_id": _digest("route-replacement"),
            "route_rollback_receipt_id": _digest("route-rollback"),
            "route_adjudication_sha256": _digest("route-adjudication"),
            "selected_route": "rom_isp_sram_bootstrap",
            "stock_backup_set_sha256": _digest("stock-backup"),
            "stock_restoration_sha256": _digest("stock-restoration"),
            "target_id": "avalon-a1246",
            "unit_fingerprint_sha256": _digest("unit-fingerprint"),
            "unit_label": "a1246-unit-01",
            "variant_profile_id": "a1246-k210-rev-a",
        }

    @staticmethod
    def _stage_result(receipt: dict[str, object]) -> dict[str, object]:
        result = {
            "authority_granted": False,
            "endurance_faults_gate_eligible": True,
            "evidence_set_sha256": receipt["evidence_set_sha256"],
            "outcome": "passed",
            "qualification_class": release.stage.QUALIFICATION_ENDURANCE,
            "receipt_id": receipt["receipt_id"],
            "target_id": receipt["target_id"],
            "unit_fingerprint_sha256": receipt["unit_fingerprint_sha256"],
            "variant_profile_id": receipt["variant_profile_id"],
        }
        for field in (
            "boot_policy_receipt_id",
            "capture_receipt_id",
            "capture_set_sha256",
            "controller_board_revision",
            "discovery_receipt_id",
            "fixture_evidence_set_sha256",
            "fixture_receipt_id",
            "installed_artifact_sha256",
            "prior_stage_evidence_set_sha256",
            "prior_stage_receipt_id",
            "recovery_receipt_id",
            "artifact_set_sha256",
            "interface_qualification_sha256",
            "no_clobber_sha256",
            "replacement_firmware_version",
            "route_replacement_receipt_id",
            "route_rollback_receipt_id",
            "route_adjudication_sha256",
            "selected_route",
            "stock_backup_set_sha256",
            "stock_restoration_sha256",
            "unit_label",
        ):
            result[field] = receipt[field]
        return result

    @contextlib.contextmanager
    def _verified_stage(self, result: dict[str, object] | None = None):
        with mock.patch.object(
            release.stage,
            "verify_bundle",
            return_value=self.stage_result if result is None else result,
        ), mock.patch.object(release.stage, "_validate_receipt", return_value=None):
            yield

    def _make_preauthorization(self) -> tuple[Path, dict[str, object]]:
        with self._verified_stage():
            _, chain = release._stage_chain(
                {},
                self.endurance,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
            )
        descriptor = release._preauthorization_template(chain)
        descriptor["preauthorizer_id"] = "release-preauthorizer"
        descriptor["reviewer_id"] = "release-reviewer"
        descriptor_path = self.root / "preauthorization-descriptor.json"
        self._write_json(descriptor_path, descriptor)
        bundle = self.root / "preauthorization"
        value = release.create_preauthorization_bundle(
            descriptor_path,
            self.keys["preauthorizer"],
            self.keys["reviewer"],
            bundle,
        )
        return bundle, value

    @staticmethod
    def _evidence_records(
        preauthorization: dict[str, object], descriptor: dict[str, object]
    ) -> dict[str, dict[str, object]]:
        scope = preauthorization["release_scope"]
        chain = preauthorization["predecessor_chain"]
        return {
            "artifact_custody_record": {
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "custody_complete": True,
                "custody_log_sha256": _digest("custody-log"),
                "firmware_version": scope["firmware_version"],
                "kind": "dcent_k210_release_artifact_custody",
                "route_replacement_receipt_id": scope[
                    "route_replacement_receipt_id"
                ],
                "unexplained_gaps": [],
            },
            "artifact_signing_record": {
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "builder_key_id_sha256": _digest("builder-key"),
                "kind": "dcent_k210_release_artifact_signing_review",
                "route_replacement_receipt_id": scope[
                    "route_replacement_receipt_id"
                ],
                "reviewer_key_id_sha256": _digest("artifact-reviewer-key"),
                "signatures_verified": True,
            },
            "install_execution_record": {
                "actions_performed": sorted(release.PERMITTED_ACTIONS),
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "completed_at_utc": descriptor["completed_at_utc"],
                "errors": [],
                "full_readback_matches": True,
                "installed_artifact_sha256": scope["installed_artifact_sha256"],
                "kind": "dcent_k210_release_install_execution",
                "preauthorization_id": preauthorization["preauthorization_id"],
                "started_at_utc": descriptor["started_at_utc"],
                "unauthorized_actions_performed": False,
                "unit_fingerprint_sha256": scope["unit_fingerprint_sha256"],
            },
            "license_review_record": {
                "approved": True,
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "kind": "dcent_k210_release_license_review",
                "restricted_vendor_code_included": False,
                "review_sha256": _digest("license-review"),
            },
            "postinstall_acceptance_record": {
                "accepted": True,
                "anomalies": [],
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "boot_succeeded": True,
                "firmware_version": scope["firmware_version"],
                "kind": "dcent_k210_release_postinstall_acceptance",
                "rollback_ready": True,
                "runtime_identity_matches": True,
                "safety_controls_ready": True,
                "target_id": scope["target_id"],
                "telemetry_ready": True,
                "unit_fingerprint_sha256": scope["unit_fingerprint_sha256"],
            },
            "reproducibility_record": {
                "artifact_bytes_match": True,
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "build_inputs_pinned": True,
                "independent_build_count": 2,
                "kind": "dcent_k210_release_reproducibility_review",
                "source_archive_sha256": _digest("source-archive"),
            },
            "restore_runbook_record": {
                "kind": "dcent_k210_release_restore_runbook",
                "runbook_sha256": _digest("restore-runbook"),
                "selected_route": scope["selected_route"],
                "stock_backup_set_sha256": chain["stock_backup_set_sha256"],
                "tested": True,
            },
            "sbom_record": {
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "complete": True,
                "kind": "dcent_k210_release_sbom_review",
                "sbom_sha256": _digest("sbom"),
            },
            "upgrade_runbook_record": {
                "artifact_set_sha256": scope["artifact_set_sha256"],
                "kind": "dcent_k210_release_upgrade_runbook",
                "rollback_on_failure": True,
                "runbook_sha256": _digest("upgrade-runbook"),
                "selected_route": scope["selected_route"],
                "tested": True,
            },
        }

    def _release_inputs(self):
        preauth_bundle, preauthorization = self._make_preauthorization()
        descriptor = release._release_template(preauthorization)
        descriptor["installer_id"] = "release-installer"
        descriptor["witness_id"] = "release-install-witness"
        evidence_root = self.root / "release-evidence"
        records = self._evidence_records(preauthorization, descriptor)
        for item in descriptor["evidence"]:
            self._write_json(evidence_root / item["path"], records[item["kind"]])
        descriptor_path = self.root / "release-descriptor.json"
        self._write_json(descriptor_path, descriptor)
        return preauth_bundle, preauthorization, descriptor_path, descriptor, evidence_root

    def _create_release(self):
        inputs = self._release_inputs()
        preauth_bundle, _, descriptor_path, _, evidence_root = inputs
        bundle = self.root / "release-bundle"
        with self._verified_stage():
            release.create_bundle(
                {},
                descriptor_path,
                evidence_root,
                preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                self.endurance,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                self.keys["installer"],
                self.keys["witness"],
                bundle,
            )
        return bundle, inputs

    def _verify_release(self, bundle: Path) -> dict[str, object]:
        with self._verified_stage():
            return release.verify_bundle(
                {},
                bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                self.keys["installer"].with_suffix(".pub"),
                self.keys["witness"].with_suffix(".pub"),
            )

    def test_standalone_preauthorization_is_exact_scope_only(self) -> None:
        bundle, preauthorization = self._make_preauthorization()
        result = release.verify_preauthorization(
            bundle,
            self.keys["preauthorizer"].with_suffix(".pub"),
            self.keys["reviewer"].with_suffix(".pub"),
        )
        self.assertTrue(result["install_authority_scope_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertFalse(result["generic_future_authority_granted"])
        self.assertEqual(result["actions"], sorted(release.PERMITTED_ACTIONS))
        self.assertEqual(
            result["unit_fingerprint_sha256"],
            preauthorization["release_scope"]["unit_fingerprint_sha256"],
        )
        self.assertRegex(result["release_scope_sha256"], r"^[0-9a-f]{64}$")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = release.main(
                [
                    "verify-preauthorization",
                    "--bundle",
                    str(bundle),
                    "--preauthorizer-public-key",
                    str(self.keys["preauthorizer"].with_suffix(".pub")),
                    "--reviewer-public-key",
                    str(self.keys["reviewer"].with_suffix(".pub")),
                ]
            )
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(out.getvalue())["install_authority_scope_eligible"])

    def test_completed_capstone_exact_joins_and_is_non_generic(self) -> None:
        bundle, inputs = self._create_release()
        result = self._verify_release(bundle)
        self.assertTrue(result["release_authority_gate_eligible"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["state"], release.RELEASE_RESULT["state"])
        self.assertEqual(
            result["preauthorization_id"], inputs[1]["preauthorization_id"]
        )
        receipt = json.loads((bundle / release.RECEIPT_NAME).read_text("utf-8"))
        self.assertFalse(receipt["authority_ceiling"]["authorizes_generic_future_install"])
        self.assertFalse(receipt["authority_ceiling"]["authorizes_unscoped_release"])

    def test_self_approval_and_key_reuse_are_rejected(self) -> None:
        with self._verified_stage():
            _, chain = release._stage_chain(
                {}, self.endurance, Path("unused"), Path("unused")
            )
        descriptor = release._preauthorization_template(chain)
        descriptor["preauthorizer_id"] = "same-principal"
        descriptor["reviewer_id"] = "same-principal"
        with self.assertRaisesRegex(release.ReleaseError, "principals must be distinct"):
            release.build_preauthorization(
                descriptor, self.keys["preauthorizer"], self.keys["reviewer"]
            )
        descriptor["reviewer_id"] = "different-principal"
        with self.assertRaisesRegex(release.ReleaseError, "keys must be distinct"):
            release.build_preauthorization(
                descriptor, self.keys["preauthorizer"], self.keys["preauthorizer"]
            )
        descriptor["issued_at_utc"] = descriptor["valid_from_utc"]
        with self.assertRaisesRegex(release.ReleaseError, "chronology"):
            release.build_preauthorization(
                descriptor, self.keys["preauthorizer"], self.keys["reviewer"]
            )

    def test_all_four_release_principals_and_keys_are_distinct(self) -> None:
        preauth_bundle, preauth, descriptor_path, descriptor, evidence_root = (
            self._release_inputs()
        )
        descriptor["installer_id"] = preauth["preauthorizer_id"]
        self._write_json(self.root / "bad-principal.json", descriptor)
        with self._verified_stage(), self.assertRaisesRegex(
            release.ReleaseError, "four release principals"
        ):
            release.create_bundle(
                {},
                self.root / "bad-principal.json",
                evidence_root,
                preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                self.endurance,
                Path("unused"),
                Path("unused"),
                self.keys["installer"],
                self.keys["witness"],
                self.root / "bad-principal-bundle",
            )
        with self._verified_stage(), self.assertRaisesRegex(
            release.ReleaseError, "four release signing keys"
        ):
            release.create_bundle(
                {},
                descriptor_path,
                evidence_root,
                preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                self.endurance,
                Path("unused"),
                Path("unused"),
                self.keys["preauthorizer"],
                self.keys["witness"],
                self.root / "bad-key-bundle",
            )

    def test_scope_broadening_splicing_and_temporal_inversion_fail(self) -> None:
        preauth_bundle, _, _, descriptor, evidence_root = self._release_inputs()
        cases = (
            ("release_scope", "target_id", "avalon-a1246-other", "broadened"),
            (
                "predecessor_chain",
                "no_clobber_sha256",
                _digest("spliced-no-clobber"),
                "spliced",
            ),
            (
                "predecessor_chain",
                "route_rollback_receipt_id",
                _digest("splice"),
                "spliced",
            ),
        )
        for index, (container, field, value, message) in enumerate(cases):
            changed = json.loads(json.dumps(descriptor))
            changed[container][field] = value
            path = self.root / f"bad-scope-{index}.json"
            self._write_json(path, changed)
            with self._verified_stage(), self.assertRaisesRegex(
                release.ReleaseError, message
            ):
                release.create_bundle(
                    {}, path, evidence_root, preauth_bundle,
                    self.keys["preauthorizer"].with_suffix(".pub"),
                    self.keys["reviewer"].with_suffix(".pub"), self.endurance,
                    Path("unused"), Path("unused"), self.keys["installer"],
                    self.keys["witness"], self.root / f"bad-scope-bundle-{index}",
                )
        inverted = json.loads(json.dumps(descriptor))
        inverted["started_at_utc"] = inverted["completed_at_utc"]
        path = self.root / "bad-time.json"
        self._write_json(path, inverted)
        with self._verified_stage(), self.assertRaisesRegex(
            release.ReleaseError, "authorization window"
        ):
            release.create_bundle(
                {}, path, evidence_root, preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"), self.endurance,
                Path("unused"), Path("unused"), self.keys["installer"],
                self.keys["witness"], self.root / "bad-time-bundle",
            )
        late_signature = json.loads(json.dumps(descriptor))
        late_signature["installer_signed_at_utc"] = "2026-01-01T03:00:01Z"
        path = self.root / "late-signature.json"
        self._write_json(path, late_signature)
        with self._verified_stage(), self.assertRaisesRegex(
            release.ReleaseError, "receipt signing"
        ):
            release.create_bundle(
                {}, path, evidence_root, preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"), self.endurance,
                Path("unused"), Path("unused"), self.keys["installer"],
                self.keys["witness"], self.root / "late-signature-bundle",
            )

    def test_incomplete_or_failed_semantic_evidence_fails_closed(self) -> None:
        preauth_bundle, _, _, descriptor, evidence_root = self._release_inputs()
        incomplete = json.loads(json.dumps(descriptor))
        incomplete["evidence"].pop()
        path = self.root / "incomplete-evidence.json"
        self._write_json(path, incomplete)
        with self._verified_stage(), self.assertRaisesRegex(
            release.ReleaseError, "exactly 9 records"
        ):
            release.create_bundle(
                {}, path, evidence_root, preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"), self.endurance,
                Path("unused"), Path("unused"), self.keys["installer"],
                self.keys["witness"], self.root / "incomplete-bundle",
            )
        sbom_path = evidence_root / "records/sbom.json"
        sbom = json.loads(sbom_path.read_text("utf-8"))
        sbom["complete"] = False
        self._write_json(self.root / "failed-sbom.json", sbom)
        shutil.copyfile(self.root / "failed-sbom.json", sbom_path)
        descriptor_path = self.root / "failed-evidence.json"
        self._write_json(descriptor_path, descriptor)
        with self._verified_stage(), self.assertRaisesRegex(
            release.ReleaseError, "SBOM review is incomplete"
        ):
            release.create_bundle(
                {}, descriptor_path, evidence_root, preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"), self.endurance,
                Path("unused"), Path("unused"), self.keys["installer"],
                self.keys["witness"], self.root / "failed-evidence-bundle",
            )

    def test_tampering_extra_members_and_unsafe_paths_are_rejected(self) -> None:
        bundle, inputs = self._create_release()
        (bundle / "extra.txt").write_text("extra", encoding="ascii")
        with self.assertRaisesRegex(release.ReleaseError, "member set is not exact"):
            self._verify_release(bundle)
        (bundle / "extra.txt").unlink()
        linked = bundle / "linked-receipt"
        try:
            os.symlink(bundle / release.RECEIPT_NAME, linked)
        except OSError:
            pass
        else:
            with self.assertRaisesRegex(release.ReleaseError, "linked member"):
                self._verify_release(bundle)
            linked.unlink()

        preauth_bundle = inputs[0]
        (preauth_bundle / "empty-extra").mkdir()
        with self.assertRaisesRegex(release.ReleaseError, "extra directory"):
            release.verify_preauthorization(
                preauth_bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
            )

        descriptor = json.loads(Path(inputs[2]).read_text("utf-8"))
        descriptor["evidence"][0]["path"] = "../escape.json"
        with self.assertRaisesRegex(release.ReleaseError, "safe relative path"):
            release.build_receipt(
                descriptor,
                inputs[4],
                inputs[1],
                inputs[1]["predecessor_chain"],
                self.keys["installer"],
                self.keys["witness"],
            )

    def test_preauthorization_signature_and_pinned_anchor_fail_closed(self) -> None:
        bundle, _ = self._make_preauthorization()
        path = bundle / release.PREAUTHORIZATION_NAME
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(release.ReleaseError, "canonical JSON"):
            release.verify_preauthorization(
                bundle,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
            )
        shutil.rmtree(bundle)
        clean, _ = self._make_preauthorization()
        with self.assertRaisesRegex(release.ReleaseError, "trust anchor"):
            release.verify_preauthorization(
                clean,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
                _digest("wrong-anchor"),
            )
        signature = clean / release.REVIEWER_SIGNATURE_NAME
        reviewer_signature = signature.read_bytes()
        signature.write_bytes(reviewer_signature + b"tamper")
        with self.assertRaisesRegex(release.ReleaseError, "canonical SSHSIG armor"):
            release.verify_preauthorization(
                clean,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
            )
        signature.write_bytes(
            (clean / release.PREAUTHORIZER_SIGNATURE_NAME).read_bytes()
        )
        with self.assertRaisesRegex(release.ReleaseError, "signature is invalid"):
            release.verify_preauthorization(
                clean,
                self.keys["preauthorizer"].with_suffix(".pub"),
                self.keys["reviewer"].with_suffix(".pub"),
            )

    def test_nonpassing_endurance_cannot_be_preauthorized(self) -> None:
        failed = dict(self.stage_result)
        failed["endurance_faults_gate_eligible"] = False
        with self._verified_stage(failed), self.assertRaisesRegex(
            release.ReleaseError, "not a passing"
        ):
            release._stage_chain({}, self.endurance, Path("unused"), Path("unused"))


if __name__ == "__main__":
    unittest.main()
