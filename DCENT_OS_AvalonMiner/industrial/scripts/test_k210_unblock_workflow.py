"""Tests for the K210 unlock workflow orchestrator (host-only)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent / "k210_unblock_workflow.py"
spec = importlib.util.spec_from_file_location("k210_unblock_workflow", SCRIPT)
wf = importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys  # noqa: E402  (dataclass resolution needs the module registered)

sys.modules["k210_unblock_workflow"] = wf
spec.loader.exec_module(wf)


def operator_receipt(validator: str) -> dict[str, object]:
    descriptor = {"semantic": "test"}
    canonical = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "bytes": 1,
        "claim": "test_semantic_claim",
        "descriptor": descriptor,
        "descriptor_sha256": hashlib.sha256(canonical).hexdigest(),
        "filename": "evidence.json",
        "sha256": "1" * 64,
        "subject_sha256": "2" * 64,
        "validator": validator,
    }


def terminal_evidence() -> dict[str, object]:
    common = "DCENT_OS_AvalonMiner/gauntlet"

    def receipt(**bundles: str) -> dict[str, object]:
        return {"descriptor": {"bundles": bundles}}

    return {
        "operator_evidence": {
            "op-discovery": receipt(discovery_bundle=common),
            "op-fixture": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
            ),
            "op-capture": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
            ),
            "op-recovery": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                recovery_bundle=common,
            ),
            "op-bootpolicy": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
            ),
            "op-replacement": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
            ),
            "op-rollback": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
                rollback_bundle=common,
            ),
            "op-firstlight": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
                rollback_bundle=common,
                first_light_bundle=common,
            ),
            "op-bench": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
                rollback_bundle=common,
                first_light_bundle=common,
                bench_bundle=common,
            ),
            "op-endurance": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
                rollback_bundle=common,
                first_light_bundle=common,
                bench_bundle=common,
                endurance_bundle=common,
            ),
            "op-preauthorize": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
                rollback_bundle=common,
                first_light_bundle=common,
                bench_bundle=common,
                endurance_bundle=common,
                release_preauthorization_bundle=common,
            ),
            "op-release": receipt(
                discovery_bundle=common,
                fixture_bundle=common,
                capture_bundle=common,
                recovery_bundle=common,
                boot_policy_bundle=common,
                replacement_bundle=common,
                rollback_bundle=common,
                first_light_bundle=common,
                bench_bundle=common,
                endurance_bundle=common,
                release_preauthorization_bundle=common,
                release_bundle=common,
            ),
        }
    }


class RegistryInvariantTests(unittest.TestCase):
    def test_registry_validates(self) -> None:
        wf.validate_registry(wf.REGISTRY)  # must not raise

    def test_unique_ids(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        self.assertEqual(len(by_id), len(wf.REGISTRY))

    def test_registry_digest_binds_lane_contract(self) -> None:
        original = wf.registry_sha256(wf.REGISTRY)
        changed = list(wf.REGISTRY)
        lane = changed[0]
        changed[0] = wf.Lane(**{**lane.__dict__, "mission": lane.mission + " changed"})
        self.assertNotEqual(original, wf.registry_sha256(tuple(changed)))

    def test_terminal_depends_on_everything(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        expected = {lane.lane_id for lane in wf.REGISTRY if lane.lane_id != "terminal"}
        self.assertEqual(set(by_id["terminal"].depends_on), expected)

    def test_operator_lanes_have_runbooks(self) -> None:
        for lane in wf.REGISTRY:
            if lane.kind == wf.OPERATOR:
                self.assertTrue(lane.runbook, f"{lane.lane_id} missing runbook")
                self.assertTrue(
                    lane.operator_validator,
                    f"{lane.lane_id} missing semantic validator disposition",
                )

    def test_every_desk_lane_declares_verify(self) -> None:
        for lane in wf.REGISTRY:
            if lane.kind == wf.DESK:
                self.assertTrue(lane.verify, f"{lane.lane_id} missing verify")

    def test_terminal_verify_requires_production_gauntlet(self) -> None:
        terminal = wf.registry_by_id(wf.REGISTRY)["terminal"]
        joined = " ".join(terminal.verify)
        self.assertIn("--model a1246", joined)
        self.assertIn("--corpus required", joined)
        self.assertIn("--require-production", joined)

    def test_future_rust_lanes_are_pinned_and_mission_specific(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        for lane_id in ("w2-codec", "w2-firmware", "w2-safety"):
            joined = " ".join(by_id[lane_id].verify)
            self.assertIn("cargo +1.90.0 test", joined)
            self.assertIn("--locked", joined)
            self.assertIn("--test k210_", joined)

    def test_semantic_desk_lane_inventory_is_complete(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        self.assertEqual(
            wf.SEMANTIC_DESK_LANES,
            {
                "w2-codec",
                "w2-firmware",
                "w2-safety",
                "w3-executor",
                "w3-validation",
                "w3-rollback",
            },
        )
        for lane_id in wf.SEMANTIC_DESK_LANES:
            self.assertEqual(by_id[lane_id].kind, wf.DESK)

    def test_file_presence_verifiers_have_semantic_report_contracts(self) -> None:
        file_presence_lanes = {
            lane.lane_id
            for lane in wf.REGISTRY
            if any(
                "py -3 -c" in command and "Path(" in command for command in lane.verify
            )
        }
        self.assertEqual(file_presence_lanes, set(wf.DESK_REPORT_CONTRACTS))

    def test_executor_requires_a_dedicated_module_and_test(self) -> None:
        executor = wf.registry_by_id(wf.REGISTRY)["w3-executor"]
        self.assertIn(
            "projects/dcent-toolbox/src/dcent_toolbox/core/k210_install_executor.py",
            executor.owns,
        )
        self.assertIn(
            "projects/dcent-toolbox/tests/test_k210_install_executor.py",
            executor.owns,
        )
        self.assertTrue(
            any(
                "test_k210_install_executor.py" in command
                for command in executor.verify
            )
        )

    def test_desk_ownership_disjoint(self) -> None:
        # validate_registry enforces this; ensure ownable lanes exist to enforce on
        ownable = [lane for lane in wf.REGISTRY if lane.kind == wf.DESK and lane.owns]
        self.assertGreater(len(ownable), 3)

    def test_directory_ownership_overlap_is_detected(self) -> None:
        self.assertTrue(
            wf.ownership_scopes_overlap(
                "DCENT_OS_AvalonMiner/k210-firmware/",
                "DCENT_OS_AvalonMiner/k210-firmware/docs/report.md",
            )
        )
        self.assertFalse(
            wf.ownership_scopes_overlap(
                "DCENT_OS_AvalonMiner/k210-firmware/src/",
                "DCENT_OS_AvalonMiner/k210-firmware/docs/report.md",
            )
        )

    def test_unordered_directory_ownership_overlap_is_rejected(self) -> None:
        first = wf.Lane(
            "first",
            "first",
            "expert",
            wf.DESK,
            verify=("true",),
            owns=("scope/",),
        )
        second = wf.Lane(
            "second",
            "second",
            "expert",
            wf.DESK,
            verify=("true",),
            owns=("scope/file",),
        )
        terminal = wf.Lane(
            "terminal",
            "terminal",
            "expert",
            wf.DESK,
            depends_on=("first", "second"),
            verify=("true",),
        )
        with self.assertRaisesRegex(wf.WorkflowError, "overlapping ownership"):
            wf.validate_registry((first, second, terminal))

    def test_cycle_detected(self) -> None:
        bad = list(wf.REGISTRY)
        # rewire two lanes into a cycle
        for i, lane in enumerate(bad):
            if lane.lane_id == "d0-census":
                bad[i] = wf.Lane(**{**lane.__dict__, "depends_on": ("d0-crossera",)})
            if lane.lane_id == "d0-crossera":
                bad[i] = wf.Lane(**{**lane.__dict__, "depends_on": ("d0-census",)})
        with self.assertRaises(wf.WorkflowError):
            wf.validate_registry(bad)

    def test_wave1_dependencies_sane(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        self.assertIn("d0-bspplan", by_id["w1-bspa"].depends_on)
        self.assertIn("op-ceremony", by_id["op-discovery"].depends_on)
        self.assertIn("w1-discoverytool", by_id["op-discovery"].depends_on)
        self.assertIn("w1-identityschema", by_id["op-discovery"].depends_on)
        self.assertIn("op-fixture", by_id["op-recovery"].depends_on)
        self.assertIn("op-fixture", by_id["op-capture"].depends_on)
        self.assertIn("w1-fixturevalidator", by_id["op-fixture"].depends_on)
        self.assertIn("w1-capturevalidator", by_id["op-capture"].depends_on)
        self.assertIn("op-capture", by_id["w2-codec"].depends_on)
        self.assertIn("w1-routeengine", by_id["w2-route"].depends_on)
        self.assertIn("op-bootpolicy", by_id["w2-route"].depends_on)
        self.assertIn("w2-route", by_id["w2-firmware"].depends_on)
        self.assertEqual(
            by_id["op-replacement"].operator_validator,
            wf.OPERATOR_VALIDATOR_GAUNTLET,
        )
        self.assertIn("w2-firmware", by_id["op-replacement"].depends_on)
        self.assertIn("op-replacement", by_id["w3-executor"].depends_on)
        self.assertIn("op-rollback", by_id["op-firstlight"].depends_on)
        self.assertIn("op-firstlight", by_id["op-bench"].depends_on)
        self.assertIn("op-bench", by_id["op-endurance"].depends_on)
        self.assertIn("op-endurance", by_id["op-preauthorize"].depends_on)
        self.assertIn("op-preauthorize", by_id["op-release"].depends_on)


class DeskSemanticProofTests(unittest.TestCase):
    def test_held_report_only_completions_match_semantic_contracts(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        for lane_id in wf.DESK_REPORT_CONTRACTS:
            with self.subTest(lane_id=lane_id):
                wf.validate_desk_deliverable(by_id[lane_id])

    def test_padded_report_placeholder_cannot_match_reviewed_content(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["d0-census"]
        relative = next(iter(wf.DESK_REPORT_CONTRACTS[lane.lane_id]))[0]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_text(
                "placeholder-shaped report\n" + "x" * 25_000, encoding="utf-8"
            )
            with mock.patch.object(wf, "REPO_ROOT", root):
                with self.assertRaisesRegex(
                    wf.WorkflowError, "reviewed content digest"
                ):
                    wf.validate_desk_deliverable(lane)

    def test_strong_existing_validation_and_rollback_contracts_pass(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        wf.validate_desk_deliverable(by_id["w3-validation"])
        wf.validate_desk_deliverable(by_id["w3-rollback"])

    def test_unimplemented_codec_firmware_safety_and_executor_fail_closed(self) -> None:
        by_id = wf.registry_by_id(wf.REGISTRY)
        for lane_id in ("w2-codec", "w2-firmware", "w2-safety", "w3-executor"):
            with self.subTest(lane_id=lane_id):
                with self.assertRaises(wf.WorkflowError):
                    wf.validate_desk_deliverable(by_id[lane_id])

    def test_empty_rust_test_target_is_not_semantic_proof(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["w2-codec"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "shared/dcent-avalon-proto/src/k210_codec.rs"
            tests = root / "shared/dcent-avalon-proto/tests/k210_codec_admission.rs"
            source.parent.mkdir(parents=True)
            tests.parent.mkdir(parents=True)
            source.write_text(
                " ".join(
                    (
                        "capture_set_sha256",
                        "unit_fingerprint_sha256",
                        "variant_profile_id",
                        "encode",
                        "decode",
                        "reject",
                        "authority_granted",
                    )
                )
                + "\n"
                + "implementation " * 200,
                encoding="utf-8",
            )
            tests.write_text(
                "// empty test target\n" + "padding\n" * 300, encoding="utf-8"
            )
            with mock.patch.object(wf, "REPO_ROOT", root):
                with self.assertRaisesRegex(wf.WorkflowError, "only 0 tests"):
                    wf.validate_desk_deliverable(lane)

    def test_completion_cannot_bypass_semantic_proof_with_green_command(self) -> None:
        executor = wf.Lane(
            "w3-executor",
            "executor",
            "expert",
            wf.DESK,
            verify=("py -3 -c pass",),
        )
        terminal = wf.Lane(
            "terminal",
            "terminal",
            "expert",
            wf.DESK,
            depends_on=("w3-executor",),
            verify=("py -3 -c pass",),
        )
        passed = mock.Mock(returncode=0, stdout="placeholder tests passed", stderr="")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_path = root / "state.json"
            with (
                mock.patch.object(wf, "REPO_ROOT", root),
                mock.patch.object(wf, "_verification_process", return_value=passed),
            ):
                with self.assertRaises(wf.WorkflowError):
                    wf.complete_lane(
                        "w3-executor",
                        (executor, terminal),
                        {"completed": []},
                        state_path=state_path,
                    )
            self.assertFalse(state_path.exists())


class EvaluateTests(unittest.TestCase):
    def test_empty_state_blocks_most(self) -> None:
        ev = wf.evaluate(wf.REGISTRY, {"completed": []})
        ready = [i for i, v in ev.items() if v["status"] == "ready"]
        # only dependency-free desk lanes can be ready with nothing done
        for lane_id in ready:
            self.assertEqual(ev[lane_id]["kind"], wf.DESK)
        self.assertNotIn("terminal", ready)

    def test_operator_lane_never_ready(self) -> None:
        ev = wf.evaluate(wf.REGISTRY, {"completed": []})
        for lane_id, v in ev.items():
            if v["kind"] == wf.OPERATOR:
                self.assertIn(
                    v["status"],
                    ("blocked", "awaiting_operator", "blocked_validator"),
                )

    def test_state_with_unknown_lane_rejected(self) -> None:
        with self.assertRaises(wf.WorkflowError):
            wf.evaluate(wf.REGISTRY, {"completed": ["nonexistent-lane"]})

    def test_persisted_terminal_cannot_bypass_dependency_closure(self) -> None:
        with self.assertRaisesRegex(wf.WorkflowError, "dependency-closed"):
            wf.evaluate(wf.REGISTRY, {"completed": ["terminal"]})

    def test_persisted_operator_requires_matching_evidence(self) -> None:
        state = {"completed": ["d0-runbooks", "op-ceremony"]}
        with self.assertRaisesRegex(wf.WorkflowError, "no semantic evidence"):
            wf.evaluate(wf.REGISTRY, state)

    def test_orphan_operator_evidence_is_rejected(self) -> None:
        state = {
            "completed": [],
            "operator_evidence": {
                "op-ceremony": operator_receipt(wf.OPERATOR_VALIDATOR_CEREMONY)
            },
        }
        with self.assertRaisesRegex(wf.WorkflowError, "without a completion"):
            wf.evaluate(wf.REGISTRY, state)

    def test_completion_order(self) -> None:
        state = {
            "completed": sorted(
                [
                    "d0-census",
                    "d0-ingest",
                    "d0-runbooks",
                    "op-ceremony",
                    "w1-discoverytool",
                    "w1-identityschema",
                ]
            ),
            "operator_evidence": {
                "op-ceremony": operator_receipt(wf.OPERATOR_VALIDATOR_CEREMONY)
            },
        }
        with mock.patch.object(wf, "_revalidate_operator_receipt"):
            ev = wf.evaluate(wf.REGISTRY, state)
        self.assertEqual(ev["op-discovery"]["status"], "awaiting_operator")


class CompleteTests(unittest.TestCase):
    def test_ceremony_anchor_inventory_is_contract_driven_and_globally_distinct(
        self,
    ) -> None:
        manifest = {
            "alpha_contract": {
                "trust_anchor": {
                    "key_id_sha256": "1" * 64,
                    "path": "trust/alpha.pub",
                    "role": "alpha_signer",
                }
            },
            "beta_contract": {
                "trust_anchors": {
                    "operator": {
                        "key_id_sha256": "2" * 64,
                        "path": "trust/beta.pub",
                        "role": "beta_operator",
                    }
                }
            },
        }
        self.assertEqual(
            wf._manifest_anchor_ids(manifest),
            {
                "alpha.signer": "1" * 64,
                "beta.operator": "2" * 64,
            },
        )
        manifest["beta_contract"]["trust_anchors"]["operator"]["path"] = (
            "trust/alpha.pub"
        )
        with self.assertRaisesRegex(wf.WorkflowError, "distinct key, path, and role"):
            wf._manifest_anchor_ids(manifest)

    def test_operator_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = {"completed": ["d0-runbooks"]}
            with self.assertRaises(wf.WorkflowError):
                wf.complete_lane(
                    "op-ceremony",
                    wf.REGISTRY,
                    state,
                    operator_confirmed=False,
                    state_path=state_path,
                )

    def test_operator_rejects_arbitrary_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_path = root / "state.json"
            receipt = root / "ceremony-receipt.json"
            receipt.write_text('{"reviewed":true}\n', encoding="utf-8")
            state = {"completed": ["d0-runbooks"]}
            with self.assertRaisesRegex(wf.WorkflowError, "requires --evidence"):
                wf.complete_lane(
                    "op-ceremony",
                    wf.REGISTRY,
                    state,
                    operator_confirmed=True,
                    state_path=state_path,
                )
            with self.assertRaises(wf.WorkflowError):
                wf.complete_lane(
                    "op-ceremony",
                    wf.REGISTRY,
                    state,
                    operator_confirmed=True,
                    operator_evidence=receipt,
                    state_path=state_path,
                )

    def test_operator_records_only_semantically_validated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state_path = root / "state.json"
            receipt = root / "ceremony-receipt.json"
            receipt.write_text('{"semantic":"mocked"}\n', encoding="utf-8")
            validated = {
                "bytes": receipt.stat().st_size,
                "claim": "all_distinct_manifest_trust_anchors_pinned",
                "descriptor": {"semantic": "mocked"},
                "descriptor_sha256": hashlib.sha256(
                    b'{"semantic":"mocked"}'
                ).hexdigest(),
                "filename": receipt.name,
                "sha256": "1" * 64,
                "subject_sha256": "2" * 64,
                "validator": wf.OPERATOR_VALIDATOR_CEREMONY,
            }
            with mock.patch.object(
                wf, "validate_operator_evidence", return_value=validated
            ):
                result = wf.complete_lane(
                    "op-ceremony",
                    wf.REGISTRY,
                    {"completed": ["d0-runbooks"]},
                    operator_confirmed=True,
                    operator_evidence=receipt,
                    state_path=state_path,
                )
            self.assertEqual(result["operator_evidence"]["op-ceremony"], validated)

    def test_no_canonical_operator_lane_uses_unimplemented_validator(self) -> None:
        self.assertFalse(
            any(
                lane.operator_validator == wf.OPERATOR_VALIDATOR_UNIMPLEMENTED
                for lane in wf.REGISTRY
            )
        )

    def test_fixture_validator_admits_only_the_narrow_nonproduction_claim(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-fixture"]
        relative = "DCENT_OS_AvalonMiner/gauntlet"
        descriptor = {
            "bundles": {
                "discovery_bundle": relative,
                "fixture_bundle": relative,
            },
            "kind": "dcent_k210_operator_fixture_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        admitted = {
            "authority_granted": False,
            "fixture_evidence_set_sha256": "1" * 64,
            "fixture_qualification_eligible": True,
            "receipt_id": "2" * 64,
            "state": "verified_signed_fixture_qualification",
            "target_id": "a1246",
            "unit_fingerprint_sha256": "3" * 64,
        }
        result = {
            "id": "a1246",
            "fixture_qualification": admitted,
            "gates": {"thermal_power_safety": {"qualifies": False}},
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "fixture.json"
            evidence.write_text(json.dumps(descriptor), encoding="utf-8")
            with mock.patch.object(wf, "_run_gauntlet", return_value=process):
                receipt = wf.validate_operator_evidence(lane, evidence)
        self.assertEqual(receipt["claim"], "exact_unit_fixture_qualified")
        self.assertEqual(receipt["validator"], wf.OPERATOR_VALIDATOR_FIXTURE)
        self.assertEqual(
            receipt["subject_sha256"],
            hashlib.sha256(
                json.dumps(admitted, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )

    def test_fixture_validator_rejects_production_gate_promotion(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-fixture"]
        descriptor = {
            "bundles": {
                "discovery_bundle": "DCENT_OS_AvalonMiner/gauntlet",
                "fixture_bundle": "DCENT_OS_AvalonMiner/gauntlet",
            },
            "kind": "dcent_k210_operator_fixture_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        result = {
            "id": "a1246",
            "fixture_qualification": {
                "authority_granted": False,
                "fixture_qualification_eligible": True,
                "state": "verified_signed_fixture_qualification",
            },
            "gates": {"thermal_power_safety": {"qualifies": True}},
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            with self.assertRaisesRegex(wf.WorkflowError, "unexpectedly qualified"):
                wf._validate_fixture_descriptor(lane, descriptor)

    def test_capture_validator_admits_raw_p1_without_codec_promotion(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-capture"]
        relative = "DCENT_OS_AvalonMiner/gauntlet"
        descriptor = {
            "bundles": {
                "capture_bundle": relative,
                "discovery_bundle": relative,
                "fixture_bundle": relative,
            },
            "kind": "dcent_k210_operator_capture_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        admitted = {
            "authority_granted": False,
            "capture_set_sha256": "1" * 64,
            "p1_capture_admission_eligible": True,
            "receipt_id": "2" * 64,
            "state": "verified_signed_p1_passive_capture",
            "target_id": "a1246",
            "wire_contract_claimed": False,
        }
        result = {
            "id": "a1246",
            "passive_capture_admission": admitted,
            "gates": {"asic_control": {"qualifies": False}},
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "capture.json"
            evidence.write_text(json.dumps(descriptor), encoding="utf-8")
            with mock.patch.object(wf, "_run_gauntlet", return_value=process):
                receipt = wf.validate_operator_evidence(lane, evidence)
        self.assertEqual(receipt["claim"], "p1_passive_capture_admitted")
        self.assertEqual(receipt["validator"], wf.OPERATOR_VALIDATOR_CAPTURE)

        promoted = deepcopy(result)
        promoted["gates"]["asic_control"]["qualifies"] = True
        process = mock.Mock(returncode=0, stdout=json.dumps(promoted), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            with self.assertRaisesRegex(wf.WorkflowError, "unexpectedly qualified"):
                wf._validate_capture_descriptor(lane, descriptor)

    def test_replacement_validator_admits_the_exact_full_bundle_chain(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-replacement"]
        relative = "DCENT_OS_AvalonMiner/gauntlet"
        descriptor = {
            "bundles": {
                name: relative for name in wf.GAUNTLET_BUNDLES_BY_LANE["op-replacement"]
            },
            "kind": "dcent_k210_operator_gate_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        result = {
            "id": "a1246",
            "fixture_qualification": {
                "authority_granted": False,
                "fixture_qualification_eligible": True,
                "state": "verified_signed_fixture_qualification",
            },
            "gates": {"replacement_firmware": {"qualifies": True}},
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            claim, subject = wf._validate_gauntlet_descriptor(lane, descriptor)
        self.assertEqual(claim, "replacement_firmware_qualifies")
        self.assertEqual(len(subject), 64)

    def test_rollback_validator_admits_only_the_exact_full_bundle_chain(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-rollback"]
        relative = "DCENT_OS_AvalonMiner/gauntlet"
        descriptor = {
            "bundles": {
                name: relative for name in wf.GAUNTLET_BUNDLES_BY_LANE["op-rollback"]
            },
            "kind": "dcent_k210_operator_gate_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        result = {
            "fixture_qualification": {
                "authority_granted": False,
                "fixture_qualification_eligible": True,
                "state": "verified_signed_fixture_qualification",
            },
            "gates": {"rollback_recovery": {"qualifies": True}},
            "id": "a1246",
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            claim, subject = wf._validate_gauntlet_descriptor(lane, descriptor)
        self.assertEqual(claim, "rollback_recovery_qualifies")
        self.assertEqual(len(subject), 64)

    def test_first_light_validator_requires_both_asic_and_safety_gates(self) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-firstlight"]
        relative = "DCENT_OS_AvalonMiner/gauntlet"
        descriptor = {
            "bundles": {
                name: relative for name in wf.GAUNTLET_BUNDLES_BY_LANE["op-firstlight"]
            },
            "kind": "dcent_k210_operator_gate_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        result = {
            "fixture_qualification": {
                "authority_granted": False,
                "fixture_qualification_eligible": True,
                "state": "verified_signed_fixture_qualification",
            },
            "gates": {
                "asic_control": {"qualifies": True},
                "thermal_power_safety": {"qualifies": True},
            },
            "id": "a1246",
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            claim, subject = wf._validate_gauntlet_descriptor(lane, descriptor)
        self.assertEqual(claim, "asic_control_and_thermal_power_safety_qualify")
        self.assertEqual(len(subject), 64)

        result["gates"]["thermal_power_safety"]["qualifies"] = False
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            with self.assertRaisesRegex(wf.WorkflowError, "thermal_power_safety"):
                wf._validate_gauntlet_descriptor(lane, descriptor)

    def test_preauthorization_validator_requires_narrow_scope_and_red_gate(
        self,
    ) -> None:
        lane = wf.registry_by_id(wf.REGISTRY)["op-preauthorize"]
        relative = "DCENT_OS_AvalonMiner/gauntlet"
        descriptor = {
            "bundles": {
                name: relative
                for name in wf.GAUNTLET_BUNDLES_BY_LANE["op-preauthorize"]
            },
            "kind": "dcent_k210_operator_gate_evidence",
            "model": "a1246",
            "schema_version": 1,
        }
        admitted = {
            "authority_granted": False,
            "generic_future_authority_granted": False,
            "install_authority_scope_eligible": True,
            "state": "verified_exact_scope_preauthorization",
        }
        result = {
            "fixture_qualification": {
                "authority_granted": False,
                "fixture_qualification_eligible": True,
                "state": "verified_signed_fixture_qualification",
            },
            "gates": {"release_authority": {"qualifies": False}},
            "id": "a1246",
            "release_preauthorization": admitted,
        }
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            claim, subject = wf._validate_gauntlet_descriptor(lane, descriptor)
        self.assertEqual(claim, "exact_scope_install_preauthorized")
        self.assertEqual(len(subject), 64)

        result["gates"]["release_authority"]["qualifies"] = True
        process = mock.Mock(returncode=0, stdout=json.dumps(result), stderr="")
        with mock.patch.object(wf, "_run_gauntlet", return_value=process):
            with self.assertRaisesRegex(wf.WorkflowError, "narrow exact-scope"):
                wf._validate_gauntlet_descriptor(lane, descriptor)

    def test_terminal_reconstructs_all_cumulative_bundle_arguments(self) -> None:
        completed = mock.Mock(returncode=0, stdout="{}", stderr="")
        state = terminal_evidence()
        with mock.patch.object(wf.subprocess, "run", return_value=completed) as run:
            self.assertIs(wf._terminal_verification_process(state), completed)
        argv = run.call_args.args[0]
        for _, _, option in wf.TERMINAL_BUNDLE_SOURCES:
            self.assertIn(option, argv)
        self.assertIn("--require-production", argv)
        self.assertEqual(argv[-1], "--require-production")

    def test_terminal_rejects_cross_lane_bundle_splicing(self) -> None:
        state = terminal_evidence()
        state["operator_evidence"]["op-fixture"]["descriptor"]["bundles"][
            "discovery_bundle"
        ] = "DCENT_OS_AvalonMiner/scripts"
        with self.assertRaisesRegex(wf.WorkflowError, "bundle join mismatch"):
            wf._terminal_bundle_arguments(state)

    def test_blocked_lane_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            with self.assertRaises(wf.WorkflowError):
                wf.complete_lane(
                    "w2-codec", wf.REGISTRY, {"completed": []}, state_path=state_path
                )

    def test_successful_desk_verify_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            completed = mock.Mock(returncode=0, stdout="ok", stderr="")
            with mock.patch.object(wf.subprocess, "run", return_value=completed):
                state = wf.complete_lane(
                    "d0-census",
                    wf.REGISTRY,
                    {"completed": []},
                    state_path=state_path,
                )
            self.assertIn("d0-census", state["completed"])
            saved = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["completed"], ["d0-census"])
            self.assertEqual(saved["operator_evidence"], {})

    def test_public_cli_has_no_verify_bypass(self) -> None:
        self.assertNotIn("--skip-verify", SCRIPT.read_text(encoding="utf-8"))

    def test_registry_verifiers_do_not_use_a_platform_shell(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        completed = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(wf.subprocess, "run", return_value=completed) as run:
            wf._verification_process(
                "py -3 -c \"from pathlib import Path; assert Path('x').name == 'x'\""
            )
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], wf.sys.executable)
        self.assertEqual(argv[1], "-c")

    def test_registry_verifier_resolves_static_cargo_workdir(self) -> None:
        completed = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(wf.subprocess, "run", return_value=completed) as run:
            wf._verification_process(
                "cd DCENT_OS_AvalonMiner/k210-firmware && cargo test --locked"
            )
        self.assertEqual(run.call_args.args[0], ["cargo", "test", "--locked"])
        self.assertEqual(
            Path(run.call_args.kwargs["cwd"]),
            wf.REPO_ROOT / "DCENT_OS_AvalonMiner/k210-firmware",
        )

    def test_double_complete_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = {"completed": ["d0-census"]}
            with self.assertRaises(wf.WorkflowError):
                wf.complete_lane("d0-census", wf.REGISTRY, state, state_path=state_path)


class StatePersistenceTests(unittest.TestCase):
    def test_state_write_is_atomic_and_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            wf.save_state({"completed": ["b", "a"]}, state_path)
            self.assertEqual(
                wf.load_state(state_path, registry=None),
                {"completed": ["a", "b"], "operator_evidence": {}},
            )
            self.assertEqual(list(Path(td).glob("*.tmp")), [])

    def test_loaded_terminal_is_revalidated_against_production_gate(self) -> None:
        base = wf.Lane("base", "base", "expert", wf.DESK, verify=("py -3 -c pass",))
        terminal = wf.Lane(
            "terminal",
            "terminal",
            "expert",
            wf.DESK,
            depends_on=("base",),
            verify=("py -3 -c pass",),
        )
        registry = (base, terminal)
        passed = mock.Mock(returncode=0, stdout="desk current", stderr="")
        failed = mock.Mock(returncode=1, stdout="not production ready", stderr="")
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            wf.save_state({"completed": ["base", "terminal"]}, state_path)
            with mock.patch.object(
                wf, "_verification_process", side_effect=(passed, failed)
            ):
                with self.assertRaisesRegex(
                    wf.WorkflowError, "terminal completion is stale"
                ):
                    wf.load_state(state_path, registry=registry)

    def test_loaded_desk_completion_replays_its_verifier(self) -> None:
        base = wf.Lane("base", "base", "expert", wf.DESK, verify=("py -3 -c pass",))
        terminal = wf.Lane(
            "terminal",
            "terminal",
            "expert",
            wf.DESK,
            depends_on=("base",),
            verify=("py -3 -c pass",),
        )
        failed = mock.Mock(returncode=1, stdout="forged completion", stderr="")
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            wf.save_state({"completed": ["base"]}, state_path)
            with mock.patch.object(wf, "_verification_process", return_value=failed):
                with self.assertRaisesRegex(
                    wf.WorkflowError, "persisted desk lane base verification is stale"
                ):
                    wf.load_state(state_path, registry=(base, terminal))

    def test_loaded_operator_evidence_is_semantically_replayed(self) -> None:
        state = {
            "completed": ["d0-runbooks", "op-ceremony"],
            "operator_evidence": {
                "op-ceremony": operator_receipt(wf.OPERATOR_VALIDATOR_CEREMONY)
            },
        }
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            wf.save_state(state, state_path)
            with mock.patch.object(wf, "_revalidate_operator_receipt") as replay:
                wf.load_state(state_path)
            replay.assert_called_once()

    def test_state_json_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state_path.write_text(
                '{"completed":[],"completed":[],"operator_evidence":{}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(wf.WorkflowError, "duplicate JSON key"):
                wf.load_state(state_path)

    def test_existing_lock_refuses_a_second_writer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            lock_path = state_path.with_name(state_path.name + ".lock")
            lock_path.write_text("pid=fixture\n", encoding="ascii")
            with mock.patch.object(wf, "LOCK_WAIT_SECONDS", 0.0):
                with self.assertRaisesRegex(wf.WorkflowError, "timed out"):
                    with wf.StateLock(state_path):
                        self.fail("lock should not have been acquired")


class EmitWaveTests(unittest.TestCase):
    def test_checked_in_wave_matches_completion_ledger(self) -> None:
        state = wf.load_state()
        evaluated = wf.evaluate(wf.REGISTRY, state)
        payload = json.loads(wf.WAVE_JSON.read_text(encoding="utf-8"))
        expected_done = sorted(
            lane_id for lane_id, body in evaluated.items() if body["status"] == "done"
        )
        expected_ready = [
            lane_id for lane_id, body in evaluated.items() if body["status"] == "ready"
        ]
        expected_awaiting = [
            lane_id
            for lane_id, body in evaluated.items()
            if body["status"] == "awaiting_operator"
        ]
        expected_blocked = [
            lane_id
            for lane_id, body in evaluated.items()
            if body["status"] == "blocked"
        ]
        expected_blocked_validator = [
            lane_id
            for lane_id, body in evaluated.items()
            if body["status"] == "blocked_validator"
        ]
        normalized_state = wf._validated_state(state)
        expected_registry_sha = wf.registry_sha256(wf.REGISTRY)
        canonical_state = json.dumps(
            normalized_state, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        expected_state_sha = hashlib.sha256(
            b"DCENT-K210-WORKFLOW-STATE-V2\x00"
            + bytes.fromhex(expected_registry_sha)
            + canonical_state
        ).hexdigest()
        self.assertEqual(payload["done"], expected_done)
        self.assertEqual(payload["ready"], expected_ready)
        self.assertEqual(payload["awaiting_operator"], expected_awaiting)
        self.assertEqual(payload["blocked"], expected_blocked)
        self.assertEqual(payload["blocked_validator"], expected_blocked_validator)
        self.assertEqual(payload["registry_sha256"], expected_registry_sha)
        self.assertEqual(payload["state_sha256"], expected_state_sha)
        self.assertIn(expected_state_sha, wf.WAVE_MD.read_text(encoding="utf-8"))
        self.assertIn(expected_registry_sha, wf.WAVE_MD.read_text(encoding="utf-8"))

    def test_emit_writes_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wave_md = Path(td) / "wave.md"
            wave_json = Path(td) / "wave.json"
            payload = wf.emit_wave(
                wf.REGISTRY,
                {"completed": []},
                gate_snapshot=None,
                wave_md=wave_md,
                wave_json=wave_json,
            )
            self.assertIn("ready", payload)
            self.assertIn("lanes", payload)
            self.assertIn("state_sha256", payload)
            self.assertIn("registry_sha256", payload)
            text = wave_md.read_text(encoding="utf-8")
            self.assertIn("K210 unlock workflow", text)
            self.assertIn(payload["state_sha256"], text)
            data = json.loads(wave_json.read_text(encoding="utf-8"))
            self.assertEqual(data["registry_size"], len(wf.REGISTRY))

    def test_gate_snapshot_runs_gauntlet(self) -> None:
        gates = wf.gauntlet_gate_snapshot()
        self.assertIn("stock_restore", gates)
        self.assertIn("exact_model_identity", gates)
        self.assertFalse(gates["stock_restore"]["qualifies"])


if __name__ == "__main__":
    unittest.main()
