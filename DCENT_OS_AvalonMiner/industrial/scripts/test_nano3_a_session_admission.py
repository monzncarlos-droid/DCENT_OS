#!/usr/bin/env python3
"""Adversarial offline tests for nano3_a_session_admission.py."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MODULE_PATH = Path(__file__).with_name("nano3_a_session_admission.py")
SPEC = importlib.util.spec_from_file_location("nano3_a_session_admission", MODULE_PATH)
assert SPEC and SPEC.loader
ADMISSION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADMISSION
SPEC.loader.exec_module(ADMISSION)

NOW = datetime(2026, 8, 24, 16, 0, tzinfo=timezone.utc)


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.prepare_root = base / "prepare"
        self.prepare_root.mkdir(mode=0o700)
        self.prepare_ledger = base / "prepare-ledger"
        self.prepare_ledger.mkdir(mode=0o700)
        self.finalize_ledger = base / "finalize-ledger"
        self.finalize_ledger.mkdir(mode=0o700)
        if os.name != "nt":
            self.prepare_root.chmod(0o700)
            self.prepare_ledger.chmod(0o700)
            self.finalize_ledger.chmod(0o700)
        self.session_id = "nano3-a-fixture-session-0001"
        self.unit_id = "nano3-fixture-unit-0001"
        self.nonce = bytes(range(32))
        self.nonce_sha = ADMISSION.sha256(self.nonce)
        self.keys = {role: Ed25519PrivateKey.generate() for role in ADMISSION.SIGNER_ROLES}
        self.result_key: Ed25519PrivateKey | None = None
        self.component_raw: dict[str, bytes] = {}
        self.plan = self._build_plan()
        self.source = self._build_source()
        self.source_path = self.prepare_root / "prepare-source.json"
        self.write_prepare()

    def _fixture_binding(self, role: str, classification: str) -> dict[str, object]:
        return {
            "fixture_only": True,
            "role": role,
            "classification": classification,
            "session_id": self.session_id,
            "unit_id": self.unit_id,
            "nonce_sha256": self.nonce_sha,
            "authority_granted": False,
            "physical_authenticity_proven": False,
        }

    def _component(self, role: str, classification: str, schema: str) -> bytes:
        if role == "image_candidate":
            return b"synthetic fixture image bytes\x00"
        document: dict[str, object]
        if role == "safety_qualification":
            document = {
                "schema_version": 1,
                "record_type": "dcent-nano3-interlock-production-qualification",
            }
        else:
            document = {"schema": schema}
        document["w4_fixture_binding"] = self._fixture_binding(role, classification)
        return ADMISSION.canonical_json(document)

    def _build_plan(self) -> dict[str, object]:
        components = []
        for role, (classification, schema) in ADMISSION.COMPONENT_POLICY.items():
            raw = self._component(role, classification, schema)
            self.component_raw[role] = raw
            suffix = ".kdimg" if role == "image_candidate" else ".json"
            components.append(
                {
                    "role": role,
                    "classification": classification,
                    "schema": schema,
                    "path": f"{role}{suffix}",
                    "bytes": len(raw),
                    "sha256": ADMISSION.sha256(raw),
                }
            )
        signers = {}
        for role in ADMISSION.SIGNER_ROLES:
            raw = public_bytes(self.keys[role])
            signers[role] = {
                "path": f"{role}.pub",
                "bytes": 32,
                "sha256": ADMISSION.sha256(raw),
                "domain": ADMISSION.SIGNER_DOMAINS[role],
                "key_epoch": f"{role}-epoch-0001",
            }
        component_by_role = {item["role"]: item for item in components}
        expected_results = []
        for role, (schema, required_when) in ADMISSION.RESULT_POLICY.items():
            expected_results.append(
                {
                    "role": role,
                    "classification": ADMISSION.CLASS_RESULT,
                    "schema": schema,
                    "required_when": required_when,
                    "output_name": f"{role}.json",
                    "producer_sha256": ADMISSION.sha256(f"producer:{role}".encode()),
                    "join": "exact_prepare_plan_session_unit_nonce_and_role",
                }
            )
        return {
            "schema": ADMISSION.PLAN_SCHEMA,
            "purpose": ADMISSION.PURPOSE,
            "bundle_id": "nano3-a-fixture-bundle-0001",
            "mode": "synthetic_fixture",
            "issued_at_utc": iso(NOW - timedelta(minutes=2)),
            "valid_from_utc": iso(NOW - timedelta(minutes=1)),
            "expires_at_utc": iso(NOW + timedelta(minutes=10)),
            "session": {
                "session_id": self.session_id,
                "unit_id": self.unit_id,
                "unit_model": ADMISSION.TARGET_MODEL,
                "unit_fingerprint_sha256": "a" * 64,
                "nonce_sha256": self.nonce_sha,
                "operator_id": "operator-fixture-0001",
                "authorization_reference": "authorization-a-fixture-0001",
                "btcminer_sha256": ADMISSION.BTCMINER_SHA256,
                "trusted_time_record_sha256": component_by_role["trusted_time_record"]["sha256"],
                "global_replay_record_sha256": component_by_role["global_replay_record"]["sha256"],
            },
            "actions": {
                "allowed": list(ADMISSION.ALLOWED_ACTIONS),
                "excluded": list(ADMISSION.EXCLUDED_ACTIONS),
            },
            "components": components,
            "signers": signers,
            "expected_results": expected_results,
            "claims": {key: False for key in sorted(ADMISSION.FALSE_CLAIMS)},
        }

    def _build_source(self) -> dict[str, object]:
        plan_raw = ADMISSION.canonical_json(self.plan)
        signatures = {
            role: base64.b64encode(
                self.keys[role].sign(
                    ADMISSION.SIGNER_DOMAINS[role].encode("ascii") + b"\x00" + plan_raw
                )
            ).decode("ascii")
            for role in ADMISSION.SIGNER_ROLES
        }
        return {
            "schema": ADMISSION.PREPARE_SOURCE_SCHEMA,
            "purpose": ADMISSION.PURPOSE,
            "plan": self.plan,
            "signatures": signatures,
        }

    def resign(self) -> None:
        self.source = self._build_source()

    def write_prepare(self) -> None:
        for record in self.plan["components"]:
            (self.prepare_root / record["path"]).write_bytes(self.component_raw[record["role"]])
        for role, record in self.plan["signers"].items():
            (self.prepare_root / record["path"]).write_bytes(public_bytes(self.keys[role]))
        self.source_path.write_bytes(ADMISSION.canonical_json(self.source))

    def rewrite_prepare(self) -> None:
        self.source_path.write_bytes(ADMISSION.canonical_json(self.source))

    def prepare(self) -> dict[str, object]:
        return dict(
            ADMISSION.prepare(
                self.source_path,
                self.prepare_ledger,
                fixture_only=True,
                now=NOW,
            )
        )

    def finalize_fixture(
        self,
        prepared: Mapping[str, object],
        *,
        manual_ac: bool = False,
        compiled_at: datetime = NOW,
    ) -> tuple[Path, dict[str, object]]:
        root = self.base / "finalize"
        root.mkdir(mode=0o700)
        if os.name != "nt":
            root.chmod(0o700)
        prepared_raw = ADMISSION.canonical_json(prepared)
        (root / "prepare-receipt.json").write_bytes(prepared_raw)
        result_key = Ed25519PrivateKey.generate()
        self.result_key = result_key
        result_public = public_bytes(result_key)
        (root / "result-reviewer.pub").write_bytes(result_public)
        statement = {
            "schema": ADMISSION.FINALIZE_STATEMENT_SCHEMA,
            "purpose": ADMISSION.PURPOSE,
            "mode": "synthetic_fixture",
            "prepare_receipt_sha256": ADMISSION.sha256(prepared_raw),
            "prepare_plan_sha256": prepared["plan_sha256"],
            "session_id": prepared["session"]["session_id"],
            "compiled_at_utc": iso(compiled_at),
            "manual_ac_invoked": manual_ac,
            "results_manifest_sha256": "0" * 64,
            "authorization_a_granted": False,
        }
        results = []
        for expectation in prepared["expected_results"]:
            role = expectation["role"]
            present = role in {"pool_receipt", "restoration_receipt"} or (
                role == "post_cut_receipt" and manual_ac
            )
            if not present:
                results.append(
                    {
                        "role": role,
                        "status": "not_performed",
                        "path": None,
                        "bytes": None,
                        "sha256": None,
                        "schema": expectation["schema"],
                        "producer_sha256": expectation["producer_sha256"],
                    }
                )
                continue
            document = {
                "schema": expectation["schema"],
                "a_session_join": {
                    "prepare_plan_sha256": prepared["plan_sha256"],
                    "session_id": prepared["session"]["session_id"],
                    "unit_id_hmac_sha256": prepared["session"]["unit_id_hmac_sha256"],
                    "unit_fingerprint_hmac_sha256": prepared["session"][
                        "unit_fingerprint_hmac_sha256"
                    ],
                    "nonce_sha256": prepared["session"]["nonce_sha256"],
                    "role": role,
                    "authorization_a_granted": False,
                },
                "w4_fixture_result_binding": {
                    "fixture_only": True,
                    "role": role,
                    "authorization_a_granted": False,
                },
            }
            raw = ADMISSION.canonical_json(document)
            (root / expectation["output_name"]).write_bytes(raw)
            results.append(
                {
                    "role": role,
                    "status": "present",
                    "path": expectation["output_name"],
                    "bytes": len(raw),
                    "sha256": ADMISSION.sha256(raw),
                    "schema": expectation["schema"],
                    "producer_sha256": expectation["producer_sha256"],
                }
            )
        source = {
            "schema": ADMISSION.FINALIZE_SOURCE_SCHEMA,
            "purpose": ADMISSION.PURPOSE,
            "prepare_receipt": {
                "path": "prepare-receipt.json",
                "bytes": len(prepared_raw),
                "sha256": ADMISSION.sha256(prepared_raw),
            },
            "statement": statement,
            "result_reviewer_key": {
                "path": "result-reviewer.pub",
                "bytes": 32,
                "sha256": ADMISSION.sha256(result_public),
            },
            "result_reviewer_signature_base64": None,
            "results": results,
        }
        self.resign_finalize(source)
        source_path = root / "finalize-source.json"
        source_path.write_bytes(ADMISSION.canonical_json(source))
        return source_path, source

    def resign_finalize(self, source: dict[str, object]) -> None:
        assert self.result_key is not None
        statement = source["statement"]
        assert isinstance(statement, dict)
        statement["results_manifest_sha256"] = ADMISSION.sha256(
            ADMISSION.canonical_json(source["results"])
        )
        signature = self.result_key.sign(
            ADMISSION.RESULT_DOMAIN.encode("ascii")
            + b"\x00"
            + ADMISSION.canonical_json(statement)
        )
        source["result_reviewer_signature_base64"] = base64.b64encode(signature).decode(
            "ascii"
        )


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.fixture = Fixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_prepare_fixture_passes_but_never_authorizes(self) -> None:
        receipt = self.fixture.prepare()
        self.assertTrue(receipt["machine_prepare_composition_valid"])
        self.assertTrue(receipt["file_contract_valid"])
        self.assertFalse(receipt["precontact_admission_ready"])
        self.assertFalse(receipt["authorization_a_granted"])
        self.assertEqual(receipt["device_contact"], "none")
        self.assertTrue(all(value is False for value in receipt["claims"].values()))
        for key, expected in ADMISSION.TYPED_STATE_POLICY.items():
            self.assertIs(receipt[key], expected)
        for result in receipt["signatures"].values():
            self.assertEqual(
                result,
                {
                    "cryptographically_verified": True,
                    "production_key_pin_verified": False,
                    "authority_proven": False,
                },
            )

    def test_generic_signature_bool_map_is_refused(self) -> None:
        receipt = self.fixture.prepare()
        receipt["signatures"] = {role: True for role in ADMISSION.SIGNER_ROLES}
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "must be an object"):
            ADMISSION.validate_prepare_receipt(receipt)

    def test_fixture_cannot_promote_any_typed_authority_state(self) -> None:
        receipt = self.fixture.prepare()
        for key, expected in ADMISSION.TYPED_STATE_POLICY.items():
            if expected is not False:
                continue
            with self.subTest(key=key):
                candidate = dict(receipt)
                candidate[key] = True
                with self.assertRaisesRegex(ADMISSION.AdmissionError, "typed state"):
                    ADMISSION.validate_prepare_receipt(candidate)
        candidate = dict(receipt)
        candidate["file_contract_valid"] = False
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "typed state"):
            ADMISSION.validate_prepare_receipt(candidate)

    def test_finalize_passes_but_cannot_rewrite_prepare(self) -> None:
        prepared = self.fixture.prepare()
        path, _ = self.fixture.finalize_fixture(prepared)
        receipt = ADMISSION.finalize(
            path,
            self.fixture.finalize_ledger,
            fixture_only=True,
            now=NOW,
        )
        self.assertFalse(receipt["temporal_boundary"]["prepare_decision_altered"])
        self.assertFalse(receipt["authorization_a_granted"])
        self.assertEqual(receipt["device_contact"], "none")
        for key, expected in ADMISSION.TYPED_STATE_POLICY.items():
            self.assertIs(receipt[key], expected)
        self.assertEqual(
            receipt["result_reviewer_signature"],
            {
                "cryptographically_verified": True,
                "production_key_pin_verified": False,
                "authority_proven": False,
            },
        )

    def test_finalize_refuses_promoted_prepare_typed_state(self) -> None:
        prepared = self.fixture.prepare()
        prepared["operator_authorization_a_signature_verified"] = True
        path, _ = self.fixture.finalize_fixture(prepared)
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "typed state"):
            ADMISSION.finalize(
                path,
                self.fixture.finalize_ledger,
                fixture_only=True,
                now=NOW,
            )

    def test_finalize_future_statement_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, _ = self.fixture.finalize_fixture(
            prepared,
            compiled_at=NOW + timedelta(seconds=1),
        )
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "future"):
            ADMISSION.finalize(
                path,
                self.fixture.finalize_ledger,
                fixture_only=True,
                now=NOW,
            )

    def test_manual_ac_requires_post_cut_result(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared, manual_ac=True)
        post = source["results"][1]
        (path.parent / post["path"]).unlink()
        post.update({"status": "not_performed", "path": None, "bytes": None, "sha256": None})
        self.fixture.resign_finalize(source)
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "required"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_prepare_replay_refused(self) -> None:
        self.fixture.prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "overwrite"):
            self.fixture.prepare()

    def test_finalize_replay_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, _ = self.fixture.finalize_fixture(prepared)
        ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "overwrite"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_extra_file_refused(self) -> None:
        (self.fixture.prepare_root / "extra.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "membership"):
            self.fixture.prepare()

    def test_missing_file_refused(self) -> None:
        (self.fixture.prepare_root / "image_receipt.json").unlink()
        with self.assertRaises(ADMISSION.AdmissionError):
            self.fixture.prepare()

    def test_component_hash_substitution_refused(self) -> None:
        path = self.fixture.prepare_root / "telemetry_contract.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "size/digest"):
            self.fixture.prepare()

    def test_component_schema_substitution_refused(self) -> None:
        path = self.fixture.prepare_root / "telemetry_contract.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["schema"] = "wrong.schema"
        raw = ADMISSION.canonical_json(doc)
        path.write_bytes(raw)
        record = self.fixture.plan["components"][4]
        record["bytes"] = len(raw)
        record["sha256"] = ADMISSION.sha256(raw)
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "schema"):
            self.fixture.prepare()

    def test_component_classification_promotion_refused(self) -> None:
        self.fixture.plan["components"][0]["classification"] = ADMISSION.CLASS_AUTH
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "classification"):
            self.fixture.prepare()

    def test_mixed_session_component_refused(self) -> None:
        path = self.fixture.prepare_root / "pool_topology.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["w4_fixture_binding"]["session_id"] = "foreign-session-0001"
        raw = ADMISSION.canonical_json(doc)
        path.write_bytes(raw)
        record = self.fixture.plan["components"][7]
        record["bytes"] = len(raw)
        record["sha256"] = ADMISSION.sha256(raw)
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "fixture binding"):
            self.fixture.prepare()

    def test_trusted_time_record_join_refused(self) -> None:
        self.fixture.plan["session"]["trusted_time_record_sha256"] = "f" * 64
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "trusted-time"):
            self.fixture.prepare()

    def test_unknown_action_refused(self) -> None:
        self.fixture.plan["actions"]["allowed"].append("invented_action")
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "action"):
            self.fixture.prepare()

    def test_phase4_exclusion_cannot_be_removed(self) -> None:
        self.fixture.plan["actions"]["excluded"].remove("phase_4_watchdog_close")
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "action"):
            self.fixture.prepare()

    def test_wrong_domain_refused_before_signature(self) -> None:
        self.fixture.plan["signers"]["operator"]["domain"] = "wrong.domain"
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "domain"):
            self.fixture.prepare()

    def test_invalid_signature_refused(self) -> None:
        self.fixture.source["signatures"]["operator"] = base64.b64encode(b"x" * 64).decode()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "signature invalid"):
            self.fixture.prepare()

    def test_duplicate_signer_key_refused(self) -> None:
        operator = self.fixture.plan["signers"]["operator"]
        reviewer = self.fixture.plan["signers"]["admission_reviewer"]
        operator["sha256"] = reviewer["sha256"]
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "distinct"):
            self.fixture.prepare()

    def test_expired_plan_refused(self) -> None:
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "stale"):
            ADMISSION.prepare(
                self.fixture.source_path,
                self.fixture.prepare_ledger,
                fixture_only=True,
                now=NOW + timedelta(hours=1),
            )

    def test_future_plan_refused(self) -> None:
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "future"):
            ADMISSION.prepare(
                self.fixture.source_path,
                self.fixture.prepare_ledger,
                fixture_only=True,
                now=NOW - timedelta(hours=1),
            )

    def test_duplicate_json_key_refused(self) -> None:
        self.fixture.source_path.write_bytes(b'{"schema":"x","schema":"y"}\n')
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "malformed"):
            self.fixture.prepare()

    def test_nonfinite_json_refused(self) -> None:
        self.fixture.source_path.write_bytes(b'{"schema":NaN}\n')
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "malformed"):
            self.fixture.prepare()

    def test_production_refuses_empty_compiled_pins(self) -> None:
        self.fixture.plan["mode"] = "production"
        self.fixture.resign()
        self.fixture.rewrite_prepare()
        with mock.patch.object(ADMISSION, "validate_production_component"):
            with self.assertRaisesRegex(ADMISSION.AdmissionError, "not provisioned"):
                ADMISSION.prepare(
                    self.fixture.source_path,
                    self.fixture.prepare_ledger,
                    fixture_only=False,
                    now=NOW,
                )

    def test_result_session_mix_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        source["statement"]["session_id"] = "foreign-session-0001"
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "mixes"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_result_cannot_claim_authorization(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        source["statement"]["authorization_a_granted"] = True
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "cannot grant"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_result_producer_substitution_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        source["results"][0]["producer_sha256"] = "f" * 64
        self.fixture.resign_finalize(source)
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "producer"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_result_extra_file_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, _ = self.fixture.finalize_fixture(prepared)
        (path.parent / "extra.bin").write_bytes(b"x")
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "membership"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_result_fixture_binding_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        result = source["results"][0]
        result_path = path.parent / result["path"]
        doc = json.loads(result_path.read_text(encoding="utf-8"))
        doc["w4_fixture_result_binding"]["role"] = "foreign_result"
        raw = ADMISSION.canonical_json(doc)
        result_path.write_bytes(raw)
        result["bytes"] = len(raw)
        result["sha256"] = ADMISSION.sha256(raw)
        self.fixture.resign_finalize(source)
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "fixture join"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_unsigned_result_manifest_substitution_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        source["results"][0]["sha256"] = "f" * 64
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "signed results manifest"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_validly_resigned_cross_session_unit_nonce_and_role_results_refused(self) -> None:
        attacks = {
            "session_id": "foreign-session-0001",
            "unit_id_hmac_sha256": "b" * 64,
            "unit_fingerprint_hmac_sha256": "c" * 64,
            "nonce_sha256": "d" * 64,
            "role": "foreign_result",
        }
        for key, replacement in attacks.items():
            with self.subTest(key=key):
                isolated = Path(tempfile.mkdtemp(dir=self.root)).resolve()
                candidate_fixture = Fixture(isolated)
                candidate_prepared = candidate_fixture.prepare()
                path, source = candidate_fixture.finalize_fixture(candidate_prepared)
                result = source["results"][0]
                result_path = path.parent / result["path"]
                document = json.loads(result_path.read_text(encoding="utf-8"))
                document["a_session_join"][key] = replacement
                raw = ADMISSION.canonical_json(document)
                result_path.write_bytes(raw)
                result["bytes"] = len(raw)
                result["sha256"] = ADMISSION.sha256(raw)
                candidate_fixture.resign_finalize(source)
                path.write_bytes(ADMISSION.canonical_json(source))
                with self.assertRaisesRegex(ADMISSION.AdmissionError, "join mismatch"):
                    ADMISSION.finalize(
                        path,
                        candidate_fixture.finalize_ledger,
                        fixture_only=True,
                        now=NOW,
                    )

    def test_validly_resigned_result_byte_extension_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        result = source["results"][0]
        result_path = path.parent / result["path"]
        document = json.loads(result_path.read_text(encoding="utf-8"))
        document["unreviewed_extra"] = True
        raw = ADMISSION.canonical_json(document)
        result_path.write_bytes(raw)
        result["bytes"] = len(raw)
        result["sha256"] = ADMISSION.sha256(raw)
        self.fixture.resign_finalize(source)
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "key set"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_result_reviewer_signature_refused(self) -> None:
        prepared = self.fixture.prepare()
        path, source = self.fixture.finalize_fixture(prepared)
        source["result_reviewer_signature_base64"] = base64.b64encode(b"z" * 64).decode()
        path.write_bytes(ADMISSION.canonical_json(source))
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "signature invalid"):
            ADMISSION.finalize(path, self.fixture.finalize_ledger, fixture_only=True, now=NOW)

    def test_relative_source_refused(self) -> None:
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "absolute"):
            ADMISSION.prepare(
                Path("relative.json"),
                self.fixture.prepare_ledger,
                fixture_only=True,
                now=NOW,
            )

    def test_symlink_component_refused_when_supported(self) -> None:
        target = self.fixture.prepare_root / "image_receipt.json"
        saved = self.fixture.prepare_root / "saved-image-receipt.json"
        target.rename(saved)
        try:
            target.symlink_to(saved.name)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ADMISSION.AdmissionError):
            self.fixture.prepare()

    def test_hard_link_component_refused_when_supported(self) -> None:
        target = self.fixture.prepare_root / "image_receipt.json"
        saved = self.root / "saved-image-receipt.json"
        target.rename(saved)
        try:
            os.link(saved, target)
        except OSError:
            self.skipTest("hard-link creation unavailable")
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "non-alias"):
            self.fixture.prepare()

    def test_template_is_deliberately_invalid_and_non_authorizing(self) -> None:
        template = MODULE_PATH.with_name("nano3_a_session_admission.template.json")
        receipt = ADMISSION.validate_template(template)
        self.assertEqual(receipt["status"], "INTENTIONALLY_INVALID_NONAUTHORIZING_TEMPLATE")
        self.assertFalse(receipt["authorization_a_granted"])
        self.assertEqual(receipt["device_contact"], "none")


if __name__ == "__main__":
    unittest.main()
