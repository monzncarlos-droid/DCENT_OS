#!/usr/bin/env python3
"""Adversarial tests for the offline Antminer universal on-ramp controller.

Tests read the REAL campaign manifest and the REAL repository tree wherever
verification is read-only; every receipt write is isolated under tmp_path so
the real evidence root is never mutated by this suite.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "universal_onramp_workflow.py"
SPEC = importlib.util.spec_from_file_location("universal_onramp_workflow", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)

WAVE = ""
SECOND_WAVE = [
    "onramp-controller-contract",
    "eula-posture-recorded",
    "stock-onramp-blueprint",
    "per-platform-install-artifacts",
    "roster-completion-v124",
    "revert-custody-design",
]
OPERATOR_LANES = [
    "s9-public-capstone",
    "xil-s19jpro-capstone",
    "bb-single-artifact",
    "s21-aml-install-proof",
    "s21pro-first-light",
    "bm1398-native-runtime",
    "stock-onramp-live-proof",
    "uart-ramboot-proofs",
    "nand-coexistence-pilot",
    "release-signing-ceremony",
]
# With an empty evidence root the dispatchable set is the manifest's own
# first wave: the triplet capstone, the armada-unblocked EEPROM arm, and the
# two dependency-free reference lanes.
INITIAL_DISPATCHABLE = [
    "triplet-re-consolidated",
    "eeprom-format1-arm",
    "s19k-reference-join",
    "dcent-ctrl-board-track",
]


@pytest.fixture(scope="session")
def manifest() -> tuple[dict, str]:
    return workflow.load_manifest(workflow.DEFAULT_MANIFEST)


@pytest.fixture()
def evidence(tmp_path: Path) -> Path:
    return tmp_path / workflow.DEFAULT_EVIDENCE_DIR


def lane_of(document: dict, lane_id: str) -> dict:
    return next(item for item in document["phases"] if item["id"] == lane_id)


def states_of(report: dict) -> dict[str, str]:
    return {item["lane_id"]: item["state"] for item in report["lanes"]}


def write_manifest(document: dict, path: Path) -> tuple[dict, str]:
    path.write_text(json.dumps(document), encoding="utf-8")
    return workflow.load_manifest(path)


def test_real_manifest_loads_with_23_lanes_and_byte_bound_hash(
    manifest: tuple[dict, str],
) -> None:
    document, manifest_sha = manifest
    assert document["schema"] == workflow.SCHEMA
    assert len(document["phases"]) == 23
    assert len({lane["id"] for lane in document["phases"]}) == 23
    # Receipts bind the exact manifest bytes on disk.
    raw = workflow.DEFAULT_MANIFEST.read_bytes()
    assert manifest_sha == hashlib.sha256(raw).hexdigest()


def test_controller_is_offline_and_grants_no_authority(
    manifest: tuple[dict, str],
) -> None:
    document, _ = manifest
    policy = document["contact_policy"]
    assert policy["controller_may_grant_authority"] is False
    assert policy["controller_is_offline_only"] is True
    assert policy["live_contact_requires_fresh_operator_authorization"] is True
    assert policy["nand_write_requires_separate_explicit_authorization"] is True
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import requests",
        "import paramiko",
        "subprocess",
        "urllib",
        "ssh ",
        "scp ",
        "/sys/class/gpio",
        "flash_erase",
        "nandwrite",
    ):
        assert forbidden not in source, forbidden


def test_manifest_validation_fails_closed(
    manifest: tuple[dict, str], tmp_path: Path
) -> None:
    document, _ = manifest

    def bad_schema(doc: dict) -> None:
        doc["schema"] = "dcentos.other/v1"

    def duplicate_id(doc: dict) -> None:
        doc["phases"][1]["id"] = doc["phases"][0]["id"]

    def unknown_dependency(doc: dict) -> None:
        doc["phases"][0]["depends_on"] = ["no-such-lane"]

    def dependency_cycle(doc: dict) -> None:
        doc["phases"][0]["depends_on"] = [doc["phases"][-1]["id"]]

    def grants_authority(doc: dict) -> None:
        doc["contact_policy"]["controller_may_grant_authority"] = True

    def offline_disabled(doc: dict) -> None:
        doc["contact_policy"]["controller_is_offline_only"] = False

    def missing_policy_flag(doc: dict) -> None:
        doc["contact_policy"].pop(
            "nand_write_requires_separate_explicit_authorization"
        )

    def bad_kind(doc: dict) -> None:
        doc["phases"][0]["kind"] = "teleport"

    def bad_verifier(doc: dict) -> None:
        doc["phases"][0]["verifier"]["kind"] = "oracle"

    def missing_wave_docs(doc: dict) -> None:
        doc.pop("wave_docs")  # triplet spec uses {wave_docs}

    def empty_title(doc: dict) -> None:
        doc["phases"][0]["title"] = ""

    def bad_required_paths(doc: dict) -> None:
        doc["phases"][0]["verifier"]["required_paths"] = [17]

    mutations = [
        bad_schema,
        duplicate_id,
        unknown_dependency,
        dependency_cycle,
        grants_authority,
        offline_disabled,
        missing_policy_flag,
        bad_kind,
        bad_verifier,
        missing_wave_docs,
        empty_title,
        bad_required_paths,
    ]
    for index, mutate in enumerate(mutations):
        mutated = copy.deepcopy(document)
        mutate(mutated)
        path = tmp_path / f"mutated-{index}.json"
        with pytest.raises(workflow.WorkflowError):
            write_manifest(mutated, path)


def test_required_paths_resolution_against_the_real_tree(
    manifest: tuple[dict, str],
) -> None:
    document, _ = manifest
    triplet = workflow.resolve_required_paths(
        document, lane_of(document, "triplet-re-consolidated")
    )
    assert triplet["required_paths"] == [
        f"{WAVE}/deliverables/L1_DOCUMENTARY_ASSETS_MINE.md",
        f"{WAVE}/deliverables/L2_RIGRUNNER_BINARY_RE.md",
        f"{WAVE}/deliverables/L3_UMCOS_V124_DELTA_MINE.md",
        f"{WAVE}/deliverables/L4_ALL_ANTMINER_COVERAGE_MATRIX.md",
        f"{WAVE}/FINDINGS.md",  # bare filename binds to the wave-docs root
    ]
    assert triplet["ignored_prose"] == []
    for rel in triplet["required_paths"]:
        assert (workflow.REPO_ROOT / rel).is_file(), rel

    controller = workflow.resolve_required_paths(
        document, lane_of(document, "onramp-controller-contract")
    )
    assert controller["required_paths"] == [
        "DCENT_OS_Antminer/scripts/universal_onramp_workflow.py",
        "DCENT_OS_Antminer/scripts/test_universal_onramp_workflow.py",
    ]
    assert workflow.resolve_required_paths(
        document, lane_of(document, "eula-posture-recorded")
    )["required_paths"] == [
        ""
    ]
    assert workflow.resolve_required_paths(
        document, lane_of(document, "stock-onramp-blueprint")
    )["required_paths"] == [f"{WAVE}/deliverables/STOCK_ONRAMP_BLUEPRINT.md"]
    assert workflow.resolve_required_paths(
        document, lane_of(document, "stock-onramp-implemented")
    )["required_paths"] == ["projects/dcent-toolbox/src/dcent_toolbox"]
    roster = workflow.resolve_required_paths(
        document, lane_of(document, "roster-completion-v124")
    )
    assert roster["required_paths"] == [
        "DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/src/hashboards.rs",
        "SUPPORT_MATRIX.md",
    ]
    eeprom = workflow.resolve_required_paths(
        document, lane_of(document, "eeprom-format1-arm")
    )
    # Partial unqualified paths stay exactly as written (fail closed, no
    # prefix guessing); prose segments are recorded, never resolved.
    assert eeprom["required_paths"] == [
        "dcentrald-api-types/src/deployed_eeprom.rs",
        "tools/decrypt_eeprom.py",
    ]
    assert eeprom["ignored_prose"] == ["dcent-toolbox preflight"]
    assert workflow.resolve_required_paths(
        document, lane_of(document, "matrix-promotion-gates")
    )["required_paths"] == ["SUPPORT_MATRIX.md"]

    for lane_id in ("s9-public-capstone", "s19k-reference-join"):
        with pytest.raises(workflow.WorkflowError):
            workflow.resolve_required_paths(document, lane_of(document, lane_id))


def test_triplet_lane_verifies_for_real_with_isolated_evidence(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    receipt = workflow.verify_lane(
        document, manifest_sha, "triplet-re-consolidated", evidence
    )
    assert receipt["lane"] == "triplet-re-consolidated"
    assert receipt["verifier_kind"] == "deliverable"
    assert receipt["manifest_sha256"] == manifest_sha
    assert receipt["verified_at"].endswith("Z")
    assert (evidence / "triplet-re-consolidated" / "verification.json").is_file()
    assert receipt["checks"][0]["check"] == "contract_resolution"
    path_checks = [
        check for check in receipt["checks"] if check["check"] == "path_exists"
    ]
    assert len(path_checks) == 5
    assert all(
        check["present"] is True
        and check["type"] == "file"
        and len(check["sha256"]) == 64
        for check in path_checks
    )
    report = workflow.derive_status(document, manifest_sha, evidence)
    assert states_of(report)["triplet-re-consolidated"] == "verified"


def test_dependency_ordering_opens_second_wave_only_after_triplet(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    before = workflow.derive_status(document, manifest_sha, evidence)
    assert before["dispatchable_now"] == INITIAL_DISPATCHABLE
    states = states_of(before)
    for lane_id in SECOND_WAVE:
        assert states[lane_id] == "pending"
    assert states["matrix-promotion-gates"] == "pending"
    assert before["complete"] is False
    with pytest.raises(workflow.DependencyGateError):
        workflow.verify_lane(
            document, manifest_sha, "onramp-controller-contract", evidence
        )

    workflow.verify_lane(document, manifest_sha, "triplet-re-consolidated", evidence)
    after = workflow.derive_status(document, manifest_sha, evidence)
    states = states_of(after)
    for lane_id in SECOND_WAVE:
        assert states[lane_id] == "dispatchable"
    assert set(SECOND_WAVE) <= set(after["dispatchable_now"])
    assert states["matrix-promotion-gates"] == "pending"


def test_operator_lanes_are_refused_and_never_verified(
    manifest: tuple[dict, str], evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    document, manifest_sha = manifest
    for lane_id in OPERATOR_LANES:
        with pytest.raises(workflow.OperatorAuthorityRefusal):
            workflow.verify_lane(document, manifest_sha, lane_id, evidence)
    assert not (evidence / "release-signing-ceremony").exists()
    code = workflow.main(
        [
            "--manifest",
            str(workflow.DEFAULT_MANIFEST),
            "--evidence-root",
            str(evidence),
            "verify",
            "xil-s19jpro-capstone",
        ]
    )
    captured = capsys.readouterr()
    assert code == 3
    assert "OPERATOR_AUTHORITY_REQUIRED" in captured.err
    assert "operator authorization" in captured.err
    report = workflow.derive_status(document, manifest_sha, evidence)
    states = states_of(report)
    for lane_id in OPERATOR_LANES:
        assert states[lane_id] == "awaiting-operator"
    assert not any(
        item["state"] == "verified" for item in report["lanes"]
    )


def test_reference_lanes_verify_from_attestation_receipt_only(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    with pytest.raises(workflow.WorkflowError):  # no receipt yet
        workflow.verify_lane(document, manifest_sha, "s19k-reference-join", evidence)

    lane_dir = evidence / "s19k-reference-join"
    lane_dir.mkdir(parents=True)
    receipt_path = lane_dir / "verification.json"
    receipt_path.write_text(
        json.dumps(
            {
                "lane": "s19k-reference-join",
                "verified_by": "DCENT_QA",
                "method": "manifest grep + path existence, recomputed fresh",
            }
        ),
        encoding="utf-8",
    )
    receipt = workflow.verify_lane(
        document, manifest_sha, "s19k-reference-join", evidence
    )
    assert receipt["verifier_kind"] == "assertion-free"
    assert receipt["verified_by"] == "DCENT_QA"
    assert receipt["manifest_sha256"] == manifest_sha
    check = receipt["checks"][0]
    assert check["check"] == "assertion_free_receipt"
    assert check["path"].endswith("s19k-reference-join/verification.json")
    # Idempotent: the merged receipt re-verifies cleanly.
    assert workflow.verify_lane(
        document, manifest_sha, "s19k-reference-join", evidence
    )["lane"] == "s19k-reference-join"
    assert (
        states_of(workflow.derive_status(document, manifest_sha, evidence))[
            "s19k-reference-join"
        ]
        == "verified"
    )

    receipt_path.write_text(
        json.dumps(
            {"lane": "somebody-else", "verified_by": "x", "method": "y"}
        ),
        encoding="utf-8",
    )
    with pytest.raises(workflow.WorkflowError):
        workflow.verify_lane(document, manifest_sha, "s19k-reference-join", evidence)
    receipt_path.write_text(
        json.dumps({"lane": "s19k-reference-join", "verified_by": "x"}),
        encoding="utf-8",
    )
    with pytest.raises(workflow.WorkflowError):
        workflow.verify_lane(document, manifest_sha, "s19k-reference-join", evidence)


def test_repo_and_hosttest_verifier_kinds(
    manifest: tuple[dict, str], evidence: Path, tmp_path: Path
) -> None:
    document, manifest_sha = manifest
    # Repo kind on the real manifest: the controller lane's two scripts.
    workflow.verify_lane(document, manifest_sha, "triplet-re-consolidated", evidence)
    repo_receipt = workflow.verify_lane(
        document, manifest_sha, "onramp-controller-contract", evidence
    )
    assert repo_receipt["verifier_kind"] == "repo"
    file_checks = [
        check for check in repo_receipt["checks"] if check["check"] == "path_exists"
    ]
    assert len(file_checks) == 2
    assert all(
        check["present"] is True and check["type"] == "file" and "sha256" in check
        for check in file_checks
    )
    assert all(
        check["check"] != "hosttest_pending" for check in repo_receipt["checks"]
    )

    # repo+hosttest kind: repo paths check fresh; the host pass stays manual.
    mutated = copy.deepcopy(document)
    mutated["phases"] = [
        lane_of(document, "triplet-re-consolidated"),
        {
            "id": "hosttest-lane",
            "track": "T",
            "title": "hosttest fixture lane",
            "kind": "code",
            "expert": "DCENT_CE",
            "review": "DCENT_QA",
            "depends_on": ["triplet-re-consolidated"],
            "verifier": {
                "kind": "repo+hosttest",
                "required_paths": [
                    "DCENT_OS_Antminer/scripts/universal_onramp_workflow.py"
                ],
            },
        },
    ]
    hosttest_document, hosttest_sha = write_manifest(
        mutated, tmp_path / "hosttest-manifest.json"
    )
    # Rebind the triplet receipt to the mutated manifest so the fixture lane's
    # dependency is satisfied inside the same isolated evidence root.
    workflow.verify_lane(
        hosttest_document, hosttest_sha, "triplet-re-consolidated", evidence
    )
    hosttest_receipt = workflow.verify_lane(
        hosttest_document, hosttest_sha, "hosttest-lane", evidence
    )
    assert hosttest_receipt["verifier_kind"] == "repo+hosttest"
    hosttest = [
        check
        for check in hosttest_receipt["checks"]
        if check["check"] == "hosttest_pending"
    ]
    assert len(hosttest) == 1
    assert "manual" in hosttest[0]["note"]


def test_failed_checks_write_no_receipt(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    workflow.verify_lane(document, manifest_sha, "triplet-re-consolidated", evidence)
    with pytest.raises(workflow.WorkflowError) as excinfo:
        workflow.verify_lane(document, manifest_sha, "eula-posture-recorded", evidence)
    assert "EPIC_LICENSE_POSTURE_20260825.md" in str(excinfo.value)
    assert not (evidence / "eula-posture-recorded").exists()


def test_unknown_lane_and_dependency_gate_exit_codes(
    manifest: tuple[dict, str], evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    code = workflow.main(
        [
            "--manifest",
            str(workflow.DEFAULT_MANIFEST),
            "--evidence-root",
            str(evidence),
            "verify",
            "no-such-lane",
        ]
    )
    assert code == 2
    code = workflow.main(
        [
            "--manifest",
            str(workflow.DEFAULT_MANIFEST),
            "--evidence-root",
            str(evidence),
            "verify",
            "onramp-controller-contract",
        ]
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "VERIFY_REFUSED" in captured.err


def test_status_is_deterministic_and_reports_operator_gates(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    first = workflow.derive_status(document, manifest_sha, evidence)
    assert first == workflow.derive_status(document, manifest_sha, evidence)
    assert first["complete"] is False
    gates = {
        gate["lane_id"]: gate["dependencies_satisfied"]
        for gate in first["operator_gates"]
    }
    assert gates == {
        "s9-public-capstone": False,
        "xil-s19jpro-capstone": False,
        "bb-single-artifact": False,
        "s21-aml-install-proof": False,
        "s21pro-first-light": False,
        "bm1398-native-runtime": False,
        "stock-onramp-live-proof": False,
        "uart-ramboot-proofs": False,
        "nand-coexistence-pilot": False,
        "release-signing-ceremony": True,
    }
    rendered = workflow.render_status(first)
    assert "campaign=antminer-universal-onramp-20260825" in rendered
    assert (
        "dispatchable_now=" + ",".join(INITIAL_DISPATCHABLE) in rendered
    )
    assert "operator_gates_ready=release-signing-ceremony" in rendered


def test_operator_receipt_unblocks_dependents_without_controller_verification(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    lane_dir = evidence / "release-signing-ceremony"
    lane_dir.mkdir(parents=True)
    (lane_dir / "verification.json").write_text(
        json.dumps(
            {
                "lane": "release-signing-ceremony",
                "verified_by": "operator witness",
                "verified_at": "2026-08-25T00:00:00Z",
                "manifest_sha256": manifest_sha,
            }
        ),
        encoding="utf-8",
    )
    report = workflow.derive_status(document, manifest_sha, evidence)
    by_id = {item["lane_id"]: item for item in report["lanes"]}
    # Still never "verified": the controller only records the receipt.
    assert by_id["release-signing-ceremony"]["state"] == "awaiting-operator"
    assert by_id["release-signing-ceremony"]["operator_receipt_present"] is True
    gates = {gate["lane_id"]: gate for gate in report["operator_gates"]}
    assert gates["s9-public-capstone"]["dependencies_satisfied"] is True
    assert gates["xil-s19jpro-capstone"]["dependencies_satisfied"] is True
    with pytest.raises(workflow.OperatorAuthorityRefusal):
        workflow.verify_lane(
            document, manifest_sha, "release-signing-ceremony", evidence
        )


def test_emit_agent_tasks_cards_carry_contract_and_prohibitions(
    manifest: tuple[dict, str], evidence: Path
) -> None:
    document, manifest_sha = manifest
    report = workflow.derive_status(document, manifest_sha, evidence)
    wave = workflow.emit_agent_tasks(document, report)
    assert wave["max_parallel_agents"] == 3
    assert [card["lane_id"] for card in wave["tasks"]] == INITIAL_DISPATCHABLE
    for card in wave["tasks"] + wave["operator_gates"]:
        lane = lane_of(document, card["lane_id"])
        assert card["standing_prohibitions"] == workflow.STANDING_PROHIBITIONS
        assert card["caveats"] == document["epic_caveats_binding"]
        assert card["owner"] == lane["expert"]
        assert card["reviewer"] == lane["review"]
        assert card["kind"] == lane["kind"]
        assert card["title"] == lane["title"]
        assert card["depends_on"] == lane["depends_on"]
        assert card["evidence_contract"] == lane["verifier"]
        assert card["evidence_dir"].startswith(".universal-onramp-evidence/")
    assert len(wave["operator_gates"]) == len(OPERATOR_LANES)
    gate = next(
        card
        for card in wave["operator_gates"]
        if card["lane_id"] == "release-signing-ceremony"
    )
    assert gate["requires_fresh_operator_authorization"] is True
    assert gate["dependencies_satisfied"] is True
    assert all(
        card["requires_fresh_operator_authorization"] is True
        for card in wave["operator_gates"]
    )
    again = workflow.emit_agent_tasks(
        document, workflow.derive_status(document, manifest_sha, evidence)
    )
    assert again == wave  # deterministic


def test_cli_status_exits_zero_and_json_round_trips(
    manifest: tuple[dict, str], evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    code = workflow.main(
        [
            "--manifest",
            str(workflow.DEFAULT_MANIFEST),
            "--evidence-root",
            str(evidence),
            "status",
        ]
    )
    assert code == 0
    rendered = capsys.readouterr().out
    assert rendered.startswith("campaign=antminer-universal-onramp-20260825")
    assert "complete=false" in rendered
    code = workflow.main(
        [
            "--manifest",
            str(workflow.DEFAULT_MANIFEST),
            "--evidence-root",
            str(evidence),
            "status",
            "--json",
        ]
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == workflow.STATUS_SCHEMA
    assert report["dispatchable_now"] == INITIAL_DISPATCHABLE
    code = workflow.main(
        [
            "--manifest",
            str(workflow.DEFAULT_MANIFEST),
            "--evidence-root",
            str(evidence),
            "emit-agent-tasks",
            "--json",
        ]
    )
    assert code == 0
    wave = json.loads(capsys.readouterr().out)
    assert wave["schema"] == workflow.WAVE_SCHEMA
    assert [card["lane_id"] for card in wave["tasks"]] == INITIAL_DISPATCHABLE


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
