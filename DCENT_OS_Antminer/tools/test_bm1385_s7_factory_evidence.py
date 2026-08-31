from __future__ import annotations

import ast
from dataclasses import fields, replace
from pathlib import Path

import pytest

import bm1385_s7_factory_evidence as evidence


_FIXTURES = Path(__file__).with_name("fixtures") / "bm1385_s7"


@pytest.fixture(scope="session")
def exact_inputs() -> dict[str, bytes]:
    return {
        "s7_45_config": (_FIXTURES / "Config.ini-S7-45").read_bytes(),
        "s7_54_config": (_FIXTURES / "Config.ini-S7-54").read_bytes(),
    }


@pytest.fixture(scope="session")
def receipt(exact_inputs):
    return evidence.inspect_bm1385_s7_factory_evidence(**exact_inputs)


def test_exact_fixtures_mint_two_profile_receipts(receipt):
    assert receipt.evidence_verified is True
    assert len(receipt.artifacts) == 2
    assert all(item.exact_bytes_verified for item in receipt.artifacts)
    assert [item.size_bytes for item in receipt.artifacts] == [2_055, 2_066]
    assert [item.sha256 for item in receipt.artifacts] == [
        "632abf407d5ea7f527f219322d3470ab9a1e2756b33dc0471ed1e01cc2b361c2",
        "7df112aef6246d376f6c02088ad1e9baeac72d8bbfd8b351232f56704baa1177",
    ]
    assert [item.variant for item in receipt.profiles] == ["S7-45", "S7-54"]
    assert all(item.exact_config_verified for item in receipt.profiles)


def test_s7_45_profile_is_typed_exactly(receipt):
    profile = receipt.profiles[0]
    assert (profile.asic_type_label, profile.asic_count, profile.cores_per_asic) == (
        1_385,
        45,
        50,
    )
    assert profile.open_core_gap_raw == 50_000
    assert profile.frequencies_mhz == (600, 600, 600, 0, 0, 0, 0, 0, 0)
    assert profile.voltages_raw == (1_025, 1_050, 1_075, 0, 0, 0, 0, 0, 0)
    assert profile.valid_nonces == (18_000,) * 9


def test_s7_54_profile_is_typed_exactly(receipt):
    profile = receipt.profiles[1]
    assert (profile.asic_type_label, profile.asic_count, profile.cores_per_asic) == (
        1_385,
        54,
        50,
    )
    assert profile.open_core_gap_raw == 100_000
    assert profile.frequencies_mhz == (
        500,
        550,
        525,
        400,
        400,
        400,
        400,
        400,
        400,
    )
    assert profile.voltages_raw == (945, 975, 1_005, 0, 0, 0, 0, 0, 0)
    assert profile.valid_nonces == (21_600,) * 9


def test_shared_factory_fields_do_not_mint_controller_authority(receipt):
    for profile in receipt.profiles:
        assert profile.command_mode == 1
        assert profile.pass_counts == (400,) * 9
        assert profile.temperature_source == "external LM75A over IIC"
        assert profile.temperature_sensors_raw == (62, 0, 0, 0)
        assert profile.open_core_masks == (
            4_294_967_295,
            4_294_967_295,
            4_294_967_295,
            262_143,
        )
        assert profile.pic_voltage is True
        assert profile.iic_pic is False
        assert profile.dac is False
        assert profile.runtime_profile_authorized is False
    assert len(receipt.unresolved) == 7
    assert all(
        getattr(receipt.authority, item.name) is False
        for item in fields(receipt.authority)
    )


def test_exact_size_mutation_and_nonbytes_reject(exact_inputs):
    wrong_size = dict(exact_inputs)
    wrong_size["s7_45_config"] += b"x"
    with pytest.raises(evidence.Bm1385S7EvidenceError, match="expected 2055"):
        evidence.inspect_bm1385_s7_factory_evidence(**wrong_size)

    changed = bytearray(exact_inputs["s7_54_config"])
    changed[10] ^= 1
    wrong_hash = dict(exact_inputs)
    wrong_hash["s7_54_config"] = bytes(changed)
    with pytest.raises(evidence.Bm1385S7EvidenceError, match="SHA-256 mismatch"):
        evidence.inspect_bm1385_s7_factory_evidence(**wrong_hash)

    nonbytes = dict(exact_inputs)
    nonbytes["s7_45_config"] = bytearray(nonbytes["s7_45_config"])
    with pytest.raises(TypeError, match="immutable exact bytes"):
        evidence.inspect_bm1385_s7_factory_evidence(**nonbytes)


def test_control_arguments_and_direct_trust_injection_reject(exact_inputs):
    with pytest.raises(TypeError, match="unexpected keyword"):
        evidence.inspect_bm1385_s7_factory_evidence(
            **exact_inputs, device="/dev/ttyS0"
        )
    with pytest.raises(TypeError):
        evidence.Authority(device_io=True)
    authority = evidence.Authority()
    assert all(getattr(authority, item.name) is False for item in fields(authority))


def test_direct_construction_and_replace_do_not_mint_exactness(receipt):
    artifact = evidence.ArtifactReceipt("x", 1, "00", "held", "fixture")
    assert artifact.exact_bytes_verified is False
    forged_artifact = replace(receipt.artifacts[0], sha256="00")
    assert forged_artifact.exact_bytes_verified is False
    forged_profile = replace(receipt.profiles[0], asic_count=54)
    assert forged_profile.exact_config_verified is False
    assert forged_profile.runtime_profile_authorized is False
    forged_receipt = replace(receipt, unresolved=())
    assert forged_receipt.evidence_verified is False


def test_prior_receipt_poisoning_cannot_change_fresh_receipt(exact_inputs):
    first = evidence.inspect_bm1385_s7_factory_evidence(**exact_inputs)
    object.__setattr__(first, "evidence_verified", False)
    object.__setattr__(first.profiles[0], "asic_count", 999)
    object.__setattr__(first.profiles[0], "runtime_profile_authorized", True)
    fresh = evidence.inspect_bm1385_s7_factory_evidence(**exact_inputs)
    assert fresh.evidence_verified is True
    assert fresh.profiles[0].asic_count == 45
    assert fresh.profiles[0].runtime_profile_authorized is False


def test_public_global_shadowing_cannot_forge_inspection(monkeypatch, exact_inputs):
    baseline = evidence.inspect_bm1385_s7_factory_evidence(**exact_inputs)
    for name in (
        "SPECS",
        "EXPECTED_PROFILE_KEYS",
        "MAX_TOTAL_BYTES",
        "len",
        "sum",
        "zip",
        "bytes",
        "ArtifactReceipt",
        "FactoryProfileObservation",
        "Bm1385S7EvidenceReceipt",
    ):
        monkeypatch.setattr(evidence, name, lambda *_args, **_kwargs: None, raising=False)
    assert evidence.inspect_bm1385_s7_factory_evidence(**exact_inputs) == baseline


def test_source_is_bytes_only_and_has_no_action_surface():
    source_path = Path(evidence.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    banned_imports = {
        "argparse",
        "os",
        "pathlib",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".")[0] not in banned_imports for alias in node.names
            )
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned_imports
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {
                "open",
                "exec",
                "eval",
                "compile",
                "__import__",
            }
