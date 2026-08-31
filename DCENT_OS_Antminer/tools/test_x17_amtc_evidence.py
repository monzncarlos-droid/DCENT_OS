from __future__ import annotations

import ast
from dataclasses import fields, replace
from functools import lru_cache
import hashlib
from pathlib import Path
import struct
import zipfile

import pytest

import x17_amtc_evidence as evidence


_WORKSPACE = Path(__file__).resolve().parents[3]
_AMTC = Path(
    r" Testing Files-20230123T153653Z-001\AMTC Testing Files"
)
_REJECTED_CROSS_GENERATION = Path(
    r""
    r"\bitmain_antminer_binaries-main\S17e\cgminer"
)
_T17E_RECOVERY = _AMTC / "T17e Testing Files" / "SD_T17e.zip"


def _unique_zip(directory: Path, size: int) -> Path:
    matches = [
        path
        for path in directory.glob("*.zip")
        if path.stat().st_size == size and not path.name.startswith("Copy of ")
    ]
    assert len(matches) == 1
    return matches[0]


def _zip_member(path: Path, suffix: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        matches = [
            item for item in archive.infolist() if item.filename.endswith(suffix)
        ]
        assert len(matches) == 1
        return archive.read(matches[0])


def _held_available() -> bool:
    return (
        _AMTC / "S17 Testing Files" / "S17PIC.hex"
    ).is_file() and _REJECTED_CROSS_GENERATION.is_file() and _T17E_RECOVERY.is_file()


@lru_cache(maxsize=1)
def _held_inputs() -> tuple[bytes, ...]:
    s17_jig_zip = _unique_zip(_AMTC / "S17 Testing Files", 30_206_409)
    t17plus_jig_zip = _AMTC / "T17+Testing Files" / "T17+TestJig.zip"
    s17plus_recovery = _unique_zip(_AMTC / "S17+ Testing Files", 32_189_053)
    s17e_recovery = _AMTC / "S17eTesting Files" / "SD-S17e.zip"
    return (
        (_AMTC / "S17 Testing Files" / "S17PIC.hex").read_bytes(),
        (_AMTC / "S17eTesting Files" / "S17ePIC.hex").read_bytes(),
        (_AMTC / "S17+ Testing Files" / "S17+PIC.hex").read_bytes(),
        (_AMTC / "T17+Testing Files" / "T17+PIC.hex").read_bytes(),
        (_AMTC / "T17e Testing Files" / "T17ePIC.hex").read_bytes(),
        _zip_member(s17_jig_zip, "0/Config.ini"),
        _zip_member(t17plus_jig_zip, "T17+/Config.ini"),
        _zip_member(s17_jig_zip, "0/single-board-test"),
        _zip_member(t17plus_jig_zip, "T17+/single-board-test"),
        _REJECTED_CROSS_GENERATION.read_bytes(),
        _zip_member(s17plus_recovery, "bin/runme.sh"),
        _zip_member(s17e_recovery, "bin/runme.sh"),
        _T17E_RECOVERY.read_bytes(),
    )


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_exact_held_artifacts_mint_bounded_evidence_receipt():
    receipt = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    assert receipt.evidence_verified is True
    assert len(receipt.artifacts) == 13
    assert all(item.member_identity_verified for item in receipt.artifacts)
    assert receipt.pic_cohorts[0].member_ids == ("s17_pic", "s17e_pic")
    assert receipt.pic_cohorts[0].physical_mcu_identity_proven is False
    assert receipt.pic_cohorts[1].member_ids == (
        "s17plus_pic",
        "t17plus_pic",
        "t17e_pic",
    )
    assert receipt.pic_cohorts[1].maximum_program_address == 0x10011
    assert receipt.jig_profiles[0].hashboard == "BHB07601"
    assert receipt.jig_profiles[0].asic_count == 48
    assert receipt.jig_profiles[1].hashboard == "BHB07702"
    assert receipt.jig_profiles[1].asic_count == 44
    assert all(
        item.exact_config_and_binary_bytes_verified for item in receipt.jig_profiles
    )
    rejected = receipt.rejected_cross_generation_bm1391_carrier
    assert rejected.exact_rejected_bytes_verified is True
    assert rejected.rejected_as_x17_product_evidence is True
    assert rejected.x17_product_model_association_verified is False
    assert rejected.runtime_route_authorized is False
    assert rejected.embedded_asic_count_comparison == 48
    assert (
        receipt.t17plus_factory_transport.updater_reachable_from_held_call_graph
        is False
    )
    assert receipt.t17plus_factory_transport.exact_t17plus_jig_binary_bytes_verified
    assert (
        receipt.t17plus_factory_transport.physical_mcu_identity_proven_by_updater_label
        is False
    )
    assert receipt.recovery_writer.atomic_update_proven is False
    assert receipt.recovery_writer.t17e_parent_exact_bytes_verified is True
    assert receipt.recovery_writer.t17e_central_directory_verified is True
    assert receipt.recovery_writer.t17e_runme_member_absence_verified is True
    assert "maximal writer branch" in receipt.recovery_writer.emulator_scope
    assert any(
        "T17e SD archive contains no runme.sh" in item for item in receipt.unresolved
    )
    assert receipt.authority == evidence.Authority()
    assert all(
        getattr(receipt.authority, item.name) is False
        for item in fields(receipt.authority)
    )


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_exact_binary_window_and_parent_member_receipts_are_pinned():
    receipt = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    carrier = receipt.rejected_cross_generation_bm1391_carrier
    assert carrier.elf_load_base == 0x10000
    assert carrier.functions[-1].name == "48-ASIC comparison"
    assert carrier.functions[-1].virtual_address == 0x301B8
    assert carrier.functions[-1].file_offset == 0x201B8
    assert carrier.functions[-1].sha256 == (
        "dac9444ae353a4fa15aeb0b0bc32bae751ae39ed9d01a51b2f721dfaf84df158"
    )
    assert all(item.exact_window_verified for item in carrier.functions)
    assert receipt.t17plus_factory_transport.functions[0].virtual_address == 0x72798
    assert receipt.t17plus_factory_transport.functions[0].file_offset == 0x62798
    assert receipt.archive_provenance[0].outer_sha256 == (
        "88c64db57c77e5fced012c946e144ba45f7bded536ef8e13413cbf12c4d61b8e"
    )
    assert receipt.archive_provenance[0].member_crc32 == 0x966483F8
    assert all(
        not item.parent_binding_recomputed for item in receipt.archive_provenance
    )
    assert receipt.artifacts[0].held_paths == ("S17 Testing Files/S17PIC.hex",)
    assert receipt.artifacts[9].held_paths == (
        "bitmain_antminer_binaries-main/S17e/cgminer",
        "bitmain_antminer_binaries-main/T17/cgminer",
        "bitmain_antminer_binaries-main/T17e/cgminer",
    )
    assert receipt.artifacts[12].held_paths == ("T17e Testing Files/SD_T17e.zip",)


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_t17e_parent_inventory_proves_script_absence_without_recovery_authority():
    receipt = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    recovery = receipt.recovery_writer
    assert recovery.t17e_parent_artifact_id == "t17e_recovery_parent"
    assert recovery.t17e_central_directory_entries == (
        "SD_T17e/",
        "SD_T17e/BOOT.bin",
        "SD_T17e/devicetree.dtb",
        "SD_T17e/.DS_Store",
        "SD_T17e/bin/",
        "SD_T17e/bin/BOOT.bin",
        "SD_T17e/bin/devicetree.dtb",
        "SD_T17e/bin/uImage",
        "SD_T17e/bin/uramdisk.image.gz",
        "SD_T17e/uImage",
        "SD_T17e/uramdisk.image.gz",
    )
    assert not any(name.endswith("/bin/runme.sh") for name in recovery.t17e_central_directory_entries)
    assert recovery.install_authorized is False
    assert receipt.authority.recovery is False
    assert receipt.authority.flash_write is False


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_exact_factory_profiles_are_typed_but_never_production():
    s17, t17plus = evidence.inspect_x17_amtc_evidence(*_held_inputs()).jig_profiles
    assert (
        s17.model_label,
        s17.hashboard,
        s17.asic_type_label,
        s17.asic_count,
        s17.config_artifact_id,
        s17.scope,
    ) == (
        "S17",
        "BHB07601",
        1397,
        48,
        "s17_config",
        "offline factory-jig profile only",
    )
    assert s17.frequency_steps_mhz == (450, 0, 0, 0, 0, 0, 0, 0, 0)
    assert s17.open_core_gap == 20_000
    assert (s17.timeout_percent, s17.baud_setting, s17.resolved_baud_bps) == (
        10,
        3,
        6_000_000,
    )
    assert (s17.open_core_voltage_raw, s17.voltage_steps_raw) == (
        2_000,
        (1_900, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    assert (s17.sensor_model, s17.temp_sensor_indices) == (1, (9, 12, 40, 37))
    assert (s17.fan_setting, s17.fan_scale_max, s17.core_clock_delay) == (
        10,
        10,
        0x34,
    )

    assert (t17plus.model_label, t17plus.hashboard, t17plus.asic_count) == (
        "T17+",
        "BHB07702",
        44,
    )
    assert t17plus.frequency_steps_mhz == (
        700,
        680,
        630,
        630,
        700,
        680,
        600,
        550,
        0,
    )
    assert t17plus.open_core_gap is None
    assert (
        t17plus.timeout_percent,
        t17plus.baud_setting,
        t17plus.resolved_baud_bps,
    ) == (90, 6_000_000, 6_000_000)
    assert (t17plus.open_core_voltage_raw, t17plus.voltage_steps_raw) == (
        1_850,
        (1_750, 1_770, 1_750, 1_780, 1_730, 1_750, 1_800, 1_830, 0),
    )
    assert (t17plus.sensor_model, t17plus.temp_sensor_indices) == (1, ())
    assert (t17plus.fan_setting, t17plus.fan_scale_max) == (100, 100)
    assert all(
        item.voltage_units_verified is False
        and item.production_profile_authorized is False
        and item.runtime_geometry_authorized is False
        for item in (s17, t17plus)
    )


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_elf_headers_prove_va_to_file_mapping_for_both_binary_cohorts():
    inputs = _held_inputs()

    def load_segments(image):
        assert image[:7] == b"\x7fELF\x01\x01\x01"
        program_offset = struct.unpack_from("<I", image, 28)[0]
        entry_size, count = struct.unpack_from("<HH", image, 42)
        return tuple(
            struct.unpack_from("<IIIIIIII", image, program_offset + index * entry_size)
            for index in range(count)
            if struct.unpack_from("<I", image, program_offset + index * entry_size)[0]
            == 1
        )

    assert load_segments(inputs[8]) == (
        (1, 0, 0x10000, 0x10000, 0x7BD74, 0x7BD74, 5, 0x10000),
        (1, 0x7C000, 0x9C000, 0x9C000, 0x1A75, 0xBA86B8, 6, 0x10000),
    )
    assert load_segments(inputs[9]) == (
        (1, 0, 0x10000, 0x10000, 0x9F710, 0x9F710, 5, 0x10000),
        (1, 0x9FEF8, 0xBFEF8, 0xBFEF8, 0x457C, 0xF9F284, 6, 0x10000),
    )


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_wrong_size_short_circuits_hash_and_mutated_exact_size_rejects(monkeypatch):
    inputs = list(_held_inputs())
    real_sha = hashlib.sha256
    calls = []

    def spy(data=b""):
        calls.append(len(data))
        return real_sha(data)

    monkeypatch.setattr(evidence.hashlib, "sha256", spy)
    inputs[0] += b"x"
    with pytest.raises(evidence.X17EvidenceError, match="aggregate|expected 55286"):
        evidence.inspect_x17_amtc_evidence(*inputs)
    assert calls == []

    inputs = list(_held_inputs())
    inputs[0] = bytes((inputs[0][0] ^ 1,)) + inputs[0][1:]
    with pytest.raises(evidence.X17EvidenceError, match="SHA-256 mismatch"):
        evidence.inspect_x17_amtc_evidence(*inputs)


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_public_global_builtin_and_type_shadow_cannot_forge_receipt(monkeypatch):
    baseline = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    for name in (
        "SPECS",
        "ARTIFACT_SPECS",
        "REJECTED_CARRIER_WINDOWS",
        "FACTORY_WINDOWS",
        "MAX_TOTAL_BYTES",
        "len",
        "sum",
        "any",
        "zip",
        "object",
        "X17EvidenceReceipt",
        "ArtifactReceipt",
        "JigProfileObservation",
    ):
        monkeypatch.setattr(
            evidence, name, lambda *_args, **_kwargs: None, raising=False
        )
    current = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    assert current == baseline
    assert current is not baseline
    assert current.artifacts is not baseline.artifacts
    assert (
        current.rejected_cross_generation_bm1391_carrier
        is not baseline.rejected_cross_generation_bm1391_carrier
    )


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_prior_receipt_poisoning_and_semantic_replace_do_not_persist():
    first = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    object.__setattr__(first, "evidence_verified", False)
    object.__setattr__(
        first.rejected_cross_generation_bm1391_carrier,
        "embedded_asic_count_comparison",
        999,
    )
    object.__setattr__(first.pic_cohorts[0], "device_metadata_observation", "forged")
    object.__setattr__(first.jig_profiles[0], "production_profile_authorized", True)
    second = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    assert second.evidence_verified is True
    assert (
        second.rejected_cross_generation_bm1391_carrier.embedded_asic_count_comparison
        == 48
    )
    assert second.pic_cohorts[0].device_metadata_observation != "forged"
    assert second.jig_profiles[0].production_profile_authorized is False
    forged = replace(second, unresolved=("nothing remains",))
    assert forged.evidence_verified is False
    forged_carrier = replace(
        second.rejected_cross_generation_bm1391_carrier,
        embedded_asic_count_comparison=999,
    )
    assert forged_carrier.exact_rejected_bytes_verified is False
    assert forged_carrier.rejected_as_x17_product_evidence is False


def test_direct_construction_and_replace_never_mint_trust_or_authority():
    artifact = evidence.ArtifactReceipt("x", 1, "00", ("x",))
    assert artifact.member_identity_verified is False
    carrier = evidence.RejectedCrossGenerationCarrierObservation(
        "x", 0, "", "", 0, 0, 0, 0, 0, (), ()
    )
    assert carrier.exact_rejected_bytes_verified is False
    assert carrier.rejected_as_x17_product_evidence is False
    assert carrier.x17_product_model_association_verified is False
    assert (
        replace(
            carrier, embedded_asic_count_comparison=48
        ).exact_rejected_bytes_verified
        is False
    )
    authority = evidence.Authority()
    with pytest.raises(TypeError):
        evidence.Authority(device_io=True)
    assert all(getattr(authority, item.name) is False for item in fields(authority))
    emulation = evidence.RecoveryEmulationReceipt(
        "base", "none", (), (), (), False, "untrusted"
    )
    assert emulation.branch_assumptions_verified is False
    assert emulation.exact_state_machine_observed is False


def test_recovery_emulator_exposes_non_atomic_masked_failures():
    complete = evidence.emulate_x17_recovery_writer("base")
    assert complete.final_state == "sequence-ended-device-state-unverified"
    assert complete.branch_assumptions_verified is True
    assert complete.branch_assumptions == (
        "BOOT.bin present",
        "devicetree.dtb present",
        "uImage present",
        "uramdisk.image.gz present",
        "/dev/mtd4 present",
        "rootfs MD5 matches md5_info",
    )
    assert complete.exact_state_machine_observed is True
    failed = evidence.emulate_x17_recovery_writer("base", "kernel")
    assert failed.continued_after_failure is True
    assert failed.final_state == "mixed-state-possible-no-rollback"
    assert "boot" in failed.commands_without_injected_failure
    assert "kernel" not in failed.commands_without_injected_failure
    assert "rootfs-primary" in failed.commands_without_injected_failure
    md5 = evidence.emulate_x17_recovery_writer("base", "rootfs-md5")
    assert md5.final_state == "boot-components-may-have-been-written-rootfs-refused"
    assert md5.attempted_stages == (
        "boot",
        "dtb",
        "kernel",
        "rootfs-md5-check",
        "sync",
    )
    assert "rootfs-primary" not in md5.commands_without_injected_failure
    assert "rootfs-backup" not in md5.commands_without_injected_failure
    denied = evidence.emulate_x17_recovery_writer("antidowngrade", "downgrade")
    assert denied.final_state == "exited-before-write"
    assert denied.attempted_stages == ()
    assert denied.branch_assumptions == (
        "/etc/ant_version present",
        "package version present and numerically lower than installed version",
    )
    with pytest.raises(evidence.X17EvidenceError, match="for base script"):
        evidence.emulate_x17_recovery_writer("base", "missing-version")
    with pytest.raises(evidence.X17EvidenceError, match="for base script"):
        evidence.emulate_x17_recovery_writer("base", "downgrade")
    assert replace(failed, final_state="success").exact_state_machine_observed is False
    assert replace(failed, final_state="success").branch_assumptions_verified is False
    assert failed.authority.flash_write is False
    assert failed.authority.recovery is False


def test_source_ast_is_bytes_only_and_has_no_action_surface():
    source_path = Path(evidence.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    banned_imports = {"argparse", "os", "pathlib", "socket", "subprocess", "requests"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".")[0] not in banned_imports for alias in node.names
            )
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned_imports
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"open", "exec", "eval", "compile", "__import__"}
    text = source_path.read_text(encoding="utf-8")
    assert "subprocess" not in text


@pytest.mark.skipif(
    not _held_available(), reason="exact operator-held AMTC corpus absent"
)
def test_exact_held_receipt_is_deterministic():
    first = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    second = evidence.inspect_x17_amtc_evidence(*_held_inputs())
    assert first == second
    assert first is not second
