"""Bounded, bytes-only evidence contract for held Bitmain X17 artifacts.

The admitted files are offline reference material.  This module records exact
AMTC PIC-image cohorts, two factory-jig profiles, a rejected cross-generation
BM1391/S11-era carrier, two recovery-writer scripts, and the exact T17e SD
archive central directory. It deliberately does not identify a physical MCU
from Intel-HEX shape alone. The misfiled ``cgminer`` is
rejected as X17 product evidence: the same misfiled bytes are held in S17e,
T17, and T17e-labelled directories, while exact signed S17e/T17e roots contain
different model-specific binaries and establish BM1396 rather than BM1391.

No function opens a path, extracts an archive, contacts hardware, emits a
payload, or grants programming, voltage, install, recovery, or runtime
authority. Archive/member relationships for the script inputs remain
provenance recorded during the offline census. The T17e parent is separately
admitted and its central directory is parsed only to prove that `runme.sh` is
absent; no payload member is extracted or authorized.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable, Tuple


class X17EvidenceError(ValueError):
    """An input did not match the bounded held-artifact contract."""


@dataclass(frozen=True)
class Authority:
    device_io: bool = field(default=False, init=False)
    fpga_io: bool = field(default=False, init=False)
    i2c_io: bool = field(default=False, init=False)
    pic_programming: bool = field(default=False, init=False)
    pic_commands: bool = field(default=False, init=False)
    eeprom_write: bool = field(default=False, init=False)
    voltage_control: bool = field(default=False, init=False)
    hashboard_power: bool = field(default=False, init=False)
    asic_runtime: bool = field(default=False, init=False)
    install: bool = field(default=False, init=False)
    recovery: bool = field(default=False, init=False)
    flash_write: bool = field(default=False, init=False)
    model_identity: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    size_bytes: int
    sha256: str
    held_paths: Tuple[str, ...]
    member_identity_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ArchiveMemberProvenance:
    association: str
    outer_filename: str
    outer_size_bytes: int
    outer_sha256: str
    member_path: str
    member_size_bytes: int
    member_crc32: int
    member_sha256: str
    parent_binding_recomputed: bool = field(default=False, init=False)
    extraction_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class PicCohortObservation:
    member_ids: Tuple[str, ...]
    file_size_bytes: int
    file_sha256: str
    record_count: int
    data_bytes: int
    minimum_program_address: int
    maximum_program_address: int
    canonical_sparse_sha256: str
    instruction_format_observation: str
    device_metadata_observation: str
    physical_mcu_identity_proven: bool = field(default=False, init=False)


@dataclass(frozen=True)
class JigProfileObservation:
    model_label: str
    hashboard: str
    asic_type_label: int
    asic_count: int
    config_artifact_id: str
    scope: str
    frequency_steps_mhz: Tuple[int, ...]
    open_core_gap: int | None
    timeout_percent: int
    baud_setting: int
    baud_semantics: str
    resolved_baud_bps: int
    open_core_voltage_raw: int
    voltage_steps_raw: Tuple[int, ...]
    sensor_label: str
    sensor_model: int
    temp_sensor_indices: Tuple[int, ...]
    fan_setting: int
    fan_scale_max: int
    core_clock_delay: int
    factory_binary_artifact_id: str
    voltage_units_verified: bool = field(default=False, init=False)
    production_profile_authorized: bool = field(default=False, init=False)
    exact_config_and_binary_bytes_verified: bool = field(default=False, init=False)
    runtime_geometry_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class FunctionWindow:
    artifact_id: str
    name: str
    virtual_address: int
    file_offset: int
    size_bytes: int
    sha256: str
    exact_window_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class RejectedCrossGenerationCarrierObservation:
    artifact_id: str
    elf_load_base: int
    pic_device_expression: str
    eeprom_device_expression: str
    fpga_iic_register_byte_offset: int
    fpga_reset_register_byte_offset: int
    fpga_plug_register_byte_offset: int
    logical_chain_scan_limit: int
    embedded_asic_count_comparison: int
    model_directory_labels: Tuple[str, ...]
    functions: Tuple[FunctionWindow, ...]
    exact_rejected_bytes_verified: bool = field(default=False, init=False)
    rejected_as_x17_product_evidence: bool = field(default=False, init=False)
    x17_product_model_association_verified: bool = field(default=False, init=False)
    runtime_route_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class FactoryTransportObservation:
    artifact_id: str
    fpga_iic_register_byte_offset: int
    pic_device_expression: str
    host_frame: str
    host_attempts: int
    host_write_to_read_delay_us: int
    host_read_to_check_delay_us: int
    backend_poll_iterations: int
    backend_poll_delay_us: int
    updater_source_label: str
    updater_reachable_from_held_call_graph: bool
    functions: Tuple[FunctionWindow, ...]
    exact_t17plus_jig_binary_bytes_verified: bool = field(default=False, init=False)
    physical_mcu_identity_proven_by_updater_label: bool = field(
        default=False, init=False
    )
    factory_command_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class RecoveryWriterObservation:
    base_script_artifact_id: str
    antidowngrade_script_artifact_id: str
    ordered_targets: Tuple[str, ...]
    rootfs_md5_only: bool
    boot_components_authenticated: bool
    command_exit_status_checked: bool
    rollback_implemented: bool
    emulator_scope: str
    t17e_parent_artifact_id: str
    t17e_central_directory_entries: Tuple[str, ...]
    exact_scripts_verified: bool = field(default=False, init=False)
    t17e_parent_exact_bytes_verified: bool = field(default=False, init=False)
    t17e_central_directory_verified: bool = field(default=False, init=False)
    t17e_runme_member_absence_verified: bool = field(default=False, init=False)
    atomic_update_proven: bool = field(default=False, init=False)
    install_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class X17EvidenceReceipt:
    artifacts: Tuple[ArtifactReceipt, ...]
    archive_provenance: Tuple[ArchiveMemberProvenance, ...]
    pic_cohorts: Tuple[PicCohortObservation, ...]
    jig_profiles: Tuple[JigProfileObservation, ...]
    rejected_cross_generation_bm1391_carrier: RejectedCrossGenerationCarrierObservation
    t17plus_factory_transport: FactoryTransportObservation
    recovery_writer: RecoveryWriterObservation
    unresolved: Tuple[str, ...]
    authority: Authority = field(default_factory=Authority, init=False)
    evidence_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class RecoveryEmulationReceipt:
    script_kind: str
    injected_failure: str
    branch_assumptions: Tuple[str, ...]
    attempted_stages: Tuple[str, ...]
    commands_without_injected_failure: Tuple[str, ...]
    continued_after_failure: bool
    final_state: str
    authority: Authority = field(default_factory=Authority, init=False)
    branch_assumptions_verified: bool = field(default=False, init=False)
    exact_state_machine_observed: bool = field(default=False, init=False)


def _make_contract() -> Tuple[
    Callable[..., X17EvidenceReceipt], Callable[..., RecoveryEmulationReceipt]
]:
    sha256 = hashlib.sha256
    unpack_from = struct.unpack_from
    b_len = len
    b_bytes = bytes
    b_isinstance = isinstance
    b_tuple = tuple
    b_any = any
    b_sum = sum
    b_zip = zip
    b_min = min
    b_max = max
    b_sorted = sorted
    b_enumerate = enumerate
    b_range = range
    frozen_setattr = object.__setattr__
    parse_errors = (ValueError, UnicodeDecodeError)
    error_type = X17EvidenceError
    artifact_type = ArtifactReceipt
    provenance_type = ArchiveMemberProvenance
    pic_type = PicCohortObservation
    jig_type = JigProfileObservation
    window_type = FunctionWindow
    rejected_carrier_type = RejectedCrossGenerationCarrierObservation
    transport_type = FactoryTransportObservation
    recovery_type = RecoveryWriterObservation
    receipt_type = X17EvidenceReceipt
    emulation_type = RecoveryEmulationReceipt

    # These primitives are captured by the closure.  Reassigning similarly
    # named public module globals cannot alter admission or minted semantics.
    specs = (
        (
            "s17_pic",
            55_286,
            "bde15c70845d6e82d1e54926ea04076f87b91282b82ca5e06172cc3c1a1af713",
        ),
        (
            "s17e_pic",
            55_286,
            "bde15c70845d6e82d1e54926ea04076f87b91282b82ca5e06172cc3c1a1af713",
        ),
        (
            "s17plus_pic",
            20_752,
            "ea101608283f6b9175fa5e6fdf205859957a92fa4c4a623979ab2cfee85f885d",
        ),
        (
            "t17plus_pic",
            20_752,
            "ea101608283f6b9175fa5e6fdf205859957a92fa4c4a623979ab2cfee85f885d",
        ),
        (
            "t17e_pic",
            20_752,
            "ea101608283f6b9175fa5e6fdf205859957a92fa4c4a623979ab2cfee85f885d",
        ),
        (
            "s17_config",
            2_019,
            "1cf8e105ab9fae0f047538b0894c86e2335436ad90ab8043b1a87821fc192ae4",
        ),
        (
            "t17plus_config",
            1_990,
            "18c716f074badb97801679474f189adbfb991c3fa2bd24d69a2ca059075cdb20",
        ),
        (
            "s17_factory_jig",
            583_696,
            "89695fc1287897c63b7c3404944e19e3b21396dbed7768e2d75d4a432b7c0b41",
        ),
        (
            "t17plus_factory_jig",
            516_132,
            "8c01ce2c7ab18e489e72340daa4feb971342d72dc79aaa358680c71434befb28",
        ),
        (
            "rejected_cross_generation_bm1391_carrier",
            1_481_552,
            "9283110862c74a7546923915be3a3d639768b56bf769577a47908df704887b8b",
        ),
        (
            "base_runme",
            1_061,
            "b8aeed73da5e2bec12704cc9a5eb7653ca661a42a102752ebfdc71db14e6fda7",
        ),
        (
            "antidowngrade_runme",
            1_571,
            "755088b87278c328798b9180266ae1128dece8ca863cd621c1dc5fedaa010c59",
        ),
        (
            "t17e_recovery_parent",
            48_748_519,
            "5eca68d32fbe724b43a2e66ba9d7d8102efa3f41dee67442c2bbc2d95eb8f238",
        ),
    )
    held_paths = (
        ("S17 Testing Files/S17PIC.hex",),
        ("S17eTesting Files/S17ePIC.hex",),
        ("S17+ Testing Files/S17+PIC.hex",),
        ("T17+Testing Files/T17+PIC.hex",),
        ("T17e Testing Files/T17ePIC.hex",),
        ("S17 Testing Files/S17治具文件.zip::0/Config.ini",),
        ("T17+Testing Files/T17+TestJig.zip::T17+/Config.ini",),
        ("S17 Testing Files/S17治具文件.zip::0/single-board-test",),
        ("T17+Testing Files/T17+TestJig.zip::T17+/single-board-test",),
        (
            "bitmain_antminer_binaries-main/S17e/cgminer",
            "bitmain_antminer_binaries-main/T17/cgminer",
            "bitmain_antminer_binaries-main/T17e/cgminer",
        ),
        (
            "S17+ Testing Files/S17+ SD卡刷文件OK(2).zip::SD_S17+/bin/runme.sh",
            "T17+Testing Files/SD_T17+.zip::FT-B╒√╗·▓Γ╩╘╦ó╗·SD┐¿─╕╞¼/bin/runme.sh",
        ),
        ("S17eTesting Files/SD-S17e.zip::FT-B╒√╗·▓Γ╩╘╦ó╗·SD┐¿─╕╞¼/bin/runme.sh",),
        ("T17e Testing Files/SD_T17e.zip",),
    )
    max_total_bytes = 52_000_000
    rejected_carrier_windows = (
        (
            "FPGA IIC read",
            0x43964,
            0x33964,
            64,
            "5183c42b8cf58932982f4ded07d6c138526774bab2e39f8d9af45aad7fddfd26",
        ),
        (
            "Zynq IIC pack",
            0x43AD0,
            0x33AD0,
            64,
            "610c51a5046e9b5c56882dccfe8b8ffd5f35338e3ec6279c72fcbb81b7680e27",
        ),
        (
            "PIC framed command",
            0x75728,
            0x65728,
            64,
            "08c4c9c322c418f7ead75c142d254c1ed7b5df9da4774faccc9520ad549c1823",
        ),
        (
            "hashboard power",
            0x75B80,
            0x65B80,
            64,
            "e3cc0723147fa5331ca0ec2dbf925a22da848d376445fe9ed9a4624060e575d9",
        ),
        (
            "PIC reset",
            0x75EE4,
            0x65EE4,
            64,
            "cf7513a056a20f728c00b99ff6251aa39233af977ef4c21f25b861c6022ad027",
        ),
        (
            "PIC jump to app",
            0x7632C,
            0x6632C,
            64,
            "2e1a72baaa18b4300502cdbf8baf50d235563d4c605d473199eaf2a798bd7590",
        ),
        (
            "EEPROM read",
            0x72D58,
            0x62D58,
            64,
            "80f013a9b9d2eaf9e033c22df0c5bbeaf6789f67656bdab34767f5206d1a5195",
        ),
        (
            "48-ASIC comparison",
            0x301B8,
            0x201B8,
            64,
            "dac9444ae353a4fa15aeb0b0bc32bae751ae39ed9d01a51b2f721dfaf84df158",
        ),
    )
    factory_windows = (
        (
            "PIC host framing/retry",
            0x72798,
            0x62798,
            64,
            "08302a7b39f7712f2e9175a7d188c1e238366e291074b5845819812d9a6d62f5",
        ),
        (
            "dormant PIC updater",
            0x72A98,
            0x62A98,
            64,
            "76afd3a9de3f6af663d968e515066509595564aeeda457bdb9ef2fa5b673f254",
        ),
        (
            "FPGA IIC backend poll",
            0x6DBE0,
            0x5DBE0,
            64,
            "0fd381fafed69b3ee92f185f924ef6efb935ee62cd3774963b4af6b15ea4272d",
        ),
        (
            "chain PIC init call site",
            0x33B2C,
            0x23B2C,
            64,
            "f700b1cc855e2c6482dcecde6105012b7dbc32539a7a19fcd0c13bcefcca7998",
        ),
    )

    provenance = (
        (
            "S17 factory",
            "S17治具文件.zip",
            30_206_409,
            "88c64db57c77e5fced012c946e144ba45f7bded536ef8e13413cbf12c4d61b8e",
            "0/Config.ini",
            2_019,
            0x966483F8,
            specs[5][2],
        ),
        (
            "S17 factory",
            "S17治具文件.zip",
            30_206_409,
            "88c64db57c77e5fced012c946e144ba45f7bded536ef8e13413cbf12c4d61b8e",
            "0/single-board-test",
            583_696,
            0xCA1E7DC3,
            specs[7][2],
        ),
        (
            "T17+ factory",
            "T17+TestJig.zip",
            29_089_700,
            "201ae4a91ae72bce91d69d8006d0564a2dc377f93c14b48b844bf9d77f3c477b",
            "T17+/Config.ini",
            1_990,
            0xAB3FF689,
            specs[6][2],
        ),
        (
            "T17+ factory",
            "T17+TestJig.zip",
            29_089_700,
            "201ae4a91ae72bce91d69d8006d0564a2dc377f93c14b48b844bf9d77f3c477b",
            "T17+/single-board-test",
            516_132,
            0x2B8C8A31,
            specs[8][2],
        ),
        (
            "S17+ recovery",
            "S17+ SD-card ZIP",
            32_189_053,
            "af5f4e80050debdfba5eaf78c0b93a2ddac39f4ba3dd257102b188614cbbbdfd",
            "SD_S17+/bin/runme.sh",
            1_061,
            0x81B060FA,
            specs[10][2],
        ),
        (
            "T17+ recovery",
            "SD_T17+.zip",
            46_958_987,
            "1d933dff55d751a6e5cbdb4d572079456e9a6c3aca9fafc8f6cb531c822ee6f7",
            "FT-B╒√╗·▓Γ╩╘╦ó╗·SD┐¿─╕╞¼/bin/runme.sh",
            1_061,
            0x81B060FA,
            specs[10][2],
        ),
        (
            "S17e recovery",
            "SD-S17e.zip",
            48_844_056,
            "74b8b553e39b487a382cb7f1a6def12ba06630bfb6923640650db953fe9f2bbc",
            "FT-B╒√╗·▓Γ╩╘╦ó╗·SD┐¿─╕╞¼/bin/runme.sh",
            1_571,
            0xC90C1367,
            specs[11][2],
        ),
    )

    def require_exact(name: str, data: bytes, size: int, digest: str) -> bytes:
        if not b_isinstance(data, b_bytes):
            raise error_type(f"{name}: immutable bytes required")
        if b_len(data) != size:
            raise error_type(f"{name}: expected {size} bytes")
        if sha256(data).hexdigest() != digest:
            raise error_type(f"{name}: SHA-256 mismatch")
        return data

    def mint_artifact(
        name: str, size: int, digest: str, paths: Tuple[str, ...]
    ) -> ArtifactReceipt:
        result = artifact_type(name, size, digest, paths)
        frozen_setattr(result, "member_identity_verified", True)
        return result

    def mint_window(
        artifact: str, item: Tuple[object, ...], image: bytes
    ) -> FunctionWindow:
        name, va, offset, size, digest = item
        if offset != va - 0x10000:
            raise error_type(f"{artifact}: ELF VA/file mapping drift")
        if offset < 0 or size <= 0 or offset + size > b_len(image):
            raise error_type(f"{artifact}: function window out of bounds")
        if sha256(image[offset : offset + size]).hexdigest() != digest:
            raise error_type(f"{artifact}: {name} window mismatch")
        result = window_type(artifact, name, va, offset, size, digest)
        frozen_setattr(result, "exact_window_verified", True)
        return result

    def parse_ihex(name: str, image: bytes) -> Tuple[int, int, int, int, str]:
        if b_len(image) > 65_536:
            raise error_type(f"{name}: Intel HEX exceeds bound")
        lines = image.splitlines()
        if not lines or b_len(lines) > 2_000:
            raise error_type(f"{name}: invalid record count")
        upper = 0
        memory = {}
        eof = 0
        for line in lines:
            if b_len(line) < 11 or line[:1] != b":" or b_len(line) > 600:
                raise error_type(f"{name}: malformed Intel HEX record")
            try:
                raw = b_bytes.fromhex(line[1:].decode("ascii"))
            except parse_errors as exc:
                raise error_type(f"{name}: malformed Intel HEX text") from exc
            if b_len(raw) < 5 or raw[0] + 5 != b_len(raw) or b_sum(raw) & 0xFF:
                raise error_type(f"{name}: Intel HEX checksum/length mismatch")
            count = raw[0]
            address = (raw[1] << 8) | raw[2]
            kind = raw[3]
            payload = raw[4 : 4 + count]
            if kind == 0:
                if eof:
                    raise error_type(f"{name}: data after EOF")
                absolute = upper + address
                for index, value in b_enumerate(payload):
                    target = absolute + index
                    if target in memory and memory[target] != value:
                        raise error_type(f"{name}: conflicting Intel HEX overlap")
                    memory[target] = value
            elif kind == 1:
                if count or address or eof:
                    raise error_type(f"{name}: invalid EOF record")
                eof = 1
            elif kind == 4:
                if count != 2 or address or eof:
                    raise error_type(f"{name}: invalid extended address record")
                upper = ((payload[0] << 8) | payload[1]) << 16
            else:
                raise error_type(f"{name}: unsupported Intel HEX record type {kind}")
        if eof != 1 or not memory:
            raise error_type(f"{name}: incomplete Intel HEX")
        sparse = b"".join(
            address.to_bytes(4, "big") + b_bytes((memory[address],))
            for address in b_sorted(memory)
        )
        return (
            b_len(lines),
            b_len(memory),
            b_min(memory),
            b_max(memory),
            sha256(sparse).hexdigest(),
        )

    def parse_t17e_zip_central_directory(image: bytes) -> Tuple[str, ...]:
        """Validate the exact central directory without extracting a member."""

        eocd = image.rfind(b"PK\x05\x06", b_max(0, b_len(image) - 65_557))
        if eocd < 0 or eocd + 22 > b_len(image):
            raise error_type("T17e recovery ZIP EOCD missing or truncated")
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = unpack_from("<4s4H2IH", image, eocd)
        if (
            signature != b"PK\x05\x06"
            or disk_number != 0
            or central_disk != 0
            or disk_entries != total_entries
            or total_entries != 11
            or eocd + 22 + comment_size != b_len(image)
            or central_offset + central_size != eocd
        ):
            raise error_type("T17e recovery ZIP EOCD geometry mismatch")

        cursor = central_offset
        central_end = central_offset + central_size
        entries = []
        sizes = []
        for _ in b_range(total_entries):
            if cursor + 46 > central_end:
                raise error_type("T17e recovery ZIP central entry truncated")
            header = unpack_from("<4s6H3I5H2I", image, cursor)
            if header[0] != b"PK\x01\x02" or header[3] & 1:
                raise error_type("T17e recovery ZIP central entry invalid")
            name_size, extra_size, entry_comment_size = header[10:13]
            entry_end = cursor + 46 + name_size + extra_size + entry_comment_size
            if entry_end > central_end:
                raise error_type("T17e recovery ZIP central entry exceeds directory")
            encoding = "utf-8" if header[3] & 0x0800 else "cp437"
            try:
                name = image[cursor + 46 : cursor + 46 + name_size].decode(encoding)
            except parse_errors as exc:
                raise error_type("T17e recovery ZIP member name is invalid") from exc
            entries.append(name)
            sizes.append(header[9])
            cursor = entry_end
        if cursor != central_end:
            raise error_type("T17e recovery ZIP central directory has trailing bytes")

        expected = (
            ("SD_T17e/", 0),
            ("SD_T17e/BOOT.bin", 2_751_032),
            ("SD_T17e/devicetree.dtb", 7_650),
            ("SD_T17e/.DS_Store", 8_196),
            ("SD_T17e/bin/", 0),
            ("SD_T17e/bin/BOOT.bin", 2_735_664),
            ("SD_T17e/bin/devicetree.dtb", 7_650),
            ("SD_T17e/bin/uImage", 4_006_832),
            ("SD_T17e/bin/uramdisk.image.gz", 12_991_279),
            ("SD_T17e/uImage", 4_006_832),
            ("SD_T17e/uramdisk.image.gz", 27_125_535),
        )
        if b_tuple(b_zip(entries, sizes)) != expected:
            raise error_type("T17e recovery ZIP member inventory mismatch")
        if b_any(name.endswith("/bin/runme.sh") for name in entries):
            raise error_type("T17e recovery ZIP unexpectedly contains runme.sh")
        return b_tuple(entries)

    def inspect(
        s17_pic: bytes,
        s17e_pic: bytes,
        s17plus_pic: bytes,
        t17plus_pic: bytes,
        t17e_pic: bytes,
        s17_config: bytes,
        t17plus_config: bytes,
        s17_factory_jig: bytes,
        t17plus_factory_jig: bytes,
        rejected_cross_generation_bm1391_carrier: bytes,
        base_runme: bytes,
        antidowngrade_runme: bytes,
        t17e_recovery_parent: bytes,
    ) -> X17EvidenceReceipt:
        values = (
            s17_pic,
            s17e_pic,
            s17plus_pic,
            t17plus_pic,
            t17e_pic,
            s17_config,
            t17plus_config,
            s17_factory_jig,
            t17plus_factory_jig,
            rejected_cross_generation_bm1391_carrier,
            base_runme,
            antidowngrade_runme,
            t17e_recovery_parent,
        )
        if b_any(not b_isinstance(value, b_bytes) for value in values):
            raise error_type("all artifacts must be immutable bytes")
        if b_sum(b_len(value) for value in values) > max_total_bytes:
            raise error_type("aggregate artifact size exceeds 3,000,000-byte bound")
        admitted = b_tuple(
            require_exact(name, value, size, digest)
            for (name, size, digest), value in b_zip(specs, values)
        )
        t17e_central_entries = parse_t17e_zip_central_directory(admitted[12])
        artifacts = b_tuple(
            mint_artifact(*spec, paths) for spec, paths in b_zip(specs, held_paths)
        )

        first_hex = parse_ihex("s17_pic", admitted[0])
        second_hex = parse_ihex("s17plus_pic", admitted[2])
        if parse_ihex("s17e_pic", admitted[1]) != first_hex:
            raise error_type("S17/S17e parsed PIC relationship drift")
        for label, image in b_zip(("t17plus_pic", "t17e_pic"), admitted[3:5]):
            if parse_ihex(label, image) != second_hex:
                raise error_type("S17+/T17+/T17e parsed PIC relationship drift")
        expected_first = (
            1_462,
            17_732,
            0,
            0x5763,
            "292a3c824f7167824d4f63381913d7215df0a859de383f35fadaa2fc3b5b173f",
        )
        expected_second = (
            464,
            7_358,
            0,
            0x10011,
            "7a9d248795dcc285da897006cb382d6244364aff428df6abf34970423233db8d",
        )
        if first_hex != expected_first or second_hex != expected_second:
            raise error_type("Intel HEX semantic receipt drift")

        anchors = (
            (
                admitted[5],
                (
                    b"Name=BHB07601",
                    b"AsicType=1397",
                    b"AsicNum=48",
                    b"OpenCoreGap=20000",
                    b"CoreClockDelay=0x34",
                    b"timeout_percent=10",
                    b"baudrate=3",
                    b"Freq1=450",
                    b"pre_open_core_voltage=2000",
                    b"Voltage1=1900",
                    b"sensor_model=1",
                    b"TempSensor1=9",
                    b"TempSensor2=12",
                    b"TempSensor3=40",
                    b"TempSensor4=37",
                    b"fan_speed=10",
                ),
            ),
            (
                admitted[6],
                (
                    b"Name=BHB07702",
                    b"Asic_Type=1397",
                    b"Asic_Num=44",
                    b"CoreClockDelay=0x34",
                    b"Timeout_Percent=90",
                    b"Baudrate=6000000",
                    b"Freq1=700",
                    b"Freq8=550",
                    b"Open_Core_Voltage=1850",
                    b"Voltage1=1750",
                    b"Voltage8=1830",
                    b"Sensor_Model=1",
                    b"Fan_Speed=100",
                ),
            ),
            (
                admitted[10],
                (
                    b"flash_erase /dev/mtd0 0x0 0x40",
                    b"nandwrite -p -s 0x1A00000",
                    b"md5sum uramdisk.image.gz",
                    b"flash_erase /dev/mtd4 0x0 0x100",
                ),
            ),
            (
                admitted[11],
                (
                    b"exit 6",
                    b"Cannot Downgrade",
                    b"exit 7",
                    b"flash_erase /dev/mtd0 0x0 0x40",
                ),
            ),
        )
        for image, required in anchors:
            if b_any(anchor not in image for anchor in required):
                raise error_type("exact text artifact semantic anchor drift")

        rejected_carrier_functions = b_tuple(
            mint_window("rejected_cross_generation_bm1391_carrier", item, admitted[9])
            for item in rejected_carrier_windows
        )
        factory_functions = b_tuple(
            mint_window("t17plus_factory_jig", item, admitted[8])
            for item in factory_windows
        )
        provenance_receipts = b_tuple(provenance_type(*item) for item in provenance)
        pic_receipts = (
            pic_type(
                ("s17_pic", "s17e_pic"),
                specs[0][1],
                specs[0][2],
                first_hex[0],
                first_hex[1],
                first_hex[2],
                first_hex[3],
                first_hex[4],
                "24-bit instruction bytes packed in four-byte program-address groups",
                "AMTC names S17/S17e; host binary carries dsPIC-labelled command families",
            ),
            pic_type(
                ("s17plus_pic", "t17plus_pic", "t17e_pic"),
                specs[2][1],
                specs[2][2],
                second_hex[0],
                second_hex[1],
                second_hex[2],
                second_hex[3],
                second_hex[4],
                "enhanced-midrange 14-bit instruction words; config word at word address 0x8007",
                "co-bundled filenames and host source label say PIC16F1704",
            ),
        )
        jig_receipts = (
            jig_type(
                model_label="S17",
                hashboard="BHB07601",
                asic_type_label=1397,
                asic_count=48,
                config_artifact_id="s17_config",
                scope="offline factory-jig profile only",
                frequency_steps_mhz=(450, 0, 0, 0, 0, 0, 0, 0, 0),
                open_core_gap=20_000,
                timeout_percent=10,
                baud_setting=3,
                baud_semantics="Bitmain FPGA/ASIC enum; 3 means 6 Mbit/s",
                resolved_baud_bps=6_000_000,
                open_core_voltage_raw=2_000,
                voltage_steps_raw=(1_900, 0, 0, 0, 0, 0, 0, 0, 0),
                sensor_label="TMP451 (sensor_model=1 comment)",
                sensor_model=1,
                temp_sensor_indices=(9, 12, 40, 37),
                fan_setting=10,
                fan_scale_max=10,
                core_clock_delay=0x34,
                factory_binary_artifact_id="s17_factory_jig",
            ),
            jig_type(
                model_label="T17+",
                hashboard="BHB07702",
                asic_type_label=1397,
                asic_count=44,
                config_artifact_id="t17plus_config",
                scope="offline factory-jig profile only",
                frequency_steps_mhz=(700, 680, 630, 630, 700, 680, 600, 550, 0),
                open_core_gap=None,
                timeout_percent=90,
                baud_setting=6_000_000,
                baud_semantics="literal bit/s",
                resolved_baud_bps=6_000_000,
                open_core_voltage_raw=1_850,
                voltage_steps_raw=(1_750, 1_770, 1_750, 1_780, 1_730, 1_750, 1_800, 1_830, 0),
                sensor_label="NCT218 (Sensor_Model=1 comment)",
                sensor_model=1,
                temp_sensor_indices=(),
                fan_setting=100,
                fan_scale_max=100,
                core_clock_delay=0x34,
                factory_binary_artifact_id="t17plus_factory_jig",
            ),
        )
        for item in jig_receipts:
            frozen_setattr(item, "exact_config_and_binary_bytes_verified", True)

        rejected_carrier = rejected_carrier_type(
            "rejected_cross_generation_bm1391_carrier",
            0x10000,
            "0x20 | (chain & 7)",
            "0x50 | (chain & 7)",
            0x30,
            0x34,
            0x08,
            16,
            48,
            ("S17e directory", "T17 directory", "T17e directory"),
            rejected_carrier_functions,
        )
        frozen_setattr(rejected_carrier, "exact_rejected_bytes_verified", True)
        frozen_setattr(rejected_carrier, "rejected_as_x17_product_evidence", True)
        factory = transport_type(
            "t17plus_factory_jig",
            0x30,
            "0x20 | (chain & 7)",
            "55 aa, length=data+4, command, payload, 16-bit additive checksum big-endian",
            4,
            500_000,
            500_000,
            102,
            5_000,
            "/etc/config/dsPIC33EP16GS202_app.txt",
            False,
            factory_functions,
        )
        frozen_setattr(factory, "exact_t17plus_jig_binary_bytes_verified", True)
        recovery = recovery_type(
            "base_runme",
            "antidowngrade_runme",
            (
                "mtd0:BOOT@0",
                "mtd0:DTB@0x1a00000",
                "mtd0:uImage@0x2000000",
                "mtd1:rootfs@0",
                "optional mtd4:rootfs-backup@0",
            ),
            True,
            False,
            False,
            False,
            "maximal writer branch: all four payload files and /dev/mtd4 present",
            "t17e_recovery_parent",
            t17e_central_entries,
        )
        frozen_setattr(recovery, "exact_scripts_verified", True)
        frozen_setattr(recovery, "t17e_parent_exact_bytes_verified", True)
        frozen_setattr(recovery, "t17e_central_directory_verified", True)
        frozen_setattr(recovery, "t17e_runme_member_absence_verified", True)
        result = receipt_type(
            artifacts,
            provenance_receipts,
            pic_receipts,
            jig_receipts,
            rejected_carrier,
            factory,
            recovery,
            (
                "S17 Pro, base T17, and model-specific production carrier artifacts remain unbound",
                "physical MCU part/revision cannot be assigned from Intel HEX shape alone",
                "S17e/T17e exact production chain UART/reset/plug/PIC/PSU maps remain unresolved",
                "T17e SD archive contains no runme.sh; boot-media execution, target binding, rollback, and recovery acceptance remain unknown",
                "live electrical limits, polarity, and rollback behavior remain unvalidated",
            ),
        )
        frozen_setattr(result, "evidence_verified", True)
        return result

    stages = (
        "boot",
        "dtb",
        "kernel",
        "rootfs-md5-check",
        "rootfs-primary",
        "rootfs-backup",
        "sync",
    )
    write_failures = ("boot", "dtb", "kernel", "rootfs-primary", "rootfs-backup")

    def emulate(
        script_kind: str, injected_failure: str = "none"
    ) -> RecoveryEmulationReceipt:
        """Observe exact control flow for one explicitly maximal writer branch.

        The normal/failure write sequence assumes all four optional payload files
        and ``/dev/mtd4`` exist.  The anti-downgrade pre-write exits are separate
        exact profiles.  Missing-component branches are deliberately not
        generalized into this non-authorizing emulator.
        """

        if script_kind not in ("base", "antidowngrade"):
            raise error_type("script_kind must be base or antidowngrade")
        common_failures = write_failures + ("rootfs-md5",)
        allowed = ("none",) + common_failures
        if script_kind == "antidowngrade":
            allowed += ("missing-version", "downgrade")
        if injected_failure not in allowed:
            raise error_type(f"unsupported failure injection for {script_kind} script")

        assumptions = (
            "BOOT.bin present",
            "devicetree.dtb present",
            "uImage present",
            "uramdisk.image.gz present",
            "/dev/mtd4 present",
        )
        if injected_failure == "rootfs-md5":
            assumptions += ("rootfs MD5 mismatches md5_info",)
        else:
            assumptions += ("rootfs MD5 matches md5_info",)
        attempted = []
        successful = []
        if script_kind == "antidowngrade" and injected_failure in (
            "missing-version",
            "downgrade",
        ):
            if injected_failure == "missing-version":
                assumptions = (
                    "/etc/ant_version present",
                    "package version file absent",
                )
            else:
                assumptions = (
                    "/etc/ant_version present",
                    "package version present and numerically lower than installed version",
                )
            result = emulation_type(
                script_kind,
                injected_failure,
                assumptions,
                (),
                (),
                False,
                "exited-before-write",
            )
            frozen_setattr(result, "branch_assumptions_verified", True)
            frozen_setattr(result, "exact_state_machine_observed", True)
            return result
        if script_kind == "antidowngrade":
            assumptions += (
                "/etc/ant_version present",
                "package version present and numerically not lower than installed version",
            )
        for stage in stages:
            if injected_failure == "rootfs-md5" and stage in (
                "rootfs-primary",
                "rootfs-backup",
            ):
                continue
            attempted.append(stage)
            if stage in ("sync", "rootfs-md5-check"):
                continue
            if injected_failure != stage:
                successful.append(stage)
        failed_command = (
            injected_failure in write_failures or injected_failure == "rootfs-md5"
        )
        state = (
            "sequence-ended-device-state-unverified"
            if injected_failure == "none"
            else "mixed-state-possible-no-rollback"
        )
        if injected_failure == "rootfs-md5":
            state = "boot-components-may-have-been-written-rootfs-refused"
        result = emulation_type(
            script_kind,
            injected_failure,
            assumptions,
            b_tuple(attempted),
            b_tuple(successful),
            failed_command,
            state,
        )
        frozen_setattr(result, "branch_assumptions_verified", True)
        frozen_setattr(result, "exact_state_machine_observed", True)
        return result

    return inspect, emulate


inspect_x17_amtc_evidence, emulate_x17_recovery_writer = _make_contract()
del _make_contract


__all__ = (
    "ArtifactReceipt",
    "Authority",
    "RejectedCrossGenerationCarrierObservation",
    "FactoryTransportObservation",
    "PicCohortObservation",
    "RecoveryEmulationReceipt",
    "RecoveryWriterObservation",
    "X17EvidenceError",
    "X17EvidenceReceipt",
    "emulate_x17_recovery_writer",
    "inspect_x17_amtc_evidence",
)
