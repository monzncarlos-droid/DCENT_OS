"""Pure, denied-action S15/T15 APW8-adjacent software evidence.

The exact December-2019 S15 and T15 stock miners drive the Zynq FPGA's
general-I2C command register with the same software tuple: device 0x10,
bus/channel 1, write direction, one-byte register prefix 0x02, and one data
byte.  This module admits only the exact held envelopes, exact extracted
``cgminer`` images, the exact held S15 maintenance guide, and the distinct
exact held APW8 maintenance guide before returning that observation.

This is deliberately not an APW8 driver.  The inspector does not parse the
signed envelopes, authenticate Bitmain, open a path or device, infer a wire
checksum, bind GPIO907 to the guide's PWR_EN net, or establish a safe voltage.
All operational authority remains false.
"""

from __future__ import annotations

import hashlib
import math
import struct
import weakref
from dataclasses import dataclass, field
from typing import Tuple


_ARTIFACT_SPECS = (
    (
        "bitmain-s15-20191213-signed-envelope",
        24_962_829,
        "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71",
    ),
    (
        "bitmain-s15-20191213-cgminer",
        691_180,
        "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8",
    ),
    (
        "bitmain-t15-20191213-signed-envelope",
        23_696_441,
        "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4",
    ),
    (
        "bitmain-t15-20191213-cgminer",
        691_180,
        "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01",
    ),
    (
        "bitmain-s15-maintenance-guide-20190702",
        3_800_577,
        "4496807c14291da95bdc4ba399097f8a3d5f1c15d0cab882dcd57c10e5e2ab27",
    ),
    (
        "bitmain-apw8-maintenance-guide",
        1_853_200,
        "a8694c6eff734784c91c71a6e6d7ceff0cf25b8e98494d8d535cc8ecfdd43214",
    ),
)

_LOAD_SEGMENTS = (
    (0, 0x8000, 0xA3F64, 0xA3F64, 5, 0x8000),
    (0xA4000, 0xB4000, 0x4648, 0x1A73B00, 6, 0x8000),
)
_T15_LOAD_SEGMENTS = (
    (0, 0x8000, 0xA3E84, 0xA3E84, 5, 0x8000),
    (0xA4000, 0xB4000, 0x4648, 0x19D6770, 6, 0x8000),
)

# name, analysis VA, file offset, exact window length, SHA-256
_S15_FUNCTIONS = (
    (
        "gpio907 software power_on",
        0x79F50,
        0x71F50,
        0x60,
        "47d5ba70d8a5f600350ebd9472434a54bd4911642f06b1831b3f22a9343da696",
    ),
    (
        "gpio907 software power_off",
        0x7A06C,
        0x7206C,
        0x60,
        "976a0626aa0d7d42eb9f78cb6ca8f39b0c4b6ca27ec8eda101254781dc9adcab",
    ),
    (
        "FPGA I2C power-byte wrapper",
        0x7A3B0,
        0x723B0,
        0x60,
        "92dfb3b5924d7152cafe324df3d0f4f71a085c9f8882ccf952a1b7068a767413",
    ),
    (
        "set_iic_power_by_voltage",
        0x7A57C,
        0x7257C,
        0x158,
        "0a4fed13ff070e85cf52320a4c7d79ef5d032635a74b4f6e71d6b4aa32e80a35",
    ),
    (
        "power conversion constants",
        0x7A6A0,
        0x726A0,
        0x18,
        "a0769edabc069045cbf692ce0837a338945abaa17ba5189baf886fbd063eed15",
    ),
    (
        "PIC heartbeat",
        0x7E304,
        0x76304,
        0x80,
        "3207a7d461340074e03efd4634ff4e0b024eaf43f6b36336a4d3a08d0bb48fe1",
    ),
    (
        "FPGA general-I2C command helper",
        0x86AEC,
        0x7EAEC,
        0x64,
        "d73a0d1ec0a679930e1d0e1c62fe0598d9e2e9efa43158d208cbd186063ea745",
    ),
    (
        "GPIO907 strings",
        0xA8910,
        0xA0910,
        0xD8,
        "3b7752b05ec8284cb6063821c67c0913e031b3b6d790ce13ab84c7c37e32b1f0",
    ),
)

_T15_FUNCTIONS = (
    (
        "gpio907 software power_on",
        0x79F18,
        0x71F18,
        0x60,
        "0ba5907dc32ebcb26809368c3cdca2ff77c695e46e88960c92ebe4d3b5389064",
    ),
    (
        "gpio907 software power_off",
        0x7A034,
        0x72034,
        0x60,
        "731707267315867742dcffb5bca414c150819b55a79ca6affec5f564a12f14f4",
    ),
    (
        "FPGA I2C power-byte wrapper",
        0x7A378,
        0x72378,
        0x60,
        "5f24b0031997a7135ad6406849941fad6c5e9be8ae8f36300c8f7ae18ca96232",
    ),
    (
        "set_iic_power_by_voltage",
        0x7A544,
        0x72544,
        0x158,
        "08112e3d69521000b585fcd046e9855418d75ec363bd785d0f5a9bf648a3e677",
    ),
    (
        "power conversion constants",
        0x7A668,
        0x72668,
        0x18,
        "a0769edabc069045cbf692ce0837a338945abaa17ba5189baf886fbd063eed15",
    ),
    (
        "PIC heartbeat",
        0x7E2CC,
        0x762CC,
        0x80,
        "c04fbffbd985d29a978e9330ba9a71cb9be822d47bd93515f02dbd220b0ce8ba",
    ),
    (
        "FPGA general-I2C command helper",
        0x86A0C,
        0x7EA0C,
        0x64,
        "fee34622fdfcbc2b7e6d9c1b266f1833257a528a60691b583bbef6a75680851e",
    ),
    (
        "GPIO907 strings",
        0xA8830,
        0xA0830,
        0xD8,
        "3b7752b05ec8284cb6063821c67c0913e031b3b6d790ce13ab84c7c37e32b1f0",
    ),
)


def _build_api(
    _artifact_specs=_ARTIFACT_SPECS,
    _s15_loads=_LOAD_SEGMENTS,
    _t15_loads=_T15_LOAD_SEGMENTS,
    _s15_functions=_S15_FUNCTIONS,
    _t15_functions=_T15_FUNCTIONS,
    _sha256=hashlib.sha256,
    _isfinite=math.isfinite,
    _unpack_from=struct.unpack_from,
    _bytes=bytes,
    _bool=bool,
    _float=float,
    _int=int,
    _object=object,
    _str=str,
    _tuple=tuple,
    _len=len,
    _type=type,
    _id=id,
    _range=range,
    _zip=zip,
    _type_error=TypeError,
    _value_error=ValueError,
    _weakref_ref=weakref.ref,
):
    artifact_specs = _tuple(_tuple(row) for row in _artifact_specs)
    s15_loads = _tuple(_tuple(row) for row in _s15_loads)
    t15_loads = _tuple(_tuple(row) for row in _t15_loads)
    s15_functions = _tuple(_tuple(row) for row in _s15_functions)
    t15_functions = _tuple(_tuple(row) for row in _t15_functions)
    verified_instances = {}
    canonical_fingerprint: Tuple[object, ...] = ()
    invalid_fingerprint = _object()

    @dataclass(frozen=True)
    class ArtifactReceipt:
        artifact_id: str
        size: int
        sha256: str

    @dataclass(frozen=True)
    class ElfLoadSegment:
        file_offset: int
        virtual_address: int
        file_size: int
        memory_size: int
        flags: int
        alignment: int

    @dataclass(frozen=True)
    class FunctionReceipt:
        name: str
        analysis_address: int
        window_file_offset: int
        window_size: int
        window_sha256: str

    @dataclass(frozen=True)
    class ModelSoftwareEvidence:
        model: str
        release: str
        package: ArtifactReceipt
        cgminer: ArtifactReceipt
        elf_loads: Tuple[ElfLoadSegment, ...]
        functions: Tuple[FunctionReceipt, ...]
        fpga_register_offset: int
        i2c_device_address: int
        fpga_bus_selector: int
        read_direction: bool
        register_prefix_enabled: bool
        register_address: int
        payload_bytes: int
        packed_command_base_without_payload: int
        poll_iterations: int
        poll_interval_microseconds: int
        wrapper_pre_delay_microseconds: int
        caller_post_delay_microseconds: int
        raw_byte_bounds: Tuple[int, int]
        conversion_slope: float
        conversion_intercept: float
        conversion_units_verified: bool
        helper_result_consumed: bool
        write_readback_observed: bool
        userspace_checksum_bytes_observed: int
        wire_checksum_rule_verified: bool
        software_power_on_level: int
        software_power_off_level: int
        gpio907_physical_binding_verified: bool
        heartbeat_frame: Tuple[int, ...]
        heartbeat_expected_reply: Tuple[int, ...]
        heartbeat_attempts: int
        heartbeat_caller_period_seconds: int
        heartbeat_failure_action_observed: str
        heartbeat_electrical_safe_off_verified: bool

    @dataclass(frozen=True)
    class GuideEvidence:
        s15_maintenance_artifact: ArtifactReceipt
        apw8_maintenance_artifact: ArtifactReceipt
        s15_document_version: str
        apw8_named_products: Tuple[str, ...]
        named_psu: str
        adjustable_output_range_volts: Tuple[float, float]
        adjustable_output_max_current_amperes: float
        fixed_output_volts: float
        fixed_output_max_current_amperes: float
        documented_values_are_runtime_safe_limits: bool
        apw8_control_signals: Tuple[str, ...]
        sda_scl_documented_as_i2c: bool
        en_documented_effective_level: int
        guide_en_polarity_bound_to_gpio907: bool
        controller_label: str
        controller_revision: str
        j11_signal_names: Tuple[str, ...]
        linux_gpio_number_printed_for_pwr_en: bool
        page_1_and_3_topology: str
        page_10_conflicting_topology_text: str
        topology_internally_consistent: bool
        exact_release_controller_binding_verified: bool

    @dataclass(frozen=True)
    class OperationalAuthority:
        device_open: bool = field(default=False, init=False)
        i2c_read: bool = field(default=False, init=False)
        i2c_write: bool = field(default=False, init=False)
        gpio_read: bool = field(default=False, init=False)
        gpio_write: bool = field(default=False, init=False)
        psu_enable: bool = field(default=False, init=False)
        psu_disable: bool = field(default=False, init=False)
        voltage_change: bool = field(default=False, init=False)
        pic_access: bool = field(default=False, init=False)
        mining_start: bool = field(default=False, init=False)
        firmware_install: bool = field(default=False, init=False)
        factory_execution: bool = field(default=False, init=False)
        live_probe: bool = field(default=False, init=False)

    @dataclass(frozen=True)
    class S15T15Apw8Inspection:
        artifacts: Tuple[ArtifactReceipt, ...]
        models: Tuple[ModelSoftwareEvidence, ...]
        guide: GuideEvidence
        package_membership_parsed_by_this_inspector: bool
        publisher_authenticity_verified: bool
        electrical_apw8_identity_verified_for_exact_release: bool
        resident_linux_dtb_presence_verified_by_this_inspector: bool
        resident_linux_dtb_association_verified: bool
        t15_physical_topology_verified: bool
        unresolved: Tuple[str, ...]
        authority: OperationalAuthority = field(
            default_factory=OperationalAuthority, init=False
        )

        @property
        def inspection_verified(self) -> bool:
            """True only for an untampered receipt minted from all exact bytes."""

            reference = verified_instances.get(_id(self))
            candidate = fingerprint(self)
            return (
                reference is not None
                and reference() is self
                and candidate is not invalid_fingerprint
                and candidate == canonical_fingerprint
            )

    def exact_primitives(value):
        value_type = _type(value)
        if value_type is _tuple:
            sanitized = []
            for item in value:
                exact = exact_primitives(item)
                if exact is invalid_fingerprint:
                    return invalid_fingerprint
                sanitized.append(exact)
            return ("tuple", _tuple(sanitized))
        if value_type is _bool:
            return ("bool", value)
        if value_type is _int:
            return ("int", value)
        if value_type is _str:
            return ("str", value)
        if value_type is _float and _isfinite(value):
            return ("float", value)
        return invalid_fingerprint

    def artifact_fingerprint(value: ArtifactReceipt) -> Tuple[object, ...]:
        if _type(value) is not ArtifactReceipt:
            return invalid_fingerprint
        return exact_primitives((value.artifact_id, value.size, value.sha256))

    def load_fingerprint(value: ElfLoadSegment) -> Tuple[object, ...]:
        if _type(value) is not ElfLoadSegment:
            return invalid_fingerprint
        return exact_primitives(
            (
                value.file_offset,
                value.virtual_address,
                value.file_size,
                value.memory_size,
                value.flags,
                value.alignment,
            )
        )

    def function_fingerprint(value: FunctionReceipt) -> Tuple[object, ...]:
        if _type(value) is not FunctionReceipt:
            return invalid_fingerprint
        return exact_primitives(
            (
                value.name,
                value.analysis_address,
                value.window_file_offset,
                value.window_size,
                value.window_sha256,
            )
        )

    def model_fingerprint(value: ModelSoftwareEvidence) -> Tuple[object, ...]:
        if (
            _type(value) is not ModelSoftwareEvidence
            or _type(value.elf_loads) is not _tuple
            or _type(value.functions) is not _tuple
            or _type(value.raw_byte_bounds) is not _tuple
            or _type(value.heartbeat_frame) is not _tuple
            or _type(value.heartbeat_expected_reply) is not _tuple
        ):
            return invalid_fingerprint
        return exact_primitives(
            (
                value.model,
                value.release,
                artifact_fingerprint(value.package),
                artifact_fingerprint(value.cgminer),
                _tuple(load_fingerprint(item) for item in value.elf_loads),
                _tuple(function_fingerprint(item) for item in value.functions),
                value.fpga_register_offset,
                value.i2c_device_address,
                value.fpga_bus_selector,
                value.read_direction,
                value.register_prefix_enabled,
                value.register_address,
                value.payload_bytes,
                value.packed_command_base_without_payload,
                value.poll_iterations,
                value.poll_interval_microseconds,
                value.wrapper_pre_delay_microseconds,
                value.caller_post_delay_microseconds,
                value.raw_byte_bounds,
                value.conversion_slope,
                value.conversion_intercept,
                value.conversion_units_verified,
                value.helper_result_consumed,
                value.write_readback_observed,
                value.userspace_checksum_bytes_observed,
                value.wire_checksum_rule_verified,
                value.software_power_on_level,
                value.software_power_off_level,
                value.gpio907_physical_binding_verified,
                value.heartbeat_frame,
                value.heartbeat_expected_reply,
                value.heartbeat_attempts,
                value.heartbeat_caller_period_seconds,
                value.heartbeat_failure_action_observed,
                value.heartbeat_electrical_safe_off_verified,
            )
        )

    def fingerprint(value: S15T15Apw8Inspection) -> Tuple[object, ...]:
        if (
            _type(value) is not S15T15Apw8Inspection
            or _type(value.artifacts) is not _tuple
            or _type(value.models) is not _tuple
            or _type(value.guide) is not GuideEvidence
            or _type(value.unresolved) is not _tuple
            or _type(value.authority) is not OperationalAuthority
        ):
            return invalid_fingerprint
        guide = value.guide
        authority = value.authority
        if (
            _type(guide.apw8_named_products) is not _tuple
            or _type(guide.adjustable_output_range_volts) is not _tuple
            or _type(guide.apw8_control_signals) is not _tuple
            or _type(guide.j11_signal_names) is not _tuple
        ):
            return invalid_fingerprint
        return exact_primitives(
            (
                _tuple(artifact_fingerprint(item) for item in value.artifacts),
                _tuple(model_fingerprint(item) for item in value.models),
                (
                    artifact_fingerprint(guide.s15_maintenance_artifact),
                    artifact_fingerprint(guide.apw8_maintenance_artifact),
                    guide.s15_document_version,
                    guide.apw8_named_products,
                    guide.named_psu,
                    guide.adjustable_output_range_volts,
                    guide.adjustable_output_max_current_amperes,
                    guide.fixed_output_volts,
                    guide.fixed_output_max_current_amperes,
                    guide.documented_values_are_runtime_safe_limits,
                    guide.apw8_control_signals,
                    guide.sda_scl_documented_as_i2c,
                    guide.en_documented_effective_level,
                    guide.guide_en_polarity_bound_to_gpio907,
                    guide.controller_label,
                    guide.controller_revision,
                    guide.j11_signal_names,
                    guide.linux_gpio_number_printed_for_pwr_en,
                    guide.page_1_and_3_topology,
                    guide.page_10_conflicting_topology_text,
                    guide.topology_internally_consistent,
                    guide.exact_release_controller_binding_verified,
                ),
                value.package_membership_parsed_by_this_inspector,
                value.publisher_authenticity_verified,
                value.electrical_apw8_identity_verified_for_exact_release,
                value.resident_linux_dtb_presence_verified_by_this_inspector,
                value.resident_linux_dtb_association_verified,
                value.t15_physical_topology_verified,
                value.unresolved,
                (
                    authority.device_open,
                    authority.i2c_read,
                    authority.i2c_write,
                    authority.gpio_read,
                    authority.gpio_write,
                    authority.psu_enable,
                    authority.psu_disable,
                    authority.voltage_change,
                    authority.pic_access,
                    authority.mining_start,
                    authority.firmware_install,
                    authority.factory_execution,
                    authority.live_probe,
                ),
            )
        )

    def admit(raw: bytes, spec: Tuple[object, ...]) -> ArtifactReceipt:
        if _type(raw) is not _bytes:
            raise _type_error("artifacts must be exact bytes")
        artifact_id, expected_size, expected_sha256 = spec
        if _len(raw) != expected_size:
            raise _value_error(f"{artifact_id} size mismatch")
        actual = _sha256(raw).hexdigest()
        if actual != expected_sha256:
            raise _value_error(f"{artifact_id} SHA-256 mismatch")
        return ArtifactReceipt(artifact_id, expected_size, expected_sha256)

    def parse_loads(raw: bytes, expected: Tuple[Tuple[int, ...], ...]):
        if raw[:6] != b"\x7fELF\x01\x01":
            raise _value_error("cgminer must be ELF32 little-endian")
        if _unpack_from("<H", raw, 18)[0] != 40:
            raise _value_error("cgminer must target ARM")
        phoff = _unpack_from("<I", raw, 28)[0]
        phentsize = _unpack_from("<H", raw, 42)[0]
        phnum = _unpack_from("<H", raw, 44)[0]
        if phentsize != 32 or phnum != 8:
            raise _value_error("cgminer program-header geometry mismatch")
        loads = []
        for index in _range(phnum):
            offset = phoff + index * phentsize
            row = _unpack_from("<8I", raw, offset)
            if row[0] == 1:
                loads.append((row[1], row[2], row[4], row[5], row[6], row[7]))
        if _tuple(loads) != expected:
            raise _value_error("cgminer PT_LOAD geometry mismatch")
        return _tuple(ElfLoadSegment(*row) for row in loads)

    def map_va(loads: Tuple[Tuple[int, ...], ...], address: int, size: int) -> int:
        for file_offset, virtual_address, file_size, _, _, _ in loads:
            if (
                virtual_address <= address
                and address + size <= virtual_address + file_size
            ):
                return file_offset + address - virtual_address
        raise _value_error("semantic window is outside a file-backed PT_LOAD")

    def validate_functions(raw, loads, rows):
        receipts = []
        for name, address, offset, size, expected_digest in rows:
            if map_va(loads, address, size) != offset:
                raise _value_error(f"{name} VA/file mapping mismatch")
            window = raw[offset : offset + size]
            if _len(window) != size or _sha256(window).hexdigest() != expected_digest:
                raise _value_error(f"{name} semantic window mismatch")
            receipts.append(
                FunctionReceipt(name, address, offset, size, expected_digest)
            )
        return _tuple(receipts)

    def make_model(model, release, package, cgminer, loads, functions):
        return ModelSoftwareEvidence(
            model=model,
            release=release,
            package=package,
            cgminer=cgminer,
            elf_loads=_tuple(ElfLoadSegment(*row) for row in loads),
            functions=functions,
            fpga_register_offset=0x30,
            i2c_device_address=0x10,
            fpga_bus_selector=1,
            read_direction=False,
            register_prefix_enabled=True,
            register_address=0x02,
            payload_bytes=1,
            packed_command_base_without_payload=0x05200200,
            poll_iterations=101,
            poll_interval_microseconds=5_000,
            wrapper_pre_delay_microseconds=100_000,
            caller_post_delay_microseconds=300_000,
            raw_byte_bounds=(0, 255),
            conversion_slope=59.93150685,
            conversion_intercept=1215.89444,
            conversion_units_verified=False,
            helper_result_consumed=False,
            write_readback_observed=False,
            userspace_checksum_bytes_observed=0,
            wire_checksum_rule_verified=False,
            software_power_on_level=0,
            software_power_off_level=1,
            gpio907_physical_binding_verified=False,
            heartbeat_frame=(0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A),
            heartbeat_expected_reply=(0x16, 0x01),
            heartbeat_attempts=3,
            heartbeat_caller_period_seconds=10,
            heartbeat_failure_action_observed="retry/log only",
            heartbeat_electrical_safe_off_verified=False,
        )

    def make_inspection(artifacts, s15_functions_receipt, t15_functions_receipt):
        s15 = make_model(
            "S15",
            "Antminer-S15-user-OM-201912131535-sig_4864",
            artifacts[0],
            artifacts[1],
            s15_loads,
            s15_functions_receipt,
        )
        t15 = make_model(
            "T15",
            "Antminer-T15-user-OM-201912131546-sig_4867",
            artifacts[2],
            artifacts[3],
            t15_loads,
            t15_functions_receipt,
        )
        guide = GuideEvidence(
            s15_maintenance_artifact=artifacts[4],
            apw8_maintenance_artifact=artifacts[5],
            s15_document_version="2019.07.02",
            apw8_named_products=("S15", "T15"),
            named_psu="APW8",
            adjustable_output_range_volts=(16.32, 20.04),
            adjustable_output_max_current_amperes=95.0,
            fixed_output_volts=12.0,
            fixed_output_max_current_amperes=5.0,
            documented_values_are_runtime_safe_limits=False,
            apw8_control_signals=("SDA", "SCL", "EN"),
            sda_scl_documented_as_i2c=True,
            en_documented_effective_level=0,
            guide_en_polarity_bound_to_gpio907=False,
            controller_label="Ctrl_C43",
            controller_revision="V1.2011",
            j11_signal_names=("PWR_I2C_SDA", "PWR_I2C_SCL", "PWR_EN"),
            linux_gpio_number_printed_for_pwr_en=False,
            page_1_and_3_topology="12 voltage domains; 5 chips/domain; 60 chips",
            page_10_conflicting_topology_text="6 chips in each domain",
            topology_internally_consistent=False,
            exact_release_controller_binding_verified=False,
        )
        return S15T15Apw8Inspection(
            artifacts=artifacts,
            models=(s15, t15),
            guide=guide,
            package_membership_parsed_by_this_inspector=False,
            publisher_authenticity_verified=False,
            electrical_apw8_identity_verified_for_exact_release=False,
            resident_linux_dtb_presence_verified_by_this_inspector=False,
            resident_linux_dtb_association_verified=False,
            t15_physical_topology_verified=False,
            unresolved=(
                "exact resident NAND DTB at 0x01a00000 for each controller",
                "net-level GPIO907 to J11 PWR_EN correlation and polarity",
                "electrical capture of device 0x10 register 0x02 transaction",
                "wire checksum or integrity behavior below the FPGA command register",
                "APW8 revision and exact release/controller association",
                "T15 board revision and independent physical topology",
                "safe operational voltage limits and fail-safe de-energization proof",
            ),
        )

    baseline_artifacts = _tuple(ArtifactReceipt(*spec) for spec in artifact_specs)
    baseline = make_inspection(
        baseline_artifacts,
        _tuple(FunctionReceipt(*row) for row in s15_functions),
        _tuple(FunctionReceipt(*row) for row in t15_functions),
    )
    canonical_fingerprint = fingerprint(baseline)

    def inspect_s15_t15_apw8_evidence(
        *,
        s15_package: bytes,
        s15_cgminer: bytes,
        t15_package: bytes,
        t15_cgminer: bytes,
        s15_maintenance_guide: bytes,
        apw8_maintenance_guide: bytes,
    ) -> S15T15Apw8Inspection:
        """Admit six exact byte strings and return observations only."""

        raw = (
            s15_package,
            s15_cgminer,
            t15_package,
            t15_cgminer,
            s15_maintenance_guide,
            apw8_maintenance_guide,
        )
        artifacts = _tuple(
            admit(value, spec) for value, spec in _zip(raw, artifact_specs)
        )
        parsed_s15_loads = parse_loads(s15_cgminer, s15_loads)
        parsed_t15_loads = parse_loads(t15_cgminer, t15_loads)
        # Re-materialize primitive tuples so no returned object is retained by the closure.
        s15_load_rows = _tuple(
            (
                item.file_offset,
                item.virtual_address,
                item.file_size,
                item.memory_size,
                item.flags,
                item.alignment,
            )
            for item in parsed_s15_loads
        )
        t15_load_rows = _tuple(
            (
                item.file_offset,
                item.virtual_address,
                item.file_size,
                item.memory_size,
                item.flags,
                item.alignment,
            )
            for item in parsed_t15_loads
        )
        inspection = make_inspection(
            artifacts,
            validate_functions(s15_cgminer, s15_load_rows, s15_functions),
            validate_functions(t15_cgminer, t15_load_rows, t15_functions),
        )
        receipt_id = _id(inspection)
        verified_instances[receipt_id] = _weakref_ref(
            inspection,
            lambda _reference, key=receipt_id: verified_instances.pop(key, None),
        )
        return inspection

    return (
        ArtifactReceipt,
        ElfLoadSegment,
        FunctionReceipt,
        ModelSoftwareEvidence,
        GuideEvidence,
        OperationalAuthority,
        S15T15Apw8Inspection,
        inspect_s15_t15_apw8_evidence,
    )


(
    ArtifactReceipt,
    ElfLoadSegment,
    FunctionReceipt,
    ModelSoftwareEvidence,
    GuideEvidence,
    OperationalAuthority,
    S15T15Apw8Inspection,
    inspect_s15_t15_apw8_evidence,
) = _build_api()
del _build_api
