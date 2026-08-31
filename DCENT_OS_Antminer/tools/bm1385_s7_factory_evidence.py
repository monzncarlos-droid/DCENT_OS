"""Bytes-only evidence contract for the two held BM1385/S7 factory profiles.

The inspector accepts immutable bytes, verifies exact size and SHA-256, parses
the bounded ``Config.ini`` syntax, and returns typed observations. It opens no
path and grants no device, transport, voltage, thermal, power, work, share,
install, or runtime-admission authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable


class Bm1385S7EvidenceError(ValueError):
    """Input bytes did not satisfy the exact held-profile contract."""


@dataclass(frozen=True)
class Authority:
    device_io: bool = field(default=False, init=False)
    transport: bool = field(default=False, init=False)
    runtime_admission: bool = field(default=False, init=False)
    work_dispatch: bool = field(default=False, init=False)
    share_submission: bool = field(default=False, init=False)
    voltage_control: bool = field(default=False, init=False)
    thermal_control: bool = field(default=False, init=False)
    rail_power: bool = field(default=False, init=False)
    install: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    size_bytes: int
    sha256: str
    held_path: str
    fixture_path: str
    exact_bytes_verified: bool = field(default=False, init=False)


@dataclass(frozen=True)
class FactoryProfileObservation:
    variant: str
    config_artifact_id: str
    name: str
    asic_type_label: int
    asic_count: int
    cores_per_asic: int
    command_mode: int
    test_mode: bool
    check_chain: bool
    timeout_raw: int
    open_core_gap_raw: int
    data_count: int
    pass_counts: tuple[int, ...]
    valid_nonces: tuple[int, ...]
    frequencies_mhz: tuple[int, ...]
    voltages_raw: tuple[int, ...]
    check_temperature: bool
    temperature_source: str
    temperature_selector_raw: int
    temperature_sensors_raw: tuple[int, ...]
    default_temperature_offset_raw: int
    start_sensor_raw: int
    start_temperature_raw: int
    target_temperature_raw: int
    alarm_temperature_raw: int
    heating_up_time_raw: int
    open_core_masks: tuple[int, ...]
    invalid_core_num: int
    pic_voltage: bool
    iic_pic: bool
    dac: bool
    factory_timestamp: tuple[int, ...]
    pattern_repeat_num: int
    get_parameter_from_pic: bool
    write_frequency_into_pic: bool
    hold_frequency_in_pic: bool
    add_voltage_after_test_ok: bool
    add_voltage_value_raw: int
    time_gap_between_test_raw: int
    exact_config_verified: bool = field(default=False, init=False)
    runtime_profile_authorized: bool = field(default=False, init=False)


@dataclass(frozen=True)
class Bm1385S7EvidenceReceipt:
    artifacts: tuple[ArtifactReceipt, ...]
    profiles: tuple[FactoryProfileObservation, ...]
    unresolved: tuple[str, ...]
    authority: Authority = field(default_factory=Authority, init=False)
    evidence_verified: bool = field(default=False, init=False)


def _make_inspector() -> Callable[..., Bm1385S7EvidenceReceipt]:
    sha256 = hashlib.sha256
    bytes_type = bytes
    tuple_type = tuple
    len_fn = len
    isinstance_fn = isinstance
    sum_fn = sum
    zip_fn = zip
    range_fn = range
    any_fn = any
    int_fn = int
    set_trusted = object.__setattr__
    error_type = Bm1385S7EvidenceError
    artifact_type = ArtifactReceipt
    profile_type = FactoryProfileObservation
    receipt_type = Bm1385S7EvidenceReceipt

    specs = (
        (
            "s7_45_config",
            "S7-45",
            2_055,
            "632abf407d5ea7f527f219322d3470ab9a1e2756b33dc0471ed1e01cc2b361c2",
            "",
            "tools/fixtures/bm1385_s7/Config.ini-S7-45",
        ),
        (
            "s7_54_config",
            "S7-54",
            2_066,
            "7df112aef6246d376f6c02088ad1e9baeac72d8bbfd8b351232f56704baa1177",
            "",
            "tools/fixtures/bm1385_s7/Config.ini-S7-54",
        ),
    )
    expected_profile_keys = (
        (
            "S7-45",
            45,
            50_000,
            (600, 600, 600, 0, 0, 0, 0, 0, 0),
            (1_025, 1_050, 1_075, 0, 0, 0, 0, 0, 0),
            (18_000,) * 9,
        ),
        (
            "S7-54",
            54,
            100_000,
            (500, 550, 525, 400, 400, 400, 400, 400, 400),
            (945, 975, 1_005, 0, 0, 0, 0, 0, 0),
            (21_600,) * 9,
        ),
    )
    unresolved = (
        "exact S7/S7-LN control-board carrier identity",
        "passive enumeration bound to the carrier and 45/54-chip variant",
        "deployed FIL transport and response framing",
        "model-bound voltage-controller command, units, and fault behavior",
        "external LM75A acquisition and independent thermal cutoff",
        "independent rail-off path",
        "known-work snapshot binding and share qualification",
    )

    def require_exact(
        artifact_id: str, data: bytes, size: int, digest: str
    ) -> bytes:
        if not isinstance_fn(data, bytes_type):
            raise TypeError(f"{artifact_id}: immutable exact bytes required")
        if len_fn(data) != size:
            raise error_type(f"{artifact_id}: expected {size} bytes")
        if sha256(data).hexdigest() != digest:
            raise error_type(f"{artifact_id}: SHA-256 mismatch")
        return data

    def parse_config(
        artifact_id: str, variant: str, data: bytes
    ) -> FactoryProfileObservation:
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise error_type(f"{artifact_id}: non-ASCII Config.ini") from exc
        lines = text.splitlines()
        if not lines or lines[0] != "[Config]" or len_fn(lines) > 160:
            raise error_type(f"{artifact_id}: malformed or oversized Config.ini")
        values: dict[str, str] = {}
        for raw_line in lines[1:]:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise error_type(f"{artifact_id}: malformed assignment")
            key, value = line.split("=", 1)
            if not key or key in values:
                raise error_type(f"{artifact_id}: duplicate or empty key {key!r}")
            values[key] = value

        def integer(key: str) -> int:
            try:
                raw_value = values[key]
                if not raw_value or any_fn(
                    char not in "-0123456789" for char in raw_value
                ):
                    raise ValueError
                return int_fn(raw_value, 10)
            except (KeyError, ValueError) as exc:
                raise error_type(f"{artifact_id}: invalid integer {key}") from exc

        def flag_value(key: str) -> bool:
            result = integer(key)
            if result not in (0, 1):
                raise error_type(f"{artifact_id}: non-boolean flag {key}")
            return result == 1

        def numbered(prefix: str, count: int) -> tuple[int, ...]:
            return tuple_type(
                integer(f"{prefix}{index}") for index in range_fn(1, count + 1)
            )

        if values.get("Name") != "S7 HASH board":
            raise error_type(f"{artifact_id}: model label mismatch")
        if values.get("TestDir") != "/mnt/mmc1/minertest64/minertest64_":
            raise error_type(f"{artifact_id}: held jig-path marker mismatch")
        if integer("GetTempFrom") != 0:
            raise error_type(f"{artifact_id}: expected external LM75A source")

        result = profile_type(
            variant=variant,
            config_artifact_id=artifact_id,
            name=values["Name"],
            asic_type_label=integer("AsicType"),
            asic_count=integer("AsicNum"),
            cores_per_asic=integer("CoreNum"),
            command_mode=integer("CommandMode"),
            test_mode=flag_value("TestMode"),
            check_chain=flag_value("CheckChain"),
            timeout_raw=integer("Timeout"),
            open_core_gap_raw=integer("OpenCoreGap"),
            data_count=integer("DataCount"),
            pass_counts=numbered("PassCount", 9),
            valid_nonces=numbered("ValidNonce", 9),
            frequencies_mhz=numbered("Freq", 9),
            voltages_raw=numbered("Voltage", 9),
            check_temperature=flag_value("CheckTemp"),
            temperature_source="external LM75A over IIC",
            temperature_selector_raw=integer("TempSel"),
            temperature_sensors_raw=numbered("TempSensor", 4),
            default_temperature_offset_raw=integer("DefaultTempOffset"),
            start_sensor_raw=integer("StartSensor"),
            start_temperature_raw=integer("StartTemp"),
            target_temperature_raw=integer("TargetTemp"),
            alarm_temperature_raw=integer("AlarmTemp"),
            heating_up_time_raw=integer("HeatingUpTime"),
            open_core_masks=numbered("Open_Core_Num", 4),
            invalid_core_num=integer("Invalid_Core_Num"),
            pic_voltage=flag_value("Pic_VOLTAGE"),
            iic_pic=flag_value("IICPic"),
            dac=flag_value("DAC"),
            factory_timestamp=(
                integer("year"),
                integer("month"),
                integer("date"),
                integer("hour"),
                integer("minute"),
                integer("second"),
            ),
            pattern_repeat_num=integer("pattern_repeat_num"),
            get_parameter_from_pic=flag_value("get_parameter_from_pic"),
            write_frequency_into_pic=flag_value("write_freq_into_pic"),
            hold_frequency_in_pic=flag_value("hold_freq_in_pic"),
            add_voltage_after_test_ok=flag_value("add_voltage_after_test_ok"),
            add_voltage_value_raw=integer("add_voltage_value"),
            time_gap_between_test_raw=integer("time_gap_between_test"),
        )
        return result

    def profile_key(profile: FactoryProfileObservation) -> tuple[object, ...]:
        return (
            profile.variant,
            profile.asic_count,
            profile.open_core_gap_raw,
            profile.frequencies_mhz,
            profile.voltages_raw,
            profile.valid_nonces,
        )

    def inspect_bm1385_s7_factory_evidence(
        *, s7_45_config: bytes, s7_54_config: bytes
    ) -> Bm1385S7EvidenceReceipt:
        supplied = (s7_45_config, s7_54_config)
        if (
            sum_fn(
                len_fn(item) for item in supplied if isinstance_fn(item, bytes_type)
            )
            > 5_000
        ):
            raise error_type("aggregate evidence exceeds 5000-byte bound")
        artifacts = []
        profiles = []
        for spec, data, expected_key in zip_fn(specs, supplied, expected_profile_keys):
            artifact_id, variant, size, digest, held_path, fixture_path = spec
            exact = require_exact(artifact_id, data, size, digest)
            profile = parse_config(artifact_id, variant, exact)
            if profile_key(profile) != expected_key:
                raise error_type(f"{artifact_id}: profile semantics mismatch")
            if (
                profile.asic_type_label != 1_385
                or profile.cores_per_asic != 50
                or profile.command_mode != 1
                or not profile.test_mode
                or not profile.check_chain
                or profile.timeout_raw != 0
                or profile.data_count != 400
                or profile.pass_counts != (400,) * 9
                or profile.valid_nonces
                != (profile.asic_count * profile.data_count,) * 9
                or profile.temperature_sensors_raw != (62, 0, 0, 0)
                or profile.open_core_masks
                != (4_294_967_295, 4_294_967_295, 4_294_967_295, 262_143)
                or not profile.pic_voltage
                or profile.iic_pic
                or profile.dac
            ):
                raise error_type(f"{artifact_id}: shared S7 contract mismatch")
            artifact = artifact_type(
                artifact_id, size, digest, held_path, fixture_path
            )
            set_trusted(artifact, "exact_bytes_verified", True)
            set_trusted(profile, "exact_config_verified", True)
            artifacts.append(artifact)
            profiles.append(profile)

        receipt = receipt_type(tuple_type(artifacts), tuple_type(profiles), unresolved)
        set_trusted(receipt, "evidence_verified", True)
        return receipt

    return inspect_bm1385_s7_factory_evidence


inspect_bm1385_s7_factory_evidence = _make_inspector()
del _make_inspector


__all__ = (
    "ArtifactReceipt",
    "Authority",
    "Bm1385S7EvidenceError",
    "Bm1385S7EvidenceReceipt",
    "FactoryProfileObservation",
    "inspect_bm1385_s7_factory_evidence",
)
