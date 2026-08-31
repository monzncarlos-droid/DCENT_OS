//! Host-pure BM1385 / Antminer S7 factory-profile and FIL-wire evidence.
//!
//! Two exact AMTC `Config.ini` artifacts prove distinct S7 factory profiles:
//! 45 BM1385 chips at a 600 MHz test point and 54 chips with 400/500/525/550
//! MHz steps. The held Bitmain jig independently proves four-byte FIL commands,
//! command CRC5 over 27 bits, five-byte returns, register-response CRC5 over 35
//! bits, and the nonce metadata masks encoded below.
//!
//! This module performs no I/O. It does not identify a physical S7, select a
//! live board variant, open a transport, dispatch work, command voltage, trust
//! temperatures, power a rail, or authorize mining. In particular, the
//! synthetic catalog value `0x1385` is never treated as a wire identity.

use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1385_S7_45_CONFIG_SIZE: usize = 2_055;
pub const BM1385_S7_45_CONFIG_SHA256: &str =
    "632abf407d5ea7f527f219322d3470ab9a1e2756b33dc0471ed1e01cc2b361c2";
pub const BM1385_S7_54_CONFIG_SIZE: usize = 2_066;
pub const BM1385_S7_54_CONFIG_SHA256: &str =
    "7df112aef6246d376f6c02088ad1e9baeac72d8bbfd8b351232f56704baa1177";

pub const BM1385_S7_ASIC_TYPE_LABEL: u16 = 1_385;
pub const BM1385_S7_CORES_PER_ASIC: u8 = 50;
pub const BM1385_S7_FIL_COMMAND_MODE: u8 = 1;
pub const BM1385_S7_FACTORY_TRIALS: usize = 9;
pub const BM1385_S7_FACTORY_DATA_COUNT: u32 = 400;
pub const BM1385_FIL_COMMAND_BYTES: usize = 4;
pub const BM1385_FIL_RETURN_BYTES: usize = 5;
pub const BM1385_FIL_COMMAND_CRC_BITS: usize = 27;
pub const BM1385_FIL_REGISTER_RETURN_CRC_BITS: usize = 35;
pub const BM1385_FIL_CRC_MASK: u8 = 0x1f;
pub const BM1385_FIL_RETURN_KIND_MASK: u8 = 0x80;
pub const BM1385_FIL_NONCE_CORE_MASK: u8 = 0x3f;
pub const BM1385_FIL_NONCE_WORK_ID_MASK: u8 = 0x7f;
pub const BM1385_FIL_MAX_CORE_INDEX: u8 = 49;
pub const BM1385_FIL_BT8D_MAX: u8 = 26;

const CMD_SET_ADDRESS: u8 = 0x01;
const CMD_WRITE_REGISTER: u8 = 0x02;
const CMD_READ_REGISTER: u8 = 0x04;
const CMD_CHAIN_INACTIVE: u8 = 0x05;
const CMD_SET_BAUD: u8 = 0x06;
const CMD_SET_PLL: u8 = 0x07;
const CMD_BROADCAST: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385S7FactoryVariant {
    S7_45,
    S7_54,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385S7TemperatureSource {
    /// `GetTempFrom=0`: external LM75A over IIC, not an ASIC diode reading.
    ExternalLm75aIic,
}

/// Exact, typed transcription of one held factory `Config.ini`.
///
/// Fields ending in `_raw` deliberately preserve the source spelling without
/// asserting unproved physical units or a production controller mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1385S7FactoryProfile {
    pub variant: Bm1385S7FactoryVariant,
    pub config_size: usize,
    pub config_sha256: &'static str,
    pub name: &'static str,
    pub asic_type_label: u16,
    pub asic_count: u8,
    pub cores_per_asic: u8,
    pub command_mode: u8,
    pub test_mode: bool,
    pub check_chain: bool,
    pub timeout_raw: u32,
    pub open_core_gap_raw: u32,
    pub data_count: u32,
    pub pass_counts: [u32; BM1385_S7_FACTORY_TRIALS],
    pub valid_nonces: [u32; BM1385_S7_FACTORY_TRIALS],
    pub frequencies_mhz: [u16; BM1385_S7_FACTORY_TRIALS],
    pub voltages_raw: [u16; BM1385_S7_FACTORY_TRIALS],
    pub check_temperature: bool,
    pub temperature_source: Bm1385S7TemperatureSource,
    pub temperature_selector_raw: u8,
    pub temperature_sensors_raw: [u8; 4],
    pub default_temperature_offset_raw: i16,
    pub start_sensor_raw: u8,
    pub start_temperature_raw: i16,
    pub target_temperature_raw: i16,
    pub alarm_temperature_raw: i16,
    pub heating_up_time_raw: u32,
    pub open_core_masks: [u32; 4],
    pub invalid_core_num: u32,
    pub pic_voltage: bool,
    pub iic_pic: bool,
    pub dac: bool,
    pub factory_timestamp: (u16, u8, u8, u8, u8, u8),
    pub pattern_repeat_num: u8,
    pub get_parameter_from_pic: bool,
    pub write_frequency_into_pic: bool,
    pub hold_frequency_in_pic: bool,
    pub add_voltage_after_test_ok: bool,
    pub add_voltage_value_raw: u16,
    pub time_gap_between_test_raw: u32,
}

const COMMON_PASS_COUNTS: [u32; BM1385_S7_FACTORY_TRIALS] =
    [BM1385_S7_FACTORY_DATA_COUNT; BM1385_S7_FACTORY_TRIALS];
const COMMON_OPEN_CORE_MASKS: [u32; 4] = [0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0x0003_ffff];

pub const BM1385_S7_45_FACTORY_PROFILE: Bm1385S7FactoryProfile = Bm1385S7FactoryProfile {
    variant: Bm1385S7FactoryVariant::S7_45,
    config_size: BM1385_S7_45_CONFIG_SIZE,
    config_sha256: BM1385_S7_45_CONFIG_SHA256,
    name: "S7 HASH board",
    asic_type_label: BM1385_S7_ASIC_TYPE_LABEL,
    asic_count: 45,
    cores_per_asic: BM1385_S7_CORES_PER_ASIC,
    command_mode: BM1385_S7_FIL_COMMAND_MODE,
    test_mode: true,
    check_chain: true,
    timeout_raw: 0,
    open_core_gap_raw: 50_000,
    data_count: BM1385_S7_FACTORY_DATA_COUNT,
    pass_counts: COMMON_PASS_COUNTS,
    valid_nonces: [18_000; BM1385_S7_FACTORY_TRIALS],
    frequencies_mhz: [600, 600, 600, 0, 0, 0, 0, 0, 0],
    voltages_raw: [1_025, 1_050, 1_075, 0, 0, 0, 0, 0, 0],
    check_temperature: true,
    temperature_source: Bm1385S7TemperatureSource::ExternalLm75aIic,
    temperature_selector_raw: 0,
    temperature_sensors_raw: [62, 0, 0, 0],
    default_temperature_offset_raw: 0,
    start_sensor_raw: 62,
    start_temperature_raw: 75,
    target_temperature_raw: 85,
    alarm_temperature_raw: 85,
    heating_up_time_raw: 120,
    open_core_masks: COMMON_OPEN_CORE_MASKS,
    invalid_core_num: 0,
    pic_voltage: true,
    iic_pic: false,
    dac: false,
    factory_timestamp: (2016, 5, 18, 10, 36, 12),
    pattern_repeat_num: 1,
    get_parameter_from_pic: false,
    write_frequency_into_pic: false,
    hold_frequency_in_pic: true,
    add_voltage_after_test_ok: false,
    add_voltage_value_raw: 10,
    time_gap_between_test_raw: 10_000,
};

pub const BM1385_S7_54_FACTORY_PROFILE: Bm1385S7FactoryProfile = Bm1385S7FactoryProfile {
    variant: Bm1385S7FactoryVariant::S7_54,
    config_size: BM1385_S7_54_CONFIG_SIZE,
    config_sha256: BM1385_S7_54_CONFIG_SHA256,
    name: "S7 HASH board",
    asic_type_label: BM1385_S7_ASIC_TYPE_LABEL,
    asic_count: 54,
    cores_per_asic: BM1385_S7_CORES_PER_ASIC,
    command_mode: BM1385_S7_FIL_COMMAND_MODE,
    test_mode: true,
    check_chain: true,
    timeout_raw: 0,
    open_core_gap_raw: 100_000,
    data_count: BM1385_S7_FACTORY_DATA_COUNT,
    pass_counts: COMMON_PASS_COUNTS,
    valid_nonces: [21_600; BM1385_S7_FACTORY_TRIALS],
    frequencies_mhz: [500, 550, 525, 400, 400, 400, 400, 400, 400],
    voltages_raw: [945, 975, 1_005, 0, 0, 0, 0, 0, 0],
    check_temperature: true,
    temperature_source: Bm1385S7TemperatureSource::ExternalLm75aIic,
    temperature_selector_raw: 0,
    temperature_sensors_raw: [62, 0, 0, 0],
    default_temperature_offset_raw: 0,
    start_sensor_raw: 62,
    start_temperature_raw: 75,
    target_temperature_raw: 85,
    alarm_temperature_raw: 85,
    heating_up_time_raw: 120,
    open_core_masks: COMMON_OPEN_CORE_MASKS,
    invalid_core_num: 0,
    pic_voltage: true,
    iic_pic: false,
    dac: false,
    factory_timestamp: (2016, 5, 18, 10, 36, 12),
    pattern_repeat_num: 1,
    get_parameter_from_pic: false,
    write_frequency_into_pic: false,
    hold_frequency_in_pic: true,
    add_voltage_after_test_ok: false,
    add_voltage_value_raw: 10,
    time_gap_between_test_raw: 10_000,
};

pub const fn bm1385_s7_factory_profile(
    variant: Bm1385S7FactoryVariant,
) -> &'static Bm1385S7FactoryProfile {
    match variant {
        Bm1385S7FactoryVariant::S7_45 => &BM1385_S7_45_FACTORY_PROFILE,
        Bm1385S7FactoryVariant::S7_54 => &BM1385_S7_54_FACTORY_PROFILE,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385S7ProfileError {
    NonCanonicalProfile,
    WrongAsicTypeLabel(u16),
    WrongCoreCount(u8),
    WrongCommandMode(u8),
    UnknownAsicCount(u8),
    DerivedNonceCountMismatch,
}

/// Validate a supplied profile against one complete, exact held configuration.
pub fn validate_bm1385_s7_factory_profile(
    profile: &Bm1385S7FactoryProfile,
) -> Result<(), Bm1385S7ProfileError> {
    if profile != bm1385_s7_factory_profile(profile.variant) {
        return Err(Bm1385S7ProfileError::NonCanonicalProfile);
    }
    let expected_nonces = u32::from(profile.asic_count) * profile.data_count;
    if profile
        .valid_nonces
        .iter()
        .any(|observed| *observed != expected_nonces)
    {
        return Err(Bm1385S7ProfileError::DerivedNonceCountMismatch);
    }
    Ok(())
}

/// Classify an exact *offline factory-profile key*.
///
/// This must not be used as runtime admission: a chip count is not a carrier
/// identity and the BM1385 exposes no readable `0x1385` identity word.
pub const fn classify_bm1385_s7_factory_profile_key(
    asic_type_label: u16,
    asic_count: u8,
    cores_per_asic: u8,
    command_mode: u8,
) -> Result<Bm1385S7FactoryVariant, Bm1385S7ProfileError> {
    if asic_type_label != BM1385_S7_ASIC_TYPE_LABEL {
        return Err(Bm1385S7ProfileError::WrongAsicTypeLabel(asic_type_label));
    }
    if cores_per_asic != BM1385_S7_CORES_PER_ASIC {
        return Err(Bm1385S7ProfileError::WrongCoreCount(cores_per_asic));
    }
    if command_mode != BM1385_S7_FIL_COMMAND_MODE {
        return Err(Bm1385S7ProfileError::WrongCommandMode(command_mode));
    }
    match asic_count {
        45 => Ok(Bm1385S7FactoryVariant::S7_45),
        54 => Ok(Bm1385S7FactoryVariant::S7_54),
        other => Err(Bm1385S7ProfileError::UnknownAsicCount(other)),
    }
}

fn bm1385_fil_frame(header: u8, byte1: u8, byte2: u8, byte3_high: u8) -> [u8; 4] {
    let mut frame = [header, byte1, byte2, byte3_high & !BM1385_FIL_CRC_MASK];
    frame[3] |= stock_bitmain_crc5(&frame, BM1385_FIL_COMMAND_CRC_BITS);
    frame
}

/// Exact `BM1385_chain_inactive` broadcast frame; pure bytes, no transport.
pub fn bm1385_fil_chain_inactive_frame() -> [u8; BM1385_FIL_COMMAND_BYTES] {
    bm1385_fil_frame(CMD_BROADCAST | CMD_CHAIN_INACTIVE, 0, 0, 0)
}

/// Exact `BM1385_set_address` frame; pure bytes, no transport.
pub fn bm1385_fil_set_address_frame(new_address: u8) -> [u8; BM1385_FIL_COMMAND_BYTES] {
    bm1385_fil_frame(CMD_SET_ADDRESS, new_address, 0, 0)
}

/// Exact `read_BM1385_asic_register` frame; pure bytes, no transport.
pub fn bm1385_fil_read_register_frame(
    chip_address: u8,
    register: u8,
    broadcast: bool,
) -> [u8; BM1385_FIL_COMMAND_BYTES] {
    let header = CMD_READ_REGISTER | if broadcast { CMD_BROADCAST } else { 0 };
    bm1385_fil_frame(header, chip_address, register, 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385FilCommandError {
    Bt8dAboveJigMaximum(u8),
    UnknownFactoryFrequency(u16),
}

/// Exact `BM1385_set_baud` layout with the jig's observed `bt8d <= 26` clamp.
pub fn bm1385_fil_set_baud_frame(
    chip_address: u8,
    bt8d: u8,
    broadcast: bool,
) -> Result<[u8; BM1385_FIL_COMMAND_BYTES], Bm1385FilCommandError> {
    if bt8d > BM1385_FIL_BT8D_MAX {
        return Err(Bm1385FilCommandError::Bt8dAboveJigMaximum(bt8d));
    }
    let header = CMD_SET_BAUD | if broadcast { CMD_BROADCAST } else { 0 };
    Ok(bm1385_fil_frame(header, chip_address, bt8d, 0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1385FactoryPllWords {
    pub frequency_mhz: u16,
    pub pll1: u32,
    pub pll2: u16,
}

/// Exact PLL rows needed by the two held S7 factory profiles.
pub const BM1385_S7_FACTORY_PLL_WORDS: [Bm1385FactoryPllWords; 5] = [
    Bm1385FactoryPllWords {
        frequency_mhz: 400,
        pll1: 0x0008_0040,
        pll2: 0x0420,
    },
    Bm1385FactoryPllWords {
        frequency_mhz: 500,
        pll1: 0x0005_0040,
        pll2: 0x0220,
    },
    Bm1385FactoryPllWords {
        frequency_mhz: 525,
        pll1: 0x0005_4040,
        pll2: 0x0220,
    },
    Bm1385FactoryPllWords {
        frequency_mhz: 550,
        pll1: 0x0005_8040,
        pll2: 0x0220,
    },
    Bm1385FactoryPllWords {
        frequency_mhz: 600,
        pll1: 0x0006_0040,
        pll2: 0x0220,
    },
];

pub fn bm1385_s7_factory_pll_words(frequency_mhz: u16) -> Option<Bm1385FactoryPllWords> {
    BM1385_S7_FACTORY_PLL_WORDS
        .iter()
        .copied()
        .find(|row| row.frequency_mhz == frequency_mhz)
}

/// Replay the jig's two-frame PLL write layout for a known factory-profile row.
///
/// The first `0x07` frame is unicast-shaped exactly as the held jig emits it;
/// only the second `0x02` frame receives the caller's recorded broadcast bit.
/// Unknown or zero profile frequencies refuse instead of inheriting the jig's
/// misleading 33 MHz lookup-miss fallback.
pub fn bm1385_s7_factory_pll_frames(
    chip_address: u8,
    frequency_mhz: u16,
    second_frame_broadcast: bool,
) -> Result<[[u8; BM1385_FIL_COMMAND_BYTES]; 2], Bm1385FilCommandError> {
    let row = bm1385_s7_factory_pll_words(frequency_mhz).ok_or(
        Bm1385FilCommandError::UnknownFactoryFrequency(frequency_mhz),
    )?;
    let pll1 = bm1385_fil_frame(
        CMD_SET_PLL,
        (row.pll1 >> 16) as u8,
        (row.pll1 >> 8) as u8,
        row.pll1 as u8,
    );
    let pll2_header = CMD_WRITE_REGISTER
        | if second_frame_broadcast {
            CMD_BROADCAST
        } else {
            0
        };
    let pll2 = bm1385_fil_frame(
        pll2_header,
        chip_address,
        (row.pll2 >> 8) as u8,
        row.pll2 as u8,
    );
    Ok([pll1, pll2])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385FilResponseIntegrity {
    /// The held nonce consumer applies no returned CRC check.
    NoReturnedCrc,
    /// Register response CRC5 matched over the first 35 bits.
    RegisterCrc5Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1385FilNonceResponse {
    pub raw: [u8; BM1385_FIL_RETURN_BYTES],
    pub nonce_be: u32,
    pub core_index: u8,
    pub work_id: u8,
    pub integrity: Bm1385FilResponseIntegrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1385FilRegisterResponse {
    pub raw: [u8; BM1385_FIL_RETURN_BYTES],
    pub register_value_be: u32,
    pub response_flags: u8,
    pub crc5: u8,
    pub integrity: Bm1385FilResponseIntegrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385FilResponse {
    Nonce(Bm1385FilNonceResponse),
    Register(Bm1385FilRegisterResponse),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385FilResponseError {
    WrongLength(usize),
    NonceCoreOutOfRange(u8),
    RegisterCrcMismatch { observed: u8, expected: u8 },
}

/// Decode one exact five-byte jig return. This does not bind the observation to
/// a dispatched job, a chain, a carrier, or a share target.
pub fn decode_bm1385_fil_response(
    bytes: &[u8],
) -> Result<Bm1385FilResponse, Bm1385FilResponseError> {
    if bytes.len() != BM1385_FIL_RETURN_BYTES {
        return Err(Bm1385FilResponseError::WrongLength(bytes.len()));
    }
    let mut raw = [0_u8; BM1385_FIL_RETURN_BYTES];
    raw.copy_from_slice(bytes);
    let value = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if raw[4] & BM1385_FIL_RETURN_KIND_MASK != 0 {
        let core_index = raw[3] & BM1385_FIL_NONCE_CORE_MASK;
        if core_index > BM1385_FIL_MAX_CORE_INDEX {
            return Err(Bm1385FilResponseError::NonceCoreOutOfRange(core_index));
        }
        return Ok(Bm1385FilResponse::Nonce(Bm1385FilNonceResponse {
            raw,
            nonce_be: value,
            core_index,
            work_id: raw[4] & BM1385_FIL_NONCE_WORK_ID_MASK,
            integrity: Bm1385FilResponseIntegrity::NoReturnedCrc,
        }));
    }

    let observed = raw[4] & BM1385_FIL_CRC_MASK;
    let expected = stock_bitmain_crc5(&raw, BM1385_FIL_REGISTER_RETURN_CRC_BITS);
    if observed != expected {
        return Err(Bm1385FilResponseError::RegisterCrcMismatch { observed, expected });
    }
    Ok(Bm1385FilResponse::Register(Bm1385FilRegisterResponse {
        raw,
        register_value_be: value,
        response_flags: raw[4] & !BM1385_FIL_CRC_MASK,
        crc5: observed,
        integrity: Bm1385FilResponseIntegrity::RegisterCrc5Verified,
    }))
}

/// The exact blockers that keep both factory profiles offline-only.
pub const BM1385_S7_RUNTIME_BLOCKERS: &[&str] = &[
    "exact S7/S7-LN control-board carrier identity",
    "passive enumeration capture bound to the carrier and 45/54-chip variant",
    "deployed FIL transport and response framing",
    "model-bound voltage-controller command/units/fault behavior",
    "external LM75A acquisition and independent thermal cutoff",
    "independent rail-off path",
    "known-work snapshot binding and share qualification",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1385S7Authority {
    device_io: bool,
    runtime_admission: bool,
    transport: bool,
    work_dispatch: bool,
    share_submission: bool,
    voltage_control: bool,
    thermal_control: bool,
    rail_power: bool,
    install: bool,
}

impl Bm1385S7Authority {
    pub const fn device_io(self) -> bool {
        self.device_io
    }
    pub const fn runtime_admission(self) -> bool {
        self.runtime_admission
    }
    pub const fn transport(self) -> bool {
        self.transport
    }
    pub const fn work_dispatch(self) -> bool {
        self.work_dispatch
    }
    pub const fn share_submission(self) -> bool {
        self.share_submission
    }
    pub const fn voltage_control(self) -> bool {
        self.voltage_control
    }
    pub const fn thermal_control(self) -> bool {
        self.thermal_control
    }
    pub const fn rail_power(self) -> bool {
        self.rail_power
    }
    pub const fn install(self) -> bool {
        self.install
    }
}

pub const BM1385_S7_AUTHORITY: Bm1385S7Authority = Bm1385S7Authority {
    device_io: false,
    runtime_admission: false,
    transport: false,
    work_dispatch: false,
    share_submission: false,
    voltage_control: false,
    thermal_control: false,
    rail_power: false,
    install: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1385S7AdmissionRefusal {
    OfflineEvidenceOnly,
}

/// Fail closed even when the caller selected one exact offline factory profile.
pub const fn refuse_bm1385_s7_runtime_admission(
    _variant: Bm1385S7FactoryVariant,
) -> Result<(), Bm1385S7AdmissionRefusal> {
    Err(Bm1385S7AdmissionRefusal::OfflineEvidenceOnly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1385_s7_exact_config_identities_are_pinned() {
        assert_eq!(BM1385_S7_45_CONFIG_SIZE, 2_055);
        assert_eq!(
            BM1385_S7_45_CONFIG_SHA256,
            "632abf407d5ea7f527f219322d3470ab9a1e2756b33dc0471ed1e01cc2b361c2"
        );
        assert_eq!(BM1385_S7_54_CONFIG_SIZE, 2_066);
        assert_eq!(
            BM1385_S7_54_CONFIG_SHA256,
            "7df112aef6246d376f6c02088ad1e9baeac72d8bbfd8b351232f56704baa1177"
        );
    }

    #[test]
    fn bm1385_s7_45_factory_profile_is_exact_and_self_consistent() {
        let profile = BM1385_S7_45_FACTORY_PROFILE;
        assert_eq!((profile.asic_count, profile.cores_per_asic), (45, 50));
        assert_eq!(profile.open_core_gap_raw, 50_000);
        assert_eq!(profile.frequencies_mhz, [600, 600, 600, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            profile.voltages_raw,
            [1_025, 1_050, 1_075, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(profile.valid_nonces, [18_000; 9]);
        assert_eq!(validate_bm1385_s7_factory_profile(&profile), Ok(()));
    }

    #[test]
    fn bm1385_s7_54_factory_profile_is_exact_and_self_consistent() {
        let profile = BM1385_S7_54_FACTORY_PROFILE;
        assert_eq!((profile.asic_count, profile.cores_per_asic), (54, 50));
        assert_eq!(profile.open_core_gap_raw, 100_000);
        assert_eq!(
            profile.frequencies_mhz,
            [500, 550, 525, 400, 400, 400, 400, 400, 400]
        );
        assert_eq!(profile.voltages_raw, [945, 975, 1_005, 0, 0, 0, 0, 0, 0]);
        assert_eq!(profile.valid_nonces, [21_600; 9]);
        assert_eq!(validate_bm1385_s7_factory_profile(&profile), Ok(()));
    }

    #[test]
    fn bm1385_s7_shared_temperature_pic_and_core_masks_stay_descriptive_only() {
        for profile in [BM1385_S7_45_FACTORY_PROFILE, BM1385_S7_54_FACTORY_PROFILE] {
            assert_eq!(
                profile.temperature_source,
                Bm1385S7TemperatureSource::ExternalLm75aIic
            );
            assert_eq!(profile.temperature_sensors_raw, [62, 0, 0, 0]);
            assert_eq!(
                (
                    profile.start_temperature_raw,
                    profile.target_temperature_raw,
                    profile.alarm_temperature_raw
                ),
                (75, 85, 85)
            );
            assert_eq!(
                profile.open_core_masks,
                [0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0x0003_ffff]
            );
            assert!(profile.pic_voltage);
            assert!(!profile.iic_pic);
            assert!(!profile.dac);
        }
    }

    #[test]
    fn bm1385_s7_profile_key_classification_is_exact_but_not_admission() {
        assert_eq!(
            classify_bm1385_s7_factory_profile_key(1_385, 45, 50, 1),
            Ok(Bm1385S7FactoryVariant::S7_45)
        );
        assert_eq!(
            classify_bm1385_s7_factory_profile_key(1_385, 54, 50, 1),
            Ok(Bm1385S7FactoryVariant::S7_54)
        );
        assert_eq!(
            classify_bm1385_s7_factory_profile_key(1_385, 46, 50, 1),
            Err(Bm1385S7ProfileError::UnknownAsicCount(46))
        );
        assert_eq!(
            refuse_bm1385_s7_runtime_admission(Bm1385S7FactoryVariant::S7_45),
            Err(Bm1385S7AdmissionRefusal::OfflineEvidenceOnly)
        );
    }

    #[test]
    fn bm1385_fil_command_frames_match_jig_crc27_goldens() {
        assert_eq!(bm1385_fil_chain_inactive_frame(), [0x85, 0x00, 0x00, 0x0f]);
        assert_eq!(bm1385_fil_set_address_frame(0x20), [0x01, 0x20, 0x00, 0x01]);
        assert_eq!(
            bm1385_fil_read_register_frame(0, 0x0c, false),
            [0x04, 0x00, 0x0c, 0x06]
        );
        assert_eq!(
            bm1385_fil_set_baud_frame(0, 26, true),
            Ok([0x86, 0x00, 0x1a, 0x1b])
        );
        assert_eq!(
            bm1385_fil_set_baud_frame(0, 27, true),
            Err(Bm1385FilCommandError::Bt8dAboveJigMaximum(27))
        );
    }

    #[test]
    fn bm1385_s7_factory_pll_frames_use_only_held_profile_rows() {
        assert_eq!(
            bm1385_s7_factory_pll_frames(0, 600, true),
            Ok([[0x07, 0x06, 0x00, 0x4d], [0x82, 0x00, 0x02, 0x20]])
        );
        assert_eq!(
            bm1385_s7_factory_pll_frames(0, 0, true),
            Err(Bm1385FilCommandError::UnknownFactoryFrequency(0))
        );
        assert_eq!(
            bm1385_s7_factory_pll_frames(0, 601, true),
            Err(Bm1385FilCommandError::UnknownFactoryFrequency(601))
        );
    }

    #[test]
    fn bm1385_register_return_requires_crc5_over_35_bits() {
        let decoded = decode_bm1385_fil_response(&[0x12, 0x34, 0x56, 0x78, 0x0e]);
        assert_eq!(
            decoded,
            Ok(Bm1385FilResponse::Register(Bm1385FilRegisterResponse {
                raw: [0x12, 0x34, 0x56, 0x78, 0x0e],
                register_value_be: 0x1234_5678,
                response_flags: 0,
                crc5: 0x0e,
                integrity: Bm1385FilResponseIntegrity::RegisterCrc5Verified,
            }))
        );
        assert!(matches!(
            decode_bm1385_fil_response(&[0x12, 0x34, 0x56, 0x78, 0x0f]),
            Err(Bm1385FilResponseError::RegisterCrcMismatch { .. })
        ));
    }

    #[test]
    fn bm1385_nonce_return_is_typed_without_inventing_crc_or_job_binding() {
        let decoded = decode_bm1385_fil_response(&[0x01, 0x02, 0x03, 0x2a, 0x87]);
        assert_eq!(
            decoded,
            Ok(Bm1385FilResponse::Nonce(Bm1385FilNonceResponse {
                raw: [0x01, 0x02, 0x03, 0x2a, 0x87],
                nonce_be: 0x0102_032a,
                core_index: 42,
                work_id: 7,
                integrity: Bm1385FilResponseIntegrity::NoReturnedCrc,
            }))
        );
        assert_eq!(
            decode_bm1385_fil_response(&[0, 0, 0, 50, 0x80]),
            Err(Bm1385FilResponseError::NonceCoreOutOfRange(50))
        );
        assert_eq!(
            decode_bm1385_fil_response(&[0; 4]),
            Err(Bm1385FilResponseError::WrongLength(4))
        );
    }

    #[test]
    fn bm1385_s7_authority_and_runtime_admission_remain_closed() {
        let authority = BM1385_S7_AUTHORITY;
        assert!(!authority.device_io());
        assert!(!authority.runtime_admission());
        assert!(!authority.transport());
        assert!(!authority.work_dispatch());
        assert!(!authority.share_submission());
        assert!(!authority.voltage_control());
        assert!(!authority.thermal_control());
        assert!(!authority.rail_power());
        assert!(!authority.install());
        assert_eq!(BM1385_S7_RUNTIME_BLOCKERS.len(), 7);
    }
}
