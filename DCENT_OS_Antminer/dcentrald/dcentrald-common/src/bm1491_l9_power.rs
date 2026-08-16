//! Pure replay of the exact held L9/BM1491 adjustable-power voltage wrappers.
//!
//! The stock layer accepts centivolts, converts each requested value to volts,
//! and delegates to the Bitmain PSU library. Direct writes propagate failure.
//! The stepped wrapper deliberately does not: it discards every per-write
//! result and reports success once its bounded arithmetic finishes. Nothing in
//! this module owns a PSU transport or authorizes a voltage mutation.

pub const BM1491_L9_SET_VOLTAGE_ADDRESS: u32 = 0x0008_9bcc;
pub const BM1491_L9_SET_VOLTAGE_BY_STEPS_ADDRESS: u32 = 0x0008_9da4;
pub const BM1491_L9_SET_WORKING_VOLTAGE_ADDRESS: u32 = 0x0008_a120;
pub const BM1491_L9_INTERNAL_PSU_WRITE_ADDRESS: u32 = 0x0008_8498;
pub const BM1491_L9_BITMAIN_SET_VOLTAGE_ADDRESS: u32 = 0x0016_4c48;
pub const BM1491_L9_CONVERT_V_TO_N_ADDRESS: u32 = 0x0016_5d10;
pub const BM1491_L9_CONVERT_V_TO_N_CALIBRATED_ADDRESS: u32 = 0x0016_554c;
pub const BM1491_L9_CONVERT_V_TO_N_DEFAULT_ADDRESS: u32 = 0x0016_579c;
pub const BM1491_L9_CONVERT_N_TO_V_DEFAULT_ADDRESS: u32 = 0x0016_7274;
pub const BM1491_L9_GET_CALIBRATION_DATA_ADDRESS: u32 = 0x0016_795c;
pub const BM1491_L9_POWER_CRC16_ADDRESS: u32 = 0x0018_8564;
pub const BM1491_L9_IS_POWER_PROTOCOL_V2_ADDRESS: u32 = 0x0016_66f4;
pub const BM1491_L9_LEGACY_SET_VOLTAGE_ADDRESS: u32 = 0x0015_fc04;
pub const BM1491_L9_LEGACY_SIM_TRANSPORT_ADDRESS: u32 = 0x0015_b020;
pub const BM1491_L9_LEGACY_IIC_TRANSPORT_ADDRESS: u32 = 0x0015_b388;
pub const BM1491_L9_LEGACY_RESPONSE_VALIDATOR_ADDRESS: u32 = 0x0015_a774;

pub const BM1491_L9_VOLTAGE_CENTIVOLTS_PER_VOLT: u32 = 100;
pub const BM1491_L9_VOLTAGE_WRITE_SETTLE_MS: u32 = 500;
pub const BM1491_L9_STEPPED_REQUEST_MAX: u32 = 100;
pub const BM1491_L9_STEPPED_REQUEST_DIVISOR: u32 = 10;
pub const BM1491_L9_WORKING_VOLTAGE_REQUESTED_STEP: u32 = 100;

pub const BM1491_L9_TOPOL_ADJUSTABLE_POWER: bool = true;
pub const BM1491_L9_TOPOL_PSU_FAMILY: &str = "APW17";
pub const BM1491_L9_TOPOL_SUPPORTED_POWER_VERSIONS: [u16; 2] = [193, 196];
pub const BM1491_L9_POWER_PROTOCOL_V2_VERSIONS: [u16; 5] = [98, 100, 101, 102, 26];
pub const BM1491_L9_LEGACY_SET_VOLTAGE_OPCODE: u8 = 0x83;
pub const BM1491_L9_LEGACY_FRAME_LENGTH: usize = 8;
pub const BM1491_L9_LEGACY_TRANSPORT_ERROR: u32 = 0x8000_0300;
pub const BM1491_L9_LEGACY_CODE_RANGE_ERROR: u32 = 0x8000_0301;
pub const BM1491_L9_LEGACY_TRANSPORT_ATTEMPTS: u8 = 3;
pub const BM1491_L9_LEGACY_WRITE_TO_READ_DELAY_MS: u32 = 400;
pub const BM1491_L9_LEGACY_POST_READ_DELAY_MS: u32 = 100;
pub const BM1491_L9_LEGACY_LOW_LEVEL_IO_RESULTS_IGNORED: bool = true;
pub const BM1491_L9_LEGACY_LOW_STATUS_SLOPE: f64 = f64::from_bits(0x4055_4000_0000_0000);
pub const BM1491_L9_LEGACY_LOW_STATUS_INTERCEPT: f64 = f64::from_bits(0x4093_ec00_0000_0000);
pub const BM1491_L9_LEGACY_HIGH_STATUS_SLOPE: f64 = f64::from_bits(0x4051_b555_5555_546b);
pub const BM1491_L9_LEGACY_HIGH_STATUS_INTERCEPT: f64 = f64::from_bits(0x4090_ef00_0000_0000);
pub const BM1491_L9_CALIBRATION_RESPONSE_LENGTH: usize = 32;
pub const BM1491_L9_CALIBRATION_CRC_COVERAGE: usize = 30;
pub const BM1491_L9_CALIBRATION_PREFIX_LENGTH: usize = 12;
pub const BM1491_L9_CALIBRATION_DELTA_START: usize = 14;
pub const BM1491_L9_CALIBRATION_MAX_DELTAS: usize = 14;
pub const BM1491_L9_CALIBRATION_MAX_POINTS: usize = 15;
pub const BM1491_L9_CALIBRATION_DELTA_TERMINATOR: u8 = 0x80;
pub const BM1491_L9_CALIBRATION_MILLIVOLTS_PER_VOLT: f64 = f64::from_bits(0x408f_4000_0000_0000);
pub const BM1491_L9_CALIBRATION_INTERVAL_TOLERANCE_V: f64 = f64::from_bits(0x3f50_624d_d2f1_a9fc);
pub const BM1491_L9_POWER_WIRE_FRAME_PROVEN: bool = true;
pub const BM1491_L9_POWER_TRANSPORT_PROVEN: bool = false;
pub const BM1491_L9_POWER_AUTHORIZES_IO: bool = false;
pub const BM1491_L9_POWER_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1491_L9_POWER_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PowerProtocol {
    Legacy,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9LegacyTransportRoute {
    I2cSim,
    IicRegister,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9VoltageCodeSource {
    CalibratedTable,
    VersionDefault,
}

/// Stock uses the calibrated interpolation table only when both the power-open
/// calibration fetch and the independently stored table-ready flag are true.
pub const fn bm1491_l9_voltage_code_source(
    calibration_fetch_succeeded: bool,
    calibration_table_ready: bool,
) -> Bm1491L9VoltageCodeSource {
    if calibration_fetch_succeeded && calibration_table_ready {
        Bm1491L9VoltageCodeSource::CalibratedTable
    } else {
        Bm1491L9VoltageCodeSource::VersionDefault
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9LegacyDefaultCurve {
    StatusErrorOrLowByteAtMostThree,
    StatusLowByteAboveThree,
}

pub const fn bm1491_l9_legacy_default_curve(power_status_word: u32) -> Bm1491L9LegacyDefaultCurve {
    if power_status_word == BM1491_L9_LEGACY_TRANSPORT_ERROR || power_status_word as u8 <= 3 {
        Bm1491L9LegacyDefaultCurve::StatusErrorOrLowByteAtMostThree
    } else {
        Bm1491L9LegacyDefaultCurve::StatusLowByteAboveThree
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9VoltageCodeError {
    NonFiniteVoltage,
    ConvertedCodeOutOfRange,
}

/// Reproduce the held versions 193/194/196 uncalibrated volts-to-code branch.
/// ARM `VCVT.S32.F64` truncates toward zero; the outer setter then admits only
/// `0..=255`. This clean helper makes both failure domains explicit.
pub fn bm1491_l9_legacy_default_voltage_code(
    voltage_v: f64,
    power_status_word: u32,
) -> Result<u8, Bm1491L9VoltageCodeError> {
    if !voltage_v.is_finite() {
        return Err(Bm1491L9VoltageCodeError::NonFiniteVoltage);
    }
    let (slope, intercept) = match bm1491_l9_legacy_default_curve(power_status_word) {
        Bm1491L9LegacyDefaultCurve::StatusErrorOrLowByteAtMostThree => (
            BM1491_L9_LEGACY_LOW_STATUS_SLOPE,
            BM1491_L9_LEGACY_LOW_STATUS_INTERCEPT,
        ),
        Bm1491L9LegacyDefaultCurve::StatusLowByteAboveThree => (
            BM1491_L9_LEGACY_HIGH_STATUS_SLOPE,
            BM1491_L9_LEGACY_HIGH_STATUS_INTERCEPT,
        ),
    };
    let raw = intercept - voltage_v * slope;
    if !raw.is_finite() || raw < f64::from(i32::MIN) || raw > f64::from(i32::MAX) {
        return Err(Bm1491L9VoltageCodeError::ConvertedCodeOutOfRange);
    }
    u8::try_from(raw.trunc() as i32).map_err(|_| Bm1491L9VoltageCodeError::ConvertedCodeOutOfRange)
}

/// Exact inverse used while the held legacy parser reconstructs its voltage
/// anchors from evenly spaced device codes.
pub fn bm1491_l9_legacy_default_code_voltage(code: u8, power_status_word: u32) -> f64 {
    let (slope, intercept) = match bm1491_l9_legacy_default_curve(power_status_word) {
        Bm1491L9LegacyDefaultCurve::StatusErrorOrLowByteAtMostThree => (
            BM1491_L9_LEGACY_LOW_STATUS_SLOPE,
            BM1491_L9_LEGACY_LOW_STATUS_INTERCEPT,
        ),
        Bm1491L9LegacyDefaultCurve::StatusLowByteAboveThree => (
            BM1491_L9_LEGACY_HIGH_STATUS_SLOPE,
            BM1491_L9_LEGACY_HIGH_STATUS_INTERCEPT,
        ),
    };
    (intercept - f64::from(code)) / slope
}

/// Exact table-backed CRC used over bytes `0..30` of the calibration record.
/// This bitwise form is equivalent to the held binary's two-table Modbus
/// implementation and keeps the polynomial and initial value explicit.
pub fn bm1491_l9_power_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1491L9VoltageCalibrationPoint {
    pub code: u8,
    pub voltage_v: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bm1491L9VoltageCalibrationTable {
    raw_identity_prefix: [u8; BM1491_L9_CALIBRATION_PREFIX_LENGTH],
    points: Vec<Bm1491L9VoltageCalibrationPoint>,
    response_crc: u16,
}

impl Bm1491L9VoltageCalibrationTable {
    pub const fn raw_identity_prefix(&self) -> &[u8; BM1491_L9_CALIBRATION_PREFIX_LENGTH] {
        &self.raw_identity_prefix
    }

    pub fn points(&self) -> &[Bm1491L9VoltageCalibrationPoint] {
        &self.points
    }

    pub const fn response_crc(&self) -> u16 {
        self.response_crc
    }

    pub const fn proves_device_identity(&self) -> bool {
        false
    }

    pub const fn authorizes_voltage_io(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9CalibrationError {
    ResponseLength,
    CrcMismatch,
    TooFewPoints,
    NonMonotonicVoltagePoints,
    NonFiniteVoltage,
    OutsideCalibratedRange,
    ConvertedCodeOutOfRange,
}

fn bm1491_l9_evenly_spaced_legacy_codes(count: usize) -> Option<Vec<u8>> {
    if !(2..=BM1491_L9_CALIBRATION_MAX_POINTS).contains(&count) {
        return None;
    }
    let step = 255.0 / (count - 1) as f64;
    Some(
        (0..count)
            .map(|index| (index as f64 * step).round() as u8)
            .collect(),
    )
}

fn bm1491_l9_points_are_strictly_monotonic(points: &[Bm1491L9VoltageCalibrationPoint]) -> bool {
    let Some([first, second]) = points.get(0..2) else {
        return false;
    };
    if !first.voltage_v.is_finite()
        || !second.voltage_v.is_finite()
        || first.voltage_v == second.voltage_v
    {
        return false;
    }
    let ascending = first.voltage_v < second.voltage_v;
    points.windows(2).all(|pair| {
        pair[0].voltage_v.is_finite()
            && pair[1].voltage_v.is_finite()
            && if ascending {
                pair[0].voltage_v < pair[1].voltage_v
            } else {
                pair[0].voltage_v > pair[1].voltage_v
            }
    })
}

/// Decode the exact held legacy 32-byte calibration response into the table
/// consumed by `bitmain_convert_V_to_N_calibration`.
///
/// Stock verifies the CRC, creates 2--15 evenly spaced codes, derives each
/// default voltage, then applies one signed big-endian millivolt base offset
/// and cumulative signed-byte millivolt deltas until byte `0x80`. The clean
/// parser additionally refuses non-monotonic tables instead of allowing a
/// divide-by-zero or ambiguous first-match interpolation.
pub fn bm1491_l9_parse_legacy_voltage_calibration(
    response: &[u8],
    power_status_word: u32,
) -> Result<Bm1491L9VoltageCalibrationTable, Bm1491L9CalibrationError> {
    if response.len() != BM1491_L9_CALIBRATION_RESPONSE_LENGTH {
        return Err(Bm1491L9CalibrationError::ResponseLength);
    }
    let computed_crc = bm1491_l9_power_crc16(&response[..BM1491_L9_CALIBRATION_CRC_COVERAGE]);
    let response_crc = u16::from_be_bytes([
        response[BM1491_L9_CALIBRATION_CRC_COVERAGE],
        response[BM1491_L9_CALIBRATION_CRC_COVERAGE + 1],
    ]);
    if computed_crc != response_crc {
        return Err(Bm1491L9CalibrationError::CrcMismatch);
    }

    let deltas = &response[BM1491_L9_CALIBRATION_DELTA_START
        ..BM1491_L9_CALIBRATION_DELTA_START + BM1491_L9_CALIBRATION_MAX_DELTAS];
    let delta_count = deltas
        .iter()
        .position(|&byte| byte == BM1491_L9_CALIBRATION_DELTA_TERMINATOR)
        .unwrap_or(BM1491_L9_CALIBRATION_MAX_DELTAS);
    let point_count = delta_count + 1;
    let codes = bm1491_l9_evenly_spaced_legacy_codes(point_count)
        .ok_or(Bm1491L9CalibrationError::TooFewPoints)?;
    let mut cumulative_offset_mv = i32::from(i16::from_be_bytes([response[12], response[13]]));
    let mut points = Vec::with_capacity(point_count);
    points.push(Bm1491L9VoltageCalibrationPoint {
        code: codes[0],
        voltage_v: bm1491_l9_legacy_default_code_voltage(codes[0], power_status_word)
            + f64::from(cumulative_offset_mv) / BM1491_L9_CALIBRATION_MILLIVOLTS_PER_VOLT,
    });
    for (index, &delta) in deltas[..delta_count].iter().enumerate() {
        cumulative_offset_mv += i32::from(delta as i8);
        let code = codes[index + 1];
        points.push(Bm1491L9VoltageCalibrationPoint {
            code,
            voltage_v: bm1491_l9_legacy_default_code_voltage(code, power_status_word)
                + f64::from(cumulative_offset_mv) / BM1491_L9_CALIBRATION_MILLIVOLTS_PER_VOLT,
        });
    }
    if !bm1491_l9_points_are_strictly_monotonic(&points) {
        return Err(Bm1491L9CalibrationError::NonMonotonicVoltagePoints);
    }

    let mut raw_identity_prefix = [0; BM1491_L9_CALIBRATION_PREFIX_LENGTH];
    raw_identity_prefix.copy_from_slice(&response[..BM1491_L9_CALIBRATION_PREFIX_LENGTH]);
    Ok(Bm1491L9VoltageCalibrationTable {
        raw_identity_prefix,
        points,
        response_crc,
    })
}

/// Reproduce the exact calibrated table interpolation and `round(3)` result.
/// Both ascending and descending point order are supported, matching stock's
/// paired interval predicates. Each interval uses strict comparisons against
/// endpoints expanded by exactly one millivolt.
pub fn bm1491_l9_calibrated_voltage_code(
    table: &Bm1491L9VoltageCalibrationTable,
    voltage_v: f64,
) -> Result<u8, Bm1491L9CalibrationError> {
    if !voltage_v.is_finite() {
        return Err(Bm1491L9CalibrationError::NonFiniteVoltage);
    }
    for pair in table.points.windows(2) {
        let first = pair[0];
        let second = pair[1];
        let within = if first.voltage_v < second.voltage_v {
            voltage_v > first.voltage_v - BM1491_L9_CALIBRATION_INTERVAL_TOLERANCE_V
                && voltage_v < second.voltage_v + BM1491_L9_CALIBRATION_INTERVAL_TOLERANCE_V
        } else {
            voltage_v < first.voltage_v + BM1491_L9_CALIBRATION_INTERVAL_TOLERANCE_V
                && voltage_v > second.voltage_v - BM1491_L9_CALIBRATION_INTERVAL_TOLERANCE_V
        };
        if !within {
            continue;
        }
        let slope = f64::from(i32::from(second.code) - i32::from(first.code))
            / (second.voltage_v - first.voltage_v);
        let raw = slope * (voltage_v - first.voltage_v) + f64::from(first.code);
        if !raw.is_finite() || raw < f64::from(i32::MIN) || raw > f64::from(i32::MAX) {
            return Err(Bm1491L9CalibrationError::ConvertedCodeOutOfRange);
        }
        return u8::try_from(raw.round() as i32)
            .map_err(|_| Bm1491L9CalibrationError::ConvertedCodeOutOfRange);
    }
    Err(Bm1491L9CalibrationError::OutsideCalibratedRange)
}

/// The stock setter reserves handle `0xff` for the i2c-simulation primitive;
/// every other handle goes through the register-IIC helpers.
pub const fn bm1491_l9_legacy_transport_route(handle: u32) -> Bm1491L9LegacyTransportRoute {
    if handle == 0xff {
        Bm1491L9LegacyTransportRoute::I2cSim
    } else {
        Bm1491L9LegacyTransportRoute::IicRegister
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9LegacyTransportContract {
    pub route: Bm1491L9LegacyTransportRoute,
    pub attempts: u8,
    pub write_to_read_delay_ms: u32,
    pub post_read_delay_ms: u32,
    pub mutex_held_across_all_attempts: bool,
    pub low_level_io_results_ignored: bool,
}

impl Bm1491L9LegacyTransportContract {
    pub const fn admits_transport_io(&self) -> bool {
        false
    }
}

pub const fn bm1491_l9_legacy_transport_contract(handle: u32) -> Bm1491L9LegacyTransportContract {
    Bm1491L9LegacyTransportContract {
        route: bm1491_l9_legacy_transport_route(handle),
        attempts: BM1491_L9_LEGACY_TRANSPORT_ATTEMPTS,
        write_to_read_delay_ms: BM1491_L9_LEGACY_WRITE_TO_READ_DELAY_MS,
        post_read_delay_ms: BM1491_L9_LEGACY_POST_READ_DELAY_MS,
        mutex_held_across_all_attempts: true,
        low_level_io_results_ignored: BM1491_L9_LEGACY_LOW_LEVEL_IO_RESULTS_IGNORED,
    }
}

/// Reproduce `is_power_protocal_v2` for the recovered runtime power version.
/// The two versions admitted by the held L9 topology both select `Legacy`.
pub const fn bm1491_l9_power_protocol(version: u16) -> Bm1491L9PowerProtocol {
    match version {
        98 | 100 | 101 | 102 | 26 => Bm1491L9PowerProtocol::V2,
        _ => Bm1491L9PowerProtocol::Legacy,
    }
}

/// Build the exact eight-byte legacy APW17 set-voltage request emitted by
/// `FUN_0015fc04`. The device-code conversion/calibration that supplies `code`
/// is deliberately outside this byte-level contract.
pub const fn bm1491_l9_legacy_set_voltage_frame(code: u8) -> [u8; BM1491_L9_LEGACY_FRAME_LENGTH] {
    let checksum = 0x06u16 + BM1491_L9_LEGACY_SET_VOLTAGE_OPCODE as u16 + code as u16;
    [
        0x55,
        0xaa,
        0x06,
        BM1491_L9_LEGACY_SET_VOLTAGE_OPCODE,
        code,
        0x00,
        checksum as u8,
        (checksum >> 8) as u8,
    ]
}

/// Replay the return value of the legacy setter after its lower transport
/// helper reports success. The setter itself extracts bytes four and five as
/// little-endian and performs no additional validation at this layer.
pub const fn bm1491_l9_legacy_set_voltage_return(
    transport_status: i32,
    response: [u8; BM1491_L9_LEGACY_FRAME_LENGTH],
) -> u32 {
    if transport_status == 0 {
        u16::from_le_bytes([response[4], response[5]]) as u32
    } else {
        BM1491_L9_LEGACY_TRANSPORT_ERROR
    }
}

/// Reproduce the shared response validator for the fixed eight-byte legacy
/// set-voltage exchange. The response checksum covers bytes 2 through 5 and is
/// stored little-endian in bytes 6 and 7. Stock also requires the two-byte
/// prefix and opcode to match the request and `response[2] + 2 == 8`.
pub const fn bm1491_l9_legacy_set_voltage_response_valid(
    request: [u8; BM1491_L9_LEGACY_FRAME_LENGTH],
    response: [u8; BM1491_L9_LEGACY_FRAME_LENGTH],
) -> bool {
    let sum = response[2] as u16 + response[3] as u16 + response[4] as u16 + response[5] as u16;
    let expected = u16::from_le_bytes([response[6], response[7]]);
    sum == expected
        && request[0] == response[0]
        && request[1] == response[1]
        && request[3] == response[3]
        && response[2] as usize + 2 == BM1491_L9_LEGACY_FRAME_LENGTH
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9VoltagePlanError {
    PowerNotInitialized,
    ZeroEffectiveStepWouldNotTerminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9SteppedVoltagePlan {
    pub current_cv: u16,
    pub target_cv: u16,
    pub requested_step: u32,
    pub effective_step_cv: u16,
    pub write_targets_cv: Vec<u16>,
    pub stock_discards_every_write_result: bool,
    pub stock_return_status: i32,
}

impl Bm1491L9SteppedVoltagePlan {
    pub const fn admits_voltage_io(&self) -> bool {
        false
    }
}

/// Reproduce `set_voltage_by_steps` target generation.
///
/// Stock clamps the caller's step to 100, then integer-divides it by ten.
/// Consequently the normal caller value 100 emits 10-centivolt increments.
/// A nonzero delta with a requested step below ten would never make progress;
/// clean replay refuses that input instead of emulating the infinite loop.
pub fn bm1491_l9_plan_stepped_voltage(
    power_initialized: bool,
    current_cv: u16,
    target_cv: u16,
    requested_step: u32,
) -> Result<Bm1491L9SteppedVoltagePlan, Bm1491L9VoltagePlanError> {
    if !power_initialized {
        return Err(Bm1491L9VoltagePlanError::PowerNotInitialized);
    }
    let effective_step =
        requested_step.min(BM1491_L9_STEPPED_REQUEST_MAX) / BM1491_L9_STEPPED_REQUEST_DIVISOR;
    if current_cv != target_cv && effective_step == 0 {
        return Err(Bm1491L9VoltagePlanError::ZeroEffectiveStepWouldNotTerminate);
    }

    let mut cursor = i32::from(current_cv);
    let target = i32::from(target_cv);
    let signed_step = if target < cursor {
        -(effective_step as i32)
    } else {
        effective_step as i32
    };
    let mut remaining = target - cursor;
    let mut writes = Vec::new();
    while remaining.unsigned_abs() > signed_step.unsigned_abs() {
        cursor += signed_step;
        remaining -= signed_step;
        writes.push(cursor as u16);
    }
    if cursor != target {
        writes.push(target_cv);
    }

    Ok(Bm1491L9SteppedVoltagePlan {
        current_cv,
        target_cv,
        requested_step,
        effective_step_cv: effective_step as u16,
        write_targets_cv: writes,
        stock_discards_every_write_result: true,
        stock_return_status: 0,
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1491L9DirectVoltageObservation {
    pub requested_cv: u16,
    pub requested_voltage_v: f64,
    pub psu_result: i32,
    pub stock_status: i32,
    pub settle_delay_ms: Option<u32>,
    pub shadow_current_cv: u16,
    pub shadow_previous_cv: u16,
}

/// Replay one internal PSU write. Any negative PSU result is normalized to
/// stock status `-1`; nonnegative results wait 500 ms, set both software
/// voltage shadows to the request, and return zero.
pub fn bm1491_l9_replay_direct_voltage_write(
    power_initialized: bool,
    requested_cv: u16,
    psu_result: i32,
    previous_shadow_current_cv: u16,
    previous_shadow_previous_cv: u16,
) -> Result<Bm1491L9DirectVoltageObservation, Bm1491L9VoltagePlanError> {
    if !power_initialized {
        return Err(Bm1491L9VoltagePlanError::PowerNotInitialized);
    }
    let accepted = psu_result >= 0;
    Ok(Bm1491L9DirectVoltageObservation {
        requested_cv,
        requested_voltage_v: f64::from(requested_cv)
            / f64::from(BM1491_L9_VOLTAGE_CENTIVOLTS_PER_VOLT),
        psu_result,
        stock_status: if accepted { 0 } else { -1 },
        settle_delay_ms: accepted.then_some(BM1491_L9_VOLTAGE_WRITE_SETTLE_MS),
        shadow_current_cv: if accepted {
            requested_cv
        } else {
            previous_shadow_current_cv
        },
        shadow_previous_cv: if accepted {
            requested_cv
        } else {
            previous_shadow_previous_cv
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SteppedVoltageReplayError {
    ResultCountMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9SteppedVoltageObservation {
    pub attempted_writes: usize,
    pub failed_writes: usize,
    pub final_shadow_current_cv: u16,
    pub final_shadow_previous_cv: u16,
    pub stock_status: i32,
}

impl Bm1491L9SteppedVoltageObservation {
    pub const fn proves_electrical_voltage(&self) -> bool {
        false
    }
}

/// Replay the stock result-discard weakness across an already-built ramp.
/// Successful underlying calls update both software shadows; failed calls do
/// not, but the stepped wrapper still returns zero after the final attempt.
pub fn bm1491_l9_replay_stepped_voltage_results(
    plan: &Bm1491L9SteppedVoltagePlan,
    psu_results: &[i32],
    initial_shadow_current_cv: u16,
    initial_shadow_previous_cv: u16,
) -> Result<Bm1491L9SteppedVoltageObservation, Bm1491L9SteppedVoltageReplayError> {
    if psu_results.len() != plan.write_targets_cv.len() {
        return Err(Bm1491L9SteppedVoltageReplayError::ResultCountMismatch);
    }
    let mut current_shadow = initial_shadow_current_cv;
    let mut previous_shadow = initial_shadow_previous_cv;
    let mut failed_writes = 0;
    for (&target, &result) in plan.write_targets_cv.iter().zip(psu_results) {
        if result < 0 {
            failed_writes += 1;
        } else {
            current_shadow = target;
            previous_shadow = target;
        }
    }
    Ok(Bm1491L9SteppedVoltageObservation {
        attempted_writes: psu_results.len(),
        failed_writes,
        final_shadow_current_cv: current_shadow,
        final_shadow_previous_cv: previous_shadow,
        stock_status: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calibration_response(base_offset_mv: i16, deltas: &[i8]) -> [u8; 32] {
        assert!(deltas.len() < BM1491_L9_CALIBRATION_MAX_DELTAS);
        let mut response = [0u8; BM1491_L9_CALIBRATION_RESPONSE_LENGTH];
        for (index, byte) in response[..BM1491_L9_CALIBRATION_PREFIX_LENGTH]
            .iter_mut()
            .enumerate()
        {
            *byte = index as u8;
        }
        response[12..14].copy_from_slice(&base_offset_mv.to_be_bytes());
        for (index, &delta) in deltas.iter().enumerate() {
            response[BM1491_L9_CALIBRATION_DELTA_START + index] = delta as u8;
        }
        response[BM1491_L9_CALIBRATION_DELTA_START + deltas.len()] =
            BM1491_L9_CALIBRATION_DELTA_TERMINATOR;
        let crc = bm1491_l9_power_crc16(&response[..BM1491_L9_CALIBRATION_CRC_COVERAGE]);
        response[BM1491_L9_CALIBRATION_CRC_COVERAGE..].copy_from_slice(&crc.to_be_bytes());
        response
    }

    #[test]
    fn normal_working_voltage_step_becomes_ten_centivolts() {
        let plan = bm1491_l9_plan_stepped_voltage(true, 1200, 1255, 100).expect("bounded ramp");
        assert_eq!(plan.effective_step_cv, 10);
        assert_eq!(plan.write_targets_cv, [1210, 1220, 1230, 1240, 1250, 1255]);
        assert_eq!(plan.stock_return_status, 0);
        assert!(plan.stock_discards_every_write_result);
        assert!(!plan.admits_voltage_io());
    }

    #[test]
    fn descending_ramp_and_exact_step_boundary_are_pinned() {
        let descending =
            bm1491_l9_plan_stepped_voltage(true, 1255, 1200, 100).expect("bounded ramp");
        assert_eq!(
            descending.write_targets_cv,
            [1245, 1235, 1225, 1215, 1205, 1200]
        );
        let exact = bm1491_l9_plan_stepped_voltage(true, 1200, 1210, 100).expect("one write");
        assert_eq!(exact.write_targets_cv, [1210]);
    }

    #[test]
    fn step_clamp_noop_and_nonprogress_refusal_are_exact() {
        let clamped = bm1491_l9_plan_stepped_voltage(true, 1200, 1221, 999).expect("clamped");
        assert_eq!(clamped.effective_step_cv, 10);
        assert_eq!(clamped.write_targets_cv, [1210, 1220, 1221]);
        let noop = bm1491_l9_plan_stepped_voltage(true, 1200, 1200, 0).expect("stock no-op");
        assert!(noop.write_targets_cv.is_empty());
        assert_eq!(
            bm1491_l9_plan_stepped_voltage(true, 1200, 1201, 9),
            Err(Bm1491L9VoltagePlanError::ZeroEffectiveStepWouldNotTerminate)
        );
    }

    #[test]
    fn direct_write_converts_centivolts_and_updates_shadows_only_on_success() {
        let success =
            bm1491_l9_replay_direct_voltage_write(true, 1250, 0, 1200, 1190).expect("initialized");
        assert_eq!(success.requested_voltage_v, 12.5);
        assert_eq!(success.stock_status, 0);
        assert_eq!(success.settle_delay_ms, Some(500));
        assert_eq!(
            (success.shadow_current_cv, success.shadow_previous_cv),
            (1250, 1250)
        );

        let failure =
            bm1491_l9_replay_direct_voltage_write(true, 1250, -7, 1200, 1190).expect("initialized");
        assert_eq!(failure.stock_status, -1);
        assert_eq!(failure.settle_delay_ms, None);
        assert_eq!(
            (failure.shadow_current_cv, failure.shadow_previous_cv),
            (1200, 1190)
        );
    }

    #[test]
    fn stepped_wrapper_ignores_failed_writes_but_shadows_track_only_successes() {
        let plan = bm1491_l9_plan_stepped_voltage(true, 1200, 1225, 100).expect("bounded ramp");
        let observed = bm1491_l9_replay_stepped_voltage_results(&plan, &[0, -7, 3], 1200, 1190)
            .expect("one result per attempt");
        assert_eq!(observed.attempted_writes, 3);
        assert_eq!(observed.failed_writes, 1);
        assert_eq!(
            (
                observed.final_shadow_current_cv,
                observed.final_shadow_previous_cv
            ),
            (1225, 1225)
        );
        assert_eq!(observed.stock_status, 0);
        assert!(!observed.proves_electrical_voltage());
    }

    #[test]
    fn initialization_result_count_and_authority_fail_closed() {
        assert_eq!(
            bm1491_l9_plan_stepped_voltage(false, 1200, 1210, 100),
            Err(Bm1491L9VoltagePlanError::PowerNotInitialized)
        );
        assert_eq!(
            bm1491_l9_replay_direct_voltage_write(false, 1200, 0, 0, 0),
            Err(Bm1491L9VoltagePlanError::PowerNotInitialized)
        );
        let plan = bm1491_l9_plan_stepped_voltage(true, 1200, 1210, 100).expect("one write");
        assert_eq!(
            bm1491_l9_replay_stepped_voltage_results(&plan, &[], 1200, 1200),
            Err(Bm1491L9SteppedVoltageReplayError::ResultCountMismatch)
        );
        assert!(BM1491_L9_TOPOL_ADJUSTABLE_POWER);
        assert_eq!(BM1491_L9_TOPOL_PSU_FAMILY, "APW17");
        assert!(BM1491_L9_POWER_WIRE_FRAME_PROVEN);
        assert!(!BM1491_L9_POWER_TRANSPORT_PROVEN);
        assert!(!BM1491_L9_POWER_AUTHORIZES_IO);
        assert!(!BM1491_L9_POWER_AUTHORIZES_RAIL_MUTATION);
        assert!(!BM1491_L9_POWER_AUTHORIZES_MINING);
    }

    #[test]
    fn held_power_versions_select_legacy_while_exact_v2_set_is_pinned() {
        for version in BM1491_L9_TOPOL_SUPPORTED_POWER_VERSIONS {
            assert_eq!(
                bm1491_l9_power_protocol(version),
                Bm1491L9PowerProtocol::Legacy
            );
        }
        for version in BM1491_L9_POWER_PROTOCOL_V2_VERSIONS {
            assert_eq!(bm1491_l9_power_protocol(version), Bm1491L9PowerProtocol::V2);
        }
        assert_eq!(
            bm1491_l9_power_protocol(0x100),
            Bm1491L9PowerProtocol::Legacy
        );
    }

    #[test]
    fn legacy_voltage_frames_pin_checksum_width_and_byte_order() {
        assert_eq!(
            bm1491_l9_legacy_set_voltage_frame(0),
            [0x55, 0xaa, 0x06, 0x83, 0x00, 0x00, 0x89, 0x00]
        );
        assert_eq!(
            bm1491_l9_legacy_set_voltage_frame(0x7f),
            [0x55, 0xaa, 0x06, 0x83, 0x7f, 0x00, 0x08, 0x01]
        );
        assert_eq!(
            bm1491_l9_legacy_set_voltage_frame(0xff),
            [0x55, 0xaa, 0x06, 0x83, 0xff, 0x00, 0x88, 0x01]
        );
    }

    #[test]
    fn legacy_setter_return_is_transport_gated_and_little_endian() {
        let response = [0xde, 0xad, 0xbe, 0xef, 0x34, 0x12, 0xaa, 0x55];
        assert_eq!(bm1491_l9_legacy_set_voltage_return(0, response), 0x1234);
        assert_eq!(
            bm1491_l9_legacy_set_voltage_return(-1, response),
            BM1491_L9_LEGACY_TRANSPORT_ERROR
        );
        assert_eq!(BM1491_L9_LEGACY_CODE_RANGE_ERROR, 0x8000_0301);
    }

    #[test]
    fn legacy_transport_routes_are_exact_and_never_authorize_io() {
        let simulated = bm1491_l9_legacy_transport_contract(0xff);
        assert_eq!(simulated.route, Bm1491L9LegacyTransportRoute::I2cSim);
        assert_eq!(simulated.attempts, 3);
        assert_eq!(simulated.write_to_read_delay_ms, 400);
        assert_eq!(simulated.post_read_delay_ms, 100);
        assert!(simulated.mutex_held_across_all_attempts);
        assert!(simulated.low_level_io_results_ignored);
        assert!(!simulated.admits_transport_io());

        assert_eq!(
            bm1491_l9_legacy_transport_route(0xfe),
            Bm1491L9LegacyTransportRoute::IicRegister
        );
        assert_eq!(
            bm1491_l9_legacy_transport_route(0x100),
            Bm1491L9LegacyTransportRoute::IicRegister
        );
    }

    #[test]
    fn legacy_response_validator_accepts_exact_header_length_opcode_and_checksum() {
        let request = bm1491_l9_legacy_set_voltage_frame(0x7f);
        let response = [0x55, 0xaa, 0x06, 0x83, 0x34, 0x12, 0xcf, 0x00];
        assert!(bm1491_l9_legacy_set_voltage_response_valid(
            request, response
        ));
        assert_eq!(bm1491_l9_legacy_set_voltage_return(0, response), 0x1234);
    }

    #[test]
    fn legacy_response_validator_rejects_each_checked_field_but_not_payload_semantics() {
        let request = bm1491_l9_legacy_set_voltage_frame(0x7f);
        let valid = [0x55, 0xaa, 0x06, 0x83, 0x34, 0x12, 0xcf, 0x00];
        for index in [0usize, 1, 2, 3, 6] {
            let mut malformed = valid;
            malformed[index] ^= 1;
            assert!(!bm1491_l9_legacy_set_voltage_response_valid(
                request, malformed
            ));
        }

        let payload = [0x55, 0xaa, 0x06, 0x83, 0xfe, 0xca, 0x51, 0x02];
        assert!(bm1491_l9_legacy_set_voltage_response_valid(
            request, payload
        ));
        assert_eq!(bm1491_l9_legacy_set_voltage_return(0, payload), 0xcafe);
    }

    #[test]
    fn voltage_code_source_requires_both_independent_calibration_flags() {
        assert_eq!(
            bm1491_l9_voltage_code_source(true, true),
            Bm1491L9VoltageCodeSource::CalibratedTable
        );
        for flags in [(false, false), (false, true), (true, false)] {
            assert_eq!(
                bm1491_l9_voltage_code_source(flags.0, flags.1),
                Bm1491L9VoltageCodeSource::VersionDefault
            );
        }
    }

    #[test]
    fn held_legacy_default_curves_pin_status_selection_and_exact_goldens() {
        assert_eq!(
            bm1491_l9_legacy_default_curve(BM1491_L9_LEGACY_TRANSPORT_ERROR),
            Bm1491L9LegacyDefaultCurve::StatusErrorOrLowByteAtMostThree
        );
        assert_eq!(
            bm1491_l9_legacy_default_curve(0x0103),
            Bm1491L9LegacyDefaultCurve::StatusErrorOrLowByteAtMostThree
        );
        assert_eq!(
            bm1491_l9_legacy_default_curve(0x0104),
            Bm1491L9LegacyDefaultCurve::StatusLowByteAboveThree
        );

        assert_eq!(bm1491_l9_legacy_default_voltage_code(12.0, 3), Ok(255));
        assert_eq!(bm1491_l9_legacy_default_voltage_code(14.5, 3), Ok(42));
        assert_eq!(bm1491_l9_legacy_default_voltage_code(15.0, 3), Ok(0));
        assert_eq!(bm1491_l9_legacy_default_voltage_code(12.0, 4), Ok(233));
        assert_eq!(bm1491_l9_legacy_default_voltage_code(14.5, 4), Ok(56));
        assert_eq!(bm1491_l9_legacy_default_voltage_code(15.0, 4), Ok(21));
    }

    #[test]
    fn held_legacy_default_converter_refuses_nonfinite_and_out_of_byte_range() {
        for voltage in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                bm1491_l9_legacy_default_voltage_code(voltage, 3),
                Err(Bm1491L9VoltageCodeError::NonFiniteVoltage)
            );
        }
        assert_eq!(
            bm1491_l9_legacy_default_voltage_code(11.98, 3),
            Err(Bm1491L9VoltageCodeError::ConvertedCodeOutOfRange)
        );
        assert_eq!(
            bm1491_l9_legacy_default_voltage_code(15.02, 3),
            Err(Bm1491L9VoltageCodeError::ConvertedCodeOutOfRange)
        );
    }

    #[test]
    fn calibration_crc_is_modbus_with_big_endian_record_storage() {
        assert_eq!(bm1491_l9_power_crc16(b"123456789"), 0x4b37);
        let response = calibration_response(100, &[10, -20, 0]);
        assert_eq!(
            u16::from_be_bytes([response[30], response[31]]),
            bm1491_l9_power_crc16(&response[..30])
        );
    }

    #[test]
    fn held_legacy_calibration_response_reconstructs_exact_codes_and_offsets() {
        let response = calibration_response(100, &[10, -20, 0]);
        let table = bm1491_l9_parse_legacy_voltage_calibration(&response, 3)
            .expect("valid held-format calibration");
        assert_eq!(
            table.raw_identity_prefix(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
        assert_eq!(
            table.response_crc(),
            u16::from_be_bytes([response[30], response[31]])
        );
        assert_eq!(
            table.points(),
            [
                Bm1491L9VoltageCalibrationPoint {
                    code: 0,
                    voltage_v: 15.1,
                },
                Bm1491L9VoltageCalibrationPoint {
                    code: 85,
                    voltage_v: 14.11,
                },
                Bm1491L9VoltageCalibrationPoint {
                    code: 170,
                    voltage_v: 13.09,
                },
                Bm1491L9VoltageCalibrationPoint {
                    code: 255,
                    voltage_v: 12.09,
                },
            ]
        );
        assert!(!table.proves_device_identity());
        assert!(!table.authorizes_voltage_io());
    }

    #[test]
    fn calibration_parser_rejects_length_crc_and_one_point_records() {
        let response = calibration_response(0, &[0]);
        assert_eq!(
            bm1491_l9_parse_legacy_voltage_calibration(&response[..31], 3),
            Err(Bm1491L9CalibrationError::ResponseLength)
        );
        let mut corrupt = response;
        corrupt[20] ^= 1;
        assert_eq!(
            bm1491_l9_parse_legacy_voltage_calibration(&corrupt, 3),
            Err(Bm1491L9CalibrationError::CrcMismatch)
        );
        let one_point = calibration_response(0, &[]);
        assert_eq!(
            bm1491_l9_parse_legacy_voltage_calibration(&one_point, 3),
            Err(Bm1491L9CalibrationError::TooFewPoints)
        );
    }

    #[test]
    fn calibration_parser_accepts_stock_fifteen_point_no_terminator_boundary() {
        let mut response = [0u8; BM1491_L9_CALIBRATION_RESPONSE_LENGTH];
        let crc = bm1491_l9_power_crc16(&response[..BM1491_L9_CALIBRATION_CRC_COVERAGE]);
        response[BM1491_L9_CALIBRATION_CRC_COVERAGE..].copy_from_slice(&crc.to_be_bytes());
        let table = bm1491_l9_parse_legacy_voltage_calibration(&response, 3)
            .expect("no terminator means the exact fifteen-point maximum");
        assert_eq!(table.points().len(), BM1491_L9_CALIBRATION_MAX_POINTS);
        assert_eq!(table.points().first().map(|point| point.code), Some(0));
        assert_eq!(table.points().last().map(|point| point.code), Some(255));
        assert_eq!(
            table.points().first().map(|point| point.voltage_v),
            Some(15.0)
        );
        assert_eq!(
            table.points().last().map(|point| point.voltage_v),
            Some(12.0)
        );
    }

    #[test]
    fn calibrated_interpolation_supports_descending_points_and_strict_tolerance() {
        let response = calibration_response(100, &[10, -20, 0]);
        let table = bm1491_l9_parse_legacy_voltage_calibration(&response, 3)
            .expect("valid held-format calibration");
        assert_eq!(bm1491_l9_calibrated_voltage_code(&table, 14.11), Ok(85));
        assert_eq!(bm1491_l9_calibrated_voltage_code(&table, 15.1005), Ok(0));
        assert_eq!(
            bm1491_l9_calibrated_voltage_code(&table, 15.1011),
            Err(Bm1491L9CalibrationError::OutsideCalibratedRange)
        );
        assert_eq!(
            bm1491_l9_calibrated_voltage_code(&table, f64::NAN),
            Err(Bm1491L9CalibrationError::NonFiniteVoltage)
        );
    }

    #[test]
    fn calibrated_interpolation_uses_half_away_from_zero_rounding() {
        let table = Bm1491L9VoltageCalibrationTable {
            raw_identity_prefix: [0; BM1491_L9_CALIBRATION_PREFIX_LENGTH],
            points: vec![
                Bm1491L9VoltageCalibrationPoint {
                    code: 0,
                    voltage_v: 0.0,
                },
                Bm1491L9VoltageCalibrationPoint {
                    code: 1,
                    voltage_v: 1.0,
                },
            ],
            response_crc: 0,
        };
        assert_eq!(bm1491_l9_calibrated_voltage_code(&table, 0.5), Ok(1));
    }
}
