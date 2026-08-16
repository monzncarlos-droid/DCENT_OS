//! Pure sensor-transport reconstruction for the exact held L7 VNish image.
//!
//! `FUN_000a0970` dispatches sensor kinds 1, 2, 4, and 5. The held L7
//! initialization calls `FUN_000e8edc` with transport profile zero, which
//! installs the raw read/write pair `FUN_00102dc0`/`FUN_00103108`. The type-2
//! path is different: it calls a configuration-selected vtable slot. The exact
//! parser maps the `BM1489` chip-model string to variant six, whose slot is
//! `FUN_000db2c0`. The held rootfs does not contain the generated runtime
//! `/config/cgminer.conf`, so that mapping is not treated as a capture of what
//! a particular running device selected.
//!
//! This module performs no I/O. All inputs are forgeable replay observations,
//! and no type here grants carrier, sensor, thermal, rail, or mining authority.

pub const BM1489_L7_SENSOR_TRANSPORT_PROFILE: u32 = 0;
pub const BM1489_L7_SENSOR_RECORD_BASE: usize = 0x290;
pub const BM1489_L7_SENSOR_RECORD_STRIDE: usize = 0x80;
pub const BM1489_L7_SENSOR_RECORD_STATE_OFFSET: usize = 0x2c;
pub const BM1489_L7_SENSOR_RECORD_KIND_OFFSET: usize = 0x30;
pub const BM1489_L7_SENSOR_RECORD_PRIMARY_OFFSET_C_OFFSET: usize = 0x48;
pub const BM1489_L7_SENSOR_RECORD_ALTERNATE_OFFSET_C_OFFSET: usize = 0x4c;
pub const BM1489_L7_SENSOR_RECORD_OFFSET_SELECTOR_OFFSET: usize = 0x50;
pub const BM1489_L7_SENSOR_RECORD_AUXILIARY_FLAG_OFFSET: usize = 0x51;
pub const BM1489_L7_SENSOR_RECORD_LAST_SAMPLE_TIMESTAMP_OFFSET: usize = 0x58;
pub const BM1489_L7_SENSOR_RECORD_MODE_TIMESTAMP_OFFSET: usize = 0x68;
pub const BM1489_L7_PROFILE_ZERO_READ_FUNCTION: u32 = 0x0010_2dc0;
pub const BM1489_L7_PROFILE_ZERO_WRITE_FUNCTION: u32 = 0x0010_3108;
pub const BM1489_L7_TYPE_TWO_VTABLE_SLOT: usize = 0x2f;
pub const BM1489_L7_TYPE_TWO_VARIANT_ZERO_FUNCTION: u32 = 0x000b_e66c;
pub const BM1489_L7_TYPE_TWO_BM1489_VARIANT: u32 = 6;
pub const BM1489_L7_TYPE_TWO_BM1489_FUNCTION: u32 = 0x000d_b2c0;
pub const BM1489_L7_TYPE_TWO_ASIC_REGISTER: u8 = 0x1c;
pub const BM1489_L7_TYPE_TWO_READ_ATTEMPTS: u8 = 8;
pub const BM1489_L7_TYPE_TWO_RETRY_DELAY_ARGUMENT: u32 = 1;
pub const BM1489_L7_TYPE_TWO_RUNTIME_VARIANT_PROVEN: bool = false;

pub const BM1489_L7_TYPE_ONE_PHASE_DELAY_MS: u32 = 30;
pub const BM1489_L7_TYPE_ONE_PAYLOAD_LEN: usize = 2;
pub const BM1489_L7_TYPE_ONE_RESPONSE_LEN: usize = 7;

pub const BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS: u32 = 20;
pub const BM1489_L7_TYPE_FIVE_SAMPLE_DELAY_MS: u32 = 65;
pub const BM1489_L7_TYPE_FIVE_SYNC_SUCCESS_DELAY_MS: u32 = 150;
pub const BM1489_L7_TYPE_FIVE_OUTER_ATTEMPTS: u8 = 3;
pub const BM1489_L7_TYPE_FIVE_SYNC_ATTEMPTS: u8 = 3;
pub const BM1489_L7_TYPE_FIVE_MODE_MASK: u8 = 0x04;
pub const BM1489_L7_TYPE_FIVE_MODE_AGE_THRESHOLD_SECONDS: f64 = 60.0;

pub const BM1489_L7_SENSOR_TRANSPORT_INPUTS_AUTHENTICATED: bool = false;
pub const BM1489_L7_SENSOR_TRANSPORT_AUTHORIZES_IO: bool = false;
pub const BM1489_L7_SENSOR_TRANSPORT_AUTHORIZES_THERMAL_READY: bool = false;
pub const BM1489_L7_SENSOR_TRANSPORT_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorTransportError {
    LaneOutOfRange,
    AddressOutOfRange,
    ChainOutOfRange,
    AddressWouldWrap,
    SensorIndexOutOfRange,
    UnknownChipModel,
    TypeTwoSelectorWouldAlias,
    TypeTwoResponseError,
    TypeTwoResponseSelectorMismatch,
    NonFiniteTimestamp,
    NegativeTimestamp,
    TimestampInFuture,
    TypeOneAckMismatch,
    TypeOneResponseLengthMismatch,
    TypeOneResponseOpcodeMismatch,
    TypeOneResponseStatusMismatch,
    TypeOneResponseChecksumMismatch,
    UnsupportedSensorKind,
    UnsupportedStartupCombination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorStartupRoute {
    /// `FUN_000a08f0`: write state two and the mode timestamp, then perform
    /// the first ordinary read. Success becomes state three; failure state
    /// zero. `FUN_000a1b94` writes the last-sample timestamp on success.
    DirectFirstRead,
    /// `FUN_000a20a8`: identify/configure a kind-two or kind-three sensor,
    /// then write mode timestamp, state two, and last-sample timestamp. The
    /// first ordinary sample is left to the later runtime reader.
    ProbeThenArm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7SensorStartupPlan {
    pub route: Bm1489L7SensorStartupRoute,
    pub armed_state: u32,
    pub successful_direct_read_state: Option<u32>,
    pub failure_state: u32,
    pub writes_mode_timestamp: bool,
    pub writes_last_sample_timestamp_before_runtime_read: bool,
}

/// Replays the exact startup route selected by `FUN_00053f94` and
/// `FUN_000546f0`. A kind-five record with its auxiliary flag set is sent to
/// `FUN_000a20a8`, whose kind-two/three gate rejects it; clean code refuses
/// that combination explicitly rather than constructing a misleading plan.
pub const fn bm1489_l7_sensor_startup_plan(
    sensor_kind: u32,
    auxiliary_flag: bool,
) -> Result<Bm1489L7SensorStartupPlan, Bm1489L7SensorTransportError> {
    match sensor_kind {
        1 | 4 => Ok(Bm1489L7SensorStartupPlan {
            route: Bm1489L7SensorStartupRoute::DirectFirstRead,
            armed_state: 2,
            successful_direct_read_state: Some(3),
            failure_state: 0,
            writes_mode_timestamp: true,
            writes_last_sample_timestamp_before_runtime_read: false,
        }),
        2 | 3 => Ok(Bm1489L7SensorStartupPlan {
            route: Bm1489L7SensorStartupRoute::ProbeThenArm,
            armed_state: 2,
            successful_direct_read_state: None,
            failure_state: 0,
            writes_mode_timestamp: true,
            writes_last_sample_timestamp_before_runtime_read: true,
        }),
        5 if !auxiliary_flag => Ok(Bm1489L7SensorStartupPlan {
            route: Bm1489L7SensorStartupRoute::DirectFirstRead,
            armed_state: 2,
            successful_direct_read_state: Some(3),
            failure_state: 0,
            writes_mode_timestamp: true,
            writes_last_sample_timestamp_before_runtime_read: false,
        }),
        5 => Err(Bm1489L7SensorTransportError::UnsupportedStartupCombination),
        _ => Err(Bm1489L7SensorTransportError::UnsupportedSensorKind),
    }
}

/// Exact chip-model-to-driver mapping in `FUN_000971a4`. The parser stores the
/// returned value at configuration word `+0x50`; `FUN_000ba1d0` uses it to
/// install the chip vtable. Inputs are configuration strings, not board
/// identity observations.
pub fn bm1489_l7_driver_variant_for_chip_model(
    chip_model: &str,
) -> Result<u32, Bm1489L7SensorTransportError> {
    match chip_model {
        "BM1360" => Ok(0),
        "BM1362" => Ok(1),
        "BM1366" => Ok(3),
        "BM1370" => Ok(5),
        "BM1368" => Ok(4),
        "BM1398" => Ok(2),
        "BM1489" => Ok(BM1489_L7_TYPE_TWO_BM1489_VARIANT),
        "BM1491" => Ok(7),
        _ => Err(Bm1489L7SensorTransportError::UnknownChipModel),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7TypeTwoReadPlan {
    pub function: u32,
    pub asic_register: u8,
    pub request_value: u32,
    pub response_selector: u8,
    pub read_attempt_limit: u8,
    /// Argument supplied to `FUN_000fd318` between failed response reads. Its
    /// unit is intentionally not promoted without a recovered callee contract.
    pub retry_delay_argument: u32,
}

/// Builds the request accepted by the exact BM1489 variant-six slot
/// `FUN_000db2c0`. Stock masks bit zero from `sensor_selector`; clean code
/// rejects an odd value instead of silently aliasing another selector.
pub fn bm1489_l7_plan_type_two_bm1489_read(
    sensor_selector: u8,
    response_selector: u8,
) -> Result<Bm1489L7TypeTwoReadPlan, Bm1489L7SensorTransportError> {
    if sensor_selector & 1 != 0 {
        return Err(Bm1489L7SensorTransportError::TypeTwoSelectorWouldAlias);
    }
    Ok(Bm1489L7TypeTwoReadPlan {
        function: BM1489_L7_TYPE_TWO_BM1489_FUNCTION,
        asic_register: BM1489_L7_TYPE_TWO_ASIC_REGISTER,
        request_value: 0x0100_0000
            | (u32::from(sensor_selector) << 16)
            | (u32::from(response_selector) << 8),
        response_selector,
        read_attempt_limit: BM1489_L7_TYPE_TWO_READ_ATTEMPTS,
        retry_delay_argument: BM1489_L7_TYPE_TWO_RETRY_DELAY_ARGUMENT,
    })
}

/// Validates the 32-bit register response consumed by `FUN_000db2c0` after
/// `FUN_000dbe80` has obtained a word with bit 31 clear. Bit 30 is the callback
/// error flag, byte one must echo the requested selector, and byte zero is the
/// returned sensor value.
pub const fn bm1489_l7_validate_type_two_bm1489_response(
    response_word: u32,
    response_selector: u8,
) -> Result<u8, Bm1489L7SensorTransportError> {
    if response_word & 0x4000_0000 != 0 {
        return Err(Bm1489L7SensorTransportError::TypeTwoResponseError);
    }
    if ((response_word >> 8) & 0xff) as u8 != response_selector {
        return Err(Bm1489L7SensorTransportError::TypeTwoResponseSelectorMismatch);
    }
    Ok(response_word as u8)
}

fn checked_lane(lane: u8) -> Result<u32, Bm1489L7SensorTransportError> {
    if lane > 3 {
        return Err(Bm1489L7SensorTransportError::LaneOutOfRange);
    }
    Ok(u32::from(lane))
}

fn checked_address(address: u8) -> Result<u32, Bm1489L7SensorTransportError> {
    if address > 0x7f {
        return Err(Bm1489L7SensorTransportError::AddressOutOfRange);
    }
    Ok(u32::from(address))
}

fn profile_zero_common_word(
    lane: u8,
    address: u8,
    register: Option<u8>,
) -> Result<u32, Bm1489L7SensorTransportError> {
    let lane = checked_lane(lane)?;
    let address = checked_address(address)?;
    let mut word = ((address & 0x78) << 17) | ((address & 0x07) << 16) | ((lane & 0x03) << 26);
    if let Some(register) = register {
        word |= 0x0100_0000 | (u32::from(register) << 8);
    }
    Ok(word)
}

/// Builds the exact profile-zero command word used by `FUN_00102dc0` for one
/// or more reads. Stock masks the address and lane; this clean helper rejects
/// values that would alias another endpoint.
pub fn bm1489_l7_profile_zero_read_word(
    lane: u8,
    address: u8,
    register: Option<u8>,
) -> Result<u32, Bm1489L7SensorTransportError> {
    let mut word = profile_zero_common_word(lane, address, register)? | 0x0200_0000;
    if lane == 1 {
        word |= 0x0008_0000;
    }
    Ok(word)
}

/// Builds one exact profile-zero write word from `FUN_00103108`. A zero-length
/// write is accepted by stock but is not represented because it emits no word.
pub fn bm1489_l7_profile_zero_write_word(
    lane: u8,
    address: u8,
    register: Option<u8>,
    value: u8,
) -> Result<u32, Bm1489L7SensorTransportError> {
    Ok(profile_zero_common_word(lane, address, register)? | u32::from(value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7TypeOnePlan {
    pub slave_address: u8,
    pub select_request: [u8; 8],
    pub read_request: [u8; 8],
    pub select_response_len: usize,
    pub read_response_len: usize,
    pub delay_before_write_ms: u32,
    pub delay_before_read_ms: u32,
    /// `FUN_000e81a0` discards every raw read/write return value.
    pub raw_transfer_results_checked: bool,
}

const fn additive_checksum_be(bytes: &[u8]) -> [u8; 2] {
    let mut index = 0;
    let mut sum = 0u16;
    while index < bytes.len() {
        sum = sum.wrapping_add(bytes[index] as u16);
        index += 1;
    }
    sum.to_be_bytes()
}

/// Builds the exact kind-one, two-byte read transaction used by
/// `FUN_000a0970` through `FUN_000e82f8`. The descriptor command is the byte at
/// sensor record `+0x24`; the exact caller supplies subcommand zero.
pub fn bm1489_l7_plan_type_one_read(chain: u8, command: u8) -> Bm1489L7TypeOnePlan {
    let slave_address = (chain & 7) | 0x20;
    let select_sum = additive_checksum_be(&[0x06, 0x3b, command, 0x00]);
    let read_sum =
        additive_checksum_be(&[0x06, 0x3c, command, BM1489_L7_TYPE_ONE_PAYLOAD_LEN as u8]);
    Bm1489L7TypeOnePlan {
        slave_address,
        select_request: [
            0x55,
            0xaa,
            0x06,
            0x3b,
            command,
            0x00,
            select_sum[0],
            select_sum[1],
        ],
        read_request: [
            0x55,
            0xaa,
            0x06,
            0x3c,
            command,
            BM1489_L7_TYPE_ONE_PAYLOAD_LEN as u8,
            read_sum[0],
            read_sum[1],
        ],
        select_response_len: 2,
        read_response_len: BM1489_L7_TYPE_ONE_RESPONSE_LEN,
        delay_before_write_ms: BM1489_L7_TYPE_ONE_PHASE_DELAY_MS,
        delay_before_read_ms: BM1489_L7_TYPE_ONE_PHASE_DELAY_MS,
        raw_transfer_results_checked: false,
    }
}

/// Validates the exact kind-one responses accepted by `FUN_000e82f8` for the
/// held caller's two-byte payload. The response checksum is additive, u16,
/// and stored big-endian after the payload.
pub fn bm1489_l7_validate_type_one_read(
    select_response: [u8; 2],
    read_response: [u8; BM1489_L7_TYPE_ONE_RESPONSE_LEN],
) -> Result<[u8; BM1489_L7_TYPE_ONE_PAYLOAD_LEN], Bm1489L7SensorTransportError> {
    if select_response != [0x3b, 0x01] {
        return Err(Bm1489L7SensorTransportError::TypeOneAckMismatch);
    }
    if usize::from(read_response[0]) != BM1489_L7_TYPE_ONE_RESPONSE_LEN {
        return Err(Bm1489L7SensorTransportError::TypeOneResponseLengthMismatch);
    }
    if read_response[1] != 0x3c {
        return Err(Bm1489L7SensorTransportError::TypeOneResponseOpcodeMismatch);
    }
    if read_response[2] != 0x01 {
        return Err(Bm1489L7SensorTransportError::TypeOneResponseStatusMismatch);
    }
    let expected = additive_checksum_be(&read_response[..5]);
    if read_response[5..7] != expected {
        return Err(Bm1489L7SensorTransportError::TypeOneResponseChecksumMismatch);
    }
    Ok([read_response[3], read_response[4]])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7RawReadPlan {
    pub command_word: u32,
    pub length: u8,
}

/// Plans the exact kind-four three-byte raw read. Stock wraps the chain plus
/// descriptor address to u8 and then masks it to seven bits. Clean code refuses
/// either wrap so a malformed descriptor cannot silently address another chip.
pub fn bm1489_l7_plan_type_four_read(
    lane: u8,
    chain: u8,
    descriptor_address: u8,
) -> Result<Bm1489L7RawReadPlan, Bm1489L7SensorTransportError> {
    if chain > 3 {
        return Err(Bm1489L7SensorTransportError::ChainOutOfRange);
    }
    let address = chain
        .checked_add(descriptor_address)
        .ok_or(Bm1489L7SensorTransportError::AddressWouldWrap)?;
    let command_word = bm1489_l7_profile_zero_read_word(lane, address, None)?;
    Ok(Bm1489L7RawReadPlan {
        command_word,
        length: 3,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7TypeFiveStep {
    Write { command_word: u32 },
    Read { command_word: u32, length: u8 },
    DelayMs(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1489L7TypeFivePlan {
    /// Bus-select prefix executed at the start of each outer attempt.
    pub attempt_prefix: Vec<Bm1489L7TypeFiveStep>,
    /// One synchronization attempt. Stock repeats it at most three times and
    /// exits early when register-three bit two equals `desired_mode_bit`.
    pub sync_attempt: Vec<Bm1489L7TypeFiveStep>,
    /// Direct sample/restore tail after no sync is needed or sync succeeds.
    pub sample_tail: Vec<Bm1489L7TypeFiveStep>,
    pub desired_mode_bit: bool,
    pub status_mask: u8,
    pub outer_attempt_limit: u8,
    pub sync_attempt_limit: u8,
    pub sync_success_delay_ms: u32,
    pub sync_mismatch_delay_ms: u32,
}

/// The initial kind-five register-three status requires synchronization iff
/// bit two differs from the mode selected by the recovered timestamp predicate.
pub const fn bm1489_l7_type_five_sync_required(
    status_register: u8,
    desired_mode_bit: bool,
) -> bool {
    ((status_register & BM1489_L7_TYPE_FIVE_MODE_MASK) != 0) != desired_mode_bit
}

/// Replays the kind-five mode predicate from `FUN_000a0970`. The stored value
/// is a `CLOCK_MONOTONIC` timestamp in seconds. Zero selects mode zero without
/// reading the clock; otherwise stock selects mode one only when age is
/// strictly greater than 60 seconds. Non-finite, negative, and future values
/// are refused here as clean fail-closed hardening.
pub fn bm1489_l7_type_five_desired_mode(
    stored_monotonic_seconds: f64,
    now_monotonic_seconds: f64,
) -> Result<bool, Bm1489L7SensorTransportError> {
    if stored_monotonic_seconds == 0.0 {
        return Ok(false);
    }
    if !stored_monotonic_seconds.is_finite() || !now_monotonic_seconds.is_finite() {
        return Err(Bm1489L7SensorTransportError::NonFiniteTimestamp);
    }
    if stored_monotonic_seconds < 0.0 {
        return Err(Bm1489L7SensorTransportError::NegativeTimestamp);
    }
    if now_monotonic_seconds < stored_monotonic_seconds {
        return Err(Bm1489L7SensorTransportError::TimestampInFuture);
    }
    Ok(BM1489_L7_TYPE_FIVE_MODE_AGE_THRESHOLD_SECONDS
        < now_monotonic_seconds - stored_monotonic_seconds)
}

/// Builds the exact profile-zero kind-five transaction templates. This is an
/// operation replay, not an executor: callers still have to supply transport
/// outcomes and the timestamp-derived desired mode. Stock retries the outer
/// acquisition and the optional synchronization three times each.
pub fn bm1489_l7_plan_type_five_read(
    lane: u8,
    bus_address: u8,
    sensor_address: u8,
    sensor_index: u8,
    desired_mode_bit: bool,
    read_auxiliary_register: bool,
) -> Result<Bm1489L7TypeFivePlan, Bm1489L7SensorTransportError> {
    if sensor_index > 7 {
        return Err(Bm1489L7SensorTransportError::SensorIndexOutOfRange);
    }
    let bus_clear = bm1489_l7_profile_zero_write_word(lane, bus_address, None, 0)?;
    let bus_select =
        bm1489_l7_profile_zero_write_word(lane, bus_address, None, 1u8 << sensor_index)?;
    let status_read = bm1489_l7_profile_zero_read_word(lane, sensor_address, Some(3))?;
    let mode_write = bm1489_l7_profile_zero_write_word(
        lane,
        sensor_address,
        Some(9),
        if desired_mode_bit {
            BM1489_L7_TYPE_FIVE_MODE_MASK
        } else {
            0
        },
    )?;
    let primary_read = bm1489_l7_profile_zero_read_word(lane, sensor_address, Some(0))?;

    let attempt_prefix = vec![
        Bm1489L7TypeFiveStep::Write {
            command_word: bus_clear,
        },
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS),
        Bm1489L7TypeFiveStep::Write {
            command_word: bus_select,
        },
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS),
        Bm1489L7TypeFiveStep::Read {
            command_word: status_read,
            length: 1,
        },
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS),
    ];
    let sync_attempt = vec![
        Bm1489L7TypeFiveStep::Write {
            command_word: mode_write,
        },
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS),
        Bm1489L7TypeFiveStep::Read {
            command_word: status_read,
            length: 1,
        },
    ];
    let mut sample_tail = vec![
        // The exact label reached by both the direct and synchronized paths
        // executes two consecutive 20-ms delays before register zero.
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS),
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS),
        Bm1489L7TypeFiveStep::Read {
            command_word: primary_read,
            length: 1,
        },
        Bm1489L7TypeFiveStep::DelayMs(BM1489_L7_TYPE_FIVE_SAMPLE_DELAY_MS),
    ];
    if read_auxiliary_register {
        sample_tail.push(Bm1489L7TypeFiveStep::DelayMs(
            BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS,
        ));
        sample_tail.push(Bm1489L7TypeFiveStep::Read {
            command_word: bm1489_l7_profile_zero_read_word(lane, sensor_address, Some(1))?,
            length: 1,
        });
        sample_tail.push(Bm1489L7TypeFiveStep::DelayMs(
            BM1489_L7_TYPE_FIVE_SAMPLE_DELAY_MS,
        ));
    }
    sample_tail.push(Bm1489L7TypeFiveStep::DelayMs(
        BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS,
    ));
    sample_tail.push(Bm1489L7TypeFiveStep::Write {
        command_word: bus_clear,
    });

    Ok(Bm1489L7TypeFivePlan {
        attempt_prefix,
        sync_attempt,
        sample_tail,
        desired_mode_bit,
        status_mask: BM1489_L7_TYPE_FIVE_MODE_MASK,
        outer_attempt_limit: BM1489_L7_TYPE_FIVE_OUTER_ATTEMPTS,
        sync_attempt_limit: BM1489_L7_TYPE_FIVE_SYNC_ATTEMPTS,
        sync_success_delay_ms: BM1489_L7_TYPE_FIVE_SYNC_SUCCESS_DELAY_MS,
        sync_mismatch_delay_ms: BM1489_L7_TYPE_FIVE_SHORT_DELAY_MS,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorKindRoute {
    TypeOneFramedTwoByteRead,
    /// Function pointer at object `+0x1b0`, table slot `0x2f`. The runtime
    /// configuration capture is absent, but the exact parser maps `BM1489` to
    /// variant six and therefore to `FUN_000db2c0`.
    TypeTwoRuntimeVtable,
    TypeFourProfileZeroThreeByteRead,
    TypeFiveProfileZeroMuxedRead,
}

pub const fn bm1489_l7_sensor_kind_route(
    sensor_kind: u32,
) -> Result<Bm1489L7SensorKindRoute, Bm1489L7SensorTransportError> {
    match sensor_kind {
        1 => Ok(Bm1489L7SensorKindRoute::TypeOneFramedTwoByteRead),
        2 => Ok(Bm1489L7SensorKindRoute::TypeTwoRuntimeVtable),
        4 => Ok(Bm1489L7SensorKindRoute::TypeFourProfileZeroThreeByteRead),
        5 => Ok(Bm1489L7SensorKindRoute::TypeFiveProfileZeroMuxedRead),
        _ => Err(Bm1489L7SensorTransportError::UnsupportedSensorKind),
    }
}

/// Kind two is dispatched only while the record state is exactly two or three.
pub const fn bm1489_l7_type_two_state_admitted(state: u32) -> bool {
    (state & !1) == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_zero_words_match_read_write_layout() {
        assert_eq!(
            bm1489_l7_profile_zero_read_word(0, 0x20, None),
            Ok(0x0240_0000)
        );
        assert_eq!(
            bm1489_l7_profile_zero_read_word(1, 0x23, Some(1)),
            Ok(0x074b_0100)
        );
        assert_eq!(
            bm1489_l7_profile_zero_write_word(1, 0x23, Some(9), 4),
            Ok(0x0543_0904)
        );
        assert_eq!(
            bm1489_l7_profile_zero_read_word(4, 0x20, None),
            Err(Bm1489L7SensorTransportError::LaneOutOfRange)
        );
        assert_eq!(
            bm1489_l7_profile_zero_read_word(0, 0x80, None),
            Err(Bm1489L7SensorTransportError::AddressOutOfRange)
        );
    }

    #[test]
    fn type_one_exact_frames_and_chain_alias_are_pinned() {
        let plan = bm1489_l7_plan_type_one_read(9, 0x2a);
        assert_eq!(plan.slave_address, 0x21);
        assert_eq!(
            plan.select_request,
            [0x55, 0xaa, 0x06, 0x3b, 0x2a, 0, 0, 0x6b]
        );
        assert_eq!(
            plan.read_request,
            [0x55, 0xaa, 0x06, 0x3c, 0x2a, 2, 0, 0x6e]
        );
        assert_eq!(plan.select_response_len, 2);
        assert_eq!(plan.read_response_len, 7);
        assert_eq!(plan.delay_before_write_ms, 30);
        assert_eq!(plan.delay_before_read_ms, 30);
        assert!(!plan.raw_transfer_results_checked);
    }

    #[test]
    fn type_one_response_requires_ack_header_status_and_checksum() {
        let valid = [7, 0x3c, 1, 0x7f, 0x80, 0x01, 0x43];
        assert_eq!(
            bm1489_l7_validate_type_one_read([0x3b, 1], valid),
            Ok([0x7f, 0x80])
        );

        assert_eq!(
            bm1489_l7_validate_type_one_read([0x3b, 0], valid),
            Err(Bm1489L7SensorTransportError::TypeOneAckMismatch)
        );
        let mut malformed = valid;
        malformed[6] ^= 1;
        assert_eq!(
            bm1489_l7_validate_type_one_read([0x3b, 1], malformed),
            Err(Bm1489L7SensorTransportError::TypeOneResponseChecksumMismatch)
        );
    }

    #[test]
    fn type_four_refuses_stock_address_aliases() {
        assert_eq!(
            bm1489_l7_plan_type_four_read(0, 2, 0x20),
            Ok(Bm1489L7RawReadPlan {
                command_word: 0x0242_0000,
                length: 3,
            })
        );
        assert_eq!(
            bm1489_l7_plan_type_four_read(0, 4, 0x20),
            Err(Bm1489L7SensorTransportError::ChainOutOfRange)
        );
        assert_eq!(
            bm1489_l7_plan_type_four_read(0, 3, 0xfe),
            Err(Bm1489L7SensorTransportError::AddressWouldWrap)
        );
    }

    #[test]
    fn type_five_sync_predicate_is_exact_bit_two_inequality() {
        assert!(!bm1489_l7_type_five_sync_required(0, false));
        assert!(bm1489_l7_type_five_sync_required(4, false));
        assert!(bm1489_l7_type_five_sync_required(0, true));
        assert!(!bm1489_l7_type_five_sync_required(4, true));
    }

    #[test]
    fn type_five_timestamp_mode_is_strictly_after_sixty_seconds() {
        assert_eq!(bm1489_l7_type_five_desired_mode(0.0, f64::NAN), Ok(false));
        assert_eq!(bm1489_l7_type_five_desired_mode(100.0, 160.0), Ok(false));
        assert_eq!(bm1489_l7_type_five_desired_mode(100.0, 160.5), Ok(true));
        assert_eq!(
            bm1489_l7_type_five_desired_mode(f64::NAN, 160.0),
            Err(Bm1489L7SensorTransportError::NonFiniteTimestamp)
        );
        assert_eq!(
            bm1489_l7_type_five_desired_mode(-1.0, 160.0),
            Err(Bm1489L7SensorTransportError::NegativeTimestamp)
        );
        assert_eq!(
            bm1489_l7_type_five_desired_mode(161.0, 160.0),
            Err(Bm1489L7SensorTransportError::TimestampInFuture)
        );
    }

    #[test]
    fn sensor_record_layout_and_direct_startup_route_are_pinned() {
        assert_eq!(BM1489_L7_SENSOR_RECORD_BASE, 0x290);
        assert_eq!(BM1489_L7_SENSOR_RECORD_STRIDE, 0x80);
        assert_eq!(BM1489_L7_SENSOR_RECORD_STATE_OFFSET, 0x2c);
        assert_eq!(BM1489_L7_SENSOR_RECORD_KIND_OFFSET, 0x30);
        assert_eq!(BM1489_L7_SENSOR_RECORD_PRIMARY_OFFSET_C_OFFSET, 0x48);
        assert_eq!(BM1489_L7_SENSOR_RECORD_ALTERNATE_OFFSET_C_OFFSET, 0x4c);
        assert_eq!(BM1489_L7_SENSOR_RECORD_OFFSET_SELECTOR_OFFSET, 0x50);
        assert_eq!(BM1489_L7_SENSOR_RECORD_AUXILIARY_FLAG_OFFSET, 0x51);
        assert_eq!(BM1489_L7_SENSOR_RECORD_LAST_SAMPLE_TIMESTAMP_OFFSET, 0x58);
        assert_eq!(BM1489_L7_SENSOR_RECORD_MODE_TIMESTAMP_OFFSET, 0x68);

        let direct = bm1489_l7_sensor_startup_plan(5, false).unwrap();
        assert_eq!(direct.route, Bm1489L7SensorStartupRoute::DirectFirstRead);
        assert_eq!(direct.armed_state, 2);
        assert_eq!(direct.successful_direct_read_state, Some(3));
        assert_eq!(direct.failure_state, 0);
        assert!(direct.writes_mode_timestamp);
        assert!(!direct.writes_last_sample_timestamp_before_runtime_read);
    }

    #[test]
    fn probe_startup_arms_kinds_two_and_three_but_refuses_kind_five_auxiliary() {
        for kind in [2, 3] {
            let probe = bm1489_l7_sensor_startup_plan(kind, true).unwrap();
            assert_eq!(probe.route, Bm1489L7SensorStartupRoute::ProbeThenArm);
            assert_eq!(probe.armed_state, 2);
            assert_eq!(probe.successful_direct_read_state, None);
            assert_eq!(probe.failure_state, 0);
            assert!(probe.writes_mode_timestamp);
            assert!(probe.writes_last_sample_timestamp_before_runtime_read);
        }
        assert_eq!(
            bm1489_l7_sensor_startup_plan(5, true),
            Err(Bm1489L7SensorTransportError::UnsupportedStartupCombination)
        );
        assert_eq!(
            bm1489_l7_sensor_startup_plan(0, false),
            Err(Bm1489L7SensorTransportError::UnsupportedSensorKind)
        );
    }

    #[test]
    fn type_five_templates_pin_attempts_delays_registers_and_restore() {
        let plan = bm1489_l7_plan_type_five_read(0, 0x20, 0x4c, 2, true, true).unwrap();
        assert_eq!(plan.outer_attempt_limit, 3);
        assert_eq!(plan.sync_attempt_limit, 3);
        assert_eq!(plan.status_mask, 4);
        assert_eq!(plan.sync_success_delay_ms, 150);
        assert_eq!(plan.sync_mismatch_delay_ms, 20);
        assert_eq!(plan.attempt_prefix.len(), 6);
        assert_eq!(plan.sync_attempt.len(), 3);
        assert_eq!(plan.sample_tail.len(), 9);
        assert_eq!(
            plan.sync_attempt[0],
            Bm1489L7TypeFiveStep::Write {
                command_word: 0x0194_0904,
            }
        );
        assert_eq!(
            plan.sample_tail[2],
            Bm1489L7TypeFiveStep::Read {
                command_word: 0x0394_0000,
                length: 1,
            }
        );
        assert_eq!(
            plan.sample_tail[5],
            Bm1489L7TypeFiveStep::Read {
                command_word: 0x0394_0100,
                length: 1,
            }
        );
        assert_eq!(
            plan.sample_tail.last(),
            Some(&Bm1489L7TypeFiveStep::Write {
                command_word: 0x0040_0000,
            })
        );
    }

    #[test]
    fn type_five_refuses_unrepresentable_mux_index() {
        assert_eq!(
            bm1489_l7_plan_type_five_read(0, 0x20, 0x4c, 8, false, false),
            Err(Bm1489L7SensorTransportError::SensorIndexOutOfRange)
        );
    }

    #[test]
    fn dispatch_scope_and_type_two_boundary_are_explicit() {
        assert_eq!(
            bm1489_l7_sensor_kind_route(2),
            Ok(Bm1489L7SensorKindRoute::TypeTwoRuntimeVtable)
        );
        assert!(bm1489_l7_type_two_state_admitted(2));
        assert!(bm1489_l7_type_two_state_admitted(3));
        assert!(!bm1489_l7_type_two_state_admitted(1));
        assert!(!bm1489_l7_type_two_state_admitted(4));
        assert_eq!(BM1489_L7_TYPE_TWO_VTABLE_SLOT, 0x2f);
        assert_eq!(BM1489_L7_TYPE_TWO_VARIANT_ZERO_FUNCTION, 0x000b_e66c);
        assert_eq!(BM1489_L7_TYPE_TWO_BM1489_VARIANT, 6);
        assert_eq!(BM1489_L7_TYPE_TWO_BM1489_FUNCTION, 0x000d_b2c0);
        assert!(!BM1489_L7_TYPE_TWO_RUNTIME_VARIANT_PROVEN);
    }

    #[test]
    fn chip_model_parser_selects_exact_bm1489_variant_six() {
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1360"), Ok(0));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1362"), Ok(1));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1366"), Ok(3));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1370"), Ok(5));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1368"), Ok(4));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1398"), Ok(2));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1489"), Ok(6));
        assert_eq!(bm1489_l7_driver_variant_for_chip_model("BM1491"), Ok(7));
        assert_eq!(
            bm1489_l7_driver_variant_for_chip_model("bm1489"),
            Err(Bm1489L7SensorTransportError::UnknownChipModel)
        );
    }

    #[test]
    fn type_two_bm1489_plan_and_response_contract_are_pinned() {
        let plan = bm1489_l7_plan_type_two_bm1489_read(0x4c, 0).unwrap();
        assert_eq!(plan.function, 0x000d_b2c0);
        assert_eq!(plan.asic_register, 0x1c);
        assert_eq!(plan.request_value, 0x014c_0000);
        assert_eq!(plan.response_selector, 0);
        assert_eq!(plan.read_attempt_limit, 8);
        assert_eq!(plan.retry_delay_argument, 1);
        assert_eq!(
            bm1489_l7_plan_type_two_bm1489_read(0x4d, 0),
            Err(Bm1489L7SensorTransportError::TypeTwoSelectorWouldAlias)
        );
        assert_eq!(
            bm1489_l7_validate_type_two_bm1489_response(0x0000_007f, 0),
            Ok(0x7f)
        );
        assert_eq!(
            bm1489_l7_validate_type_two_bm1489_response(0x4000_007f, 0),
            Err(Bm1489L7SensorTransportError::TypeTwoResponseError)
        );
        assert_eq!(
            bm1489_l7_validate_type_two_bm1489_response(0x0000_017f, 0),
            Err(Bm1489L7SensorTransportError::TypeTwoResponseSelectorMismatch)
        );
    }

    #[test]
    fn pure_transport_contract_never_mints_authority() {
        assert!(!BM1489_L7_SENSOR_TRANSPORT_INPUTS_AUTHENTICATED);
        assert!(!BM1489_L7_SENSOR_TRANSPORT_AUTHORIZES_IO);
        assert!(!BM1489_L7_SENSOR_TRANSPORT_AUTHORIZES_THERMAL_READY);
        assert!(!BM1489_L7_SENSOR_TRANSPORT_AUTHORIZES_MINING);
    }
}
