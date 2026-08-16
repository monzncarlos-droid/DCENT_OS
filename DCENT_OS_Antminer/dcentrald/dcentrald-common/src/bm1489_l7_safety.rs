//! Pure thermal/fan/shutdown replay for the exact held L7 VNish image.
//!
//! The recovered functions are `FUN_00054a3c` (per-chain overtemperature),
//! `FUN_00072384`/`FUN_00073e08` (fan state/supervision), `FUN_0006f5b4`
//! (startup fan admission), and the `FUN_00059600` -> `FUN_00059f6c` ->
//! `FUN_00067878` shutdown path. The L7 callback installed by
//! `FUN_000e8edc` is `FUN_001037f4`.
//!
//! This module performs no I/O. Its inputs are unauthenticated observations,
//! and an observed stock power-control write is not proof of electrical off.

pub const BM1489_L7_RUNTIME_FAN_GRACE_SECONDS: f64 = 10.0;
pub const BM1489_L7_RUNTIME_LOOP_TAIL_DELAY_MS: u32 = 1_000;
pub const BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT: usize = 15;
pub const BM1489_L7_STARTUP_FAN_SAMPLE_DELAY_MS: u32 = 1_000;
pub const BM1489_L7_FAN_CAPTURE_WORDS_PER_CYCLE: usize = 4;
pub const BM1489_L7_FAN_CAPTURE_TAIL_DELAY_MS: u32 = 1_000;
pub const BM1489_L7_FAN_SLOT_COUNT: usize = 4;
pub const BM1489_L7_FAN_DEFAULT_RPM_MULTIPLIER: u32 = 120;
pub const BM1489_L7_FAN_ALTERNATE_RPM_MULTIPLIER: u32 = 240;
pub const BM1489_L7_FAN_ALTERNATE_HARDWARE_WORD_LOW16: u16 = 0xb025;
pub const BM1489_L7_FAN_LOSS_PWM_FLOOR_PERCENT: u32 = 10;
pub const BM1489_L7_SENSOR_TYPE_145_STALE_AFTER_SECONDS: f64 = 25.0;
pub const BM1489_L7_SENSOR_TYPE_23_STALE_AFTER_SECONDS: f64 = 20.0;

pub const BM1489_L7_REASON_FAN_SHORTFALL: u32 = 0x07d4;
pub const BM1489_L7_REASON_SENSOR_AVAILABILITY: u32 = 0x07d6;
pub const BM1489_L7_REASON_COOL_DOWN_FAILED: u32 = 0x0bb9;
pub const BM1489_L7_REASON_PCB_OVERHEAT: u32 = 0x0bba;
pub const BM1489_L7_REASON_CHIP_OVERHEAT: u32 = 0x0bbb;
pub const BM1489_L7_COOL_DOWN_BALANCED_DELTA_MAX_C: u32 = 5;
pub const BM1489_L7_COOL_DOWN_SENSOR_SAMPLE_DELAY_MS: u32 = 5_000;
pub const BM1489_L7_COOL_DOWN_TIMED_STEP_DELAY_MS: u32 = 10_000;
pub const BM1489_L7_COOL_DOWN_STANDARD_SECONDS: u32 = 120;
pub const BM1489_L7_COOL_DOWN_ALTERNATE_SECONDS: u32 = 240;

pub const BM1489_L7_POWER_CONTROL_SELECTOR: u32 = 0x0d;
pub const BM1489_L7_POWER_CONTROL_CHAIN_LIMIT: u32 = 4;

pub const BM1489_L7_OVERHEAT_CONTROL_FLOW_RECOVERED: bool = true;
pub const BM1489_L7_FAN_SHORTFALL_CONTROL_FLOW_RECOVERED: bool = true;
pub const BM1489_L7_POWER_CALLBACK_RECOVERED: bool = true;
pub const BM1489_L7_THERMAL_INPUTS_AUTHENTICATED: bool = false;
pub const BM1489_L7_POWER_WRITE_READBACK_VERIFIED: bool = false;
pub const BM1489_L7_ELECTRICAL_OFF_PROVEN: bool = false;
pub const BM1489_L7_SAFETY_AUTHORIZES_HARDWARE_IO: bool = false;
pub const BM1489_L7_SAFETY_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorFreshnessDecision {
    AlreadyInvalid,
    Fresh,
    Invalidated,
}

impl Bm1489L7SensorFreshnessDecision {
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorInputError {
    NonFiniteElapsedTime,
    NegativeElapsedTime,
    NonFiniteExternalTemperature,
    ExternalTemperatureOutOfRange,
}

/// Replays the state/age predicate in `FUN_000a1db8`. A zero state is already
/// invalid. Sensor kinds 1/4/5 expire only when age is strictly greater than
/// 25 seconds; kinds 2/3 use 20 seconds. Other kinds have no recovered age
/// expiry in this helper. Finite/nonnegative validation is clean hardening.
pub fn bm1489_l7_sensor_freshness(
    state: u32,
    sensor_kind: u32,
    elapsed_since_last_success_seconds: f64,
) -> Result<Bm1489L7SensorFreshnessDecision, Bm1489L7SensorInputError> {
    if !elapsed_since_last_success_seconds.is_finite() {
        return Err(Bm1489L7SensorInputError::NonFiniteElapsedTime);
    }
    if elapsed_since_last_success_seconds < 0.0 {
        return Err(Bm1489L7SensorInputError::NegativeElapsedTime);
    }
    if state == 0 {
        return Ok(Bm1489L7SensorFreshnessDecision::AlreadyInvalid);
    }
    let stale_after = match sensor_kind {
        1 | 4 | 5 => Some(BM1489_L7_SENSOR_TYPE_145_STALE_AFTER_SECONDS),
        2 | 3 => Some(BM1489_L7_SENSOR_TYPE_23_STALE_AFTER_SECONDS),
        _ => None,
    };
    if stale_after.is_some_and(|limit| elapsed_since_last_success_seconds > limit) {
        Ok(Bm1489L7SensorFreshnessDecision::Invalidated)
    } else {
        Ok(Bm1489L7SensorFreshnessDecision::Fresh)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7SensorRecordState {
    pub state: u32,
    pub sensor_kind: u32,
    /// Exact record flag which selects the wrapped `raw - 64` decode. Kind
    /// two selects that decode regardless of this flag.
    pub subtract_64_mode: bool,
    pub chip_offset_c: i32,
    pub previous_sample_initialized: bool,
    pub previous_pcb_c: i32,
    pub pcb_c: i32,
    pub chip_c: i32,
    pub consecutive_failures: u32,
}

/// Selects the exact signed calibration offset consumed by
/// `FUN_000a1b94`: record byte `+0x50 == 0` selects the integer at `+0x48`;
/// any nonzero value selects `+0x4c`. The provenance and physical meaning of
/// both configured integers remain unproved by the held static rootfs.
pub const fn bm1489_l7_select_chip_offset_c(
    primary_offset_c: i32,
    alternate_offset_c: i32,
    alternate_selected: bool,
) -> i32 {
    if alternate_selected {
        alternate_offset_c
    } else {
        primary_offset_c
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorReadDisposition {
    Applied,
    /// Kind five rejects a jump over 30 C, but its outer acquisition wrapper
    /// still reports success and does not increment the failure counter.
    KindFiveJumpRejectedButWrapperReportsSuccess,
    AcquisitionFailed,
    ThirdConsecutiveFailureInvalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7SensorReadStep {
    pub state: Bm1489L7SensorRecordState,
    pub disposition: Bm1489L7SensorReadDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorReadError {
    AlreadyInvalid,
    FailureCounterOverflow,
}

const fn bm1489_l7_decode_sensor_raw(raw: u8, subtract_64: bool) -> i32 {
    let decoded = if subtract_64 {
        raw.wrapping_sub(64)
    } else {
        raw
    };
    decoded as i8 as i32
}

/// Replays the common successful-read state mutation in `FUN_000a0970` and
/// `FUN_000a1b94`. The raw conversion is signed byte arithmetic; subtract-64
/// mode wraps in eight bits before sign extension. On an applied sample the
/// failure counter resets and state two advances to state three.
pub fn bm1489_l7_apply_sensor_read_success(
    previous: Bm1489L7SensorRecordState,
    raw: u8,
) -> Result<Bm1489L7SensorReadStep, Bm1489L7SensorReadError> {
    if previous.state == 0 {
        return Err(Bm1489L7SensorReadError::AlreadyInvalid);
    }
    let pcb_c =
        bm1489_l7_decode_sensor_raw(raw, previous.sensor_kind == 2 || previous.subtract_64_mode);
    if previous.sensor_kind == 5
        && previous.previous_sample_initialized
        && (previous.previous_pcb_c - pcb_c).abs() > 30
    {
        return Ok(Bm1489L7SensorReadStep {
            state: previous,
            disposition:
                Bm1489L7SensorReadDisposition::KindFiveJumpRejectedButWrapperReportsSuccess,
        });
    }

    Ok(Bm1489L7SensorReadStep {
        state: Bm1489L7SensorRecordState {
            state: if previous.state == 2 {
                3
            } else {
                previous.state
            },
            previous_sample_initialized: true,
            previous_pcb_c: if previous.previous_sample_initialized {
                previous.pcb_c
            } else {
                pcb_c
            },
            pcb_c,
            chip_c: pcb_c.wrapping_add(previous.chip_offset_c),
            consecutive_failures: 0,
            ..previous
        },
        disposition: Bm1489L7SensorReadDisposition::Applied,
    })
}

/// Replays the common failed-read counter in `FUN_000a0970`. The third
/// consecutive failure clears the sensor state; the first two retain it.
pub fn bm1489_l7_apply_sensor_read_failure(
    previous: Bm1489L7SensorRecordState,
) -> Result<Bm1489L7SensorReadStep, Bm1489L7SensorReadError> {
    if previous.state == 0 {
        return Err(Bm1489L7SensorReadError::AlreadyInvalid);
    }
    let failures = previous
        .consecutive_failures
        .checked_add(1)
        .ok_or(Bm1489L7SensorReadError::FailureCounterOverflow)?;
    let invalidated = failures >= 3;
    Ok(Bm1489L7SensorReadStep {
        state: Bm1489L7SensorRecordState {
            state: if invalidated { 0 } else { previous.state },
            consecutive_failures: failures,
            ..previous
        },
        disposition: if invalidated {
            Bm1489L7SensorReadDisposition::ThirdConsecutiveFailureInvalidated
        } else {
            Bm1489L7SensorReadDisposition::AcquisitionFailed
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7SensorObservation {
    /// Only exact state value three contributes to `FUN_00054210`.
    pub state: u32,
    pub pcb_c: i32,
    pub chip_c: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1489L7TemperatureSummary {
    pub has_valid_sample: bool,
    pub minimum_c: i32,
    pub average_c: i32,
    pub maximum_c: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1489L7ChainTemperatureSummary {
    pub pcb: Bm1489L7TemperatureSummary,
    pub chip: Bm1489L7TemperatureSummary,
}

/// Replays the direct-sensor aggregation portion of `FUN_00054210`. Only
/// sensors in exact state three contribute. Empty valid sets publish zero
/// min/average/max and clear the valid flag. Integer averages truncate toward
/// zero. The function's optional external chip-temperature overlay is a
/// separate recovered branch and is not represented by this helper.
pub fn bm1489_l7_aggregate_direct_sensor_temperatures(
    sensors: &[Bm1489L7SensorObservation],
) -> Bm1489L7ChainTemperatureSummary {
    let mut count = 0i64;
    let mut pcb_sum = 0i64;
    let mut chip_sum = 0i64;
    let mut pcb_min = i32::MAX;
    let mut pcb_max = i32::MIN;
    let mut chip_min = i32::MAX;
    let mut chip_max = i32::MIN;
    for sensor in sensors.iter().filter(|sensor| sensor.state == 3) {
        count += 1;
        pcb_sum += i64::from(sensor.pcb_c);
        chip_sum += i64::from(sensor.chip_c);
        pcb_min = pcb_min.min(sensor.pcb_c);
        pcb_max = pcb_max.max(sensor.pcb_c);
        chip_min = chip_min.min(sensor.chip_c);
        chip_max = chip_max.max(sensor.chip_c);
    }
    if count == 0 {
        return Bm1489L7ChainTemperatureSummary::default();
    }
    Bm1489L7ChainTemperatureSummary {
        pcb: Bm1489L7TemperatureSummary {
            has_valid_sample: true,
            minimum_c: pcb_min,
            average_c: (pcb_sum / count) as i32,
            maximum_c: pcb_max,
        },
        chip: Bm1489L7TemperatureSummary {
            has_valid_sample: true,
            minimum_c: chip_min,
            average_c: (chip_sum / count) as i32,
            maximum_c: chip_max,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489L7ExternalChipTemperature {
    pub enabled: bool,
    pub temperature_c: f64,
}

/// Replays the optional external chip-temperature overlay in `FUN_00054210`
/// after its separate configuration/runtime gates have selected the branch.
/// Enabled f64 samples replace only chip min/average/max after truncation to
/// signed integers; the direct-sensor valid flag is deliberately preserved.
/// Finite and i32-range checks are clean fail-closed hardening.
pub fn bm1489_l7_apply_external_chip_temperature_overlay(
    mut direct: Bm1489L7ChainTemperatureSummary,
    overlay_branch_selected: bool,
    samples: &[Bm1489L7ExternalChipTemperature],
) -> Result<Bm1489L7ChainTemperatureSummary, Bm1489L7SensorInputError> {
    if !overlay_branch_selected {
        return Ok(direct);
    }
    let mut count = 0u32;
    let mut sum = 0.0f64;
    let mut minimum = i32::MAX;
    let mut maximum = i32::MIN;
    for sample in samples.iter().filter(|sample| sample.enabled) {
        if !sample.temperature_c.is_finite() {
            return Err(Bm1489L7SensorInputError::NonFiniteExternalTemperature);
        }
        if sample.temperature_c < f64::from(i32::MIN) || sample.temperature_c > f64::from(i32::MAX)
        {
            return Err(Bm1489L7SensorInputError::ExternalTemperatureOutOfRange);
        }
        count = count
            .checked_add(1)
            .ok_or(Bm1489L7SensorInputError::ExternalTemperatureOutOfRange)?;
        sum += sample.temperature_c;
        if !sum.is_finite() {
            return Err(Bm1489L7SensorInputError::ExternalTemperatureOutOfRange);
        }
        let truncated = sample.temperature_c.trunc() as i32;
        minimum = minimum.min(truncated);
        maximum = maximum.max(truncated);
    }
    if count != 0 {
        direct.chip.minimum_c = minimum;
        direct.chip.average_c = (sum / f64::from(count)).trunc() as i32;
        direct.chip.maximum_c = maximum;
    }
    Ok(direct)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7SensorAvailability {
    pub freshness: Bm1489L7SensorFreshnessDecision,
    /// Exact per-sensor field compared with value three by `FUN_00054d78`.
    pub invalid_policy_code: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7InvalidSensorDecision {
    Continue,
    ChainFailure,
}

/// Replays `FUN_00054d78` after the freshness helper has updated each sensor.
/// The first invalid sensor fails the chain when runtime state equals two or
/// that sensor's policy field equals three. Other invalid sensors are ignored
/// by this particular gate.
pub fn bm1489_l7_invalid_sensor_decision(
    runtime_state_is_two: bool,
    sensors: &[Bm1489L7SensorAvailability],
) -> Bm1489L7InvalidSensorDecision {
    if sensors.iter().any(|sensor| {
        !sensor.freshness.is_valid() && (runtime_state_is_two || sensor.invalid_policy_code == 3)
    }) {
        Bm1489L7InvalidSensorDecision::ChainFailure
    } else {
        Bm1489L7InvalidSensorDecision::Continue
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SensorAvailabilityMode {
    Standard,
    Alternate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7PostIsolationAvailabilityInput {
    pub mode: Bm1489L7SensorAvailabilityMode,
    /// Sum of `FUN_00052c40` across enumerated chains.
    pub active_chain_count: u32,
    /// Number of enumerated chains whose state field equals five.
    pub state_five_chain_count: u32,
    /// Miner-state `+0xe8`, used only by the standard branch.
    pub required_chain_count: u32,
    /// Sum of `FUN_00052c68`, used only by the alternate branch.
    pub alternate_eligible_count: u32,
    /// Whether the final `FUN_000fdb5c` gate returned nonzero.
    pub alternate_external_gate_nonzero: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7PostIsolationAvailabilityDecision {
    Continue,
    FatalSensorAvailability,
}

impl Bm1489L7PostIsolationAvailabilityDecision {
    pub const fn reason_code(self) -> Option<u32> {
        match self {
            Self::Continue => None,
            Self::FatalSensorAvailability => Some(BM1489_L7_REASON_SENSOR_AVAILABILITY),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7AvailabilityInputError {
    CountOverflow,
}

/// Replays `FUN_0005b6bc`, which is called after a chain is isolated for an
/// invalid required sensor. The standard branch requires active plus
/// state-five chains to reach the configured count. The alternate branch has
/// the stock-inverted shape: it fails only when its eligible count is nonzero
/// and the external gate returns zero.
pub fn bm1489_l7_post_isolation_availability_decision(
    input: Bm1489L7PostIsolationAvailabilityInput,
) -> Result<Bm1489L7PostIsolationAvailabilityDecision, Bm1489L7AvailabilityInputError> {
    let fatal = match input.mode {
        Bm1489L7SensorAvailabilityMode::Standard => {
            input
                .active_chain_count
                .checked_add(input.state_five_chain_count)
                .ok_or(Bm1489L7AvailabilityInputError::CountOverflow)?
                < input.required_chain_count
        }
        Bm1489L7SensorAvailabilityMode::Alternate => {
            input.alternate_eligible_count != 0 && !input.alternate_external_gate_nonzero
        }
    };
    Ok(if fatal {
        Bm1489L7PostIsolationAvailabilityDecision::FatalSensorAvailability
    } else {
        Bm1489L7PostIsolationAvailabilityDecision::Continue
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7CoolDownMode {
    Standard,
    Alternate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7CoolDownConfig {
    /// Fan setting restored after either cool-down route completes or fails.
    pub normal_fan_percent: i32,
    /// Configured cool-down fan setting before the alternate-mode division.
    pub cooling_fan_percent: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7CoolDownProfile {
    pub normal_fan_percent: i32,
    pub effective_cooling_fan_percent: i32,
    pub maximum_seconds: u32,
}

/// Replays the mode-dependent constants in `FUN_0005d3f0` and
/// `FUN_0005db80`. Alternate mode doubles the duration and divides the
/// configured cooling fan setting by two with signed truncation toward zero.
pub const fn bm1489_l7_cool_down_profile(
    mode: Bm1489L7CoolDownMode,
    config: Bm1489L7CoolDownConfig,
) -> Bm1489L7CoolDownProfile {
    match mode {
        Bm1489L7CoolDownMode::Standard => Bm1489L7CoolDownProfile {
            normal_fan_percent: config.normal_fan_percent,
            effective_cooling_fan_percent: config.cooling_fan_percent,
            maximum_seconds: BM1489_L7_COOL_DOWN_STANDARD_SECONDS,
        },
        Bm1489L7CoolDownMode::Alternate => Bm1489L7CoolDownProfile {
            normal_fan_percent: config.normal_fan_percent,
            effective_cooling_fan_percent: config.cooling_fan_percent / 2,
            maximum_seconds: BM1489_L7_COOL_DOWN_ALTERNATE_SECONDS,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7CoolDownChainState {
    /// Exact selected-chain record state at offset `+0x08`.
    pub state: u32,
    /// Exact selected-chain byte at offset `+0x21`. Its physical semantic is
    /// intentionally not inferred; stock XORs the full byte with one.
    pub byte_0x21: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7CoolDownRoute {
    PcbSpread,
    TimedFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7CoolDownInputError {
    StateFiveWeightOverflow,
    MissingInitialPcbRange,
    InvalidPcbRange,
    InsufficientPcbRanges,
}

/// Replays the route selector in `FUN_00061c24`. The PCB-spread helper is
/// selected when the sum of `(byte_0x21 ^ 1)` for state-five records exceeds
/// one, or when any selected record has state one or four. All other shapes
/// take the blind timed fallback.
pub fn bm1489_l7_select_cool_down_route(
    chains: &[Bm1489L7CoolDownChainState],
) -> Result<Bm1489L7CoolDownRoute, Bm1489L7CoolDownInputError> {
    let mut state_five_weight = 0_u32;
    for chain in chains {
        if chain.state == 5 {
            state_five_weight = state_five_weight
                .checked_add(u32::from(chain.byte_0x21 ^ 1))
                .ok_or(Bm1489L7CoolDownInputError::StateFiveWeightOverflow)?;
        }
    }
    if state_five_weight > 1 || chains.iter().any(|chain| matches!(chain.state, 1 | 4)) {
        Ok(Bm1489L7CoolDownRoute::PcbSpread)
    } else {
        Ok(Bm1489L7CoolDownRoute::TimedFallback)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7PcbRangeSample {
    /// `None` represents failure to obtain a valid global PCB minimum.
    pub minimum_c: Option<i32>,
    /// `None` represents failure to obtain a valid global PCB maximum.
    pub maximum_c: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7CoolDownOutcome {
    PcbSpreadBalanced,
    /// Stock exhausts the bounded loop and still returns helper success.
    PcbSpreadTimedOutButReportsSuccess,
    PcbRangeUnavailable,
    TimedFallbackCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7CoolDownReplay {
    pub route: Bm1489L7CoolDownRoute,
    pub outcome: Bm1489L7CoolDownOutcome,
    pub cooling_fan_request: Option<i32>,
    pub normal_fan_restore_request: Option<i32>,
    pub sensor_delay_count: u32,
    pub timed_fallback_delay_count: u32,
    pub elapsed_seconds: u32,
    /// Return from `FUN_0005d3f0`; the fallback helper is represented as zero.
    pub helper_return: i32,
    /// `FUN_00061c24` returns zero even after the helper failure branch.
    pub outer_return: i32,
    pub recorded_reason: Option<u32>,
    /// On helper failure the caller attempts to create its failure worker. A
    /// creation failure falls back to the observed shutdown coordinator.
    pub attempts_failure_worker: bool,
}

fn bm1489_l7_pcb_range_delta(
    sample: Bm1489L7PcbRangeSample,
) -> Result<Option<u32>, Bm1489L7CoolDownInputError> {
    let (Some(minimum_c), Some(maximum_c)) = (sample.minimum_c, sample.maximum_c) else {
        return Ok(None);
    };
    if minimum_c > maximum_c {
        return Err(Bm1489L7CoolDownInputError::InvalidPcbRange);
    }
    Ok(Some((i64::from(maximum_c) - i64::from(minimum_c)) as u32))
}

fn bm1489_l7_cool_down_replay_result(
    route: Bm1489L7CoolDownRoute,
    outcome: Bm1489L7CoolDownOutcome,
    cooling_fan_request: Option<i32>,
    normal_fan_restore_request: Option<i32>,
    sensor_delay_count: u32,
    timed_fallback_delay_count: u32,
    elapsed_seconds: u32,
) -> Bm1489L7CoolDownReplay {
    let failed = outcome == Bm1489L7CoolDownOutcome::PcbRangeUnavailable;
    Bm1489L7CoolDownReplay {
        route,
        outcome,
        cooling_fan_request,
        normal_fan_restore_request,
        sensor_delay_count,
        timed_fallback_delay_count,
        elapsed_seconds,
        helper_return: if failed { -1 } else { 0 },
        outer_return: 0,
        recorded_reason: failed.then_some(BM1489_L7_REASON_COOL_DOWN_FAILED),
        attempts_failure_worker: failed,
    }
}

/// Pure replay of the hardware-facing spine of `FUN_00061c24`,
/// `FUN_0005d3f0`, and `FUN_0005db80`. It does not perform fan I/O, sleep,
/// authenticate temperature samples, or prove that a completed stock loop is
/// thermally ready.
pub fn bm1489_l7_replay_cool_down(
    route: Bm1489L7CoolDownRoute,
    mode: Bm1489L7CoolDownMode,
    runtime_state_is_two: bool,
    config: Bm1489L7CoolDownConfig,
    pcb_ranges: &[Bm1489L7PcbRangeSample],
) -> Result<Bm1489L7CoolDownReplay, Bm1489L7CoolDownInputError> {
    let profile = bm1489_l7_cool_down_profile(mode, config);
    let normal_fan_restore_request = (!runtime_state_is_two).then_some(profile.normal_fan_percent);
    if route == Bm1489L7CoolDownRoute::TimedFallback {
        return Ok(bm1489_l7_cool_down_replay_result(
            route,
            Bm1489L7CoolDownOutcome::TimedFallbackCompleted,
            (!runtime_state_is_two).then_some(profile.effective_cooling_fan_percent),
            normal_fan_restore_request,
            0,
            profile.maximum_seconds / (BM1489_L7_COOL_DOWN_TIMED_STEP_DELAY_MS / 1_000),
            profile.maximum_seconds,
        ));
    }

    let initial = *pcb_ranges
        .first()
        .ok_or(Bm1489L7CoolDownInputError::MissingInitialPcbRange)?;
    let Some(initial_delta) = bm1489_l7_pcb_range_delta(initial)? else {
        return Ok(bm1489_l7_cool_down_replay_result(
            route,
            Bm1489L7CoolDownOutcome::PcbRangeUnavailable,
            None,
            normal_fan_restore_request,
            0,
            0,
            0,
        ));
    };
    if initial_delta <= BM1489_L7_COOL_DOWN_BALANCED_DELTA_MAX_C {
        return Ok(bm1489_l7_cool_down_replay_result(
            route,
            Bm1489L7CoolDownOutcome::PcbSpreadBalanced,
            None,
            normal_fan_restore_request,
            0,
            0,
            0,
        ));
    }

    let cooling_fan_request =
        (!runtime_state_is_two).then_some(profile.effective_cooling_fan_percent);
    let mut elapsed_seconds = 0_u32;
    let mut sensor_delay_count = 0_u32;
    for sample in &pcb_ranges[1..] {
        let Some(delta) = bm1489_l7_pcb_range_delta(*sample)? else {
            return Ok(bm1489_l7_cool_down_replay_result(
                route,
                Bm1489L7CoolDownOutcome::PcbRangeUnavailable,
                cooling_fan_request,
                normal_fan_restore_request,
                sensor_delay_count,
                0,
                elapsed_seconds,
            ));
        };
        if delta <= BM1489_L7_COOL_DOWN_BALANCED_DELTA_MAX_C {
            return Ok(bm1489_l7_cool_down_replay_result(
                route,
                Bm1489L7CoolDownOutcome::PcbSpreadBalanced,
                cooling_fan_request,
                normal_fan_restore_request,
                sensor_delay_count,
                0,
                elapsed_seconds,
            ));
        }
        sensor_delay_count += 1;
        elapsed_seconds += BM1489_L7_COOL_DOWN_SENSOR_SAMPLE_DELAY_MS / 1_000;
        if elapsed_seconds >= profile.maximum_seconds {
            return Ok(bm1489_l7_cool_down_replay_result(
                route,
                Bm1489L7CoolDownOutcome::PcbSpreadTimedOutButReportsSuccess,
                cooling_fan_request,
                normal_fan_restore_request,
                sensor_delay_count,
                0,
                elapsed_seconds,
            ));
        }
    }
    Err(Bm1489L7CoolDownInputError::InsufficientPcbRanges)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1489L7FanCapture {
    /// Persistent last observed RPM values for the four L7 callback slots.
    pub rpm_by_slot: [u32; BM1489_L7_FAN_SLOT_COUNT],
}

/// Replays the exact L7 capture worker `FUN_000fe4e8` for one four-word
/// cycle. Each tach word supplies `id = bits[10:8]` and `raw = bits[7:0]`.
/// IDs zero and one are swapped, IDs two and three are unchanged, and all
/// other IDs are ignored. Slots absent from a cycle retain their prior value.
pub const fn bm1489_l7_apply_fan_capture_cycle(
    previous: Bm1489L7FanCapture,
    hardware_selector_word: u32,
    tach_words: [u32; BM1489_L7_FAN_CAPTURE_WORDS_PER_CYCLE],
) -> Bm1489L7FanCapture {
    let multiplier = if hardware_selector_word as u16 == BM1489_L7_FAN_ALTERNATE_HARDWARE_WORD_LOW16
    {
        BM1489_L7_FAN_ALTERNATE_RPM_MULTIPLIER
    } else {
        BM1489_L7_FAN_DEFAULT_RPM_MULTIPLIER
    };
    let mut next = previous;
    let mut index = 0;
    while index < tach_words.len() {
        let word = tach_words[index];
        let wire_id = ((word >> 8) & 7) as usize;
        if wire_id < BM1489_L7_FAN_SLOT_COUNT {
            let slot = if wire_id == 0 {
                1
            } else if wire_id == 1 {
                0
            } else {
                wire_id
            };
            next.rpm_by_slot[slot] = (word & 0xff) * multiplier;
        }
        index += 1;
    }
    next
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1489L7FanSlotState {
    /// Exact inverted stock latch: false means alive and true means lost.
    pub lost: bool,
    pub stored_rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7FanLivenessState {
    pub slots: [Bm1489L7FanSlotState; BM1489_L7_FAN_SLOT_COUNT],
    pub alive_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1489L7FanReadPair {
    pub first_rpm: u32,
    pub second_rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7FanStateError {
    InvalidConfiguredFanCount,
    InvalidPwmPercent,
    InvalidNormalizationThreshold,
    InconsistentAliveCount,
}

/// Replays one `FUN_00072384` update over the configured L7 fan slots.
/// Stock normalizes a first read at or above `normalization_threshold_rpm` to
/// that threshold; only a lower first read causes the immediate second read
/// to become the stored observation. An observation in the inclusive range
/// `1..=threshold*3` is alive. A bad observation removes an already-alive fan
/// only when the current PWM is at least ten percent; a good observation
/// restores a previously-lost fan without a PWM gate.
pub fn bm1489_l7_update_fan_liveness(
    previous: Bm1489L7FanLivenessState,
    configured_fans: usize,
    current_pwm_percent: u32,
    normalization_threshold_rpm: u32,
    reads: [Bm1489L7FanReadPair; BM1489_L7_FAN_SLOT_COUNT],
) -> Result<Bm1489L7FanLivenessState, Bm1489L7FanStateError> {
    if configured_fans == 0 || configured_fans > BM1489_L7_FAN_SLOT_COUNT {
        return Err(Bm1489L7FanStateError::InvalidConfiguredFanCount);
    }
    if current_pwm_percent > 100 {
        return Err(Bm1489L7FanStateError::InvalidPwmPercent);
    }
    let upper_valid_rpm = normalization_threshold_rpm
        .checked_mul(3)
        .filter(|_| normalization_threshold_rpm != 0)
        .ok_or(Bm1489L7FanStateError::InvalidNormalizationThreshold)?;
    let counted_alive = previous.slots[..configured_fans]
        .iter()
        .filter(|slot| !slot.lost)
        .count() as u32;
    if counted_alive != previous.alive_count {
        return Err(Bm1489L7FanStateError::InconsistentAliveCount);
    }

    let mut next = previous;
    for index in 0..configured_fans {
        let pair = reads[index];
        let observed = if pair.first_rpm >= normalization_threshold_rpm {
            normalization_threshold_rpm
        } else {
            pair.second_rpm
        };
        let is_alive = observed >= 1 && observed <= upper_valid_rpm;
        let slot = &mut next.slots[index];
        slot.stored_rpm = observed;
        if is_alive && slot.lost {
            slot.lost = false;
            next.alive_count += 1;
        } else if !is_alive
            && current_pwm_percent >= BM1489_L7_FAN_LOSS_PWM_FLOOR_PERCENT
            && !slot.lost
        {
            slot.lost = true;
            next.alive_count -= 1;
        }
    }
    Ok(next)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7ThermalLimits {
    pub pcb_danger_c: i32,
    pub chip_danger_c: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7OverheatDecision {
    Continue,
    PcbAtOrAboveLimit,
    ChipAtOrAboveLimit,
}

impl Bm1489L7OverheatDecision {
    pub const fn reason_code(self) -> Option<u32> {
        match self {
            Self::Continue => None,
            Self::PcbAtOrAboveLimit => Some(BM1489_L7_REASON_PCB_OVERHEAT),
            Self::ChipAtOrAboveLimit => Some(BM1489_L7_REASON_CHIP_OVERHEAT),
        }
    }

    pub const fn begins_global_shutdown(self) -> bool {
        !matches!(self, Self::Continue)
    }
}

/// Exact comparison order from `FUN_00054a3c`: PCB is checked first and both
/// danger limits are inclusive. Consequently, a simultaneous violation is
/// classified as PCB overtemperature.
pub const fn bm1489_l7_overheat_decision(
    pcb_max_c: i32,
    chip_max_c: i32,
    limits: Bm1489L7ThermalLimits,
) -> Bm1489L7OverheatDecision {
    if pcb_max_c >= limits.pcb_danger_c {
        Bm1489L7OverheatDecision::PcbAtOrAboveLimit
    } else if chip_max_c >= limits.chip_danger_c {
        Bm1489L7OverheatDecision::ChipAtOrAboveLimit
    } else {
        Bm1489L7OverheatDecision::Continue
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489L7RuntimeFanInput {
    /// Exact state-value exclusion in `FUN_00073e08`.
    pub runtime_state_is_two: bool,
    /// Exact byte gate at miner state `+0x24`.
    pub fan_fault_monitoring_enabled: bool,
    pub elapsed_since_monitor_epoch_seconds: f64,
    pub alive_fans: u32,
    pub minimum_fans: u32,
    pub configured_fans: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7FanDecision {
    NotArmed,
    GracePeriod,
    Continue,
    FatalShortfall,
}

impl Bm1489L7FanDecision {
    pub const fn reason_code(self) -> Option<u32> {
        match self {
            Self::FatalShortfall => Some(BM1489_L7_REASON_FAN_SHORTFALL),
            _ => None,
        }
    }

    pub const fn begins_global_shutdown(self) -> bool {
        matches!(self, Self::FatalShortfall)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7FanInputError {
    InvalidFanCounts,
    AliveCountExceedsConfigured,
    NonFiniteElapsedTime,
    TooManyStartupSamples,
}

fn validate_fan_counts(
    alive_fans: u32,
    minimum_fans: u32,
    configured_fans: u32,
) -> Result<(), Bm1489L7FanInputError> {
    if configured_fans == 0 || minimum_fans == 0 || minimum_fans > configured_fans {
        return Err(Bm1489L7FanInputError::InvalidFanCounts);
    }
    if alive_fans > configured_fans {
        return Err(Bm1489L7FanInputError::AliveCountExceedsConfigured);
    }
    Ok(())
}

/// Replays the runtime shortfall predicate after the separate stateful tach
/// updater has produced `alive_fans`. Count and finite-time validation are
/// deliberate clean fail-closed checks around the stock comparison.
pub fn bm1489_l7_runtime_fan_decision(
    input: Bm1489L7RuntimeFanInput,
) -> Result<Bm1489L7FanDecision, Bm1489L7FanInputError> {
    validate_fan_counts(input.alive_fans, input.minimum_fans, input.configured_fans)?;
    if !input.elapsed_since_monitor_epoch_seconds.is_finite() {
        return Err(Bm1489L7FanInputError::NonFiniteElapsedTime);
    }
    if input.runtime_state_is_two || !input.fan_fault_monitoring_enabled {
        return Ok(Bm1489L7FanDecision::NotArmed);
    }
    if input.elapsed_since_monitor_epoch_seconds < BM1489_L7_RUNTIME_FAN_GRACE_SECONDS {
        return Ok(Bm1489L7FanDecision::GracePeriod);
    }
    if input.alive_fans < input.minimum_fans {
        Ok(Bm1489L7FanDecision::FatalShortfall)
    } else {
        Ok(Bm1489L7FanDecision::Continue)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7StartupFanDecision {
    NeedMoreSamples,
    AllConfiguredFansObserved,
    MinimumFanCountObserved,
    FatalShortfall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7StartupFanPlan {
    pub decision: Bm1489L7StartupFanDecision,
    pub samples_consumed: usize,
    pub tail_delays_consumed: usize,
}

impl Bm1489L7StartupFanPlan {
    pub const fn begins_global_shutdown(&self) -> bool {
        matches!(self.decision, Bm1489L7StartupFanDecision::FatalShortfall)
    }

    pub const fn reason_code(&self) -> Option<u32> {
        if self.begins_global_shutdown() {
            Some(BM1489_L7_REASON_FAN_SHORTFALL)
        } else {
            None
        }
    }
}

/// Replays `FUN_0006f5b4`'s startup sampling boundary. Each supplied count is
/// the result after one tach update and one 1,000-ms delay. Stock exits early
/// only when all configured fans are alive. After the fifteenth sample it
/// admits the configured minimum, otherwise it enters global shutdown.
pub fn bm1489_l7_startup_fan_plan(
    alive_samples: &[u32],
    minimum_fans: u32,
    configured_fans: u32,
) -> Result<Bm1489L7StartupFanPlan, Bm1489L7FanInputError> {
    if alive_samples.len() > BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT {
        return Err(Bm1489L7FanInputError::TooManyStartupSamples);
    }
    validate_fan_counts(0, minimum_fans, configured_fans)?;

    for (index, alive) in alive_samples.iter().copied().enumerate() {
        validate_fan_counts(alive, minimum_fans, configured_fans)?;
        if alive >= configured_fans {
            let consumed = index + 1;
            return Ok(Bm1489L7StartupFanPlan {
                decision: Bm1489L7StartupFanDecision::AllConfiguredFansObserved,
                samples_consumed: consumed,
                tail_delays_consumed: consumed,
            });
        }
    }

    if alive_samples.len() < BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT {
        return Ok(Bm1489L7StartupFanPlan {
            decision: Bm1489L7StartupFanDecision::NeedMoreSamples,
            samples_consumed: alive_samples.len(),
            tail_delays_consumed: alive_samples.len(),
        });
    }

    let last_alive = alive_samples[BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT - 1];
    Ok(Bm1489L7StartupFanPlan {
        decision: if last_alive < minimum_fans {
            Bm1489L7StartupFanDecision::FatalShortfall
        } else {
            Bm1489L7StartupFanDecision::MinimumFanCountObserved
        },
        samples_consumed: BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT,
        tail_delays_consumed: BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7PowerCallbackError {
    UnsupportedChain,
}

/// Exact L7 callback body installed for the stock `(chain, state)` operation.
/// With the shutdown path's nonzero state argument it reads the selector,
/// sets one low chain bit, and invokes the setter. The setter has no result or
/// explicit readback in this path.
pub const fn bm1489_l7_power_callback_set_bit(
    chain: u32,
    observed_selector_value: u32,
) -> Result<u32, Bm1489L7PowerCallbackError> {
    if chain >= BM1489_L7_POWER_CONTROL_CHAIN_LIMIT {
        return Err(Bm1489L7PowerCallbackError::UnsupportedChain);
    }
    Ok(observed_selector_value | (1u32 << chain))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7PowerOffDisposition {
    GuardRejected,
    RequestsIssued,
}

pub const BM1489_L7_POWER_TRANSITION_GPIO: u32 = 907;
pub const BM1489_L7_POWER_TRANSITION_OFF_VALUE: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7PowerTransitionInput {
    /// Exact callback state-byte observation. Only value one causes the L7
    /// callback to attempt the GPIO write; every other value returns success.
    pub gpio_initialized_flag: u8,
    /// Caller-supplied result of the write helper when a write is attempted.
    /// This is replay evidence, not an authenticated hardware observation.
    pub gpio_write_succeeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7PowerTransitionResult {
    pub gpio_write_attempted: bool,
    pub coordinator_may_continue: bool,
}

/// Replays the exact L7 callback installed behind `FUN_000f023c`.
///
/// `FUN_00104864` attempts `GPIO 907 <- 1` only when its state byte equals
/// one. A failed attempted write returns `-1`; a successful write or any
/// other state-byte value returns zero. The physical load and electrical
/// polarity of GPIO 907 are intentionally not inferred here.
pub const fn bm1489_l7_power_transition_result(
    input: Bm1489L7PowerTransitionInput,
) -> Bm1489L7PowerTransitionResult {
    let gpio_write_attempted = input.gpio_initialized_flag == 1;
    Bm1489L7PowerTransitionResult {
        gpio_write_attempted,
        coordinator_may_continue: !gpio_write_attempted || input.gpio_write_succeeded,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7PowerOffStep {
    InvokePowerTransitionCallback {
        gpio: u32,
        requested_value: u8,
        write_attempted: bool,
    },
    InvokeChainCallback {
        chain: u32,
    },
    ClearMinerPowerState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1489L7PowerOffPlan {
    pub disposition: Bm1489L7PowerOffDisposition,
    pub steps: Vec<Bm1489L7PowerOffStep>,
    pub unsupported_chain_callbacks: u32,
}

impl Bm1489L7PowerOffPlan {
    pub const fn proves_electrical_off(&self) -> bool {
        false
    }

    pub const fn admits_hardware_io(&self) -> bool {
        false
    }
}

/// Replays the final stock power-off coordinator `FUN_00067878`. The
/// per-chain callback errors for indices four and above are ignored by stock;
/// they are counted here so a clean executor cannot mistake requests for
/// verified shutdown.
pub fn bm1489_l7_power_off_plan(
    enumerated_chain_count: u32,
    power_transition: Bm1489L7PowerTransitionInput,
) -> Bm1489L7PowerOffPlan {
    let transition = bm1489_l7_power_transition_result(power_transition);
    let mut steps = vec![Bm1489L7PowerOffStep::InvokePowerTransitionCallback {
        gpio: BM1489_L7_POWER_TRANSITION_GPIO,
        requested_value: BM1489_L7_POWER_TRANSITION_OFF_VALUE,
        write_attempted: transition.gpio_write_attempted,
    }];
    if !transition.coordinator_may_continue {
        return Bm1489L7PowerOffPlan {
            disposition: Bm1489L7PowerOffDisposition::GuardRejected,
            steps,
            unsupported_chain_callbacks: 0,
        };
    }

    for chain in 0..enumerated_chain_count {
        steps.push(Bm1489L7PowerOffStep::InvokeChainCallback { chain });
    }
    steps.push(Bm1489L7PowerOffStep::ClearMinerPowerState);
    Bm1489L7PowerOffPlan {
        disposition: Bm1489L7PowerOffDisposition::RequestsIssued,
        steps,
        unsupported_chain_callbacks: enumerated_chain_count
            .saturating_sub(BM1489_L7_POWER_CONTROL_CHAIN_LIMIT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Bm1489L7ThermalLimits = Bm1489L7ThermalLimits {
        pcb_danger_c: 80,
        chip_danger_c: 90,
    };

    fn runtime_fans() -> Bm1489L7RuntimeFanInput {
        Bm1489L7RuntimeFanInput {
            runtime_state_is_two: false,
            fan_fault_monitoring_enabled: true,
            elapsed_since_monitor_epoch_seconds: 10.0,
            alive_fans: 4,
            minimum_fans: 4,
            configured_fans: 4,
        }
    }

    #[test]
    fn recovered_constants_and_authority_boundary_are_pinned() {
        assert_eq!(BM1489_L7_RUNTIME_FAN_GRACE_SECONDS, 10.0);
        assert_eq!(BM1489_L7_RUNTIME_LOOP_TAIL_DELAY_MS, 1_000);
        assert_eq!(BM1489_L7_STARTUP_FAN_SAMPLE_LIMIT, 15);
        assert_eq!(BM1489_L7_STARTUP_FAN_SAMPLE_DELAY_MS, 1_000);
        assert_eq!(BM1489_L7_FAN_CAPTURE_WORDS_PER_CYCLE, 4);
        assert_eq!(BM1489_L7_FAN_CAPTURE_TAIL_DELAY_MS, 1_000);
        assert_eq!(BM1489_L7_FAN_SLOT_COUNT, 4);
        assert_eq!(BM1489_L7_FAN_DEFAULT_RPM_MULTIPLIER, 120);
        assert_eq!(BM1489_L7_FAN_ALTERNATE_RPM_MULTIPLIER, 240);
        assert_eq!(BM1489_L7_FAN_ALTERNATE_HARDWARE_WORD_LOW16, 0xb025);
        assert_eq!(BM1489_L7_FAN_LOSS_PWM_FLOOR_PERCENT, 10);
        assert_eq!(BM1489_L7_SENSOR_TYPE_145_STALE_AFTER_SECONDS, 25.0);
        assert_eq!(BM1489_L7_SENSOR_TYPE_23_STALE_AFTER_SECONDS, 20.0);
        assert_eq!(BM1489_L7_REASON_FAN_SHORTFALL, 0x07d4);
        assert_eq!(BM1489_L7_REASON_SENSOR_AVAILABILITY, 0x07d6);
        assert_eq!(BM1489_L7_REASON_COOL_DOWN_FAILED, 0x0bb9);
        assert_eq!(BM1489_L7_REASON_PCB_OVERHEAT, 0x0bba);
        assert_eq!(BM1489_L7_REASON_CHIP_OVERHEAT, 0x0bbb);
        assert_eq!(BM1489_L7_COOL_DOWN_BALANCED_DELTA_MAX_C, 5);
        assert_eq!(BM1489_L7_COOL_DOWN_SENSOR_SAMPLE_DELAY_MS, 5_000);
        assert_eq!(BM1489_L7_COOL_DOWN_TIMED_STEP_DELAY_MS, 10_000);
        assert_eq!(BM1489_L7_COOL_DOWN_STANDARD_SECONDS, 120);
        assert_eq!(BM1489_L7_COOL_DOWN_ALTERNATE_SECONDS, 240);
        assert_eq!(BM1489_L7_POWER_TRANSITION_GPIO, 907);
        assert_eq!(BM1489_L7_POWER_TRANSITION_OFF_VALUE, 1);
        assert_eq!(BM1489_L7_POWER_CONTROL_SELECTOR, 0x0d);
        assert_eq!(BM1489_L7_POWER_CONTROL_CHAIN_LIMIT, 4);
        assert!(!BM1489_L7_THERMAL_INPUTS_AUTHENTICATED);
        assert!(!BM1489_L7_POWER_WRITE_READBACK_VERIFIED);
        assert!(!BM1489_L7_ELECTRICAL_OFF_PROVEN);
        assert!(!BM1489_L7_SAFETY_AUTHORIZES_HARDWARE_IO);
        assert!(!BM1489_L7_SAFETY_AUTHORIZES_MINING);
    }

    #[test]
    fn sensor_freshness_uses_strict_release_specific_kind_boundaries() {
        for kind in [1, 4, 5] {
            assert_eq!(
                bm1489_l7_sensor_freshness(3, kind, 25.0).unwrap(),
                Bm1489L7SensorFreshnessDecision::Fresh
            );
            assert_eq!(
                bm1489_l7_sensor_freshness(3, kind, 25.000_001).unwrap(),
                Bm1489L7SensorFreshnessDecision::Invalidated
            );
        }
        for kind in [2, 3] {
            assert_eq!(
                bm1489_l7_sensor_freshness(3, kind, 20.0).unwrap(),
                Bm1489L7SensorFreshnessDecision::Fresh
            );
            assert_eq!(
                bm1489_l7_sensor_freshness(3, kind, 20.000_001).unwrap(),
                Bm1489L7SensorFreshnessDecision::Invalidated
            );
        }
        assert_eq!(
            bm1489_l7_sensor_freshness(3, 99, 1_000_000.0).unwrap(),
            Bm1489L7SensorFreshnessDecision::Fresh
        );
    }

    #[test]
    fn sensor_freshness_preserves_already_invalid_and_rejects_time_forgery() {
        assert_eq!(
            bm1489_l7_sensor_freshness(0, 1, 0.0).unwrap(),
            Bm1489L7SensorFreshnessDecision::AlreadyInvalid
        );
        assert_eq!(
            bm1489_l7_sensor_freshness(3, 1, f64::NAN),
            Err(Bm1489L7SensorInputError::NonFiniteElapsedTime)
        );
        assert_eq!(
            bm1489_l7_sensor_freshness(3, 1, -0.001),
            Err(Bm1489L7SensorInputError::NegativeElapsedTime)
        );
    }

    fn sensor_record(kind: u32) -> Bm1489L7SensorRecordState {
        Bm1489L7SensorRecordState {
            state: 2,
            sensor_kind: kind,
            subtract_64_mode: false,
            chip_offset_c: 7,
            previous_sample_initialized: false,
            previous_pcb_c: 0,
            pcb_c: 0,
            chip_c: 0,
            consecutive_failures: 0,
        }
    }

    #[test]
    fn successful_sensor_read_pins_signed_byte_and_wrapped_subtract_64_decodes() {
        let signed = bm1489_l7_apply_sensor_read_success(sensor_record(1), 0xff).unwrap();
        assert_eq!(signed.disposition, Bm1489L7SensorReadDisposition::Applied);
        assert_eq!(signed.state.state, 3);
        assert_eq!(signed.state.pcb_c, -1);
        assert_eq!(signed.state.chip_c, 6);
        assert_eq!(signed.state.previous_pcb_c, -1);

        let shifted = bm1489_l7_apply_sensor_read_success(sensor_record(2), 0).unwrap();
        assert_eq!(shifted.state.pcb_c, -64);
        assert_eq!(shifted.state.chip_c, -57);
        let wrapped = bm1489_l7_apply_sensor_read_success(sensor_record(2), 192).unwrap();
        assert_eq!(wrapped.state.pcb_c, -128);
    }

    #[test]
    fn chip_offset_selector_uses_primary_only_for_exact_zero() {
        assert_eq!(bm1489_l7_select_chip_offset_c(7, -3, false), 7);
        assert_eq!(bm1489_l7_select_chip_offset_c(7, -3, true), -3);
    }

    #[test]
    fn kind_five_jump_filter_is_31_degrees_and_outer_wrapper_still_succeeds() {
        let previous = Bm1489L7SensorRecordState {
            state: 3,
            previous_sample_initialized: true,
            previous_pcb_c: 20,
            pcb_c: 20,
            chip_c: 27,
            ..sensor_record(5)
        };
        let equality = bm1489_l7_apply_sensor_read_success(previous, 50).unwrap();
        assert_eq!(equality.disposition, Bm1489L7SensorReadDisposition::Applied);
        assert_eq!(equality.state.pcb_c, 50);
        assert_eq!(equality.state.previous_pcb_c, 20);

        let rejected = bm1489_l7_apply_sensor_read_success(previous, 51).unwrap();
        assert_eq!(
            rejected.disposition,
            Bm1489L7SensorReadDisposition::KindFiveJumpRejectedButWrapperReportsSuccess
        );
        assert_eq!(rejected.state, previous);
    }

    #[test]
    fn third_consecutive_sensor_failure_invalidates_and_success_resets_counter() {
        let first = bm1489_l7_apply_sensor_read_failure(sensor_record(1)).unwrap();
        assert_eq!(first.state.state, 2);
        assert_eq!(first.state.consecutive_failures, 1);
        let second = bm1489_l7_apply_sensor_read_failure(first.state).unwrap();
        assert_eq!(second.state.state, 2);
        assert_eq!(second.state.consecutive_failures, 2);
        let third = bm1489_l7_apply_sensor_read_failure(second.state).unwrap();
        assert_eq!(third.state.state, 0);
        assert_eq!(third.state.consecutive_failures, 3);
        assert_eq!(
            third.disposition,
            Bm1489L7SensorReadDisposition::ThirdConsecutiveFailureInvalidated
        );
        assert_eq!(
            bm1489_l7_apply_sensor_read_success(third.state, 40),
            Err(Bm1489L7SensorReadError::AlreadyInvalid)
        );

        let recovered = bm1489_l7_apply_sensor_read_success(second.state, 40).unwrap();
        assert_eq!(recovered.state.consecutive_failures, 0);
        assert_eq!(recovered.state.state, 3);
    }

    #[test]
    fn failed_sensor_read_refuses_invalid_state_and_counter_overflow() {
        assert_eq!(
            bm1489_l7_apply_sensor_read_failure(Bm1489L7SensorRecordState {
                state: 0,
                ..sensor_record(1)
            }),
            Err(Bm1489L7SensorReadError::AlreadyInvalid)
        );
        assert_eq!(
            bm1489_l7_apply_sensor_read_failure(Bm1489L7SensorRecordState {
                consecutive_failures: u32::MAX,
                ..sensor_record(1)
            }),
            Err(Bm1489L7SensorReadError::FailureCounterOverflow)
        );
    }

    #[test]
    fn temperature_aggregation_uses_only_state_three_and_truncates_toward_zero() {
        let summary = bm1489_l7_aggregate_direct_sensor_temperatures(&[
            Bm1489L7SensorObservation {
                state: 3,
                pcb_c: -2,
                chip_c: 90,
            },
            Bm1489L7SensorObservation {
                state: 2,
                pcb_c: 1_000,
                chip_c: 1_000,
            },
            Bm1489L7SensorObservation {
                state: 3,
                pcb_c: 1,
                chip_c: 93,
            },
        ]);
        assert_eq!(
            summary.pcb,
            Bm1489L7TemperatureSummary {
                has_valid_sample: true,
                minimum_c: -2,
                average_c: 0,
                maximum_c: 1,
            }
        );
        assert_eq!(
            summary.chip,
            Bm1489L7TemperatureSummary {
                has_valid_sample: true,
                minimum_c: 90,
                average_c: 91,
                maximum_c: 93,
            }
        );
    }

    #[test]
    fn temperature_aggregation_publishes_zeroes_when_no_state_three_exists() {
        let summary = bm1489_l7_aggregate_direct_sensor_temperatures(&[
            Bm1489L7SensorObservation {
                state: 0,
                pcb_c: 80,
                chip_c: 90,
            },
            Bm1489L7SensorObservation {
                state: 2,
                pcb_c: 81,
                chip_c: 91,
            },
        ]);
        assert_eq!(summary, Bm1489L7ChainTemperatureSummary::default());
    }

    #[test]
    fn external_chip_overlay_replaces_only_chip_scalars_and_preserves_valid_flag() {
        let direct = bm1489_l7_aggregate_direct_sensor_temperatures(&[Bm1489L7SensorObservation {
            state: 3,
            pcb_c: 40,
            chip_c: 60,
        }]);
        let overlaid = bm1489_l7_apply_external_chip_temperature_overlay(
            direct,
            true,
            &[
                Bm1489L7ExternalChipTemperature {
                    enabled: true,
                    temperature_c: 50.9,
                },
                Bm1489L7ExternalChipTemperature {
                    enabled: false,
                    temperature_c: 1_000.0,
                },
                Bm1489L7ExternalChipTemperature {
                    enabled: true,
                    temperature_c: -2.9,
                },
            ],
        )
        .unwrap();
        assert_eq!(overlaid.pcb, direct.pcb);
        assert_eq!(
            overlaid.chip,
            Bm1489L7TemperatureSummary {
                has_valid_sample: true,
                minimum_c: -2,
                average_c: 24,
                maximum_c: 50,
            }
        );

        let no_direct = bm1489_l7_apply_external_chip_temperature_overlay(
            Bm1489L7ChainTemperatureSummary::default(),
            true,
            &[Bm1489L7ExternalChipTemperature {
                enabled: true,
                temperature_c: 70.0,
            }],
        )
        .unwrap();
        assert!(!no_direct.chip.has_valid_sample);
        assert_eq!(no_direct.chip.minimum_c, 70);
        assert_eq!(no_direct.chip.average_c, 70);
        assert_eq!(no_direct.chip.maximum_c, 70);
    }

    #[test]
    fn external_chip_overlay_is_gated_and_rejects_nonfinite_or_out_of_range_values() {
        let direct = Bm1489L7ChainTemperatureSummary::default();
        assert_eq!(
            bm1489_l7_apply_external_chip_temperature_overlay(
                direct,
                false,
                &[Bm1489L7ExternalChipTemperature {
                    enabled: true,
                    temperature_c: f64::NAN,
                }],
            )
            .unwrap(),
            direct
        );
        assert_eq!(
            bm1489_l7_apply_external_chip_temperature_overlay(
                direct,
                true,
                &[Bm1489L7ExternalChipTemperature {
                    enabled: true,
                    temperature_c: f64::INFINITY,
                }],
            ),
            Err(Bm1489L7SensorInputError::NonFiniteExternalTemperature)
        );
        assert_eq!(
            bm1489_l7_apply_external_chip_temperature_overlay(
                direct,
                true,
                &[Bm1489L7ExternalChipTemperature {
                    enabled: true,
                    temperature_c: f64::from(i32::MAX) + 1.0,
                }],
            ),
            Err(Bm1489L7SensorInputError::ExternalTemperatureOutOfRange)
        );
    }

    #[test]
    fn invalid_sensor_gate_keeps_runtime_state_and_policy_code_distinct() {
        let optional_invalid = [Bm1489L7SensorAvailability {
            freshness: Bm1489L7SensorFreshnessDecision::Invalidated,
            invalid_policy_code: 2,
        }];
        assert_eq!(
            bm1489_l7_invalid_sensor_decision(false, &optional_invalid),
            Bm1489L7InvalidSensorDecision::Continue
        );
        assert_eq!(
            bm1489_l7_invalid_sensor_decision(true, &optional_invalid),
            Bm1489L7InvalidSensorDecision::ChainFailure
        );

        let required_invalid = [Bm1489L7SensorAvailability {
            freshness: Bm1489L7SensorFreshnessDecision::AlreadyInvalid,
            invalid_policy_code: 3,
        }];
        assert_eq!(
            bm1489_l7_invalid_sensor_decision(false, &required_invalid),
            Bm1489L7InvalidSensorDecision::ChainFailure
        );
        let fresh_required = [Bm1489L7SensorAvailability {
            freshness: Bm1489L7SensorFreshnessDecision::Fresh,
            invalid_policy_code: 3,
        }];
        assert_eq!(
            bm1489_l7_invalid_sensor_decision(true, &fresh_required),
            Bm1489L7InvalidSensorDecision::Continue
        );
    }

    #[test]
    fn standard_post_isolation_availability_uses_active_plus_state_five_count() {
        let input = Bm1489L7PostIsolationAvailabilityInput {
            mode: Bm1489L7SensorAvailabilityMode::Standard,
            active_chain_count: 2,
            state_five_chain_count: 1,
            required_chain_count: 3,
            alternate_eligible_count: 0,
            alternate_external_gate_nonzero: false,
        };
        assert_eq!(
            bm1489_l7_post_isolation_availability_decision(input).unwrap(),
            Bm1489L7PostIsolationAvailabilityDecision::Continue
        );

        let short = Bm1489L7PostIsolationAvailabilityInput {
            required_chain_count: 4,
            ..input
        };
        let decision = bm1489_l7_post_isolation_availability_decision(short).unwrap();
        assert_eq!(
            decision,
            Bm1489L7PostIsolationAvailabilityDecision::FatalSensorAvailability
        );
        assert_eq!(
            decision.reason_code(),
            Some(BM1489_L7_REASON_SENSOR_AVAILABILITY)
        );

        assert_eq!(
            bm1489_l7_post_isolation_availability_decision(
                Bm1489L7PostIsolationAvailabilityInput {
                    active_chain_count: u32::MAX,
                    state_five_chain_count: 1,
                    ..input
                }
            ),
            Err(Bm1489L7AvailabilityInputError::CountOverflow)
        );
    }

    #[test]
    fn alternate_post_isolation_availability_pins_inverted_external_gate_shape() {
        let no_eligible = Bm1489L7PostIsolationAvailabilityInput {
            mode: Bm1489L7SensorAvailabilityMode::Alternate,
            active_chain_count: u32::MAX,
            state_five_chain_count: u32::MAX,
            required_chain_count: u32::MAX,
            alternate_eligible_count: 0,
            alternate_external_gate_nonzero: false,
        };
        assert_eq!(
            bm1489_l7_post_isolation_availability_decision(no_eligible).unwrap(),
            Bm1489L7PostIsolationAvailabilityDecision::Continue
        );

        let gate_passes = Bm1489L7PostIsolationAvailabilityInput {
            alternate_eligible_count: 1,
            alternate_external_gate_nonzero: true,
            ..no_eligible
        };
        assert_eq!(
            bm1489_l7_post_isolation_availability_decision(gate_passes).unwrap(),
            Bm1489L7PostIsolationAvailabilityDecision::Continue
        );

        let gate_fails = Bm1489L7PostIsolationAvailabilityInput {
            alternate_external_gate_nonzero: false,
            ..gate_passes
        };
        assert_eq!(
            bm1489_l7_post_isolation_availability_decision(gate_fails).unwrap(),
            Bm1489L7PostIsolationAvailabilityDecision::FatalSensorAvailability
        );
    }

    const COOL_DOWN_CONFIG: Bm1489L7CoolDownConfig = Bm1489L7CoolDownConfig {
        normal_fan_percent: 30,
        cooling_fan_percent: 81,
    };

    const UNBALANCED_PCB_RANGE: Bm1489L7PcbRangeSample = Bm1489L7PcbRangeSample {
        minimum_c: Some(40),
        maximum_c: Some(46),
    };

    #[test]
    fn cool_down_profile_doubles_time_and_halves_fan_with_signed_truncation() {
        assert_eq!(
            bm1489_l7_cool_down_profile(Bm1489L7CoolDownMode::Standard, COOL_DOWN_CONFIG),
            Bm1489L7CoolDownProfile {
                normal_fan_percent: 30,
                effective_cooling_fan_percent: 81,
                maximum_seconds: 120,
            }
        );
        assert_eq!(
            bm1489_l7_cool_down_profile(
                Bm1489L7CoolDownMode::Alternate,
                Bm1489L7CoolDownConfig {
                    cooling_fan_percent: -81,
                    ..COOL_DOWN_CONFIG
                }
            ),
            Bm1489L7CoolDownProfile {
                normal_fan_percent: 30,
                effective_cooling_fan_percent: -40,
                maximum_seconds: 240,
            }
        );
    }

    #[test]
    fn cool_down_route_pins_state_five_weight_and_state_one_four_override() {
        assert_eq!(
            bm1489_l7_select_cool_down_route(&[Bm1489L7CoolDownChainState {
                state: 5,
                byte_0x21: 0,
            }])
            .unwrap(),
            Bm1489L7CoolDownRoute::TimedFallback
        );
        assert_eq!(
            bm1489_l7_select_cool_down_route(&[
                Bm1489L7CoolDownChainState {
                    state: 5,
                    byte_0x21: 0,
                },
                Bm1489L7CoolDownChainState {
                    state: 5,
                    byte_0x21: 0,
                },
            ])
            .unwrap(),
            Bm1489L7CoolDownRoute::PcbSpread
        );
        for state in [1, 4] {
            assert_eq!(
                bm1489_l7_select_cool_down_route(&[Bm1489L7CoolDownChainState {
                    state,
                    byte_0x21: 1,
                }])
                .unwrap(),
                Bm1489L7CoolDownRoute::PcbSpread
            );
        }
        assert_eq!(
            bm1489_l7_select_cool_down_route(&[Bm1489L7CoolDownChainState {
                state: 5,
                byte_0x21: 2,
            }])
            .unwrap(),
            Bm1489L7CoolDownRoute::PcbSpread
        );
    }

    #[test]
    fn pcb_spread_equality_completes_without_requesting_cooling_fan() {
        let replay = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::PcbSpread,
            Bm1489L7CoolDownMode::Standard,
            false,
            COOL_DOWN_CONFIG,
            &[Bm1489L7PcbRangeSample {
                minimum_c: Some(40),
                maximum_c: Some(45),
            }],
        )
        .unwrap();
        assert_eq!(replay.outcome, Bm1489L7CoolDownOutcome::PcbSpreadBalanced);
        assert_eq!(replay.cooling_fan_request, None);
        assert_eq!(replay.normal_fan_restore_request, Some(30));
        assert_eq!(replay.sensor_delay_count, 0);
        assert_eq!(replay.helper_return, 0);
        assert_eq!(replay.outer_return, 0);
        assert_eq!(replay.recorded_reason, None);
    }

    #[test]
    fn pcb_spread_resamples_immediately_then_delays_only_while_unbalanced() {
        let replay = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::PcbSpread,
            Bm1489L7CoolDownMode::Standard,
            false,
            COOL_DOWN_CONFIG,
            &[
                UNBALANCED_PCB_RANGE,
                UNBALANCED_PCB_RANGE,
                Bm1489L7PcbRangeSample {
                    minimum_c: Some(41),
                    maximum_c: Some(46),
                },
            ],
        )
        .unwrap();
        assert_eq!(replay.outcome, Bm1489L7CoolDownOutcome::PcbSpreadBalanced);
        assert_eq!(replay.cooling_fan_request, Some(81));
        assert_eq!(replay.sensor_delay_count, 1);
        assert_eq!(replay.elapsed_seconds, 5);
    }

    #[test]
    fn pcb_spread_timeout_is_an_observed_stock_success_weakness() {
        let mut samples = vec![UNBALANCED_PCB_RANGE];
        samples.extend([UNBALANCED_PCB_RANGE; 24]);
        let replay = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::PcbSpread,
            Bm1489L7CoolDownMode::Standard,
            false,
            COOL_DOWN_CONFIG,
            &samples,
        )
        .unwrap();
        assert_eq!(
            replay.outcome,
            Bm1489L7CoolDownOutcome::PcbSpreadTimedOutButReportsSuccess
        );
        assert_eq!(replay.sensor_delay_count, 24);
        assert_eq!(replay.elapsed_seconds, 120);
        assert_eq!(replay.helper_return, 0);
        assert_eq!(replay.outer_return, 0);
        assert_eq!(replay.recorded_reason, None);
        assert!(!replay.attempts_failure_worker);
    }

    #[test]
    fn pcb_range_failure_records_reason_but_outer_wrapper_still_returns_zero() {
        let replay = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::PcbSpread,
            Bm1489L7CoolDownMode::Standard,
            false,
            COOL_DOWN_CONFIG,
            &[Bm1489L7PcbRangeSample {
                minimum_c: None,
                maximum_c: Some(50),
            }],
        )
        .unwrap();
        assert_eq!(replay.outcome, Bm1489L7CoolDownOutcome::PcbRangeUnavailable);
        assert_eq!(replay.cooling_fan_request, None);
        assert_eq!(replay.helper_return, -1);
        assert_eq!(replay.outer_return, 0);
        assert_eq!(
            replay.recorded_reason,
            Some(BM1489_L7_REASON_COOL_DOWN_FAILED)
        );
        assert!(replay.attempts_failure_worker);
        assert_eq!(replay.normal_fan_restore_request, Some(30));
    }

    #[test]
    fn timed_fallback_uses_twelve_or_twenty_four_ten_second_delays() {
        let standard = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::TimedFallback,
            Bm1489L7CoolDownMode::Standard,
            false,
            COOL_DOWN_CONFIG,
            &[],
        )
        .unwrap();
        assert_eq!(
            standard.outcome,
            Bm1489L7CoolDownOutcome::TimedFallbackCompleted
        );
        assert_eq!(standard.cooling_fan_request, Some(81));
        assert_eq!(standard.normal_fan_restore_request, Some(30));
        assert_eq!(standard.timed_fallback_delay_count, 12);
        assert_eq!(standard.elapsed_seconds, 120);

        let alternate = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::TimedFallback,
            Bm1489L7CoolDownMode::Alternate,
            false,
            COOL_DOWN_CONFIG,
            &[],
        )
        .unwrap();
        assert_eq!(alternate.cooling_fan_request, Some(40));
        assert_eq!(alternate.timed_fallback_delay_count, 24);
        assert_eq!(alternate.elapsed_seconds, 240);
    }

    #[test]
    fn cool_down_replay_skips_fan_writes_in_runtime_state_two_and_fails_closed() {
        let replay = bm1489_l7_replay_cool_down(
            Bm1489L7CoolDownRoute::TimedFallback,
            Bm1489L7CoolDownMode::Standard,
            true,
            COOL_DOWN_CONFIG,
            &[],
        )
        .unwrap();
        assert_eq!(replay.cooling_fan_request, None);
        assert_eq!(replay.normal_fan_restore_request, None);

        assert_eq!(
            bm1489_l7_replay_cool_down(
                Bm1489L7CoolDownRoute::PcbSpread,
                Bm1489L7CoolDownMode::Standard,
                false,
                COOL_DOWN_CONFIG,
                &[]
            ),
            Err(Bm1489L7CoolDownInputError::MissingInitialPcbRange)
        );
        assert_eq!(
            bm1489_l7_replay_cool_down(
                Bm1489L7CoolDownRoute::PcbSpread,
                Bm1489L7CoolDownMode::Standard,
                false,
                COOL_DOWN_CONFIG,
                &[Bm1489L7PcbRangeSample {
                    minimum_c: Some(50),
                    maximum_c: Some(49),
                }]
            ),
            Err(Bm1489L7CoolDownInputError::InvalidPcbRange)
        );
        assert_eq!(
            bm1489_l7_replay_cool_down(
                Bm1489L7CoolDownRoute::PcbSpread,
                Bm1489L7CoolDownMode::Standard,
                false,
                COOL_DOWN_CONFIG,
                &[UNBALANCED_PCB_RANGE]
            ),
            Err(Bm1489L7CoolDownInputError::InsufficientPcbRanges)
        );
    }

    #[test]
    fn fan_capture_swaps_zero_one_scales_and_ignores_unsupported_ids() {
        let previous = Bm1489L7FanCapture {
            rpm_by_slot: [11, 22, 33, 44],
        };
        let next = bm1489_l7_apply_fan_capture_cycle(
            previous,
            0,
            [0x0000_0002, 0x0000_0103, 0x0000_0204, 0x0000_0705],
        );
        assert_eq!(next.rpm_by_slot, [360, 240, 480, 44]);

        let alternate = bm1489_l7_apply_fan_capture_cycle(
            Bm1489L7FanCapture::default(),
            0xabcd_b025,
            [0x0000_0001, 0x0000_0102, 0x0000_0203, 0x0000_0304],
        );
        assert_eq!(alternate.rpm_by_slot, [480, 240, 720, 960]);
    }

    #[test]
    fn fan_capture_is_persistent_and_last_observation_for_an_id_wins() {
        let previous = Bm1489L7FanCapture {
            rpm_by_slot: [100, 200, 300, 400],
        };
        let next = bm1489_l7_apply_fan_capture_cycle(
            previous,
            0,
            [0x0000_0201, 0x0000_0202, 0x0000_0709, 0x0000_070a],
        );
        assert_eq!(next.rpm_by_slot, [100, 200, 240, 400]);
    }

    fn all_alive_fan_state() -> Bm1489L7FanLivenessState {
        Bm1489L7FanLivenessState {
            slots: [Bm1489L7FanSlotState::default(); BM1489_L7_FAN_SLOT_COUNT],
            alive_count: 4,
        }
    }

    #[test]
    fn stateful_fan_update_obeys_pwm_loss_gate_and_immediate_recovery() {
        let bad = [Bm1489L7FanReadPair::default(); BM1489_L7_FAN_SLOT_COUNT];
        let below_gate =
            bm1489_l7_update_fan_liveness(all_alive_fan_state(), 4, 9, 6_000, bad).unwrap();
        assert_eq!(below_gate.alive_count, 4);
        assert!(below_gate.slots.iter().all(|slot| !slot.lost));

        let lost = bm1489_l7_update_fan_liveness(below_gate, 4, 10, 6_000, bad).unwrap();
        assert_eq!(lost.alive_count, 0);
        assert!(lost.slots.iter().all(|slot| slot.lost));

        let good = [Bm1489L7FanReadPair {
            first_rpm: 5_999,
            second_rpm: 1,
        }; BM1489_L7_FAN_SLOT_COUNT];
        let restored = bm1489_l7_update_fan_liveness(lost, 4, 0, 6_000, good).unwrap();
        assert_eq!(restored.alive_count, 4);
        assert!(restored.slots.iter().all(|slot| !slot.lost));
        assert!(restored.slots.iter().all(|slot| slot.stored_rpm == 1));
    }

    #[test]
    fn stateful_fan_update_pins_first_read_normalization_and_upper_boundary() {
        let reads = [
            Bm1489L7FanReadPair {
                first_rpm: 6_000,
                second_rpm: 0,
            },
            Bm1489L7FanReadPair {
                first_rpm: 5_999,
                second_rpm: 18_000,
            },
            Bm1489L7FanReadPair {
                first_rpm: 5_999,
                second_rpm: 18_001,
            },
            Bm1489L7FanReadPair {
                first_rpm: 5_999,
                second_rpm: 0,
            },
        ];
        let next =
            bm1489_l7_update_fan_liveness(all_alive_fan_state(), 4, 10, 6_000, reads).unwrap();
        assert_eq!(next.alive_count, 2);
        assert_eq!(
            next.slots.map(|slot| (slot.lost, slot.stored_rpm)),
            [(false, 6_000), (false, 18_000), (true, 18_001), (true, 0),]
        );
    }

    #[test]
    fn stateful_fan_update_rejects_forged_shape_and_count_inputs() {
        let reads = [Bm1489L7FanReadPair::default(); BM1489_L7_FAN_SLOT_COUNT];
        assert_eq!(
            bm1489_l7_update_fan_liveness(all_alive_fan_state(), 0, 10, 6_000, reads),
            Err(Bm1489L7FanStateError::InvalidConfiguredFanCount)
        );
        assert_eq!(
            bm1489_l7_update_fan_liveness(all_alive_fan_state(), 4, 101, 6_000, reads),
            Err(Bm1489L7FanStateError::InvalidPwmPercent)
        );
        assert_eq!(
            bm1489_l7_update_fan_liveness(all_alive_fan_state(), 4, 10, 0, reads),
            Err(Bm1489L7FanStateError::InvalidNormalizationThreshold)
        );
        assert_eq!(
            bm1489_l7_update_fan_liveness(
                Bm1489L7FanLivenessState {
                    alive_count: 3,
                    ..all_alive_fan_state()
                },
                4,
                10,
                6_000,
                reads,
            ),
            Err(Bm1489L7FanStateError::InconsistentAliveCount)
        );
    }

    #[test]
    fn overheat_boundaries_are_inclusive_and_pcb_has_priority() {
        assert_eq!(
            bm1489_l7_overheat_decision(79, 89, LIMITS),
            Bm1489L7OverheatDecision::Continue
        );
        assert_eq!(
            bm1489_l7_overheat_decision(80, 89, LIMITS),
            Bm1489L7OverheatDecision::PcbAtOrAboveLimit
        );
        assert_eq!(
            bm1489_l7_overheat_decision(79, 90, LIMITS),
            Bm1489L7OverheatDecision::ChipAtOrAboveLimit
        );
        let both = bm1489_l7_overheat_decision(80, 90, LIMITS);
        assert_eq!(both, Bm1489L7OverheatDecision::PcbAtOrAboveLimit);
        assert_eq!(both.reason_code(), Some(0x0bba));
        assert!(both.begins_global_shutdown());
    }

    #[test]
    fn runtime_fan_fault_arms_at_exact_ten_second_boundary() {
        let before = bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
            elapsed_since_monitor_epoch_seconds: 9.999,
            alive_fans: 3,
            ..runtime_fans()
        })
        .unwrap();
        assert_eq!(before, Bm1489L7FanDecision::GracePeriod);

        let at = bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
            alive_fans: 3,
            ..runtime_fans()
        })
        .unwrap();
        assert_eq!(at, Bm1489L7FanDecision::FatalShortfall);
        assert_eq!(at.reason_code(), Some(0x07d4));
        assert!(at.begins_global_shutdown());
    }

    #[test]
    fn runtime_state_and_enable_gates_suppress_fan_faulting() {
        assert_eq!(
            bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
                runtime_state_is_two: true,
                alive_fans: 0,
                ..runtime_fans()
            })
            .unwrap(),
            Bm1489L7FanDecision::NotArmed
        );
        assert_eq!(
            bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
                fan_fault_monitoring_enabled: false,
                alive_fans: 0,
                ..runtime_fans()
            })
            .unwrap(),
            Bm1489L7FanDecision::NotArmed
        );
    }

    #[test]
    fn runtime_fan_inputs_fail_closed() {
        assert_eq!(
            bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
                elapsed_since_monitor_epoch_seconds: f64::NAN,
                ..runtime_fans()
            }),
            Err(Bm1489L7FanInputError::NonFiniteElapsedTime)
        );
        assert_eq!(
            bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
                minimum_fans: 0,
                ..runtime_fans()
            }),
            Err(Bm1489L7FanInputError::InvalidFanCounts)
        );
        assert_eq!(
            bm1489_l7_runtime_fan_decision(Bm1489L7RuntimeFanInput {
                alive_fans: 5,
                ..runtime_fans()
            }),
            Err(Bm1489L7FanInputError::AliveCountExceedsConfigured)
        );
    }

    #[test]
    fn startup_exits_early_only_when_all_configured_fans_are_seen() {
        let plan = bm1489_l7_startup_fan_plan(&[1, 2, 4, 3], 2, 4).unwrap();
        assert_eq!(
            plan.decision,
            Bm1489L7StartupFanDecision::AllConfiguredFansObserved
        );
        assert_eq!(plan.samples_consumed, 3);
        assert_eq!(plan.tail_delays_consumed, 3);
    }

    #[test]
    fn startup_needs_fifteen_samples_before_minimum_only_admission() {
        let fourteen = bm1489_l7_startup_fan_plan(&[3; 14], 2, 4).unwrap();
        assert_eq!(
            fourteen.decision,
            Bm1489L7StartupFanDecision::NeedMoreSamples
        );

        let fifteen = bm1489_l7_startup_fan_plan(&[3; 15], 2, 4).unwrap();
        assert_eq!(
            fifteen.decision,
            Bm1489L7StartupFanDecision::MinimumFanCountObserved
        );
        assert_eq!(fifteen.samples_consumed, 15);
    }

    #[test]
    fn startup_terminal_shortfall_records_fan_reason() {
        let plan = bm1489_l7_startup_fan_plan(&[1; 15], 2, 4).unwrap();
        assert_eq!(plan.decision, Bm1489L7StartupFanDecision::FatalShortfall);
        assert_eq!(plan.reason_code(), Some(0x07d4));
        assert!(plan.begins_global_shutdown());
    }

    #[test]
    fn startup_rejects_out_of_range_samples_and_lengths() {
        assert_eq!(
            bm1489_l7_startup_fan_plan(&[5], 2, 4),
            Err(Bm1489L7FanInputError::AliveCountExceedsConfigured)
        );
        assert_eq!(
            bm1489_l7_startup_fan_plan(&[1; 16], 2, 4),
            Err(Bm1489L7FanInputError::TooManyStartupSamples)
        );
    }

    #[test]
    fn l7_power_callback_sets_only_four_supported_chain_bits() {
        let mut value = 0xa5a5_0000;
        for chain in 0..4 {
            value = bm1489_l7_power_callback_set_bit(chain, value).unwrap();
        }
        assert_eq!(value, 0xa5a5_000f);
        assert_eq!(
            bm1489_l7_power_callback_set_bit(4, value),
            Err(Bm1489L7PowerCallbackError::UnsupportedChain)
        );
    }

    #[test]
    fn shutdown_gpio_failure_issues_no_chain_callbacks() {
        let plan = bm1489_l7_power_off_plan(
            4,
            Bm1489L7PowerTransitionInput {
                gpio_initialized_flag: 1,
                gpio_write_succeeded: false,
            },
        );
        assert_eq!(plan.disposition, Bm1489L7PowerOffDisposition::GuardRejected);
        assert_eq!(
            plan.steps,
            vec![Bm1489L7PowerOffStep::InvokePowerTransitionCallback {
                gpio: 907,
                requested_value: 1,
                write_attempted: true,
            }]
        );
        assert!(!plan.proves_electrical_off());
        assert!(!plan.admits_hardware_io());
    }

    #[test]
    fn shutdown_gpio_callback_is_a_noop_success_unless_flag_equals_one() {
        let transition = bm1489_l7_power_transition_result(Bm1489L7PowerTransitionInput {
            gpio_initialized_flag: 0,
            gpio_write_succeeded: false,
        });
        assert!(!transition.gpio_write_attempted);
        assert!(transition.coordinator_may_continue);

        let plan = bm1489_l7_power_off_plan(
            0,
            Bm1489L7PowerTransitionInput {
                gpio_initialized_flag: 2,
                gpio_write_succeeded: false,
            },
        );
        assert_eq!(
            plan.disposition,
            Bm1489L7PowerOffDisposition::RequestsIssued
        );
        assert_eq!(
            plan.steps,
            vec![
                Bm1489L7PowerOffStep::InvokePowerTransitionCallback {
                    gpio: 907,
                    requested_value: 1,
                    write_attempted: false,
                },
                Bm1489L7PowerOffStep::ClearMinerPowerState,
            ]
        );
    }

    #[test]
    fn shutdown_requests_every_enumerated_chain_but_exposes_ignored_overflow() {
        let plan = bm1489_l7_power_off_plan(
            6,
            Bm1489L7PowerTransitionInput {
                gpio_initialized_flag: 1,
                gpio_write_succeeded: true,
            },
        );
        assert_eq!(
            plan.disposition,
            Bm1489L7PowerOffDisposition::RequestsIssued
        );
        assert_eq!(plan.unsupported_chain_callbacks, 2);
        assert_eq!(
            plan.steps.last(),
            Some(&Bm1489L7PowerOffStep::ClearMinerPowerState)
        );
        assert_eq!(
            plan.steps
                .iter()
                .filter(|step| matches!(step, Bm1489L7PowerOffStep::InvokeChainCallback { .. }))
                .count(),
            6
        );
        assert!(!plan.proves_electrical_off());
    }
}
