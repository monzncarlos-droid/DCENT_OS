// SPDX-License-Identifier: GPL-3.0-or-later
//
// Read-only Nano 3 cooling/thermal/watchdog evidence and energization gate.
//
// This module deliberately performs no I/O.  It names only paths and
// conversions recovered from the held non-S Nano 3 image, validates bytes
// already read by an outer process, and decides whether a complete safety
// snapshot is admissible.  It contains no PWM writer, watchdog ioctl, GPIO
// operation, UART encoder, or hash-power command.
//
// Evidence boundary:
//   * recovery master SHA-256 b99a2358...fb830be;
//   * stock DTB SHA-256 1eb30142...ce956e (enabled K230 ADC, PWM, DW-WDT,
//     and timer5 index 5 nodes; no external regulator/poweroff binding);
//   * stock btcminer SHA-256 e6c11630...ca6751 (fan.c, timer.c, temper.c,
//     and wdog.c symbols retained);
//   * extracted rootfs has no separate fan/watchdog/hash-power helper.
// Full addresses, formulas, hashes, and the negative power-cut result are in
// {NANO3_NATIVE_UART_PROTOCOL_RE,
// NANO3_HASH_POWER_CUT_RE_ADDENDUM}.md`.

use std::fmt;

use sha2::{Digest, Sha256};

// Held stock btcminer (SHA-256 e6c11630...ca6751), functions fan_init /
// set_fan_duty_cycle.  These constants describe the observed Nano 3 path;
// they are not permission to write it.
pub const NANO3_PWM_EXPORT: &str = "/sys/class/pwm/pwmchip0/export";
pub const NANO3_PWM_PERIOD: &str = "/sys/class/pwm/pwmchip0/pwm2/period";
pub const NANO3_PWM_DUTY: &str = "/sys/class/pwm/pwmchip0/pwm2/duty_cycle";
pub const NANO3_PWM_ENABLE: &str = "/sys/class/pwm/pwmchip0/pwm2/enable";
pub const NANO3_PWM_PERIOD_NS: u32 = 40_000;
pub const NANO3_STOCK_INITIAL_DUTY_NS: u32 = 10_000;
pub const NANO3_STOCK_MIN_DUTY_NS: u32 = 4_000;
pub const NANO3_STOCK_MAX_DUTY_NS: u32 = 40_000;

// Held stock timer.c/fan.c evidence.  Stock reads one eight-byte little-endian
// count and reports count * 30 RPM.  A non-zero result proves pulse motion,
// not that a production minimum-RPM threshold has been qualified.
pub const NANO3_TACH_DEVICE: &str = "/dev/timer5";
pub const NANO3_TACH_ENABLE_IOCTL: u32 = 0x4004_5420;
pub const NANO3_TACH_RPM_PER_COUNT: u64 = 30;

// Held stock temper.c evidence for the non-S Nano 3.
pub const NANO3_INLET_ADC: &str = "/sys/bus/iio/devices/iio:device0/in_voltage0_raw";
pub const NANO3_OUTLET_ADC: &str = "/sys/bus/iio/devices/iio:device0/in_voltage1_raw";
pub const NANO3_ADC_MAX_STOCK_VALID: u16 = 4094;
const NANO3_ADC_VOLTS_PER_COUNT: f64 = 0.000_439_453_1;
const NANO3_ADC_DIVIDER_OHMS: f64 = 10_000.0;
const NANO3_ADC_REFERENCE_VOLTS: f64 = 1.8;
const NANO3_NTC_R25_OHMS: f64 = 100_000.0;
const NANO3_NTC_BETA: f64 = 3950.0;
const NANO3_NTC_INV_T25: f64 = 0.003_354_016_434_680_53;

// Stock runs its fan/temperature block about every two seconds.  DCENT's
// observation policy allows one additional second, then fails closed.  This
// is a software admission bound, not a claim about component thermal inertia.
pub const NANO3_OBSERVATION_MAX_AGE_MS: u64 = 3_000;

// Held stock wdog.c behavior.  The path resets the K230; held bytes do not
// prove that expiry removes ASIC/hash power.
pub const NANO3_STOCK_WATCHDOG_DEVICE: &str = "/dev/watchdog";
pub const NANO3_STOCK_WATCHDOG_TIMEOUT_SECONDS: u32 = 89;

// Desk-specified external interlock heartbeat.  This remains non-authorizing
// until the exact fixture and cutoff timing are live-qualified.
pub const NANO3_HEARTBEAT_MIN_VALID_CYCLES: u32 = 6;
pub const NANO3_HEARTBEAT_MIN_DUTY_PERCENT: u8 = 20;
pub const NANO3_HEARTBEAT_MAX_DUTY_PERCENT: u8 = 80;
pub const NANO3_HEARTBEAT_COMMISSIONING_TIMEOUT_MS: u64 = 1_500;

/// Deliberate compile-time release latch. Held bytes prove observation paths
/// but not exclusive actuator custody or an independent electrical cut, so the
/// shipping binary cannot currently authorize native Nano 3 energization.
/// This may become `true` only in the same reviewed change that attaches the
/// completed live qualification record named by the production runbook.
pub const NANO3_NATIVE_ENERGIZATION_RELEASED: bool = false;

/// Exact reviewed production qualification compiled into an energizable build.
///
/// `None` is a second, independent release latch. A future release must replace
/// it with the identity and SHA-256 of the signed record that binds the exact
/// interlock fixture, charger specimen, cable specimen, and numeric cutoff and
/// passive-coast-down results. Runtime evidence must name that same record.
pub const NANO3_APPROVED_PRODUCTION_QUALIFICATION: Option<Nano3ProductionQualification> = None;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Timed<T> {
    pub value: T,
    pub observed_at_ms: u64,
    pub sequence: u64,
}

impl<T> Timed<T> {
    pub const fn new(value: T, observed_at_ms: u64, sequence: u64) -> Self {
        Self {
            value,
            observed_at_ms,
            sequence,
        }
    }

    fn is_fresh_at(&self, now_ms: u64) -> bool {
        now_ms
            .checked_sub(self.observed_at_ms)
            .is_some_and(|age| age <= NANO3_OBSERVATION_MAX_AGE_MS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanTach {
    count: u64,
    rpm: u64,
}

impl FanTach {
    /// Decode exactly one stock-shaped `/dev/timer5` read.
    pub fn decode(raw: &[u8]) -> Result<Self, ObservationError> {
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| ObservationError::WrongTachLength(raw.len()))?;
        let count = u64::from_le_bytes(bytes);
        let rpm = count
            .checked_mul(NANO3_TACH_RPM_PER_COUNT)
            .ok_or(ObservationError::TachRpmOverflow(count))?;
        Ok(Self { count, rpm })
    }

    pub const fn count(self) -> u64 {
        self.count
    }

    pub const fn rpm(self) -> u64 {
        self.rpm
    }

    pub const fn motion_observed(self) -> bool {
        self.count != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BoardTemperatures {
    inlet_c: f64,
    outlet_c: f64,
    inlet_raw: u16,
    outlet_raw: u16,
}

impl BoardTemperatures {
    /// Parse sysfs bytes already read by the caller.  DCENT rejects raw zero as
    /// a short/saturated boundary and values above the held stock limit.  This
    /// is deliberately stricter than stock's `raw > 4094` sentinel handling.
    pub fn decode(inlet_raw: &[u8], outlet_raw: &[u8]) -> Result<Self, ObservationError> {
        let inlet_raw = parse_adc_ascii(inlet_raw)?;
        let outlet_raw = parse_adc_ascii(outlet_raw)?;
        Ok(Self {
            inlet_c: nano3_ntc_celsius(inlet_raw)?,
            outlet_c: nano3_ntc_celsius(outlet_raw)?,
            inlet_raw,
            outlet_raw,
        })
    }

    pub const fn inlet_c(self) -> f64 {
        self.inlet_c
    }

    pub const fn outlet_c(self) -> f64 {
        self.outlet_c
    }

    pub const fn inlet_raw(self) -> u16 {
        self.inlet_raw
    }

    pub const fn outlet_raw(self) -> u16 {
        self.outlet_raw
    }
}

fn parse_adc_ascii(raw: &[u8]) -> Result<u16, ObservationError> {
    let text = std::str::from_utf8(raw).map_err(|_| ObservationError::InvalidAdcAscii)?;
    let trimmed = text.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ObservationError::InvalidAdcAscii);
    }
    trimmed
        .parse::<u16>()
        .map_err(|_| ObservationError::InvalidAdcAscii)
}

pub fn nano3_ntc_celsius(raw: u16) -> Result<f64, ObservationError> {
    if raw == 0 || raw > NANO3_ADC_MAX_STOCK_VALID {
        return Err(ObservationError::AdcOpenOrShort(raw));
    }
    let volts = f64::from(raw) * NANO3_ADC_VOLTS_PER_COUNT;
    let denominator = NANO3_ADC_REFERENCE_VOLTS - volts;
    if !(volts > 0.0 && denominator > 0.0) {
        return Err(ObservationError::AdcOpenOrShort(raw));
    }
    let resistance = volts * NANO3_ADC_DIVIDER_OHMS / denominator;
    let kelvin =
        1.0 / ((resistance / NANO3_NTC_R25_OHMS).ln() / NANO3_NTC_BETA + NANO3_NTC_INV_T25);
    let celsius = kelvin - 273.15;
    if !celsius.is_finite() {
        return Err(ObservationError::NonFiniteTemperature(raw));
    }
    Ok(celsius)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationError {
    WrongTachLength(usize),
    TachRpmOverflow(u64),
    InvalidAdcAscii,
    AdcOpenOrShort(u16),
    NonFiniteTemperature(u16),
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongTachLength(n) => {
                write!(f, "Nano 3 timer5 read must be exactly 8 bytes, got {n}")
            }
            Self::TachRpmOverflow(count) => {
                write!(f, "Nano 3 timer5 count {count} overflows RPM conversion")
            }
            Self::InvalidAdcAscii => write!(f, "Nano 3 IIO ADC sample is not strict decimal ASCII"),
            Self::AdcOpenOrShort(raw) => {
                write!(f, "Nano 3 IIO ADC boundary {raw} is open/short/saturated")
            }
            Self::NonFiniteTemperature(raw) => {
                write!(f, "Nano 3 IIO ADC {raw} produced a non-finite temperature")
            }
        }
    }
}

impl std::error::Error for ObservationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogPath {
    /// Held stock `/dev/watchdog`: availability reset only, never a cut proof.
    StockK230Reset,
    /// `/dev/watchdog` held by dcentrald. This is still a K230 availability
    /// reset path and cannot substitute for an independent hash/power cut.
    DcentK230Reset,
    /// Independently powered fixture watchdog whose healthy contact is in the
    /// contactor/hash-cut permit chain.
    IndependentInterlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependentCutTopology {
    /// Whole-device input cut.  Because it also stops the fan, worst-case
    /// passive coast-down must be qualified.
    WholeDevice,
    /// Independently measured hash-domain cut that retains cooling power.
    HashDomainCoolingRetained,
}

/// Immutable identity of a reviewed qualification record.
///
/// SHA-256 is binary rather than caller-formatted text, so case, whitespace,
/// and truncated-digest ambiguity cannot enter the release comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualificationRecordIdentity {
    record_id: &'static str,
    sha256: [u8; 32],
}

impl QualificationRecordIdentity {
    #[cfg(test)]
    const fn new(record_id: &'static str, sha256: [u8; 32]) -> Self {
        Self { record_id, sha256 }
    }

    pub const fn record_id(self) -> &'static str {
        self.record_id
    }

    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }

    fn is_well_formed(self) -> bool {
        !self.record_id.trim().is_empty() && self.sha256 != [0; 32]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualificationVerificationError {
    NotReleased,
    DigestMismatch,
}

impl fmt::Display for QualificationVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReleased => {
                f.write_str("no Nano 3 production qualification record is compiled into this build")
            }
            Self::DigestMismatch => {
                f.write_str("Nano 3 production qualification record SHA-256 does not match")
            }
        }
    }
}

impl std::error::Error for QualificationVerificationError {}

/// Hash actual record bytes and return the only identity admissible to a
/// runtime snapshot. Identity construction is private so sibling modules
/// cannot manufacture a record claim without passing this byte-level verifier.
pub fn verify_compiled_qualification_record(
    record_bytes: &[u8],
) -> Result<QualificationRecordIdentity, QualificationVerificationError> {
    verify_qualification_record_against(record_bytes, NANO3_APPROVED_PRODUCTION_QUALIFICATION)
}

fn verify_qualification_record_against(
    record_bytes: &[u8],
    approved: Option<Nano3ProductionQualification>,
) -> Result<QualificationRecordIdentity, QualificationVerificationError> {
    let approved = approved.ok_or(QualificationVerificationError::NotReleased)?;
    let actual: [u8; 32] = Sha256::digest(record_bytes).into();
    if actual != approved.identity.sha256 {
        return Err(QualificationVerificationError::DigestMismatch);
    }
    Ok(approved.identity)
}

/// Exact physical assets bound by the reviewed qualification record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedNano3PowerChain {
    pub fixture_asset_id: &'static str,
    pub charger_asset_id: &'static str,
    pub charger_model: &'static str,
    pub cable_asset_id: &'static str,
    pub cable_model: &'static str,
}

impl QualifiedNano3PowerChain {
    fn is_well_formed(self) -> bool {
        [
            self.fixture_asset_id,
            self.charger_asset_id,
            self.charger_model,
            self.cable_asset_id,
            self.cable_model,
        ]
        .into_iter()
        .all(|field| !field.trim().is_empty())
    }
}

/// Numeric results and limits from the exact reviewed fault campaign.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualifiedNano3CutEnvelope {
    pub topology: IndependentCutTopology,
    pub maximum_safe_cutoff_ms: u64,
    pub worst_case_contactor_release_ms: u64,
    pub worst_case_hash_stop_ms: u64,
    pub worst_case_rail_collapse_ms: u64,
    pub worst_case_watchdog_expiry_to_cut_ms: u64,
    pub maximum_post_cut_temperature_rise_c: f64,
    pub worst_case_post_cut_temperature_rise_c: f64,
    pub maximum_post_cut_peak_temperature_c: f64,
    pub worst_case_post_cut_peak_temperature_c: f64,
}

impl QualifiedNano3CutEnvelope {
    fn values_are_well_formed(self) -> bool {
        self.maximum_safe_cutoff_ms > 0
            && self.worst_case_contactor_release_ms > 0
            && self.worst_case_hash_stop_ms > 0
            && self.worst_case_rail_collapse_ms > 0
            && self.worst_case_watchdog_expiry_to_cut_ms > 0
            && self.maximum_post_cut_temperature_rise_c.is_finite()
            && self.maximum_post_cut_temperature_rise_c >= 0.0
            && self.worst_case_post_cut_temperature_rise_c.is_finite()
            && self.worst_case_post_cut_temperature_rise_c >= 0.0
            && self.maximum_post_cut_peak_temperature_c.is_finite()
            && self.maximum_post_cut_peak_temperature_c > 0.0
            && self.worst_case_post_cut_peak_temperature_c.is_finite()
            && self.worst_case_post_cut_peak_temperature_c > 0.0
    }

    fn cutoff_is_within_limit(self) -> bool {
        self.worst_case_contactor_release_ms <= self.maximum_safe_cutoff_ms
            && self.worst_case_hash_stop_ms <= self.maximum_safe_cutoff_ms
            && self.worst_case_rail_collapse_ms <= self.maximum_safe_cutoff_ms
            && self.worst_case_watchdog_expiry_to_cut_ms <= self.maximum_safe_cutoff_ms
    }

    fn coast_down_is_within_limits(self) -> bool {
        self.worst_case_post_cut_temperature_rise_c <= self.maximum_post_cut_temperature_rise_c
            && self.worst_case_post_cut_peak_temperature_c
                <= self.maximum_post_cut_peak_temperature_c
    }
}

/// Live-qualified operating thresholds copied exactly from the hashed record.
/// Runtime callers may report observations, but cannot choose easier limits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualifiedNano3OperatingEnvelope {
    pub minimum_fan_rpm: u64,
    pub maximum_inlet_temperature_c: f64,
    pub maximum_outlet_temperature_c: f64,
    pub heartbeat_timeout_ms: u64,
}

impl QualifiedNano3OperatingEnvelope {
    fn is_well_formed(self) -> bool {
        self.minimum_fan_rpm > 0
            && self.maximum_inlet_temperature_c.is_finite()
            && self.maximum_inlet_temperature_c > 0.0
            && self.maximum_outlet_temperature_c.is_finite()
            && self.maximum_outlet_temperature_c > 0.0
            && self.heartbeat_timeout_ms > 0
            && self.heartbeat_timeout_ms <= NANO3_HEARTBEAT_COMMISSIONING_TIMEOUT_MS
    }
}

/// One compile-pinned production record. The digest pins the reviewed evidence
/// artifact; separately pinned explicit fields keep every asset and numeric
/// safety comparison reviewable by code and tests instead of hiding it behind
/// a bool. Release review must confirm those fields match the hashed record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nano3ProductionQualification {
    pub identity: QualificationRecordIdentity,
    pub power_chain: QualifiedNano3PowerChain,
    pub cut: QualifiedNano3CutEnvelope,
    pub operating: QualifiedNano3OperatingEnvelope,
}

impl Nano3ProductionQualification {
    fn is_well_formed(self) -> bool {
        self.identity.is_well_formed()
            && self.power_chain.is_well_formed()
            && self.cut.values_are_well_formed()
            && self.operating.is_well_formed()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FanSafetyEvidence {
    pub custody_iteration: u64,
    pub previous: Timed<FanTach>,
    pub current: Timed<FanTach>,
    pub actuator_exclusive: bool,
    pub pwm_path_live_verified: bool,
    pub intended_pwm_period_ns: u32,
    pub intended_pwm_duty_ns: u32,
    pub observed_pwm_period_ns: Option<u32>,
    pub observed_pwm_duty_ns: Option<u32>,
    pub observed_pwm_enabled: Option<bool>,
    /// `None` means no live-qualified threshold exists and must fail closed.
    pub qualified_minimum_rpm: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThermalSafetyEvidence {
    pub custody_iteration: u64,
    pub board: Timed<BoardTemperatures>,
    /// `None`, zero, negative, NaN, or infinity means unqualified.
    pub qualified_inlet_max_c: Option<f64>,
    pub qualified_outlet_max_c: Option<f64>,
    pub independent_hard_temperature_channels_healthy: bool,
    pub controller_asic_response_live_qualified: bool,
    pub sensor_loss_cut_live_qualified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalHeartbeatEvidence {
    pub custody_iteration: u64,
    pub rising_edges: u32,
    pub falling_edges: u32,
    pub valid_cycles: u32,
    pub duty_percent: u8,
    pub last_edge_at_ms: u64,
    pub production_timeout_ms: u64,
    /// True only when waveform generation is coupled to one complete fresh
    /// temperature/fan/controller custody iteration, never a free-running timer.
    pub coupled_to_complete_custody_iteration: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogSafetyEvidence {
    pub custody_iteration: u64,
    pub observed_at_ms: u64,
    pub path: WatchdogPath,
    pub owner_exclusive: bool,
    pub independent_supervisor_watchdog_healthy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndependentCutEvidence {
    pub custody_iteration: u64,
    pub observed_at_ms: u64,
    pub topology: IndependentCutTopology,
    /// Must exactly match the compile-pinned approved record identity.
    pub qualification_record: Option<QualificationRecordIdentity>,
    pub cutoff_armed: bool,
    pub manual_rearm_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nano3SafetySnapshot {
    pub now_ms: u64,
    pub custody_iteration: u64,
    pub fan: FanSafetyEvidence,
    pub thermal: ThermalSafetyEvidence,
    pub heartbeat: PhysicalHeartbeatEvidence,
    pub watchdog: WatchdogSafetyEvidence,
    pub cut: IndependentCutEvidence,
    pub controller_fault_absent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyBlocker {
    NativeEnergizationNotReleased,
    ProductionQualificationNotReleased,
    ProductionQualificationRecordMismatch,
    ProductionQualificationRecordInvalid,
    CoolingQualificationMismatch,
    HeartbeatTimeoutQualificationMismatch,
    CutTopologyMismatch,
    CutTimingOutsideQualifiedEnvelope,
    PostCutThermalOutsideQualifiedEnvelope,
    EvidenceIterationMismatch,
    TachTimestampInvalidOrStale,
    TachSequenceNotConsecutive,
    FanStopped,
    FanActuatorNotExclusive,
    PwmPathNotLiveVerified,
    PwmCommandOutOfRange,
    PwmCommandReadbackMismatch,
    MinimumRpmNotLiveQualified,
    FanBelowQualifiedMinimum,
    TemperatureTimestampInvalidOrStale,
    BoardLimitsNotLiveQualified,
    BoardTemperatureNotFinite,
    TemperatureAboveQualifiedLimit,
    IndependentHardTemperatureChannelsUnhealthy,
    ControllerAsicThermalResponseNotLiveQualified,
    SensorLossCutNotLiveQualified,
    HeartbeatEdgesInvalid,
    HeartbeatCyclesInsufficient,
    HeartbeatDutyInvalid,
    HeartbeatStale,
    HeartbeatTimeoutNotLiveQualified,
    HeartbeatNotCoupledToCustodyLoop,
    K230ResetWatchdogIsNotHashCut,
    WatchdogTimestampInvalidOrStale,
    WatchdogOwnerNotExclusive,
    IndependentSupervisorWatchdogUnhealthy,
    CutTimestampInvalidOrStale,
    IndependentCutNotArmed,
    AutomaticRearmPossible,
    ControllerFaultPresent,
}

impl SafetyBlocker {
    pub const fn description(self) -> &'static str {
        match self {
            Self::NativeEnergizationNotReleased => {
                "native Nano 3 energization compile-time release latch has not been released"
            }
            Self::ProductionQualificationNotReleased => {
                "no exact Nano 3 production qualification record is compiled into this build"
            }
            Self::ProductionQualificationRecordMismatch => {
                "runtime qualification identity matches the compile-pinned record and SHA-256"
            }
            Self::ProductionQualificationRecordInvalid => {
                "compile-pinned power-chain, cutoff, cooling, and heartbeat qualification fields are complete and valid"
            }
            Self::CoolingQualificationMismatch => {
                "runtime fan and temperature limits exactly match the compile-pinned qualification record"
            }
            Self::HeartbeatTimeoutQualificationMismatch => {
                "runtime heartbeat timeout exactly matches the compile-pinned qualification record"
            }
            Self::CutTopologyMismatch => {
                "live independent-cut topology matches the compile-pinned qualification record"
            }
            Self::CutTimingOutsideQualifiedEnvelope => {
                "measured contactor, hash-stop, rail-collapse, and watchdog-expiry times are within the qualified cutoff limit"
            }
            Self::PostCutThermalOutsideQualifiedEnvelope => {
                "measured post-cut temperature rise and peak are within qualified limits"
            }
            Self::EvidenceIterationMismatch => {
                "all safety evidence belongs to the same nonzero custody iteration"
            }
            Self::TachTimestampInvalidOrStale => "fan tach is fresh on the monotonic clock",
            Self::TachSequenceNotConsecutive => "fan tach samples are consecutive",
            Self::FanStopped => "fan motion is present in both tach samples",
            Self::FanActuatorNotExclusive => "fan actuator custody is exclusive",
            Self::PwmPathNotLiveVerified => "Nano 3 PWM-to-fan path is live-verified",
            Self::PwmCommandOutOfRange => "PWM period and duty are inside the held Nano 3 envelope",
            Self::PwmCommandReadbackMismatch => {
                "PWM command readback matches the intended custody iteration"
            }
            Self::MinimumRpmNotLiveQualified => "minimum fan RPM is live-qualified",
            Self::FanBelowQualifiedMinimum => "fan tach meets the qualified minimum",
            Self::TemperatureTimestampInvalidOrStale => {
                "board temperatures are fresh on the monotonic clock"
            }
            Self::BoardLimitsNotLiveQualified => "board temperature limits are live-qualified",
            Self::BoardTemperatureNotFinite => "decoded board temperatures are finite",
            Self::TemperatureAboveQualifiedLimit => "board temperatures are below qualified limits",
            Self::IndependentHardTemperatureChannelsUnhealthy => {
                "both independent hard-temperature channels are healthy"
            }
            Self::ControllerAsicThermalResponseNotLiveQualified => {
                "controller/ASIC thermal response is live-qualified"
            }
            Self::SensorLossCutNotLiveQualified => "sensor loss reaches the independent cut",
            Self::HeartbeatEdgesInvalid => "physical heartbeat has rising and falling edges",
            Self::HeartbeatCyclesInsufficient => "physical heartbeat has six valid cycles",
            Self::HeartbeatDutyInvalid => "physical heartbeat duty is within 20..=80 percent",
            Self::HeartbeatStale => "physical heartbeat is fresh",
            Self::HeartbeatTimeoutNotLiveQualified => {
                "heartbeat timeout is live-qualified within the commissioning bound"
            }
            Self::HeartbeatNotCoupledToCustodyLoop => {
                "heartbeat generation is coupled to a complete custody iteration"
            }
            Self::K230ResetWatchdogIsNotHashCut => {
                "an independent interlock watchdog is required; a K230 reset watchdog is not a hash cut"
            }
            Self::WatchdogTimestampInvalidOrStale => "watchdog evidence is fresh",
            Self::WatchdogOwnerNotExclusive => "watchdog ownership is exclusive",
            Self::IndependentSupervisorWatchdogUnhealthy => {
                "independent supervisor watchdog is healthy"
            }
            Self::CutTimestampInvalidOrStale => "independent cut evidence is fresh",
            Self::IndependentCutNotArmed => "independent cut is armed",
            Self::AutomaticRearmPossible => "cut requires manual re-arm after a trip",
            Self::ControllerFaultPresent => "controller reports no fault",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct NativeReleaseAuthority {
    energization_released: bool,
    approved_qualification: Option<Nano3ProductionQualification>,
}

impl Nano3SafetySnapshot {
    /// Return every reason this snapshot cannot authorize energization.
    pub fn blockers(&self) -> Vec<SafetyBlocker> {
        self.blockers_against(NativeReleaseAuthority {
            energization_released: NANO3_NATIVE_ENERGIZATION_RELEASED,
            approved_qualification: NANO3_APPROVED_PRODUCTION_QUALIFICATION,
        })
    }

    fn blockers_against(&self, authority: NativeReleaseAuthority) -> Vec<SafetyBlocker> {
        let mut out = Vec::new();

        if !authority.energization_released {
            out.push(SafetyBlocker::NativeEnergizationNotReleased);
        }
        match authority.approved_qualification {
            None => out.push(SafetyBlocker::ProductionQualificationNotReleased),
            Some(qualification) => {
                if self.cut.qualification_record != Some(qualification.identity) {
                    out.push(SafetyBlocker::ProductionQualificationRecordMismatch);
                }
                if !qualification.is_well_formed() {
                    out.push(SafetyBlocker::ProductionQualificationRecordInvalid);
                } else {
                    if self.fan.qualified_minimum_rpm
                        != Some(qualification.operating.minimum_fan_rpm)
                        || self.thermal.qualified_inlet_max_c
                            != Some(qualification.operating.maximum_inlet_temperature_c)
                        || self.thermal.qualified_outlet_max_c
                            != Some(qualification.operating.maximum_outlet_temperature_c)
                    {
                        out.push(SafetyBlocker::CoolingQualificationMismatch);
                    }
                    if self.heartbeat.production_timeout_ms
                        != qualification.operating.heartbeat_timeout_ms
                    {
                        out.push(SafetyBlocker::HeartbeatTimeoutQualificationMismatch);
                    }
                    if self.cut.topology != qualification.cut.topology {
                        out.push(SafetyBlocker::CutTopologyMismatch);
                    }
                    if !qualification.cut.cutoff_is_within_limit() {
                        out.push(SafetyBlocker::CutTimingOutsideQualifiedEnvelope);
                    }
                    if !qualification.cut.coast_down_is_within_limits() {
                        out.push(SafetyBlocker::PostCutThermalOutsideQualifiedEnvelope);
                    }
                }
            }
        }
        if self.custody_iteration == 0
            || self.fan.custody_iteration != self.custody_iteration
            || self.thermal.custody_iteration != self.custody_iteration
            || self.heartbeat.custody_iteration != self.custody_iteration
            || self.watchdog.custody_iteration != self.custody_iteration
            || self.cut.custody_iteration != self.custody_iteration
        {
            out.push(SafetyBlocker::EvidenceIterationMismatch);
        }

        if !self.fan.previous.is_fresh_at(self.now_ms)
            || !self.fan.current.is_fresh_at(self.now_ms)
            || self.fan.current.observed_at_ms <= self.fan.previous.observed_at_ms
        {
            out.push(SafetyBlocker::TachTimestampInvalidOrStale);
        }
        if self.fan.previous.sequence.checked_add(1) != Some(self.fan.current.sequence) {
            out.push(SafetyBlocker::TachSequenceNotConsecutive);
        }
        if !self.fan.previous.value.motion_observed() || !self.fan.current.value.motion_observed() {
            out.push(SafetyBlocker::FanStopped);
        }
        if !self.fan.actuator_exclusive {
            out.push(SafetyBlocker::FanActuatorNotExclusive);
        }
        if !self.fan.pwm_path_live_verified {
            out.push(SafetyBlocker::PwmPathNotLiveVerified);
        }
        let pwm_command_valid = self.fan.intended_pwm_period_ns == NANO3_PWM_PERIOD_NS
            && (NANO3_STOCK_MIN_DUTY_NS..=NANO3_STOCK_MAX_DUTY_NS)
                .contains(&self.fan.intended_pwm_duty_ns)
            && self.fan.intended_pwm_duty_ns <= self.fan.intended_pwm_period_ns;
        if !pwm_command_valid {
            out.push(SafetyBlocker::PwmCommandOutOfRange);
        }
        if self.fan.observed_pwm_period_ns != Some(self.fan.intended_pwm_period_ns)
            || self.fan.observed_pwm_duty_ns != Some(self.fan.intended_pwm_duty_ns)
            || self.fan.observed_pwm_enabled != Some(true)
        {
            out.push(SafetyBlocker::PwmCommandReadbackMismatch);
        }
        match self.fan.qualified_minimum_rpm {
            None | Some(0) => out.push(SafetyBlocker::MinimumRpmNotLiveQualified),
            Some(minimum_rpm)
                if self.fan.previous.value.rpm() < minimum_rpm
                    || self.fan.current.value.rpm() < minimum_rpm =>
            {
                out.push(SafetyBlocker::FanBelowQualifiedMinimum);
            }
            Some(_) => {}
        }

        if !self.thermal.board.is_fresh_at(self.now_ms) {
            out.push(SafetyBlocker::TemperatureTimestampInvalidOrStale);
        }
        let board_temperature_finite = self.thermal.board.value.inlet_c().is_finite()
            && self.thermal.board.value.outlet_c().is_finite();
        if !board_temperature_finite {
            out.push(SafetyBlocker::BoardTemperatureNotFinite);
        }
        match (
            self.thermal.qualified_inlet_max_c,
            self.thermal.qualified_outlet_max_c,
        ) {
            (Some(inlet_max), Some(outlet_max))
                if inlet_max.is_finite()
                    && outlet_max.is_finite()
                    && inlet_max > 0.0
                    && outlet_max > 0.0 =>
            {
                if board_temperature_finite
                    && (self.thermal.board.value.inlet_c() >= inlet_max
                        || self.thermal.board.value.outlet_c() >= outlet_max)
                {
                    out.push(SafetyBlocker::TemperatureAboveQualifiedLimit);
                }
            }
            _ => out.push(SafetyBlocker::BoardLimitsNotLiveQualified),
        }
        if !self.thermal.independent_hard_temperature_channels_healthy {
            out.push(SafetyBlocker::IndependentHardTemperatureChannelsUnhealthy);
        }
        if !self.thermal.controller_asic_response_live_qualified {
            out.push(SafetyBlocker::ControllerAsicThermalResponseNotLiveQualified);
        }
        if !self.thermal.sensor_loss_cut_live_qualified {
            out.push(SafetyBlocker::SensorLossCutNotLiveQualified);
        }

        if self.heartbeat.rising_edges == 0 || self.heartbeat.falling_edges == 0 {
            out.push(SafetyBlocker::HeartbeatEdgesInvalid);
        }
        if self.heartbeat.valid_cycles < NANO3_HEARTBEAT_MIN_VALID_CYCLES {
            out.push(SafetyBlocker::HeartbeatCyclesInsufficient);
        }
        if !(NANO3_HEARTBEAT_MIN_DUTY_PERCENT..=NANO3_HEARTBEAT_MAX_DUTY_PERCENT)
            .contains(&self.heartbeat.duty_percent)
        {
            out.push(SafetyBlocker::HeartbeatDutyInvalid);
        }
        if self
            .now_ms
            .checked_sub(self.heartbeat.last_edge_at_ms)
            .is_none_or(|age| age > self.heartbeat.production_timeout_ms)
        {
            out.push(SafetyBlocker::HeartbeatStale);
        }
        if self.heartbeat.production_timeout_ms == 0
            || self.heartbeat.production_timeout_ms > NANO3_HEARTBEAT_COMMISSIONING_TIMEOUT_MS
        {
            out.push(SafetyBlocker::HeartbeatTimeoutNotLiveQualified);
        }
        if !self.heartbeat.coupled_to_complete_custody_iteration {
            out.push(SafetyBlocker::HeartbeatNotCoupledToCustodyLoop);
        }

        if self.watchdog.path != WatchdogPath::IndependentInterlock {
            out.push(SafetyBlocker::K230ResetWatchdogIsNotHashCut);
        }
        if self
            .now_ms
            .checked_sub(self.watchdog.observed_at_ms)
            .is_none_or(|age| age > NANO3_OBSERVATION_MAX_AGE_MS)
        {
            out.push(SafetyBlocker::WatchdogTimestampInvalidOrStale);
        }
        if !self.watchdog.owner_exclusive {
            out.push(SafetyBlocker::WatchdogOwnerNotExclusive);
        }
        if !self.watchdog.independent_supervisor_watchdog_healthy {
            out.push(SafetyBlocker::IndependentSupervisorWatchdogUnhealthy);
        }

        if self
            .now_ms
            .checked_sub(self.cut.observed_at_ms)
            .is_none_or(|age| age > NANO3_OBSERVATION_MAX_AGE_MS)
        {
            out.push(SafetyBlocker::CutTimestampInvalidOrStale);
        }
        if !self.cut.cutoff_armed {
            out.push(SafetyBlocker::IndependentCutNotArmed);
        }
        if !self.cut.manual_rearm_only {
            out.push(SafetyBlocker::AutomaticRearmPossible);
        }
        if !self.controller_fault_absent {
            out.push(SafetyBlocker::ControllerFaultPresent);
        }
        out
    }

    pub fn first_blocker(&self) -> Option<SafetyBlocker> {
        self.blockers().into_iter().next()
    }

    pub fn may_energize(&self) -> bool {
        self.first_blocker().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tach(count: u64, observed_at_ms: u64, sequence: u64) -> Timed<FanTach> {
        Timed::new(
            FanTach::decode(&count.to_le_bytes()).expect("valid timer fixture"),
            observed_at_ms,
            sequence,
        )
    }

    fn complete_test_qualification() -> Nano3ProductionQualification {
        Nano3ProductionQualification {
            identity: QualificationRecordIdentity::new(
                "nano3-production-qualification-test",
                [0x5a; 32],
            ),
            power_chain: QualifiedNano3PowerChain {
                fixture_asset_id: "fixture-test-1",
                charger_asset_id: "charger-test-1",
                charger_model: "qualified-charger-test-model",
                cable_asset_id: "cable-test-1",
                cable_model: "qualified-cable-test-model",
            },
            cut: QualifiedNano3CutEnvelope {
                topology: IndependentCutTopology::WholeDevice,
                maximum_safe_cutoff_ms: 1_500,
                worst_case_contactor_release_ms: 120,
                worst_case_hash_stop_ms: 200,
                worst_case_rail_collapse_ms: 250,
                worst_case_watchdog_expiry_to_cut_ms: 1_000,
                maximum_post_cut_temperature_rise_c: 10.0,
                worst_case_post_cut_temperature_rise_c: 4.0,
                maximum_post_cut_peak_temperature_c: 95.0,
                worst_case_post_cut_peak_temperature_c: 82.0,
            },
            operating: QualifiedNano3OperatingEnvelope {
                minimum_fan_rpm: 1_500,
                maximum_inlet_temperature_c: 150.0,
                maximum_outlet_temperature_c: 150.0,
                heartbeat_timeout_ms: 1_000,
            },
        }
    }

    fn released_test_authority(
        qualification: Nano3ProductionQualification,
    ) -> NativeReleaseAuthority {
        NativeReleaseAuthority {
            energization_released: true,
            approved_qualification: Some(qualification),
        }
    }

    /// Complete synthetic physical evidence.  The production release latch is
    /// intentionally still open, so even this test snapshot cannot energize.
    fn complete_unreleased_snapshot() -> Nano3SafetySnapshot {
        let board = BoardTemperatures::decode(b"2150\n", b"2250\n").unwrap();
        Nano3SafetySnapshot {
            now_ms: 10_000,
            custody_iteration: 70,
            fan: FanSafetyEvidence {
                custody_iteration: 70,
                previous: tach(58, 8_000, 40),
                current: tach(59, 9_900, 41),
                actuator_exclusive: true,
                pwm_path_live_verified: true,
                intended_pwm_period_ns: 40_000,
                intended_pwm_duty_ns: 10_000,
                observed_pwm_period_ns: Some(40_000),
                observed_pwm_duty_ns: Some(10_000),
                observed_pwm_enabled: Some(true),
                qualified_minimum_rpm: Some(1_500),
            },
            thermal: ThermalSafetyEvidence {
                custody_iteration: 70,
                board: Timed::new(board, 9_900, 50),
                qualified_inlet_max_c: Some(150.0),
                qualified_outlet_max_c: Some(150.0),
                independent_hard_temperature_channels_healthy: true,
                controller_asic_response_live_qualified: true,
                sensor_loss_cut_live_qualified: true,
            },
            heartbeat: PhysicalHeartbeatEvidence {
                custody_iteration: 70,
                rising_edges: 6,
                falling_edges: 6,
                valid_cycles: 6,
                duty_percent: 50,
                last_edge_at_ms: 9_900,
                production_timeout_ms: 1_000,
                coupled_to_complete_custody_iteration: true,
            },
            watchdog: WatchdogSafetyEvidence {
                custody_iteration: 70,
                observed_at_ms: 9_900,
                path: WatchdogPath::IndependentInterlock,
                owner_exclusive: true,
                independent_supervisor_watchdog_healthy: true,
            },
            cut: IndependentCutEvidence {
                custody_iteration: 70,
                observed_at_ms: 9_900,
                topology: IndependentCutTopology::WholeDevice,
                qualification_record: None,
                cutoff_armed: true,
                manual_rearm_only: true,
            },
            controller_fault_absent: true,
        }
    }

    #[test]
    fn exact_held_paths_and_constants_are_pinned() {
        assert_eq!(NANO3_PWM_DUTY, "/sys/class/pwm/pwmchip0/pwm2/duty_cycle");
        assert_eq!(NANO3_PWM_PERIOD_NS, 40_000);
        assert_eq!(NANO3_STOCK_INITIAL_DUTY_NS, 10_000);
        assert_eq!(NANO3_TACH_DEVICE, "/dev/timer5");
        assert_eq!(NANO3_TACH_ENABLE_IOCTL, 0x4004_5420);
        assert_eq!(
            NANO3_INLET_ADC,
            "/sys/bus/iio/devices/iio:device0/in_voltage0_raw"
        );
        assert_eq!(
            NANO3_OUTLET_ADC,
            "/sys/bus/iio/devices/iio:device0/in_voltage1_raw"
        );
        assert_eq!(NANO3_STOCK_WATCHDOG_TIMEOUT_SECONDS, 89);
    }

    #[test]
    fn timer5_decode_is_exact_length_little_endian_and_checked() {
        let sample = FanTach::decode(&58_u64.to_le_bytes()).unwrap();
        assert_eq!(sample.count(), 58);
        assert_eq!(sample.rpm(), 1740);
        assert!(sample.motion_observed());
        assert!(!FanTach::decode(&0_u64.to_le_bytes())
            .unwrap()
            .motion_observed());
        assert_eq!(
            FanTach::decode(&[1, 2]).unwrap_err(),
            ObservationError::WrongTachLength(2)
        );
        assert!(matches!(
            FanTach::decode(&u64::MAX.to_le_bytes()),
            Err(ObservationError::TachRpmOverflow(u64::MAX))
        ));
    }

    #[test]
    fn nano3_ntc_conversion_matches_held_formula_and_rejects_boundaries() {
        let t = nano3_ntc_celsius(2048).unwrap();
        assert!((t - 87.72).abs() < 0.1, "unexpected conversion {t}");
        assert_eq!(
            nano3_ntc_celsius(0),
            Err(ObservationError::AdcOpenOrShort(0))
        );
        assert_eq!(
            nano3_ntc_celsius(4095),
            Err(ObservationError::AdcOpenOrShort(4095))
        );
        assert!(BoardTemperatures::decode(b"2048\n", b"2050\n").is_ok());
        assert_eq!(
            BoardTemperatures::decode(b"12x", b"2050\n").unwrap_err(),
            ObservationError::InvalidAdcAscii
        );
    }

    #[test]
    fn k230_reset_watchdogs_can_never_satisfy_energization_gate() {
        for path in [WatchdogPath::StockK230Reset, WatchdogPath::DcentK230Reset] {
            let mut snapshot = complete_unreleased_snapshot();
            snapshot.watchdog.path = path;
            assert!(!snapshot.may_energize());
            assert!(snapshot
                .blockers()
                .contains(&SafetyBlocker::K230ResetWatchdogIsNotHashCut));
        }
    }

    #[test]
    fn stopped_stale_or_nonconsecutive_fan_fails_closed() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.fan.current = tach(0, 9_900, 43);
        snapshot.fan.previous.observed_at_ms = 6_999;
        let blockers = snapshot.blockers();
        assert!(blockers.contains(&SafetyBlocker::FanStopped));
        assert!(blockers.contains(&SafetyBlocker::TachSequenceNotConsecutive));
        assert!(blockers.contains(&SafetyBlocker::TachTimestampInvalidOrStale));
        assert!(!snapshot.may_energize());
    }

    #[test]
    fn fan_minimum_is_numeric_qualified_and_boundary_checked() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.fan.qualified_minimum_rpm = None;
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::MinimumRpmNotLiveQualified));

        snapshot.fan.qualified_minimum_rpm = Some(0);
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::MinimumRpmNotLiveQualified));

        snapshot.fan.qualified_minimum_rpm = Some(1_741);
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::FanBelowQualifiedMinimum));

        // The threshold is a minimum: equality is admitted. Previous tach is
        // exactly 1740 RPM and current tach is 1770 RPM.
        snapshot.fan.qualified_minimum_rpm = Some(1_740);
        assert!(!snapshot
            .blockers()
            .contains(&SafetyBlocker::FanBelowQualifiedMinimum));
    }

    #[test]
    fn pwm_admission_compares_numeric_command_and_readback() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.fan.intended_pwm_period_ns = 0;
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::PwmCommandOutOfRange));

        snapshot = complete_unreleased_snapshot();
        snapshot.fan.intended_pwm_duty_ns = NANO3_STOCK_MIN_DUTY_NS - 1;
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::PwmCommandOutOfRange));

        snapshot = complete_unreleased_snapshot();
        snapshot.fan.observed_pwm_duty_ns = Some(9_999);
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::PwmCommandReadbackMismatch));

        snapshot = complete_unreleased_snapshot();
        snapshot.fan.observed_pwm_enabled = Some(false);
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::PwmCommandReadbackMismatch));
    }

    #[test]
    fn sensor_loss_and_stale_or_future_samples_fail_closed() {
        assert!(matches!(
            BoardTemperatures::decode(b"4095\n", b"2000\n"),
            Err(ObservationError::AdcOpenOrShort(4095))
        ));

        let mut snapshot = complete_unreleased_snapshot();
        snapshot.thermal.board.observed_at_ms = 10_001;
        snapshot.thermal.sensor_loss_cut_live_qualified = false;
        let blockers = snapshot.blockers();
        assert!(blockers.contains(&SafetyBlocker::TemperatureTimestampInvalidOrStale));
        assert!(blockers.contains(&SafetyBlocker::SensorLossCutNotLiveQualified));
    }

    #[test]
    fn thermal_limits_are_numeric_qualified_and_trip_at_the_boundary() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.thermal.qualified_inlet_max_c = None;
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::BoardLimitsNotLiveQualified));

        for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            snapshot = complete_unreleased_snapshot();
            snapshot.thermal.qualified_inlet_max_c = Some(invalid);
            assert!(
                snapshot
                    .blockers()
                    .contains(&SafetyBlocker::BoardLimitsNotLiveQualified),
                "invalid inlet maximum {invalid:?} was admitted"
            );
        }

        snapshot = complete_unreleased_snapshot();
        snapshot.thermal.qualified_outlet_max_c = Some(snapshot.thermal.board.value.outlet_c());
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::TemperatureAboveQualifiedLimit));

        snapshot = complete_unreleased_snapshot();
        snapshot.thermal.qualified_outlet_max_c =
            Some(snapshot.thermal.board.value.outlet_c() + 0.001);
        assert!(!snapshot
            .blockers()
            .contains(&SafetyBlocker::TemperatureAboveQualifiedLimit));
    }

    #[test]
    fn non_finite_observed_temperature_fails_closed_even_if_injected_internally() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.thermal.board.value = BoardTemperatures {
            inlet_c: f64::NAN,
            outlet_c: 20.0,
            inlet_raw: 2_150,
            outlet_raw: 2_250,
        };
        let blockers = snapshot.blockers();
        assert!(blockers.contains(&SafetyBlocker::BoardTemperatureNotFinite));
        assert!(!snapshot.may_energize());
    }

    #[test]
    fn free_running_or_stuck_heartbeat_fails_closed() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.heartbeat.falling_edges = 0;
        snapshot.heartbeat.coupled_to_complete_custody_iteration = false;
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::HeartbeatEdgesInvalid));
        assert!(snapshot
            .blockers()
            .contains(&SafetyBlocker::HeartbeatNotCoupledToCustodyLoop));
    }

    #[test]
    fn every_independent_cut_fact_is_load_bearing() {
        let qualification = complete_test_qualification();
        let authority = released_test_authority(qualification);
        let mut base = complete_unreleased_snapshot();
        base.cut.qualification_record = Some(qualification.identity);
        assert!(base.blockers_against(authority).is_empty());
        assert_eq!(
            base.blockers(),
            vec![
                SafetyBlocker::NativeEnergizationNotReleased,
                SafetyBlocker::ProductionQualificationNotReleased,
            ]
        );
        assert!(!base.may_energize());

        let mutations: &[(SafetyBlocker, fn(&mut Nano3SafetySnapshot))] = &[
            (SafetyBlocker::ProductionQualificationRecordMismatch, |s| {
                s.cut.qualification_record = None
            }),
            (SafetyBlocker::CutTopologyMismatch, |s| {
                s.cut.topology = IndependentCutTopology::HashDomainCoolingRetained
            }),
            (SafetyBlocker::IndependentCutNotArmed, |s| {
                s.cut.cutoff_armed = false
            }),
            (SafetyBlocker::AutomaticRearmPossible, |s| {
                s.cut.manual_rearm_only = false
            }),
        ];
        for (expected, mutate) in mutations {
            let mut snapshot = base;
            mutate(&mut snapshot);
            assert!(
                snapshot.blockers_against(authority).contains(expected),
                "missing {expected:?}"
            );
            assert!(!snapshot.may_energize());
        }
    }

    #[test]
    fn production_record_identity_and_hash_are_exact_release_gates() {
        let qualification = complete_test_qualification();
        let authority = released_test_authority(qualification);
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.cut.qualification_record = Some(qualification.identity);
        assert!(snapshot.blockers_against(authority).is_empty());

        snapshot.cut.qualification_record = Some(QualificationRecordIdentity::new(
            qualification.identity.record_id(),
            [0x5b; 32],
        ));
        assert!(snapshot
            .blockers_against(authority)
            .contains(&SafetyBlocker::ProductionQualificationRecordMismatch));

        let mut invalid = qualification;
        invalid.identity = QualificationRecordIdentity::new("", [0; 32]);
        assert!(snapshot
            .blockers_against(released_test_authority(invalid))
            .contains(&SafetyBlocker::ProductionQualificationRecordInvalid));

        let record_bytes = b"signed test-only Nano 3 production qualification";
        let mut byte_verified = qualification;
        byte_verified.identity = QualificationRecordIdentity::new(
            "nano3-production-qualification-test",
            Sha256::digest(record_bytes).into(),
        );
        assert_eq!(
            verify_qualification_record_against(record_bytes, Some(byte_verified)),
            Ok(byte_verified.identity)
        );
        assert_eq!(
            verify_qualification_record_against(b"altered", Some(byte_verified)),
            Err(QualificationVerificationError::DigestMismatch)
        );
        assert_eq!(
            verify_compiled_qualification_record(record_bytes),
            Err(QualificationVerificationError::NotReleased)
        );
    }

    #[test]
    fn cutoff_and_coast_down_numeric_limits_fail_closed_at_boundaries() {
        let mut qualification = complete_test_qualification();
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.cut.qualification_record = Some(qualification.identity);

        qualification.cut.worst_case_hash_stop_ms = qualification.cut.maximum_safe_cutoff_ms;
        qualification.cut.worst_case_rail_collapse_ms = qualification.cut.maximum_safe_cutoff_ms;
        qualification.cut.worst_case_watchdog_expiry_to_cut_ms =
            qualification.cut.maximum_safe_cutoff_ms;
        qualification.cut.worst_case_post_cut_temperature_rise_c =
            qualification.cut.maximum_post_cut_temperature_rise_c;
        qualification.cut.worst_case_post_cut_peak_temperature_c =
            qualification.cut.maximum_post_cut_peak_temperature_c;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .is_empty());

        qualification.cut.worst_case_hash_stop_ms += 1;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .contains(&SafetyBlocker::CutTimingOutsideQualifiedEnvelope));

        qualification = complete_test_qualification();
        qualification.cut.worst_case_post_cut_temperature_rise_c =
            qualification.cut.maximum_post_cut_temperature_rise_c + 0.001;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .contains(&SafetyBlocker::PostCutThermalOutsideQualifiedEnvelope));

        qualification = complete_test_qualification();
        qualification.cut.worst_case_post_cut_peak_temperature_c = f64::NAN;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .contains(&SafetyBlocker::ProductionQualificationRecordInvalid));
    }

    #[test]
    fn runtime_operating_limits_must_exactly_match_the_hashed_record() {
        let qualification = complete_test_qualification();
        let authority = released_test_authority(qualification);
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.cut.qualification_record = Some(qualification.identity);
        assert!(snapshot.blockers_against(authority).is_empty());

        snapshot.fan.qualified_minimum_rpm = Some(qualification.operating.minimum_fan_rpm - 1);
        assert!(snapshot
            .blockers_against(authority)
            .contains(&SafetyBlocker::CoolingQualificationMismatch));

        snapshot = complete_unreleased_snapshot();
        snapshot.cut.qualification_record = Some(qualification.identity);
        snapshot.thermal.qualified_outlet_max_c =
            Some(qualification.operating.maximum_outlet_temperature_c + 0.001);
        assert!(snapshot
            .blockers_against(authority)
            .contains(&SafetyBlocker::CoolingQualificationMismatch));

        snapshot = complete_unreleased_snapshot();
        snapshot.cut.qualification_record = Some(qualification.identity);
        snapshot.heartbeat.production_timeout_ms = qualification.operating.heartbeat_timeout_ms - 1;
        assert!(snapshot
            .blockers_against(authority)
            .contains(&SafetyBlocker::HeartbeatTimeoutQualificationMismatch));
    }

    #[test]
    fn operating_record_values_reject_zero_nonfinite_and_timeout_overflow() {
        let mut qualification = complete_test_qualification();
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.cut.qualification_record = Some(qualification.identity);

        qualification.operating.heartbeat_timeout_ms = NANO3_HEARTBEAT_COMMISSIONING_TIMEOUT_MS;
        snapshot.heartbeat.production_timeout_ms = NANO3_HEARTBEAT_COMMISSIONING_TIMEOUT_MS;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .is_empty());

        qualification = complete_test_qualification();
        qualification.operating.minimum_fan_rpm = 0;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .contains(&SafetyBlocker::ProductionQualificationRecordInvalid));

        for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            qualification = complete_test_qualification();
            qualification.operating.maximum_inlet_temperature_c = invalid;
            assert!(
                snapshot
                    .blockers_against(released_test_authority(qualification))
                    .contains(&SafetyBlocker::ProductionQualificationRecordInvalid),
                "invalid record inlet maximum {invalid:?} was admitted"
            );

            qualification = complete_test_qualification();
            qualification.operating.maximum_outlet_temperature_c = invalid;
            assert!(
                snapshot
                    .blockers_against(released_test_authority(qualification))
                    .contains(&SafetyBlocker::ProductionQualificationRecordInvalid),
                "invalid record outlet maximum {invalid:?} was admitted"
            );
        }

        qualification = complete_test_qualification();
        qualification.operating.heartbeat_timeout_ms = NANO3_HEARTBEAT_COMMISSIONING_TIMEOUT_MS + 1;
        assert!(snapshot
            .blockers_against(released_test_authority(qualification))
            .contains(&SafetyBlocker::ProductionQualificationRecordInvalid));
    }

    #[test]
    fn current_build_has_no_energization_path_even_with_synthetic_complete_evidence() {
        assert!(!NANO3_NATIVE_ENERGIZATION_RELEASED);
        assert!(NANO3_APPROVED_PRODUCTION_QUALIFICATION.is_none());
        let snapshot = complete_unreleased_snapshot();
        assert_eq!(
            snapshot.blockers(),
            vec![
                SafetyBlocker::NativeEnergizationNotReleased,
                SafetyBlocker::ProductionQualificationNotReleased,
            ]
        );
        assert_eq!(
            snapshot.first_blocker(),
            Some(SafetyBlocker::NativeEnergizationNotReleased)
        );
        assert!(!snapshot.may_energize());
    }

    #[test]
    fn evidence_cannot_be_mixed_across_iterations_or_reused_after_staleness() {
        let mut snapshot = complete_unreleased_snapshot();
        snapshot.watchdog.custody_iteration += 1;
        snapshot.cut.observed_at_ms = 6_999;
        snapshot.watchdog.observed_at_ms = 10_001;
        let blockers = snapshot.blockers();
        assert!(blockers.contains(&SafetyBlocker::EvidenceIterationMismatch));
        assert!(blockers.contains(&SafetyBlocker::CutTimestampInvalidOrStale));
        assert!(blockers.contains(&SafetyBlocker::WatchdogTimestampInvalidOrStale));
    }

    #[test]
    fn read_only_module_defines_no_actuator_or_device_open_surface() {
        let source = include_str!("nano3_safety.rs");
        for banned in [
            concat!("fn ", "set_fan_"),
            concat!("fn ", "write_pwm"),
            concat!("fn ", "kick_watchdog"),
            concat!("fn ", "open_watchdog"),
            concat!("fn ", "set_hash_power"),
            concat!("std::fs::", "write"),
            concat!("OpenOptions", "::new"),
            concat!("File", "::open"),
            concat!("libc", "::ioctl"),
        ] {
            assert!(
                !source.contains(banned),
                "read-only module contains {banned}"
            );
        }
    }
}
