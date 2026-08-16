//! Pure, fail-closed thermal, fan, PIC-heartbeat, and shutdown evidence for
//! the exact held S15/T15 BM1391 stock releases.
//!
//! The stock facts represented here come from the held binaries identified in
//! the companion phase-6 evidence note. This module performs no I/O and grants
//! no driver, carrier, rail, work-dispatch, or re-energization authority.
//! In particular, a PIC acknowledgement is not proof that a rail is off:
//! [`verify_bm1391_shutdown`] also requires an independent electrical
//! observation for every declared-present chain.

pub const BM1391_STOCK_CHAIN_SLOTS: u8 = 16;
pub const BM1391_STOCK_TEMPERATURE_OFFSET_C: i16 = 0x40;
pub const BM1391_STOCK_ADJUSTED_TEMPERATURE_DELTA_C: i16 = 15;
pub const BM1391_STOCK_OUTLET_FULL_FAN_THRESHOLD_C: i16 = 68;
pub const BM1391_STOCK_FATAL_OUTLET_THRESHOLD_C: i16 = 81;
pub const BM1391_STOCK_MINIMUM_PRESENT_FANS: u8 = 2;
pub const BM1391_STOCK_FAN_SLOTS: usize = 8;
pub const BM1391_STOCK_FAN_SCAN_PASSES: u8 = 2;
pub const BM1391_STOCK_FAN_RECORDS_PER_CHECK: u8 =
    BM1391_STOCK_FAN_SCAN_PASSES * BM1391_STOCK_FAN_SLOTS as u8;
pub const BM1391_STOCK_FAN_TACH_RPM_PER_COUNT: u32 = 120;
pub const BM1391_STOCK_FAN_LOW_SPEED_LOG_THRESHOLD_RPM: u32 = 501;
pub const BM1391_STOCK_FAN_PWM_MIN_PERCENT: u8 = 30;
pub const BM1391_STOCK_FAN_PWM_MAX_PERCENT: u8 = 100;
pub const BM1391_STOCK_SUPERVISOR_PERIOD_SECS: u8 = 10;
pub const BM1391_STOCK_HEARTBEAT_PERIOD_SECS: u8 = 10;
pub const BM1391_STOCK_PIC_ATTEMPTS: u8 = 3;
pub const BM1391_STOCK_PIC_RETRY_DELAY_SECS: u8 = 1;
pub const BM1391_STOCK_PIC_TX_GUARD_US: u32 = 100_000;
pub const BM1391_STOCK_PIC_RX_WAIT_US: u32 = 400_000;
pub const BM1391_STOCK_FPGA_RUN_BIT: u32 = 1 << 6;

/// Exact command bytes sent by the generic PIC transport for heartbeat.
pub const BM1391_STOCK_HEARTBEAT_REQUEST: [u8; 6] = [0x55, 0xaa, 0x04, 0x16, 0x00, 0x1a];
/// Exact command bytes used by the stock fatal path to request rail-off.
pub const BM1391_STOCK_RAIL_OFF_REQUEST: [u8; 7] = [0x55, 0xaa, 0x05, 0x15, 0x00, 0x00, 0x1a];
/// Exact inverse command found adjacent to rail-off. It is data only here.
pub const BM1391_STOCK_RAIL_ON_REQUEST: [u8; 7] = [0x55, 0xaa, 0x05, 0x15, 0x01, 0x00, 0x1b];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockModel {
    S15,
    T15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockTemperatureAggregate {
    /// Candidate for the maximum value logged by stock as PCB `out`.
    PcbOutMaximum,
    /// Candidate for the minimum value logged by stock as PCB `in`.
    PcbInMinimum,
    Neither,
}

/// Model-specific address grouping used only for stock diagnostic logging.
pub const fn bm1391_stock_temperature_log_group(model: Bm1391StockModel, address: u8) -> u8 {
    match model {
        Bm1391StockModel::S15 => address / 3,
        Bm1391StockModel::T15 => address >> 2,
    }
}

/// Classify the exact sensor-address ranges consumed by the stock aggregate.
pub const fn bm1391_stock_temperature_aggregate(
    model: Bm1391StockModel,
    address: u8,
) -> Bm1391StockTemperatureAggregate {
    match model {
        Bm1391StockModel::S15 if address >= 0x24 && address <= 0x26 => {
            Bm1391StockTemperatureAggregate::PcbOutMaximum
        }
        Bm1391StockModel::S15 if address >= 0x33 && address <= 0x35 => {
            Bm1391StockTemperatureAggregate::PcbInMinimum
        }
        Bm1391StockModel::T15 if address >= 0x28 && address <= 0x2b => {
            Bm1391StockTemperatureAggregate::PcbOutMaximum
        }
        Bm1391StockModel::T15 if address >= 0x38 && address <= 0x3b => {
            Bm1391StockTemperatureAggregate::PcbInMinimum
        }
        _ => Bm1391StockTemperatureAggregate::Neither,
    }
}

/// Decode the low byte accepted by the stock temperature transaction.
///
/// Stock treats a zero return word as transaction failure. A successful value
/// is stored as `low_byte - 0x40`; the separately retained adjusted sample is
/// this value plus 15 degrees C.
pub const fn decode_bm1391_stock_temperature(response_word: u32) -> Option<i16> {
    if response_word == 0 {
        None
    } else {
        Some((response_word as u8) as i16 - BM1391_STOCK_TEMPERATURE_OFFSET_C)
    }
}

pub const fn bm1391_stock_adjusted_temperature(temperature_c: i16) -> Option<i16> {
    temperature_c.checked_add(BM1391_STOCK_ADJUSTED_TEMPERATURE_DELTA_C)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockFanPwm {
    pub requested_percent: i32,
    pub clamped_percent: u8,
    pub register_word: u32,
}

/// Reproduce the exact 30..100 percent clamp and AXI PWM word construction.
pub const fn bm1391_stock_fan_pwm(requested_percent: i32) -> Bm1391StockFanPwm {
    let clamped_percent = if requested_percent < BM1391_STOCK_FAN_PWM_MIN_PERCENT as i32 {
        BM1391_STOCK_FAN_PWM_MIN_PERCENT
    } else if requested_percent > BM1391_STOCK_FAN_PWM_MAX_PERCENT as i32 {
        BM1391_STOCK_FAN_PWM_MAX_PERCENT
    } else {
        requested_percent as u8
    };
    let percent = clamped_percent as u32;
    let register_word = ((percent >> 1) << 16) | ((5_000 - percent * 50) / 100);
    Bm1391StockFanPwm {
        requested_percent,
        clamped_percent,
        register_word,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391FanTachError {
    RpmOverflow { raw_count: u32 },
}

/// Decode one stock tach count. Zero is retained as fan-absent.
pub const fn decode_bm1391_stock_fan_tach(
    raw_count: u32,
) -> Result<Option<u32>, Bm1391FanTachError> {
    if raw_count == 0 {
        return Ok(None);
    }
    match raw_count.checked_mul(BM1391_STOCK_FAN_TACH_RPM_PER_COUNT) {
        Some(rpm) => Ok(Some(rpm)),
        None => Err(Bm1391FanTachError::RpmOverflow { raw_count }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockFanSpeedAction {
    Accept,
    /// Exact stock behavior below 501 RPM: log/return failure from the check,
    /// while the supervisor later discards that return value.
    LogOnly,
}

pub const fn bm1391_stock_fan_speed_action(rpm: u32) -> Bm1391StockFanSpeedAction {
    if rpm < BM1391_STOCK_FAN_LOW_SPEED_LOG_THRESHOLD_RPM {
        Bm1391StockFanSpeedAction::LogOnly
    } else {
        Bm1391StockFanSpeedAction::Accept
    }
}

/// The stock heartbeat accepts only response bytes 1=`0x16`, 2=`0x01`.
pub const fn bm1391_stock_heartbeat_ack(response: [u8; 6]) -> bool {
    response[1] == 0x16 && response[2] == 0x01
}

/// The stock rail-control helper accepts only the two-byte `0x15, 0x01` reply.
pub const fn bm1391_stock_rail_control_ack(response: [u8; 2]) -> bool {
    response[0] == 0x15 && response[1] == 0x01
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockHeartbeatHostAction {
    /// Exact stock behavior for both success and three-attempt exhaustion:
    /// discard the probe result and sleep before the next probe.
    ContinueAfterTenSeconds,
}

pub const fn bm1391_stock_heartbeat_host_action(
    _probe_acked: bool,
) -> Bm1391StockHeartbeatHostAction {
    Bm1391StockHeartbeatHostAction::ContinueAfterTenSeconds
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391FailClosedStopReason {
    MissingOutletTemperature,
    OutletTemperatureAtOrAboveStockTrip { observed_c: i16 },
    MissingFanObservation,
    FanCountBelowStockMinimum { observed: u8 },
    HeartbeatProbeExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391SafetyDecision {
    Monitor,
    StopAndAttemptRailOff(Bm1391FailClosedStopReason),
}

/// Fail-closed policy around the exact stock high-temperature/fan boundaries.
/// Missing observations are stopped even though stock is not consistently
/// fail-closed for missing sensor data.
pub const fn assess_bm1391_thermal_and_fans(
    pcb_out_temperature_c: Option<i16>,
    healthy_fan_count: Option<u8>,
) -> Bm1391SafetyDecision {
    match pcb_out_temperature_c {
        None => Bm1391SafetyDecision::StopAndAttemptRailOff(
            Bm1391FailClosedStopReason::MissingOutletTemperature,
        ),
        Some(observed_c) if observed_c >= BM1391_STOCK_FATAL_OUTLET_THRESHOLD_C => {
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::OutletTemperatureAtOrAboveStockTrip { observed_c },
            )
        }
        Some(_) => match healthy_fan_count {
            None => Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::MissingFanObservation,
            ),
            Some(observed) if observed < BM1391_STOCK_MINIMUM_PRESENT_FANS => {
                Bm1391SafetyDecision::StopAndAttemptRailOff(
                    Bm1391FailClosedStopReason::FanCountBelowStockMinimum { observed },
                )
            }
            Some(_) => Bm1391SafetyDecision::Monitor,
        },
    }
}

/// Count only fans meeting the recovered 501 RPM stock diagnostic boundary,
/// then apply the fail-closed two-fan requirement. Stock itself counts every
/// nonzero tach as present and discards the low-speed check result.
pub fn assess_bm1391_fan_rpms(
    fan_rpm: [Option<u32>; BM1391_STOCK_FAN_SLOTS],
) -> Bm1391SafetyDecision {
    let healthy = fan_rpm
        .into_iter()
        .flatten()
        .filter(|rpm| *rpm >= BM1391_STOCK_FAN_LOW_SPEED_LOG_THRESHOLD_RPM)
        .count() as u8;
    if healthy < BM1391_STOCK_MINIMUM_PRESENT_FANS {
        Bm1391SafetyDecision::StopAndAttemptRailOff(
            Bm1391FailClosedStopReason::FanCountBelowStockMinimum { observed: healthy },
        )
    } else {
        Bm1391SafetyDecision::Monitor
    }
}

/// Fail-closed wrapper for one completed three-attempt stock heartbeat probe.
pub const fn assess_bm1391_heartbeat(probe_acked: bool) -> Bm1391SafetyDecision {
    if probe_acked {
        Bm1391SafetyDecision::Monitor
    } else {
        Bm1391SafetyDecision::StopAndAttemptRailOff(
            Bm1391FailClosedStopReason::HeartbeatProbeExhausted,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockShutdownStep {
    LatchMainStateStopByte,
    LatchGlobalStopByte,
    RequestPicRailOffForEachStateOneChainWhileNotDead,
    MarkDead,
    ClearFpgaRunBit,
}

pub const BM1391_STOCK_FATAL_SHUTDOWN_SEQUENCE: [Bm1391StockShutdownStep; 5] = [
    Bm1391StockShutdownStep::LatchMainStateStopByte,
    Bm1391StockShutdownStep::LatchGlobalStopByte,
    Bm1391StockShutdownStep::RequestPicRailOffForEachStateOneChainWhileNotDead,
    Bm1391StockShutdownStep::MarkDead,
    Bm1391StockShutdownStep::ClearFpgaRunBit,
];

/// Forgeable passive assertions supplied by an observation owner. This type
/// carries no source identity, freshness, generation, or temporal ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391ShutdownEvidence {
    /// Chains independently declared physically present by the caller.
    pub present_chain_mask: u16,
    /// Chain slots actually observed entering the rail-off wrapper. Stock
    /// requires both chain state exactly `1` and dead state not yet `0xdead`.
    pub stock_active_chain_mask: u16,
    /// Chain requests for which the exact PIC acknowledgement was observed.
    pub pic_rail_off_ack_mask: u16,
    /// Chains independently measured electrically de-energized.
    pub electrically_off_chain_mask: u16,
    /// Read-back observation that FPGA run bit 6 is clear.
    pub fpga_run_bit_cleared: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391ShutdownEvidenceError {
    NoPresentChainsObserved,
    StockActiveMaskOutsidePresent { outside_mask: u16 },
    PicAckMaskOutsidePresent { outside_mask: u16 },
    ElectricalMaskOutsidePresent { outside_mask: u16 },
    StockSkippedPresentChains { missing_mask: u16 },
    MissingPicRailOffAcks { missing_mask: u16 },
    FpgaRunBitStillSet,
    MissingElectricalOffEvidence { missing_mask: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391VerifiedOff {
    present_chain_mask: u16,
}

impl Bm1391VerifiedOff {
    pub const fn present_chain_mask(&self) -> u16 {
        self.present_chain_mask
    }

    /// A successful passive consistency check is never live safety authority.
    pub const fn admits_live_authority(&self) -> bool {
        false
    }
}

/// Check one caller-asserted shutdown observation without granting authority.
///
/// Stock's fatal function ignores each rail-off helper return. This stricter
/// contract therefore requires command coverage, exact PIC acknowledgements,
/// FPGA stop read-back, and independent electrical rail-off assertions. The
/// pure function cannot authenticate their source, freshness, or ordering.
pub const fn verify_bm1391_shutdown(
    evidence: Bm1391ShutdownEvidence,
) -> Result<Bm1391VerifiedOff, Bm1391ShutdownEvidenceError> {
    let present = evidence.present_chain_mask;
    if present == 0 {
        return Err(Bm1391ShutdownEvidenceError::NoPresentChainsObserved);
    }
    let outside_active = evidence.stock_active_chain_mask & !present;
    if outside_active != 0 {
        return Err(Bm1391ShutdownEvidenceError::StockActiveMaskOutsidePresent {
            outside_mask: outside_active,
        });
    }
    let outside_ack = evidence.pic_rail_off_ack_mask & !present;
    if outside_ack != 0 {
        return Err(Bm1391ShutdownEvidenceError::PicAckMaskOutsidePresent {
            outside_mask: outside_ack,
        });
    }
    let outside_electrical = evidence.electrically_off_chain_mask & !present;
    if outside_electrical != 0 {
        return Err(Bm1391ShutdownEvidenceError::ElectricalMaskOutsidePresent {
            outside_mask: outside_electrical,
        });
    }
    let skipped = present & !evidence.stock_active_chain_mask;
    if skipped != 0 {
        return Err(Bm1391ShutdownEvidenceError::StockSkippedPresentChains {
            missing_mask: skipped,
        });
    }
    let missing_ack = present & !evidence.pic_rail_off_ack_mask;
    if missing_ack != 0 {
        return Err(Bm1391ShutdownEvidenceError::MissingPicRailOffAcks {
            missing_mask: missing_ack,
        });
    }
    if !evidence.fpga_run_bit_cleared {
        return Err(Bm1391ShutdownEvidenceError::FpgaRunBitStillSet);
    }
    let missing_electrical = present & !evidence.electrically_off_chain_mask;
    if missing_electrical != 0 {
        return Err(Bm1391ShutdownEvidenceError::MissingElectricalOffEvidence {
            missing_mask: missing_electrical,
        });
    }
    Ok(Bm1391VerifiedOff {
        present_chain_mask: present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_specific_temperature_address_groups_do_not_collapse() {
        assert_eq!(
            bm1391_stock_temperature_log_group(Bm1391StockModel::S15, 0x24),
            0x0c
        );
        assert_eq!(
            bm1391_stock_temperature_log_group(Bm1391StockModel::T15, 0x28),
            0x0a
        );
        assert_eq!(
            bm1391_stock_temperature_aggregate(Bm1391StockModel::S15, 0x26),
            Bm1391StockTemperatureAggregate::PcbOutMaximum
        );
        assert_eq!(
            bm1391_stock_temperature_aggregate(Bm1391StockModel::S15, 0x33),
            Bm1391StockTemperatureAggregate::PcbInMinimum
        );
        assert_eq!(
            bm1391_stock_temperature_aggregate(Bm1391StockModel::T15, 0x2b),
            Bm1391StockTemperatureAggregate::PcbOutMaximum
        );
        assert_eq!(
            bm1391_stock_temperature_aggregate(Bm1391StockModel::T15, 0x38),
            Bm1391StockTemperatureAggregate::PcbInMinimum
        );
        assert_eq!(
            bm1391_stock_temperature_aggregate(Bm1391StockModel::S15, 0x2b),
            Bm1391StockTemperatureAggregate::Neither
        );

        let boundaries = [
            (
                Bm1391StockModel::S15,
                0x23,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::S15,
                0x24,
                Bm1391StockTemperatureAggregate::PcbOutMaximum,
            ),
            (
                Bm1391StockModel::S15,
                0x27,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::S15,
                0x32,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::S15,
                0x35,
                Bm1391StockTemperatureAggregate::PcbInMinimum,
            ),
            (
                Bm1391StockModel::S15,
                0x36,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::T15,
                0x27,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::T15,
                0x28,
                Bm1391StockTemperatureAggregate::PcbOutMaximum,
            ),
            (
                Bm1391StockModel::T15,
                0x2c,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::T15,
                0x37,
                Bm1391StockTemperatureAggregate::Neither,
            ),
            (
                Bm1391StockModel::T15,
                0x3b,
                Bm1391StockTemperatureAggregate::PcbInMinimum,
            ),
            (
                Bm1391StockModel::T15,
                0x3c,
                Bm1391StockTemperatureAggregate::Neither,
            ),
        ];
        for (model, address, expected) in boundaries {
            assert_eq!(bm1391_stock_temperature_aggregate(model, address), expected);
        }
    }

    #[test]
    fn stock_temperature_decode_keeps_zero_as_failure_and_exact_offsets() {
        assert_eq!(decode_bm1391_stock_temperature(0), None);
        assert_eq!(decode_bm1391_stock_temperature(0x40), Some(0));
        assert_eq!(decode_bm1391_stock_temperature(0x91), Some(81));
        assert_eq!(decode_bm1391_stock_temperature(0x100), Some(-64));
        assert_eq!(bm1391_stock_adjusted_temperature(81), Some(96));
        assert_eq!(bm1391_stock_adjusted_temperature(i16::MAX), None);
    }

    #[test]
    fn stock_pwm_clamps_and_encodes_every_boundary() {
        assert_eq!(bm1391_stock_fan_pwm(29).clamped_percent, 30);
        assert_eq!(bm1391_stock_fan_pwm(29).register_word, 0x000f_0023);
        assert_eq!(bm1391_stock_fan_pwm(30).register_word, 0x000f_0023);
        assert_eq!(bm1391_stock_fan_pwm(31).register_word, 0x000f_0022);
        assert_eq!(bm1391_stock_fan_pwm(99).register_word, 0x0031_0000);
        assert_eq!(bm1391_stock_fan_pwm(100).register_word, 0x0032_0000);
        assert_eq!(bm1391_stock_fan_pwm(101).register_word, 0x0032_0000);
        assert_eq!(bm1391_stock_fan_pwm(i32::MIN).register_word, 0x000f_0023);
        assert_eq!(bm1391_stock_fan_pwm(i32::MAX).register_word, 0x0032_0000);
    }

    #[test]
    fn stock_tach_zero_is_absent_and_nonzero_is_times_120() {
        assert_eq!(decode_bm1391_stock_fan_tach(0), Ok(None));
        assert_eq!(decode_bm1391_stock_fan_tach(50), Ok(Some(6_000)));
        assert_eq!(
            decode_bm1391_stock_fan_tach(u32::MAX),
            Err(Bm1391FanTachError::RpmOverflow {
                raw_count: u32::MAX
            })
        );
        let largest_raw = u32::MAX / BM1391_STOCK_FAN_TACH_RPM_PER_COUNT;
        assert_eq!(
            decode_bm1391_stock_fan_tach(largest_raw),
            Ok(Some(largest_raw * BM1391_STOCK_FAN_TACH_RPM_PER_COUNT))
        );
        assert!(matches!(
            decode_bm1391_stock_fan_tach(largest_raw + 1),
            Err(Bm1391FanTachError::RpmOverflow { .. })
        ));
        assert_eq!(
            bm1391_stock_fan_speed_action(500),
            Bm1391StockFanSpeedAction::LogOnly
        );
        assert_eq!(
            bm1391_stock_fan_speed_action(501),
            Bm1391StockFanSpeedAction::Accept
        );
    }

    #[test]
    fn fan_scan_pic_timing_and_fatal_sequence_are_exact() {
        assert_eq!(BM1391_STOCK_FAN_SLOTS, 8);
        assert_eq!(BM1391_STOCK_FAN_SCAN_PASSES, 2);
        assert_eq!(BM1391_STOCK_FAN_RECORDS_PER_CHECK, 16);
        assert_eq!(BM1391_STOCK_PIC_ATTEMPTS, 3);
        assert_eq!(BM1391_STOCK_PIC_RETRY_DELAY_SECS, 1);
        assert_eq!(BM1391_STOCK_PIC_TX_GUARD_US, 100_000);
        assert_eq!(BM1391_STOCK_PIC_RX_WAIT_US, 400_000);
        assert_eq!(
            BM1391_STOCK_FATAL_SHUTDOWN_SEQUENCE,
            [
                Bm1391StockShutdownStep::LatchMainStateStopByte,
                Bm1391StockShutdownStep::LatchGlobalStopByte,
                Bm1391StockShutdownStep::RequestPicRailOffForEachStateOneChainWhileNotDead,
                Bm1391StockShutdownStep::MarkDead,
                Bm1391StockShutdownStep::ClearFpgaRunBit,
            ]
        );
    }

    #[test]
    fn pic_frames_and_ack_positions_are_exact() {
        assert_eq!(
            BM1391_STOCK_HEARTBEAT_REQUEST,
            [0x55, 0xaa, 0x04, 0x16, 0x00, 0x1a]
        );
        assert!(bm1391_stock_heartbeat_ack([
            0xff, 0x16, 0x01, 0xaa, 0xbb, 0xcc
        ]));
        assert!(!bm1391_stock_heartbeat_ack([0x16, 0x01, 0x00, 0, 0, 0]));
        assert_eq!(
            BM1391_STOCK_RAIL_OFF_REQUEST,
            [0x55, 0xaa, 0x05, 0x15, 0, 0, 0x1a]
        );
        assert_eq!(
            BM1391_STOCK_RAIL_ON_REQUEST,
            [0x55, 0xaa, 0x05, 0x15, 1, 0, 0x1b]
        );
        assert!(bm1391_stock_rail_control_ack([0x15, 0x01]));
        assert!(!bm1391_stock_rail_control_ack([0x15, 0x00]));
    }

    #[test]
    fn heartbeat_loss_is_observed_but_not_enforced_by_stock() {
        assert_eq!(
            bm1391_stock_heartbeat_host_action(true),
            Bm1391StockHeartbeatHostAction::ContinueAfterTenSeconds
        );
        assert_eq!(
            bm1391_stock_heartbeat_host_action(false),
            Bm1391StockHeartbeatHostAction::ContinueAfterTenSeconds
        );
        assert_eq!(
            assess_bm1391_heartbeat(false),
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::HeartbeatProbeExhausted
            )
        );
    }

    #[test]
    fn thermal_and_fan_boundaries_are_fail_closed() {
        assert_eq!(
            assess_bm1391_thermal_and_fans(Some(80), Some(2)),
            Bm1391SafetyDecision::Monitor
        );
        assert_eq!(
            assess_bm1391_thermal_and_fans(Some(81), Some(2)),
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::OutletTemperatureAtOrAboveStockTrip { observed_c: 81 }
            )
        );
        assert_eq!(
            assess_bm1391_thermal_and_fans(Some(80), Some(1)),
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::FanCountBelowStockMinimum { observed: 1 }
            )
        );
        assert_eq!(
            assess_bm1391_thermal_and_fans(None, Some(2)),
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::MissingOutletTemperature
            )
        );
        assert_eq!(
            assess_bm1391_thermal_and_fans(Some(80), None),
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::MissingFanObservation
            )
        );
        assert_eq!(
            assess_bm1391_fan_rpms([Some(500), Some(501), None, None, None, None, None, None,]),
            Bm1391SafetyDecision::StopAndAttemptRailOff(
                Bm1391FailClosedStopReason::FanCountBelowStockMinimum { observed: 1 }
            )
        );
        assert_eq!(
            assess_bm1391_fan_rpms([Some(501), Some(502), None, None, None, None, None, None,]),
            Bm1391SafetyDecision::Monitor
        );
    }

    #[test]
    fn shutdown_needs_coverage_ack_fpga_stop_and_electrical_evidence() {
        let complete = Bm1391ShutdownEvidence {
            present_chain_mask: 0b111,
            stock_active_chain_mask: 0b111,
            pic_rail_off_ack_mask: 0b111,
            electrically_off_chain_mask: 0b111,
            fpga_run_bit_cleared: true,
        };
        assert_eq!(
            verify_bm1391_shutdown(complete),
            Ok(Bm1391VerifiedOff {
                present_chain_mask: 0b111
            })
        );
        let verified = verify_bm1391_shutdown(complete).expect("consistent passive assertions");
        assert_eq!(verified.present_chain_mask(), 0b111);
        assert!(!verified.admits_live_authority());

        assert_eq!(
            verify_bm1391_shutdown(Bm1391ShutdownEvidence {
                present_chain_mask: 0,
                stock_active_chain_mask: 0,
                pic_rail_off_ack_mask: 0,
                electrically_off_chain_mask: 0,
                fpga_run_bit_cleared: true,
            }),
            Err(Bm1391ShutdownEvidenceError::NoPresentChainsObserved)
        );

        let outside_active = Bm1391ShutdownEvidence {
            stock_active_chain_mask: 0b1111,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(outside_active),
            Err(Bm1391ShutdownEvidenceError::StockActiveMaskOutsidePresent {
                outside_mask: 0b1000
            })
        );
        let outside_ack = Bm1391ShutdownEvidence {
            pic_rail_off_ack_mask: 0b1111,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(outside_ack),
            Err(Bm1391ShutdownEvidenceError::PicAckMaskOutsidePresent {
                outside_mask: 0b1000
            })
        );
        let outside_electrical = Bm1391ShutdownEvidence {
            electrically_off_chain_mask: 0b1111,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(outside_electrical),
            Err(Bm1391ShutdownEvidenceError::ElectricalMaskOutsidePresent {
                outside_mask: 0b1000
            })
        );

        let skipped = Bm1391ShutdownEvidence {
            stock_active_chain_mask: 0b011,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(skipped),
            Err(Bm1391ShutdownEvidenceError::StockSkippedPresentChains {
                missing_mask: 0b100
            })
        );
        let no_ack = Bm1391ShutdownEvidence {
            pic_rail_off_ack_mask: 0b011,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(no_ack),
            Err(Bm1391ShutdownEvidenceError::MissingPicRailOffAcks {
                missing_mask: 0b100
            })
        );
        let still_running = Bm1391ShutdownEvidence {
            fpga_run_bit_cleared: false,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(still_running),
            Err(Bm1391ShutdownEvidenceError::FpgaRunBitStillSet)
        );
        let not_measured = Bm1391ShutdownEvidence {
            electrically_off_chain_mask: 0b011,
            ..complete
        };
        assert_eq!(
            verify_bm1391_shutdown(not_measured),
            Err(Bm1391ShutdownEvidenceError::MissingElectricalOffEvidence {
                missing_mask: 0b100
            })
        );
    }
}
