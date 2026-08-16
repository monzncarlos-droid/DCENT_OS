//! Exact held-release L3+ temperature, fan-tach, and PWM replay.
//!
//! The 2017 binary reads two Linux GPIO interrupt counters, calibrates two
//! sensor routes per active chain through ASIC GENERAL_IIC, and controls a
//! sysfs PWM from a narrow retained temperature input. This module performs no
//! file, UART, ASIC, or PWM I/O and grants no cooling or thermal authority.

use crate::bm1485_l3plus_stock::BM1485_L3PLUS_STOCK_CHAIN_COUNT;
use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1485_L3PLUS_STOCK_FAN_COUNT: usize = 2;
pub const BM1485_L3PLUS_STOCK_FAN_INTERRUPT_LABELS: [&str; 2] = ["256", "254"];
pub const BM1485_L3PLUS_STOCK_FAN_INTERRUPT_MARKER: &str = "gpiolib";
pub const BM1485_L3PLUS_STOCK_FAN_SAMPLE_SECONDS: u32 = 5;
pub const BM1485_L3PLUS_STOCK_FAN_RPM_PER_COUNTER_DELTA: u32 = 6;
pub const BM1485_L3PLUS_STOCK_FAN_RPM_CAP: u32 = 0x1004;

pub const BM1485_L3PLUS_STOCK_PWM_PERIOD_NS: u32 = 100_000;
pub const BM1485_L3PLUS_STOCK_PWM_STARTUP_DUTY_NS: u32 = 50_000;
pub const BM1485_L3PLUS_STOCK_PWM_DUTY_NS_PER_PERCENT: u32 = 1_000;
pub const BM1485_L3PLUS_STOCK_PWM_AUTO_LOW_MAX_C: u8 = 35;
pub const BM1485_L3PLUS_STOCK_PWM_AUTO_FULL_ABOVE_C: u8 = 74;
pub const BM1485_L3PLUS_STOCK_PWM_AUTO_PERCENT_PER_C_ABOVE_35: u8 = 2;
pub const BM1485_L3PLUS_STOCK_PWM_UPDATE_HYSTERESIS_C: u8 = 1;

pub const BM1485_L3PLUS_STOCK_SENSOR_ASIC_ADDRESSES: [u8; 2] = [0x0c, 0xc9];
pub const BM1485_L3PLUS_STOCK_REGISTER_GENERAL_IIC: u8 = 0x1c;
pub const BM1485_L3PLUS_STOCK_REGISTER_EXT_TEMP_SENSOR: u8 = 0x44;
pub const BM1485_L3PLUS_STOCK_SENSOR_BUS_ADDRESS_WORD: u8 = 0x98;
pub const BM1485_L3PLUS_STOCK_SENSOR_LOCAL_REGISTER: u8 = 0x00;
pub const BM1485_L3PLUS_STOCK_SENSOR_REMOTE_REGISTER: u8 = 0x01;
pub const BM1485_L3PLUS_STOCK_SENSOR_OFFSET_REGISTER: u8 = 0x11;
pub const BM1485_L3PLUS_STOCK_SENSOR_INITIAL_OFFSET: i8 = -40;
pub const BM1485_L3PLUS_STOCK_SENSOR_REMOTE_ZERO_OFFSET_INCREMENT: i8 = 30;
pub const BM1485_L3PLUS_STOCK_SENSOR_CONVERGED_DELTA_EXCLUSIVE: i16 = 3;
pub const BM1485_L3PLUS_STOCK_SENSOR_CALIBRATION_MAX_PASSES: u8 = 11;
pub const BM1485_L3PLUS_STOCK_SENSOR_READ_MAX_ATTEMPTS: u8 = 4;
pub const BM1485_L3PLUS_STOCK_SENSOR_READ_ATTEMPT_DELAY_MS: u32 = 100;
pub const BM1485_L3PLUS_STOCK_SENSOR_WRITE_DELAY_US: u32 = 2_000;
pub const BM1485_L3PLUS_STOCK_SENSOR_BATCH_SETTLE_MS: u32 = 200;
pub const BM1485_L3PLUS_STOCK_RUNTIME_TEMP_QUERY_SETTLE_MS: u32 = 100;
pub const BM1485_L3PLUS_STOCK_RUNTIME_TEMP_REFRESH_SLEEP_SECONDS: u32 = 10;

pub const BM1485_L3PLUS_STOCK_THERMAL_CONTROL_USES_FIRST_SENSOR_LOCAL_ONLY: bool = true;
pub const BM1485_L3PLUS_STOCK_THERMAL_CONTROL_USES_REMOTE: bool = false;
pub const BM1485_L3PLUS_STOCK_THERMAL_CONTROL_USES_SECOND_SENSOR: bool = false;
pub const BM1485_L3PLUS_STOCK_THERMAL_SHUTDOWN_USES_FAN_COUNT: bool = false;
pub const BM1485_L3PLUS_STOCK_SENSOR_IDENTITY_PHYSICALLY_CONFIRMED: bool = false;
pub const BM1485_L3PLUS_STOCK_COOLING_AUTHORIZES_UART_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_COOLING_AUTHORIZES_PWM_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_COOLING_AUTHORIZES_THERMAL_OPERATION: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockCoolingError {
    FanIndexOutOfRange(usize),
    InterruptLineMissingLabelOrMarker,
    InterruptLineMissingColon,
    InterruptCounterMissing,
    InterruptCounterInvalid,
}

/// Fail-closed parser for the first interrupt count on a stock-matched line.
/// Stock uses substring matching for both the numeric label and `gpiolib`.
pub fn bm1485_l3plus_stock_parse_fan_interrupt_counter(
    line: &str,
    fan_index: usize,
) -> Result<u32, Bm1485L3plusStockCoolingError> {
    let Some(label) = BM1485_L3PLUS_STOCK_FAN_INTERRUPT_LABELS.get(fan_index) else {
        return Err(Bm1485L3plusStockCoolingError::FanIndexOutOfRange(fan_index));
    };
    if !line.contains(label) || !line.contains(BM1485_L3PLUS_STOCK_FAN_INTERRUPT_MARKER) {
        return Err(Bm1485L3plusStockCoolingError::InterruptLineMissingLabelOrMarker);
    }
    let Some((_, after_colon)) = line.split_once(':') else {
        return Err(Bm1485L3plusStockCoolingError::InterruptLineMissingColon);
    };
    let Some(counter) = after_colon.split_ascii_whitespace().next() else {
        return Err(Bm1485L3plusStockCoolingError::InterruptCounterMissing);
    };
    counter
        .parse()
        .map_err(|_| Bm1485L3plusStockCoolingError::InterruptCounterInvalid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1485L3plusStockFanState {
    pub previous_interrupt_counts: [u32; BM1485_L3PLUS_STOCK_FAN_COUNT],
    pub rpm: [u32; BM1485_L3PLUS_STOCK_FAN_COUNT],
    pub present: [bool; BM1485_L3PLUS_STOCK_FAN_COUNT],
    pub maximum_observed_rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockFanSample {
    pub state: Bm1485L3plusStockFanState,
    pub effective_fan_count: u8,
    pub sample_tail_sleep_seconds: u32,
    pub missing_observation_preserves_prior_state: bool,
}

impl Bm1485L3plusStockFanSample {
    pub const fn admits_cooling(self) -> bool {
        false
    }
}

/// Exact stock counter-delta arithmetic. The counter-regression branch uses
/// `current + !previous` without the usual carry, so it is one count below a
/// conventional wrapping subtraction.
pub const fn bm1485_l3plus_stock_fan_counter_delta_exact(previous: u32, current: u32) -> u32 {
    if current >= previous {
        current - previous
    } else {
        current.wrapping_add(!previous)
    }
}

pub const fn bm1485_l3plus_stock_fan_rpm_exact(previous: u32, current: u32) -> u32 {
    let delta = bm1485_l3plus_stock_fan_counter_delta_exact(previous, current);
    let rpm = delta
        .wrapping_mul(60)
        .wrapping_div(BM1485_L3PLUS_STOCK_FAN_SAMPLE_SECONDS * 2);
    if rpm > BM1485_L3PLUS_STOCK_FAN_RPM_CAP {
        BM1485_L3PLUS_STOCK_FAN_RPM_CAP
    } else {
        rpm
    }
}

/// Apply one five-second scan. A missing matching line preserves that fan's
/// prior counter, RPM, and presence flag, matching the persistent stock state.
pub fn bm1485_l3plus_stock_fan_sample(
    mut state: Bm1485L3plusStockFanState,
    observed_interrupt_counts: [Option<u32>; BM1485_L3PLUS_STOCK_FAN_COUNT],
) -> Bm1485L3plusStockFanSample {
    for (fan, observation) in observed_interrupt_counts.into_iter().enumerate() {
        let Some(current) = observation else {
            continue;
        };
        let rpm = bm1485_l3plus_stock_fan_rpm_exact(state.previous_interrupt_counts[fan], current);
        state.previous_interrupt_counts[fan] = current;
        state.rpm[fan] = rpm;
        state.present[fan] = rpm != 0;
        state.maximum_observed_rpm = state.maximum_observed_rpm.max(rpm);
    }
    Bm1485L3plusStockFanSample {
        state,
        effective_fan_count: state.present.into_iter().map(u8::from).sum(),
        sample_tail_sleep_seconds: BM1485_L3PLUS_STOCK_FAN_SAMPLE_SECONDS,
        missing_observation_preserves_prior_state: true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockPwmSource {
    ManualConfiguration,
    AutomaticInvalidOrHot,
    AutomaticCurve,
    AutomaticLow,
    AutomaticHysteresisSuppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockPwmPlan {
    pub source: Bm1485L3plusStockPwmSource,
    pub requested_percent: Option<u8>,
    pub duty_ns: Option<u32>,
    pub next_previous_temperature_c: u8,
    pub stock_uses_fan_count_for_this_decision: bool,
}

impl Bm1485L3plusStockPwmPlan {
    pub const fn authorizes_pwm_io(self) -> bool {
        false
    }
}

fn pwm_write_plan(
    source: Bm1485L3plusStockPwmSource,
    percent: u8,
    previous_temperature_c: u8,
) -> Bm1485L3plusStockPwmPlan {
    let percent = percent.min(100);
    Bm1485L3plusStockPwmPlan {
        source,
        requested_percent: Some(percent),
        duty_ns: Some(u32::from(percent) * BM1485_L3PLUS_STOCK_PWM_DUTY_NS_PER_PERCENT),
        next_previous_temperature_c: previous_temperature_c,
        stock_uses_fan_count_for_this_decision: false,
    }
}

/// Replay `FUN_0003c4cc`. `manual_pwm_percent` is used only when it is at most
/// 100; an out-of-range configured value falls back to the automatic curve.
pub fn bm1485_l3plus_stock_pwm_plan(
    latest_control_temperature_c: u8,
    previous_temperature_c: u8,
    manual_pwm_percent: Option<u8>,
) -> Bm1485L3plusStockPwmPlan {
    if let Some(percent @ 0..=100) = manual_pwm_percent {
        return pwm_write_plan(
            Bm1485L3plusStockPwmSource::ManualConfiguration,
            percent,
            previous_temperature_c,
        );
    }
    if latest_control_temperature_c == 0
        || latest_control_temperature_c > BM1485_L3PLUS_STOCK_PWM_AUTO_FULL_ABOVE_C
    {
        return pwm_write_plan(
            Bm1485L3plusStockPwmSource::AutomaticInvalidOrHot,
            100,
            previous_temperature_c,
        );
    }
    if latest_control_temperature_c <= BM1485_L3PLUS_STOCK_PWM_AUTO_LOW_MAX_C {
        return pwm_write_plan(
            Bm1485L3plusStockPwmSource::AutomaticLow,
            0,
            previous_temperature_c,
        );
    }
    if latest_control_temperature_c.abs_diff(previous_temperature_c)
        <= BM1485_L3PLUS_STOCK_PWM_UPDATE_HYSTERESIS_C
    {
        return Bm1485L3plusStockPwmPlan {
            source: Bm1485L3plusStockPwmSource::AutomaticHysteresisSuppressed,
            requested_percent: None,
            duty_ns: None,
            next_previous_temperature_c: previous_temperature_c,
            stock_uses_fan_count_for_this_decision: false,
        };
    }
    let percent = (latest_control_temperature_c - BM1485_L3PLUS_STOCK_PWM_AUTO_LOW_MAX_C)
        * BM1485_L3PLUS_STOCK_PWM_AUTO_PERCENT_PER_C_ABOVE_35;
    let mut plan = pwm_write_plan(
        Bm1485L3plusStockPwmSource::AutomaticCurve,
        percent,
        latest_control_temperature_c,
    );
    plan.next_previous_temperature_c = latest_control_temperature_c;
    plan
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1485L3plusStockSensorPair {
    pub local_c: u8,
    pub remote_c: u8,
}

/// Exact control-temperature aggregation in `FUN_0003d0e0`: only the local
/// value retained for ASIC address 0x0c is considered for each active chain.
pub fn bm1485_l3plus_stock_control_temperature(
    active_chains: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    retained_sensor_pairs: [[Bm1485L3plusStockSensorPair; 2]; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
) -> u8 {
    let mut maximum = 0;
    for (chain, active) in active_chains.into_iter().enumerate() {
        if active {
            maximum = maximum.max(retained_sensor_pairs[chain][0].local_c);
        }
    }
    maximum
}

fn read_register_frame(chip_address: u8, register: u8) -> [u8; 5] {
    let mut frame = [0x42, 4, chip_address, register, 0];
    frame[4] = stock_bitmain_crc5(&frame[..4], 32);
    frame
}

fn general_iic_write_frame(chip_address: u8, value: u32) -> [u8; 9] {
    let mut frame = [
        0x41,
        8,
        chip_address,
        BM1485_L3PLUS_STOCK_REGISTER_GENERAL_IIC,
        0,
        0,
        0,
        0,
        0,
    ];
    frame[4..8].copy_from_slice(&value.to_le_bytes());
    frame[8] = stock_bitmain_crc5(&frame[..8], 64);
    frame
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockRuntimeTemperatureQueryPlan {
    pub first_sensor_read: [u8; 5],
    pub second_sensor_read: [u8; 5],
    pub register: u8,
    pub delay_after_each_active_chain_ms: u32,
    pub settle_after_both_reads_ms: u32,
    pub refresh_tail_sleep_seconds: u32,
}

impl Bm1485L3plusStockRuntimeTemperatureQueryPlan {
    pub const fn authorizes_uart_io(self) -> bool {
        false
    }
}

pub fn bm1485_l3plus_stock_runtime_temperature_query_plan(
) -> Bm1485L3plusStockRuntimeTemperatureQueryPlan {
    Bm1485L3plusStockRuntimeTemperatureQueryPlan {
        first_sensor_read: read_register_frame(
            BM1485_L3PLUS_STOCK_SENSOR_ASIC_ADDRESSES[0],
            BM1485_L3PLUS_STOCK_REGISTER_EXT_TEMP_SENSOR,
        ),
        second_sensor_read: read_register_frame(
            BM1485_L3PLUS_STOCK_SENSOR_ASIC_ADDRESSES[1],
            BM1485_L3PLUS_STOCK_REGISTER_EXT_TEMP_SENSOR,
        ),
        register: BM1485_L3PLUS_STOCK_REGISTER_EXT_TEMP_SENSOR,
        delay_after_each_active_chain_ms: 10,
        settle_after_both_reads_ms: BM1485_L3PLUS_STOCK_RUNTIME_TEMP_QUERY_SETTLE_MS,
        refresh_tail_sleep_seconds: BM1485_L3PLUS_STOCK_RUNTIME_TEMP_REFRESH_SLEEP_SECONDS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockCalibrationStep {
    Converged,
    WriteOffset(i8),
}

/// One exact local/remote calibration decision from `FUN_0003e70c`.
pub const fn bm1485_l3plus_stock_sensor_calibration_step(
    local_c: i8,
    remote_c: i8,
    current_offset: i8,
) -> Bm1485L3plusStockCalibrationStep {
    if remote_c == 0 {
        return Bm1485L3plusStockCalibrationStep::WriteOffset(
            current_offset.wrapping_add(BM1485_L3PLUS_STOCK_SENSOR_REMOTE_ZERO_OFFSET_INCREMENT),
        );
    }
    let difference = (remote_c as i16 - local_c as i16).abs();
    if difference < BM1485_L3PLUS_STOCK_SENSOR_CONVERGED_DELTA_EXCLUSIVE {
        Bm1485L3plusStockCalibrationStep::Converged
    } else {
        Bm1485L3plusStockCalibrationStep::WriteOffset(
            local_c.wrapping_add(current_offset).wrapping_sub(remote_c),
        )
    }
}

pub const fn bm1485_l3plus_stock_sensor_register_read_value(register: u8) -> u32 {
    (register as u32) << 16 | 0x9801
}

pub const fn bm1485_l3plus_stock_sensor_offset_write_value(offset: i8) -> u32 {
    (offset as u8 as u32) << 24 | 0x0011_9901
}

pub fn bm1485_l3plus_stock_sensor_offset_write_frames(offset: i8) -> [[u8; 9]; 2] {
    let value = bm1485_l3plus_stock_sensor_offset_write_value(offset);
    [
        general_iic_write_frame(BM1485_L3PLUS_STOCK_SENSOR_ASIC_ADDRESSES[0], value),
        general_iic_write_frame(BM1485_L3PLUS_STOCK_SENSOR_ASIC_ADDRESSES[1], value),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupt_parser_pins_two_exact_labels_and_first_cpu_counter() {
        assert_eq!(
            bm1485_l3plus_stock_parse_fan_interrupt_counter("256: 1234 0 0 0 gpiolib fan0", 0),
            Ok(1234)
        );
        assert_eq!(
            bm1485_l3plus_stock_parse_fan_interrupt_counter("254: 9 gpiolib fan1", 1),
            Ok(9)
        );
        assert!(
            bm1485_l3plus_stock_parse_fan_interrupt_counter("256: 1 another-driver", 0).is_err()
        );
        assert_eq!(
            bm1485_l3plus_stock_parse_fan_interrupt_counter("256: 1 gpiolib", 2),
            Err(Bm1485L3plusStockCoolingError::FanIndexOutOfRange(2))
        );
    }

    #[test]
    fn fan_sample_uses_exact_delta_six_cap_and_persistent_missing_state() {
        let first = bm1485_l3plus_stock_fan_sample(
            Bm1485L3plusStockFanState::default(),
            [Some(100), Some(1000)],
        );
        assert_eq!(first.state.rpm, [600, 4100]);
        assert_eq!(first.effective_fan_count, 2);
        assert_eq!(first.state.maximum_observed_rpm, 4100);

        let second = bm1485_l3plus_stock_fan_sample(first.state, [Some(100), None]);
        assert_eq!(second.state.rpm, [0, 4100]);
        assert_eq!(second.state.present, [false, true]);
        assert_eq!(second.effective_fan_count, 1);
        assert_eq!(second.sample_tail_sleep_seconds, 5);
        assert!(!second.admits_cooling());

        assert_eq!(
            bm1485_l3plus_stock_fan_counter_delta_exact(10, 0),
            u32::MAX - 10
        );
    }

    #[test]
    fn automatic_pwm_boundaries_and_hysteresis_match_stock() {
        for temperature in [0, 75, 255] {
            let plan = bm1485_l3plus_stock_pwm_plan(temperature, 50, None);
            assert_eq!(plan.requested_percent, Some(100));
            assert_eq!(plan.duty_ns, Some(100_000));
            assert_eq!(plan.next_previous_temperature_c, 50);
        }
        let low = bm1485_l3plus_stock_pwm_plan(35, 50, None);
        assert_eq!(low.requested_percent, Some(0));
        assert_eq!(low.next_previous_temperature_c, 50);

        let curve = bm1485_l3plus_stock_pwm_plan(36, 50, None);
        assert_eq!(curve.requested_percent, Some(2));
        assert_eq!(curve.duty_ns, Some(2_000));
        assert_eq!(curve.next_previous_temperature_c, 36);

        let top_curve = bm1485_l3plus_stock_pwm_plan(74, 50, None);
        assert_eq!(top_curve.requested_percent, Some(78));
        for temperature in [49, 50, 51] {
            let suppressed = bm1485_l3plus_stock_pwm_plan(temperature, 50, None);
            assert_eq!(suppressed.requested_percent, None);
            assert_eq!(suppressed.next_previous_temperature_c, 50);
        }
        let downward_curve = bm1485_l3plus_stock_pwm_plan(48, 50, None);
        assert_eq!(downward_curve.requested_percent, Some(26));
        assert_eq!(downward_curve.next_previous_temperature_c, 48);
    }

    #[test]
    fn manual_pwm_at_most_one_hundred_overrides_auto() {
        let manual = bm1485_l3plus_stock_pwm_plan(90, 17, Some(37));
        assert_eq!(
            manual.source,
            Bm1485L3plusStockPwmSource::ManualConfiguration
        );
        assert_eq!(manual.duty_ns, Some(37_000));
        assert_eq!(manual.next_previous_temperature_c, 17);

        let manual_max = bm1485_l3plus_stock_pwm_plan(90, 17, Some(100));
        assert_eq!(manual_max.requested_percent, Some(100));

        let invalid_falls_back = bm1485_l3plus_stock_pwm_plan(50, 40, Some(101));
        assert_eq!(
            invalid_falls_back.source,
            Bm1485L3plusStockPwmSource::AutomaticCurve
        );
        assert!(!manual.authorizes_pwm_io());
    }

    #[test]
    fn control_temperature_ignores_remote_and_second_sensor() {
        let mut sensors = [[Bm1485L3plusStockSensorPair::default(); 2]; 4];
        sensors[0][0] = Bm1485L3plusStockSensorPair {
            local_c: 40,
            remote_c: 250,
        };
        sensors[0][1] = Bm1485L3plusStockSensorPair {
            local_c: 240,
            remote_c: 240,
        };
        sensors[1][0].local_c = 60;
        sensors[2][0].local_c = 90;
        assert_eq!(
            bm1485_l3plus_stock_control_temperature([true, true, false, false], sensors),
            60
        );
        assert!(!BM1485_L3PLUS_STOCK_THERMAL_CONTROL_USES_REMOTE);
        assert!(!BM1485_L3PLUS_STOCK_THERMAL_CONTROL_USES_SECOND_SENSOR);
        assert!(!BM1485_L3PLUS_STOCK_THERMAL_SHUTDOWN_USES_FAN_COUNT);
    }

    #[test]
    fn runtime_query_frames_target_both_sensor_asics_and_register_44() {
        let plan = bm1485_l3plus_stock_runtime_temperature_query_plan();
        assert_eq!(plan.first_sensor_read[..4], [0x42, 4, 0x0c, 0x44]);
        assert_eq!(plan.second_sensor_read[..4], [0x42, 4, 0xc9, 0x44]);
        assert_eq!(
            plan.first_sensor_read[4],
            stock_bitmain_crc5(&plan.first_sensor_read[..4], 32)
        );
        assert_eq!(plan.delay_after_each_active_chain_ms, 10);
        assert_eq!(plan.settle_after_both_reads_ms, 100);
        assert_eq!(plan.refresh_tail_sleep_seconds, 10);
        assert!(!plan.authorizes_uart_io());
    }

    #[test]
    fn calibration_step_pins_remote_zero_tolerance_and_signed_offset_math() {
        assert_eq!(
            bm1485_l3plus_stock_sensor_calibration_step(40, 0, -40),
            Bm1485L3plusStockCalibrationStep::WriteOffset(-10)
        );
        for remote in [38, 39, 40, 41, 42] {
            assert_eq!(
                bm1485_l3plus_stock_sensor_calibration_step(40, remote, -20),
                Bm1485L3plusStockCalibrationStep::Converged
            );
        }
        assert_eq!(
            bm1485_l3plus_stock_sensor_calibration_step(40, 43, -20),
            Bm1485L3plusStockCalibrationStep::WriteOffset(-23)
        );
        assert_eq!(BM1485_L3PLUS_STOCK_SENSOR_CALIBRATION_MAX_PASSES, 11);
        assert_eq!(BM1485_L3PLUS_STOCK_SENSOR_READ_MAX_ATTEMPTS, 4);
    }

    #[test]
    fn general_iic_words_and_offset_frames_are_little_endian_exact() {
        assert_eq!(
            bm1485_l3plus_stock_sensor_register_read_value(0),
            0x0000_9801
        );
        assert_eq!(
            bm1485_l3plus_stock_sensor_register_read_value(1),
            0x0001_9801
        );
        assert_eq!(
            bm1485_l3plus_stock_sensor_offset_write_value(-40),
            0xd811_9901
        );
        let frames = bm1485_l3plus_stock_sensor_offset_write_frames(-40);
        assert_eq!(frames[0][..8], [0x41, 8, 0x0c, 0x1c, 1, 0x99, 0x11, 0xd8]);
        assert_eq!(frames[1][2], 0xc9);
        for frame in frames {
            assert_eq!(frame[8], stock_bitmain_crc5(&frame[..8], 64));
        }
    }
}
