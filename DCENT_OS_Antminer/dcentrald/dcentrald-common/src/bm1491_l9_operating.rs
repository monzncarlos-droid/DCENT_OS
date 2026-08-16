//! Exact held-release BM1491/L9 operating frequency/voltage policy replay.
//!
//! The recovered stock function couples clock ramps, warm-up temperature
//! observations, and voltage requests. This module is deliberately pure: it
//! records the observed policy and its weaknesses, but owns no carrier, clock,
//! sensor, fan, or rail and cannot authorize hardware I/O or mining.

use crate::bm1491_l9_work::{BM1491_L9_CHAIN_COUNT, BM1491_L9_CHIPS_PER_CHAIN};

pub const BM1491_L9_SET_FREQUENCY_WITH_VOLTAGE_ADDRESS: u32 = 0x0007_1734;
pub const BM1491_L9_TEMPERATURE_VOLTAGE_OFFSET_ADDRESS: u32 = 0x0007_14a8;
pub const BM1491_L9_CHECK_TEMPERATURE_BASE_ADDRESS: u32 = 0x0007_6a08;
pub const BM1491_L9_STARTUP_MONITOR_ADDRESS: u32 = 0x0007_a13c;

pub const BM1491_L9_COARSE_FREQUENCY_STEP_MHZ: f32 = 12.5;
pub const BM1491_L9_FINE_FREQUENCY_STEP_MHZ: f32 = 6.25;
pub const BM1491_L9_COARSE_FREQUENCY_CAP_MHZ: f32 = 850.0;
pub const BM1491_L9_CONFIGURED_FREQUENCY_CAP_MHZ: f32 = 2_000.0;
pub const BM1491_L9_WARMUP_TEMPERATURE_C: i32 = 70;
pub const BM1491_L9_WARMUP_BUDGET_MS: u32 = 120_000;
pub const BM1491_L9_WARMUP_SLEEP_SECONDS: u8 = 1;
pub const BM1491_L9_WARMUP_PWM_PERCENT: u8 = 30;
pub const BM1491_L9_POST_WARMUP_PWM_PERCENT: u8 = 50;
pub const BM1491_L9_FREQUENCY_VOLTAGE_TRIM_CV: i32 = 10;
pub const BM1491_L9_FREQUENCY_VOLTAGE_MARGIN_CV: i32 = 20;
pub const BM1491_L9_FREQUENCY_VOLTAGE_SETTLE_US: u32 = 200_000;
pub const BM1491_L9_STARTUP_VOLTAGE_TOLERANCE_CV: i32 = 9;
pub const BM1491_L9_STARTUP_VOLTAGE_REQUESTED_STEP: u32 = 100;
pub const BM1491_L9_STARTUP_MONITOR_FATAL_SAMPLES: u8 = 2;
pub const BM1491_L9_EEPROM_FORMAT_WITH_FREQUENCIES: u8 = 4;
pub const BM1491_L9_PT2_SWEEP_BRANCH_CUTOFF_MHZ: i32 = 1_300;

pub const BM1491_L9_TEMPERATURE_OFFSET_THRESHOLDS_C: [i32; 9] = [60, 50, 37, 32, 17, 8, 0, -6, -19];
pub const BM1491_L9_TEMPERATURE_OFFSET_CV: [i32; 9] = [-10, 0, 10, 20, 30, 40, 50, 60, 70];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9TemperatureVoltageOffset {
    pub smoothed_temperature_c: i32,
    pub offset_cv: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9OperatingError {
    RuntimeCountMismatch { observed: u8 },
    NonFiniteFrequency,
    FrequencyOutsideHeldDomain,
    ArithmeticOverflow,
    Pt2FrequencyOutsideHeldDomain { observed: i32 },
    SweepFrequencyCountMismatch { observed: usize },
    NonFiniteSweepFrequency,
    SweepFrequencyOutsideHeldDomain { index: usize },
}

/// Replay the exact one-sample smoothing and temperature bucket table at
/// `0x000714a8`.
///
/// Stock moves the new observation one degree toward the previous global
/// value, rather than moving the previous value one degree toward the new one.
pub fn bm1491_l9_temperature_voltage_offset(
    previous_global_temperature_c: i32,
    observed_temperature_c: i32,
) -> Result<Bm1491L9TemperatureVoltageOffset, Bm1491L9OperatingError> {
    let smoothed = if observed_temperature_c < previous_global_temperature_c {
        observed_temperature_c.checked_add(1)
    } else if observed_temperature_c > previous_global_temperature_c {
        observed_temperature_c.checked_sub(1)
    } else {
        Some(observed_temperature_c)
    }
    .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?;

    let mut offset = 0;
    for index in 0..8 {
        if BM1491_L9_TEMPERATURE_OFFSET_THRESHOLDS_C[index + 1] < smoothed
            && smoothed <= BM1491_L9_TEMPERATURE_OFFSET_THRESHOLDS_C[index]
        {
            offset = BM1491_L9_TEMPERATURE_OFFSET_CV[index];
            break;
        }
    }
    if BM1491_L9_TEMPERATURE_OFFSET_THRESHOLDS_C[0] < smoothed {
        offset = BM1491_L9_TEMPERATURE_OFFSET_CV[0];
    }
    if smoothed <= BM1491_L9_TEMPERATURE_OFFSET_THRESHOLDS_C[8] {
        offset = BM1491_L9_TEMPERATURE_OFFSET_CV[8];
    }
    offset = offset.clamp(BM1491_L9_TEMPERATURE_OFFSET_CV[0], 100);
    Ok(Bm1491L9TemperatureVoltageOffset {
        smoothed_temperature_c: smoothed,
        offset_cv: offset,
    })
}

/// Exact fixed post-warm-up voltage request selected from the stored ambient
/// temperature field. The `-64` sentinel is below eight and therefore selects
/// 1420 cV in stock.
pub const fn bm1491_l9_startup_voltage_target_cv(ambient_temperature_c: i32) -> i32 {
    if ambient_temperature_c < 8 {
        1_420
    } else if ambient_temperature_c < 33 {
        1_390
    } else {
        1_350
    }
}

pub const fn bm1491_l9_warmup_required(minimum_c: i32, maximum_c: i32) -> bool {
    minimum_c < BM1491_L9_WARMUP_TEMPERATURE_C && maximum_c < BM1491_L9_WARMUP_TEMPERATURE_C
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bm1491L9OperatingAction {
    SetFrequencyAll {
        target_mhz: f32,
        runtime_count: u8,
        first_nonzero_result_propagates: bool,
    },
    DelayUs(u32),
    CheckTemperature,
    WarmupUntilThresholdOrBudget {
        threshold_c: i32,
        budget_ms: u32,
        pwm_percent: u8,
        sleep_seconds_per_cycle: u8,
        repeated_checks_per_cycle: u8,
    },
    SetFanPwmPercent(u8),
    StartTemperatureMonitor {
        create_result_ignored: bool,
    },
    SetVoltageBySteps {
        target_cv: i32,
        requested_step: u32,
        result_ignored: bool,
    },
    SetTemperatureMonitorStopFlag,
    JoinTemperatureMonitor {
        create_result_was_ignored: bool,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bm1491L9OperatingRampPlan {
    pub effective_target_mhz: f32,
    pub temperature_voltage_offset: Option<Bm1491L9TemperatureVoltageOffset>,
    pub coarse_voltage_target_cv: i32,
    pub post_warmup_voltage_target_cv: i32,
    pub final_planned_frequency_mhz: f32,
    pub actions: Vec<Bm1491L9OperatingAction>,
    pub stock_post_warmup_voltage_result_ignored: bool,
    pub evidence_is_forgeable: bool,
}

impl Bm1491L9OperatingRampPlan {
    pub const fn admits_hardware_io(&self) -> bool {
        false
    }

    pub const fn admits_mining(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1491L9OperatingRampInput {
    pub current_frequency_mhz: f32,
    pub runtime_frequency_limit_mhz: f32,
    pub configured_frequency_limit_mhz: f32,
    pub frequency_step_delay_us: u32,
    pub ambient_temperature_c: i32,
    pub previous_temperature_global_c: i32,
    pub current_voltage_cv: i32,
    pub working_voltage_cv: i32,
    pub initial_temperature_minimum_c: i32,
    pub initial_temperature_maximum_c: i32,
    pub runtime_count: u8,
}

fn validate_frequency(value: f32) -> Result<(), Bm1491L9OperatingError> {
    if !value.is_finite() {
        return Err(Bm1491L9OperatingError::NonFiniteFrequency);
    }
    if !(0.0..=BM1491_L9_CONFIGURED_FREQUENCY_CAP_MHZ).contains(&value) {
        return Err(Bm1491L9OperatingError::FrequencyOutsideHeldDomain);
    }
    Ok(())
}

/// Build the exact hardware-facing spine through the fine 6.25-MHz ramp.
///
/// The warm-up loop remains an explicit bounded action because its sensor
/// samples and elapsed monotonic time are runtime observations. The monitor
/// state transition itself is separately replayable below.
pub fn bm1491_l9_plan_operating_ramp(
    input: Bm1491L9OperatingRampInput,
) -> Result<Bm1491L9OperatingRampPlan, Bm1491L9OperatingError> {
    if input.runtime_count != BM1491_L9_CHAIN_COUNT {
        return Err(Bm1491L9OperatingError::RuntimeCountMismatch {
            observed: input.runtime_count,
        });
    }
    validate_frequency(input.current_frequency_mhz)?;
    validate_frequency(input.runtime_frequency_limit_mhz)?;
    validate_frequency(input.configured_frequency_limit_mhz)?;

    let effective_target =
        if input.runtime_frequency_limit_mhz <= input.configured_frequency_limit_mhz {
            input.runtime_frequency_limit_mhz
        } else {
            input.configured_frequency_limit_mhz
        };
    let temperature_offset = if input.ambient_temperature_c == -64 {
        None
    } else {
        Some(bm1491_l9_temperature_voltage_offset(
            input.previous_temperature_global_c,
            input.ambient_temperature_c,
        )?)
    };
    let offset_cv = temperature_offset.map_or(0, |value| value.offset_cv);
    let coarse_voltage_target = input
        .working_voltage_cv
        .checked_add(offset_cv)
        .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?;
    let mut current_voltage = input.current_voltage_cv;
    let voltage_steps = current_voltage
        .checked_sub(coarse_voltage_target)
        .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?
        / BM1491_L9_FREQUENCY_VOLTAGE_TRIM_CV;
    let coarse_steps = ((effective_target - input.current_frequency_mhz)
        / BM1491_L9_COARSE_FREQUENCY_STEP_MHZ) as i32;
    let mut frequency = input.current_frequency_mhz;
    let mut actions = Vec::new();

    for index in 0..coarse_steps.max(0) {
        frequency += BM1491_L9_COARSE_FREQUENCY_STEP_MHZ;
        if frequency > BM1491_L9_COARSE_FREQUENCY_CAP_MHZ {
            frequency = BM1491_L9_COARSE_FREQUENCY_CAP_MHZ;
            break;
        }
        actions.push(Bm1491L9OperatingAction::SetFrequencyAll {
            target_mhz: frequency,
            runtime_count: input.runtime_count,
            first_nonzero_result_propagates: true,
        });
        actions.push(Bm1491L9OperatingAction::DelayUs(
            input.frequency_step_delay_us,
        ));

        if coarse_voltage_target
            .checked_add(BM1491_L9_FREQUENCY_VOLTAGE_MARGIN_CV)
            .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?
            < current_voltage
            && effective_target < frequency
            && coarse_steps - voltage_steps <= index
        {
            current_voltage = current_voltage
                .checked_sub(BM1491_L9_FREQUENCY_VOLTAGE_TRIM_CV)
                .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?;
            actions.push(Bm1491L9OperatingAction::SetVoltageBySteps {
                target_cv: current_voltage,
                requested_step: BM1491_L9_STARTUP_VOLTAGE_REQUESTED_STEP,
                result_ignored: false,
            });
            actions.push(Bm1491L9OperatingAction::DelayUs(
                BM1491_L9_FREQUENCY_VOLTAGE_SETTLE_US,
            ));
        }
    }

    actions.push(Bm1491L9OperatingAction::CheckTemperature);
    if bm1491_l9_warmup_required(
        input.initial_temperature_minimum_c,
        input.initial_temperature_maximum_c,
    ) {
        actions.push(Bm1491L9OperatingAction::WarmupUntilThresholdOrBudget {
            threshold_c: BM1491_L9_WARMUP_TEMPERATURE_C,
            budget_ms: BM1491_L9_WARMUP_BUDGET_MS,
            pwm_percent: BM1491_L9_WARMUP_PWM_PERCENT,
            sleep_seconds_per_cycle: BM1491_L9_WARMUP_SLEEP_SECONDS,
            repeated_checks_per_cycle: input.runtime_count,
        });
    }
    actions.push(Bm1491L9OperatingAction::SetFanPwmPercent(
        BM1491_L9_POST_WARMUP_PWM_PERCENT,
    ));
    actions.push(Bm1491L9OperatingAction::StartTemperatureMonitor {
        create_result_ignored: true,
    });

    let post_warmup_voltage = bm1491_l9_startup_voltage_target_cv(input.ambient_temperature_c);
    if input.current_voltage_cv.abs_diff(post_warmup_voltage)
        > BM1491_L9_STARTUP_VOLTAGE_TOLERANCE_CV as u32
    {
        actions.push(Bm1491L9OperatingAction::SetVoltageBySteps {
            target_cv: post_warmup_voltage,
            requested_step: BM1491_L9_STARTUP_VOLTAGE_REQUESTED_STEP,
            result_ignored: true,
        });
    }
    actions.push(Bm1491L9OperatingAction::SetTemperatureMonitorStopFlag);
    actions.push(Bm1491L9OperatingAction::DelayUs(1_000_000));
    actions.push(Bm1491L9OperatingAction::JoinTemperatureMonitor {
        create_result_was_ignored: true,
    });

    let fine_steps = ((effective_target - frequency) / BM1491_L9_FINE_FREQUENCY_STEP_MHZ) as i32;
    for _ in 0..fine_steps.max(0) {
        frequency += BM1491_L9_FINE_FREQUENCY_STEP_MHZ;
        actions.push(Bm1491L9OperatingAction::SetFrequencyAll {
            target_mhz: frequency,
            runtime_count: input.runtime_count,
            first_nonzero_result_propagates: true,
        });
        actions.push(Bm1491L9OperatingAction::DelayUs(
            input.frequency_step_delay_us,
        ));
    }

    Ok(Bm1491L9OperatingRampPlan {
        effective_target_mhz: effective_target,
        temperature_voltage_offset: temperature_offset,
        coarse_voltage_target_cv: coarse_voltage_target,
        post_warmup_voltage_target_cv: post_warmup_voltage,
        final_planned_frequency_mhz: frequency,
        actions,
        stock_post_warmup_voltage_result_ignored: true,
        evidence_is_forgeable: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9StartupMonitorState {
    pub consecutive_read_failures: u8,
    pub consecutive_over_limit: u8,
    pub retained_minimum_c: i32,
    pub retained_maximum_c: i32,
}

impl Default for Bm1491L9StartupMonitorState {
    fn default() -> Self {
        Self {
            consecutive_read_failures: 0,
            consecutive_over_limit: 0,
            retained_minimum_c: -64,
            retained_maximum_c: 255,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9StartupMonitorFault {
    HighTemperature,
    IneffectiveTemperature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9StartupMonitorReaction {
    ContinueAfterOneSecond,
    ClearStopFlagAndExit,
    StockPowerOffSetStatusThenFanMax { fault: Bm1491L9StartupMonitorFault },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9StartupMonitorStep {
    pub state: Bm1491L9StartupMonitorState,
    pub reaction: Bm1491L9StartupMonitorReaction,
    pub stock_fan_max_is_not_dcent_home_policy: bool,
}

pub fn bm1491_l9_startup_monitor_step(
    previous: Bm1491L9StartupMonitorState,
    temperature_result: Result<(i32, i32), ()>,
    high_temperature_limit_c: i32,
    stop_requested: bool,
) -> Result<Bm1491L9StartupMonitorStep, Bm1491L9OperatingError> {
    let mut state = previous;
    match temperature_result {
        Ok((minimum, maximum)) => {
            state.consecutive_read_failures = 0;
            state.retained_minimum_c = minimum;
            state.retained_maximum_c = maximum;
        }
        Err(()) => {
            state.consecutive_read_failures = state
                .consecutive_read_failures
                .checked_add(1)
                .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?;
        }
    }

    if state.retained_minimum_c.max(state.retained_maximum_c) > high_temperature_limit_c {
        state.consecutive_over_limit = state
            .consecutive_over_limit
            .checked_add(1)
            .ok_or(Bm1491L9OperatingError::ArithmeticOverflow)?;
    } else {
        state.consecutive_over_limit = 0;
    }

    let reaction = if state.consecutive_over_limit >= BM1491_L9_STARTUP_MONITOR_FATAL_SAMPLES {
        Bm1491L9StartupMonitorReaction::StockPowerOffSetStatusThenFanMax {
            fault: Bm1491L9StartupMonitorFault::HighTemperature,
        }
    } else if state.consecutive_read_failures >= BM1491_L9_STARTUP_MONITOR_FATAL_SAMPLES {
        Bm1491L9StartupMonitorReaction::StockPowerOffSetStatusThenFanMax {
            fault: Bm1491L9StartupMonitorFault::IneffectiveTemperature,
        }
    } else if stop_requested {
        Bm1491L9StartupMonitorReaction::ClearStopFlagAndExit
    } else {
        Bm1491L9StartupMonitorReaction::ContinueAfterOneSecond
    };

    Ok(Bm1491L9StartupMonitorStep {
        state,
        reaction,
        stock_fan_max_is_not_dcent_home_policy: true,
    })
}

pub fn bm1491_l9_quantize_sweep_average_mhz(value: i32) -> i32 {
    if value > 1_299 {
        1_300
    } else if value > 1_264 {
        1_265
    } else if value > 1_224 {
        1_225
    } else if value > 1_174 {
        1_175
    } else if value > 1_149 {
        1_150
    } else {
        value
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Bm1491L9EepromFrequencyAction {
    PublishPerAsicSweep {
        frequencies_mhz: Vec<f32>,
        callback_result_ignored: bool,
    },
    SetFrequencySingle {
        target_mhz: f32,
        callback_result_ignored: bool,
    },
    DelayUs(u32),
    PublishFrequencyShadow {
        target_mhz: i32,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bm1491L9EepromFrequencyPlan {
    pub average_mhz: Option<f32>,
    pub published_frequency_mhz: i32,
    pub actions: Vec<Bm1491L9EepromFrequencyAction>,
    pub last_ignored_callback_result_becomes_stock_return: bool,
    pub evidence_is_forgeable: bool,
}

impl Bm1491L9EepromFrequencyPlan {
    pub const fn admits_hardware_io(&self) -> bool {
        false
    }
}

/// Replay the format-four EEPROM/PT2 post-ramp policy.
pub fn bm1491_l9_plan_eeprom_frequency(
    current_frequency_mhz: f32,
    pt2_frequency_mhz: i32,
    per_asic_frequencies_mhz: &[f32],
    frequency_step_delay_us: u32,
) -> Result<Bm1491L9EepromFrequencyPlan, Bm1491L9OperatingError> {
    validate_frequency(current_frequency_mhz)?;
    if !(0..=BM1491_L9_CONFIGURED_FREQUENCY_CAP_MHZ as i32).contains(&pt2_frequency_mhz) {
        return Err(Bm1491L9OperatingError::Pt2FrequencyOutsideHeldDomain {
            observed: pt2_frequency_mhz,
        });
    }
    if pt2_frequency_mhz < BM1491_L9_PT2_SWEEP_BRANCH_CUTOFF_MHZ {
        if per_asic_frequencies_mhz.len() != usize::from(BM1491_L9_CHIPS_PER_CHAIN) {
            return Err(Bm1491L9OperatingError::SweepFrequencyCountMismatch {
                observed: per_asic_frequencies_mhz.len(),
            });
        }
        let mut sum = 0.0_f32;
        for (index, frequency) in per_asic_frequencies_mhz.iter().enumerate() {
            if !frequency.is_finite() {
                return Err(Bm1491L9OperatingError::NonFiniteSweepFrequency);
            }
            if !(0.0..=BM1491_L9_CONFIGURED_FREQUENCY_CAP_MHZ).contains(frequency) {
                return Err(Bm1491L9OperatingError::SweepFrequencyOutsideHeldDomain { index });
            }
            sum += *frequency;
        }
        let average = sum / per_asic_frequencies_mhz.len() as f32;
        let published = bm1491_l9_quantize_sweep_average_mhz(average as i32);
        return Ok(Bm1491L9EepromFrequencyPlan {
            average_mhz: Some(average),
            published_frequency_mhz: published,
            actions: vec![
                Bm1491L9EepromFrequencyAction::PublishPerAsicSweep {
                    frequencies_mhz: per_asic_frequencies_mhz.to_vec(),
                    callback_result_ignored: true,
                },
                Bm1491L9EepromFrequencyAction::PublishFrequencyShadow {
                    target_mhz: published,
                },
            ],
            last_ignored_callback_result_becomes_stock_return: false,
            evidence_is_forgeable: true,
        });
    }

    let mut current = current_frequency_mhz;
    let steps = ((pt2_frequency_mhz as f32 - current) / BM1491_L9_FINE_FREQUENCY_STEP_MHZ) as i32;
    let mut actions = Vec::new();
    for _ in 0..steps.max(0) {
        current += BM1491_L9_FINE_FREQUENCY_STEP_MHZ;
        actions.push(Bm1491L9EepromFrequencyAction::SetFrequencySingle {
            target_mhz: current,
            callback_result_ignored: true,
        });
        actions.push(Bm1491L9EepromFrequencyAction::DelayUs(
            frequency_step_delay_us,
        ));
    }
    actions.push(Bm1491L9EepromFrequencyAction::SetFrequencySingle {
        target_mhz: pt2_frequency_mhz as f32,
        callback_result_ignored: true,
    });
    actions.push(Bm1491L9EepromFrequencyAction::DelayUs(
        frequency_step_delay_us,
    ));
    actions.push(Bm1491L9EepromFrequencyAction::PublishFrequencyShadow {
        target_mhz: pt2_frequency_mhz,
    });
    Ok(Bm1491L9EepromFrequencyPlan {
        average_mhz: None,
        published_frequency_mhz: pt2_frequency_mhz,
        actions,
        last_ignored_callback_result_becomes_stock_return: true,
        evidence_is_forgeable: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> Bm1491L9OperatingRampInput {
        Bm1491L9OperatingRampInput {
            current_frequency_mhz: 50.0,
            runtime_frequency_limit_mhz: 1_200.0,
            configured_frequency_limit_mhz: 2_000.0,
            frequency_step_delay_us: 500_000,
            ambient_temperature_c: 20,
            previous_temperature_global_c: 0,
            current_voltage_cv: 1_420,
            working_voltage_cv: 1_350,
            initial_temperature_minimum_c: 70,
            initial_temperature_maximum_c: 70,
            runtime_count: BM1491_L9_CHAIN_COUNT,
        }
    }

    #[test]
    fn temperature_offset_pins_smoothing_and_every_bucket_boundary() {
        assert_eq!(
            bm1491_l9_temperature_voltage_offset(0, 20).unwrap(),
            Bm1491L9TemperatureVoltageOffset {
                smoothed_temperature_c: 19,
                offset_cv: 20,
            }
        );
        let cases = [
            (61, -10),
            (60, -10),
            (50, 0),
            (37, 10),
            (32, 20),
            (17, 30),
            (8, 40),
            (0, 50),
            (-6, 60),
            (-19, 70),
            (-20, 70),
        ];
        for (temperature, offset) in cases {
            assert_eq!(
                bm1491_l9_temperature_voltage_offset(temperature, temperature)
                    .unwrap()
                    .offset_cv,
                offset
            );
        }
    }

    #[test]
    fn startup_voltage_bands_and_tolerance_are_exact() {
        assert_eq!(bm1491_l9_startup_voltage_target_cv(-64), 1_420);
        assert_eq!(bm1491_l9_startup_voltage_target_cv(7), 1_420);
        assert_eq!(bm1491_l9_startup_voltage_target_cv(8), 1_390);
        assert_eq!(bm1491_l9_startup_voltage_target_cv(32), 1_390);
        assert_eq!(bm1491_l9_startup_voltage_target_cv(33), 1_350);

        let mut input = base_input();
        input.current_voltage_cv = 1_399;
        let plan = bm1491_l9_plan_operating_ramp(input).unwrap();
        assert!(!plan.actions.iter().any(|action| matches!(
            action,
            Bm1491L9OperatingAction::SetVoltageBySteps {
                target_cv: 1390,
                result_ignored: true,
                ..
            }
        )));
        input.current_voltage_cv = 1_400;
        let plan = bm1491_l9_plan_operating_ramp(input).unwrap();
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            Bm1491L9OperatingAction::SetVoltageBySteps {
                target_cv: 1390,
                result_ignored: true,
                ..
            }
        )));
    }

    #[test]
    fn coarse_then_fine_ramp_caps_at_850_and_reaches_exact_aligned_target() {
        let plan = bm1491_l9_plan_operating_ramp(base_input()).unwrap();
        let frequencies: Vec<_> = plan
            .actions
            .iter()
            .filter_map(|action| match action {
                Bm1491L9OperatingAction::SetFrequencyAll { target_mhz, .. } => Some(*target_mhz),
                _ => None,
            })
            .collect();
        assert_eq!(frequencies.first(), Some(&62.5));
        assert!(frequencies.contains(&850.0));
        assert_eq!(frequencies.last(), Some(&1_200.0));
        assert_eq!(plan.final_planned_frequency_mhz, 1_200.0);
        assert_eq!(plan.effective_target_mhz, 1_200.0);
        assert!(plan.stock_post_warmup_voltage_result_ignored);
        assert!(!plan.admits_hardware_io());
        assert!(!plan.admits_mining());
    }

    #[test]
    fn fine_ramp_preserves_stock_truncated_remainder() {
        let mut input = base_input();
        input.runtime_frequency_limit_mhz = 1_203.0;
        let plan = bm1491_l9_plan_operating_ramp(input).unwrap();
        assert_eq!(plan.effective_target_mhz, 1_203.0);
        assert_eq!(plan.final_planned_frequency_mhz, 1_200.0);
    }

    #[test]
    fn warmup_action_is_bounded_and_repeated_per_held_chain_count() {
        let mut input = base_input();
        input.initial_temperature_minimum_c = 69;
        input.initial_temperature_maximum_c = 69;
        let plan = bm1491_l9_plan_operating_ramp(input).unwrap();
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            Bm1491L9OperatingAction::WarmupUntilThresholdOrBudget {
                threshold_c: 70,
                budget_ms: 120_000,
                pwm_percent: 30,
                sleep_seconds_per_cycle: 1,
                repeated_checks_per_cycle: 3,
            }
        )));
        assert!(!bm1491_l9_warmup_required(70, 69));
        assert!(!bm1491_l9_warmup_required(69, 70));
    }

    #[test]
    fn monitor_fault_precedence_and_second_consecutive_boundaries_are_exact() {
        let safe = Bm1491L9StartupMonitorState {
            retained_minimum_c: 20,
            retained_maximum_c: 60,
            ..Default::default()
        };
        let first_fail = bm1491_l9_startup_monitor_step(safe, Err(()), 90, false).unwrap();
        assert_eq!(
            first_fail.reaction,
            Bm1491L9StartupMonitorReaction::ContinueAfterOneSecond
        );
        let second_fail =
            bm1491_l9_startup_monitor_step(first_fail.state, Err(()), 90, true).unwrap();
        assert_eq!(
            second_fail.reaction,
            Bm1491L9StartupMonitorReaction::StockPowerOffSetStatusThenFanMax {
                fault: Bm1491L9StartupMonitorFault::IneffectiveTemperature,
            }
        );

        let first_high = bm1491_l9_startup_monitor_step(safe, Ok((20, 91)), 90, false).unwrap();
        let second_high =
            bm1491_l9_startup_monitor_step(first_high.state, Err(()), 90, true).unwrap();
        assert_eq!(
            second_high.reaction,
            Bm1491L9StartupMonitorReaction::StockPowerOffSetStatusThenFanMax {
                fault: Bm1491L9StartupMonitorFault::HighTemperature,
            }
        );
        assert!(second_high.stock_fan_max_is_not_dcent_home_policy);

        let first_default_failure =
            bm1491_l9_startup_monitor_step(Default::default(), Err(()), 90, false).unwrap();
        assert_eq!(first_default_failure.state.consecutive_read_failures, 1);
        assert_eq!(first_default_failure.state.consecutive_over_limit, 1);
        let second_default_failure =
            bm1491_l9_startup_monitor_step(first_default_failure.state, Err(()), 90, false)
                .unwrap();
        assert_eq!(
            second_default_failure.reaction,
            Bm1491L9StartupMonitorReaction::StockPowerOffSetStatusThenFanMax {
                fault: Bm1491L9StartupMonitorFault::HighTemperature,
            }
        );
    }

    #[test]
    fn monitor_stop_clears_only_when_no_fatal_branch_wins() {
        let step = bm1491_l9_startup_monitor_step(
            Bm1491L9StartupMonitorState {
                retained_minimum_c: 20,
                retained_maximum_c: 60,
                ..Default::default()
            },
            Ok((20, 60)),
            90,
            true,
        )
        .unwrap();
        assert_eq!(
            step.reaction,
            Bm1491L9StartupMonitorReaction::ClearStopFlagAndExit
        );
    }

    #[test]
    fn sweep_average_quantization_pins_every_boundary() {
        let cases = [
            (1_149, 1_149),
            (1_150, 1_150),
            (1_174, 1_150),
            (1_175, 1_175),
            (1_224, 1_175),
            (1_225, 1_225),
            (1_264, 1_225),
            (1_265, 1_265),
            (1_299, 1_265),
            (1_300, 1_300),
        ];
        for (input, expected) in cases {
            assert_eq!(bm1491_l9_quantize_sweep_average_mhz(input), expected);
        }
    }

    #[test]
    fn eeprom_sweep_branch_averages_f32_then_publishes_quantized_shadow() {
        let mut frequencies = vec![1_200.0; usize::from(BM1491_L9_CHIPS_PER_CHAIN)];
        frequencies[usize::from(BM1491_L9_CHIPS_PER_CHAIN) / 2..].fill(1_250.0);
        let plan = bm1491_l9_plan_eeprom_frequency(1_200.0, 1_299, &frequencies, 500_000).unwrap();
        assert_eq!(plan.average_mhz, Some(1_225.0));
        assert_eq!(plan.published_frequency_mhz, 1_225);
        assert!(!plan.last_ignored_callback_result_becomes_stock_return);
        assert!(!plan.admits_hardware_io());
    }

    #[test]
    fn eeprom_pt2_branch_writes_intermediates_then_exact_target_and_ignores_results() {
        let plan = bm1491_l9_plan_eeprom_frequency(1_200.0, 1_313, &[], 500_000).unwrap();
        let writes: Vec<_> = plan
            .actions
            .iter()
            .filter_map(|action| match action {
                Bm1491L9EepromFrequencyAction::SetFrequencySingle { target_mhz, .. } => {
                    Some(*target_mhz)
                }
                _ => None,
            })
            .collect();
        assert_eq!(writes.len(), 19);
        assert_eq!(writes.first(), Some(&1_206.25));
        assert_eq!(writes.get(writes.len() - 2), Some(&1_312.5));
        assert_eq!(writes.last(), Some(&1_313.0));
        assert_eq!(plan.published_frequency_mhz, 1_313);
        assert!(plan.last_ignored_callback_result_becomes_stock_return);
        assert!(plan.evidence_is_forgeable);
    }

    #[test]
    fn malformed_shapes_fail_closed() {
        let mut input = base_input();
        input.runtime_count = 2;
        assert_eq!(
            bm1491_l9_plan_operating_ramp(input),
            Err(Bm1491L9OperatingError::RuntimeCountMismatch { observed: 2 })
        );
        input = base_input();
        input.current_frequency_mhz = f32::NAN;
        assert_eq!(
            bm1491_l9_plan_operating_ramp(input),
            Err(Bm1491L9OperatingError::NonFiniteFrequency)
        );
        assert_eq!(
            bm1491_l9_plan_eeprom_frequency(1_200.0, 1_299, &[], 1),
            Err(Bm1491L9OperatingError::SweepFrequencyCountMismatch { observed: 0 })
        );
        input = base_input();
        input.working_voltage_cv = i32::MAX;
        assert_eq!(
            bm1491_l9_plan_operating_ramp(input),
            Err(Bm1491L9OperatingError::ArithmeticOverflow)
        );
        assert_eq!(
            bm1491_l9_plan_eeprom_frequency(1_200.0, i32::MAX, &[], 1),
            Err(Bm1491L9OperatingError::Pt2FrequencyOutsideHeldDomain { observed: i32::MAX })
        );
        let mut frequencies = vec![1_200.0; usize::from(BM1491_L9_CHIPS_PER_CHAIN)];
        frequencies[7] = f32::NAN;
        assert_eq!(
            bm1491_l9_plan_eeprom_frequency(1_200.0, 1_299, &frequencies, 1),
            Err(Bm1491L9OperatingError::NonFiniteSweepFrequency)
        );
        frequencies[7] = -1.0;
        assert_eq!(
            bm1491_l9_plan_eeprom_frequency(1_200.0, 1_299, &frequencies, 1),
            Err(Bm1491L9OperatingError::SweepFrequencyOutsideHeldDomain { index: 7 })
        );
    }
}
