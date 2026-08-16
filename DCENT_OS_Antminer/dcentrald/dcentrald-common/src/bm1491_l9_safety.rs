//! Exact held-release BM1491/L9 temperature and shutdown pure contract.
//!
//! The evidence is the symbol-bearing `godminer` from held
//! `FR-1.19(260302-L9).bmu`. This module models the BM1491 chip-temperature
//! query/record conversion, the high/low extrema debounce, and the stock
//! one-shot shutdown call order. It performs no I/O. In particular, GPIO 412
//! value zero is only the recovered stock-software `power_off` request; the
//! physical load, electrical polarity, write completion, and de-energization
//! are not proved by the held image.

use crate::bm1491_l9_work::{BM1491_L9_ASIC_ADDRESS_INTERVAL, BM1491_L9_CHIPS_PER_CHAIN};

pub const BM1491_L9_CHIP_TEMP_FUNCTION_ADDRESS: u32 = 0x000f_99b8;
pub const BM1491_L9_TEMP_AGGREGATE_FUNCTION_ADDRESS: u32 = 0x000f_67d8;
pub const BM1491_L9_UPDATE_TEMPERATURE_ADDRESS: u32 = 0x0009_7d88;
pub const BM1491_L9_STATUS_TASK_ADDRESS: u32 = 0x0008_dbbc;
pub const BM1491_L9_ALL_DEVICE_POWEROFF_ADDRESS: u32 = 0x0008_8b64;
pub const BM1491_L9_POWER_OFF_ADDRESS: u32 = 0x0008_8c20;
pub const BM1491_L9_BITMAIN_POWER_OFF_ADDRESS: u32 = 0x0014_dfb0;

pub const BM1491_L9_TEMP_COMMAND_REGISTER: u8 = 0x8c;
pub const BM1491_L9_TEMP_COMMAND_SELECT_ZERO: u32 = 0x1100_0000;
pub const BM1491_L9_TEMP_COMMAND_SELECT_TWO: u32 = 0x1102_0000;
pub const BM1491_L9_TEMP_RESPONSE_REGISTER: u16 = 0x0090;
pub const BM1491_L9_TEMP_RESPONSE_VALID_BIT: u32 = 0x80;
pub const BM1491_L9_TEMP_COMMAND_DELAY_MS: u32 = 10;
pub const BM1491_L9_TEMP_RECORD_LEN: usize = 12;

pub const BM1491_L9_CHIP_TEMP_MULTIPLIER_BITS: u64 = 0x4084_b70a_3d70_a3d7;
pub const BM1491_L9_CHIP_TEMP_DIVISOR_BITS: u64 = 0x40b0_0000_0000_0000;
pub const BM1491_L9_CHIP_TEMP_OFFSET_BITS: u64 = 0x4071_f7ae_147a_e148;

pub const BM1491_L9_MAX_CHIP_TEMP_C: i32 = 95;
pub const BM1491_L9_MAX_PCB_TEMP_C: i32 = 80;
pub const BM1491_L9_MIN_PCB_TEMP_C: i32 = -40;
pub const BM1491_L9_FATAL_CONSECUTIVE_SAMPLES: u32 = 3;
pub const BM1491_L9_EVENT_TEMPERATURE_ACQUISITION_BIT: u32 = 1 << 0;
pub const BM1491_L9_EVENT_HIGH_TEMPERATURE_BIT: u32 = 1 << 1;
pub const BM1491_L9_EVENT_LOW_TEMPERATURE_BIT: u32 = 1 << 2;
pub const BM1491_L9_EVENT_SENSOR_MISSING_BIT: u32 = 1 << 3;
pub const BM1491_L9_MAX_INEFFECTIVE_TEMPERATURES: u8 = 2;
pub const BM1491_L9_SENSOR_COUNT: u8 = 2;
pub const BM1491_L9_SENSOR_VALUES_PER_SENSOR: u8 = 3;
pub const BM1491_L9_MISSING_SENSOR_FATAL_SAMPLES: u32 = 3;
pub const BM1491_L9_INEFFECTIVE_RESET_SAMPLES: u32 = 2;
pub const BM1491_L9_SENSOR_COLLECTION_SUCCESS: i32 = 0;
pub const BM1491_L9_SENSOR_COLLECTION_FAILURE: i32 = -1;

pub const BM1491_L9_POWER_GPIO: u32 = 412;
pub const BM1491_L9_POWER_GPIO_OUTPUT_DIRECTION: u32 = 1;
pub const BM1491_L9_POWER_OFF_GPIO_VALUE: u32 = 0;
pub const BM1491_L9_POWER_OFF_DELAY_SECONDS: u32 = 1;
pub const BM1491_L9_RUNTIME_COUNT: usize = 3;
pub const BM1491_L9_TOPOL_PIC_MCU_ENABLED: bool = false;

pub const BM1491_L9_TEMPERATURE_INPUT_AUTHENTICATED: bool = false;
pub const BM1491_L9_GPIO_PHYSICAL_LOAD_PROVEN: bool = false;
pub const BM1491_L9_POWER_WRITE_READBACK_VERIFIED: bool = false;
pub const BM1491_L9_ELECTRICAL_OFF_PROVEN: bool = false;
pub const BM1491_L9_SAFETY_AUTHORIZES_HARDWARE_IO: bool = false;
pub const BM1491_L9_SAFETY_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ChipTemperatureQueryStep {
    WriteRegister { register: u8, value: u32 },
    DelayMilliseconds(u32),
    SynchronousRead { register: u16, expected_records: u8 },
}

/// Exact stock query spine from `chip_temp_ltc_1491`. The chain/runtime and
/// transport receiver remain caller context and are not admitted here.
pub const BM1491_L9_CHIP_TEMPERATURE_QUERY: [Bm1491L9ChipTemperatureQueryStep; 5] = [
    Bm1491L9ChipTemperatureQueryStep::WriteRegister {
        register: BM1491_L9_TEMP_COMMAND_REGISTER,
        value: BM1491_L9_TEMP_COMMAND_SELECT_ZERO,
    },
    Bm1491L9ChipTemperatureQueryStep::DelayMilliseconds(BM1491_L9_TEMP_COMMAND_DELAY_MS),
    Bm1491L9ChipTemperatureQueryStep::WriteRegister {
        register: BM1491_L9_TEMP_COMMAND_REGISTER,
        value: BM1491_L9_TEMP_COMMAND_SELECT_TWO,
    },
    Bm1491L9ChipTemperatureQueryStep::DelayMilliseconds(BM1491_L9_TEMP_COMMAND_DELAY_MS),
    Bm1491L9ChipTemperatureQueryStep::SynchronousRead {
        register: BM1491_L9_TEMP_RESPONSE_REGISTER,
        expected_records: BM1491_L9_CHIPS_PER_CHAIN,
    },
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1491L9ChipTemperatureSample {
    pub raw_chip_address: u8,
    pub chip_index: u8,
    pub raw_code: u16,
    pub temperature_c: f32,
}

impl Bm1491L9ChipTemperatureSample {
    pub const fn admits_thermal_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ChipTemperatureRecordError {
    InvalidResponseStatus,
    UnexpectedRegister { observed: u16 },
    UnalignedChipAddress { observed: u8 },
    ChipIndexOutOfRange { observed: u8 },
}

/// Decode one exact 12-byte register-return record.
///
/// Stock tests bit `0x80` in the native little-endian response word, byte
/// swaps that word, and uses its low 16 bits as the ADC code. Stock integer
/// divides the address by two; refusing odd addresses is deliberate clean
/// hardening against aliasing two wire addresses onto one chip index.
#[allow(clippy::indexing_slicing)]
pub fn bm1491_l9_decode_chip_temperature_record(
    record: &[u8; BM1491_L9_TEMP_RECORD_LEN],
) -> Result<Bm1491L9ChipTemperatureSample, Bm1491L9ChipTemperatureRecordError> {
    let response_word = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
    if response_word & BM1491_L9_TEMP_RESPONSE_VALID_BIT == 0 {
        return Err(Bm1491L9ChipTemperatureRecordError::InvalidResponseStatus);
    }
    let register = u16::from_le_bytes([record[6], record[7]]);
    if register != BM1491_L9_TEMP_RESPONSE_REGISTER {
        return Err(Bm1491L9ChipTemperatureRecordError::UnexpectedRegister { observed: register });
    }
    let raw_chip_address = record[4];
    if raw_chip_address % BM1491_L9_ASIC_ADDRESS_INTERVAL != 0 {
        return Err(Bm1491L9ChipTemperatureRecordError::UnalignedChipAddress {
            observed: raw_chip_address,
        });
    }
    let chip_index = raw_chip_address / BM1491_L9_ASIC_ADDRESS_INTERVAL;
    if chip_index >= BM1491_L9_CHIPS_PER_CHAIN {
        return Err(Bm1491L9ChipTemperatureRecordError::ChipIndexOutOfRange {
            observed: chip_index,
        });
    }
    let raw_code = (response_word.swap_bytes() & 0xffff) as u16;
    let temperature_c = (((f64::from(raw_code) - 0.5)
        * f64::from_bits(BM1491_L9_CHIP_TEMP_MULTIPLIER_BITS))
        / f64::from_bits(BM1491_L9_CHIP_TEMP_DIVISOR_BITS)
        - f64::from_bits(BM1491_L9_CHIP_TEMP_OFFSET_BITS)) as f32;
    Ok(Bm1491L9ChipTemperatureSample {
        raw_chip_address,
        chip_index,
        raw_code,
        temperature_c,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9TemperatureExtrema {
    pub pcb_min_c: i32,
    pub pcb_max_c: i32,
    pub chip_max_c: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bm1491L9ThermalDebounceState {
    pub consecutive_high_samples: u32,
    pub consecutive_low_samples: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9ThermalEvents {
    pub high_temperature: bool,
    pub low_temperature: bool,
}

impl Bm1491L9ThermalEvents {
    pub const fn event_mask(self) -> u32 {
        (if self.high_temperature {
            BM1491_L9_EVENT_HIGH_TEMPERATURE_BIT
        } else {
            0
        }) | (if self.low_temperature {
            BM1491_L9_EVENT_LOW_TEMPERATURE_BIT
        } else {
            0
        })
    }

    pub const fn requests_stock_shutdown(self) -> bool {
        self.high_temperature || self.low_temperature
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9ThermalStep {
    pub state: Bm1491L9ThermalDebounceState,
    pub events: Bm1491L9ThermalEvents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ThermalStepError {
    HighCounterOverflow,
    LowCounterOverflow,
}

/// Replay the high/low extrema branches in `update_temperature`.
///
/// High is strict (`chip > 95 || pcb > 80`); low is inclusive at the lower
/// bound (`pcb_min <= -40`). Each event appears on the third consecutive
/// violating sample. Safe observations reset only their corresponding
/// counter. Inputs remain caller assertions and grant no shutdown authority.
pub fn bm1491_l9_step_thermal_extrema(
    previous: Bm1491L9ThermalDebounceState,
    extrema: Bm1491L9TemperatureExtrema,
) -> Result<Bm1491L9ThermalStep, Bm1491L9ThermalStepError> {
    let high_violation = extrema.chip_max_c > BM1491_L9_MAX_CHIP_TEMP_C
        || extrema.pcb_max_c > BM1491_L9_MAX_PCB_TEMP_C;
    let low_violation = extrema.pcb_min_c <= BM1491_L9_MIN_PCB_TEMP_C;
    let high = if high_violation {
        previous
            .consecutive_high_samples
            .checked_add(1)
            .ok_or(Bm1491L9ThermalStepError::HighCounterOverflow)?
    } else {
        0
    };
    let low = if low_violation {
        previous
            .consecutive_low_samples
            .checked_add(1)
            .ok_or(Bm1491L9ThermalStepError::LowCounterOverflow)?
    } else {
        0
    };
    Ok(Bm1491L9ThermalStep {
        state: Bm1491L9ThermalDebounceState {
            consecutive_high_samples: high,
            consecutive_low_samples: low,
        },
        events: Bm1491L9ThermalEvents {
            high_temperature: high >= BM1491_L9_FATAL_CONSECUTIVE_SAMPLES,
            low_temperature: low >= BM1491_L9_FATAL_CONSECUTIVE_SAMPLES,
        },
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bm1491L9SensorAvailabilityState {
    pub consecutive_local_missing: u32,
    pub consecutive_remote_missing: u32,
    pub consecutive_ineffective_excess: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9SensorAvailabilityObservation {
    pub local_valid_count: u8,
    pub remote_valid_count: u8,
    /// Count of `-64` local, remote, or third-value fields across both
    /// configured sensor records.
    pub ineffective_value_count: u8,
    /// Exact runtime byte `+0x494`, set only around `scan_rxu_hang` in the
    /// recovered binary. It suppresses immediate event bit zero, not the
    /// later missing-sensor counters.
    pub rxu_hang_scan_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9SensorAvailabilityStep {
    pub state: Bm1491L9SensorAvailabilityState,
    /// `FUN_00097160` returns zero only when every configured local and remote
    /// value is valid. The underlying runtime read callback's return is
    /// discarded before this classification.
    pub collection_return: i32,
    pub immediate_acquisition_error_event: bool,
    pub local_missing_event: bool,
    pub remote_missing_event: bool,
    /// Exact held-L9 `opt_algo == 0x0d` branch: the second consecutive sample
    /// with more than two ineffective values invokes runtime vtable `+0x18`.
    pub reset_hashing_for_ineffective_sensors: bool,
}

impl Bm1491L9SensorAvailabilityStep {
    pub const fn event_mask(self) -> u32 {
        let acquisition = if self.immediate_acquisition_error_event {
            BM1491_L9_EVENT_TEMPERATURE_ACQUISITION_BIT
        } else {
            0
        };
        let missing = if self.local_missing_event || self.remote_missing_event {
            BM1491_L9_EVENT_SENSOR_MISSING_BIT
        } else {
            0
        };
        acquisition | missing
    }

    pub const fn requests_stock_fatal_status(self) -> bool {
        self.local_missing_event || self.remote_missing_event
    }

    pub const fn admits_hardware_reset(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SensorAvailabilityError {
    LocalValidCountOutOfRange { observed: u8 },
    RemoteValidCountOutOfRange { observed: u8 },
    IneffectiveValueCountOutOfRange { observed: u8 },
    LocalMissingCounterOverflow,
    RemoteMissingCounterOverflow,
    IneffectiveCounterOverflow,
}

/// Replay the held L9 missing/ineffective branches in `update_temperature`.
///
/// `FUN_00097160` ignores the sensor callback's return and instead returns
/// failure unless all two local and all two remote values are valid. That
/// failure raises immediate event bit zero unless `scan_rxu_hang` has set the
/// runtime suppression byte. The stock shutdown task does not consume bit
/// zero; its missing-sensor input is the separately debounced bit three below.
///
/// Zero valid local or remote readings raises the common missing-sensor event
/// on the third consecutive sample. More than two ineffective values uses the
/// L9-specific `opt_algo == 0x0d` branch: its second consecutive sample calls
/// the hashing-reset callback and clears the local, remote, and ineffective
/// counters. Events already raised earlier in that same update remain raised.
/// Count bounds are clean hardening for the exact two-record/three-value
/// profile.
pub fn bm1491_l9_step_sensor_availability(
    previous: Bm1491L9SensorAvailabilityState,
    observation: Bm1491L9SensorAvailabilityObservation,
) -> Result<Bm1491L9SensorAvailabilityStep, Bm1491L9SensorAvailabilityError> {
    if observation.local_valid_count > BM1491_L9_SENSOR_COUNT {
        return Err(Bm1491L9SensorAvailabilityError::LocalValidCountOutOfRange {
            observed: observation.local_valid_count,
        });
    }
    if observation.remote_valid_count > BM1491_L9_SENSOR_COUNT {
        return Err(
            Bm1491L9SensorAvailabilityError::RemoteValidCountOutOfRange {
                observed: observation.remote_valid_count,
            },
        );
    }
    let maximum_ineffective = BM1491_L9_SENSOR_COUNT * BM1491_L9_SENSOR_VALUES_PER_SENSOR;
    if observation.ineffective_value_count > maximum_ineffective {
        return Err(
            Bm1491L9SensorAvailabilityError::IneffectiveValueCountOutOfRange {
                observed: observation.ineffective_value_count,
            },
        );
    }

    let collection_return = if observation.local_valid_count == BM1491_L9_SENSOR_COUNT
        && observation.remote_valid_count == BM1491_L9_SENSOR_COUNT
    {
        BM1491_L9_SENSOR_COLLECTION_SUCCESS
    } else {
        BM1491_L9_SENSOR_COLLECTION_FAILURE
    };
    let immediate_acquisition_error_event = collection_return
        != BM1491_L9_SENSOR_COLLECTION_SUCCESS
        && !observation.rxu_hang_scan_active;

    let mut state = previous;
    state.consecutive_local_missing = if observation.local_valid_count == 0 {
        previous
            .consecutive_local_missing
            .checked_add(1)
            .ok_or(Bm1491L9SensorAvailabilityError::LocalMissingCounterOverflow)?
    } else {
        0
    };
    let local_missing_event =
        state.consecutive_local_missing >= BM1491_L9_MISSING_SENSOR_FATAL_SAMPLES;

    state.consecutive_remote_missing = if observation.remote_valid_count == 0 {
        previous
            .consecutive_remote_missing
            .checked_add(1)
            .ok_or(Bm1491L9SensorAvailabilityError::RemoteMissingCounterOverflow)?
    } else {
        0
    };
    let remote_missing_event =
        state.consecutive_remote_missing >= BM1491_L9_MISSING_SENSOR_FATAL_SAMPLES;

    let mut reset_hashing_for_ineffective_sensors = false;
    if observation.ineffective_value_count > BM1491_L9_MAX_INEFFECTIVE_TEMPERATURES {
        state.consecutive_ineffective_excess = previous
            .consecutive_ineffective_excess
            .checked_add(1)
            .ok_or(Bm1491L9SensorAvailabilityError::IneffectiveCounterOverflow)?;
        if state.consecutive_ineffective_excess >= BM1491_L9_INEFFECTIVE_RESET_SAMPLES {
            reset_hashing_for_ineffective_sensors = true;
            state = Bm1491L9SensorAvailabilityState::default();
        }
    } else {
        state.consecutive_ineffective_excess = 0;
    }

    Ok(Bm1491L9SensorAvailabilityStep {
        state,
        collection_return,
        immediate_acquisition_error_event,
        local_missing_event,
        remote_missing_event,
        reset_hashing_for_ineffective_sensors,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ShutdownAction {
    LatchOneShotPowerOff,
    EnsurePowerGpioExportedAsOutputIfMissing { gpio: u32, direction: u32 },
    WritePowerGpio { gpio: u32, value: u32 },
    SetSoftwarePowerStateOff,
    DelaySeconds(u32),
    StopRuntimeHashing { runtime_index: usize },
    InvokeDevicePowerOffCallback { runtime_index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9ShutdownPlan {
    pub actions: Vec<Bm1491L9ShutdownAction>,
    pub already_latched: bool,
    pub stock_gpio_write_result_discarded: bool,
    pub electrical_off_proven: bool,
}

impl Bm1491L9ShutdownPlan {
    pub const fn admits_hardware_io(&self) -> bool {
        false
    }

    pub const fn admits_mining(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ShutdownPlanError {
    RuntimeCountOutOfRange { observed: usize },
}

fn bm1491_l9_append_stock_global_power_off(actions: &mut Vec<Bm1491L9ShutdownAction>) {
    actions.push(
        Bm1491L9ShutdownAction::EnsurePowerGpioExportedAsOutputIfMissing {
            gpio: BM1491_L9_POWER_GPIO,
            direction: BM1491_L9_POWER_GPIO_OUTPUT_DIRECTION,
        },
    );
    actions.push(Bm1491L9ShutdownAction::WritePowerGpio {
        gpio: BM1491_L9_POWER_GPIO,
        value: BM1491_L9_POWER_OFF_GPIO_VALUE,
    });
    actions.push(Bm1491L9ShutdownAction::SetSoftwarePowerStateOff);
    actions.push(Bm1491L9ShutdownAction::DelaySeconds(
        BM1491_L9_POWER_OFF_DELAY_SECONDS,
    ));
}

/// Build the observed one-shot shutdown call order in `task_check_miner_status`.
///
/// On the first fatal event, stock latches the state, performs global power
/// off, invokes the stop-hashing and device power-off callbacks for every
/// runtime, then performs global power off a second time. A set latch makes
/// later calls no-ops. The exact L9 profile has three runtimes/chains; larger
/// caller-supplied counts are refused.
pub fn bm1491_l9_plan_stock_shutdown(
    already_latched: bool,
    runtime_count: usize,
) -> Result<Bm1491L9ShutdownPlan, Bm1491L9ShutdownPlanError> {
    if runtime_count > BM1491_L9_RUNTIME_COUNT {
        return Err(Bm1491L9ShutdownPlanError::RuntimeCountOutOfRange {
            observed: runtime_count,
        });
    }
    if already_latched {
        return Ok(Bm1491L9ShutdownPlan {
            actions: Vec::new(),
            already_latched: true,
            stock_gpio_write_result_discarded: true,
            electrical_off_proven: false,
        });
    }
    let mut actions = Vec::with_capacity(9 + runtime_count * 2);
    actions.push(Bm1491L9ShutdownAction::LatchOneShotPowerOff);
    bm1491_l9_append_stock_global_power_off(&mut actions);
    for runtime_index in 0..runtime_count {
        actions.push(Bm1491L9ShutdownAction::StopRuntimeHashing { runtime_index });
        actions.push(Bm1491L9ShutdownAction::InvokeDevicePowerOffCallback { runtime_index });
    }
    bm1491_l9_append_stock_global_power_off(&mut actions);
    Ok(Bm1491L9ShutdownPlan {
        actions,
        already_latched: false,
        stock_gpio_write_result_discarded: true,
        electrical_off_proven: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(raw_code: u16, chip_address: u8, register: u16, valid: bool) -> [u8; 12] {
        let mut bytes = [0_u8; 12];
        let mut response_word = u32::from(raw_code).swap_bytes();
        if valid {
            response_word |= BM1491_L9_TEMP_RESPONSE_VALID_BIT;
        }
        bytes[0..4].copy_from_slice(&response_word.to_le_bytes());
        bytes[4] = chip_address;
        bytes[6..8].copy_from_slice(&register.to_le_bytes());
        bytes
    }

    #[test]
    fn exact_query_order_and_release_limits_are_pinned() {
        assert_eq!(BM1491_L9_CHIP_TEMPERATURE_QUERY.len(), 5);
        assert_eq!(
            BM1491_L9_CHIP_TEMPERATURE_QUERY[4],
            Bm1491L9ChipTemperatureQueryStep::SynchronousRead {
                register: 0x90,
                expected_records: 110,
            }
        );
        assert_eq!(BM1491_L9_POWER_GPIO, 412);
        assert!(!BM1491_L9_TOPOL_PIC_MCU_ENABLED);
    }

    #[test]
    fn chip_temperature_conversion_matches_exact_f64_to_f32_goldens() {
        for (raw, expected) in [
            (0_u16, -287.560_9_f32),
            (1, -287.399_08),
            (1_000, -125.724_98),
            (2_048, 43.879_08),
            (4_095, 375.157_26),
        ] {
            let sample = bm1491_l9_decode_chip_temperature_record(&record(raw, 218, 0x90, true))
                .expect("exact valid record");
            assert_eq!(sample.raw_code, raw);
            assert_eq!(sample.chip_index, 109);
            assert_eq!(sample.temperature_c, expected);
        }
    }

    #[test]
    fn malformed_temperature_records_fail_closed() {
        assert_eq!(
            bm1491_l9_decode_chip_temperature_record(&record(2_048, 0, 0x90, false)),
            Err(Bm1491L9ChipTemperatureRecordError::InvalidResponseStatus)
        );
        assert_eq!(
            bm1491_l9_decode_chip_temperature_record(&record(2_048, 0, 0x8c, true)),
            Err(Bm1491L9ChipTemperatureRecordError::UnexpectedRegister { observed: 0x8c })
        );
        assert_eq!(
            bm1491_l9_decode_chip_temperature_record(&record(2_048, 1, 0x90, true)),
            Err(Bm1491L9ChipTemperatureRecordError::UnalignedChipAddress { observed: 1 })
        );
        assert_eq!(
            bm1491_l9_decode_chip_temperature_record(&record(2_048, 220, 0x90, true)),
            Err(Bm1491L9ChipTemperatureRecordError::ChipIndexOutOfRange { observed: 110 })
        );
    }

    #[test]
    fn extrema_boundaries_match_stock_strictness() {
        let step = bm1491_l9_step_thermal_extrema(
            Bm1491L9ThermalDebounceState::default(),
            Bm1491L9TemperatureExtrema {
                pcb_min_c: -39,
                pcb_max_c: 80,
                chip_max_c: 95,
            },
        )
        .expect("safe equality");
        assert_eq!(step.state, Bm1491L9ThermalDebounceState::default());
        assert!(!step.events.requests_stock_shutdown());

        let violating = bm1491_l9_step_thermal_extrema(
            Bm1491L9ThermalDebounceState::default(),
            Bm1491L9TemperatureExtrema {
                pcb_min_c: -40,
                pcb_max_c: 81,
                chip_max_c: 96,
            },
        )
        .expect("first violation");
        assert_eq!(violating.state.consecutive_high_samples, 1);
        assert_eq!(violating.state.consecutive_low_samples, 1);
    }

    #[test]
    fn third_consecutive_violation_sets_both_exact_event_bits() {
        let mut state = Bm1491L9ThermalDebounceState::default();
        let extrema = Bm1491L9TemperatureExtrema {
            pcb_min_c: -40,
            pcb_max_c: 81,
            chip_max_c: 95,
        };
        for attempt in 1..=3 {
            let step = bm1491_l9_step_thermal_extrema(state, extrema).expect("bounded counter");
            assert_eq!(step.events.requests_stock_shutdown(), attempt == 3);
            state = step.state;
        }
        let events = bm1491_l9_step_thermal_extrema(state, extrema)
            .expect("continued violation")
            .events;
        assert_eq!(
            events.event_mask(),
            BM1491_L9_EVENT_HIGH_TEMPERATURE_BIT | BM1491_L9_EVENT_LOW_TEMPERATURE_BIT
        );
    }

    #[test]
    fn counters_reset_independently_and_overflow_fails_closed() {
        let step = bm1491_l9_step_thermal_extrema(
            Bm1491L9ThermalDebounceState {
                consecutive_high_samples: 2,
                consecutive_low_samples: 2,
            },
            Bm1491L9TemperatureExtrema {
                pcb_min_c: -39,
                pcb_max_c: 81,
                chip_max_c: 95,
            },
        )
        .expect("high only");
        assert_eq!(step.state.consecutive_high_samples, 3);
        assert_eq!(step.state.consecutive_low_samples, 0);
        assert_eq!(
            bm1491_l9_step_thermal_extrema(
                Bm1491L9ThermalDebounceState {
                    consecutive_high_samples: u32::MAX,
                    consecutive_low_samples: 0,
                },
                Bm1491L9TemperatureExtrema {
                    pcb_min_c: 0,
                    pcb_max_c: 81,
                    chip_max_c: 0,
                },
            ),
            Err(Bm1491L9ThermalStepError::HighCounterOverflow)
        );
    }

    #[test]
    fn shutdown_plan_preserves_two_global_off_calls_and_runtime_order() {
        let plan = bm1491_l9_plan_stock_shutdown(false, 3).expect("exact runtime count");
        assert_eq!(plan.actions.len(), 15);
        assert_eq!(
            plan.actions[0],
            Bm1491L9ShutdownAction::LatchOneShotPowerOff
        );
        assert_eq!(
            plan.actions[1],
            Bm1491L9ShutdownAction::EnsurePowerGpioExportedAsOutputIfMissing {
                gpio: 412,
                direction: 1,
            }
        );
        assert_eq!(
            plan.actions[2],
            Bm1491L9ShutdownAction::WritePowerGpio {
                gpio: 412,
                value: 0,
            }
        );
        assert_eq!(
            &plan.actions[5..11],
            &[
                Bm1491L9ShutdownAction::StopRuntimeHashing { runtime_index: 0 },
                Bm1491L9ShutdownAction::InvokeDevicePowerOffCallback { runtime_index: 0 },
                Bm1491L9ShutdownAction::StopRuntimeHashing { runtime_index: 1 },
                Bm1491L9ShutdownAction::InvokeDevicePowerOffCallback { runtime_index: 1 },
                Bm1491L9ShutdownAction::StopRuntimeHashing { runtime_index: 2 },
                Bm1491L9ShutdownAction::InvokeDevicePowerOffCallback { runtime_index: 2 },
            ]
        );
        assert_eq!(plan.actions[11], plan.actions[1]);
        assert_eq!(plan.actions[12], plan.actions[2]);
        assert!(plan.stock_gpio_write_result_discarded);
        assert!(!plan.electrical_off_proven);
    }

    #[test]
    fn shutdown_is_one_shot_bounded_and_never_authoritative() {
        let latched = bm1491_l9_plan_stock_shutdown(true, 3).expect("latched no-op");
        assert!(latched.actions.is_empty());
        assert!(!latched.admits_hardware_io());
        assert!(!latched.admits_mining());
        assert_eq!(
            bm1491_l9_plan_stock_shutdown(false, 4),
            Err(Bm1491L9ShutdownPlanError::RuntimeCountOutOfRange { observed: 4 })
        );
        assert!(!BM1491_L9_TEMPERATURE_INPUT_AUTHENTICATED);
        assert!(!BM1491_L9_GPIO_PHYSICAL_LOAD_PROVEN);
        assert!(!BM1491_L9_POWER_WRITE_READBACK_VERIFIED);
        assert!(!BM1491_L9_ELECTRICAL_OFF_PROVEN);
        assert!(!BM1491_L9_SAFETY_AUTHORIZES_HARDWARE_IO);
        assert!(!BM1491_L9_SAFETY_AUTHORIZES_MINING);
    }

    #[test]
    fn third_missing_sample_raises_the_common_fatal_event() {
        let mut state = Bm1491L9SensorAvailabilityState::default();
        let missing = Bm1491L9SensorAvailabilityObservation {
            local_valid_count: 0,
            remote_valid_count: 0,
            ineffective_value_count: 2,
            rxu_hang_scan_active: false,
        };
        for attempt in 1..=3 {
            let step = bm1491_l9_step_sensor_availability(state, missing)
                .expect("bounded missing counters");
            assert_eq!(step.collection_return, BM1491_L9_SENSOR_COLLECTION_FAILURE);
            assert!(step.immediate_acquisition_error_event);
            let expected_mask = if attempt == 3 {
                BM1491_L9_EVENT_TEMPERATURE_ACQUISITION_BIT | BM1491_L9_EVENT_SENSOR_MISSING_BIT
            } else {
                BM1491_L9_EVENT_TEMPERATURE_ACQUISITION_BIT
            };
            assert_eq!(step.event_mask(), expected_mask);
            assert_eq!(step.requests_stock_fatal_status(), attempt == 3);
            state = step.state;
        }
        let step =
            bm1491_l9_step_sensor_availability(state, missing).expect("continued missing sample");
        assert_eq!(
            step.event_mask(),
            BM1491_L9_EVENT_TEMPERATURE_ACQUISITION_BIT | BM1491_L9_EVENT_SENSOR_MISSING_BIT
        );
    }

    #[test]
    fn rxu_hang_scan_suppresses_only_immediate_acquisition_event() {
        let scanning = Bm1491L9SensorAvailabilityObservation {
            local_valid_count: 0,
            remote_valid_count: 0,
            ineffective_value_count: 2,
            rxu_hang_scan_active: true,
        };
        let mut state = Bm1491L9SensorAvailabilityState::default();
        for attempt in 1..=3 {
            let step = bm1491_l9_step_sensor_availability(state, scanning)
                .expect("bounded scan-active counters");
            assert_eq!(step.collection_return, BM1491_L9_SENSOR_COLLECTION_FAILURE);
            assert!(!step.immediate_acquisition_error_event);
            assert_eq!(
                step.event_mask(),
                if attempt == 3 {
                    BM1491_L9_EVENT_SENSOR_MISSING_BIT
                } else {
                    0
                }
            );
            assert_eq!(step.requests_stock_fatal_status(), attempt == 3);
            state = step.state;
        }

        let complete = bm1491_l9_step_sensor_availability(
            Bm1491L9SensorAvailabilityState::default(),
            Bm1491L9SensorAvailabilityObservation {
                local_valid_count: 2,
                remote_valid_count: 2,
                ineffective_value_count: 0,
                rxu_hang_scan_active: false,
            },
        )
        .expect("complete collection");
        assert_eq!(
            complete.collection_return,
            BM1491_L9_SENSOR_COLLECTION_SUCCESS
        );
        assert!(!complete.immediate_acquisition_error_event);
        assert_eq!(complete.event_mask(), 0);
    }

    #[test]
    fn second_ineffective_excess_requests_hash_reset_and_clears_all_counters() {
        let observation = Bm1491L9SensorAvailabilityObservation {
            local_valid_count: 0,
            remote_valid_count: 0,
            ineffective_value_count: 3,
            rxu_hang_scan_active: false,
        };
        let first = bm1491_l9_step_sensor_availability(
            Bm1491L9SensorAvailabilityState::default(),
            observation,
        )
        .expect("first ineffective sample");
        assert!(!first.reset_hashing_for_ineffective_sensors);
        assert_eq!(first.state.consecutive_ineffective_excess, 1);
        let second = bm1491_l9_step_sensor_availability(first.state, observation)
            .expect("second ineffective sample");
        assert!(second.reset_hashing_for_ineffective_sensors);
        assert_eq!(second.state, Bm1491L9SensorAvailabilityState::default());
        assert!(!second.requests_stock_fatal_status());
        assert!(!second.admits_hardware_reset());
    }

    #[test]
    fn same_update_events_survive_the_l9_counter_reset() {
        let step = bm1491_l9_step_sensor_availability(
            Bm1491L9SensorAvailabilityState {
                consecutive_local_missing: 2,
                consecutive_remote_missing: 2,
                consecutive_ineffective_excess: 1,
            },
            Bm1491L9SensorAvailabilityObservation {
                local_valid_count: 0,
                remote_valid_count: 0,
                ineffective_value_count: 3,
                rxu_hang_scan_active: false,
            },
        )
        .expect("third missing and second ineffective sample");
        assert!(step.local_missing_event);
        assert!(step.remote_missing_event);
        assert!(step.reset_hashing_for_ineffective_sensors);
        assert_eq!(step.state, Bm1491L9SensorAvailabilityState::default());
    }

    #[test]
    fn valid_samples_reset_only_their_recovered_counters() {
        let step = bm1491_l9_step_sensor_availability(
            Bm1491L9SensorAvailabilityState {
                consecutive_local_missing: 2,
                consecutive_remote_missing: 2,
                consecutive_ineffective_excess: 1,
            },
            Bm1491L9SensorAvailabilityObservation {
                local_valid_count: 1,
                remote_valid_count: 0,
                ineffective_value_count: 2,
                rxu_hang_scan_active: false,
            },
        )
        .expect("mixed availability");
        assert_eq!(step.state.consecutive_local_missing, 0);
        assert_eq!(step.state.consecutive_remote_missing, 3);
        assert_eq!(step.state.consecutive_ineffective_excess, 0);
        assert!(!step.local_missing_event);
        assert!(step.remote_missing_event);
    }

    #[test]
    fn forged_availability_counts_and_counter_overflow_fail_closed() {
        assert_eq!(
            bm1491_l9_step_sensor_availability(
                Bm1491L9SensorAvailabilityState::default(),
                Bm1491L9SensorAvailabilityObservation {
                    local_valid_count: 3,
                    remote_valid_count: 0,
                    ineffective_value_count: 0,
                    rxu_hang_scan_active: false,
                },
            ),
            Err(Bm1491L9SensorAvailabilityError::LocalValidCountOutOfRange { observed: 3 })
        );
        assert_eq!(
            bm1491_l9_step_sensor_availability(
                Bm1491L9SensorAvailabilityState::default(),
                Bm1491L9SensorAvailabilityObservation {
                    local_valid_count: 0,
                    remote_valid_count: 0,
                    ineffective_value_count: 7,
                    rxu_hang_scan_active: false,
                },
            ),
            Err(Bm1491L9SensorAvailabilityError::IneffectiveValueCountOutOfRange { observed: 7 })
        );
        assert_eq!(
            bm1491_l9_step_sensor_availability(
                Bm1491L9SensorAvailabilityState {
                    consecutive_local_missing: u32::MAX,
                    ..Bm1491L9SensorAvailabilityState::default()
                },
                Bm1491L9SensorAvailabilityObservation {
                    local_valid_count: 0,
                    remote_valid_count: 1,
                    ineffective_value_count: 0,
                    rxu_hang_scan_active: false,
                },
            ),
            Err(Bm1491L9SensorAvailabilityError::LocalMissingCounterOverflow)
        );
    }
}
