//! Exact held-release BM1491/L9 top-init and setup-all-chip replay.
//!
//! This module is deliberately pure. It serializes the command bytes and
//! preserves stock ordering/return-value weaknesses, but it owns no transport
//! and cannot authorize hardware I/O or mining.

use crate::bm1491_l9_work::{BM1491_L9_ASIC_ADDRESS_INTERVAL, BM1491_L9_CHIPS_PER_CHAIN};
use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1491_L9_HELD_GODMINER_SIZE: u64 = 2_807_036;
pub const BM1491_L9_HELD_GODMINER_SHA256: &str =
    "7b088dcb42a57f021a8448f27dcadbfef6f4c4e71652ac871393e9f73c038487";

pub const BM1491_L9_TOP_INIT_ADDRESS: u32 = 0x000f_80bc;
pub const BM1491_L9_SETUP_ALL_CHIP_ADDRESS: u32 = 0x000f_87c0;
pub const BM1491_L9_CHECK_ASIC_NUM_ADDRESS: u32 = 0x000f_63e0;
pub const BM1491_L9_PLL_SOLVER_ADDRESS: u32 = 0x000f_cab0;
pub const BM1491_L9_SET_CHIP_REGISTER_ADDRESS: u32 = 0x000f_adb8;
pub const BM1491_L9_SET_CORE_REGISTER_ADDRESS: u32 = 0x000f_b64c;
pub const BM1491_L9_SET_CHIP_ADDRESS_ADDRESS: u32 = 0x0016_9f40;
pub const BM1491_L9_SET_INACTIVE_ADDRESS: u32 = 0x0016_a15c;
pub const BM1491_L9_FIXED_TRIGGER_WORK_ADDRESS: u32 = 0x0027_df04;

pub const BM1491_L9_STOCK_SUCCESS: u32 = 0;
pub const BM1491_L9_STOCK_ASIC_COUNT_ERROR: u32 = 0x66;
pub const BM1491_L9_POPULATION_ATTEMPTS: u8 = 3;
pub const BM1491_L9_POPULATION_RESPONSE_TAG: u8 = 0x33;
pub const BM1491_L9_POPULATION_TIMEOUT_MS: u32 = 3_000;
pub const BM1491_L9_POPULATION_RETRY_DELAY_US: u32 = 300_000;
pub const BM1491_L9_POPULATION_RETRY_CALLBACK_18: u16 = 0x18;
pub const BM1491_L9_POPULATION_RETRY_CALLBACK_2C: u16 = 0x2c;

pub const BM1491_L9_SET_ADDRESS_DELAY_US: u32 = 20_000;
pub const BM1491_L9_PLL_WRITE_DELAY_US: u32 = 10_000;
pub const BM1491_L9_PLL_STEP_DELAY_US: u32 = 200_000;
pub const BM1491_L9_REGISTER_SETTLE_DELAY_US: u32 = 1_000;
pub const BM1491_L9_SOFTWARE_RESET_DELAY_US: u32 = 10_000;
pub const BM1491_L9_TRIGGER_WORK_DELAY_US: u32 = 10_000;

pub const BM1491_L9_INITIAL_FREQUENCY_MHZ: u16 = 900;
pub const BM1491_L9_PLL_FIRST_TARGET_MHZ: u16 = 850;
pub const BM1491_L9_PLL_LAST_TARGET_MHZ: u16 = 50;
pub const BM1491_L9_PLL_TARGET_STEP_MHZ: u16 = 50;
pub const BM1491_L9_SOFTWARE_RESET_PASSES: u8 = 3;
pub const BM1491_L9_TRIGGER_WORK_PASSES: u8 = 3;
pub const BM1491_L9_LAST_CHIP_ADDRESS: u8 = 218;
pub const BM1491_L9_CORE_COUNT: u8 = 0x88;

pub const BM1491_L9_CHIP_REG_PLL: u8 = 0x08;
pub const BM1491_L9_CHIP_REG_MISC: u8 = 0x1c;
pub const BM1491_L9_CHIP_REG_NONCE_COUNT_RESET: u8 = 0x3c;
pub const BM1491_L9_CHIP_REG_SOFTWARE_RESET: u8 = 0x44;
pub const BM1491_L9_CHIP_REG_PLL_OBSERVATION: u8 = 0x48;
pub const BM1491_L9_CHIP_REG_CORE_COMMAND: u8 = 0x94;
pub const BM1491_L9_CHIP_REG_CORE_ERROR_CONTROL: u8 = 0xa8;
pub const BM1491_L9_CORE_REG_WORKING_MODE: u8 = 0x00;
pub const BM1491_L9_CORE_REG_TICKET_LOW: u8 = 0x02;
pub const BM1491_L9_CORE_REG_TICKET_HIGH: u8 = 0x04;

pub const BM1491_L9_TOP_INIT_MISC_VALUE: u32 = 0xc102_1f10;
pub const BM1491_L9_SETUP_MISC_VALUE: u32 = 0xc112_1f10;
pub const BM1491_L9_SOFTWARE_RESET_VALUE: u32 = 3;
pub const BM1491_L9_CORE_COMMAND_VALUE: u32 = 0x8000_0088;
pub const BM1491_L9_WORKING_MODE_VALUE: u32 = 0x0000_04ff;
pub const BM1491_L9_CORE_ERROR_CONTROL_VALUE: u32 = 0x8064_0bb8;
pub const BM1491_L9_TICKET_MASK: u32 = 0xffff_ffff;
pub const BM1491_L9_TICKET_MASK_COUNT: u8 = 48;

pub const BM1491_L9_PLL_FALLBACK_WORD: u32 = 0xc048_0110;
pub const BM1491_L9_PLL_REFERENCE_MHZ: f32 = 25.0;
pub const BM1491_L9_PLL_MIN_VCO_MHZ: f32 = 1_600.0;
pub const BM1491_L9_PLL_MAX_VCO_MHZ: f32 = 3_200.0;
pub const BM1491_L9_PLL_HIGH_VCO_SPLIT_MHZ: f32 = 2_400.0;
pub const BM1491_L9_TIMEOUT_NUMERATOR_BITS: u64 = 0x41a8_7fff_ffff_ffff;

pub const BM1491_L9_FIXED_TRIGGER_WORK: [u8; 86] = [
    0x55, 0xaa, 0x30, 0x00, 0x27, 0xa1, 0x00, 0x1a, 0x80, 0xf5, 0xd5, 0x64, 0xf6, 0xd3, 0xf1, 0x30,
    0xa3, 0x5d, 0xb1, 0x40, 0x35, 0x4d, 0x0f, 0x3d, 0xb5, 0x23, 0x9f, 0x34, 0x2c, 0x72, 0xdb, 0x5c,
    0x10, 0x2b, 0xa7, 0x3a, 0xf7, 0x3b, 0x59, 0xbd, 0x6f, 0x7a, 0xd8, 0x09, 0x4f, 0x08, 0x3c, 0x90,
    0xc6, 0x76, 0xb7, 0x5e, 0x47, 0x49, 0xaf, 0x17, 0x3a, 0x6b, 0x21, 0xd3, 0xe2, 0xdf, 0x1c, 0x15,
    0x26, 0x33, 0xcf, 0xc8, 0xeb, 0x34, 0x52, 0xad, 0x52, 0xe1, 0x91, 0xa8, 0x00, 0x00, 0x00, 0x20,
    0x00, 0xbd, 0xc2, 0x00, 0x80, 0xfa,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9PllSolution {
    pub target_mhz: u16,
    pub actual_mhz: u16,
    pub word: u32,
    pub feedback_divider: u16,
    pub reference_divider: u8,
    pub post_divider_one_index: u8,
    pub post_divider_two_index: u8,
}

/// Replay `inferred_plldivider_ltc` for an integer-MHz target.
///
/// The stock solver uses single-precision intermediates, searches reference
/// divider two before one, and accepts only an integer-frequency result whose
/// absolute error is strictly below 3 MHz.
pub fn bm1491_l9_solve_pll(target_mhz: u16) -> Option<Bm1491L9PllSolution> {
    let target = target_mhz as f32;
    for reference_divider in (1_u32..=2).rev() {
        for post_divider_one_index in 0_u32..8 {
            for post_divider_two_index in (0_u32..=post_divider_one_index).rev() {
                let scaled = (((post_divider_one_index + 1) as f32
                    * target
                    * (post_divider_two_index + 1) as f32
                    * reference_divider as f32)
                    / BM1491_L9_PLL_REFERENCE_MHZ)
                    * 100.0;
                let scaled_integer = scaled as i32;
                let feedback_divider = if scaled_integer % 100 < 51 {
                    scaled_integer / 100
                } else {
                    scaled_integer / 100 + 1
                };
                let vco = feedback_divider as f32 * BM1491_L9_PLL_REFERENCE_MHZ
                    / reference_divider as f32;
                let accepted_vco = feedback_divider > 7
                    && feedback_divider < 0x42b
                    && (reference_divider != 1 || vco <= 13_325.0)
                    && (BM1491_L9_PLL_MIN_VCO_MHZ..=BM1491_L9_PLL_MAX_VCO_MHZ).contains(&vco);
                if !accepted_vco {
                    continue;
                }
                let actual = (((feedback_divider * 25) / reference_divider as i32)
                    / (post_divider_one_index + 1) as i32)
                    / (post_divider_two_index + 1) as i32;
                if ((actual as f32) - target).abs() >= 3.0 {
                    continue;
                }
                let high_vco = u32::from(vco > BM1491_L9_PLL_HIGH_VCO_SPLIT_MHZ);
                let word = 0xc000_0000
                    | (high_vco << 28)
                    | ((feedback_divider as u32 & 0x0fff) << 16)
                    | ((reference_divider & 0x3f) << 8)
                    | ((post_divider_one_index & 7) << 4)
                    | (post_divider_two_index & 7);
                return Some(Bm1491L9PllSolution {
                    target_mhz,
                    actual_mhz: actual as u16,
                    word,
                    feedback_divider: feedback_divider as u16,
                    reference_divider: reference_divider as u8,
                    post_divider_one_index: post_divider_one_index as u8,
                    post_divider_two_index: post_divider_two_index as u8,
                });
            }
        }
    }
    None
}

pub fn bm1491_l9_frequency_timeout_ticks(target_mhz: u16) -> Option<u64> {
    if target_mhz == 0 {
        return None;
    }
    let numerator = f64::from_bits(BM1491_L9_TIMEOUT_NUMERATOR_BITS);
    Some(((numerator / f64::from(target_mhz)) * 70.0 / 100.0) as u64)
}

pub fn bm1491_l9_build_chip_register_frame(
    broadcast: bool,
    chip_address: u8,
    register: u8,
    value: u32,
) -> [u8; 11] {
    let mut frame = [0_u8; 11];
    frame[0] = 0x55;
    frame[1] = 0xaa;
    frame[2] = if broadcast { 0x51 } else { 0x41 };
    frame[3] = 9;
    frame[4] = chip_address;
    frame[5] = register;
    frame[6..10].copy_from_slice(&value.to_be_bytes());
    frame[10] = stock_bitmain_crc5(&frame[2..10], 64);
    frame
}

pub fn bm1491_l9_build_core_register_frame(
    broadcast: bool,
    chip_address: u8,
    register: u8,
    core: u8,
    value: u32,
) -> [u8; 11] {
    let mut frame = [0_u8; 11];
    frame[0] = 0x55;
    frame[1] = 0xaa;
    frame[2] = if broadcast { 0x54 } else { 0x44 };
    frame[3] = 9;
    frame[4] = chip_address;
    frame[5] = register & 0x0f;
    frame[6] = core;
    frame[7] = (value >> 16) as u8;
    frame[8] = (value >> 8) as u8;
    frame[9] = value as u8;
    frame[10] = stock_bitmain_crc5(&frame[2..10], 64);
    frame
}

pub fn bm1491_l9_build_set_inactive_frame() -> [u8; 7] {
    let mut frame = [0x55, 0xaa, 0x53, 5, 0, 0, 0];
    frame[6] = stock_bitmain_crc5(&frame[2..6], 32);
    frame
}

pub fn bm1491_l9_build_set_address_frame(address: u8) -> [u8; 7] {
    let mut frame = [0x55, 0xaa, 0x40, 5, address, 0, 0];
    frame[6] = stock_bitmain_crc5(&frame[2..6], 32);
    frame
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PopulationPhase {
    TopInit,
    SetupBeforeProgramming,
    SetupAfterProgramming,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1491L9InitAction {
    QueryPopulation {
        phase: Bm1491L9PopulationPhase,
        attempt: u8,
        requested_records: u8,
        response_tag: u8,
        timeout_ms: u32,
        observed_valid_chips: u16,
    },
    DelayUs(u32),
    InvokePopulationRetryCallback {
        vtable_offset: u16,
    },
    PublishAddressInterval {
        interval: u8,
    },
    SetInactive {
        frame: [u8; 7],
    },
    SetAddress {
        index: u8,
        address: u8,
        frame: [u8; 7],
    },
    WriteChipRegister {
        register: u8,
        value: u32,
        frame: [u8; 11],
    },
    WriteCoreRegister {
        register: u8,
        core: u8,
        value: u32,
        frame: [u8; 11],
    },
    ReadChipRegister {
        chip_address: u8,
        register: u8,
        requested_records: u8,
    },
    PublishFrequencyState {
        target_mhz: u16,
        timeout_ticks: Option<u64>,
    },
    PublishTicketMaskCount {
        count: u8,
    },
    WaitForTxCapacityUnbounded {
        minimum_bytes: u8,
    },
    SendFixedTriggerWork {
        pass: u8,
        bytes: [u8; 86],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9InitPlan {
    pub actions: Vec<Bm1491L9InitAction>,
    pub stock_return: u32,
    pub population_attempts_consumed: u8,
    pub stock_register_results_ignored: bool,
    pub stock_pll_observation_is_diagnostic_only: bool,
    pub stock_tx_capacity_wait_is_unbounded: bool,
    pub evidence_is_forgeable: bool,
}

impl Bm1491L9InitPlan {
    pub const fn admits_hardware_io(&self) -> bool {
        false
    }

    pub const fn admits_mining(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9InitPlanError {
    PllUnsolvable { target_mhz: u16 },
    TimeoutUnrepresentable { target_mhz: u16 },
}

fn append_population_check(
    actions: &mut Vec<Bm1491L9InitAction>,
    phase: Bm1491L9PopulationPhase,
    observed_valid_chips: [u16; BM1491_L9_POPULATION_ATTEMPTS as usize],
) -> (bool, u8) {
    for (index, observed) in observed_valid_chips.into_iter().enumerate() {
        let attempt = index as u8 + 1;
        actions.push(Bm1491L9InitAction::QueryPopulation {
            phase,
            attempt,
            requested_records: BM1491_L9_CHIPS_PER_CHAIN,
            response_tag: BM1491_L9_POPULATION_RESPONSE_TAG,
            timeout_ms: BM1491_L9_POPULATION_TIMEOUT_MS,
            observed_valid_chips: observed,
        });
        if observed == u16::from(BM1491_L9_CHIPS_PER_CHAIN) {
            return (true, attempt);
        }
        actions.push(Bm1491L9InitAction::DelayUs(
            BM1491_L9_POPULATION_RETRY_DELAY_US,
        ));
        actions.push(Bm1491L9InitAction::InvokePopulationRetryCallback {
            vtable_offset: BM1491_L9_POPULATION_RETRY_CALLBACK_18,
        });
        actions.push(Bm1491L9InitAction::InvokePopulationRetryCallback {
            vtable_offset: BM1491_L9_POPULATION_RETRY_CALLBACK_2C,
        });
    }
    (false, BM1491_L9_POPULATION_ATTEMPTS)
}

fn push_chip_write(actions: &mut Vec<Bm1491L9InitAction>, register: u8, value: u32) {
    actions.push(Bm1491L9InitAction::WriteChipRegister {
        register,
        value,
        frame: bm1491_l9_build_chip_register_frame(true, 0, register, value),
    });
}

fn push_core_write(actions: &mut Vec<Bm1491L9InitAction>, register: u8, core: u8, value: u32) {
    push_chip_write(
        actions,
        BM1491_L9_CHIP_REG_CORE_COMMAND,
        BM1491_L9_CORE_COMMAND_VALUE,
    );
    actions.push(Bm1491L9InitAction::WriteCoreRegister {
        register,
        core,
        value,
        frame: bm1491_l9_build_core_register_frame(true, 0, register, core, value),
    });
}

fn append_address_assignment(actions: &mut Vec<Bm1491L9InitAction>) {
    actions.push(Bm1491L9InitAction::PublishAddressInterval {
        interval: BM1491_L9_ASIC_ADDRESS_INTERVAL,
    });
    actions.push(Bm1491L9InitAction::SetInactive {
        frame: bm1491_l9_build_set_inactive_frame(),
    });
    actions.push(Bm1491L9InitAction::DelayUs(BM1491_L9_SET_ADDRESS_DELAY_US));
    for index in 0..BM1491_L9_CHIPS_PER_CHAIN {
        let address = index * BM1491_L9_ASIC_ADDRESS_INTERVAL;
        actions.push(Bm1491L9InitAction::SetAddress {
            index,
            address,
            frame: bm1491_l9_build_set_address_frame(address),
        });
        actions.push(Bm1491L9InitAction::DelayUs(BM1491_L9_SET_ADDRESS_DELAY_US));
    }
}

fn append_ticket_mask(actions: &mut Vec<Bm1491L9InitAction>) {
    push_core_write(
        actions,
        BM1491_L9_CORE_REG_TICKET_LOW,
        0xff,
        BM1491_L9_TICKET_MASK & 0xffff,
    );
    actions.push(Bm1491L9InitAction::DelayUs(
        BM1491_L9_REGISTER_SETTLE_DELAY_US,
    ));
    push_core_write(
        actions,
        BM1491_L9_CORE_REG_TICKET_HIGH,
        0xff,
        BM1491_L9_TICKET_MASK >> 16,
    );
    actions.push(Bm1491L9InitAction::PublishTicketMaskCount {
        count: BM1491_L9_TICKET_MASK_COUNT,
    });
}

fn append_working_mode(actions: &mut Vec<Bm1491L9InitAction>) {
    push_core_write(
        actions,
        BM1491_L9_CORE_REG_WORKING_MODE,
        0xff,
        BM1491_L9_WORKING_MODE_VALUE,
    );
    actions.push(Bm1491L9InitAction::DelayUs(
        BM1491_L9_REGISTER_SETTLE_DELAY_US,
    ));
}

/// Build the exact held `top_init_ltc` hardware-facing spine.
///
/// Population observations are replay inputs, not authenticated hardware
/// evidence. Once a matching observation appears, later array elements are
/// deliberately ignored because stock exits the retry loop immediately.
pub fn bm1491_l9_plan_top_init(
    observed_valid_chips: [u16; BM1491_L9_POPULATION_ATTEMPTS as usize],
) -> Result<Bm1491L9InitPlan, Bm1491L9InitPlanError> {
    let mut actions = Vec::new();
    let (population_matches, population_attempts_consumed) = append_population_check(
        &mut actions,
        Bm1491L9PopulationPhase::TopInit,
        observed_valid_chips,
    );
    if !population_matches {
        return Ok(Bm1491L9InitPlan {
            actions,
            stock_return: BM1491_L9_STOCK_ASIC_COUNT_ERROR,
            population_attempts_consumed,
            stock_register_results_ignored: true,
            stock_pll_observation_is_diagnostic_only: true,
            stock_tx_capacity_wait_is_unbounded: true,
            evidence_is_forgeable: true,
        });
    }

    append_address_assignment(&mut actions);
    push_chip_write(
        &mut actions,
        BM1491_L9_CHIP_REG_MISC,
        BM1491_L9_TOP_INIT_MISC_VALUE,
    );

    let mut target = BM1491_L9_PLL_FIRST_TARGET_MHZ;
    loop {
        let solution = bm1491_l9_solve_pll(target)
            .ok_or(Bm1491L9InitPlanError::PllUnsolvable { target_mhz: target })?;
        push_chip_write(&mut actions, BM1491_L9_CHIP_REG_PLL, solution.word);
        actions.push(Bm1491L9InitAction::DelayUs(BM1491_L9_PLL_WRITE_DELAY_US));
        actions.push(Bm1491L9InitAction::ReadChipRegister {
            chip_address: BM1491_L9_LAST_CHIP_ADDRESS,
            register: BM1491_L9_CHIP_REG_PLL_OBSERVATION,
            requested_records: 1,
        });
        let timeout_ticks = bm1491_l9_frequency_timeout_ticks(target)
            .ok_or(Bm1491L9InitPlanError::TimeoutUnrepresentable { target_mhz: target })?;
        actions.push(Bm1491L9InitAction::PublishFrequencyState {
            target_mhz: target,
            timeout_ticks: Some(timeout_ticks),
        });
        actions.push(Bm1491L9InitAction::DelayUs(BM1491_L9_PLL_STEP_DELAY_US));
        if target == BM1491_L9_PLL_LAST_TARGET_MHZ {
            break;
        }
        target -= BM1491_L9_PLL_TARGET_STEP_MHZ;
    }

    for _ in 0..BM1491_L9_SOFTWARE_RESET_PASSES {
        push_chip_write(
            &mut actions,
            BM1491_L9_CHIP_REG_SOFTWARE_RESET,
            BM1491_L9_SOFTWARE_RESET_VALUE,
        );
        actions.push(Bm1491L9InitAction::DelayUs(
            BM1491_L9_SOFTWARE_RESET_DELAY_US,
        ));
        append_ticket_mask(&mut actions);
    }
    append_working_mode(&mut actions);
    push_chip_write(
        &mut actions,
        BM1491_L9_CHIP_REG_CORE_ERROR_CONTROL,
        BM1491_L9_CORE_ERROR_CONTROL_VALUE,
    );
    actions.push(Bm1491L9InitAction::DelayUs(
        BM1491_L9_REGISTER_SETTLE_DELAY_US,
    ));

    for pass in 1..=BM1491_L9_TRIGGER_WORK_PASSES {
        actions.push(Bm1491L9InitAction::WaitForTxCapacityUnbounded {
            minimum_bytes: BM1491_L9_FIXED_TRIGGER_WORK.len() as u8,
        });
        actions.push(Bm1491L9InitAction::SendFixedTriggerWork {
            pass,
            bytes: BM1491_L9_FIXED_TRIGGER_WORK,
        });
        actions.push(Bm1491L9InitAction::DelayUs(BM1491_L9_TRIGGER_WORK_DELAY_US));
    }

    Ok(Bm1491L9InitPlan {
        actions,
        stock_return: BM1491_L9_STOCK_SUCCESS,
        population_attempts_consumed,
        stock_register_results_ignored: true,
        stock_pll_observation_is_diagnostic_only: true,
        stock_tx_capacity_wait_is_unbounded: true,
        evidence_is_forgeable: true,
    })
}

/// Replay the separately exposed `setup_all_chip_ltc` branch exactly.
///
/// The held function has inverted-looking return behavior: it returns `0x66`
/// when either population check succeeds, while an exhausted post-programming
/// mismatch returns zero. This records the stock weakness and does not endorse
/// it as a clean admission policy.
pub fn bm1491_l9_plan_setup_all_chip(
    before_programming: [u16; BM1491_L9_POPULATION_ATTEMPTS as usize],
    after_programming: [u16; BM1491_L9_POPULATION_ATTEMPTS as usize],
) -> Bm1491L9InitPlan {
    let mut actions = Vec::new();
    let (already_matches, first_attempts) = append_population_check(
        &mut actions,
        Bm1491L9PopulationPhase::SetupBeforeProgramming,
        before_programming,
    );
    if already_matches {
        return Bm1491L9InitPlan {
            actions,
            stock_return: BM1491_L9_STOCK_ASIC_COUNT_ERROR,
            population_attempts_consumed: first_attempts,
            stock_register_results_ignored: true,
            stock_pll_observation_is_diagnostic_only: true,
            stock_tx_capacity_wait_is_unbounded: true,
            evidence_is_forgeable: true,
        };
    }

    append_address_assignment(&mut actions);
    push_chip_write(
        &mut actions,
        BM1491_L9_CHIP_REG_MISC,
        BM1491_L9_SETUP_MISC_VALUE,
    );
    append_ticket_mask(&mut actions);
    append_working_mode(&mut actions);
    push_chip_write(&mut actions, BM1491_L9_CHIP_REG_NONCE_COUNT_RESET, 0);
    actions.push(Bm1491L9InitAction::PublishFrequencyState {
        target_mhz: BM1491_L9_INITIAL_FREQUENCY_MHZ,
        timeout_ticks: None,
    });
    let (post_matches, second_attempts) = append_population_check(
        &mut actions,
        Bm1491L9PopulationPhase::SetupAfterProgramming,
        after_programming,
    );
    Bm1491L9InitPlan {
        actions,
        stock_return: if post_matches {
            BM1491_L9_STOCK_ASIC_COUNT_ERROR
        } else {
            BM1491_L9_STOCK_SUCCESS
        },
        population_attempts_consumed: first_attempts + second_attempts,
        stock_register_results_ignored: true,
        stock_pll_observation_is_diagnostic_only: true,
        stock_tx_capacity_wait_is_unbounded: true,
        evidence_is_forgeable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_command_frames_have_independent_literal_goldens() {
        assert_eq!(
            bm1491_l9_build_set_inactive_frame(),
            [0x55, 0xaa, 0x53, 0x05, 0x00, 0x00, 0x03]
        );
        assert_eq!(
            bm1491_l9_build_set_address_frame(0),
            [0x55, 0xaa, 0x40, 0x05, 0x00, 0x00, 0x1c]
        );
        assert_eq!(
            bm1491_l9_build_set_address_frame(218),
            [0x55, 0xaa, 0x40, 0x05, 0xda, 0x00, 0x03]
        );
        assert_eq!(
            bm1491_l9_build_chip_register_frame(true, 0, 0x1c, 0xc102_1f10),
            [0x55, 0xaa, 0x51, 0x09, 0x00, 0x1c, 0xc1, 0x02, 0x1f, 0x10, 0x03]
        );
        assert_eq!(
            bm1491_l9_build_core_register_frame(true, 0, 0, 0xff, 0x04ff),
            [0x55, 0xaa, 0x54, 0x09, 0x00, 0x00, 0xff, 0x00, 0x04, 0xff, 0x1a]
        );
    }

    #[test]
    fn pll_solver_matches_every_held_top_init_target() {
        let expected = [
            (850, 0xc088_0210),
            (800, 0xd100_0211),
            (750, 0xd0f0_0211),
            (700, 0xd0e0_0211),
            (650, 0xd0d0_0211),
            (600, 0xc0c0_0211),
            (550, 0xc0b0_0211),
            (500, 0xc0a0_0211),
            (450, 0xc090_0211),
            (400, 0xc080_0211),
            (350, 0xd0fc_0222),
            (300, 0xd0d8_0222),
            (250, 0xc0b4_0222),
            (200, 0xc090_0222),
            (150, 0xc0c0_0233),
            (100, 0xc080_0233),
            (50, 0xc090_0255),
        ];
        for (target, word) in expected {
            let solution = bm1491_l9_solve_pll(target).expect("held target is solvable");
            assert_eq!(solution.actual_mhz, target);
            assert_eq!(solution.word, word);
        }
        assert_eq!(bm1491_l9_solve_pll(0), None);
    }

    #[test]
    fn timeout_math_preserves_exact_double_and_truncation() {
        assert_eq!(
            f64::from_bits(BM1491_L9_TIMEOUT_NUMERATOR_BITS),
            205_520_895.999_999_97
        );
        assert_eq!(bm1491_l9_frequency_timeout_ticks(900), Some(159_849));
        assert_eq!(bm1491_l9_frequency_timeout_ticks(850), Some(169_252));
        assert_eq!(bm1491_l9_frequency_timeout_ticks(50), Some(2_877_292));
        assert_eq!(bm1491_l9_frequency_timeout_ticks(0), None);
    }

    #[test]
    fn population_retry_executes_side_effects_after_terminal_mismatch() {
        let plan = bm1491_l9_plan_top_init([0, 109, 0]).expect("pure replay");
        assert_eq!(plan.stock_return, BM1491_L9_STOCK_ASIC_COUNT_ERROR);
        assert_eq!(plan.population_attempts_consumed, 3);
        assert_eq!(
            plan.actions
                .iter()
                .filter(|action| matches!(action, Bm1491L9InitAction::QueryPopulation { .. }))
                .count(),
            3
        );
        assert_eq!(
            &plan.actions[plan.actions.len() - 3..],
            &[
                Bm1491L9InitAction::DelayUs(BM1491_L9_POPULATION_RETRY_DELAY_US),
                Bm1491L9InitAction::InvokePopulationRetryCallback {
                    vtable_offset: BM1491_L9_POPULATION_RETRY_CALLBACK_18,
                },
                Bm1491L9InitAction::InvokePopulationRetryCallback {
                    vtable_offset: BM1491_L9_POPULATION_RETRY_CALLBACK_2C,
                },
            ]
        );
        assert!(!plan.actions.iter().any(|action| matches!(
            action,
            Bm1491L9InitAction::WriteChipRegister { .. } | Bm1491L9InitAction::SetAddress { .. }
        )));
    }

    #[test]
    fn successful_top_init_assigns_stride_two_and_walks_frequency_down() {
        let plan = bm1491_l9_plan_top_init([110, 0, 0]).expect("exact held planner");
        assert_eq!(plan.stock_return, BM1491_L9_STOCK_SUCCESS);
        assert_eq!(plan.population_attempts_consumed, 1);
        let addresses: Vec<_> = plan
            .actions
            .iter()
            .filter_map(|action| match action {
                Bm1491L9InitAction::SetAddress { index, address, .. } => Some((*index, *address)),
                _ => None,
            })
            .collect();
        assert_eq!(addresses.len(), 110);
        assert_eq!(addresses.first(), Some(&(0, 0)));
        assert_eq!(addresses.last(), Some(&(109, 218)));

        let targets: Vec<_> = plan
            .actions
            .iter()
            .filter_map(|action| match action {
                Bm1491L9InitAction::PublishFrequencyState {
                    target_mhz,
                    timeout_ticks: Some(_),
                } => Some(*target_mhz),
                _ => None,
            })
            .collect();
        assert_eq!(targets, (1..=17).map(|n| 900 - n * 50).collect::<Vec<_>>());
        assert!(plan.actions.iter().any(|action| {
            matches!(action, Bm1491L9InitAction::WriteChipRegister {
                register: BM1491_L9_CHIP_REG_PLL,
                value: 0xc088_0210,
                frame,
            } if *frame == [0x55,0xaa,0x51,0x09,0x00,0x08,0xc0,0x88,0x02,0x10,0x00])
        }));
    }

    #[test]
    fn reset_ticket_working_mode_and_core_error_order_is_exact() {
        let plan = bm1491_l9_plan_top_init([110, 0, 0]).expect("exact held planner");
        let software_resets = plan
            .actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    Bm1491L9InitAction::WriteChipRegister {
                        register: BM1491_L9_CHIP_REG_SOFTWARE_RESET,
                        value: BM1491_L9_SOFTWARE_RESET_VALUE,
                        ..
                    }
                )
            })
            .count();
        let ticket_low = plan
            .actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    Bm1491L9InitAction::WriteCoreRegister {
                        register: BM1491_L9_CORE_REG_TICKET_LOW,
                        value: 0xffff,
                        ..
                    }
                )
            })
            .count();
        let ticket_high = plan
            .actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    Bm1491L9InitAction::WriteCoreRegister {
                        register: BM1491_L9_CORE_REG_TICKET_HIGH,
                        value: 0xffff,
                        ..
                    }
                )
            })
            .count();
        assert_eq!((software_resets, ticket_low, ticket_high), (3, 3, 3));

        let working_index = plan
            .actions
            .iter()
            .position(|action| {
                matches!(
                    action,
                    Bm1491L9InitAction::WriteCoreRegister {
                        register: BM1491_L9_CORE_REG_WORKING_MODE,
                        value: BM1491_L9_WORKING_MODE_VALUE,
                        ..
                    }
                )
            })
            .expect("working-mode write");
        let core_error_index = plan
            .actions
            .iter()
            .position(|action| {
                matches!(
                    action,
                    Bm1491L9InitAction::WriteChipRegister {
                        register: BM1491_L9_CHIP_REG_CORE_ERROR_CONTROL,
                        value: BM1491_L9_CORE_ERROR_CONTROL_VALUE,
                        ..
                    }
                )
            })
            .expect("core-error write");
        assert!(working_index < core_error_index);
    }

    #[test]
    fn fixed_trigger_work_is_exact_three_passes_with_unbounded_capacity_wait() {
        let plan = bm1491_l9_plan_top_init([110, 0, 0]).expect("exact held planner");
        let mut passes = Vec::new();
        for window in plan.actions.windows(3) {
            if let [Bm1491L9InitAction::WaitForTxCapacityUnbounded { minimum_bytes }, Bm1491L9InitAction::SendFixedTriggerWork { pass, bytes }, Bm1491L9InitAction::DelayUs(delay)] =
                window
            {
                if *minimum_bytes == 86 && *delay == BM1491_L9_TRIGGER_WORK_DELAY_US {
                    assert_eq!(*bytes, BM1491_L9_FIXED_TRIGGER_WORK);
                    passes.push(*pass);
                }
            }
        }
        assert_eq!(passes, vec![1, 2, 3]);
        assert!(plan.stock_tx_capacity_wait_is_unbounded);
    }

    #[test]
    fn setup_all_chip_inverted_stock_return_is_recorded_but_never_authority() {
        let already = bm1491_l9_plan_setup_all_chip([110, 0, 0], [0, 0, 0]);
        assert_eq!(already.stock_return, BM1491_L9_STOCK_ASIC_COUNT_ERROR);
        assert!(!already
            .actions
            .iter()
            .any(|action| matches!(action, Bm1491L9InitAction::SetAddress { .. })));

        let repaired = bm1491_l9_plan_setup_all_chip([0, 0, 0], [110, 0, 0]);
        assert_eq!(repaired.stock_return, BM1491_L9_STOCK_ASIC_COUNT_ERROR);
        assert!(repaired.actions.iter().any(|action| matches!(
            action,
            Bm1491L9InitAction::WriteChipRegister {
                register: BM1491_L9_CHIP_REG_NONCE_COUNT_RESET,
                value: 0,
                ..
            }
        )));

        let still_missing = bm1491_l9_plan_setup_all_chip([0, 0, 0], [0, 0, 0]);
        assert_eq!(still_missing.stock_return, BM1491_L9_STOCK_SUCCESS);
        assert!(still_missing.stock_register_results_ignored);
        assert!(still_missing.stock_pll_observation_is_diagnostic_only);
        assert!(still_missing.evidence_is_forgeable);
        assert!(!still_missing.admits_hardware_io());
        assert!(!still_missing.admits_mining());
    }
}
