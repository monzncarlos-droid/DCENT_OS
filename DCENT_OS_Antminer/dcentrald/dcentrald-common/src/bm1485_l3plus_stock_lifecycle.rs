//! Exact held-release L3+ presence, enumeration, and startup-failure replay.
//!
//! The stock 2017 initializer can continue after a cumulative short-chain
//! mismatch budget is exceeded, and several thread failures after rail enable
//! return without a direct initializer rail-disable attempt. This module records those behaviors
//! for offline analysis only; it performs no file, process, GPIO, PIC, UART,
//! ASIC, thread, rail, or work I/O and grants no lifecycle authority.

use crate::bm1485_l3plus_stock::{
    BM1485_L3PLUS_STOCK_CHAIN_COUNT, BM1485_L3PLUS_STOCK_CHIPS_PER_CHAIN,
};

pub const BM1485_L3PLUS_STOCK_PLUG_GPIO_NUMBERS: [u32; 4] = [51, 48, 47, 44];
pub const BM1485_L3PLUS_STOCK_HASHBOARD_RESET_GPIO_NUMBERS: [u32; 4] = [5, 4, 27, 22];
pub const BM1485_L3PLUS_STOCK_HASHBOARD_RESET_PULSE_INVOCATIONS: u8 = 2;
pub const BM1485_L3PLUS_STOCK_HASHBOARD_RESET_LOW_TO_HIGH_DELAY_MS: u32 = 500;
pub const BM1485_L3PLUS_STOCK_HASHBOARD_RESET_FINAL_DELAY_MS: u32 = 500;

pub const BM1485_L3PLUS_STOCK_ENUMERATION_QUERY_REGISTER: u8 = 0x00;
pub const BM1485_L3PLUS_STOCK_ENUMERATION_RESPONSE_WAIT_SECONDS: u32 = 2;
pub const BM1485_L3PLUS_STOCK_ENUMERATION_CUMULATIVE_MISMATCH_BUDGET: u32 = 5;
pub const BM1485_L3PLUS_STOCK_SCAN_THREAD_SETTLE_MS: u32 = 100;
pub const BM1485_L3PLUS_STOCK_TEMP_TO_THERMAL_THREAD_DELAY_SECONDS: u32 = 2;

pub const BM1485_L3PLUS_STOCK_NEED_REBOOT_MARKER: &str = "/usr/bin/need_reboot";
pub const BM1485_L3PLUS_STOCK_ALREADY_REBOOT_MARKER: &str = "/usr/bin/already_reboot";
pub const BM1485_L3PLUS_STOCK_RESTART_COMMAND: &str = "/etc/init.d/cgminer.sh restart";

pub const BM1485_L3PLUS_STOCK_LIFECYCLE_IDENTIFIES_PHYSICAL_BOARD: bool = false;
pub const BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_FILE_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_PROCESS_RESTART: bool = false;
pub const BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_GPIO_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_STARTUP: bool = false;

/// Exact `FUN_0003d1ac` presence interpretation: a read whose first byte is
/// ASCII `1` marks the slot active; open/read failures and every other value
/// mark it inactive.
pub fn bm1485_l3plus_stock_detect_present_chains(
    gpio_value_reads: [Option<&[u8]>; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
) -> [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT] {
    gpio_value_reads.map(|reading| reading.and_then(|bytes| bytes.first()).copied() == Some(b'1'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockHashboardResetPlan {
    pub gpio_numbers: [u32; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub invocation_count: u8,
    /// Each invocation writes all four GPIOs low, waits, then writes all high.
    pub delay_between_low_and_high_ms: u32,
    /// The top-level initializer adds this delay after the second invocation.
    pub delay_after_final_invocation_ms: u32,
}

impl Bm1485L3plusStockHashboardResetPlan {
    pub const fn authorizes_gpio_io(self) -> bool {
        false
    }
}

pub const fn bm1485_l3plus_stock_hashboard_reset_plan() -> Bm1485L3plusStockHashboardResetPlan {
    Bm1485L3plusStockHashboardResetPlan {
        gpio_numbers: BM1485_L3PLUS_STOCK_HASHBOARD_RESET_GPIO_NUMBERS,
        invocation_count: BM1485_L3PLUS_STOCK_HASHBOARD_RESET_PULSE_INVOCATIONS,
        delay_between_low_and_high_ms: BM1485_L3PLUS_STOCK_HASHBOARD_RESET_LOW_TO_HIGH_DELAY_MS,
        delay_after_final_invocation_ms: BM1485_L3PLUS_STOCK_HASHBOARD_RESET_FINAL_DELAY_MS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockRestartCommand {
    TouchNeedRebootMarker,
    AppendAlreadyRebootCodeOne,
    AppendAlreadyRebootCodeTwo,
    RestartCgminer,
}

impl Bm1485L3plusStockRestartCommand {
    pub const fn shell_command(self) -> &'static str {
        match self {
            Self::TouchNeedRebootMarker => "touch /usr/bin/need_reboot",
            Self::AppendAlreadyRebootCodeOne => "echo 1 >> /usr/bin/already_reboot",
            Self::AppendAlreadyRebootCodeTwo => "echo 2 >> /usr/bin/already_reboot",
            Self::RestartCgminer => BM1485_L3PLUS_STOCK_RESTART_COMMAND,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockRestartPlan {
    pub need_reboot_marker_already_exists: bool,
    pub commands: [Option<Bm1485L3plusStockRestartCommand>; 3],
}

impl Bm1485L3plusStockRestartPlan {
    pub const fn authorizes_file_or_process_io(self) -> bool {
        false
    }
}

/// Exact `FUN_000412c4` branch. Existing marker => append `2` only. Missing
/// marker => touch it, append `1`, then request a cgminer restart.
pub const fn bm1485_l3plus_stock_restart_plan(
    need_reboot_marker_already_exists: bool,
) -> Bm1485L3plusStockRestartPlan {
    let commands = if need_reboot_marker_already_exists {
        [
            Some(Bm1485L3plusStockRestartCommand::AppendAlreadyRebootCodeTwo),
            None,
            None,
        ]
    } else {
        [
            Some(Bm1485L3plusStockRestartCommand::TouchNeedRebootMarker),
            Some(Bm1485L3plusStockRestartCommand::AppendAlreadyRebootCodeOne),
            Some(Bm1485L3plusStockRestartCommand::RestartCgminer),
        ]
    };
    Bm1485L3plusStockRestartPlan {
        need_reboot_marker_already_exists,
        commands,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1485L3plusStockEnumerationState {
    /// Stock increments this once per mismatching active slot, not per scan.
    pub cumulative_mismatching_slot_observations: u32,
    /// The exact-count flag at chain state `+4`; inactive slots are untouched.
    pub exact_count_flags: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    /// The per-slot retry marker; inactive slots are untouched.
    pub retry_markers: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockEnumerationDisposition {
    ExactCounts,
    RetryWithProcessSideEffect,
    ContinueDespiteMismatchBudgetExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockEnumerationObservation {
    pub state: Bm1485L3plusStockEnumerationState,
    pub disposition: Bm1485L3plusStockEnumerationDisposition,
    pub restart_plan: Option<Bm1485L3plusStockRestartPlan>,
    pub clears_four_scan_counters_before_retry: bool,
    pub response_wait_seconds: u32,
    pub stock_initializer_directly_attempts_rail_disable: bool,
}

impl Bm1485L3plusStockEnumerationObservation {
    pub const fn authorizes_retry_or_startup(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockLifecycleError {
    MismatchCounterOverflow,
}

/// Replay one exact count-observation round from `FUN_00041838`.
///
/// A mismatch on any active slot requests another round while the cumulative
/// number of mismatching slot observations is at most five. Once it exceeds
/// five, stock stops retrying and continues initialization despite mismatch.
pub fn bm1485_l3plus_stock_enumeration_observation(
    mut state: Bm1485L3plusStockEnumerationState,
    active_chains: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    observed_chip_counts: [u8; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    need_reboot_marker_already_exists: bool,
) -> Result<Bm1485L3plusStockEnumerationObservation, Bm1485L3plusStockLifecycleError> {
    let mut any_mismatch = false;
    for chain_slot in 0..BM1485_L3PLUS_STOCK_CHAIN_COUNT {
        if !active_chains[chain_slot] {
            continue;
        }
        if usize::from(observed_chip_counts[chain_slot]) == BM1485_L3PLUS_STOCK_CHIPS_PER_CHAIN {
            state.exact_count_flags[chain_slot] = true;
            state.retry_markers[chain_slot] = false;
        } else {
            state.exact_count_flags[chain_slot] = false;
            state.retry_markers[chain_slot] = true;
            state.cumulative_mismatching_slot_observations = state
                .cumulative_mismatching_slot_observations
                .checked_add(1)
                .ok_or(Bm1485L3plusStockLifecycleError::MismatchCounterOverflow)?;
            any_mismatch = true;
        }
    }

    let disposition = if !any_mismatch {
        Bm1485L3plusStockEnumerationDisposition::ExactCounts
    } else if state.cumulative_mismatching_slot_observations
        > BM1485_L3PLUS_STOCK_ENUMERATION_CUMULATIVE_MISMATCH_BUDGET
    {
        Bm1485L3plusStockEnumerationDisposition::ContinueDespiteMismatchBudgetExceeded
    } else {
        Bm1485L3plusStockEnumerationDisposition::RetryWithProcessSideEffect
    };
    let retry = disposition == Bm1485L3plusStockEnumerationDisposition::RetryWithProcessSideEffect;
    Ok(Bm1485L3plusStockEnumerationObservation {
        state,
        disposition,
        restart_plan: retry
            .then(|| bm1485_l3plus_stock_restart_plan(need_reboot_marker_already_exists)),
        clears_four_scan_counters_before_retry: retry,
        response_wait_seconds: BM1485_L3PLUS_STOCK_ENUMERATION_RESPONSE_WAIT_SECONDS,
        stock_initializer_directly_attempts_rail_disable: false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockThreadStage {
    PicHeartbeat,
    AsicScanResponse,
    FanTach,
    TemperatureRefresh,
    ThermalStatus,
    HashrateRegisterRead,
}

pub const BM1485_L3PLUS_STOCK_THREAD_ORDER: [Bm1485L3plusStockThreadStage; 6] = [
    Bm1485L3plusStockThreadStage::PicHeartbeat,
    Bm1485L3plusStockThreadStage::AsicScanResponse,
    Bm1485L3plusStockThreadStage::FanTach,
    Bm1485L3plusStockThreadStage::TemperatureRefresh,
    Bm1485L3plusStockThreadStage::ThermalStatus,
    Bm1485L3plusStockThreadStage::HashrateRegisterRead,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockThreadFailureObservation {
    pub stage: Bm1485L3plusStockThreadStage,
    pub initializer_return_code: i32,
    pub rails_may_already_be_energized: bool,
    pub stock_initializer_directly_attempts_rail_disable_before_return: bool,
    pub clean_runtime_requires_fail_safe_teardown: bool,
}

impl Bm1485L3plusStockThreadFailureObservation {
    pub const fn authorizes_thread_or_rail_operation(self) -> bool {
        false
    }
}

/// Exact top-level failure codes and rail exposure from `FUN_00041838`.
pub const fn bm1485_l3plus_stock_thread_failure_observation(
    stage: Bm1485L3plusStockThreadStage,
) -> Bm1485L3plusStockThreadFailureObservation {
    let (initializer_return_code, rails_may_already_be_energized) = match stage {
        Bm1485L3plusStockThreadStage::PicHeartbeat => (-3, false),
        Bm1485L3plusStockThreadStage::AsicScanResponse => (-3, true),
        Bm1485L3plusStockThreadStage::FanTach => (-5, true),
        Bm1485L3plusStockThreadStage::TemperatureRefresh => (-7, true),
        Bm1485L3plusStockThreadStage::ThermalStatus => (-5, true),
        Bm1485L3plusStockThreadStage::HashrateRegisterRead => (-6, true),
    };
    Bm1485L3plusStockThreadFailureObservation {
        stage,
        initializer_return_code,
        rails_may_already_be_energized,
        stock_initializer_directly_attempts_rail_disable_before_return: false,
        clean_runtime_requires_fail_safe_teardown: rails_may_already_be_energized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_scan_pins_gpio_order_and_first_byte_only() {
        assert_eq!(BM1485_L3PLUS_STOCK_PLUG_GPIO_NUMBERS, [51, 48, 47, 44]);
        assert_eq!(
            bm1485_l3plus_stock_detect_present_chains([
                Some(b"1\n"),
                Some(b"0\n"),
                None,
                Some(b"10"),
            ]),
            [true, false, false, true]
        );
        assert_eq!(
            bm1485_l3plus_stock_detect_present_chains([Some(b""), None, None, None]),
            [false; 4]
        );
    }

    #[test]
    fn hashboard_reset_gpio_plan_pins_two_low_wait_high_invocations() {
        let plan = bm1485_l3plus_stock_hashboard_reset_plan();
        assert_eq!(plan.gpio_numbers, [5, 4, 27, 22]);
        assert_eq!(plan.invocation_count, 2);
        assert_eq!(plan.delay_between_low_and_high_ms, 500);
        assert_eq!(plan.delay_after_final_invocation_ms, 500);
        assert!(!plan.authorizes_gpio_io());
    }

    #[test]
    fn exact_counts_complete_without_restart() {
        let observed = bm1485_l3plus_stock_enumeration_observation(
            Bm1485L3plusStockEnumerationState::default(),
            [true; 4],
            [72; 4],
            false,
        )
        .unwrap();
        assert_eq!(
            observed.disposition,
            Bm1485L3plusStockEnumerationDisposition::ExactCounts
        );
        assert_eq!(observed.state.exact_count_flags, [true; 4]);
        assert_eq!(observed.restart_plan, None);
        assert_eq!(observed.response_wait_seconds, 2);
        assert!(!observed.stock_initializer_directly_attempts_rail_disable);
    }

    #[test]
    fn one_bad_slot_retries_five_times_then_stock_continues_on_sixth() {
        let mut state = Bm1485L3plusStockEnumerationState::default();
        for mismatch_number in 1..=6 {
            let observed = bm1485_l3plus_stock_enumeration_observation(
                state,
                [true, false, false, false],
                [71, 0, 0, 0],
                false,
            )
            .unwrap();
            state = observed.state;
            assert_eq!(
                state.cumulative_mismatching_slot_observations,
                mismatch_number
            );
            if mismatch_number <= 5 {
                assert_eq!(
                    observed.disposition,
                    Bm1485L3plusStockEnumerationDisposition::RetryWithProcessSideEffect
                );
                assert!(observed.clears_four_scan_counters_before_retry);
            } else {
                assert_eq!(
                    observed.disposition,
                    Bm1485L3plusStockEnumerationDisposition::ContinueDespiteMismatchBudgetExceeded
                );
                assert_eq!(observed.restart_plan, None);
            }
        }
    }

    #[test]
    fn four_bad_slots_consume_budget_per_slot_not_per_round() {
        let first = bm1485_l3plus_stock_enumeration_observation(
            Bm1485L3plusStockEnumerationState::default(),
            [true; 4],
            [0; 4],
            true,
        )
        .unwrap();
        assert_eq!(first.state.cumulative_mismatching_slot_observations, 4);
        assert_eq!(
            first.disposition,
            Bm1485L3plusStockEnumerationDisposition::RetryWithProcessSideEffect
        );
        let second =
            bm1485_l3plus_stock_enumeration_observation(first.state, [true; 4], [0; 4], true)
                .unwrap();
        assert_eq!(second.state.cumulative_mismatching_slot_observations, 8);
        assert_eq!(
            second.disposition,
            Bm1485L3plusStockEnumerationDisposition::ContinueDespiteMismatchBudgetExceeded
        );
    }

    #[test]
    fn inactive_slots_preserve_prior_flags_and_do_not_consume_budget() {
        let initial = Bm1485L3plusStockEnumerationState {
            cumulative_mismatching_slot_observations: 2,
            exact_count_flags: [false, true, false, true],
            retry_markers: [true, false, true, false],
        };
        let observed = bm1485_l3plus_stock_enumeration_observation(
            initial,
            [false, true, false, false],
            [0, 72, 0, 0],
            false,
        )
        .unwrap();
        assert_eq!(observed.state, initial);
        assert_eq!(
            observed.disposition,
            Bm1485L3plusStockEnumerationDisposition::ExactCounts
        );
    }

    #[test]
    fn restart_side_effect_branch_is_exact_but_never_authority() {
        let missing = bm1485_l3plus_stock_restart_plan(false);
        assert_eq!(
            missing
                .commands
                .map(|command| command.map(|item| item.shell_command())),
            [
                Some("touch /usr/bin/need_reboot"),
                Some("echo 1 >> /usr/bin/already_reboot"),
                Some("/etc/init.d/cgminer.sh restart"),
            ]
        );
        let existing = bm1485_l3plus_stock_restart_plan(true);
        assert_eq!(
            existing
                .commands
                .map(|command| command.map(|item| item.shell_command())),
            [Some("echo 2 >> /usr/bin/already_reboot"), None, None]
        );
        assert!(!missing.authorizes_file_or_process_io());
        assert!(!existing.authorizes_file_or_process_io());
    }

    #[test]
    fn post_rail_thread_failures_return_without_stock_teardown() {
        let expected = [
            (-3, false),
            (-3, true),
            (-5, true),
            (-7, true),
            (-5, true),
            (-6, true),
        ];
        for (stage, (code, energized)) in BM1485_L3PLUS_STOCK_THREAD_ORDER.into_iter().zip(expected)
        {
            let observation = bm1485_l3plus_stock_thread_failure_observation(stage);
            assert_eq!(observation.initializer_return_code, code);
            assert_eq!(observation.rails_may_already_be_energized, energized);
            assert!(!observation.stock_initializer_directly_attempts_rail_disable_before_return);
            assert_eq!(
                observation.clean_runtime_requires_fail_safe_teardown,
                energized
            );
            assert!(!observation.authorizes_thread_or_rail_operation());
        }
    }

    #[test]
    fn lifecycle_contract_never_mints_live_authority() {
        assert!(!BM1485_L3PLUS_STOCK_LIFECYCLE_IDENTIFIES_PHYSICAL_BOARD);
        assert!(!BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_FILE_IO);
        assert!(!BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_PROCESS_RESTART);
        assert!(!BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_GPIO_IO);
        assert!(!BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_RAIL_MUTATION);
        assert!(!BM1485_L3PLUS_STOCK_LIFECYCLE_AUTHORIZES_STARTUP);
        assert_eq!(BM1485_L3PLUS_STOCK_SCAN_THREAD_SETTLE_MS, 100);
        assert_eq!(BM1485_L3PLUS_STOCK_TEMP_TO_THERMAL_THREAD_DELAY_SECONDS, 2);
        assert_eq!(BM1485_L3PLUS_STOCK_ENUMERATION_QUERY_REGISTER, 0);
    }
}
