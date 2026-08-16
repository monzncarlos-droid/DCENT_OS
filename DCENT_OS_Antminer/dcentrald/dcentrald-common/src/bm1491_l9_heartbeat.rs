//! Exact held-release BM1491/L9 heartbeat and PSU-watchdog replay.
//!
//! The symbol-bearing `godminer` from held `FR-1.19(260302-L9).bmu`
//! selects the PSU-watchdog thread because `topol.conf` sets
//! `pic_mcu_en=false`. The alternate PIC path is retained because it is
//! compiled into the same exact binary. This module performs no I/O and does
//! not treat a stock thread, log line, software voltage, or library return as
//! proof that a physical rail is safe.

pub const BM1491_L9_HEARTBEAT_ON_DEVICE_ADDRESS: u32 = 0x0008_3f7c;
pub const BM1491_L9_PSU_WATCHDOG_ADDRESS: u32 = 0x0008_4144;
pub const BM1491_L9_START_HEARTBEAT_THREAD_ADDRESS: u32 = 0x0008_46c8;
pub const BM1491_L9_STOP_HEARTBEAT_THREAD_ADDRESS: u32 = 0x0008_4858;
pub const BM1491_L9_READ_FEEDBACK_VOLTAGE_ADDRESS: u32 = 0x0008_7838;
pub const BM1491_L9_BITMAIN_GET_POWER_STATUS_ADDRESS: u32 = 0x0016_2cac;
pub const BM1491_L9_BITMAIN_SET_WATCHDOG_ADDRESS: u32 = 0x0016_3cfc;
pub const BM1491_L9_LEGACY_SET_WATCHDOG_ADDRESS: u32 = 0x0016_0b50;
pub const BM1491_L9_PIC_HEARTBEAT_ADDRESS: u32 = 0x0014_6f08;
pub const BM1491_L9_PIC_PROCESS_COMMAND_ADDRESS: u32 = 0x0014_66c8;
pub const BM1491_L9_PIC_TRANSACTION_ADDRESS: u32 = 0x0014_6600;
pub const BM1491_L9_HEARTBEAT_TO_HAL_ADDRESS: u32 = 0x0017_0218;

/// Exact host-watchdog module present in the held CVCtrl rootfs.
///
/// Artifact presence is not evidence that the module was loaded or that a
/// watchdog was armed. The same rootfs has no module-load metadata, init-script
/// reference, or recovered userspace feeder for this driver.
pub const BM1491_L9_HOST_WDT_MODULE_PATH: &str = "/mnt/system/ko/cv183x_wdt.ko";
pub const BM1491_L9_HOST_WDT_MODULE_SIZE: u64 = 17_120;
pub const BM1491_L9_HOST_WDT_MODULE_SHA256: &str =
    "9f98d1f0ebb72ce79078824c886b07538c0d4e630fdcdeda99db5faea5d6043b";
pub const BM1491_L9_HOST_WDT_MODULE_BUILD_ID: &str = "655fbdbce5501fca6a8f4de49b0997c459553ce7";
pub const BM1491_L9_HOST_WDT_MODULE_VERMAGIC: &str = "4.9.38-tag- SMP preempt mod_unload aarch64 ";
pub const BM1491_L9_HOST_WDT_MODULE_DESCRIPTION: &str = "Synopsys DesignWare Watchdog Driver";
pub const BM1491_L9_HOST_WDT_MODULE_NOWAYOUT_DEFAULT: bool = false;
pub const BM1491_L9_HOST_WDT_INIT_REFERENCE_PRESENT: bool = false;
pub const BM1491_L9_HOST_WDT_AUTOLOAD_METADATA_PRESENT: bool = false;
pub const BM1491_L9_HOST_WDT_FEEDER_RECOVERED: bool = false;
pub const BM1491_L9_HOST_WDT_ACTIVE_PROVEN: bool = false;

pub const BM1491_L9_HELD_PIC_MCU_ENABLED: bool = false;
pub const BM1491_L9_HEARTBEAT_THREAD_CREATE_FAILURE: u8 = 5;
pub const BM1491_L9_START_HEARTBEAT_CALLER_MAX_ATTEMPTS: u8 = 2;
pub const BM1491_L9_PIC_HEARTBEAT_COMMAND: u8 = 0x16;
pub const BM1491_L9_PIC_HEARTBEAT_RESPONSE_LEN: usize = 6;
pub const BM1491_L9_PIC_COMMAND_ATTEMPTS: usize = 4;
pub const BM1491_L9_PIC_WRITE_TO_READ_DELAY_MS: u32 = 10;
pub const BM1491_L9_PIC_MISMATCH_BACKOFF_SECONDS: u32 = 1;
pub const BM1491_L9_PIC_CHAIN_DELAY_SECONDS: u32 = 5;
pub const BM1491_L9_PSU_WATCHDOG_LOOP_DELAY_SECONDS: u32 = 10;
pub const BM1491_L9_PSU_ERROR_LIMIT: u32 = 3;
pub const BM1491_L9_FEEDBACK_SCALE_BITS: u64 = 0x4059_0000_0000_0000;
pub const BM1491_L9_FEEDBACK_HIGH_RATIO_BITS: u64 = 0x3ff1_9999_9999_999a;
pub const BM1491_L9_FEEDBACK_LOW_RATIO_BITS: u64 = 0x3fec_cccc_cccc_cccd;
pub const BM1491_L9_LEGACY_WATCHDOG_OPCODE: u8 = 0x81;
pub const BM1491_L9_LEGACY_WATCHDOG_LENGTH: u8 = 6;
pub const BM1491_L9_LEGACY_WATCHDOG_FRAME_LEN: usize = 8;
pub const BM1491_L9_LEGACY_WATCHDOG_ENABLE_FRAME: [u8; 8] =
    [0x55, 0xaa, 0x06, 0x81, 0x01, 0x00, 0x88, 0x00];
pub const BM1491_L9_PIC_HEARTBEAT_FRAME: [u8; 6] = [0x55, 0xaa, 0x04, 0x16, 0x00, 0x1a];

pub const BM1491_L9_HEARTBEAT_INPUT_AUTHENTICATED: bool = false;
pub const BM1491_L9_PSU_WATCHDOG_ELECTRICAL_EFFECT_PROVEN: bool = false;
pub const BM1491_L9_HEARTBEAT_AUTHORIZES_IO: bool = false;
pub const BM1491_L9_HEARTBEAT_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1491_L9_HEARTBEAT_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9HeartbeatThreadRoute {
    PsuWatchdog,
    PicPerChain,
}

pub const fn bm1491_l9_heartbeat_thread_route(
    pic_mcu_enabled: bool,
) -> Bm1491L9HeartbeatThreadRoute {
    if pic_mcu_enabled {
        Bm1491L9HeartbeatThreadRoute::PicPerChain
    } else {
        Bm1491L9HeartbeatThreadRoute::PsuWatchdog
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9HeartbeatCallerDisposition {
    ContinueStartupAfterFirstSuccess,
    /// Stock returns the second `start_heartbeat_thread` result immediately.
    /// A successful retry therefore starts a thread but skips the remainder of
    /// the calling startup function.
    ReturnFromStartupAfterRetry {
        returned_code: u8,
        thread_running: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9HeartbeatStartError {
    MissingSecondAttempt,
}

/// Replay the exact two-call wrapper used by the held L9 `start_mining_base`.
pub const fn bm1491_l9_replay_heartbeat_start_caller(
    first_thread_created: bool,
    second_thread_created: Option<bool>,
) -> Result<Bm1491L9HeartbeatCallerDisposition, Bm1491L9HeartbeatStartError> {
    if first_thread_created {
        return Ok(Bm1491L9HeartbeatCallerDisposition::ContinueStartupAfterFirstSuccess);
    }
    let Some(second_thread_created) = second_thread_created else {
        return Err(Bm1491L9HeartbeatStartError::MissingSecondAttempt);
    };
    Ok(
        Bm1491L9HeartbeatCallerDisposition::ReturnFromStartupAfterRetry {
            returned_code: if second_thread_created {
                0
            } else {
                BM1491_L9_HEARTBEAT_THREAD_CREATE_FAILURE
            },
            thread_running: second_thread_created,
        },
    )
}

/// Build the exact held legacy APW17 watchdog request.
pub const fn bm1491_l9_legacy_watchdog_frame(enable: bool) -> [u8; 8] {
    let value = if enable { 1 } else { 0 };
    let checksum = BM1491_L9_LEGACY_WATCHDOG_LENGTH as u16
        + BM1491_L9_LEGACY_WATCHDOG_OPCODE as u16
        + value as u16;
    [
        0x55,
        0xaa,
        BM1491_L9_LEGACY_WATCHDOG_LENGTH,
        BM1491_L9_LEGACY_WATCHDOG_OPCODE,
        value,
        0,
        checksum as u8,
        (checksum >> 8) as u8,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PsuWatchdogStart {
    Active(Bm1491L9PsuWatchdogState),
    ExitedAfterEnableFailure { observed_result: i32 },
}

/// Stock enters the loop only for the exact library result `1`.
pub const fn bm1491_l9_psu_watchdog_start(enable_result: i32) -> Bm1491L9PsuWatchdogStart {
    if enable_result == 1 {
        Bm1491L9PsuWatchdogStart::Active(Bm1491L9PsuWatchdogState {
            consecutive_feedback_errors: 0,
            consecutive_power_status_errors: 0,
        })
    } else {
        Bm1491L9PsuWatchdogStart::ExitedAfterEnableFailure {
            observed_result: enable_result,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bm1491L9PsuWatchdogState {
    pub consecutive_feedback_errors: u32,
    pub consecutive_power_status_errors: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9FeedbackClassification {
    NotCheckedBecausePowerOff,
    ReadFailure,
    InRange,
    BelowWindow,
    AboveWindow,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1491L9PsuWatchdogSample {
    pub power_is_on: bool,
    /// Exact stock failure domain: any negative returned voltage.
    pub feedback_voltage_v: f64,
    pub current_voltage_centivolts: i32,
    /// Zero is stock success; every other value is a status error.
    pub power_status_result: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PsuWatchdogDisposition {
    Continue {
        update_miner_power: bool,
        tail_delay_seconds: u32,
    },
    /// A status failure returns immediately whenever the feedback counter is
    /// nonzero, even on the first feedback error.
    ExitOnCombinedStatusAndFeedback {
        feedback_errors: u32,
        power_status_errors: u32,
    },
    ExitOnPowerStatus {
        power_status_errors: u32,
    },
    ExitOnFeedback {
        feedback_errors: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PsuWatchdogError {
    NonFiniteFeedback,
    FeedbackCounterOverflow,
    PowerStatusCounterOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9PsuWatchdogStep {
    pub state: Bm1491L9PsuWatchdogState,
    pub feedback_classification: Bm1491L9FeedbackClassification,
    pub disposition: Bm1491L9PsuWatchdogDisposition,
}

impl Bm1491L9PsuWatchdogStep {
    pub const fn proves_physical_watchdog_effect(self) -> bool {
        false
    }

    pub const fn authorizes_rail_io(self) -> bool {
        false
    }
}

fn increment_feedback_errors(
    state: &mut Bm1491L9PsuWatchdogState,
) -> Result<(), Bm1491L9PsuWatchdogError> {
    state.consecutive_feedback_errors = state
        .consecutive_feedback_errors
        .checked_add(1)
        .ok_or(Bm1491L9PsuWatchdogError::FeedbackCounterOverflow)?;
    Ok(())
}

/// Replay one exact `psu_watchdog` iteration after successful enablement.
///
/// Exiting this worker does not call power-off, stop hashing, disable the
/// watchdog, or publish a fatal event in the recovered function.
pub fn bm1491_l9_step_psu_watchdog(
    previous: Bm1491L9PsuWatchdogState,
    sample: Bm1491L9PsuWatchdogSample,
) -> Result<Bm1491L9PsuWatchdogStep, Bm1491L9PsuWatchdogError> {
    let mut state = previous;
    let feedback_classification = if !sample.power_is_on {
        Bm1491L9FeedbackClassification::NotCheckedBecausePowerOff
    } else {
        let returned_voltage_v = sample.feedback_voltage_v;
        if !returned_voltage_v.is_finite() {
            return Err(Bm1491L9PsuWatchdogError::NonFiniteFeedback);
        }
        if returned_voltage_v < 0.0 {
            increment_feedback_errors(&mut state)?;
            Bm1491L9FeedbackClassification::ReadFailure
        } else {
            let feedback_centivolts =
                returned_voltage_v * f64::from_bits(BM1491_L9_FEEDBACK_SCALE_BITS);
            let current = f64::from(sample.current_voltage_centivolts);
            if current * f64::from_bits(BM1491_L9_FEEDBACK_HIGH_RATIO_BITS) < feedback_centivolts {
                increment_feedback_errors(&mut state)?;
                Bm1491L9FeedbackClassification::AboveWindow
            } else if feedback_centivolts
                < current * f64::from_bits(BM1491_L9_FEEDBACK_LOW_RATIO_BITS)
            {
                increment_feedback_errors(&mut state)?;
                Bm1491L9FeedbackClassification::BelowWindow
            } else {
                state.consecutive_feedback_errors = 0;
                Bm1491L9FeedbackClassification::InRange
            }
        }
    };

    if sample.power_status_result == 0 {
        state.consecutive_power_status_errors = 0;
    } else {
        state.consecutive_power_status_errors = state
            .consecutive_power_status_errors
            .checked_add(1)
            .ok_or(Bm1491L9PsuWatchdogError::PowerStatusCounterOverflow)?;
        if state.consecutive_feedback_errors != 0 {
            return Ok(Bm1491L9PsuWatchdogStep {
                state,
                feedback_classification,
                disposition: Bm1491L9PsuWatchdogDisposition::ExitOnCombinedStatusAndFeedback {
                    feedback_errors: state.consecutive_feedback_errors,
                    power_status_errors: state.consecutive_power_status_errors,
                },
            });
        }
        if state.consecutive_power_status_errors > BM1491_L9_PSU_ERROR_LIMIT {
            return Ok(Bm1491L9PsuWatchdogStep {
                state,
                feedback_classification,
                disposition: Bm1491L9PsuWatchdogDisposition::ExitOnPowerStatus {
                    power_status_errors: state.consecutive_power_status_errors,
                },
            });
        }
    }

    let disposition = if state.consecutive_feedback_errors > BM1491_L9_PSU_ERROR_LIMIT {
        Bm1491L9PsuWatchdogDisposition::ExitOnFeedback {
            feedback_errors: state.consecutive_feedback_errors,
        }
    } else {
        Bm1491L9PsuWatchdogDisposition::Continue {
            update_miner_power: true,
            tail_delay_seconds: BM1491_L9_PSU_WATCHDOG_LOOP_DELAY_SECONDS,
        }
    };
    Ok(Bm1491L9PsuWatchdogStep {
        state,
        feedback_classification,
        disposition,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9PicHeartbeatAttemptReport {
    pub attempts: usize,
    pub mismatch_backoffs: usize,
    pub success: bool,
}

impl Bm1491L9PicHeartbeatAttemptReport {
    pub const fn authorizes_pic_io(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PicHeartbeatReplayError {
    IncompleteAttempts,
    TrailingUnexecutedResponses,
}

pub const fn bm1491_l9_pic_heartbeat_response_valid(
    response: &[u8; BM1491_L9_PIC_HEARTBEAT_RESPONSE_LEN],
) -> bool {
    response[0] == BM1491_L9_PIC_HEARTBEAT_RESPONSE_LEN as u8
        && response[1] == BM1491_L9_PIC_HEARTBEAT_COMMAND
}

/// Replay the generic PIC command loop. Each invalid response incurs the
/// one-second backoff, including the fourth and terminal mismatch.
pub fn bm1491_l9_replay_pic_heartbeat_attempts(
    responses: &[[u8; BM1491_L9_PIC_HEARTBEAT_RESPONSE_LEN]],
) -> Result<Bm1491L9PicHeartbeatAttemptReport, Bm1491L9PicHeartbeatReplayError> {
    let mut mismatch_backoffs = 0;
    for (index, response) in responses.iter().enumerate() {
        if index >= BM1491_L9_PIC_COMMAND_ATTEMPTS {
            return Err(Bm1491L9PicHeartbeatReplayError::TrailingUnexecutedResponses);
        }
        if bm1491_l9_pic_heartbeat_response_valid(response) {
            if index + 1 != responses.len() {
                return Err(Bm1491L9PicHeartbeatReplayError::TrailingUnexecutedResponses);
            }
            return Ok(Bm1491L9PicHeartbeatAttemptReport {
                attempts: index + 1,
                mismatch_backoffs,
                success: true,
            });
        }
        mismatch_backoffs += 1;
    }
    if responses.len() != BM1491_L9_PIC_COMMAND_ATTEMPTS {
        return Err(Bm1491L9PicHeartbeatReplayError::IncompleteAttempts);
    }
    Ok(Bm1491L9PicHeartbeatAttemptReport {
        attempts: BM1491_L9_PIC_COMMAND_ATTEMPTS,
        mismatch_backoffs,
        success: false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PicHeartbeatLoopAction {
    InvokeHeartbeat { chain_selector: u8 },
    LogPicLost { chain_selector: u8 },
    DelaySeconds(u32),
    UpdateMinerPower,
}

/// Replay one complete `heartbeat_on_device` scan. Failures add only a log;
/// there is no counter, threshold, isolation, rail cut, or recovery action.
pub fn bm1491_l9_plan_pic_heartbeat_scan(
    chain_results: &[(u8, bool)],
) -> Vec<Bm1491L9PicHeartbeatLoopAction> {
    let mut actions = Vec::with_capacity(chain_results.len() * 3 + 1);
    for &(chain_selector, succeeded) in chain_results {
        actions.push(Bm1491L9PicHeartbeatLoopAction::InvokeHeartbeat { chain_selector });
        if !succeeded {
            actions.push(Bm1491L9PicHeartbeatLoopAction::LogPicLost { chain_selector });
        }
        actions.push(Bm1491L9PicHeartbeatLoopAction::DelaySeconds(
            BM1491_L9_PIC_CHAIN_DELAY_SECONDS,
        ));
    }
    actions.push(Bm1491L9PicHeartbeatLoopAction::UpdateMinerPower);
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(feedback_v: f64, power_status_result: i32) -> Bm1491L9PsuWatchdogSample {
        Bm1491L9PsuWatchdogSample {
            power_is_on: true,
            feedback_voltage_v: feedback_v,
            current_voltage_centivolts: 1_400,
            power_status_result,
        }
    }

    #[test]
    fn held_topology_selects_psu_watchdog() {
        assert_eq!(
            bm1491_l9_heartbeat_thread_route(BM1491_L9_HELD_PIC_MCU_ENABLED),
            Bm1491L9HeartbeatThreadRoute::PsuWatchdog
        );
        assert_eq!(
            bm1491_l9_heartbeat_thread_route(true),
            Bm1491L9HeartbeatThreadRoute::PicPerChain
        );
    }

    #[test]
    fn held_host_watchdog_module_is_inventory_not_arm_evidence() {
        assert_eq!(
            BM1491_L9_HOST_WDT_MODULE_PATH,
            "/mnt/system/ko/cv183x_wdt.ko"
        );
        assert_eq!(BM1491_L9_HOST_WDT_MODULE_SIZE, 17_120);
        assert_eq!(
            BM1491_L9_HOST_WDT_MODULE_SHA256,
            "9f98d1f0ebb72ce79078824c886b07538c0d4e630fdcdeda99db5faea5d6043b"
        );
        assert_eq!(
            BM1491_L9_HOST_WDT_MODULE_BUILD_ID,
            "655fbdbce5501fca6a8f4de49b0997c459553ce7"
        );
        assert_eq!(
            BM1491_L9_HOST_WDT_MODULE_VERMAGIC,
            "4.9.38-tag- SMP preempt mod_unload aarch64 "
        );
        assert_eq!(
            BM1491_L9_HOST_WDT_MODULE_DESCRIPTION,
            "Synopsys DesignWare Watchdog Driver"
        );
        assert!(!BM1491_L9_HOST_WDT_MODULE_NOWAYOUT_DEFAULT);
        assert!(!BM1491_L9_HOST_WDT_INIT_REFERENCE_PRESENT);
        assert!(!BM1491_L9_HOST_WDT_AUTOLOAD_METADATA_PRESENT);
        assert!(!BM1491_L9_HOST_WDT_FEEDER_RECOVERED);
        assert!(!BM1491_L9_HOST_WDT_ACTIVE_PROVEN);
    }

    #[test]
    fn caller_retries_once_then_returns_retry_result() {
        assert_eq!(
            bm1491_l9_replay_heartbeat_start_caller(true, None),
            Ok(Bm1491L9HeartbeatCallerDisposition::ContinueStartupAfterFirstSuccess)
        );
        assert_eq!(
            bm1491_l9_replay_heartbeat_start_caller(false, Some(true)),
            Ok(
                Bm1491L9HeartbeatCallerDisposition::ReturnFromStartupAfterRetry {
                    returned_code: 0,
                    thread_running: true,
                }
            )
        );
        assert_eq!(
            bm1491_l9_replay_heartbeat_start_caller(false, Some(false)),
            Ok(
                Bm1491L9HeartbeatCallerDisposition::ReturnFromStartupAfterRetry {
                    returned_code: 5,
                    thread_running: false,
                }
            )
        );
    }

    #[test]
    fn exact_watchdog_and_pic_frames_are_pinned() {
        assert_eq!(
            bm1491_l9_legacy_watchdog_frame(true),
            BM1491_L9_LEGACY_WATCHDOG_ENABLE_FRAME
        );
        assert_eq!(
            bm1491_l9_legacy_watchdog_frame(false),
            [0x55, 0xaa, 0x06, 0x81, 0x00, 0x00, 0x87, 0x00]
        );
        assert_eq!(
            BM1491_L9_PIC_HEARTBEAT_FRAME,
            [0x55, 0xaa, 4, 0x16, 0, 0x1a]
        );
    }

    #[test]
    fn watchdog_requires_exact_enable_result_one() {
        assert!(matches!(
            bm1491_l9_psu_watchdog_start(1),
            Bm1491L9PsuWatchdogStart::Active(_)
        ));
        for result in [0, 2, -1, i32::MIN] {
            assert_eq!(
                bm1491_l9_psu_watchdog_start(result),
                Bm1491L9PsuWatchdogStart::ExitedAfterEnableFailure {
                    observed_result: result
                }
            );
        }
    }

    #[test]
    fn feedback_window_is_strict_and_equality_passes() {
        let state = Bm1491L9PsuWatchdogState::default();
        for value in [12.6, 15.4] {
            let step = bm1491_l9_step_psu_watchdog(state, sample(value, 0)).unwrap();
            assert_eq!(
                step.feedback_classification,
                Bm1491L9FeedbackClassification::InRange
            );
            assert_eq!(step.state.consecutive_feedback_errors, 0);
        }
        assert_eq!(
            bm1491_l9_step_psu_watchdog(state, sample(12.599, 0))
                .unwrap()
                .feedback_classification,
            Bm1491L9FeedbackClassification::BelowWindow
        );
        assert_eq!(
            bm1491_l9_step_psu_watchdog(state, sample(15.401, 0))
                .unwrap()
                .feedback_classification,
            Bm1491L9FeedbackClassification::AboveWindow
        );
    }

    #[test]
    fn good_feedback_resets_counter_but_power_off_preserves_it() {
        let state = Bm1491L9PsuWatchdogState {
            consecutive_feedback_errors: 2,
            consecutive_power_status_errors: 0,
        };
        let good = bm1491_l9_step_psu_watchdog(state, sample(14.0, 0)).unwrap();
        assert_eq!(good.state.consecutive_feedback_errors, 0);

        let mut off = sample(14.0, 0);
        off.power_is_on = false;
        let preserved = bm1491_l9_step_psu_watchdog(state, off).unwrap();
        assert_eq!(preserved.state.consecutive_feedback_errors, 2);
        assert_eq!(
            preserved.feedback_classification,
            Bm1491L9FeedbackClassification::NotCheckedBecausePowerOff
        );
    }

    #[test]
    fn negative_feedback_is_read_failure_and_nonfinite_is_refused() {
        let state = Bm1491L9PsuWatchdogState::default();
        let failed = bm1491_l9_step_psu_watchdog(state, sample(-1.0, 0)).unwrap();
        assert_eq!(
            failed.feedback_classification,
            Bm1491L9FeedbackClassification::ReadFailure
        );
        assert_eq!(failed.state.consecutive_feedback_errors, 1);
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                bm1491_l9_step_psu_watchdog(state, sample(value, 0)),
                Err(Bm1491L9PsuWatchdogError::NonFiniteFeedback)
            );
        }
    }

    #[test]
    fn one_feedback_error_plus_status_error_exits_immediately() {
        let step =
            bm1491_l9_step_psu_watchdog(Bm1491L9PsuWatchdogState::default(), sample(12.0, -7))
                .unwrap();
        assert_eq!(
            step.disposition,
            Bm1491L9PsuWatchdogDisposition::ExitOnCombinedStatusAndFeedback {
                feedback_errors: 1,
                power_status_errors: 1,
            }
        );
    }

    #[test]
    fn fourth_error_exits_but_no_stock_rail_action_is_claimed() {
        let feedback = bm1491_l9_step_psu_watchdog(
            Bm1491L9PsuWatchdogState {
                consecutive_feedback_errors: 3,
                consecutive_power_status_errors: 0,
            },
            sample(12.0, 0),
        )
        .unwrap();
        assert_eq!(
            feedback.disposition,
            Bm1491L9PsuWatchdogDisposition::ExitOnFeedback { feedback_errors: 4 }
        );
        assert!(!feedback.proves_physical_watchdog_effect());
        assert!(!feedback.authorizes_rail_io());

        let status = bm1491_l9_step_psu_watchdog(
            Bm1491L9PsuWatchdogState {
                consecutive_feedback_errors: 0,
                consecutive_power_status_errors: 3,
            },
            sample(14.0, -9),
        )
        .unwrap();
        assert_eq!(
            status.disposition,
            Bm1491L9PsuWatchdogDisposition::ExitOnPowerStatus {
                power_status_errors: 4
            }
        );
    }

    #[test]
    fn pic_response_is_prefix_only_and_terminal_failure_still_backs_off() {
        let success = bm1491_l9_replay_pic_heartbeat_attempts(&[
            [0, 0, 0, 0, 0, 0],
            [6, 0x16, 0xde, 0xad, 0xbe, 0xef],
        ])
        .unwrap();
        assert_eq!(success.attempts, 2);
        assert_eq!(success.mismatch_backoffs, 1);
        assert!(success.success);

        let failed = bm1491_l9_replay_pic_heartbeat_attempts(&[[0; 6]; 4]).unwrap();
        assert_eq!(failed.attempts, 4);
        assert_eq!(failed.mismatch_backoffs, 4);
        assert!(!failed.success);
        assert!(!failed.authorizes_pic_io());
    }

    #[test]
    fn pic_loop_logs_only_and_updates_power_after_scan() {
        assert_eq!(
            bm1491_l9_plan_pic_heartbeat_scan(&[(3, false), (4, true)]),
            vec![
                Bm1491L9PicHeartbeatLoopAction::InvokeHeartbeat { chain_selector: 3 },
                Bm1491L9PicHeartbeatLoopAction::LogPicLost { chain_selector: 3 },
                Bm1491L9PicHeartbeatLoopAction::DelaySeconds(5),
                Bm1491L9PicHeartbeatLoopAction::InvokeHeartbeat { chain_selector: 4 },
                Bm1491L9PicHeartbeatLoopAction::DelaySeconds(5),
                Bm1491L9PicHeartbeatLoopAction::UpdateMinerPower,
            ]
        );
        assert_eq!(
            bm1491_l9_plan_pic_heartbeat_scan(&[]),
            vec![Bm1491L9PicHeartbeatLoopAction::UpdateMinerPower]
        );
    }
}
