//! Exact-release BM1485/L3+ stock process-exit and shutdown evidence.
//!
//! The held 2017 image has no normal exit path that directly quiesces the
//! ASICs or disables their PIC-controlled rails. The co-bundled service script
//! uses `SIGKILL`; signal/API exits use generic cgminer cleanup. This module is
//! pure, accepts caller-forgeable observations, and grants no shutdown or I/O
//! authority.

use crate::bm1485_l3plus_stock::BM1485_L3PLUS_STOCK_CHAIN_COUNT;

pub const BM1485_L3PLUS_STOCK_SERVICE_SCRIPT_PATH: &str = "/etc/init.d/cgminer.sh";
pub const BM1485_L3PLUS_STOCK_SERVICE_SCRIPT_SHA256: &str =
    "160fc812b14a4b969f3c9780802c2dd93e5975928fed374229718cde37582814";
pub const BM1485_L3PLUS_STOCK_SERVICE_STOP_COMMAND: &str = "killall -9 cgminer || true";
pub const BM1485_L3PLUS_STOCK_GENERIC_COMPLETION_WAIT_MS: u32 = 5_000;
pub const BM1485_L3PLUS_STOCK_GENERIC_FORCED_EXIT_WATCHDOG_SECONDS: u32 = 5;

pub const BM1485_L3PLUS_STOCK_NORMAL_EXIT_DIRECTLY_QUIESCES_ASICS: bool = false;
pub const BM1485_L3PLUS_STOCK_NORMAL_EXIT_DIRECTLY_DISABLES_RAILS: bool = false;
pub const BM1485_L3PLUS_STOCK_NORMAL_EXIT_CHANGES_FAN_PWM: bool = false;
pub const BM1485_L3PLUS_STOCK_NORMAL_EXIT_PROVES_ELECTRICAL_OFF: bool = false;
pub const BM1485_L3PLUS_STOCK_SHUTDOWN_IDENTIFIES_PHYSICAL_BOARD: bool = false;
pub const BM1485_L3PLUS_STOCK_SHUTDOWN_AUTHORIZES_PROCESS_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_SHUTDOWN_AUTHORIZES_RAIL_IO: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockExitEntry {
    /// `do_stop()` in the co-bundled SysV script.
    ServiceStop,
    /// `do_stop()` followed by `do_start()` in the co-bundled SysV script.
    ServiceRestart,
    /// `FUN_00017338`, installed as the generic shutdown signal handler.
    SignalHandler,
    /// `FUN_00031e9c`, whose resolved pre-exit callback is the no-op
    /// `FUN_00028460`, followed by `FUN_00017338`.
    ApiCleanQuit,
    /// The share-limit branch in `FUN_000201e0` reaches `FUN_00017338`.
    ShareLimitExit,
    /// The scheduled-stop branch reaches `FUN_00017338`.
    ScheduledStopExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockExitObservation {
    pub entry: Bm1485L3PlusStockExitEntry,
    pub service_command: Option<&'static str>,
    pub sends_sigkill: bool,
    pub restarts_process_after_stop: bool,
    pub reaches_generic_shutdown_handler: bool,
    pub generic_completion_wait_ms: Option<u32>,
    pub generic_forced_exit_watchdog_seconds: Option<u32>,
    pub directly_quiesces_asics: bool,
    pub directly_attempts_pic_rail_disable: bool,
    pub changes_fan_pwm: bool,
    pub verifies_electrical_off: bool,
}

impl Bm1485L3PlusStockExitObservation {
    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

/// Returns the exact process-exit behavior visible in the held binary and its
/// co-bundled service script. This deliberately does not infer that process
/// death stops already-published ASIC work or de-energizes a rail.
pub const fn bm1485_l3plus_stock_exit_observation(
    entry: Bm1485L3PlusStockExitEntry,
) -> Bm1485L3PlusStockExitObservation {
    let service_entry = matches!(
        entry,
        Bm1485L3PlusStockExitEntry::ServiceStop | Bm1485L3PlusStockExitEntry::ServiceRestart
    );
    let reaches_generic_shutdown_handler = !service_entry;
    Bm1485L3PlusStockExitObservation {
        entry,
        service_command: if service_entry {
            Some(BM1485_L3PLUS_STOCK_SERVICE_STOP_COMMAND)
        } else {
            None
        },
        sends_sigkill: service_entry,
        restarts_process_after_stop: matches!(entry, Bm1485L3PlusStockExitEntry::ServiceRestart),
        reaches_generic_shutdown_handler,
        generic_completion_wait_ms: if reaches_generic_shutdown_handler {
            Some(BM1485_L3PLUS_STOCK_GENERIC_COMPLETION_WAIT_MS)
        } else {
            None
        },
        generic_forced_exit_watchdog_seconds: if reaches_generic_shutdown_handler {
            Some(BM1485_L3PLUS_STOCK_GENERIC_FORCED_EXIT_WATCHDOG_SECONDS)
        } else {
            None
        },
        directly_quiesces_asics: BM1485_L3PLUS_STOCK_NORMAL_EXIT_DIRECTLY_QUIESCES_ASICS,
        directly_attempts_pic_rail_disable: BM1485_L3PLUS_STOCK_NORMAL_EXIT_DIRECTLY_DISABLES_RAILS,
        changes_fan_pwm: BM1485_L3PLUS_STOCK_NORMAL_EXIT_CHANGES_FAN_PWM,
        verifies_electrical_off: BM1485_L3PLUS_STOCK_NORMAL_EXIT_PROVES_ELECTRICAL_OFF,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusShutdownEvidence {
    /// Caller assertion: chains believed energized immediately before teardown.
    pub energized_chains_before_shutdown: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub dispatch_revoked: bool,
    pub workers_quiesced: bool,
    pub rail_disable_attempted: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub rail_disable_response_verified: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub electrical_off_independently_observed: [bool; BM1485_L3PLUS_STOCK_CHAIN_COUNT],
    pub cooling_custody_held_until_electrical_off: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusShutdownAssessmentError {
    NoEnergizedChainScope,
    DispatchNotRevoked,
    WorkersNotQuiesced,
    RailDisableNotAttempted(usize),
    RailDisableResponseNotVerified(usize),
    ElectricalOffNotObserved(usize),
    EvidenceForChainOutsideEnergizedScope(usize),
    CoolingCustodyLostBeforeElectricalOff,
}

/// A passive consistency result over caller-supplied observations. It is not a
/// live receipt and cannot establish freshness, ordering, or signal provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusShutdownConsistency {
    checked_energized_chains: u8,
}

impl Bm1485L3PlusShutdownConsistency {
    pub const fn checked_energized_chains(self) -> u8 {
        self.checked_energized_chains
    }

    pub const fn authorizes_shutdown_or_rail_io(self) -> bool {
        false
    }

    pub const fn proves_fresh_electrical_off(self) -> bool {
        false
    }
}

/// Fail-closed assessment required before a future live carrier could describe
/// teardown as complete. The exact stock path cannot satisfy the response and
/// independent electrical-off requirements by itself.
pub fn assess_bm1485_l3plus_shutdown_consistency(
    evidence: Bm1485L3PlusShutdownEvidence,
) -> Result<Bm1485L3PlusShutdownConsistency, Bm1485L3PlusShutdownAssessmentError> {
    let checked_energized_chains = evidence
        .energized_chains_before_shutdown
        .into_iter()
        .filter(|energized| *energized)
        .count();
    if checked_energized_chains == 0 {
        return Err(Bm1485L3PlusShutdownAssessmentError::NoEnergizedChainScope);
    }
    if !evidence.dispatch_revoked {
        return Err(Bm1485L3PlusShutdownAssessmentError::DispatchNotRevoked);
    }
    if !evidence.workers_quiesced {
        return Err(Bm1485L3PlusShutdownAssessmentError::WorkersNotQuiesced);
    }

    for chain_slot in 0..BM1485_L3PLUS_STOCK_CHAIN_COUNT {
        let energized = evidence.energized_chains_before_shutdown[chain_slot];
        let attempted = evidence.rail_disable_attempted[chain_slot];
        let response_verified = evidence.rail_disable_response_verified[chain_slot];
        let electrical_off = evidence.electrical_off_independently_observed[chain_slot];
        if !energized && (attempted || response_verified || electrical_off) {
            return Err(
                Bm1485L3PlusShutdownAssessmentError::EvidenceForChainOutsideEnergizedScope(
                    chain_slot,
                ),
            );
        }
        if energized && !attempted {
            return Err(Bm1485L3PlusShutdownAssessmentError::RailDisableNotAttempted(chain_slot));
        }
        if energized && !response_verified {
            return Err(
                Bm1485L3PlusShutdownAssessmentError::RailDisableResponseNotVerified(chain_slot),
            );
        }
        if energized && !electrical_off {
            return Err(Bm1485L3PlusShutdownAssessmentError::ElectricalOffNotObserved(chain_slot));
        }
    }
    if !evidence.cooling_custody_held_until_electrical_off {
        return Err(Bm1485L3PlusShutdownAssessmentError::CoolingCustodyLostBeforeElectricalOff);
    }

    Ok(Bm1485L3PlusShutdownConsistency {
        checked_energized_chains: checked_energized_chains as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_evidence() -> Bm1485L3PlusShutdownEvidence {
        Bm1485L3PlusShutdownEvidence {
            energized_chains_before_shutdown: [true, false, true, false],
            dispatch_revoked: true,
            workers_quiesced: true,
            rail_disable_attempted: [true, false, true, false],
            rail_disable_response_verified: [true, false, true, false],
            electrical_off_independently_observed: [true, false, true, false],
            cooling_custody_held_until_electrical_off: true,
        }
    }

    #[test]
    fn service_stop_and_restart_are_sigkill_without_hardware_teardown() {
        for (entry, restarts) in [
            (Bm1485L3PlusStockExitEntry::ServiceStop, false),
            (Bm1485L3PlusStockExitEntry::ServiceRestart, true),
        ] {
            let observed = bm1485_l3plus_stock_exit_observation(entry);
            assert_eq!(observed.service_command, Some("killall -9 cgminer || true"));
            assert!(observed.sends_sigkill);
            assert_eq!(observed.restarts_process_after_stop, restarts);
            assert!(!observed.reaches_generic_shutdown_handler);
            assert_eq!(observed.generic_completion_wait_ms, None);
            assert_eq!(observed.generic_forced_exit_watchdog_seconds, None);
            assert!(!observed.directly_quiesces_asics);
            assert!(!observed.directly_attempts_pic_rail_disable);
            assert!(!observed.changes_fan_pwm);
            assert!(!observed.verifies_electrical_off);
            assert!(!observed.authorizes_execution());
        }
    }

    #[test]
    fn graceful_entries_converge_on_generic_cleanup_without_rail_off() {
        for entry in [
            Bm1485L3PlusStockExitEntry::SignalHandler,
            Bm1485L3PlusStockExitEntry::ApiCleanQuit,
            Bm1485L3PlusStockExitEntry::ShareLimitExit,
            Bm1485L3PlusStockExitEntry::ScheduledStopExit,
        ] {
            let observed = bm1485_l3plus_stock_exit_observation(entry);
            assert_eq!(observed.service_command, None);
            assert!(!observed.sends_sigkill);
            assert!(observed.reaches_generic_shutdown_handler);
            assert_eq!(observed.generic_completion_wait_ms, Some(5_000));
            assert_eq!(observed.generic_forced_exit_watchdog_seconds, Some(5));
            assert!(!observed.directly_quiesces_asics);
            assert!(!observed.directly_attempts_pic_rail_disable);
            assert!(!observed.changes_fan_pwm);
            assert!(!observed.verifies_electrical_off);
        }
    }

    #[test]
    fn exact_stock_observations_cannot_satisfy_clean_shutdown_evidence() {
        let mut evidence = complete_evidence();
        evidence.rail_disable_response_verified = [false; 4];
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::RailDisableResponseNotVerified(0))
        );
    }

    #[test]
    fn assessment_refuses_every_missing_safety_stage_in_order() {
        let mut evidence = complete_evidence();
        evidence.dispatch_revoked = false;
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::DispatchNotRevoked)
        );
        evidence = complete_evidence();
        evidence.workers_quiesced = false;
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::WorkersNotQuiesced)
        );
        evidence = complete_evidence();
        evidence.rail_disable_attempted[0] = false;
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::RailDisableNotAttempted(0))
        );
        evidence = complete_evidence();
        evidence.electrical_off_independently_observed[2] = false;
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::ElectricalOffNotObserved(2))
        );
        evidence = complete_evidence();
        evidence.cooling_custody_held_until_electrical_off = false;
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::CoolingCustodyLostBeforeElectricalOff)
        );
    }

    #[test]
    fn scope_refuses_empty_and_out_of_scope_chain_evidence() {
        let mut evidence = complete_evidence();
        evidence.energized_chains_before_shutdown = [false; 4];
        evidence.rail_disable_attempted = [false; 4];
        evidence.rail_disable_response_verified = [false; 4];
        evidence.electrical_off_independently_observed = [false; 4];
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::NoEnergizedChainScope)
        );
        evidence = complete_evidence();
        evidence.rail_disable_attempted[1] = true;
        assert_eq!(
            assess_bm1485_l3plus_shutdown_consistency(evidence),
            Err(Bm1485L3PlusShutdownAssessmentError::EvidenceForChainOutsideEnergizedScope(1))
        );
    }

    #[test]
    fn complete_passive_consistency_never_mints_authority() {
        let consistency = assess_bm1485_l3plus_shutdown_consistency(complete_evidence()).unwrap();
        assert_eq!(consistency.checked_energized_chains(), 2);
        assert!(!consistency.authorizes_shutdown_or_rail_io());
        assert!(!consistency.proves_fresh_electrical_off());
        assert!(!BM1485_L3PLUS_STOCK_SHUTDOWN_IDENTIFIES_PHYSICAL_BOARD);
        assert!(!BM1485_L3PLUS_STOCK_SHUTDOWN_AUTHORIZES_PROCESS_IO);
        assert!(!BM1485_L3PLUS_STOCK_SHUTDOWN_AUTHORIZES_RAIL_IO);
    }
}
