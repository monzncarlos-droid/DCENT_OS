//! Decrease-only actuation policy for [`crate::BadChipAction`].
//!
//! Quality bar (gauntlet #11): LuxOS `healthchipget`/`healthchipset` plus the
//! in-tree RE-004 action ladder. Detection already lives in
//! [`crate::BadChipSupervisor`]; this module is the missing **caller policy**
//! that turns those actions into frequency/hash-cut intents the daemon can
//! apply without touching voltage, fans, EEPROM, or rails.
//!
//! Safety:
//! - Every frequency intent is a **ceiling** at or below the live operating
//!   point. The helper never returns a higher MHz than `current_*_mhz`.
//! - HaltMining becomes a floor ceiling (cut hash). It never requests fan PWM.
//! - BoardReset is refused: process-exit / board reset is not a SafeOff receipt.
//! - Default-off: the daemon only applies these intents when
//!   `[autotune.bad_chip].actuate = true` (separate from `.enabled` telemetry).

use crate::bad_chip_supervisor::{BadChipAction, HaltReason};

/// Lowest frequency the policy will command as a ceiling.
/// Matches the dispatcher `MIN_RUNTIME_FREQ_MHZ` / ATM floor so a health
/// actuation cannot drive the chain into an unminable PLL.
pub const BAD_CHIP_ACTUATION_FLOOR_MHZ: u16 = 200;

/// Planned actuation. Pure data — no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadChipActuation {
    /// Per-chip frequency ceiling (decrease-only).
    ChipCeiling {
        chain_id: u8,
        chip_index: u8,
        max_freq_mhz: u16,
    },
    /// Whole-chain frequency ceiling (decrease-only).
    ChainCeiling { chain_id: u8, max_freq_mhz: u16 },
    /// Cut hash on this chain by parking the ceiling at the floor.
    CutHash {
        chain_id: u8,
        max_freq_mhz: u16,
        reason: HaltReason,
    },
    /// Explicit refuse (no hardware mutation).
    Refuse {
        chain_id: u8,
        why: BadChipRefuseReason,
    },
    /// Nothing to apply.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadChipRefuseReason {
    /// BoardReset requires a typed SafeOff receipt that this path does not have.
    BoardResetNeedsSafeOffReceipt,
    /// Chip index does not fit the dispatcher's `u8` chip address.
    ChipIndexOutOfRange,
}

/// Prefer live operating MHz for expected-nonce / first-step math.
///
/// A stale config nameplate (e.g. 525 MHz) against a 400 MHz live point
/// inflates expected nonces and false-degrades every chip. Live is used when
/// it is positive and not above the operator/SKU nameplate.
pub fn resolve_health_operating_mhz(live: Option<u16>, config_nominal: u16) -> u16 {
    let nominal = config_nominal.max(1);
    match live {
        Some(freq) if freq > 0 => freq.min(nominal),
        _ => nominal,
    }
}

/// First ATM / health step-down base: existing ceiling, else live, else nameplate.
pub fn decrease_only_step_base(
    current_ceiling: Option<u16>,
    live_operating: Option<u16>,
    config_nominal: u16,
) -> u16 {
    if let Some(ceiling) = current_ceiling {
        return ceiling.min(config_nominal.max(1));
    }
    resolve_health_operating_mhz(live_operating, config_nominal)
}

/// Per-chip and per-chain bases for one actuation tick.
///
/// Always start from an already-applied BadChip ceiling when present so a
/// later ReduceBoardProfile cannot recompute from live nameplate and raise.
pub fn actuation_bases(
    existing_chip_ceiling: Option<u16>,
    existing_chain_ceiling: Option<u16>,
    live_operating: Option<u16>,
    config_nominal: u16,
) -> (u16, u16) {
    (
        decrease_only_step_base(existing_chip_ceiling, live_operating, config_nominal),
        decrease_only_step_base(existing_chain_ceiling, live_operating, config_nominal),
    )
}

fn decrease_only_ceiling(current_mhz: u16, step_mhz: u16, floor_mhz: u16) -> u16 {
    let floor = floor_mhz.max(1);
    current_mhz
        .saturating_sub(step_mhz)
        .max(floor)
        .min(current_mhz)
}

/// Map one supervisor action to a decrease-only actuation intent.
///
/// `current_chip_mhz` / `current_chain_mhz` are the live (or resolved)
/// operating points. The returned ceiling is never above those values.
pub fn plan_bad_chip_actuation(
    action: &BadChipAction,
    current_chip_mhz: u16,
    current_chain_mhz: u16,
    floor_mhz: u16,
) -> BadChipActuation {
    match action {
        BadChipAction::NoOp => BadChipActuation::None,
        BadChipAction::PerChipDownclock {
            chain_id,
            chip_index,
            mhz_step,
        } => {
            let Ok(chip_index) = u8::try_from(*chip_index) else {
                return BadChipActuation::Refuse {
                    chain_id: *chain_id,
                    why: BadChipRefuseReason::ChipIndexOutOfRange,
                };
            };
            BadChipActuation::ChipCeiling {
                chain_id: *chain_id,
                chip_index,
                max_freq_mhz: decrease_only_ceiling(current_chip_mhz, *mhz_step, floor_mhz),
            }
        }
        BadChipAction::BlacklistChip {
            chain_id,
            chip_index,
            ..
        } => {
            let Ok(chip_index) = u8::try_from(*chip_index) else {
                return BadChipActuation::Refuse {
                    chain_id: *chain_id,
                    why: BadChipRefuseReason::ChipIndexOutOfRange,
                };
            };
            // Park the chip at the floor. Share-submit stays intact; the
            // supervisor already dropped the chip from expected-nonce math.
            BadChipActuation::ChipCeiling {
                chain_id: *chain_id,
                chip_index,
                max_freq_mhz: floor_mhz.max(1).min(current_chip_mhz.max(1)),
            }
        }
        BadChipAction::ReduceBoardProfile { chain_id } => BadChipActuation::ChainCeiling {
            chain_id: *chain_id,
            max_freq_mhz: decrease_only_ceiling(
                current_chain_mhz,
                // One board-profile step equals the default per-chip step so
                // a board-wide failure does not jump more than a single rung.
                25,
                floor_mhz,
            ),
        },
        BadChipAction::HaltMining { reason } => BadChipActuation::CutHash {
            // Halt is emitted for the chain `observe()` just classified.
            // The caller applies the floor ceiling on that chain only.
            chain_id: 0,
            max_freq_mhz: floor_mhz.max(1).min(current_chain_mhz.max(1)),
            reason: *reason,
        },
        BadChipAction::BoardReset { chain_id, .. } => BadChipActuation::Refuse {
            chain_id: *chain_id,
            why: BadChipRefuseReason::BoardResetNeedsSafeOffReceipt,
        },
    }
}

/// HaltMining is not chain-tagged on the action enum. Bind it to the
/// snapshot chain the supervisor just observed.
pub fn plan_bad_chip_actuation_on_chain(
    action: &BadChipAction,
    observed_chain_id: u8,
    current_chip_mhz: u16,
    current_chain_mhz: u16,
    floor_mhz: u16,
) -> BadChipActuation {
    match plan_bad_chip_actuation(action, current_chip_mhz, current_chain_mhz, floor_mhz) {
        BadChipActuation::CutHash {
            max_freq_mhz,
            reason,
            ..
        } => BadChipActuation::CutHash {
            chain_id: observed_chain_id,
            max_freq_mhz,
            reason,
        },
        other => other,
    }
}

/// True when the daemon may apply [`plan_bad_chip_actuation`] results.
/// Telemetry (`enabled`) stays independent of actuation.
pub fn bad_chip_actuation_armed(enabled: bool, actuate: bool) -> bool {
    enabled && actuate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bad_chip_supervisor::BadChipReason;

    #[test]
    fn resolve_health_operating_mhz_prefers_live_below_nameplate() {
        assert_eq!(resolve_health_operating_mhz(Some(400), 525), 400);
        assert_eq!(resolve_health_operating_mhz(Some(525), 525), 525);
        assert_eq!(resolve_health_operating_mhz(Some(600), 525), 525);
        assert_eq!(resolve_health_operating_mhz(Some(0), 525), 525);
        assert_eq!(resolve_health_operating_mhz(None, 525), 525);
        assert_eq!(resolve_health_operating_mhz(None, 0), 1);
    }

    #[test]
    fn decrease_only_step_base_starts_from_live_when_unconstrained() {
        assert_eq!(decrease_only_step_base(None, Some(400), 525), 400);
        assert_eq!(decrease_only_step_base(Some(450), Some(400), 525), 450);
        assert_eq!(decrease_only_step_base(None, None, 525), 525);
    }

    #[test]
    fn reduce_board_cannot_raise_existing_ceiling_from_live_nameplate() {
        let (chip_base, chain_base) = actuation_bases(Some(400), Some(400), Some(525), 525);
        assert_eq!(chip_base, 400);
        assert_eq!(chain_base, 400);
        let action = BadChipAction::ReduceBoardProfile { chain_id: 8 };
        match plan_bad_chip_actuation(&action, chip_base, chain_base, BAD_CHIP_ACTUATION_FLOOR_MHZ)
        {
            BadChipActuation::ChainCeiling { max_freq_mhz, .. } => {
                assert_eq!(max_freq_mhz, 375);
                assert!(max_freq_mhz < 400);
            }
            other => panic!("expected chain ceiling, got {other:?}"),
        }
    }

    #[test]
    fn downclock_never_raises_and_respects_floor() {
        let action = BadChipAction::PerChipDownclock {
            chain_id: 6,
            chip_index: 2,
            mhz_step: 25,
        };
        let planned = plan_bad_chip_actuation(&action, 485, 485, BAD_CHIP_ACTUATION_FLOOR_MHZ);
        assert_eq!(
            planned,
            BadChipActuation::ChipCeiling {
                chain_id: 6,
                chip_index: 2,
                max_freq_mhz: 460,
            }
        );
        let at_floor = plan_bad_chip_actuation(&action, 200, 200, BAD_CHIP_ACTUATION_FLOOR_MHZ);
        assert_eq!(
            at_floor,
            BadChipActuation::ChipCeiling {
                chain_id: 6,
                chip_index: 2,
                max_freq_mhz: 200,
            }
        );
        // A huge step still cannot go below the floor or above current.
        let huge = BadChipAction::PerChipDownclock {
            chain_id: 6,
            chip_index: 2,
            mhz_step: 10_000,
        };
        match plan_bad_chip_actuation(&huge, 485, 485, BAD_CHIP_ACTUATION_FLOOR_MHZ) {
            BadChipActuation::ChipCeiling { max_freq_mhz, .. } => {
                assert_eq!(max_freq_mhz, BAD_CHIP_ACTUATION_FLOOR_MHZ);
                assert!(max_freq_mhz <= 485);
            }
            other => panic!("expected chip ceiling, got {other:?}"),
        }
    }

    #[test]
    fn blacklist_parks_at_floor_without_raising() {
        let action = BadChipAction::BlacklistChip {
            chain_id: 7,
            chip_index: 1,
            reason: BadChipReason::PersistentlyLowNonceRate,
        };
        assert_eq!(
            plan_bad_chip_actuation(&action, 400, 400, BAD_CHIP_ACTUATION_FLOOR_MHZ),
            BadChipActuation::ChipCeiling {
                chain_id: 7,
                chip_index: 1,
                max_freq_mhz: 200,
            }
        );
    }

    #[test]
    fn reduce_board_profile_is_chain_ceiling_decrease_only() {
        let action = BadChipAction::ReduceBoardProfile { chain_id: 8 };
        match plan_bad_chip_actuation(&action, 500, 500, BAD_CHIP_ACTUATION_FLOOR_MHZ) {
            BadChipActuation::ChainCeiling {
                chain_id,
                max_freq_mhz,
            } => {
                assert_eq!(chain_id, 8);
                assert_eq!(max_freq_mhz, 475);
                assert!(max_freq_mhz < 500);
            }
            other => panic!("expected chain ceiling, got {other:?}"),
        }
    }

    #[test]
    fn halt_cuts_hash_at_floor_and_binds_observed_chain() {
        let action = BadChipAction::HaltMining {
            reason: HaltReason::InsufficientHealthyChains,
        };
        let planned =
            plan_bad_chip_actuation_on_chain(&action, 6, 485, 485, BAD_CHIP_ACTUATION_FLOOR_MHZ);
        assert_eq!(
            planned,
            BadChipActuation::CutHash {
                chain_id: 6,
                max_freq_mhz: 200,
                reason: HaltReason::InsufficientHealthyChains,
            }
        );
    }

    #[test]
    fn board_reset_is_refused_without_safeoff_receipt() {
        let action = BadChipAction::BoardReset {
            chain_id: 6,
            attempt: 1,
        };
        assert_eq!(
            plan_bad_chip_actuation(&action, 485, 485, BAD_CHIP_ACTUATION_FLOOR_MHZ),
            BadChipActuation::Refuse {
                chain_id: 6,
                why: BadChipRefuseReason::BoardResetNeedsSafeOffReceipt,
            }
        );
    }

    #[test]
    fn chip_index_above_u8_is_refused() {
        let action = BadChipAction::PerChipDownclock {
            chain_id: 6,
            chip_index: 300,
            mhz_step: 25,
        };
        assert_eq!(
            plan_bad_chip_actuation(&action, 485, 485, BAD_CHIP_ACTUATION_FLOOR_MHZ),
            BadChipActuation::Refuse {
                chain_id: 6,
                why: BadChipRefuseReason::ChipIndexOutOfRange,
            }
        );
    }

    #[test]
    fn actuation_stays_disarmed_unless_both_flags() {
        assert!(!bad_chip_actuation_armed(false, false));
        assert!(!bad_chip_actuation_armed(true, false));
        assert!(!bad_chip_actuation_armed(false, true));
        assert!(bad_chip_actuation_armed(true, true));
    }

    #[test]
    fn noop_is_none() {
        assert_eq!(
            plan_bad_chip_actuation(&BadChipAction::NoOp, 485, 485, 200),
            BadChipActuation::None
        );
    }

    #[test]
    fn daemon_wires_shipped_actuation_policy() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let daemon_without_whitespace = daemon.split_whitespace().collect::<String>();
        assert!(
            daemon.contains("dcentrald_autotuner::plan_bad_chip_actuation_on_chain("),
            "daemon.rs must plan BadChipAction through the shipped actuation policy"
        );
        assert!(
            daemon.contains("dcentrald_autotuner::resolve_health_operating_mhz("),
            "daemon.rs must resolve expected-nonce MHz from live operating freq"
        );
        assert!(
            daemon.contains("dcentrald_autotuner::bad_chip_actuation_armed("),
            "daemon.rs must keep actuation behind the enabled+actuate gate"
        );
        assert!(
            daemon.contains("apply_bad_chip_actuation(&bad_chip_freq_tx, &planned);"),
            "daemon.rs must apply planned decrease-only intents on the freq channel"
        );
        assert!(
            daemon.contains("source: dcentrald_autotuner::FrequencyLimitSource::BadChip,"),
            "actuation must use the dedicated BadChip ceiling slot"
        );
        assert!(
            daemon.contains("dcentrald_autotuner::actuation_bases("),
            "daemon.rs must stack ReduceBoardProfile from the existing ceiling"
        );
        assert!(
            daemon.contains("supervisor.invalidate_after_downclock("),
            "daemon.rs must drop the rolling window after a downclock"
        );
        assert!(
            daemon_without_whitespace.contains("self.config.autotuner.enabled||bad_chip_enabled"),
            "snapshot stream must exist for health even when AM2 autotune is off"
        );
        assert!(
            daemon_without_whitespace.contains("letspawn_autotuner=self.config.autotuner.enabled"),
            "AM2 default must still refuse to spawn TABS when only health is on"
        );
        let start = daemon
            .find("fn apply_bad_chip_actuation")
            .expect("apply_bad_chip_actuation must exist");
        let body = &daemon[start..start + 1800];
        assert!(
            body.contains("BadChipActuation::Refuse"),
            "apply helper must ignore Refuse (BoardReset / out-of-range)"
        );
        assert!(
            !body.contains("SetVoltage"),
            "apply_bad_chip_actuation must not send SetVoltage"
        );
    }
}
