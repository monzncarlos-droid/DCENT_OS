//!  tune-C — staggered chain power-up planner (HAL-free).
//!
//! Source RE evidence:
//! Phase 13D Ghidra RE of bosminer's `Apw121215a::cold_boot_sequence` and
//! `Phase 14 PSU GPIO gate` analysis.
//!
//! When a multi-chain miner cold-boots, all chains powering up
//! simultaneously creates a current spike that can:
//! - Trip the PSU's overcurrent protection (we've seen APW121215a EIO on
//!   the first PMBus write in this scenario).
//! - Brown out the dsPIC controllers, leaving them in fw=0x86 corruption state.
//! - Trigger thermal protection on the bus tap before the dsPIC can read
//!   APW telemetry.
//!
//! Bosminer's flow staggers chain enable by ~250 ms. This module plans the
//! sequence as a pure list of `(chain_id, delay_ms)` pairs that the runtime
//! adapter executes via the platform's GPIO/PMBus HAL.
//!
//! # SSOT (Constitution offline cycle 2026-07-22)
//!
//! Absolute schedule math, production refuse, and inter-step deltas live in
//! [`dcentrald_common::powerup_schedule`]. This module is a **serde-bearing
//! façade** so profile/export call sites keep `Serialize` steps without
//! forking the brownout policy. Prefer
//! [`dcentrald_common::plan_production_powerup`] or
//! [`plan_production_powerup`] at energize call sites.

use serde::{Deserialize, Serialize};

/// One step in the power-up sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerUpStep {
    /// Wall-clock millisecond offset from the start of the sequence at
    /// which this chain's power should be enabled. The first chain has
    /// `at_ms = 0`.
    pub at_ms: u32,
    /// Zero-indexed chain identifier (0, 1, 2 for a 3-chain miner).
    pub chain_id: u8,
}

/// Configuration for the planner.
#[derive(Debug, Clone, Copy)]
pub struct StaggerConfig {
    /// Delay between consecutive chain enables.
    pub stagger_ms: u32,
    /// Optional fixed warmup before the first chain enable. Bosminer
    /// uses this to allow the APW PSU to stabilize after PWR_CONTROL
    /// is asserted but before any chain begins drawing current.
    pub psu_warmup_ms: u32,
}

impl Default for StaggerConfig {
    fn default() -> Self {
        Self {
            stagger_ms: dcentrald_common::DEFAULT_CHAIN_STAGGER_MS,
            psu_warmup_ms: 0,
        }
    }
}

impl From<StaggerConfig> for dcentrald_common::StaggerConfig {
    fn from(c: StaggerConfig) -> Self {
        Self {
            stagger_ms: c.stagger_ms,
            psu_warmup_ms: c.psu_warmup_ms,
        }
    }
}

impl From<dcentrald_common::PowerUpStep> for PowerUpStep {
    fn from(s: dcentrald_common::PowerUpStep) -> Self {
        Self {
            at_ms: s.at_ms,
            chain_id: s.chain_id,
        }
    }
}

/// Build a stagger schedule for `chain_count` chains.
///
/// Returns a `Vec<PowerUpStep>` of length `chain_count`. Chain 0 is enabled
/// first at `psu_warmup_ms`, chain 1 at `psu_warmup_ms + stagger_ms`, etc.
///
/// `chain_count` of 0 returns an empty schedule. `stagger_ms = 0` collapses
/// to a single-step burst (all chains at `psu_warmup_ms`). Production paths
/// must not use zero stagger for multi-chain — use [`plan_production_powerup`].
pub fn plan_powerup(chain_count: u8, config: StaggerConfig) -> Vec<PowerUpStep> {
    dcentrald_common::plan_powerup(chain_count, config.into())
        .into_iter()
        .map(PowerUpStep::from)
        .collect()
}

/// Total schedule duration including the last chain's settling time
/// (defaults to one extra `stagger_ms` past the last enable).
pub fn schedule_duration_ms(chain_count: u8, config: StaggerConfig) -> u32 {
    dcentrald_common::schedule_duration_ms(chain_count, config.into())
}

/// Verify that two consecutive steps' delta meets a minimum spacing
/// requirement. Caller can use this as a pre-flight assertion when
/// loading a schedule from config.
pub fn validate_minimum_spacing(steps: &[PowerUpStep], min_gap_ms: u32) -> Result<(), String> {
    let common_steps: Vec<dcentrald_common::PowerUpStep> = steps
        .iter()
        .map(|s| dcentrald_common::PowerUpStep {
            at_ms: s.at_ms,
            chain_id: s.chain_id,
        })
        .collect();
    dcentrald_common::validate_schedule_gaps(&common_steps, min_gap_ms).map_err(|e| e.to_string())
}

/// Production multi-chain plan: refuse simultaneous burst, return sleep/enable deltas.
///
/// Thin façade over [`dcentrald_common::plan_production_powerup`] so engines that
/// already depend on silicon-profiles get the fail-closed gate without a second
/// import path forking policy.
pub fn plan_production_powerup(
    chain_count: u8,
    config: StaggerConfig,
) -> Result<Vec<(u8, u32)>, dcentrald_common::PowerUpPolicyError> {
    dcentrald_common::plan_production_powerup(chain_count, config.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_bosminer_cadence() {
        // Phase 13D RE: 250 ms stagger between chains.
        let cfg = StaggerConfig::default();
        assert_eq!(cfg.stagger_ms, 250);
        assert_eq!(cfg.stagger_ms, dcentrald_common::DEFAULT_CHAIN_STAGGER_MS);
    }

    #[test]
    fn three_chains_default_stagger_yields_0_250_500() {
        let steps = plan_powerup(3, StaggerConfig::default());
        assert_eq!(steps.len(), 3);
        assert_eq!(
            steps,
            vec![
                PowerUpStep {
                    at_ms: 0,
                    chain_id: 0
                },
                PowerUpStep {
                    at_ms: 250,
                    chain_id: 1
                },
                PowerUpStep {
                    at_ms: 500,
                    chain_id: 2
                },
            ]
        );
    }

    #[test]
    fn psu_warmup_shifts_entire_schedule() {
        let steps = plan_powerup(
            3,
            StaggerConfig {
                psu_warmup_ms: 500,
                stagger_ms: 250,
            },
        );
        assert_eq!(steps[0].at_ms, 500);
        assert_eq!(steps[1].at_ms, 750);
        assert_eq!(steps[2].at_ms, 1000);
    }

    #[test]
    fn zero_chain_count_yields_empty_schedule() {
        let steps = plan_powerup(0, StaggerConfig::default());
        assert!(steps.is_empty());
        assert_eq!(schedule_duration_ms(0, StaggerConfig::default()), 0);
    }

    #[test]
    fn zero_stagger_collapses_to_burst() {
        let steps = plan_powerup(
            3,
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 100,
            },
        );
        // All chains at the same offset.
        assert!(steps.iter().all(|s| s.at_ms == 100));
        assert_eq!(steps.len(), 3);
    }

    #[test]
    fn schedule_duration_includes_settling_window() {
        let cfg = StaggerConfig::default();
        // 3 chains: last enable at 500 ms; duration = 750 ms
        // (psu_warmup 0 + 3*250).
        assert_eq!(schedule_duration_ms(3, cfg), 750);
        // 4 chains: last enable at 750 ms; duration = 1000 ms.
        assert_eq!(schedule_duration_ms(4, cfg), 1000);
    }

    #[test]
    fn validate_minimum_spacing_passes_default() {
        let steps = plan_powerup(4, StaggerConfig::default());
        assert!(validate_minimum_spacing(&steps, 200).is_ok());
    }

    #[test]
    fn validate_minimum_spacing_fails_too_tight() {
        let steps = plan_powerup(
            3,
            StaggerConfig {
                stagger_ms: 100,
                psu_warmup_ms: 0,
            },
        );
        let err = validate_minimum_spacing(&steps, 200).unwrap_err();
        // Exact text, not an `|| contains("100")` escape hatch. A weakened OR
        // arm is unconditionally satisfied by the first arm's own substring and
        // would silently accept a reworded brownout error.
        //
        // The two substrings asserted below ARE preserved across delegation to
        // `dcentrald_common::PowerUpPolicyError::InsufficientGap`, but the full
        // message is NOT byte-identical to the pre-delegation one: the literal
        // `chain ` before the second id was dropped
        // (`powerup_schedule.rs:95` renders `...between chain 0 and 1 is...`,
        // where the old local format produced `...between chain 0 and chain 1
        // is...`). So do NOT tighten this to `assert_eq!` on the whole message
        // or add a `contains("and chain ")` arm — either would fail.
        assert!(err.contains("100ms"), "unexpected gap error text: {err}");
        assert!(
            err.contains("below minimum 200ms"),
            "unexpected minimum text: {err}"
        );
    }

    #[test]
    fn validate_minimum_spacing_passes_for_single_chain() {
        // No pairs to compare → trivially OK.
        let steps = plan_powerup(1, StaggerConfig::default());
        assert!(validate_minimum_spacing(&steps, 1_000_000).is_ok());
    }

    #[test]
    fn validate_minimum_spacing_passes_for_empty() {
        assert!(validate_minimum_spacing(&[], 100).is_ok());
    }

    #[test]
    fn saturating_arithmetic_does_not_overflow() {
        // u32::MAX warmup + huge stagger should saturate, not panic.
        let cfg = StaggerConfig {
            stagger_ms: u32::MAX,
            psu_warmup_ms: u32::MAX,
        };
        let steps = plan_powerup(3, cfg);
        // No panic; values clamp to u32::MAX.
        assert_eq!(steps[0].at_ms, u32::MAX);
        assert_eq!(steps[1].at_ms, u32::MAX);
        assert_eq!(steps[2].at_ms, u32::MAX);
    }

    #[test]
    fn production_facade_refuses_burst_and_matches_common() {
        assert!(plan_production_powerup(
            2,
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0
            }
        )
        .is_err());
        let delays = plan_production_powerup(3, StaggerConfig::default()).unwrap();
        assert_eq!(
            delays,
            dcentrald_common::plan_production_powerup(
                3,
                dcentrald_common::StaggerConfig::default()
            )
            .unwrap()
        );
    }
}
