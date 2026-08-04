//! Multi-chain power-up schedule policy (decade backlog P1-5 companion).
//!
//! # Why
//!
//! Simultaneous multi-chain enable creates inrush that can brown out dsPIC
//! controllers into fw=0x86 and trip APW overcurrent. Bosminer staggers chain
//! enable by ~250 ms. The pure planner lives in
//! `dcentrald_silicon_profiles::staggered_powerup::plan_powerup`; this module
//! owns the **policy language** adapters must speak before they call enable:
//!
//! - refuse zero-stagger multi-chain energize on production/home paths
//! - convert absolute `at_ms` schedules into inter-step sleep deltas
//! - provide a single fail-closed gate for "is this schedule safe to run?"
//!
//! # Status
//!
//! **Production pure policy** for multi-chain enable paths. The silicon
//! planner remains the schedule source of truth for the 250 ms cadence; this
//! crate stays HAL-free and does not depend on silicon-profiles so Windows
//! host tests stay leaf-fast. Hybrid multi-PIC voltage enable (default-OFF
//! `all_active_voltage_enable`) calls [`plan_production_powerup`] for remaining
//! actives (P1-5, 2026-07-29). Broader primary-path multi-chain orchestrator
//! wire remains a strangler residual; this module makes silent simultaneous
//! enable a typed refuse rather than an accident.

/// Default bosminer-observed inter-chain stagger (milliseconds).
pub const DEFAULT_CHAIN_STAGGER_MS: u32 = 250;

/// Minimum production stagger between consecutive chain enables (ms).
///
/// Below this, multi-chain enable is treated as a simultaneous burst risk.
pub const MIN_PRODUCTION_STAGGER_MS: u32 = 100;

/// One absolute-time step (mirrors silicon-profiles `PowerUpStep` shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerUpStep {
    /// Offset from schedule start at which this chain is enabled.
    pub at_ms: u32,
    /// Zero-based chain id.
    pub chain_id: u8,
}

/// Planner configuration (mirrors silicon-profiles `StaggerConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaggerConfig {
    pub stagger_ms: u32,
    pub psu_warmup_ms: u32,
}

impl Default for StaggerConfig {
    fn default() -> Self {
        Self {
            stagger_ms: DEFAULT_CHAIN_STAGGER_MS,
            psu_warmup_ms: 0,
        }
    }
}

/// Why a schedule is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerUpPolicyError {
    /// Multi-chain enable with stagger below production minimum.
    SimultaneousMultiChain {
        chain_count: u8,
        stagger_ms: u32,
        min_required_ms: u32,
    },
    /// Adjacent steps closer than the required gap.
    InsufficientGap {
        earlier_chain: u8,
        later_chain: u8,
        gap_ms: u32,
        min_gap_ms: u32,
    },
    /// Empty schedule when at least one chain was expected.
    EmptySchedule,
}

impl std::fmt::Display for PowerUpPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimultaneousMultiChain {
                chain_count,
                stagger_ms,
                min_required_ms,
            } => write!(
                f,
                "refusing simultaneous multi-chain power-up: {chain_count} chains with stagger_ms={stagger_ms} (min {min_required_ms})"
            ),
            Self::InsufficientGap {
                earlier_chain,
                later_chain,
                gap_ms,
                min_gap_ms,
            } => write!(
                f,
                "stagger gap between chain {earlier_chain} and {later_chain} is {gap_ms}ms, below minimum {min_gap_ms}ms"
            ),
            Self::EmptySchedule => write!(f, "power-up schedule is empty"),
        }
    }
}

impl std::error::Error for PowerUpPolicyError {}

/// Build an absolute schedule (identical cadence contract to silicon-profiles).
pub fn plan_powerup(chain_count: u8, config: StaggerConfig) -> Vec<PowerUpStep> {
    if chain_count == 0 {
        return Vec::new();
    }
    (0..chain_count)
        .map(|chain_id| PowerUpStep {
            at_ms: config
                .psu_warmup_ms
                .saturating_add(config.stagger_ms.saturating_mul(chain_id as u32)),
            chain_id,
        })
        .collect()
}

/// Total schedule duration including the last chain's settling window
/// (one extra `stagger_ms` past the last enable). SSOT for silicon-profiles.
pub fn schedule_duration_ms(chain_count: u8, config: StaggerConfig) -> u32 {
    if chain_count == 0 {
        return 0;
    }
    config
        .psu_warmup_ms
        .saturating_add(config.stagger_ms.saturating_mul(chain_count as u32))
}

/// Convert absolute `at_ms` steps into per-step sleep-before-enable deltas.
///
/// First step sleeps `steps[0].at_ms`; each later step sleeps the delta from
/// the previous step's `at_ms`. Adapters `sleep(delta)` then `enable(chain)`.
pub fn inter_step_delays_ms(steps: &[PowerUpStep]) -> Vec<(u8, u32)> {
    let mut out = Vec::with_capacity(steps.len());
    let mut prev_at = 0u32;
    for (i, step) in steps.iter().enumerate() {
        let delay = if i == 0 {
            step.at_ms
        } else {
            step.at_ms.saturating_sub(prev_at)
        };
        out.push((step.chain_id, delay));
        prev_at = step.at_ms;
    }
    out
}

/// Fail-closed production gate: multi-chain requires adequate stagger.
///
/// Single-chain and empty schedules always pass (empty is handled by
/// [`require_nonempty`] if needed). Zero-stagger multi-chain is refused.
pub fn validate_production_stagger(
    chain_count: u8,
    config: StaggerConfig,
) -> Result<(), PowerUpPolicyError> {
    if chain_count > 1 && config.stagger_ms < MIN_PRODUCTION_STAGGER_MS {
        return Err(PowerUpPolicyError::SimultaneousMultiChain {
            chain_count,
            stagger_ms: config.stagger_ms,
            min_required_ms: MIN_PRODUCTION_STAGGER_MS,
        });
    }
    Ok(())
}

/// Validate an absolute schedule against a minimum adjacent gap.
// clippy::indexing_slicing: iterating `steps.windows(2)`, so every `window` has
// exactly 2 elements and `[0]`/`[1]` cannot be out of range.
#[allow(clippy::indexing_slicing)]
pub fn validate_schedule_gaps(
    steps: &[PowerUpStep],
    min_gap_ms: u32,
) -> Result<(), PowerUpPolicyError> {
    if steps.len() < 2 {
        return Ok(());
    }
    for window in steps.windows(2) {
        let gap = window[1].at_ms.saturating_sub(window[0].at_ms);
        if gap < min_gap_ms {
            return Err(PowerUpPolicyError::InsufficientGap {
                earlier_chain: window[0].chain_id,
                later_chain: window[1].chain_id,
                gap_ms: gap,
                min_gap_ms,
            });
        }
    }
    Ok(())
}

/// Refuse empty schedules when the caller expected chains.
pub fn require_nonempty(steps: &[PowerUpStep]) -> Result<(), PowerUpPolicyError> {
    if steps.is_empty() {
        Err(PowerUpPolicyError::EmptySchedule)
    } else {
        Ok(())
    }
}

/// Plan + validate a production multi-chain schedule in one step.
///
/// Returns inter-step delays ready for an adapter sleep/enable loop.
/// Each entry is `(step_chain_id, sleep_ms_before_enable)` where
/// `step_chain_id` is `0..chain_count` (not a PIC I²C address).
pub fn plan_production_powerup(
    chain_count: u8,
    config: StaggerConfig,
) -> Result<Vec<(u8, u32)>, PowerUpPolicyError> {
    validate_production_stagger(chain_count, config)?;
    let steps = plan_powerup(chain_count, config);
    if chain_count > 0 {
        require_nonempty(&steps)?;
        if chain_count > 1 {
            validate_schedule_gaps(&steps, MIN_PRODUCTION_STAGGER_MS.min(config.stagger_ms))?;
        }
    }
    Ok(inter_step_delays_ms(&steps))
}

/// Zip ordered enable **targets** (PIC addresses, chain indices, …) with
/// production inter-step delays.
///
/// Returns `(target, sleep_ms_before_enable)` for adapter sleep/enable loops:
///
/// ```ignore
/// for (addr, delay_ms) in plan_production_enable_sequence(&addrs, cfg)? {
///     if delay_ms > 0 { sleep(delay_ms); }
///     enable(addr);
/// }
/// ```
///
/// Fail-closed: multi-target zero-stagger is refused via
/// [`plan_production_powerup`]. Empty `targets` returns an empty schedule.
pub fn plan_production_enable_sequence(
    targets: &[u8],
    config: StaggerConfig,
) -> Result<Vec<(u8, u32)>, PowerUpPolicyError> {
    if targets.len() > u8::MAX as usize {
        // Unreachable for real hashboard topologies (≤3 chains); keep typed.
        return Err(PowerUpPolicyError::SimultaneousMultiChain {
            chain_count: u8::MAX,
            stagger_ms: config.stagger_ms,
            min_required_ms: MIN_PRODUCTION_STAGGER_MS,
        });
    }
    let delays = plan_production_powerup(targets.len() as u8, config)?;
    Ok(delays
        .into_iter()
        .zip(targets.iter().copied())
        .map(|((_step_id, delay_ms), target)| (target, delay_ms))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_three_chain_matches_bosminer_cadence() {
        let steps = plan_powerup(3, StaggerConfig::default());
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
    fn inter_step_delays_are_deltas() {
        let steps = plan_powerup(
            3,
            StaggerConfig {
                stagger_ms: 250,
                psu_warmup_ms: 500,
            },
        );
        assert_eq!(
            inter_step_delays_ms(&steps),
            vec![(0, 500), (1, 250), (2, 250)]
        );
    }

    #[test]
    fn production_refuses_zero_stagger_multi_chain() {
        let err = validate_production_stagger(
            3,
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PowerUpPolicyError::SimultaneousMultiChain { chain_count: 3, .. }
        ));
    }

    #[test]
    fn production_allows_single_chain_zero_stagger() {
        assert!(validate_production_stagger(
            1,
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0
            }
        )
        .is_ok());
    }

    #[test]
    fn plan_production_powerup_happy_path() {
        let delays = plan_production_powerup(3, StaggerConfig::default()).unwrap();
        assert_eq!(delays, vec![(0, 0), (1, 250), (2, 250)]);
    }

    /// Adapter contract: delays zip 1:1 with ordered enable targets.
    /// Engines sleep `delay_ms` then enable the address at that index.
    #[test]
    fn production_delays_zip_with_ordered_enable_targets() {
        let targets = [0x20u8, 0x21, 0x22];
        let delays = plan_production_powerup(targets.len() as u8, StaggerConfig::default())
            .expect("three-chain production plan");
        assert_eq!(delays.len(), targets.len());
        let mut enable_order = Vec::new();
        for ((step_id, delay_ms), &addr) in delays.iter().zip(targets.iter()) {
            assert_eq!(*step_id as usize, enable_order.len());
            // Document the sleep-then-enable loop engines must follow.
            let _sleep_before_enable = *delay_ms;
            enable_order.push(addr);
        }
        assert_eq!(enable_order, targets);
        assert_eq!(delays[0].1, 0);
        assert_eq!(delays[1].1, DEFAULT_CHAIN_STAGGER_MS);
        assert_eq!(delays[2].1, DEFAULT_CHAIN_STAGGER_MS);
    }

    #[test]
    fn plan_production_enable_sequence_binds_targets_not_step_ids() {
        let targets = [0x22u8, 0x20, 0x21];
        let seq = plan_production_enable_sequence(&targets, StaggerConfig::default())
            .expect("enable sequence");
        // Targets preserved in call order (not sorted / renumbered).
        assert_eq!(
            seq,
            vec![
                (0x22, 0),
                (0x20, DEFAULT_CHAIN_STAGGER_MS),
                (0x21, DEFAULT_CHAIN_STAGGER_MS),
            ]
        );
    }

    #[test]
    fn plan_production_enable_sequence_refuses_burst_multi_target() {
        let err = plan_production_enable_sequence(
            &[0x20, 0x21],
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PowerUpPolicyError::SimultaneousMultiChain { chain_count: 2, .. }
        ));
    }

    #[test]
    fn plan_production_enable_sequence_empty_is_ok() {
        assert_eq!(
            plan_production_enable_sequence(&[], StaggerConfig::default()).unwrap(),
            Vec::<(u8, u32)>::new()
        );
    }

    #[test]
    fn plan_production_powerup_refuses_burst() {
        assert!(plan_production_powerup(
            2,
            StaggerConfig {
                stagger_ms: 50,
                psu_warmup_ms: 0
            }
        )
        .is_err());
    }

    #[test]
    fn require_nonempty_fails_on_empty() {
        assert!(require_nonempty(&[]).is_err());
    }

    /// Cadence contract pin vs silicon-profiles `staggered_powerup` defaults.
    ///
    /// Engines may consume either planner; absolute schedules must stay identical
    /// so a future wire into mining paths cannot fork the brownout policy.
    #[test]
    fn absolute_schedule_matches_silicon_profiles_bosminer_contract() {
        // silicon-profiles::plan_powerup(3, default) is pinned at 0/250/500 ms.
        let steps = plan_powerup(3, StaggerConfig::default());
        assert_eq!(steps[0].at_ms, 0);
        assert_eq!(steps[1].at_ms, DEFAULT_CHAIN_STAGGER_MS);
        assert_eq!(steps[2].at_ms, DEFAULT_CHAIN_STAGGER_MS * 2);
        assert_eq!(DEFAULT_CHAIN_STAGGER_MS, 250);
        assert_eq!(MIN_PRODUCTION_STAGGER_MS, 100);
    }

    #[test]
    fn schedule_duration_includes_settling_window() {
        assert_eq!(schedule_duration_ms(0, StaggerConfig::default()), 0);
        assert_eq!(schedule_duration_ms(3, StaggerConfig::default()), 750);
        assert_eq!(
            schedule_duration_ms(
                3,
                StaggerConfig {
                    stagger_ms: 250,
                    psu_warmup_ms: 500
                }
            ),
            1250
        );
    }
}
