//! Composed pure policy for production multi-chain energize (decade strangler).
//!
//! # Why
//!
//! Engines historically ordered chain enable, work dispatch, and safety
//! admission ad-hoc. Two pure gates already exist:
//!
//! - [`crate::powerup_schedule`] — refuse simultaneous multi-chain inrush
//! - [`crate::work_dispatch_safety`] — refuse dispatch without watchdog +
//!   same-cycle heartbeat + thermal readiness
//!
//! This module **composes** them so a future engine wire cannot admit work
//! dispatch while still planning a burst power-up, or energize chains without
//! a dispatch safety receipt. HAL adapters remain responsible for sleeps and
//! GPIO/PMBus; this is schedule + admission only.
//!
//! # Status
//!
//! **Production pure composition.** Hybrid multi-PIC remaining-actives enable
//! (`DCENT_AM2_VOLTAGE_ENABLE_ALL_ACTIVE_PICS`, default-OFF) uses
//! [`plan_multi_chain_enable`]: Phase 3 typically lands
//! [`MultiChainEnableAuthority::PowerUpOnly`] (dispatch admit is Phase 10);
//! after green work-dispatch admit the same target set is re-planned and
//! expected to become [`MultiChainEnableAuthority::Composed`] (fail-closed if
//! production stagger refuses). Primary single-PIC cold-boot remains the
//! proven path.

use crate::powerup_schedule::{
    plan_production_enable_sequence, plan_production_powerup, PowerUpPolicyError, StaggerConfig,
};
use crate::work_dispatch_safety::{
    admit_work_dispatch, WorkDispatchAdmissionReceipt, WorkDispatchSafetyError,
    WorkDispatchSafetyInputs,
};

/// Ordered production energize plan ready for an adapter sleep/enable loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionMultiChainEnergizePlan {
    /// Inter-step delays: `(chain_id, sleep_ms_before_enable)`.
    pub chain_enable_delays: Vec<(u8, u32)>,
    /// Proof that work-dispatch safety pillars were green at plan time.
    pub dispatch_admission: WorkDispatchAdmissionReceipt,
}

/// Combined refuse reasons for the composed gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiningLifecycleError {
    PowerUp(PowerUpPolicyError),
    Dispatch(WorkDispatchSafetyError),
}

impl std::fmt::Display for MiningLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PowerUp(e) => write!(f, "mining lifecycle power-up: {e}"),
            Self::Dispatch(e) => write!(f, "mining lifecycle dispatch: {e}"),
        }
    }
}

impl std::error::Error for MiningLifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PowerUp(e) => Some(e),
            Self::Dispatch(e) => Some(e),
        }
    }
}

/// Admit work-dispatch safety **then** plan production multi-chain power-up.
///
/// Order is intentional: never schedule chain inrush when dispatch would
/// immediately be refused (or terminally revoked). Callers must still latch
/// terminal revoke after energize if a pillar fails mid-run.
///
/// `chain_enable_delays` uses step ids `0..chain_count`. For PIC-address
/// binding prefer [`plan_production_multi_chain_energize_for_targets`].
pub fn plan_production_multi_chain_energize(
    chain_count: u8,
    stagger: StaggerConfig,
    dispatch_inputs: &WorkDispatchSafetyInputs,
) -> Result<ProductionMultiChainEnergizePlan, MiningLifecycleError> {
    let dispatch_admission =
        admit_work_dispatch(dispatch_inputs).map_err(MiningLifecycleError::Dispatch)?;
    let chain_enable_delays =
        plan_production_powerup(chain_count, stagger).map_err(MiningLifecycleError::PowerUp)?;
    Ok(ProductionMultiChainEnergizePlan {
        chain_enable_delays,
        dispatch_admission,
    })
}

/// Admit work-dispatch safety **then** zip production delays onto ordered
/// enable targets (PIC addresses, logical chain ids, …).
///
/// Returns the admission receipt plus `(target, sleep_ms_before_enable)`.
/// Prefer this over open-coding admit + [`plan_production_enable_sequence`].
pub fn plan_production_multi_chain_energize_for_targets(
    targets: &[u8],
    stagger: StaggerConfig,
    dispatch_inputs: &WorkDispatchSafetyInputs,
) -> Result<(WorkDispatchAdmissionReceipt, Vec<(u8, u32)>), MiningLifecycleError> {
    let dispatch_admission =
        admit_work_dispatch(dispatch_inputs).map_err(MiningLifecycleError::Dispatch)?;
    let enable_sequence =
        plan_production_enable_sequence(targets, stagger).map_err(MiningLifecycleError::PowerUp)?;
    Ok((dispatch_admission, enable_sequence))
}

/// How a multi-chain enable sequence was authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiChainEnableAuthority {
    /// Dispatch pillars were green; schedule is compose-authorized.
    Composed {
        admission: WorkDispatchAdmissionReceipt,
    },
    /// Dispatch pillars were absent or refused; power-up stagger only.
    ///
    /// Engines that already latched work-dispatch elsewhere (or enable rails
    /// before Phase-10 admit) still must not simultaneous-burst.
    PowerUpOnly,
}

/// Fail-closed multi-chain enable plan for engine adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiChainEnablePlan {
    /// `(target, sleep_ms_before_enable)` for the sleep/enable loop.
    pub sequence: Vec<(u8, u32)>,
    /// Whether dispatch admission composed with the schedule.
    pub authority: MultiChainEnableAuthority,
}

/// Plan multi-chain enable with optional dispatch composition.
///
/// - When `dispatch_inputs` is `Some` **and** admit succeeds →
///   [`MultiChainEnableAuthority::Composed`] + enable sequence.
/// - When `dispatch_inputs` is `None` **or** admit fails (watchdog/HB/thermal) →
///   fall back to power-up-only stagger ([`MultiChainEnableAuthority::PowerUpOnly`]).
/// - When production stagger itself refuses (simultaneous multi-chain) →
///   **hard error** ([`PowerUpPolicyError`]) — never return an empty “ok” burst.
///
/// This is the decade-strangler entry for engines that may enable rails
/// before or after work-dispatch admission, without inventing pillars.
pub fn plan_multi_chain_enable(
    targets: &[u8],
    stagger: StaggerConfig,
    dispatch_inputs: Option<&WorkDispatchSafetyInputs>,
) -> Result<MultiChainEnablePlan, PowerUpPolicyError> {
    if let Some(inputs) = dispatch_inputs {
        match plan_production_multi_chain_energize_for_targets(targets, stagger, inputs) {
            Ok((admission, sequence)) => {
                return Ok(MultiChainEnablePlan {
                    sequence,
                    authority: MultiChainEnableAuthority::Composed { admission },
                });
            }
            Err(MiningLifecycleError::Dispatch(_)) => {
                // Pillars not green yet — stagger-only fallback below.
            }
            Err(MiningLifecycleError::PowerUp(e)) => return Err(e),
        }
    }
    let sequence = plan_production_enable_sequence(targets, stagger)?;
    Ok(MultiChainEnablePlan {
        sequence,
        authority: MultiChainEnableAuthority::PowerUpOnly,
    })
}

/// Production multi-PIC enable plan — **refuses empty target lists**.
///
/// Same composition as [`plan_multi_chain_enable`], but empty `targets` is
/// [`PowerUpPolicyError::EmptySchedule`] rather than an empty Ok sequence.
/// Engines that claim "enable all actives" must not silently no-op when the
/// active set is empty after discovery (P1-5 pure polish).
pub fn plan_production_multi_chain_enable(
    targets: &[u8],
    stagger: StaggerConfig,
    dispatch_inputs: Option<&WorkDispatchSafetyInputs>,
) -> Result<MultiChainEnablePlan, PowerUpPolicyError> {
    if targets.is_empty() {
        return Err(PowerUpPolicyError::EmptySchedule);
    }
    plan_multi_chain_enable(targets, stagger, dispatch_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work_dispatch_safety::{
        ControllerHeartbeatObservation, HeartbeatRequirement, ThermalSafetyState,
        WatchdogSafetyState,
    };

    fn green_dispatch() -> WorkDispatchSafetyInputs {
        WorkDispatchSafetyInputs {
            watchdog: WatchdogSafetyState::Armed,
            heartbeat_requirement: HeartbeatRequirement::AllControllersSameCycle,
            controllers: vec![ControllerHeartbeatObservation {
                controller_id: 0x20,
                heartbeat_ok: true,
                cycle_id: 1,
            }],
            thermal: ThermalSafetyState::Ready,
            previously_revoked: false,
        }
    }

    #[test]
    fn composed_plan_returns_bosminer_delays_when_dispatch_green() {
        let plan =
            plan_production_multi_chain_energize(3, StaggerConfig::default(), &green_dispatch())
                .expect("composed plan");
        assert_eq!(plan.chain_enable_delays, vec![(0, 0), (1, 250), (2, 250)]);
        assert_eq!(plan.dispatch_admission.controller_count, 1);
    }

    #[test]
    fn composed_plan_refuses_burst_even_when_dispatch_green() {
        let err = plan_production_multi_chain_energize(
            2,
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0,
            },
            &green_dispatch(),
        )
        .unwrap_err();
        assert!(matches!(err, MiningLifecycleError::PowerUp(_)));
    }

    #[test]
    fn composed_plan_refuses_dispatch_before_powerup_math() {
        let mut inputs = green_dispatch();
        inputs.watchdog = WatchdogSafetyState::NotPositivelyAdmitted;
        let err =
            plan_production_multi_chain_energize(3, StaggerConfig::default(), &inputs).unwrap_err();
        assert!(matches!(err, MiningLifecycleError::Dispatch(_)));
    }

    #[test]
    fn terminal_revoke_blocks_composed_plan() {
        let mut inputs = green_dispatch();
        inputs.previously_revoked = true;
        assert!(matches!(
            plan_production_multi_chain_energize(1, StaggerConfig::default(), &inputs),
            Err(MiningLifecycleError::Dispatch(_))
        ));
    }

    #[test]
    fn composed_for_targets_preserves_pic_order_and_admits() {
        let targets = [0x22u8, 0x20];
        let (admission, seq) = plan_production_multi_chain_energize_for_targets(
            &targets,
            StaggerConfig::default(),
            &green_dispatch(),
        )
        .expect("composed target plan");
        assert_eq!(admission.controller_count, 1);
        assert_eq!(
            seq,
            vec![
                (0x22, 0),
                (0x20, crate::powerup_schedule::DEFAULT_CHAIN_STAGGER_MS)
            ]
        );
    }

    #[test]
    fn composed_for_targets_refuses_dispatch_before_powerup() {
        let mut inputs = green_dispatch();
        inputs.thermal = ThermalSafetyState::NotReady;
        let err = plan_production_multi_chain_energize_for_targets(
            &[0x20, 0x21],
            StaggerConfig::default(),
            &inputs,
        )
        .unwrap_err();
        assert!(matches!(err, MiningLifecycleError::Dispatch(_)));
    }

    #[test]
    fn composed_for_targets_refuses_burst() {
        let err = plan_production_multi_chain_energize_for_targets(
            &[0x20, 0x21],
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0,
            },
            &green_dispatch(),
        )
        .unwrap_err();
        assert!(matches!(err, MiningLifecycleError::PowerUp(_)));
    }

    #[test]
    fn plan_multi_chain_enable_composes_when_dispatch_green() {
        let plan = plan_multi_chain_enable(
            &[0x22, 0x20],
            StaggerConfig::default(),
            Some(&green_dispatch()),
        )
        .expect("plan");
        assert!(matches!(
            plan.authority,
            MultiChainEnableAuthority::Composed { .. }
        ));
        assert_eq!(
            plan.sequence,
            vec![
                (0x22, 0),
                (0x20, crate::powerup_schedule::DEFAULT_CHAIN_STAGGER_MS)
            ]
        );
    }

    #[test]
    fn plan_multi_chain_enable_powerup_only_when_dispatch_absent() {
        let plan =
            plan_multi_chain_enable(&[0x20, 0x21], StaggerConfig::default(), None).expect("plan");
        assert_eq!(plan.authority, MultiChainEnableAuthority::PowerUpOnly);
        assert_eq!(plan.sequence.len(), 2);
        assert_eq!(
            plan.sequence[1].1,
            crate::powerup_schedule::DEFAULT_CHAIN_STAGGER_MS
        );
    }

    #[test]
    fn plan_multi_chain_enable_powerup_only_when_dispatch_refuses() {
        let mut inputs = green_dispatch();
        inputs.thermal = ThermalSafetyState::NotReady;
        let plan = plan_multi_chain_enable(&[0x20, 0x21], StaggerConfig::default(), Some(&inputs))
            .expect("stagger still planned");
        assert_eq!(plan.authority, MultiChainEnableAuthority::PowerUpOnly);
        assert_eq!(plan.sequence.len(), 2);
    }

    #[test]
    fn plan_production_multi_chain_enable_refuses_empty_targets() {
        // Lab/helper plan_multi_chain_enable may return empty Ok; production façade must not.
        let empty_ok =
            plan_multi_chain_enable(&[], StaggerConfig::default(), None).expect("empty ok");
        assert!(empty_ok.sequence.is_empty());
        let err = plan_production_multi_chain_enable(&[], StaggerConfig::default(), None)
            .expect_err("production empty refuse");
        assert!(matches!(err, PowerUpPolicyError::EmptySchedule));
    }

    #[test]
    fn plan_production_multi_chain_enable_composes_nonempty() {
        let plan = plan_production_multi_chain_enable(
            &[0x22, 0x20],
            StaggerConfig::default(),
            Some(&green_dispatch()),
        )
        .expect("production plan");
        assert!(matches!(
            plan.authority,
            MultiChainEnableAuthority::Composed { .. }
        ));
        assert_eq!(plan.sequence.len(), 2);
    }

    #[test]
    fn plan_multi_chain_enable_hard_refuses_simultaneous_burst() {
        let err = plan_multi_chain_enable(
            &[0x20, 0x21],
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0,
            },
            Some(&green_dispatch()),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PowerUpPolicyError::SimultaneousMultiChain { .. }
        ));
        // Also refuse when dispatch is absent — never silent burst.
        let err2 = plan_multi_chain_enable(
            &[0x20, 0x21],
            StaggerConfig {
                stagger_ms: 0,
                psu_warmup_ms: 0,
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err2,
            PowerUpPolicyError::SimultaneousMultiChain { .. }
        ));
    }
}
