//! Work-dispatch safety admission — pure NO-SHIP contract (offline).
//!
//! # Why
//!
//! Runtime mining engines historically could start work dispatch before the
//! hardware watchdog was positively armed, before every required controller
//! reported a same-cycle heartbeat, or while thermal custody was not ready.
//! That class of ordering bug is a permanent safety debt: a late recovery of
//! one signal must never silently re-admit an old dispatcher lifecycle.
//!
//! This module is the **policy language** for that gate. It is HAL-free and
//! engine-free so host tests pin the refuse/revoke matrix without owning the
//! concurrent daemon/hybrid/serial worktrees. Adapters (daemon, hybrid, stock)
//! must call [`admit_work_dispatch`] before energizing standard work dispatch
//! and must treat [`revoke_work_dispatch`] as **terminal** for the current
//! lifecycle (fresh admission required after teardown).
//!
//! # Status
//!
//! **Production pure policy.** Engine wiring remains a strangler residual when
//! those files are free of concurrent ownership collision. Prefer this over
//! inventing a second admission matrix in each engine.
//!
//! Continuous-audit residual (2026-07-22): gate standard work dispatch on
//! positive watchdog + all-controller same-cycle heartbeat + thermal readiness;
//! terminally revoke dispatch and watchdog feeding on heartbeat/cutoff failure.

use crate::safety_command::{FanCommand, PowerCut, PowerCutReason, SafetyAction};

/// Watchdog contribution to work-dispatch admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogSafetyState {
    /// Descriptor armed and kick path admitted for this lifecycle.
    Armed,
    /// Operator/config explicitly disabled the hardware watchdog.
    DisabledByConfiguration,
    /// Open may have succeeded but arm was not positively observed.
    NotPositivelyAdmitted,
    /// Device unavailable / open failed before arm.
    Unavailable,
}

/// Thermal supervision contribution to work-dispatch admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalSafetyState {
    /// Thermal loop ready to supervise hashing.
    Ready,
    /// Not yet ready (init / sensors missing / cold start).
    NotReady,
    /// Emergency / cutoff already asserted.
    Emergency,
}

/// Classify a fresh process generation from a real pre-energize temperature
/// observation.
///
/// A new in-memory emergency latch is not evidence that hardware cooled across
/// a watchdog reset. Admission therefore requires one finite measurement below
/// the same `dangerous - hysteresis` boundary used by the thermal controller's
/// cooldown transition. Missing or merely cooled-to-the-boundary evidence stays
/// [`ThermalSafetyState::NotReady`]; a reading at/above the emergency threshold
/// is [`ThermalSafetyState::Emergency`].
pub fn measured_startup_thermal_state(
    measured_temp_c: Option<f32>,
    dangerous_temp_c: u8,
    hysteresis_c: u8,
) -> ThermalSafetyState {
    let Some(measured_temp_c) = measured_temp_c.filter(|temp| temp.is_finite()) else {
        return ThermalSafetyState::NotReady;
    };
    let dangerous = f32::from(dangerous_temp_c);
    if measured_temp_c >= dangerous {
        return ThermalSafetyState::Emergency;
    }
    let recovery_boundary = dangerous - f32::from(hysteresis_c);
    if measured_temp_c < recovery_boundary {
        ThermalSafetyState::Ready
    } else {
        ThermalSafetyState::NotReady
    }
}

/// How controller heartbeats participate in admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatRequirement {
    /// Path has no voltage controllers to heartbeat (explicit opt-out).
    NoneRequired,
    /// At least one controller observation; every observation must be ok and
    /// share one `cycle_id` (same observation cycle).
    AllControllersSameCycle,
}

/// One controller's heartbeat sample in a single observation cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerHeartbeatObservation {
    /// Stable controller identity (I²C addr, slot index, etc.).
    pub controller_id: u8,
    /// Whether this controller's heartbeat succeeded this cycle.
    pub heartbeat_ok: bool,
    /// Monotonic observation cycle. All admitted samples must match.
    pub cycle_id: u64,
}

/// Snapshot of safety inputs for one admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDispatchSafetyInputs {
    pub watchdog: WatchdogSafetyState,
    pub heartbeat_requirement: HeartbeatRequirement,
    pub controllers: Vec<ControllerHeartbeatObservation>,
    pub thermal: ThermalSafetyState,
    /// Once true for a lifecycle, only a new lifecycle (fresh inputs with
    /// `previously_revoked = false` after full teardown) may admit again.
    pub previously_revoked: bool,
}

/// Why work dispatch was refused or revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkDispatchSafetyError {
    TerminallyRevoked,
    WatchdogNotAdmitted {
        state: WatchdogSafetyState,
    },
    ThermalNotReady {
        state: ThermalSafetyState,
    },
    NoControllerObservations,
    HeartbeatFailed {
        controller_id: u8,
        cycle_id: u64,
    },
    HeartbeatCycleMismatch {
        expected_cycle: u64,
        observed_cycle: u64,
        controller_id: u8,
    },
}

impl std::fmt::Display for WorkDispatchSafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TerminallyRevoked => write!(
                f,
                "work dispatch terminally revoked for this lifecycle; require fresh admission"
            ),
            Self::WatchdogNotAdmitted { state } => {
                write!(f, "work dispatch refused: watchdog not positively admitted ({state:?})")
            }
            Self::ThermalNotReady { state } => {
                write!(f, "work dispatch refused: thermal not ready ({state:?})")
            }
            Self::NoControllerObservations => write!(
                f,
                "work dispatch refused: heartbeat required but no controller observations"
            ),
            Self::HeartbeatFailed {
                controller_id,
                cycle_id,
            } => write!(
                f,
                "work dispatch refused: controller 0x{controller_id:02x} heartbeat failed in cycle {cycle_id}"
            ),
            Self::HeartbeatCycleMismatch {
                expected_cycle,
                observed_cycle,
                controller_id,
            } => write!(
                f,
                "work dispatch refused: controller 0x{controller_id:02x} cycle {observed_cycle} != expected {expected_cycle}"
            ),
        }
    }
}

impl std::error::Error for WorkDispatchSafetyError {}

/// Proof that [`admit_work_dispatch`] succeeded for one lifecycle snapshot.
///
/// Opaque to engines except for logging/forensics fields. Not a capability
/// token across process restarts — pure policy receipt only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDispatchAdmissionReceipt {
    pub watchdog: WatchdogSafetyState,
    pub thermal: ThermalSafetyState,
    pub controller_count: usize,
    pub heartbeat_cycle_id: Option<u64>,
}

/// Cause of terminal work-dispatch revocation after prior admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchRevocationCause {
    WatchdogLost,
    HeartbeatFailure,
    ThermalCutoff,
    OperatorSafeOff,
}

/// Whether watchdog feed must stop when this cause fires.
pub fn revocation_stops_watchdog_feed(cause: DispatchRevocationCause) -> bool {
    match cause {
        // Lost arm / feed path must not keep kicking a dead contract.
        DispatchRevocationCause::WatchdogLost => true,
        // Heartbeat/thermal failures still cut hash; keep feed only if the
        // arm is still valid — policy still *allows* feed stop so engines can
        // choose terminal disarm. Default: stop feed to fail closed.
        DispatchRevocationCause::HeartbeatFailure => true,
        DispatchRevocationCause::ThermalCutoff => true,
        DispatchRevocationCause::OperatorSafeOff => true,
    }
}

/// Admit standard work dispatch only when every safety pillar is green.
// clippy::indexing_slicing: `controllers[0]` is reached only under the
// `controllers.is_empty()` early-return directly above it.
#[allow(clippy::indexing_slicing)]
pub fn admit_work_dispatch(
    inputs: &WorkDispatchSafetyInputs,
) -> Result<WorkDispatchAdmissionReceipt, WorkDispatchSafetyError> {
    if inputs.previously_revoked {
        return Err(WorkDispatchSafetyError::TerminallyRevoked);
    }

    match inputs.watchdog {
        WatchdogSafetyState::Armed | WatchdogSafetyState::DisabledByConfiguration => {}
        state => {
            return Err(WorkDispatchSafetyError::WatchdogNotAdmitted { state });
        }
    }

    match inputs.thermal {
        ThermalSafetyState::Ready => {}
        state => {
            return Err(WorkDispatchSafetyError::ThermalNotReady { state });
        }
    }

    let heartbeat_cycle_id = match inputs.heartbeat_requirement {
        HeartbeatRequirement::NoneRequired => None,
        HeartbeatRequirement::AllControllersSameCycle => {
            if inputs.controllers.is_empty() {
                return Err(WorkDispatchSafetyError::NoControllerObservations);
            }
            let expected_cycle = inputs.controllers[0].cycle_id;
            for obs in &inputs.controllers {
                if obs.cycle_id != expected_cycle {
                    return Err(WorkDispatchSafetyError::HeartbeatCycleMismatch {
                        expected_cycle,
                        observed_cycle: obs.cycle_id,
                        controller_id: obs.controller_id,
                    });
                }
                if !obs.heartbeat_ok {
                    return Err(WorkDispatchSafetyError::HeartbeatFailed {
                        controller_id: obs.controller_id,
                        cycle_id: obs.cycle_id,
                    });
                }
            }
            Some(expected_cycle)
        }
    };

    Ok(WorkDispatchAdmissionReceipt {
        watchdog: inputs.watchdog,
        thermal: inputs.thermal,
        controller_count: inputs.controllers.len(),
        heartbeat_cycle_id,
    })
}

/// Terminal revoke: cut hash before noise, and report whether feed must stop.
///
/// Callers must latch `previously_revoked = true` for the lifecycle after this
/// returns; a later green sample does not clear the latch without teardown.
/// Prefer [`WorkDispatchLifecycle::revoke`] so the latch cannot be forgotten.
pub fn revoke_work_dispatch(
    cause: DispatchRevocationCause,
    profile_max_pwm: u8,
) -> (SafetyAction, bool) {
    let cut = match cause {
        DispatchRevocationCause::WatchdogLost => PowerCut {
            reason: PowerCutReason::Watchdog,
            cut_hash_before_noise: true,
        },
        DispatchRevocationCause::HeartbeatFailure => PowerCut {
            reason: PowerCutReason::PicHeartbeatMiss,
            cut_hash_before_noise: true,
        },
        DispatchRevocationCause::ThermalCutoff => PowerCut::thermal_emergency(),
        DispatchRevocationCause::OperatorSafeOff => PowerCut {
            reason: PowerCutReason::OperatorSafeOff,
            cut_hash_before_noise: true,
        },
    };
    let action = match cause {
        DispatchRevocationCause::OperatorSafeOff => {
            SafetyAction::PowerCutThenFan(cut, FanCommand::home_quiet_park(profile_max_pwm))
        }
        DispatchRevocationCause::ThermalCutoff => cut.with_emergency_fans(profile_max_pwm),
        // Heartbeat / watchdog: cut power, park fans quiet (not fan blast).
        _ => SafetyAction::PowerCutThenFan(cut, FanCommand::home_quiet_park(profile_max_pwm)),
    };
    (action, revocation_stops_watchdog_feed(cause))
}

/// One mining-lifecycle's work-dispatch admit/revoke latch.
///
/// Engines historically re-implemented "were we admitted?" and "did we
/// revoke?" with free-floating bools that could drift out of the pure
/// [`admit_work_dispatch`] / [`revoke_work_dispatch`] matrix. This type is the
/// shared state machine:
///
/// 1. Fresh lifecycle starts **not admitted**, **not revoked**.
/// 2. [`Self::admit`] calls the pure gate, forcing `previously_revoked` from
///    the latch (callers cannot smuggle a false clear).
/// 3. [`Self::revoke`] is terminal: drops the receipt, latches revoked, and
///    returns the SafetyAction + feed-stop bit.
/// 4. Only [`Self::reset_after_full_teardown`] clears the latch — requiring an
///    explicit post-teardown call so a recovered heartbeat cannot re-admit an
///    old dispatcher without a new lifecycle.
///
/// Build shared safety inputs for any engine adapter.
///
/// Engines map their runtime observations into the typed pillars, then call
/// this (or construct the struct directly). The lifecycle latch owns
/// `previously_revoked` — callers must leave it false here.
pub fn build_work_dispatch_inputs(
    watchdog: WatchdogSafetyState,
    heartbeat_requirement: HeartbeatRequirement,
    controllers: &[ControllerHeartbeatObservation],
    thermal: ThermalSafetyState,
) -> WorkDispatchSafetyInputs {
    WorkDispatchSafetyInputs {
        watchdog,
        heartbeat_requirement,
        controllers: controllers.to_vec(),
        thermal,
        previously_revoked: false,
    }
}

/// Map config + positive ownership into the watchdog pillar.
///
/// Used by stock / hybrid / serial adapters so the three engines share one
/// interpretation of "armed vs disabled vs unavailable".
pub fn map_watchdog_safety_state(
    config_enabled: bool,
    positively_owned: bool,
) -> WatchdogSafetyState {
    match (config_enabled, positively_owned) {
        (false, _) => WatchdogSafetyState::DisabledByConfiguration,
        (true, true) => WatchdogSafetyState::Armed,
        (true, false) => WatchdogSafetyState::Unavailable,
    }
}

/// Lock-free cross-task publication of work-dispatch admission state.
///
/// Engines that split admit/revoke (daemon lifecycle, PIC heartbeat thread,
/// thermal emergency) from work commit (`WorkDispatcher` hot loop) share one
/// [`std::sync::Arc`] of this type. Publication is fail-closed and one-way for
/// a generation:
///
/// 1. Fresh → not admitted, not revoked (no work).
/// 2. [`Self::publish_admitted`] after a successful lifecycle admit.
/// 3. [`Self::publish_revoked`] is terminal for this generation (clears
///    admitted, latches revoked). A later green heartbeat cannot re-admit
///    without a new publication instance / full teardown.
///
/// # Status
///
/// **Production pure policy.** Host-testable without HAL. Adapters must not
/// invent a second AtomicBool matrix.
#[derive(Debug, Default)]
pub struct WorkDispatchAdmissionPublication {
    admitted: std::sync::atomic::AtomicBool,
    terminally_revoked: std::sync::atomic::AtomicBool,
}

impl WorkDispatchAdmissionPublication {
    /// Fresh publication: no work commit allowed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish green admission for this generation.
    ///
    /// No-op if already terminally revoked (recovered HB must not re-open an
    /// old dispatcher generation).
    pub fn publish_admitted(&self) {
        use std::sync::atomic::Ordering;
        if self.terminally_revoked.load(Ordering::Acquire) {
            return;
        }
        self.admitted.store(true, Ordering::Release);
    }

    /// Terminal revoke for this generation: work commit forbidden forever on
    /// this publication instance.
    pub fn publish_revoked(&self) {
        use std::sync::atomic::Ordering;
        self.terminally_revoked.store(true, Ordering::Release);
        self.admitted.store(false, Ordering::Release);
    }

    /// Whether standard work may be committed right now.
    pub fn allow_work_commit(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.admitted.load(Ordering::Acquire) && !self.terminally_revoked.load(Ordering::Acquire)
    }

    /// Alias used by engines that mirror [`WorkDispatchLifecycle::is_admitted`].
    pub fn is_admitted(&self) -> bool {
        self.allow_work_commit()
    }

    pub fn is_terminally_revoked(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.terminally_revoked.load(Ordering::Acquire)
    }
}

/// Pure policy: when admission required ≥1 controller and zero remain
/// Active-healthy, terminal-revoke work dispatch (fail-closed).
///
/// NoPic / empty admission (`required == 0`) never trips this path — those
/// paths use thermal / operator revoke only.
pub fn should_revoke_work_dispatch_for_controller_health(
    controllers_required_at_admit: usize,
    controllers_still_active_healthy: usize,
) -> bool {
    controllers_required_at_admit > 0 && controllers_still_active_healthy == 0
}

/// **Production pure policy.** Engines own one lifecycle per mining run
/// (stock / hybrid / serial adapters) instead of open-coding a second matrix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkDispatchLifecycle {
    previously_revoked: bool,
    admission: Option<WorkDispatchAdmissionReceipt>,
}

impl WorkDispatchLifecycle {
    /// Fresh lifecycle: not admitted, not revoked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this lifecycle currently holds a successful admission receipt.
    pub fn is_admitted(&self) -> bool {
        self.admission.is_some()
    }

    /// Whether a terminal revoke has already fired for this lifecycle.
    pub fn is_terminally_revoked(&self) -> bool {
        self.previously_revoked
    }

    /// Borrow the current admission receipt, if any.
    pub fn admission(&self) -> Option<&WorkDispatchAdmissionReceipt> {
        self.admission.as_ref()
    }

    /// Attempt admission. The latch's revoke flag always wins over any
    /// `previously_revoked` value on the caller's inputs.
    pub fn admit(
        &mut self,
        inputs: &WorkDispatchSafetyInputs,
    ) -> Result<&WorkDispatchAdmissionReceipt, WorkDispatchSafetyError> {
        let mut gated = inputs.clone();
        gated.previously_revoked = self.previously_revoked || inputs.previously_revoked;
        let receipt = admit_work_dispatch(&gated)?;
        // `Option::insert` hands back a reference to the value it just stored, so
        // the store-then-`expect` round trip (and its panic path) is unnecessary.
        Ok(&*self.admission.insert(receipt))
    }

    /// Terminal revoke for this lifecycle.
    ///
    /// Clears the admission receipt, latches `previously_revoked`, and returns
    /// the cut-hash-before-noise action plus whether the watchdog feed must stop.
    pub fn revoke(
        &mut self,
        cause: DispatchRevocationCause,
        profile_max_pwm: u8,
    ) -> (SafetyAction, bool) {
        self.admission = None;
        self.previously_revoked = true;
        revoke_work_dispatch(cause, profile_max_pwm)
    }

    /// Clear the terminal latch after a **full** teardown (new lifecycle only).
    ///
    /// Must not be called while the previous dispatcher is still live — the
    /// whole point of the latch is that a recovered controller cannot resume
    /// an old work generation.
    pub fn reset_after_full_teardown(&mut self) {
        self.previously_revoked = false;
        self.admission = None;
    }

    /// Mirror this lifecycle into a shared publication (cross-task consumers).
    pub fn sync_publication(&self, publication: &WorkDispatchAdmissionPublication) {
        if self.previously_revoked {
            publication.publish_revoked();
        } else if self.admission.is_some() {
            publication.publish_admitted();
        }
        // else: neither admitted nor revoked — leave publication at fresh state
    }

    /// Terminal revoke and immediately publish to cross-task consumers.
    pub fn revoke_and_publish(
        &mut self,
        cause: DispatchRevocationCause,
        profile_max_pwm: u8,
        publication: &WorkDispatchAdmissionPublication,
    ) -> (SafetyAction, bool) {
        let out = self.revoke(cause, profile_max_pwm);
        publication.publish_revoked();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety_command::{
        power_precedes_fan_raise, PowerCutReason, HOME_FAN_PWM_SAFETY_MAX,
    };

    fn green_inputs() -> WorkDispatchSafetyInputs {
        WorkDispatchSafetyInputs {
            watchdog: WatchdogSafetyState::Armed,
            heartbeat_requirement: HeartbeatRequirement::AllControllersSameCycle,
            controllers: vec![
                ControllerHeartbeatObservation {
                    controller_id: 0x20,
                    heartbeat_ok: true,
                    cycle_id: 7,
                },
                ControllerHeartbeatObservation {
                    controller_id: 0x22,
                    heartbeat_ok: true,
                    cycle_id: 7,
                },
            ],
            thermal: ThermalSafetyState::Ready,
            previously_revoked: false,
        }
    }

    #[test]
    fn fresh_generation_requires_finite_measured_cooldown_below_controller_boundary() {
        assert_eq!(
            measured_startup_thermal_state(None, 80, 3),
            ThermalSafetyState::NotReady
        );
        for non_finite in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                measured_startup_thermal_state(Some(non_finite), 80, 3),
                ThermalSafetyState::NotReady
            );
        }
        assert_eq!(
            measured_startup_thermal_state(Some(80.0), 80, 3),
            ThermalSafetyState::Emergency
        );
        assert_eq!(
            measured_startup_thermal_state(Some(79.9), 80, 3),
            ThermalSafetyState::NotReady
        );
        assert_eq!(
            measured_startup_thermal_state(Some(77.0), 80, 3),
            ThermalSafetyState::NotReady,
            "the controller requires strictly below dangerous-hysteresis"
        );
        assert_eq!(
            measured_startup_thermal_state(Some(76.9), 80, 3),
            ThermalSafetyState::Ready
        );
    }

    #[test]
    fn standard_daemon_binds_fresh_generation_to_pre_energize_measurement() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let startup_lockout_block = daemon
            .find("// Read any source-aware lockout before obtaining fresh startup")
            .expect("startup lockout block");
        let lockout_load = daemon[startup_lockout_block..]
            .find("load_thermal_lockout(&thermal_lockout_path)")
            .map(|offset| startup_lockout_block + offset)
            .expect("fresh generation must consume durable source-domain lockout");
        let measured = daemon
            .find("let startup_temp_result = Xadc::read_temp()")
            .expect("fresh generation must obtain finite XADC evidence");
        let source_aware_release = daemon
            .find("evaluate_thermal_lockout_release(")
            .expect("persisted source domain must own release policy");
        let durable_removal = daemon
            .find("remove_thermal_lockout(&thermal_lockout_path)")
            .expect("accepted recovery must durably clear the lockout");
        let classified = daemon
            .find("measured_startup_thermal_state(")
            .expect("fresh generation must consume the pure measured policy");
        let prearmed = daemon[classified..]
            .find("let prearmed_lockout = prearmed_thermal_generation(")
            .map(|offset| classified + offset)
            .expect("admitted generation must pre-arm an Unknown crash marker");
        let prearm_persist = daemon[prearmed..]
            .find("persist_terminal_thermal_generation_bounded(")
            .map(|offset| prearmed + offset)
            .expect("pre-armed marker must be durably published");
        let watchdog_phase = daemon
            .find("// ---- Phase 1: Watchdog ----")
            .expect("startup phase boundary");
        daemon
            .find("daemon_thermal_safety_state(false, self.startup_thermal_safety)")
            .expect("work dispatch must consume the retained startup proof");

        assert!(
            lockout_load < measured
                && measured < source_aware_release
                && source_aware_release < durable_removal
                && durable_removal < classified
                && classified < prearmed
                && prearmed < prearm_persist
                && prearm_persist < watchdog_phase,
            "source-aware recovery, measured admission, and durable Unknown pre-arm must precede watchdog, heartbeat, and rail bring-up"
        );
        assert!(
            daemon.contains("Fresh-generation pre-energize thermal admission REFUSED")
                && daemon.contains("latch_terminal_safe_off()"),
            "missing/hot startup evidence must fail closed"
        );
        assert!(
            daemon.contains("ReleaseExperimentalBoardProxy")
                && daemon.contains("this is NOT same-domain hash-board temperature equivalence"),
            "proxy release must remain explicitly experimental and honestly labeled"
        );
    }

    #[test]
    fn admits_when_watchdog_armed_heartbeats_same_cycle_thermal_ready() {
        let receipt = admit_work_dispatch(&green_inputs()).expect("admit");
        assert_eq!(receipt.controller_count, 2);
        assert_eq!(receipt.heartbeat_cycle_id, Some(7));
        assert_eq!(receipt.watchdog, WatchdogSafetyState::Armed);
    }

    #[test]
    fn admits_when_watchdog_disabled_by_configuration() {
        let mut inputs = green_inputs();
        inputs.watchdog = WatchdogSafetyState::DisabledByConfiguration;
        assert!(admit_work_dispatch(&inputs).is_ok());
    }

    #[test]
    fn refuses_watchdog_not_positively_admitted() {
        let mut inputs = green_inputs();
        inputs.watchdog = WatchdogSafetyState::NotPositivelyAdmitted;
        let err = admit_work_dispatch(&inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::WatchdogNotAdmitted {
                state: WatchdogSafetyState::NotPositivelyAdmitted
            }
        ));
    }

    #[test]
    fn refuses_missing_controller_heartbeat() {
        let mut inputs = green_inputs();
        inputs.controllers[1].heartbeat_ok = false;
        let err = admit_work_dispatch(&inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::HeartbeatFailed {
                controller_id: 0x22,
                ..
            }
        ));
    }

    #[test]
    fn refuses_cross_cycle_heartbeat_mix() {
        let mut inputs = green_inputs();
        inputs.controllers[1].cycle_id = 8;
        let err = admit_work_dispatch(&inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::HeartbeatCycleMismatch {
                expected_cycle: 7,
                observed_cycle: 8,
                controller_id: 0x22
            }
        ));
    }

    #[test]
    fn refuses_empty_controllers_when_required() {
        let mut inputs = green_inputs();
        inputs.controllers.clear();
        assert!(matches!(
            admit_work_dispatch(&inputs),
            Err(WorkDispatchSafetyError::NoControllerObservations)
        ));
    }

    #[test]
    fn allows_none_required_without_observations() {
        let inputs = WorkDispatchSafetyInputs {
            watchdog: WatchdogSafetyState::Armed,
            heartbeat_requirement: HeartbeatRequirement::NoneRequired,
            controllers: vec![],
            thermal: ThermalSafetyState::Ready,
            previously_revoked: false,
        };
        let receipt = admit_work_dispatch(&inputs).unwrap();
        assert_eq!(receipt.controller_count, 0);
        assert_eq!(receipt.heartbeat_cycle_id, None);
    }

    #[test]
    fn refuses_thermal_not_ready_or_emergency() {
        for state in [ThermalSafetyState::NotReady, ThermalSafetyState::Emergency] {
            let mut inputs = green_inputs();
            inputs.thermal = state;
            assert!(matches!(
                admit_work_dispatch(&inputs),
                Err(WorkDispatchSafetyError::ThermalNotReady { .. })
            ));
        }
    }

    #[test]
    fn terminal_revoke_latch_blocks_re_admit() {
        let mut inputs = green_inputs();
        inputs.previously_revoked = true;
        assert!(matches!(
            admit_work_dispatch(&inputs),
            Err(WorkDispatchSafetyError::TerminallyRevoked)
        ));
    }

    #[test]
    fn revoke_cuts_hash_before_noise_and_stops_feed() {
        let (action, stop_feed) =
            revoke_work_dispatch(DispatchRevocationCause::HeartbeatFailure, 100);
        assert!(stop_feed);
        let steps = action.steps();
        assert!(power_precedes_fan_raise(&steps));
        match &steps[0] {
            crate::safety_command::SafetyStep::CutPower(cut) => {
                assert_eq!(cut.reason, PowerCutReason::PicHeartbeatMiss);
                assert!(cut.cut_hash_before_noise);
            }
            other => panic!("expected cut first, got {other:?}"),
        }
        match &steps[1] {
            crate::safety_command::SafetyStep::CommandFans(fan) => {
                assert!(fan.effective_pwm() <= HOME_FAN_PWM_SAFETY_MAX);
            }
            other => panic!("expected fans second, got {other:?}"),
        }
    }

    #[test]
    fn thermal_revoke_uses_emergency_fan_cap_not_blast() {
        let (action, stop_feed) = revoke_work_dispatch(DispatchRevocationCause::ThermalCutoff, 100);
        assert!(stop_feed);
        let steps = action.steps();
        assert!(power_precedes_fan_raise(&steps));
        if let crate::safety_command::SafetyStep::CommandFans(fan) = steps[1] {
            assert_eq!(fan.effective_pwm(), HOME_FAN_PWM_SAFETY_MAX);
        } else {
            panic!("expected fan step");
        }
    }

    /// Lifecycle latch is the engine-facing SSOT: admit stores a receipt,
    /// revoke drops it and blocks re-admit even if inputs look green, and only
    /// an explicit full-teardown reset re-opens admission.
    ///
    /// Mutation that clears `previously_revoked` inside `admit` without going
    /// through `reset_after_full_teardown` would make this go green incorrectly.
    #[test]
    fn lifecycle_latch_blocks_re_admit_until_full_teardown() {
        let mut life = WorkDispatchLifecycle::new();
        assert!(!life.is_admitted());
        assert!(!life.is_terminally_revoked());

        life.admit(&green_inputs()).expect("first admit");
        assert!(life.is_admitted());
        assert_eq!(life.admission().map(|r| r.controller_count), Some(2));

        let (action, stop_feed) = life.revoke(DispatchRevocationCause::HeartbeatFailure, 100);
        assert!(stop_feed);
        assert!(power_precedes_fan_raise(&action.steps()));
        assert!(!life.is_admitted());
        assert!(life.is_terminally_revoked());

        // A green sample after revoke must still refuse — recovered heartbeat
        // must not resume the old dispatcher generation.
        let err = life.admit(&green_inputs()).unwrap_err();
        assert_eq!(err, WorkDispatchSafetyError::TerminallyRevoked);

        life.reset_after_full_teardown();
        assert!(!life.is_terminally_revoked());
        life.admit(&green_inputs()).expect("admit after teardown");
        assert!(life.is_admitted());
    }

    /// Callers cannot clear the latch by passing `previously_revoked: false`
    /// on inputs — the lifecycle owns that bit.
    #[test]
    fn lifecycle_forces_revoke_flag_over_caller_inputs() {
        let mut life = WorkDispatchLifecycle::new();
        life.revoke(DispatchRevocationCause::OperatorSafeOff, 30);
        let mut green = green_inputs();
        green.previously_revoked = false; // attempted smuggle
        assert!(matches!(
            life.admit(&green),
            Err(WorkDispatchSafetyError::TerminallyRevoked)
        ));
    }

    #[test]
    fn map_watchdog_and_build_inputs_feed_admit() {
        let wd = map_watchdog_safety_state(true, true);
        assert_eq!(wd, WatchdogSafetyState::Armed);
        assert_eq!(
            map_watchdog_safety_state(false, true),
            WatchdogSafetyState::DisabledByConfiguration
        );
        assert_eq!(
            map_watchdog_safety_state(true, false),
            WatchdogSafetyState::Unavailable
        );
        let controllers = [ControllerHeartbeatObservation {
            controller_id: 0x20,
            heartbeat_ok: true,
            cycle_id: 1,
        }];
        let inputs = build_work_dispatch_inputs(
            wd,
            HeartbeatRequirement::AllControllersSameCycle,
            &controllers,
            ThermalSafetyState::Ready,
        );
        let mut life = WorkDispatchLifecycle::new();
        life.admit(&inputs)
            .expect("green admit via shared builders");
        assert!(life.is_admitted());
    }

    #[test]
    fn admission_publication_is_fail_closed_and_one_way() {
        let pub_ = WorkDispatchAdmissionPublication::new();
        assert!(!pub_.allow_work_commit());
        assert!(!pub_.is_terminally_revoked());

        pub_.publish_admitted();
        assert!(pub_.allow_work_commit());

        pub_.publish_revoked();
        assert!(!pub_.allow_work_commit());
        assert!(pub_.is_terminally_revoked());

        // Recovered heartbeat must not re-open the same generation.
        pub_.publish_admitted();
        assert!(!pub_.allow_work_commit());
        assert!(pub_.is_terminally_revoked());
    }

    #[test]
    fn lifecycle_revoke_and_publish_syncs_shared_gate() {
        let mut life = WorkDispatchLifecycle::new();
        let pub_ = WorkDispatchAdmissionPublication::new();
        life.admit(&green_inputs()).expect("admit");
        life.sync_publication(&pub_);
        assert!(pub_.allow_work_commit());

        let (action, stop_feed) =
            life.revoke_and_publish(DispatchRevocationCause::HeartbeatFailure, 100, &pub_);
        assert!(stop_feed);
        assert!(power_precedes_fan_raise(&action.steps()));
        assert!(!pub_.allow_work_commit());
        assert!(pub_.is_terminally_revoked());
        assert!(life.is_terminally_revoked());
    }

    #[test]
    fn controller_health_revoke_policy_is_fail_closed() {
        assert!(!should_revoke_work_dispatch_for_controller_health(0, 0));
        assert!(!should_revoke_work_dispatch_for_controller_health(3, 1));
        assert!(!should_revoke_work_dispatch_for_controller_health(3, 3));
        assert!(should_revoke_work_dispatch_for_controller_health(3, 0));
        assert!(should_revoke_work_dispatch_for_controller_health(1, 0));
    }

    /// Structural pins: hybrid + serial engines must own the shared lifecycle
    /// and call the shipped admit/revoke adapters (not a private matrix).
    ///
    /// Mutation: rename/remove `WorkDispatchLifecycle::new` or the admit
    /// adapter call site in either engine → this test goes red on host without
    /// needing the Linux HAL binary crate.
    #[test]
    fn hybrid_and_serial_engine_sources_own_shared_lifecycle() {
        let hybrid = include_str!("../../dcentrald/src/s19j_hybrid_mining.rs");
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        let stock = include_str!("../../dcentrald/src/stock_mining.rs");

        for (name, src) in [("hybrid", hybrid), ("serial", serial), ("stock", stock)] {
            assert!(
                src.contains("WorkDispatchLifecycle::new()"),
                "{name} must own WorkDispatchLifecycle::new()"
            );
            assert!(
                src.contains("DispatchRevocationCause::HeartbeatFailure"),
                "{name} must terminal-revoke on HeartbeatFailure"
            );
            assert!(
                src.contains("if !dispatch_life.is_admitted()"),
                "{name} must gate work dispatch on live admission"
            );
        }

        assert!(
            hybrid.contains("hybrid_admit_standard_work_dispatch"),
            "hybrid must call shipped admit adapter"
        );
        assert!(
            hybrid.contains("hybrid_revoke_and_stop_watchdog_feed"),
            "hybrid must revoke AND stop SoC WDT feed (stock parity)"
        );
        assert!(
            hybrid.contains("close_terminal_lock_free()"),
            "hybrid stop_feed path must terminally close the WDT feed gate"
        );
        assert!(
            hybrid.contains("DispatchRevocationCause::ThermalCutoff"),
            "hybrid must revoke on ThermalCutoff"
        );
        assert!(
            hybrid.contains("DispatchRevocationCause::OperatorSafeOff"),
            "hybrid must revoke on OperatorSafeOff"
        );
        assert!(
            hybrid.contains("terminal_failure.store(true, Ordering::SeqCst)"),
            "hybrid PIC HB thread must latch terminal failure"
        );

        assert!(
            serial.contains("serial_admit_standard_work_dispatch"),
            "serial must call shipped admit adapter"
        );
        assert!(
            serial.contains("serial_revoke_and_stop_watchdog_feed"),
            "serial must revoke AND stop SoC WDT feed (stock parity)"
        );
        assert!(
            serial.contains("close_terminal_lock_free()"),
            "serial stop_feed path must terminally close exact WDT feed gate"
        );
        assert!(
            serial.contains("DispatchRevocationCause::ThermalCutoff"),
            "serial must revoke on ThermalCutoff"
        );
        assert!(
            serial.contains("DispatchRevocationCause::OperatorSafeOff"),
            "serial must revoke on OperatorSafeOff"
        );
        // Fail-closed thermal: production must not invent Ready via constants.
        assert!(
            serial.contains("thermal_proof_present"),
            "serial admit must derive thermal_proof_present from topology owners"
        );
        assert!(
            !serial.contains("serial_thermal_safety_state(true, false)"),
            "serial must not hard-code thermal Ready with (true, false)"
        );

        assert!(
            stock.contains("stock_fpga_admit_standard_work_dispatch"),
            "stock must call shipped admit adapter"
        );
        assert!(
            stock.contains("stock_fpga_revoke_work_dispatch"),
            "stock must call shipped revoke adapter"
        );

        // Standard FPGA daemon path (constitution 2026-07-29): admit before
        // WorkDispatcher::new with SoC watchdog feed ownership established first.
        // Mid-run `if !dispatch_life.is_admitted()` tick gate remains a residual
        // (WorkDispatcher owns the hot loop; stock/serial/hybrid keep local loops).
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        assert!(
            daemon.contains("WorkDispatchLifecycle::new()"),
            "daemon must own WorkDispatchLifecycle::new()"
        );
        assert!(
            daemon.contains("fn daemon_admit_standard_work_dispatch"),
            "daemon must ship admit adapter"
        );
        assert!(
            daemon.contains("fn daemon_revoke_work_dispatch"),
            "daemon must ship revoke adapter"
        );
        // Anchor on a once-only live comment (must not be re-quoted in any test).
        let section = daemon
            .find("Continuous-audit NO-SHIP residual: refuse WorkDispatcher construction")
            .expect("daemon work-dispatch NO-SHIP residual comment");
        let after = &daemon[section..];
        assert!(
            after.contains("owned_watchdog_kicker("),
            "section must hoist owned_watchdog_kicker before admit"
        );
        assert!(
            after.contains("self.watchdog_feed_owner = Some(watchdog_feed_owner);"),
            "section must latch SoC WDT feed ownership before admit"
        );
        assert!(
            after.contains("daemon_admit_standard_work_dispatch"),
            "section must call shipped admit adapter"
        );
        // Latch identifier is unique enough when searched only after the section.
        let latch_rel = after
            .find("_dispatch_life_admitted")
            .expect("dispatch_life latch after admit");
        let disp_rel = after[latch_rel..]
            .find("WorkDispatcher::new(")
            .map(|j| latch_rel + j)
            .expect("WorkDispatcher::new after latch");
        let admit_rel = after
            .find("daemon_admit_standard_work_dispatch")
            .expect("admit adapter in section");
        assert!(
            admit_rel < latch_rel && latch_rel < disp_rel,
            "section order: admit → latch → WorkDispatcher::new"
        );
        assert!(
            after.contains("work-dispatch admission OK")
                && after.contains("WorkDispatcher construction allowed"),
            "green admit log required in section"
        );
        assert!(
            after.contains("work-dispatch admission REFUSED")
                && after.contains("no WorkDispatcher construction"),
            "refuse path log required in section"
        );
        assert!(
            after.contains("WorkDispatchAdmissionPublication"),
            "daemon must share WorkDispatchAdmissionPublication with WorkDispatcher"
        );
        assert!(
            after.contains("sync_publication"),
            "daemon must sync lifecycle → publication after green admit"
        );

        // Mid-run gate: WorkDispatcher hot loop + HB/thermal revoke paths.
        let dispatcher = include_str!("../../dcentrald/src/work_dispatcher.rs");
        assert!(
            dispatcher.contains("work_dispatch_admission"),
            "WorkDispatcher must own shared admission publication field"
        );
        assert!(
            dispatcher.contains("allow_work_commit()"),
            "WorkDispatcher dispatch tick must gate on allow_work_commit"
        );
        assert!(
            after.contains("should_revoke_work_dispatch_for_controller_health")
                || daemon.contains("should_revoke_work_dispatch_for_controller_health"),
            "daemon HB path must use pure controller-health revoke policy"
        );
        assert!(
            daemon.contains("mark_thermal_emergency_and_revoke_work_dispatch"),
            "thermal emergency must terminally revoke work-dispatch admission"
        );
    }
}
