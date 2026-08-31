//! Board-agnostic, fail-closed proof state for a de-energized hash domain.
//!
//! This module consumes already-normalized observations. It has no hardware
//! access, no timing source, no model defaults, and no actuation result. A
//! successful proof can reach only independent review; it can never authorize
//! hashing, power, cooling, GPIO, networking, or firmware mutation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyLimitsError {
    ZeroMaximumSampleAge,
    ZeroMaximumWatchdogAge,
    ZeroMinimumCoolingRpm,
    ZeroMinimumHealthySpan,
    WarningNotBelowCutoff,
    InsufficientHealthySamples,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyBindingError {
    ZeroProfileDigest,
    ZeroSessionDigest,
    ReusedDigest,
}

/// Opaque joins to an externally reviewed model profile and exact run.
///
/// This type authenticates nothing. The higher receipt layer must verify both
/// digests before interpreting a verdict. Keeping the joins in every verdict
/// prevents an otherwise healthy-looking result from being accidentally
/// detached from the model limits or spliced into a different run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyBinding {
    profile_digest: [u8; 32],
    session_digest: [u8; 32],
}

impl SafetyBinding {
    pub const fn new(
        profile_digest: [u8; 32],
        session_digest: [u8; 32],
    ) -> Result<Self, SafetyBindingError> {
        if all_zero(profile_digest) {
            return Err(SafetyBindingError::ZeroProfileDigest);
        }
        if all_zero(session_digest) {
            return Err(SafetyBindingError::ZeroSessionDigest);
        }
        if arrays_equal(profile_digest, session_digest) {
            return Err(SafetyBindingError::ReusedDigest);
        }
        Ok(Self {
            profile_digest,
            session_digest,
        })
    }

    #[must_use]
    pub const fn profile_digest(self) -> [u8; 32] {
        self.profile_digest
    }

    #[must_use]
    pub const fn session_digest(self) -> [u8; 32] {
        self.session_digest
    }
}

const fn all_zero(bytes: [u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn arrays_equal(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Model-bound limits supplied by a higher layer from reviewed evidence.
///
/// The policy core deliberately provides no default temperature or cooling
/// values: a numeric default could be mistaken for qualification across models.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyLimits {
    max_sample_age_ticks: u32,
    max_watchdog_age_ticks: u32,
    min_cooling_rpm: u32,
    warning_temp_mc: i32,
    cutoff_temp_mc: i32,
    required_healthy_samples: u32,
    minimum_healthy_span_ticks: u64,
}

impl SafetyLimits {
    pub const fn new(
        max_sample_age_ticks: u32,
        max_watchdog_age_ticks: u32,
        min_cooling_rpm: u32,
        warning_temp_mc: i32,
        cutoff_temp_mc: i32,
        required_healthy_samples: u32,
        minimum_healthy_span_ticks: u64,
    ) -> Result<Self, SafetyLimitsError> {
        if max_sample_age_ticks == 0 {
            return Err(SafetyLimitsError::ZeroMaximumSampleAge);
        }
        if max_watchdog_age_ticks == 0 {
            return Err(SafetyLimitsError::ZeroMaximumWatchdogAge);
        }
        if min_cooling_rpm == 0 {
            return Err(SafetyLimitsError::ZeroMinimumCoolingRpm);
        }
        if warning_temp_mc >= cutoff_temp_mc {
            return Err(SafetyLimitsError::WarningNotBelowCutoff);
        }
        if required_healthy_samples < 2 {
            return Err(SafetyLimitsError::InsufficientHealthySamples);
        }
        if minimum_healthy_span_ticks == 0 {
            return Err(SafetyLimitsError::ZeroMinimumHealthySpan);
        }
        Ok(Self {
            max_sample_age_ticks,
            max_watchdog_age_ticks,
            min_cooling_rpm,
            warning_temp_mc,
            cutoff_temp_mc,
            required_healthy_samples,
            minimum_healthy_span_ticks,
        })
    }

    #[must_use]
    pub const fn max_sample_age_ticks(self) -> u32 {
        self.max_sample_age_ticks
    }

    #[must_use]
    pub const fn max_watchdog_age_ticks(self) -> u32 {
        self.max_watchdog_age_ticks
    }

    #[must_use]
    pub const fn min_cooling_rpm(self) -> u32 {
        self.min_cooling_rpm
    }

    #[must_use]
    pub const fn warning_temp_mc(self) -> i32 {
        self.warning_temp_mc
    }

    #[must_use]
    pub const fn cutoff_temp_mc(self) -> i32 {
        self.cutoff_temp_mc
    }

    #[must_use]
    pub const fn required_healthy_samples(self) -> u32 {
        self.required_healthy_samples
    }

    #[must_use]
    pub const fn minimum_healthy_span_ticks(self) -> u64 {
        self.minimum_healthy_span_ticks
    }
}

/// A single observation normalized by a future, target-bound hardware layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyObservation {
    pub sequence: u64,
    /// Target monotonic tick captured with this normalized observation.
    pub monotonic_tick: u64,
    pub sample_age_ticks: u32,
    pub hottest_temp_mc: Option<i32>,
    pub min_cooling_rpm: Option<u32>,
    pub independent_cutoff_asserted: Option<bool>,
    pub hash_power_present: Option<bool>,
    pub watchdog_age_ticks: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyFault {
    ReplayOrOutOfOrderSequence { previous: u64, observed: u64 },
    NonIncreasingMonotonicTick { previous: u64, observed: u64 },
    StaleTelemetry { age_ticks: u32, maximum_ticks: u32 },
    WatchdogFeedbackMissing,
    StaleWatchdog { age_ticks: u32, maximum_ticks: u32 },
    TemperatureFeedbackMissing,
    TemperatureAtOrAboveCutoff { observed_mc: i32, cutoff_mc: i32 },
    TemperatureAtOrAboveWarning { observed_mc: i32, warning_mc: i32 },
    CoolingFeedbackMissing,
    CoolingBelowMinimum { observed_rpm: u32, minimum_rpm: u32 },
    IndependentCutoffFeedbackMissing,
    IndependentCutoffNotAsserted,
    HashPowerFeedbackMissing,
    UnexpectedHashPower,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SafetyState {
    #[default]
    Sealed,
    ProvingCooling,
    AwaitingIndependentReview,
    FaultLatched {
        reason: SafetyFault,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginProofError {
    AlreadyStarted { state: SafetyState },
}

#[must_use = "discarding a safety verdict can bypass fail-closed handling"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyVerdict {
    pub binding: SafetyBinding,
    pub state: SafetyState,
    pub healthy_streak: u32,
}

/// One-way supervisor for proving that a hash domain is safely de-energized.
///
/// There is intentionally no reset method. A latched fault requires destroying
/// this value and passing through an external, independently reviewed recovery
/// procedure before a higher layer may construct another supervisor.
/// ```compile_fail
/// use dcent_avalon_k210_core::safety::{
///     SafetyBinding, SafetyLimits, SafetySupervisor,
/// };
/// let binding = SafetyBinding::new([1; 32], [2; 32]).unwrap();
/// let limits = SafetyLimits::new(1, 1, 1, 1, 2, 2, 1).unwrap();
/// let supervisor = SafetySupervisor::new(binding, limits);
/// let rollback_copy = supervisor;
/// let _original_must_be_moved = supervisor;
/// let _ = rollback_copy;
/// ```
///
/// ```compile_fail
/// use dcent_avalon_k210_core::safety::{
///     SafetyBinding, SafetyLimits, SafetySupervisor,
/// };
/// let binding = SafetyBinding::new([1; 32], [2; 32]).unwrap();
/// let limits = SafetyLimits::new(1, 1, 1, 1, 2, 2, 1).unwrap();
/// let supervisor = SafetySupervisor::new(binding, limits);
/// let _rollback_clone = supervisor.clone();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct SafetySupervisor {
    binding: SafetyBinding,
    limits: SafetyLimits,
    state: SafetyState,
    last_sequence: Option<u64>,
    last_monotonic_tick: Option<u64>,
    first_healthy_tick: Option<u64>,
    healthy_streak: u32,
}

impl SafetySupervisor {
    #[must_use]
    pub const fn new(binding: SafetyBinding, limits: SafetyLimits) -> Self {
        Self {
            binding,
            limits,
            state: SafetyState::Sealed,
            last_sequence: None,
            last_monotonic_tick: None,
            first_healthy_tick: None,
            healthy_streak: 0,
        }
    }

    pub fn begin_proof(&mut self) -> Result<SafetyVerdict, BeginProofError> {
        if self.state != SafetyState::Sealed {
            return Err(BeginProofError::AlreadyStarted { state: self.state });
        }
        self.state = SafetyState::ProvingCooling;
        Ok(self.verdict())
    }

    pub const fn verdict(&self) -> SafetyVerdict {
        SafetyVerdict {
            binding: self.binding,
            state: self.state,
            healthy_streak: self.healthy_streak,
        }
    }

    /// Consumes an observation without ever producing actuation authority.
    ///
    /// Observations received while sealed are ignored. Once proof begins, the
    /// first fault in the documented deterministic order is latched forever:
    /// sequence, telemetry freshness, watchdog, temperature, cooling,
    /// independent cutoff, then hash-power feedback.
    pub fn observe(&mut self, observation: SafetyObservation) -> SafetyVerdict {
        if matches!(
            self.state,
            SafetyState::Sealed | SafetyState::FaultLatched { .. }
        ) {
            return self.verdict();
        }

        if let Some(reason) = self.first_fault(observation) {
            self.state = SafetyState::FaultLatched { reason };
            self.healthy_streak = 0;
            return self.verdict();
        }

        self.last_sequence = Some(observation.sequence);
        self.last_monotonic_tick = Some(observation.monotonic_tick);
        let first_healthy_tick = match self.first_healthy_tick {
            Some(tick) => tick,
            None => {
                self.first_healthy_tick = Some(observation.monotonic_tick);
                observation.monotonic_tick
            }
        };
        self.healthy_streak = self.healthy_streak.saturating_add(1);
        let healthy_span = observation
            .monotonic_tick
            .saturating_sub(first_healthy_tick);
        if self.healthy_streak >= self.limits.required_healthy_samples
            && healthy_span >= self.limits.minimum_healthy_span_ticks
        {
            self.state = SafetyState::AwaitingIndependentReview;
        }
        self.verdict()
    }

    fn first_fault(&self, observation: SafetyObservation) -> Option<SafetyFault> {
        if let Some(previous) = self.last_sequence
            && observation.sequence <= previous
        {
            return Some(SafetyFault::ReplayOrOutOfOrderSequence {
                previous,
                observed: observation.sequence,
            });
        }
        if let Some(previous) = self.last_monotonic_tick
            && observation.monotonic_tick <= previous
        {
            return Some(SafetyFault::NonIncreasingMonotonicTick {
                previous,
                observed: observation.monotonic_tick,
            });
        }
        if observation.sample_age_ticks > self.limits.max_sample_age_ticks {
            return Some(SafetyFault::StaleTelemetry {
                age_ticks: observation.sample_age_ticks,
                maximum_ticks: self.limits.max_sample_age_ticks,
            });
        }
        match observation.watchdog_age_ticks {
            None => return Some(SafetyFault::WatchdogFeedbackMissing),
            Some(age_ticks) if age_ticks > self.limits.max_watchdog_age_ticks => {
                return Some(SafetyFault::StaleWatchdog {
                    age_ticks,
                    maximum_ticks: self.limits.max_watchdog_age_ticks,
                });
            }
            Some(_) => {}
        }
        match observation.hottest_temp_mc {
            None => return Some(SafetyFault::TemperatureFeedbackMissing),
            Some(observed_mc) if observed_mc >= self.limits.cutoff_temp_mc => {
                return Some(SafetyFault::TemperatureAtOrAboveCutoff {
                    observed_mc,
                    cutoff_mc: self.limits.cutoff_temp_mc,
                });
            }
            Some(observed_mc) if observed_mc >= self.limits.warning_temp_mc => {
                return Some(SafetyFault::TemperatureAtOrAboveWarning {
                    observed_mc,
                    warning_mc: self.limits.warning_temp_mc,
                });
            }
            Some(_) => {}
        }
        match observation.min_cooling_rpm {
            None => return Some(SafetyFault::CoolingFeedbackMissing),
            Some(observed_rpm) if observed_rpm < self.limits.min_cooling_rpm => {
                return Some(SafetyFault::CoolingBelowMinimum {
                    observed_rpm,
                    minimum_rpm: self.limits.min_cooling_rpm,
                });
            }
            Some(_) => {}
        }
        match observation.independent_cutoff_asserted {
            None => return Some(SafetyFault::IndependentCutoffFeedbackMissing),
            Some(false) => return Some(SafetyFault::IndependentCutoffNotAsserted),
            Some(true) => {}
        }
        match observation.hash_power_present {
            None => Some(SafetyFault::HashPowerFeedbackMissing),
            Some(true) => Some(SafetyFault::UnexpectedHashPower),
            Some(false) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SafetyBinding {
        SafetyBinding::new([0x11; 32], [0x22; 32]).unwrap()
    }

    fn limits() -> SafetyLimits {
        SafetyLimits::new(3, 2, 1_500, 70_000, 80_000, 3, 20).unwrap()
    }

    fn healthy(sequence: u64) -> SafetyObservation {
        healthy_at(sequence, sequence * 10)
    }

    fn healthy_at(sequence: u64, monotonic_tick: u64) -> SafetyObservation {
        SafetyObservation {
            sequence,
            monotonic_tick,
            sample_age_ticks: 0,
            hottest_temp_mc: Some(40_000),
            min_cooling_rpm: Some(2_000),
            independent_cutoff_asserted: Some(true),
            hash_power_present: Some(false),
            watchdog_age_ticks: Some(0),
        }
    }

    fn supervisor() -> SafetySupervisor {
        SafetySupervisor::new(binding(), limits())
    }

    fn begin(supervisor: &mut SafetySupervisor) {
        assert_eq!(
            supervisor.begin_proof().unwrap().state,
            SafetyState::ProvingCooling
        );
    }

    #[test]
    fn binding_requires_distinct_nonzero_profile_and_session_digests() {
        assert_eq!(
            SafetyBinding::new([0; 32], [2; 32]),
            Err(SafetyBindingError::ZeroProfileDigest)
        );
        assert_eq!(
            SafetyBinding::new([1; 32], [0; 32]),
            Err(SafetyBindingError::ZeroSessionDigest)
        );
        assert_eq!(
            SafetyBinding::new([3; 32], [3; 32]),
            Err(SafetyBindingError::ReusedDigest)
        );
        assert_eq!(binding().profile_digest(), [0x11; 32]);
        assert_eq!(binding().session_digest(), [0x22; 32]);
    }

    #[test]
    fn rejects_structurally_unsafe_limits() {
        assert_eq!(
            SafetyLimits::new(0, 2, 1_500, 70_000, 80_000, 3, 20),
            Err(SafetyLimitsError::ZeroMaximumSampleAge)
        );
        assert_eq!(
            SafetyLimits::new(3, 0, 1_500, 70_000, 80_000, 3, 20),
            Err(SafetyLimitsError::ZeroMaximumWatchdogAge)
        );
        assert_eq!(
            SafetyLimits::new(3, 2, 0, 70_000, 80_000, 3, 20),
            Err(SafetyLimitsError::ZeroMinimumCoolingRpm)
        );
        assert_eq!(
            SafetyLimits::new(3, 2, 1_500, 80_000, 80_000, 3, 20),
            Err(SafetyLimitsError::WarningNotBelowCutoff)
        );
        assert_eq!(
            SafetyLimits::new(3, 2, 1_500, 70_000, 80_000, 1, 20),
            Err(SafetyLimitsError::InsufficientHealthySamples)
        );
        assert_eq!(
            SafetyLimits::new(3, 2, 1_500, 70_000, 80_000, 3, 0),
            Err(SafetyLimitsError::ZeroMinimumHealthySpan)
        );
        assert_eq!(limits().minimum_healthy_span_ticks(), 20);
    }

    #[test]
    fn sealed_supervisor_ignores_observations() {
        let mut supervisor = supervisor();
        let mut unsafe_observation = healthy(1);
        unsafe_observation.hash_power_present = Some(true);
        assert_eq!(
            supervisor.observe(unsafe_observation),
            SafetyVerdict {
                binding: binding(),
                state: SafetyState::Sealed,
                healthy_streak: 0,
            }
        );
    }

    #[test]
    fn missing_feedback_latches_the_first_fault() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        let mut incomplete = healthy(1);
        incomplete.watchdog_age_ticks = None;
        incomplete.hottest_temp_mc = None;
        assert_eq!(
            supervisor.observe(incomplete).state,
            SafetyState::FaultLatched {
                reason: SafetyFault::WatchdogFeedbackMissing
            }
        );
    }

    #[test]
    fn replay_or_out_of_order_sequence_latches() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        assert_eq!(
            supervisor.observe(healthy(7)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy(7)).state,
            SafetyState::FaultLatched {
                reason: SafetyFault::ReplayOrOutOfOrderSequence {
                    previous: 7,
                    observed: 7
                }
            }
        );
    }

    #[test]
    fn non_increasing_monotonic_tick_latches_even_with_new_sequence() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        assert_eq!(
            supervisor.observe(healthy_at(1, 10)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy_at(2, 10)).state,
            SafetyState::FaultLatched {
                reason: SafetyFault::NonIncreasingMonotonicTick {
                    previous: 10,
                    observed: 10
                }
            }
        );
    }

    #[test]
    fn cutoff_temperature_takes_precedence_over_warning() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        let mut hot = healthy(1);
        hot.hottest_temp_mc = Some(80_000);
        assert_eq!(
            supervisor.observe(hot).state,
            SafetyState::FaultLatched {
                reason: SafetyFault::TemperatureAtOrAboveCutoff {
                    observed_mc: 80_000,
                    cutoff_mc: 80_000
                }
            }
        );
    }

    #[test]
    fn low_cooling_latches() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        let mut slow = healthy(1);
        slow.min_cooling_rpm = Some(1_499);
        assert_eq!(
            supervisor.observe(slow).state,
            SafetyState::FaultLatched {
                reason: SafetyFault::CoolingBelowMinimum {
                    observed_rpm: 1_499,
                    minimum_rpm: 1_500
                }
            }
        );
    }

    #[test]
    fn unexpected_hash_power_latches() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        let mut energized = healthy(1);
        energized.hash_power_present = Some(true);
        assert_eq!(
            supervisor.observe(energized).state,
            SafetyState::FaultLatched {
                reason: SafetyFault::UnexpectedHashPower
            }
        );
    }

    #[test]
    fn healthy_streak_reaches_review_only() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        assert_eq!(
            supervisor.observe(healthy(1)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy(2)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy(3)),
            SafetyVerdict {
                binding: binding(),
                state: SafetyState::AwaitingIndependentReview,
                healthy_streak: 3
            }
        );
        assert_eq!(
            supervisor.begin_proof(),
            Err(BeginProofError::AlreadyStarted {
                state: SafetyState::AwaitingIndependentReview
            })
        );
    }

    #[test]
    fn sample_count_alone_cannot_skip_the_minimum_healthy_span() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        assert_eq!(
            supervisor.observe(healthy_at(1, 100)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy_at(2, 101)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy_at(3, 102)).state,
            SafetyState::ProvingCooling
        );
        assert_eq!(
            supervisor.observe(healthy_at(4, 120)).state,
            SafetyState::AwaitingIndependentReview
        );
    }

    #[test]
    fn verdicts_remain_bound_to_the_exact_profile_and_session() {
        let other_binding = SafetyBinding::new([0x11; 32], [0x33; 32]).unwrap();
        let mut first = supervisor();
        let mut second = SafetySupervisor::new(other_binding, limits());
        begin(&mut first);
        begin(&mut second);
        assert_ne!(first.observe(healthy(1)), second.observe(healthy(1)));
    }

    #[test]
    fn fault_remains_latched_after_healthy_observation() {
        let mut supervisor = supervisor();
        begin(&mut supervisor);
        let mut stale = healthy(1);
        stale.sample_age_ticks = 4;
        let latched = supervisor.observe(stale);
        assert_eq!(supervisor.observe(healthy(2)), latched);
        assert_eq!(latched.healthy_streak, 0);
    }
}
