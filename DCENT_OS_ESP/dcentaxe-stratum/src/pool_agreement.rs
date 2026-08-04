// DCENT_axe — live pool difficulty-convention agreement monitor
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0
//
// P2 of `docs/SCRYPT_STACK_DESIGN.md` (§2.3 / risk R4).
//
// ── Why this exists ─────────────────────────────────────────────────────────
// A share is submitted only after WE decided, locally, that its hash meets the
// pool's target — a target we computed from `mining.set_difficulty` using a
// per-algorithm diff-1 constant. If our constant disagrees with the pool's by
// the classic scrypt `x65536`, the wire traffic stays perfectly well-formed
// and the failure is silent in exactly one of two directions:
//
//   * our constant TOO LOOSE  -> we submit shares the pool considers below its
//     target -> a flood of "low difficulty share" rejects -> pool ban;
//   * our constant TOO TIGHT  -> we submit almost nothing and under-report
//     hashrate by the same factor. Looks like broken hardware.
//
// Neither is detectable from a single share. Both are trivially detectable
// from the FIRST FEW POOL RESPONSES, which is what this monitor watches: it
// only counts shares we locally believed were valid, so a healthy pool should
// accept nearly all of them. A systematically high reject rate on
// locally-valid shares is the signature of a target-math disagreement.
//
// This is deliberately a pure, allocation-free, host-testable state machine
// with NO I/O: the Stratum client feeds it and reads a verdict.

use dcentaxe_asic::common::PowAlgorithm;

/// Minimum locally-valid shares that must be resolved before any verdict is
/// reported. Below this a couple of stale/duplicate rejects is normal noise.
pub const AGREEMENT_MIN_SAMPLES: u32 = 16;

/// Reject fraction (of locally-valid, pool-resolved shares) above which the
/// pool's target math is judged to disagree with ours.
///
/// Stale + duplicate rejects on a healthy pool sit well under 10 %; a diff-1
/// scale mismatch rejects ~everything. 50 % leaves a very wide margin so a
/// noisy-but-working pool is never falsely alarmed.
pub const AGREEMENT_REJECT_FRACTION: f64 = 0.5;

/// Verdict on whether our share-target math agrees with the pool's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolAgreement {
    /// Fewer than [`AGREEMENT_MIN_SAMPLES`] resolved shares — no verdict yet.
    Insufficient,
    /// Pool accepts the shares we believe are valid. Target math agrees.
    Agrees,
    /// The pool rejects most shares we locally validated. Our diff-1 constant
    /// or difficulty scale most likely disagrees with the pool's.
    ///
    /// ⚠ This is a DIAGNOSIS, not a proof: a pool that is simply broken, or a
    /// chain of stale jobs, produces the same signature. It is surfaced to the
    /// operator, never used to silently rewrite the target math.
    Diverges,
}

impl PoolAgreement {
    pub const fn as_str(self) -> &'static str {
        match self {
            PoolAgreement::Insufficient => "insufficient-samples",
            PoolAgreement::Agrees => "agrees",
            PoolAgreement::Diverges => "diverges",
        }
    }
}

/// Bounded accept/reject accumulator over LOCALLY-VALIDATED shares.
///
/// Counters saturate rather than wrap, so a long-running session can never
/// flip the verdict through overflow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolAgreementMonitor {
    algorithm_is_scrypt: bool,
    accepted: u32,
    rejected: u32,
    alarm_raised: bool,
}

impl PoolAgreementMonitor {
    pub const fn new(algorithm: PowAlgorithm) -> Self {
        Self {
            algorithm_is_scrypt: matches!(algorithm, PowAlgorithm::Scrypt1024),
            accepted: 0,
            rejected: 0,
            alarm_raised: false,
        }
    }

    /// Reset on a session change (reconnect / new extranonce / pool switch):
    /// counters from a previous session say nothing about this one's target
    /// agreement.
    pub fn reset(&mut self) {
        self.accepted = 0;
        self.rejected = 0;
        self.alarm_raised = false;
    }

    /// Re-key to a new algorithm (also resets).
    pub fn set_algorithm(&mut self, algorithm: PowAlgorithm) {
        self.algorithm_is_scrypt = matches!(algorithm, PowAlgorithm::Scrypt1024);
        self.reset();
    }

    /// Record one pool response to a share WE locally validated as meeting the
    /// pool target. Do not feed shares that were never submitted, or shares
    /// dropped locally (duplicate / out-of-mask) — they carry no information
    /// about target agreement.
    pub fn record(&mut self, accepted: bool) {
        if accepted {
            self.accepted = self.accepted.saturating_add(1);
        } else {
            self.rejected = self.rejected.saturating_add(1);
        }
    }

    pub fn accepted(&self) -> u32 {
        self.accepted
    }

    pub fn rejected(&self) -> u32 {
        self.rejected
    }

    pub fn resolved(&self) -> u32 {
        self.accepted.saturating_add(self.rejected)
    }

    /// Current verdict.
    pub fn verdict(&self) -> PoolAgreement {
        let resolved = self.resolved();
        if resolved < AGREEMENT_MIN_SAMPLES {
            return PoolAgreement::Insufficient;
        }
        let reject_fraction = self.rejected as f64 / resolved as f64;
        if reject_fraction > AGREEMENT_REJECT_FRACTION {
            PoolAgreement::Diverges
        } else {
            PoolAgreement::Agrees
        }
    }

    /// True exactly ONCE, on the first transition into [`PoolAgreement::Diverges`].
    ///
    /// Lets the caller log a loud, actionable warning without spamming it on
    /// every subsequent share.
    pub fn take_new_divergence_alarm(&mut self) -> bool {
        if self.verdict() == PoolAgreement::Diverges && !self.alarm_raised {
            self.alarm_raised = true;
            true
        } else {
            false
        }
    }

    /// Operator-facing explanation of the current verdict. The scrypt arm
    /// names the `x65536` convention explicitly because that is the single
    /// most likely cause on a Litecoin pool.
    pub fn diagnosis(&self) -> &'static str {
        match self.verdict() {
            PoolAgreement::Insufficient => "not enough resolved shares to judge target agreement",
            PoolAgreement::Agrees => "pool accepts locally-validated shares; target math agrees",
            PoolAgreement::Diverges if self.algorithm_is_scrypt => {
                "pool rejects most locally-validated shares - the scrypt diff-1 convention \
                 probably disagrees (ltc-scale x65536 vs btc-scale). Verify on a test account \
                 before mining a real pool."
            }
            PoolAgreement::Diverges => {
                "pool rejects most locally-validated shares - check the share target math, \
                 job staleness, and the pool's difficulty units"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_verdict_before_the_minimum_sample_count() {
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Scrypt1024);
        for _ in 0..(AGREEMENT_MIN_SAMPLES - 1) {
            m.record(false);
        }
        assert_eq!(m.verdict(), PoolAgreement::Insufficient);
        assert!(
            !m.take_new_divergence_alarm(),
            "must not alarm on a short sample - a couple of stale rejects is normal"
        );
    }

    #[test]
    fn all_rejected_diverges_and_alarms_exactly_once() {
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Scrypt1024);
        for _ in 0..AGREEMENT_MIN_SAMPLES {
            m.record(false);
        }
        assert_eq!(m.verdict(), PoolAgreement::Diverges);
        assert!(m.take_new_divergence_alarm(), "first crossing alarms");
        assert!(
            !m.take_new_divergence_alarm(),
            "must not re-alarm (no spam)"
        );
        assert!(
            m.diagnosis().contains("65536"),
            "scrypt diagnosis names the scale"
        );
    }

    #[test]
    fn healthy_pool_with_some_stale_rejects_still_agrees() {
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Sha256d);
        for _ in 0..30 {
            m.record(true);
        }
        for _ in 0..3 {
            m.record(false);
        }
        assert_eq!(m.verdict(), PoolAgreement::Agrees);
        assert!(!m.take_new_divergence_alarm());
        assert_eq!(m.accepted(), 30);
        assert_eq!(m.rejected(), 3);
        assert_eq!(m.resolved(), 33);
    }

    #[test]
    fn exactly_at_the_threshold_is_not_a_divergence() {
        // 50 % rejects is the boundary; the check is strictly greater-than so
        // an exactly-half sample does not alarm.
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Sha256d);
        for _ in 0..(AGREEMENT_MIN_SAMPLES / 2) {
            m.record(true);
            m.record(false);
        }
        assert_eq!(m.resolved(), AGREEMENT_MIN_SAMPLES);
        assert_eq!(m.verdict(), PoolAgreement::Agrees);
    }

    #[test]
    fn reset_clears_counters_and_the_alarm_latch() {
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Scrypt1024);
        for _ in 0..AGREEMENT_MIN_SAMPLES {
            m.record(false);
        }
        assert!(m.take_new_divergence_alarm());
        m.reset();
        assert_eq!(m.resolved(), 0);
        assert_eq!(m.verdict(), PoolAgreement::Insufficient);
        for _ in 0..AGREEMENT_MIN_SAMPLES {
            m.record(false);
        }
        assert!(
            m.take_new_divergence_alarm(),
            "a fresh session must be able to alarm again"
        );
    }

    #[test]
    fn sha256d_diagnosis_does_not_mention_the_scrypt_scale() {
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Sha256d);
        for _ in 0..AGREEMENT_MIN_SAMPLES {
            m.record(false);
        }
        assert_eq!(m.verdict(), PoolAgreement::Diverges);
        assert!(!m.diagnosis().contains("65536"));
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut m = PoolAgreementMonitor::new(PowAlgorithm::Sha256d);
        for _ in 0..3 {
            m.record(true);
        }
        m.accepted = u32::MAX;
        m.record(true);
        assert_eq!(m.accepted(), u32::MAX, "saturating, never wrap to 0");
    }
}
