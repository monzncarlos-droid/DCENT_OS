//! Transport-neutral serial-chain enumeration and bounded-work proof policy.
//!
//! These types generalize the pure accounting first proven by the S19k Pro
//! Track-1 runtime. They perform no I/O and grant no platform, electrical, or
//! mining admission. A platform runtime remains responsible for executing the
//! returned plan and for binding observations to an admitted physical route.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Bounded cadence and retry policy for a serial address-assignment ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacedEnumerationPolicy {
    step_delay: Duration,
    settle_delay: Duration,
    response_window: Duration,
    max_coverage_attempts: u8,
}

impl PacedEnumerationPolicy {
    /// Construct a non-zero, bounded enumeration policy.
    pub fn new(
        step_delay: Duration,
        settle_delay: Duration,
        response_window: Duration,
        max_coverage_attempts: u8,
    ) -> Result<Self, &'static str> {
        if step_delay.is_zero() {
            return Err("serial enumeration step delay must be nonzero");
        }
        if response_window.is_zero() {
            return Err("serial enumeration response window must be nonzero");
        }
        if max_coverage_attempts == 0 {
            return Err("serial enumeration must permit at least one coverage attempt");
        }
        Ok(Self {
            step_delay,
            settle_delay,
            response_window,
            max_coverage_attempts,
        })
    }

    pub const fn step_delay(self) -> Duration {
        self.step_delay
    }
    pub const fn settle_delay(self) -> Duration {
        self.settle_delay
    }
    pub const fn response_window(self) -> Duration {
        self.response_window
    }
    pub const fn max_coverage_attempts(self) -> u8 {
        self.max_coverage_attempts
    }
}

/// Exact coverage failure, retaining duplicates separately from missing slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCoverageError {
    pub expected_addresses: Vec<u8>,
    pub observed_addresses: Vec<u8>,
    pub missing_addresses: Vec<u8>,
    pub unexpected_addresses: Vec<u8>,
    pub duplicate_addresses: Vec<u8>,
}

impl std::fmt::Display for ChainCoverageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "serial address coverage incomplete: expected={:02X?}, observed={:02X?}, missing={:02X?}, unexpected={:02X?}, duplicate_addresses={:02X?}",
            self.expected_addresses, self.observed_addresses, self.missing_addresses,
            self.unexpected_addresses, self.duplicate_addresses)
    }
}

impl std::error::Error for ChainCoverageError {}

/// Certificate that every expected address appeared exactly once.
#[must_use = "coverage certification must be bound to the admitted chain"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCoverageCertificate {
    addresses: Vec<u8>,
}

impl ChainCoverageCertificate {
    pub fn certify(expected: &[u8], observed: &[u8]) -> Result<Self, ChainCoverageError> {
        let expected_set: BTreeSet<u8> = expected.iter().copied().collect();
        let mut counts = BTreeMap::<u8, usize>::new();
        for address in observed {
            *counts.entry(*address).or_default() += 1;
        }
        let observed_set: BTreeSet<u8> = counts.keys().copied().collect();
        let missing_addresses = expected_set.difference(&observed_set).copied().collect();
        let unexpected_addresses = observed_set.difference(&expected_set).copied().collect();
        let duplicate_addresses = counts
            .iter()
            .filter_map(|(address, count)| (*count > 1).then_some(*address))
            .collect();
        let error = ChainCoverageError {
            expected_addresses: expected.to_vec(),
            observed_addresses: observed.to_vec(),
            missing_addresses,
            unexpected_addresses,
            duplicate_addresses,
        };
        if expected.is_empty()
            || expected.len() != expected_set.len()
            || !error.missing_addresses.is_empty()
            || !error.unexpected_addresses.is_empty()
            || !error.duplicate_addresses.is_empty()
            || observed.len() != expected.len()
        {
            return Err(error);
        }
        Ok(Self {
            addresses: expected.to_vec(),
        })
    }

    pub fn addresses(&self) -> &[u8] {
        &self.addresses
    }
}

/// Return unclaimed plan addresses eligible for paced re-enrollment.
/// Off-plan responders make repair unsafe and return `None`.
pub fn re_enrollment_addresses(expected: &[u8], observed: &[u8]) -> Option<Vec<u8>> {
    let expected: BTreeSet<u8> = expected.iter().copied().collect();
    let observed: BTreeSet<u8> = observed.iter().copied().collect();
    observed
        .is_subset(&expected)
        .then(|| expected.difference(&observed).copied().collect())
}

/// Monotonic per-path work and response counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SerialPathHealth {
    pub committed_tx: u64,
    pub received_frames: u64,
    pub valid_nonces: u64,
    pub accepted_shares: u64,
}

impl SerialPathHealth {
    pub fn note_tx(&mut self) {
        self.committed_tx = self.committed_tx.saturating_add(1);
    }
    pub fn note_rx(&mut self) {
        self.received_frames = self.received_frames.saturating_add(1);
    }
    pub fn note_nonce(&mut self) {
        self.valid_nonces = self.valid_nonces.saturating_add(1);
    }
    pub fn note_accepted_share(&mut self) {
        self.accepted_shares = self.accepted_shares.saturating_add(1);
    }
    pub const fn rx_silent_after_tx(&self) -> bool {
        self.committed_tx > 0 && self.received_frames == 0
    }
}

/// Accepted-share accounting that requires every configured physical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedWorkProof {
    required_paths: BTreeSet<String>,
    accepted_paths: BTreeSet<String>,
}

impl BoundedWorkProof {
    pub fn new(paths: impl IntoIterator<Item = impl Into<String>>) -> Result<Self, &'static str> {
        let required_paths: BTreeSet<String> = paths.into_iter().map(Into::into).collect();
        if required_paths.is_empty() {
            return Err("bounded work proof requires at least one path");
        }
        Ok(Self {
            required_paths,
            accepted_paths: BTreeSet::new(),
        })
    }
    pub fn note_accepted(&mut self, path: &str) -> Result<bool, &'static str> {
        if !self.required_paths.contains(path) {
            return Err("accepted share came from an unrequired path");
        }
        self.accepted_paths.insert(path.to_owned());
        Ok(self.is_complete())
    }
    pub fn is_complete(&self) -> bool {
        self.accepted_paths == self.required_paths
    }
    pub fn missing_paths(&self) -> Vec<&str> {
        self.required_paths
            .difference(&self.accepted_paths)
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_renders_duplicates_and_missing_addresses() {
        let error = ChainCoverageCertificate::certify(&[0, 2, 4], &[0, 2, 2]).unwrap_err();
        assert_eq!(error.missing_addresses, vec![4]);
        assert_eq!(error.duplicate_addresses, vec![2]);
        assert!(error.to_string().contains("duplicate_addresses=[02]"));
    }

    #[test]
    fn reenrollment_refuses_off_plan_responders() {
        assert_eq!(re_enrollment_addresses(&[0, 2, 4], &[0]), Some(vec![2, 4]));
        assert_eq!(re_enrollment_addresses(&[0, 2, 4], &[0, 3]), None);
    }

    #[test]
    fn bounded_work_needs_acceptance_from_every_required_path() {
        let mut proof = BoundedWorkProof::new(["ttyS1", "ttyS2"]).unwrap();
        assert!(!proof.note_accepted("ttyS1").unwrap());
        assert_eq!(proof.missing_paths(), vec!["ttyS2"]);
        assert!(proof.note_accepted("ttyS2").unwrap());
        assert!(proof.is_complete());
    }

    #[test]
    fn health_distinguishes_tx_only_from_returning_work() {
        let mut health = SerialPathHealth::default();
        health.note_tx();
        assert!(health.rx_silent_after_tx());
        health.note_rx();
        health.note_nonce();
        assert!(!health.rx_silent_after_tx());
        assert_eq!(health.valid_nonces, 1);
    }
}
