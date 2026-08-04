//! Finite Stratum V1 work-domain allocation.
//!
//! A pool subscription assigns an exact extranonce2 width. That creates a
//! finite domain of `2^(8 * width)` values. The allocator below emits every
//! value at most once, emits the maximum value once, and then enters an
//! irreversible exhausted state. It is shared by every clone of a V1
//! [`JobTemplate`](crate::types::JobTemplate), so parallel hash chains and
//! non-adjacent notify replays cannot start independent counters inside the
//! same subscription-parameter namespace.

use crate::types::{is_valid_v1_extranonce2_size, MAX_V1_EXTRANONCE2_SIZE};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::mpsc;

/// Internal identity for a pool subscription and an accepted job generation.
///
/// The pool wire still uses `(job_id, extranonce2)`. This identity prevents
/// reused pool job IDs, reconnect races, and mid-session parameter rotations
/// from aliasing internal work or late shares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct WorkGeneration {
    pub session: u64,
    pub job: u64,
}

impl WorkGeneration {
    /// Sentinel for protocol paths that do not use a V1 extranonce2 domain.
    pub const UNTRACKED: Self = Self { session: 0, job: 0 };
}

/// Exact finite-domain exhaustion report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "Stratum V1 extranonce2 exhausted for session {generation_session}, job {generation_job}, width {extranonce2_size}"
)]
pub struct Extranonce2Exhausted {
    pub generation_session: u64,
    pub generation_job: u64,
    pub extranonce2_size: usize,
}

impl Extranonce2Exhausted {
    pub fn generation(self) -> WorkGeneration {
        WorkGeneration {
            session: self.generation_session,
            job: self.generation_job,
        }
    }
}

/// Work-construction failures that must never degrade into truncation or reuse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WorkBuildError {
    #[error("invalid Stratum V1 extranonce2 width {0}; expected 1..={MAX_V1_EXTRANONCE2_SIZE}")]
    InvalidExtranonce2Size(usize),
    #[error("extranonce2 value {value} exceeds {width}-byte domain maximum {max}")]
    Extranonce2OutOfDomain { value: u64, width: usize, max: u64 },
    #[error("V1 job {0:?} has no shared extranonce2 work domain")]
    MissingV1WorkDomain(WorkGeneration),
    #[error(
        "V1 job {job:?} carries mismatched work domain {domain:?} at width {domain_width} (job width {job_width})"
    )]
    MismatchedV1WorkDomain {
        job: WorkGeneration,
        domain: WorkGeneration,
        job_width: usize,
        domain_width: usize,
    },
    #[error("V1 work generation {requested:?} was superseded by active generation {active:?}")]
    SupersededV1WorkGeneration {
        requested: WorkGeneration,
        active: WorkGeneration,
    },
    #[error(
        "invalid V1 work-domain rotation from {current:?} to {requested:?}; the session must stay fixed and the job generation must increase"
    )]
    InvalidV1WorkGenerationRotation {
        current: WorkGeneration,
        requested: WorkGeneration,
    },
    #[error(transparent)]
    Extranonce2Exhausted(#[from] Extranonce2Exhausted),
}

/// Typed reverse signal from the finite allocator to the V1 session owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V1WorkControl {
    Extranonce2Exhausted(Extranonce2Exhausted),
}

#[derive(Debug)]
struct DomainState {
    generation: WorkGeneration,
    next: Option<u64>,
    max: u64,
    exhaustion_signaled: bool,
}

/// One shared, finite extranonce2 domain for one V1 subscription namespace.
///
/// Its active job generation rotates monotonically without rewinding the
/// cursor, invalidating stale builders while retaining global uniqueness.
#[derive(Debug)]
pub struct V1WorkDomain {
    extranonce2_size: usize,
    state: Mutex<DomainState>,
    control_tx: mpsc::UnboundedSender<V1WorkControl>,
}

impl V1WorkDomain {
    pub(crate) fn new(
        generation: WorkGeneration,
        extranonce2_size: usize,
        control_tx: mpsc::UnboundedSender<V1WorkControl>,
    ) -> Result<Arc<Self>, WorkBuildError> {
        if !is_valid_v1_extranonce2_size(extranonce2_size) {
            return Err(WorkBuildError::InvalidExtranonce2Size(extranonce2_size));
        }
        let max = if extranonce2_size == MAX_V1_EXTRANONCE2_SIZE {
            u64::MAX
        } else {
            (1u64 << (extranonce2_size * 8)) - 1
        };
        Ok(Arc::new(Self {
            extranonce2_size,
            state: Mutex::new(DomainState {
                generation,
                next: Some(0),
                max,
                exhaustion_signaled: false,
            }),
            control_tx,
        }))
    }

    pub fn generation(&self) -> WorkGeneration {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation
    }

    pub fn extranonce2_size(&self) -> usize {
        self.extranonce2_size
    }

    /// Allocate the next exact-width little-endian extranonce2.
    ///
    /// The maximum domain value is returned once. Every later call returns the
    /// same typed exhaustion error and never changes state back to ready.
    pub(crate) fn allocate_hex_for(
        &self,
        expected_generation: WorkGeneration,
    ) -> Result<String, WorkBuildError> {
        let value = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if expected_generation != state.generation {
                return Err(WorkBuildError::SupersededV1WorkGeneration {
                    requested: expected_generation,
                    active: state.generation,
                });
            }
            let Some(value) = state.next else {
                let exhausted = Extranonce2Exhausted {
                    generation_session: state.generation.session,
                    generation_job: state.generation.job,
                    extranonce2_size: self.extranonce2_size,
                };
                let signal = if state.exhaustion_signaled {
                    None
                } else {
                    state.exhaustion_signaled = true;
                    Some(exhausted)
                };
                drop(state);
                if let Some(exhausted) = signal {
                    let _ = self
                        .control_tx
                        .send(V1WorkControl::Extranonce2Exhausted(exhausted));
                }
                return Err(exhausted.into());
            };
            state.next = if value == state.max {
                None
            } else {
                Some(value + 1)
            };
            value
        };

        let bytes = value.to_le_bytes();
        Ok(hex::encode(&bytes[..self.extranonce2_size]))
    }

    /// Rotate the share-validity epoch while retaining the one linear EN2
    /// cursor. Old `JobTemplate` clones fail closed after this method returns.
    pub(crate) fn rotate_generation_preserving_cursor(
        &self,
        requested: WorkGeneration,
    ) -> Result<(), WorkBuildError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = state.generation;
        if requested.session != current.session || requested.job <= current.job {
            return Err(WorkBuildError::InvalidV1WorkGenerationRotation { current, requested });
        }
        state.generation = requested;
        // If the cursor was already exhausted, the next attempted allocation
        // must signal exhaustion for this active epoch. A queued report for the
        // old epoch will be ignored by the client as stale.
        state.exhaustion_signaled = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn domain(width: usize) -> (Arc<V1WorkDomain>, mpsc::UnboundedReceiver<V1WorkControl>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            V1WorkDomain::new(
                WorkGeneration {
                    session: 7,
                    job: 11,
                },
                width,
                tx,
            )
            .unwrap(),
            rx,
        )
    }

    #[test]
    fn width_one_emits_all_256_values_once_then_stays_exhausted() {
        let (domain, mut rx) = domain(1);
        let generation = domain.generation();
        let mut seen = HashSet::new();
        for _ in 0..=u8::MAX {
            seen.insert(domain.allocate_hex_for(generation).unwrap());
        }
        assert_eq!(seen.len(), 256);
        assert_eq!(
            domain.allocate_hex_for(generation).unwrap_err(),
            domain.allocate_hex_for(generation).unwrap_err()
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            V1WorkControl::Extranonce2Exhausted(Extranonce2Exhausted {
                generation_session: 7,
                generation_job: 11,
                extranonce2_size: 1,
            })
        );
        assert!(
            rx.try_recv().is_err(),
            "exhaustion is signaled exactly once"
        );
    }

    #[test]
    fn every_width_emits_its_maximum_once_without_incrementing_it() {
        for width in 1..=MAX_V1_EXTRANONCE2_SIZE {
            let (tx, _rx) = mpsc::unbounded_channel();
            let max = if width == 8 {
                u64::MAX
            } else {
                (1u64 << (width * 8)) - 1
            };
            let domain = V1WorkDomain {
                extranonce2_size: width,
                state: Mutex::new(DomainState {
                    generation: WorkGeneration { session: 1, job: 1 },
                    next: Some(max),
                    max,
                    exhaustion_signaled: false,
                }),
                control_tx: tx,
            };
            let generation = domain.generation();
            let expected = hex::encode(&max.to_le_bytes()[..width]);
            assert_eq!(domain.allocate_hex_for(generation).unwrap(), expected);
            assert!(matches!(
                domain.allocate_hex_for(generation),
                Err(WorkBuildError::Extranonce2Exhausted(_))
            ));
            assert!(matches!(
                domain.allocate_hex_for(generation),
                Err(WorkBuildError::Extranonce2Exhausted(_))
            ));
        }
    }

    #[test]
    fn clones_share_one_domain_instead_of_restarting_at_zero() {
        let (domain, _rx) = domain(2);
        let other_chain = Arc::clone(&domain);
        let generation = domain.generation();
        assert_eq!(domain.allocate_hex_for(generation).unwrap(), "0000");
        assert_eq!(other_chain.allocate_hex_for(generation).unwrap(), "0100");
        assert_eq!(domain.allocate_hex_for(generation).unwrap(), "0200");
    }

    #[test]
    fn generation_rotation_revokes_old_clones_without_restarting_cursor() {
        let (domain, _rx) = domain(1);
        let old_generation = domain.generation();
        assert_eq!(domain.allocate_hex_for(old_generation).unwrap(), "00");

        let new_generation = WorkGeneration {
            session: old_generation.session,
            job: old_generation.job + 1,
        };
        domain
            .rotate_generation_preserving_cursor(new_generation)
            .unwrap();

        assert_eq!(
            domain.allocate_hex_for(old_generation),
            Err(WorkBuildError::SupersededV1WorkGeneration {
                requested: old_generation,
                active: new_generation,
            })
        );
        assert_eq!(
            domain.allocate_hex_for(new_generation).unwrap(),
            "01",
            "epoch rotation must preserve the next unallocated server-sized value"
        );
    }

    #[test]
    fn rejects_zero_and_oversized_widths() {
        for width in [0, MAX_V1_EXTRANONCE2_SIZE + 1, usize::MAX] {
            let (tx, _rx) = mpsc::unbounded_channel();
            assert!(matches!(
                V1WorkDomain::new(WorkGeneration::UNTRACKED, width, tx),
                Err(WorkBuildError::InvalidExtranonce2Size(actual)) if actual == width
            ));
        }
    }
}
