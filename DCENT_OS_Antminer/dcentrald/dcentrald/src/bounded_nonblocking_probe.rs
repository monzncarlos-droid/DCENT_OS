//! Shared bounded observation for move-only, nonblocking lifecycle probes.
//!
//! Hardware revocation must close admission synchronously, then observe any
//! already-entered commit without parking a Tokio worker or abandoning a
//! blocking-pool waiter. This helper owns only that observation policy. It does
//! not decide whether later terminal safe-off work may be skipped when the
//! observation budget expires.

use std::time::{Duration, Instant};

/// One nonblocking observation of a move-only pending state.
#[derive(Debug)]
pub(crate) enum NonblockingProbe<S, T> {
    Pending(S),
    Ready {
        value: T,
        /// Authoritative completion time minted by the observed domain.
        completed_at: Instant,
    },
}

/// Deadline classification for a nonblocking observation loop.
#[derive(Debug)]
pub(crate) enum BoundedProbeOutcome<S, T> {
    Timely(T),
    DeadlineExceeded { pending: S },
    CompletedAfterDeadline(T),
}

/// Repeatedly probe `pending` without blocking until it completes or the
/// absolute monotonic `deadline` expires.
///
/// Completion is timely only when the domain-minted timestamp is strictly
/// earlier than the deadline. The pre-probe deadline check and biased deadline
/// branch ensure a callback or scheduler delay cannot cause another probe
/// after the observation budget has expired.
pub(crate) async fn observe_nonblocking_until<S, T, F>(
    mut pending: S,
    deadline: tokio::time::Instant,
    poll_interval: Duration,
    mut probe: F,
) -> BoundedProbeOutcome<S, T>
where
    F: FnMut(S) -> NonblockingProbe<S, T>,
{
    assert!(
        !poll_interval.is_zero(),
        "bounded nonblocking probe interval must be non-zero"
    );
    loop {
        if tokio::time::Instant::now() >= deadline {
            return BoundedProbeOutcome::DeadlineExceeded { pending };
        }
        pending = match probe(pending) {
            NonblockingProbe::Pending(pending) => pending,
            NonblockingProbe::Ready {
                value,
                completed_at,
            } => {
                return if completed_at < deadline.into_std() {
                    BoundedProbeOutcome::Timely(value)
                } else {
                    BoundedProbeOutcome::CompletedAfterDeadline(value)
                };
            }
        };
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                return BoundedProbeOutcome::DeadlineExceeded { pending };
            }
            _ = tokio::time::sleep(poll_interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn immediate_completion_preserves_value_and_strict_timestamp() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let completed_at = deadline.into_std() - Duration::from_millis(1);

        let outcome =
            observe_nonblocking_until("pending", deadline, Duration::from_millis(10), |state| {
                NonblockingProbe::Ready {
                    value: state.len(),
                    completed_at,
                }
            })
            .await;

        assert!(matches!(outcome, BoundedProbeOutcome::Timely(7)));
    }

    #[tokio::test]
    async fn completion_at_deadline_is_not_timely() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);

        let outcome =
            observe_nonblocking_until(17_u8, deadline, Duration::from_millis(10), |state| {
                NonblockingProbe::Ready {
                    value: state,
                    completed_at: deadline.into_std(),
                }
            })
            .await;

        assert!(matches!(
            outcome,
            BoundedProbeOutcome::CompletedAfterDeadline(17)
        ));
    }

    #[tokio::test]
    async fn pending_state_is_returned_and_never_probed_after_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        let probes = AtomicUsize::new(0);

        let outcome =
            observe_nonblocking_until(0_usize, deadline, Duration::from_millis(5), |state| {
                probes.fetch_add(1, Ordering::SeqCst);
                NonblockingProbe::<usize, ()>::Pending(state + 1)
            })
            .await;
        let probes_at_return = probes.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(10)).await;

        match outcome {
            BoundedProbeOutcome::DeadlineExceeded { pending } => {
                assert_eq!(pending, probes_at_return);
                assert!(pending > 0);
            }
            other => panic!("pending probe unexpectedly completed: {other:?}"),
        }
        assert_eq!(probes.load(Ordering::SeqCst), probes_at_return);
    }
}
