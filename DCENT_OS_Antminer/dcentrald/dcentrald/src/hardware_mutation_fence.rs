//! Bounded async observation for the runtime-neutral HAL mutation fence.
//!
//! HAL closes admission synchronously and exposes only a nonblocking probe.
//! Keeping Tokio here prevents a wedged physical commit from retaining an
//! unabortable blocking-pool waiter or stalling runtime destruction.

use std::time::Duration;

use crate::bounded_nonblocking_probe::{
    observe_nonblocking_until, BoundedProbeOutcome, NonblockingProbe,
};
use anyhow::Result;
use dcentrald_hal::platform::{
    HardwareMutationCommitFenceReceipt, HardwareMutationCommitFenceTryWait,
    RevokedHardwareMutationCommitFence,
};
use tracing::error;

const HARDWARE_MUTATION_FENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub(crate) enum HardwareMutationCommitFenceWaitOutcome {
    TimelyFenced(HardwareMutationCommitFenceReceipt),
    DeadlineExceeded {
        fence: RevokedHardwareMutationCommitFence,
    },
    QuiescentAfterDeadline(HardwareMutationCommitFenceReceipt),
}

pub(crate) async fn wait_revoked_hardware_mutation_commit_fence(
    fence: RevokedHardwareMutationCommitFence,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
    lifecycle_scope: &'static str,
) -> Result<HardwareMutationCommitFenceReceipt> {
    require_timely_hardware_mutation_commit_fence(
        observe_revoked_hardware_mutation_commit_fence(fence, deadline).await,
        started,
        deadline,
        lifecycle_scope,
    )
}

async fn observe_revoked_hardware_mutation_commit_fence(
    fence: RevokedHardwareMutationCommitFence,
    deadline: tokio::time::Instant,
) -> HardwareMutationCommitFenceWaitOutcome {
    observe_revoked_hardware_mutation_commit_fence_with_post_pending_probe(fence, deadline, || {})
        .await
}

async fn observe_revoked_hardware_mutation_commit_fence_with_post_pending_probe<F>(
    mut fence: RevokedHardwareMutationCommitFence,
    deadline: tokio::time::Instant,
    mut post_pending_probe: F,
) -> HardwareMutationCommitFenceWaitOutcome
where
    F: FnMut(),
{
    match observe_nonblocking_until(
        fence,
        deadline,
        HARDWARE_MUTATION_FENCE_POLL_INTERVAL,
        |fence| match fence.try_wait() {
            HardwareMutationCommitFenceTryWait::Fenced(receipt) => NonblockingProbe::Ready {
                completed_at: receipt.fenced_at(),
                value: receipt,
            },
            HardwareMutationCommitFenceTryWait::Pending(fence) => {
                post_pending_probe();
                NonblockingProbe::Pending(fence)
            }
        },
    )
    .await
    {
        BoundedProbeOutcome::Timely(receipt) => {
            HardwareMutationCommitFenceWaitOutcome::TimelyFenced(receipt)
        }
        BoundedProbeOutcome::DeadlineExceeded { pending } => {
            HardwareMutationCommitFenceWaitOutcome::DeadlineExceeded { fence: pending }
        }
        BoundedProbeOutcome::CompletedAfterDeadline(receipt) => {
            HardwareMutationCommitFenceWaitOutcome::QuiescentAfterDeadline(receipt)
        }
    }
}

fn require_timely_hardware_mutation_commit_fence(
    outcome: HardwareMutationCommitFenceWaitOutcome,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
    lifecycle_scope: &str,
) -> Result<HardwareMutationCommitFenceReceipt> {
    let deadline_duration = deadline.saturating_duration_since(started);
    match outcome {
        HardwareMutationCommitFenceWaitOutcome::TimelyFenced(receipt) => {
            if receipt.fence_poisoned() {
                let closed_generation = receipt.closed_generation();
                error!(
                    lifecycle_scope,
                    closed_generation,
                    deadline_ms = deadline_duration.as_millis(),
                    elapsed_ms = started.elapsed().as_millis(),
                    mutation_admission_revoked = true,
                    commit_fence_state = "quiescent_but_poisoned",
                    entered_commit_state = "unwound_with_possible_partial_side_effect",
                    fence_poisoned = true,
                    detached_waiter = false,
                    "hardware mutation commit fence is quiescent but cannot support clean shutdown"
                );
                anyhow::bail!(
                    "{lifecycle_scope} hardware-mutation generation {closed_generation} became quiescent after a commit panic; terminal safe-off remains mandatory and clean watchdog disarm is forbidden"
                )
            }
            Ok(receipt)
        }
        HardwareMutationCommitFenceWaitOutcome::DeadlineExceeded { fence } => {
            let closed_generation = fence.closed_generation();
            error!(
                lifecycle_scope,
                closed_generation,
                deadline_ms = deadline_duration.as_millis(),
                elapsed_ms = started.elapsed().as_millis(),
                mutation_admission_revoked = true,
                commit_fence_state = "no_timely_quiescence_observation",
                entered_commit_state = "unknown",
                detached_waiter = false,
                "hardware mutation commit fence exceeded its bounded nonblocking wait"
            );
            anyhow::bail!(
                "{lifecycle_scope} hardware-mutation generation {closed_generation} was revoked, but its commit fence produced no timely quiescence evidence within {} ms; no blocking waiter was detached",
                deadline_duration.as_millis()
            )
        }
        HardwareMutationCommitFenceWaitOutcome::QuiescentAfterDeadline(receipt) => {
            let closed_generation = receipt.closed_generation();
            let fence_poisoned = receipt.fence_poisoned();
            error!(
                lifecycle_scope,
                closed_generation,
                deadline_ms = deadline_duration.as_millis(),
                elapsed_ms = started.elapsed().as_millis(),
                mutation_admission_revoked = true,
                commit_fence_state = "quiescent_after_deadline",
                entered_commit_state = "unknown",
                fence_poisoned,
                detached_waiter = false,
                "hardware mutation commit fence exceeded its bounded nonblocking wait"
            );
            anyhow::bail!(
                "{lifecycle_scope} hardware-mutation generation {closed_generation} was revoked, but commit-fence quiescence was first observed after its {} ms deadline (fence_poisoned={fence_poisoned}); no blocking waiter was detached",
                deadline_duration.as_millis()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_hal::platform::HardwareMutationGate;
    use std::sync::mpsc;

    #[test]
    fn bounded_hardware_mutation_fence_timeout_allows_runtime_drop_before_commit_release() {
        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();
        let (commit_entered_tx, commit_entered_rx) = mpsc::channel();
        let (release_commit_tx, release_commit_rx) = mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            lease
                .commit(|| {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("hardware mutation entered its final commit section");

        let revoked = gate.revoke_commit_fence();
        assert!(gate.try_acquire().is_err());
        let (release_after_runtime_tx, release_after_runtime_rx) = mpsc::channel();
        let safety_releaser = std::thread::spawn(move || {
            let released_after_runtime_drop = release_after_runtime_rx
                .recv_timeout(Duration::from_secs(5))
                .is_ok();
            release_commit_tx.send(()).unwrap();
            released_after_runtime_drop
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            let started = tokio::time::Instant::now();
            wait_revoked_hardware_mutation_commit_fence(
                revoked,
                started,
                started + Duration::from_millis(25),
                "runtime-drop fixture",
            )
            .await
        });
        assert!(result.is_err());
        drop(runtime);
        let _ = release_after_runtime_tx.send(());

        assert!(
            safety_releaser.join().unwrap(),
            "runtime drop waited for the held HAL commit until the five-second safety fallback"
        );
        commit_thread.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hardware_mutation_fence_never_probes_after_absolute_deadline() {
        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();
        let (commit_entered_tx, commit_entered_rx) = mpsc::channel();
        let (release_commit_tx, release_commit_rx) = mpsc::channel();
        let (commit_returned_tx, commit_returned_rx) = mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            lease
                .commit(|| {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            commit_returned_tx.send(()).unwrap();
        });
        commit_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let mut release_commit_tx = Some(release_commit_tx);
        let mut pending_probe_count = 0usize;
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_millis(25);

        let outcome = observe_revoked_hardware_mutation_commit_fence_with_post_pending_probe(
            gate.revoke_commit_fence(),
            deadline,
            || {
                pending_probe_count += 1;
                release_commit_tx.take().unwrap().send(()).unwrap();
                commit_returned_rx
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap();
                std::thread::sleep(Duration::from_millis(30));
            },
        )
        .await;

        assert!(matches!(
            outcome,
            HardwareMutationCommitFenceWaitOutcome::DeadlineExceeded { .. }
        ));
        if let Some(release_commit_tx) = release_commit_tx.take() {
            release_commit_tx.send(()).unwrap();
            commit_returned_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
        }
        assert!(
            pending_probe_count <= 1,
            "the fence was probed again after the callback crossed the deadline"
        );
        commit_thread.join().unwrap();
    }

    #[tokio::test]
    async fn poisoned_commit_fence_is_negative_clean_shutdown_evidence() {
        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lease.commit(|| -> dcentrald_hal::Result<()> {
                panic!("fixture hardware commit panic")
            });
        }));
        assert!(panic.is_err());

        let started = tokio::time::Instant::now();
        let error = wait_revoked_hardware_mutation_commit_fence(
            gate.revoke_commit_fence(),
            started,
            started + Duration::from_secs(1),
            "poison fixture",
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("clean watchdog disarm is forbidden"));
    }
}
