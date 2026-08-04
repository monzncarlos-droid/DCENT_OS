//! Measured runtime execution commit authority.
//!
//! This domain is intentionally separate from API/recovery hardware-mutation
//! admission. It fences hardware writes performed by the mining engine and its
//! owned workers against composition revocation and terminal safe-off.

use crate::execution_fence::{
    execution_fence_domain, ExecutionCommitError, ExecutionFenceIdentity, ExecutionFencePort,
    ExecutionFenceReceipt, ExecutionFenceTerminal, RevokedExecutionFence,
};
use dcentrald_api::HardwareCompositionToken;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Cloneable, generation-bound capability for final mining-runtime commits.
///
/// Only the measured composition admission path can create this port. Clones
/// remain bound to the same immutable composition token and all become stale
/// when the terminal side closes the domain.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeExecutionCommitPort {
    inner: ExecutionFencePort<HardwareCompositionToken>,
    generation: u64,
    active_generation: Arc<AtomicU64>,
}

impl RuntimeExecutionCommitPort {
    pub(crate) fn commit<R, E>(
        &self,
        operation: &'static str,
        mutation: impl FnOnce() -> Result<R, E>,
    ) -> Result<R, ExecutionCommitError>
    where
        E: fmt::Display,
    {
        self.inner.commit_if(
            operation,
            || self.active_generation.load(Ordering::Acquire) == self.generation,
            mutation,
        )
    }
}

/// Terminal side of one measured execution domain.
///
/// Clones are retained only by the composition authority and its move-only
/// lifetime session. Closing any clone is irreversible for every commit port.
pub(crate) type RuntimeExecutionTerminal = ExecutionFenceTerminal<HardwareCompositionToken>;
pub(crate) type RuntimeExecutionCommitError = ExecutionCommitError;
pub(crate) type RuntimeExecutionFenceReceipt = ExecutionFenceReceipt<HardwareCompositionToken>;
pub(crate) type RevokedRuntimeExecutionFence = RevokedExecutionFence<HardwareCompositionToken>;

impl ExecutionFenceIdentity for HardwareCompositionToken {
    fn execution_identity(&self) -> String {
        format!("{} ({})", self.generation, self.fingerprint)
    }
}

pub(crate) fn runtime_execution_domain(
    token: HardwareCompositionToken,
    active_generation: Arc<AtomicU64>,
) -> (RuntimeExecutionCommitPort, RuntimeExecutionTerminal) {
    let generation = token.generation;
    let (inner, terminal) = execution_fence_domain(token);
    (
        RuntimeExecutionCommitPort {
            inner,
            generation,
            active_generation,
        },
        terminal,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_fence::ExecutionFenceTryWait;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    fn token(generation: u64) -> HardwareCompositionToken {
        HardwareCompositionToken::new(generation, format!("chains:6:63:g{generation}"))
    }

    fn domain(
        token: HardwareCompositionToken,
    ) -> (RuntimeExecutionCommitPort, RuntimeExecutionTerminal) {
        let active_generation = Arc::new(AtomicU64::new(token.generation));
        runtime_execution_domain(token, active_generation)
    }

    #[test]
    fn terminal_close_rejects_a_later_commit_without_running_its_closure() {
        let (port, terminal) = domain(token(17));
        let receipt = match terminal.revoke().try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Fenced(receipt) => receipt,
            ExecutionFenceTryWait::Pending(_) => panic!("idle execution fence remained busy"),
        };
        let executed = std::sync::atomic::AtomicBool::new(false);

        let error = port
            .commit("late work send", || -> Result<(), &'static str> {
                executed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();

        assert_eq!(receipt.token().generation, 17);
        assert_eq!(receipt.token().fingerprint, "chains:6:63:g17");
        assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(error
            .to_string()
            .contains("is closed; refusing late work send"));
    }

    #[test]
    fn entered_commit_finishes_before_terminal_fence_receipt() {
        let (port, terminal) = domain(token(23));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let commit_thread = thread::spawn(move || {
            port.commit("bounded FPGA write", || -> Result<(), &'static str> {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        entered_rx.recv().unwrap();

        let pending = match terminal.revoke().try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Pending(pending) => pending,
            ExecutionFenceTryWait::Fenced(_) => {
                panic!("entered execution commit unexpectedly appeared quiescent")
            }
        };
        release_tx.send(()).unwrap();
        commit_thread.join().unwrap().unwrap();
        let receipt = match pending.try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Fenced(receipt) => receipt,
            ExecutionFenceTryWait::Pending(_) => {
                panic!("returned execution commit remained unexpectedly busy")
            }
        };

        assert_eq!(receipt.token().generation, 23);
        assert!(receipt.fenced_at() <= Instant::now());
    }

    #[test]
    fn independent_runtime_commits_are_not_serialized_in_steady_state() {
        let (port, _terminal) = domain(token(27));
        let first_port = port.clone();
        let second_port = port;
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first = thread::spawn(move || {
            first_port.commit(
                "first independent commit",
                || -> Result<(), &'static str> {
                    first_entered_tx.send(()).unwrap();
                    release_first_rx.recv().unwrap();
                    Ok(())
                },
            )
        });
        first_entered_rx.recv().unwrap();

        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            second_port.commit(
                "second independent commit",
                || -> Result<(), &'static str> {
                    second_entered_tx.send(()).unwrap();
                    Ok(())
                },
            )
        });
        second_entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("read-side commit fence must preserve steady-state concurrency");

        release_first_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    }

    #[test]
    fn operation_failure_preserves_context() {
        let (port, _terminal) = domain(token(29));
        let error = port
            .commit("PLL write", || -> Result<(), &'static str> {
                Err("UART timeout")
            })
            .unwrap_err();

        assert_eq!(error.to_string(), "PLL write failed: UART timeout");
    }
}
