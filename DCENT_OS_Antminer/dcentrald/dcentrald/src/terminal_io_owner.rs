//! Process-wide owner lane for terminal hardware I/O that originates in
//! destructors.
//!
//! Rust destructors cannot `await`, and these guards are commonly dropped by
//! an async `?` path. Performing sysfs, GPIO, PWM, or controller traffic in the
//! destructor would therefore block a Tokio worker. The destructor instead
//! transfers a move-only job to this dedicated OS thread and returns. Normal
//! shutdown continues to use its explicit, awaited `spawn_blocking` path so
//! checked shutdown evidence is never minted from a merely queued operation.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::thread;

use tracing::{error, warn};

type TerminalIoTask = Box<dyn FnOnce() + Send + 'static>;

struct TerminalIoJob {
    operation: &'static str,
    task: TerminalIoTask,
}

const TERMINAL_IO_QUEUE_CAPACITY: usize = 16;

static TERMINAL_IO_OWNER: OnceLock<Option<SyncSender<TerminalIoJob>>> = OnceLock::new();

fn run_owner(receiver: Receiver<TerminalIoJob>) {
    while let Ok(job) = receiver.recv() {
        if catch_unwind(AssertUnwindSafe(job.task)).is_err() {
            error!(
                operation = job.operation,
                "terminal I/O owner caught a panicking cleanup job; continuing to serve later safety work"
            );
        }
    }
}

fn start_owner() -> Option<SyncSender<TerminalIoJob>> {
    let (sender, receiver) = mpsc::sync_channel(TERMINAL_IO_QUEUE_CAPACITY);
    match thread::Builder::new()
        .name("terminal-io-owner".to_string())
        .spawn(move || run_owner(receiver))
    {
        Ok(_owner) => Some(sender),
        Err(error) => {
            error!(%error, "failed to start the terminal I/O owner thread");
            None
        }
    }
}

/// Start the owner before a hardware guard can become armed. This keeps OS
/// thread creation out of the destructor's normal path.
pub(crate) fn prepare() {
    let _ = TERMINAL_IO_OWNER.get_or_init(start_owner);
}

/// Transfer terminal work away from the current executor without waiting for
/// physical I/O. The hardware watchdog remains the independent cutoff backstop
/// for this necessarily evidence-free destructor path.
pub(crate) fn dispatch(operation: &'static str, task: impl FnOnce() + Send + 'static) {
    let job = TerminalIoJob {
        operation,
        task: Box::new(task),
    };
    let owner = TERMINAL_IO_OWNER.get_or_init(start_owner);
    let job = match owner {
        Some(sender) => match sender.try_send(job) {
            Ok(()) => return,
            Err(TrySendError::Full(job)) => {
                warn!(
                    operation,
                    capacity = TERMINAL_IO_QUEUE_CAPACITY,
                    "terminal I/O owner queue is full; starting an isolated fallback owner"
                );
                job
            }
            Err(TrySendError::Disconnected(job)) => {
                warn!(
                    operation,
                    "terminal I/O owner disconnected; starting an isolated fallback owner"
                );
                job
            }
        },
        None => job,
    };

    // A prior owner-start failure must not discard an emergency cutoff. This
    // remains non-waiting for the caller and preserves single-job ownership.
    let fallback_operation = job.operation;
    if let Err(error) = thread::Builder::new()
        .name("terminal-io-fallback".to_string())
        .spawn(move || {
            if catch_unwind(AssertUnwindSafe(job.task)).is_err() {
                error!(
                    operation = fallback_operation,
                    "fallback terminal I/O owner caught a panicking cleanup job"
                );
            }
        })
    {
        error!(
            operation = fallback_operation,
            %error,
            "failed to start any terminal I/O owner; hardware watchdog remains armed"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::dispatch;

    #[test]
    fn destructor_work_runs_on_the_single_blocking_owner_in_submission_order() {
        let submitter = thread::current().id();
        let (sender, receiver) = mpsc::channel();

        for sequence in 0..3 {
            let sender = sender.clone();
            dispatch("test-terminal-cleanup", move || {
                sender
                    .send((sequence, thread::current().id()))
                    .expect("test receiver remains alive");
            });
        }

        for expected in 0..3 {
            let (observed, worker) = receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("terminal owner must run queued work");
            assert_eq!(observed, expected);
            assert_ne!(worker, submitter);
        }
    }
}
