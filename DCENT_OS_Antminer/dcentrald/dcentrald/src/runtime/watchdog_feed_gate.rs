//! Linearization boundary for physical hardware-watchdog feeds.
//!
//! Control-channel priority is not sufficient to stop a late watchdog kick:
//! cancellation or a terminal deadline can become visible after a worker has
//! selected a ready timer tick but before it enters the device write. This
//! gate serializes terminal closure and the physical kick under one non-async
//! mutex. Absolute feed-deadline publication is deliberately lock-free: a
//! blocked kernel watchdog write must never delay a load-bearing rail cutoff.
//! Once `close_terminal` returns, no later kick can begin.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchdogFeedOutcome {
    Kicked,
    WithheldTerminal,
    WithheldDeadline,
    WithheldPoisoned,
}

#[derive(Debug, Default)]
struct WatchdogFeedState {
    terminally_closed: bool,
}

/// Cloneable stop-only capability for crash paths that cannot wait for a
/// physical watchdog write already admitted by the feed gate. Publication is
/// lock-free and irreversible. It cannot kick or disarm the watchdog.
#[derive(Debug, Clone)]
pub(crate) struct WatchdogFeedStopSignal {
    terminal_intent: Arc<AtomicBool>,
}

impl WatchdogFeedStopSignal {
    pub(crate) fn close_terminal_lock_free(&self) {
        self.terminal_intent.store(true, Ordering::SeqCst);
    }
}

/// Worker-side handle. Cloning it does not create terminal authority.
#[derive(Debug, Clone)]
pub(crate) struct WatchdogFeedGate {
    state: Arc<Mutex<WatchdogFeedState>>,
    terminal_intent: Arc<AtomicBool>,
    deadline_request: Arc<OnceLock<Instant>>,
}

/// Sole lifecycle owner. Drop is a synchronous fail-closed publication.
#[derive(Debug)]
pub(crate) struct WatchdogFeedGateOwner {
    gate: WatchdogFeedGate,
}

impl WatchdogFeedGateOwner {
    pub(crate) fn new() -> Self {
        let terminal_intent = Arc::new(AtomicBool::new(false));
        Self {
            gate: WatchdogFeedGate {
                state: Arc::new(Mutex::new(WatchdogFeedState::default())),
                terminal_intent,
                deadline_request: Arc::new(OnceLock::new()),
            },
        }
    }

    pub(crate) fn gate(&self) -> WatchdogFeedGate {
        self.gate.clone()
    }

    /// Publish the immutable absolute feed deadline without acquiring the
    /// physical-kick mutex. This remains legal after a stop-only terminal
    /// signal: recording teardown timing must not reopen feeding, and typed
    /// closeout must not abort merely because an emergency already withheld
    /// every kick. A matching replay is allowed; every contradictory replay is
    /// refused because this is a one-shot teardown boundary.
    pub(crate) fn publish_deadline(&self, deadline: Instant) -> Result<(), &'static str> {
        self.gate.publish_deadline(deadline)
    }

    pub(crate) fn deadline_request(&self) -> Arc<OnceLock<Instant>> {
        Arc::clone(&self.gate.deadline_request)
    }

    pub(crate) fn stop_signal(&self) -> WatchdogFeedStopSignal {
        WatchdogFeedStopSignal {
            terminal_intent: Arc::clone(&self.gate.terminal_intent),
        }
    }

    pub(crate) fn close_terminal(&self) {
        self.gate.close_terminal();
    }

    #[cfg(test)]
    pub(crate) fn is_terminally_closed(&self) -> bool {
        self.gate.is_terminally_closed()
    }
}

impl Drop for WatchdogFeedGateOwner {
    fn drop(&mut self) {
        self.close_terminal();
    }
}

impl WatchdogFeedGate {
    fn publish_deadline(&self, deadline: Instant) -> Result<(), &'static str> {
        match self.deadline_request.set(deadline) {
            Ok(()) => Ok(()),
            Err(replayed) if self.deadline_request.get() == Some(&replayed) => Ok(()),
            Err(_) => Err("watchdog feed deadline replacement was refused"),
        }
    }

    pub(crate) fn close_terminal(&self) {
        self.terminal_intent.store(true, Ordering::SeqCst);
        match self.state.lock() {
            Ok(mut state) => state.terminally_closed = true,
            Err(poisoned) => poisoned.into_inner().terminally_closed = true,
        }
    }

    /// Hold the gate across the actual device operation. The kick therefore
    /// linearizes before or after terminal closure; it can never straddle a
    /// completed closure publication.
    pub(crate) fn try_kick<E>(
        &self,
        kick: impl FnOnce() -> Result<(), E>,
    ) -> Result<WatchdogFeedOutcome, E> {
        self.try_kick_at(Instant::now, kick)
    }

    fn try_kick_at<E>(
        &self,
        physical_now: impl FnOnce() -> Instant,
        kick: impl FnOnce() -> Result<(), E>,
    ) -> Result<WatchdogFeedOutcome, E> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Ok(WatchdogFeedOutcome::WithheldPoisoned),
        };
        if state.terminally_closed || self.terminal_intent.load(Ordering::SeqCst) {
            state.terminally_closed = true;
            return Ok(WatchdogFeedOutcome::WithheldTerminal);
        }
        // Sample time only after acquiring the same lock held across the
        // physical write. A timestamp captured by the caller before lock
        // contention could otherwise authorize a post-deadline kick.
        let now = physical_now();
        if self
            .deadline_request
            .get()
            .is_some_and(|deadline| now >= *deadline)
        {
            state.terminally_closed = true;
            self.terminal_intent.store(true, Ordering::SeqCst);
            return Ok(WatchdogFeedOutcome::WithheldDeadline);
        }
        kick()?;
        Ok(WatchdogFeedOutcome::Kicked)
    }

    #[cfg(test)]
    fn is_terminally_closed(&self) -> bool {
        if self.terminal_intent.load(Ordering::SeqCst) {
            return true;
        }
        match self.state.lock() {
            Ok(state) => state.terminally_closed,
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn terminal_close_and_physical_kick_share_one_linearization_boundary() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let kicks = Arc::new(AtomicUsize::new(0));
        let worker = {
            let gate = gate.clone();
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let kicks = Arc::clone(&kicks);
            thread::spawn(move || {
                gate.try_kick(|| -> Result<(), ()> {
                    entered.wait();
                    release.wait();
                    kicks.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap()
            })
        };
        entered.wait();
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = thread::spawn(move || {
            owner.close_terminal();
            closed_tx.send(()).unwrap();
        });
        assert!(closed_rx.recv_timeout(Duration::from_millis(20)).is_err());
        release.wait();
        assert_eq!(worker.join().unwrap(), WatchdogFeedOutcome::Kicked);
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        closer.join().unwrap();
        assert_eq!(kicks.load(Ordering::SeqCst), 1);
        assert_eq!(
            gate.try_kick(|| -> Result<(), ()> {
                kicks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap(),
            WatchdogFeedOutcome::WithheldTerminal
        );
        assert_eq!(kicks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn absolute_deadline_latches_terminally_at_the_physical_kick_boundary() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        let deadline = Instant::now() + Duration::from_millis(10);
        owner.publish_deadline(deadline).unwrap();
        assert_eq!(
            gate.try_kick_at(|| deadline, || -> Result<(), ()> { Ok(()) })
                .unwrap(),
            WatchdogFeedOutcome::WithheldDeadline
        );
        assert!(owner.is_terminally_closed());
        assert!(owner
            .publish_deadline(deadline + Duration::from_secs(1))
            .is_err());
    }

    #[test]
    fn deadline_publication_never_waits_for_a_blocked_physical_kick() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            gate.try_kick(|| -> Result<(), ()> {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap()
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (published_tx, published_rx) = mpsc::channel();
        let publisher = thread::spawn(move || {
            let result = owner.publish_deadline(Instant::now() + Duration::from_secs(30));
            published_tx.send(result).unwrap();
        });
        let publication = published_rx.recv_timeout(Duration::from_secs(1));

        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), WatchdogFeedOutcome::Kicked);
        publisher.join().unwrap();
        assert_eq!(publication.unwrap(), Ok(()));
    }

    #[test]
    fn lock_free_stop_signal_withholds_every_later_feed_admission() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        owner.stop_signal().close_terminal_lock_free();

        assert_eq!(
            gate.try_kick(|| -> Result<(), ()> { Ok(()) }).unwrap(),
            WatchdogFeedOutcome::WithheldTerminal
        );
        assert!(owner.is_terminally_closed());
    }

    #[test]
    fn terminal_stop_still_allows_one_teardown_deadline_without_reopening_feed() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        let deadline = Instant::now() + Duration::from_secs(30);

        owner.stop_signal().close_terminal_lock_free();
        owner
            .publish_deadline(deadline)
            .expect("typed teardown must retain its immutable deadline");
        assert_eq!(owner.deadline_request().get(), Some(&deadline));
        assert_eq!(
            gate.try_kick(|| -> Result<(), ()> { Ok(()) }).unwrap(),
            WatchdogFeedOutcome::WithheldTerminal
        );
        assert!(owner.is_terminally_closed());
        assert!(owner
            .publish_deadline(deadline + Duration::from_secs(1))
            .is_err());
        assert_eq!(
            owner.publish_deadline(deadline),
            Ok(()),
            "an exact teardown replay is idempotent"
        );
    }

    #[test]
    fn terminal_feed_is_withheld_while_following_persistence_is_blocked() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        let entered_persistence = Arc::new(Barrier::new(2));
        let release_persistence = Arc::new(Barrier::new(2));

        // This is the R5 ordering used by the thermal terminal path: consume
        // feed authority first, then start potentially blocking persistence.
        owner.stop_signal().close_terminal_lock_free();
        let persistence = {
            let entered_persistence = Arc::clone(&entered_persistence);
            let release_persistence = Arc::clone(&release_persistence);
            thread::spawn(move || {
                entered_persistence.wait();
                release_persistence.wait();
            })
        };
        entered_persistence.wait();

        let physical_kicks = AtomicUsize::new(0);
        assert_eq!(
            gate.try_kick(|| -> Result<(), ()> {
                physical_kicks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap(),
            WatchdogFeedOutcome::WithheldTerminal
        );
        assert_eq!(
            physical_kicks.load(Ordering::SeqCst),
            0,
            "a blocked lockout fsync must never keep watchdog feeding alive"
        );

        release_persistence.wait();
        persistence.join().unwrap();
    }

    #[test]
    fn terminal_feed_deadline_leads_into_daemon_safe_off_sequence() {
        let daemon = include_str!("../daemon.rs");
        let shutdown = daemon
            .split_once("async fn shutdown(&mut self)")
            .expect("standard typed shutdown must remain present")
            .1;
        let deadline = shutdown
            .find(".publish_deadline(deadline)")
            .expect("shutdown must publish its immutable feed deadline");
        let terminal_i2c = shutdown
            .find(".latch_terminal_safe_off()")
            .expect("shutdown must latch terminal I2C safe-off");
        let terminal_mailbox = shutdown
            .find("voltage_mailbox.latch_terminal()")
            .expect("shutdown must terminally latch the voltage mailbox");
        let first_cut = shutdown
            .find("VoltageCommand::DisableVoltage")
            .expect("shutdown must issue its checked first-stage voltage cut");

        assert!(
            deadline < terminal_i2c
                && terminal_i2c < terminal_mailbox
                && terminal_mailbox < first_cut,
            "a terminal feed signal must still proceed through I2C/mailbox barriers and voltage cut"
        );
    }

    #[test]
    fn physical_deadline_time_is_sampled_only_after_gate_lock_acquisition() {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        let deadline = Instant::now();
        owner.publish_deadline(deadline).unwrap();
        let held = gate.state.lock().unwrap();
        let (sampled_tx, sampled_rx) = mpsc::channel();
        let worker = {
            let gate = gate.clone();
            thread::spawn(move || {
                gate.try_kick_at(
                    || {
                        sampled_tx.send(()).unwrap();
                        deadline
                    },
                    || -> Result<(), ()> { Ok(()) },
                )
                .unwrap()
            })
        };
        assert!(sampled_rx.recv_timeout(Duration::from_millis(20)).is_err());
        drop(held);
        sampled_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            worker.join().unwrap(),
            WatchdogFeedOutcome::WithheldDeadline
        );
    }

    #[test]
    fn owner_drop_closes_worker_handle_fail_closed() {
        let gate = {
            let owner = WatchdogFeedGateOwner::new();
            owner.gate()
        };
        assert_eq!(
            gate.try_kick(|| -> Result<(), ()> { Ok(()) }).unwrap(),
            WatchdogFeedOutcome::WithheldTerminal
        );
    }
}
