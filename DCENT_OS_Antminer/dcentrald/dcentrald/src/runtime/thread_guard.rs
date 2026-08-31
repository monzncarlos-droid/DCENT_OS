//! Bounded ownership for blocking runtime feeder threads.
//!
//! Hardware watchdog and heartbeat workers are ordinary OS threads because
//! their transports are blocking.  They must still obey the async runtime's
//! lifecycle: cancellation is broadcast once, every worker shares one total
//! shutdown deadline, and dropping an owner must never block an async executor
//! thread indefinitely.

use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use anyhow::Result;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const THREAD_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Sleep on a blocking worker while remaining responsive to cancellation.
///
/// Returns `true` when cancellation was observed. Long hardware-feed periods
/// must use this helper instead of one monolithic `thread::sleep`, otherwise a
/// nominal 20-second feed interval also becomes a 20-second shutdown delay.
pub(crate) fn sleep_until_cancelled(shutdown: &CancellationToken, duration: Duration) -> bool {
    let deadline = StdInstant::now() + duration;
    loop {
        if shutdown.is_cancelled() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(StdInstant::now());
        if remaining.is_zero() {
            return shutdown.is_cancelled();
        }
        std::thread::sleep(THREAD_POLL_INTERVAL.min(remaining));
    }
}

/// Terminal state observed while reclaiming a blocking worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadStopOutcome {
    Joined,
    Panicked,
    TimedOut,
}

/// Per-worker shutdown evidence returned to the hardware owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadStopReport {
    pub(crate) name: &'static str,
    pub(crate) outcome: ThreadStopOutcome,
}

/// Aggregate result for one bounded shutdown operation.
#[derive(Debug)]
pub(crate) struct ThreadStopSummary {
    reports: Vec<ThreadStopReport>,
}

impl ThreadStopSummary {
    pub(crate) fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }

    pub(crate) fn any_timed_out(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.outcome == ThreadStopOutcome::TimedOut)
    }

    pub(crate) fn any_panicked(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.outcome == ThreadStopOutcome::Panicked)
    }

    /// Exact, stable worker identities for terminal diagnostics. Join order is
    /// scheduler-dependent, so sort and deduplicate before rendering an
    /// operator-visible failure.
    pub(crate) fn panicked_worker_names(&self) -> Vec<&'static str> {
        let mut names = self
            .reports
            .iter()
            .filter(|report| report.outcome == ThreadStopOutcome::Panicked)
            .map(|report| report.name)
            .collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        names
    }

    #[cfg(test)]
    fn reports(&self) -> &[ThreadStopReport] {
        &self.reports
    }
}

/// Wait for one already-signalled worker without blocking a Tokio executor.
///
/// This is intentionally separate from [`RuntimeThreadGuard`] for legacy
/// owners whose stop flag is not a `CancellationToken`.  New multi-worker
/// runtimes should use the guard so all workers consume one total deadline.
pub(crate) async fn join_thread_bounded(
    handle: JoinHandle<()>,
    timeout: Duration,
) -> ThreadStopOutcome {
    join_thread_until(handle, StdInstant::now() + timeout).await
}

/// Wait for one already-signalled worker against an existing absolute
/// deadline. This preserves a teardown schedule issued by another owner;
/// callers must not convert remaining time back into a fresh relative budget.
pub(crate) async fn join_thread_until(
    handle: JoinHandle<()>,
    deadline: StdInstant,
) -> ThreadStopOutcome {
    let mut handle = Some(handle);

    loop {
        if StdInstant::now() >= deadline {
            // Without a worker-owned completion timestamp, observing a
            // finished handle after the deadline cannot be positive evidence.
            return ThreadStopOutcome::TimedOut;
        }
        if handle.as_ref().is_some_and(JoinHandle::is_finished) {
            if StdInstant::now() >= deadline {
                return ThreadStopOutcome::TimedOut;
            }
            return classify_join(handle.take().expect("checked above"));
        }
        sleep(THREAD_POLL_INTERVAL.min(deadline.saturating_duration_since(StdInstant::now())))
            .await;
    }
}

/// Owns blocking runtime workers and bounds their collective shutdown time.
pub(crate) struct RuntimeThreadGuard {
    shutdown: CancellationToken,
    handles: Vec<(&'static str, JoinHandle<()>)>,
}

impl RuntimeThreadGuard {
    pub(crate) fn new(shutdown: CancellationToken) -> Self {
        Self {
            shutdown,
            handles: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, name: &'static str, handle: JoinHandle<()>) {
        self.handles.push((name, handle));
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    pub(crate) fn contains(&self, name: &'static str) -> bool {
        self.handles
            .iter()
            .any(|(worker_name, _)| *worker_name == name)
    }

    pub(crate) fn request_stop(&self) {
        self.shutdown.cancel();
    }

    /// Cancel and reclaim every worker under one total deadline.
    ///
    /// Finished handles are joined only after `is_finished()` reports true.
    /// Remaining handles are detached at the deadline, allowing the caller to
    /// execute a transport-independent hard stop instead of deadlocking on a
    /// mutex still held by a wedged feeder.
    pub(crate) async fn stop_and_join(&mut self, total_timeout: Duration) -> ThreadStopSummary {
        self.stop_and_join_until(StdInstant::now() + total_timeout)
            .await
    }

    /// Cancel and reclaim every worker against an already-issued absolute
    /// deadline. A delayed first poll must not mint a fresh relative interval.
    pub(crate) async fn stop_and_join_until(&mut self, deadline: StdInstant) -> ThreadStopSummary {
        self.request_stop();
        let started_at = StdInstant::now();
        let available = deadline.saturating_duration_since(started_at);
        let mut reports = Vec::with_capacity(self.handles.len());

        while !self.handles.is_empty() {
            if StdInstant::now() >= deadline {
                for (name, _detached_handle) in self.handles.drain(..) {
                    warn!(
                        thread = name,
                        timeout_ms = available.as_millis(),
                        "runtime thread completion was not observed before the shared deadline; detaching"
                    );
                    reports.push(ThreadStopReport {
                        name,
                        outcome: ThreadStopOutcome::TimedOut,
                    });
                }
                break;
            }
            if let Some(index) = self
                .handles
                .iter()
                .position(|(_, handle)| handle.is_finished())
            {
                if StdInstant::now() >= deadline {
                    continue;
                }
                let (name, handle) = self.handles.swap_remove(index);
                let outcome = classify_join(handle);
                match outcome {
                    ThreadStopOutcome::Joined => info!(thread = name, "runtime thread joined"),
                    ThreadStopOutcome::Panicked => {
                        warn!(thread = name, "runtime thread panicked during shutdown")
                    }
                    ThreadStopOutcome::TimedOut => unreachable!("finished handle cannot time out"),
                }
                reports.push(ThreadStopReport { name, outcome });
                continue;
            }

            sleep(THREAD_POLL_INTERVAL.min(deadline.saturating_duration_since(StdInstant::now())))
                .await;
        }

        ThreadStopSummary { reports }
    }
}

impl Drop for RuntimeThreadGuard {
    fn drop(&mut self) {
        // Drop is deliberately non-blocking.  Cancellation-aware workers can
        // exit naturally; owners that need proof of quiescence must explicitly
        // await `stop_and_join` before releasing hardware resources.
        self.request_stop();
        self.handles.clear();
    }
}

/// Closed set of logical hardware-thread slots for one exact route.
pub(crate) trait FixedThreadSlot: Copy + Eq + Debug {
    fn name(self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadSlotRequirement {
    Required,
    Conditional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadSlotDeclaration<S> {
    slot: S,
    requirement: ThreadSlotRequirement,
}

impl<S> ThreadSlotDeclaration<S> {
    pub(crate) fn required(slot: S) -> Self {
        Self {
            slot,
            requirement: ThreadSlotRequirement::Required,
        }
    }

    pub(crate) fn conditional(slot: S) -> Self {
        Self {
            slot,
            requirement: ThreadSlotRequirement::Conditional,
        }
    }
}

#[derive(Debug)]
enum ThreadSlotState {
    Declared,
    Reserved,
    Running,
    NotApplicable(ThreadSlotNonApplicability),
    StartFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadSlotNonApplicability {
    Topology(&'static str),
    RuntimeNotAdmitted(&'static str),
}

#[derive(Debug)]
struct RosterSlot<S> {
    declaration: ThreadSlotDeclaration<S>,
    state: ThreadSlotState,
}

/// Move-only issuer half created at exact watchdog route admission.
pub(crate) struct ThreadRosterOwner<S> {
    issuer: Arc<()>,
    declarations: Box<[ThreadSlotDeclaration<S>]>,
}

/// Route-scope-retained expectation half. It carries no run identity; the
/// enclosing move-only watchdog route scope supplies that binding.
pub(crate) struct ThreadRosterExpectation<S> {
    issuer: Arc<()>,
    _slot: PhantomData<S>,
}

/// Same-roster authority to resolve untouched conditional declarations only
/// because terminal closeout began before normal runtime admission.
pub(crate) struct ThreadRosterPreRuntimeCloseout<S> {
    issuer: Arc<()>,
    _slot: PhantomData<S>,
}

impl<S> ThreadRosterExpectation<S> {
    pub(crate) fn issue_pre_runtime_closeout(&self) -> ThreadRosterPreRuntimeCloseout<S> {
        ThreadRosterPreRuntimeCloseout {
            issuer: Arc::clone(&self.issuer),
            _slot: PhantomData,
        }
    }
}

/// Issue one fixed roster. Duplicate logical slots and duplicate diagnostic
/// names are rejected before any worker can spawn.
pub(super) fn issue_thread_roster<S>(
    declarations: impl IntoIterator<Item = ThreadSlotDeclaration<S>>,
) -> Result<(ThreadRosterOwner<S>, ThreadRosterExpectation<S>)>
where
    S: FixedThreadSlot,
{
    let declarations = declarations.into_iter().collect::<Vec<_>>();
    anyhow::ensure!(!declarations.is_empty(), "fixed thread roster is empty");
    for (index, declaration) in declarations.iter().enumerate() {
        anyhow::ensure!(
            !declarations[..index]
                .iter()
                .any(|prior| prior.slot == declaration.slot),
            "fixed thread roster declares duplicate slot {:?}",
            declaration.slot
        );
        anyhow::ensure!(
            !declarations[..index]
                .iter()
                .any(|prior| prior.slot.name() == declaration.slot.name()),
            "fixed thread roster declares duplicate worker name {}",
            declaration.slot.name()
        );
    }
    let issuer = Arc::new(());
    Ok((
        ThreadRosterOwner {
            issuer: Arc::clone(&issuer),
            declarations: declarations.into_boxed_slice(),
        },
        ThreadRosterExpectation {
            issuer,
            _slot: PhantomData,
        },
    ))
}

impl<S> ThreadRosterOwner<S>
where
    S: FixedThreadSlot,
{
    pub(crate) fn activate(self, shutdown: CancellationToken) -> FixedThreadRosterGuard<S> {
        FixedThreadRosterGuard {
            inner: RuntimeThreadGuard::new(shutdown),
            issuer: self.issuer,
            slots: self
                .declarations
                .into_vec()
                .into_iter()
                .map(|declaration| RosterSlot {
                    declaration,
                    state: ThreadSlotState::Declared,
                })
                .collect(),
            terminalized: false,
            runtime_admitted: false,
            registration_failed: false,
        }
    }
}

/// Exact-route wrapper over the legacy join mechanics. Registration is typed
/// and closes irreversibly before terminal cancellation begins.
pub(crate) struct FixedThreadRosterGuard<S> {
    inner: RuntimeThreadGuard,
    issuer: Arc<()>,
    slots: Vec<RosterSlot<S>>,
    terminalized: bool,
    runtime_admitted: bool,
    registration_failed: bool,
}

impl<S> FixedThreadRosterGuard<S>
where
    S: FixedThreadSlot,
{
    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation_token()
    }

    /// Reserve before spawning so validation failure cannot detach an
    /// already-live hardware worker.
    pub(crate) fn reserve(&mut self, slot: S) -> Result<ThreadSlotReservation<'_, S>> {
        if self.terminalized || self.runtime_admitted {
            self.registration_failed = true;
            anyhow::bail!("thread roster registration is closed");
        }
        let Some(index) = self
            .slots
            .iter()
            .position(|entry| entry.declaration.slot == slot)
        else {
            self.registration_failed = true;
            anyhow::bail!("thread roster does not declare slot {slot:?}");
        };
        if !matches!(self.slots[index].state, ThreadSlotState::Declared) {
            self.registration_failed = true;
            anyhow::bail!("thread roster slot {slot:?} was already resolved or reserved");
        }
        self.slots[index].state = ThreadSlotState::Reserved;
        Ok(ThreadSlotReservation {
            guard: self,
            index,
            resolved: false,
        })
    }

    pub(crate) fn slot_is_registered(&self, slot: S) -> bool {
        self.slots.iter().any(|entry| {
            entry.declaration.slot == slot && matches!(entry.state, ThreadSlotState::Running)
        })
    }

    /// Close one conditional admission after topology discovery. An applicable
    /// slot must already have been reserved-before-spawn and attached; an
    /// inapplicable slot is recorded explicitly rather than being confused
    /// with a worker that was never started.
    pub(crate) fn resolve_conditional(
        &mut self,
        slot: S,
        applicable: bool,
        not_applicable_reason: &'static str,
    ) -> Result<()> {
        if self.terminalized || self.runtime_admitted {
            self.registration_failed = true;
            anyhow::bail!("thread roster registration is closed");
        }
        let Some(index) = self
            .slots
            .iter()
            .position(|entry| entry.declaration.slot == slot)
        else {
            self.registration_failed = true;
            anyhow::bail!("thread roster does not declare slot {slot:?}");
        };
        if self.slots[index].declaration.requirement != ThreadSlotRequirement::Conditional {
            self.registration_failed = true;
            anyhow::bail!("required thread roster slot cannot be resolved conditionally");
        }

        match (&self.slots[index].state, applicable) {
            (ThreadSlotState::Running, true) | (ThreadSlotState::NotApplicable(_), false) => Ok(()),
            (ThreadSlotState::Declared, false) => {
                anyhow::ensure!(
                    !not_applicable_reason.trim().is_empty(),
                    "thread roster non-applicability reason is empty"
                );
                self.slots[index].state = ThreadSlotState::NotApplicable(
                    ThreadSlotNonApplicability::Topology(not_applicable_reason),
                );
                Ok(())
            }
            (state, expected_applicable) => {
                self.registration_failed = true;
                anyhow::bail!(
                    "conditional thread roster slot {slot:?} resolved as applicable={expected_applicable} from incompatible state {state:?}"
                )
            }
        }
    }

    pub(crate) fn request_stop(&self) {
        self.inner.request_stop();
    }

    /// Seal a fully resolved roster before the runtime can enter its normal
    /// service loop. The receipt is issuer-bound and records which logical
    /// actors had successfully registered/attached handles versus being
    /// explicitly absent from the admitted topology. This is not a liveness
    /// probe: route-specific exit channels must establish actor freshness at
    /// the final service-phase boundary. No later registration or
    /// applicability change is possible.
    pub(crate) fn seal_runtime_admission(&mut self) -> Result<ThreadRosterRuntimeAdmission<S>> {
        if self.terminalized || self.runtime_admitted {
            self.registration_failed = true;
            anyhow::bail!("thread roster runtime admission is already closed");
        }
        if self.registration_failed {
            anyhow::bail!("thread roster has a prior registration failure");
        }

        let mut slots = Vec::with_capacity(self.slots.len());
        for entry in &self.slots {
            let state = match entry.state {
                ThreadSlotState::Running => RuntimeThreadSlotState::Running,
                ThreadSlotState::NotApplicable(ThreadSlotNonApplicability::Topology(reason))
                    if entry.declaration.requirement == ThreadSlotRequirement::Conditional =>
                {
                    RuntimeThreadSlotState::NotApplicable(reason)
                }
                ref state => {
                    self.registration_failed = true;
                    anyhow::bail!(
                        "thread roster cannot admit runtime with unresolved slot {:?} in state {state:?}",
                        entry.declaration.slot
                    );
                }
            };
            slots.push(RuntimeThreadSlot {
                slot: entry.declaration.slot,
                state,
            });
        }
        self.runtime_admitted = true;
        Ok(ThreadRosterRuntimeAdmission {
            issuer: Arc::clone(&self.issuer),
            slots: slots.into_boxed_slice(),
        })
    }

    /// Before normal runtime admission, a clean terminal path may truthfully
    /// resolve untouched conditional actors as not reached. Reserved or
    /// failed starts are deliberately preserved as negative evidence.
    pub(crate) fn resolve_unstarted_conditionals_for_closeout(
        &mut self,
        admission: ThreadRosterPreRuntimeCloseout<S>,
        reason: &'static str,
    ) -> Result<()> {
        if self.terminalized || self.runtime_admitted || reason.trim().is_empty() {
            self.registration_failed = true;
            anyhow::bail!("thread roster pre-runtime closeout is not admissible");
        }
        anyhow::ensure!(
            Arc::ptr_eq(&self.issuer, &admission.issuer),
            "pre-runtime closeout authority was issued by another thread roster"
        );
        for entry in &mut self.slots {
            if entry.declaration.requirement == ThreadSlotRequirement::Conditional
                && matches!(entry.state, ThreadSlotState::Declared)
            {
                entry.state = ThreadSlotState::NotApplicable(
                    ThreadSlotNonApplicability::RuntimeNotAdmitted(reason),
                );
            }
        }
        Ok(())
    }

    pub(crate) fn validate_runtime_admitted_closeout(
        &mut self,
        admission: ThreadRosterRuntimeAdmission<S>,
    ) -> Result<()> {
        if self.terminalized
            || !self.runtime_admitted
            || !Arc::ptr_eq(&self.issuer, &admission.issuer)
        {
            self.registration_failed = true;
            anyhow::bail!(
                "runtime-admitted closeout authority does not match the active thread roster"
            );
        }
        Ok(())
    }

    pub(crate) fn reject_unbound_closeout(&mut self) {
        self.registration_failed = true;
    }

    pub(crate) async fn stop_and_join(&mut self, total_timeout: Duration) -> ThreadRosterStop<S> {
        self.stop_and_join_until(StdInstant::now() + total_timeout)
            .await
    }

    pub(crate) async fn stop_and_join_until(
        &mut self,
        deadline: StdInstant,
    ) -> ThreadRosterStop<S> {
        if self.terminalized {
            warn!("refusing to mint a second fixed thread-roster closeout");
            let summary = self.inner.stop_and_join_until(deadline).await;
            return ThreadRosterStop {
                summary,
                receipt: None,
            };
        }
        self.terminalized = true;
        let summary = self.inner.stop_and_join_until(deadline).await;
        let mut terminal_slots = Vec::with_capacity(self.slots.len());
        let mut positive = !self.registration_failed;
        let running_count = self
            .slots
            .iter()
            .filter(|entry| matches!(entry.state, ThreadSlotState::Running))
            .count();
        if summary.reports.len() != running_count {
            positive = false;
        }

        for entry in &self.slots {
            match entry.state {
                ThreadSlotState::Running => {
                    let reports = summary
                        .reports
                        .iter()
                        .filter(|report| report.name == entry.declaration.slot.name())
                        .collect::<Vec<_>>();
                    if reports.len() == 1 && reports[0].outcome == ThreadStopOutcome::Joined {
                        terminal_slots.push(TerminalThreadSlot {
                            slot: entry.declaration.slot,
                            outcome: TerminalThreadSlotOutcome::Joined,
                        });
                    } else {
                        positive = false;
                    }
                }
                ThreadSlotState::NotApplicable(reason)
                    if entry.declaration.requirement == ThreadSlotRequirement::Conditional =>
                {
                    terminal_slots.push(TerminalThreadSlot {
                        slot: entry.declaration.slot,
                        outcome: TerminalThreadSlotOutcome::NotApplicable(reason),
                    });
                }
                ThreadSlotState::Declared
                | ThreadSlotState::Reserved
                | ThreadSlotState::StartFailed
                | ThreadSlotState::NotApplicable(_) => positive = false,
            }
        }
        if terminal_slots.len() != self.slots.len() {
            positive = false;
        }
        let receipt = positive.then(|| ThreadRosterQuiescenceReceipt {
            issuer: Arc::clone(&self.issuer),
            slots: terminal_slots.into_boxed_slice(),
        });
        ThreadRosterStop { summary, receipt }
    }
}

/// Borrowed, unresolved slot reservation. Dropping it before attachment or an
/// explicit applicability decision records a permanent start failure.
pub(crate) struct ThreadSlotReservation<'a, S>
where
    S: FixedThreadSlot,
{
    guard: &'a mut FixedThreadRosterGuard<S>,
    index: usize,
    resolved: bool,
}

impl<S> ThreadSlotReservation<'_, S>
where
    S: FixedThreadSlot,
{
    pub(crate) fn attach(mut self, handle: JoinHandle<()>) {
        let slot = self.guard.slots[self.index].declaration.slot;
        self.guard.inner.push(slot.name(), handle);
        self.guard.slots[self.index].state = ThreadSlotState::Running;
        self.resolved = true;
    }

    pub(crate) fn mark_not_applicable(mut self, reason: &'static str) -> Result<()> {
        anyhow::ensure!(
            self.guard.slots[self.index].declaration.requirement
                == ThreadSlotRequirement::Conditional,
            "required thread roster slot cannot be marked not applicable"
        );
        anyhow::ensure!(
            !reason.trim().is_empty(),
            "thread roster non-applicability reason is empty"
        );
        self.guard.slots[self.index].state =
            ThreadSlotState::NotApplicable(ThreadSlotNonApplicability::Topology(reason));
        self.resolved = true;
        Ok(())
    }
}

impl<S> Drop for ThreadSlotReservation<'_, S>
where
    S: FixedThreadSlot,
{
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        self.guard.slots[self.index].state = ThreadSlotState::StartFailed;
        self.guard.registration_failed = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalThreadSlotOutcome {
    Joined,
    NotApplicable(ThreadSlotNonApplicability),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeThreadSlotState {
    Running,
    NotApplicable(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeThreadSlot<S> {
    slot: S,
    state: RuntimeThreadSlotState,
}

/// Move-only proof that one issuer's complete actor topology was resolved
/// before normal runtime admission. This is not shutdown evidence: joined
/// quiescence is still required independently at terminal closeout.
pub(crate) struct ThreadRosterRuntimeAdmission<S> {
    issuer: Arc<()>,
    slots: Box<[RuntimeThreadSlot<S>]>,
}

impl<S> ThreadRosterRuntimeAdmission<S>
where
    S: FixedThreadSlot,
{
    pub(crate) fn authorizes(&self, expectation: &ThreadRosterExpectation<S>) -> bool {
        Arc::ptr_eq(&self.issuer, &expectation.issuer)
    }

    pub(crate) fn running(&self, slot: S) -> bool {
        self.slots
            .iter()
            .any(|entry| entry.slot == slot && entry.state == RuntimeThreadSlotState::Running)
    }

    pub(crate) fn not_applicable(&self, slot: S) -> bool {
        self.slots.iter().any(|entry| {
            entry.slot == slot && matches!(entry.state, RuntimeThreadSlotState::NotApplicable(_))
        })
    }

    pub(crate) fn topology_not_applicable(&self, slot: S) -> bool {
        self.not_applicable(slot)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalThreadSlot<S> {
    slot: S,
    outcome: TerminalThreadSlotOutcome,
}

/// Opaque exact-roster authority. It is useful only with the expectation that
/// remained inside the corresponding watchdog-issued route scope.
pub(crate) struct ThreadRosterQuiescenceReceipt<S> {
    issuer: Arc<()>,
    slots: Box<[TerminalThreadSlot<S>]>,
}

impl<S> ThreadRosterQuiescenceReceipt<S>
where
    S: FixedThreadSlot,
{
    pub(crate) fn authorizes(&self, expectation: &ThreadRosterExpectation<S>) -> bool {
        Arc::ptr_eq(&self.issuer, &expectation.issuer)
    }

    pub(crate) fn joined(&self, slot: S) -> bool {
        self.slots
            .iter()
            .any(|entry| entry.slot == slot && entry.outcome == TerminalThreadSlotOutcome::Joined)
    }

    pub(crate) fn not_applicable(&self, slot: S) -> bool {
        self.slots.iter().any(|entry| {
            entry.slot == slot
                && matches!(entry.outcome, TerminalThreadSlotOutcome::NotApplicable(_))
        })
    }

    pub(crate) fn topology_not_applicable(&self, slot: S) -> bool {
        self.slots.iter().any(|entry| {
            entry.slot == slot
                && matches!(
                    entry.outcome,
                    TerminalThreadSlotOutcome::NotApplicable(ThreadSlotNonApplicability::Topology(
                        _
                    ))
                )
        })
    }

    pub(crate) fn not_started_before_runtime_admission(&self, slot: S) -> bool {
        self.slots.iter().any(|entry| {
            entry.slot == slot
                && matches!(
                    entry.outcome,
                    TerminalThreadSlotOutcome::NotApplicable(
                        ThreadSlotNonApplicability::RuntimeNotAdmitted(_)
                    )
                )
        })
    }
}

/// Diagnostic and authority result of one terminal roster transition.
pub(crate) struct ThreadRosterStop<S> {
    summary: ThreadStopSummary,
    receipt: Option<ThreadRosterQuiescenceReceipt<S>>,
}

impl<S> ThreadRosterStop<S> {
    pub(crate) fn all_started_threads_quiesced(&self) -> bool {
        !self.summary.any_timed_out()
    }

    pub(crate) fn any_panicked(&self) -> bool {
        self.summary.any_panicked()
    }

    pub(crate) fn any_timed_out(&self) -> bool {
        self.summary.any_timed_out()
    }

    pub(crate) fn panicked_worker_names(&self) -> Vec<&'static str> {
        self.summary.panicked_worker_names()
    }

    pub(crate) fn into_receipt(self) -> Option<ThreadRosterQuiescenceReceipt<S>> {
        self.receipt
    }
}

fn classify_join(handle: JoinHandle<()>) -> ThreadStopOutcome {
    match handle.join() {
        Ok(()) => ThreadStopOutcome::Joined,
        Err(_) => ThreadStopOutcome::Panicked,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tokio_util::sync::CancellationToken;

    use super::{
        issue_thread_roster, join_thread_bounded, join_thread_until, sleep_until_cancelled,
        FixedThreadSlot, RuntimeThreadGuard, ThreadSlotDeclaration, ThreadStopOutcome,
    };
    use crate::runtime::source_contract::compact_rust_source;

    #[test]
    fn long_worker_sleep_observes_cancellation_promptly() {
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let started = Instant::now();
        let handle =
            thread::spawn(move || sleep_until_cancelled(&worker_shutdown, Duration::from_secs(20)));

        thread::sleep(Duration::from_millis(30));
        shutdown.cancel();

        assert!(handle.join().unwrap());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn completion_first_observed_at_the_deadline_is_not_positive_evidence() {
        let handle = thread::spawn(|| {});
        while !handle.is_finished() {
            thread::yield_now();
        }
        assert_eq!(
            join_thread_bounded(handle, Duration::ZERO).await,
            ThreadStopOutcome::TimedOut
        );

        let mut guard = RuntimeThreadGuard::new(CancellationToken::new());
        let handle = thread::spawn(|| {});
        while !handle.is_finished() {
            thread::yield_now();
        }
        guard.push("finished-before-zero-budget", handle);
        let summary = guard.stop_and_join(Duration::ZERO).await;
        assert!(summary.any_timed_out());
    }

    #[tokio::test]
    async fn absolute_join_never_rebases_an_expired_deadline() {
        let completed = thread::spawn(|| {});
        while !completed.is_finished() {
            thread::yield_now();
        }
        assert_eq!(
            join_thread_until(completed, Instant::now()).await,
            ThreadStopOutcome::TimedOut
        );

        let completed = thread::spawn(|| {});
        assert_eq!(
            join_thread_until(completed, Instant::now() + Duration::from_secs(1)).await,
            ThreadStopOutcome::Joined
        );

        let mut guard = RuntimeThreadGuard::new(CancellationToken::new());
        let completed = thread::spawn(|| {});
        while !completed.is_finished() {
            thread::yield_now();
        }
        guard.push("completed-before-delayed-poll", completed);
        let original_deadline = Instant::now();
        tokio::task::yield_now().await;

        let summary = guard.stop_and_join_until(original_deadline).await;

        assert!(summary.any_timed_out());
    }

    #[tokio::test]
    async fn joins_responsive_and_classifies_panicked_workers() {
        let shutdown = CancellationToken::new();
        let mut guard = RuntimeThreadGuard::new(shutdown.clone());
        guard.push(
            "responsive",
            thread::spawn(move || {
                while !shutdown.is_cancelled() {
                    thread::yield_now();
                }
            }),
        );
        guard.push("panicked", thread::spawn(|| panic!("test panic")));

        let summary = guard.stop_and_join(Duration::from_secs(1)).await;

        assert!(summary.reports().iter().any(|report| {
            report.name == "responsive" && report.outcome == ThreadStopOutcome::Joined
        }));
        assert!(summary.reports().iter().any(|report| {
            report.name == "panicked" && report.outcome == ThreadStopOutcome::Panicked
        }));
        assert!(summary.any_panicked());
        assert_eq!(summary.panicked_worker_names(), vec!["panicked"]);
        assert!(!summary.any_timed_out());
    }

    #[tokio::test]
    async fn one_total_deadline_bounds_multiple_stalled_workers() {
        let release = Arc::new(AtomicBool::new(false));
        let mut guard = RuntimeThreadGuard::new(CancellationToken::new());
        for name in ["stalled-a", "stalled-b", "stalled-c"] {
            let release = Arc::clone(&release);
            guard.push(
                name,
                thread::spawn(move || {
                    while !release.load(Ordering::Acquire) {
                        thread::yield_now();
                    }
                }),
            );
        }

        let started = Instant::now();
        let summary = guard.stop_and_join(Duration::from_millis(60)).await;
        let elapsed = started.elapsed();
        release.store(true, Ordering::Release);

        assert_eq!(summary.reports().len(), 3);
        assert!(summary.any_timed_out());
        assert!(elapsed < Duration::from_millis(250), "elapsed={elapsed:?}");
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestSlot {
        Required,
        Conditional,
        DuplicateName,
    }

    impl FixedThreadSlot for TestSlot {
        fn name(self) -> &'static str {
            match self {
                Self::Required | Self::DuplicateName => "required-worker",
                Self::Conditional => "conditional-worker",
            }
        }
    }

    #[test]
    fn fixed_roster_issuance_rejects_duplicate_slots_and_names() {
        assert!(issue_thread_roster([
            ThreadSlotDeclaration::required(TestSlot::Required),
            ThreadSlotDeclaration::required(TestSlot::Required),
        ])
        .is_err());
        assert!(issue_thread_roster([
            ThreadSlotDeclaration::required(TestSlot::Required),
            ThreadSlotDeclaration::required(TestSlot::DuplicateName),
        ])
        .is_err());
    }

    #[tokio::test]
    async fn fixed_roster_required_never_started_cannot_mint_authority() {
        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let mut guard = owner.activate(CancellationToken::new());

        let stop = guard.stop_and_join(Duration::ZERO).await;
        assert!(stop.all_started_threads_quiesced());
        assert!(stop.into_receipt().is_none());
    }

    #[tokio::test]
    async fn fixed_roster_conditional_slot_requires_explicit_non_applicability() {
        let (owner, expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        guard
            .reserve(TestSlot::Conditional)
            .unwrap()
            .mark_not_applicable("topology has no smart PSU")
            .unwrap();

        let receipt = guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .expect("explicit conditional resolution is positive evidence");
        assert!(receipt.authorizes(&expectation));
        assert!(receipt.not_applicable(TestSlot::Conditional));
        assert!(!receipt.joined(TestSlot::Conditional));
    }

    #[tokio::test]
    async fn fixed_roster_conditional_resolution_matches_discovered_topology() {
        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        guard
            .resolve_conditional(TestSlot::Conditional, false, "topology has no smart PSU")
            .unwrap();
        assert!(guard
            .resolve_conditional(TestSlot::Conditional, true, "unused")
            .is_err());
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());

        let (owner, expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let mut guard = owner.activate(shutdown);
        guard
            .reserve(TestSlot::Conditional)
            .unwrap()
            .attach(thread::spawn(move || {
                while !worker_shutdown.is_cancelled() {
                    thread::yield_now();
                }
            }));
        guard
            .resolve_conditional(TestSlot::Conditional, true, "unused")
            .unwrap();
        let receipt = guard
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .expect("registered applicable slot must close positively");
        assert!(receipt.authorizes(&expectation));
        assert!(receipt.joined(TestSlot::Conditional));
    }

    #[tokio::test]
    async fn fixed_roster_reservation_drop_and_duplicate_are_terminal_failures() {
        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        drop(guard.reserve(TestSlot::Required).unwrap());
        assert!(guard.reserve(TestSlot::Required).is_err());
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());

        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let mut guard = owner.activate(shutdown);
        guard
            .reserve(TestSlot::Required)
            .unwrap()
            .attach(thread::spawn(move || {
                while !worker_shutdown.is_cancelled() {
                    thread::yield_now();
                }
            }));
        assert!(guard.reserve(TestSlot::Required).is_err());
        assert!(guard
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .is_none());
    }

    #[tokio::test]
    async fn fixed_roster_receipt_is_issuer_bound_and_terminalization_is_one_shot() {
        let (owner, expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let (_foreign_owner, foreign_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        guard
            .reserve(TestSlot::Required)
            .unwrap()
            .attach(thread::spawn(|| {}));
        let receipt = guard
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .unwrap();
        assert!(receipt.authorizes(&expectation));
        assert!(!receipt.authorizes(&foreign_expectation));
        assert!(receipt.joined(TestSlot::Required));
        assert!(guard.reserve(TestSlot::Required).is_err());
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());
    }

    #[tokio::test]
    async fn fixed_roster_distinguishes_topology_absence_from_pre_runtime_closeout() {
        let (owner, topology_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let mut topology_guard = owner.activate(CancellationToken::new());
        topology_guard
            .resolve_conditional(
                TestSlot::Conditional,
                false,
                "discovered topology has no worker",
            )
            .unwrap();
        let topology_receipt = topology_guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .unwrap();
        assert!(topology_receipt.authorizes(&topology_expectation));
        assert!(topology_receipt.topology_not_applicable(TestSlot::Conditional));
        assert!(!topology_receipt.not_started_before_runtime_admission(TestSlot::Conditional));

        let (owner, pre_runtime_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let pre_runtime = pre_runtime_expectation.issue_pre_runtime_closeout();
        let mut pre_runtime_guard = owner.activate(CancellationToken::new());
        pre_runtime_guard
            .resolve_unstarted_conditionals_for_closeout(
                pre_runtime,
                "terminal closeout preceded runtime admission",
            )
            .unwrap();
        let pre_runtime_receipt = pre_runtime_guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .unwrap();
        assert!(pre_runtime_receipt.authorizes(&pre_runtime_expectation));
        assert!(!pre_runtime_receipt.topology_not_applicable(TestSlot::Conditional));
        assert!(pre_runtime_receipt.not_started_before_runtime_admission(TestSlot::Conditional));
    }

    #[tokio::test]
    async fn fixed_roster_pre_runtime_closeout_is_issuer_bound() {
        let (owner, expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let (_foreign_owner, foreign_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let mut guard = owner.activate(CancellationToken::new());

        let error = guard
            .resolve_unstarted_conditionals_for_closeout(
                foreign_expectation.issue_pre_runtime_closeout(),
                "foreign terminal closeout",
            )
            .unwrap_err();
        assert!(error.to_string().contains("another thread roster"));
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());
        drop(expectation);
    }

    #[tokio::test]
    async fn fixed_roster_runtime_seal_closes_registration_permanently() {
        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        guard
            .resolve_conditional(TestSlot::Conditional, false, "topology has no worker")
            .unwrap();
        let runtime = guard.seal_runtime_admission().unwrap();
        assert!(runtime.topology_not_applicable(TestSlot::Conditional));
        assert!(guard.reserve(TestSlot::Conditional).is_err());
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());
    }

    #[tokio::test]
    async fn fixed_roster_start_failure_cannot_be_reclassified_as_not_admitted() {
        let (owner, expectation) =
            issue_thread_roster([ThreadSlotDeclaration::conditional(TestSlot::Conditional)])
                .unwrap();
        let pre_runtime = expectation.issue_pre_runtime_closeout();
        let mut guard = owner.activate(CancellationToken::new());
        drop(guard.reserve(TestSlot::Conditional).unwrap());

        guard
            .resolve_unstarted_conditionals_for_closeout(
                pre_runtime,
                "terminal closeout preceded runtime admission",
            )
            .unwrap();
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_roster_panic_and_timeout_are_diagnostic_only() {
        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        guard
            .reserve(TestSlot::Required)
            .unwrap()
            .attach(thread::spawn(|| panic!("roster panic fixture")));
        let stop = guard.stop_and_join(Duration::from_secs(1)).await;
        assert!(stop.any_panicked());
        assert!(stop.all_started_threads_quiesced());
        assert!(stop.into_receipt().is_none());

        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let (owner, _expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(TestSlot::Required)]).unwrap();
        let mut guard = owner.activate(CancellationToken::new());
        guard
            .reserve(TestSlot::Required)
            .unwrap()
            .attach(thread::spawn(move || {
                while !worker_release.load(Ordering::Acquire) {
                    thread::yield_now();
                }
            }));
        let stop = guard.stop_and_join(Duration::from_millis(30)).await;
        release.store(true, Ordering::Release);
        assert!(stop.any_timed_out());
        assert!(!stop.all_started_threads_quiesced());
        assert!(stop.into_receipt().is_none());
    }

    #[test]
    fn drop_cancels_without_waiting_for_a_stalled_worker() {
        let shutdown = CancellationToken::new();
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let mut guard = RuntimeThreadGuard::new(shutdown.clone());
        guard.push(
            "stalled",
            thread::spawn(move || {
                while !worker_release.load(Ordering::Acquire) {
                    thread::yield_now();
                }
            }),
        );

        let started = Instant::now();
        drop(guard);
        let elapsed = started.elapsed();
        release.store(true, Ordering::Release);

        assert!(shutdown.is_cancelled());
        assert!(elapsed < Duration::from_millis(50), "elapsed={elapsed:?}");
    }

    #[test]
    fn feeder_owners_do_not_regress_to_unbounded_join_calls() {
        let serial = include_str!("../serial_mining.rs");
        let hybrid = include_str!("../s19j_hybrid_mining.rs");
        let serial_production = serial
            .split_once("pub async fn run(&mut self) -> Result<()>")
            .expect("serial mining runtime entry")
            .1
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("serial mining production runtime section");
        let hybrid_production = hybrid
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("hybrid mining production section");

        assert!(!serial_production.contains(".join()"));
        assert!(!hybrid_production.contains(".join()"));
        assert!(hybrid.contains("force_am2_home_hard_stop_blocking(config, reason).await"));
        assert!(hybrid.contains("skipping PSU mutex teardown after feeder timeout"));
        assert!(serial.contains("hard_stop_out_of_band(\"runtime-thread-timeout\")"));
        assert!(serial.contains("crate::terminal_io_owner::dispatch(\"am2-serial-drop-hard-stop\""));
        assert!(serial.contains("Self::execute_manually_retained_hard_stop(&mut owned, \"drop\")"));

        let normal_shutdown = hybrid
            .split("=== SHUTDOWN: graceful PSU teardown ===")
            .nth(1)
            .expect("normal AM2 shutdown section must exist");
        let feeder_stop = normal_shutdown
            .find("stop_am2_runtime_feeders_with_evidence(")
            .expect("normal shutdown must stop feeders with typed quiescence evidence");
        let pic_disable = normal_shutdown
            .find("PIC voltage disabled after heartbeat feeders quiesced")
            .expect("normal shutdown must disable PIC after quiescence");
        assert!(feeder_stop < pic_disable);
    }

    #[test]
    fn stock_and_legacy_psu_feeders_keep_explicit_bounded_ownership() {
        let stock = include_str!("../stock_mining.rs");
        let daemon = include_str!("../daemon.rs");
        let compact_stock = compact_rust_source(stock);

        assert!(
            compact_stock.contains("runtime_threads.push(\"stock-pic-heartbeat\",heartbeat_handle")
        );
        assert!(compact_stock.contains(
            "sleep_until_cancelled(&hb_shutdown,Duration::from_millis(HEARTBEAT_INTERVAL_MS)"
        ));
        assert!(!stock.contains("OnceLock<Vec<u8>>"));
        let guard_owner = stock
            .find("let mut run_safety = StockRunSafetyGuard::new")
            .expect("stock run-scope guard must be installed before energizing");
        let first_enable = stock
            // P1-2: energization now flows through the VoltageRail facet SSOT.
            .find("energize_voltage_rail(&mut rail, STOCK_PIC16_INIT_MV)")
            .expect("stock voltage-enable site must exist");
        let panic_mask = stock
            .find("mark_stock_chain_energized(&STOCK_FPGA_ENERGIZED_CHAIN_MASK, chain_id)")
            .expect("stock panic mask must be updated after enable");
        let guard_chain = stock
            .find("run_safety.add_energized_chain(chain_id)")
            .expect("stock ordinary-return guard must own each energized chain");
        let initial_heartbeat = stock
            // P1-2: initial heartbeat flows through the same rail facet.
            .find("match rail.heartbeat()")
            .expect("stock initial heartbeat site must exist");
        assert!(guard_owner < panic_mask);
        assert!(panic_mask < first_enable);
        assert!(guard_chain < first_enable);
        assert!(first_enable < initial_heartbeat);
        let stock_shutdown = stock
            .split("=== STOCK FPGA MINING SHUTDOWN ===")
            .nth(1)
            .expect("stock shutdown section must exist");
        let stock_join = stock_shutdown
            .find("runtime_threads.stop_and_join(Duration::from_secs(3))")
            .expect("stock heartbeat must use bounded join");
        let stock_disable = stock_shutdown
            .find("let voltage_evidence = run_safety.teardown(")
            .expect("stock voltage teardown must be explicit");
        assert!(stock_join < stock_disable);
        let stock_disable_body = &stock_shutdown[stock_disable..];
        assert!(stock_disable_body.contains("stock-dispatch-io-failure"));
        assert!(stock_disable_body.contains("normal-shutdown"));

        let stock_drop = stock
            .split("impl Drop for StockRunSafetyGuard")
            .nth(1)
            .and_then(|tail| tail.split("pub struct StockMiner").next())
            .expect("stock safety Drop section must exist");
        assert!(!stock_drop.contains("StockFpga::open"));
        assert!(!stock_drop.contains("enable_voltage"));

        let energized_stock_body = stock
            .split("let mut run_safety =")
            .nth(1)
            .and_then(|tail| tail.split("// ---- Shutdown ----").next())
            .expect("post-energize stock body must exist");
        assert!(
            !energized_stock_body.contains("?;"),
            "post-energize fallible exits must run explicit teardown"
        );
        // Every post-energize fallible exit must appear here BY REASON, not just
        // by count — a bare count silently tolerated `work-dispatch-admission-
        // refused` being added while this list still named four reasons, so the
        // count (4) and the source (5) had already drifted apart before
        // `passthrough-dma-layout-refused` was added. Adding a teardown path
        // means adding its reason here; the count is the backstop, not the check.
        assert_eq!(energized_stock_body.matches("return Err").count(), 7);
        for reason in [
            "no-pics-initialized",
            "cold-chain-refusal",
            "dma-open-failed",
            "heartbeat-spawn-failed",
            "work-dispatch-admission-refused",
            "passthrough-dma-layout-refused",
            "full-init-dhash-refused",
        ] {
            assert!(
                energized_stock_body.contains(reason),
                "post-energize teardown reason {reason} missing from stock_mining.rs"
            );
        }

        let psu_feeder = daemon
            .split("// ---- PSU watchdog feed thread ----")
            .nth(1)
            .and_then(|tail| tail.split("// ---- Start thermal control loop ----").next())
            .expect("PSU feeder section must exist");
        assert!(psu_feeder.contains("self.psu_watchdog_threads.push(\"psu-watchdog\""));
        assert!(psu_feeder.contains("sleep_until_cancelled("));
        assert!(psu_feeder.contains("psu_lock_for_watchdog.try_lock()"));
        assert!(!psu_feeder.contains("disable_watchdog"));

        let psu_init = daemon
            .split("// Step 5.0: Legacy smart-PSU initialization")
            .nth(1)
            .and_then(|tail| tail.split("// Step 5.1:").next())
            .expect("legacy PSU initialization section must exist");
        assert!(psu_init.contains("smart_psu_path_allowed"));
        assert!(!psu_init.contains("collect_hardware_info"));
        let psu_probe = daemon
            .split("let mut detected_smart_psu_version")
            .nth(1)
            .and_then(|tail| tail.split("// ---- PSU watchdog feed thread ----").next())
            .expect("legacy PSU probe section must exist");
        assert!(psu_probe.contains("legacy_psu_path_allowed"));

        let daemon_shutdown = daemon
            .split("async fn shutdown(&mut self)")
            .nth(1)
            .expect("daemon shutdown section must exist");
        let psu_join = daemon_shutdown
            .find(".stop_and_join(psu_stop_timeout)")
            .expect("daemon shutdown must join PSU feeder");
        let terminal_latch = daemon_shutdown
            .find("latch_terminal_safe_off()")
            .expect("daemon shutdown terminal latch must exist");
        assert!(
            terminal_latch < psu_join,
            "terminal mutation admission must close before shutdown waits for the legacy PSU feeder"
        );
    }
}
