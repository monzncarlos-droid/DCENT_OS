// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) D-Central Technologies — https://d-central.tech

//! One immutable, watchdog-issued deadline schedule for terminal teardown.
//!
//! Relative timeouts are safe only when a single operation owns the complete
//! interval. Mining teardown is a sequence of mutation fences, physical power
//! cuts, actor joins, controller cleanup, watchdog Disarm, receipt observation,
//! and worker reclamation. Giving every stage a fresh relative timeout silently
//! extends the energized lifetime and can consume the time reserved for an
//! irreversible cutoff or watchdog closeout.
//!
//! [`TeardownBudget`] is therefore move-only and issued once for one watchdog
//! run and private issuer identity. Callers may clone a [`TeardownBudgetView`]
//! to classify or clamp ordinary stages, but only the original budget can be
//! consumed into [`TeardownDisarmAuthority`]. All boundary checks are strict:
//! completion exactly at a deadline is late.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::safety_watchdog::WatchdogRunScope;

const DEFAULT_CUTOFF_START_OFFSET: Duration = Duration::from_secs(2);
const DEFAULT_CUTOFF_COMPLETE_OFFSET: Duration = Duration::from_secs(4);
const DEFAULT_CLEANUP_COMPLETE_OFFSET: Duration = Duration::from_secs(26);
const DEFAULT_DISARM_START_OFFSET: Duration = Duration::from_secs(28);
const DEFAULT_FEED_DEADLINE_OFFSET: Duration = Duration::from_secs(30);
const DEFAULT_TERMINAL_RECEIPT_OFFSET: Duration = Duration::from_secs(32);
const DEFAULT_WORKER_JOIN_OFFSET: Duration = Duration::from_secs(34);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeardownStage {
    CutoffStart,
    CutoffComplete,
    CleanupComplete,
    DisarmStart,
    FeedDeadline,
    TerminalReceipt,
    WorkerJoin,
}

impl TeardownStage {
    fn label(self) -> &'static str {
        match self {
            Self::CutoffStart => "cutoff start",
            Self::CutoffComplete => "cutoff completion",
            Self::CleanupComplete => "cleanup completion",
            Self::DisarmStart => "watchdog Disarm start",
            Self::FeedDeadline => "watchdog feed",
            Self::TerminalReceipt => "terminal receipt",
            Self::WorkerJoin => "watchdog worker join",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TeardownBudgetPolicy {
    cutoff_start: Duration,
    cutoff_complete: Duration,
    cleanup_complete: Duration,
    disarm_start: Duration,
    feed_deadline: Duration,
    terminal_receipt: Duration,
    worker_join: Duration,
}

impl TeardownBudgetPolicy {
    pub(crate) const fn watchdog_default() -> Self {
        Self {
            cutoff_start: DEFAULT_CUTOFF_START_OFFSET,
            cutoff_complete: DEFAULT_CUTOFF_COMPLETE_OFFSET,
            cleanup_complete: DEFAULT_CLEANUP_COMPLETE_OFFSET,
            disarm_start: DEFAULT_DISARM_START_OFFSET,
            feed_deadline: DEFAULT_FEED_DEADLINE_OFFSET,
            terminal_receipt: DEFAULT_TERMINAL_RECEIPT_OFFSET,
            worker_join: DEFAULT_WORKER_JOIN_OFFSET,
        }
    }

    fn offsets(self) -> [(TeardownStage, Duration); 7] {
        [
            (TeardownStage::CutoffStart, self.cutoff_start),
            (TeardownStage::CutoffComplete, self.cutoff_complete),
            (TeardownStage::CleanupComplete, self.cleanup_complete),
            (TeardownStage::DisarmStart, self.disarm_start),
            (TeardownStage::FeedDeadline, self.feed_deadline),
            (TeardownStage::TerminalReceipt, self.terminal_receipt),
            (TeardownStage::WorkerJoin, self.worker_join),
        ]
    }
}

#[derive(Debug)]
struct TeardownSchedule {
    run_scope: WatchdogRunScope,
    issuer: Arc<()>,
    started_at: Instant,
    cutoff_start: Instant,
    cutoff_complete: Instant,
    cleanup_complete: Instant,
    disarm_start: Instant,
    feed_deadline: Instant,
    terminal_receipt: Instant,
    worker_join: Instant,
}

impl TeardownSchedule {
    fn new(
        run_scope: WatchdogRunScope,
        issuer: Arc<()>,
        started_at: Instant,
        policy: TeardownBudgetPolicy,
    ) -> Result<Self> {
        let offsets = policy.offsets();
        let mut previous = Duration::ZERO;
        for (stage, offset) in offsets {
            anyhow::ensure!(
                offset > previous,
                "teardown {} offset must be strictly later than the previous stage",
                stage.label()
            );
            previous = offset;
        }

        let deadline = |stage: TeardownStage, offset: Duration| {
            started_at
                .checked_add(offset)
                .with_context(|| format!("teardown {} deadline overflowed Instant", stage.label()))
        };

        Ok(Self {
            run_scope,
            issuer,
            started_at,
            cutoff_start: deadline(TeardownStage::CutoffStart, policy.cutoff_start)?,
            cutoff_complete: deadline(TeardownStage::CutoffComplete, policy.cutoff_complete)?,
            cleanup_complete: deadline(TeardownStage::CleanupComplete, policy.cleanup_complete)?,
            disarm_start: deadline(TeardownStage::DisarmStart, policy.disarm_start)?,
            feed_deadline: deadline(TeardownStage::FeedDeadline, policy.feed_deadline)?,
            terminal_receipt: deadline(TeardownStage::TerminalReceipt, policy.terminal_receipt)?,
            worker_join: deadline(TeardownStage::WorkerJoin, policy.worker_join)?,
        })
    }

    fn deadline(&self, stage: TeardownStage) -> Instant {
        match stage {
            TeardownStage::CutoffStart => self.cutoff_start,
            TeardownStage::CutoffComplete => self.cutoff_complete,
            TeardownStage::CleanupComplete => self.cleanup_complete,
            TeardownStage::DisarmStart => self.disarm_start,
            TeardownStage::FeedDeadline => self.feed_deadline,
            TeardownStage::TerminalReceipt => self.terminal_receipt,
            TeardownStage::WorkerJoin => self.worker_join,
        }
    }

    fn remaining_at(&self, stage: TeardownStage, now: Instant) -> Result<Duration> {
        self.require_not_before_start(now)?;
        let deadline = self.deadline(stage);
        anyhow::ensure!(
            now < deadline,
            "teardown {} deadline was reached or exceeded",
            stage.label()
        );
        Ok(deadline.duration_since(now))
    }

    fn remaining_capped_at(
        &self,
        stage: TeardownStage,
        requested: Duration,
        now: Instant,
    ) -> Result<Duration> {
        anyhow::ensure!(
            !requested.is_zero(),
            "teardown {} requested timeout must be non-zero",
            stage.label()
        );
        Ok(self.remaining_at(stage, now)?.min(requested))
    }

    fn require_completed_at(&self, stage: TeardownStage, completed_at: Instant) -> Result<()> {
        self.require_not_before_start(completed_at)?;
        anyhow::ensure!(
            completed_at < self.deadline(stage),
            "teardown {} completed at or after its absolute deadline",
            stage.label()
        );
        Ok(())
    }

    fn require_not_before_start(&self, observed_at: Instant) -> Result<()> {
        anyhow::ensure!(
            observed_at >= self.started_at,
            "teardown evidence predates the watchdog-issued budget start"
        );
        Ok(())
    }

    fn authorizes(
        &self,
        run_scope: &WatchdogRunScope,
        expectation: &TeardownBudgetExpectation,
    ) -> bool {
        self.run_scope.same_run(run_scope) && Arc::ptr_eq(&self.issuer, &expectation.0)
    }
}

/// Move-only lifecycle budget. Cloning is intentionally unavailable: only
/// this owner can become watchdog Disarm authority.
#[derive(Debug)]
pub(crate) struct TeardownBudget {
    schedule: Arc<TeardownSchedule>,
}

impl TeardownBudget {
    pub(crate) fn view(&self) -> TeardownBudgetView {
        TeardownBudgetView {
            schedule: Arc::clone(&self.schedule),
        }
    }

    pub(crate) fn started_at(&self) -> Instant {
        self.schedule.started_at
    }

    pub(crate) fn deadline(&self, stage: TeardownStage) -> Instant {
        self.schedule.deadline(stage)
    }

    pub(crate) fn begin_disarm_at(self, now: Instant) -> Result<TeardownDisarmAuthority> {
        self.schedule
            .remaining_at(TeardownStage::DisarmStart, now)?;
        Ok(TeardownDisarmAuthority {
            schedule: self.schedule,
            started_at: now,
        })
    }
}

/// Cloneable, non-authorizing view for ordinary teardown stages.
#[derive(Debug, Clone)]
pub(crate) struct TeardownBudgetView {
    schedule: Arc<TeardownSchedule>,
}

impl TeardownBudgetView {
    pub(crate) fn started_at(&self) -> Instant {
        self.schedule.started_at
    }

    pub(crate) fn deadline(&self, stage: TeardownStage) -> Instant {
        self.schedule.deadline(stage)
    }

    pub(crate) fn remaining_at(&self, stage: TeardownStage, now: Instant) -> Result<Duration> {
        self.schedule.remaining_at(stage, now)
    }

    pub(crate) fn remaining_capped_at(
        &self,
        stage: TeardownStage,
        requested: Duration,
        now: Instant,
    ) -> Result<Duration> {
        self.schedule.remaining_capped_at(stage, requested, now)
    }

    pub(crate) fn require_completed_at(
        &self,
        stage: TeardownStage,
        completed_at: Instant,
    ) -> Result<()> {
        self.schedule.require_completed_at(stage, completed_at)
    }

    /// Reject evidence timestamps from before this run's absolute teardown
    /// schedule. Upper-bound-only checks would otherwise accept a timestamp
    /// laundered from an earlier run or pre-budget operation.
    pub(crate) fn require_not_before_start(&self, observed_at: Instant) -> Result<()> {
        self.schedule.require_not_before_start(observed_at)
    }

    pub(crate) fn authorizes(
        &self,
        run_scope: &WatchdogRunScope,
        expectation: &TeardownBudgetExpectation,
    ) -> bool {
        self.schedule.authorizes(run_scope, expectation)
    }

    pub(crate) fn same_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        Arc::ptr_eq(&self.schedule, &authority.schedule)
    }

    pub(crate) fn same_view(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.schedule, &other.schedule)
    }
}

/// Move-only proof that Disarm began before the budget's strict start bound.
#[derive(Debug)]
pub(crate) struct TeardownDisarmAuthority {
    schedule: Arc<TeardownSchedule>,
    started_at: Instant,
}

/// Budget plus the watchdog worker's acknowledgement result. Local deadline
/// publication succeeds before the acknowledgement wait, so callers must keep
/// using the returned budget even when admission is negative.
pub(crate) struct TeardownStart {
    budget: TeardownBudget,
    admission: std::result::Result<(), String>,
}

impl TeardownStart {
    pub(super) fn new(budget: TeardownBudget, admission: std::result::Result<(), String>) -> Self {
        Self { budget, admission }
    }

    pub(crate) fn into_parts(self) -> (TeardownBudget, std::result::Result<(), String>) {
        (self.budget, self.admission)
    }
}

impl TeardownDisarmAuthority {
    pub(crate) fn started_at(&self) -> Instant {
        self.started_at
    }

    pub(crate) fn deadline(&self, stage: TeardownStage) -> Instant {
        self.schedule.deadline(stage)
    }

    pub(crate) fn remaining_at(&self, stage: TeardownStage, now: Instant) -> Result<Duration> {
        self.schedule.remaining_at(stage, now)
    }

    pub(crate) fn require_disarm_command_started_at(&self, started_at: Instant) -> Result<()> {
        self.schedule
            .require_completed_at(TeardownStage::DisarmStart, started_at)
    }

    pub(crate) fn require_completed_at(
        &self,
        stage: TeardownStage,
        completed_at: Instant,
    ) -> Result<()> {
        self.schedule.require_completed_at(stage, completed_at)
    }

    pub(crate) fn authorizes(
        &self,
        run_scope: &WatchdogRunScope,
        expectation: &TeardownBudgetExpectation,
    ) -> bool {
        self.schedule.authorizes(run_scope, expectation)
    }
}

/// The sole issuer for one watchdog run. Losing or consuming it cannot be
/// repaired by constructing a later schedule.
pub(crate) struct TeardownBudgetIssuer {
    run_scope: WatchdogRunScope,
    issuer: Arc<()>,
    issued: bool,
}

/// Watchdog-retained half of the budget trust root.
#[derive(Clone)]
pub(crate) struct TeardownBudgetExpectation(Arc<()>);

pub(super) fn issue_teardown_budget_authority(
    run_scope: WatchdogRunScope,
) -> (TeardownBudgetIssuer, TeardownBudgetExpectation) {
    let identity = Arc::new(());
    (
        TeardownBudgetIssuer {
            run_scope,
            issuer: Arc::clone(&identity),
            issued: false,
        },
        TeardownBudgetExpectation(identity),
    )
}

impl TeardownBudgetIssuer {
    pub(crate) fn issue_at(
        &mut self,
        started_at: Instant,
        policy: TeardownBudgetPolicy,
    ) -> Result<TeardownBudget> {
        anyhow::ensure!(
            !std::mem::replace(&mut self.issued, true),
            "teardown budget was already issued for this watchdog run"
        );
        let schedule = TeardownSchedule::new(
            self.run_scope.clone(),
            Arc::clone(&self.issuer),
            started_at,
            policy,
        )?;
        Ok(TeardownBudget {
            schedule: Arc::new(schedule),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(offsets: [u64; 7]) -> TeardownBudgetPolicy {
        TeardownBudgetPolicy {
            cutoff_start: Duration::from_nanos(offsets[0]),
            cutoff_complete: Duration::from_nanos(offsets[1]),
            cleanup_complete: Duration::from_nanos(offsets[2]),
            disarm_start: Duration::from_nanos(offsets[3]),
            feed_deadline: Duration::from_nanos(offsets[4]),
            terminal_receipt: Duration::from_nanos(offsets[5]),
            worker_join: Duration::from_nanos(offsets[6]),
        }
    }

    #[test]
    fn absolute_schedule_is_strict_ordered_checked_and_nonextending() {
        let run_scope = WatchdogRunScope::new();
        let (mut issuer, _expectation) = issue_teardown_budget_authority(run_scope);
        let now = Instant::now();

        assert!(issuer.issue_at(now, policy([1, 2, 3, 4, 5, 6, 6])).is_err());

        let another_scope = WatchdogRunScope::new();
        let (mut overflow_issuer, _) = issue_teardown_budget_authority(another_scope);
        let overflow_policy = TeardownBudgetPolicy {
            cutoff_start: Duration::from_nanos(1),
            cutoff_complete: Duration::from_nanos(2),
            cleanup_complete: Duration::from_nanos(3),
            disarm_start: Duration::from_nanos(4),
            feed_deadline: Duration::from_nanos(5),
            terminal_receipt: Duration::from_nanos(6),
            worker_join: Duration::MAX,
        };
        assert!(overflow_issuer.issue_at(now, overflow_policy).is_err());

        let defaults = TeardownBudgetPolicy::watchdog_default().offsets();
        assert!(defaults.windows(2).all(|pair| pair[0].1 < pair[1].1));
    }

    #[test]
    fn budget_is_one_shot_run_and_issuer_bound() {
        let scope = WatchdogRunScope::new();
        let (mut issuer, expectation) = issue_teardown_budget_authority(scope.clone());
        let now = Instant::now();
        let budget = issuer.issue_at(now, policy([1, 2, 3, 4, 5, 6, 7])).unwrap();
        let view = budget.view();

        assert!(view.authorizes(&scope, &expectation));
        assert!(issuer.issue_at(now, policy([2, 3, 4, 5, 6, 7, 8])).is_err());

        let foreign_scope = WatchdogRunScope::new();
        assert!(!view.authorizes(&foreign_scope, &expectation));
        let (_foreign_issuer, foreign_expectation) = issue_teardown_budget_authority(scope.clone());
        assert!(!view.authorizes(&scope, &foreign_expectation));

        let disarm = budget
            .begin_disarm_at(now + Duration::from_nanos(3))
            .unwrap();
        assert!(disarm.authorizes(&scope, &expectation));
        assert_eq!(disarm.started_at(), now + Duration::from_nanos(3));
    }

    #[test]
    fn sequential_stages_share_one_cleanup_deadline() {
        let scope = WatchdogRunScope::new();
        let (mut issuer, _) = issue_teardown_budget_authority(scope);
        let now = Instant::now();
        let budget = issuer
            .issue_at(now, policy([1, 2, 10, 12, 14, 16, 18]))
            .unwrap();
        let view = budget.view();

        assert_eq!(
            view.remaining_capped_at(
                TeardownStage::CleanupComplete,
                Duration::from_nanos(9),
                now + Duration::from_nanos(3),
            )
            .unwrap(),
            Duration::from_nanos(7)
        );
        assert_eq!(
            view.remaining_capped_at(
                TeardownStage::CleanupComplete,
                Duration::from_nanos(9),
                now + Duration::from_nanos(8),
            )
            .unwrap(),
            Duration::from_nanos(2)
        );
        assert!(view
            .remaining_at(
                TeardownStage::CleanupComplete,
                now + Duration::from_nanos(10),
            )
            .is_err());
    }

    #[test]
    fn every_stage_boundary_is_strict() {
        let scope = WatchdogRunScope::new();
        let (mut issuer, _) = issue_teardown_budget_authority(scope);
        let now = Instant::now();
        let budget = issuer.issue_at(now, policy([1, 2, 3, 4, 5, 6, 7])).unwrap();
        let view = budget.view();

        view.require_not_before_start(now).unwrap();
        let before_budget = now - Duration::from_nanos(1);
        assert!(view.require_not_before_start(before_budget).is_err());

        for stage in [
            TeardownStage::CutoffStart,
            TeardownStage::CutoffComplete,
            TeardownStage::CleanupComplete,
            TeardownStage::DisarmStart,
            TeardownStage::FeedDeadline,
            TeardownStage::TerminalReceipt,
            TeardownStage::WorkerJoin,
        ] {
            let deadline = view.deadline(stage);
            let just_before = deadline.checked_sub(Duration::from_nanos(1)).unwrap();
            assert!(view.remaining_at(stage, before_budget).is_err());
            assert!(view.require_completed_at(stage, before_budget).is_err());
            assert_eq!(
                view.remaining_at(stage, just_before).unwrap(),
                Duration::from_nanos(1)
            );
            assert!(view.remaining_at(stage, deadline).is_err());
            view.require_completed_at(stage, just_before).unwrap();
            assert!(view.require_completed_at(stage, deadline).is_err());
        }

        let disarm_deadline = view.deadline(TeardownStage::DisarmStart);
        assert!(budget
            .view()
            .remaining_at(TeardownStage::DisarmStart, before_budget)
            .is_err());
        assert!(budget.begin_disarm_at(before_budget).is_err());
    }

    #[test]
    fn disarm_command_and_completion_reject_pre_budget_timestamps() {
        let scope = WatchdogRunScope::new();
        let (mut issuer, _) = issue_teardown_budget_authority(scope);
        let now = Instant::now();
        let before_budget = now - Duration::from_nanos(1);
        let budget = issuer.issue_at(now, policy([1, 2, 3, 4, 5, 6, 7])).unwrap();
        let disarm_deadline = budget.deadline(TeardownStage::DisarmStart);
        let disarm = budget
            .begin_disarm_at(disarm_deadline - Duration::from_nanos(1))
            .unwrap();
        assert!(disarm
            .require_disarm_command_started_at(before_budget)
            .is_err());
        assert!(disarm
            .require_completed_at(TeardownStage::FeedDeadline, before_budget)
            .is_err());
        disarm
            .require_disarm_command_started_at(disarm_deadline - Duration::from_nanos(1))
            .unwrap();
        assert!(disarm
            .require_disarm_command_started_at(disarm_deadline)
            .is_err());
    }
}
