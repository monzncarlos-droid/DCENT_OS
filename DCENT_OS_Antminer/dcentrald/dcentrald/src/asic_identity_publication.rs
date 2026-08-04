//! Generation-bound publication of measured ASIC enumeration evidence.
//!
//! The work dispatcher is the first owner that simultaneously holds the
//! dispatcher chip identity and every active mining chain. This module keeps
//! publication behind that boundary and binds it to an immutable composition
//! token. Activating a later composition revokes prior measured evidence before
//! an older dispatcher can publish again.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use dcentrald_api::{HardwareCompositionToken, HardwareIdentityEvidence, HardwareInfo};
use dcentrald_asic::chain::MeasuredEnumeration;
use dcentrald_asic::drivers::{ChipDriverAdmission, ChipRegistry};

use crate::execution_fence::ExecutionFenceTryWait;
use crate::runtime_execution::{
    runtime_execution_domain, RevokedRuntimeExecutionFence, RuntimeExecutionCommitPort,
    RuntimeExecutionTerminal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExpectedMiningChain {
    pub chain_id: u8,
    pub chip_count: u8,
}

/// Receipt minted only when a chain's GetAddress enumeration succeeds.
///
/// Keeping construction in this module makes provenance explicit at daemon
/// call sites. Non-zero chain fields, model profiles, and passthrough state are
/// deliberately not interchangeable with this receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnumeratedMiningChainReceipt {
    chain_id: u8,
    chip_count: u8,
    chip_id: u16,
}

impl EnumeratedMiningChainReceipt {
    pub(crate) fn from_successful_get_address(chain_id: u8, measured: MeasuredEnumeration) -> Self {
        Self {
            chain_id,
            chip_count: measured.chip_count(),
            chip_id: measured.chip_id(),
        }
    }

    pub(crate) fn chain_id(self) -> u8 {
        self.chain_id
    }

    pub(crate) fn chip_count(self) -> u8 {
        self.chip_count
    }

    pub(crate) fn chip_id(self) -> u16 {
        self.chip_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnumerationConsensus {
    token: HardwareCompositionToken,
    chip_id: u16,
    chip_label: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AsicIdentityPublicationError {
    #[error("dispatcher composition has no initialized mining chains")]
    ZeroChains,
    #[error("dispatcher composition repeats chain {0}")]
    DuplicateExpectedChain(u8),
    #[error("dispatcher composition chain {0} has zero enumerated chips")]
    ZeroChipCount(u8),
    #[error("dispatcher generation counter is exhausted")]
    GenerationExhausted,
    #[error("dispatcher composition revocation epoch is exhausted; activation remains closed")]
    RevocationEpochExhausted,
    #[error("dispatcher ASIC identity 0x{0:04X} is unsupported")]
    UnsupportedChip(u16),
    #[error("enumeration snapshot has {observed} chains but composition expects {expected}")]
    Partial { expected: usize, observed: usize },
    #[error("enumeration snapshot repeats chain {0}")]
    DuplicateObservedChain(u8),
    #[error("enumeration snapshot contains unexpected chain {0}")]
    UnexpectedChain(u8),
    #[error(
        "enumeration snapshot chain {chain_id} chip count {observed} disagrees with composition {expected}"
    )]
    CompositionMismatch {
        chain_id: u8,
        expected: u8,
        observed: u8,
    },
    #[error(
        "enumeration snapshot chain {chain_id} ASIC 0x{observed:04X} disagrees with dispatcher 0x{dispatcher:04X}"
    )]
    Mixed {
        chain_id: u8,
        dispatcher: u16,
        observed: u16,
    },
    #[error("dispatcher composition generation is stale")]
    StaleGeneration,
    #[error("dispatcher identity publication state is unavailable")]
    StateUnavailable,
    #[error("dispatcher composition authority is busy")]
    AuthorityBusy,
    #[error("preceding dispatcher composition revocation is still pending")]
    RevocationPending,
    #[error("dispatcher composition did not become quiescent within {timeout_ms} ms")]
    RevocationDeadlineExceeded { timeout_ms: u64 },
    #[error(
        "dispatcher composition generation {generation} ({fingerprint}) became quiescent after an execution commit panic"
    )]
    ExecutionFencePoisoned {
        generation: u64,
        fingerprint: String,
    },
}

#[derive(Debug, Default)]
struct AuthorityState {
    phase: CompositionPhase,
    last_completed: Option<CompletedComposition>,
}

#[derive(Debug, Default)]
enum CompositionPhase {
    #[default]
    Idle,
    Active(ActiveComposition),
    Revoking(RevokingComposition),
}

#[derive(Debug, Clone)]
struct CompletedComposition {
    token: HardwareCompositionToken,
    completed_at: Instant,
}

#[derive(Debug)]
struct ActiveComposition {
    token: HardwareCompositionToken,
    hardware_info: Arc<Mutex<HardwareInfo>>,
    execution_terminal: RuntimeExecutionTerminal,
}

#[derive(Debug)]
struct RevokingComposition {
    token: HardwareCompositionToken,
    hardware_info: Arc<Mutex<HardwareInfo>>,
    fence: Option<RevokedRuntimeExecutionFence>,
    fenced_at: Option<Instant>,
    identity_cleared_at: Option<Instant>,
    fence_poisoned: bool,
    identity_cleared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionInvalidationStatus {
    AlreadyIdle {
        last_completed_at: Option<Instant>,
        last_completed_token: Option<HardwareCompositionToken>,
    },
    Fenced {
        completed_at: Instant,
        token: HardwareCompositionToken,
    },
    Pending {
        token: HardwareCompositionToken,
    },
}

/// Move-only proof that one exact composition boundary was observed closed
/// before its absolute deadline.
#[derive(Debug)]
pub(crate) struct CompositionInvalidationReceipt {
    boundary_epoch: u64,
    completed_at: Instant,
    fenced_token: Option<HardwareCompositionToken>,
    activation_barrier: Option<Arc<AtomicU64>>,
}

/// Move-only ownership of one exact, still-closed composition boundary.
///
/// Opening the boundary synchronously closes execution admission. Completing
/// it waits on that same transition; it never starts a second invalidation.
/// The activation barrier transfers into the resulting receipt, so a later
/// generation cannot open while watchdog-disarm evidence still exists.
#[derive(Debug)]
pub(crate) struct CompositionInvalidationBoundary {
    boundary_epoch: u64,
    authority_state: Arc<Mutex<AuthorityState>>,
    activation_barrier: Option<Arc<AtomicU64>>,
    target: Option<HardwareCompositionToken>,
    completion: Option<(Instant, Option<HardwareCompositionToken>)>,
    terminal_error: Option<AsicIdentityPublicationError>,
    #[cfg(test)]
    bounded_probe_pause: Arc<TestPause>,
}

impl CompositionInvalidationBoundary {
    fn observe(
        &mut self,
        status: CompositionInvalidationStatus,
    ) -> Result<(), AsicIdentityPublicationError> {
        match status {
            CompositionInvalidationStatus::Fenced {
                completed_at,
                token,
            } => {
                if self.target.as_ref().is_some_and(|target| target != &token) {
                    return Err(AsicIdentityPublicationError::StaleGeneration);
                }
                self.target = Some(token.clone());
                self.completion = Some((completed_at, Some(token)));
            }
            CompositionInvalidationStatus::Pending { token } => {
                if self.target.as_ref().is_some_and(|target| target != &token) {
                    return Err(AsicIdentityPublicationError::StaleGeneration);
                }
                self.target = Some(token);
            }
            CompositionInvalidationStatus::AlreadyIdle {
                last_completed_at,
                last_completed_token,
            } => {
                if let Some(target) = self.target.as_ref() {
                    if last_completed_token.as_ref() != Some(target) {
                        return Err(AsicIdentityPublicationError::StaleGeneration);
                    }
                    self.completion = Some((
                        last_completed_at.ok_or(AsicIdentityPublicationError::StateUnavailable)?,
                        Some(target.clone()),
                    ));
                } else {
                    self.completion = Some((Instant::now(), None));
                }
            }
        }
        Ok(())
    }

    fn probe(&mut self) -> Result<(), AsicIdentityPublicationError> {
        #[cfg(test)]
        self.bounded_probe_pause.wait_if_enabled();
        let status = {
            let mut state = match self.authority_state.try_lock() {
                Ok(state) => state,
                Err(TryLockError::WouldBlock) => {
                    return Err(AsicIdentityPublicationError::AuthorityBusy)
                }
                Err(TryLockError::Poisoned(error)) => error.into_inner(),
            };
            begin_active_revocation(&mut state);
            probe_revocation(&mut state)?
        };
        self.observe(status)
    }

    pub(crate) async fn complete_bounded(
        mut self,
        timeout: Duration,
    ) -> Result<CompositionInvalidationReceipt, AsicIdentityPublicationError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some((completed_at, fenced_token)) = self.completion.take() {
                if completed_at >= deadline.into_std() {
                    return Err(AsicIdentityPublicationError::RevocationDeadlineExceeded {
                        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                    });
                }
                if let Some(error) = self.terminal_error.take() {
                    return Err(error);
                }
                return Ok(CompositionInvalidationReceipt {
                    boundary_epoch: self.boundary_epoch,
                    completed_at,
                    fenced_token,
                    activation_barrier: self.activation_barrier.take(),
                });
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AsicIdentityPublicationError::RevocationDeadlineExceeded {
                    timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                });
            }
            match self.probe() {
                Ok(()) | Err(AsicIdentityPublicationError::AuthorityBusy) => {}
                Err(error) => return Err(error),
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(AsicIdentityPublicationError::RevocationDeadlineExceeded {
                        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }
}

impl Drop for CompositionInvalidationBoundary {
    fn drop(&mut self) {
        if let Some(barrier) = self.activation_barrier.take() {
            let previous = barrier.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "composition activation barrier underflow");
        }
    }
}

impl CompositionInvalidationReceipt {
    pub(crate) fn boundary_epoch(&self) -> u64 {
        self.boundary_epoch
    }

    pub(crate) fn completed_at(&self) -> Instant {
        self.completed_at
    }

    pub(crate) fn fenced_token(&self) -> Option<&HardwareCompositionToken> {
        self.fenced_token.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn test_idle() -> Self {
        Self {
            boundary_epoch: 0,
            completed_at: Instant::now(),
            fenced_token: None,
            activation_barrier: None,
        }
    }
}

impl Drop for CompositionInvalidationReceipt {
    fn drop(&mut self) {
        if let Some(barrier) = self.activation_barrier.take() {
            let previous = barrier.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "composition activation barrier underflow");
        }
    }
}

fn begin_active_revocation(state: &mut AuthorityState) {
    let phase = std::mem::take(&mut state.phase);
    state.phase = match phase {
        CompositionPhase::Active(active) => CompositionPhase::Revoking(RevokingComposition {
            token: active.token,
            hardware_info: active.hardware_info,
            fence: Some(active.execution_terminal.revoke()),
            fenced_at: None,
            identity_cleared_at: None,
            fence_poisoned: false,
            identity_cleared: false,
        }),
        phase => phase,
    };
}

fn probe_revocation(
    state: &mut AuthorityState,
) -> Result<CompositionInvalidationStatus, AsicIdentityPublicationError> {
    let revoking = match &mut state.phase {
        CompositionPhase::Idle => {
            return Ok(CompositionInvalidationStatus::AlreadyIdle {
                last_completed_at: state
                    .last_completed
                    .as_ref()
                    .map(|completion| completion.completed_at),
                last_completed_token: state
                    .last_completed
                    .as_ref()
                    .map(|completion| completion.token.clone()),
            })
        }
        CompositionPhase::Active(active) => {
            return Ok(CompositionInvalidationStatus::Pending {
                token: active.token.clone(),
            })
        }
        CompositionPhase::Revoking(revoking) => revoking,
    };

    if !revoking.identity_cleared && try_restore_non_measured_identity(&revoking.hardware_info)? {
        revoking.identity_cleared = true;
        revoking.identity_cleared_at = Some(Instant::now());
    }
    if let Some(fence) = revoking.fence.take() {
        match fence.try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Pending(fence) => revoking.fence = Some(fence),
            ExecutionFenceTryWait::Fenced(receipt) => {
                revoking.fenced_at = Some(receipt.fenced_at());
                revoking.fence_poisoned = receipt.fence_poisoned();
            }
        }
    }

    if revoking.fence_poisoned {
        return Err(AsicIdentityPublicationError::ExecutionFencePoisoned {
            generation: revoking.token.generation,
            fingerprint: revoking.token.fingerprint.clone(),
        });
    }

    if revoking.identity_cleared && revoking.fenced_at.is_some() {
        let fenced_at = revoking
            .fenced_at
            .expect("completed revocation retained its fence timestamp");
        let identity_cleared_at = revoking
            .identity_cleared_at
            .expect("completed revocation retained its identity-clear timestamp");
        let completed_at = fenced_at.max(identity_cleared_at);
        let token = revoking.token.clone();
        state.phase = CompositionPhase::Idle;
        state.last_completed = Some(CompletedComposition {
            token: token.clone(),
            completed_at,
        });
        Ok(CompositionInvalidationStatus::Fenced {
            completed_at,
            token,
        })
    } else {
        Ok(CompositionInvalidationStatus::Pending {
            token: revoking.token.clone(),
        })
    }
}

fn try_restore_non_measured_identity(
    hardware_info: &Arc<Mutex<HardwareInfo>>,
) -> Result<bool, AsicIdentityPublicationError> {
    let mut hardware = match hardware_info.try_lock() {
        Ok(hardware) => hardware,
        Err(TryLockError::WouldBlock) => return Ok(false),
        Err(TryLockError::Poisoned(_)) => {
            return Err(AsicIdentityPublicationError::StateUnavailable)
        }
    };
    hardware.identification.clear_measured_asic_evidence();
    hardware.chip_type = hardware
        .identification
        .best_non_measured_asic_resolved_value()
        .unwrap_or("Unknown")
        .to_string();
    Ok(true)
}

/// Daemon-owned composition generation authority.
///
/// This is process-local and is not a global singleton. A future dispatcher
/// replacement activates a new generation through the same authority, which
/// invalidates every older publication port.
#[derive(Debug)]
pub(crate) struct DispatcherCompositionAuthority {
    next_generation: AtomicU64,
    revocation_epoch: Arc<AtomicU64>,
    active_generation: Arc<AtomicU64>,
    state: Arc<Mutex<AuthorityState>>,
    open_invalidation_boundaries: Arc<AtomicU64>,
    #[cfg(test)]
    activation_publish_pause: TestPause,
    #[cfg(test)]
    bounded_probe_pause: Arc<TestPause>,
}

impl Default for DispatcherCompositionAuthority {
    fn default() -> Self {
        Self {
            next_generation: AtomicU64::new(0),
            revocation_epoch: Arc::new(AtomicU64::new(0)),
            active_generation: Arc::new(AtomicU64::new(0)),
            state: Arc::new(Mutex::new(AuthorityState::default())),
            open_invalidation_boundaries: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            activation_publish_pause: TestPause::default(),
            #[cfg(test)]
            bounded_probe_pause: Arc::new(TestPause::default()),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestPause {
    enabled: std::sync::atomic::AtomicBool,
    entered: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl TestPause {
    fn enable(&self) {
        self.entered.store(false, Ordering::Release);
        self.released.store(false, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    fn wait_if_enabled(&self) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        self.entered.store(true, Ordering::Release);
        while !self.released.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        self.enabled.store(false, Ordering::Release);
    }

    fn wait_until_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !self.entered.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "test pause was not reached within one second"
            );
            std::thread::yield_now();
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
}

impl DispatcherCompositionAuthority {
    /// Linearize a composition boundary before closing the current generation.
    /// Activation records the returned epoch and may publish only if no later
    /// boundary increment occurred while it held the authority mutex.
    fn close_execution_admission(&self) -> Result<u64, AsicIdentityPublicationError> {
        let epoch = self
            .revocation_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| AsicIdentityPublicationError::RevocationEpochExhausted)
            .and_then(|previous| {
                previous
                    .checked_add(1)
                    .ok_or(AsicIdentityPublicationError::RevocationEpochExhausted)
            });
        self.active_generation.store(0, Ordering::Release);
        epoch
    }

    fn invalidate_active_state(
        &self,
    ) -> Result<CompositionInvalidationStatus, AsicIdentityPublicationError> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return Err(AsicIdentityPublicationError::AuthorityBusy)
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        begin_active_revocation(&mut state);
        probe_revocation(&mut state)
    }

    /// Open one exact cancellation boundary and retain its activation barrier.
    pub(crate) fn begin_invalidation(&self) -> CompositionInvalidationBoundary {
        let barrier_result = self.open_invalidation_boundaries.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        );
        let activation_barrier = barrier_result
            .ok()
            .map(|_| Arc::clone(&self.open_invalidation_boundaries));
        let mut boundary = CompositionInvalidationBoundary {
            boundary_epoch: self.revocation_epoch.load(Ordering::Acquire),
            authority_state: Arc::clone(&self.state),
            activation_barrier,
            target: None,
            completion: None,
            terminal_error: None,
            #[cfg(test)]
            bounded_probe_pause: Arc::clone(&self.bounded_probe_pause),
        };
        if barrier_result.is_err() {
            boundary.terminal_error = Some(AsicIdentityPublicationError::GenerationExhausted);
        }
        match self.close_execution_admission() {
            Ok(boundary_epoch) => boundary.boundary_epoch = boundary_epoch,
            Err(error) => boundary.terminal_error = Some(error),
        }
        match self.invalidate_active_state() {
            Ok(status) => {
                if let Err(error) = boundary.observe(status) {
                    boundary.terminal_error = Some(error);
                }
            }
            Err(AsicIdentityPublicationError::AuthorityBusy) => {}
            Err(error) => boundary.terminal_error = Some(error),
        }
        boundary
    }

    #[cfg(test)]
    pub(crate) fn invalidate_active(
        &self,
    ) -> Result<CompositionInvalidationStatus, AsicIdentityPublicationError> {
        let mut boundary = self.begin_invalidation();
        if let Some(error) = boundary.terminal_error.take() {
            return Err(error);
        }
        if let Some((completed_at, fenced_token)) = boundary.completion.take() {
            return Ok(match fenced_token {
                Some(token) => CompositionInvalidationStatus::Fenced {
                    completed_at,
                    token,
                },
                None => CompositionInvalidationStatus::AlreadyIdle {
                    last_completed_at: Some(completed_at),
                    last_completed_token: None,
                },
            });
        }
        Ok(CompositionInvalidationStatus::Pending {
            token: boundary
                .target
                .take()
                .ok_or(AsicIdentityPublicationError::AuthorityBusy)?,
        })
    }

    /// Bound composition invalidation without spawning or parking a worker.
    /// Cancellation leaves the revoked fence inside `RevokingComposition`, so
    /// a later retry can complete and no replacement generation can overlap.
    pub(crate) async fn invalidate_active_bounded(
        &self,
        timeout: Duration,
    ) -> Result<CompositionInvalidationReceipt, AsicIdentityPublicationError> {
        self.begin_invalidation().complete_bounded(timeout).await
    }

    fn invalidate_if_current(
        &self,
        token: &HardwareCompositionToken,
        hardware_info: &Arc<Mutex<HardwareInfo>>,
    ) -> Result<CompositionInvalidationStatus, AsicIdentityPublicationError> {
        let mut epoch_error = None;
        if self
            .active_generation
            .compare_exchange(token.generation, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            && self
                .revocation_epoch
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                })
                .is_err()
        {
            epoch_error = Some(AsicIdentityPublicationError::RevocationEpochExhausted);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return Err(AsicIdentityPublicationError::AuthorityBusy)
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if !matches!(&state.phase, CompositionPhase::Active(active) if &active.token == token) {
            let status = probe_revocation(&mut state)?;
            return epoch_error.map_or(Ok(status), Err);
        }
        begin_active_revocation(&mut state);
        if matches!(
            &state.phase,
            CompositionPhase::Revoking(revoking)
                if !Arc::ptr_eq(&revoking.hardware_info, hardware_info)
        ) {
            try_restore_non_measured_identity(hardware_info)?;
        }
        let status = probe_revocation(&mut state)?;
        epoch_error.map_or(Ok(status), Err)
    }

    fn activate_publication(
        &self,
        mut expected: Vec<ExpectedMiningChain>,
        receipts: Vec<EnumeratedMiningChainReceipt>,
        hardware_info: Arc<Mutex<HardwareInfo>>,
    ) -> Result<AsicIdentityPublicationPort, AsicIdentityPublicationError> {
        if self.open_invalidation_boundaries.load(Ordering::Acquire) != 0 {
            return Err(AsicIdentityPublicationError::RevocationPending);
        }
        // Every attempted replacement is a composition boundary. Close prior
        // commit admission before the authority mutex or candidate validation.
        let boundary_epoch = self.close_execution_admission()?;
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return Err(AsicIdentityPublicationError::AuthorityBusy)
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        // Every activation attempt is a composition boundary, including an
        // invalid replacement. Revoke the preceding measured claim before
        // validating the next composition so malformed or empty composition
        // cannot inherit confidence from an older dispatcher.
        begin_active_revocation(&mut state);
        if matches!(
            probe_revocation(&mut state)?,
            CompositionInvalidationStatus::Pending { .. }
        ) {
            return Err(AsicIdentityPublicationError::RevocationPending);
        }
        if self.open_invalidation_boundaries.load(Ordering::Acquire) != 0 {
            return Err(AsicIdentityPublicationError::RevocationPending);
        }
        if !try_restore_non_measured_identity(&hardware_info)? {
            return Err(AsicIdentityPublicationError::StateUnavailable);
        }

        expected.sort_unstable();
        if expected.is_empty() {
            return Err(AsicIdentityPublicationError::ZeroChains);
        }
        for (index, chain) in expected.iter().enumerate() {
            if chain.chip_count == 0 {
                return Err(AsicIdentityPublicationError::ZeroChipCount(chain.chain_id));
            }
            if index > 0 && expected[index - 1].chain_id == chain.chain_id {
                return Err(AsicIdentityPublicationError::DuplicateExpectedChain(
                    chain.chain_id,
                ));
            }
        }

        let generation = self
            .next_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| AsicIdentityPublicationError::GenerationExhausted)?
            + 1;
        let fingerprint = expected
            .iter()
            .map(|chain| format!("{}:{}", chain.chain_id, chain.chip_count))
            .collect::<Vec<_>>()
            .join(",");
        let token = HardwareCompositionToken::new(generation, format!("chains:{fingerprint}"));
        let (execution_commit_port, execution_terminal) =
            runtime_execution_domain(token.clone(), Arc::clone(&self.active_generation));

        // The authority lock has remained held throughout the transition, so
        // an old port cannot pass its stale-token check in the middle of it.
        state.phase = CompositionPhase::Active(ActiveComposition {
            token: token.clone(),
            hardware_info: Arc::clone(&hardware_info),
            execution_terminal,
        });
        #[cfg(test)]
        self.activation_publish_pause.wait_if_enabled();
        self.active_generation.store(generation, Ordering::Release);

        // A lock-independent invalidation may have been requested while this
        // activation held the authority mutex. Never overwrite that later
        // cancellation boundary with an open generation.
        if self.revocation_epoch.load(Ordering::Acquire) != boundary_epoch
            || self.open_invalidation_boundaries.load(Ordering::Acquire) != 0
        {
            let _ = self.active_generation.compare_exchange(
                generation,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            begin_active_revocation(&mut state);
            return Err(AsicIdentityPublicationError::StaleGeneration);
        }

        Ok(AsicIdentityPublicationPort {
            authority: Arc::clone(&self.state),
            active_generation: Arc::clone(&self.active_generation),
            revocation_epoch: Arc::clone(&self.revocation_epoch),
            token,
            expected,
            receipts,
            hardware_info,
            execution_commit_port,
            execution_terminal: match &state.phase {
                CompositionPhase::Active(active) => active.execution_terminal.clone(),
                _ => unreachable!("active composition was installed above"),
            },
        })
    }

    /// Consume one measured driver admission into the same generation that
    /// owns the dispatcher's ASIC-identity publication capability.
    ///
    /// Receipt consensus is evaluated before this method returns, so a partial,
    /// mixed, or composition-mismatched snapshot cannot cross the dispatcher
    /// constructor. The returned bundle is move-only and has no raw chip-ID or
    /// execution-policy substitute.
    pub(crate) fn activate_execution(
        &self,
        driver_admission: ChipDriverAdmission,
        expected: Vec<ExpectedMiningChain>,
        receipts: Vec<EnumeratedMiningChainReceipt>,
        hardware_info: Arc<Mutex<HardwareInfo>>,
    ) -> Result<MeasuredDispatcherExecutionAdmission, AsicIdentityPublicationError> {
        let publication = self.activate_publication(expected, receipts, hardware_info)?;
        let token = publication.token.clone();
        let publication_hardware_info = Arc::clone(&publication.hardware_info);
        let session = match publication.publish(driver_admission.chip_id()) {
            Ok(session) => session,
            Err(error) => {
                if matches!(
                    self.invalidate_if_current(&token, &publication_hardware_info)?,
                    CompositionInvalidationStatus::Pending { .. }
                ) {
                    return Err(AsicIdentityPublicationError::RevocationPending);
                }
                return Err(error);
            }
        };
        Ok(MeasuredDispatcherExecutionAdmission {
            driver_admission,
            session,
        })
    }

    #[cfg(test)]
    pub(crate) fn activate(
        &self,
        expected: Vec<ExpectedMiningChain>,
        receipts: Vec<EnumeratedMiningChainReceipt>,
        hardware_info: Arc<Mutex<HardwareInfo>>,
    ) -> Result<AsicIdentityPublicationPort, AsicIdentityPublicationError> {
        self.activate_publication(expected, receipts, hardware_info)
    }
}

/// Immutable dispatcher-scoped publication capability.
#[derive(Debug)]
pub(crate) struct AsicIdentityPublicationPort {
    authority: Arc<Mutex<AuthorityState>>,
    active_generation: Arc<AtomicU64>,
    revocation_epoch: Arc<AtomicU64>,
    token: HardwareCompositionToken,
    expected: Vec<ExpectedMiningChain>,
    receipts: Vec<EnumeratedMiningChainReceipt>,
    hardware_info: Arc<Mutex<HardwareInfo>>,
    execution_commit_port: RuntimeExecutionCommitPort,
    execution_terminal: RuntimeExecutionTerminal,
}

impl AsicIdentityPublicationPort {
    fn evaluate(
        &self,
        dispatcher_chip_id: u16,
    ) -> Result<EnumerationConsensus, AsicIdentityPublicationError> {
        let registry = ChipRegistry::new();
        let recognition = registry.recognize(dispatcher_chip_id).ok_or(
            AsicIdentityPublicationError::UnsupportedChip(dispatcher_chip_id),
        )?;
        if self.receipts.len() != self.expected.len() {
            return Err(AsicIdentityPublicationError::Partial {
                expected: self.expected.len(),
                observed: self.receipts.len(),
            });
        }
        let mut observations = self.receipts.clone();
        observations.sort_unstable_by_key(|chain| chain.chain_id);
        for (index, observed) in observations.iter().enumerate() {
            if index > 0 && observations[index - 1].chain_id == observed.chain_id {
                return Err(AsicIdentityPublicationError::DuplicateObservedChain(
                    observed.chain_id,
                ));
            }
            let Some(expected) = self
                .expected
                .iter()
                .find(|expected| expected.chain_id == observed.chain_id)
            else {
                return Err(AsicIdentityPublicationError::UnexpectedChain(
                    observed.chain_id,
                ));
            };
            if observed.chip_count != expected.chip_count {
                return Err(AsicIdentityPublicationError::CompositionMismatch {
                    chain_id: observed.chain_id,
                    expected: expected.chip_count,
                    observed: observed.chip_count,
                });
            }
            if observed.chip_id != dispatcher_chip_id {
                return Err(AsicIdentityPublicationError::Mixed {
                    chain_id: observed.chain_id,
                    dispatcher: dispatcher_chip_id,
                    observed: observed.chip_id,
                });
            }
        }

        Ok(EnumerationConsensus {
            token: self.token.clone(),
            chip_id: dispatcher_chip_id,
            chip_label: recognition.chip_name().to_string(),
        })
    }

    pub(crate) fn publish(
        self,
        dispatcher_chip_id: u16,
    ) -> Result<ActiveCompositionSession, AsicIdentityPublicationError> {
        let consensus = self.evaluate(dispatcher_chip_id)?;
        let generation = consensus.token.generation;
        if self.active_generation.load(Ordering::Acquire) != generation {
            return Err(AsicIdentityPublicationError::StaleGeneration);
        }
        let state = match self.authority.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return Err(AsicIdentityPublicationError::AuthorityBusy)
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if !matches!(
            &state.phase,
            CompositionPhase::Active(active) if active.token == consensus.token
        ) {
            return Err(AsicIdentityPublicationError::StaleGeneration);
        }
        if self.active_generation.load(Ordering::Acquire) != generation {
            return Err(AsicIdentityPublicationError::StaleGeneration);
        }

        let mut hardware = match self.hardware_info.try_lock() {
            Ok(hardware) => hardware,
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                return Err(AsicIdentityPublicationError::StateUnavailable)
            }
        };
        hardware.identification.clear_measured_asic_evidence();
        hardware
            .identification
            .push_evidence(HardwareIdentityEvidence::measured_asic_enumeration(
                consensus.chip_id,
                &consensus.chip_label,
                consensus.token,
            ));
        hardware.chip_type = consensus.chip_label;
        if self.active_generation.load(Ordering::Acquire) != generation {
            hardware.identification.clear_measured_asic_evidence();
            hardware.chip_type = hardware
                .identification
                .best_non_measured_asic_resolved_value()
                .unwrap_or("Unknown")
                .to_string();
            return Err(AsicIdentityPublicationError::StaleGeneration);
        }
        drop(hardware);
        drop(state);

        Ok(ActiveCompositionSession {
            authority: Arc::clone(&self.authority),
            active_generation: Arc::clone(&self.active_generation),
            revocation_epoch: Arc::clone(&self.revocation_epoch),
            token: self.token,
            hardware_info: Arc::clone(&self.hardware_info),
            execution_commit_port: self.execution_commit_port,
            execution_terminal: Some(self.execution_terminal),
            finished: false,
        })
    }
}

/// Move-only handoff from measured Phase 7 authority to one work dispatcher.
///
/// This type fuses the exact executable driver admission with an already
/// published lease for the same measured composition generation. Only
/// [`DispatcherCompositionAuthority::activate_execution`] can mint it.
#[derive(Debug)]
pub(crate) struct MeasuredDispatcherExecutionAdmission {
    driver_admission: ChipDriverAdmission,
    session: ActiveCompositionSession,
}

impl MeasuredDispatcherExecutionAdmission {
    pub(crate) fn chip_id(&self) -> u16 {
        self.driver_admission.chip_id()
    }

    pub(crate) fn runtime_execution_commit_port(&self) -> RuntimeExecutionCommitPort {
        self.session.execution_commit_port.clone()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ChipDriverAdmission,
        ActiveCompositionSession,
        RuntimeExecutionCommitPort,
    ) {
        let execution_commit_port = self.session.execution_commit_port.clone();
        (self.driver_admission, self.session, execution_commit_port)
    }
}

/// Engine-owned lease for one published composition generation.
///
/// The mining engine must retain this value for its whole dispatch lifetime.
/// Explicit revocation is deterministic on normal shutdown; `Drop` is the
/// non-panicking fallback for task cancellation and unwind. A stale lease can
/// never clear a later generation because revocation compares the exact token
/// while holding the authority lock before touching `HardwareInfo`.
#[derive(Debug)]
pub(crate) struct ActiveCompositionSession {
    authority: Arc<Mutex<AuthorityState>>,
    active_generation: Arc<AtomicU64>,
    revocation_epoch: Arc<AtomicU64>,
    token: HardwareCompositionToken,
    hardware_info: Arc<Mutex<HardwareInfo>>,
    execution_commit_port: RuntimeExecutionCommitPort,
    execution_terminal: Option<RuntimeExecutionTerminal>,
    finished: bool,
}

impl ActiveCompositionSession {
    pub(crate) fn revoke(mut self) -> Result<(), AsicIdentityPublicationError> {
        let result = self.revoke_if_current_nonblocking();
        self.finished = true;
        result
    }

    fn revoke_if_current_nonblocking(&mut self) -> Result<(), AsicIdentityPublicationError> {
        let mut epoch_error = None;
        if self
            .active_generation
            .compare_exchange(
                self.token.generation,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            && self
                .revocation_epoch
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                })
                .is_err()
        {
            epoch_error = Some(AsicIdentityPublicationError::RevocationEpochExhausted);
        }
        // Close this exact execution domain before even attempting the
        // authority lock. The returned revoked observer is intentionally
        // dropped: the authority retains its own terminal clone and owns the
        // retryable positive-evidence path.
        if let Some(terminal) = self.execution_terminal.take() {
            drop(terminal.revoke());
        }
        let mut state = match self.authority.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return Err(epoch_error.unwrap_or(AsicIdentityPublicationError::RevocationPending))
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if matches!(
            &state.phase,
            CompositionPhase::Active(active) if active.token == self.token
        ) {
            begin_active_revocation(&mut state);
        } else if !matches!(
            &state.phase,
            CompositionPhase::Revoking(revoking) if revoking.token == self.token
        ) {
            return epoch_error.map_or(Ok(()), Err);
        }
        let result = match probe_revocation(&mut state)? {
            CompositionInvalidationStatus::Pending { .. } => {
                Err(AsicIdentityPublicationError::RevocationPending)
            }
            CompositionInvalidationStatus::AlreadyIdle { .. }
            | CompositionInvalidationStatus::Fenced { .. } => Ok(()),
        };
        if let Some(error) = epoch_error {
            Err(error)
        } else {
            result
        }
    }
}

impl Drop for ActiveCompositionSession {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.revoke_if_current_nonblocking();
            self.finished = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_api::{HardwareIdentityConfidence, HardwareIdentityEvidenceLevel};

    fn hardware() -> Arc<Mutex<HardwareInfo>> {
        Arc::new(Mutex::new(HardwareInfo::default()))
    }

    fn expected() -> Vec<ExpectedMiningChain> {
        vec![
            ExpectedMiningChain {
                chain_id: 6,
                chip_count: 63,
            },
            ExpectedMiningChain {
                chain_id: 7,
                chip_count: 63,
            },
        ]
    }

    fn exact(chip_id: u16) -> Vec<EnumeratedMiningChainReceipt> {
        vec![test_receipt(6, 63, chip_id), test_receipt(7, 63, chip_id)]
    }

    fn test_receipt(chain_id: u8, chip_count: u8, chip_id: u16) -> EnumeratedMiningChainReceipt {
        EnumeratedMiningChainReceipt {
            chain_id,
            chip_count,
            chip_id,
        }
    }

    #[test]
    fn exact_consensus_publishes_generation_bound_measured_identity() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let port = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap();
        let _session = port.publish(0x1387).unwrap();

        let hardware = hardware.lock().unwrap();
        assert_eq!(hardware.chip_type, "BM1387");
        assert_eq!(
            hardware.identification.confidence,
            HardwareIdentityConfidence::High
        );
        assert_eq!(
            hardware.identification.strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Measured)
        );
        let token = hardware.identification.evidence[0]
            .composition
            .as_ref()
            .unwrap();
        assert_eq!(token.generation, 1);
        assert_eq!(token.fingerprint, "chains:6:63,7:63");
    }

    #[test]
    fn assumed_chain_fields_without_get_address_receipts_never_publish_measured_identity() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let port = authority
            .activate(expected(), Vec::new(), Arc::clone(&hardware))
            .unwrap();

        assert!(matches!(
            port.publish(0x1387),
            Err(AsicIdentityPublicationError::Partial {
                expected: 2,
                observed: 0,
            })
        ));
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            None
        );
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn partial_and_mixed_enumeration_never_publish_measured_identity() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let partial = authority
            .activate(expected(), vec![exact(0x1387)[0]], Arc::clone(&hardware))
            .unwrap();
        assert!(matches!(
            partial.publish(0x1387),
            Err(AsicIdentityPublicationError::Partial {
                expected: 2,
                observed: 1
            })
        ));
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            None
        );
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");

        let mut observations = exact(0x1387);
        observations[1].chip_id = 0x1397;
        let mixed = authority
            .activate(expected(), observations, Arc::clone(&hardware))
            .unwrap();
        assert!(matches!(
            mixed.publish(0x1387),
            Err(AsicIdentityPublicationError::Mixed { .. })
        ));
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            None
        );
    }

    #[test]
    fn later_composition_revokes_and_rejects_stale_generation() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let stale = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap();
        let current = authority
            .activate(
                vec![ExpectedMiningChain {
                    chain_id: 8,
                    chip_count: 63,
                }],
                vec![test_receipt(8, 63, 0x1387)],
                Arc::clone(&hardware),
            )
            .unwrap();

        assert!(matches!(
            stale.publish(0x1387),
            Err(AsicIdentityPublicationError::StaleGeneration)
        ));
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            None
        );
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");

        let _current_session = current.publish(0x1387).unwrap();
        let generation = hardware.lock().unwrap().identification.evidence[0]
            .composition
            .as_ref()
            .unwrap()
            .generation;
        assert_eq!(generation, 2);
    }

    #[test]
    fn invalid_compositions_revoke_measured_and_restore_declared_identity() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        {
            let mut snapshot = hardware.lock().unwrap();
            snapshot
                .identification
                .push_evidence(HardwareIdentityEvidence::declared_asic_config(
                    "s19jpro", "BM1362",
                ));
            snapshot.chip_type = "BM1362".to_string();
        }
        let _session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Measured)
        );

        assert!(matches!(
            authority.activate(Vec::new(), Vec::new(), Arc::clone(&hardware)),
            Err(AsicIdentityPublicationError::ZeroChains)
        ));
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Declared)
        );
        assert_eq!(hardware.lock().unwrap().chip_type, "BM1362");
        assert!(matches!(
            authority.activate(
                vec![ExpectedMiningChain {
                    chain_id: 6,
                    chip_count: 0
                }],
                Vec::new(),
                Arc::clone(&hardware)
            ),
            Err(AsicIdentityPublicationError::ZeroChipCount(6))
        ));
        let port = authority
            .activate(expected(), exact(0xFFFF), Arc::clone(&hardware))
            .unwrap();
        assert!(matches!(
            port.publish(0xFFFF),
            Err(AsicIdentityPublicationError::UnsupportedChip(0xFFFF))
        ));
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Declared)
        );
    }

    #[test]
    fn active_session_drop_revokes_measured_and_restores_declared_identity() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        {
            let mut snapshot = hardware.lock().unwrap();
            snapshot
                .identification
                .push_evidence(HardwareIdentityEvidence::declared_asic_config(
                    "s9", "BM1387",
                ));
            snapshot.chip_type = "BM1387".to_string();
        }

        let session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Measured)
        );

        drop(session);
        let snapshot = hardware.lock().unwrap();
        assert_eq!(
            snapshot.identification.strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Declared)
        );
        assert_eq!(snapshot.chip_type, "BM1387");
    }

    #[test]
    fn stale_session_drop_cannot_revoke_a_newer_generation() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let stale_session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();
        let current_session = authority
            .activate(
                vec![ExpectedMiningChain {
                    chain_id: 8,
                    chip_count: 63,
                }],
                vec![test_receipt(8, 63, 0x1387)],
                Arc::clone(&hardware),
            )
            .unwrap()
            .publish(0x1387)
            .unwrap();

        drop(stale_session);
        let generation = hardware.lock().unwrap().identification.evidence[0]
            .composition
            .as_ref()
            .unwrap()
            .generation;
        assert_eq!(generation, 2);
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Measured)
        );
        drop(current_session);
    }

    #[test]
    fn authority_invalidation_revokes_now_and_later_session_drop_is_a_noop() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();

        authority.invalidate_active().unwrap();
        assert_eq!(
            hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            None
        );
        drop(session);
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn replacement_clears_the_previous_publication_target() {
        let first_hardware = hardware();
        let second_hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let stale_session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&first_hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();

        let _replacement = authority
            .activate(expected(), exact(0x1387), Arc::clone(&second_hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();
        assert_eq!(
            first_hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            None
        );
        assert_eq!(
            second_hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Measured)
        );
        drop(stale_session);
        assert_eq!(
            second_hardware
                .lock()
                .unwrap()
                .identification
                .strongest_asic_evidence_level(),
            Some(HardwareIdentityEvidenceLevel::Measured)
        );
    }

    #[test]
    fn session_drop_never_panics_when_authority_state_is_poisoned() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();
        let commit_port = session.execution_commit_port.clone();
        let state = Arc::clone(&session.authority);
        let _ = std::thread::spawn(move || {
            let _guard = state.lock().unwrap();
            panic!("intentional authority poison");
        })
        .join();

        assert!(std::panic::catch_unwind(|| drop(session)).is_ok());
        let executed = std::sync::atomic::AtomicBool::new(false);
        assert!(commit_port
            .commit("post-poison work send", || -> Result<(), &'static str> {
                executed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .is_err());
        assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn measured_execution_bundle_consumes_one_exact_driver_admission() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let driver_admission = ChipRegistry::production()
            .admit(0x1387)
            .expect("BM1387 production driver admission");

        let execution = authority
            .activate_execution(
                driver_admission,
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        assert_eq!(execution.chip_id(), 0x1387);

        let (driver_admission, _session, _commit_port) = execution.into_parts();
        let runtime_registry = ChipRegistry::from_admission(driver_admission);
        assert!(runtime_registry.detect(0x1387).is_some());
        assert!(runtime_registry.detect(0x1362).is_none());
        assert_eq!(hardware.lock().unwrap().chip_type, "BM1387");
    }

    #[test]
    fn identity_invalidation_fences_the_same_measured_execution_generation() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        commit_port
            .commit(
                "pre-revocation work send",
                || -> Result<(), &'static str> { Ok(()) },
            )
            .unwrap();

        authority.invalidate_active().unwrap();
        let executed = std::sync::atomic::AtomicBool::new(false);
        let error = commit_port
            .commit(
                "post-revocation work send",
                || -> Result<(), &'static str> {
                    executed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap_err();

        assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(error
            .to_string()
            .contains("is closed; refusing post-revocation work send"));
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn poisoned_authority_still_recovers_to_fence_terminal_execution() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        let authority_state = Arc::clone(&authority.state);
        let _ = std::thread::spawn(move || {
            let _guard = authority_state.lock().unwrap();
            panic!("intentional authority poison before terminal invalidation");
        })
        .join();

        authority.invalidate_active().unwrap();
        assert!(commit_port
            .commit("post-poison late work", || -> Result<(), &'static str> {
                Ok(())
            })
            .is_err());
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn panicked_execution_commit_is_not_clean_composition_revocation_evidence() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = commit_port.commit(
                "panicking measured-runtime commit",
                || -> Result<(), &'static str> { panic!("fixture measured runtime commit panic") },
            );
        }));
        assert!(panic.is_err());

        assert_eq!(
            authority.invalidate_active().unwrap_err(),
            AsicIdentityPublicationError::ExecutionFencePoisoned {
                generation: 1,
                fingerprint: "chains:6:63,7:63".to_string(),
            }
        );
        assert!(commit_port
            .commit(
                "late measured-runtime commit",
                || -> Result<(), &'static str> { Ok(()) },
            )
            .is_err());
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
        assert!(authority
            .activate(expected(), exact(0x1387), hardware)
            .is_err());
    }

    #[test]
    fn partial_measured_execution_never_mints_a_dispatcher_bundle() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let driver_admission = ChipRegistry::production().admit(0x1387).unwrap();

        assert_eq!(
            authority
                .activate_execution(
                    driver_admission,
                    expected(),
                    vec![test_receipt(6, 63, 0x1387)],
                    hardware,
                )
                .unwrap_err(),
            AsicIdentityPublicationError::Partial {
                expected: 2,
                observed: 1,
            }
        );
        assert!(
            matches!(
                &authority.state.lock().unwrap().phase,
                CompositionPhase::Idle
            ),
            "failed measured execution must not leave an unpublished active generation"
        );
    }

    #[test]
    fn later_generation_revokes_an_execution_bundle_without_clearing_replacement() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let driver_admission = ChipRegistry::production().admit(0x1387).unwrap();
        let execution = authority
            .activate_execution(
                driver_admission,
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();

        let replacement = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap();
        let replacement_session = replacement.publish(0x1387).unwrap();
        let (_driver_admission, stale_session, _commit_port) = execution.into_parts();
        stale_session.revoke().unwrap();
        assert_eq!(hardware.lock().unwrap().chip_type, "BM1387");
        replacement_session.revoke().unwrap();
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_commit_denies_replacement_until_bounded_revocation_retry_succeeds() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        let late_port = commit_port.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            commit_port
                .commit(
                    "held measured-runtime commit",
                    || -> Result<(), &'static str> {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert!(matches!(
            authority.invalidate_active().unwrap(),
            CompositionInvalidationStatus::Pending { .. }
        ));
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
        assert!(late_port
            .commit(
                "late measured-runtime commit",
                || -> Result<(), &'static str> { Ok(()) }
            )
            .is_err());
        assert_eq!(
            authority
                .activate(expected(), exact(0x1387), Arc::clone(&hardware))
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationPending
        );
        assert_eq!(
            authority
                .invalidate_active_bounded(Duration::from_millis(25))
                .await
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationDeadlineExceeded { timeout_ms: 25 }
        );

        release_tx.send(()).unwrap();
        commit_thread.join().unwrap();
        let receipt = authority
            .invalidate_active_bounded(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(receipt.boundary_epoch() > 0);
        assert!(receipt.completed_at() <= Instant::now());
        assert_eq!(
            receipt.fenced_token().map(|token| token.generation),
            Some(1)
        );
        assert_eq!(
            authority
                .activate(expected(), exact(0x1387), Arc::clone(&hardware))
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationPending,
            "the closed receipt must retain activation authority until consumed or dropped"
        );
        drop(receipt);
        let replacement = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap();
        assert!(replacement.publish(0x1387).is_ok());
    }

    #[tokio::test]
    async fn fast_invalidation_retains_the_exact_token_and_denies_reopening() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let _session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();

        let boundary = authority.begin_invalidation();
        let receipt = boundary
            .complete_bounded(Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(
            receipt.fenced_token().map(|token| token.generation),
            Some(1)
        );
        assert_eq!(
            receipt.boundary_epoch(),
            authority.revocation_epoch.load(Ordering::Acquire),
            "fast completion must retain the boundary opened at shutdown start"
        );
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
        assert_eq!(
            authority
                .activate(expected(), exact(0x1387), Arc::clone(&hardware))
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationPending
        );

        drop(receipt);
        assert!(authority
            .activate(expected(), exact(0x1387), hardware)
            .is_ok());
    }

    #[tokio::test]
    async fn revocation_epoch_exhaustion_still_reclaims_execution_and_identity() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        authority
            .revocation_epoch
            .store(u64::MAX, Ordering::Release);

        assert_eq!(
            authority
                .begin_invalidation()
                .complete_bounded(Duration::from_secs(1))
                .await
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationEpochExhausted
        );
        assert_eq!(authority.active_generation.load(Ordering::Acquire), 0);
        assert!(matches!(
            &authority.state.lock().unwrap().phase,
            CompositionPhase::Idle
        ));
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
        assert!(commit_port
            .commit("post-exhaustion commit", || -> Result<(), &'static str> {
                Ok(())
            })
            .is_err());
        assert_eq!(
            authority
                .activate(expected(), exact(0x1387), hardware)
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationEpochExhausted
        );
    }

    #[test]
    fn cancelled_bounded_invalidation_cannot_be_overwritten_by_activation_publish() {
        let hardware = hardware();
        let authority = Arc::new(DispatcherCompositionAuthority::default());
        authority.activation_publish_pause.enable();
        let activating_authority = Arc::clone(&authority);
        let activating_hardware = Arc::clone(&hardware);
        let activation = std::thread::spawn(move || {
            activating_authority.activate(expected(), exact(0x1387), activating_hardware)
        });
        authority.activation_publish_pause.wait_until_entered();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let invalidation = authority.invalidate_active_bounded(Duration::from_secs(1));
            tokio::pin!(invalidation);
            tokio::select! {
                result = &mut invalidation => panic!("contended invalidation unexpectedly completed: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        });

        authority.activation_publish_pause.release();
        assert_eq!(
            activation.join().unwrap().unwrap_err(),
            AsicIdentityPublicationError::StaleGeneration
        );
        assert_eq!(authority.active_generation.load(Ordering::Acquire), 0);
        assert!(matches!(
            &authority.state.lock().unwrap().phase,
            CompositionPhase::Idle | CompositionPhase::Revoking(_)
        ));
        runtime
            .block_on(authority.invalidate_active_bounded(Duration::from_secs(1)))
            .unwrap();
    }

    #[test]
    fn identity_clear_after_deadline_is_not_attributed_to_early_execution_fence() {
        let hardware = hardware();
        let authority = Arc::new(DispatcherCompositionAuthority::default());
        let _session = authority
            .activate(expected(), exact(0x1387), Arc::clone(&hardware))
            .unwrap()
            .publish(0x1387)
            .unwrap();
        let lock_hardware = Arc::clone(&hardware);
        let release_authority = Arc::clone(&authority);
        let (lock_entered_tx, lock_entered_rx) = std::sync::mpsc::channel();
        let lock_owner = std::thread::spawn(move || {
            let guard = lock_hardware.lock().unwrap();
            lock_entered_tx.send(()).unwrap();
            release_authority.bounded_probe_pause.wait_until_entered();
            std::thread::sleep(Duration::from_millis(40));
            drop(guard);
            release_authority.bounded_probe_pause.release();
        });
        lock_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        assert!(matches!(
            authority.invalidate_active().unwrap(),
            CompositionInvalidationStatus::Pending { .. }
        ));
        authority.bounded_probe_pause.enable();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        assert_eq!(
            runtime
                .block_on(authority.invalidate_active_bounded(Duration::from_millis(25)))
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationDeadlineExceeded { timeout_ms: 25 }
        );
        lock_owner.join().unwrap();
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn active_session_drop_with_held_commit_is_nonblocking() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let (driver, session, commit_port) = execution.into_parts();
        drop(driver);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            commit_port
                .commit(
                    "drop-liveness held commit",
                    || -> Result<(), &'static str> {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (drop_returned_tx, drop_returned_rx) = std::sync::mpsc::channel();
        let drop_thread = std::thread::spawn(move || {
            drop(session);
            drop_returned_tx.send(()).unwrap();
        });
        drop_returned_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("session Drop blocked on the held physical commit");
        drop_thread.join().unwrap();

        release_tx.send(()).unwrap();
        commit_thread.join().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime
            .block_on(authority.invalidate_active_bounded(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(hardware.lock().unwrap().chip_type, "Unknown");
    }

    #[test]
    fn composition_revocation_timeout_allows_runtime_drop_before_commit_release() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                hardware,
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            commit_port
                .commit(
                    "runtime-drop composition commit",
                    || -> Result<(), &'static str> {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (runtime_dropped_tx, runtime_dropped_rx) = std::sync::mpsc::channel();
        let safety_releaser = std::thread::spawn(move || {
            let after_runtime_drop = runtime_dropped_rx
                .recv_timeout(Duration::from_secs(5))
                .is_ok();
            release_tx.send(()).unwrap();
            after_runtime_drop
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let result =
            runtime.block_on(authority.invalidate_active_bounded(Duration::from_millis(25)));
        assert!(matches!(
            result,
            Err(AsicIdentityPublicationError::RevocationDeadlineExceeded { timeout_ms: 25 })
        ));
        drop(runtime);
        let _ = runtime_dropped_tx.send(());

        assert!(
            safety_releaser.join().unwrap(),
            "composition revocation retained runtime shutdown until the held commit was released"
        );
        commit_thread.join().unwrap();
    }

    #[test]
    fn composition_authority_source_has_no_production_blocking_fence_or_drop_wait() {
        let source = include_str!("asic_identity_publication.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        assert!(!production.contains("close_and_wait_for_commit_fence"));
        assert!(!production.contains(".lock()"));
        let drop_body = production
            .split_once("impl Drop for ActiveCompositionSession")
            .unwrap()
            .1;
        assert!(drop_body.contains("revoke_if_current_nonblocking()"));
        assert!(!drop_body.contains(".lock()"));
        assert!(!drop_body.contains("wait_for_commit_fence"));
        assert!(!drop_body.contains("spawn_blocking"));
    }

    #[test]
    fn contended_authority_mutex_respects_deadline_and_runtime_drop() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let _session = authority
            .activate(expected(), exact(0x1387), hardware)
            .unwrap()
            .publish(0x1387)
            .unwrap();
        let state = Arc::clone(&authority.state);
        let (lock_entered_tx, lock_entered_rx) = std::sync::mpsc::channel();
        let (release_lock_tx, release_lock_rx) = std::sync::mpsc::channel();
        let lock_owner = std::thread::spawn(move || {
            let _guard = state.lock().unwrap();
            lock_entered_tx.send(()).unwrap();
            release_lock_rx.recv().unwrap();
        });
        lock_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        assert_eq!(
            authority.invalidate_active().unwrap_err(),
            AsicIdentityPublicationError::AuthorityBusy
        );
        let (runtime_dropped_tx, runtime_dropped_rx) = std::sync::mpsc::channel();
        let safety_releaser = std::thread::spawn(move || {
            let after_runtime_drop = runtime_dropped_rx
                .recv_timeout(Duration::from_secs(5))
                .is_ok();
            release_lock_tx.send(()).unwrap();
            after_runtime_drop
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let result =
            runtime.block_on(authority.invalidate_active_bounded(Duration::from_millis(25)));
        assert_eq!(
            result.unwrap_err(),
            AsicIdentityPublicationError::RevocationDeadlineExceeded { timeout_ms: 25 }
        );
        drop(runtime);
        let _ = runtime_dropped_tx.send(());

        assert!(
            safety_releaser.join().unwrap(),
            "authority mutex contention retained Tokio runtime destruction"
        );
        lock_owner.join().unwrap();
    }

    #[test]
    fn cancelled_bounded_revocation_while_authority_busy_closes_commit_generation() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                hardware,
            )
            .unwrap();
        let commit_port = execution.runtime_execution_commit_port();
        let state = Arc::clone(&authority.state);
        let (lock_entered_tx, lock_entered_rx) = std::sync::mpsc::channel();
        let (release_lock_tx, release_lock_rx) = std::sync::mpsc::channel();
        let lock_owner = std::thread::spawn(move || {
            let _guard = state.lock().unwrap();
            lock_entered_tx.send(()).unwrap();
            release_lock_rx.recv().unwrap();
        });
        lock_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let invalidation = authority.invalidate_active_bounded(Duration::from_secs(1));
            tokio::pin!(invalidation);
            tokio::select! {
                result = &mut invalidation => panic!("contended invalidation unexpectedly completed: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
            // Cancellation occurs here while AuthorityState is still locked by
            // another thread. The generation latch must remain terminal.
        });

        let executed = std::sync::atomic::AtomicBool::new(false);
        assert!(commit_port
            .commit(
                "post-cancellation work send",
                || -> Result<(), &'static str> {
                    executed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .is_err());
        assert!(!executed.load(Ordering::SeqCst));

        release_lock_tx.send(()).unwrap();
        lock_owner.join().unwrap();
        runtime
            .block_on(authority.invalidate_active_bounded(Duration::from_secs(1)))
            .unwrap();
    }

    #[test]
    fn cancelled_bounded_revocation_after_pending_retains_exclusive_retry_state() {
        let hardware = hardware();
        let authority = DispatcherCompositionAuthority::default();
        let execution = authority
            .activate_execution(
                ChipRegistry::production().admit(0x1387).unwrap(),
                expected(),
                exact(0x1387),
                Arc::clone(&hardware),
            )
            .unwrap();
        let held_port = execution.runtime_execution_commit_port();
        let late_port = held_port.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit_thread = std::thread::spawn(move || {
            held_port
                .commit(
                    "cancellation fixture held commit",
                    || -> Result<(), &'static str> {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let invalidation = authority.invalidate_active_bounded(Duration::from_secs(1));
            tokio::pin!(invalidation);
            tokio::select! {
                result = &mut invalidation => panic!("held commit unexpectedly fenced: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        });

        assert!(matches!(
            &authority.state.lock().unwrap().phase,
            CompositionPhase::Revoking(_)
        ));
        assert!(late_port
            .commit(
                "late commit after cancelled invalidation",
                || -> Result<(), &'static str> { Ok(()) },
            )
            .is_err());
        assert_eq!(
            authority
                .activate(expected(), exact(0x1387), Arc::clone(&hardware))
                .unwrap_err(),
            AsicIdentityPublicationError::RevocationPending
        );

        release_tx.send(()).unwrap();
        commit_thread.join().unwrap();
        runtime
            .block_on(authority.invalidate_active_bounded(Duration::from_secs(1)))
            .unwrap();
        assert!(authority
            .activate(expected(), exact(0x1387), hardware)
            .is_ok());
    }
}
