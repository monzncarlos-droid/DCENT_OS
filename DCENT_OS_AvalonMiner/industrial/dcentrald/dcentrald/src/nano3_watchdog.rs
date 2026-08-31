// SPDX-License-Identifier: GPL-3.0-or-later
//
// Desk-only Nano 3 K230 reset-watchdog custody model.
//
// This module deliberately performs no I/O. It models the evidence and order a
// future runtime backend must prove before it may describe `/dev/watchdog` as
// held by dcentrald. K230 reset custody is availability evidence only; it is
// never evidence that hash power or whole-device power was independently cut.

use std::fmt;

pub const NANO3_WATCHDOG_DEVICE: &str = "/dev/watchdog";

/// Desk review cannot promote modeled evidence into live hardware authority.
pub const NANO3_WATCHDOG_LIVE_EFFECTIVENESS_PROVEN: bool = false;
pub const NANO3_WATCHDOG_HARDWARE_PROVENANCE_PROVEN: bool = false;
pub const NANO3_WATCHDOG_PRODUCTION_AUTHORIZED: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogIdentitySource {
    FstatSysfsAndIoctlReadback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnexpectedCloseOutcome {
    ResetRemainsArmed,
    WatchdogDisarmed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogPolicy<'a> {
    pub device: &'a str,
    pub driver_identity: &'a str,
    pub watchdog_info_identity: &'a str,
    pub required_watchdog_options: u32,
    pub expected_nowayout: bool,
    pub expected_unexpected_close_outcome: UnexpectedCloseOutcome,
    pub identity_source: WatchdogIdentitySource,
    pub boot_id_sha256: [u8; 32],
    pub lease_epoch: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub requested_timeout_seconds: u32,
    pub maximum_effective_timeout_seconds: u32,
    pub qualified_keepalive_cadence_ms: u64,
    pub maximum_keepalive_jitter_ms: u64,
    pub timeout_safety_margin_ms: u64,
    pub maximum_observation_age_ms: u64,
}

impl WatchdogPolicy<'_> {
    fn validate(self) -> Result<(), CustodyError> {
        policy_require(self.device == NANO3_WATCHDOG_DEVICE, "exact watchdog path")?;
        policy_require(!self.driver_identity.is_empty(), "pinned driver identity")?;
        policy_require(
            !self.watchdog_info_identity.is_empty(),
            "pinned WDIOC_GETSUPPORT identity",
        )?;
        policy_require(
            self.required_watchdog_options != 0,
            "non-zero pinned watchdog options",
        )?;
        policy_require(self.expected_nowayout, "qualified nowayout is required")?;
        policy_require(
            self.expected_unexpected_close_outcome == UnexpectedCloseOutcome::ResetRemainsArmed,
            "unexpected close must leave reset armed",
        )?;
        policy_require(self.boot_id_sha256 != [0; 32], "non-zero boot identity")?;
        policy_require(self.lease_epoch > 0, "non-zero lease epoch")?;
        policy_require(
            self.requested_timeout_seconds > 0,
            "non-zero requested timeout",
        )?;
        policy_require(
            self.maximum_effective_timeout_seconds >= self.requested_timeout_seconds,
            "effective-timeout policy includes the request",
        )?;
        policy_require(
            self.qualified_keepalive_cadence_ms > 0,
            "non-zero qualified keepalive cadence",
        )?;
        policy_require(
            self.maximum_keepalive_jitter_ms > 0,
            "non-zero maximum keepalive jitter",
        )?;
        policy_require(
            self.timeout_safety_margin_ms > 0,
            "non-zero timeout safety margin",
        )?;
        policy_require(
            self.maximum_observation_age_ms > 0,
            "non-zero observation age bound",
        )?;
        policy_require(
            self.maximum_observation_age_ms <= self.maximum_keepalive_jitter_ms,
            "observation age is within qualified jitter",
        )?;
        let required_ms = self
            .lease_window_ms()
            .and_then(|window| window.checked_add(self.timeout_safety_margin_ms))
            .ok_or(CustodyError::InvalidPolicy("watchdog timing overflow"))?;
        let maximum_timeout_ms = u64::from(self.maximum_effective_timeout_seconds)
            .checked_mul(1_000)
            .ok_or(CustodyError::InvalidPolicy("watchdog timeout overflow"))?;
        policy_require(
            required_ms < maximum_timeout_ms,
            "cadence, jitter, and safety margin fit strictly inside timeout",
        )?;
        Ok(())
    }

    fn lease_window_ms(self) -> Option<u64> {
        self.qualified_keepalive_cadence_ms
            .checked_add(self.maximum_keepalive_jitter_ms)
    }

    fn timing_fits_effective_timeout(self, effective_timeout_seconds: u32) -> bool {
        self.lease_window_ms()
            .and_then(|window| window.checked_add(self.timeout_safety_margin_ms))
            .zip(u64::from(effective_timeout_seconds).checked_mul(1_000))
            .is_some_and(|(required_ms, effective_ms)| required_ms < effective_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogCustodyState {
    AwaitingIndependentBridge,
    AwaitingStockQuiescence,
    AwaitingReplacementCustody,
    AwaitingStockRelease,
    AwaitingExclusiveOpen,
    AwaitingTimeoutReadback,
    AwaitingFirstLease,
    Held,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogFault {
    DeviceBusy,
    LeaseExpired,
    RuntimeBackendLost,
    IdentityChanged,
    TimeoutReadbackChanged,
    EvidenceRejected,
    ObservationInvalid,
    EventOutOfOrder,
    LeaseFenceInvalid,
    KeepaliveRejected,
    Other(&'static str),
}

/// Required ordering after any terminal custody fault. These are modeled
/// obligations only; this desk module has no actuator or process-control I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogFailSafeAction {
    RejectFurtherKeepalives,
    RequestIndependentHashCut,
    LeaveNativeWatchdogUnpetted,
    TreatNativeWatchdogOutcomeAsUnknown,
    RequireFreshMachineBootAndLease,
}

pub const NANO3_WATCHDOG_FAIL_SAFE_ACTIONS: [WatchdogFailSafeAction; 4] = [
    WatchdogFailSafeAction::RejectFurtherKeepalives,
    WatchdogFailSafeAction::RequestIndependentHashCut,
    WatchdogFailSafeAction::LeaveNativeWatchdogUnpetted,
    WatchdogFailSafeAction::RequireFreshMachineBootAndLease,
];

pub const NANO3_WATCHDOG_UNQUALIFIED_CLOSE_FAIL_SAFE_ACTIONS: [WatchdogFailSafeAction; 4] = [
    WatchdogFailSafeAction::RejectFurtherKeepalives,
    WatchdogFailSafeAction::RequestIndependentHashCut,
    WatchdogFailSafeAction::TreatNativeWatchdogOutcomeAsUnknown,
    WatchdogFailSafeAction::RequireFreshMachineBootAndLease,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogEvent<'a> {
    IndependentBridgeReady {
        custody_iteration: u64,
        observed_at_ms: u64,
        independent_cut_armed: bool,
        independent_heartbeat_fresh: bool,
    },
    StockQuiesced {
        custody_iteration: u64,
        observed_at_ms: u64,
        hash_off_independently_observed: bool,
        stock_quiesced: bool,
        automatic_restart_inhibited: bool,
    },
    ReplacementCustodyHeld {
        custody_iteration: u64,
        observed_at_ms: u64,
        replacement_cooling_held: bool,
        replacement_sensors_held: bool,
    },
    StockWatchdogReleased {
        custody_iteration: u64,
        observed_at_ms: u64,
        stock_watchdog_fd_released: bool,
    },
    ExclusiveDeviceOpened {
        custody_iteration: u64,
        observed_at_ms: u64,
        device: &'a str,
        is_character_device: bool,
        exclusive_open: bool,
        driver_identity: &'a str,
        device_major: u32,
        device_minor: u32,
        identity_source: WatchdogIdentitySource,
        boot_id_sha256: [u8; 32],
        stock_watchdog_openers: u32,
        dcentral_watchdog_openers: u32,
    },
    OpenRejectedBusy {
        custody_iteration: u64,
        observed_at_ms: u64,
    },
    TimeoutReadBack {
        custody_iteration: u64,
        observed_at_ms: u64,
        set_timeout_acknowledged: bool,
        requested_timeout_seconds: u32,
        set_timeout_returned_seconds: u32,
        get_timeout_acknowledged: bool,
        get_timeout_readback_seconds: u32,
        support_identity_read: bool,
        support_identity: &'a str,
        support_options: u32,
        nowayout_observed: bool,
        unexpected_close_outcome: UnexpectedCloseOutcome,
        unexpected_close_live_qualified: bool,
    },
    LeaseRenewed {
        custody_iteration: u64,
        observed_at_ms: u64,
        sequence: u64,
        fencing_token: u128,
        lease_epoch: u64,
        boot_id_sha256: [u8; 32],
        device: &'a str,
        driver_identity: &'a str,
        support_identity: &'a str,
        support_options: u32,
        device_major: u32,
        device_minor: u32,
        identity_source: WatchdogIdentitySource,
        stock_watchdog_openers: u32,
        dcentral_watchdog_openers: u32,
        effective_timeout_seconds: u32,
        nowayout_observed: bool,
        unexpected_close_outcome: UnexpectedCloseOutcome,
        unexpected_close_live_qualified: bool,
        independent_heartbeat_fresh: bool,
        independent_cut_armed: bool,
        replacement_cooling_fresh: bool,
        replacement_sensors_fresh: bool,
        controller_healthy: bool,
        complete_custody_iteration: bool,
        keepalive_acknowledged: bool,
    },
}

impl WatchdogEvent<'_> {
    const fn name(self) -> &'static str {
        match self {
            Self::IndependentBridgeReady { .. } => "independent-bridge-ready",
            Self::StockQuiesced { .. } => "stock-quiesced",
            Self::ReplacementCustodyHeld { .. } => "replacement-custody-held",
            Self::StockWatchdogReleased { .. } => "stock-watchdog-released",
            Self::ExclusiveDeviceOpened { .. } => "exclusive-device-opened",
            Self::OpenRejectedBusy { .. } => "open-rejected-busy",
            Self::TimeoutReadBack { .. } => "timeout-read-back",
            Self::LeaseRenewed { .. } => "lease-renewed",
        }
    }

    const fn iteration(self) -> u64 {
        match self {
            Self::IndependentBridgeReady {
                custody_iteration, ..
            }
            | Self::StockQuiesced {
                custody_iteration, ..
            }
            | Self::ReplacementCustodyHeld {
                custody_iteration, ..
            }
            | Self::StockWatchdogReleased {
                custody_iteration, ..
            }
            | Self::ExclusiveDeviceOpened {
                custody_iteration, ..
            }
            | Self::OpenRejectedBusy {
                custody_iteration, ..
            }
            | Self::TimeoutReadBack {
                custody_iteration, ..
            }
            | Self::LeaseRenewed {
                custody_iteration, ..
            } => custody_iteration,
        }
    }

    const fn observed_at_ms(self) -> u64 {
        match self {
            Self::IndependentBridgeReady { observed_at_ms, .. }
            | Self::StockQuiesced { observed_at_ms, .. }
            | Self::ReplacementCustodyHeld { observed_at_ms, .. }
            | Self::StockWatchdogReleased { observed_at_ms, .. }
            | Self::ExclusiveDeviceOpened { observed_at_ms, .. }
            | Self::OpenRejectedBusy { observed_at_ms, .. }
            | Self::TimeoutReadBack { observed_at_ms, .. }
            | Self::LeaseRenewed { observed_at_ms, .. } => observed_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    InvalidPolicy(&'static str),
    OutOfOrder {
        state: WatchdogCustodyState,
        event: &'static str,
    },
    MissingEvidence(&'static str),
    ObservationInFuture,
    ObservationStale,
    ObservationNotMonotonic,
    IterationMismatch,
    DeviceIdentityMismatch,
    TimeoutMismatch,
    LeaseExpired,
    LeaseSequenceMismatch,
    FencingTokenMismatch,
    TerminalFault,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(item) => write!(f, "invalid watchdog policy: {item}"),
            Self::OutOfOrder { state, event } => {
                write!(f, "event {event} is not admitted from {state:?}")
            }
            Self::MissingEvidence(item) => write!(f, "missing evidence: {item}"),
            Self::ObservationInFuture => write!(f, "watchdog observation is in the future"),
            Self::ObservationStale => write!(f, "watchdog observation is stale"),
            Self::ObservationNotMonotonic => {
                write!(f, "watchdog observation time did not advance")
            }
            Self::IterationMismatch => write!(f, "watchdog custody iteration mismatch"),
            Self::DeviceIdentityMismatch => write!(f, "watchdog device identity mismatch"),
            Self::TimeoutMismatch => write!(f, "watchdog effective timeout mismatch"),
            Self::LeaseExpired => write!(f, "watchdog lease expired before renewal"),
            Self::LeaseSequenceMismatch => write!(f, "watchdog lease sequence mismatch"),
            Self::FencingTokenMismatch => write!(f, "watchdog lease fencing token mismatch"),
            Self::TerminalFault => write!(f, "watchdog custody fault is terminal"),
        }
    }
}

impl std::error::Error for CustodyError {}

impl CustodyError {
    fn terminal_fault(&self) -> WatchdogFault {
        match self {
            Self::OutOfOrder { .. } => WatchdogFault::EventOutOfOrder,
            Self::MissingEvidence("watchdog keepalive is acknowledged") => {
                WatchdogFault::KeepaliveRejected
            }
            Self::MissingEvidence(_) => WatchdogFault::EvidenceRejected,
            Self::ObservationInFuture
            | Self::ObservationStale
            | Self::ObservationNotMonotonic
            | Self::IterationMismatch => WatchdogFault::ObservationInvalid,
            Self::DeviceIdentityMismatch => WatchdogFault::IdentityChanged,
            Self::TimeoutMismatch => WatchdogFault::TimeoutReadbackChanged,
            Self::LeaseExpired => WatchdogFault::LeaseExpired,
            Self::LeaseSequenceMismatch | Self::FencingTokenMismatch => {
                WatchdogFault::LeaseFenceInvalid
            }
            Self::InvalidPolicy(_) | Self::TerminalFault => WatchdogFault::Other("internal"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Nano3WatchdogCustody<'a> {
    policy: WatchdogPolicy<'a>,
    state: WatchdogCustodyState,
    custody_iteration: Option<u64>,
    last_observed_at_ms: Option<u64>,
    lease_sequence: u64,
    fencing_token: Option<u128>,
    lease_observed_at_ms: Option<u64>,
    effective_timeout_seconds: Option<u32>,
    nowayout_observed: Option<bool>,
    unexpected_close_live_qualified: bool,
    fault: Option<WatchdogFault>,
}

impl<'a> Nano3WatchdogCustody<'a> {
    pub fn new(policy: WatchdogPolicy<'a>) -> Result<Self, CustodyError> {
        policy.validate()?;
        Ok(Self {
            policy,
            state: WatchdogCustodyState::AwaitingIndependentBridge,
            custody_iteration: None,
            last_observed_at_ms: None,
            lease_sequence: 0,
            fencing_token: None,
            lease_observed_at_ms: None,
            effective_timeout_seconds: None,
            nowayout_observed: None,
            unexpected_close_live_qualified: false,
            fault: None,
        })
    }

    pub const fn state(&self) -> WatchdogCustodyState {
        self.state
    }

    pub const fn fault(&self) -> Option<WatchdogFault> {
        self.fault
    }

    pub const fn required_fail_safe_actions(&self) -> Option<&'static [WatchdogFailSafeAction; 4]> {
        if matches!(self.state, WatchdogCustodyState::Faulted) {
            if self.unexpected_close_live_qualified {
                Some(&NANO3_WATCHDOG_FAIL_SAFE_ACTIONS)
            } else {
                Some(&NANO3_WATCHDOG_UNQUALIFIED_CLOSE_FAIL_SAFE_ACTIONS)
            }
        } else {
            None
        }
    }

    /// A terminal fault has no acknowledgement or in-place recovery edge.
    /// A future backend must create a new machine with newly authenticated
    /// boot identity, lease epoch, fencing token, and complete handoff.
    pub const fn requires_fresh_machine_for_recovery(&self) -> bool {
        matches!(self.state, WatchdogCustodyState::Faulted)
    }

    /// True only for a fresh modeled K230-reset lease. This never proves an
    /// independent hash-power or whole-device cut.
    pub fn k230_reset_lease_held(&self, now_ms: u64) -> bool {
        self.state == WatchdogCustodyState::Held
            && self
                .lease_observed_at_ms
                .zip(self.policy.lease_window_ms())
                .is_some_and(|(observed, window)| {
                    now_ms
                        .checked_sub(observed)
                        .is_some_and(|age| age <= window)
                })
    }

    pub fn latch_fault(&mut self, fault: WatchdogFault) -> Result<(), CustodyError> {
        if self.state == WatchdogCustodyState::Faulted {
            return Err(CustodyError::TerminalFault);
        }
        self.fault = Some(fault);
        self.state = WatchdogCustodyState::Faulted;
        Ok(())
    }

    pub fn expire_if_stale(&mut self, now_ms: u64) -> bool {
        if self.state == WatchdogCustodyState::Held && !self.k230_reset_lease_held(now_ms) {
            self.fault = Some(WatchdogFault::LeaseExpired);
            self.state = WatchdogCustodyState::Faulted;
            return true;
        }
        false
    }

    pub fn apply(
        &mut self,
        now_ms: u64,
        event: WatchdogEvent<'_>,
    ) -> Result<WatchdogCustodyState, CustodyError> {
        if self.state == WatchdogCustodyState::Faulted {
            return Err(CustodyError::TerminalFault);
        }

        let result = self.apply_inner(now_ms, event);
        if let Err(error) = &result {
            let close_semantics_still_match = match event {
                WatchdogEvent::TimeoutReadBack {
                    support_options,
                    nowayout_observed,
                    unexpected_close_outcome,
                    unexpected_close_live_qualified,
                    ..
                }
                | WatchdogEvent::LeaseRenewed {
                    support_options,
                    nowayout_observed,
                    unexpected_close_outcome,
                    unexpected_close_live_qualified,
                    ..
                } => {
                    unexpected_close_live_qualified
                        && support_options == self.policy.required_watchdog_options
                        && nowayout_observed == self.policy.expected_nowayout
                        && unexpected_close_outcome == self.policy.expected_unexpected_close_outcome
                }
                _ => self.unexpected_close_live_qualified,
            };
            self.unexpected_close_live_qualified = close_semantics_still_match;
            self.fault = Some(error.terminal_fault());
            self.state = WatchdogCustodyState::Faulted;
        }
        result
    }

    fn apply_inner(
        &mut self,
        now_ms: u64,
        event: WatchdogEvent<'_>,
    ) -> Result<WatchdogCustodyState, CustodyError> {
        if matches!(
            (self.state, event),
            (
                WatchdogCustodyState::AwaitingFirstLease | WatchdogCustodyState::Held,
                WatchdogEvent::LeaseRenewed { .. }
            )
        ) && self.last_observed_at_ms.is_some_and(|last| {
            self.policy
                .lease_window_ms()
                .is_none_or(|window| now_ms.checked_sub(last).is_none_or(|age| age > window))
        }) {
            return Err(CustodyError::LeaseExpired);
        }
        self.validate_envelope(now_ms, event)?;

        let next = match (self.state, event) {
            (
                WatchdogCustodyState::AwaitingIndependentBridge,
                WatchdogEvent::IndependentBridgeReady {
                    independent_cut_armed,
                    independent_heartbeat_fresh,
                    ..
                },
            ) => {
                require(independent_cut_armed, "independent cut is armed")?;
                require(
                    independent_heartbeat_fresh,
                    "independent heartbeat is fresh",
                )?;
                WatchdogCustodyState::AwaitingStockQuiescence
            }
            (
                WatchdogCustodyState::AwaitingStockQuiescence,
                WatchdogEvent::StockQuiesced {
                    hash_off_independently_observed,
                    stock_quiesced,
                    automatic_restart_inhibited,
                    ..
                },
            ) => {
                require(
                    hash_off_independently_observed,
                    "stock hash-off is independently observed",
                )?;
                require(stock_quiesced, "stock miner is quiesced")?;
                require(
                    automatic_restart_inhibited,
                    "stock automatic restart is inhibited",
                )?;
                WatchdogCustodyState::AwaitingReplacementCustody
            }
            (
                WatchdogCustodyState::AwaitingReplacementCustody,
                WatchdogEvent::ReplacementCustodyHeld {
                    replacement_cooling_held,
                    replacement_sensors_held,
                    ..
                },
            ) => {
                require(replacement_cooling_held, "replacement cooling is held")?;
                require(replacement_sensors_held, "replacement sensors are held")?;
                WatchdogCustodyState::AwaitingStockRelease
            }
            (
                WatchdogCustodyState::AwaitingStockRelease,
                WatchdogEvent::StockWatchdogReleased {
                    stock_watchdog_fd_released,
                    ..
                },
            ) => {
                require(
                    stock_watchdog_fd_released,
                    "stock watchdog file descriptor is released",
                )?;
                WatchdogCustodyState::AwaitingExclusiveOpen
            }
            (
                WatchdogCustodyState::AwaitingExclusiveOpen,
                WatchdogEvent::OpenRejectedBusy { .. },
            ) => {
                self.fault = Some(WatchdogFault::DeviceBusy);
                WatchdogCustodyState::Faulted
            }
            (
                WatchdogCustodyState::AwaitingExclusiveOpen,
                WatchdogEvent::ExclusiveDeviceOpened {
                    device,
                    is_character_device,
                    exclusive_open,
                    driver_identity,
                    device_major,
                    device_minor,
                    identity_source,
                    boot_id_sha256,
                    stock_watchdog_openers,
                    dcentral_watchdog_openers,
                    ..
                },
            ) => {
                require(is_character_device, "watchdog node is a character device")?;
                require(exclusive_open, "watchdog open is exclusive")?;
                require(
                    stock_watchdog_openers == 0,
                    "stock watchdog opener count is zero",
                )?;
                require(
                    dcentral_watchdog_openers == 1,
                    "dcentral watchdog opener count is exactly one",
                )?;
                if device != self.policy.device
                    || driver_identity != self.policy.driver_identity
                    || device_major != self.policy.device_major
                    || device_minor != self.policy.device_minor
                    || identity_source != self.policy.identity_source
                    || boot_id_sha256 != self.policy.boot_id_sha256
                {
                    return Err(CustodyError::DeviceIdentityMismatch);
                }
                WatchdogCustodyState::AwaitingTimeoutReadback
            }
            (
                WatchdogCustodyState::AwaitingTimeoutReadback,
                WatchdogEvent::TimeoutReadBack {
                    set_timeout_acknowledged,
                    requested_timeout_seconds,
                    set_timeout_returned_seconds,
                    get_timeout_acknowledged,
                    get_timeout_readback_seconds,
                    support_identity_read,
                    support_identity,
                    support_options,
                    nowayout_observed,
                    unexpected_close_outcome,
                    unexpected_close_live_qualified,
                    ..
                },
            ) => {
                require(set_timeout_acknowledged, "WDIOC_SETTIMEOUT is acknowledged")?;
                require(get_timeout_acknowledged, "WDIOC_GETTIMEOUT is acknowledged")?;
                require(support_identity_read, "WDIOC_GETSUPPORT identity is read")?;
                require(
                    unexpected_close_live_qualified,
                    "unexpected-close behavior is live qualified",
                )?;
                if support_identity != self.policy.watchdog_info_identity {
                    return Err(CustodyError::DeviceIdentityMismatch);
                }
                if support_options != self.policy.required_watchdog_options
                    || nowayout_observed != self.policy.expected_nowayout
                    || unexpected_close_outcome != self.policy.expected_unexpected_close_outcome
                {
                    return Err(CustodyError::TimeoutMismatch);
                }
                if requested_timeout_seconds != self.policy.requested_timeout_seconds
                    || set_timeout_returned_seconds < requested_timeout_seconds
                    || set_timeout_returned_seconds > self.policy.maximum_effective_timeout_seconds
                    || get_timeout_readback_seconds != set_timeout_returned_seconds
                    || !self
                        .policy
                        .timing_fits_effective_timeout(get_timeout_readback_seconds)
                {
                    return Err(CustodyError::TimeoutMismatch);
                }
                self.effective_timeout_seconds = Some(get_timeout_readback_seconds);
                self.nowayout_observed = Some(nowayout_observed);
                self.unexpected_close_live_qualified = true;
                WatchdogCustodyState::AwaitingFirstLease
            }
            (
                WatchdogCustodyState::AwaitingFirstLease | WatchdogCustodyState::Held,
                WatchdogEvent::LeaseRenewed {
                    sequence,
                    fencing_token,
                    lease_epoch,
                    boot_id_sha256,
                    device,
                    driver_identity,
                    support_identity,
                    support_options,
                    device_major,
                    device_minor,
                    identity_source,
                    stock_watchdog_openers,
                    dcentral_watchdog_openers,
                    effective_timeout_seconds,
                    nowayout_observed,
                    unexpected_close_outcome,
                    unexpected_close_live_qualified,
                    independent_heartbeat_fresh,
                    independent_cut_armed,
                    replacement_cooling_fresh,
                    replacement_sensors_fresh,
                    controller_healthy,
                    complete_custody_iteration,
                    keepalive_acknowledged,
                    observed_at_ms,
                    ..
                },
            ) => {
                require(
                    independent_heartbeat_fresh,
                    "independent heartbeat remains fresh",
                )?;
                require(independent_cut_armed, "independent cut remains armed")?;
                require(
                    replacement_cooling_fresh,
                    "replacement cooling evidence is fresh",
                )?;
                require(
                    replacement_sensors_fresh,
                    "replacement sensor evidence is fresh",
                )?;
                require(controller_healthy, "controller health is fresh")?;
                require(
                    complete_custody_iteration,
                    "lease is coupled to a complete custody iteration",
                )?;
                require(
                    unexpected_close_live_qualified,
                    "unexpected-close behavior remains live qualified",
                )?;
                require(
                    stock_watchdog_openers == 0,
                    "stock watchdog opener count remains zero",
                )?;
                require(
                    dcentral_watchdog_openers == 1,
                    "dcentral watchdog opener count remains exactly one",
                )?;
                if device != self.policy.device
                    || driver_identity != self.policy.driver_identity
                    || support_identity != self.policy.watchdog_info_identity
                    || device_major != self.policy.device_major
                    || device_minor != self.policy.device_minor
                    || identity_source != self.policy.identity_source
                    || boot_id_sha256 != self.policy.boot_id_sha256
                    || lease_epoch != self.policy.lease_epoch
                    || support_options != self.policy.required_watchdog_options
                    || unexpected_close_outcome != self.policy.expected_unexpected_close_outcome
                {
                    return Err(CustodyError::DeviceIdentityMismatch);
                }
                if self.effective_timeout_seconds != Some(effective_timeout_seconds)
                    || self.nowayout_observed != Some(nowayout_observed)
                    || nowayout_observed != self.policy.expected_nowayout
                    || !self
                        .policy
                        .timing_fits_effective_timeout(effective_timeout_seconds)
                {
                    return Err(CustodyError::TimeoutMismatch);
                }
                if self.lease_sequence.checked_add(1) != Some(sequence) {
                    return Err(CustodyError::LeaseSequenceMismatch);
                }
                if fencing_token == 0
                    || self
                        .fencing_token
                        .is_some_and(|expected| expected != fencing_token)
                {
                    return Err(CustodyError::FencingTokenMismatch);
                }
                require(keepalive_acknowledged, "watchdog keepalive is acknowledged")?;
                self.lease_sequence = sequence;
                self.fencing_token = Some(fencing_token);
                self.lease_observed_at_ms = Some(observed_at_ms);
                WatchdogCustodyState::Held
            }
            (state, event) => {
                return Err(CustodyError::OutOfOrder {
                    state,
                    event: event.name(),
                });
            }
        };

        if matches!(event, WatchdogEvent::LeaseRenewed { .. }) {
            self.custody_iteration = Some(event.iteration());
        } else {
            self.custody_iteration.get_or_insert(event.iteration());
        }
        self.last_observed_at_ms = Some(event.observed_at_ms());
        self.state = next;
        Ok(next)
    }

    fn validate_envelope(&self, now_ms: u64, event: WatchdogEvent<'_>) -> Result<(), CustodyError> {
        let observed_at_ms = event.observed_at_ms();
        let age = now_ms
            .checked_sub(observed_at_ms)
            .ok_or(CustodyError::ObservationInFuture)?;
        if age > self.policy.maximum_observation_age_ms {
            return Err(CustodyError::ObservationStale);
        }
        if self
            .last_observed_at_ms
            .is_some_and(|previous| observed_at_ms <= previous)
        {
            return Err(CustodyError::ObservationNotMonotonic);
        }
        let iteration_valid = match (self.state, event, self.custody_iteration) {
            (
                WatchdogCustodyState::AwaitingFirstLease | WatchdogCustodyState::Held,
                WatchdogEvent::LeaseRenewed { .. },
                Some(previous),
            ) => previous.checked_add(1) == Some(event.iteration()),
            (_, _, Some(expected)) => expected == event.iteration(),
            (_, _, None) => true,
        };
        if !iteration_valid {
            return Err(CustodyError::IterationMismatch);
        }
        Ok(())
    }
}

fn require(observed: bool, evidence: &'static str) -> Result<(), CustodyError> {
    if observed {
        Ok(())
    } else {
        Err(CustodyError::MissingEvidence(evidence))
    }
}

fn policy_require(valid: bool, item: &'static str) -> Result<(), CustodyError> {
    if valid {
        Ok(())
    } else {
        Err(CustodyError::InvalidPolicy(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> WatchdogPolicy<'static> {
        WatchdogPolicy {
            device: NANO3_WATCHDOG_DEVICE,
            driver_identity: "k230-wdt",
            watchdog_info_identity: "k230-wdt",
            required_watchdog_options: 0x8180,
            expected_nowayout: true,
            expected_unexpected_close_outcome: UnexpectedCloseOutcome::ResetRemainsArmed,
            identity_source: WatchdogIdentitySource::FstatSysfsAndIoctlReadback,
            boot_id_sha256: [0x42; 32],
            lease_epoch: 3,
            device_major: 10,
            device_minor: 130,
            requested_timeout_seconds: 89,
            maximum_effective_timeout_seconds: 90,
            qualified_keepalive_cadence_ms: 750,
            maximum_keepalive_jitter_ms: 250,
            timeout_safety_margin_ms: 1_000,
            maximum_observation_age_ms: 250,
        }
    }

    fn bridge(at: u64) -> WatchdogEvent<'static> {
        WatchdogEvent::IndependentBridgeReady {
            custody_iteration: 7,
            observed_at_ms: at,
            independent_cut_armed: true,
            independent_heartbeat_fresh: true,
        }
    }

    fn stock_quiesced(at: u64) -> WatchdogEvent<'static> {
        WatchdogEvent::StockQuiesced {
            custody_iteration: 7,
            observed_at_ms: at,
            hash_off_independently_observed: true,
            stock_quiesced: true,
            automatic_restart_inhibited: true,
        }
    }

    fn replacement_custody(at: u64) -> WatchdogEvent<'static> {
        WatchdogEvent::ReplacementCustodyHeld {
            custody_iteration: 7,
            observed_at_ms: at,
            replacement_cooling_held: true,
            replacement_sensors_held: true,
        }
    }

    fn stock_released(at: u64) -> WatchdogEvent<'static> {
        WatchdogEvent::StockWatchdogReleased {
            custody_iteration: 7,
            observed_at_ms: at,
            stock_watchdog_fd_released: true,
        }
    }

    fn opened(at: u64) -> WatchdogEvent<'static> {
        WatchdogEvent::ExclusiveDeviceOpened {
            custody_iteration: 7,
            observed_at_ms: at,
            device: NANO3_WATCHDOG_DEVICE,
            is_character_device: true,
            exclusive_open: true,
            driver_identity: "k230-wdt",
            device_major: 10,
            device_minor: 130,
            identity_source: WatchdogIdentitySource::FstatSysfsAndIoctlReadback,
            boot_id_sha256: [0x42; 32],
            stock_watchdog_openers: 0,
            dcentral_watchdog_openers: 1,
        }
    }

    fn configured(at: u64) -> WatchdogEvent<'static> {
        WatchdogEvent::TimeoutReadBack {
            custody_iteration: 7,
            observed_at_ms: at,
            set_timeout_acknowledged: true,
            requested_timeout_seconds: 89,
            set_timeout_returned_seconds: 89,
            get_timeout_acknowledged: true,
            get_timeout_readback_seconds: 89,
            support_identity_read: true,
            support_identity: "k230-wdt",
            support_options: 0x8180,
            nowayout_observed: true,
            unexpected_close_outcome: UnexpectedCloseOutcome::ResetRemainsArmed,
            unexpected_close_live_qualified: true,
        }
    }

    fn lease(at: u64, sequence: u64, token: u128) -> WatchdogEvent<'static> {
        WatchdogEvent::LeaseRenewed {
            custody_iteration: 7 + sequence,
            observed_at_ms: at,
            sequence,
            fencing_token: token,
            lease_epoch: 3,
            boot_id_sha256: [0x42; 32],
            device: NANO3_WATCHDOG_DEVICE,
            driver_identity: "k230-wdt",
            support_identity: "k230-wdt",
            support_options: 0x8180,
            device_major: 10,
            device_minor: 130,
            identity_source: WatchdogIdentitySource::FstatSysfsAndIoctlReadback,
            stock_watchdog_openers: 0,
            dcentral_watchdog_openers: 1,
            effective_timeout_seconds: 89,
            nowayout_observed: true,
            independent_heartbeat_fresh: true,
            independent_cut_armed: true,
            replacement_cooling_fresh: true,
            replacement_sensors_fresh: true,
            controller_healthy: true,
            complete_custody_iteration: true,
            unexpected_close_outcome: UnexpectedCloseOutcome::ResetRemainsArmed,
            unexpected_close_live_qualified: true,
            keepalive_acknowledged: true,
        }
    }

    fn advance_to_first_lease() -> Nano3WatchdogCustody<'static> {
        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        assert_eq!(
            custody.apply(1_010, bridge(1_000)).unwrap(),
            WatchdogCustodyState::AwaitingStockQuiescence
        );
        custody.apply(1_020, stock_quiesced(1_010)).unwrap();
        custody.apply(1_030, replacement_custody(1_020)).unwrap();
        custody.apply(1_040, stock_released(1_030)).unwrap();
        custody.apply(1_050, opened(1_040)).unwrap();
        custody.apply(1_060, configured(1_050)).unwrap();
        custody
    }

    fn advance_to_replacement_custody() -> Nano3WatchdogCustody<'static> {
        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        custody.apply(1_010, bridge(1_000)).unwrap();
        custody.apply(1_020, stock_quiesced(1_010)).unwrap();
        custody
    }

    fn advance_to_stock_release() -> Nano3WatchdogCustody<'static> {
        let mut custody = advance_to_replacement_custody();
        custody.apply(1_030, replacement_custody(1_020)).unwrap();
        custody
    }

    fn advance_to_exclusive_open() -> Nano3WatchdogCustody<'static> {
        let mut custody = advance_to_stock_release();
        custody.apply(1_040, stock_released(1_030)).unwrap();
        custody
    }

    fn advance_to_timeout_readback() -> Nano3WatchdogCustody<'static> {
        let mut custody = advance_to_exclusive_open();
        custody.apply(1_050, opened(1_040)).unwrap();
        custody
    }

    fn held() -> Nano3WatchdogCustody<'static> {
        let mut custody = advance_to_first_lease();
        custody.apply(1_070, lease(1_060, 1, 44)).unwrap();
        custody
    }

    #[test]
    fn exact_order_reaches_a_fresh_k230_reset_lease() {
        let mut custody = advance_to_first_lease();
        assert_eq!(
            custody.apply(1_070, lease(1_060, 1, 44)).unwrap(),
            WatchdogCustodyState::Held
        );
        assert!(custody.k230_reset_lease_held(2_060));
        assert!(!custody.k230_reset_lease_held(2_061));
    }

    #[test]
    fn every_handoff_fact_is_load_bearing_and_failure_is_terminal() {
        let bridge_mutations: &[fn(&mut WatchdogEvent<'static>)] = &[
            |event| match event {
                WatchdogEvent::IndependentBridgeReady {
                    independent_cut_armed,
                    ..
                } => *independent_cut_armed = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::IndependentBridgeReady {
                    independent_heartbeat_fresh,
                    ..
                } => *independent_heartbeat_fresh = false,
                _ => unreachable!(),
            },
        ];
        for mutate in bridge_mutations {
            let mut event = bridge(1_000);
            mutate(&mut event);
            let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
            assert!(matches!(
                custody.apply(1_010, event),
                Err(CustodyError::MissingEvidence(_))
            ));
            assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        }

        let stock_mutations: &[fn(&mut WatchdogEvent<'static>)] = &[
            |event| match event {
                WatchdogEvent::StockQuiesced {
                    hash_off_independently_observed,
                    ..
                } => *hash_off_independently_observed = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::StockQuiesced { stock_quiesced, .. } => *stock_quiesced = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::StockQuiesced {
                    automatic_restart_inhibited,
                    ..
                } => *automatic_restart_inhibited = false,
                _ => unreachable!(),
            },
        ];
        for mutate in stock_mutations {
            let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
            custody.apply(1_010, bridge(1_000)).unwrap();
            let mut event = stock_quiesced(1_010);
            mutate(&mut event);
            assert!(matches!(
                custody.apply(1_020, event),
                Err(CustodyError::MissingEvidence(_))
            ));
            assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        }

        for mutate in [
            |event: &mut WatchdogEvent<'static>| match event {
                WatchdogEvent::ReplacementCustodyHeld {
                    replacement_cooling_held,
                    ..
                } => *replacement_cooling_held = false,
                _ => unreachable!(),
            },
            |event: &mut WatchdogEvent<'static>| match event {
                WatchdogEvent::ReplacementCustodyHeld {
                    replacement_sensors_held,
                    ..
                } => *replacement_sensors_held = false,
                _ => unreachable!(),
            },
        ] {
            let mut custody = advance_to_replacement_custody();
            let mut event = replacement_custody(1_020);
            mutate(&mut event);
            assert!(matches!(
                custody.apply(1_030, event),
                Err(CustodyError::MissingEvidence(_))
            ));
            assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        }

        let mut custody = advance_to_stock_release();
        let mut event = stock_released(1_030);
        let WatchdogEvent::StockWatchdogReleased {
            stock_watchdog_fd_released,
            ..
        } = &mut event
        else {
            unreachable!()
        };
        *stock_watchdog_fd_released = false;
        assert!(matches!(
            custody.apply(1_040, event),
            Err(CustodyError::MissingEvidence(_))
        ));
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
    }

    #[test]
    fn busy_open_is_a_terminal_fault() {
        let mut custody = advance_to_exclusive_open();
        assert_eq!(
            custody
                .apply(
                    1_050,
                    WatchdogEvent::OpenRejectedBusy {
                        custody_iteration: 7,
                        observed_at_ms: 1_040,
                    },
                )
                .unwrap(),
            WatchdogCustodyState::Faulted
        );
        assert_eq!(custody.fault(), Some(WatchdogFault::DeviceBusy));
        assert_eq!(
            custody.apply(1_060, opened(1_050)),
            Err(CustodyError::TerminalFault)
        );
    }

    #[test]
    fn identity_and_timeout_substitutions_fault_terminally() {
        let mut custody = advance_to_exclusive_open();
        let mut wrong = opened(1_040);
        if let WatchdogEvent::ExclusiveDeviceOpened { device_minor, .. } = &mut wrong {
            *device_minor += 1;
        }
        assert_eq!(
            custody.apply(1_050, wrong),
            Err(CustodyError::DeviceIdentityMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        assert_eq!(custody.fault(), Some(WatchdogFault::IdentityChanged));

        let mut custody = advance_to_timeout_readback();
        let mut wrong = configured(1_050);
        if let WatchdogEvent::TimeoutReadBack {
            set_timeout_returned_seconds,
            ..
        } = &mut wrong
        {
            *set_timeout_returned_seconds = 90;
        }
        assert_eq!(
            custody.apply(1_060, wrong),
            Err(CustodyError::TimeoutMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = advance_to_timeout_readback();
        let mut wrong = configured(1_050);
        if let WatchdogEvent::TimeoutReadBack {
            get_timeout_readback_seconds,
            ..
        } = &mut wrong
        {
            *get_timeout_readback_seconds = 90;
        }
        assert_eq!(
            custody.apply(1_060, wrong),
            Err(CustodyError::TimeoutMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        assert_eq!(custody.fault(), Some(WatchdogFault::TimeoutReadbackChanged));

        let mut custody = advance_to_timeout_readback();
        let mut wrong = configured(1_050);
        if let WatchdogEvent::TimeoutReadBack {
            support_identity, ..
        } = &mut wrong
        {
            *support_identity = "substituted-driver";
        }
        assert_eq!(
            custody.apply(1_060, wrong),
            Err(CustodyError::DeviceIdentityMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let setup_mutations: &[fn(&mut WatchdogEvent<'static>)] = &[
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    set_timeout_acknowledged,
                    ..
                } => *set_timeout_acknowledged = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    get_timeout_acknowledged,
                    ..
                } => *get_timeout_acknowledged = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    support_identity_read,
                    ..
                } => *support_identity_read = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    support_options, ..
                } => *support_options ^= 1,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    nowayout_observed, ..
                } => *nowayout_observed = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    unexpected_close_outcome,
                    ..
                } => *unexpected_close_outcome = UnexpectedCloseOutcome::Unknown,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::TimeoutReadBack {
                    unexpected_close_live_qualified,
                    ..
                } => *unexpected_close_live_qualified = false,
                _ => unreachable!(),
            },
        ];
        for mutate in setup_mutations {
            let mut custody = advance_to_timeout_readback();
            let mut wrong = configured(1_050);
            mutate(&mut wrong);
            assert!(custody.apply(1_060, wrong).is_err());
            assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        }

        let mut custody = advance_to_timeout_readback();
        let mut unqualified_close = configured(1_050);
        if let WatchdogEvent::TimeoutReadBack {
            unexpected_close_live_qualified,
            ..
        } = &mut unqualified_close
        {
            *unexpected_close_live_qualified = false;
        }
        assert!(custody.apply(1_060, unqualified_close).is_err());
        assert_eq!(
            custody.required_fail_safe_actions(),
            Some(&NANO3_WATCHDOG_UNQUALIFIED_CLOSE_FAIL_SAFE_ACTIONS)
        );

        let mut short_timeout_policy = policy();
        short_timeout_policy.requested_timeout_seconds = 1;
        let mut custody = Nano3WatchdogCustody::new(short_timeout_policy).unwrap();
        custody.apply(1_010, bridge(1_000)).unwrap();
        custody.apply(1_020, stock_quiesced(1_010)).unwrap();
        custody.apply(1_030, replacement_custody(1_020)).unwrap();
        custody.apply(1_040, stock_released(1_030)).unwrap();
        custody.apply(1_050, opened(1_040)).unwrap();
        let mut unsafe_timeout = configured(1_050);
        if let WatchdogEvent::TimeoutReadBack {
            requested_timeout_seconds,
            set_timeout_returned_seconds,
            get_timeout_readback_seconds,
            ..
        } = &mut unsafe_timeout
        {
            *requested_timeout_seconds = 1;
            *set_timeout_returned_seconds = 1;
            *get_timeout_readback_seconds = 1;
        }
        assert_eq!(
            custody.apply(1_060, unsafe_timeout),
            Err(CustodyError::TimeoutMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
    }

    #[test]
    fn envelope_errors_and_out_of_order_events_fault_terminally() {
        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        assert_eq!(
            custody.apply(999, bridge(1_000)),
            Err(CustodyError::ObservationInFuture)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        assert_eq!(
            custody.apply(1_251, bridge(1_000)),
            Err(CustodyError::ObservationStale)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        custody.apply(1_010, bridge(1_000)).unwrap();
        assert_eq!(
            custody.apply(1_020, stock_quiesced(1_000)),
            Err(CustodyError::ObservationNotMonotonic)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        custody.apply(1_010, bridge(1_000)).unwrap();
        let mut cross_iteration = stock_quiesced(1_010);
        if let WatchdogEvent::StockQuiesced {
            custody_iteration, ..
        } = &mut cross_iteration
        {
            *custody_iteration = 8;
        }
        assert_eq!(
            custody.apply(1_020, cross_iteration),
            Err(CustodyError::IterationMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        assert!(matches!(
            custody.apply(1_010, stock_quiesced(1_000)),
            Err(CustodyError::OutOfOrder { .. })
        ));
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        assert_eq!(custody.fault(), Some(WatchdogFault::EventOutOfOrder));
    }

    #[test]
    fn leases_are_fenced_monotonic_and_expire_terminally() {
        let mut custody = held();
        let mut duplicate = lease(1_070, 1, 44);
        if let WatchdogEvent::LeaseRenewed {
            custody_iteration, ..
        } = &mut duplicate
        {
            *custody_iteration = 9;
        }
        assert_eq!(
            custody.apply(1_080, duplicate),
            Err(CustodyError::LeaseSequenceMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        assert_eq!(custody.fault(), Some(WatchdogFault::LeaseFenceInvalid));

        let mut custody = held();
        assert_eq!(
            custody.apply(1_080, lease(1_070, 3, 44)),
            Err(CustodyError::IterationMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = held();
        assert_eq!(
            custody.apply(1_080, lease(1_070, 2, 45)),
            Err(CustodyError::FencingTokenMismatch)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = held();
        assert_eq!(
            custody.apply(2_071, lease(2_070, 2, 44)),
            Err(CustodyError::LeaseExpired)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);

        let mut custody = held();
        custody.apply(1_080, lease(1_070, 2, 44)).unwrap();
        assert!(custody.expire_if_stale(2_071));
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        assert_eq!(custody.fault(), Some(WatchdogFault::LeaseExpired));
    }

    #[test]
    fn every_runtime_renewal_revalidates_custody_identity_and_timeout() {
        let mutations: &[fn(&mut WatchdogEvent<'static>)] = &[
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    independent_heartbeat_fresh,
                    ..
                } => *independent_heartbeat_fresh = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    independent_cut_armed,
                    ..
                } => *independent_cut_armed = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    replacement_cooling_fresh,
                    ..
                } => *replacement_cooling_fresh = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    replacement_sensors_fresh,
                    ..
                } => *replacement_sensors_fresh = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    controller_healthy, ..
                } => *controller_healthy = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    complete_custody_iteration,
                    ..
                } => *complete_custody_iteration = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    stock_watchdog_openers,
                    ..
                } => *stock_watchdog_openers = 1,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    dcentral_watchdog_openers,
                    ..
                } => *dcentral_watchdog_openers = 2,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed { device_minor, .. } => *device_minor += 1,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    support_identity, ..
                } => *support_identity = "substituted-driver",
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed { lease_epoch, .. } => *lease_epoch += 1,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed { boot_id_sha256, .. } => boot_id_sha256[0] ^= 0xff,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    effective_timeout_seconds,
                    ..
                } => *effective_timeout_seconds += 1,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    nowayout_observed, ..
                } => *nowayout_observed = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    support_options, ..
                } => *support_options ^= 1,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    unexpected_close_outcome,
                    ..
                } => *unexpected_close_outcome = UnexpectedCloseOutcome::WatchdogDisarmed,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    unexpected_close_live_qualified,
                    ..
                } => *unexpected_close_live_qualified = false,
                _ => unreachable!(),
            },
            |event| match event {
                WatchdogEvent::LeaseRenewed {
                    keepalive_acknowledged,
                    ..
                } => *keepalive_acknowledged = false,
                _ => unreachable!(),
            },
        ];

        for mutate in mutations {
            let mut custody = held();
            let mut event = lease(1_070, 2, 44);
            mutate(&mut event);
            assert!(custody.apply(1_080, event).is_err());
            assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        }

        let mut custody = advance_to_first_lease();
        assert_eq!(
            custody.apply(2_061, lease(2_060, 1, 44)),
            Err(CustodyError::LeaseExpired)
        );
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
    }

    #[test]
    fn desk_model_never_grants_physical_or_production_authority() {
        assert!(!std::hint::black_box(
            NANO3_WATCHDOG_LIVE_EFFECTIVENESS_PROVEN
        ));
        assert!(!std::hint::black_box(
            NANO3_WATCHDOG_HARDWARE_PROVENANCE_PROVEN
        ));
        assert!(!std::hint::black_box(NANO3_WATCHDOG_PRODUCTION_AUTHORIZED));

        let custody = held();
        assert!(custody.k230_reset_lease_held(1_100));
        assert!(custody.required_fail_safe_actions().is_none());

        let mut custody = custody;
        custody
            .latch_fault(WatchdogFault::RuntimeBackendLost)
            .unwrap();
        assert_eq!(
            custody.required_fail_safe_actions(),
            Some(&NANO3_WATCHDOG_FAIL_SAFE_ACTIONS)
        );
        assert!(custody.requires_fresh_machine_for_recovery());
        assert_eq!(
            custody.apply(1_110, lease(1_100, 2, 44)),
            Err(CustodyError::TerminalFault)
        );
    }

    #[test]
    fn invalid_policy_and_runtime_faults_fail_closed() {
        let mut invalid = policy();
        invalid.device = "/tmp/watchdog";
        assert!(matches!(
            Nano3WatchdogCustody::new(invalid),
            Err(CustodyError::InvalidPolicy(_))
        ));

        for mutate in [
            |policy: &mut WatchdogPolicy<'static>| policy.qualified_keepalive_cadence_ms = 0,
            |policy: &mut WatchdogPolicy<'static>| policy.maximum_keepalive_jitter_ms = 0,
            |policy: &mut WatchdogPolicy<'static>| policy.timeout_safety_margin_ms = 0,
            |policy: &mut WatchdogPolicy<'static>| policy.qualified_keepalive_cadence_ms = u64::MAX,
            |policy: &mut WatchdogPolicy<'static>| policy.expected_nowayout = false,
            |policy: &mut WatchdogPolicy<'static>| {
                policy.expected_unexpected_close_outcome = UnexpectedCloseOutcome::WatchdogDisarmed
            },
        ] {
            let mut invalid = policy();
            mutate(&mut invalid);
            assert!(matches!(
                Nano3WatchdogCustody::new(invalid),
                Err(CustodyError::InvalidPolicy(_))
            ));
        }

        let mut unsafe_timing = policy();
        unsafe_timing.requested_timeout_seconds = 1;
        unsafe_timing.maximum_effective_timeout_seconds = 2;
        assert!(matches!(
            Nano3WatchdogCustody::new(unsafe_timing),
            Err(CustodyError::InvalidPolicy(_))
        ));

        let mut custody = Nano3WatchdogCustody::new(policy()).unwrap();
        custody
            .latch_fault(WatchdogFault::RuntimeBackendLost)
            .unwrap();
        assert_eq!(custody.state(), WatchdogCustodyState::Faulted);
        assert_eq!(
            custody.latch_fault(WatchdogFault::Other("again")),
            Err(CustodyError::TerminalFault)
        );
    }

    #[test]
    fn module_has_no_device_or_ioctl_backend() {
        let source = include_str!("nano3_watchdog.rs");
        for banned in [
            concat!("Open", "Options"),
            concat!("File", "::open"),
            concat!("libc", "::ioctl"),
            concat!("std::fs::", "write"),
            concat!("tokio::", "spawn"),
        ] {
            assert!(
                !source.contains(banned),
                "model contains I/O surface {banned}"
            );
        }
    }
}
