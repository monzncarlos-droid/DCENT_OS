// SPDX-License-Identifier: GPL-3.0-or-later
//
// Disabled-by-construction Nano 3 watchdog backend qualification and receipt
// contract. This module contains no system adapter and performs no I/O. It
// validates caller-supplied desk evidence, defines a future append/sync sink
// boundary, and produces fixture-authenticated tamper-evident records. None of
// those operations proves a live device, durable media, or physical effect.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::nano3_watchdog::{UnexpectedCloseOutcome, WatchdogCustodyState, NANO3_WATCHDOG_DEVICE};

pub type Sha256Digest = [u8; 32];
pub type ReceiptSignature = [u8; 64];

pub const NANO3_WATCHDOG_SYSTEM_BACKEND_ENABLED: bool = false;
pub const NANO3_WATCHDOG_BACKEND_LIVE_QUALIFIED: bool = false;
pub const NANO3_WATCHDOG_BACKEND_PRODUCTION_AUTHORIZED: bool = false;
pub const NANO3_WATCHDOG_RECEIPT_MEDIA_DURABILITY_PROVEN: bool = false;
pub const NANO3_WATCHDOG_RECEIPT_GLOBAL_DURABILITY_PROVEN: bool = false;
pub const NANO3_WATCHDOG_EXTERNAL_HEAD_CUSTODY_PROVEN: bool = false;
pub const NANO3_WATCHDOG_PRODUCTION_RECEIPT_KEY_SHA256: Option<Sha256Digest> = None;
pub const NANO3_WATCHDOG_MAX_CANONICAL_RECORD_BYTES: usize = 16_384;
pub const NANO3_WATCHDOG_MAX_CANONICAL_HEAD_BYTES: usize = 1_024;
pub const NANO3_WATCHDOG_W4_MODEL_SOURCE_SHA256: Sha256Digest = [
    0x65, 0xa6, 0x8c, 0xb8, 0xff, 0x0c, 0xef, 0x12, 0xdb, 0x52, 0x4f, 0x32, 0x66, 0xc9, 0xf7, 0x6a,
    0x02, 0x04, 0xfb, 0x57, 0x0e, 0xd7, 0x6b, 0x05, 0xdc, 0xf5, 0x3c, 0x81, 0x50, 0x80, 0x50, 0x6a,
];

const RECEIPT_SCHEMA_DOMAIN: &[u8] = b"dcentral.nano3.k230-watchdog-custody-receipt.v1";
const RECORD_SIGNATURE_DOMAIN: &[u8] = b"dcentral.nano3.watchdog-receipt-record-signature.v1";
const HEAD_SIGNATURE_DOMAIN: &[u8] = b"dcentral.nano3.watchdog-receipt-head-signature.v1";
const FAULT_NONCE_DOMAIN: &[u8] = b"dcentral.nano3.watchdog-receipt-fault-nonce.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendEvidenceSource {
    DeskFixtureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptSignerClass {
    FixtureOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSignerIdentity {
    pub purpose: String,
    pub key_identity_sha256: Sha256Digest,
    pub key_epoch: u64,
    pub class: ReceiptSignerClass,
}

impl ReceiptSignerIdentity {
    fn validate(&self) -> Result<(), BackendError> {
        require_identity(
            self.purpose == "nano3-watchdog-custody-receipt",
            "exact watchdog receipt signer purpose",
        )?;
        require_identity(
            nonzero_digest(self.key_identity_sha256),
            "non-zero receipt signer key identity",
        )?;
        require_identity(self.key_epoch > 0, "non-zero receipt signer key epoch")?;
        require_identity(
            self.class == ReceiptSignerClass::FixtureOnly,
            "fixture-only receipt signer class",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityKeySeparation {
    pub receipt_key_sha256: Sha256Digest,
    pub authorization_a_key_sha256: Sha256Digest,
    pub operator_key_sha256: Sha256Digest,
    pub physical_observer_key_sha256: Sha256Digest,
}

impl AuthorityKeySeparation {
    fn validate(self, signer: &ReceiptSignerIdentity) -> Result<(), BackendError> {
        let keys = [
            self.receipt_key_sha256,
            self.authorization_a_key_sha256,
            self.operator_key_sha256,
            self.physical_observer_key_sha256,
        ];
        require_identity(
            keys.into_iter().all(nonzero_digest),
            "all role key identities are non-zero",
        )?;
        require_identity(
            self.receipt_key_sha256 == signer.key_identity_sha256,
            "receipt signer matches receipt-role key identity",
        )?;
        for left in 0..keys.len() {
            for right in (left + 1)..keys.len() {
                require_identity(
                    keys[left] != keys[right],
                    "role key identities are distinct",
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogBackendIdentity {
    pub unit_fingerprint_sha256: Sha256Digest,
    pub session_id_sha256: Sha256Digest,
    pub session_nonce_sha256: Sha256Digest,
    pub boot_id_sha256: Sha256Digest,
    pub monotonic_clock_domain_sha256: Sha256Digest,
    pub kernel_build_sha256: Sha256Digest,
    pub kernel_config_sha256: Sha256Digest,
    pub policy_sha256: Sha256Digest,
    pub backend_source_sha256: Sha256Digest,
    pub receipt_schema_source_sha256: Sha256Digest,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub process_start_ticks: u64,
    pub keeper_thread_id: u64,
    pub executable_sha256: Sha256Digest,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable_size: u64,
    pub executable_link_count: u64,
    pub watchdog_device_path: String,
    pub owner_epoch: u64,
    pub fencing_token_sha256: Sha256Digest,
    pub maximum_receipt_observation_age_ms: u64,
    pub source: BackendEvidenceSource,
}

impl WatchdogBackendIdentity {
    fn validate(&self) -> Result<(), BackendError> {
        let digests = [
            self.unit_fingerprint_sha256,
            self.session_id_sha256,
            self.session_nonce_sha256,
            self.boot_id_sha256,
            self.monotonic_clock_domain_sha256,
            self.kernel_build_sha256,
            self.kernel_config_sha256,
            self.policy_sha256,
            self.backend_source_sha256,
            self.receipt_schema_source_sha256,
            self.executable_sha256,
            self.fencing_token_sha256,
        ];
        require_identity(
            digests.into_iter().all(nonzero_digest),
            "all backend identity digests are non-zero",
        )?;
        require_identity(self.process_id > 0, "non-zero keeper process id")?;
        require_identity(
            self.parent_process_id > 0 && self.parent_process_id != self.process_id,
            "distinct non-zero parent process id",
        )?;
        require_identity(
            self.process_start_ticks > 0,
            "non-zero process start identity",
        )?;
        require_identity(self.keeper_thread_id > 0, "non-zero keeper thread id")?;
        require_identity(self.executable_size > 0, "non-empty executable")?;
        require_identity(
            self.executable_device > 0 && self.executable_inode > 0,
            "executable file identity",
        )?;
        require_identity(
            self.executable_link_count == 1,
            "single-link executable identity",
        )?;
        require_identity(
            self.watchdog_device_path == NANO3_WATCHDOG_DEVICE,
            "exact watchdog device path",
        )?;
        require_identity(self.owner_epoch > 0, "non-zero owner epoch")?;
        require_identity(
            self.maximum_receipt_observation_age_ms > 0,
            "non-zero receipt observation age bound",
        )?;
        require_identity(
            self.source == BackendEvidenceSource::DeskFixtureOnly,
            "desk-fixture backend evidence source",
        )?;
        Ok(())
    }

    pub fn digest(&self) -> Sha256Digest {
        hash_bytes(&encode_backend_identity(self))
    }

    fn same_process_instance(&self, observed: &Self) -> bool {
        self.process_id == observed.process_id
            && self.process_start_ticks == observed.process_start_ticks
            && self.keeper_thread_id == observed.keeper_thread_id
            && self.executable_sha256 == observed.executable_sha256
    }

    fn same_static_target(&self, proposed: &Self) -> bool {
        self.unit_fingerprint_sha256 == proposed.unit_fingerprint_sha256
            && self.kernel_build_sha256 == proposed.kernel_build_sha256
            && self.kernel_config_sha256 == proposed.kernel_config_sha256
            && self.policy_sha256 == proposed.policy_sha256
            && self.backend_source_sha256 == proposed.backend_source_sha256
            && self.receipt_schema_source_sha256 == proposed.receipt_schema_source_sha256
            && self.executable_sha256 == proposed.executable_sha256
            && self.watchdog_device_path == proposed.watchdog_device_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedWatchdogIdentity {
    pub watchdog_fd: u32,
    pub watchdog_open_description_sha256: Sha256Digest,
    pub watchdog_device_major: u32,
    pub watchdog_device_minor: u32,
    pub sysfs_device_identity_sha256: Sha256Digest,
    pub driver_identity_sha256: Sha256Digest,
    pub driver_module_sha256: Sha256Digest,
    pub device_tree_identity_sha256: Sha256Digest,
    pub opened_read_write: bool,
    pub opened_no_follow: bool,
    pub opened_close_on_exec: bool,
    pub exactly_one_keeper: bool,
}

impl OpenedWatchdogIdentity {
    fn validate(self) -> Result<(), BackendError> {
        require_identity(self.watchdog_fd > 2, "dedicated watchdog file descriptor")?;
        require_identity(
            [
                self.watchdog_open_description_sha256,
                self.sysfs_device_identity_sha256,
                self.driver_identity_sha256,
                self.driver_module_sha256,
                self.device_tree_identity_sha256,
            ]
            .into_iter()
            .all(nonzero_digest),
            "complete post-open identity digests",
        )?;
        require_identity(
            self.watchdog_device_major > 0,
            "non-zero watchdog character-device major",
        )?;
        require_identity(self.opened_read_write, "read/write open semantics")?;
        require_identity(self.opened_no_follow, "no-follow open semantics")?;
        require_identity(self.opened_close_on_exec, "close-on-exec open semantics")?;
        require_identity(self.exactly_one_keeper, "exactly one post-open keeper")?;
        Ok(())
    }

    pub fn digest(self) -> Sha256Digest {
        hash_bytes(&encode_opened_identity(self))
    }
}

pub trait ReceiptAuthenticator {
    fn identity(&self) -> ReceiptSignerIdentity;
    fn sign_fixture(&self, message: &[u8]) -> Result<ReceiptSignature, BackendError>;
    fn verify_fixture(&self, message: &[u8], signature: &ReceiptSignature) -> bool;
}

#[derive(Debug, Clone)]
pub struct WatchdogBackendQualification {
    identity: WatchdogBackendIdentity,
    identity_sha256: Sha256Digest,
    signer_identity: ReceiptSignerIdentity,
    key_separation: AuthorityKeySeparation,
}

impl WatchdogBackendQualification {
    pub fn validate_desk_only(
        identity: WatchdogBackendIdentity,
        signer_identity: ReceiptSignerIdentity,
        key_separation: AuthorityKeySeparation,
    ) -> Result<Self, BackendError> {
        identity.validate()?;
        signer_identity.validate()?;
        key_separation.validate(&signer_identity)?;
        Ok(Self {
            identity_sha256: identity.digest(),
            identity,
            signer_identity,
            key_separation,
        })
    }

    pub const fn backend_enabled(&self) -> bool {
        false
    }

    pub const fn live_effectiveness_proven(&self) -> bool {
        false
    }

    pub const fn hardware_provenance_proven(&self) -> bool {
        false
    }

    pub const fn production_authorized(&self) -> bool {
        false
    }

    pub const fn phase_b_authorized(&self) -> bool {
        false
    }

    pub const fn independent_cut_observed(&self) -> bool {
        false
    }

    pub const fn device_contact(&self) -> &'static str {
        "none"
    }

    pub const fn identity(&self) -> &WatchdogBackendIdentity {
        &self.identity
    }

    pub const fn identity_sha256(&self) -> Sha256Digest {
        self.identity_sha256
    }

    pub const fn signer_identity(&self) -> &ReceiptSignerIdentity {
        &self.signer_identity
    }

    pub const fn key_separation(&self) -> AuthorityKeySeparation {
        self.key_separation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendReceiptState {
    Uninitialized,
    StartupSafeIdle,
    OpenIntentRecorded,
    ExclusiveOpenClaimedUnproven,
    TimeoutClaimedUnproven,
    LeaseModeled,
    Faulted,
    DurabilityAmbiguous,
}

impl BackendReceiptState {
    const fn code(self) -> u8 {
        match self {
            Self::Uninitialized => 0,
            Self::StartupSafeIdle => 1,
            Self::OpenIntentRecorded => 2,
            Self::ExclusiveOpenClaimedUnproven => 3,
            Self::TimeoutClaimedUnproven => 4,
            Self::LeaseModeled => 5,
            Self::Faulted => 6,
            Self::DurabilityAmbiguous => 7,
        }
    }

    const fn terminal(self) -> bool {
        matches!(self, Self::Faulted | Self::DurabilityAmbiguous)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFault {
    IdentityMismatch,
    ForkOrRestartDetected,
    StaleOrFutureMonotonicEvidence,
    ReplayOrDuplicate,
    InvalidTransition,
    LeaseFenceMismatch,
    W4LeaseNotHeld,
    CrashObserved,
    SinkAppendFailed,
    SinkContractMismatch,
    ReceiptAuthenticationFailed,
    ReceiptChainInvalid,
    RestartFenceRejected,
}

impl BackendFault {
    const fn code(self) -> u8 {
        match self {
            Self::IdentityMismatch => 1,
            Self::ForkOrRestartDetected => 2,
            Self::StaleOrFutureMonotonicEvidence => 3,
            Self::ReplayOrDuplicate => 4,
            Self::InvalidTransition => 5,
            Self::LeaseFenceMismatch => 6,
            Self::W4LeaseNotHeld => 7,
            Self::CrashObserved => 8,
            Self::SinkAppendFailed => 9,
            Self::SinkContractMismatch => 10,
            Self::ReceiptAuthenticationFailed => 11,
            Self::ReceiptChainInvalid => 12,
            Self::RestartFenceRejected => 13,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptMeaning {
    IntentOnly,
    ClaimedDeskFactUnproven,
    ModelTransitionOnly,
    RequestedFailSafeEffectUnknown,
}

impl ReceiptMeaning {
    const fn code(self) -> u8 {
        match self {
            Self::IntentOnly => 1,
            Self::ClaimedDeskFactUnproven => 2,
            Self::ModelTransitionOnly => 3,
            Self::RequestedFailSafeEffectUnknown => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogBackendEvent {
    StartupSafeIdle {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
    },
    OpenIntent {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
    },
    ExclusiveOpenClaimedUnproven {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
        open_evidence_sha256: Sha256Digest,
        opened_identity: OpenedWatchdogIdentity,
    },
    TimeoutClaimedUnproven {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
        timeout_evidence_sha256: Sha256Digest,
        opened_identity_sha256: Sha256Digest,
        requested_timeout_seconds: u32,
        set_timeout_returned_seconds: u32,
        get_timeout_readback_seconds: u32,
        support_identity_sha256: Sha256Digest,
        support_options: u32,
        nowayout_observed: bool,
        unexpected_close_outcome: UnexpectedCloseOutcome,
        close_qualification_receipt_sha256: Sha256Digest,
    },
    LeaseModeled {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
        lease_sequence: u64,
        custody_iteration: u64,
        w4_state: WatchdogCustodyState,
        w4_model_source_sha256: Sha256Digest,
        w4_policy_sha256: Sha256Digest,
        w4_identity_sha256: Sha256Digest,
        w4_lease_fence_sha256: Sha256Digest,
        w4_receipt_sha256: Sha256Digest,
        opened_identity_sha256: Sha256Digest,
    },
    FaultLatched {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
        fault: BackendFault,
        rejected_evidence_sha256: Sha256Digest,
    },
    CrashObserved {
        monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
    },
}

impl WatchdogBackendEvent {
    pub const fn monotonic_ms(self) -> u64 {
        match self {
            Self::StartupSafeIdle { monotonic_ms, .. }
            | Self::OpenIntent { monotonic_ms, .. }
            | Self::ExclusiveOpenClaimedUnproven { monotonic_ms, .. }
            | Self::TimeoutClaimedUnproven { monotonic_ms, .. }
            | Self::LeaseModeled { monotonic_ms, .. }
            | Self::FaultLatched { monotonic_ms, .. }
            | Self::CrashObserved { monotonic_ms, .. } => monotonic_ms,
        }
    }

    pub const fn nonce_sha256(self) -> Sha256Digest {
        match self {
            Self::StartupSafeIdle { nonce_sha256, .. }
            | Self::OpenIntent { nonce_sha256, .. }
            | Self::ExclusiveOpenClaimedUnproven { nonce_sha256, .. }
            | Self::TimeoutClaimedUnproven { nonce_sha256, .. }
            | Self::LeaseModeled { nonce_sha256, .. }
            | Self::FaultLatched { nonce_sha256, .. }
            | Self::CrashObserved { nonce_sha256, .. } => nonce_sha256,
        }
    }

    const fn meaning(self) -> ReceiptMeaning {
        match self {
            Self::OpenIntent { .. } => ReceiptMeaning::IntentOnly,
            Self::ExclusiveOpenClaimedUnproven { .. } | Self::TimeoutClaimedUnproven { .. } => {
                ReceiptMeaning::ClaimedDeskFactUnproven
            }
            Self::StartupSafeIdle { .. } | Self::LeaseModeled { .. } => {
                ReceiptMeaning::ModelTransitionOnly
            }
            Self::FaultLatched { .. } | Self::CrashObserved { .. } => {
                ReceiptMeaning::RequestedFailSafeEffectUnknown
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogCustodyReceipt {
    sequence: u64,
    previous_record_sha256: Sha256Digest,
    identity: WatchdogBackendIdentity,
    identity_sha256: Sha256Digest,
    signer_identity: ReceiptSignerIdentity,
    state_before: BackendReceiptState,
    state_after: BackendReceiptState,
    event: WatchdogBackendEvent,
    verified_at_monotonic_ms: u64,
    event_sha256: Sha256Digest,
    signature: ReceiptSignature,
    record_sha256: Sha256Digest,
}

impl WatchdogCustodyReceipt {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn record_sha256(&self) -> Sha256Digest {
        self.record_sha256
    }

    pub const fn state_after(&self) -> BackendReceiptState {
        self.state_after
    }

    pub const fn event(&self) -> WatchdogBackendEvent {
        self.event
    }

    pub const fn identity_manifest(&self) -> &WatchdogBackendIdentity {
        &self.identity
    }

    pub const fn verified_at_monotonic_ms(&self) -> u64 {
        self.verified_at_monotonic_ms
    }

    pub const fn backend_enabled(&self) -> bool {
        false
    }

    pub const fn physical_effect_observed(&self) -> bool {
        false
    }

    pub const fn independent_cut_observed(&self) -> bool {
        false
    }

    fn body_bytes(&self) -> Vec<u8> {
        encode_receipt_body(
            self.sequence,
            self.previous_record_sha256,
            &self.identity,
            self.identity_sha256,
            &self.signer_identity,
            self.state_before,
            self.state_after,
            self.event,
            self.verified_at_monotonic_ms,
            self.event_sha256,
        )
    }

    pub fn canonical_storage_bytes(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        put_bytes(&mut out, &self.signature);
        put_digest(&mut out, self.record_sha256);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptChainHead {
    pub receipt_count: u64,
    pub record_sha256: Sha256Digest,
    pub identity_sha256: Sha256Digest,
    pub signer_identity: ReceiptSignerIdentity,
    pub signature: ReceiptSignature,
}

impl ReceiptChainHead {
    fn body_bytes(&self) -> Vec<u8> {
        encode_head_body(
            self.receipt_count,
            self.record_sha256,
            self.identity_sha256,
            &self.signer_identity,
        )
    }

    pub fn canonical_storage_bytes(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        put_bytes(&mut out, &self.signature);
        out
    }

    pub const fn external_custody_proven(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptDurabilityClaims {
    pub append_durability_proven: bool,
    pub file_sync_durability_proven: bool,
    pub parent_sync_durability_proven: bool,
    pub media_durability_proven: bool,
    pub global_durability_proven: bool,
}

impl ReceiptDurabilityClaims {
    pub const fn none_proven() -> Self {
        Self {
            append_durability_proven: false,
            file_sync_durability_proven: false,
            parent_sync_durability_proven: false,
            media_durability_proven: false,
            global_durability_proven: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptSinkAck {
    pub sequence: u64,
    pub previous_record_sha256: Sha256Digest,
    pub record_sha256: Sha256Digest,
    pub exclusive_append_step_exercised: bool,
    pub full_write_step_exercised: bool,
    pub file_sync_step_exercised: bool,
    pub parent_sync_step_exercised: bool,
    pub owner_only_step_exercised: bool,
    pub no_alias_step_exercised: bool,
}

pub struct ReceiptWriteRequest<'a> {
    pub sequence: u64,
    pub expected_previous_record_sha256: Sha256Digest,
    pub record_sha256: Sha256Digest,
    pub canonical_record_bytes: &'a [u8],
}

pub trait ReceiptSink {
    fn append_no_overwrite_and_sync(
        &mut self,
        request: ReceiptWriteRequest<'_>,
    ) -> Result<ReceiptSinkAck, ReceiptSinkFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptSinkFailure {
    AppendRejected,
    ShortWrite,
    FileSyncFailed,
    ParentSyncFailed,
    AliasOrOwnershipRejected,
    HeadChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    InvalidIdentity(&'static str),
    GateClosed(&'static str),
    Faulted(BackendFault),
    ReceiptSink(ReceiptSinkFailure),
    ReceiptContract(&'static str),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(item) => write!(f, "invalid backend identity: {item}"),
            Self::GateClosed(gate) => write!(f, "watchdog backend gate is closed: {gate}"),
            Self::Faulted(fault) => write!(f, "watchdog backend receipt fault: {fault:?}"),
            Self::ReceiptSink(error) => write!(f, "watchdog receipt sink failed: {error:?}"),
            Self::ReceiptContract(item) => write!(f, "watchdog receipt contract failed: {item}"),
        }
    }
}

impl std::error::Error for BackendError {}

pub struct WatchdogCustodyJournal<A: ReceiptAuthenticator, S: ReceiptSink> {
    qualification: WatchdogBackendQualification,
    authenticator: A,
    sink: S,
    state: BackendReceiptState,
    receipts: Vec<WatchdogCustodyReceipt>,
    last_monotonic_ms: Option<u64>,
    last_lease_sequence: u64,
    last_custody_iteration: u64,
    opened_identity_sha256: Option<Sha256Digest>,
    fault: Option<BackendFault>,
}

impl<A: ReceiptAuthenticator, S: ReceiptSink> WatchdogCustodyJournal<A, S> {
    pub fn start_fixture_only(
        qualification: WatchdogBackendQualification,
        authenticator: A,
        sink: S,
        monotonic_ms: u64,
        verified_at_monotonic_ms: u64,
        nonce_sha256: Sha256Digest,
    ) -> Result<Self, BackendError> {
        if authenticator.identity() != *qualification.signer_identity() {
            return Err(BackendError::InvalidIdentity(
                "authenticator identity matches qualification",
            ));
        }
        if !nonzero_digest(nonce_sha256) {
            return Err(BackendError::Faulted(BackendFault::ReplayOrDuplicate));
        }
        let mut journal = Self {
            qualification,
            authenticator,
            sink,
            state: BackendReceiptState::Uninitialized,
            receipts: Vec::new(),
            last_monotonic_ms: None,
            last_lease_sequence: 0,
            last_custody_iteration: 0,
            opened_identity_sha256: None,
            fault: None,
        };
        journal.validate_observation_time(monotonic_ms, verified_at_monotonic_ms)?;
        journal.persist(
            WatchdogBackendEvent::StartupSafeIdle {
                monotonic_ms,
                nonce_sha256,
            },
            verified_at_monotonic_ms,
        )?;
        Ok(journal)
    }

    pub const fn state(&self) -> BackendReceiptState {
        self.state
    }

    pub const fn fault(&self) -> Option<BackendFault> {
        self.fault
    }

    pub fn receipts(&self) -> &[WatchdogCustodyReceipt] {
        &self.receipts
    }

    pub const fn durability_claims(&self) -> ReceiptDurabilityClaims {
        ReceiptDurabilityClaims::none_proven()
    }

    pub const fn may_contact_device(&self) -> bool {
        false
    }

    pub const fn may_pet_watchdog(&self) -> bool {
        false
    }

    pub const fn may_resume_after_restart(&self) -> bool {
        false
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn head(&self) -> Result<ReceiptChainHead, BackendError> {
        let last = self
            .receipts
            .last()
            .ok_or(BackendError::ReceiptContract("receipt chain is empty"))?;
        let mut head = ReceiptChainHead {
            receipt_count: self.receipts.len() as u64,
            record_sha256: last.record_sha256,
            identity_sha256: self.qualification.identity_sha256(),
            signer_identity: self.authenticator.identity(),
            signature: [0; 64],
        };
        let mut signed = Vec::from(HEAD_SIGNATURE_DOMAIN);
        signed.extend_from_slice(&head.body_bytes());
        head.signature = self.authenticator.sign_fixture(&signed)?;
        Ok(head)
    }

    pub fn append_fixture_event(
        &mut self,
        runtime_identity: &WatchdogBackendIdentity,
        event: WatchdogBackendEvent,
        verified_at_monotonic_ms: u64,
    ) -> Result<(), BackendError> {
        if self.state.terminal() {
            return Err(BackendError::Faulted(
                self.fault.unwrap_or(BackendFault::SinkContractMismatch),
            ));
        }
        if runtime_identity != self.qualification.identity() {
            let fault = if self
                .qualification
                .identity()
                .same_process_instance(runtime_identity)
            {
                BackendFault::IdentityMismatch
            } else {
                BackendFault::ForkOrRestartDetected
            };
            return self.reject(fault, event, verified_at_monotonic_ms);
        }
        if let Err(fault) = self.validate_event(event, verified_at_monotonic_ms) {
            return self.reject(fault, event, verified_at_monotonic_ms);
        }
        self.persist(event, verified_at_monotonic_ms)
    }

    fn validate_observation_time(
        &self,
        event_monotonic_ms: u64,
        verified_at_monotonic_ms: u64,
    ) -> Result<(), BackendError> {
        let age = verified_at_monotonic_ms
            .checked_sub(event_monotonic_ms)
            .ok_or(BackendError::Faulted(
                BackendFault::StaleOrFutureMonotonicEvidence,
            ))?;
        if age
            > self
                .qualification
                .identity()
                .maximum_receipt_observation_age_ms
        {
            return Err(BackendError::Faulted(
                BackendFault::StaleOrFutureMonotonicEvidence,
            ));
        }
        Ok(())
    }

    fn validate_event(
        &self,
        event: WatchdogBackendEvent,
        verified_at_monotonic_ms: u64,
    ) -> Result<(), BackendFault> {
        if !nonzero_digest(event.nonce_sha256())
            || self
                .receipts
                .iter()
                .any(|receipt| receipt.event.nonce_sha256() == event.nonce_sha256())
        {
            return Err(BackendFault::ReplayOrDuplicate);
        }
        if self
            .last_monotonic_ms
            .is_some_and(|previous| event.monotonic_ms() <= previous)
        {
            return Err(BackendFault::StaleOrFutureMonotonicEvidence);
        }
        self.validate_observation_time(event.monotonic_ms(), verified_at_monotonic_ms)
            .map_err(|_| BackendFault::StaleOrFutureMonotonicEvidence)?;
        match event {
            WatchdogBackendEvent::TimeoutClaimedUnproven {
                opened_identity_sha256,
                ..
            }
            | WatchdogBackendEvent::LeaseModeled {
                opened_identity_sha256,
                ..
            } if self.opened_identity_sha256 != Some(opened_identity_sha256) => {
                return Err(BackendFault::IdentityMismatch);
            }
            _ => {}
        }
        next_state(
            self.state,
            event,
            self.last_lease_sequence,
            self.last_custody_iteration,
        )
        .map(|_| ())
        .map_err(|error| match error {
            BackendError::Faulted(fault) => fault,
            _ => BackendFault::InvalidTransition,
        })
    }

    fn reject(
        &mut self,
        fault: BackendFault,
        rejected: WatchdogBackendEvent,
        verified_at_monotonic_ms: u64,
    ) -> Result<(), BackendError> {
        let evidence_sha256 = hash_bytes(&encode_event(rejected));
        let next_after_last = self
            .last_monotonic_ms
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| self.mark_ambiguous(BackendFault::SinkContractMismatch))?;
        let monotonic_ms = next_after_last.max(verified_at_monotonic_ms);
        let nonce_sha256 = derive_fault_nonce(
            evidence_sha256,
            self.receipts.len().saturating_add(1) as u64,
        );
        let fault_event = WatchdogBackendEvent::FaultLatched {
            monotonic_ms,
            nonce_sha256,
            fault,
            rejected_evidence_sha256: evidence_sha256,
        };
        if self.persist(fault_event, monotonic_ms).is_err() {
            return Err(self.mark_ambiguous(BackendFault::SinkAppendFailed));
        }
        self.fault = Some(fault);
        Err(BackendError::Faulted(fault))
    }

    fn persist(
        &mut self,
        event: WatchdogBackendEvent,
        verified_at_monotonic_ms: u64,
    ) -> Result<(), BackendError> {
        let state_after = next_state(
            self.state,
            event,
            self.last_lease_sequence,
            self.last_custody_iteration,
        )?;
        let sequence = (self.receipts.len() as u64)
            .checked_add(1)
            .ok_or(BackendError::ReceiptContract("receipt sequence overflow"))?;
        let previous_record_sha256 = self
            .receipts
            .last()
            .map_or([0; 32], WatchdogCustodyReceipt::record_sha256);
        let event_sha256 = hash_bytes(&encode_event(event));
        let signer_identity = self.authenticator.identity();
        let body = encode_receipt_body(
            sequence,
            previous_record_sha256,
            self.qualification.identity(),
            self.qualification.identity_sha256(),
            &signer_identity,
            self.state,
            state_after,
            event,
            verified_at_monotonic_ms,
            event_sha256,
        );
        let mut signed = Vec::from(RECORD_SIGNATURE_DOMAIN);
        signed.extend_from_slice(&body);
        let signature = self.authenticator.sign_fixture(&signed)?;
        let mut record_material = body;
        record_material.extend_from_slice(&signature);
        let record_sha256 = hash_bytes(&record_material);
        let receipt = WatchdogCustodyReceipt {
            sequence,
            previous_record_sha256,
            identity: self.qualification.identity().clone(),
            identity_sha256: self.qualification.identity_sha256(),
            signer_identity,
            state_before: self.state,
            state_after,
            event,
            verified_at_monotonic_ms,
            event_sha256,
            signature,
            record_sha256,
        };
        let storage = receipt.canonical_storage_bytes();
        let ack = self
            .sink
            .append_no_overwrite_and_sync(ReceiptWriteRequest {
                sequence,
                expected_previous_record_sha256: previous_record_sha256,
                record_sha256,
                canonical_record_bytes: &storage,
            })
            .map_err(|error| {
                self.state = BackendReceiptState::DurabilityAmbiguous;
                self.fault = Some(BackendFault::SinkAppendFailed);
                BackendError::ReceiptSink(error)
            })?;
        if ack.sequence != sequence
            || ack.previous_record_sha256 != previous_record_sha256
            || ack.record_sha256 != record_sha256
            || !ack.exclusive_append_step_exercised
            || !ack.full_write_step_exercised
            || !ack.file_sync_step_exercised
            || !ack.parent_sync_step_exercised
            || !ack.owner_only_step_exercised
            || !ack.no_alias_step_exercised
        {
            self.state = BackendReceiptState::DurabilityAmbiguous;
            self.fault = Some(BackendFault::SinkContractMismatch);
            return Err(BackendError::ReceiptContract(
                "fixture sink acknowledgement mismatch",
            ));
        }
        self.receipts.push(receipt);
        self.state = state_after;
        self.last_monotonic_ms = Some(event.monotonic_ms());
        if let WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
            opened_identity, ..
        } = event
        {
            self.opened_identity_sha256 = Some(opened_identity.digest());
        }
        if let WatchdogBackendEvent::LeaseModeled {
            lease_sequence,
            custody_iteration,
            ..
        } = event
        {
            self.last_lease_sequence = lease_sequence;
            self.last_custody_iteration = custody_iteration;
        }
        if let WatchdogBackendEvent::FaultLatched { fault, .. } = event {
            self.fault = Some(fault);
        }
        if matches!(event, WatchdogBackendEvent::CrashObserved { .. }) {
            self.fault = Some(BackendFault::CrashObserved);
        }
        Ok(())
    }

    fn mark_ambiguous(&mut self, fault: BackendFault) -> BackendError {
        self.state = BackendReceiptState::DurabilityAmbiguous;
        self.fault = Some(fault);
        BackendError::Faulted(fault)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartAssessment {
    pub prior_chain_valid: bool,
    pub fresh_session: bool,
    pub fresh_boot: bool,
    pub fresh_process_instance: bool,
    pub advanced_owner_epoch: bool,
    pub fresh_fencing_token: bool,
    pub prior_open_claim_not_resumable: bool,
    pub starts_safe_idle_faulted: bool,
    pub full_handoff_required: bool,
    pub prior_chain_resumable: bool,
    pub device_contact: &'static str,
}

pub fn assess_restart<A: ReceiptAuthenticator>(
    prior_identity: &WatchdogBackendIdentity,
    prior_receipts: &[WatchdogCustodyReceipt],
    prior_head: &ReceiptChainHead,
    authenticator: &A,
    proposed_identity: &WatchdogBackendIdentity,
) -> Result<RestartAssessment, BackendError> {
    verify_receipt_chain(prior_receipts, prior_head, authenticator)?;
    prior_identity.validate()?;
    proposed_identity.validate()?;
    if prior_identity.digest() != prior_head.identity_sha256
        || !prior_identity.same_static_target(proposed_identity)
    {
        return Err(BackendError::Faulted(BackendFault::RestartFenceRejected));
    }
    let assessment = RestartAssessment {
        prior_chain_valid: true,
        fresh_session: prior_identity.session_id_sha256 != proposed_identity.session_id_sha256
            && prior_identity.session_nonce_sha256 != proposed_identity.session_nonce_sha256,
        fresh_boot: prior_identity.boot_id_sha256 != proposed_identity.boot_id_sha256,
        fresh_process_instance: prior_identity.process_id != proposed_identity.process_id
            || prior_identity.process_start_ticks != proposed_identity.process_start_ticks,
        advanced_owner_epoch: proposed_identity.owner_epoch > prior_identity.owner_epoch,
        fresh_fencing_token: prior_identity.fencing_token_sha256
            != proposed_identity.fencing_token_sha256,
        prior_open_claim_not_resumable: true,
        starts_safe_idle_faulted: true,
        full_handoff_required: true,
        prior_chain_resumable: false,
        device_contact: "none",
    };
    if !assessment.fresh_session
        || !assessment.fresh_boot
        || !assessment.fresh_process_instance
        || !assessment.advanced_owner_epoch
        || !assessment.fresh_fencing_token
    {
        return Err(BackendError::Faulted(BackendFault::RestartFenceRejected));
    }
    Ok(assessment)
}

pub fn verify_receipt_chain<A: ReceiptAuthenticator>(
    receipts: &[WatchdogCustodyReceipt],
    expected_head: &ReceiptChainHead,
    authenticator: &A,
) -> Result<(), BackendError> {
    if receipts.is_empty() || expected_head.receipt_count != receipts.len() as u64 {
        return Err(BackendError::Faulted(BackendFault::ReceiptChainInvalid));
    }
    if authenticator.identity() != expected_head.signer_identity {
        return Err(BackendError::Faulted(
            BackendFault::ReceiptAuthenticationFailed,
        ));
    }
    let mut head_signed = Vec::from(HEAD_SIGNATURE_DOMAIN);
    head_signed.extend_from_slice(&expected_head.body_bytes());
    if !authenticator.verify_fixture(&head_signed, &expected_head.signature) {
        return Err(BackendError::Faulted(
            BackendFault::ReceiptAuthenticationFailed,
        ));
    }

    let mut previous_hash = [0; 32];
    let mut previous_state = BackendReceiptState::Uninitialized;
    let mut previous_monotonic = None;
    let mut last_lease_sequence = 0;
    let mut last_custody_iteration = 0;
    let mut opened_identity_sha256 = None;
    let identity_sha256 = receipts[0].identity_sha256;
    let identity = &receipts[0].identity;
    identity.validate()?;
    if identity.digest() != identity_sha256 {
        return Err(BackendError::Faulted(BackendFault::ReceiptChainInvalid));
    }
    for (index, receipt) in receipts.iter().enumerate() {
        let observation_age = receipt
            .verified_at_monotonic_ms
            .checked_sub(receipt.event.monotonic_ms());
        let opened_identity_join_valid = match receipt.event {
            WatchdogBackendEvent::TimeoutClaimedUnproven {
                opened_identity_sha256: claimed,
                ..
            }
            | WatchdogBackendEvent::LeaseModeled {
                opened_identity_sha256: claimed,
                ..
            } => opened_identity_sha256 == Some(claimed),
            _ => true,
        };
        if receipt.sequence != (index as u64) + 1
            || receipt.previous_record_sha256 != previous_hash
            || receipt.identity != *identity
            || receipt.identity.digest() != receipt.identity_sha256
            || receipt.identity_sha256 != identity_sha256
            || receipt.identity_sha256 != expected_head.identity_sha256
            || receipt.signer_identity != expected_head.signer_identity
            || receipt.state_before != previous_state
            || !nonzero_digest(receipt.event.nonce_sha256())
            || receipts[..index]
                .iter()
                .any(|prior| prior.event.nonce_sha256() == receipt.event.nonce_sha256())
            || previous_monotonic.is_some_and(|previous| receipt.event.monotonic_ms() <= previous)
            || observation_age
                .is_none_or(|age| age > receipt.identity.maximum_receipt_observation_age_ms)
            || !opened_identity_join_valid
            || hash_bytes(&encode_event(receipt.event)) != receipt.event_sha256
            || next_state(
                receipt.state_before,
                receipt.event,
                last_lease_sequence,
                last_custody_iteration,
            ) != Ok(receipt.state_after)
        {
            return Err(BackendError::Faulted(BackendFault::ReceiptChainInvalid));
        }
        let body = receipt.body_bytes();
        let mut signed = Vec::from(RECORD_SIGNATURE_DOMAIN);
        signed.extend_from_slice(&body);
        if !authenticator.verify_fixture(&signed, &receipt.signature) {
            return Err(BackendError::Faulted(
                BackendFault::ReceiptAuthenticationFailed,
            ));
        }
        let mut material = body;
        material.extend_from_slice(&receipt.signature);
        if hash_bytes(&material) != receipt.record_sha256 {
            return Err(BackendError::Faulted(BackendFault::ReceiptChainInvalid));
        }
        if let WatchdogBackendEvent::LeaseModeled {
            lease_sequence,
            custody_iteration,
            ..
        } = receipt.event
        {
            last_lease_sequence = lease_sequence;
            last_custody_iteration = custody_iteration;
        }
        if let WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
            opened_identity, ..
        } = receipt.event
        {
            opened_identity_sha256 = Some(opened_identity.digest());
        }
        previous_hash = receipt.record_sha256;
        previous_state = receipt.state_after;
        previous_monotonic = Some(receipt.event.monotonic_ms());
    }
    if previous_hash != expected_head.record_sha256 {
        return Err(BackendError::Faulted(BackendFault::ReceiptChainInvalid));
    }
    Ok(())
}

fn next_state(
    state: BackendReceiptState,
    event: WatchdogBackendEvent,
    last_lease_sequence: u64,
    last_custody_iteration: u64,
) -> Result<BackendReceiptState, BackendError> {
    match (state, event) {
        (BackendReceiptState::Uninitialized, WatchdogBackendEvent::StartupSafeIdle { .. }) => {
            Ok(BackendReceiptState::StartupSafeIdle)
        }
        (BackendReceiptState::StartupSafeIdle, WatchdogBackendEvent::OpenIntent { .. }) => {
            Ok(BackendReceiptState::OpenIntentRecorded)
        }
        (
            BackendReceiptState::OpenIntentRecorded,
            WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
                open_evidence_sha256,
                opened_identity,
                ..
            },
        ) if nonzero_digest(open_evidence_sha256) && opened_identity.validate().is_ok() => {
            Ok(BackendReceiptState::ExclusiveOpenClaimedUnproven)
        }
        (
            BackendReceiptState::ExclusiveOpenClaimedUnproven,
            WatchdogBackendEvent::TimeoutClaimedUnproven {
                timeout_evidence_sha256,
                requested_timeout_seconds,
                set_timeout_returned_seconds,
                get_timeout_readback_seconds,
                support_identity_sha256,
                support_options,
                nowayout_observed,
                unexpected_close_outcome,
                close_qualification_receipt_sha256,
                ..
            },
        ) if nonzero_digest(timeout_evidence_sha256)
            && requested_timeout_seconds > 0
            && set_timeout_returned_seconds >= requested_timeout_seconds
            && set_timeout_returned_seconds == get_timeout_readback_seconds
            && nonzero_digest(support_identity_sha256)
            && support_options != 0
            && nowayout_observed
            && unexpected_close_outcome == UnexpectedCloseOutcome::ResetRemainsArmed
            && nonzero_digest(close_qualification_receipt_sha256) =>
        {
            Ok(BackendReceiptState::TimeoutClaimedUnproven)
        }
        (
            BackendReceiptState::TimeoutClaimedUnproven | BackendReceiptState::LeaseModeled,
            WatchdogBackendEvent::LeaseModeled {
                lease_sequence,
                custody_iteration,
                w4_state,
                w4_model_source_sha256,
                w4_policy_sha256,
                w4_identity_sha256,
                w4_lease_fence_sha256,
                w4_receipt_sha256,
                ..
            },
        ) => {
            if w4_state != WatchdogCustodyState::Held
                || w4_model_source_sha256 != NANO3_WATCHDOG_W4_MODEL_SOURCE_SHA256
                || !nonzero_digest(w4_policy_sha256)
                || !nonzero_digest(w4_identity_sha256)
                || !nonzero_digest(w4_lease_fence_sha256)
                || !nonzero_digest(w4_receipt_sha256)
            {
                return Err(BackendError::Faulted(BackendFault::W4LeaseNotHeld));
            }
            let expected_lease = last_lease_sequence
                .checked_add(1)
                .ok_or(BackendError::Faulted(BackendFault::LeaseFenceMismatch))?;
            if lease_sequence != expected_lease
                || custody_iteration == 0
                || (last_custody_iteration != 0
                    && last_custody_iteration.checked_add(1) != Some(custody_iteration))
            {
                return Err(BackendError::Faulted(BackendFault::LeaseFenceMismatch));
            }
            Ok(BackendReceiptState::LeaseModeled)
        }
        (
            BackendReceiptState::StartupSafeIdle
            | BackendReceiptState::OpenIntentRecorded
            | BackendReceiptState::ExclusiveOpenClaimedUnproven
            | BackendReceiptState::TimeoutClaimedUnproven
            | BackendReceiptState::LeaseModeled,
            WatchdogBackendEvent::FaultLatched { .. } | WatchdogBackendEvent::CrashObserved { .. },
        ) => Ok(BackendReceiptState::Faulted),
        _ => Err(BackendError::Faulted(BackendFault::InvalidTransition)),
    }
}

fn encode_backend_identity(identity: &WatchdogBackendIdentity) -> Vec<u8> {
    let mut out = Vec::from(RECEIPT_SCHEMA_DOMAIN);
    for digest in [
        identity.unit_fingerprint_sha256,
        identity.session_id_sha256,
        identity.session_nonce_sha256,
        identity.boot_id_sha256,
        identity.monotonic_clock_domain_sha256,
        identity.kernel_build_sha256,
        identity.kernel_config_sha256,
        identity.policy_sha256,
        identity.backend_source_sha256,
        identity.receipt_schema_source_sha256,
    ] {
        put_digest(&mut out, digest);
    }
    put_u32(&mut out, identity.process_id);
    put_u32(&mut out, identity.parent_process_id);
    put_u64(&mut out, identity.process_start_ticks);
    put_u64(&mut out, identity.keeper_thread_id);
    put_digest(&mut out, identity.executable_sha256);
    put_u64(&mut out, identity.executable_device);
    put_u64(&mut out, identity.executable_inode);
    put_u64(&mut out, identity.executable_size);
    put_u64(&mut out, identity.executable_link_count);
    put_string(&mut out, &identity.watchdog_device_path);
    put_u64(&mut out, identity.owner_epoch);
    put_digest(&mut out, identity.fencing_token_sha256);
    put_u64(&mut out, identity.maximum_receipt_observation_age_ms);
    put_u8(&mut out, 1);
    out
}

fn encode_opened_identity(identity: OpenedWatchdogIdentity) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, identity.watchdog_fd);
    put_digest(&mut out, identity.watchdog_open_description_sha256);
    put_u32(&mut out, identity.watchdog_device_major);
    put_u32(&mut out, identity.watchdog_device_minor);
    put_digest(&mut out, identity.sysfs_device_identity_sha256);
    put_digest(&mut out, identity.driver_identity_sha256);
    put_digest(&mut out, identity.driver_module_sha256);
    put_digest(&mut out, identity.device_tree_identity_sha256);
    put_u8(&mut out, identity.opened_read_write as u8);
    put_u8(&mut out, identity.opened_no_follow as u8);
    put_u8(&mut out, identity.opened_close_on_exec as u8);
    put_u8(&mut out, identity.exactly_one_keeper as u8);
    out
}

fn encode_event(event: WatchdogBackendEvent) -> Vec<u8> {
    let mut out = Vec::new();
    put_u64(&mut out, event.monotonic_ms());
    put_digest(&mut out, event.nonce_sha256());
    put_u8(&mut out, event.meaning().code());
    match event {
        WatchdogBackendEvent::StartupSafeIdle { .. } => put_u8(&mut out, 1),
        WatchdogBackendEvent::OpenIntent { .. } => put_u8(&mut out, 2),
        WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
            open_evidence_sha256,
            opened_identity,
            ..
        } => {
            put_u8(&mut out, 3);
            put_digest(&mut out, open_evidence_sha256);
            put_bytes(&mut out, &encode_opened_identity(opened_identity));
        }
        WatchdogBackendEvent::TimeoutClaimedUnproven {
            timeout_evidence_sha256,
            opened_identity_sha256,
            requested_timeout_seconds,
            set_timeout_returned_seconds,
            get_timeout_readback_seconds,
            support_identity_sha256,
            support_options,
            nowayout_observed,
            unexpected_close_outcome,
            close_qualification_receipt_sha256,
            ..
        } => {
            put_u8(&mut out, 4);
            put_digest(&mut out, timeout_evidence_sha256);
            put_digest(&mut out, opened_identity_sha256);
            put_u32(&mut out, requested_timeout_seconds);
            put_u32(&mut out, set_timeout_returned_seconds);
            put_u32(&mut out, get_timeout_readback_seconds);
            put_digest(&mut out, support_identity_sha256);
            put_u32(&mut out, support_options);
            put_u8(&mut out, nowayout_observed as u8);
            put_u8(
                &mut out,
                unexpected_close_outcome_code(unexpected_close_outcome),
            );
            put_digest(&mut out, close_qualification_receipt_sha256);
        }
        WatchdogBackendEvent::LeaseModeled {
            lease_sequence,
            custody_iteration,
            w4_state,
            w4_model_source_sha256,
            w4_policy_sha256,
            w4_identity_sha256,
            w4_lease_fence_sha256,
            w4_receipt_sha256,
            opened_identity_sha256,
            ..
        } => {
            put_u8(&mut out, 5);
            put_u64(&mut out, lease_sequence);
            put_u64(&mut out, custody_iteration);
            put_u8(&mut out, w4_state_code(w4_state));
            put_digest(&mut out, w4_model_source_sha256);
            put_digest(&mut out, w4_policy_sha256);
            put_digest(&mut out, w4_identity_sha256);
            put_digest(&mut out, w4_lease_fence_sha256);
            put_digest(&mut out, w4_receipt_sha256);
            put_digest(&mut out, opened_identity_sha256);
        }
        WatchdogBackendEvent::FaultLatched {
            fault,
            rejected_evidence_sha256,
            ..
        } => {
            put_u8(&mut out, 6);
            put_u8(&mut out, fault.code());
            put_digest(&mut out, rejected_evidence_sha256);
        }
        WatchdogBackendEvent::CrashObserved { .. } => put_u8(&mut out, 7),
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn encode_receipt_body(
    sequence: u64,
    previous_record_sha256: Sha256Digest,
    identity: &WatchdogBackendIdentity,
    identity_sha256: Sha256Digest,
    signer_identity: &ReceiptSignerIdentity,
    state_before: BackendReceiptState,
    state_after: BackendReceiptState,
    event: WatchdogBackendEvent,
    verified_at_monotonic_ms: u64,
    event_sha256: Sha256Digest,
) -> Vec<u8> {
    let mut out = Vec::from(RECEIPT_SCHEMA_DOMAIN);
    put_u64(&mut out, sequence);
    put_digest(&mut out, previous_record_sha256);
    put_bytes(&mut out, &encode_backend_identity(identity));
    put_digest(&mut out, identity_sha256);
    put_string(&mut out, &signer_identity.purpose);
    put_digest(&mut out, signer_identity.key_identity_sha256);
    put_u64(&mut out, signer_identity.key_epoch);
    put_u8(&mut out, 1);
    put_u8(&mut out, state_before.code());
    put_u8(&mut out, state_after.code());
    put_bytes(&mut out, &encode_event(event));
    put_u64(&mut out, verified_at_monotonic_ms);
    put_digest(&mut out, event_sha256);
    out
}

fn encode_head_body(
    receipt_count: u64,
    record_sha256: Sha256Digest,
    identity_sha256: Sha256Digest,
    signer_identity: &ReceiptSignerIdentity,
) -> Vec<u8> {
    let mut out = Vec::from(RECEIPT_SCHEMA_DOMAIN);
    put_u64(&mut out, receipt_count);
    put_digest(&mut out, record_sha256);
    put_digest(&mut out, identity_sha256);
    put_string(&mut out, &signer_identity.purpose);
    put_digest(&mut out, signer_identity.key_identity_sha256);
    put_u64(&mut out, signer_identity.key_epoch);
    put_u8(&mut out, 1);
    out
}

fn derive_fault_nonce(evidence_sha256: Sha256Digest, sequence: u64) -> Sha256Digest {
    let mut bytes = Vec::from(FAULT_NONCE_DOMAIN);
    put_digest(&mut bytes, evidence_sha256);
    put_u64(&mut bytes, sequence);
    hash_bytes(&bytes)
}

fn w4_state_code(state: WatchdogCustodyState) -> u8 {
    match state {
        WatchdogCustodyState::AwaitingIndependentBridge => 1,
        WatchdogCustodyState::AwaitingStockQuiescence => 2,
        WatchdogCustodyState::AwaitingReplacementCustody => 3,
        WatchdogCustodyState::AwaitingStockRelease => 4,
        WatchdogCustodyState::AwaitingExclusiveOpen => 5,
        WatchdogCustodyState::AwaitingTimeoutReadback => 6,
        WatchdogCustodyState::AwaitingFirstLease => 7,
        WatchdogCustodyState::Held => 8,
        WatchdogCustodyState::Faulted => 9,
    }
}

fn unexpected_close_outcome_code(outcome: UnexpectedCloseOutcome) -> u8 {
    match outcome {
        UnexpectedCloseOutcome::ResetRemainsArmed => 1,
        UnexpectedCloseOutcome::WatchdogDisarmed => 2,
        UnexpectedCloseOutcome::Unknown => 3,
    }
}

fn hash_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256::digest(bytes).into()
}

fn nonzero_digest(digest: Sha256Digest) -> bool {
    digest != [0; 32]
}

fn require_identity(valid: bool, item: &'static str) -> Result<(), BackendError> {
    if valid {
        Ok(())
    } else {
        Err(BackendError::InvalidIdentity(item))
    }
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_digest(out: &mut Vec<u8>, value: Sha256Digest) {
    out.extend_from_slice(&value);
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    put_u64(out, length);
    out.extend_from_slice(value);
}

const MAX_IDENTITY_BYTES: usize = 8_192;
const MAX_EVENT_BYTES: usize = 4_096;
const MAX_STRING_BYTES: usize = 256;

struct CanonicalDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> CanonicalDecoder<'a> {
    fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, BackendError> {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(malformed_receipt());
        }
        Ok(Self { bytes, cursor: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BackendError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(malformed_receipt)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(malformed_receipt)?;
        self.cursor = end;
        Ok(value)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), BackendError> {
        if self.take(expected.len())? != expected {
            return Err(malformed_receipt());
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, BackendError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BackendError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| malformed_receipt())
    }

    fn u64(&mut self) -> Result<u64, BackendError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| malformed_receipt())
    }

    fn digest(&mut self) -> Result<Sha256Digest, BackendError> {
        self.take(32)?.try_into().map_err(|_| malformed_receipt())
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], BackendError> {
        let length = usize::try_from(self.u64()?).map_err(|_| malformed_receipt())?;
        if length > maximum {
            return Err(malformed_receipt());
        }
        self.take(length)
    }

    fn string(&mut self) -> Result<String, BackendError> {
        let bytes = self.bytes(MAX_STRING_BYTES)?;
        let text = std::str::from_utf8(bytes).map_err(|_| malformed_receipt())?;
        Ok(text.to_owned())
    }

    fn finish(self) -> Result<(), BackendError> {
        if self.cursor != self.bytes.len() {
            return Err(malformed_receipt());
        }
        Ok(())
    }
}

fn malformed_receipt() -> BackendError {
    BackendError::ReceiptContract("malformed or non-canonical receipt bytes")
}

fn decode_backend_identity(bytes: &[u8]) -> Result<WatchdogBackendIdentity, BackendError> {
    let mut input = CanonicalDecoder::new(bytes, MAX_IDENTITY_BYTES)?;
    input.expect(RECEIPT_SCHEMA_DOMAIN)?;
    let identity = WatchdogBackendIdentity {
        unit_fingerprint_sha256: input.digest()?,
        session_id_sha256: input.digest()?,
        session_nonce_sha256: input.digest()?,
        boot_id_sha256: input.digest()?,
        monotonic_clock_domain_sha256: input.digest()?,
        kernel_build_sha256: input.digest()?,
        kernel_config_sha256: input.digest()?,
        policy_sha256: input.digest()?,
        backend_source_sha256: input.digest()?,
        receipt_schema_source_sha256: input.digest()?,
        process_id: input.u32()?,
        parent_process_id: input.u32()?,
        process_start_ticks: input.u64()?,
        keeper_thread_id: input.u64()?,
        executable_sha256: input.digest()?,
        executable_device: input.u64()?,
        executable_inode: input.u64()?,
        executable_size: input.u64()?,
        executable_link_count: input.u64()?,
        watchdog_device_path: input.string()?,
        owner_epoch: input.u64()?,
        fencing_token_sha256: input.digest()?,
        maximum_receipt_observation_age_ms: input.u64()?,
        source: match input.u8()? {
            1 => BackendEvidenceSource::DeskFixtureOnly,
            _ => return Err(malformed_receipt()),
        },
    };
    input.finish()?;
    identity.validate()?;
    if encode_backend_identity(&identity) != bytes {
        return Err(malformed_receipt());
    }
    Ok(identity)
}

fn decode_opened_identity(bytes: &[u8]) -> Result<OpenedWatchdogIdentity, BackendError> {
    let mut input = CanonicalDecoder::new(bytes, 512)?;
    let identity = OpenedWatchdogIdentity {
        watchdog_fd: input.u32()?,
        watchdog_open_description_sha256: input.digest()?,
        watchdog_device_major: input.u32()?,
        watchdog_device_minor: input.u32()?,
        sysfs_device_identity_sha256: input.digest()?,
        driver_identity_sha256: input.digest()?,
        driver_module_sha256: input.digest()?,
        device_tree_identity_sha256: input.digest()?,
        opened_read_write: decode_bool(input.u8()?)?,
        opened_no_follow: decode_bool(input.u8()?)?,
        opened_close_on_exec: decode_bool(input.u8()?)?,
        exactly_one_keeper: decode_bool(input.u8()?)?,
    };
    input.finish()?;
    identity.validate()?;
    if encode_opened_identity(identity) != bytes {
        return Err(malformed_receipt());
    }
    Ok(identity)
}

fn decode_event(bytes: &[u8]) -> Result<WatchdogBackendEvent, BackendError> {
    let mut input = CanonicalDecoder::new(bytes, MAX_EVENT_BYTES)?;
    let monotonic_ms = input.u64()?;
    let nonce_sha256 = input.digest()?;
    let meaning = input.u8()?;
    let tag = input.u8()?;
    let event = match tag {
        1 if meaning == ReceiptMeaning::ModelTransitionOnly.code() => {
            WatchdogBackendEvent::StartupSafeIdle {
                monotonic_ms,
                nonce_sha256,
            }
        }
        2 if meaning == ReceiptMeaning::IntentOnly.code() => WatchdogBackendEvent::OpenIntent {
            monotonic_ms,
            nonce_sha256,
        },
        3 if meaning == ReceiptMeaning::ClaimedDeskFactUnproven.code() => {
            WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
                monotonic_ms,
                nonce_sha256,
                open_evidence_sha256: input.digest()?,
                opened_identity: decode_opened_identity(input.bytes(512)?)?,
            }
        }
        4 if meaning == ReceiptMeaning::ClaimedDeskFactUnproven.code() => {
            WatchdogBackendEvent::TimeoutClaimedUnproven {
                monotonic_ms,
                nonce_sha256,
                timeout_evidence_sha256: input.digest()?,
                opened_identity_sha256: input.digest()?,
                requested_timeout_seconds: input.u32()?,
                set_timeout_returned_seconds: input.u32()?,
                get_timeout_readback_seconds: input.u32()?,
                support_identity_sha256: input.digest()?,
                support_options: input.u32()?,
                nowayout_observed: decode_bool(input.u8()?)?,
                unexpected_close_outcome: decode_unexpected_close_outcome(input.u8()?)?,
                close_qualification_receipt_sha256: input.digest()?,
            }
        }
        5 if meaning == ReceiptMeaning::ModelTransitionOnly.code() => {
            WatchdogBackendEvent::LeaseModeled {
                monotonic_ms,
                nonce_sha256,
                lease_sequence: input.u64()?,
                custody_iteration: input.u64()?,
                w4_state: decode_w4_state(input.u8()?)?,
                w4_model_source_sha256: input.digest()?,
                w4_policy_sha256: input.digest()?,
                w4_identity_sha256: input.digest()?,
                w4_lease_fence_sha256: input.digest()?,
                w4_receipt_sha256: input.digest()?,
                opened_identity_sha256: input.digest()?,
            }
        }
        6 if meaning == ReceiptMeaning::RequestedFailSafeEffectUnknown.code() => {
            WatchdogBackendEvent::FaultLatched {
                monotonic_ms,
                nonce_sha256,
                fault: decode_fault(input.u8()?)?,
                rejected_evidence_sha256: input.digest()?,
            }
        }
        7 if meaning == ReceiptMeaning::RequestedFailSafeEffectUnknown.code() => {
            WatchdogBackendEvent::CrashObserved {
                monotonic_ms,
                nonce_sha256,
            }
        }
        _ => return Err(malformed_receipt()),
    };
    input.finish()?;
    if encode_event(event) != bytes {
        return Err(malformed_receipt());
    }
    Ok(event)
}

pub fn decode_canonical_receipt(bytes: &[u8]) -> Result<WatchdogCustodyReceipt, BackendError> {
    let mut input = CanonicalDecoder::new(bytes, NANO3_WATCHDOG_MAX_CANONICAL_RECORD_BYTES)?;
    input.expect(RECEIPT_SCHEMA_DOMAIN)?;
    let sequence = input.u64()?;
    let previous_record_sha256 = input.digest()?;
    let identity = decode_backend_identity(input.bytes(MAX_IDENTITY_BYTES)?)?;
    let identity_sha256 = input.digest()?;
    let signer_identity = decode_signer_identity(&mut input)?;
    let state_before = decode_state(input.u8()?)?;
    let state_after = decode_state(input.u8()?)?;
    let event = decode_event(input.bytes(MAX_EVENT_BYTES)?)?;
    let verified_at_monotonic_ms = input.u64()?;
    let event_sha256 = input.digest()?;
    let signature: ReceiptSignature = input
        .bytes(64)?
        .try_into()
        .map_err(|_| malformed_receipt())?;
    let record_sha256 = input.digest()?;
    input.finish()?;
    let receipt = WatchdogCustodyReceipt {
        sequence,
        previous_record_sha256,
        identity,
        identity_sha256,
        signer_identity,
        state_before,
        state_after,
        event,
        verified_at_monotonic_ms,
        event_sha256,
        signature,
        record_sha256,
    };
    if receipt.canonical_storage_bytes() != bytes {
        return Err(malformed_receipt());
    }
    Ok(receipt)
}

pub fn decode_canonical_head(bytes: &[u8]) -> Result<ReceiptChainHead, BackendError> {
    let mut input = CanonicalDecoder::new(bytes, NANO3_WATCHDOG_MAX_CANONICAL_HEAD_BYTES)?;
    input.expect(RECEIPT_SCHEMA_DOMAIN)?;
    let head = ReceiptChainHead {
        receipt_count: input.u64()?,
        record_sha256: input.digest()?,
        identity_sha256: input.digest()?,
        signer_identity: decode_signer_identity(&mut input)?,
        signature: input
            .bytes(64)?
            .try_into()
            .map_err(|_| malformed_receipt())?,
    };
    input.finish()?;
    if head.canonical_storage_bytes() != bytes {
        return Err(malformed_receipt());
    }
    Ok(head)
}

pub fn verify_persisted_receipt_chain<A: ReceiptAuthenticator>(
    record_bytes: &[Vec<u8>],
    head_bytes: &[u8],
    authenticator: &A,
) -> Result<Vec<WatchdogCustodyReceipt>, BackendError> {
    let receipts = record_bytes
        .iter()
        .map(|bytes| decode_canonical_receipt(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let head = decode_canonical_head(head_bytes)?;
    verify_receipt_chain(&receipts, &head, authenticator)?;
    Ok(receipts)
}

pub fn assess_restart_from_persisted<A: ReceiptAuthenticator>(
    prior_identity: &WatchdogBackendIdentity,
    record_bytes: &[Vec<u8>],
    head_bytes: &[u8],
    authenticator: &A,
    proposed_identity: &WatchdogBackendIdentity,
) -> Result<RestartAssessment, BackendError> {
    let receipts = verify_persisted_receipt_chain(record_bytes, head_bytes, authenticator)?;
    let head = decode_canonical_head(head_bytes)?;
    assess_restart(
        prior_identity,
        &receipts,
        &head,
        authenticator,
        proposed_identity,
    )
}

fn decode_signer_identity(
    input: &mut CanonicalDecoder<'_>,
) -> Result<ReceiptSignerIdentity, BackendError> {
    let signer = ReceiptSignerIdentity {
        purpose: input.string()?,
        key_identity_sha256: input.digest()?,
        key_epoch: input.u64()?,
        class: match input.u8()? {
            1 => ReceiptSignerClass::FixtureOnly,
            _ => return Err(malformed_receipt()),
        },
    };
    signer.validate()?;
    Ok(signer)
}

fn decode_state(value: u8) -> Result<BackendReceiptState, BackendError> {
    match value {
        0 => Ok(BackendReceiptState::Uninitialized),
        1 => Ok(BackendReceiptState::StartupSafeIdle),
        2 => Ok(BackendReceiptState::OpenIntentRecorded),
        3 => Ok(BackendReceiptState::ExclusiveOpenClaimedUnproven),
        4 => Ok(BackendReceiptState::TimeoutClaimedUnproven),
        5 => Ok(BackendReceiptState::LeaseModeled),
        6 => Ok(BackendReceiptState::Faulted),
        7 => Ok(BackendReceiptState::DurabilityAmbiguous),
        _ => Err(malformed_receipt()),
    }
}

fn decode_fault(value: u8) -> Result<BackendFault, BackendError> {
    match value {
        1 => Ok(BackendFault::IdentityMismatch),
        2 => Ok(BackendFault::ForkOrRestartDetected),
        3 => Ok(BackendFault::StaleOrFutureMonotonicEvidence),
        4 => Ok(BackendFault::ReplayOrDuplicate),
        5 => Ok(BackendFault::InvalidTransition),
        6 => Ok(BackendFault::LeaseFenceMismatch),
        7 => Ok(BackendFault::W4LeaseNotHeld),
        8 => Ok(BackendFault::CrashObserved),
        9 => Ok(BackendFault::SinkAppendFailed),
        10 => Ok(BackendFault::SinkContractMismatch),
        11 => Ok(BackendFault::ReceiptAuthenticationFailed),
        12 => Ok(BackendFault::ReceiptChainInvalid),
        13 => Ok(BackendFault::RestartFenceRejected),
        _ => Err(malformed_receipt()),
    }
}

fn decode_w4_state(value: u8) -> Result<WatchdogCustodyState, BackendError> {
    match value {
        1 => Ok(WatchdogCustodyState::AwaitingIndependentBridge),
        2 => Ok(WatchdogCustodyState::AwaitingStockQuiescence),
        3 => Ok(WatchdogCustodyState::AwaitingReplacementCustody),
        4 => Ok(WatchdogCustodyState::AwaitingStockRelease),
        5 => Ok(WatchdogCustodyState::AwaitingExclusiveOpen),
        6 => Ok(WatchdogCustodyState::AwaitingTimeoutReadback),
        7 => Ok(WatchdogCustodyState::AwaitingFirstLease),
        8 => Ok(WatchdogCustodyState::Held),
        9 => Ok(WatchdogCustodyState::Faulted),
        _ => Err(malformed_receipt()),
    }
}

fn decode_unexpected_close_outcome(value: u8) -> Result<UnexpectedCloseOutcome, BackendError> {
    match value {
        1 => Ok(UnexpectedCloseOutcome::ResetRemainsArmed),
        2 => Ok(UnexpectedCloseOutcome::WatchdogDisarmed),
        3 => Ok(UnexpectedCloseOutcome::Unknown),
        _ => Err(malformed_receipt()),
    }
}

fn decode_bool(value: u8) -> Result<bool, BackendError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(malformed_receipt()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone)]
    struct FixtureAuthenticator {
        identity: ReceiptSignerIdentity,
        secret: Sha256Digest,
    }

    impl ReceiptAuthenticator for FixtureAuthenticator {
        fn identity(&self) -> ReceiptSignerIdentity {
            self.identity.clone()
        }

        fn sign_fixture(&self, message: &[u8]) -> Result<ReceiptSignature, BackendError> {
            let mut first = Vec::from(self.secret);
            first.extend_from_slice(message);
            let first = hash_bytes(&first);
            let mut second = Vec::from(message);
            second.extend_from_slice(&self.secret);
            let second = hash_bytes(&second);
            let mut signature = [0; 64];
            signature[..32].copy_from_slice(&first);
            signature[32..].copy_from_slice(&second);
            Ok(signature)
        }

        fn verify_fixture(&self, message: &[u8], signature: &ReceiptSignature) -> bool {
            self.sign_fixture(message)
                .is_ok_and(|expected| expected == *signature)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SinkMode {
        GoodFixture,
        Fail(ReceiptSinkFailure),
        WrongHead,
        MissingFileSync,
    }

    #[derive(Debug, Default)]
    struct SharedSinkState {
        sequence: u64,
        head: Sha256Digest,
        writes: Vec<Vec<u8>>,
    }

    #[derive(Clone)]
    struct FixtureSink {
        state: Rc<RefCell<SharedSinkState>>,
        mode: SinkMode,
    }

    impl FixtureSink {
        fn new(mode: SinkMode) -> Self {
            Self {
                state: Rc::new(RefCell::new(SharedSinkState::default())),
                mode,
            }
        }

        fn forked(mode: SinkMode, state: Rc<RefCell<SharedSinkState>>) -> Self {
            Self { state, mode }
        }
    }

    impl ReceiptSink for FixtureSink {
        fn append_no_overwrite_and_sync(
            &mut self,
            request: ReceiptWriteRequest<'_>,
        ) -> Result<ReceiptSinkAck, ReceiptSinkFailure> {
            if let SinkMode::Fail(error) = self.mode {
                return Err(error);
            }
            let mut state = self.state.borrow_mut();
            if request.sequence != state.sequence + 1
                || request.expected_previous_record_sha256 != state.head
            {
                return Err(ReceiptSinkFailure::HeadChanged);
            }
            state.sequence = request.sequence;
            state.head = request.record_sha256;
            state.writes.push(request.canonical_record_bytes.to_vec());
            Ok(ReceiptSinkAck {
                sequence: request.sequence,
                previous_record_sha256: if self.mode == SinkMode::WrongHead {
                    [0x99; 32]
                } else {
                    request.expected_previous_record_sha256
                },
                record_sha256: request.record_sha256,
                exclusive_append_step_exercised: true,
                full_write_step_exercised: true,
                file_sync_step_exercised: self.mode != SinkMode::MissingFileSync,
                parent_sync_step_exercised: true,
                owner_only_step_exercised: true,
                no_alias_step_exercised: true,
            })
        }
    }

    #[derive(Default)]
    struct FakeSystemCallCounter {
        path_resolution: u64,
        process_inspection: u64,
        stat: u64,
        open: u64,
        ioctl: u64,
        write: u64,
        close: u64,
        task_spawn: u64,
    }

    fn digest(byte: u8) -> Sha256Digest {
        [byte; 32]
    }

    fn identity() -> WatchdogBackendIdentity {
        WatchdogBackendIdentity {
            unit_fingerprint_sha256: digest(1),
            session_id_sha256: digest(2),
            session_nonce_sha256: digest(3),
            boot_id_sha256: digest(4),
            monotonic_clock_domain_sha256: digest(5),
            kernel_build_sha256: digest(6),
            kernel_config_sha256: digest(7),
            policy_sha256: digest(8),
            backend_source_sha256: digest(9),
            receipt_schema_source_sha256: digest(10),
            process_id: 700,
            parent_process_id: 1,
            process_start_ticks: 55_000,
            keeper_thread_id: 701,
            executable_sha256: digest(11),
            executable_device: 9,
            executable_inode: 99,
            executable_size: 1_000_000,
            executable_link_count: 1,
            watchdog_device_path: NANO3_WATCHDOG_DEVICE.to_owned(),
            owner_epoch: 3,
            fencing_token_sha256: digest(17),
            maximum_receipt_observation_age_ms: 250,
            source: BackendEvidenceSource::DeskFixtureOnly,
        }
    }

    fn opened_identity() -> OpenedWatchdogIdentity {
        OpenedWatchdogIdentity {
            watchdog_fd: 8,
            watchdog_open_description_sha256: digest(12),
            watchdog_device_major: 10,
            watchdog_device_minor: 130,
            sysfs_device_identity_sha256: digest(13),
            driver_identity_sha256: digest(14),
            driver_module_sha256: digest(15),
            device_tree_identity_sha256: digest(16),
            opened_read_write: true,
            opened_no_follow: true,
            opened_close_on_exec: true,
            exactly_one_keeper: true,
        }
    }

    fn signer() -> FixtureAuthenticator {
        FixtureAuthenticator {
            identity: ReceiptSignerIdentity {
                purpose: "nano3-watchdog-custody-receipt".to_owned(),
                key_identity_sha256: digest(21),
                key_epoch: 1,
                class: ReceiptSignerClass::FixtureOnly,
            },
            secret: digest(22),
        }
    }

    fn separation() -> AuthorityKeySeparation {
        AuthorityKeySeparation {
            receipt_key_sha256: digest(21),
            authorization_a_key_sha256: digest(23),
            operator_key_sha256: digest(24),
            physical_observer_key_sha256: digest(25),
        }
    }

    fn qualification() -> WatchdogBackendQualification {
        WatchdogBackendQualification::validate_desk_only(
            identity(),
            signer().identity(),
            separation(),
        )
        .unwrap()
    }

    fn journal() -> WatchdogCustodyJournal<FixtureAuthenticator, FixtureSink> {
        WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            FixtureSink::new(SinkMode::GoodFixture),
            1_000,
            1_005,
            digest(31),
        )
        .unwrap()
    }

    fn open_claim(monotonic_ms: u64, nonce: u8) -> WatchdogBackendEvent {
        WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
            monotonic_ms,
            nonce_sha256: digest(nonce),
            open_evidence_sha256: digest(80),
            opened_identity: opened_identity(),
        }
    }

    fn timeout_claim(monotonic_ms: u64, nonce: u8) -> WatchdogBackendEvent {
        WatchdogBackendEvent::TimeoutClaimedUnproven {
            monotonic_ms,
            nonce_sha256: digest(nonce),
            timeout_evidence_sha256: digest(81),
            opened_identity_sha256: opened_identity().digest(),
            requested_timeout_seconds: 89,
            set_timeout_returned_seconds: 89,
            get_timeout_readback_seconds: 89,
            support_identity_sha256: digest(82),
            support_options: 0x8180,
            nowayout_observed: true,
            unexpected_close_outcome: UnexpectedCloseOutcome::ResetRemainsArmed,
            close_qualification_receipt_sha256: digest(83),
        }
    }

    fn lease_claim(
        monotonic_ms: u64,
        nonce: u8,
        state: WatchdogCustodyState,
    ) -> WatchdogBackendEvent {
        WatchdogBackendEvent::LeaseModeled {
            monotonic_ms,
            nonce_sha256: digest(nonce),
            lease_sequence: 1,
            custody_iteration: 8,
            w4_state: state,
            w4_model_source_sha256: NANO3_WATCHDOG_W4_MODEL_SOURCE_SHA256,
            w4_policy_sha256: digest(84),
            w4_identity_sha256: digest(85),
            w4_lease_fence_sha256: digest(86),
            w4_receipt_sha256: digest(87),
            opened_identity_sha256: opened_identity().digest(),
        }
    }

    fn append_through_lease(
        journal: &mut WatchdogCustodyJournal<FixtureAuthenticator, FixtureSink>,
    ) {
        let id = identity();
        journal
            .append_fixture_event(
                &id,
                WatchdogBackendEvent::OpenIntent {
                    monotonic_ms: 1_010,
                    nonce_sha256: digest(32),
                },
                1_015,
            )
            .unwrap();
        journal
            .append_fixture_event(&id, open_claim(1_020, 33), 1_025)
            .unwrap();
        journal
            .append_fixture_event(&id, timeout_claim(1_030, 34), 1_035)
            .unwrap();
        journal
            .append_fixture_event(
                &id,
                lease_claim(1_040, 35, WatchdogCustodyState::Held),
                1_045,
            )
            .unwrap();
    }

    #[test]
    fn disabled_build_has_zero_system_calls_and_no_authority_surface() {
        let calls = FakeSystemCallCounter::default();
        let qualification = qualification();
        assert!(!std::hint::black_box(NANO3_WATCHDOG_SYSTEM_BACKEND_ENABLED));
        assert!(!std::hint::black_box(NANO3_WATCHDOG_BACKEND_LIVE_QUALIFIED));
        assert!(!std::hint::black_box(
            NANO3_WATCHDOG_BACKEND_PRODUCTION_AUTHORIZED
        ));
        assert!(!std::hint::black_box(
            NANO3_WATCHDOG_RECEIPT_MEDIA_DURABILITY_PROVEN
        ));
        assert!(!std::hint::black_box(
            NANO3_WATCHDOG_RECEIPT_GLOBAL_DURABILITY_PROVEN
        ));
        assert_eq!(NANO3_WATCHDOG_PRODUCTION_RECEIPT_KEY_SHA256, None);
        assert!(!qualification.backend_enabled());
        assert!(!qualification.live_effectiveness_proven());
        assert!(!qualification.hardware_provenance_proven());
        assert!(!qualification.production_authorized());
        assert!(!qualification.phase_b_authorized());
        assert!(!qualification.independent_cut_observed());
        assert_eq!(qualification.device_contact(), "none");
        assert_eq!(
            [
                calls.path_resolution,
                calls.process_inspection,
                calls.stat,
                calls.open,
                calls.ioctl,
                calls.write,
                calls.close,
                calls.task_spawn,
            ],
            [0; 8]
        );

        let source = include_str!("nano3_watchdog_backend.rs");
        let main_source = include_str!("main.rs");
        for banned in [
            concat!("std::fs", "::"),
            concat!("Open", "Options"),
            concat!("libc", "::ioctl"),
            concat!("Command", "::new"),
            concat!("std::env", "::var"),
            concat!("tokio::", "spawn"),
            concat!("/dev/watchdog", "0"),
        ] {
            assert!(
                !source.contains(banned),
                "forbidden backend surface: {banned}"
            );
        }
        assert_eq!(
            main_source
                .matches("pub mod nano3_watchdog_backend;")
                .count(),
            1
        );
        assert!(!main_source.contains("WatchdogBackendQualification::"));
        assert!(!main_source.contains("WatchdogCustodyJournal::"));
    }

    #[test]
    fn exact_identity_and_role_separation_are_load_bearing() {
        let mutations: &[fn(&mut WatchdogBackendIdentity)] = &[
            |value| value.unit_fingerprint_sha256 = [0; 32],
            |value| value.session_id_sha256 = [0; 32],
            |value| value.boot_id_sha256 = [0; 32],
            |value| value.process_start_ticks = 0,
            |value| value.executable_link_count = 2,
            |value| value.watchdog_device_path = format!("{}{}", NANO3_WATCHDOG_DEVICE, 0),
            |value| value.owner_epoch = 0,
            |value| value.maximum_receipt_observation_age_ms = 0,
        ];
        for mutate in mutations {
            let mut value = identity();
            mutate(&mut value);
            assert!(WatchdogBackendQualification::validate_desk_only(
                value,
                signer().identity(),
                separation()
            )
            .is_err());
        }

        let mut collapsed = separation();
        collapsed.receipt_key_sha256 = collapsed.operator_key_sha256;
        assert!(WatchdogBackendQualification::validate_desk_only(
            identity(),
            signer().identity(),
            collapsed
        )
        .is_err());

        let open_mutations: &[fn(&mut OpenedWatchdogIdentity)] = &[
            |value| value.watchdog_fd = 0,
            |value| value.watchdog_open_description_sha256 = [0; 32],
            |value| value.driver_identity_sha256 = [0; 32],
            |value| value.opened_read_write = false,
            |value| value.opened_no_follow = false,
            |value| value.opened_close_on_exec = false,
            |value| value.exactly_one_keeper = false,
        ];
        for mutate in open_mutations {
            let mut value = opened_identity();
            mutate(&mut value);
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn ordered_fixture_chain_is_authenticated_but_never_durable_or_live() {
        let mut journal = journal();
        append_through_lease(&mut journal);
        assert_eq!(journal.state(), BackendReceiptState::LeaseModeled);
        assert!(!journal.may_contact_device());
        assert!(!journal.may_pet_watchdog());
        assert!(!journal.may_resume_after_restart());
        assert_eq!(
            journal.durability_claims(),
            ReceiptDurabilityClaims::none_proven()
        );
        assert_eq!(journal.receipts().len(), 5);
        assert_eq!(journal.sink().state.borrow().writes.len(), 5);
        let head = journal.head().unwrap();
        verify_receipt_chain(journal.receipts(), &head, &signer()).unwrap();
        for receipt in journal.receipts() {
            assert!(!receipt.backend_enabled());
            assert!(!receipt.physical_effect_observed());
            assert!(!receipt.independent_cut_observed());
        }
    }

    #[test]
    fn forged_reordered_duplicate_truncated_extended_and_cross_signed_chains_fail() {
        let mut journal = journal();
        append_through_lease(&mut journal);
        let receipts = journal.receipts().to_vec();
        let head = journal.head().unwrap();

        let mut forged = receipts.clone();
        forged[2].event_sha256[0] ^= 1;
        assert!(verify_receipt_chain(&forged, &head, &signer()).is_err());

        let mut reordered = receipts.clone();
        reordered.swap(1, 2);
        assert!(verify_receipt_chain(&reordered, &head, &signer()).is_err());

        let mut duplicate = receipts.clone();
        duplicate[3] = duplicate[2].clone();
        assert!(verify_receipt_chain(&duplicate, &head, &signer()).is_err());

        assert!(verify_receipt_chain(&receipts[..4], &head, &signer()).is_err());
        let mut extended = receipts.clone();
        extended.push(receipts[4].clone());
        assert!(verify_receipt_chain(&extended, &head, &signer()).is_err());

        let other_signer = FixtureAuthenticator {
            identity: ReceiptSignerIdentity {
                key_identity_sha256: digest(99),
                ..signer().identity()
            },
            secret: digest(98),
        };
        assert!(verify_receipt_chain(&receipts, &head, &other_signer).is_err());

        let mut identity_tampered = receipts.clone();
        identity_tampered[2].identity.policy_sha256[0] ^= 1;
        assert!(verify_receipt_chain(&identity_tampered, &head, &signer()).is_err());
    }

    #[test]
    fn persisted_bytes_round_trip_and_malformed_storage_fail_closed() {
        let mut journal = journal();
        append_through_lease(&mut journal);
        let head = journal.head().unwrap();
        let head_bytes = head.canonical_storage_bytes();
        let records = journal.sink().state.borrow().writes.clone();
        let decoded = verify_persisted_receipt_chain(&records, &head_bytes, &signer()).unwrap();
        assert_eq!(decoded, journal.receipts());
        assert_eq!(decoded[0].identity_manifest(), &identity());
        assert!(!head.external_custody_proven());
        assert!(!std::hint::black_box(
            NANO3_WATCHDOG_EXTERNAL_HEAD_CUSTODY_PROVEN
        ));

        let mut truncated = records.clone();
        truncated[1].pop();
        assert!(verify_persisted_receipt_chain(&truncated, &head_bytes, &signer()).is_err());

        let mut trailing = records.clone();
        trailing[1].push(0);
        assert!(verify_persisted_receipt_chain(&trailing, &head_bytes, &signer()).is_err());

        let mut malformed_length = records[0].clone();
        let identity_length_offset = RECEIPT_SCHEMA_DOMAIN.len() + 8 + 32;
        malformed_length[identity_length_offset..identity_length_offset + 8].fill(0xff);
        assert!(decode_canonical_receipt(&malformed_length).is_err());

        let oversized = vec![0; NANO3_WATCHDOG_MAX_CANONICAL_RECORD_BYTES + 1];
        assert!(decode_canonical_receipt(&oversized).is_err());

        let mut malformed_head = head_bytes.clone();
        malformed_head.push(0);
        assert!(decode_canonical_head(&malformed_head).is_err());

        let mut event_bytes = encode_event(open_claim(1_020, 90));
        event_bytes[8 + 32 + 1] = 0xff;
        assert!(decode_event(&event_bytes).is_err());
    }

    #[test]
    fn future_and_expired_observations_are_terminal() {
        assert!(WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            FixtureSink::new(SinkMode::GoodFixture),
            1_000,
            1_005,
            [0; 32],
        )
        .is_err());
        assert!(WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            FixtureSink::new(SinkMode::GoodFixture),
            1_000,
            999,
            digest(90),
        )
        .is_err());
        assert!(WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            FixtureSink::new(SinkMode::GoodFixture),
            1_000,
            1_251,
            digest(91),
        )
        .is_err());

        for verified_at in [1_009, 1_261] {
            let mut journal = journal();
            assert!(journal
                .append_fixture_event(
                    &identity(),
                    WatchdogBackendEvent::OpenIntent {
                        monotonic_ms: 1_010,
                        nonce_sha256: digest(92),
                    },
                    verified_at,
                )
                .is_err());
            assert_eq!(journal.state(), BackendReceiptState::Faulted);
            assert!(!journal.may_pet_watchdog());
        }
    }

    #[test]
    fn caller_claim_details_and_exact_w4_bindings_are_load_bearing() {
        let id = identity();

        let mut missing_open = journal();
        missing_open
            .append_fixture_event(
                &id,
                WatchdogBackendEvent::OpenIntent {
                    monotonic_ms: 1_010,
                    nonce_sha256: digest(93),
                },
                1_015,
            )
            .unwrap();
        let mut invalid_open = open_claim(1_020, 94);
        if let WatchdogBackendEvent::ExclusiveOpenClaimedUnproven {
            open_evidence_sha256,
            ..
        } = &mut invalid_open
        {
            *open_evidence_sha256 = [0; 32];
        }
        assert!(missing_open
            .append_fixture_event(&id, invalid_open, 1_025)
            .is_err());

        let timeout_mutations: &[fn(&mut WatchdogBackendEvent)] = &[
            |event| {
                if let WatchdogBackendEvent::TimeoutClaimedUnproven {
                    opened_identity_sha256,
                    ..
                } = event
                {
                    *opened_identity_sha256 = digest(79);
                }
            },
            |event| {
                if let WatchdogBackendEvent::TimeoutClaimedUnproven {
                    timeout_evidence_sha256,
                    ..
                } = event
                {
                    *timeout_evidence_sha256 = [0; 32];
                }
            },
            |event| {
                if let WatchdogBackendEvent::TimeoutClaimedUnproven {
                    get_timeout_readback_seconds,
                    ..
                } = event
                {
                    *get_timeout_readback_seconds = 88;
                }
            },
            |event| {
                if let WatchdogBackendEvent::TimeoutClaimedUnproven {
                    support_options, ..
                } = event
                {
                    *support_options = 0;
                }
            },
            |event| {
                if let WatchdogBackendEvent::TimeoutClaimedUnproven {
                    nowayout_observed, ..
                } = event
                {
                    *nowayout_observed = false;
                }
            },
            |event| {
                if let WatchdogBackendEvent::TimeoutClaimedUnproven {
                    unexpected_close_outcome,
                    ..
                } = event
                {
                    *unexpected_close_outcome = UnexpectedCloseOutcome::Unknown;
                }
            },
        ];
        for mutate in timeout_mutations {
            let mut journal = journal();
            journal
                .append_fixture_event(
                    &id,
                    WatchdogBackendEvent::OpenIntent {
                        monotonic_ms: 1_010,
                        nonce_sha256: digest(95),
                    },
                    1_015,
                )
                .unwrap();
            journal
                .append_fixture_event(&id, open_claim(1_020, 96), 1_025)
                .unwrap();
            let mut claim = timeout_claim(1_030, 97);
            mutate(&mut claim);
            assert!(journal.append_fixture_event(&id, claim, 1_035).is_err());
            assert!(!journal.may_pet_watchdog());
        }

        let lease_mutations: &[fn(&mut WatchdogBackendEvent)] = &[
            |event| {
                if let WatchdogBackendEvent::LeaseModeled {
                    opened_identity_sha256,
                    ..
                } = event
                {
                    *opened_identity_sha256 = digest(79);
                }
            },
            |event| {
                if let WatchdogBackendEvent::LeaseModeled {
                    w4_model_source_sha256,
                    ..
                } = event
                {
                    *w4_model_source_sha256 = digest(98);
                }
            },
            |event| {
                if let WatchdogBackendEvent::LeaseModeled {
                    w4_policy_sha256, ..
                } = event
                {
                    *w4_policy_sha256 = [0; 32];
                }
            },
            |event| {
                if let WatchdogBackendEvent::LeaseModeled {
                    w4_identity_sha256, ..
                } = event
                {
                    *w4_identity_sha256 = [0; 32];
                }
            },
            |event| {
                if let WatchdogBackendEvent::LeaseModeled {
                    w4_lease_fence_sha256,
                    ..
                } = event
                {
                    *w4_lease_fence_sha256 = [0; 32];
                }
            },
            |event| {
                if let WatchdogBackendEvent::LeaseModeled {
                    w4_receipt_sha256, ..
                } = event
                {
                    *w4_receipt_sha256 = [0; 32];
                }
            },
        ];
        for mutate in lease_mutations {
            let mut journal = journal();
            journal
                .append_fixture_event(
                    &id,
                    WatchdogBackendEvent::OpenIntent {
                        monotonic_ms: 1_010,
                        nonce_sha256: digest(99),
                    },
                    1_015,
                )
                .unwrap();
            journal
                .append_fixture_event(&id, open_claim(1_020, 100), 1_025)
                .unwrap();
            journal
                .append_fixture_event(&id, timeout_claim(1_030, 101), 1_035)
                .unwrap();
            let mut claim = lease_claim(1_040, 102, WatchdogCustodyState::Held);
            mutate(&mut claim);
            assert!(journal.append_fixture_event(&id, claim, 1_045).is_err());
            assert_eq!(journal.state(), BackendReceiptState::Faulted);
        }
    }

    #[test]
    fn pre_intent_receipts_cannot_contain_open_or_fd_claims() {
        let mut custody = journal();
        let opened_bytes = encode_opened_identity(opened_identity());
        let startup = &custody.receipts()[0];
        assert!(matches!(
            startup.event(),
            WatchdogBackendEvent::StartupSafeIdle { .. }
        ));
        assert!(!startup
            .canonical_storage_bytes()
            .windows(opened_bytes.len())
            .any(|window| window == opened_bytes));

        custody
            .append_fixture_event(
                &identity(),
                WatchdogBackendEvent::OpenIntent {
                    monotonic_ms: 1_010,
                    nonce_sha256: digest(103),
                },
                1_015,
            )
            .unwrap();
        assert!(matches!(
            custody.receipts()[1].event(),
            WatchdogBackendEvent::OpenIntent { .. }
        ));
        assert!(!custody.receipts()[1]
            .canonical_storage_bytes()
            .windows(opened_bytes.len())
            .any(|window| window == opened_bytes));

        let mut out_of_order = journal();
        assert!(out_of_order
            .append_fixture_event(&identity(), open_claim(1_010, 104), 1_015)
            .is_err());
        assert_eq!(out_of_order.state(), BackendReceiptState::Faulted);
    }

    #[test]
    fn locally_signed_alternate_heads_never_promote_custody_or_durability() {
        let first = journal();
        let second = WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            FixtureSink::new(SinkMode::GoodFixture),
            1_000,
            1_005,
            digest(105),
        )
        .unwrap();
        let first_head = first.head().unwrap();
        let second_head = second.head().unwrap();
        assert_ne!(first_head.record_sha256, second_head.record_sha256);
        verify_receipt_chain(first.receipts(), &first_head, &signer()).unwrap();
        verify_receipt_chain(second.receipts(), &second_head, &signer()).unwrap();
        for journal in [&first, &second] {
            assert!(!journal.may_contact_device());
            assert!(!journal.may_pet_watchdog());
            assert!(!journal.may_resume_after_restart());
            assert_eq!(
                journal.durability_claims(),
                ReceiptDurabilityClaims::none_proven()
            );
        }
        assert!(!first_head.external_custody_proven());
        assert!(!second_head.external_custody_proven());
    }

    #[test]
    fn stale_replay_out_of_order_and_wrong_w4_state_are_terminal() {
        let failures = [
            WatchdogBackendEvent::OpenIntent {
                monotonic_ms: 999,
                nonce_sha256: digest(40),
            },
            WatchdogBackendEvent::OpenIntent {
                monotonic_ms: 1_010,
                nonce_sha256: digest(31),
            },
            open_claim(1_010, 41),
        ];
        for event in failures {
            let mut journal = journal();
            assert!(journal
                .append_fixture_event(&identity(), event, 1_015)
                .is_err());
            assert_eq!(journal.state(), BackendReceiptState::Faulted);
            assert!(journal
                .append_fixture_event(
                    &identity(),
                    WatchdogBackendEvent::OpenIntent {
                        monotonic_ms: 2_000,
                        nonce_sha256: digest(42),
                    },
                    2_005,
                )
                .is_err());
        }

        let mut journal = journal();
        let id = identity();
        for event in [
            WatchdogBackendEvent::OpenIntent {
                monotonic_ms: 1_010,
                nonce_sha256: digest(43),
            },
            open_claim(1_020, 44),
            timeout_claim(1_030, 45),
        ] {
            journal
                .append_fixture_event(&id, event, event.monotonic_ms() + 5)
                .unwrap();
        }
        assert!(journal
            .append_fixture_event(
                &id,
                lease_claim(1_040, 46, WatchdogCustodyState::Faulted),
                1_045,
            )
            .is_err());
        assert_eq!(journal.state(), BackendReceiptState::Faulted);
    }

    #[test]
    fn fork_process_restart_and_identity_substitution_are_terminal() {
        for mutate in [
            |value: &mut WatchdogBackendIdentity| value.process_id += 1,
            |value: &mut WatchdogBackendIdentity| value.process_start_ticks += 1,
            |value: &mut WatchdogBackendIdentity| value.keeper_thread_id += 1,
            |value: &mut WatchdogBackendIdentity| value.executable_sha256[0] ^= 1,
            |value: &mut WatchdogBackendIdentity| value.policy_sha256[0] ^= 1,
            |value: &mut WatchdogBackendIdentity| value.watchdog_device_path.push('0'),
            |value: &mut WatchdogBackendIdentity| value.session_id_sha256[0] ^= 1,
        ] {
            let mut journal = journal();
            let mut observed = identity();
            mutate(&mut observed);
            assert!(journal
                .append_fixture_event(
                    &observed,
                    WatchdogBackendEvent::OpenIntent {
                        monotonic_ms: 1_010,
                        nonce_sha256: digest(50),
                    },
                    1_015,
                )
                .is_err());
            assert_eq!(journal.state(), BackendReceiptState::Faulted);
        }
    }

    #[test]
    fn sink_failures_and_forked_heads_are_terminally_ambiguous() {
        for mode in [
            SinkMode::Fail(ReceiptSinkFailure::ShortWrite),
            SinkMode::Fail(ReceiptSinkFailure::FileSyncFailed),
            SinkMode::Fail(ReceiptSinkFailure::ParentSyncFailed),
            SinkMode::WrongHead,
            SinkMode::MissingFileSync,
        ] {
            let mut journal = WatchdogCustodyJournal::start_fixture_only(
                qualification(),
                signer(),
                FixtureSink::new(SinkMode::GoodFixture),
                1_000,
                1_005,
                digest(61),
            )
            .unwrap();
            journal.sink.mode = mode;
            assert!(journal
                .append_fixture_event(
                    &identity(),
                    WatchdogBackendEvent::OpenIntent {
                        monotonic_ms: 1_010,
                        nonce_sha256: digest(62),
                    },
                    1_015,
                )
                .is_err());
            assert_eq!(journal.state(), BackendReceiptState::DurabilityAmbiguous);
            assert!(!journal.may_pet_watchdog());
        }

        let shared = Rc::new(RefCell::new(SharedSinkState::default()));
        let first = FixtureSink::forked(SinkMode::GoodFixture, Rc::clone(&shared));
        let second = FixtureSink::forked(SinkMode::GoodFixture, shared);
        let _winner = WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            first,
            1_000,
            1_005,
            digest(63),
        )
        .unwrap();
        assert!(WatchdogCustodyJournal::start_fixture_only(
            qualification(),
            signer(),
            second,
            1_000,
            1_005,
            digest(64),
        )
        .is_err());
    }

    #[test]
    fn crash_and_restart_are_never_resumable_even_with_fresh_fences() {
        let mut journal = journal();
        append_through_lease(&mut journal);
        journal
            .append_fixture_event(
                &identity(),
                WatchdogBackendEvent::CrashObserved {
                    monotonic_ms: 1_050,
                    nonce_sha256: digest(70),
                },
                1_055,
            )
            .unwrap();
        assert_eq!(journal.state(), BackendReceiptState::Faulted);
        let head = journal.head().unwrap();

        let mut fresh = identity();
        fresh.session_id_sha256 = digest(71);
        fresh.session_nonce_sha256 = digest(72);
        fresh.boot_id_sha256 = digest(73);
        fresh.process_id += 1;
        fresh.process_start_ticks += 1;
        fresh.owner_epoch += 1;
        fresh.fencing_token_sha256 = digest(74);
        let assessment =
            assess_restart(&identity(), journal.receipts(), &head, &signer(), &fresh).unwrap();
        assert!(assessment.starts_safe_idle_faulted);
        assert!(assessment.full_handoff_required);
        assert!(!assessment.prior_chain_resumable);
        assert!(assessment.prior_open_claim_not_resumable);
        assert_eq!(assessment.device_contact, "none");
        let records = journal.sink().state.borrow().writes.clone();
        let persisted_assessment = assess_restart_from_persisted(
            &identity(),
            &records,
            &head.canonical_storage_bytes(),
            &signer(),
            &fresh,
        )
        .unwrap();
        assert_eq!(persisted_assessment, assessment);

        for mutate in [
            |value: &mut WatchdogBackendIdentity| value.session_id_sha256 = digest(2),
            |value: &mut WatchdogBackendIdentity| value.boot_id_sha256 = digest(4),
            |value: &mut WatchdogBackendIdentity| {
                value.process_id = 700;
                value.process_start_ticks = 55_000;
            },
            |value: &mut WatchdogBackendIdentity| value.owner_epoch = 3,
            |value: &mut WatchdogBackendIdentity| value.fencing_token_sha256 = digest(17),
        ] {
            let mut stale = fresh.clone();
            mutate(&mut stale);
            assert!(
                assess_restart(&identity(), journal.receipts(), &head, &signer(), &stale).is_err()
            );
        }
    }
}
