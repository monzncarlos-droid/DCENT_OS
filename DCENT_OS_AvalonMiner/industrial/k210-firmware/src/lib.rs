#![no_std]
#![forbid(unsafe_code)]
#![doc = "Fail-closed policy core for the DCENT_OS Avalon K210 firmware lane."]
#![doc = "This crate has no hardware I/O and cannot produce mutation authority."]

pub mod bsp;
pub mod safety;

/// Built-in Rust target used to prove that this core remains freestanding.
pub const FREESTANDING_TARGET: &str = "riscv64gc-unknown-none-elf";

/// Ordered production gates shared with the host-side K210 gauntlet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EvidenceGate {
    ExactModelIdentity = 0,
    StockRestore = 1,
    BootPolicy = 2,
    ReplacementFirmware = 3,
    AsicControl = 4,
    ThermalPowerSafety = 5,
    RollbackRecovery = 6,
    BenchMining = 7,
    EnduranceFaults = 8,
    ReleaseAuthority = 9,
}

impl EvidenceGate {
    pub const ALL: [Self; 10] = [
        Self::ExactModelIdentity,
        Self::StockRestore,
        Self::BootPolicy,
        Self::ReplacementFirmware,
        Self::AsicControl,
        Self::ThermalPowerSafety,
        Self::RollbackRecovery,
        Self::BenchMining,
        Self::EnduranceFaults,
        Self::ReleaseAuthority,
    ];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ExactModelIdentity => "exact_model_identity",
            Self::StockRestore => "stock_restore",
            Self::BootPolicy => "boot_policy",
            Self::ReplacementFirmware => "replacement_firmware",
            Self::AsicControl => "asic_control",
            Self::ThermalPowerSafety => "thermal_power_safety",
            Self::RollbackRecovery => "rollback_recovery",
            Self::BenchMining => "bench_mining",
            Self::EnduranceFaults => "endurance_faults",
            Self::ReleaseAuthority => "release_authority",
        }
    }

    const fn bit(self) -> u16 {
        1_u16 << (self as u8)
    }
}

const ALL_GATE_BITS: u16 = (1_u16 << EvidenceGate::ALL.len()) - 1;

/// Census classification. Only an exact physical-model row can reach review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetKind {
    PhysicalModel,
    CandidatePhysicalModel,
    FirmwareFamily,
}

/// A bounded, allocation-free target identity borrowed from trusted storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetIdentity<'a> {
    id: &'a str,
    kind: TargetKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    Empty,
    TooLong,
    InvalidCharacter,
    InvalidFirstCharacter,
}

impl<'a> TargetIdentity<'a> {
    pub const MAX_ID_BYTES: usize = 32;

    pub fn new(id: &'a str, kind: TargetKind) -> Result<Self, IdentityError> {
        let bytes = id.as_bytes();
        if bytes.is_empty() {
            return Err(IdentityError::Empty);
        }
        if bytes.len() > Self::MAX_ID_BYTES {
            return Err(IdentityError::TooLong);
        }
        if !bytes[0].is_ascii_lowercase() {
            return Err(IdentityError::InvalidFirstCharacter);
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(IdentityError::InvalidCharacter);
        }
        Ok(Self { id, kind })
    }

    #[must_use]
    pub const fn id(self) -> &'a str {
        self.id
    }

    #[must_use]
    pub const fn kind(self) -> TargetKind {
        self.kind
    }
}

/// Untrusted evidence bookkeeping.
///
/// Recording a bit never creates device, mutation, mining, or release
/// authority. Authenticity and custody belong to higher-level signed receipts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvidenceLedger {
    bits: u16,
}

impl EvidenceLedger {
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub fn record_for_planning(&mut self, gate: EvidenceGate) {
        self.bits |= gate.bit();
    }

    #[must_use]
    pub const fn contains(self, gate: EvidenceGate) -> bool {
        self.bits & gate.bit() != 0
    }

    #[must_use]
    pub fn first_missing(self) -> Option<EvidenceGate> {
        EvidenceGate::ALL
            .into_iter()
            .find(|gate| !self.contains(*gate))
    }

    #[must_use]
    pub const fn recorded_bits(self) -> u16 {
        self.bits
    }

    #[must_use]
    pub const fn all_recorded(self) -> bool {
        self.bits & ALL_GATE_BITS == ALL_GATE_BITS
    }

    #[must_use]
    pub fn admission(self, target: TargetIdentity<'_>) -> AdmissionDisposition {
        if target.kind() != TargetKind::PhysicalModel {
            return AdmissionDisposition::NeedsExactPhysicalModel;
        }
        match self.first_missing() {
            Some(first_missing) => AdmissionDisposition::Blocked { first_missing },
            None => AdmissionDisposition::IndependentReleaseReviewRequired,
        }
    }
}

/// This core never emits a production-ready disposition by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    NeedsExactPhysicalModel,
    Blocked { first_missing: EvidenceGate },
    IndependentReleaseReviewRequired,
}

/// Recovery-first phases that target-bound firmware must enter in order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimePhase {
    #[default]
    Sealed,
    IdentityBound,
    StockRecoveryBound,
    BootPolicyBound,
    DeskCoreVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseEvent {
    BindExactIdentity,
    BindProvenStockRecovery,
    BindMeasuredBootPolicy,
    VerifyDeskCore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseOrderError {
    pub phase: RuntimePhase,
    pub event: PhaseEvent,
}

impl RuntimePhase {
    pub fn advance(self, event: PhaseEvent) -> Result<Self, PhaseOrderError> {
        match (self, event) {
            (Self::Sealed, PhaseEvent::BindExactIdentity) => Ok(Self::IdentityBound),
            (Self::IdentityBound, PhaseEvent::BindProvenStockRecovery) => {
                Ok(Self::StockRecoveryBound)
            }
            (Self::StockRecoveryBound, PhaseEvent::BindMeasuredBootPolicy) => {
                Ok(Self::BootPolicyBound)
            }
            (Self::BootPolicyBound, PhaseEvent::VerifyDeskCore) => Ok(Self::DeskCoreVerified),
            (phase, event) => Err(PhaseOrderError { phase, event }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOperation {
    ContactNetwork,
    Reboot,
    WriteFlash,
    DriveGpio,
    EnergizeHashRail,
    DriveCooling,
    TransmitAsicWork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    NoTargetBoundHardwareLayer,
}

/// Deliberately has no `Allow` variant. Board code cannot treat this desk core
/// as an actuator or release-authority provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationDisposition {
    Refuse {
        operation: MutationOperation,
        reason: RefusalReason,
    },
}

#[must_use]
pub const fn mutation_disposition(operation: MutationOperation) -> MutationDisposition {
    MutationDisposition::Refuse {
        operation,
        reason: RefusalReason::NoTargetBoundHardwareLayer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn physical() -> TargetIdentity<'static> {
        TargetIdentity::new("a1346", TargetKind::PhysicalModel).unwrap()
    }

    #[test]
    fn gate_ids_match_the_host_manifest_order() {
        assert_eq!(EvidenceGate::ALL.len(), 10);
        assert_eq!(EvidenceGate::ALL[0].id(), "exact_model_identity");
        assert_eq!(EvidenceGate::ALL[9].id(), "release_authority");
    }

    #[test]
    fn empty_ledger_fails_at_identity() {
        assert_eq!(
            EvidenceLedger::empty().admission(physical()),
            AdmissionDisposition::Blocked {
                first_missing: EvidenceGate::ExactModelIdentity
            }
        );
    }

    #[test]
    fn first_missing_is_deterministic_not_recording_order() {
        let mut ledger = EvidenceLedger::empty();
        ledger.record_for_planning(EvidenceGate::BootPolicy);
        ledger.record_for_planning(EvidenceGate::ExactModelIdentity);
        assert_eq!(ledger.first_missing(), Some(EvidenceGate::StockRestore));
    }

    #[test]
    fn family_row_never_reaches_release_review() {
        let mut ledger = EvidenceLedger::empty();
        for gate in EvidenceGate::ALL {
            ledger.record_for_planning(gate);
        }
        let family = TargetIdentity::new("a14xi", TargetKind::FirmwareFamily).unwrap();
        assert_eq!(
            ledger.admission(family),
            AdmissionDisposition::NeedsExactPhysicalModel
        );
    }

    #[test]
    fn complete_planning_bits_still_require_independent_release_review() {
        let mut ledger = EvidenceLedger::empty();
        for gate in EvidenceGate::ALL {
            ledger.record_for_planning(gate);
        }
        assert!(ledger.all_recorded());
        assert_eq!(ledger.recorded_bits(), ALL_GATE_BITS);
        assert_eq!(
            ledger.admission(physical()),
            AdmissionDisposition::IndependentReleaseReviewRequired
        );
    }

    #[test]
    fn target_ids_are_strict_and_bounded() {
        assert_eq!(
            TargetIdentity::new("A1346", TargetKind::PhysicalModel),
            Err(IdentityError::InvalidFirstCharacter)
        );
        assert_eq!(
            TargetIdentity::new("a1346_unsafe", TargetKind::PhysicalModel),
            Err(IdentityError::InvalidCharacter)
        );
    }

    #[test]
    fn phase_machine_refuses_out_of_order_evidence() {
        assert_eq!(
            RuntimePhase::Sealed.advance(PhaseEvent::BindMeasuredBootPolicy),
            Err(PhaseOrderError {
                phase: RuntimePhase::Sealed,
                event: PhaseEvent::BindMeasuredBootPolicy
            })
        );
    }

    #[test]
    fn phase_machine_is_recovery_first() {
        let phase = RuntimePhase::Sealed
            .advance(PhaseEvent::BindExactIdentity)
            .unwrap()
            .advance(PhaseEvent::BindProvenStockRecovery)
            .unwrap()
            .advance(PhaseEvent::BindMeasuredBootPolicy)
            .unwrap()
            .advance(PhaseEvent::VerifyDeskCore)
            .unwrap();
        assert_eq!(phase, RuntimePhase::DeskCoreVerified);
    }

    #[test]
    fn every_mutation_kind_is_unconditionally_refused() {
        let operations = [
            MutationOperation::ContactNetwork,
            MutationOperation::Reboot,
            MutationOperation::WriteFlash,
            MutationOperation::DriveGpio,
            MutationOperation::EnergizeHashRail,
            MutationOperation::DriveCooling,
            MutationOperation::TransmitAsicWork,
        ];
        for operation in operations {
            assert_eq!(
                mutation_disposition(operation),
                MutationDisposition::Refuse {
                    operation,
                    reason: RefusalReason::NoTargetBoundHardwareLayer
                }
            );
        }
    }
}
