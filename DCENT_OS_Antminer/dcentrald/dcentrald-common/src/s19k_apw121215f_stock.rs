//! Exact held-stock S19k Pro APW121215f evidence (pure, no I/O).
//!
//! This module pins facts recovered from the exact `a lab unit` `bosminer.unpacked`.
//! It identifies stock's logical PSU-control output and checksum algorithms,
//! but does not build APW command frames or authorize I2C/GPIO writes. The PSU
//! service's `PSU: Enable` arm locks its driver object, invokes trait slot
//! `+0x20`, and polls the returned future. The exact S19k APW object allocator
//! returns the vtable whose `+0x20` entry is the already-recovered enable
//! constructor. The disable future enqueues message tag `3`; the worker
//! acknowledges that tag without calling either APW backend operation and
//! continues its loop. Only then does stock write logical `1` to the
//! PSU-control output. These are controller-side facts, not independent proof
//! of voltage rise, rail state, or rail collapse.

/// Exact held stock ELF identity used for every address below.
pub const S19K_STOCK_BOSMINER_BYTES: u64 = 23_963_080;
pub const S19K_STOCK_BOSMINER_SHA256: &str =
    "5a49dcbe2e2d9f4fb047eca856e71440bd73fc020a817e808b5af3b45a7c8707";

/// Stock model enum passed by the S19k Pro builder.
pub const S19K_PRO_STOCK_MODEL_ENUM: u8 = 8;
/// Version bytes admitted by the S19k-specific lazy APW profile.
pub const S19K_APW121215F_REPORTED_VERSION_BYTES: [u8; 3] = [0x75, 0x76, 0x77];
/// Profile compatibility discriminator at object offset `+0xe0`.
/// Stock compares this byte between candidate profiles before sharing a PSU.
/// Its precise protocol enum name remains unrecovered; it is not the checksum
/// mode byte consumed by the frame parser.
pub const S19K_APW121215F_PROFILE_DISCRIMINATOR: u8 = 4;
pub const S19K_APW121215F_PROFILE_INIT_FN_VA: u64 = 0x0082_9ED4;
pub const S19K_APW121215F_FACTORY_PTR_VA: u64 = 0x01AC_DDB8;
pub const S19K_APW121215F_FACTORY_FN_VA: u64 = 0x0090_E2B8;
/// Exact allocator selected for the APW implementation object. It returns the
/// allocated object in `x0` and [`S19K_APW121215F_TRAIT_VTABLE_VA`] in `x1`.
pub const S19K_APW121215F_TRAIT_ALLOC_PTR_VA: u64 = 0x01AC_F2C8;
pub const S19K_APW121215F_TRAIT_ALLOC_FN_VA: u64 = 0x0090_DFC0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockApwTraitMethod {
    pub slot: u8,
    pub constructor_va: u64,
    pub poll_va: Option<u64>,
    pub evidence_name: &'static str,
}

/// Trait vtable at VA `0x019c8e78`. The first three qwords are
/// drop/size/alignment (`0x00909928`, `0xf0`, `8`); method slots follow.
pub const S19K_APW121215F_TRAIT_VTABLE_VA: u64 = 0x019C_8E78;
pub const S19K_APW121215F_TRAIT_DROP_VA: u64 = 0x0090_9928;
pub const S19K_APW121215F_TRAIT_OBJECT_SIZE: u64 = 0xF0;
pub const S19K_APW121215F_TRAIT_OBJECT_ALIGN: u64 = 8;
pub const S19K_APW121215F_TRAIT_METHODS: [StockApwTraitMethod; 8] = [
    StockApwTraitMethod {
        slot: 0x18,
        constructor_va: 0x0090_E38C,
        poll_va: Some(0x0090_E410),
        evidence_name: "init",
    },
    StockApwTraitMethod {
        slot: 0x20,
        constructor_va: 0x0090_FCC8,
        poll_va: Some(0x0090_FD70),
        evidence_name: "enable",
    },
    StockApwTraitMethod {
        slot: 0x28,
        constructor_va: 0x0090_FF58,
        poll_va: Some(0x0090_FFA0),
        evidence_name: "disable",
    },
    StockApwTraitMethod {
        slot: 0x30,
        constructor_va: 0x0091_0334,
        poll_va: Some(0x0091_038C),
        evidence_name: "set-voltage",
    },
    StockApwTraitMethod {
        slot: 0x38,
        constructor_va: 0x0091_0758,
        poll_va: Some(0x0091_07A0),
        evidence_name: "read-voltage",
    },
    StockApwTraitMethod {
        slot: 0x40,
        constructor_va: 0x0091_0D20,
        poll_va: Some(0x0091_0D68),
        evidence_name: "heartbeat",
    },
    StockApwTraitMethod {
        slot: 0x48,
        constructor_va: 0x0091_1188,
        poll_va: Some(0x0091_120C),
        evidence_name: "read-power",
    },
    StockApwTraitMethod {
        slot: 0x50,
        constructor_va: 0x0090_7518,
        poll_va: None,
        evidence_name: "shutdown",
    },
];

/// Stock PSU service async state machine containing both references to the
/// retained `PSU: Enable` record and the common enable-dispatch continuation.
pub const BOSMINER_PSU_SERVICE_ASYNC_STATE_MACHINE_FN_VA: u64 = 0x00B8_BE50;
pub const BOSMINER_PSU_ENABLE_LOG_RECORD_VA: u64 = 0x019F_BCA8;
pub const BOSMINER_PSU_ENABLE_LOG_MESSAGE_VA: u64 = 0x0139_0D52;
pub const BOSMINER_PSU_ENABLE_LOG_MESSAGE: &[u8] = b"PSU: Enable";
pub const BOSMINER_PSU_SOURCE_VA: u64 = 0x0139_0BEB;
pub const BOSMINER_PSU_SOURCE: &[u8] = b"open/bosminer/bosminer-backend/src/psu.rs";
pub const BOSMINER_PSU_ENABLE_SOURCE_LINE: u32 = 374;
pub const BOSMINER_PSU_ENABLE_SOURCE_COLUMN: u32 = 42;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockPsuEnableDispatchStep {
    ReferenceEnableLogRecord,
    LockPsuServiceDriver,
    LoadPsuTraitObject,
    InvokePsuTraitSlot(u8),
    PollReturnedFuture,
}

/// Exact software-side enable corridor in `FUN_00b8be50`. Log emission remains
/// subject to the stock tracing filter, while both logging branches converge
/// on the same driver lock and slot-`+0x20` dispatch.
pub const S19K_STOCK_PSU_ENABLE_DISPATCH: [StockPsuEnableDispatchStep; 5] = [
    StockPsuEnableDispatchStep::ReferenceEnableLogRecord,
    StockPsuEnableDispatchStep::LockPsuServiceDriver,
    StockPsuEnableDispatchStep::LoadPsuTraitObject,
    StockPsuEnableDispatchStep::InvokePsuTraitSlot(0x20),
    StockPsuEnableDispatchStep::PollReturnedFuture,
];

/// The exact PSU future and exact hashchain reset future are separately
/// recovered. Their boundary is joined by the frozen repeated runtime trace,
/// not by one statically recovered transaction or direct call edge.
pub fn refuse_stock_psu_enable_and_hashboard_reset_as_one_static_transaction(
) -> Result<(), &'static str> {
    Err("stock PSU enable and hashchain reset are separate exact futures; only the retained runtime trace currently joins their order")
}

/// Completion of the exact software enable corridor cannot attest to voltage
/// rise, board-rail state, or available power.
pub fn refuse_stock_psu_enable_dispatch_as_electrical_rail_proof() -> Result<(), &'static str> {
    Err("stock PSU enable dispatch proves a controller call and logical GPIO write, not voltage rise or physical rail state")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockApwLifecycleStep {
    LockPsuControlOutput,
    AwaitI2cWorkerBarrier,
    RelockPsuControlOutput,
    WritePsuControlOutput(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockApwDisableWorkerStep {
    EnqueueMessageTag(u8),
    AwaitWorkerAcknowledgement,
    AcknowledgeWithoutApwBackendCall,
    ContinueWorkerLoop,
}

/// Successful stock enable writes logical `0` to the PSU-control output.
pub const S19K_STOCK_APW_ENABLE_SEQUENCE: [StockApwLifecycleStep; 2] = [
    StockApwLifecycleStep::LockPsuControlOutput,
    StockApwLifecycleStep::WritePsuControlOutput(false),
];

/// Successful stock disable awaits a barrier handled by the I2C worker before
/// passing boolean `1` to that same PSU-control output. The barrier itself
/// emits no APW frame. Do not collapse this into independent rail-cut proof.
pub const S19K_STOCK_APW_DISABLE_SEQUENCE: [StockApwLifecycleStep; 4] = [
    StockApwLifecycleStep::LockPsuControlOutput,
    StockApwLifecycleStep::AwaitI2cWorkerBarrier,
    StockApwLifecycleStep::RelockPsuControlOutput,
    StockApwLifecycleStep::WritePsuControlOutput(true),
];

/// The disable future enqueues tag `3` through the same serialized worker used
/// by APW operations. The tag-3 branch calls the reply helper with zero, makes
/// no call through either APW backend function pointer, and returns to the
/// common worker loop. Thus it is a worker barrier, not an APW command.
pub const S19K_STOCK_APW_DISABLE_WORKER_MESSAGE_TAG: u8 = 3;
pub const S19K_STOCK_APW_DISABLE_WORKER_SEQUENCE: [StockApwDisableWorkerStep; 4] = [
    StockApwDisableWorkerStep::EnqueueMessageTag(S19K_STOCK_APW_DISABLE_WORKER_MESSAGE_TAG),
    StockApwDisableWorkerStep::AwaitWorkerAcknowledgement,
    StockApwDisableWorkerStep::AcknowledgeWithoutApwBackendCall,
    StockApwDisableWorkerStep::ContinueWorkerLoop,
];
pub const S19K_STOCK_APW_DISABLE_I2C_FUTURE_FN_VA: u64 = 0x0091_6474;
pub const S19K_STOCK_APW_DISABLE_I2C_POLL_FN_VA: u64 = 0x0091_64EC;
pub const S19K_STOCK_APW_I2C_WORKER_LOOP_FN_VA: u64 = 0x0091_50E0;
pub const S19K_STOCK_APW_I2C_WORKER_TAG3_HANDLER_VA: u64 = 0x0091_5274;
pub const S19K_STOCK_APW_I2C_WORKER_REPLY_FN_VA: u64 = 0x0091_8330;
/// Hardware initialization opens the object reported as `PSU Control pin`
/// with this logical state before handing it into the APW implementation.
pub const S19K_STOCK_PSU_CONTROL_INITIAL_STATE: bool = true;
pub const S19K_STOCK_PSU_CONTROL_OPEN_FN_VA: u64 = 0x008D_A6EC;
pub const S19K_STOCK_PIN_OUT_DISPATCH_FN_VA: u64 = 0x0093_B51C;
pub const S19K_STOCK_PSU_CONTROL_OUTPUT_HELPER_VA: u64 = 0x0093_CA80;
pub const S19K_STOCK_SYSFS_PIN_OUT_WRITE_FN_VA: u64 = 0x0093_D4D4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockApwChecksumAlgorithm {
    /// Add little-endian 16-bit words; an odd trailing byte is the low byte of
    /// a final word whose high byte is zero.
    LittleEndianWordAdditive,
    /// Add individual bytes.
    ByteAdditive,
}

/// The frame parser selects the word-additive helper only for mode byte `1`.
/// Every other observed mode takes the byte-additive branch.
pub const S19K_STOCK_APW_WORD_CHECKSUM_MODE: u8 = 1;
pub const S19K_STOCK_APW_WORD_CHECKSUM_FN_VA: u64 = 0x0091_DE68;

pub fn s19k_stock_apw_checksum_algorithm(mode: u8) -> StockApwChecksumAlgorithm {
    if mode == S19K_STOCK_APW_WORD_CHECKSUM_MODE {
        StockApwChecksumAlgorithm::LittleEndianWordAdditive
    } else {
        StockApwChecksumAlgorithm::ByteAdditive
    }
}

/// Produce the low 16 wire bits of stock's selected additive checksum.
pub fn s19k_stock_apw_wire_checksum(mode: u8, bytes: &[u8]) -> u16 {
    match s19k_stock_apw_checksum_algorithm(mode) {
        StockApwChecksumAlgorithm::LittleEndianWordAdditive => {
            bytes.chunks(2).fold(0_u16, |sum, chunk| {
                let word = u16::from(chunk[0]) | u16::from(*chunk.get(1).unwrap_or(&0)) << 8;
                sum.wrapping_add(word)
            })
        }
        StockApwChecksumAlgorithm::ByteAdditive => bytes
            .iter()
            .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockApwSetVoltagePolicy {
    pub command: u8,
    pub write_to_read_delay_ms: u32,
    /// Eligible retries after the initial attempt.
    pub retry_count: u8,
    pub retry_delay_s: u8,
    pub maximum_attempts: u8,
}

/// Exact set-voltage policy. The retry policy is scoped to this command and
/// must not be silently generalized to every APW operation.
pub const S19K_STOCK_APW_SET_VOLTAGE_POLICY: StockApwSetVoltagePolicy = StockApwSetVoltagePolicy {
    command: 0x83,
    write_to_read_delay_ms: 350,
    retry_count: 3,
    retry_delay_s: 2,
    maximum_attempts: 4,
};

pub fn s19k_stock_apw_version_admitted(version: u8) -> bool {
    S19K_APW121215F_REPORTED_VERSION_BYTES.contains(&version)
}

/// Evidence collected around a terminal S19k cut. The two stock fields are
/// deliberately represented so tests can prove that they grant no electrical
/// authority by themselves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct S19kSafeOffEvidence {
    pub stock_disable_log_seen: bool,
    pub stock_disable_future_completed: bool,
    pub gpio437_disengaged_readback: bool,
    pub independent_rail_or_current_decay: bool,
    pub resets_asserted_before_cut: bool,
    pub cooling_owned_through_decay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kRailCutAssessment {
    /// Checked GPIO437 readback proves controller intent only.
    ControllerSafeOffOnly,
    /// An independent instrument also observed rail/current decay.
    VerifiedRailCut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kSafeOffEvidenceError {
    MissingCheckedGpio437DisengagedReadback,
    MissingIndependentRailOrCurrentDecay,
    MissingResetBeforeCutOrdering,
    CoolingReleasedBeforeDecayCompleted,
}

/// Classify controller intent separately from independent electrical proof.
pub fn classify_s19k_rail_cut(
    evidence: S19kSafeOffEvidence,
) -> Result<S19kRailCutAssessment, S19kSafeOffEvidenceError> {
    if !evidence.gpio437_disengaged_readback {
        return Err(S19kSafeOffEvidenceError::MissingCheckedGpio437DisengagedReadback);
    }
    if evidence.independent_rail_or_current_decay {
        Ok(S19kRailCutAssessment::VerifiedRailCut)
    } else {
        Ok(S19kRailCutAssessment::ControllerSafeOffOnly)
    }
}

/// Admit the complete terminal sequence required by the next-office runbook.
/// This is still a pure evidence check and grants no hardware authority.
pub fn admit_s19k_terminal_safeoff_evidence(
    evidence: S19kSafeOffEvidence,
) -> Result<(), S19kSafeOffEvidenceError> {
    match classify_s19k_rail_cut(evidence)? {
        S19kRailCutAssessment::ControllerSafeOffOnly => {
            return Err(S19kSafeOffEvidenceError::MissingIndependentRailOrCurrentDecay);
        }
        S19kRailCutAssessment::VerifiedRailCut => {}
    }
    if !evidence.resets_asserted_before_cut {
        return Err(S19kSafeOffEvidenceError::MissingResetBeforeCutOrdering);
    }
    if !evidence.cooling_owned_through_decay {
        return Err(S19kSafeOffEvidenceError::CoolingReleasedBeforeDecayCompleted);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_profile_and_vtable_are_pinned() {
        assert_eq!(S19K_PRO_STOCK_MODEL_ENUM, 8);
        assert_eq!(S19K_APW121215F_REPORTED_VERSION_BYTES, [0x75, 0x76, 0x77]);
        assert_eq!(S19K_APW121215F_PROFILE_DISCRIMINATOR, 4);
        assert_eq!(S19K_APW121215F_TRAIT_ALLOC_FN_VA, 0x0090_DFC0);
        assert_eq!(S19K_APW121215F_TRAIT_METHODS[0].slot, 0x18);
        assert_eq!(S19K_APW121215F_TRAIT_METHODS[2].evidence_name, "disable");
        assert_eq!(S19K_APW121215F_TRAIT_METHODS[7].slot, 0x50);
        assert!(s19k_stock_apw_version_admitted(0x76));
        assert!(!s19k_stock_apw_version_admitted(0x74));
        assert!(!s19k_stock_apw_version_admitted(0x78));
    }

    #[test]
    fn psu_service_enable_dispatch_resolves_to_apw_slot_twenty_only_as_software_evidence() {
        assert_eq!(
            S19K_STOCK_PSU_ENABLE_DISPATCH,
            [
                StockPsuEnableDispatchStep::ReferenceEnableLogRecord,
                StockPsuEnableDispatchStep::LockPsuServiceDriver,
                StockPsuEnableDispatchStep::LoadPsuTraitObject,
                StockPsuEnableDispatchStep::InvokePsuTraitSlot(0x20),
                StockPsuEnableDispatchStep::PollReturnedFuture,
            ]
        );
        assert_eq!(
            S19K_APW121215F_TRAIT_METHODS[1],
            StockApwTraitMethod {
                slot: 0x20,
                constructor_va: 0x0090_FCC8,
                poll_va: Some(0x0090_FD70),
                evidence_name: "enable",
            }
        );
        assert!(refuse_stock_psu_enable_dispatch_as_electrical_rail_proof().is_err());
        assert!(refuse_stock_psu_enable_and_hashboard_reset_as_one_static_transaction().is_err());
    }

    #[test]
    fn disable_worker_barrier_precedes_boolean_one_and_emits_no_apw_call() {
        assert_eq!(
            S19K_STOCK_APW_DISABLE_SEQUENCE,
            [
                StockApwLifecycleStep::LockPsuControlOutput,
                StockApwLifecycleStep::AwaitI2cWorkerBarrier,
                StockApwLifecycleStep::RelockPsuControlOutput,
                StockApwLifecycleStep::WritePsuControlOutput(true),
            ]
        );
        assert_eq!(
            S19K_STOCK_APW_DISABLE_WORKER_SEQUENCE,
            [
                StockApwDisableWorkerStep::EnqueueMessageTag(3),
                StockApwDisableWorkerStep::AwaitWorkerAcknowledgement,
                StockApwDisableWorkerStep::AcknowledgeWithoutApwBackendCall,
                StockApwDisableWorkerStep::ContinueWorkerLoop,
            ]
        );
        assert_eq!(
            S19K_STOCK_APW_ENABLE_SEQUENCE.last(),
            Some(&StockApwLifecycleStep::WritePsuControlOutput(false))
        );
        assert!(S19K_STOCK_PSU_CONTROL_INITIAL_STATE);
    }

    #[test]
    fn checksum_modes_match_the_exact_stock_algorithms() {
        let frame_prefix = [0x55, 0xaa, 0x06, 0x83, 0x34, 0x12];
        assert_eq!(
            s19k_stock_apw_checksum_algorithm(1),
            StockApwChecksumAlgorithm::LittleEndianWordAdditive
        );
        assert_eq!(
            s19k_stock_apw_checksum_algorithm(0),
            StockApwChecksumAlgorithm::ByteAdditive
        );
        assert_eq!(s19k_stock_apw_wire_checksum(1, &frame_prefix), 0x3f8f);
        assert_eq!(s19k_stock_apw_wire_checksum(0, &frame_prefix), 0x01ce);
        assert_eq!(s19k_stock_apw_wire_checksum(1, &[1, 2, 3]), 0x0204);
        assert_eq!(s19k_stock_apw_wire_checksum(1, &[]), 0);
    }

    #[test]
    fn set_voltage_retry_count_is_not_total_attempt_count() {
        assert_eq!(S19K_STOCK_APW_SET_VOLTAGE_POLICY.command, 0x83);
        assert_eq!(
            S19K_STOCK_APW_SET_VOLTAGE_POLICY.write_to_read_delay_ms,
            350
        );
        assert_eq!(S19K_STOCK_APW_SET_VOLTAGE_POLICY.retry_count, 3);
        assert_eq!(S19K_STOCK_APW_SET_VOLTAGE_POLICY.retry_delay_s, 2);
        assert_eq!(S19K_STOCK_APW_SET_VOLTAGE_POLICY.maximum_attempts, 4);
    }

    #[test]
    fn stock_disable_log_and_future_never_mint_electrical_proof() {
        let stock_only = S19kSafeOffEvidence {
            stock_disable_log_seen: true,
            stock_disable_future_completed: true,
            ..S19kSafeOffEvidence::default()
        };
        assert_eq!(
            classify_s19k_rail_cut(stock_only),
            Err(S19kSafeOffEvidenceError::MissingCheckedGpio437DisengagedReadback)
        );

        let controller_only = S19kSafeOffEvidence {
            gpio437_disengaged_readback: true,
            ..stock_only
        };
        assert_eq!(
            classify_s19k_rail_cut(controller_only),
            Ok(S19kRailCutAssessment::ControllerSafeOffOnly)
        );
        assert_eq!(
            admit_s19k_terminal_safeoff_evidence(controller_only),
            Err(S19kSafeOffEvidenceError::MissingIndependentRailOrCurrentDecay)
        );
    }

    #[test]
    fn terminal_safeoff_requires_rail_reset_order_and_cooling() {
        let electrical = S19kSafeOffEvidence {
            gpio437_disengaged_readback: true,
            independent_rail_or_current_decay: true,
            ..S19kSafeOffEvidence::default()
        };
        assert_eq!(
            classify_s19k_rail_cut(electrical),
            Ok(S19kRailCutAssessment::VerifiedRailCut)
        );
        assert_eq!(
            admit_s19k_terminal_safeoff_evidence(electrical),
            Err(S19kSafeOffEvidenceError::MissingResetBeforeCutOrdering)
        );
        assert_eq!(
            admit_s19k_terminal_safeoff_evidence(S19kSafeOffEvidence {
                resets_asserted_before_cut: true,
                ..electrical
            }),
            Err(S19kSafeOffEvidenceError::CoolingReleasedBeforeDecayCompleted)
        );
        assert_eq!(
            admit_s19k_terminal_safeoff_evidence(S19kSafeOffEvidence {
                resets_asserted_before_cut: true,
                cooling_owned_through_decay: true,
                ..electrical
            }),
            Ok(())
        );
    }
}
