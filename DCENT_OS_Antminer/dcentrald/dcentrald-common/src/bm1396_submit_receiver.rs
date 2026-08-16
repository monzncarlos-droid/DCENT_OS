//! Pure replay contract for the stock BM1396 `bitmain_submit_nonce` receiver.
//!
//! Exact co-bundled `cgminer` artifacts for S17e/T17e 2019 and signed 2020
//! reconstruct the command payload, reject an immediately repeated nonce,
//! regenerate the full 80-byte double SHA-256, apply a release/model-scoped
//! coarse gate, compare all eight native digest words with the cloned work
//! target, and only then enter generic asynchronous submission admission.
//! This module performs no command transport, queue I/O, or pool request.

use crate::bm1391_share_qualification::{
    bm1391_stock_full_target_passes, stock_double_sha256_from_word_swapped_header,
};
use crate::bm1396_contract::Bm1396Model;
use crate::bm1396_lifecycle::Bm1396FirmwareRelease;
use crate::bm1396_work_binding::{
    BM1396_SUBMIT_NONCE_FIRST_STRING_LENGTH_OFFSET, BM1396_SUBMIT_NONCE_FIXED_WORK_LEN,
    BM1396_SUBMIT_NONCE_STRING_COUNT,
};

pub const BM1396_SUBMIT_RECEIVER_NONCE_OFFSET: usize = 1;
pub const BM1396_SUBMIT_RECEIVER_FIXED_WORK_OFFSET: usize = 5;
pub const BM1396_SUBMIT_RECEIVER_FIRST_STRING_DATA_OFFSET: usize = 0x1c6;
pub const BM1396_RECEIVER_WORK_NONCE_OFFSET: usize = 0x4c;
pub const BM1396_RECEIVER_WORK_TARGET_OFFSET: usize = 0xa0;
pub const BM1396_RECEIVER_WORK_DIGEST_OFFSET: usize = 0xc0;
pub const BM1396_RECEIVER_WORK_POOL_POINTER_OFFSET: usize = 0x104;
pub const BM1396_RECEIVER_HEADER_LEN: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396SubmitReceiverEvidence {
    pub cgminer_size: u32,
    pub cgminer_sha256: &'static str,
    pub receiver_function: u32,
    pub full_target_wrapper_function: u32,
    pub stratum_submit_thread_function: u32,
    pub stratum_response_function: u32,
    pub coarse_digest_word7_max: u32,
}

pub const fn bm1396_submit_receiver_evidence(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
) -> Bm1396SubmitReceiverEvidence {
    match (release, model) {
        (Bm1396FirmwareRelease::Legacy2019, Bm1396Model::S17e) => Bm1396SubmitReceiverEvidence {
            cgminer_size: 283_155,
            cgminer_sha256: "43187d687d17bd601e0e549d96de3ee2cf8dd35009c27f0cea689b1691ca9e24",
            receiver_function: 0x0003_c5d4,
            full_target_wrapper_function: 0x0003_37c4,
            stratum_submit_thread_function: 0x0003_0418,
            stratum_response_function: 0x0002_eda4,
            coarse_digest_word7_max: 1,
        },
        (Bm1396FirmwareRelease::Legacy2019, Bm1396Model::T17e) => Bm1396SubmitReceiverEvidence {
            cgminer_size: 229_928,
            cgminer_sha256: "40bc7efc8d73aedcab61c0142e65486e416c91014663092c31ae6d0203a772cd",
            receiver_function: 0x0003_7ef0,
            full_target_wrapper_function: 0x0003_1b10,
            stratum_submit_thread_function: 0x0002_c8ac,
            stratum_response_function: 0x0002_fdec,
            coarse_digest_word7_max: 0,
        },
        (Bm1396FirmwareRelease::Signed2020, Bm1396Model::S17e | Bm1396Model::T17e) => {
            Bm1396SubmitReceiverEvidence {
                cgminer_size: 283_195,
                cgminer_sha256: "68df4a7e393f467a645a4e50a3cf79fa1cf2a04b5c7f00c0576dc564a9199276",
                receiver_function: 0x0003_c5ec,
                full_target_wrapper_function: 0x0003_37dc,
                stratum_submit_thread_function: 0x0003_0430,
                stratum_response_function: 0x0002_edbc,
                coarse_digest_word7_max: 1,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1396SubmitReceiverDecodeError {
    PacketTooShort {
        observed: usize,
        minimum: usize,
    },
    StringLengthZero {
        string_index: usize,
    },
    StringTruncated {
        string_index: usize,
        declared: usize,
        available: usize,
    },
    StringMissingTerminator {
        string_index: usize,
    },
    EmbeddedNul {
        string_index: usize,
        byte_index: usize,
    },
    TrailingBytes {
        observed: usize,
    },
}

/// Bounded decoded receiver input. Pointer-bearing bytes in `fixed_work` are
/// still inert caller data; the stock receiver overwrites its local device,
/// pool, and string pointers before using the clone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396SubmitReceiverPayload {
    pool_selector_byte: u8,
    nonce3: u32,
    fixed_work: [u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN],
    work_strings: [Vec<u8>; BM1396_SUBMIT_NONCE_STRING_COUNT],
}

impl Bm1396SubmitReceiverPayload {
    pub const fn pool_selector_byte(&self) -> u8 {
        self.pool_selector_byte
    }

    pub const fn nonce3(&self) -> u32 {
        self.nonce3
    }

    pub const fn fixed_work(&self) -> &[u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN] {
        &self.fixed_work
    }

    pub fn work_strings(&self) -> [&[u8]; BM1396_SUBMIT_NONCE_STRING_COUNT] {
        [
            self.work_strings[0].as_slice(),
            self.work_strings[1].as_slice(),
            self.work_strings[2].as_slice(),
        ]
    }

    pub const fn admits_receiver_or_pool_authority(&self) -> bool {
        false
    }
}

/// Decode the exact payload shape with bounds the stock pointer-only receiver
/// lacks. The clean subset requires all three encoded C strings to be nonempty,
/// terminated, free of interior NULs, and to consume the complete packet.
pub fn bm1396_decode_submit_receiver_payload(
    packet: &[u8],
) -> Result<Bm1396SubmitReceiverPayload, Bm1396SubmitReceiverDecodeError> {
    if packet.len() < BM1396_SUBMIT_RECEIVER_FIRST_STRING_DATA_OFFSET {
        return Err(Bm1396SubmitReceiverDecodeError::PacketTooShort {
            observed: packet.len(),
            minimum: BM1396_SUBMIT_RECEIVER_FIRST_STRING_DATA_OFFSET,
        });
    }

    let short_packet = || Bm1396SubmitReceiverDecodeError::PacketTooShort {
        observed: packet.len(),
        minimum: BM1396_SUBMIT_RECEIVER_FIRST_STRING_DATA_OFFSET,
    };
    let pool_selector_byte = *packet.first().ok_or_else(short_packet)?;
    let nonce_bytes: [u8; 4] = packet
        .get(BM1396_SUBMIT_RECEIVER_NONCE_OFFSET..BM1396_SUBMIT_RECEIVER_FIXED_WORK_OFFSET)
        .ok_or_else(short_packet)?
        .try_into()
        .map_err(|_| short_packet())?;
    let nonce3 = u32::from_le_bytes(nonce_bytes);
    let mut fixed_work = [0u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
    let fixed_work_bytes = packet
        .get(
            BM1396_SUBMIT_RECEIVER_FIXED_WORK_OFFSET
                ..BM1396_SUBMIT_NONCE_FIRST_STRING_LENGTH_OFFSET,
        )
        .ok_or_else(short_packet)?;
    fixed_work.copy_from_slice(fixed_work_bytes);

    let mut strings: [Vec<u8>; BM1396_SUBMIT_NONCE_STRING_COUNT] =
        std::array::from_fn(|_| Vec::new());
    let mut cursor = BM1396_SUBMIT_NONCE_FIRST_STRING_LENGTH_OFFSET;
    for (string_index, string) in strings.iter_mut().enumerate() {
        let Some(&declared_byte) = packet.get(cursor) else {
            return Err(Bm1396SubmitReceiverDecodeError::StringTruncated {
                string_index,
                declared: 1,
                available: 0,
            });
        };
        let declared = usize::from(declared_byte);
        if declared == 0 {
            return Err(Bm1396SubmitReceiverDecodeError::StringLengthZero { string_index });
        }
        cursor += 1;
        let end = cursor.checked_add(declared).ok_or(
            Bm1396SubmitReceiverDecodeError::StringTruncated {
                string_index,
                declared,
                available: packet.len().saturating_sub(cursor),
            },
        )?;
        let Some(encoded) = packet.get(cursor..end) else {
            return Err(Bm1396SubmitReceiverDecodeError::StringTruncated {
                string_index,
                declared,
                available: packet.len().saturating_sub(cursor),
            });
        };
        let Some(payload) = encoded.strip_suffix(&[0]) else {
            return Err(Bm1396SubmitReceiverDecodeError::StringMissingTerminator { string_index });
        };
        if let Some(byte_index) = payload.iter().position(|byte| *byte == 0) {
            return Err(Bm1396SubmitReceiverDecodeError::EmbeddedNul {
                string_index,
                byte_index,
            });
        }
        *string = payload.to_vec();
        cursor = end;
    }
    if cursor != packet.len() {
        return Err(Bm1396SubmitReceiverDecodeError::TrailingBytes {
            observed: packet.len() - cursor,
        });
    }
    Ok(Bm1396SubmitReceiverPayload {
        pool_selector_byte,
        nonce3,
        fixed_work,
        work_strings: strings,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396ReceiverAsyncInput {
    pub benchmark_mode: bool,
    pub stale: bool,
    pub submit_stale_enabled: bool,
    pub pool_requests_stale: bool,
    pub stratum_work: bool,
    pub stratum_queue_present: bool,
    pub stratum_queue_push_succeeds: bool,
    pub non_stratum_thread_create_succeeds: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396ReceiverAsyncStep {
    TimestampWorkFound,
    CountBenchmarkAcceptedWithoutNetwork,
    EvaluateStaleWork,
    MarkWorkStale,
    AccountAndDiscardStale,
    SpawnNonStratumSubmitThread,
    FatalProcessOnThreadCreationFailure,
    PushToStratumQueue,
    FreeAfterMissingOrRejectedStratumQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396ReceiverAsyncOutcome {
    BenchmarkCountedAcceptedWithoutNetwork,
    DiscardedStale,
    NonStratumSubmitThreadStarted,
    FatalProcessOnThreadCreationFailure,
    StratumQueueAccepted,
    StratumQueueMissingOrRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396ReceiverAsyncPlan {
    pub steps: Vec<Bm1396ReceiverAsyncStep>,
    pub outcome: Bm1396ReceiverAsyncOutcome,
}

impl Bm1396ReceiverAsyncPlan {
    pub const fn proves_network_delivery(&self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }
}

pub fn bm1396_receiver_async_plan(input: Bm1396ReceiverAsyncInput) -> Bm1396ReceiverAsyncPlan {
    let mut steps = vec![Bm1396ReceiverAsyncStep::TimestampWorkFound];
    if input.benchmark_mode {
        steps.push(Bm1396ReceiverAsyncStep::CountBenchmarkAcceptedWithoutNetwork);
        return Bm1396ReceiverAsyncPlan {
            steps,
            outcome: Bm1396ReceiverAsyncOutcome::BenchmarkCountedAcceptedWithoutNetwork,
        };
    }
    steps.push(Bm1396ReceiverAsyncStep::EvaluateStaleWork);
    if input.stale && !input.submit_stale_enabled && !input.pool_requests_stale {
        steps.push(Bm1396ReceiverAsyncStep::AccountAndDiscardStale);
        return Bm1396ReceiverAsyncPlan {
            steps,
            outcome: Bm1396ReceiverAsyncOutcome::DiscardedStale,
        };
    }
    if input.stale {
        steps.push(Bm1396ReceiverAsyncStep::MarkWorkStale);
    }
    if !input.stratum_work {
        steps.push(Bm1396ReceiverAsyncStep::SpawnNonStratumSubmitThread);
        let outcome = if input.non_stratum_thread_create_succeeds {
            Bm1396ReceiverAsyncOutcome::NonStratumSubmitThreadStarted
        } else {
            steps.push(Bm1396ReceiverAsyncStep::FatalProcessOnThreadCreationFailure);
            Bm1396ReceiverAsyncOutcome::FatalProcessOnThreadCreationFailure
        };
        return Bm1396ReceiverAsyncPlan { steps, outcome };
    }
    steps.push(Bm1396ReceiverAsyncStep::PushToStratumQueue);
    let outcome = if input.stratum_queue_present && input.stratum_queue_push_succeeds {
        Bm1396ReceiverAsyncOutcome::StratumQueueAccepted
    } else {
        steps.push(Bm1396ReceiverAsyncStep::FreeAfterMissingOrRejectedStratumQueue);
        Bm1396ReceiverAsyncOutcome::StratumQueueMissingOrRejected
    };
    Bm1396ReceiverAsyncPlan { steps, outcome }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396SubmitReceiverInput {
    pub previous_device_nonce: u32,
    pub available_pool_count: usize,
    pub async_input: Bm1396ReceiverAsyncInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396SubmitReceiverPlanError {
    PoolSelectorOutOfRange {
        observed: u8,
        available_pool_count: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396SubmitReceiverStep {
    RestoreDevicePointers,
    SelectAndRestorePoolPointer { selector: u8, work_offset: usize },
    RestoreThreeStringPointers,
    CheckImmediateDuplicateNonce,
    CommitDeviceLastNonce { nonce: u32 },
    StoreNonceInWork { offset: usize },
    RegenerateFullHeaderDoubleSha { digest_offset: usize },
    ApplyCoarseDigestWord7Gate { maximum: u32 },
    AccountHardwareError,
    UpdateWorkStatistics,
    CompareFullDigestWithClonedTarget { target_offset: usize },
    FullTargetMissReturnsTransportSuccess,
    CloneWorkForAsyncAdmission,
    InvokeAsyncAdmission,
    ReturnCommandSuccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396SubmitReceiverDisposition {
    DuplicateRejectedAsHardwareError,
    CoarseDigestRejectedAsHardwareError,
    AbovePoolTargetTransportSuccess,
    AsyncAdmission(Bm1396ReceiverAsyncOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396SubmitReceiverPlan {
    pub evidence: Bm1396SubmitReceiverEvidence,
    pub next_device_nonce: u32,
    pub digest_words_native: Option<[u32; 8]>,
    pub target_words_native: [u32; 8],
    pub full_target_passed: Option<bool>,
    /// `None` represents the exact fatal async thread-creation branch, which
    /// terminates the process before the command receiver can return.
    pub stock_command_return_value: Option<i32>,
    pub steps: Vec<Bm1396SubmitReceiverStep>,
    pub async_plan: Option<Bm1396ReceiverAsyncPlan>,
    pub disposition: Bm1396SubmitReceiverDisposition,
}

impl Bm1396SubmitReceiverPlan {
    pub const fn admits_live_receiver_authority(&self) -> bool {
        false
    }

    pub const fn proves_network_delivery(&self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }
}

pub const fn bm1396_submit_receiver_coarse_digest_passes(
    evidence: Bm1396SubmitReceiverEvidence,
    digest_word7_native: u32,
) -> bool {
    digest_word7_native <= evidence.coarse_digest_word7_max
}

/// Replay the exact receiver-side decision spine. Pool count and all payload
/// fields remain caller observations; the clean planner adds a selector bound
/// which the stock global-table lookup lacks.
#[allow(clippy::indexing_slicing)]
pub fn bm1396_plan_submit_nonce_receiver(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
    payload: &Bm1396SubmitReceiverPayload,
    input: Bm1396SubmitReceiverInput,
) -> Result<Bm1396SubmitReceiverPlan, Bm1396SubmitReceiverPlanError> {
    if usize::from(payload.pool_selector_byte) >= input.available_pool_count {
        return Err(Bm1396SubmitReceiverPlanError::PoolSelectorOutOfRange {
            observed: payload.pool_selector_byte,
            available_pool_count: input.available_pool_count,
        });
    }
    let evidence = bm1396_submit_receiver_evidence(release, model);
    let mut steps = vec![
        Bm1396SubmitReceiverStep::RestoreDevicePointers,
        Bm1396SubmitReceiverStep::SelectAndRestorePoolPointer {
            selector: payload.pool_selector_byte,
            work_offset: BM1396_RECEIVER_WORK_POOL_POINTER_OFFSET,
        },
        Bm1396SubmitReceiverStep::RestoreThreeStringPointers,
        Bm1396SubmitReceiverStep::CheckImmediateDuplicateNonce,
    ];

    let mut target_words_native = [0u32; 8];
    for (index, target) in target_words_native.iter_mut().enumerate() {
        let offset = BM1396_RECEIVER_WORK_TARGET_OFFSET + index * 4;
        *target = u32::from_le_bytes([
            payload.fixed_work[offset],
            payload.fixed_work[offset + 1],
            payload.fixed_work[offset + 2],
            payload.fixed_work[offset + 3],
        ]);
    }

    if input.previous_device_nonce == payload.nonce3 {
        steps.push(Bm1396SubmitReceiverStep::AccountHardwareError);
        return Ok(Bm1396SubmitReceiverPlan {
            evidence,
            next_device_nonce: input.previous_device_nonce,
            digest_words_native: None,
            target_words_native,
            full_target_passed: None,
            stock_command_return_value: Some(-1),
            steps,
            async_plan: None,
            disposition: Bm1396SubmitReceiverDisposition::DuplicateRejectedAsHardwareError,
        });
    }

    steps.push(Bm1396SubmitReceiverStep::CommitDeviceLastNonce {
        nonce: payload.nonce3,
    });
    steps.push(Bm1396SubmitReceiverStep::StoreNonceInWork {
        offset: BM1396_RECEIVER_WORK_NONCE_OFFSET,
    });
    let mut work_header = [0u8; BM1396_RECEIVER_HEADER_LEN];
    work_header.copy_from_slice(&payload.fixed_work[..BM1396_RECEIVER_HEADER_LEN]);
    work_header[BM1396_RECEIVER_WORK_NONCE_OFFSET..BM1396_RECEIVER_WORK_NONCE_OFFSET + 4]
        .copy_from_slice(&payload.nonce3.to_le_bytes());
    let digest_state_words = stock_double_sha256_from_word_swapped_header(&work_header);
    let digest_words_native = digest_state_words.map(u32::swap_bytes);
    steps.push(Bm1396SubmitReceiverStep::RegenerateFullHeaderDoubleSha {
        digest_offset: BM1396_RECEIVER_WORK_DIGEST_OFFSET,
    });
    steps.push(Bm1396SubmitReceiverStep::ApplyCoarseDigestWord7Gate {
        maximum: evidence.coarse_digest_word7_max,
    });
    if !bm1396_submit_receiver_coarse_digest_passes(evidence, digest_words_native[7]) {
        steps.push(Bm1396SubmitReceiverStep::AccountHardwareError);
        return Ok(Bm1396SubmitReceiverPlan {
            evidence,
            next_device_nonce: payload.nonce3,
            digest_words_native: Some(digest_words_native),
            target_words_native,
            full_target_passed: None,
            stock_command_return_value: Some(-1),
            steps,
            async_plan: None,
            disposition: Bm1396SubmitReceiverDisposition::CoarseDigestRejectedAsHardwareError,
        });
    }

    steps.push(Bm1396SubmitReceiverStep::UpdateWorkStatistics);
    steps.push(
        Bm1396SubmitReceiverStep::CompareFullDigestWithClonedTarget {
            target_offset: BM1396_RECEIVER_WORK_TARGET_OFFSET,
        },
    );
    let full_target_passed =
        bm1391_stock_full_target_passes(digest_words_native, target_words_native);
    if !full_target_passed {
        steps.push(Bm1396SubmitReceiverStep::FullTargetMissReturnsTransportSuccess);
        steps.push(Bm1396SubmitReceiverStep::ReturnCommandSuccess);
        return Ok(Bm1396SubmitReceiverPlan {
            evidence,
            next_device_nonce: payload.nonce3,
            digest_words_native: Some(digest_words_native),
            target_words_native,
            full_target_passed: Some(false),
            stock_command_return_value: Some(0),
            steps,
            async_plan: None,
            disposition: Bm1396SubmitReceiverDisposition::AbovePoolTargetTransportSuccess,
        });
    }

    steps.push(Bm1396SubmitReceiverStep::CloneWorkForAsyncAdmission);
    steps.push(Bm1396SubmitReceiverStep::InvokeAsyncAdmission);
    let async_plan = bm1396_receiver_async_plan(input.async_input);
    let fatal =
        async_plan.outcome == Bm1396ReceiverAsyncOutcome::FatalProcessOnThreadCreationFailure;
    if !fatal {
        steps.push(Bm1396SubmitReceiverStep::ReturnCommandSuccess);
    }
    let disposition = Bm1396SubmitReceiverDisposition::AsyncAdmission(async_plan.outcome);
    Ok(Bm1396SubmitReceiverPlan {
        evidence,
        next_device_nonce: payload.nonce3,
        digest_words_native: Some(digest_words_native),
        target_words_native,
        full_target_passed: Some(true),
        stock_command_return_value: (!fatal).then_some(0),
        steps,
        async_plan: Some(async_plan),
        disposition,
    })
}

/// Exact hardware-independent ordering of the stock Stratum sender's request
/// ID and tracking publication. The socket send happens before the tracking
/// record becomes visible to the response thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StratumSubmitStep {
    AssignCurrentRequestId,
    IncrementGlobalRequestId,
    FormatMiningSubmit,
    SendBeforeTrackingPublication,
    InsertFourByteIdTrackingRecord,
    IncrementPoolOutstandingShareCount,
    LeaveRequestUntrackedAfterSendFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StratumSubmitPlanError {
    RequestIdWouldOverflow { observed: i32 },
}

/// Private correlation material produced only for a stock-observed successful
/// send. It remains caller-derived replay data, not a live-session receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396StratumShareTrackingToken {
    request_id: i32,
    work_allows_null_result: bool,
}

impl Bm1396StratumShareTrackingToken {
    pub const fn request_id(&self) -> i32 {
        self.request_id
    }

    pub const fn admits_pool_session_or_acceptance_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396StratumSubmitPlan {
    pub assigned_request_id: i32,
    pub next_request_id: i32,
    pub steps: Vec<Bm1396StratumSubmitStep>,
    tracking_token: Option<Bm1396StratumShareTrackingToken>,
}

impl Bm1396StratumSubmitPlan {
    pub const fn tracking_token(&self) -> Option<Bm1396StratumShareTrackingToken> {
        self.tracking_token
    }

    pub const fn proves_socket_delivery_or_pool_acceptance(&self) -> bool {
        false
    }
}

/// Reproduce the stock request-ID/tracking order while refusing the native
/// signed-int overflow that the ARM binary does not guard.
pub fn bm1396_plan_stratum_submit_tracking(
    request_id_counter: i32,
    stratum_send_succeeded: bool,
    work_allows_null_result: bool,
) -> Result<Bm1396StratumSubmitPlan, Bm1396StratumSubmitPlanError> {
    let next_request_id = request_id_counter.checked_add(1).ok_or(
        Bm1396StratumSubmitPlanError::RequestIdWouldOverflow {
            observed: request_id_counter,
        },
    )?;
    let mut steps = vec![
        Bm1396StratumSubmitStep::AssignCurrentRequestId,
        Bm1396StratumSubmitStep::IncrementGlobalRequestId,
        Bm1396StratumSubmitStep::FormatMiningSubmit,
        Bm1396StratumSubmitStep::SendBeforeTrackingPublication,
    ];
    let tracking_token = if stratum_send_succeeded {
        steps.push(Bm1396StratumSubmitStep::InsertFourByteIdTrackingRecord);
        steps.push(Bm1396StratumSubmitStep::IncrementPoolOutstandingShareCount);
        Some(Bm1396StratumShareTrackingToken {
            request_id: request_id_counter,
            work_allows_null_result,
        })
    } else {
        steps.push(Bm1396StratumSubmitStep::LeaveRequestUntrackedAfterSendFailure);
        None
    };
    Ok(Bm1396StratumSubmitPlan {
        assigned_request_id: request_id_counter,
        next_request_id,
        steps,
        tracking_token,
    })
}

/// Jansson value class used by the exact response function. Numeric enum
/// values remain internal to Jansson; the semantic cases are the stable ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StratumResultValue {
    Missing,
    True,
    False,
    Null,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StratumResponseStep {
    ParseResultErrorAndId,
    LookUpFourByteRequestId,
    RemoveMatchedTrackingBeforeAccounting,
    DecrementPoolOutstandingShareCount,
    ComputeTrackedResponseLag,
    AccountAcceptedShareAndDifficulty,
    ResetSequentialRejectCount,
    AccountRejectedShareAndDifficulty,
    IncrementSequentialRejectCount,
    AccountUntrackedAcceptedShare,
    AccountUntrackedRejectedShare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StratumResponseDisposition {
    StockWouldAccountTrackedAccepted,
    StockWouldAccountTrackedRejected,
    StockWouldAccountUntrackedAccepted,
    StockWouldAccountUntrackedRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396StratumResponsePlan {
    pub steps: Vec<Bm1396StratumResponseStep>,
    pub disposition: Bm1396StratumResponseDisposition,
}

impl Bm1396StratumResponsePlan {
    pub const fn proves_response_source_or_pool_acceptance(&self) -> bool {
        false
    }
}

/// Model the exact tracked/untracked response accounting. A matching ID is
/// removed before result accounting. Stock accepts JSON true, plus JSON null
/// for one work-flagged special case. This pure function does not establish
/// that a response came from an admitted or authenticated pool session.
pub fn bm1396_plan_stratum_response(
    response_id: Option<i32>,
    result: Bm1396StratumResultValue,
    tracking_token: Option<Bm1396StratumShareTrackingToken>,
) -> Bm1396StratumResponsePlan {
    let mut steps = vec![Bm1396StratumResponseStep::ParseResultErrorAndId];
    let tracked = match (response_id, tracking_token) {
        (Some(observed), Some(token)) if observed == token.request_id => Some(token),
        _ => None,
    };

    if let Some(token) = tracked {
        steps.extend([
            Bm1396StratumResponseStep::LookUpFourByteRequestId,
            Bm1396StratumResponseStep::RemoveMatchedTrackingBeforeAccounting,
            Bm1396StratumResponseStep::DecrementPoolOutstandingShareCount,
            Bm1396StratumResponseStep::ComputeTrackedResponseLag,
        ]);
        let accepted = result == Bm1396StratumResultValue::True
            || (result == Bm1396StratumResultValue::Null && token.work_allows_null_result);
        if accepted {
            steps.extend([
                Bm1396StratumResponseStep::AccountAcceptedShareAndDifficulty,
                Bm1396StratumResponseStep::ResetSequentialRejectCount,
            ]);
            Bm1396StratumResponsePlan {
                steps,
                disposition: Bm1396StratumResponseDisposition::StockWouldAccountTrackedAccepted,
            }
        } else {
            steps.extend([
                Bm1396StratumResponseStep::AccountRejectedShareAndDifficulty,
                Bm1396StratumResponseStep::IncrementSequentialRejectCount,
            ]);
            Bm1396StratumResponsePlan {
                steps,
                disposition: Bm1396StratumResponseDisposition::StockWouldAccountTrackedRejected,
            }
        }
    } else {
        steps.push(Bm1396StratumResponseStep::LookUpFourByteRequestId);
        if result == Bm1396StratumResultValue::True {
            steps.push(Bm1396StratumResponseStep::AccountUntrackedAcceptedShare);
            Bm1396StratumResponsePlan {
                steps,
                disposition: Bm1396StratumResponseDisposition::StockWouldAccountUntrackedAccepted,
            }
        } else {
            steps.push(Bm1396StratumResponseStep::AccountUntrackedRejectedShare);
            Bm1396StratumResponsePlan {
                steps,
                disposition: Bm1396StratumResponseDisposition::StockWouldAccountUntrackedRejected,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn async_queue_success() -> Bm1396ReceiverAsyncInput {
        Bm1396ReceiverAsyncInput {
            benchmark_mode: false,
            stale: false,
            submit_stale_enabled: false,
            pool_requests_stale: false,
            stratum_work: true,
            stratum_queue_present: true,
            stratum_queue_push_succeeds: true,
            non_stratum_thread_create_succeeds: true,
        }
    }

    fn encode_payload(
        selector: u8,
        nonce3: u32,
        fixed_work: &[u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN],
        strings: [&[u8]; 3],
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(selector);
        packet.extend_from_slice(&nonce3.to_le_bytes());
        packet.extend_from_slice(fixed_work);
        for string in strings {
            assert!(string.len() < usize::from(u8::MAX));
            packet.push(u8::try_from(string.len() + 1).unwrap_or_default());
            packet.extend_from_slice(string);
            packet.push(0);
        }
        packet
    }

    fn genesis_work_and_target() -> [u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN] {
        let mut canonical = [0u8; BM1396_RECEIVER_HEADER_LEN];
        canonical[..4].copy_from_slice(&[1, 0, 0, 0]);
        canonical[36..68].copy_from_slice(&[
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ]);
        canonical[68..72].copy_from_slice(&[0x29, 0xab, 0x5f, 0x49]);
        canonical[72..76].copy_from_slice(&[0xff, 0xff, 0x00, 0x1d]);
        canonical[76..80].copy_from_slice(&[0x1d, 0xac, 0x2b, 0x7c]);

        let mut work = [0u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
        for word_index in 0..20 {
            let offset = word_index * 4;
            work[offset] = canonical[offset + 3];
            work[offset + 1] = canonical[offset + 2];
            work[offset + 2] = canonical[offset + 1];
            work[offset + 3] = canonical[offset];
        }
        let native_target: [u32; 8] = [
            0x0a8c_e26f,
            0x72b3_f1b6,
            0x46a2_a6c1,
            0x4ff7_63ae,
            0x6583_1e93,
            0x9c08_5ae1,
            0x0019_d668,
            0,
        ];
        for (index, word) in native_target.into_iter().enumerate() {
            let offset = BM1396_RECEIVER_WORK_TARGET_OFFSET + index * 4;
            work[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        work
    }

    #[test]
    fn exact_receiver_artifacts_and_t17e_2019_coarse_gate_divergence_are_pinned() {
        let s19 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Legacy2019, Bm1396Model::S17e);
        let t19 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Legacy2019, Bm1396Model::T17e);
        let s20 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Signed2020, Bm1396Model::S17e);
        let t20 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Signed2020, Bm1396Model::T17e);
        assert_eq!(s19.coarse_digest_word7_max, 1);
        assert_eq!(t19.coarse_digest_word7_max, 0);
        assert!(bm1396_submit_receiver_coarse_digest_passes(s19, 1));
        assert!(!bm1396_submit_receiver_coarse_digest_passes(t19, 1));
        assert_eq!(s20, t20);
        assert_eq!(s20.receiver_function, 0x3c5ec);
    }

    #[test]
    fn bounded_decoder_round_trips_the_exact_selector_nonce_work_and_strings() {
        let work = genesis_work_and_target();
        let encoded = encode_payload(2, 0x1dac_2b7c, &work, [b"job", b"user", b"pool"]);
        let decoded = bm1396_decode_submit_receiver_payload(&encoded).expect("valid payload");
        assert_eq!(decoded.pool_selector_byte(), 2);
        assert_eq!(decoded.nonce3(), 0x1dac_2b7c);
        assert_eq!(decoded.fixed_work(), &work);
        assert_eq!(
            decoded.work_strings(),
            [b"job".as_slice(), b"user", b"pool"]
        );
        assert!(!decoded.admits_receiver_or_pool_authority());
    }

    #[test]
    fn decoder_refuses_stock_out_of_bounds_and_ambiguous_c_string_shapes() {
        assert!(matches!(
            bm1396_decode_submit_receiver_payload(&[0; 8]),
            Err(Bm1396SubmitReceiverDecodeError::PacketTooShort { .. })
        ));
        let work = [0u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
        let good = encode_payload(0, 1, &work, [b"a", b"b", b"c"]);

        let mut zero = good.clone();
        zero[BM1396_SUBMIT_NONCE_FIRST_STRING_LENGTH_OFFSET] = 0;
        assert!(matches!(
            bm1396_decode_submit_receiver_payload(&zero),
            Err(Bm1396SubmitReceiverDecodeError::StringLengthZero { string_index: 0 })
        ));

        let mut missing_nul = good.clone();
        missing_nul[BM1396_SUBMIT_RECEIVER_FIRST_STRING_DATA_OFFSET + 1] = b'x';
        assert!(matches!(
            bm1396_decode_submit_receiver_payload(&missing_nul),
            Err(Bm1396SubmitReceiverDecodeError::StringMissingTerminator { string_index: 0 })
        ));

        let mut trailing = good.clone();
        trailing.push(0xaa);
        assert!(matches!(
            bm1396_decode_submit_receiver_payload(&trailing),
            Err(Bm1396SubmitReceiverDecodeError::TrailingBytes { observed: 1 })
        ));

        let mut truncated = good;
        truncated.pop();
        assert!(matches!(
            bm1396_decode_submit_receiver_payload(&truncated),
            Err(Bm1396SubmitReceiverDecodeError::StringTruncated {
                string_index: 2,
                ..
            })
        ));
    }

    #[test]
    fn genesis_receiver_rehashes_full_header_accepts_equal_target_and_queues() {
        let work = genesis_work_and_target();
        let encoded = encode_payload(1, 0x1dac_2b7c, &work, [b"job", b"user", b"pool"]);
        let decoded = bm1396_decode_submit_receiver_payload(&encoded).expect("valid payload");
        let plan = bm1396_plan_submit_nonce_receiver(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            &decoded,
            Bm1396SubmitReceiverInput {
                previous_device_nonce: 0,
                available_pool_count: 2,
                async_input: async_queue_success(),
            },
        )
        .expect("selector admitted");
        assert_eq!(
            plan.digest_words_native,
            Some([
                0x0a8c_e26f,
                0x72b3_f1b6,
                0x46a2_a6c1,
                0x4ff7_63ae,
                0x6583_1e93,
                0x9c08_5ae1,
                0x0019_d668,
                0,
            ])
        );
        assert_eq!(plan.full_target_passed, Some(true));
        assert_eq!(plan.stock_command_return_value, Some(0));
        assert_eq!(
            plan.disposition,
            Bm1396SubmitReceiverDisposition::AsyncAdmission(
                Bm1396ReceiverAsyncOutcome::StratumQueueAccepted
            )
        );
        assert!(!plan.proves_network_delivery());
        assert!(!plan.proves_pool_acceptance());
    }

    #[test]
    fn duplicate_and_coarse_failures_return_minus_one_and_account_hardware_error() {
        let work = genesis_work_and_target();
        let encoded = encode_payload(0, 0x1dac_2b7c, &work, [b"a", b"b", b"c"]);
        let decoded = bm1396_decode_submit_receiver_payload(&encoded).expect("valid payload");
        let duplicate = bm1396_plan_submit_nonce_receiver(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            &decoded,
            Bm1396SubmitReceiverInput {
                previous_device_nonce: decoded.nonce3(),
                available_pool_count: 1,
                async_input: async_queue_success(),
            },
        )
        .expect("selector admitted");
        assert_eq!(duplicate.stock_command_return_value, Some(-1));
        assert_eq!(duplicate.digest_words_native, None);
        assert_eq!(
            duplicate.disposition,
            Bm1396SubmitReceiverDisposition::DuplicateRejectedAsHardwareError
        );

        let mut bad_work = work;
        bad_work[..BM1396_RECEIVER_HEADER_LEN].fill(0);
        let encoded = encode_payload(0, 7, &bad_work, [b"a", b"b", b"c"]);
        let decoded = bm1396_decode_submit_receiver_payload(&encoded).expect("valid payload");
        let coarse = bm1396_plan_submit_nonce_receiver(
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::T17e,
            &decoded,
            Bm1396SubmitReceiverInput {
                previous_device_nonce: 0,
                available_pool_count: 1,
                async_input: async_queue_success(),
            },
        )
        .expect("selector admitted");
        assert_eq!(coarse.stock_command_return_value, Some(-1));
        assert_eq!(
            coarse.disposition,
            Bm1396SubmitReceiverDisposition::CoarseDigestRejectedAsHardwareError
        );
    }

    #[test]
    fn above_target_is_transport_success_but_never_submission_or_acceptance() {
        let mut work = genesis_work_and_target();
        work[BM1396_RECEIVER_WORK_TARGET_OFFSET..BM1396_RECEIVER_WORK_TARGET_OFFSET + 32].fill(0);
        let encoded = encode_payload(0, 0x1dac_2b7c, &work, [b"a", b"b", b"c"]);
        let decoded = bm1396_decode_submit_receiver_payload(&encoded).expect("valid payload");
        let plan = bm1396_plan_submit_nonce_receiver(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            &decoded,
            Bm1396SubmitReceiverInput {
                previous_device_nonce: 0,
                available_pool_count: 1,
                async_input: async_queue_success(),
            },
        )
        .expect("selector admitted");
        assert_eq!(plan.full_target_passed, Some(false));
        assert_eq!(plan.stock_command_return_value, Some(0));
        assert_eq!(
            plan.disposition,
            Bm1396SubmitReceiverDisposition::AbovePoolTargetTransportSuccess
        );
        assert!(plan.async_plan.is_none());
        assert!(!plan.admits_live_receiver_authority());
        assert!(!plan.proves_pool_acceptance());
    }

    #[test]
    fn pool_selector_and_every_async_terminal_branch_fail_closed_or_stay_observational() {
        let work = genesis_work_and_target();
        let encoded = encode_payload(3, 0x1dac_2b7c, &work, [b"a", b"b", b"c"]);
        let decoded = bm1396_decode_submit_receiver_payload(&encoded).expect("valid payload");
        assert_eq!(
            bm1396_plan_submit_nonce_receiver(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::S17e,
                &decoded,
                Bm1396SubmitReceiverInput {
                    previous_device_nonce: 0,
                    available_pool_count: 3,
                    async_input: async_queue_success(),
                },
            ),
            Err(Bm1396SubmitReceiverPlanError::PoolSelectorOutOfRange {
                observed: 3,
                available_pool_count: 3,
            })
        );

        let benchmark = bm1396_receiver_async_plan(Bm1396ReceiverAsyncInput {
            benchmark_mode: true,
            ..async_queue_success()
        });
        assert_eq!(
            benchmark.outcome,
            Bm1396ReceiverAsyncOutcome::BenchmarkCountedAcceptedWithoutNetwork
        );
        let stale = bm1396_receiver_async_plan(Bm1396ReceiverAsyncInput {
            stale: true,
            ..async_queue_success()
        });
        assert_eq!(stale.outcome, Bm1396ReceiverAsyncOutcome::DiscardedStale);
        let thread_failure = bm1396_receiver_async_plan(Bm1396ReceiverAsyncInput {
            stratum_work: false,
            non_stratum_thread_create_succeeds: false,
            ..async_queue_success()
        });
        assert_eq!(
            thread_failure.outcome,
            Bm1396ReceiverAsyncOutcome::FatalProcessOnThreadCreationFailure
        );
        let queue_failure = bm1396_receiver_async_plan(Bm1396ReceiverAsyncInput {
            stratum_queue_present: false,
            ..async_queue_success()
        });
        assert_eq!(
            queue_failure.outcome,
            Bm1396ReceiverAsyncOutcome::StratumQueueMissingOrRejected
        );
        assert!(!benchmark.proves_pool_acceptance());
        assert!(!queue_failure.proves_network_delivery());
    }

    #[test]
    fn exact_submit_and_response_functions_are_release_scoped() {
        let s19 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Legacy2019, Bm1396Model::S17e);
        let t19 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Legacy2019, Bm1396Model::T17e);
        let s20 =
            bm1396_submit_receiver_evidence(Bm1396FirmwareRelease::Signed2020, Bm1396Model::S17e);
        assert_eq!(s19.stratum_submit_thread_function, 0x30418);
        assert_eq!(s19.stratum_response_function, 0x2eda4);
        assert_eq!(t19.stratum_submit_thread_function, 0x2c8ac);
        assert_eq!(t19.stratum_response_function, 0x2fdec);
        assert_eq!(s20.stratum_submit_thread_function, 0x30430);
        assert_eq!(s20.stratum_response_function, 0x2edbc);
    }

    #[test]
    fn stratum_tracking_is_published_only_after_successful_send() {
        let success =
            bm1396_plan_stratum_submit_tracking(41, true, false).expect("bounded request ID");
        assert_eq!(success.assigned_request_id, 41);
        assert_eq!(success.next_request_id, 42);
        assert_eq!(
            success.steps,
            vec![
                Bm1396StratumSubmitStep::AssignCurrentRequestId,
                Bm1396StratumSubmitStep::IncrementGlobalRequestId,
                Bm1396StratumSubmitStep::FormatMiningSubmit,
                Bm1396StratumSubmitStep::SendBeforeTrackingPublication,
                Bm1396StratumSubmitStep::InsertFourByteIdTrackingRecord,
                Bm1396StratumSubmitStep::IncrementPoolOutstandingShareCount,
            ]
        );
        let token = success
            .tracking_token()
            .expect("successful send is tracked");
        assert_eq!(token.request_id(), 41);
        assert!(!token.admits_pool_session_or_acceptance_authority());
        assert!(!success.proves_socket_delivery_or_pool_acceptance());

        let failure =
            bm1396_plan_stratum_submit_tracking(42, false, false).expect("bounded request ID");
        assert!(failure.tracking_token().is_none());
        assert_eq!(
            failure.steps.last(),
            Some(&Bm1396StratumSubmitStep::LeaveRequestUntrackedAfterSendFailure)
        );
        assert_eq!(
            bm1396_plan_stratum_submit_tracking(i32::MAX, true, false),
            Err(Bm1396StratumSubmitPlanError::RequestIdWouldOverflow { observed: i32::MAX })
        );
    }

    #[test]
    fn tracked_true_false_and_flagged_null_results_pin_stock_accounting() {
        let token = bm1396_plan_stratum_submit_tracking(7, true, false)
            .expect("bounded request ID")
            .tracking_token()
            .expect("tracked");
        let accepted =
            bm1396_plan_stratum_response(Some(7), Bm1396StratumResultValue::True, Some(token));
        assert_eq!(
            accepted.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountTrackedAccepted
        );
        assert_eq!(
            accepted.steps[1..5],
            [
                Bm1396StratumResponseStep::LookUpFourByteRequestId,
                Bm1396StratumResponseStep::RemoveMatchedTrackingBeforeAccounting,
                Bm1396StratumResponseStep::DecrementPoolOutstandingShareCount,
                Bm1396StratumResponseStep::ComputeTrackedResponseLag,
            ]
        );
        assert!(!accepted.proves_response_source_or_pool_acceptance());

        let rejected =
            bm1396_plan_stratum_response(Some(7), Bm1396StratumResultValue::False, Some(token));
        assert_eq!(
            rejected.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountTrackedRejected
        );

        let null_rejected =
            bm1396_plan_stratum_response(Some(7), Bm1396StratumResultValue::Null, Some(token));
        assert_eq!(
            null_rejected.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountTrackedRejected
        );
        let null_token = bm1396_plan_stratum_submit_tracking(8, true, true)
            .expect("bounded request ID")
            .tracking_token()
            .expect("tracked");
        let null_accepted =
            bm1396_plan_stratum_response(Some(8), Bm1396StratumResultValue::Null, Some(null_token));
        assert_eq!(
            null_accepted.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountTrackedAccepted
        );
    }

    #[test]
    fn missing_or_mismatched_ids_take_the_exact_untracked_branch() {
        let token = bm1396_plan_stratum_submit_tracking(9, true, false)
            .expect("bounded request ID")
            .tracking_token()
            .expect("tracked");
        let accepted =
            bm1396_plan_stratum_response(None, Bm1396StratumResultValue::True, Some(token));
        assert_eq!(
            accepted.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountUntrackedAccepted
        );
        let rejected =
            bm1396_plan_stratum_response(Some(10), Bm1396StratumResultValue::True, Some(token));
        assert_eq!(
            rejected.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountUntrackedAccepted
        );
        let missing = bm1396_plan_stratum_response(None, Bm1396StratumResultValue::Missing, None);
        assert_eq!(
            missing.disposition,
            Bm1396StratumResponseDisposition::StockWouldAccountUntrackedRejected
        );
        assert!(!missing.proves_response_source_or_pool_acceptance());
    }
}
