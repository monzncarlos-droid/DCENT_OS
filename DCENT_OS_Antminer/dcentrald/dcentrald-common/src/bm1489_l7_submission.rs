//! Pure submission/pending-response replay for the exact held L7 VNish image.
//!
//! This begins after a full-target share has entered the stock Stratum queue.
//! It models `FUN_0003a378`'s send-thread state transition and the share-response
//! portion of `FUN_0003c778`. All inputs are caller observations: this module
//! does not open a socket, authenticate a pool, prove request provenance, or
//! grant submission/mining authority.

pub const BM1489_L7_SUBMISSION_MAX_NONCE2_BYTES: usize = 8;
pub const BM1489_L7_SUBMISSION_REQUEST_BUFFER_BYTES: usize = 1024;
pub const BM1489_L7_SUBMISSION_RETRY_WINDOW_SECONDS: u64 = 120;
pub const BM1489_L7_SUBMISSION_RETRY_DELAY_SECONDS: u64 = 5;
pub const BM1489_L7_PENDING_SHARE_ALLOCATION_BYTES: usize = 0x48;
pub const BM1489_L7_JSON_TRUE_TYPE_TAG: u32 = 5;
pub const BM1489_L7_JSON_NULL_TYPE_TAG: u32 = 7;
pub const BM1489_L7_TRACKED_ACCEPTED_POOL_DIFFICULTY_MULTIPLIER: f64 = 512.0;

pub const BM1489_L7_SUBMISSION_THREAD_RECOVERED: bool = true;
pub const BM1489_L7_PENDING_ID_LOOKUP_RECOVERED: bool = true;
pub const BM1489_L7_ACCEPTED_RESPONSE_PREDICATE_RECOVERED: bool = true;
pub const BM1489_L7_REQUEST_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1489_L7_RESPONSE_SOURCE_AUTHENTICATED: bool = false;
pub const BM1489_L7_PENDING_INPUTS_AUTHENTICATED: bool = false;
pub const BM1489_L7_SUBMISSION_AUTHORIZES_NETWORK_IO: bool = false;
pub const BM1489_L7_SUBMISSION_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489L7PendingShare {
    /// Exact four-byte key assigned from the stock `swork_id++` counter.
    pub request_id: i32,
    /// Work field `+0x1ac`, equivalent to cgminer's `work->gbt` flag.
    pub gbt_work: bool,
    /// Work field `+0x1e0`, used for tracked accepted/rejected difficulty.
    pub work_difficulty: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489L7SubmissionInput {
    pub nonce2_len: usize,
    pub nonce: u32,
    pub nonce2: u64,
    pub previous_submitted_nonce: u32,
    pub previous_submitted_nonce2: u64,
    pub next_request_id: i32,
    pub version_mask_parameter_present: bool,
    /// Caller-observed result after stock's bounded retry policy. This is not
    /// a pool acknowledgement; it only means the request bytes reached the
    /// socket send helper successfully.
    pub socket_send_succeeded_within_window: bool,
    pub gbt_work: bool,
    pub work_difficulty: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SubmissionDisposition {
    Nonce2TooLong,
    DuplicateShareFiltered,
    SocketSendFailedAndMarkedStale,
    PendingPoolResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SubmissionStep {
    PopSubmissionQueue,
    CheckNonce2Length,
    CheckLastNonceAndNonce2,
    CommitLastNonceAndNonce2,
    AllocatePendingShare,
    AssignRequestId,
    FormatMiningSubmit,
    ApplyBoundedSocketRetryPolicy,
    InsertPendingByRequestId,
    IncrementPoolOutstandingShares,
    FreeWork,
    FreeWorkAndPending,
    IncrementStaleCounts,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bm1489L7SubmissionPlan {
    pub disposition: Bm1489L7SubmissionDisposition,
    pub steps: Vec<Bm1489L7SubmissionStep>,
    pub request_id: Option<i32>,
    pub next_request_id: i32,
    pub next_submitted_nonce: u32,
    pub next_submitted_nonce2: u64,
    /// Five stock `mining.submit` parameters, or six when the pool's version
    /// mask path contributes its extra version value.
    pub request_parameter_count: Option<u8>,
    pub pending_share: Option<Bm1489L7PendingShare>,
    pub outstanding_share_count_delta: i32,
    pub stale_share_count_delta: u64,
}

impl Bm1489L7SubmissionPlan {
    pub const fn admits_network_io_authority(&self) -> bool {
        false
    }

    pub const fn admits_mining_authority(&self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }
}

/// Replays the exact send-thread boundary after a work clone has been popped
/// from the per-pool submission queue.
pub fn bm1489_l7_submission_plan(input: Bm1489L7SubmissionInput) -> Bm1489L7SubmissionPlan {
    let mut steps = vec![
        Bm1489L7SubmissionStep::PopSubmissionQueue,
        Bm1489L7SubmissionStep::CheckNonce2Length,
    ];

    if input.nonce2_len > BM1489_L7_SUBMISSION_MAX_NONCE2_BYTES {
        steps.push(Bm1489L7SubmissionStep::FreeWork);
        return Bm1489L7SubmissionPlan {
            disposition: Bm1489L7SubmissionDisposition::Nonce2TooLong,
            steps,
            request_id: None,
            next_request_id: input.next_request_id,
            next_submitted_nonce: input.previous_submitted_nonce,
            next_submitted_nonce2: input.previous_submitted_nonce2,
            request_parameter_count: None,
            pending_share: None,
            outstanding_share_count_delta: 0,
            stale_share_count_delta: 0,
        };
    }

    steps.push(Bm1489L7SubmissionStep::CheckLastNonceAndNonce2);
    if input.nonce == input.previous_submitted_nonce
        && input.nonce2 == input.previous_submitted_nonce2
    {
        steps.push(Bm1489L7SubmissionStep::FreeWork);
        return Bm1489L7SubmissionPlan {
            disposition: Bm1489L7SubmissionDisposition::DuplicateShareFiltered,
            steps,
            request_id: None,
            next_request_id: input.next_request_id,
            next_submitted_nonce: input.previous_submitted_nonce,
            next_submitted_nonce2: input.previous_submitted_nonce2,
            request_parameter_count: None,
            pending_share: None,
            outstanding_share_count_delta: 0,
            stale_share_count_delta: 0,
        };
    }

    steps.extend([
        Bm1489L7SubmissionStep::CommitLastNonceAndNonce2,
        Bm1489L7SubmissionStep::AllocatePendingShare,
        Bm1489L7SubmissionStep::AssignRequestId,
        Bm1489L7SubmissionStep::FormatMiningSubmit,
        Bm1489L7SubmissionStep::ApplyBoundedSocketRetryPolicy,
    ]);
    let request_id = input.next_request_id;
    let next_request_id = request_id.wrapping_add(1);
    let request_parameter_count = Some(if input.version_mask_parameter_present {
        6
    } else {
        5
    });

    if !input.socket_send_succeeded_within_window {
        steps.extend([
            Bm1489L7SubmissionStep::FreeWorkAndPending,
            Bm1489L7SubmissionStep::IncrementStaleCounts,
        ]);
        return Bm1489L7SubmissionPlan {
            disposition: Bm1489L7SubmissionDisposition::SocketSendFailedAndMarkedStale,
            steps,
            request_id: Some(request_id),
            next_request_id,
            next_submitted_nonce: input.nonce,
            next_submitted_nonce2: input.nonce2,
            request_parameter_count,
            pending_share: None,
            outstanding_share_count_delta: 0,
            stale_share_count_delta: 1,
        };
    }

    steps.extend([
        Bm1489L7SubmissionStep::InsertPendingByRequestId,
        Bm1489L7SubmissionStep::IncrementPoolOutstandingShares,
    ]);
    Bm1489L7SubmissionPlan {
        disposition: Bm1489L7SubmissionDisposition::PendingPoolResponse,
        steps,
        request_id: Some(request_id),
        next_request_id,
        next_submitted_nonce: input.nonce,
        next_submitted_nonce2: input.nonce2,
        request_parameter_count,
        pending_share: Some(Bm1489L7PendingShare {
            request_id,
            gbt_work: input.gbt_work,
            work_difficulty: input.work_difficulty,
        }),
        outstanding_share_count_delta: 1,
        stale_share_count_delta: 0,
    }
}

/// Observational equivalent of the Jansson result values used by the exact
/// receiver. `Other` includes JSON false and every non-true/non-null value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7JsonResultKind {
    Missing,
    True,
    Null,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489L7ResponseInput {
    /// Missing and JSON-null IDs both stop before pending-table lookup.
    pub response_id: Option<i32>,
    pub result: Bm1489L7JsonResultKind,
    /// A caller-supplied candidate. It is tracked only when its four-byte ID
    /// equals `response_id`, matching the exact uthash key comparison.
    pub pending_candidate: Option<Bm1489L7PendingShare>,
    /// Used for an untracked response with a present result and for the exact
    /// optional tracked-acceptance difficulty cap.
    pub current_pool_difficulty: f64,
    /// Exact pool-mode branch at `FUN_0003c778`: when set, a tracked accepted
    /// share credits at most current pool difficulty times 512. Rejected
    /// tracked shares still charge the retained work difficulty.
    pub cap_tracked_accepted_difficulty_to_pool_times_512: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7ResponseDisposition {
    NotShareResponse,
    UntrackedWithoutResult,
    AcceptedUntracked,
    RejectedUntracked,
    AcceptedTracked,
    RejectedTracked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7ResponseStep {
    DecodeJson,
    RequireNonNullId,
    LookupPendingByFourByteId,
    RemovePendingBeforeAccounting,
    DecrementPoolOutstandingShares,
    ClassifyResult,
    AttributePoolCounters,
    AttributeDeviceCounters,
    FreeTrackedWorkAndPending,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bm1489L7ResponsePlan {
    pub disposition: Bm1489L7ResponseDisposition,
    pub steps: Vec<Bm1489L7ResponseStep>,
    pub tracked_pending_removed: bool,
    pub outstanding_share_count_delta: i32,
    pub accepted_share_count_delta: u64,
    pub rejected_share_count_delta: u64,
    pub accepted_difficulty_delta: f64,
    pub rejected_difficulty_delta: f64,
    pub device_attributed: bool,
    /// Exact parser return: true only when a pending record matched, even
    /// though untracked responses can still alter pool/global counters.
    pub receiver_reports_tracked_response: bool,
}

impl Bm1489L7ResponsePlan {
    pub const fn admits_network_io_authority(&self) -> bool {
        false
    }

    pub const fn proves_response_source(&self) -> bool {
        false
    }

    pub const fn admits_mining_authority(&self) -> bool {
        false
    }
}

pub fn bm1489_l7_response_plan(input: Bm1489L7ResponseInput) -> Bm1489L7ResponsePlan {
    let mut steps = vec![
        Bm1489L7ResponseStep::DecodeJson,
        Bm1489L7ResponseStep::RequireNonNullId,
    ];
    let Some(response_id) = input.response_id else {
        return Bm1489L7ResponsePlan {
            disposition: Bm1489L7ResponseDisposition::NotShareResponse,
            steps,
            tracked_pending_removed: false,
            outstanding_share_count_delta: 0,
            accepted_share_count_delta: 0,
            rejected_share_count_delta: 0,
            accepted_difficulty_delta: 0.0,
            rejected_difficulty_delta: 0.0,
            device_attributed: false,
            receiver_reports_tracked_response: false,
        };
    };

    steps.push(Bm1489L7ResponseStep::LookupPendingByFourByteId);
    let pending = input
        .pending_candidate
        .filter(|candidate| candidate.request_id == response_id);

    if let Some(pending) = pending {
        steps.extend([
            Bm1489L7ResponseStep::RemovePendingBeforeAccounting,
            Bm1489L7ResponseStep::DecrementPoolOutstandingShares,
            Bm1489L7ResponseStep::ClassifyResult,
            Bm1489L7ResponseStep::AttributePoolCounters,
            Bm1489L7ResponseStep::AttributeDeviceCounters,
            Bm1489L7ResponseStep::FreeTrackedWorkAndPending,
        ]);
        let accepted = input.result == Bm1489L7JsonResultKind::True
            || (input.result == Bm1489L7JsonResultKind::Null && pending.gbt_work);
        let accepted_difficulty = if accepted {
            if input.cap_tracked_accepted_difficulty_to_pool_times_512 {
                let cap = input.current_pool_difficulty
                    * BM1489_L7_TRACKED_ACCEPTED_POOL_DIFFICULTY_MULTIPLIER;
                if pending.work_difficulty <= cap {
                    pending.work_difficulty
                } else {
                    cap
                }
            } else {
                pending.work_difficulty
            }
        } else {
            0.0
        };
        return Bm1489L7ResponsePlan {
            disposition: if accepted {
                Bm1489L7ResponseDisposition::AcceptedTracked
            } else {
                Bm1489L7ResponseDisposition::RejectedTracked
            },
            steps,
            tracked_pending_removed: true,
            outstanding_share_count_delta: -1,
            accepted_share_count_delta: u64::from(accepted),
            rejected_share_count_delta: u64::from(!accepted),
            accepted_difficulty_delta: accepted_difficulty,
            rejected_difficulty_delta: if accepted {
                0.0
            } else {
                pending.work_difficulty
            },
            device_attributed: true,
            receiver_reports_tracked_response: true,
        };
    }

    if input.result == Bm1489L7JsonResultKind::Missing {
        return Bm1489L7ResponsePlan {
            disposition: Bm1489L7ResponseDisposition::UntrackedWithoutResult,
            steps,
            tracked_pending_removed: false,
            outstanding_share_count_delta: 0,
            accepted_share_count_delta: 0,
            rejected_share_count_delta: 0,
            accepted_difficulty_delta: 0.0,
            rejected_difficulty_delta: 0.0,
            device_attributed: false,
            receiver_reports_tracked_response: false,
        };
    }

    steps.extend([
        Bm1489L7ResponseStep::ClassifyResult,
        Bm1489L7ResponseStep::AttributePoolCounters,
    ]);
    let accepted = input.result == Bm1489L7JsonResultKind::True;
    Bm1489L7ResponsePlan {
        disposition: if accepted {
            Bm1489L7ResponseDisposition::AcceptedUntracked
        } else {
            Bm1489L7ResponseDisposition::RejectedUntracked
        },
        steps,
        tracked_pending_removed: false,
        outstanding_share_count_delta: 0,
        accepted_share_count_delta: u64::from(accepted),
        rejected_share_count_delta: u64::from(!accepted),
        accepted_difficulty_delta: if accepted {
            input.current_pool_difficulty
        } else {
            0.0
        },
        rejected_difficulty_delta: if accepted {
            0.0
        } else {
            input.current_pool_difficulty
        },
        device_attributed: false,
        receiver_reports_tracked_response: false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1489L7PendingClearPlan {
    pub outstanding_share_count_delta: i32,
    pub stale_share_count_delta: u64,
    pub stale_difficulty_delta: f64,
    pub tracked_work_and_pending_freed: bool,
}

impl Bm1489L7PendingClearPlan {
    pub const fn admits_network_io_authority(&self) -> bool {
        false
    }
}

/// Exact one-entry contribution of `FUN_0002b2e0`/`clear_stratum_shares`.
pub const fn bm1489_l7_clear_pending_share(
    pending: Bm1489L7PendingShare,
) -> Bm1489L7PendingClearPlan {
    Bm1489L7PendingClearPlan {
        outstanding_share_count_delta: -1,
        stale_share_count_delta: 1,
        stale_difficulty_delta: pending.work_difficulty,
        tracked_work_and_pending_freed: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission_input() -> Bm1489L7SubmissionInput {
        Bm1489L7SubmissionInput {
            nonce2_len: 4,
            nonce: 0x1122_3344,
            nonce2: 0x0102_0304_0506_0708,
            previous_submitted_nonce: 0,
            previous_submitted_nonce2: 0,
            next_request_id: 41,
            version_mask_parameter_present: false,
            socket_send_succeeded_within_window: true,
            gbt_work: false,
            work_difficulty: 128.0,
        }
    }

    fn pending(id: i32, gbt_work: bool, difficulty: f64) -> Bm1489L7PendingShare {
        Bm1489L7PendingShare {
            request_id: id,
            gbt_work,
            work_difficulty: difficulty,
        }
    }

    #[test]
    fn exact_submission_constants_are_pinned() {
        assert_eq!(BM1489_L7_SUBMISSION_MAX_NONCE2_BYTES, 8);
        assert_eq!(BM1489_L7_SUBMISSION_REQUEST_BUFFER_BYTES, 1024);
        assert_eq!(BM1489_L7_SUBMISSION_RETRY_WINDOW_SECONDS, 120);
        assert_eq!(BM1489_L7_SUBMISSION_RETRY_DELAY_SECONDS, 5);
        assert_eq!(BM1489_L7_PENDING_SHARE_ALLOCATION_BYTES, 0x48);
        assert_eq!(BM1489_L7_JSON_TRUE_TYPE_TAG, 5);
        assert_eq!(BM1489_L7_JSON_NULL_TYPE_TAG, 7);
        assert_eq!(BM1489_L7_TRACKED_ACCEPTED_POOL_DIFFICULTY_MULTIPLIER, 512.0);
    }

    #[test]
    fn nonce2_over_eight_bytes_is_freed_without_consuming_id_or_last_pair() {
        let input = Bm1489L7SubmissionInput {
            nonce2_len: 9,
            ..submission_input()
        };
        let plan = bm1489_l7_submission_plan(input);
        assert_eq!(
            plan.disposition,
            Bm1489L7SubmissionDisposition::Nonce2TooLong
        );
        assert_eq!(plan.request_id, None);
        assert_eq!(plan.next_request_id, input.next_request_id);
        assert_eq!(plan.next_submitted_nonce, input.previous_submitted_nonce);
        assert_eq!(plan.next_submitted_nonce2, input.previous_submitted_nonce2);
    }

    #[test]
    fn duplicate_pair_is_filtered_before_request_id_allocation() {
        let input = Bm1489L7SubmissionInput {
            previous_submitted_nonce: 0x1122_3344,
            previous_submitted_nonce2: 0x0102_0304_0506_0708,
            ..submission_input()
        };
        let plan = bm1489_l7_submission_plan(input);
        assert_eq!(
            plan.disposition,
            Bm1489L7SubmissionDisposition::DuplicateShareFiltered
        );
        assert_eq!(plan.request_id, None);
        assert_eq!(plan.next_request_id, 41);
    }

    #[test]
    fn socket_send_failure_consumes_id_and_last_pair_but_creates_no_pending_entry() {
        let input = Bm1489L7SubmissionInput {
            socket_send_succeeded_within_window: false,
            ..submission_input()
        };
        let plan = bm1489_l7_submission_plan(input);
        assert_eq!(
            plan.disposition,
            Bm1489L7SubmissionDisposition::SocketSendFailedAndMarkedStale
        );
        assert_eq!(plan.request_id, Some(41));
        assert_eq!(plan.next_request_id, 42);
        assert_eq!(plan.next_submitted_nonce, input.nonce);
        assert_eq!(plan.next_submitted_nonce2, input.nonce2);
        assert_eq!(plan.pending_share, None);
        assert_eq!(plan.stale_share_count_delta, 1);
        assert_eq!(plan.outstanding_share_count_delta, 0);
    }

    #[test]
    fn successful_send_creates_pending_entry_but_does_not_prove_acceptance() {
        let mut input = submission_input();
        input.version_mask_parameter_present = true;
        let plan = bm1489_l7_submission_plan(input);
        assert_eq!(
            plan.disposition,
            Bm1489L7SubmissionDisposition::PendingPoolResponse
        );
        assert_eq!(plan.request_parameter_count, Some(6));
        assert_eq!(plan.outstanding_share_count_delta, 1);
        assert_eq!(plan.pending_share, Some(pending(41, false, 128.0)));
        assert!(!plan.proves_pool_acceptance());
        assert!(!plan.admits_network_io_authority());
    }

    #[test]
    fn request_id_increment_matches_native_wrapping_add() {
        let input = Bm1489L7SubmissionInput {
            next_request_id: i32::MAX,
            ..submission_input()
        };
        let plan = bm1489_l7_submission_plan(input);
        assert_eq!(plan.request_id, Some(i32::MAX));
        assert_eq!(plan.next_request_id, i32::MIN);
    }

    #[test]
    fn tracked_true_response_is_the_normal_accepted_share_oracle() {
        let plan = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: Some(7),
            result: Bm1489L7JsonResultKind::True,
            pending_candidate: Some(pending(7, false, 512.0)),
            current_pool_difficulty: 64.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: false,
        });
        assert_eq!(
            plan.disposition,
            Bm1489L7ResponseDisposition::AcceptedTracked
        );
        assert!(plan.tracked_pending_removed);
        assert_eq!(plan.outstanding_share_count_delta, -1);
        assert_eq!(plan.accepted_share_count_delta, 1);
        assert_eq!(plan.accepted_difficulty_delta, 512.0);
        assert!(plan.device_attributed);
        assert!(plan.receiver_reports_tracked_response);
        assert!(!plan.proves_response_source());
    }

    #[test]
    fn tracked_null_is_accepted_only_for_gbt_work() {
        for (gbt_work, expected) in [
            (true, Bm1489L7ResponseDisposition::AcceptedTracked),
            (false, Bm1489L7ResponseDisposition::RejectedTracked),
        ] {
            let plan = bm1489_l7_response_plan(Bm1489L7ResponseInput {
                response_id: Some(9),
                result: Bm1489L7JsonResultKind::Null,
                pending_candidate: Some(pending(9, gbt_work, 32.0)),
                current_pool_difficulty: 4.0,
                cap_tracked_accepted_difficulty_to_pool_times_512: false,
            });
            assert_eq!(plan.disposition, expected);
            assert!(plan.tracked_pending_removed);
        }
    }

    #[test]
    fn tracked_missing_result_is_rejected_after_pending_removal() {
        let plan = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: Some(12),
            result: Bm1489L7JsonResultKind::Missing,
            pending_candidate: Some(pending(12, true, 16.0)),
            current_pool_difficulty: 4.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: false,
        });
        assert_eq!(
            plan.disposition,
            Bm1489L7ResponseDisposition::RejectedTracked
        );
        assert_eq!(plan.rejected_share_count_delta, 1);
        assert_eq!(plan.rejected_difficulty_delta, 16.0);
        assert!(plan.receiver_reports_tracked_response);
    }

    #[test]
    fn untracked_true_uses_current_pool_difficulty_without_device_attribution() {
        let plan = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: Some(99),
            result: Bm1489L7JsonResultKind::True,
            pending_candidate: Some(pending(98, false, 1024.0)),
            current_pool_difficulty: 8.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: false,
        });
        assert_eq!(
            plan.disposition,
            Bm1489L7ResponseDisposition::AcceptedUntracked
        );
        assert_eq!(plan.accepted_difficulty_delta, 8.0);
        assert!(!plan.device_attributed);
        assert!(!plan.receiver_reports_tracked_response);
        assert!(!plan.tracked_pending_removed);
    }

    #[test]
    fn untracked_missing_result_and_missing_id_do_not_account_a_share() {
        let untracked = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: Some(99),
            result: Bm1489L7JsonResultKind::Missing,
            pending_candidate: None,
            current_pool_difficulty: 8.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: false,
        });
        assert_eq!(
            untracked.disposition,
            Bm1489L7ResponseDisposition::UntrackedWithoutResult
        );
        let no_id = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: None,
            result: Bm1489L7JsonResultKind::True,
            pending_candidate: Some(pending(0, false, 8.0)),
            current_pool_difficulty: 8.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: false,
        });
        assert_eq!(
            no_id.disposition,
            Bm1489L7ResponseDisposition::NotShareResponse
        );
        assert_eq!(no_id.accepted_share_count_delta, 0);
    }

    #[test]
    fn untracked_nontrue_result_is_rejected_at_current_pool_difficulty() {
        let plan = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: Some(21),
            result: Bm1489L7JsonResultKind::Other,
            pending_candidate: None,
            current_pool_difficulty: 256.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: false,
        });
        assert_eq!(
            plan.disposition,
            Bm1489L7ResponseDisposition::RejectedUntracked
        );
        assert_eq!(plan.rejected_share_count_delta, 1);
        assert_eq!(plan.rejected_difficulty_delta, 256.0);
        assert!(!plan.device_attributed);
    }

    #[test]
    fn exact_optional_tracked_acceptance_cap_uses_pool_difficulty_times_512() {
        let plan = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            response_id: Some(31),
            result: Bm1489L7JsonResultKind::True,
            pending_candidate: Some(pending(31, false, 4097.0)),
            current_pool_difficulty: 8.0,
            cap_tracked_accepted_difficulty_to_pool_times_512: true,
        });
        assert_eq!(
            plan.disposition,
            Bm1489L7ResponseDisposition::AcceptedTracked
        );
        assert_eq!(plan.accepted_difficulty_delta, 4096.0);

        let below_cap = bm1489_l7_response_plan(Bm1489L7ResponseInput {
            pending_candidate: Some(pending(31, false, 4095.0)),
            ..Bm1489L7ResponseInput {
                response_id: Some(31),
                result: Bm1489L7JsonResultKind::True,
                pending_candidate: None,
                current_pool_difficulty: 8.0,
                cap_tracked_accepted_difficulty_to_pool_times_512: true,
            }
        });
        assert_eq!(below_cap.accepted_difficulty_delta, 4095.0);
    }

    #[test]
    fn disconnect_clear_marks_each_pending_share_stale_and_frees_it() {
        let plan = bm1489_l7_clear_pending_share(pending(5, false, 64.0));
        assert_eq!(plan.outstanding_share_count_delta, -1);
        assert_eq!(plan.stale_share_count_delta, 1);
        assert_eq!(plan.stale_difficulty_delta, 64.0);
        assert!(plan.tracked_work_and_pending_freed);
        assert!(!plan.admits_network_io_authority());
    }

    #[test]
    fn recovered_predicates_do_not_promote_authority() {
        assert!(BM1489_L7_SUBMISSION_THREAD_RECOVERED);
        assert!(BM1489_L7_PENDING_ID_LOOKUP_RECOVERED);
        assert!(BM1489_L7_ACCEPTED_RESPONSE_PREDICATE_RECOVERED);
        assert!(!BM1489_L7_REQUEST_PROVENANCE_AUTHENTICATED);
        assert!(!BM1489_L7_RESPONSE_SOURCE_AUTHENTICATED);
        assert!(!BM1489_L7_PENDING_INPUTS_AUTHENTICATED);
        assert!(!BM1489_L7_SUBMISSION_AUTHORIZES_NETWORK_IO);
        assert!(!BM1489_L7_SUBMISSION_AUTHORIZES_MINING);
    }
}
