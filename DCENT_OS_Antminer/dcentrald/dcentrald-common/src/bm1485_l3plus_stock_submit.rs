//! Pure submit/pending-response replay for the exact held 2017 L3+ image.
//!
//! This begins after the BM1485 work-return path has produced a candidate
//! share. It records `FUN_000250e4`, Stratum sender `FUN_000218b8`, and
//! response parser `FUN_000201e0` without opening a socket or trusting the
//! caller-supplied work, pool, response, or request ID. No result from this
//! module grants network, mining, or accepted-share authority.

pub const BM1485_L3PLUS_STOCK_SUBMIT_JSON_BUFFER_BYTES: usize = 0x400;
pub const BM1485_L3PLUS_STOCK_MAX_EXTRANONCE2_BYTES: usize = 8;
pub const BM1485_L3PLUS_STOCK_PENDING_ALLOCATION_BYTES: usize = 0x34;
pub const BM1485_L3PLUS_STOCK_PENDING_ID_KEY_BYTES: usize = 4;
pub const BM1485_L3PLUS_STOCK_MAX_RETRY_AGE_SECONDS_INCLUSIVE: u64 = 0x77;

pub const BM1485_L3PLUS_STOCK_NON_STRATUM_THREAD_DETACHES_ONLY: bool = true;
pub const BM1485_L3PLUS_STOCK_PENDING_INSERT_AFTER_SEND_SUCCESS: bool = true;
pub const BM1485_L3PLUS_STOCK_PENDING_REMOVED_BEFORE_CLASSIFICATION: bool = true;
pub const BM1485_L3PLUS_STOCK_REQUEST_ID_HAS_WRAP_GUARD: bool = false;
pub const BM1485_L3PLUS_STOCK_RESPONSE_SOURCE_AUTHENTICATED: bool = false;
pub const BM1485_L3PLUS_STOCK_ACCEPTED_SHARE_ORACLE_RECOVERED: bool = false;
pub const BM1485_L3PLUS_STOCK_SUBMISSION_AUTHORIZES_NETWORK_IO: bool = false;
pub const BM1485_L3PLUS_STOCK_SUBMISSION_AUTHORIZES_MINING: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockSubmitRoute {
    /// Work field `+0x11c` was nonzero and stock enqueued the work for the
    /// pool-owned Stratum sender thread.
    PoolStratumQueue,
    /// Stock created a detached thread whose exact 20-byte body only detached
    /// itself and returned. It did not consume or submit the work pointer.
    DetachedNoopThread,
}

pub const fn bm1485_l3plus_stock_submit_route(
    pool_stratum_flag_nonzero: bool,
) -> Bm1485L3plusStockSubmitRoute {
    if pool_stratum_flag_nonzero {
        Bm1485L3plusStockSubmitRoute::PoolStratumQueue
    } else {
        Bm1485L3plusStockSubmitRoute::DetachedNoopThread
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockShareTuple {
    pub nonce: u32,
    pub nonce2_low: u32,
    pub nonce2_high: u32,
}

/// Exact duplicate key used by the Stratum sender before request formatting.
pub const fn bm1485_l3plus_stock_is_duplicate_share(
    previous: Bm1485L3plusStockShareTuple,
    candidate: Bm1485L3plusStockShareTuple,
) -> bool {
    previous.nonce == candidate.nonce
        && previous.nonce2_low == candidate.nonce2_low
        && previous.nonce2_high == candidate.nonce2_high
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockSubmitStringField {
    Username,
    JobId,
    Ntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1485L3plusStockSubmitError {
    Extranonce2TooLong {
        observed: usize,
    },
    UnsafeJsonString {
        field: Bm1485L3plusStockSubmitStringField,
    },
    NtimeNotEightHexBytes {
        observed: usize,
    },
    RequestIdWouldWrap,
    SubmitJsonTooLong {
        observed: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1485L3plusStockSubmitRequestPlan {
    pub request_id: u32,
    /// The same 32 bits interpreted by the stock `%d` formatter.
    pub request_id_json: i32,
    pub next_request_id: u32,
    pub username: String,
    pub job_id: String,
    pub extranonce2_hex: String,
    pub ntime_hex: String,
    pub nonce_hex: String,
    pub json: String,
    pub stock_request_buffer_bytes: usize,
    pub stock_retry_age_seconds_inclusive: u64,
    pub evidence_is_caller_supplied: bool,
}

impl Bm1485L3plusStockSubmitRequestPlan {
    pub const fn admits_network_io(&self) -> bool {
        false
    }

    pub const fn admits_mining(&self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }
}

fn safe_nonempty_unescaped_json_string(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\')
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Exact stock counter transition, including its unguarded native wrap.
pub const fn bm1485_l3plus_stock_next_request_id_exact(request_id: u32) -> u32 {
    request_id.wrapping_add(1)
}

/// Build the exact five-parameter `mining.submit` JSON mapping with additional
/// fail-closed bounds. Stock used a 0x400-byte buffer and did not guard the
/// request-ID wrap or JSON escaping; this clean planner refuses both hazards.
pub fn bm1485_l3plus_stock_submit_request_plan(
    username: &str,
    job_id: &str,
    extranonce2: &[u8],
    ntime_hex: &str,
    returned_nonce: u32,
    request_id: u32,
) -> Result<Bm1485L3plusStockSubmitRequestPlan, Bm1485L3plusStockSubmitError> {
    if extranonce2.len() > BM1485_L3PLUS_STOCK_MAX_EXTRANONCE2_BYTES {
        return Err(Bm1485L3plusStockSubmitError::Extranonce2TooLong {
            observed: extranonce2.len(),
        });
    }
    if !safe_nonempty_unescaped_json_string(username) {
        return Err(Bm1485L3plusStockSubmitError::UnsafeJsonString {
            field: Bm1485L3plusStockSubmitStringField::Username,
        });
    }
    if !safe_nonempty_unescaped_json_string(job_id) {
        return Err(Bm1485L3plusStockSubmitError::UnsafeJsonString {
            field: Bm1485L3plusStockSubmitStringField::JobId,
        });
    }
    if ntime_hex.len() != 8 || !ntime_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        if ntime_hex.len() == 8 {
            return Err(Bm1485L3plusStockSubmitError::UnsafeJsonString {
                field: Bm1485L3plusStockSubmitStringField::Ntime,
            });
        }
        return Err(Bm1485L3plusStockSubmitError::NtimeNotEightHexBytes {
            observed: ntime_hex.len(),
        });
    }
    if request_id == u32::MAX {
        return Err(Bm1485L3plusStockSubmitError::RequestIdWouldWrap);
    }

    let extranonce2_hex = lower_hex(extranonce2);
    let nonce_hex = lower_hex(&returned_nonce.to_le_bytes());
    let request_id_json = request_id as i32;
    let json = format!(
        "{{\"params\": [\"{username}\", \"{job_id}\", \"{extranonce2_hex}\", \"{ntime_hex}\", \"{nonce_hex}\"], \"id\": {request_id_json}, \"method\": \"mining.submit\"}}"
    );
    if json.len() >= BM1485_L3PLUS_STOCK_SUBMIT_JSON_BUFFER_BYTES {
        return Err(Bm1485L3plusStockSubmitError::SubmitJsonTooLong {
            observed: json.len(),
        });
    }

    Ok(Bm1485L3plusStockSubmitRequestPlan {
        request_id,
        request_id_json,
        next_request_id: request_id + 1,
        username: username.to_owned(),
        job_id: job_id.to_owned(),
        extranonce2_hex,
        ntime_hex: ntime_hex.to_owned(),
        nonce_hex,
        json,
        stock_request_buffer_bytes: BM1485_L3PLUS_STOCK_SUBMIT_JSON_BUFFER_BYTES,
        stock_retry_age_seconds_inclusive: BM1485_L3PLUS_STOCK_MAX_RETRY_AGE_SECONDS_INCLUSIVE,
        evidence_is_caller_supplied: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3plusStockPendingShare {
    pub request_id: u32,
    /// Exact native ARM little-endian four-byte hash key.
    pub request_id_key: [u8; BM1485_L3PLUS_STOCK_PENDING_ID_KEY_BYTES],
    /// Work `+0x144`; stock accepts a tracked JSON-null result only when set.
    pub accept_null_result: bool,
    pub allocation_bytes: usize,
    pub evidence_is_caller_supplied: bool,
}

impl Bm1485L3plusStockPendingShare {
    pub const fn admits_pending_table_insertion(&self) -> bool {
        false
    }
}

/// Stock inserts the pending record only after its socket helper reports
/// success. This helper records that transition without performing it.
pub const fn bm1485_l3plus_stock_pending_after_send(
    request_id: u32,
    accept_null_result: bool,
    socket_send_succeeded: bool,
) -> Option<Bm1485L3plusStockPendingShare> {
    if !socket_send_succeeded {
        return None;
    }
    Some(Bm1485L3plusStockPendingShare {
        request_id,
        request_id_key: request_id.to_le_bytes(),
        accept_null_result,
        allocation_bytes: BM1485_L3PLUS_STOCK_PENDING_ALLOCATION_BYTES,
        evidence_is_caller_supplied: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockJsonResultKind {
    Missing,
    True,
    False,
    Null,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockResponseDisposition {
    NotShareResponse,
    UntrackedWithoutResult,
    AcceptedUntracked,
    RejectedUntracked,
    AcceptedTracked,
    RejectedTracked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3plusStockResponseStep {
    DecodeJson,
    RequireRequestId,
    LookupPendingByNativeIdBytes,
    RemovePendingBeforeClassification,
    DecrementPoolOutstanding,
    ClassifyResult,
    UpdateStockAcceptedOrRejectedAccounting,
    FreeTrackedWorkAndPending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1485L3plusStockResponsePlan {
    pub disposition: Bm1485L3plusStockResponseDisposition,
    pub steps: Vec<Bm1485L3plusStockResponseStep>,
    pub matched_pending: bool,
    pub pending_removed: bool,
    pub outstanding_share_count_delta: i32,
    pub accepted_count_delta: u32,
    pub rejected_count_delta: u32,
    pub tracked_work_freed: bool,
    pub response_source_authenticated: bool,
}

impl Bm1485L3plusStockResponsePlan {
    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }

    pub const fn admits_share_accounting(&self) -> bool {
        false
    }
}

/// Replay the exact tracked/untracked Jansson result classification. A
/// candidate is tracked only when its ID equals the parsed response ID.
pub fn bm1485_l3plus_stock_response_plan(
    response_id: Option<u32>,
    result: Bm1485L3plusStockJsonResultKind,
    pending_candidate: Option<Bm1485L3plusStockPendingShare>,
) -> Bm1485L3plusStockResponsePlan {
    let mut steps = vec![
        Bm1485L3plusStockResponseStep::DecodeJson,
        Bm1485L3plusStockResponseStep::RequireRequestId,
    ];
    let Some(response_id) = response_id else {
        return Bm1485L3plusStockResponsePlan {
            disposition: Bm1485L3plusStockResponseDisposition::NotShareResponse,
            steps,
            matched_pending: false,
            pending_removed: false,
            outstanding_share_count_delta: 0,
            accepted_count_delta: 0,
            rejected_count_delta: 0,
            tracked_work_freed: false,
            response_source_authenticated: false,
        };
    };

    steps.push(Bm1485L3plusStockResponseStep::LookupPendingByNativeIdBytes);
    let pending = pending_candidate.filter(|candidate| candidate.request_id == response_id);
    let Some(pending) = pending else {
        steps.push(Bm1485L3plusStockResponseStep::ClassifyResult);
        let (disposition, accepted_count_delta, rejected_count_delta) = match result {
            Bm1485L3plusStockJsonResultKind::Missing => (
                Bm1485L3plusStockResponseDisposition::UntrackedWithoutResult,
                0,
                0,
            ),
            Bm1485L3plusStockJsonResultKind::True => (
                Bm1485L3plusStockResponseDisposition::AcceptedUntracked,
                1,
                0,
            ),
            Bm1485L3plusStockJsonResultKind::False
            | Bm1485L3plusStockJsonResultKind::Null
            | Bm1485L3plusStockJsonResultKind::Other => (
                Bm1485L3plusStockResponseDisposition::RejectedUntracked,
                0,
                1,
            ),
        };
        if accepted_count_delta != 0 || rejected_count_delta != 0 {
            steps.push(Bm1485L3plusStockResponseStep::UpdateStockAcceptedOrRejectedAccounting);
        }
        return Bm1485L3plusStockResponsePlan {
            disposition,
            steps,
            matched_pending: false,
            pending_removed: false,
            outstanding_share_count_delta: 0,
            accepted_count_delta,
            rejected_count_delta,
            tracked_work_freed: false,
            response_source_authenticated: false,
        };
    };

    steps.extend([
        Bm1485L3plusStockResponseStep::RemovePendingBeforeClassification,
        Bm1485L3plusStockResponseStep::DecrementPoolOutstanding,
        Bm1485L3plusStockResponseStep::ClassifyResult,
    ]);
    let accepted = matches!(result, Bm1485L3plusStockJsonResultKind::True)
        || (matches!(result, Bm1485L3plusStockJsonResultKind::Null) && pending.accept_null_result);
    let disposition = if accepted {
        Bm1485L3plusStockResponseDisposition::AcceptedTracked
    } else {
        Bm1485L3plusStockResponseDisposition::RejectedTracked
    };
    steps.extend([
        Bm1485L3plusStockResponseStep::UpdateStockAcceptedOrRejectedAccounting,
        Bm1485L3plusStockResponseStep::FreeTrackedWorkAndPending,
    ]);
    Bm1485L3plusStockResponsePlan {
        disposition,
        steps,
        matched_pending: true,
        pending_removed: true,
        outstanding_share_count_delta: -1,
        accepted_count_delta: u32::from(accepted),
        rejected_count_delta: u32::from(!accepted),
        tracked_work_freed: true,
        response_source_authenticated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_stratum_and_exact_detached_noop_paths() {
        assert_eq!(
            bm1485_l3plus_stock_submit_route(true),
            Bm1485L3plusStockSubmitRoute::PoolStratumQueue
        );
        assert_eq!(
            bm1485_l3plus_stock_submit_route(false),
            Bm1485L3plusStockSubmitRoute::DetachedNoopThread
        );
        assert!(BM1485_L3PLUS_STOCK_NON_STRATUM_THREAD_DETACHES_ONLY);
    }

    #[test]
    fn duplicate_key_uses_all_three_exact_words() {
        let previous = Bm1485L3plusStockShareTuple {
            nonce: 1,
            nonce2_low: 2,
            nonce2_high: 3,
        };
        assert!(bm1485_l3plus_stock_is_duplicate_share(previous, previous));
        for candidate in [
            Bm1485L3plusStockShareTuple {
                nonce: 4,
                ..previous
            },
            Bm1485L3plusStockShareTuple {
                nonce2_low: 4,
                ..previous
            },
            Bm1485L3plusStockShareTuple {
                nonce2_high: 4,
                ..previous
            },
        ] {
            assert!(!bm1485_l3plus_stock_is_duplicate_share(previous, candidate));
        }
    }

    #[test]
    fn request_plan_pins_parameter_order_and_arm_nonce_bytes() {
        let plan = bm1485_l3plus_stock_submit_request_plan(
            "worker.1",
            "job-42",
            &[0x01, 0xab],
            "65f0A1b2",
            0x1234_5678,
            7,
        )
        .unwrap();
        assert_eq!(plan.extranonce2_hex, "01ab");
        assert_eq!(plan.nonce_hex, "78563412");
        assert_eq!(plan.next_request_id, 8);
        assert_eq!(
            plan.json,
            "{\"params\": [\"worker.1\", \"job-42\", \"01ab\", \"65f0A1b2\", \"78563412\"], \"id\": 7, \"method\": \"mining.submit\"}"
        );
        assert!(!plan.admits_network_io());
        assert!(!plan.proves_pool_acceptance());

        let signed =
            bm1485_l3plus_stock_submit_request_plan("w", "j", &[], "00000000", 0, 0x8000_0000)
                .unwrap();
        assert_eq!(signed.request_id_json, i32::MIN);
        assert!(signed.json.contains("\"id\": -2147483648"));
    }

    #[test]
    fn request_plan_fail_closes_stock_bounds_and_wrap() {
        assert!(matches!(
            bm1485_l3plus_stock_submit_request_plan("w", "j", &[0; 9], "00000000", 0, 1),
            Err(Bm1485L3plusStockSubmitError::Extranonce2TooLong { observed: 9 })
        ));
        assert!(matches!(
            bm1485_l3plus_stock_submit_request_plan("w", "j", &[], "bad", 0, 1),
            Err(Bm1485L3plusStockSubmitError::NtimeNotEightHexBytes { observed: 3 })
        ));
        assert!(matches!(
            bm1485_l3plus_stock_submit_request_plan("bad\"user", "j", &[], "00000000", 0, 1),
            Err(Bm1485L3plusStockSubmitError::UnsafeJsonString { .. })
        ));
        assert_eq!(bm1485_l3plus_stock_next_request_id_exact(u32::MAX), 0);
        assert!(matches!(
            bm1485_l3plus_stock_submit_request_plan("w", "j", &[], "00000000", 0, u32::MAX),
            Err(Bm1485L3plusStockSubmitError::RequestIdWouldWrap)
        ));
        let long = "x".repeat(BM1485_L3PLUS_STOCK_SUBMIT_JSON_BUFFER_BYTES);
        assert!(matches!(
            bm1485_l3plus_stock_submit_request_plan(&long, "j", &[], "00000000", 0, 1),
            Err(Bm1485L3plusStockSubmitError::SubmitJsonTooLong { .. })
        ));
    }

    #[test]
    fn pending_is_insertable_only_after_success_and_key_is_native_le() {
        assert_eq!(
            bm1485_l3plus_stock_pending_after_send(0x1234_5678, false, false),
            None
        );
        let pending = bm1485_l3plus_stock_pending_after_send(0x1234_5678, true, true).unwrap();
        assert_eq!(pending.request_id_key, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(pending.allocation_bytes, 0x34);
        assert!(!pending.admits_pending_table_insertion());
    }

    #[test]
    fn tracked_true_and_flagged_null_accept_after_removal() {
        for (result, null_flag) in [
            (Bm1485L3plusStockJsonResultKind::True, false),
            (Bm1485L3plusStockJsonResultKind::Null, true),
        ] {
            let pending = bm1485_l3plus_stock_pending_after_send(9, null_flag, true);
            let plan = bm1485_l3plus_stock_response_plan(Some(9), result, pending);
            assert_eq!(
                plan.disposition,
                Bm1485L3plusStockResponseDisposition::AcceptedTracked
            );
            assert!(plan.pending_removed);
            assert_eq!(plan.outstanding_share_count_delta, -1);
            assert_eq!(plan.accepted_count_delta, 1);
            assert!(plan.tracked_work_freed);
            assert!(!plan.proves_pool_acceptance());
        }

        let pending = bm1485_l3plus_stock_pending_after_send(9, false, true);
        let rejected = bm1485_l3plus_stock_response_plan(
            Some(9),
            Bm1485L3plusStockJsonResultKind::Null,
            pending,
        );
        assert_eq!(
            rejected.disposition,
            Bm1485L3plusStockResponseDisposition::RejectedTracked
        );
        assert_eq!(rejected.rejected_count_delta, 1);
    }

    #[test]
    fn untracked_classification_matches_stock_weakness() {
        let missing = bm1485_l3plus_stock_response_plan(
            Some(3),
            Bm1485L3plusStockJsonResultKind::Missing,
            None,
        );
        assert_eq!(
            missing.disposition,
            Bm1485L3plusStockResponseDisposition::UntrackedWithoutResult
        );
        assert_eq!(missing.accepted_count_delta, 0);
        assert_eq!(missing.rejected_count_delta, 0);

        let accepted =
            bm1485_l3plus_stock_response_plan(Some(3), Bm1485L3plusStockJsonResultKind::True, None);
        assert_eq!(
            accepted.disposition,
            Bm1485L3plusStockResponseDisposition::AcceptedUntracked
        );
        assert_eq!(accepted.accepted_count_delta, 1);

        for result in [
            Bm1485L3plusStockJsonResultKind::False,
            Bm1485L3plusStockJsonResultKind::Null,
            Bm1485L3plusStockJsonResultKind::Other,
        ] {
            let rejected = bm1485_l3plus_stock_response_plan(Some(3), result, None);
            assert_eq!(
                rejected.disposition,
                Bm1485L3plusStockResponseDisposition::RejectedUntracked
            );
            assert_eq!(rejected.rejected_count_delta, 1);
        }

        let no_id =
            bm1485_l3plus_stock_response_plan(None, Bm1485L3plusStockJsonResultKind::True, None);
        assert_eq!(
            no_id.disposition,
            Bm1485L3plusStockResponseDisposition::NotShareResponse
        );
    }
}
