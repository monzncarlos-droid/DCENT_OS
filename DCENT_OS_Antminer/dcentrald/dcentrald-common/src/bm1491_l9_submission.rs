//! Exact held-release BM1491/L9 nonce-to-Stratum submission replay.
//!
//! This module records the stock staging, JSON, retry, and response-accounting
//! decisions without opening a socket or trusting a caller-supplied pool,
//! snapshot, nonce, or response. No result grants submission or acceptance
//! authority.

pub const BM1491_L9_NONCE_SUBMIT_THREAD_ADDRESS: u32 = 0x0003_1518;
pub const BM1491_L9_WORKIO_SUBMIT_ADDRESS: u32 = 0x0003_0514;
pub const BM1491_L9_SUBMIT_FORMATTER_ADDRESS: u32 = 0x0005_8c9c;
pub const BM1491_L9_RETURN_BINDER_ADDRESS: u32 = 0x0008_15ac;
pub const BM1491_L9_STRATUM_RESPONSE_ADDRESS: u32 = 0x0005_2104;
pub const BM1491_L9_SHARE_RESULT_ADDRESS: u32 = 0x0003_b534;

pub const BM1491_L9_POOL_WORK_COPY_LEN: usize = 0x470;
pub const BM1491_L9_JOB_ID_COPY_CAPACITY: usize = 0x40;
pub const BM1491_L9_SUBMIT_JSON_CAPACITY: usize = 0x0c00;
pub const BM1491_L9_RETURNED_NONCE_BYTES: usize = 4;
pub const BM1491_L9_MAX_EXTRANONCE2_BYTES: usize = 8;
pub const BM1491_L9_SUBMIT_MAX_ATTEMPTS: usize = 4;
pub const BM1491_L9_SEND_SUCCESS: u8 = 1;
pub const BM1491_L9_FIRST_SHARE_RESPONSE_ID: i64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SubmitStringField {
    Worker,
    CurrentWorkJobId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1491L9SubmissionError {
    PoolIndexOutsideTable { observed: u64, pool_count: usize },
    PoolEntryMissing { index: usize },
    ExpectedExtranonce2TooLong { observed: usize },
    Extranonce2LengthMismatch { expected: usize, observed: usize },
    UnsafeJsonString { field: Bm1491L9SubmitStringField },
    SubmitJsonTooLong { observed: usize },
    IncompleteSendObservations { observed: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9PoolSelection {
    Selected { index: usize },
}

impl Bm1491L9PoolSelection {
    pub const fn admits_network_io(self) -> bool {
        false
    }
}

/// Replay the exact unsigned pool-index bound and null-entry drop.
pub fn bm1491_l9_select_nonce_pool(
    pool_index: u64,
    pool_count: usize,
    selected_entry_present: bool,
) -> Result<Bm1491L9PoolSelection, Bm1491L9SubmissionError> {
    let index = usize::try_from(pool_index).map_err(|_| {
        Bm1491L9SubmissionError::PoolIndexOutsideTable {
            observed: pool_index,
            pool_count,
        }
    })?;
    if index >= pool_count {
        return Err(Bm1491L9SubmissionError::PoolIndexOutsideTable {
            observed: pool_index,
            pool_count,
        });
    }
    if !selected_entry_present {
        return Err(Bm1491L9SubmissionError::PoolEntryMissing { index });
    }
    Ok(Bm1491L9PoolSelection::Selected { index })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1491L9PreparedSubmit {
    pub request_id: i32,
    pub next_request_id: i32,
    pub worker: String,
    pub job_id: String,
    pub extranonce2_hex: String,
    pub ntime_hex: String,
    pub nonce_hex: String,
    pub json: String,
    pub stock_work_copy_len: usize,
    pub stock_formatter_result_was_ignored: bool,
    pub evidence_is_forgeable: bool,
}

impl Bm1491L9PreparedSubmit {
    pub const fn admits_network_io(&self) -> bool {
        false
    }

    pub const fn admits_share_submission(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1491L9PreSubmitDisposition {
    StaleStockCode1 {
        job_id_mismatch: bool,
        extranonce2_length_mismatch: bool,
        stock_accounts_stale_difficulty: bool,
    },
    Prepared(Bm1491L9PreparedSubmit),
}

fn safe_unescaped_json_string(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9PreSubmitInput<'a> {
    pub request_id: i32,
    pub worker: &'a str,
    /// Job string in the copied current pool-work record used by the formatter.
    pub current_work_job_id: &'a str,
    /// Current pool job pointer. Stock bypasses the comparison when it is null.
    pub pool_current_job_id: Option<&'a str>,
    /// Job string retained with the returned nonce snapshot.
    pub returned_job_id: &'a str,
    pub expected_extranonce2_len: usize,
    pub returned_extranonce2: &'a [u8],
    /// Four return bytes converted as big-endian to a native word before hex.
    pub returned_nonce_bytes: [u8; BM1491_L9_RETURNED_NONCE_BYTES],
    /// Native word copied into the work record before `bin2hex`.
    pub returned_ntime_word: u32,
}

/// Replay the L9 `dhash_content` binder followed by the base submit formatter.
pub fn bm1491_l9_prepare_submit(
    input: Bm1491L9PreSubmitInput<'_>,
) -> Result<Bm1491L9PreSubmitDisposition, Bm1491L9SubmissionError> {
    if input.expected_extranonce2_len > BM1491_L9_MAX_EXTRANONCE2_BYTES {
        return Err(Bm1491L9SubmissionError::ExpectedExtranonce2TooLong {
            observed: input.expected_extranonce2_len,
        });
    }

    let job_id_mismatch = input
        .pool_current_job_id
        .is_some_and(|current| current != input.returned_job_id);
    let extranonce2_length_mismatch =
        input.expected_extranonce2_len != input.returned_extranonce2.len();
    if job_id_mismatch || extranonce2_length_mismatch {
        return Ok(Bm1491L9PreSubmitDisposition::StaleStockCode1 {
            job_id_mismatch,
            extranonce2_length_mismatch,
            stock_accounts_stale_difficulty: true,
        });
    }

    if !safe_unescaped_json_string(input.worker) {
        return Err(Bm1491L9SubmissionError::UnsafeJsonString {
            field: Bm1491L9SubmitStringField::Worker,
        });
    }
    if !safe_unescaped_json_string(input.current_work_job_id)
        || input.current_work_job_id.len() >= BM1491_L9_JOB_ID_COPY_CAPACITY
    {
        return Err(Bm1491L9SubmissionError::UnsafeJsonString {
            field: Bm1491L9SubmitStringField::CurrentWorkJobId,
        });
    }

    let extranonce2_hex = lower_hex(input.returned_extranonce2);
    let nonce_word = u32::from_be_bytes(input.returned_nonce_bytes);
    let nonce_hex = lower_hex(&nonce_word.to_le_bytes());
    let ntime_hex = lower_hex(&input.returned_ntime_word.to_le_bytes());
    let json = format!(
        "{{\"id\":{},\"method\":\"mining.submit\",\"params\":[\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"]}}",
        input.request_id,
        input.worker,
        input.current_work_job_id,
        extranonce2_hex,
        ntime_hex,
        nonce_hex,
    );
    if json.len() >= BM1491_L9_SUBMIT_JSON_CAPACITY {
        return Err(Bm1491L9SubmissionError::SubmitJsonTooLong {
            observed: json.len(),
        });
    }

    Ok(Bm1491L9PreSubmitDisposition::Prepared(
        Bm1491L9PreparedSubmit {
            request_id: input.request_id,
            next_request_id: input.request_id.wrapping_add(1),
            worker: input.worker.to_owned(),
            job_id: input.current_work_job_id.to_owned(),
            extranonce2_hex,
            ntime_hex,
            nonce_hex,
            json,
            stock_work_copy_len: BM1491_L9_POOL_WORK_COPY_LEN,
            stock_formatter_result_was_ignored: true,
            evidence_is_forgeable: true,
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9SendDisposition {
    IdlePoolStockReturn0,
    SentStockReturn1,
    Exhausted { last_result: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9SendReplay {
    pub disposition: Bm1491L9SendDisposition,
    pub attempts: usize,
    pub failed_attempt_accounting_increments: usize,
    pub each_attempt_uses_pool_send_mutex: bool,
    pub caller_ignores_final_result: bool,
}

impl Bm1491L9SendReplay {
    pub const fn admits_network_io(&self) -> bool {
        false
    }
}

/// Replay up to four stock socket-send results. A complete all-failure replay
/// must supply four observations; a success terminates immediately.
pub fn bm1491_l9_replay_send_attempts(
    pool_is_idle: bool,
    observed_results: &[u8],
) -> Result<Bm1491L9SendReplay, Bm1491L9SubmissionError> {
    if pool_is_idle {
        return Ok(Bm1491L9SendReplay {
            disposition: Bm1491L9SendDisposition::IdlePoolStockReturn0,
            attempts: 0,
            failed_attempt_accounting_increments: 0,
            each_attempt_uses_pool_send_mutex: true,
            caller_ignores_final_result: true,
        });
    }

    let mut failures = 0;
    for (index, result) in observed_results
        .iter()
        .copied()
        .take(BM1491_L9_SUBMIT_MAX_ATTEMPTS)
        .enumerate()
    {
        if result == BM1491_L9_SEND_SUCCESS {
            return Ok(Bm1491L9SendReplay {
                disposition: Bm1491L9SendDisposition::SentStockReturn1,
                attempts: index + 1,
                failed_attempt_accounting_increments: failures,
                each_attempt_uses_pool_send_mutex: true,
                caller_ignores_final_result: true,
            });
        }
        failures += 1;
    }
    if observed_results.len() < BM1491_L9_SUBMIT_MAX_ATTEMPTS {
        return Err(Bm1491L9SubmissionError::IncompleteSendObservations {
            observed: observed_results.len(),
        });
    }
    Ok(Bm1491L9SendReplay {
        disposition: Bm1491L9SendDisposition::Exhausted {
            last_result: observed_results[BM1491_L9_SUBMIT_MAX_ATTEMPTS - 1],
        },
        attempts: BM1491_L9_SUBMIT_MAX_ATTEMPTS,
        failed_attempt_accounting_increments: BM1491_L9_SUBMIT_MAX_ATTEMPTS,
        each_attempt_uses_pool_send_mutex: true,
        caller_ignores_final_result: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ResponseResult {
    Missing,
    Null,
    False,
    True,
    StringOk,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ResponseError<'a> {
    Missing,
    Null,
    ArrayIndexOneString(Option<&'a str>),
    DirectString(&'a str),
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ResponseId {
    Missing,
    Null,
    Integer(i64),
    OtherJsonType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9ResponseObservation<'a> {
    pub json_decode_succeeded: bool,
    pub result: Bm1491L9ResponseResult,
    pub error: Bm1491L9ResponseError<'a>,
    pub id: Bm1491L9ResponseId,
    /// Stock pool byte `+0x678`: false uses error array index one; true uses a
    /// direct error string and does not reserve IDs below four.
    pub direct_error_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ResponseDisposition<'a> {
    JsonDecodeFailed,
    LogNullIdNoAccounting,
    ReservedOrUntrackedNoAccounting,
    AccountShare {
        accepted: bool,
        rejection_reason: Option<&'a str>,
        share_result_returns_one: bool,
        response_handler_returns_one: bool,
        stock_only_applies_id_floor_without_outstanding_request_match: bool,
    },
}

impl Bm1491L9ResponseDisposition<'_> {
    pub const fn admits_pool_acceptance_authority(self) -> bool {
        false
    }
}

fn stock_response_accepted(
    result: Bm1491L9ResponseResult,
    error: Bm1491L9ResponseError<'_>,
) -> bool {
    match result {
        Bm1491L9ResponseResult::True => matches!(
            error,
            Bm1491L9ResponseError::Missing | Bm1491L9ResponseError::Null
        ),
        Bm1491L9ResponseResult::StringOk => matches!(error, Bm1491L9ResponseError::Null),
        _ => false,
    }
}

/// Replay `stratum_handle_response_base` after JSON parsing. This classifies
/// caller-supplied values only; even `accepted: true` is not authenticated
/// pool acceptance.
pub fn bm1491_l9_classify_stratum_response<'a>(
    observation: Bm1491L9ResponseObservation<'a>,
) -> Bm1491L9ResponseDisposition<'a> {
    if !observation.json_decode_succeeded {
        return Bm1491L9ResponseDisposition::JsonDecodeFailed;
    }
    if matches!(
        observation.id,
        Bm1491L9ResponseId::Missing | Bm1491L9ResponseId::Null
    ) {
        return Bm1491L9ResponseDisposition::LogNullIdNoAccounting;
    }

    if !observation.direct_error_mode {
        let id_value = match observation.id {
            Bm1491L9ResponseId::Integer(value) => value,
            Bm1491L9ResponseId::OtherJsonType => 0,
            Bm1491L9ResponseId::Missing | Bm1491L9ResponseId::Null => {
                return Bm1491L9ResponseDisposition::LogNullIdNoAccounting;
            }
        };
        if observation.result == Bm1491L9ResponseResult::Missing
            || id_value < BM1491_L9_FIRST_SHARE_RESPONSE_ID
        {
            return Bm1491L9ResponseDisposition::ReservedOrUntrackedNoAccounting;
        }
    } else if observation.result == Bm1491L9ResponseResult::Missing
        && observation.error == Bm1491L9ResponseError::Missing
    {
        return Bm1491L9ResponseDisposition::ReservedOrUntrackedNoAccounting;
    }

    let accepted = stock_response_accepted(observation.result, observation.error);
    let rejection_reason = if accepted {
        None
    } else if observation.direct_error_mode {
        match observation.error {
            Bm1491L9ResponseError::DirectString(reason) => Some(reason),
            _ => None,
        }
    } else {
        match observation.error {
            Bm1491L9ResponseError::ArrayIndexOneString(reason) => reason,
            _ => None,
        }
    };
    Bm1491L9ResponseDisposition::AccountShare {
        accepted,
        rejection_reason,
        share_result_returns_one: true,
        response_handler_returns_one: true,
        stock_only_applies_id_floor_without_outstanding_request_match: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_submit<'a>() -> Bm1491L9PreSubmitInput<'a> {
        Bm1491L9PreSubmitInput {
            request_id: 4,
            worker: "wallet.worker",
            current_work_job_id: "job-7",
            pool_current_job_id: Some("job-7"),
            returned_job_id: "job-7",
            expected_extranonce2_len: 4,
            returned_extranonce2: &[1, 2, 3, 4],
            returned_nonce_bytes: [0x12, 0x34, 0x56, 0x78],
            returned_ntime_word: 0x1122_3344,
        }
    }

    #[test]
    fn pool_selection_refuses_outside_and_null_entries_without_authority() {
        assert_eq!(
            bm1491_l9_select_nonce_pool(2, 3, true),
            Ok(Bm1491L9PoolSelection::Selected { index: 2 })
        );
        assert_eq!(
            bm1491_l9_select_nonce_pool(3, 3, true),
            Err(Bm1491L9SubmissionError::PoolIndexOutsideTable {
                observed: 3,
                pool_count: 3,
            })
        );
        assert_eq!(
            bm1491_l9_select_nonce_pool(1, 3, false),
            Err(Bm1491L9SubmissionError::PoolEntryMissing { index: 1 })
        );
        assert!(!Bm1491L9PoolSelection::Selected { index: 0 }.admits_network_io());
    }

    #[test]
    fn exact_submit_json_pins_parameter_order_and_byte_transforms() {
        let Bm1491L9PreSubmitDisposition::Prepared(prepared) =
            bm1491_l9_prepare_submit(base_submit()).unwrap()
        else {
            panic!("expected prepared submission");
        };
        assert_eq!(prepared.extranonce2_hex, "01020304");
        assert_eq!(prepared.ntime_hex, "44332211");
        assert_eq!(prepared.nonce_hex, "78563412");
        assert_eq!(
            prepared.json,
            "{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"wallet.worker\",\"job-7\",\"01020304\",\"44332211\",\"78563412\"]}"
        );
        assert_eq!(prepared.next_request_id, 5);
        assert!(prepared.stock_formatter_result_was_ignored);
        assert!(!prepared.admits_network_io());
        assert!(!prepared.admits_share_submission());
    }

    #[test]
    fn job_and_private_length_mismatches_take_stock_stale_path() {
        let mut input = base_submit();
        input.returned_job_id = "old-job";
        assert!(matches!(
            bm1491_l9_prepare_submit(input).unwrap(),
            Bm1491L9PreSubmitDisposition::StaleStockCode1 {
                job_id_mismatch: true,
                extranonce2_length_mismatch: false,
                ..
            }
        ));

        input = base_submit();
        input.pool_current_job_id = None;
        input.returned_job_id = "old-job";
        assert!(matches!(
            bm1491_l9_prepare_submit(input).unwrap(),
            Bm1491L9PreSubmitDisposition::Prepared(_)
        ));

        input = base_submit();
        input.returned_extranonce2 = &[1, 2, 3];
        assert!(matches!(
            bm1491_l9_prepare_submit(input).unwrap(),
            Bm1491L9PreSubmitDisposition::StaleStockCode1 {
                extranonce2_length_mismatch: true,
                ..
            }
        ));
    }

    #[test]
    fn forged_strings_lengths_and_formatter_capacity_fail_closed() {
        let mut input = base_submit();
        input.expected_extranonce2_len = 9;
        assert_eq!(
            bm1491_l9_prepare_submit(input),
            Err(Bm1491L9SubmissionError::ExpectedExtranonce2TooLong { observed: 9 })
        );
        input = base_submit();
        input.worker = "bad\"worker";
        assert_eq!(
            bm1491_l9_prepare_submit(input),
            Err(Bm1491L9SubmissionError::UnsafeJsonString {
                field: Bm1491L9SubmitStringField::Worker,
            })
        );
        let long_worker = "x".repeat(BM1491_L9_SUBMIT_JSON_CAPACITY);
        input = base_submit();
        input.worker = &long_worker;
        assert!(matches!(
            bm1491_l9_prepare_submit(input),
            Err(Bm1491L9SubmissionError::SubmitJsonTooLong { .. })
        ));
    }

    #[test]
    fn send_replay_stops_on_one_and_exhausts_after_four_failures() {
        let sent = bm1491_l9_replay_send_attempts(false, &[0, 2, 1, 0]).unwrap();
        assert_eq!(sent.disposition, Bm1491L9SendDisposition::SentStockReturn1);
        assert_eq!(sent.attempts, 3);
        assert_eq!(sent.failed_attempt_accounting_increments, 2);
        assert!(sent.caller_ignores_final_result);
        assert!(!sent.admits_network_io());

        let exhausted = bm1491_l9_replay_send_attempts(false, &[0, 2, 3, 4, 1]).unwrap();
        assert_eq!(
            exhausted.disposition,
            Bm1491L9SendDisposition::Exhausted { last_result: 4 }
        );
        assert_eq!(exhausted.attempts, 4);
        assert_eq!(exhausted.failed_attempt_accounting_increments, 4);
        assert_eq!(
            bm1491_l9_replay_send_attempts(false, &[0, 0]),
            Err(Bm1491L9SubmissionError::IncompleteSendObservations { observed: 2 })
        );
    }

    #[test]
    fn idle_pool_returns_zero_without_socket_attempt() {
        let replay = bm1491_l9_replay_send_attempts(true, &[]).unwrap();
        assert_eq!(
            replay.disposition,
            Bm1491L9SendDisposition::IdlePoolStockReturn0
        );
        assert_eq!(replay.attempts, 0);
    }

    fn response<'a>(
        result: Bm1491L9ResponseResult,
        error: Bm1491L9ResponseError<'a>,
        id: Bm1491L9ResponseId,
        direct_error_mode: bool,
    ) -> Bm1491L9ResponseObservation<'a> {
        Bm1491L9ResponseObservation {
            json_decode_succeeded: true,
            result,
            error,
            id,
            direct_error_mode,
        }
    }

    #[test]
    fn standard_response_accepts_true_or_exact_ok_with_observed_error_shapes() {
        let accepted_true = bm1491_l9_classify_stratum_response(response(
            Bm1491L9ResponseResult::True,
            Bm1491L9ResponseError::Missing,
            Bm1491L9ResponseId::Integer(4),
            false,
        ));
        assert!(matches!(
            accepted_true,
            Bm1491L9ResponseDisposition::AccountShare { accepted: true, .. }
        ));
        assert!(!accepted_true.admits_pool_acceptance_authority());

        assert!(matches!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::StringOk,
                Bm1491L9ResponseError::Null,
                Bm1491L9ResponseId::Integer(5),
                false,
            )),
            Bm1491L9ResponseDisposition::AccountShare { accepted: true, .. }
        ));
        assert!(matches!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::StringOk,
                Bm1491L9ResponseError::Missing,
                Bm1491L9ResponseId::Integer(5),
                false,
            )),
            Bm1491L9ResponseDisposition::AccountShare {
                accepted: false,
                ..
            }
        ));
    }

    #[test]
    fn standard_response_reserves_ids_below_four_and_extracts_array_reason() {
        assert_eq!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::True,
                Bm1491L9ResponseError::Missing,
                Bm1491L9ResponseId::Integer(3),
                false,
            )),
            Bm1491L9ResponseDisposition::ReservedOrUntrackedNoAccounting
        );
        assert_eq!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::False,
                Bm1491L9ResponseError::ArrayIndexOneString(Some("low difficulty")),
                Bm1491L9ResponseId::Integer(4),
                false,
            )),
            Bm1491L9ResponseDisposition::AccountShare {
                accepted: false,
                rejection_reason: Some("low difficulty"),
                share_result_returns_one: true,
                response_handler_returns_one: true,
                stock_only_applies_id_floor_without_outstanding_request_match: true,
            }
        );
    }

    #[test]
    fn null_id_decode_failure_and_missing_standard_result_do_not_account() {
        assert_eq!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::True,
                Bm1491L9ResponseError::Null,
                Bm1491L9ResponseId::Null,
                false,
            )),
            Bm1491L9ResponseDisposition::LogNullIdNoAccounting
        );
        let mut observation = response(
            Bm1491L9ResponseResult::True,
            Bm1491L9ResponseError::Null,
            Bm1491L9ResponseId::Integer(4),
            false,
        );
        observation.json_decode_succeeded = false;
        assert_eq!(
            bm1491_l9_classify_stratum_response(observation),
            Bm1491L9ResponseDisposition::JsonDecodeFailed
        );
        assert_eq!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::Missing,
                Bm1491L9ResponseError::Null,
                Bm1491L9ResponseId::Integer(4),
                false,
            )),
            Bm1491L9ResponseDisposition::ReservedOrUntrackedNoAccounting
        );
    }

    #[test]
    fn direct_error_mode_uses_direct_string_and_does_not_reserve_low_ids() {
        assert_eq!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::False,
                Bm1491L9ResponseError::DirectString("stale"),
                Bm1491L9ResponseId::Integer(0),
                true,
            )),
            Bm1491L9ResponseDisposition::AccountShare {
                accepted: false,
                rejection_reason: Some("stale"),
                share_result_returns_one: true,
                response_handler_returns_one: true,
                stock_only_applies_id_floor_without_outstanding_request_match: true,
            }
        );
        assert_eq!(
            bm1491_l9_classify_stratum_response(response(
                Bm1491L9ResponseResult::Missing,
                Bm1491L9ResponseError::Missing,
                Bm1491L9ResponseId::Integer(0),
                true,
            )),
            Bm1491L9ResponseDisposition::ReservedOrUntrackedNoAccounting
        );
    }
}
