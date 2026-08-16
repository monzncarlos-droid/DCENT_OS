//! Exact-release BM1485/L3+ stock work and nonce-return contract.
//!
//! The held 2017 stock `cgminer` emits an 82-byte UART work frame and receives
//! seven-byte ASIC returns which userspace expands with a chain byte. The
//! stock publisher reuses a 7-bit work-ID table without a generation carried
//! on the return wire. This module is pure: it performs no UART I/O, replays
//! the exact Scrypt digest and target predicates from caller-supplied data,
//! and grants no work-dispatch or submission authority.

use crate::bm1485_l3plus_stock::BM1485_L3PLUS_STOCK_CHAIN_COUNT;
use crate::bm1489_l7_share_qualification::bm1489_l7_scrypt_1024_1_1_256;
use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1485_L3PLUS_STOCK_SOURCE_WORK_LEN: usize = 80;
pub const BM1485_L3PLUS_STOCK_WORK_FRAME_LEN: usize = 82;
pub const BM1485_L3PLUS_STOCK_WORK_CRC_SPAN: usize = 80;
pub const BM1485_L3PLUS_STOCK_WORK_PAYLOAD_LEN: usize = 76;
pub const BM1485_L3PLUS_STOCK_WORK_HEADER: u8 = 0x20;
pub const BM1485_L3PLUS_STOCK_WORK_LENGTH_FIELD: u8 = 0x50;
pub const BM1485_L3PLUS_STOCK_WORK_ID_MASK: u8 = 0x7f;
pub const BM1485_L3PLUS_STOCK_WORK_ID_COUNT: usize = 128;
pub const BM1485_L3PLUS_STOCK_UART_WRITE_TAIL_DELAY_US: u32 = 500;

pub const BM1485_L3PLUS_STOCK_UART_RETURN_LEN: usize = 7;
pub const BM1485_L3PLUS_STOCK_SOFTWARE_RETURN_LEN: usize = 8;
pub const BM1485_L3PLUS_STOCK_RETURN_CRC_BITS: usize = 51;
pub const BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY: u16 = 0x360;

pub const BM1485_L3PLUS_STOCK_CLONE_PUBLISHED_BEFORE_UART_WRITE: bool = true;
pub const BM1485_L3PLUS_STOCK_UART_WRITE_RESULT_PROPAGATED: bool = false;
pub const BM1485_L3PLUS_STOCK_RETURN_POP_PRECEDES_VALIDATION: bool = true;
pub const BM1485_L3PLUS_STOCK_RETURN_CARRIES_GENERATION: bool = false;
pub const BM1485_L3PLUS_STOCK_LATE_RETURN_EXCLUDED: bool = false;
pub const BM1485_L3PLUS_STOCK_AUTHORIZES_WORK_DISPATCH: bool = false;
pub const BM1485_L3PLUS_STOCK_AUTHORIZES_SHARE_SUBMISSION: bool = false;

pub const BM1485_L3PLUS_STOCK_HEADER_BYTES: usize = 80;
pub const BM1485_L3PLUS_STOCK_HEADER_WORDS: usize = 20;
pub const BM1485_L3PLUS_STOCK_DIGEST_BYTES: usize = 32;
pub const BM1485_L3PLUS_STOCK_DIGEST_WORDS: usize = 8;
pub const BM1485_L3PLUS_STOCK_COARSE_DIGEST_WORD: usize = 7;
pub const BM1485_L3PLUS_STOCK_SCRYPT_N: usize = 1024;
pub const BM1485_L3PLUS_STOCK_SCRYPT_R: usize = 1;
pub const BM1485_L3PLUS_STOCK_SCRYPT_P: usize = 1;
pub const BM1485_L3PLUS_STOCK_SCRYPT_COARSE_MAX: u32 = 0x0000_ffff;
pub const BM1485_L3PLUS_HELD_INIT_ENABLES_SCRYPT: bool = true;
pub const BM1485_L3PLUS_STOCK_SCRYPT_PARAMETERS_RECOVERED: bool = true;
pub const BM1485_L3PLUS_STOCK_HEADER_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1485_L3PLUS_STOCK_TARGET_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1485_L3PLUS_STOCK_POOL_RESPONSE_BOUND_TO_REQUEST: bool = false;
pub const BM1485_L3PLUS_STOCK_ACCEPTED_SHARE_ORACLE_RECOVERED: bool = false;

/// CRC16-CCITT/FALSE used by `FUN_0003b968`: polynomial `0x1021`, initial
/// state `0xffff`, MSB first, no reflection, no final xor.
pub fn bm1485_l3plus_stock_crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockWorkFrame {
    pub work_id: u8,
    pub wire_bytes: [u8; BM1485_L3PLUS_STOCK_WORK_FRAME_LEN],
    pub clone_published_before_uart_write: bool,
    pub uart_write_result_propagated: bool,
    pub uart_write_tail_delay_us: u32,
}

impl Bm1485L3PlusStockWorkFrame {
    pub const fn authorizes_dispatch(self) -> bool {
        false
    }
}

/// Replays the normal-pool work construction in `FUN_0003b968`.
///
/// Stock masks the source work ID to seven bits, reverses the complete 80-byte
/// source image, then copies reversed bytes 4..80. Equivalently, the payload is
/// source bytes 75..0 in descending order; source bytes 76..79 are omitted.
pub fn bm1485_l3plus_stock_build_work_frame(
    source_work_id: u32,
    source_work: &[u8; BM1485_L3PLUS_STOCK_SOURCE_WORK_LEN],
) -> Bm1485L3PlusStockWorkFrame {
    let work_id = (source_work_id as u8) & BM1485_L3PLUS_STOCK_WORK_ID_MASK;
    let mut wire_bytes = [0_u8; BM1485_L3PLUS_STOCK_WORK_FRAME_LEN];
    wire_bytes[0] = BM1485_L3PLUS_STOCK_WORK_HEADER;
    wire_bytes[1] = BM1485_L3PLUS_STOCK_WORK_LENGTH_FIELD;
    wire_bytes[2] = work_id;
    // Byte 3 remains zero from the stock memset.
    for (destination, source) in wire_bytes[4..80].iter_mut().zip(
        source_work[..BM1485_L3PLUS_STOCK_WORK_PAYLOAD_LEN]
            .iter()
            .rev(),
    ) {
        *destination = *source;
    }
    let crc =
        bm1485_l3plus_stock_crc16_ccitt_false(&wire_bytes[..BM1485_L3PLUS_STOCK_WORK_CRC_SPAN]);
    wire_bytes[80..82].copy_from_slice(&crc.to_be_bytes());
    Bm1485L3PlusStockWorkFrame {
        work_id,
        wire_bytes,
        clone_published_before_uart_write: BM1485_L3PLUS_STOCK_CLONE_PUBLISHED_BEFORE_UART_WRITE,
        uart_write_result_propagated: BM1485_L3PLUS_STOCK_UART_WRITE_RESULT_PROPAGATED,
        uart_write_tail_delay_us: BM1485_L3PLUS_STOCK_UART_WRITE_TAIL_DELAY_US,
    }
}

/// Reconstruct the exact 80-byte buffer passed to the stock Scrypt function.
///
/// `FUN_00015fec` first stores the returned nonce as the native word at clone
/// offset `0x4c`. `FUN_00014a98` then byte-swaps every one of the twenty native
/// header words. On ARM little-endian this is exactly each `u32` encoded
/// big-endian after replacing word 19 with the nonce.
pub fn bm1485_l3plus_stock_scrypt_header(
    mut native_header_words: [u32; BM1485_L3PLUS_STOCK_HEADER_WORDS],
    returned_nonce: u32,
) -> [u8; BM1485_L3PLUS_STOCK_HEADER_BYTES] {
    native_header_words[BM1485_L3PLUS_STOCK_HEADER_WORDS - 1] = returned_nonce;
    let mut header = [0_u8; BM1485_L3PLUS_STOCK_HEADER_BYTES];
    for (bytes, word) in header.chunks_exact_mut(4).zip(native_header_words) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    header
}

/// Exact standard Scrypt N=1024/r=1/p=1 digest followed by stock's final
/// per-word byte swap. The shared implementation is also independently pinned
/// by the later exact BM1489/L7 contract; this wrapper carries only BM1485
/// release facts and grants no cross-model authority.
pub fn bm1485_l3plus_stock_scrypt_digest_words(
    scrypt_header: [u8; BM1485_L3PLUS_STOCK_HEADER_BYTES],
) -> [u32; BM1485_L3PLUS_STOCK_DIGEST_WORDS] {
    let digest = bm1489_l7_scrypt_1024_1_1_256(scrypt_header);
    let mut words = [0_u32; BM1485_L3PLUS_STOCK_DIGEST_WORDS];
    for (word, bytes) in words.iter_mut().zip(digest.chunks_exact(4)) {
        let mut native = [0_u8; 4];
        native.copy_from_slice(bytes);
        *word = u32::from_be_bytes(native);
    }
    words
}

/// Exact `FUN_0002a608` comparison: word seven is most significant and
/// equality passes.
pub fn bm1485_l3plus_stock_full_target_passes(
    digest_words: [u32; BM1485_L3PLUS_STOCK_DIGEST_WORDS],
    target_words: [u32; BM1485_L3PLUS_STOCK_DIGEST_WORDS],
) -> bool {
    for (&digest, &target) in digest_words.iter().zip(target_words.iter()).rev() {
        if digest < target {
            return true;
        }
        if digest > target {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockQualificationDisposition {
    CoarseDigestMiss,
    FullTargetMiss,
    WouldEnterStockSubmitPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockQualificationPlan {
    pub returned_nonce: u32,
    pub scrypt_header: [u8; BM1485_L3PLUS_STOCK_HEADER_BYTES],
    pub digest_words: [u32; BM1485_L3PLUS_STOCK_DIGEST_WORDS],
    pub coarse_digest_passed: bool,
    pub full_target_passed: Option<bool>,
    pub disposition: Bm1485L3PlusStockQualificationDisposition,
    pub would_enter_stock_submit_path: bool,
    pub header_provenance_authenticated: bool,
    pub target_provenance_authenticated: bool,
    pub pool_response_bound_to_request: bool,
}

impl Bm1485L3PlusStockQualificationPlan {
    pub const fn authorizes_share_submission(self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(self) -> bool {
        false
    }
}

/// Replay `FUN_00015fec` -> `FUN_00014a98` -> `FUN_0002a608` for the exact
/// held L3+ Scrypt mode. Stock first requires digest word seven `<= 0xffff`,
/// then compares the complete digest with the target. Reaching the later
/// submit path is only an observed local control-flow fact.
pub fn bm1485_l3plus_stock_qualification_plan(
    native_header_words: [u32; BM1485_L3PLUS_STOCK_HEADER_WORDS],
    returned_nonce: u32,
    target_words: [u32; BM1485_L3PLUS_STOCK_DIGEST_WORDS],
) -> Bm1485L3PlusStockQualificationPlan {
    let scrypt_header = bm1485_l3plus_stock_scrypt_header(native_header_words, returned_nonce);
    let digest_words = bm1485_l3plus_stock_scrypt_digest_words(scrypt_header);
    let coarse_digest_passed = digest_words[BM1485_L3PLUS_STOCK_COARSE_DIGEST_WORD]
        <= BM1485_L3PLUS_STOCK_SCRYPT_COARSE_MAX;
    let (full_target_passed, disposition, would_enter_stock_submit_path) = if !coarse_digest_passed
    {
        (
            None,
            Bm1485L3PlusStockQualificationDisposition::CoarseDigestMiss,
            false,
        )
    } else if bm1485_l3plus_stock_full_target_passes(digest_words, target_words) {
        (
            Some(true),
            Bm1485L3PlusStockQualificationDisposition::WouldEnterStockSubmitPath,
            true,
        )
    } else {
        (
            Some(false),
            Bm1485L3PlusStockQualificationDisposition::FullTargetMiss,
            false,
        )
    };
    Bm1485L3PlusStockQualificationPlan {
        returned_nonce,
        scrypt_header,
        digest_words,
        coarse_digest_passed,
        full_target_passed,
        disposition,
        would_enter_stock_submit_path,
        header_provenance_authenticated: BM1485_L3PLUS_STOCK_HEADER_PROVENANCE_AUTHENTICATED,
        target_provenance_authenticated: BM1485_L3PLUS_STOCK_TARGET_PROVENANCE_AUTHENTICATED,
        pool_response_bound_to_request: BM1485_L3PLUS_STOCK_POOL_RESPONSE_BOUND_TO_REQUEST,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockReturnError {
    ChainSlotOutOfRange(u8),
    AlternateRecordType(u8),
    Crc5Mismatch { stored: u8, computed: u8 },
    WorkIdOutOfRange(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockDecodedReturn {
    /// The first four UART bytes, explicitly reconstructed big-endian.
    pub nonce: u32,
    /// Stock log label `wc`; no stronger semantic is established here.
    pub work_count_tag: u8,
    /// Stock log label `diff`, but this byte indexes the current clone table.
    pub work_id: u8,
    /// Bits 6:5 of the CRC/status byte. Bit 7 selects the alternate queue.
    pub status_bits: u8,
    pub stored_crc5: u8,
    pub chain_slot: u8,
}

/// Decode the eight-byte software record consumed by `FUN_0003b14c`:
/// seven UART bytes followed by the reader thread's chain slot.
pub fn bm1485_l3plus_stock_decode_return(
    record: [u8; BM1485_L3PLUS_STOCK_SOFTWARE_RETURN_LEN],
) -> Result<Bm1485L3PlusStockDecodedReturn, Bm1485L3PlusStockReturnError> {
    let chain_slot = record[7];
    if usize::from(chain_slot) >= BM1485_L3PLUS_STOCK_CHAIN_COUNT {
        return Err(Bm1485L3PlusStockReturnError::ChainSlotOutOfRange(
            chain_slot,
        ));
    }
    if record[6] & 0x80 != 0 {
        return Err(Bm1485L3PlusStockReturnError::AlternateRecordType(record[6]));
    }
    let stored = record[6] & 0x1f;
    let computed = stock_bitmain_crc5(
        &record[..BM1485_L3PLUS_STOCK_UART_RETURN_LEN],
        BM1485_L3PLUS_STOCK_RETURN_CRC_BITS,
    );
    if computed != stored {
        return Err(Bm1485L3PlusStockReturnError::Crc5Mismatch { stored, computed });
    }
    let work_id = record[5];
    if usize::from(work_id) >= BM1485_L3PLUS_STOCK_WORK_ID_COUNT {
        return Err(Bm1485L3PlusStockReturnError::WorkIdOutOfRange(work_id));
    }
    Ok(Bm1485L3PlusStockDecodedReturn {
        nonce: u32::from_be_bytes([record[0], record[1], record[2], record[3]]),
        work_count_tag: record[4],
        work_id,
        status_bits: record[6] & 0x60,
        stored_crc5: stored,
        chain_slot,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1485L3PlusStockReturnQueueState {
    pub write_index: u16,
    pub read_index: u16,
    pub count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockReturnQueueError {
    WriteIndexOutOfRange(u16),
    ReadIndexOutOfRange(u16),
    CountOutOfRange(u16),
    NonEmptyReadIndexHasNoWritableSlot(u16),
}

fn validate_queue_state(
    state: Bm1485L3PlusStockReturnQueueState,
) -> Result<(), Bm1485L3PlusStockReturnQueueError> {
    if state.write_index > BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY {
        return Err(Bm1485L3PlusStockReturnQueueError::WriteIndexOutOfRange(
            state.write_index,
        ));
    }
    if state.read_index > BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY {
        return Err(Bm1485L3PlusStockReturnQueueError::ReadIndexOutOfRange(
            state.read_index,
        ));
    }
    if state.count > BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY {
        return Err(Bm1485L3PlusStockReturnQueueError::CountOutOfRange(
            state.count,
        ));
    }
    if state.count != 0 && state.read_index == BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY {
        return Err(
            Bm1485L3PlusStockReturnQueueError::NonEmptyReadIndexHasNoWritableSlot(state.read_index),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockEnqueueTransition {
    Stored {
        record_index: u16,
        next_state: Bm1485L3PlusStockReturnQueueState,
    },
    /// Exact stock overflow handling calls `FUN_0003fb40`, discarding all
    /// queued records and resetting all three indices to zero.
    FlushedAll {
        next_state: Bm1485L3PlusStockReturnQueueState,
    },
}

pub fn bm1485_l3plus_stock_return_enqueue_transition(
    state: Bm1485L3PlusStockReturnQueueState,
) -> Result<Bm1485L3PlusStockEnqueueTransition, Bm1485L3PlusStockReturnQueueError> {
    validate_queue_state(state)?;
    if state.count < BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY
        && state.write_index < BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY
    {
        return Ok(Bm1485L3PlusStockEnqueueTransition::Stored {
            record_index: state.write_index,
            next_state: Bm1485L3PlusStockReturnQueueState {
                write_index: state.write_index + 1,
                read_index: state.read_index,
                count: state.count + 1,
            },
        });
    }
    Ok(Bm1485L3PlusStockEnqueueTransition::FlushedAll {
        next_state: Bm1485L3PlusStockReturnQueueState::default(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockConsumedReturn {
    pub record_index: u16,
    pub next_state: Bm1485L3PlusStockReturnQueueState,
    /// A CRC/type/ID failure still consumes the record in stock.
    pub decoded: Result<Bm1485L3PlusStockDecodedReturn, Bm1485L3PlusStockReturnError>,
}

/// Replays the main consumer's state transition. Stock decrements `count`
/// before CRC/type/work lookup and advances `read_index` on every drop path.
pub fn bm1485_l3plus_stock_consume_return(
    state: Bm1485L3PlusStockReturnQueueState,
    record: [u8; BM1485_L3PLUS_STOCK_SOFTWARE_RETURN_LEN],
) -> Result<Option<Bm1485L3PlusStockConsumedReturn>, Bm1485L3PlusStockReturnQueueError> {
    validate_queue_state(state)?;
    if state.count == 0 {
        return Ok(None);
    }
    let record_index = state.read_index;
    let next_read_index = if state.read_index < BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY {
        state.read_index + 1
    } else {
        0
    };
    Ok(Some(Bm1485L3PlusStockConsumedReturn {
        record_index,
        next_state: Bm1485L3PlusStockReturnQueueState {
            write_index: state.write_index,
            read_index: next_read_index,
            count: state.count - 1,
        },
        decoded: bm1485_l3plus_stock_decode_return(record),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockWorkBindingAssessment {
    pub returned_work_id: u8,
    pub current_clone_slot_populated: bool,
    pub stock_would_validate_current_clone: bool,
    pub generation_carried_on_wire: bool,
    pub late_return_excluded: bool,
}

impl Bm1485L3PlusStockWorkBindingAssessment {
    pub const fn authorizes_submission(self) -> bool {
        false
    }
}

/// Stock uses only the returned 7-bit slot to find the current clone. A
/// populated slot is therefore necessary for stock validation but cannot show
/// that a late return belongs to the clone currently occupying that slot.
pub const fn bm1485_l3plus_stock_work_binding_assessment(
    returned_work_id: u8,
    current_clone_slot_populated: bool,
) -> Bm1485L3PlusStockWorkBindingAssessment {
    Bm1485L3PlusStockWorkBindingAssessment {
        returned_work_id,
        current_clone_slot_populated,
        stock_would_validate_current_clone: current_clone_slot_populated
            && returned_work_id <= BM1485_L3PLUS_STOCK_WORK_ID_MASK,
        generation_carried_on_wire: BM1485_L3PLUS_STOCK_RETURN_CARRIES_GENERATION,
        late_return_excluded: BM1485_L3PLUS_STOCK_LATE_RETURN_EXCLUDED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn return_record(
        nonce: [u8; 4],
        work_count_tag: u8,
        work_id: u8,
        high_status_bits: u8,
        chain_slot: u8,
    ) -> [u8; BM1485_L3PLUS_STOCK_SOFTWARE_RETURN_LEN] {
        let mut record = [
            nonce[0],
            nonce[1],
            nonce[2],
            nonce[3],
            work_count_tag,
            work_id,
            high_status_bits & 0xe0,
            chain_slot,
        ];
        record[6] |= stock_bitmain_crc5(
            &record[..BM1485_L3PLUS_STOCK_UART_RETURN_LEN],
            BM1485_L3PLUS_STOCK_RETURN_CRC_BITS,
        );
        record
    }

    #[test]
    fn crc16_matches_ccitt_false_and_exact_frame_goldens() {
        assert_eq!(bm1485_l3plus_stock_crc16_ccitt_false(b"123456789"), 0x29b1);
        let zero_work = [0_u8; BM1485_L3PLUS_STOCK_SOURCE_WORK_LEN];
        let zero_frame = bm1485_l3plus_stock_build_work_frame(0, &zero_work);
        assert_eq!(&zero_frame.wire_bytes[80..82], &[0xc3, 0x46]);

        let mut sequential = [0_u8; BM1485_L3PLUS_STOCK_SOURCE_WORK_LEN];
        for (index, byte) in sequential.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let frame = bm1485_l3plus_stock_build_work_frame(0x7f, &sequential);
        assert_eq!(&frame.wire_bytes[80..82], &[0x08, 0x10]);
    }

    #[test]
    fn normal_work_frame_reverses_only_source_bytes_zero_through_seventy_five() {
        let mut source = [0_u8; BM1485_L3PLUS_STOCK_SOURCE_WORK_LEN];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let frame = bm1485_l3plus_stock_build_work_frame(0xffff_ffff, &source);
        assert_eq!(&frame.wire_bytes[..4], &[0x20, 0x50, 0x7f, 0x00]);
        assert_eq!(frame.wire_bytes[4], 75);
        assert_eq!(frame.wire_bytes[79], 0);
        assert!(!frame.wire_bytes[4..80].contains(&76));
        assert!(frame.clone_published_before_uart_write);
        assert!(!frame.uart_write_result_propagated);
        assert_eq!(frame.uart_write_tail_delay_us, 500);
        assert!(!frame.authorizes_dispatch());
    }

    #[test]
    fn scrypt_header_overwrites_nonce_then_swaps_each_native_word() {
        let mut words = [0_u32; BM1485_L3PLUS_STOCK_HEADER_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            *word = 0x0102_0304_u32.wrapping_add(index as u32);
        }
        let header = bm1485_l3plus_stock_scrypt_header(words, 0x1122_3344);
        assert_eq!(
            &header[..8],
            &[0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x05]
        );
        assert_eq!(&header[76..80], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn scrypt_digest_matches_independent_zero_and_incrementing_goldens() {
        assert_eq!(
            bm1485_l3plus_stock_scrypt_digest_words([0; BM1485_L3PLUS_STOCK_HEADER_BYTES]),
            [
                0x161d_0876,
                0xf3b9_3b10,
                0x48cd_a1bd,
                0xeaa7_332e,
                0xe210_f713,
                0x1b42_013c,
                0xb439_13a6,
                0x553a_4b69,
            ]
        );
        let mut incrementing = [0_u8; BM1485_L3PLUS_STOCK_HEADER_BYTES];
        for (value, byte) in incrementing.iter_mut().zip(0_u8..) {
            *value = byte;
        }
        assert_eq!(
            bm1485_l3plus_stock_scrypt_digest_words(incrementing),
            [
                0xbc54_0a1a,
                0x801d_f96e,
                0x4930_05c7,
                0x1e01_0e2d,
                0x3876_07fb,
                0xf0fe_c416,
                0xfd3c_2645,
                0xaa1b_a9d2,
            ]
        );
        assert!(BM1485_L3PLUS_HELD_INIT_ENABLES_SCRYPT);
        assert!(BM1485_L3PLUS_STOCK_SCRYPT_PARAMETERS_RECOVERED);
        assert_eq!(BM1485_L3PLUS_STOCK_SCRYPT_N, 1024);
        assert_eq!(BM1485_L3PLUS_STOCK_SCRYPT_R, 1);
        assert_eq!(BM1485_L3PLUS_STOCK_SCRYPT_P, 1);
    }

    #[test]
    fn full_target_compare_is_word_seven_first_and_accepts_equality() {
        let digest = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        assert!(bm1485_l3plus_stock_full_target_passes(digest, digest));

        let mut lower_target = digest;
        lower_target[0] -= 1;
        assert!(!bm1485_l3plus_stock_full_target_passes(
            digest,
            lower_target
        ));

        let mut higher_target = digest;
        higher_target[7] += 1;
        assert!(bm1485_l3plus_stock_full_target_passes(
            digest,
            higher_target
        ));
    }

    #[test]
    fn derived_qualification_pins_coarse_full_target_and_no_authority() {
        let mut words = [0_u32; BM1485_L3PLUS_STOCK_HEADER_WORDS];
        let mut source = [0_u8; BM1485_L3PLUS_STOCK_HEADER_BYTES];
        for (value, byte) in source.iter_mut().zip(0_u8..) {
            *value = byte;
        }
        for (word, bytes) in words.iter_mut().zip(source.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }

        let coarse_miss = bm1485_l3plus_stock_qualification_plan(
            words,
            0x4c4d_4e4f,
            [u32::MAX; BM1485_L3PLUS_STOCK_DIGEST_WORDS],
        );
        assert_eq!(
            coarse_miss.disposition,
            Bm1485L3PlusStockQualificationDisposition::CoarseDigestMiss
        );
        assert!(!coarse_miss.coarse_digest_passed);
        assert_eq!(coarse_miss.full_target_passed, None);

        // Independently generated with Python/OpenSSL Scrypt over bytes
        // 00..4b followed by the big-endian nonce 0x0001d29f.
        let equality_digest = [
            0x74bb_2265,
            0x5285_a84c,
            0xc0c0_0177,
            0x08e9_be1c,
            0x2055_4e19,
            0x04c6_6f70,
            0x243c_a298,
            0x0000_5fd8,
        ];
        let equal = bm1485_l3plus_stock_qualification_plan(words, 0x0001_d29f, equality_digest);
        assert_eq!(equal.digest_words, equality_digest);
        assert!(equal.coarse_digest_passed);
        assert_eq!(equal.full_target_passed, Some(true));
        assert_eq!(
            equal.disposition,
            Bm1485L3PlusStockQualificationDisposition::WouldEnterStockSubmitPath
        );
        assert!(equal.would_enter_stock_submit_path);
        assert!(!equal.header_provenance_authenticated);
        assert!(!equal.target_provenance_authenticated);
        assert!(!equal.pool_response_bound_to_request);
        assert!(!equal.authorizes_share_submission());
        assert!(!equal.proves_pool_acceptance());
        assert!(!BM1485_L3PLUS_STOCK_ACCEPTED_SHARE_ORACLE_RECOVERED);

        let mut lower_target = equality_digest;
        lower_target[0] -= 1;
        let miss = bm1485_l3plus_stock_qualification_plan(words, 0x0001_d29f, lower_target);
        assert_eq!(miss.full_target_passed, Some(false));
        assert_eq!(
            miss.disposition,
            Bm1485L3PlusStockQualificationDisposition::FullTargetMiss
        );
        assert!(!miss.would_enter_stock_submit_path);
    }

    #[test]
    fn main_return_decodes_big_endian_nonce_and_fifty_one_bit_crc5() {
        let record = return_record([0x12, 0x34, 0x56, 0x78], 9, 0x2a, 0x40, 3);
        assert_eq!(record[6], 0x40, "this vector has stored CRC5 zero");
        let decoded = bm1485_l3plus_stock_decode_return(record).unwrap();
        assert_eq!(decoded.nonce, 0x1234_5678);
        assert_eq!(decoded.work_count_tag, 9);
        assert_eq!(decoded.work_id, 0x2a);
        assert_eq!(decoded.status_bits, 0x40);
        assert_eq!(decoded.stored_crc5, 0);
        assert_eq!(decoded.chain_slot, 3);
    }

    #[test]
    fn alternate_crc_corruption_work_id_and_chain_fail_closed() {
        let alternate = return_record([1, 2, 3, 4], 0, 1, 0x80, 0);
        assert!(matches!(
            bm1485_l3plus_stock_decode_return(alternate),
            Err(Bm1485L3PlusStockReturnError::AlternateRecordType(_))
        ));

        let mut corrupt = return_record([1, 2, 3, 4], 0, 1, 0, 0);
        corrupt[0] ^= 1;
        assert!(matches!(
            bm1485_l3plus_stock_decode_return(corrupt),
            Err(Bm1485L3PlusStockReturnError::Crc5Mismatch { .. })
        ));

        let overwide_id = return_record([1, 2, 3, 4], 0, 0x80, 0, 0);
        assert_eq!(
            bm1485_l3plus_stock_decode_return(overwide_id),
            Err(Bm1485L3PlusStockReturnError::WorkIdOutOfRange(0x80))
        );

        let bad_chain = return_record([1, 2, 3, 4], 0, 1, 0, 4);
        assert_eq!(
            bm1485_l3plus_stock_decode_return(bad_chain),
            Err(Bm1485L3PlusStockReturnError::ChainSlotOutOfRange(4))
        );
    }

    #[test]
    fn queue_writer_admits_864_records_then_flushes_all_state() {
        let initial = Bm1485L3PlusStockReturnQueueState::default();
        assert_eq!(
            bm1485_l3plus_stock_return_enqueue_transition(initial),
            Ok(Bm1485L3PlusStockEnqueueTransition::Stored {
                record_index: 0,
                next_state: Bm1485L3PlusStockReturnQueueState {
                    write_index: 1,
                    read_index: 0,
                    count: 1,
                },
            })
        );

        let full = Bm1485L3PlusStockReturnQueueState {
            write_index: BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY,
            read_index: 0,
            count: BM1485_L3PLUS_STOCK_RETURN_QUEUE_CAPACITY,
        };
        assert_eq!(
            bm1485_l3plus_stock_return_enqueue_transition(full),
            Ok(Bm1485L3PlusStockEnqueueTransition::FlushedAll {
                next_state: Bm1485L3PlusStockReturnQueueState::default(),
            })
        );
    }

    #[test]
    fn crc_failure_is_still_consumed_before_drop() {
        let state = Bm1485L3PlusStockReturnQueueState {
            write_index: 1,
            read_index: 0,
            count: 1,
        };
        let mut corrupt = return_record([1, 2, 3, 4], 0, 1, 0, 0);
        corrupt[0] ^= 1;
        let consumed = bm1485_l3plus_stock_consume_return(state, corrupt)
            .unwrap()
            .unwrap();
        assert_eq!(consumed.record_index, 0);
        assert_eq!(consumed.next_state.read_index, 1);
        assert_eq!(consumed.next_state.count, 0);
        assert!(matches!(
            consumed.decoded,
            Err(Bm1485L3PlusStockReturnError::Crc5Mismatch { .. })
        ));
        assert_eq!(
            bm1485_l3plus_stock_consume_return(
                Bm1485L3PlusStockReturnQueueState::default(),
                [0; BM1485_L3PLUS_STOCK_SOFTWARE_RETURN_LEN]
            ),
            Ok(None)
        );
    }

    #[test]
    fn malformed_queue_state_is_never_used_for_indexing() {
        assert_eq!(
            bm1485_l3plus_stock_return_enqueue_transition(Bm1485L3PlusStockReturnQueueState {
                write_index: 865,
                read_index: 0,
                count: 0,
            }),
            Err(Bm1485L3PlusStockReturnQueueError::WriteIndexOutOfRange(865))
        );
        assert_eq!(
            bm1485_l3plus_stock_consume_return(
                Bm1485L3PlusStockReturnQueueState {
                    write_index: 864,
                    read_index: 864,
                    count: 1,
                },
                [0; BM1485_L3PLUS_STOCK_SOFTWARE_RETURN_LEN]
            ),
            Err(Bm1485L3PlusStockReturnQueueError::NonEmptyReadIndexHasNoWritableSlot(864))
        );
    }

    #[test]
    fn current_clone_lookup_never_proves_return_generation() {
        let occupied = bm1485_l3plus_stock_work_binding_assessment(0x2a, true);
        assert!(occupied.stock_would_validate_current_clone);
        assert!(!occupied.generation_carried_on_wire);
        assert!(!occupied.late_return_excluded);
        assert!(!occupied.authorizes_submission());

        let empty = bm1485_l3plus_stock_work_binding_assessment(0x2a, false);
        assert!(!empty.stock_would_validate_current_clone);
        assert!(!empty.authorizes_submission());
        assert!(!BM1485_L3PLUS_STOCK_AUTHORIZES_WORK_DISPATCH);
        assert!(!BM1485_L3PLUS_STOCK_AUTHORIZES_SHARE_SUBMISSION);
    }
}
