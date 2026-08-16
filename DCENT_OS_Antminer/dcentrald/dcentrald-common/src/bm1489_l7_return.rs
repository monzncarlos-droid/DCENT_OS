//! Pure BM1489/L7 VNish serial-return and work-snapshot binding facts.
//!
//! The exact held binary contains this parser and selector-six derived-field
//! functions. The 128-entry table producer and its stock 1-through-127 ID
//! cycle are also recovered. The path from a physical L7 chain to this parser,
//! a generation-safe reuse/completion barrier, authenticated hash/target
//! provenance, and accepted-share response binding are not recovered. This
//! module therefore decodes and replays supplied bytes only; it performs no
//! I/O and grants no work-dispatch or share authority. The separate
//! `bm1489_l7_share_qualification` module models the recovered post-queue gates.

use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1489_L7_SERIAL_RETURN_HEADER: [u8; 2] = [0xaa, 0x55];
pub const BM1489_L7_SERIAL_RETURN_BODY_LEN: usize = 7;
pub const BM1489_L7_SERIAL_RETURN_FRAME_LEN: usize = 9;
pub const BM1489_L7_SERIAL_RETURN_CRC_BITS: usize = 51;
pub const BM1489_L7_RETURN_NONCE_FLAG: u8 = 0x80;
pub const BM1489_L7_RETURN_AUXILIARY_FLAG: u8 = 0x40;
pub const BM1489_L7_RETURN_CRC5_MASK: u8 = 0x1f;
pub const BM1489_L7_WORK_SELECTOR_MASK: u8 = 0x7f;

pub const BM1489_L7_WORK_TABLE_ENTRY_COUNT: usize = 128;
pub const BM1489_L7_WORK_TABLE_ENTRY_LEN: usize = 0x18;
pub const BM1489_L7_WORK_TABLE_LEN: usize =
    BM1489_L7_WORK_TABLE_ENTRY_COUNT * BM1489_L7_WORK_TABLE_ENTRY_LEN;
pub const BM1489_L7_WORK_TABLE_VALID_OFFSET: usize = 0x14;
pub const BM1489_L7_STOCK_FIRST_WORK_ID: u8 = 1;
pub const BM1489_L7_STOCK_LAST_WORK_ID: u8 = 0x7f;
pub const BM1489_L7_STOCK_WORK_ID_CYCLE_LEN: usize = 0x7f;
pub const BM1489_L7_STOCK_WORK_FRAME_LEN: usize = 0x56;

pub const BM1489_L7_NONCE_QUEUE_CAPACITY: usize = 0x1000;
pub const BM1489_L7_NONCE_QUEUE_RECORD_LEN: usize = 0x48;
/// Only this prefix is initialized with stable logical fields by the parser.
pub const BM1489_L7_NONCE_QUEUE_INITIALIZED_PREFIX_LEN: usize = 0x24;
pub const BM1489_L7_REGISTER_QUEUE_CAPACITY: usize = 0x400;
pub const BM1489_L7_REGISTER_QUEUE_RECORD_LEN: usize = 0x10;
pub const BM1489_L7_SERIAL_PARSER_IDLE_DELAY: u32 = 5;
pub const BM1489_L7_SERIAL_PARSER_SHORT_BUFFER_DELAY: u32 = 100;

/// `FUN_000dae90` stops deterministic decoding at this nonce value and uses a
/// process-random result modulo 117 instead. Clean replay rejects that branch.
pub const BM1489_L7_NONCE_GROUP_RANDOM_FALLBACK_START: u32 = 0xea00_0000;
pub const BM1489_L7_NONCE_GROUP_RANDOM_MODULUS: u32 = 0x75;

pub const BM1489_L7_RETURN_PATH_TO_PHYSICAL_L7_PROVEN: bool = false;
pub const BM1489_L7_WORK_TABLE_WRITER_RECOVERED: bool = true;
pub const BM1489_L7_WORK_ID_ALLOCATION_RECOVERED: bool = true;
/// The producer protects its writes with a mutex, but the exact return parser
/// reads the table without acquiring that mutex.
pub const BM1489_L7_WORK_TABLE_READER_TAKES_PRODUCER_MUTEX: bool = false;
/// Stock sets byte `+0x14` before writing words `+0x04..+0x10`.
pub const BM1489_L7_STOCK_VALIDITY_PRECEDES_SNAPSHOT_WORDS: bool = true;
/// The producer's ID issuer contains no per-ID return/completion gate before
/// cycling from 127 back to 1.
pub const BM1489_L7_STOCK_ID_ISSUER_HAS_COMPLETION_GATE: bool = false;
pub const BM1489_L7_WORK_ID_REUSE_BARRIER_RECOVERED: bool = false;
pub const BM1489_L7_RETURN_AUTHORIZES_LIVE_IO: bool = false;
pub const BM1489_L7_RETURN_AUTHORIZES_WORK_DISPATCH: bool = false;
pub const BM1489_L7_RETURN_AUTHORIZES_SHARE_SUBMISSION: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7ReturnDecodeError {
    WrongLength { actual: usize },
    HeaderMismatch { observed: [u8; 2] },
    CrcMismatch { observed: u8, expected: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7RegisterReturn {
    pub value: u32,
    pub chip_address: u8,
    pub register: u8,
    /// High three bits of the final body byte. Bit seven being set does not
    /// select the nonce path when the raw work-selector byte is zero.
    pub flags: u8,
    pub crc5: u8,
    /// Selector six returns `0xffff_ffff` from the legacy register-suppression
    /// helper, so otherwise-valid records enter the callback/queue path.
    pub enters_callback_then_queue_path: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7NonceReturn {
    /// The parser byte-swaps the ARM little-endian load, equivalent to reading
    /// the first four body bytes as a big-endian `u32`.
    pub nonce: u32,
    pub raw_work_selector: u8,
    pub work_index: u8,
    pub flags: u8,
    pub crc5: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7SerialReturn {
    Register(Bm1489L7RegisterReturn),
    Nonce(Bm1489L7NonceReturn),
}

/// Decode one complete `aa 55` plus seven-byte serial return record.
///
/// Stock stream code resynchronizes one byte at a time before this step. It
/// classifies a record as nonce-like only when flag bit seven is set *and* the
/// raw work-selector byte is nonzero; all other CRC-valid records take the
/// register path.
pub fn decode_bm1489_l7_serial_return(
    frame: &[u8],
) -> Result<Bm1489L7SerialReturn, Bm1489L7ReturnDecodeError> {
    let frame_array: &[u8; BM1489_L7_SERIAL_RETURN_FRAME_LEN] =
        frame
            .try_into()
            .map_err(|_| Bm1489L7ReturnDecodeError::WrongLength {
                actual: frame.len(),
            })?;
    let [header_0, header_1, body_0, body_1, body_2, body_3, body_4, body_5, body_6] = *frame_array;
    let observed_header = [header_0, header_1];
    if observed_header != BM1489_L7_SERIAL_RETURN_HEADER {
        return Err(Bm1489L7ReturnDecodeError::HeaderMismatch {
            observed: observed_header,
        });
    }
    let body = [body_0, body_1, body_2, body_3, body_4, body_5, body_6];
    let final_byte = body_6;
    let observed_crc = final_byte & BM1489_L7_RETURN_CRC5_MASK;
    let expected_crc = stock_bitmain_crc5(&body, BM1489_L7_SERIAL_RETURN_CRC_BITS);
    if observed_crc != expected_crc {
        return Err(Bm1489L7ReturnDecodeError::CrcMismatch {
            observed: observed_crc,
            expected: expected_crc,
        });
    }

    let value_or_nonce = u32::from_be_bytes([body_0, body_1, body_2, body_3]);
    let flags = final_byte & !BM1489_L7_RETURN_CRC5_MASK;
    let raw_work_selector = body_5;
    if final_byte & BM1489_L7_RETURN_NONCE_FLAG != 0 && raw_work_selector != 0 {
        Ok(Bm1489L7SerialReturn::Nonce(Bm1489L7NonceReturn {
            nonce: value_or_nonce,
            raw_work_selector,
            work_index: raw_work_selector & BM1489_L7_WORK_SELECTOR_MASK,
            flags,
            crc5: observed_crc,
        }))
    } else {
        Ok(Bm1489L7SerialReturn::Register(Bm1489L7RegisterReturn {
            value: value_or_nonce,
            chip_address: body_4,
            register: body_5,
            flags,
            crc5: observed_crc,
            enters_callback_then_queue_path: true,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7WorkSnapshot {
    pub word_04: u32,
    pub word_08: u32,
    pub word_0c: u32,
    pub word_10: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7WorkPublicationError {
    InvalidWorkId { work_id: u8 },
}

/// Hardware-facing order emitted by the exact stock producer after it has
/// already constructed the serial work frame and its CRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7WorkPublicationStep {
    AcquireProducerMutex,
    WriteWorkId(u8),
    WriteValidity(u8),
    WriteWord04(u32),
    WriteWord08(u32),
    WriteWord0c(u32),
    WriteWord10(u32),
    ReleaseProducerMutex,
    SendSerialWorkFrame { length: usize },
}

/// Advance the exact observable stock ID cycle. Entry zero is never issued by
/// an uncorrupted producer: `1, 2, ... 127, 1, ...`.
pub fn bm1489_l7_stock_next_work_id(
    issued_work_id: u8,
) -> Result<u8, Bm1489L7WorkPublicationError> {
    if !(BM1489_L7_STOCK_FIRST_WORK_ID..=BM1489_L7_STOCK_LAST_WORK_ID).contains(&issued_work_id) {
        return Err(Bm1489L7WorkPublicationError::InvalidWorkId {
            work_id: issued_work_id,
        });
    }
    Ok(if issued_work_id == BM1489_L7_STOCK_LAST_WORK_ID {
        BM1489_L7_STOCK_FIRST_WORK_ID
    } else {
        issued_work_id + 1
    })
}

/// Reproduce the exact stock table-publication and send spine for one emitted
/// chain work packet. This deliberately exposes the unsafe validity-before-
/// payload order and does not claim an atomic or generation-safe handoff.
pub fn bm1489_l7_stock_work_publication_steps(
    work_id: u8,
    snapshot: Bm1489L7WorkSnapshot,
) -> Result<[Bm1489L7WorkPublicationStep; 9], Bm1489L7WorkPublicationError> {
    if !(BM1489_L7_STOCK_FIRST_WORK_ID..=BM1489_L7_STOCK_LAST_WORK_ID).contains(&work_id) {
        return Err(Bm1489L7WorkPublicationError::InvalidWorkId { work_id });
    }
    Ok([
        Bm1489L7WorkPublicationStep::AcquireProducerMutex,
        Bm1489L7WorkPublicationStep::WriteWorkId(work_id),
        Bm1489L7WorkPublicationStep::WriteValidity(1),
        Bm1489L7WorkPublicationStep::WriteWord04(snapshot.word_04),
        Bm1489L7WorkPublicationStep::WriteWord08(snapshot.word_08),
        Bm1489L7WorkPublicationStep::WriteWord0c(snapshot.word_0c),
        Bm1489L7WorkPublicationStep::WriteWord10(snapshot.word_10),
        Bm1489L7WorkPublicationStep::ReleaseProducerMutex,
        Bm1489L7WorkPublicationStep::SendSerialWorkFrame {
            length: BM1489_L7_STOCK_WORK_FRAME_LEN,
        },
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7WorkBindError {
    WorkTableTooShort {
        work_index: u8,
        required_len: usize,
        actual_len: usize,
    },
    SnapshotInvalid {
        work_index: u8,
    },
    ConfiguredDivisorZero,
    DerivedQuotientOutOfRange {
        derived: u32,
        configured_bound: u32,
    },
    StockRandomFallbackRequired {
        nonce: u32,
    },
}

fn read_le_u32(record: &[u8], offset: usize) -> Option<u32> {
    let bytes = record.get(offset..offset.checked_add(4)?)?;
    let mut word = [0_u8; 4];
    word.copy_from_slice(bytes);
    Some(u32::from_le_bytes(word))
}

/// Read the exact 24-byte table entry selected by the low seven work bits.
/// Word zero is not copied into the nonce queue record. Byte `+0x14` is the
/// validity latch; the remaining bytes after it are not interpreted here.
pub fn decode_bm1489_l7_work_snapshot(
    table: &[u8],
    work_index: u8,
) -> Result<Bm1489L7WorkSnapshot, Bm1489L7WorkBindError> {
    let start = usize::from(work_index) * BM1489_L7_WORK_TABLE_ENTRY_LEN;
    let end = start + BM1489_L7_WORK_TABLE_ENTRY_LEN;
    let record = table
        .get(start..end)
        .ok_or(Bm1489L7WorkBindError::WorkTableTooShort {
            work_index,
            required_len: end,
            actual_len: table.len(),
        })?;
    if record
        .get(BM1489_L7_WORK_TABLE_VALID_OFFSET)
        .copied()
        .unwrap_or(0)
        == 0
    {
        return Err(Bm1489L7WorkBindError::SnapshotInvalid { work_index });
    }
    // All offsets are fixed inside the already length-checked 24-byte record.
    let word_04 = read_le_u32(record, 0x04).ok_or(Bm1489L7WorkBindError::WorkTableTooShort {
        work_index,
        required_len: end,
        actual_len: table.len(),
    })?;
    let word_08 = read_le_u32(record, 0x08).ok_or(Bm1489L7WorkBindError::WorkTableTooShort {
        work_index,
        required_len: end,
        actual_len: table.len(),
    })?;
    let word_0c = read_le_u32(record, 0x0c).ok_or(Bm1489L7WorkBindError::WorkTableTooShort {
        work_index,
        required_len: end,
        actual_len: table.len(),
    })?;
    let word_10 = read_le_u32(record, 0x10).ok_or(Bm1489L7WorkBindError::WorkTableTooShort {
        work_index,
        required_len: end,
        actual_len: table.len(),
    })?;
    Ok(Bm1489L7WorkSnapshot {
        word_04,
        word_08,
        word_0c,
        word_10,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7BoundNonce {
    pub chain: u32,
    /// Exact selector-six quotient derived from a byte-swapped nonce view.
    /// Its physical chip/address meaning is deliberately not asserted.
    pub derived_quotient: u32,
    /// Exact deterministic `nonce >> 25` result below the stock fallback cut.
    pub derived_nonce_group: u32,
    pub snapshot_word_10: u32,
    pub raw_work_selector: u32,
    pub snapshot_word_04: u32,
    pub snapshot_word_08: u32,
    pub snapshot_word_0c: u32,
    pub nonce: u32,
}

/// Bind a decoded nonce to the supplied table and reproduce the stable first
/// 36 bytes of the stock 72-byte host queue record.
///
/// Stock logs and substitutes random attribution when either derived value is
/// invalid. Clean replay refuses those branches instead.
pub fn bind_bm1489_l7_nonce(
    chain: u32,
    returned: Bm1489L7NonceReturn,
    work_table: &[u8],
    configured_divisor: u32,
    configured_bound: u32,
) -> Result<Bm1489L7BoundNonce, Bm1489L7WorkBindError> {
    if configured_divisor == 0 {
        return Err(Bm1489L7WorkBindError::ConfiguredDivisorZero);
    }
    let snapshot = decode_bm1489_l7_work_snapshot(work_table, returned.work_index)?;

    // `FUN_000dadc8` byte-swaps the already parser-swapped nonce before this
    // extraction, so the bit fields apply to this reversed view.
    let reversed_view = returned.nonce.swap_bytes();
    let numerator = (((reversed_view >> 24) & 1) << 7) | ((reversed_view >> 17) & 0x7f);
    let derived_quotient = numerator / configured_divisor;
    if derived_quotient >= configured_bound {
        return Err(Bm1489L7WorkBindError::DerivedQuotientOutOfRange {
            derived: derived_quotient,
            configured_bound,
        });
    }
    if returned.nonce >= BM1489_L7_NONCE_GROUP_RANDOM_FALLBACK_START {
        return Err(Bm1489L7WorkBindError::StockRandomFallbackRequired {
            nonce: returned.nonce,
        });
    }

    Ok(Bm1489L7BoundNonce {
        chain,
        derived_quotient,
        derived_nonce_group: returned.nonce >> 25,
        snapshot_word_10: snapshot.word_10,
        raw_work_selector: u32::from(returned.raw_work_selector),
        snapshot_word_04: snapshot.word_04,
        snapshot_word_08: snapshot.word_08,
        snapshot_word_0c: snapshot.word_0c,
        nonce: returned.nonce,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7NonceQueueState {
    pub read_index: usize,
    pub write_index: usize,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7StockQueuePush {
    pub next: Bm1489L7NonceQueueState,
    /// Exact stock behavior at capacity is to pop the oldest record first.
    pub dropped_oldest: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7QueueError {
    IndexOutOfRange,
    CountOutOfRange,
    InconsistentFullState,
}

/// Replay the exact nonce-queue index/count transition. This reports stock's
/// overwrite-oldest policy; it is not a recommendation for a clean executor.
pub fn bm1489_l7_stock_nonce_queue_push(
    state: Bm1489L7NonceQueueState,
) -> Result<Bm1489L7StockQueuePush, Bm1489L7QueueError> {
    if state.read_index >= BM1489_L7_NONCE_QUEUE_CAPACITY
        || state.write_index >= BM1489_L7_NONCE_QUEUE_CAPACITY
    {
        return Err(Bm1489L7QueueError::IndexOutOfRange);
    }
    if state.count > BM1489_L7_NONCE_QUEUE_CAPACITY {
        return Err(Bm1489L7QueueError::CountOutOfRange);
    }
    let full = state.count == BM1489_L7_NONCE_QUEUE_CAPACITY;
    if full && state.read_index != state.write_index {
        return Err(Bm1489L7QueueError::InconsistentFullState);
    }
    let read_index = if full {
        (state.read_index + 1) % BM1489_L7_NONCE_QUEUE_CAPACITY
    } else {
        state.read_index
    };
    let write_index = (state.write_index + 1) % BM1489_L7_NONCE_QUEUE_CAPACITY;
    let count = if full {
        BM1489_L7_NONCE_QUEUE_CAPACITY
    } else {
        state.count + 1
    };
    Ok(Bm1489L7StockQueuePush {
        next: Bm1489L7NonceQueueState {
            read_index,
            write_index,
            count,
        },
        dropped_oldest: full,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_with_crc(mut body: [u8; 7]) -> [u8; 9] {
        body[6] &= !BM1489_L7_RETURN_CRC5_MASK;
        body[6] |= stock_bitmain_crc5(&body, BM1489_L7_SERIAL_RETURN_CRC_BITS);
        let mut frame = [0_u8; 9];
        frame[..2].copy_from_slice(&BM1489_L7_SERIAL_RETURN_HEADER);
        frame[2..].copy_from_slice(&body);
        frame
    }

    #[test]
    fn exact_shape_and_no_authority_boundary_are_pinned() {
        assert_eq!(BM1489_L7_SERIAL_RETURN_FRAME_LEN, 9);
        assert_eq!(BM1489_L7_WORK_TABLE_LEN, 3_072);
        assert_eq!(BM1489_L7_STOCK_WORK_ID_CYCLE_LEN, 127);
        assert_eq!(BM1489_L7_STOCK_WORK_FRAME_LEN, 86);
        assert_eq!(BM1489_L7_NONCE_QUEUE_CAPACITY, 4_096);
        assert_eq!(BM1489_L7_NONCE_QUEUE_RECORD_LEN, 72);
        assert_eq!(BM1489_L7_NONCE_QUEUE_INITIALIZED_PREFIX_LEN, 36);
        assert_eq!(BM1489_L7_REGISTER_QUEUE_CAPACITY, 1_024);
        assert!(!BM1489_L7_RETURN_PATH_TO_PHYSICAL_L7_PROVEN);
        assert!(BM1489_L7_WORK_TABLE_WRITER_RECOVERED);
        assert!(BM1489_L7_WORK_ID_ALLOCATION_RECOVERED);
        assert!(!BM1489_L7_WORK_TABLE_READER_TAKES_PRODUCER_MUTEX);
        assert!(BM1489_L7_STOCK_VALIDITY_PRECEDES_SNAPSHOT_WORDS);
        assert!(!BM1489_L7_STOCK_ID_ISSUER_HAS_COMPLETION_GATE);
        assert!(!BM1489_L7_WORK_ID_REUSE_BARRIER_RECOVERED);
        assert!(!BM1489_L7_RETURN_AUTHORIZES_LIVE_IO);
        assert!(!BM1489_L7_RETURN_AUTHORIZES_WORK_DISPATCH);
        assert!(!BM1489_L7_RETURN_AUTHORIZES_SHARE_SUBMISSION);
    }

    #[test]
    fn stock_work_ids_cycle_one_through_127_without_entry_zero() {
        let mut work_id = BM1489_L7_STOCK_FIRST_WORK_ID;
        let mut observed = Vec::with_capacity(BM1489_L7_STOCK_WORK_ID_CYCLE_LEN);
        for _ in 0..BM1489_L7_STOCK_WORK_ID_CYCLE_LEN {
            observed.push(work_id);
            work_id = bm1489_l7_stock_next_work_id(work_id).unwrap();
        }
        assert_eq!(observed.first(), Some(&1));
        assert_eq!(observed.last(), Some(&127));
        assert!(!observed.contains(&0));
        assert_eq!(work_id, 1);
        for invalid in [0, 0x80, 0xff] {
            assert_eq!(
                bm1489_l7_stock_next_work_id(invalid),
                Err(Bm1489L7WorkPublicationError::InvalidWorkId { work_id: invalid })
            );
        }
    }

    #[test]
    fn stock_publication_sets_valid_before_words_and_sends_after_unlock() {
        let snapshot = Bm1489L7WorkSnapshot {
            word_04: 0x1122_3344,
            word_08: 0x5566_7788,
            word_0c: 0x99aa_bbcc,
            word_10: 0xddee_ff00,
        };
        assert_eq!(
            bm1489_l7_stock_work_publication_steps(5, snapshot),
            Ok([
                Bm1489L7WorkPublicationStep::AcquireProducerMutex,
                Bm1489L7WorkPublicationStep::WriteWorkId(5),
                Bm1489L7WorkPublicationStep::WriteValidity(1),
                Bm1489L7WorkPublicationStep::WriteWord04(0x1122_3344),
                Bm1489L7WorkPublicationStep::WriteWord08(0x5566_7788),
                Bm1489L7WorkPublicationStep::WriteWord0c(0x99aa_bbcc),
                Bm1489L7WorkPublicationStep::WriteWord10(0xddee_ff00),
                Bm1489L7WorkPublicationStep::ReleaseProducerMutex,
                Bm1489L7WorkPublicationStep::SendSerialWorkFrame { length: 0x56 },
            ])
        );
        assert!(bm1489_l7_stock_work_publication_steps(0, snapshot).is_err());
        assert!(bm1489_l7_stock_work_publication_steps(0x80, snapshot).is_err());
    }

    #[test]
    fn register_return_decodes_big_endian_value_and_callback_key() {
        let frame = frame_with_crc([0x12, 0x34, 0x56, 0x78, 0x2a, 0x1c, 0x40]);
        assert_eq!(
            frame,
            [0xaa, 0x55, 0x12, 0x34, 0x56, 0x78, 0x2a, 0x1c, 0x49]
        );
        assert_eq!(
            decode_bm1489_l7_serial_return(&frame),
            Ok(Bm1489L7SerialReturn::Register(Bm1489L7RegisterReturn {
                value: 0x1234_5678,
                chip_address: 0x2a,
                register: 0x1c,
                flags: 0x40,
                crc5: 9,
                enters_callback_then_queue_path: true,
            }))
        );
    }

    #[test]
    fn nonce_classification_uses_raw_nonzero_selector_then_masks_index() {
        let frame = frame_with_crc([0x12, 0x34, 0x56, 0x78, 0x99, 0x85, 0x80]);
        assert_eq!(
            frame,
            [0xaa, 0x55, 0x12, 0x34, 0x56, 0x78, 0x99, 0x85, 0x9f]
        );
        assert_eq!(
            decode_bm1489_l7_serial_return(&frame),
            Ok(Bm1489L7SerialReturn::Nonce(Bm1489L7NonceReturn {
                nonce: 0x1234_5678,
                raw_work_selector: 0x85,
                work_index: 5,
                flags: 0x80,
                crc5: 0x1f,
            }))
        );

        let selector_80 = frame_with_crc([1, 2, 3, 4, 5, 0x80, 0x80]);
        let Bm1489L7SerialReturn::Nonce(returned) =
            decode_bm1489_l7_serial_return(&selector_80).unwrap()
        else {
            panic!("raw selector 0x80 must take the nonce path")
        };
        assert_eq!(returned.work_index, 0);

        let selector_zero = frame_with_crc([1, 2, 3, 4, 5, 0, 0x80]);
        assert!(matches!(
            decode_bm1489_l7_serial_return(&selector_zero),
            Ok(Bm1489L7SerialReturn::Register(_))
        ));
    }

    #[test]
    fn malformed_header_length_and_crc_are_refused() {
        let mut frame = frame_with_crc([1, 2, 3, 4, 5, 6, 0]);
        assert!(matches!(
            decode_bm1489_l7_serial_return(&frame[..8]),
            Err(Bm1489L7ReturnDecodeError::WrongLength { actual: 8 })
        ));
        frame[0] = 0x55;
        assert!(matches!(
            decode_bm1489_l7_serial_return(&frame),
            Err(Bm1489L7ReturnDecodeError::HeaderMismatch { .. })
        ));
        frame[0] = 0xaa;
        frame[8] ^= 1;
        assert!(matches!(
            decode_bm1489_l7_serial_return(&frame),
            Err(Bm1489L7ReturnDecodeError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn work_snapshot_and_bound_record_match_exact_offsets() {
        let frame = frame_with_crc([0x12, 0x34, 0x56, 0x78, 0x99, 0x85, 0x80]);
        let Ok(Bm1489L7SerialReturn::Nonce(returned)) = decode_bm1489_l7_serial_return(&frame)
        else {
            panic!("golden must decode as nonce")
        };
        let mut table = vec![0_u8; 6 * BM1489_L7_WORK_TABLE_ENTRY_LEN];
        let entry =
            &mut table[5 * BM1489_L7_WORK_TABLE_ENTRY_LEN..6 * BM1489_L7_WORK_TABLE_ENTRY_LEN];
        entry[4..8].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
        entry[8..12].copy_from_slice(&0x5566_7788_u32.to_le_bytes());
        entry[12..16].copy_from_slice(&0x99aa_bbcc_u32.to_le_bytes());
        entry[16..20].copy_from_slice(&0xddee_ff00_u32.to_le_bytes());
        entry[20] = 1;

        assert_eq!(
            bind_bm1489_l7_nonce(3, returned, &table, 4, 11),
            Ok(Bm1489L7BoundNonce {
                chain: 3,
                derived_quotient: 10,
                derived_nonce_group: 9,
                snapshot_word_10: 0xddee_ff00,
                raw_work_selector: 0x85,
                snapshot_word_04: 0x1122_3344,
                snapshot_word_08: 0x5566_7788,
                snapshot_word_0c: 0x99aa_bbcc,
                nonce: 0x1234_5678,
            })
        );
    }

    #[test]
    fn binding_refuses_missing_invalid_and_random_stock_fallbacks() {
        let base = Bm1489L7NonceReturn {
            nonce: 0x1234_5678,
            raw_work_selector: 5,
            work_index: 5,
            flags: 0x80,
            crc5: 0,
        };
        let mut table = vec![0_u8; 6 * BM1489_L7_WORK_TABLE_ENTRY_LEN];
        assert!(matches!(
            bind_bm1489_l7_nonce(0, base, &table[..100], 1, 128),
            Err(Bm1489L7WorkBindError::WorkTableTooShort { .. })
        ));
        assert_eq!(
            bind_bm1489_l7_nonce(0, base, &table, 1, 128),
            Err(Bm1489L7WorkBindError::SnapshotInvalid { work_index: 5 })
        );
        table[5 * BM1489_L7_WORK_TABLE_ENTRY_LEN + BM1489_L7_WORK_TABLE_VALID_OFFSET] = 1;
        assert_eq!(
            bind_bm1489_l7_nonce(0, base, &table, 0, 128),
            Err(Bm1489L7WorkBindError::ConfiguredDivisorZero)
        );
        assert_eq!(
            bind_bm1489_l7_nonce(0, base, &table, 4, 10),
            Err(Bm1489L7WorkBindError::DerivedQuotientOutOfRange {
                derived: 10,
                configured_bound: 10,
            })
        );
        let random = Bm1489L7NonceReturn {
            nonce: BM1489_L7_NONCE_GROUP_RANDOM_FALLBACK_START,
            ..base
        };
        assert_eq!(
            bind_bm1489_l7_nonce(0, random, &table, 1, 256),
            Err(Bm1489L7WorkBindError::StockRandomFallbackRequired {
                nonce: BM1489_L7_NONCE_GROUP_RANDOM_FALLBACK_START,
            })
        );
    }

    #[test]
    fn stock_nonce_queue_drops_oldest_only_at_capacity() {
        assert_eq!(
            bm1489_l7_stock_nonce_queue_push(Bm1489L7NonceQueueState {
                read_index: 0,
                write_index: 0,
                count: 0,
            }),
            Ok(Bm1489L7StockQueuePush {
                next: Bm1489L7NonceQueueState {
                    read_index: 0,
                    write_index: 1,
                    count: 1,
                },
                dropped_oldest: false,
            })
        );
        assert_eq!(
            bm1489_l7_stock_nonce_queue_push(Bm1489L7NonceQueueState {
                read_index: 4_095,
                write_index: 4_095,
                count: 4_096,
            }),
            Ok(Bm1489L7StockQueuePush {
                next: Bm1489L7NonceQueueState {
                    read_index: 0,
                    write_index: 0,
                    count: 4_096,
                },
                dropped_oldest: true,
            })
        );
    }

    #[test]
    fn corrupt_queue_states_fail_closed() {
        for state in [
            Bm1489L7NonceQueueState {
                read_index: 4_096,
                write_index: 0,
                count: 0,
            },
            Bm1489L7NonceQueueState {
                read_index: 0,
                write_index: 0,
                count: 4_097,
            },
            Bm1489L7NonceQueueState {
                read_index: 0,
                write_index: 1,
                count: 4_096,
            },
        ] {
            assert!(bm1489_l7_stock_nonce_queue_push(state).is_err());
        }
    }
}
