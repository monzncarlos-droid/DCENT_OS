//! Pure BM1396 outstanding-work binding and host nonce-ring state machine.
//!
//! The held S17e/T17e 2019 and signed-2020 miners all expand an eight-byte
//! FPGA nonce return through a `work_id * 0x40` lookup into a stable 60-byte
//! host-ring record. The consumer pops that record, deduplicates on
//! `(nonce3, work_id)`, selects one of three job snapshots with wrapping
//! subtraction, validates the hash, and only then enters the share callback.
//! The callback serializes the selected work clone for the stock
//! `bitmain_submit_nonce` command bridge; its transport result is logged but
//! never propagated.
//!
//! This module models that confirmed pure boundary and hardens the unchecked
//! stock table lookup. It also records the exact initial address-publication
//! facts without performing them. It does not own the FPGA mapping or writer,
//! ID allocation/reuse, cache/completion barriers, job-snapshot storage,
//! carrier, callback receiver, pool acceptance, or hardware I/O.

use crate::bm1391_share_qualification::{
    bm1391_stock_digest_disposition, bm1391_stock_double_sha256_from_midstate,
    bm1391_stock_normalize_share_difficulty, Bm1391StockDifficultyNormalizationError,
    Bm1391StockDigestDisposition, Bm1391StockPrecomputedHashInput,
};
use crate::bm1396_carrier_preflight::BM1396_FPGA_MEM_ALLOWED_BASES;
use crate::bm1396_fpga_abi::{
    Bm1396FpgaRegisterWrite, BM1396_FPGA_JOB_BUFFER_A_OFFSET, BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET,
    BM1396_FPGA_OUTSTANDING_TABLE_BASE_OFFSET,
};
use crate::bm1396_work::{
    Bm1396NonceRecord, BM1396_NONCE_QUEUE_CAPACITY, BM1396_OUTSTANDING_WORK_RECORD_SIZE,
    BM1396_WORK_ID_MASK,
};

pub const BM1396_HOST_NONCE_RING_HEADER_LEN: usize = 0x0c;
pub const BM1396_HOST_BOUND_NONCE_RECORD_LEN: usize = 0x3c;
pub const BM1396_ACCEPTED_JOB_SNAPSHOT_COUNT: u32 = 3;
pub const BM1396_OUTSTANDING_WORK_ENTRY_COUNT: usize = (BM1396_WORK_ID_MASK as usize) + 1;
pub const BM1396_OUTSTANDING_WORK_TABLE_LEN: usize =
    BM1396_OUTSTANDING_WORK_ENTRY_COUNT * BM1396_OUTSTANDING_WORK_RECORD_SIZE;
pub const BM1396_STOCK_SNAPSHOT_TAIL_OFFSET: usize = 0x40;
pub const BM1396_STOCK_SNAPSHOT_MIDSTATE_OFFSET: usize = 0x80;
pub const BM1396_STOCK_SNAPSHOT_DIFFICULTY_OFFSET: usize = 0x138;
pub const BM1396_STOCK_LOW_DIFFICULTY_COUNTER_INCREMENT: u32 = 0x100;
pub const BM1396_SUBMIT_NONCE_FIXED_WORK_LEN: usize = 0x1c0;
pub const BM1396_SUBMIT_NONCE_FIXED_PREFIX_LEN: usize = 5;
pub const BM1396_SUBMIT_NONCE_FIRST_STRING_LENGTH_OFFSET: usize = 0x1c5;
pub const BM1396_SUBMIT_NONCE_STRING_COUNT: usize = 3;
pub const BM1396_SUBMIT_NONCE_MAX_STRING_LEN: usize = u8::MAX as usize - 1;
pub const BM1396_SUBMIT_NONCE_COMMAND: &str = "bitmain_submit_nonce";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396OutstandingPublicationError {
    UnsupportedPhysicalBase { observed: u32 },
}

/// Pure arithmetic description of the exact initial stock publication. This
/// is deliberately not an MMIO transaction, ownership token, publication
/// barrier, or permission to dispatch work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396InitialOutstandingPublication {
    pub table_physical_base: u32,
    pub table_len: usize,
    pub initial_job_buffer_physical_base: u32,
    pub writes: [Bm1396FpgaRegisterWrite; 2],
}

impl Bm1396InitialOutstandingPublication {
    /// The exact address sequence does not prove cache coherency, FPGA
    /// completion, 15-bit ID allocation/reuse, or a retained carrier lease.
    pub const fn admits_live_publication(&self) -> bool {
        false
    }
}

/// Reconstruct the two exact initial address values for an already-evidenced
/// stock physical base. Only the three bases present in the held firmware are
/// accepted. The returned values remain passive evidence and perform no I/O.
pub fn bm1396_initial_outstanding_publication(
    physical_base: u32,
) -> Result<Bm1396InitialOutstandingPublication, Bm1396OutstandingPublicationError> {
    if !BM1396_FPGA_MEM_ALLOWED_BASES.contains(&physical_base) {
        return Err(Bm1396OutstandingPublicationError::UnsupportedPhysicalBase {
            observed: physical_base,
        });
    }

    let initial_job_buffer_physical_base = physical_base + BM1396_FPGA_JOB_BUFFER_A_OFFSET;
    Ok(Bm1396InitialOutstandingPublication {
        table_physical_base: physical_base,
        table_len: BM1396_OUTSTANDING_WORK_TABLE_LEN,
        initial_job_buffer_physical_base,
        writes: [
            Bm1396FpgaRegisterWrite {
                offset: BM1396_FPGA_OUTSTANDING_TABLE_BASE_OFFSET,
                value: physical_base,
            },
            Bm1396FpgaRegisterWrite {
                offset: BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET,
                value: initial_job_buffer_physical_base,
            },
        ],
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396OutstandingWork {
    pub job_id: u32,
    /// Wire-order word copied unchanged into the host ring. The stock consumer
    /// byte-swaps the complete word before using its low byte for submission.
    pub version_word_wire: u32,
    pub nonce2: u64,
    pub opaque_tail_20_3f: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396OutstandingWorkError {
    WrongEntryLength {
        observed: usize,
    },
    WorkIdOutsideBacking {
        work_id: u16,
        required_end: usize,
        available: usize,
    },
}

pub fn bm1396_decode_outstanding_work(
    entry: &[u8],
) -> Result<Bm1396OutstandingWork, Bm1396OutstandingWorkError> {
    let entry: &[u8; BM1396_OUTSTANDING_WORK_RECORD_SIZE] =
        entry
            .try_into()
            .map_err(|_| Bm1396OutstandingWorkError::WrongEntryLength {
                observed: entry.len(),
            })?;
    let mut tail = [0u8; 32];
    tail.copy_from_slice(&entry[0x20..0x40]);
    Ok(Bm1396OutstandingWork {
        job_id: u32::from_le_bytes([entry[0x00], entry[0x01], entry[0x02], entry[0x03]]),
        version_word_wire: u32::from_le_bytes([entry[0x04], entry[0x05], entry[0x06], entry[0x07]]),
        nonce2: u64::from_le_bytes([
            entry[0x08],
            entry[0x09],
            entry[0x0a],
            entry[0x0b],
            entry[0x0c],
            entry[0x0d],
            entry[0x0e],
            entry[0x0f],
        ]),
        opaque_tail_20_3f: tail,
    })
}

/// Select a complete 64-byte entry without reproducing stock's unchecked
/// pointer arithmetic. The caller supplies the actual mapped table backing;
/// the complete entry must exist even though the exact aperture is 2 MiB.
pub fn bm1396_select_outstanding_work(
    backing: &[u8],
    work_id: u16,
) -> Result<Bm1396OutstandingWork, Bm1396OutstandingWorkError> {
    let offset = usize::from(work_id) * BM1396_OUTSTANDING_WORK_RECORD_SIZE;
    let required_end = offset + BM1396_OUTSTANDING_WORK_RECORD_SIZE;
    let entry = backing.get(offset..required_end).ok_or(
        Bm1396OutstandingWorkError::WorkIdOutsideBacking {
            work_id,
            required_end,
            available: backing.len(),
        },
    )?;
    bm1396_decode_outstanding_work(entry)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396HostBoundNonce {
    pub job_id: u32,
    pub work_id: u16,
    pub version_word_wire: u32,
    pub nonce2: u64,
    pub nonce3: u32,
    pub chain_slot: u8,
    pub opaque_tail_20_3f: [u8; 32],
}

impl Bm1396HostBoundNonce {
    /// Exact logical record copied into the stock host nonce ring.
    pub fn to_host_ring_bytes(&self) -> [u8; BM1396_HOST_BOUND_NONCE_RECORD_LEN] {
        let mut out = [0u8; BM1396_HOST_BOUND_NONCE_RECORD_LEN];
        out[0x00..0x04].copy_from_slice(&self.job_id.to_le_bytes());
        out[0x04..0x08].copy_from_slice(&u32::from(self.work_id).to_le_bytes());
        out[0x08..0x0c].copy_from_slice(&self.version_word_wire.to_le_bytes());
        out[0x0c..0x14].copy_from_slice(&self.nonce2.to_le_bytes());
        out[0x14..0x18].copy_from_slice(&self.nonce3.to_le_bytes());
        out[0x18..0x1c].copy_from_slice(&u32::from(self.chain_slot).to_le_bytes());
        out[0x1c..0x3c].copy_from_slice(&self.opaque_tail_20_3f);
        out
    }

    pub const fn duplicate_key(&self) -> Bm1396DuplicateKey {
        Bm1396DuplicateKey {
            nonce3: self.nonce3,
            work_id: self.work_id,
        }
    }

    pub const fn host_version_word(&self) -> u32 {
        self.version_word_wire.swap_bytes()
    }

    /// Exact fourth callback argument after the stock full-word byte swap.
    /// The receiver uses this byte to select and restore its local pool pointer;
    /// it is not itself the submitted block-version field.
    pub const fn callback_pool_selector_byte(&self) -> u8 {
        self.host_version_word() as u8
    }
}

pub fn bm1396_bind_nonce_to_outstanding(
    nonce: Bm1396NonceRecord,
    outstanding: Bm1396OutstandingWork,
) -> Bm1396HostBoundNonce {
    Bm1396HostBoundNonce {
        job_id: outstanding.job_id,
        work_id: nonce.work_id,
        version_word_wire: outstanding.version_word_wire,
        nonce2: outstanding.nonce2,
        nonce3: nonce.nonce,
        chain_slot: nonce.chain_slot,
        opaque_tail_20_3f: outstanding.opaque_tail_20_3f,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396HostNonceRingState {
    pub write_index: u16,
    pub read_index: u16,
    pub queued: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396HostNonceRingError {
    WriteIndexOutOfRange { observed: u16 },
    ReadIndexOutOfRange { observed: u16 },
    QueuedCountOutOfRange { observed: u16 },
    Full,
    Empty,
}

fn validate_ring(state: Bm1396HostNonceRingState) -> Result<(), Bm1396HostNonceRingError> {
    if state.write_index >= BM1396_NONCE_QUEUE_CAPACITY {
        return Err(Bm1396HostNonceRingError::WriteIndexOutOfRange {
            observed: state.write_index,
        });
    }
    if state.read_index >= BM1396_NONCE_QUEUE_CAPACITY {
        return Err(Bm1396HostNonceRingError::ReadIndexOutOfRange {
            observed: state.read_index,
        });
    }
    if state.queued > BM1396_NONCE_QUEUE_CAPACITY {
        return Err(Bm1396HostNonceRingError::QueuedCountOutOfRange {
            observed: state.queued,
        });
    }
    Ok(())
}

const fn next_ring_index(index: u16) -> u16 {
    if index + 1 == BM1396_NONCE_QUEUE_CAPACITY {
        0
    } else {
        index + 1
    }
}

pub fn bm1396_advance_host_nonce_enqueue(
    state: Bm1396HostNonceRingState,
) -> Result<Bm1396HostNonceRingState, Bm1396HostNonceRingError> {
    validate_ring(state)?;
    if state.queued == BM1396_NONCE_QUEUE_CAPACITY {
        return Err(Bm1396HostNonceRingError::Full);
    }
    Ok(Bm1396HostNonceRingState {
        write_index: next_ring_index(state.write_index),
        read_index: state.read_index,
        queued: state.queued + 1,
    })
}

pub fn bm1396_advance_host_nonce_dequeue(
    state: Bm1396HostNonceRingState,
) -> Result<Bm1396HostNonceRingState, Bm1396HostNonceRingError> {
    validate_ring(state)?;
    if state.queued == 0 {
        return Err(Bm1396HostNonceRingError::Empty);
    }
    Ok(Bm1396HostNonceRingState {
        write_index: state.write_index,
        read_index: next_ring_index(state.read_index),
        queued: state.queued - 1,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1396DuplicateKey {
    pub nonce3: u32,
    pub work_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396JobSnapshot {
    Current,
    Previous,
    Oldest,
}

impl Bm1396JobSnapshot {
    pub const fn from_wrapping_distance(distance: u32) -> Option<Self> {
        match distance {
            0 => Some(Self::Current),
            1 => Some(Self::Previous),
            2 => Some(Self::Oldest),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396ShareValidationPlan {
    /// Snapshot which the caller must clone before validation, matching stock.
    pub snapshot: Bm1396JobSnapshot,
    pub job_id: u32,
    pub work_id: u16,
    pub nonce2: u64,
    pub nonce3: u32,
    pub host_version_word: u32,
    /// Passed to the stock callback after hash qualification. The receiver
    /// uses this byte as an index into its local pool-pointer table.
    pub callback_pool_selector_byte: u8,
    pub chain_slot: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1396HostNonceDisposition {
    DropDuplicate,
    DropOutsideJobWindow { wrapping_distance: u32 },
    Validate(Bm1396ShareValidationPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396HostNonceConsumeResult {
    /// The stock consumer pops the ring before either drop check.
    pub next_ring: Bm1396HostNonceRingState,
    /// A non-duplicate updates this key before job-window admission. Therefore
    /// even an outside-window drop changes the next duplicate decision.
    pub next_duplicate_key: Bm1396DuplicateKey,
    pub disposition: Bm1396HostNonceDisposition,
}

pub fn bm1396_consume_host_nonce(
    ring: Bm1396HostNonceRingState,
    duplicate_key: Bm1396DuplicateKey,
    current_job_id: u32,
    record: &Bm1396HostBoundNonce,
) -> Result<Bm1396HostNonceConsumeResult, Bm1396HostNonceRingError> {
    let next_ring = bm1396_advance_host_nonce_dequeue(ring)?;
    let candidate_key = record.duplicate_key();
    if candidate_key == duplicate_key {
        return Ok(Bm1396HostNonceConsumeResult {
            next_ring,
            next_duplicate_key: duplicate_key,
            disposition: Bm1396HostNonceDisposition::DropDuplicate,
        });
    }

    let distance = current_job_id.wrapping_sub(record.job_id);
    let Some(snapshot) = Bm1396JobSnapshot::from_wrapping_distance(distance) else {
        return Ok(Bm1396HostNonceConsumeResult {
            next_ring,
            next_duplicate_key: candidate_key,
            disposition: Bm1396HostNonceDisposition::DropOutsideJobWindow {
                wrapping_distance: distance,
            },
        });
    };

    Ok(Bm1396HostNonceConsumeResult {
        next_ring,
        next_duplicate_key: candidate_key,
        disposition: Bm1396HostNonceDisposition::Validate(Bm1396ShareValidationPlan {
            snapshot,
            job_id: record.job_id,
            work_id: record.work_id,
            nonce2: record.nonce2,
            nonce3: record.nonce3,
            host_version_word: record.host_version_word(),
            callback_pool_selector_byte: record.callback_pool_selector_byte(),
            chain_slot: record.chain_slot,
        }),
    })
}

/// Caller-supplied fields from the selected stock work snapshot. Exact
/// S17e/T17e consumers load these at `+0x80`, `+0x40`, and `+0x138`
/// respectively after cloning the selected current/previous/oldest work.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1396SelectedSnapshotHashInput {
    pub midstate_words: [u32; 8],
    pub tail_words: [u32; 3],
    pub share_difficulty: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bm1396ShareHashError {
    NonFiniteDifficulty { observed: f64 },
    NegativeDifficulty { observed: f64 },
    DifficultyAboveU64Range { observed: f64 },
}

impl From<Bm1391StockDifficultyNormalizationError> for Bm1396ShareHashError {
    fn from(error: Bm1391StockDifficultyNormalizationError) -> Self {
        match error {
            Bm1391StockDifficultyNormalizationError::NonFinite { observed } => {
                Self::NonFiniteDifficulty { observed }
            }
            Bm1391StockDifficultyNormalizationError::Negative { observed } => {
                Self::NegativeDifficulty { observed }
            }
            Bm1391StockDifficultyNormalizationError::AboveU64Range { observed } => {
                Self::DifficultyAboveU64Range { observed }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396ShareHashDisposition {
    /// The stock consumer calls its `bitmain_submit_nonce` bridge callback.
    InvokeSubmitNonceCallback,
    /// Stock does not invoke the callback, but adds 256 to its low-difficulty
    /// accounting counter.
    IncrementLowDifficultyCounterBy256,
    Drop,
}

/// A pure sequencing token emitted only by the recovered hash gate. Its
/// fields remain private because it is an observation, not a transport or
/// share-submission capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396QualifiedSubmitNonce {
    nonce3: u32,
    callback_pool_selector_byte: u8,
}

impl Bm1396QualifiedSubmitNonce {
    pub const fn nonce3(&self) -> u32 {
        self.nonce3
    }

    pub const fn callback_pool_selector_byte(&self) -> u8 {
        self.callback_pool_selector_byte
    }

    pub const fn admits_callback_transport_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396ShareHashPlan {
    pub normalized_share_difficulty: u64,
    /// Exact eight numeric u32 words after the consumer's final per-word
    /// byte reversal.
    pub digest_words: [u32; 8],
    pub disposition: Bm1396ShareHashDisposition,
    pub qualified_callback: Option<Bm1396QualifiedSubmitNonce>,
}

impl Bm1396ShareHashPlan {
    pub const fn admits_share_submission_authority(&self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }
}

/// Replay the exact post-snapshot BM1396 hash gate recovered in all four held
/// S17e/T17e consumers. The SHA and power-of-two difficulty primitives are
/// byte-semantics-identical to the independently recovered S15/T15 stock
/// primitives and intentionally share that tested implementation.
pub fn bm1396_stock_share_hash_plan(
    validation: &Bm1396ShareValidationPlan,
    snapshot: Bm1396SelectedSnapshotHashInput,
) -> Result<Bm1396ShareHashPlan, Bm1396ShareHashError> {
    let normalized_share_difficulty =
        bm1391_stock_normalize_share_difficulty(snapshot.share_difficulty)
            .map_err(Bm1396ShareHashError::from)?;
    let digest_words = bm1391_stock_double_sha256_from_midstate(Bm1391StockPrecomputedHashInput {
        midstate_words: snapshot.midstate_words,
        tail_words: snapshot.tail_words,
        nonce3: validation.nonce3,
    });
    let disposition =
        match bm1391_stock_digest_disposition(digest_words, normalized_share_difficulty) {
            Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper => {
                Bm1396ShareHashDisposition::InvokeSubmitNonceCallback
            }
            Bm1391StockDigestDisposition::IncrementLowDifficultyCounterBy256 => {
                Bm1396ShareHashDisposition::IncrementLowDifficultyCounterBy256
            }
            Bm1391StockDigestDisposition::Drop => Bm1396ShareHashDisposition::Drop,
        };
    let qualified_callback = (disposition == Bm1396ShareHashDisposition::InvokeSubmitNonceCallback)
        .then_some(Bm1396QualifiedSubmitNonce {
            nonce3: validation.nonce3,
            callback_pool_selector_byte: validation.callback_pool_selector_byte,
        });
    Ok(Bm1396ShareHashPlan {
        normalized_share_difficulty,
        digest_words,
        disposition,
        qualified_callback,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396SubmitNoncePayloadError {
    EmbeddedNul {
        string_index: usize,
        byte_index: usize,
    },
    StringTooLong {
        string_index: usize,
        observed: usize,
        maximum: usize,
    },
    PacketLengthOverflow,
}

/// Build the exact stock command-bridge payload. `fixed_work` is the first
/// 0x1c0 bytes of the cloned work object. Each supplied string excludes its
/// C terminator; the builder appends the length byte and terminator itself.
///
/// Stock truncates each `strlen + 1` to u8 before copying. Clean replay
/// refuses embedded NULs and lengths which would wrap instead.
pub fn bm1396_build_submit_nonce_payload(
    qualified: &Bm1396QualifiedSubmitNonce,
    fixed_work: &[u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN],
    work_strings: [&[u8]; BM1396_SUBMIT_NONCE_STRING_COUNT],
) -> Result<Vec<u8>, Bm1396SubmitNoncePayloadError> {
    let mut packet_len = BM1396_SUBMIT_NONCE_FIRST_STRING_LENGTH_OFFSET;
    for (string_index, string) in work_strings.iter().enumerate() {
        if let Some(byte_index) = string.iter().position(|byte| *byte == 0) {
            return Err(Bm1396SubmitNoncePayloadError::EmbeddedNul {
                string_index,
                byte_index,
            });
        }
        if string.len() > BM1396_SUBMIT_NONCE_MAX_STRING_LEN {
            return Err(Bm1396SubmitNoncePayloadError::StringTooLong {
                string_index,
                observed: string.len(),
                maximum: BM1396_SUBMIT_NONCE_MAX_STRING_LEN,
            });
        }
        packet_len = packet_len
            .checked_add(1)
            .and_then(|length| length.checked_add(string.len()))
            .and_then(|length| length.checked_add(1))
            .ok_or(Bm1396SubmitNoncePayloadError::PacketLengthOverflow)?;
    }

    let mut payload = Vec::with_capacity(packet_len);
    payload.push(qualified.callback_pool_selector_byte);
    payload.extend_from_slice(&qualified.nonce3.to_le_bytes());
    payload.extend_from_slice(fixed_work);
    for (string_index, string) in work_strings.into_iter().enumerate() {
        let encoded_len = u8::try_from(string.len() + 1).map_err(|_| {
            Bm1396SubmitNoncePayloadError::StringTooLong {
                string_index,
                observed: string.len(),
                maximum: BM1396_SUBMIT_NONCE_MAX_STRING_LEN,
            }
        })?;
        payload.push(encoded_len);
        payload.extend_from_slice(string);
        payload.push(0);
    }
    debug_assert_eq!(payload.len(), packet_len);
    Ok(payload)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396SubmitNonceCallbackStep {
    SerializeSelectedWorkClone,
    CallBitmainSubmitNonceCommand,
    LogTransportError,
    FreeSerializedPayload,
    ReturnOne,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396SubmitNonceCallbackPlan {
    pub command: &'static str,
    pub payload: Vec<u8>,
    pub steps: Vec<Bm1396SubmitNonceCallbackStep>,
    /// Exact stock wrapper result. This is one even when the command bridge
    /// reports an error.
    pub stock_return_value: u32,
    pub command_bridge_error_ignored: bool,
}

impl Bm1396SubmitNonceCallbackPlan {
    pub const fn admits_command_transport_authority(&self) -> bool {
        false
    }

    pub const fn proves_callback_receiver_acceptance(&self) -> bool {
        false
    }

    pub const fn proves_pool_acceptance(&self) -> bool {
        false
    }
}

/// Describe the exact callback sequence without invoking the command bridge.
/// `command_bridge_returned_nonzero` is an observation supplied by a future
/// executor: stock logs that case, frees the payload, and still returns one.
pub fn bm1396_submit_nonce_callback_plan(
    qualified: &Bm1396QualifiedSubmitNonce,
    fixed_work: &[u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN],
    work_strings: [&[u8]; BM1396_SUBMIT_NONCE_STRING_COUNT],
    command_bridge_returned_nonzero: bool,
) -> Result<Bm1396SubmitNonceCallbackPlan, Bm1396SubmitNoncePayloadError> {
    let payload = bm1396_build_submit_nonce_payload(qualified, fixed_work, work_strings)?;
    let mut steps = vec![
        Bm1396SubmitNonceCallbackStep::SerializeSelectedWorkClone,
        Bm1396SubmitNonceCallbackStep::CallBitmainSubmitNonceCommand,
    ];
    if command_bridge_returned_nonzero {
        steps.push(Bm1396SubmitNonceCallbackStep::LogTransportError);
    }
    steps.extend([
        Bm1396SubmitNonceCallbackStep::FreeSerializedPayload,
        Bm1396SubmitNonceCallbackStep::ReturnOne,
    ]);
    Ok(Bm1396SubmitNonceCallbackPlan {
        command: BM1396_SUBMIT_NONCE_COMMAND,
        payload,
        steps,
        stock_return_value: 1,
        command_bridge_error_ignored: command_bridge_returned_nonzero,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(work_id: u16, nonce: u32) -> Bm1396NonceRecord {
        Bm1396NonceRecord {
            chain_slot: 3,
            work_id,
            nonce,
            core_id: 0,
            wire_chip_address: 0,
            chip_ordinal: 0,
        }
    }

    fn bound(job_id: u32, work_id: u16, nonce3: u32) -> Bm1396HostBoundNonce {
        Bm1396HostBoundNonce {
            job_id,
            work_id,
            version_word_wire: 0x4433_2211,
            nonce2: 0x1122_3344_5566_7788,
            nonce3,
            chain_slot: 3,
            opaque_tail_20_3f: [0x5a; 32],
        }
    }

    fn validation(nonce3: u32) -> Bm1396ShareValidationPlan {
        Bm1396ShareValidationPlan {
            snapshot: Bm1396JobSnapshot::Current,
            job_id: 7,
            work_id: 9,
            nonce2: 0x1122_3344_5566_7788,
            nonce3,
            host_version_word: 0x1122_3344,
            callback_pool_selector_byte: 0x44,
            chain_slot: 3,
        }
    }

    #[test]
    fn exact_entry_fields_reconstruct_the_sixty_byte_host_record() {
        let mut entry = [0u8; 0x40];
        entry[0x00..0x04].copy_from_slice(&0xaabb_ccddu32.to_le_bytes());
        entry[0x04..0x08].copy_from_slice(&0x4433_2211u32.to_le_bytes());
        entry[0x08..0x10].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        for (index, byte) in entry[0x20..0x40].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let outstanding = bm1396_decode_outstanding_work(&entry).expect("exact entry");
        let record = bm1396_bind_nonce_to_outstanding(nonce(0x1234, 0xdead_beef), outstanding);
        let bytes = record.to_host_ring_bytes();
        assert_eq!(&bytes[0x00..0x04], &0xaabb_ccddu32.to_le_bytes());
        assert_eq!(&bytes[0x04..0x08], &0x1234u32.to_le_bytes());
        assert_eq!(&bytes[0x08..0x0c], &0x4433_2211u32.to_le_bytes());
        assert_eq!(&bytes[0x0c..0x14], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&bytes[0x14..0x18], &0xdead_beefu32.to_le_bytes());
        assert_eq!(&bytes[0x18..0x1c], &3u32.to_le_bytes());
        assert_eq!(&bytes[0x1c..0x3c], &entry[0x20..0x40]);
        assert_eq!(record.host_version_word(), 0x1122_3344);
        assert_eq!(record.callback_pool_selector_byte(), 0x44);
    }

    #[test]
    fn table_selection_rejects_the_first_incomplete_entry() {
        let backing = [0u8; 0x84];
        assert!(bm1396_select_outstanding_work(&backing, 1).is_ok());
        assert_eq!(
            bm1396_select_outstanding_work(&backing, 2),
            Err(Bm1396OutstandingWorkError::WorkIdOutsideBacking {
                work_id: 2,
                required_end: 0xc0,
                available: 0x84,
            })
        );
    }

    #[test]
    fn exact_table_geometry_fills_the_aperture_before_job_buffer_a() {
        assert_eq!(BM1396_OUTSTANDING_WORK_ENTRY_COUNT, 32_768);
        assert_eq!(BM1396_OUTSTANDING_WORK_TABLE_LEN, 0x20_0000);
        assert_eq!(
            BM1396_OUTSTANDING_WORK_TABLE_LEN,
            BM1396_FPGA_JOB_BUFFER_A_OFFSET as usize
        );
    }

    #[test]
    fn initial_publication_is_exact_ordered_and_never_authority() {
        for physical_base in BM1396_FPGA_MEM_ALLOWED_BASES {
            let publication = bm1396_initial_outstanding_publication(physical_base)
                .expect("exact held stock base");
            assert_eq!(publication.table_physical_base, physical_base);
            assert_eq!(publication.table_len, 0x20_0000);
            assert_eq!(
                publication.initial_job_buffer_physical_base,
                physical_base + 0x20_0000
            );
            assert_eq!(
                publication.writes,
                [
                    Bm1396FpgaRegisterWrite {
                        offset: 0x110,
                        value: physical_base,
                    },
                    Bm1396FpgaRegisterWrite {
                        offset: 0x118,
                        value: physical_base + 0x20_0000,
                    },
                ]
            );
            assert!(!publication.admits_live_publication());
        }
    }

    #[test]
    fn initial_publication_rejects_unheld_physical_base() {
        assert_eq!(
            bm1396_initial_outstanding_publication(0x2f00_0000),
            Err(Bm1396OutstandingPublicationError::UnsupportedPhysicalBase {
                observed: 0x2f00_0000,
            })
        );
    }

    #[test]
    fn ring_wraps_at_511_and_never_overwrites_when_full() {
        let state = Bm1396HostNonceRingState {
            write_index: 510,
            read_index: 17,
            queued: 510,
        };
        assert_eq!(
            bm1396_advance_host_nonce_enqueue(state),
            Ok(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 17,
                queued: 511,
            })
        );
        assert_eq!(
            bm1396_advance_host_nonce_enqueue(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 17,
                queued: 511,
            }),
            Err(Bm1396HostNonceRingError::Full)
        );
        assert_eq!(
            bm1396_advance_host_nonce_dequeue(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 510,
                queued: 1,
            }),
            Ok(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 0,
                queued: 0,
            })
        );
        assert_eq!(
            bm1396_advance_host_nonce_dequeue(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 0,
                queued: 0,
            }),
            Err(Bm1396HostNonceRingError::Empty)
        );
        assert!(matches!(
            bm1396_advance_host_nonce_enqueue(Bm1396HostNonceRingState {
                write_index: 511,
                read_index: 0,
                queued: 0,
            }),
            Err(Bm1396HostNonceRingError::WriteIndexOutOfRange { observed: 511 })
        ));
        assert!(matches!(
            bm1396_advance_host_nonce_dequeue(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 511,
                queued: 1,
            }),
            Err(Bm1396HostNonceRingError::ReadIndexOutOfRange { observed: 511 })
        ));
        assert!(matches!(
            bm1396_advance_host_nonce_enqueue(Bm1396HostNonceRingState {
                write_index: 0,
                read_index: 0,
                queued: 512,
            }),
            Err(Bm1396HostNonceRingError::QueuedCountOutOfRange { observed: 512 })
        ));
    }

    #[test]
    fn duplicate_drop_occurs_after_pop_without_changing_key() {
        let record = bound(7, 9, 11);
        let result = bm1396_consume_host_nonce(
            Bm1396HostNonceRingState {
                write_index: 4,
                read_index: 3,
                queued: 1,
            },
            record.duplicate_key(),
            7,
            &record,
        )
        .expect("non-empty valid ring");
        assert_eq!(result.next_ring.read_index, 4);
        assert_eq!(result.next_ring.queued, 0);
        assert_eq!(result.next_duplicate_key, record.duplicate_key());
        assert_eq!(
            result.disposition,
            Bm1396HostNonceDisposition::DropDuplicate
        );
    }

    #[test]
    fn outside_window_drop_updates_duplicate_key_first() {
        let record = bound(96, 12, 34);
        let result = bm1396_consume_host_nonce(
            Bm1396HostNonceRingState {
                write_index: 1,
                read_index: 0,
                queued: 1,
            },
            Bm1396DuplicateKey::default(),
            100,
            &record,
        )
        .expect("non-empty valid ring");
        assert_eq!(result.next_duplicate_key, record.duplicate_key());
        assert_eq!(
            result.disposition,
            Bm1396HostNonceDisposition::DropOutsideJobWindow {
                wrapping_distance: 4,
            }
        );
    }

    #[test]
    fn job_window_uses_wrapping_subtraction_for_current_previous_oldest() {
        let ring = Bm1396HostNonceRingState {
            write_index: 3,
            read_index: 0,
            queued: 3,
        };
        let cases = [
            (0u32, 0u32, Bm1396JobSnapshot::Current),
            (0u32, u32::MAX, Bm1396JobSnapshot::Previous),
            (1u32, u32::MAX, Bm1396JobSnapshot::Oldest),
        ];
        for (index, (current, returned, expected)) in cases.into_iter().enumerate() {
            let record = bound(returned, index as u16 + 1, index as u32 + 1);
            let result =
                bm1396_consume_host_nonce(ring, Bm1396DuplicateKey::default(), current, &record)
                    .expect("non-empty valid ring");
            let Bm1396HostNonceDisposition::Validate(plan) = result.disposition else {
                panic!("expected validation plan");
            };
            assert_eq!(plan.snapshot, expected);
            assert_eq!(plan.host_version_word, 0x1122_3344);
            assert_eq!(plan.callback_pool_selector_byte, 0x44);
        }
    }

    #[test]
    fn future_job_id_is_not_mistaken_for_previous_work() {
        let record = bound(1, 2, 3);
        let result = bm1396_consume_host_nonce(
            Bm1396HostNonceRingState {
                write_index: 1,
                read_index: 0,
                queued: 1,
            },
            Bm1396DuplicateKey::default(),
            0,
            &record,
        )
        .expect("non-empty valid ring");
        assert_eq!(
            result.disposition,
            Bm1396HostNonceDisposition::DropOutsideJobWindow {
                wrapping_distance: u32::MAX,
            }
        );
    }

    #[test]
    fn genesis_midstate_replays_exact_bm1396_hash_and_callback_gate() {
        let plan = bm1396_stock_share_hash_plan(
            &validation(0x1dac_2b7c),
            Bm1396SelectedSnapshotHashInput {
                midstate_words: [
                    0xbc90_9a33,
                    0x6358_bff0,
                    0x90cc_ac7d,
                    0x1e59_caa8,
                    0xc3c8_d8e9,
                    0x4f01_03c8,
                    0x96b1_8736,
                    0x4719_f91b,
                ],
                tail_words: [0x4b1e_5e4a, 0x29ab_5f49, 0xffff_001d],
                share_difficulty: 1.0,
            },
        )
        .expect("finite exact difficulty");
        assert_eq!(
            plan.digest_words,
            [
                0x6fe2_8c0a,
                0xb6f1_b372,
                0xc1a6_a246,
                0xae63_f74f,
                0x931e_8365,
                0xe15a_089c,
                0x68d6_1900,
                0,
            ]
        );
        assert_eq!(
            plan.disposition,
            Bm1396ShareHashDisposition::InvokeSubmitNonceCallback
        );
        let qualified = plan.qualified_callback.expect("qualified callback");
        assert_eq!(qualified.nonce3(), 0x1dac_2b7c);
        assert_eq!(qualified.callback_pool_selector_byte(), 0x44);
        assert!(!qualified.admits_callback_transport_authority());
        assert!(!plan.admits_share_submission_authority());
        assert!(!plan.proves_pool_acceptance());
    }

    #[test]
    fn hash_gate_refuses_undefined_difficulty_conversion_domains() {
        let snapshot = |share_difficulty| Bm1396SelectedSnapshotHashInput {
            midstate_words: [0; 8],
            tail_words: [0; 3],
            share_difficulty,
        };
        assert!(matches!(
            bm1396_stock_share_hash_plan(&validation(1), snapshot(f64::NAN)),
            Err(Bm1396ShareHashError::NonFiniteDifficulty { observed }) if observed.is_nan()
        ));
        assert_eq!(
            bm1396_stock_share_hash_plan(&validation(1), snapshot(-1.0)),
            Err(Bm1396ShareHashError::NegativeDifficulty { observed: -1.0 })
        );
        assert_eq!(
            bm1396_stock_share_hash_plan(&validation(1), snapshot(18_446_744_073_709_551_616.0)),
            Err(Bm1396ShareHashError::DifficultyAboveU64Range {
                observed: 18_446_744_073_709_551_616.0,
            })
        );
    }

    #[test]
    fn submit_nonce_payload_pins_prefix_fixed_clone_and_three_c_strings() {
        let hash = bm1396_stock_share_hash_plan(
            &validation(0x1dac_2b7c),
            Bm1396SelectedSnapshotHashInput {
                midstate_words: [
                    0xbc90_9a33,
                    0x6358_bff0,
                    0x90cc_ac7d,
                    0x1e59_caa8,
                    0xc3c8_d8e9,
                    0x4f01_03c8,
                    0x96b1_8736,
                    0x4719_f91b,
                ],
                tail_words: [0x4b1e_5e4a, 0x29ab_5f49, 0xffff_001d],
                share_difficulty: 1.0,
            },
        )
        .expect("qualified genesis");
        let qualified = hash.qualified_callback.expect("qualified callback");
        let fixed_work = [0xa5; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
        let payload =
            bm1396_build_submit_nonce_payload(&qualified, &fixed_work, [b"alpha", b"", b"gamma"])
                .expect("bounded C strings");
        assert_eq!(payload.len(), 0x1cb + 5 + 5);
        assert_eq!(payload[0], 0x44);
        assert_eq!(&payload[1..5], &0x1dac_2b7cu32.to_le_bytes());
        assert_eq!(&payload[5..0x1c5], &fixed_work);
        assert_eq!(&payload[0x1c5..0x1cc], b"\x06alpha\0");
        assert_eq!(&payload[0x1cc..0x1ce], b"\x01\0");
        assert_eq!(&payload[0x1ce..], b"\x06gamma\0");
    }

    #[test]
    fn submit_nonce_payload_fails_closed_before_stock_u8_length_wrap() {
        let qualified = Bm1396QualifiedSubmitNonce {
            nonce3: 1,
            callback_pool_selector_byte: 2,
        };
        let fixed_work = [0u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
        let too_long = [b'x'; BM1396_SUBMIT_NONCE_MAX_STRING_LEN + 1];
        assert_eq!(
            bm1396_build_submit_nonce_payload(&qualified, &fixed_work, [&too_long, b"", b""]),
            Err(Bm1396SubmitNoncePayloadError::StringTooLong {
                string_index: 0,
                observed: 255,
                maximum: 254,
            })
        );
        assert_eq!(
            bm1396_build_submit_nonce_payload(&qualified, &fixed_work, [b"a\0b", b"", b""]),
            Err(Bm1396SubmitNoncePayloadError::EmbeddedNul {
                string_index: 0,
                byte_index: 1,
            })
        );
    }

    #[test]
    fn callback_transport_error_is_logged_freed_and_still_returns_one() {
        let qualified = Bm1396QualifiedSubmitNonce {
            nonce3: 0x4433_2211,
            callback_pool_selector_byte: 0x5a,
        };
        let fixed_work = [0u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
        let plan = bm1396_submit_nonce_callback_plan(
            &qualified,
            &fixed_work,
            [b"one", b"two", b"three"],
            true,
        )
        .expect("bounded callback payload");
        assert_eq!(plan.command, "bitmain_submit_nonce");
        assert_eq!(plan.stock_return_value, 1);
        assert!(plan.command_bridge_error_ignored);
        assert_eq!(
            plan.steps,
            [
                Bm1396SubmitNonceCallbackStep::SerializeSelectedWorkClone,
                Bm1396SubmitNonceCallbackStep::CallBitmainSubmitNonceCommand,
                Bm1396SubmitNonceCallbackStep::LogTransportError,
                Bm1396SubmitNonceCallbackStep::FreeSerializedPayload,
                Bm1396SubmitNonceCallbackStep::ReturnOne,
            ]
        );
        assert!(!plan.admits_command_transport_authority());
        assert!(!plan.proves_callback_receiver_acceptance());
        assert!(!plan.proves_pool_acceptance());
    }

    #[test]
    fn callback_success_path_omits_error_log_but_proves_no_acceptance() {
        let qualified = Bm1396QualifiedSubmitNonce {
            nonce3: 1,
            callback_pool_selector_byte: 2,
        };
        let fixed_work = [0u8; BM1396_SUBMIT_NONCE_FIXED_WORK_LEN];
        let plan =
            bm1396_submit_nonce_callback_plan(&qualified, &fixed_work, [b"", b"", b""], false)
                .expect("empty C strings are encoded as one-byte terminators");
        assert!(!plan.command_bridge_error_ignored);
        assert!(!plan
            .steps
            .contains(&Bm1396SubmitNonceCallbackStep::LogTransportError));
        assert_eq!(plan.payload.len(), 0x1cb);
        assert!(!plan.proves_callback_receiver_acceptance());
    }
}
