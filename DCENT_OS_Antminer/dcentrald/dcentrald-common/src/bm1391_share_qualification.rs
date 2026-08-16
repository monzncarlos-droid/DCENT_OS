//! Pure replay of the stock S15/T15 BM1391 nonce-consumer gates.
//!
//! Exact held S15 `cgminer` (`FUN_0003a998`) and T15 `cgminer`
//! (`FUN_0003a998`) consume the 60-byte records produced by
//! [`crate::bm1391_stock_return`]. Both releases pop the ring entry before any
//! duplicate, age, hash, or target rejection; suppress duplicates by
//! `(nonce3, work_id)`; retain only wrapping job ages zero through two; and
//! select one of three saved work snapshots before reconstructing and hashing
//! the 80-byte header.
//!
//! This module stops at pure observations. The record, current job id,
//! duplicate state, saved SHA state, target words, difficulty, and chain state
//! are all supplied by the caller. It owns no queue lock, work snapshot,
//! target provenance, carrier, pool session, or asynchronous submit queue and
//! therefore cannot authorize a share submission or hardware I/O. The exact
//! async admission helper is replayed separately so invoking it is never
//! confused with queueing, network delivery, or pool acceptance.

use crate::bm1391_stock_return::{
    Bm1391StockBoundNonce, BM1391_STOCK_BOUND_NONCE_RECORD_LEN, BM1391_STOCK_RETURN_RING_CAPACITY,
};

pub const BM1391_STOCK_RETURN_RING_HEADER_LEN: usize = 0x0c;
pub const BM1391_STOCK_CURRENT_SNAPSHOT_OFFSET: usize = 0x02e0;
pub const BM1391_STOCK_PREVIOUS_ONE_SNAPSHOT_OFFSET: usize = 0x0a18;
pub const BM1391_STOCK_PREVIOUS_TWO_SNAPSHOT_OFFSET: usize = 0x1150;
pub const BM1391_STOCK_LOW_DIFFICULTY_COUNTER_INCREMENT: u32 = 0x100;
pub const BM1391_STOCK_LOW_DIFFICULTY_WORD_MAX: u32 = 0x00ff_fffe;
pub const BM1391_STOCK_TWO_NEGATIVE_32_F64_BITS: u64 = 0x3df0_0000_0000_0000;
pub const BM1391_STOCK_TWO_POSITIVE_32_F64_BITS: u64 = 0x41f0_0000_0000_0000;
pub const BM1391_STOCK_HEADER_BYTE_LEN: u32 = 80;
pub const BM1391_STOCK_SNAPSHOT_TAIL_OFFSET: usize = 0x40;
pub const BM1391_STOCK_SNAPSHOT_MIDSTATE_OFFSET: usize = 0x80;
pub const BM1391_STOCK_SHA_CONTEXT_WORDS: usize = 14;
pub const BM1391_STOCK_WORK_NONCE_OFFSET: usize = 0x4c;
pub const BM1391_STOCK_WORK_TARGET_OFFSET: usize = 0xa0;
pub const BM1391_STOCK_WORK_DIGEST_OFFSET: usize = 0xc0;
pub const BM1391_STOCK_WORK_DIGEST_LAST_WORD_OFFSET: usize = 0xdc;
pub const BM1391_STOCK_COPY_WORK_NOFFSET: u32 = 0x0001_6148;
pub const BM1391_STOCK_SUBMIT_WORK_ASYNC: u32 = 0x0002_1b74;
pub const BM1391_STOCK_STALE_WORK: u32 = 0x0001_f1b8;
pub const BM1391_STOCK_STRATUM_QUEUE_PUSH: u32 = 0x0002_6444;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bm1391StockDifficultyNormalizationError {
    NonFinite { observed: f64 },
    Negative { observed: f64 },
    AboveU64Range { observed: f64 },
}

/// Replay the stock finite-domain `f64` difficulty split into a logical u64.
///
/// Exact S15 `FUN_00090c40` and T15 `FUN_00090b60` multiply by 2^-32,
/// truncate that quotient to the high u32, subtract `high * 2^32`, and
/// truncate the remainder to the low u32. Stock does not establish safe ARM
/// conversion behavior for negative, non-finite, or >=2^64 inputs, so clean
/// replay refuses those values rather than emulating an undocumented result.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn bm1391_stock_normalize_share_difficulty(
    difficulty: f64,
) -> Result<u64, Bm1391StockDifficultyNormalizationError> {
    if !difficulty.is_finite() {
        return Err(Bm1391StockDifficultyNormalizationError::NonFinite {
            observed: difficulty,
        });
    }
    if difficulty < 0.0 {
        return Err(Bm1391StockDifficultyNormalizationError::Negative {
            observed: difficulty,
        });
    }
    if difficulty >= 18_446_744_073_709_551_616.0 {
        return Err(Bm1391StockDifficultyNormalizationError::AboveU64Range {
            observed: difficulty,
        });
    }

    let two_negative_32 = f64::from_bits(BM1391_STOCK_TWO_NEGATIVE_32_F64_BITS);
    let two_positive_32 = f64::from_bits(BM1391_STOCK_TWO_POSITIVE_32_F64_BITS);
    let high = (difficulty * two_negative_32).trunc() as u32;
    let low = (difficulty - f64::from(high) * two_positive_32).trunc() as u32;
    Ok((u64::from(high) << 32) | u64::from(low))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockPrecomputedHashInput {
    /// SHA-256 state copied without byte conversion from snapshot
    /// `+0x80..+0x9c`.
    pub midstate_words: [u32; 8],
    /// The three header-tail words loaded from snapshot `+0x40..+0x48`.
    /// Stock byte-reverses each word before storing it in the SHA context.
    pub tail_words: [u32; 3],
    /// Full returned nonce3. Stock byte-reverses it as the fourth tail word.
    pub nonce3: u32,
}

/// Build the exact 56-byte stock SHA-256 context prefix before finalization.
///
/// The returned words are the native little-endian ARM memory values:
/// byte-count low/high, eight SHA state words, three byte-reversed snapshot
/// tail words, and byte-reversed nonce3.
pub fn bm1391_stock_sha_context_words(
    input: Bm1391StockPrecomputedHashInput,
) -> [u32; BM1391_STOCK_SHA_CONTEXT_WORDS] {
    let mut words = [0u32; BM1391_STOCK_SHA_CONTEXT_WORDS];
    words[0] = BM1391_STOCK_HEADER_BYTE_LEN;
    words[2..10].copy_from_slice(&input.midstate_words);
    for (destination, source) in words[10..13].iter_mut().zip(input.tail_words) {
        *destination = source.swap_bytes();
    }
    words[13] = input.nonce3.swap_bytes();
    words
}

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[allow(clippy::indexing_slicing)]
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut schedule = [0u32; 64];
    for (index, word) in schedule[..16].iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let sigma0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let sigma1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let temporary1 = h
            .wrapping_add(big_sigma1)
            .wrapping_add(choose)
            .wrapping_add(SHA256_ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = big_sigma0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temporary1);
        d = c;
        c = b;
        b = a;
        a = temporary1.wrapping_add(temporary2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

/// Replay the exact midstate-based double-SHA256 path used by both consumers.
///
/// The result is the eight numeric words after stock's final per-word byte
/// reversal, which is the input shape expected by
/// [`bm1391_stock_digest_disposition`]. Inputs remain caller-forgeable and
/// this helper grants no work-generation, pool, or submission authority.
#[allow(clippy::indexing_slicing)]
pub fn bm1391_stock_double_sha256_from_midstate(
    input: Bm1391StockPrecomputedHashInput,
) -> [u32; 8] {
    let mut first_final_block = [0u8; 64];
    for (index, word) in input
        .tail_words
        .into_iter()
        .chain([input.nonce3])
        .enumerate()
    {
        let offset = index * 4;
        first_final_block[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    first_final_block[16] = 0x80;
    first_final_block[56..64]
        .copy_from_slice(&(u64::from(BM1391_STOCK_HEADER_BYTE_LEN) * 8).to_be_bytes());

    let mut first_digest_words = input.midstate_words;
    sha256_compress(&mut first_digest_words, &first_final_block);

    let mut second_block = [0u8; 64];
    for (index, word) in first_digest_words.into_iter().enumerate() {
        let offset = index * 4;
        second_block[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    second_block[32] = 0x80;
    second_block[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());

    let mut second_digest_words = SHA256_INITIAL_STATE;
    sha256_compress(&mut second_digest_words, &second_block);
    second_digest_words
}

/// Shared stock-cgminer primitive used by the co-bundled BM1396 command
/// receiver. The work object stores each of the twenty header words in the
/// opposite byte order from the byte stream passed to SHA-256.
///
/// This remains crate-private because it is a replay primitive, not a work or
/// pool-target authority surface.
#[allow(clippy::indexing_slicing)]
pub(crate) fn stock_double_sha256_from_word_swapped_header(
    work_header: &[u8; BM1391_STOCK_HEADER_BYTE_LEN as usize],
) -> [u32; 8] {
    let mut canonical_header = [0u8; BM1391_STOCK_HEADER_BYTE_LEN as usize];
    for word_index in 0..20 {
        let offset = word_index * 4;
        canonical_header[offset] = work_header[offset + 3];
        canonical_header[offset + 1] = work_header[offset + 2];
        canonical_header[offset + 2] = work_header[offset + 1];
        canonical_header[offset + 3] = work_header[offset];
    }

    let mut first_state = SHA256_INITIAL_STATE;
    let mut first_block = [0u8; 64];
    first_block.copy_from_slice(&canonical_header[..64]);
    sha256_compress(&mut first_state, &first_block);

    let mut first_final_block = [0u8; 64];
    first_final_block[..16].copy_from_slice(&canonical_header[64..]);
    first_final_block[16] = 0x80;
    first_final_block[56..64]
        .copy_from_slice(&(u64::from(BM1391_STOCK_HEADER_BYTE_LEN) * 8).to_be_bytes());
    sha256_compress(&mut first_state, &first_final_block);

    let mut second_block = [0u8; 64];
    for (index, word) in first_state.into_iter().enumerate() {
        let offset = index * 4;
        second_block[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    second_block[32] = 0x80;
    second_block[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());
    let mut second_state = SHA256_INITIAL_STATE;
    sha256_compress(&mut second_state, &second_block);
    second_state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockConsumerRecord {
    pub job_id: u32,
    pub work_id: u16,
    /// The value printed as `version` and supplied to the stock work-clone
    /// helper. The queued u32 is byte-reversed once by the consumer.
    pub version: u32,
    pub nonce2: u64,
    pub nonce3: u32,
    pub chain_slot: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockConsumerRecordError {
    WrongLength { observed: usize },
    WorkIdOutsideFifteenBits { observed: u32 },
    ChainOutsideLowNibble { observed: u32 },
}

/// Decode the exact logical 60-byte record, excluding the stock ring's
/// preceding 12-byte `{write_index, read_index, count}` header.
pub fn decode_bm1391_stock_consumer_record(
    record: &[u8],
) -> Result<Bm1391StockConsumerRecord, Bm1391StockConsumerRecordError> {
    let record: &[u8; BM1391_STOCK_BOUND_NONCE_RECORD_LEN] =
        record
            .try_into()
            .map_err(|_| Bm1391StockConsumerRecordError::WrongLength {
                observed: record.len(),
            })?;
    let read_u32 = |offset: usize| {
        let bytes: [u8; 4] = record
            .get(offset..offset.saturating_add(4))
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Bm1391StockConsumerRecordError::WrongLength {
                observed: record.len(),
            })?;
        Ok::<u32, Bm1391StockConsumerRecordError>(u32::from_le_bytes(bytes))
    };
    let work_id = read_u32(0x04)?;
    if work_id > 0x7fff {
        return Err(Bm1391StockConsumerRecordError::WorkIdOutsideFifteenBits { observed: work_id });
    }
    let chain_slot = read_u32(0x18)?;
    if chain_slot > 0x0f {
        return Err(Bm1391StockConsumerRecordError::ChainOutsideLowNibble {
            observed: chain_slot,
        });
    }
    Ok(Bm1391StockConsumerRecord {
        job_id: read_u32(0x00)?,
        work_id: work_id as u16,
        version: read_u32(0x08)?.swap_bytes(),
        nonce2: u64::from(read_u32(0x0c)?) | (u64::from(read_u32(0x10)?) << 32),
        nonce3: read_u32(0x14)?,
        chain_slot: chain_slot as u8,
    })
}

impl Bm1391StockBoundNonce {
    pub fn stock_consumer_record(
        &self,
    ) -> Result<Bm1391StockConsumerRecord, Bm1391StockConsumerRecordError> {
        decode_bm1391_stock_consumer_record(&self.to_stock_queue_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockConsumerRingState {
    pub read_index: u16,
    pub queued: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockRingPop {
    pub popped_index: u16,
    pub next: Bm1391StockConsumerRingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockConsumerRingError {
    ReadIndexOutOfRange { observed: u16 },
    QueuedCountOutOfRange { observed: u16 },
    Empty,
}

/// Exact successful pop arithmetic. Stock performs this mutation before its
/// first duplicate or stale-return branch.
pub fn pop_bm1391_stock_consumer_ring(
    state: Bm1391StockConsumerRingState,
) -> Result<Bm1391StockRingPop, Bm1391StockConsumerRingError> {
    if state.read_index >= BM1391_STOCK_RETURN_RING_CAPACITY {
        return Err(Bm1391StockConsumerRingError::ReadIndexOutOfRange {
            observed: state.read_index,
        });
    }
    if state.queued > BM1391_STOCK_RETURN_RING_CAPACITY {
        return Err(Bm1391StockConsumerRingError::QueuedCountOutOfRange {
            observed: state.queued,
        });
    }
    if state.queued == 0 {
        return Err(Bm1391StockConsumerRingError::Empty);
    }
    Ok(Bm1391StockRingPop {
        popped_index: state.read_index,
        next: Bm1391StockConsumerRingState {
            read_index: if state.read_index + 1 == BM1391_STOCK_RETURN_RING_CAPACITY {
                0
            } else {
                state.read_index + 1
            },
            queued: state.queued - 1,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockDuplicateKey {
    pub nonce3: u32,
    pub work_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockSnapshotAge {
    Current,
    PreviousOne,
    PreviousTwo,
}

impl Bm1391StockSnapshotAge {
    pub const fn stock_offset(self) -> usize {
        match self {
            Self::Current => BM1391_STOCK_CURRENT_SNAPSHOT_OFFSET,
            Self::PreviousOne => BM1391_STOCK_PREVIOUS_ONE_SNAPSHOT_OFFSET,
            Self::PreviousTwo => BM1391_STOCK_PREVIOUS_TWO_SNAPSHOT_OFFSET,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockPreHashDisposition {
    Duplicate {
        account_hardware_error: bool,
    },
    Snapshot(Bm1391StockSnapshotAge),
    Stale {
        wrapping_age: u32,
        account_hardware_error: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockPreHashStep {
    pub next_duplicate_key: Bm1391StockDuplicateKey,
    pub disposition: Bm1391StockPreHashDisposition,
}

/// Replay the exact duplicate and three-snapshot gates after a successful
/// ring pop. A nonduplicate key is committed before stock checks job age, so a
/// stale record becomes the next duplicate key too.
pub const fn bm1391_stock_pre_hash_step(
    record: Bm1391StockConsumerRecord,
    previous_duplicate_key: Bm1391StockDuplicateKey,
    current_job_id: u32,
    chain_state_is_one: bool,
) -> Bm1391StockPreHashStep {
    let key = Bm1391StockDuplicateKey {
        nonce3: record.nonce3,
        work_id: record.work_id,
    };
    if key.nonce3 == previous_duplicate_key.nonce3 && key.work_id == previous_duplicate_key.work_id
    {
        return Bm1391StockPreHashStep {
            next_duplicate_key: previous_duplicate_key,
            disposition: Bm1391StockPreHashDisposition::Duplicate {
                account_hardware_error: chain_state_is_one,
            },
        };
    }

    let wrapping_age = current_job_id.wrapping_sub(record.job_id);
    let disposition = match wrapping_age {
        0 => Bm1391StockPreHashDisposition::Snapshot(Bm1391StockSnapshotAge::Current),
        1 => Bm1391StockPreHashDisposition::Snapshot(Bm1391StockSnapshotAge::PreviousOne),
        2 => Bm1391StockPreHashDisposition::Snapshot(Bm1391StockSnapshotAge::PreviousTwo),
        _ => Bm1391StockPreHashDisposition::Stale {
            wrapping_age,
            account_hardware_error: chain_state_is_one,
        },
    };
    Bm1391StockPreHashStep {
        next_duplicate_key: key,
        disposition,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockDigestDisposition {
    /// Stock reaches its generic submit wrapper. That wrapper may still miss
    /// the full target, and its async helper may still discard before queueing.
    StockWouldInvokeSubmitWrapper,
    /// Stock does not submit, but adds `0x100` to its per-chain low-difficulty
    /// accounting counter.
    IncrementLowDifficultyCounterBy256,
    Drop,
}

impl Bm1391StockDigestDisposition {
    pub const fn admits_share_submission_authority(self) -> bool {
        false
    }
}

/// Replay the exact power-of-two share-difficulty comparison after stock has
/// reconstructed and double-SHA256-hashed the 80-byte header.
///
/// `digest_words` are the eight u32 values after stock copies the SHA output
/// and byte-reverses each word. The exact comparison reverses the selected
/// word again. `normalized_share_difficulty` is the output of the stock
/// release's preceding f64-to-u64 normalization helper, not an
/// independently authenticated pool value. The threshold uses
/// `floor(log2(normalized_share_difficulty))`; it is not a general 256-bit
/// target comparison. A zero value is rejected.
pub fn bm1391_stock_digest_disposition(
    digest_words: [u32; 8],
    normalized_share_difficulty: u64,
) -> Bm1391StockDigestDisposition {
    if digest_words[7] != 0 || normalized_share_difficulty == 0 {
        return Bm1391StockDigestDisposition::Drop;
    }

    let difficulty_bit = 63 - normalized_share_difficulty.leading_zeros();
    let word_shift = difficulty_bit / 32;
    let mut leading_zero_words = 0u32;
    for word in digest_words[..7].iter().rev() {
        if *word != 0 {
            break;
        }
        leading_zero_words += 1;
    }
    if word_shift > leading_zero_words {
        return Bm1391StockDigestDisposition::Drop;
    }

    let selected_index = 6usize - word_shift as usize;
    let Some(selected) = digest_words.get(selected_index).copied() else {
        return Bm1391StockDigestDisposition::Drop;
    };
    let selected = selected.swap_bytes();
    let threshold = u32::MAX >> (difficulty_bit & 0x1f);
    if selected < threshold {
        return Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper;
    }
    if digest_words[6].swap_bytes() <= BM1391_STOCK_LOW_DIFFICULTY_WORD_MAX {
        return Bm1391StockDigestDisposition::IncrementLowDifficultyCounterBy256;
    }
    Bm1391StockDigestDisposition::Drop
}

/// Exact generic 256-bit comparison used after the submit wrapper regenerates
/// the work hash.
///
/// Both inputs are the eight native u32 words stored in the stock work object.
/// Word seven is the most-significant limb. Equality passes, matching cgminer's
/// `fulltest` helper. Target provenance is deliberately outside this function.
pub fn bm1391_stock_full_target_passes(digest_words: [u32; 8], target_words: [u32; 8]) -> bool {
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
pub struct Bm1391StockSubmitWrapperInput {
    /// Last nonce retained in the stock device state at `+0xec`.
    pub previous_device_nonce: u32,
    pub returned_nonce: u32,
    /// Regenerated double-SHA256 words stored at work `+0xc0..+0xdc`.
    pub digest_words: [u32; 8],
    /// Current work target words stored at work `+0xa0..+0xbc`.
    pub target_words: [u32; 8],
    /// Conjunction of the two stock globals that enables its optional bench
    /// diagnostic after the target helper returns.
    pub bench_diagnostic_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockSubmitWrapperStep {
    CheckDeviceNonceNotRepeated,
    CommitDeviceLastNonce { nonce: u32 },
    StoreNonceInWork { offset: usize, nonce: u32 },
    RegenerateDoubleSha256 { digest_offset: usize },
    AccountHardwareError,
    UpdateWorkStatistics,
    CompareFullDigestWithWorkTarget { target_offset: usize },
    CloneWorkForAsyncSubmission,
    InvokeAsyncSubmissionPath,
    FullTargetMissNoAsyncSubmission,
    EmitBenchDiagnostic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1391StockSubmitWrapperPlan {
    pub next_device_nonce: u32,
    pub steps: Vec<Bm1391StockSubmitWrapperStep>,
    /// Exact return from the generic stock wrapper. A value of one means only
    /// that the repeat-nonce and digest-word-seven prechecks passed.
    pub wrapper_returns_one: bool,
    pub full_target_passed: Option<bool>,
    /// A full-target pass calls stock's async admission helper. That helper can
    /// still discard or fail before queueing, so this is intentionally not a
    /// queue/delivery claim.
    pub async_submission_would_be_invoked: bool,
}

impl Bm1391StockSubmitWrapperPlan {
    pub const fn admits_pool_acceptance_authority(&self) -> bool {
        false
    }

    pub const fn admits_share_submission_authority(&self) -> bool {
        false
    }
}

/// Replay exact S15/T15 `FUN_000223f0` submit-wrapper control flow.
///
/// The wrapper rejects a repeat of the device's immediately preceding nonce,
/// commits every new nonce before hashing, stores nonce at work `+0x4c`,
/// regenerates the 80-byte double SHA into `+0xc0`, and requires digest word
/// seven at `+0xdc` to be zero. Either precheck failure accounts one hardware
/// error and returns zero. Otherwise the nested `submit_tested_work` updates
/// statistics, performs the full eight-word target comparison, and invokes the
/// asynchronous submission path with a work clone only on a pass. Critically,
/// the async helper can still discard before queueing, and the outer wrapper
/// discards that nested boolean and returns one even on a full-target miss.
/// It never waits for or observes a pool response.
pub fn bm1391_stock_submit_wrapper_plan(
    input: Bm1391StockSubmitWrapperInput,
) -> Bm1391StockSubmitWrapperPlan {
    let mut steps = vec![Bm1391StockSubmitWrapperStep::CheckDeviceNonceNotRepeated];
    if input.previous_device_nonce == input.returned_nonce {
        steps.push(Bm1391StockSubmitWrapperStep::AccountHardwareError);
        return Bm1391StockSubmitWrapperPlan {
            next_device_nonce: input.previous_device_nonce,
            steps,
            wrapper_returns_one: false,
            full_target_passed: None,
            async_submission_would_be_invoked: false,
        };
    }

    steps.push(Bm1391StockSubmitWrapperStep::CommitDeviceLastNonce {
        nonce: input.returned_nonce,
    });
    steps.push(Bm1391StockSubmitWrapperStep::StoreNonceInWork {
        offset: BM1391_STOCK_WORK_NONCE_OFFSET,
        nonce: input.returned_nonce,
    });
    steps.push(Bm1391StockSubmitWrapperStep::RegenerateDoubleSha256 {
        digest_offset: BM1391_STOCK_WORK_DIGEST_OFFSET,
    });
    if input.digest_words[7] != 0 {
        steps.push(Bm1391StockSubmitWrapperStep::AccountHardwareError);
        return Bm1391StockSubmitWrapperPlan {
            next_device_nonce: input.returned_nonce,
            steps,
            wrapper_returns_one: false,
            full_target_passed: None,
            async_submission_would_be_invoked: false,
        };
    }

    steps.push(Bm1391StockSubmitWrapperStep::UpdateWorkStatistics);
    steps.push(
        Bm1391StockSubmitWrapperStep::CompareFullDigestWithWorkTarget {
            target_offset: BM1391_STOCK_WORK_TARGET_OFFSET,
        },
    );
    let full_target_passed =
        bm1391_stock_full_target_passes(input.digest_words, input.target_words);
    if full_target_passed {
        steps.push(Bm1391StockSubmitWrapperStep::CloneWorkForAsyncSubmission);
        steps.push(Bm1391StockSubmitWrapperStep::InvokeAsyncSubmissionPath);
    } else {
        steps.push(Bm1391StockSubmitWrapperStep::FullTargetMissNoAsyncSubmission);
    }
    if input.bench_diagnostic_enabled {
        steps.push(Bm1391StockSubmitWrapperStep::EmitBenchDiagnostic);
    }

    Bm1391StockSubmitWrapperPlan {
        next_device_nonce: input.returned_nonce,
        steps,
        wrapper_returns_one: true,
        full_target_passed: Some(full_target_passed),
        async_submission_would_be_invoked: full_target_passed,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockAsyncSubmissionInput {
    /// Stock benchmark mode increments accepted counters without a network
    /// request or pool response.
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
pub enum Bm1391StockAsyncSubmissionStep {
    TimestampWorkFound,
    AccountBenchmarkAcceptedWithoutNetwork,
    EvaluateStaleWork,
    MarkWorkStale,
    AccountAndDiscardStale,
    SpawnNonStratumSubmitThread,
    FatalProcessOnThreadCreationFailure,
    PushToStratumQueue,
    FreeAfterMissingOrRejectedStratumQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockAsyncSubmissionOutcome {
    BenchmarkCountedAcceptedWithoutNetwork,
    DiscardedStale,
    NonStratumSubmitThreadStarted,
    FatalProcessOnThreadCreationFailure,
    StratumQueueAccepted,
    StratumQueueMissingOrRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1391StockAsyncSubmissionPlan {
    pub steps: Vec<Bm1391StockAsyncSubmissionStep>,
    pub outcome: Bm1391StockAsyncSubmissionOutcome,
}

impl Bm1391StockAsyncSubmissionPlan {
    pub const fn proves_network_delivery(&self) -> bool {
        false
    }

    pub const fn admits_pool_acceptance_authority(&self) -> bool {
        false
    }
}

/// Replay exact S15/T15 `FUN_00021b74` async-admission control flow.
///
/// Both held releases are instruction-semantics identical. Benchmark mode
/// counts the clone accepted locally without sending it. Outside benchmark,
/// stale work is discarded unless either the operator or pool requests stale
/// submission. Non-Stratum work asks `pthread_create` to run the submission
/// worker and terminates the process on creation failure. Stratum work is
/// queued only when the pool queue exists and accepts the push; otherwise the
/// clone is freed. No branch in this helper observes network delivery or a pool
/// response.
pub fn bm1391_stock_async_submission_plan(
    input: Bm1391StockAsyncSubmissionInput,
) -> Bm1391StockAsyncSubmissionPlan {
    let mut steps = vec![Bm1391StockAsyncSubmissionStep::TimestampWorkFound];
    if input.benchmark_mode {
        steps.push(Bm1391StockAsyncSubmissionStep::AccountBenchmarkAcceptedWithoutNetwork);
        return Bm1391StockAsyncSubmissionPlan {
            steps,
            outcome: Bm1391StockAsyncSubmissionOutcome::BenchmarkCountedAcceptedWithoutNetwork,
        };
    }

    steps.push(Bm1391StockAsyncSubmissionStep::EvaluateStaleWork);
    if input.stale {
        if !input.submit_stale_enabled && !input.pool_requests_stale {
            steps.push(Bm1391StockAsyncSubmissionStep::AccountAndDiscardStale);
            return Bm1391StockAsyncSubmissionPlan {
                steps,
                outcome: Bm1391StockAsyncSubmissionOutcome::DiscardedStale,
            };
        }
        steps.push(Bm1391StockAsyncSubmissionStep::MarkWorkStale);
    }

    if !input.stratum_work {
        steps.push(Bm1391StockAsyncSubmissionStep::SpawnNonStratumSubmitThread);
        if input.non_stratum_thread_create_succeeds {
            return Bm1391StockAsyncSubmissionPlan {
                steps,
                outcome: Bm1391StockAsyncSubmissionOutcome::NonStratumSubmitThreadStarted,
            };
        }
        steps.push(Bm1391StockAsyncSubmissionStep::FatalProcessOnThreadCreationFailure);
        return Bm1391StockAsyncSubmissionPlan {
            steps,
            outcome: Bm1391StockAsyncSubmissionOutcome::FatalProcessOnThreadCreationFailure,
        };
    }

    steps.push(Bm1391StockAsyncSubmissionStep::PushToStratumQueue);
    if input.stratum_queue_present && input.stratum_queue_push_succeeds {
        return Bm1391StockAsyncSubmissionPlan {
            steps,
            outcome: Bm1391StockAsyncSubmissionOutcome::StratumQueueAccepted,
        };
    }
    steps.push(Bm1391StockAsyncSubmissionStep::FreeAfterMissingOrRejectedStratumQueue);
    Bm1391StockAsyncSubmissionPlan {
        steps,
        outcome: Bm1391StockAsyncSubmissionOutcome::StratumQueueMissingOrRejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(job_id: u32, work_id: u16, nonce3: u32) -> Bm1391StockConsumerRecord {
        Bm1391StockConsumerRecord {
            job_id,
            work_id,
            version: 0x2000_0000,
            nonce2: 0x0102_0304_0506_0708,
            nonce3,
            chain_slot: 3,
        }
    }

    #[test]
    fn consumer_view_matches_the_exact_sixty_byte_layout() {
        let bound = Bm1391StockBoundNonce {
            job_id: 0x1122_3344,
            work_id: 0x1234,
            outstanding_word_04: 0x0000_0020,
            outstanding_word_08: 0x0506_0708,
            outstanding_word_0c: 0x0102_0304,
            nonce: 0xaabb_ccdd,
            chain_slot: 5,
            outstanding_tail_20_3f: [0x5a; 32],
        };
        assert_eq!(
            bound.stock_consumer_record(),
            Ok(Bm1391StockConsumerRecord {
                job_id: 0x1122_3344,
                work_id: 0x1234,
                version: 0x2000_0000,
                nonce2: 0x0102_0304_0506_0708,
                nonce3: 0xaabb_ccdd,
                chain_slot: 5,
            })
        );
    }

    #[test]
    fn clean_decoder_refuses_shapes_the_stock_producer_cannot_emit() {
        assert!(matches!(
            decode_bm1391_stock_consumer_record(&[0; 59]),
            Err(Bm1391StockConsumerRecordError::WrongLength { observed: 59 })
        ));
        let mut bytes = [0u8; 60];
        bytes[4..8].copy_from_slice(&0x8000u32.to_le_bytes());
        assert!(matches!(
            decode_bm1391_stock_consumer_record(&bytes),
            Err(Bm1391StockConsumerRecordError::WorkIdOutsideFifteenBits { .. })
        ));
        bytes[4..8].copy_from_slice(&0x7fffu32.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&0x10u32.to_le_bytes());
        assert!(matches!(
            decode_bm1391_stock_consumer_record(&bytes),
            Err(Bm1391StockConsumerRecordError::ChainOutsideLowNibble { .. })
        ));
    }

    #[test]
    fn pop_happens_before_drop_and_wraps_after_slot_510() {
        assert_eq!(
            pop_bm1391_stock_consumer_ring(Bm1391StockConsumerRingState {
                read_index: 510,
                queued: 1,
            }),
            Ok(Bm1391StockRingPop {
                popped_index: 510,
                next: Bm1391StockConsumerRingState {
                    read_index: 0,
                    queued: 0,
                },
            })
        );
        assert_eq!(
            pop_bm1391_stock_consumer_ring(Bm1391StockConsumerRingState {
                read_index: 0,
                queued: 0,
            }),
            Err(Bm1391StockConsumerRingError::Empty)
        );
        assert!(matches!(
            pop_bm1391_stock_consumer_ring(Bm1391StockConsumerRingState {
                read_index: 511,
                queued: 1,
            }),
            Err(Bm1391StockConsumerRingError::ReadIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn duplicate_key_is_nonce3_plus_work_id_and_chain_state_only_changes_accounting() {
        let previous = Bm1391StockDuplicateKey {
            nonce3: 0xdead_beef,
            work_id: 7,
        };
        let active = bm1391_stock_pre_hash_step(record(10, 7, 0xdead_beef), previous, 10, true);
        assert_eq!(active.next_duplicate_key, previous);
        assert_eq!(
            active.disposition,
            Bm1391StockPreHashDisposition::Duplicate {
                account_hardware_error: true,
            }
        );
        assert_eq!(
            bm1391_stock_pre_hash_step(record(10, 7, 0xdead_beef), previous, 10, false).disposition,
            Bm1391StockPreHashDisposition::Duplicate {
                account_hardware_error: false,
            }
        );
        assert_eq!(
            bm1391_stock_pre_hash_step(
                record(0, 0, 0),
                Bm1391StockDuplicateKey {
                    nonce3: 0,
                    work_id: 0,
                },
                0,
                true,
            )
            .disposition,
            Bm1391StockPreHashDisposition::Duplicate {
                account_hardware_error: true,
            },
            "stock's zero-initialized duplicate key also suppresses a first zero/zero return"
        );
    }

    #[test]
    fn exact_snapshot_window_accepts_wrapping_ages_zero_one_and_two() {
        let previous = Bm1391StockDuplicateKey {
            nonce3: 0,
            work_id: 0,
        };
        for (returned, age) in [
            (0u32, Bm1391StockSnapshotAge::Current),
            (u32::MAX, Bm1391StockSnapshotAge::PreviousOne),
            (u32::MAX - 1, Bm1391StockSnapshotAge::PreviousTwo),
        ] {
            assert_eq!(
                bm1391_stock_pre_hash_step(
                    record(returned, 1, returned.wrapping_add(3)),
                    previous,
                    0,
                    true,
                )
                .disposition,
                Bm1391StockPreHashDisposition::Snapshot(age)
            );
        }
        assert_eq!(
            Bm1391StockSnapshotAge::Current.stock_offset(),
            BM1391_STOCK_CURRENT_SNAPSHOT_OFFSET
        );
        assert_eq!(
            Bm1391StockSnapshotAge::PreviousOne.stock_offset(),
            BM1391_STOCK_PREVIOUS_ONE_SNAPSHOT_OFFSET
        );
        assert_eq!(
            Bm1391StockSnapshotAge::PreviousTwo.stock_offset(),
            BM1391_STOCK_PREVIOUS_TWO_SNAPSHOT_OFFSET
        );
    }

    #[test]
    fn stale_nonduplicate_commits_the_key_before_rejection() {
        let previous = Bm1391StockDuplicateKey {
            nonce3: 1,
            work_id: 1,
        };
        let step = bm1391_stock_pre_hash_step(record(7, 9, 0x1234), previous, 10, true);
        assert_eq!(
            step.next_duplicate_key,
            Bm1391StockDuplicateKey {
                nonce3: 0x1234,
                work_id: 9,
            }
        );
        assert_eq!(
            step.disposition,
            Bm1391StockPreHashDisposition::Stale {
                wrapping_age: 3,
                account_hardware_error: true,
            }
        );
    }

    #[test]
    fn exact_digest_threshold_is_strict_and_rounds_difficulty_by_bit_length() {
        let mut digest = [0u32; 8];
        digest[6] = 1u32.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 1),
            Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper
        );

        digest[6] = u32::MAX.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 1),
            Bm1391StockDigestDisposition::Drop
        );

        digest[6] = 0x3fff_ffffu32.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 2),
            bm1391_stock_digest_disposition(digest, 3),
            "difficulty 2 and 3 share floor(log2(diff)) == 1"
        );
    }

    #[test]
    fn selected_word_and_low_difficulty_accounting_boundaries_are_exact() {
        let mut digest = [0u32; 8];
        digest[6] = 0x007f_ffffu32.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 512),
            Bm1391StockDigestDisposition::IncrementLowDifficultyCounterBy256
        );
        digest[6] = 0x007f_fffeu32.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 512),
            Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper
        );
        digest[6] = BM1391_STOCK_LOW_DIFFICULTY_WORD_MAX.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 512),
            Bm1391StockDigestDisposition::IncrementLowDifficultyCounterBy256
        );
        digest[6] = (BM1391_STOCK_LOW_DIFFICULTY_WORD_MAX + 1).swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 512),
            Bm1391StockDigestDisposition::Drop
        );

        digest = [0; 8];
        digest[5] = 1u32.swap_bytes();
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 1u64 << 32),
            Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper
        );
        digest[7] = 1;
        assert_eq!(
            bm1391_stock_digest_disposition(digest, 1u64 << 32),
            Bm1391StockDigestDisposition::Drop
        );
        assert_eq!(
            bm1391_stock_digest_disposition([0; 8], 0),
            Bm1391StockDigestDisposition::Drop
        );
    }

    #[test]
    fn exact_f64_difficulty_normalizer_splits_at_two_to_the_32_and_fails_closed() {
        assert_eq!(
            f64::from_bits(BM1391_STOCK_TWO_NEGATIVE_32_F64_BITS),
            2f64.powi(-32)
        );
        assert_eq!(
            f64::from_bits(BM1391_STOCK_TWO_POSITIVE_32_F64_BITS),
            2f64.powi(32)
        );
        assert_eq!(bm1391_stock_normalize_share_difficulty(0.0), Ok(0));
        assert_eq!(bm1391_stock_normalize_share_difficulty(1.9), Ok(1));
        assert_eq!(bm1391_stock_normalize_share_difficulty(3.0), Ok(3));
        assert_eq!(
            bm1391_stock_normalize_share_difficulty(4_294_967_296.5),
            Ok(0x0000_0001_0000_0000)
        );
        assert!(matches!(
            bm1391_stock_normalize_share_difficulty(f64::NAN),
            Err(Bm1391StockDifficultyNormalizationError::NonFinite { .. })
        ));
        assert!(matches!(
            bm1391_stock_normalize_share_difficulty(-1.0),
            Err(Bm1391StockDifficultyNormalizationError::Negative { .. })
        ));
        assert!(matches!(
            bm1391_stock_normalize_share_difficulty(18_446_744_073_709_551_616.0),
            Err(Bm1391StockDifficultyNormalizationError::AboveU64Range { .. })
        ));
    }

    #[test]
    fn exact_precomputed_sha_context_preserves_snapshot_offsets_and_byte_order() {
        let input = Bm1391StockPrecomputedHashInput {
            midstate_words: [1, 2, 3, 4, 5, 6, 7, 8],
            tail_words: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc],
            nonce3: 0xddee_ff00,
        };
        assert_eq!(
            bm1391_stock_sha_context_words(input),
            [
                80,
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                0x4433_2211,
                0x8877_6655,
                0xccbb_aa99,
                0x00ff_eedd,
            ]
        );
        assert_eq!(BM1391_STOCK_SNAPSHOT_TAIL_OFFSET, 0x40);
        assert_eq!(BM1391_STOCK_SNAPSHOT_MIDSTATE_OFFSET, 0x80);
    }

    #[test]
    fn genesis_header_midstate_replays_stock_double_sha_and_digest_gate() {
        // Independently pinned from the 80-byte Bitcoin genesis header:
        // version/prevhash/merkle fill block zero; ntime/nbits/nonce fill the
        // 16-byte tail. The expected digest is standard double-SHA256 before
        // Bitcoin's display-order reversal.
        let input = Bm1391StockPrecomputedHashInput {
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
            nonce3: 0x1dac_2b7c,
        };
        let digest = bm1391_stock_double_sha256_from_midstate(input);
        assert_eq!(
            digest,
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
            bm1391_stock_digest_disposition(digest, 1),
            Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper
        );
    }

    #[test]
    fn observational_submit_result_never_mints_authority() {
        assert!(!Bm1391StockDigestDisposition::StockWouldInvokeSubmitWrapper
            .admits_share_submission_authority());
        assert_eq!(BM1391_STOCK_LOW_DIFFICULTY_COUNTER_INCREMENT, 0x100);
        assert_eq!(BM1391_STOCK_RETURN_RING_HEADER_LEN, 0x0c);
    }

    #[test]
    fn full_target_comparison_is_word_seven_first_and_accepts_equality() {
        let target = [0x1111_1111, 2, 3, 4, 5, 6, 7, 8];
        assert!(bm1391_stock_full_target_passes(target, target));

        let mut lower = target;
        lower[6] = 6;
        lower[0] = u32::MAX;
        assert!(bm1391_stock_full_target_passes(lower, target));

        let mut higher = target;
        higher[7] = 9;
        higher[0] = 0;
        assert!(!bm1391_stock_full_target_passes(higher, target));
    }

    #[test]
    fn submit_wrapper_return_one_does_not_mean_target_pass_or_pool_acceptance() {
        let plan = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
            previous_device_nonce: 1,
            returned_nonce: 2,
            digest_words: [u32::MAX, 0, 0, 0, 0, 0, 2, 0],
            target_words: [0, 0, 0, 0, 0, 0, 1, 0],
            bench_diagnostic_enabled: true,
        });
        assert!(plan.wrapper_returns_one);
        assert_eq!(plan.full_target_passed, Some(false));
        assert!(!plan.async_submission_would_be_invoked);
        assert_eq!(plan.next_device_nonce, 2);
        assert_eq!(
            plan.steps,
            vec![
                Bm1391StockSubmitWrapperStep::CheckDeviceNonceNotRepeated,
                Bm1391StockSubmitWrapperStep::CommitDeviceLastNonce { nonce: 2 },
                Bm1391StockSubmitWrapperStep::StoreNonceInWork {
                    offset: 0x4c,
                    nonce: 2,
                },
                Bm1391StockSubmitWrapperStep::RegenerateDoubleSha256 {
                    digest_offset: 0xc0,
                },
                Bm1391StockSubmitWrapperStep::UpdateWorkStatistics,
                Bm1391StockSubmitWrapperStep::CompareFullDigestWithWorkTarget {
                    target_offset: 0xa0,
                },
                Bm1391StockSubmitWrapperStep::FullTargetMissNoAsyncSubmission,
                Bm1391StockSubmitWrapperStep::EmitBenchDiagnostic,
            ]
        );
        assert!(!plan.admits_share_submission_authority());
        assert!(!plan.admits_pool_acceptance_authority());
    }

    #[test]
    fn repeat_nonce_and_nonzero_digest_word_seven_account_hardware_error() {
        let repeated = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
            previous_device_nonce: 7,
            returned_nonce: 7,
            digest_words: [0; 8],
            target_words: [u32::MAX; 8],
            bench_diagnostic_enabled: false,
        });
        assert_eq!(
            repeated.steps,
            vec![
                Bm1391StockSubmitWrapperStep::CheckDeviceNonceNotRepeated,
                Bm1391StockSubmitWrapperStep::AccountHardwareError,
            ]
        );
        assert!(!repeated.wrapper_returns_one);
        assert_eq!(repeated.full_target_passed, None);

        let high_word = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
            previous_device_nonce: 7,
            returned_nonce: 8,
            digest_words: [0, 0, 0, 0, 0, 0, 0, 1],
            target_words: [u32::MAX; 8],
            bench_diagnostic_enabled: false,
        });
        assert_eq!(high_word.next_device_nonce, 8);
        assert_eq!(
            high_word.steps.last(),
            Some(&Bm1391StockSubmitWrapperStep::AccountHardwareError)
        );
        assert!(!high_word.wrapper_returns_one);
        assert_eq!(BM1391_STOCK_WORK_DIGEST_LAST_WORD_OFFSET, 0xdc);
    }

    #[test]
    fn full_target_pass_invokes_async_path_but_does_not_prove_queueing() {
        let plan = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
            previous_device_nonce: 0,
            returned_nonce: 1,
            digest_words: [0; 8],
            target_words: [0; 8],
            bench_diagnostic_enabled: false,
        });
        assert!(plan.wrapper_returns_one);
        assert_eq!(plan.full_target_passed, Some(true));
        assert!(plan.async_submission_would_be_invoked);
        assert_eq!(
            plan.steps[plan.steps.len() - 2..],
            [
                Bm1391StockSubmitWrapperStep::CloneWorkForAsyncSubmission,
                Bm1391StockSubmitWrapperStep::InvokeAsyncSubmissionPath,
            ]
        );
        assert!(!plan.admits_share_submission_authority());
        assert!(!plan.admits_pool_acceptance_authority());
    }

    #[test]
    fn async_benchmark_counts_acceptance_without_network_or_authority() {
        let plan = bm1391_stock_async_submission_plan(Bm1391StockAsyncSubmissionInput {
            benchmark_mode: true,
            stale: true,
            submit_stale_enabled: false,
            pool_requests_stale: false,
            stratum_work: true,
            stratum_queue_present: false,
            stratum_queue_push_succeeds: false,
            non_stratum_thread_create_succeeds: false,
        });
        assert_eq!(
            plan.steps,
            vec![
                Bm1391StockAsyncSubmissionStep::TimestampWorkFound,
                Bm1391StockAsyncSubmissionStep::AccountBenchmarkAcceptedWithoutNetwork,
            ]
        );
        assert_eq!(
            plan.outcome,
            Bm1391StockAsyncSubmissionOutcome::BenchmarkCountedAcceptedWithoutNetwork
        );
        assert!(!plan.proves_network_delivery());
        assert!(!plan.admits_pool_acceptance_authority());
    }

    #[test]
    fn async_stale_policy_discards_only_when_neither_operator_nor_pool_allows() {
        for (operator_allows, pool_allows) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let plan = bm1391_stock_async_submission_plan(Bm1391StockAsyncSubmissionInput {
                benchmark_mode: false,
                stale: true,
                submit_stale_enabled: operator_allows,
                pool_requests_stale: pool_allows,
                stratum_work: true,
                stratum_queue_present: true,
                stratum_queue_push_succeeds: true,
                non_stratum_thread_create_succeeds: true,
            });
            if operator_allows || pool_allows {
                assert_eq!(
                    plan.outcome,
                    Bm1391StockAsyncSubmissionOutcome::StratumQueueAccepted
                );
                assert!(plan
                    .steps
                    .contains(&Bm1391StockAsyncSubmissionStep::MarkWorkStale));
            } else {
                assert_eq!(
                    plan.outcome,
                    Bm1391StockAsyncSubmissionOutcome::DiscardedStale
                );
                assert_eq!(
                    plan.steps.last(),
                    Some(&Bm1391StockAsyncSubmissionStep::AccountAndDiscardStale)
                );
            }
        }
    }

    #[test]
    fn async_transport_branches_pin_queue_drop_thread_and_fatal_outcomes() {
        let base = Bm1391StockAsyncSubmissionInput {
            benchmark_mode: false,
            stale: false,
            submit_stale_enabled: false,
            pool_requests_stale: false,
            stratum_work: true,
            stratum_queue_present: true,
            stratum_queue_push_succeeds: true,
            non_stratum_thread_create_succeeds: true,
        };
        assert_eq!(
            bm1391_stock_async_submission_plan(base).outcome,
            Bm1391StockAsyncSubmissionOutcome::StratumQueueAccepted
        );
        assert_eq!(
            bm1391_stock_async_submission_plan(Bm1391StockAsyncSubmissionInput {
                stratum_queue_present: false,
                ..base
            })
            .outcome,
            Bm1391StockAsyncSubmissionOutcome::StratumQueueMissingOrRejected
        );
        assert_eq!(
            bm1391_stock_async_submission_plan(Bm1391StockAsyncSubmissionInput {
                stratum_work: false,
                ..base
            })
            .outcome,
            Bm1391StockAsyncSubmissionOutcome::NonStratumSubmitThreadStarted
        );
        let fatal = bm1391_stock_async_submission_plan(Bm1391StockAsyncSubmissionInput {
            stratum_work: false,
            non_stratum_thread_create_succeeds: false,
            ..base
        });
        assert_eq!(
            fatal.outcome,
            Bm1391StockAsyncSubmissionOutcome::FatalProcessOnThreadCreationFailure
        );
        assert_eq!(
            fatal.steps.last(),
            Some(&Bm1391StockAsyncSubmissionStep::FatalProcessOnThreadCreationFailure)
        );
    }
}
