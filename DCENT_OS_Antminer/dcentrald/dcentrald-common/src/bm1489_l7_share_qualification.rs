//! Pure post-queue share-qualification replay for exact L7 VNish BM1489 code.
//!
//! This module starts after [`crate::bm1489_l7_return`] has popped and bound a
//! serial nonce record. It models the recovered three-snapshot selection,
//! work reconstruction inputs, duplicate/stale gates, stock coarse digest
//! gate, recovered Scrypt-1024/1/1/256 work hash, and full target comparison.
//! Header, target, pool, and retained-job inputs remain caller-forgeable. No
//! function here proves a live transport, queues a share, observes a pool
//! response, or grants mining authority.

use crate::bm1489_l7_return::Bm1489L7BoundNonce;

pub const BM1489_L7_RETAINED_JOB_SLOTS: usize = 3;
pub const BM1489_L7_HEADER_BYTES: usize = 80;
pub const BM1489_L7_HEADER_WORDS: usize = BM1489_L7_HEADER_BYTES / 4;
pub const BM1489_L7_DIGEST_WORDS: usize = 8;
pub const BM1489_L7_STOCK_COARSE_DIGEST_WORD: usize = 7;
pub const BM1489_L7_STOCK_COARSE_DIGEST_HIGH_MASK: u32 = 0xffff_0000;
pub const BM1489_L7_SCRYPT_N: usize = 1024;
pub const BM1489_L7_SCRYPT_R: usize = 1;
pub const BM1489_L7_SCRYPT_P: usize = 1;
pub const BM1489_L7_SCRYPT_OUTPUT_BYTES: usize = 32;

pub const BM1489_L7_POSTQUEUE_CONSUMER_RECOVERED: bool = true;
pub const BM1489_L7_STOCK_HASH_FUNCTION_REIMPLEMENTED: bool = true;
pub const BM1489_L7_SCRYPT_PARAMETERS_RECOVERED: bool = true;
pub const BM1489_L7_HEADER_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1489_L7_DIGEST_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1489_L7_TARGET_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1489_L7_POOL_RESPONSE_BOUND_TO_REQUEST: bool = false;
pub const BM1489_L7_ACCEPTED_SHARE_ORACLE_RECOVERED: bool = false;
pub const BM1489_L7_QUALIFICATION_AUTHORIZES_LIVE_IO: bool = false;
pub const BM1489_L7_QUALIFICATION_AUTHORIZES_SHARE_SUBMISSION: bool = false;

/// Exact scalar inputs passed by `FUN_0006fecc` to work reconstruction
/// `FUN_0002d380` after selecting one of the three retained job snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7ShareReconstructionInputs {
    pub job_id: u32,
    pub nonce: u32,
    /// Low and high native words of the exact 64-bit work nonce-two value.
    pub nonce2_low: u32,
    pub nonce2_high: u32,
    /// The stock caller byte-swaps snapshot word `+0x04` before passing it.
    /// Its narrower ntime/version meaning is not asserted here.
    pub swapped_work_scalar: u32,
}

pub const fn bm1489_l7_share_reconstruction_inputs(
    record: Bm1489L7BoundNonce,
) -> Bm1489L7ShareReconstructionInputs {
    Bm1489L7ShareReconstructionInputs {
        job_id: record.snapshot_word_10,
        nonce: record.nonce,
        nonce2_low: record.snapshot_word_08,
        nonce2_high: record.snapshot_word_0c,
        swapped_work_scalar: record.snapshot_word_04.swap_bytes(),
    }
}

/// Caller-supplied replay view of one stock-retained job slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7RetainedJob {
    pub job_id: u32,
    /// Snapshot `+0x1c` was non-null.
    pub associated_work_present: bool,
    /// `FUN_0003205c` accepted the associated work in the global pool list.
    pub associated_work_registered: bool,
    /// Associated work field `+0x1f4` was nonzero.
    pub associated_work_active: bool,
    /// Associated work field `+0x3d4` enabled the submit-wrapper path.
    pub submission_enabled: bool,
    /// Native u32 target limbs at reconstructed work `+0x100..+0x11c`.
    pub target_words: [u32; BM1489_L7_DIGEST_WORDS],
}

impl Bm1489L7RetainedJob {
    const fn associated_work_is_usable(self) -> bool {
        self.associated_work_present
            && self.associated_work_registered
            && self.associated_work_active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7QualificationInput {
    pub record: Bm1489L7BoundNonce,
    /// Exact stock priority is slot zero, then one, then two.
    pub retained_jobs: [Bm1489L7RetainedJob; BM1489_L7_RETAINED_JOB_SLOTS],
    /// Stack-local selected slot retained from the preceding record in the
    /// same `FUN_0006fecc` queue-drain invocation. Stock initializes it to
    /// none only once before the loop and fails to clear it on an ID miss.
    pub prior_selected_slot_in_drain: Option<usize>,
    /// Consumer thread field `+0x52`; nonzero bypasses qualification.
    pub diagnostic_only: bool,
    /// Last nonce retained in the selected chain/derived-unit accounting slot.
    pub previous_unit_nonce: u32,
    /// Unsigned minimum job ID at context `+0x19c`.
    pub minimum_job_id: u32,
    /// Last nonce at device context `+0xe8` used by `FUN_00030150`.
    pub previous_global_nonce: u32,
    /// Exact caller-visible residue of stock RNG modulo eight. Stock accounts
    /// a hardware error on rejected results only when this equals four.
    pub random_mod_8: u8,
    /// Eight native u32 digest limbs after stock's work-hash function and its
    /// per-word byte swap. The base replay accepts these caller-supplied; use
    /// [`bm1489_l7_qualification_plan_from_scrypt_header`] to derive them.
    pub digest_words: [u32; BM1489_L7_DIGEST_WORDS],
    /// Whether stock's dynamic pool-selection/search path reaches
    /// `FUN_0002f6f8` after the coarse digest gate.
    pub downstream_pool_path_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7QualificationError {
    InvalidRandomModulo8 { observed: u8 },
    InvalidPriorSelectedSlot { observed: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7QualificationDisposition {
    DiagnosticOnly,
    JobNotRetained,
    AssociatedWorkUnavailable,
    PerUnitDuplicate,
    BelowMinimumJobId,
    SubmissionDisabled,
    GlobalDuplicate,
    CoarseDigestMiss,
    DownstreamPoolPathUnavailable,
    FullTargetMiss,
    WouldEnterPostTargetSubmissionPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7QualificationStep {
    PopNonceQueueRecord,
    SelectRetainedJob,
    ReusePriorSelectedJobAfterIdMiss,
    ValidateAssociatedWork,
    ReconstructWork,
    CheckDiagnosticOnly,
    CheckPerUnitDuplicate,
    CheckMinimumJobId,
    CheckSubmissionEnabled,
    CheckGlobalDuplicate,
    CommitGlobalLastNonce { nonce: u32 },
    RunStockWorkHash,
    CheckCoarseDigestHigh16,
    SelectDownstreamPoolPath,
    CompareFullDigestWithTarget,
    EnterPostTargetSubmissionPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1489L7QualificationPlan {
    pub selected_slot: Option<usize>,
    /// Exact stack-local selection carried to the next record in this drain.
    pub next_selected_slot_in_drain: Option<usize>,
    /// Stock can reconstruct against this stale slot when a later record's
    /// job ID misses all three retained IDs.
    pub reused_prior_slot_after_job_id_miss: bool,
    pub reconstruction: Option<Bm1489L7ShareReconstructionInputs>,
    pub steps: Vec<Bm1489L7QualificationStep>,
    pub disposition: Bm1489L7QualificationDisposition,
    /// Stock commits a new global nonce before hashing and retains it even
    /// when the coarse digest or later target test fails.
    pub next_global_nonce: u32,
    /// Exact `FUN_00030150` return. A value of one means it reached
    /// `FUN_0002f6f8`; it does not mean the full target passed.
    pub stock_outer_wrapper_returns_one: bool,
    pub full_target_passed: Option<bool>,
    pub account_hardware_error: bool,
    pub account_hardware_success: bool,
    pub post_target_submission_path_would_be_entered: bool,
}

impl Bm1489L7QualificationPlan {
    pub const fn admits_live_io_authority(&self) -> bool {
        false
    }

    pub const fn admits_share_submission_authority(&self) -> bool {
        false
    }

    pub const fn admits_pool_acceptance_authority(&self) -> bool {
        false
    }
}

fn early_plan(
    selected_slot: Option<usize>,
    reconstruction: Option<Bm1489L7ShareReconstructionInputs>,
    steps: Vec<Bm1489L7QualificationStep>,
    disposition: Bm1489L7QualificationDisposition,
    previous_global_nonce: u32,
    account_hardware_error: bool,
) -> Bm1489L7QualificationPlan {
    Bm1489L7QualificationPlan {
        selected_slot,
        next_selected_slot_in_drain: selected_slot,
        reused_prior_slot_after_job_id_miss: false,
        reconstruction,
        steps,
        disposition,
        next_global_nonce: previous_global_nonce,
        stock_outer_wrapper_returns_one: false,
        full_target_passed: None,
        account_hardware_error,
        account_hardware_success: false,
        post_target_submission_path_would_be_entered: false,
    }
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

pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len().saturating_add(72));
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = SHA256_INITIAL_STATE;
    for chunk in padded.chunks_exact(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        sha256_compress(&mut state, &block);
    }

    let mut digest = [0u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        key_block[..32].copy_from_slice(&sha256(key));
    } else {
        for (slot, byte) in key_block.iter_mut().zip(key) {
            *slot = *byte;
        }
    }

    let mut inner = Vec::with_capacity(64usize.saturating_add(message.len()));
    inner.extend(key_block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner_digest = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + inner_digest.len());
    outer.extend(key_block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

/// PBKDF2-HMAC-SHA256 with the one iteration used by Scrypt.
fn pbkdf2_hmac_sha256_once(password: &[u8], salt: &[u8], output_len: usize) -> Vec<u8> {
    let block_count = output_len.div_ceil(32);
    let mut output = Vec::with_capacity(block_count.saturating_mul(32));
    for block_index in 1..=block_count {
        let mut message = Vec::with_capacity(salt.len().saturating_add(4));
        message.extend_from_slice(salt);
        message.extend_from_slice(&(block_index as u32).to_be_bytes());
        output.extend_from_slice(&hmac_sha256(password, &message));
    }
    output.truncate(output_len);
    output
}

#[allow(clippy::indexing_slicing)]
fn salsa20_8(block: [u8; 64]) -> [u8; 64] {
    let mut input = [0u32; 16];
    for (word, bytes) in input.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let mut x = input;
    for _ in 0..4 {
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);
        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);
        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);
        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);
        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }

    let mut output = [0u8; 64];
    for (chunk, (word, original)) in output.chunks_exact_mut(4).zip(x.into_iter().zip(input)) {
        chunk.copy_from_slice(&word.wrapping_add(original).to_le_bytes());
    }
    output
}

fn blockmix_salsa20_8_r1(block: [u8; 128]) -> [u8; 128] {
    let mut x = [0u8; 64];
    for (slot, source) in x.iter_mut().zip(block.iter().skip(64)) {
        *slot = *source;
    }
    let mut output = [0u8; 128];
    for (source_chunk, output_chunk) in block.chunks_exact(64).zip(output.chunks_exact_mut(64)) {
        for (slot, source) in x.iter_mut().zip(source_chunk) {
            *slot ^= *source;
        }
        x = salsa20_8(x);
        output_chunk.copy_from_slice(&x);
    }
    output
}

#[allow(clippy::indexing_slicing)]
fn romix_1024_r1(mut block: [u8; 128]) -> [u8; 128] {
    let mut scratch = vec![[0u8; 128]; BM1489_L7_SCRYPT_N];
    for slot in &mut scratch {
        *slot = block;
        block = blockmix_salsa20_8_r1(block);
    }
    for _ in 0..BM1489_L7_SCRYPT_N {
        let selected = (u32::from_le_bytes([block[64], block[65], block[66], block[67]])
            & (BM1489_L7_SCRYPT_N as u32 - 1)) as usize;
        for (byte, selected_byte) in block.iter_mut().zip(scratch[selected]) {
            *byte ^= selected_byte;
        }
        block = blockmix_salsa20_8_r1(block);
    }
    block
}

/// Compute the exact Scrypt work hash recovered from `FUN_000b3fec` and
/// `FUN_000b432c`: PBKDF2-HMAC-SHA256 with one iteration, ROMix
/// N=1024/r=1/p=1 using Salsa20/8, and a 32-byte final PBKDF2 output.
///
/// `header` is the exact 80-byte buffer passed to `FUN_000b432c`, after
/// `FUN_000b3fec` has byte-swapped each native work-header word. This helper
/// is pure and does not authenticate where those bytes came from.
pub fn bm1489_l7_scrypt_1024_1_1_256(
    header: [u8; BM1489_L7_HEADER_BYTES],
) -> [u8; BM1489_L7_SCRYPT_OUTPUT_BYTES] {
    let initial = pbkdf2_hmac_sha256_once(&header, &header, 128);
    let mut mixed = [0u8; 128];
    mixed.copy_from_slice(&initial);
    mixed = romix_1024_r1(mixed);
    let final_bytes = pbkdf2_hmac_sha256_once(&header, &mixed, BM1489_L7_SCRYPT_OUTPUT_BYTES);
    let mut digest = [0u8; BM1489_L7_SCRYPT_OUTPUT_BYTES];
    digest.copy_from_slice(&final_bytes);
    digest
}

/// Compute the eight native digest words after stock's final per-word byte
/// swap. The returned layout is consumed by the recovered coarse and full
/// target comparisons.
pub fn bm1489_l7_stock_digest_words_from_scrypt_header(
    header: [u8; BM1489_L7_HEADER_BYTES],
) -> [u32; BM1489_L7_DIGEST_WORDS] {
    let digest = bm1489_l7_scrypt_1024_1_1_256(header);
    let mut words = [0u32; BM1489_L7_DIGEST_WORDS];
    for (word, bytes) in words.iter_mut().zip(digest.chunks_exact(4)) {
        let mut native = [0u8; 4];
        native.copy_from_slice(bytes);
        *word = u32::from_be_bytes(native);
    }
    words
}

/// Mirror `FUN_000b3fec`'s input transform from 20 native work-header words
/// to the 80 Scrypt bytes, then return its final byte-swapped digest words.
pub fn bm1489_l7_stock_digest_words_from_work_header(
    work_header_words: [u32; BM1489_L7_HEADER_WORDS],
) -> [u32; BM1489_L7_DIGEST_WORDS] {
    let mut header = [0u8; BM1489_L7_HEADER_BYTES];
    for (chunk, word) in header.chunks_exact_mut(4).zip(work_header_words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    bm1489_l7_stock_digest_words_from_scrypt_header(header)
}

/// Replay qualification while deriving the digest from an exact post-swap
/// 80-byte Scrypt header. The caller-provided `digest_words` field is ignored.
pub fn bm1489_l7_qualification_plan_from_scrypt_header(
    mut input: Bm1489L7QualificationInput,
    header: [u8; BM1489_L7_HEADER_BYTES],
) -> Result<Bm1489L7QualificationPlan, Bm1489L7QualificationError> {
    input.digest_words = bm1489_l7_stock_digest_words_from_scrypt_header(header);
    bm1489_l7_qualification_plan(input)
}

/// Compare the exact native digest and target limbs used by `FUN_00011a5c`.
/// Word seven is most significant and equality passes.
pub fn bm1489_l7_full_target_passes(
    digest_words: [u32; BM1489_L7_DIGEST_WORDS],
    target_words: [u32; BM1489_L7_DIGEST_WORDS],
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

/// Replay the deterministic qualification spine recovered from exact held
/// VNish functions `FUN_0006fecc`, `FUN_00030150`, and `FUN_0002f6f8`.
///
/// The record is already popped before every later drop. Slot zero wins if
/// duplicate retained job IDs exist. A new global nonce is committed before
/// hashing. Once the outer wrapper reaches `FUN_0002f6f8`, it returns one and
/// the consumer accounts hardware success even if the full target later
/// misses. A full-target pass only enters further stock submission logic; no
/// response or pool acceptance is observed here.
pub fn bm1489_l7_qualification_plan(
    input: Bm1489L7QualificationInput,
) -> Result<Bm1489L7QualificationPlan, Bm1489L7QualificationError> {
    if input.random_mod_8 > 7 {
        return Err(Bm1489L7QualificationError::InvalidRandomModulo8 {
            observed: input.random_mod_8,
        });
    }
    if let Some(observed) = input.prior_selected_slot_in_drain {
        if observed >= BM1489_L7_RETAINED_JOB_SLOTS {
            return Err(Bm1489L7QualificationError::InvalidPriorSelectedSlot { observed });
        }
    }

    let reconstruction = bm1489_l7_share_reconstruction_inputs(input.record);
    let mut steps = vec![
        Bm1489L7QualificationStep::PopNonceQueueRecord,
        Bm1489L7QualificationStep::SelectRetainedJob,
    ];
    let matched_slot = input
        .retained_jobs
        .iter()
        .position(|job| job.job_id == reconstruction.job_id);
    let (selected_slot, reused_prior_slot_after_job_id_miss) = match matched_slot {
        Some(selected_slot) => (selected_slot, false),
        None => match input.prior_selected_slot_in_drain {
            Some(selected_slot) => {
                steps.push(Bm1489L7QualificationStep::ReusePriorSelectedJobAfterIdMiss);
                (selected_slot, true)
            }
            None => {
                return Ok(early_plan(
                    None,
                    None,
                    steps,
                    Bm1489L7QualificationDisposition::JobNotRetained,
                    input.previous_global_nonce,
                    false,
                ));
            }
        },
    };
    let Some(&selected) = input.retained_jobs.get(selected_slot) else {
        return Err(Bm1489L7QualificationError::InvalidPriorSelectedSlot {
            observed: selected_slot,
        });
    };
    steps.push(Bm1489L7QualificationStep::ValidateAssociatedWork);
    if !selected.associated_work_is_usable() {
        let mut plan = early_plan(
            Some(selected_slot),
            None,
            steps,
            Bm1489L7QualificationDisposition::AssociatedWorkUnavailable,
            input.previous_global_nonce,
            false,
        );
        plan.reused_prior_slot_after_job_id_miss = reused_prior_slot_after_job_id_miss;
        return Ok(plan);
    }

    steps.push(Bm1489L7QualificationStep::ReconstructWork);
    steps.push(Bm1489L7QualificationStep::CheckDiagnosticOnly);
    if input.diagnostic_only {
        let mut plan = early_plan(
            Some(selected_slot),
            Some(reconstruction),
            steps,
            Bm1489L7QualificationDisposition::DiagnosticOnly,
            input.previous_global_nonce,
            false,
        );
        plan.reused_prior_slot_after_job_id_miss = reused_prior_slot_after_job_id_miss;
        return Ok(plan);
    }

    steps.push(Bm1489L7QualificationStep::CheckPerUnitDuplicate);
    if input.previous_unit_nonce == input.record.nonce {
        let mut plan = early_plan(
            Some(selected_slot),
            Some(reconstruction),
            steps,
            Bm1489L7QualificationDisposition::PerUnitDuplicate,
            input.previous_global_nonce,
            input.random_mod_8 == 4,
        );
        plan.reused_prior_slot_after_job_id_miss = reused_prior_slot_after_job_id_miss;
        return Ok(plan);
    }

    steps.push(Bm1489L7QualificationStep::CheckMinimumJobId);
    if input.record.snapshot_word_10 < input.minimum_job_id {
        let mut plan = early_plan(
            Some(selected_slot),
            Some(reconstruction),
            steps,
            Bm1489L7QualificationDisposition::BelowMinimumJobId,
            input.previous_global_nonce,
            false,
        );
        plan.reused_prior_slot_after_job_id_miss = reused_prior_slot_after_job_id_miss;
        return Ok(plan);
    }

    steps.push(Bm1489L7QualificationStep::CheckSubmissionEnabled);
    if !selected.submission_enabled {
        let mut plan = early_plan(
            Some(selected_slot),
            Some(reconstruction),
            steps,
            Bm1489L7QualificationDisposition::SubmissionDisabled,
            input.previous_global_nonce,
            false,
        );
        plan.reused_prior_slot_after_job_id_miss = reused_prior_slot_after_job_id_miss;
        return Ok(plan);
    }

    steps.push(Bm1489L7QualificationStep::CheckGlobalDuplicate);
    if input.previous_global_nonce == input.record.nonce {
        let mut plan = early_plan(
            Some(selected_slot),
            Some(reconstruction),
            steps,
            Bm1489L7QualificationDisposition::GlobalDuplicate,
            input.previous_global_nonce,
            input.random_mod_8 == 4,
        );
        plan.reused_prior_slot_after_job_id_miss = reused_prior_slot_after_job_id_miss;
        return Ok(plan);
    }

    steps.push(Bm1489L7QualificationStep::CommitGlobalLastNonce {
        nonce: input.record.nonce,
    });
    steps.push(Bm1489L7QualificationStep::RunStockWorkHash);
    steps.push(Bm1489L7QualificationStep::CheckCoarseDigestHigh16);
    if input.digest_words[BM1489_L7_STOCK_COARSE_DIGEST_WORD]
        & BM1489_L7_STOCK_COARSE_DIGEST_HIGH_MASK
        != 0
    {
        return Ok(Bm1489L7QualificationPlan {
            selected_slot: Some(selected_slot),
            next_selected_slot_in_drain: Some(selected_slot),
            reused_prior_slot_after_job_id_miss,
            reconstruction: Some(reconstruction),
            steps,
            disposition: Bm1489L7QualificationDisposition::CoarseDigestMiss,
            next_global_nonce: input.record.nonce,
            stock_outer_wrapper_returns_one: false,
            full_target_passed: None,
            account_hardware_error: input.random_mod_8 == 4,
            account_hardware_success: false,
            post_target_submission_path_would_be_entered: false,
        });
    }

    steps.push(Bm1489L7QualificationStep::SelectDownstreamPoolPath);
    if !input.downstream_pool_path_available {
        return Ok(Bm1489L7QualificationPlan {
            selected_slot: Some(selected_slot),
            next_selected_slot_in_drain: Some(selected_slot),
            reused_prior_slot_after_job_id_miss,
            reconstruction: Some(reconstruction),
            steps,
            disposition: Bm1489L7QualificationDisposition::DownstreamPoolPathUnavailable,
            next_global_nonce: input.record.nonce,
            stock_outer_wrapper_returns_one: false,
            full_target_passed: None,
            account_hardware_error: input.random_mod_8 == 4,
            account_hardware_success: false,
            post_target_submission_path_would_be_entered: false,
        });
    }

    steps.push(Bm1489L7QualificationStep::CompareFullDigestWithTarget);
    let full_target_passed =
        bm1489_l7_full_target_passes(input.digest_words, selected.target_words);
    let disposition = if full_target_passed {
        steps.push(Bm1489L7QualificationStep::EnterPostTargetSubmissionPath);
        Bm1489L7QualificationDisposition::WouldEnterPostTargetSubmissionPath
    } else {
        Bm1489L7QualificationDisposition::FullTargetMiss
    };
    Ok(Bm1489L7QualificationPlan {
        selected_slot: Some(selected_slot),
        next_selected_slot_in_drain: Some(selected_slot),
        reused_prior_slot_after_job_id_miss,
        reconstruction: Some(reconstruction),
        steps,
        disposition,
        next_global_nonce: input.record.nonce,
        stock_outer_wrapper_returns_one: true,
        full_target_passed: Some(full_target_passed),
        account_hardware_error: false,
        account_hardware_success: true,
        post_target_submission_path_would_be_entered: full_target_passed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(job_id: u32, nonce: u32) -> Bm1489L7BoundNonce {
        Bm1489L7BoundNonce {
            chain: 2,
            derived_quotient: 3,
            derived_nonce_group: 4,
            snapshot_word_10: job_id,
            raw_work_selector: 5,
            snapshot_word_04: 0x1122_3344,
            snapshot_word_08: 0x5566_7788,
            snapshot_word_0c: 0x99aa_bbcc,
            nonce,
        }
    }

    fn retained(job_id: u32, target_words: [u32; 8]) -> Bm1489L7RetainedJob {
        Bm1489L7RetainedJob {
            job_id,
            associated_work_present: true,
            associated_work_registered: true,
            associated_work_active: true,
            submission_enabled: true,
            target_words,
        }
    }

    fn input() -> Bm1489L7QualificationInput {
        Bm1489L7QualificationInput {
            record: record(42, 0x1234_5678),
            retained_jobs: [
                retained(41, [0; 8]),
                retained(42, [u32::MAX; 8]),
                retained(40, [0; 8]),
            ],
            prior_selected_slot_in_drain: None,
            diagnostic_only: false,
            previous_unit_nonce: 0,
            minimum_job_id: 42,
            previous_global_nonce: 0,
            random_mod_8: 0,
            digest_words: [0; 8],
            downstream_pool_path_available: true,
        }
    }

    #[test]
    fn exact_reconstruction_inputs_and_no_authority_are_pinned() {
        let rebuilt = bm1489_l7_share_reconstruction_inputs(record(42, 0x1234_5678));
        assert_eq!(
            rebuilt,
            Bm1489L7ShareReconstructionInputs {
                job_id: 42,
                nonce: 0x1234_5678,
                nonce2_low: 0x5566_7788,
                nonce2_high: 0x99aa_bbcc,
                swapped_work_scalar: 0x4433_2211,
            }
        );
        assert!(BM1489_L7_POSTQUEUE_CONSUMER_RECOVERED);
        assert!(BM1489_L7_STOCK_HASH_FUNCTION_REIMPLEMENTED);
        assert!(BM1489_L7_SCRYPT_PARAMETERS_RECOVERED);
        assert_eq!(BM1489_L7_SCRYPT_N, 1024);
        assert_eq!(BM1489_L7_SCRYPT_R, 1);
        assert_eq!(BM1489_L7_SCRYPT_P, 1);
        assert!(!BM1489_L7_HEADER_PROVENANCE_AUTHENTICATED);
        assert!(!BM1489_L7_DIGEST_PROVENANCE_AUTHENTICATED);
        assert!(!BM1489_L7_TARGET_PROVENANCE_AUTHENTICATED);
        assert!(!BM1489_L7_POOL_RESPONSE_BOUND_TO_REQUEST);
        assert!(!BM1489_L7_ACCEPTED_SHARE_ORACLE_RECOVERED);
    }

    #[test]
    fn retained_job_selection_is_first_match_and_missing_records_are_popped() {
        let mut duplicate = input();
        duplicate.retained_jobs[0] = retained(42, [u32::MAX; 8]);
        assert_eq!(
            bm1489_l7_qualification_plan(duplicate)
                .unwrap()
                .selected_slot,
            Some(0)
        );

        let mut missing = input();
        missing.record.snapshot_word_10 = 99;
        let plan = bm1489_l7_qualification_plan(missing).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::JobNotRetained
        );
        assert_eq!(
            plan.steps,
            vec![
                Bm1489L7QualificationStep::PopNonceQueueRecord,
                Bm1489L7QualificationStep::SelectRetainedJob,
            ]
        );

        missing.prior_selected_slot_in_drain = Some(2);
        let plan = bm1489_l7_qualification_plan(missing).unwrap();
        assert_eq!(plan.selected_slot, Some(2));
        assert_eq!(plan.next_selected_slot_in_drain, Some(2));
        assert!(plan.reused_prior_slot_after_job_id_miss);
        assert!(plan
            .steps
            .contains(&Bm1489L7QualificationStep::ReusePriorSelectedJobAfterIdMiss));
    }

    #[test]
    fn unusable_associated_work_and_diagnostic_mode_stop_after_reconstruction_boundary() {
        let mut unusable = input();
        unusable.retained_jobs[1].associated_work_registered = false;
        let plan = bm1489_l7_qualification_plan(unusable).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::AssociatedWorkUnavailable
        );
        assert!(plan.reconstruction.is_none());

        let mut diagnostic = input();
        diagnostic.diagnostic_only = true;
        let plan = bm1489_l7_qualification_plan(diagnostic).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::DiagnosticOnly
        );
        assert!(plan.reconstruction.is_some());
    }

    #[test]
    fn per_unit_duplicate_and_wrapper_failures_account_only_on_rng_residue_four() {
        let mut duplicate = input();
        duplicate.previous_unit_nonce = duplicate.record.nonce;
        duplicate.random_mod_8 = 4;
        let plan = bm1489_l7_qualification_plan(duplicate).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::PerUnitDuplicate
        );
        assert!(plan.account_hardware_error);

        let mut invalid_rng = input();
        invalid_rng.random_mod_8 = 8;
        assert_eq!(
            bm1489_l7_qualification_plan(invalid_rng),
            Err(Bm1489L7QualificationError::InvalidRandomModulo8 { observed: 8 })
        );

        let mut invalid_prior = input();
        invalid_prior.prior_selected_slot_in_drain = Some(3);
        assert_eq!(
            bm1489_l7_qualification_plan(invalid_prior),
            Err(Bm1489L7QualificationError::InvalidPriorSelectedSlot { observed: 3 })
        );
    }

    #[test]
    fn minimum_job_submission_and_global_duplicate_gates_preserve_global_nonce() {
        let mut stale = input();
        stale.minimum_job_id = 43;
        assert_eq!(
            bm1489_l7_qualification_plan(stale).unwrap().disposition,
            Bm1489L7QualificationDisposition::BelowMinimumJobId
        );

        let mut disabled = input();
        disabled.retained_jobs[1].submission_enabled = false;
        assert_eq!(
            bm1489_l7_qualification_plan(disabled).unwrap().disposition,
            Bm1489L7QualificationDisposition::SubmissionDisabled
        );

        let mut duplicate = input();
        duplicate.previous_global_nonce = duplicate.record.nonce;
        let plan = bm1489_l7_qualification_plan(duplicate).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::GlobalDuplicate
        );
        assert_eq!(plan.next_global_nonce, duplicate.record.nonce);
    }

    #[test]
    fn new_global_nonce_is_committed_before_coarse_digest_failure() {
        let mut coarse = input();
        coarse.digest_words[7] = 0x0001_0000;
        coarse.random_mod_8 = 4;
        let plan = bm1489_l7_qualification_plan(coarse).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::CoarseDigestMiss
        );
        assert_eq!(plan.next_global_nonce, coarse.record.nonce);
        assert!(!plan.stock_outer_wrapper_returns_one);
        assert!(plan.account_hardware_error);

        coarse.digest_words[7] = 0x0000_ffff;
        coarse.random_mod_8 = 0;
        assert_ne!(
            bm1489_l7_qualification_plan(coarse).unwrap().disposition,
            Bm1489L7QualificationDisposition::CoarseDigestMiss
        );
    }

    #[test]
    fn unavailable_downstream_path_is_not_a_target_result() {
        let mut unavailable = input();
        unavailable.downstream_pool_path_available = false;
        let plan = bm1489_l7_qualification_plan(unavailable).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::DownstreamPoolPathUnavailable
        );
        assert_eq!(plan.full_target_passed, None);
        assert!(!plan.stock_outer_wrapper_returns_one);
    }

    #[test]
    fn full_target_compare_is_word_seven_first_and_accepts_equality() {
        let target = [1, 2, 3, 4, 5, 6, 7, 0xffff];
        assert!(bm1489_l7_full_target_passes(target, target));
        let mut lower = target;
        lower[6] -= 1;
        assert!(bm1489_l7_full_target_passes(lower, target));
        let mut higher = target;
        higher[6] += 1;
        assert!(!bm1489_l7_full_target_passes(higher, target));
        higher = target;
        higher[7] += 1;
        assert!(!bm1489_l7_full_target_passes(higher, target));
    }

    #[test]
    fn full_target_miss_still_returns_outer_success_and_counts_hardware_success() {
        let mut miss = input();
        miss.retained_jobs[1].target_words = [0; 8];
        miss.digest_words[0] = 1;
        let plan = bm1489_l7_qualification_plan(miss).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::FullTargetMiss
        );
        assert_eq!(plan.full_target_passed, Some(false));
        assert!(plan.stock_outer_wrapper_returns_one);
        assert!(plan.account_hardware_success);
        assert!(!plan.post_target_submission_path_would_be_entered);
    }

    #[test]
    fn full_target_pass_enters_later_path_without_minting_acceptance() {
        let plan = bm1489_l7_qualification_plan(input()).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::WouldEnterPostTargetSubmissionPath
        );
        assert_eq!(plan.full_target_passed, Some(true));
        assert!(plan.stock_outer_wrapper_returns_one);
        assert!(plan.account_hardware_success);
        assert!(plan.post_target_submission_path_would_be_entered);
        assert!(!plan.admits_live_io_authority());
        assert!(!plan.admits_share_submission_authority());
        assert!(!plan.admits_pool_acceptance_authority());
    }

    #[test]
    fn scrypt_1024_1_1_256_matches_independent_zero_and_incrementing_headers() {
        assert_eq!(
            bm1489_l7_scrypt_1024_1_1_256([0; BM1489_L7_HEADER_BYTES]),
            [
                0x16, 0x1d, 0x08, 0x76, 0xf3, 0xb9, 0x3b, 0x10, 0x48, 0xcd, 0xa1, 0xbd, 0xea, 0xa7,
                0x33, 0x2e, 0xe2, 0x10, 0xf7, 0x13, 0x1b, 0x42, 0x01, 0x3c, 0xb4, 0x39, 0x13, 0xa6,
                0x55, 0x3a, 0x4b, 0x69,
            ]
        );

        let mut incrementing = [0u8; BM1489_L7_HEADER_BYTES];
        for (value, byte) in incrementing.iter_mut().zip(0u8..) {
            *value = byte;
        }
        assert_eq!(
            bm1489_l7_scrypt_1024_1_1_256(incrementing),
            [
                0xbc, 0x54, 0x0a, 0x1a, 0x80, 0x1d, 0xf9, 0x6e, 0x49, 0x30, 0x05, 0xc7, 0x1e, 0x01,
                0x0e, 0x2d, 0x38, 0x76, 0x07, 0xfb, 0xf0, 0xfe, 0xc4, 0x16, 0xfd, 0x3c, 0x26, 0x45,
                0xaa, 0x1b, 0xa9, 0xd2,
            ]
        );
    }

    #[test]
    fn stock_word_transforms_and_header_derived_qualification_are_pinned() {
        let mut incrementing = [0u8; BM1489_L7_HEADER_BYTES];
        for (value, byte) in incrementing.iter_mut().zip(0u8..) {
            *value = byte;
        }
        let words = bm1489_l7_stock_digest_words_from_scrypt_header(incrementing);
        assert_eq!(
            words,
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

        let mut work_words = [0u32; BM1489_L7_HEADER_WORDS];
        for (word, bytes) in work_words.iter_mut().zip(incrementing.chunks_exact(4)) {
            let mut native = [0u8; 4];
            native.copy_from_slice(bytes);
            *word = u32::from_be_bytes(native);
        }
        assert_eq!(
            bm1489_l7_stock_digest_words_from_work_header(work_words),
            words
        );

        let mut replay = input();
        replay.digest_words = [0; BM1489_L7_DIGEST_WORDS];
        replay.retained_jobs[1].target_words = [u32::MAX; BM1489_L7_DIGEST_WORDS];
        let plan = bm1489_l7_qualification_plan_from_scrypt_header(replay, incrementing).unwrap();
        assert_eq!(
            plan.disposition,
            Bm1489L7QualificationDisposition::CoarseDigestMiss
        );
        assert_eq!(plan.full_target_passed, None);
        assert!(!plan.post_target_submission_path_would_be_entered);
    }
}
