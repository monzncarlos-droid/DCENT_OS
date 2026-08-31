//! Job template processing and merkle root computation.
//!
//! Converts pool-received mining.notify data into work items ready for
//! ASIC dispatch. Handles extranonce generation, coinbase construction,
//! merkle root computation, and midstate calculation.
//!
//! This module provides lower-level building blocks. For the full work
//! generation pipeline with version rolling and extranonce2 management,
//! use `crate::work::WorkBuilder`.
//!
//! Work generation pipeline:
//!   1. JobTemplate (from pool)
//!   2. Generate extranonce2 (incrementing counter)
//!   3. Build coinbase: coinbase1 + extranonce1 + extranonce2 + coinbase2
//!   4. SHA256d(coinbase) -> coinbase_hash
//!   5. Build merkle root: fold coinbase_hash with merkle_branches
//!   6. Build block header: version + prevhash + merkle_root + ntime + nbits + nonce
//!   7. Compute SHA-256 midstate of first 64 bytes (for ASIC dispatch)

use sha2::{Digest, Sha256};

use crate::types::{JobTemplate, MAX_V1_EXTRANONCE2_SIZE};
use crate::work::compute_midstate_from_prefix;
use crate::work_domain::WorkBuildError;

/// Compute the SHA256d (double SHA-256) of input data.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Build the coinbase transaction from its parts.
///
/// coinbase = coinbase1 + extranonce1 + extranonce2 + coinbase2
///
/// The coinbase is a special transaction that creates new coins. The pool
/// splits it around the extranonce insertion point so each miner session
/// (extranonce1) and each work unit (extranonce2) produces a unique coinbase
/// and therefore a unique merkle root and block header.
pub fn build_coinbase(
    coinbase1: &[u8],
    extranonce1: &[u8],
    extranonce2: &[u8],
    coinbase2: &[u8],
) -> Vec<u8> {
    let mut coinbase = Vec::with_capacity(
        coinbase1.len() + extranonce1.len() + extranonce2.len() + coinbase2.len(),
    );
    coinbase.extend_from_slice(coinbase1);
    coinbase.extend_from_slice(extranonce1);
    coinbase.extend_from_slice(extranonce2);
    coinbase.extend_from_slice(coinbase2);
    coinbase
}

/// Compute the merkle root from the coinbase hash and merkle branches.
///
/// Starting with the coinbase hash, iteratively concatenate each branch
/// hash on the right and SHA256d the result. The coinbase is always the
/// leftmost leaf in Bitcoin's merkle tree.
///
/// If there are no branches (solo mining with a single transaction), the
/// merkle root IS the coinbase hash.
pub fn compute_merkle_root(coinbase_hash: &[u8; 32], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *coinbase_hash;

    for branch in branches {
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&current);
        concat[32..].copy_from_slice(branch);
        current = sha256d(&concat);
    }

    current
}

/// Build an 80-byte block header from its components.
///
/// Layout (all fields little-endian in the header):
///   Bytes  0..3:  version (4 bytes)
///   Bytes  4..35: previous block hash (32 bytes)
///   Bytes 36..67: merkle root (32 bytes)
///   Bytes 68..71: ntime (4 bytes, Unix timestamp)
///   Bytes 72..75: nbits (4 bytes, compact difficulty target)
///   Bytes 76..79: nonce (4 bytes, iterated by ASIC)
pub fn build_block_header(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut header = [0u8; 80];

    header[0..4].copy_from_slice(&version.to_le_bytes());
    header[4..36].copy_from_slice(prev_hash);
    header[36..68].copy_from_slice(merkle_root);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header[72..76].copy_from_slice(&nbits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());

    header
}

/// Compute the SHA-256 midstate of the first 64 bytes of a block header.
///
/// The midstate is the SHA-256 internal compression state (eight 32-bit
/// chaining variables H0..H7) after processing exactly one 512-bit block
/// (the first 64 bytes of the 80-byte block header).
///
/// The ASIC only needs:
///   - This 32-byte midstate
///   - The remaining 16 bytes: merkle_root[28..32] + ntime + nbits
///   - The 4-byte nonce (which the ASIC iterates over)
///   - SHA-256 padding (computed in hardware)
///
/// This is NOT the same as SHA-256(first_64_bytes) — it's the intermediate
/// compression function output WITHOUT finalization.
///
/// Delegates to `crate::work::compute_midstate_from_prefix` which has the
/// correct manual SHA-256 compression implementation.
pub fn compute_midstate(header_prefix: &[u8; 64]) -> [u8; 32] {
    compute_midstate_from_prefix(header_prefix)
}

/// Generate an extranonce2 value from a counter.
///
/// Returns `size` bytes representing the counter in little-endian format.
/// Invalid widths and values outside the exact server-sized domain fail
/// explicitly; this helper must never be a truncating bypass around
/// [`crate::work::WorkBuilder`].
///
/// Typical sizes:
///   - 4 bytes (most pools): 2^32 = ~4 billion unique work units per job
///   - 8 bytes (some pools): 2^64 = virtually unlimited
pub fn generate_extranonce2(counter: u64, size: usize) -> Result<Vec<u8>, WorkBuildError> {
    if !(1..=MAX_V1_EXTRANONCE2_SIZE).contains(&size) {
        return Err(WorkBuildError::InvalidExtranonce2Size(size));
    }
    let max = if size == MAX_V1_EXTRANONCE2_SIZE {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    };
    if counter > max {
        return Err(WorkBuildError::Extranonce2OutOfDomain {
            value: counter,
            width: size,
            max,
        });
    }
    let bytes = counter.to_le_bytes();
    let mut result = vec![0u8; size];
    result.copy_from_slice(&bytes[..size]);
    Ok(result)
}

/// `(merkle_root, midstate, header_tail)` as produced by [`process_job`].
///
/// Named rather than returned as a bare triple so the three same-shaped byte
/// arrays cannot be silently reordered at a call site — two of them are 32 bytes
/// and swapping them would still compile.
pub type ProcessedJobParts = ([u8; 32], [u8; 32], [u8; 16]);

/// Process a job template into work-ready components.
///
/// Returns (merkle_root, midstate, header_tail) for ASIC dispatch.
///
/// - `merkle_root`: The full 32-byte merkle root (for full header reconstruction)
/// - `midstate`: SHA-256 intermediate state of first 64 header bytes (for ASIC)
/// - `header_tail`: Last 4 bytes of merkle root + ntime + nbits + padding
///   (the ASIC processes this along with the nonce)
pub fn process_job(
    job: &JobTemplate,
    extranonce2_counter: u64,
) -> Result<ProcessedJobParts, WorkBuildError> {
    // Generate extranonce2
    let extranonce2 = generate_extranonce2(extranonce2_counter, job.extranonce2_size)?;

    // Build and hash coinbase
    let coinbase = build_coinbase(
        &job.coinbase1,
        &job.extranonce1,
        &extranonce2,
        &job.coinbase2,
    );
    let coinbase_hash = sha256d(&coinbase);

    // Compute merkle root
    let merkle_root = compute_merkle_root(&coinbase_hash, &job.merkle_branches);

    // Build first 64 bytes of header for midstate computation
    let mut header_prefix = [0u8; 64];
    header_prefix[0..4].copy_from_slice(&job.version.to_le_bytes());
    // prev_block_hash from the pool is in Stratum wire format (each 4-byte word
    // is byte-swapped relative to the block header's internal format).
    // Reverse bytes within each word to get the correct header byte order.
    let mut prev_hash = job.prev_block_hash;
    for chunk in prev_hash.chunks_exact_mut(4) {
        chunk.reverse();
    }
    header_prefix[4..36].copy_from_slice(&prev_hash);
    header_prefix[36..64].copy_from_slice(&merkle_root[..28]);

    let midstate = compute_midstate(&header_prefix);

    // Header tail: last 4 bytes of merkle root + ntime + nbits + 4 bytes padding
    let mut header_tail = [0u8; 16];
    header_tail[0..4].copy_from_slice(&merkle_root[28..32]);
    header_tail[4..8].copy_from_slice(&job.ntime.to_le_bytes());
    header_tail[8..12].copy_from_slice(&job.nbits.to_le_bytes());
    // bytes 12..15 are the nonce placeholder (zeros — ASIC fills this)

    Ok((merkle_root, midstate, header_tail))
}

/// Quality bar: does this nonce hash the template packed in a shipped
/// Closed11d `21 36` TX (not a re-coded `WorkEntry`)?
pub fn s19k_unpacked_tx_meets_share_target(
    wire: &[u8],
    nonce: u32,
    version_bits: u16,
    share_target: &[u8; 32],
) -> Result<bool, &'static str> {
    let fields = dcentrald_common::s19k_braiins_job::unpack_s19k_braiins_ghidra_job_wire(wire)?;
    let rolled = dcentrald_common::s19k_braiins_job::s19k_braiins_midstate0_version(
        fields.packed_ver0,
        version_bits,
    );
    let header = build_block_header(
        rolled,
        &fields.prev_block_hash,
        &fields.merkle_root,
        fields.ntime,
        fields.nbits,
        nonce,
    );
    Ok(crate::work::validate_full_header(&header, share_target))
}

/// Same as [`s19k_unpacked_tx_meets_share_target`] for leftover dump hex.
pub fn s19k_compact_tx_meets_share_target(
    hex: &str,
    nonce: u32,
    version_bits: u16,
    share_target: &[u8; 32],
) -> Result<bool, &'static str> {
    if hex.is_empty() {
        return Err("compact TX hex is empty");
    }
    let wire = dcentrald_common::s19k_braiins_job::parse_s19k_compact_hex(hex)?;
    s19k_unpacked_tx_meets_share_target(&wire, nonce, version_bits, share_target)
}

/// live444 leftover_header=4 leftover_hit=0: wrap-4 leftover `55 AA 21 36`
/// hashed against POST-admit `latest_entry.share_target` only. leftover_header
/// used retired history `candidate.share_target`. Hash the retired-generation
/// 21 36 bytes (no compact-hex round-trip) against any of those targets so
/// leftover_hit can re-accumulate after leftover-admit wipe.
pub fn s19k_retired_generation_tx_meets_any_share_target(
    wire: &[u8],
    nonce: u32,
    version_bits: u16,
    targets: &[[u8; 32]],
) -> bool {
    targets.iter().any(|target| {
        s19k_unpacked_tx_meets_share_target(wire, nonce, version_bits, target).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256d_empty() {
        let result = sha256d(b"");
        let hex_result = hex::encode(result);
        assert_eq!(
            hex_result,
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn test_build_coinbase() {
        let cb1 = hex::decode("01000000").unwrap();
        let en1 = hex::decode("deadbeef").unwrap();
        let en2 = hex::decode("00000001").unwrap();
        let cb2 = hex::decode("ffffffff").unwrap();
        let result = build_coinbase(&cb1, &en1, &en2, &cb2);
        assert_eq!(hex::encode(&result), "01000000deadbeef00000001ffffffff");
    }

    #[test]
    fn test_merkle_root_no_branches() {
        // With 0 branches (solo mining), merkle root IS the coinbase hash
        let hash = [0x42u8; 32];
        let result = compute_merkle_root(&hash, &[]);
        assert_eq!(result, hash);
    }

    #[test]
    fn test_merkle_root_one_branch() {
        let coinbase_hash = [0x01u8; 32];
        let branch = [0x02u8; 32];
        let result = compute_merkle_root(&coinbase_hash, &[branch]);
        // Should be SHA256d(coinbase_hash || branch)
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&coinbase_hash);
        concat[32..].copy_from_slice(&branch);
        let expected = sha256d(&concat);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_block_header_length() {
        let header = build_block_header(
            0x20000000, &[0u8; 32], &[0u8; 32], 0x65a7e340, 0x170b3ce9, 0x00000000,
        );
        assert_eq!(header.len(), 80);
    }

    #[test]
    fn test_build_block_header_version() {
        let header = build_block_header(0x20000000, &[0u8; 32], &[0u8; 32], 0, 0, 0);
        // Version should be at bytes 0..4 in little-endian
        assert_eq!(&header[0..4], &[0x00, 0x00, 0x00, 0x20]);
    }

    #[test]
    fn test_generate_extranonce2() {
        let en2_zero = generate_extranonce2(1, 0);
        assert!(matches!(
            en2_zero,
            Err(WorkBuildError::InvalidExtranonce2Size(0))
        ));

        let en2 = generate_extranonce2(1, 4).unwrap();
        assert_eq!(en2, vec![0x01, 0x00, 0x00, 0x00]); // LE
        assert_eq!(en2.len(), 4);

        let en2_8 = generate_extranonce2(1, 8).unwrap();
        assert_eq!(en2_8.len(), 8);
        assert_eq!(en2_8[0], 0x01);

        let en2_capped = generate_extranonce2(1, MAX_V1_EXTRANONCE2_SIZE + 1024);
        assert!(matches!(
            en2_capped,
            Err(WorkBuildError::InvalidExtranonce2Size(_))
        ));
    }

    #[test]
    fn test_midstate_is_deterministic() {
        let data = [0u8; 64];
        let ms1 = compute_midstate(&data);
        let ms2 = compute_midstate(&data);
        assert_eq!(ms1, ms2);
        assert_ne!(ms1, [0u8; 32]); // Should not be all zeros
    }

    #[test]
    fn test_midstate_differs_from_sha256() {
        // The midstate should NOT equal SHA-256(data) — it's the intermediate
        // compression state, not the finalized hash.
        let data = [0u8; 64];
        let midstate = compute_midstate(&data);
        let sha256_hash = Sha256::digest(&data);
        let mut sha256_arr = [0u8; 32];
        sha256_arr.copy_from_slice(&sha256_hash);
        assert_ne!(
            midstate, sha256_arr,
            "Midstate should differ from SHA-256 hash — midstate is the intermediate \
             compression state without padding and finalization"
        );
    }

    // -----------------------------------------------------------------------
    // Field-layout, multi-branch merkle, and extranonce2 truncation contracts.
    //
    // The existing tests cover happy paths but leave several wire-format
    // invariants and silent edge cases unpinned. Pin them so a refactor of
    // the header builder, merkle walk, or extranonce counter cannot
    // silently mis-encode work for the ASIC.
    // -----------------------------------------------------------------------

    #[test]
    fn sha256d_abc_known_answer_vector() {
        // SHA256d("abc") is a well-known test vector in Bitcoin literature.
        // Pin so a future refactor of the SHA-256 wrapper or Sha2 dependency
        // bump cannot silently change the hash output.
        let result = sha256d(b"abc");
        assert_eq!(
            hex::encode(result),
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
        );
    }

    #[test]
    fn build_coinbase_empty_parts_produces_empty_vec() {
        let coinbase = build_coinbase(&[], &[], &[], &[]);
        assert!(coinbase.is_empty());
    }

    #[test]
    fn build_coinbase_preserves_concatenation_order() {
        // Order matters for coinbase txid. coinbase = c1 || en1 || en2 || c2.
        let coinbase = build_coinbase(b"AAAA", b"BB", b"CC", b"DDDD");
        assert_eq!(coinbase, b"AAAABBCCDDDD");
    }

    #[test]
    fn compute_merkle_root_two_branches_matches_manual_walk() {
        // SV1 merkle walk: hash = sha256d(hash || branch) for each branch.
        // Pin two-branch case so a refactor that flips the walk direction
        // (left/right) is caught.
        let coinbase_hash = [0x11u8; 32];
        let branch_a = [0x22u8; 32];
        let branch_b = [0x33u8; 32];

        let result = compute_merkle_root(&coinbase_hash, &[branch_a, branch_b]);

        // Manual walk:
        // step 1: sha256d(coinbase_hash || branch_a)
        // step 2: sha256d(step1 || branch_b)
        let mut step1_input = [0u8; 64];
        step1_input[..32].copy_from_slice(&coinbase_hash);
        step1_input[32..].copy_from_slice(&branch_a);
        let step1 = sha256d(&step1_input);

        let mut step2_input = [0u8; 64];
        step2_input[..32].copy_from_slice(&step1);
        step2_input[32..].copy_from_slice(&branch_b);
        let expected = sha256d(&step2_input);

        assert_eq!(result, expected);
    }

    #[test]
    fn compute_merkle_root_branch_order_matters() {
        // Different branch ordering must produce different merkle roots
        // (otherwise the merkle path is not authenticating tree position).
        let coinbase_hash = [0x44u8; 32];
        let branch_a = [0x55u8; 32];
        let branch_b = [0x66u8; 32];

        let order_ab = compute_merkle_root(&coinbase_hash, &[branch_a, branch_b]);
        let order_ba = compute_merkle_root(&coinbase_hash, &[branch_b, branch_a]);
        assert_ne!(order_ab, order_ba);
    }

    #[test]
    fn build_block_header_field_positions_are_locked() {
        // Pin every field's byte position in the 80-byte block header.
        // The Bitcoin protocol commits to this layout — a refactor that
        // reordered any field would silently produce invalid blocks.
        let version: u32 = 0xDEAD_BEEF;
        let prev_hash = [0x11u8; 32];
        let merkle_root = [0x22u8; 32];
        let ntime: u32 = 0x65A7_E340;
        let nbits: u32 = 0x170B_3CE9;
        let nonce: u32 = 0xCAFE_BABE;

        let header = build_block_header(version, &prev_hash, &merkle_root, ntime, nbits, nonce);

        // Layout per Bitcoin spec:
        //   bytes  0..4   = version (LE)
        //   bytes  4..36  = prev_hash (raw, no swap)
        //   bytes 36..68  = merkle_root (raw, no swap)
        //   bytes 68..72  = ntime (LE)
        //   bytes 72..76  = nbits (LE)
        //   bytes 76..80  = nonce (LE)
        assert_eq!(&header[0..4], &version.to_le_bytes());
        assert_eq!(&header[4..36], &prev_hash);
        assert_eq!(&header[36..68], &merkle_root);
        assert_eq!(&header[68..72], &ntime.to_le_bytes());
        assert_eq!(&header[72..76], &nbits.to_le_bytes());
        assert_eq!(&header[76..80], &nonce.to_le_bytes());
        assert_eq!(header.len(), 80);
    }

    /// G22: mining engines must thin-wrap this pure SSOT (not open-code 80-byte layout).
    /// Stock midstate path intentionally stays separate — do not force StockWorkEntry unify.
    #[test]
    fn mining_engines_consume_build_block_header_ssot() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (rel, fn_name) in [
            ("dcentrald/src/serial_mining.rs", "fn serial_build_header"),
            (
                "dcentrald/src/s19j_hybrid_mining.rs",
                "fn hybrid_build_header",
            ),
            ("dcentrald/src/s19j_tap_mining.rs", "fn tap_build_header"),
            (
                "dcentrald/src/work_dispatcher.rs",
                "fn dispatcher_build_header",
            ),
        ] {
            let src = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| {
                panic!("read {rel}: {e}");
            });
            let body = src
                .split(fn_name)
                .nth(1)
                .unwrap_or_else(|| panic!("{rel}: missing {fn_name}"))
                .split("fn ")
                .next()
                .expect("function body");
            assert!(
                body.contains("build_block_header")
                    || body.contains("dcentrald_stratum::v1::job::build_block_header"),
                "{rel} {fn_name} must thin-wrap stratum build_block_header SSOT"
            );
            // Must not re-open-code the 80-byte field layout.
            assert!(
                !body.contains("header[0..4].copy_from_slice")
                    && !body.contains("header[4..36].copy_from_slice"),
                "{rel} {fn_name} must not open-code header field copies"
            );
        }
        // Honesty: stock path remains separate (midstate / header_tail engine residual).
        let stock = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            stock.contains("Do not unify with hybrid/serial WorkEntry")
                || stock.contains("StockWorkEntry"),
            "stock midstate entry must stay distinct (not false-unified)"
        );
    }

    #[test]
    fn generate_extranonce2_counter_zero_produces_all_zeros() {
        // Counter=0 is the first work unit per job. Some downstream code
        // may treat all-zero extranonce as "no work assigned"; pin that
        // generate_extranonce2 actually produces all-zero bytes for counter=0
        // so any "no work" sentinel logic stays correct.
        let en2 = generate_extranonce2(0, 4).unwrap();
        assert_eq!(en2, vec![0u8; 4]);
    }

    #[test]
    fn generate_extranonce2_rejects_counter_past_size_capacity() {
        let error = generate_extranonce2(0x1_0000_0001, 4).unwrap_err();
        assert_eq!(
            error,
            WorkBuildError::Extranonce2OutOfDomain {
                value: 0x1_0000_0001,
                width: 4,
                max: u32::MAX as u64,
            }
        );
    }

    #[test]
    fn generate_extranonce2_size_two_holds_uint16_range() {
        // size=2 extranonce gives 65536 unique work units before wrap.
        // Pin the LE byte ordering at the boundary.
        let max_u16 = generate_extranonce2(u16::MAX as u64, 2).unwrap();
        assert_eq!(max_u16, vec![0xFF, 0xFF]);

        assert!(matches!(
            generate_extranonce2(u16::MAX as u64 + 1, 2),
            Err(WorkBuildError::Extranonce2OutOfDomain { .. })
        ));
    }

    #[test]
    fn process_job_returns_consistent_merkle_and_midstate_for_same_inputs() {
        // Same job + same counter must produce identical merkle/midstate/tail
        // — work generation is deterministic. Pin so a refactor that
        // introduces nondeterminism (e.g. randomized padding) is caught.
        let job = JobTemplate {
            work_generation: crate::work_domain::WorkGeneration::UNTRACKED,
            v1_work_domain: None,
            job_id: "test".to_string(),
            prev_block_hash: [0x42; 32],
            coinbase1: vec![0x01, 0x02, 0x03, 0x04],
            coinbase2: vec![0xFA, 0xFB, 0xFC, 0xFD],
            merkle_branches: vec![[0x55; 32]],
            version: 0x2000_0000,
            nbits: 0x170b_3ce9,
            ntime: 1_700_000_000,
            clean_jobs: true,
            share_target: [0xFF; 32],
            extranonce1: vec![0xAA, 0xBB],
            extranonce2_size: 4,
            version_mask: 0,
            merkle_root: [0u8; 32],
            pool_difficulty: 1.0,
        };

        let (root_a, mid_a, tail_a) = process_job(&job, 7).unwrap();
        let (root_b, mid_b, tail_b) = process_job(&job, 7).unwrap();
        assert_eq!(root_a, root_b);
        assert_eq!(mid_a, mid_b);
        assert_eq!(tail_a, tail_b);

        // Different counter must produce different merkle root (otherwise
        // extranonce2 isn't actually salting the coinbase).
        let (root_c, _, _) = process_job(&job, 8).unwrap();
        assert_ne!(root_a, root_c);
    }

    #[test]
    fn process_job_header_tail_layout_is_locked() {
        // Header tail = merkle_root[28..32] + ntime + nbits + 4 zero bytes
        // The ASIC consumes this 16-byte chunk + 4-byte nonce. Pin the
        // layout so a refactor doesn't silently shift the field offsets
        // and break ASIC nonce search.
        let job = JobTemplate {
            work_generation: crate::work_domain::WorkGeneration::UNTRACKED,
            v1_work_domain: None,
            job_id: "test".to_string(),
            prev_block_hash: [0x42; 32],
            coinbase1: vec![0x01],
            coinbase2: vec![0x02],
            merkle_branches: vec![],
            version: 0x2000_0000,
            nbits: 0x1234_5678,
            ntime: 0xABCD_0000,
            clean_jobs: true,
            share_target: [0xFF; 32],
            extranonce1: vec![],
            extranonce2_size: 4,
            version_mask: 0,
            merkle_root: [0u8; 32],
            pool_difficulty: 1.0,
        };

        let (merkle_root, _, tail) = process_job(&job, 0).unwrap();

        // Tail layout: [merkle_root[28..32]] [ntime LE] [nbits LE] [zeros]
        assert_eq!(&tail[0..4], &merkle_root[28..32]);
        assert_eq!(&tail[4..8], &0xABCD_0000u32.to_le_bytes());
        assert_eq!(&tail[8..12], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&tail[12..16], &[0u8; 4]);
    }

    /// live412 SHARE #1 was accepted on `...8bd0`. Reconstruct that header
    /// from the logged RAW_NOTIFY and prove the same nonce misses `...8bd1`
    /// (same prevhash, different coinbase/merkle/ntime). Quality bar for
    /// leftover classification: a real share solves one generation only.
    #[test]
    fn s19k_live412_share1_meets_logged_8bd0_and_misses_8bd1() {
        fn decode32(hex: &str) -> [u8; 32] {
            let bytes = hex::decode(hex).expect("32-byte hex");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        fn header_for(
            coinbase1: &str,
            coinbase2: &str,
            branches: &[&str],
            ntime_hex: &str,
        ) -> [u8; 80] {
            let coinbase = build_coinbase(
                &hex::decode(coinbase1).unwrap(),
                &hex::decode("7637ab6c").unwrap(),
                &hex::decode("0800000000000000").unwrap(),
                &hex::decode(coinbase2).unwrap(),
            );
            let coinbase_hash = sha256d(&coinbase);
            let branches: Vec<[u8; 32]> = branches.iter().copied().map(decode32).collect();
            let merkle = compute_merkle_root(&coinbase_hash, &branches);
            let mut prev =
                decode32("981b849e96f63334a06f451b5db3e19edbbe21fb000180b40000000000000000");
            crate::work::reverse_endianness_per_word_pub(&mut prev);
            let ntime = u32::from_str_radix(ntime_hex, 16).unwrap();
            let nonce = u32::from_str_radix("4e3e900d", 16).unwrap();
            build_block_header(
                0x2004_0000, // logged rolled version (base 0x20000000 | 0x00040000)
                &prev,
                &merkle,
                ntime,
                0x1702_353d,
                nonce,
            )
        }

        let branches_8bd0 = [
            "360b693dd2b3e2cf0c4d1426cbaec64a12e69a08a294b406e24db711b958089b",
            "a2d051044a8c73346f2a76eb5a16dbfafca6a3f80d191d2da31cb5d2ecb3c16d",
            "886277e0b77f2881366fdf306c523c899f1a64fd87ff056900c8037cfaff3010",
            "1a1c8e09971ba90a9e1e955eab5fc2b94a1cf6a0534a9bc32dda6b06cd746f6b",
            "b0ac5aee5bef18f0589fd5a3907e76179f7e26a169132fe97a7c9bfdf83da788",
            "d54ce2e66dccd07ebe8a41a35348b5d38747517c5d7e595c4eaf5ce7fcf0f62c",
            "9c8144f96ef79866a026958cf34ba1288bc25d563797eaefe5acc1418d4f4448",
            "686775fe6da43db984adf12f946d21837778a23d5ce1928439d64c44d9245a21",
            "5aeaf273c5c366025cd1103da5154c024203a1bb3f3d5188301020ed30cddefb",
            "3a111ce39534f4e70306dec65db9cb886818560dd9f10a3df9690564afa2bb58",
            "8362363130d1789246c8d8cb0d948426bbebb49dc36a9e18077cb84efc92e431",
        ];
        let branches_8bd1 = [
            "360b693dd2b3e2cf0c4d1426cbaec64a12e69a08a294b406e24db711b958089b",
            "a2d051044a8c73346f2a76eb5a16dbfafca6a3f80d191d2da31cb5d2ecb3c16d",
            "886277e0b77f2881366fdf306c523c899f1a64fd87ff056900c8037cfaff3010",
            "1a1c8e09971ba90a9e1e955eab5fc2b94a1cf6a0534a9bc32dda6b06cd746f6b",
            "315bfab5e929b0d32f48135f85557f7e8122654eeff7d1f95276ef3830dfd4b7",
            "9a796edbfc4afddaa4b17eb3397362f92e7d78422aad9b05a03dd05d0486f612",
            "aa64bcfea8b3685ab146840364e915b5459162959467c87024be0b5f134063e2",
            "387aa28bf8e58894ee2e8e2c381b7816331a125d3df13af10633d1c8748918d1",
            "155178189ba9bcace429f6927677ba5ec26d21865537c4740c36c3465a745fa9",
            "755f1a3d0aefe798bf8f36098e8b1b2aaf9bb770fb4782a70022f46a31df8186",
            "cebee827338ec0a0f279056a47048b240df6be54cc5048c547d166378c5ccb71",
        ];
        let header_8bd0 = header_for(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703fab00e0004b057826a04b314a4000c",
            "0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe033f1f4c12000000001600146409983967fecf538c0e4b6f115a788c2c8660f625985f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9edccf768b44cc44adfd2655beb194dc252f2f4fb3d8dad646c96ee16d02a234872f9b00e00",
            &branches_8bd0,
            "6a8257b0",
        );
        let header_8bd1 = header_for(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703fab00e0004ce57826a045286a5000c",
            "0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe0309874c12000000001600146409983967fecf538c0e4b6f115a788c2c8660f6449a5f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9edcec9558f6a07a439844812c28b3c3ec89f53dca9d213d967200c12697298f943f9b00e00",
            &branches_8bd1,
            "6a8257ce",
        );
        let target = crate::work::difficulty_to_target(10_000.0);
        assert!(
            crate::work::validate_full_header(&header_8bd0, &target),
            "live412 SHARE #1 0x4E3E900D must meet the logged 8bd0 notify"
        );
        assert!(
            !crate::work::validate_full_header(&header_8bd1, &target),
            "the same nonce must not meet the later 8bd1 notify"
        );
    }

    /// live412 SHARE #2 was accepted on first-fill `...8bd1` (extranonce2
    /// 0x51). Reconstruct it and prove it misses the earlier 8bd0 template.
    #[test]
    fn s19k_live412_share2_meets_logged_8bd1_and_misses_8bd0() {
        fn decode32(hex: &str) -> [u8; 32] {
            let bytes = hex::decode(hex).expect("32-byte hex");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        fn header_for(
            coinbase1: &str,
            coinbase2: &str,
            branches: &[&str],
            ntime_hex: &str,
            extra2: &str,
            rolled: u32,
            nonce_hex: &str,
        ) -> [u8; 80] {
            let coinbase = build_coinbase(
                &hex::decode(coinbase1).unwrap(),
                &hex::decode("7637ab6c").unwrap(),
                &hex::decode(extra2).unwrap(),
                &hex::decode(coinbase2).unwrap(),
            );
            let coinbase_hash = sha256d(&coinbase);
            let branches: Vec<[u8; 32]> = branches.iter().copied().map(decode32).collect();
            let merkle = compute_merkle_root(&coinbase_hash, &branches);
            let mut prev =
                decode32("981b849e96f63334a06f451b5db3e19edbbe21fb000180b40000000000000000");
            crate::work::reverse_endianness_per_word_pub(&mut prev);
            build_block_header(
                rolled,
                &prev,
                &merkle,
                u32::from_str_radix(ntime_hex, 16).unwrap(),
                0x1702_353d,
                u32::from_str_radix(nonce_hex, 16).unwrap(),
            )
        }
        let branches_8bd0 = [
            "360b693dd2b3e2cf0c4d1426cbaec64a12e69a08a294b406e24db711b958089b",
            "a2d051044a8c73346f2a76eb5a16dbfafca6a3f80d191d2da31cb5d2ecb3c16d",
            "886277e0b77f2881366fdf306c523c899f1a64fd87ff056900c8037cfaff3010",
            "1a1c8e09971ba90a9e1e955eab5fc2b94a1cf6a0534a9bc32dda6b06cd746f6b",
            "b0ac5aee5bef18f0589fd5a3907e76179f7e26a169132fe97a7c9bfdf83da788",
            "d54ce2e66dccd07ebe8a41a35348b5d38747517c5d7e595c4eaf5ce7fcf0f62c",
            "9c8144f96ef79866a026958cf34ba1288bc25d563797eaefe5acc1418d4f4448",
            "686775fe6da43db984adf12f946d21837778a23d5ce1928439d64c44d9245a21",
            "5aeaf273c5c366025cd1103da5154c024203a1bb3f3d5188301020ed30cddefb",
            "3a111ce39534f4e70306dec65db9cb886818560dd9f10a3df9690564afa2bb58",
            "8362363130d1789246c8d8cb0d948426bbebb49dc36a9e18077cb84efc92e431",
        ];
        let branches_8bd1 = [
            "360b693dd2b3e2cf0c4d1426cbaec64a12e69a08a294b406e24db711b958089b",
            "a2d051044a8c73346f2a76eb5a16dbfafca6a3f80d191d2da31cb5d2ecb3c16d",
            "886277e0b77f2881366fdf306c523c899f1a64fd87ff056900c8037cfaff3010",
            "1a1c8e09971ba90a9e1e955eab5fc2b94a1cf6a0534a9bc32dda6b06cd746f6b",
            "315bfab5e929b0d32f48135f85557f7e8122654eeff7d1f95276ef3830dfd4b7",
            "9a796edbfc4afddaa4b17eb3397362f92e7d78422aad9b05a03dd05d0486f612",
            "aa64bcfea8b3685ab146840364e915b5459162959467c87024be0b5f134063e2",
            "387aa28bf8e58894ee2e8e2c381b7816331a125d3df13af10633d1c8748918d1",
            "155178189ba9bcace429f6927677ba5ec26d21865537c4740c36c3465a745fa9",
            "755f1a3d0aefe798bf8f36098e8b1b2aaf9bb770fb4782a70022f46a31df8186",
            "cebee827338ec0a0f279056a47048b240df6be54cc5048c547d166378c5ccb71",
        ];
        let cb1_8bd0 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703fab00e0004b057826a04b314a4000c";
        let cb2_8bd0 = "0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe033f1f4c12000000001600146409983967fecf538c0e4b6f115a788c2c8660f625985f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9edccf768b44cc44adfd2655beb194dc252f2f4fb3d8dad646c96ee16d02a234872f9b00e00";
        let cb1_8bd1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703fab00e0004ce57826a045286a5000c";
        let cb2_8bd1 = "0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe0309874c12000000001600146409983967fecf538c0e4b6f115a788c2c8660f6449a5f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9edcec9558f6a07a439844812c28b3c3ec89f53dca9d213d967200c12697298f943f9b00e00";
        let header_8bd1 = header_for(
            cb1_8bd1,
            cb2_8bd1,
            &branches_8bd1,
            "6a8257ce",
            "5100000000000000",
            0x205B_0000,
            "e5d3c50d",
        );
        let header_8bd0 = header_for(
            cb1_8bd0,
            cb2_8bd0,
            &branches_8bd0,
            "6a8257b0",
            "5100000000000000",
            0x205B_0000,
            "e5d3c50d",
        );
        let target = crate::work::difficulty_to_target(10_000.0);
        assert!(
            crate::work::validate_full_header(&header_8bd1, &target),
            "live412 SHARE #2 0xE5D3C50D must meet the logged 8bd1 notify"
        );
        assert!(
            !crate::work::validate_full_header(&header_8bd0, &target),
            "SHARE #2 must not meet the earlier 8bd0 notify"
        );
    }

    /// : a post-clean dump `tx_wire` is the shipped 21 36 packer.
    /// Unpacking that wire and hashing SHARE #1 must meet the 8bd0 target —
    /// the leftover bar is measured against the real TX, not a re-coded header.
    #[test]
    fn s19k_live412_share1_solves_unpacked_ghidra_tx_wire() {
        fn decode32(hex: &str) -> [u8; 32] {
            let bytes = hex::decode(hex).expect("32-byte hex");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        let branches = [
            "360b693dd2b3e2cf0c4d1426cbaec64a12e69a08a294b406e24db711b958089b",
            "a2d051044a8c73346f2a76eb5a16dbfafca6a3f80d191d2da31cb5d2ecb3c16d",
            "886277e0b77f2881366fdf306c523c899f1a64fd87ff056900c8037cfaff3010",
            "1a1c8e09971ba90a9e1e955eab5fc2b94a1cf6a0534a9bc32dda6b06cd746f6b",
            "b0ac5aee5bef18f0589fd5a3907e76179f7e26a169132fe97a7c9bfdf83da788",
            "d54ce2e66dccd07ebe8a41a35348b5d38747517c5d7e595c4eaf5ce7fcf0f62c",
            "9c8144f96ef79866a026958cf34ba1288bc25d563797eaefe5acc1418d4f4448",
            "686775fe6da43db984adf12f946d21837778a23d5ce1928439d64c44d9245a21",
            "5aeaf273c5c366025cd1103da5154c024203a1bb3f3d5188301020ed30cddefb",
            "3a111ce39534f4e70306dec65db9cb886818560dd9f10a3df9690564afa2bb58",
            "8362363130d1789246c8d8cb0d948426bbebb49dc36a9e18077cb84efc92e431",
        ];
        let coinbase = build_coinbase(
            &hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703fab00e0004b057826a04b314a4000c").unwrap(),
            &hex::decode("7637ab6c").unwrap(),
            &hex::decode("0800000000000000").unwrap(),
            &hex::decode("0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe033f1f4c12000000001600146409983967fecf538c0e4b6f115a788c2c8660f625985f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9edccf768b44cc44adfd2655beb194dc252f2f4fb3d8dad646c96ee16d02a234872f9b00e00").unwrap(),
        );
        let merkle = compute_merkle_root(
            &sha256d(&coinbase),
            &branches.iter().copied().map(decode32).collect::<Vec<_>>(),
        );
        let mut prev = decode32("981b849e96f63334a06f451b5db3e19edbbe21fb000180b40000000000000000");
        crate::work::reverse_endianness_per_word_pub(&mut prev);
        let ntime = 0x6a82_57b0;
        let nbits = 0x1702_353d;
        let version = 0x2000_0000u32;
        let wire = dcentrald_common::s19k_braiins_job::build_s19k_braiins_mining_on_work_wire(
            8, version, prev, merkle, ntime, nbits,
        );
        let compact: String = wire.iter().map(|b| format!("{b:02X}")).collect();
        let parsed =
            dcentrald_common::s19k_braiins_job::parse_s19k_compact_hex(&compact).expect("dump hex");
        let fields =
            dcentrald_common::s19k_braiins_job::unpack_s19k_braiins_ghidra_job_wire(&parsed)
                .expect("unpack dumped TX");
        let rolled = dcentrald_common::s19k_braiins_job::s19k_braiins_midstate0_version(
            fields.packed_ver0,
            0x0020,
        );
        let header = build_block_header(
            rolled,
            &fields.prev_block_hash,
            &fields.merkle_root,
            fields.ntime,
            fields.nbits,
            0x4E3E_900D,
        );
        let target = crate::work::difficulty_to_target(10_000.0);
        assert!(
            crate::work::validate_full_header(&header, &target),
            "SHARE #1 must solve the unpacked shipped 21 36 TX"
        );
        assert_eq!(fields.job_id, 8);
        assert_eq!(fields.ntime, ntime);
        assert_eq!(fields.merkle_root, merkle);
        assert_eq!(fields.prev_block_hash, prev);
        assert!(
            s19k_compact_tx_meets_share_target(&compact, 0x4E3E_900D, 0x0020, &target)
                .expect("quality-bar hash"),
            "SHARE #1 must meet the unpacked shipped TX via the quality-bar helper"
        );
    }

    /// The only held live412 on-wire dump is first-fill job_id 0 (extra2=00).
    /// SHARE #1 is extra2=08. Unpacking the captured frame and hashing SHARE #1
    /// against *that* merkle must miss — leftover measurement needs the
    /// share's own TX, not the session's first FULL FRAME line.
    #[test]
    fn s19k_live412_share1_misses_captured_first_frame_merkle() {
        const LIVE412_FIRST_FRAME: &str = "55 AA 21 36 00 01 00 00 00 00 3D 35 02 17 \
B0 57 82 6A 76 F5 EF 1D 69 B7 B2 8E 1B A6 BC 50 CA 98 F0 6C 93 96 28 A6 8F 12 33 \
DD E7 92 4A 00 85 62 E9 03 00 00 00 00 00 00 00 00 B4 80 01 00 FB 21 BE DB 9E E1 \
B3 5D 1B 45 6F A0 34 33 F6 96 9E 84 1B 98 00 00 00 20 64 C2";
        let parsed =
            dcentrald_common::s19k_braiins_job::parse_s19k_compact_hex(LIVE412_FIRST_FRAME)
                .expect("live412 spaced dump");
        let fields =
            dcentrald_common::s19k_braiins_job::unpack_s19k_braiins_ghidra_job_wire(&parsed)
                .expect("unpack live412 frame");
        let coinbase = build_coinbase(
            &hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703fab00e0004b057826a04b314a4000c").unwrap(),
            &hex::decode("7637ab6c").unwrap(),
            &hex::decode("0000000000000000").unwrap(),
            &hex::decode("0a636b706f6f6c1375772f736f6c6f2e636b706f6f6c2e6f72672ffffffffe033f1f4c12000000001600146409983967fecf538c0e4b6f115a788c2c8660f625985f000000000016001451ed61d2f6aa260cc72cdf743e4e436a82c010270000000000000000266a24aa21a9edccf768b44cc44adfd2655beb194dc252f2f4fb3d8dad646c96ee16d02a234872f9b00e00").unwrap(),
        );
        let branches = [
            "360b693dd2b3e2cf0c4d1426cbaec64a12e69a08a294b406e24db711b958089b",
            "a2d051044a8c73346f2a76eb5a16dbfafca6a3f80d191d2da31cb5d2ecb3c16d",
            "886277e0b77f2881366fdf306c523c899f1a64fd87ff056900c8037cfaff3010",
            "1a1c8e09971ba90a9e1e955eab5fc2b94a1cf6a0534a9bc32dda6b06cd746f6b",
            "b0ac5aee5bef18f0589fd5a3907e76179f7e26a169132fe97a7c9bfdf83da788",
            "d54ce2e66dccd07ebe8a41a35348b5d38747517c5d7e595c4eaf5ce7fcf0f62c",
            "9c8144f96ef79866a026958cf34ba1288bc25d563797eaefe5acc1418d4f4448",
            "686775fe6da43db984adf12f946d21837778a23d5ce1928439d64c44d9245a21",
            "5aeaf273c5c366025cd1103da5154c024203a1bb3f3d5188301020ed30cddefb",
            "3a111ce39534f4e70306dec65db9cb886818560dd9f10a3df9690564afa2bb58",
            "8362363130d1789246c8d8cb0d948426bbebb49dc36a9e18077cb84efc92e431",
        ];
        fn decode32(hex: &str) -> [u8; 32] {
            let bytes = hex::decode(hex).expect("32-byte hex");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        let merkle = compute_merkle_root(
            &sha256d(&coinbase),
            &branches.iter().copied().map(decode32).collect::<Vec<_>>(),
        );
        assert_eq!(
            fields.merkle_root, merkle,
            "captured first frame must be 8bd0 extra2=00, not merely the 8bd0 ntime"
        );
        let header = build_block_header(
            0x2004_0000,
            &fields.prev_block_hash,
            &fields.merkle_root,
            fields.ntime,
            fields.nbits,
            0x4E3E_900D,
        );
        let target = crate::work::difficulty_to_target(10_000.0);
        assert!(
            !crate::work::validate_full_header(&header, &target),
            "SHARE #1 extra2=08 must not solve the captured job_id=0 first frame"
        );
        assert!(
            !s19k_compact_tx_meets_share_target(LIVE412_FIRST_FRAME, 0x4E3E_900D, 0x0020, &target)
                .expect("quality-bar hash of captured frame"),
            "quality-bar helper must miss SHARE #1 on the captured job0 TX"
        );
        assert!(s19k_compact_tx_meets_share_target("", 0, 0, &target).is_err());
    }

    #[test]
    fn s19k_live444_wrap4_leftover_21_36_meets_retired_target_not_only_latest() {
        let merkle = [0x11u8; 32];
        let mut prev = [0u8; 32];
        prev[0] = 0x22;
        let wire = dcentrald_common::s19k_braiins_job::build_s19k_braiins_mining_on_work_wire(
            2,
            0x2000_0000,
            prev,
            merkle,
            0x6a82_57b0,
            0x1702_353d,
        );
        let retired_target = [0xFFu8; 32];
        let latest_target = [0u8; 32];
        assert!(
            s19k_unpacked_tx_meets_share_target(&wire, 0, 0, &retired_target).unwrap(),
            "wrap-4 leftover 21 36 must meet retired history share_target"
        );
        assert!(
            !s19k_unpacked_tx_meets_share_target(&wire, 0, 0, &latest_target).unwrap(),
            "POST-admit latest_entry.share_target must not be the only leftover_hit gate"
        );
        assert!(
            s19k_retired_generation_tx_meets_any_share_target(
                &wire,
                0,
                0,
                &[latest_target, retired_target],
            ),
            "leftover_hit must re-accumulate from wrap-4 leftover 21 36 vs retired target"
        );
        assert!(
            !s19k_retired_generation_tx_meets_any_share_target(&wire, 0, 0, &[latest_target]),
            "leftover_header-only (no retired 21 36 meet) must not leftover_hit"
        );
    }
}
