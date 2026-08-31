// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — SHARED Avalon Stratum→ASIC work bridge.
//
// THIS FILE IS THE ONE COPY. It is `include!`d verbatim by both Avalon
// daemons:
//
//   DCENT_OS_AvalonMiner/home/dcentaxe-nano3s/src/bridge.rs        (HOME line)
//   DCENT_OS_AvalonMiner/dcentrald/dcentrald/src/bridge.rs     (INDUSTRIAL)
//
// WHY THIS FILE EXISTS. Until 2026-08-03 the industrial daemon carried its own
// 51-line `bridge.rs` that was a BYTE-EXACT PREFIX of the home daemon's
// 244-line one: identical `avalon_work_to_job` + `reverse_32bit_words`, and
// then nothing — the entire `#[cfg(test)] mod tests` block was absent. So the
// industrial line shipped a share-affecting transform with ZERO tests, while
// the home line's own comment on `differs_from_full_byte_reversal` warned that
// substituting a naive full-byte reversal would "silently corrupt every share".
// One line was guarded against that; the other was not. Collapsing to a single
// source makes the guards structurally impossible to have on only one side.
//
// (The line-ending difference is why a plain `diff` reported three hunks and
// hid the prefix relationship: the industrial copy was CRLF, the home copy LF.
// `diff --strip-trailing-cr` showed the truth — a single `51a52,244`.)
//
// WHY `include!` AND NOT A CARGO DEPENDENCY. Same reason as
// `avalon_shim_driver.rs` beside it: the two daemons live in SEPARATE cargo
// workspaces with independently pinned toolchains, and the bridge is glue over
// each crate's own already-imported `dcentaxe_asic` / `dcentaxe_stratum`
// types. A shared crate would have to re-export those types and would couple
// the two workspaces' dependency graphs; `include!` shares the bytes and
// nothing else.
//
// DO NOT copy this body back into either `src/`. Both stubs carry an
// anti-refork test that fails if you do.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/
//
// MiningWork → MiningJob adapter for Avalon.
//
// Mirrors the pattern in `dcentos-esp/dcentaxe/src/bridge.rs` for
// BM1366/BM1368/BM1370/BM1373: use the full-header job form with
// word-reversed prev_block_hash and merkle_root. The Avalon `asic_miner_e`
// RT-Smart blob is expected to consume the same convention (verify in
// Plan 4 when we trace the SET_JOB sub-frame layout from a live unit or
// from `canaan-cgminer/driver-avalon-miner.c`).
//
// Avalon does NOT use the BM1397-style midstate path: the K230 big core
// computes midstates internally. We hand the host's full-header form via
// `AvalonShimDriver::send_work` → `MmPkg::SetJob`.

use dcentaxe_asic::common::MiningJob;
use dcentaxe_stratum::MiningWork;

/// Repo-relative path of THIS file. Both stubs assert against it so an
/// `include!` and its paired `include_str!` cannot drift onto different files.
#[allow(dead_code)]
const SHARED_BRIDGE_SOURCE: &str = "shared/dcent-avalon-proto/shared/avalon_bridge.rs";

/// Build an Avalon MiningJob from a Stratum MiningWork + dispatcher-assigned
/// `job_id`.
///
/// Word-reversal of `prev_block_hash` and `merkle_root` matches the BM1366+
/// convention used by `dcentos-esp/dcentaxe/src/bridge.rs:42-54`.
/// If Avalon's RT-Smart blob expects raw (non-reversed) bytes, swap to the
/// commented branch in Plan 4 after live-unit trace.
pub fn avalon_work_to_job(work: &MiningWork, job_id: u8) -> MiningJob {
    let prev_hash_reversed = reverse_32bit_words(&work.prev_block_hash);
    let merkle_root_reversed = reverse_32bit_words(&work.merkle_root);

    MiningJob::new_full(
        job_id,
        work.version,
        prev_hash_reversed,
        merkle_root_reversed,
        work.ntime,
        work.nbits,
        0, // starting_nonce
    )
    .with_coinbase_parts(
        work.coinbase.clone(),
        work.merkle_branches.clone(),
        extranonce2_low_u32(&work.extranonce2),
        work.nonce2_offset as i32,
        work.nonce2_size as i32,
        Some(work.share_target),
    )
}

/// The assigned extranonce2 as a u32 (the hex is little-endian zero-padded;
/// take the low 4 bytes — the stock mm_work field is a u32 and stock
/// software supports 4-byte en2). Hand-parsed so the shared body keeps
/// working inside BOTH consumers regardless of their dependency sets.
fn extranonce2_low_u32(extranonce2_hex: &str) -> u32 {
    let hex = extranonce2_hex.as_bytes();
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks(2) {
        let hi = (pair.first().copied().unwrap_or(b'0') as char).to_digit(16);
        let lo = (pair.get(1).copied().unwrap_or(b'0') as char).to_digit(16);
        if let (Some(hi), Some(lo)) = (hi, lo) {
            bytes.push(((hi << 4) | lo) as u8);
        }
    }
    let mut value = 0u32;
    for (index, byte) in bytes.iter().rev().take(4).enumerate() {
        value |= u32::from(*byte) << (8 * index);
    }
    value
}

/// Reverse the order of 32-bit words in a 32-byte array.
/// `word[0] ↔ word[7]`, `word[1] ↔ word[6]`, etc.
/// Port of ESP-Miner's `reverse_32bit_words()`.
fn reverse_32bit_words(src: &[u8; 32]) -> [u8; 32] {
    let mut dest = [0u8; 32];
    for i in 0..8 {
        let j = 7 - i;
        dest[i * 4..i * 4 + 4].copy_from_slice(&src[j * 4..j * 4 + 4]);
    }
    dest
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical semantics (
    // §8.1 "Endianness Notes", lines 1730-1736):
    //
    //   Input:   [W0][W1][W2][W3][W4][W5][W6][W7]
    //   Output:  [W7][W6][W5][W4][W3][W2][W1][W0]
    //
    //   "Where each W is a 4-byte (32-bit) word. The bytes within each word are
    //    NOT swapped."
    //
    // The same `reverse_32bit_words` is re-applied on the share-verification path
    // (Bible §2.8, line 668: `reverse_32bit_words(job->prev_block_hash, header+4)`
    // // restore to header order) to rebuild the 80-byte header before the
    // double-SHA256 difficulty check. That round-trip is only correct because the
    // transform is its own inverse — `roundtrip_is_its_own_inverse` pins exactly
    // that property, so a pool would validate the share the BM1366+/Avalon ASIC
    // returns.

    /// Golden multi-word vector with a hand-computed expected output.
    ///
    /// Input bytes are their own index `0..=31`, so the eight 4-byte words are
    /// `W0=[0,1,2,3] … W7=[28,29,30,31]`. Reversing the WORD order (bytes inside
    /// each word preserved) must yield `W7 W6 W5 W4 W3 W2 W1 W0`. The expected
    /// array below is written out by hand — it does not call the function under
    /// test, so the test is self-checking, not a tautology.
    #[test]
    fn golden_word_order_reversed_byte_in_word_preserved() {
        let mut src = [0u8; 32];
        for (i, b) in src.iter_mut().enumerate() {
            *b = i as u8;
        }

        let expected: [u8; 32] = [
            28, 29, 30, 31, // W7
            24, 25, 26, 27, // W6
            20, 21, 22, 23, // W5
            16, 17, 18, 19, // W4
            12, 13, 14, 15, // W3
            8, 9, 10, 11, // W2
            4, 5, 6, 7, // W1
            0, 1, 2, 3, // W0
        ];

        assert_eq!(reverse_32bit_words(&src), expected);
    }

    /// The bytes WITHIN each 32-bit word must stay in order. This is the
    /// load-bearing distinction between this transform and a naive full 32-byte
    /// reversal (`src.iter().rev()`), which a future "simplification" might
    /// wrongly substitute and silently corrupt every share.
    #[test]
    fn differs_from_full_byte_reversal() {
        let mut src = [0u8; 32];
        for (i, b) in src.iter_mut().enumerate() {
            *b = i as u8;
        }

        let got = reverse_32bit_words(&src);

        // Word-order reversal keeps W7 = [28,29,30,31] intact at the front...
        assert_eq!(&got[0..4], &[28, 29, 30, 31]);

        // ...whereas a full byte reversal would produce [31,30,29,28] there.
        let mut full_reverse = src;
        full_reverse.reverse();
        assert_eq!(&full_reverse[0..4], &[31, 30, 29, 28]);
        assert_ne!(
            got, full_reverse,
            "32-bit-word reversal must NOT equal a full byte reversal"
        );
    }

    /// A single non-zero leading word must land at the opposite end (W0 -> W7
    /// slot, bytes [28..32]) with its byte order untouched, and nothing else may
    /// move. Pins word repositioning precisely.
    #[test]
    fn single_nonzero_word_moves_to_opposite_end() {
        let mut src = [0u8; 32];
        src[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let got = reverse_32bit_words(&src);

        let mut expected = [0u8; 32];
        expected[28..32].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(got, expected);
    }

    /// The all-zero array is a fixed point (edge case: no panics, no garbage).
    #[test]
    fn all_zero_is_fixed_point() {
        assert_eq!(reverse_32bit_words(&[0u8; 32]), [0u8; 32]);
    }

    /// `reverse(reverse(x)) == x` for an asymmetric input — the involution
    /// property the share-verification header rebuild relies on (Bible §2.8).
    /// The input is asymmetric so the single reversal is genuinely NOT identity,
    /// which keeps the round-trip non-trivial.
    #[test]
    fn roundtrip_is_its_own_inverse() {
        // Deterministic, distinctive, asymmetric byte pattern.
        let mut src = [0u8; 32];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }

        let once = reverse_32bit_words(&src);
        assert_ne!(once, src, "a single reversal must not be the identity");
        assert_eq!(
            reverse_32bit_words(&once),
            src,
            "reverse_32bit_words must be its own inverse"
        );
    }

    /// If the word layout is palindromic (`word[i] == word[7-i]`), reversing the
    /// word order is a no-op. Independent confirmation that only WORD position
    /// changes, never the bytes inside a word.
    #[test]
    fn palindromic_word_layout_is_fixed_point() {
        let w = |a: u8| [a, a.wrapping_add(1), a.wrapping_add(2), a.wrapping_add(3)];
        let mut src = [0u8; 32];
        // Mirror words around the centre: W0==W7, W1==W6, W2==W5, W3==W4.
        for (i, word) in [w(0x10), w(0x20), w(0x30), w(0x40)].into_iter().enumerate() {
            src[i * 4..i * 4 + 4].copy_from_slice(&word);
            let mirror = 7 - i;
            src[mirror * 4..mirror * 4 + 4].copy_from_slice(&word);
        }

        assert_eq!(reverse_32bit_words(&src), src);
    }

    /// End-to-end: `avalon_work_to_job` must word-reverse BOTH `prev_block_hash`
    /// and `merkle_root` (the fields the Avalon full-header job feeds to the
    /// ASIC) and pass every other field straight through with `starting_nonce=0`
    /// and no midstates (full-header form, not BM1397 midstate form).
    ///
    /// Expected reversed values are hand-computed golden constants (the index
    /// vector for prev, a single-word vector for merkle), NOT recomputed via the
    /// function under test, so this also independently re-pins the reversal.
    #[test]
    fn avalon_work_to_job_reverses_prev_and_merkle_passes_through_rest() {
        let mut prev = [0u8; 32];
        for (i, b) in prev.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let work = MiningWork {
            midstates: Vec::new(),
            merkle4: [0xAA, 0xBB, 0xCC, 0xDD],
            ntime: 0x6651_1234,
            nbits: 0x1703_2E1D,
            version: 0x2000_0000,
            version_mask: 0x1FFF_E000,
            prev_block_hash: prev,
            merkle_root: merkle,
            job_id: "bf".to_string(),
            extranonce2: "00000000".to_string(),
            share_target: [0u8; 32],
            algorithm: dcentaxe_stratum::PowAlgorithm::Sha256d,
        };

        let job: MiningJob = avalon_work_to_job(&work, 0x40);

        // prev_block_hash word-reversed (golden, hand-computed).
        let expected_prev: [u8; 32] = [
            28, 29, 30, 31, 24, 25, 26, 27, 20, 21, 22, 23, 16, 17, 18, 19, 12, 13, 14, 15, 8, 9,
            10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
        ];
        assert_eq!(job.prev_block_hash, expected_prev);

        // merkle_root word-reversed: the only non-zero word (W0) lands in W7.
        let mut expected_merkle = [0u8; 32];
        expected_merkle[28..32].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(job.merkle_root, expected_merkle);

        // Everything else passes through verbatim, full-header form.
        assert_eq!(job.job_id, 0x40);
        assert_eq!(job.version, 0x2000_0000);
        assert_eq!(job.ntime, 0x6651_1234);
        assert_eq!(job.nbits, 0x1703_2E1D);
        assert_eq!(job.starting_nonce, 0);
        assert!(
            job.midstates.is_empty(),
            "Avalon uses the full-header job form, not BM1397 midstates"
        );
    }
    /// 2026-08-29 coinbase interface extension: the bridge must forward the
    /// stratum layer's coinbase/branch/en2-geometry into the MiningJob so
    /// the shim can emit a complete mm_work SET_JOB.
    #[test]
    fn forwards_coinbase_parts_into_the_mining_job() {
        use dcentaxe_stratum::PowAlgorithm;
        let work = MiningWork {
            midstates: Vec::new(),
            merkle4: [0u8; 4],
            ntime: 0x6651_0000,
            nbits: 0x1703_2E1D,
            version: 0x2000_0000,
            version_mask: 0x1FFF_E000,
            prev_block_hash: [0u8; 32],
            merkle_root: [7u8; 32],
            job_id: "pool-job".into(),
            extranonce2: "0102aabb".into(),
            share_target: [0xFF; 32],
            coinbase: vec![0xCB; 32],
            merkle_branches: vec![[0x33; 32], [0x44; 32]],
            nonce2_offset: 41,
            nonce2_size: 4,
            algorithm: PowAlgorithm::Sha256d,
        };
        let job = avalon_work_to_job(&work, 0x5A);
        assert_eq!(job.job_id, 0x5A);
        assert_eq!(job.coinbase, vec![0xCB; 32]);
        assert_eq!(job.merkle_branches, vec![[0x33; 32], [0x44; 32]]);
        assert_eq!(job.nonce2_offset, 41);
        assert_eq!(job.nonce2_size, 4);
        assert_eq!(job.target, Some([0xFF; 32]));
        assert!(job.has_coinbase_parts());
        // Little-endian hex extranonce2 "0102aabb" -> u32 0xBBAA0201.
        assert_eq!(job.nonce2, 0xBBAA_0201);
    }

}
