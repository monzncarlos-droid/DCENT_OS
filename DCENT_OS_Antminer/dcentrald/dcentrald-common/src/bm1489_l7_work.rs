//! Pure outbound-work construction recovered from the exact held L7 VNish BM1489 binary.
//!
//! This reproduces the selector-six frame, coinbase/nonce2/Merkle derivation,
//! CRC, work snapshot, and stock publication spine without I/O. The previous
//! hash remains caller-supplied wire bytes. No physical carrier or generation-
//! safe work-ID reuse barrier is recovered, so this grants no live authority.

use crate::bm1489_l7_return::{
    bm1489_l7_stock_next_work_id, bm1489_l7_stock_work_publication_steps,
    Bm1489L7WorkPublicationStep, Bm1489L7WorkSnapshot, BM1489_L7_STOCK_FIRST_WORK_ID,
    BM1489_L7_STOCK_LAST_WORK_ID,
};
use crate::bm1489_l7_share_qualification::sha256;

pub const BM1489_L7_WORK_FRAME_LEN: usize = 0x56;
pub const BM1489_L7_WORK_HEADER: [u8; 2] = [0x55, 0xaa];
pub const BM1489_L7_WORK_COMMAND: u8 = 0x20;
pub const BM1489_L7_WORK_CRC_OFFSET: usize = 2;
pub const BM1489_L7_WORK_CRC_INPUT_LEN: usize = 0x52;
pub const BM1489_L7_WORK_START_NONCE: u32 = 0;
pub const BM1489_L7_MERKLE_BRANCH_LEN: usize = 32;
pub const BM1489_L7_MAX_NONCE2_SIZE: u8 = 8;

pub const BM1489_L7_WORK_FRAME_RECOVERED: bool = true;
pub const BM1489_L7_WORK_MERKLE_DERIVATION_RECOVERED: bool = true;
pub const BM1489_L7_WORK_PREVIOUS_HASH_PROVENANCE_AUTHENTICATED: bool = false;
pub const BM1489_L7_WORK_ID_REUSE_BARRIER_RECOVERED: bool = false;
pub const BM1489_L7_WORK_AUTHORIZES_LIVE_IO: bool = false;
pub const BM1489_L7_WORK_AUTHORIZES_DISPATCH: bool = false;
pub const BM1489_L7_WORK_AUTHORIZES_SHARE_SUBMISSION: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1489L7WorkJob<'a> {
    pub work_id: u8,
    pub job_id: u32,
    pub version: u32,
    /// Exact frame bytes 8..39; upstream byte-order provenance is unproved.
    pub previous_hash_wire: [u8; 32],
    pub coinbase: &'a [u8],
    pub nonce2_offset: usize,
    pub nonce2_size: u8,
    pub nonce2: u64,
    /// Standard 32-byte SHA-256 digest byte strings.
    pub merkle_branches: &'a [[u8; BM1489_L7_MERKLE_BRANCH_LEN]],
    pub nbits: u32,
    pub ntime: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1489L7WorkBuildError {
    InvalidWorkId {
        work_id: u8,
    },
    Nonce2TooLarge {
        size: u8,
    },
    Nonce2RangeOverflow,
    Nonce2OutsideCoinbase {
        offset: usize,
        size: u8,
        coinbase_len: usize,
    },
    CoinbaseAllocationFailed {
        requested: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1489L7WorkPlan {
    pub frame: [u8; BM1489_L7_WORK_FRAME_LEN],
    /// Standard digest byte order before stock's per-word frame reversal.
    pub merkle_root: [u8; 32],
    pub snapshot: Bm1489L7WorkSnapshot,
    pub publication_steps: [Bm1489L7WorkPublicationStep; 9],
    pub next_work_id: u8,
}

impl Bm1489L7WorkPlan {
    pub const fn authorizes_live_io(&self) -> bool {
        false
    }

    pub const fn authorizes_dispatch(&self) -> bool {
        false
    }

    pub const fn authorizes_share_submission(&self) -> bool {
        false
    }
}

/// CRC-16/CCITT-FALSE: polynomial `0x1021`, initial `0xffff`, no final XOR.
pub fn bm1489_l7_crc16_ccitt_false(bytes: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
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

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(&sha256(bytes))
}

/// Build one exact selector-six work frame and its unsafe publication spine.
pub fn bm1489_l7_plan_work(
    job: Bm1489L7WorkJob<'_>,
) -> Result<Bm1489L7WorkPlan, Bm1489L7WorkBuildError> {
    if !(BM1489_L7_STOCK_FIRST_WORK_ID..=BM1489_L7_STOCK_LAST_WORK_ID).contains(&job.work_id) {
        return Err(Bm1489L7WorkBuildError::InvalidWorkId {
            work_id: job.work_id,
        });
    }
    if job.nonce2_size > BM1489_L7_MAX_NONCE2_SIZE {
        return Err(Bm1489L7WorkBuildError::Nonce2TooLarge {
            size: job.nonce2_size,
        });
    }
    let nonce2_end = job
        .nonce2_offset
        .checked_add(usize::from(job.nonce2_size))
        .ok_or(Bm1489L7WorkBuildError::Nonce2RangeOverflow)?;
    if nonce2_end > job.coinbase.len() {
        return Err(Bm1489L7WorkBuildError::Nonce2OutsideCoinbase {
            offset: job.nonce2_offset,
            size: job.nonce2_size,
            coinbase_len: job.coinbase.len(),
        });
    }

    let mut patched_coinbase = Vec::new();
    patched_coinbase
        .try_reserve_exact(job.coinbase.len())
        .map_err(|_| Bm1489L7WorkBuildError::CoinbaseAllocationFailed {
            requested: job.coinbase.len(),
        })?;
    patched_coinbase.extend_from_slice(job.coinbase);
    let nonce2_bytes = job.nonce2.to_le_bytes();
    patched_coinbase[job.nonce2_offset..nonce2_end]
        .copy_from_slice(&nonce2_bytes[..usize::from(job.nonce2_size)]);

    let mut merkle_root = double_sha256(&patched_coinbase);
    for branch in job.merkle_branches {
        let mut pair = [0_u8; 64];
        pair[..32].copy_from_slice(&merkle_root);
        pair[32..].copy_from_slice(branch);
        merkle_root = double_sha256(&pair);
    }

    let mut frame = [0_u8; BM1489_L7_WORK_FRAME_LEN];
    frame[..2].copy_from_slice(&BM1489_L7_WORK_HEADER);
    frame[2] = BM1489_L7_WORK_COMMAND;
    frame[3] = job.work_id;
    frame[4..8].copy_from_slice(&job.version.to_le_bytes());
    frame[8..40].copy_from_slice(&job.previous_hash_wire);
    for (wire_word, digest_word) in frame[40..72]
        .chunks_exact_mut(4)
        .zip(merkle_root.chunks_exact(4))
    {
        wire_word.copy_from_slice(&[
            digest_word[3],
            digest_word[2],
            digest_word[1],
            digest_word[0],
        ]);
    }
    frame[72..76].copy_from_slice(&job.nbits.to_le_bytes());
    frame[76..80].copy_from_slice(&job.ntime.to_le_bytes());
    frame[80..84].copy_from_slice(&BM1489_L7_WORK_START_NONCE.to_le_bytes());
    let crc_end = BM1489_L7_WORK_CRC_OFFSET + BM1489_L7_WORK_CRC_INPUT_LEN;
    let crc = bm1489_l7_crc16_ccitt_false(&frame[BM1489_L7_WORK_CRC_OFFSET..crc_end]);
    frame[84..86].copy_from_slice(&crc.to_be_bytes());

    let snapshot = Bm1489L7WorkSnapshot {
        word_04: job.version,
        word_08: job.nonce2 as u32,
        word_0c: (job.nonce2 >> 32) as u32,
        word_10: job.job_id,
    };
    let publication_steps =
        bm1489_l7_stock_work_publication_steps(job.work_id, snapshot).map_err(|_| {
            Bm1489L7WorkBuildError::InvalidWorkId {
                work_id: job.work_id,
            }
        })?;
    let next_work_id = bm1489_l7_stock_next_work_id(job.work_id).map_err(|_| {
        Bm1489L7WorkBuildError::InvalidWorkId {
            work_id: job.work_id,
        }
    })?;

    Ok(Bm1489L7WorkPlan {
        frame,
        merkle_root,
        snapshot,
        publication_steps,
        next_work_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_job<'a>(
        coinbase: &'a [u8],
        branches: &'a [[u8; BM1489_L7_MERKLE_BRANCH_LEN]],
    ) -> Bm1489L7WorkJob<'a> {
        let mut previous_hash_wire = [0_u8; 32];
        for (byte, value) in previous_hash_wire.iter_mut().zip(0_u8..) {
            *byte = value;
        }
        Bm1489L7WorkJob {
            work_id: 1,
            job_id: 0x1122_3344,
            version: 0x2000_0000,
            previous_hash_wire,
            coinbase,
            nonce2_offset: 2,
            nonce2_size: 4,
            nonce2: 0x0102_0304_0506_0708,
            merkle_branches: branches,
            nbits: 0x1d00_ffff,
            ntime: 0x05f5_e100,
        }
    }

    #[test]
    fn crc_matches_canonical_ccitt_false_vector() {
        assert_eq!(bm1489_l7_crc16_ccitt_false(b"123456789"), 0x29b1);
    }

    #[test]
    fn exact_work_frame_merkle_snapshot_and_publication_match_golden() {
        let coinbase = [0_u8; 10];
        let branches = [[0x11_u8; 32], [0x22_u8; 32]];
        let plan = bm1489_l7_plan_work(golden_job(&coinbase, &branches)).unwrap();
        let expected_frame = [
            0x55, 0xaa, 0x20, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x75, 0xac,
            0x75, 0xde, 0x4d, 0xe3, 0x46, 0x91, 0x2b, 0x38, 0x8b, 0xde, 0xe4, 0x85, 0xfc, 0x76,
            0x07, 0xd0, 0xae, 0x17, 0xa8, 0x71, 0xc1, 0x34, 0x1f, 0x44, 0x17, 0x04, 0xa9, 0x0f,
            0xdb, 0x79, 0xff, 0xff, 0x00, 0x1d, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
            0x39, 0x28,
        ];
        assert_eq!(plan.frame, expected_frame);
        assert_eq!(
            plan.merkle_root,
            [
                0xde, 0x75, 0xac, 0x75, 0x91, 0x46, 0xe3, 0x4d, 0xde, 0x8b, 0x38, 0x2b, 0x76, 0xfc,
                0x85, 0xe4, 0x17, 0xae, 0xd0, 0x07, 0x34, 0xc1, 0x71, 0xa8, 0x04, 0x17, 0x44, 0x1f,
                0x79, 0xdb, 0x0f, 0xa9,
            ]
        );
        assert_eq!(
            plan.snapshot,
            Bm1489L7WorkSnapshot {
                word_04: 0x2000_0000,
                word_08: 0x0506_0708,
                word_0c: 0x0102_0304,
                word_10: 0x1122_3344,
            }
        );
        assert_eq!(plan.next_work_id, 2);
        assert_eq!(
            plan.publication_steps[8],
            Bm1489L7WorkPublicationStep::SendSerialWorkFrame { length: 0x56 }
        );
        assert!(!plan.authorizes_live_io());
        assert!(!plan.authorizes_dispatch());
        assert!(!plan.authorizes_share_submission());
    }

    #[test]
    fn work_id_and_nonce2_bounds_fail_closed() {
        let coinbase = [0_u8; 10];
        let branches = [];
        for work_id in [0, 0x80, 0xff] {
            let mut job = golden_job(&coinbase, &branches);
            job.work_id = work_id;
            assert_eq!(
                bm1489_l7_plan_work(job),
                Err(Bm1489L7WorkBuildError::InvalidWorkId { work_id })
            );
        }

        let mut too_large = golden_job(&coinbase, &branches);
        too_large.nonce2_size = 9;
        assert_eq!(
            bm1489_l7_plan_work(too_large),
            Err(Bm1489L7WorkBuildError::Nonce2TooLarge { size: 9 })
        );

        let mut overflow = golden_job(&coinbase, &branches);
        overflow.nonce2_offset = usize::MAX;
        assert_eq!(
            bm1489_l7_plan_work(overflow),
            Err(Bm1489L7WorkBuildError::Nonce2RangeOverflow)
        );

        let mut outside = golden_job(&coinbase, &branches);
        outside.nonce2_offset = 8;
        assert_eq!(
            bm1489_l7_plan_work(outside),
            Err(Bm1489L7WorkBuildError::Nonce2OutsideCoinbase {
                offset: 8,
                size: 4,
                coinbase_len: 10,
            })
        );
    }

    #[test]
    fn zero_length_nonce2_at_coinbase_end_is_valid_and_last_id_wraps() {
        let coinbase = [0x5a_u8; 3];
        let branches = [];
        let mut job = golden_job(&coinbase, &branches);
        job.work_id = BM1489_L7_STOCK_LAST_WORK_ID;
        job.nonce2_offset = coinbase.len();
        job.nonce2_size = 0;
        let plan = bm1489_l7_plan_work(job).unwrap();
        assert_eq!(plan.next_work_id, BM1489_L7_STOCK_FIRST_WORK_ID);
        assert_eq!(plan.merkle_root, double_sha256(&coinbase));
    }

    #[test]
    fn merkle_branch_order_is_load_bearing() {
        let coinbase = [0_u8; 10];
        let forward = [[0x11_u8; 32], [0x22_u8; 32]];
        let reverse = [[0x22_u8; 32], [0x11_u8; 32]];
        let forward_plan = bm1489_l7_plan_work(golden_job(&coinbase, &forward)).unwrap();
        let reverse_plan = bm1489_l7_plan_work(golden_job(&coinbase, &reverse)).unwrap();
        assert_ne!(forward_plan.merkle_root, reverse_plan.merkle_root);
        assert_ne!(&forward_plan.frame[40..72], &reverse_plan.frame[40..72]);
    }

    #[test]
    fn authority_and_reuse_barrier_remain_closed() {
        assert!(BM1489_L7_WORK_FRAME_RECOVERED);
        assert!(BM1489_L7_WORK_MERKLE_DERIVATION_RECOVERED);
        assert!(!BM1489_L7_WORK_PREVIOUS_HASH_PROVENANCE_AUTHENTICATED);
        assert!(!BM1489_L7_WORK_ID_REUSE_BARRIER_RECOVERED);
        assert!(!BM1489_L7_WORK_AUTHORIZES_LIVE_IO);
        assert!(!BM1489_L7_WORK_AUTHORIZES_DISPATCH);
        assert!(!BM1489_L7_WORK_AUTHORIZES_SHARE_SUBMISSION);
    }
}
