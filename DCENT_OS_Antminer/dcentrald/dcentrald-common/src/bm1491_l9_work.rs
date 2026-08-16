//! Exact held-release L9 BM1491 work-frame and nonce-return pure contract.
//!
//! Recovered from the symbol-bearing `godminer` in the held signed
//! `FR-1.19(260302-L9).bmu` image. This module reproduces supplied bytes and
//! stock decision predicates only. It performs no I/O and grants no carrier,
//! work-dispatch, snapshot-binding, share-submission, or pool-acceptance
//! authority.

use crate::stock_fpga_policy::stock_bitmain_crc5;

pub const BM1491_L9_BMU_SHA256: &str =
    "2af05a3465ae8f3bdb32a74058f8beb0c4f9246da409441e09d922f05c3aa827";
pub const BM1491_L9_BMU_SIZE: u32 = 29_910_998;
pub const BM1491_L9_CVCTRL_COMPONENT_SHA256: &str =
    "4c997d2e20027827bda5262248d7877a34f145d7dcd700a7fc103f003b3dd1f3";
pub const BM1491_L9_GODMINER_SHA256: &str =
    "7b088dcb42a57f021a8448f27dcadbfef6f4c4e71652ac871393e9f73c038487";
pub const BM1491_L9_GODMINER_SIZE: u32 = 2_807_036;

pub const BM1491_L9_WORK_TO_PACKET_ADDRESS: u32 = 0x000f_57c8;
pub const BM1491_L9_PACKET_TO_NONCE_ADDRESS: u32 = 0x000f_60a0;
pub const BM1491_L9_CHECK_NONCE_ADDRESS: u32 = 0x000f_8c4c;
pub const BM1491_L9_CRC16_ADDRESS: u32 = 0x0018_825c;
pub const BM1491_L9_CRC5_ADDRESS: u32 = 0x0018_8368;

pub const BM1491_L9_WORK_HEADER: [u8; 2] = [0x55, 0xaa];
pub const BM1491_L9_WORK_BASE_MODE: u8 = 0x20;
pub const BM1491_L9_WORK_MODE_FLAG_ONE_BIT: u8 = 0x10;
pub const BM1491_L9_WORK_HEADER_LEN: usize = 80;
pub const BM1491_L9_WORK_FRAME_LEN: usize = 0x56;
pub const BM1491_L9_WORK_CRC_OFFSET: usize = 0x54;
pub const BM1491_L9_WORK_CRC_SPAN: usize = 0x52;
pub const BM1491_L9_WORK_SLOT_COUNT: u8 = 0x80;
pub const BM1491_L9_WORK_SLOT_MASK: u8 = 0x7f;

pub const BM1491_L9_RETURN_RECORD_LEN: usize = 10;
pub const BM1491_L9_RETURN_CANDIDATE_FLAG: u8 = 0x80;
pub const BM1491_L9_RETURN_CRC5_MASK: u8 = 0x1f;
pub const BM1491_L9_RETURN_CRC5_BITS: usize = 0x3b;
pub const BM1491_L9_STATUS_SELECTOR_ZERO: u8 = 0;
pub const BM1491_L9_STATUS_SELECTOR_NINETY: u8 = 0x90;

pub const BM1491_L9_CHAIN_COUNT: u8 = 3;
pub const BM1491_L9_CHIPS_PER_CHAIN: u8 = 110;
pub const BM1491_L9_ASIC_ADDRESS_INTERVAL: u8 = 2;

pub const BM1491_L9_MIN_CALCULATED_DIFFICULTY: u8 = 0x1c;
pub const BM1491_L9_ANSWER_DIFFICULTY_OFFSET: u8 = 0x10;
pub const BM1491_L9_ANSWER_DIFFICULTY_EXTENDED_BIT: u8 = 0x20;
pub const BM1491_L9_MIN_EXTENDED_DIFFICULTY: u8 = 0x30;

pub const BM1491_L9_PHYSICAL_RETURN_PATH_PROVEN: bool = false;
pub const BM1491_L9_WORK_SLOT_REUSE_BARRIER_RECOVERED: bool = false;
pub const BM1491_L9_LIVE_CARRIER_AUTHORITY: bool = false;
pub const BM1491_L9_WORK_DISPATCH_AUTHORITY: bool = false;
pub const BM1491_L9_SHARE_SUBMISSION_AUTHORITY: bool = false;
pub const BM1491_L9_POOL_ACCEPTANCE_AUTHORITY: bool = false;

/// Exact CRC-16/CCITT-FALSE used by `BM_CRC16`: poly 0x1021, initial 0xffff,
/// no reflection, and no final xor.
pub fn bm1491_l9_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in data {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9WorkFrame {
    pub bytes: [u8; BM1491_L9_WORK_FRAME_LEN],
    pub issued_work_slot: u8,
    pub next_work_slot: u8,
    /// Stock reverses the caller's 80-byte header in place. The clean builder
    /// preserves the input and reports the divergence explicitly.
    pub stock_mutated_input_header: bool,
}

impl Bm1491L9WorkFrame {
    pub const fn admits_live_carrier_authority(&self) -> bool {
        false
    }

    pub const fn admits_work_dispatch_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9WorkFrameError {
    InvalidWorkSlot { observed: u8 },
}

/// Build the exact 86-byte stock serial work frame without mutating `header`.
///
/// `mode_flag_is_one` is deliberately observational: it corresponds to the
/// stock context word at `+0x21c` being exactly one. Its higher-level meaning
/// and a live transport route are not inferred here.
#[allow(clippy::indexing_slicing)]
pub fn bm1491_l9_build_work_frame(
    header: &[u8; BM1491_L9_WORK_HEADER_LEN],
    current_work_slot: u8,
    mode_flag_is_one: bool,
) -> Result<Bm1491L9WorkFrame, Bm1491L9WorkFrameError> {
    if current_work_slot >= BM1491_L9_WORK_SLOT_COUNT {
        return Err(Bm1491L9WorkFrameError::InvalidWorkSlot {
            observed: current_work_slot,
        });
    }

    let mut bytes = [0_u8; BM1491_L9_WORK_FRAME_LEN];
    bytes[0..2].copy_from_slice(&BM1491_L9_WORK_HEADER);
    bytes[2] = BM1491_L9_WORK_BASE_MODE
        | if mode_flag_is_one {
            BM1491_L9_WORK_MODE_FLAG_ONE_BIT
        } else {
            0
        };
    bytes[3] = current_work_slot;

    // Stock reverses all 80 input bytes, copies reversed bytes 4..79 to frame
    // 4..79, then places reversed bytes 0..3 at frame 80..83.
    for (output, input) in bytes[4..80].iter_mut().zip(header[0..76].iter().rev()) {
        *output = *input;
    }
    for (output, input) in bytes[80..84].iter_mut().zip(header[76..80].iter().rev()) {
        *output = *input;
    }

    let crc = bm1491_l9_crc16(&bytes[2..84]);
    bytes[BM1491_L9_WORK_CRC_OFFSET..BM1491_L9_WORK_FRAME_LEN].copy_from_slice(&crc.to_be_bytes());

    Ok(Bm1491L9WorkFrame {
        bytes,
        issued_work_slot: current_work_slot,
        next_work_slot: current_work_slot.wrapping_add(1) & BM1491_L9_WORK_SLOT_MASK,
        stock_mutated_input_header: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9StatusClass {
    SelectorZero,
    SelectorNinety,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1491L9NonceCandidate {
    /// Native unaligned ARM load from return bytes 3..6.
    pub nonce: u32,
    /// Return byte four, divided by the configured address interval by stock.
    pub raw_chip_address: u8,
    /// Return byte seven, used by `check_nonce_ltc`'s difficulty gate.
    pub answer_difficulty: u8,
    pub work_slot: u8,
    pub flags: u8,
    pub crc5: u8,
}

impl Bm1491L9NonceCandidate {
    pub const fn admits_share_submission_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ReturnRecord {
    Status {
        selector: u8,
        class: Bm1491L9StatusClass,
    },
    Candidate(Bm1491L9NonceCandidate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ReturnDecodeError {
    WrongLength { actual: usize },
    CrcMismatch { observed: u8, expected: u8 },
}

/// Decode the exact ten-byte input prefix consumed by `packet_2_nonce_ltc`.
///
/// Stock checks CRC5 only when return byte nine has bit seven set. Bit-seven-
/// clear records are status traffic and are classified without CRC rejection.
pub fn bm1491_l9_decode_return_record(
    record: &[u8],
) -> Result<Bm1491L9ReturnRecord, Bm1491L9ReturnDecodeError> {
    let record: &[u8; BM1491_L9_RETURN_RECORD_LEN] =
        record
            .try_into()
            .map_err(|_| Bm1491L9ReturnDecodeError::WrongLength {
                actual: record.len(),
            })?;
    let [_, _, crc_prefix, nonce_0, nonce_1, nonce_2, nonce_3, answer_difficulty, work_slot, flags_crc] =
        *record;

    if flags_crc & BM1491_L9_RETURN_CANDIDATE_FLAG == 0 {
        let class = match work_slot {
            BM1491_L9_STATUS_SELECTOR_ZERO => Bm1491L9StatusClass::SelectorZero,
            BM1491_L9_STATUS_SELECTOR_NINETY => Bm1491L9StatusClass::SelectorNinety,
            other => Bm1491L9StatusClass::Other(other),
        };
        return Ok(Bm1491L9ReturnRecord::Status {
            selector: work_slot,
            class,
        });
    }

    let crc_input = [
        crc_prefix,
        nonce_0,
        nonce_1,
        nonce_2,
        nonce_3,
        answer_difficulty,
        work_slot,
        flags_crc,
    ];
    let expected = stock_bitmain_crc5(&crc_input, BM1491_L9_RETURN_CRC5_BITS);
    let observed = flags_crc & BM1491_L9_RETURN_CRC5_MASK;
    if observed != expected {
        return Err(Bm1491L9ReturnDecodeError::CrcMismatch { observed, expected });
    }

    Ok(Bm1491L9ReturnRecord::Candidate(Bm1491L9NonceCandidate {
        nonce: u32::from_le_bytes([nonce_0, nonce_1, nonce_2, nonce_3]),
        raw_chip_address: nonce_1,
        answer_difficulty,
        work_slot,
        flags: flags_crc & !BM1491_L9_RETURN_CRC5_MASK,
        crc5: observed,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9ChipIndexError {
    OutOfRange {
        raw_chip_address: u8,
        calculated_index: u8,
    },
}

/// Deterministic part of the held L9 decoder's address-to-index mapping.
/// Stock substitutes a random in-range index after an out-of-range quotient;
/// clean replay refuses that branch.
pub fn bm1491_l9_chip_index(raw_chip_address: u8) -> Result<u8, Bm1491L9ChipIndexError> {
    let index = raw_chip_address / BM1491_L9_ASIC_ADDRESS_INTERVAL;
    if index >= BM1491_L9_CHIPS_PER_CHAIN {
        return Err(Bm1491L9ChipIndexError::OutOfRange {
            raw_chip_address,
            calculated_index: index,
        });
    }
    Ok(index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1491L9NonceQualification {
    QualifiedStockCode0,
    BelowPoolTargetStockCode1,
    CalculatedDifficultyTooLowStockCode2,
    AnswerDifficultyMismatchStockCode3,
}

impl Bm1491L9NonceQualification {
    pub const fn admits_share_submission_authority(self) -> bool {
        false
    }

    pub const fn admits_pool_acceptance_authority(self) -> bool {
        false
    }
}

/// Exact little-endian-word 256-bit comparison used by `check_nonce_ltc`.
/// Equality qualifies; word seven is compared first and word zero last.
#[allow(clippy::indexing_slicing)]
pub fn bm1491_l9_digest_meets_target(digest: &[u8; 32], target: &[u8; 32]) -> bool {
    for word_index in (0..8).rev() {
        let offset = word_index * 4;
        let digest_word = u32::from_le_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let target_word = u32::from_le_bytes([
            target[offset],
            target[offset + 1],
            target[offset + 2],
            target[offset + 3],
        ]);
        if digest_word < target_word {
            return true;
        }
        if digest_word > target_word {
            return false;
        }
    }
    true
}

/// Replay the exact post-scrypt difficulty/target gates. `calculated_difficulty`
/// and `digest` are caller assertions: this helper does not perform scrypt or
/// authenticate the snapshot, target, work generation, or pool session.
pub fn bm1491_l9_qualify_replayed_nonce(
    calculated_difficulty: u8,
    answer_difficulty: u8,
    required_pool_difficulty: u32,
    digest: &[u8; 32],
    target: &[u8; 32],
) -> Bm1491L9NonceQualification {
    if calculated_difficulty < BM1491_L9_MIN_CALCULATED_DIFFICULTY {
        return Bm1491L9NonceQualification::CalculatedDifficultyTooLowStockCode2;
    }

    if answer_difficulty & BM1491_L9_ANSWER_DIFFICULTY_EXTENDED_BIT == 0 {
        if u16::from(calculated_difficulty)
            != u16::from(answer_difficulty) + u16::from(BM1491_L9_ANSWER_DIFFICULTY_OFFSET)
        {
            return Bm1491L9NonceQualification::AnswerDifficultyMismatchStockCode3;
        }
    } else if calculated_difficulty < BM1491_L9_MIN_EXTENDED_DIFFICULTY {
        return Bm1491L9NonceQualification::AnswerDifficultyMismatchStockCode3;
    }

    if u32::from(calculated_difficulty) >= required_pool_difficulty
        && bm1491_l9_digest_meets_target(digest, target)
    {
        Bm1491L9NonceQualification::QualifiedStockCode0
    } else {
        Bm1491L9NonceQualification::BelowPoolTargetStockCode1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccitt_crc_matches_standard_and_exact_frame_golden() {
        assert_eq!(bm1491_l9_crc16(b"123456789"), 0x29b1);

        let mut header = [0_u8; BM1491_L9_WORK_HEADER_LEN];
        for (value, byte) in (0_u8..80).zip(header.iter_mut()) {
            *byte = value;
        }
        let plan = bm1491_l9_build_work_frame(&header, 0x7f, true).unwrap();
        assert_eq!(&plan.bytes[..8], &[0x55, 0xaa, 0x30, 0x7f, 75, 74, 73, 72]);
        assert_eq!(
            &plan.bytes[76..86],
            &[3, 2, 1, 0, 79, 78, 77, 76, 0x30, 0x89]
        );
        assert_eq!(plan.next_work_slot, 0);
        assert_eq!(header[0], 0);
        assert_eq!(header[79], 79);
        assert!(plan.stock_mutated_input_header);
        assert!(!plan.admits_live_carrier_authority());
        assert!(!plan.admits_work_dispatch_authority());
    }

    #[test]
    fn frame_rejects_slots_outside_exact_seven_bit_state() {
        assert_eq!(
            bm1491_l9_build_work_frame(&[0; 80], 0x80, false),
            Err(Bm1491L9WorkFrameError::InvalidWorkSlot { observed: 0x80 })
        );
    }

    #[test]
    fn candidate_golden_decodes_unaligned_little_endian_nonce() {
        let record = [0x00, 0x00, 0x33, 0x78, 0x56, 0x34, 0x12, 0x0c, 0x7f, 0x97];
        assert_eq!(
            bm1491_l9_decode_return_record(&record),
            Ok(Bm1491L9ReturnRecord::Candidate(Bm1491L9NonceCandidate {
                nonce: 0x1234_5678,
                raw_chip_address: 0x56,
                answer_difficulty: 0x0c,
                work_slot: 0x7f,
                flags: 0x80,
                crc5: 0x17,
            }))
        );
    }

    #[test]
    fn candidate_crc_is_mandatory_but_status_crc_is_not_checked() {
        let mut bad_candidate = [0x00, 0x00, 0x33, 0x78, 0x56, 0x34, 0x12, 0x0c, 0x7f, 0x97];
        bad_candidate[9] ^= 1;
        assert!(matches!(
            bm1491_l9_decode_return_record(&bad_candidate),
            Err(Bm1491L9ReturnDecodeError::CrcMismatch { .. })
        ));

        let status = [0, 0, 0xff, 1, 2, 3, 4, 5, 0x90, 0x1f];
        assert_eq!(
            bm1491_l9_decode_return_record(&status),
            Ok(Bm1491L9ReturnRecord::Status {
                selector: 0x90,
                class: Bm1491L9StatusClass::SelectorNinety,
            })
        );
    }

    #[test]
    fn return_decoder_refuses_non_exact_lengths() {
        for length in [0, 9, 11] {
            let bytes = vec![0_u8; length];
            assert_eq!(
                bm1491_l9_decode_return_record(&bytes),
                Err(Bm1491L9ReturnDecodeError::WrongLength { actual: length })
            );
        }
    }

    #[test]
    fn chip_index_uses_interval_two_and_refuses_stock_random_fallback() {
        assert_eq!(bm1491_l9_chip_index(0), Ok(0));
        assert_eq!(bm1491_l9_chip_index(2), Ok(1));
        assert_eq!(bm1491_l9_chip_index(218), Ok(109));
        assert_eq!(
            bm1491_l9_chip_index(220),
            Err(Bm1491L9ChipIndexError::OutOfRange {
                raw_chip_address: 220,
                calculated_index: 110,
            })
        );
    }

    #[test]
    fn digest_target_compare_is_little_endian_word_major() {
        let equal = [0x55_u8; 32];
        assert!(bm1491_l9_digest_meets_target(&equal, &equal));

        let mut digest = [0_u8; 32];
        let mut target = [0_u8; 32];
        target[28] = 1;
        digest[0] = 0xff;
        assert!(bm1491_l9_digest_meets_target(&digest, &target));
        assert!(!bm1491_l9_digest_meets_target(&target, &digest));
    }

    #[test]
    fn exact_nonce_qualification_boundaries_are_pinned_without_authority() {
        let digest = [0_u8; 32];
        let target = [0xff_u8; 32];
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0x1b, 0x0c, 0x1c, &digest, &target),
            Bm1491L9NonceQualification::CalculatedDifficultyTooLowStockCode2
        );
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0x1c, 0x0c, 0x1c, &digest, &target),
            Bm1491L9NonceQualification::QualifiedStockCode0
        );
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0x1d, 0x0c, 0x1c, &digest, &target),
            Bm1491L9NonceQualification::AnswerDifficultyMismatchStockCode3
        );
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0x2f, 0x20, 0x1c, &digest, &target),
            Bm1491L9NonceQualification::AnswerDifficultyMismatchStockCode3
        );
        let qualified = bm1491_l9_qualify_replayed_nonce(0x30, 0x20, 0x30, &digest, &target);
        assert_eq!(qualified, Bm1491L9NonceQualification::QualifiedStockCode0);
        assert!(!qualified.admits_share_submission_authority());
        assert!(!qualified.admits_pool_acceptance_authority());
    }

    #[test]
    fn pool_difficulty_and_target_must_both_pass() {
        let digest = [0x10_u8; 32];
        let target = [0x0f_u8; 32];
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0x30, 0x20, 0x31, &digest, &[0xff; 32]),
            Bm1491L9NonceQualification::BelowPoolTargetStockCode1
        );
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0xff, 0x20, 0x100, &digest, &[0xff; 32]),
            Bm1491L9NonceQualification::BelowPoolTargetStockCode1
        );
        assert_eq!(
            bm1491_l9_qualify_replayed_nonce(0x30, 0x20, 0x30, &digest, &target),
            Bm1491L9NonceQualification::BelowPoolTargetStockCode1
        );
    }

    #[test]
    fn every_executable_authority_remains_false() {
        assert!(!BM1491_L9_PHYSICAL_RETURN_PATH_PROVEN);
        assert!(!BM1491_L9_WORK_SLOT_REUSE_BARRIER_RECOVERED);
        assert!(!BM1491_L9_LIVE_CARRIER_AUTHORITY);
        assert!(!BM1491_L9_WORK_DISPATCH_AUTHORITY);
        assert!(!BM1491_L9_SHARE_SUBMISSION_AUTHORITY);
        assert!(!BM1491_L9_POOL_ACCEPTANCE_AUTHORITY);
    }
}
