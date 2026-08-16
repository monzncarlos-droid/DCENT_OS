//! Host-testable BM1396 userspace-to-FPGA register facts recovered from the
//! exact signed S17e/T17e production miners.
//!
//! Names stay observational where the binaries prove dispatch shape but not a
//! complete semantic payload contract. This module performs no MMIO.

pub const BM1396_FPGA_WORK_READY_OFFSET: u32 = 0x0c;
pub const BM1396_FPGA_RETURN_WORD1_OFFSET: u32 = 0x10;
pub const BM1396_FPGA_RETURN_WORD2_OFFSET: u32 = 0x14;
pub const BM1396_FPGA_RETURN_COUNT_OFFSET: u32 = 0x18;
pub const BM1396_FPGA_RETURN_CONTROL_OFFSET: u32 = 0x1c;
pub const BM1396_FPGA_BC_COMMAND_OFFSET: u32 = 0xc0;
pub const BM1396_FPGA_TICKET_DIFFICULTY_OFFSET: u32 = 0x8c;
pub const BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET: u32 = 0x100;
pub const BM1396_FPGA_JOB_COINBASE_LAYOUT_OFFSET: u32 = 0x104;
pub const BM1396_FPGA_JOB_NONCE2_LOW_OFFSET: u32 = 0x108;
pub const BM1396_FPGA_JOB_NONCE2_HIGH_OFFSET: u32 = 0x10c;
/// Physical base of the FPGA-produced 15-bit-work-ID table. In all four held
/// S17e/T17e miners this is published before the initial job-buffer address.
pub const BM1396_FPGA_OUTSTANDING_TABLE_BASE_OFFSET: u32 = 0x110;
pub const BM1396_FPGA_JOB_MERKLE_COUNT_OFFSET: u32 = 0x114;
pub const BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET: u32 = 0x118;
pub const BM1396_FPGA_JOB_PAYLOAD_END_OFFSET: u32 = 0x11c;
pub const BM1396_FPGA_JOB_ID_OFFSET: u32 = 0x124;
pub const BM1396_FPGA_JOB_BLOCK_VERSION_OFFSET: u32 = 0x130;
pub const BM1396_FPGA_JOB_NTIME_OFFSET: u32 = 0x134;
pub const BM1396_FPGA_JOB_NBITS_OFFSET: u32 = 0x138;
pub const BM1396_FPGA_JOB_PREVIOUS_HASH_BASE_OFFSET: u32 = 0x140;
pub const BM1396_FPGA_JOB_PREVIOUS_HASH_WORDS: u8 = 8;
pub const BM1396_FPGA_JOB_BUFFER_A_OFFSET: u32 = 0x20_0000;
pub const BM1396_FPGA_JOB_BUFFER_B_OFFSET: u32 = 0x21_0000;
pub const BM1396_FPGA_VERSION_LANE_1_OFFSET: u32 = 0x164;
pub const BM1396_FPGA_VERSION_LANE_2_OFFSET: u32 = 0x168;
pub const BM1396_FPGA_VERSION_LANE_3_OFFSET: u32 = 0x16c;
pub const BM1396_FPGA_VERSION_LANE_4_OFFSET: u32 = 0x470;
pub const BM1396_FPGA_VERSION_LANE_5_OFFSET: u32 = 0x474;
pub const BM1396_FPGA_VERSION_LANE_6_OFFSET: u32 = 0x478;
pub const BM1396_FPGA_VERSION_LANE_7_OFFSET: u32 = 0x47c;

pub const BM1396_FPGA_RETURN_ENABLE_BIT: u32 = 1 << 16;
pub const BM1396_FPGA_RETURN_COUNT_MASK: u32 = 0x01ff;
pub const BM1396_FPGA_TWO_WORD_RECORD_MARKER: u32 = 0x5555_aaaa;
pub const BM1396_FPGA_RETURN_WORD1_DISPATCH_BIT: u32 = 1 << 31;

pub const BM1396_FPGA_WORK_READY_MAX_POLLS: u16 = 3_000;
pub const BM1396_FPGA_WORK_READY_DELAY_CALL_VALUE: u32 = 1_000;
pub const BM1396_FPGA_BC_COMMAND_MAX_POLLS: u16 = 0x0bb9;
pub const BM1396_FPGA_BC_COMMAND_POLL_SLEEP_US: u32 = 1_000;
pub const BM1396_FPGA_SINGLE_COUNT_REASSERT_OBSERVATIONS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396ReturnFifoStatus {
    pub raw_count: u16,
    pub complete_record_count: u16,
    pub single_word_stuck_observation: bool,
}

/// Decode the exact low-nine-bit return FIFO count convention.
pub const fn bm1396_return_fifo_status(register_value: u32) -> Bm1396ReturnFifoStatus {
    let raw_count = (register_value & BM1396_FPGA_RETURN_COUNT_MASK) as u16;
    Bm1396ReturnFifoStatus {
        raw_count,
        complete_record_count: if raw_count > 1 { raw_count >> 1 } else { 0 },
        single_word_stuck_observation: raw_count == 1,
    }
}

/// A return record is two words only when word 2 is the exact marker;
/// otherwise the reader immediately consumes a second word pair.
pub const fn bm1396_return_record_word_count(word2: u32) -> u8 {
    if word2 == BM1396_FPGA_TWO_WORD_RECORD_MARKER {
        2
    } else {
        4
    }
}

/// Exact bit-31 handler split recovered through both handler bodies and their
/// log/queue xrefs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396ReturnDispatch {
    Nonce,
    Register,
}

pub const fn bm1396_return_dispatch(word1: u32) -> Bm1396ReturnDispatch {
    if word1 & BM1396_FPGA_RETURN_WORD1_DISPATCH_BIT != 0 {
        Bm1396ReturnDispatch::Nonce
    } else {
        Bm1396ReturnDispatch::Register
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396VersionLaneMode {
    One,
    Two,
    Four,
    Eight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1396FpgaRegisterWrite {
    pub offset: u32,
    pub value: u32,
}

/// Exact base-version and mode-tagged mirror writes. The runtime mode is an
/// explicit input; it must not be inferred from an unvalidated packet field.
pub fn bm1396_version_lane_writes(
    block_version: u32,
    mode: Bm1396VersionLaneMode,
) -> Vec<Bm1396FpgaRegisterWrite> {
    let mut writes = vec![Bm1396FpgaRegisterWrite {
        offset: BM1396_FPGA_JOB_BLOCK_VERSION_OFFSET,
        value: block_version,
    }];
    let mirrors = [
        (BM1396_FPGA_VERSION_LANE_1_OFFSET, 0x0000_4000),
        (BM1396_FPGA_VERSION_LANE_2_OFFSET, 0x0000_8000),
        (BM1396_FPGA_VERSION_LANE_3_OFFSET, 0x0000_c000),
        (BM1396_FPGA_VERSION_LANE_4_OFFSET, 0x0000_2000),
        (BM1396_FPGA_VERSION_LANE_5_OFFSET, 0x0000_6000),
        (BM1396_FPGA_VERSION_LANE_6_OFFSET, 0x0000_a000),
        (BM1396_FPGA_VERSION_LANE_7_OFFSET, 0x0000_e000),
    ];
    let mirror_count = match mode {
        Bm1396VersionLaneMode::One => 0,
        Bm1396VersionLaneMode::Two => 1,
        Bm1396VersionLaneMode::Four => 3,
        Bm1396VersionLaneMode::Eight => 7,
    };
    writes.extend(
        mirrors[..mirror_count]
            .iter()
            .map(|(offset, tag)| Bm1396FpgaRegisterWrite {
                offset: *offset,
                value: block_version | *tag,
            }),
    );
    writes
}

/// RMW value used to enable/recover the return path.
pub const fn bm1396_return_control_enable(old_value: u32) -> u32 {
    old_value | BM1396_FPGA_RETURN_ENABLE_BIT
}

/// Whether the exact stuck-count path reasserts return enable after the
/// required repeated single-count observations.
pub const fn bm1396_should_reassert_return_enable(
    raw_count: u16,
    consecutive_single_count_observations: u8,
) -> bool {
    raw_count == 1
        && consecutive_single_count_observations >= BM1396_FPGA_SINGLE_COUNT_REASSERT_OBSERVATIONS
}

/// Test one chain's work-FIFO ready bit. The exact miners expose 16 slots.
pub const fn bm1396_work_fifo_ready(status: u32, chain_slot: u8) -> Option<bool> {
    if chain_slot >= 16 {
        return None;
    }
    Some(status & (1u32 << chain_slot) != 0)
}

/// Negative BC command words use the completion-poll path; nonnegative words
/// receive one readback only.
pub const fn bm1396_bc_command_requires_completion_poll(command: u32) -> bool {
    command & (1 << 31) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_fifo_count_shape_and_dispatch_are_exact() {
        assert_eq!(
            bm1396_return_fifo_status(0xffff_fe01),
            Bm1396ReturnFifoStatus {
                raw_count: 1,
                complete_record_count: 0,
                single_word_stuck_observation: true,
            }
        );
        assert_eq!(bm1396_return_fifo_status(6).complete_record_count, 3);
        assert_eq!(bm1396_return_fifo_status(7).complete_record_count, 3);
        assert_eq!(bm1396_return_record_word_count(0x5555_aaaa), 2);
        assert_eq!(bm1396_return_record_word_count(0x5555_aaab), 4);
        assert_eq!(
            bm1396_return_dispatch(0x8000_0000),
            Bm1396ReturnDispatch::Nonce
        );
        assert_eq!(
            bm1396_return_dispatch(0x7fff_ffff),
            Bm1396ReturnDispatch::Register
        );
        assert_eq!(bm1396_return_control_enable(0x1234), 0x0001_1234);
        assert!(!bm1396_should_reassert_return_enable(1, 1));
        assert!(bm1396_should_reassert_return_enable(1, 2));
        assert!(!bm1396_should_reassert_return_enable(2, 2));
    }

    #[test]
    fn work_ready_and_bc_poll_policies_are_bounded() {
        assert_eq!(bm1396_work_fifo_ready(1 << 5, 5), Some(true));
        assert_eq!(bm1396_work_fifo_ready(1 << 5, 4), Some(false));
        assert_eq!(bm1396_work_fifo_ready(u32::MAX, 16), None);
        assert_eq!(BM1396_FPGA_WORK_READY_MAX_POLLS, 3_000);
        assert_eq!(BM1396_FPGA_WORK_READY_DELAY_CALL_VALUE, 1_000);
        assert_eq!(BM1396_FPGA_BC_COMMAND_MAX_POLLS, 0x0bb9);
        assert_eq!(BM1396_FPGA_BC_COMMAND_POLL_SLEEP_US, 1_000);
        assert!(!bm1396_bc_command_requires_completion_poll(0x7fff_ffff));
        assert!(bm1396_bc_command_requires_completion_poll(0x8000_0000));
        assert_eq!(BM1396_FPGA_JOB_BUFFER_A_OFFSET, 0x20_0000);
        assert_eq!(BM1396_FPGA_JOB_BUFFER_B_OFFSET, 0x21_0000);
        assert_eq!(BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET, 0x118);
        assert_eq!(BM1396_FPGA_JOB_PREVIOUS_HASH_BASE_OFFSET, 0x140);
        assert_eq!(BM1396_FPGA_JOB_PREVIOUS_HASH_WORDS, 8);

        assert_eq!(
            bm1396_version_lane_writes(0x2000_0000, Bm1396VersionLaneMode::Four),
            [
                Bm1396FpgaRegisterWrite {
                    offset: 0x130,
                    value: 0x2000_0000,
                },
                Bm1396FpgaRegisterWrite {
                    offset: 0x164,
                    value: 0x2000_4000,
                },
                Bm1396FpgaRegisterWrite {
                    offset: 0x168,
                    value: 0x2000_8000,
                },
                Bm1396FpgaRegisterWrite {
                    offset: 0x16c,
                    value: 0x2000_c000,
                },
            ]
        );
        let eight = bm1396_version_lane_writes(0x2000_0000, Bm1396VersionLaneMode::Eight);
        assert_eq!(eight.len(), 8);
        assert_eq!(eight[7].offset, 0x47c);
        assert_eq!(eight[7].value, 0x2000_e000);
    }
}
