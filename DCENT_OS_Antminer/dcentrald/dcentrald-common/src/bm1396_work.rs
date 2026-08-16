//! Pure BM1396 work-packet and eight-byte FPGA return-record codecs.
//!
//! Recovered from exact signed 2020 S17e/T17e miners and cross-checked against
//! the 2019 S17e binary. The stock job function trusts lengths; this parser
//! adds checked bounds before exposing borrowed payload slices. Nonce address
//! alignment/range checks are also deliberate DCENT fail-closed hardening: the
//! stock decoder integer-divides first and only applies some later statistics
//! bounds.

use crate::bm1396_contract::Bm1396Model;
use crate::bm1396_fpga_abi::{
    bm1396_version_lane_writes, Bm1396FpgaRegisterWrite, Bm1396VersionLaneMode,
    BM1396_FPGA_JOB_BUFFER_A_OFFSET, BM1396_FPGA_JOB_BUFFER_B_OFFSET,
    BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET, BM1396_FPGA_JOB_COINBASE_LAYOUT_OFFSET,
    BM1396_FPGA_JOB_ID_OFFSET, BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
    BM1396_FPGA_JOB_MERKLE_COUNT_OFFSET, BM1396_FPGA_JOB_NBITS_OFFSET,
    BM1396_FPGA_JOB_NONCE2_HIGH_OFFSET, BM1396_FPGA_JOB_NONCE2_LOW_OFFSET,
    BM1396_FPGA_JOB_NTIME_OFFSET, BM1396_FPGA_JOB_PAYLOAD_END_OFFSET,
    BM1396_FPGA_JOB_PREVIOUS_HASH_BASE_OFFSET, BM1396_FPGA_RETURN_CONTROL_OFFSET,
    BM1396_FPGA_TICKET_DIFFICULTY_OFFSET,
};

pub const BM1396_RETURN_RECORD_LEN: usize = 8;
pub const BM1396_NONCE_VALID_BIT: u8 = 0x80;
pub const BM1396_RETURN_CRC_ERROR_BIT: u8 = 0x40;
pub const BM1396_RETURN_CHAIN_MASK: u8 = 0x0f;
pub const BM1396_WORK_ID_MASK: u16 = 0x7fff;
pub const BM1396_NONCE_CORE_SHIFT: u8 = 25;
pub const BM1396_NONCE_CHIP_ADDRESS_SHIFT: u8 = 17;
pub const BM1396_OUTSTANDING_WORK_RECORD_SIZE: usize = 0x40;
pub const BM1396_NONCE_QUEUE_CAPACITY: u16 = 511;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396NonceRecord {
    pub chain_slot: u8,
    pub work_id: u16,
    pub nonce: u32,
    pub core_id: u8,
    pub wire_chip_address: u8,
    pub chip_ordinal: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396NonceDecodeError {
    WrongLength { observed: usize },
    NotValid,
    FpgaCrcError,
    MisalignedWireAddress { address: u8, interval: u8 },
    ChipOrdinalOutOfRange { observed: u16, maximum: u16 },
}

pub fn bm1396_decode_nonce_record(
    model: Bm1396Model,
    record: &[u8],
) -> Result<Bm1396NonceRecord, Bm1396NonceDecodeError> {
    if record.len() != BM1396_RETURN_RECORD_LEN {
        return Err(Bm1396NonceDecodeError::WrongLength {
            observed: record.len(),
        });
    }
    if record[0] & BM1396_NONCE_VALID_BIT == 0 {
        return Err(Bm1396NonceDecodeError::NotValid);
    }
    if record[0] & BM1396_RETURN_CRC_ERROR_BIT != 0 {
        return Err(Bm1396NonceDecodeError::FpgaCrcError);
    }
    let work_id = u16::from_le_bytes([record[2], record[3]]) & BM1396_WORK_ID_MASK;
    let nonce = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);
    let wire_chip_address = ((nonce >> BM1396_NONCE_CHIP_ADDRESS_SHIFT) & 0xff) as u8;
    let interval = model.address_interval();
    if wire_chip_address % interval != 0 {
        return Err(Bm1396NonceDecodeError::MisalignedWireAddress {
            address: wire_chip_address,
            interval,
        });
    }
    let chip_ordinal = u16::from(wire_chip_address / interval);
    let maximum = model.expected_chips_per_present_chain();
    if chip_ordinal >= maximum {
        return Err(Bm1396NonceDecodeError::ChipOrdinalOutOfRange {
            observed: chip_ordinal,
            maximum,
        });
    }
    Ok(Bm1396NonceRecord {
        chain_slot: record[0] & BM1396_RETURN_CHAIN_MASK,
        work_id,
        nonce,
        core_id: ((nonce >> BM1396_NONCE_CORE_SHIFT) & 0x7f) as u8,
        wire_chip_address,
        chip_ordinal,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396RegisterRecord {
    pub chain_slot: u8,
    pub register: u8,
    pub chip_address: u8,
    pub crc5: u8,
    pub register_type: u8,
    pub value: u32,
}

impl Bm1396RegisterRecord {
    /// Type zero enters the stock normal path; it is necessary but not
    /// sufficient for queuing because callbacks and the register-0x40 gate may
    /// still consume/suppress the observation.
    pub const fn is_normal_path_type(self) -> bool {
        self.register_type == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396RegisterDecodeError {
    WrongLength { observed: usize },
    FpgaCrcError,
}

pub fn bm1396_decode_register_record(
    record: &[u8],
) -> Result<Bm1396RegisterRecord, Bm1396RegisterDecodeError> {
    if record.len() != BM1396_RETURN_RECORD_LEN {
        return Err(Bm1396RegisterDecodeError::WrongLength {
            observed: record.len(),
        });
    }
    if record[0] & BM1396_RETURN_CRC_ERROR_BIT != 0 {
        return Err(Bm1396RegisterDecodeError::FpgaCrcError);
    }
    Ok(Bm1396RegisterRecord {
        chain_slot: record[0] & BM1396_RETURN_CHAIN_MASK,
        register: record[1],
        chip_address: record[2],
        crc5: record[3] & 0x1f,
        register_type: (record[3] >> 5) & 0x03,
        value: u32::from_le_bytes([record[4], record[5], record[6], record[7]]),
    })
}

pub const BM1396_JOB_HEADER: u8 = 0x52;
pub const BM1396_JOB_FIXED_LEN: usize = 0x58;
pub const BM1396_MERKLE_BRANCH_LEN: usize = 32;
pub const BM1396_JOB_MAIN_CONTROL_BIT7_FLAG: u8 = 1;
pub const BM1396_JOB_TICKET_DIFFICULTY_FLAG: u8 = 1 << 1;
pub const BM1396_JOB_MAIN_CONTROL_CLEAR_MASK: u32 = 0x40;
pub const BM1396_JOB_MAIN_CONTROL_CLEAR_MAX_POLLS: u8 = 10;
pub const BM1396_JOB_DELAY_CALL_VALUE: u32 = 1;
pub const BM1396_JOB_FIRST_RETURN_ENABLE_MASK: u32 = 0x0001_0000;
pub const BM1396_JOB_MAIN_CONTROL_BIT7_MASK: u32 = 0x80;
pub const BM1396_JOB_TIMEOUT_CONTROL_OFFSET: u32 = 0x88;
pub const BM1396_JOB_FINAL_MAIN_PRESERVE_MASK: u32 = 0xffff_f0bf;
pub const BM1396_JOB_SINGLE_MODE_WORD: u32 = 0x8160;
pub const BM1396_JOB_MULTIVERSION_MODE_BASE: u32 = 0x8060;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396JobPacket<'a> {
    pub body_len: u32,
    pub flags: u8,
    pub ticket_difficulty: u8,
    pub job_id: u32,
    pub block_version: u32,
    pub previous_header_hash: [u8; 32],
    pub block_ntime: u32,
    pub nbits: u32,
    pub coinbase_len: u16,
    pub nonce2_offset: u16,
    pub nonce2_size: u8,
    pub merkle_branch_count: u16,
    pub nonce2_initial: u64,
    pub multiversion_enable: u8,
    pub multiversion_count: u32,
    pub coinbase: &'a [u8],
    pub merkle_branches: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396JobParseError {
    TooShort {
        observed: usize,
    },
    WrongHeader {
        observed: u8,
    },
    LengthOverflow,
    BodyLengthMismatch {
        declared_total: usize,
        observed: usize,
    },
    PayloadLengthOverflow,
    PayloadTruncated {
        required: usize,
        observed: usize,
    },
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

pub fn bm1396_parse_job_packet(data: &[u8]) -> Result<Bm1396JobPacket<'_>, Bm1396JobParseError> {
    if data.len() < BM1396_JOB_FIXED_LEN {
        return Err(Bm1396JobParseError::TooShort {
            observed: data.len(),
        });
    }
    if data[0] != BM1396_JOB_HEADER {
        return Err(Bm1396JobParseError::WrongHeader { observed: data[0] });
    }
    let body_len = read_u32_le(data, 0x04);
    let declared_total = usize::try_from(body_len)
        .ok()
        .and_then(|length| length.checked_add(8))
        .ok_or(Bm1396JobParseError::LengthOverflow)?;
    if declared_total != data.len() {
        return Err(Bm1396JobParseError::BodyLengthMismatch {
            declared_total,
            observed: data.len(),
        });
    }
    let coinbase_len = read_u16_le(data, 0x3c);
    let merkle_branch_count = read_u16_le(data, 0x42);
    let merkle_len = usize::from(merkle_branch_count)
        .checked_mul(BM1396_MERKLE_BRANCH_LEN)
        .ok_or(Bm1396JobParseError::PayloadLengthOverflow)?;
    let coinbase_end = BM1396_JOB_FIXED_LEN
        .checked_add(usize::from(coinbase_len))
        .ok_or(Bm1396JobParseError::PayloadLengthOverflow)?;
    let payload_end = coinbase_end
        .checked_add(merkle_len)
        .ok_or(Bm1396JobParseError::PayloadLengthOverflow)?;
    if payload_end > data.len() {
        return Err(Bm1396JobParseError::PayloadTruncated {
            required: payload_end,
            observed: data.len(),
        });
    }
    let mut previous_header_hash = [0u8; 32];
    previous_header_hash.copy_from_slice(&data[0x14..0x34]);
    Ok(Bm1396JobPacket {
        body_len,
        flags: data[0x09],
        ticket_difficulty: data[0x0a],
        job_id: read_u32_le(data, 0x0c),
        block_version: read_u32_le(data, 0x10),
        previous_header_hash,
        block_ntime: read_u32_le(data, 0x34),
        nbits: read_u32_le(data, 0x38),
        coinbase_len,
        nonce2_offset: read_u16_le(data, 0x3e),
        nonce2_size: data[0x40],
        merkle_branch_count,
        nonce2_initial: u64::from_le_bytes([
            data[0x48], data[0x49], data[0x4a], data[0x4b], data[0x4c], data[0x4d], data[0x4e],
            data[0x4f],
        ]),
        multiversion_enable: data[0x50],
        multiversion_count: read_u32_le(data, 0x54),
        coinbase: &data[BM1396_JOB_FIXED_LEN..coinbase_end],
        merkle_branches: &data[coinbase_end..payload_end],
    })
}

pub fn bm1396_sha256_pad_coinbase(coinbase: &[u8]) -> Option<Vec<u8>> {
    crate::sha256_padding::sha256_pad_message(coinbase)
}

/// Eight 32-bit previous-hash words constructed directly from each four-byte
/// packet chunk in native little-endian order before the raw FPGA writes.
pub fn bm1396_previous_hash_fpga_words(previous_hash: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (index, chunk) in previous_hash.chunks_exact(4).enumerate() {
        words[index] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// Bounded common register values and DDR payload for one stock-format job.
/// It deliberately performs no MMIO; [`bm1396_plan_ordered_job_dispatch`]
/// composes this value into the complete recovered hardware-facing DDR/MMIO
/// spine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396JobFpgaPlan {
    buffer_offset: u32,
    buffer_payload: Vec<u8>,
    padded_coinbase_len: usize,
    ticket_difficulty: Option<u8>,
    force_main_control_bit7: bool,
    multiversion_enable: bool,
    multiversion_count: u32,
    job_id: u32,
    block_version: u32,
    previous_hash_words: [u32; 8],
    block_ntime: u32,
    nbits: u32,
    coinbase_layout: u32,
    nonce2_low: u32,
    nonce2_high: u32,
    merkle_branch_count: u16,
    payload_end: u32,
}

impl Bm1396JobFpgaPlan {
    pub const fn buffer_offset(&self) -> u32 {
        self.buffer_offset
    }

    pub fn buffer_payload(&self) -> &[u8] {
        &self.buffer_payload
    }

    pub const fn ticket_difficulty(&self) -> Option<u8> {
        self.ticket_difficulty
    }

    pub const fn multiversion_enable(&self) -> bool {
        self.multiversion_enable
    }

    pub const fn multiversion_count(&self) -> u32 {
        self.multiversion_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396JobPlanError {
    InvalidBufferIndex {
        observed: u8,
    },
    InconsistentCoinbaseLength {
        declared: u16,
        observed: usize,
    },
    InconsistentMerkleLength {
        declared_count: u16,
        observed: usize,
    },
    CoinbasePaddingOverflow,
    CoinbaseBlockCountOverflow {
        observed: usize,
    },
    PayloadEndOverflow {
        observed: usize,
    },
}

/// Convert a checked host job into the exact software-visible FPGA fields.
///
/// The vendor path masks the payload end with `0xffe0`; clean-room code refuses
/// values that would be truncated instead of silently wrapping them. The limit
/// also stays within the 64-KiB stride inferred from the two exact buffer bases.
pub fn bm1396_plan_job_fpga(
    job: &Bm1396JobPacket<'_>,
    buffer_index: u8,
) -> Result<Bm1396JobFpgaPlan, Bm1396JobPlanError> {
    let buffer_offset = match buffer_index {
        0 => BM1396_FPGA_JOB_BUFFER_A_OFFSET,
        1 => BM1396_FPGA_JOB_BUFFER_B_OFFSET,
        observed => return Err(Bm1396JobPlanError::InvalidBufferIndex { observed }),
    };
    if usize::from(job.coinbase_len) != job.coinbase.len() {
        return Err(Bm1396JobPlanError::InconsistentCoinbaseLength {
            declared: job.coinbase_len,
            observed: job.coinbase.len(),
        });
    }
    let expected_merkle_len = usize::from(job.merkle_branch_count)
        .checked_mul(BM1396_MERKLE_BRANCH_LEN)
        .ok_or(Bm1396JobPlanError::InconsistentMerkleLength {
            declared_count: job.merkle_branch_count,
            observed: job.merkle_branches.len(),
        })?;
    if expected_merkle_len != job.merkle_branches.len() {
        return Err(Bm1396JobPlanError::InconsistentMerkleLength {
            declared_count: job.merkle_branch_count,
            observed: job.merkle_branches.len(),
        });
    }
    let padded_coinbase = bm1396_sha256_pad_coinbase(job.coinbase)
        .ok_or(Bm1396JobPlanError::CoinbasePaddingOverflow)?;
    let coinbase_blocks = padded_coinbase.len() / 64;
    if coinbase_blocks > usize::from(u8::MAX) {
        return Err(Bm1396JobPlanError::CoinbaseBlockCountOverflow {
            observed: coinbase_blocks,
        });
    }
    let payload_end = padded_coinbase
        .len()
        .checked_add(job.merkle_branches.len())
        .ok_or(Bm1396JobPlanError::PayloadEndOverflow {
            observed: usize::MAX,
        })?;
    if payload_end > 0xffe0 {
        return Err(Bm1396JobPlanError::PayloadEndOverflow {
            observed: payload_end,
        });
    }

    let mut buffer_payload = padded_coinbase;
    let padded_coinbase_len = buffer_payload.len();
    buffer_payload.extend_from_slice(job.merkle_branches);
    Ok(Bm1396JobFpgaPlan {
        buffer_offset,
        buffer_payload,
        padded_coinbase_len,
        ticket_difficulty: (job.flags & BM1396_JOB_TICKET_DIFFICULTY_FLAG != 0)
            .then_some(job.ticket_difficulty),
        force_main_control_bit7: job.flags & BM1396_JOB_MAIN_CONTROL_BIT7_FLAG != 0,
        multiversion_enable: job.multiversion_enable != 0,
        multiversion_count: job.multiversion_count,
        job_id: job.job_id,
        block_version: job.block_version,
        previous_hash_words: bm1396_previous_hash_fpga_words(&job.previous_header_hash),
        block_ntime: job.block_ntime,
        nbits: job.nbits,
        coinbase_layout: (u32::from(job.nonce2_offset) << 16)
            | (u32::from(job.nonce2_size) << 8)
            | coinbase_blocks as u32,
        nonce2_low: job.nonce2_initial as u32,
        nonce2_high: (job.nonce2_initial >> 32) as u32,
        merkle_branch_count: job.merkle_branch_count,
        payload_end: (payload_end as u32) & 0xffe0,
    })
}

/// Exact ordered scalar-write spine after the selected DDR buffer address is
/// published and before the stock one-unit settle call. Main-control and
/// buffer-ownership transitions are intentionally not represented here.
pub fn bm1396_job_scalar_writes(
    plan: &Bm1396JobFpgaPlan,
    version_mode: Bm1396VersionLaneMode,
) -> Vec<Bm1396FpgaRegisterWrite> {
    let mut writes = Vec::new();
    if let Some(value) = plan.ticket_difficulty {
        writes.push(Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_TICKET_DIFFICULTY_OFFSET,
            value: u32::from(value),
        });
    }
    writes.push(Bm1396FpgaRegisterWrite {
        offset: BM1396_FPGA_JOB_ID_OFFSET,
        value: plan.job_id,
    });
    writes.extend(bm1396_version_lane_writes(plan.block_version, version_mode));
    writes.extend(
        plan.previous_hash_words
            .iter()
            .enumerate()
            .map(|(index, value)| Bm1396FpgaRegisterWrite {
                offset: BM1396_FPGA_JOB_PREVIOUS_HASH_BASE_OFFSET + (index as u32 * 4),
                value: *value,
            }),
    );
    writes.extend([
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_NTIME_OFFSET,
            value: plan.block_ntime,
        },
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_NBITS_OFFSET,
            value: plan.nbits,
        },
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_COINBASE_LAYOUT_OFFSET,
            value: plan.coinbase_layout,
        },
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_NONCE2_LOW_OFFSET,
            value: plan.nonce2_low,
        },
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_NONCE2_HIGH_OFFSET,
            value: plan.nonce2_high,
        },
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_MERKLE_COUNT_OFFSET,
            value: u32::from(plan.merkle_branch_count),
        },
        Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_PAYLOAD_END_OFFSET,
            value: plan.payload_end,
        },
    ]);
    writes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396JobDispatchPlanError {
    MissingMultiversionEnable,
    UnsupportedMultiversionCount { observed: u32 },
    BufferAddressOverflow,
    TimeoutControlOverflow,
}

pub const fn bm1396_job_version_mode(
    plan: &Bm1396JobFpgaPlan,
    runtime_multiversion_enabled: bool,
) -> Result<Bm1396VersionLaneMode, Bm1396JobDispatchPlanError> {
    if !runtime_multiversion_enabled {
        return Ok(Bm1396VersionLaneMode::One);
    }
    if !plan.multiversion_enable {
        return Err(Bm1396JobDispatchPlanError::MissingMultiversionEnable);
    }
    match plan.multiversion_count {
        2 => Ok(Bm1396VersionLaneMode::Two),
        4 => Ok(Bm1396VersionLaneMode::Four),
        8 => Ok(Bm1396VersionLaneMode::Eight),
        observed => Err(Bm1396JobDispatchPlanError::UnsupportedMultiversionCount { observed }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1396OrderedJobOp {
    CopyDdrPayload {
        absolute_address: u32,
        payload_offset: usize,
        length: usize,
    },
    /// Stock reads back every padded-coinbase and merkle byte, logging a
    /// mismatch and continuing. A clean executor must fail closed instead.
    VerifyDdrPayload {
        absolute_address: u32,
        payload_offset: usize,
        length: usize,
    },
    RmwClear {
        offset: u32,
        clear_mask: u32,
    },
    /// DCENT requires observed clear or returns timeout. Stock merely logs
    /// after the tenth failed read and continues.
    RequireClear {
        offset: u32,
        clear_mask: u32,
        max_polls: u8,
        delay_call_value: u32,
    },
    WriteRegister(Bm1396FpgaRegisterWrite),
    DelayCall(u32),
    RmwSet {
        offset: u32,
        set_mask: u32,
    },
    RmwFinal {
        offset: u32,
        preserve_mask: u32,
        mode_word: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396OrderedJobPlan {
    buffer_payload: Vec<u8>,
    version_mode: Bm1396VersionLaneMode,
    ops: Vec<Bm1396OrderedJobOp>,
}

impl Bm1396OrderedJobPlan {
    pub fn buffer_payload(&self) -> &[u8] {
        &self.buffer_payload
    }

    pub const fn version_mode(&self) -> Bm1396VersionLaneMode {
        self.version_mode
    }

    pub fn ops(&self) -> &[Bm1396OrderedJobOp] {
        &self.ops
    }
}

/// Exact timeout-control field arithmetic with a DCENT fail-closed range check.
/// Signed S17e/T17e firmware stores a separately derived timeout base at the
/// runtime state object's `+0x4c`; it is not an ASIC-count field. Stock keeps
/// only bits 2..18 of the low-32-bit product. This clean planner refuses a
/// value that would require that truncation.
pub fn bm1396_job_timeout_control_value(
    timeout_base_word_0x4c: u32,
    effective_multiversion_count: u8,
) -> Result<u32, Bm1396JobDispatchPlanError> {
    let product = u64::from(timeout_base_word_0x4c)
        .checked_mul(u64::from(effective_multiversion_count))
        .ok_or(Bm1396JobDispatchPlanError::TimeoutControlOverflow)?;
    let scaled = product >> 2;
    if scaled > 0x1_ffff {
        return Err(Bm1396JobDispatchPlanError::TimeoutControlOverflow);
    }
    Ok(0x8000_0000 | scaled as u32)
}

/// Build the exact hardware-facing DDR/MMIO spine through the final
/// main-control RMW, with conservative refusal for unsupported multiversion
/// counts and fail-closed readback/control checks. Host wall-clock adjustment
/// and post-dispatch software synchronization are outside this hardware plan.
/// The returned value performs no I/O and grants no carrier authority.
pub fn bm1396_plan_ordered_job_dispatch(
    plan: &Bm1396JobFpgaPlan,
    external_memory_base: u32,
    runtime_multiversion_enabled: bool,
    first_job: bool,
    timeout_base_word_0x4c: u32,
) -> Result<Bm1396OrderedJobPlan, Bm1396JobDispatchPlanError> {
    let version_mode = bm1396_job_version_mode(plan, runtime_multiversion_enabled)?;
    let effective_count = match version_mode {
        Bm1396VersionLaneMode::One => 1,
        Bm1396VersionLaneMode::Two => 2,
        Bm1396VersionLaneMode::Four => 4,
        Bm1396VersionLaneMode::Eight => 8,
    };
    let absolute_address = external_memory_base
        .checked_add(plan.buffer_offset)
        .ok_or(Bm1396JobDispatchPlanError::BufferAddressOverflow)?;
    let _payload_end_address = absolute_address
        .checked_add(
            u32::try_from(plan.buffer_payload.len())
                .map_err(|_| Bm1396JobDispatchPlanError::BufferAddressOverflow)?,
        )
        .ok_or(Bm1396JobDispatchPlanError::BufferAddressOverflow)?;
    let timeout_control =
        bm1396_job_timeout_control_value(timeout_base_word_0x4c, effective_count)?;
    let mut ops = vec![
        Bm1396OrderedJobOp::CopyDdrPayload {
            absolute_address,
            payload_offset: 0,
            length: plan.padded_coinbase_len,
        },
        Bm1396OrderedJobOp::VerifyDdrPayload {
            absolute_address,
            payload_offset: 0,
            length: plan.padded_coinbase_len,
        },
    ];
    let merkle_len = plan.buffer_payload.len() - plan.padded_coinbase_len;
    if merkle_len != 0 {
        let merkle_address = absolute_address
            .checked_add(plan.padded_coinbase_len as u32)
            .ok_or(Bm1396JobDispatchPlanError::BufferAddressOverflow)?;
        ops.push(Bm1396OrderedJobOp::CopyDdrPayload {
            absolute_address: merkle_address,
            payload_offset: plan.padded_coinbase_len,
            length: merkle_len,
        });
        ops.push(Bm1396OrderedJobOp::VerifyDdrPayload {
            absolute_address: merkle_address,
            payload_offset: plan.padded_coinbase_len,
            length: merkle_len,
        });
    }
    ops.extend([
        Bm1396OrderedJobOp::RmwClear {
            offset: BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
            clear_mask: BM1396_JOB_MAIN_CONTROL_CLEAR_MASK,
        },
        Bm1396OrderedJobOp::RequireClear {
            offset: BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
            clear_mask: BM1396_JOB_MAIN_CONTROL_CLEAR_MASK,
            max_polls: BM1396_JOB_MAIN_CONTROL_CLEAR_MAX_POLLS,
            delay_call_value: BM1396_JOB_DELAY_CALL_VALUE,
        },
        Bm1396OrderedJobOp::WriteRegister(Bm1396FpgaRegisterWrite {
            offset: BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET,
            value: absolute_address,
        }),
    ]);
    ops.extend(
        bm1396_job_scalar_writes(plan, version_mode)
            .into_iter()
            .map(Bm1396OrderedJobOp::WriteRegister),
    );
    ops.push(Bm1396OrderedJobOp::DelayCall(BM1396_JOB_DELAY_CALL_VALUE));
    if first_job {
        ops.push(Bm1396OrderedJobOp::RmwSet {
            offset: BM1396_FPGA_RETURN_CONTROL_OFFSET,
            set_mask: BM1396_JOB_FIRST_RETURN_ENABLE_MASK,
        });
        ops.push(Bm1396OrderedJobOp::RmwSet {
            offset: BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
            set_mask: BM1396_JOB_MAIN_CONTROL_BIT7_MASK,
        });
    }
    ops.push(Bm1396OrderedJobOp::WriteRegister(Bm1396FpgaRegisterWrite {
        offset: BM1396_JOB_TIMEOUT_CONTROL_OFFSET,
        value: timeout_control,
    }));
    if plan.force_main_control_bit7 {
        ops.push(Bm1396OrderedJobOp::RmwSet {
            offset: BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
            set_mask: BM1396_JOB_MAIN_CONTROL_BIT7_MASK,
        });
    }
    let mode_word = match version_mode {
        Bm1396VersionLaneMode::One => BM1396_JOB_SINGLE_MODE_WORD,
        Bm1396VersionLaneMode::Two => BM1396_JOB_MULTIVERSION_MODE_BASE | (2 << 8),
        Bm1396VersionLaneMode::Four => BM1396_JOB_MULTIVERSION_MODE_BASE | (4 << 8),
        Bm1396VersionLaneMode::Eight => BM1396_JOB_MULTIVERSION_MODE_BASE | (8 << 8),
    };
    ops.push(Bm1396OrderedJobOp::RmwFinal {
        offset: BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
        preserve_mask: BM1396_JOB_FINAL_MAIN_PRESERVE_MASK,
        mode_word,
    });
    Ok(Bm1396OrderedJobPlan {
        buffer_payload: plan.buffer_payload.clone(),
        version_mode,
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout_and_model_addressing_are_exact_and_fail_closed() {
        let nonce = (0x12u32 << 25) | (231u32 << 17) | 0x12345;
        let mut record = [0u8; 8];
        record[0] = BM1396_NONCE_VALID_BIT | 3;
        record[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        record[4..8].copy_from_slice(&nonce.to_le_bytes());
        assert_eq!(
            bm1396_decode_nonce_record(Bm1396Model::T17e, &record),
            Ok(Bm1396NonceRecord {
                chain_slot: 3,
                work_id: 0x7fff,
                nonce,
                core_id: 0x12,
                wire_chip_address: 231,
                chip_ordinal: 77,
            })
        );
        record[0] |= BM1396_RETURN_CRC_ERROR_BIT;
        assert_eq!(
            bm1396_decode_nonce_record(Bm1396Model::T17e, &record),
            Err(Bm1396NonceDecodeError::FpgaCrcError)
        );
        record[0] = BM1396_NONCE_VALID_BIT;
        let misaligned = (230u32 << 17).to_le_bytes();
        record[4..8].copy_from_slice(&misaligned);
        assert!(matches!(
            bm1396_decode_nonce_record(Bm1396Model::T17e, &record),
            Err(Bm1396NonceDecodeError::MisalignedWireAddress { .. })
        ));
    }

    #[test]
    fn register_layout_keeps_reg_before_chip_and_does_not_invent_crc_recompute() {
        let record = [0x03, 0x18, 0xe7, 0x05, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            bm1396_decode_register_record(&record),
            Ok(Bm1396RegisterRecord {
                chain_slot: 3,
                register: 0x18,
                chip_address: 0xe7,
                crc5: 5,
                register_type: 0,
                value: 0x1234_5678,
            })
        );
        let diagnostic = [0x03, 0x18, 0xe7, 0x25, 0, 0, 0, 0];
        assert!(!bm1396_decode_register_record(&diagnostic)
            .unwrap()
            .is_normal_path_type());
    }

    fn sample_job() -> Vec<u8> {
        let coinbase = [0x11, 0x22, 0x33];
        let branch = [0x44u8; 32];
        let mut data = vec![0u8; BM1396_JOB_FIXED_LEN];
        data[0] = BM1396_JOB_HEADER;
        data[0x09] = 3;
        data[0x0a] = 7;
        data[0x0c..0x10].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        for (index, byte) in data[0x14..0x34].iter_mut().enumerate() {
            *byte = index as u8;
        }
        data[0x34..0x38].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        data[0x38..0x3c].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());
        data[0x3c..0x3e].copy_from_slice(&(coinbase.len() as u16).to_le_bytes());
        data[0x3e..0x40].copy_from_slice(&2u16.to_le_bytes());
        data[0x40] = 4;
        data[0x42..0x44].copy_from_slice(&1u16.to_le_bytes());
        data[0x48..0x50].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        data[0x50] = 1;
        data[0x54..0x58].copy_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&coinbase);
        data.extend_from_slice(&branch);
        let body_len = (data.len() - 8) as u32;
        data[0x04..0x08].copy_from_slice(&body_len.to_le_bytes());
        data
    }

    #[test]
    fn job_parser_adds_bounds_stock_function_lacks() {
        let data = sample_job();
        let parsed = bm1396_parse_job_packet(&data).expect("bounded job");
        assert_eq!(parsed.job_id, 0x1122_3344);
        assert_eq!(parsed.block_version, 0x2000_0000);
        assert_eq!(parsed.nonce2_initial, 0x0102_0304_0506_0708);
        assert_eq!(parsed.coinbase, [0x11, 0x22, 0x33]);
        assert_eq!(parsed.merkle_branches, [0x44; 32]);

        let plan = bm1396_plan_job_fpga(&parsed, 1).expect("bounded FPGA plan");
        assert_eq!(plan.buffer_offset, BM1396_FPGA_JOB_BUFFER_B_OFFSET);
        assert_eq!(plan.buffer_payload.len(), 96);
        assert_eq!(&plan.buffer_payload[..4], &[0x11, 0x22, 0x33, 0x80]);
        assert_eq!(&plan.buffer_payload[64..], &[0x44; 32]);
        assert_eq!(plan.ticket_difficulty, Some(7));
        assert_eq!(plan.coinbase_layout, (2 << 16) | (4 << 8) | 1);
        assert_eq!(plan.nonce2_low, 0x0506_0708);
        assert_eq!(plan.nonce2_high, 0x0102_0304);
        assert_eq!(plan.merkle_branch_count, 1);
        assert_eq!(plan.payload_end, 96);
        let writes = bm1396_job_scalar_writes(&plan, Bm1396VersionLaneMode::Four);
        assert_eq!(writes.len(), 21);
        assert_eq!(
            &writes[..6],
            &[
                Bm1396FpgaRegisterWrite {
                    offset: 0x8c,
                    value: 7,
                },
                Bm1396FpgaRegisterWrite {
                    offset: 0x124,
                    value: 0x1122_3344,
                },
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
        assert_eq!(writes[6].offset, 0x140);
        assert_eq!(writes[6].value, 0x0302_0100);
        assert_eq!(writes.last().unwrap().offset, 0x11c);
        assert_eq!(writes.last().unwrap().value, 96);
        let ordered = bm1396_plan_ordered_job_dispatch(&plan, 0x0f00_0000, true, true, 78)
            .expect("strict 8-lane ordered plan");
        assert_eq!(ordered.version_mode(), Bm1396VersionLaneMode::Eight);
        assert_eq!(ordered.buffer_payload(), plan.buffer_payload());
        assert_eq!(ordered.ops().len(), 38);
        assert_eq!(
            ordered.ops()[0],
            Bm1396OrderedJobOp::CopyDdrPayload {
                absolute_address: 0x0f21_0000,
                payload_offset: 0,
                length: 64,
            }
        );
        assert_eq!(
            ordered.ops()[1],
            Bm1396OrderedJobOp::VerifyDdrPayload {
                absolute_address: 0x0f21_0000,
                payload_offset: 0,
                length: 64,
            }
        );
        assert_eq!(
            ordered.ops()[2],
            Bm1396OrderedJobOp::CopyDdrPayload {
                absolute_address: 0x0f21_0040,
                payload_offset: 64,
                length: 32,
            }
        );
        assert_eq!(
            ordered.ops()[3],
            Bm1396OrderedJobOp::VerifyDdrPayload {
                absolute_address: 0x0f21_0040,
                payload_offset: 64,
                length: 32,
            }
        );
        assert_eq!(
            ordered.ops()[6],
            Bm1396OrderedJobOp::WriteRegister(Bm1396FpgaRegisterWrite {
                offset: 0x118,
                value: 0x0f21_0000,
            })
        );
        assert_eq!(
            ordered.ops()[ordered.ops().len() - 3],
            Bm1396OrderedJobOp::WriteRegister(Bm1396FpgaRegisterWrite {
                offset: 0x88,
                value: 0x8000_009c,
            })
        );
        assert_eq!(
            ordered.ops().last(),
            Some(&Bm1396OrderedJobOp::RmwFinal {
                offset: 0x100,
                preserve_mask: 0xffff_f0bf,
                mode_word: 0x8860,
            })
        );
        assert_eq!(bm1396_job_timeout_control_value(78, 8), Ok(0x8000_009c));
        assert_eq!(
            bm1396_job_timeout_control_value(0x1_0000, 8),
            Err(Bm1396JobDispatchPlanError::TimeoutControlOverflow)
        );
        assert_eq!(
            bm1396_plan_ordered_job_dispatch(&plan, 0xffdf_ffff, true, true, 78),
            Err(Bm1396JobDispatchPlanError::BufferAddressOverflow)
        );

        let mut no_multiversion = parsed.clone();
        no_multiversion.multiversion_enable = 0;
        let no_multiversion = bm1396_plan_job_fpga(&no_multiversion, 0).unwrap();
        assert_eq!(
            bm1396_job_version_mode(&no_multiversion, true),
            Err(Bm1396JobDispatchPlanError::MissingMultiversionEnable)
        );
        assert_eq!(
            bm1396_job_version_mode(&no_multiversion, false),
            Ok(Bm1396VersionLaneMode::One)
        );
        let mut bad_count = parsed.clone();
        bad_count.multiversion_count = 1;
        let bad_count = bm1396_plan_job_fpga(&bad_count, 0).unwrap();
        assert_eq!(
            bm1396_job_version_mode(&bad_count, true),
            Err(Bm1396JobDispatchPlanError::UnsupportedMultiversionCount { observed: 1 })
        );
        assert_eq!(
            bm1396_plan_job_fpga(&parsed, 2),
            Err(Bm1396JobPlanError::InvalidBufferIndex { observed: 2 })
        );
        let mut inconsistent = parsed.clone();
        inconsistent.coinbase_len += 1;
        assert!(matches!(
            bm1396_plan_job_fpga(&inconsistent, 0),
            Err(Bm1396JobPlanError::InconsistentCoinbaseLength { .. })
        ));
        let mut inconsistent = parsed.clone();
        inconsistent.merkle_branch_count += 1;
        assert!(matches!(
            bm1396_plan_job_fpga(&inconsistent, 0),
            Err(Bm1396JobPlanError::InconsistentMerkleLength { .. })
        ));

        let mut wrong_header = data.clone();
        wrong_header[0] = 0x51;
        assert!(matches!(
            bm1396_parse_job_packet(&wrong_header),
            Err(Bm1396JobParseError::WrongHeader { .. })
        ));
        let mut oversized = data.clone();
        oversized[0x3c..0x3e].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            bm1396_parse_job_packet(&oversized),
            Err(Bm1396JobParseError::PayloadTruncated { .. })
        ));
        let mut mismatch = data.clone();
        mismatch[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            bm1396_parse_job_packet(&mismatch),
            Err(Bm1396JobParseError::BodyLengthMismatch { .. })
        ));
    }

    #[test]
    fn sha_padding_and_previous_hash_words_are_exact() {
        let padded = bm1396_sha256_pad_coinbase(&[0x61, 0x62, 0x63]).unwrap();
        assert_eq!(padded.len(), 64);
        assert_eq!(&padded[..4], &[0x61, 0x62, 0x63, 0x80]);
        assert_eq!(&padded[56..64], &24u64.to_be_bytes());
        assert_eq!(bm1396_sha256_pad_coinbase(&[0; 56]).unwrap().len(), 128);

        let mut hash = [0u8; 32];
        for (index, byte) in hash.iter_mut().enumerate() {
            *byte = index as u8;
        }
        assert_eq!(
            bm1396_previous_hash_fpga_words(&hash),
            [
                0x0302_0100,
                0x0706_0504,
                0x0b0a_0908,
                0x0f0e_0d0c,
                0x1312_1110,
                0x1716_1514,
                0x1b1a_1918,
                0x1f1e_1d1c,
            ]
        );
    }
}
