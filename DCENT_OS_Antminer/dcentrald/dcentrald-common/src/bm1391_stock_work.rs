//! Exact-release, pure S15/T15 BM1391 stock job decoder and FPGA publication planner.
//!
//! This module is reconstructed from the two held stock `cgminer` executables.
//! It contains no mapping, MMIO, carrier, rail, dispatch, or share-submission
//! capability. A returned plan is evidence about stock-visible bytes and ordering,
//! not permission to execute it.

pub const BM1391_STOCK_JOB_TYPE: u8 = 0x52;
pub const BM1391_STOCK_JOB_FIXED_LEN: usize = 0x58;
pub const BM1391_STOCK_JOB_CRC_LEN: usize = 2;
/// The producer's CRC loop reduces its byte count modulo 2^16. Clean decoding
/// refuses frames whose pre-CRC span would exercise that wraparound behavior.
pub const BM1391_STOCK_JOB_MAX_NONWRAPPING_CRC_LEN: usize = u16::MAX as usize;
pub const BM1391_STOCK_MERKLE_BRANCH_LEN: usize = 32;

pub const BM1391_STOCK_FPGA_MAP_LEN: u32 = 0x0100_0000;
pub const BM1391_STOCK_OUTSTANDING_TABLE_OFFSET: u32 = 0;
pub const BM1391_STOCK_OUTSTANDING_TABLE_BASE_REGISTER: u32 = 0x110;
pub const BM1391_STOCK_OUTSTANDING_WORK_ID_COUNT: u32 = 0x8000;
pub const BM1391_STOCK_OUTSTANDING_RECORD_LEN: u32 = 0x40;
pub const BM1391_STOCK_OUTSTANDING_TABLE_LEN: u32 =
    BM1391_STOCK_OUTSTANDING_WORK_ID_COUNT * BM1391_STOCK_OUTSTANDING_RECORD_LEN;
pub const BM1391_STOCK_JOB_BUFFER_A_OFFSET: u32 = 0x0020_0000;
pub const BM1391_STOCK_JOB_BUFFER_B_OFFSET: u32 = 0x0021_0000;
pub const BM1391_STOCK_JOB_BUFFER_STRIDE: usize = 0x0001_0000;
pub const BM1391_STOCK_FPGA_MEMORY_BASES: [u32; 3] = [0x0f00_0000, 0x1f00_0000, 0x3f00_0000];

pub const BM1391_STOCK_TIMEOUT_OFFSET: u32 = 0x88;
pub const BM1391_STOCK_TICKET_OFFSET: u32 = 0x8c;
pub const BM1391_STOCK_DHASH_CONTROL_OFFSET: u32 = 0x100;
pub const BM1391_STOCK_COINBASE_LAYOUT_OFFSET: u32 = 0x104;
pub const BM1391_STOCK_NONCE2_LOW_OFFSET: u32 = 0x108;
pub const BM1391_STOCK_NONCE2_HIGH_OFFSET: u32 = 0x10c;
pub const BM1391_STOCK_MERKLE_COUNT_OFFSET: u32 = 0x114;
pub const BM1391_STOCK_JOB_START_OFFSET: u32 = 0x118;
pub const BM1391_STOCK_JOB_LENGTH_OFFSET: u32 = 0x11c;
pub const BM1391_STOCK_JOB_ID_OFFSET: u32 = 0x124;
pub const BM1391_STOCK_VERSION_OFFSET: u32 = 0x130;
pub const BM1391_STOCK_NTIME_OFFSET: u32 = 0x134;
pub const BM1391_STOCK_NBITS_OFFSET: u32 = 0x138;
pub const BM1391_STOCK_PREVIOUS_HASH_OFFSET: u32 = 0x140;
pub const BM1391_STOCK_VERSION_1_OFFSET: u32 = 0x164;
pub const BM1391_STOCK_NONCE_FIFO_CONTROL_OFFSET: u32 = 0x1c;

pub const BM1391_STOCK_TICKET_UPDATE_FLAG: u8 = 0x02;
pub const BM1391_STOCK_DHASH_RUN_BIT: u32 = 0x40;
/// Bit 5 is set by both exact publishers' final job operation. The held ARM
/// binaries do not independently prove the bitstream's name for this bit.
pub const BM1391_STOCK_DHASH_OPERATION_BIT5: u32 = 0x20;
pub const BM1391_STOCK_DHASH_BIT7: u32 = 0x80;
pub const BM1391_STOCK_FIRST_NONCE_FIFO_ENABLE: u32 = 0x0001_0000;
pub const BM1391_STOCK_SINGLE_CONTROL_PRESERVE: u32 = 0xffff_709f;
pub const BM1391_STOCK_SINGLE_CONTROL_WORD: u32 = 0x8160;
pub const BM1391_STOCK_MULTI_CONTROL_PRESERVE: u32 = 0xffff_f0bf;
pub const BM1391_STOCK_MULTI_CONTROL_BASE: u32 = 0x8060;
pub const BM1391_STOCK_TIMEOUT_ENABLE: u32 = 0x8000_0000;
pub const BM1391_STOCK_TIMEOUT_MASK: u32 = 0x0001_ffff;
pub const BM1391_STOCK_DELAY_MS: u32 = 1;
pub const BM1391_CLEAN_DHASH_CLEAR_MAX_POLLS: u16 = 10;
pub const BM1391_STOCK_DHASH_WRITE_READBACK_CHECKS: u8 = 10;
pub const BM1391_STOCK_DHASH_WRITE_RETRY_DELAY_MS: u32 = 2;

pub const BM1391_S15_CGMINER_SHA256: &str =
    "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8";
pub const BM1391_T15_CGMINER_SHA256: &str =
    "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockRelease {
    S15_1_92992_0_14,
    T15_1_92992_0_13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockWorkEvidence {
    pub cgminer_sha256: &'static str,
    pub packet_producer: u32,
    pub job_publisher: u32,
    pub fpga_mapper: u32,
    pub outstanding_base_setter: u32,
    pub initial_job_base_setter: u32,
}

impl Bm1391StockRelease {
    pub const fn evidence(self) -> Bm1391StockWorkEvidence {
        match self {
            Self::S15_1_92992_0_14 => Bm1391StockWorkEvidence {
                cgminer_sha256: BM1391_S15_CGMINER_SHA256,
                packet_producer: 0x0005_1508,
                job_publisher: 0x0005_1868,
                fpga_mapper: 0x0003_c5c0,
                outstanding_base_setter: 0x0008_6e1c,
                initial_job_base_setter: 0x0008_7004,
            },
            Self::T15_1_92992_0_13 => Bm1391StockWorkEvidence {
                cgminer_sha256: BM1391_T15_CGMINER_SHA256,
                packet_producer: 0x0005_1538,
                job_publisher: 0x0005_1898,
                fpga_mapper: 0x0003_c5b8,
                outstanding_base_setter: 0x0008_6d3c,
                initial_job_base_setter: 0x0008_6f24,
            },
        }
    }
}

/// CRC-16/MODBUS: reflected polynomial `0xa001`, initial value `0xffff`, no xor-out.
/// The stock packet producer appends the numeric result in ARM little-endian order.
pub fn bm1391_stock_job_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = data.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1391StockJobPacket<'a> {
    /// Caller-selected evidence label; decoding does not authenticate a binary
    /// or bind this packet to an attached board.
    pub release: Bm1391StockRelease,
    /// Byte `+0x08` is copied by the exact producer and ignored by the exact publisher.
    pub opaque_byte_08: u8,
    pub flags: u8,
    pub ticket: u8,
    pub job_id: u32,
    pub version: u32,
    pub previous_hash: [u8; 32],
    pub ntime: u32,
    pub nbits: u32,
    pub nonce2_offset: u16,
    pub nonce2_size: u8,
    pub merkle_count: u16,
    pub nonce2: u64,
    pub multiversion_enabled: bool,
    pub multiversion_count: u32,
    pub coinbase: &'a [u8],
    /// Contiguous, wire-order 32-byte branches.
    pub merkle_branches: &'a [u8],
}

impl Bm1391StockJobPacket<'_> {
    /// CRC-16 detects accidental changes only. The caller can recompute it and
    /// can freely choose the release enum, so decoding proves no provenance.
    pub const fn authenticates_stock_provenance(&self) -> bool {
        false
    }

    pub const fn admits_hardware_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockJobDecodeError {
    TooShort {
        observed: usize,
    },
    WrongType {
        observed: u8,
    },
    LengthOverflow,
    DeclaredLengthMismatch {
        declared: usize,
        observed: usize,
    },
    PayloadLengthOverflow,
    PayloadLengthMismatch {
        required: usize,
        observed: usize,
    },
    BadCrc {
        expected: u16,
        observed: u16,
    },
    StockCrcLengthWouldWrap {
        pre_crc_len: usize,
    },
    Nonce2TooWide {
        observed: u8,
    },
    Nonce2WindowOutsideCoinbase {
        offset: u16,
        required_window: usize,
        coinbase_len: u16,
    },
}

/// Decode the exact packet emitted by the held producer, adding fail-closed bounds
/// absent from stock. The producer reads an eight-byte coinbase window at nonce2
/// offset before replacing `nonce2_size` leading bytes, so clean admission requires
/// the complete eight-byte window to exist.
pub fn decode_bm1391_stock_job_packet(
    release: Bm1391StockRelease,
    data: &[u8],
) -> Result<Bm1391StockJobPacket<'_>, Bm1391StockJobDecodeError> {
    if data.len() < BM1391_STOCK_JOB_FIXED_LEN + BM1391_STOCK_JOB_CRC_LEN {
        return Err(Bm1391StockJobDecodeError::TooShort {
            observed: data.len(),
        });
    }
    let too_short = Bm1391StockJobDecodeError::TooShort {
        observed: data.len(),
    };
    let observed_type = data.first().copied().ok_or(too_short)?;
    if observed_type != BM1391_STOCK_JOB_TYPE {
        return Err(Bm1391StockJobDecodeError::WrongType {
            observed: observed_type,
        });
    }
    let declared = usize::try_from(read_u32_le(data, 0x04).ok_or(too_short)?)
        .ok()
        .and_then(|body| body.checked_add(8))
        .ok_or(Bm1391StockJobDecodeError::LengthOverflow)?;
    if declared != data.len() {
        return Err(Bm1391StockJobDecodeError::DeclaredLengthMismatch {
            declared,
            observed: data.len(),
        });
    }

    let coinbase_len = read_u16_le(data, 0x3c).ok_or(too_short)?;
    let merkle_count = read_u16_le(data, 0x42).ok_or(too_short)?;
    let merkle_len = usize::from(merkle_count)
        .checked_mul(BM1391_STOCK_MERKLE_BRANCH_LEN)
        .ok_or(Bm1391StockJobDecodeError::PayloadLengthOverflow)?;
    let coinbase_end = BM1391_STOCK_JOB_FIXED_LEN
        .checked_add(usize::from(coinbase_len))
        .ok_or(Bm1391StockJobDecodeError::PayloadLengthOverflow)?;
    let payload_end = coinbase_end
        .checked_add(merkle_len)
        .ok_or(Bm1391StockJobDecodeError::PayloadLengthOverflow)?;
    let required = payload_end
        .checked_add(BM1391_STOCK_JOB_CRC_LEN)
        .ok_or(Bm1391StockJobDecodeError::PayloadLengthOverflow)?;
    if required != data.len() {
        return Err(Bm1391StockJobDecodeError::PayloadLengthMismatch {
            required,
            observed: data.len(),
        });
    }
    if payload_end > BM1391_STOCK_JOB_MAX_NONWRAPPING_CRC_LEN {
        return Err(Bm1391StockJobDecodeError::StockCrcLengthWouldWrap {
            pre_crc_len: payload_end,
        });
    }

    let observed_crc = read_u16_le(data, payload_end).ok_or(too_short)?;
    let crc_input =
        data.get(..payload_end)
            .ok_or(Bm1391StockJobDecodeError::PayloadLengthMismatch {
                required,
                observed: data.len(),
            })?;
    let expected_crc = bm1391_stock_job_crc16(crc_input);
    if observed_crc != expected_crc {
        return Err(Bm1391StockJobDecodeError::BadCrc {
            expected: expected_crc,
            observed: observed_crc,
        });
    }

    let nonce2_size = data.get(0x40).copied().ok_or(too_short)?;
    if nonce2_size > 8 {
        return Err(Bm1391StockJobDecodeError::Nonce2TooWide {
            observed: nonce2_size,
        });
    }
    let nonce2_offset = read_u16_le(data, 0x3e).ok_or(too_short)?;
    let nonce2_window_end = usize::from(nonce2_offset)
        .checked_add(8)
        .ok_or(Bm1391StockJobDecodeError::PayloadLengthOverflow)?;
    if nonce2_window_end > usize::from(coinbase_len) {
        return Err(Bm1391StockJobDecodeError::Nonce2WindowOutsideCoinbase {
            offset: nonce2_offset,
            required_window: 8,
            coinbase_len,
        });
    }

    let previous_hash: [u8; 32] = data
        .get(0x14..0x34)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(too_short)?;
    let nonce2_bytes: [u8; 8] = data
        .get(0x48..0x50)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(too_short)?;
    let coinbase = data.get(BM1391_STOCK_JOB_FIXED_LEN..coinbase_end).ok_or(
        Bm1391StockJobDecodeError::PayloadLengthMismatch {
            required,
            observed: data.len(),
        },
    )?;
    let merkle_branches = data.get(coinbase_end..payload_end).ok_or(
        Bm1391StockJobDecodeError::PayloadLengthMismatch {
            required,
            observed: data.len(),
        },
    )?;
    Ok(Bm1391StockJobPacket {
        release,
        opaque_byte_08: data.get(0x08).copied().ok_or(too_short)?,
        flags: data.get(0x09).copied().ok_or(too_short)?,
        ticket: data.get(0x0a).copied().ok_or(too_short)?,
        job_id: read_u32_le(data, 0x0c).ok_or(too_short)?,
        version: read_u32_le(data, 0x10).ok_or(too_short)?,
        previous_hash,
        ntime: read_u32_le(data, 0x34).ok_or(too_short)?,
        nbits: read_u32_le(data, 0x38).ok_or(too_short)?,
        nonce2_offset,
        nonce2_size,
        merkle_count,
        nonce2: u64::from_le_bytes(nonce2_bytes),
        multiversion_enabled: data.get(0x50).copied().ok_or(too_short)? != 0,
        multiversion_count: read_u32_le(data, 0x54).ok_or(too_short)?,
        coinbase,
        merkle_branches,
    })
}

pub fn bm1391_stock_previous_hash_words(previous_hash: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (word, chunk) in words.iter_mut().zip(previous_hash.chunks_exact(4)) {
        let bytes: [u8; 4] = chunk.try_into().unwrap_or([0; 4]);
        *word = u32::from_le_bytes(bytes);
    }
    words
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockRegisterWrite {
    pub offset: u32,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockJobBuffer {
    A,
    B,
}

impl Bm1391StockJobBuffer {
    pub const fn offset(self) -> u32 {
        match self {
            Self::A => BM1391_STOCK_JOB_BUFFER_A_OFFSET,
            Self::B => BM1391_STOCK_JOB_BUFFER_B_OFFSET,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockPlannerInput {
    pub buffer: Bm1391StockJobBuffer,
    /// Caller-observed `/proc/meminfo` `MemTotal` value. This remains forgeable;
    /// it is used only to require internal agreement with stock base selection.
    pub observed_mem_total_kib: u64,
    pub fpga_memory_physical_base: u32,
    /// Exact stock source is per-buffer runtime state `+0x48`, not a packet field.
    pub timeout_base: u32,
    pub first_job: bool,
    pub runtime_multiversion_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1391StockPublicationStep {
    /// Stock writes every byte and immediately reads every byte back, logging but
    /// continuing on mismatch. A clean executor must fail on any mismatch.
    WriteDdrAndRequireExactReadback {
        buffer_offset: u32,
        physical_address: u32,
        bytes: Vec<u8>,
    },
    /// Read DHASH control when this step executes, apply the masks, then use the
    /// stock setter. A precomputed caller snapshot is not equivalent: stock
    /// performs a fresh read at each of its three control transitions.
    ReadModifyWriteDhashWithStockRetry {
        preserve_mask: u32,
        set_mask: u32,
        readback_checks: u8,
        retry_delay_ms: u32,
        ignored_compare_mask: u32,
    },
    DelayMs(u32),
    /// Stock polls forever; the pure clean-room contract supplies a finite limit.
    RequireDhashBitClear {
        mask: u32,
        max_polls: u16,
        poll_delay_ms: u32,
    },
    ReadModifyWriteSet {
        offset: u32,
        set_mask: u32,
    },
    Write(Bm1391StockRegisterWrite),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1391StockJobPublicationPlan {
    pub release: Bm1391StockRelease,
    pub padded_coinbase_len: usize,
    pub ordered_steps: Vec<Bm1391StockPublicationStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockJobPlanError {
    CoinbaseLengthTooLarge {
        observed: usize,
    },
    InconsistentMerkleLength {
        declared: u16,
        observed: usize,
    },
    Nonce2TooWide {
        observed: u8,
    },
    Nonce2WindowOutsideCoinbase {
        offset: u16,
        required_window: usize,
        coinbase_len: usize,
    },
    CoinbasePaddingOverflow,
    CoinbaseBlockCountOverflow {
        observed: usize,
    },
    DdrPayloadTooLong {
        observed: usize,
    },
    UnsupportedPhysicalBase {
        observed: u32,
    },
    PhysicalBaseMemTotalMismatch {
        observed: u32,
        expected: u32,
        mem_total_kib: u64,
    },
    JobPhysicalAddressOverflow,
    JobPhysicalEndOverflow,
    MultiversionModeMismatch,
    UnsupportedMultiversionCount {
        observed: u32,
    },
    TimeoutOverflow {
        base: u32,
        multiplier: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockInitialMemoryPublicationPlan {
    pub release: Bm1391StockRelease,
    pub outstanding_table_relative_offset: u32,
    pub outstanding_table_len: u32,
    pub initial_job_buffer_relative_offset: u32,
    pub ordered_writes: [Bm1391StockRegisterWrite; 2],
}

impl Bm1391StockInitialMemoryPublicationPlan {
    pub const fn admits_hardware_authority(&self) -> bool {
        false
    }

    pub const fn proves_entry_completion_or_reuse(&self) -> bool {
        false
    }
}

/// Recover the exact initial physical-address publication performed after the
/// 16-MiB `/dev/fpga_mem` mapping is established.
///
/// S15 `FUN_0003c5c0` calls `FUN_00086e1c(base)` and then
/// `FUN_00087004(base + 0x200000)`; T15 `FUN_0003c5b8` calls the equivalent
/// `FUN_00086d3c` / `FUN_00086f24`. The setters write MMIO `0x110` and
/// `0x118`, respectively. The 15-bit work-id geometry makes the first region
/// exactly 32768 * 0x40 = 0x200000 bytes, ending at job buffer A.
///
/// This proves only the initial base/geometry/order. It does not expose the
/// FPGA's per-entry allocation, completion, generation, or reuse protocol.
pub fn plan_bm1391_stock_initial_memory_publication(
    release: Bm1391StockRelease,
    observed_mem_total_kib: u64,
    fpga_memory_physical_base: u32,
) -> Result<Bm1391StockInitialMemoryPublicationPlan, Bm1391StockJobPlanError> {
    if !BM1391_STOCK_FPGA_MEMORY_BASES.contains(&fpga_memory_physical_base) {
        return Err(Bm1391StockJobPlanError::UnsupportedPhysicalBase {
            observed: fpga_memory_physical_base,
        });
    }
    let expected = crate::bm1391_carrier_profile::bm1391_stock_dma_base_for_memtotal_kib(
        observed_mem_total_kib,
    );
    if fpga_memory_physical_base != expected {
        return Err(Bm1391StockJobPlanError::PhysicalBaseMemTotalMismatch {
            observed: fpga_memory_physical_base,
            expected,
            mem_total_kib: observed_mem_total_kib,
        });
    }
    let initial_job_buffer = fpga_memory_physical_base
        .checked_add(BM1391_STOCK_JOB_BUFFER_A_OFFSET)
        .ok_or(Bm1391StockJobPlanError::JobPhysicalAddressOverflow)?;
    Ok(Bm1391StockInitialMemoryPublicationPlan {
        release,
        outstanding_table_relative_offset: BM1391_STOCK_OUTSTANDING_TABLE_OFFSET,
        outstanding_table_len: BM1391_STOCK_OUTSTANDING_TABLE_LEN,
        initial_job_buffer_relative_offset: BM1391_STOCK_JOB_BUFFER_A_OFFSET,
        ordered_writes: [
            Bm1391StockRegisterWrite {
                offset: BM1391_STOCK_OUTSTANDING_TABLE_BASE_REGISTER,
                value: fpga_memory_physical_base,
            },
            Bm1391StockRegisterWrite {
                offset: BM1391_STOCK_JOB_START_OFFSET,
                value: initial_job_buffer,
            },
        ],
    })
}

fn push_write(steps: &mut Vec<Bm1391StockPublicationStep>, offset: u32, value: u32) {
    steps.push(Bm1391StockPublicationStep::Write(
        Bm1391StockRegisterWrite { offset, value },
    ));
}

/// Build the exact S15/T15 publication spine with bounded clean-room failure policy.
///
/// Only the two-version hardware lane is admitted when multiversion is enabled:
/// the exact stock publisher writes only version lane 1, tagged with `0x4000`,
/// and does so only when the count equals two. This function never performs I/O.
pub fn plan_bm1391_stock_job_publication(
    job: &Bm1391StockJobPacket<'_>,
    input: Bm1391StockPlannerInput,
) -> Result<Bm1391StockJobPublicationPlan, Bm1391StockJobPlanError> {
    if job.coinbase.len() > usize::from(u16::MAX) {
        return Err(Bm1391StockJobPlanError::CoinbaseLengthTooLarge {
            observed: job.coinbase.len(),
        });
    }
    let expected_merkle_len = usize::from(job.merkle_count)
        .checked_mul(BM1391_STOCK_MERKLE_BRANCH_LEN)
        .ok_or(Bm1391StockJobPlanError::InconsistentMerkleLength {
            declared: job.merkle_count,
            observed: job.merkle_branches.len(),
        })?;
    if expected_merkle_len != job.merkle_branches.len() {
        return Err(Bm1391StockJobPlanError::InconsistentMerkleLength {
            declared: job.merkle_count,
            observed: job.merkle_branches.len(),
        });
    }
    if job.nonce2_size > 8 {
        return Err(Bm1391StockJobPlanError::Nonce2TooWide {
            observed: job.nonce2_size,
        });
    }
    let nonce2_window_end = usize::from(job.nonce2_offset).checked_add(8).ok_or(
        Bm1391StockJobPlanError::Nonce2WindowOutsideCoinbase {
            offset: job.nonce2_offset,
            required_window: 8,
            coinbase_len: job.coinbase.len(),
        },
    )?;
    if nonce2_window_end > job.coinbase.len() {
        return Err(Bm1391StockJobPlanError::Nonce2WindowOutsideCoinbase {
            offset: job.nonce2_offset,
            required_window: 8,
            coinbase_len: job.coinbase.len(),
        });
    }
    if job.multiversion_enabled != input.runtime_multiversion_enabled {
        return Err(Bm1391StockJobPlanError::MultiversionModeMismatch);
    }
    let effective_count = if input.runtime_multiversion_enabled {
        if job.multiversion_count != 2 {
            return Err(Bm1391StockJobPlanError::UnsupportedMultiversionCount {
                observed: job.multiversion_count,
            });
        }
        2
    } else {
        1
    };

    let padded_coinbase = crate::sha256_padding::sha256_pad_message(job.coinbase)
        .ok_or(Bm1391StockJobPlanError::CoinbasePaddingOverflow)?;
    let padded_coinbase_len = padded_coinbase.len();
    let coinbase_blocks = padded_coinbase_len / 64;
    if coinbase_blocks > usize::from(u8::MAX) {
        return Err(Bm1391StockJobPlanError::CoinbaseBlockCountOverflow {
            observed: coinbase_blocks,
        });
    }
    let ddr_payload_len = padded_coinbase_len
        .checked_add(job.merkle_branches.len())
        .ok_or(Bm1391StockJobPlanError::DdrPayloadTooLong {
            observed: usize::MAX,
        })?;
    if ddr_payload_len >= BM1391_STOCK_JOB_BUFFER_STRIDE {
        return Err(Bm1391StockJobPlanError::DdrPayloadTooLong {
            observed: ddr_payload_len,
        });
    }
    if !BM1391_STOCK_FPGA_MEMORY_BASES.contains(&input.fpga_memory_physical_base) {
        return Err(Bm1391StockJobPlanError::UnsupportedPhysicalBase {
            observed: input.fpga_memory_physical_base,
        });
    }
    let expected_physical_base =
        crate::bm1391_carrier_profile::bm1391_stock_dma_base_for_memtotal_kib(
            input.observed_mem_total_kib,
        );
    if input.fpga_memory_physical_base != expected_physical_base {
        return Err(Bm1391StockJobPlanError::PhysicalBaseMemTotalMismatch {
            observed: input.fpga_memory_physical_base,
            expected: expected_physical_base,
            mem_total_kib: input.observed_mem_total_kib,
        });
    }
    let payload_len_u32 = u32::try_from(ddr_payload_len)
        .map_err(|_| Bm1391StockJobPlanError::JobPhysicalEndOverflow)?;
    let relative_end = input
        .buffer
        .offset()
        .checked_add(payload_len_u32)
        .filter(|end| *end <= BM1391_STOCK_FPGA_MAP_LEN)
        .ok_or(Bm1391StockJobPlanError::JobPhysicalEndOverflow)?;
    let physical_address = input
        .fpga_memory_physical_base
        .checked_add(input.buffer.offset())
        .ok_or(Bm1391StockJobPlanError::JobPhysicalAddressOverflow)?;
    input
        .fpga_memory_physical_base
        .checked_add(relative_end)
        .ok_or(Bm1391StockJobPlanError::JobPhysicalEndOverflow)?;
    let timeout = input
        .timeout_base
        .checked_mul(effective_count)
        .filter(|value| *value <= BM1391_STOCK_TIMEOUT_MASK)
        .ok_or(Bm1391StockJobPlanError::TimeoutOverflow {
            base: input.timeout_base,
            multiplier: effective_count,
        })?;

    let mut steps = vec![
        Bm1391StockPublicationStep::WriteDdrAndRequireExactReadback {
            buffer_offset: input.buffer.offset(),
            physical_address,
            bytes: padded_coinbase,
        },
    ];
    if !job.merkle_branches.is_empty() {
        let padded_len_u32 = u32::try_from(padded_coinbase_len)
            .map_err(|_| Bm1391StockJobPlanError::JobPhysicalEndOverflow)?;
        steps.push(
            Bm1391StockPublicationStep::WriteDdrAndRequireExactReadback {
                buffer_offset: input
                    .buffer
                    .offset()
                    .checked_add(padded_len_u32)
                    .ok_or(Bm1391StockJobPlanError::JobPhysicalEndOverflow)?,
                physical_address: physical_address
                    .checked_add(padded_len_u32)
                    .ok_or(Bm1391StockJobPlanError::JobPhysicalEndOverflow)?,
                bytes: job.merkle_branches.to_vec(),
            },
        );
    }
    steps.extend([
        Bm1391StockPublicationStep::ReadModifyWriteDhashWithStockRetry {
            preserve_mask: !BM1391_STOCK_DHASH_RUN_BIT,
            set_mask: 0,
            readback_checks: BM1391_STOCK_DHASH_WRITE_READBACK_CHECKS,
            retry_delay_ms: BM1391_STOCK_DHASH_WRITE_RETRY_DELAY_MS,
            ignored_compare_mask: BM1391_STOCK_DHASH_BIT7,
        },
        Bm1391StockPublicationStep::DelayMs(BM1391_STOCK_DELAY_MS),
        Bm1391StockPublicationStep::RequireDhashBitClear {
            mask: BM1391_STOCK_DHASH_RUN_BIT,
            max_polls: BM1391_CLEAN_DHASH_CLEAR_MAX_POLLS,
            poll_delay_ms: BM1391_STOCK_DELAY_MS,
        },
        Bm1391StockPublicationStep::DelayMs(BM1391_STOCK_DELAY_MS),
    ]);
    push_write(&mut steps, BM1391_STOCK_JOB_START_OFFSET, physical_address);
    if job.flags & BM1391_STOCK_TICKET_UPDATE_FLAG != 0 {
        push_write(
            &mut steps,
            BM1391_STOCK_TICKET_OFFSET,
            u32::from(job.ticket),
        );
    }
    push_write(&mut steps, BM1391_STOCK_JOB_ID_OFFSET, job.job_id);
    push_write(&mut steps, BM1391_STOCK_VERSION_OFFSET, job.version);
    if effective_count == 2 {
        push_write(
            &mut steps,
            BM1391_STOCK_VERSION_1_OFFSET,
            job.version | 0x4000,
        );
    }
    for (index, value) in bm1391_stock_previous_hash_words(&job.previous_hash)
        .iter()
        .enumerate()
    {
        push_write(
            &mut steps,
            BM1391_STOCK_PREVIOUS_HASH_OFFSET + index as u32 * 4,
            *value,
        );
    }
    push_write(&mut steps, BM1391_STOCK_NTIME_OFFSET, job.ntime);
    push_write(&mut steps, BM1391_STOCK_NBITS_OFFSET, job.nbits);
    let coinbase_blocks = coinbase_blocks as u32;
    let coinbase_layout =
        (u32::from(job.nonce2_offset) << 16) | (u32::from(job.nonce2_size) << 8) | coinbase_blocks;
    push_write(
        &mut steps,
        BM1391_STOCK_COINBASE_LAYOUT_OFFSET,
        coinbase_layout,
    );
    push_write(
        &mut steps,
        BM1391_STOCK_NONCE2_LOW_OFFSET,
        job.nonce2 as u32,
    );
    push_write(
        &mut steps,
        BM1391_STOCK_NONCE2_HIGH_OFFSET,
        (job.nonce2 >> 32) as u32,
    );
    push_write(
        &mut steps,
        BM1391_STOCK_MERKLE_COUNT_OFFSET,
        u32::from(job.merkle_count),
    );
    push_write(
        &mut steps,
        BM1391_STOCK_JOB_LENGTH_OFFSET,
        (padded_coinbase_len + job.merkle_branches.len()) as u32,
    );
    steps.push(Bm1391StockPublicationStep::DelayMs(BM1391_STOCK_DELAY_MS));
    if input.first_job {
        steps.push(Bm1391StockPublicationStep::ReadModifyWriteSet {
            offset: BM1391_STOCK_NONCE_FIFO_CONTROL_OFFSET,
            set_mask: BM1391_STOCK_FIRST_NONCE_FIFO_ENABLE,
        });
        steps.push(
            Bm1391StockPublicationStep::ReadModifyWriteDhashWithStockRetry {
                preserve_mask: u32::MAX,
                set_mask: BM1391_STOCK_DHASH_BIT7,
                readback_checks: BM1391_STOCK_DHASH_WRITE_READBACK_CHECKS,
                retry_delay_ms: BM1391_STOCK_DHASH_WRITE_RETRY_DELAY_MS,
                ignored_compare_mask: BM1391_STOCK_DHASH_BIT7,
            },
        );
    }
    push_write(
        &mut steps,
        BM1391_STOCK_TIMEOUT_OFFSET,
        BM1391_STOCK_TIMEOUT_ENABLE | timeout,
    );
    let (final_preserve_mask, final_set_mask) = if effective_count == 1 {
        (
            BM1391_STOCK_SINGLE_CONTROL_PRESERVE,
            BM1391_STOCK_SINGLE_CONTROL_WORD,
        )
    } else {
        (
            BM1391_STOCK_MULTI_CONTROL_PRESERVE,
            ((effective_count & 0x0f) << 8) | BM1391_STOCK_MULTI_CONTROL_BASE,
        )
    };
    steps.push(
        Bm1391StockPublicationStep::ReadModifyWriteDhashWithStockRetry {
            preserve_mask: final_preserve_mask,
            set_mask: final_set_mask,
            readback_checks: BM1391_STOCK_DHASH_WRITE_READBACK_CHECKS,
            retry_delay_ms: BM1391_STOCK_DHASH_WRITE_RETRY_DELAY_MS,
            ignored_compare_mask: BM1391_STOCK_DHASH_BIT7,
        },
    );

    Ok(Bm1391StockJobPublicationPlan {
        release: job.release,
        padded_coinbase_len,
        ordered_steps: steps,
    })
}

impl Bm1391StockJobPublicationPlan {
    /// All packet, release, memory-size, buffer-state, and runtime-policy inputs
    /// are caller supplied. A plan never grants authority to touch hardware.
    pub const fn admits_live_dispatch(&self) -> bool {
        false
    }

    pub const fn admits_share_submission(&self) -> bool {
        false
    }

    pub const fn authenticates_stock_provenance(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(multiversion: bool, count: u32, coinbase_len: usize, merkle_count: u16) -> Vec<u8> {
        assert!(coinbase_len >= 8 && coinbase_len <= usize::from(u16::MAX));
        let payload_len = coinbase_len + usize::from(merkle_count) * 32;
        let mut data = vec![0u8; BM1391_STOCK_JOB_FIXED_LEN + payload_len + 2];
        data[0] = BM1391_STOCK_JOB_TYPE;
        let body_len = u32::try_from(data.len() - 8).unwrap();
        data[4..8].copy_from_slice(&body_len.to_le_bytes());
        data[8] = 0xa5;
        data[9] = BM1391_STOCK_TICKET_UPDATE_FLAG;
        data[10] = 0x0f;
        data[0x0c..0x10].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        for (index, byte) in data[0x14..0x34].iter_mut().enumerate() {
            *byte = index as u8;
        }
        data[0x34..0x38].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        data[0x38..0x3c].copy_from_slice(&0x99aa_bbccu32.to_le_bytes());
        data[0x3c..0x3e].copy_from_slice(&(coinbase_len as u16).to_le_bytes());
        data[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes());
        data[0x40] = 4;
        data[0x42..0x44].copy_from_slice(&merkle_count.to_le_bytes());
        data[0x48..0x50].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
        data[0x50] = u8::from(multiversion);
        data[0x54..0x58].copy_from_slice(&count.to_le_bytes());
        for (index, byte) in data[0x58..0x58 + payload_len].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(3);
        }
        let crc_offset = data.len() - 2;
        let crc = bm1391_stock_job_crc16(&data[..crc_offset]);
        data[crc_offset..].copy_from_slice(&crc.to_le_bytes());
        data
    }

    #[test]
    fn release_evidence_is_exact_and_scoped() {
        assert_eq!(
            Bm1391StockRelease::S15_1_92992_0_14.evidence(),
            Bm1391StockWorkEvidence {
                cgminer_sha256: BM1391_S15_CGMINER_SHA256,
                packet_producer: 0x51508,
                job_publisher: 0x51868,
                fpga_mapper: 0x3c5c0,
                outstanding_base_setter: 0x86e1c,
                initial_job_base_setter: 0x87004,
            }
        );
        assert_eq!(
            Bm1391StockRelease::T15_1_92992_0_13
                .evidence()
                .job_publisher,
            0x51898
        );
        assert_eq!(
            Bm1391StockRelease::T15_1_92992_0_13
                .evidence()
                .outstanding_base_setter,
            0x86d3c
        );
    }

    #[test]
    fn initial_memory_publication_pins_full_table_then_job_a_base() {
        for (release, mem_total_kib, base) in [
            (Bm1391StockRelease::S15_1_92992_0_14, 400_000, 0x0f00_0000),
            (Bm1391StockRelease::T15_1_92992_0_13, 400_001, 0x1f00_0000),
            (Bm1391StockRelease::S15_1_92992_0_14, 1_000_001, 0x3f00_0000),
        ] {
            let plan =
                plan_bm1391_stock_initial_memory_publication(release, mem_total_kib, base).unwrap();
            assert_eq!(plan.outstanding_table_relative_offset, 0);
            assert_eq!(plan.outstanding_table_len, 0x20_0000);
            assert_eq!(
                plan.outstanding_table_len,
                BM1391_STOCK_OUTSTANDING_WORK_ID_COUNT * BM1391_STOCK_OUTSTANDING_RECORD_LEN
            );
            assert_eq!(plan.initial_job_buffer_relative_offset, 0x20_0000);
            assert_eq!(
                plan.ordered_writes,
                [
                    Bm1391StockRegisterWrite {
                        offset: 0x110,
                        value: base,
                    },
                    Bm1391StockRegisterWrite {
                        offset: 0x118,
                        value: base + 0x20_0000,
                    },
                ]
            );
            assert!(!plan.admits_hardware_authority());
            assert!(!plan.proves_entry_completion_or_reuse());
        }
    }

    #[test]
    fn initial_memory_publication_refuses_unselected_or_unknown_bases() {
        assert!(matches!(
            plan_bm1391_stock_initial_memory_publication(
                Bm1391StockRelease::S15_1_92992_0_14,
                400_001,
                0x0f00_0000,
            ),
            Err(Bm1391StockJobPlanError::PhysicalBaseMemTotalMismatch { .. })
        ));
        assert!(matches!(
            plan_bm1391_stock_initial_memory_publication(
                Bm1391StockRelease::T15_1_92992_0_13,
                400_001,
                0x2f00_0000,
            ),
            Err(Bm1391StockJobPlanError::UnsupportedPhysicalBase { .. })
        ));
    }

    #[test]
    fn crc_is_modbus_and_little_endian_in_frame() {
        assert_eq!(bm1391_stock_job_crc16(b"123456789"), 0x4b37);
        let data = frame(false, 0, 8, 0);
        assert_eq!(
            &data[data.len() - 2..],
            &bm1391_stock_job_crc16(&data[..data.len() - 2]).to_le_bytes()
        );
    }

    #[test]
    fn decoder_pins_all_packet_fields_and_endianness() {
        let data = frame(false, 0, 12, 2);
        let job =
            decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &data).unwrap();
        assert_eq!(job.opaque_byte_08, 0xa5);
        assert_eq!(job.flags, 2);
        assert_eq!(job.ticket, 0x0f);
        assert_eq!(job.job_id, 0x1122_3344);
        assert_eq!(job.version, 0x2000_0000);
        assert_eq!(job.ntime, 0x5566_7788);
        assert_eq!(job.nbits, 0x99aa_bbcc);
        assert_eq!(job.nonce2, 0x0123_4567_89ab_cdef);
        assert!(!job.authenticates_stock_provenance());
        assert!(!job.admits_hardware_authority());
        assert_eq!(job.coinbase.len(), 12);
        assert_eq!(job.merkle_branches.len(), 64);
        assert_eq!(
            bm1391_stock_previous_hash_words(&job.previous_hash),
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

    #[test]
    fn decoder_rejects_header_length_payload_crc_and_nonce_forgery() {
        let good = frame(false, 0, 8, 1);
        assert!(matches!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &good[..20]),
            Err(Bm1391StockJobDecodeError::TooShort { .. })
        ));
        let mut bad = good.clone();
        bad[0] = 0x51;
        assert!(matches!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &bad),
            Err(Bm1391StockJobDecodeError::WrongType { .. })
        ));
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &bad),
            Err(Bm1391StockJobDecodeError::DeclaredLengthMismatch { .. })
        ));
        let mut bad = good.clone();
        bad[0x42..0x44].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &bad),
            Err(Bm1391StockJobDecodeError::PayloadLengthMismatch { .. })
        ));
        let mut bad = good.clone();
        bad[0x10] ^= 1;
        assert!(matches!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &bad),
            Err(Bm1391StockJobDecodeError::BadCrc { .. })
        ));
        let mut bad = frame(false, 0, 8, 0);
        bad[0x40] = 9;
        let end = bad.len() - 2;
        let crc = bm1391_stock_job_crc16(&bad[..end]);
        bad[end..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &bad),
            Err(Bm1391StockJobDecodeError::Nonce2TooWide { observed: 9 })
        ));

        let crc_wrap = frame(false, 0, usize::from(u16::MAX), 0);
        assert_eq!(
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &crc_wrap,),
            Err(Bm1391StockJobDecodeError::StockCrcLengthWouldWrap {
                pre_crc_len: BM1391_STOCK_JOB_FIXED_LEN + usize::from(u16::MAX),
            })
        );
    }

    #[test]
    fn sha_padding_boundaries_match_stock_for_every_u16_boundary_sample() {
        for raw_len in [8usize, 55, 56, 63, 64, 119, 120, 255, 256, 1023] {
            let data = frame(false, 0, raw_len, 0);
            let job = decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &data)
                .unwrap();
            let padded = crate::sha256_padding::sha256_pad_message(job.coinbase).unwrap();
            let expected = if raw_len & 0x3f < 0x38 {
                (raw_len & !0x3f) + 0x40
            } else {
                (raw_len & !0x3f) + 0x80
            };
            assert_eq!(padded.len(), expected);
            assert_eq!(
                &padded[expected - 8..],
                &((raw_len as u64) * 8).to_be_bytes()
            );
        }
    }

    #[test]
    fn single_version_plan_pins_ddr_and_scalar_order() {
        let data = frame(false, 0, 64, 1);
        let job =
            decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &data).unwrap();
        let plan = plan_bm1391_stock_job_publication(
            &job,
            Bm1391StockPlannerInput {
                buffer: Bm1391StockJobBuffer::B,
                observed_mem_total_kib: 500_000,
                fpga_memory_physical_base: 0x1f00_0000,
                timeout_base: 0x1234,
                first_job: false,
                runtime_multiversion_enabled: false,
            },
        )
        .unwrap();
        assert_eq!(plan.padded_coinbase_len, 128);
        assert!(matches!(
            &plan.ordered_steps[0],
            Bm1391StockPublicationStep::WriteDdrAndRequireExactReadback {
                buffer_offset: BM1391_STOCK_JOB_BUFFER_B_OFFSET,
                physical_address: 0x1f21_0000,
                bytes,
            } if bytes.len() == 128
        ));
        assert!(matches!(
            &plan.ordered_steps[1],
            Bm1391StockPublicationStep::WriteDdrAndRequireExactReadback {
                buffer_offset,
                physical_address: 0x1f21_0080,
                bytes,
            } if *buffer_offset == BM1391_STOCK_JOB_BUFFER_B_OFFSET + 128 && bytes.len() == 32
        ));
        let writes: Vec<_> = plan
            .ordered_steps
            .iter()
            .filter_map(|step| match step {
                Bm1391StockPublicationStep::Write(write) => Some(*write),
                _ => None,
            })
            .collect();
        let offsets: Vec<_> = writes.iter().map(|write| write.offset).collect();
        assert_eq!(
            offsets,
            [
                0x118, 0x8c, 0x124, 0x130, 0x140, 0x144, 0x148, 0x14c, 0x150, 0x154, 0x158, 0x15c,
                0x134, 0x138, 0x104, 0x108, 0x10c, 0x114, 0x11c, 0x88,
            ]
        );
        assert_eq!(writes[14].value, 0x0000_0402);
        assert_eq!(writes[18].value, 160);
        assert_eq!(writes[19].value, 0x8000_1234);
        assert!(matches!(
            plan.ordered_steps.last(),
            Some(
                Bm1391StockPublicationStep::ReadModifyWriteDhashWithStockRetry {
                    preserve_mask: BM1391_STOCK_SINGLE_CONTROL_PRESERVE,
                    set_mask: BM1391_STOCK_SINGLE_CONTROL_WORD,
                    ..
                }
            )
        ));
    }

    #[test]
    fn two_version_plan_writes_lane_one_multiplies_timeout_and_sets_first_job_steps() {
        let data = frame(true, 2, 8, 0);
        let job =
            decode_bm1391_stock_job_packet(Bm1391StockRelease::T15_1_92992_0_13, &data).unwrap();
        let plan = plan_bm1391_stock_job_publication(
            &job,
            Bm1391StockPlannerInput {
                buffer: Bm1391StockJobBuffer::A,
                observed_mem_total_kib: 1_000_001,
                fpga_memory_physical_base: 0x3f00_0000,
                timeout_base: 0x100,
                first_job: true,
                runtime_multiversion_enabled: true,
            },
        )
        .unwrap();
        assert!(plan
            .ordered_steps
            .contains(&Bm1391StockPublicationStep::Write(
                Bm1391StockRegisterWrite {
                    offset: BM1391_STOCK_VERSION_1_OFFSET,
                    value: 0x2000_4000,
                }
            )));
        assert!(plan
            .ordered_steps
            .contains(&Bm1391StockPublicationStep::Write(
                Bm1391StockRegisterWrite {
                    offset: BM1391_STOCK_TIMEOUT_OFFSET,
                    value: 0x8000_0200,
                }
            )));
        assert!(plan
            .ordered_steps
            .contains(&Bm1391StockPublicationStep::ReadModifyWriteSet {
                offset: BM1391_STOCK_NONCE_FIFO_CONTROL_OFFSET,
                set_mask: BM1391_STOCK_FIRST_NONCE_FIFO_ENABLE,
            }));
        assert!(matches!(
            plan.ordered_steps.last(),
            Some(Bm1391StockPublicationStep::ReadModifyWriteDhashWithStockRetry {
                preserve_mask: BM1391_STOCK_MULTI_CONTROL_PRESERVE,
                set_mask,
                ..
            }) if *set_mask == ((2 << 8) | BM1391_STOCK_MULTI_CONTROL_BASE)
        ));
        assert!(!plan.admits_live_dispatch());
        assert!(!plan.admits_share_submission());
        assert!(!plan.authenticates_stock_provenance());
    }

    #[test]
    fn planner_refuses_mode_count_address_and_timeout_ambiguity() {
        let single_data = frame(false, 0, 8, 0);
        let single =
            decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &single_data)
                .unwrap();
        let base = Bm1391StockPlannerInput {
            buffer: Bm1391StockJobBuffer::A,
            observed_mem_total_kib: 500_000,
            fpga_memory_physical_base: 0x1f00_0000,
            timeout_base: 1,
            first_job: false,
            runtime_multiversion_enabled: true,
        };
        assert_eq!(
            plan_bm1391_stock_job_publication(&single, base),
            Err(Bm1391StockJobPlanError::MultiversionModeMismatch)
        );

        let multi_data = frame(true, 4, 8, 0);
        let multi =
            decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &multi_data)
                .unwrap();
        assert_eq!(
            plan_bm1391_stock_job_publication(&multi, base),
            Err(Bm1391StockJobPlanError::UnsupportedMultiversionCount { observed: 4 })
        );
        let two_data = frame(true, 2, 8, 0);
        let two = decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &two_data)
            .unwrap();
        assert!(matches!(
            plan_bm1391_stock_job_publication(
                &two,
                Bm1391StockPlannerInput {
                    timeout_base: 0x1_0000,
                    ..base
                }
            ),
            Err(Bm1391StockJobPlanError::TimeoutOverflow { .. })
        ));
        assert_eq!(
            plan_bm1391_stock_job_publication(
                &two,
                Bm1391StockPlannerInput {
                    fpga_memory_physical_base: 0x2000_0000,
                    timeout_base: 1,
                    ..base
                }
            ),
            Err(Bm1391StockJobPlanError::UnsupportedPhysicalBase {
                observed: 0x2000_0000
            })
        );
        assert_eq!(
            plan_bm1391_stock_job_publication(
                &two,
                Bm1391StockPlannerInput {
                    fpga_memory_physical_base: 0x0f00_0000,
                    timeout_base: 1,
                    ..base
                }
            ),
            Err(Bm1391StockJobPlanError::PhysicalBaseMemTotalMismatch {
                observed: 0x0f00_0000,
                expected: 0x1f00_0000,
                mem_total_kib: 500_000,
            })
        );
    }

    #[test]
    fn planner_revalidates_public_packet_fields_before_producing_steps() {
        let data = frame(false, 0, 8, 1);
        let mut job =
            decode_bm1391_stock_job_packet(Bm1391StockRelease::S15_1_92992_0_14, &data).unwrap();
        let input = Bm1391StockPlannerInput {
            buffer: Bm1391StockJobBuffer::A,
            observed_mem_total_kib: 400_000,
            fpga_memory_physical_base: 0x0f00_0000,
            timeout_base: 1,
            first_job: false,
            runtime_multiversion_enabled: false,
        };
        job.merkle_count = 2;
        assert_eq!(
            plan_bm1391_stock_job_publication(&job, input),
            Err(Bm1391StockJobPlanError::InconsistentMerkleLength {
                declared: 2,
                observed: 32,
            })
        );
        job.merkle_count = 1;
        job.nonce2_offset = 1;
        assert_eq!(
            plan_bm1391_stock_job_publication(&job, input),
            Err(Bm1391StockJobPlanError::Nonce2WindowOutsideCoinbase {
                offset: 1,
                required_window: 8,
                coinbase_len: 8,
            })
        );
        job.nonce2_offset = 0;
        job.nonce2_size = 9;
        assert_eq!(
            plan_bm1391_stock_job_publication(&job, input),
            Err(Bm1391StockJobPlanError::Nonce2TooWide { observed: 9 })
        );
    }
}
