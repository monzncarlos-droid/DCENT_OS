//! Pure stock FPGA AsicBoost / version-rolling policy (G17).
//!
//! # Bar
//!
//! Exact S9j 4-way overt AsicBoost on the DHASH path:
//! - Version 0 at `0x130`; versions 1..3 at `0x164, 0x168, 0x16c`
//! - Packing: `version[i] = (base_version & !mask) | ((i << 13) & mask)` for `i = 0..3`
//! - DHASH_ACC_CONTROL bits 11:8 carry the admitted midstate count
//! - Job-id correlation remains G15 REG_JOB_ID low-byte spine (not redefined here)
//!
//! # Honesty
//!
//! Pure packing only. Does **not** invent share-dedup, nonce EXT layout changes,
//! or pool BIP-310 negotiation. No mask currently admits runtime four-way dispatch.
//!
//! Exact S9j disproves the former timestamp/target alias theory. Runtime
//! AsicBoost stays refused until the extra lane aperture and nonce/version
//! correlation are admitted by board/revision policy.

/// Number of stock FPGA version-rolling slots (native 4-way AsicBoost).
pub const STOCK_ASICBOOST_SLOT_COUNT: u8 = 4;

/// Exact S9j version-register addresses. Slot zero uses the ordinary version
/// register; the three extra lanes do not alias timestamp or target.
pub const STOCK_ASICBOOST_VERSION_REGS: [u32; 4] = [0x130, 0x164, 0x168, 0x16c];

/// Slot index → mask bit shift used by stock/bmminer packing (`i << 13`).
pub const STOCK_ASICBOOST_SLOT_BIT_SHIFT: u32 = 13;

/// Common BIP-320 / pool mask used in Braiins and stock AsicBoost paths.
pub const STOCK_ASICBOOST_BIP320_MASK: u32 = 0x1FFF_E000;

/// DHASH_ACC_CONTROL midstate-count field from the S9/BM1387 stock header,
/// independently matched by the exact signed S17e/T17e job finalizers.
pub const STOCK_DHASH_MIDSTATE_COUNT_MASK: u32 = 0x0f00;
pub const STOCK_DHASH_MIDSTATE_COUNT_SHIFT: u32 = 8;

/// Only the one-way and four-way shapes used by this stock S9 path are
/// admitted. This prevents the former false bit-12 boolean approximation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StockDhashMidstateMode {
    Single,
    FourWay,
}

impl StockDhashMidstateMode {
    pub const fn count(self) -> u8 {
        match self {
            Self::Single => 1,
            Self::FourWay => STOCK_ASICBOOST_SLOT_COUNT,
        }
    }
}

#[inline]
pub const fn stock_dhash_with_midstate_mode(dhash: u32, mode: StockDhashMidstateMode) -> u32 {
    (dhash & !STOCK_DHASH_MIDSTATE_COUNT_MASK)
        | ((mode.count() as u32) << STOCK_DHASH_MIDSTATE_COUNT_SHIFT)
}

#[inline]
pub const fn stock_dhash_midstate_count(dhash: u32) -> u8 {
    ((dhash & STOCK_DHASH_MIDSTATE_COUNT_MASK) >> STOCK_DHASH_MIDSTATE_COUNT_SHIFT) as u8
}

/// Whether the stock path should use 4-way AsicBoost dispatch.
///
/// The recovered S9j extra lanes extend beyond the current logical aperture,
/// and nonce/version correlation is not complete. Refuse every runtime mask
/// until both are admitted by a typed board/revision policy.
#[inline]
pub const fn stock_asicboost_admitted(_version_mask: u32) -> bool {
    false
}

/// Pure: pack four version words for stock FPGA `REG_BLOCK_HEADER_VERSION` slots.
///
/// Offline BIP-320 candidate packing only. The exact S9j lane values and
/// nonce/version correlation still require a separately admitted planner;
/// this helper is not consumed by live HAL mutation.
#[inline]
// clippy::indexing_slicing: `out` is `[u32; 4]` and the loop is `0u32..4`.
#[allow(clippy::indexing_slicing)]
pub fn stock_asicboost_version_words(base_version: u32, version_mask: u32) -> [u32; 4] {
    let mut out = [0u32; 4];
    for i in 0u32..4 {
        let version_bits = (i << STOCK_ASICBOOST_SLOT_BIT_SHIFT) & version_mask;
        out[i as usize] = (base_version & !version_mask) | version_bits;
    }
    out
}

/// Register address for AsicBoost version slot `i` (0..3).
#[inline]
pub const fn stock_asicboost_version_reg(slot: u8) -> u32 {
    STOCK_ASICBOOST_VERSION_REGS[(slot % STOCK_ASICBOOST_SLOT_COUNT) as usize]
}

/// Map RETURN_NONCE_EXT solution index (low byte) to a stock AsicBoost slot.
#[inline]
pub const fn stock_asicboost_slot_from_solution_idx(solution_idx: u8) -> u8 {
    solution_idx % STOCK_ASICBOOST_SLOT_COUNT
}

/// Version word for a nonce's solution index under stock packing.
///
/// **Honesty (G27 RE):** held T9+/S9SE stock bmminer does **not** use
/// `solution_idx % 4` for midstate/version selection — share rebuild keys
/// work_id + jobstore header_version. This helper remains for experimental
/// multi-version slot indexing only; do not treat it as stock-share SSOT.
#[inline]
// clippy::indexing_slicing: `words` is `[u32; 4]` and the index is
// `solution_idx % STOCK_ASICBOOST_SLOT_COUNT` (= 4), so it is 0..=3.
#[allow(clippy::indexing_slicing)]
pub fn stock_asicboost_version_for_solution(
    base_version: u32,
    version_mask: u32,
    solution_idx: u8,
) -> u32 {
    let words = stock_asicboost_version_words(base_version, version_mask);
    words[stock_asicboost_slot_from_solution_idx(solution_idx) as usize]
}

/// Exact stock S9/S9j merkle-branch width.
pub const STOCK_DMA_MERKLE_BRANCH_LEN: usize = 32;
/// Exact double-buffer slot size at offsets `0x200000` and `0x210000`.
pub const STOCK_DMA_JOB_SLOT_SIZE: usize = 0x1_0000;

/// Convert a numeric Stratum/header scalar into the stock FPGA MMIO word.
///
/// The V1 parser stores version, ntime, and nbits as numeric big-endian hex
/// values, while the little-endian stock bmminer structure reaches the raw
/// MMIO setter without another conversion. The register therefore observes
/// the byte-swapped numeric value.
pub const fn stock_fpga_header_scalar_word(numeric: u32) -> u32 {
    numeric.swap_bytes()
}

/// Recovered, bounded DDR payload and scalar registers for one stock S9 job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockDmaJobPlan {
    buffer_payload: Vec<u8>,
    padded_coinbase_len: usize,
    coinbase_layout: u32,
    nonce2_low: u32,
    nonce2_high: u32,
    merkle_count: u16,
    job_length: u16,
}

impl StockDmaJobPlan {
    pub fn buffer_payload(&self) -> &[u8] {
        &self.buffer_payload
    }

    pub const fn padded_coinbase_len(&self) -> usize {
        self.padded_coinbase_len
    }

    pub const fn coinbase_layout(&self) -> u32 {
        self.coinbase_layout
    }

    pub const fn nonce2_low(&self) -> u32 {
        self.nonce2_low
    }

    pub const fn nonce2_high(&self) -> u32 {
        self.nonce2_high
    }

    pub const fn merkle_count(&self) -> u16 {
        self.merkle_count
    }

    pub const fn job_length(&self) -> u16 {
        self.job_length
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockDmaJobPlanError {
    CoinbaseLengthOutOfBounds,
    MerkleLengthOverflow,
    PayloadLengthMismatch { expected: usize, observed: usize },
    Nonce2LengthUnsupported { observed: usize },
    Nonce2RangeOutOfBounds,
    CoinbasePaddingOverflow,
    CoinbaseBlockCountOverflow,
    MerkleCountOverflow,
    JobSlotOverflow { required: usize, slot_size: usize },
    JobLengthOverflow,
}

/// Build the exact S9/S9j SHA-padded DMA payload and its coupled registers.
///
/// `job_data` is the caller's raw `coinbase || merkle_branches` buffer. This
/// function prevents the historical field inversion at `0x104`: high 16 bits
/// are the nonce2 offset, not the raw coinbase length.
#[allow(clippy::indexing_slicing)]
pub fn plan_stock_dma_job(
    job_data: &[u8],
    raw_coinbase_len: usize,
    nonce2_offset: usize,
    nonce2_len: usize,
    merkle_count: usize,
) -> Result<StockDmaJobPlan, StockDmaJobPlanError> {
    if raw_coinbase_len > job_data.len() {
        return Err(StockDmaJobPlanError::CoinbaseLengthOutOfBounds);
    }
    let merkle_len = merkle_count
        .checked_mul(STOCK_DMA_MERKLE_BRANCH_LEN)
        .ok_or(StockDmaJobPlanError::MerkleLengthOverflow)?;
    let expected_len = raw_coinbase_len
        .checked_add(merkle_len)
        .ok_or(StockDmaJobPlanError::MerkleLengthOverflow)?;
    if expected_len != job_data.len() {
        return Err(StockDmaJobPlanError::PayloadLengthMismatch {
            expected: expected_len,
            observed: job_data.len(),
        });
    }
    if nonce2_len > 8 || nonce2_len > usize::from(u8::MAX) {
        return Err(StockDmaJobPlanError::Nonce2LengthUnsupported {
            observed: nonce2_len,
        });
    }
    let nonce2_end = nonce2_offset
        .checked_add(nonce2_len)
        .ok_or(StockDmaJobPlanError::Nonce2RangeOutOfBounds)?;
    if nonce2_offset > usize::from(u16::MAX) || nonce2_end > raw_coinbase_len {
        return Err(StockDmaJobPlanError::Nonce2RangeOutOfBounds);
    }
    let merkle_count_u16 =
        u16::try_from(merkle_count).map_err(|_| StockDmaJobPlanError::MerkleCountOverflow)?;
    let mut padded_coinbase =
        crate::sha256_padding::sha256_pad_message(&job_data[..raw_coinbase_len])
            .ok_or(StockDmaJobPlanError::CoinbasePaddingOverflow)?;
    let padded_coinbase_len = padded_coinbase.len();
    let block_count = padded_coinbase_len / 64;
    let block_count_u8 =
        u8::try_from(block_count).map_err(|_| StockDmaJobPlanError::CoinbaseBlockCountOverflow)?;
    let final_len = padded_coinbase_len
        .checked_add(merkle_len)
        .ok_or(StockDmaJobPlanError::JobLengthOverflow)?;
    if final_len > STOCK_DMA_JOB_SLOT_SIZE {
        return Err(StockDmaJobPlanError::JobSlotOverflow {
            required: final_len,
            slot_size: STOCK_DMA_JOB_SLOT_SIZE,
        });
    }
    let job_length =
        u16::try_from(final_len).map_err(|_| StockDmaJobPlanError::JobLengthOverflow)?;
    padded_coinbase.extend_from_slice(&job_data[raw_coinbase_len..]);

    let mut nonce2_bytes = [0u8; 8];
    nonce2_bytes[..nonce2_len].copy_from_slice(&job_data[nonce2_offset..nonce2_end]);
    let nonce2_initial = u64::from_le_bytes(nonce2_bytes);
    let coinbase_layout =
        ((nonce2_offset as u32) << 16) | ((nonce2_len as u32) << 8) | u32::from(block_count_u8);

    Ok(StockDmaJobPlan {
        buffer_payload: padded_coinbase,
        padded_coinbase_len,
        coinbase_layout,
        nonce2_low: nonce2_initial as u32,
        nonce2_high: (nonce2_initial >> 32) as u32,
        merkle_count: merkle_count_u16,
        job_length,
    })
}

// ---------------------------------------------------------------------------
// G27: stock FPGA BC SetConfig → BM1387 PLL (VIL multi-version path)
// ---------------------------------------------------------------------------
//
// Bar: T9+ bmminer `set_frequency_with_addr` (VIL / `opt_multi_version`) programs
// PLL via BC_COMMAND_BUFFER @ 0x0C4 + BC_WRITE_COMMAND trigger @ 0x0C0.
// PLL word SSOT is G16 `resolve_bm1387_pll` @ reg 0x0C — pure plans the BC frame
// only (no invent of non-VIL legacy 0x07/0x82 path).
//
// Held evidence: +/bmminer.dec/
// set_frequency_with_addr@319A4.c` + Braiins BM1387 SetConfig byte golden.

/// Stock FPGA BC_WRITE_COMMAND register offset (matches HAL `REG_BC_WRITE_COMMAND`).
pub const STOCK_REG_BC_WRITE_COMMAND: u32 = 0x0C0;
/// Stock FPGA BC_COMMAND_BUFFER word0 (matches HAL `REG_BC_COMMAND_BUFFER`).
///
/// T9+ `set_BC_command_buffer` writes `axi_fpga_addr[49..51]` = byte offsets
/// `0x0C4`, `0x0C8`, `0x0CC` (three consecutive 32-bit words).
pub const STOCK_REG_BC_COMMAND_BUFFER: u32 = 0x0C4;
/// BC_COMMAND_BUFFER word1 (cmd_buf[1] = PLL value).
pub const STOCK_REG_BC_COMMAND_BUFFER_W1: u32 = 0x0C8;
/// BC_COMMAND_BUFFER word2 (cmd_buf[2] = CRC5 << 24).
pub const STOCK_REG_BC_COMMAND_BUFFER_W2: u32 = 0x0CC;

/// VIL SetConfig header: broadcast (`mode=1`).
pub const STOCK_SET_CONFIG_HDR_BCAST: u8 = 0x58;
/// VIL SetConfig header: unicast (`mode=0`).
pub const STOCK_SET_CONFIG_HDR_UNICAST: u8 = 0x48;
/// VIL SetConfig length byte (9 payload bytes before CRC).
pub const STOCK_SET_CONFIG_LEN: u8 = 0x09;
/// BM1387 PLL parameter register on the VIL SetConfig path.
pub const STOCK_BM1387_SET_CONFIG_PLL_REG: u8 = 0x0C;

/// BC write trigger OR-mask (bit 31 + enable class). Stock: `| 0x8080_0000`.
pub const STOCK_BC_WRITE_TRIGGER_OR: u32 = 0x8080_0000;
/// Busy / in-flight bit on BC_WRITE_COMMAND (T9+ `value & 0x80000000`).
pub const STOCK_BC_BUSY_BIT: u32 = 0x8000_0000;
/// Chain field clear mask before re-inserting chain id (bits 19:16).
pub const STOCK_BC_CHAIN_FIELD_CLEAR: u32 = 0xFFF0_FFFF;
/// Post-trigger settle on VIL set_frequency path (µs) — after busy-wait completes.
pub const STOCK_BC_SET_CONFIG_SETTLE_US: u32 = 10_000;

// ---------------------------------------------------------------------------
// G33: T9+ post-trigger BC bit31 busy-wait (`set_BC_write_command@2F0A4.c`)
// ---------------------------------------------------------------------------
//
// Bar: After writing BC_WRITE_COMMAND with bit 31 set, stock polls
// `get_BC_write_command()` until bit 31 clears, sleeping 1 ms per still-busy
// iteration, for at most 3001 sleeps (~3 s). Writes without bit 31 do a single
// status read and return. This is **post-write** wait — not a pre-trigger
// ready-poll invent on the VIL set_freq path.

/// T9+ busy-wait budget: `v1 = 3001` before the while-loop.
pub const STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS: u32 = 3001;
/// T9+ `cgsleep_ms(1)` between still-busy polls.
pub const STOCK_BC_POST_TRIGGER_POLL_MS: u32 = 1;

/// Pure outcome of one post-trigger busy-wait status sample (T9+ control flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockBcBusyWaitStep {
    /// Status bit 31 clear — buffer ready.
    Ready,
    /// Still busy; sleep then re-enter with `attempts_after_sleep`.
    SleepThenRepoll {
        sleep_ms: u32,
        attempts_after_sleep: u32,
    },
    /// Still busy with one attempt left: T9+ sleeps then times out without
    /// another status read when `--v1` hits zero.
    SleepThenTimeout { sleep_ms: u32 },
    /// Budget already exhausted (defensive); still busy.
    Timeout,
}

/// Pure: does a **written** BC_WRITE_COMMAND value require the T9+ busy-wait?
///
/// T9+: `if ((value & 2147483648) != 0) { … while busy … } else { get once }`.
#[inline]
pub const fn stock_bc_write_requires_busy_wait(written_value: u32) -> bool {
    (written_value & STOCK_BC_BUSY_BIT) != 0
}

/// Pure: initial attempt budget when a write requires busy-wait (`Some(3001)`),
/// or `None` when only a single status read is needed (bit 31 clear on write).
#[inline]
pub const fn stock_bc_post_trigger_wait_budget(written_value: u32) -> Option<u32> {
    if stock_bc_write_requires_busy_wait(written_value) {
        Some(STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS)
    } else {
        None
    }
}

/// Pure: one step of the T9+ post-write busy-wait given a status sample and
/// remaining sleep budget (`attempts_remaining` starts at 3001).
///
/// Control flow matches:
/// ```c
/// while ((get_BC_write_command() & 0x80000000) != 0) {
///     cgsleep_ms(1);
///     if (!--v1) { /* timeout */ return; }
/// }
/// ```
#[inline]
pub const fn stock_bc_busy_wait_step(status: u32, attempts_remaining: u32) -> StockBcBusyWaitStep {
    if stock_bc_ready(status) {
        return StockBcBusyWaitStep::Ready;
    }
    // Still busy (bit 31 set).
    if attempts_remaining == 0 {
        return StockBcBusyWaitStep::Timeout;
    }
    if attempts_remaining == 1 {
        // Sleep once, then T9+ hits `!--v1` → timeout without re-read.
        return StockBcBusyWaitStep::SleepThenTimeout {
            sleep_ms: STOCK_BC_POST_TRIGGER_POLL_MS,
        };
    }
    StockBcBusyWaitStep::SleepThenRepoll {
        sleep_ms: STOCK_BC_POST_TRIGGER_POLL_MS,
        attempts_after_sleep: attempts_remaining - 1,
    }
}

/// Pure plan for one stock BC SetConfig write (VIL multi-version form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockBcSetConfigPlan {
    /// Logical chain index (bits 19:16 of BC_WRITE_COMMAND).
    pub chain: u8,
    /// Chip address byte in the VIL frame (`0` for broadcast).
    pub chip_addr: u8,
    /// `true` → hdr `0x58`; `false` → hdr `0x48`.
    pub broadcast: bool,
    /// ASIC register (BM1387 PLL = `0x0C`).
    pub reg: u8,
    /// 32-bit register value (G16 PLL word for frequency path).
    pub value: u32,
    /// 9-byte wire frame: hdr,len,addr,reg,value_BE[4],crc5.
    pub frame: [u8; 9],
    /// Three words for `BC_COMMAND_BUFFER` (matches stock packing).
    pub cmd_buf: [u32; 3],
    /// Settle after trigger (µs).
    pub settle_us: u32,
}

/// Bitmain BM13xx CRC5 (poly x^5+x^2+1, init 0x1F, MSB-first) over `bit_len` bits.
///
/// Same algorithm as `dcentrald_api_types::zhiju_eeprom::bitmain_crc5` / cgminer
/// BM13xx CMD CRC5 — pure copy so `dcentrald-common` stays free of api-types.
// clippy::indexing_slicing: `bit_len` is clamped to `data.len() * 8` below, so
// `data[bit_index / 8]` is in-bounds for every `bit_index < bit_len`.
#[allow(clippy::indexing_slicing)]
pub fn stock_bitmain_crc5(data: &[u8], bit_len: usize) -> u8 {
    debug_assert!(bit_len <= data.len() * 8);
    // The debug_assert above is compiled OUT in release, so on a shipped image an
    // over-long `bit_len` would index past `data` and panic. Clamp to the bits we
    // actually have: a bounded CRC over the real bytes beats a release panic.
    let bit_len = bit_len.min(data.len() * 8);
    let mut reg: u8 = 0x1F;
    for bit_index in 0..bit_len {
        let byte = data[bit_index / 8];
        let input_bit = (byte >> (7 - (bit_index % 8))) & 1;
        let top = (reg >> 4) & 1;
        let feedback = top ^ input_bit;
        reg = ((reg << 1) & 0x1F) ^ feedback ^ (feedback << 2);
    }
    reg & 0x1F
}

/// Whether BC_WRITE_COMMAND is ready for a new trigger (bit 31 clear as i32 ≥ 0).
#[inline]
pub const fn stock_bc_ready(status: u32) -> bool {
    (status as i32) >= 0
}

/// Pure: merge chain + trigger into a sampled BC_WRITE_COMMAND status word.
///
/// Stock: `status & 0xFFF0_FFFF | (chain << 16) | 0x8080_0000`.
#[inline]
pub const fn stock_bc_write_command(status: u32, chain: u8) -> u32 {
    (status & STOCK_BC_CHAIN_FIELD_CLEAR) | ((chain as u32) << 16) | STOCK_BC_WRITE_TRIGGER_OR
}

/// Pure plan: VIL SetConfig for an arbitrary register value (BC buffer + frame).
pub fn plan_stock_bc_set_config(
    chain: u8,
    chip_addr: u8,
    broadcast: bool,
    reg: u8,
    value: u32,
) -> StockBcSetConfigPlan {
    let hdr = if broadcast {
        STOCK_SET_CONFIG_HDR_BCAST
    } else {
        STOCK_SET_CONFIG_HDR_UNICAST
    };
    let mut frame = [0u8; 9];
    frame[0] = hdr;
    frame[1] = STOCK_SET_CONFIG_LEN;
    frame[2] = chip_addr;
    frame[3] = reg;
    frame[4] = (value >> 24) as u8;
    frame[5] = (value >> 16) as u8;
    frame[6] = (value >> 8) as u8;
    frame[7] = value as u8;
    let crc = stock_bitmain_crc5(&frame[..8], 64);
    frame[8] = crc;
    // cmd_buf[0] = (hdr << 24) | 0x0009000C | (addr << 8) for reg=0x0C / len=9
    // General form: (hdr<<24) | ((len as u32)<<16) | ((chip_addr as u32)<<8) | (reg as u32)
    let cmd0 = ((hdr as u32) << 24)
        | ((STOCK_SET_CONFIG_LEN as u32) << 16)
        | ((chip_addr as u32) << 8)
        | (reg as u32);
    let cmd1 = value;
    let cmd2 = (crc as u32) << 24;
    StockBcSetConfigPlan {
        chain,
        chip_addr,
        broadcast,
        reg,
        value,
        frame,
        cmd_buf: [cmd0, cmd1, cmd2],
        settle_us: STOCK_BC_SET_CONFIG_SETTLE_US,
    }
}

/// Pure plan: BM1387 frequency via G16 PLL word + VIL BC SetConfig @ reg `0x0C`.
pub fn plan_stock_bm1387_set_freq(
    chain: u8,
    chip_addr: u8,
    broadcast: bool,
    freq_mhz: u16,
) -> StockBcSetConfigPlan {
    let sol = crate::pll_model::resolve_bm1387_pll(freq_mhz);
    plan_stock_bc_set_config(
        chain,
        chip_addr,
        broadcast,
        STOCK_BM1387_SET_CONFIG_PLL_REG,
        sol.register_value,
    )
}

// ---------------------------------------------------------------------------
// G35: stock VIL chain_inactive + set_address + software_set_address pure SSOT
// ---------------------------------------------------------------------------
//
// Bar: T9+ bmminer VIL (`opt_multi_version`) `chain_inactive@33A1C.c`,
// `set_address@33BC0.c`, `software_set_address@33F30.c` — BC_COMMAND_BUFFER
// frames + pre-ready poll → buffer → trigger (status from pre-ready sample).
// Do **not** invent non-VIL legacy path or full `open_core` work dispatch.
//
// Pre-ready note: T9+ pre-poll is unbounded; pure uses the same 3001×1 ms
// fail-safe cap as G33 post-trigger so a stuck BC cannot hang the daemon
// (honest safety delta, not invent of the inactive/addr wire words).

/// VIL chain_inactive header byte (`buf[0]=85`).
pub const STOCK_VIL_CHAIN_INACTIVE_HDR: u8 = 0x55;
/// VIL set_address header byte (`buf[0]=65`).
pub const STOCK_VIL_SET_ADDRESS_HDR: u8 = 0x41;
/// VIL short-command length byte (`buf[1]=5` for inactive/set_address).
pub const STOCK_VIL_SHORT_CMD_LEN: u8 = 0x05;
/// T9+ `software_set_address` hardcodes `addrInterval = 4`.
pub const STOCK_SOFTWARE_SET_ADDRESS_INTERVAL: u8 = 4;
/// T9+ fires chain_inactive three times before the address ladder.
pub const STOCK_SOFTWARE_SET_ADDRESS_INACTIVE_REPEATS: u8 = 3;
/// T9+ `cgsleep_ms(30)` between inactive repeats and between set_address steps.
pub const STOCK_SOFTWARE_SET_ADDRESS_DWELL_MS: u32 = 30;
/// Fail-safe cap for T9+ pre-ready poll (T9+ is unbounded; pure is bounded).
pub const STOCK_BC_PRE_READY_WAIT_MAX_ATTEMPTS: u32 = STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS;

/// Pure VIL short BC command (chain_inactive / set_address) — not SetConfig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockBcVilCmdPlan {
    pub chain: u8,
    /// First four payload bytes before CRC5 (32-bit CRC span).
    pub payload4: [u8; 4],
    pub crc5: u8,
    pub cmd_buf: [u32; 3],
    /// Always true for T9+ VIL inactive/address (pre-poll then buffer+trigger).
    pub pre_ready_poll: bool,
}

/// One step of pure `software_set_address` composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockSoftwareSetAddressOp {
    /// Execute a VIL BC command with pre-ready poll order.
    Bc(StockBcVilCmdPlan),
    /// Inter-step dwell (T9+ 30 ms).
    DelayMs(u32),
}

/// Pure: one step of the T9+ **pre-buffer** ready poll.
///
/// T9+: `while ((get_BC_write_command() as i32) < 0) cgsleep_ms(1);`
/// Pure adds a fail-safe attempt budget (see [`STOCK_BC_PRE_READY_WAIT_MAX_ATTEMPTS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockBcPreReadyStep {
    /// Bit 31 clear — ready; use this `status` for trigger merge.
    Ready,
    SleepThenRepoll {
        sleep_ms: u32,
        attempts_after_sleep: u32,
    },
    Timeout,
}

#[inline]
pub const fn stock_bc_pre_ready_step(status: u32, attempts_remaining: u32) -> StockBcPreReadyStep {
    if stock_bc_ready(status) {
        return StockBcPreReadyStep::Ready;
    }
    if attempts_remaining == 0 {
        return StockBcPreReadyStep::Timeout;
    }
    StockBcPreReadyStep::SleepThenRepoll {
        sleep_ms: STOCK_BC_POST_TRIGGER_POLL_MS,
        attempts_after_sleep: attempts_remaining - 1,
    }
}

/// Pure: VIL chain_inactive BC plan (T9+ multi-version).
///
/// Wire: `cmd_buf[0]=0x55050000`, `cmd_buf[1]=CRC5<<24`, `cmd_buf[2]=0`.
pub fn plan_stock_bc_chain_inactive_vil(chain: u8) -> StockBcVilCmdPlan {
    let payload4 = [
        STOCK_VIL_CHAIN_INACTIVE_HDR,
        STOCK_VIL_SHORT_CMD_LEN,
        0x00,
        0x00,
    ];
    let crc5 = stock_bitmain_crc5(&payload4, 32);
    let cmd0 = ((payload4[0] as u32) << 24)
        | ((payload4[1] as u32) << 16)
        | ((payload4[2] as u32) << 8)
        | (payload4[3] as u32);
    debug_assert_eq!(cmd0, 0x5505_0000);
    StockBcVilCmdPlan {
        chain,
        payload4,
        crc5,
        cmd_buf: [cmd0, (crc5 as u32) << 24, 0],
        pre_ready_poll: true,
    }
}

/// Pure: VIL set_address BC plan (T9+ multi-version, mode=0 unicast path).
///
/// Wire: `cmd_buf[0]=0x41050000 | (addr<<8)`, `cmd_buf[1]=CRC5<<24`.
pub fn plan_stock_bc_set_address_vil(chain: u8, chip_addr: u8) -> StockBcVilCmdPlan {
    let payload4 = [
        STOCK_VIL_SET_ADDRESS_HDR,
        STOCK_VIL_SHORT_CMD_LEN,
        chip_addr,
        0x00,
    ];
    let crc5 = stock_bitmain_crc5(&payload4, 32);
    let cmd0 = 0x4105_0000 | ((chip_addr as u32) << 8);
    StockBcVilCmdPlan {
        chain,
        payload4,
        crc5,
        cmd_buf: [cmd0, (crc5 as u32) << 24, 0],
        pre_ready_poll: true,
    }
}

/// Pure buffer write triple for a VIL short command (same offsets as SetConfig).
#[inline]
pub fn stock_bc_vil_cmd_buffer_writes(plan: &StockBcVilCmdPlan) -> [(u32, u32); 3] {
    [
        (STOCK_REG_BC_COMMAND_BUFFER, plan.cmd_buf[0]),
        (STOCK_REG_BC_COMMAND_BUFFER_W1, plan.cmd_buf[1]),
        (STOCK_REG_BC_COMMAND_BUFFER_W2, plan.cmd_buf[2]),
    ]
}

/// Pure trigger word from a **pre-ready** status sample (T9+ inactive/address).
#[inline]
pub fn stock_bc_vil_cmd_trigger_write(
    plan: &StockBcVilCmdPlan,
    pre_ready_status: u32,
) -> (u32, u32) {
    (
        STOCK_REG_BC_WRITE_COMMAND,
        stock_bc_write_command(pre_ready_status, plan.chain),
    )
}

/// Pure: T9+ `software_set_address` for one chain (inactive×3 + full addr ladder).
///
/// `addr_interval` of 0 falls back to [`STOCK_SOFTWARE_SET_ADDRESS_INTERVAL`] (4).
/// Address steps: `0, interval, 2*interval, …` while count `< 256/interval`.
/// After every inactive and every set_address: DelayMs(30) (T9+ byte-faithful).
/// open_core is a separate pure plan: [`plan_stock_open_core_one_chain_vil`].
pub fn plan_stock_software_set_address(
    chain: u8,
    addr_interval: u8,
) -> Vec<StockSoftwareSetAddressOp> {
    let interval = if addr_interval == 0 {
        STOCK_SOFTWARE_SET_ADDRESS_INTERVAL
    } else {
        addr_interval
    };
    let steps = 256u16 / u16::from(interval);
    let mut ops = Vec::with_capacity(
        (STOCK_SOFTWARE_SET_ADDRESS_INACTIVE_REPEATS as usize) * 2 + (steps as usize) * 2,
    );
    for _ in 0..STOCK_SOFTWARE_SET_ADDRESS_INACTIVE_REPEATS {
        ops.push(StockSoftwareSetAddressOp::Bc(
            plan_stock_bc_chain_inactive_vil(chain),
        ));
        ops.push(StockSoftwareSetAddressOp::DelayMs(
            STOCK_SOFTWARE_SET_ADDRESS_DWELL_MS,
        ));
    }
    let mut addr: u16 = 0;
    for _ in 0..steps {
        ops.push(StockSoftwareSetAddressOp::Bc(
            plan_stock_bc_set_address_vil(chain, addr as u8),
        ));
        ops.push(StockSoftwareSetAddressOp::DelayMs(
            STOCK_SOFTWARE_SET_ADDRESS_DWELL_MS,
        ));
        addr = addr.saturating_add(u16::from(interval));
    }
    ops
}

// ---------------------------------------------------------------------------
// G36: stock VIL open_core_one_chain pure SSOT (T9+ open_core_one_chain@35420)
// ---------------------------------------------------------------------------
//
// Bar: T9+ bmminer VIL (`opt_multi_version`) path only — DHASH RMW + hash_count=0
// + MiscCtrl gateblk SetConfig @ reg 0x1C + 114 dummy TW works via
// set_TW_write_command_vil + optional nullwork BC bit. Do **not** invent the
// non-VIL `gateblk[0]=0x86` branch.
//
// Held: +/bmminer.dec/
// open_core_one_chain@35420.c` + `set_TW_write_command_vil@2E8E0.c`.

/// FPGA BUFFER_SPACE (axi[3]) — work-FIFO ready bitmask.
pub const STOCK_REG_BUFFER_SPACE: u32 = 0x0C;
/// Task-write command base (axi[16]) — 13-word VIL work burst.
pub const STOCK_REG_TW_WRITE_COMMAND: u32 = 0x40;
/// DHASH_ACC_CONTROL (axi[64]).
pub const STOCK_REG_DHASH_ACC_CONTROL: u32 = 0x100;
/// HASH_COUNTING_NUMBER (axi[36]).
pub const STOCK_REG_HASH_COUNTING_NUMBER: u32 = 0x090;
/// BM1387 MiscCtrl register on VIL SetConfig (gateblk) path.
pub const STOCK_BM1387_MISC_CTRL_REG: u8 = 0x1C;
/// T9+ open_core dummy work count (v2 runs 0..113 inclusive).
pub const STOCK_OPEN_CORE_DUMMY_WORK_COUNT: u32 = 114;
/// T9+ buffer-space wait budget (`v22 = 3001`).
pub const STOCK_OPEN_CORE_BUFFER_WAIT_MAX_ATTEMPTS: u32 = 3001;
/// T9+ `cgsleep_us(1000)` between buffer-space polls.
pub const STOCK_OPEN_CORE_BUFFER_POLL_US: u32 = 1_000;
/// T9+ settle after gateblk BC trigger.
pub const STOCK_OPEN_CORE_GATEBLK_SETTLE_US: u32 = 10_000;
/// T9+ settle after BC nullwork prelude write.
pub const STOCK_OPEN_CORE_BC_PRELUDE_SETTLE_US: u32 = 1_000;
/// Bits cleared on DHASH before open_core: `current & 0xFFFF7FDF`.
pub const STOCK_OPEN_CORE_DHASH_CLEAR_MASK: u32 = 0xFFFF_7FDF;
/// VIL mode bit set on DHASH during open_core (`| 0x8000`).
pub const STOCK_OPEN_CORE_DHASH_VIL_BIT: u32 = 0x8000;
/// BC_WRITE_COMMAND bit 23 set in nullwork prelude (`| 0x800000`).
pub const STOCK_OPEN_CORE_BC_NULLWORK_PRELUDE_BIT: u32 = 0x80_0000;
/// BC_WRITE_COMMAND bit 22 set when nullwork_enable after dummy works.
pub const STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT: u32 = 0x40_0000;
/// AND-mask for BC prelude sample (`status & 0xFFB0FFFF`).
pub const STOCK_OPEN_CORE_BC_PRELUDE_AND: u32 = 0xFFB0_FFFF;
/// Fixed high half of gateblk MiscCtrl value before baud nibble (`| 0x40200080`).
pub const STOCK_OPEN_CORE_GATEBLK_VALUE_BASE: u32 = 0x4020_0080;
/// First dummy work type byte (T9+ `work_type = 17`).
pub const STOCK_OPEN_CORE_FIRST_WORK_TYPE: u8 = 17;
/// Subsequent dummy work type byte (T9+ `work_type = 1`).
pub const STOCK_OPEN_CORE_REST_WORK_TYPE: u8 = 1;
/// Typical stock S9 baud divisor low-5 seen on BC_WRITE idle (`0x1A`).
pub const STOCK_OPEN_CORE_DEFAULT_BAUD_DIV_LOW5: u8 = 0x1A;
/// Default opt_multi_version midstate field (non-AsicBoost open_core).
pub const STOCK_OPEN_CORE_DEFAULT_MULTI_VERSION: u8 = 1;

/// Pure: DHASH value for open_core **entry** (T9+ VIL).
#[inline]
pub const fn stock_open_core_dhash_entry(current: u32, multi_version: u8) -> u32 {
    ((multi_version as u32) & 0xF) << 8
        | STOCK_OPEN_CORE_DHASH_VIL_BIT
        | (current & STOCK_OPEN_CORE_DHASH_CLEAR_MASK)
}

/// Pure: DHASH value for open_core **exit** (T9+ VIL).
#[inline]
pub const fn stock_open_core_dhash_exit(current: u32, multi_version: u8) -> u32 {
    current | ((multi_version as u32) & 0xF) << 8 | STOCK_OPEN_CORE_DHASH_VIL_BIT
}

/// Pure: MiscCtrl gateblk value for VIL open_core (baud low-5 in bits 12:8 of v17 path).
///
/// T9+: `v17 = (baud & 0x1F) | 0x80`; `cmd_buf[1] = (v17 << 8) | 0x40200080`.
#[inline]
pub const fn stock_open_core_gateblk_misc_value(baud_div_low5: u8) -> u32 {
    let v17 = (baud_div_low5 & 0x1F) | 0x80;
    ((v17 as u32) << 8) | STOCK_OPEN_CORE_GATEBLK_VALUE_BASE
}

/// Pure: BC_WRITE_COMMAND after nullwork prelude sample.
#[inline]
pub const fn stock_open_core_bc_nullwork_prelude(status: u32, chain: u8) -> u32 {
    (status & STOCK_OPEN_CORE_BC_PRELUDE_AND)
        | (((chain as u32) & 0xF) << 16)
        | STOCK_OPEN_CORE_BC_NULLWORK_PRELUDE_BIT
}

/// Pure: BC_WRITE_COMMAND after nullwork enable (end of open_core when enabled).
#[inline]
pub const fn stock_open_core_bc_nullwork_enable(status: u32) -> u32 {
    status | STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT
}

/// Pure shutdown RMW from signed S9j `bitmain_c5_shutdown@0x2db64`.
///
/// Nullwork is disabled before DHASH RUN is cleared so the FPGA cannot keep
/// emitting dummy work while software proceeds to rail teardown.
pub const fn stock_shutdown_bc_disable_nullwork(status: u32) -> u32 {
    status & !STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT
}

/// Pure: BUFFER_SPACE has room for chain (bit set).
#[inline]
pub const fn stock_buffer_space_ready(status: u32, chain: u8) -> bool {
    (status & (1u32 << (chain & 31))) != 0
}

/// Pure step for BUFFER_SPACE wait (T9+ wait for bit **set**, budget 3001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockBufferSpaceWaitStep {
    Ready,
    SleepThenRepoll {
        sleep_us: u32,
        attempts_after_sleep: u32,
    },
    Timeout,
}

#[inline]
pub const fn stock_buffer_space_wait_step(
    status: u32,
    chain: u8,
    attempts_remaining: u32,
) -> StockBufferSpaceWaitStep {
    if stock_buffer_space_ready(status, chain) {
        return StockBufferSpaceWaitStep::Ready;
    }
    if attempts_remaining == 0 {
        return StockBufferSpaceWaitStep::Timeout;
    }
    // T9+: while busy { sleep 1ms; if !--v22 timeout }. attempts starts at 3001.
    StockBufferSpaceWaitStep::SleepThenRepoll {
        sleep_us: STOCK_OPEN_CORE_BUFFER_POLL_US,
        attempts_after_sleep: attempts_remaining - 1,
    }
}

/// Pure: one 13-word VIL TW dummy-work burst for open_core.
///
/// T9+ packing (`open_core_one_chain` VIL):
/// - `buf_vil_tw[0] = work_type<<24 | chain_id<<16` (reserved1 = 0)
/// - `buf_vil_tw[1] = work_count` (0)
/// - packs struct bytes until `data[4]`: header + work_count + data[0..3]
/// - `memset(buf_vil_tw[5], 0, 32)` → words 5..12 zero
///
/// `work_index` 0 → work_type 17; else work_type 1. Data bytes are 0xFF.
pub fn stock_open_core_dummy_tw_words(chain: u8, work_index: u32) -> [u32; 13] {
    let work_type = if work_index == 0 {
        STOCK_OPEN_CORE_FIRST_WORK_TYPE
    } else {
        STOCK_OPEN_CORE_REST_WORK_TYPE
    };
    let chain_id = chain | 0x80;
    let mut words = [0u32; 13];
    words[0] = ((work_type as u32) << 24) | ((chain_id as u32) << 16);
    words[1] = 0; // work_count
                  // Pack (work_type, reserved1[0]=0, reserved1[1]=0, chain_id)
    words[2] = ((work_type as u32) << 24) | (chain_id as u32);
    words[3] = 0; // work_count field as 4 zero bytes
    words[4] = 0xFFFF_FFFF; // data[0..3] all 0xFF
                            // words[5..12] remain 0
    words
}

/// One pure step of VIL open_core_one_chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockOpenCoreOp {
    /// RMW DHASH_ACC_CONTROL to entry formula (needs current read at execute).
    DhashEntry {
        multi_version: u8,
    },
    /// Write HASH_COUNTING_NUMBER = 0.
    ClearHashCounting,
    /// Sample BC_WRITE_COMMAND and write nullwork prelude.
    BcNullworkPrelude {
        chain: u8,
    },
    DelayUs(u32),
    /// Gateblk MiscCtrl SetConfig (G27 plan @ reg 0x1C) — buffer→sample→trigger+G33.
    GateblkSetConfig(StockBcSetConfigPlan),
    /// Wait BUFFER_SPACE bit for chain (budget 3001 × 1 ms).
    WaitBufferSpace {
        chain: u8,
    },
    /// Write 13 TW words starting at [`STOCK_REG_TW_WRITE_COMMAND`].
    TwWriteVil {
        words: [u32; 13],
    },
    /// Optional: sample BC and OR nullwork enable bit 22.
    BcNullworkEnable,
    /// RMW DHASH_ACC_CONTROL to exit formula.
    DhashExit {
        multi_version: u8,
    },
}

/// Pure: VIL open_core_one_chain plan (T9+).
///
/// `baud_div_low5` is the engine residual (`dev->baud` low 5 bits). Use
/// [`STOCK_OPEN_CORE_DEFAULT_BAUD_DIV_LOW5`] when unknown (S9-class idle BC).
/// `multi_version` is `opt_multi_version` low nibble (default 1).
/// `nullwork_enable` matches T9+ `nullwork_enable` (typically true on init).
///
/// **EXPERIMENTAL** maturity for live execute; pure encodes held VIL path only.
pub fn plan_stock_open_core_one_chain_vil(
    chain: u8,
    baud_div_low5: u8,
    multi_version: u8,
    nullwork_enable: bool,
) -> Vec<StockOpenCoreOp> {
    let mv = multi_version & 0xF;
    let mut ops = Vec::with_capacity(8 + STOCK_OPEN_CORE_DUMMY_WORK_COUNT as usize * 2);
    ops.push(StockOpenCoreOp::DhashEntry { multi_version: mv });
    ops.push(StockOpenCoreOp::ClearHashCounting);
    ops.push(StockOpenCoreOp::BcNullworkPrelude { chain });
    ops.push(StockOpenCoreOp::DelayUs(
        STOCK_OPEN_CORE_BC_PRELUDE_SETTLE_US,
    ));
    let gate_val = stock_open_core_gateblk_misc_value(baud_div_low5);
    // T9+ hardcodes cmd0 = 0x5809001C (broadcast SetConfig reg 0x1C).
    let gate = plan_stock_bc_set_config(chain, 0, true, STOCK_BM1387_MISC_CTRL_REG, gate_val);
    debug_assert_eq!(gate.cmd_buf[0], 0x5809_001C);
    debug_assert_eq!(gate.cmd_buf[1], gate_val);
    // Gateblk plan carries settle_us=10_000 (G27); execute_stock_bc_set_config
    // applies it — do not double-delay (G36 critic hygiene).
    ops.push(StockOpenCoreOp::GateblkSetConfig(gate));
    for i in 0..STOCK_OPEN_CORE_DUMMY_WORK_COUNT {
        ops.push(StockOpenCoreOp::WaitBufferSpace { chain });
        ops.push(StockOpenCoreOp::TwWriteVil {
            words: stock_open_core_dummy_tw_words(chain, i),
        });
    }
    if nullwork_enable {
        ops.push(StockOpenCoreOp::BcNullworkEnable);
    }
    ops.push(StockOpenCoreOp::DhashExit { multi_version: mv });
    ops
}

// ---------------------------------------------------------------------------
// G37: open_core BUFFER timeout policy + pure write-trace golden (offline)
// ---------------------------------------------------------------------------
//
// Bar: T9+ on BUFFER_SPACE wait failure logs and `goto LABEL_x5612` — **still**
// runs DHASH exit, skips remaining TW and nullwork enable. Pure SSOT for that
// policy + pure expected write trace for happy-path recording-mock A/B.

/// Pure: T9+ BUFFER_SPACE timeout continues to DHASH exit (does not hard-abort
/// open_core before exit RMW). Remaining TW + nullwork enable are skipped.
#[inline]
pub const fn stock_open_core_buffer_timeout_continues_to_dhash_exit() -> bool {
    true
}

/// Pure: after BUFFER_SPACE timeout, skip remaining TW writes (T9+ goto).
#[inline]
pub const fn stock_open_core_buffer_timeout_skips_remaining_tw() -> bool {
    true
}

/// Pure: after BUFFER_SPACE timeout, skip nullwork enable (T9+ jumps past it).
#[inline]
pub const fn stock_open_core_buffer_timeout_skips_nullwork_enable() -> bool {
    true
}

/// Simulated register snapshot for pure open_core write-trace goldens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockOpenCoreSimState {
    /// Current DHASH_ACC_CONTROL.
    pub dhash: u32,
    /// Current BC_WRITE_COMMAND (prelude / gate sample / nullwork).
    pub bc_write: u32,
    /// BUFFER_SPACE bitmask — bit `chain` set means ready.
    pub buffer_space: u32,
}

impl StockOpenCoreSimState {
    /// Happy-path defaults: DHASH idle init bit, BC clear, all buffer bits ready.
    pub const fn happy_path() -> Self {
        Self {
            dhash: 0x0000_0020,
            bc_write: 0x0000_0000,
            buffer_space: 0xFFFF_FFFF,
        }
    }
}

/// Pure offline report for open_core execute (happy path or buffer timeout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockOpenCoreSimReport {
    /// Ordered register writes `(offset, value)`.
    pub writes: Vec<(u32, u32)>,
    /// True if BUFFER_SPACE wait timed out (T9+ log + continue to DHASH exit).
    pub buffer_space_timeout: bool,
}

/// Pure: simulate open_core op list into a write trace (no I/O, no sleep).
///
/// Gateblk expands to G32 buffer→sample→trigger (sample uses `state.bc_write`).
/// BUFFER_SPACE timeout uses a zero budget when `force_buffer_timeout` is true
/// (first WaitBufferSpace fails immediately) so offline goldens stay tiny.
///
/// Policy: on timeout, skip remaining TW + nullwork enable; still apply DhashExit
/// (T9+ `LABEL_x5612`).
pub fn stock_open_core_sim_write_trace(
    ops: &[StockOpenCoreOp],
    mut state: StockOpenCoreSimState,
    force_buffer_timeout: bool,
) -> StockOpenCoreSimReport {
    let mut writes = Vec::new();
    let mut buffer_timeout = false;
    let mut saw_first_wait = false;

    for op in ops {
        match op {
            StockOpenCoreOp::DhashEntry { multi_version } => {
                let v = stock_open_core_dhash_entry(state.dhash, *multi_version);
                writes.push((STOCK_REG_DHASH_ACC_CONTROL, v));
                state.dhash = v;
            }
            StockOpenCoreOp::ClearHashCounting => {
                writes.push((STOCK_REG_HASH_COUNTING_NUMBER, 0));
            }
            StockOpenCoreOp::BcNullworkPrelude { chain } => {
                let v = stock_open_core_bc_nullwork_prelude(state.bc_write, *chain);
                writes.push((STOCK_REG_BC_WRITE_COMMAND, v));
                state.bc_write = v;
            }
            StockOpenCoreOp::DelayUs(_) => {}
            StockOpenCoreOp::GateblkSetConfig(plan) => {
                // G32 order: buffer then sample(state.bc_write) then trigger.
                for w in stock_bc_set_config_buffer_writes(plan) {
                    writes.push(w);
                }
                let trig = stock_bc_set_config_trigger_write(plan, state.bc_write);
                writes.push(trig);
                state.bc_write = trig.1;
                // Post-trigger busy-wait has no extra writes when status ready.
            }
            StockOpenCoreOp::WaitBufferSpace { chain } => {
                if buffer_timeout && stock_open_core_buffer_timeout_skips_remaining_tw() {
                    continue;
                }
                let ready = stock_buffer_space_ready(state.buffer_space, *chain);
                let fail = force_buffer_timeout && !saw_first_wait;
                saw_first_wait = true;
                if !ready || fail {
                    buffer_timeout = true;
                    // T9+: no TW on this iteration; remaining TW skipped.
                    continue;
                }
            }
            StockOpenCoreOp::TwWriteVil { words } => {
                if buffer_timeout && stock_open_core_buffer_timeout_skips_remaining_tw() {
                    continue;
                }
                for (i, w) in words.iter().enumerate() {
                    writes.push((STOCK_REG_TW_WRITE_COMMAND + (i as u32) * 4, *w));
                }
            }
            StockOpenCoreOp::BcNullworkEnable => {
                if buffer_timeout && stock_open_core_buffer_timeout_skips_nullwork_enable() {
                    continue;
                }
                let v = stock_open_core_bc_nullwork_enable(state.bc_write);
                writes.push((STOCK_REG_BC_WRITE_COMMAND, v));
                state.bc_write = v;
            }
            StockOpenCoreOp::DhashExit { multi_version } => {
                // Always runs (T9+ LABEL_x5612), even after buffer timeout.
                let v = stock_open_core_dhash_exit(state.dhash, *multi_version);
                writes.push((STOCK_REG_DHASH_ACC_CONTROL, v));
                state.dhash = v;
            }
        }
    }

    StockOpenCoreSimReport {
        writes,
        buffer_space_timeout: buffer_timeout,
    }
}

// ---------------------------------------------------------------------------
// G38: Stock VIL set_baud pure SSOT (T9+ set_baud@342D8.c)
// ---------------------------------------------------------------------------
//
// Bar: T9+ VIL set_baud — per existing chain BC SetConfig broadcast MiscCtrl
// reg 0x1C with value (bauddiv&0x1F)<<8 | 0x0020_0000; after all chains,
// 50 ms settle then merge host FPGA baud into BC_WRITE_COMMAND low-5.
// No non-VIL 0x86 path. Distinct from open_core gateblk (0x4020_0080 base).

/// T9+ set_baud MiscCtrl fixed high: `buf[5]=32` (`0x20`).
pub const STOCK_SET_BAUD_MISC_FIXED: u32 = 0x0020_0000;

/// T9+ post-all-chains settle before host baud merge (`cgsleep_us(50000)`).
pub const STOCK_SET_BAUD_POST_ALL_CHAINS_SETTLE_US: u32 = 50_000;

/// Pure: T9+ VIL set_baud MiscCtrl register value for `bauddiv`.
///
/// `cmd_buf[1] = (bauddiv & 0x1F) << 8 | 0x0020_0000` — **not** open_core
/// gateblk (`0x4020_0080 | (baud|0x80)<<8`).
#[inline]
pub const fn stock_set_baud_misc_value(bauddiv: u8) -> u32 {
    STOCK_SET_BAUD_MISC_FIXED | (((bauddiv as u32) & 0x1F) << 8)
}

/// Pure: merge host FPGA UART baud divisor into BC_WRITE_COMMAND low-5.
///
/// T9+: `status & 0xFFFF_FFE0 | (bauddiv & 0x1F)`.
#[inline]
pub const fn stock_bc_write_merge_host_baud(status: u32, bauddiv: u8) -> u32 {
    (status & !0x1F) | ((bauddiv as u32) & 0x1F)
}

/// Pure plan ops for one-chain VIL set_baud (T9+ exist-chain body + post merge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockSetBaudOp {
    /// Per-chain BC SetConfig (buffer→sample→trigger; settle_us=0).
    BcSetConfig(StockBcSetConfigPlan),
    /// Post-all-chains settle (T9+ 50 ms once, not per-chain 10 ms).
    DelayUs(u32),
    /// Host BC_WRITE low-5 merge after settle.
    MergeHostBaud { bauddiv: u8 },
}

/// Pure: one-chain VIL set_baud BC plan (reg `0x1C`, settle_us=0).
///
/// `cmd0` hardcodes T9+ `0x5809_001C`. Value = [`stock_set_baud_misc_value`].
pub fn plan_stock_set_baud_vil(chain: u8, bauddiv: u8) -> StockBcSetConfigPlan {
    let mut plan = plan_stock_bc_set_config(
        chain,
        0,
        true,
        STOCK_BM1387_MISC_CTRL_REG,
        stock_set_baud_misc_value(bauddiv),
    );
    // T9+ set_baud has no per-chain 10 ms settle — only 50 ms after all chains.
    plan.settle_us = 0;
    plan
}

/// Pure: multi-chain set_baud (T9+ exist-loop + **one** 50 ms + **one** merge).
///
/// Emits N×`BcSetConfig` then a single `DelayUs(50_000)` + `MergeHostBaud`.
/// Do **not** loop [`plan_stock_set_baud_one_chain_vil`] per chain (that would
/// apply N×50 ms and N merges — wrong vs T9+).
///
/// Empty `chains` still applies host merge after settle (T9+ all-skip path still
/// reaches LABEL_x3E6 settle+merge when bauddiv changes).
pub fn plan_stock_set_baud_chains_vil(chains: &[u8], bauddiv: u8) -> Vec<StockSetBaudOp> {
    let div = bauddiv & 0x1F;
    let mut ops = Vec::with_capacity(chains.len() + 2);
    for &chain in chains {
        ops.push(StockSetBaudOp::BcSetConfig(plan_stock_set_baud_vil(
            chain, div,
        )));
    }
    ops.push(StockSetBaudOp::DelayUs(
        STOCK_SET_BAUD_POST_ALL_CHAINS_SETTLE_US,
    ));
    ops.push(StockSetBaudOp::MergeHostBaud { bauddiv: div });
    ops
}

/// Pure: one-chain set_baud sequence (BC + 50 ms + host baud merge).
///
/// Equivalent to [`plan_stock_set_baud_chains_vil`] with `chains = [chain]`.
pub fn plan_stock_set_baud_one_chain_vil(chain: u8, bauddiv: u8) -> Vec<StockSetBaudOp> {
    plan_stock_set_baud_chains_vil(&[chain], bauddiv)
}

// ---------------------------------------------------------------------------
// G39: Stock VIL set_asic_ticket_mask + set_hcnt (T9+ init post-open_core)
// ---------------------------------------------------------------------------
//
// Bar: T9+ `set_asic_ticket_mask@3405C` reg 0x18 value=mask (held init 63);
// `set_hcnt@341E8` reg 0x14 value=hcnt (held init 0). VIL only; no non-VIL 0x86.
// Distinct from G24 difficulty→ticket_mask encode (stock init uses held 63).

/// T9+ BM1387 ticket mask SetConfig register (`buf[3]=24`).
pub const STOCK_ASIC_TICKET_MASK_REG: u8 = 0x18;

/// T9+ hash-count SetConfig register (`buf[3]=20`).
pub const STOCK_HCNT_REG: u8 = 0x14;

/// Held stock init ticket mask (`set_asic_ticket_mask(63u)` in bitmain_c5_init).
pub const STOCK_INIT_ASIC_TICKET_MASK: u32 = 63;

/// Pure: one-chain VIL set_asic_ticket_mask (reg `0x18`, settle_us=0).
///
/// `cmd0 = 0x5809_0018`. Value is the raw mask (e.g. 63) — **not** G24 BitReversed.
pub fn plan_stock_set_asic_ticket_mask_vil(chain: u8, ticket_mask: u32) -> StockBcSetConfigPlan {
    let mut plan =
        plan_stock_bc_set_config(chain, 0, true, STOCK_ASIC_TICKET_MASK_REG, ticket_mask);
    plan.settle_us = 0;
    plan
}

/// Pure: one-chain VIL set_hcnt (reg `0x14`, settle_us=0).
///
/// `cmd0 = 0x5809_0014`. Held init uses `hcnt=0`.
pub fn plan_stock_set_hcnt_vil(chain: u8, hcnt: u32) -> StockBcSetConfigPlan {
    let mut plan = plan_stock_bc_set_config(chain, 0, true, STOCK_HCNT_REG, hcnt);
    plan.settle_us = 0;
    plan
}

/// Pure: multi-chain ticket_mask (T9+ exist-loop; one BC per chain).
pub fn plan_stock_set_asic_ticket_mask_chains_vil(
    chains: &[u8],
    ticket_mask: u32,
) -> Vec<StockBcSetConfigPlan> {
    chains
        .iter()
        .map(|&c| plan_stock_set_asic_ticket_mask_vil(c, ticket_mask))
        .collect()
}

/// Pure: multi-chain set_hcnt.
pub fn plan_stock_set_hcnt_chains_vil(chains: &[u8], hcnt: u32) -> Vec<StockBcSetConfigPlan> {
    chains
        .iter()
        .map(|&c| plan_stock_set_hcnt_vil(c, hcnt))
        .collect()
}

/// Pure: T9+ post-open_core init pair — ticket_mask(63) all chains then hcnt(0) all chains.
pub fn plan_stock_init_ticket_mask_and_hcnt_vil(chains: &[u8]) -> Vec<StockBcSetConfigPlan> {
    let mut ops = plan_stock_set_asic_ticket_mask_chains_vil(chains, STOCK_INIT_ASIC_TICKET_MASK);
    ops.extend(plan_stock_set_hcnt_chains_vil(chains, 0));
    ops
}

// ---------------------------------------------------------------------------
// G40: Stock timeout / TIME_OUT_CONTROL pure arithmetic (T9+ bitmain_c5_init)
// ---------------------------------------------------------------------------
//
// Bar: `calculate_core_number@33DB0` + timeout formula
// `90 * (addrInterval * (16777216 / core_num) / frequency) / 100` clamp 131071;
// `set_time_out_control` pack: `(scaled & 0x1FFFF) | 0x80000000`.

/// T9+ fixed core-tick numerator (`16777216` = 2^24).
pub const STOCK_TIMEOUT_CORE_TICKS: u32 = 16_777_216;

/// Timeout scale numerator / denominator (90/100).
pub const STOCK_TIMEOUT_SCALE_NUM: u32 = 90;
pub const STOCK_TIMEOUT_SCALE_DEN: u32 = 100;

/// T9+ `dev->timeout` clamp (`> 131071` → 131071).
pub const STOCK_TIMEOUT_MAX: u32 = 131_071;

/// TIME_OUT_CONTROL enable bit (`0x8000_0000`).
pub const STOCK_TIME_OUT_CONTROL_ENABLE: u32 = 0x8000_0000;

/// TIME_OUT_CONTROL low 17-bit mask.
pub const STOCK_TIME_OUT_CONTROL_MASK: u32 = 0x1_FFFF;

/// FPGA register offset for TIME_OUT_CONTROL (T9+ / stock map).
pub const STOCK_REG_TIME_OUT_CONTROL: u32 = 0x088;

/// How T9+ scales `dev->timeout` before packing TIME_OUT_CONTROL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockTimeOutControlScale {
    /// Early init: `timeout / 10`.
    Div10,
    /// Final path: `timeout * opt_multi_version`.
    Multiversion(u32),
    /// Final path: `timeout` as-is (multi_version branch else).
    Identity,
}

/// Pure: T9+ `calculate_core_number` (ceil power-of-two buckets 1..128).
///
/// Returns `None` outside 1..=128 (T9+ debug-only path returns -1; we refuse invent).
pub const fn stock_calculate_core_number(actual_core_number: u32) -> Option<u32> {
    match actual_core_number {
        1 | 2 => Some(actual_core_number),
        3 | 4 => Some(4),
        5..=8 => Some(8),
        9..=16 => Some(16),
        17..=32 => Some(32),
        33..=64 => Some(64),
        65..=128 => Some(128),
        _ => None,
    }
}

/// Pure: T9+ auto timeout when config timeout fields empty.
///
/// `timeout = 90 * (addr_interval * (16_777_216 / core_num) / frequency) / 100`,
/// then clamp to [`STOCK_TIMEOUT_MAX`]. `core_num` is the **raw** corenum
/// (passed through [`stock_calculate_core_number`]). Zero freq/core → `None`.
pub fn stock_dev_timeout_auto(
    addr_interval: u32,
    actual_core_number: u32,
    frequency_mhz: u32,
) -> Option<u32> {
    if frequency_mhz == 0 || addr_interval == 0 {
        return None;
    }
    let core_num = stock_calculate_core_number(actual_core_number)?;
    if core_num == 0 {
        return None;
    }
    // Integer order matches C: * and / left-associative. Use u64 intermediates
    // so pathological intervals do not wrap before the T9+ 131071 clamp.
    let ticks = u64::from(STOCK_TIMEOUT_CORE_TICKS) / u64::from(core_num);
    let inner = u64::from(addr_interval) * ticks / u64::from(frequency_mhz);
    let raw = u64::from(STOCK_TIMEOUT_SCALE_NUM) * inner / u64::from(STOCK_TIMEOUT_SCALE_DEN);
    let clamped = raw.min(u64::from(STOCK_TIMEOUT_MAX)) as u32;
    Some(clamped)
}

/// Pure: pack TIME_OUT_CONTROL register word (enable | scaled timeout low-17).
#[inline]
pub const fn stock_time_out_control_reg(timeout: u32, scale: StockTimeOutControlScale) -> u32 {
    let scaled = match scale {
        StockTimeOutControlScale::Div10 => timeout / 10,
        StockTimeOutControlScale::Multiversion(mv) => {
            // saturating to avoid invent on overflow; low-17 mask still applies
            timeout.saturating_mul(mv)
        }
        StockTimeOutControlScale::Identity => timeout,
    };
    (scaled & STOCK_TIME_OUT_CONTROL_MASK) | STOCK_TIME_OUT_CONTROL_ENABLE
}

// ---------------------------------------------------------------------------
// G44: Stock T9+ set_PWM → FAN_CONTROL pure pack (axi[33] / reg 0x084)
// ---------------------------------------------------------------------------
//
// Bar: T9+ `set_PWM@2EB60` — clamp pct≤100; pack
// `((5000 − 50·pct)/100) | ((pct>>1)<<16)`; `set_fan_control` → axi[33].
// Live probe: 88% → `0x002C_0006` @ `0x084` (S9_STOCK_FPGA_LIVE_PROBE).
// Not invent scale `(pct*255/100)<<16`. Home paths must still intersect PWM-30.

/// FPGA FAN_CONTROL register (T9+ `axi_fpga_addr[33]` = 33×4 = `0x084`).
pub const STOCK_REG_FAN_CONTROL: u32 = 0x084;

/// Pure: clamp PWM percent to T9+ set_PWM domain (0..=100).
#[inline]
pub const fn stock_set_pwm_percent_clamped(pwm_percent: u8) -> u8 {
    if pwm_percent >= 100 {
        100
    } else {
        pwm_percent
    }
}

/// Pure: T9+ `set_PWM` FAN_CONTROL register value from percent.
///
/// `value = ((5000 − 50·pct)/100) | ((pct >> 1) << 16)` with pct clamped ≤100.
/// Live golden: pct=88 → `0x002C_0006`.
#[inline]
pub const fn stock_fan_control_value(pwm_percent: u8) -> u32 {
    let p = stock_set_pwm_percent_clamped(pwm_percent) as u32;
    let lo = (5000u32 - 50 * p) / 100;
    let hi = (p >> 1) << 16;
    hi | lo
}

/// Pure: FAN_CONTROL value for T9+ cold-boot full fan (`set_PWM(100)`).
#[inline]
pub const fn stock_fan_control_full() -> u32 {
    stock_fan_control_value(100)
}

// ---------------------------------------------------------------------------
// G45: Stock T9+ init_uart_baud pure bauddiv (from dev->timeout)
// ---------------------------------------------------------------------------
//
// Bar: T9+ `init_uart_baud@3450C` (Capstone-verified Thumb-2):
//   q = 1_666_666 / timeout
//   rBaudrate = 432 * q
//   bauddiv = min(26, 3125000 / rBaudrate − 1)
// Constants: 0x0019_6E6A, 0x1B0, 0x002F_AF08, clamp 0x1A.
// Not S9-jig `(q<<9)` scale (512); not invent host termios. Phase 4b still false.
// S11 production forces baud=1 (separate product path — not this pure).

/// T9+ `init_uart_baud` numerator A (`movw/movt` → `0x0019_6E6A`).
pub const STOCK_INIT_UART_BAUD_NUMER_A: u32 = 1_666_666;

/// T9+ scale after `1666666/timeout` (`mov.w #0x1B0` = 432).
pub const STOCK_INIT_UART_BAUD_SCALE: u32 = 432;

/// T9+ `init_uart_baud` numerator B (`0x002F_AF08` = 3_125_000).
pub const STOCK_INIT_UART_BAUD_NUMER_B: u32 = 3_125_000;

/// T9+ bauddiv clamp max (`cmp #0x1A` → 26). Same as open_core default idle.
pub const STOCK_INIT_UART_BAUDDIV_MAX: u8 = 26;

/// Pure: T9+ `init_uart_baud` bauddiv from `dev->timeout`.
///
/// Returns `None` when `timeout == 0` (refuse invent). When
/// `432 * (1666666/timeout) == 0`, clamps to [`STOCK_INIT_UART_BAUDDIV_MAX`]
/// (matches T9+ `> 26` clamp branch intent for starved rBaudrate).
#[inline]
pub const fn stock_init_uart_bauddiv(timeout: u32) -> Option<u8> {
    if timeout == 0 {
        return None;
    }
    let q = STOCK_INIT_UART_BAUD_NUMER_A / timeout;
    let r_baudrate = STOCK_INIT_UART_BAUD_SCALE.saturating_mul(q);
    if r_baudrate == 0 {
        return Some(STOCK_INIT_UART_BAUDDIV_MAX);
    }
    let baud = STOCK_INIT_UART_BAUD_NUMER_B / r_baudrate;
    let bauddiv = baud.saturating_sub(1);
    let max = STOCK_INIT_UART_BAUDDIV_MAX as u32;
    let clamped = if bauddiv > max {
        STOCK_INIT_UART_BAUDDIV_MAX
    } else {
        bauddiv as u8
    };
    Some(clamped)
}

// ---------------------------------------------------------------------------
// G46: Stock T9+ sensor get_local / get_remote / calc_offset pure arithmetic
// ---------------------------------------------------------------------------
//
// Bar: T9+ `get_local@329CC` / `get_remote@32924` / `calc_offset@328D0`
// (byte-identical on S9 jig + S11 lineage): local=raw−64;
// remote_c = (int)(((raw−64)×1.008 − 27.8613) / 1.11);
// offset = (int8_t)(int)(float)(0 − (remote − (local+273.15)×0.101190476 − local)).
// Pure arithmetic only — I²C / check_reg_temp / device=152 choreography stays residual.
// Phase 4b still false.

/// T9+ remote scale (`1.008`).
pub const STOCK_SENSOR_REMOTE_SCALE: f64 = 1.008;
/// T9+ remote offset subtracted after scale (`27.8613`).
pub const STOCK_SENSOR_REMOTE_BIAS: f64 = 27.8613;
/// T9+ remote divisor (`1.11`).
pub const STOCK_SENSOR_REMOTE_DIV: f64 = 1.11;
/// T9+ Kelvin offset for local term (`273.15`).
pub const STOCK_SENSOR_KELVIN_C: f64 = 273.15;
/// T9+ offset coefficient (`0.101190476` ≈ 1/9.9).
pub const STOCK_SENSOR_OFFSET_COEF: f64 = 0.101190476;
/// T9+ raw local/remote bias (`64`).
pub const STOCK_SENSOR_RAW_BIAS: i16 = 64;

/// Pure: T9+ `get_local` — `raw - 64`.
#[inline]
pub const fn stock_sensor_get_local(raw: i16) -> i16 {
    raw.wrapping_sub(STOCK_SENSOR_RAW_BIAS)
}

/// Pure: T9+ `get_remote` — `((raw-64)*1.008 - 27.8613) / 1.11` truncated toward zero to i16.
#[inline]
pub fn stock_sensor_get_remote_c(raw: i16) -> i16 {
    let centered = f64::from(raw.wrapping_sub(STOCK_SENSOR_RAW_BIAS));
    let t =
        (centered * STOCK_SENSOR_REMOTE_SCALE - STOCK_SENSOR_REMOTE_BIAS) / STOCK_SENSOR_REMOTE_DIV;
    // C `(int)v2` truncates toward zero; match with f64→i16 cast on finite values.
    t as i16
}

/// Pure: T9+ `calc_offset(remote, local)` → i8.
///
/// `v = remote − (local+273.15)*0.101190476 − local`; return `(int8_t)(int)(float)(0 − v)`.
#[inline]
pub fn stock_sensor_calc_offset(remote: i32, local: i32) -> i8 {
    let v = f64::from(remote)
        - (f64::from(local) + STOCK_SENSOR_KELVIN_C) * STOCK_SENSOR_OFFSET_COEF
        - f64::from(local);
    let f = (0.0_f64 - v) as f32;
    let i = f as i32;
    i as i8
}

// ---------------------------------------------------------------------------
// G41: Stock cold-boot composition plan-only inventory (no Phase 4b auto-wire)
// ---------------------------------------------------------------------------
//
// Bar: T9+ `bitmain_c5_init@37090` order for **held pure library** steps only:
// software_set_address → set_freq → timeout compute → set_baud → TIME_OUT/10 →
// open_core_one_chain × exist → ticket_mask(63)+hcnt(0) → final TIME_OUT.
// Explicit residual steps for fan/sensor I²C/PIC; G45/G46 close pure bodies.
// Pure inventory — `stock_cold_boot_composition_is_phase4b_admitted() == false`.
// G44: ResidualFanPwm* bodies pack via [`stock_fan_control_value`] when executed.
// G45: InitUartBauddiv pure from timeout (not Residual).
// G46: sensor get_local/remote/calc_offset pure; ResidualSensorCalibration = I/O only.

/// T9+ post-address / post-freq dwell (`cgsleep_ms(10)`).
pub const STOCK_COLD_BOOT_INTER_STAGE_MS: u32 = 10;

/// Pure: whether full stock cold-boot composition is admitted into Phase 4b.
///
/// Always `false` offline — library execute paths stay EXPERIMENTAL and operator-gated.
#[inline]
pub const fn stock_cold_boot_composition_is_phase4b_admitted() -> bool {
    false
}

/// Parameters for pure cold-boot library inventory (caller-supplied board profile).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockColdBootCompositionParams {
    /// Existing chain indices (T9+ `chain_exist == 1`).
    pub chains: Vec<u8>,
    /// Software set_address interval (0 → default 4).
    pub addr_interval: u8,
    /// BM1387 set_frequency MHz (G16/G27).
    pub freq_mhz: u16,
    /// Raw `dev->corenum` for timeout auto formula.
    pub actual_core_number: u32,
    /// Baud divisor low-5 for set_baud + open_core gateblk.
    /// When [`None`], inventory uses pure [`stock_init_uart_bauddiv`] from timeout
    /// auto (G45). When `Some`, caller override (lab / S11-force-1 style).
    pub bauddiv: Option<u8>,
    /// `opt_multi_version` low nibble for open_core + final TIME_OUT scale.
    pub multi_version: u8,
    /// open_core nullwork enable (T9+ init uses true).
    pub nullwork_enable: bool,
}

impl StockColdBootCompositionParams {
    /// Minimal default for offline goldens (one chain, held T9+-like defaults).
    pub fn offline_golden_one_chain() -> Self {
        Self {
            chains: vec![0],
            addr_interval: STOCK_SOFTWARE_SET_ADDRESS_INTERVAL,
            freq_mhz: 500,
            actual_core_number: 114,
            // G45: resolve pure from timeout auto (not hard-coded 0x1A).
            bauddiv: None,
            multi_version: STOCK_OPEN_CORE_DEFAULT_MULTI_VERSION,
            nullwork_enable: true,
        }
    }
}

/// High-level pure inventory step (maps 1:1 to G32–G40 library or named residual).
///
/// Residual variants are ordered to T9+ interleave (not free-floating tags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockColdBootLibraryStep {
    /// G35: per-chain software_set_address.
    SoftwareSetAddress { chain: u8, addr_interval: u8 },
    /// Inter-stage dwell (T9+ 10 ms or open_core `sleep(1)` → 1000 ms).
    DelayMs(u32),
    /// G27/G32: BM1387 broadcast set_freq on one chain.
    SetFreqBm1387Broadcast { chain: u8, freq_mhz: u16 },
    /// G40: auto timeout from addr/core/freq (value computed at plan time).
    TimeoutAuto {
        addr_interval: u32,
        actual_core_number: u32,
        frequency_mhz: u32,
        /// Precomputed clamped timeout (None if OOR params).
        timeout: Option<u32>,
    },
    /// G45: pure T9+ `init_uart_baud` bauddiv from timeout (body closed offline).
    InitUartBauddiv { timeout: u32, bauddiv: u8 },
    /// G38: multi-chain set_baud (N BC + one settle + one host merge).
    SetBaud { chains: Vec<u8>, bauddiv: u8 },
    /// G40: pack + write TIME_OUT_CONTROL scale variant.
    TimeOutControl {
        timeout: u32,
        scale: StockTimeOutControlScale,
    },
    /// Named residual: T9+ config/temp fan after set_freq (before timeout).
    ResidualFanPwmConfig,
    /// Named residual: T9+ `set_PWM(100)` after first TIME_OUT/10, before open_core.
    ResidualFanPwmFull,
    /// Named residual: sensor I²C/check_reg_temp choreography after baud.
    /// Pure arithmetic is G46 [`stock_sensor_get_local`] / [`stock_sensor_get_remote_c`] /
    /// [`stock_sensor_calc_offset`] — this step remains residual for live I/O only.
    ResidualSensorCalibration,
    /// G36/G37: VIL open_core_one_chain.
    OpenCoreOneChain {
        chain: u8,
        baud_div_low5: u8,
        multi_version: u8,
        nullwork_enable: bool,
    },
    /// Named residual: PIC/working-voltage after open_core (not pure BC).
    ResidualPicVoltage,
    /// G39: ticket_mask + hcnt for all exist chains (held init 63 / 0).
    TicketMaskAndHcnt {
        chains: Vec<u8>,
        ticket_mask: u32,
        hcnt: u32,
    },
}

/// T9+ open_core inter-chain settle (`sleep(1)` → 1000 ms).
pub const STOCK_COLD_BOOT_OPEN_CORE_SETTLE_MS: u32 = 1_000;

/// Pure: T9+-ordered **library inventory** for stock cold-boot (plan only).
///
/// Residual steps are **positioned** to T9+ interleave (fan after freq; sensor after
/// baud; full PWM after first TIME_OUT/10). Does **not** invent fan/PIC/sensor
/// execute bodies. G45: init_uart_baud bauddiv is pure from timeout. Does **not**
/// admit Phase 4b auto-wire ([`stock_cold_boot_composition_is_phase4b_admitted`] is false).
pub fn plan_stock_cold_boot_library_inventory(
    params: &StockColdBootCompositionParams,
) -> Vec<StockColdBootLibraryStep> {
    let mv = params.multi_version & 0xF;
    let interval = if params.addr_interval == 0 {
        STOCK_SOFTWARE_SET_ADDRESS_INTERVAL
    } else {
        params.addr_interval
    };
    let mut steps = Vec::with_capacity(params.chains.len() * 4 + 20);

    // 1. software_set_address (T9+ global; we emit per exist-chain pure plan).
    for &chain in &params.chains {
        steps.push(StockColdBootLibraryStep::SoftwareSetAddress {
            chain,
            addr_interval: interval,
        });
    }
    steps.push(StockColdBootLibraryStep::DelayMs(
        STOCK_COLD_BOOT_INTER_STAGE_MS,
    ));

    // 2. set_frequency (broadcast per exist chain).
    for &chain in &params.chains {
        steps.push(StockColdBootLibraryStep::SetFreqBm1387Broadcast {
            chain,
            freq_mhz: params.freq_mhz,
        });
    }
    steps.push(StockColdBootLibraryStep::DelayMs(
        STOCK_COLD_BOOT_INTER_STAGE_MS,
    ));

    // 3. T9+: fan config/temp residual **before** timeout compute.
    steps.push(StockColdBootLibraryStep::ResidualFanPwmConfig);

    // 4. timeout auto (config-empty path).
    let timeout = stock_dev_timeout_auto(
        u32::from(interval),
        params.actual_core_number,
        u32::from(params.freq_mhz),
    );
    steps.push(StockColdBootLibraryStep::TimeoutAuto {
        addr_interval: u32::from(interval),
        actual_core_number: params.actual_core_number,
        frequency_mhz: u32::from(params.freq_mhz),
        timeout,
    });

    // 5. G45: pure init_uart_baud then set_baud (caller override or pure).
    let div = match params.bauddiv {
        Some(b) => b & 0x1F,
        None => match timeout.and_then(stock_init_uart_bauddiv) {
            Some(b) => b & 0x1F,
            // Fail-closed to held idle default when timeout pure refuses.
            None => STOCK_OPEN_CORE_DEFAULT_BAUD_DIV_LOW5 & 0x1F,
        },
    };
    if let Some(t) = timeout {
        if let Some(pure_div) = stock_init_uart_bauddiv(t) {
            steps.push(StockColdBootLibraryStep::InitUartBauddiv {
                timeout: t,
                bauddiv: pure_div,
            });
        }
    }
    steps.push(StockColdBootLibraryStep::SetBaud {
        chains: params.chains.clone(),
        bauddiv: div,
    });
    steps.push(StockColdBootLibraryStep::DelayMs(
        STOCK_COLD_BOOT_INTER_STAGE_MS,
    ));

    // 6. sensor cal residual after baud (T9+).
    steps.push(StockColdBootLibraryStep::ResidualSensorCalibration);

    // 7. TIME_OUT /10 then set_PWM(100) residual then open_core.
    if let Some(t) = timeout {
        steps.push(StockColdBootLibraryStep::TimeOutControl {
            timeout: t,
            scale: StockTimeOutControlScale::Div10,
        });
    }
    steps.push(StockColdBootLibraryStep::ResidualFanPwmFull);

    // 8. open_core per exist chain + 1s settle + PIC residual.
    for &chain in &params.chains {
        steps.push(StockColdBootLibraryStep::OpenCoreOneChain {
            chain,
            baud_div_low5: div,
            multi_version: mv,
            nullwork_enable: params.nullwork_enable,
        });
        steps.push(StockColdBootLibraryStep::DelayMs(
            STOCK_COLD_BOOT_OPEN_CORE_SETTLE_MS,
        ));
        steps.push(StockColdBootLibraryStep::ResidualPicVoltage);
    }

    // 9. T9+ L837: second TIME_OUT/10 after open_core loop, before ticket.
    if let Some(t) = timeout {
        steps.push(StockColdBootLibraryStep::TimeOutControl {
            timeout: t,
            scale: StockTimeOutControlScale::Div10,
        });
    }

    // 10. ticket_mask(63) + hcnt(0).
    steps.push(StockColdBootLibraryStep::TicketMaskAndHcnt {
        chains: params.chains.clone(),
        ticket_mask: STOCK_INIT_ASIC_TICKET_MASK,
        hcnt: 0,
    });
    steps.push(StockColdBootLibraryStep::DelayMs(
        STOCK_COLD_BOOT_INTER_STAGE_MS,
    ));

    // 11. final TIME_OUT (multi_version scale when mv != 0, else Identity).
    if let Some(t) = timeout {
        let scale = if mv > 0 {
            StockTimeOutControlScale::Multiversion(u32::from(mv))
        } else {
            StockTimeOutControlScale::Identity
        };
        steps.push(StockColdBootLibraryStep::TimeOutControl { timeout: t, scale });
    }

    steps
}

/// Pure: count library (executable) steps vs named residuals in an inventory.
pub fn stock_cold_boot_inventory_counts(steps: &[StockColdBootLibraryStep]) -> (usize, usize) {
    let residual = steps
        .iter()
        .filter(|s| {
            matches!(
                s,
                StockColdBootLibraryStep::ResidualFanPwmConfig
                    | StockColdBootLibraryStep::ResidualFanPwmFull
                    | StockColdBootLibraryStep::ResidualSensorCalibration
                    | StockColdBootLibraryStep::ResidualPicVoltage
            )
        })
        .count();
    (steps.len() - residual, residual)
}

/// G32: pure BC_COMMAND_BUFFER write triple (T9+ `set_BC_command_buffer`).
///
/// Order: `0x0C4`, `0x0C8`, `0x0CC` ← cmd_buf[0..2]. Callers then **sample**
/// `STOCK_REG_BC_WRITE_COMMAND` and apply [`stock_bc_set_config_trigger_write`].
#[inline]
pub fn stock_bc_set_config_buffer_writes(plan: &StockBcSetConfigPlan) -> [(u32, u32); 3] {
    [
        (STOCK_REG_BC_COMMAND_BUFFER, plan.cmd_buf[0]),
        (STOCK_REG_BC_COMMAND_BUFFER_W1, plan.cmd_buf[1]),
        (STOCK_REG_BC_COMMAND_BUFFER_W2, plan.cmd_buf[2]),
    ]
}

/// G32: pure BC_WRITE_COMMAND trigger word after a post-buffer status sample.
#[inline]
pub fn stock_bc_set_config_trigger_write(plan: &StockBcSetConfigPlan, status: u32) -> (u32, u32) {
    (
        STOCK_REG_BC_WRITE_COMMAND,
        stock_bc_write_command(status, plan.chain),
    )
}

/// G32: full pure write sequence **given** a pre-sampled status (tests / dry-run).
///
/// T9+ live order is buffer → **then** sample → trigger. Prefer
/// [`stock_bc_set_config_buffer_writes`] + sample + [`stock_bc_set_config_trigger_write`]
/// on the wire so the sample is post-buffer (T9+ faithful). This helper is for
/// offline vectors when `status` is already known.
#[inline]
pub fn stock_bc_set_config_write_sequence(
    plan: &StockBcSetConfigPlan,
    status: u32,
) -> [(u32, u32); 4] {
    let buf = stock_bc_set_config_buffer_writes(plan);
    let trig = stock_bc_set_config_trigger_write(plan, status);
    [buf[0], buf[1], buf[2], trig]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_s9_dma_job_plan_pads_and_derives_coupled_registers() {
        let coinbase = [0xaa, 0xbb, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let mut raw = coinbase.to_vec();
        raw.extend_from_slice(&[0xcc; STOCK_DMA_MERKLE_BRANCH_LEN]);
        let plan = plan_stock_dma_job(&raw, coinbase.len(), 2, 8, 1).expect("exact plan");
        assert_eq!(plan.padded_coinbase_len(), 64);
        assert_eq!(plan.buffer_payload().len(), 96);
        assert_eq!(&plan.buffer_payload()[..coinbase.len()], &coinbase);
        assert_eq!(plan.buffer_payload()[coinbase.len()], 0x80);
        assert_eq!(
            &plan.buffer_payload()[56..64],
            &(u64::try_from(coinbase.len()).unwrap() * 8).to_be_bytes()
        );
        assert_eq!(&plan.buffer_payload()[64..], &[0xcc; 32]);
        assert_eq!(plan.coinbase_layout(), (2 << 16) | (8 << 8) | 1);
        assert_eq!(plan.nonce2_low(), 0x0506_0708);
        assert_eq!(plan.nonce2_high(), 0x0102_0304);
        assert_eq!(plan.merkle_count(), 1);
        assert_eq!(plan.job_length(), 96);
    }

    #[test]
    fn exact_s9_header_scalars_match_signed_binary_and_live_probe() {
        assert_eq!(stock_fpga_header_scalar_word(0x2000_0000), 0x0000_0020);
        assert_eq!(stock_fpga_header_scalar_word(0x69b3_3555), 0x5535_b369);
        assert_eq!(stock_fpga_header_scalar_word(0x1701_f0cc), 0xccf0_0117);
    }

    #[test]
    fn exact_s9_shutdown_disables_nullwork_before_dhash_stop() {
        assert_eq!(stock_shutdown_bc_disable_nullwork(0xffff_ffff), 0xffbf_ffff);
        assert_eq!(stock_shutdown_bc_disable_nullwork(0x1234_5678), 0x1234_5678);

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga_work.rs"))
            .expect("stock FPGA HAL");
        let start = src.find("pub fn stop(&self)").expect("stop method");
        let body: String = src[start..].chars().take(1_500).collect();
        let nullwork = body
            .find("stock_shutdown_bc_disable_nullwork")
            .expect("nullwork disable");
        let dhash = body.find("dhash_stop_value").expect("DHASH stop");
        assert!(
            nullwork < dhash,
            "signed S9j shutdown disables BC nullwork before clearing DHASH RUN"
        );
    }

    #[test]
    fn s9_dma_job_plan_refuses_inconsistent_or_cross_slot_payloads() {
        assert_eq!(
            plan_stock_dma_job(&[0u8; 10], 4, 0, 4, 1),
            Err(StockDmaJobPlanError::PayloadLengthMismatch {
                expected: 36,
                observed: 10,
            })
        );
        assert_eq!(
            plan_stock_dma_job(&[0u8; 16], 16, 10, 8, 0),
            Err(StockDmaJobPlanError::Nonce2RangeOutOfBounds)
        );
        let largest = vec![0u8; 1 + 2_045 * STOCK_DMA_MERKLE_BRANCH_LEN];
        assert_eq!(
            plan_stock_dma_job(&largest, 1, 0, 0, 2_045)
                .expect("largest u16-aligned exact job")
                .job_length(),
            0xffe0
        );
        let wraps_u16 = vec![0u8; 1 + 2_046 * STOCK_DMA_MERKLE_BRANCH_LEN];
        assert_eq!(
            plan_stock_dma_job(&wraps_u16, 1, 0, 0, 2_046),
            Err(StockDmaJobPlanError::JobLengthOverflow)
        );
    }

    #[test]
    fn bip320_mask_packs_first_four_slots_like_increment_bitmask() {
        // For contiguous mask starting at bit 13, stock (i<<13)&mask matches
        // the first four increment_bitmask steps from a cleared base.
        let base = 0x2000_0000_u32;
        let mask = STOCK_ASICBOOST_BIP320_MASK;
        let words = stock_asicboost_version_words(base, mask);
        assert_eq!(words[0], 0x2000_0000);
        assert_eq!(words[1], 0x2000_2000);
        assert_eq!(words[2], 0x2000_4000);
        assert_eq!(words[3], 0x2000_6000);
        // Outside mask bits preserved; slot 0 clears any pre-set rolling bits.
        let dirty = base | 0x0000_2000;
        let cleared = stock_asicboost_version_words(dirty, mask);
        assert_eq!(cleared[0], base & !mask | (base & !mask)); // == base with mask cleared
        assert_eq!(cleared[0], 0x2000_0000);
        assert_eq!(cleared[1], 0x2000_2000);
    }

    #[test]
    fn zero_mask_not_admitted_and_all_slots_equal_base() {
        assert!(!stock_asicboost_admitted(0));
        let words = stock_asicboost_version_words(0x2000_0000, 0);
        assert_eq!(words, [0x2000_0000; 4]);
    }

    #[test]
    fn every_runtime_mask_is_refused_until_s9j_extra_lanes_are_mapped() {
        assert!(!stock_asicboost_admitted(STOCK_ASICBOOST_BIP320_MASK));
        assert!(!stock_asicboost_admitted(0x00FF_E000));
    }

    #[test]
    fn exact_s9j_version_regs_do_not_alias_timestamp_or_target() {
        assert_eq!(stock_asicboost_version_reg(0), 0x130);
        assert_eq!(stock_asicboost_version_reg(1), 0x164);
        assert_eq!(stock_asicboost_version_reg(2), 0x168);
        assert_eq!(stock_asicboost_version_reg(3), 0x16C);
        assert_eq!(stock_asicboost_version_reg(4), 0x130); // wrap
    }

    #[test]
    fn solution_idx_maps_to_slot_and_version() {
        let base = 0x2000_0000;
        let mask = STOCK_ASICBOOST_BIP320_MASK;
        assert_eq!(stock_asicboost_slot_from_solution_idx(0), 0);
        assert_eq!(stock_asicboost_slot_from_solution_idx(3), 3);
        assert_eq!(stock_asicboost_slot_from_solution_idx(5), 1);
        assert_eq!(
            stock_asicboost_version_for_solution(base, mask, 2),
            0x2000_4000
        );
    }

    #[test]
    fn hal_asicboost_entry_is_non_mutating_and_fail_closed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga_work.rs"))
            .expect("stock_fpga_work");
        let start = src
            .find("pub fn dispatch_work_asicboost")
            .expect("dispatch_work_asicboost");
        let body: String = src[start..].chars().take(3_500).collect();
        assert!(
            body.contains("four-way AsicBoost is refused")
                && !body.contains("self.fpga.write_reg")
                && !body.contains("write_bytes_verified"),
            "four-way entry must return an evidence-backed refusal before hardware mutation"
        );
    }

    /// Exact S9j falsifies the old consecutive 0x130..0x13c alias map.
    #[test]
    fn hal_asicboost_dispatch_never_overwrites_timestamp_or_target() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga_work.rs"))
            .expect("stock_fpga_work");
        let start = src
            .find("pub fn dispatch_work_asicboost")
            .expect("dispatch_work_asicboost");
        let body: String = src[start..].chars().take(3_500).collect();
        assert!(
            !body.contains("REG_TIME_STAMP")
                && !body.contains("REG_TARGET_BITS")
                && !body.contains("REG_JOB_DATA_READY"),
            "refused four-way entry must not emit the disproved alias or 0x120 writes"
        );
    }

    #[test]
    fn midstate_count_field_switches_one_and_four_without_touching_other_bits() {
        let base = 0x8160_u32;
        assert_eq!(stock_dhash_midstate_count(base), 1);
        let ab = stock_dhash_with_midstate_mode(base, StockDhashMidstateMode::FourWay);
        assert_eq!(ab, 0x8460);
        assert_eq!(stock_dhash_midstate_count(ab), 4);
        let cleared = stock_dhash_with_midstate_mode(ab, StockDhashMidstateMode::Single);
        assert_eq!(cleared, base);
        assert_eq!(stock_dhash_midstate_count(cleared), 1);
        assert_eq!(
            stock_dhash_with_midstate_mode(base | (1 << 12), StockDhashMidstateMode::FourWay),
            0x9460
        );
    }

    /// G27: CRC5 matches published BM1397 GetAddress vector (same poly/init).
    #[test]
    fn stock_crc5_matches_published_bm1397_getaddress_vector() {
        // skot/BM1397, cgminer-gekko: CRC5([0x52,0x05,0x00,0x00], 32) == 0x0A
        // (frame 55 AA 52 05 00 00 0A — CRC over 4 payload bytes).
        assert_eq!(stock_bitmain_crc5(&[0x52, 0x05, 0x00, 0x00], 32), 0x0A);
    }

    /// G27: VIL BC SetConfig plan for BM1387 PLL goldens (G16 words + T9+ layout).
    #[test]
    fn stock_bm1387_set_freq_bc_plan_matches_t9_vil_layout() {
        // Broadcast 500 MHz → G16 0x00500221
        let p500 = plan_stock_bm1387_set_freq(0, 0, true, 500);
        assert_eq!(p500.value, 0x0050_0221);
        assert_eq!(p500.reg, 0x0C);
        assert_eq!(p500.frame[0], 0x58);
        assert_eq!(p500.frame[1], 0x09);
        assert_eq!(p500.frame[2], 0x00);
        assert_eq!(p500.frame[3], 0x0C);
        assert_eq!(&p500.frame[4..8], &[0x00, 0x50, 0x02, 0x21]);
        assert_eq!(p500.cmd_buf[0], 0x5809_000C);
        assert_eq!(p500.cmd_buf[1], 0x0050_0221);
        assert_eq!(p500.cmd_buf[2], (p500.frame[8] as u32) << 24);
        assert_eq!(p500.settle_us, 10_000);
        // CRC is CRC5 over first 8 frame bytes, 64 bits.
        assert_eq!(p500.frame[8], stock_bitmain_crc5(&p500.frame[..8], 64));

        // Broadcast 650 MHz → G16 0x00680221
        let p650 = plan_stock_bm1387_set_freq(1, 0, true, 650);
        assert_eq!(p650.value, 0x0068_0221);
        assert_eq!(p650.cmd_buf[0], 0x5809_000C);
        assert_eq!(p650.cmd_buf[1], 0x0068_0221);
        assert_eq!(p650.chain, 1);

        // Unicast chip 0x24 @ 650 — Braiins-class hdr 0x48 + addr in cmd0
        let uni = plan_stock_bm1387_set_freq(0, 0x24, false, 650);
        assert_eq!(uni.frame[0], 0x48);
        assert_eq!(uni.frame[2], 0x24);
        assert_eq!(uni.cmd_buf[0], 0x4809_240C);
        assert_eq!(&uni.frame[4..8], &[0x00, 0x68, 0x02, 0x21]);

        // BC ready + trigger merge
        assert!(stock_bc_ready(0x0000_0000));
        assert!(!stock_bc_ready(0x8000_0000));
        assert_eq!(
            stock_bc_write_command(0x1234_5678, 2),
            (0x1234_5678 & 0xFFF0_FFFF) | (2 << 16) | 0x8080_0000
        );
    }

    /// G27/G32: HAL exposes BC buffer offsets matching pure constants (structural).
    #[test]
    fn stock_hal_bc_register_offsets_match_pure() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga.rs"))
            .expect("stock_fpga");
        assert!(
            src.contains("REG_BC_WRITE_COMMAND") && src.contains("0x0C0"),
            "HAL must keep BC_WRITE_COMMAND @ 0x0C0"
        );
        assert!(
            src.contains("REG_BC_COMMAND_BUFFER") && src.contains("0x0C4"),
            "HAL must keep BC_COMMAND_BUFFER @ 0x0C4"
        );
        assert_eq!(STOCK_REG_BC_WRITE_COMMAND, 0x0C0);
        assert_eq!(STOCK_REG_BC_COMMAND_BUFFER, 0x0C4);
        assert_eq!(STOCK_REG_BC_COMMAND_BUFFER_W1, 0x0C8);
        assert_eq!(STOCK_REG_BC_COMMAND_BUFFER_W2, 0x0CC);
        // G32: execute adapter must consume pure buffer + post-buffer sample + trigger.
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_bc_set_config")
                && exec.contains("stock_bc_set_config_buffer_writes")
                && exec.contains("stock_bc_set_config_trigger_write")
                && exec.contains("plan_stock_bm1387_set_freq"),
            "G32 HAL execute must consume pure buffer/trigger + set_freq plan"
        );
        // T9+ order inside execute_stock_bc_set_config_with_options body only
        // (imports mention the same symbols earlier — ignore those).
        let body = exec
            .split("fn execute_stock_bc_set_config_with_options")
            .nth(1)
            .and_then(|s| s.split("pub fn execute_stock_bm1387_set_freq").next())
            .expect("execute body");
        let buf_pos = body
            .find("stock_bc_set_config_buffer_writes")
            .expect("buffer in body");
        let sample_pos = body
            .find("io.read_reg(STOCK_REG_BC_WRITE_COMMAND)")
            .expect("sample in body");
        let trig_pos = body
            .find("stock_bc_set_config_trigger_write")
            .expect("trigger in body");
        assert!(
            buf_pos < sample_pos && sample_pos < trig_pos,
            "G32 execute body must be T9+ buffer → sample → trigger"
        );
    }

    /// G32: pure write sequence is T9+ three-word buffer then trigger (no invent).
    #[test]
    fn g32_stock_bc_write_sequence_matches_t9_vil_order() {
        let plan = plan_stock_bm1387_set_freq(2, 0, true, 500);
        let status = 0x1234_5678_u32;
        let seq = stock_bc_set_config_write_sequence(&plan, status);
        assert_eq!(seq[0], (0x0C4, 0x5809_000C));
        assert_eq!(seq[1], (0x0C8, 0x0050_0221)); // G16 500 MHz
        assert_eq!(seq[2].0, 0x0CC);
        assert_eq!(seq[2].1, (plan.frame[8] as u32) << 24);
        assert_eq!(
            seq[3],
            (0x0C0, (status & 0xFFF0_FFFF) | (2 << 16) | 0x8080_0000)
        );

        let p650 = plan_stock_bm1387_set_freq(0, 0, true, 650);
        let s0 = stock_bc_set_config_write_sequence(&p650, 0);
        assert_eq!(s0[1], (0x0C8, 0x0068_0221));
        assert_eq!(s0[3], (0x0C0, 0x8080_0000));

        let uni = plan_stock_bm1387_set_freq(0, 0x24, false, 650);
        let su = stock_bc_set_config_write_sequence(&uni, 0);
        assert_eq!(su[0], (0x0C4, 0x4809_240C));
    }

    /// G33: T9+ post-trigger bit31 busy-wait pure SSOT.
    #[test]
    fn g33_stock_bc_post_trigger_busy_wait_matches_t9() {
        assert_eq!(STOCK_BC_BUSY_BIT, 0x8000_0000);
        assert_eq!(STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS, 3001);
        assert_eq!(STOCK_BC_POST_TRIGGER_POLL_MS, 1);

        // Trigger OR always sets bit 31 → busy-wait required after set_freq.
        let trig = stock_bc_write_command(0, 0);
        assert!(stock_bc_write_requires_busy_wait(trig));
        assert_eq!(stock_bc_post_trigger_wait_budget(trig), Some(3001));
        // Explicit clear of bit 31 → single read path, no wait budget.
        assert!(!stock_bc_write_requires_busy_wait(0x0000_0001));
        assert_eq!(stock_bc_post_trigger_wait_budget(0x1234_5678), None);

        // Immediate ready (first poll clears) — no sleep.
        assert_eq!(
            stock_bc_busy_wait_step(0x0000_0000, 3001),
            StockBcBusyWaitStep::Ready
        );
        assert_eq!(
            stock_bc_busy_wait_step(0x7FFF_FFFF, 1),
            StockBcBusyWaitStep::Ready
        );

        // Busy with full budget → sleep 1 ms, 3000 left.
        assert_eq!(
            stock_bc_busy_wait_step(0x8000_0000, 3001),
            StockBcBusyWaitStep::SleepThenRepoll {
                sleep_ms: 1,
                attempts_after_sleep: 3000,
            }
        );
        // Busy with 2 left → sleep, 1 left.
        assert_eq!(
            stock_bc_busy_wait_step(0x8080_0000, 2),
            StockBcBusyWaitStep::SleepThenRepoll {
                sleep_ms: 1,
                attempts_after_sleep: 1,
            }
        );
        // Busy with 1 left → sleep then timeout (T9+ `!--v1` after sleep).
        assert_eq!(
            stock_bc_busy_wait_step(0x8000_0000, 1),
            StockBcBusyWaitStep::SleepThenTimeout { sleep_ms: 1 }
        );
        // Defensive exhausted budget.
        assert_eq!(
            stock_bc_busy_wait_step(0x8000_0000, 0),
            StockBcBusyWaitStep::Timeout
        );

        // stock_bc_ready ≡ bit31 clear (same test T9+ uses).
        assert!(stock_bc_ready(0x7FFF_FFFF));
        assert!(!stock_bc_ready(0x8000_0000));

        // Full pure loop: busy → busy → ready (simulates HAL run_stock_bc_post_trigger_wait).
        let mut attempts = STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS;
        let statuses = [0x8000_0000_u32, 0x8000_0000, 0x0000_0000];
        let mut done = false;
        for &st in &statuses {
            match stock_bc_busy_wait_step(st, attempts) {
                StockBcBusyWaitStep::Ready => {
                    done = true;
                    break;
                }
                StockBcBusyWaitStep::SleepThenRepoll {
                    attempts_after_sleep,
                    ..
                } => attempts = attempts_after_sleep,
                StockBcBusyWaitStep::SleepThenTimeout { .. } | StockBcBusyWaitStep::Timeout => {
                    panic!("unexpected timeout")
                }
            }
        }
        assert!(done);
        assert_eq!(attempts, 2999); // 3001 → 3000 after first busy, still 2999 after second

        // Timeout path: one busy with attempts=1 → SleepThenTimeout.
        assert_eq!(
            stock_bc_busy_wait_step(0x8000_0000, 1),
            StockBcBusyWaitStep::SleepThenTimeout { sleep_ms: 1 }
        );

        // HAL execute must consume pure busy-wait (structural).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("stock_bc_post_trigger_wait_budget")
                && exec.contains("stock_bc_busy_wait_step")
                && exec.contains("StockBcBusyWaitStep")
                && exec.contains("run_stock_bc_post_trigger_wait"),
            "G33 HAL must consume pure post-trigger busy-wait SSOT"
        );
    }

    /// G37: BUFFER timeout continues to DHASH exit + pure write-trace golden.
    #[test]
    fn g37_open_core_buffer_timeout_and_write_trace_golden() {
        assert!(stock_open_core_buffer_timeout_continues_to_dhash_exit());
        assert!(stock_open_core_buffer_timeout_skips_remaining_tw());
        assert!(stock_open_core_buffer_timeout_skips_nullwork_enable());

        let ops = plan_stock_open_core_one_chain_vil(0, 0x1A, 1, true);

        // Happy path: buffer always ready → 114 TW bursts + nullwork + dhash exit.
        let happy =
            stock_open_core_sim_write_trace(&ops, StockOpenCoreSimState::happy_path(), false);
        assert!(!happy.buffer_space_timeout);
        // First write is DHASH entry.
        assert_eq!(happy.writes[0].0, STOCK_REG_DHASH_ACC_CONTROL);
        assert_eq!(happy.writes[0].1, stock_open_core_dhash_entry(0x20, 1));
        assert_eq!(happy.writes[1], (STOCK_REG_HASH_COUNTING_NUMBER, 0));
        // Gateblk three buffer words include 0x5809001C
        assert!(happy
            .writes
            .iter()
            .any(|&(o, v)| o == 0x0C4 && v == 0x5809_001C));
        // 114 × 13 TW words
        let tw_writes = happy
            .writes
            .iter()
            .filter(|(o, _)| (0x40..0x40 + 13 * 4).contains(o))
            .count();
        assert_eq!(tw_writes, 114 * 13);
        // Nullwork enable bit 22
        assert!(happy.writes.iter().any(|&(o, v)| {
            o == STOCK_REG_BC_WRITE_COMMAND && (v & STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT) != 0
        }));
        // Last write is DHASH exit
        let last = happy.writes.last().expect("writes");
        assert_eq!(last.0, STOCK_REG_DHASH_ACC_CONTROL);
        assert_eq!(
            last.1,
            stock_open_core_dhash_exit(stock_open_core_dhash_entry(0x20, 1), 1)
        );

        // Buffer timeout: no TW, no nullwork enable, still DHASH exit.
        let fail = stock_open_core_sim_write_trace(&ops, StockOpenCoreSimState::happy_path(), true);
        assert!(fail.buffer_space_timeout);
        let tw_fail = fail
            .writes
            .iter()
            .filter(|(o, _)| (0x40..0x40 + 13 * 4).contains(o))
            .count();
        assert_eq!(tw_fail, 0, "T9+ skips remaining TW after buffer timeout");
        assert!(
            !fail.writes.iter().any(|&(o, v)| {
                o == STOCK_REG_BC_WRITE_COMMAND && (v & STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT) != 0
            }),
            "T9+ skips nullwork enable when jumping to LABEL_x5612"
        );
        let last_f = fail.writes.last().expect("exit");
        assert_eq!(last_f.0, STOCK_REG_DHASH_ACC_CONTROL);
        assert_eq!(
            last_f.1,
            stock_open_core_dhash_exit(stock_open_core_dhash_entry(0x20, 1), 1)
        );

        // HAL must consume pure buffer-timeout policy (structural).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("stock_open_core_buffer_timeout_continues_to_dhash_exit")
                && exec.contains("buffer_space_timeout")
                && exec.contains("StockOpenCoreExecuteReport"),
            "G37 HAL must continue to DHASH exit on BUFFER timeout (T9+)"
        );
        assert!(
            exec.contains("stock_open_core_buffer_timeout_skips_remaining_tw")
                && exec.contains("stock_open_core_buffer_timeout_skips_nullwork_enable"),
            "G37 HAL must skip TW + nullwork after buffer timeout"
        );
        // G37 R2 critic: T9+ writeInitLogFile on BUFFER timeout.
        assert!(
            exec.contains("tracing::error!") && exec.contains("send open core work Failed"),
            "G37 HAL must error-log BUFFER timeout (T9+ writeInitLogFile)"
        );
        // G37 R2: fail-path pure↔HAL full write-trace equality (not just happy path).
        assert!(
            exec.contains("force_buffer_timeout")
                || exec.contains("pure_fail.writes")
                || exec.contains("pure_fail"),
            "G37 HAL timeout test must pin full pure fail write-trace"
        );
    }

    /// G44: T9+ set_PWM FAN_CONTROL pack + live 88% golden.
    #[test]
    fn g44_stock_fan_control_matches_t9_set_pwm() {
        assert_eq!(STOCK_REG_FAN_CONTROL, 0x084);
        // Live probe: 88% → 0x002C0006
        assert_eq!(stock_fan_control_value(88), 0x002C_0006);
        // lo = (5000-50*88)/100 = 6; hi = (88>>1)<<16 = 0x2C<<16
        assert_eq!((5000u32 - 50 * 88) / 100, 6);
        assert_eq!((88u32 >> 1) << 16, 0x002C_0000);

        assert_eq!(stock_fan_control_value(100), 0x0032_0000); // (100>>1)=50
        assert_eq!(stock_fan_control_full(), 0x0032_0000);
        assert_eq!(stock_fan_control_value(0), 0x0000_0032); // 5000/100=50
        assert_eq!(stock_set_pwm_percent_clamped(255), 100);
        assert_eq!(stock_fan_control_value(255), stock_fan_control_value(100));

        // Home-cap 30% is still a valid T9+ pack (product must still cap before write).
        let home30 = stock_fan_control_value(30);
        assert_eq!(home30, 0x000F_0023); // hi=15, lo=(5000-1500)/100=35=0x23
                                         // Must not equal invent scale (30*255/100)<<16 | 0x14
        let invent = ((30u32 * 255 / 100) << 16) | 0x14;
        assert_ne!(home30, invent);

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_set_pwm")
                && exec.contains("stock_fan_control_value")
                && exec.contains("STOCK_REG_FAN_CONTROL"),
            "G44 HAL must write pure FAN_CONTROL pack"
        );
        let sm = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            sm.contains("stock_fan_control_value") && !sm.contains("* 255 / 100"),
            "stock_mining cooldown must use pure T9+ FAN_CONTROL pack (not invent 0-255 scale)"
        );
        assert!(
            sm.contains("PWM_SAFETY_MAX") || sm.contains("fan_max_pwm"),
            "home fan cap must remain on stock cooldown path"
        );
    }

    /// G46: T9+ sensor get_local / get_remote / calc_offset pure arithmetic.
    #[test]
    fn g46_stock_sensor_temp_offset_matches_t9() {
        assert_eq!(STOCK_SENSOR_RAW_BIAS, 64);
        assert!((STOCK_SENSOR_REMOTE_SCALE - 1.008).abs() < 1e-12);
        assert!((STOCK_SENSOR_REMOTE_BIAS - 27.8613).abs() < 1e-9);
        assert!((STOCK_SENSOR_REMOTE_DIV - 1.11).abs() < 1e-12);
        assert!((STOCK_SENSOR_KELVIN_C - 273.15).abs() < 1e-12);
        assert!((STOCK_SENSOR_OFFSET_COEF - 0.101190476).abs() < 1e-12);

        // get_local
        assert_eq!(stock_sensor_get_local(64), 0);
        assert_eq!(stock_sensor_get_local(90), 26);
        assert_eq!(stock_sensor_get_local(64 + 40), 40);

        // get_remote: raw 90 → centered 26 → (26*1.008 - 27.8613)/1.11 ≈ -1.49 → (int)-1
        assert_eq!(stock_sensor_get_remote_c(90), -1);
        // raw 100 → centered 36 → (36*1.008 - 27.8613)/1.11 ≈ 7.55 → 7
        assert_eq!(stock_sensor_get_remote_c(100), 7);
        // raw 64 → centered 0 → (0 - 27.8613)/1.11 ≈ -25.1 → -25
        assert_eq!(stock_sensor_get_remote_c(64), -25);

        // calc_offset goldens: match C `(int)(float)(0 - v)` truncation.
        // remote=30, local=25 → 25; remote=10, local=30 → 50; remote=40, local=40 → 31
        assert_eq!(stock_sensor_calc_offset(30, 25), 25);
        assert_eq!(stock_sensor_calc_offset(10, 30), 50);
        assert_eq!(stock_sensor_calc_offset(40, 40), 31);
        // Cross-check float path identity for one pair
        let v = 30.0_f64 - (25.0 + 273.15) * 0.101190476 - 25.0;
        let expect = ((0.0_f64 - v) as f32) as i32 as i8;
        assert_eq!(stock_sensor_calc_offset(30, 25), expect);

        // Inventory still positions sensor residual (I/O); pure is available offline.
        let steps = plan_stock_cold_boot_library_inventory(
            &StockColdBootCompositionParams::offline_golden_one_chain(),
        );
        assert!(steps
            .iter()
            .any(|s| matches!(s, StockColdBootLibraryStep::ResidualSensorCalibration)));
        assert!(!stock_cold_boot_composition_is_phase4b_admitted());

        // Structural: pure constants appear once as SSOT (not invent open code in HAL).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Ok(exec) =
            std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
        {
            assert!(
                !exec.contains("0.101190476") && !exec.contains("27.8613"),
                "HAL must not open-code sensor float constants (pure SSOT)"
            );
        }
    }

    /// G45: T9+ init_uart_baud pure bauddiv (Capstone @3450C: 1666666, 432, 3125000, clamp 26).
    #[test]
    fn g45_stock_init_uart_bauddiv_matches_t9() {
        assert_eq!(STOCK_INIT_UART_BAUD_NUMER_A, 1_666_666);
        assert_eq!(STOCK_INIT_UART_BAUD_SCALE, 432);
        assert_eq!(STOCK_INIT_UART_BAUD_NUMER_B, 3_125_000);
        assert_eq!(STOCK_INIT_UART_BAUDDIV_MAX, 26);
        assert_eq!(
            STOCK_INIT_UART_BAUDDIV_MAX,
            STOCK_OPEN_CORE_DEFAULT_BAUD_DIV_LOW5
        );

        // Zero timeout refuse.
        assert_eq!(stock_init_uart_bauddiv(0), None);

        // timeout=943 (G40 @ 500 MHz / interval 4 / core 114):
        // q=1666666/943=1767; r=432*1767=763344; 3125000/763344=4; bauddiv=3
        assert_eq!(stock_dev_timeout_auto(4, 114, 500), Some(943));
        assert_eq!(stock_init_uart_bauddiv(943), Some(3));

        // More goldens vs integer formula.
        assert_eq!(stock_init_uart_bauddiv(725), Some(2)); // ~650 MHz path
        assert_eq!(stock_init_uart_bauddiv(2358), Some(9)); // ~200 MHz path
        assert_eq!(stock_init_uart_bauddiv(6242), Some(26)); // clamp
        assert_eq!(stock_init_uart_bauddiv(100_000), Some(26));

        // Not S9-jig <<9 scale: (1666666/943)<<9 → different bauddiv.
        let s9_style_r = (1_666_666u32 / 943) << 9;
        let s9_style = 3_125_000u32 / s9_style_r - 1;
        assert_ne!(s9_style, 3, "T9+ uses *432 not <<9; pin anti-alias S9 jig");

        // Inventory wires pure InitUartBauddiv + SetBaud bauddiv=3 for offline golden.
        let steps = plan_stock_cold_boot_library_inventory(
            &StockColdBootCompositionParams::offline_golden_one_chain(),
        );
        assert!(steps.iter().any(|s| matches!(
            s,
            StockColdBootLibraryStep::InitUartBauddiv {
                timeout: 943,
                bauddiv: 3
            }
        )));
        assert!(steps
            .iter()
            .any(|s| matches!(s, StockColdBootLibraryStep::SetBaud { bauddiv: 3, .. })));
        // Caller override wins for set_baud path (lab / S11-force style).
        let forced = plan_stock_cold_boot_library_inventory(&StockColdBootCompositionParams {
            bauddiv: Some(1),
            ..StockColdBootCompositionParams::offline_golden_one_chain()
        });
        assert!(forced
            .iter()
            .any(|s| matches!(s, StockColdBootLibraryStep::SetBaud { bauddiv: 1, .. })));
        // Pure InitUartBauddiv still recorded for honesty when timeout known.
        assert!(forced.iter().any(|s| matches!(
            s,
            StockColdBootLibraryStep::InitUartBauddiv { bauddiv: 3, .. }
        )));

        // Phase 4b still false; pure InitUartBauddiv is a library step (not residual count).
        assert!(!stock_cold_boot_composition_is_phase4b_admitted());
        let (lib, res) = stock_cold_boot_inventory_counts(&steps);
        assert!(lib >= 7, "InitUartBauddiv counts as library: lib={lib}");
        assert!(res >= 3, "fan/sensor/pic residuals remain: res={res}");
    }

    /// G41: cold-boot library inventory order matches T9+ held pure steps; Phase 4b not admitted.
    #[test]
    fn g41_stock_cold_boot_library_inventory_order() {
        assert!(!stock_cold_boot_composition_is_phase4b_admitted());

        let p = StockColdBootCompositionParams::offline_golden_one_chain();
        let steps = plan_stock_cold_boot_library_inventory(&p);
        assert!(!steps.is_empty());

        // First: software_set_address
        assert!(matches!(
            &steps[0],
            StockColdBootLibraryStep::SoftwareSetAddress {
                chain: 0,
                addr_interval: 4
            }
        ));
        // Contains set_freq, set_baud, open_core, ticket, dual TIME_OUT
        assert!(steps.iter().any(|s| matches!(
            s,
            StockColdBootLibraryStep::SetFreqBm1387Broadcast {
                chain: 0,
                freq_mhz: 500
            }
        )));
        // G45: timeout=943 @ 500 MHz → pure bauddiv=3 (not hard-coded 0x1A).
        assert!(steps.iter().any(|s| matches!(
            s,
            StockColdBootLibraryStep::InitUartBauddiv {
                timeout: 943,
                bauddiv: 3,
            }
        )));
        assert!(steps
            .iter()
            .any(|s| matches!(s, StockColdBootLibraryStep::SetBaud { bauddiv: 3, .. })));
        assert!(steps.iter().any(|s| matches!(
            s,
            StockColdBootLibraryStep::OpenCoreOneChain {
                chain: 0,
                baud_div_low5: 3,
                nullwork_enable: true,
                ..
            }
        )));
        assert!(steps.iter().any(|s| matches!(
            s,
            StockColdBootLibraryStep::TicketMaskAndHcnt {
                ticket_mask: 63,
                hcnt: 0,
                ..
            }
        )));
        assert!(steps
            .iter()
            .any(|s| matches!(s, StockColdBootLibraryStep::ResidualFanPwmConfig)));
        assert!(steps
            .iter()
            .any(|s| matches!(s, StockColdBootLibraryStep::ResidualFanPwmFull)));

        // Relative order (T9+ interleave including residuals).
        let idx = |pred: fn(&StockColdBootLibraryStep) -> bool| {
            steps.iter().position(pred).expect("step present")
        };
        let i_addr = idx(|s| matches!(s, StockColdBootLibraryStep::SoftwareSetAddress { .. }));
        let i_freq = idx(|s| matches!(s, StockColdBootLibraryStep::SetFreqBm1387Broadcast { .. }));
        let i_fan_cfg = idx(|s| matches!(s, StockColdBootLibraryStep::ResidualFanPwmConfig));
        let i_tout_auto = idx(|s| matches!(s, StockColdBootLibraryStep::TimeoutAuto { .. }));
        let i_baud = idx(|s| matches!(s, StockColdBootLibraryStep::SetBaud { .. }));
        let i_sensor = idx(|s| matches!(s, StockColdBootLibraryStep::ResidualSensorCalibration));
        let i_toc_div10 = idx(|s| {
            matches!(
                s,
                StockColdBootLibraryStep::TimeOutControl {
                    scale: StockTimeOutControlScale::Div10,
                    ..
                }
            )
        });
        let i_fan_full = idx(|s| matches!(s, StockColdBootLibraryStep::ResidualFanPwmFull));
        let i_oc = idx(|s| matches!(s, StockColdBootLibraryStep::OpenCoreOneChain { .. }));
        let i_oc_settle = idx(|s| {
            matches!(
                s,
                StockColdBootLibraryStep::DelayMs(STOCK_COLD_BOOT_OPEN_CORE_SETTLE_MS)
            )
        });
        let i_tm = idx(|s| matches!(s, StockColdBootLibraryStep::TicketMaskAndHcnt { .. }));
        let i_toc_final = steps
            .iter()
            .rposition(|s| matches!(s, StockColdBootLibraryStep::TimeOutControl { .. }))
            .expect("final toc");
        // Second Div10 after open_core (L837), before ticket.
        let toc_div10_count = steps
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    StockColdBootLibraryStep::TimeOutControl {
                        scale: StockTimeOutControlScale::Div10,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(toc_div10_count, 2);
        let i_toc_div10_post = steps
            .iter()
            .rposition(|s| {
                matches!(
                    s,
                    StockColdBootLibraryStep::TimeOutControl {
                        scale: StockTimeOutControlScale::Div10,
                        ..
                    }
                )
            })
            .expect("post-oc div10");
        assert!(i_addr < i_freq);
        assert!(i_freq < i_fan_cfg);
        assert!(i_fan_cfg < i_tout_auto);
        assert!(i_tout_auto < i_baud);
        assert!(i_baud < i_sensor);
        assert!(i_sensor < i_toc_div10);
        assert!(i_toc_div10 < i_fan_full);
        assert!(i_fan_full < i_oc);
        assert!(i_oc < i_oc_settle);
        assert!(i_oc < i_toc_div10_post);
        assert!(i_toc_div10_post < i_tm);
        assert!(i_tm < i_toc_final);

        // Timeout golden matches G40 auto for params.
        match &steps[i_tout_auto] {
            StockColdBootLibraryStep::TimeoutAuto { timeout, .. } => {
                assert_eq!(*timeout, stock_dev_timeout_auto(4, 114, 500));
                assert_eq!(*timeout, Some(943));
            }
            _ => panic!("timeout step"),
        }

        let (lib, res) = stock_cold_boot_inventory_counts(&steps);
        assert!(lib >= 6, "library steps present");
        assert!(res >= 3, "named residuals present");

        // Multi-chain: N open_core, one set_baud, one ticket step.
        let multi = plan_stock_cold_boot_library_inventory(&StockColdBootCompositionParams {
            chains: vec![0, 2, 5],
            ..StockColdBootCompositionParams::offline_golden_one_chain()
        });
        let oc_n = multi
            .iter()
            .filter(|s| matches!(s, StockColdBootLibraryStep::OpenCoreOneChain { .. }))
            .count();
        let baud_n = multi
            .iter()
            .filter(|s| matches!(s, StockColdBootLibraryStep::SetBaud { .. }))
            .count();
        assert_eq!(oc_n, 3);
        assert_eq!(baud_n, 1);

        // Honesty: Phase 4b not admitted; stock_mining passthrough; no composition *call sites*.
        assert!(!stock_cold_boot_composition_is_phase4b_admitted());
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let sm = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            sm.contains("passthrough") && sm.contains("not yet admitted"),
            "Phase 4b must remain passthrough / not admitted"
        );
        // Ban invoke forms (not comment mentions of the concept).
        assert!(
            !sm.contains("plan_stock_cold_boot_library_inventory(")
                && !sm.contains("stock_cold_boot_composition_is_phase4b_admitted()")
                && !sm.contains("execute_stock_cold_boot"),
            "Phase 4b must not call composition inventory as auto-wire"
        );
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            !exec.contains("plan_stock_cold_boot_library_inventory")
                && !exec.contains("execute_stock_cold_boot_composition"),
            "HAL must not auto-execute full cold-boot composition"
        );
    }

    /// G40: core_number + timeout + TIME_OUT_CONTROL pure arithmetic (T9+).
    #[test]
    fn g40_stock_timeout_math_matches_t9() {
        assert_eq!(stock_calculate_core_number(1), Some(1));
        assert_eq!(stock_calculate_core_number(2), Some(2));
        assert_eq!(stock_calculate_core_number(3), Some(4));
        assert_eq!(stock_calculate_core_number(4), Some(4));
        assert_eq!(stock_calculate_core_number(5), Some(8));
        assert_eq!(stock_calculate_core_number(8), Some(8));
        assert_eq!(stock_calculate_core_number(9), Some(16));
        assert_eq!(stock_calculate_core_number(17), Some(32));
        assert_eq!(stock_calculate_core_number(33), Some(64));
        assert_eq!(stock_calculate_core_number(65), Some(128));
        assert_eq!(stock_calculate_core_number(114), Some(128));
        assert_eq!(stock_calculate_core_number(128), Some(128));
        assert_eq!(stock_calculate_core_number(0), None);
        assert_eq!(stock_calculate_core_number(129), None);

        // addr=4, core=114→128, freq=500:
        // ticks=16777216/128=131072; 4*131072/500=1048; 90*1048/100=943
        assert_eq!(stock_dev_timeout_auto(4, 114, 500), Some(943));
        // clamp
        assert_eq!(
            stock_dev_timeout_auto(255, 1, 1).map(|t| t <= STOCK_TIMEOUT_MAX),
            Some(true)
        );
        assert!(stock_dev_timeout_auto(4, 114, 0).is_none());
        assert!(stock_dev_timeout_auto(4, 200, 500).is_none());

        assert_eq!(
            stock_time_out_control_reg(943, StockTimeOutControlScale::Div10),
            (94 & 0x1_FFFF) | 0x8000_0000
        );
        assert_eq!(
            stock_time_out_control_reg(943, StockTimeOutControlScale::Identity),
            (943 & 0x1_FFFF) | 0x8000_0000
        );
        assert_eq!(
            stock_time_out_control_reg(100, StockTimeOutControlScale::Multiversion(4)),
            (400 & 0x1_FFFF) | 0x8000_0000
        );
        // enable bit always set
        assert_eq!(
            stock_time_out_control_reg(0, StockTimeOutControlScale::Identity),
            0x8000_0000
        );
        assert_eq!(STOCK_TIMEOUT_MAX, 131_071);
        assert_eq!(STOCK_TIMEOUT_CORE_TICKS, 16_777_216);
        assert_eq!(STOCK_REG_TIME_OUT_CONTROL, 0x088);

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_time_out_control")
                && exec.contains("stock_time_out_control_reg")
                && exec.contains("STOCK_REG_TIME_OUT_CONTROL"),
            "G40 HAL must write pure-packed TIME_OUT_CONTROL"
        );
        let fpga = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga.rs"))
            .expect("stock_fpga");
        assert!(
            fpga.contains("REG_TIME_OUT_CONTROL") && fpga.contains("0x088"),
            "HAL stock map must keep TIME_OUT_CONTROL @ 0x088"
        );
    }

    /// G39: VIL ticket_mask(63) + hcnt(0) pure SSOT (T9+ post-open_core).
    #[test]
    fn g39_stock_ticket_mask_and_hcnt_matches_t9_vil() {
        // ticket mask reg 0x18, held 63
        let tm = plan_stock_set_asic_ticket_mask_vil(1, STOCK_INIT_ASIC_TICKET_MASK);
        assert_eq!(tm.reg, STOCK_ASIC_TICKET_MASK_REG);
        assert_eq!(tm.reg, 0x18);
        assert_eq!(tm.cmd_buf[0], 0x5809_0018); // T9+ 1476984856
        assert_eq!(tm.cmd_buf[1], 63);
        assert_eq!(tm.value, 63);
        assert_eq!(tm.frame[3], 0x18);
        assert_eq!(tm.frame[4..8], [0, 0, 0, 63]);
        assert_eq!(tm.settle_us, 0);
        assert_eq!(tm.frame[8], stock_bitmain_crc5(&tm.frame[..8], 64));
        assert_eq!(tm.cmd_buf[2], (tm.frame[8] as u32) << 24);

        // hcnt reg 0x14, held 0
        let hc = plan_stock_set_hcnt_vil(2, 0);
        assert_eq!(hc.reg, STOCK_HCNT_REG);
        assert_eq!(hc.reg, 0x14);
        assert_eq!(hc.cmd_buf[0], 0x5809_0014); // T9+ 1476984852
        assert_eq!(hc.cmd_buf[1], 0);
        assert_eq!(hc.frame[3], 0x14);
        assert_eq!(hc.frame[4..8], [0, 0, 0, 0]);
        assert_eq!(hc.settle_us, 0);

        // Non-zero hcnt packs BE into frame / cmd1 = value
        let hc2 = plan_stock_set_hcnt_vil(0, 0x0102_0304);
        assert_eq!(hc2.cmd_buf[1], 0x0102_0304);
        assert_eq!(hc2.frame[4..8], [0x01, 0x02, 0x03, 0x04]);

        // Multi-chain init pair: N ticket then N hcnt
        let init = plan_stock_init_ticket_mask_and_hcnt_vil(&[0, 2]);
        assert_eq!(init.len(), 4);
        assert_eq!(init[0].cmd_buf[0], 0x5809_0018);
        assert_eq!(init[0].cmd_buf[1], 63);
        assert_eq!(init[0].chain, 0);
        assert_eq!(init[1].chain, 2);
        assert_eq!(init[1].cmd_buf[1], 63);
        assert_eq!(init[2].cmd_buf[0], 0x5809_0014);
        assert_eq!(init[2].cmd_buf[1], 0);
        assert_eq!(init[2].chain, 0);
        assert_eq!(init[3].chain, 2);

        // Honesty: not G24 BitReversed invent for stock init 63
        // 63 plain is held; BitReversed(63) would differ — pin plain value.
        assert_eq!(STOCK_INIT_ASIC_TICKET_MASK, 63);

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_set_asic_ticket_mask")
                && exec.contains("execute_stock_set_hcnt")
                && exec.contains("plan_stock_init_ticket_mask_and_hcnt_vil"),
            "G39 HAL must execute pure ticket_mask + hcnt plans"
        );
        let sm = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            sm.contains("passthrough")
                && (sm.contains("G32")
                    || sm.contains("EXPERIMENTAL")
                    || sm.contains("composition")),
            "stock_mining must keep Phase 4b passthrough honesty after G39"
        );
    }

    /// G38: VIL set_baud pure SSOT (T9+ set_baud@342D8) — distinct from open_core gateblk.
    #[test]
    fn g38_stock_set_baud_matches_t9_vil() {
        // MiscCtrl value goldens (bauddiv low-5 only).
        assert_eq!(stock_set_baud_misc_value(0x1A), 0x0020_1A00);
        assert_eq!(stock_set_baud_misc_value(0), 0x0020_0000);
        assert_eq!(stock_set_baud_misc_value(0x1F), 0x0020_1F00);
        assert_eq!(stock_set_baud_misc_value(0x3F), 0x0020_1F00); // mask low-5
                                                                  // Must NOT equal open_core gateblk at same baud.
        assert_ne!(
            stock_set_baud_misc_value(0x1A),
            stock_open_core_gateblk_misc_value(0x1A)
        );
        assert_eq!(stock_open_core_gateblk_misc_value(0x1A), 0x4020_9A80);

        let plan = plan_stock_set_baud_vil(2, 0x1A);
        assert_eq!(plan.chain, 2);
        assert!(plan.broadcast);
        assert_eq!(plan.reg, STOCK_BM1387_MISC_CTRL_REG);
        assert_eq!(plan.cmd_buf[0], 0x5809_001C); // T9+ 1476984860
        assert_eq!(plan.cmd_buf[1], 0x0020_1A00);
        assert_eq!(plan.cmd_buf[2], (plan.frame[8] as u32) << 24);
        assert_eq!(plan.frame[0], 0x58);
        assert_eq!(plan.frame[1], 0x09);
        assert_eq!(plan.frame[2], 0);
        assert_eq!(plan.frame[3], 0x1C);
        assert_eq!(plan.frame[4], 0x00);
        assert_eq!(plan.frame[5], 0x20);
        assert_eq!(plan.frame[6], 0x1A);
        assert_eq!(plan.frame[7], 0x00);
        assert_eq!(plan.frame[8], stock_bitmain_crc5(&plan.frame[..8], 64));
        assert_eq!(plan.settle_us, 0, "T9+ set_baud: no per-chain 10ms settle");

        // Host baud merge: low-5 only.
        assert_eq!(
            stock_bc_write_merge_host_baud(0x1234_5678, 0x1A),
            0x1234_5678 & !0x1F | 0x1A
        );
        assert_eq!(stock_bc_write_merge_host_baud(0xFFFF_FFFF, 0), 0xFFFF_FFE0);
        assert_eq!(
            stock_bc_write_merge_host_baud(0xABCD_0000, 0x1F),
            0xABCD_001F
        );

        let ops = plan_stock_set_baud_one_chain_vil(0, 0x1A);
        assert_eq!(ops.len(), 3);
        assert_eq!(ops, plan_stock_set_baud_chains_vil(&[0], 0x1A));
        match &ops[0] {
            StockSetBaudOp::BcSetConfig(p) => {
                assert_eq!(p.cmd_buf[0], 0x5809_001C);
                assert_eq!(p.cmd_buf[1], 0x0020_1A00);
                assert_eq!(p.settle_us, 0);
            }
            _ => panic!("op0 must be BcSetConfig"),
        }
        assert_eq!(
            ops[1],
            StockSetBaudOp::DelayUs(STOCK_SET_BAUD_POST_ALL_CHAINS_SETTLE_US)
        );
        assert_eq!(ops[2], StockSetBaudOp::MergeHostBaud { bauddiv: 0x1A });
        assert_eq!(STOCK_SET_BAUD_POST_ALL_CHAINS_SETTLE_US, 50_000);

        // Multi-chain: N BC + 1 settle + 1 merge (not 3N).
        let multi = plan_stock_set_baud_chains_vil(&[0, 2, 5], 0x0C);
        assert_eq!(multi.len(), 3 + 2); // N+2
        let bc_count = multi
            .iter()
            .filter(|o| matches!(o, StockSetBaudOp::BcSetConfig(_)))
            .count();
        let delay_count = multi
            .iter()
            .filter(|o| matches!(o, StockSetBaudOp::DelayUs(_)))
            .count();
        let merge_count = multi
            .iter()
            .filter(|o| matches!(o, StockSetBaudOp::MergeHostBaud { .. }))
            .count();
        assert_eq!(bc_count, 3);
        assert_eq!(delay_count, 1);
        assert_eq!(merge_count, 1);
        match &multi[2] {
            StockSetBaudOp::BcSetConfig(p) => assert_eq!(p.chain, 5),
            _ => panic!("third op BC for chain 5"),
        }

        // HAL + honesty structural pins.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_set_baud_one_chain")
                && exec.contains("execute_stock_set_baud_chains")
                && exec.contains("stock_bc_write_merge_host_baud")
                && exec.contains("plan_stock_set_baud_one_chain_vil")
                && exec.contains("plan_stock_set_baud_chains_vil"),
            "G38 HAL must execute pure set_baud one-chain + multi-chain plans"
        );
        // No non-VIL invent: pure set_baud uses VIL only; HAL module states no legacy invent.
        assert!(
            exec.contains("Does **not** invent non-VIL")
                || exec.contains("does **not** invent non-VIL"),
            "G38 HAL must refuse non-VIL legacy invent"
        );
        // set_baud misc must not collapse into open_core gateblk 0x4020 base.
        assert!(
            !exec.contains("stock_set_baud_misc_value")
                || !exec.contains("0x4020_0080")
                || exec.contains("stock_open_core_gateblk"),
            "G38 set_baud must stay distinct from open_core gateblk base"
        );
        let sm = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            sm.contains("passthrough")
                && (sm.contains("G32")
                    || sm.contains("composition")
                    || sm.contains("EXPERIMENTAL")),
            "stock_mining must keep Phase 4b passthrough honesty after G38"
        );
    }

    /// G36: VIL open_core_one_chain pure SSOT (gateblk + 114 TW + DHASH).
    #[test]
    fn g36_stock_open_core_one_chain_matches_t9_vil() {
        // Gateblk MiscCtrl value for baud 0x1A
        let g = stock_open_core_gateblk_misc_value(0x1A);
        assert_eq!(g, 0x4020_9A80); // (0x9A<<8)|0x40200080
        assert_eq!(stock_open_core_gateblk_misc_value(0), 0x4020_8080);

        // DHASH entry/exit
        assert_eq!(
            stock_open_core_dhash_entry(0x0000_0020, 1),
            (1 << 8) | 0x8000 | (0x20 & 0xFFFF_7FDF)
        );
        assert_eq!(
            stock_open_core_dhash_exit(0x0000_8100, 1),
            0x0000_8100 | (1 << 8) | 0x8000
        );

        // Dummy TW first vs rest
        let w0 = stock_open_core_dummy_tw_words(0, 0);
        assert_eq!(w0[0], 0x1180_0000); // type 17, chain_id 0x80
        assert_eq!(w0[1], 0);
        assert_eq!(w0[2], 0x1100_0080);
        assert_eq!(w0[3], 0);
        assert_eq!(w0[4], 0xFFFF_FFFF);
        let w1 = stock_open_core_dummy_tw_words(2, 5);
        assert_eq!(w1[0], 0x0182_0000); // type 1, chain_id 0x82
        assert_eq!(w1[2], 0x0100_0082);

        // Plan shape
        let ops = plan_stock_open_core_one_chain_vil(0, 0x1A, 1, true);
        assert!(matches!(
            ops[0],
            StockOpenCoreOp::DhashEntry { multi_version: 1 }
        ));
        assert!(matches!(ops[1], StockOpenCoreOp::ClearHashCounting));
        assert!(matches!(
            ops[2],
            StockOpenCoreOp::BcNullworkPrelude { chain: 0 }
        ));
        let gate = ops.iter().find_map(|o| match o {
            StockOpenCoreOp::GateblkSetConfig(p) => Some(p),
            _ => None,
        });
        let gate = gate.expect("gateblk");
        assert_eq!(gate.cmd_buf[0], 0x5809_001C);
        assert_eq!(gate.cmd_buf[1], 0x4020_9A80);
        assert_eq!(gate.reg, 0x1C);
        let tw_count = ops
            .iter()
            .filter(|o| matches!(o, StockOpenCoreOp::TwWriteVil { .. }))
            .count();
        assert_eq!(tw_count, 114);
        assert!(ops
            .iter()
            .any(|o| matches!(o, StockOpenCoreOp::BcNullworkEnable)));
        assert!(ops
            .iter()
            .any(|o| matches!(o, StockOpenCoreOp::DhashExit { .. })));
        // Without nullwork
        let ops2 = plan_stock_open_core_one_chain_vil(1, 0, 4, false);
        assert!(!ops2
            .iter()
            .any(|o| matches!(o, StockOpenCoreOp::BcNullworkEnable)));

        // Buffer space wait
        assert!(stock_buffer_space_ready(0x01, 0));
        assert!(!stock_buffer_space_ready(0x00, 0));
        assert_eq!(
            stock_buffer_space_wait_step(0x01, 0, 3001),
            StockBufferSpaceWaitStep::Ready
        );
        assert_eq!(
            stock_buffer_space_wait_step(0x00, 0, 3),
            StockBufferSpaceWaitStep::SleepThenRepoll {
                sleep_us: 1000,
                attempts_after_sleep: 2,
            }
        );

        // HAL must wire execute_stock_open_core_one_chain
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_open_core_one_chain")
                && exec.contains("stock_open_core_dhash_entry")
                && exec.contains("STOCK_REG_TW_WRITE_COMMAND")
                && exec.contains("stock_buffer_space_wait_step"),
            "G36 HAL must execute pure open_core VIL plan"
        );
        // No non-VIL invent (0x86 gateblk header) — case-insensitive invent pin.
        let invent_pin =
            exec.contains("does **not** invent") || exec.contains("Does **not** invent");
        assert!(
            !exec.contains("0x86") || invent_pin,
            "G36 must not invent non-VIL 0x86 gateblk"
        );
        let sm = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            sm.contains("open_core")
                && (sm.contains("EXPERIMENTAL")
                    || sm.contains("composition residual")
                    || sm.contains("passthrough")),
            "stock_mining must not silently claim open_core production cold-boot"
        );
    }

    /// G35: VIL chain_inactive + set_address + software_set_address pure SSOT.
    #[test]
    fn g35_stock_software_set_address_matches_t9_vil() {
        // chain_inactive: cmd0 = 0x55050000, cmd1 = CRC5<<24
        let ina = plan_stock_bc_chain_inactive_vil(2);
        assert!(ina.pre_ready_poll);
        assert_eq!(ina.chain, 2);
        assert_eq!(ina.payload4, [0x55, 0x05, 0x00, 0x00]);
        assert_eq!(ina.cmd_buf[0], 0x5505_0000);
        assert_eq!(ina.crc5, stock_bitmain_crc5(&ina.payload4, 32));
        assert_eq!(ina.cmd_buf[1], (ina.crc5 as u32) << 24);
        assert_eq!(ina.cmd_buf[2], 0);

        // set_address @ 0x00 and 0x04
        let a0 = plan_stock_bc_set_address_vil(0, 0x00);
        assert_eq!(a0.cmd_buf[0], 0x4105_0000);
        assert_eq!(a0.payload4, [0x41, 0x05, 0x00, 0x00]);
        let a4 = plan_stock_bc_set_address_vil(1, 0x04);
        assert_eq!(a4.cmd_buf[0], 0x4105_0000 | (0x04 << 8));
        assert_eq!(a4.cmd_buf[0], 0x4105_0400);
        assert_eq!(a4.crc5, stock_bitmain_crc5(&[0x41, 0x05, 0x04, 0x00], 32));

        // Trigger merge from pre-ready status (not invent).
        let trig = stock_bc_vil_cmd_trigger_write(&ina, 0x1234_5678);
        assert_eq!(
            trig,
            (0x0C0, (0x1234_5678 & 0xFFF0_FFFF) | (2 << 16) | 0x8080_0000)
        );

        // Pre-ready step SSOT.
        assert_eq!(stock_bc_pre_ready_step(0, 3001), StockBcPreReadyStep::Ready);
        assert_eq!(
            stock_bc_pre_ready_step(0x8000_0000, 5),
            StockBcPreReadyStep::SleepThenRepoll {
                sleep_ms: 1,
                attempts_after_sleep: 4,
            }
        );
        assert_eq!(
            stock_bc_pre_ready_step(0x8000_0000, 0),
            StockBcPreReadyStep::Timeout
        );

        // software_set_address composition: 3 inactive + 64 set_address, dwell after each.
        let ops = plan_stock_software_set_address(0, 4);
        let bc_count = ops
            .iter()
            .filter(|o| matches!(o, StockSoftwareSetAddressOp::Bc(_)))
            .count();
        let delay_count = ops
            .iter()
            .filter(|o| matches!(o, StockSoftwareSetAddressOp::DelayMs(30)))
            .count();
        assert_eq!(bc_count, 3 + 64); // 3 inactive + 256/4 addresses
        assert_eq!(delay_count, 3 + 64);
        // First three BC ops are inactive.
        for op in ops.iter().take(6).step_by(2) {
            match op {
                StockSoftwareSetAddressOp::Bc(p) => {
                    assert_eq!(p.cmd_buf[0], 0x5505_0000);
                }
                _ => panic!("expected inactive BC"),
            }
        }
        // Address ladder: 0,4,8,...,252
        let addrs: Vec<u8> = ops
            .iter()
            .filter_map(|o| match o {
                StockSoftwareSetAddressOp::Bc(p) if p.cmd_buf[0] != 0x5505_0000 => {
                    Some(p.payload4[2])
                }
                _ => None,
            })
            .collect();
        assert_eq!(addrs.len(), 64);
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 4);
        assert_eq!(addrs[63], 252);

        // HAL must wire pre-ready execute (structural).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let exec = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_bc_execute.rs"))
            .expect("stock_bc_execute");
        assert!(
            exec.contains("execute_stock_bc_vil_cmd_pre_ready")
                && exec.contains("execute_stock_software_set_address")
                && exec.contains("stock_bc_pre_ready_step")
                && exec.contains("stock_bc_vil_cmd_trigger_write"),
            "G35 HAL must execute pure VIL inactive/address with pre-ready order"
        );
        // stock_mining must not claim open_core is done.
        let sm = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        assert!(
            sm.contains("open_core")
                && (sm.contains("composition residual")
                    || sm.contains("NOT IMPLEMENTED")
                    || sm.contains("not yet implemented")),
            "stock_mining must keep open_core / full cold-boot honest NI"
        );
    }

    #[test]
    fn hal_dispatch_commits_single_count_and_refuses_four_way() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga_work.rs"))
            .expect("stock_fpga_work");
        let start = src.find("pub fn dispatch_work(").expect("dispatch_work");
        // Only the single-version dispatch_work body (before asicboost twin).
        let end = src[start..]
            .find("pub fn dispatch_work_asicboost")
            .map(|i| start + i)
            .unwrap_or(start + 2_500);
        let body = &src[start..end];
        assert!(
            body.contains("resume_after_job_commit")
                && body.contains("StockDhashMidstateMode::Single"),
            "single-version dispatch_work must program explicit count one"
        );
        assert!(
            body.contains("plan_stock_dma_job")
                && body.contains("plan.buffer_payload()")
                && body.contains("split_at(plan.padded_coinbase_len())")
                && body.contains("set_coinbase_layout(plan.coinbase_layout())")
                && body.contains("set_nonce2_parts(plan.nonce2_low(), plan.nonce2_high())")
                && body.contains("REG_JOB_LENGTH")
                && body.contains("plan.job_length()"),
            "live single-version dispatch must consume the exact coupled DMA job plan"
        );
        let job_address = body.find("REG_JOB_START_ADDRESS").expect("job address");
        let job_id = body.find("REG_JOB_ID").expect("job id");
        let version = body
            .find("REG_BLOCK_HEADER_VERSION")
            .expect("block version");
        assert!(
            job_address < job_id && job_id < version,
            "exact S9j scalar spine must publish JOB_START, JOB_ID, then VERSION"
        );
        assert!(
            body.contains("self.poisoned = true")
                && body.contains("self.active_buffer = published_buffer"),
            "ambiguous post-quiesce failures must poison the engine after publishing ownership"
        );
        let ab_start = src
            .find("pub fn dispatch_work_asicboost")
            .expect("dispatch_work_asicboost");
        let ab_body: String = src[ab_start..].chars().take(5_000).collect();
        assert!(
            ab_body.contains("four-way AsicBoost is refused")
                && !ab_body.contains("StockDhashMidstateMode::FourWay"),
            "AsicBoost dispatch must not program count four before aperture admission"
        );
    }

    #[test]
    fn hal_dhash_setter_rewrites_and_checks_full_word_ignoring_bit_seven() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga_work.rs"))
            .expect("stock_fpga_work");
        let start = src
            .find("fn write_dhash_control_verified")
            .expect("verified DHASH setter");
        let body: String = src[start..].chars().take(1_500).collect();
        assert!(body.contains("for _ in 0..DHASH_STOP_MAX_POLLS"));
        assert!(body.contains("write_reg(REG_DHASH_ACC_CONTROL, requested)"));
        assert!(body.contains("DHASH_STOP_POLL_DELAY_MS"));
        assert!(body.contains("(requested | DHASH_NEW_BLOCK) == (observed | DHASH_NEW_BLOCK)"));
    }

    #[test]
    fn stock_mining_keeps_asicboost_behind_fail_closed_policy() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        let mining_start = src.find("let mut work_builder").expect("work_builder");
        let body: String = src[mining_start..].chars().take(30_000).collect();
        assert!(
            body.contains("dispatch_work_asicboost") && body.contains("stock_asicboost_admitted"),
            "stock mining must gate dispatch_work_asicboost on pure admit"
        );
        assert!(
            body.contains("set_version_mask") || body.contains("version_mask"),
            "stock mining must observe job/work version_mask for AsicBoost"
        );
        // G15 spine preserved: still key history from fpga_job_id low byte.
        assert!(
            body.contains("(fpga_job_id & 0xFF) as u8"),
            "G15 REG_JOB_ID history key must remain"
        );
        // Do not invent share-dedup on stock path.
        assert!(
            !body.contains("SeenShareSet"),
            "G17 must not invent SeenShareSet on stock"
        );
    }
}
