//! Stock FPGA DMA work dispatch and nonce collection.
//!
//! The stock Bitmain FPGA uses a fundamentally different work dispatch model
//! from BraiinsOS's per-chain FIFO approach:
//!
//! 1. **CPU writes and verifies job data** in the inactive DMA buffer.
//! 2. **CPU clears and polls DHASH RUN bit 6** before shared job-register writes.
//! 3. **CPU publishes the inactive buffer address and job metadata**.
//! 4. **CPU commits the job** with the final midstate-count + VIL/RUN/operation RMW.
//! 5. **FPGA distributes work** to all 3 chains simultaneously via DMA.
//! 6. **FPGA collects nonces** into the shared RETURN_NONCE FIFO.
//!
//! Double-buffering: two 64 KiB DDR regions alternate at offsets 0x200000 and
//! 0x210000. The separate 2 MiB region at offset zero is reserved for the
//! FPGA-written nonce2/job-id mapping store. Physical base is admitted from the
//! kernel module parameter as 0x0F000000, 0x1F000000, or 0x3F000000.
//!
//! Four-way AsicBoost remains fail-closed: exact S9j extra version lanes
//! `0x164..0x16c` exceed the currently admitted logical aperture.
//!
//! Source: S9_STOCK_FPGA_REGISTER_MAP.md, S9_STOCK_BMMINER_RE.md

use std::num::NonZeroUsize;

use nix::sys::mman::{MapFlags, ProtFlags};

use crate::stock_fpga::*;
use crate::{HalError, Result};

// ---------------------------------------------------------------------------
// DMA buffer layout
// ---------------------------------------------------------------------------

/// Stock-supported physical bases selected by the kernel module from RAM size.
pub const STOCK_DMA_BASE_256M: u32 = 0x0F00_0000;
pub const STOCK_DMA_BASE_512M: u32 = 0x1F00_0000;
pub const STOCK_DMA_BASE_1G: u32 = 0x3F00_0000;
pub const STOCK_DMA_BASES: [u32; 3] = [STOCK_DMA_BASE_256M, STOCK_DMA_BASE_512M, STOCK_DMA_BASE_1G];

/// FPGA-written nonce2/job-id mapping store (2 MiB) starts at DMA offset zero.
pub const NONCE2_JOBID_STORE_OFFSET: u32 = 0;
pub const NONCE2_JOBID_STORE_SIZE: usize = 0x0020_0000;

/// CPU-written double-buffered job regions from the stock cgminer layout.
///
/// These must never alias the mapping store. The previous implementation
/// incorrectly alternated back to 0x1F000000 and overwrote FPGA correlation
/// records on every second dispatch.
pub const JOB_BUFFER_0_OFFSET: u32 = 0x0020_0000;
pub const JOB_BUFFER_1_OFFSET: u32 = 0x0021_0000;
pub const JOB_BUFFER_SIZE: usize = 0x0001_0000;

/// Admitted physical layout for one loaded `fpga_mem_driver` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockDmaLayout {
    physical_base: u32,
}

impl StockDmaLayout {
    /// Accept only the three RAM-dependent bases present in stock Bitmain
    /// startup scripts and cgminer constants. Unknown/aligned guesses fail.
    pub fn admit(physical_base: u64) -> Result<Self> {
        let physical_base = u32::try_from(physical_base).map_err(|_| {
            HalError::Other(format!(
                "stock FPGA DMA base 0x{physical_base:X} exceeds the 32-bit register ABI"
            ))
        })?;
        if !STOCK_DMA_BASES.contains(&physical_base) {
            return Err(HalError::Other(format!(
                "unverified stock FPGA DMA base 0x{physical_base:08X}; expected one of 0x0F000000, 0x1F000000, or 0x3F000000"
            )));
        }
        Ok(Self { physical_base })
    }

    pub const fn physical_base(self) -> u32 {
        self.physical_base
    }

    pub const fn nonce2_jobid_store(self) -> u32 {
        self.physical_base + NONCE2_JOBID_STORE_OFFSET
    }

    pub const fn job_buffer_0(self) -> u32 {
        self.physical_base + JOB_BUFFER_0_OFFSET
    }

    pub const fn job_buffer_1(self) -> u32 {
        self.physical_base + JOB_BUFFER_1_OFFSET
    }
}

const FPGA_MEM_OFFSET_PARAMETER_PATHS: [&str; 2] = [
    "/sys/module/fpga_mem_driver/parameters/fpga_mem_offset_addr",
    "/sys/module/fpga_mem/parameters/fpga_mem_offset_addr",
];

fn parse_stock_dma_base(raw: &str) -> Result<u64> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(HalError::Other(
            "empty fpga_mem_offset_addr module parameter".to_string(),
        ));
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|error| {
            HalError::Other(format!(
                "invalid hexadecimal fpga_mem_offset_addr {value:?}: {error}"
            ))
        })
    } else {
        value.parse::<u64>().map_err(|error| {
            HalError::Other(format!(
                "invalid decimal fpga_mem_offset_addr {value:?}: {error}"
            ))
        })
    }
}

fn discover_stock_dma_layout() -> Result<StockDmaLayout> {
    let mut observed: Option<(String, u64)> = None;
    for path in FPGA_MEM_OFFSET_PARAMETER_PATHS {
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        let base = parse_stock_dma_base(&raw)?;
        if let Some((previous_path, previous_base)) = &observed {
            if *previous_base != base {
                return Err(HalError::Other(format!(
                    "conflicting stock FPGA DMA bases: {previous_path}=0x{previous_base:X}, {path}=0x{base:X}"
                )));
            }
        } else {
            observed = Some((path.to_string(), base));
        }
    }
    let Some((source, base)) = observed else {
        return Err(HalError::Other(format!(
            "cannot verify stock FPGA DMA base: none of {} exists",
            FPGA_MEM_OFFSET_PARAMETER_PATHS.join(", ")
        )));
    };
    let layout = StockDmaLayout::admit(base)?;
    tracing::info!(
        source,
        physical_base = format_args!("0x{:08X}", layout.physical_base()),
        "Admitted stock FPGA DMA layout from kernel module parameter"
    );
    Ok(layout)
}

/// Work item size in DMA buffer (64 bytes = 0x40).
/// Each work item contains: work_id, version, counter, reserved,
/// target[4], midstate[8], extra[4] = 20 words = 80 bytes.
/// (Actual used fields may be smaller; 64 bytes is the slot size.)
pub const WORK_ITEM_SIZE: usize = 64;

/// Maximum work items per DMA buffer.
pub const MAX_WORK_ITEMS: usize = NONCE2_JOBID_STORE_SIZE / WORK_ITEM_SIZE;

// ---------------------------------------------------------------------------
// Nonce return format
// ---------------------------------------------------------------------------

/// Nonce value register (32-bit golden nonce).
/// Read from REG_RETURN_NONCE (0x010).
///
/// Extended data at REG_RETURN_NONCE_EXT (0x014):
/// Contains chain_id, job_id, chip_id encoded fields.
///
/// Format of extended word (from bmminer debug):
///   "FPGA recv : buf[0]=0x%08x buf[1]=0x%08x"
///   buf[0] = nonce, buf[1] = chain_id + job_id + solution_idx
///
/// Number of nonce words per result (nonce + extended data).
pub const NONCE_WORDS: usize = 2;

// ---------------------------------------------------------------------------
// StockFpgaDma — DMA buffer access
// ---------------------------------------------------------------------------

/// DMA buffer access via /dev/fpga_mem.
///
/// Provides mmap'd access to the 16 MB DDR region selected by the kernel
/// module for work data transfer between CPU and FPGA.
pub struct StockFpgaDma {
    /// mmap'd pointer to DMA region base.
    dma_base: *mut u8,
    /// File handle for /dev/fpga_mem (kept open for mmap lifetime).
    _dma_file: std::fs::File,
    /// Total mmap size.
    dma_size: usize,
    /// Physical address programmed into FPGA registers for this mapping.
    layout: StockDmaLayout,
}

// SAFETY: StockFpgaDma holds an mmap'd pointer that is process-global.
unsafe impl Send for StockFpgaDma {}
unsafe impl Sync for StockFpgaDma {}

impl StockFpgaDma {
    /// Open the DMA buffer interface.
    ///
    /// Opens /dev/fpga_mem and mmaps the 16 MB DMA region.
    /// The physical base is read back from the `fpga_mem_driver` kernel module
    /// parameter and admitted against the stock RAM-dependent address set
    /// before the device is opened.
    pub fn open() -> Result<Self> {
        let layout = discover_stock_dma_layout()?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEV_FPGA_MEM)
            .map_err(|e| HalError::DeviceOpen {
                path: DEV_FPGA_MEM.to_string(),
                source: e,
            })?;

        let dma_size = DMA_SIZE;
        let ptr = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(dma_size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &file,
                0,
            )
            .map_err(|e| HalError::MmapFailed {
                device: DEV_FPGA_MEM.to_string(),
                source: e,
            })?
        };

        tracing::info!(
            size = format_args!("{} MB", dma_size / (1024 * 1024)),
            physical_base = format_args!("0x{:08X}", layout.physical_base()),
            "Stock FPGA DMA buffer opened ({} MB at /dev/fpga_mem)",
            dma_size / (1024 * 1024),
        );

        Ok(Self {
            dma_base: ptr.as_ptr() as *mut u8,
            _dma_file: file,
            dma_size,
            layout,
        })
    }

    pub const fn layout(&self) -> StockDmaLayout {
        self.layout
    }

    /// Get a mutable pointer to an offset within the DMA region.
    ///
    /// The offset is relative to the admitted physical DMA base.
    /// The nonce2/job-id store begins at offset 0; job buffers begin at
    /// offsets 0x200000 and 0x210000.
    ///
    /// # Safety
    /// Caller must ensure offset + access size does not exceed DMA region.
    fn ptr_at(&self, offset: usize) -> *mut u8 {
        debug_assert!(
            offset < self.dma_size,
            "DMA offset 0x{:X} out of bounds (size=0x{:X})",
            offset,
            self.dma_size
        );
        unsafe { self.dma_base.add(offset) }
    }

    /// Write a 32-bit word at the given byte offset in the DMA region.
    #[inline]
    pub fn write_word(&self, offset: usize, value: u32) {
        debug_assert!(offset + 4 <= self.dma_size);
        debug_assert!(offset.is_multiple_of(4));
        unsafe {
            let ptr = self.ptr_at(offset) as *mut u32;
            std::ptr::write_volatile(ptr, value);
        }
    }

    /// Read a 32-bit word at the given byte offset in the DMA region.
    #[inline]
    pub fn read_word(&self, offset: usize) -> u32 {
        debug_assert!(offset + 4 <= self.dma_size);
        debug_assert!(offset.is_multiple_of(4));
        unsafe {
            let ptr = self.ptr_at(offset) as *const u32;
            std::ptr::read_volatile(ptr)
        }
    }

    /// Write a block of bytes to the DMA region.
    pub fn write_bytes(&self, offset: usize, data: &[u8]) {
        debug_assert!(offset + data.len() <= self.dma_size);
        unsafe {
            let dst = self.ptr_at(offset);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
    }

    /// Write and read back one inactive job-buffer region before it is
    /// published to DHASH.
    pub fn write_bytes_verified(&self, offset: usize, data: &[u8]) -> Result<()> {
        offset
            .checked_add(data.len())
            .filter(|end| *end <= self.dma_size)
            .ok_or_else(|| {
                HalError::Other(format!(
                    "stock FPGA DMA range 0x{offset:X}+0x{:X} exceeds mapped size 0x{:X}",
                    data.len(),
                    self.dma_size
                ))
            })?;
        for (index, byte) in data.iter().copied().enumerate() {
            unsafe {
                std::ptr::write_volatile(self.ptr_at(offset + index), byte);
            }
        }
        for (index, expected) in data.iter().copied().enumerate() {
            let observed = unsafe { std::ptr::read_volatile(self.ptr_at(offset + index)) };
            if observed != expected {
                return Err(HalError::Other(format!(
                    "stock FPGA DMA readback mismatch at 0x{:X}: wrote 0x{expected:02X}, read 0x{observed:02X}",
                    offset + index
                )));
            }
        }
        Ok(())
    }
}

impl Drop for StockFpgaDma {
    fn drop(&mut self) {
        // Kernel exit cleanup is sufficient for the DMA mapping.
    }
}

// ---------------------------------------------------------------------------
// StockFpgaWorkEngine — high-level work dispatch + nonce collection
// ---------------------------------------------------------------------------

/// High-level work dispatch engine for the stock Bitmain FPGA.
///
/// Manages double-buffered single-version DMA dispatch, DHASH control, and
/// nonce FIFO reading. Four-way AsicBoost remains explicitly refused.
///
/// This is the stock equivalent of FpgaChain's write_work() / read_nonce()
/// methods, but operates on ALL chains simultaneously (stock FPGA does not
/// have per-chain work dispatch).
pub struct StockFpgaWorkEngine<'a> {
    /// Reference to the FPGA register interface.
    fpga: &'a StockFpga,
    /// Reference to the DMA buffer interface.
    dma: &'a StockFpgaDma,
    /// Current active DMA buffer index (0 or 1 for double-buffering).
    active_buffer: u8,
    /// Current job ID counter.
    job_id: u32,
    /// A pool clean-job transition to pulse immediately before the next final
    /// commit. Primary S9 source and the multi-model 46e9579a... test-jig image
    /// do this; the e5312ad1... S9j recovery image omits it, so this is an
    /// explicit firmware-profile differential rather than universal parity.
    pending_new_block: bool,
    /// Set after a post-quiesce control-write failure. The requested RUN write
    /// may have reached hardware even when readback never matched, so buffer
    /// ownership is uncertain and this engine must never dispatch again.
    poisoned: bool,
}

impl<'a> StockFpgaWorkEngine<'a> {
    /// Create a new work engine.
    pub fn new(fpga: &'a StockFpga, dma: &'a StockFpgaDma) -> Self {
        Self {
            fpga,
            dma,
            active_buffer: 0,
            job_id: 0,
            pending_new_block: false,
            poisoned: false,
        }
    }

    /// Initialize the DHASH accelerator for VIL mode mining (full init).
    ///
    /// Sets up the DHASH control register, nonce2/jobid store address,
    /// and initial job start address. Must be called before dispatching work.
    ///
    pub fn init(&mut self) -> Result<()> {
        // Exact S9j open-core initializes this live hash-counting/liveness
        // register to zero. It is not a topology or total-chip-count field.
        self.fpga.write_reg(REG_HASH_COUNTING_NUMBER, 0);

        // Set nonce2/jobid store address
        self.fpga.write_reg(
            REG_NONCE2_AND_JOBID_STORE_ADDRESS,
            self.dma.layout().nonce2_jobid_store(),
        );

        // Set initial job start address.
        self.fpga
            .write_reg(REG_JOB_START_ADDRESS, self.dma.layout().job_buffer_0());

        // Enable nonce FIFO interrupt
        self.fpga
            .write_reg(REG_NONCE_FIFO_INTERRUPT, NONCE_IRQ_ENABLE | 0x01);

        // Set timeout (enabled, ~40000 cycles)
        self.fpga.set_timeout(0x8000_9C40);

        // Admit the VIL/count-one/operation fields but remain quiesced until a
        // verified job has been published. RUN is asserted only by the final
        // per-job commit RMW.
        let quiesced_dhash = dhash_stop_value(DHASH_MINING_VIL);
        self.write_dhash_control_verified(quiesced_dhash)?;

        self.active_buffer = 0;
        self.job_id = 0;
        self.pending_new_block = false;
        self.poisoned = false;

        tracing::info!(
            dhash = format_args!("0x{quiesced_dhash:08X}"),
            "Stock FPGA work engine initialized quiesced (VIL mode, full init)"
        );
        Ok(())
    }

    /// Passthrough init — preserve the inherited DHASH state.
    ///
    /// In passthrough mode, a previous runtime already configured the DHASH accelerator.
    /// We only read the current state and set our job_id counter to continue
    /// from where that runtime left off. DO NOT overwrite DHASH_ACC_CONTROL or
    /// NONCE2_AND_JOBID_STORE_ADDRESS.
    pub fn init_passthrough(&mut self) -> Result<()> {
        let dhash = self.fpga.read_reg(REG_DHASH_ACC_CONTROL);
        let job_id = self.fpga.read_reg(REG_JOB_ID);
        let job_start = self.fpga.read_reg(REG_JOB_START_ADDRESS);
        let nonce2_store = self.fpga.read_reg(REG_NONCE2_AND_JOBID_STORE_ADDRESS);
        let buffer_space = self.fpga.read_reg(REG_BUFFER_SPACE);

        let layout = self.dma.layout();
        if nonce2_store != layout.nonce2_jobid_store() {
            return Err(HalError::Other(format!(
                "inherited stock FPGA nonce2 store 0x{nonce2_store:08X} does not match admitted kernel DMA base 0x{:08X}",
                layout.nonce2_jobid_store()
            )));
        }

        // Continue from the inherited job_id
        self.job_id = job_id;
        self.pending_new_block = false;
        self.poisoned = false;

        // Determine active buffer from JOB_START_ADDRESS
        if job_start == layout.job_buffer_1() {
            self.active_buffer = 1;
        } else if job_start == layout.job_buffer_0() {
            self.active_buffer = 0;
        } else {
            return Err(HalError::Other(format!(
                "inherited stock FPGA job buffer 0x{job_start:08X} is outside admitted DMA layout (expected 0x{:08X} or 0x{:08X})",
                layout.job_buffer_0(),
                layout.job_buffer_1()
            )));
        }

        tracing::info!(
            dhash = format_args!("0x{:08X}", dhash),
            job_id = format_args!("0x{:08X}", job_id),
            job_start = format_args!("0x{:08X}", job_start),
            nonce2_store = format_args!("0x{:08X}", nonce2_store),
            buffer_space = format_args!("0x{:02X}", buffer_space),
            "Stock FPGA work engine passthrough: preserving inherited DHASH state"
        );
        Ok(())
    }

    /// Get the physical address of the currently inactive (writable) DMA buffer.
    fn writable_buffer_phys(&self) -> u64 {
        if self.active_buffer == 0 {
            u64::from(self.dma.layout().job_buffer_1())
        } else {
            u64::from(self.dma.layout().job_buffer_0())
        }
    }

    /// Get the DMA offset of the currently inactive (writable) buffer.
    fn writable_buffer_offset(&self) -> usize {
        if self.active_buffer == 0 {
            JOB_BUFFER_1_OFFSET as usize
        } else {
            JOB_BUFFER_0_OFFSET as usize
        }
    }

    /// Write previous block hash to FPGA PRE_HEADER_HASH registers.
    ///
    /// Writes 8 x 32-bit words to registers 0x140-0x15C.
    ///
    /// **IMPORTANT**: In VIL mode, these registers contain the PREVIOUS BLOCK HASH,
    /// NOT the midstate! The FPGA computes the midstate internally from:
    ///   prev_hash + coinbase (DMA) + merkle branches (DMA) + ntime + nbits + version.
    ///
    /// The prev_hash is in pool/stratum byte order (each 4-byte word is byte-swapped
    /// relative to the block header's internal format).
    pub fn write_prev_hash(&self, prev_hash: &[u32; 8]) {
        for (i, &word) in prev_hash.iter().enumerate() {
            self.fpga
                .write_reg(REG_PRE_HEADER_HASH_BASE + (i as u32 * 4), word);
        }
    }

    /// Write block header fields to FPGA registers.
    ///
    /// # Arguments
    /// * `version` - Block version (with overt ASICBoost version bits if enabled)
    /// * `ntime` - Block timestamp
    /// * `nbits` - Compact difficulty target
    pub fn write_header_fields(&self, version: u32, ntime: u32, nbits: u32) {
        self.fpga.write_reg(
            REG_BLOCK_HEADER_VERSION,
            dcentrald_common::stock_fpga_header_scalar_word(version),
        );
        self.fpga.write_reg(
            REG_TIME_STAMP,
            dcentrald_common::stock_fpga_header_scalar_word(ntime),
        );
        self.fpga.write_reg(
            REG_TARGET_BITS,
            dcentrald_common::stock_fpga_header_scalar_word(nbits),
        );
    }

    /// Set the exact 64-bit nonce2 start value.
    pub fn set_nonce2_parts(&self, low: u32, high: u32) {
        self.fpga.write_reg(REG_WORK_NONCE2, low);
        self.fpga.write_reg(REG_WORK_NONCE2_HIGH, high);
    }

    /// Write the pure planner's exact `0x104` word:
    /// `nonce2_offset<<16 | nonce2_len<<8 | padded_coinbase_blocks`.
    pub fn set_coinbase_layout(&self, value: u32) {
        self.fpga.write_reg(REG_COINBASE_AND_NONCE2_LENGTH, value);
    }

    /// Set the number of merkle branches.
    pub fn set_merkle_count(&self, count: u32) {
        self.fpga.write_reg(REG_MERKLE_BIN_NUMBER, count);
    }

    /// Exact S9j DHASH setter: rewrite after each mismatch, sleep 2 ms, and
    /// compare the complete requested word while ignoring self-clearing bit 7.
    fn write_dhash_control_verified(&self, requested: u32) -> Result<()> {
        self.fpga.write_reg(REG_DHASH_ACC_CONTROL, requested);
        for _ in 0..DHASH_STOP_MAX_POLLS {
            let observed = self.fpga.read_reg(REG_DHASH_ACC_CONTROL);
            if (requested | DHASH_NEW_BLOCK) == (observed | DHASH_NEW_BLOCK) {
                return Ok(());
            }
            self.fpga.write_reg(REG_DHASH_ACC_CONTROL, requested);
            std::thread::sleep(std::time::Duration::from_millis(DHASH_STOP_POLL_DELAY_MS));
        }
        Err(HalError::Other(format!(
            "stock FPGA DHASH control 0x{requested:08X} was not acknowledged after {DHASH_STOP_MAX_POLLS} readback attempts"
        )))
    }

    /// Clear RUN and require its bounded acknowledgement before replacing
    /// shared job MMIO. Inactive DDR may be prepared before this barrier.
    fn quiesce_for_job_commit(&self, mode: dcentrald_common::StockDhashMidstateMode) -> Result<()> {
        let dhash = self.fpga.read_reg(REG_DHASH_ACC_CONTROL);
        let mut quiesced = dhash_stop_value(dhash);
        if dcentrald_common::stock_dhash_midstate_count(dhash) != mode.count() {
            quiesced |= DHASH_MIDSTATE_COUNT_CHANGE;
        }
        self.write_dhash_control_verified(quiesced)?;
        std::thread::sleep(std::time::Duration::from_millis(1));
        Ok(())
    }

    /// Final job-commit RMW: replace only the midstate-count nibble and assert
    /// VIL, RUN, and operation mode. NEW_BLOCK bit 7 is FPGA-owned.
    fn resume_after_job_commit(
        &self,
        mode: dcentrald_common::StockDhashMidstateMode,
    ) -> Result<()> {
        let current = self.fpga.read_reg(REG_DHASH_ACC_CONTROL);
        let value = dcentrald_common::stock_dhash_with_midstate_mode(
            current & !DHASH_MIDSTATE_COUNT_CHANGE,
            mode,
        ) | DHASH_VIL_MODE
            | DHASH_RUN
            | DHASH_OPERATION_MODE;
        self.write_dhash_control_verified(value)
    }

    /// Write job data to the inactive DMA buffer and dispatch to FPGA.
    ///
    /// This is the main work submission function, equivalent to bmminer's
    /// `set_TW_write_command_vil()` for VIL/AsicBoost mode.
    ///
    /// In VIL mode, the FPGA computes the midstate internally from:
    ///   prev_hash (registers) + coinbase (DMA) + merkle (DMA) + ntime + nbits + version.
    ///
    /// # Arguments
    /// * `job_data` - Complete job data (coinbase + merkle branches) to write to DMA
    /// * `prev_hash` - Previous block hash (8 x 32-bit words, pool byte order)
    /// * `version` - Block version
    /// * `ntime` - Block timestamp
    /// * `nbits` - Compact difficulty target
    ///
    /// # Returns
    /// The job ID assigned to this work item.
    pub fn dispatch_work(
        &mut self,
        job_data: &[u8],
        prev_hash: &[u32; 8],
        version: u32,
        ntime: u32,
        nbits: u32,
        coinbase_len: usize,
        nonce2_len: usize,
        nonce2_offset: usize,
        merkle_count: usize,
    ) -> Result<u32> {
        if self.poisoned {
            return Err(HalError::Other(
                "stock FPGA work engine is poisoned after an ambiguous control-write failure"
                    .to_owned(),
            ));
        }
        let plan = dcentrald_common::plan_stock_dma_job(
            job_data,
            coinbase_len,
            nonce2_offset,
            nonce2_len,
            merkle_count,
        )
        .map_err(|error| HalError::Other(format!("invalid stock FPGA DMA job: {error:?}")))?;

        // Exact e5312ad1... ordering verifies the SHA-padded coinbase first,
        // then writes and verifies the merkle region separately.
        let buf_offset = self.writable_buffer_offset();
        let (padded_coinbase, merkle_payload) =
            plan.buffer_payload().split_at(plan.padded_coinbase_len());
        self.dma.write_bytes_verified(buf_offset, padded_coinbase)?;
        if !merkle_payload.is_empty() {
            self.dma
                .write_bytes_verified(buf_offset + plan.padded_coinbase_len(), merkle_payload)?;
        }
        if let Err(error) =
            self.quiesce_for_job_commit(dcentrald_common::StockDhashMidstateMode::Single)
        {
            self.poisoned = true;
            return Err(error);
        }

        // Exact S9-family order publishes the verified inactive buffer before
        // the remaining shared job registers. The final DHASH RMW is the
        // commit trigger; register 0x120 is not written by the exact S9j path.
        let published_buffer = self.active_buffer ^ 1;
        self.fpga
            .write_reg(REG_JOB_START_ADDRESS, self.writable_buffer_phys() as u32);
        // The address is now hardware-visible. Advance ownership before any
        // later fallible control write; a failure poisons the engine.
        self.active_buffer = published_buffer;

        // Exact S9j scalar order publishes the correlation ID immediately
        // after the job address (and optional ticket mask, which this lane does
        // not mutate), before version/header fields.
        let next_job_id = self.job_id.wrapping_add(1);
        self.fpga.write_reg(REG_JOB_ID, next_job_id);
        self.job_id = next_job_id;

        // Exact S9j order after JOB_ID: version, previous hash,
        // timestamp/target, then coupled coinbase/nonce2/merkle/job length.
        self.fpga.write_reg(
            REG_BLOCK_HEADER_VERSION,
            dcentrald_common::stock_fpga_header_scalar_word(version),
        );
        self.write_prev_hash(prev_hash);
        self.fpga.write_reg(
            REG_TIME_STAMP,
            dcentrald_common::stock_fpga_header_scalar_word(ntime),
        );
        self.fpga.write_reg(
            REG_TARGET_BITS,
            dcentrald_common::stock_fpga_header_scalar_word(nbits),
        );
        self.set_coinbase_layout(plan.coinbase_layout());
        self.set_nonce2_parts(plan.nonce2_low(), plan.nonce2_high());
        self.set_merkle_count(u32::from(plan.merkle_count()));
        self.fpga
            .write_reg(REG_JOB_LENGTH, u32::from(plan.job_length()));

        // One-millisecond publication settle precedes the final DHASH commit.
        std::thread::sleep(std::time::Duration::from_millis(1));
        if self.pending_new_block {
            let current = self.fpga.read_reg(REG_DHASH_ACC_CONTROL);
            if let Err(error) = self.write_dhash_control_verified(current | DHASH_NEW_BLOCK) {
                self.poisoned = true;
                return Err(error);
            }
            self.pending_new_block = false;
        }
        if let Err(error) =
            self.resume_after_job_commit(dcentrald_common::StockDhashMidstateMode::Single)
        {
            self.poisoned = true;
            return Err(error);
        }

        tracing::trace!(
            job_id = self.job_id,
            len = plan.job_length(),
            buffer = self.active_buffer,
            "Dispatched work to stock FPGA"
        );

        Ok(self.job_id)
    }

    /// Fail-closed four-way AsicBoost entry point.
    ///
    /// Exact S9j uses version lanes `0x130,0x164,0x168,0x16c`. The latter
    /// three exceed the current logical FPGA aperture, so no mutation is
    /// emitted until a board/revision-specific mapping and nonce-correlation
    /// contract are admitted.
    pub fn dispatch_work_asicboost(
        &mut self,
        job_data: &[u8],
        prev_hash: &[u32; 8],
        base_version: u32,
        version_mask: u32,
        ntime: u32,
        nbits: u32,
        coinbase_len: usize,
        nonce2_len: usize,
        nonce2_offset: usize,
        merkle_count: usize,
    ) -> Result<u32> {
        let _ = (
            job_data,
            prev_hash,
            base_version,
            version_mask,
            ntime,
            nbits,
            coinbase_len,
            nonce2_len,
            nonce2_offset,
            merkle_count,
        );
        Err(HalError::Other(
            "stock FPGA four-way AsicBoost is refused: exact S9j lanes 0x164..0x16c are outside the admitted aperture"
                .to_string(),
        ))
    }

    /// Check how many nonces are pending in the FIFO.
    pub fn nonce_count(&self) -> u32 {
        self.fpga.read_reg(REG_NONCE_NUMBER_IN_FIFO)
    }

    /// Check if there are any nonces available.
    pub fn has_nonces(&self) -> bool {
        self.nonce_count() > 0
    }

    /// Read a nonce from the FIFO.
    ///
    /// Returns None if no nonces are pending.
    /// Returns (nonce, extended_data) where:
    ///   - nonce: 32-bit golden nonce value
    ///   - extended_data: chain_id + job_id + solution_idx encoded
    pub fn read_nonce(&self) -> Option<(u32, u32)> {
        if !self.has_nonces() {
            return None;
        }

        let nonce = self.fpga.read_reg(REG_RETURN_NONCE);
        let ext = self.fpga.read_reg(REG_RETURN_NONCE_EXT);

        Some((nonce, ext))
    }

    /// Flush all pending nonces from the FIFO.
    ///
    /// Uses the NONCE_FIFO_INTERRUPT register's flush bit.
    /// Called on clean_jobs to discard stale nonces from the previous block.
    pub fn flush_nonces(&self) {
        let count = self.nonce_count();
        if count > 0 {
            tracing::info!(
                count,
                "Flushing {} stale nonces from stock FPGA FIFO",
                count
            );
        }

        // Set flush bit in NONCE_FIFO_INTERRUPT
        let current = self.fpga.read_reg(REG_NONCE_FIFO_INTERRUPT);
        self.fpga
            .write_reg(REG_NONCE_FIFO_INTERRUPT, current | NONCE_FIFO_FLUSH);

        // Clear flush bit
        std::thread::sleep(std::time::Duration::from_millis(1));
        self.fpga
            .write_reg(REG_NONCE_FIFO_INTERRUPT, current & !NONCE_FIFO_FLUSH);
    }

    /// Read the current job ID from the FPGA.
    pub fn current_job_id(&self) -> u32 {
        self.fpga.read_reg(REG_JOB_ID)
    }

    /// Check available buffer space.
    ///
    /// Returns the BUFFER_SPACE register value. When idle, this mirrors
    /// HASH_ON_PLUG. When mining, it indicates available work slots.
    pub fn buffer_space(&self) -> u32 {
        self.fpga.read_reg(REG_BUFFER_SPACE)
    }

    /// Signal a new block (clean_jobs from pool).
    ///
    /// Primary S9 source and the multi-model 46e9579a... test-jig image map a
    /// clean-job indication to self-clearing DHASH bit 7 immediately before
    /// the final commit. The e5312ad1... S9j recovery image omits the pulse;
    /// retaining it here is a conservative profile-unifying behavior paired
    /// with the mandatory RUN-clear barrier.
    pub fn signal_new_block(&mut self) {
        self.pending_new_block = true;
        self.flush_nonces();
    }

    /// Stop the DHASH accelerator and require the recovered bit-six clear
    /// acknowledgement. A false result requires the caller to continue to a
    /// rail-safe teardown rather than claiming the work engine is quiescent.
    pub fn stop(&self) -> bool {
        // Signed S9j shutdown first disables BC nullwork, then clears DHASH
        // RUN. This prevents dummy work from continuing during heartbeat join
        // and rail teardown.
        let bc_write = self.fpga.read_reg(REG_BC_WRITE_COMMAND);
        self.fpga.write_reg(
            REG_BC_WRITE_COMMAND,
            dcentrald_common::stock_shutdown_bc_disable_nullwork(bc_write),
        );
        let dhash = self.fpga.read_reg(REG_DHASH_ACC_CONTROL);
        match self.write_dhash_control_verified(dhash_stop_value(dhash)) {
            Ok(()) => {
                tracing::info!("Stock FPGA DHASH accelerator stopped");
                true
            }
            Err(error) => {
                tracing::error!(%error, "Stock FPGA DHASH RUN clear was not acknowledged; rail-safe teardown required");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WorkBackend — runtime selection between UIO/devmem (Zynq) and
//               bitmain_axi.ko mmap (BB / CV1835), with optional dev/debug
//               IOCTL fallback under the `axi-ioctl-debug` Cargo feature.
// ---------------------------------------------------------------------------

/// Stock-FPGA work-shuttle backend, picked at runtime based on the kernel
/// devices present.
///
/// Two flavors:
///
/// * [`WorkBackend::UioDma`] — the existing Zynq path. The FPGA is integrated
///   PL on a Zynq SoC, exposed via `/dev/uio*` for register access and
///   `/dev/fpga_mem` for DMA buffers. This is the default for every miner
///   we ship today (S9 / S17 / S19 / S19j Pro Zynq / S21).
///
/// * [`WorkBackend::AxiBitmain`] — an external-FPGA path for AM335x
///   BeagleBone-class control boards and Cvitek CV1835 control boards. The
///   FPGA is SPI-attached and the `bitmain_axi.ko` kernel module exposes it
///   via `/dev/axi_fpga_dev`. **Production canonical is mmap** per RE3
///   (`bitmain_axi_ioctl_report.md` — DWARF-confirms zero IOCTL handlers in
///   shipping `bitmain_axi.ko` and `cv183x_base.ko`). The dev/debug IOCTL
///   ABI lives in [`crate::stock_fpga_axi_mmap::BitmainAxiUnifiedBackend`]
///   and is only compiled in when the `axi-ioctl-debug` Cargo feature is
///   enabled (W13.B5 retired the W10-era runtime env-gate
///   `DCENT_BB_TRUST_INFERRED_AXI_IOCTL`).
///
/// Use [`WorkBackend::select`] to auto-pick the right backend; it never
/// changes behavior on Zynq fleets (uio0 is present → UIO/DMA wins). Direct
/// constructors are also provided for tests and explicit lab overrides.
pub enum WorkBackend {
    /// Zynq integrated-PL path (default). Requires `/dev/fpga_mem` to be
    /// present; the caller still provides the `StockFpga` register handle
    /// separately (it lives on `/dev/axi_fpga_dev` major 245 on Zynq stock,
    /// or via UIO on BraiinsOS).
    UioDma(StockFpgaDma),

    /// External SPI-attached FPGA via `bitmain_axi.ko` (BB / CV1835).
    /// Production path is mmap; dev/debug IOCTL fallback compiled in only
    /// under the `axi-ioctl-debug` Cargo feature.
    AxiBitmain(crate::stock_fpga_axi_mmap::BitmainAxiUnifiedBackend),
}

impl WorkBackend {
    /// Pick the right backend based on what kernel devices exist.
    ///
    /// Order of preference:
    /// 1. `BitmainAxiUnifiedBackend::try_open()` — only succeeds when
    ///    `/dev/axi_fpga_dev` exists AND `/dev/uio*` does NOT (BB / CV1835).
    ///    Production builds get mmap exclusively (RE3 canonical).
    /// 2. `StockFpgaDma::open()` — the existing UIO/devmem DMA path (Zynq).
    ///
    /// On every Zynq miner currently in the fleet, step 1 returns `Ok(None)`
    /// because `/dev/uio0` is always present, so step 2 wins. There is **no
    /// behavior change on Zynq**.
    pub fn select() -> Result<Self> {
        if let Some(axi) = crate::stock_fpga_axi_mmap::BitmainAxiUnifiedBackend::try_open()? {
            tracing::info!(
                mmap = axi.is_mmap(),
                ioctl = axi.is_ioctl(),
                "WorkBackend: AxiBitmain (bitmain_axi.ko) selected"
            );
            return Ok(WorkBackend::AxiBitmain(axi));
        }

        let dma = StockFpgaDma::open()?;
        tracing::info!("WorkBackend: UioDma (UIO + /dev/fpga_mem) selected");
        Ok(WorkBackend::UioDma(dma))
    }

    /// Returns `true` if this backend is the BB/CV1835 bitmain_axi path
    /// (mmap in production; IOCTL only when `axi-ioctl-debug` is on AND
    /// mmap declined).
    pub fn is_axi_bitmain(&self) -> bool {
        matches!(self, WorkBackend::AxiBitmain(_))
    }

    /// Returns `true` if this backend is the Zynq UIO/DMA path.
    pub fn is_uio_dma(&self) -> bool {
        matches!(self, WorkBackend::UioDma(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stock_dma_layout_keeps_job_buffers_outside_mapping_store() {
        for base in STOCK_DMA_BASES {
            let layout = StockDmaLayout::admit(u64::from(base)).expect("evidence-backed base");
            let store_end = layout.nonce2_jobid_store() + NONCE2_JOBID_STORE_SIZE as u32;
            assert_eq!(store_end, layout.job_buffer_0());
            assert_eq!(
                layout.job_buffer_1() - layout.job_buffer_0(),
                JOB_BUFFER_SIZE as u32
            );
            assert!(layout.job_buffer_0() >= store_end);
            assert!(layout.job_buffer_1() >= store_end);
        }
        assert_eq!(MAX_WORK_ITEMS, 32_768);
    }

    #[test]
    fn writable_job_buffer_offsets_match_stock_cgminer_layout() {
        assert_eq!(JOB_BUFFER_0_OFFSET, 0x0020_0000);
        assert_eq!(JOB_BUFFER_1_OFFSET, 0x0021_0000);
    }

    #[test]
    fn stock_dma_layout_refuses_unknown_or_out_of_range_bases() {
        for base in [0, 0x1000, 0x2F00_0000, 0x4F00_0000, u64::MAX] {
            assert!(
                StockDmaLayout::admit(base).is_err(),
                "unverified base 0x{base:X} must fail closed"
            );
        }
    }

    #[test]
    fn stock_dma_module_parameter_parser_accepts_kernel_hex_and_decimal_forms() {
        assert_eq!(parse_stock_dma_base("0x0F000000\n").unwrap(), 0x0F00_0000);
        assert_eq!(parse_stock_dma_base("520093696").unwrap(), 0x1F00_0000);
        assert_eq!(parse_stock_dma_base("1056964608\n").unwrap(), 0x3F00_0000);
        assert!(parse_stock_dma_base("").is_err());
        assert!(parse_stock_dma_base("0xnothex").is_err());
    }
}
