// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentaxe-asic
//
// ASIC driver crate for BitAxe mining hardware.
// Rust port of ESP-Miner ASIC drivers (BM1366, BM1368, BM1370, BM1397).
//
// Each driver faithfully reproduces the init sequences, register writes,
// job packet construction, and response parsing from the original C code.

pub mod common;
pub mod crc;
pub mod pll;
pub mod serial;

pub mod bm1366;
pub mod bm1368;
pub mod bm1370;
pub mod bm1373;
pub mod bm1397;

// Research-only KF1950 (WhatsMiner K-series) driver. UNTESTED.
// Gated by `asic-kf1950` Cargo feature, default OFF.
#[cfg(feature = "asic-kf1950")]
pub mod kf1950;

// MSBT0501 / LT0051 — the Scrypt ASIC in the Hammer DC0x line.
// Gated by `asic-lt0051`, default OFF. The driver is a FAIL-CLOSED scaffold
// (every trait method returns Err) whose frame builders/parsers are real and
// host-tested; see the module header for the open protocol residuals.
#[cfg(feature = "asic-lt0051")]
pub mod lt0051;

#[cfg(test)]
mod test_utils;

// Re-export key types at crate root for convenience
pub use common::{
    AsicError, AsicModel, AsicResult, MiningJob, PowAlgorithm, RegisterData, RegisterType,
};
pub use serial::SerialPort;

/// Core ASIC driver trait -- each chip variant implements this.
///
/// The driver manages the full lifecycle of an ASIC mining chain:
/// initialization, work dispatch, nonce collection, frequency control,
/// and telemetry reads.
pub trait AsicDriver: Send {
    /// Initialize the ASIC chain: detect chips, set addresses, configure registers.
    ///
    /// Performs the full init sequence (chip detection, register configuration,
    /// address assignment, frequency ramp-up).
    ///
    /// # Arguments
    /// * `frequency` - Target hash frequency in MHz
    /// * `chain_count` - Expected number of ASIC chips on the chain
    /// * `initial_difficulty` - Starting TicketMask difficulty. ESP-Miner reads this
    ///   from device config (PR #1594 / `bfc422a`). Caller should pass the last-known
    ///   pool difficulty (NVS cache) or 256.0 as a safe default. `set_difficulty()`
    ///   overrides this once the pool's `mining.set_difficulty` arrives.
    ///
    /// # Returns
    /// The actual number of chips detected, or an error.
    fn init(
        &mut self,
        frequency: f32,
        chain_count: u8,
        initial_difficulty: f64,
    ) -> Result<u8, AsicError>;

    /// Send a mining job to the ASIC chain.
    fn send_work(&mut self, job: &MiningJob) -> Result<(), AsicError>;

    /// Process UART responses -- returns nonces found and/or register data.
    ///
    /// Parses the raw UART response bytes and returns zero or more results.
    /// Each result is either a nonce (job response) or a register value.
    fn process_work(&mut self, rx_buf: &[u8]) -> Result<Vec<AsicResult>, AsicError>;

    /// Set hash frequency (MHz).
    fn set_frequency(&mut self, target_freq: f32) -> Result<(), AsicError>;

    /// Set version mask for AsicBoost / version rolling.
    /// (No-op on BM1397 which doesn't support it.)
    fn set_version_mask(&mut self, mask: u32) -> Result<(), AsicError>;

    /// Read all known registers from all chips.
    fn read_registers(&mut self) -> Result<Vec<RegisterData>, AsicError>;

    /// Get the number of detected chips.
    fn chip_count(&self) -> u8;

    /// Get current operating frequency (MHz).
    fn current_frequency(&self) -> f32;

    /// Read and process UART responses with timeout.
    /// Returns nonces found and/or register data.
    fn read_responses(&mut self, timeout_ms: u16) -> Result<Vec<AsicResult>, AsicError>;

    /// Update the ASIC difficulty mask (TicketMask register).
    /// Called when pool difficulty changes to reduce UART traffic
    /// by filtering nonces below pool difficulty in hardware.
    ///
    /// `difficulty` is `f64` to match Stratum V1 fractional
    /// `mining.set_difficulty` support (ESP-Miner PR #1594).
    fn set_difficulty(&mut self, difficulty: f64) -> Result<(), AsicError>;

    /// Switch ASIC UART to maximum baud rate for full-speed mining.
    /// Must be called after init() completes. Returns the new baud rate
    /// so the host UART can be reconfigured to match.
    fn set_max_baud(&mut self) -> Result<u32, AsicError>;
}

/// A driver that refuses every operation, used where a chip is recognised but
/// its driver is not compiled into this build.
///
/// This exists so an unrecognised-driver situation is a REFUSAL rather than a
/// fallthrough to some other chip's driver. Running the wrong chip's init
/// sequence against live silicon is the failure mode this type prevents.
pub struct UnsupportedAsicDriver {
    chip: &'static str,
    reason: &'static str,
}

impl UnsupportedAsicDriver {
    pub const fn new(chip: &'static str, reason: &'static str) -> Self {
        Self { chip, reason }
    }

    fn refuse<T>(&self, op: &str) -> Result<T, AsicError> {
        Err(AsicError::InitFailed(format!(
            "{} {op}: driver not available in this build ({})",
            self.chip, self.reason
        )))
    }
}

impl AsicDriver for UnsupportedAsicDriver {
    fn init(&mut self, _f: f32, _c: u8, _d: f64) -> Result<u8, AsicError> {
        self.refuse("init")
    }
    fn send_work(&mut self, _job: &MiningJob) -> Result<(), AsicError> {
        self.refuse("send_work")
    }
    fn process_work(&mut self, _rx: &[u8]) -> Result<Vec<AsicResult>, AsicError> {
        self.refuse("process_work")
    }
    fn set_frequency(&mut self, _f: f32) -> Result<(), AsicError> {
        self.refuse("set_frequency")
    }
    fn set_version_mask(&mut self, _m: u32) -> Result<(), AsicError> {
        self.refuse("set_version_mask")
    }
    fn read_registers(&mut self) -> Result<Vec<RegisterData>, AsicError> {
        self.refuse("read_registers")
    }
    fn chip_count(&self) -> u8 {
        0
    }
    fn current_frequency(&self) -> f32 {
        0.0
    }
    fn read_responses(&mut self, _t: u16) -> Result<Vec<AsicResult>, AsicError> {
        self.refuse("read_responses")
    }
    fn set_difficulty(&mut self, _d: f64) -> Result<(), AsicError> {
        self.refuse("set_difficulty")
    }
    fn set_max_baud(&mut self) -> Result<u32, AsicError> {
        self.refuse("set_max_baud")
    }
}

/// Supported ASIC model metadata
impl AsicModel {
    /// Which proof-of-work function this chip computes.
    ///
    /// Every Bitmain/Canaan/WhatsMiner part here is SHA-256d; MSBT0501 is the
    /// first Scrypt part. This is the single mapping that lets a board's
    /// dispatcher/stratum algorithm be derived from its chip rather than
    /// hand-set at each site.
    pub const fn pow_algorithm(&self) -> PowAlgorithm {
        match self {
            Self::Lt0051 => PowAlgorithm::Scrypt1024,
            _ => PowAlgorithm::Sha256d,
        }
    }

    /// Default operating frequency for this ASIC model (MHz)
    pub fn default_frequency(&self) -> f32 {
        match self {
            Self::BM1366 => 485.0,
            Self::BM1368 => 490.0,
            Self::BM1370 => 525.0,
            Self::BM1373 => 550.0, // PROJECTED — verify on hardware
            Self::BM1397 => 400.0,
            // MSBT0501: the vendor's own stock default (0x8FC = 2300 MHz).
            // The vendor CLAMP is 700-2600 MHz, but that is what the app
            // permits, not a bench-proven envelope — see `max_frequency`.
            Self::Lt0051 => 2300.0,
            // KF1950: PLL formula not RE'd; the upstream fork hardcodes
            // pll_n=0x80 regardless of target. 400 MHz is a safe placeholder.
            #[cfg(feature = "asic-kf1950")]
            Self::KF1950 => 400.0,
            // Avalon A3197 nominal ~500 MHz; CPM table covers 99-600 MHz in
            // ~1.5 MHz steps (293 entries) per AVALON_ASIC_PROTOCOL.md §8.
            #[cfg(feature = "asic-avalon")]
            Self::Avalon => 500.0,
        }
    }

    /// Maximum safe frequency for this ASIC model (MHz)
    pub fn max_frequency(&self) -> f32 {
        match self {
            Self::BM1366 => 600.0,
            Self::BM1368 => 600.0,
            Self::BM1370 => 650.0,
            Self::BM1373 => 700.0, // PROJECTED — verify on hardware
            Self::BM1397 => 500.0,
            // MSBT0501: pinned to the vendor STOCK default, i.e. ZERO
            // overclock headroom. The vendor firmware clamp tops out at
            // 2600 MHz and its web UI shows 2400, but neither is bench-proven
            // and the protocol contract explicitly says to treat neither as a
            // safe limit. Raise only from a wattmeter+thermal-witnessed soak.
            Self::Lt0051 => 2300.0,
            // KF1950: M30S/M30S+ class — stock WhatsMiner runs ~600-700 MHz
            // per chip. Conservative bound until verified.
            #[cfg(feature = "asic-kf1950")]
            Self::KF1950 => 600.0,
            // Avalon CPM-table top entry per AVALON_ASIC_PROTOCOL.md §8.
            #[cfg(feature = "asic-avalon")]
            Self::Avalon => 600.0,
        }
    }

    /// Minimum operating frequency (MHz)
    pub fn min_frequency(&self) -> f32 {
        match self {
            Self::BM1366 => 100.0,
            Self::BM1368 => 100.0,
            Self::BM1370 => 100.0,
            Self::BM1373 => 100.0, // PROJECTED
            Self::BM1397 => 50.0,
            // MSBT0501: the vendor firmware clamp's lower bound.
            Self::Lt0051 => 700.0,
            #[cfg(feature = "asic-kf1950")]
            Self::KF1950 => 100.0,
            // Avalon CPM-table bottom entry (~99 MHz, rounded up).
            #[cfg(feature = "asic-avalon")]
            Self::Avalon => 100.0,
        }
    }

    /// Expected chip ID register value for detection
    pub fn expected_chip_id(&self) -> u16 {
        match self {
            Self::BM1366 => 0x1366,
            Self::BM1368 => 0x1368,
            Self::BM1370 => 0x1370,
            // PROVEN (BM1373_DOSSIER.md, 2026-07-27): real BM1373 silicon
            // reports 0x1372, NOT the 0x1373 part number. The driver's accept
            // logic (`bm1373::chip_id_accepted`) admits both, mirroring the
            // vendor's own fix; this single-valued metadata reports what the
            // silicon actually says.
            Self::BM1373 => 0x1372,
            Self::BM1397 => 0x1397,
            // MSBT0501 has no 16-bit chip-ID register in the RE'd protocol —
            // enumeration is a broadcast READ of reg 0x10 whose responders are
            // COUNTED, not identity-checked (MSBT0501_PROTOCOL.md §6 step 1).
            // 0 is an honest "no chip-ID contract", not a placeholder to
            // compare against.
            Self::Lt0051 => 0x0000,
            #[cfg(feature = "asic-kf1950")]
            Self::KF1950 => 0x1950,
            // Avalon AVA_P_DETECT response carries DNA/version, not a 16-bit
            // chip-ID register. Placeholder to satisfy the trait — actual
            // identity is parsed by `AvalonShimDriver::init` from the
            // AVA_P_ACKDETECT payload.
            #[cfg(feature = "asic-avalon")]
            Self::Avalon => 0x3197,
        }
    }

    /// ASIC response size in bytes (BM1397=9, MSBT0501=11, others=11)
    pub fn response_size(&self) -> usize {
        match self {
            Self::BM1397 => 9,
            // MSBT0501 is also 11 bytes, but for a completely different
            // reason and with a different layout — see `lt0051::parse_response`.
            _ => 11,
        }
    }
}

/// Create a driver for the specified ASIC model.
///
/// Note: `AsicModel::Avalon` is **not** constructible via this factory — the
/// Avalon shim driver lives in `projects/dcentaxe-avalon/dcentaxe-nano3s-asic`
/// and `DCENT_OS_AvalonMiner/dcentrald/dcentrald-avalon-asic`, and owns a
/// SysV-msgq transport instead of a `SerialPort`. Construct it directly via
/// `AvalonShimDriver::open_default()` from those crates.
pub fn create_driver(model: AsicModel, serial_port: SerialPort) -> Box<dyn AsicDriver> {
    match model {
        AsicModel::BM1366 => Box::new(bm1366::BM1366::new(serial_port)),
        AsicModel::BM1368 => Box::new(bm1368::BM1368::new(serial_port)),
        AsicModel::BM1370 => Box::new(bm1370::BM1370::new(serial_port)),
        AsicModel::BM1373 => Box::new(bm1373::BM1373::new(serial_port)),
        AsicModel::BM1397 => Box::new(bm1397::BM1397::new(serial_port)),
        // MSBT0501 / LT0051 (Scrypt). With `asic-lt0051` the real fail-closed
        // scaffold is used; without it, a refusing driver — NEVER a fallthrough
        // to a Bitmain driver, which would run a SHA-256 init sequence against
        // Scrypt silicon.
        #[cfg(feature = "asic-lt0051")]
        AsicModel::Lt0051 => Box::new(lt0051::Lt0051::new(serial_port)),
        #[cfg(not(feature = "asic-lt0051"))]
        AsicModel::Lt0051 => {
            let _ = serial_port;
            Box::new(UnsupportedAsicDriver::new(
                "MSBT0501/LT0051",
                "build without the `asic-lt0051` feature",
            ))
        }
        #[cfg(feature = "asic-kf1950")]
        AsicModel::KF1950 => Box::new(kf1950::Kf1950::new(serial_port)),
        #[cfg(feature = "asic-avalon")]
        AsicModel::Avalon => panic!(
            "AsicModel::Avalon cannot be constructed via create_driver — \
             use AvalonShimDriver::open_default() from dcentaxe-nano3s-asic \
             or dcentrald-avalon-asic instead. See dcentaxe-asic/src/lib.rs \
             docstring on `create_driver` for context."
        ),
    }
}
