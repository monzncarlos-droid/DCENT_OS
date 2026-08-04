// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — ASIC driver common types
// Faithful port from ESP-Miner C codebase

use std::fmt;

// ── Protocol constants ──────────────────────────────────────────────────────

/// UART preamble bytes: 0x55 0xAA (little-endian on wire)
pub const PREAMBLE: [u8; 2] = [0x55, 0xAA];

/// Preamble as u16 for response validation (big-endian: 0xAA55)
pub const PREAMBLE_BE: u16 = 0xAA55;

// Command types
pub const TYPE_JOB: u8 = 0x20;
pub const TYPE_CMD: u8 = 0x40;

// Group flags
pub const GROUP_SINGLE: u8 = 0x00;
pub const GROUP_ALL: u8 = 0x10;

// Command codes
pub const CMD_SETADDRESS: u8 = 0x00;
pub const CMD_WRITE: u8 = 0x01;
pub const CMD_READ: u8 = 0x02;
pub const CMD_INACTIVE: u8 = 0x03;

/// Default UART baud rate
pub const UART_FREQ: u32 = 115200;

/// Default Stratum version mask
pub const STRATUM_DEFAULT_VERSION_MASK: u32 = 0x1FFFE000;

// ── Register types ──────────────────────────────────────────────────────────

/// Register type identifiers matching the C enum
/// (`Invalid`..=`PllParam` are the faithful ESP-Miner port; the telemetry
/// variants below them are DCENT extensions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegisterType {
    Invalid = 0,
    Hashrate,
    TotalCount,
    Domain0Count,
    Domain1Count,
    Domain2Count,
    Domain3Count,
    ErrorCount,
    PllParam,
    // ── DCENT extensions (not in the ESP-Miner C enum) ──────────────────────
    // Appended at the END so the existing #[repr(u8)] discriminants
    // (Invalid=0 .. PllParam=8) never move. Added for the Avalon shim
    // drivers' STATUS_ASIC Temp/Volt telemetry, which previously had no
    // honest variant and was mislabelled as `Hashrate` — a raw temperature
    // ADC word must never be typed as hashrate.
    /// Raw temperature telemetry word (e.g. Avalon STATUS_ASIC subtype Temp).
    /// Units/scaling are chip-specific and NOT normalised here.
    Temperature,
    /// Raw voltage telemetry word (e.g. Avalon STATUS_ASIC subtype Volt).
    /// Units/scaling are chip-specific and NOT normalised here.
    Voltage,
}

// ── ASIC model ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsicModel {
    BM1366,
    BM1368,
    BM1370,
    BM1373, // S23 chip — SCAFFOLD (pre-hardware, 2026-04-14)
    BM1397,
    /// MSBT0501 (vendor driver name `LT0051`) — the **Scrypt** ASIC in the
    /// Hammer/Volc DC0x line. `PowAlgorithm::Scrypt1024`, not SHA-256d.
    ///
    /// The variant is deliberately **NOT** feature-gated even though the
    /// `lt0051` driver module is (`asic-lt0051`, default OFF). Reason: the
    /// NVS `asicmodel` string "MSBT0501" must resolve to THIS variant on every
    /// build. A cfg-gated variant would leave the string falling through
    /// `config.rs::asic_model()`'s catch-all to the **BM1366** fallback — the
    /// exact latent trap that was found and fixed for BM1373 in the BC0x lane,
    /// and which here would mean running a Bitmain SHA-256 init sequence
    /// against live Scrypt silicon.
    ///
    /// With the feature off, `create_driver` returns an `UnsupportedAsicDriver`
    /// that refuses every operation — same fail-closed outcome as the real
    /// scaffold, no wrong-chip init.
    Lt0051,
    // KF1950 (WhatsMiner K-series, M30/M30S/M31S/M32 era).
    // UNTESTED RESEARCH DRIVER — gated by `asic-kf1950` feature, default OFF.
    #[cfg(feature = "asic-kf1950")]
    KF1950,
    // Canaan Avalon A-series (A3197 / A3198 / A3197S / A3198S / etc.).
    // Used by DCENT_axe Avalon (Nano 3/3S/Mini 3) and DCENT_OS Avalon
    // (Avalon Q + A14xx/A15xx/A16xx industrial). Driver lives in the
    // dcentaxe-avalon and dcentos-avalon workspaces; this enum variant lets
    // the shared `dcentaxe-mining::MiningDispatcher` recognise the chip.
    // Gated by `asic-avalon`, default OFF.
    #[cfg(feature = "asic-avalon")]
    Avalon,
}

impl fmt::Display for AsicModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsicModel::BM1366 => write!(f, "BM1366"),
            AsicModel::BM1368 => write!(f, "BM1368"),
            AsicModel::BM1370 => write!(f, "BM1370"),
            AsicModel::BM1373 => write!(f, "BM1373"),
            AsicModel::BM1397 => write!(f, "BM1397"),
            AsicModel::Lt0051 => write!(f, "MSBT0501"),
            #[cfg(feature = "asic-kf1950")]
            AsicModel::KF1950 => write!(f, "KF1950"),
            #[cfg(feature = "asic-avalon")]
            AsicModel::Avalon => write!(f, "Avalon"),
        }
    }
}

// ── Proof-of-work algorithm (P1 Scrypt seam / P2 Scrypt target math) ────────

/// Bitcoin pool-difficulty-1 share target, `2^224 - 1`, 32 bytes big-endian.
///
/// Single source shared with `dcentaxe_stratum::types::PDIFF1_TARGET` (a
/// compile-linked parity test pins the two byte-identical).
pub const SHA256D_PDIFF1_TARGET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// **THE SCRYPT DIFF-1 CONVENTION (P2 decision, `SCRYPT_STACK_DESIGN.md`
/// §2.3 R4).**
///
/// Litecoin/scrypt pools conventionally define "difficulty 1" as a target
/// `65536 x` LARGER (easier) than Bitcoin's — i.e. a diff-1 scrypt share costs
/// `2^16` hashes where a diff-1 SHA-256 share costs `2^32`. This is the
/// "ltc-scale" convention; the alternative "btc-scale" convention reuses
/// Bitcoin's constant and compensates by sending FRACTIONAL difficulties.
///
/// The scale is expressed here as ONE named constant rather than a magic
/// number baked into a target literal, because getting it wrong is a
/// `x65536` error in BOTH directions at once:
/// - too loose  -> we submit ~65536x too many shares -> "low difficulty share"
///   flood -> pool ban;
/// - too tight  -> we submit ~nothing and report a hashrate 65536x low.
///
/// Neither failure is visible from the wire format, so the runtime
/// [`pool agreement monitor`](../../dcentaxe-stratum/src/pool_agreement.rs)
/// is the live cross-check that catches a convention mismatch from the pool's
/// own accept/reject responses.
pub const SCRYPT_DIFF1_SCALE_VS_BITCOIN: u64 = 65536;

/// Scrypt pool-difficulty-1 share target =
/// [`SHA256D_PDIFF1_TARGET`] x [`SCRYPT_DIFF1_SCALE_VS_BITCOIN`]
/// = `(2^224 - 1) * 2^16` = `2^240 - 2^16`, 32 bytes big-endian.
///
/// Byte form: two `0x00`, twenty-eight `0xFF`, two `0x00`. Derived (not
/// transcribed) by `scrypt_pdiff1_is_exactly_bitcoin_pdiff1_times_the_scale`.
pub const SCRYPT_PDIFF1_TARGET: [u8; 32] = [
    0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
];

/// `log2` of the diff-1 target used by the fractional-difficulty target
/// solver: Bitcoin's `2^224`, Scrypt's `2^240`.
pub const SHA256D_PDIFF1_LOG2: i32 = 224;
/// See [`SHA256D_PDIFF1_LOG2`].
pub const SCRYPT_PDIFF1_LOG2: i32 = 240;

/// Lowest `mining.set_difficulty` value the Scrypt path will honour without
/// flooring (STRATUM-2, made algorithm-conditional in P2).
///
/// `1 / 65536` is chosen for one specific reason, not as a round number: under
/// [`SCRYPT_PDIFF1_TARGET`] it produces EXACTLY the target that a **btc-scale**
/// pool means by "difficulty 1". It is therefore the widest sub-1 value that a
/// diff-1 *convention mismatch* can possibly explain. Anything below it is not
/// a scale disagreement — it is garbage — and is floored, exactly as the
/// SHA-256 path floors at `1.0`.
///
/// ⚠ Honest residual: honouring a sub-1 difficulty under the ltc-scale
/// constant still yields a very loose target. The floor bounds the blast
/// radius; the real defence against a convention mismatch is the pool
/// agreement monitor, and bring-up must run on a test account first.
pub const SCRYPT_MIN_POOL_DIFFICULTY: f64 = 1.0 / SCRYPT_DIFF1_SCALE_VS_BITCOIN as f64;

/// Hashrate display unit for an algorithm (design §4.6). Scrypt ASICs are
/// SRAM-dominated and hash in MH/s, not GH/s — using the SHA-256 unit would
/// misreport a DC06 by `1000x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashrateUnit {
    /// Gigahashes per second (SHA-256 boards).
    GigaHashPerSecond,
    /// Megahashes per second (Scrypt boards).
    MegaHashPerSecond,
}

impl HashrateUnit {
    pub const fn as_str(self) -> &'static str {
        match self {
            HashrateUnit::GigaHashPerSecond => "GH/s",
            HashrateUnit::MegaHashPerSecond => "MH/s",
        }
    }

    /// Hashes per one unit (`1e9` for GH/s, `1e6` for MH/s).
    pub const fn hashes_per_unit(self) -> f64 {
        match self {
            HashrateUnit::GigaHashPerSecond => 1.0e9,
            HashrateUnit::MegaHashPerSecond => 1.0e6,
        }
    }
}

/// Which proof-of-work function a chip / work unit / board mines.
///
/// Design: `docs/SCRYPT_STACK_DESIGN.md` §4.2 — deliberately an **enum, not a
/// trait object** (no `dyn` on the hot path; `match` exhaustiveness gives the
/// same compiler-enforced coverage the board tables rely on).
///
/// P2 status: BOTH algorithms now have real target math and real host-side
/// share validation. Product-level fail-closed posture for Scrypt is enforced
/// where it belongs instead — the `LT0051` driver is a refusing scaffold and
/// every Hammer DC0x board row declares `fan/temp/power = None` so
/// `BoardConfig::validate()` refuses mining.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum PowAlgorithm {
    /// Bitcoin SHA-256d — all existing chips (BM13xx, KF1950, Avalon).
    #[default]
    Sha256d,
    /// Litecoin `scrypt(N=1024, r=1, p=1)` — MSBT0501/LT0051, future
    /// BM1485/BM1489.
    Scrypt1024,
}

impl PowAlgorithm {
    /// The pool-difficulty-1 share target for this algorithm (32 bytes,
    /// big-endian). See [`SCRYPT_DIFF1_SCALE_VS_BITCOIN`] for the Scrypt
    /// convention decision.
    pub const fn pdiff1_target(self) -> [u8; 32] {
        match self {
            PowAlgorithm::Sha256d => SHA256D_PDIFF1_TARGET,
            PowAlgorithm::Scrypt1024 => SCRYPT_PDIFF1_TARGET,
        }
    }

    /// `log2` of the diff-1 target, for the fractional-difficulty solver.
    pub const fn pdiff1_log2(self) -> i32 {
        match self {
            PowAlgorithm::Sha256d => SHA256D_PDIFF1_LOG2,
            PowAlgorithm::Scrypt1024 => SCRYPT_PDIFF1_LOG2,
        }
    }

    /// Lowest pool difficulty honoured before flooring (STRATUM-2, now
    /// algorithm-conditional).
    ///
    /// `Sha256d` keeps the historical `1.0` floor byte-for-byte: SHA-256 ASIC
    /// pools never set diff<1 for a BitAxe, and both the dispatcher's
    /// `mining.set_difficulty` handler and `difficulty_to_target` collapse
    /// `0 < d < 1` to the diff-1 target. `Scrypt1024` lowers it to
    /// [`SCRYPT_MIN_POOL_DIFFICULTY`] so a legitimate btc-scale Scrypt pool's
    /// fractional difficulty is honoured instead of silently over-tightened.
    ///
    /// ⚠ BOTH consumers must move together (the STRATUM-2 note): the
    /// dispatcher floor and the target math. They do — each calls this.
    pub const fn min_pool_difficulty(self) -> f64 {
        match self {
            PowAlgorithm::Sha256d => 1.0,
            PowAlgorithm::Scrypt1024 => SCRYPT_MIN_POOL_DIFFICULTY,
        }
    }

    /// Whether BIP310/BIP320 version rolling (ASICBoost) applies.
    ///
    /// Scrypt has no AsicBoost equivalent; the Stratum client must skip
    /// `mining.configure` version-rolling negotiation entirely for Scrypt
    /// pools (design §2.3) and the dispatcher must never reconstruct a rolled
    /// version, program a hardware version mask, or drop a share for rolling
    /// "outside the negotiated mask" on a Scrypt work unit.
    pub const fn supports_version_rolling(self) -> bool {
        match self {
            PowAlgorithm::Sha256d => true,
            PowAlgorithm::Scrypt1024 => false,
        }
    }

    /// Display unit for hashrate surfaces (design §4.6).
    pub const fn hashrate_unit(self) -> HashrateUnit {
        match self {
            PowAlgorithm::Sha256d => HashrateUnit::GigaHashPerSecond,
            PowAlgorithm::Scrypt1024 => HashrateUnit::MegaHashPerSecond,
        }
    }

    /// True when the full host-side stack (target math, share validation) is
    /// implemented for this algorithm. Both are implemented as of P2 — this
    /// is NOT a claim that a Scrypt BOARD can mine (it cannot: the LT0051
    /// driver refuses and the DC0x board rows refuse).
    pub const fn is_implemented(self) -> bool {
        matches!(self, PowAlgorithm::Sha256d | PowAlgorithm::Scrypt1024)
    }
}

impl fmt::Display for PowAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PowAlgorithm::Sha256d => write!(f, "SHA-256d"),
            PowAlgorithm::Scrypt1024 => write!(f, "Scrypt-1024"),
        }
    }
}

#[cfg(test)]
mod pow_algorithm_tests {
    use super::*;

    #[test]
    fn default_is_sha256d() {
        // The entire P1 seam relies on this: every site that does not
        // explicitly choose an algorithm gets Sha256d.
        assert_eq!(PowAlgorithm::default(), PowAlgorithm::Sha256d);
    }

    #[test]
    fn sha256d_pdiff1_target_is_2_pow_224_minus_1() {
        let t = PowAlgorithm::Sha256d.pdiff1_target();
        assert_eq!(&t[0..4], &[0, 0, 0, 0]);
        assert!(t[4..].iter().all(|&b| b == 0xFF));
        assert!(PowAlgorithm::Sha256d.is_implemented());
    }

    // ── P2: the diff-1 convention landmine, pinned by DERIVATION ────────────
    //
    // The Scrypt constant is not transcribed by hand; this test multiplies the
    // Bitcoin constant by the named scale factor with 256-bit long
    // multiplication and asserts the literal matches. A typo in either the
    // scale or the byte literal fails here, which is the whole point: a
    // x65536 error is invisible on the wire and shows up only as a pool ban
    // or a 65536x hashrate lie.
    #[test]
    fn scrypt_pdiff1_is_exactly_bitcoin_pdiff1_times_the_scale() {
        assert_eq!(SCRYPT_DIFF1_SCALE_VS_BITCOIN, 65536);

        // 256-bit big-endian multiply-by-u64 with carry.
        let mut product = [0u8; 32];
        let mut carry: u128 = 0;
        for i in (0..32).rev() {
            let v =
                SHA256D_PDIFF1_TARGET[i] as u128 * SCRYPT_DIFF1_SCALE_VS_BITCOIN as u128 + carry;
            product[i] = (v & 0xFF) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "scaled diff-1 target must fit in 256 bits");
        assert_eq!(
            product, SCRYPT_PDIFF1_TARGET,
            "SCRYPT_PDIFF1_TARGET must equal Bitcoin pdiff1 x SCRYPT_DIFF1_SCALE_VS_BITCOIN"
        );
        assert_eq!(
            PowAlgorithm::Scrypt1024.pdiff1_target(),
            SCRYPT_PDIFF1_TARGET
        );

        // Shape sanity: 2^240 - 2^16 == 00 00 | FF x28 | 00 00.
        assert_eq!(&SCRYPT_PDIFF1_TARGET[0..2], &[0x00, 0x00]);
        assert!(SCRYPT_PDIFF1_TARGET[2..30].iter().all(|&b| b == 0xFF));
        assert_eq!(&SCRYPT_PDIFF1_TARGET[30..32], &[0x00, 0x00]);

        // It is EASIER (numerically larger) than Bitcoin's — a regression that
        // made it harder would silently zero the share rate.
        assert!(SCRYPT_PDIFF1_TARGET.as_slice() > SHA256D_PDIFF1_TARGET.as_slice());
    }

    #[test]
    fn pdiff1_log2_matches_the_target_magnitude() {
        // The fractional-difficulty solver approximates diff1 as 2^log2, so the
        // exponent must be the bit index just above the target's top set bit.
        for (algo, log2) in [
            (PowAlgorithm::Sha256d, 224),
            (PowAlgorithm::Scrypt1024, 240),
        ] {
            assert_eq!(algo.pdiff1_log2(), log2);
            let t = algo.pdiff1_target();
            let leading_zero_bytes = t.iter().take_while(|&&b| b == 0).count();
            // top set bit index = 8 * (32 - leading_zero_bytes) - 1
            let top_bit = 8 * (32 - leading_zero_bytes) - 1;
            assert_eq!(top_bit as i32 + 1, log2, "{algo:?}");
        }
    }

    #[test]
    fn min_pool_difficulty_is_algorithm_conditional() {
        // STRATUM-2: SHA-256 keeps the historical 1.0 floor byte-for-byte.
        assert_eq!(PowAlgorithm::Sha256d.min_pool_difficulty(), 1.0);
        // Scrypt honours sub-1 down to the btc-scale diff-1 equivalent.
        assert_eq!(
            PowAlgorithm::Scrypt1024.min_pool_difficulty(),
            1.0 / 65536.0
        );
        assert!(PowAlgorithm::Scrypt1024.min_pool_difficulty() < 1.0);
        assert!(PowAlgorithm::Scrypt1024.min_pool_difficulty() > 0.0);
    }

    #[test]
    fn version_rolling_is_sha256d_only() {
        assert!(PowAlgorithm::Sha256d.supports_version_rolling());
        assert!(!PowAlgorithm::Scrypt1024.supports_version_rolling());
    }

    #[test]
    fn hashrate_unit_is_mh_for_scrypt_and_gh_for_sha256d() {
        assert_eq!(
            PowAlgorithm::Sha256d.hashrate_unit(),
            HashrateUnit::GigaHashPerSecond
        );
        assert_eq!(PowAlgorithm::Sha256d.hashrate_unit().as_str(), "GH/s");
        assert_eq!(
            PowAlgorithm::Scrypt1024.hashrate_unit(),
            HashrateUnit::MegaHashPerSecond
        );
        assert_eq!(PowAlgorithm::Scrypt1024.hashrate_unit().as_str(), "MH/s");
        assert_eq!(
            PowAlgorithm::Sha256d.hashrate_unit().hashes_per_unit()
                / PowAlgorithm::Scrypt1024.hashrate_unit().hashes_per_unit(),
            1000.0
        );
    }
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AsicError {
    /// Serial/UART I/O error
    Serial(String),
    /// Timeout waiting for response
    Timeout,
    /// CRC mismatch
    CrcError,
    /// Preamble mismatch in response
    PreambleMismatch,
    /// No ASICs detected on chain
    NoAsicsFound,
    /// Invalid response length
    InvalidResponse(String),
    /// General initialization failure
    InitFailed(String),
}

impl fmt::Display for AsicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsicError::Serial(msg) => write!(f, "Serial error: {}", msg),
            AsicError::Timeout => write!(f, "UART timeout"),
            AsicError::CrcError => write!(f, "CRC verification failed"),
            AsicError::PreambleMismatch => write!(f, "Preamble mismatch in response"),
            AsicError::NoAsicsFound => write!(f, "No ASIC chips detected on chain"),
            AsicError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            AsicError::InitFailed(msg) => write!(f, "Init failed: {}", msg),
        }
    }
}

impl std::error::Error for AsicError {}

// ── Mining job (sent to ASIC) ───────────────────────────────────────────────

/// A mining job to send to the ASIC chain.
/// For BM1366/BM1368/BM1370: uses full prev_block_hash + merkle_root (82-byte payload).
/// For BM1397: uses midstates + merkle4 (variable-length payload with up to 4 midstates).
#[derive(Debug, Clone)]
pub struct MiningJob {
    pub job_id: u8,
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub ntime: u32,
    pub nbits: u32,
    pub starting_nonce: u32,
    /// For BM1397 only: up to 4 midstates (each 32 bytes)
    pub midstates: Vec<[u8; 32]>,
    /// For BM1397 only: last 4 bytes of merkle root
    pub merkle4: [u8; 4],
}

impl MiningJob {
    /// Create a new job for BM1366/BM1368/BM1370 style ASICs (full block header)
    pub fn new_full(
        job_id: u8,
        version: u32,
        prev_block_hash: [u8; 32],
        merkle_root: [u8; 32],
        ntime: u32,
        nbits: u32,
        starting_nonce: u32,
    ) -> Self {
        Self {
            job_id,
            version,
            prev_block_hash,
            merkle_root,
            ntime,
            nbits,
            starting_nonce,
            midstates: Vec::new(),
            merkle4: [0u8; 4],
        }
    }

    /// Create a new job for BM1397 style ASICs (midstate-based)
    pub fn new_midstate(
        job_id: u8,
        version: u32,
        ntime: u32,
        nbits: u32,
        starting_nonce: u32,
        merkle4: [u8; 4],
        midstates: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            job_id,
            version,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            ntime,
            nbits,
            starting_nonce,
            midstates,
            merkle4,
        }
    }
}

// ── ASIC result (received from ASIC) ────────────────────────────────────────

/// Result from an ASIC: either a nonce (job response) or a register read.
///
/// `timestamp_us` is the uptime micros (`esp_timer_get_time()`) captured at
/// the moment the response was parsed. Ports ESP-Miner `asic_common.c:81-86`
/// (commit `64f8144` / PR #1621) — used for nonce latency / time-of-flight
/// analytics. Set to 0 when a timestamp is unavailable.
#[derive(Debug, Clone)]
pub enum AsicResult {
    /// A nonce result from mining
    Nonce {
        job_id: u8,
        nonce: u32,
        /// Rolled version (with version bits applied)
        rolled_version: u32,
        /// Which ASIC chip in the chain produced this
        asic_nr: u8,
        /// Receive timestamp (microseconds since boot, 0 if unavailable)
        timestamp_us: i64,
    },
    /// A register read response
    Register {
        register_type: RegisterType,
        asic_nr: u8,
        value: u32,
        /// Receive timestamp (microseconds since boot, 0 if unavailable)
        timestamp_us: i64,
    },
}

/// Fetch a monotonic microsecond timestamp. Pure Rust on host (for tests), backed by
/// `esp_timer_get_time()` on ESP-IDF targets.
#[inline]
pub fn now_us() -> i64 {
    #[cfg(target_os = "espidf")]
    unsafe {
        esp_idf_hal::sys::esp_timer_get_time()
    }
    #[cfg(not(target_os = "espidf"))]
    {
        0
    }
}

// ── Register data (for read_registers return) ───────────────────────────────

#[derive(Debug, Clone)]
pub struct RegisterData {
    pub register_type: RegisterType,
    pub asic_nr: u8,
    pub value: u32,
}

// ── Recent-nonce dedup ring (driver-level, per UART stream) ──────────────────

/// Number of recent nonces remembered per driver stream. Small, fixed, and
/// heap-free so it costs nothing meaningful on the ESP32-S3 (8 × 4 bytes = 32 B
/// per driver). Chosen as a bounded superset of upstream ESP-Miner's
/// single-`prev_nonce` filter.
pub const RECENT_NONCE_RING_LEN: usize = 8;

/// Bounded per-stream recent-nonce filter (driver-level dedup).
///
/// Bitmain ASICs re-emit the same nonce stream in a loop and can repeat a
/// nonce non-consecutively. Upstream ESP-Miner only filters the *immediately
/// previous* nonce (`static prev_nonce` in `bm1397.c:79`), so a looped
/// duplicate interleaved with other nonces slips through and is re-validated,
/// re-counted, and re-submitted (pool "duplicate share" reject).
///
/// This ring remembers the last `RECENT_NONCE_RING_LEN` *distinct* nonces and
/// reports a hit when the incoming nonce matches any of them. It is a strict
/// superset of `prev_nonce`: a consecutive duplicate is still caught, and a
/// non-consecutive looped duplicate within the window is now caught too.
///
/// Crucially it does **not** permanently blacklist any value — an old nonce
/// ages out of the ring after `RECENT_NONCE_RING_LEN` newer distinct nonces, so
/// a genuinely-rediscovered valid nonce in a later job is accepted again. This
/// fixes the earlier `first_nonce`/`nonce_found` regression (ASIC-1) where the
/// session's very first nonce was filtered forever.
///
/// This is the DRIVER-level (per UART stream) dedup tier. It is complementary
/// to, not a replacement for, any DISPATCHER-level cross-stream dedup keyed by
/// `(job_id, nonce, asic_nr)`.
#[derive(Debug, Clone)]
pub struct RecentNonceRing {
    /// Sentinel-free presence is tracked by `len`; entries `[0..len)` are valid.
    slots: [u32; RECENT_NONCE_RING_LEN],
    /// Number of populated slots (saturates at `RECENT_NONCE_RING_LEN`).
    len: usize,
    /// Next write position (wraps modulo `RECENT_NONCE_RING_LEN`).
    head: usize,
}

impl RecentNonceRing {
    /// Create an empty ring.
    pub const fn new() -> Self {
        Self {
            slots: [0u32; RECENT_NONCE_RING_LEN],
            len: 0,
            head: 0,
        }
    }

    /// Returns `true` if `nonce` is in the recent window (a duplicate to drop).
    pub fn contains(&self, nonce: u32) -> bool {
        self.slots[..self.len].iter().any(|&n| n == nonce)
    }

    /// Record `nonce` as the most-recently-seen value. No-op if it is already
    /// present (keeps the window holding distinct values so the effective
    /// look-back is `RECENT_NONCE_RING_LEN` *distinct* nonces).
    pub fn record(&mut self, nonce: u32) {
        if self.contains(nonce) {
            return;
        }
        self.slots[self.head] = nonce;
        self.head = (self.head + 1) % RECENT_NONCE_RING_LEN;
        if self.len < RECENT_NONCE_RING_LEN {
            self.len += 1;
        }
    }

    /// Combined check-and-record: returns `true` (and records nothing new) when
    /// `nonce` is a recent duplicate that should be dropped; otherwise records
    /// it and returns `false`.
    pub fn is_duplicate(&mut self, nonce: u32) -> bool {
        if self.contains(nonce) {
            return true;
        }
        self.record(nonce);
        false
    }
}

impl Default for RecentNonceRing {
    fn default() -> Self {
        Self::new()
    }
}

// ── Packet type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Job,
    Cmd,
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Reverse bits in a byte (port of _reverse_bits from C)
pub fn reverse_bits(num: u8) -> u8 {
    let mut reversed: u8 = 0;
    let mut n = num;
    for _ in 0..8 {
        reversed <<= 1;
        reversed |= n & 1;
        n >>= 1;
    }
    reversed
}

/// Find largest power of two <= num (port of _largest_power_of_two from C)
pub fn largest_power_of_two(num: u32) -> u32 {
    let mut power = 0u32;
    let mut n = num;
    while n > 1 {
        n >>= 1;
        power += 1;
    }
    1u32 << power
}

/// Compute the difficulty mask bytes for the TICKET_MASK register.
/// Port of `get_difficulty_mask()` from ESP-Miner `components/asic/asic_common.c`
/// (commit bfc422a / PR #1594 — fractional-difficulty support).
///
/// The mask must be one less than a power of two so there are no holes in the
/// accept range. Match ESP-Miner: ceil the pool difficulty first, then select
/// the largest supported power-of-two bucket at or below that integer value.
pub fn get_difficulty_mask(difficulty: f64) -> [u8; 6] {
    // ceil first to avoid making the ASIC harder than asked; floor at 1.
    let diff_int = difficulty.ceil().max(1.0) as u32;
    let mask = largest_power_of_two(diff_int).saturating_sub(1);
    let mut out = [0u8; 6];
    out[0] = 0x00;
    out[1] = 0x14; // TICKET_MASK register address
    out[2] = reverse_bits(((mask >> 24) & 0xFF) as u8);
    out[3] = reverse_bits(((mask >> 16) & 0xFF) as u8);
    out[4] = reverse_bits(((mask >> 8) & 0xFF) as u8);
    out[5] = reverse_bits((mask & 0xFF) as u8);
    out
}

#[cfg(test)]
mod difficulty_tests {
    use super::*;

    #[test]
    fn diff_256_is_power_of_two() {
        let mask = get_difficulty_mask(256.0);
        // 256 - 1 = 0x000000FF → reversed by byte: [0, 0x14, 0, 0, 0, 0xFF]
        assert_eq!(mask[0], 0x00);
        assert_eq!(mask[1], 0x14);
        assert_eq!(&mask[2..6], &[0x00, 0x00, 0x00, 0xFF]);
    }

    #[test]
    fn fractional_diff_can_cross_power_bucket_after_ceil() {
        // 511.5 ceil -> 512 -> largest_power_of_two(512) = 512 -> mask 511.
        // 511.0 stays in the 256 bucket.
        let frac = get_difficulty_mask(511.5);
        let next = get_difficulty_mask(512.0);
        assert_eq!(frac, next);
        let whole = get_difficulty_mask(511.0);
        assert_ne!(frac, whole);
    }

    #[test]
    fn zero_and_subunit_clamp_to_one() {
        let zero = get_difficulty_mask(0.0);
        let one = get_difficulty_mask(1.0);
        let half = get_difficulty_mask(0.5);
        assert_eq!(zero, one);
        // 0.5 ceils to 1
        assert_eq!(half, one);
    }

    #[test]
    fn large_u32_range_difficulty() {
        // Main-net difficulties can exceed u16 range. 1_048_576 (2^20) must not overflow.
        let mask = get_difficulty_mask(1_048_576.0);
        // largest_power_of_two(1048576) = 1048576 → mask = 1048575 = 0x000FFFFF
        // Bytes: 0x00, 0x0F, 0xFF, 0xFF → reversed: 0x00, 0xF0, 0xFF, 0xFF
        assert_eq!(&mask[2..6], &[0x00, 0xF0, 0xFF, 0xFF]);
    }
}

#[cfg(test)]
mod recent_nonce_ring_tests {
    use super::*;

    #[test]
    fn first_nonce_is_never_permanently_filtered() {
        // ASIC-1 regression guard: the session's first nonce must NOT be
        // blacklisted forever. It is filtered only while it is still in the
        // recent window; once RECENT_NONCE_RING_LEN newer distinct nonces have
        // arrived it ages out and is accepted again.
        let mut ring = RecentNonceRing::new();
        let first = 0xDEAD_BEEFu32;
        assert!(!ring.is_duplicate(first), "first sighting must pass");
        assert!(ring.is_duplicate(first), "immediate repeat is a duplicate");
        // Flush the window with RECENT_NONCE_RING_LEN distinct other nonces.
        for k in 0..RECENT_NONCE_RING_LEN as u32 {
            assert!(!ring.is_duplicate(0x1000_0000 + k));
        }
        // `first` has now aged out — a genuine rediscovery is accepted again.
        assert!(
            !ring.is_duplicate(first),
            "aged-out nonce must be accepted, not blacklisted forever"
        );
    }

    #[test]
    fn catches_consecutive_and_nonconsecutive_loop_duplicates() {
        // MD-4: a non-consecutive looped duplicate within the window is caught,
        // which the single-element prev_nonce filter misses.
        let mut ring = RecentNonceRing::new();
        assert!(!ring.is_duplicate(0xA));
        assert!(!ring.is_duplicate(0xB));
        assert!(!ring.is_duplicate(0xC));
        // 0xA was not the immediately-previous nonce, but is still in-window.
        assert!(ring.is_duplicate(0xA), "in-window loop duplicate dropped");
        // consecutive duplicate still caught (prev_nonce superset).
        assert!(!ring.is_duplicate(0xD));
        assert!(ring.is_duplicate(0xD));
    }

    #[test]
    fn record_keeps_window_to_distinct_values() {
        // Re-recording an already-present nonce must not evict other window
        // entries (keeps the effective look-back at RECENT_NONCE_RING_LEN
        // DISTINCT nonces, not raw insertions).
        let mut ring = RecentNonceRing::new();
        for k in 0..RECENT_NONCE_RING_LEN as u32 {
            ring.record(k);
        }
        // Re-record the oldest several times — must not push out 0..LEN.
        for _ in 0..100 {
            ring.record(0);
        }
        for k in 0..RECENT_NONCE_RING_LEN as u32 {
            assert!(ring.contains(k), "distinct nonce {k} must stay in window");
        }
    }

    #[test]
    fn empty_ring_reports_no_duplicates() {
        let ring = RecentNonceRing::new();
        assert!(!ring.contains(0));
        assert!(!ring.contains(0xFFFF_FFFF));
    }
}

// NOTE: increment_bitmask was previously duplicated here.
// The canonical implementation lives in dcentaxe_stratum::work::increment_bitmask.
// Removed to avoid divergence (Phase 6.2 dedup).
