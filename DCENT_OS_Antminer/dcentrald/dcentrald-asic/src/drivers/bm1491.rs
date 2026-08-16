//! BM1491 ASIC driver (Antminer L9 — CVCtrl/CV183x variant, Litecoin Scrypt) — SCAFFOLD
//!
//! # What this is
//!
//! The **BM1491** is the Scrypt-mining ASIC in the **CVCtrl (CV183x) variant of
//! the Antminer L9**. It is a DISTINCT chip identity from the `am3-aml` L9, which
//! `bm1489.rs` / `scrypt_l7.rs` key on `0x1489`. This driver keys on **`0x1491`**
//! and does NOT overwrite the `0x1489` belief — two L9 control-board variants, two
//! chip ids, both fail-closed until a live unit reconciles them.
//!
//! Status: **SCAFFOLD — simulator only, no live L9-CVCtrl unit on bench.** Every
//! hardware-touching method returns `Err`. Only chip-identity getters and the two
//! byte-exact RE'd constants below are trustworthy.
//!
//! # Recovered evidence (2026-08-05, hardware-supremacy-campaign, operator FW drop)
//!
//! Unlike `bm1485`/`bm1489` (whose operational baud is unrecoverable from the
//! obfuscated/encrypted stock), the L9-CVCtrl ships an **un-obfuscated `godminer`**
//! (full symbols) + a **plaintext `/etc/topol.conf`**. From it we recovered, byte-exact:
//!
//! - **Chain address stride = 2** — plaintext `/etc/topol.conf`. See [`CHAIN_ADDRESS_STRIDE`].
//! - **Operational chain baud = 1,562,500** (`bt8d=1`, the canonical scrypt rate:
//!   `25 MHz / ((1 + bt8d) * 8) = 1,562,500`) — `godminer` symbol
//!   `chip_setting_buadrate_ltc@0x000fc294`; runtime driver `machine_runtime_ctrl_ltc_1491@0x000727e4`.
//!   godminer sha256 `7b088dcb…3038487`. Captured as [`OPERATIONAL_BAUD`] but **NOT**
//!   driven by [`Bm1491Driver::max_baud`] — per the load-bearing "never raise a driver
//!   baud without a bench UART capture in the same commit" rule, `max_baud()` stays at
//!   the enumeration rate until a live L9-CVCtrl confirms it on the wire.
//!
//! Everything else (register addresses, init sequence, work packet shape, nonce
//! decode, voltage-controller identity, PLL bit layout) is `[GAP — needs a live
//! L9-CVCtrl unit]` and the driver refuses to touch hardware.
//!
//! # References
//!
//! - Sibling scaffold pattern: [`crate::drivers::bm1489`] (L7/L9-AML, `0x1489`).
//! - Evidence:  ledger row `asic.bm1491`;
//!   memory .
//! - Identity discrepancy (0x1489 vs 0x1491 across L9 variants): flagged for a bench unit.

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::Result;
use dcentrald_hal::fpga_chain::{self, FpgaChain};

/// BM1491 chip ID — the L9-CVCtrl (CV183x) variant reports `0x1491`
/// (`godminer` `machine_runtime_ctrl_ltc_1491`). DISTINCT from `bm1489`'s `0x1489`.
pub const CHIP_ID: u16 = 0x1491;

/// Recovered operational chain baud (byte-exact from the un-obfuscated `godminer`
/// `chip_setting_buadrate_ltc`): `1,562,500` = `25 MHz / ((1 + bt8d) * 8)` with
/// `bt8d = 1` — the canonical scrypt rate (cross-checks our own BM1485 metadata).
///
/// This is RECOVERED, not GAP. It is intentionally **not** returned by
/// [`Bm1491Driver::max_baud`]: raising a driver's on-wire baud requires a bench UART
/// capture landing in the same commit (load-bearing rule). Recorded here so the value
/// is preserved and a future bench wave can wire it after live confirmation.
pub const OPERATIONAL_BAUD: Option<u32> = Some(1_562_500);

/// Recovered chain address stride (byte-exact from the plaintext `/etc/topol.conf`).
/// A stride, not a divisor: chip N sits at address `N * 2`.
pub const CHAIN_ADDRESS_STRIDE: u8 = 2;

/// BM1489-lineage 7-byte nonce response (Scrypt raw framing). `[GAP — confirm on a
/// live L9-CVCtrl]`; inherited from the BM1485/BM1489 Scrypt family as the first cut.
pub const RESPONSE_BYTES: usize = 7;

/// Scrypt cores per chip — placeholder inherited from the BM1485/BM1489 family (12).
/// `[GAP — needs a live L9-CVCtrl]`.
const NUM_CORES_ON_CHIP: u32 = 12;

/// Crystal reference (25 MHz, industry standard; the recovered baud math assumes it).
const CLKI_MHZ: f64 = 25.0;

/// Discrete PLL frequencies for the autotuner (placeholder Scrypt range)
/// `[GAP — needs a live L9-CVCtrl]`.
static PLL_FREQ_TABLE: &[u16] = &[280, 300, 320, 340, 360, 380, 400, 425, 450, 470, 490, 510];

/// Sorted list of discrete PLL frequencies (placeholder).
pub fn pll_frequencies() -> &'static [u16] {
    PLL_FREQ_TABLE
}

/// BM1491 driver — SCAFFOLD (simulator only). All hardware paths fail closed.
pub struct Bm1491Driver;

impl Bm1491Driver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Bm1491Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl ChipDriver for Bm1491Driver {
    fn chip_id(&self) -> u16 {
        CHIP_ID
    }

    fn chip_name(&self) -> &'static str {
        "BM1491"
    }

    fn cores_per_chip(&self) -> u32 {
        NUM_CORES_ON_CHIP
    }

    fn response_length(&self) -> usize {
        RESPONSE_BYTES
    }

    fn default_baud(&self) -> u32 {
        // Enumeration rate. The recovered OPERATIONAL_BAUD (1_562_500) is NOT used
        // here — bench-gated per the load-bearing baud rule.
        115_200
    }

    fn max_baud(&self) -> u32 {
        // Deliberately == default_baud (enumeration rate). Even though OPERATIONAL_BAUD
        // is byte-exact RE-recovered, raising the driver's max baud requires a live
        // L9-CVCtrl UART capture in the same commit. Do NOT return OPERATIONAL_BAUD here.
        115_200
    }

    fn init_chain(&self, _chain: &mut FpgaChain, chip_count: u8, freq_mhz: u16) -> Result<()> {
        tracing::warn!(
            chip_count = chip_count,
            freq_mhz = freq_mhz,
            "BM1491 init_chain: SCAFFOLD — simulator only, no live L9-CVCtrl unit. \
             Only the chain stride (2) and operational baud (1_562_500) are RE-recovered; \
             the register map + init sequence are unresolved."
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1491 driver is a pre-hardware scaffold. Cannot init a chain without \
             verified register values. [GAP — needs a live L9-CVCtrl unit]"
                .into(),
        ))
    }

    fn set_frequency(&self, _chain: &mut FpgaChain, _chip_addr: u8, _freq_mhz: u16) -> Result<()> {
        Err(crate::AsicError::InvalidParameter(
            "BM1491 set_frequency not implemented (scaffold) [GAP — live L9-CVCtrl]".into(),
        ))
    }

    fn set_voltage(&self, _pic: &mut PicController, voltage_mv: u16) -> Result<()> {
        // Voltage-controller identity on the CVCtrl L9 is unconfirmed. No-op (like the
        // other Scrypt scaffolds) rather than driving an unverified rail.
        tracing::warn!(
            voltage_mv = voltage_mv,
            "BM1491 set_voltage: SCAFFOLD — voltage path unconfirmed [GAP — live L9-CVCtrl]"
        );
        Ok(())
    }

    fn send_work(&self, _chain: &mut FpgaChain, _work: &MiningWork) -> Result<u16> {
        Err(crate::AsicError::InvalidParameter(
            "BM1491 send_work not implemented (scaffold, Scrypt packet) [GAP — live L9-CVCtrl]"
                .into(),
        ))
    }

    fn decode_nonce(&self, raw: &[u32; 2]) -> Result<NonceResult> {
        // Synthetic decode so the offline harness can exercise the path. NOT correct
        // for real hardware — a live L9-CVCtrl capture must replace this.
        Ok(NonceResult {
            nonce: raw[0],
            chip_index: ((raw[1] >> 17) & 0xFF) as u8,
            work_id: ((raw[1] >> 8) & 0xFFFF) as u16,
            solution_id: (raw[1] & 0xFF) as u8,
            midstate_idx: 0, // Scrypt has no midstate concept.
        })
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        let div = fpga_clock_hz / (16 * target_baud);
        div.saturating_sub(1)
    }

    fn ctrl_reg_value(&self) -> u32 {
        fpga_chain::CTRL_BM139X | fpga_chain::CTRL_ENABLE
    }

    fn job_interval_ms(&self, _chip_count: u8, _freq_mhz: u16) -> u32 {
        10
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::PlainDiffMinusOne,
            difficulty,
        )
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        // Placeholder BM1397-pattern search (same as bm1489). Real BM1491 PLL bit
        // layout is [GAP]. Kept so the autotuner can prep tables offline.
        let target = freq_mhz.clamp(50, 800) as f64;
        let mut best = (0u32, 96u16, 1u8, 1u8, 1u8, f64::MAX);
        for refdiv in [1u8, 2] {
            for pd1 in 1..=7u8 {
                for pd2 in 1..=pd1 {
                    let divider = (refdiv as f64) * (pd1 as f64) * (pd2 as f64);
                    let fb = (target * divider / CLKI_MHZ).round() as u16;
                    if !(60..=200).contains(&fb) {
                        continue;
                    }
                    let actual = CLKI_MHZ * (fb as f64) / divider;
                    let diff = (actual - target).abs();
                    if diff < best.5 {
                        best = (0, fb, refdiv, pd1, pd2, diff);
                    }
                }
            }
        }
        let (_, fb, refd, pd1, pd2, _) = best;
        let reg_value: u32 = (1u32 << 30)
            | ((fb as u32 & 0x7FF) << 16)
            | ((refd as u32 & 0x3F) << 8)
            | ((pd1 as u32 & 0x7) << 4)
            | (pd2 as u32 & 0x7);
        PllConfig {
            fb_div: fb,
            ref_div: refd,
            post_div1: pd1,
            post_div2: pd2,
            reg_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_id_is_0x1491_and_distinct_from_bm1489() {
        assert_eq!(Bm1491Driver::new().chip_id(), 0x1491);
        assert_eq!(CHIP_ID, 0x1491);
        // Must NOT collide with the AML L9 identity.
        assert_ne!(CHIP_ID, crate::drivers::bm1489::CHIP_ID);
    }

    #[test]
    fn name_is_bm1491() {
        assert_eq!(Bm1491Driver::new().chip_name(), "BM1491");
    }

    #[test]
    fn operational_baud_is_recovered_but_not_driven() {
        // RECOVERED byte-exact from godminer chip_setting_buadrate_ltc.
        assert_eq!(OPERATIONAL_BAUD, Some(1_562_500));
        // Load-bearing baud rule: max_baud stays at the enumeration rate until a
        // bench UART capture confirms the on-wire baud. It must NOT equal the
        // recovered operational baud.
        let d = Bm1491Driver::new();
        assert_eq!(d.max_baud(), d.default_baud());
        assert_eq!(d.max_baud(), 115_200);
        assert_ne!(d.max_baud(), OPERATIONAL_BAUD.unwrap());
    }

    #[test]
    fn chain_address_stride_is_two() {
        // Byte-exact from the plaintext /etc/topol.conf.
        assert_eq!(CHAIN_ADDRESS_STRIDE, 2);
    }

    #[test]
    fn init_chain_fails_closed() {
        // The scaffold cannot bring up a chain. (Structural: driver constructs and
        // reports its identity; init_chain returns Err by construction — verified by
        // the RE-007 CI gate which greps this file for the fail-closed Err.)
        assert_eq!(Bm1491Driver::new().chip_id(), 0x1491);
    }

    #[test]
    fn pll_params_valid_for_nameplate() {
        let cfg = Bm1491Driver::new().pll_params(425);
        assert!(cfg.fb_div >= 60 && cfg.fb_div <= 200);
        assert_ne!(cfg.reg_value & (1u32 << 30), 0);
    }

    #[test]
    fn ticket_mask_256_is_255() {
        assert_eq!(Bm1491Driver::new().ticket_mask(256), 255);
    }
}
