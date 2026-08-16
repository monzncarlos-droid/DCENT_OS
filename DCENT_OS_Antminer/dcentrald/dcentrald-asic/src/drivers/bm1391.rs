//! BM1391 ASIC driver (Antminer S11 / S15 / T15) — JIG-VERIFIED SCAFFOLD
//!
//! The BM1391 is the **7 nm** SHA-256 die (Bitmain's first-gen 7 nm, Nov 2018)
//! used in the Antminer S11 / S15 / T15 (and the BM1391P/BM1391S variants).
//! CORRECTED 2026-07-02: the prior header "16 nm" + "T9+" were BM1387-template
//! copy-paste errors (T9+ uses the 16 nm BM1387; BM1391 is 7 nm per
//! `asics.rs` `Bm1391 = Nm7` + the Bitmain BM1391 datasheet). Unlike the
//! `bm1373` scaffold (whose values are
//! *projected* from BM1370), the command/register constants below are byte-
//! verified from the Bitmain S17 factory `single-board-test` jig (which carries the full,
//! unstripped BM1391 protocol: `BM1391_set_config`, `set_BM1391_freq`,
//! `BM1391_set_baud`, `BM1391_set_TM`, `BM1391_chain_inactive`,
//! `BM1391_set_address`, `single_BM1391{P,S}_open_core`, …) — decoded
//! 2026-06-10 in the local Ghidra GUI.
//!
//! Status: **SCAFFOLD — fail-closed.** The S17 factory jig establishes a
//! BM1391 ASIC command dialect, but it does not establish the S15/T15 control-
//! board FIFO layout, reset/enable GPIOs, voltage-controller command unit, or
//! safe energization envelope. Every mutating [`ChipDriver`] entry point
//! therefore refuses. The host-only S17-jig observation decoder below is kept
//! deliberately separate from the carrier-independent trait decoder.
//!
//! ## BM1391 baud generation (the key family fact, jig-verified)
//! BM1391 is **Generation-1** (like BM1387/S9): the chain UART baud is set via
//! the **MiscControl divider (reg 0x18)** off CLKI — there is **NO PLL baud
//! reclock** (unlike Gen-2 BM1397/BM1398 = PLL3/0x68, or Gen-3 BM1362/66/68/70
//! = PLL1/0x60). `BM1391_set_baud`:
//! `MiscCtrl = (MiscCtrl & 0xffffe0ff) | (baud_index << 8)`.
//!.
//!
//! ## Command/wire format (jig-verified, = BM1397 family, NOT BM1387)
//! Register write = `[0x51 (bcast) | 0x41 (single), 0x09, asic_addr, reg,
//! data_BE[4], CRC5]` (`BM1391_set_config`). CRC5 over the 9-byte frame.
//!
//! References:
//!   - S17 jig `single-board-test`
//!   - `bm1387.rs` (same Gen-1 baud mechanism; closest live-proven template)
//!   - `BM13XX_BAUD_FAMILY_MAP.md`

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::Result;
use dcentrald_hal::fpga_chain::FpgaChain;

/// BM1391 chip ID. Read from the chip-address register (reg 0x00, bits 31:16).
pub const CHIP_ID: u16 = 0x1391;

/// No model-independent BM1391 chain count exists in the held corpus.
///
/// The S15 maintenance guide is internally inconsistent: its hashrate formula
/// names 60 chips while its 12 voltage domains of six chips imply 72. The held
/// S15 and T15 stock releases enumerate 72 and 60 replies respectively, but
/// release-scoped software counts do not establish a universal physical chain
/// fallback for S11/S15/T15. The generic driver therefore has no default.
pub const DEFAULT_CHIPS_PER_CHAIN: Option<u8> = None;

/// SHA-256 cores per BM1391 chip.
///
/// Bitmain's S17 factory jig passes `256` to every BM1391
/// `calculate_core_number` path. The official S15 maintenance guide independently
/// states `frequency × chip core number 256 × chip number 60` on page 11. The
/// core-count corroboration remains useful even though the guide's chip-count
/// statements do not establish release-independent geometry.
const CORES_PER_CHIP: u32 = 256;

/// No BM1391 runtime mutation is authorized by this scaffold.
pub const RUNTIME_MUTATION_AUTHORIZED: bool = false;

/// Legacy scaffold placeholder for an unverified raw-ASIC response length.
///
/// The held S17 jig and exact S15/T15 miners consume an FPGA-normalized pair of
/// `u32` words (8 bytes). That does not establish the pre-FPGA ASIC wire reply
/// length. Conversely, the verified 9-byte BM1391 register-*write* command does
/// not establish a 9-byte reply. The driver stays unregistered and fail-closed.
pub const RESPONSE_BYTES: usize = 9;
pub const RESPONSE_BYTES_VERIFIED: bool = false;

/// Held S17-jig 200 MHz fallback; not the exact S15/T15 register payload.
const S17_JIG_PLL_FALLBACK_200M: u32 = dcentrald_common::BM1391_S17_JIG_PLL_FALLBACK_200M;

/// BM1391 register addresses — JIG-VERIFIED from `BM1391_set_config` call sites.
pub mod regs {
    /// Chip address register (contains ChipID in bits 31:16).
    pub const CHIP_ADDRESS: u8 = 0x00;
    /// PLL0 parameter — hash clock PLL (jig `set_BM1391_freq` writes reg 0x08).
    pub const PLL0: u8 = 0x08;
    /// Ticket mask — hardware difficulty filter (jig `BM1391_set_TM` writes reg
    /// 0x14, BIT-REVERSED via `bit_swap_table`).
    pub const TICKET_MASK: u8 = 0x14;
    /// Misc control — baud divider + clock config (jig `BM1391_set_baud`).
    pub const MISC_CONTROL: u8 = 0x18;
    /// Core register control (indirect core access; `BM1391_enable_core_clock`).
    pub const CORE_REG_CTRL: u8 = 0x3C;
    /// PLL0 output divider (jig `set_BM1391_freq` writes reg 0x70).
    pub const PLL0_DIVIDER: u8 = 0x70;
}

/// BM1391 driver — jig-verified scaffold with no admitted S15/T15 carrier.
pub struct Bm1391Driver;

/// Host-decoded nonce observation in the exact two-word format consumed by
/// Bitmain's held S17 `single-board-test` BM1391 jig.
///
/// This is evidence tooling, not an S15/T15 carrier contract. In particular,
/// it grants no FIFO address, reset GPIO, voltage, or work-submission authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S17JigNonceObservation {
    pub nonce: u32,
    pub chip_index: u8,
    pub core_index: u8,
    pub work_id: u16,
}

/// Decode the held S17 jig's `single_BM1391_check_nonce` two-word observation.
///
/// The decompiled jig uses word 0 bit 31 to distinguish nonces from register
/// replies, requires `(word0 & 0xe0) == 0x80`, extracts `work_id` from the high
/// halfword masked with `0x7fff`, takes the raw ASIC address from word 1's high
/// byte, divides it by the jig's chain address interval, and takes the core
/// index from word 1's low byte. Bounds are supplied by the caller because the
/// observation itself does not carry chain geometry.
pub fn decode_s17_jig_nonce_observation(
    raw: &[u32; 2],
    address_interval: u8,
    expected_chip_count: u8,
) -> Result<S17JigNonceObservation> {
    if address_interval == 0 {
        return Err(crate::AsicError::InvalidParameter(
            "BM1391 S17-jig decode requires a non-zero address interval".into(),
        ));
    }
    if expected_chip_count == 0 {
        return Err(crate::AsicError::InvalidParameter(
            "BM1391 S17-jig decode requires a non-zero expected chip count".into(),
        ));
    }

    let flags = raw[0];
    if flags & 0x8000_0000 == 0 {
        return Err(crate::AsicError::InvalidParameter(
            "BM1391 S17-jig observation is a register reply, not a nonce".into(),
        ));
    }
    if flags & 0x0000_00e0 != 0x0000_0080 {
        return Err(crate::AsicError::InvalidParameter(format!(
            "BM1391 S17-jig nonce flags are not admissible: 0x{:02x}",
            flags & 0xff
        )));
    }

    let raw_address = (raw[1] >> 24) as u8;
    let chip_index = raw_address / address_interval;
    if chip_index >= expected_chip_count {
        return Err(crate::AsicError::InvalidParameter(format!(
            "BM1391 S17-jig ASIC index {chip_index} is outside expected chain length {expected_chip_count}"
        )));
    }

    Ok(S17JigNonceObservation {
        nonce: raw[1],
        chip_index,
        core_index: raw[1] as u8,
        work_id: ((raw[0] >> 16) & 0x7fff) as u16,
    })
}

fn refuse_live_operation<T>(operation: &str) -> Result<T> {
    tracing::warn!(
        operation,
        "BM1391 live operation refused: exact S15/T15 carrier and energization authority are unheld"
    );
    Err(crate::AsicError::InvalidParameter(format!(
        "BM1391 {operation} is scaffold-only; exact S15/T15 carrier and energization authority are unheld"
    )))
}

impl Default for Bm1391Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1391Driver {
    pub fn new() -> Self {
        Self
    }
}

impl ChipDriver for Bm1391Driver {
    fn chip_id(&self) -> u16 {
        CHIP_ID
    }

    fn chip_name(&self) -> &'static str {
        "BM1391"
    }

    fn cores_per_chip(&self) -> u32 {
        CORES_PER_CHIP
    }

    fn response_length(&self) -> usize {
        RESPONSE_BYTES
    }

    fn default_baud(&self) -> u32 {
        115_200
    }

    fn max_baud(&self) -> u32 {
        // Gen-1: MiscControl divider off CLKI; no PLL reclock. Conservative
        // until live-verified on an S11.
        3_125_000
    }

    fn init_chain(&self, _chain: &mut FpgaChain, _chip_count: u8, _freq_mhz: u16) -> Result<()> {
        // Fail-closed. The verified factory sequence (from the S17 jig) is:
        //   chain_inactive → set_address(interval) → set_BM1391_freq (PLL0 reg
        //   0x08 + divider reg 0x70) → enable_core_clock → set_TM (reg 0x14,
        //   bit-reversed) → set_baud (MiscControl reg 0x18 divider) → open_core.
        // This sibling-jig sequence is not S15/T15 carrier or rail authority.
        refuse_live_operation("init_chain")
    }

    fn set_frequency(&self, _chain: &mut FpgaChain, _chip_addr: u8, _freq_mhz: u16) -> Result<()> {
        refuse_live_operation("set_frequency")
    }

    fn set_voltage(&self, _pic: &mut PicController, _voltage_mv: u16) -> Result<()> {
        // A successful no-op is unsafe here: callers could mistake it for a
        // verified rail transition. Refuse until the exact controller, units,
        // envelope, heartbeat, and readback contract are admitted.
        refuse_live_operation("set_voltage")
    }

    fn send_work(&self, _chain: &mut FpgaChain, _work: &MiningWork) -> Result<u16> {
        refuse_live_operation("send_work")
    }

    fn decode_nonce(&self, _raw: &[u32; 2]) -> Result<NonceResult> {
        refuse_live_operation("decode_nonce")
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        // FPGA-side divisor: div = fpga_clock_hz / (16 * target_baud) - 1.
        let div = fpga_clock_hz / (16 * target_baud.max(1));
        div.saturating_sub(1)
    }

    fn ctrl_reg_value(&self) -> u32 {
        // BM139X-family command mode (0x51/0x41), bit4=1 — same as BM1397.
        0x0000_000C
    }

    fn job_interval_ms(&self, _chip_count: u8, _freq_mhz: u16) -> u32 {
        1000
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        // G25 pure SSOT: BM1391_set_TM bit-swap (was wrongly plain while comments
        // claimed bit-reversed — fixed to BitReversed for non-256 difficulties).
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::BitReversed,
            difficulty.max(1),
        )
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        // G42 S17-jig SSOT preview only. This trait remains fail-closed; exact
        // S15/T15 stock solving/programming lives in bm1391_stock_startup.
        let sol = dcentrald_common::resolve_bm1391_pll(freq_mhz);
        PllConfig {
            fb_div: sol.fb_div,
            ref_div: sol.ref_div,
            post_div1: sol.post_div1,
            post_div2: sol.post_div2,
            reg_value: sol.pll0_register,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1391_identity_and_gen1_baud() {
        let d = Bm1391Driver::new();
        assert_eq!(d.chip_id(), 0x1391);
        assert_eq!(d.chip_name(), "BM1391");
        assert_eq!(d.default_baud(), 115_200);
    }

    #[test]
    fn bm1391_jig_verified_register_map() {
        // Pins the byte-verified BM1391 register addresses from the S17 jig.
        assert_eq!(regs::PLL0, 0x08);
        assert_eq!(regs::PLL0_DIVIDER, 0x70);
        assert_eq!(regs::TICKET_MASK, 0x14);
        assert_eq!(regs::MISC_CONTROL, 0x18);
        assert_eq!(S17_JIG_PLL_FALLBACK_200M, 0xC078_0111);
    }

    #[test]
    fn bm1391_pll_encoding_matches_jig_format() {
        // G42: jig 200 MHz fallback 0xC0780111 (fbdiv=120, external /15) — not fbdiv=8 invent.
        let pll = Bm1391Driver::new().pll_params(200);
        assert_eq!(pll.fb_div, 120);
        assert_eq!(pll.reg_value, 0xC078_0111);
        assert_eq!(pll.reg_value, S17_JIG_PLL_FALLBACK_200M);
        let pure = dcentrald_common::resolve_bm1391_pll(200);
        assert_eq!(pll.reg_value, pure.pll0_register);
        assert_eq!(pure.external_div, 15);
        assert_eq!(
            S17_JIG_PLL_FALLBACK_200M & 0x3fff_ffff,
            dcentrald_common::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_WORD
        );
        assert_eq!(
            dcentrald_common::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_REGISTER_PAYLOAD,
            0x4078_0111
        );
        assert_ne!(
            pll.reg_value,
            dcentrald_common::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_REGISTER_PAYLOAD
        );
        assert!(!dcentrald_common::BM1391_S17_JIG_PLL_AUTHORIZES_S15_T15_PROGRAMMING);
    }

    #[test]
    fn bm1391_init_is_fail_closed() {
        // Exact S15/T15 carrier and energization authority are unheld.
        let d = Bm1391Driver::new();
        // (init_chain needs a FpgaChain; the contract is asserted by the
        // Err-return in the impl — pinned here as a doc invariant.)
        assert!(!RUNTIME_MUTATION_AUTHORIZED);
        assert_eq!(DEFAULT_CHIPS_PER_CHAIN, None);
        assert_eq!(d.cores_per_chip(), 256);
        assert_eq!(d.response_length(), RESPONSE_BYTES);
        assert_eq!(RESPONSE_BYTES, 9, "legacy raw-ASIC placeholder only");
        assert!(!RESPONSE_BYTES_VERIFIED);
        assert_eq!(dcentrald_common::BM1391_STOCK_FPGA_RETURN_RECORD_LEN, 8);
        assert_ne!(
            RESPONSE_BYTES,
            dcentrald_common::BM1391_STOCK_FPGA_RETURN_RECORD_LEN,
            "raw ASIC wire replies and FPGA-normalized records are different layers"
        );
        for operation in [
            "init_chain",
            "set_frequency",
            "set_voltage",
            "send_work",
            "decode_nonce",
        ] {
            let err = refuse_live_operation::<()>(operation).expect_err("must refuse");
            assert!(err.to_string().contains(operation));
        }
    }

    #[test]
    fn s17_jig_nonce_observation_is_bounded_and_does_not_unlock_trait_decode() {
        // Synthetic words exercise the exact held-jig bit extraction. They are
        // not presented as a captured S15/T15 nonce.
        let raw = [0x9234_0080, 0x3000_00a5];
        let decoded = decode_s17_jig_nonce_observation(&raw, 0x10, 4).unwrap();
        assert_eq!(
            decoded,
            S17JigNonceObservation {
                nonce: 0x3000_00a5,
                chip_index: 3,
                core_index: 0xa5,
                work_id: 0x1234,
            }
        );

        let driver_err = match Bm1391Driver::new().decode_nonce(&raw) {
            Ok(_) => panic!("S17 jig evidence must not authorize a carrier decoder"),
            Err(err) => err,
        };
        assert!(driver_err.to_string().contains("decode_nonce"));
    }

    #[test]
    fn s17_jig_nonce_observation_rejects_non_nonce_flags_and_bad_geometry() {
        assert!(decode_s17_jig_nonce_observation(&[0x1234_0080, 0], 1, 1).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_00c0, 0], 1, 1).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_0080, 0], 0, 1).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_0080, 0], 1, 0).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_0080, 0x4000_0000], 0x10, 4).is_err());
    }
}
