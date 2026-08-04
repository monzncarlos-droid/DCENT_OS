//! BM1385 ASIC driver (Antminer S7 / S7-LN) — JIG-VERIFIED SCAFFOLD
//!
//! The BM1385 is Bitmain's **28 nm** SHA-256 die (mid-2015), the chip in the
//! Antminer S7 — an entire pre-S9 ASIC generation DCENT_OS previously did not
//! model. Like BM1387/BM1391 it is **Generation-1 FIL-framed**: 4-byte command
//! frames with **no `0x55 0xAA` preamble**, CRC5 over the first **27 bits**
//! (low 5 bits of byte 3 carry the CRC), and a **5-byte** nonce/register
//! response. Its command opcodes differ from BM1387's (BM1387 uses 0x04
//! GetAddress / 0x05 ChainInactive; BM1385 uses the opcodes in [`cmd`]).
//!
//! Status: **SCAFFOLD — fail-closed.** The protocol is byte-verified from the
//! factory jig, but there is **no live Antminer S7 on the fleet** to validate a
//! bring-up against, so `init_chain` / `set_frequency` / `send_work` /
//! `decode_nonce` all refuse. The value delivered here is the *pinned protocol*
//! — exactly as the BM1391 scaffold delivered it — not a live mining path.
//!
//! ## Provenance — every constant below is byte-extracted, not guessed
//! Bitmain factory `single-board-test` jig (unstripped ARM ELF) held at
//!
//! (the Z9-mini jig binary bundles the full BM1385 protocol; +3 more on-disk
//! copies). Decompilation tree `…/single-board-test-ok.dec/`:
//!   - `get_BM1385_plldata@8CD0.c` — the `freq_pll_1385[]` lookup (124 entries).
//!   - `set_BM1385_freq@8FB0.c` — PLL1 write `cmd 0x07`, PLL2 write `cmd 0x02`,
//!     broadcast bit `0x80`, `CRC5(frame, 27)`.
//!   - `BM1385_set_baud@9630.c` / `BM1385_set_gateblk@96AC.c` — `cmd 0x06`,
//!     5-bit `bt8d` baud field (`a3 & 0x1F`).
//!   - `read_BM1385_asic_register@8F1C.c` — register read `cmd 0x04`.
//!   - `BM1385_set_address@95D0.c` — `cmd 0x01`; `single_BM1385_set_address@9AE8.c`
//!     loops `256 / gChain_Asic_Interval` addresses stepping the interval.
//!   - `BM1385_chain_inactive@956C.c` — `cmd 0x85` (`0x80 | 0x05`).
//!   - `single_BM1385_open_core@9BC4.c` — gateblk then **50** 64-byte frames.
//!   - `single_BM1385_calculate_timeout_and_baud@9914.c` — `calculate_core_number(50)`,
//!     `bt8d = 3125000 / ((1666666/timeout) << 9) - 1` clamped `<= 26`.
//!   - `single_BM1385_check_nonce@A2D8.c` — nonce core index `resp[3] & 0x3F`
//!     valid `<= 49`, work_id `resp[4] & 0x7F`.
//!   - `single_BM1385_receive_func@AC14.c` — **5-byte** response frames.
//!   - `singleBoardTest_V9_BM1385_45@18774.c` — 45-chip board, PIC16F1704
//!     voltage path (`V9_set_voltage` / `enable_PIC16F1704_dc_dc`).
//!
//! The 124-entry [`FREQ_PLL`] table is a byte-exact read of ELF `.data` symbol
//! `freq_pll_1385` at addr `0x2454c` (1984 bytes = 124 × 16). Each on-disk row
//! is `{char* freq_ascii, u32 PLL1, u16 PLL2, u32 vilpll}`; the freq is stored
//! as a pointer to a `.rodata` string, resolved here to its integer MHz value.
//!
//! ## Jig printf caveat (do not trust it)
//! `get_BM1385_plldata` sets `i = 4` and prints `"Using 200M"` on a lookup
//! miss — but table **index 4 is 33 MHz**, not 200 MHz (real 200 MHz is index
//! 14). The printf label is a Bitmain bug; the bytes are authoritative.
//!
//! References: `bm1391.rs` (sibling Gen-1 jig scaffold), `bm1387.rs` (live Gen-1
//! template),
//! H2-ASIC-GENERATIONS.md` §G-3.

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::Result;
use dcentrald_hal::fpga_chain::FpgaChain;

/// BM1385 catalog key.
///
/// **NOTE:** the BM1385 exposes **no readable 16-bit chip-ID register** — the
/// jig identifies boards by counting register-read responses
/// (`check_BM1385_asic_reg`), not by an id word. `0x1385` is a synthetic
/// catalog key (mirroring the `0x1391` convention), NOT a value the silicon
/// reports on the wire. Detection of a real S7 must be by chain length, never
/// by a chip-id probe.
pub const CHIP_ID: u16 = 0x1385;

/// SHA-256 cores per BM1385 chip. Jig-verified (`calculate_core_number(50)`;
/// both open-core loops run `i = 0..=49`; `check_nonce` rejects core `> 49`).
const CORES_PER_CHIP: u32 = 50;

/// Chips per S7 hashboard as exercised by the factory jig
/// (`singleBoardTest_V9_BM1385_45`) and AMTC "S7-45". Passthrough fallback
/// only — the driver enumerates when it drives hardware (which it does not yet).
pub const DEFAULT_CHIPS_PER_CHAIN: u8 = 45;

/// Nonce / register response frame length. Jig-verified: the receive loop
/// parses `v16 / 5` records (`single_BM1385_receive_func`). Gen-1 FIL 5-byte
/// response, distinct from BM1387's 9-byte frame.
pub const RESPONSE_BYTES: usize = 5;

/// FPGA baud divisor the jig programs for BM1385 (`set_fpga_baud(26)`), and the
/// clamp ceiling for the chip-side 5-bit `bt8d` field
/// (`single_BM1385_calculate_timeout_and_baud`, `dword_1456B8 > 26 -> 26`).
pub const BT8D_MAX: u8 = 26;

/// BM1385 4-byte command opcodes (byte 0 of each FIL frame; the broadcast bit
/// [`cmd::BROADCAST`] ORs in when the frame targets all chips). Byte-verified
/// from the jig call sites named in the module docs.
pub mod cmd {
    /// Set chip address (`BM1385_set_address`, byte0 = 0x01).
    pub const SET_ADDRESS: u8 = 0x01;
    /// Write a config register — used for the PLL2 word in `set_BM1385_freq`
    /// (byte0 |= 0x02).
    pub const WRITE_REG: u8 = 0x02;
    /// Read a chip register (`read_BM1385_asic_register`, byte0 = 0x04).
    pub const READ_REG: u8 = 0x04;
    /// Chain inactive (`BM1385_chain_inactive`, byte0 = 0x85 = BROADCAST | 0x05).
    pub const CHAIN_INACTIVE: u8 = 0x05;
    /// Set baud / gate-block config (`BM1385_set_baud` + `BM1385_set_gateblk`,
    /// byte0 |= 0x06).
    pub const SET_BAUD: u8 = 0x06;
    /// Write the PLL1 word (`set_BM1385_freq`, byte0 = 0x07).
    pub const SET_PLL: u8 = 0x07;
    /// Broadcast bit ORed into byte 0 to target all chips on the chain.
    pub const BROADCAST: u8 = 0x80;
}

/// One byte-exact row of the jig's `freq_pll_1385[]` table:
/// `(freq_mhz, pll1_word, pll2_word, vilpll_word)`.
///
/// `pll1` is the 32-bit PLL1 register value written by `set_BM1385_freq`'s
/// first (`cmd 0x07`) frame; `pll2` is the 16-bit value written by the second
/// (`cmd 0x02`) frame; `vilpll` is the VIL-mode PLL word the jig also records.
/// These are **raw chip register words** — the fb/ref/post-divider factoring is
/// deliberately NOT reversed here (that would be a guess), so [`pll_params`]
/// surfaces only the raw `reg_value`.
pub type Bm1385PllRow = (u16, u32, u16, u32);

/// The full 124-entry `freq_pll_1385[]` table, byte-extracted from ELF `.data`
/// symbol `freq_pll_1385` (`0x2454c`, 1984 bytes) of the held S7 jig. Ordered
/// exactly as on disk (ascending frequency with the fine 404–800 MHz band
/// interleaving two VCO settings). Index 4 = 33 MHz is the jig's "Using 200M"
/// fallback (a mislabelled printf; see module docs). Index 14 = 200 MHz,
/// index 76 = 600 MHz (the AMTC S7-45 functional-test point).
pub static FREQ_PLL: [Bm1385PllRow; 124] = [
    (19, 0x00020040, 0x0420, 0x00200273),
    (22, 0x00020040, 0x0420, 0x00200263),
    (26, 0x00020040, 0x0420, 0x00200253),
    (28, 0x00020040, 0x0420, 0x00200272),
    (33, 0x00020040, 0x0420, 0x00200243),
    (40, 0x00020040, 0x0420, 0x00200252),
    (50, 0x00020040, 0x0420, 0x00200242),
    (57, 0x00020040, 0x0420, 0x00200271),
    (66, 0x00020040, 0x0420, 0x00200261),
    (80, 0x00020040, 0x0420, 0x00200251),
    (100, 0x00020040, 0x0420, 0x00200241),
    (125, 0x00028040, 0x0420, 0x00280241),
    (150, 0x00030040, 0x0420, 0x00300241),
    (175, 0x00038040, 0x0420, 0x00380241),
    (200, 0x00040040, 0x0420, 0x00400241),
    (225, 0x00048040, 0x0420, 0x00480241),
    (250, 0x00050040, 0x0420, 0x00500241),
    (275, 0x00058040, 0x0420, 0x00580241),
    (300, 0x00060040, 0x0420, 0x00600241),
    (325, 0x00068040, 0x0420, 0x00680241),
    (350, 0x00070040, 0x0420, 0x00700241),
    (375, 0x00078040, 0x0420, 0x00780241),
    (400, 0x00080040, 0x0420, 0x00800241),
    (404, 0x00061040, 0x0320, 0x00610231),
    (406, 0x00041040, 0x0220, 0x00410221),
    (408, 0x00062040, 0x0320, 0x00620231),
    (412, 0x00042040, 0x0220, 0x00420221),
    (416, 0x00064040, 0x0320, 0x00640231),
    (418, 0x00043040, 0x0220, 0x00430221),
    (420, 0x00065040, 0x0320, 0x00650231),
    (425, 0x00044040, 0x0220, 0x00440221),
    (429, 0x00067040, 0x0320, 0x00670231),
    (431, 0x00045040, 0x0220, 0x00450221),
    (433, 0x00068040, 0x0320, 0x00680231),
    (437, 0x00046040, 0x0220, 0x00460221),
    (441, 0x0006A040, 0x0320, 0x006A0231),
    (443, 0x00047040, 0x0220, 0x00470221),
    (445, 0x0006B040, 0x0320, 0x006B0231),
    (450, 0x00048040, 0x0220, 0x00480221),
    (454, 0x0006D040, 0x0320, 0x006D0231),
    (456, 0x00049040, 0x0220, 0x00490221),
    (458, 0x0006E040, 0x0320, 0x006E0231),
    (462, 0x0004A040, 0x0220, 0x004A0221),
    (466, 0x00070040, 0x0320, 0x00700231),
    (468, 0x0004B040, 0x0220, 0x004B0221),
    (470, 0x00071040, 0x0320, 0x00710231),
    (475, 0x0004C040, 0x0220, 0x004C0221),
    (479, 0x00073040, 0x0320, 0x00730231),
    (481, 0x0004D040, 0x0220, 0x004D0221),
    (483, 0x00074040, 0x0320, 0x00740231),
    (487, 0x0004E040, 0x0220, 0x004E0221),
    (491, 0x00076040, 0x0320, 0x00760231),
    (493, 0x0004F040, 0x0220, 0x004F0221),
    (495, 0x00077040, 0x0320, 0x00770231),
    (500, 0x00050040, 0x0220, 0x00500221),
    (504, 0x00079040, 0x0320, 0x00790231),
    (506, 0x00051040, 0x0220, 0x00510221),
    (508, 0x0007A040, 0x0320, 0x007A0231),
    (512, 0x00052040, 0x0220, 0x00520221),
    (516, 0x0007C040, 0x0320, 0x007C0231),
    (518, 0x00053040, 0x0220, 0x00530221),
    (520, 0x0007D040, 0x0320, 0x007D0231),
    (525, 0x00054040, 0x0220, 0x00540221),
    (529, 0x0007F040, 0x0320, 0x007F0231),
    (531, 0x00055040, 0x0220, 0x00550221),
    (533, 0x00080040, 0x0320, 0x00800231),
    (537, 0x00056040, 0x0220, 0x00560221),
    (543, 0x00057040, 0x0220, 0x00570221),
    (550, 0x00058040, 0x0220, 0x00580221),
    (556, 0x00059040, 0x0220, 0x00590221),
    (562, 0x0005A040, 0x0220, 0x005A0221),
    (568, 0x0005B040, 0x0220, 0x005B0221),
    (575, 0x0005C040, 0x0220, 0x005C0221),
    (581, 0x0005D040, 0x0220, 0x005D0221),
    (587, 0x0005E040, 0x0220, 0x005E0221),
    (593, 0x0005F040, 0x0220, 0x005F0221),
    (600, 0x00060040, 0x0220, 0x00600221),
    (606, 0x00061040, 0x0220, 0x00610221),
    (612, 0x00062040, 0x0220, 0x00620221),
    (618, 0x00063040, 0x0220, 0x00630221),
    (625, 0x00064040, 0x0220, 0x00640221),
    (631, 0x00065040, 0x0220, 0x00650221),
    (637, 0x00066040, 0x0220, 0x00660221),
    (643, 0x00067040, 0x0220, 0x00670221),
    (650, 0x00068040, 0x0220, 0x00680221),
    (656, 0x00069040, 0x0220, 0x00690221),
    (662, 0x0006A040, 0x0220, 0x006A0221),
    (668, 0x0006B040, 0x0220, 0x006B0221),
    (675, 0x0006C040, 0x0220, 0x006C0221),
    (681, 0x0006D040, 0x0220, 0x006D0221),
    (687, 0x0006E040, 0x0220, 0x006E0221),
    (693, 0x0006F040, 0x0220, 0x006F0221),
    (700, 0x00070040, 0x0220, 0x00700221),
    (706, 0x00071040, 0x0220, 0x00710221),
    (712, 0x00072040, 0x0220, 0x00720221),
    (718, 0x00073040, 0x0220, 0x00730221),
    (725, 0x00074040, 0x0220, 0x00740221),
    (731, 0x00075040, 0x0220, 0x00750221),
    (737, 0x00076040, 0x0220, 0x00760221),
    (743, 0x00077040, 0x0220, 0x00770221),
    (750, 0x00078040, 0x0220, 0x00780221),
    (756, 0x00079040, 0x0220, 0x00790221),
    (762, 0x0007A040, 0x0220, 0x007A0221),
    (768, 0x0007B040, 0x0220, 0x007B0221),
    (775, 0x0007C040, 0x0220, 0x007C0221),
    (781, 0x0007D040, 0x0220, 0x007D0221),
    (787, 0x0007E040, 0x0220, 0x007E0221),
    (793, 0x0007F040, 0x0220, 0x007F0221),
    (800, 0x00080040, 0x0220, 0x00800221),
    (825, 0x00042040, 0x0120, 0x00420211),
    (850, 0x00044040, 0x0120, 0x00440211),
    (875, 0x00046040, 0x0120, 0x00460221),
    (900, 0x00048040, 0x0120, 0x00480221),
    (925, 0x0004A040, 0x0120, 0x004A0221),
    (950, 0x0004C040, 0x0120, 0x004C0221),
    (975, 0x0004E040, 0x0120, 0x004E0221),
    (1000, 0x00050040, 0x0120, 0x00500221),
    (1025, 0x00052040, 0x0120, 0x00520221),
    (1050, 0x00054040, 0x0120, 0x00540221),
    (1075, 0x00056040, 0x0120, 0x00560221),
    (1100, 0x00058040, 0x0120, 0x00580221),
    (1125, 0x0005A040, 0x0120, 0x005A0221),
    (1150, 0x0005C040, 0x0120, 0x005C0221),
    (1175, 0x0005E040, 0x0120, 0x005E0221),
];

/// The `freq_pll_1385` index the jig falls back to on a lookup miss
/// (`get_BM1385_plldata` sets `i = 4`). This entry is **33 MHz**, not 200 MHz —
/// the jig's `"Using 200M"` printf is mislabelled. Pinned so the discrepancy is
/// documented in code, not lost.
pub const FALLBACK_INDEX: usize = 4;

/// Look up the exact `freq_pll_1385` row for `freq_mhz`, or `None` if the jig
/// table has no exact entry (the jig itself only accepts exact matches, then
/// falls back to [`FALLBACK_INDEX`]).
pub fn pll_row(freq_mhz: u16) -> Option<&'static Bm1385PllRow> {
    FREQ_PLL.iter().find(|(f, _, _, _)| *f == freq_mhz)
}

/// BM1385 driver — jig-verified scaffold (no live Antminer S7 to validate).
pub struct Bm1385Driver;

impl Default for Bm1385Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1385Driver {
    pub fn new() -> Self {
        Self
    }
}

impl ChipDriver for Bm1385Driver {
    fn chip_id(&self) -> u16 {
        CHIP_ID
    }

    fn chip_name(&self) -> &'static str {
        "BM1385"
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
        // Gen-1: chain baud is a chip-side 5-bit `bt8d` divider off the core
        // clock; the jig clamps the FPGA divisor to 26 (`set_fpga_baud(26)`).
        // Conservative until live-verified on an S7.
        3_125_000
    }

    fn init_chain(&self, _chain: &mut FpgaChain, _chip_count: u8, _freq_mhz: u16) -> Result<()> {
        // Fail-closed. The verified factory sequence (from the S7 jig) is:
        //   check_asic_reg (count chips) -> set_baud (V9) -> reset -> set_freq
        //   (PLL1 cmd 0x07 + PLL2 cmd 0x02) -> set_address (chain_inactive then
        //   256/interval SET_ADDRESS frames) -> set_baud (bt8d) -> open_core
        //   (gateblk + 50 x 64-byte frames). It is NOT wired to live hardware
        //   until an operator validates it on a real Antminer S7 — there is no
        //   S7 on the fleet to prove a bring-up against.
        tracing::warn!(
            "BM1385 init_chain: jig-verified scaffold — refusing live bring-up until \
             validated on a real Antminer S7 (no live unit on the fleet)."
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1385 driver is a jig-verified scaffold; live bring-up is gated until an \
             operator validates it on an Antminer S7."
                .into(),
        ))
    }

    fn set_frequency(&self, _chain: &mut FpgaChain, _chip_addr: u8, _freq_mhz: u16) -> Result<()> {
        tracing::warn!("BM1385 set_frequency: scaffold (PLL1 cmd 0x07 + PLL2 cmd 0x02)");
        Err(crate::AsicError::InvalidParameter(
            "BM1385 set_frequency gated until live S7 validation".into(),
        ))
    }

    fn set_voltage(&self, _pic: &mut PicController, _voltage_mv: u16) -> Result<()> {
        // S7 uses a PIC16F1704 voltage path (jig `V9_set_voltage` /
        // `enable_PIC16F1704_dc_dc`), 8-bit DAC — same controller family as the
        // S9/BM1387. Gated until validated on a live S7.
        tracing::warn!("BM1385 set_voltage: scaffold — PIC16F1704 path unvalidated on live S7");
        Err(crate::AsicError::InvalidParameter(
            "BM1385 set_voltage gated until live S7 validation".into(),
        ))
    }

    fn send_work(&self, _chain: &mut FpgaChain, _work: &MiningWork) -> Result<u16> {
        Err(crate::AsicError::InvalidParameter(
            "BM1385 send_work gated until live S7 validation".into(),
        ))
    }

    fn decode_nonce(&self, _raw: &[u32; 2]) -> Result<NonceResult> {
        // Real BM1385 nonce frames are 5 bytes off the wire (nonce[4] + status,
        // core = status & 0x3F, work_id = next & 0x7F). The FpgaChain 2-u32
        // shape here is the Zynq-FIFO carrier, which no S7 uses; gated.
        Err(crate::AsicError::InvalidParameter(
            "BM1385 decode_nonce gated until live S7 validation".into(),
        ))
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        // FPGA-side divisor: div = fpga_clock_hz / (16 * target_baud) - 1.
        let div = fpga_clock_hz / (16 * target_baud.max(1));
        div.saturating_sub(1)
    }

    fn ctrl_reg_value(&self) -> u32 {
        // Gen-1 FIL command mode, ENABLE + MIDSTATE_CNT=2 — mirrors BM1387's
        // 0x0C. (Never applied: the driver is fail-closed and no S7 rides a
        // Zynq FIFO anyway.)
        0x0000_000C
    }

    fn job_interval_ms(&self, _chip_count: u8, _freq_mhz: u16) -> u32 {
        1000
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        // The S7 jig has NO settable ticket-mask register — it validates nonces
        // by direct comparison against dispatched work (`single_BM1385_check_nonce`
        // + `check_hw`), not a hardware difficulty filter. This is therefore a
        // scaffold placeholder mirroring the Gen-1 sibling BM1387 (BitReversed);
        // it never runs (init is fail-closed) and carries no BM1385 evidence.
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::BitReversed,
            difficulty.max(1),
        )
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        // Byte-exact `freq_pll_1385[]` lookup: exact match, else the jig's own
        // fallback (index 4). `reg_value` is the raw PLL1 word; the fb/ref/post
        // divider factoring is intentionally NOT reversed (that would be a
        // guess), so those fields are 0. Consumers must treat `reg_value` as the
        // authoritative datum for BM1385 and ignore the divider fields.
        let (_, pll1, _, _) = pll_row(freq_mhz)
            .copied()
            .unwrap_or(FREQ_PLL[FALLBACK_INDEX]);
        PllConfig {
            fb_div: 0,
            ref_div: 0,
            post_div1: 0,
            post_div2: 0,
            reg_value: pll1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1385_identity_and_gen1_geometry() {
        let d = Bm1385Driver::new();
        assert_eq!(d.chip_id(), 0x1385);
        assert_eq!(d.chip_name(), "BM1385");
        assert_eq!(d.cores_per_chip(), 50);
        assert_eq!(d.response_length(), 5);
        assert_eq!(d.default_baud(), 115_200);
    }

    #[test]
    fn bm1385_jig_command_opcodes() {
        // Byte-verified from the jig call sites (see module docs).
        assert_eq!(cmd::SET_ADDRESS, 0x01);
        assert_eq!(cmd::WRITE_REG, 0x02);
        assert_eq!(cmd::READ_REG, 0x04);
        assert_eq!(cmd::CHAIN_INACTIVE, 0x05);
        assert_eq!(cmd::SET_BAUD, 0x06);
        assert_eq!(cmd::SET_PLL, 0x07);
        assert_eq!(cmd::BROADCAST, 0x80);
        // chain_inactive on the wire is BROADCAST | 0x05 = 0x85.
        assert_eq!(cmd::BROADCAST | cmd::CHAIN_INACTIVE, 0x85);
        assert_eq!(BT8D_MAX, 26);
    }

    #[test]
    fn bm1385_freq_pll_table_is_byte_exact() {
        // 124 entries per get_BM1385_plldata (`sizeof/sizeof = 124`).
        assert_eq!(FREQ_PLL.len(), 124);
        // Spot-check byte-extracted rows against the ELF .data read.
        // Index 4 = the jig's "Using 200M" fallback — actually 33 MHz.
        assert_eq!(FREQ_PLL[FALLBACK_INDEX].0, 33);
        // Index 14 = real 200 MHz.
        assert_eq!(FREQ_PLL[14], (200, 0x00040040, 0x0420, 0x00400241));
        // Index 76 = 600 MHz (AMTC S7-45 functional-test point).
        assert_eq!(FREQ_PLL[76], (600, 0x00060040, 0x0220, 0x00600221));
        // First and last rows.
        assert_eq!(FREQ_PLL[0], (19, 0x00020040, 0x0420, 0x00200273));
        assert_eq!(FREQ_PLL[123], (1175, 0x0005E040, 0x0120, 0x005E0221));
        // Every frequency label is unique.
        let mut freqs: Vec<u16> = FREQ_PLL.iter().map(|(f, _, _, _)| *f).collect();
        freqs.sort_unstable();
        freqs.dedup();
        assert_eq!(freqs.len(), 124);
    }

    #[test]
    fn bm1385_pll_params_uses_exact_table_word() {
        // 600 MHz -> the exact PLL1 word from freq_pll_1385[76].
        let pll = Bm1385Driver::new().pll_params(600);
        assert_eq!(pll.reg_value, 0x00060040);
        // A frequency absent from the jig table -> jig fallback (index 4).
        let miss = Bm1385Driver::new().pll_params(1234);
        assert_eq!(miss.reg_value, FREQ_PLL[FALLBACK_INDEX].1);
    }

    #[test]
    fn bm1385_pll_row_exact_lookup() {
        assert_eq!(pll_row(600), Some(&FREQ_PLL[76]));
        assert!(pll_row(601).is_none());
    }
}
