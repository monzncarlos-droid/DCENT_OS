//! S17-family (BM1397) AM2/Zynq hybrid mining runtime — desk promotion.
//!
//! Campaign `2026-08-27-antminer17-unlock-armada` (agent B1, 2026-08-27).
//! Recipe-swapped counterpart of the proven BM1362 engine
//! ([`crate::s19j_hybrid_mining`]); the BM1362 file is regression-pinned and
//! stays byte-stable. This module owns the BM1397 family values:
//!
//! - **Geometry** (A1 §V2 + stock pattern files): S17/S17 Pro 3×48 (BHB07601),
//!   S17+ 3×65 (BHB07602), T17 3×30 (BHB07701), T17+ 3×44 (BHB07702 — 44, not
//!   45). Address stride `floor(256/N)`: 5/3/8/5.
//! - **UART plan**: 3 chains at the 115,740 default, upgraded through chain
//!   register `0x18` (MiscCtrl) — canonical operational word `0x0000_6031`
//!   (6.25 Mbaud, `dcentrald-silicon-profiles` SSOT). The factory-jig
//!   PLL3/FastUART pair (reg `0x68`/`0x28`) is an opt-in alternative.
//! - **Voltage executors**: typed, byte-exact per A3 §2. dsPIC33EP16GS202
//!   "G2a framed" @ FPGA-bus `0x20|chain` for am2-s17p/am2-t17; PIC16F1704
//!   "G2b raw" for am2-s17plus/am2-t17plus; APW9 PSU DAC @ `0x10` sub 0x02.
//! - **Work codec**: BM1397 serial job packet `14 + 4 + N×32` with 4-midstate
//!   AsicBoost (NOT BIP320 chip-side version rolling — baked-config note),
//!   job-id `+4 mod 128` (`dcentaxe-asic` BM1397 dispatcher).
//! - **Power ordering** (A1 §V3): soc/fpga → scan chains → GPIO907=0 → init
//!   PIC → working voltage → set-address → baud → frequency; reverse on
//!   power-down with PIC SAFE-OFF and GPIO907=1.
//!
//! ## Safety rules enforced here (verify on every edit)
//! - am2 hashboard EEPROM `0x50..=0x57` writes are denied at the HAL fabric;
//!   the denylist is registered before any wire access (rule
//!    #28).
//! - dsPIC fw=`0x86` is refused for voltage commands unless
//!   `DCENT_AM2_S17_TRUST_DEGRADED_FW=1` (lab-only; rule #30).
//! - SET_VOLTAGE is deferred until 5 stable heartbeat ticks (rule #24).
//! - No destructive PIC op (RESET `0x07` / JUMP `0x06` / ERASE `0x09` /
//!   SEND_DATA `0x14`) exists in this module (rule #29); a PIC16 seen in
//!   loader mode (`0xCC`) fails closed instead of jumping.
//! - Voltage executors are fail-closed: no reply ⇒ error + teardown, never a
//!   silent retry loop; heartbeats are bounded.
//! - **Pre-bench energize gate**: no hardware is energized unless
//!   `DCENT_AM2_S17_ALLOW_ENERGIZE=1` is set on the bench unit. The gate is
//!   adjudicated in `main.rs` BEFORE the watchdog is armed, so a gate refusal
//!   parks management-only with the API up and no armed watchdog.
//!
//! DESK-ONLY promotion: every byte here is pinned by held-binary RE; no live
//! S17-family unit has run this code (see the live-bring-up risk list in
//! ).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio_util::sync::CancellationToken;

use crate::config::DcentraldConfig;
use crate::runtime::safety_watchdog::{
    HybridWatchdogRouteScope, SafetyLiveness, SafetyWatchdogOwner,
};
use dcentrald_hal::platform::HardwareMutationGateOwner;

// ---------------------------------------------------------------------------
// Targets, geometry, hashboard identities
// ---------------------------------------------------------------------------

/// Promoted board targets (mirrors `s17_hybrid_admission`).
pub(crate) const S17_HYBRID_BOARD_TARGETS: [&str; 4] =
    ["am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"];

/// Hashboard part number per target (A1 §V1 constants table).
pub(crate) fn s17_hashboard_part_number(board_target: &str) -> Option<&'static str> {
    match board_target {
        "am2-s17p" => Some("BHB07601"),
        "am2-s17plus" => Some("BHB07602"),
        "am2-t17" => Some("BHB07701"),
        "am2-t17plus" => Some("BHB07702"),
        _ => None,
    }
}

/// BM1397 chips per chain per target. T17+ is **44** (stock
/// `07702_pattern_44.txt`, VNish 3.0.5 factory tables — A1 §V2); a claim of 45
/// is refused, not rounded.
pub(crate) fn s17_chips_per_chain(board_target: &str) -> Option<u8> {
    match board_target {
        "am2-s17p" => Some(48),
        "am2-s17plus" => Some(65),
        "am2-t17" => Some(30),
        "am2-t17plus" => Some(44),
        _ => None,
    }
}

/// Address stride for a chain: `floor(256/N)` via the shared SSOT
/// (`dcentrald_common::bm1397plus_addr_interval`). 48→5, 65→3, 30→8, 44→5.
pub(crate) fn s17_addr_interval(board_target: &str) -> Option<u8> {
    s17_chips_per_chain(board_target).map(dcentrald_common::bm1397plus_addr_interval)
}

/// Chain count for the S17 family (3 hashboards per unit; A2 §2 SKU table).
pub(crate) const S17_CHAIN_COUNT: u8 = 3;

// ---------------------------------------------------------------------------
// UART / MiscCtrl ladder (A1 §V4)
// ---------------------------------------------------------------------------

/// Default chain link baud before the upgrade (stock 115200-class default;
/// A2 §2: VNish ladder starts at 115,740).
pub(crate) const S17_DEFAULT_BAUD: u32 = 115_740;

/// Operational baud after the MiscCtrl upgrade
/// (`dcentrald-silicon-profiles` `BM1397_OPERATIONAL_BAUD`).
pub(crate) const S17_OPERATIONAL_BAUD: u32 = 6_250_000;

/// Canonical MiscCtrl (chain register `0x18`) word for the operational baud
/// (`dcentrald-silicon-profiles` `BM1397_MISCCTRL_BAUD_VALUE`).
pub(crate) const S17_MISCCTRL_OPERATIONAL: u32 = 0x0000_6031;

/// Hot-start baud-reset MiscCtrl word (forces chips back toward the 115,740
/// domain; mirrors the FPGA driver `init_chain` step 0,
/// `dcentrald-asic/src/drivers/bm1397.rs`).
pub(crate) const S17_MISCCTRL_RESET_BAUD: u32 = 0x0000_7A31;

/// Factory-jig fast-UART alternative: PLL3 reg `0x68` word then FastUART
/// reg `0x28` word (`dcentrald_common` SSOT; opt-in via
/// `DCENT_AM2_S17_FAST_UART_PLL3`).
pub(crate) const S17_FAST_UART_REG68: u32 = dcentrald_common::BM1397_FAST_UART_PLL3_VALUE;
pub(crate) const S17_FAST_UART_REG28: u32 = dcentrald_common::BM1397_FAST_UART_CONFIG_VALUE;

/// Stock bmminer `dhash_chip_set_baud_v2` law for the chain MiscCtrl word
/// (A1 §V4): `conf_base | (baud > 3_000_000 ? bit16 : 0) |
/// (divider & 0x1F) << 8 | ((divider >> 5) & 0xF) << 24`.
///
/// Pure; the FPGA-side divider comes from the (unheld) `hal_conf.json`
/// per-host values, so live callers must measure it on the bench unit.
pub(crate) fn miscctrl_baud_word(conf_base: u32, baud_hz: u32, divider: u32) -> u32 {
    let high_speed = if baud_hz > 3_000_000 { 1u32 << 16 } else { 0 };
    conf_base | high_speed | ((divider & 0x1F) << 8) | (((divider >> 5) & 0xF) << 24)
}

/// Decode the high-speed bit the stock law encodes (inverse of
/// [`miscctrl_baud_word`] for the bit-16 field only).
pub(crate) fn miscctrl_high_speed_enabled(word: u32) -> bool {
    word & (1 << 16) != 0
}

// ---------------------------------------------------------------------------
// GPIO907 hashboard power (A1 §V3)
// ---------------------------------------------------------------------------

/// PSU/hashboard power gate GPIO (Zynq am2; HAL const
/// `dcentrald-hal/src/platform/zynq.rs`).
pub(crate) const S17_HASHBOARD_POWER_GPIO: u32 = 907;

/// GPIO907 value that turns hashboard power ON (A1 §V3: 0 = ON, 1 = OFF).
pub(crate) const S17_HASHBOARD_POWER_ON: u8 = 0;

/// GPIO907 value that turns hashboard power OFF.
pub(crate) const S17_HASHBOARD_POWER_OFF: u8 = 1;

/// One-second settle after the sysfs GPIO907 prologue (stock `power_on`
/// sleeps 1 s after value write).
pub(crate) const S17_GPIO907_SETTLE: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// PIC controller classes and byte-exact frames (A3 §2)
// ---------------------------------------------------------------------------

/// The two S17-family voltage-controller application ABIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S17PicControllerClass {
    /// dsPIC33EP16GS202, framed `55 AA LEN CMD payload SUM16-BE` @ `0x20|chain`
    /// (am2-s17p, am2-t17).
    DsPicG2aFramed,
    /// PIC16F1704, raw S9-family frames via i2c fd with 200 ms pacing
    /// (am2-s17plus, am2-t17plus).
    Pic16G2bRaw,
}

impl S17PicControllerClass {
    /// Map the BoardDesc adapter class to the wire class (None ⇒ not an
    /// S17-family plan).
    pub(crate) fn from_voltage_controller(
        controller: dcentrald_common::VoltageControllerClass,
    ) -> Option<Self> {
        match controller {
            dcentrald_common::VoltageControllerClass::DsPic33Ep => Some(Self::DsPicG2aFramed),
            dcentrald_common::VoltageControllerClass::Pic16F1704 => Some(Self::Pic16G2bRaw),
            _ => None,
        }
    }

    pub(crate) const fn settle_after_command(self) -> Duration {
        match self {
            // A1 §V3 / A3 §2: 500 ms settle after each dsPIC command.
            Self::DsPicG2aFramed => Duration::from_millis(500),
            // A3 §2: 200 ms pacing between raw PIC16 frames.
            Self::Pic16G2bRaw => Duration::from_millis(200),
        }
    }
}

/// Board PIC I²C address on the FPGA bus: `0x20 | (chain & 7)` → 0x20/0x21/0x22
/// (A1 §V1 wire-protocol fork falsification; identical for both classes).
pub(crate) const fn s17_pic_i2c_addr(chain: u8) -> u8 {
    0x20 | (chain & 7)
}

/// dsPIC G2a frame checksum: `u16` big-endian sum of `LEN + CMD + payload`
/// (A3 §2; verified against A1 §V3 example
/// `55 AA 07 10 A0 00 01 00 B8` → 0x00B8).
fn dspic_g2a_checksum(len: u8, cmd: u8, payload: &[u8]) -> u16 {
    let sum = u16::from(len) + u16::from(cmd) + payload.iter().map(|&b| u16::from(b)).sum::<u16>();
    sum
}

/// Build a dsPIC G2a framed command: `55 AA LEN CMD payload CK_HI CK_LO` with
/// `LEN = payload_len + 4` (A3 §2).
fn dspic_g2a_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 4) as u8;
    let ck = dspic_g2a_checksum(len, cmd, payload);
    let mut frame = Vec::with_capacity(payload.len() + 6);
    frame.extend_from_slice(&[0x55, 0xAA, len, cmd]);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&ck.to_be_bytes());
    frame
}

/// dsPIC G2a SET_VOLTAGE (CMD `0x10`, payload `[VV, 0x00, 0x00]`, 500 ms
/// settle). `vv` is the raw code byte the stock flow writes; its cV→code law
/// is an open live item (A1 "open items": PIC voltage-payload unit encoding).
pub(crate) fn dspic_g2a_set_voltage_frame(vv: u8) -> Vec<u8> {
    dspic_g2a_frame(0x10, &[vv, 0x00, 0x00])
}

/// dsPIC G2a SAFE-OFF / DC-DC off (CMD `0x15`, payload `[0x00]`).
pub(crate) fn dspic_g2a_safe_off_frame() -> Vec<u8> {
    dspic_g2a_frame(0x15, &[0x00])
}

/// dsPIC G2a HEARTBEAT (CMD `0x16`, no payload).
pub(crate) fn dspic_g2a_heartbeat_frame() -> Vec<u8> {
    dspic_g2a_frame(0x16, &[])
}

/// dsPIC G2a GET_VERSION (CMD `0x17`; reply `[05 17 FW x x]`).
pub(crate) fn dspic_g2a_get_version_frame() -> Vec<u8> {
    dspic_g2a_frame(0x17, &[])
}

/// dsPIC G2a READ RAIL mV (CMD `0x29`; reply raw BE16 × 3.3/4096 × 7.6).
pub(crate) fn dspic_g2a_read_rail_frame() -> Vec<u8> {
    dspic_g2a_frame(0x29, &[])
}

/// dsPIC G2a READ PWM duty (CMD `0x2B`; reply PDC0/1/2 BE16).
pub(crate) fn dspic_g2a_read_pwm_duty_frame() -> Vec<u8> {
    dspic_g2a_frame(0x2B, &[])
}

/// PIC16 G2b raw SET_VOLTAGE: `55 AA 10 VV` (A3 §2).
pub(crate) fn pic16_g2b_set_voltage_frame(vv: u8) -> Vec<u8> {
    vec![0x55, 0xAA, 0x10, vv]
}

/// PIC16 G2b raw SAFE-OFF: `55 AA 15 00`.
pub(crate) fn pic16_g2b_safe_off_frame() -> Vec<u8> {
    vec![0x55, 0xAA, 0x15, 0x00]
}

/// PIC16 G2b raw HEARTBEAT: `55 AA 16`.
pub(crate) fn pic16_g2b_heartbeat_frame() -> Vec<u8> {
    vec![0x55, 0xAA, 0x16]
}

/// PIC16 G2b raw GET_VERSION: `55 AA 17` (reply 1 byte; `0xCC` = loader).
pub(crate) fn pic16_g2b_get_version_frame() -> Vec<u8> {
    vec![0x55, 0xAA, 0x17]
}

/// dsPIC33 firmware version that is the proven post-PIC-RESET corruption
/// state — REFUSED for voltage commands (rust-firmware rule #30).
pub(crate) const S17_DEGRADED_DSPIC_FW: u8 = 0x86;

/// PIC16 loader-mode GET_VERSION reply — the runtime fails closed (it must
/// not send the JUMP `0x06` op; recovery-tool owns that).
pub(crate) const S17_PIC16_LOADER_MODE_FW: u8 = 0xCC;

/// Number of stable heartbeat ticks required before SET_VOLTAGE may be sent
/// (rust-firmware rule #24 — NACK before stability corrupts the PIC parser).
pub(crate) const S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE: u32 = 5;

// ---------------------------------------------------------------------------
// APW9 PSU DAC (A1 §V3 / A3 §2)
// ---------------------------------------------------------------------------

/// APW9 PSU I²C address on the FPGA bus (sub-address mode, DAC sub `0x02`).
pub(crate) const S17_APW9_I2C_ADDR: u8 = 0x10;

/// APW9 DAC-write sub-address (FPGA IIC engine sub-address field).
pub(crate) const S17_APW9_DAC_SUBADDR: u8 = 0x02;

/// APW9 PSU SET DAC frame: `55 AA 06 83 DAC 00 CK_HI CK_LO` with
/// `CK = 0x89 + DAC` (A1 §V3; identical SUM16 core law as the dsPIC frames).
pub(crate) fn apw9_set_dac_frame(dac: u8) -> Vec<u8> {
    let ck = 0x06u16 + 0x83 + 0x00 + u16::from(dac);
    let mut frame = Vec::with_capacity(8);
    frame.extend_from_slice(&[0x55, 0xAA, 0x06, 0x83, dac, 0x00]);
    frame.extend_from_slice(&ck.to_be_bytes());
    frame
}

/// APW9 DAC law: `uint8(765.411764 − 35.833333 × V)` clamped to `[0, 255]`
/// (f64 literals from the T17 libplatform disasm, A1 §V3). Truncating cast
/// matches the stock `uint8` semantics (V = 17 V → 156). Valid input range
/// 14.24–21.36 V; out-of-range volts clamp rather than wrap — callers must
/// additionally enforce the cV envelope below before asking for a DAC code.
pub(crate) fn apw9_dac_for_volts(volts: f64) -> u8 {
    let raw = 765.411_764 - 35.833_333 * volts;
    raw.clamp(0.0, 255.0) as u8
}

/// APW9 DAC from the stock `bitmain-voltage` unit (cV×10 on the PSU bus:
/// 1700 = 17.00 V; A1 §V3).
pub(crate) fn apw9_dac_for_bitmain_cv(cv: u32) -> u8 {
    apw9_dac_for_volts(f64::from(cv) / 100.0)
}

/// NO PSU watchdog command exists in the 17-family stock (A1 §V3: "PSU
/// watchdog none — no 0x84 template anywhere in stock 17-family"). This
/// constant documents the refusal: unlike the S19j APW121215a 1 Hz heartbeat
/// requirement, the APW9 needs no 0x84 keep-alive, and sending one would be
/// an unproven mutation.
pub(crate) const S17_PSU_WATCHDOG_CMD_ABSENT: u8 = 0x84;

// ---------------------------------------------------------------------------
// Voltage envelope (clamps)
// ---------------------------------------------------------------------------

/// Vendor software clamp for the PIC-controlled hashboard input bus in cV
/// (18.0–21.0 V; the S17e-class datum "only the 1800-2100 cV vendor software
/// clamp is statically bounded", `board_desc.rs` AM2_S17E_CLASS_UNCONFIRMED_DATUMS).
pub(crate) const S17_PIC_VOLTAGE_MIN_CV: u16 = 1800;
pub(crate) const S17_PIC_VOLTAGE_MAX_CV: u16 = 2100;

/// Bring-up point: 500 MHz @ 1850 cV (VNish 2.0.4 all-SKU identical factory
/// conf, A2 §2 — the conservative desk-proven first target).
pub(crate) const S17_BRING_UP_FREQ_MHZ: u32 = 500;
pub(crate) const S17_BRING_UP_VOLTAGE_CV: u16 = 1850;

/// Clamp a requested PIC bus voltage in cV into the vendor envelope.
/// Out-of-envelope requests are REFUSED (fail-closed), not silently clamped:
/// an operator asking for 15 V or 23 V has the wrong units or the wrong board.
pub(crate) fn clamp_pic_voltage_cv(requested_cv: u16) -> Result<u16> {
    if (S17_PIC_VOLTAGE_MIN_CV..=S17_PIC_VOLTAGE_MAX_CV).contains(&requested_cv) {
        Ok(requested_cv)
    } else {
        Err(anyhow!(
            "S17 PIC bus voltage {requested_cv} cV outside the vendor envelope \
             {S17_PIC_VOLTAGE_MIN_CV}..={S17_PIC_VOLTAGE_MAX_CV} cV — refusing (wrong units or wrong board?)"
        ))
    }
}

// ---------------------------------------------------------------------------
// EEPROM write-deny (rust-firmware rule #28)
// ---------------------------------------------------------------------------

/// am2 hashboard EEPROM addresses `0x50..=0x57` — writes denied at the HAL
/// fabric; the S17 hybrid path registers this list before any wire access
/// (same production pattern as the BM1362 engine's
/// `spawn_i2c_service_no_register_touch_with_denylist_and_reserved_preparation`).
pub(crate) const S17_EEPROM_WRITE_DENYLIST: [u8; 8] =
    [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

// ---------------------------------------------------------------------------
// Power ordering (A1 §V3)
// ---------------------------------------------------------------------------

/// Ordered power-up steps (stock `power_on` flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S17PowerUpStep {
    SocAndFpgaInit,
    ScanChains,
    HashboardPowerOn,
    InitPic,
    WorkingVoltage,
    SetChipAddresses,
    BaudSwitch,
    FrequencyInit,
}

/// Ordered power-down steps: reverse of power-up, with the PIC SAFE-OFF
/// preceding the GPIO907 power cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S17PowerDownStep {
    FrequencyStop,
    HashboardReleaseSleep,
    VoltageDown,
    PicSafeOff,
    HashboardPowerOff,
}

impl S17PowerUpStep {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::SocAndFpgaInit => "soc_fpga_init",
            Self::ScanChains => "scan_chains",
            Self::HashboardPowerOn => "gpio907_power_on",
            Self::InitPic => "init_pic",
            Self::WorkingVoltage => "working_voltage",
            Self::SetChipAddresses => "set_chip_addresses",
            Self::BaudSwitch => "baud_switch",
            Self::FrequencyInit => "frequency_init",
        }
    }

    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::SocAndFpgaInit => 0,
            Self::ScanChains => 1,
            Self::HashboardPowerOn => 2,
            Self::InitPic => 3,
            Self::WorkingVoltage => 4,
            Self::SetChipAddresses => 5,
            Self::BaudSwitch => 6,
            Self::FrequencyInit => 7,
        }
    }
}

impl S17PowerDownStep {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::FrequencyStop => "frequency_stop",
            Self::HashboardReleaseSleep => "hashboard_release_sleep",
            Self::VoltageDown => "voltage_down",
            Self::PicSafeOff => "pic_safe_off",
            Self::HashboardPowerOff => "gpio907_power_off",
        }
    }

    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::FrequencyStop => 0,
            Self::HashboardReleaseSleep => 1,
            Self::VoltageDown => 2,
            Self::PicSafeOff => 3,
            Self::HashboardPowerOff => 4,
        }
    }
}

/// Canonical power-up order (A1 §V3: fpga/soc init → init_scan_exist_chain →
/// GPIO907=0 → init_pic → init_working_voltage → set addresses → baud switch →
/// freq init).
pub(crate) const S17_POWER_UP_ORDER: [S17PowerUpStep; 8] = [
    S17PowerUpStep::SocAndFpgaInit,
    S17PowerUpStep::ScanChains,
    S17PowerUpStep::HashboardPowerOn,
    S17PowerUpStep::InitPic,
    S17PowerUpStep::WorkingVoltage,
    S17PowerUpStep::SetChipAddresses,
    S17PowerUpStep::BaudSwitch,
    S17PowerUpStep::FrequencyInit,
];

/// Canonical power-down order (A1 §V3 power-down + work order: reverse with
/// PIC SAFE-OFF + GPIO907=1).
pub(crate) const S17_POWER_DOWN_ORDER: [S17PowerDownStep; 5] = [
    S17PowerDownStep::FrequencyStop,
    S17PowerDownStep::HashboardReleaseSleep,
    S17PowerDownStep::VoltageDown,
    S17PowerDownStep::PicSafeOff,
    S17PowerDownStep::HashboardPowerOff,
];

// ---------------------------------------------------------------------------
// BM1397 serial work codec (dcentaxe-asic reference)
// ---------------------------------------------------------------------------

/// Job-packet header: `TYPE_JOB | GROUP_SINGLE | CMD_WRITE` = `0x21`
/// (`dcentaxe-asic/src/common.rs`).
pub(crate) const BM1397_JOB_HEADER: u8 = 0x21;

/// Fixed 4-midstate job-packet payload length: `14 + 4 + 4×32` = 146 bytes
/// (`14 + 4 + N×32` with N zero-padded to 4; ESP-Miner always sends the full
/// 146-byte job_packet struct).
pub(crate) const BM1397_JOB_PACKET_LEN: usize = 146;

/// BM1397 job-id advance: `+4 mod 128` (4-midstate stride;
/// `dcentaxe-mining` `DispatcherConfig::for_bm1397`).
pub(crate) const fn next_bm1397_job_id(current: u8) -> u8 {
    (current + 4) % 128
}

/// BM1397 4-midstate AsicBoost: BM1397 uses midstate-based version rolling
/// with NO chip-side BIP320 mask (baked-config note: "BM1397 is 4-midstate
/// AsicBoost (NOT BIP320 chip-side)"). This module must not import or derive
/// the BM1362 BIP320 reconstruction.
pub(crate) const BM1397_MIDSTATE_SLOTS: usize = 4;

/// Build the BM1397 serial job packet (header byte NOT included — callers
/// frame it per transport): `job_id(1) num_midstates(1) starting_nonce(4 LE)
/// nbits(4 LE) ntime(4 LE) merkle4(4) midstate0..3(32×4, zero-padded)`.
pub(crate) fn build_bm1397_job_packet(
    job_id: u8,
    midstates: &[[u8; 32]],
    starting_nonce: u32,
    nbits: u32,
    ntime: u32,
    merkle4: [u8; 4],
) -> Result<Vec<u8>> {
    if midstates.is_empty() || midstates.len() > BM1397_MIDSTATE_SLOTS {
        return Err(anyhow!(
            "BM1397 job requires 1..=4 midstates, got {}",
            midstates.len()
        ));
    }
    let mut packet = Vec::with_capacity(BM1397_JOB_PACKET_LEN);
    packet.push(job_id);
    packet.push(midstates.len() as u8);
    packet.extend_from_slice(&starting_nonce.to_le_bytes());
    packet.extend_from_slice(&nbits.to_le_bytes());
    packet.extend_from_slice(&ntime.to_le_bytes());
    packet.extend_from_slice(&merkle4);
    for slot in 0..BM1397_MIDSTATE_SLOTS {
        match midstates.get(slot) {
            Some(midstate) => packet.extend_from_slice(midstate),
            None => packet.extend_from_slice(&[0u8; 32]),
        }
    }
    Ok(packet)
}

/// BM1397 nonce decoding: chip address lives in nonce bits `[24:17]`
/// (`dcentrald-asic` FPGA driver `decode_nonce`; the S17 jig
/// `BHB07601_check_nonce` divides by `gChain_Asic_Interval`).
pub(crate) const fn bm1397_chip_addr_from_nonce(nonce: u32) -> u8 {
    ((nonce >> 17) & 0xFF) as u8
}

/// Chip index from a nonce given the chain's address stride.
pub(crate) const fn bm1397_chip_index_from_nonce(nonce: u32, addr_interval: u8) -> u8 {
    let interval = if addr_interval == 0 { 1 } else { addr_interval };
    bm1397_chip_addr_from_nonce(nonce) / interval
}

// ---------------------------------------------------------------------------
// Env gates (family-scoped DCENT_AM2_S17_*; -style guard)
// ---------------------------------------------------------------------------

/// Family-scoped env-flag reader with the same truthy-value semantics as the
/// BM1362 engine's `am2_env_flag` (kept local so the BM1362 file stays
/// byte-stable).
pub(crate) fn s17_env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            matches!(
                v.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

/// Opt in to the factory-jig PLL3/FastUART baud pair (reg 0x68/0x28).
/// Default OFF: the stock-proven path is the MiscCtrl `0x18` ladder.
pub(crate) const ENV_S17_FAST_UART_PLL3: &str = "DCENT_AM2_S17_FAST_UART_PLL3";

/// Opt in to serial work dispatch (BM1397 job packets over the chain UART)
/// instead of the FPGA work FIFO. Default OFF until bench proof.
pub(crate) const ENV_S17_SERIAL_WORK_DISPATCH: &str = "DCENT_AM2_S17_SERIAL_WORK_DISPATCH";

/// Skip the per-chain 115200 per-chip init pass. Default OFF (per-chip init
/// RUNS) — the AM2 chain-collapse lesson requires it.
pub(crate) const ENV_S17_SKIP_PER_CHIP_INIT: &str = "DCENT_AM2_S17_SKIP_PER_CHIP_INIT";

/// Lab-only trust of dsPIC fw=0x86 for voltage commands (rule #30). Default
/// OFF; refusing to combine with energization is enforced by the guard.
pub(crate) const ENV_S17_TRUST_DEGRADED_FW: &str = "DCENT_AM2_S17_TRUST_DEGRADED_FW";

/// THE bench gate: hardware energization is refused unless this is set on the
/// bench unit. Default OFF everywhere, and images must never set it.
pub(crate) const ENV_S17_ALLOW_ENERGIZE: &str = "DCENT_AM2_S17_ALLOW_ENERGIZE";

/// Adjudicated recipe derived from the `DCENT_AM2_S17_*` env family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct S17Recipe {
    /// Baud mechanism: MiscCtrl `0x18` ladder (stock-proven default) or the
    /// factory-jig PLL3/FastUART pair (opt-in).
    pub fast_uart_pll3: bool,
    /// Serial work dispatch instead of the FPGA work FIFO.
    pub serial_work_dispatch: bool,
    /// Per-chip 115200 init pass skipped (guard-restricted).
    pub skip_per_chip_init: bool,
    /// dsPIC fw=0x86 trusted for voltage (lab only).
    pub trust_degraded_fw: bool,
    /// Hardware energization admitted (bench gate).
    pub allow_energize: bool,
}

/// Raw env snapshot for [`adjudicate_s17_recipe_from`] (injectable for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct S17RecipeEnv {
    pub fast_uart_pll3: bool,
    pub serial_work_dispatch: bool,
    pub skip_per_chip_init: bool,
    pub trust_degraded_fw: bool,
    pub allow_energize: bool,
}

impl S17RecipeEnv {
    /// Read the real process environment.
    pub(crate) fn from_env() -> Self {
        Self {
            fast_uart_pll3: s17_env_flag(ENV_S17_FAST_UART_PLL3),
            serial_work_dispatch: s17_env_flag(ENV_S17_SERIAL_WORK_DISPATCH),
            skip_per_chip_init: s17_env_flag(ENV_S17_SKIP_PER_CHIP_INIT),
            trust_degraded_fw: s17_env_flag(ENV_S17_TRUST_DEGRADED_FW),
            allow_energize: s17_env_flag(ENV_S17_ALLOW_ENERGIZE),
        }
    }
}

/// Pure adjudication of the env family into a recipe; refuses known-bad
/// combinations ( pattern):
///
/// 1. Energizing with the per-chip init skipped — the AM2 chain-collapse
///    lesson: per-chip 115200 init is mandatory when energizing.
/// 2. Serial work dispatch with the per-chip init skipped — same root cause.
/// 3. Trusting degraded PIC firmware while energizing — the fw=0x86 state is
///    the proven corruption state; it must never see voltage commands outside
///    a read-only lab session.
pub(crate) fn adjudicate_s17_recipe_from(flags: S17RecipeEnv) -> Result<S17Recipe> {
    let recipe = S17Recipe {
        fast_uart_pll3: flags.fast_uart_pll3,
        serial_work_dispatch: flags.serial_work_dispatch,
        skip_per_chip_init: flags.skip_per_chip_init,
        trust_degraded_fw: flags.trust_degraded_fw,
        allow_energize: flags.allow_energize,
    };
    if recipe.allow_energize && recipe.skip_per_chip_init {
        return Err(anyhow!(
            "S17 recipe guard: DCENT_AM2_S17_SKIP_PER_CHIP_INIT=1 cannot be combined with \
             energization (AM2 chain-collapse lesson: per-chip 115200 init is mandatory)"
        ));
    }
    if recipe.serial_work_dispatch && recipe.skip_per_chip_init {
        return Err(anyhow!(
            "S17 recipe guard: serial work dispatch requires the per-chip init pass \
             (DCENT_AM2_S17_SKIP_PER_CHIP_INIT must stay unset)"
        ));
    }
    if recipe.allow_energize && recipe.trust_degraded_fw {
        return Err(anyhow!(
            "S17 recipe guard: DCENT_AM2_S17_TRUST_DEGRADED_FW=1 is read-path lab-only and \
             cannot be combined with energization"
        ));
    }
    Ok(recipe)
}

/// Adjudicate the pre-bench energize gate. Called by `main.rs` BEFORE the
/// watchdog is armed: a refusal parks management-only with the API reachable
/// and no armed watchdog (no reboot loop).
pub(crate) fn adjudicate_s17_energize_gate() -> Result<S17Recipe> {
    adjudicate_s17_recipe_from(S17RecipeEnv::from_env())
}

// ---------------------------------------------------------------------------
// Fail-closed typed voltage executor
// ---------------------------------------------------------------------------

/// Wire transport for PIC/PSU transactions (host-mockable).
pub(crate) trait S17PicWire {
    /// Write `write` to `i2c_addr` and read `read_len` bytes back. Implementors
    /// must apply the EEPROM denylist at their fabric boundary; an `Err`
    /// return models a missing/negative reply.
    fn transact(&mut self, i2c_addr: u8, write: &[u8], read_len: usize)
        -> std::io::Result<Vec<u8>>;
}

/// Adjudicated PIC firmware state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S17PicFirmwareState {
    /// Application firmware byte accepted for voltage commands.
    App { version: u8 },
    /// dsPIC post-corruption state (fw=0x86) — refused unless lab-trusted.
    DegradedDspic,
    /// PIC16 loader mode (0xCC) — always refused; recovery-tool owns the jump.
    LoaderMode,
}

impl S17PicFirmwareState {
    pub(crate) fn from_version(class: S17PicControllerClass, version: u8) -> Self {
        if version == S17_PIC16_LOADER_MODE_FW {
            return Self::LoaderMode;
        }
        if class == S17PicControllerClass::DsPicG2aFramed && version == S17_DEGRADED_DSPIC_FW {
            return Self::DegradedDspic;
        }
        Self::App { version }
    }
}

/// Typed, fail-closed voltage executor for one hashboard PIC.
///
/// Invariants:
/// - SET_VOLTAGE is refused until [`S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE`]
///   consecutive heartbeats have succeeded (rule #24).
/// - dsPIC fw=`0x86` and PIC16 loader-mode (`0xCC`) are refused for voltage
///   commands; the executor never sends JUMP/RESET (rule #29).
/// - Any wire error propagates as `Err` — the caller must tear the chain down;
///   there is no silent retry.
pub(crate) struct S17VoltageExecutor<W: S17PicWire> {
    class: S17PicControllerClass,
    chain: u8,
    wire: W,
    stable_heartbeats: u32,
    trust_degraded_fw: bool,
    firmware_version: Option<u8>,
}

impl<W: S17PicWire> S17VoltageExecutor<W> {
    pub(crate) fn new(class: S17PicControllerClass, chain: u8, wire: W) -> Self {
        Self {
            class,
            chain,
            wire,
            stable_heartbeats: 0,
            trust_degraded_fw: false,
            firmware_version: None,
        }
    }

    /// Lab-only override for the fw=0x86 refusal (rule #30; guard refuses to
    /// combine this with energization).
    pub(crate) fn with_trust_degraded_fw(mut self, trusted: bool) -> Self {
        self.trust_degraded_fw = trusted;
        self
    }

    pub(crate) const fn i2c_addr(&self) -> u8 {
        s17_pic_i2c_addr(self.chain)
    }

    /// Probe GET_VERSION and adjudicate the firmware state. Any reply shape
    /// we cannot parse fails closed.
    pub(crate) fn probe_firmware(&mut self) -> std::io::Result<S17PicFirmwareState> {
        let parse: fn(&[u8]) -> std::io::Result<u8> = match self.class {
            S17PicControllerClass::DsPicG2aFramed => parse_ds_pic_version_reply,
            S17PicControllerClass::Pic16G2bRaw => parse_pic16_version_reply,
        };
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_get_version_frame(),
            S17PicControllerClass::Pic16G2bRaw => pic16_g2b_get_version_frame(),
        };
        let reply = self.wire.transact(self.i2c_addr(), &frame, 5)?;
        let version = parse(&reply)?;
        self.firmware_version = Some(version);
        Ok(S17PicFirmwareState::from_version(self.class, version))
    }

    /// One heartbeat transaction; success increments the stability counter.
    pub(crate) fn heartbeat(&mut self) -> std::io::Result<()> {
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_heartbeat_frame(),
            S17PicControllerClass::Pic16G2bRaw => pic16_g2b_heartbeat_frame(),
        };
        // Any non-empty acknowledgement counts; an Err (no reply) propagates.
        let reply = self.wire.transact(self.i2c_addr(), &frame, 2)?;
        if reply.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "S17 PIC heartbeat returned no bytes (fail-closed)",
            ));
        }
        self.stable_heartbeats = self.stable_heartbeats.saturating_add(1);
        Ok(())
    }

    /// Bounded heartbeat pass: at most `max_attempts` transactions; a missing
    /// reply is an error (never an unbounded loop).
    pub(crate) fn heartbeat_bounded(&mut self, max_attempts: u32) -> std::io::Result<()> {
        let mut remaining = max_attempts.max(1);
        loop {
            match self.heartbeat() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if remaining <= 1 {
                        return Err(error);
                    }
                    remaining -= 1;
                }
            }
        }
    }

    /// SET_VOLTAGE with the raw code byte for this controller class. Refused
    /// (Err) before the 5-stable-heartbeat gate, on degraded/loader firmware,
    /// without a prior firmware probe, and on any wire fault.
    pub(crate) fn set_voltage_code(&mut self, vv: u8) -> std::io::Result<()> {
        if self.stable_heartbeats < S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "S17 PIC SET_VOLTAGE deferred: {} stable heartbeats required, {} observed",
                    S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE, self.stable_heartbeats
                ),
            ));
        }
        self.adjudicate_firmware_for_voltage()?;
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_set_voltage_frame(vv),
            S17PicControllerClass::Pic16G2bRaw => pic16_g2b_set_voltage_frame(vv),
        };
        let reply = self.wire.transact(self.i2c_addr(), &frame, 2)?;
        if reply.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "S17 PIC SET_VOLTAGE returned no bytes (fail-closed teardown)",
            ));
        }
        Ok(())
    }

    /// SAFE-OFF (DC-DC off). Always permitted — safe direction — and still
    /// fail-closed on a missing reply.
    pub(crate) fn safe_off(&mut self) -> std::io::Result<()> {
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_safe_off_frame(),
            S17PicControllerClass::Pic16G2bRaw => pic16_g2b_safe_off_frame(),
        };
        self.wire.transact(self.i2c_addr(), &frame, 2)?;
        Ok(())
    }

    fn adjudicate_firmware_for_voltage(&self) -> std::io::Result<()> {
        let Some(version) = self.firmware_version else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "S17 PIC firmware not probed; refusing SET_VOLTAGE",
            ));
        };
        match S17PicFirmwareState::from_version(self.class, version) {
            S17PicFirmwareState::App { .. } => Ok(()),
            S17PicFirmwareState::DegradedDspic if self.trust_degraded_fw => Ok(()),
            S17PicFirmwareState::DegradedDspic => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "S17 dsPIC fw=0x86 (post-corruption state) refused for voltage; \
                 physical ICSP recovery required",
            )),
            S17PicFirmwareState::LoaderMode => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "S17 PIC16 in loader mode (0xCC) refused for voltage; \
                 recovery-tool owns the jump op",
            )),
        }
    }
}

/// dsPIC G2a GET_VERSION reply `[05 17 FW x x]` → `FW` (A3 §2).
fn parse_ds_pic_version_reply(reply: &[u8]) -> std::io::Result<u8> {
    if reply.len() >= 3 && reply[0] == 0x05 && reply[1] == 0x17 {
        Ok(reply[2])
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed dsPIC GET_VERSION reply {reply:02X?}"),
        ))
    }
}

/// PIC16 G2b GET_VERSION reply: 1 byte FW (A3 §2).
fn parse_pic16_version_reply(reply: &[u8]) -> std::io::Result<u8> {
    if reply.len() == 1 {
        Ok(reply[0])
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed PIC16 GET_VERSION reply {reply:02X?}"),
        ))
    }
}

/// Host-test mock wire: scripted replies + a transaction log.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockS17PicWire {
    pub replies: std::collections::VecDeque<std::io::Result<Vec<u8>>>,
    pub log: Vec<(u8, Vec<u8>)>,
}

#[cfg(test)]
impl S17PicWire for MockS17PicWire {
    fn transact(
        &mut self,
        i2c_addr: u8,
        write: &[u8],
        _read_len: usize,
    ) -> std::io::Result<Vec<u8>> {
        self.log.push((i2c_addr, write.to_vec()));
        self.replies.pop_front().unwrap_or_else(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no reply",
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Safety admission + miner
// ---------------------------------------------------------------------------

/// Watchdog bring-up grace before the first liveness kick is expected.
const S17_HYBRID_WATCHDOG_BRINGUP_GRACE: Duration = Duration::from_secs(180);

/// Pre-energize ownership bundle for one exact AM2/Zynq BM1397 hybrid run
/// (mirrors the BM1362 `S19jHybridSafetyAdmission` shape).
#[must_use = "S17 hybrid safety admission must be moved into exactly one mining lifecycle"]
pub(crate) struct S17HybridSafetyAdmission {
    route_admission: crate::s17_hybrid_admission::S17HybridRouteAdmission,
    watchdog: SafetyWatchdogOwner,
    watchdog_route_scope: HybridWatchdogRouteScope,
    liveness: SafetyLiveness,
    hardware_mutation_owner: HardwareMutationGateOwner,
}

impl S17HybridSafetyAdmission {
    pub(crate) async fn start(
        config: &DcentraldConfig,
        runtime_dispatch_admission: crate::RuntimeDispatchAdmission,
        route_admission: crate::s17_hybrid_admission::S17HybridRouteAdmission,
    ) -> Result<Self> {
        let _protocol_admission = runtime_dispatch_admission
            .require_asic_protocol(
                crate::RuntimeDispatchKind::S17Hybrid,
                route_admission.board_target(),
                dcentrald_common::AsicProtocolIdentity::Bm1397,
            )
            .map_err(anyhow::Error::msg)?;

        let liveness = SafetyLiveness::default();
        let expected_liveness = Duration::from_secs_f32(config.thermal.pid_interval_s.max(1.0));
        let (mut watchdog, admission) = SafetyWatchdogOwner::start_before_energizing(
            &config.watchdog,
            S17_HYBRID_WATCHDOG_BRINGUP_GRACE,
            expected_liveness,
            liveness.clone(),
        )
        .await?;
        let receipt = admission.require_armed("s17-hybrid")?;
        let watchdog_route_scope = watchdog.claim_hybrid_route_scope().map_err(|error| {
            crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                "s17-hybrid",
                format!("post-arm route-scope claim failed: {error:#}"),
            )
        })?;
        tracing::info!(
            requested_timeout_s = receipt.requested_timeout_s,
            effective_timeout_s = receipt.effective_timeout_s,
            kick_interval_s = receipt.kick_interval_s,
            board_target = route_admission.board_target(),
            "s17-hybrid: pre-energize watchdog ownership admitted"
        );

        Ok(Self {
            route_admission,
            watchdog,
            watchdog_route_scope,
            liveness,
            hardware_mutation_owner: HardwareMutationGateOwner::new_pending(),
        })
    }

    pub(crate) fn hardware_mutation_gate(&self) -> dcentrald_hal::platform::HardwareMutationGate {
        self.hardware_mutation_owner.gate()
    }
}

/// The BM1397 hybrid engine. Constructible only with the one-shot route +
/// safety admissions; [`S17HybridMiner::run`] executes the desk-proven phase
/// plan and fail-closes at the first unproven hardware boundary.
pub struct S17HybridMiner {
    safety_admission: Option<S17HybridSafetyAdmission>,
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<tokio::sync::watch::Sender<dcentrald_api::MinerState>>,
}

impl S17HybridMiner {
    /// Construct the BM1397-only hybrid engine after composition admission.
    /// No hardware is opened here; rejecting before construction keeps every
    /// future mutation behind the same invariant.
    pub fn new(
        config: DcentraldConfig,
        shutdown: CancellationToken,
        safety_admission: S17HybridSafetyAdmission,
    ) -> Result<Self> {
        Ok(Self {
            safety_admission: Some(safety_admission),
            config,
            shutdown,
            state_tx: None,
        })
    }

    /// Attach a live `MinerState` publisher (dashboard), mirroring the BM1362
    /// builder. Fail-closed: a closed channel only drops the publish.
    pub fn with_state_tx(
        mut self,
        state_tx: tokio::sync::watch::Sender<dcentrald_api::MinerState>,
    ) -> Self {
        self.state_tx = Some(state_tx);
        self
    }

    /// Execute one hybrid lifecycle.
    ///
    /// Current (desk promotion) scope: re-adjudicate the recipe env, log the
    /// full phase plan (geometry, ladder, UART plan, power order), and then
    /// fail closed at the first boundary that has no live-proof wiring yet —
    /// the chain UART/FPGA transport execution. The bench milestone replaces
    /// that boundary with the real transport while keeping every invariant
    /// above it unchanged.
    pub async fn run(mut self) -> Result<()> {
        let safety = self
            .safety_admission
            .take()
            .ok_or_else(|| anyhow!("s17-hybrid run() entered twice"))?;
        let recipe = adjudicate_s17_recipe_from(S17RecipeEnv::from_env())?;
        if !recipe.allow_energize {
            return Err(anyhow!(
                "s17-hybrid energize gate refused after watchdog arm — main.rs must adjudicate \
                 the gate before arming; this is an internal ordering bug"
            ));
        }

        let board_target = safety.route_admission.board_target();
        let chips = s17_chips_per_chain(board_target)
            .ok_or_else(|| anyhow!("unknown S17 geometry for {board_target}"))?;
        let interval = s17_addr_interval(board_target)
            .ok_or_else(|| anyhow!("unknown S17 address stride for {board_target}"))?;

        tracing::info!(
            board_target,
            hashboard = s17_hashboard_part_number(board_target),
            chains = S17_CHAIN_COUNT,
            chips_per_chain = chips,
            addr_interval = interval,
            bring_up_freq_mhz = S17_BRING_UP_FREQ_MHZ,
            bring_up_voltage_cv = S17_BRING_UP_VOLTAGE_CV,
            fast_uart_pll3 = recipe.fast_uart_pll3,
            serial_work_dispatch = recipe.serial_work_dispatch,
            power_up = ?S17_POWER_UP_ORDER
                .iter()
                .map(|step| step.label())
                .collect::<Vec<_>>(),
            "s17-hybrid: phase plan admitted"
        );

        // EEPROM write-denylist contract reference (rule #28): the denylist
        // must be registered with the I2C service BEFORE any wire access. The
        // transport binding itself is the bench milestone; keeping the
        // contract asserted at the point where wire access would begin makes
        // the invariant impossible to drop silently.
        debug_assert_eq!(S17_EEPROM_WRITE_DENYLIST.len(), 8);
        debug_assert_eq!(S17_EEPROM_WRITE_DENYLIST.first(), Some(&0x50));
        debug_assert_eq!(S17_EEPROM_WRITE_DENYLIST.last(), Some(&0x57));

        let _ = self.shutdown; // bench wiring: cancellation feeds teardown arms.
        let _ = self.state_tx;
        let _ = self.config;

        Err(anyhow!(
            "s17-hybrid live bring-up wiring pending bench milestone: chain UART/FPGA transport \
             execution for {board_target} ({chips} chips/chain, stride {interval}) is not \
             live-proven; refusing to energize (desk promotion, \
             2026-08-27-antminer17-unlock-armada)"
        ))
        .with_context(|| {
            "S17HybridMiner::run reached the unproven transport boundary with \
             DCENT_AM2_S17_ALLOW_ENERGIZE set"
        })
    }
}

// ---------------------------------------------------------------------------
// Host tests (desk-exact; no hardware)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("s17_hybrid_mining.rs");

    // ---- geometry ------------------------------------------------------

    #[test]
    fn s17_geometry_per_target_matches_stock_re() {
        // A1 §V1/§V2: pattern files 07601(48)/07602(65)/07701(30)/07702(44).
        for (target, chips, hashboard) in [
            ("am2-s17p", 48u8, "BHB07601"),
            ("am2-s17plus", 65, "BHB07602"),
            ("am2-t17", 30, "BHB07701"),
            ("am2-t17plus", 44, "BHB07702"),
        ] {
            assert_eq!(s17_chips_per_chain(target), Some(chips), "{target}");
            assert_eq!(
                s17_hashboard_part_number(target),
                Some(hashboard),
                "{target}"
            );
        }
        // Unknown targets resolve nothing (no prefix inheritance).
        assert_eq!(s17_chips_per_chain("am2-s19j"), None);
        assert_eq!(s17_hashboard_part_number("am2-s17e"), None);
    }

    #[test]
    fn t17plus_is_44_not_45() {
        // A1 §V2 (HIGH): stock `07702_pattern_44.txt` + VNish 3.0.5 factory
        // tables pin 3×44=132. The retired "45" operator note must not return.
        assert_eq!(s17_chips_per_chain("am2-t17plus"), Some(44));
        assert_ne!(s17_chips_per_chain("am2-t17plus"), Some(45));
        assert_eq!(s17_addr_interval("am2-t17plus"), Some(5)); // floor(256/44)
        assert_eq!(dcentrald_common::bm1397plus_addr_interval(45), 5);
        // But 45 is not a registered model geometry:
        assert!(!S17_HYBRID_BOARD_TARGETS
            .iter()
            .any(|t| s17_chips_per_chain(t) == Some(45)));
    }

    #[test]
    fn address_intervals_match_jig_formula() {
        for (target, interval) in [
            ("am2-s17p", 5u8),
            ("am2-s17plus", 3),
            ("am2-t17", 8),
            ("am2-t17plus", 5),
        ] {
            assert_eq!(s17_addr_interval(target), Some(interval), "{target}");
        }
    }

    // ---- UART / MiscCtrl ladder ----------------------------------------

    #[test]
    fn miscctrl_baud_word_encodes_the_stock_law() {
        // A1 §V4: bit16 set iff baud > 3,000,000; divider split across
        // bits 8-12 and 24-27.
        let low = miscctrl_baud_word(0x31, 115_740, 26);
        assert!(!miscctrl_high_speed_enabled(low));
        assert_eq!((low >> 8) & 0x1F, 26 & 0x1F);
        assert_eq!((low >> 24) & 0xF, 0);

        let high = miscctrl_baud_word(0x31, 6_250_000, 33); // divider spans the split
        assert!(miscctrl_high_speed_enabled(high));
        assert_eq!((high >> 8) & 0x1F, 33 & 0x1F); // 1
        assert_eq!((high >> 24) & 0xF, (33 >> 5) & 0xF); // 1

        // Boundary: exactly 3,000,000 stays low-speed; +1 goes high.
        assert!(!miscctrl_high_speed_enabled(miscctrl_baud_word(
            0, 3_000_000, 1
        )));
        assert!(miscctrl_high_speed_enabled(miscctrl_baud_word(
            0, 3_000_001, 1
        )));

        // conf_base bits pass through untouched.
        assert_eq!(miscctrl_baud_word(0x31, 115_740, 0) & 0xFF, 0x31);
    }

    #[test]
    fn canonical_miscctrl_and_baud_constants_match_silicon_profiles() {
        assert_eq!(S17_MISCCTRL_OPERATIONAL, 0x0000_6031);
        assert_eq!(S17_MISCCTRL_RESET_BAUD, 0x0000_7A31);
        assert_eq!(S17_OPERATIONAL_BAUD, 6_250_000);
        assert_eq!(S17_DEFAULT_BAUD, 115_740);
        assert_eq!(S17_FAST_UART_REG68, 0xC070_0111);
        assert_eq!(S17_FAST_UART_REG28, 0x0600_000F);
        // Cross-check against the silicon-profiles SSOT itself.
        assert_eq!(
            S17_MISCCTRL_OPERATIONAL,
            dcentrald_silicon_profiles::bm1397::BM1397_MISCCTRL_BAUD_VALUE
        );
        assert_eq!(
            S17_OPERATIONAL_BAUD,
            dcentrald_silicon_profiles::bm1397::BM1397_OPERATIONAL_BAUD
        );
    }

    #[test]
    fn gpio907_polarity_is_on_zero_off_one() {
        assert_eq!(S17_HASHBOARD_POWER_GPIO, 907);
        assert_eq!(S17_HASHBOARD_POWER_ON, 0);
        assert_eq!(S17_HASHBOARD_POWER_OFF, 1);
    }

    // ---- PIC frame fixtures (byte-exact, A3 §2) -------------------------

    #[test]
    fn dspic_g2a_checksum_law_matches_the_held_example() {
        // A1 §V3 held example: chain1/0x00A0 payload [A0 00 01] → 00 B8.
        let frame = dspic_g2a_frame(0x10, &[0xA0, 0x00, 0x01]);
        assert_eq!(
            frame,
            vec![0x55, 0xAA, 0x07, 0x10, 0xA0, 0x00, 0x01, 0x00, 0xB8]
        );
    }

    #[test]
    fn dspic_g2a_command_frames_are_byte_exact() {
        // A3 §2 table (payload [VV 00 00] form; checksum computed by the law).
        assert_eq!(
            dspic_g2a_set_voltage_frame(0xA0),
            vec![0x55, 0xAA, 0x07, 0x10, 0xA0, 0x00, 0x00, 0x00, 0xB7]
        );
        assert_eq!(
            dspic_g2a_safe_off_frame(),
            vec![0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A]
        );
        assert_eq!(
            dspic_g2a_heartbeat_frame(),
            vec![0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A]
        );
        assert_eq!(
            dspic_g2a_get_version_frame(),
            vec![0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B]
        );
        assert_eq!(
            dspic_g2a_read_rail_frame(),
            vec![0x55, 0xAA, 0x04, 0x29, 0x00, 0x2D]
        );
        assert_eq!(
            dspic_g2a_read_pwm_duty_frame(),
            vec![0x55, 0xAA, 0x04, 0x2B, 0x00, 0x2F]
        );
    }

    #[test]
    fn pic16_g2b_command_frames_are_byte_exact() {
        assert_eq!(
            pic16_g2b_set_voltage_frame(0x5A),
            vec![0x55, 0xAA, 0x10, 0x5A]
        );
        assert_eq!(pic16_g2b_safe_off_frame(), vec![0x55, 0xAA, 0x15, 0x00]);
        assert_eq!(pic16_g2b_heartbeat_frame(), vec![0x55, 0xAA, 0x16]);
        assert_eq!(pic16_g2b_get_version_frame(), vec![0x55, 0xAA, 0x17]);
    }

    #[test]
    fn pic_addresses_are_20_or_chain_for_both_classes() {
        for chain in 0u8..8 {
            assert_eq!(s17_pic_i2c_addr(chain), 0x20 | (chain & 7));
        }
        assert_eq!(s17_pic_i2c_addr(0), 0x20);
        assert_eq!(s17_pic_i2c_addr(1), 0x21);
        assert_eq!(s17_pic_i2c_addr(2), 0x22);
        // Settle/pacing per class (A1 §V3 500 ms; A3 §2 200 ms).
        assert_eq!(
            S17PicControllerClass::DsPicG2aFramed.settle_after_command(),
            Duration::from_millis(500)
        );
        assert_eq!(
            S17PicControllerClass::Pic16G2bRaw.settle_after_command(),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn controller_class_maps_the_board_desc_adjudication() {
        use dcentrald_common::VoltageControllerClass;
        assert_eq!(
            S17PicControllerClass::from_voltage_controller(VoltageControllerClass::DsPic33Ep),
            Some(S17PicControllerClass::DsPicG2aFramed)
        );
        assert_eq!(
            S17PicControllerClass::from_voltage_controller(VoltageControllerClass::Pic16F1704),
            Some(S17PicControllerClass::Pic16G2bRaw)
        );
        assert_eq!(
            S17PicControllerClass::from_voltage_controller(
                VoltageControllerClass::RuntimeDiscovered
            ),
            None
        );
    }

    // ---- APW9 PSU -------------------------------------------------------

    #[test]
    fn apw9_dac_law_boundaries() {
        // Held anchor: V = 17 → DAC 156 (A1 §V3).
        assert_eq!(apw9_dac_for_volts(17.0), 156);
        assert_eq!(apw9_dac_for_bitmain_cv(1700), 156);
        // Low-voltage clamp saturates at 0xFF (A1: clamp 0xFF).
        assert_eq!(apw9_dac_for_volts(14.24), 255);
        assert_eq!(apw9_dac_for_volts(10.0), 255);
        // High-voltage clamp saturates at 0.
        assert_eq!(apw9_dac_for_volts(21.36), 0);
        assert_eq!(apw9_dac_for_volts(25.0), 0);
        // Monotone non-increasing across the range.
        let mut last = 255u8;
        for tenths in 1424..=2136 {
            let dac = apw9_dac_for_volts(f64::from(tenths) / 100.0);
            assert!(dac <= last, "DAC increased at {tenths}cV");
            last = dac;
        }
    }

    #[test]
    fn apw9_frame_is_byte_exact_with_0x89_plus_dac_checksum() {
        assert_eq!(
            apw9_set_dac_frame(156),
            vec![0x55, 0xAA, 0x06, 0x83, 0x9C, 0x00, 0x01, 0x25] // CK = 0x89+0x9C = 0x125
        );
        assert_eq!(
            apw9_set_dac_frame(0),
            vec![0x55, 0xAA, 0x06, 0x83, 0x00, 0x00, 0x00, 0x89]
        );
        assert_eq!(S17_APW9_I2C_ADDR, 0x10);
        assert_eq!(S17_APW9_DAC_SUBADDR, 0x02);
    }

    #[test]
    fn no_psu_watchdog_command_exists_in_this_generation() {
        // A1 §V3: no 0x84 template anywhere in stock 17-family. The constant
        // exists to document the refusal; the module must never build a frame
        // with that opcode.
        assert_eq!(S17_PSU_WATCHDOG_CMD_ABSENT, 0x84);
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(
            !production.contains("apw9_watchdog"),
            "the APW9 watchdog opcode must not gain an executor"
        );
    }

    // ---- voltage envelope -------------------------------------------------

    #[test]
    fn pic_voltage_envelope_refuses_out_of_range() {
        assert_eq!(clamp_pic_voltage_cv(1850).unwrap(), 1850);
        assert_eq!(clamp_pic_voltage_cv(1800).unwrap(), 1800);
        assert_eq!(clamp_pic_voltage_cv(2100).unwrap(), 2100);
        assert!(clamp_pic_voltage_cv(1799).is_err());
        assert!(clamp_pic_voltage_cv(2101).is_err());
        assert!(clamp_pic_voltage_cv(1450).is_err());
        assert!(clamp_pic_voltage_cv(1370).is_err());
        assert_eq!(S17_BRING_UP_FREQ_MHZ, 500);
        assert_eq!(S17_BRING_UP_VOLTAGE_CV, 1850);
    }

    // ---- EEPROM denylist ---------------------------------------------------

    #[test]
    fn eeprom_write_denylist_is_50_through_57() {
        assert_eq!(
            S17_EEPROM_WRITE_DENYLIST,
            [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]
        );
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(
            production.contains("S17_EEPROM_WRITE_DENYLIST"),
            "the denylist contract must stay referenced at the wire boundary"
        );
    }

    // ---- power ordering ------------------------------------------------------

    #[test]
    fn power_up_order_matches_the_stock_flow() {
        let labels: Vec<&str> = S17_POWER_UP_ORDER.iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            vec![
                "soc_fpga_init",
                "scan_chains",
                "gpio907_power_on",
                "init_pic",
                "working_voltage",
                "set_chip_addresses",
                "baud_switch",
                "frequency_init",
            ]
        );
        let orders: Vec<u8> = S17_POWER_UP_ORDER.iter().map(|s| s.order()).collect();
        assert_eq!(orders, (0u8..8).collect::<Vec<_>>());
    }

    #[test]
    fn power_down_order_is_reverse_safe_off_last_steps() {
        let labels: Vec<&str> = S17_POWER_DOWN_ORDER.iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            vec![
                "frequency_stop",
                "hashboard_release_sleep",
                "voltage_down",
                "pic_safe_off",
                "gpio907_power_off",
            ]
        );
        // The PIC SAFE-OFF must precede the hashboard power cut.
        let safe_off_pos = S17_POWER_DOWN_ORDER
            .iter()
            .position(|s| matches!(s, S17PowerDownStep::PicSafeOff))
            .unwrap();
        let power_off_pos = S17_POWER_DOWN_ORDER
            .iter()
            .position(|s| matches!(s, S17PowerDownStep::HashboardPowerOff))
            .unwrap();
        assert!(safe_off_pos < power_off_pos);
        // Frequency stop is the first thing down.
        assert!(matches!(
            S17_POWER_DOWN_ORDER[0],
            S17PowerDownStep::FrequencyStop
        ));
    }

    // ---- work codec -----------------------------------------------------------

    #[test]
    fn job_packet_is_146_bytes_with_four_padded_midstates() {
        let midstates = [[0xAAu8; 32]];
        let packet = build_bm1397_job_packet(
            0x07,
            &midstates,
            0x1234_5678,
            0xFFFF_001D,
            0x6789_ABCD,
            [0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();
        assert_eq!(packet.len(), 146);
        assert_eq!(packet[0], 0x07); // job id
        assert_eq!(packet[1], 1); // num_midstates
        assert_eq!(packet[2..6], 0x1234_5678u32.to_le_bytes());
        assert_eq!(packet[6..10], 0xFFFF_001Du32.to_le_bytes());
        assert_eq!(packet[10..14], 0x6789_ABCDu32.to_le_bytes());
        assert_eq!(packet[14..18], [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(packet[18..50], [0xAA; 32]); // midstate 0
        assert_eq!(packet[50..146], [0x00; 96]); // zero-padded slots 1-3
    }

    #[test]
    fn job_packet_refuses_empty_and_overflowing_midstate_sets() {
        assert!(build_bm1397_job_packet(0, &[], 0, 0, 0, [0; 4]).is_err());
        let five = [[0u8; 32]; 5];
        assert!(build_bm1397_job_packet(0, &five, 0, 0, 0, [0; 4]).is_err());
        assert_eq!(BM1397_JOB_HEADER, 0x21);
        assert_eq!(BM1397_MIDSTATE_SLOTS, 4);
    }

    #[test]
    fn job_id_advances_plus_four_mod_128() {
        assert_eq!(next_bm1397_job_id(0), 4);
        assert_eq!(next_bm1397_job_id(4), 8);
        assert_eq!(next_bm1397_job_id(124), 0); // wraps mod 128
        let mut id = 0u8;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            seen.insert(id);
            id = next_bm1397_job_id(id);
        }
        assert_eq!(seen.len(), 32); // full 4-stride cycle
    }

    #[test]
    fn nonce_chip_address_decoding_matches_the_driver() {
        // nonce bits [24:17] carry the chip address (drivers/bm1397.rs).
        let nonce = (0x2Au32 << 17) | 0x1234;
        assert_eq!(bm1397_chip_addr_from_nonce(nonce), 0x2A);
        assert_eq!(bm1397_chip_index_from_nonce(nonce, 5), 8); // 42/5
        assert_eq!(bm1397_chip_index_from_nonce(nonce, 3), 14); // 42/3
    }

    #[test]
    fn no_bip320_reconstruction_in_the_bm1397_lane() {
        // 4-midstate AsicBoost, not chip-side BIP320 version rolling.
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("bip320_reconstruct"));
        assert!(!production.contains("BIP320_VERSION_ROLLING_MASK"));
    }

    // ---- env guard --------------------------------------------------------------

    fn env(
        fast_uart: bool,
        serial: bool,
        skip_init: bool,
        degraded: bool,
        energize: bool,
    ) -> S17RecipeEnv {
        S17RecipeEnv {
            fast_uart_pll3: fast_uart,
            serial_work_dispatch: serial,
            skip_per_chip_init: skip_init,
            trust_degraded_fw: degraded,
            allow_energize: energize,
        }
    }

    #[test]
    fn recipe_guard_admits_the_proven_default_and_lab_combos() {
        assert!(adjudicate_s17_recipe_from(env(false, false, false, false, false)).is_ok());
        assert!(adjudicate_s17_recipe_from(env(false, false, false, false, true)).is_ok());
        assert!(adjudicate_s17_recipe_from(env(true, false, false, false, true)).is_ok());
        assert!(adjudicate_s17_recipe_from(env(false, true, false, false, true)).is_ok());
    }

    #[test]
    fn recipe_guard_refuses_known_bad_combos() {
        // (1) energize + skipped per-chip init.
        let err = adjudicate_s17_recipe_from(env(false, false, true, false, true)).unwrap_err();
        assert!(err.to_string().contains("chain-collapse"));
        // (2) serial dispatch + skipped per-chip init (no energize needed).
        let err = adjudicate_s17_recipe_from(env(false, true, true, false, false)).unwrap_err();
        assert!(err.to_string().contains("per-chip init pass"));
        // (3) degraded-fw trust + energize.
        let err = adjudicate_s17_recipe_from(env(false, false, false, true, true)).unwrap_err();
        assert!(err.to_string().contains("lab-only"));
    }

    // ---- fail-closed executor -------------------------------------------------

    fn ok(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }

    #[test]
    fn set_voltage_is_deferred_until_five_stable_heartbeats() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x82, 0x00, 0x00]));
        for _ in 0..10 {
            wire.replies.push_back(ok(&[0x16, 0x01]));
        }
        wire.replies.push_back(ok(&[0x10, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 1, wire);
        assert!(executor.probe_firmware().is_ok());

        // Four heartbeats are not enough (rule #24).
        for _ in 0..4 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0xA0).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // The fifth stable heartbeat admits it, at 0x21 for chain 1.
        executor.heartbeat().unwrap();
        executor.set_voltage_code(0xA0).unwrap();
        let (addr, last) = executor.wire.log.last().unwrap();
        assert_eq!(last, &dspic_g2a_set_voltage_frame(0xA0));
        assert_eq!(*addr, 0x21);
    }

    #[test]
    fn degraded_dspic_firmware_is_refused_unless_lab_trusted() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x86, 0x00, 0x00])); // fw=0x86
        for _ in 0..8 {
            wire.replies.push_back(ok(&[0x16, 0x01]));
        }
        wire.replies.push_back(ok(&[0x10, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        assert_eq!(
            executor.probe_firmware().unwrap(),
            S17PicFirmwareState::DegradedDspic
        );
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0xA0).unwrap_err();
        assert!(err.to_string().contains("0x86"));

        // Lab-only override still works (read-path lab session).
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x86, 0x00, 0x00]));
        for _ in 0..8 {
            wire.replies.push_back(ok(&[0x16, 0x01]));
        }
        wire.replies.push_back(ok(&[0x10, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire)
            .with_trust_degraded_fw(true);
        executor.probe_firmware().unwrap();
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        assert!(executor.set_voltage_code(0xA0).is_ok());
    }

    #[test]
    fn pic16_loader_mode_is_always_refused_and_never_jumped() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0xCC])); // loader-mode version reply
        for _ in 0..8 {
            wire.replies.push_back(ok(&[0x16]));
        }
        wire.replies.push_back(ok(&[0x10]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bRaw, 2, wire);
        assert_eq!(
            executor.probe_firmware().unwrap(),
            S17PicFirmwareState::LoaderMode
        );
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0x5A).unwrap_err();
        assert!(err.to_string().contains("loader mode"));
        // No JUMP (0x06) / RESET (0x07) / ERASE (0x09) opcode was ever sent.
        for (_, frame) in &executor.wire.log {
            assert_ne!(frame.get(2), Some(&0x06));
            assert_ne!(frame.get(2), Some(&0x07));
            assert_ne!(frame.get(2), Some(&0x09));
        }
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("jump_to_app"));
        assert!(!production.contains("pic_reset"));
    }

    #[test]
    fn unprobed_firmware_refuses_voltage_even_after_heartbeats() {
        let mut wire = MockS17PicWire::default();
        for _ in 0..8 {
            wire.replies.push_back(ok(&[0x16, 0x01]));
        }
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0xA0).unwrap_err();
        assert!(err.to_string().contains("not probed"));
    }

    #[test]
    fn missing_set_voltage_reply_fails_closed() {
        // Exactly the probe + five heartbeat acks; the SET transaction then has
        // no scripted reply left, so the wire is silent (fail-closed teardown).
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x82, 0x00, 0x00]));
        for _ in 0..5 {
            wire.replies.push_back(ok(&[0x16, 0x01]));
        }
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        executor.probe_firmware().unwrap();
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        assert!(executor.set_voltage_code(0xA0).is_err());
    }

    #[test]
    fn safe_off_is_always_available_and_first_in_teardown() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x15, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        executor.safe_off().unwrap();
        let (addr, frame) = &executor.wire.log[0];
        assert_eq!(*addr, 0x20);
        assert_eq!(frame, &dspic_g2a_safe_off_frame());
    }

    #[test]
    fn heartbeat_retry_is_bounded() {
        let mut wire = MockS17PicWire::default(); // no replies at all
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bRaw, 0, wire);
        let err = executor.heartbeat_bounded(3).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(executor.wire.log.len(), 3, "exactly the bounded attempts");
    }

    #[test]
    fn malformed_version_replies_fail_closed() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x99, 0x98]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        assert!(executor.probe_firmware().is_err());

        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x17, 0x82])); // PIC16 expects exactly 1 byte
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bRaw, 0, wire);
        assert!(executor.probe_firmware().is_err());
    }
}
