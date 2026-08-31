// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentrald-avalon-asic :: industrial hashboard MCU mux
//
// Wave 3.2 (2026-08-05): the multi-hashboard TCA9546A I2C mux that the crate
// header (`lib.rs`) and `main.rs:145` recorded as "deferred" — landed here
// (BESIDE the shared `include!`, per that header's instruction), as the crate's
// industrial-only extension over the shared single-chain shim.
//
// SCOPE: this module is the PURE LOGIC layer only — control-byte computation,
// channel/register maps, and the board-temperature decode. It does NOT open
// `/dev/i2c-0` or drive hardware; the live I2C transaction (open, `i2c_write_cs`
// the control byte, read the MCU register) is wired by the industrial K230 HAL
// once a bench unit validates it, exactly as the rest of this crate gates
// hardware behind proven logic. That keeps the mining path unaffected and makes
// every constant here unit-testable on the host.
//
// ⚠️ LICENSE WARNING (2026-08-05): `Canaan-Creative/Avalon_mm` (`big/`+`little/mm_miner/`)
// is **BUSL-1.1**, NOT GPL — commercial production use needs a separate Canaan license
// (4-yr cliff to GPLv3); only `little/cgminer/` is BSD-3-Clause. Flagged "a major footgun
// for D-Central" in `AVALON_MM_K230_INDUSTRIAL_RE.md:7`. The constants below are hardware
// register/GPIO/temp-decode FACTS (believed uncopyrightable), transcribed for interop —
// OPERATOR LEGAL REVIEW required before shipping in GPL-3.0 DCENT_OS.
//
// GROUND TRUTH — every constant is transcribed byte-exact from Canaan-Creative
// `Avalon_mm/little/mm_miner/platform/hash_mcu.{c,h}` (BUSL-1.1). Nothing is inferred:
//   hash_mcu.h:20 TCA9546A_ADDR 0x70 · :21-24 HASH0..3_ADDR 0x10 · :25 READ_LEN 3
//   :26 MCU_VER_LEN 4 · :29 T_COEF 0.0625 · :33 REG_VER 0x00 · :34 REG_TMP_BOARD_OUT 0x15
//   :35 REG_TMP_BOARD_IN 0x16 · :36 REG_HASH_GETSN 0x20 · :37 SN_LEN 40
//   hash_mcu.c:69 `channl = 1 << m` · :49 temp_12bit_complement · :100 hashmcu_info_get
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

#![allow(dead_code)] // pure logic layer; consumed by the K230 industrial HAL once bench-validated.

/// TCA9546A 4-channel I2C mux 7-bit address (`hash_mcu.h:20`).
pub const TCA9546A_ADDR: u8 = 0x70;

/// Per-hashboard MCU 7-bit address behind the mux — identical on every channel
/// (`hash_mcu.h:21-24`, all four `HASHn_ADDR` = `0x10`); the mux channel, not
/// the address, distinguishes the boards.
pub const HASH_MCU_ADDR: u8 = 0x10;

/// The industrial line carries four hashboards (`board_hw/A15_AC/`, RE doc §
/// "4 x hashboard"), one per mux channel.
pub const HASHBOARD_COUNT: u8 = 4;

// MCU register map (`hash_mcu.h:33-37`).
/// Version register; value carries an `'a'`/`'h'` magic byte (`hash_mcu.c:163`).
pub const REG_VER: u8 = 0x00;
/// Board outlet temperature (12-bit signed, ×`T_COEF`).
pub const REG_TMP_BOARD_OUT: u8 = 0x15;
/// Board inlet temperature (12-bit signed, ×`T_COEF`).
pub const REG_TMP_BOARD_IN: u8 = 0x16;
/// 40-byte serial-number register.
pub const REG_HASH_GETSN: u8 = 0x20;

/// Serial-number length in bytes (`hash_mcu.h:37`).
pub const SN_LEN: usize = 40;
/// MCU version payload length (`hash_mcu.h:26`).
pub const MCU_VER_LEN: usize = 4;
/// Register read length for temp/version words (`hash_mcu.h:25`).
pub const READ_LEN: usize = 3;
/// Temperature coefficient — °C per LSB (`hash_mcu.h:29`).
pub const T_COEF: f32 = 0.0625;

/// TCA9546A control byte that routes I2C to exactly `channel` (0..3) and
/// disables the others. Mirrors `channl = 1 << m` (`hash_mcu.c:69`).
///
/// Returns `None` for an out-of-range channel (fail-closed — never selects a
/// non-existent board or a wrong bitmask).
pub fn channel_select_byte(channel: u8) -> Option<u8> {
    if channel < HASHBOARD_COUNT {
        Some(1u8 << channel)
    } else {
        None
    }
}

/// Control byte that disables all downstream channels (safe/idle state).
pub const DISABLE_ALL_CHANNELS: u8 = 0x00;

/// The exact 12-bit signed decode from `hash_mcu.c:49 temp_12bit_complement`.
///
/// Transcribed operation-for-operation from the firmware (NOT "standard 12-bit
/// two's complement" — the vendor routine has a deliberate quirk at `0x800`,
/// which this reproduces byte-exact so our reading matches the miner's).
pub fn temp_12bit_complement(raw: u16) -> i16 {
    let mut temp: i16 = (raw & 0x0fff) as i16;
    if temp & 0x0800 != 0 {
        temp &= 0x07ff;
        temp = !temp;
        temp = temp.wrapping_add(1);
        temp &= 0x07ff;
        temp = -temp;
    }
    temp
}

/// Decode a raw board-temperature register word to °C
/// (`hash_mcu.c:114/117`: `temp_12bit_complement(value) * T_COEF`).
pub fn decode_board_temp_c(raw: u16) -> f32 {
    temp_12bit_complement(raw) as f32 * T_COEF
}

/// A `REG_HASH_GETSN` read is [`SN_LEN`] = 40 bytes. Per `hash_mcu.c:138-145`,
/// an **all-`0xFF`** payload means the MCU carries no programmed serial → the
/// firmware treats it as invalid and zeroes it. `true` == no valid SN present.
pub fn sn_is_all_invalid(raw: &[u8; SN_LEN]) -> bool {
    raw.iter().all(|&b| b == 0xff)
}

/// The MCU version read is `MCU_VER_LEN + 1` = 5 bytes (`hash_mcu.c:161`).
pub const MCU_VER_READ_LEN: usize = MCU_VER_LEN + 1;

/// Validate an MCU version read: byte 0 is an XOR checksum over the next four
/// (`hash_mcu.c:167`: `checksum = (tmp[1]^tmp[2]) ^ (tmp[3]^tmp[4])`, must equal
/// `tmp[0]`). Fail-closed — a bad checksum means the read is rejected.
pub fn version_checksum_ok(ver: &[u8; MCU_VER_READ_LEN]) -> bool {
    ver[0] == (ver[1] ^ ver[2]) ^ (ver[3] ^ ver[4])
}

// ── Per-board reset GPIO map (K230, `board_gpio.c:22-31,39-44`) ──
//
// The mux itself has a reset line, and each hashboard MCU has its own reset +
// bootloader-select (BSL) line. These are K230 GPIO numbers; the actual
// gpio-drive is the industrial HAL's job (gated), so this is a pure map.

/// K230 GPIO for the TCA9546A `RESET_N` line, held HIGH in normal operation
/// (`board_gpio.c:22`, released HIGH in `board_gpio_init`).
pub const I2C_MUX_RESET_N_GPIO: u32 = 6;

/// Per-hashboard MCU reset GPIO, indexed by channel 0..3
/// (`board_gpio.c:24-30` HASH0..3_MCU_RST → `hb_reset_map`).
pub const HB_MCU_RESET_GPIO: [u32; 4] = [30, 20, 28, 62];

/// Per-hashboard MCU bootloader-select (BSL) GPIO, indexed by channel 0..3
/// (`board_gpio.c:25-31` HASH0..3_MCU_BSL → `hb_bsl_map`).
pub const HB_MCU_BSL_GPIO: [u32; 4] = [31, 21, 29, 63];

/// MCU reset pulse timing (`hash_mcu.c:43-46`): drive the reset GPIO LOW, hold
/// [`HB_RESET_ASSERT_US`], drive HIGH, then settle [`HB_RESET_SETTLE_US`].
/// Active-LOW pulse.
pub const HB_RESET_ASSERT_US: u32 = 1_000; // 1 ms
pub const HB_RESET_SETTLE_US: u32 = 10_000; // 10 ms

/// The per-board MCU reset GPIO for `channel` (0..3), fail-closed for any other.
pub fn hb_mcu_reset_gpio(channel: u8) -> Option<u32> {
    HB_MCU_RESET_GPIO.get(channel as usize).copied()
}

/// The ordered I²C operations to read one MCU register on a specific hashboard,
/// via the mux. The industrial K230 HAL executes these against `/dev/i2c-0`
/// (the pure "what to write/read" layer; this crate does not touch hardware).
///
/// Mirrors `hash_mcu.c`: `i2c_write_cs(TCA9546A_ADDR, 1<<m)` then
/// `i2c_read(HASH_MCU_ADDR, reg, .., len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McuReadPlan {
    /// Write `mux_ctrl` to `mux_addr` (0x70) to route to the target board.
    pub mux_addr: u8,
    pub mux_ctrl: u8,
    /// Then read `read_len` bytes of register `reg` from the MCU at `mcu_addr` (0x10).
    pub mcu_addr: u8,
    pub reg: u8,
    pub read_len: usize,
}

/// Compose the [`McuReadPlan`] for reading `reg` (`read_len` bytes) on hashboard
/// `channel` (0..3). Fail-closed (`None`) for an out-of-range channel — never
/// emits a plan that would select a non-existent board.
pub fn plan_mcu_register_read(channel: u8, reg: u8, read_len: usize) -> Option<McuReadPlan> {
    let mux_ctrl = channel_select_byte(channel)?;
    Some(McuReadPlan {
        mux_addr: TCA9546A_ADDR,
        mux_ctrl,
        mcu_addr: HASH_MCU_ADDR,
        reg,
        read_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_select_is_one_hot_and_fail_closed() {
        // `1 << m` for the four real channels (hash_mcu.c:69).
        assert_eq!(channel_select_byte(0), Some(0b0001));
        assert_eq!(channel_select_byte(1), Some(0b0010));
        assert_eq!(channel_select_byte(2), Some(0b0100));
        assert_eq!(channel_select_byte(3), Some(0b1000));
        // Fail-closed: no board 4+, never a wrong/overflowing bitmask.
        assert_eq!(channel_select_byte(4), None);
        assert_eq!(channel_select_byte(255), None);
        assert_eq!(DISABLE_ALL_CHANNELS, 0x00);
    }

    #[test]
    fn register_and_addr_map_matches_open_source_firmware() {
        // hash_mcu.h byte-exact.
        assert_eq!(TCA9546A_ADDR, 0x70);
        assert_eq!(HASH_MCU_ADDR, 0x10);
        assert_eq!(HASHBOARD_COUNT, 4);
        assert_eq!(
            (REG_VER, REG_TMP_BOARD_OUT, REG_TMP_BOARD_IN, REG_HASH_GETSN),
            (0x00, 0x15, 0x16, 0x20)
        );
        assert_eq!((SN_LEN, MCU_VER_LEN, READ_LEN), (40, 4, 3));
        assert_eq!(T_COEF, 0.0625);
    }

    #[test]
    fn temp_decode_is_byte_exact_to_the_vendor_routine() {
        // Hand-computed by running hash_mcu.c's temp_12bit_complement:
        assert_eq!(temp_12bit_complement(0x000), 0); //   0
        assert_eq!(temp_12bit_complement(0x100), 256); // +256 LSB
        assert_eq!(temp_12bit_complement(0x190), 400); // +400 LSB
        assert_eq!(temp_12bit_complement(0xfff), -1); //  -1 LSB
        assert_eq!(temp_12bit_complement(0xc00), -1024);
        assert_eq!(temp_12bit_complement(0x801), -2047);
        // The vendor quirk: 0x800 decodes to 0 (NOT -2048 that "standard" 2c gives).
        assert_eq!(temp_12bit_complement(0x800), 0);
        // °C conversion (× T_COEF = 0.0625):
        assert_eq!(decode_board_temp_c(0x190), 25.0); // 400 * 0.0625
        assert_eq!(decode_board_temp_c(0x100), 16.0); // 256 * 0.0625
        assert_eq!(decode_board_temp_c(0xfff), -0.0625);
        assert_eq!(decode_board_temp_c(0xc00), -64.0);
    }

    #[test]
    fn sn_all_ff_is_invalid_else_valid() {
        // hash_mcu.c:138-145 — all-0xFF => no programmed SN.
        assert!(sn_is_all_invalid(&[0xff; SN_LEN]));
        let mut s = [0xff; SN_LEN];
        s[7] = b'A'; // one real byte => valid
        assert!(!sn_is_all_invalid(&s));
        assert!(!sn_is_all_invalid(&[0u8; SN_LEN]));
    }

    #[test]
    fn version_checksum_matches_vendor_xor() {
        assert_eq!(MCU_VER_READ_LEN, 5);
        // hash_mcu.c:167 — tmp[0] == (tmp[1]^tmp[2]) ^ (tmp[3]^tmp[4]).
        // 1^2^3^4 = 4, so byte0 must be 4.
        assert!(version_checksum_ok(&[4, 1, 2, 3, 4]));
        assert!(version_checksum_ok(&[0, 0, 0, 0, 0]));
        // Fail-closed on a wrong checksum byte.
        assert!(!version_checksum_ok(&[0, 1, 2, 3, 4]));
        assert!(!version_checksum_ok(&[5, 1, 2, 3, 4]));
    }

    #[test]
    fn reset_gpio_map_matches_board_gpio_source() {
        // board_gpio.c:22-31 byte-exact.
        assert_eq!(I2C_MUX_RESET_N_GPIO, 6);
        assert_eq!(HB_MCU_RESET_GPIO, [30, 20, 28, 62]);
        assert_eq!(HB_MCU_BSL_GPIO, [31, 21, 29, 63]);
        // Per-channel accessor, fail-closed past channel 3.
        assert_eq!(hb_mcu_reset_gpio(0), Some(30));
        assert_eq!(hb_mcu_reset_gpio(3), Some(62));
        assert_eq!(hb_mcu_reset_gpio(4), None);
        // Active-low pulse timing (hash_mcu.c:43-46).
        assert_eq!((HB_RESET_ASSERT_US, HB_RESET_SETTLE_US), (1_000, 10_000));
    }

    #[test]
    fn mcu_read_plan_composes_the_mux_then_read_transaction() {
        // Read the outlet temp (0x15, READ_LEN bytes) on hashboard 2.
        let plan = plan_mcu_register_read(2, REG_TMP_BOARD_OUT, READ_LEN).unwrap();
        assert_eq!(
            plan,
            McuReadPlan {
                mux_addr: 0x70,
                mux_ctrl: 0b0100, // 1 << 2
                mcu_addr: 0x10,
                reg: 0x15,
                read_len: 3,
            }
        );
        // SN read on board 0.
        let sn = plan_mcu_register_read(0, REG_HASH_GETSN, SN_LEN).unwrap();
        assert_eq!((sn.mux_ctrl, sn.reg, sn.read_len), (0b0001, 0x20, 40));
        // Fail-closed: no plan for a non-existent board.
        assert_eq!(plan_mcu_register_read(4, REG_VER, 5), None);
    }
}
