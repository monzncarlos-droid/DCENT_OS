//! Watchdog (DW-WDT) facts — stop and kick only in phase A.
//!
//! Source: S1 `lib/drivers/include/wdt.h` (register offsets from the
//! `wdt_t` struct, `WDT_CR_*` / `WDT_TORR_*` / `WDT_CRR_MASK` defines,
//! `WDT_RESET_ALL`/`WDT_RESET_CPU`) and S1 `lib/drivers/wdt.c`
//! (`wdt_disable` = kick then clear the enable bit; `wdt_get_top` /
//! `wdt_init` timeout math). Two units: WDT0 `0x50400000`, WDT1
//! `0x50410000` (S1 `platform.h`; boot contract §1.8). Phase A stops WDT0
//! and never arms either (BSP_PLAN §4: a hung safe-idle is already safe).

/// Control register (enable, response mode, reset pulse length).
pub const REG_CR: u64 = 0x00;
/// Timeout-range register.
pub const REG_TORR: u64 = 0x04;
/// Current counter value (read-only).
pub const REG_CCVR: u64 = 0x08;
/// Counter-restart ("kick") register — write-only.
pub const REG_CRR: u64 = 0x0C;
/// Interrupt status register.
pub const REG_STAT: u64 = 0x10;
/// End-of-interrupt register.
pub const REG_EOI: u64 = 0x14;

/// `cr` bit 0: watchdog enable (S1 `WDT_CR_ENABLE`).
pub const CR_ENABLE: u32 = 0x1;
/// `cr` bit 1: response-mode mask (S1 `WDT_CR_RMOD_MASK`).
pub const CR_RMOD_MASK: u32 = 0x2;
/// Response mode: system reset (S1 `WDT_CR_RMOD_RESET` = 0).
pub const CR_RMOD_RESET: u32 = 0x0;
/// Response mode: interrupt then reset (S1 `WDT_CR_RMOD_INTERRUPT` = 2).
pub const CR_RMOD_INTERRUPT: u32 = 0x2;
/// `cr` bits [4:2]: reset pulse length mask (S1 `WDT_CR_RPL_MASK`).
pub const CR_RPL_MASK: u32 = 0x1C;
/// Writing `0x76` to `crr` restarts the counter (S1 `WDT_CRR_MASK`).
pub const CRR_RESTART: u32 = 0x76;

/// `torr` encodes the same top index into both the initiator and final
/// timeout fields (S1 `WDT_TORR_TOP(x) = (x << 4) | x`).
#[must_use]
pub const fn torr_word(top: u8) -> Option<u32> {
    if top <= 15 {
        Some(((top as u32) << 4) | top as u32)
    } else {
        None
    }
}

/// Control word that keeps every field but the enable bit — exactly S1
/// `wdt.c wdt_disable`'s read-modify-write (`cr &= ~WDT_CR_ENABLE`).
#[must_use]
pub const fn disable_cr_word(current_cr: u32) -> u32 {
    current_cr & !CR_ENABLE
}

/// Whether the control word says the watchdog is running.
#[must_use]
pub const fn is_enabled(cr_word: u32) -> bool {
    cr_word & CR_ENABLE != 0
}

/// `floor(log2(v))` for `v >= 1` (helper for the S1 timeout math).
const fn floor_log2(v: u64) -> u32 {
    63 - v.leading_zeros()
}

/// Timeout top index for a request of `timeout_ms` at a watchdog clock of
/// `wdt_clk_hz`, mirroring S1 `wdt.c wdt_get_top`:
/// `ret = (timeout_ms * wdt_clk / 1000) >> 16;` then `log2`, clamped to
/// `0xF`. A zero or one-cycle request clamps to top index 0.
#[must_use]
pub fn top_index_for(timeout_ms: u64, wdt_clk_hz: u64) -> u8 {
    let scaled = (timeout_ms.saturating_mul(wdt_clk_hz) / 1000) >> 16;
    if scaled <= 1 {
        return 0;
    }
    let top = floor_log2(scaled);
    if top > 15 { 15 } else { top as u8 }
}

/// Counter ticks per watchdog period for a top index, mirroring S1
/// `wdt.c wdt_init`'s return math: period cycles = `1 << (top + 16 + 1)`.
#[must_use]
pub const fn timeout_cycles(top: u8) -> Option<u64> {
    if top > 15 {
        return None;
    }
    Some(1_u64 << (top as u32 + 17))
}

/// Period in milliseconds produced by a top index at `wdt_clk_hz`.
#[must_use]
pub const fn timeout_ms(top: u8, wdt_clk_hz: u64) -> Option<u64> {
    if wdt_clk_hz == 0 {
        return None;
    }
    match timeout_cycles(top) {
        Some(cycles) => Some(cycles * 1000 / wdt_clk_hz),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsp::{WDT0_BASE, WDT1_BASE};

    #[test]
    fn register_offsets_and_constants_match_the_pinned_header() {
        assert_eq!(REG_CR, 0x00);
        assert_eq!(REG_TORR, 0x04);
        assert_eq!(REG_CCVR, 0x08);
        assert_eq!(REG_CRR, 0x0C);
        assert_eq!(REG_STAT, 0x10);
        assert_eq!(REG_EOI, 0x14);
        assert_eq!(CRR_RESTART, 0x76);
        assert_eq!(CR_RMOD_INTERRUPT, 0x2);
        assert_eq!(CR_RPL_MASK, 0x1C);
        assert_eq!(WDT0_BASE + REG_CRR, 0x5040_000C);
        assert_eq!(WDT1_BASE + REG_CR, 0x5041_0000);
    }

    #[test]
    fn disable_word_clears_only_the_enable_bit() {
        let armed = CR_ENABLE | CR_RMOD_INTERRUPT | (0x3 << 2);
        assert_eq!(disable_cr_word(armed), CR_RMOD_INTERRUPT | (0x3 << 2));
        assert!(!is_enabled(disable_cr_word(armed)));
        assert!(is_enabled(armed));
        assert_eq!(disable_cr_word(0), 0);
    }

    #[test]
    fn torr_encodes_both_timeout_fields() {
        assert_eq!(torr_word(0), Some(0));
        assert_eq!(torr_word(5), Some((5 << 4) | 5));
        assert_eq!(torr_word(15), Some(0xFF));
        assert_eq!(torr_word(16), None);
    }

    #[test]
    fn timeout_math_mirrors_the_sdk() {
        // wdt_get_top(1000 ms, 10 MHz): (1000 * 10_000_000 / 1000) >> 16
        // = 152 -> log2 -> 7.
        assert_eq!(top_index_for(1000, 10_000_000), 7);
        // wdt_init period for top 7 at 10 MHz: 2^24 cycles = 1677 ms.
        assert_eq!(timeout_cycles(7), Some(1 << 24));
        assert_eq!(timeout_ms(7, 10_000_000), Some(1677));
        // Monotonicity and the 0xF clamp.
        assert!(top_index_for(10_000, 10_000_000) > top_index_for(1_000, 10_000_000));
        assert_eq!(top_index_for(u64::MAX, 10_000_000), 15);
        assert_eq!(top_index_for(0, 10_000_000), 0);
        assert_eq!(timeout_ms(0, 0), None);
        assert_eq!(timeout_cycles(16), None);
        assert_eq!(timeout_ms(16, 10_000_000), None);
    }
}
