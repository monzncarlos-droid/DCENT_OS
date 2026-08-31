//! SYSCTL facts — silicon-revision evidence and peripheral clock gates.
//!
//! Source: S1 `lib/drivers/include/sysctl.h` (the `sysctl_t` struct's
//! numbered offsets: No. 0 `git_id` @ 0x00, No. 1 `clk_freq` @ 0x04, No. 11
//! `clk_en_peri` @ 0x2c, with the `sysctl_clk_en_peri_t` bitfield order)
//! and S1 `lib/drivers/uarths.c` (the UARTHS divisor consumes
//! `sysctl_clock_get_freq(SYSCTL_CLOCK_CPU)`). BSP_PLAN §0: record `git_id`
//! and `clk_freq` in every boot log as silicon-revision evidence.
//!
//! Phase A performs **zero sysctl writes** — these are read/query facts
//! only (BSP_PLAN §1 row 3: mutation waits for UART/SPI enable needs).

/// Git short commit id register, read-only (S1 `sysctl_t` No. 0).
pub const REG_GIT_ID: u64 = 0x00;
/// System clock base frequency register (S1 `sysctl_t` No. 1).
pub const REG_CLK_FREQ: u64 = 0x04;
/// Peripheral clock-enable register (S1 `sysctl_t` No. 11, offset 0x2c).
pub const REG_CLK_EN_PERI: u64 = 0x2C;

/// Absolute address of the `git_id` register.
#[must_use]
pub const fn git_id_addr(base: u64) -> u64 {
    base + REG_GIT_ID
}

/// Absolute address of the `clk_freq` register.
#[must_use]
pub const fn clk_freq_addr(base: u64) -> u64 {
    base + REG_CLK_FREQ
}

/// Absolute address of the `clk_en_peri` register.
#[must_use]
pub const fn clk_en_peri_addr(base: u64) -> u64 {
    base + REG_CLK_EN_PERI
}

/// `clk_en_peri` bit positions, from the S1 `sysctl_clk_en_peri_t`
/// bitfield order (bit N = the Nth field).
pub mod clk_en_peri {
    /// WDT0 APB clock enable (25th field = bit 24).
    pub const WDT0: u32 = 1 << 24;
    /// WDT1 APB clock enable (26th field = bit 25).
    pub const WDT1: u32 = 1 << 25;
    /// FPIOA APB clock enable (21st field = bit 20).
    pub const FPIOA: u32 = 1 << 20;
}

/// Whether the WDT0 APB clock is enabled in a `clk_en_peri` word.
#[must_use]
pub const fn wdt0_clock_enabled(clk_en_peri_word: u32) -> bool {
    clk_en_peri_word & clk_en_peri::WDT0 != 0
}

/// Whether the WDT1 APB clock is enabled in a `clk_en_peri` word.
#[must_use]
pub const fn wdt1_clock_enabled(clk_en_peri_word: u32) -> bool {
    clk_en_peri_word & clk_en_peri::WDT1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsp::SYSCTL_BASE;

    #[test]
    fn register_offsets_match_the_pinned_struct() {
        assert_eq!(git_id_addr(SYSCTL_BASE), 0x5044_0000);
        assert_eq!(clk_freq_addr(SYSCTL_BASE), 0x5044_0004);
        assert_eq!(clk_en_peri_addr(SYSCTL_BASE), 0x5044_002C);
    }

    #[test]
    fn wdt_clock_enable_bits_decode() {
        assert!(wdt0_clock_enabled(1 << 24));
        assert!(!wdt0_clock_enabled(0));
        assert!(!wdt0_clock_enabled(1 << 25));
        assert!(wdt1_clock_enabled(1 << 25));
        assert!(!wdt1_clock_enabled(1 << 24));
        // Reset-style word with many enables at once.
        let word = (1 << 24) | (1 << 20) | 1;
        assert!(wdt0_clock_enabled(word));
        assert!(!wdt1_clock_enabled(word));
    }
}
