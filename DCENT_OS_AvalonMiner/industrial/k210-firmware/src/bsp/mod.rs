//! Vendored K210 SoC register facts (BSP Phase A, `docs/BSP_PLAN.md` §1).
//!
//! Every base address, register offset, and bit layout below is a *fact*
//! transcribed from public documentation — no vendor code is copied:
//!
//! - **S1** — Kendryte standalone SDK, Apache-2.0, pinned commit
//!   `02576ba67e8797444f3ee3f34c625b5ed048e707`, files
//!   `lib/bsp/include/platform.h`,
//!   `lib/drivers/include/{fpioa,uarths,gpiohs,clint,wdt,sysctl}.h`, and
//!   `lib/drivers/{uarths,wdt,gpiohs,fpioa}.c`.
//! - **S2** — Kendryte K210 datasheet, `en/003.md` (public).
//! - **Contract** —
//!   K210_SOC_BOOT_FLASH_ISP_CONTRACT.md` (desk-verified boot/ISP/SRAM map).
//!
//! This module tree is entirely pure math and constants. The policy core's
//! `#![forbid(unsafe_code)]` is untouched: volatile MMIO access lives only in
//! the explicitly emulator-only `dcent-k210-renode-console` binary, confined
//! to one documented `unsafe` module. The physical Phase-A runtime performs
//! zero MMIO. No Avalon A1246 board pin is claimed anywhere in this tree — every
//! board assignment is a PENDING-DISCOVERY placeholder owned by
//! [`profile`]. Addresses are `u64` so the same code host-tests and
//! cross-builds for `riscv64gc`.

pub mod clint;
pub mod fpioa;
pub mod gpiohs;
pub mod hexfmt;
pub mod profile;
pub mod sysctl;
pub mod uarths;
pub mod wdt;

/// CLINT base (S1 `platform.h` `CLINT_BASE_ADDR`).
pub const CLINT_BASE: u64 = 0x0200_0000;
/// PLIC base (S1 `platform.h` `PLIC_BASE_ADDR`).
pub const PLIC_BASE: u64 = 0x0C00_0000;
/// High-speed UART (UARTHS) base, TileLink bus (S1 `platform.h`
/// `UARTHS_BASE_ADDR`; contract §1.4 confirms it is the ROM ISP transport).
pub const UARTHS_BASE: u64 = 0x3800_0000;
/// High-speed GPIO (GPIOHS) base, TileLink bus (S1 `platform.h`
/// `GPIOHS_BASE_ADDR`).
pub const GPIOHS_BASE: u64 = 0x3800_1000;
/// FPIOA pin mux base, APB1 (S1 `platform.h` `FPIOA_BASE_ADDR`).
pub const FPIOA_BASE: u64 = 0x502B_0000;
/// Watchdog 0 base, APB2 (S1 `platform.h` `WDT0_BASE_ADDR`; contract §1.8).
pub const WDT0_BASE: u64 = 0x5040_0000;
/// Watchdog 1 base, APB2 (S1 `platform.h` `WDT1_BASE_ADDR`). Phase A never
/// touches WDT1 (BSP_PLAN §4 keeps it unassigned by default).
pub const WDT1_BASE: u64 = 0x5041_0000;
/// System controller base, APB2 (S1 `platform.h` `SYSCTL_BASE_ADDR`).
pub const SYSCTL_BASE: u64 = 0x5044_0000;
/// ROM load base / cached general SRAM start (S1 `platform.h`
/// `RAM_BASE_ADDR`; contract §1.7 — 6 MiB general + 2 MiB AI SRAM).
pub const RAM_BASE: u64 = 0x8000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_bases_match_the_pinned_sdk_platform_header() {
        assert_eq!(CLINT_BASE, 0x0200_0000);
        assert_eq!(PLIC_BASE, 0x0C00_0000);
        assert_eq!(UARTHS_BASE, 0x3800_0000);
        assert_eq!(GPIOHS_BASE, 0x3800_1000);
        assert_eq!(FPIOA_BASE, 0x502B_0000);
        assert_eq!(WDT0_BASE, 0x5040_0000);
        assert_eq!(WDT1_BASE, 0x5041_0000);
        assert_eq!(SYSCTL_BASE, 0x5044_0000);
        assert_eq!(RAM_BASE, 0x8000_0000);
    }
}
