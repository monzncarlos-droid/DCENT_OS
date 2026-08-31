//! CLINT (core-local interruptor) facts — the safety monotonic tick.
//!
//! Source: S1 `lib/drivers/include/clint.h` — map documented in that
//! header: `msip` for core N at `0x02000000 + 4*N`, `mtimecmp` for core N
//! at `0x02004000 + 8*N`, shared `mtime` at `0x0200BFF8`;
//! `CLINT_NUM_CORES = 2`; the mtime tick is the input clock divided by
//! `CLINT_CLOCK_DIV = 50` (S1). BSP_PLAN §0 and §4: `mtime` is the only
//! time source the safety supervisor trusts.

/// Offset of the `msip` region (S1 `CLINT_MSIP`).
pub const MSIP_OFFSET: u64 = 0x0000;
/// Stride of one core's `msip` register (S1 `CLINT_MSIP_SIZE`).
pub const MSIP_STRIDE: u64 = 4;
/// Offset of the `mtimecmp` region (S1 `CLINT_MTIMECMP`).
pub const MTIMECMP_OFFSET: u64 = 0x4000;
/// Stride of one core's 64-bit `mtimecmp` register (S1
/// `CLINT_MTIMECMP_SIZE`).
pub const MTIMECMP_STRIDE: u64 = 8;
/// Offset of the shared 64-bit `mtime` counter (S1 `CLINT_MTIME`).
pub const MTIME_OFFSET: u64 = 0xBFF8;
/// Implemented cores (S1 `CLINT_NUM_CORES`).
pub const NUM_CORES: u32 = 2;
/// mtime increments once per 50 input clock cycles (S1 `CLINT_CLOCK_DIV`).
pub const CLOCK_DIV: u32 = 50;

/// Address of core `hart`'s software-interrupt register.
#[must_use]
pub const fn msip_addr(base: u64, hart: u32) -> Option<u64> {
    if hart < NUM_CORES {
        Some(base + MSIP_OFFSET + MSIP_STRIDE * hart as u64)
    } else {
        None
    }
}

/// Address of core `hart`'s 64-bit timer-compare register.
#[must_use]
pub const fn mtimecmp_addr(base: u64, hart: u32) -> Option<u64> {
    if hart < NUM_CORES {
        Some(base + MTIMECMP_OFFSET + MTIMECMP_STRIDE * hart as u64)
    } else {
        None
    }
}

/// Address of the shared 64-bit monotonic counter.
#[must_use]
pub const fn mtime_addr(base: u64) -> u64 {
    base + MTIME_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsp::CLINT_BASE;

    #[test]
    fn clint_map_matches_the_pinned_header() {
        assert_eq!(msip_addr(CLINT_BASE, 0), Some(0x0200_0000));
        assert_eq!(msip_addr(CLINT_BASE, 1), Some(0x0200_0004));
        assert_eq!(mtimecmp_addr(CLINT_BASE, 0), Some(0x0200_4000));
        assert_eq!(mtimecmp_addr(CLINT_BASE, 1), Some(0x0200_4008));
        assert_eq!(mtime_addr(CLINT_BASE), 0x0200_BFF8);
        assert_eq!(msip_addr(CLINT_BASE, 2), None);
        assert_eq!(mtimecmp_addr(CLINT_BASE, 4095), None);
    }

    #[test]
    fn documented_divisor_is_recorded() {
        assert_eq!(CLOCK_DIV, 50);
        assert_eq!(NUM_CORES, 2);
    }
}
