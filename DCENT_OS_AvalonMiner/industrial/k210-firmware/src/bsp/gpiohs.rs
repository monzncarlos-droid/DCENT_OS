//! GPIOHS (high-speed GPIO) facts — banked registers, bit per pin.
//!
//! Source: S1 `lib/drivers/include/gpiohs.h` (offset defines
//! `GPIOHS_INPUT_VAL..GPIOHS_OUTPUT_XOR`) and S1
//! `lib/drivers/gpiohs.c` — the controller is banked SiFive-style: one
//! 32-bit register per function where **bit n is GPIOHS pin n**
//! (`get_gpio_bit(gpiohs->input_val.u32, pin)` with the 32-entry
//! `pin_instance[]` table). Each GPIOHS pin has its own PLIC source
//! 34..=65 (BSP_PLAN §0 from S1 `plic.h`).
//!
//! Phase A deliberately vendors **input reads only**: there is no
//! output-enable or output-value encoding helper here, so no amount of
//! profile data can turn this module into an output driver (BSP_PLAN §1
//! row 5: outputs wait for phase D).

/// Input values: bit n = level of GPIOHS pin n (S1 offset 0x00).
pub const REG_INPUT_VAL: u64 = 0x00;
/// Input enables (not vendored for writing; documented for completeness).
pub const REG_INPUT_EN: u64 = 0x04;
/// Output enables — phase D territory, never written in phase A.
pub const REG_OUTPUT_EN: u64 = 0x08;
/// Output values — phase D territory, never written in phase A.
pub const REG_OUTPUT_VAL: u64 = 0x0C;

/// Highest GPIOHS pin index (S1 `gpiohs.c` `pin_instance[32]`, function
/// codes `FUNC_GPIOHS0..31`).
pub const MAX_PIN: u8 = 31;

/// A validated GPIOHS index, 0..=31 (SoC fact, S1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpiohsIndex(u8);

impl GpiohsIndex {
    pub const fn new(index: u8) -> Option<Self> {
        if index <= MAX_PIN {
            Some(Self(index))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }
}

/// Absolute address of the input-value register.
#[must_use]
pub const fn input_val_addr(base: u64) -> u64 {
    base + REG_INPUT_VAL
}

/// Level of `pin` from a register word. `None` for pins the SoC does not
/// have.
#[must_use]
pub const fn input_level(word: u32, pin: u8) -> Option<bool> {
    if pin <= MAX_PIN {
        Some((word >> pin) & 1 == 1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsp::GPIOHS_BASE;

    #[test]
    fn register_offsets_match_the_pinned_header() {
        assert_eq!(REG_INPUT_VAL, 0x00);
        assert_eq!(REG_INPUT_EN, 0x04);
        assert_eq!(REG_OUTPUT_EN, 0x08);
        assert_eq!(REG_OUTPUT_VAL, 0x0C);
    }

    #[test]
    fn input_levels_decode_bit_per_pin() {
        assert_eq!(input_level(0, 0), Some(false));
        assert_eq!(input_level(1, 0), Some(true));
        assert_eq!(input_level(1 << 31, 31), Some(true));
        assert_eq!(input_level(0xFFFF_FFFF, 15), Some(true));
        assert_eq!(input_level(0, 15), Some(false));
        assert_eq!(input_level(0, 32), None);
    }

    #[test]
    fn addresses_and_indices_validate() {
        assert_eq!(input_val_addr(GPIOHS_BASE), 0x3800_1000);
        assert_eq!(GpiohsIndex::new(31).map(GpiohsIndex::index), Some(31));
        assert_eq!(GpiohsIndex::new(32), None);
    }
}
