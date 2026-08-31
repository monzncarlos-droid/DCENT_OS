//! FPIOA pin-multiplexer facts (48 pads x function select + IO driving).
//!
//! Source: S1 `lib/drivers/include/fpioa.h` (Apache-2.0 facts, pinned commit
//! `02576ba67e8797444f3ee3f34c625b5ed048e707`) — `FPIOA_NUM_IO`, the
//! `fpioa_io_config_t` bitfield layout, and the `fpioa_function_t` enum
//! values verified by grep at that commit. Per S2 every peripheral signal
//! reaches a pad only through the FPIOA.

/// Number of FPIOA pads (S1 `fpioa.h` `FPIOA_NUM_IO` = 48).
pub const NUM_PADS: u8 = 48;

/// Each pad owns one 32-bit configuration register, four bytes apart
/// (S1 `fpioa.h` `fpioa_t` = `fpioa_io_config_t io[48]`, packed aligned 4).
pub const PAD_REGISTER_BYTES: u64 = 4;

/// Absolute address of a pad's configuration register. `None` for pads the
/// SoC does not have.
#[must_use]
pub const fn pad_config_addr(base: u64, pad: u8) -> Option<u64> {
    if pad < NUM_PADS {
        Some(base + PAD_REGISTER_BYTES * pad as u64)
    } else {
        None
    }
}

/// A validated FPIOA pad index, 0..=47 (SoC fact, S1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FpioaPad(u8);

impl FpioaPad {
    /// Accepts only pads the SoC actually has.
    pub const fn new(pad: u8) -> Option<Self> {
        if pad < NUM_PADS {
            Some(Self(pad))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }
}

/// A function-select code vendored from the S1 `fpioa_function_t` enum.
///
/// Only codes whose numeric values were verified by grep at the pinned
/// commit are constructible; anything else fails closed (`from_code`
/// returns `None`). The full SoC table has 256 encodings — unvendored
/// codes are deliberately unreachable until a need is reviewed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FpioaFunction(u8);

impl FpioaFunction {
    /// JTAG test pins (S1: `FUNC_JTAG_TCLK..TDO` = 0..=3; the SoC boot
    /// contract §1.5 notes IO_0..IO_3 default to these after reset).
    pub const JTAG_TCLK: Self = Self(0);
    pub const JTAG_TDI: Self = Self(1);
    pub const JTAG_TMS: Self = Self(2);
    pub const JTAG_TDO: Self = Self(3);
    /// High-speed UART receiver/transmitter (S1: 18/19). This is the ROM
    /// ISP console peripheral.
    pub const UARTHS_RX: Self = Self(18);
    pub const UARTHS_TX: Self = Self(19);
    /// High-speed GPIO 0..=31 (S1: `FUNC_GPIOHS0..31` = 24..=55).
    pub const GPIOHS0: Self = Self(24);
    pub const GPIOHS31: Self = Self(55);
    /// APB GPIO 0..=7 (S1: `FUNC_GPIO0..7` = 56..=63).
    pub const GPIO0: Self = Self(56);
    pub const GPIO7: Self = Self(63);
    /// UART1 receiver/transmitter (S1: 64/65).
    pub const UART1_RX: Self = Self(64);
    pub const UART1_TX: Self = Self(65);

    /// GPIOHS function code for index 0..=31 (S1: 24 + n).
    #[must_use]
    pub const fn gpiohs(index: u8) -> Option<Self> {
        if index < 32 {
            Some(Self(24 + index))
        } else {
            None
        }
    }

    /// GPIOHS index encoded by this function code, if it is one.
    #[must_use]
    pub const fn gpiohs_index(self) -> Option<u8> {
        let code = self.0;
        if code >= 24 && code <= 55 {
            Some(code - 24)
        } else {
            None
        }
    }

    /// APB GPIO function code for index 0..=7 (S1: 56 + n).
    #[must_use]
    pub const fn gpio(index: u8) -> Option<Self> {
        if index < 8 {
            Some(Self(56 + index))
        } else {
            None
        }
    }

    /// Accepts only vendored code ranges (fail closed on the rest).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0..=3 => Some(Self(code)),
            18 | 19 => Some(Self(code)),
            24..=55 => Some(Self(code)),
            56..=63 => Some(Self(code)),
            64 | 65 => Some(Self(code)),
            _ => None,
        }
    }

    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }
}

/// The writable fields of one pad's 32-bit configuration register, exactly
/// as documented by S1 `fpioa_io_config_t` (field names preserved).
///
/// The reserved bits and the read-only `pad_di` (current input level) are
/// never encoded here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PadIoConfig {
    /// Bits [7:0]: channel (function) select.
    pub ch_sel: u8,
    /// Bits [11:8]: driving selector, 0..=15 (S1 `fpioa_driving_t`
    /// `FPIOA_DRIVING_0..15`).
    pub ds: u8,
    /// Bit 12: static output enable.
    pub oe_en: bool,
    /// Bit 13: invert output enable.
    pub oe_inv: bool,
    /// Bit 14: data output select (0 = DO, 1 = OE).
    pub do_sel: bool,
    /// Bit 15: invert data output select result.
    pub do_inv: bool,
    /// Bit 16: pull-up enable.
    pub pu: bool,
    /// Bit 17: pull-down enable.
    pub pd: bool,
    /// Bit 19: slew-rate control enable.
    pub sl: bool,
    /// Bit 20: static input enable.
    pub ie_en: bool,
    /// Bit 21: invert input enable.
    pub ie_inv: bool,
    /// Bit 22: invert data input.
    pub di_inv: bool,
    /// Bit 23: Schmitt trigger.
    pub st: bool,
}

impl PadIoConfig {
    /// Encodes into the 32-bit pad register word. `None` if a field is out
    /// of its documented range (`ds` > 15) or both pull resistors are
    /// requested. The pinned SDK labels PU+PD as undefined, so it fails closed.
    #[must_use]
    pub const fn encode(self) -> Option<u32> {
        if self.ds > 15 || (self.pu && self.pd) {
            return None;
        }
        let mut word: u32 = self.ch_sel as u32;
        word |= (self.ds as u32) << 8;
        word |= (self.oe_en as u32) << 12;
        word |= (self.oe_inv as u32) << 13;
        word |= (self.do_sel as u32) << 14;
        word |= (self.do_inv as u32) << 15;
        word |= (self.pu as u32) << 16;
        word |= (self.pd as u32) << 17;
        word |= (self.sl as u32) << 19;
        word |= (self.ie_en as u32) << 20;
        word |= (self.ie_inv as u32) << 21;
        word |= (self.di_inv as u32) << 22;
        word |= (self.st as u32) << 23;
        Some(word)
    }

    /// Decodes the writable fields of a pad register word.
    #[must_use]
    pub const fn decode(word: u32) -> Self {
        Self {
            ch_sel: (word & 0xFF) as u8,
            ds: ((word >> 8) & 0xF) as u8,
            oe_en: (word & (1 << 12)) != 0,
            oe_inv: (word & (1 << 13)) != 0,
            do_sel: (word & (1 << 14)) != 0,
            do_inv: (word & (1 << 15)) != 0,
            pu: (word & (1 << 16)) != 0,
            pd: (word & (1 << 17)) != 0,
            sl: (word & (1 << 19)) != 0,
            ie_en: (word & (1 << 20)) != 0,
            ie_inv: (word & (1 << 21)) != 0,
            di_inv: (word & (1 << 22)) != 0,
            st: (word & (1 << 23)) != 0,
        }
    }

    /// Pure-input configuration for a pad whose function is selected but
    /// must never drive (phase-A posture for any read-only assignment).
    #[must_use]
    pub const fn input_only(function: FpioaFunction) -> Self {
        Self {
            ch_sel: function.code(),
            ds: 0,
            oe_en: false,
            oe_inv: false,
            do_sel: false,
            do_inv: false,
            pu: false,
            pd: false,
            sl: false,
            ie_en: true,
            ie_inv: false,
            di_inv: false,
            st: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsp::FPIOA_BASE;

    #[test]
    fn pad_address_math_covers_exactly_48_pads() {
        assert_eq!(pad_config_addr(FPIOA_BASE, 0), Some(FPIOA_BASE));
        assert_eq!(pad_config_addr(FPIOA_BASE, 1), Some(FPIOA_BASE + 4));
        assert_eq!(pad_config_addr(FPIOA_BASE, 47), Some(FPIOA_BASE + 0xBC));
        assert_eq!(pad_config_addr(FPIOA_BASE, 48), None);
        assert_eq!(pad_config_addr(FPIOA_BASE, 255), None);
    }

    #[test]
    fn vendored_function_codes_match_the_pinned_enum() {
        assert_eq!(FpioaFunction::JTAG_TCLK.code(), 0);
        assert_eq!(FpioaFunction::JTAG_TDO.code(), 3);
        assert_eq!(FpioaFunction::UARTHS_RX.code(), 18);
        assert_eq!(FpioaFunction::UARTHS_TX.code(), 19);
        assert_eq!(FpioaFunction::GPIOHS0.code(), 24);
        assert_eq!(FpioaFunction::GPIOHS31.code(), 55);
        assert_eq!(FpioaFunction::GPIO0.code(), 56);
        assert_eq!(FpioaFunction::GPIO7.code(), 63);
        assert_eq!(FpioaFunction::UART1_RX.code(), 64);
        assert_eq!(FpioaFunction::UART1_TX.code(), 65);
    }

    #[test]
    fn function_codes_fail_closed_outside_vendored_ranges() {
        assert_eq!(FpioaFunction::from_code(17), None);
        assert_eq!(FpioaFunction::from_code(20), None);
        assert_eq!(FpioaFunction::from_code(66), None);
        assert_eq!(FpioaFunction::from_code(255), None);
        assert!(FpioaFunction::from_code(24).is_some());
        assert!(FpioaFunction::from_code(65).is_some());
    }

    #[test]
    fn gpiohs_function_round_trip() {
        assert_eq!(FpioaFunction::gpiohs(0), Some(FpioaFunction::GPIOHS0));
        assert_eq!(FpioaFunction::gpiohs(31), Some(FpioaFunction::GPIOHS31));
        assert_eq!(FpioaFunction::gpiohs(32), None);
        assert_eq!(FpioaFunction::GPIOHS0.gpiohs_index(), Some(0));
        assert_eq!(FpioaFunction::GPIOHS31.gpiohs_index(), Some(31));
        assert_eq!(FpioaFunction::UARTHS_RX.gpiohs_index(), None);
    }

    #[test]
    fn pad_io_config_encodes_documented_bit_positions() {
        let all = PadIoConfig {
            ch_sel: 19,
            ds: 15,
            oe_en: true,
            oe_inv: true,
            do_sel: true,
            do_inv: true,
            pu: true,
            pd: false,
            sl: true,
            ie_en: true,
            ie_inv: true,
            di_inv: true,
            st: true,
        };
        let word = all.encode().unwrap();
        assert_eq!(word & 0xFF, 19);
        assert_eq!((word >> 8) & 0xF, 15);
        assert_eq!(word & (1 << 16), 1 << 16);
        assert_eq!(word & (1 << 17), 0);
        assert_eq!(word >> 24, 0, "bits 24..=31 must stay clear");
        assert_eq!(PadIoConfig::decode(word), all);
    }

    #[test]
    fn pad_io_config_rejects_oversized_drive_and_reserves_bit18() {
        let bad = PadIoConfig {
            ds: 16,
            ..PadIoConfig::default()
        };
        assert_eq!(bad.encode(), None);
        let undefined_pulls = PadIoConfig {
            pu: true,
            pd: true,
            ..PadIoConfig::default()
        };
        assert_eq!(undefined_pulls.encode(), None);
        let word = PadIoConfig::input_only(FpioaFunction::UARTHS_TX)
            .encode()
            .unwrap();
        assert_eq!(word & 0xFF, 19);
        assert_eq!(word & (1 << 18), 0, "reserved bit 18 must stay clear");
        assert_eq!(word & (1 << 31), 0, "read-only pad_di must stay clear");
        assert!(word & (1 << 20) != 0, "input enable");
        assert!(word & (1 << 23) != 0, "schmitt trigger");
    }

    #[test]
    fn pads_validate() {
        assert_eq!(FpioaPad::new(47).map(FpioaPad::index), Some(47));
        assert_eq!(FpioaPad::new(48), None);
    }
}
