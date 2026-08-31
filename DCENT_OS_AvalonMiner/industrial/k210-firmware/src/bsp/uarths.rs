//! UARTHS (high-speed UART) facts — the ROM ISP console peripheral.
//!
//! Source: S1 `lib/drivers/include/uarths.h` (register offsets
//! `UARTHS_REG_*`, `uarths_{txdata,rxdata,txctrl,rxctrl,ie,ip,div}_t`
//! bitfields) and S1 `lib/drivers/uarths.c` (`uarths_init`/`uarths_config`
//! divisor math `div = input_clock / baud - 1`, input clock =
//! `sysctl_clock_get_freq(SYSCTL_CLOCK_CPU)`). Base `0x38000000` per S1
//! `platform.h`; the boot contract §1.4 documents it as the 115200 8N1 ROM
//! ISP transport. Five-megabaud-class TL UART with an 8-entry TX FIFO (S2).

/// TX data register (write data, read FIFO-full status).
pub const REG_TXDATA: u64 = 0x00;
/// RX data register (read data, read FIFO-empty status).
pub const REG_RXDATA: u64 = 0x04;
/// TX control register.
pub const REG_TXCTRL: u64 = 0x08;
/// RX control register.
pub const REG_RXCTRL: u64 = 0x0C;
/// Interrupt-enable register.
pub const REG_IE: u64 = 0x10;
/// Interrupt-pending register.
pub const REG_IP: u64 = 0x14;
/// Baud-rate divisor register.
pub const REG_DIV: u64 = 0x18;

/// `txdata` bits [7:0] hold the byte to send (S1 `uarths_txdata_t`).
pub const TXDATA_DATA_MASK: u32 = 0xFF;
/// `txdata` bit 31 reads as FIFO-full; poll before writing (S1).
pub const TXDATA_FULL: u32 = 1 << 31;
/// `rxdata` bit 31 reads as FIFO-empty (S1 `uarths_rxdata_t`).
pub const RXDATA_EMPTY: u32 = 1 << 31;

/// `txctrl` bit 0: TX enable (S1 `uarths_txctrl_t.txen`, `UARTHS_TXEN`).
pub const TXCTRL_TXEN: u32 = 1 << 0;
/// `txctrl` bit 1: number of stop bits — 0 means one stop bit (S1
/// `uarths_txctrl_t.nstop`).
pub const TXCTRL_NSTOP: u32 = 1 << 1;
/// `txctrl` bits [18:16]: TX watermark threshold (S1 `uarths_txctrl_t.txcnt`).
pub const TXCTRL_TXCNT_SHIFT: u32 = 16;

/// `div` holds a 16-bit divisor (S1 `uarths_div_t.div`).
pub const DIV_MAX: u32 = 0xFFFF;

/// Baud divisor per S1 `uarths.c`: `div = input_hz / baud - 1` (so the
/// effective rate is `input_hz / (div + 1)`).
///
/// Returns `None` (fail closed) when `baud` is zero, the input clock cannot
/// reach it, or the divisor exceeds the 16-bit register.
#[must_use]
pub const fn divisor(input_hz: u32, baud: u32) -> Option<u16> {
    if baud == 0 {
        return None;
    }
    let quotient = input_hz / baud;
    if quotient == 0 {
        return None;
    }
    let div = quotient - 1;
    if div > DIV_MAX {
        return None;
    }
    Some(div as u16)
}

/// Effective baud for a divisor (`input_hz / (div + 1)`), for diagnostics.
#[must_use]
pub const fn effective_baud(input_hz: u32, div: u16) -> u32 {
    input_hz / (div as u32 + 1)
}

/// Encodes a `txctrl` word: TX enable, stop-bit count, watermark. Watermarks
/// wider than the documented three-bit field fail closed.
#[must_use]
pub const fn txctrl_word(txen: bool, two_stop_bits: bool, txcnt: u8) -> Option<u32> {
    if txcnt > 7 {
        return None;
    }
    let mut word = 0_u32;
    if txen {
        word |= TXCTRL_TXEN;
    }
    if two_stop_bits {
        word |= TXCTRL_NSTOP;
    }
    word |= (txcnt as u32) << TXCTRL_TXCNT_SHIFT;
    Some(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_offsets_match_the_pinned_header() {
        assert_eq!(REG_TXDATA, 0x00);
        assert_eq!(REG_RXDATA, 0x04);
        assert_eq!(REG_TXCTRL, 0x08);
        assert_eq!(REG_RXCTRL, 0x0C);
        assert_eq!(REG_IE, 0x10);
        assert_eq!(REG_IP, 0x14);
        assert_eq!(REG_DIV, 0x18);
    }

    #[test]
    fn divisor_follows_the_sdk_formula() {
        // uarths.c: div = freq / baud - 1.
        assert_eq!(divisor(115_200, 115_200), Some(0));
        assert_eq!(divisor(230_400, 115_200), Some(1));
        // 390 MHz SDK-default CPU clock (BSP_PLAN §0) at 115200:
        // 390_000_000 / 115_200 = 3385 -> div 3384.
        assert_eq!(divisor(390_000_000, 115_200), Some(3384));
        assert_eq!(effective_baud(390_000_000, 3384), 390_000_000 / 3385);
    }

    #[test]
    fn divisor_fails_closed() {
        assert_eq!(divisor(390_000_000, 0), None);
        // Input clock below the requested baud would underflow.
        assert_eq!(divisor(115_199, 115_200), None);
        // Divisor wider than the 16-bit register.
        assert_eq!(divisor(2_000_000_000, 9_600), None);
        assert_eq!(divisor(4_000_000_000, 9_600), None);
    }

    #[test]
    fn sixteen_bit_divisor_boundary_is_exact() {
        // div == 0xFFFF must be accepted, 0x1_0000 must not.
        assert_eq!(divisor(6_553_600, 100), Some(0xFFFF));
        assert_eq!(divisor(6_553_700, 100), None);
    }

    #[test]
    fn txctrl_encoding_matches_documented_bits() {
        assert_eq!(txctrl_word(true, false, 0), Some(TXCTRL_TXEN));
        assert_eq!(
            txctrl_word(true, true, 7),
            Some(TXCTRL_TXEN | TXCTRL_NSTOP | (7 << 16))
        );
        assert_eq!(txctrl_word(false, false, 0), Some(0));
        assert_eq!(txctrl_word(true, false, 8), None);
    }
}
