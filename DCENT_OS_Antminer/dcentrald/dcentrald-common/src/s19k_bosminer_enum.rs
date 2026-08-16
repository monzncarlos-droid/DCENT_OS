//! `a lab unit` bosminer enum fault — live `read_register(reg=0x0)` contract.
//!
//! Does not open UART. Pins what Braiins *expected* vs what it *got* on
//! this SKU so 8/77 is not confused with parser silence or a 3M FastUART miss.

/// BHB56902 / S19k AML chip count Braiins demands on `a lab unit`.
pub const S19K_BHB56902_CHIP_COUNT: u32 = 77;
/// Register Braiins reads during hashchain init (`read_register(reg=0x0)`).
pub const S19K_78_ENUM_REG: u8 = 0x00;
/// First live CHAIN/1 window: 8 replies, address `0x02` missing (interval 2).
pub const S19K_78_CHAIN1_GOT: u32 = 8;
pub const S19K_78_CHAIN1_MISSING_ADDR: u8 = 0x02;
/// CHAIN/2 and CHAIN/3 first window: zero replies, address `0x00` missing.
pub const S19K_78_CHAIN23_GOT: u32 = 0;
pub const S19K_78_CHAIN23_MISSING_ADDR: u8 = 0x00;
/// EEPROM average frequency label. Not a PLL write and not FastUART proof.
pub const S19K_78_EEPROM_FREQ_MHZ: u32 = 670;
/// `a lab unit` `bosminer.log.before` has **zero** `Set baud rate` lines.
pub const S19K_78_BOSMINER_SET_BAUD_LINES: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosminerEnumFault {
    pub chain: Option<u8>,
    pub got: u32,
    pub expected: u32,
    pub missing_addr: u8,
    pub reg: u8,
}

/// Parse `Hashchip: number of responses N of read_register(reg=0x0) doesn't match chip count 77: reply 0x2 missing`.
pub fn parse_s19k_bosminer_enum_fault(line: &str) -> Option<S19kBosminerEnumFault> {
    let chain = line
        .split("CHAIN/")
        .nth(1)
        .and_then(|s| s.chars().next())
        .and_then(|c| c.to_digit(10))
        .map(|n| n as u8);
    let after_resp = line.split("number of responses ").nth(1)?;
    let got: u32 = after_resp.split(' ').next()?.parse().ok()?;
    let after_reg = line.split("read_register(reg=0x").nth(1)?;
    let reg = u8::from_str_radix(after_reg.split(')').next()?, 16).ok()?;
    let after_count = line.split("chip count ").nth(1)?;
    let expected: u32 = after_count.split(':').next()?.trim().parse().ok()?;
    let after_reply = line.split("reply 0x").nth(1)?;
    let missing_addr = u8::from_str_radix(after_reply.split(' ').next()?, 16).ok()?;
    Some(S19kBosminerEnumFault {
        chain,
        got,
        expected,
        missing_addr,
        reg,
    })
}

pub fn admit_s19k_78_chain1_enum(fault: S19kBosminerEnumFault) -> Result<(), &'static str> {
    if fault.expected != S19K_BHB56902_CHIP_COUNT {
        return Err("enum expected chip count is not BHB56902 77");
    }
    if fault.reg != S19K_78_ENUM_REG {
        return Err("enum register is not read_register(0x0)");
    }
    if fault.got != S19K_78_CHAIN1_GOT {
        return Err("CHAIN/1 first window is 8 replies, not this count");
    }
    if fault.missing_addr != S19K_78_CHAIN1_MISSING_ADDR {
        return Err("CHAIN/1 missing address is 0x02 (interval 2), not this addr");
    }
    Ok(())
}

/// 8/77 with `0x02` missing is a short enum, not UART parser silence.
pub fn refuse_s19k_78_enum_shortfall_as_parser_silence(
    fault: S19kBosminerEnumFault,
) -> Result<(), &'static str> {
    if fault.got > 0 && fault.got < fault.expected {
        return Err(
            "partial read_register(0x0) replies are a short enum, not a parser/framing fault",
        );
    }
    Ok(())
}

/// : `reply 0x2 missing` is **consistent** with interval 2, not a proof.
/// The formatter only names the first absent reply address. Linear 0,1,2,…
/// would also emit `0x2` if chip 2 were missing. Interval 2 stays desk-11g.
pub fn refuse_reply_0x2_missing_as_interval_proof(missing_addr: u8) -> Result<(), &'static str> {
    if missing_addr == S19K_78_CHAIN1_MISSING_ADDR {
        return Err(
            "reply 0x2 missing is consistent with interval 2 but does not prove the formatter uses it",
        );
    }
    Ok(())
}

/// `a lab unit` bosminer log never printed `Set baud rate`. Do not invent 3M chip FastUART from it.
pub fn refuse_s19k_78_bosminer_log_as_fastuart_proof(
    set_baud_line_count: usize,
) -> Result<(), &'static str> {
    if set_baud_line_count == 0 {
        return Err(
            ".78 bosminer.log has 0 Set baud rate lines; refuse as S19k chip FastUART / 3M proof",
        );
    }
    Ok(())
}

/// 670 MHz is the EEPROM hashrate-table label, not the PLL0 write we must emit.
pub fn refuse_eeprom_670mhz_as_pll0_write(mhz: u32) -> Result<(), &'static str> {
    if mhz == S19K_78_EEPROM_FREQ_MHZ {
        return Err("670 MHz is BHB56902 EEPROM average label, not a proven PLL0 write");
    }
    Ok(())
}

pub fn count_s19k_bosminer_set_baud_lines(log: &str) -> usize {
    log.matches("Set baud rate").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN1: &str = "2025-12-04T23:25:59.598135Z  WARN bosminer_backend::hashchain: CHAIN/1: Init failed: Hashchip: number of responses 8 of read_register(reg=0x0) doesn't match chip count 77: reply 0x2 missing";
    const CHAIN2: &str = "2025-12-04T23:25:59.592320Z  WARN bosminer_backend::hashchain: CHAIN/2: Init failed: Hashchip: number of responses 0 of read_register(reg=0x0) doesn't match chip count 77: reply 0x0 missing";

    #[test]
    fn parse_78_chain1_is_8_of_77_missing_0x2() {
        let f = parse_s19k_bosminer_enum_fault(CHAIN1).expect("parse");
        assert_eq!(f.chain, Some(1));
        assert_eq!(f.got, 8);
        assert_eq!(f.expected, 77);
        assert_eq!(f.missing_addr, 0x02);
        assert_eq!(f.reg, 0x00);
        assert!(admit_s19k_78_chain1_enum(f).is_ok());
        assert!(refuse_s19k_78_enum_shortfall_as_parser_silence(f).is_err());
        let f2 = parse_s19k_bosminer_enum_fault(CHAIN2).expect("parse");
        assert_eq!(f2.chain, Some(2));
        assert_eq!(f2.got, 0);
        assert_eq!(f2.missing_addr, 0x00);
        assert!(refuse_s19k_78_bosminer_log_as_fastuart_proof(0).is_err());
        assert!(refuse_s19k_78_bosminer_log_as_fastuart_proof(1).is_ok());
        assert!(refuse_eeprom_670mhz_as_pll0_write(670).is_err());
        assert!(refuse_eeprom_670mhz_as_pll0_write(400).is_ok());
        assert_eq!(count_s19k_bosminer_set_baud_lines("no baud here"), 0);
        assert_eq!(S19K_BHB56902_CHIP_COUNT, 77);
        assert_eq!(S19K_78_ENUM_REG, 0);
        assert!(refuse_reply_0x2_missing_as_interval_proof(0x02).is_err());
        assert!(refuse_reply_0x2_missing_as_interval_proof(0x00).is_ok());
        let rx = crate::s19k_bm1366_uart_rx::expected_rx_after(
            crate::s19k_bm1366_uart_rx::S19kRxExpectedAfter::GetAddress,
        );
        assert!(rx.contains("77"));
        assert!(rx.contains("read_register"));
    }
}
