//! S9 SE / BM1393 VIL frame builders (desk-only).
//!
//! Stock `cgminer_1393` + S9k `asic.c` speak BM139x VIL + software CRC5.
//! This module packs those frames. It does **not** write FPGA BC buffers,
//! open UART, or admit a transport.
//!
//! Evidence: .

/// `set_address` (`buf[0] = 64`).
pub const HDR_SET_ADDR: u8 = 0x40;
/// Write-register, single chip.
pub const HDR_WRITE_SINGLE: u8 = 0x41;
/// Read-register, single chip.
pub const HDR_READ_SINGLE: u8 = 0x42;
/// Write-register, broadcast.
pub const HDR_WRITE_ALL: u8 = 0x51;
/// Read-register, broadcast.
pub const HDR_READ_ALL: u8 = 0x52;
/// `chain_inactive` VIL (`buf[0] = 83`).
pub const HDR_INACTIVE_ALL: u8 = 0x53;

pub const VIL_LEN_SHORT: u8 = 5;
pub const VIL_LEN_SET_CONFIG: u8 = 9;

pub const CRC5_POLY: u8 = 0x05;
pub const CRC5_INIT: u8 = 0x1F;
pub const CRC5_SHORT_BITS: u32 = 27;
pub const CRC5_VIL_SHORT_BITS: u32 = 32;
pub const CRC5_VIL_SET_CONFIG_BITS: u32 = 64;

/// W11.10 catalog treated these FPGA AXI *offsets* as UART opcodes.
pub const FPGA_OFFSETS_NOT_UART: &[u8] = &[0xC0, 0xC4, 0xC8, 0xCC, 0x30, 0x34, 0x80, 0x1C];

/// Issue #2 live BC word0: last-chip read at addr `0x78`.
pub const ISSUE2_CAPTURED_SHORT_FRAME: [u8; 4] = [0x42, 0x05, 0x78, 0x1C];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeVilError {
    FpgaOffsetIsNotUartOpcode { observed: u8 },
    HeaderNotVil,
    CrcMismatch { expected: u8, observed: u8 },
}

/// Bit-serial CRC5 (MSB-first). `nbits` is Bitmain `CRC5(buf, n)`.
pub fn crc5_bits(data: &[u8], nbits: u32) -> u8 {
    let mut crc = CRC5_INIT;
    for i in 0..nbits {
        let byte = data.get((i / 8) as usize).copied().unwrap_or(0);
        let bit_index = 7 - (i % 8);
        let input_bit = (byte >> bit_index) & 1;
        let crc_top = (crc >> 4) & 1;
        crc = (crc << 1) & 0x1F;
        if input_bit ^ crc_top != 0 {
            crc ^= CRC5_POLY;
        }
    }
    crc
}

/// Refuse the W11.10 FPGA-offset-as-opcode catalog.
pub fn refuse_fpga_offset_as_uart_opcode(byte: u8) -> Result<(), S9SeVilError> {
    if FPGA_OFFSETS_NOT_UART.contains(&byte) {
        return Err(S9SeVilError::FpgaOffsetIsNotUartOpcode { observed: byte });
    }
    Ok(())
}

/// Non-VIL 4-byte short frame: CRC5 over 27 bits (issue #2 capture class).
pub fn pack_short_nonvil(header: u8, addr: u8) -> Result<[u8; 4], S9SeVilError> {
    refuse_fpga_offset_as_uart_opcode(header)?;
    if !is_known_vil_header(header) {
        return Err(S9SeVilError::HeaderNotVil);
    }
    let mut frame = [header, VIL_LEN_SHORT, addr, 0];
    frame[3] = crc5_bits(&frame[..3], CRC5_SHORT_BITS);
    Ok(frame)
}

/// VIL 5-byte short frame: CRC5 over 32 bits (`set_address` / `chain_inactive`).
pub fn pack_vil_short(header: u8, addr: u8) -> Result<[u8; 5], S9SeVilError> {
    refuse_fpga_offset_as_uart_opcode(header)?;
    if !is_known_vil_header(header) {
        return Err(S9SeVilError::HeaderNotVil);
    }
    let mut frame = [header, VIL_LEN_SHORT, addr, 0, 0];
    frame[4] = crc5_bits(&frame[..4], CRC5_VIL_SHORT_BITS);
    Ok(frame)
}

pub fn pack_chain_inactive_vil() -> [u8; 5] {
    pack_vil_short(HDR_INACTIVE_ALL, 0).expect("0x53 is a VIL header")
}

pub fn pack_set_address_vil(addr: u8) -> [u8; 5] {
    pack_vil_short(HDR_SET_ADDR, addr).expect("0x40 is a VIL header")
}

pub fn pack_read_single_nonvil(addr: u8) -> [u8; 4] {
    pack_short_nonvil(HDR_READ_SINGLE, addr).expect("0x42 is a VIL header")
}

/// VIL set-config 9-byte: type/write/single `0x41`, CRC5 over 64 bits.
pub fn pack_set_config_single(chip_addr: u8, reg: u8, value: u32) -> [u8; 9] {
    pack_set_config(false, chip_addr, reg, value)
}

/// VIL set-config 9-byte broadcast (`0x51`, S9k `set_config_BM1393` `mode!=0`).
pub fn pack_set_config_all(chip_addr: u8, reg: u8, value: u32) -> [u8; 9] {
    pack_set_config(true, chip_addr, reg, value)
}

pub fn pack_set_config(broadcast: bool, chip_addr: u8, reg: u8, value: u32) -> [u8; 9] {
    let v = value.to_be_bytes();
    let header = if broadcast {
        HDR_WRITE_ALL
    } else {
        HDR_WRITE_SINGLE
    };
    let mut frame = [
        header,
        VIL_LEN_SET_CONFIG,
        chip_addr,
        reg,
        v[0],
        v[1],
        v[2],
        v[3],
        0,
    ];
    frame[8] = crc5_bits(&frame[..8], CRC5_VIL_SET_CONFIG_BITS);
    frame
}

pub fn admit_issue2_captured_short_frame() -> Result<(), S9SeVilError> {
    let expected = pack_read_single_nonvil(0x78);
    if expected != ISSUE2_CAPTURED_SHORT_FRAME {
        return Err(S9SeVilError::CrcMismatch {
            expected: expected[3],
            observed: ISSUE2_CAPTURED_SHORT_FRAME[3],
        });
    }
    Ok(())
}

fn is_known_vil_header(header: u8) -> bool {
    matches!(
        header,
        HDR_SET_ADDR
            | HDR_WRITE_SINGLE
            | HDR_READ_SINGLE
            | HDR_WRITE_ALL
            | HDR_READ_ALL
            | HDR_INACTIVE_ALL
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue2_capture_is_27bit_crc5() {
        admit_issue2_captured_short_frame().unwrap();
        assert_eq!(crc5_bits(&[0x42, 0x05, 0x78], 24), 0x11);
        assert_ne!(crc5_bits(&[0x42, 0x05, 0x78], 24), 0x1C);
    }

    #[test]
    fn fpga_offsets_are_refused_as_headers() {
        for b in FPGA_OFFSETS_NOT_UART {
            assert!(refuse_fpga_offset_as_uart_opcode(*b).is_err());
            assert!(pack_short_nonvil(*b, 0).is_err());
        }
        refuse_fpga_offset_as_uart_opcode(HDR_READ_SINGLE).unwrap();
    }

    #[test]
    fn vil_inactive_is_32bit_crc5() {
        let frame = pack_chain_inactive_vil();
        assert_eq!(frame[0], 0x53);
        assert_eq!(frame[1], 5);
        assert_eq!(frame[4], crc5_bits(&frame[..4], 32));
    }

    #[test]
    fn set_address_vil_is_5_bytes() {
        let frame = pack_set_address_vil(0x78);
        assert_eq!(frame[0], 0x40);
        assert_eq!(frame[2], 0x78);
        assert_eq!(frame[4], crc5_bits(&frame[..4], 32));
    }

    #[test]
    fn set_config_is_9_bytes_64bit_crc5() {
        let frame = pack_set_config_single(0x00, 0x00, 0);
        assert_eq!(frame[0], HDR_WRITE_SINGLE);
        assert_eq!(frame[1], 9);
        assert_eq!(frame.len(), 9);
        assert_eq!(frame[8], crc5_bits(&frame[..8], 64));
        let all = pack_set_config_all(0, 0x18, 0x3A01);
        assert_eq!(all[0], HDR_WRITE_ALL);
        assert_eq!(all[3], 0x18);
    }
}
