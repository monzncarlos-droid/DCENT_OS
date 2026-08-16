//! BM1393 protocol reference (S9k / S9 SE).
//!
//! **This module is reference-only.** It is not wired into
//! [`crate::drivers::ChipRegistry`]. `0x1393` stays undriveable on the
//! production `am1-s9` (BM1387) path until a dedicated `am1-s9se` /
//! C43 profile exists.
//!
//! ## What this file is *not*
//!
//! The W11.10 catalog treated RE2 §8.3's "14 UART opcodes"
//! (`BC_WRITE=0xC0`, `TW_WRITE=0x40`, `IIC=0x30`, …) as ASIC commands
//! and left `BM1393_CRC8_POLY_TBD`. That was wrong. Those bytes are
//! **stock-FPGA AXI register offsets** (already in
//! `dcentrald_hal::stock_fpga`). GitHub
//! [DCENT_OS#2](https://github.com/DCentralTech/DCENT_OS/issues/2)
//! (live S9 SE, 2026-08-15) and the firmware RE in
//!
//! close it.
//!
//! ## Wire protocol (validated)
//!
//! BM1393 speaks the BM139x VIL command set — the same headers as
//! `drivers/bm139x.rs` — with **software CRC5** (poly `x^5+x^2+1` =
//! `0x05`, init `0b11111`), **not** CRC8 and **not** BM1387 HW-CRC:
//!
//! | header | meaning | VIL length |
//! |--------|---------|------------|
//! | `0x40` | set_address | 5 (CRC5 over 32 bits) |
//! | `0x41` | write single | 9 (CRC5 over 64 bits) |
//! | `0x42` | read single | 5 |
//! | `0x51` | write all | 9 |
//! | `0x53` | chain_inactive | 5 |
//!
//! Short (non-VIL) frames use CRC5 over **27 bits**. The #2 capture
//! `0xC4 = 0x4205781c` → `42 05 78 1c` reproduces bit-exact as 27-bit
//! CRC5 of `[0x42, 0x05, 0x78]`.
//!
//! FPGA path: `set_BC_command_buffer` writes `axi[49..51]` =
//! `0xC4/0xC8/0xCC`; `set_BC_write_command` writes `axi[48]` = `0xC0`.
//!
//! ## Evidence
//!
//! - Downloaded HiveOS S9 SE stock+client
//!   (`S9se-stock-plus-hive-client.tar.gz`, sha256
//!   `b5609be2…274d46`); inner ramdisk `usr/bin/cgminer` sha256
//!   `e113eab6…c9fb`, opkg source `cgminer_1393` branch `CE`.
//! - Held S9k `cgminer.dec` (`chain_inactive@132F0`,
//!   `read_asic_register@13EB8`, `set_address@13508`,
//!   `set_BC_command_buffer@45DE8`, `open_core_bm1393@21C12`,
//!   `get_power_iic_value_from_voltage@3B710`,
//!   `statusServiceThread@732A6`).
//! - Live report: 3×60 chips, last addr `0x78`, `open_core_bm1393`,
//!   Ctrl_C43 / XC7Z007S.

#![allow(dead_code)]

/// ASIC UART command headers (BM139x VIL). These are **not** FPGA
/// offsets — see [`fpga`].
pub mod uart {
    /// `set_address` (`buf[0] = 64` in S9k `set_address@13508`).
    pub const HDR_SET_ADDR: u8 = 0x40;
    /// Write-register, single chip (`register_build_set_config_command`
    /// packs type/write/single → `0x41`).
    pub const HDR_WRITE_SINGLE: u8 = 0x41;
    /// Read-register, single chip (`read_asic_register` VIL `buf[0] = 66`).
    pub const HDR_READ_SINGLE: u8 = 0x42;
    /// Write-register, broadcast.
    pub const HDR_WRITE_ALL: u8 = 0x51;
    /// Read-register, broadcast (`mode` bit sets `0x42 | 0x10`).
    pub const HDR_READ_ALL: u8 = 0x52;
    /// `chain_inactive` VIL (`buf[0] = 83`).
    pub const HDR_INACTIVE_ALL: u8 = 0x53;

    /// VIL short-frame length byte (`buf[1] = 5`).
    pub const VIL_LEN_SHORT: u8 = 5;
    /// VIL set-config length byte (`_Length = 9`).
    pub const VIL_LEN_SET_CONFIG: u8 = 9;
}

/// Stock-FPGA AXI byte offsets. Same map as
/// `dcentrald_hal::stock_fpga`. The W11.10 catalog mislabeled these as
/// UART opcodes.
pub mod fpga {
    /// `axi[48]` — `set_BC_write_command@460E4`.
    pub const BC_WRITE_COMMAND: u32 = 0x0C0;
    /// `axi[49]` — `set_BC_command_buffer@45DE8` word0.
    pub const BC_COMMAND_BUFFER: u32 = 0x0C4;
    /// `axi[50]`.
    pub const BC_COMMAND_BUFFER_W1: u32 = 0x0C8;
    /// `axi[51]`.
    pub const BC_COMMAND_BUFFER_W2: u32 = 0x0CC;
    /// `axi[16]` — first VIL TW word (`set_TW_write_command_vil@4717C`).
    pub const TW_WRITE_COMMAND: u32 = 0x40;
    /// `axi[17]` — subsequent VIL TW words.
    pub const TW_WRITE_COMMAND_CONT: u32 = 0x44;
    /// `axi[12]` — PIC I²C (`REG_IIC_COMMAND`).
    pub const IIC_COMMAND: u32 = 0x30;
    /// `axi[13]` — hashboard reset.
    pub const RESET_HASHBOARD: u32 = 0x34;
    /// `axi[32]` — QN write.
    pub const QN_WRITE_DATA_COMMAND: u32 = 0x80;
    /// `axi[33]` — fan PWM (`set_fan_control`). On Ctrl_C43 the register
    /// accepts writes but does not move air — see
    /// `dcentrald_common::s9se_cooling`.
    pub const FAN_CONTROL: u32 = 0x84;
    /// `axi[1]` — fan tach (`get_fan_speed`). Ctrl_C43 live: always 0.
    pub const FAN_SPEED: u32 = 0x04;
    /// `axi[64]` — `get/set_dhash_acc_control@46FA4`.
    pub const DHASH_ACC_CONTROL: u32 = 0x100;
    /// `axi[3]` — work-FIFO ready bitmask.
    pub const BUFFER_SPACE: u32 = 0x0C;
}

/// BM1393 core registers `0x0..=0x7` per RE2 §8.5 (not re-probed on
/// the S9 SE image; kept as the core-clock catalog `enable_core_clock_BM1393`
/// indexes).
pub mod core_reg {
    pub const CLOCK_DELAY_CTRL: u8 = 0x0;
    pub const PROCESS_MONITOR_CTRL: u8 = 0x1;
    pub const PROCESS_MONITOR_DATA: u8 = 0x2;
    pub const CORE_ERROR: u8 = 0x3;
    pub const CORE_ENABLE: u8 = 0x4;
    pub const HASH_CLOCK_CTRL: u8 = 0x5;
    pub const HASH_CLOCK_COUNTER: u8 = 0x6;
    pub const SWEEP_CLOCK_CTRL: u8 = 0x7;
    pub const ALL: [u8; 8] = [
        CLOCK_DELAY_CTRL,
        PROCESS_MONITOR_CTRL,
        PROCESS_MONITOR_DATA,
        CORE_ERROR,
        CORE_ENABLE,
        HASH_CLOCK_CTRL,
        HASH_CLOCK_COUNTER,
        SWEEP_CLOCK_CTRL,
    ];
}

/// CRC5 polynomial `x^5+x^2+1`.
pub const CRC5_POLY: u8 = 0x05;
/// CRC5 LFSR init (`0b11111`).
pub const CRC5_INIT: u8 = 0x1F;
/// Non-VIL short frame: CRC5 over 27 bits (`CRC5(buf, 27u)`).
pub const CRC5_SHORT_BITS: u32 = 27;
/// VIL 5-byte frame: CRC5 over 32 bits (`CRC5(buf, 32u)`).
pub const CRC5_VIL_SHORT_BITS: u32 = 32;
/// VIL 9-byte set-config: CRC5 over 64 bits (`CRC5(buf, 64u)`).
pub const CRC5_VIL_SET_CONFIG_BITS: u32 = 64;

/// #2 live capture of FPGA `BC_COMMAND_BUFFER` word0 after stock enum.
/// Bytes `42 05 78 1c`: VIL/read header + len 5 + last-chip addr
/// `0x78` (60 chips × stride 2) + 27-bit CRC5 `0x1c`.
pub const ISSUE2_CAPTURED_BC_WORD0: u32 = 0x4205_781C;
pub const ISSUE2_CAPTURED_SHORT_FRAME: [u8; 4] = [0x42, 0x05, 0x78, 0x1C];

/// EEPROM `CHIP_MAJOR_TYPE` low-3-bits: `0` → print `"1393"`
/// (`statusServiceThread@732A6`).
pub const EEPROM_MAJOR_TYPE_1393: u8 = 0;

/// Catalog chip ID. **Not** a production `ChipRegistry` key.
pub const CHIP_ID: u16 = 0x1393;

/// Cores per chip: 4 banks × 52 (`open_core_bm1393` + `CORE_NUM=0xD0`
/// + S9k/S9SE maintenance guide).
pub const CORES_PER_CHIP: u16 = 208;
pub const OPEN_CORE_PER_BANK: u16 = 52;
pub const OPEN_CORE_BANKS: u16 = 4;

/// VIL TW burst length: `set_TW_write_command_vil` writes `i = 0..=12`.
/// Distinct from the #2 reporter's 12-word `send_job` count.
pub const VIL_TW_WORDS: usize = 13;

/// DHASH raw-TW / freq-scan mode (`set_dhash_acc_control(… | 0x8100)`).
pub const DHASH_MODE_RAW_TW: u32 = 0x8100;

/// dsPIC IIC←voltage, board-type 4/2 CE/B_BGM
/// (`get_power_iic_value_from_voltage@3B710`).
/// `iic = (B − V·D) / (V·C − A)`, cap 127.
pub const POWER_IIC_A: f64 = 44.244;
pub const POWER_IIC_B: f64 = 1943.4048;
pub const POWER_IIC_C: f64 = 5.74;
pub const POWER_IIC_D: f64 = 174.9552;

/// Alternate dsPIC IIC map (non-CE / non-B_BGM).
pub const POWER_IIC_A2: f64 = 43.956;
pub const POWER_IIC_B2: f64 = 1899.7248;
pub const POWER_IIC_C2: f64 = 5.26;
pub const POWER_IIC_D2: f64 = 161.5872;

/// PLL xtal used by `get_pllparam_divider@129D8`:
/// `f = 25 MHz × fbdiv / (refdiv × postdiv1 × postdiv2)`.
pub const PLL_XTAL_MHZ: f64 = 25.0;

/// Ticket-mask register (`set_asic_ticket_mask` `buf[3]=20`). Same
/// family as BM1397+, **not** BM1387 `0x18`. Encoding is per-byte
/// bit-reverse (`dcentrald_common::ticket_mask`).
pub const BM1393_TICKET_MASK_REG: u8 = 0x14;

/// Default operating UART baud (RE2 §4.1 family default; S9 SE factory
/// conf enables VIL and does not override this here).
pub const BM1393_BAUD_DEFAULT: u32 = 937_500;

/// Ctrl_C43 256 MiB `fpga_mem` offset (`cgminer.sh` else-branch).
pub const BM1393_FPGA_MEM_OFFSET_256MIB: u32 = 0x0F00_0000;

/// FPGA / ASIC work_id width..
pub const BM1393_WORK_ID_BITS: u32 = 8;

/// Nonce width. 32-bit; 64-bit is the BM1362/1366 family.
pub const BM1393_NONCE_BITS: u32 = 32;

/// Bit-serial CRC5 (MSB-first). `nbits` is the Bitmain `CRC5(buf, n)`
/// length argument.
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

/// dsPIC IIC byte from commanded voltage (primary CE/B_BGM map).
pub fn power_iic_from_voltage(voltage: f64) -> u8 {
    let raw = (POWER_IIC_B - voltage * POWER_IIC_D) / (voltage * POWER_IIC_C - POWER_IIC_A);
    if raw >= 127.0 {
        127
    } else if raw <= 0.0 {
        0
    } else {
        raw as u8
    }
}

/// Inverse of [`power_iic_from_voltage`].
pub fn voltage_from_power_iic(iic: u8) -> f64 {
    let data = f64::from(iic);
    (data * POWER_IIC_A + POWER_IIC_B) / (data * POWER_IIC_C + POWER_IIC_D)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uart_headers_match_bm139x_vil() {
        assert_eq!(uart::HDR_SET_ADDR, 0x40);
        assert_eq!(uart::HDR_WRITE_SINGLE, 0x41);
        assert_eq!(uart::HDR_READ_SINGLE, 0x42);
        assert_eq!(uart::HDR_WRITE_ALL, 0x51);
        assert_eq!(uart::HDR_READ_ALL, 0x52);
        assert_eq!(uart::HDR_INACTIVE_ALL, 0x53);
        assert_eq!(uart::VIL_LEN_SHORT, 5);
        assert_eq!(uart::VIL_LEN_SET_CONFIG, 9);
    }

    #[test]
    fn fpga_offsets_match_stock_fpga_map() {
        // Numeric pins only — do not import dcentrald_hal here (Unix mmap).
        // Must stay equal to `dcentrald_hal::stock_fpga::REG_*`.
        assert_eq!(fpga::BC_WRITE_COMMAND, 0x0C0);
        assert_eq!(fpga::BC_COMMAND_BUFFER, 0x0C4);
        assert_eq!(fpga::BC_COMMAND_BUFFER_W1, 0x0C8);
        assert_eq!(fpga::BC_COMMAND_BUFFER_W2, 0x0CC);
        assert_eq!(fpga::TW_WRITE_COMMAND, 0x40);
        assert_eq!(fpga::TW_WRITE_COMMAND_CONT, 0x44);
        assert_eq!(fpga::IIC_COMMAND, 0x30);
        assert_eq!(fpga::RESET_HASHBOARD, 0x34);
        assert_eq!(fpga::QN_WRITE_DATA_COMMAND, 0x80);
        assert_eq!(fpga::FAN_CONTROL, 0x84);
        assert_eq!(fpga::FAN_SPEED, 0x04);
        assert_eq!(fpga::DHASH_ACC_CONTROL, 0x100);
        assert_eq!(fpga::BUFFER_SPACE, 0x0C);
        // axi word index × 4 = byte offset (S9k zynq.c).
        assert_eq!(fpga::BC_WRITE_COMMAND, 48 * 4);
        assert_eq!(fpga::BC_COMMAND_BUFFER, 49 * 4);
        assert_eq!(fpga::TW_WRITE_COMMAND, 16 * 4);
        assert_eq!(fpga::DHASH_ACC_CONTROL, 64 * 4);
    }

    #[test]
    fn issue2_captured_short_frame_is_crc5_27() {
        let [cmd, len, addr, crc] = ISSUE2_CAPTURED_SHORT_FRAME;
        assert_eq!(cmd, uart::HDR_READ_SINGLE);
        assert_eq!(len, uart::VIL_LEN_SHORT);
        assert_eq!(addr, 0x78, "60 chips × stride 2");
        assert_eq!(crc5_bits(&[cmd, len, addr], CRC5_SHORT_BITS), crc);
        assert_eq!(
            crc5_bits(&[cmd, len, addr, 0], CRC5_SHORT_BITS),
            crc,
            "padding bits after the 24 data bits are zero"
        );
        // Full-byte 24-bit CRC5 is a *different* value — do not use it.
        assert_ne!(crc5_bits(&[cmd, len, addr], 24), crc);
        assert_eq!(ISSUE2_CAPTURED_BC_WORD0, 0x4205_781C);
    }

    #[test]
    fn vil_inactive_crc5_is_32_bits() {
        let mut buf = [uart::HDR_INACTIVE_ALL, uart::VIL_LEN_SHORT, 0, 0, 0];
        buf[4] = crc5_bits(&buf[..4], CRC5_VIL_SHORT_BITS);
        assert_eq!(buf[0], 83);
        assert_eq!(buf[4], crc5_bits(&[0x53, 0x05, 0x00, 0x00], 32));
    }

    #[test]
    fn crc5_is_not_crc8() {
        assert_eq!(CRC5_POLY, 0x05);
        assert_eq!(CRC5_INIT, 0x1F);
    }

    #[test]
    fn eeprom_major_zero_is_1393() {
        assert_eq!(EEPROM_MAJOR_TYPE_1393, 0);
        assert_eq!(CHIP_ID, 0x1393);
    }

    #[test]
    fn cores_are_four_banks_of_52() {
        assert_eq!(OPEN_CORE_PER_BANK * OPEN_CORE_BANKS, CORES_PER_CHIP);
        assert_eq!(CORES_PER_CHIP, 208);
    }

    #[test]
    fn vil_tw_burst_is_13_words() {
        assert_eq!(VIL_TW_WORDS, 13);
        assert_eq!(DHASH_MODE_RAW_TW, 0x8100);
    }

    #[test]
    fn dspic_iic_voltage_round_trips_primary_map() {
        // Working voltage from #2 EEPROM (9.60 V) is inside the map.
        let iic = power_iic_from_voltage(9.60);
        assert!(iic < 127);
        let back = voltage_from_power_iic(iic);
        assert!((back - 9.60).abs() < 0.05, "back={back} iic={iic}");
        // Inverse formula is the S9k `get_power_voltage_from_iic_value`.
        let v = voltage_from_power_iic(50);
        let iic2 = power_iic_from_voltage(v);
        assert_eq!(iic2, 50);
    }

    #[test]
    fn pll_xtal_is_25mhz() {
        assert_eq!(PLL_XTAL_MHZ, 25.0);
    }

    #[test]
    fn work_id_is_8_bits() {
        assert_eq!(BM1393_WORK_ID_BITS, 8);
        assert_eq!(1u32 << BM1393_WORK_ID_BITS, 256);
    }

    #[test]
    fn baud_default_is_937500() {
        assert_eq!(BM1393_BAUD_DEFAULT, 937_500);
        assert_eq!(BM1393_TICKET_MASK_REG, 0x14);
        assert_eq!(BM1393_FPGA_MEM_OFFSET_256MIB, 0x0F00_0000);
    }

    #[test]
    fn nonce_is_32_bits() {
        assert_eq!(BM1393_NONCE_BITS, 32);
    }

    #[test]
    fn core_register_count_is_8() {
        assert_eq!(core_reg::ALL.len(), 8);
        for (i, reg) in core_reg::ALL.iter().enumerate() {
            assert_eq!(*reg as usize, i);
        }
    }
}
