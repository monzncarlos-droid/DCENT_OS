//! S9 SE factory / firmware identity pins (desk-only).
//!
//! Held HiveOS S9 SE stock+client ramdisk + DTB + `cgminer.sh`.

pub const BOARD_TARGET: &str = "am1-s9se";
pub const SOC: &str = "XC7Z007S";
pub const CONTROLLER: &str = "Ctrl_C43";
pub const DTB_COMPATIBLE: &str = "xlnx,zynq-7000";
pub const DTB_MODEL: &str = "Xilinx Zynq";
pub const DTB_MEMORY_SIZE: u32 = 0x1000_0000;
pub const NAND_CONTROLLER: &str = "arm,pl353-nand-r2p1";
pub const AXI_FPGA_DEV: &str = "/dev/axi_fpga_dev";
pub const FPGA_MEM_DEV: &str = "/dev/fpga_mem";

pub const FACTORY_USE_VIL: bool = true;
pub const FACTORY_FAN_CTRL: bool = false;
pub const FACTORY_FAN_PWM: u8 = 100;
/// Factory `"bitmain-freq": "O"` — token, not a megahertz value.
pub const FACTORY_FREQ_TOKEN: &str = "O";
pub const FACTORY_VOLTAGE_TOKEN: u16 = 950;

pub const OPKG_PACKAGE: &str = "cgminer-t11";
pub const OPKG_SOURCE_NEEDLE: &str = "cgminer_1393";
pub const OPKG_BRANCH: &str = "CE";
pub const CGMINER_SHA256: &str =
    "e113eab6d2480ec1596f23992ce013b855196821b276760441c2bc060d9bc9fb";
pub const UIMAGE_SHA256: &str =
    "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f";
pub const BOOTBIN_SHA256: &str =
    "e7353cb4a4b06434f3fc36b203fb0c794c54dc70491d319c23b0df3bfdaab222";
pub const URAMDISK_SHA256: &str =
    "83f9b081c5445f60e0122042bf06619bbf713abefd62d51acdbe6709ad54aeff";
pub const HIVE_WRAP_SHA256: &str =
    "b5609be28769ed1b55617637b2d1ab772662640026bb4ccaf3f4977276274d46";
/// S9 SE `cgminer` `last commit version` string (stripped binary).
pub const CGMINER_COMMIT: &str = "9df023c";
pub const CGMINER_COMMIT_TIME: &str = "2019-07-25 12:01:46";
pub const CGMINER_BUILD_TIME: &str = "2019-07-28 21:25:53";
/// Shared C43/S15 family `uImage` (byte-identical to BM1391 shared kernel).
pub const UIMAGE_MAGIC: u32 = 0x2705_1956;
pub const UIMAGE_SIZE: usize = 4_006_832;
pub const UIMAGE_NAME: &str = "Linux-4.6.0-xilinx-gff81";
pub const UIMAGE_LOAD_ADDR: u32 = 0x8000;

/// `cgminer.sh` LED GPIOs (T11). Not cooling actuators.
pub const GPIO_RED_LED: u16 = 941;
pub const GPIO_GREEN_LED: u16 = 942;
/// LCD bit-bang GPIOs from the same script (CS / SID / SCLK / RESET).
pub const GPIO_LCD_CS: u16 = 954;
pub const GPIO_LCD_SID: u16 = 955;
pub const GPIO_LCD_SCLK: u16 = 958;
pub const GPIO_LCD_RESET: u16 = 959;
/// Held ramdisk `/etc/ant_version`.
pub const ANT_VERSION: &str = "3172";
/// Held inner `md5_info` (single-line digest).
pub const INNER_MD5_INFO: &str = "9112c08c09c7d52f4c2ef996d4012f77";
/// `Angstrom v2013.06` on the ramdisk.
pub const ANGSTROM_VERSION: &str = "Angstrom v2013.06";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeIdentityError {
    FreqTokenIsNotMhz,
    NotS9SeBoard,
}

/// `"O"` is not a numeric factory frequency.
pub fn refuse_factory_freq_token_as_mhz(token: &str) -> Result<(), S9SeIdentityError> {
    if token == FACTORY_FREQ_TOKEN {
        return Err(S9SeIdentityError::FreqTokenIsNotMhz);
    }
    Ok(())
}

pub fn admit_factory_conf() -> Result<(), S9SeIdentityError> {
    if !FACTORY_USE_VIL {
        return Err(S9SeIdentityError::NotS9SeBoard);
    }
    if FACTORY_VOLTAGE_TOKEN != 950 {
        return Err(S9SeIdentityError::NotS9SeBoard);
    }
    Ok(())
}

/// U-Boot `uImage` magic + load address from the held C43 kernel.
pub fn admit_uimage_header(bytes: &[u8]) -> Result<(), S9SeIdentityError> {
    if bytes.len() < 64 {
        return Err(S9SeIdentityError::NotS9SeBoard);
    }
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != UIMAGE_MAGIC {
        return Err(S9SeIdentityError::NotS9SeBoard);
    }
    let load = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    if load != UIMAGE_LOAD_ADDR {
        return Err(S9SeIdentityError::NotS9SeBoard);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_conf_and_hashes_are_pinned() {
        admit_factory_conf().unwrap();
        assert_eq!(
            refuse_factory_freq_token_as_mhz("O"),
            Err(S9SeIdentityError::FreqTokenIsNotMhz)
        );
        assert_eq!(CGMINER_SHA256.len(), 64);
        assert_eq!(UIMAGE_SHA256.len(), 64);
        assert_eq!(DTB_MEMORY_SIZE, 256 * 1024 * 1024);
        assert_eq!(OPKG_SOURCE_NEEDLE, "cgminer_1393");
        assert_eq!(CGMINER_COMMIT, "9df023c");
        assert_eq!(UIMAGE_MAGIC, 0x2705_1956);
        assert_eq!(UIMAGE_NAME, "Linux-4.6.0-xilinx-gff81");
        assert_eq!(GPIO_LCD_CS, 954);
        assert_eq!(GPIO_LCD_RESET, 959);
        assert_eq!(ANT_VERSION, "3172");
        assert_eq!(INNER_MD5_INFO.len(), 32);
        assert_eq!(ANGSTROM_VERSION, "Angstrom v2013.06");
    }

    #[test]
    fn admit_uimage_header_accepts_held_s9se_kernel() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let bytes = std::fs::read(&path).expect("held S9 SE uImage");
        assert_eq!(bytes.len(), UIMAGE_SIZE);
        admit_uimage_header(&bytes).unwrap();
        let name = std::str::from_utf8(&bytes[32..56])
            .unwrap_or("")
            .trim_end_matches('\0');
        assert_eq!(name, UIMAGE_NAME);
    }
}
