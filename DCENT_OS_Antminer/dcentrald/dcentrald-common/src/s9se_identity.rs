//! S9 SE factory / firmware identity pins (desk-only).
//!
//! Two evidence sources: the held HiveOS S9 SE stock+client ramdisk + DTB +
//! `cgminer.sh` (2026-08-15 gauntlet), and the operator-supplied official
//! Bitmain OM user firmware `om-20190918` (cross-adjudicated 2026-08-17 —
//! factory conf, launcher, and wire tables byte-identical across builds).

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
pub const CGMINER_SHA256: &str = "e113eab6d2480ec1596f23992ce013b855196821b276760441c2bc060d9bc9fb";
pub const UIMAGE_SHA256: &str = "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f";
pub const BOOTBIN_SHA256: &str = "e7353cb4a4b06434f3fc36b203fb0c794c54dc70491d319c23b0df3bfdaab222";
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

/// Operator-supplied **official Bitmain OM user firmware** for the S9 SE
/// (`Antminer-S9 SE-user-OM-201909181551-sig_4034.tar.gz`, 2019-09-18). The
/// 2026-08-15 gauntlet derived its pins from a held HiveOS stock+client
/// ramdisk because the official CDN link was dead; this package is the
/// official-artifact cross-adjudication. Preserved at
/// .
///
/// Cross-build result (2026-08-17): factory `cgminer.conf`, `cgminer.sh`,
/// the 33×12 `freq_high_pll_1393` table, the 179×16 `freq_pll_1393` region,
/// and the assertion-string set are **byte-identical** to the held July
/// HiveOS build; only the build dates, `/etc/ant_version`, opkg revision,
/// and `.data` file offsets differ.
pub const OFFICIAL_OM_TAR_SHA256: &str =
    "0d9216cd42c2f84f0d6888828e03dbbf31cf2c9345b868d161b407e3843587aa";
pub const OFFICIAL_OM_VERSION_NUMBER: &str = "1.84994.0.15";
/// Official OM ramdisk `/etc/ant_version` (held HiveOS ramdisk was `3172`).
pub const OFFICIAL_OM_ANT_VERSION: &str = "4034";
pub const OFFICIAL_OM_MD5_INFO: &str = "a641070a4d0f609258be3858c9792f77";
pub const OFFICIAL_URAMDISK_SHA256: &str =
    "ae1e6bc0da990ede70abeaf153f06692c973540b12d39f4525c1d14ef303d870";
/// Official OM `cgminer` (stripped ARM ELF; held HiveOS build was
/// `e113eab6…`, 611708 B, opkg `1.0-r1.110`).
pub const OFFICIAL_CGMINER_SHA256: &str =
    "4c05228fac5f682887c8da8b851793ae3759f72167a0bd443b60a7373197c82e";
pub const OFFICIAL_CGMINER_SIZE: usize = 614_796;
pub const OFFICIAL_OPKG_REVISION: &str = "1.0-r1.29";
/// `/usr/bin/compile_time` second line — explicit model stamp in the
/// official image (the held HiveOS extraction did not retain this file).
pub const OFFICIAL_COMPILE_MODEL: &str = "Antminer S9 SE";
/// Official OM ships the C43 kernel modules unstripped (new corpus items;
/// the held HiveOS extraction kept no `lib/modules` files).
pub const OFFICIAL_BITMAIN_AXI_KO_SHA256: &str =
    "00500755f72420e3c084e0ea6ecfe71b7989a219a972c2db5e34818f3f750ab4";
pub const OFFICIAL_BITMAIN_AXI_KO_SIZE: usize = 7_519;
pub const OFFICIAL_FPGA_MEM_KO_SHA256: &str =
    "2ec39eda2d5b691c07475b73797c335949a56eb6df9b0a5d83881474bfff0c3f";
pub const OFFICIAL_FPGA_MEM_KO_SIZE: usize = 8_030;
/// Both `.ko` files carry this vermagic. The held uImage name is
/// `Linux-4.6.0-xilinx-gff81`; which 4.6.0-xilinx build an official unit
/// actually runs stays CaptureFirst (`/proc/version` on the unit).
pub const OFFICIAL_KO_VERMAGIC_NEEDLE: &str = "4.6.0-xilinx-g20b57cf-dirty";
/// `bitmainer_setup.sh` forces `NO_START=1` into `/config/dropbear` —
/// stock SSH is disabled by default on the official image.
pub const OFFICIAL_DROPBEAR_NO_START: bool = true;

/// `cgminer.sh` picks the `fpga_mem_driver.ko` `fpga_mem_offset_addr` module
/// parameter from `/proc/meminfo` MemTotal in three tiers. The C43 DTB pins
/// 256 MiB (`DTB_MEMORY_SIZE`), so the S9 SE tier is `0x0F000000`; the
/// classic-S9 512 MiB tier (`0x1F000000`) is the neighboring band, not this
/// board.
pub const FPGA_MEM_TIER_HIGH_KB: u64 = 1_000_000;
pub const FPGA_MEM_TIER_LOW_KB: u64 = 400_000;
pub const FPGA_MEM_OFFSET_1024M: u32 = 0x3F00_0000;
pub const FPGA_MEM_OFFSET_512M: u32 = 0x1F00_0000;
pub const FPGA_MEM_OFFSET_256M: u32 = 0x0F00_0000;

/// Stock `cgminer.sh` `fpga_mem` offset tier for a MemTotal (KiB).
///
/// Official OM-20190918 and Hive `etc/init.d/cgminer.sh` use three tests:
/// `-gt 1000000` → `0x3F000000`; `-lt 1000000 -a -gt 400000` → `0x1F000000`;
/// else (including **exact** 1000000 and `<= 400000`) → `0x0F000000`.
pub fn fpga_mem_offset_for_memtotal_kb(memtotal_kb: u64) -> u32 {
    if memtotal_kb > FPGA_MEM_TIER_HIGH_KB {
        FPGA_MEM_OFFSET_1024M
    } else if memtotal_kb < FPGA_MEM_TIER_HIGH_KB && memtotal_kb > FPGA_MEM_TIER_LOW_KB {
        FPGA_MEM_OFFSET_512M
    } else {
        FPGA_MEM_OFFSET_256M
    }
}

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

    fn official_om_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../")
    }

    #[test]
    fn official_om_pins_are_pinned() {
        assert_eq!(OFFICIAL_OM_TAR_SHA256.len(), 64);
        assert_eq!(OFFICIAL_URAMDISK_SHA256.len(), 64);
        assert_eq!(OFFICIAL_CGMINER_SHA256.len(), 64);
        assert_eq!(OFFICIAL_BITMAIN_AXI_KO_SHA256.len(), 64);
        assert_eq!(OFFICIAL_FPGA_MEM_KO_SHA256.len(), 64);
        assert_eq!(OFFICIAL_OM_MD5_INFO.len(), 32);
        // The official OM is a distinct, newer build — never collapse its
        // identity onto the held HiveOS ramdisk pins.
        assert_ne!(OFFICIAL_OM_ANT_VERSION, ANT_VERSION);
        assert_ne!(OFFICIAL_CGMINER_SHA256, CGMINER_SHA256);
        // Factory contract is unchanged across builds.
        assert_eq!(OFFICIAL_COMPILE_MODEL, "Antminer S9 SE");
        assert!(OFFICIAL_DROPBEAR_NO_START);
        assert_eq!(FACTORY_FREQ_TOKEN, "O");
        assert_eq!(FACTORY_VOLTAGE_TOKEN, 950);
        assert!(FACTORY_USE_VIL);
    }

    #[test]
    fn official_om_artifacts_match_pins() {
        let root = official_om_root();
        let read = |rel: &str| {
            std::fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("{rel}: {e}"))
                .trim_end_matches('\n')
                .to_string()
        };
        assert_eq!(
            read("outer/version_number"),
            OFFICIAL_OM_VERSION_NUMBER,
            "outer package version_number"
        );
        assert_eq!(
            read("fw/version"),
            OFFICIAL_OM_ANT_VERSION,
            "inner ant release"
        );
        assert_eq!(read("fw/md5_info"), OFFICIAL_OM_MD5_INFO);
        assert_eq!(
            read("rootfs/etc/ant_version"),
            OFFICIAL_OM_ANT_VERSION,
            "official ramdisk ant_version"
        );
        let compile_time = std::fs::read_to_string(root.join("rootfs/usr/bin/compile_time"))
            .expect("official compile_time");
        assert!(
            compile_time.contains(OFFICIAL_COMPILE_MODEL),
            "compile_time model stamp missing: {compile_time}"
        );
        assert!(compile_time.contains("2019"));

        // Factory conf is byte-identical to the held HiveOS ramdisk copy.
        let official_conf =
            std::fs::read(root.join("rootfs/etc/cgminer.conf.factory")).expect("official conf");
        let held_conf =
            std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../../",
            ))
            .expect("held conf");
        assert_eq!(official_conf, held_conf);
        let conf = String::from_utf8_lossy(&official_conf);
        assert!(conf.contains("\"bitmain-use-vil\" : true"));
        assert!(conf.contains("\"bitmain-freq\" : \"O\""));
        assert!(conf.contains("\"bitmain-voltage\" : \"950\""));

        // Official cgminer build identity.
        let cgminer = std::fs::read(root.join("rootfs/usr/bin/cgminer")).expect("official cgminer");
        assert_eq!(cgminer.len(), OFFICIAL_CGMINER_SIZE);
        assert_eq!(&cgminer[..4], b"\x7fELF");
        assert!(
            cgminer
                .windows(b"check_asic_num".len())
                .any(|w| w == b"check_asic_num"),
            "official cgminer lost the stock assertion strings"
        );
    }

    #[test]
    fn official_om_kernel_modules_pin_axi_devices() {
        let root = official_om_root();
        let axi =
            std::fs::read(root.join("rootfs/lib/modules/bitmain_axi.ko")).expect("bitmain_axi.ko");
        assert_eq!(axi.len(), OFFICIAL_BITMAIN_AXI_KO_SIZE);
        assert_eq!(&axi[..4], b"\x7fELF");
        for needle in [
            AXI_FPGA_DEV.trim_start_matches("/dev/").as_bytes(),
            b"axi_fpga_dev_mmap",
            OFFICIAL_KO_VERMAGIC_NEEDLE.as_bytes(),
        ] {
            assert!(
                axi.windows(needle.len()).any(|w| w == needle),
                "bitmain_axi.ko missing needle"
            );
        }
        let fpga = std::fs::read(root.join("rootfs/lib/modules/fpga_mem_driver.ko"))
            .expect("fpga_mem_driver.ko");
        assert_eq!(fpga.len(), OFFICIAL_FPGA_MEM_KO_SIZE);
        for needle in [
            FPGA_MEM_DEV.trim_start_matches("/dev/").as_bytes(),
            b"fpga_mem_offset_addr",
            OFFICIAL_KO_VERMAGIC_NEEDLE.as_bytes(),
        ] {
            assert!(
                fpga.windows(needle.len()).any(|w| w == needle),
                "fpga_mem_driver.ko missing needle"
            );
        }
    }

    #[test]
    fn fpga_mem_offset_tiers_match_stock_cgminer_sh() {
        let official = official_om_root().join("rootfs/etc/init.d/cgminer.sh");
        let script = std::fs::read_to_string(&official).expect("held official cgminer.sh");
        assert!(script.contains("if [ $memory_size -gt 1000000 ]; then"));
        assert!(
            script.contains("elif [ $memory_size -lt 1000000 -a  $memory_size -gt 400000 ]; then")
        );
        assert!(script.contains("fpga_mem_offset_addr=0x0F000000"));
        assert!(script.contains("fpga_mem_offset_addr=0x1F000000"));
        assert!(script.contains("fpga_mem_offset_addr=0x3F000000"));
        // Exact 1000000 fails both -gt 1000000 and -lt 1000000: else → 256M.
        assert_eq!(
            fpga_mem_offset_for_memtotal_kb(FPGA_MEM_TIER_HIGH_KB),
            FPGA_MEM_OFFSET_256M
        );
        assert_eq!(
            fpga_mem_offset_for_memtotal_kb(FPGA_MEM_TIER_HIGH_KB + 1),
            FPGA_MEM_OFFSET_1024M
        );
        assert_eq!(
            fpga_mem_offset_for_memtotal_kb(FPGA_MEM_TIER_LOW_KB),
            FPGA_MEM_OFFSET_256M
        );
        assert_eq!(
            fpga_mem_offset_for_memtotal_kb(FPGA_MEM_TIER_LOW_KB + 1),
            FPGA_MEM_OFFSET_512M
        );
        // The C43 256 MiB DTB lands in the low/else tier.
        assert_eq!(
            fpga_mem_offset_for_memtotal_kb((DTB_MEMORY_SIZE / 1024) as u64),
            FPGA_MEM_OFFSET_256M
        );
        // A classic-S9-class 512 MiB unit would land one band up — that is
        // the neighboring board, not am1-s9se.
        assert_eq!(
            fpga_mem_offset_for_memtotal_kb(500_000),
            FPGA_MEM_OFFSET_512M
        );
    }
}
