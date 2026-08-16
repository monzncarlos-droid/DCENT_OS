//! Offline-only carrier evidence for the held BM1485/L3+ stock image.
//!
//! The archive, boot artifacts, device tree, init script, and exact 2017
//! `cgminer` form a reproducible software tuple.  A separately held maintenance
//! guide documents the L3+ hashboard-side 2x9 header and PIC16(L)F1704 circuit.
//! Neither evidence source identifies an attached control board or binds the
//! software nodes to a same-unit physical header: the DTB names a generic TI
//! AM335x BeagleBone, is reused by later L3+ images, and contains no captured
//! serial/EEPROM identity.  This module therefore performs no I/O and grants no
//! UART, I2C, GPIO, PWM, rail, install, or mining authority.

use crate::bm1485_l3plus_stock::{
    BM1485_L3PLUS_STOCK_CGMINER_SHA256, BM1485_L3PLUS_STOCK_CGMINER_SIZE,
    BM1485_L3PLUS_STOCK_CHAIN_COUNT,
};
use crate::bm1485_l3plus_stock_pic::BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES;

pub const BM1485_L3PLUS_STOCK_ARCHIVE_SHA256: &str =
    "e5f668f57b2c47f85a3c0e49f1d113a35af91c08931628c85a64d3d6035d5ca4";
pub const BM1485_L3PLUS_STOCK_ARCHIVE_SIZE: u64 = 29_387_251;
pub const BM1485_L3PLUS_STOCK_MLO_SHA256: &str =
    "702936fab07348e78bcd9f4c8db714ab9e46f70260c939dcf1512bd7c333bdc4";
pub const BM1485_L3PLUS_STOCK_MLO_SIZE: u64 = 100_416;
pub const BM1485_L3PLUS_STOCK_DTB_SHA256: &str =
    "cc687f8db10d2301ba9bb976ec13607e3d9ec47827d16e8942c9f7d9d9b5b4af";
pub const BM1485_L3PLUS_STOCK_DTB_SIZE: u64 = 19_598;
pub const BM1485_L3PLUS_STOCK_UBOOT_SHA256: &str =
    "18b26ddb9b7a50778b7240ce19f74d03284388492cfb2c4657659f6dd866d7e3";
pub const BM1485_L3PLUS_STOCK_UBOOT_SIZE: u64 = 380_204;
pub const BM1485_L3PLUS_STOCK_UIMAGE_SHA256: &str =
    "259349b4e9c8fc9c8bfd67ac67144418bb5ecd9304254fa112dca5a75a95fbf8";
pub const BM1485_L3PLUS_STOCK_UIMAGE_SIZE: u64 = 4_403_568;
pub const BM1485_L3PLUS_STOCK_SD_INITRAMFS_SHA256: &str =
    "eaab4a435f7db974e08dd67798642c705abb7f7d7825aa293a13174ced249d72";
pub const BM1485_L3PLUS_STOCK_SD_INITRAMFS_SIZE: u64 = 10_620_922;
pub const BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SHA256: &str =
    "e542e2a0bf4656c0c485548461d09bfac045e74e570c31d180c1d17f487b4630";
pub const BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SIZE: u64 = 10_620_499;
pub const BM1485_L3PLUS_STOCK_SD_UENV_SHA256: &str =
    "9339e80702c32a9f96bed802a3af633b9eb750fcb5bbaaa681e8570920daaf51";
pub const BM1485_L3PLUS_STOCK_SD_UENV_SIZE: u64 = 552;
pub const BM1485_L3PLUS_STOCK_NAND_UENV_SHA256: &str =
    "e851d7c7f82d764400f539913d4e769a3f69869f668252cae5a873ff3c86edf2";
pub const BM1485_L3PLUS_STOCK_NAND_UENV_SIZE: u64 = 551;
pub const BM1485_L3PLUS_STOCK_INIT_SCRIPT_SHA256: &str =
    "160fc812b14a4b969f3c9780802c2dd93e5975928fed374229718cde37582814";
pub const BM1485_L3PLUS_STOCK_INIT_SCRIPT_SIZE: u64 = 4_972;
pub const BM1485_L3PLUS_STOCK_SD_COMPILE_TIME_SHA256: &str =
    "f2fec4f73459b39d61e8ee771a889d40b95b961fda7aa2bbb7e783a27811e4d5";
pub const BM1485_L3PLUS_STOCK_NAND_COMPILE_TIME_SHA256: &str =
    "c71e7ad0f7b3d38ef30840781403deae1795bd83d2bfea84af0790801fe23c39";
pub const BM1485_L3PLUS_STOCK_SD_COMPILE_TIME: &str = "Wed Apr 19 12:51:35 CST 2017";
pub const BM1485_L3PLUS_STOCK_NAND_COMPILE_TIME: &str = "Fri Jan 20 18:13:55 CST 2017";

pub const BM1485_L3PLUS_STOCK_KERNEL_IMAGE_NAME: &str = "Linux-3.8.13";
pub const BM1485_L3PLUS_STOCK_DTB_MODEL: &str = "TI AM335x BeagleBone";
pub const BM1485_L3PLUS_STOCK_DTB_COMPATIBLE: [&str; 2] = ["ti,am335x-bone", "ti,am33xx"];
pub const BM1485_L3PLUS_STOCK_DTB_CORPUS_MATCHING_COPIES_20260811: usize = 16;

pub const BM1485_L3PLUS_STOCK_UART_OPEN_FLAGS: i32 = 0x0102;
pub const BM1485_L3PLUS_STOCK_UART_FALLBACK_SPEED_T: u32 = 0x1002;
pub const BM1485_L3PLUS_STOCK_UART_VTIME: u8 = 0;
pub const BM1485_L3PLUS_STOCK_UART_VMIN: u8 = 7;
pub const BM1485_L3PLUS_STOCK_UART_FLUSH_SELECTOR: i32 = 2;
pub const BM1485_L3PLUS_STOCK_AFTER_CHAIN_THREAD_DELAY_MS: u32 = 200;
pub const BM1485_L3PLUS_STOCK_I2C_OPEN_FLAGS: i32 = 0x0802;
pub const BM1485_L3PLUS_STOCK_I2C_PATH: &str = "/dev/i2c-0";
pub const BM1485_L3PLUS_STOCK_I2C_DTB_BASE: u32 = 0x4819_c000;
pub const BM1485_L3PLUS_STOCK_I2C_DTB_CLOCK_HZ: u32 = 100_000;

pub const BM1485_L3PLUS_STOCK_PRESENCE_GPIOS: [u16; 4] = [51, 48, 47, 44];
pub const BM1485_L3PLUS_STOCK_RESET_GPIOS: [u16; 4] = [5, 4, 27, 22];
pub const BM1485_L3PLUS_STOCK_FAN_TACH_GPIOS: [u16; 2] = [112, 110];
pub const BM1485_L3PLUS_STOCK_BEEPER_GPIO: u16 = 20;
pub const BM1485_L3PLUS_STOCK_RED_LED_GPIO: u16 = 45;
pub const BM1485_L3PLUS_STOCK_GREEN_LED_GPIO: u16 = 23;
pub const BM1485_L3PLUS_STOCK_PWM_SYSFS_PATH: &str = "/sys/class/pwm/pwm1";
pub const BM1485_L3PLUS_STOCK_PWM_DTB_BASE: u32 = 0x4830_0200;
pub const BM1485_L3PLUS_STOCK_PWM_PINMUX_OFFSET: u16 = 0x0194;
pub const BM1485_L3PLUS_STOCK_PWM_PINMUX_VALUE: u8 = 0x01;
pub const BM1485_L3PLUS_STOCK_INITIAL_PWM_PERIOD_NS: u32 = 100_000;
pub const BM1485_L3PLUS_STOCK_INITIAL_PWM_DUTY_NS: u32 = 50_000;

pub const BM1485_L3PLUS_MAINTENANCE_GUIDE_SHA256: &str =
    "8a96cfa2034d126200b7ec711b46f9e2b4b51f987dc74e8a0b4059cfcf5e6420";
pub const BM1485_L3PLUS_MAINTENANCE_GUIDE_SIZE: u64 = 1_870_262;
pub const BM1485_L3PLUS_MAINTENANCE_GUIDE_PAGE_COUNT: u8 = 10;
pub const BM1485_L3PLUS_GUIDE_VOLTAGE_DOMAIN_COUNT: u8 = 12;
pub const BM1485_L3PLUS_GUIDE_CHIPS_PER_VOLTAGE_DOMAIN: u8 = 6;
pub const BM1485_L3PLUS_GUIDE_HEADER_LOGIC_MV: u16 = 3_300;
pub const BM1485_L3PLUS_GUIDE_CHAIN_LOGIC_MV: u16 = 1_800;
pub const BM1485_L3PLUS_GUIDE_HEARTBEAT_REQUIRED_INTERVAL_SECONDS: u8 = 60;
pub const BM1485_L3PLUS_GUIDE_NO_HEARTBEAT_CLOSE_AFTER_SECONDS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1485L3PlusGuidePicPhysicalPart {
    Pic16Lf1704Family,
}

pub const BM1485_L3PLUS_GUIDE_PIC_PHYSICAL_PART: Bm1485L3PlusGuidePicPhysicalPart =
    Bm1485L3PlusGuidePicPhysicalPart::Pic16Lf1704Family;
pub const BM1485_L3PLUS_GUIDE_PIC_VDD_PIN: u8 = 1;
pub const BM1485_L3PLUS_GUIDE_PIC_VSS_PIN: u8 = 14;
pub const BM1485_L3PLUS_GUIDE_PIC_ADDRESS_PINS: [u8; 3] = [5, 6, 7];
pub const BM1485_L3PLUS_GUIDE_PIC_FEEDBACK_PIN: u8 = 8;
pub const BM1485_L3PLUS_GUIDE_PIC_I2C_PINS: [u8; 2] = [9, 10];
pub const BM1485_L3PLUS_GUIDE_PIC_ENABLE_PIN: u8 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1485L3PlusHashboardHeaderSignal {
    Ground,
    I2cSda,
    I2cScl,
    Plug0,
    PicAddressA2,
    PicAddressA1,
    PicAddressA0,
    HashUartTx,
    HashUartRx,
    Reset,
    ControlBoard3v3,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1485L3PlusHashboardHeaderPin {
    pub pin: u8,
    pub signal: Bm1485L3PlusHashboardHeaderSignal,
}

/// Hashboard-side pinout documented by figures 8, 10, and 13 of the held
/// maintenance guide. Pins 17 and 18 are present but unlabeled in figure 8.
pub const BM1485_L3PLUS_GUIDE_HASHBOARD_HEADER: [Bm1485L3PlusHashboardHeaderPin; 18] = [
    Bm1485L3PlusHashboardHeaderPin {
        pin: 1,
        signal: Bm1485L3PlusHashboardHeaderSignal::Ground,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 2,
        signal: Bm1485L3PlusHashboardHeaderSignal::Ground,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 3,
        signal: Bm1485L3PlusHashboardHeaderSignal::I2cSda,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 4,
        signal: Bm1485L3PlusHashboardHeaderSignal::I2cScl,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 5,
        signal: Bm1485L3PlusHashboardHeaderSignal::Plug0,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 6,
        signal: Bm1485L3PlusHashboardHeaderSignal::PicAddressA2,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 7,
        signal: Bm1485L3PlusHashboardHeaderSignal::PicAddressA1,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 8,
        signal: Bm1485L3PlusHashboardHeaderSignal::PicAddressA0,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 9,
        signal: Bm1485L3PlusHashboardHeaderSignal::Ground,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 10,
        signal: Bm1485L3PlusHashboardHeaderSignal::Ground,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 11,
        signal: Bm1485L3PlusHashboardHeaderSignal::HashUartTx,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 12,
        signal: Bm1485L3PlusHashboardHeaderSignal::HashUartRx,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 13,
        signal: Bm1485L3PlusHashboardHeaderSignal::Ground,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 14,
        signal: Bm1485L3PlusHashboardHeaderSignal::Ground,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 15,
        signal: Bm1485L3PlusHashboardHeaderSignal::Reset,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 16,
        signal: Bm1485L3PlusHashboardHeaderSignal::ControlBoard3v3,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 17,
        signal: Bm1485L3PlusHashboardHeaderSignal::Unspecified,
    },
    Bm1485L3PlusHashboardHeaderPin {
        pin: 18,
        signal: Bm1485L3PlusHashboardHeaderSignal::Unspecified,
    },
];

pub const BM1485_L3PLUS_GUIDE_HASHBOARD_HEADER_WIRING_DOCUMENTED: bool = true;
pub const BM1485_L3PLUS_GUIDE_PIC_PART_DOCUMENTED: bool = true;
pub const BM1485_L3PLUS_GUIDE_SAME_UNIT_CONTROLLER_TO_HEADER_ROUTE_PROVEN: bool = false;
pub const BM1485_L3PLUS_GUIDE_HEARTBEAT_FAILSAFE_BENCH_PROVEN: bool = false;
pub const BM1485_L3PLUS_GUIDE_HAS_INDEPENDENT_SIGNATURE: bool = false;

pub const BM1485_L3PLUS_STOCK_ARCHIVE_HAS_INDEPENDENT_SIGNATURE: bool = false;
pub const BM1485_L3PLUS_STOCK_DTB_HAS_BOARD_BOUND_IDENTITY: bool = false;
pub const BM1485_L3PLUS_STOCK_CONTROLLER_REVISION_PROVEN: bool = false;
pub const BM1485_L3PLUS_STOCK_UART_PHYSICAL_ROUTE_PROVEN: bool = false;
pub const BM1485_L3PLUS_STOCK_PIC_I2C_PHYSICAL_ROUTE_PROVEN: bool = false;
pub const BM1485_L3PLUS_STOCK_GPIO_PHYSICAL_ROUTE_PROVEN: bool = false;
pub const BM1485_L3PLUS_STOCK_PWM_FAN_CONNECTOR_PROVEN: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusGuideObservation<'a> {
    pub sha256: &'a str,
    pub size: u64,
    pub page_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusGuideError {
    HashMismatch,
    SizeMismatch,
    PageCountMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusGuideEvidence {
    exact_document: bool,
}

impl Bm1485L3PlusGuideEvidence {
    pub const fn matches_exact_document(self) -> bool {
        self.exact_document
    }

    pub const fn documents_hashboard_header_and_pic(self) -> bool {
        self.exact_document
    }

    /// A copyable guide is not proof that the attached unit implements it.
    pub const fn identifies_attached_physical_board(self) -> bool {
        false
    }

    pub const fn authorizes_device_or_rail_access(self) -> bool {
        false
    }
}

/// Match the exact held maintenance guide without converting its schematic
/// evidence into a same-unit carrier or electrical-behavior receipt.
pub fn match_bm1485_l3plus_maintenance_guide(
    observation: Bm1485L3PlusGuideObservation<'_>,
) -> Result<Bm1485L3PlusGuideEvidence, Bm1485L3PlusGuideError> {
    if !observation
        .sha256
        .eq_ignore_ascii_case(BM1485_L3PLUS_MAINTENANCE_GUIDE_SHA256)
    {
        return Err(Bm1485L3PlusGuideError::HashMismatch);
    }
    if observation.size != BM1485_L3PLUS_MAINTENANCE_GUIDE_SIZE {
        return Err(Bm1485L3PlusGuideError::SizeMismatch);
    }
    if observation.page_count != BM1485_L3PLUS_MAINTENANCE_GUIDE_PAGE_COUNT {
        return Err(Bm1485L3PlusGuideError::PageCountMismatch);
    }
    Ok(Bm1485L3PlusGuideEvidence {
        exact_document: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockChainCarrierRoute {
    pub chain_slot: u8,
    pub tty_alias: u8,
    pub tty_path: &'static str,
    pub uart_dtb_base: u32,
    pub presence_gpio: u16,
    pub reset_gpio: u16,
    pub pic_i2c_slave_address: u8,
}

/// Exact software route formed by the cgminer alias table, the held DTB, the
/// init script, and the already-recovered PIC endpoint table. The maintenance
/// guide documents the hashboard-side header, but no same-unit observation
/// binds these software nodes to a particular physical header or slot.
pub const BM1485_L3PLUS_STOCK_CHAIN_CARRIER_ROUTES: [Bm1485L3PlusStockChainCarrierRoute;
    BM1485_L3PLUS_STOCK_CHAIN_COUNT] = [
    Bm1485L3PlusStockChainCarrierRoute {
        chain_slot: 0,
        tty_alias: 1,
        tty_path: "/dev/ttyO1",
        uart_dtb_base: 0x4802_2000,
        presence_gpio: 51,
        reset_gpio: 5,
        pic_i2c_slave_address: BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES[0],
    },
    Bm1485L3PlusStockChainCarrierRoute {
        chain_slot: 1,
        tty_alias: 2,
        tty_path: "/dev/ttyO2",
        uart_dtb_base: 0x4802_4000,
        presence_gpio: 48,
        reset_gpio: 4,
        pic_i2c_slave_address: BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES[1],
    },
    Bm1485L3PlusStockChainCarrierRoute {
        chain_slot: 2,
        tty_alias: 4,
        tty_path: "/dev/ttyO4",
        uart_dtb_base: 0x481a_8000,
        presence_gpio: 47,
        reset_gpio: 27,
        pic_i2c_slave_address: BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES[2],
    },
    Bm1485L3PlusStockChainCarrierRoute {
        chain_slot: 3,
        tty_alias: 5,
        tty_path: "/dev/ttyO5",
        uart_dtb_base: 0x481a_a000,
        presence_gpio: 44,
        reset_gpio: 22,
        pic_i2c_slave_address: BM1485_L3PLUS_STOCK_PIC_SLAVE_ADDRESSES[3],
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusStockCarrierArtifactObservation<'a> {
    pub archive_sha256: &'a str,
    pub archive_size: u64,
    pub mlo_sha256: &'a str,
    pub mlo_size: u64,
    pub dtb_sha256: &'a str,
    pub dtb_size: u64,
    pub uboot_sha256: &'a str,
    pub uboot_size: u64,
    pub uimage_sha256: &'a str,
    pub uimage_size: u64,
    pub sd_initramfs_sha256: &'a str,
    pub sd_initramfs_size: u64,
    pub nand_initramfs_sha256: &'a str,
    pub nand_initramfs_size: u64,
    pub sd_uenv_sha256: &'a str,
    pub sd_uenv_size: u64,
    pub nand_uenv_sha256: &'a str,
    pub nand_uenv_size: u64,
    pub cgminer_sha256: &'a str,
    pub cgminer_size: u64,
    pub init_script_sha256: &'a str,
    pub init_script_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusStockCarrierArtifactError {
    ArchiveMismatch,
    MloMismatch,
    DtbMismatch,
    UbootMismatch,
    UimageMismatch,
    SdInitramfsMismatch,
    NandInitramfsMismatch,
    SdUenvMismatch,
    NandUenvMismatch,
    CgminerMismatch,
    InitScriptMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusExactStockCarrierEvidence {
    exact_archive_tuple: bool,
}

impl Bm1485L3PlusExactStockCarrierEvidence {
    pub const fn matches_exact_archive_tuple(self) -> bool {
        self.exact_archive_tuple
    }

    /// Artifact hashes are caller-supplied and copyable; they are not a board
    /// identity or a live carrier receipt.
    pub const fn identifies_physical_board(self) -> bool {
        false
    }

    pub const fn authorizes_device_access(self) -> bool {
        false
    }

    pub const fn authorizes_gpio_or_pwm_mutation(self) -> bool {
        false
    }

    pub const fn authorizes_rail_mutation(self) -> bool {
        false
    }

    pub const fn authorizes_install_or_mining(self) -> bool {
        false
    }
}

fn artifact_matches(
    observed_hash: &str,
    observed_size: u64,
    expected_hash: &str,
    expected_size: u64,
) -> bool {
    observed_size == expected_size && observed_hash.eq_ignore_ascii_case(expected_hash)
}

/// Match the complete held SD-tools archive tuple without promoting its
/// copyable software identity into a physical-board or runtime admission.
pub fn match_bm1485_l3plus_exact_stock_carrier_artifacts(
    observation: Bm1485L3PlusStockCarrierArtifactObservation<'_>,
) -> Result<Bm1485L3PlusExactStockCarrierEvidence, Bm1485L3PlusStockCarrierArtifactError> {
    if !artifact_matches(
        observation.archive_sha256,
        observation.archive_size,
        BM1485_L3PLUS_STOCK_ARCHIVE_SHA256,
        BM1485_L3PLUS_STOCK_ARCHIVE_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::ArchiveMismatch);
    }
    if !artifact_matches(
        observation.mlo_sha256,
        observation.mlo_size,
        BM1485_L3PLUS_STOCK_MLO_SHA256,
        BM1485_L3PLUS_STOCK_MLO_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::MloMismatch);
    }
    if !artifact_matches(
        observation.dtb_sha256,
        observation.dtb_size,
        BM1485_L3PLUS_STOCK_DTB_SHA256,
        BM1485_L3PLUS_STOCK_DTB_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::DtbMismatch);
    }
    if !artifact_matches(
        observation.uboot_sha256,
        observation.uboot_size,
        BM1485_L3PLUS_STOCK_UBOOT_SHA256,
        BM1485_L3PLUS_STOCK_UBOOT_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::UbootMismatch);
    }
    if !artifact_matches(
        observation.uimage_sha256,
        observation.uimage_size,
        BM1485_L3PLUS_STOCK_UIMAGE_SHA256,
        BM1485_L3PLUS_STOCK_UIMAGE_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::UimageMismatch);
    }
    if !artifact_matches(
        observation.sd_initramfs_sha256,
        observation.sd_initramfs_size,
        BM1485_L3PLUS_STOCK_SD_INITRAMFS_SHA256,
        BM1485_L3PLUS_STOCK_SD_INITRAMFS_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::SdInitramfsMismatch);
    }
    if !artifact_matches(
        observation.nand_initramfs_sha256,
        observation.nand_initramfs_size,
        BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SHA256,
        BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::NandInitramfsMismatch);
    }
    if !artifact_matches(
        observation.sd_uenv_sha256,
        observation.sd_uenv_size,
        BM1485_L3PLUS_STOCK_SD_UENV_SHA256,
        BM1485_L3PLUS_STOCK_SD_UENV_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::SdUenvMismatch);
    }
    if !artifact_matches(
        observation.nand_uenv_sha256,
        observation.nand_uenv_size,
        BM1485_L3PLUS_STOCK_NAND_UENV_SHA256,
        BM1485_L3PLUS_STOCK_NAND_UENV_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::NandUenvMismatch);
    }
    if !artifact_matches(
        observation.cgminer_sha256,
        observation.cgminer_size,
        BM1485_L3PLUS_STOCK_CGMINER_SHA256,
        BM1485_L3PLUS_STOCK_CGMINER_SIZE as u64,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::CgminerMismatch);
    }
    if !artifact_matches(
        observation.init_script_sha256,
        observation.init_script_size,
        BM1485_L3PLUS_STOCK_INIT_SCRIPT_SHA256,
        BM1485_L3PLUS_STOCK_INIT_SCRIPT_SIZE,
    ) {
        return Err(Bm1485L3PlusStockCarrierArtifactError::InitScriptMismatch);
    }

    Ok(Bm1485L3PlusExactStockCarrierEvidence {
        exact_archive_tuple: true,
    })
}

/// The software tuple is insufficient until each physical route and the
/// controller revision are independently bound to the same unit.
pub const fn bm1485_l3plus_exact_carrier_tuple_complete() -> bool {
    BM1485_L3PLUS_STOCK_DTB_HAS_BOARD_BOUND_IDENTITY
        && BM1485_L3PLUS_STOCK_CONTROLLER_REVISION_PROVEN
        && BM1485_L3PLUS_STOCK_UART_PHYSICAL_ROUTE_PROVEN
        && BM1485_L3PLUS_STOCK_PIC_I2C_PHYSICAL_ROUTE_PROVEN
        && BM1485_L3PLUS_STOCK_GPIO_PHYSICAL_ROUTE_PROVEN
        && BM1485_L3PLUS_STOCK_PWM_FAN_CONNECTOR_PROVEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_observation() -> Bm1485L3PlusStockCarrierArtifactObservation<'static> {
        Bm1485L3PlusStockCarrierArtifactObservation {
            archive_sha256: BM1485_L3PLUS_STOCK_ARCHIVE_SHA256,
            archive_size: BM1485_L3PLUS_STOCK_ARCHIVE_SIZE,
            mlo_sha256: BM1485_L3PLUS_STOCK_MLO_SHA256,
            mlo_size: BM1485_L3PLUS_STOCK_MLO_SIZE,
            dtb_sha256: BM1485_L3PLUS_STOCK_DTB_SHA256,
            dtb_size: BM1485_L3PLUS_STOCK_DTB_SIZE,
            uboot_sha256: BM1485_L3PLUS_STOCK_UBOOT_SHA256,
            uboot_size: BM1485_L3PLUS_STOCK_UBOOT_SIZE,
            uimage_sha256: BM1485_L3PLUS_STOCK_UIMAGE_SHA256,
            uimage_size: BM1485_L3PLUS_STOCK_UIMAGE_SIZE,
            sd_initramfs_sha256: BM1485_L3PLUS_STOCK_SD_INITRAMFS_SHA256,
            sd_initramfs_size: BM1485_L3PLUS_STOCK_SD_INITRAMFS_SIZE,
            nand_initramfs_sha256: BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SHA256,
            nand_initramfs_size: BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SIZE,
            sd_uenv_sha256: BM1485_L3PLUS_STOCK_SD_UENV_SHA256,
            sd_uenv_size: BM1485_L3PLUS_STOCK_SD_UENV_SIZE,
            nand_uenv_sha256: BM1485_L3PLUS_STOCK_NAND_UENV_SHA256,
            nand_uenv_size: BM1485_L3PLUS_STOCK_NAND_UENV_SIZE,
            cgminer_sha256: BM1485_L3PLUS_STOCK_CGMINER_SHA256,
            cgminer_size: BM1485_L3PLUS_STOCK_CGMINER_SIZE as u64,
            init_script_sha256: BM1485_L3PLUS_STOCK_INIT_SCRIPT_SHA256,
            init_script_size: BM1485_L3PLUS_STOCK_INIT_SCRIPT_SIZE,
        }
    }

    #[test]
    fn exact_archive_tuple_matches_without_minting_any_authority() {
        let evidence =
            match_bm1485_l3plus_exact_stock_carrier_artifacts(exact_observation()).unwrap();
        assert!(evidence.matches_exact_archive_tuple());
        assert!(!evidence.identifies_physical_board());
        assert!(!evidence.authorizes_device_access());
        assert!(!evidence.authorizes_gpio_or_pwm_mutation());
        assert!(!evidence.authorizes_rail_mutation());
        assert!(!evidence.authorizes_install_or_mining());
        assert!(!BM1485_L3PLUS_STOCK_ARCHIVE_HAS_INDEPENDENT_SIGNATURE);
    }

    #[test]
    fn every_artifact_pair_is_fail_closed() {
        let mutations: [fn(&mut Bm1485L3PlusStockCarrierArtifactObservation<'static>); 22] = [
            |o| o.archive_sha256 = "00",
            |o| o.archive_size -= 1,
            |o| o.mlo_sha256 = "00",
            |o| o.mlo_size -= 1,
            |o| o.dtb_sha256 = "00",
            |o| o.dtb_size -= 1,
            |o| o.uboot_sha256 = "00",
            |o| o.uboot_size -= 1,
            |o| o.uimage_sha256 = "00",
            |o| o.uimage_size -= 1,
            |o| o.sd_initramfs_sha256 = "00",
            |o| o.sd_initramfs_size -= 1,
            |o| o.nand_initramfs_sha256 = "00",
            |o| o.nand_initramfs_size -= 1,
            |o| o.sd_uenv_sha256 = "00",
            |o| o.sd_uenv_size -= 1,
            |o| o.nand_uenv_sha256 = "00",
            |o| o.nand_uenv_size -= 1,
            |o| o.cgminer_sha256 = "00",
            |o| o.cgminer_size -= 1,
            |o| o.init_script_sha256 = "00",
            |o| o.init_script_size -= 1,
        ];

        for mutate in mutations {
            let mut observation = exact_observation();
            mutate(&mut observation);
            assert!(match_bm1485_l3plus_exact_stock_carrier_artifacts(observation).is_err());
        }
    }

    #[test]
    fn chain_routes_bind_exact_software_nodes_but_not_physical_headers() {
        let expected = [
            (0, 1, "/dev/ttyO1", 0x4802_2000, 51, 5, 0x50),
            (1, 2, "/dev/ttyO2", 0x4802_4000, 48, 4, 0x51),
            (2, 4, "/dev/ttyO4", 0x481a_8000, 47, 27, 0x52),
            (3, 5, "/dev/ttyO5", 0x481a_a000, 44, 22, 0x53),
        ];
        for (route, expected) in BM1485_L3PLUS_STOCK_CHAIN_CARRIER_ROUTES
            .iter()
            .zip(expected)
        {
            assert_eq!(
                (
                    route.chain_slot,
                    route.tty_alias,
                    route.tty_path,
                    route.uart_dtb_base,
                    route.presence_gpio,
                    route.reset_gpio,
                    route.pic_i2c_slave_address,
                ),
                expected
            );
        }
        assert!(!BM1485_L3PLUS_STOCK_UART_PHYSICAL_ROUTE_PROVEN);
        assert!(!BM1485_L3PLUS_STOCK_PIC_I2C_PHYSICAL_ROUTE_PROVEN);
    }

    #[test]
    fn uart_and_i2c_software_open_contract_is_pinned() {
        assert_eq!(BM1485_L3PLUS_STOCK_UART_OPEN_FLAGS, 0x102);
        assert_eq!(BM1485_L3PLUS_STOCK_UART_FALLBACK_SPEED_T, 0x1002);
        assert_eq!(BM1485_L3PLUS_STOCK_UART_VTIME, 0);
        assert_eq!(BM1485_L3PLUS_STOCK_UART_VMIN, 7);
        assert_eq!(BM1485_L3PLUS_STOCK_UART_FLUSH_SELECTOR, 2);
        assert_eq!(BM1485_L3PLUS_STOCK_AFTER_CHAIN_THREAD_DELAY_MS, 200);
        assert_eq!(BM1485_L3PLUS_STOCK_I2C_OPEN_FLAGS, 0x802);
        assert_eq!(BM1485_L3PLUS_STOCK_I2C_PATH, "/dev/i2c-0");
        assert_eq!(BM1485_L3PLUS_STOCK_I2C_DTB_BASE, 0x4819_c000);
        assert_eq!(BM1485_L3PLUS_STOCK_I2C_DTB_CLOCK_HZ, 100_000);
    }

    #[test]
    fn gpio_and_pwm_inventory_is_stock_script_intent_only() {
        assert_eq!(BM1485_L3PLUS_STOCK_PRESENCE_GPIOS, [51, 48, 47, 44]);
        assert_eq!(BM1485_L3PLUS_STOCK_RESET_GPIOS, [5, 4, 27, 22]);
        assert_eq!(BM1485_L3PLUS_STOCK_FAN_TACH_GPIOS, [112, 110]);
        assert_eq!(BM1485_L3PLUS_STOCK_BEEPER_GPIO, 20);
        assert_eq!(BM1485_L3PLUS_STOCK_RED_LED_GPIO, 45);
        assert_eq!(BM1485_L3PLUS_STOCK_GREEN_LED_GPIO, 23);
        assert_eq!(BM1485_L3PLUS_STOCK_PWM_SYSFS_PATH, "/sys/class/pwm/pwm1");
        assert_eq!(BM1485_L3PLUS_STOCK_PWM_DTB_BASE, 0x4830_0200);
        assert_eq!(BM1485_L3PLUS_STOCK_PWM_PINMUX_OFFSET, 0x194);
        assert_eq!(BM1485_L3PLUS_STOCK_PWM_PINMUX_VALUE, 1);
        assert_eq!(BM1485_L3PLUS_STOCK_INITIAL_PWM_PERIOD_NS, 100_000);
        assert_eq!(BM1485_L3PLUS_STOCK_INITIAL_PWM_DUTY_NS, 50_000);
        assert!(!BM1485_L3PLUS_STOCK_GPIO_PHYSICAL_ROUTE_PROVEN);
        assert!(!BM1485_L3PLUS_STOCK_PWM_FAN_CONNECTOR_PROVEN);
    }

    #[test]
    fn dtb_is_reproducible_but_generic_and_not_board_identity() {
        assert_eq!(BM1485_L3PLUS_STOCK_DTB_MODEL, "TI AM335x BeagleBone");
        assert_eq!(
            BM1485_L3PLUS_STOCK_DTB_COMPATIBLE,
            ["ti,am335x-bone", "ti,am33xx"]
        );
        assert_eq!(BM1485_L3PLUS_STOCK_DTB_CORPUS_MATCHING_COPIES_20260811, 16);
        assert_eq!(BM1485_L3PLUS_STOCK_KERNEL_IMAGE_NAME, "Linux-3.8.13");
        assert!(!BM1485_L3PLUS_STOCK_DTB_HAS_BOARD_BOUND_IDENTITY);
        assert!(!BM1485_L3PLUS_STOCK_CONTROLLER_REVISION_PROVEN);
        assert!(!bm1485_l3plus_exact_carrier_tuple_complete());
    }

    #[test]
    fn exact_maintenance_guide_documents_hashboard_without_minting_authority() {
        let exact = Bm1485L3PlusGuideObservation {
            sha256: BM1485_L3PLUS_MAINTENANCE_GUIDE_SHA256,
            size: BM1485_L3PLUS_MAINTENANCE_GUIDE_SIZE,
            page_count: BM1485_L3PLUS_MAINTENANCE_GUIDE_PAGE_COUNT,
        };
        let evidence = match_bm1485_l3plus_maintenance_guide(exact).unwrap();
        assert!(evidence.matches_exact_document());
        assert!(evidence.documents_hashboard_header_and_pic());
        assert!(!evidence.identifies_attached_physical_board());
        assert!(!evidence.authorizes_device_or_rail_access());

        for observation in [
            Bm1485L3PlusGuideObservation {
                sha256: "00",
                ..exact
            },
            Bm1485L3PlusGuideObservation {
                size: exact.size - 1,
                ..exact
            },
            Bm1485L3PlusGuideObservation {
                page_count: exact.page_count - 1,
                ..exact
            },
        ] {
            assert!(match_bm1485_l3plus_maintenance_guide(observation).is_err());
        }
        assert!(!BM1485_L3PLUS_GUIDE_HAS_INDEPENDENT_SIGNATURE);
    }

    #[test]
    fn guide_pinout_pic_and_heartbeat_are_hashboard_scoped() {
        use Bm1485L3PlusHashboardHeaderSignal as Signal;

        let expected = [
            Signal::Ground,
            Signal::Ground,
            Signal::I2cSda,
            Signal::I2cScl,
            Signal::Plug0,
            Signal::PicAddressA2,
            Signal::PicAddressA1,
            Signal::PicAddressA0,
            Signal::Ground,
            Signal::Ground,
            Signal::HashUartTx,
            Signal::HashUartRx,
            Signal::Ground,
            Signal::Ground,
            Signal::Reset,
            Signal::ControlBoard3v3,
            Signal::Unspecified,
            Signal::Unspecified,
        ];
        for (index, (pin, expected_signal)) in BM1485_L3PLUS_GUIDE_HASHBOARD_HEADER
            .iter()
            .zip(expected)
            .enumerate()
        {
            assert_eq!(pin.pin, u8::try_from(index + 1).unwrap());
            assert_eq!(pin.signal, expected_signal);
        }

        assert_eq!(
            BM1485_L3PLUS_GUIDE_PIC_PHYSICAL_PART,
            Bm1485L3PlusGuidePicPhysicalPart::Pic16Lf1704Family
        );
        assert_eq!(BM1485_L3PLUS_GUIDE_PIC_VDD_PIN, 1);
        assert_eq!(BM1485_L3PLUS_GUIDE_PIC_VSS_PIN, 14);
        assert_eq!(BM1485_L3PLUS_GUIDE_PIC_ADDRESS_PINS, [5, 6, 7]);
        assert_eq!(BM1485_L3PLUS_GUIDE_PIC_FEEDBACK_PIN, 8);
        assert_eq!(BM1485_L3PLUS_GUIDE_PIC_I2C_PINS, [9, 10]);
        assert_eq!(BM1485_L3PLUS_GUIDE_PIC_ENABLE_PIN, 11);
        assert_eq!(BM1485_L3PLUS_GUIDE_HEADER_LOGIC_MV, 3_300);
        assert_eq!(BM1485_L3PLUS_GUIDE_CHAIN_LOGIC_MV, 1_800);
        assert_eq!(
            BM1485_L3PLUS_GUIDE_VOLTAGE_DOMAIN_COUNT * BM1485_L3PLUS_GUIDE_CHIPS_PER_VOLTAGE_DOMAIN,
            72
        );
        assert_eq!(BM1485_L3PLUS_GUIDE_HEARTBEAT_REQUIRED_INTERVAL_SECONDS, 60);
        assert_eq!(BM1485_L3PLUS_GUIDE_NO_HEARTBEAT_CLOSE_AFTER_SECONDS, 60);
        assert!(BM1485_L3PLUS_GUIDE_HASHBOARD_HEADER_WIRING_DOCUMENTED);
        assert!(BM1485_L3PLUS_GUIDE_PIC_PART_DOCUMENTED);
        assert!(!BM1485_L3PLUS_GUIDE_SAME_UNIT_CONTROLLER_TO_HEADER_ROUTE_PROVEN);
        assert!(!BM1485_L3PLUS_GUIDE_HEARTBEAT_FAILSAFE_BENCH_PROVEN);
        assert!(!bm1485_l3plus_exact_carrier_tuple_complete());
    }

    #[test]
    fn archive_preserves_two_boot_variants_with_one_exact_miner() {
        assert_ne!(
            BM1485_L3PLUS_STOCK_SD_INITRAMFS_SHA256,
            BM1485_L3PLUS_STOCK_NAND_INITRAMFS_SHA256
        );
        assert_ne!(
            BM1485_L3PLUS_STOCK_SD_UENV_SHA256,
            BM1485_L3PLUS_STOCK_NAND_UENV_SHA256
        );
        assert_eq!(
            BM1485_L3PLUS_STOCK_SD_COMPILE_TIME,
            "Wed Apr 19 12:51:35 CST 2017"
        );
        assert_eq!(
            BM1485_L3PLUS_STOCK_NAND_COMPILE_TIME,
            "Fri Jan 20 18:13:55 CST 2017"
        );
        assert_ne!(
            BM1485_L3PLUS_STOCK_SD_COMPILE_TIME_SHA256,
            BM1485_L3PLUS_STOCK_NAND_COMPILE_TIME_SHA256
        );
        assert_eq!(
            BM1485_L3PLUS_STOCK_CGMINER_SHA256,
            "eb5872ea31257be343495b45d02d2d3a27756ba21b008e42d48a3dfaaa2a8889"
        );
    }
}
