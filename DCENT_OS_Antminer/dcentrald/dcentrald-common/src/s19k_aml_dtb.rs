//! LuxOS-captured `a lab unit` `axg_s400_antminer.dtb` NAND plats — host-testable.
//!
//! Does not write NAND. Pins U-Boot `nand device 1` = `nandnormal` and
//! shows `nvdata` is a U-Boot-named fill-rest slot, not a live BOS mtd.

use crate::s19k_nand_env::S19K_78_PROC_MTD_NAMES;

/// Held LuxOS DTB on the `a lab unit` capture tree.
pub const S19K_78_LUXOS_DTB_NAME: &str = "axg_s400_antminer.dtb";
pub const S19K_78_LUXOS_DTB_BYTES: usize = 45_596;
pub const S19K_78_NANDNORMAL_CHIP_NUM: u32 = 2;
pub const S19K_78_BOOTLOADER_CHIP_NUM: u32 = 1;
/// DTB `nandnormal.plane_mode = "twoplane"`. Not a Linux mtd count.
pub const S19K_78_NANDNORMAL_PLANE_MODE: &str = "twoplane";
pub const S19K_UBOOT_NANDNORMAL_DEVICE: u8 = 1;
pub const S19K_UBOOT_BOOTLOADER_DEVICE: u8 = 0;
/// DTB `nvdata` offset `0xffffffffffffffff` = Amlogic fill-rest marker.
pub const S19K_DTB_NVDATA_FILL_REST: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kDtbNandPart {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kDtbNandLayout {
    pub plat_names: Vec<String>,
    pub bootloader_chip_num: Option<u32>,
    pub nandnormal_chip_num: Option<u32>,
    pub nandnormal_plane_mode: Option<String>,
    pub parts: Vec<S19kDtbNandPart>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUbootNandDevice {
    Bootloader,
    Nandnormal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kNvdataClass {
    /// DTB `nand_partition/nvdata` offset=MAX size=0.
    UbootFillRest,
}

pub fn classify_s19k_uboot_nand_device(dev: u8) -> Result<S19kUbootNandDevice, &'static str> {
    match dev {
        S19K_UBOOT_BOOTLOADER_DEVICE => Ok(S19kUbootNandDevice::Bootloader),
        S19K_UBOOT_NANDNORMAL_DEVICE => Ok(S19kUbootNandDevice::Nandnormal),
        _ => Err("only nand device 0=bootloader and 1=nandnormal are pinned"),
    }
}

pub fn classify_s19k_dtb_nvdata(part: &S19kDtbNandPart) -> Result<S19kNvdataClass, &'static str> {
    if part.name != "nvdata" {
        return Err("not the DTB nvdata node");
    }
    if part.offset == S19K_DTB_NVDATA_FILL_REST && part.size == 0 {
        return Ok(S19kNvdataClass::UbootFillRest);
    }
    Err("DTB nvdata is fill-rest (offset=MAX, size=0); refuse other encodings")
}

/// Live BOS `/proc/mtd` has no `nvdata`. Do not treat Linux names as the
/// U-Boot `erase.part nvdata` target.
pub fn refuse_s19k_78_linux_mtd_as_uboot_nvdata(names: &[&str]) -> Result<(), &'static str> {
    if names.iter().any(|n| *n == "nvdata") {
        return Ok(());
    }
    if names == S19K_78_PROC_MTD_NAMES {
        return Err("`a lab unit` Linux /proc/mtd has no nvdata; U-Boot nvdata is not an mtd name");
    }
    Err("not the live `a lab unit` BOS mtd list")
}

/// 20231115 `partition_emmc_miner.xml` nvdata is CV/eMMC, not AML NAND.
pub fn refuse_s19k_20231115_emmc_nvdata_as_aml_nand(xml: &str) -> Result<(), &'static str> {
    if xml.contains("type=\"emmc\"") && xml.contains("label=\"nvdata\"") {
        return Err("20231115 nvdata is eMMC /nvdata, not Amlogic NAND erase.part nvdata");
    }
    Ok(())
}

/// S19j 7-part `mtd6 nvdata` is not the `a lab unit` BOS map.
pub fn refuse_s19k_s19j_mtd6_nvdata_as_78(names: &[&str]) -> Result<(), &'static str> {
    if names.last() == Some(&"nvdata") && names.len() >= 7 {
        return Err("7-part mtd6 nvdata is S19j/stock comparative, not `a lab unit` BOS");
    }
    Ok(())
}

/// `chip_num=2` + `twoplane` is NAND geometry, not six Linux mtd devices.
pub fn refuse_s19k_dtb_chip_num_as_linux_mtd_count(chip_num: u32) -> Result<(), &'static str> {
    if chip_num == S19K_78_NANDNORMAL_CHIP_NUM {
        return Err("DTB nandnormal chip_num=2 is NAND CS/twoplane, not Linux mtd count");
    }
    Ok(())
}

/// VNish S19k AML nand tarball `devicetree.dtb` — AXG SoC tree, **no**
/// hashboard `PWR_CONTROL` / gpio437 labels. 20945 B vs LuxOS `a lab unit`
/// `axg_s400_antminer.dtb` 45596 B.
pub const VNISH_S19K_AML_DTB_BYTES: usize = 20_945;
pub const VNISH_S19K_AML_DTB_HAS_PWR_CONTROL: bool = false;
pub const VNISH_S19K_AML_DTB_SERIAL_ALIASES: [&str; 4] =
    ["serial0", "serial1", "serial2", "serial3"];
/// AO `serial@3000` under `aobus@ff800000`. Matches `a lab unit` console MMIO.
pub const VNISH_S19K_AML_AO_UART0_MMIO: u32 = 0xFF80_3000;
/// EE `serial@ffd24000` / `serial@ffd23000`. `a lab unit` dmesg binds these to
/// ttyS1 / ttyS2. DTB **aliases** `serial0..3` are still not that map.
pub const VNISH_S19K_AML_EE_UART_A_MMIO: u32 = 0xFFD2_4000;
pub const VNISH_S19K_AML_EE_UART_B_MMIO: u32 = 0xFFD2_3000;
/// AO `serial@4000` under `aobus@ff800000` = `0xFF804000` = `a lab unit` ttyS3.
pub const VNISH_S19K_AML_AO_UART1_MMIO: u32 = 0xFF80_4000;

fn blob_has(blob: &[u8], needle: &[u8]) -> bool {
    blob.windows(needle.len()).any(|w| w == needle)
}

/// Admit the held VNish S19k AML SoC DTB by size + FDT + serial aliases.
pub fn admit_vnish_s19k_aml_soc_dtb(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() != VNISH_S19K_AML_DTB_BYTES {
        return Err("not the held VNish S19k AML 20945-byte DTB");
    }
    if blob.len() < 4 || blob[0..4] != [0xd0, 0x0d, 0xfe, 0xed] {
        return Err("not an FDT");
    }
    if blob_has(blob, b"PWR_CONTROL") {
        return Err("VNish S19k AML SoC DTB unexpectedly contains PWR_CONTROL");
    }
    for alias in VNISH_S19K_AML_DTB_SERIAL_ALIASES {
        if !blob_has(blob, alias.as_bytes()) {
            return Err("VNish DTB missing serialN alias");
        }
    }
    if !blob_has(blob, b"serial@3000") {
        return Err("VNish DTB missing AO serial@3000");
    }
    if !blob_has(blob, b"serial@4000") {
        return Err("VNish DTB missing AO serial@4000");
    }
    if !blob_has(blob, b"serial@ffd24000") || !blob_has(blob, b"serial@ffd23000") {
        return Err("VNish DTB missing EE serial@ffd24000/@ffd23000");
    }
    Ok(())
}

/// This DTB cannot close GPIO437 polarity.
pub fn refuse_vnish_s19k_dtb_as_gpio437_polarity() -> Result<(), &'static str> {
    Err(
        "VNish S19k AML DTB has no PWR_CONTROL/gpio437; polarity stays S11board+Braiins+ePIC software",
    )
}

/// `serial0..3` aliases are not a ttyS1/S2/S3 hashboard map.
pub fn refuse_vnish_dtb_serial_alias_as_ttys_map() -> Result<(), &'static str> {
    Err("serial0-3 aliases are not a ttyS1/S2/S3 hashboard map; discover-on-bench")
}

/// Gzipped factory `dtb/meson1` (item 14) from AML-19k-Pro-202311151447 img.
pub const S19K_FACTORY_MESON1_GZIP_BYTES: usize = 28_568;
/// Gunzipped factory `dtb/meson1` from AML-19k-Pro-202311151447 img item 14.
pub const S19K_FACTORY_MESON1_GUNZIP_BYTES: usize = 114_688;
pub const S19K_AML_MULTI_DTB_MAGIC: &[u8; 4] = b"AML_";
pub const S19K_AML_MULTI_DTB_VERSION: u32 = 2;
pub const S19K_FACTORY_MESON1_ENTRY_COUNT: u32 = 2;
pub const S19K_AML_MULTI_DTB_ENTRY_STRIDE: usize = 56;
pub const S19K_FACTORY_MESON1_SOC: &str = "gxa";
pub const S19K_FACTORY_MESON1_PLAT: &str = "004s";
pub const S19K_FACTORY_MESON1_VARIANT_G1: &str = "g1";
pub const S19K_FACTORY_MESON1_VARIANT_S30V: &str = "s30v  rb";
pub const S19K_FACTORY_MESON1_ENTRY0_OFF: u32 = 0x800;
pub const S19K_FACTORY_MESON1_ENTRY1_OFF: u32 = 0x1_0800;
pub const S19K_FACTORY_MESON1_ENTRY0_SIZE: u32 = 0x1_0000;
pub const S19K_FACTORY_MESON1_ENTRY1_SIZE: u32 = 0xB800;
/// USB UBOOT (item 2) names `GPIOAO_3`, not gpio437 / PWR_CONTROL.
pub const S19K_USB_UBOOT_GPIOAO3: &str = "GPIOAO_3";
pub const S19K_USB_UBOOT_BYTES: usize = 769_024;
/// Unique `GPIOAO_3` in plaintext USB UBOOT. Packed image, not a C string table.
pub const S19K_USB_UBOOT_GPIOAO3_OFF: usize = 675_920;
/// Packed `gpio ` word 9 bytes before GPIOAO_3. Not `gpio GPIOAO_3`.
pub const S19K_USB_UBOOT_GPIO_WORD_OFF: usize = 675_911;
/// Item 6 SDC UBOOT has the same packed GPIOAO_3 tail as USB UBOOT.
pub const S19K_SDC_UBOOT_GPIOAO3_OFF: usize = 725_584;
pub const S19K_UBOOT_GPIOAO3_FROM_END: usize = 93_104;
/// `gpio ` + 4 packed bytes + `GPIOAO_3` shared by USB and SDC U-Boot.
pub const S19K_UBOOT_PACKED_GPIOAO3: &[u8] = b"gpio \xf0\x38\x98 GPIOAO_3";
pub const S19K_USB_UBOOT_PACKED_CONSOLE: &[u8] = b"console=ttyS0";
pub const S19K_USB_UBOOT_PACKED_EARLYCON: &[u8] = b"uart,0xff803000";
pub const S19K_FACTORY_S30V_PART_NAMES: &[&str] =
    &["tpl", "misc", "recovery", "boot", "config", "nvdata"];
/// s30v `nand_partition` sizes. Offsets are 0 except nvdata=MAX fill-rest.
pub const S19K_FACTORY_S30V_MISC_BYTES: u64 = 0x20_0000;
pub const S19K_FACTORY_S30V_RECOVERY_BYTES: u64 = 0x100_0000;
pub const S19K_FACTORY_S30V_BOOT_BYTES: u64 = 0x200_0000;
pub const S19K_FACTORY_S30V_CONFIG_BYTES: u64 = 0x50_0000;
/// s30v AO I2C miner devices. Not gpio437.
pub const S19K_FACTORY_S30V_MCU: &str = "mcu6350";
pub const S19K_FACTORY_S30V_TAS: &str = "tas5782m";
/// g1 Android-TV audio. Not the miner I2C roster.
pub const S19K_FACTORY_G1_TAS5707: &str = "tas5707";
/// AO I2C PCA9557 LED ring @ 0x1f. Packed USB `i2c mw 1f 3.1 0 2`.
pub const S19K_FACTORY_PCA9557_NODE: &str = "aml_pca9557@0x1f";
pub const S19K_FACTORY_LEDRING: &str = "aml, ledring";
pub const S19K_USB_UBOOT_I2C_MW_1F: &[u8] = b"i2c mw 1f 3.1 0 2";
pub const S19K_USB_UBOOT_I2C_MW_1F_OFF: usize = 674_340;
/// Packed truncated `setenv boo` — not bootargs/bootcmd/firstboot.
pub const S19K_USB_UBOOT_SETENV_OFF: usize = 674_967;
pub const S19K_USB_UBOOT_SETENV_PREFIX: &[u8] = b"setenv boo";
pub const S19K_USB_UBOOT_MTDIDS_QUOTED: &[u8] = b"'mtdids'";
/// Packed Android display bootargs. Not S19k NAND geometry.
pub const S19K_USB_UBOOT_LOGO_OFF: usize = 674_989;
pub const S19K_USB_UBOOT_LOGO: &[u8] = b"logo=${display_layer}";
pub const S19K_USB_UBOOT_ANDROID9_OFF: usize = 675_016;
pub const S19K_USB_UBOOT_ANDROID9: &[u8] = b"android9";
/// Packed Android cmdline fragment. Not a board/NAND hardware identity.
pub const S19K_USB_UBOOT_HARDWARE_OFF: usize = 675_071;
pub const S19K_USB_UBOOT_HARDWARE: &[u8] = b"hardware";
/// Packed remnant after `hardwareF\\x02`. Not the string `amlogic`.
pub const S19K_USB_UBOOT_IOGIC_OFF: usize = 675_081;
pub const S19K_USB_UBOOT_IOGIC: &[u8] = b"Iogic";
/// Packed Android telephony cmdline next to `hardware`.
pub const S19K_USB_UBOOT_BASEBAND_OFF: usize = 675_118;
pub const S19K_USB_UBOOT_BASEBAND: &[u8] = b"baseband=N/A";
/// USB UBOOT BL31 ATF source paths. Real `amlogic` hits; not packed cmdline.
pub const S19K_USB_UBOOT_PLAT_AMLOGIC: &[&[u8]] = &[
    b"plat/amlogic/common/bl31_plat_setup.c",
    b"plat/amlogic/common/sip_svc.c",
    b"plat/amlogic/common/plat_pm.c",
    b"plat/amlogic/board/axg/secureboot/secureboot.c",
];
pub const S19K_USB_UBOOT_AMLOGIC_SECURE: &[u8] = b"Amlogic-secure-boot-module-v0.4";
/// Packed remnant of `build.expect`. Leading `b` is packed away.
pub const S19K_USB_UBOOT_UILD_EXPECT_OFF: usize = 675_106;
pub const S19K_USB_UBOOT_UILD_EXPECT: &[u8] = b"uild.expect";
/// Packed remnant of `acmdline`. Trailing `e` is packed away.
pub const S19K_USB_UBOOT_ACMDLIN_OFF: usize = 675_132;
pub const S19K_USB_UBOOT_ACMDLIN: &[u8] = b"acmdlin";
/// Packed USB U-Boot SoC SARADC channel name. Not the BL2 sample-error string.
pub const S19K_USB_UBOOT_SARADC_WORD_OFF: usize = 686_158;
pub const S19K_USB_UBOOT_SARADC_WORD: &[u8] = b"saradc";
pub const S19K_USB_UBOOT_SARADC_CH2_OFF: usize = 686_169;
pub const S19K_USB_UBOOT_SARADC_CH2: &[u8] = b"SARADC channel2";
/// USB controller FIFO / speed enum. Not hash UART FIFO or 77-chip enum.
pub const S19K_USB_UBOOT_TXFIFO_FULL_OFF: usize = 729_904;
pub const S19K_USB_UBOOT_TXFIFO_FULL: &[u8] = b"TxFIFO FULL";
pub const S19K_USB_UBOOT_SPEED_ENUM_OFF: usize = 729_940;
pub const S19K_USB_UBOOT_SPEED_ENUM: &[u8] = b"SPEED ENUM";
/// ATF xlat_tables address mask. Not nandrecovery / mtd5.
pub const S19K_USB_UBOOT_ADDR_MASK_OFF: usize = 257_284;
pub const S19K_USB_UBOOT_ADDR_MASK: &[u8] = b"ADDR_MASK_48_TO_63";
/// Packed `ramoops` next to console=ttyS0. Not recover_env.
pub const S19K_USB_UBOOT_RAMOOPS_OFF: usize = 674_787;
pub const S19K_USB_UBOOT_RAMOOPS: &[u8] = b"ramoops";
/// USB-gadget / Chrome-EC Cortex-M panic dump. Not hash UART or nandrecovery.
pub const S19K_USB_UBOOT_EXCEPTION_OFF: usize = 41_822;
pub const S19K_USB_UBOOT_EXCEPTION: &[u8] = b"=== %s EXCEPTION:";
pub const S19K_USB_UBOOT_PSTACK_OFF: usize = 41_995;
pub const S19K_USB_UBOOT_PSTACK: &[u8] = b"=========== Process Stack Contents ===========";
pub const S19K_USB_UBOOT_CORTEX_TASK_OFF: usize = 42_807;
pub const S19K_USB_UBOOT_CORTEX_TASK: &[u8] = b"core/cortex-m/task.c";
/// USB Chrome-EC task table. Not hash UART / nandrecovery.
pub const S19K_USB_UBOOT_WAIT_EVT_OFF: usize = 42_640;
pub const S19K_USB_UBOOT_WAIT_EVT: &[u8] = b"__wait_evt";
pub const S19K_USB_UBOOT_TASK_READY_OFF: usize = 42_692;
pub const S19K_USB_UBOOT_TASK_READY: &[u8] = b"Task Ready Name";
pub const S19K_USB_UBOOT_MUTEX_LOCK_OFF: usize = 42_652;
pub const S19K_USB_UBOOT_MUTEX_LOCK: &[u8] = b"mutex_lock";
pub const S19K_USB_UBOOT_SVC_HANDLER_OFF: usize = 42_680;
pub const S19K_USB_UBOOT_SVC_HANDLER: &[u8] = b"svc_handler";
pub const S19K_USB_UBOOT_TASK_EXIT_OFF: usize = 42_868;
pub const S19K_USB_UBOOT_TASK_EXIT: &[u8] = b"Task %d (%s) exited!";
pub const S19K_USB_UBOOT_TASK_SET_EVENT_OFF: usize = 42_664;
pub const S19K_USB_UBOOT_TASK_SET_EVENT: &[u8] = b"task_set_event";
pub const S19K_USB_UBOOT_STACK_OV_OFF: usize = 42_900;
pub const S19K_USB_UBOOT_STACK_OV: &[u8] = b"Stack overflow in %s task!";
pub const S19K_USB_UBOOT_TASKS_READY_OFF: usize = 42_928;
pub const S19K_USB_UBOOT_TASKS_READY: &[u8] = b"tasks_ready";
pub const S19K_USB_UBOOT_IDLE_OFF: usize = 42_940;
pub const S19K_USB_UBOOT_IDLE: &[u8] = b"<< idle >>";
pub const S19K_USB_UBOOT_HOOKS_OFF: usize = 42_951;
pub const S19K_USB_UBOOT_HOOKS: &[u8] = b"HOOKS";
pub const S19K_USB_UBOOT_TIMERTASK_OFF: usize = 42_957;
pub const S19K_USB_UBOOT_TIMERTASK: &[u8] = b"TIMERTASK";
pub const S19K_USB_UBOOT_LOWMAILBOX_OFF: usize = 42_967;
pub const S19K_USB_UBOOT_LOWMAILBOX: &[u8] = b"LOWMAILBOX";
pub const S19K_USB_UBOOT_HIGHMAILBOX_OFF: usize = 42_978;
pub const S19K_USB_UBOOT_HIGHMAILBOX: &[u8] = b"HIGHMAILBOX";
pub const S19K_USB_UBOOT_SECMAILBOX_OFF: usize = 42_990;
pub const S19K_USB_UBOOT_SECMAILBOX: &[u8] = b"SECMAILBOX";
pub const S19K_USB_UBOOT_USERLOWTASK_OFF: usize = 43_001;
pub const S19K_USB_UBOOT_USERLOWTASK: &[u8] = b"USERLOWTASK";
pub const S19K_USB_UBOOT_USERHIGHTASK_OFF: usize = 43_013;
pub const S19K_USB_UBOOT_USERHIGHTASK: &[u8] = b"USERHIGHTASK";
pub const S19K_USB_UBOOT_USERSECURETASK_OFF: usize = 43_026;
pub const S19K_USB_UBOOT_USERSECURETASK: &[u8] = b"USERSECURETASK";
pub const S19K_USB_UBOOT_TIMERFORADC_OFF: usize = 43_041;
pub const S19K_USB_UBOOT_TIMERFORADC: &[u8] = b"TIMERFORADCTASK";
pub const S19K_USB_UBOOT_EMPTY_EFUSE_OFF: usize = 43_064;
pub const S19K_USB_UBOOT_EMPTY_EFUSE: &[u8] = b"empty chip, efuse not burned.";
pub const S19K_USB_UBOOT_ES_CHIP_OFF: usize = 43_096;
pub const S19K_USB_UBOOT_ES_CHIP: &[u8] = b"This is ES chip";
pub const S19K_USB_UBOOT_DVFS_VOL_OFF: usize = 43_120;
pub const S19K_USB_UBOOT_DVFS_VOL: &[u8] = b"is_set_dvfs_vol_first";
pub const S19K_USB_UBOOT_GET_INIT_DVFS_OFF: usize = 43_144;
pub const S19K_USB_UBOOT_GET_INIT_DVFS: &[u8] = b"get_init_dvfs";
pub const S19K_USB_UBOOT_GET_DVFS_OFF: usize = 43_160;
pub const S19K_USB_UBOOT_GET_DVFS: &[u8] = b"get_dvfs";
pub const S19K_USB_UBOOT_FREQ_TO_IDX_OFF: usize = 43_172;
pub const S19K_USB_UBOOT_FREQ_TO_IDX: &[u8] = b"freq_to_idx";
pub const S19K_USB_UBOOT_SET_DVFS_INFO_OFF: usize = 43_184;
pub const S19K_USB_UBOOT_SET_DVFS_INFO: &[u8] = b"set_dvfs_info";
pub const S19K_USB_UBOOT_USE_SYS_PLL_OFF: usize = 43_200;
pub const S19K_USB_UBOOT_USE_SYS_PLL: &[u8] = b"use_sys_pll";
pub const S19K_USB_UBOOT_USE_FIX_CLK_OFF: usize = 43_380;
pub const S19K_USB_UBOOT_USE_FIX_CLK: &[u8] = b"use_fix_clk";
pub const S19K_USB_UBOOT_SYS_PLL_LOCK_OFF: usize = 43_595;
pub const S19K_USB_UBOOT_SYS_PLL_LOCK: &[u8] = b"sys pll lock done";
/// Standalone `set_dvfs\0` after `use_fix_clk`. Not `set_dvfs_info` / `is_set_dvfs_vol_first`.
pub const S19K_USB_UBOOT_SET_DVFS_OFF: usize = 43_392;
pub const S19K_USB_UBOOT_SET_DVFS: &[u8] = b"set_dvfs";
pub const S19K_USB_UBOOT_CPU_CLK_SUSPEND_OFF: usize = 43_710;
pub const S19K_USB_UBOOT_CPU_CLK_SUSPEND: &[u8] = b"cpu clk suspend rate";
pub const S19K_USB_UBOOT_SET_DVFS_BUSY_OFF: usize = 43_852;
pub const S19K_USB_UBOOT_SET_DVFS_BUSY: &[u8] = b"set_dvfs_busy";
pub const S19K_USB_UBOOT_HIGH_TASK_SET_DVFS_OFF: usize = 43_868;
pub const S19K_USB_UBOOT_HIGH_TASK_SET_DVFS: &[u8] = b"high_task_set_dvfs";
pub const S19K_USB_UBOOT_AML_THERMAL_OFF: usize = 44_476;
pub const S19K_USB_UBOOT_AML_THERMAL: &[u8] = b"aml_thermal";
pub const S19K_USB_UBOOT_CPU_CLK_RESUME_OFF: usize = 43_735;
pub const S19K_USB_UBOOT_CPU_CLK_RESUME: &[u8] = b"cpu clk resume rate";
pub const S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS_OFF: usize = 43_888;
pub const S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS: &[u8] = b"high_task_init_dvfs";
pub const S19K_USB_UBOOT_BL30_THERMAL_OFF: usize = 44_496;
pub const S19K_USB_UBOOT_BL30_THERMAL: &[u8] = b"bl30:thermal";
/// Vendor typo `diasble` is in the held USB UBOOT image.
pub const S19K_USB_UBOOT_JTAG_FORCE_OFF: usize = 43_932;
pub const S19K_USB_UBOOT_JTAG_FORCE: &[u8] = b"JTAG force diasble";
pub const S19K_USB_UBOOT_EFUSE_PW_EN_OFF: usize = 43_985;
pub const S19K_USB_UBOOT_EFUSE_PW_EN: &[u8] = b"efuse_pw_en: 0x%x";
pub const S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL_OFF: usize = 43_908;
pub const S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL: &[u8] = b"high_task_init_dvfstbl";
pub const S19K_USB_UBOOT_DISABLE_M3_JTAG_OFF: usize = 43_952;
pub const S19K_USB_UBOOT_DISABLE_M3_JTAG: &[u8] = b"disable M3 JTAG";
pub const S19K_USB_UBOOT_EFUSE_BITS_DISABLED_OFF: usize = 44_004;
pub const S19K_USB_UBOOT_EFUSE_BITS_DISABLED: &[u8] = b"WARNING! efuse bits is disabled";
/// First `bl30:thermal` occurrence is this longer trim-disable banner.
pub const S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF: usize = 44_496;
pub const S19K_USB_UBOOT_BL30_THERMAL_TRIM: &[u8] = b"bl30:thermal disable trim";
pub const S19K_USB_UBOOT_DISABLE_A53_JTAG_OFF: usize = 43_968;
pub const S19K_USB_UBOOT_DISABLE_A53_JTAG: &[u8] = b"disable A53 JTAG";
pub const S19K_USB_UBOOT_ENABLE_M3_JTAG_OFF: usize = 44_037;
pub const S19K_USB_UBOOT_ENABLE_M3_JTAG: &[u8] = b"Enable M3 JTAG";
pub const S19K_USB_UBOOT_BL30_THERMAL_CALIB_OFF: usize = 44_540;
pub const S19K_USB_UBOOT_BL30_THERMAL_CALIB: &[u8] = b"bl30:thermal_calib";
pub const S19K_USB_UBOOT_GXL_ES_THERMAL_OFF: usize = 44_949;
pub const S19K_USB_UBOOT_GXL_ES_THERMAL: &[u8] = b"bl30: GXL ES chip disable thermal";
pub const S19K_USB_UBOOT_ENABLE_A53_JTAG_OFF: usize = 44_068;
pub const S19K_USB_UBOOT_ENABLE_A53_JTAG: &[u8] = b"Enable A53 JTAG";
/// Leading space is in the held USB UBOOT image (`Enable M3 JTAG\0 to AO`).
pub const S19K_USB_UBOOT_JTAG_TO_AO_OFF: usize = 44_052;
pub const S19K_USB_UBOOT_JTAG_TO_AO: &[u8] = b" to AO";
pub const S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR_OFF: usize = 44_578;
pub const S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR: &[u8] = b"bl30:ERROR: thermal_calib";
pub const S19K_USB_UBOOT_BL30_UNTRIMMED_OFF: usize = 44_695;
pub const S19K_USB_UBOOT_BL30_UNTRIMMED: &[u8] = b"bl30:This chip has not trimmed thermal";
/// Leading space is in the held USB UBOOT image (` to AO\n\0 to EE`).
pub const S19K_USB_UBOOT_JTAG_TO_EE_OFF: usize = 44_060;
pub const S19K_USB_UBOOT_JTAG_TO_EE: &[u8] = b" to EE";
pub const S19K_USB_UBOOT_INCORRECT_PASSWORD_OFF: usize = 44_118;
pub const S19K_USB_UBOOT_INCORRECT_PASSWORD: &[u8] = b"Error: Incorrect password";
pub const S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF: usize = 44_807;
pub const S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA: &[u8] = b"bl30:thermal_calibration_data";
pub const S19K_USB_UBOOT_BL30_AXG_VER_OFF: usize = 44_738;
pub const S19K_USB_UBOOT_BL30_AXG_VER: &[u8] = b"bl30:axg ver";
pub const S19K_USB_UBOOT_INVALID_INPUT_OFF: usize = 44_096;
pub const S19K_USB_UBOOT_INVALID_INPUT: &[u8] = b"Error: Invalid input";
pub const S19K_USB_UBOOT_PLEASE_TRY_AGAIN_OFF: usize = 44_145;
pub const S19K_USB_UBOOT_PLEASE_TRY_AGAIN: &[u8] = b"Please try again";
pub const S19K_USB_UBOOT_BL30_AXG_THERMAL0_OFF: usize = 44_765;
pub const S19K_USB_UBOOT_BL30_AXG_THERMAL0: &[u8] = b"bl30:axg thermal0";
pub const S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF: usize = 44_784;
pub const S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR: &[u8] = b"bl30:thermal init err";
/// Post-45000 BL30 cluster. SoC power/crypto, not hash UART / ANDROID decrypt.
pub const S19K_USB_UBOOT_OTP_BLOCK11_OFF: usize = 45_261;
pub const S19K_USB_UBOOT_OTP_BLOCK11: &[u8] = b"--> UPDATE MVN in OTP BLOCK_11";
pub const S19K_USB_UBOOT_SCPI_CSS_OFF: usize = 45_328;
pub const S19K_USB_UBOOT_SCPI_CSS: &[u8] = b"scpi_set_css_power_state";
pub const S19K_USB_UBOOT_DDR_SUSPEND_OFF: usize = 45_483;
pub const S19K_USB_UBOOT_DDR_SUSPEND: &[u8] = b"Enter ddr suspend";
pub const S19K_USB_UBOOT_GCM_TAG_OFF: usize = 45_797;
pub const S19K_USB_UBOOT_GCM_TAG: &[u8] = b"GCM: Tag mismatch";
pub const S19K_USB_UBOOT_BL30_AXG_STAMP_OFF: usize = 46_256;
pub const S19K_USB_UBOOT_BL30_AXG_STAMP: &[u8] = b"axg_v1.1.3494-9ec8345";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kAmlMultiDtbEntry {
    pub soc: String,
    pub plat: String,
    pub variant: String,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kAmlMultiDtb {
    pub version: u32,
    pub entries: Vec<S19kAmlMultiDtbEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kFactoryMeson1Kind {
    /// `g1` — logo/system/data Android-TV NAND map.
    G1AndroidTv,
    /// `s30v  rb` — stock miner map with nvdata fill-rest.
    S30vMinerStock,
}

fn aml_pad16(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

/// Parse gunzipped `AML_` multi-DTB. Does not parse inner FDTs.
pub fn parse_s19k_aml_multi_dtb(blob: &[u8]) -> Result<S19kAmlMultiDtb, &'static str> {
    if blob.len() < 12 + S19K_AML_MULTI_DTB_ENTRY_STRIDE {
        return Err("AML_ multi-DTB header too short");
    }
    if &blob[..4] != S19K_AML_MULTI_DTB_MAGIC {
        return Err("not AML_ multi-DTB");
    }
    let version = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    let count = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    if version != S19K_AML_MULTI_DTB_VERSION {
        return Err("factory meson1 AML_ version is 2");
    }
    let mut entries = Vec::new();
    let mut off = 12usize;
    for _ in 0..count {
        if off + S19K_AML_MULTI_DTB_ENTRY_STRIDE > blob.len() {
            return Err("truncated AML_ entry");
        }
        let soc = aml_pad16(&blob[off..off + 16]);
        let plat = aml_pad16(&blob[off + 16..off + 32]);
        let variant = aml_pad16(&blob[off + 32..off + 48]);
        let offset = u32::from_le_bytes(blob[off + 48..off + 52].try_into().unwrap());
        let size = u32::from_le_bytes(blob[off + 52..off + 56].try_into().unwrap());
        entries.push(S19kAmlMultiDtbEntry {
            soc,
            plat,
            variant,
            offset,
            size,
        });
        off += S19K_AML_MULTI_DTB_ENTRY_STRIDE;
    }
    Ok(S19kAmlMultiDtb { version, entries })
}

pub fn classify_s19k_factory_meson1_variant(variant: &str) -> Result<S19kFactoryMeson1Kind, &'static str> {
    if variant == S19K_FACTORY_MESON1_VARIANT_G1 || variant == "g1" {
        return Ok(S19kFactoryMeson1Kind::G1AndroidTv);
    }
    if variant == S19K_FACTORY_MESON1_VARIANT_S30V || variant.starts_with("s30v") {
        return Ok(S19kFactoryMeson1Kind::S30vMinerStock);
    }
    Err("unknown factory meson1 variant")
}

pub fn admit_s19k_factory_meson1_header(m: &S19kAmlMultiDtb) -> Result<(), &'static str> {
    if m.version != S19K_AML_MULTI_DTB_VERSION || m.entries.len() != 2 {
        return Err("factory meson1 is AML_ v2 with 2 entries");
    }
    let e0 = &m.entries[0];
    let e1 = &m.entries[1];
    if e0.soc != S19K_FACTORY_MESON1_SOC || e1.soc != S19K_FACTORY_MESON1_SOC {
        return Err("factory meson1 soc is gxa");
    }
    if e0.plat != S19K_FACTORY_MESON1_PLAT || e1.plat != S19K_FACTORY_MESON1_PLAT {
        return Err("factory meson1 plat is 004s");
    }
    if classify_s19k_factory_meson1_variant(&e0.variant)? != S19kFactoryMeson1Kind::G1AndroidTv {
        return Err("entry0 variant is g1");
    }
    if classify_s19k_factory_meson1_variant(&e1.variant)? != S19kFactoryMeson1Kind::S30vMinerStock {
        return Err("entry1 variant is s30v");
    }
    if e0.offset != S19K_FACTORY_MESON1_ENTRY0_OFF || e1.offset != S19K_FACTORY_MESON1_ENTRY1_OFF {
        return Err("factory meson1 FDT offsets are 0x800 and 0x10800");
    }
    Ok(())
}

pub fn refuse_s19k_factory_g1_as_miner_nand(
    kind: S19kFactoryMeson1Kind,
) -> Result<(), &'static str> {
    if kind == S19kFactoryMeson1Kind::G1AndroidTv {
        return Err("factory meson1 g1 is logo/system/data Android-TV NAND, not S19k miner/BOS");
    }
    Ok(())
}

pub fn refuse_s19k_factory_s30v_sizes_as_78_linux(parts: &[S19kDtbNandPart]) -> Result<(), &'static str> {
    let has_stock = parts.iter().any(|p| {
        matches!(p.name.as_str(), "misc" | "recovery" | "boot" | "config")
    });
    if has_stock {
        return Err(
            "factory s30v nand_partition names/sizes are stock misc/recovery/boot/config, not .78 2/8/50/5/32/153 MiB",
        );
    }
    Ok(())
}

pub fn refuse_s19k_factory_meson1_as_gpio437() -> Result<(), &'static str> {
    Err("factory meson1 has no gpio-line-names/PWR_CONTROL; GPIO437 polarity not in this DTB")
}

pub fn refuse_s19k_usb_uboot_gpioao3_as_gpio437(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(S19K_USB_UBOOT_GPIOAO3.len()).any(|w| w == S19K_USB_UBOOT_GPIOAO3.as_bytes())
    {
        return Err("USB UBOOT GPIOAO_3 is AO pinmux, not am3-s19k gpio437/PWR_CONTROL");
    }
    Ok(())
}

pub fn refuse_s19k_usb_uboot_as_recover_env(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"recover_env".len()).any(|w| w == b"recover_env")
        || blob
            .windows(b"nandrecovery_env".len())
            .any(|w| w == b"nandrecovery_env")
    {
        return Ok(());
    }
    Err("USB UBOOT has no recover_env/nandrecovery_env script; not .78 nand_env")
}

/// Item 14 `dtb/meson1` is gzip. Do not parse the 28568-byte item as FDT/AML_.
pub fn refuse_s19k_meson1_gzip_as_raw_fdt(head: &[u8]) -> Result<(), &'static str> {
    if head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B {
        return Err("factory dtb/meson1 item is gzip; gunzip to AML_ multi-DTB, not raw FDT");
    }
    Ok(())
}

/// Slice one AML_ inner FDT. Does not walk properties.
pub fn s19k_aml_multi_dtb_inner<'a>(
    blob: &'a [u8],
    e: &S19kAmlMultiDtbEntry,
) -> Result<&'a [u8], &'static str> {
    let start = e.offset as usize;
    let end = start.saturating_add(e.size as usize);
    if start >= blob.len() || end > blob.len() || start >= end {
        return Err("AML_ entry FDT out of range");
    }
    let inner = &blob[start..end];
    if inner.len() < 4 || inner[0..4] != [0xd0, 0x0d, 0xfe, 0xed] {
        return Err("AML_ entry is not an FDT");
    }
    Ok(inner)
}

/// Admit factory s30v `nand_partition` sizes. Offsets stay 0 except nvdata=MAX.
pub fn admit_s19k_factory_s30v_nand_sizes(parts: &[S19kDtbNandPart]) -> Result<(), &'static str> {
    let find = |n: &str| parts.iter().find(|p| p.name == n);
    let misc = find("misc").ok_or("s30v nand_partition missing misc")?;
    let recovery = find("recovery").ok_or("s30v nand_partition missing recovery")?;
    let boot = find("boot").ok_or("s30v nand_partition missing boot")?;
    let config = find("config").ok_or("s30v nand_partition missing config")?;
    let nv = find("nvdata").ok_or("s30v nand_partition missing nvdata")?;
    if misc.size != S19K_FACTORY_S30V_MISC_BYTES {
        return Err("s30v misc is 2 MiB");
    }
    if recovery.size != S19K_FACTORY_S30V_RECOVERY_BYTES {
        return Err("s30v recovery is 16 MiB");
    }
    if boot.size != S19K_FACTORY_S30V_BOOT_BYTES {
        return Err("s30v boot is 32 MiB");
    }
    if config.size != S19K_FACTORY_S30V_CONFIG_BYTES {
        return Err("s30v config is 5 MiB");
    }
    classify_s19k_dtb_nvdata(nv)?;
    Ok(())
}

/// s30v miner I2C vs g1 Android-TV audio. Not a gpio437 map.
pub fn classify_s19k_factory_meson1_i2c(blob: &[u8]) -> Result<S19kFactoryMeson1Kind, &'static str> {
    let miner = blob_has(blob, S19K_FACTORY_S30V_MCU.as_bytes())
        && blob_has(blob, S19K_FACTORY_S30V_TAS.as_bytes());
    let tv = blob_has(blob, S19K_FACTORY_G1_TAS5707.as_bytes())
        && !blob_has(blob, S19K_FACTORY_S30V_MCU.as_bytes());
    if miner && !tv {
        return Ok(S19kFactoryMeson1Kind::S30vMinerStock);
    }
    if tv && !miner {
        return Ok(S19kFactoryMeson1Kind::G1AndroidTv);
    }
    Err("factory meson1 I2C is s30v mcu6350+tas5782m or g1 tas5707")
}

pub fn refuse_s19k_factory_s30v_mcu6350_as_gpio437() -> Result<(), &'static str> {
    Err("s30v mcu6350@40 is AO I2C, not gpio437/PWR_CONTROL")
}

pub fn admit_s19k_factory_pca9557_ledring(blob: &[u8]) -> Result<(), &'static str> {
    if !blob_has(blob, S19K_FACTORY_PCA9557_NODE.as_bytes())
        || !blob_has(blob, S19K_FACTORY_LEDRING.as_bytes())
    {
        return Err("factory meson1 has aml_pca9557@0x1f compatible aml, ledring");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_i2c_mw_1f(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_I2C_MW_1F_OFF;
    if blob.len() >= off + S19K_USB_UBOOT_I2C_MW_1F.len()
        && &blob[off..off + S19K_USB_UBOOT_I2C_MW_1F.len()] == S19K_USB_UBOOT_I2C_MW_1F
    {
        return Ok(());
    }
    if blob
        .windows(S19K_USB_UBOOT_I2C_MW_1F.len())
        .any(|w| w == S19K_USB_UBOOT_I2C_MW_1F)
    {
        return Ok(());
    }
    Err("USB UBOOT packed stream has i2c mw 1f 3.1 0 2 at 674340")
}

pub fn refuse_s19k_i2c_mw_1f_as_gpio437() -> Result<(), &'static str> {
    Err("i2c mw 1f 3.1 0 2 is PCA9557@0x1f ledring config, not gpio437/PWR_CONTROL")
}

pub fn admit_s19k_usb_uboot_packed_setenv(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_SETENV_OFF;
    if blob.len() < off + S19K_USB_UBOOT_SETENV_PREFIX.len() {
        return Err("USB UBOOT shorter than packed setenv");
    }
    if &blob[off..off + S19K_USB_UBOOT_SETENV_PREFIX.len()] != S19K_USB_UBOOT_SETENV_PREFIX {
        return Err("USB UBOOT packed setenv boo is at 674967");
    }
    Ok(())
}

pub fn refuse_s19k_usb_setenv_as_bootcmd(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"setenv bootcmd".len()).any(|w| w == b"setenv bootcmd")
        || blob.windows(b"bootcmd".len()).any(|w| w == b"bootcmd")
    {
        return Ok(());
    }
    Err("USB UBOOT has packed setenv boo, not setenv bootcmd / bootcmd")
}

pub fn refuse_s19k_usb_setenv_as_firstboot(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"setenv firstboot".len()).any(|w| w == b"setenv firstboot")
        || blob.windows(b"firstboot".len()).any(|w| w == b"firstboot")
    {
        return Ok(());
    }
    Err("USB UBOOT packed setenv is not fw_setenv firstboot")
}

pub fn refuse_s19k_usb_quoted_mtdids_as_mtdparts(blob: &[u8]) -> Result<(), &'static str> {
    let quoted = blob
        .windows(S19K_USB_UBOOT_MTDIDS_QUOTED.len())
        .any(|w| w == S19K_USB_UBOOT_MTDIDS_QUOTED);
    let parts = blob.windows(b"mtdparts".len()).any(|w| w == b"mtdparts");
    if quoted && !parts {
        return Err("USB UBOOT 'mtdids' is a packed identifier, not live mtdparts geometry");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_packed_logo(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_LOGO_OFF;
    if blob.len() < off + S19K_USB_UBOOT_LOGO.len()
        || &blob[off..off + S19K_USB_UBOOT_LOGO.len()] != S19K_USB_UBOOT_LOGO
    {
        return Err("USB UBOOT packed logo=${display_layer} is at 674989");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_packed_android9(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_ANDROID9_OFF;
    if blob.len() < off + S19K_USB_UBOOT_ANDROID9.len()
        || &blob[off..off + S19K_USB_UBOOT_ANDROID9.len()] != S19K_USB_UBOOT_ANDROID9
    {
        return Err("USB UBOOT packed android9 is at 675016");
    }
    Ok(())
}

pub fn refuse_s19k_usb_logo_as_nand_bootargs() -> Result<(), &'static str> {
    Err("logo=${display_layer} is packed Android display bootargs, not S19k NAND bootargs")
}

pub fn refuse_s19k_usb_android9_as_s19k_rootfs() -> Result<(), &'static str> {
    Err("packed android9 is Android-TV cmdline, not .78/s30v miner rootfs identity")
}

pub fn admit_s19k_usb_uboot_packed_hardware(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_HARDWARE_OFF;
    if blob.len() < off + S19K_USB_UBOOT_HARDWARE.len()
        || &blob[off..off + S19K_USB_UBOOT_HARDWARE.len()] != S19K_USB_UBOOT_HARDWARE
    {
        return Err("USB UBOOT packed hardware is at 675071");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_packed_iogic(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_IOGIC_OFF;
    if blob.len() < off + S19K_USB_UBOOT_IOGIC.len()
        || &blob[off..off + S19K_USB_UBOOT_IOGIC.len()] != S19K_USB_UBOOT_IOGIC
    {
        return Err("USB UBOOT packed Iogic remnant is at 675081");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_packed_baseband(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_BASEBAND_OFF;
    if blob.len() < off + S19K_USB_UBOOT_BASEBAND.len()
        || &blob[off..off + S19K_USB_UBOOT_BASEBAND.len()] != S19K_USB_UBOOT_BASEBAND
    {
        return Err("USB UBOOT packed baseband=N/A is at 675118");
    }
    Ok(())
}

pub fn refuse_s19k_usb_hardware_as_board_id() -> Result<(), &'static str> {
    Err("packed hardware is Android cmdline next to baseband=N/A, not S19k board/NAND identity")
}

pub fn refuse_s19k_usb_iogic_as_amlogic() -> Result<(), &'static str> {
    Err("packed Iogic at 675081 is not contiguous amlogic; packed 674800-676000 has 0 amlogic")
}

pub fn admit_s19k_usb_uboot_atf_plat_amlogic(blob: &[u8]) -> Result<(), &'static str> {
    for needle in S19K_USB_UBOOT_PLAT_AMLOGIC {
        if !blob.windows(needle.len()).any(|w| w == *needle) {
            return Err("USB UBOOT missing BL31 plat/amlogic ATF source path");
        }
    }
    if !blob
        .windows(S19K_USB_UBOOT_AMLOGIC_SECURE.len())
        .any(|w| w == S19K_USB_UBOOT_AMLOGIC_SECURE)
    {
        return Err("USB UBOOT missing Amlogic-secure-boot-module-v0.4");
    }
    Ok(())
}

pub fn refuse_s19k_usb_plat_amlogic_as_miner_nand() -> Result<(), &'static str> {
    Err("plat/amlogic ATF source paths are BL31, not .78/s30v miner NAND identity")
}

pub fn admit_s19k_usb_uboot_packed_uild_expect(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_UILD_EXPECT_OFF;
    if blob.len() < off + S19K_USB_UBOOT_UILD_EXPECT.len()
        || &blob[off..off + S19K_USB_UBOOT_UILD_EXPECT.len()] != S19K_USB_UBOOT_UILD_EXPECT
    {
        return Err("USB UBOOT packed uild.expect is at 675106");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_packed_acmdlin(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_ACMDLIN_OFF;
    if blob.len() < off + S19K_USB_UBOOT_ACMDLIN.len()
        || &blob[off..off + S19K_USB_UBOOT_ACMDLIN.len()] != S19K_USB_UBOOT_ACMDLIN
    {
        return Err("USB UBOOT packed acmdlin is at 675132");
    }
    Ok(())
}

pub fn refuse_s19k_usb_uild_expect_as_build_prop() -> Result<(), &'static str> {
    Err("packed uild.expect is Android build.expect remnant, not a miner build.prop or board id")
}

pub fn refuse_s19k_usb_acmdlin_as_nand_bootargs() -> Result<(), &'static str> {
    Err("packed acmdlin is Android cmdline remnant, not S19k NAND bootargs")
}

pub fn admit_s19k_usb_uboot_saradc_channel2(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_SARADC_CH2_OFF;
    if blob.len() >= off + S19K_USB_UBOOT_SARADC_CH2.len()
        && &blob[off..off + S19K_USB_UBOOT_SARADC_CH2.len()] == S19K_USB_UBOOT_SARADC_CH2
    {
        return Ok(());
    }
    if blob
        .windows(S19K_USB_UBOOT_SARADC_CH2.len())
        .any(|w| w == S19K_USB_UBOOT_SARADC_CH2)
    {
        return Ok(());
    }
    Err("USB UBOOT packed SARADC channel2 is at 686169")
}

pub fn refuse_s19k_usb_saradc_ch2_as_bl2_error() -> Result<(), &'static str> {
    Err("USB SARADC channel2 is a packed U-Boot channel name, not BL2 Get saradc sample Error")
}

pub fn refuse_s19k_usb_saradc_ch2_as_miner_adc() -> Result<(), &'static str> {
    Err("USB SARADC channel2 is AXG SoC SARADC, not miner voltage/temp ADC")
}

pub fn admit_s19k_usb_uboot_txfifo_speed_enum(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_TXFIFO_FULL_OFF, S19K_USB_UBOOT_TXFIFO_FULL),
        (S19K_USB_UBOOT_SPEED_ENUM_OFF, S19K_USB_UBOOT_SPEED_ENUM),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing TxFIFO FULL / SPEED ENUM");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_txfifo_as_hash_fifo() -> Result<(), &'static str> {
    Err("USB TxFIFO FULL is USB-controller FIFO, not hash/FPGA work FIFO")
}

pub fn refuse_s19k_usb_speed_enum_as_chip_enum() -> Result<(), &'static str> {
    Err("USB SPEED ENUM is USB speed enumeration, not 77-chip GetAddress enum")
}

pub fn admit_s19k_usb_uboot_addr_mask(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_ADDR_MASK_OFF;
    if blob.len() >= off + S19K_USB_UBOOT_ADDR_MASK.len()
        && &blob[off..off + S19K_USB_UBOOT_ADDR_MASK.len()] == S19K_USB_UBOOT_ADDR_MASK
    {
        return Ok(());
    }
    if blob
        .windows(S19K_USB_UBOOT_ADDR_MASK.len())
        .any(|w| w == S19K_USB_UBOOT_ADDR_MASK)
    {
        return Ok(());
    }
    Err("USB UBOOT ADDR_MASK_48_TO_63 is at 257284")
}

pub fn refuse_s19k_usb_addr_mask_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB ADDR_MASK_48_TO_63 is ATF xlat_tables, not nandrecovery_env / mtd5")
}

pub fn admit_s19k_usb_uboot_ramoops(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_RAMOOPS_OFF;
    if blob.len() >= off + S19K_USB_UBOOT_RAMOOPS.len()
        && &blob[off..off + S19K_USB_UBOOT_RAMOOPS.len()] == S19K_USB_UBOOT_RAMOOPS
    {
        return Ok(());
    }
    if blob
        .windows(S19K_USB_UBOOT_RAMOOPS.len())
        .any(|w| w == S19K_USB_UBOOT_RAMOOPS)
    {
        return Ok(());
    }
    Err("USB UBOOT packed ramoops is at 674787")
}

pub fn refuse_s19k_usb_ramoops_as_recover_env() -> Result<(), &'static str> {
    Err("USB ramoops is Android pstore remnant next to console=ttyS0, not recover_env")
}

pub fn admit_s19k_usb_uboot_cortex_exception(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_EXCEPTION_OFF, S19K_USB_UBOOT_EXCEPTION),
        (S19K_USB_UBOOT_PSTACK_OFF, S19K_USB_UBOOT_PSTACK),
        (S19K_USB_UBOOT_CORTEX_TASK_OFF, S19K_USB_UBOOT_CORTEX_TASK),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing Cortex-M EXCEPTION / Process Stack / task.c");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_cortex_exception_as_hash_uart() -> Result<(), &'static str> {
    Err("USB Cortex-M EXCEPTION/xPSR dump is USB-gadget EC, not BM1366 ttyS / 55 AA")
}

pub fn refuse_s19k_usb_cortex_task_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB core/cortex-m/task.c is Chrome-EC task dump, not nandrecovery_env / mtd5")
}

pub fn admit_s19k_usb_uboot_ec_task_table(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_WAIT_EVT_OFF, S19K_USB_UBOOT_WAIT_EVT),
        (S19K_USB_UBOOT_TASK_READY_OFF, S19K_USB_UBOOT_TASK_READY),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing __wait_evt / Task Ready Name");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_task_table_as_hash_uart() -> Result<(), &'static str> {
    Err("USB Task Ready Name / __wait_evt is Chrome-EC task table, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_task_table_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB EC task table is not nandrecovery_env / recover_env")
}

pub fn admit_s19k_usb_uboot_ec_mutex_svc(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_MUTEX_LOCK_OFF, S19K_USB_UBOOT_MUTEX_LOCK),
        (S19K_USB_UBOOT_SVC_HANDLER_OFF, S19K_USB_UBOOT_SVC_HANDLER),
        (S19K_USB_UBOOT_TASK_EXIT_OFF, S19K_USB_UBOOT_TASK_EXIT),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing mutex_lock / svc_handler / Task exited");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_mutex_svc_as_hash_uart() -> Result<(), &'static str> {
    Err("USB mutex_lock/svc_handler/Task exited is Chrome-EC, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_mutex_svc_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB EC mutex/svc/task-exit is not nandrecovery_env / recover_env")
}

pub fn admit_s19k_usb_uboot_ec_task_set_stack(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (
            S19K_USB_UBOOT_TASK_SET_EVENT_OFF,
            S19K_USB_UBOOT_TASK_SET_EVENT,
        ),
        (S19K_USB_UBOOT_STACK_OV_OFF, S19K_USB_UBOOT_STACK_OV),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing task_set_event / Stack overflow");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_task_set_stack_as_hash_uart() -> Result<(), &'static str> {
    Err("USB task_set_event / Stack overflow is Chrome-EC, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_stack_ov_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB Stack overflow in %s task! is Chrome-EC, not nandrecovery_env")
}

pub fn admit_s19k_usb_uboot_ec_idle(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_TASKS_READY_OFF, S19K_USB_UBOOT_TASKS_READY),
        (S19K_USB_UBOOT_IDLE_OFF, S19K_USB_UBOOT_IDLE),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing tasks_ready / << idle >>");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_idle_as_hash_uart() -> Result<(), &'static str> {
    Err("USB tasks_ready / << idle >> is Chrome-EC idle task, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_idle_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB tasks_ready / << idle >> is Chrome-EC, not nandrecovery_env")
}

pub fn admit_s19k_usb_uboot_ec_hooks_timer(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_HOOKS_OFF, S19K_USB_UBOOT_HOOKS),
        (S19K_USB_UBOOT_TIMERTASK_OFF, S19K_USB_UBOOT_TIMERTASK),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing HOOKS / TIMERTASK");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_hooks_timer_as_hash_uart() -> Result<(), &'static str> {
    Err("USB HOOKS / TIMERTASK is Chrome-EC task names, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_hooks_timer_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB HOOKS / TIMERTASK is Chrome-EC, not nandrecovery_env")
}

pub fn admit_s19k_usb_uboot_ec_mailbox(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_LOWMAILBOX_OFF, S19K_USB_UBOOT_LOWMAILBOX),
        (S19K_USB_UBOOT_HIGHMAILBOX_OFF, S19K_USB_UBOOT_HIGHMAILBOX),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing LOWMAILBOX / HIGHMAILBOX");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_mailbox_as_hash_uart() -> Result<(), &'static str> {
    Err("USB LOWMAILBOX / HIGHMAILBOX is Chrome-EC mailbox, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_mailbox_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB LOWMAILBOX / HIGHMAILBOX is Chrome-EC, not nandrecovery_env")
}

pub fn admit_s19k_usb_uboot_ec_sec_userlow(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_SECMAILBOX_OFF, S19K_USB_UBOOT_SECMAILBOX),
        (S19K_USB_UBOOT_USERLOWTASK_OFF, S19K_USB_UBOOT_USERLOWTASK),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing SECMAILBOX / USERLOWTASK");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_sec_userlow_as_hash_uart() -> Result<(), &'static str> {
    Err("USB SECMAILBOX / USERLOWTASK is Chrome-EC mailbox/task, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_sec_userlow_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB SECMAILBOX / USERLOWTASK is Chrome-EC, not nandrecovery_env")
}

pub fn admit_s19k_usb_uboot_ec_user_high_secure(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_USERHIGHTASK_OFF, S19K_USB_UBOOT_USERHIGHTASK),
        (
            S19K_USB_UBOOT_USERSECURETASK_OFF,
            S19K_USB_UBOOT_USERSECURETASK,
        ),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing USERHIGHTASK / USERSECURETASK");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_user_high_secure_as_hash_uart() -> Result<(), &'static str> {
    Err("USB USERHIGHTASK / USERSECURETASK is Chrome-EC task names, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_user_high_secure_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB USERHIGHTASK / USERSECURETASK is Chrome-EC, not nandrecovery_env")
}

pub fn admit_s19k_usb_uboot_ec_timer_efuse(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_TIMERFORADC_OFF, S19K_USB_UBOOT_TIMERFORADC),
        (S19K_USB_UBOOT_EMPTY_EFUSE_OFF, S19K_USB_UBOOT_EMPTY_EFUSE),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing TIMERFORADCTASK / empty-chip efuse");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ec_timer_efuse_as_hash_uart() -> Result<(), &'static str> {
    Err("USB TIMERFORADCTASK / empty-chip efuse is Chrome-EC/Amlogic OTP, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ec_timer_efuse_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB TIMERFORADCTASK / empty-chip efuse is not nandrecovery_env")
}

pub fn refuse_s19k_usb_empty_efuse_as_otp_decrypt() -> Result<(), &'static str> {
    Err("USB empty-chip efuse string is Amlogic OTP status, not ENC-item decrypt")
}

pub fn admit_s19k_usb_uboot_es_chip_dvfs(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_ES_CHIP_OFF, S19K_USB_UBOOT_ES_CHIP),
        (S19K_USB_UBOOT_DVFS_VOL_OFF, S19K_USB_UBOOT_DVFS_VOL),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing This is ES chip / is_set_dvfs_vol_first");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_es_chip_dvfs_as_hash_uart() -> Result<(), &'static str> {
    Err("USB This is ES chip / is_set_dvfs_vol_first is Amlogic OTP/DVFS, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_es_chip_dvfs_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB This is ES chip / is_set_dvfs_vol_first is not nandrecovery_env")
}

pub fn refuse_s19k_usb_dvfs_as_hash_pll() -> Result<(), &'static str> {
    Err("USB is_set_dvfs_vol_first is Amlogic SoC DVFS, not hash/UART/ASIC PLL")
}

pub fn refuse_s19k_usb_es_chip_as_miner_identity() -> Result<(), &'static str> {
    Err("USB This is ES chip is Amlogic engineering-sample OTP, not S19k chassis/BHB56")
}

pub fn admit_s19k_usb_uboot_dvfs_freq(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_GET_INIT_DVFS_OFF, S19K_USB_UBOOT_GET_INIT_DVFS),
        (S19K_USB_UBOOT_GET_DVFS_OFF, S19K_USB_UBOOT_GET_DVFS),
        (S19K_USB_UBOOT_FREQ_TO_IDX_OFF, S19K_USB_UBOOT_FREQ_TO_IDX),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing get_init_dvfs / get_dvfs / freq_to_idx");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_dvfs_freq_as_hash_uart() -> Result<(), &'static str> {
    Err("USB get_init_dvfs / get_dvfs / freq_to_idx is Amlogic SoC DVFS, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_dvfs_freq_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB get_init_dvfs / get_dvfs / freq_to_idx is not nandrecovery_env")
}

pub fn refuse_s19k_usb_freq_to_idx_as_hash_pll() -> Result<(), &'static str> {
    Err("USB freq_to_idx is Amlogic SoC DVFS table, not hash/UART/ASIC PLL")
}

pub fn admit_s19k_usb_uboot_dvfs_sys_pll(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_SET_DVFS_INFO_OFF, S19K_USB_UBOOT_SET_DVFS_INFO),
        (S19K_USB_UBOOT_USE_SYS_PLL_OFF, S19K_USB_UBOOT_USE_SYS_PLL),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing set_dvfs_info / use_sys_pll");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_dvfs_sys_pll_as_hash_uart() -> Result<(), &'static str> {
    Err("USB set_dvfs_info / use_sys_pll is Amlogic SoC DVFS/PLL, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_dvfs_sys_pll_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB set_dvfs_info / use_sys_pll is not nandrecovery_env")
}

pub fn refuse_s19k_usb_use_sys_pll_as_hash_pll() -> Result<(), &'static str> {
    Err("USB use_sys_pll is Amlogic SoC SYS PLL, not hash/UART/ASIC PLL")
}

pub fn admit_s19k_usb_uboot_fix_clk_pll_lock(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_USE_FIX_CLK_OFF, S19K_USB_UBOOT_USE_FIX_CLK),
        (S19K_USB_UBOOT_SYS_PLL_LOCK_OFF, S19K_USB_UBOOT_SYS_PLL_LOCK),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing use_fix_clk / sys pll lock done");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_fix_clk_pll_lock_as_hash_uart() -> Result<(), &'static str> {
    Err("USB use_fix_clk / sys pll lock done is Amlogic SoC clock, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_fix_clk_pll_lock_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB use_fix_clk / sys pll lock done is not nandrecovery_env")
}

pub fn refuse_s19k_usb_sys_pll_lock_as_hash_pll() -> Result<(), &'static str> {
    Err("USB sys pll lock done is Amlogic SoC SYS PLL lock, not hash/UART/ASIC PLL")
}

fn usb_has_standalone_set_dvfs(blob: &[u8]) -> bool {
    let off = S19K_USB_UBOOT_SET_DVFS_OFF;
    let needle = S19K_USB_UBOOT_SET_DVFS;
    if blob.len() >= off + needle.len() + 1
        && &blob[off..off + needle.len()] == needle
        && blob[off + needle.len()] == 0
    {
        return true;
    }
    blob.windows(needle.len() + 1)
        .any(|w| w == b"set_dvfs\x00")
}

pub fn admit_s19k_usb_uboot_dvfs_thermal(blob: &[u8]) -> Result<(), &'static str> {
    if !usb_has_standalone_set_dvfs(blob) {
        return Err("USB UBOOT missing standalone set_dvfs (NUL, not set_dvfs_info)");
    }
    for (off, needle) in [
        (
            S19K_USB_UBOOT_CPU_CLK_SUSPEND_OFF,
            S19K_USB_UBOOT_CPU_CLK_SUSPEND,
        ),
        (S19K_USB_UBOOT_SET_DVFS_BUSY_OFF, S19K_USB_UBOOT_SET_DVFS_BUSY),
        (
            S19K_USB_UBOOT_HIGH_TASK_SET_DVFS_OFF,
            S19K_USB_UBOOT_HIGH_TASK_SET_DVFS,
        ),
        (S19K_USB_UBOOT_AML_THERMAL_OFF, S19K_USB_UBOOT_AML_THERMAL),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err("USB UBOOT missing cpu clk suspend / set_dvfs_busy / high_task_set_dvfs / aml_thermal");
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_dvfs_thermal_as_hash_uart() -> Result<(), &'static str> {
    Err("USB set_dvfs / cpu clk suspend / set_dvfs_busy / high_task_set_dvfs / aml_thermal is SoC DVFS/thermal, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_dvfs_thermal_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB set_dvfs / cpu clk suspend / aml_thermal is not nandrecovery_env")
}

pub fn refuse_s19k_usb_cpu_clk_suspend_as_hash_pll() -> Result<(), &'static str> {
    Err("USB cpu clk suspend rate is Amlogic SoC CPU clock, not hash/UART/ASIC PLL")
}

pub fn refuse_s19k_usb_aml_thermal_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB aml_thermal is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn admit_s19k_usb_uboot_bl30_jtag_efuse(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (
            S19K_USB_UBOOT_CPU_CLK_RESUME_OFF,
            S19K_USB_UBOOT_CPU_CLK_RESUME,
        ),
        (
            S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS_OFF,
            S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS,
        ),
        (S19K_USB_UBOOT_BL30_THERMAL_OFF, S19K_USB_UBOOT_BL30_THERMAL),
        (S19K_USB_UBOOT_JTAG_FORCE_OFF, S19K_USB_UBOOT_JTAG_FORCE),
        (S19K_USB_UBOOT_EFUSE_PW_EN_OFF, S19K_USB_UBOOT_EFUSE_PW_EN),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing cpu clk resume / high_task_init_dvfs / bl30:thermal / JTAG / efuse",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_bl30_jtag_efuse_as_hash_uart() -> Result<(), &'static str> {
    Err("USB cpu clk resume / high_task_init_dvfs / bl30:thermal / JTAG / efuse is SoC/BL30, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_bl30_jtag_efuse_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB cpu clk resume / bl30:thermal / JTAG / efuse is not nandrecovery_env")
}

pub fn refuse_s19k_usb_cpu_clk_resume_as_hash_pll() -> Result<(), &'static str> {
    Err("USB cpu clk resume rate is Amlogic SoC CPU clock, not hash/UART/ASIC PLL")
}

pub fn refuse_s19k_usb_bl30_thermal_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:thermal is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn refuse_s19k_usb_efuse_pw_en_as_otp_decrypt() -> Result<(), &'static str> {
    Err("USB efuse_pw_en is BL30 debug, not ENC-item decrypt")
}

pub fn admit_s19k_usb_uboot_dvfstbl_jtag_trim(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (
            S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL_OFF,
            S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL,
        ),
        (
            S19K_USB_UBOOT_DISABLE_M3_JTAG_OFF,
            S19K_USB_UBOOT_DISABLE_M3_JTAG,
        ),
        (
            S19K_USB_UBOOT_EFUSE_BITS_DISABLED_OFF,
            S19K_USB_UBOOT_EFUSE_BITS_DISABLED,
        ),
        (
            S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF,
            S19K_USB_UBOOT_BL30_THERMAL_TRIM,
        ),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing high_task_init_dvfstbl / disable M3 JTAG / efuse-disabled / bl30 thermal trim",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_dvfstbl_jtag_trim_as_hash_uart() -> Result<(), &'static str> {
    Err("USB high_task_init_dvfstbl / disable M3 JTAG / efuse-disabled / bl30 thermal trim is SoC/BL30, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_dvfstbl_jtag_trim_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB high_task_init_dvfstbl / disable M3 JTAG / efuse-disabled / bl30 thermal trim is not nandrecovery_env")
}

pub fn refuse_s19k_usb_efuse_bits_disabled_as_otp_decrypt() -> Result<(), &'static str> {
    Err("USB WARNING! efuse bits is disabled is BL30 debug, not ENC-item decrypt")
}

pub fn refuse_s19k_usb_bl30_thermal_trim_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:thermal disable trim is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn admit_s19k_usb_uboot_a53_gxl_thermal(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (
            S19K_USB_UBOOT_DISABLE_A53_JTAG_OFF,
            S19K_USB_UBOOT_DISABLE_A53_JTAG,
        ),
        (
            S19K_USB_UBOOT_ENABLE_M3_JTAG_OFF,
            S19K_USB_UBOOT_ENABLE_M3_JTAG,
        ),
        (
            S19K_USB_UBOOT_BL30_THERMAL_CALIB_OFF,
            S19K_USB_UBOOT_BL30_THERMAL_CALIB,
        ),
        (
            S19K_USB_UBOOT_GXL_ES_THERMAL_OFF,
            S19K_USB_UBOOT_GXL_ES_THERMAL,
        ),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing disable A53 JTAG / Enable M3 JTAG / bl30:thermal_calib / GXL ES thermal",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_a53_gxl_thermal_as_hash_uart() -> Result<(), &'static str> {
    Err("USB disable A53 JTAG / Enable M3 JTAG / bl30:thermal_calib / GXL ES thermal is SoC/BL30, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_a53_gxl_thermal_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB disable A53 JTAG / Enable M3 JTAG / bl30:thermal_calib / GXL ES thermal is not nandrecovery_env")
}

pub fn refuse_s19k_usb_bl30_thermal_calib_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:thermal_calib is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn refuse_s19k_usb_gxl_es_thermal_as_miner_identity() -> Result<(), &'static str> {
    Err("USB bl30: GXL ES chip disable thermal is BL30 GXL ES debug, not S19k chassis/BHB56")
}

pub fn admit_s19k_usb_uboot_a53_ao_untrimmed(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (
            S19K_USB_UBOOT_ENABLE_A53_JTAG_OFF,
            S19K_USB_UBOOT_ENABLE_A53_JTAG,
        ),
        (S19K_USB_UBOOT_JTAG_TO_AO_OFF, S19K_USB_UBOOT_JTAG_TO_AO),
        (
            S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR_OFF,
            S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR,
        ),
        (S19K_USB_UBOOT_BL30_UNTRIMMED_OFF, S19K_USB_UBOOT_BL30_UNTRIMMED),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing Enable A53 JTAG / to AO / bl30:ERROR thermal_calib / untrimmed thermal",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_a53_ao_untrimmed_as_hash_uart() -> Result<(), &'static str> {
    Err("USB Enable A53 JTAG / to AO / bl30:ERROR thermal_calib / untrimmed thermal is SoC/BL30, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_a53_ao_untrimmed_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB Enable A53 JTAG / to AO / bl30:ERROR thermal_calib / untrimmed thermal is not nandrecovery_env")
}

pub fn refuse_s19k_usb_bl30_thermal_calib_err_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:ERROR: thermal_calib is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn refuse_s19k_usb_bl30_untrimmed_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:This chip has not trimmed thermal is BL30 SoC thermal, not hashboard thermal")
}

pub fn admit_s19k_usb_uboot_ee_pw_axg(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_JTAG_TO_EE_OFF, S19K_USB_UBOOT_JTAG_TO_EE),
        (
            S19K_USB_UBOOT_INCORRECT_PASSWORD_OFF,
            S19K_USB_UBOOT_INCORRECT_PASSWORD,
        ),
        (
            S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF,
            S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA,
        ),
        (S19K_USB_UBOOT_BL30_AXG_VER_OFF, S19K_USB_UBOOT_BL30_AXG_VER),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing to EE / Incorrect password / thermal_calibration_data / axg ver",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_ee_pw_axg_as_hash_uart() -> Result<(), &'static str> {
    Err("USB to EE / Incorrect password / thermal_calibration_data / axg ver is SoC/BL30, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ee_pw_axg_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB to EE / Incorrect password / thermal_calibration_data / axg ver is not nandrecovery_env")
}

pub fn refuse_s19k_usb_incorrect_password_as_miner_auth() -> Result<(), &'static str> {
    Err("USB Error: Incorrect password is BL30 JTAG debug, not miner/stock auth")
}

pub fn refuse_s19k_usb_bl30_thermal_cal_data_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:thermal_calibration_data is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn refuse_s19k_usb_bl30_axg_ver_as_miner_identity() -> Result<(), &'static str> {
    Err("USB bl30:axg ver is BL30 AXG SoC version, not S19k chassis/BHB56")
}

pub fn admit_s19k_usb_uboot_invalid_try_thermal0(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (
            S19K_USB_UBOOT_INVALID_INPUT_OFF,
            S19K_USB_UBOOT_INVALID_INPUT,
        ),
        (
            S19K_USB_UBOOT_PLEASE_TRY_AGAIN_OFF,
            S19K_USB_UBOOT_PLEASE_TRY_AGAIN,
        ),
        (
            S19K_USB_UBOOT_BL30_AXG_THERMAL0_OFF,
            S19K_USB_UBOOT_BL30_AXG_THERMAL0,
        ),
        (
            S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF,
            S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR,
        ),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing Invalid input / Please try again / axg thermal0 / thermal init err",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_invalid_try_thermal0_as_hash_uart() -> Result<(), &'static str> {
    Err("USB Invalid input / Please try again / axg thermal0 / thermal init err is SoC/BL30, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_invalid_try_thermal0_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB Invalid input / Please try again / axg thermal0 / thermal init err is not nandrecovery_env")
}

pub fn refuse_s19k_usb_invalid_input_as_miner_auth() -> Result<(), &'static str> {
    Err("USB Error: Invalid input / Please try again is BL30 JTAG debug, not miner/stock auth")
}

pub fn refuse_s19k_usb_bl30_axg_thermal0_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:axg thermal0 is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn refuse_s19k_usb_bl30_thermal_init_err_as_hash_thermal() -> Result<(), &'static str> {
    Err("USB bl30:thermal init err is BL30 SoC thermal, not hashboard / gpio437 thermal")
}

pub fn admit_s19k_usb_uboot_scpi_ddr_gcm(blob: &[u8]) -> Result<(), &'static str> {
    for (off, needle) in [
        (S19K_USB_UBOOT_OTP_BLOCK11_OFF, S19K_USB_UBOOT_OTP_BLOCK11),
        (S19K_USB_UBOOT_SCPI_CSS_OFF, S19K_USB_UBOOT_SCPI_CSS),
        (S19K_USB_UBOOT_DDR_SUSPEND_OFF, S19K_USB_UBOOT_DDR_SUSPEND),
        (S19K_USB_UBOOT_GCM_TAG_OFF, S19K_USB_UBOOT_GCM_TAG),
    ] {
        if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
            continue;
        }
        if !blob.windows(needle.len()).any(|w| w == needle) {
            return Err(
                "USB UBOOT missing OTP BLOCK_11 / scpi_set_css_power_state / Enter ddr suspend / GCM: Tag mismatch",
            );
        }
    }
    Ok(())
}

pub fn refuse_s19k_usb_scpi_ddr_gcm_as_hash_uart() -> Result<(), &'static str> {
    Err("USB OTP BLOCK / SCPI / ddr suspend / GCM tag is BL30 SoC, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_scpi_ddr_gcm_as_nandrecovery() -> Result<(), &'static str> {
    Err("USB OTP BLOCK / SCPI / ddr suspend / GCM tag is not nandrecovery_env")
}

pub fn refuse_s19k_usb_gcm_tag_as_android_decrypt() -> Result<(), &'static str> {
    Err("USB GCM: Tag mismatch is BL30 A53-restart crypto, not ANDROID/AMLSECU payload decrypt")
}

pub fn refuse_s19k_usb_scpi_as_hash_uart() -> Result<(), &'static str> {
    Err("USB scpi_set_css_power_state is BL30 SCPI cluster power, not BM1366 ttyS")
}

pub fn refuse_s19k_usb_ddr_suspend_as_hashboard_rail() -> Result<(), &'static str> {
    Err("USB Enter ddr suspend is DMC DRAM suspend, not hashboard rail / gpio437")
}

pub fn refuse_s19k_usb_otp_block_as_gpio437() -> Result<(), &'static str> {
    Err("USB UPDATE MVN in OTP BLOCK_11 is Amlogic OTP MVN, not gpio437")
}

pub fn admit_s19k_usb_uboot_bl30_axg_stamp(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_BL30_AXG_STAMP_OFF;
    let needle = S19K_USB_UBOOT_BL30_AXG_STAMP;
    if blob.len() >= off + needle.len() && &blob[off..off + needle.len()] == needle {
        return Ok(());
    }
    if blob.windows(needle.len()).any(|w| w == needle) {
        return Ok(());
    }
    Err("USB UBOOT missing axg_v1.1.3494-9ec8345 BL30 stamp")
}

pub fn refuse_s19k_usb_bl30_stamp_as_miner_identity() -> Result<(), &'static str> {
    Err("USB axg_v1.1.3494-9ec8345 is BL30 SoC firmware stamp, not S19k chassis/BHB56")
}

pub fn refuse_s19k_factory_s30v_serial_as_ttys_map() -> Result<(), &'static str> {
    Err("factory s30v serial0-3 aliases are not a ttyS1/S2/S3 hashboard map")
}

/// AXG EE/periphs pinctrl mux. Factory s30v `pinctrl@ff634480`.
pub const S19K_AXG_PERIPHS_MUX: u32 = 0xFF63_4480;
/// AXG AO/aobus pinctrl mux. Factory s30v `pinctrl@ff800014`.
pub const S19K_AXG_AOBUS_MUX: u32 = 0xFF80_0014;
pub const S19K_AXG_GPIO_CELLS: u32 = 2;
/// Live 4.9 `gpiochip411` pin_base. **Not** a meson1 cell.
pub const S19K_AXG_VENDOR_GPIOCHIP_BASE: u32 = 411;
/// `meson-axg-gpio.h` GPIOA_0 local offset. **Not** named in factory meson1.
pub const S19K_AXG_GPIOA0_LOCAL: u32 = 26;
/// AO GPIOAO_3 local offset. Sysfs 500 if AO base is 497, never 437.
pub const S19K_AXG_GPIOAO3_LOCAL: u32 = 3;
pub const S19K_AXG_PERIPHS_PINCTRL: &str = "amlogic,meson-axg-periphs-pinctrl";
pub const S19K_AXG_AOBUS_PINCTRL: &str = "amlogic,meson-axg-aobus-pinctrl";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kDtbGpioCtrl {
    pub path: String,
    pub mux: u32,
    pub gpio_cells: Option<u32>,
    pub linux_gpio_base: Option<u32>,
    pub has_gpio_ranges: bool,
    pub has_line_names: bool,
}

/// Walk FDT `gpio-controller` nodes. Does not invent linux gpio numbers.
pub fn parse_s19k_aml_dtb_gpio_controllers(
    blob: &[u8],
) -> Result<Vec<S19kDtbGpioCtrl>, &'static str> {
    if blob.len() < 40 {
        return Err("dtb too short");
    }
    let magic = u32::from_be_bytes(blob[0..4].try_into().unwrap());
    if magic != 0xD00D_FEED {
        return Err("not an FDT");
    }
    let off_struct = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    let off_strings = u32::from_be_bytes(blob[12..16].try_into().unwrap()) as usize;
    let size_strings = u32::from_be_bytes(blob[32..36].try_into().unwrap()) as usize;
    let size_struct = u32::from_be_bytes(blob[36..40].try_into().unwrap()) as usize;
    if off_struct
        .checked_add(size_struct)
        .filter(|e| *e <= blob.len())
        .is_none()
        || off_strings
            .checked_add(size_strings)
            .filter(|e| *e <= blob.len())
            .is_none()
    {
        return Err("dtb struct/strings out of range");
    }
    let strings = &blob[off_strings..off_strings + size_strings];
    let mut off = off_struct;
    let end = off_struct + size_struct;
    #[derive(Default)]
    struct Open {
        name: String,
        is_ctrl: bool,
        cells: Option<u32>,
        mux: Option<u32>,
        linux_base: Option<u32>,
        ranges: bool,
        lines: bool,
    }
    let mut stack: Vec<Open> = Vec::new();
    let mut out: Vec<S19kDtbGpioCtrl> = Vec::new();
    while off + 4 <= end {
        let tag = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap());
        off += 4;
        match tag {
            0x0000_0001 => {
                let start = off;
                while off < end && blob[off] != 0 {
                    off += 1;
                }
                let name = std::str::from_utf8(&blob[start..off]).unwrap_or("").to_string();
                off = (off + 4) & !3;
                stack.push(Open {
                    name,
                    ..Open::default()
                });
            }
            0x0000_0002 => {
                if let Some(n) = stack.pop() {
                    if n.is_ctrl {
                        let path = stack
                            .iter()
                            .map(|p| p.name.as_str())
                            .chain(std::iter::once(n.name.as_str()))
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join("/");
                        out.push(S19kDtbGpioCtrl {
                            path,
                            mux: n.mux.unwrap_or(0),
                            gpio_cells: n.cells,
                            linux_gpio_base: n.linux_base,
                            has_gpio_ranges: n.ranges,
                            has_line_names: n.lines,
                        });
                    }
                }
            }
            0x0000_0003 => {
                if off + 8 > end {
                    return Err("truncated FDT_PROP");
                }
                let plen = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
                let nameoff = u32::from_be_bytes(blob[off + 4..off + 8].try_into().unwrap()) as usize;
                off += 8;
                if off + plen > end {
                    return Err("truncated FDT prop value");
                }
                let val = &blob[off..off + plen];
                off = (off + plen + 3) & !3;
                let pname = fdt_string(strings, nameoff);
                if let Some(cur) = stack.last_mut() {
                    match pname.as_str() {
                        "gpio-controller" => cur.is_ctrl = true,
                        "#gpio-cells" if val.len() >= 4 => {
                            cur.cells = Some(u32::from_be_bytes(val[..4].try_into().unwrap()));
                        }
                        "linux,gpio-base" if val.len() >= 4 => {
                            cur.linux_base = Some(u32::from_be_bytes(val[..4].try_into().unwrap()));
                        }
                        "gpio-ranges" => cur.ranges = true,
                        "gpio-line-names" => cur.lines = true,
                        "reg" if cur.mux.is_none() && val.len() >= 8 => {
                            cur.mux = Some(u32::from_be_bytes(val[4..8].try_into().unwrap()));
                        }
                        _ => {}
                    }
                }
            }
            0x0000_0009 => break,
            _ => {}
        }
    }
    Ok(out)
}

/// Admit the two AXG gpiochips. Does not emit linux gpio 437.
pub fn admit_s19k_s30v_axg_gpio_controllers(
    ctrls: &[S19kDtbGpioCtrl],
) -> Result<(), &'static str> {
    let periphs = ctrls
        .iter()
        .find(|c| c.mux == S19K_AXG_PERIPHS_MUX)
        .ok_or("s30v missing periphs gpio mux 0xff634480")?;
    let ao = ctrls
        .iter()
        .find(|c| c.mux == S19K_AXG_AOBUS_MUX)
        .ok_or("s30v missing aobus gpio mux 0xff800014")?;
    if periphs.gpio_cells != Some(S19K_AXG_GPIO_CELLS) || ao.gpio_cells != Some(S19K_AXG_GPIO_CELLS)
    {
        return Err("AXG #gpio-cells is 2");
    }
    Ok(())
}

/// 437 = vendor pin_base 411 + GPIOA_0(26). meson1 has neither cell.
pub fn refuse_s19k_dt_math_as_gpio437(ctrls: &[S19kDtbGpioCtrl]) -> Result<(), &'static str> {
    if ctrls.iter().any(|c| {
        c.linux_gpio_base == Some(S19K_AXG_VENDOR_GPIOCHIP_BASE) && c.has_line_names
    }) {
        return Ok(());
    }
    Err("437 is 4.9 gpiochip.base 411 + GPIOA_0(26); meson1 has no linux,gpio-base or line-names")
}

pub fn refuse_s19k_vendor_gpiochip_base_as_dt_cell(
    base: Option<u32>,
) -> Result<(), &'static str> {
    if base.is_none() {
        return Err("linux,gpio-base 411 is not a meson1 cell; it is 4.9 gpiolib pin_base");
    }
    Ok(())
}

pub fn refuse_s19k_gpioao3_local_as_gpio437() -> Result<(), &'static str> {
    Err("GPIOAO_3 is AO local 3 (sysfs 500 if AO base=497), not periphs 26 / gpio437")
}

pub fn admit_s19k_usb_uboot_gpioao3_offset(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_GPIOAO3_OFF;
    if blob.len() < off + S19K_USB_UBOOT_GPIOAO3.len() {
        return Err("USB UBOOT shorter than GPIOAO_3 offset");
    }
    if &blob[off..off + S19K_USB_UBOOT_GPIOAO3.len()] != S19K_USB_UBOOT_GPIOAO3.as_bytes() {
        return Err("USB UBOOT GPIOAO_3 is at file offset 675920");
    }
    Ok(())
}

/// Packed USB UBOOT is not a NUL table of GPIOAO_0..13.
pub fn refuse_s19k_usb_uboot_gpioao_as_pin_table(blob: &[u8]) -> Result<(), &'static str> {
    let has_family = ["GPIOAO_0", "GPIOAO_1", "GPIOAO_2", "GPIOAO_4", "GPIOAO_5"]
        .iter()
        .any(|n| blob.windows(n.len()).any(|w| w == n.as_bytes()));
    if has_family {
        return Ok(());
    }
    Err("USB UBOOT has one packed GPIOAO_3, not an AO pin-name table")
}

pub fn admit_s19k_usb_uboot_packed_gpio_word(blob: &[u8]) -> Result<(), &'static str> {
    let off = S19K_USB_UBOOT_GPIO_WORD_OFF;
    if blob.len() < S19K_USB_UBOOT_GPIOAO3_OFF + 8 {
        return Err("USB UBOOT shorter than packed gpio neighborhood");
    }
    if &blob[off..off + 5] != b"gpio " {
        return Err("USB UBOOT packed gpio word is at 675911");
    }
    if off + 9 != S19K_USB_UBOOT_GPIOAO3_OFF {
        return Err("gpio word is 9 bytes before GPIOAO_3");
    }
    if &blob[off + 5..S19K_USB_UBOOT_GPIOAO3_OFF] == b"GPIO" {
        return Err("packed gap is not ASCII GPIO");
    }
    Ok(())
}

pub fn refuse_s19k_usb_uboot_contiguous_gpio_cmd(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"gpio GPIOAO_3".len()).any(|w| w == b"gpio GPIOAO_3") {
        return Ok(());
    }
    Err("USB UBOOT has no contiguous gpio GPIOAO_3 command; 4 packed bytes sit between gpio and GPIOAO_3")
}

pub fn admit_s19k_uboot_gpioao3_from_end(blob_len: usize, gpio_off: usize) -> Result<(), &'static str> {
    if blob_len.saturating_sub(gpio_off) != S19K_UBOOT_GPIOAO3_FROM_END {
        return Err("USB/SDC UBOOT GPIOAO_3 is 93104 bytes from EOF");
    }
    Ok(())
}

pub fn admit_s19k_uboot_packed_gpioao3_seq(blob: &[u8], gpio_off: usize) -> Result<(), &'static str> {
    let start = gpio_off.saturating_sub(S19K_UBOOT_PACKED_GPIOAO3.len() - S19K_USB_UBOOT_GPIOAO3.len());
    if start + S19K_UBOOT_PACKED_GPIOAO3.len() > blob.len() {
        return Err("packed GPIOAO_3 sequence out of range");
    }
    if &blob[start..start + S19K_UBOOT_PACKED_GPIOAO3.len()] != S19K_UBOOT_PACKED_GPIOAO3 {
        return Err("USB/SDC UBOOT share packed gpio .. GPIOAO_3 sequence");
    }
    Ok(())
}

pub fn admit_s19k_usb_uboot_packed_console(blob: &[u8]) -> Result<(), &'static str> {
    if !blob
        .windows(S19K_USB_UBOOT_PACKED_CONSOLE.len())
        .any(|w| w == S19K_USB_UBOOT_PACKED_CONSOLE)
        || !blob
            .windows(S19K_USB_UBOOT_PACKED_EARLYCON.len())
            .any(|w| w == S19K_USB_UBOOT_PACKED_EARLYCON)
    {
        return Err("USB UBOOT packed stream names console=ttyS0 and uart,0xff803000");
    }
    Ok(())
}

pub fn refuse_s19k_usb_uboot_packed_as_nand_env(blob: &[u8]) -> Result<(), &'static str> {
    if blob.windows(b"recover_env=".len()).any(|w| w == b"recover_env=")
        || blob.windows(b"nandrecovery_env=".len()).any(|w| w == b"nandrecovery_env=")
    {
        return Ok(());
    }
    Err("USB UBOOT packed fragments are not a recover_env import")
}

pub fn admit_vnish_ao_uart0_is_console_mmio(mmio: u32) -> Result<(), &'static str> {
    if mmio != VNISH_S19K_AML_AO_UART0_MMIO {
        return Err("AO serial@3000 is 0xFF803000 (matches .78 console)");
    }
    Ok(())
}

/// DTB stock names (misc/recovery/boot/config/nvdata) are not live BOS names.
pub fn refuse_s19k_dtb_stock_names_as_78_linux(names: &[&str]) -> Result<(), &'static str> {
    if names.iter().any(|n| {
        matches!(
            *n,
            "misc" | "recovery" | "boot" | "config" | "nvdata"
        )
    }) {
        return Err("DTB nand_partition stock names are not `a lab unit` Linux mtd names");
    }
    Ok(())
}

pub fn admit_s19k_78_dtb_nand(layout: &S19kDtbNandLayout) -> Result<(), &'static str> {
    if layout.plat_names != ["bootloader".to_string(), "nandnormal".to_string()] {
        return Err("DTB plat-names must be bootloader + nandnormal");
    }
    if layout.bootloader_chip_num != Some(S19K_78_BOOTLOADER_CHIP_NUM) {
        return Err("DTB bootloader chip_num is 1");
    }
    if layout.nandnormal_chip_num != Some(S19K_78_NANDNORMAL_CHIP_NUM) {
        return Err("DTB nandnormal chip_num is 2");
    }
    if layout.nandnormal_plane_mode.as_deref() != Some(S19K_78_NANDNORMAL_PLANE_MODE) {
        return Err("DTB nandnormal plane_mode is twoplane");
    }
    let nv = layout
        .parts
        .iter()
        .find(|p| p.name == "nvdata")
        .ok_or("DTB nand_partition missing nvdata")?;
    classify_s19k_dtb_nvdata(nv)?;
    Ok(())
}

pub fn parse_s19k_aml_nand_dtb(blob: &[u8]) -> Result<S19kDtbNandLayout, &'static str> {
    if blob.len() < 40 {
        return Err("dtb too short");
    }
    let magic = u32::from_be_bytes(blob[0..4].try_into().unwrap());
    if magic != 0xD00D_FEED {
        return Err("not an FDT");
    }
    let off_struct = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    let off_strings = u32::from_be_bytes(blob[12..16].try_into().unwrap()) as usize;
    let size_strings = u32::from_be_bytes(blob[32..36].try_into().unwrap()) as usize;
    let size_struct = u32::from_be_bytes(blob[36..40].try_into().unwrap()) as usize;
    if off_struct
        .checked_add(size_struct)
        .filter(|e| *e <= blob.len())
        .is_none()
        || off_strings
            .checked_add(size_strings)
            .filter(|e| *e <= blob.len())
            .is_none()
    {
        return Err("dtb struct/strings out of range");
    }
    let strings = &blob[off_strings..off_strings + size_strings];
    let mut off = off_struct;
    let end = off_struct + size_struct;
    let mut path: Vec<String> = Vec::new();
    let mut plat_names = Vec::new();
    let mut bootloader_chip_num = None;
    let mut nandnormal_chip_num = None;
    let mut nandnormal_plane_mode = None;
    let mut parts: Vec<S19kDtbNandPart> = Vec::new();
    while off + 4 <= end {
        let tag = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap());
        off += 4;
        match tag {
            0x0000_0001 => {
                let start = off;
                while off < end && blob[off] != 0 {
                    off += 1;
                }
                let name = std::str::from_utf8(&blob[start..off]).unwrap_or("").to_string();
                off = (off + 4) & !3;
                path.push(name);
            }
            0x0000_0002 => {
                path.pop();
            }
            0x0000_0003 => {
                if off + 8 > end {
                    return Err("truncated FDT_PROP");
                }
                let plen = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap()) as usize;
                let nameoff = u32::from_be_bytes(blob[off + 4..off + 8].try_into().unwrap()) as usize;
                off += 8;
                if off + plen > end {
                    return Err("truncated FDT prop value");
                }
                let val = &blob[off..off + plen];
                off = (off + plen + 3) & !3;
                let pname = fdt_string(strings, nameoff);
                let pth = path
                    .iter()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("/");
                if pth == "mtd_nand" && pname == "plat-names" {
                    plat_names = split_cstrs(val);
                } else if pth == "mtd_nand/bootloader" && pname == "chip_num" && val.len() >= 4 {
                    bootloader_chip_num = Some(u32::from_be_bytes(val[..4].try_into().unwrap()));
                } else if pth == "mtd_nand/nandnormal" && pname == "chip_num" && val.len() >= 4 {
                    nandnormal_chip_num = Some(u32::from_be_bytes(val[..4].try_into().unwrap()));
                } else if pth == "mtd_nand/nandnormal" && pname == "plane_mode" {
                    nandnormal_plane_mode = split_cstrs(val).into_iter().next();
                } else if pth.starts_with("mtd_nand/nand_partition/")
                    && (pname == "offset" || pname == "size")
                    && val.len() >= 8
                {
                    let part_name = path.last().cloned().unwrap_or_default();
                    let word = u64::from_be_bytes(val[..8].try_into().unwrap());
                    if let Some(existing) = parts.iter_mut().find(|p| p.name == part_name) {
                        if pname == "offset" {
                            existing.offset = word;
                        } else {
                            existing.size = word;
                        }
                    } else {
                        parts.push(S19kDtbNandPart {
                            name: part_name,
                            offset: if pname == "offset" { word } else { 0 },
                            size: if pname == "size" { word } else { 0 },
                        });
                    }
                }
            }
            0x0000_0004 => {}
            0x0000_0009 => break,
            _ => return Err("unknown FDT tag"),
        }
    }
    if plat_names.is_empty() && parts.is_empty() {
        return Err("no mtd_nand partition data");
    }
    Ok(S19kDtbNandLayout {
        plat_names,
        bootloader_chip_num,
        nandnormal_chip_num,
        nandnormal_plane_mode,
        parts,
    })
}

fn fdt_string(strings: &[u8], off: usize) -> String {
    if off >= strings.len() {
        return String::new();
    }
    let end = strings[off..]
        .iter()
        .position(|b| *b == 0)
        .map(|i| off + i)
        .unwrap_or(strings.len());
    std::str::from_utf8(&strings[off..end])
        .unwrap_or("")
        .to_string()
}

fn split_cstrs(val: &[u8]) -> Vec<String> {
    val.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn align4(buf: &mut Vec<u8>) {
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }

    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn emit_node(struct_buf: &mut Vec<u8>, name: &str) {
        put_u32(struct_buf, 1);
        struct_buf.extend_from_slice(name.as_bytes());
        struct_buf.push(0);
        align4(struct_buf);
    }

    fn emit_end(struct_buf: &mut Vec<u8>) {
        put_u32(struct_buf, 2);
    }

    fn intern(strings: &mut Vec<u8>, s: &str) -> u32 {
        let off = strings.len() as u32;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        off
    }

    fn emit_prop(struct_buf: &mut Vec<u8>, strings: &mut Vec<u8>, name: &str, val: &[u8]) {
        put_u32(struct_buf, 3);
        put_u32(struct_buf, val.len() as u32);
        put_u32(struct_buf, intern(strings, name));
        struct_buf.extend_from_slice(val);
        align4(struct_buf);
    }

    fn build_dtb() -> Vec<u8> {
        let mut strings = Vec::new();
        let mut st = Vec::new();
        emit_node(&mut st, "");
        emit_node(&mut st, "mtd_nand");
        emit_prop(
            &mut st,
            &mut strings,
            "plat-names",
            b"bootloader\0nandnormal\0",
        );
        emit_node(&mut st, "bootloader");
        emit_prop(&mut st, &mut strings, "chip_num", &1u32.to_be_bytes());
        emit_end(&mut st);
        emit_node(&mut st, "nandnormal");
        emit_prop(&mut st, &mut strings, "chip_num", &2u32.to_be_bytes());
        emit_prop(&mut st, &mut strings, "plane_mode", b"twoplane\0");
        emit_end(&mut st);
        emit_node(&mut st, "nand_partition");
        emit_node(&mut st, "nvdata");
        emit_prop(
            &mut st,
            &mut strings,
            "offset",
            &u64::MAX.to_be_bytes(),
        );
        emit_prop(&mut st, &mut strings, "size", &0u64.to_be_bytes());
        emit_end(&mut st);
        emit_end(&mut st);
        emit_end(&mut st);
        emit_end(&mut st);
        put_u32(&mut st, 9);

        let mut out = vec![0u8; 40];
        let rsv_off = 40usize;
        let mut body = vec![0u8; 16];
        let struct_off = rsv_off + body.len();
        body.extend_from_slice(&st);
        let strings_off = rsv_off + body.len();
        body.extend_from_slice(&strings);
        let totalsize = 40 + body.len();
        out.clear();
        out.extend_from_slice(&0xD00D_FEEDu32.to_be_bytes());
        out.extend_from_slice(&(totalsize as u32).to_be_bytes());
        out.extend_from_slice(&(struct_off as u32).to_be_bytes());
        out.extend_from_slice(&(strings_off as u32).to_be_bytes());
        out.extend_from_slice(&(rsv_off as u32).to_be_bytes());
        out.extend_from_slice(&17u32.to_be_bytes());
        out.extend_from_slice(&16u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_be_bytes());
        out.extend_from_slice(&(st.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn be64_pair(addr: u32, size: u32) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[4..8].copy_from_slice(&addr.to_be_bytes());
        a[12..16].copy_from_slice(&size.to_be_bytes());
        a
    }

    fn build_gpio_dtb() -> Vec<u8> {
        let mut strings = Vec::new();
        let mut st = Vec::new();
        emit_node(&mut st, "");
        emit_node(&mut st, "pinctrl@ff634480");
        emit_node(&mut st, "banks@ff634480");
        emit_prop(&mut st, &mut strings, "gpio-controller", &[]);
        emit_prop(&mut st, &mut strings, "#gpio-cells", &2u32.to_be_bytes());
        emit_prop(
            &mut st,
            &mut strings,
            "reg",
            &be64_pair(S19K_AXG_PERIPHS_MUX, 0x40),
        );
        emit_end(&mut st);
        emit_end(&mut st);
        emit_node(&mut st, "pinctrl@ff800014");
        emit_node(&mut st, "ao-bank@ff800014");
        emit_prop(&mut st, &mut strings, "gpio-controller", &[]);
        emit_prop(&mut st, &mut strings, "#gpio-cells", &2u32.to_be_bytes());
        emit_prop(
            &mut st,
            &mut strings,
            "reg",
            &be64_pair(S19K_AXG_AOBUS_MUX, 0x08),
        );
        emit_end(&mut st);
        emit_end(&mut st);
        emit_end(&mut st);
        put_u32(&mut st, 9);

        let rsv_off = 40usize;
        let mut body = vec![0u8; 16];
        let struct_off = rsv_off + body.len();
        body.extend_from_slice(&st);
        let strings_off = rsv_off + body.len();
        body.extend_from_slice(&strings);
        let mut out = Vec::new();
        out.extend_from_slice(&0xD00D_FEEDu32.to_be_bytes());
        out.extend_from_slice(&((40 + body.len()) as u32).to_be_bytes());
        out.extend_from_slice(&(struct_off as u32).to_be_bytes());
        out.extend_from_slice(&(strings_off as u32).to_be_bytes());
        out.extend_from_slice(&(rsv_off as u32).to_be_bytes());
        out.extend_from_slice(&17u32.to_be_bytes());
        out.extend_from_slice(&16u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_be_bytes());
        out.extend_from_slice(&(st.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parse_dtb_and_refuse_linux_nvdata_alias() {
        let blob = build_dtb();
        let layout = parse_s19k_aml_nand_dtb(&blob).unwrap();
        assert!(admit_s19k_78_dtb_nand(&layout).is_ok());
        assert_eq!(
            classify_s19k_uboot_nand_device(1).unwrap(),
            S19kUbootNandDevice::Nandnormal
        );
        assert_eq!(
            classify_s19k_uboot_nand_device(0).unwrap(),
            S19kUbootNandDevice::Bootloader
        );
        assert!(classify_s19k_uboot_nand_device(2).is_err());
        assert!(refuse_s19k_78_linux_mtd_as_uboot_nvdata(S19K_78_PROC_MTD_NAMES).is_err());
        assert!(refuse_s19k_78_linux_mtd_as_uboot_nvdata(&[
            "bootloader",
            "tpl",
            "stock_system",
            "stock_config",
            "overlay",
            "system",
            "nvdata"
        ])
        .is_ok());
        assert!(refuse_s19k_20231115_emmc_nvdata_as_aml_nand(
            "<physical_partition type=\"emmc\"><partition label=\"nvdata\"/></physical_partition>"
        )
        .is_err());
        assert!(refuse_s19k_s19j_mtd6_nvdata_as_78(&[
            "bootloader", "tpl", "misc", "recovery", "boot", "config", "nvdata"
        ])
        .is_err());
        assert!(refuse_s19k_dtb_stock_names_as_78_linux(&["tpl", "misc", "nvdata"]).is_err());
        assert!(refuse_s19k_dtb_stock_names_as_78_linux(S19K_78_PROC_MTD_NAMES).is_ok());
        assert!(refuse_s19k_dtb_chip_num_as_linux_mtd_count(2).is_err());
        assert_eq!(layout.nandnormal_plane_mode.as_deref(), Some("twoplane"));
        assert_eq!(S19K_78_LUXOS_DTB_BYTES, 45_596);
        assert!(parse_s19k_aml_nand_dtb(b"not-fdt").is_err());
        assert_ne!(VNISH_S19K_AML_DTB_BYTES, S19K_78_LUXOS_DTB_BYTES);
        assert!(!VNISH_S19K_AML_DTB_HAS_PWR_CONTROL);
        let mut vnish = vec![0u8; VNISH_S19K_AML_DTB_BYTES];
        vnish[0..4].copy_from_slice(&[0xd0, 0x0d, 0xfe, 0xed]);
        let mut o = 64usize;
        for s in [
            "serial0",
            "serial1",
            "serial2",
            "serial3",
            "serial@3000",
            "serial@4000",
            "serial@ffd24000",
            "serial@ffd23000",
        ] {
            vnish[o..o + s.len()].copy_from_slice(s.as_bytes());
            o += s.len() + 1;
        }
        assert!(admit_vnish_s19k_aml_soc_dtb(&vnish).is_ok());
        vnish[o..o + 11].copy_from_slice(b"PWR_CONTROL");
        assert!(admit_vnish_s19k_aml_soc_dtb(&vnish).is_err());
        assert!(refuse_vnish_s19k_dtb_as_gpio437_polarity().is_err());
        assert!(refuse_vnish_dtb_serial_alias_as_ttys_map().is_err());
        assert!(admit_vnish_ao_uart0_is_console_mmio(0xFF80_3000).is_ok());
        assert_eq!(
            VNISH_S19K_AML_AO_UART0_MMIO,
            crate::s19k_am3_install::S19K_78_CONSOLE_MMIO
        );
        let miner = build_dtb();
        let g1 = miner.clone();
        // header-only stand-in; wrapper offsets matter more than inner parse here
        let mut packed = Vec::new();
        packed.extend_from_slice(S19K_AML_MULTI_DTB_MAGIC);
        packed.extend_from_slice(&S19K_AML_MULTI_DTB_VERSION.to_le_bytes());
        packed.extend_from_slice(&2u32.to_le_bytes());
        fn pad16(s: &str) -> [u8; 16] {
            let mut a = [b' '; 16];
            let b = s.as_bytes();
            a[..b.len()].copy_from_slice(b);
            a
        }
        let e0_off = 12 + 2 * S19K_AML_MULTI_DTB_ENTRY_STRIDE;
        let e0_off = (e0_off + 0x7FF) & !0x7FF;
        assert_eq!(e0_off, 0x800);
        packed.extend_from_slice(&pad16(S19K_FACTORY_MESON1_SOC));
        packed.extend_from_slice(&pad16(S19K_FACTORY_MESON1_PLAT));
        packed.extend_from_slice(&pad16("g1"));
        packed.extend_from_slice(&S19K_FACTORY_MESON1_ENTRY0_OFF.to_le_bytes());
        packed.extend_from_slice(&(g1.len() as u32).to_le_bytes());
        packed.extend_from_slice(&pad16(S19K_FACTORY_MESON1_SOC));
        packed.extend_from_slice(&pad16(S19K_FACTORY_MESON1_PLAT));
        packed.extend_from_slice(&pad16(S19K_FACTORY_MESON1_VARIANT_S30V));
        packed.extend_from_slice(&S19K_FACTORY_MESON1_ENTRY1_OFF.to_le_bytes());
        packed.extend_from_slice(&(miner.len() as u32).to_le_bytes());
        packed.resize(S19K_FACTORY_MESON1_ENTRY0_OFF as usize, 0);
        packed.extend_from_slice(&g1);
        packed.resize(S19K_FACTORY_MESON1_ENTRY1_OFF as usize, 0);
        packed.extend_from_slice(&miner);
        let multi = parse_s19k_aml_multi_dtb(&packed).unwrap();
        assert!(admit_s19k_factory_meson1_header(&multi).is_ok());
        assert_eq!(
            classify_s19k_factory_meson1_variant(&multi.entries[0].variant).unwrap(),
            S19kFactoryMeson1Kind::G1AndroidTv
        );
        assert_eq!(
            classify_s19k_factory_meson1_variant(&multi.entries[1].variant).unwrap(),
            S19kFactoryMeson1Kind::S30vMinerStock
        );
        assert!(refuse_s19k_factory_g1_as_miner_nand(S19kFactoryMeson1Kind::G1AndroidTv).is_err());
        assert!(refuse_s19k_factory_g1_as_miner_nand(S19kFactoryMeson1Kind::S30vMinerStock).is_ok());
        let s30v_fdt = s19k_aml_multi_dtb_inner(&packed, &multi.entries[1]).unwrap();
        let s30v = parse_s19k_aml_nand_dtb(s30v_fdt).unwrap();
        assert!(admit_s19k_78_dtb_nand(&s30v).is_ok());
        let stock_parts = [
            S19kDtbNandPart {
                name: "tpl".into(),
                offset: 0,
                size: 0,
            },
            S19kDtbNandPart {
                name: "misc".into(),
                offset: 0,
                size: S19K_FACTORY_S30V_MISC_BYTES,
            },
            S19kDtbNandPart {
                name: "recovery".into(),
                offset: 0,
                size: S19K_FACTORY_S30V_RECOVERY_BYTES,
            },
            S19kDtbNandPart {
                name: "boot".into(),
                offset: 0,
                size: S19K_FACTORY_S30V_BOOT_BYTES,
            },
            S19kDtbNandPart {
                name: "config".into(),
                offset: 0,
                size: S19K_FACTORY_S30V_CONFIG_BYTES,
            },
            S19kDtbNandPart {
                name: "nvdata".into(),
                offset: u64::MAX,
                size: 0,
            },
        ];
        assert!(admit_s19k_factory_s30v_nand_sizes(&stock_parts).is_ok());
        assert!(refuse_s19k_factory_s30v_sizes_as_78_linux(&stock_parts).is_err());
        assert!(refuse_s19k_factory_s30v_sizes_as_78_linux(&[]).is_ok());
        assert!(refuse_s19k_factory_meson1_as_gpio437().is_err());
        assert!(refuse_s19k_usb_uboot_gpioao3_as_gpio437(b"gpio GPIOAO_3 detect").is_err());
        assert!(refuse_s19k_usb_uboot_gpioao3_as_gpio437(b"no ao pin").is_ok());
        assert!(refuse_s19k_usb_uboot_as_recover_env(b"S19k-Pro_BHB56XXX").is_err());
        assert!(refuse_s19k_usb_uboot_as_recover_env(b"run recover_env").is_ok());
        assert!(refuse_s19k_meson1_gzip_as_raw_fdt(&[0x1F, 0x8B, 0x08]).is_err());
        assert!(refuse_s19k_meson1_gzip_as_raw_fdt(S19K_AML_MULTI_DTB_MAGIC).is_ok());
        assert_eq!(
            classify_s19k_factory_meson1_i2c(b"mcu6350@40 tas5782m_pu5").unwrap(),
            S19kFactoryMeson1Kind::S30vMinerStock
        );
        assert_eq!(
            classify_s19k_factory_meson1_i2c(b"tas5707_36 tlv320adc3101").unwrap(),
            S19kFactoryMeson1Kind::G1AndroidTv
        );
        assert!(classify_s19k_factory_meson1_i2c(b"no i2c roster").is_err());
        assert!(refuse_s19k_factory_s30v_mcu6350_as_gpio437().is_err());
        assert!(refuse_s19k_factory_s30v_serial_as_ttys_map().is_err());
        assert!(admit_s19k_factory_pca9557_ledring(b"aml_pca9557@0x1f aml, ledring").is_ok());
        assert!(admit_s19k_factory_pca9557_ledring(b"no expander").is_err());
        let mut i2c = vec![0u8; S19K_USB_UBOOT_I2C_MW_1F_OFF + 24];
        i2c[S19K_USB_UBOOT_I2C_MW_1F_OFF..S19K_USB_UBOOT_I2C_MW_1F_OFF + 17]
            .copy_from_slice(S19K_USB_UBOOT_I2C_MW_1F);
        assert!(admit_s19k_usb_uboot_i2c_mw_1f(&i2c).is_ok());
        assert!(refuse_s19k_i2c_mw_1f_as_gpio437().is_err());
        let mut setenv = vec![0u8; S19K_USB_UBOOT_SETENV_OFF + 24];
        setenv[S19K_USB_UBOOT_SETENV_OFF..S19K_USB_UBOOT_SETENV_OFF + 10]
            .copy_from_slice(S19K_USB_UBOOT_SETENV_PREFIX);
        setenv.extend_from_slice(S19K_USB_UBOOT_MTDIDS_QUOTED);
        assert!(admit_s19k_usb_uboot_packed_setenv(&setenv).is_ok());
        assert!(refuse_s19k_usb_setenv_as_bootcmd(&setenv).is_err());
        assert!(refuse_s19k_usb_setenv_as_firstboot(&setenv).is_err());
        assert!(refuse_s19k_usb_quoted_mtdids_as_mtdparts(&setenv).is_err());
        let mut logo = vec![0u8; S19K_USB_UBOOT_BASEBAND_OFF + S19K_USB_UBOOT_BASEBAND.len()];
        logo[S19K_USB_UBOOT_LOGO_OFF..S19K_USB_UBOOT_LOGO_OFF + S19K_USB_UBOOT_LOGO.len()]
            .copy_from_slice(S19K_USB_UBOOT_LOGO);
        logo[S19K_USB_UBOOT_ANDROID9_OFF
            ..S19K_USB_UBOOT_ANDROID9_OFF + S19K_USB_UBOOT_ANDROID9.len()]
            .copy_from_slice(S19K_USB_UBOOT_ANDROID9);
        logo[S19K_USB_UBOOT_HARDWARE_OFF
            ..S19K_USB_UBOOT_HARDWARE_OFF + S19K_USB_UBOOT_HARDWARE.len()]
            .copy_from_slice(S19K_USB_UBOOT_HARDWARE);
        logo[S19K_USB_UBOOT_IOGIC_OFF..S19K_USB_UBOOT_IOGIC_OFF + S19K_USB_UBOOT_IOGIC.len()]
            .copy_from_slice(S19K_USB_UBOOT_IOGIC);
        logo[S19K_USB_UBOOT_BASEBAND_OFF
            ..S19K_USB_UBOOT_BASEBAND_OFF + S19K_USB_UBOOT_BASEBAND.len()]
            .copy_from_slice(S19K_USB_UBOOT_BASEBAND);
        assert!(admit_s19k_usb_uboot_packed_logo(&logo).is_ok());
        assert!(admit_s19k_usb_uboot_packed_android9(&logo).is_ok());
        assert!(refuse_s19k_usb_logo_as_nand_bootargs().is_err());
        assert!(refuse_s19k_usb_android9_as_s19k_rootfs().is_err());
        assert!(admit_s19k_usb_uboot_packed_hardware(&logo).is_ok());
        assert!(admit_s19k_usb_uboot_packed_iogic(&logo).is_ok());
        assert!(admit_s19k_usb_uboot_packed_baseband(&logo).is_ok());
        assert!(refuse_s19k_usb_hardware_as_board_id().is_err());
        assert!(refuse_s19k_usb_iogic_as_amlogic().is_err());
        let mut atf = Vec::new();
        for p in S19K_USB_UBOOT_PLAT_AMLOGIC {
            atf.extend_from_slice(p);
            atf.push(0);
        }
        atf.extend_from_slice(S19K_USB_UBOOT_AMLOGIC_SECURE);
        assert!(admit_s19k_usb_uboot_atf_plat_amlogic(&atf).is_ok());
        assert!(admit_s19k_usb_uboot_atf_plat_amlogic(&logo).is_err());
        assert!(refuse_s19k_usb_plat_amlogic_as_miner_nand().is_err());
        let mut packed_cmd = vec![0u8; S19K_USB_UBOOT_ACMDLIN_OFF + S19K_USB_UBOOT_ACMDLIN.len()];
        packed_cmd[S19K_USB_UBOOT_UILD_EXPECT_OFF
            ..S19K_USB_UBOOT_UILD_EXPECT_OFF + S19K_USB_UBOOT_UILD_EXPECT.len()]
            .copy_from_slice(S19K_USB_UBOOT_UILD_EXPECT);
        packed_cmd[S19K_USB_UBOOT_ACMDLIN_OFF
            ..S19K_USB_UBOOT_ACMDLIN_OFF + S19K_USB_UBOOT_ACMDLIN.len()]
            .copy_from_slice(S19K_USB_UBOOT_ACMDLIN);
        assert!(admit_s19k_usb_uboot_packed_uild_expect(&packed_cmd).is_ok());
        assert!(admit_s19k_usb_uboot_packed_acmdlin(&packed_cmd).is_ok());
        assert!(refuse_s19k_usb_uild_expect_as_build_prop().is_err());
        assert!(refuse_s19k_usb_acmdlin_as_nand_bootargs().is_err());
        assert!(admit_s19k_usb_uboot_saradc_channel2(S19K_USB_UBOOT_SARADC_CH2).is_ok());
        assert!(refuse_s19k_usb_saradc_ch2_as_bl2_error().is_err());
        assert!(refuse_s19k_usb_saradc_ch2_as_miner_adc().is_err());
        assert_eq!(S19K_USB_UBOOT_SARADC_CH2_OFF, 686_169);
        let mut usb_ctrl = vec![0u8; S19K_USB_UBOOT_SPEED_ENUM_OFF + S19K_USB_UBOOT_SPEED_ENUM.len()];
        usb_ctrl[S19K_USB_UBOOT_TXFIFO_FULL_OFF
            ..S19K_USB_UBOOT_TXFIFO_FULL_OFF + S19K_USB_UBOOT_TXFIFO_FULL.len()]
            .copy_from_slice(S19K_USB_UBOOT_TXFIFO_FULL);
        usb_ctrl[S19K_USB_UBOOT_SPEED_ENUM_OFF
            ..S19K_USB_UBOOT_SPEED_ENUM_OFF + S19K_USB_UBOOT_SPEED_ENUM.len()]
            .copy_from_slice(S19K_USB_UBOOT_SPEED_ENUM);
        assert!(admit_s19k_usb_uboot_txfifo_speed_enum(&usb_ctrl).is_ok());
        assert!(refuse_s19k_usb_txfifo_as_hash_fifo().is_err());
        assert!(refuse_s19k_usb_speed_enum_as_chip_enum().is_err());
        assert_eq!(S19K_USB_UBOOT_TXFIFO_FULL_OFF, 729_904);
        assert_eq!(S19K_USB_UBOOT_SPEED_ENUM_OFF, 729_940);
        let mut atf_mask = vec![0u8; S19K_USB_UBOOT_ADDR_MASK_OFF + S19K_USB_UBOOT_ADDR_MASK.len()];
        atf_mask[S19K_USB_UBOOT_ADDR_MASK_OFF
            ..S19K_USB_UBOOT_ADDR_MASK_OFF + S19K_USB_UBOOT_ADDR_MASK.len()]
            .copy_from_slice(S19K_USB_UBOOT_ADDR_MASK);
        assert!(admit_s19k_usb_uboot_addr_mask(&atf_mask).is_ok());
        assert!(refuse_s19k_usb_addr_mask_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_ADDR_MASK_OFF, 257_284);
        let mut ramoops = vec![0u8; S19K_USB_UBOOT_RAMOOPS_OFF + S19K_USB_UBOOT_RAMOOPS.len()];
        ramoops[S19K_USB_UBOOT_RAMOOPS_OFF
            ..S19K_USB_UBOOT_RAMOOPS_OFF + S19K_USB_UBOOT_RAMOOPS.len()]
            .copy_from_slice(S19K_USB_UBOOT_RAMOOPS);
        assert!(admit_s19k_usb_uboot_ramoops(&ramoops).is_ok());
        assert!(refuse_s19k_usb_ramoops_as_recover_env().is_err());
        assert_eq!(S19K_USB_UBOOT_RAMOOPS_OFF, 674_787);
        let mut cortex = vec![0u8; S19K_USB_UBOOT_CORTEX_TASK_OFF + S19K_USB_UBOOT_CORTEX_TASK.len()];
        cortex[S19K_USB_UBOOT_EXCEPTION_OFF
            ..S19K_USB_UBOOT_EXCEPTION_OFF + S19K_USB_UBOOT_EXCEPTION.len()]
            .copy_from_slice(S19K_USB_UBOOT_EXCEPTION);
        cortex[S19K_USB_UBOOT_PSTACK_OFF
            ..S19K_USB_UBOOT_PSTACK_OFF + S19K_USB_UBOOT_PSTACK.len()]
            .copy_from_slice(S19K_USB_UBOOT_PSTACK);
        cortex[S19K_USB_UBOOT_CORTEX_TASK_OFF
            ..S19K_USB_UBOOT_CORTEX_TASK_OFF + S19K_USB_UBOOT_CORTEX_TASK.len()]
            .copy_from_slice(S19K_USB_UBOOT_CORTEX_TASK);
        assert!(admit_s19k_usb_uboot_cortex_exception(&cortex).is_ok());
        assert!(refuse_s19k_usb_cortex_exception_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_cortex_task_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_EXCEPTION_OFF, 41_822);
        assert_eq!(S19K_USB_UBOOT_PSTACK_OFF, 41_995);
        assert_eq!(S19K_USB_UBOOT_CORTEX_TASK_OFF, 42_807);
        let mut ec = vec![0u8; S19K_USB_UBOOT_TASK_READY_OFF + S19K_USB_UBOOT_TASK_READY.len()];
        ec[S19K_USB_UBOOT_WAIT_EVT_OFF
            ..S19K_USB_UBOOT_WAIT_EVT_OFF + S19K_USB_UBOOT_WAIT_EVT.len()]
            .copy_from_slice(S19K_USB_UBOOT_WAIT_EVT);
        ec[S19K_USB_UBOOT_TASK_READY_OFF
            ..S19K_USB_UBOOT_TASK_READY_OFF + S19K_USB_UBOOT_TASK_READY.len()]
            .copy_from_slice(S19K_USB_UBOOT_TASK_READY);
        assert!(admit_s19k_usb_uboot_ec_task_table(&ec).is_ok());
        assert!(refuse_s19k_usb_ec_task_table_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_task_table_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_WAIT_EVT_OFF, 42_640);
        assert_eq!(S19K_USB_UBOOT_TASK_READY_OFF, 42_692);
        let mut svc = vec![0u8; S19K_USB_UBOOT_TASK_EXIT_OFF + S19K_USB_UBOOT_TASK_EXIT.len()];
        svc[S19K_USB_UBOOT_MUTEX_LOCK_OFF
            ..S19K_USB_UBOOT_MUTEX_LOCK_OFF + S19K_USB_UBOOT_MUTEX_LOCK.len()]
            .copy_from_slice(S19K_USB_UBOOT_MUTEX_LOCK);
        svc[S19K_USB_UBOOT_SVC_HANDLER_OFF
            ..S19K_USB_UBOOT_SVC_HANDLER_OFF + S19K_USB_UBOOT_SVC_HANDLER.len()]
            .copy_from_slice(S19K_USB_UBOOT_SVC_HANDLER);
        svc[S19K_USB_UBOOT_TASK_EXIT_OFF
            ..S19K_USB_UBOOT_TASK_EXIT_OFF + S19K_USB_UBOOT_TASK_EXIT.len()]
            .copy_from_slice(S19K_USB_UBOOT_TASK_EXIT);
        assert!(admit_s19k_usb_uboot_ec_mutex_svc(&svc).is_ok());
        assert!(refuse_s19k_usb_ec_mutex_svc_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_mutex_svc_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_MUTEX_LOCK_OFF, 42_652);
        assert_eq!(S19K_USB_UBOOT_SVC_HANDLER_OFF, 42_680);
        assert_eq!(S19K_USB_UBOOT_TASK_EXIT_OFF, 42_868);
        let mut ov = vec![0u8; S19K_USB_UBOOT_STACK_OV_OFF + S19K_USB_UBOOT_STACK_OV.len()];
        ov[S19K_USB_UBOOT_TASK_SET_EVENT_OFF
            ..S19K_USB_UBOOT_TASK_SET_EVENT_OFF + S19K_USB_UBOOT_TASK_SET_EVENT.len()]
            .copy_from_slice(S19K_USB_UBOOT_TASK_SET_EVENT);
        ov[S19K_USB_UBOOT_STACK_OV_OFF
            ..S19K_USB_UBOOT_STACK_OV_OFF + S19K_USB_UBOOT_STACK_OV.len()]
            .copy_from_slice(S19K_USB_UBOOT_STACK_OV);
        assert!(admit_s19k_usb_uboot_ec_task_set_stack(&ov).is_ok());
        assert!(refuse_s19k_usb_ec_task_set_stack_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_stack_ov_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_TASK_SET_EVENT_OFF, 42_664);
        assert_eq!(S19K_USB_UBOOT_STACK_OV_OFF, 42_900);
        let mut idle = vec![0u8; S19K_USB_UBOOT_IDLE_OFF + S19K_USB_UBOOT_IDLE.len()];
        idle[S19K_USB_UBOOT_TASKS_READY_OFF
            ..S19K_USB_UBOOT_TASKS_READY_OFF + S19K_USB_UBOOT_TASKS_READY.len()]
            .copy_from_slice(S19K_USB_UBOOT_TASKS_READY);
        idle[S19K_USB_UBOOT_IDLE_OFF..S19K_USB_UBOOT_IDLE_OFF + S19K_USB_UBOOT_IDLE.len()]
            .copy_from_slice(S19K_USB_UBOOT_IDLE);
        assert!(admit_s19k_usb_uboot_ec_idle(&idle).is_ok());
        assert!(refuse_s19k_usb_ec_idle_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_idle_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_TASKS_READY_OFF, 42_928);
        assert_eq!(S19K_USB_UBOOT_IDLE_OFF, 42_940);
        let mut hooks = vec![0u8; S19K_USB_UBOOT_TIMERTASK_OFF + S19K_USB_UBOOT_TIMERTASK.len()];
        hooks[S19K_USB_UBOOT_HOOKS_OFF..S19K_USB_UBOOT_HOOKS_OFF + S19K_USB_UBOOT_HOOKS.len()]
            .copy_from_slice(S19K_USB_UBOOT_HOOKS);
        hooks[S19K_USB_UBOOT_TIMERTASK_OFF
            ..S19K_USB_UBOOT_TIMERTASK_OFF + S19K_USB_UBOOT_TIMERTASK.len()]
            .copy_from_slice(S19K_USB_UBOOT_TIMERTASK);
        assert!(admit_s19k_usb_uboot_ec_hooks_timer(&hooks).is_ok());
        assert!(refuse_s19k_usb_ec_hooks_timer_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_hooks_timer_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_HOOKS_OFF, 42_951);
        assert_eq!(S19K_USB_UBOOT_TIMERTASK_OFF, 42_957);
        let mut mbox = vec![0u8; S19K_USB_UBOOT_HIGHMAILBOX_OFF + S19K_USB_UBOOT_HIGHMAILBOX.len()];
        mbox[S19K_USB_UBOOT_LOWMAILBOX_OFF
            ..S19K_USB_UBOOT_LOWMAILBOX_OFF + S19K_USB_UBOOT_LOWMAILBOX.len()]
            .copy_from_slice(S19K_USB_UBOOT_LOWMAILBOX);
        mbox[S19K_USB_UBOOT_HIGHMAILBOX_OFF
            ..S19K_USB_UBOOT_HIGHMAILBOX_OFF + S19K_USB_UBOOT_HIGHMAILBOX.len()]
            .copy_from_slice(S19K_USB_UBOOT_HIGHMAILBOX);
        assert!(admit_s19k_usb_uboot_ec_mailbox(&mbox).is_ok());
        assert!(refuse_s19k_usb_ec_mailbox_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_mailbox_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_LOWMAILBOX_OFF, 42_967);
        assert_eq!(S19K_USB_UBOOT_HIGHMAILBOX_OFF, 42_978);
        let mut sec = vec![0u8; S19K_USB_UBOOT_USERLOWTASK_OFF + S19K_USB_UBOOT_USERLOWTASK.len()];
        sec[S19K_USB_UBOOT_SECMAILBOX_OFF
            ..S19K_USB_UBOOT_SECMAILBOX_OFF + S19K_USB_UBOOT_SECMAILBOX.len()]
            .copy_from_slice(S19K_USB_UBOOT_SECMAILBOX);
        sec[S19K_USB_UBOOT_USERLOWTASK_OFF
            ..S19K_USB_UBOOT_USERLOWTASK_OFF + S19K_USB_UBOOT_USERLOWTASK.len()]
            .copy_from_slice(S19K_USB_UBOOT_USERLOWTASK);
        assert!(admit_s19k_usb_uboot_ec_sec_userlow(&sec).is_ok());
        assert!(refuse_s19k_usb_ec_sec_userlow_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_sec_userlow_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_SECMAILBOX_OFF, 42_990);
        assert_eq!(S19K_USB_UBOOT_USERLOWTASK_OFF, 43_001);
        let mut high = vec![
            0u8;
            S19K_USB_UBOOT_USERSECURETASK_OFF + S19K_USB_UBOOT_USERSECURETASK.len()
        ];
        high[S19K_USB_UBOOT_USERHIGHTASK_OFF
            ..S19K_USB_UBOOT_USERHIGHTASK_OFF + S19K_USB_UBOOT_USERHIGHTASK.len()]
            .copy_from_slice(S19K_USB_UBOOT_USERHIGHTASK);
        high[S19K_USB_UBOOT_USERSECURETASK_OFF
            ..S19K_USB_UBOOT_USERSECURETASK_OFF + S19K_USB_UBOOT_USERSECURETASK.len()]
            .copy_from_slice(S19K_USB_UBOOT_USERSECURETASK);
        assert!(admit_s19k_usb_uboot_ec_user_high_secure(&high).is_ok());
        assert!(refuse_s19k_usb_ec_user_high_secure_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_user_high_secure_as_nandrecovery().is_err());
        assert_eq!(S19K_USB_UBOOT_USERHIGHTASK_OFF, 43_013);
        assert_eq!(S19K_USB_UBOOT_USERSECURETASK_OFF, 43_026);
        let mut adc = vec![0u8; S19K_USB_UBOOT_EMPTY_EFUSE_OFF + S19K_USB_UBOOT_EMPTY_EFUSE.len()];
        adc[S19K_USB_UBOOT_TIMERFORADC_OFF
            ..S19K_USB_UBOOT_TIMERFORADC_OFF + S19K_USB_UBOOT_TIMERFORADC.len()]
            .copy_from_slice(S19K_USB_UBOOT_TIMERFORADC);
        adc[S19K_USB_UBOOT_EMPTY_EFUSE_OFF
            ..S19K_USB_UBOOT_EMPTY_EFUSE_OFF + S19K_USB_UBOOT_EMPTY_EFUSE.len()]
            .copy_from_slice(S19K_USB_UBOOT_EMPTY_EFUSE);
        assert!(admit_s19k_usb_uboot_ec_timer_efuse(&adc).is_ok());
        assert!(refuse_s19k_usb_ec_timer_efuse_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ec_timer_efuse_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_empty_efuse_as_otp_decrypt().is_err());
        assert_eq!(S19K_USB_UBOOT_TIMERFORADC_OFF, 43_041);
        assert_eq!(S19K_USB_UBOOT_EMPTY_EFUSE_OFF, 43_064);
        let mut es = vec![0u8; S19K_USB_UBOOT_DVFS_VOL_OFF + S19K_USB_UBOOT_DVFS_VOL.len()];
        es[S19K_USB_UBOOT_ES_CHIP_OFF..S19K_USB_UBOOT_ES_CHIP_OFF + S19K_USB_UBOOT_ES_CHIP.len()]
            .copy_from_slice(S19K_USB_UBOOT_ES_CHIP);
        es[S19K_USB_UBOOT_DVFS_VOL_OFF..S19K_USB_UBOOT_DVFS_VOL_OFF + S19K_USB_UBOOT_DVFS_VOL.len()]
            .copy_from_slice(S19K_USB_UBOOT_DVFS_VOL);
        assert!(admit_s19k_usb_uboot_es_chip_dvfs(&es).is_ok());
        assert!(refuse_s19k_usb_es_chip_dvfs_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_es_chip_dvfs_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_dvfs_as_hash_pll().is_err());
        assert!(refuse_s19k_usb_es_chip_as_miner_identity().is_err());
        assert_eq!(S19K_USB_UBOOT_ES_CHIP_OFF, 43_096);
        assert_eq!(S19K_USB_UBOOT_DVFS_VOL_OFF, 43_120);
        let mut dvfs = vec![0u8; S19K_USB_UBOOT_FREQ_TO_IDX_OFF + S19K_USB_UBOOT_FREQ_TO_IDX.len()];
        dvfs[S19K_USB_UBOOT_GET_INIT_DVFS_OFF
            ..S19K_USB_UBOOT_GET_INIT_DVFS_OFF + S19K_USB_UBOOT_GET_INIT_DVFS.len()]
            .copy_from_slice(S19K_USB_UBOOT_GET_INIT_DVFS);
        dvfs[S19K_USB_UBOOT_GET_DVFS_OFF
            ..S19K_USB_UBOOT_GET_DVFS_OFF + S19K_USB_UBOOT_GET_DVFS.len()]
            .copy_from_slice(S19K_USB_UBOOT_GET_DVFS);
        dvfs[S19K_USB_UBOOT_FREQ_TO_IDX_OFF
            ..S19K_USB_UBOOT_FREQ_TO_IDX_OFF + S19K_USB_UBOOT_FREQ_TO_IDX.len()]
            .copy_from_slice(S19K_USB_UBOOT_FREQ_TO_IDX);
        assert!(admit_s19k_usb_uboot_dvfs_freq(&dvfs).is_ok());
        assert!(refuse_s19k_usb_dvfs_freq_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_dvfs_freq_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_freq_to_idx_as_hash_pll().is_err());
        assert_eq!(S19K_USB_UBOOT_GET_INIT_DVFS_OFF, 43_144);
        assert_eq!(S19K_USB_UBOOT_GET_DVFS_OFF, 43_160);
        assert_eq!(S19K_USB_UBOOT_FREQ_TO_IDX_OFF, 43_172);
        let mut syspll = vec![0u8; S19K_USB_UBOOT_USE_SYS_PLL_OFF + S19K_USB_UBOOT_USE_SYS_PLL.len()];
        syspll[S19K_USB_UBOOT_SET_DVFS_INFO_OFF
            ..S19K_USB_UBOOT_SET_DVFS_INFO_OFF + S19K_USB_UBOOT_SET_DVFS_INFO.len()]
            .copy_from_slice(S19K_USB_UBOOT_SET_DVFS_INFO);
        syspll[S19K_USB_UBOOT_USE_SYS_PLL_OFF
            ..S19K_USB_UBOOT_USE_SYS_PLL_OFF + S19K_USB_UBOOT_USE_SYS_PLL.len()]
            .copy_from_slice(S19K_USB_UBOOT_USE_SYS_PLL);
        assert!(admit_s19k_usb_uboot_dvfs_sys_pll(&syspll).is_ok());
        assert!(refuse_s19k_usb_dvfs_sys_pll_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_dvfs_sys_pll_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_use_sys_pll_as_hash_pll().is_err());
        assert_eq!(S19K_USB_UBOOT_SET_DVFS_INFO_OFF, 43_184);
        assert_eq!(S19K_USB_UBOOT_USE_SYS_PLL_OFF, 43_200);
        let mut fix = vec![0u8; S19K_USB_UBOOT_SYS_PLL_LOCK_OFF + S19K_USB_UBOOT_SYS_PLL_LOCK.len()];
        fix[S19K_USB_UBOOT_USE_FIX_CLK_OFF
            ..S19K_USB_UBOOT_USE_FIX_CLK_OFF + S19K_USB_UBOOT_USE_FIX_CLK.len()]
            .copy_from_slice(S19K_USB_UBOOT_USE_FIX_CLK);
        fix[S19K_USB_UBOOT_SYS_PLL_LOCK_OFF
            ..S19K_USB_UBOOT_SYS_PLL_LOCK_OFF + S19K_USB_UBOOT_SYS_PLL_LOCK.len()]
            .copy_from_slice(S19K_USB_UBOOT_SYS_PLL_LOCK);
        assert!(admit_s19k_usb_uboot_fix_clk_pll_lock(&fix).is_ok());
        assert!(refuse_s19k_usb_fix_clk_pll_lock_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_fix_clk_pll_lock_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_sys_pll_lock_as_hash_pll().is_err());
        assert_eq!(S19K_USB_UBOOT_USE_FIX_CLK_OFF, 43_380);
        assert_eq!(S19K_USB_UBOOT_SYS_PLL_LOCK_OFF, 43_595);
        let mut therm = vec![0u8; S19K_USB_UBOOT_AML_THERMAL_OFF + S19K_USB_UBOOT_AML_THERMAL.len()];
        therm[S19K_USB_UBOOT_SET_DVFS_OFF
            ..S19K_USB_UBOOT_SET_DVFS_OFF + S19K_USB_UBOOT_SET_DVFS.len()]
            .copy_from_slice(S19K_USB_UBOOT_SET_DVFS);
        therm[S19K_USB_UBOOT_SET_DVFS_OFF + S19K_USB_UBOOT_SET_DVFS.len()] = 0;
        therm[S19K_USB_UBOOT_CPU_CLK_SUSPEND_OFF
            ..S19K_USB_UBOOT_CPU_CLK_SUSPEND_OFF + S19K_USB_UBOOT_CPU_CLK_SUSPEND.len()]
            .copy_from_slice(S19K_USB_UBOOT_CPU_CLK_SUSPEND);
        therm[S19K_USB_UBOOT_SET_DVFS_BUSY_OFF
            ..S19K_USB_UBOOT_SET_DVFS_BUSY_OFF + S19K_USB_UBOOT_SET_DVFS_BUSY.len()]
            .copy_from_slice(S19K_USB_UBOOT_SET_DVFS_BUSY);
        therm[S19K_USB_UBOOT_HIGH_TASK_SET_DVFS_OFF
            ..S19K_USB_UBOOT_HIGH_TASK_SET_DVFS_OFF + S19K_USB_UBOOT_HIGH_TASK_SET_DVFS.len()]
            .copy_from_slice(S19K_USB_UBOOT_HIGH_TASK_SET_DVFS);
        therm[S19K_USB_UBOOT_AML_THERMAL_OFF
            ..S19K_USB_UBOOT_AML_THERMAL_OFF + S19K_USB_UBOOT_AML_THERMAL.len()]
            .copy_from_slice(S19K_USB_UBOOT_AML_THERMAL);
        assert!(admit_s19k_usb_uboot_dvfs_thermal(&therm).is_ok());
        assert!(refuse_s19k_usb_dvfs_thermal_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_dvfs_thermal_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_cpu_clk_suspend_as_hash_pll().is_err());
        assert!(refuse_s19k_usb_aml_thermal_as_hash_thermal().is_err());
        assert_eq!(S19K_USB_UBOOT_SET_DVFS_OFF, 43_392);
        assert_eq!(S19K_USB_UBOOT_CPU_CLK_SUSPEND_OFF, 43_710);
        assert_eq!(S19K_USB_UBOOT_SET_DVFS_BUSY_OFF, 43_852);
        assert_eq!(S19K_USB_UBOOT_HIGH_TASK_SET_DVFS_OFF, 43_868);
        assert_eq!(S19K_USB_UBOOT_AML_THERMAL_OFF, 44_476);
        assert!(admit_s19k_usb_uboot_dvfs_thermal(b"set_dvfs_info").is_err());
        let mut bl30 = vec![0u8; S19K_USB_UBOOT_BL30_THERMAL_OFF + S19K_USB_UBOOT_BL30_THERMAL.len()];
        bl30[S19K_USB_UBOOT_CPU_CLK_RESUME_OFF
            ..S19K_USB_UBOOT_CPU_CLK_RESUME_OFF + S19K_USB_UBOOT_CPU_CLK_RESUME.len()]
            .copy_from_slice(S19K_USB_UBOOT_CPU_CLK_RESUME);
        bl30[S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS_OFF
            ..S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS_OFF + S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS.len()]
            .copy_from_slice(S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS);
        bl30[S19K_USB_UBOOT_BL30_THERMAL_OFF
            ..S19K_USB_UBOOT_BL30_THERMAL_OFF + S19K_USB_UBOOT_BL30_THERMAL.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_THERMAL);
        bl30[S19K_USB_UBOOT_JTAG_FORCE_OFF
            ..S19K_USB_UBOOT_JTAG_FORCE_OFF + S19K_USB_UBOOT_JTAG_FORCE.len()]
            .copy_from_slice(S19K_USB_UBOOT_JTAG_FORCE);
        bl30[S19K_USB_UBOOT_EFUSE_PW_EN_OFF
            ..S19K_USB_UBOOT_EFUSE_PW_EN_OFF + S19K_USB_UBOOT_EFUSE_PW_EN.len()]
            .copy_from_slice(S19K_USB_UBOOT_EFUSE_PW_EN);
        assert!(admit_s19k_usb_uboot_bl30_jtag_efuse(&bl30).is_ok());
        assert!(refuse_s19k_usb_bl30_jtag_efuse_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_bl30_jtag_efuse_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_cpu_clk_resume_as_hash_pll().is_err());
        assert!(refuse_s19k_usb_bl30_thermal_as_hash_thermal().is_err());
        assert!(refuse_s19k_usb_efuse_pw_en_as_otp_decrypt().is_err());
        assert_eq!(S19K_USB_UBOOT_CPU_CLK_RESUME_OFF, 43_735);
        assert_eq!(S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS_OFF, 43_888);
        assert_eq!(S19K_USB_UBOOT_BL30_THERMAL_OFF, 44_496);
        assert_eq!(S19K_USB_UBOOT_JTAG_FORCE_OFF, 43_932);
        assert_eq!(S19K_USB_UBOOT_EFUSE_PW_EN_OFF, 43_985);
        let mut trim = vec![
            0u8;
            S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF + S19K_USB_UBOOT_BL30_THERMAL_TRIM.len()
        ];
        trim[S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL_OFF
            ..S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL_OFF + S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL.len()]
            .copy_from_slice(S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL);
        trim[S19K_USB_UBOOT_DISABLE_M3_JTAG_OFF
            ..S19K_USB_UBOOT_DISABLE_M3_JTAG_OFF + S19K_USB_UBOOT_DISABLE_M3_JTAG.len()]
            .copy_from_slice(S19K_USB_UBOOT_DISABLE_M3_JTAG);
        trim[S19K_USB_UBOOT_EFUSE_BITS_DISABLED_OFF
            ..S19K_USB_UBOOT_EFUSE_BITS_DISABLED_OFF + S19K_USB_UBOOT_EFUSE_BITS_DISABLED.len()]
            .copy_from_slice(S19K_USB_UBOOT_EFUSE_BITS_DISABLED);
        trim[S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF
            ..S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF + S19K_USB_UBOOT_BL30_THERMAL_TRIM.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_THERMAL_TRIM);
        assert!(admit_s19k_usb_uboot_dvfstbl_jtag_trim(&trim).is_ok());
        assert!(refuse_s19k_usb_dvfstbl_jtag_trim_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_dvfstbl_jtag_trim_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_efuse_bits_disabled_as_otp_decrypt().is_err());
        assert!(refuse_s19k_usb_bl30_thermal_trim_as_hash_thermal().is_err());
        assert_eq!(S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL_OFF, 43_908);
        assert_eq!(S19K_USB_UBOOT_DISABLE_M3_JTAG_OFF, 43_952);
        assert_eq!(S19K_USB_UBOOT_EFUSE_BITS_DISABLED_OFF, 44_004);
        assert_eq!(S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF, 44_496);
        let mut gxl = vec![0u8; S19K_USB_UBOOT_GXL_ES_THERMAL_OFF + S19K_USB_UBOOT_GXL_ES_THERMAL.len()];
        gxl[S19K_USB_UBOOT_DISABLE_A53_JTAG_OFF
            ..S19K_USB_UBOOT_DISABLE_A53_JTAG_OFF + S19K_USB_UBOOT_DISABLE_A53_JTAG.len()]
            .copy_from_slice(S19K_USB_UBOOT_DISABLE_A53_JTAG);
        gxl[S19K_USB_UBOOT_ENABLE_M3_JTAG_OFF
            ..S19K_USB_UBOOT_ENABLE_M3_JTAG_OFF + S19K_USB_UBOOT_ENABLE_M3_JTAG.len()]
            .copy_from_slice(S19K_USB_UBOOT_ENABLE_M3_JTAG);
        gxl[S19K_USB_UBOOT_BL30_THERMAL_CALIB_OFF
            ..S19K_USB_UBOOT_BL30_THERMAL_CALIB_OFF + S19K_USB_UBOOT_BL30_THERMAL_CALIB.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_THERMAL_CALIB);
        gxl[S19K_USB_UBOOT_GXL_ES_THERMAL_OFF
            ..S19K_USB_UBOOT_GXL_ES_THERMAL_OFF + S19K_USB_UBOOT_GXL_ES_THERMAL.len()]
            .copy_from_slice(S19K_USB_UBOOT_GXL_ES_THERMAL);
        assert!(admit_s19k_usb_uboot_a53_gxl_thermal(&gxl).is_ok());
        assert!(refuse_s19k_usb_a53_gxl_thermal_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_a53_gxl_thermal_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_bl30_thermal_calib_as_hash_thermal().is_err());
        assert!(refuse_s19k_usb_gxl_es_thermal_as_miner_identity().is_err());
        assert_eq!(S19K_USB_UBOOT_DISABLE_A53_JTAG_OFF, 43_968);
        assert_eq!(S19K_USB_UBOOT_ENABLE_M3_JTAG_OFF, 44_037);
        assert_eq!(S19K_USB_UBOOT_BL30_THERMAL_CALIB_OFF, 44_540);
        assert_eq!(S19K_USB_UBOOT_GXL_ES_THERMAL_OFF, 44_949);
        let mut untrim = vec![0u8; S19K_USB_UBOOT_BL30_UNTRIMMED_OFF + S19K_USB_UBOOT_BL30_UNTRIMMED.len()];
        untrim[S19K_USB_UBOOT_ENABLE_A53_JTAG_OFF
            ..S19K_USB_UBOOT_ENABLE_A53_JTAG_OFF + S19K_USB_UBOOT_ENABLE_A53_JTAG.len()]
            .copy_from_slice(S19K_USB_UBOOT_ENABLE_A53_JTAG);
        untrim[S19K_USB_UBOOT_JTAG_TO_AO_OFF
            ..S19K_USB_UBOOT_JTAG_TO_AO_OFF + S19K_USB_UBOOT_JTAG_TO_AO.len()]
            .copy_from_slice(S19K_USB_UBOOT_JTAG_TO_AO);
        untrim[S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR_OFF
            ..S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR_OFF + S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR);
        untrim[S19K_USB_UBOOT_BL30_UNTRIMMED_OFF
            ..S19K_USB_UBOOT_BL30_UNTRIMMED_OFF + S19K_USB_UBOOT_BL30_UNTRIMMED.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_UNTRIMMED);
        assert!(admit_s19k_usb_uboot_a53_ao_untrimmed(&untrim).is_ok());
        assert!(refuse_s19k_usb_a53_ao_untrimmed_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_a53_ao_untrimmed_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_bl30_thermal_calib_err_as_hash_thermal().is_err());
        assert!(refuse_s19k_usb_bl30_untrimmed_as_hash_thermal().is_err());
        assert_eq!(S19K_USB_UBOOT_ENABLE_A53_JTAG_OFF, 44_068);
        assert_eq!(S19K_USB_UBOOT_JTAG_TO_AO_OFF, 44_052);
        assert_eq!(S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR_OFF, 44_578);
        assert_eq!(S19K_USB_UBOOT_BL30_UNTRIMMED_OFF, 44_695);
        let mut ee = vec![
            0u8;
            S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF + S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA.len()
        ];
        ee[S19K_USB_UBOOT_JTAG_TO_EE_OFF
            ..S19K_USB_UBOOT_JTAG_TO_EE_OFF + S19K_USB_UBOOT_JTAG_TO_EE.len()]
            .copy_from_slice(S19K_USB_UBOOT_JTAG_TO_EE);
        ee[S19K_USB_UBOOT_INCORRECT_PASSWORD_OFF
            ..S19K_USB_UBOOT_INCORRECT_PASSWORD_OFF + S19K_USB_UBOOT_INCORRECT_PASSWORD.len()]
            .copy_from_slice(S19K_USB_UBOOT_INCORRECT_PASSWORD);
        ee[S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF
            ..S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF + S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA);
        ee[S19K_USB_UBOOT_BL30_AXG_VER_OFF
            ..S19K_USB_UBOOT_BL30_AXG_VER_OFF + S19K_USB_UBOOT_BL30_AXG_VER.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_AXG_VER);
        assert!(admit_s19k_usb_uboot_ee_pw_axg(&ee).is_ok());
        assert!(refuse_s19k_usb_ee_pw_axg_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_ee_pw_axg_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_incorrect_password_as_miner_auth().is_err());
        assert!(refuse_s19k_usb_bl30_thermal_cal_data_as_hash_thermal().is_err());
        assert!(refuse_s19k_usb_bl30_axg_ver_as_miner_identity().is_err());
        assert_eq!(S19K_USB_UBOOT_JTAG_TO_EE_OFF, 44_060);
        assert_eq!(S19K_USB_UBOOT_INCORRECT_PASSWORD_OFF, 44_118);
        assert_eq!(S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF, 44_807);
        assert_eq!(S19K_USB_UBOOT_BL30_AXG_VER_OFF, 44_738);
        let mut inv = vec![
            0u8;
            S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF + S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR.len()
        ];
        inv[S19K_USB_UBOOT_INVALID_INPUT_OFF
            ..S19K_USB_UBOOT_INVALID_INPUT_OFF + S19K_USB_UBOOT_INVALID_INPUT.len()]
            .copy_from_slice(S19K_USB_UBOOT_INVALID_INPUT);
        inv[S19K_USB_UBOOT_PLEASE_TRY_AGAIN_OFF
            ..S19K_USB_UBOOT_PLEASE_TRY_AGAIN_OFF + S19K_USB_UBOOT_PLEASE_TRY_AGAIN.len()]
            .copy_from_slice(S19K_USB_UBOOT_PLEASE_TRY_AGAIN);
        inv[S19K_USB_UBOOT_BL30_AXG_THERMAL0_OFF
            ..S19K_USB_UBOOT_BL30_AXG_THERMAL0_OFF + S19K_USB_UBOOT_BL30_AXG_THERMAL0.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_AXG_THERMAL0);
        inv[S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF
            ..S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF + S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR.len()]
            .copy_from_slice(S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR);
        assert!(admit_s19k_usb_uboot_invalid_try_thermal0(&inv).is_ok());
        assert!(refuse_s19k_usb_invalid_try_thermal0_as_hash_uart().is_err());
        assert!(refuse_s19k_usb_invalid_try_thermal0_as_nandrecovery().is_err());
        assert!(refuse_s19k_usb_invalid_input_as_miner_auth().is_err());
        assert!(refuse_s19k_usb_bl30_axg_thermal0_as_hash_thermal().is_err());
        assert!(refuse_s19k_usb_bl30_thermal_init_err_as_hash_thermal().is_err());
        assert_eq!(S19K_USB_UBOOT_INVALID_INPUT_OFF, 44_096);
        assert_eq!(S19K_USB_UBOOT_PLEASE_TRY_AGAIN_OFF, 44_145);
        assert_eq!(S19K_USB_UBOOT_BL30_AXG_THERMAL0_OFF, 44_765);
        assert_eq!(S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF, 44_784);
        assert_eq!(S19K_USB_UBOOT_SARADC_WORD_OFF, 686_158);
        assert!(parse_s19k_aml_multi_dtb(b"\xd0\x0d\xfe\xed").is_err());
        assert_eq!(S19K_FACTORY_MESON1_GUNZIP_BYTES, 114_688);
        assert_eq!(S19K_FACTORY_MESON1_GZIP_BYTES, 28_568);
        assert_eq!(S19K_USB_UBOOT_BYTES, 769_024);
        assert_eq!(S19K_FACTORY_S30V_PART_NAMES[5], "nvdata");
        assert_eq!(S19K_FACTORY_MESON1_ENTRY1_SIZE, 0xB800);
        assert_eq!(S19K_FACTORY_MESON1_ENTRY0_SIZE, 0x1_0000);
        let gpios = parse_s19k_aml_dtb_gpio_controllers(&build_gpio_dtb()).unwrap();
        assert!(admit_s19k_s30v_axg_gpio_controllers(&gpios).is_ok());
        assert_eq!(gpios.len(), 2);
        assert!(gpios.iter().all(|c| c.linux_gpio_base.is_none()));
        assert!(gpios.iter().all(|c| !c.has_line_names && !c.has_gpio_ranges));
        assert!(refuse_s19k_dt_math_as_gpio437(&gpios).is_err());
        assert!(refuse_s19k_vendor_gpiochip_base_as_dt_cell(None).is_err());
        assert!(refuse_s19k_vendor_gpiochip_base_as_dt_cell(Some(411)).is_ok());
        assert!(refuse_s19k_gpioao3_local_as_gpio437().is_err());
        let mut usb_fix = vec![0u8; S19K_USB_UBOOT_GPIOAO3_OFF + 16];
        usb_fix[S19K_USB_UBOOT_GPIOAO3_OFF..S19K_USB_UBOOT_GPIOAO3_OFF + 8]
            .copy_from_slice(b"GPIOAO_3");
        usb_fix[S19K_USB_UBOOT_GPIO_WORD_OFF..S19K_USB_UBOOT_GPIO_WORD_OFF + 5]
            .copy_from_slice(b"gpio ");
        usb_fix[S19K_USB_UBOOT_GPIO_WORD_OFF + 5..S19K_USB_UBOOT_GPIOAO3_OFF]
            .copy_from_slice(&[0xf0, 0x38, 0x98, 0x20]);
        assert!(admit_s19k_usb_uboot_gpioao3_offset(&usb_fix).is_ok());
        assert!(admit_s19k_usb_uboot_packed_gpio_word(&usb_fix).is_ok());
        assert!(refuse_s19k_usb_uboot_contiguous_gpio_cmd(&usb_fix).is_err());
        assert!(refuse_s19k_usb_uboot_gpioao_as_pin_table(&usb_fix).is_err());
        assert!(admit_s19k_uboot_gpioao3_from_end(S19K_USB_UBOOT_BYTES, S19K_USB_UBOOT_GPIOAO3_OFF).is_ok());
        assert!(admit_s19k_uboot_gpioao3_from_end(818_688, S19K_SDC_UBOOT_GPIOAO3_OFF).is_ok());
        assert!(admit_s19k_uboot_packed_gpioao3_seq(&usb_fix, S19K_USB_UBOOT_GPIOAO3_OFF).is_ok());
        let mut packed_console = usb_fix.clone();
        packed_console.extend_from_slice(S19K_USB_UBOOT_PACKED_CONSOLE);
        packed_console.extend_from_slice(S19K_USB_UBOOT_PACKED_EARLYCON);
        assert!(admit_s19k_usb_uboot_packed_console(&packed_console).is_ok());
        assert!(refuse_s19k_usb_uboot_packed_as_nand_env(&usb_fix).is_err());
        assert_eq!(S19K_UBOOT_PACKED_GPIOAO3.len(), 17);
        usb_fix.extend_from_slice(b"GPIOAO_0");
        assert!(refuse_s19k_usb_uboot_gpioao_as_pin_table(&usb_fix).is_ok());
        assert_eq!(S19K_AXG_GPIOA0_LOCAL + S19K_AXG_VENDOR_GPIOCHIP_BASE, 437);
        assert_eq!(S19K_AXG_GPIOAO3_LOCAL, 3);
        assert_eq!(S19K_AXG_PERIPHS_PINCTRL, "amlogic,meson-axg-periphs-pinctrl");
        assert_eq!(S19K_AXG_AOBUS_PINCTRL, "amlogic,meson-axg-aobus-pinctrl");
    }
}
