//! `a lab unit` `/dev/nand_env` (64 KiB U-Boot env) — host-testable parser.
//!
//! Does not write NAND. Pins bootdelay, console, BOS/stock `bootcmd`,
//! and the BOS image map from the held `nand_env.bin`.

use std::collections::BTreeMap;

/// Live Braiins AML `dd` of `/dev/nand_env`.
pub const S19K_NAND_ENV_LEN: usize = 65_536;
pub const S19K_78_NAND_ENV_CRC: u32 = 0x471D_6B1A;
pub const S19K_78_BOOTDELAY: u32 = 1;
pub const S19K_78_ENV_BAUD: u32 = 115_200;
pub const S19K_78_UBOOT_VERSION: &str = "U-Boot 2015.01";
pub const S19K_78_BOOTCMD: &str =
    "run try_to_boot_bos_normally; run try_to_boot_bos_after_install; run recover_to_stock";
pub const S19K_78_TRY_BOS_NORMAL: &str =
    "run read_flag_from_nand; mw.b ${flagcmpaddr} ${recovery_flag_successful}; if cmp.b ${flagaddr} ${flagcmpaddr} 1; then run boot_bos; fi;";
pub const S19K_78_TRY_BOS_AFTER_INSTALL: &str =
    "run read_flag_from_nand; mw.b ${flagcmpaddr} ${recovery_flag_installed}; if cmp.b ${flagaddr} ${flagcmpaddr} 1; then echo First start of BOS...; run recovery_set_flag_2; run boot_bos; fi;";
pub const S19K_78_RECOVER_TO_STOCK: &str =
    "echo Running recovery to stock FW...; run recover_env; echo Erase BOS from device...; nand erase.part nvdata; reset;";
pub const S19K_78_RECOVER_ENV: &str =
    "echo Reset env to stock...; nand read 01060000 ${nandrecovery_env_offset} ${env_size}; env default -a; env import -d -c 01060000 0x10000; env save;";
/// U-Boot RAM dest in [`S19K_78_RECOVER_ENV`] (`nand read` + `env import`).
pub const S19K_78_RECOVER_ENV_RAM: u32 = 0x0106_0000;
pub const S19K_78_ENV_IMPORT_SIZE: u32 = 0x1_0000;
/// `a lab unit` `nand_env.bin`: first-BOS-start writes `recovery_flag_first_boot` (0x2).
pub const S19K_78_RECOVERY_SET_FLAG_2: &str =
    "mw.b ${flagcmpaddr} ${recovery_flag_first_boot}; run recovery_set_flag;";
/// U-Boot eraseblock rewrite of the flag (nand device 1, global offset).
pub const S19K_78_RECOVERY_SET_FLAG: &str =
    "nand device 1; nand erase ${nandrecovery_flag_offset} 0x20000; nand write ${flagcmpaddr} ${nandrecovery_flag_offset} 1";
/// Erase length in `recovery_set_flag`. Same as mtd5 `erasesize` 131072.
pub const S19K_78_RECOVERY_FLAG_ERASE: u32 = 0x2_0000;
pub const S19K_78_BOOT_BOS: &str =
    "run read_images_from_nand && env export -b $envaddr $stage2_vars && run boot_stage2";
pub const S19K_78_READ_IMAGES: &str =
    "nand device 1 && nand read $loadaddr $nanduboot $nandubootlen && nand read $kerneladdr $nandkernel $nandkernellen && nand read $fdtaddr $nandfdt $nandfdtlen && nand read $initramfsaddr $nandrootfs $nandrootfslen";
pub const S19K_78_BOOT_STAGE2: &str = "dcache flush && icache flush && go $loadaddr";
/// U-Boot 2015.01 default prompt. Not present as a string in `nand_env.bin`.
pub const S19K_UBOOT_2015_DEFAULT_STOP_PROMPT: &str = "Hit any key to stop autoboot";
pub const S19K_78_CONSOLE_BOOTARGS: &str = "console=ttyS0,115200";
pub const S19K_78_EARLYCON: &str = "earlycon=aml_uart,0xff803000";

/// Same hex values as `s19k_am3_install` recovery-flag constants.
pub const S19K_78_RECOVERY_FLAG_INSTALLED: u8 = 0x01;
pub const S19K_78_RECOVERY_FLAG_FIRST_BOOT: u8 = 0x02;
pub const S19K_78_RECOVERY_FLAG_SUCCESSFUL: u8 = 0x03;

/// U-Boot globals from the live env (nand device 1 / raw chip view).
pub const S19K_78_NAND_DEVICE: u8 = 1;
pub const S19K_78_NANDUBOOT: u64 = 0x0700_0000;
pub const S19K_78_NANDUBOOT_LEN: u64 = 0x20_0000;
pub const S19K_78_NANDFDT: u64 = 0x0750_0000;
pub const S19K_78_NANDFDT_LEN: u64 = 0x2_0000;
pub const S19K_78_NANDKERNEL: u64 = 0x0780_0000;
pub const S19K_78_NANDKERNEL_LEN: u64 = 0x140_0000;
pub const S19K_78_NANDROOTFS: u64 = 0x0B80_0000;
pub const S19K_78_NANDROOTFS_LEN: u64 = 0x280_0000;
pub const S19K_78_NANDRECOVERY_ENV: u64 = 0x0B00_0000;
pub const S19K_78_NANDRECOVERY_FLAG: u64 = 0x0B40_0000;
pub const S19K_78_ENV_SIZE: u64 = 0x1_0000;
pub const S19K_78_NAND_ERASESIZE: u32 = 0x2_0000;
pub const S19K_78_NAND_WRITESIZE: u32 = 0x800;

/// Live `a lab unit` `/proc/mtd` names (recon.txt). mtd3 is `stock_config`, not reserved.
pub const S19K_78_PROC_MTD_NAMES: &[&str] = &[
    "bootloader",
    "tpl",
    "stock_system",
    "stock_config",
    "overlay",
    "system",
];
pub const S19K_78_PROC_MTD_SIZES: &[u64] = &[
    0x0020_0000,
    0x0080_0000,
    0x0320_0000,
    0x0050_0000,
    0x0200_0000,
    0x0990_0000,
];
/// Held S21 Braiins `/proc/mtd` sizes from `nand_and_ubi.txt`. Same as `a lab unit`.
pub const S21_HELD_PROC_MTD_SIZES: &[u64] = &[
    0x0020_0000,
    0x0080_0000,
    0x0320_0000,
    0x0050_0000,
    0x0200_0000,
    0x0990_0000,
];

pub fn admit_s21_held_proc_mtd_matches_78() -> Result<(), &'static str> {
    if S21_HELD_PROC_MTD_SIZES != S19K_78_PROC_MTD_SIZES {
        return Err("held S21 /proc/mtd sizes must match .78");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kNandEnv {
    pub crc: u32,
    pub crc_ok: bool,
    pub vars: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUbootInterrupt {
    /// `bootdelay>=1`, `stdin=serial`, no custom `bootstopkey`.
    /// Exact key is U-Boot 2015.01 default (any key), not a held banner.
    AnyKeyDuringBootdelay,
}

/// What U-Boot actually runs for a recovery-flag byte on this env.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUbootFlagAction {
    /// `0x03` → `boot_bos` (`nand device 1` + `go $loadaddr`).
    BootBos,
    /// `0x01` → write `0x02` then `boot_bos`.
    FirstBosThenSetFlag2,
    /// `0x02` and any other value → `recover_env` + `nand erase.part nvdata`.
    RecoverToStock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosNandImageMap {
    pub nand_device: u8,
    pub uboot: u64,
    pub uboot_len: u64,
    pub fdt: u64,
    pub fdt_len: u64,
    pub kernel: u64,
    pub kernel_len: u64,
    pub rootfs: u64,
    pub rootfs_len: u64,
    pub recovery_env: u64,
    pub recovery_flag: u64,
}

pub const S19K_78_BOS_NAND_MAP: S19kBosNandImageMap = S19kBosNandImageMap {
    nand_device: S19K_78_NAND_DEVICE,
    uboot: S19K_78_NANDUBOOT,
    uboot_len: S19K_78_NANDUBOOT_LEN,
    fdt: S19K_78_NANDFDT,
    fdt_len: S19K_78_NANDFDT_LEN,
    kernel: S19K_78_NANDKERNEL,
    kernel_len: S19K_78_NANDKERNEL_LEN,
    rootfs: S19K_78_NANDROOTFS,
    rootfs_len: S19K_78_NANDROOTFS_LEN,
    recovery_env: S19K_78_NANDRECOVERY_ENV,
    recovery_flag: S19K_78_NANDRECOVERY_FLAG,
};

pub fn parse_s19k_nand_env(blob: &[u8]) -> Result<S19kNandEnv, &'static str> {
    if blob.len() != S19K_NAND_ENV_LEN {
        return Err("nand_env must be 65536 bytes");
    }
    let crc = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let body = &blob[4..];
    let crc_ok = crc32_iso_hdlc(body) == crc;
    let mut vars = BTreeMap::new();
    for part in body.split(|b| *b == 0) {
        if part.is_empty() {
            break;
        }
        let Ok(s) = std::str::from_utf8(part) else {
            continue;
        };
        let Some((k, v)) = s.split_once('=') else {
            continue;
        };
        if !k.is_empty() {
            vars.insert(k.to_string(), v.to_string());
        }
    }
    if vars.is_empty() {
        return Err("nand_env has no key=value pairs");
    }
    Ok(S19kNandEnv { crc, crc_ok, vars })
}

pub(crate) fn crc32_iso_hdlc(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Host fixture: 64 KiB U-Boot env with ISO-HDLC CRC32. Does not write NAND.
pub fn encode_s19k_nand_env(pairs: &[(&str, &str)]) -> [u8; S19K_NAND_ENV_LEN] {
    let mut body = Vec::new();
    for (k, v) in pairs {
        body.extend_from_slice(k.as_bytes());
        body.push(b'=');
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    body.resize(S19K_NAND_ENV_LEN - 4, 0);
    let crc = crc32_iso_hdlc(&body);
    let mut out = [0u8; S19K_NAND_ENV_LEN];
    out[..4].copy_from_slice(&crc.to_le_bytes());
    out[4..].copy_from_slice(&body);
    out
}

/// Minimal CRC-valid `nandrecovery_env.bin` for recover `--dry-run`.
pub fn construct_s19k_nandrecovery_env_fixture() -> [u8; S19K_NAND_ENV_LEN] {
    encode_s19k_nand_env(&[("recover", "1")])
}

fn hex_u64(s: &str) -> Option<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok()
}

pub fn admit_s19k_78_nand_env(env: &S19kNandEnv) -> Result<(), &'static str> {
    if !env.crc_ok {
        return Err("nand_env CRC32 mismatch");
    }
    if env.vars.get("bootdelay").map(String::as_str) != Some("1") {
        return Err("`a lab unit` bootdelay is 1");
    }
    if env.vars.get("stdin").map(String::as_str) != Some("serial") {
        return Err("`a lab unit` stdin is serial");
    }
    if env.vars.get("baudrate").map(String::as_str) != Some("115200") {
        return Err("`a lab unit` env baudrate is 115200");
    }
    if env.vars.get("bootloader_version").map(String::as_str) != Some(S19K_78_UBOOT_VERSION) {
        return Err("`a lab unit` bootloader_version is U-Boot 2015.01");
    }
    if env.vars.get("bootcmd").map(String::as_str) != Some(S19K_78_BOOTCMD) {
        return Err("`a lab unit` bootcmd is try_bos_normally; after_install; recover_to_stock");
    }
    if env.vars.get("try_to_boot_bos_normally").map(String::as_str) != Some(S19K_78_TRY_BOS_NORMAL)
    {
        return Err("`a lab unit` try_to_boot_bos_normally mismatch");
    }
    if env
        .vars
        .get("try_to_boot_bos_after_install")
        .map(String::as_str)
        != Some(S19K_78_TRY_BOS_AFTER_INSTALL)
    {
        return Err("`a lab unit` try_to_boot_bos_after_install mismatch");
    }
    if env.vars.get("recover_to_stock").map(String::as_str) != Some(S19K_78_RECOVER_TO_STOCK) {
        return Err("`a lab unit` recover_to_stock mismatch");
    }
    if env.vars.get("recover_env").map(String::as_str) != Some(S19K_78_RECOVER_ENV) {
        return Err("`a lab unit` recover_env mismatch");
    }
    if env.vars.get("recovery_set_flag").map(String::as_str) != Some(S19K_78_RECOVERY_SET_FLAG) {
        return Err("`a lab unit` recovery_set_flag is nand erase 0x20000 + write 1 at flag offset");
    }
    if env.vars.get("recovery_set_flag_2").map(String::as_str) != Some(S19K_78_RECOVERY_SET_FLAG_2)
    {
        return Err(
            "`a lab unit` recovery_set_flag_2 writes recovery_flag_first_boot then recovery_set_flag",
        );
    }
    if env.vars.get("boot_bos").map(String::as_str) != Some(S19K_78_BOOT_BOS) {
        return Err("`a lab unit` boot_bos mismatch");
    }
    if env.vars.get("read_images_from_nand").map(String::as_str) != Some(S19K_78_READ_IMAGES) {
        return Err("`a lab unit` read_images_from_nand mismatch");
    }
    if env.vars.get("recovery_flag_installed").map(String::as_str) != Some("0x1") {
        return Err("`a lab unit` recovery_flag_installed is 0x1");
    }
    if env.vars.get("recovery_flag_first_boot").map(String::as_str) != Some("0x2") {
        return Err("`a lab unit` recovery_flag_first_boot is 0x2");
    }
    if env.vars.get("recovery_flag_successful").map(String::as_str) != Some("0x3") {
        return Err("`a lab unit` recovery_flag_successful is 0x3");
    }
    if hex_u64(env.vars.get("nandrootfs").map(String::as_str).unwrap_or(""))
        != Some(S19K_78_NANDROOTFS)
    {
        return Err("`a lab unit` nandrootfs is 0x0B800000");
    }
    if hex_u64(
        env.vars
            .get("nandrecovery_flag_offset")
            .map(String::as_str)
            .unwrap_or(""),
    ) != Some(S19K_78_NANDRECOVERY_FLAG)
    {
        return Err("`a lab unit` nandrecovery_flag_offset is 0x0B400000");
    }
    if hex_u64(
        env.vars
            .get("nandrecovery_env_offset")
            .map(String::as_str)
            .unwrap_or(""),
    ) != Some(S19K_78_NANDRECOVERY_ENV)
    {
        return Err("`a lab unit` nandrecovery_env_offset is 0x0B000000");
    }
    let bootargs = env.vars.get("bootargs").map(String::as_str).unwrap_or("");
    if !bootargs.contains(S19K_78_CONSOLE_BOOTARGS) || !bootargs.contains(S19K_78_EARLYCON) {
        return Err("`a lab unit` bootargs must pin ttyS0 115200 + earlycon 0xff803000");
    }
    if env.vars.contains_key("bootstopkey") || env.vars.contains_key("bootdelaykey") {
        return Err("`a lab unit` env must not define a custom bootstopkey");
    }
    Ok(())
}

/// Interrupt policy from env. Does not invent a custom key sequence.
pub fn classify_s19k_uboot_interrupt(
    env: &S19kNandEnv,
) -> Result<S19kUbootInterrupt, &'static str> {
    if env.vars.contains_key("bootstopkey") || env.vars.contains_key("bootdelaykey") {
        return Err("custom bootstopkey/bootdelaykey present; refuse default any-key claim");
    }
    let delay: u32 = env
        .vars
        .get("bootdelay")
        .and_then(|s| s.parse().ok())
        .ok_or("bootdelay missing")?;
    if delay == 0 {
        return Err("bootdelay=0 disables autoboot interrupt");
    }
    if env.vars.get("stdin").map(String::as_str) != Some("serial") {
        return Err("stdin is not serial; refuse console interrupt");
    }
    Ok(S19kUbootInterrupt::AnyKeyDuringBootdelay)
}

/// Flag byte → U-Boot action on this `bootcmd` sequencer.
pub fn classify_s19k_uboot_flag_action(flag: u8) -> S19kUbootFlagAction {
    match flag {
        S19K_78_RECOVERY_FLAG_SUCCESSFUL => S19kUbootFlagAction::BootBos,
        S19K_78_RECOVERY_FLAG_INSTALLED => S19kUbootFlagAction::FirstBosThenSetFlag2,
        _ => S19kUbootFlagAction::RecoverToStock,
    }
}

/// `a lab unit` `bootcmd` is exactly these three `run` arms, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUbootBootcmdArm {
    TryBosNormally,
    TryBosAfterInstall,
    RecoverToStock,
}

pub const S19K_UBOOT_BOOTCMD_ARMS: [S19kUbootBootcmdArm; 3] = [
    S19kUbootBootcmdArm::TryBosNormally,
    S19kUbootBootcmdArm::TryBosAfterInstall,
    S19kUbootBootcmdArm::RecoverToStock,
];

/// Host-readable sequencer. Does not write env or NAND.
pub fn format_s19k_uboot_bootcmd_plan() -> String {
    format!(
        "schema=dcentos.amlogic-uboot-bootcmd/v1\n\
arm0=try_to_boot_bos_normally\nflag0=0x{success:02X}\naction0={act0:?}\n\
arm1=try_to_boot_bos_after_install\nflag1=0x{installed:02X}\naction1={act1:?}\n\
arm2=recover_to_stock\nflag2=else\naction2={act2:?}\n\
firstboot_unread_by_bootcmd=true\nbootm_mtd2=false\n\
execute=CLEAR_FOR_FLASH\nclear_for_flash=false\n",
        success = S19K_78_RECOVERY_FLAG_SUCCESSFUL,
        installed = S19K_78_RECOVERY_FLAG_INSTALLED,
        act0 = classify_s19k_uboot_flag_action(S19K_78_RECOVERY_FLAG_SUCCESSFUL),
        act1 = classify_s19k_uboot_flag_action(S19K_78_RECOVERY_FLAG_INSTALLED),
        act2 = classify_s19k_uboot_flag_action(S19K_78_RECOVERY_FLAG_FIRST_BOOT),
    )
}

pub fn admit_s19k_uboot_bootcmd_plan(plan: &str) -> Result<(), &'static str> {
    if S19K_UBOOT_BOOTCMD_ARMS.len() != 3 {
        return Err("bootcmd arm census drifted");
    }
    if !plan.contains("arm0=try_to_boot_bos_normally") {
        return Err("bootcmd plan missing try_to_boot_bos_normally");
    }
    if !plan.contains("arm1=try_to_boot_bos_after_install") {
        return Err("bootcmd plan missing try_to_boot_bos_after_install");
    }
    if !plan.contains("arm2=recover_to_stock") {
        return Err("bootcmd plan missing recover_to_stock");
    }
    if !plan.contains("firstboot_unread_by_bootcmd=true") {
        return Err("bootcmd plan must not treat firstboot as a sequencer arm");
    }
    if !plan.contains("bootm_mtd2=false") {
        return Err("bootcmd plan must refuse bootm mtd2");
    }
    if !plan.contains("clear_for_flash=false") {
        return Err("bootcmd plan must stay CLEAR_FOR_FLASH=false");
    }
    if !S19K_78_BOOTCMD.contains("try_to_boot_bos_normally")
        || !S19K_78_BOOTCMD.contains("try_to_boot_bos_after_install")
        || !S19K_78_BOOTCMD.contains("recover_to_stock")
    {
        return Err(".78 bootcmd string drifted from the three-arm plan");
    }
    Ok(())
}

pub fn admit_s19k_78_bos_nand_map(map: &S19kBosNandImageMap) -> Result<(), &'static str> {
    if *map != S19K_78_BOS_NAND_MAP {
        return Err("BOS nand map is not the `a lab unit` env map");
    }
    Ok(())
}

pub fn admit_s19k_78_proc_mtd_names(names: &[&str]) -> Result<(), &'static str> {
    if names == S19K_78_PROC_MTD_NAMES {
        return Ok(());
    }
    Err("`a lab unit` /proc/mtd is bootloader/tpl/stock_system/stock_config/overlay/system")
}

/// Board README must quote `a lab unit` hex sizes (mtd0=2MiB, mtd1=8MiB), not 4+4.
pub fn admit_s19k_board_readme_mtd_sizes(readme: &str) -> Result<(), &'static str> {
    if readme.contains("4 MiB") && !readme.contains("0x00200000") {
        return Err("am3-s19kpro README must not describe mtd0/mtd1 as 4+4 MiB");
    }
    for hex in [
        "0x00200000",
        "0x00800000",
        "0x03200000",
        "0x00500000",
        "0x02000000",
        "0x09900000",
    ] {
        if !readme.contains(hex) {
            return Err("README missing S19K_78_PROC_MTD_SIZES hex");
        }
    }
    Ok(())
}

/// The 2015.01 banner is not in `nand_env.bin`. Do not treat it as a captured string.
pub fn refuse_uboot_2015_prompt_as_held_env_string(env: &S19kNandEnv) -> Result<(), &'static str> {
    let hay: String = env.vars.values().cloned().collect();
    if hay.contains(S19K_UBOOT_2015_DEFAULT_STOP_PROMPT) {
        return Ok(());
    }
    Err("Hit any key to stop autoboot is U-Boot 2015.01 default text, not a nand_env string")
}

/// `recover_to_stock` erases `nvdata` then resets. Not a flag-only revert.
pub fn refuse_recover_to_stock_as_flag_only(cmd: &str) -> Result<(), &'static str> {
    if cmd.contains("nand erase.part nvdata") {
        return Err("recover_to_stock runs nand erase.part nvdata; not flag-only revert");
    }
    Ok(())
}

/// U-Boot first-BOS-start rewrite: load 0x2 into flagcmpaddr, erase 128 KiB, write 1 byte.
pub fn admit_s19k_78_recovery_set_flag(env: &S19kNandEnv) -> Result<(), &'static str> {
    if env.vars.get("recovery_set_flag").map(String::as_str) != Some(S19K_78_RECOVERY_SET_FLAG) {
        return Err("recovery_set_flag must erase 0x20000 then nand write 1");
    }
    if env.vars.get("recovery_set_flag_2").map(String::as_str) != Some(S19K_78_RECOVERY_SET_FLAG_2)
    {
        return Err("recovery_set_flag_2 must mw.b first_boot then run recovery_set_flag");
    }
    if !S19K_78_RECOVERY_SET_FLAG.contains("0x20000") {
        return Err("recovery_set_flag erase length missing");
    }
    if S19K_78_RECOVERY_FLAG_ERASE != 0x2_0000 {
        return Err("recovery-flag erase is 128 KiB");
    }
    Ok(())
}

/// Proves that the eraseblock used by the held `a lab unit` U-Boot
/// `recovery_set_flag` command contains no data other than its first flag byte.
///
/// The vendor command erases 128 KiB and writes back only one byte. A DCENT
/// installer must therefore refuse its `0x01 -> 0x02` first-boot path unless
/// every adjacent byte is already erased (`0xFF`). This is an offline
/// admission check, not permission to mutate NAND.
pub fn admit_s19k_78_flag_eraseblock_exclusive(block: &[u8]) -> Result<(), &'static str> {
    if block.len() != S19K_78_RECOVERY_FLAG_ERASE as usize {
        return Err("S19k recovery-flag eraseblock must be exactly 128 KiB");
    }
    if !matches!(
        block[0],
        S19K_78_RECOVERY_FLAG_INSTALLED
            | S19K_78_RECOVERY_FLAG_FIRST_BOOT
            | S19K_78_RECOVERY_FLAG_SUCCESSFUL
    ) {
        return Err("S19k recovery-flag byte is not a held 0x01/0x02/0x03 state");
    }
    if block[1..].iter().any(|byte| *byte != 0xFF) {
        return Err(
            "S19k .78 U-Boot erase+writes one flag byte; adjacent non-FF data would be destroyed",
        );
    }
    Ok(())
}

/// `0x02` falls through to `recover_to_stock`. It does not `bootm` mtd2.
pub fn refuse_s19k_flag_02_as_direct_mtd2_boot(flag: u8) -> Result<(), &'static str> {
    if flag == S19K_78_RECOVERY_FLAG_FIRST_BOOT {
        return Err(
            "flag 0x02 runs recover_to_stock (restore env + erase nvdata); not a direct mtd2 boot",
        );
    }
    Ok(())
}

/// `boot_bos` is `nand device 1` + `go $loadaddr`, not an mtd5 uImage nandwrite.
pub fn refuse_boot_bos_as_mtd5_uimage_write(cmd: &str) -> Result<(), &'static str> {
    if cmd.contains("nand device 1") || cmd.contains("go $loadaddr") {
        return Err("boot_bos reads nand device 1 then go $loadaddr; not mtd5 uImage nandwrite");
    }
    Ok(())
}

/// `recover_to_stock` is not `nandwrite` of a stock uImage to mtd5.
pub fn refuse_recover_to_stock_as_mtd5_uimage_write(cmd: &str) -> Result<(), &'static str> {
    if cmd.contains("nand erase.part nvdata") || cmd.contains("run recover_env") {
        return Err("recover_to_stock restores env and erases nvdata; not mtd5 uImage nandwrite");
    }
    Ok(())
}

/// Two stock-return mechanisms. Mixing them is a brick-class confusion.
/// : [`classify_s19k_stock_return_path`] **refuses**
/// [`Self::FirstbootEnvFlip`] — `a lab unit` `bootcmd` never reads `firstboot`.
/// The variant remains as a historical/S99 name, not an admitted S19k path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kStockReturnPath {
    /// Historical DCENT/S99 `fw_setenv firstboot 1`. **Not** an admitted
    /// S19k stock-return ().
    FirstbootEnvFlip,
    /// NAND recovery-flag `0x02` → `bootcmd` falls through to
    /// `recover_to_stock` (restore env + `nand erase.part nvdata`).
    RecoverToStockFlag,
}

/// `recovery_flag_first_boot` is the **name** of flag value `0x02`.
pub const S19K_78_RECOVERY_FLAG_FIRST_BOOT_NAME: &str = "recovery_flag_first_boot";
/// U-Boot env key used by DCENT S99upgrade / the revert helper.
pub const S19K_DCENT_FIRSTBOOT_ENV_KEY: &str = "firstboot";
/// Held `a lab unit` nand_env already stores this. `bootcmd` never reads it.
pub const S19K_78_FIRSTBOOT_ENV_VALUE: &str = "1";
/// `a lab unit` dmesg / `bootargs` token. Not the `firstboot` env key.
pub const S19K_78_ANDROIDBOOT_FIRSTBOOT: &str = "androidboot.firstboot=1";

/// `a lab unit` `bootcmd` sequencer never mentions the `firstboot` env key.
pub fn admit_s19k_78_bootcmd_has_no_firstboot(bootcmd: &str) -> Result<(), &'static str> {
    let mentions_firstboot_key = bootcmd.contains("${firstboot}")
        || bootcmd.contains("run firstboot")
        || bootcmd
            .split(|c: char| c.is_whitespace() || c == ';')
            .any(|t| t == "firstboot");
    if mentions_firstboot_key {
        return Err(".78 bootcmd unexpectedly reads firstboot");
    }
    if !bootcmd.contains("recover_to_stock") {
        return Err(".78 bootcmd must run recover_to_stock last");
    }
    Ok(())
}

pub fn refuse_firstboot_as_recover_to_stock() -> Result<(), &'static str> {
    Err("fw_setenv firstboot 1 is not recover_to_stock; .78 bootcmd never reads firstboot")
}

/// `a lab unit` `recover_env` imports 64 KiB from RAM `0x01060000`.
pub fn admit_s19k_78_recover_env_ram() -> Result<(), &'static str> {
    if S19K_78_RECOVER_ENV_RAM != 0x0106_0000 {
        return Err("recover_env RAM dest is 0x01060000");
    }
    if S19K_78_ENV_IMPORT_SIZE != 0x1_0000 {
        return Err("env import size is 0x10000");
    }
    if !S19K_78_RECOVER_ENV.contains("nand read 01060000") {
        return Err("recover_env must nand read 01060000");
    }
    if !S19K_78_RECOVER_ENV.contains("env import -d -c 01060000 0x10000") {
        return Err("recover_env must env import -d -c 01060000 0x10000");
    }
    Ok(())
}

/// `a lab unit` `recover_env` NAND source is `nandrecovery_env_offset` / `env_size`.
pub fn admit_s19k_78_recover_env_nand_src() -> Result<(), &'static str> {
    admit_s19k_78_recover_env_ram()?;
    if S19K_78_NANDRECOVERY_ENV != 0x0B00_0000 {
        return Err("nandrecovery_env_offset is 0x0B000000");
    }
    if S19K_78_ENV_SIZE != u64::from(S19K_78_ENV_IMPORT_SIZE) {
        return Err("env_size must equal env import size 0x10000");
    }
    if !S19K_78_RECOVER_ENV.contains("nand read 01060000 ${nandrecovery_env_offset} ${env_size}") {
        return Err("recover_env must nand read RAM from nandrecovery_env_offset env_size");
    }
    Ok(())
}

/// `a lab unit` BOS `nand_env` has no `mtdparts`. `nvdata` exists only inside
/// `recover_to_stock` after `recover_env` imports the stock map.
pub fn admit_s19k_78_nand_env_has_no_mtdparts(env: &S19kNandEnv) -> Result<(), &'static str> {
    if env.vars.contains_key("mtdparts") {
        return Err(".78 BOS nand_env has no mtdparts key");
    }
    Ok(())
}

pub fn admit_s19k_78_recover_erases_nvdata_after_recover_env() -> Result<(), &'static str> {
    let cmd = S19K_78_RECOVER_TO_STOCK;
    let env_i = cmd
        .find("run recover_env")
        .ok_or("recover_to_stock missing recover_env")?;
    let erase_i = cmd
        .find("nand erase.part nvdata")
        .ok_or("recover_to_stock missing erase.part nvdata")?;
    if env_i >= erase_i {
        return Err("recover_to_stock must run recover_env before nand erase.part nvdata");
    }
    Ok(())
}

pub fn refuse_s19k_erase_nvdata_before_recover_env() -> Result<(), &'static str> {
    Err(
        "nand erase.part nvdata is not a BOS /proc/mtd name; it is only valid after recover_env imports stock mtdparts",
    )
}

pub fn refuse_s19k_78_bos_overlay_as_uboot_nvdata() -> Result<(), &'static str> {
    Err("BOS mtd4 overlay is Linux /data UBI; not U-Boot erase.part nvdata")
}

/// `a lab unit` `recover_env` is nand-read, then `env default -a`, then
/// `env import -d -c`, then `env save`. Default-alone is compiled-in
/// U-Boot defaults, not the held `nandrecovery_env` blob.
pub fn admit_s19k_78_recover_env_default_before_import() -> Result<(), &'static str> {
    let cmd = S19K_78_RECOVER_ENV;
    let read_i = cmd
        .find("nand read 01060000")
        .ok_or("recover_env missing nand read")?;
    let def_i = cmd
        .find("env default -a")
        .ok_or("recover_env missing env default -a")?;
    let imp_i = cmd
        .find("env import -d -c")
        .ok_or("recover_env missing env import -d -c")?;
    let save_i = cmd.find("env save").ok_or("recover_env missing env save")?;
    if !(read_i < def_i && def_i < imp_i && imp_i < save_i) {
        return Err("recover_env must nand-read, env default -a, import -d -c, then env save");
    }
    Ok(())
}

pub fn refuse_s19k_env_default_a_as_recover_env() -> Result<(), &'static str> {
    Err(
        "env default -a alone loads compiled-in U-Boot defaults; recover_env then imports nandrecovery_env",
    )
}

pub fn refuse_s19k_env_import_without_default_a() -> Result<(), &'static str> {
    Err("env import without env default -a would merge stock onto leftover BOS env keys")
}

pub fn refuse_s19k_uboot_compiled_defaults_as_nandrecovery_env() -> Result<(), &'static str> {
    Err("compiled-in U-Boot defaults are not the held nandrecovery_env blob")
}

/// U-Boot 2015.01 `common/cmd_nvedit.c` `do_env_import` help.
/// Held `a lab unit` `ver` is [`S19K_78_UBOOT_VERSION`]. Factory AML USB
/// UBOOT item 2 has 0 of these strings (W379 classified as BL30).
pub const S19K_UBOOT_2015_ENV_IMPORT_DASH_D: &str = "delete existing environment before importing";
pub const S19K_UBOOT_2015_ENV_IMPORT_DASH_C: &str = "assume checksum protected environment format";

/// `a lab unit` `recover_env` is `env import -d -c` on U-Boot 2015.01:
/// `-d` deletes existing env, `-c` is the CRC env blob format.
pub fn admit_s19k_78_recover_env_import_flags() -> Result<(), &'static str> {
    if S19K_78_UBOOT_VERSION != "U-Boot 2015.01" {
        return Err("held BOS env is U-Boot 2015.01");
    }
    if !S19K_78_RECOVER_ENV.contains("env import -d -c 01060000 0x10000") {
        return Err("recover_env must env import -d -c 01060000 0x10000");
    }
    if !S19K_UBOOT_2015_ENV_IMPORT_DASH_D.contains("delete existing") {
        return Err("U-Boot 2015.01 -d is delete existing");
    }
    if !S19K_UBOOT_2015_ENV_IMPORT_DASH_C.contains("checksum protected") {
        return Err("U-Boot 2015.01 -c is checksum-protected format");
    }
    Ok(())
}

pub fn refuse_s19k_dry_run_as_env_import_dash_d() -> Result<(), &'static str> {
    Err("DCENT [DRY RUN] is a host walk; U-Boot 2015.01 env import -d deletes existing env")
}

pub fn refuse_s19k_env_import_dash_c_as_continue() -> Result<(), &'static str> {
    Err("U-Boot 2015.01 env import -c is checksum-protected format, not continue")
}

pub fn refuse_s19k_zynq_do_env_import_as_78_recover_env() -> Result<(), &'static str> {
    Err("20231108 BMU part01 do_env_import sits next to zynq_load/sdhci; not S19k AML recover_env")
}

pub fn refuse_firstboot_as_mtd2_boot() -> Result<(), &'static str> {
    Err("fw_setenv firstboot 1 does not bootm mtd2 stock_system")
}

pub fn refuse_recovery_flag_first_boot_name_as_fw_setenv() -> Result<(), &'static str> {
    Err("recovery_flag_first_boot is the 0x02 NAND flag name; not fw_setenv firstboot")
}

pub fn refuse_androidboot_firstboot_as_fw_setenv(cmdline: &str) -> Result<(), &'static str> {
    if cmdline.contains(S19K_78_ANDROIDBOOT_FIRSTBOOT) || cmdline.contains("androidboot.firstboot=")
    {
        return Err("dmesg androidboot.firstboot=1 is kernel cmdline, not fw_setenv firstboot");
    }
    Ok(())
}

/// `a lab unit` has `firstboot=1` **and** `androidboot.firstboot=1` in bootargs.
/// Neither is consulted by `bootcmd`.
pub fn admit_s19k_78_firstboot_unused_by_bootcmd(env: &S19kNandEnv) -> Result<(), &'static str> {
    if env
        .vars
        .get(S19K_DCENT_FIRSTBOOT_ENV_KEY)
        .map(String::as_str)
        != Some(S19K_78_FIRSTBOOT_ENV_VALUE)
    {
        return Err(".78 nand_env firstboot is 1 (present; unused by bootcmd)");
    }
    let bootcmd = env.vars.get("bootcmd").map(String::as_str).unwrap_or("");
    admit_s19k_78_bootcmd_has_no_firstboot(bootcmd)?;
    Ok(())
}

/// Admit the S19k corpus stock-return path.
///
/// : firstboot-only is **not** admitted. `a lab unit` `bootcmd` never
/// reads `firstboot`. Only recovery-flag `0x02` → `recover_to_stock`
/// is admitted. Mixing firstboot + `0x02` stays refused.
pub fn classify_s19k_stock_return_path(
    firstboot_set: bool,
    recovery_flag: Option<u8>,
) -> Result<S19kStockReturnPath, &'static str> {
    match (firstboot_set, recovery_flag) {
        (true, Some(S19K_78_RECOVERY_FLAG_FIRST_BOOT)) => {
            Err("firstboot=1 and flag 0x02 are distinct paths; refuse mixing")
        }
        (true, _) => Err(
            "firstboot-only is not an S19k stock-return path; .78 bootcmd never reads firstboot",
        ),
        (false, Some(S19K_78_RECOVERY_FLAG_FIRST_BOOT)) => {
            Ok(S19kStockReturnPath::RecoverToStockFlag)
        }
        _ => Err("no admitted stock-return path"),
    }
}

/// `FirstbootEnvFlip` is historical/S99, not an admitted `a lab unit` path.
pub fn refuse_s19k_firstboot_env_flip_as_stock_return() -> Result<(), &'static str> {
    Err("S19k stock-return is recover_to_stock via flag 0x02; FirstbootEnvFlip is not admitted")
}

/// `a lab unit` mtd3 is `stock_config` (UBI). `reserved` is a stale README name.
pub fn refuse_s19k_78_mtd3_as_reserved(name: &str) -> Result<(), &'static str> {
    if name == "reserved" {
        return Err("`a lab unit` mtd3 is stock_config, not reserved");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in pairs {
            body.extend_from_slice(k.as_bytes());
            body.push(b'=');
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        body.resize(S19K_NAND_ENV_LEN - 4, 0);
        let crc = crc32_iso_hdlc(&body);
        let mut out = Vec::with_capacity(S19K_NAND_ENV_LEN);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn shaped_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("bootdelay", "1"),
            ("stdin", "serial"),
            ("stdout", "serial"),
            ("stderr", "serial"),
            ("baudrate", "115200"),
            ("bootloader_version", S19K_78_UBOOT_VERSION),
            ("bootcmd", S19K_78_BOOTCMD),
            ("try_to_boot_bos_normally", S19K_78_TRY_BOS_NORMAL),
            ("try_to_boot_bos_after_install", S19K_78_TRY_BOS_AFTER_INSTALL),
            ("recover_to_stock", S19K_78_RECOVER_TO_STOCK),
            ("recover_env", S19K_78_RECOVER_ENV),
            ("recovery_set_flag", S19K_78_RECOVERY_SET_FLAG),
            ("recovery_set_flag_2", S19K_78_RECOVERY_SET_FLAG_2),
            ("boot_bos", S19K_78_BOOT_BOS),
            ("read_images_from_nand", S19K_78_READ_IMAGES),
            ("boot_stage2", S19K_78_BOOT_STAGE2),
            ("recovery_flag_installed", "0x1"),
            ("recovery_flag_first_boot", "0x2"),
            ("recovery_flag_successful", "0x3"),
            ("nandrootfs", "0x00000B800000"),
            ("nandrecovery_flag_offset", "0x00000B400000"),
            ("nandrecovery_env_offset", "0x00000B000000"),
            (
                "bootargs",
                "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml_uart,0xff803000 androidboot.firstboot=1",
            ),
            ("firstboot", "1"),
        ]
    }

    #[test]
    fn parse_and_admit_78_shaped_env() {
        let blob = env_with(&shaped_pairs());
        let env = parse_s19k_nand_env(&blob).unwrap();
        assert!(env.crc_ok);
        assert!(admit_s19k_78_nand_env(&env).is_ok());
        assert_eq!(
            classify_s19k_uboot_interrupt(&env).unwrap(),
            S19kUbootInterrupt::AnyKeyDuringBootdelay
        );
        assert!(refuse_uboot_2015_prompt_as_held_env_string(&env).is_err());
        assert!(refuse_recover_to_stock_as_flag_only(S19K_78_RECOVER_TO_STOCK).is_err());
        assert!(admit_s19k_78_recover_env_ram().is_ok());
        assert!(admit_s19k_78_recover_env_nand_src().is_ok());
        assert_eq!(S19K_78_RECOVER_ENV_RAM, 0x0106_0000);
        assert_eq!(S19K_78_ENV_IMPORT_SIZE, 0x1_0000);
        assert_eq!(S19K_78_NANDRECOVERY_ENV, 0x0B00_0000);
        assert_eq!(S19K_78_ENV_SIZE, 0x1_0000);
        assert!(refuse_s19k_flag_02_as_direct_mtd2_boot(0x02).is_err());
        assert!(refuse_s19k_flag_02_as_direct_mtd2_boot(0x03).is_ok());
        assert!(refuse_boot_bos_as_mtd5_uimage_write(S19K_78_READ_IMAGES).is_err());
        assert!(refuse_recover_to_stock_as_mtd5_uimage_write(S19K_78_RECOVER_TO_STOCK).is_err());
        assert!(admit_s19k_78_bootcmd_has_no_firstboot(S19K_78_BOOTCMD).is_ok());
        let bootcmd_plan = format_s19k_uboot_bootcmd_plan();
        assert!(admit_s19k_uboot_bootcmd_plan(&bootcmd_plan).is_ok());
        assert_eq!(
            S19K_UBOOT_BOOTCMD_ARMS[0],
            S19kUbootBootcmdArm::TryBosNormally
        );
        assert_eq!(
            S19K_UBOOT_BOOTCMD_ARMS[2],
            S19kUbootBootcmdArm::RecoverToStock
        );
        assert!(bootcmd_plan.contains("action0=BootBos"));
        assert!(bootcmd_plan.contains("action1=FirstBosThenSetFlag2"));
        assert!(bootcmd_plan.contains("action2=RecoverToStock"));
        assert!(admit_s19k_uboot_bootcmd_plan("arm0=only").is_err());
        assert!(admit_s19k_78_firstboot_unused_by_bootcmd(&env).is_ok());
        assert!(
            admit_s19k_78_bootcmd_has_no_firstboot("run firstboot; run recover_to_stock").is_err()
        );
        assert!(refuse_firstboot_as_recover_to_stock().is_err());
        assert!(refuse_firstboot_as_mtd2_boot().is_err());
        assert!(refuse_recovery_flag_first_boot_name_as_fw_setenv().is_err());
        assert!(refuse_androidboot_firstboot_as_fw_setenv(S19K_78_ANDROIDBOOT_FIRSTBOOT).is_err());
        assert!(classify_s19k_stock_return_path(true, None).is_err());
        assert!(refuse_s19k_firstboot_env_flip_as_stock_return().is_err());
        assert_eq!(
            classify_s19k_stock_return_path(false, Some(0x02)).unwrap(),
            S19kStockReturnPath::RecoverToStockFlag
        );
        assert!(classify_s19k_stock_return_path(true, Some(0x02)).is_err());
        assert!(classify_s19k_stock_return_path(false, None).is_err());
        const REVERT: &str = include_str!("../../../scripts/revert_to_stock_am3_aml_s19k.sh");
        const FLAG_SH: &str = include_str!("../../../scripts/s19k_write_recovery_flag.sh");
        const INSTALL: &str = include_str!("../../../scripts/install_amlogic_persistent.sh");
        assert!(REVERT.contains("NOT recover_to_stock"));
        assert!(REVERT.contains("does NOT boot mtd2"));
        assert!(REVERT.contains("refusing firstboot-only"));
        assert!(REVERT.contains("REVERT_COMMIT_PLAN"));
        assert!(REVERT.contains("recover_env"));
        assert!(REVERT.contains("nandrecovery_env.bin"));
        assert!(!REVERT.contains("Reboot now to start stock firmware"));
        assert!(!REVERT.contains("\nfw_setenv firstboot 1\n"));
        assert!(FLAG_SH.contains("recover_to_stock"));
        assert!(FLAG_SH.contains("NOT a direct bootm of mtd2"));
        assert!(FLAG_SH.contains("NOT fw_setenv firstboot"));
        assert!(INSTALL.contains("recover_to_stock"));
        assert!(!INSTALL.contains("U-Boot will revert to mtd2 stock_system if first boot fails"));
        assert!(!INSTALL.contains("U-Boot reverts to mtd2 stock_system"));
        assert!(refuse_s19k_78_mtd3_as_reserved("reserved").is_err());
        assert!(refuse_s19k_78_mtd3_as_reserved("stock_config").is_ok());
        assert_eq!(
            classify_s19k_uboot_flag_action(0x03),
            S19kUbootFlagAction::BootBos
        );
        assert_eq!(
            classify_s19k_uboot_flag_action(0x01),
            S19kUbootFlagAction::FirstBosThenSetFlag2
        );
        assert_eq!(
            classify_s19k_uboot_flag_action(0x02),
            S19kUbootFlagAction::RecoverToStock
        );
        assert_eq!(
            classify_s19k_uboot_flag_action(0x00),
            S19kUbootFlagAction::RecoverToStock
        );
        assert!(admit_s19k_78_bos_nand_map(&S19K_78_BOS_NAND_MAP).is_ok());
        assert!(admit_s19k_78_proc_mtd_names(S19K_78_PROC_MTD_NAMES).is_ok());
        assert!(admit_s19k_78_proc_mtd_names(&[
            "bootloader",
            "tpl",
            "stock_system",
            "reserved",
            "overlay",
            "system"
        ])
        .is_err());
        assert!(parse_s19k_nand_env(&[0u8; 8]).is_err());
        let mut zero_delay = env.clone();
        zero_delay.vars.insert("bootdelay".into(), "0".into());
        assert!(classify_s19k_uboot_interrupt(&zero_delay).is_err());
        let mut keyed = env.clone();
        keyed.vars.insert("bootstopkey".into(), "xyz".into());
        assert!(classify_s19k_uboot_interrupt(&keyed).is_err());
        assert!(admit_s19k_78_nand_env(&keyed).is_err());
        assert_eq!(S19K_78_BOOTDELAY, 1);
        assert!(S19K_78_TRY_BOS_AFTER_INSTALL.contains("recovery_set_flag_2"));
        assert!(admit_s19k_78_recovery_set_flag(&env).is_ok());
        assert!(
            S19K_78_RECOVERY_SET_FLAG.contains("nand erase ${nandrecovery_flag_offset} 0x20000")
        );
        assert!(S19K_78_RECOVERY_SET_FLAG_2.contains("recovery_flag_first_boot"));
        assert_eq!(S19K_78_RECOVERY_FLAG_ERASE, 0x2_0000);
        assert_eq!(
            S19K_78_RECOVERY_FLAG_ERASE,
            crate::s19k_am3_install::ROOTFS_ERASESIZE
        );
        assert_eq!(S19K_78_NAND_ENV_CRC, 0x471D_6B1A);
        assert_eq!(S19K_78_PROC_MTD_SIZES.iter().sum::<u64>(), 0x0FA0_0000);
        assert_eq!(S19K_78_PROC_MTD_SIZES[..5].iter().sum::<u64>(), 0x0610_0000);
        assert_eq!(S19K_78_PROC_MTD_SIZES[0], 0x0020_0000);
        assert_eq!(S19K_78_PROC_MTD_SIZES[1], 0x0080_0000);
        assert!(admit_s19k_board_readme_mtd_sizes(
            "SoT 0x00200000 0x00800000 0x03200000 0x00500000 0x02000000 0x09900000"
        )
        .is_ok());
        assert!(
            admit_s19k_board_readme_mtd_sizes("| 0   | bootloader | 0x00000000 | 4 MiB |").is_err()
        );
    }

    #[test]
    fn s19k_recover_to_stock_erases_nvdata_after_recover_env() {
        assert!(admit_s19k_78_recover_erases_nvdata_after_recover_env().is_ok());
        assert!(
            S19K_78_RECOVER_TO_STOCK.find("run recover_env").unwrap()
                < S19K_78_RECOVER_TO_STOCK
                    .find("nand erase.part nvdata")
                    .unwrap()
        );
        assert!(!S19K_78_PROC_MTD_NAMES.contains(&"nvdata"));
        assert_eq!(S19K_78_PROC_MTD_NAMES[4], "overlay");
        assert!(refuse_s19k_erase_nvdata_before_recover_env().is_err());
        assert!(refuse_s19k_78_bos_overlay_as_uboot_nvdata().is_err());
        let blob = env_with(&shaped_pairs());
        let env = parse_s19k_nand_env(&blob).unwrap();
        assert!(admit_s19k_78_nand_env_has_no_mtdparts(&env).is_ok());
        let mut with_parts = env.clone();
        with_parts
            .vars
            .insert("mtdparts".into(), "aml-nand:1m(boot)".into());
        assert!(admit_s19k_78_nand_env_has_no_mtdparts(&with_parts).is_err());
        assert!(
            crate::s19k_aml_dtb::refuse_s19k_78_linux_mtd_as_uboot_nvdata(S19K_78_PROC_MTD_NAMES)
                .is_err()
        );
    }

    #[test]
    fn s19k_78_vendor_flag_rewrite_requires_an_exclusive_eraseblock() {
        let mut block = vec![0xFF; S19K_78_RECOVERY_FLAG_ERASE as usize];
        block[0] = S19K_78_RECOVERY_FLAG_SUCCESSFUL;
        assert!(admit_s19k_78_flag_eraseblock_exclusive(&block).is_ok());

        for state in [
            S19K_78_RECOVERY_FLAG_INSTALLED,
            S19K_78_RECOVERY_FLAG_FIRST_BOOT,
            S19K_78_RECOVERY_FLAG_SUCCESSFUL,
        ] {
            block[0] = state;
            assert!(admit_s19k_78_flag_eraseblock_exclusive(&block).is_ok());
        }

        block[0] = 0x00;
        assert!(admit_s19k_78_flag_eraseblock_exclusive(&block).is_err());
        block[0] = S19K_78_RECOVERY_FLAG_SUCCESSFUL;
        block[0x1_FFFF] = 0x7A;
        assert!(admit_s19k_78_flag_eraseblock_exclusive(&block).is_err());
        assert!(admit_s19k_78_flag_eraseblock_exclusive(&block[..block.len() - 1]).is_err());
    }

    #[test]
    fn s19k_recover_env_defaults_before_import() {
        assert!(admit_s19k_78_recover_env_default_before_import().is_ok());
        let cmd = S19K_78_RECOVER_ENV;
        assert!(cmd.find("nand read 01060000").unwrap() < cmd.find("env default -a").unwrap());
        assert!(cmd.find("env default -a").unwrap() < cmd.find("env import -d -c").unwrap());
        assert!(cmd.find("env import -d -c").unwrap() < cmd.find("env save").unwrap());
        assert!(refuse_s19k_env_default_a_as_recover_env().is_err());
        assert!(refuse_s19k_env_import_without_default_a().is_err());
        assert!(refuse_s19k_uboot_compiled_defaults_as_nandrecovery_env().is_err());
        assert!(S19K_78_RECOVER_ENV.contains("env default -a; env import -d -c"));
    }

    #[test]
    fn s19k_recover_env_import_flags_are_delete_and_crc() {
        assert!(admit_s19k_78_recover_env_import_flags().is_ok());
        assert_eq!(S19K_78_UBOOT_VERSION, "U-Boot 2015.01");
        assert!(S19K_78_RECOVER_ENV.contains("env import -d -c"));
        assert!(S19K_UBOOT_2015_ENV_IMPORT_DASH_D.starts_with("delete existing"));
        assert!(S19K_UBOOT_2015_ENV_IMPORT_DASH_C.contains("checksum protected"));
        assert!(refuse_s19k_dry_run_as_env_import_dash_d().is_err());
        assert!(refuse_s19k_env_import_dash_c_as_continue().is_err());
        assert!(refuse_s19k_zynq_do_env_import_as_78_recover_env().is_err());
        assert!(!S19K_UBOOT_2015_ENV_IMPORT_DASH_D.contains("dry-run"));
        assert!(!S19K_UBOOT_2015_ENV_IMPORT_DASH_C.contains("continue"));
    }
}
