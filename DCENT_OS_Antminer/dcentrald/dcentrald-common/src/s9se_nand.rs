//! S9 SE NAND / install refuse (desk-only).
//!
//! Partition table is the S9 SE DTB
//! `ps7-nand@e1000000/partition@*` plus inner `runme.sh` offsets.
//! `bitmainer_setup.sh` mounts UBI `mtd2` → `/config` and `mtd5` → `/nvdata`.
//! FLASH stays refused. Classic S9 SD/sysupgrade images are refused.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9SeNandPartition {
    pub label: &'static str,
    pub offset: u32,
    pub size: u32,
}

pub const NAND_BOOT_ENV_DTS_KERNEL: S9SeNandPartition = S9SeNandPartition {
    label: "BOOT.bin-env-dts-kernel",
    offset: 0x0000_0000,
    size: 0x0280_0000,
};
pub const NAND_RAMFS: S9SeNandPartition = S9SeNandPartition {
    label: "ramfs",
    offset: 0x0280_0000,
    size: 0x0200_0000,
};
pub const NAND_CONFIGS: S9SeNandPartition = S9SeNandPartition {
    label: "configs",
    offset: 0x0480_0000,
    size: 0x0080_0000,
};
pub const NAND_RESERVE: S9SeNandPartition = S9SeNandPartition {
    label: "reserve",
    offset: 0x0500_0000,
    size: 0x0100_0000,
};
pub const NAND_RAMFS_BAK: S9SeNandPartition = S9SeNandPartition {
    label: "ramfs-bak",
    offset: 0x0600_0000,
    size: 0x0200_0000,
};
pub const NAND_RESERVE1: S9SeNandPartition = S9SeNandPartition {
    label: "reserve1",
    offset: 0x0800_0000,
    size: 0x0800_0000,
};

pub const NAND_PARTITIONS: &[S9SeNandPartition] = &[
    NAND_BOOT_ENV_DTS_KERNEL,
    NAND_RAMFS,
    NAND_CONFIGS,
    NAND_RESERVE,
    NAND_RAMFS_BAK,
    NAND_RESERVE1,
];

/// DTB `memory@0` size. Same as Ctrl_C43 256 MiB DRAM.
pub const DRAM_SIZE_BYTES: u32 = 0x1000_0000;
/// Sum of NAND partitions (also 256 MiB).
pub const NAND_SIZE_BYTES: u32 = 0x1000_0000;

/// `runme.sh` payload offsets inside mtd0.
pub const RUNME_BOOT_BIN_OFF: u32 = 0x0000_0000;
pub const RUNME_DTB_OFF: u32 = 0x01A0_0000;
pub const RUNME_UIMAGE_OFF: u32 = 0x0200_0000;

/// UBI: `ubi.sh 2 0 configs` → `/config`; `ubi.sh 5 1 reserve1` → `/nvdata`.
pub const UBI_CONFIG_MTD: u8 = 2;
pub const UBI_NVDATA_MTD: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeNandError {
    FlashRefused,
    ClassicS9ImageRefused,
    PartitionTableMismatch,
}

pub fn admit_nand_table() -> Result<(), S9SeNandError> {
    let mut cursor = 0u32;
    let mut total = 0u32;
    for p in NAND_PARTITIONS {
        if p.offset != cursor {
            return Err(S9SeNandError::PartitionTableMismatch);
        }
        cursor = cursor.saturating_add(p.size);
        total = total.saturating_add(p.size);
    }
    if total != NAND_SIZE_BYTES || DRAM_SIZE_BYTES != 0x1000_0000 {
        return Err(S9SeNandError::PartitionTableMismatch);
    }
    if RUNME_DTB_OFF >= NAND_BOOT_ENV_DTS_KERNEL.size
        || RUNME_UIMAGE_OFF >= NAND_BOOT_ENV_DTS_KERNEL.size
    {
        return Err(S9SeNandError::PartitionTableMismatch);
    }
    Ok(())
}

pub fn refuse_s9se_flash() -> Result<(), S9SeNandError> {
    Err(S9SeNandError::FlashRefused)
}

/// Classic `am1-s9` XC7Z010 images must not land on Ctrl_C43.
pub fn refuse_classic_s9_image(board_target: &str) -> Result<(), S9SeNandError> {
    if board_target == "am1-s9" || board_target == "am1-s15" {
        return Err(S9SeNandError::ClassicS9ImageRefused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtb_nand_and_dram_are_256mib() {
        admit_nand_table().unwrap();
        assert_eq!(NAND_PARTITIONS.len(), 6);
        assert_eq!(NAND_CONFIGS.offset, 0x0480_0000);
        assert_eq!(UBI_CONFIG_MTD, 2);
        assert_eq!(UBI_NVDATA_MTD, 5);
        assert_eq!(refuse_s9se_flash(), Err(S9SeNandError::FlashRefused));
        assert!(refuse_classic_s9_image("am1-s9").is_err());
        refuse_classic_s9_image("am1-s9se").unwrap();
    }
}
