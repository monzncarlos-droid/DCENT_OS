//! S9 SE / S9k stock-FPGA AXI map (desk-only).
//!
//! Word index × 4 = byte offset (`S9k/cgminer.dec` `zynq.c` getters).
//! S9 SE `cgminer` carries the same `get_*` / `set_*` names and
//! `/dev/axi_fpga_dev` + `/dev/fpga_mem`. This module never mmaps those
//! devices.
//!
//! DMA base comes from S9 SE `cgminer.sh`: 256 MiB (`MemTotal` < 400000 kB)
//! loads `fpga_mem_driver.ko fpga_mem_offset_addr=0x0F000000`. The DTB
//! `memory@0` reg is `0x00000000 0x10000000` (256 MiB).

/// `set_BC_write_command` trigger OR (`zynq.c` + every `asic.c` TX).
pub const BC_WRITE_TRIGGER: u32 = 0x8080_0000;
/// Busy / buffer-not-ready bit (`get_BC_write_command() < 0`).
pub const BC_WRITE_BUSY_BIT: u32 = 1 << 31;
/// Chain-select field in BC_WRITE: `(chain << 16) & 0x000F_0000`.
pub const BC_WRITE_CHAIN_SHIFT: u32 = 16;
pub const BC_WRITE_CHAIN_MASK: u32 = 0x000F_0000;
/// Bits preserved when inserting chain + trigger: `ret & 0xFFF0FFFF`.
pub const BC_WRITE_PRESERVE_MASK: u32 = 0xFFF0_FFFF;
/// FPGA baud field in BC_WRITE: `bauddiv & 0x3F | ret & 0xFFFFFFC0`.
pub const BC_WRITE_BAUD_MASK: u32 = 0x3F;
pub const BC_WRITE_BAUD_PRESERVE: u32 = 0xFFFF_FFC0;

/// 256 MiB Ctrl_C43 path (`cgminer.sh` else-branch).
pub const FPGA_MEM_OFFSET_256MIB: u32 = 0x0F00_0000;
/// 512 MiB-class path (`400000 < MemTotal < 1000000` kB).
pub const FPGA_MEM_OFFSET_512MIB: u32 = 0x1F00_0000;
/// ≥ 1 GiB path (`MemTotal > 1000000` kB).
pub const FPGA_MEM_OFFSET_1GIB: u32 = 0x3F00_0000;

pub const AXI_FPGA_DEV_PATH: &str = "/dev/axi_fpga_dev";
pub const FPGA_MEM_DEV_PATH: &str = "/dev/fpga_mem";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9SeFpgaReg {
    pub axi_word: u32,
    pub byte_offset: u32,
}

impl S9SeFpgaReg {
    pub const fn from_axi_word(word: u32) -> Self {
        Self {
            axi_word: word,
            byte_offset: word * 4,
        }
    }
}

pub const FAN_SPEED: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(1);
pub const HASH_ON_PLUG: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(2);
pub const BUFFER_SPACE: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(3);
pub const RETURN_NONCE0: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(4);
pub const RETURN_NONCE1: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(5);
pub const NONCE_NUMBER_IN_FIFO: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(6);
pub const NONCE_FIFO_INTERRUPT: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(7);
pub const IIC_COMMAND: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(12);
pub const RESET_HASHBOARD: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(13);
/// S9 SE `set_bt8d_control` `str [axi, #0x3c]` = word 15.
pub const BT8D_CONTROL: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(15);
pub const TW_WRITE: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(16);
pub const TW_WRITE_CONT: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(17);
pub const QN_WRITE_DATA: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(32);
pub const FAN_CONTROL: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(33);
pub const TIME_OUT_CONTROL: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(34);
pub const TICKET_MASK: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(35);
pub const HASH_COUNTING_NUMBER: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(36);
pub const BC_WRITE_COMMAND: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(48);
pub const BC_COMMAND_BUFFER0: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(49);
pub const BC_COMMAND_BUFFER1: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(50);
pub const BC_COMMAND_BUFFER2: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(51);
pub const CRC_COUNT: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(62);
pub const DHASH_ACC_CONTROL: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(64);
pub const COINBASE_LEN_NONCE2_LEN: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(65);
pub const WORK_NONCE2_0: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(66);
pub const WORK_NONCE2_1: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(67);
/// S9k / S9 SE `set_nonce2_and_job_id_store_address` → `axi[68]`.
pub const NONCE2_AND_JOBID_STORE: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(68);
pub const MERKLE_BIN_NUMBER: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(69);
pub const JOB_START_ADDRESS: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(70);
/// S9 SE / S9k `set_job_length` → `axi[71]`.
pub const JOB_LENGTH: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(71);
pub const JOB_ID: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(73);
pub const BLOCK_HEADER_VERSION: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(76);
pub const TIME_STAMP: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(77);
pub const TARGET_BITS: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(78);
/// `set_pre_header_hash` writes eight words `axi[80..=87]`.
pub const PRE_HEADER_HASH0: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(80);
pub const PRE_HEADER_HASH7: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(87);
pub const BLOCK_HEADER_VERSION_1: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(89);
/// S9 SE `get_block_header_version_2` `ldr [axi, #0x168]`.
pub const BLOCK_HEADER_VERSION_2: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(90);
/// S9 SE `get_block_header_version_3` `ldr [axi, #0x16c]`.
pub const BLOCK_HEADER_VERSION_3: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(91);
/// `set_block_header_version_1(bbversion | 0x4000)` when `opt_multi_version == 2`.
pub const VERSION_1_AB_OR: u32 = 0x4000;
pub const HARDWARE_VERSION: S9SeFpgaReg = S9SeFpgaReg::from_axi_word(0);

/// Low 16 of `*axi_fpga_addr` compared in `bitmain_axi_init`.
pub const HARDWARE_VERSION_VALUE: u16 = 50_433; // 0xC501
/// `mmap(..., 352, ...)` of `/dev/axi_fpga_dev`.
pub const AXI_MMAP_BYTES: usize = 352;
/// `set_QN_write_data_command(2155905039)` at soc init / reopen.
pub const QN_WRITE_DATA_INIT: u32 = 0x8080_800F;
/// `open_core_bm1393` / `pre_open` start with `set_hash_counting_number(0)`.
pub const HASH_COUNTING_OPEN_CORE: u32 = 0;
/// `get_nonce_number_in_fifo() & 0x1FF`.
pub const NONCE_FIFO_COUNT_MASK: u32 = 0x1FF;
/// `set_nonce_fifo_interrupt(ret | 0x10000)`.
pub const NONCE_FIFO_INTERRUPT_ENABLE: u32 = 0x0001_0000;
/// `set_iic` writes `data & 0x3FFFFFFF`.
pub const IIC_COMMAND_WRITE_MASK: u32 = 0x3FFF_FFFF;
pub const IIC_READ_BIT: u32 = 0x0200_0000;
pub const IIC_REG_VALID_BIT: u32 = 0x0100_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeFpgaError {
    ChainOutOfRange { chain: u8 },
    FpgaIoRefused,
}

/// Pack BC_WRITE for one chain TX. Planner only.
pub fn pack_bc_write_command(previous: u32, chain: u8) -> Result<u32, S9SeFpgaError> {
    if chain > 15 {
        return Err(S9SeFpgaError::ChainOutOfRange { chain });
    }
    Ok((previous & BC_WRITE_PRESERVE_MASK)
        | (u32::from(chain) << BC_WRITE_CHAIN_SHIFT)
        | BC_WRITE_TRIGGER)
}

/// Pack FPGA baud bits into BC_WRITE (`set_baud`).
pub fn pack_bc_write_baud(previous: u32, bauddiv: u8) -> u32 {
    (u32::from(bauddiv) & BC_WRITE_BAUD_MASK) | (previous & BC_WRITE_BAUD_PRESERVE)
}

/// Hashboard reset bitmask: bit `chain` of `axi[13]`.
pub fn hashboard_reset_mask(chain: u8) -> Result<u32, S9SeFpgaError> {
    if chain > 15 {
        return Err(S9SeFpgaError::ChainOutOfRange { chain });
    }
    Ok(1u32 << chain)
}

/// `set_reset_hashboard`: OR the bit to assert, AND-NOT to release.
pub fn apply_hashboard_reset(
    previous: u32,
    chain: u8,
    assert_reset: bool,
) -> Result<u32, S9SeFpgaError> {
    let bit = hashboard_reset_mask(chain)?;
    if assert_reset {
        Ok(previous | bit)
    } else {
        Ok(previous & !bit)
    }
}

/// S9 SE `set_reset_allhashboard`: low 16 bits of `axi[13]`.
pub const ALL_HASHBOARD_RESET_MASK: u32 = 0xFFFF;

pub fn apply_all_hashboard_reset(previous: u32, assert_reset: bool) -> u32 {
    if assert_reset {
        (previous & !ALL_HASHBOARD_RESET_MASK) | ALL_HASHBOARD_RESET_MASK
    } else {
        previous & !ALL_HASHBOARD_RESET_MASK
    }
}

/// `zynq_set_iic` command word. Not a PIC write permit.
pub fn pack_zynq_iic(
    dev_addr: u8,
    which_iic: u8,
    read: bool,
    reg_addr_valid: bool,
    reg_addr: u8,
    data: u8,
) -> u32 {
    let mut value = 0u32;
    if read {
        value = IIC_READ_BIT;
    }
    if reg_addr_valid {
        value |= (u32::from(reg_addr) << 8) | IIC_REG_VALID_BIT;
    }
    value |= u32::from(data);
    value |= (u32::from(dev_addr) << 16) & 0x0007_0000;
    value |= (u32::from(dev_addr >> 3) << 20) & 0x00F0_0000;
    value |= (u32::from(which_iic) << 26) & 0x0C00_0000;
    value
}

pub fn iic_command_store_word(packed: u32) -> u32 {
    packed & IIC_COMMAND_WRITE_MASK
}

pub fn hash_on_plug_populated(mask: u32, chain: u8) -> bool {
    chain <= 15 && ((mask >> chain) & 1) == 1
}

pub fn hash_on_plug_count(mask: u32) -> u8 {
    (0u8..16).filter(|c| hash_on_plug_populated(mask, *c)).count() as u8
}

/// `check_chain` success on T11/S9 SE is exactly three populated bits.
pub fn admit_three_populated_chains(mask: u32) -> Result<(), S9SeFpgaError> {
    if hash_on_plug_count(mask) != 3 {
        return Err(S9SeFpgaError::ChainOutOfRange {
            chain: hash_on_plug_count(mask),
        });
    }
    Ok(())
}

pub fn admit_hardware_version_low16(observed: u32) -> bool {
    observed as u16 == HARDWARE_VERSION_VALUE
}

/// `BUFFER_SPACE` bit `chain` means the TW FIFO will accept a write.
pub fn work_fifo_ready(buffer_space: u32, chain: u8) -> bool {
    chain <= 15 && ((buffer_space >> chain) & 1) != 0
}

/// `get_fan_speed`: low 8 = speed, bits[10:8] = fan id. Not a tach admit.
pub fn decode_fan_speed_word(ret: u32) -> (u8, u8) {
    let speed = ret as u8;
    let fan_id = ((ret >> 8) & 7) as u8;
    (fan_id, speed)
}

/// `set_merkle_bin_number` stores the low 16 bits.
pub fn merkle_bin_number_word(merkle_count: u16) -> u32 {
    u32::from(merkle_count)
}

/// FPGA `TICKET_MASK` (`axi[35]`) is the raw `asic_diff`, not the chip bit-reverse.
pub fn fpga_ticket_mask_word(asic_diff: u8) -> u32 {
    u32::from(asic_diff)
}

/// `set_block_header_version_1` AB-midstate sibling.
pub fn block_header_version_1_word(bbversion: u32) -> u32 {
    bbversion | VERSION_1_AB_OR
}

/// Select `fpga_mem` offset from `/proc/meminfo` MemTotal kilobytes.
pub fn fpga_mem_offset_from_memtotal_kb(memtotal_kb: u64) -> u32 {
    if memtotal_kb > 1_000_000 {
        FPGA_MEM_OFFSET_1GIB
    } else if memtotal_kb > 400_000 {
        FPGA_MEM_OFFSET_512MIB
    } else {
        FPGA_MEM_OFFSET_256MIB
    }
}

/// `bitmain_soc_init` `PHY_MEM_NONCE2_JOBID_ADDRESS` on the 256 MiB path
/// is the same `0x0F000000` as `fpga_mem`. Not a mmap permit.
pub fn nonce2_jobid_store_phy() -> u32 {
    FPGA_MEM_OFFSET_256MIB
}

/// Ctrl_C43 256 MiB DRAM is the S9 SE path. Not a 512 MiB classic S9.
pub fn admit_s9se_fpga_mem_is_256mib_path() -> Result<(), S9SeFpgaError> {
    let kb = 256u64 * 1024;
    if fpga_mem_offset_from_memtotal_kb(kb) != FPGA_MEM_OFFSET_256MIB {
        return Err(S9SeFpgaError::FpgaIoRefused);
    }
    Ok(())
}

/// No mmap /dev/axi_fpga_dev this wave.
pub fn refuse_s9se_fpga_io() -> Result<(), S9SeFpgaError> {
    Err(S9SeFpgaError::FpgaIoRefused)
}

/// Pack a 5-byte VIL/short frame into the three BC buffer words.
pub fn pack_bc_buffer_short(frame5: [u8; 5]) -> [u32; 3] {
    let w0 = u32::from_be_bytes([frame5[0], frame5[1], frame5[2], frame5[3]]);
    let w1 = u32::from(frame5[4]) << 24;
    [w0, w1, 0]
}

/// Pack a 9-byte set-config frame into the three BC buffer words.
pub fn pack_bc_buffer_set_config(frame9: [u8; 9]) -> [u32; 3] {
    let w0 = u32::from_be_bytes([frame9[0], frame9[1], frame9[2], frame9[3]]);
    let w1 = u32::from_be_bytes([frame9[4], frame9[5], frame9[6], frame9[7]]);
    let w2 = u32::from(frame9[8]) << 24;
    [w0, w1, w2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axi_word_times_four_is_byte_offset() {
        assert_eq!(FAN_SPEED.byte_offset, 0x04);
        assert_eq!(HASH_ON_PLUG.byte_offset, 0x08);
        assert_eq!(BUFFER_SPACE.byte_offset, 0x0C);
        assert_eq!(IIC_COMMAND.byte_offset, 0x30);
        assert_eq!(RESET_HASHBOARD.byte_offset, 0x34);
        assert_eq!(BT8D_CONTROL.byte_offset, 0x3C);
        assert_eq!(BT8D_CONTROL.axi_word, 15);
        assert_eq!(TW_WRITE.byte_offset, 0x40);
        assert_eq!(TW_WRITE_CONT.byte_offset, 0x44);
        assert_eq!(FAN_CONTROL.byte_offset, 0x84);
        assert_eq!(HASH_COUNTING_NUMBER.byte_offset, 0x90);
        assert_eq!(BC_WRITE_COMMAND.byte_offset, 0xC0);
        assert_eq!(BC_COMMAND_BUFFER0.byte_offset, 0xC4);
        assert_eq!(DHASH_ACC_CONTROL.byte_offset, 0x100);
        assert_eq!(JOB_LENGTH.axi_word, 71);
        assert_eq!(JOB_LENGTH.byte_offset, 0x11C);
        assert_eq!(PRE_HEADER_HASH0.axi_word, 80);
        assert_eq!(PRE_HEADER_HASH0.byte_offset, 0x140);
        assert_eq!(PRE_HEADER_HASH7.byte_offset, 0x15C);
        assert_eq!(BLOCK_HEADER_VERSION_1.axi_word, 89);
        assert_eq!(NONCE2_AND_JOBID_STORE.axi_word, 68);
        assert_eq!(NONCE2_AND_JOBID_STORE.byte_offset, 0x110);
        assert_eq!(BLOCK_HEADER_VERSION_2.byte_offset, 0x168);
        assert_eq!(BLOCK_HEADER_VERSION_3.byte_offset, 0x16C);
        assert_eq!(nonce2_jobid_store_phy(), FPGA_MEM_OFFSET_256MIB);
        assert_eq!(nonce2_jobid_store_phy(), 0x0F00_0000);
    }

    #[test]
    fn bc_write_inserts_chain_and_trigger() {
        let v = pack_bc_write_command(0, 2).unwrap();
        assert_eq!(v & BC_WRITE_TRIGGER, BC_WRITE_TRIGGER);
        assert_eq!((v & BC_WRITE_CHAIN_MASK) >> BC_WRITE_CHAIN_SHIFT, 2);
        assert!(pack_bc_write_command(0, 16).is_err());
    }

    #[test]
    fn s9se_256mib_selects_0f000000() {
        admit_s9se_fpga_mem_is_256mib_path().unwrap();
        assert_eq!(fpga_mem_offset_from_memtotal_kb(262_144), FPGA_MEM_OFFSET_256MIB);
        assert_eq!(fpga_mem_offset_from_memtotal_kb(524_288), FPGA_MEM_OFFSET_512MIB);
        assert_eq!(fpga_mem_offset_from_memtotal_kb(1_048_576), FPGA_MEM_OFFSET_1GIB);
        assert_eq!(refuse_s9se_fpga_io(), Err(S9SeFpgaError::FpgaIoRefused));
    }

    #[test]
    fn reset_mask_is_one_bit_per_chain() {
        assert_eq!(hashboard_reset_mask(0).unwrap(), 1);
        assert_eq!(hashboard_reset_mask(2).unwrap(), 4);
        assert_eq!(apply_hashboard_reset(0, 2, true).unwrap(), 4);
        assert_eq!(apply_hashboard_reset(0xF, 0, false).unwrap(), 0xE);
        assert_eq!(apply_all_hashboard_reset(0x0001_0000, true), 0x0001_FFFF);
        assert_eq!(apply_all_hashboard_reset(0x0001_FFFF, false), 0x0001_0000);
    }

    #[test]
    fn zynq_iic_and_hw_version_and_plug_are_packed() {
        let word = pack_zynq_iic(0x20, 0, true, true, 0x11, 0xAA);
        assert_eq!(word & IIC_READ_BIT, IIC_READ_BIT);
        assert_eq!(word & IIC_REG_VALID_BIT, IIC_REG_VALID_BIT);
        assert_eq!(word & 0xFF, 0xAA);
        assert_eq!(iic_command_store_word(0xFFFF_FFFF), IIC_COMMAND_WRITE_MASK);
        assert!(admit_hardware_version_low16(u32::from(HARDWARE_VERSION_VALUE)));
        assert_eq!(HARDWARE_VERSION.byte_offset, 0);
        assert_eq!(AXI_MMAP_BYTES, 352);
        assert_eq!(QN_WRITE_DATA_INIT, 2_155_905_039);
        admit_three_populated_chains(0b0111).unwrap();
        assert!(admit_three_populated_chains(0b0001).is_err());
        assert!(work_fifo_ready(0b0100, 2));
        assert!(!work_fifo_ready(0b0100, 0));
        assert_eq!(decode_fan_speed_word(0x0000_0500), (5, 0));
        assert_eq!(decode_fan_speed_word(0x0000_0318), (3, 0x18));
        assert_eq!(merkle_bin_number_word(3), 3);
        assert_eq!(fpga_ticket_mask_word(15), 15);
        assert_eq!(block_header_version_1_word(0x2000_0000), 0x2000_4000);
        assert_eq!(refuse_s9se_fpga_io(), Err(S9SeFpgaError::FpgaIoRefused));
    }
}
