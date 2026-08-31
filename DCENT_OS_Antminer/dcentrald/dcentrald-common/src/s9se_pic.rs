//! S9 SE dsPIC33EP16GS202 command catalog (desk-only).
//!
//! Frames from S9k `send_pic_cmd@701BC` + the S9 SE `cgminer` strings
//! `dsPIC33EP16GS202_{reset_pic,jump_to_app_from_loader,pic_heart_beat,
//! enable_pic_dc_dc,set_pic_voltage}`. This module packs. It never
//! talks I²C and never ENABLE/RESET/JUMP on a live rail.

/// PIC preamble (`write_pic_iic(chain, 85)` / `170`).
pub const PIC_PREAMBLE: [u8; 2] = [0x55, 0xAA];
pub const CMD_JUMP_TO_APP: u8 = 0x06;
pub const CMD_RESET: u8 = 0x07;
pub const CMD_SET_VOLTAGE: u8 = 0x10;
pub const CMD_ENABLE_DC_DC: u8 = 0x15;
pub const CMD_HEARTBEAT: u8 = 0x16;
/// `dsPIC33EP16GS202_get_software_version` `cmd[0]=23`.
pub const CMD_GET_SOFTWARE_VERSION: u8 = 0x17;
/// `dsPIC33EP16GS202_crab_circuit_control` `cmd[0]=49`.
pub const CMD_CRAB_CIRCUIT: u8 = 0x31;
/// `dsPIC33EP16GS202_pic_get_an_voltage2` `cmd[0]=41`.
pub const CMD_GET_AN_VOLTAGE2: u8 = 0x29;
/// S9 SE `get_crab_voltage@72e0c` `strb #0x28`.
pub const CMD_GET_CRAB_VOLTAGE: u8 = 0x28;
/// S9 SE `get_PDCx@72c28` `strb #0x2b`.
pub const CMD_GET_PDCX: u8 = 0x2B;
/// `write_pic_iic`: `zynq_set_iic(chain & 7 | 0x20, …)`.
pub const PIC_IIC_DEV_BASE: u8 = 0x20;
pub const PIC_IIC_WHICH: u8 = 0;
/// `init_pic_one_chain` sleeps 1 s after JUMP before ENABLE 0.
pub const INIT_PIC_AFTER_JUMP_S: u8 = 1;
/// `decode_an_voltage_buf`: `v_n * 3.3 / 4096`.
pub const AN_VREF: f64 = 3.3;
pub const AN_COUNTS: f64 = 4096.0;
/// Printed as `v_10 = v_an2 * 7.5999999`.
pub const AN_V10_SCALE: f64 = 7.6;

/// ACK payload after SET/ENABLE/RESET/JUMP: `[cmd, 1]`.
pub const PIC_ACK_OK: u8 = 0x01;
/// Heartbeat reply length (`send_pic_cmd(..., 6)`).
pub const HEARTBEAT_REPLY_LEN: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SePicError {
    VoltageBit7Set { iic: u8 },
    PicIoRefused,
}

/// `crc = cmd_len + 3 + sum(cmd)`.
pub fn pic_crc(cmd: &[u8]) -> u16 {
    let mut crc = u16::from(cmd.len() as u8).saturating_add(3);
    for b in cmd {
        crc = crc.saturating_add(u16::from(*b));
    }
    crc
}

/// On-wire frame: `55 AA | (cmd_len+3) | cmd... | crc_hi | crc_lo`.
pub fn pack_pic_frame(cmd: &[u8]) -> Vec<u8> {
    let crc = pic_crc(cmd);
    let mut out = Vec::with_capacity(2 + 1 + cmd.len() + 2);
    out.extend_from_slice(&PIC_PREAMBLE);
    out.push((cmd.len() as u8).saturating_add(3));
    out.extend_from_slice(cmd);
    out.push((crc >> 8) as u8);
    out.push(crc as u8);
    out
}

pub fn pack_reset() -> Vec<u8> {
    pack_pic_frame(&[CMD_RESET])
}

pub fn pack_jump_to_app() -> Vec<u8> {
    pack_pic_frame(&[CMD_JUMP_TO_APP])
}

pub fn pack_heartbeat() -> Vec<u8> {
    pack_pic_frame(&[CMD_HEARTBEAT])
}

pub fn pack_enable_dc_dc(enable: u8) -> Vec<u8> {
    pack_pic_frame(&[CMD_ENABLE_DC_DC, enable])
}

pub fn pack_get_software_version() -> Vec<u8> {
    pack_pic_frame(&[CMD_GET_SOFTWARE_VERSION])
}

pub fn pack_crab_circuit(enable: u8) -> Vec<u8> {
    pack_pic_frame(&[CMD_CRAB_CIRCUIT, enable])
}

pub fn pack_get_an_voltage2() -> Vec<u8> {
    pack_pic_frame(&[CMD_GET_AN_VOLTAGE2])
}

pub fn pack_get_crab_voltage() -> Vec<u8> {
    pack_pic_frame(&[CMD_GET_CRAB_VOLTAGE])
}

pub fn pack_get_pdcx() -> Vec<u8> {
    pack_pic_frame(&[CMD_GET_PDCX])
}

/// FPGA IIC device address for one PIC chain. T11a 1↔2 swap is not S9 SE.
pub fn pic_iic_dev_addr(chain: u8) -> u8 {
    (chain & 7) | PIC_IIC_DEV_BASE
}

/// `write_pic_iic` FPGA command word. Not a bus permit.
pub fn pack_write_pic_iic(chain: u8, data: u8) -> u32 {
    crate::s9se_fpga::pack_zynq_iic(
        pic_iic_dev_addr(chain),
        PIC_IIC_WHICH,
        false,
        false,
        0,
        data,
    )
}

pub fn refuse_t11a_chain_swap_on_s9se(apply_swap: bool) -> Result<(), S9SePicError> {
    if apply_swap {
        return Err(S9SePicError::PicIoRefused);
    }
    Ok(())
}

/// `init_pic_one_chain`: RESET → JUMP → 1 s → ENABLE 0. Planning only.
pub fn s9se_init_pic_order() -> [u8; 3] {
    [CMD_RESET, CMD_JUMP_TO_APP, CMD_ENABLE_DC_DC]
}

/// PIC FLASH pointer / `update_pic_program` stay refused (no recovery-tool).
pub fn refuse_s9se_pic_flash() -> Result<(), S9SePicError> {
    Err(S9SePicError::PicIoRefused)
}

/// Reply `[?, 0x29, 1, …]` from `pic_get_an_voltage2`.
pub fn admit_an_voltage_ack(reply: &[u8]) -> bool {
    reply.len() >= 3 && reply[1] == CMD_GET_AN_VOLTAGE2 && reply[2] == PIC_ACK_OK
}

/// S9 SE `get_crab_voltage`: reply_len 13, values at `[4,6,8,10]`.
pub fn crab_na_values(reply: &[u8]) -> Option<[u8; 4]> {
    if reply.len() >= 11 && reply[1] == CMD_GET_CRAB_VOLTAGE && reply[2] == PIC_ACK_OK {
        Some([reply[4], reply[6], reply[8], reply[10]])
    } else {
        None
    }
}

/// S9 SE `get_PDCx`: reply_len 9, values at `[4,6,8]`.
pub fn pdcx_values(reply: &[u8]) -> Option<[u8; 3]> {
    if reply.len() >= 9 && reply[1] == CMD_GET_PDCX && reply[2] == PIC_ACK_OK {
        Some([reply[4], reply[6], reply[8]])
    } else {
        None
    }
}

/// BE u16 at `buf+3` is the 12-bit AN sample.
pub fn an_counts_from_reply(reply: &[u8]) -> Option<u16> {
    if reply.len() < 5 {
        return None;
    }
    Some(u16::from_be_bytes([reply[3], reply[4]]))
}

pub fn decode_an_voltage_v10(counts: u16) -> f64 {
    f64::from(counts) * AN_VREF / AN_COUNTS * AN_V10_SCALE
}

/// `check_crc`: sum of first `len-2` bytes equals BE trailer.
pub fn admit_pic_reply_crc(buf: &[u8]) -> bool {
    if buf.is_empty() || buf[0] <= 3 {
        return false;
    }
    let body_end = usize::from(buf[0]) - 2;
    if buf.len() < body_end + 2 {
        return false;
    }
    let sum1: u16 = buf[..body_end].iter().map(|b| u16::from(*b)).sum();
    let sum2 = u16::from_be_bytes([buf[body_end], buf[body_end + 1]]);
    sum1 == sum2
}

/// Reply `[5, 23, version, …]` from `get_software_version`.
pub fn admit_software_version_ack(reply: &[u8]) -> Option<u8> {
    if reply.len() >= 3 && reply[0] == 5 && reply[1] == CMD_GET_SOFTWARE_VERSION {
        Some(reply[2])
    } else {
        None
    }
}

/// `dsPIC33EP16GS202_set_pic_voltage` refuses bit 7 (`return -2`).
pub fn pack_set_voltage(iic: u8) -> Result<Vec<u8>, S9SePicError> {
    if iic & 0x80 != 0 {
        return Err(S9SePicError::VoltageBit7Set { iic });
    }
    Ok(pack_pic_frame(&[CMD_SET_VOLTAGE, iic, 0, 0]))
}

pub fn admit_ack(cmd: u8, reply: &[u8]) -> bool {
    reply.len() >= 2 && reply[0] == cmd && reply[1] == PIC_ACK_OK
}

pub fn admit_heartbeat_ack(reply: &[u8]) -> bool {
    reply.len() >= 3 && reply[1] == CMD_HEARTBEAT && reply[2] == PIC_ACK_OK
}

/// No live PIC adapter. Packing is not a write permit.
pub fn refuse_s9se_pic_io() -> Result<(), S9SePicError> {
    Err(S9SePicError::PicIoRefused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_frame_is_55aa_plus_sum_crc() {
        let frame = pack_reset();
        assert_eq!(frame[0], 0x55);
        assert_eq!(frame[1], 0xAA);
        assert_eq!(frame[2], 4); // cmd_len 1 + 3
        assert_eq!(frame[3], CMD_RESET);
        let crc = pic_crc(&[CMD_RESET]);
        assert_eq!(crc, 4 + 7);
        assert_eq!(frame[4], (crc >> 8) as u8);
        assert_eq!(frame[5], crc as u8);
    }

    #[test]
    fn voltage_bit7_is_refused() {
        assert!(pack_set_voltage(128).is_err());
        let frame = pack_set_voltage(50).unwrap();
        assert_eq!(frame[3], CMD_SET_VOLTAGE);
        assert_eq!(frame[4], 50);
    }

    #[test]
    fn enable_and_jump_opcodes_match_stock() {
        assert_eq!(pack_enable_dc_dc(1)[3], 0x15);
        assert_eq!(pack_jump_to_app()[3], 0x06);
        assert_eq!(pack_heartbeat()[3], 0x16);
        assert_eq!(pack_get_software_version()[3], 0x17);
        assert_eq!(pack_crab_circuit(1)[3], 0x31);
        assert_eq!(pack_get_an_voltage2()[3], 0x29);
        assert_eq!(pack_get_crab_voltage()[3], 0x28);
        assert_eq!(pack_get_pdcx()[3], 0x2B);
        assert_eq!(
            crab_na_values(&[13, 0x28, 1, 0, 10, 0, 20, 0, 30, 0, 40]),
            Some([10, 20, 30, 40])
        );
        assert_eq!(
            pdcx_values(&[9, 0x2B, 1, 0, 1, 0, 2, 0, 3]),
            Some([1, 2, 3])
        );
        assert_eq!(pic_iic_dev_addr(2), 0x22);
        assert_eq!(pack_write_pic_iic(2, 0x55) & 0xFF, 0x55);
        assert_eq!((pack_write_pic_iic(2, 0x55) >> 16) & 0x7, 2);
        refuse_t11a_chain_swap_on_s9se(false).unwrap();
        assert!(refuse_t11a_chain_swap_on_s9se(true).is_err());
        assert_eq!(
            s9se_init_pic_order(),
            [CMD_RESET, CMD_JUMP_TO_APP, CMD_ENABLE_DC_DC]
        );
        assert_eq!(refuse_s9se_pic_flash(), Err(S9SePicError::PicIoRefused));
        assert!(admit_an_voltage_ack(&[9, 0x29, 0x01, 0x08, 0x00]));
        assert!((decode_an_voltage_v10(0x0800) - (2048.0 * 3.3 / 4096.0 * 7.6)).abs() < 1e-9);
        assert_eq!(admit_software_version_ack(&[5, 0x17, 0x89]), Some(0x89));
        let mut crc_ok = vec![5, 0x29, 0x01];
        let sum: u16 = crc_ok.iter().map(|b| u16::from(*b)).sum();
        crc_ok.extend_from_slice(&sum.to_be_bytes());
        assert!(admit_pic_reply_crc(&crc_ok));
        assert!(admit_ack(0x15, &[0x15, 0x01]));
        assert!(admit_heartbeat_ack(&[0, 0x16, 0x01, 0, 0, 0]));
        assert_eq!(refuse_s9se_pic_io(), Err(S9SePicError::PicIoRefused));
    }
}
