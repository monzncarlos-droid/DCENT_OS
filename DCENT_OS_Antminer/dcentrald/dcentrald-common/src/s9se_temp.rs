//! S9 SE on-chip I²C temperature path (desk-only).
//!
//! `bring_up_chain` calls `calibration_sensor_offset(152, chain)`.
//! `read_temp` writes VIL set-config to register `0x1C` (GENERAL_I2C).
//! `set_iic_for_temperature_by_chain` only sets MISC I²C-enable on the
//! EEPROM-named temp chips. This module packs. It never talks I²C.

use crate::s9se_vil::{
    crc5_bits, pack_set_config_single, CRC5_VIL_SET_CONFIG_BITS, HDR_WRITE_SINGLE,
};

/// `calibration_sensor_offset(152u, chain)` — default TMP device.
pub const TEMP_DEVICE_DEFAULT: u8 = 152; // 0x98
/// `TMP441B` → `DEVICEADDR = -102`.
pub const TEMP_DEVICE_TMP441B: u8 = 0x9A;
/// `TMP411C` → `DEVICEADDR = -100`.
pub const TEMP_DEVICE_TMP411C: u8 = 0x9C;
/// `read_temp` `buf[3] = 28`.
pub const REG_GENERAL_I2C: u8 = 0x1C;
/// `read_temp` `buf[4] = 1`.
pub const TEMP_I2C_PREFIX: u8 = 0x01;
/// `get_local`: `return local - 64`.
pub const TEMP_LOCAL_OFFSET: i16 = 64;
/// Inlet sensors: `TempChipAddr >> 2 == 30` → address `0x78`.
pub const TEMP_INLET_CHIP_ADDR: u8 = 0x78;
/// `calibration_sensor_offset` log: `"sensor type is not TMP451,error"`.
pub const TEMP_SENSOR_TMP451: &str = "TMP451";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeTempSensor {
    Default098,
    Tmp441b,
    Tmp411c,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeTempError {
    TempIoRefused,
}

impl S9SeTempSensor {
    pub const fn device_addr(self) -> u8 {
        match self {
            Self::Default098 => TEMP_DEVICE_DEFAULT,
            Self::Tmp441b => TEMP_DEVICE_TMP441B,
            Self::Tmp411c => TEMP_DEVICE_TMP411C,
        }
    }
}

/// VIL `read_temp` frame: `41 09 chip 1C 01 (write|device) reg data CRC5-64`.
pub fn pack_read_temp_vil(chip_addr: u8, device: u8, reg: u8, data: u8, write: bool) -> [u8; 9] {
    let write_bit = u8::from(write);
    let mut frame = pack_set_config_single(chip_addr, REG_GENERAL_I2C, 0);
    frame[0] = HDR_WRITE_SINGLE;
    frame[4] = TEMP_I2C_PREFIX;
    frame[5] = write_bit | device;
    frame[6] = reg;
    frame[7] = data;
    frame[8] = crc5_bits(&frame[..8], CRC5_VIL_SET_CONFIG_BITS);
    frame
}

/// `set_iic_for_temperature_by_chain` is MISC I²C-enable, not a PWM raise.
pub fn temperature_uses_misc_i2c_enable() -> bool {
    true
}

pub fn refuse_s9se_temp_io() -> Result<(), S9SeTempError> {
    Err(S9SeTempError::TempIoRefused)
}

pub fn local_temp_c(raw: u8) -> i16 {
    i16::from(raw) - TEMP_LOCAL_OFFSET
}

/// `get_remote`: same `raw - 64` as local.
pub fn remote_temp_c(raw: u8) -> i16 {
    i16::from(raw) - TEMP_LOCAL_OFFSET
}

pub fn is_inlet_temp_chip(chip_addr: u8) -> bool {
    chip_addr >> 2 == 30
}

/// `calc_offset_simple`: `local - remote`.
pub fn calc_offset_simple(remote: i16, local: i16) -> i16 {
    local - remote
}

/// `_get_target_chip_temp_t11` PKG_CE economic branch (S9 SE is `cgminer_1393` CE).
pub fn target_chip_temp_ce_economic(min_entrance_pcb_c: i32) -> i32 {
    if min_entrance_pcb_c <= 16 {
        75
    } else if min_entrance_pcb_c <= 24 {
        75 - 5 * (min_entrance_pcb_c - 16) / 8
    } else if min_entrance_pcb_c <= 29 {
        10 * (min_entrance_pcb_c - 24) / -5 + 70
    } else if min_entrance_pcb_c <= 39 {
        12 * (min_entrance_pcb_c - 29) / 10 + 60
    } else if min_entrance_pcb_c <= 48 {
        10 * (min_entrance_pcb_c - 39) / 9 + 72
    } else {
        82
    }
}

/// Non-economic CE package returns a flat 85 °C target.
pub fn target_chip_temp_ce_normal() -> i32 {
    85
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_device_is_152_and_frame_hits_reg_1c() {
        assert_eq!(S9SeTempSensor::Default098.device_addr(), 152);
        assert_eq!(S9SeTempSensor::Tmp441b.device_addr(), 0x9A);
        assert_eq!(S9SeTempSensor::Tmp411c.device_addr(), 0x9C);
        let frame = pack_read_temp_vil(0x02, TEMP_DEVICE_DEFAULT, 0x00, 0, false);
        assert_eq!(frame[0], 0x41);
        assert_eq!(frame[2], 0x02);
        assert_eq!(frame[3], 0x1C);
        assert_eq!(frame[4], 0x01);
        assert_eq!(frame[5], TEMP_DEVICE_DEFAULT);
        assert_eq!(frame[8], crc5_bits(&frame[..8], 64));
        assert!(temperature_uses_misc_i2c_enable());
        assert_eq!(refuse_s9se_temp_io(), Err(S9SeTempError::TempIoRefused));
        assert_eq!(local_temp_c(80), 16);
        assert_eq!(remote_temp_c(80), 16);
        assert!(is_inlet_temp_chip(TEMP_INLET_CHIP_ADDR));
        assert!(!is_inlet_temp_chip(0x02));
        assert_eq!(calc_offset_simple(70, 80), 10);
        assert_eq!(target_chip_temp_ce_economic(10), 75);
        assert_eq!(target_chip_temp_ce_economic(50), 82);
        assert_eq!(target_chip_temp_ce_normal(), 85);
        assert_eq!(TEMP_SENSOR_TMP451, "TMP451");
    }
}
