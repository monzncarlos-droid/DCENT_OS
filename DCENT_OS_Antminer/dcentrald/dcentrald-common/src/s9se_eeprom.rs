//! S9 SE hashboard EEPROM facts (desk-only).
//!
//! Production `statusServiceThread` / `eeprom_get_chip_major_type`:
//! `array_read_one_byte(248) & 7`; `0` prints `"1393"`. Writes stay refused.

pub const EEPROM_CHIP_MAJOR_OFFSET: u8 = 248;
pub const EEPROM_CHIP_MAJOR_MASK: u8 = 7;
pub const EEPROM_MAJOR_1393: u8 = 0;
pub const EEPROM_MAJOR_1391: u8 = 1;
pub const CHIP_LABEL_1393: &str = "1393";
/// Production `eeprom_get_voltage` mode 0: `array_read_one_byte(1)`.
pub const EEPROM_VOLTAGE_OFFSET_MODE0: u8 = 1;
/// Production `eeprom_get_freq` mode 0: 60 bytes starting at offset 2.
pub const EEPROM_FREQ_OFFSET_MODE0: u8 = 2;
pub const EEPROM_FREQ_CHIP_COUNT: usize = 60;
/// `buf[i] = 5 * eeprom_info[chain][i + 2]`.
pub const EEPROM_FREQ_SCALE_MHZ: u16 = 5;
/// `voltage = 2 * (vol + 300) / 100`.
pub const EEPROM_VOLTAGE_OFFSET_ADD: u16 = 300;
/// Jig `eeprom_test` uses `(vol+200)*5/100` — not the production SSOT.
pub const JIG_EEPROM_VOLTAGE_ADD: u16 = 200;
pub const JIG_EEPROM_VOLTAGE_SCALE: f64 = 0.05;
/// `_eeprom_get_temp_sensor_type` `array_read_one_byte(121)`.
pub const EEPROM_TEMP_SENSOR_TYPE_OFFSET: u8 = 121;
/// `_eeprom_get_hashrate` mode 0 starts at byte 110 (4-byte LE).
pub const EEPROM_HASHRATE_OFFSET_MODE0: u8 = 110;
/// `_eeprom_get_pcb_version` byte 252.
pub const EEPROM_PCB_VERSION_OFFSET: u8 = 252;
/// `_eeprom_get_bom_version` byte 253.
pub const EEPROM_BOM_VERSION_OFFSET: u8 = 253;
/// `array_check_crc` covers the first 254 bytes.
pub const EEPROM_CRC_LEN: usize = 254;
/// `_eeprom_get_temp_sensor_pos` / `_data` count at byte 122, max 6.
pub const EEPROM_TEMP_SENSOR_NUM_OFFSET: u8 = 122;
pub const EEPROM_TEMP_SENSOR_MAX: u8 = 6;
/// `chip_info` byte 248: major[2:0], minor[5:3], level[7:6].
pub const EEPROM_CHIP_MINOR_SHIFT: u8 = 3;
pub const EEPROM_CHIP_LEVEL_SHIFT: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeEepromError {
    MajorIsNot1393 { observed: u8 },
    EepromWriteRefused,
}

pub fn chip_major_from_byte(raw: u8) -> u8 {
    raw & EEPROM_CHIP_MAJOR_MASK
}

pub fn admit_major_is_1393(raw: u8) -> Result<(), S9SeEepromError> {
    let major = chip_major_from_byte(raw);
    if major != EEPROM_MAJOR_1393 {
        return Err(S9SeEepromError::MajorIsNot1393 { observed: major });
    }
    Ok(())
}

pub fn refuse_s9se_eeprom_write() -> Result<(), S9SeEepromError> {
    Err(S9SeEepromError::EepromWriteRefused)
}

/// Production S9k/S9SE `eeprom_get_voltage` mode 0.
pub fn voltage_from_eeprom_byte(vol: u8) -> f64 {
    f64::from(u16::from(vol) + EEPROM_VOLTAGE_OFFSET_ADD) * 2.0 / 100.0
}

pub fn eeprom_byte_from_voltage(voltage: f64) -> u8 {
    let raw = voltage * 50.0 - f64::from(EEPROM_VOLTAGE_OFFSET_ADD);
    if raw <= 0.0 {
        0
    } else if raw >= 255.0 {
        255
    } else {
        raw as u8
    }
}

pub fn freq_mhz_from_eeprom_byte(raw: u8) -> u16 {
    u16::from(raw) * EEPROM_FREQ_SCALE_MHZ
}

/// Production `eeprom_get_hashrate` mode 0: four LE bytes at offset 110.
pub fn hashrate_from_eeprom_bytes(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

pub fn chip_minor_from_byte(raw: u8) -> u8 {
    (raw >> EEPROM_CHIP_MINOR_SHIFT) & EEPROM_CHIP_MAJOR_MASK
}

pub fn chip_level_from_byte(raw: u8) -> u8 {
    raw >> EEPROM_CHIP_LEVEL_SHIFT
}

/// Same CRC-16/Modbus as `CRC16@1AE00` / job packets.
pub fn eeprom_payload_crc16(payload: &[u8]) -> u16 {
    crate::s9se_job::s9se_job_crc16(payload)
}

pub fn admit_eeprom_crc(payload254: &[u8], stored: u16) -> bool {
    payload254.len() == EEPROM_CRC_LEN && eeprom_payload_crc16(payload254) == stored
}

pub fn temp_sensor_pos_offset(index: u8) -> Option<u8> {
    if index >= EEPROM_TEMP_SENSOR_MAX {
        return None;
    }
    Some(2 * index + 123)
}

pub fn temp_sensor_data_offset(index: u8) -> Option<u8> {
    if index >= EEPROM_TEMP_SENSOR_MAX {
        return None;
    }
    Some(2 * (index + 62))
}

/// Jig AT24C02 formula is a different tool. Do not use it as S9 SE SSOT.
pub fn refuse_jig_voltage_formula_as_ssot(use_jig: bool) -> Result<(), S9SeEepromError> {
    if use_jig {
        return Err(S9SeEepromError::EepromWriteRefused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_zero_is_1393() {
        admit_major_is_1393(0).unwrap();
        admit_major_is_1393(0xF8).unwrap();
        assert!(admit_major_is_1393(1).is_err());
        assert_eq!(CHIP_LABEL_1393, "1393");
        assert_eq!(
            refuse_s9se_eeprom_write(),
            Err(S9SeEepromError::EepromWriteRefused)
        );
        let v960 = voltage_from_eeprom_byte(eeprom_byte_from_voltage(9.60));
        assert!((v960 - 9.60).abs() < 0.03, "v960={v960}");
        assert_eq!(freq_mhz_from_eeprom_byte(80), 400);
        refuse_jig_voltage_formula_as_ssot(false).unwrap();
        assert!(refuse_jig_voltage_formula_as_ssot(true).is_err());
        assert_eq!(EEPROM_FREQ_CHIP_COUNT, 60);
        assert_eq!(EEPROM_PCB_VERSION_OFFSET, 252);
        assert_eq!(EEPROM_BOM_VERSION_OFFSET, 253);
        assert_eq!(EEPROM_TEMP_SENSOR_TYPE_OFFSET, 121);
        assert_eq!(
            hashrate_from_eeprom_bytes([0x11, 0x22, 0x33, 0x44]),
            0x4433_2211
        );
        assert_eq!(chip_minor_from_byte(0b00_101_000), 5);
        assert_eq!(chip_level_from_byte(0b10_000_000), 2);
        assert_eq!(temp_sensor_pos_offset(0), Some(123));
        assert_eq!(temp_sensor_data_offset(0), Some(124));
        let payload = [0u8; EEPROM_CRC_LEN];
        let crc = eeprom_payload_crc16(&payload);
        assert!(admit_eeprom_crc(&payload, crc));
        assert!(!admit_eeprom_crc(&payload, crc ^ 1));
    }
}
