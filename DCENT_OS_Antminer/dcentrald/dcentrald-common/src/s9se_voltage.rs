//! S9 SE dsPIC IIC voltage map (desk-only).
//!
//! S9k `get_power_iic_value_from_voltage@3B710` and the S9 SE `cgminer`
//! `.rodata` doubles pin two maps. Identity alone must not select an
//! AM2 framed warmup or ChipDriver PIC write. This module converts
//! numbers. It never talks I²C.

/// Primary CE/B_BGM map (`iic = (B − V·D) / (V·C − A)`, cap 127).
pub const POWER_IIC_A: f64 = 44.244;
pub const POWER_IIC_B: f64 = 1943.4048;
pub const POWER_IIC_C: f64 = 5.74;
pub const POWER_IIC_D: f64 = 174.9552;

/// Alternate map (non-CE / non-B_BGM) — present in S9 SE `.rodata`.
pub const POWER_IIC_A2: f64 = 43.956;
pub const POWER_IIC_B2: f64 = 1899.7248;
pub const POWER_IIC_C2: f64 = 5.26;
pub const POWER_IIC_D2: f64 = 161.5872;

/// Factory `cgminer.conf` `"bitmain-voltage": "950"` → 9.50 V.
pub const FACTORY_CONF_VOLTAGE_V: f64 = 9.50;
/// Issue #2 EEPROM working voltage.
pub const ISSUE2_EEPROM_VOLTAGE_V: f64 = 9.60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeIicMap {
    PrimaryCeBBgm,
    Alternate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeVoltageError {
    WriteRefusedNoAdapter,
    VoltageOutOfMap,
}

pub fn power_iic_from_voltage_on_map(voltage: f64, map: S9SeIicMap) -> Result<u8, S9SeVoltageError> {
    let (a, b, c, d) = match map {
        S9SeIicMap::PrimaryCeBBgm => (POWER_IIC_A, POWER_IIC_B, POWER_IIC_C, POWER_IIC_D),
        S9SeIicMap::Alternate => (POWER_IIC_A2, POWER_IIC_B2, POWER_IIC_C2, POWER_IIC_D2),
    };
    let denom = voltage * c - a;
    if !denom.is_finite() || denom == 0.0 {
        return Err(S9SeVoltageError::VoltageOutOfMap);
    }
    let raw = (b - voltage * d) / denom;
    if !raw.is_finite() {
        return Err(S9SeVoltageError::VoltageOutOfMap);
    }
    if raw >= 127.0 {
        Ok(127)
    } else if raw <= 0.0 {
        Ok(0)
    } else {
        Ok(raw as u8)
    }
}

pub fn power_iic_from_voltage(voltage: f64) -> Result<u8, S9SeVoltageError> {
    power_iic_from_voltage_on_map(voltage, S9SeIicMap::PrimaryCeBBgm)
}

pub fn voltage_from_power_iic_on_map(iic: u8, map: S9SeIicMap) -> f64 {
    let (a, b, c, d) = match map {
        S9SeIicMap::PrimaryCeBBgm => (POWER_IIC_A, POWER_IIC_B, POWER_IIC_C, POWER_IIC_D),
        S9SeIicMap::Alternate => (POWER_IIC_A2, POWER_IIC_B2, POWER_IIC_C2, POWER_IIC_D2),
    };
    let data = f64::from(iic);
    (data * a + b) / (data * c + d)
}

pub fn voltage_from_power_iic(iic: u8) -> f64 {
    voltage_from_power_iic_on_map(iic, S9SeIicMap::PrimaryCeBBgm)
}

/// No live IIC adapter is admitted. Desk conversion is not a write permit.
pub fn refuse_s9se_voltage_write() -> Result<(), S9SeVoltageError> {
    Err(S9SeVoltageError::WriteRefusedNoAdapter)
}

/// `slowly_adapt_voltage`: a higher target voltage is applied in one
/// shot; a lower target ramps IIC (higher IIC = lower voltage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeVoltageClimbKind {
    ImmediateRaise,
    RampDown,
}

pub fn voltage_climb_kind(current_v: f64, target_v: f64) -> S9SeVoltageClimbKind {
    if target_v > current_v {
        S9SeVoltageClimbKind::ImmediateRaise
    } else {
        S9SeVoltageClimbKind::RampDown
    }
}

/// Down-ramp IIC step from the `|diff| > 32 / > 16 / > 2` table.
pub fn iic_ramp_step(current_iic: u8, target_iic: u8) -> u8 {
    let diff = current_iic.abs_diff(target_iic);
    if diff > 32 {
        16
    } else if diff > 16 {
        8
    } else if diff > 2 {
        2
    } else {
        1
    }
}

/// Coarse first-leg step is `|iic_cur - iic_tgt| / 6` (`715827883` = 2^32/6).
pub fn iic_coarse_threshold(current_iic: u8, target_iic: u8) -> u8 {
    current_iic.abs_diff(target_iic) / 6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_and_eeprom_voltages_are_inside_primary_map() {
        let iic_factory = power_iic_from_voltage(FACTORY_CONF_VOLTAGE_V).unwrap();
        let iic_eeprom = power_iic_from_voltage(ISSUE2_EEPROM_VOLTAGE_V).unwrap();
        assert!(iic_factory < 127);
        assert!(iic_eeprom < 127);
        let back = voltage_from_power_iic(iic_eeprom);
        assert!(
            (back - ISSUE2_EEPROM_VOLTAGE_V).abs() < 0.05,
            "back={back} iic={iic_eeprom}"
        );
    }

    #[test]
    fn primary_map_round_trips_integer_iic_within_one_lsb() {
        let v = voltage_from_power_iic(50);
        let back = power_iic_from_voltage(v).unwrap();
        let delta = i16::from(back).abs_diff(50);
        assert!(delta <= 1, "back={back} v={v}");
    }

    #[test]
    fn alternate_map_is_distinct_and_present() {
        let p = power_iic_from_voltage_on_map(9.60, S9SeIicMap::PrimaryCeBBgm).unwrap();
        let a = power_iic_from_voltage_on_map(9.60, S9SeIicMap::Alternate).unwrap();
        assert_ne!(p, a);
    }

    #[test]
    fn voltage_write_is_refused_without_adapter() {
        assert_eq!(
            refuse_s9se_voltage_write(),
            Err(S9SeVoltageError::WriteRefusedNoAdapter)
        );
        assert_eq!(
            voltage_climb_kind(9.0, 9.6),
            S9SeVoltageClimbKind::ImmediateRaise
        );
        assert_eq!(
            voltage_climb_kind(9.6, 9.0),
            S9SeVoltageClimbKind::RampDown
        );
        assert_eq!(iic_ramp_step(10, 50), 16);
        assert_eq!(iic_ramp_step(10, 28), 8);
        assert_eq!(iic_ramp_step(10, 14), 2);
        assert_eq!(iic_coarse_threshold(0, 60), 10);
    }
}
