//! TI INA226 high-side current/voltage power monitor driver.
//!
//! The INA226 measures bus voltage (0-36V) and shunt voltage (±81.92 mV)
//! via a precision shunt resistor, providing current and power readings.
//! Communication via standard I2C (no custom framing like Bitmain PSU).
//!
//! Used for real power measurement in Direct DC / Off-Grid mode.
//! Per hash board: 1 mΩ shunt + INA226 at 0x40/0x41/0x42 on the existing I2C bus.
//!
//! Register map (from TI INA226 datasheet, SBOS547A):
//!   0x00  Configuration    RW  16-bit  Averaging, conversion time, mode
//!   0x01  Shunt Voltage    R   16-bit  Shunt voltage measurement (2.5 µV LSB)
//!   0x02  Bus Voltage      R   16-bit  Bus voltage measurement (1.25 mV LSB)
//!   0x03  Power            R   16-bit  Power = current × bus_voltage (25 mW LSB default)
//!   0x04  Current          R   16-bit  Calibrated current (LSB set by calibration register)
//!   0x05  Calibration      RW  16-bit  Sets current LSB scaling
//!   0xFE  Manufacturer ID  R   16-bit  0x5449 ("TI")
//!   0xFF  Die ID           R   16-bit  0x2260

use crate::i2c::I2cBus;
use crate::Result;

// INA226 register addresses
const REG_CONFIGURATION: u8 = 0x00;
const REG_SHUNT_VOLTAGE: u8 = 0x01;
const REG_BUS_VOLTAGE: u8 = 0x02;
#[allow(dead_code)]
const REG_POWER: u8 = 0x03;
#[allow(dead_code)]
const REG_CURRENT: u8 = 0x04;
const REG_CALIBRATION: u8 = 0x05;
const REG_MANUFACTURER_ID: u8 = 0xFE;
const REG_DIE_ID: u8 = 0xFF;

/// Expected manufacturer ID for TI INA226.
///
/// This is a MANUFACTURER id, so by construction it cannot tell two TI parts
/// apart — see [`classify_ina2xx`].
const MANUFACTURER_ID_TI: u16 = 0x5449;

/// Die ID reported by the INA226.
///
/// Source: the TI SBOS547A register map reproduced in this module's header
/// (`0xFF  Die ID  R  16-bit  0x2260`).
const DIE_ID_INA226: u16 = 0x2260;

/// Die ID reported by the INA260.
///
/// Source: this workspace's sibling ESP HAL,
/// `DCENT_OS_ESP/dcentaxe-hal/src/power.rs` (`/// Die ID (should be
/// 0x2270)`), which reads both IDs from a real INA260.
///
/// Recorded for the log line and for the test vectors; nothing branches on it
/// directly — an unrecognized die is handled by its difference from
/// [`DIE_ID_INA226`], not by matching this.
#[allow(dead_code)]
const DIE_ID_INA260: u16 = 0x2270;

/// Which TI part actually answered at the configured address.
///
/// This exists because the manufacturer ID alone cannot discriminate: an
/// INA226 and an INA260 both report `0x5449`. The register layouts then
/// diverge in a way that silently corrupts a reading rather than failing —
/// register `0x01` is a *shunt voltage* in 2.5 µV steps on the INA226 and a
/// *current* in 1.25 mA steps on the INA260, so the same bytes decode to a
/// plausible but wrong number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ina2xxAdmission {
    /// Manufacturer and die both match the INA226. The shunt-voltage decode in
    /// [`Ina226::read`] is correct for this part.
    Ina226 { die_id: u16 },
    /// A TI part that is not an INA226 die.
    ///
    /// Bus voltage (register `0x02`, 1.25 mV/LSB) is common to this family and
    /// stays trustworthy, which is why this is reported rather than refused —
    /// the off-grid protection path gates on voltage. Current and power do NOT
    /// stay trustworthy and callers must stop publishing them.
    OtherTiPart { die_id: u16 },
    /// Not a TI part at all, or a dead/floating bus (`0x0000` / `0xFFFF`).
    NotTi { mfr_id: u16 },
}

impl Ina2xxAdmission {
    /// Whether register `0x01` may be decoded as an INA226 shunt voltage.
    pub fn shunt_decode_is_valid(self) -> bool {
        matches!(self, Self::Ina226 { .. })
    }

    /// A label that never over-claims. An unrecognized TI die is reported by
    /// its die ID instead of being published as `"INA226"`.
    pub fn source_label(self) -> String {
        match self {
            Self::Ina226 { .. } => "INA226".to_string(),
            Self::OtherTiPart { die_id } => format!("INA2xx(die=0x{die_id:04X})"),
            Self::NotTi { mfr_id } => format!("unknown(mfr=0x{mfr_id:04X})"),
        }
    }
}

/// Pure classification of a probed `(manufacturer_id, die_id)` pair.
///
/// Split out from the I2C probe so the whole matrix is host-testable with no
/// bus. **This never refuses anything** — it returns what was observed, and the
/// caller decides what to publish. A fail-closed allowlist here would trade an
/// availability regression on real INA226 silicon (a die revision we have not
/// seen) against a reporting defect, which is the wrong trade on a rail.
///
/// The low nibble of the die register is treated as a revision field, so
/// `0x226x` is accepted as an INA226. That field split is an ASSUMPTION, not a
/// datasheet quote — it is safe here only because it errs toward the existing
/// behaviour (today every part that answers is treated as an INA226) and never
/// toward refusing a working sensor.
pub fn classify_ina2xx(mfr_id: u16, die_id: u16) -> Ina2xxAdmission {
    if mfr_id != MANUFACTURER_ID_TI {
        return Ina2xxAdmission::NotTi { mfr_id };
    }
    if die_id >> 4 == DIE_ID_INA226 >> 4 {
        Ina2xxAdmission::Ina226 { die_id }
    } else {
        Ina2xxAdmission::OtherTiPart { die_id }
    }
}

/// Default configuration: 16 averages, 1.1ms conversion, continuous shunt+bus.
const DEFAULT_CONFIG: u16 = 0x4527;

/// INA226 measurement reading.
#[derive(Debug, Clone, Default)]
pub struct Ina226Reading {
    /// Bus voltage in volts (0-36V range, 1.25 mV resolution).
    pub bus_voltage_v: f32,
    /// Shunt voltage in millivolts (±81.92 mV range, 2.5 µV resolution).
    pub shunt_voltage_mv: f32,
    /// Calculated current in amps (from shunt voltage / shunt resistance).
    pub current_a: f32,
    /// Calculated power in watts (bus_voltage × current).
    pub power_w: f32,
}

/// INA226 configuration.
#[derive(Debug, Clone)]
pub struct Ina226Config {
    /// I2C address (0x40-0x4F, set by A0/A1 pins).
    pub i2c_addr: u8,
    /// Shunt resistor value in milliohms (e.g., 1 for 1 mΩ, 10 for 10 mΩ).
    pub shunt_resistor_mohm: u16,
    /// Maximum expected current in amps (for calibration register).
    pub max_current_a: f32,
}

impl Default for Ina226Config {
    fn default() -> Self {
        Self {
            i2c_addr: 0x40,
            shunt_resistor_mohm: 10,
            max_current_a: 50.0,
        }
    }
}

/// INA226 power monitor instance.
pub struct Ina226 {
    config: Ina226Config,
    /// Shunt resistance in ohms (derived from config).
    shunt_ohms: f32,
    /// Current LSB in amps (set by calibration).
    current_lsb: f32,
}

impl Ina226 {
    /// Create a new INA226 instance with the given configuration.
    pub fn new(config: Ina226Config) -> Self {
        let shunt_ohms = config.shunt_resistor_mohm as f32 / 1000.0;
        // Current LSB = max_current / 2^15 (INA226 is 15-bit signed)
        let current_lsb = config.max_current_a / 32768.0;
        Self {
            config,
            shunt_ohms,
            current_lsb,
        }
    }

    /// Probe the configured address and report which TI part answered.
    ///
    /// Reads BOTH the manufacturer ID and the die ID. The manufacturer ID
    /// alone was never enough: an INA260 answers `0x5449` too, and would then
    /// have its current register decoded as an INA226 shunt voltage.
    ///
    /// Returns `None` only when the bus read itself failed. A part that
    /// answers but is not an INA226 is reported, not hidden — see
    /// [`Ina2xxAdmission`].
    pub fn probe_part(&self, i2c: &mut I2cBus) -> Option<Ina2xxAdmission> {
        let mfr_id = self.read_register(i2c, REG_MANUFACTURER_ID).ok()?;
        // Read the die ID even when the manufacturer already mismatched: the
        // observed pair is what makes a field report actionable.
        let die_id = self.read_register(i2c, REG_DIE_ID).ok()?;
        let admission = classify_ina2xx(mfr_id, die_id);
        match admission {
            Ina2xxAdmission::Ina226 { die_id } => tracing::info!(
                addr = format_args!("0x{:02X}", self.config.i2c_addr),
                die_id = format_args!("0x{die_id:04X}"),
                "INA226 detected (TI manufacturer ID 0x5449)"
            ),
            Ina2xxAdmission::OtherTiPart { die_id } => tracing::warn!(
                addr = format_args!("0x{:02X}", self.config.i2c_addr),
                die_id = format_args!("0x{die_id:04X}"),
                expected_die = format_args!("0x{DIE_ID_INA226:04X}"),
                "TI power monitor answered with a non-INA226 die ID. Bus voltage \
                 is common to this family and stays trustworthy, but register 0x01 \
                 is not an INA226 shunt voltage on this part, so current and power \
                 will not be published."
            ),
            Ina2xxAdmission::NotTi { mfr_id } => tracing::warn!(
                addr = format_args!("0x{:02X}", self.config.i2c_addr),
                mfr_id = format_args!("0x{mfr_id:04X}"),
                "device at the configured INA226 address is not a TI part"
            ),
        }
        Some(admission)
    }

    /// Compatibility shim: whether an INA226 specifically was identified.
    ///
    /// Prefer [`Self::probe_part`] — this collapses "no device", "not TI" and
    /// "TI but a different die" into one `false`, which is exactly the
    /// distinction the caller needs to report honestly.
    pub fn probe(&self, i2c: &mut I2cBus) -> bool {
        self.probe_part(i2c)
            .is_some_and(Ina2xxAdmission::shunt_decode_is_valid)
    }

    /// Configure the INA226 (set averaging, conversion time, calibration).
    /// Call once after probe returns true.
    pub fn configure(&self, i2c: &mut I2cBus) -> Result<()> {
        // Set configuration: 16 averages, 1.1ms shunt+bus conversion, continuous mode
        self.write_register(i2c, REG_CONFIGURATION, DEFAULT_CONFIG)?;

        // Calculate and set calibration register
        // CAL = 0.00512 / (current_lsb × R_shunt)
        let cal = (0.00512 / (self.current_lsb * self.shunt_ohms)) as u16;
        self.write_register(i2c, REG_CALIBRATION, cal)?;

        tracing::info!(
            addr = format_args!("0x{:02X}", self.config.i2c_addr),
            shunt_mohm = self.config.shunt_resistor_mohm,
            cal,
            current_lsb_ua = format_args!("{:.1}", self.current_lsb * 1e6),
            "INA226 configured"
        );
        Ok(())
    }

    /// Read all measurements from INA226.
    pub fn read(&self, i2c: &mut I2cBus) -> Result<Ina226Reading> {
        let bus_raw = self.read_register(i2c, REG_BUS_VOLTAGE)?;
        let shunt_raw = self.read_register(i2c, REG_SHUNT_VOLTAGE)? as i16;

        // Bus voltage: 1.25 mV per LSB
        let bus_voltage_v = bus_raw as f32 * 1.25e-3;

        // Shunt voltage: 2.5 µV per LSB (signed)
        let shunt_voltage_mv = shunt_raw as f32 * 2.5e-3;

        // Current from shunt voltage and resistance
        let current_a = (shunt_voltage_mv / 1000.0) / self.shunt_ohms;

        // Power
        let power_w = bus_voltage_v * current_a;

        Ok(Ina226Reading {
            bus_voltage_v,
            shunt_voltage_mv,
            current_a: current_a.abs(),
            power_w: power_w.abs(),
        })
    }

    /// Read bus voltage only (faster, single register).
    pub fn read_bus_voltage(&self, i2c: &mut I2cBus) -> Result<f32> {
        let raw = self.read_register(i2c, REG_BUS_VOLTAGE)?;
        Ok(raw as f32 * 1.25e-3)
    }

    fn read_register(&self, i2c: &mut I2cBus, reg: u8) -> Result<u16> {
        i2c.set_slave(self.config.i2c_addr)?;
        let mut buf = [0u8; 2];
        i2c.write_exact(&[reg], "INA226 register-pointer write")?;
        std::thread::sleep(std::time::Duration::from_micros(500));
        i2c.read(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn write_register(&self, i2c: &mut I2cBus, reg: u8, value: u16) -> Result<()> {
        i2c.set_slave(self.config.i2c_addr)?;
        let bytes = value.to_be_bytes();
        i2c.write_exact(&[reg, bytes[0], bytes[1]], "INA226 register mutation")?;
        std::thread::sleep(std::time::Duration::from_micros(500));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manufacturer ID cannot discriminate, and the die ID must.
    ///
    /// Tautology to avoid: asserting only that `(0x5449, 0x2260)` is an INA226
    /// self-satisfies — it restates the constant the implementation matches on.
    /// The load-bearing vector is the INA260 one, because that is the part that
    /// silently mis-decodes: it shares the manufacturer ID, so before the die
    /// read it was admitted as an INA226 and its CURRENT register (1.25 mA/LSB)
    /// was decoded as a shunt voltage (2.5 µV/LSB).
    #[test]
    fn an_ina260_shares_the_ti_manufacturer_id_and_must_be_told_apart_by_die() {
        assert_eq!(
            classify_ina2xx(MANUFACTURER_ID_TI, DIE_ID_INA260),
            Ina2xxAdmission::OtherTiPart {
                die_id: DIE_ID_INA260
            },
            "an INA260 must not be admitted as an INA226"
        );
        // The reason it is dangerous: the vendor id alone says nothing.
        assert_eq!(MANUFACTURER_ID_TI, 0x5449);
        assert_ne!(DIE_ID_INA226, DIE_ID_INA260);

        let ina260 = classify_ina2xx(MANUFACTURER_ID_TI, DIE_ID_INA260);
        assert!(!ina260.shunt_decode_is_valid());
        assert_eq!(ina260.source_label(), "INA2xx(die=0x2270)");
        assert!(
            !ina260.source_label().contains("INA226"),
            "an unidentified die must never be published as INA226"
        );
    }

    #[test]
    fn a_real_ina226_is_admitted_across_die_revisions() {
        assert!(classify_ina2xx(MANUFACTURER_ID_TI, DIE_ID_INA226).shunt_decode_is_valid());
        // Revision nibble tolerance. This errs toward the pre-existing
        // behaviour (everything was admitted) and never toward refusing a
        // working sensor on a rail.
        for die in [0x2260u16, 0x2261, 0x2265, 0x226F] {
            assert!(
                classify_ina2xx(MANUFACTURER_ID_TI, die).shunt_decode_is_valid(),
                "die 0x{die:04X} is an INA226 revision and must stay admitted"
            );
        }
        assert_eq!(
            classify_ina2xx(MANUFACTURER_ID_TI, 0x2265).source_label(),
            "INA226"
        );
    }

    #[test]
    fn a_dead_or_floating_bus_is_never_a_part() {
        for (mfr, die) in [(0x0000u16, 0x0000u16), (0xFFFF, 0xFFFF)] {
            let admission = classify_ina2xx(mfr, die);
            assert_eq!(admission, Ina2xxAdmission::NotTi { mfr_id: mfr });
            assert!(!admission.shunt_decode_is_valid());
            assert!(!admission.source_label().contains("INA226"));
        }
        // A TI part reading a floating die is still not an INA226.
        assert!(!classify_ina2xx(MANUFACTURER_ID_TI, 0xFFFF).shunt_decode_is_valid());
        // A non-TI vendor is rejected on the vendor id regardless of die.
        assert_eq!(
            classify_ina2xx(0x1234, DIE_ID_INA226),
            Ina2xxAdmission::NotTi { mfr_id: 0x1234 }
        );
    }
}
