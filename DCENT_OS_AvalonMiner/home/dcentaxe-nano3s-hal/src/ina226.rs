// SPDX-License-Identifier: GPL-3.0-or-later
//
// INA226 input-rail telemetry core (host-pure, datasheet math).
//
// The Nano 3/3S input rail (USB-C PD, ~27 V class) is monitored by an
// INA226 on the Linux-side I2C bus. Per the 2026-08-29 adjudication §A14
// (TNA ↔ third-party-fork convergence, same-origin class): it measures the
// INPUT rail only — core power is inferred, never measured — so this
// driver feeds the B7 voltage-sweep and B8 wattmeter bench procedures
// (BENCH_CAPTURE_PLAN.md P1-8/P1-10) and runtime input-rail telemetry, and
// MUST NOT be presented as core-rail evidence.
//
// Register map and conversion math are public TI datasheet facts (SBOS576),
// not reverse-engineered values: bus-voltage LSB 1.25 mV, shunt-voltage LSB
// 2.5 µV (signed), CAL = 0.00512 / (CURRENT_LSB · R_shunt), power LSB =
// 25 · CURRENT_LSB. The bus/address wiring (i2c-2, 0x40) stays a
// platform-config hypothesis until the P1-8 i2cdetect capture confirms it.
//
// Following the `tps5364x_convert.rs` pattern: everything here is pure and
// host-testable; the Linux /dev/i2c edge supplies a register-read closure
// and is wired separately.

/// INA226 register addresses (datasheet Table 12).
pub mod reg {
    pub const CONFIGURATION: u8 = 0x00;
    pub const SHUNT_VOLTAGE: u8 = 0x01;
    pub const BUS_VOLTAGE: u8 = 0x02;
    pub const POWER: u8 = 0x03;
    pub const CURRENT: u8 = 0x04;
    pub const CALIBRATION: u8 = 0x05;
    pub const MASK_ENABLE: u8 = 0x06;
    pub const ALERT_LIMIT: u8 = 0x07;
    pub const MANUFACTURER_ID: u8 = 0xFE;
    pub const DIE_ID: u8 = 0xFF;
}

/// `MANUFACTURER_ID` value every INA226 reports (TI bank code).
pub const MANUFACTURER_ID_VALUE: u16 = 0x5449;
/// `DIE_ID` value every INA226 reports.
pub const DIE_ID_VALUE: u16 = 0x2260;

/// Bus-voltage register LSB (datasheet §7.5.1, fixed at 1.25 mV).
pub const BUS_VOLTAGE_LSB_MV: f64 = 1.25;
/// Shunt-voltage register LSB (datasheet §7.5.1, fixed at 2.5 µV).
pub const SHUNT_VOLTAGE_LSB_UV: f64 = 2.5;
/// Numerator of the calibration equation (datasheet §7.5.1).
pub const CALIBRATION_CONSTANT: f64 = 0.00512;
/// Power-register LSB multiplier relative to CURRENT_LSB (datasheet).
pub const POWER_LSB_CURRENT_MULTIPLE: f64 = 25.0;

/// Decode a bus-voltage register into millivolts.
pub fn bus_voltage_mv(raw: u16) -> f64 {
    f64::from(raw) * BUS_VOLTAGE_LSB_MV
}

/// Decode a shunt-voltage register (signed) into microvolts.
pub fn shunt_voltage_uv(raw: u16) -> f64 {
    f64::from(raw as i16) * SHUNT_VOLTAGE_LSB_UV
}

/// Programmed-scale context derived from the calibration register and the
/// physical shunt resistance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ina226Scale {
    /// Calibration register value as written/read over I2C.
    pub calibration: u16,
    /// Physical shunt resistance in ohms.
    pub shunt_ohms: f64,
}

impl Ina226Scale {
    /// Compute the scale context for a desired maximum current: choose
    /// CURRENT_LSB = max_current / 2^15 (datasheet §7.5.1 procedure) and
    /// derive the truncated calibration register value. The result must fit
    /// the 16-bit register — an out-of-range combination is refused rather
    /// than silently wrapped.
    pub fn for_max_current(max_current_a: f64, shunt_ohms: f64) -> Result<Self, String> {
        if !max_current_a.is_finite() || max_current_a <= 0.0 {
            return Err("INA226 max current must be positive and finite".into());
        }
        if !shunt_ohms.is_finite() || shunt_ohms <= 0.0 {
            return Err("INA226 shunt resistance must be positive and finite".into());
        }
        let current_lsb = max_current_a / 32_768.0;
        let calibration = CALIBRATION_CONSTANT / (current_lsb * shunt_ohms);
        if calibration < 1.0 {
            return Err(
                "INA226 calibration underflows the register (shunt too small for the range)"
                    .into(),
            );
        }
        if calibration > 65_535.0 {
            return Err(
                "INA226 calibration overflows the 16-bit register (full scale too small for this shunt)"
                    .into(),
            );
        }
        Ok(Self {
            calibration: calibration as u16,
            shunt_ohms,
        })
    }

    /// Effective CURRENT_LSB after register truncation (A per code).
    pub fn current_lsb_a(&self) -> f64 {
        CALIBRATION_CONSTANT / (f64::from(self.calibration) * self.shunt_ohms)
    }

    /// Decode a current register (signed) into amperes.
    pub fn current_a(&self, raw: u16) -> f64 {
        f64::from(raw as i16) * self.current_lsb_a()
    }

    /// Decode a power register into watts.
    pub fn power_w(&self, raw: u16) -> f64 {
        f64::from(raw) * self.current_lsb_a() * POWER_LSB_CURRENT_MULTIPLE
    }
}

/// One telemetry sample decoded from a register snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ina226Sample {
    pub bus_mv: f64,
    pub shunt_uv: f64,
    pub current_a: f64,
    pub power_w: f64,
}

/// Read + decode one telemetry sample through a register-read closure
/// (`Ok(word)` per address, big-endian on the wire as the INA226 speaks it —
/// the edge supplies the byte order swap). Identity registers are verified
/// first: a wrong-address or absent part fails closed instead of decoding
/// garbage as telemetry.
pub fn read_sample(
    mut read_reg: impl FnMut(u8) -> Result<u16, String>,
    scale: &Ina226Scale,
) -> Result<Ina226Sample, String> {
    let manufacturer = read_reg(reg::MANUFACTURER_ID)?;
    if manufacturer != MANUFACTURER_ID_VALUE {
        return Err(format!(
            "INA226 identity mismatch: manufacturer id 0x{manufacturer:04X} != 0x{MANUFACTURER_ID_VALUE:04X}"
        ));
    }
    let die = read_reg(reg::DIE_ID)?;
    if die != DIE_ID_VALUE {
        return Err(format!(
            "INA226 identity mismatch: die id 0x{die:04X} != 0x{DIE_ID_VALUE:04X}"
        ));
    }
    let bus = read_reg(reg::BUS_VOLTAGE)?;
    let shunt = read_reg(reg::SHUNT_VOLTAGE)?;
    let current = read_reg(reg::CURRENT)?;
    let power = read_reg(reg::POWER)?;
    Ok(Ina226Sample {
        bus_mv: bus_voltage_mv(bus),
        shunt_uv: shunt_voltage_uv(shunt),
        current_a: scale.current_a(current),
        power_w: scale.power_w(power),
    })
}

/// Configuration register builder (datasheet Table 11 field packing).
///
/// Kept minimal and explicit: averaging mode, bus/shunt conversion times,
/// and the measurement mode. The power-on default is `0x4127`; callers that
/// only want telemetry can leave the part at its default and skip writing
/// configuration entirely.
pub fn configuration_word(
    averaging: Averaging,
    bus_vct: ConversionTime,
    shunt_vct: ConversionTime,
    mode: Mode,
) -> u16 {
    // Bits 15..12 always read back as the fixed reset pattern 0100; the
    // datasheet power-on default 0x4127 packs as AVG=X1, 1.1 ms / 1.1 ms,
    // shunt+bus continuous — reproduced exactly by this builder below.
    let mut word: u16 = 0x4000;
    word |= (averaging.encode() as u16) << 9;
    word |= (bus_vct.encode() as u16) << 6;
    word |= (shunt_vct.encode() as u16) << 3;
    word |= mode.encode() as u16;
    word
}

/// Analog averaging samples per conversion (CONFIG bits 11..9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Averaging {
    X1,
    X4,
    X16,
    X64,
    X128,
    X256,
    X512,
    X1024,
}

impl Averaging {
    const fn encode(self) -> u8 {
        match self {
            Averaging::X1 => 0,
            Averaging::X4 => 1,
            Averaging::X16 => 2,
            Averaging::X64 => 3,
            Averaging::X128 => 4,
            Averaging::X256 => 5,
            Averaging::X512 => 6,
            Averaging::X1024 => 7,
        }
    }
}

/// Bus/shunt conversion time (CONFIG bits 8..6 / 5..3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionTime {
    Us140,
    Us204,
    Us332,
    Us588,
    Us1100,
    Us2116,
    Us4156,
    Us8244,
}

impl ConversionTime {
    const fn encode(self) -> u8 {
        match self {
            ConversionTime::Us140 => 0,
            ConversionTime::Us204 => 1,
            ConversionTime::Us332 => 2,
            ConversionTime::Us588 => 3,
            ConversionTime::Us1100 => 4,
            ConversionTime::Us2116 => 5,
            ConversionTime::Us4156 => 6,
            ConversionTime::Us8244 => 7,
        }
    }
}

/// Operating mode (CONFIG bits 2..0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    PowerDown,
    ShuntTriggered,
    BusTriggered,
    ShuntBusTriggered,
    PowerDown2,
    ShuntContinuous,
    BusContinuous,
    ShuntBusContinuous,
}

impl Mode {
    const fn encode(self) -> u8 {
        match self {
            Mode::PowerDown => 0,
            Mode::ShuntTriggered => 1,
            Mode::BusTriggered => 2,
            Mode::ShuntBusTriggered => 3,
            Mode::PowerDown2 => 4,
            Mode::ShuntContinuous => 5,
            Mode::BusContinuous => 6,
            Mode::ShuntBusContinuous => 7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Datasheet §7.5.1 worked example: 0.010 Ω shunt, 15 A full scale.
    #[test]
    fn scale_matches_the_datasheet_worked_example() {
        let scale = Ina226Scale::for_max_current(15.0, 0.010)
            .expect("valid full-scale choice");
        // CURRENT_LSB = 15 / 32768 = 457.76 µA; CAL = 0.00512 /
        // (457.76e-6 * 0.010) = 1118.47 -> truncated register 1118 = 0x45E.
        assert_eq!(scale.calibration, 1118);
        // The register truncation shifts the effective LSB by < 0.05 %.
        let lsb = scale.current_lsb_a();
        assert!((lsb - 457.76e-6).abs() < 0.5e-6, "lsb {lsb}");
        // A 1.0 A current therefore reads 1.0 / 457.96µA ≈ 2184 codes and
        // decodes back to within one LSB of 1.0 A.
        let raw = (1.0f64 / lsb).round() as i16 as u16;
        assert!((scale.current_a(raw) - 1.0).abs() < lsb);
    }

    #[test]
    fn scale_refuses_degenerate_inputs_and_register_overflow() {
        assert!(Ina226Scale::for_max_current(0.0, 0.01).is_err());
        assert!(Ina226Scale::for_max_current(-1.0, 0.01).is_err());
        assert!(Ina226Scale::for_max_current(f64::NAN, 0.01).is_err());
        assert!(Ina226Scale::for_max_current(15.0, 0.0).is_err());
        // A full scale far too small for the shunt overflows the 16-bit
        // calibration register — refused, never silently wrapped.
        assert!(Ina226Scale::for_max_current(0.001, 1.0).is_err());
    }

    #[test]
    fn fixed_lsbs_decode_exactly() {
        assert_eq!(bus_voltage_mv(0), 0.0);
        assert_eq!(bus_voltage_mv(8_000), 10_000.0); // 27 V-class rail
        assert_eq!(shunt_voltage_uv(0), 0.0);
        // Negative shunt reading (discharge direction) decodes signed.
        let negative = (-2_000i16) as u16;
        assert_eq!(shunt_voltage_uv(negative), -5_000.0);
    }

    #[test]
    fn read_sample_verifies_identity_before_decoding() {
        let scale = Ina226Scale::for_max_current(15.0, 0.010).unwrap();
        // Wrong manufacturer id: fail closed, never decode garbage.
        let bad: HashMap<u8, u16> = HashMap::from([
            (reg::MANUFACTURER_ID, 0x0000),
            (reg::DIE_ID, DIE_ID_VALUE),
        ]);
        let err = read_sample(
            |address| bad.get(&address).copied().ok_or_else(|| "no device".to_string()),
            &scale,
        )
        .expect_err("identity mismatch must refuse");
        assert!(err.contains("manufacturer id"));

        // Good identity: the sample decodes from the four data registers.
        let lsb = scale.current_lsb_a();
        let good: HashMap<u8, u16> = HashMap::from([
            (reg::MANUFACTURER_ID, MANUFACTURER_ID_VALUE),
            (reg::DIE_ID, DIE_ID_VALUE),
            (reg::BUS_VOLTAGE, 21_600),            // 27.000 V
            (reg::SHUNT_VOLTAGE, 0),
            (reg::CURRENT, (2.0f64 / lsb).round() as i16 as u16), // 2 A
            (reg::POWER, 0),                        // power read as 0 by the part
        ]);
        let sample = read_sample(
            |address| good.get(&address).copied().ok_or_else(|| "no device".to_string()),
            &scale,
        )
        .expect("valid device");
        assert!((sample.bus_mv - 27_000.0).abs() < 1e-9);
        // Current decodes to within one LSB of the encoded 2 A (the
        // truncated calibration LSB is not an exact divisor).
        assert!((sample.current_a - 2.0).abs() < scale.current_lsb_a());
    }

    #[test]
    fn configuration_packs_datasheet_field_positions() {
        let word = configuration_word(
            Averaging::X16,
            ConversionTime::Us1100,
            ConversionTime::Us332,
            Mode::ShuntBusContinuous,
        );
        // Fixed 0100 top nibble | AVG=2<<9 | VBUSCT=4<<6 | VSHCT=2<<3 | MODE=7.
        assert_eq!(word, 0x4000 | (2 << 9) | (4 << 6) | (2 << 3) | 7);
        // The power-on default 0x4127 decodes to AVG=X1, 1.1 ms/1.1 ms,
        // shunt+bus continuous — the classic telemetry setup.
        assert_eq!(
            configuration_word(
                Averaging::X1,
                ConversionTime::Us1100,
                ConversionTime::Us1100,
                Mode::ShuntBusContinuous
            ),
            0x4127
        );
    }
}
