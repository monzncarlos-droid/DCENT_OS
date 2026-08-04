//! ADC abstraction for DC bus voltage and current monitoring.
//!
//! Provides a unified interface for reading DC bus voltage regardless of
//! the underlying hardware: INA226 I2C power monitor, sysfs IIO ADC,
//! or simulated values for testing.
//!
//! Used by the off-grid controller to monitor battery voltage and
//! trigger frequency curtailment when voltage drops.

use serde::{Deserialize, Serialize};

use crate::i2c::I2cBus;
use crate::ina226::{Ina226, Ina226Config};
use crate::Result;

/// ADC reading from the DC bus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdcReading {
    /// DC bus voltage in volts (e.g., 48.2V for a 48V battery bank).
    pub voltage_v: f32,
    /// DC bus current in amps (positive = load, 0 if not measured).
    pub current_a: f32,
    /// Computed power in watts (voltage × current, or 0 if current not measured).
    pub power_w: f32,
}

/// ADC backend configuration (from TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdcBackendConfig {
    /// TI INA226 I2C power monitor (recommended for off-grid).
    Ina226 {
        #[serde(default = "default_i2c_bus")]
        i2c_bus: u8,
        #[serde(default = "default_ina226_addr")]
        i2c_addr: u8,
        #[serde(default = "default_shunt_mohm")]
        shunt_mohm: u16,
        /// External voltage divider ratio (1.0 = direct, 4.0 = 4:1 divider for >36V).
        #[serde(default = "default_divider")]
        voltage_divider: f32,
    },
    /// Linux IIO sysfs ADC (Amlogic SARADC, Zynq XADC external channels).
    Sysfs {
        /// Path to voltage raw value (e.g., "/sys/bus/iio/devices/iio:device0/in_voltage0_raw").
        voltage_path: String,
        /// ADC reference voltage in volts.
        #[serde(default = "default_vref")]
        vref: f32,
        /// ADC resolution in bits.
        #[serde(default = "default_adc_bits")]
        bits: u8,
        /// External voltage divider ratio.
        #[serde(default = "default_divider")]
        voltage_divider: f32,
    },
    /// Simulated ADC for testing without hardware.
    Simulated {
        voltage_v: f32,
        #[serde(default)]
        current_a: f32,
    },
}

fn default_i2c_bus() -> u8 {
    0
}
fn default_ina226_addr() -> u8 {
    0x40
}
fn default_shunt_mohm() -> u16 {
    10
}
fn default_divider() -> f32 {
    1.0
}
fn default_vref() -> f32 {
    1.8
}
fn default_adc_bits() -> u8 {
    12
}

impl Default for AdcBackendConfig {
    fn default() -> Self {
        AdcBackendConfig::Simulated {
            voltage_v: 52.0,
            current_a: 0.0,
        }
    }
}

/// Trait for reading DC bus voltage/current.
pub trait VoltageSource: Send + Sync {
    /// Read the current DC bus voltage and optionally current/power.
    fn read(&mut self) -> Result<AdcReading>;

    /// Human-readable backend name for dashboard display.
    fn source_name(&self) -> &str;

    /// Whether this source provides real current measurement.
    fn has_current(&self) -> bool {
        false
    }
}

/// AT24C-class hashboard EEPROM I2C addresses (0x50..=0x57).
///
/// Corruption-prevention guarantee (2026-04-29 `a lab unit` hb2 EEPROM incident,
/// ): hashboard EEPROM addresses are
/// write-protected at the HAL. The long-running platform I2C *services*
/// register this denylist at startup, but `Ina226Source` opens a RAW
/// `I2cBus` handle from operator-supplied TOML (`[power.offgrid] adc`),
/// which previously carried an EMPTY denylist — so a config typo pointing
/// `i2c_addr` at 0x50..=0x57 could have directed INA226 register writes
/// (`[reg, hi, lo]` — byte-shape-identical to an AT24C 2-byte page write)
/// at a hashboard EEPROM. Defense-in-depth: the raw handle now carries the
/// same 0x50..=0x57 write-deny as the platform services. Legitimate INA226
/// traffic is unaffected: valid INA226 addresses are 0x40..=0x4F by A0/A1
/// strapping (TI SBOS547A), disjoint from this denylist.
const INA226_RAW_HANDLE_EEPROM_WRITE_DENYLIST: [u8; 8] =
    [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

/// Lowest hardware-realizable INA226 I2C address (TI SBOS547A, A0/A1 = GND/GND).
const INA226_ADDR_MIN: u8 = 0x40;
/// Highest hardware-realizable INA226 I2C address (TI SBOS547A, A0/A1 = SCL/SCL).
const INA226_ADDR_MAX: u8 = 0x4F;

/// INA226-based voltage/current source.
pub struct Ina226Source {
    ina: Ina226,
    i2c: I2cBus,
    voltage_divider: f32,
    /// What actually answered at the configured address. `None` = the probe
    /// read failed, i.e. no device. This replaces a bare `configured: bool`
    /// because "a TI part answered but it is not an INA226" is a third state
    /// that must not be reported as either "absent" or "INA226".
    admission: Option<crate::ina226::Ina2xxAdmission>,
    /// Pre-rendered so `source_name()` can return a `&str` without ever
    /// claiming a part we did not identify.
    source_label: String,
}

impl Ina226Source {
    pub fn open(i2c_bus: u8, addr: u8, shunt_mohm: u16, voltage_divider: f32) -> Result<Self> {
        // Fail closed BEFORE any bus contact: the INA226's A0/A1 strapping can
        // only produce 0x40..=0x4F (TI SBOS547A). Any other operator-supplied
        // address is a config error, and probing it would direct
        // register-pointer writes at an arbitrary device (0x50..=0x57 would be
        // an AT24C hashboard EEPROM). The resulting Err takes the same
        // fail-safe path as a bus-open failure: the daemon off-grid task
        // enters sensor_fault + curtailment sleep.
        if !(INA226_ADDR_MIN..=INA226_ADDR_MAX).contains(&addr) {
            return Err(crate::HalError::I2c {
                bus: i2c_bus,
                addr,
                detail: format!(
                    "INA226 i2c_addr 0x{:02X} is outside the hardware-valid range \
                     0x40..=0x4F (TI SBOS547A A0/A1 strapping); refusing to touch the bus",
                    addr
                ),
            });
        }

        let mut i2c = I2cBus::open(i2c_bus)?;
        // Defense-in-depth per the HAL corruption-prevention guarantee: this
        // raw handle does not inherit the platform service's EEPROM
        // write-denylist, so register it here. Reads stay unaffected; denied
        // writes error and bump the diagnostic counter.
        i2c.set_write_denylist(&INA226_RAW_HANDLE_EEPROM_WRITE_DENYLIST);
        let config = Ina226Config {
            i2c_addr: addr,
            shunt_resistor_mohm: shunt_mohm,
            max_current_a: 50.0,
        };
        let ina = Ina226::new(config);

        let mut source = Self {
            ina,
            i2c,
            voltage_divider,
            admission: None,
            source_label: "INA226(absent)".to_string(),
        };

        source.admission = source.ina.probe_part(&mut source.i2c);
        match source.admission {
            Some(admission) => {
                source.source_label = admission.source_label();
                // Only calibrate a part we actually identified. `configure()`
                // writes the configuration and calibration registers, and those
                // addresses are not guaranteed to mean the same thing on an
                // unidentified die — writing them would be poking registers on
                // an unknown device.
                if admission.shunt_decode_is_valid() {
                    source.ina.configure(&mut source.i2c)?;
                }
            }
            None => {
                tracing::warn!(
                    addr = format_args!("0x{:02X}", addr),
                    bus = i2c_bus,
                    "INA226 not found — voltage readings will be unavailable"
                );
            }
        }

        Ok(source)
    }
}

impl VoltageSource for Ina226Source {
    fn read(&mut self) -> Result<AdcReading> {
        match self.admission {
            None => Err(crate::HalError::I2c {
                bus: 0,
                addr: 0x40,
                detail: "INA226 not configured — sensor not detected on I2C bus".into(),
            }),
            Some(crate::ina226::Ina2xxAdmission::NotTi { mfr_id }) => Err(crate::HalError::I2c {
                bus: 0,
                addr: 0x40,
                detail: format!(
                    "device at the configured INA226 address reports manufacturer \
                     0x{mfr_id:04X}, not TI 0x5449 — refusing to decode its registers"
                ),
            }),
            Some(crate::ina226::Ina2xxAdmission::Ina226 { .. }) => {
                let reading = self.ina.read(&mut self.i2c)?;
                Ok(AdcReading {
                    voltage_v: reading.bus_voltage_v * self.voltage_divider,
                    current_a: reading.current_a,
                    power_w: reading.power_w * self.voltage_divider,
                })
            }
            // A TI part with a die we do not recognize. Bus voltage (register
            // 0x02, 1.25 mV/LSB) is common across this family, and the off-grid
            // protection path gates on voltage — so keep the rail readable
            // rather than blinding it. Register 0x01 is NOT an INA226 shunt
            // voltage here, so current and power are reported as zero and
            // `has_current()` is false; consumers must not publish them.
            Some(crate::ina226::Ina2xxAdmission::OtherTiPart { .. }) => {
                let bus_v = self.ina.read_bus_voltage(&mut self.i2c)?;
                Ok(AdcReading {
                    voltage_v: bus_v * self.voltage_divider,
                    current_a: 0.0,
                    power_w: 0.0,
                })
            }
        }
    }

    fn source_name(&self) -> &str {
        &self.source_label
    }
    fn has_current(&self) -> bool {
        self.admission
            .is_some_and(crate::ina226::Ina2xxAdmission::shunt_decode_is_valid)
    }
}

/// Sysfs IIO ADC voltage source (voltage only, no current).
pub struct SysfsSource {
    voltage_path: String,
    scale: f32, // (vref / 2^bits) * voltage_divider
}

impl SysfsSource {
    pub fn new(voltage_path: String, vref: f32, bits: u8, voltage_divider: f32) -> Self {
        // Clamp bits to 0-24 to prevent overflow in 1 << bits (u32 max shift is 31)
        let safe_bits = bits.min(24);
        let scale = (vref / (1u32 << safe_bits) as f32) * voltage_divider;
        Self {
            voltage_path,
            scale,
        }
    }
}

impl VoltageSource for SysfsSource {
    fn read(&mut self) -> Result<AdcReading> {
        let raw_str = std::fs::read_to_string(&self.voltage_path).map_err(|e| {
            crate::HalError::DeviceOpen {
                path: self.voltage_path.clone(),
                source: e,
            }
        })?;
        let raw: u32 = raw_str.trim().parse().unwrap_or(0);
        Ok(AdcReading {
            voltage_v: raw as f32 * self.scale,
            current_a: 0.0,
            power_w: 0.0,
        })
    }

    fn source_name(&self) -> &str {
        "Sysfs ADC"
    }
}

/// Simulated voltage source for testing.
pub struct SimulatedSource {
    voltage_v: f32,
    current_a: f32,
}

impl SimulatedSource {
    pub fn new(voltage_v: f32, current_a: f32) -> Self {
        Self {
            voltage_v,
            current_a,
        }
    }
}

impl VoltageSource for SimulatedSource {
    fn read(&mut self) -> Result<AdcReading> {
        Ok(AdcReading {
            voltage_v: self.voltage_v,
            current_a: self.current_a,
            power_w: self.voltage_v * self.current_a,
        })
    }

    fn source_name(&self) -> &str {
        "Simulated"
    }
    fn has_current(&self) -> bool {
        self.current_a > 0.0
    }
}

/// Create a VoltageSource from configuration.
pub fn create_voltage_source(config: &AdcBackendConfig) -> Result<Box<dyn VoltageSource>> {
    match config {
        AdcBackendConfig::Ina226 {
            i2c_bus,
            i2c_addr,
            shunt_mohm,
            voltage_divider,
        } => Ok(Box::new(Ina226Source::open(
            *i2c_bus,
            *i2c_addr,
            *shunt_mohm,
            *voltage_divider,
        )?)),
        AdcBackendConfig::Sysfs {
            voltage_path,
            vref,
            bits,
            voltage_divider,
        } => Ok(Box::new(SysfsSource::new(
            voltage_path.clone(),
            *vref,
            *bits,
            *voltage_divider,
        ))),
        AdcBackendConfig::Simulated {
            voltage_v,
            current_a,
        } => Ok(Box::new(SimulatedSource::new(*voltage_v, *current_a))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address gate must reject every address the INA226 hardware cannot
    /// occupy — including the full AT24C hashboard EEPROM band 0x50..=0x57 —
    /// BEFORE any bus/fabric contact. This is why the test is host-safe: a
    /// rejected address never reaches `I2cBus::open`.
    #[test]
    fn ina226_open_refuses_addresses_outside_hardware_range() {
        for addr in [0x00u8, 0x3F, 0x50, 0x51, 0x55, 0x57, 0x58, 0x7F, 0xFF] {
            let err = Ina226Source::open(0, addr, 10, 1.0)
                .err()
                .unwrap_or_else(|| {
                    panic!("INA226 open must refuse invalid address 0x{:02X}", addr)
                });
            let msg = err.to_string();
            assert!(
                msg.contains("outside the hardware-valid range"),
                "address 0x{:02X} must be rejected by the validation gate, got: {}",
                addr,
                msg
            );
        }
    }

    /// Hardware-valid addresses must pass the validation gate. On a test host
    /// the subsequent raw bus open fails (no device node / fabric refusal),
    /// but that failure must NOT be the address-validation error — proving
    /// the gate does not over-reject legitimate INA226 strapping.
    #[test]
    fn ina226_open_validation_does_not_over_reject_valid_addresses() {
        for addr in [INA226_ADDR_MIN, 0x48, INA226_ADDR_MAX] {
            // Bus 250 guarantees no /dev/i2c-250 exists on any test host.
            match Ina226Source::open(250, addr, 10, 1.0) {
                Ok(_) => {
                    panic!("test host must not have /dev/i2c-250; open unexpectedly succeeded")
                }
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        !msg.contains("outside the hardware-valid range"),
                        "valid address 0x{:02X} was wrongly rejected by the validation gate: {}",
                        addr,
                        msg
                    );
                }
            }
        }
    }

    /// Denylist shape pin, mirroring the platform-module tests: exactly the 8
    /// AT24C hashboard EEPROM addresses, and every entry disjoint from the
    /// valid INA226 range so the deny can never block legitimate traffic.
    #[test]
    fn ina226_raw_handle_denylist_covers_eeprom_band_and_never_valid_ina226_addrs() {
        assert_eq!(INA226_RAW_HANDLE_EEPROM_WRITE_DENYLIST.len(), 8);
        for addr in 0x50u8..=0x57 {
            assert!(
                INA226_RAW_HANDLE_EEPROM_WRITE_DENYLIST.contains(&addr),
                "EEPROM address 0x{:02X} missing from the raw-handle denylist",
                addr
            );
        }
        for addr in INA226_RAW_HANDLE_EEPROM_WRITE_DENYLIST {
            assert!(
                !(INA226_ADDR_MIN..=INA226_ADDR_MAX).contains(&addr),
                "denylist entry 0x{:02X} overlaps the valid INA226 range — would block legitimate traffic",
                addr
            );
        }
    }

    /// Claim honesty for a TI part that is not an INA226 die.
    ///
    /// Host-pure: drives the same admission classification the probe path
    /// stores on `Ina226Source`, without opening a bus. Mutation that deletes
    /// the die-ID branch in `classify_ina2xx` turns the INA260 case green on
    /// the old manufacturer-only path (would claim `INA226` + current).
    #[test]
    fn wrong_ti_part_must_not_claim_ina226_or_current() {
        use crate::ina226::{classify_ina2xx, Ina2xxAdmission};

        let wrong = classify_ina2xx(0x5449, 0x2270); // INA260 die
        assert_eq!(
            wrong,
            Ina2xxAdmission::OtherTiPart { die_id: 0x2270 },
            "INA260 must classify as OtherTiPart, not Ina226"
        );
        assert!(
            !wrong.shunt_decode_is_valid(),
            "VoltageSource::has_current() is shunt_decode_is_valid()"
        );
        let label = wrong.source_label();
        assert_ne!(label, "INA226");
        assert!(
            !label.contains("INA226"),
            "source_name must not contain INA226 for wrong die; got {label}"
        );
        assert_eq!(label, "INA2xx(die=0x2270)");

        // Admitted INA226 still claims the part and current.
        let good = classify_ina2xx(0x5449, 0x2260);
        assert!(good.shunt_decode_is_valid());
        assert_eq!(good.source_label(), "INA226");
    }
}
