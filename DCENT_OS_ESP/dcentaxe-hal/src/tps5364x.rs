//! TPS53647 / TPS53667 multi-phase PMBus VRM — SMBus transport shim.
//!
//! All decisions (part identity, VID ladder, fail-closed voltage window, phase
//! and over-current encoding) live in the host-pure [`crate::tps5364x_convert`]
//! module and are covered by the host test gate. This file only moves bytes.
//!
//! Fitted to the Nerd family's multi-ASIC boards (NerdQAxe+, NerdQAxe++ pre-rev7,
//! NerdOCTAXE+, NerdOCTAXE-γ) in place of the TPS546 used by BitAxe-class boards.
//! See `tps5364x_convert` for the board/part/phase table and the safety posture.

use log::{error, info, warn};

use crate::i2c::{I2cBus, I2cError};
use crate::power_convert::{f32_to_pmbus_linear11, pmbus_linear11_to_f32};
pub use crate::tps5364x_convert::Tps5364xConfig;

use crate::tps5364x_convert::{
    self as conv, reg, Tps5364xConfigError, Variant, ON_OFF_CONFIG_INIT, OT_FAULT_C, OT_WARN_C,
    SWITCH_FREQ_500KHZ, TPS5364X_ADDR,
};

/// Errors from the TPS5364x driver.
#[derive(Debug)]
pub enum Tps5364xError {
    /// I2C/SMBus transport failure.
    I2c(I2cError),
    /// The part did not identify as a supported TPS5364x.
    ///
    /// Bring-up MUST treat this as "refuse to energize": something other than a
    /// known multi-phase controller is answering at this address.
    Unidentified(u16),
    /// A configuration value was refused by the pure core.
    Config(Tps5364xConfigError),
}

impl core::fmt::Display for Tps5364xError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::I2c(e) => write!(f, "TPS5364x I2C error: {e}"),
            Self::Unidentified(c) => {
                write!(f, "no supported TPS5364x found (device code 0x{c:04x})")
            }
            Self::Config(e) => write!(f, "TPS5364x config refused: {e}"),
        }
    }
}

impl From<I2cError> for Tps5364xError {
    fn from(e: I2cError) -> Self {
        Self::I2c(e)
    }
}

impl From<Tps5364xConfigError> for Tps5364xError {
    fn from(e: Tps5364xConfigError) -> Self {
        Self::Config(e)
    }
}

/// A detected and configured TPS53647/TPS53667.
pub struct Tps5364x {
    addr: u8,
    variant: Variant,
    /// Series voltage domains on this rail. Every current Nerd board carrying
    /// this part is a single domain (ASICs in parallel).
    voltage_domains: u16,
    initialized: bool,
}

impl Tps5364x {
    /// Probe the bus and identify the part **before** any configuration write.
    ///
    /// Reads `MFR_SPECIFIC_44` and refuses anything that is not a known device
    /// code. There is deliberately no fallback variant: a wrong guess would send
    /// VID codes to a part with a different output-voltage mapping.
    pub fn identify(i2c: &mut I2cBus, addr: u8) -> Result<Variant, Tps5364xError> {
        let code = i2c.read_reg_u16_le(addr, reg::MFR_SPECIFIC_44)?;
        Variant::from_device_code(code).ok_or(Tps5364xError::Unidentified(code))
    }

    /// Detect, identify and initialize the regulator with output **off**.
    ///
    /// The init sequence follows `TPS53647::init` / `TPS53667::init` from the
    /// upstream C, including the `ON_OFF_CONFIG` write that guarantees the stage
    /// stays off until an explicit enable.
    pub fn new(
        i2c: &mut I2cBus,
        addr: u8,
        config: &Tps5364xConfig,
        voltage_domains: u16,
    ) -> Result<Self, Tps5364xError> {
        let variant = Self::identify(i2c, addr)?;
        info!(
            "{} detected at 0x{addr:02x} ({} phases requested, imax {} A)",
            variant.name(),
            config.num_phases,
            config.imax_a
        );

        // Validate the whole envelope against the DETECTED part before writing
        // anything. A 6-phase profile landing on a TPS53647 (the NerdOCTAXE-γ
        // rev3.3-vs-rev3.4 case) is refused here, not half-applied.
        let phase_reg = conv::phase_register(variant, config.num_phases)?;
        let imax_reg = conv::imax_register(config.imax_a)?;
        // An over-current threshold above the imax sense scale is a protection
        // that can never assert. Refused here, before the stage is touched,
        // rather than written and believed in.
        let ifault_a = conv::check_iout_fault_limit(config.imax_a, config.ifault_a)?;

        let mut dev = Self {
            addr,
            variant,
            voltage_domains,
            initialized: false,
        };

        // Clear latched faults, then restore the NVM defaults so we start from a
        // known state regardless of what ran before us.
        dev.write_command(i2c, reg::CLEAR_FAULTS)?;
        dev.write_command(i2c, reg::RESTORE_DEFAULT_ALL)?;

        // Output OFF before anything else touches the power stage.
        i2c.write_reg_u8(addr, reg::ON_OFF_CONFIG, ON_OFF_CONFIG_INIT)?;
        i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_12, SWITCH_FREQ_500KHZ)?;
        i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_10, imax_reg)?;
        i2c.write_reg_u8(
            addr,
            reg::MFR_SPECIFIC_13,
            conv::operation_mode(config.phase_shedding),
        )?;

        // Re-assert ON_OFF_CONFIG and switching frequency: upstream writes both
        // twice, after RESTORE_DEFAULT_ALL has had time to settle.
        i2c.write_reg_u8(addr, reg::ON_OFF_CONFIG, ON_OFF_CONFIG_INIT)?;
        i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_12, SWITCH_FREQ_500KHZ)?;

        i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_20, phase_reg)?;

        if variant == Variant::Tps53667 {
            // Enable every phase (clear the shed mask), then apply the '667-only
            // protection setup.
            i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_24, 0x00)?;

            let vout_max_vid = conv::vout_command(variant, variant.vout_max_v())?;
            i2c.write_reg_u16_le(addr, reg::VOUT_MAX, vout_max_vid as u16)?;
            // Per-phase over-current limit, 45 A threshold.
            i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_00, 0x07)?;
            // VIN under-voltage lockout, 6 V threshold.
            i2c.write_reg_u8(addr, reg::MFR_SPECIFIC_16, 0x01)?;
            i2c.write_reg_u16_le(addr, reg::MFR_SPECIFIC_19, 0x0003)?;
        }

        // Thermal protection.
        i2c.write_reg_u16_le(addr, reg::OT_WARN_LIMIT, f32_to_pmbus_linear11(OT_WARN_C))?;
        i2c.write_reg_u16_le(addr, reg::OT_FAULT_LIMIT, f32_to_pmbus_linear11(OT_FAULT_C))?;

        // Output over-current: warn and fault at the same threshold, matching
        // upstream — there is no useful headroom between them on this stage.
        let ifault = f32_to_pmbus_linear11(ifault_a);
        i2c.write_reg_u16_le(addr, reg::IOUT_OC_WARN_LIMIT, ifault)?;
        i2c.write_reg_u16_le(addr, reg::IOUT_OC_FAULT_LIMIT, ifault)?;

        if variant == Variant::Tps53667 {
            i2c.write_reg_u16_le(
                addr,
                reg::IIN_OC_WARN_LIMIT,
                f32_to_pmbus_linear11(config.iin_oc_warn_a),
            )?;
            i2c.write_reg_u16_le(
                addr,
                reg::IIN_OC_FAULT_LIMIT,
                f32_to_pmbus_linear11(config.iin_oc_fault_a),
            )?;
        }

        dev.initialized = true;
        info!(
            "{} initialized: {} phases, imax {} A, ifault {:.1} A, {} voltage domain(s)",
            variant.name(),
            config.num_phases,
            config.imax_a,
            ifault_a,
            voltage_domains
        );
        Ok(dev)
    }

    /// Which part was detected.
    pub fn variant(&self) -> Variant {
        self.variant
    }

    fn write_command(&self, i2c: &mut I2cBus, command: u8) -> Result<(), Tps5364xError> {
        i2c.write(self.addr, &[command])?;
        Ok(())
    }

    /// Set the **per-ASIC** core voltage in millivolts.
    ///
    /// The commanded rail is `voltage_mv * voltage_domains`, matching
    /// the `safety::rail_voltage_v` helper. The resulting rail is range-checked
    /// against the detected part and **rejected**, never clamped, when outside
    /// its window.
    pub fn set_voltage_mv(&self, i2c: &mut I2cBus, voltage_mv: u16) -> Result<(), Tps5364xError> {
        let rail_v = conv::rail_voltage_v_for_domains(voltage_mv, self.voltage_domains);
        let vid = conv::vout_command(self.variant, rail_v)?;
        i2c.write_reg_u16_le(self.addr, reg::VOUT_COMMAND, vid as u16)?;
        if self.voltage_domains > 1 {
            info!(
                "{}: {} mV/ASIC over {} domains -> {:.3} V rail (VID 0x{vid:02x})",
                self.variant.name(),
                voltage_mv,
                self.voltage_domains,
                rail_v
            );
        } else {
            info!(
                "{}: core voltage -> {:.3} V (VID 0x{vid:02x})",
                self.variant.name(),
                rail_v
            );
        }
        Ok(())
    }

    /// Read back the live output voltage in volts.
    ///
    /// Note this uses `MFR_SPECIFIC_04` with a ULINEAR16 `2^-9` encoding — a
    /// *different* encoding from the VID ladder used to command voltage.
    pub fn get_vout(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        if !self.initialized {
            return Ok(0.0);
        }
        let raw = i2c.read_reg_u16_le(self.addr, reg::MFR_SPECIFIC_04)?;
        Ok(conv::decode_vout_readback(raw))
    }

    /// Per-ASIC voltage implied by the live rail readback.
    pub fn get_voltage_mv(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        let rail = self.get_vout(i2c)?;
        Ok(rail / self.voltage_domains.max(1) as f32 * 1000.0)
    }

    fn read_linear11(&self, i2c: &mut I2cBus, register: u8) -> Result<f32, Tps5364xError> {
        if !self.initialized {
            return Ok(0.0);
        }
        let raw = i2c.read_reg_u16_le(self.addr, register)?;
        Ok(pmbus_linear11_to_f32(raw))
    }

    /// Regulator temperature, °C.
    pub fn get_temperature(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        self.read_linear11(i2c, reg::READ_TEMPERATURE_1)
    }

    /// Input power, W.
    pub fn get_pin(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        self.read_linear11(i2c, reg::READ_PIN)
    }

    /// Output power, W.
    pub fn get_pout(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        self.read_linear11(i2c, reg::READ_POUT)
    }

    /// Input voltage, V.
    pub fn get_vin(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        self.read_linear11(i2c, reg::READ_VIN)
    }

    /// Input current, A.
    pub fn get_iin(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        self.read_linear11(i2c, reg::READ_IIN)
    }

    /// Output current, A.
    pub fn get_iout(&self, i2c: &mut I2cBus) -> Result<f32, Tps5364xError> {
        self.read_linear11(i2c, reg::READ_IOUT)
    }

    /// Clear latched fault flags.
    pub fn clear_faults(&self, i2c: &mut I2cBus) -> Result<(), Tps5364xError> {
        self.write_command(i2c, reg::CLEAR_FAULTS)
    }

    /// Read the PMBus status registers and log them.
    ///
    /// Returns `true` when every status register is clear. Bit 1 of
    /// `STATUS_BYTE`/`STATUS_WORD` (CML) is masked: upstream suppresses it as a
    /// spurious communication flag on this part.
    pub fn status_is_clear(&self, i2c: &mut I2cBus) -> Result<bool, Tps5364xError> {
        let status_byte = i2c.read_reg_u8(self.addr, reg::STATUS_BYTE)? & !0x02;
        let status_word = i2c.read_reg_u16_le(self.addr, reg::STATUS_WORD)? & !0x0002;
        let status_vout = i2c.read_reg_u8(self.addr, reg::STATUS_VOUT)?;
        let status_iout = i2c.read_reg_u8(self.addr, reg::STATUS_IOUT)?;
        let status_input = i2c.read_reg_u8(self.addr, reg::STATUS_INPUT)?;
        let status_temp = i2c.read_reg_u8(self.addr, reg::STATUS_TEMPERATURE)?;
        let status_mfr = i2c.read_reg_u8(self.addr, reg::STATUS_MFR_SPECIFIC)?;

        let clear = status_byte == 0
            && status_word == 0
            && status_vout == 0
            && status_iout == 0
            && status_input == 0
            && status_temp == 0
            && status_mfr == 0;

        if clear {
            info!("{} status clear", self.variant.name());
        } else {
            warn!(
                "{} status byte={status_byte:02x} word={status_word:04x} vout={status_vout:02x} \
                 iout={status_iout:02x} input={status_input:02x} temp={status_temp:02x} \
                 mfr={status_mfr:02x}",
                self.variant.name()
            );
        }
        Ok(clear)
    }
}

/// Probe for a TPS5364x at the family address without configuring it.
///
/// Used by board bring-up to distinguish a multi-phase Nerd board from a
/// TPS546-equipped revision before committing to a regulator driver.
pub fn probe(i2c: &mut I2cBus) -> Option<Variant> {
    if !i2c.probe(TPS5364X_ADDR) {
        return None;
    }
    match Tps5364x::identify(i2c, TPS5364X_ADDR) {
        Ok(v) => Some(v),
        Err(e) => {
            error!("device at 0x{TPS5364X_ADDR:02x} is not a supported TPS5364x: {e}");
            None
        }
    }
}
