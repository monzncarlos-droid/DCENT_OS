//! FXL6408 8-bit I²C GPIO port expander — transport shim.
//!
//! Every decision (register map, pin bounds, shadow-register arithmetic, the
//! pull-up write order, the CAN slave-detect inversion) lives in the host-pure
//! [`crate::fxl6408_convert`] module and is covered by the host test gate. This
//! file only moves bytes — and checks the results upstream discards.
//!
//! Fitted to the Q1370/Q1373, the first family whose ASIC reset, VREG enable and
//! LDO enable are I²C transactions rather than GPIO writes.
//!
//! # Two divergences from upstream, both about failed writes
//!
//! * **`Fxl6408::init()` returns `true` after a reset whose writes are only
//!   logged.** Upstream's `write_reg(REG_CTRL, 0x01)` and its `OUTPUT_HIZ` clear
//!   both ignore their result, so a half-answering expander reports a successful
//!   init and the board then drives ASIC reset into a part still in high-Z.
//!   Every step here is checked.
//! * **Upstream updates its direction/output/pull shadows BEFORE the write.** A
//!   failed write leaves the shadow ahead of the hardware, and the next
//!   single-pin change computes its byte from a fiction — flipping an unrelated
//!   pin. [`PortState::with_pin`] builds a candidate and only
//!   [`PortState::commit`] advances the shadow, so [`Fxl6408::write_port`]
//!   physically cannot record a write that did not land.

use log::info;

use crate::fxl6408_convert::{
    self as conv, q_series, reg, Fxl6408ConfigError, Port, PortState, ADDR, CTRL_SOFT_RESET,
    OUTPUT_HIZ_NONE, PULL_UP_WRITE_ORDER,
};
use crate::i2c::{I2cBus, I2cError};

/// Settle after each step of the reset sequence. Upstream waits 100 ms after the
/// soft reset and again after clearing output high-Z.
const RESET_SETTLE_MS: u32 = 100;

/// Errors from the FXL6408 driver.
#[derive(Debug)]
pub enum Fxl6408Error {
    /// I²C transport failure. **The pin did not move.**
    I2c(I2cError),
    /// Nothing answered at this address.
    NotFound(u8),
    /// The pure core refused the request before it reached the bus.
    Config(Fxl6408ConfigError),
}

impl core::fmt::Display for Fxl6408Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::I2c(e) => write!(f, "FXL6408 I2C error: {e}"),
            Self::NotFound(a) => write!(f, "no FXL6408 at 0x{a:02X}"),
            Self::Config(e) => write!(f, "FXL6408: {e}"),
        }
    }
}

impl From<I2cError> for Fxl6408Error {
    fn from(e: I2cError) -> Self {
        Self::I2c(e)
    }
}

impl From<Fxl6408ConfigError> for Fxl6408Error {
    fn from(e: Fxl6408ConfigError) -> Self {
        Self::Config(e)
    }
}

fn sleep_ms(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

/// A detected and reset FXL6408 port expander.
pub struct Fxl6408 {
    addr: u8,
    state: PortState,
}

impl Fxl6408 {
    /// Probe, read the device code, and run the checked reset sequence.
    ///
    /// On success the part is in its post-reset state — every pin an input,
    /// every output latch low, no pulls — and [`Self::state`] agrees with it.
    /// That agreement is what makes the first single-pin write safe: a shadow
    /// starting anywhere else would send seven invented bits alongside it.
    pub fn new(i2c: &mut I2cBus, addr: u8) -> Result<Self, Fxl6408Error> {
        if !i2c.probe(addr) {
            return Err(Fxl6408Error::NotFound(addr));
        }
        let device_code = i2c.read_reg_u8(addr, reg::CTRL)?;
        info!("FXL6408 0x{addr:02X}: device code 0x{device_code:02X}");
        let mut dev = Self {
            addr,
            state: PortState::after_reset(),
        };
        dev.reset(i2c)?;
        Ok(dev)
    }

    /// Probe at the only address upstream ever uses for this part (0x43).
    pub fn new_default(i2c: &mut I2cBus) -> Result<Self, Fxl6408Error> {
        Self::new(i2c, ADDR)
    }

    /// The address this instance drives.
    pub fn addr(&self) -> u8 {
        self.addr
    }

    /// The shadow of the part's write-only registers.
    pub fn state(&self) -> PortState {
        self.state
    }

    /// Soft-reset and take the outputs out of high-Z. Both writes are checked.
    fn reset(&mut self, i2c: &mut I2cBus) -> Result<(), Fxl6408Error> {
        i2c.write_reg_u8(self.addr, reg::CTRL, CTRL_SOFT_RESET)?;
        sleep_ms(RESET_SETTLE_MS);
        i2c.write_reg_u8(self.addr, reg::OUTPUT_HIZ, OUTPUT_HIZ_NONE)?;
        sleep_ms(RESET_SETTLE_MS);
        self.state = PortState::after_reset();
        info!(
            "FXL6408 0x{:02X}: reset, outputs actively driven",
            self.addr
        );
        Ok(())
    }

    /// Change one pin in one shadowed register, advancing the shadow ONLY if
    /// the bus accepted the byte.
    fn write_port(
        &mut self,
        i2c: &mut I2cBus,
        port: Port,
        pin: u8,
        set: bool,
    ) -> Result<(), Fxl6408Error> {
        let candidate = self.state.with_pin(port, pin, set)?;
        i2c.write_reg_u8(self.addr, port.register(), candidate)?;
        self.state.commit(port, candidate);
        Ok(())
    }

    /// Set a pin's direction. `true` = output.
    pub fn set_direction(
        &mut self,
        i2c: &mut I2cBus,
        pin: u8,
        output: bool,
    ) -> Result<(), Fxl6408Error> {
        self.write_port(i2c, Port::Direction, pin, output)
    }

    /// Drive an output pin.
    pub fn write_pin(
        &mut self,
        i2c: &mut I2cBus,
        pin: u8,
        level: bool,
    ) -> Result<(), Fxl6408Error> {
        self.write_port(i2c, Port::Output, pin, level)
    }

    /// Enable a pull-UP, select before enable.
    ///
    /// The order is [`PULL_UP_WRITE_ORDER`] and it is not cosmetic: enabling the
    /// pull first would momentarily arm whatever `PULL_SELECT` holds, which
    /// after reset is pull-DOWN. On the CAN slave-detect strap that transient
    /// reads as "slave".
    pub fn enable_pull_up(&mut self, i2c: &mut I2cBus, pin: u8) -> Result<(), Fxl6408Error> {
        for port in PULL_UP_WRITE_ORDER {
            self.write_port(i2c, port, pin, true)?;
        }
        Ok(())
    }

    /// Read the pad-level register.
    pub fn input_status(&mut self, i2c: &mut I2cBus) -> Result<u8, Fxl6408Error> {
        Ok(i2c.read_reg_u8(self.addr, reg::INPUT_STATUS)?)
    }

    /// Read one pad's level.
    pub fn read_pin(&mut self, i2c: &mut I2cBus, pin: u8) -> Result<bool, Fxl6408Error> {
        Ok(conv::pin_level(self.input_status(i2c)?, pin)?)
    }

    /// Decode the CAN slave-detect strap. **Low means slave.**
    pub fn is_can_slave(&mut self, i2c: &mut I2cBus) -> Result<bool, Fxl6408Error> {
        Ok(conv::is_can_slave(self.input_status(i2c)?)?)
    }

    /// Configure ASIC reset, VREG enable and LDO enable as outputs driven LOW.
    ///
    /// Upstream `Q1370B::initBoard` does exactly this, immediately after the
    /// expander init and before anything can energize. Direction is set before
    /// the level because the post-reset output latch is already 0 — so the pin
    /// drives low the instant it becomes an output, and there is no window in
    /// which it drives high.
    pub fn configure_power_sequence_outputs(
        &mut self,
        i2c: &mut I2cBus,
    ) -> Result<(), Fxl6408Error> {
        for pin in q_series::POWER_SEQUENCE_OUTPUTS {
            self.set_direction(i2c, pin, true)?;
            self.write_pin(i2c, pin, false)?;
        }
        info!(
            "FXL6408 0x{:02X}: ASIC reset / VREG / LDO configured as outputs, all LOW",
            self.addr
        );
        Ok(())
    }
}
