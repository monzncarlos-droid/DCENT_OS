//! PCA9544A I2C bus multiplexer — transport shim.
//!
//! Every decision (address block, control-byte encoding, channel validation,
//! readback decode, the disabled-vs-selected distinction) lives in the
//! host-pure [`crate::pca9544_convert`] module and is covered by the host test
//! gate. This file only moves bytes.
//!
//! Fitted to the BitForge Nano, whose two EMC2101s share one hard-wired address
//! and are reachable only through this part at 0x70 on channels 2 and 3.
//!
//! # The API is shaped to make the upstream bug inexpressible
//!
//! All 11 vendor call sites are a bare `PAC9544_selectChannel(2);` with the
//! return value discarded, and `Thermal_getAsicChipTemp` does not select at all
//! — it reads whichever channel happens to be live. A failed select therefore
//! returns the *other* ASIC's die temperature under this ASIC's name.
//!
//! [`Pca9544::with_channel`] is the only way to transact through the mux: it
//! selects, settles, reads the control register back, verifies it, and only
//! then runs the caller's closure. There is no way to reach a downstream device
//! without that verification having succeeded.

use log::{info, warn};

use crate::i2c::{I2cBus, I2cError};
use crate::pca9544_convert::{
    self as conv, MuxState, Pca9544Error, BASE_ADDRESS, CONTROL_WRITE_LEN,
};

/// Errors from the PCA9544A driver.
#[derive(Debug)]
pub enum Pca9544DriverError {
    /// I2C transport failure.
    I2c(I2cError),
    /// Nothing answered at this address.
    NotFound(u8),
    /// The pure core refused the request, or the readback did not match it.
    Mux(Pca9544Error),
    /// A control-register readback returned the wrong number of bytes.
    ShortRead {
        /// Bytes actually returned.
        got: usize,
    },
}

impl core::fmt::Display for Pca9544DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::I2c(e) => write!(f, "PCA9544A I2C error: {e}"),
            Self::NotFound(a) => write!(f, "no PCA9544A at 0x{a:02X}"),
            Self::Mux(e) => write!(f, "PCA9544A: {e}"),
            Self::ShortRead { got } => {
                write!(f, "PCA9544A control readback returned {got} bytes, want 1")
            }
        }
    }
}

impl From<I2cError> for Pca9544DriverError {
    fn from(e: I2cError) -> Self {
        Self::I2c(e)
    }
}

impl From<Pca9544Error> for Pca9544DriverError {
    fn from(e: Pca9544Error) -> Self {
        Self::Mux(e)
    }
}

fn sleep_ms(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

/// A PCA9544A 4-channel I2C bus multiplexer.
pub struct Pca9544 {
    addr: u8,
}

impl Pca9544 {
    /// Probe and construct at an explicit address.
    ///
    /// The address is validated against the part's own 0x70..=0x77 block by the
    /// pure core, so a temperature sensor or a floating bus cannot be adopted
    /// as a multiplexer.
    pub fn new(i2c: &mut I2cBus, addr: u8) -> Result<Self, Pca9544DriverError> {
        if !conv::is_plausible_address(addr) {
            return Err(Pca9544DriverError::Mux(Pca9544Error::AddressReserved(addr)));
        }
        if !i2c.probe(addr) {
            return Err(Pca9544DriverError::NotFound(addr));
        }
        let mux = Self { addr };
        info!("PCA9544A: found at 0x{addr:02X}");
        Ok(mux)
    }

    /// Probe and construct at the strapped-low default address (0x70).
    ///
    /// This is the BitForge Nano's wiring — A0/A1/A2 are all tied to GND in its
    /// PCB netlist.
    pub fn new_default(i2c: &mut I2cBus) -> Result<Self, Pca9544DriverError> {
        Self::new(i2c, BASE_ADDRESS)
    }

    /// The strapped address this instance drives.
    pub fn addr(&self) -> u8 {
        self.addr
    }

    /// Read the control register and decode which channel, if any, is live.
    pub fn selected(&mut self, i2c: &mut I2cBus) -> Result<MuxState, Pca9544DriverError> {
        Ok(MuxState::from_readback(self.read_control(i2c)?))
    }

    /// Disconnect every downstream channel.
    ///
    /// Worth doing before touching any non-muxed device on the same bus: with
    /// the mux open, a downstream address collision is reachable from the
    /// upstream side.
    pub fn disable(&mut self, i2c: &mut I2cBus) -> Result<(), Pca9544DriverError> {
        self.write_control(i2c, conv::disable())?;
        Ok(())
    }

    /// Select `channel`, settle, and verify it actually took.
    ///
    /// Fails closed on an out-of-range channel, a rejected write, a disabled
    /// mux, or a readback naming a different channel.
    pub fn select(&mut self, i2c: &mut I2cBus, channel: u8) -> Result<(), Pca9544DriverError> {
        let selection = conv::select(channel)?;
        self.write_control(i2c, selection.control_byte())?;
        // The part needs time to connect the downstream segment; upstream waits
        // the same 10 ms after every select.
        sleep_ms(selection.settle_ms());
        let readback = self.read_control(i2c)?;
        if let Err(e) = selection.confirm(readback) {
            warn!(
                "PCA9544A 0x{:02X}: select ch{channel} failed to verify (readback 0x{readback:02X}): {e}",
                self.addr
            );
            return Err(Pca9544DriverError::Mux(e));
        }
        Ok(())
    }

    /// Run `f` with `channel` connected, having verified the selection first.
    ///
    /// This is the intended entry point. The closure cannot run unless the
    /// channel is confirmed live, which is what keeps one ASIC's die
    /// temperature from being reported under the other ASIC's name.
    ///
    /// The channel is left selected afterwards — the next `with_channel` call
    /// re-asserts and re-verifies regardless, so no caller may assume it.
    pub fn with_channel<T>(
        &mut self,
        i2c: &mut I2cBus,
        channel: u8,
        f: impl FnOnce(&mut I2cBus) -> T,
    ) -> Result<T, Pca9544DriverError> {
        self.select(i2c, channel)?;
        Ok(f(i2c))
    }

    /// Per-channel interrupt flags from the control register.
    pub fn interrupt_flags(&mut self, i2c: &mut I2cBus) -> Result<[bool; 4], Pca9544DriverError> {
        Ok(conv::interrupt_flags(self.read_control(i2c)?))
    }

    /// Write the control register.
    ///
    /// EXACTLY one byte. The part has no register pointer: the byte after the
    /// address IS the control register. Upstream routes this through a
    /// `register_write_byte` helper that transmits `{0x00, control}`, so every
    /// vendor channel select is preceded by a spurious mux-disable byte.
    fn write_control(&mut self, i2c: &mut I2cBus, control: u8) -> Result<(), Pca9544DriverError> {
        let frame = [control];
        debug_assert_eq!(frame.len(), CONTROL_WRITE_LEN);
        i2c.write(self.addr, &frame)?;
        Ok(())
    }

    /// Read the control register back.
    ///
    /// Also a bare one-byte read for the same reason — there is no register to
    /// point at.
    fn read_control(&mut self, i2c: &mut I2cBus) -> Result<u8, Pca9544DriverError> {
        let bytes = i2c.read(self.addr, 1)?;
        match bytes.first() {
            Some(&b) => Ok(b),
            None => Err(Pca9544DriverError::ShortRead { got: bytes.len() }),
        }
    }
}
