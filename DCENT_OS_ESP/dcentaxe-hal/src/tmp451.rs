//! TMP451 / ADT7461-family remote-diode sensor — I2C + GPIO transport shim.
//!
//! Every decision (register map, signed/extended decode, open-circuit
//! availability, mux channel encoding, per-board calibration bounds) lives in
//! the host-pure [`crate::tmp451_convert`] module and is covered by the host
//! test gate. This file only moves bytes and toggles pins.
//!
//! Fitted to the muxed Nerd boards, where one sensor is fanned across four ASIC
//! diodes by a 2-bit analog mux. The NerdOCTAXE-γ carries **two** of these
//! (0x4C and 0x4E) whose select lines are the SAME pair of GPIOs — see
//! [`MuxSelect`] for why that is safe and how to drive it efficiently.

use log::{info, warn};

use esp_idf_hal::gpio::{AnyIOPin, Output, PinDriver};
use esp_idf_hal::sys::EspError;

use crate::i2c::{I2cBus, I2cError};
use crate::tmp451_convert::{
    self as conv, reg, Calibration, Reading, Settling, TempRange, Tmp451ConfigError,
    ONE_SHOT_TRIGGER,
};

/// Errors from the TMP451 driver.
#[derive(Debug)]
pub enum Tmp451Error {
    /// I2C transport failure.
    I2c(I2cError),
    /// GPIO failure driving the mux select lines.
    Gpio(EspError),
    /// Nothing answered at this address.
    NotFound(u8),
    /// A configuration value was refused by the pure core.
    Config(Tmp451ConfigError),
    /// A one-shot conversion never cleared BUSY.
    ConversionTimeout,
    /// A muxed channel was requested on a sensor with no mux wired.
    NoMux(u8),
}

impl core::fmt::Display for Tmp451Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::I2c(e) => write!(f, "TMP451 I2C error: {e}"),
            Self::Gpio(e) => write!(f, "TMP451 mux GPIO error: {e}"),
            Self::NotFound(a) => write!(f, "no TMP451 answered at 0x{a:02X}"),
            Self::Config(e) => write!(f, "TMP451 config refused: {e}"),
            Self::ConversionTimeout => write!(f, "TMP451 one-shot conversion timed out"),
            Self::NoMux(c) => write!(f, "channel {c} requested but no mux is wired"),
        }
    }
}

impl From<I2cError> for Tmp451Error {
    fn from(e: I2cError) -> Self {
        Self::I2c(e)
    }
}

impl From<EspError> for Tmp451Error {
    fn from(e: EspError) -> Self {
        Self::Gpio(e)
    }
}

impl From<Tmp451ConfigError> for Tmp451Error {
    fn from(e: Tmp451ConfigError) -> Self {
        Self::Config(e)
    }
}

fn sleep_ms(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

/// The 2-bit analog mux that fans one sensor across four ASIC diodes.
///
/// On the NerdOCTAXE-γ both TMP451s share ONE pair of select lines, so a single
/// `MuxSelect` drives the analog path for both sensors at once: select a channel
/// once, then read the same channel from each address. That is why this is a
/// separate owned type rather than a field baked into [`Tmp451`] — two sensors
/// cannot each own the same GPIO.
pub struct MuxSelect<'d> {
    a0: PinDriver<'d, Output>,
    a1: PinDriver<'d, Output>,
    active_high: bool,
    /// Last channel driven, so a repeat select can skip the settle delay.
    selected: Option<u8>,
}

impl<'d> MuxSelect<'d> {
    /// Claim the two select GPIOs as outputs.
    ///
    /// `active_high == false` inverts both lines, for a board that wires them
    /// through an inverting buffer.
    pub fn new(a0: AnyIOPin<'d>, a1: AnyIOPin<'d>, active_high: bool) -> Result<Self, Tmp451Error> {
        Ok(Self {
            a0: PinDriver::output(a0)?,
            a1: PinDriver::output(a1)?,
            active_high,
            selected: None,
        })
    }

    /// Drive the select lines for `channel`.
    ///
    /// Returns `true` when the analog path actually changed, so the caller can
    /// skip the settle delay on a repeat select.
    pub fn select(&mut self, channel: u8) -> Result<bool, Tmp451Error> {
        let (a0, a1) = conv::mux_levels(channel, self.active_high)?;
        if self.selected == Some(channel) {
            return Ok(false);
        }
        self.a0.set_level(a0.into())?;
        self.a1.set_level(a1.into())?;
        self.selected = Some(channel);
        Ok(true)
    }

    /// The channel currently driven, if any.
    pub fn selected(&self) -> Option<u8> {
        self.selected
    }
}

/// A TMP451 / ADT7461-family sensor on the I2C bus.
pub struct Tmp451 {
    addr: u8,
    range: TempRange,
    cal: Calibration,
    settling: Settling,
}

impl Tmp451 {
    /// Probe and initialize the sensor at `addr`.
    ///
    /// Mirrors upstream's init: enter standby for one-shot operation, reset the
    /// ideality (n-factor) and remote-offset registers to their defaults so a
    /// warm reboot cannot inherit a previous session's correction. Then reads
    /// the CONFIG register BACK to derive the temperature range rather than
    /// assuming it — a part left in extended range by another firmware decodes
    /// correctly instead of reading 64 C low.
    ///
    /// `cal` must be the calibration DECLARED by the board row. Passing
    /// [`Calibration::IDENTITY`] is the safe choice for an uncharacterized
    /// board: it over-reports relative to a board that needs correction, which
    /// errs toward cutting off early rather than cooking the chip.
    pub fn new(i2c: &mut I2cBus, addr: u8, cal: Calibration) -> Result<Self, Tmp451Error> {
        if !conv::is_plausible_address(addr) {
            return Err(Tmp451Error::Config(Tmp451ConfigError::AddressReserved(
                addr,
            )));
        }
        cal.validate()?;

        if !i2c.probe(addr) {
            return Err(Tmp451Error::NotFound(addr));
        }
        // Upstream treats an unreadable STATUS as "not responding"; a device
        // that ACKs its address but cannot be read is not a usable sensor.
        i2c.read_reg_u8(addr, reg::STATUS)
            .map_err(|_| Tmp451Error::NotFound(addr))?;

        i2c.write_reg_u8(addr, reg::CONFIG_WRITE, conv::init_config_byte())?;
        i2c.write_reg_u8(addr, reg::NFACTOR, 0x00)?;
        i2c.write_reg_u8(addr, reg::REMOTE_OFFSET_MSB, 0x00)?;
        i2c.write_reg_u8(addr, reg::REMOTE_OFFSET_LSB, 0x00)?;

        // Derive the range from what the part actually reports, never from a
        // bit we wrote. `init_config_byte` deliberately leaves the range bit
        // clear, so a well-behaved part answers Standard here.
        let range = match i2c.read_reg_u8(addr, reg::CONFIG_READ) {
            Ok(cfg) => TempRange::from_config(cfg),
            Err(e) => {
                // Standard is the range every board in our corpus ships and the
                // one we just asked for; a readback failure is not a reason to
                // refuse the sensor, but it IS worth surfacing.
                warn!("TMP451 0x{addr:02X}: CONFIG readback failed ({e}), assuming standard range");
                TempRange::Standard
            }
        };

        info!(
            "TMP451 0x{:02X}: initialized, range={:?}, calibration={}",
            addr,
            range,
            if cal.is_identity() {
                "identity"
            } else {
                "board-declared"
            }
        );

        Ok(Self {
            addr,
            range,
            cal,
            settling: Settling::default(),
        })
    }

    /// Override the settling profile (defaults are upstream's).
    pub fn with_settling(mut self, settling: Settling) -> Self {
        self.settling = settling;
        self
    }

    /// The I2C address this sensor answers at.
    pub fn addr(&self) -> u8 {
        self.addr
    }

    /// The decode range derived at init.
    pub fn range(&self) -> TempRange {
        self.range
    }

    /// The board-declared calibration in force.
    pub fn calibration(&self) -> &Calibration {
        &self.cal
    }

    /// Trigger a one-shot conversion and wait for BUSY to clear.
    fn one_shot(&self, i2c: &mut I2cBus) -> Result<(), Tmp451Error> {
        i2c.write_reg_u8(self.addr, reg::ONE_SHOT, ONE_SHOT_TRIGGER)?;

        let mut waited = 0u32;
        loop {
            let status = i2c.read_reg_u8(self.addr, reg::STATUS)?;
            if !conv::conversion_busy(status) {
                return Ok(());
            }
            if waited >= self.settling.one_shot_timeout_ms {
                warn!(
                    "TMP451 0x{:02X}: one-shot timeout, status=0x{:02X}",
                    self.addr, status
                );
                return Err(Tmp451Error::ConversionTimeout);
            }
            sleep_ms(self.settling.poll_interval_ms);
            waited += self.settling.poll_interval_ms;
        }
    }

    /// Read the local (sensor die) temperature.
    ///
    /// This is board temperature near the sensor, NOT an ASIC junction
    /// temperature — never substitute it for a per-chip reading.
    pub fn read_local(&self, i2c: &mut I2cBus) -> Result<Option<f32>, Tmp451Error> {
        self.one_shot(i2c)?;
        // MSB first: reading the integer register latches the fraction.
        let msb = i2c.read_reg_u8(self.addr, reg::LOCAL_MSB)?;
        let lsb = i2c.read_reg_u8(self.addr, reg::LOCAL_LSB)?;
        Ok(conv::decode_available_temp(self.range, msb, lsb))
    }

    /// Read the remote diode currently selected on the analog path.
    ///
    /// `channel` selects which calibration offset applies; it does NOT drive the
    /// mux. Call [`MuxSelect::select`] first — see [`read_muxed_channel`] for
    /// the sequenced version.
    ///
    /// Returns `Ok(None)` when the diode reads as an open circuit.
    pub fn read_remote(
        &self,
        i2c: &mut I2cBus,
        channel: u8,
    ) -> Result<Option<Reading>, Tmp451Error> {
        self.one_shot(i2c)?;
        let msb = i2c.read_reg_u8(self.addr, reg::REMOTE_MSB)?;
        let lsb = i2c.read_reg_u8(self.addr, reg::REMOTE_LSB)?;
        Ok(Reading::decode(self.range, &self.cal, channel, msb, lsb)?)
    }

    /// Select a mux channel, let the analog path settle, and read it.
    ///
    /// The discarded first conversion is load-bearing: the conversion in flight
    /// when the mux switches was started against the PREVIOUS channel's diode,
    /// so reporting it would attribute one ASIC's temperature to another. Only
    /// paid when the select actually changed the analog path.
    pub fn read_muxed_channel(
        &self,
        i2c: &mut I2cBus,
        mux: &mut MuxSelect<'_>,
        channel: u8,
    ) -> Result<Option<Reading>, Tmp451Error> {
        let changed = mux.select(channel)?;
        if changed {
            sleep_ms(self.settling.after_switch_ms);
            // Discard: started against the previous channel's diode.
            let _ = self.read_remote(i2c, channel);
            sleep_ms(self.settling.before_read_ms);
        }
        self.read_remote(i2c, channel)
    }

    /// Read a channel without a mux (single-diode board).
    ///
    /// Refuses any channel but 0 rather than silently returning the one diode
    /// that is wired — a board asking for channel 2 on an unmuxed sensor is
    /// misconfigured, and answering would attribute one diode to four ASICs.
    pub fn read_unmuxed(
        &self,
        i2c: &mut I2cBus,
        channel: u8,
    ) -> Result<Option<Reading>, Tmp451Error> {
        if channel != 0 {
            return Err(Tmp451Error::NoMux(channel));
        }
        self.read_remote(i2c, 0)
    }
}

/// Probe for a TMP451 without claiming it.
///
/// Used by bring-up to decide whether a board revision actually fits the sensor
/// — the muxed Nerd revisions are the newer ones, and an older board simply
/// does not answer.
pub fn probe(i2c: &mut I2cBus, addr: u8) -> bool {
    if !conv::is_plausible_address(addr) {
        return false;
    }
    i2c.probe(addr) && i2c.read_reg_u8(addr, reg::STATUS).is_ok()
}
