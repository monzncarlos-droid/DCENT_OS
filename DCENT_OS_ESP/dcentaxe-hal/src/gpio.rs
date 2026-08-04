//! GPIO helpers for BitAxe board control.
//!
//! Provides simple wrappers for the discrete GPIO functions on a BitAxe:
//! - ASIC chain reset (active low)
//! - Buck converter enable
//! - Status LED

use esp_idf_hal::gpio::{Output, OutputPin, PinDriver};
use log::*;

/// Errors from GPIO operations
#[derive(Debug)]
pub enum GpioError {
    /// Failed to configure a GPIO pin
    ConfigFailed(String),
    /// Failed to set a GPIO output level
    SetLevelFailed(String),
}

impl core::fmt::Display for GpioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConfigFailed(msg) => write!(f, "GPIO config failed: {}", msg),
            Self::SetLevelFailed(msg) => write!(f, "GPIO set level failed: {}", msg),
        }
    }
}

impl std::error::Error for GpioError {}

/// GPIO controller for BitAxe board-level functions.
///
/// Manages the discrete GPIO pins for ASIC reset, buck converter enable,
/// and status LED. All pins are configured as push-pull outputs.
pub struct GpioController<'d> {
    /// ASIC chain reset pin — active low (low = reset, high = normal)
    asic_reset: PinDriver<'d, Output>,
    /// Buck converter enable pin
    buck_enable: Option<PinDriver<'d, Output>>,
    /// True if buck enable is active-low (Max/Ultra DS4432U boards)
    buck_active_low: bool,
    /// Status LED pin — high = on (polarity may vary by board)
    led: PinDriver<'d, Output>,
    /// ASIC LDO enable pin — ACTIVE-HIGH, `None` on boards with no LDO rail.
    ///
    /// A SECOND supply, not a second handle on the buck. See
    /// [`crate::board::LdoEnable`]: on the multi-phase Nerd line the dies need
    /// both this and the core rail, and the LDO must be up first.
    ldo_enable: Option<PinDriver<'d, Output>>,
}

impl<'d> GpioController<'d> {
    /// Initialize GPIO controller with the given pins.
    ///
    /// All pins are configured as push-pull outputs with initial safe states:
    /// - ASIC reset: HIGH (not in reset)
    /// - Buck enable: LOW (regulator off until explicitly enabled)
    /// - LED: LOW (off)
    pub fn new(
        asic_reset_pin: impl OutputPin + 'd,
        buck_enable_pin: impl OutputPin + 'd,
        led_pin: impl OutputPin + 'd,
        buck_active_low: bool,
    ) -> Result<Self, GpioError> {
        let mut asic_reset = PinDriver::output(asic_reset_pin)
            .map_err(|e| GpioError::ConfigFailed(format!("asic_reset: {:?}", e)))?;
        let mut buck_enable = PinDriver::output(buck_enable_pin)
            .map_err(|e| GpioError::ConfigFailed(format!("buck_enable: {:?}", e)))?;
        let mut led = PinDriver::output(led_pin)
            .map_err(|e| GpioError::ConfigFailed(format!("led: {:?}", e)))?;

        // Safe initial states
        asic_reset
            .set_high()
            .map_err(|e| GpioError::SetLevelFailed(format!("asic_reset high: {:?}", e)))?;
        // Buck off: active-low means HIGH=off, active-high means LOW=off
        if buck_active_low {
            buck_enable.set_high().map_err(|e| {
                GpioError::SetLevelFailed(format!("buck_enable high(off): {:?}", e))
            })?;
        } else {
            buck_enable
                .set_low()
                .map_err(|e| GpioError::SetLevelFailed(format!("buck_enable low(off): {:?}", e)))?;
        }
        led.set_low()
            .map_err(|e| GpioError::SetLevelFailed(format!("led low: {:?}", e)))?;

        info!(
            "GPIO controller initialized (reset=HIGH, buck=OFF, led=OFF, active_low={})",
            buck_active_low
        );

        Ok(Self {
            asic_reset,
            buck_enable: Some(buck_enable),
            buck_active_low,
            led,
            ldo_enable: None,
        })
    }

    /// Initialize reset + buck + LED **and** a discrete ASIC LDO enable.
    ///
    /// For the multi-phase Nerd line, whose dies are fed by an LDO bank on top
    /// of the TPS5364x core rail (`crate::board::LdoEnable`). The LDO starts
    /// LOW — off — exactly as upstream's `initBoard` leaves it, so nothing is
    /// energized by construction; `enable_ldo(true)` is a separate, ordered
    /// step in the power-up sequence.
    pub fn new_with_ldo(
        asic_reset_pin: impl OutputPin + 'd,
        buck_enable_pin: impl OutputPin + 'd,
        led_pin: impl OutputPin + 'd,
        ldo_enable_pin: impl OutputPin + 'd,
        buck_active_low: bool,
    ) -> Result<Self, GpioError> {
        let mut ctrl = Self::new(asic_reset_pin, buck_enable_pin, led_pin, buck_active_low)?;
        let mut ldo = PinDriver::output(ldo_enable_pin)
            .map_err(|e| GpioError::ConfigFailed(format!("ldo_enable: {:?}", e)))?;
        ldo.set_low()
            .map_err(|e| GpioError::SetLevelFailed(format!("ldo_enable low(off): {:?}", e)))?;
        ctrl.ldo_enable = Some(ldo);
        info!("GPIO controller: ASIC LDO enable configured (OFF)");
        Ok(ctrl)
    }

    /// Initialize reset + status LED without claiming a buck-enable GPIO.
    ///
    /// Hammer boards use this path: GPIO46 is ST7789 D5, GPIO15 is a shared
    /// board/LCD-power net, and no discrete regulator-enable pin is verified.
    /// An absent buck is represented explicitly rather than borrowing a panel
    /// or PGOOD pin as a "safe" dummy output.
    pub fn new_without_buck(
        asic_reset_pin: impl OutputPin + 'd,
        led_pin: impl OutputPin + 'd,
    ) -> Result<Self, GpioError> {
        let mut asic_reset = PinDriver::output(asic_reset_pin)
            .map_err(|e| GpioError::ConfigFailed(format!("asic_reset: {:?}", e)))?;
        let mut led = PinDriver::output(led_pin)
            .map_err(|e| GpioError::ConfigFailed(format!("led: {:?}", e)))?;

        asic_reset
            .set_high()
            .map_err(|e| GpioError::SetLevelFailed(format!("asic_reset high: {:?}", e)))?;
        led.set_low()
            .map_err(|e| GpioError::SetLevelFailed(format!("led low: {:?}", e)))?;

        info!("GPIO controller initialized (reset=HIGH, buck=ABSENT, led=OFF)");
        Ok(Self {
            asic_reset,
            buck_enable: None,
            buck_active_low: false,
            led,
            ldo_enable: None,
        })
    }

    /// Whether this board has a discrete ASIC LDO enable bound.
    ///
    /// `false` means the board genuinely has no separate LDO rail — NOT that
    /// one exists and failed to bind. The binder cannot produce the second
    /// case: an arm either hands `new_with_ldo` a pin or does not exist.
    pub fn has_ldo(&self) -> bool {
        self.ldo_enable.is_some()
    }

    /// Whether the ASIC LDO is currently being driven HIGH.
    ///
    /// Reads the driver's own output state rather than a shadow flag, so it
    /// cannot drift from the pin. `false` for a board with no LDO — "not
    /// energized" is the truthful answer there, and it lets a shutdown path
    /// skip the LDO step without a second `has_ldo()` call.
    ///
    /// This is what makes the fail-closed LDO drop IDEMPOTENT. That path is
    /// reachable from the supervisor loop (POWER FAULT, INA260 over-current),
    /// and its 500 ms settle must happen at most once — a settle re-run every
    /// tick would spend the task-WDT budget on a rail that is already down.
    pub fn ldo_is_enabled(&self) -> bool {
        self.ldo_enable
            .as_ref()
            .map(|p| p.is_set_high())
            .unwrap_or(false)
    }

    /// Drive the ASIC LDO enable. ACTIVE-HIGH: `true` powers the LDO bank.
    ///
    /// Returns `Err` only when this board has no LDO pin at all. That is a
    /// TOPOLOGY report, exactly like `enable_buck`'s on a board with no buck
    /// GPIO — read it through [`Self::has_ldo`], never as an actuation failure.
    /// The distinction is the whole subject of
    /// : one un-`ok()`d call
    /// site turned that same sentinel into a permanent mining refusal for three
    /// boards.
    pub fn enable_ldo(&mut self, on: bool) -> Result<(), GpioError> {
        let ldo = self.ldo_enable.as_mut().ok_or_else(|| {
            GpioError::ConfigFailed("board has no ASIC LDO enable pin".to_string())
        })?;
        if on {
            ldo.set_high()
                .map_err(|e| GpioError::SetLevelFailed(format!("ldo_enable high: {:?}", e)))?;
        } else {
            ldo.set_low()
                .map_err(|e| GpioError::SetLevelFailed(format!("ldo_enable low: {:?}", e)))?;
        }
        info!("ASIC LDO {}", if on { "ENABLED" } else { "DISABLED" });
        Ok(())
    }

    /// Reset the ASIC chain by pulsing the reset pin low for 100 ms.
    ///
    /// The ASIC reset is active-low: pulling the pin LOW resets all ASICs
    /// on the chain. After the reset pulse, the pin is driven HIGH again
    /// to release the ASICs for normal operation.
    ///
    /// A 100 ms delay after releasing reset allows the ASICs to complete
    /// their internal power-on sequence before UART communication begins.
    pub fn reset_asic(&mut self) -> Result<(), GpioError> {
        info!("Resetting ASIC chain (100ms low pulse)");

        // Drive reset LOW
        self.asic_reset
            .set_low()
            .map_err(|e| GpioError::SetLevelFailed(format!("reset low: {:?}", e)))?;

        // Hold low for 100 ms
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Release reset
        self.asic_reset
            .set_high()
            .map_err(|e| GpioError::SetLevelFailed(format!("reset high: {:?}", e)))?;

        // Wait for ASIC to stabilize after reset
        std::thread::sleep(std::time::Duration::from_millis(100));

        info!("ASIC reset complete");
        Ok(())
    }

    /// Bring the ASIC rail up in the correct order: buck-enable → settle →
    /// reset-pulse, in a single place.
    ///
    /// HALT-8: `new()` releases ASIC reset HIGH and forces the buck OFF, so the
    /// power-on *ordering* (rail up before the reset pulse, per BM136x/BM1370
    /// expectations) was previously the caller's responsibility, spread across
    /// `main.rs`, with nothing in the type coupling power-up and reset. A future
    /// refactor could reorder them. This helper encapsulates the guarantee that
    /// `lib.rs` attributes to the HAL so the sequence lives in one auditable
    /// place. It is opt-in — boards that already drive the legacy explicit
    /// `enable_buck()` / `reset_asic()` order keep their exact behavior.
    ///
    /// Sequence: enable the buck, wait `settle_ms` for the rail to stabilize,
    /// then pulse reset (100 ms low + 100 ms post-release settle via
    /// [`reset_asic`](Self::reset_asic)). If the buck enable fails the rail is
    /// not energized and reset is NOT pulsed (fail-closed — never pulse reset
    /// into an un-powered or partially-powered chip).
    ///
    /// # Arguments
    /// * `settle_ms` - rail stabilization delay between buck-on and the reset
    ///   pulse (BitAxe boards use ~100–500 ms; the GT path uses 500 ms).
    pub fn power_on_sequence(&mut self, settle_ms: u64) -> Result<(), GpioError> {
        info!(
            "GPIO power-on sequence: buck ENABLE → settle {} ms → ASIC reset pulse",
            settle_ms
        );
        // 1. Energize the rail first.
        self.enable_buck(true)?;
        // 2. Let the buck output stabilize before clocking the chip out of reset.
        std::thread::sleep(std::time::Duration::from_millis(settle_ms));
        // 3. Pulse reset only after the rail is up (rail-up → reset → UART).
        self.reset_asic()?;
        Ok(())
    }

    /// Enable or disable the buck converter (TPS546 power stage).
    ///
    /// The buck converter must be enabled before the ASIC can operate.
    /// Disabling it cuts power to the ASIC entirely — used for emergency
    /// shutdown or low-power standby.
    ///
    /// Ordering note (HALT-8): the BM136x/BM1370 chips expect rail-up → reset
    /// pulse → UART. If you drive `enable_buck()` and [`reset_asic`](Self::reset_asic)
    /// independently, the caller owns that ordering; prefer
    /// [`power_on_sequence`](Self::power_on_sequence), which encapsulates it.
    ///
    /// # Arguments
    /// * `on` - `true` to enable the buck converter, `false` to disable
    pub fn enable_buck(&mut self, on: bool) -> Result<(), GpioError> {
        let buck_enable = self.buck_enable.as_mut().ok_or_else(|| {
            GpioError::ConfigFailed(format!(
                "buck-enable GPIO is not bound; refusing request to turn rail {}",
                if on { "on" } else { "off" }
            ))
        })?;
        // Active-low: LOW=enabled, HIGH=disabled
        // Active-high: HIGH=enabled, LOW=disabled
        // Single source of truth shared with the fail-closed panic hook
        // (XPSAFE-1) so the driver and the hook can never disagree on polarity.
        let level_high = crate::safety::buck_level_high(self.buck_active_low, on);
        if level_high {
            buck_enable
                .set_high()
                .map_err(|e| GpioError::SetLevelFailed(format!("buck high: {:?}", e)))?;
        } else {
            buck_enable
                .set_low()
                .map_err(|e| GpioError::SetLevelFailed(format!("buck low: {:?}", e)))?;
        }
        info!(
            "Buck converter {} (pin={}, active_low={})",
            if on { "ENABLED" } else { "DISABLED" },
            if level_high { "HIGH" } else { "LOW" },
            self.buck_active_low
        );
        Ok(())
    }

    /// Set the status LED on or off.
    ///
    /// # Arguments
    /// * `on` - `true` to turn the LED on, `false` to turn it off
    pub fn set_led(&mut self, on: bool) -> Result<(), GpioError> {
        if on {
            self.led
                .set_high()
                .map_err(|e| GpioError::SetLevelFailed(format!("led high: {:?}", e)))?;
        } else {
            self.led
                .set_low()
                .map_err(|e| GpioError::SetLevelFailed(format!("led low: {:?}", e)))?;
        }
        Ok(())
    }

    /// Toggle the LED state (useful for heartbeat blink).
    pub fn toggle_led(&mut self) -> Result<(), GpioError> {
        self.led
            .toggle()
            .map_err(|e| GpioError::SetLevelFailed(format!("led toggle: {:?}", e)))?;
        Ok(())
    }
}
