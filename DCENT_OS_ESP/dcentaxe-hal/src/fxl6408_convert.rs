//! FXL6408 8-bit I²C GPIO port expander — host-pure register and bit core.
//!
//! # Why this exists
//!
//! Every board in the registry before the Q-series drives its safety-critical
//! enables — ASIC reset, VREG enable, LDO enable — from ESP GPIOs. A GPIO write
//! cannot fail: the pin moves. The Q1370/Q1373 route all three through an
//! FXL6408 at `0x43` instead, which makes each one an I²C transaction, and an
//! I²C transaction *can* fail. That is the whole reason this is a driver rather
//! than three `gpio_set_level` calls:
//!
//! * A failed write means **the pin did not move**. The shadow state this module
//!   maintains must therefore be updated only on success, or the next write
//!   would compute its mask from a fiction and silently flip an unrelated pin.
//! * There is no "read the pin back" for an output on this part — the input
//!   status register reflects the pad, but reading it costs another transaction
//!   that can itself fail. So the honest contract is: report the error, never
//!   assume.
//!
//! # Evidence
//!
//! Register map and reset behaviour are from upstream's `fxl6408.cpp` in
//! `ESP-Miner-NerdQAxePlus` (`main/boards/drivers/`), which is the only
//! implementation in our corpus that drives this part. Pin assignments are from
//! `q1370.cpp`: expander pin 0 = ASIC reset, 1 = VREG enable, 2 = LDO enable,
//! 3/4 = TMP451 mux selects, 5 = CAN slave-detect strap (input, pull-up).
//!
//! # Divergences from upstream, and why
//!
//! * **Upstream's `init()` returns `true` after a reset whose write errors are
//!   only logged.** `write_reg(REG_CTRL, 0x01)` and the output-high-Z clear both
//!   ignore their result — so a board whose expander half-answered reports a
//!   successful init and then drives ASIC reset into a device that never left
//!   high-Z. Here every step of the reset sequence is checked.
//! * **Upstream tracks direction/output/pull shadows as plain fields updated
//!   before the write.** A failed write leaves the shadow ahead of the hardware.
//!   [`PortState`] applies the mask to a *candidate*, and only
//!   [`PortState::commit`] moves the shadow — so the caller physically cannot
//!   record a write that did not land.
//! * **Upstream's pin bound is `pin > 7`.** Same bound here, but as a typed
//!   error rather than an `ESP_ERR_INVALID_ARG` a caller may ignore.

/// I²C register addresses (upstream `fxl6408.cpp`).
pub mod reg {
    /// Device ID + control. Reads a device code; writing bit 0 is a soft reset.
    pub const CTRL: u8 = 0x01;
    /// Per-pin direction. `1` = output, `0` = input.
    pub const DIRECTION: u8 = 0x03;
    /// Per-pin output level for pins configured as outputs.
    pub const OUTPUT_STATE: u8 = 0x05;
    /// Per-pin output high-Z. `1` = high-Z, `0` = actively driven.
    pub const OUTPUT_HIZ: u8 = 0x07;
    /// Per-pin pull resistor enable.
    pub const PULL_ENABLE: u8 = 0x0B;
    /// Per-pin pull direction. `1` = pull-up, `0` = pull-down.
    pub const PULL_SELECT: u8 = 0x0D;
    /// Per-pin pad level, readable regardless of direction.
    pub const INPUT_STATUS: u8 = 0x0F;
}

/// The only I²C address upstream ever uses for this part.
pub const ADDR: u8 = 0x43;

/// Soft-reset command written to [`reg::CTRL`].
pub const CTRL_SOFT_RESET: u8 = 0x01;

/// All pins actively driven (no high-Z), written to [`reg::OUTPUT_HIZ`].
pub const OUTPUT_HIZ_NONE: u8 = 0x00;

/// Highest addressable pin. The part is 8-bit: pins 0..=7.
pub const MAX_PIN: u8 = 7;

/// Q-series expander pin assignments (`q1370.cpp`).
pub mod q_series {
    /// ASIC reset. Driven low to hold the chain in reset.
    pub const ASIC_RESET: u8 = 0;
    /// Core-rail regulator enable.
    pub const VREG_ENABLE: u8 = 1;
    /// LDO enable.
    pub const LDO_ENABLE: u8 = 2;
    /// TMP451 analog-mux select A0.
    pub const TMUX_A0: u8 = 3;
    /// TMP451 analog-mux select A1.
    pub const TMUX_A1: u8 = 4;
    /// CAN slave-detect strap. Input with pull-up; a DIP switch pulls it to GND
    /// on a slave board, so **low = slave** and open/high = master.
    pub const CAN_SLAVE_DETECT: u8 = 5;

    /// The three pins that must be driven LOW before the rail is brought up.
    ///
    /// Upstream's `Q1370B::initBoard` sets all three to output-low immediately
    /// after the expander init and before anything energizes. Ordering matters:
    /// an ASIC released from reset onto an unpowered rail, or a VREG enabled
    /// while the LDO is down, are both out-of-sequence bring-ups.
    pub const POWER_SEQUENCE_OUTPUTS: [u8; 3] = [ASIC_RESET, VREG_ENABLE, LDO_ENABLE];
}

/// Why an FXL6408 operation was refused before it reached the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fxl6408ConfigError {
    /// Pin index above [`MAX_PIN`].
    PinOutOfRange(u8),
}

impl core::fmt::Display for Fxl6408ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PinOutOfRange(p) => {
                write!(f, "FXL6408 pin {p} is above the 8-bit range")
            }
        }
    }
}

/// Bit mask for a pin, range-checked.
pub fn pin_mask(pin: u8) -> Result<u8, Fxl6408ConfigError> {
    if pin > MAX_PIN {
        return Err(Fxl6408ConfigError::PinOutOfRange(pin));
    }
    Ok(1 << pin)
}

/// Decode a pin's level out of an [`reg::INPUT_STATUS`] byte.
pub fn pin_level(status: u8, pin: u8) -> Result<bool, Fxl6408ConfigError> {
    Ok(status & pin_mask(pin)? != 0)
}

/// Decode the CAN slave-detect strap.
///
/// The pin is an input with a pull-up; a DIP switch pulls it to ground on a
/// slave board. **Low means slave.** Stated as its own function because the
/// inversion is exactly the kind of detail that gets dropped when a caller reads
/// the raw level and compares it to `true`.
pub fn is_can_slave(status: u8) -> Result<bool, Fxl6408ConfigError> {
    Ok(!pin_level(status, q_series::CAN_SLAVE_DETECT)?)
}

/// Shadow copies of the expander's write-only registers.
///
/// The FXL6408's direction, output, pull-enable and pull-select registers are
/// written as whole bytes, so changing one pin requires knowing the other seven.
/// The part gives no cheap read-back path for them, so the driver must remember.
///
/// **The shadow only advances on a successful write.** [`Self::with_pin`]
/// returns the byte to send without mutating anything; [`Self::commit`] is the
/// separate step a caller performs *after* the bus reports success. Upstream
/// merges the two and so records writes that never landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortState {
    direction: u8,
    output: u8,
    pull_enable: u8,
    pull_select: u8,
}

/// Which shadow register a pending write targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port {
    Direction,
    Output,
    PullEnable,
    PullSelect,
}

impl Port {
    /// The I²C register this port is written to.
    pub fn register(self) -> u8 {
        match self {
            Self::Direction => reg::DIRECTION,
            Self::Output => reg::OUTPUT_STATE,
            Self::PullEnable => reg::PULL_ENABLE,
            Self::PullSelect => reg::PULL_SELECT,
        }
    }
}

impl PortState {
    /// Power-on state: every pin an input, every output low, no pulls.
    ///
    /// This matches the part after the [`CTRL_SOFT_RESET`] the driver issues, so
    /// the shadow and the hardware start in agreement. Starting from anything
    /// else would mean the first single-pin write sends seven invented bits.
    pub const fn after_reset() -> Self {
        Self {
            direction: 0,
            output: 0,
            pull_enable: 0,
            pull_select: 0,
        }
    }

    /// Current byte for a port.
    pub fn get(&self, port: Port) -> u8 {
        match port {
            Port::Direction => self.direction,
            Port::Output => self.output,
            Port::PullEnable => self.pull_enable,
            Port::PullSelect => self.pull_select,
        }
    }

    /// The byte that would set `pin` to `set` in `port` — **without** recording
    /// it. Send this to the bus; call [`Self::commit`] only if that succeeded.
    pub fn with_pin(&self, port: Port, pin: u8, set: bool) -> Result<u8, Fxl6408ConfigError> {
        let mask = pin_mask(pin)?;
        let current = self.get(port);
        Ok(if set { current | mask } else { current & !mask })
    }

    /// Record a byte the hardware has confirmed it accepted.
    pub fn commit(&mut self, port: Port, value: u8) {
        match port {
            Port::Direction => self.direction = value,
            Port::Output => self.output = value,
            Port::PullEnable => self.pull_enable = value,
            Port::PullSelect => self.pull_select = value,
        }
    }

    /// Whether a pin is currently configured as an output.
    pub fn is_output(&self, pin: u8) -> Result<bool, Fxl6408ConfigError> {
        Ok(self.direction & pin_mask(pin)? != 0)
    }
}

/// The two register writes that enable a pull-UP on a pin, in order.
///
/// Select before enable: setting `PULL_ENABLE` first would momentarily arm
/// whatever direction `PULL_SELECT` currently holds, which after reset is
/// pull-DOWN. On the CAN slave-detect strap that transient reads as "slave".
/// Upstream writes them in this order; stating it here keeps it from being
/// reordered by someone tidying up.
pub const PULL_UP_WRITE_ORDER: [Port; 2] = [Port::PullSelect, Port::PullEnable];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_addresses_match_upstream() {
        assert_eq!(reg::CTRL, 0x01);
        assert_eq!(reg::DIRECTION, 0x03);
        assert_eq!(reg::OUTPUT_STATE, 0x05);
        assert_eq!(reg::OUTPUT_HIZ, 0x07);
        assert_eq!(reg::PULL_ENABLE, 0x0B);
        assert_eq!(reg::PULL_SELECT, 0x0D);
        assert_eq!(reg::INPUT_STATUS, 0x0F);
        assert_eq!(ADDR, 0x43);
    }

    #[test]
    fn pins_above_the_eight_bit_range_are_refused() {
        for pin in 0..=MAX_PIN {
            assert_eq!(pin_mask(pin), Ok(1 << pin));
        }
        for pin in [8u8, 9, 255] {
            assert_eq!(pin_mask(pin), Err(Fxl6408ConfigError::PinOutOfRange(pin)));
        }
    }

    #[test]
    fn the_q_series_pin_map_matches_q1370_cpp() {
        assert_eq!(q_series::ASIC_RESET, 0);
        assert_eq!(q_series::VREG_ENABLE, 1);
        assert_eq!(q_series::LDO_ENABLE, 2);
        assert_eq!(q_series::TMUX_A0, 3);
        assert_eq!(q_series::TMUX_A1, 4);
        assert_eq!(q_series::CAN_SLAVE_DETECT, 5);
    }

    #[test]
    fn every_q_series_pin_is_distinct_and_addressable() {
        let pins = [
            q_series::ASIC_RESET,
            q_series::VREG_ENABLE,
            q_series::LDO_ENABLE,
            q_series::TMUX_A0,
            q_series::TMUX_A1,
            q_series::CAN_SLAVE_DETECT,
        ];
        for (i, a) in pins.iter().enumerate() {
            assert!(pin_mask(*a).is_ok(), "pin {a} must be addressable");
            for b in &pins[i + 1..] {
                assert_ne!(a, b, "two Q-series functions share expander pin {a}");
            }
        }
    }

    #[test]
    fn the_power_sequence_outputs_are_the_three_enables_and_nothing_else() {
        // A mux select or the slave-detect strap appearing here would be driven
        // low at bring-up: the strap is an INPUT and driving it would fight the
        // DIP switch.
        assert_eq!(
            q_series::POWER_SEQUENCE_OUTPUTS,
            [
                q_series::ASIC_RESET,
                q_series::VREG_ENABLE,
                q_series::LDO_ENABLE
            ]
        );
        assert!(!q_series::POWER_SEQUENCE_OUTPUTS.contains(&q_series::CAN_SLAVE_DETECT));
        assert!(!q_series::POWER_SEQUENCE_OUTPUTS.contains(&q_series::TMUX_A0));
        assert!(!q_series::POWER_SEQUENCE_OUTPUTS.contains(&q_series::TMUX_A1));
    }

    // ── The shadow-state contract ─────────────────────────────────────────────

    #[test]
    fn a_failed_write_leaves_the_shadow_untouched() {
        // THE defect this split exists to prevent. `with_pin` computes; only
        // `commit` records. Simulate a bus failure by simply not committing.
        let mut state = PortState::after_reset();
        let pending = state.with_pin(Port::Output, 2, true).unwrap();
        assert_eq!(pending, 0b0000_0100);
        // Bus said no. Nothing is recorded.
        assert_eq!(state.get(Port::Output), 0);
        // The next write must therefore still compute from 0, not from 0b100.
        let next = state.with_pin(Port::Output, 1, true).unwrap();
        assert_eq!(
            next, 0b0000_0010,
            "a write that failed must not leak into the next mask"
        );
        state.commit(Port::Output, next);
        assert_eq!(state.get(Port::Output), 0b0000_0010);
    }

    #[test]
    fn setting_one_pin_preserves_the_other_seven() {
        let mut state = PortState::after_reset();
        for pin in 0..=MAX_PIN {
            let v = state.with_pin(Port::Direction, pin, true).unwrap();
            state.commit(Port::Direction, v);
        }
        assert_eq!(state.get(Port::Direction), 0xFF);

        let v = state.with_pin(Port::Direction, 3, false).unwrap();
        state.commit(Port::Direction, v);
        assert_eq!(
            state.get(Port::Direction),
            0b1111_0111,
            "clearing pin 3 must not disturb any other pin"
        );
    }

    #[test]
    fn the_shadow_starts_where_the_part_starts_after_a_reset() {
        // If this drifted, the very first single-pin write would send seven
        // invented bits to a part whose real state is all zeroes.
        let state = PortState::after_reset();
        for port in [
            Port::Direction,
            Port::Output,
            Port::PullEnable,
            Port::PullSelect,
        ] {
            assert_eq!(state.get(port), 0, "{port:?} must start cleared");
        }
        assert_eq!(PortState::default(), PortState::after_reset());
    }

    #[test]
    fn ports_map_to_their_own_registers() {
        assert_eq!(Port::Direction.register(), reg::DIRECTION);
        assert_eq!(Port::Output.register(), reg::OUTPUT_STATE);
        assert_eq!(Port::PullEnable.register(), reg::PULL_ENABLE);
        assert_eq!(Port::PullSelect.register(), reg::PULL_SELECT);
        // No two ports may share a register — a collision would make one port's
        // shadow silently overwrite the other's on the wire.
        let regs = [
            Port::Direction.register(),
            Port::Output.register(),
            Port::PullEnable.register(),
            Port::PullSelect.register(),
        ];
        for (i, a) in regs.iter().enumerate() {
            for b in &regs[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn a_pull_up_selects_before_it_enables() {
        assert_eq!(PULL_UP_WRITE_ORDER, [Port::PullSelect, Port::PullEnable]);
    }

    // ── Strap decoding ────────────────────────────────────────────────────────

    #[test]
    fn the_can_slave_strap_is_active_low() {
        // DIP pulls to GND on a slave; the pull-up holds it high on a master.
        let slave = 0x00;
        let master = 1 << q_series::CAN_SLAVE_DETECT;
        assert_eq!(is_can_slave(slave), Ok(true));
        assert_eq!(is_can_slave(master), Ok(false));
    }

    #[test]
    fn the_strap_reads_only_its_own_pin() {
        // Every other pin high, the strap low: still a slave.
        let status = !(1u8 << q_series::CAN_SLAVE_DETECT);
        assert_eq!(is_can_slave(status), Ok(true));
    }

    #[test]
    fn pin_level_decodes_each_bit_independently() {
        let status = 0b1010_1010;
        for pin in 0..=MAX_PIN {
            assert_eq!(pin_level(status, pin), Ok(pin % 2 == 1), "pin {pin}");
        }
        assert_eq!(
            pin_level(status, 8),
            Err(Fxl6408ConfigError::PinOutOfRange(8))
        );
    }

    #[test]
    fn direction_readback_reflects_committed_writes_only() {
        let mut state = PortState::after_reset();
        assert_eq!(state.is_output(q_series::VREG_ENABLE), Ok(false));
        let v = state
            .with_pin(Port::Direction, q_series::VREG_ENABLE, true)
            .unwrap();
        assert_eq!(
            state.is_output(q_series::VREG_ENABLE),
            Ok(false),
            "uncommitted write must not appear as configured"
        );
        state.commit(Port::Direction, v);
        assert_eq!(state.is_output(q_series::VREG_ENABLE), Ok(true));
    }
}
