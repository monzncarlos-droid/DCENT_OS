//! Host-pure PCA9544A I2C bus-multiplexer channel control.
//!
//! The espidf transport is a thin write/read of one control byte; everything a
//! host test can execute lives here. Same split as
//! `tmp451_convert.rs`/`tmp451.rs` and `fxl6408_convert.rs`.
//!
//! # Why this part matters
//!
//! This is the first board in the registry that needs a **bus** multiplexer.
//! Every I2C part we drive today sits at a fixed address on one flat bus; the
//! BitForge Nano carries two EMC2101s, and the EMC2101's address is hard-wired,
//! so the only way to reach either one is to select a PCA9544A channel first.
//!
//! That makes the channel select part of the *thermal* path, not part of the
//! bus plumbing. If a select fails and the caller reads anyway, it gets the
//! previously-selected ASIC's die temperature and attributes it to the other
//! ASIC — a thermal-supervision lie of exactly the kind
//! `board::has_trusted_thermal_source_configured` exists to prevent. Everything
//! in this module is shaped to make that outcome inexpressible.
//!
//! The NerdOCTAXE-gamma's twin TMP451s are the same fixed-address collision
//! solved a different way — an *analog* mux on two GPIO select lines, see
//! [`tmp451_convert::mux_levels`](crate::tmp451_convert::mux_levels). This is
//! the I2C-bus form of that problem, so it is built as a reusable part driver
//! rather than as a BitForge branch.
//!
//! # Evidence
//!
//! Two INDEPENDENT sources for the same board, which is the strongest evidence
//! position we have had for any third-party ESP board:
//!
//! * /PAC9544.{c,h}`
//!   — the vendor firmware (filename is typo'd; the contents and the datasheet
//!   link are PCA9544A). Gives address 0x70 and the `0x4 | channel` control
//!   byte encoding.
//! *  — the CERN-OHL-S
//!   schematic. `Fan.kicad_sch` instantiates `PCA9544APW` (NXP), and the PCB
//!   netlist ties **A0/A1/A2 all to GND**, independently confirming 0x70 rather
//!   than taking the firmware constant on trust.
//!
//! The schematic also confirms the **channel assignment**: the live downstream
//! nets are `SC2`/`SD2` and `SC3`/`SD3`, carrying `FAN_1_*` and `FAN_2_*`
//! respectively. So the two EMC2101s are on channels **2 and 3**, not 0 and 1 —
//! matching every `PAC9544_selectChannel(2)` / `(3)` call site in the firmware.
//! Channels 0 and 1 are brought out but unused.
//!
//! # Deliberate divergences from the upstream C
//!
//! Four, each pinned by a test below. The first three are defects in shipped
//! firmware; the fourth is a transport detail our shim must not copy.
//!
//! 1. **Out-of-range channels are rejected, not masked.**
//!    `PAC9544_selectChannel` computes `0x4 | channel` with no validation, so
//!    `channel = 4` silently selects channel **0** and `channel = 7` selects
//!    **3**. On a board where the channel decides which ASIC's die you are
//!    reading, an out-of-range select does not fail — it reads the wrong ASIC
//!    and reports the number as the requested ASIC's temperature.
//!    [`control_byte_for_channel`] returns `Err` instead.
//!
//! 2. **"Disabled" is a first-class state, not an underflow.**
//!    `PAC9544_get_selected_channel` returns `(status & 0x0F) - 0x4`, which is
//!    correct only while the enable bit is set. With the mux disabled it
//!    underflows a `uint8_t` to 252..255 — so a disabled mux reports a
//!    plausible-looking integer rather than an error, and there is no distinct
//!    "nothing selected" value at all. [`MuxState`] models it as a variant.
//!
//! 3. **A failed select must stop the transaction.** All 11 upstream call sites
//!    discard the return value (`self_test.c`, `power_management_task.c`,
//!    `ThermalMonitoring.c` — every one is a bare `PAC9544_selectChannel(2);`),
//!    and `Thermal_getAsicChipTemp` does not select at all: it reads whichever
//!    channel happens to be live. [`select`] returns a [`Selection`] that the
//!    caller must hold to proceed, and [`Selection::confirm`] makes the
//!    readback check mandatory rather than optional.
//!
//! 4. **The control write is ONE byte.** The PCA9544A has no register pointer —
//!    the byte after the address IS the control register. Upstream routes the
//!    write through `i2c_bitforge_register_write_byte`, which transmits
//!    `{0x00, control}` (`i2c_bitforge.c:137`), so every channel select is
//!    preceded by a spurious `0x00` — a mux **disable**. The part latches the
//!    later byte so it works in practice, but our shim must send exactly
//!    [`CONTROL_WRITE_LEN`] byte. See [`Selection::control_byte`].
//!
//! # Verify, do not remember
//!
//! Unlike the FXL6408's write-only shadow registers
//! ([`fxl6408_convert`](crate::fxl6408_convert)), this part's control register
//! reads back. There is therefore no reason to cache which channel we believe
//! is live: [`MuxState::from_readback`] decodes the truth off the wire, and
//! [`Selection::confirm`] compares it against what was asked for. A driver that
//! remembers can be wrong; one that verifies cannot.

/// Base 7-bit address with all three strap pins low.
///
/// Confirmed twice: `PAC9544_ADDR` in the vendor firmware, and A0/A1/A2 tied to
/// GND in the BitForge Nano PCB netlist.
pub const BASE_ADDRESS: u8 = 0x70;

/// Number of downstream channels this part multiplexes.
pub const CHANNEL_COUNT: u8 = 4;

/// Highest addressable channel.
pub const MAX_CHANNEL: u8 = CHANNEL_COUNT - 1;

/// Control-register bit that enables the selected channel.
///
/// With this bit clear no downstream channel is connected, whatever the channel
/// bits say.
pub const CONTROL_ENABLE: u8 = 0x04;

/// Control-register bits holding the channel number.
pub const CONTROL_CHANNEL_MASK: u8 = 0x03;

/// Control byte that disconnects every downstream channel.
pub const DISABLE_CONTROL_BYTE: u8 = 0x00;

/// Bit position of the interrupt-flag nibble in a control-register readback.
///
/// Bits 4..=7 are `INT0`..=`INT3`, one per downstream channel. They are read
/// only and must never be interpreted as part of the channel number.
pub const CONTROL_INTERRUPT_SHIFT: u8 = 4;

/// Length in bytes of a control-register write.
///
/// The part has no register pointer. See divergence 4 in the module docs.
pub const CONTROL_WRITE_LEN: usize = 1;

/// Settling delay after a channel switch, in milliseconds.
///
/// Upstream's value: every `PAC9544_selectChannel` call site is followed by
/// `vTaskDelay(pdMS_TO_TICKS(10))` with the comment "Allow PAC9544 channel
/// switch to settle".
pub const SETTLE_AFTER_SELECT_MS: u32 = 10;

/// Errors from addressing, selecting, or verifying the multiplexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pca9544Error {
    /// Channel above [`MAX_CHANNEL`]. Upstream would have masked this into a
    /// valid-looking channel; see divergence 1.
    ChannelOutOfRange(u8),
    /// Strap index above 2, or a computed address outside the usable 7-bit
    /// space.
    AddressReserved(u8),
    /// The readback says no channel is connected, but one was requested.
    NotSelected {
        /// Channel the caller asked for.
        expected: u8,
    },
    /// The readback says a different channel is live than the one requested.
    ///
    /// This is the thermal-misattribution case: proceeding here would read the
    /// wrong ASIC's die and label it with the requested ASIC's identity.
    WrongChannel {
        /// Channel the caller asked for.
        expected: u8,
        /// Channel the part reports as live.
        actual: u8,
    },
}

impl core::fmt::Display for Pca9544Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelOutOfRange(c) => {
                write!(f, "mux channel {c} exceeds {MAX_CHANNEL}")
            }
            Self::AddressReserved(a) => {
                write!(f, "0x{a:02X} is not a usable PCA9544A address")
            }
            Self::NotSelected { expected } => {
                write!(f, "mux reports no channel connected, expected {expected}")
            }
            Self::WrongChannel { expected, actual } => {
                write!(f, "mux reports channel {actual} live, expected {expected}")
            }
        }
    }
}

/// Which downstream channel, if any, is connected to the upstream bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxState {
    /// No channel connected. A distinct state, never an integer — see
    /// divergence 2 in the module docs.
    Disabled,
    /// The given channel is connected to the upstream bus.
    Channel(u8),
}

impl MuxState {
    /// Control byte that puts the part into this state.
    pub fn control_byte(self) -> u8 {
        match self {
            Self::Disabled => DISABLE_CONTROL_BYTE,
            Self::Channel(c) => CONTROL_ENABLE | (c & CONTROL_CHANNEL_MASK),
        }
    }

    /// Decode a control-register readback.
    ///
    /// Masks the interrupt nibble off before looking at the channel bits, so a
    /// pending interrupt can never be read as a channel number. Cannot fail and
    /// cannot underflow: the enable bit decides the variant.
    pub fn from_readback(status: u8) -> Self {
        if status & CONTROL_ENABLE == 0 {
            Self::Disabled
        } else {
            Self::Channel(status & CONTROL_CHANNEL_MASK)
        }
    }

    /// The live channel, or `None` when the mux is disabled.
    pub fn channel(self) -> Option<u8> {
        match self {
            Self::Disabled => None,
            Self::Channel(c) => Some(c),
        }
    }
}

/// 7-bit address for the given strap pin levels.
///
/// `A0` is the LSB. The BitForge Nano grounds all three, giving
/// [`BASE_ADDRESS`].
pub fn address_for_straps(a0: bool, a1: bool, a2: bool) -> u8 {
    BASE_ADDRESS | (a0 as u8) | ((a1 as u8) << 1) | ((a2 as u8) << 2)
}

/// True when `addr` is an address this part can actually be strapped to.
///
/// The PCA9544A occupies 0x70..=0x77. Deliberately narrower than the generic
/// 7-bit check in [`tmp451_convert`](crate::tmp451_convert): a floating bus
/// reading back 0x00 or 0xFF cannot be mistaken for this part, and neither can
/// a temperature sensor at 0x4C.
pub fn is_plausible_address(addr: u8) -> bool {
    (BASE_ADDRESS..=BASE_ADDRESS | 0x07).contains(&addr)
}

/// Control byte that selects `channel`, or an error if it is out of range.
///
/// Rejects rather than masks — see divergence 1 in the module docs.
pub fn control_byte_for_channel(channel: u8) -> Result<u8, Pca9544Error> {
    if channel > MAX_CHANNEL {
        return Err(Pca9544Error::ChannelOutOfRange(channel));
    }
    Ok(MuxState::Channel(channel).control_byte())
}

/// Per-channel interrupt flags from a control-register readback.
///
/// Index 0 is `INT0`. These are informational: the part asserts them from the
/// downstream devices regardless of which channel is currently connected.
pub fn interrupt_flags(status: u8) -> [bool; CHANNEL_COUNT as usize] {
    let nibble = status >> CONTROL_INTERRUPT_SHIFT;
    [
        nibble & 0x1 != 0,
        nibble & 0x2 != 0,
        nibble & 0x4 != 0,
        nibble & 0x8 != 0,
    ]
}

/// A channel select that has been validated but not yet confirmed on the wire.
///
/// Holding one of these is the only way to name a channel for a downstream
/// transaction, and [`confirm`](Selection::confirm) is the only way to discharge
/// it. That is what makes upstream's "select, ignore the result, read anyway"
/// shape inexpressible here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    channel: u8,
    control_byte: u8,
}

impl Selection {
    /// The validated channel number.
    pub fn channel(&self) -> u8 {
        self.channel
    }

    /// The single byte to transmit. Exactly [`CONTROL_WRITE_LEN`] byte long —
    /// no register-pointer prefix; see divergence 4 in the module docs.
    pub fn control_byte(&self) -> u8 {
        self.control_byte
    }

    /// Milliseconds to wait after the write before transacting downstream.
    pub fn settle_ms(&self) -> u32 {
        SETTLE_AFTER_SELECT_MS
    }

    /// Check a control-register readback against what was requested.
    ///
    /// Must be called before any downstream transaction. A disabled mux and a
    /// wrong live channel are distinct errors so a caller (or a log) can tell
    /// "the select never landed" from "something else moved the mux".
    pub fn confirm(&self, readback: u8) -> Result<(), Pca9544Error> {
        match MuxState::from_readback(readback) {
            MuxState::Disabled => Err(Pca9544Error::NotSelected {
                expected: self.channel,
            }),
            MuxState::Channel(actual) if actual == self.channel => Ok(()),
            MuxState::Channel(actual) => Err(Pca9544Error::WrongChannel {
                expected: self.channel,
                actual,
            }),
        }
    }
}

/// Validate `channel` and produce the [`Selection`] needed to reach it.
pub fn select(channel: u8) -> Result<Selection, Pca9544Error> {
    Ok(Selection {
        channel,
        control_byte: control_byte_for_channel(channel)?,
    })
}

/// Control byte that disconnects every downstream channel.
pub fn disable() -> u8 {
    MuxState::Disabled.control_byte()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── address ─────────────────────────────────────────────────────────────

    #[test]
    fn all_straps_grounded_is_the_bitforge_nano_address() {
        // PCB netlist: A0/A1/A2 -> GND. Firmware: PAC9544_ADDR 0x70.
        assert_eq!(address_for_straps(false, false, false), 0x70);
        assert_eq!(address_for_straps(false, false, false), BASE_ADDRESS);
    }

    #[test]
    fn straps_walk_the_eight_addresses_with_a0_as_lsb() {
        assert_eq!(address_for_straps(true, false, false), 0x71);
        assert_eq!(address_for_straps(false, true, false), 0x72);
        assert_eq!(address_for_straps(false, false, true), 0x74);
        assert_eq!(address_for_straps(true, true, true), 0x77);
    }

    #[test]
    fn only_the_parts_own_address_block_is_plausible() {
        for addr in 0x70..=0x77u8 {
            assert!(is_plausible_address(addr), "0x{addr:02X} should be valid");
        }
        // A floating bus, and the EMC2101 this part multiplexes.
        for addr in [0x00u8, 0x4C, 0x4E, 0x6F, 0x78, 0xFF] {
            assert!(
                !is_plausible_address(addr),
                "0x{addr:02X} should be refused"
            );
        }
    }

    // ── channel encoding ────────────────────────────────────────────────────

    #[test]
    fn each_channel_encodes_as_enable_plus_its_number() {
        assert_eq!(control_byte_for_channel(0), Ok(0x04));
        assert_eq!(control_byte_for_channel(1), Ok(0x05));
        assert_eq!(control_byte_for_channel(2), Ok(0x06));
        assert_eq!(control_byte_for_channel(3), Ok(0x07));
    }

    #[test]
    fn the_two_emc2101_channels_are_2_and_3() {
        // Schematic: SC2/SD2 carries FAN_1_*, SC3/SD3 carries FAN_2_*.
        // Firmware: every call site is selectChannel(2) or selectChannel(3).
        assert_eq!(control_byte_for_channel(2), Ok(0x06));
        assert_eq!(control_byte_for_channel(3), Ok(0x07));
    }

    /// Divergence 1: upstream masks, we reject.
    #[test]
    fn an_out_of_range_channel_is_refused_not_masked_into_a_valid_one() {
        for bad in [4u8, 5, 6, 7, 8, 100, 255] {
            assert_eq!(
                control_byte_for_channel(bad),
                Err(Pca9544Error::ChannelOutOfRange(bad)),
                "channel {bad} must be refused"
            );
            assert_eq!(select(bad), Err(Pca9544Error::ChannelOutOfRange(bad)));
        }
    }

    /// The specific upstream failure the rejection above prevents: `0x4 |
    /// channel` turns 4 into channel 0 and 7 into channel 3, so an out-of-range
    /// request silently reads a DIFFERENT ASIC's die and reports it under the
    /// requested ASIC's name.
    #[test]
    fn the_upstream_mask_would_have_aliased_bad_channels_onto_real_ones() {
        let upstream_encode = |channel: u8| CONTROL_ENABLE | channel;
        assert_eq!(
            MuxState::from_readback(upstream_encode(4)),
            MuxState::Channel(0),
            "upstream would alias channel 4 onto channel 0"
        );
        assert_eq!(
            MuxState::from_readback(upstream_encode(7)),
            MuxState::Channel(3),
            "upstream would alias channel 7 onto channel 3"
        );
        // Ours never produces those bytes in the first place.
        assert!(control_byte_for_channel(4).is_err());
        assert!(control_byte_for_channel(7).is_err());
    }

    // ── readback decode ─────────────────────────────────────────────────────

    #[test]
    fn readback_roundtrips_every_valid_channel() {
        for ch in 0..=MAX_CHANNEL {
            let byte = control_byte_for_channel(ch).unwrap();
            assert_eq!(MuxState::from_readback(byte), MuxState::Channel(ch));
            assert_eq!(MuxState::from_readback(byte).channel(), Some(ch));
        }
    }

    /// Divergence 2: upstream's `(status & 0x0F) - 0x4` underflows on a
    /// disabled mux and reports 252, a plausible-looking integer. We report a
    /// state.
    #[test]
    fn a_disabled_mux_decodes_to_disabled_and_never_to_an_integer() {
        assert_eq!(MuxState::from_readback(0x00), MuxState::Disabled);
        assert_eq!(MuxState::from_readback(0x00).channel(), None);
        assert_eq!(disable(), 0x00);

        // The upstream expression, evaluated on the same byte.
        let upstream = ((0x00u8 & 0x0F) as u8).wrapping_sub(0x04);
        assert_eq!(upstream, 252, "upstream underflows to a fake channel");
        assert_ne!(
            MuxState::from_readback(0x00),
            MuxState::Channel(upstream & CONTROL_CHANNEL_MASK)
        );
    }

    #[test]
    fn channel_bits_are_ignored_while_the_enable_bit_is_clear() {
        // 0x03 has channel bits set but no enable bit: nothing is connected.
        assert_eq!(MuxState::from_readback(0x03), MuxState::Disabled);
    }

    #[test]
    fn a_pending_interrupt_is_never_read_as_a_channel_number() {
        // All four interrupt flags set, channel 2 live.
        let status = 0xF0 | CONTROL_ENABLE | 2;
        assert_eq!(MuxState::from_readback(status), MuxState::Channel(2));
        assert_eq!(interrupt_flags(status), [true, true, true, true]);
    }

    #[test]
    fn interrupt_flags_map_int0_to_index_zero() {
        assert_eq!(interrupt_flags(0x10), [true, false, false, false]);
        assert_eq!(interrupt_flags(0x20), [false, true, false, false]);
        assert_eq!(interrupt_flags(0x40), [false, false, true, false]);
        assert_eq!(interrupt_flags(0x80), [false, false, false, true]);
        assert_eq!(interrupt_flags(0x00), [false; 4]);
        // Channel/enable bits must not leak into the flags.
        assert_eq!(interrupt_flags(0x07), [false; 4]);
    }

    // ── the select/confirm contract ─────────────────────────────────────────

    #[test]
    fn a_confirmed_select_matches_its_own_control_byte() {
        for ch in 0..=MAX_CHANNEL {
            let sel = select(ch).unwrap();
            assert_eq!(sel.channel(), ch);
            assert_eq!(sel.confirm(sel.control_byte()), Ok(()));
        }
    }

    /// Divergence 3, the thermal-misattribution case. This is the exact live
    /// failure in shipped firmware: the select does not land, the mux stays on
    /// the previous ASIC, and the read is attributed to the requested one.
    #[test]
    fn confirm_refuses_a_readback_naming_a_different_asic() {
        let sel = select(3).unwrap();
        let still_on_channel_2 = control_byte_for_channel(2).unwrap();
        assert_eq!(
            sel.confirm(still_on_channel_2),
            Err(Pca9544Error::WrongChannel {
                expected: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn confirm_distinguishes_a_dead_mux_from_a_moved_one() {
        let sel = select(2).unwrap();
        assert_eq!(
            sel.confirm(DISABLE_CONTROL_BYTE),
            Err(Pca9544Error::NotSelected { expected: 2 })
        );
        assert!(matches!(
            sel.confirm(control_byte_for_channel(3).unwrap()),
            Err(Pca9544Error::WrongChannel { .. })
        ));
    }

    #[test]
    fn confirm_ignores_interrupt_flags_riding_along_with_a_good_channel() {
        let sel = select(2).unwrap();
        assert_eq!(sel.confirm(0xF0 | sel.control_byte()), Ok(()));
    }

    // ── transport shape ─────────────────────────────────────────────────────

    /// Divergence 4: the part has no register pointer. Upstream's helper
    /// transmits `{0x00, control}`, so every select is preceded by a spurious
    /// mux-disable byte.
    #[test]
    fn the_control_write_is_a_single_byte_with_no_register_prefix() {
        assert_eq!(CONTROL_WRITE_LEN, 1);
        let sel = select(2).unwrap();
        let frame = [sel.control_byte()];
        assert_eq!(frame.len(), CONTROL_WRITE_LEN);
        // The byte upstream sends first would disable the mux outright.
        assert_eq!(MuxState::from_readback(0x00), MuxState::Disabled);
    }

    #[test]
    fn the_settling_delay_matches_the_vendor_firmware() {
        assert_eq!(SETTLE_AFTER_SELECT_MS, 10);
        assert_eq!(select(2).unwrap().settle_ms(), SETTLE_AFTER_SELECT_MS);
    }

    #[test]
    fn errors_render_without_panicking() {
        let rendered = [
            Pca9544Error::ChannelOutOfRange(9),
            Pca9544Error::AddressReserved(0x4C),
            Pca9544Error::NotSelected { expected: 2 },
            Pca9544Error::WrongChannel {
                expected: 3,
                actual: 2,
            },
        ]
        .iter()
        .map(|e| alloc_display(e))
        .collect::<Vec<_>>();
        for text in rendered {
            assert!(!text.is_empty());
        }
    }

    fn alloc_display(e: &Pca9544Error) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        write!(&mut s, "{e}").unwrap();
        s
    }
}
