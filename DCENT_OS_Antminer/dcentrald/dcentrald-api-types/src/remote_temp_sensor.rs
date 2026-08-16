//! LM90-family remote-diode temperature sensor decoder (TMP451 / ADT7461 / NCT218).
//!
//! # Why
//!
//! Antminer hashboards read chip temperature through a remote-diode sensor on the
//! board, reachable via the BM1387 register-`0x20` I²C passthrough (S9) or a direct
//! I²C bus. DCENT knew *which* sensor each board carries (catalog metadata) but had no
//! decoder to turn the raw register bytes into a temperature — so S9 board-temp fell
//! back to the Zynq XADC die temp. This module supplies that decode as pure logic.
//!
//! # Register family
//!
//! TMP451 (TI), ADT7461/ADT7461A (Analog Devices), and NCT218 (ON Semi) are all
//! register-compatible members of the classic **LM90 / ADM1032** remote-diode family.
//! The subset this decoder uses is identical across all three:
//!
//! | Reg  | Meaning                              |
//! |------|--------------------------------------|
//! | 0x00 | Local temperature (signed °C)        |
//! | 0x01 | Remote temperature, high byte (°C)   |
//! | 0x10 | Remote temperature, low byte (frac)  |
//! | 0xFE | Manufacturer ID                      |
//! | 0xFF | Die revision / device ID             |
//!
//! Manufacturer IDs (from  hardware reference, corroborating the datasheets):
//! **TI `0x55`, Analog Devices `0x41`, ON Semi `0x1A`**.
//!
//! # Deliberate conservatism
//!
//! - Temperatures are decoded in the **standard two's-complement** mode. LM90-family
//!   parts also have an *extended* (offset-binary, +64 °C) mode selected by the RANGE
//!   bit of Configuration Register 1. Decoding extended-mode bytes with the standard
//!   decoder is wrong by exactly 64 °C on a thermal-safety path, so safety-path
//!   callers MUST read the config register (address via [`config_register_for`]) and
//!   use [`decode_reading_checked`], which **refuses** (returns `None`) when the
//!   RANGE bit is set. No compensation is ever attempted — a wrong mode guess in the
//!   under-read direction defeats thermal throttling entirely. The raw
//!   [`decode_reading`] stays available for non-safety byte inspection only.
//! - The remote **low** byte carries fractional bits in `[7:5]` (0.125 °C/LSB); the
//!   lower bits are undefined and masked off.
//! - An unrecognized manufacturer ID yields [`SensorModel::Unknown`] but still decodes
//!   temperatures (the LM90 register layout is what matters, not the vendor) — the model
//!   is advisory. A caller must keep the existing die-temp fallback: a failed/implausible
//!   board-temp read must never by itself trigger an emergency shutdown.
//!
//! Pure, host-testable, no HAL/IO.

/// Which LM90-family part answered, by manufacturer-ID byte (register `0xFE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorModel {
    /// TI `0x55` — TMP451.
    Tmp451,
    /// Analog Devices `0x41` — ADT7461 / ADT7461A.
    Adt7461,
    /// ON Semi `0x1A` — NCT218.
    Nct218,
    /// Unrecognized manufacturer ID (temperatures still decode; model is advisory).
    Unknown { manufacturer_id: u8 },
}

/// LM90-family register addresses used by this decoder.
pub mod reg {
    pub const LOCAL_TEMP: u8 = 0x00;
    pub const REMOTE_TEMP_HIGH: u8 = 0x01;
    /// Configuration Register 1, classic LM90 **read** pointer (the write pointer
    /// is 0x09). Carries the RANGE (extended-mode) bit — see
    /// [`super::CONFIG_EXTENDED_RANGE_MASK`]. Applies to TMP451/TMP461,
    /// ADT7461/ADT7461A, NCT72/NCT1008, NCT218/NCT214 (Linux drivers/hwmon/lm90.c +
    /// tmp401.c, datasheet-corroborated). Does NOT apply to TMP42x — use the
    /// register named by [`TMP42X_CONFIG_1`] there (selection helper:
    /// [`super::config_register_for`]).
    pub const CONFIG_READ: u8 = 0x03;
    /// TMP421/422/423 Configuration Register 1. The TMP42x family does NOT use
    /// the LM90 split read/write pointer convention: config 1 is at pointer 0x09
    /// for both read and write, and pointer 0x03 is undocumented (Linux
    /// drivers/hwmon/tmp421.c `TMP421_CONFIG_REG_1`, TI TMP421 datasheet). This
    /// matters in production: AMTC jig intel pins the plain S9 board sensor as
    /// TMP421, so reading 0x03 there would refuse board temp on every S9.
    pub const TMP42X_CONFIG_1: u8 = 0x09;
    pub const REMOTE_TEMP_LOW: u8 = 0x10;
    pub const MANUFACTURER_ID: u8 = 0xFE;
    pub const DEVICE_ID: u8 = 0xFF;
}

/// Manufacturer-ID byte values (register `0xFE`).
pub const MFR_ID_TI: u8 = 0x55;
pub const MFR_ID_ANALOG_DEVICES: u8 = 0x41;
pub const MFR_ID_ON_SEMI: u8 = 0x1A;

/// Identify the sensor model from the manufacturer-ID byte.
pub const fn model_from_manufacturer_id(manufacturer_id: u8) -> SensorModel {
    match manufacturer_id {
        MFR_ID_TI => SensorModel::Tmp451,
        MFR_ID_ANALOG_DEVICES => SensorModel::Adt7461,
        MFR_ID_ON_SEMI => SensorModel::Nct218,
        other => SensorModel::Unknown {
            manufacturer_id: other,
        },
    }
}

/// A decoded remote-diode sensor reading.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RemoteTempReading {
    pub model: SensorModel,
    /// Local (sensor-die) temperature, °C. Signed, 1 °C resolution.
    pub local_c: i8,
    /// Remote (ASIC-diode) temperature, °C, with the 0.125 °C fractional part folded in.
    pub remote_c: f32,
}

/// Decode a local temperature byte (register `0x00`), standard two's-complement mode.
pub const fn decode_local_temp(byte: u8) -> i8 {
    byte as i8
}

/// Decode remote temperature from the high (`0x01`) and low (`0x10`) bytes.
///
/// High byte is signed °C; the low byte's top three bits are 0.125 °C/LSB fractional.
pub fn decode_remote_temp(high: u8, low: u8) -> f32 {
    let whole = high as i8 as f32;
    // Fraction lives in bits [7:5]; each step is 0.125 °C.
    let eighths = (low >> 5) & 0x07;
    let frac = eighths as f32 * 0.125;
    // For negative whole temps the fraction still adds toward zero magnitude in the
    // LM90 encoding (the high byte is the two's-complement integer part, the low byte
    // is an unsigned fraction added to it).
    whole + frac
}

/// Decode a full reading from the four register bytes.
///
/// `manufacturer_id` = reg `0xFE`, `local` = reg `0x00`, `remote_high` = reg `0x01`,
/// `remote_low` = reg `0x10`. All reads are the caller's responsibility (HAL); this is
/// pure decode.
pub fn decode_reading(
    manufacturer_id: u8,
    local: u8,
    remote_high: u8,
    remote_low: u8,
) -> RemoteTempReading {
    RemoteTempReading {
        model: model_from_manufacturer_id(manufacturer_id),
        local_c: decode_local_temp(local),
        remote_c: decode_remote_temp(remote_high, remote_low),
    }
}

/// Plausibility bound: a hashboard remote-diode reading outside this range is almost
/// certainly a bus error or an unpowered sensor, and the caller must fall back to the
/// die-temp path rather than trust it (never emergency-shutdown on an implausible board
/// temp alone). Not a safety limit — a sanity filter.
pub const PLAUSIBLE_REMOTE_C: core::ops::RangeInclusive<f32> = -40.0..=150.0;

impl RemoteTempReading {
    /// Whether the remote reading is within the plausible sanity window.
    pub fn remote_is_plausible(&self) -> bool {
        PLAUSIBLE_REMOTE_C.contains(&self.remote_c)
    }
}

// --- Device-ID (register 0xFF) refinement — item C6-3b -----------------------------
//
// `model_from_manufacturer_id` maps by manufacturer ID (0xFE) alone, so every TI part
// collapses to `Tmp451`, every ADI part to `Adt7461`, every ON Semi part to `Nct218`.
// This refinement disambiguates the concrete part using the device-ID byte (register
// 0xFF). It is PURE labelling: `decode_reading` still decodes temperature regardless, and
// unrecognized IDs fall through to `UnknownForVendor`/`Unknown` (temperatures still
// decode; the die-temp fallback is never gated on the label). NOTHING here is wired into a
// board-temp read or thermal-control path.
//
// Provenance:
//   * TMP42x 0x21/0x22/0x23  — IN-REPO:
//     :118-121 (BraiinsOS), corroborated by TI datasheets.
//   * TMP401/411A/411B/411C/431/432/435 — Linux drivers/hwmon/tmp401.c (#define
//     TMP*_DEVICE_ID), datasheet-sourced.
//   * TMP451/TMP461 = 0x00 — Linux drivers/hwmon/lm90.c + TI datasheet; these two are NOT
//     distinguishable by 0xFF (address-only) -> Tmp451Or461.
//   * ADT7461 0x51, ADT7461A 0x57, NCT72 (mfr 0x41, dev 0x55), NCT1008 0x54, NCT218
//     (mfr 0x1A) 0xCA, NCT214 0x5A, NCT210 0x3F — Linux drivers/hwmon/lm90.c, datasheet.
//   NOTE: NCT72 reports the Analog-Devices manufacturer ID 0x41 (not 0x1A) — it is an
//   ADT7461A-compatible part, so the coarse model would mislabel it ADT7461; this
//   refinement corrects it. ECT218 (AMTC #5) has NO sourced 0xFF byte and is left
//   unresolved (UnknownForVendor) rather than guessed.
//   The held AMTC single_board_test jigs identify sensors by QR/config STRING and hardcode
//   an I2C address; they never read 0xFF, so no jig-verified 0xFF constants exist for these
//   parts (the above are datasheet/Linux-driver-sourced, except the in-repo TMP42x bytes).

/// Device-ID (register `0xFF`) byte constants, grouped by manufacturer.
pub mod dev_id {
    // TI (manufacturer 0x55)
    pub const TMP401: u8 = 0x11;
    pub const TMP411A: u8 = 0x12;
    pub const TMP411B: u8 = 0x13;
    pub const TMP411C: u8 = 0x10;
    pub const TMP431: u8 = 0x31; // also TMP431A / TMP431B (address-distinguished)
    pub const TMP432: u8 = 0x32;
    pub const TMP435: u8 = 0x35;
    pub const TMP451_OR_461: u8 = 0x00; // TMP451 and TMP461 share this ID
    pub const TMP421: u8 = 0x21;
    pub const TMP422: u8 = 0x22;
    pub const TMP423: u8 = 0x23;
    // Analog Devices (manufacturer 0x41)
    pub const ADT7461: u8 = 0x51;
    pub const ADT7461A: u8 = 0x57;
    pub const NCT72: u8 = 0x55; // ADT7461A-compatible, reports ADI mfr 0x41
    pub const NCT1008: u8 = 0x54;
    // ON Semi (manufacturer 0x1A)
    pub const NCT218: u8 = 0xCA;
    pub const NCT214: u8 = 0x5A;
    pub const NCT210: u8 = 0x3F;
}

/// Concrete LM90-family part identified from BOTH ID bytes (0xFE manufacturer + 0xFF
/// device). Advisory only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorPart {
    // TI (mfr 0x55)
    Tmp401,
    Tmp411a,
    Tmp411b,
    Tmp411c,
    /// TMP431/TMP431A/TMP431B — `0xFF` cannot separate the address suffix.
    Tmp431Family,
    Tmp432,
    Tmp435,
    /// TMP421/422/423; `channels` = 1/2/3 (`device_id - 0x20`).
    Tmp42x {
        channels: u8,
    },
    /// `0xFF` cannot separate TMP451 from TMP461 (address-only).
    Tmp451Or461,
    // Analog Devices (mfr 0x41)
    Adt7461,
    Adt7461a,
    Nct72,
    Nct1008,
    // ON Semi (mfr 0x1A)
    Nct218,
    Nct214,
    Nct210,
    /// Known vendor, unrecognized device ID (e.g. ECT218, or a future revision).
    UnknownForVendor {
        manufacturer_id: u8,
        device_id: u8,
    },
    /// Unrecognized manufacturer ID entirely.
    Unknown {
        manufacturer_id: u8,
        device_id: u8,
    },
}

/// Refine the concrete part from the manufacturer ID (`0xFE`) and device ID (`0xFF`).
/// Pure; never performs I/O. Unmatched inputs yield an `Unknown*` variant — the caller
/// must still decode temperature via [`decode_reading`].
pub const fn refine_part(manufacturer_id: u8, device_id: u8) -> SensorPart {
    match manufacturer_id {
        MFR_ID_TI => match device_id {
            dev_id::TMP401 => SensorPart::Tmp401,
            dev_id::TMP411A => SensorPart::Tmp411a,
            dev_id::TMP411B => SensorPart::Tmp411b,
            dev_id::TMP411C => SensorPart::Tmp411c,
            dev_id::TMP431 => SensorPart::Tmp431Family,
            dev_id::TMP432 => SensorPart::Tmp432,
            dev_id::TMP435 => SensorPart::Tmp435,
            dev_id::TMP421 => SensorPart::Tmp42x { channels: 1 },
            dev_id::TMP422 => SensorPart::Tmp42x { channels: 2 },
            dev_id::TMP423 => SensorPart::Tmp42x { channels: 3 },
            dev_id::TMP451_OR_461 => SensorPart::Tmp451Or461,
            other => SensorPart::UnknownForVendor {
                manufacturer_id,
                device_id: other,
            },
        },
        MFR_ID_ANALOG_DEVICES => match device_id {
            dev_id::ADT7461 => SensorPart::Adt7461,
            dev_id::ADT7461A => SensorPart::Adt7461a,
            dev_id::NCT72 => SensorPart::Nct72,
            dev_id::NCT1008 => SensorPart::Nct1008,
            other => SensorPart::UnknownForVendor {
                manufacturer_id,
                device_id: other,
            },
        },
        MFR_ID_ON_SEMI => match device_id {
            dev_id::NCT218 => SensorPart::Nct218,
            dev_id::NCT214 => SensorPart::Nct214,
            dev_id::NCT210 => SensorPart::Nct210,
            // ECT218 (AMTC #5) lands here as UnknownForVendor — no sourced 0xFF byte.
            other => SensorPart::UnknownForVendor {
                manufacturer_id,
                device_id: other,
            },
        },
        other => SensorPart::Unknown {
            manufacturer_id: other,
            device_id,
        },
    }
}

/// Admit only a concrete part whose manufacturer/device tuple is present in
/// the supported registry above.
///
/// A known manufacturer is not sufficient: future or incompatible devices can
/// reuse the vendor ID while exposing a different register map. Runtime sensor
/// probes must use this helper before treating register bytes as thermal proof.
/// Unknown tuples return `None` and callers must retain their honest fallback.
pub const fn recognized_part(manufacturer_id: u8, device_id: u8) -> Option<SensorPart> {
    let part = refine_part(manufacturer_id, device_id);
    match part {
        SensorPart::UnknownForVendor { .. } | SensorPart::Unknown { .. } => None,
        _ => Some(part),
    }
}

/// Advisory human label for a refined part.
pub const fn refined_part_label(part: SensorPart) -> &'static str {
    match part {
        SensorPart::Tmp401 => "TMP401",
        SensorPart::Tmp411a => "TMP411A",
        SensorPart::Tmp411b => "TMP411B",
        SensorPart::Tmp411c => "TMP411C",
        SensorPart::Tmp431Family => "TMP431/TMP431B",
        SensorPart::Tmp432 => "TMP432",
        SensorPart::Tmp435 => "TMP435",
        SensorPart::Tmp42x { .. } => "TMP42x",
        SensorPart::Tmp451Or461 => "TMP451/TMP461",
        SensorPart::Adt7461 => "ADT7461",
        SensorPart::Adt7461a => "ADT7461A",
        SensorPart::Nct72 => "NCT72",
        SensorPart::Nct1008 => "NCT1008",
        SensorPart::Nct218 => "NCT218",
        SensorPart::Nct214 => "NCT214",
        SensorPart::Nct210 => "NCT210",
        SensorPart::UnknownForVendor { .. } => "unknown (known vendor)",
        SensorPart::Unknown { .. } => "unknown",
    }
}

// --- Extended-range (RANGE bit) refusal gate —  R10 ---------------------------
//
// LM90-family parts encode temperature in TWO selectable formats:
//
//   * standard mode (RANGE=0): two's-complement °C — what `decode_remote_temp`
//     and `decode_local_temp` implement;
//   * extended mode (RANGE=1): offset binary, register value = temperature + 64 °C,
//     covering roughly −64..+191 °C.
//
// Decoding extended-mode bytes with the standard decoder is wrong by exactly 64 °C.
// On a thermal-safety path a silent 64 °C error in the under-read direction reads
// "cold" while the die cooks and defeats throttling, so the ONLY safe behavior when
// the RANGE bit is set (or the config byte cannot be read) is to REFUSE the reading
// and let the caller fall back honestly (e.g. XADC die temp labelled
// `soc_die_fallback` by `thermal_model::assemble_chain_published_temp`). No
// compensation is attempted anywhere in this crate.
//
// RANGE bit provenance: bit 2 (mask 0x04) of Configuration Register 1 on
// TMP451/TMP461 (TI datasheet + Linux tmp401.c), ADT7461/ADT7461A/NCT72/NCT1008
// (Linux lm90.c `ADT7461` extended handling), NCT218/NCT214 (ON Semi datasheets,
// ADT7461-compatible), and TMP421/422/423 (TI datasheet + Linux tmp421.c). On parts
// without an extended mode (classic LM90/ADM1032) bit 2 is reserved-reads-0, so the
// gate degrades to a no-op instead of a false refusal.

/// RANGE / extended-range select bit in Configuration Register 1 (bit 2 on every
/// supported vendor): `0` = standard two's-complement, `1` = extended (+64 °C
/// offset binary — MUST be refused, see module docs).
pub const CONFIG_EXTENDED_RANGE_MASK: u8 = 0x04;

/// Whether a Configuration Register 1 byte declares extended (+64 °C offset
/// binary) range mode. When this returns `true`, the standard decoders in this
/// module are wrong by 64 °C and the reading MUST be refused, not compensated.
pub const fn is_extended_range(config: u8) -> bool {
    config & CONFIG_EXTENDED_RANGE_MASK != 0
}

/// Pick the Configuration Register 1 pointer for the identified part: TMP42x
/// keeps config at `0x09` for read+write; every other supported part follows the
/// classic LM90 convention (read at `0x03`). Reading `0x03` on a TMP42x is
/// undocumented and would spuriously refuse board temp on plain S9 boards
/// (AMTC: S9 = TMP421).
pub const fn config_register_for(manufacturer_id: u8, device_id: u8) -> u8 {
    match refine_part(manufacturer_id, device_id) {
        SensorPart::Tmp42x { .. } => reg::TMP42X_CONFIG_1,
        _ => reg::CONFIG_READ,
    }
}

/// Pick the remote-diode **fraction** (low-byte) pointer for the identified
/// part, or `None` when this module cannot decode one safely.
///
/// The classic LM90 convention puts the remote low byte at `0x10` with the
/// fraction in the upper 3 bits (0.125 °C/LSB) — that is what
/// [`reg::REMOTE_TEMP_LOW`] encodes. **TMP42x does not follow it.** On
/// TMP421/422/423 the map is `MSB(channel) = 0x00 + channel` and
/// `LSB(channel) = 0x10 + channel`, so `0x10` is the **local** channel's
/// fraction, not remote-1's. Pairing it with the remote MSB at `0x01` yields a
/// remote whole-degree value carrying the *local* channel's fraction — wrong by
/// up to ±0.875 °C on the part AMTC pins as the plain-S9 board sensor.
///
/// This returns `None` for TMP42x rather than `0x11`: remote-1's fraction there
/// is a 4-bit field (0.0625 °C/LSB) that this module's 3-bit decoders would
/// mis-scale. Callers degrade honestly to whole degrees (see
/// `missing_fraction_byte_degrades_to_whole_degrees`) — bounded loss under 1 °C,
/// never a fabricated value. Lifting this needs a TMP42x-specific decoder plus a
/// live capture to validate it against; do not guess the scaling on a thermal
/// path.
pub const fn remote_low_register_for(manufacturer_id: u8, device_id: u8) -> Option<u8> {
    match refine_part(manufacturer_id, device_id) {
        SensorPart::Tmp42x { .. } => None,
        _ => Some(reg::REMOTE_TEMP_LOW),
    }
}

/// Remote-temperature high byte latched on an open/faulted external diode:
/// `0x7F` (+127 °C). ADM1032-lineage parts report +127 with the OPEN status bit
/// on a broken TEMP_P/TEMP_N connection, and BraiinsOS' S9 sensor path treats
/// 127 as open-circuit/error. NOTE: +127 °C is *inside* [`PLAUSIBLE_REMOTE_C`],
/// so callers must reject this value explicitly before the plausibility window.
pub const REMOTE_OPEN_CIRCUIT_HIGH: u8 = 0x7F;

/// Decode a full reading ONLY when the configuration byte proves standard
/// (two's-complement) mode.
///
/// Returns `None` — a refusal, not an error value — when the RANGE bit is set,
/// because the standard decoders would be wrong by 64 °C on a thermal-safety
/// path. Callers must treat `None` as "no board temperature exists" and fall
/// back honestly (die-temp proxy with an honest source label); they must NEVER
/// substitute `0.0` — a fabricated 0 °C reads as "cold" and defeats throttling.
pub fn decode_reading_checked(
    config: u8,
    manufacturer_id: u8,
    local: u8,
    remote_high: u8,
    remote_low: u8,
) -> Option<RemoteTempReading> {
    if is_extended_range(config) {
        return None;
    }
    Some(decode_reading(
        manufacturer_id,
        local,
        remote_high,
        remote_low,
    ))
}

#[cfg(test)]
mod extended_range_tests {
    use super::*;

    #[test]
    fn standard_mode_config_decodes_and_matches_unchecked() {
        let checked = decode_reading_checked(0x00, 0x1A, 49, 65, 0x40).expect("standard mode");
        assert_eq!(checked, decode_reading(0x1A, 49, 65, 0x40));
        // Other config bits (conversion rate, ALERT mask, STOP...) must not refuse.
        assert!(decode_reading_checked(0xFB, 0x55, 40, 60, 0x00).is_some());
    }

    #[test]
    fn extended_range_mode_is_refused_never_compensated() {
        // RANGE bit alone.
        assert_eq!(decode_reading_checked(0x04, 0x41, 40, 94, 0x00), None);
        // RANGE bit among other set bits.
        assert_eq!(decode_reading_checked(0x05, 0x41, 40, 94, 0x00), None);
        assert_eq!(decode_reading_checked(0xFF, 0x55, 40, 94, 0x00), None);
        assert!(is_extended_range(0x04));
        assert!(!is_extended_range(0xFB & !0x04));
    }

    #[test]
    fn negative_temperature_round_trips_through_checked_decode() {
        // 0xF6 = -10 °C two's complement; the unsigned legacy decode read 246.
        let r = decode_reading_checked(0x00, 0x55, 0xFB, 0xF6, 0x00).expect("standard mode");
        assert_eq!(r.local_c, -5);
        assert!((r.remote_c - (-10.0)).abs() < 1e-6);
        assert!(r.remote_is_plausible());
        // LM90 fraction is an unsigned add onto the signed integer part:
        // -10 °C + 4/8 °C = -9.5 °C.
        let r = decode_reading_checked(0x00, 0x55, 0x00, 0xF6, 0x80).expect("standard mode");
        assert!((r.remote_c - (-9.5)).abs() < 1e-6);
    }

    #[test]
    fn zero_celsius_is_a_valid_plausible_temperature() {
        // The legacy driver filter `temp > 0` discarded a real 0 °C (cold-garage
        // startup). 0 °C must decode and pass plausibility.
        let r = decode_reading_checked(0x00, 0x1A, 0, 0, 0).expect("standard mode");
        assert!((r.remote_c - 0.0).abs() < 1e-6);
        assert!(r.remote_is_plausible());
    }

    #[test]
    fn config_register_pointer_is_part_aware() {
        // TMP42x: config 1 lives at 0x09 (no LM90 split-pointer convention).
        assert_eq!(config_register_for(0x55, 0x21), reg::TMP42X_CONFIG_1);
        assert_eq!(config_register_for(0x55, 0x22), reg::TMP42X_CONFIG_1);
        assert_eq!(config_register_for(0x55, 0x23), reg::TMP42X_CONFIG_1);
        // Classic LM90 read pointer everywhere else.
        assert_eq!(config_register_for(0x55, 0x00), reg::CONFIG_READ); // TMP451/461
        assert_eq!(config_register_for(0x41, 0x51), reg::CONFIG_READ); // ADT7461
        assert_eq!(config_register_for(0x41, 0x55), reg::CONFIG_READ); // NCT72
        assert_eq!(config_register_for(0x1A, 0xCA), reg::CONFIG_READ); // NCT218
        assert_eq!(config_register_for(0x99, 0x00), reg::CONFIG_READ); // unknown
        assert_eq!((reg::CONFIG_READ, reg::TMP42X_CONFIG_1), (0x03, 0x09));
    }

    #[test]
    fn remote_fraction_pointer_is_part_aware_and_refuses_tmp42x() {
        // TMP42x: 0x10 is the LOCAL channel's low byte (remote-1 is 0x11, and a
        // 4-bit field), so there is no pointer this module's 3-bit decoders can
        // use. Refuse rather than pair a remote MSB with the local fraction.
        assert_eq!(remote_low_register_for(MFR_ID_TI, dev_id::TMP421), None);
        assert_eq!(remote_low_register_for(0x55, 0x22), None);
        assert_eq!(remote_low_register_for(0x55, 0x23), None);
        // Classic LM90 lineage keeps the 0x10 remote low byte.
        for (mfr, dev) in [(0x55u8, 0x00u8), (0x41, 0x51), (0x41, 0x55), (0x1A, 0xCA)] {
            assert_eq!(
                remote_low_register_for(mfr, dev),
                Some(reg::REMOTE_TEMP_LOW)
            );
        }
        // Unknown parts keep the classic pointer (matches config_register_for).
        assert_eq!(
            remote_low_register_for(0x99, 0x00),
            Some(reg::REMOTE_TEMP_LOW)
        );
        // The two part-aware selectors must agree on which family is special:
        // whenever the config pointer is the TMP42x one, the fraction is refused.
        for dev in [dev_id::TMP421, 0x22, 0x23] {
            assert_eq!(config_register_for(MFR_ID_TI, dev), reg::TMP42X_CONFIG_1);
            assert_eq!(remote_low_register_for(MFR_ID_TI, dev), None);
        }
    }

    #[test]
    fn open_circuit_latch_is_inside_the_plausible_window() {
        // Documents WHY callers must reject 0x7F by value: +127 °C decodes fine
        // and passes plausibility, so the window alone cannot catch a broken diode.
        assert_eq!(REMOTE_OPEN_CIRCUIT_HIGH, 0x7F);
        let t = decode_remote_temp(REMOTE_OPEN_CIRCUIT_HIGH, 0x00);
        assert!((t - 127.0).abs() < 1e-6);
        assert!(PLAUSIBLE_REMOTE_C.contains(&t));
    }
}

#[cfg(test)]
mod refine_tests {
    use super::*;

    // Known-answer vectors: (mfr 0xFE, dev 0xFF) -> part. Bytes sourced per the provenance
    // block above (Linux tmp401.c / lm90.c + in-repo BraiinsOS TMP42x).
    #[test]
    fn kat_ti_parts() {
        assert_eq!(refine_part(0x55, 0x11), SensorPart::Tmp401);
        assert_eq!(refine_part(0x55, 0x12), SensorPart::Tmp411a);
        assert_eq!(refine_part(0x55, 0x13), SensorPart::Tmp411b);
        assert_eq!(refine_part(0x55, 0x10), SensorPart::Tmp411c);
        assert_eq!(refine_part(0x55, 0x31), SensorPart::Tmp431Family);
        assert_eq!(refine_part(0x55, 0x32), SensorPart::Tmp432);
        assert_eq!(refine_part(0x55, 0x35), SensorPart::Tmp435);
        assert_eq!(refine_part(0x55, 0x21), SensorPart::Tmp42x { channels: 1 });
        assert_eq!(refine_part(0x55, 0x22), SensorPart::Tmp42x { channels: 2 });
        assert_eq!(refine_part(0x55, 0x23), SensorPart::Tmp42x { channels: 3 });
        assert_eq!(refine_part(0x55, 0x00), SensorPart::Tmp451Or461);
    }

    #[test]
    fn kat_analog_devices_parts() {
        assert_eq!(refine_part(0x41, 0x51), SensorPart::Adt7461);
        assert_eq!(refine_part(0x41, 0x57), SensorPart::Adt7461a);
        // NCT72 reports the ADI manufacturer ID (0x41), device 0x55 — the coarse
        // SensorModel would call this Adt7461; the refinement corrects it.
        assert_eq!(refine_part(0x41, 0x55), SensorPart::Nct72);
        assert_eq!(refine_part(0x41, 0x54), SensorPart::Nct1008);
    }

    #[test]
    fn kat_on_semi_parts() {
        assert_eq!(refine_part(0x1A, 0xCA), SensorPart::Nct218);
        assert_eq!(refine_part(0x1A, 0x5A), SensorPart::Nct214);
        assert_eq!(refine_part(0x1A, 0x3F), SensorPart::Nct210);
    }

    #[test]
    fn recognized_part_admits_exact_registry_and_refuses_unknown_ids() {
        let exact = [
            (0x55, 0x11), // TMP401
            (0x55, 0x12), // TMP411A
            (0x55, 0x13), // TMP411B
            (0x55, 0x10), // TMP411C
            (0x55, 0x31), // TMP431 family
            (0x55, 0x32), // TMP432
            (0x55, 0x35), // TMP435
            (0x55, 0x21), // TMP421
            (0x55, 0x22), // TMP422
            (0x55, 0x23), // TMP423
            (0x55, 0x00), // TMP451/TMP461
            (0x41, 0x51), // ADT7461
            (0x41, 0x57), // ADT7461A
            (0x41, 0x55), // NCT72
            (0x41, 0x54), // NCT1008
            (0x1A, 0xCA), // NCT218
            (0x1A, 0x5A), // NCT214
            (0x1A, 0x3F), // NCT210
        ];
        for (manufacturer_id, device_id) in exact {
            assert!(recognized_part(manufacturer_id, device_id).is_some());
        }

        assert_eq!(recognized_part(0x55, 0x99), None);
        assert_eq!(recognized_part(0x1A, 0x99), None);
        assert_eq!(recognized_part(0x99, 0x00), None);
    }

    #[test]
    fn unknown_device_id_falls_through_but_keeps_vendor() {
        // ECT218 (AMTC #5): known ON Semi vendor, unsourced device ID -> not guessed.
        assert_eq!(
            refine_part(0x1A, 0x99),
            SensorPart::UnknownForVendor {
                manufacturer_id: 0x1A,
                device_id: 0x99
            }
        );
        assert_eq!(
            refine_part(0x99, 0x00),
            SensorPart::Unknown {
                manufacturer_id: 0x99,
                device_id: 0x00
            }
        );
    }

    #[test]
    fn refinement_is_purely_advisory_temp_still_decodes() {
        // Same bytes the coarse decoder handles; temperature is unaffected by refinement.
        let r = decode_reading(0x1A, 49, 65, 0x40);
        assert_eq!(r.model, SensorModel::Nct218); // coarse, unchanged
        assert_eq!(refine_part(0x1A, 0xCA), SensorPart::Nct218); // fine
        assert!(r.remote_is_plausible());
        assert_eq!(refined_part_label(SensorPart::Nct72), "NCT72");
    }

    #[test]
    fn tmp42x_channel_count_matches_braiins_extraction() {
        // BraiinsOS braiins_sensor.rs: TMP42x index = device_id - 0x20.
        for (dev, ch) in [(0x21u8, 1u8), (0x22, 2), (0x23, 3)] {
            assert_eq!(refine_part(0x55, dev), SensorPart::Tmp42x { channels: ch });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manufacturer_ids_map_to_documented_models() {
        assert_eq!(model_from_manufacturer_id(0x55), SensorModel::Tmp451);
        assert_eq!(model_from_manufacturer_id(0x41), SensorModel::Adt7461);
        assert_eq!(model_from_manufacturer_id(0x1A), SensorModel::Nct218);
        assert_eq!(
            model_from_manufacturer_id(0x99),
            SensorModel::Unknown {
                manufacturer_id: 0x99
            }
        );
    }

    #[test]
    fn local_temp_is_signed() {
        assert_eq!(decode_local_temp(45), 45);
        assert_eq!(decode_local_temp(0), 0);
        // 0xFB = -5 in two's complement.
        assert_eq!(decode_local_temp(0xFB), -5);
    }

    #[test]
    fn remote_temp_folds_in_eighths() {
        // 60 °C, no fraction.
        assert!((decode_remote_temp(60, 0x00) - 60.0).abs() < 1e-6);
        // 60 °C + 0.5 °C: eighths = 4 -> low byte bits[7:5]=100 -> 0x80.
        assert!((decode_remote_temp(60, 0x80) - 60.5).abs() < 1e-6);
        // 60 °C + 0.875 °C: eighths = 7 -> 0xE0.
        assert!((decode_remote_temp(60, 0xE0) - 60.875).abs() < 1e-6);
        // Low bits below [7:5] are ignored.
        assert!((decode_remote_temp(60, 0x1F) - 60.0).abs() < 1e-6);
    }

    #[test]
    fn full_reading_decodes_all_fields() {
        // NCT218 (0x1A), local 49 °C, remote 65.25 °C (65, eighths=2 -> 0x40).
        let r = decode_reading(0x1A, 49, 65, 0x40);
        assert_eq!(r.model, SensorModel::Nct218);
        assert_eq!(r.local_c, 49);
        assert!((r.remote_c - 65.25).abs() < 1e-6);
        assert!(r.remote_is_plausible());
    }

    #[test]
    fn implausible_reading_is_flagged_for_fallback() {
        // 0xFF high byte = -1 °C whole; that is plausible. Use a clearly-broken value:
        // an unpowered sensor commonly reads 0x00/0xFF garbage far outside the window.
        let broken = RemoteTempReading {
            model: SensorModel::Unknown {
                manufacturer_id: 0x00,
            },
            local_c: 0,
            remote_c: 200.0,
        };
        assert!(!broken.remote_is_plausible());
        // A real ~65 °C mining temp is plausible.
        let ok = decode_reading(0x55, 40, 65, 0x00);
        assert!(ok.remote_is_plausible());
    }

    #[test]
    fn register_and_id_constants_are_pinned() {
        assert_eq!(reg::LOCAL_TEMP, 0x00);
        assert_eq!(reg::REMOTE_TEMP_HIGH, 0x01);
        assert_eq!(reg::REMOTE_TEMP_LOW, 0x10);
        assert_eq!(reg::MANUFACTURER_ID, 0xFE);
        assert_eq!(reg::DEVICE_ID, 0xFF);
        assert_eq!(
            (MFR_ID_TI, MFR_ID_ANALOG_DEVICES, MFR_ID_ON_SEMI),
            (0x55, 0x41, 0x1A)
        );
    }
}
