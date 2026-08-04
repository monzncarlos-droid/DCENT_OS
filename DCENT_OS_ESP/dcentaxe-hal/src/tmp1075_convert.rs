//! Host-pure TMP1075 addressing, topology and decode.
//!
//! The decode half of `temp::Tmp1075`, plus the multi-device addressing the
//! Nerd boards need. `temp.rs` links esp-idf-hal and only compiles for the
//! espidf target, so everything a host test can execute lives here — same split
//! as `temp_decode.rs` (EMC2101) and `tmp451_convert.rs`.
//!
//! # Addressing
//!
//! The part's address is strapped as `0x48 + n` for `n` in `0..=3`. BitAxe Hex
//! boards fit two at 0x4A/0x4B (inlet/outlet); the Nerd multi-ASIC boards fit up
//! to four starting at 0x48 — which is why the fixed primary/secondary pair the
//! driver started with cannot describe them.
//!
//! # The VR device is not an ASIC sensor
//!
//! On the Nerd boards **device index 1 (0x49) is the voltage-regulator sensor on
//! the back of the board**, not an ASIC sensor
//! (`nerdqaxeplus.cpp: #define VR_TEMP1075_ADDR 0x1`, and `detectNumTempSensors`
//! skips it). Upstream maps logical ASIC sensor `n` to device index
//! `n + !!n` — i.e. 0, 2, 3 — so a four-ASIC board exposes three ASIC sensors.
//! Reporting the VR device as an ASIC temperature would attribute a regulator
//! reading to a die; [`nerd_asic_device_index`] encodes the skip so no caller
//! has to rediscover it.
//!
//! # Two inherited defects this module does not reproduce
//!
//! Both are in `TMP1075.cpp` upstream:
//!
//! 1. **`0.0` as an error sentinel.** `TMP1075_read_temperature` returns `0.0f`
//!    when the I2C read fails, and its callers test `if (!temp)`. `0.0` is a
//!    plausible cold-boot temperature, so a dead sensor reads as "cold" — and
//!    `detectNumTempSensors` uses that same falsy test to decide a sensor is
//!    ABSENT, meaning a board booted in a cold room would detect zero sensors.
//!    Everything here returns `Option`.
//! 2. **Unsigned shift.** `(temp_raw >> 4) * 0.0625f` treats a two's-complement
//!    value as unsigned, so -0.0625 C (`0xFFF0`) decodes as +255.94 C. Upstream
//!    masks the symptom with a `> 0x7ff0` "invalid" test that rejects every
//!    sub-zero reading. [`decode_temp`] shifts signed, so negatives decode
//!    correctly and no reading has to be discarded to hide an arithmetic bug.

/// Lowest strapped address of the family.
pub const ADDR_BASE: u8 = 0x48;

/// Number of distinct strapped addresses (`0x48..=0x4B`).
pub const MAX_DEVICES: u8 = 4;

/// Temperature register (16-bit, big-endian, left-justified 12-bit signed).
pub const REG_TEMP: u8 = 0x00;
/// Configuration register.
pub const REG_CONFIG: u8 = 0x01;
/// Device ID register.
pub const REG_DEVICE_ID: u8 = 0x0F;

/// Degrees Celsius per LSB after the 4-bit right shift.
pub const RESOLUTION_C: f32 = 0.0625;

/// Nerd board device index carrying the voltage-regulator sensor.
///
/// `nerdqaxeplus.cpp: #define VR_TEMP1075_ADDR 0x1` — i.e. 0x49.
pub const NERD_VR_DEVICE_INDEX: u8 = 1;

/// Lower reject bound, matching the pre-existing `temp::Tmp1075::read_temp`.
///
/// The part's guaranteed-accuracy floor. A reading below this is an open or
/// absent sensor, not a measurement.
pub const TEMP_MIN_C: f32 = -40.0;

/// Errors from addressing the part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tmp1075ConfigError {
    /// Device index at or above [`MAX_DEVICES`].
    DeviceIndexOutOfRange(u8),
    /// A logical ASIC-sensor index with no device behind it.
    AsicSensorIndexOutOfRange(u8),
    /// The requested device is the VR sensor, not an ASIC sensor.
    DeviceIsVoltageRegulator(u8),
}

impl core::fmt::Display for Tmp1075ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceIndexOutOfRange(i) => {
                write!(f, "TMP1075 device index {i} exceeds {}", MAX_DEVICES - 1)
            }
            Self::AsicSensorIndexOutOfRange(i) => {
                write!(f, "no TMP1075 ASIC sensor at logical index {i}")
            }
            Self::DeviceIsVoltageRegulator(i) => {
                write!(f, "TMP1075 device {i} is the VR sensor, not an ASIC sensor")
            }
        }
    }
}

/// What a given device on the board actually measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorRole {
    /// Near an ASIC die — usable as a chip temperature.
    Asic,
    /// On the voltage regulator — must NOT be reported as a chip temperature.
    VoltageRegulator,
}

/// I2C address for a strapped device index.
pub fn address_for_device(index: u8) -> Result<u8, Tmp1075ConfigError> {
    if index >= MAX_DEVICES {
        return Err(Tmp1075ConfigError::DeviceIndexOutOfRange(index));
    }
    Ok(ADDR_BASE + index)
}

/// What device `index` measures on a Nerd board.
pub fn nerd_role(index: u8) -> Result<SensorRole, Tmp1075ConfigError> {
    if index >= MAX_DEVICES {
        return Err(Tmp1075ConfigError::DeviceIndexOutOfRange(index));
    }
    Ok(if index == NERD_VR_DEVICE_INDEX {
        SensorRole::VoltageRegulator
    } else {
        SensorRole::Asic
    })
}

/// Number of ASIC temperature sensors a fully-populated Nerd board exposes.
///
/// Three, not four: the VR device is skipped.
pub const NERD_ASIC_SENSOR_COUNT: u8 = MAX_DEVICES - 1;

/// Map a logical ASIC-sensor index to its strapped device index.
///
/// Reproduces upstream's `index + !!index` (0 -> 0, 1 -> 2, 2 -> 3), skipping
/// the VR device, but as a checked mapping rather than an arithmetic trick.
pub fn nerd_asic_device_index(logical: u8) -> Result<u8, Tmp1075ConfigError> {
    if logical >= NERD_ASIC_SENSOR_COUNT {
        return Err(Tmp1075ConfigError::AsicSensorIndexOutOfRange(logical));
    }
    Ok(if logical == 0 { 0 } else { logical + 1 })
}

/// I2C address of the Nerd VR sensor.
pub fn nerd_vr_address() -> u8 {
    ADDR_BASE + NERD_VR_DEVICE_INDEX
}

/// Decode the temperature register.
///
/// 12-bit two's complement, left-justified in a big-endian 16-bit word. Shifting
/// as `i16` keeps the sign — see the module docs for the unsigned-shift defect
/// this does not reproduce.
pub fn decode_temp(raw: u16) -> f32 {
    ((raw as i16) >> 4) as f32 * RESOLUTION_C
}

/// Decode and reject an absent/open sensor.
///
/// Returns `None` only below [`TEMP_MIN_C`]. There is deliberately no upper
/// reject: a signed 12-bit decode saturates at +127.94 C, which is real danger
/// and must reach the thermal-emergency path.
pub fn decode_available_temp(raw: u16) -> Option<f32> {
    let temp = decode_temp(raw);
    if temp < TEMP_MIN_C {
        return None;
    }
    Some(temp)
}

/// Highest temperature a signed 12-bit decode can produce.
pub const DECODE_MAX_C: f32 = 127.9375;
/// Lowest temperature a signed 12-bit decode can produce.
pub const DECODE_MIN_C: f32 = -128.0;

#[cfg(test)]
mod tests {
    use super::*;

    // ── addressing ──────────────────────────────────────────────────────────

    #[test]
    fn devices_are_strapped_from_the_base_address() {
        assert_eq!(address_for_device(0), Ok(0x48));
        assert_eq!(address_for_device(1), Ok(0x49));
        assert_eq!(address_for_device(2), Ok(0x4A));
        assert_eq!(address_for_device(3), Ok(0x4B));
    }

    #[test]
    fn the_existing_hex_pair_is_still_reachable_by_index() {
        // The driver's pre-existing primary/secondary are 0x4A/0x4B; the
        // indexed form must agree so generalizing cannot move a Hex board's
        // sensors.
        assert_eq!(address_for_device(2), Ok(0x4A));
        assert_eq!(address_for_device(3), Ok(0x4B));
    }

    #[test]
    fn a_fifth_device_has_no_address() {
        assert_eq!(
            address_for_device(4),
            Err(Tmp1075ConfigError::DeviceIndexOutOfRange(4))
        );
    }

    // ── topology: the VR device is not an ASIC sensor ───────────────────────

    #[test]
    fn device_one_is_the_voltage_regulator() {
        assert_eq!(nerd_role(1), Ok(SensorRole::VoltageRegulator));
        assert_eq!(nerd_vr_address(), 0x49);
    }

    #[test]
    fn every_other_device_is_an_asic_sensor() {
        assert_eq!(nerd_role(0), Ok(SensorRole::Asic));
        assert_eq!(nerd_role(2), Ok(SensorRole::Asic));
        assert_eq!(nerd_role(3), Ok(SensorRole::Asic));
    }

    #[test]
    fn asic_sensor_mapping_skips_the_vr_device() {
        // Upstream's `index + !!index`, made explicit.
        assert_eq!(nerd_asic_device_index(0), Ok(0));
        assert_eq!(nerd_asic_device_index(1), Ok(2));
        assert_eq!(nerd_asic_device_index(2), Ok(3));
    }

    #[test]
    fn no_asic_sensor_mapping_ever_lands_on_the_vr_device() {
        // The load-bearing property: a regulator reading must never be
        // published as a die temperature.
        for logical in 0..NERD_ASIC_SENSOR_COUNT {
            let dev = nerd_asic_device_index(logical).unwrap();
            assert_ne!(dev, NERD_VR_DEVICE_INDEX, "logical {logical}");
            assert_eq!(nerd_role(dev), Ok(SensorRole::Asic));
        }
    }

    #[test]
    fn a_four_asic_board_still_only_has_three_asic_sensors() {
        assert_eq!(NERD_ASIC_SENSOR_COUNT, 3);
        assert_eq!(
            nerd_asic_device_index(3),
            Err(Tmp1075ConfigError::AsicSensorIndexOutOfRange(3))
        );
    }

    // ── decode ──────────────────────────────────────────────────────────────

    #[test]
    fn positive_readings_decode_at_quarter_sixteenth_resolution() {
        assert_eq!(decode_temp(0x0000), 0.0);
        assert_eq!(decode_temp(0x1900), 25.0);
        assert_eq!(decode_temp(0x0010), 0.0625);
    }

    #[test]
    fn negative_readings_decode_signed() {
        // THE inherited defect: an unsigned shift turns 0xFFF0 into +255.94.
        assert_eq!(decode_temp(0xFFF0), -0.0625);
        assert_eq!(decode_temp(0xE700), -25.0);
    }

    #[test]
    fn the_unsigned_defect_is_not_reproduced() {
        // Pinned explicitly so nobody "simplifies" the cast back.
        let unsigned_would_be = (0xFFF0u16 >> 4) as f32 * RESOLUTION_C;
        assert!(unsigned_would_be > 255.0);
        assert!(decode_temp(0xFFF0) < 0.0);
    }

    #[test]
    fn decode_saturates_inside_the_parts_range() {
        assert_eq!(decode_temp(0x7FF0), DECODE_MAX_C);
        assert_eq!(decode_temp(0x8000), DECODE_MIN_C);
    }

    // ── availability ────────────────────────────────────────────────────────

    #[test]
    fn zero_celsius_is_a_reading_not_an_absent_sensor() {
        // Upstream's `if (!TMP1075_read_temperature(i)) break;` treats 0.0 as
        // "sensor absent", so a board booted at 0 C detects no sensors at all.
        assert_eq!(decode_available_temp(0x0000), Some(0.0));
    }

    #[test]
    fn an_open_sensor_is_unavailable() {
        assert_eq!(decode_available_temp(0x8000), None);
    }

    #[test]
    fn the_reject_bound_is_exclusive() {
        // -40.0 decodes from 0xD800 and is kept; anything colder is rejected.
        assert_eq!(decode_available_temp(0xD800), Some(-40.0));
        assert_eq!(decode_available_temp(0xD7F0), None);
    }

    #[test]
    fn a_dangerously_high_reading_is_reported_not_dropped() {
        // HALT-3 again: no upper reject.
        assert_eq!(decode_available_temp(0x7FF0), Some(DECODE_MAX_C));
    }

    #[test]
    fn a_signed_decode_can_never_reach_the_legacy_upper_reject() {
        // `temp::Tmp1075::read_temp` also rejects `> 200.0`. With a signed
        // shift the decode saturates at 127.94, so that arm is unreachable —
        // recorded here so a future reader does not mistake it for live
        // protection against a hot chip.
        assert!(DECODE_MAX_C < 200.0);
    }
}
