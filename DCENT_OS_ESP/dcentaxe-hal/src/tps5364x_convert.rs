//! TPS53647 / TPS53667 multi-phase PMBus VRM — **host-pure core**.
//!
//! This is the decision half of the TPS5364x driver: VID conversion, part
//! identification, phase/current encoding and the init register plan. It has no
//! I2C and no ESP-IDF dependency, so every rule below is exercised by the host
//! test gate (`cargo test -p dcentaxe-hal`). The thin bus shim that actually
//! talks SMBus lives in `tps5364x.rs` behind `#[cfg(target_os = "espidf")]` —
//! the same split as `power_convert.rs` / `power.rs` and `temp_decode.rs` /
//! `temp.rs`.
//!
//! # Why this driver exists
//!
//! The Nerd family's multi-ASIC boards do **not** carry the TPS546 that every
//! BitAxe-class board uses. They carry a multi-phase controller:
//!
//! | Board             | ASICs         | VRM                       | Phases |
//! |-------------------|---------------|---------------------------|--------|
//! | NerdQAxe+         | 4× BM1368     | TPS53647                  | 2      |
//! | NerdQAxe++ (pre-rev7) | 4× BM1370 | TPS53647                  | 3      |
//! | NerdOCTAXE+       | 8× BM1368     | TPS53647                  | 3      |
//! | NerdOCTAXE-γ ≤rev3.3 | 8× BM1370  | TPS53647                  | 4      |
//! | NerdOCTAXE-γ rev3.4  | 8× BM1370  | TPS53667                  | 6      |
//!
//! (Reference: `ESP-Miner-NerdQAxePlus/main/boards/drivers/TPS53647.cpp` and
//! `TPS53667.cpp`, plus the per-board constructors in `main/boards/*.cpp`.)
//!
//! The two parts share a register map but differ in device code, minimum output
//! voltage and init sequence — so they are **one driver with a variant**, never
//! one profile with a parameter.
//!
//! # Safety posture
//!
//! * **Part identity is a gate, not a hint.** `Variant::from_device_code`
//!   returns `None` for anything that is not a known part, and the bring-up path
//!   must refuse to energize on `None`. A TPS546 answering at a TPS5364x address
//!   would otherwise be driven with ULINEAR16 semantics against a VID register
//!   map — a wrong-voltage event on a 100–300 W rail.
//! * **Out-of-range is rejected, never clamped.** `vout_command` returns `Err`
//!   rather than saturating, matching `PowerManager::set_voltage`'s documented
//!   fail-closed contract. Upstream's C returns VID `0` here, which silently
//!   means "output off"; we surface it as a typed error instead.
//! * **`imax` is range-checked.** Upstream casts to `uint8_t`, so an `imax`
//!   above 255 A wraps to a *smaller* over-current limit — the dangerous
//!   direction. We reject it.
//! * **The rail is per-ASIC volts × voltage domains.** Same formula as
//!   `safety::rail_voltage_v`. Every TPS5364x Nerd board is a single domain with
//!   ASICs in parallel; a domain count > 1 on one of these rows would command a
//!   multiple of ~1.2 V onto parallel dies. See `rail_voltage_v_for_domains`.

/// PMBus / MFR-specific registers used by the TPS5364x family.
///
/// Values transcribed from
/// `ESP-Miner-NerdQAxePlus/main/boards/drivers/pmbus_commands.h`.
pub mod reg {
    pub const ON_OFF_CONFIG: u8 = 0x02;
    pub const CLEAR_FAULTS: u8 = 0x03;
    pub const RESTORE_DEFAULT_ALL: u8 = 0x12;
    pub const VOUT_COMMAND: u8 = 0x21;
    pub const VOUT_MAX: u8 = 0x24;
    pub const IOUT_OC_FAULT_LIMIT: u8 = 0x46;
    pub const IOUT_OC_WARN_LIMIT: u8 = 0x4A;
    pub const OT_FAULT_LIMIT: u8 = 0x4F;
    pub const OT_WARN_LIMIT: u8 = 0x51;
    pub const IIN_OC_FAULT_LIMIT: u8 = 0x5B;
    pub const IIN_OC_WARN_LIMIT: u8 = 0x5D;
    pub const STATUS_BYTE: u8 = 0x78;
    pub const STATUS_WORD: u8 = 0x79;
    pub const STATUS_VOUT: u8 = 0x7A;
    pub const STATUS_IOUT: u8 = 0x7B;
    pub const STATUS_INPUT: u8 = 0x7C;
    pub const STATUS_TEMPERATURE: u8 = 0x7D;
    pub const STATUS_MFR_SPECIFIC: u8 = 0x80;
    pub const READ_VIN: u8 = 0x88;
    pub const READ_IIN: u8 = 0x89;
    pub const READ_IOUT: u8 = 0x8C;
    pub const READ_TEMPERATURE_1: u8 = 0x8D;
    pub const READ_POUT: u8 = 0x96;
    pub const READ_PIN: u8 = 0x97;

    /// Per-phase over-current limit threshold selector (TPS53667 init).
    pub const MFR_SPECIFIC_00: u8 = 0xD0;
    /// Live VOUT readback, encoded as `raw * 2^-9` volts.
    pub const MFR_SPECIFIC_04: u8 = 0xD4;
    /// Maximum output current, in amperes, as a single byte.
    pub const MFR_SPECIFIC_10: u8 = 0xDA;
    /// Switching frequency selector (`0x20` = 500 kHz).
    pub const MFR_SPECIFIC_12: u8 = 0xDC;
    /// Operation mode / phase-shedding control.
    pub const MFR_SPECIFIC_13: u8 = 0xDD;
    /// VIN under-voltage lockout threshold selector (TPS53667 init).
    pub const MFR_SPECIFIC_16: u8 = 0xE0;
    /// TPS53667-only init word.
    pub const MFR_SPECIFIC_19: u8 = 0xE3;
    /// Active phase count, written as `phases - 1`.
    pub const MFR_SPECIFIC_20: u8 = 0xE4;
    /// Phase-enable mask (TPS53667). `0x00` = all phases enabled.
    pub const MFR_SPECIFIC_24: u8 = 0xE8;
    /// Device code — the part-identity register.
    pub const MFR_SPECIFIC_44: u8 = 0xFC;
}

/// I2C address shared by both parts.
pub const TPS5364X_ADDR: u8 = 0x71;

/// VID step size in volts. Both parts use a 5 mV VID ladder.
pub const VID_STEP_V: f32 = 0.005;

/// VID ladder base voltage (`m_hwMinVoltage` upstream).
pub const VID_BASE_V: f32 = 0.25;

/// The VID that encodes exactly 1.000 V.
///
/// Upstream deliberately never *writes* this code: the part powers up with
/// VOUT_COMMAND at the factory default 1.000 V, so leaving `0x97` reserved lets
/// firmware distinguish "regulator was reset underneath us" from "firmware
/// commanded 1.000 V". `vout_command` substitutes [`VID_ONE_VOLT_SUBSTITUTE`].
pub const VID_ONE_VOLT: u8 = 0x97;

/// Substituted for [`VID_ONE_VOLT`] — 0.995 V, i.e. one step *down* (safe
/// direction) rather than up.
pub const VID_ONE_VOLT_SUBSTITUTE: u8 = 0x96;

/// Switching-frequency selector value for 500 kHz.
pub const SWITCH_FREQ_500KHZ: u8 = 0x20;

/// `ON_OFF_CONFIG` value used at init by both parts — output stays off until
/// explicitly enabled.
pub const ON_OFF_CONFIG_INIT: u8 = 0b0001_0111;

/// Over-temperature warning threshold, °C.
pub const OT_WARN_C: f32 = 95.0;

/// Over-temperature fault threshold, °C.
pub const OT_FAULT_C: f32 = 125.0;

/// Board-supplied operating envelope for the regulator.
#[derive(Debug, Clone, Copy)]
pub struct Tps5364xConfig {
    /// Number of active phases. Must not exceed the detected part's maximum.
    pub num_phases: u8,
    /// Maximum output current in amperes (`MFR_SPECIFIC_10`).
    pub imax_a: u16,
    /// Over-current warn/fault threshold in amperes.
    pub ifault_a: f32,
    /// Whether to allow dynamic phase shedding. The NerdOCTAXE-γ runs with this
    /// **disabled** so all six phases share current at all times.
    pub phase_shedding: bool,
    /// TPS53667 only: input over-current warn / fault limits in amperes.
    pub iin_oc_warn_a: f32,
    pub iin_oc_fault_a: f32,
}

/// Which member of the TPS5364x family is on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// TPS53647 — up to 4 phases. Device code `0x01F0`.
    Tps53647,
    /// TPS53667 — up to 6 phases. Device code `0x01F8`.
    Tps53667,
}

/// Device code reported by a TPS53647 in `MFR_SPECIFIC_44`.
pub const DEVICE_CODE_TPS53647: u16 = 0x01F0;

/// Device code reported by a TPS53667 in `MFR_SPECIFIC_44`.
pub const DEVICE_CODE_TPS53667: u16 = 0x01F8;

impl Variant {
    /// Identify the part from its `MFR_SPECIFIC_44` device code.
    ///
    /// Returns `None` for any unrecognized code — including `0x0000` and
    /// `0xFFFF`, the two values a floating or NAKing bus produces. Callers MUST
    /// treat `None` as "refuse to energize"; there is no default variant,
    /// because guessing wrong writes VID codes to a part with a different
    /// output-voltage mapping.
    pub fn from_device_code(code: u16) -> Option<Self> {
        match code {
            DEVICE_CODE_TPS53647 => Some(Self::Tps53647),
            DEVICE_CODE_TPS53667 => Some(Self::Tps53667),
            _ => None,
        }
    }

    /// The device code this part is expected to report.
    pub fn device_code(&self) -> u16 {
        match self {
            Self::Tps53647 => DEVICE_CODE_TPS53647,
            Self::Tps53667 => DEVICE_CODE_TPS53667,
        }
    }

    /// Human-readable part name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tps53647 => "TPS53647",
            Self::Tps53667 => "TPS53667",
        }
    }

    /// Minimum commandable output voltage, volts.
    ///
    /// The TPS53667 floor is higher (1.005 V vs 0.8 V) because it is only fitted
    /// to the high-phase-count boards, which are not characterized below that.
    pub fn vout_min_v(&self) -> f32 {
        match self {
            Self::Tps53647 => 0.8,
            Self::Tps53667 => 1.005,
        }
    }

    /// Maximum commandable output voltage, volts. Both parts cap at 1.4 V.
    pub fn vout_max_v(&self) -> f32 {
        1.4
    }

    /// Maximum phase count the part supports.
    pub fn max_phases(&self) -> u8 {
        match self {
            Self::Tps53647 => 4,
            Self::Tps53667 => 6,
        }
    }
}

/// Why a TPS5364x operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tps5364xConfigError {
    /// The device code did not match any known part.
    UnknownDeviceCode(u16),
    /// Requested output voltage is outside the part's commandable window.
    VoltageOutOfRange,
    /// Requested voltage maps outside the representable VID ladder.
    VidOutOfRange,
    /// Phase count is zero or exceeds what the part supports.
    PhaseCountOutOfRange,
    /// `imax` does not fit the single-byte MFR_SPECIFIC_10 register.
    ImaxOutOfRange,
    /// The over-current threshold is zero, negative or non-finite.
    IoutFaultLimitOutOfRange,
    /// The over-current threshold sits above the current-sense full scale set by
    /// `imax`, so the comparator can never reach it. See
    /// [`check_iout_fault_limit`].
    IoutFaultLimitAboveFullScale,
}

impl core::fmt::Display for Tps5364xConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownDeviceCode(c) => {
                write!(f, "unknown TPS5364x device code 0x{c:04x}")
            }
            Self::VoltageOutOfRange => write!(f, "requested voltage outside part range"),
            Self::VidOutOfRange => write!(f, "requested voltage outside VID ladder"),
            Self::PhaseCountOutOfRange => write!(f, "phase count out of range for part"),
            Self::ImaxOutOfRange => write!(f, "imax does not fit MFR_SPECIFIC_10"),
            Self::IoutFaultLimitOutOfRange => {
                write!(f, "over-current threshold is not a positive current")
            }
            Self::IoutFaultLimitAboveFullScale => {
                write!(f, "over-current threshold exceeds the imax sense scale")
            }
        }
    }
}

/// Convert a VID code back to volts.
///
/// VID `0` means "output off" and maps to 0.0 V.
pub fn vid_to_volts(vid: u8) -> f32 {
    if vid == 0 {
        return 0.0;
    }
    (vid as f32 - 1.0) * VID_STEP_V + VID_BASE_V
}

/// Convert volts to a VID code, without applying any part-specific range check.
///
/// Returns `Err(VidOutOfRange)` when the value cannot be represented in the
/// `0x01..=0xFF` ladder. Prefer [`vout_command`], which additionally enforces
/// the part's commandable window.
///
/// # Deliberate divergence from the upstream C
///
/// `TPS53647.cpp` computes `(int)((volts - m_hwMinVoltage) / 0.005f) + 1`, i.e.
/// it **truncates**. In `f32`, `0.255 - 0.25` evaluates to `0.0049999952`, so
/// that expression divides to `0.99999905` and truncates to `0` — landing a
/// whole 5 mV step below the requested voltage. The error is not confined to
/// that one input: any voltage whose offset from the 0.25 V base lands just
/// under an exact multiple of the step encodes one step low.
///
/// We round to nearest instead, which is the correct reading of a VID ladder and
/// bounds the encoding error at half a step (±2.5 mV) rather than a full step.
/// `vid_encoding_is_within_half_a_step` pins that guarantee. This is an
/// algorithmic fix, not a register-value change — every magic register constant
/// is still preserved exactly from the ESP-Miner C.
pub fn volts_to_vid(volts: f32) -> Result<u8, Tps5364xConfigError> {
    if volts <= 0.0 {
        return Ok(0);
    }
    let steps = ((volts - VID_BASE_V) / VID_STEP_V).round() as i32 + 1;
    if steps < 1 || steps > 0xFF {
        return Err(Tps5364xConfigError::VidOutOfRange);
    }
    Ok(steps as u8)
}

/// Build the VID byte to write to `VOUT_COMMAND` for a requested per-rail voltage.
///
/// Enforces the part's `[vout_min, vout_max]` window **fail-closed** and applies
/// the [`VID_ONE_VOLT`] reservation. This is the only function bring-up should
/// use to derive a voltage command.
pub fn vout_command(variant: Variant, volts: f32) -> Result<u8, Tps5364xConfigError> {
    if !volts.is_finite() {
        return Err(Tps5364xConfigError::VoltageOutOfRange);
    }
    if volts < variant.vout_min_v() || volts > variant.vout_max_v() {
        return Err(Tps5364xConfigError::VoltageOutOfRange);
    }
    let vid = volts_to_vid(volts)?;
    if vid == VID_ONE_VOLT {
        return Ok(VID_ONE_VOLT_SUBSTITUTE);
    }
    Ok(vid)
}

/// Decode the live VOUT readback from `MFR_SPECIFIC_04`.
///
/// The part reports this as a ULINEAR16 with a fixed `2^-9` exponent, which is a
/// different encoding from the VID ladder used to *command* voltage.
pub fn decode_vout_readback(raw: u16) -> f32 {
    raw as f32 / 512.0
}

/// Encode the active phase count for `MFR_SPECIFIC_20` (written as `n - 1`).
pub fn phase_register(variant: Variant, num_phases: u8) -> Result<u8, Tps5364xConfigError> {
    if num_phases == 0 || num_phases > variant.max_phases() {
        return Err(Tps5364xConfigError::PhaseCountOutOfRange);
    }
    Ok(num_phases - 1)
}

/// Encode the maximum output current for `MFR_SPECIFIC_10`.
///
/// Upstream casts a C `int` straight to `uint8_t`. That truncation is unsafe in
/// the wrong direction — an `imax` of 300 A would wrap to 44 A, quietly
/// arming a far tighter over-current trip than intended, or worse, a value that
/// no longer protects the stage it was sized for. We reject instead.
pub fn imax_register(imax_a: u16) -> Result<u8, Tps5364xConfigError> {
    if imax_a == 0 || imax_a > 0xFF {
        return Err(Tps5364xConfigError::ImaxOutOfRange);
    }
    Ok(imax_a as u8)
}

/// Check an over-current warn/fault threshold against the current-sense scale.
///
/// `imax_a` and `ifault_a` are not independent knobs. `imax_a` is written to
/// `MFR_SPECIFIC_10`, which sets the **full scale of the current sense** — it is
/// what `READ_IOUT` and the over-current comparator are measured against.
/// `ifault_a` is then written to `IOUT_OC_WARN_LIMIT` / `IOUT_OC_FAULT_LIMIT` as
/// the threshold to compare with. A threshold **above** full scale is a
/// protection that can never assert: the measurement saturates below it, so the
/// stage runs to destruction with an over-current trip that is armed on paper
/// and inert in silicon.
///
/// Every Nerd board upstream sets `ifault` within ±5 A of `imax` — except
/// **NerdQX**, which sets `imax = 90` and then `ifault = 142` (its own
/// deliberately obfuscated `decode_m_ifault(3)`, `(3 * 60) - 38`). That is 58%
/// above full scale. We refuse it rather than copy it, and a board that wants
/// that envelope must raise `imax` to match — which is the honest change,
/// because it is the sense scale that has to be able to see the current.
///
/// A threshold *below* full scale is allowed and normal: that is a protection
/// deliberately tripping before the sensor's ceiling.
pub fn check_iout_fault_limit(imax_a: u16, ifault_a: f32) -> Result<f32, Tps5364xConfigError> {
    if !ifault_a.is_finite() || ifault_a <= 0.0 {
        return Err(Tps5364xConfigError::IoutFaultLimitOutOfRange);
    }
    if ifault_a > imax_a as f32 {
        return Err(Tps5364xConfigError::IoutFaultLimitAboveFullScale);
    }
    Ok(ifault_a)
}

/// Operation-mode byte for `MFR_SPECIFIC_13`.
///
/// `0x89` keeps every phase switching; `0x99` enables dynamic phase shedding.
/// The NerdOCTAXE-γ deliberately runs with shedding **disabled** so all six
/// phases share current at all times.
pub fn operation_mode(phase_shedding: bool) -> u8 {
    if phase_shedding {
        0x99
    } else {
        0x89
    }
}

/// Rail voltage for a per-ASIC setpoint across `voltage_domains` series domains.
///
/// Mirrors the `safety::rail_voltage_v` helper. Restated here so the TPS5364x
/// tests pin the relationship directly: every Nerd board carrying one of these
/// parts is a **single** domain with its ASICs in parallel, so `domains` must be
/// 1 and the rail equals the per-ASIC setpoint. A row that declared 2 domains
/// would command double the intended voltage onto parallel dies.
pub fn rail_voltage_v_for_domains(per_asic_mv: u16, voltage_domains: u16) -> f32 {
    (per_asic_mv as f32 / 1000.0) * voltage_domains as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Part identity is a gate ───────────────────────────────────────────────

    #[test]
    fn device_codes_identify_the_two_known_parts() {
        assert_eq!(
            Variant::from_device_code(0x01F0),
            Some(Variant::Tps53647),
            "0x01F0 is the TPS53647 device code (TPS53647.cpp init)"
        );
        assert_eq!(
            Variant::from_device_code(0x01F8),
            Some(Variant::Tps53667),
            "0x01F8 is the TPS53667 device code (TPS53667.cpp init)"
        );
    }

    #[test]
    fn unknown_device_codes_are_refused_not_defaulted() {
        // A floating/NAKing bus reads as one of these two; neither may resolve
        // to a usable variant, or bring-up would drive an unknown part.
        assert_eq!(Variant::from_device_code(0x0000), None);
        assert_eq!(Variant::from_device_code(0xFFFF), None);
        // A TPS546 answering here must NOT be adopted.
        assert_eq!(Variant::from_device_code(0x0054), None);
    }

    #[test]
    fn device_code_roundtrips_through_variant() {
        for v in [Variant::Tps53647, Variant::Tps53667] {
            assert_eq!(Variant::from_device_code(v.device_code()), Some(v));
        }
    }

    // ── VID ladder ────────────────────────────────────────────────────────────

    #[test]
    fn vid_0x97_is_exactly_one_volt() {
        // Upstream's comment "0x97 is 1.00V" is the anchor for the whole ladder.
        assert!((vid_to_volts(VID_ONE_VOLT) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn vid_zero_is_output_off() {
        assert_eq!(vid_to_volts(0), 0.0);
        assert_eq!(volts_to_vid(0.0), Ok(0));
    }

    #[test]
    fn vid_roundtrips_across_the_ladder() {
        for vid in 1u8..=0xFF {
            let volts = vid_to_volts(vid);
            let back = volts_to_vid(volts).expect("ladder value must re-encode");
            assert_eq!(back, vid, "VID {vid:#04x} -> {volts} V -> {back:#04x}");
        }
    }

    #[test]
    fn vid_encoding_is_within_half_a_step() {
        // The guarantee that replaces upstream's truncation. Sweep the whole
        // commandable window at 1 mV resolution; the encoded VID must never be
        // more than half a step (2.5 mV) from what was asked for. Under
        // truncation this fails by a full step at ladder boundaries.
        let mut mv = 800u32;
        while mv <= 1400 {
            let want = mv as f32 / 1000.0;
            let vid = volts_to_vid(want).expect("in-range voltage must encode");
            let got = vid_to_volts(vid);
            assert!(
                (got - want).abs() <= VID_STEP_V / 2.0 + 1e-6,
                "{want} V encoded to VID {vid:#04x} = {got} V, off by more than half a step"
            );
            mv += 1;
        }
    }

    #[test]
    fn boundary_voltage_does_not_encode_a_step_low() {
        // The exact input that caught upstream's truncation bug.
        assert_eq!(volts_to_vid(0.255), Ok(2));
        assert!((vid_to_volts(2) - 0.255).abs() < 1e-6);
    }

    #[test]
    fn vid_step_is_five_millivolts() {
        let a = vid_to_volts(100);
        let b = vid_to_volts(101);
        assert!((b - a - VID_STEP_V).abs() < 1e-6);
    }

    // ── Fail-closed voltage command ───────────────────────────────────────────

    #[test]
    fn vout_command_rejects_below_part_minimum() {
        // 0.9 V is fine on a '647 but below the '667 floor of 1.005 V.
        assert!(vout_command(Variant::Tps53647, 0.9).is_ok());
        assert_eq!(
            vout_command(Variant::Tps53667, 0.9),
            Err(Tps5364xConfigError::VoltageOutOfRange)
        );
    }

    #[test]
    fn vout_command_rejects_above_maximum_rather_than_clamping() {
        // The house contract is reject, never saturate — a clamped 1.4 V on a
        // request for 1.8 V would silently mine at the wrong point.
        for v in [Variant::Tps53647, Variant::Tps53667] {
            assert_eq!(
                vout_command(v, 1.45),
                Err(Tps5364xConfigError::VoltageOutOfRange)
            );
            assert_eq!(
                vout_command(v, 3.6),
                Err(Tps5364xConfigError::VoltageOutOfRange)
            );
        }
    }

    #[test]
    fn vout_command_rejects_non_finite() {
        assert_eq!(
            vout_command(Variant::Tps53647, f32::NAN),
            Err(Tps5364xConfigError::VoltageOutOfRange)
        );
        assert_eq!(
            vout_command(Variant::Tps53647, f32::INFINITY),
            Err(Tps5364xConfigError::VoltageOutOfRange)
        );
    }

    #[test]
    fn vout_command_never_emits_the_reserved_one_volt_vid() {
        // Sweep the whole commandable window of both parts at 1 mV resolution;
        // 0x97 must never be produced, or reset detection breaks.
        for variant in [Variant::Tps53647, Variant::Tps53667] {
            let lo = (variant.vout_min_v() * 1000.0) as u32;
            let hi = (variant.vout_max_v() * 1000.0) as u32;
            for mv in lo..=hi {
                if let Ok(vid) = vout_command(variant, mv as f32 / 1000.0) {
                    assert_ne!(
                        vid,
                        VID_ONE_VOLT,
                        "{} at {mv} mV emitted the reserved VID",
                        variant.name()
                    );
                }
            }
        }
    }

    #[test]
    fn one_volt_substitutes_downward_not_upward() {
        let vid = vout_command(Variant::Tps53647, 1.0).unwrap();
        assert_eq!(vid, VID_ONE_VOLT_SUBSTITUTE);
        assert!(
            vid_to_volts(vid) < 1.0,
            "substitution must undervolt, never overvolt"
        );
    }

    #[test]
    fn commandable_window_endpoints_encode() {
        for v in [Variant::Tps53647, Variant::Tps53667] {
            assert!(vout_command(v, v.vout_min_v()).is_ok());
            assert!(vout_command(v, v.vout_max_v()).is_ok());
        }
    }

    // ── VOUT readback uses a different encoding from VOUT command ─────────────

    #[test]
    fn vout_readback_is_ulinear16_not_vid() {
        // 1.2 V readback == 1.2 * 512 == 614.4 -> 614 raw.
        assert!((decode_vout_readback(614) - 1.199).abs() < 0.01);
        // The same raw value read as a VID would be nonsense; this test exists
        // so nobody "unifies" the two encodings.
        assert!((decode_vout_readback(512) - 1.0).abs() < 1e-6);
    }

    // ── Phase + current encoding ──────────────────────────────────────────────

    #[test]
    fn phase_register_is_count_minus_one() {
        assert_eq!(phase_register(Variant::Tps53647, 1), Ok(0));
        assert_eq!(phase_register(Variant::Tps53647, 4), Ok(3));
        assert_eq!(phase_register(Variant::Tps53667, 6), Ok(5));
    }

    #[test]
    fn phase_register_rejects_counts_the_part_cannot_drive() {
        // A 6-phase profile on a '647 is the NerdOCTAXE-γ rev-mismatch case.
        assert_eq!(
            phase_register(Variant::Tps53647, 6),
            Err(Tps5364xConfigError::PhaseCountOutOfRange)
        );
        assert_eq!(
            phase_register(Variant::Tps53667, 0),
            Err(Tps5364xConfigError::PhaseCountOutOfRange)
        );
    }

    #[test]
    fn imax_register_rejects_values_that_would_truncate() {
        assert_eq!(imax_register(60), Ok(60));
        assert_eq!(imax_register(180), Ok(180));
        assert_eq!(imax_register(240), Ok(240));
        assert_eq!(imax_register(255), Ok(255));
        // Upstream's (uint8_t) cast would turn 300 A into 44 A.
        assert_eq!(imax_register(300), Err(Tps5364xConfigError::ImaxOutOfRange));
        assert_eq!(imax_register(0), Err(Tps5364xConfigError::ImaxOutOfRange));
    }

    #[test]
    fn an_over_current_trip_at_or_below_full_scale_is_accepted() {
        // The envelopes our rows declare: every one sits at or under its imax.
        for (imax, ifault) in [
            (60u16, 55.0f32), // NerdQAxe+  — 2 phases, upstream imax-5
            (90, 85.0),       // NerdQAxe++ — 3 phases, imax-5 (see below)
            (120, 105.0),     // NerdHaxe-γ — 4 phases, upstream value
            (240, 235.0),     // NerdEKO    — 6 phases, upstream value
        ] {
            assert!(
                check_iout_fault_limit(imax, ifault).is_ok(),
                "imax {imax} A / ifault {ifault} A should be accepted"
            );
        }
    }

    #[test]
    fn the_nerdqx_over_current_limit_is_refused_not_inherited() {
        // NerdQX sets imax = num_phases * 30 = 90 A and then computes ifault
        // through its own obfuscated decoder: (3 * 60) - 38 = 142 A. That trip
        // point is 58% ABOVE the current-sense full scale, so it can never
        // assert. Refusing it is the whole point of this check — if this test
        // ever starts passing the value, the protection has become decorative.
        let imax = 90u16;
        let ifault = 142.0f32;
        assert!(
            ifault > imax as f32,
            "the hazard premise itself: {ifault} A must be above the {imax} A scale"
        );
        assert_eq!(
            check_iout_fault_limit(imax, ifault),
            Err(Tps5364xConfigError::IoutFaultLimitAboveFullScale)
        );
    }

    #[test]
    fn the_nerdqaxepp_plus_five_pattern_is_also_refused() {
        // Not only NerdQX: upstream's NerdQAxe++ base sets `ifault = imax + 5`,
        // which is above full scale by the same argument, just by less. This is
        // recorded so nobody "fixes" the NerdQX case alone and leaves a whole
        // family of +5 A inert trips in place. Our rows must declare an ifault
        // at or below imax.
        assert_eq!(
            check_iout_fault_limit(90, 95.0),
            Err(Tps5364xConfigError::IoutFaultLimitAboveFullScale)
        );
    }

    #[test]
    fn a_non_positive_or_non_finite_trip_point_is_refused() {
        for bad in [0.0f32, -1.0, f32::NAN, f32::INFINITY] {
            assert_eq!(
                check_iout_fault_limit(90, bad),
                Err(Tps5364xConfigError::IoutFaultLimitOutOfRange),
                "{bad} is not a usable over-current threshold"
            );
        }
    }

    #[test]
    fn a_trip_exactly_at_full_scale_is_the_boundary_and_is_allowed() {
        assert!(check_iout_fault_limit(90, 90.0).is_ok());
        assert_eq!(
            check_iout_fault_limit(90, 90.0001),
            Err(Tps5364xConfigError::IoutFaultLimitAboveFullScale)
        );
    }

    #[test]
    fn operation_mode_matches_upstream_bytes() {
        assert_eq!(operation_mode(false), 0x89, "shedding disabled (OCTAXE-γ)");
        assert_eq!(operation_mode(true), 0x99, "shedding enabled (EKO)");
    }

    // ── Rail / domain relationship ────────────────────────────────────────────

    #[test]
    fn single_domain_rail_equals_per_asic_setpoint() {
        assert!((rail_voltage_v_for_domains(1200, 1) - 1.2).abs() < 1e-6);
    }

    #[test]
    fn multiplying_domains_multiplies_the_rail() {
        // This is the Lucky LV08 hazard restated for the Nerd rows: every
        // TPS5364x board is ASICs-in-parallel on ONE domain. If a board row ever
        // declares 2, the rail doubles onto parallel dies.
        assert!((rail_voltage_v_for_domains(1200, 2) - 2.4).abs() < 1e-6);
        assert!((rail_voltage_v_for_domains(1200, 3) - 3.6).abs() < 1e-6);
    }

    #[test]
    fn a_two_domain_rail_is_not_commandable_on_either_part() {
        // Belt and braces: even if a row were mis-declared, the part-level range
        // check refuses the resulting rail, so the mistake cannot reach silicon
        // through this driver.
        let rail = rail_voltage_v_for_domains(1200, 2);
        for v in [Variant::Tps53647, Variant::Tps53667] {
            assert_eq!(
                vout_command(v, rail),
                Err(Tps5364xConfigError::VoltageOutOfRange),
                "{} accepted a 2-domain rail",
                v.name()
            );
        }
    }

    // ── Register map pins ─────────────────────────────────────────────────────

    #[test]
    fn device_code_register_is_mfr_specific_44() {
        // Guards against a copy-paste swap with MFR_SPECIFIC_04 (VOUT readback),
        // which would make identity checks read a voltage.
        assert_eq!(reg::MFR_SPECIFIC_44, 0xFC);
        assert_eq!(reg::MFR_SPECIFIC_04, 0xD4);
        assert_ne!(reg::MFR_SPECIFIC_44, reg::MFR_SPECIFIC_04);
    }

    #[test]
    fn vout_command_register_is_not_the_readback_register() {
        assert_eq!(reg::VOUT_COMMAND, 0x21);
        assert_ne!(reg::VOUT_COMMAND, reg::MFR_SPECIFIC_04);
    }
}
