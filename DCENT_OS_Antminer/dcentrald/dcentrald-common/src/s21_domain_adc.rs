//! S21 domain ADC scale converters (default-off; log volts OK).
//!
//! Source of truth:
//!
//! - Desk: `S21_VCO_DUALCHAIN_DESK.md` §8 ADDENDUM
//!
//! `domain_adc_scale` is CLOSED for Daemon conversion (path A / A′ / B).
//! Climb / autotune stay `enabled=false` until sealed per-SKU F/V envelopes
//! and wall/board power telemetry admit rails exist. These converters do
//! **not** enable climb. Do **not** invent vmin/vmax from fixture Sweep /
//! Test_Loop.

/// Desk/Daemon marker: scale formulas are closed and converters are available.
pub const S21_DOMAIN_ADC_SCALE_CLOSED: bool = true;

/// Domain ADC register index (reg 189).
pub const S21_DOMAIN_ADC_REG: u32 = 189;
/// Keep lower 15 bits after bit31 validity gate.
pub const S21_DOMAIN_ADC_RAW_MASK: u32 = 0x7FFF;
/// Validity gate: bit31 must be set.
pub const S21_DOMAIN_ADC_VALID_BIT: u32 = 1 << 31;

/// Upward power-admit helpers must require wall/board telemetry.
pub const S21_REQUIRE_POWER_TELEMETRY: bool = true;

#[derive(Debug, Clone, PartialEq)]
pub enum S21DomainAdcError {
    InvalidAdcSample { reg189: u32 },
    ZeroSampleRejectsAvg,
    MissingWallBoardTelemetry,
    ClimbMustStayDisabled,
    AutotuneMustStayDisabled,
    SealedEnvelopeRequired,
}

impl core::fmt::Display for S21DomainAdcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidAdcSample { reg189 } => write!(
                f,
                "S21 domain ADC: reg189=0x{reg189:08x} missing bit31 validity"
            ),
            Self::ZeroSampleRejectsAvg => {
                write!(f, "S21 domain ADC: zero sample (== 0.0) rejects average")
            }
            Self::MissingWallBoardTelemetry => write!(
                f,
                "S21 domain ADC: refuse upward admit without wall/board power telemetry"
            ),
            Self::ClimbMustStayDisabled => {
                write!(f, "S21 domain ADC: domain climb path must stay disabled")
            }
            Self::AutotuneMustStayDisabled => {
                write!(f, "S21 domain ADC: autotune must stay disabled")
            }
            Self::SealedEnvelopeRequired => write!(
                f,
                "S21 domain ADC: climb/autotune require sealed F/V envelope + power telemetry — do not invent"
            ),
        }
    }
}

/// Extract raw domain ADC from reg189. Requires bit31; returns `& 0x7FFF`.
pub fn domain_adc_raw(reg189: u32) -> Result<u16, S21DomainAdcError> {
    if reg189 & S21_DOMAIN_ADC_VALID_BIT == 0 {
        return Err(S21DomainAdcError::InvalidAdcSample { reg189 });
    }
    Ok((reg189 & S21_DOMAIN_ADC_RAW_MASK) as u16)
}

/// Path A (BM1370 avg / `adc_get_domain_voltage` family):
/// `V = raw / 2048.0 / 8.0 - 1.0`
pub fn path_a_bm1370_volts(raw: u16) -> f64 {
    (raw as f64) / 2048.0 / 8.0 - 1.0
}

/// Path A′: if `domain_index > 1`, `V *= 2` (same as `V + V`).
pub fn path_a_prime_scale(volts: f64, domain_index: u32) -> f64 {
    if domain_index > 1 {
        volts * 2.0
    } else {
        volts
    }
}

/// Path A + A′ from a reg189 sample and domain index.
pub fn path_a_domain_volts(reg189: u32, domain_index: u32) -> Result<f64, S21DomainAdcError> {
    let raw = domain_adc_raw(reg189)?;
    let v = path_a_bm1370_volts(raw);
    Ok(path_a_prime_scale(v, domain_index))
}

/// Path B (BM1368 register-189 → `asic_val` ONLY):
/// `V = (raw / 2048.0 / 8.0 - 1.0) * 0.6`
/// Never apply 0.6 to Path A.
pub fn path_b_bm1368_reg_volts(reg189: u32) -> Result<f64, S21DomainAdcError> {
    let raw = domain_adc_raw(reg189)?;
    Ok(path_a_bm1370_volts(raw) * 0.6)
}

/// Average domain volts; any sample `== 0.0` aborts.
pub fn avg_domain_volts(samples_volts: &[f64]) -> Result<f64, S21DomainAdcError> {
    if samples_volts.is_empty() {
        return Err(S21DomainAdcError::ZeroSampleRejectsAvg);
    }
    for &v in samples_volts {
        if v == 0.0 {
            return Err(S21DomainAdcError::ZeroSampleRejectsAvg);
        }
    }
    let sum: f64 = samples_volts.iter().sum();
    Ok(sum / (samples_volts.len() as f64))
}

/// Inputs for upward power admit (domain convert available; climb stays off).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UpwardPowerAdmitRequest {
    pub wall_telemetry_present: bool,
    pub board_telemetry_present: bool,
    pub climb_requested: bool,
    pub autotune_requested: bool,
}

/// Admit upward power only when wall/board telemetry are present and climb/
/// autotune are not requested. `require_power_telemetry` is always true.
/// Converters do not enable climb; sealed F/V envelopes remain DESK_PENDING.
pub fn admit_upward_power(req: &UpwardPowerAdmitRequest) -> Result<(), S21DomainAdcError> {
    debug_assert!(S21_REQUIRE_POWER_TELEMETRY);
    if !S21_REQUIRE_POWER_TELEMETRY {
        return Err(S21DomainAdcError::MissingWallBoardTelemetry);
    }
    if req.climb_requested {
        return Err(S21DomainAdcError::ClimbMustStayDisabled);
    }
    if req.autotune_requested {
        return Err(S21DomainAdcError::AutotuneMustStayDisabled);
    }
    if !req.wall_telemetry_present || !req.board_telemetry_present {
        return Err(S21DomainAdcError::MissingWallBoardTelemetry);
    }
    // Domain volts convert is available, but board-rail admit envelopes
    // (sealed vmin/vmax / F envelope) remain open — refuse climb enablement.
    Err(S21DomainAdcError::SealedEnvelopeRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_closed_marker() {
        assert!(S21_DOMAIN_ADC_SCALE_CLOSED);
        assert_eq!(S21_DOMAIN_ADC_REG, 189);
        assert_eq!(S21_DOMAIN_ADC_RAW_MASK, 0x7FFF);
        assert_eq!(S21_DOMAIN_ADC_VALID_BIT, 1 << 31);
        assert!(S21_REQUIRE_POWER_TELEMETRY);
    }

    #[test]
    fn bit31_invalid_refuse() {
        // raw would be 24576 but bit31 clear → refuse
        assert!(matches!(
            domain_adc_raw(24576),
            Err(S21DomainAdcError::InvalidAdcSample { .. })
        ));
        assert!(matches!(
            path_a_domain_volts(24576, 0),
            Err(S21DomainAdcError::InvalidAdcSample { .. })
        ));
        assert!(matches!(
            path_b_bm1368_reg_volts(24576),
            Err(S21DomainAdcError::InvalidAdcSample { .. })
        ));
    }

    #[test]
    fn path_a_math_known_volts() {
        // raw = 24576 = 2048 * 12 → V = 12/8 - 1 = 0.5
        let raw = 24576u16;
        assert!((path_a_bm1370_volts(raw) - 0.5).abs() < 1e-12);
        let reg = S21_DOMAIN_ADC_VALID_BIT | (raw as u32);
        assert_eq!(domain_adc_raw(reg).unwrap(), raw);
        assert!((path_a_domain_volts(reg, 0).unwrap() - 0.5).abs() < 1e-12);
        assert!((path_a_domain_volts(reg, 1).unwrap() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn path_a_prime_domain_index_scale() {
        let v = 0.5;
        assert!((path_a_prime_scale(v, 0) - 0.5).abs() < 1e-12);
        assert!((path_a_prime_scale(v, 1) - 0.5).abs() < 1e-12);
        assert!((path_a_prime_scale(v, 2) - 1.0).abs() < 1e-12);
        assert!((path_a_prime_scale(v, 3) - 1.0).abs() < 1e-12);
        let reg = S21_DOMAIN_ADC_VALID_BIT | 24576;
        assert!((path_a_domain_volts(reg, 2).unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn path_b_applies_0_6_path_a_does_not() {
        // Path A: 0.5; Path B: 0.5 * 0.6 = 0.3
        let reg = S21_DOMAIN_ADC_VALID_BIT | 24576;
        let a = path_a_domain_volts(reg, 0).unwrap();
        let b = path_b_bm1368_reg_volts(reg).unwrap();
        assert!((a - 0.5).abs() < 1e-12);
        assert!((b - 0.3).abs() < 1e-12);
        // Explicit: Path A must not silently include 0.6
        assert!((a - b).abs() > 0.1);
    }

    #[test]
    fn zero_sample_rejects_avg() {
        assert!(matches!(
            avg_domain_volts(&[1.5, 0.0, 1.25]),
            Err(S21DomainAdcError::ZeroSampleRejectsAvg)
        ));
        assert!(matches!(
            avg_domain_volts(&[]),
            Err(S21DomainAdcError::ZeroSampleRejectsAvg)
        ));
        assert!((avg_domain_volts(&[1.5, 1.0, 0.5]).unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn upward_admit_refuses_without_telemetry_climb_stays_off() {
        assert!(matches!(
            admit_upward_power(&UpwardPowerAdmitRequest {
                wall_telemetry_present: false,
                board_telemetry_present: true,
                climb_requested: false,
                autotune_requested: false,
            }),
            Err(S21DomainAdcError::MissingWallBoardTelemetry)
        ));
        assert!(matches!(
            admit_upward_power(&UpwardPowerAdmitRequest {
                wall_telemetry_present: true,
                board_telemetry_present: false,
                climb_requested: false,
                autotune_requested: false,
            }),
            Err(S21DomainAdcError::MissingWallBoardTelemetry)
        ));
        assert!(matches!(
            admit_upward_power(&UpwardPowerAdmitRequest {
                wall_telemetry_present: true,
                board_telemetry_present: true,
                climb_requested: true,
                autotune_requested: false,
            }),
            Err(S21DomainAdcError::ClimbMustStayDisabled)
        ));
        assert!(matches!(
            admit_upward_power(&UpwardPowerAdmitRequest {
                wall_telemetry_present: true,
                board_telemetry_present: true,
                climb_requested: false,
                autotune_requested: true,
            }),
            Err(S21DomainAdcError::AutotuneMustStayDisabled)
        ));
        // Telemetry present and climb off — still refuse: sealed F/V open.
        assert!(matches!(
            admit_upward_power(&UpwardPowerAdmitRequest {
                wall_telemetry_present: true,
                board_telemetry_present: true,
                climb_requested: false,
                autotune_requested: false,
            }),
            Err(S21DomainAdcError::SealedEnvelopeRequired)
        ));
    }
}
