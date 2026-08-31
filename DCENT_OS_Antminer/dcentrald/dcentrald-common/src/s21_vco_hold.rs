//! S21 VCO / domain climb HOLD pin (verify-only).
//!
//! Source:
//!
//!
//!
//!
//! Keep `pll_vco_clamp_mode=jig_clamp` and autotune `enabled=false`.
//! Wire admit helpers for quoted jig VCO window (2000–3200, ≤3125 @ refdiv1);
//! reject program attempts outside 1600–3200.
//!
//! Domain ADC scale converters are CLOSED (`s21_domain_adc` path A / A′ / B);
//! log volts OK. Climb/autotune stay **false** until sealed per-SKU F/V
//! envelopes + wall/board power-telemetry rails exist — converters do not
//! enable climb. Do not invent vmin/vmax from fixture Sweep/Test_Loop.
//!
//! ADDENDUM (Lead): same jig_clamp windows reuse across public jigs
//! `S21xp` / `S21xp-hydro` / `U3S21EXPH`. bmminer `hw_threshold` *structure*
//! confirmed (float @ basic+0x1c / fine+0x2c; stop when
//! `hw > (asics×cores×8)×float`) — numeric default stays DESK_PENDING;
//! do not invent a float. Climb/autotune stay off.

/// Profile string Lead directed: jig_clamp.
pub const S21_PLL_VCO_CLAMP_MODE: &str = "jig_clamp";
/// Autotune must stay disabled until sealed F/V envelopes + wall/board rails desk-closed.
pub const S21_AUTOTUNE_ENABLED: bool = false;
/// Domain climb path must not be enabled from this pin.
pub const S21_DOMAIN_CLIMB_ENABLED: bool = false;

/// Quoted `get_pllparam_divider` search clamp (S21 / S21pro public .dec).
pub const S21_VCO_SEARCH_MIN_MHZ: f64 = 2000.0;
pub const S21_VCO_SEARCH_MAX_MHZ: f64 = 3200.0;
/// Extra ceiling when `refdiv == 1`.
pub const S21_VCO_SEARCH_MAX_REFDIV1_MHZ: f64 = 3125.0;
/// `set_pllparameter` absolute program window.
pub const S21_VCO_PROGRAM_MIN_MHZ: f64 = 1600.0;
pub const S21_VCO_PROGRAM_MAX_MHZ: f64 = 3200.0;
/// Encode band split: [1600,2400) clears bit; [2400,3200] sets `0x10000000`.
pub const S21_VCO_ENCODE_BAND_SPLIT_MHZ: f64 = 2400.0;
pub const S21_VCO_ENCODE_HIGH_BIT: u32 = 0x1000_0000;
/// Public fixture Most_HW_Num (metric only; not bmminer hw_threshold).
pub const S21_MOST_HW_NUM_FIXTURE: u16 = 128;
/// Domain ADC scale desk work is closed (converters in `s21_domain_adc`).
/// Kept as `false` so callers stop treating scale as the climb blocker.
pub const S21_DOMAIN_ADC_SCALE_DESK_PENDING: bool = false;

/// Public jig SKUs that share the same jig_clamp VCO windows (Lead ADDENDUM).
pub const S21_JIG_CLAMP_REUSE_SKUS: &[&str] = &["S21xp", "S21xp-hydro", "U3S21EXPH"];

/// bmminer hw_threshold *structure* (Lead ADDENDUM) — offsets only.
/// Numeric float default is DESK_PENDING; never invent one.
pub const S21_HW_THRESHOLD_BASIC_FLOAT_OFF: usize = 0x1c;
pub const S21_HW_THRESHOLD_FINE_FLOAT_OFF: usize = 0x2c;
/// Multiplier in stop predicate: hw > (asics × cores × N) × float.
pub const S21_HW_THRESHOLD_CORE_FACTOR: u32 = 8;
/// Honest desk state: numeric hw_threshold float default still DESK_PENDING.
pub const S21_HW_THRESHOLD_FLOAT_DEFAULT_DESK_PENDING: bool = true;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct S21VcoHoldProfile {
    pub pll_vco_clamp_mode: &'static str,
    pub autotune_enabled: bool,
    pub domain_climb_enabled: bool,
    pub domain_adc_scale_desk_pending: bool,
}

pub const S21_VCO_HOLD: S21VcoHoldProfile = S21VcoHoldProfile {
    pll_vco_clamp_mode: S21_PLL_VCO_CLAMP_MODE,
    autotune_enabled: S21_AUTOTUNE_ENABLED,
    domain_climb_enabled: S21_DOMAIN_CLIMB_ENABLED,
    domain_adc_scale_desk_pending: S21_DOMAIN_ADC_SCALE_DESK_PENDING,
};

#[derive(Debug, Clone, PartialEq)]
pub enum S21VcoHoldError {
    AutotuneMustStayDisabled,
    DomainClimbMustStayDisabled,
    ClampModeMustBeJigClamp {
        observed: String,
    },
    /// Climb/autotune refuse: sealed F/V + power telemetry still required.
    SealedFvEnvelopeRequired,
    HwThresholdFloatDefaultDeskPending,
    VcoOutsideSearchClamp {
        vco_mhz: f64,
        refdiv: u32,
    },
    VcoOutsideProgramWindow {
        vco_mhz: f64,
    },
}

impl core::fmt::Display for S21VcoHoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AutotuneMustStayDisabled => {
                write!(f, "S21 VCO hold: autotune enabled must stay false")
            }
            Self::DomainClimbMustStayDisabled => {
                write!(f, "S21 VCO hold: domain climb path must stay disabled")
            }
            Self::ClampModeMustBeJigClamp { observed } => write!(
                f,
                "S21 VCO hold: pll_vco_clamp_mode must be jig_clamp (observed {observed:?})"
            ),
            Self::SealedFvEnvelopeRequired => write!(
                f,
                "S21 VCO hold: climb/autotune must stay disabled — sealed F/V envelope + wall/board power telemetry required (do not invent)"
            ),
            Self::HwThresholdFloatDefaultDeskPending => write!(
                f,
                "S21 VCO hold: hw_threshold float default DESK_PENDING — do not invent"
            ),
            Self::VcoOutsideSearchClamp { vco_mhz, refdiv } => write!(
                f,
                "S21 VCO hold: VCO {vco_mhz} MHz outside jig_clamp search (refdiv={refdiv})"
            ),
            Self::VcoOutsideProgramWindow { vco_mhz } => write!(
                f,
                "S21 VCO hold: VCO {vco_mhz} MHz outside program window 1600..=3200"
            ),
        }
    }
}

/// Verify hold latch — jig_clamp + autotune/climb off.
pub fn verify_s21_vco_hold(profile: &S21VcoHoldProfile) -> Result<(), S21VcoHoldError> {
    if profile.pll_vco_clamp_mode != "jig_clamp" {
        return Err(S21VcoHoldError::ClampModeMustBeJigClamp {
            observed: profile.pll_vco_clamp_mode.to_string(),
        });
    }
    if profile.autotune_enabled {
        return Err(S21VcoHoldError::AutotuneMustStayDisabled);
    }
    if profile.domain_climb_enabled {
        return Err(S21VcoHoldError::DomainClimbMustStayDisabled);
    }
    Ok(())
}

/// jig_clamp search admit: 2000..=3200, and if refdiv==1 also <=3125.
pub fn admit_jig_clamp_search_vco(vco_mhz: f64, refdiv: u32) -> Result<(), S21VcoHoldError> {
    let mut max = S21_VCO_SEARCH_MAX_MHZ;
    if refdiv == 1 {
        max = S21_VCO_SEARCH_MAX_REFDIV1_MHZ;
    }
    if vco_mhz < S21_VCO_SEARCH_MIN_MHZ || vco_mhz > max {
        return Err(S21VcoHoldError::VcoOutsideSearchClamp { vco_mhz, refdiv });
    }
    Ok(())
}

/// Reject program attempts outside absolute 1600..=3200 window.
pub fn admit_jig_clamp_program_vco(vco_mhz: f64) -> Result<(), S21VcoHoldError> {
    if vco_mhz < S21_VCO_PROGRAM_MIN_MHZ || vco_mhz > S21_VCO_PROGRAM_MAX_MHZ {
        return Err(S21VcoHoldError::VcoOutsideProgramWindow { vco_mhz });
    }
    Ok(())
}

/// Encode-band hint from `set_pllparameter` (no MMIO write).
pub fn jig_clamp_encode_high_band(vco_mhz: f64) -> Result<bool, S21VcoHoldError> {
    admit_jig_clamp_program_vco(vco_mhz)?;
    Ok(vco_mhz >= S21_VCO_ENCODE_BAND_SPLIT_MHZ)
}

/// True when `sku` is in the Lead-listed public jig reuse set.
pub fn jig_clamp_windows_apply_to_sku(sku: &str) -> bool {
    S21_JIG_CLAMP_REUSE_SKUS.iter().any(|s| *s == sku)
}

/// Stop predicate structure only: `hw > (asics × cores × 8) × threshold_float`.
/// Caller must supply an evidenced float — refuse if default is still pending
/// and no explicit float is provided (`threshold_float = None`).
pub fn hw_threshold_stop(
    hw: f64,
    asics: u32,
    cores: u32,
    threshold_float: Option<f64>,
) -> Result<bool, S21VcoHoldError> {
    let Some(tf) = threshold_float else {
        if S21_HW_THRESHOLD_FLOAT_DEFAULT_DESK_PENDING {
            return Err(S21VcoHoldError::HwThresholdFloatDefaultDeskPending);
        }
        return Err(S21VcoHoldError::HwThresholdFloatDefaultDeskPending);
    };
    let limit = (asics as f64) * (cores as f64) * (S21_HW_THRESHOLD_CORE_FACTOR as f64) * tf;
    Ok(hw > limit)
}

/// Explicit refuse if a caller tries to enable domain / VCO climb / autotune.
/// Always refuses: ADC scale being closed does **not** enable climb.
/// Fail-closed on sealed F/V envelope + wall/board power telemetry.
pub fn refuse_s21_domain_climb(
    autotune_enabled: bool,
    domain_climb_enabled: bool,
) -> Result<(), S21VcoHoldError> {
    if autotune_enabled {
        return Err(S21VcoHoldError::AutotuneMustStayDisabled);
    }
    if domain_climb_enabled {
        return Err(S21VcoHoldError::DomainClimbMustStayDisabled);
    }
    // Scale converters closed; climb still blocked on sealed F/V + telemetry.
    let _scale_closed = !S21_DOMAIN_ADC_SCALE_DESK_PENDING;
    Err(S21VcoHoldError::SealedFvEnvelopeRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_profile_is_jig_clamp_autotune_off() {
        assert_eq!(S21_PLL_VCO_CLAMP_MODE, "jig_clamp");
        assert!(!S21_AUTOTUNE_ENABLED);
        assert!(!S21_DOMAIN_CLIMB_ENABLED);
        assert!(!S21_DOMAIN_ADC_SCALE_DESK_PENDING);
        assert_eq!(S21_MOST_HW_NUM_FIXTURE, 128);
        assert!(verify_s21_vco_hold(&S21_VCO_HOLD).is_ok());
    }

    #[test]
    fn jig_clamp_search_and_program_windows() {
        assert!(admit_jig_clamp_search_vco(2000.0, 2).is_ok());
        assert!(admit_jig_clamp_search_vco(3200.0, 2).is_ok());
        assert!(admit_jig_clamp_search_vco(3125.0, 1).is_ok());
        assert!(matches!(
            admit_jig_clamp_search_vco(3126.0, 1),
            Err(S21VcoHoldError::VcoOutsideSearchClamp { .. })
        ));
        assert!(matches!(
            admit_jig_clamp_search_vco(1999.0, 2),
            Err(S21VcoHoldError::VcoOutsideSearchClamp { .. })
        ));
        assert!(admit_jig_clamp_program_vco(1600.0).is_ok());
        assert!(admit_jig_clamp_program_vco(3200.0).is_ok());
        assert!(matches!(
            admit_jig_clamp_program_vco(1599.0),
            Err(S21VcoHoldError::VcoOutsideProgramWindow { .. })
        ));
        assert_eq!(jig_clamp_encode_high_band(2399.0).unwrap(), false);
        assert_eq!(jig_clamp_encode_high_band(2400.0).unwrap(), true);
        assert_eq!(S21_VCO_ENCODE_HIGH_BIT, 0x1000_0000);
    }

    #[test]
    fn refuse_climb_and_autotune_enablement() {
        assert!(matches!(
            refuse_s21_domain_climb(true, false),
            Err(S21VcoHoldError::AutotuneMustStayDisabled)
        ));
        assert!(matches!(
            refuse_s21_domain_climb(false, true),
            Err(S21VcoHoldError::DomainClimbMustStayDisabled)
        ));
        assert!(matches!(
            refuse_s21_domain_climb(false, false),
            Err(S21VcoHoldError::SealedFvEnvelopeRequired)
        ));
        let bad = S21VcoHoldProfile {
            pll_vco_clamp_mode: "unclamped",
            ..S21_VCO_HOLD
        };
        assert!(matches!(
            verify_s21_vco_hold(&bad),
            Err(S21VcoHoldError::ClampModeMustBeJigClamp { .. })
        ));
    }

    #[test]
    fn addendum_sku_reuse_and_hw_threshold_structure() {
        assert!(jig_clamp_windows_apply_to_sku("S21xp"));
        assert!(jig_clamp_windows_apply_to_sku("S21xp-hydro"));
        assert!(jig_clamp_windows_apply_to_sku("U3S21EXPH"));
        assert!(!jig_clamp_windows_apply_to_sku("S19k"));
        assert_eq!(S21_HW_THRESHOLD_BASIC_FLOAT_OFF, 0x1c);
        assert_eq!(S21_HW_THRESHOLD_FINE_FLOAT_OFF, 0x2c);
        assert_eq!(S21_HW_THRESHOLD_CORE_FACTOR, 8);
        assert!(S21_HW_THRESHOLD_FLOAT_DEFAULT_DESK_PENDING);
        assert!(matches!(
            hw_threshold_stop(1.0, 1, 1, None),
            Err(S21VcoHoldError::HwThresholdFloatDefaultDeskPending)
        ));
        // Structure check with an explicit (caller-supplied) float — not a default.
        assert_eq!(hw_threshold_stop(9.0, 1, 1, Some(1.0)).unwrap(), true); // 9 > 8
        assert_eq!(hw_threshold_stop(8.0, 1, 1, Some(1.0)).unwrap(), false);
    }
}
