//! Universal measurement provenance (decade backlog P2-3).
//!
//! # Why
//!
//! Telemetry historically mixed commanded setpoints, modeled estimates, and
//! genuine sensor readbacks under bare numeric fields. Downstream UIs and
//! autotune loops then treated a commanded DAC value as if it were a measured
//! rail, or a profile default as if it were live. The rail-voltage resolver in
//! [`crate::chain_voltage`] already has the right vocabulary for one domain;
//! this module generalizes that honesty to **any** quantity.
//!
//! # Status
//!
//! **Production-ready pure types** for new surfaces. Existing wire tags
//! (`measured` / `commanded_not_measured` / …) remain stable; new code should
//! carry a [`Measurement`] rather than inventing parallel enums.
//!
//! HAL-free and host-testable.

use crate::chain_voltage::RailVoltageSource;

/// How a numeric (or structured) value was obtained.
///
/// Wire tags match the existing rail-voltage / dashboard vocabulary where
/// applicable so fleet clients can share one decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeasurementProvenance {
    /// Live sensor / controller readback of the physical quantity.
    Measured,
    /// Open-loop setpoint or last commanded value (not a sensor).
    CommandedNotMeasured,
    /// Chip/board profile default before any command or measure.
    CommandedDefault,
    /// Derived from a model (J/TH estimate, projected power, etc.).
    Modeled,
    /// Explicit unknown — never fabricate zero as "measured".
    Unknown,
}

impl MeasurementProvenance {
    /// Canonical wire tag (stable for API / logs).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::CommandedNotMeasured => "commanded_not_measured",
            Self::CommandedDefault => "commanded_default",
            Self::Modeled => "modeled",
            Self::Unknown => "unknown",
        }
    }

    /// True only for a genuine sensor/controller readback.
    pub const fn is_measured(self) -> bool {
        matches!(self, Self::Measured)
    }

    /// True when a closed-loop controller may treat the value as physical truth.
    pub const fn is_physical_truth(self) -> bool {
        matches!(self, Self::Measured)
    }

    /// Map from the AT-1 rail-voltage vocabulary without losing meaning.
    pub const fn from_rail_source(src: RailVoltageSource) -> Self {
        match src {
            RailVoltageSource::Measured => Self::Measured,
            RailVoltageSource::CommandedNotMeasured => Self::CommandedNotMeasured,
            RailVoltageSource::CommandedDefault => Self::CommandedDefault,
            RailVoltageSource::Unknown => Self::Unknown,
        }
    }

    /// Convert into the rail-voltage vocabulary when the quantity is a rail.
    ///
    /// [`MeasurementProvenance::Modeled`] has no rail-voltage peer — maps to
    /// [`RailVoltageSource::Unknown`] so a modeled estimate is never labelled
    /// measured or commanded.
    pub const fn to_rail_source(self) -> RailVoltageSource {
        match self {
            Self::Measured => RailVoltageSource::Measured,
            Self::CommandedNotMeasured => RailVoltageSource::CommandedNotMeasured,
            Self::CommandedDefault => RailVoltageSource::CommandedDefault,
            Self::Modeled | Self::Unknown => RailVoltageSource::Unknown,
        }
    }
}

/// A value plus how it was obtained (and optional age).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measurement<T> {
    /// The quantity (caller units — mV, °C×10, RPM, W, …).
    pub value: T,
    /// Provenance of `value`.
    pub provenance: MeasurementProvenance,
    /// Optional monotonic age in milliseconds since observation (None = unknown).
    pub age_ms: Option<u64>,
}

impl<T> Measurement<T> {
    /// Construct a measured observation.
    pub const fn measured(value: T) -> Self {
        Self {
            value,
            provenance: MeasurementProvenance::Measured,
            age_ms: None,
        }
    }

    /// Construct a commanded-not-measured setpoint.
    pub const fn commanded(value: T) -> Self {
        Self {
            value,
            provenance: MeasurementProvenance::CommandedNotMeasured,
            age_ms: None,
        }
    }

    /// Construct a profile-default value.
    pub const fn defaulted(value: T) -> Self {
        Self {
            value,
            provenance: MeasurementProvenance::CommandedDefault,
            age_ms: None,
        }
    }

    /// Construct a modeled estimate.
    pub const fn modeled(value: T) -> Self {
        Self {
            value,
            provenance: MeasurementProvenance::Modeled,
            age_ms: None,
        }
    }

    /// Explicit unknown (value is present only as a placeholder for type continuity).
    pub const fn unknown(value: T) -> Self {
        Self {
            value,
            provenance: MeasurementProvenance::Unknown,
            age_ms: None,
        }
    }

    /// Attach observation age.
    pub const fn with_age_ms(mut self, age_ms: u64) -> Self {
        self.age_ms = Some(age_ms);
        self
    }

    /// Map the inner value while keeping provenance and age.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Measurement<U> {
        Measurement {
            value: f(self.value),
            provenance: self.provenance,
            age_ms: self.age_ms,
        }
    }

    /// Prefer this measured value over `fallback` when provenance is measured.
    pub fn or_if_not_measured(self, fallback: Measurement<T>) -> Measurement<T> {
        if self.provenance.is_measured() {
            self
        } else {
            fallback
        }
    }
}

/// Prefer a measured observation; otherwise keep the fallback (with its tags).
///
/// This is the generic form of AT-1 "measured beats commanded" without domain
/// knowledge of millivolts.
pub fn prefer_measured<T>(primary: Measurement<T>, fallback: Measurement<T>) -> Measurement<T> {
    if primary.provenance.is_measured() {
        primary
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_tags_match_rail_vocabulary() {
        assert_eq!(MeasurementProvenance::Measured.as_str(), "measured");
        assert_eq!(
            MeasurementProvenance::CommandedNotMeasured.as_str(),
            "commanded_not_measured"
        );
        assert_eq!(
            MeasurementProvenance::CommandedDefault.as_str(),
            "commanded_default"
        );
        assert_eq!(MeasurementProvenance::Unknown.as_str(), "unknown");
        assert_eq!(MeasurementProvenance::Modeled.as_str(), "modeled");
    }

    #[test]
    fn rail_roundtrip_preserves_non_modeled() {
        for src in [
            RailVoltageSource::Measured,
            RailVoltageSource::CommandedNotMeasured,
            RailVoltageSource::CommandedDefault,
            RailVoltageSource::Unknown,
        ] {
            let p = MeasurementProvenance::from_rail_source(src);
            assert_eq!(p.to_rail_source(), src);
        }
    }

    #[test]
    fn modeled_never_maps_to_measured_rail() {
        let rail = MeasurementProvenance::Modeled.to_rail_source();
        assert_eq!(rail, RailVoltageSource::Unknown);
        assert!(!MeasurementProvenance::Modeled.is_physical_truth());
    }

    #[test]
    fn prefer_measured_beats_commanded() {
        let m = Measurement::measured(12_500u16);
        let c = Measurement::commanded(13_700u16);
        let chosen = prefer_measured(m, c);
        assert_eq!(chosen.value, 12_500);
        assert!(chosen.provenance.is_measured());
    }

    #[test]
    fn prefer_measured_keeps_fallback_when_primary_not_measured() {
        let c = Measurement::commanded(13_700u16);
        let d = Measurement::defaulted(12_000u16);
        let chosen = prefer_measured(c, d);
        assert_eq!(chosen.value, 12_000);
        assert_eq!(chosen.provenance, MeasurementProvenance::CommandedDefault);
    }

    #[test]
    fn map_preserves_provenance_and_age() {
        let m = Measurement::measured(49u16).with_age_ms(100);
        let f = m.map(|c| c as f32 / 10.0);
        assert!((f.value - 4.9).abs() < f32::EPSILON);
        assert_eq!(f.provenance, MeasurementProvenance::Measured);
        assert_eq!(f.age_ms, Some(100));
    }
}
