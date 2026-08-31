//! Fail-closed PSU routing rows with no SET-voltage authority.
//!
//! The silicon-profiles catalog (`dcentrald_silicon_profiles::psus`) is the
//! fleet SoT. This HAL module is the host-testable refuse surface for rows
//! that must not encode or send a voltage SET (desk-now 2026-08-19 rank 17).
//!
//! APW8: first-party guide documents I²C PIC + EN active-low on S15/T15.
//! Opcode/LSB is unbound (`conversion_units_verified=false`). Do not invent
//! a millivolt scale. No GPIO907↔PWR_EN join.

use crate::{HalError, Result};

/// Routing keys that exist so dispatch can fail closed instead of omitting
/// the family. None of these grant a shipped SET backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailClosedPsuRoute {
    /// APW8 — S15 / T15. Guide I²C PIC; opcode/LSB unbound.
    Apw8,
}

/// One fail-closed routing row. Numbers that would require an invented LSB
/// stay unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailClosedPsuRouteEntry {
    pub model: &'static str,
    pub used_in: &'static [&'static str],
    pub protocol: &'static str,
    pub control_binding: &'static str,
    pub set_voltage_authorized: bool,
    pub i2c_address: Option<u8>,
    pub enable_gpio: Option<u32>,
}

impl FailClosedPsuRoute {
    /// Catalog row for this fail-closed family.
    pub const fn catalog(self) -> FailClosedPsuRouteEntry {
        match self {
            Self::Apw8 => FailClosedPsuRouteEntry {
                model: "APW8",
                used_in: &["S15", "T15"],
                protocol: "apw8_unspecified_i2c",
                control_binding: "none_unimplemented",
                set_voltage_authorized: false,
                // Software observation 0x10 exists in bm1391 evidence; it is
                // not a bound production address. Leave None so dispatch
                // cannot probe.
                i2c_address: None,
                enable_gpio: None,
            },
        }
    }

    /// SET voltage is refused. No opcode, no LSB, no I/O.
    pub fn set_voltage_mv(self, mv: u16) -> Result<()> {
        let _ = mv;
        Err(HalError::PsuProtocolOwned(format!(
            "{} SET_VOLTAGE refused: fail-closed routing row (desk-now 2026-08-19); opcode/LSB unbound",
            self.catalog().model
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apw8_routing_row_is_fail_closed_and_has_no_set() {
        let row = FailClosedPsuRoute::Apw8.catalog();
        assert_eq!(row.model, "APW8");
        assert_eq!(row.used_in, &["S15", "T15"]);
        assert_eq!(row.protocol, "apw8_unspecified_i2c");
        assert_eq!(row.control_binding, "none_unimplemented");
        assert!(!row.set_voltage_authorized);
        assert_eq!(row.i2c_address, None);
        assert_eq!(row.enable_gpio, None);
        let err = FailClosedPsuRoute::Apw8
            .set_voltage_mv(16320)
            .expect_err("APW8 must not SET");
        let rendered = err.to_string();
        assert!(rendered.contains("APW8 SET_VOLTAGE refused"), "{rendered}");
        assert!(rendered.contains("opcode/LSB unbound"), "{rendered}");
    }
}
