//! S9 SE address-assignment program (desk-only).
//!
//! Issue #2 last-chip addr `0x78` = 60 chips × stride 2. S9k
//! `init_address_info` uses interval 4 — do not copy that onto S9 SE.
//! Classic `am1-s9` is 63 × BM1387 — do not copy that either.
//!
//! This module builds the *sequence of frames*. It does not write BC
//! buffers and does not treat enum as mining.

use crate::s9se_vil::{pack_chain_inactive_vil, pack_set_address_vil};
use crate::serial_chain_proof::{
    ChainCoverageCertificate, ChainCoverageError, PacedEnumerationPolicy,
};

pub const S9SE_CHIPS_PER_CHAIN: u8 = 60;
pub const S9SE_ADDR_INTERVAL: u8 = 2;
/// Issue #2 captured last-chip addr. Equals `60 * 2`, not `(60-1) * 2`.
pub const S9SE_LAST_CHIP_ADDR_CAPTURED: u8 = 0x78;
/// Stock-like `for i in 0..60 { i * 2 }` last addr.
pub const S9SE_LAST_CHIP_ADDR_START_AT_ZERO: u8 = 0x76;
/// Prefer the captured last until live GetAddress count is bound.
pub const S9SE_LAST_CHIP_ADDR: u8 = S9SE_LAST_CHIP_ADDR_CAPTURED;
/// S9k sibling interval — refuse as S9 SE geometry.
pub const S9K_ADDR_INTERVAL: u8 = 4;
/// Classic S9 chip count — refuse as S9 SE geometry.
pub const AM1_S9_CHIPS_PER_CHAIN: u8 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeEnumError {
    IntervalIsS9k,
    ChipCountIsAm1S9,
    LastAddrMismatch { observed: u8 },
    GeometryMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S9SeAddressProgram {
    pub inactive: [u8; 5],
    pub set_address: Vec<[u8; 5]>,
    pub pacing: Option<PacedEnumerationPolicy>,
}

impl S9SeAddressProgram {
    pub fn expected_addresses(&self) -> Vec<u8> {
        self.set_address.iter().map(|frame| frame[2]).collect()
    }

    pub fn certify_coverage(
        &self,
        observed: &[u8],
    ) -> Result<ChainCoverageCertificate, ChainCoverageError> {
        ChainCoverageCertificate::certify(&self.expected_addresses(), observed)
    }
}

/// `for i in 0..chips { i * interval }` last address.
pub fn last_chip_addr_start_at_zero(chips: u8, interval: u8) -> u16 {
    u16::from(chips.saturating_sub(1)) * u16::from(interval)
}

/// `for i in 1..=chips { i * interval }` last address (`60*2 = 0x78`).
pub fn last_chip_addr_start_at_interval(chips: u8, interval: u8) -> u16 {
    u16::from(chips) * u16::from(interval)
}

pub fn admit_s9se_geometry(chips: u8, interval: u8, last: u8) -> Result<(), S9SeEnumError> {
    if interval == S9K_ADDR_INTERVAL {
        return Err(S9SeEnumError::IntervalIsS9k);
    }
    if chips == AM1_S9_CHIPS_PER_CHAIN {
        return Err(S9SeEnumError::ChipCountIsAm1S9);
    }
    if chips != S9SE_CHIPS_PER_CHAIN || interval != S9SE_ADDR_INTERVAL {
        return Err(S9SeEnumError::GeometryMismatch);
    }
    // Captured last is 0x78. Start-at-zero last is 0x76. Both are
    // desk-plausible; do not collapse them until live GetAddress count.
    if last != S9SE_LAST_CHIP_ADDR_CAPTURED && last != S9SE_LAST_CHIP_ADDR_START_AT_ZERO {
        return Err(S9SeEnumError::LastAddrMismatch { observed: last });
    }
    Ok(())
}

pub fn refuse_s9k_interval_on_s9se(interval: u8) -> Result<(), S9SeEnumError> {
    if interval == S9K_ADDR_INTERVAL {
        return Err(S9SeEnumError::IntervalIsS9k);
    }
    Ok(())
}

pub fn refuse_am1_s9_chip_count(chips: u8) -> Result<(), S9SeEnumError> {
    if chips == AM1_S9_CHIPS_PER_CHAIN {
        return Err(S9SeEnumError::ChipCountIsAm1S9);
    }
    Ok(())
}

/// `chain_inactive` then `set_address` for each chip. Not a live enum.
pub fn plan_s9se_address_program() -> Result<S9SeAddressProgram, S9SeEnumError> {
    admit_s9se_geometry(
        S9SE_CHIPS_PER_CHAIN,
        S9SE_ADDR_INTERVAL,
        S9SE_LAST_CHIP_ADDR,
    )?;
    // Capture-matching hypothesis: first addr = interval, last = 0x78.
    // Start-at-zero (last 0x76) stays a documented alternate; do not dispatch.
    let mut set_address = Vec::with_capacity(usize::from(S9SE_CHIPS_PER_CHAIN));
    for i in 1..=S9SE_CHIPS_PER_CHAIN {
        let addr = i.saturating_mul(S9SE_ADDR_INTERVAL);
        set_address.push(pack_set_address_vil(addr));
    }
    Ok(S9SeAddressProgram {
        inactive: pack_chain_inactive_vil(),
        set_address,
        pacing: None,
    })
}

/// Bind a caller-selected nonzero pacing policy to the exact desk program.
/// No S19k cadence is inherited into BM1393 by default.
pub fn plan_s9se_paced_address_program(
    pacing: PacedEnumerationPolicy,
) -> Result<S9SeAddressProgram, S9SeEnumError> {
    let mut plan = plan_s9se_address_program()?;
    plan.pacing = Some(pacing);
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue2_last_addr_is_60_times_stride_2() {
        admit_s9se_geometry(60, 2, 0x78).unwrap();
        admit_s9se_geometry(60, 2, 0x76).unwrap();
        assert_eq!(last_chip_addr_start_at_interval(60, 2), 0x78);
        assert_eq!(last_chip_addr_start_at_zero(60, 2), 0x76);
        assert_ne!(
            last_chip_addr_start_at_zero(60, 2),
            last_chip_addr_start_at_interval(60, 2),
            "start-at-0 vs start-at-interval stay distinct until live count"
        );
        assert!(admit_s9se_geometry(60, 4, 0xEC).is_err());
        assert!(admit_s9se_geometry(63, 2, 0x7C).is_err());
    }

    #[test]
    fn s9k_interval_and_s9_count_are_refused() {
        assert_eq!(
            refuse_s9k_interval_on_s9se(4),
            Err(S9SeEnumError::IntervalIsS9k)
        );
        refuse_s9k_interval_on_s9se(2).unwrap();
        assert_eq!(
            refuse_am1_s9_chip_count(63),
            Err(S9SeEnumError::ChipCountIsAm1S9)
        );
        refuse_am1_s9_chip_count(60).unwrap();
    }

    #[test]
    fn address_program_is_inactive_plus_60_set_address() {
        let plan = plan_s9se_address_program().unwrap();
        assert_eq!(plan.inactive[0], 0x53);
        assert_eq!(plan.set_address.len(), 60);
        assert_eq!(plan.set_address[0][2], 0x02);
        assert_eq!(plan.set_address[59][2], 0x78);
        assert_eq!(plan.set_address[59][0], 0x40);
        assert!(plan.certify_coverage(&plan.expected_addresses()).is_ok());
        assert!(plan
            .certify_coverage(&plan.expected_addresses()[..59])
            .is_err());
    }
}
