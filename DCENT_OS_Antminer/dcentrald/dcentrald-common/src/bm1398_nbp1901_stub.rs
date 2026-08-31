//! Legacy BM1398 / NBP1901 identity + geometry compatibility layer.
//!
//! Source:
//!
//!
//!
//! This was the first desk-only scaffold. It is intentionally retained for old
//! callers that import its identity/geometry names, but it is no longer the
//! protocol source of truth. Exact stock-NBP1901 plus repair-jig evidence now
//! lives in `dcentrald-api-types::bm1398_protocol`, and executable codec support
//! lives in `dcentrald-asic::drivers::bm1398`.
//!
//! The remaining refusal is narrower and load-bearing: the held corpus contains
//! no deployed S19 Pro EEPROM page whose decoded board name independently binds
//! the physical hashboard to BM1398. Therefore protocol reconstruction is true,
//! native runtime admission is false, mining stays default-off, and this module
//! exposes no alternate encoder. No energize / flash.

use core::fmt;

/// Machine / board_name key from NBP1901 topol.
pub const NBP1901_MACHINE: &str = "NBP1901";
/// Domain shorthand (= NBP1901 + chain_domain_num 38).
pub const NBP1901_38: &str = "NBP1901-38";
/// ASIC id string from topol.
pub const BM1398P_ASIC_ID: &str = "BM1398P";
/// ChipID / asic_addr config word.
pub const BM1398_CHIP_ID: u16 = 0x1398;
/// Family label for catalog.
pub const BM1398_FAMILY: &str = "BM1398";

pub const NBP1901_CHAIN_NUM_SLOTS: u8 = 4;
pub const NBP1901_CHAIN_DOMAIN_NUM: u8 = 38;
pub const NBP1901_CHAIN_ASIC_NUM: u8 = 114;
pub const NBP1901_DOMAIN_ASIC_NUM: u8 = 3;
pub const NBP1901_ASIC_CORE_NUM: u16 = 156;
pub const NBP1901_ASIC_SMALL_CORE_NUM: u16 = 623;
pub const NBP1901_CORE_SMALL_CORE_NUM: u8 = 4;
pub const NBP1901_ASIC_DOMAIN_NUM: u8 = 1;
pub const NBP1901_ASIC_ADDR_INTERVAL: u8 = 2;
/// Derived last address: 2*(114-1) = 226 = 0xE2.
pub const NBP1901_LAST_ASIC_ADDR: u8 = 226;

pub const NBP1901_DISCOVER_BAUD_HZ: u32 = 115_200;
pub const NBP1901_WORK_BAUD_HZ: u32 = 12_000_000;

pub const NBP1901_PIC_TYPE: &str = "PIC1704";
pub const NBP1901_PIC_I2C_ADDR: u8 = 32;
pub const NBP1901_PIC_FW_OBSERVED: u8 = 0x89;

/// Family hint only (S21 jig) — default-off, not NBP1901 Config.ini truth.
pub const MOST_HW_HINT_FAMILY_S21: u16 = 128;
pub const MOST_HW_HINT_DEFAULT_OFF: bool = true;

/// The exact BM1398/NBP1901 software protocol surface has been reconstructed.
///
/// This is not runtime authority. See [`BM1398_NBP1901_DEPLOYED_IDENTITY_HELD`]
/// and [`BM1398_NBP1901_ADMIT`].
pub const BM1398_NBP1901_PROTOCOL_RECONSTRUCTED: bool = true;
/// No held deployed S19 Pro page currently provides an exact independent
/// board-name -> BM1398 binding.
pub const BM1398_NBP1901_DEPLOYED_IDENTITY_HELD: bool = false;
/// Production/native admission remains false until that physical identity gap
/// closes and the current binary earns its capstone.
pub const BM1398_NBP1901_ADMIT: bool = false;
/// Compatibility name: this means the *native runtime composition* is not
/// implemented/admitted. It does not mean the chip protocol is unrecovered.
pub const BM1398_NBP1901_IMPLEMENTED: bool = false;
pub const BM1398_MINING_DEFAULT_ENABLED: bool = false;

/// Legacy string retained for source compatibility only. Current code must use
/// `dcentrald-api-types::bm1398_protocol`, not interpret this as current evidence.
#[deprecated(
    note = "BM1398 wire evidence is reconstructed in dcentrald-api-types::bm1398_protocol"
)]
pub const DESK_PENDING_BINARY: &str = "DESK_PENDING_BINARY";

/// Exact remaining native-runtime blocker after protocol convergence.
pub const BM1398_NBP1901_RUNTIME_BLOCKER: &str =
    "missing held deployed S19 Pro EEPROM page with an exact board-name-to-BM1398 binding";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398Nbp1901Identity {
    pub machine: &'static str,
    pub domain_shorthand: &'static str,
    pub asic_id: &'static str,
    pub chip_id: u16,
    pub family: &'static str,
    pub chain_asic_num: u8,
    pub asic_addr_interval: u8,
    pub chain_domain_num: u8,
    pub domain_asic_num: u8,
    pub protocol_reconstructed: bool,
    pub deployed_identity_held: bool,
    pub admit: bool,
    pub implemented: bool,
    pub mining_default_enabled: bool,
}

pub const BM1398_NBP1901_IDENTITY: Bm1398Nbp1901Identity = Bm1398Nbp1901Identity {
    machine: NBP1901_MACHINE,
    domain_shorthand: NBP1901_38,
    asic_id: BM1398P_ASIC_ID,
    chip_id: BM1398_CHIP_ID,
    family: BM1398_FAMILY,
    chain_asic_num: NBP1901_CHAIN_ASIC_NUM,
    asic_addr_interval: NBP1901_ASIC_ADDR_INTERVAL,
    chain_domain_num: NBP1901_CHAIN_DOMAIN_NUM,
    domain_asic_num: NBP1901_DOMAIN_ASIC_NUM,
    protocol_reconstructed: BM1398_NBP1901_PROTOCOL_RECONSTRUCTED,
    deployed_identity_held: BM1398_NBP1901_DEPLOYED_IDENTITY_HELD,
    admit: BM1398_NBP1901_ADMIT,
    implemented: BM1398_NBP1901_IMPLEMENTED,
    mining_default_enabled: BM1398_MINING_DEFAULT_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1398Nbp1901StubError {
    MissingDeployedIdentityEvidence,
    AdmitFalse,
    ProtocolSurfaceMoved { op: &'static str },
    ChipIdMismatch { observed: u16 },
    GeometryMismatch,
    MiningDefaultMustStayOff,
}

impl fmt::Display for Bm1398Nbp1901StubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDeployedIdentityEvidence => write!(
                f,
                "BM1398 NBP1901 native runtime refused: {BM1398_NBP1901_RUNTIME_BLOCKER}"
            ),
            Self::AdmitFalse => write!(f, "BM1398 NBP1901 native runtime: admit=false"),
            Self::ProtocolSurfaceMoved { op } => write!(
                f,
                "BM1398 NBP1901 {op} belongs to dcentrald-api-types::bm1398_protocol / dcentrald-asic::drivers::bm1398; the legacy compatibility layer exposes no second encoder"
            ),
            Self::ChipIdMismatch { observed } => {
                write!(f, "BM1398 NBP1901 stub: chip_id {observed:#06x} != 0x1398")
            }
            Self::GeometryMismatch => write!(
                f,
                "BM1398 NBP1901 stub: geometry must be 114 ASICs @ interval 2 / 38×3"
            ),
            Self::MiningDefaultMustStayOff => {
                write!(
                    f,
                    "BM1398 NBP1901 stub: mining_default_enabled must stay false"
                )
            }
        }
    }
}

/// Address **plan** math only — no TX. `0, 2, 4, …, 226`.
pub fn nbp1901_address_plan() -> Vec<u8> {
    (0..NBP1901_CHAIN_ASIC_NUM)
        .map(|i| i.saturating_mul(NBP1901_ASIC_ADDR_INTERVAL))
        .collect()
}

pub fn validate_identity_geometry() -> Result<(), Bm1398Nbp1901StubError> {
    let id = BM1398_NBP1901_IDENTITY;
    if id.chip_id != 0x1398 {
        return Err(Bm1398Nbp1901StubError::ChipIdMismatch {
            observed: id.chip_id,
        });
    }
    if id.chain_asic_num != 114
        || id.asic_addr_interval != 2
        || id.chain_domain_num != 38
        || id.domain_asic_num != 3
        || (id.chain_domain_num as u16) * (id.domain_asic_num as u16) != 114
    {
        return Err(Bm1398Nbp1901StubError::GeometryMismatch);
    }
    let plan = nbp1901_address_plan();
    if plan.len() != 114 || plan[0] != 0 || plan[113] != NBP1901_LAST_ASIC_ADDR {
        return Err(Bm1398Nbp1901StubError::GeometryMismatch);
    }
    if !id.protocol_reconstructed
        || id.deployed_identity_held
        || id.admit
        || id.implemented
        || id.mining_default_enabled
    {
        return Err(Bm1398Nbp1901StubError::AdmitFalse);
    }
    Ok(())
}

/// Production/native admit gate — false for the exact physical-identity gap,
/// not for lack of reconstructed protocol bytes.
pub fn admit_bm1398_nbp1901() -> Result<(), Bm1398Nbp1901StubError> {
    if BM1398_NBP1901_ADMIT || BM1398_NBP1901_IMPLEMENTED {
        return Err(Bm1398Nbp1901StubError::AdmitFalse);
    }
    Err(Bm1398Nbp1901StubError::MissingDeployedIdentityEvidence)
}

/// Legacy wire entry point. The exact protocol has one newer source of truth;
/// this compatibility layer refuses to create a divergent second encoder.
pub fn refuse_runtime_wire_try(op: &'static str) -> Result<(), Bm1398Nbp1901StubError> {
    Err(Bm1398Nbp1901StubError::ProtocolSurfaceMoved { op })
}

/// Legacy empty GetAddress entry point; use the exact current protocol module.
pub fn get_address_tx_template() -> Result<&'static [u8], Bm1398Nbp1901StubError> {
    refuse_runtime_wire_try("GetAddress")?;
    unreachable!()
}

/// Empty SetAddress TX template.
pub fn set_address_tx_template(_addr: u8) -> Result<&'static [u8], Bm1398Nbp1901StubError> {
    refuse_runtime_wire_try("SetAddress")?;
    unreachable!()
}

/// Empty chain_inactive TX template.
pub fn chain_inactive_tx_template() -> Result<&'static [u8], Bm1398Nbp1901StubError> {
    refuse_runtime_wire_try("chain_inactive")?;
    unreachable!()
}

/// Empty open-core TX template.
pub fn open_core_tx_template() -> Result<&'static [u8], Bm1398Nbp1901StubError> {
    refuse_runtime_wire_try("open_core")?;
    unreachable!()
}

/// Empty midstate-4 work TX template.
pub fn midstate4_work_tx_template() -> Result<&'static [u8], Bm1398Nbp1901StubError> {
    refuse_runtime_wire_try("midstate4_work")?;
    unreachable!()
}

/// Legacy analogue-opcode adjudicator.
///
/// The old scaffold incorrectly treated the shared BM1397-family command heads
/// as forbidden BM1398 guesses. Exact NBP1901 evidence superseded that claim.
/// Refuse this obsolete adjudicator itself so it can neither reject proven
/// commands nor authorize a byte outside the current protocol module.
#[deprecated(note = "use dcentrald-api-types::bm1398_protocol and the BM1398 driver")]
pub fn refuse_bm1397_analogue_opcode(_byte: u8) -> Result<(), Bm1398Nbp1901StubError> {
    refuse_runtime_wire_try("legacy BM1397-analogue opcode adjudication")
}

pub fn admit_mining_default_off(
    mining_default_enabled: bool,
) -> Result<(), Bm1398Nbp1901StubError> {
    if mining_default_enabled || BM1398_MINING_DEFAULT_ENABLED {
        return Err(Bm1398Nbp1901StubError::MiningDefaultMustStayOff);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_constants_nbp1901_38_bm1398p() {
        assert_eq!(NBP1901_MACHINE, "NBP1901");
        assert_eq!(NBP1901_38, "NBP1901-38");
        assert_eq!(BM1398P_ASIC_ID, "BM1398P");
        assert_eq!(BM1398_CHIP_ID, 0x1398);
        assert_eq!(BM1398_NBP1901_IDENTITY.chip_id, 0x1398);
        assert_eq!(BM1398_NBP1901_IDENTITY.asic_id, "BM1398P");
        assert_eq!(BM1398_NBP1901_IDENTITY.domain_shorthand, "NBP1901-38");
        assert!(validate_identity_geometry().is_ok());
    }

    #[test]
    fn geometry_114_interval_2_domains_38x3() {
        assert_eq!(NBP1901_CHAIN_ASIC_NUM, 114);
        assert_eq!(NBP1901_ASIC_ADDR_INTERVAL, 2);
        assert_eq!(NBP1901_CHAIN_DOMAIN_NUM, 38);
        assert_eq!(NBP1901_DOMAIN_ASIC_NUM, 3);
        assert_eq!(NBP1901_ASIC_CORE_NUM, 156);
        assert_eq!(NBP1901_ASIC_SMALL_CORE_NUM, 623);
        let plan = nbp1901_address_plan();
        assert_eq!(plan.len(), 114);
        assert_eq!(plan[0], 0);
        assert_eq!(plan[1], 2);
        assert_eq!(plan[113], 226);
        assert_eq!(NBP1901_LAST_ASIC_ADDR, 0xE2);
    }

    #[test]
    fn protocol_is_reconstructed_but_native_runtime_stays_refused() {
        assert!(BM1398_NBP1901_PROTOCOL_RECONSTRUCTED);
        assert!(!BM1398_NBP1901_DEPLOYED_IDENTITY_HELD);
        assert!(!BM1398_NBP1901_ADMIT);
        assert!(!BM1398_NBP1901_IMPLEMENTED);
        assert!(!BM1398_MINING_DEFAULT_ENABLED);
        assert!(matches!(
            admit_bm1398_nbp1901(),
            Err(Bm1398Nbp1901StubError::MissingDeployedIdentityEvidence)
        ));
        assert!(admit_mining_default_off(false).is_ok());
        assert!(admit_mining_default_off(true).is_err());
    }

    #[test]
    fn legacy_runtime_wire_surface_refuses_a_second_encoder() {
        assert!(matches!(
            refuse_runtime_wire_try("GetAddress"),
            Err(Bm1398Nbp1901StubError::ProtocolSurfaceMoved { op: "GetAddress" })
        ));
        assert!(get_address_tx_template().is_err());
        assert!(set_address_tx_template(0).is_err());
        assert!(chain_inactive_tx_template().is_err());
        assert!(open_core_tx_template().is_err());
        assert!(midstate4_work_tx_template().is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn obsolete_analogue_adjudicator_cannot_authorize_or_reject_bytes() {
        for b in [0x40u8, 0x52, 0x53, 0x42] {
            assert!(matches!(
                refuse_bm1397_analogue_opcode(b),
                Err(Bm1398Nbp1901StubError::ProtocolSurfaceMoved { .. })
            ));
        }
        assert!(refuse_bm1397_analogue_opcode(0x00).is_err());
    }

    #[test]
    fn baud_scaffold_and_most_hw_hint_default_off() {
        assert_eq!(NBP1901_DISCOVER_BAUD_HZ, 115_200);
        assert_eq!(NBP1901_WORK_BAUD_HZ, 12_000_000);
        assert_eq!(MOST_HW_HINT_FAMILY_S21, 128);
        assert!(MOST_HW_HINT_DEFAULT_OFF);
        assert_eq!(NBP1901_PIC_TYPE, "PIC1704");
        assert_eq!(NBP1901_PIC_I2C_ADDR, 32);
        assert_eq!(NBP1901_PIC_FW_OBSERVED, 0x89);
    }
}
