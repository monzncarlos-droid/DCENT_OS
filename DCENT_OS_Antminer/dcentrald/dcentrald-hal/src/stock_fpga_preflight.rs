//! Unminted live-receipt boundary for the stock S9 FPGA carrier.
//!
//! `dcentrald-common` can assess forgeable passive observation data offline.
//! That assessment is not mutation authority. A future target-only issuer must
//! acquire and retain the real cross-process lease, perform the read-only C5
//! and DMA checks in order, and then construct this receipt inside this module.
//! No issuer exists today, so `StockFpgaCarrierPreflightReceipt` cannot be
//! constructed by `dcentrald` and the top-level stock route remains closed.

use dcentrald_common::stock_fpga_carrier_preflight::StockFpgaCarrierPreflightAssessment;
use dcentrald_fabric_lease::{topology, FabricLeaseError, OsI2cFabricLease, PhysicalI2cFabricId};

/// Stock S9 FPGA-IIC has its own canonical topology identity.
///
/// The exact stock capture has no Linux I2C adapter and reaches per-chain PICs
/// only through `IIC_COMMAND` at `0x030`; assigning `linux_adapter(0)` would
/// therefore be a device-number guess. Every stock register/IIC handle must
/// share this one retained owner rather than acquire per-handle leases.
pub const STOCK_FPGA_MANAGEMENT_FABRIC: PhysicalI2cFabricId = topology::STOCK_S9_FPGA_IIC;

/// Move-only live carrier receipt.
///
/// Private fields and the absence of a constructor are intentional. The
/// receipt owns the lease rather than storing a Boolean claim, so dropping it
/// releases cross-process exclusion. It proves only passive carrier preflight;
/// it does not prove thermal, watchdog, voltage, ASIC-enumeration, or share
/// correlation readiness.
#[must_use = "stock FPGA carrier receipt must retain its exclusive fabric lease"]
#[derive(Debug)]
pub struct StockFpgaCarrierPreflightReceipt {
    assessment: StockFpgaCarrierPreflightAssessment,
    retained_fabric_lease: OsI2cFabricLease,
}

impl StockFpgaCarrierPreflightReceipt {
    pub const fn assessment(&self) -> StockFpgaCarrierPreflightAssessment {
        self.assessment
    }

    pub fn validate_current_process(&self) -> Result<(), FabricLeaseError> {
        self.retained_fabric_lease.validate_current_process()
    }

    pub const fn fabric(&self) -> PhysicalI2cFabricId {
        self.retained_fabric_lease.fabric()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_fpga_uses_the_canonical_stock_iic_topology_not_adapter_zero() {
        assert_eq!(STOCK_FPGA_MANAGEMENT_FABRIC, topology::STOCK_S9_FPGA_IIC);
        assert_ne!(
            STOCK_FPGA_MANAGEMENT_FABRIC,
            PhysicalI2cFabricId::linux_adapter(0)
        );
        let lease_ledger = include_str!("../../dcentrald-fabric-lease/src/lib.rs");
        assert!(lease_ledger.contains("STOCK_S9_FPGA_IIC"));
        assert!(lease_ledger.contains("no Linux I2C adapter is instantiated"));
        assert!(lease_ledger.contains("IIC_COMMAND"));
    }

    #[test]
    fn live_receipt_has_no_offline_or_public_issuer() {
        let source = include_str!("stock_fpga_preflight.rs");
        assert!(!source.contains("pub fn new("));
        assert!(!source.contains("pub fn issue("));
        assert!(!source.contains("pub fn mint("));
        assert!(source.contains("retained_fabric_lease: OsI2cFabricLease"));
    }
}
