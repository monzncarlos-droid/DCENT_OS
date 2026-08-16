//! Offline-only admission contracts for the stock Bitmain S9 FPGA carrier.
//!
//! This module deliberately separates two different claims:
//! 1. [`StockFpgaDeclaredRouteAdmission`] proves that declared/configured
//!    policy selects the one exact supported candidate composition.
//! 2. [`assess_stock_fpga_carrier_preflight`] checks a passive observation
//!    record, but returns data only. It is **not** live hardware authority.
//!
//! A mutation-capable runtime must additionally retain the real cross-process
//! fabric lease and mint a separate, private live receipt after performing the
//! plan on the target. No such issuer exists in the offline campaign, so this
//! module cannot make `--stock-fpga` executable.

use crate::{
    AsicProtocolAdmission, AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind,
    VoltageControllerClass, WorkEngineKind,
};

/// Stock S9 FPGA `HARDWARE_VERSION` register offset.
///
/// Evidence: primary S9 `driver-btm-soc.h` (`HARDWARE_VERSION`) and live S9
/// C51A/C51E captures in .
pub const STOCK_FPGA_HARDWARE_VERSION_OFFSET: u32 = 0x000;

/// C5 carrier discriminator stored in `HARDWARE_VERSION[15:8]`.
///
/// C5 is necessary but not sufficient: S9-family siblings and T9+ also use C5,
/// so the exact `am1-s9` declared target remains load-bearing.
pub const STOCK_FPGA_EXPECTED_BOARD_TYPE: u8 = 0xC5;

/// RAM-size-dependent bases supported by stock `fpga_mem_driver`.
///
/// Evidence: primary S9 source plus held stock startup scripts. These values
/// match `dcentrald-hal::stock_fpga_work::STOCK_DMA_BASES`; unknown aligned
/// addresses are not accepted as guesses.
pub const STOCK_FPGA_ALLOWED_DMA_BASES: [u32; 3] = [0x0F00_0000, 0x1F00_0000, 0x3F00_0000];

/// Pure inputs for the declared/configured half of stock-FPGA admission.
///
/// `explicit_stock_fpga_dispatch` is selection evidence only. It is supplied
/// by the top-level `RuntimeDispatchKind` wrapper and is not carrier evidence.
#[derive(Debug)]
pub struct StockFpgaDeclaredRouteRequest<'a> {
    pub explicit_stock_fpga_dispatch: bool,
    pub board_desc: &'a BoardDesc,
    pub configured_or_observed_asic: Option<AsicProtocolIdentity>,
    pub requested_transport: ChainTransportKind,
    pub requested_work_engine: WorkEngineKind,
    pub nonce2_beta_enabled: bool,
    pub all_pool_routes_v1: bool,
    pub passthrough_enabled: bool,
}

/// Move-only declaration proof for the exact stock S9 candidate route.
///
/// This token is intentionally not `Clone` or `Copy`. It proves no live C5
/// register, DMA mapping, conflicting clean-image UIO absence, lease ownership, ASIC enumeration,
/// watchdog, thermal, voltage, or share-correlation fact.
#[must_use = "declared stock-FPGA admission must remain bound to one candidate lifecycle"]
#[derive(Debug, PartialEq, Eq)]
pub struct StockFpgaDeclaredRouteAdmission {
    board_target: &'static str,
    asic_protocol: AsicProtocolAdmission,
    transport: ChainTransportKind,
    work_engine: WorkEngineKind,
}

impl StockFpgaDeclaredRouteAdmission {
    pub const fn board_target(&self) -> &'static str {
        self.board_target
    }

    pub const fn asic_protocol(&self) -> AsicProtocolIdentity {
        self.asic_protocol.identity()
    }

    pub const fn transport(&self) -> ChainTransportKind {
        self.transport
    }

    pub const fn work_engine(&self) -> WorkEngineKind {
        self.work_engine
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockFpgaDeclaredRouteError {
    DispatchNotExplicit,
    WrongBoardTarget { observed: &'static str },
    WrongBoardFamily { observed: BoardFamily },
    WrongVoltageController { observed: VoltageControllerClass },
    WrongTransport { observed: ChainTransportKind },
    WrongWorkEngine { observed: WorkEngineKind },
    AsicProtocolNotIndependentlyAdmitted { detail: String },
    Nonce2BetaNotEnabled,
    NonV1PoolRoute,
    PassthroughNotEnabled,
}

impl std::fmt::Display for StockFpgaDeclaredRouteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DispatchNotExplicit => {
                write!(formatter, "stock FPGA route was not selected explicitly")
            }
            Self::WrongBoardTarget { observed } => write!(
                formatter,
                "stock FPGA route requires exact board target am1-s9, got {observed}"
            ),
            Self::WrongBoardFamily { observed } => write!(
                formatter,
                "stock FPGA route requires Zynq board family, got {observed:?}"
            ),
            Self::WrongVoltageController { observed } => write!(
                formatter,
                "stock FPGA route requires PIC16F1704, got {observed:?}"
            ),
            Self::WrongTransport { observed } => write!(
                formatter,
                "stock FPGA route requires StockFpga carrier, got {observed:?}"
            ),
            Self::WrongWorkEngine { observed } => write!(
                formatter,
                "stock FPGA route requires StockDma work engine, got {observed:?}"
            ),
            Self::AsicProtocolNotIndependentlyAdmitted { detail } => write!(
                formatter,
                "stock FPGA route lacks independent BM1387 admission: {detail}"
            ),
            Self::Nonce2BetaNotEnabled => write!(
                formatter,
                "stock FPGA route requires the explicit nonce2-correlation beta gate"
            ),
            Self::NonV1PoolRoute => write!(
                formatter,
                "stock FPGA route requires every configured pool route to resolve to V1"
            ),
            Self::PassthroughNotEnabled => write!(
                formatter,
                "stock FPGA route is limited to inherited passthrough state until cold boot is admitted"
            ),
        }
    }
}

impl std::error::Error for StockFpgaDeclaredRouteError {}

/// Admit only the exact declared/configured stock S9 candidate route.
///
/// `BoardDesc` continues to describe the clean-image UIO/FIFO default. The
/// explicit stock lane is an alternate carrier/work overlay and therefore
/// checks `StockFpga`/`StockDma` independently instead of rewriting the row.
pub fn admit_stock_fpga_declared_route(
    request: StockFpgaDeclaredRouteRequest<'_>,
) -> Result<StockFpgaDeclaredRouteAdmission, StockFpgaDeclaredRouteError> {
    if !request.explicit_stock_fpga_dispatch {
        return Err(StockFpgaDeclaredRouteError::DispatchNotExplicit);
    }
    if request.board_desc.board_target != "am1-s9" {
        return Err(StockFpgaDeclaredRouteError::WrongBoardTarget {
            observed: request.board_desc.board_target,
        });
    }
    if request.board_desc.family != BoardFamily::Zynq {
        return Err(StockFpgaDeclaredRouteError::WrongBoardFamily {
            observed: request.board_desc.family,
        });
    }
    if request.board_desc.voltage_controller != VoltageControllerClass::Pic16F1704 {
        return Err(StockFpgaDeclaredRouteError::WrongVoltageController {
            observed: request.board_desc.voltage_controller,
        });
    }
    if request.requested_transport != ChainTransportKind::StockFpga {
        return Err(StockFpgaDeclaredRouteError::WrongTransport {
            observed: request.requested_transport,
        });
    }
    if request.requested_work_engine != WorkEngineKind::StockDma {
        return Err(StockFpgaDeclaredRouteError::WrongWorkEngine {
            observed: request.requested_work_engine,
        });
    }

    let asic_protocol = request
        .board_desc
        .admit_asic_protocol(
            request.configured_or_observed_asic,
            AsicProtocolIdentity::Bm1387,
        )
        .map_err(
            |detail| StockFpgaDeclaredRouteError::AsicProtocolNotIndependentlyAdmitted { detail },
        )?;

    if !request.nonce2_beta_enabled {
        return Err(StockFpgaDeclaredRouteError::Nonce2BetaNotEnabled);
    }
    if !request.all_pool_routes_v1 {
        return Err(StockFpgaDeclaredRouteError::NonV1PoolRoute);
    }
    if !request.passthrough_enabled {
        return Err(StockFpgaDeclaredRouteError::PassthroughNotEnabled);
    }

    Ok(StockFpgaDeclaredRouteAdmission {
        board_target: request.board_desc.board_target,
        asic_protocol,
        transport: request.requested_transport,
        work_engine: request.requested_work_engine,
    })
}

/// Ordered passive checks required before a future live issuer may mint the
/// second-stage carrier receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockFpgaCarrierPreflightStep {
    AcquireAndRetainExclusiveFabricLease,
    ProveNoConflictingCleanFpgaChainUio,
    OpenRegisterProbeReadOnly,
    ReadAndValidateC5HardwareVersion,
    AdmitKernelReportedDmaBase,
    ValidateInheritedDmaRegisterLayout,
}

pub const STOCK_FPGA_CARRIER_PREFLIGHT_PLAN: [StockFpgaCarrierPreflightStep; 6] = [
    StockFpgaCarrierPreflightStep::AcquireAndRetainExclusiveFabricLease,
    StockFpgaCarrierPreflightStep::ProveNoConflictingCleanFpgaChainUio,
    StockFpgaCarrierPreflightStep::OpenRegisterProbeReadOnly,
    StockFpgaCarrierPreflightStep::ReadAndValidateC5HardwareVersion,
    StockFpgaCarrierPreflightStep::AdmitKernelReportedDmaBase,
    StockFpgaCarrierPreflightStep::ValidateInheritedDmaRegisterLayout,
];

/// Passive observations supplied by a future HAL issuer.
///
/// This structure is forgeable test/input data and never authorizes mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockFpgaCarrierPreflightObservation {
    pub retained_exclusive_fabric_lease: bool,
    /// Exact clean-image `FpgaUio` chain/common topology is present. Unrelated
    /// UIO devices do not conflict with the stock ABI and must not be refused.
    pub clean_fpga_chain_uio_present: bool,
    pub register_probe_read_only: bool,
    pub hardware_version: Option<u32>,
    pub dma_physical_base: Option<u64>,
    pub inherited_dma_registers_match: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockFpgaCarrierPreflightError {
    RetainedExclusiveFabricLeaseMissing,
    ConflictingCleanFpgaChainUioPresent,
    RegisterProbeNotReadOnly,
    HardwareVersionMissing,
    HardwareVersionInvalid { observed: u32 },
    WrongBoardType { observed: u8 },
    DmaBaseMissing,
    DmaBaseUnsupported { observed: u64 },
    InheritedDmaRegisterLayoutUnproven,
}

impl std::fmt::Display for StockFpgaCarrierPreflightError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RetainedExclusiveFabricLeaseMissing => {
                write!(formatter, "stock FPGA fabric lease is not retained exclusively")
            }
            Self::ConflictingCleanFpgaChainUioPresent => write!(
                formatter,
                "the clean-image FPGA-chain UIO topology is present; stock and clean-image chain ABIs are mutually exclusive"
            ),
            Self::RegisterProbeNotReadOnly => write!(
                formatter,
                "HARDWARE_VERSION probe was not opened through a read-only mapping"
            ),
            Self::HardwareVersionMissing => {
                write!(formatter, "stock FPGA HARDWARE_VERSION was not observed")
            }
            Self::HardwareVersionInvalid { observed } => write!(
                formatter,
                "stock FPGA HARDWARE_VERSION sentinel is invalid: 0x{observed:08X}"
            ),
            Self::WrongBoardType { observed } => write!(
                formatter,
                "stock FPGA HARDWARE_VERSION board byte is 0x{observed:02X}, expected C5"
            ),
            Self::DmaBaseMissing => {
                write!(formatter, "stock fpga_mem_driver DMA base was not observed")
            }
            Self::DmaBaseUnsupported { observed } => write!(
                formatter,
                "stock FPGA DMA base 0x{observed:X} is outside the admitted 0F/1F/3F layouts"
            ),
            Self::InheritedDmaRegisterLayoutUnproven => write!(
                formatter,
                "inherited FPGA DMA registers do not match the admitted kernel layout"
            ),
        }
    }
}

impl std::error::Error for StockFpgaCarrierPreflightError {}

/// Non-authoritative result of validating passive carrier observations.
///
/// This is deliberately `Copy`: it is evidence data, not the live receipt.
/// Mutation remains impossible until a HAL-owned receipt retains the actual OS
/// lease and this assessment together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockFpgaCarrierPreflightAssessment {
    hardware_version: u32,
    dma_physical_base: u32,
}

impl StockFpgaCarrierPreflightAssessment {
    pub const fn hardware_version(self) -> u32 {
        self.hardware_version
    }

    pub const fn board_type(self) -> u8 {
        ((self.hardware_version >> 8) & 0xff) as u8
    }

    pub const fn fpga_revision(self) -> u8 {
        (self.hardware_version & 0xff) as u8
    }

    pub const fn dma_physical_base(self) -> u32 {
        self.dma_physical_base
    }
}

/// Validate a passive observation record without minting live authority.
pub fn assess_stock_fpga_carrier_preflight(
    observation: StockFpgaCarrierPreflightObservation,
) -> Result<StockFpgaCarrierPreflightAssessment, StockFpgaCarrierPreflightError> {
    if !observation.retained_exclusive_fabric_lease {
        return Err(StockFpgaCarrierPreflightError::RetainedExclusiveFabricLeaseMissing);
    }
    if observation.clean_fpga_chain_uio_present {
        return Err(StockFpgaCarrierPreflightError::ConflictingCleanFpgaChainUioPresent);
    }
    if !observation.register_probe_read_only {
        return Err(StockFpgaCarrierPreflightError::RegisterProbeNotReadOnly);
    }
    let hardware_version = observation
        .hardware_version
        .ok_or(StockFpgaCarrierPreflightError::HardwareVersionMissing)?;
    if matches!(hardware_version, 0 | u32::MAX) {
        return Err(StockFpgaCarrierPreflightError::HardwareVersionInvalid {
            observed: hardware_version,
        });
    }
    let board_type = ((hardware_version >> 8) & 0xff) as u8;
    if board_type != STOCK_FPGA_EXPECTED_BOARD_TYPE {
        return Err(StockFpgaCarrierPreflightError::WrongBoardType {
            observed: board_type,
        });
    }
    let dma_physical_base = observation
        .dma_physical_base
        .ok_or(StockFpgaCarrierPreflightError::DmaBaseMissing)?;
    let dma_physical_base_u32 = u32::try_from(dma_physical_base).map_err(|_| {
        StockFpgaCarrierPreflightError::DmaBaseUnsupported {
            observed: dma_physical_base,
        }
    })?;
    if !STOCK_FPGA_ALLOWED_DMA_BASES.contains(&dma_physical_base_u32) {
        return Err(StockFpgaCarrierPreflightError::DmaBaseUnsupported {
            observed: dma_physical_base,
        });
    }
    if !observation.inherited_dma_registers_match {
        return Err(StockFpgaCarrierPreflightError::InheritedDmaRegisterLayoutUnproven);
    }

    Ok(StockFpgaCarrierPreflightAssessment {
        hardware_version,
        dma_physical_base: dma_physical_base_u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_request<'a>(board_desc: &'a BoardDesc) -> StockFpgaDeclaredRouteRequest<'a> {
        StockFpgaDeclaredRouteRequest {
            explicit_stock_fpga_dispatch: true,
            board_desc,
            configured_or_observed_asic: Some(AsicProtocolIdentity::Bm1387),
            requested_transport: ChainTransportKind::StockFpga,
            requested_work_engine: WorkEngineKind::StockDma,
            nonce2_beta_enabled: true,
            all_pool_routes_v1: true,
            passthrough_enabled: true,
        }
    }

    #[test]
    fn exact_am1_s9_declared_stock_overlay_is_offline_admissible() {
        let s9 = BoardDesc::am1_s9();
        let admission = admit_stock_fpga_declared_route(exact_request(&s9)).unwrap();
        assert_eq!(admission.board_target(), "am1-s9");
        assert_eq!(admission.asic_protocol(), AsicProtocolIdentity::Bm1387);
        assert_eq!(admission.transport(), ChainTransportKind::StockFpga);
        assert_eq!(admission.work_engine(), WorkEngineKind::StockDma);
        assert_eq!(s9.chain_transport, ChainTransportKind::FpgaUio);
        assert_eq!(s9.work_engine, WorkEngineKind::FpgaWorkFifo);
    }

    #[test]
    fn declared_route_refuses_every_exact_constraint_mutation_and_lookalike() {
        let s9 = BoardDesc::am1_s9();

        let mut request = exact_request(&s9);
        request.explicit_stock_fpga_dispatch = false;
        assert_eq!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::DispatchNotExplicit)
        );

        for target in ["am1-s9i", "am1-s9j", "am1-t9plus", "future-am1-s9-copy"] {
            let mut lookalike = BoardDesc::am1_s9();
            lookalike.board_target = target;
            assert!(matches!(
                admit_stock_fpga_declared_route(exact_request(&lookalike)),
                Err(StockFpgaDeclaredRouteError::WrongBoardTarget { observed }) if observed == target
            ));
        }

        let mut wrong_family = BoardDesc::am1_s9();
        wrong_family.family = BoardFamily::BeagleBone;
        assert!(matches!(
            admit_stock_fpga_declared_route(exact_request(&wrong_family)),
            Err(StockFpgaDeclaredRouteError::WrongBoardFamily { .. })
        ));

        let mut wrong_controller = BoardDesc::am1_s9();
        wrong_controller.voltage_controller = VoltageControllerClass::RuntimeDiscovered;
        assert!(matches!(
            admit_stock_fpga_declared_route(exact_request(&wrong_controller)),
            Err(StockFpgaDeclaredRouteError::WrongVoltageController { .. })
        ));

        let mut request = exact_request(&s9);
        request.requested_transport = ChainTransportKind::FpgaUio;
        assert!(matches!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::WrongTransport { .. })
        ));

        let mut request = exact_request(&s9);
        request.requested_work_engine = WorkEngineKind::FpgaWorkFifo;
        assert!(matches!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::WrongWorkEngine { .. })
        ));

        let mut request = exact_request(&s9);
        request.configured_or_observed_asic = None;
        assert!(matches!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::AsicProtocolNotIndependentlyAdmitted { .. })
        ));

        let mut request = exact_request(&s9);
        request.nonce2_beta_enabled = false;
        assert_eq!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::Nonce2BetaNotEnabled)
        );

        let mut request = exact_request(&s9);
        request.all_pool_routes_v1 = false;
        assert_eq!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::NonV1PoolRoute)
        );

        let mut request = exact_request(&s9);
        request.passthrough_enabled = false;
        assert_eq!(
            admit_stock_fpga_declared_route(request),
            Err(StockFpgaDeclaredRouteError::PassthroughNotEnabled)
        );
    }

    fn valid_observation() -> StockFpgaCarrierPreflightObservation {
        StockFpgaCarrierPreflightObservation {
            retained_exclusive_fabric_lease: true,
            clean_fpga_chain_uio_present: false,
            register_probe_read_only: true,
            hardware_version: Some(0x0000_C51E),
            dma_physical_base: Some(0x1F00_0000),
            inherited_dma_registers_match: true,
        }
    }

    #[test]
    fn carrier_plan_is_passive_ordered_and_non_authoritative() {
        assert_eq!(
            STOCK_FPGA_CARRIER_PREFLIGHT_PLAN,
            [
                StockFpgaCarrierPreflightStep::AcquireAndRetainExclusiveFabricLease,
                StockFpgaCarrierPreflightStep::ProveNoConflictingCleanFpgaChainUio,
                StockFpgaCarrierPreflightStep::OpenRegisterProbeReadOnly,
                StockFpgaCarrierPreflightStep::ReadAndValidateC5HardwareVersion,
                StockFpgaCarrierPreflightStep::AdmitKernelReportedDmaBase,
                StockFpgaCarrierPreflightStep::ValidateInheritedDmaRegisterLayout,
            ]
        );

        let assessment = assess_stock_fpga_carrier_preflight(valid_observation()).unwrap();
        assert_eq!(assessment.hardware_version(), 0x0000_C51E);
        assert_eq!(assessment.board_type(), 0xC5);
        assert_eq!(assessment.fpga_revision(), 0x1E);
        assert_eq!(assessment.dma_physical_base(), 0x1F00_0000);
    }

    #[test]
    fn carrier_preflight_fails_closed_on_every_required_observation() {
        let mut observation = valid_observation();
        observation.retained_exclusive_fabric_lease = false;
        assert_eq!(
            assess_stock_fpga_carrier_preflight(observation),
            Err(StockFpgaCarrierPreflightError::RetainedExclusiveFabricLeaseMissing)
        );

        let mut observation = valid_observation();
        observation.clean_fpga_chain_uio_present = true;
        assert_eq!(
            assess_stock_fpga_carrier_preflight(observation),
            Err(StockFpgaCarrierPreflightError::ConflictingCleanFpgaChainUioPresent)
        );

        let mut observation = valid_observation();
        observation.register_probe_read_only = false;
        assert_eq!(
            assess_stock_fpga_carrier_preflight(observation),
            Err(StockFpgaCarrierPreflightError::RegisterProbeNotReadOnly)
        );

        for version in [None, Some(0), Some(u32::MAX), Some(0x0000_C41E)] {
            let mut observation = valid_observation();
            observation.hardware_version = version;
            assert!(assess_stock_fpga_carrier_preflight(observation).is_err());
        }

        for base in [None, Some(0x2000_0000), Some(u64::from(u32::MAX) + 1)] {
            let mut observation = valid_observation();
            observation.dma_physical_base = base;
            assert!(assess_stock_fpga_carrier_preflight(observation).is_err());
        }

        for base in STOCK_FPGA_ALLOWED_DMA_BASES {
            let mut observation = valid_observation();
            observation.dma_physical_base = Some(u64::from(base));
            assert!(assess_stock_fpga_carrier_preflight(observation).is_ok());
        }

        let mut observation = valid_observation();
        observation.inherited_dma_registers_match = false;
        assert_eq!(
            assess_stock_fpga_carrier_preflight(observation),
            Err(StockFpgaCarrierPreflightError::InheritedDmaRegisterLayoutUnproven)
        );
    }
}
