//! Offline-only stock carrier preflight facts for exact BM1396 S17e/T17e roots.
//!
//! The four held 2019/signed-2020 S17e/T17e roots ship byte-identical
//! `bitmain_axi.ko` and `fpga_mem_driver.ko` modules.  This module records the
//! exact mapping contract and validates a passive observation record.  It does
//! **not** create a carrier receipt, prove MMIO/DMA cache coherency, retain an
//! OS mapping/fabric lease, or authorize any device access.

use crate::{Bm1396FirmwareRelease, Bm1396Model};

pub const BM1396_AXI_MODULE_SHA256: &str =
    "00500755f72420e3c084e0ea6ecfe71b7989a219a972c2db5e34818f3f750ab4";
pub const BM1396_AXI_MODULE_SIZE: u64 = 7_519;
pub const BM1396_FPGA_MEM_MODULE_SHA256: &str =
    "2ec39eda2d5b691c07475b73797c335949a56eb6df9b0a5d83881474bfff0c3f";
pub const BM1396_FPGA_MEM_MODULE_SIZE: u64 = 8_030;
pub const BM1396_STOCK_MODULE_VERMAGIC: &str =
    "4.6.0-xilinx-g20b57cf-dirty SMP preempt mod_unload modversions ARMv7 p2v8 ";

pub const BM1396_AXI_DEVICE_PATH: &str = "/dev/axi_fpga_dev";
pub const BM1396_FPGA_MEM_DEVICE_PATH: &str = "/dev/fpga_mem";
pub const BM1396_AXI_PHYSICAL_BASE: u32 = 0x4000_0000;
pub const BM1396_AXI_RESERVED_LEN: u32 = 0x1400;
/// Exact length requested by all four held miners (2019 S17e `0x5d230`, 2019
/// T17e Thumb `0x5f82e`, signed-2020 S17e `0xb1d70`, and signed-2020 T17e
/// `0xb2d88`). This is deliberately narrower than the module's reserved
/// physical aperture.
pub const BM1396_AXI_USER_MAP_LEN: u32 = 0x1200;
pub const BM1396_FPGA_MEM_MAP_LEN: u32 = 0x0100_0000;
pub const BM1396_FPGA_MEM_DEFAULT_BASE: u32 = 0x0f00_0000;
pub const BM1396_FPGA_MEM_ALLOWED_BASES: [u32; 3] = [0x0f00_0000, 0x1f00_0000, 0x3f00_0000];

/// The exact shell-script thresholds are strict.  Values equal to either
/// threshold take the lower/default branch.
pub const BM1396_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB: u64 = 1_000_000;
pub const BM1396_FPGA_MEM_MEDIUM_RAM_THRESHOLD_KIB: u64 = 400_000;

/// Exact stock software access surface. The two modules expose open, release,
/// and mmap file operations; no read/write/ioctl/IRQ data plane is imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StockCarrierAccessMode {
    MmapOnly,
}

pub const BM1396_STOCK_CARRIER_ACCESS_MODE: Bm1396StockCarrierAccessMode =
    Bm1396StockCarrierAccessMode::MmapOnly;

/// Exact stock userspace behavior. The receive thread and work-ready helper
/// poll MMIO register offsets; these module artifacts register no kernel IRQ.
/// This describes the held software, not an assertion that the FPGA fabric has
/// no interrupt output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396StockCarrierNotificationMode {
    UserspaceMmioPolling,
}

pub const BM1396_STOCK_CARRIER_NOTIFICATION_MODE: Bm1396StockCarrierNotificationMode =
    Bm1396StockCarrierNotificationMode::UserspaceMmioPolling;

/// Recovered stock mapping behavior, not an executable load sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396CarrierPreflightStep {
    BindExactModelAndRelease,
    VerifyAxiModuleDigestSizeAndVermagic,
    VerifyFpgaMemModuleDigestSizeAndVermagic,
    AcquireAndRetainExclusiveRegisterDmaAndPicOwnership,
    ProveNoOverlappingUioDevmemOrVendorMinerOwner,
    SelectDmaBaseFromExactMemTotalThresholds,
    RequireBothCharacterDevices,
    MapAxiExactlyAndRejectNullOrMapFailed,
    MapDmaExactlyAndRejectNullOrMapFailed,
    ProveRuntimeCacheBarrierAndBoundedPollingContract,
}

pub const BM1396_CARRIER_PREFLIGHT_PLAN: [Bm1396CarrierPreflightStep; 10] = [
    Bm1396CarrierPreflightStep::BindExactModelAndRelease,
    Bm1396CarrierPreflightStep::VerifyAxiModuleDigestSizeAndVermagic,
    Bm1396CarrierPreflightStep::VerifyFpgaMemModuleDigestSizeAndVermagic,
    Bm1396CarrierPreflightStep::AcquireAndRetainExclusiveRegisterDmaAndPicOwnership,
    Bm1396CarrierPreflightStep::ProveNoOverlappingUioDevmemOrVendorMinerOwner,
    Bm1396CarrierPreflightStep::SelectDmaBaseFromExactMemTotalThresholds,
    Bm1396CarrierPreflightStep::RequireBothCharacterDevices,
    Bm1396CarrierPreflightStep::MapAxiExactlyAndRejectNullOrMapFailed,
    Bm1396CarrierPreflightStep::MapDmaExactlyAndRejectNullOrMapFailed,
    Bm1396CarrierPreflightStep::ProveRuntimeCacheBarrierAndBoundedPollingContract,
];

/// Exact vendor script selection from `/proc/meminfo`'s `MemTotal` in KiB.
pub const fn bm1396_stock_dma_base_for_memtotal_kib(mem_total_kib: u64) -> u32 {
    if mem_total_kib > BM1396_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB {
        0x3f00_0000
    } else if mem_total_kib < BM1396_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB
        && mem_total_kib > BM1396_FPGA_MEM_MEDIUM_RAM_THRESHOLD_KIB
    {
        0x1f00_0000
    } else {
        BM1396_FPGA_MEM_DEFAULT_BASE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396MappedAddressObservation {
    /// Software-visible 32-bit result returned by `mmap`.
    pub address: u32,
    pub requested_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396CarrierArtifactObservation<'a> {
    pub sha256: &'a str,
    pub size: u64,
    pub vermagic: &'a str,
}

/// Forgeable passive data used only to compare an observation with the exact
/// stock tuple.  It is intentionally not a live authority token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396CarrierStaticObservation<'a> {
    pub model: Bm1396Model,
    pub release: Bm1396FirmwareRelease,
    pub axi_module: Bm1396CarrierArtifactObservation<'a>,
    pub fpga_mem_module: Bm1396CarrierArtifactObservation<'a>,
    pub axi_module_loaded: bool,
    pub fpga_mem_module_loaded: bool,
    pub axi_device_path: &'a str,
    pub fpga_mem_device_path: &'a str,
    pub axi_device_present: bool,
    pub fpga_mem_device_present: bool,
    pub mem_total_kib: u64,
    pub configured_dma_base: u32,
    pub axi_mapping: Bm1396MappedAddressObservation,
    pub dma_mapping: Bm1396MappedAddressObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396CarrierStaticAssessment {
    model: Bm1396Model,
    release: Bm1396FirmwareRelease,
    dma_base: u32,
}

impl Bm1396CarrierStaticAssessment {
    pub const fn model(&self) -> Bm1396Model {
        self.model
    }

    pub const fn release(&self) -> Bm1396FirmwareRelease {
        self.release
    }

    pub const fn dma_base(&self) -> u32 {
        self.dma_base
    }

    /// Static matching can never mint live carrier authority.
    pub const fn admits_live_carrier(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396CarrierPreflightError {
    AxiArtifactMismatch,
    FpgaMemArtifactMismatch,
    AxiModuleNotLoaded,
    FpgaMemModuleNotLoaded,
    AxiDevicePathMismatch,
    FpgaMemDevicePathMismatch,
    AxiDeviceMissing,
    FpgaMemDeviceMissing,
    DmaBaseMismatch { expected: u32, observed: u32 },
    AxiMapLengthMismatch { observed: u32 },
    DmaMapLengthMismatch { observed: u32 },
    AxiMapInvalidAddress { observed: u32 },
    DmaMapInvalidAddress { observed: u32 },
}

impl std::fmt::Display for Bm1396CarrierPreflightError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "BM1396 static carrier preflight failed: {self:?}"
        )
    }
}

impl std::error::Error for Bm1396CarrierPreflightError {}

fn artifact_matches(
    observation: Bm1396CarrierArtifactObservation<'_>,
    sha256: &str,
    size: u64,
) -> bool {
    observation.sha256.eq_ignore_ascii_case(sha256)
        && observation.size == size
        && observation.vermagic == BM1396_STOCK_MODULE_VERMAGIC
}

fn valid_mmap_address(address: u32) -> bool {
    // Stock checks only for null.  POSIX MAP_FAILED is `(void *)-1`, so clean
    // code must reject both values instead of preserving that unsafe quirk.
    address != 0 && address != u32::MAX
}

/// Validate only the exact static stock module/device/mapping tuple.
///
/// Even success leaves live authority closed: a future target-only issuer must
/// own all overlapping PL, DMA and PIC resources; validate the current process
/// after fork; establish the required volatile/barrier/cache contract; and
/// retain deterministic teardown authority.
pub fn assess_bm1396_static_carrier(
    observation: Bm1396CarrierStaticObservation<'_>,
) -> Result<Bm1396CarrierStaticAssessment, Bm1396CarrierPreflightError> {
    if !artifact_matches(
        observation.axi_module,
        BM1396_AXI_MODULE_SHA256,
        BM1396_AXI_MODULE_SIZE,
    ) {
        return Err(Bm1396CarrierPreflightError::AxiArtifactMismatch);
    }
    if !artifact_matches(
        observation.fpga_mem_module,
        BM1396_FPGA_MEM_MODULE_SHA256,
        BM1396_FPGA_MEM_MODULE_SIZE,
    ) {
        return Err(Bm1396CarrierPreflightError::FpgaMemArtifactMismatch);
    }
    if !observation.axi_module_loaded {
        return Err(Bm1396CarrierPreflightError::AxiModuleNotLoaded);
    }
    if !observation.fpga_mem_module_loaded {
        return Err(Bm1396CarrierPreflightError::FpgaMemModuleNotLoaded);
    }
    if observation.axi_device_path != BM1396_AXI_DEVICE_PATH {
        return Err(Bm1396CarrierPreflightError::AxiDevicePathMismatch);
    }
    if observation.fpga_mem_device_path != BM1396_FPGA_MEM_DEVICE_PATH {
        return Err(Bm1396CarrierPreflightError::FpgaMemDevicePathMismatch);
    }
    if !observation.axi_device_present {
        return Err(Bm1396CarrierPreflightError::AxiDeviceMissing);
    }
    if !observation.fpga_mem_device_present {
        return Err(Bm1396CarrierPreflightError::FpgaMemDeviceMissing);
    }

    let expected_dma_base = bm1396_stock_dma_base_for_memtotal_kib(observation.mem_total_kib);
    if observation.configured_dma_base != expected_dma_base {
        return Err(Bm1396CarrierPreflightError::DmaBaseMismatch {
            expected: expected_dma_base,
            observed: observation.configured_dma_base,
        });
    }
    if observation.axi_mapping.requested_len != BM1396_AXI_USER_MAP_LEN {
        return Err(Bm1396CarrierPreflightError::AxiMapLengthMismatch {
            observed: observation.axi_mapping.requested_len,
        });
    }
    if observation.dma_mapping.requested_len != BM1396_FPGA_MEM_MAP_LEN {
        return Err(Bm1396CarrierPreflightError::DmaMapLengthMismatch {
            observed: observation.dma_mapping.requested_len,
        });
    }
    if !valid_mmap_address(observation.axi_mapping.address) {
        return Err(Bm1396CarrierPreflightError::AxiMapInvalidAddress {
            observed: observation.axi_mapping.address,
        });
    }
    if !valid_mmap_address(observation.dma_mapping.address) {
        return Err(Bm1396CarrierPreflightError::DmaMapInvalidAddress {
            observed: observation.dma_mapping.address,
        });
    }

    Ok(Bm1396CarrierStaticAssessment {
        model: observation.model,
        release: observation.release,
        dma_base: expected_dma_base,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact<'a>(sha256: &'a str, size: u64) -> Bm1396CarrierArtifactObservation<'a> {
        Bm1396CarrierArtifactObservation {
            sha256,
            size,
            vermagic: BM1396_STOCK_MODULE_VERMAGIC,
        }
    }

    fn valid_observation() -> Bm1396CarrierStaticObservation<'static> {
        Bm1396CarrierStaticObservation {
            model: Bm1396Model::T17e,
            release: Bm1396FirmwareRelease::Signed2020,
            axi_module: artifact(BM1396_AXI_MODULE_SHA256, BM1396_AXI_MODULE_SIZE),
            fpga_mem_module: artifact(BM1396_FPGA_MEM_MODULE_SHA256, BM1396_FPGA_MEM_MODULE_SIZE),
            axi_module_loaded: true,
            fpga_mem_module_loaded: true,
            axi_device_path: BM1396_AXI_DEVICE_PATH,
            fpga_mem_device_path: BM1396_FPGA_MEM_DEVICE_PATH,
            axi_device_present: true,
            fpga_mem_device_present: true,
            mem_total_kib: 512_000,
            configured_dma_base: 0x1f00_0000,
            axi_mapping: Bm1396MappedAddressObservation {
                address: 0xb6ef_e000,
                requested_len: BM1396_AXI_USER_MAP_LEN,
            },
            dma_mapping: Bm1396MappedAddressObservation {
                address: 0xb5cf_7000,
                requested_len: BM1396_FPGA_MEM_MAP_LEN,
            },
        }
    }

    #[test]
    fn exact_script_thresholds_are_strict_and_boundary_pinned() {
        assert_eq!(bm1396_stock_dma_base_for_memtotal_kib(400_000), 0x0f00_0000);
        assert_eq!(bm1396_stock_dma_base_for_memtotal_kib(400_001), 0x1f00_0000);
        assert_eq!(bm1396_stock_dma_base_for_memtotal_kib(999_999), 0x1f00_0000);
        assert_eq!(
            bm1396_stock_dma_base_for_memtotal_kib(1_000_000),
            0x0f00_0000
        );
        assert_eq!(
            bm1396_stock_dma_base_for_memtotal_kib(1_000_001),
            0x3f00_0000
        );
    }

    #[test]
    fn exact_static_tuple_is_observational_and_never_live_authority() {
        assert_eq!(
            BM1396_STOCK_CARRIER_ACCESS_MODE,
            Bm1396StockCarrierAccessMode::MmapOnly
        );
        assert_eq!(
            BM1396_STOCK_CARRIER_NOTIFICATION_MODE,
            Bm1396StockCarrierNotificationMode::UserspaceMmioPolling
        );
        let assessment = assess_bm1396_static_carrier(valid_observation()).unwrap();
        assert_eq!(assessment.model(), Bm1396Model::T17e);
        assert_eq!(assessment.release(), Bm1396FirmwareRelease::Signed2020);
        assert_eq!(assessment.dma_base(), 0x1f00_0000);
        assert!(!assessment.admits_live_carrier());
    }

    #[test]
    fn artifact_device_and_mapping_shape_mismatches_fail_closed() {
        let mut observation = valid_observation();
        observation.axi_module.size -= 1;
        assert_eq!(
            assess_bm1396_static_carrier(observation),
            Err(Bm1396CarrierPreflightError::AxiArtifactMismatch)
        );

        let mut observation = valid_observation();
        observation.fpga_mem_module_loaded = false;
        assert_eq!(
            assess_bm1396_static_carrier(observation),
            Err(Bm1396CarrierPreflightError::FpgaMemModuleNotLoaded)
        );

        let mut observation = valid_observation();
        observation.axi_device_path = "/dev/mem";
        assert_eq!(
            assess_bm1396_static_carrier(observation),
            Err(Bm1396CarrierPreflightError::AxiDevicePathMismatch)
        );

        let mut observation = valid_observation();
        observation.configured_dma_base = 0x0f00_0000;
        assert_eq!(
            assess_bm1396_static_carrier(observation),
            Err(Bm1396CarrierPreflightError::DmaBaseMismatch {
                expected: 0x1f00_0000,
                observed: 0x0f00_0000,
            })
        );

        let mut observation = valid_observation();
        observation.axi_mapping.requested_len = BM1396_AXI_RESERVED_LEN;
        assert_eq!(
            assess_bm1396_static_carrier(observation),
            Err(Bm1396CarrierPreflightError::AxiMapLengthMismatch {
                observed: BM1396_AXI_RESERVED_LEN,
            })
        );
    }

    #[test]
    fn null_and_map_failed_are_both_rejected_for_each_mapping() {
        for address in [0, u32::MAX] {
            let mut observation = valid_observation();
            observation.axi_mapping.address = address;
            assert_eq!(
                assess_bm1396_static_carrier(observation),
                Err(Bm1396CarrierPreflightError::AxiMapInvalidAddress { observed: address })
            );

            let mut observation = valid_observation();
            observation.dma_mapping.address = address;
            assert_eq!(
                assess_bm1396_static_carrier(observation),
                Err(Bm1396CarrierPreflightError::DmaMapInvalidAddress { observed: address })
            );
        }
    }
}
