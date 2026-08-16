//! Offline-only evidence profile for the held S15/T15 BM1391 stock carrier.
//!
//! This module deliberately separates an exact firmware-release match from a
//! physical carrier identity.  The held update packages do not contain their
//! resident DTB, and the only held controller schematic is in an S15 guide
//! whose 60-chip geometry conflicts with the exact S15 release's 72-chip
//! stock expectation.  A
//! successful release match therefore authorizes no device access, rail
//! transition, install, or model identity.

pub const BM1391_S15_PACKAGE_SHA256: &str =
    "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71";
pub const BM1391_S15_PACKAGE_SIZE: u64 = 24_962_829;
pub const BM1391_S15_VERSION_NUMBER: &str = "1.92992.0.14";
pub const BM1391_S15_CGMINER_SHA256: &str =
    "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8";
pub const BM1391_S15_BAKED_PATTERN_PATH: &str = "/dev/91602_pattern_72.txt";
pub const BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN: u8 = 72;

pub const BM1391_T15_PACKAGE_SHA256: &str =
    "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4";
pub const BM1391_T15_PACKAGE_SIZE: u64 = 23_696_441;
pub const BM1391_T15_VERSION_NUMBER: &str = "1.92992.0.13";
pub const BM1391_T15_CGMINER_SHA256: &str =
    "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01";
pub const BM1391_T15_BAKED_PATTERN_PATH: &str = "/dev/91602_pattern_60.txt";
pub const BM1391_T15_STOCK_EXPECTED_CHIPS_PER_CHAIN: u8 = 60;

pub const BM1391_SHARED_CGMINER_SIZE: u64 = 691_180;
pub const BM1391_SHARED_BOOT_BIN_SHA256: &str =
    "e6b85d66e226856203588794afb56da458716129852848c2c6069cb0ba84ab32";
pub const BM1391_SHARED_BOOT_BIN_SIZE: u64 = 2_735_664;
pub const BM1391_SHARED_UIMAGE_SHA256: &str =
    "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f";
pub const BM1391_SHARED_UIMAGE_SIZE: u64 = 4_006_832;
pub const BM1391_AXI_MODULE_SHA256: &str =
    "00500755f72420e3c084e0ea6ecfe71b7989a219a972c2db5e34818f3f750ab4";
pub const BM1391_AXI_MODULE_SIZE: u64 = 7_519;
pub const BM1391_FPGA_MEM_MODULE_SHA256: &str =
    "2ec39eda2d5b691c07475b73797c335949a56eb6df9b0a5d83881474bfff0c3f";
pub const BM1391_FPGA_MEM_MODULE_SIZE: u64 = 8_030;
pub const BM1391_STOCK_MODULE_VERMAGIC: &str =
    "4.6.0-xilinx-g20b57cf-dirty SMP preempt mod_unload modversions ARMv7 p2v8 ";

pub const BM1391_AXI_DEVICE_PATH: &str = "/dev/axi_fpga_dev";
pub const BM1391_FPGA_MEM_DEVICE_PATH: &str = "/dev/fpga_mem";
pub const BM1391_AXI_PHYSICAL_BASE: u32 = 0x4000_0000;
pub const BM1391_AXI_MODULE_RESERVED_LEN: u32 = 0x1400;
pub const BM1391_AXI_USER_MAP_LEN: u32 = 0x0160;
pub const BM1391_FPGA_MEM_MAP_LEN: u32 = 0x0100_0000;
pub const BM1391_FPGA_MEM_DEFAULT_BASE: u32 = 0x0f00_0000;
pub const BM1391_FPGA_MEM_MEDIUM_BASE: u32 = 0x1f00_0000;
pub const BM1391_FPGA_MEM_LARGE_BASE: u32 = 0x3f00_0000;
pub const BM1391_FPGA_MEM_MEDIUM_RAM_THRESHOLD_KIB: u64 = 400_000;
pub const BM1391_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB: u64 = 1_000_000;
pub const BM1391_FPGA_VERSION_LOW16: u16 = 0xc501;
pub const BM1391_FPGA_GENERAL_I2C_OFFSET: u32 = 0x30;
pub const BM1391_FPGA_GENERAL_I2C_COMPLETE_BIT: u32 = 1 << 31;
pub const BM1391_FPGA_GENERAL_I2C_RESPONSE_MASK: u32 = 0xff;

/// Exact first-party guide artifact.  It is useful physical evidence, but its
/// 60-chip S15 geometry conflicts with the held December-2019 S15 release.
pub const BM1391_S15_GUIDE_SHA256: &str =
    "4496807c14291da95bdc4ba399097f8a3d5f1c15d0cab882dcd57c10e5e2ab27";
pub const BM1391_S15_GUIDE_DOCUMENT_VERSION: &str = "2019.07.02";
pub const BM1391_S15_GUIDE_CONTROLLER_MODEL: &str = "Ctrl_C43";
pub const BM1391_S15_GUIDE_CONTROLLER_REVISION: &str = "V1.2011";
pub const BM1391_S15_GUIDE_SOC: &str = "XC7Z007SCLG225";
pub const BM1391_S15_GUIDE_PIC: &str = "PIC16(L)F1704";
pub const BM1391_S15_GUIDE_HASHBOARD_CHIPS: u8 = 60;
pub const BM1391_S15_GUIDE_HEADER_SIGNAL_MV: u16 = 3_300;
pub const BM1391_S15_GUIDE_HASHCHAIN_SIGNAL_MV: u16 = 1_800;

/// No held update artifact binds a resident DTB digest to either exact release.
pub const BM1391_S15_RESIDENT_DTB_SHA256: Option<&str> = None;
pub const BM1391_T15_RESIDENT_DTB_SHA256: Option<&str> = None;
/// The guide's controller identity cannot be projected across its geometry
/// conflict, and there is no equivalent held T15 controller guide.
pub const BM1391_S15_EXACT_RELEASE_CONTROLLER_REVISION: Option<&str> = None;
pub const BM1391_T15_EXACT_RELEASE_CONTROLLER_REVISION: Option<&str> = None;
/// The stock names below prove software intent only.  The physical load and
/// electrical rail polarity of GPIO907 still require a schematic/net trace or
/// an independently measured rail transition.
pub const BM1391_GPIO907_PHYSICAL_LOAD_PROVEN: bool = false;
pub const BM1391_GPIO907_ELECTRICAL_POLARITY_PROVEN: bool = false;
pub const BM1391_RELEASE_BOUND_UART_ROUTE_PROVEN: bool = false;
pub const BM1391_BOARD_BOUND_MODEL_IDENTITY_PROVEN: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockRelease {
    S15December2019,
    T15December2019,
}

impl Bm1391StockRelease {
    /// Software expectation recovered from the exact release, not a physical
    /// inventory of an attached board.
    pub const fn stock_expected_chips_per_chain(self) -> u8 {
        match self {
            Self::S15December2019 => BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN,
            Self::T15December2019 => BM1391_T15_STOCK_EXPECTED_CHIPS_PER_CHAIN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391StockReleaseObservation<'a> {
    pub package_sha256: &'a str,
    pub package_size: u64,
    pub version_number: &'a str,
    pub cgminer_sha256: &'a str,
    pub cgminer_size: u64,
    pub baked_pattern_path: &'a str,
    pub boot_bin_sha256: &'a str,
    pub boot_bin_size: u64,
    pub uimage_sha256: &'a str,
    pub uimage_size: u64,
    pub axi_module_sha256: &'a str,
    pub axi_module_size: u64,
    pub fpga_mem_module_sha256: &'a str,
    pub fpga_mem_module_size: u64,
    pub module_vermagic: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391StockReleaseMatchError {
    UnknownPackage,
    PackageSizeMismatch,
    VersionMismatch,
    CgminerMismatch,
    BakedPatternMismatch,
    SharedBootMismatch,
    SharedKernelMismatch,
    AxiModuleMismatch,
    FpgaMemModuleMismatch,
    ModuleVermagicMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391ExactStockReleaseEvidence {
    release: Bm1391StockRelease,
}

impl Bm1391ExactStockReleaseEvidence {
    pub const fn release(&self) -> Bm1391StockRelease {
        self.release
    }

    /// All observation fields are caller-supplied and forgeable.  Exact bytes
    /// identify an offline release artifact, never the attached hardware.
    pub const fn admits_board_identity(&self) -> bool {
        false
    }

    pub const fn admits_live_carrier(&self) -> bool {
        false
    }

    pub const fn admits_voltage_or_rail_control(&self) -> bool {
        false
    }

    pub const fn admits_install(&self) -> bool {
        false
    }
}

fn digest_matches(observed: &str, expected: &str) -> bool {
    observed.eq_ignore_ascii_case(expected)
}

/// Match one exact held release tuple without claiming publisher trust or
/// board identity.  The packages carry their own certificate material; no
/// independently anchored Bitmain trust root was established in this lane.
pub fn match_bm1391_exact_stock_release(
    observation: Bm1391StockReleaseObservation<'_>,
) -> Result<Bm1391ExactStockReleaseEvidence, Bm1391StockReleaseMatchError> {
    let (release, package_size, version, cgminer, pattern) =
        if digest_matches(observation.package_sha256, BM1391_S15_PACKAGE_SHA256) {
            (
                Bm1391StockRelease::S15December2019,
                BM1391_S15_PACKAGE_SIZE,
                BM1391_S15_VERSION_NUMBER,
                BM1391_S15_CGMINER_SHA256,
                BM1391_S15_BAKED_PATTERN_PATH,
            )
        } else if digest_matches(observation.package_sha256, BM1391_T15_PACKAGE_SHA256) {
            (
                Bm1391StockRelease::T15December2019,
                BM1391_T15_PACKAGE_SIZE,
                BM1391_T15_VERSION_NUMBER,
                BM1391_T15_CGMINER_SHA256,
                BM1391_T15_BAKED_PATTERN_PATH,
            )
        } else {
            return Err(Bm1391StockReleaseMatchError::UnknownPackage);
        };

    if observation.package_size != package_size {
        return Err(Bm1391StockReleaseMatchError::PackageSizeMismatch);
    }
    if observation.version_number != version {
        return Err(Bm1391StockReleaseMatchError::VersionMismatch);
    }
    if observation.cgminer_size != BM1391_SHARED_CGMINER_SIZE
        || !digest_matches(observation.cgminer_sha256, cgminer)
    {
        return Err(Bm1391StockReleaseMatchError::CgminerMismatch);
    }
    if observation.baked_pattern_path != pattern {
        return Err(Bm1391StockReleaseMatchError::BakedPatternMismatch);
    }
    if observation.boot_bin_size != BM1391_SHARED_BOOT_BIN_SIZE
        || !digest_matches(observation.boot_bin_sha256, BM1391_SHARED_BOOT_BIN_SHA256)
    {
        return Err(Bm1391StockReleaseMatchError::SharedBootMismatch);
    }
    if observation.uimage_size != BM1391_SHARED_UIMAGE_SIZE
        || !digest_matches(observation.uimage_sha256, BM1391_SHARED_UIMAGE_SHA256)
    {
        return Err(Bm1391StockReleaseMatchError::SharedKernelMismatch);
    }
    if observation.axi_module_size != BM1391_AXI_MODULE_SIZE
        || !digest_matches(observation.axi_module_sha256, BM1391_AXI_MODULE_SHA256)
    {
        return Err(Bm1391StockReleaseMatchError::AxiModuleMismatch);
    }
    if observation.fpga_mem_module_size != BM1391_FPGA_MEM_MODULE_SIZE
        || !digest_matches(
            observation.fpga_mem_module_sha256,
            BM1391_FPGA_MEM_MODULE_SHA256,
        )
    {
        return Err(Bm1391StockReleaseMatchError::FpgaMemModuleMismatch);
    }
    if observation.module_vermagic != BM1391_STOCK_MODULE_VERMAGIC {
        return Err(Bm1391StockReleaseMatchError::ModuleVermagicMismatch);
    }

    Ok(Bm1391ExactStockReleaseEvidence { release })
}

/// Exact shell-script selection from `/proc/meminfo`'s `MemTotal` in KiB.
/// Both comparisons are strict, so either equality takes the default base.
pub const fn bm1391_stock_dma_base_for_memtotal_kib(mem_total_kib: u64) -> u32 {
    if mem_total_kib > BM1391_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB {
        BM1391_FPGA_MEM_LARGE_BASE
    } else if mem_total_kib < BM1391_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB
        && mem_total_kib > BM1391_FPGA_MEM_MEDIUM_RAM_THRESHOLD_KIB
    {
        BM1391_FPGA_MEM_MEDIUM_BASE
    } else {
        BM1391_FPGA_MEM_DEFAULT_BASE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391Gpio907StockIntent {
    PowerOn,
    PowerOff,
}

/// Stock `power.c` software meaning, not a physical-load identification.
pub const fn bm1391_gpio907_stock_level(intent: Bm1391Gpio907StockIntent) -> u8 {
    match intent {
        Bm1391Gpio907StockIntent::PowerOn => 0,
        Bm1391Gpio907StockIntent::PowerOff => 1,
    }
}

/// Recover the exact per-chain PIC selector compiled into each held miner.
/// T15 enables an additional chain-1/2 swap only when that chain's stock route
/// state is exactly `0x0100`; S15 compiles the predicate to constant false.
pub const fn bm1391_stock_pic_selector(
    release: Bm1391StockRelease,
    chain: u8,
    stock_route_state: u16,
) -> u8 {
    if matches!(release, Bm1391StockRelease::T15December2019) && stock_route_state == 0x0100 {
        if chain == 1 {
            return 0x22;
        }
        if chain == 2 {
            return 0x21;
        }
    }
    0x20 | (chain & 7)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391GeneralI2cCommandFields {
    pub device_selector: u8,
    /// Raw stock field placed in bits 27:26.  Its higher-level meaning was not
    /// established, so the API deliberately does not give it a semantic name.
    pub field_27_26: u8,
    pub read: bool,
    pub write_data: Option<u8>,
    pub payload: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391GeneralI2cPackError {
    DeviceSelectorOutsideSevenBits { observed: u8 },
    Field2726OutsideTwoBits { observed: u8 },
}

/// Pure parity packer for the word written to FPGA offset `0x30` by the held
/// miners.  It performs no polling and grants no I2C or controller authority.
pub const fn pack_bm1391_general_i2c_command(
    fields: Bm1391GeneralI2cCommandFields,
) -> Result<u32, Bm1391GeneralI2cPackError> {
    if fields.device_selector > 0x7f {
        return Err(Bm1391GeneralI2cPackError::DeviceSelectorOutsideSevenBits {
            observed: fields.device_selector,
        });
    }
    if fields.field_27_26 > 3 {
        return Err(Bm1391GeneralI2cPackError::Field2726OutsideTwoBits {
            observed: fields.field_27_26,
        });
    }
    let selector = (((fields.device_selector >> 3) & 0x0f) as u32) << 20
        | ((fields.device_selector & 7) as u32) << 16;
    let mut word = selector | ((fields.field_27_26 as u32) << 26) | fields.payload as u32;
    if fields.read {
        word |= 1 << 25;
    }
    if let Some(data) = fields.write_data {
        word |= 1 << 24;
        word |= (data as u32) << 8;
    }
    Ok(word)
}

/// The guide cannot close the exact release carrier tuple because it describes
/// 60 chips while the exact S15 release contains the 72-chip baked route.
pub const fn bm1391_s15_guide_binds_exact_release() -> bool {
    BM1391_S15_GUIDE_HASHBOARD_CHIPS == BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN
}

/// Every still-missing physical facet must be independently bound before a
/// future runtime owner may consider the carrier tuple complete.
pub const fn bm1391_exact_carrier_tuple_complete() -> bool {
    BM1391_S15_RESIDENT_DTB_SHA256.is_some()
        && BM1391_T15_RESIDENT_DTB_SHA256.is_some()
        && BM1391_S15_EXACT_RELEASE_CONTROLLER_REVISION.is_some()
        && BM1391_T15_EXACT_RELEASE_CONTROLLER_REVISION.is_some()
        && BM1391_GPIO907_PHYSICAL_LOAD_PROVEN
        && BM1391_GPIO907_ELECTRICAL_POLARITY_PROVEN
        && BM1391_RELEASE_BOUND_UART_ROUTE_PROVEN
        && BM1391_BOARD_BOUND_MODEL_IDENTITY_PROVEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_observation(release: Bm1391StockRelease) -> Bm1391StockReleaseObservation<'static> {
        let (package_sha256, package_size, version_number, cgminer_sha256, baked_pattern_path) =
            match release {
                Bm1391StockRelease::S15December2019 => (
                    BM1391_S15_PACKAGE_SHA256,
                    BM1391_S15_PACKAGE_SIZE,
                    BM1391_S15_VERSION_NUMBER,
                    BM1391_S15_CGMINER_SHA256,
                    BM1391_S15_BAKED_PATTERN_PATH,
                ),
                Bm1391StockRelease::T15December2019 => (
                    BM1391_T15_PACKAGE_SHA256,
                    BM1391_T15_PACKAGE_SIZE,
                    BM1391_T15_VERSION_NUMBER,
                    BM1391_T15_CGMINER_SHA256,
                    BM1391_T15_BAKED_PATTERN_PATH,
                ),
            };
        Bm1391StockReleaseObservation {
            package_sha256,
            package_size,
            version_number,
            cgminer_sha256,
            cgminer_size: BM1391_SHARED_CGMINER_SIZE,
            baked_pattern_path,
            boot_bin_sha256: BM1391_SHARED_BOOT_BIN_SHA256,
            boot_bin_size: BM1391_SHARED_BOOT_BIN_SIZE,
            uimage_sha256: BM1391_SHARED_UIMAGE_SHA256,
            uimage_size: BM1391_SHARED_UIMAGE_SIZE,
            axi_module_sha256: BM1391_AXI_MODULE_SHA256,
            axi_module_size: BM1391_AXI_MODULE_SIZE,
            fpga_mem_module_sha256: BM1391_FPGA_MEM_MODULE_SHA256,
            fpga_mem_module_size: BM1391_FPGA_MEM_MODULE_SIZE,
            module_vermagic: BM1391_STOCK_MODULE_VERMAGIC,
        }
    }

    #[test]
    fn exact_release_tuples_match_but_never_mint_hardware_authority() {
        for release in [
            Bm1391StockRelease::S15December2019,
            Bm1391StockRelease::T15December2019,
        ] {
            let evidence = match_bm1391_exact_stock_release(exact_observation(release)).unwrap();
            assert_eq!(evidence.release(), release);
            assert!(!evidence.admits_board_identity());
            assert!(!evidence.admits_live_carrier());
            assert!(!evidence.admits_voltage_or_rail_control());
            assert!(!evidence.admits_install());
        }
    }

    #[test]
    fn mixed_model_tuple_and_unknown_package_fail_closed() {
        let mut observation = exact_observation(Bm1391StockRelease::S15December2019);
        observation.cgminer_sha256 = BM1391_T15_CGMINER_SHA256;
        assert_eq!(
            match_bm1391_exact_stock_release(observation),
            Err(Bm1391StockReleaseMatchError::CgminerMismatch)
        );

        let mut observation = exact_observation(Bm1391StockRelease::T15December2019);
        observation.package_sha256 = "00";
        assert_eq!(
            match_bm1391_exact_stock_release(observation),
            Err(Bm1391StockReleaseMatchError::UnknownPackage)
        );
    }

    #[test]
    fn every_release_tuple_field_is_pinned() {
        let mutations: [fn(&mut Bm1391StockReleaseObservation<'static>); 15] = [
            |o| o.package_sha256 = "00",
            |o| o.package_size -= 1,
            |o| o.version_number = BM1391_T15_VERSION_NUMBER,
            |o| o.cgminer_sha256 = BM1391_T15_CGMINER_SHA256,
            |o| o.cgminer_size -= 1,
            |o| o.baked_pattern_path = BM1391_T15_BAKED_PATTERN_PATH,
            |o| o.boot_bin_sha256 = "00",
            |o| o.boot_bin_size -= 1,
            |o| o.uimage_sha256 = "00",
            |o| o.uimage_size -= 1,
            |o| o.axi_module_sha256 = "00",
            |o| o.axi_module_size -= 1,
            |o| o.fpga_mem_module_sha256 = "00",
            |o| o.fpga_mem_module_size -= 1,
            |o| o.module_vermagic = "4.6.0-xilinx",
        ];
        for mutate in mutations {
            let mut observation = exact_observation(Bm1391StockRelease::S15December2019);
            mutate(&mut observation);
            assert!(match_bm1391_exact_stock_release(observation).is_err());
        }
    }

    #[test]
    fn stock_dma_thresholds_preserve_strict_boundary_behavior() {
        assert_eq!(bm1391_stock_dma_base_for_memtotal_kib(400_000), 0x0f00_0000);
        assert_eq!(bm1391_stock_dma_base_for_memtotal_kib(400_001), 0x1f00_0000);
        assert_eq!(bm1391_stock_dma_base_for_memtotal_kib(999_999), 0x1f00_0000);
        assert_eq!(
            bm1391_stock_dma_base_for_memtotal_kib(1_000_000),
            0x0f00_0000
        );
        assert_eq!(
            bm1391_stock_dma_base_for_memtotal_kib(1_000_001),
            0x3f00_0000
        );
    }

    #[test]
    fn gpio907_records_only_stock_software_intent() {
        assert_eq!(
            bm1391_gpio907_stock_level(Bm1391Gpio907StockIntent::PowerOn),
            0
        );
        assert_eq!(
            bm1391_gpio907_stock_level(Bm1391Gpio907StockIntent::PowerOff),
            1
        );
        assert!(!BM1391_GPIO907_PHYSICAL_LOAD_PROVEN);
        assert!(!BM1391_GPIO907_ELECTRICAL_POLARITY_PROVEN);
    }

    #[test]
    fn pic_selector_keeps_s15_default_and_t15_conditional_swap() {
        assert_eq!(
            bm1391_stock_pic_selector(Bm1391StockRelease::S15December2019, 1, 0x0100),
            0x21
        );
        assert_eq!(
            bm1391_stock_pic_selector(Bm1391StockRelease::S15December2019, 2, 0x0100),
            0x22
        );
        assert_eq!(
            bm1391_stock_pic_selector(Bm1391StockRelease::T15December2019, 1, 0),
            0x21
        );
        assert_eq!(
            bm1391_stock_pic_selector(Bm1391StockRelease::T15December2019, 1, 0x0100),
            0x22
        );
        assert_eq!(
            bm1391_stock_pic_selector(Bm1391StockRelease::T15December2019, 2, 0x0100),
            0x21
        );
    }

    #[test]
    fn general_i2c_packer_matches_recovered_pic_read_and_write_words() {
        let write = pack_bm1391_general_i2c_command(Bm1391GeneralI2cCommandFields {
            device_selector: 0x21,
            field_27_26: 0,
            read: false,
            write_data: None,
            payload: 0x55,
        })
        .unwrap();
        assert_eq!(write, 0x0041_0055);

        let read = pack_bm1391_general_i2c_command(Bm1391GeneralI2cCommandFields {
            device_selector: 0x22,
            field_27_26: 0,
            read: true,
            write_data: None,
            payload: 0,
        })
        .unwrap();
        assert_eq!(read, 0x0242_0000);

        let data_write = pack_bm1391_general_i2c_command(Bm1391GeneralI2cCommandFields {
            device_selector: 0x7f,
            field_27_26: 3,
            read: false,
            write_data: Some(0xa5),
            payload: 0x5a,
        })
        .unwrap();
        assert_eq!(data_write, 0x0df7_a55a);
    }

    #[test]
    fn general_i2c_packer_rejects_field_overflow() {
        assert_eq!(
            pack_bm1391_general_i2c_command(Bm1391GeneralI2cCommandFields {
                device_selector: 0x80,
                field_27_26: 0,
                read: false,
                write_data: None,
                payload: 0,
            }),
            Err(Bm1391GeneralI2cPackError::DeviceSelectorOutsideSevenBits { observed: 0x80 })
        );
        assert_eq!(
            pack_bm1391_general_i2c_command(Bm1391GeneralI2cCommandFields {
                device_selector: 0x20,
                field_27_26: 4,
                read: false,
                write_data: None,
                payload: 0,
            }),
            Err(Bm1391GeneralI2cPackError::Field2726OutsideTwoBits { observed: 4 })
        );
    }

    #[test]
    fn guide_geometry_conflict_keeps_exact_carrier_tuple_closed() {
        assert_eq!(BM1391_S15_GUIDE_HASHBOARD_CHIPS, 60);
        assert_eq!(BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN, 72);
        assert!(!bm1391_s15_guide_binds_exact_release());
        assert!(!BM1391_RELEASE_BOUND_UART_ROUTE_PROVEN);
        assert!(!BM1391_BOARD_BOUND_MODEL_IDENTITY_PROVEN);
        assert!(!bm1391_exact_carrier_tuple_complete());
    }
}
