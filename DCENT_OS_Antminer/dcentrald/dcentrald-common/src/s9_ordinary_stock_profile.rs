//! Exact-profile, offline-only facts for an ordinary stock Antminer S9.
//!
//! This module narrows the broad C5-family carrier envelope to the ordinary
//! `am1-s9` production observations. It deliberately rejects the held S9j
//! e531 recovery miner, the S9SE/S9K test jig, the Cyclone-V C5 recovery
//! miner, direct `/dev/mem` access, and the clean-image UIO fabric.
//!
//! Every input accepted here is forgeable data. Success does not prove a
//! retained OS lease, execute a sensor transaction, exercise a fan, service a
//! PIC or host watchdog, validate DMA coherency, or authorize mutation. There
//! is intentionally no live receipt issuer in this module.

pub const S9_ORDINARY_BOARD_TARGET: &str = "am1-s9";

/// Metadata captured from an ordinary production S9 running stock firmware.
///
/// The exact file was not recovered into the corpus, so only the captured MD5
/// and size can currently be matched. This must not be represented as a held
/// SHA-256-backed artifact.
pub const S9_ORDINARY_20190701_BMMINER_SIZE: u64 = 487_472;
pub const S9_ORDINARY_20190701_BMMINER_MD5: &str = "8618bbd2b5ea7fcee19ac598c595af1b";

pub const S9J_E531_BMMINER_SIZE: u64 = 487_640;
pub const S9J_E531_BMMINER_SHA256: &str =
    "e5312ad1e5b2c086906ef96223f9b7b728ad30251264c2bb4575667651669cf2";
pub const S9_SES9K_TEST_JIG_BMMINER_SIZE: u64 = 1_068_416;
pub const S9_SES9K_TEST_JIG_BMMINER_SHA256: &str =
    "46e9579a250d9c1320736ed818b47c7e444d58c7dcc458ec76791ca8b0f1f6d0";
pub const C5_RECOVERY_20160607_BMMINER_SIZE: u64 = 266_028;
pub const C5_RECOVERY_20160607_BMMINER_SHA256: &str =
    "39e0f3fb130174c27f9bb9f5debfb93a2cc9266ffac6bcfad3d11c9a641bc6f0";

/// Comparative S9j module artifacts. The ordinary 2019 module bytes are not
/// held, so these digests are evidence of the mapping implementation, not an
/// ordinary-S9 admission requirement.
pub const S9J_HELD_AXI_MODULE_SHA256: &str =
    "b791de4ab2ad1ee4dbd51a65f89e9b39be75b212abc548f488a721b5bcf4e2b4";
pub const S9J_HELD_FPGA_MEM_MODULE_SHA256: &str =
    "fa0b569b6534b383f2638d5298e69692924c27d8963b2343b5bffee6b7ddfb46";

pub const S9_STOCK_AXI_DEVICE_PATH: &str = "/dev/axi_fpga_dev";
pub const S9_STOCK_FPGA_MEM_DEVICE_PATH: &str = "/dev/fpga_mem";
pub const S9_STOCK_AXI_PHYSICAL_BASE: u32 = 0x43c0_0000;
pub const S9_STOCK_AXI_MAP_LEN: u32 = 0x160;
pub const S9_STOCK_FPGA_MEM_MAP_LEN: u32 = 0x0100_0000;
pub const S9_STOCK_ALLOWED_DMA_BASES: [u32; 3] = [0x0f00_0000, 0x1f00_0000, 0x3f00_0000];

pub const S9_STOCK_FAN_SPEED_OFFSET: u32 = 0x004;
pub const S9_STOCK_FAN_CONTROL_OFFSET: u32 = 0x084;
pub const S9_STOCK_GENERAL_I2C_OFFSET: u32 = 0x030;
pub const S9_STOCK_FAN_READS_PER_SWEEP: usize = 8;
pub const S9_STOCK_FAN_SWEEP_COUNT: usize = 2;
pub const S9_STOCK_FAN_READ_COUNT: usize = S9_STOCK_FAN_READS_PER_SWEEP * S9_STOCK_FAN_SWEEP_COUNT;
pub const S9_STOCK_MIN_ACTIVE_FANS: u8 = 2;
pub const S9_STOCK_RPM_PER_TACH_COUNT: u32 = 120;
pub const S9_STOCK_PWM_PERIOD_TICKS: u16 = 50;
pub const S9_STOCK_PIC_HEARTBEAT_OPCODE: u8 = 0x16;
pub const S9_PRIMARY_SOURCE_HEARTBEAT_GAP_SECONDS: u8 = 10;

/// Exact acquisition route recovered from primary source. Reading a current
/// sensor sample requires ASIC-broadcast/general-I2C traffic and therefore is
/// not part of the passive register probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryThermalAcquisitionRoute {
    AsicBroadcastViaStockGeneralI2c,
}

impl S9OrdinaryThermalAcquisitionRoute {
    pub const fn is_passive_carrier_read(self) -> bool {
        false
    }

    pub const fn requires_retained_mutating_fabric(self) -> bool {
        true
    }
}

pub const S9_ORDINARY_THERMAL_ACQUISITION_ROUTE: S9OrdinaryThermalAcquisitionRoute =
    S9OrdinaryThermalAcquisitionRoute::AsicBroadcastViaStockGeneralI2c;

/// No exact ordinary-production cutoff policy is currently supportable. The
/// held S9j and jig policies are named negative controls, not fallbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryThermalCutoffStatus {
    ExactOrdinaryMinerAndBenchEvidenceMissing,
}

pub const S9_ORDINARY_THERMAL_CUTOFF_STATUS: S9OrdinaryThermalCutoffStatus =
    S9OrdinaryThermalCutoffStatus::ExactOrdinaryMinerAndBenchEvidenceMissing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryWatchdogKind {
    PicRailHeartbeat,
    ZynqHostReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9OrdinaryWatchdogPrerequisite {
    pub kind: S9OrdinaryWatchdogKind,
    pub shares_stock_flat_fabric: bool,
    pub exact_timeout_and_failure_bench_proven: bool,
}

/// Both watchdogs are mandatory future-issuer prerequisites and neither has
/// an ordinary-S9 bench proof in the current evidence set.
pub const S9_ORDINARY_WATCHDOG_PREREQUISITES: [S9OrdinaryWatchdogPrerequisite; 2] = [
    S9OrdinaryWatchdogPrerequisite {
        kind: S9OrdinaryWatchdogKind::PicRailHeartbeat,
        shares_stock_flat_fabric: true,
        exact_timeout_and_failure_bench_proven: false,
    },
    S9OrdinaryWatchdogPrerequisite {
        kind: S9OrdinaryWatchdogKind::ZynqHostReset,
        shares_stock_flat_fabric: false,
        exact_timeout_and_failure_bench_proven: false,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9MinerArtifactFingerprint<'a> {
    pub size: u64,
    pub sha256: Option<&'a str>,
    pub md5: Option<&'a str>,
}

/// Corpus/capture classification. Only the first variant is ordinary S9
/// production metadata; the remaining exact artifacts are negative controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9MinerArtifactClass {
    OrdinaryS9Production20190701CapturedMd5,
    S9jRecoveryE531,
    S9SeS9kTestJig,
    C5Recovery20160607,
    Unknown,
}

fn optional_digest_matches(observed: Option<&str>, expected: &str) -> bool {
    observed.is_some_and(|digest| digest.eq_ignore_ascii_case(expected))
}

pub fn classify_s9_miner_artifact(
    artifact: S9MinerArtifactFingerprint<'_>,
) -> S9MinerArtifactClass {
    if artifact.size == S9_ORDINARY_20190701_BMMINER_SIZE
        && optional_digest_matches(artifact.md5, S9_ORDINARY_20190701_BMMINER_MD5)
    {
        S9MinerArtifactClass::OrdinaryS9Production20190701CapturedMd5
    } else if artifact.size == S9J_E531_BMMINER_SIZE
        && optional_digest_matches(artifact.sha256, S9J_E531_BMMINER_SHA256)
    {
        S9MinerArtifactClass::S9jRecoveryE531
    } else if artifact.size == S9_SES9K_TEST_JIG_BMMINER_SIZE
        && optional_digest_matches(artifact.sha256, S9_SES9K_TEST_JIG_BMMINER_SHA256)
    {
        S9MinerArtifactClass::S9SeS9kTestJig
    } else if artifact.size == C5_RECOVERY_20160607_BMMINER_SIZE
        && optional_digest_matches(artifact.sha256, C5_RECOVERY_20160607_BMMINER_SHA256)
    {
        S9MinerArtifactClass::C5Recovery20160607
    } else {
        S9MinerArtifactClass::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryHardwareRevision {
    C51A,
    C51E,
    C510Flag8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9HardwareVersionError {
    C501IsC5OrTestJig,
    UnobservedC5Revision { observed: u32 },
    WrongBoardType { observed: u8 },
}

/// Match only hardware-version words observed on ordinary S9 units.
///
/// The generic C5 byte is insufficient. In particular, C501 is present in the
/// Cyclone-V/test-jig evidence and is therefore rejected rather than widened.
pub const fn classify_s9_ordinary_hardware_version(
    hardware_version: u32,
) -> Result<S9OrdinaryHardwareRevision, S9HardwareVersionError> {
    match hardware_version {
        0x0000_c51a => Ok(S9OrdinaryHardwareRevision::C51A),
        0x0000_c51e => Ok(S9OrdinaryHardwareRevision::C51E),
        0x0008_c510 => Ok(S9OrdinaryHardwareRevision::C510Flag8),
        0x0000_c501 => Err(S9HardwareVersionError::C501IsC5OrTestJig),
        observed if ((observed >> 8) & 0xff) == 0xc5 => {
            Err(S9HardwareVersionError::UnobservedC5Revision { observed })
        }
        observed => Err(S9HardwareVersionError::WrongBoardType {
            observed: ((observed >> 8) & 0xff) as u8,
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9StockCarrierAccessPath {
    KernelCharacterDevices,
    DirectPhysicalMemory,
    CleanImageUio,
}

/// Claimed retained ownership for every mutating consumer of the flat stock
/// fabric. These booleans remain forgeable until a target-only issuer binds
/// them to one live, cross-process lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockFabricOwnershipObservation {
    pub exclusive_cross_process_lease_retained: bool,
    pub register_aperture_retained: bool,
    pub dma_window_retained: bool,
    pub fan_tach_and_pwm_retained: bool,
    pub asic_i2c_and_pic_heartbeat_retained: bool,
    pub thermal_supervision_retained: bool,
    pub dhash_cut_retained: bool,
}

impl S9StockFabricOwnershipObservation {
    pub const fn complete(self) -> bool {
        self.exclusive_cross_process_lease_retained
            && self.register_aperture_retained
            && self.dma_window_retained
            && self.fan_tach_and_pwm_retained
            && self.asic_i2c_and_pic_heartbeat_retained
            && self.thermal_supervision_retained
            && self.dhash_cut_retained
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockPwmDecode {
    pub high_ticks: u16,
    pub low_ticks: u16,
    pub percent: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9StockPwmDecodeError {
    TickOutOfRange { high: u16, low: u16 },
    InvalidPeriod { high: u16, low: u16 },
}

/// Decode the stock 50-tick PWM packing recovered from primary source and
/// corroborated by ordinary/VNish live words.
pub const fn decode_s9_stock_pwm(word: u32) -> Result<S9StockPwmDecode, S9StockPwmDecodeError> {
    let high = (word >> 16) as u16;
    let low = word as u16;
    if high > S9_STOCK_PWM_PERIOD_TICKS || low > S9_STOCK_PWM_PERIOD_TICKS {
        return Err(S9StockPwmDecodeError::TickOutOfRange { high, low });
    }
    let sum = high + low;
    if sum != S9_STOCK_PWM_PERIOD_TICKS && sum + 1 != S9_STOCK_PWM_PERIOD_TICKS {
        return Err(S9StockPwmDecodeError::InvalidPeriod { high, low });
    }
    let odd = if sum + 1 == S9_STOCK_PWM_PERIOD_TICKS {
        1
    } else {
        0
    };
    let percent = (high as u8) * 2 + odd;
    if percent > 100 {
        return Err(S9StockPwmDecodeError::InvalidPeriod { high, low });
    }
    Ok(S9StockPwmDecode {
        high_ticks: high,
        low_ticks: low,
        percent,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockFanSweepAssessment {
    pub active_id_mask: u8,
    pub active_fan_count: u8,
    pub minimum_active_rpm: u32,
    pub maximum_active_rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9StockFanSweepError {
    ReservedBitsSet { sweep: u8, index: u8, word: u32 },
    ActiveFanSetChanged { first_mask: u8, second_mask: u8 },
    TooFewActiveFans { observed: u8 },
}

/// Validate two eight-read windows from the stock fan FIFO.
///
/// Connector IDs are intentionally not fixed: ordinary stock captured IDs
/// 3/6 while a VNish-on-stock-fabric capture saw 4/5. The stable two-sweep set
/// is D-Central hardening; a connector-map claim still requires a bench
/// exercise. Stock requests eight reads per window but does not require every
/// possible ID to appear exactly once, and a held live sequence cycles only
/// through IDs 0..5.
pub fn assess_s9_stock_fan_sweeps(
    reads: [u32; S9_STOCK_FAN_READ_COUNT],
) -> Result<S9StockFanSweepAssessment, S9StockFanSweepError> {
    let mut active_masks = [0_u8; S9_STOCK_FAN_SWEEP_COUNT];
    let mut min_rpm = u32::MAX;
    let mut max_rpm = 0_u32;

    for (sweep, (sweep_reads, active_mask)) in reads
        .chunks_exact(S9_STOCK_FAN_READS_PER_SWEEP)
        .zip(active_masks.iter_mut())
        .enumerate()
    {
        for (index, word) in sweep_reads.iter().copied().enumerate() {
            if word & !0x7ff != 0 {
                return Err(S9StockFanSweepError::ReservedBitsSet {
                    sweep: sweep as u8,
                    index: index as u8,
                    word,
                });
            }
            let id = ((word >> 8) & 0x7) as u8;
            let id_bit = 1_u8 << id;

            let raw = word & 0xff;
            if raw != 0 {
                *active_mask |= id_bit;
                let rpm = raw * S9_STOCK_RPM_PER_TACH_COUNT;
                min_rpm = min_rpm.min(rpm);
                max_rpm = max_rpm.max(rpm);
            }
        }
    }

    let [first_mask, second_mask] = active_masks;
    if first_mask != second_mask {
        return Err(S9StockFanSweepError::ActiveFanSetChanged {
            first_mask,
            second_mask,
        });
    }
    let count = first_mask.count_ones() as u8;
    if count < S9_STOCK_MIN_ACTIVE_FANS {
        return Err(S9StockFanSweepError::TooFewActiveFans { observed: count });
    }

    Ok(S9StockFanSweepAssessment {
        active_id_mask: first_mask,
        active_fan_count: count,
        minimum_active_rpm: min_rpm,
        maximum_active_rpm: max_rpm,
    })
}

/// Forgeable input to the ordinary-S9 static profile matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9OrdinaryStockStaticObservation<'a> {
    pub board_target: &'a str,
    pub miner_artifact: S9MinerArtifactFingerprint<'a>,
    pub hardware_version: u32,
    pub access_path: S9StockCarrierAccessPath,
    pub axi_module_loaded: bool,
    pub fpga_mem_module_loaded: bool,
    pub axi_device_path: &'a str,
    pub fpga_mem_device_path: &'a str,
    pub register_physical_base: u32,
    pub register_map_len: u32,
    pub dma_physical_base: u32,
    pub dma_map_len: u32,
    pub inherited_dma_registers_match: bool,
    pub clean_fpga_chain_uio_present: bool,
    pub register_probe_read_only: bool,
    pub ownership: S9StockFabricOwnershipObservation,
    pub fan_control_word: u32,
    pub fan_speed_reads: [u32; S9_STOCK_FAN_READ_COUNT],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9OrdinaryStockStaticAssessment {
    hardware_revision: S9OrdinaryHardwareRevision,
    dma_physical_base: u32,
    pwm: S9StockPwmDecode,
    fans: S9StockFanSweepAssessment,
}

impl S9OrdinaryStockStaticAssessment {
    pub const fn hardware_revision(&self) -> S9OrdinaryHardwareRevision {
        self.hardware_revision
    }

    pub const fn dma_physical_base(&self) -> u32 {
        self.dma_physical_base
    }

    pub const fn pwm(&self) -> S9StockPwmDecode {
        self.pwm
    }

    pub const fn fans(&self) -> S9StockFanSweepAssessment {
        self.fans
    }

    /// Offline matching never creates live carrier or safety authority.
    pub const fn admits_live_receipt(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryStockProfileError {
    WrongBoardTarget,
    OrdinaryMinerArtifactNotExact,
    OrdinaryMinerHardwareTupleNotCoObserved {
        observed: S9OrdinaryHardwareRevision,
    },
    S9jMinerArtifact,
    TestJigMinerArtifact,
    C5RecoveryMinerArtifact,
    HardwareVersion(S9HardwareVersionError),
    DirectPhysicalMemoryAccess,
    CleanImageUioAccess,
    AxiModuleNotLoaded,
    FpgaMemModuleNotLoaded,
    AxiDevicePathMismatch,
    FpgaMemDevicePathMismatch,
    RegisterPhysicalBaseMismatch {
        observed: u32,
    },
    RegisterMapLengthMismatch {
        observed: u32,
    },
    DmaPhysicalBaseUnsupported {
        observed: u32,
    },
    DmaMapLengthMismatch {
        observed: u32,
    },
    InheritedDmaRegisterLayoutUnproven,
    ConflictingCleanFpgaChainUioPresent,
    RegisterProbeNotReadOnly,
    FabricOwnershipIncomplete,
    Pwm(S9StockPwmDecodeError),
    FanSweep(S9StockFanSweepError),
}

impl std::fmt::Display for S9OrdinaryStockProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "ordinary S9 static profile mismatch: {self:?}")
    }
}

impl std::error::Error for S9OrdinaryStockProfileError {}

/// Match the exact static ordinary-S9 profile envelope recovered so far.
///
/// This function performs no I/O and its success remains non-authoritative.
pub fn assess_s9_ordinary_stock_static_profile(
    observation: S9OrdinaryStockStaticObservation<'_>,
) -> Result<S9OrdinaryStockStaticAssessment, S9OrdinaryStockProfileError> {
    if observation.board_target != S9_ORDINARY_BOARD_TARGET {
        return Err(S9OrdinaryStockProfileError::WrongBoardTarget);
    }
    match classify_s9_miner_artifact(observation.miner_artifact) {
        S9MinerArtifactClass::OrdinaryS9Production20190701CapturedMd5 => {}
        S9MinerArtifactClass::S9jRecoveryE531 => {
            return Err(S9OrdinaryStockProfileError::S9jMinerArtifact)
        }
        S9MinerArtifactClass::S9SeS9kTestJig => {
            return Err(S9OrdinaryStockProfileError::TestJigMinerArtifact)
        }
        S9MinerArtifactClass::C5Recovery20160607 => {
            return Err(S9OrdinaryStockProfileError::C5RecoveryMinerArtifact)
        }
        S9MinerArtifactClass::Unknown => {
            return Err(S9OrdinaryStockProfileError::OrdinaryMinerArtifactNotExact)
        }
    }

    let hardware_revision = classify_s9_ordinary_hardware_version(observation.hardware_version)
        .map_err(S9OrdinaryStockProfileError::HardwareVersion)?;
    if hardware_revision != S9OrdinaryHardwareRevision::C51E {
        return Err(
            S9OrdinaryStockProfileError::OrdinaryMinerHardwareTupleNotCoObserved {
                observed: hardware_revision,
            },
        );
    }

    match observation.access_path {
        S9StockCarrierAccessPath::KernelCharacterDevices => {}
        S9StockCarrierAccessPath::DirectPhysicalMemory => {
            return Err(S9OrdinaryStockProfileError::DirectPhysicalMemoryAccess)
        }
        S9StockCarrierAccessPath::CleanImageUio => {
            return Err(S9OrdinaryStockProfileError::CleanImageUioAccess)
        }
    }
    if !observation.axi_module_loaded {
        return Err(S9OrdinaryStockProfileError::AxiModuleNotLoaded);
    }
    if !observation.fpga_mem_module_loaded {
        return Err(S9OrdinaryStockProfileError::FpgaMemModuleNotLoaded);
    }
    if observation.axi_device_path != S9_STOCK_AXI_DEVICE_PATH {
        return Err(S9OrdinaryStockProfileError::AxiDevicePathMismatch);
    }
    if observation.fpga_mem_device_path != S9_STOCK_FPGA_MEM_DEVICE_PATH {
        return Err(S9OrdinaryStockProfileError::FpgaMemDevicePathMismatch);
    }
    if observation.register_physical_base != S9_STOCK_AXI_PHYSICAL_BASE {
        return Err(S9OrdinaryStockProfileError::RegisterPhysicalBaseMismatch {
            observed: observation.register_physical_base,
        });
    }
    if observation.register_map_len != S9_STOCK_AXI_MAP_LEN {
        return Err(S9OrdinaryStockProfileError::RegisterMapLengthMismatch {
            observed: observation.register_map_len,
        });
    }
    if !S9_STOCK_ALLOWED_DMA_BASES.contains(&observation.dma_physical_base) {
        return Err(S9OrdinaryStockProfileError::DmaPhysicalBaseUnsupported {
            observed: observation.dma_physical_base,
        });
    }
    if observation.dma_map_len != S9_STOCK_FPGA_MEM_MAP_LEN {
        return Err(S9OrdinaryStockProfileError::DmaMapLengthMismatch {
            observed: observation.dma_map_len,
        });
    }
    if !observation.inherited_dma_registers_match {
        return Err(S9OrdinaryStockProfileError::InheritedDmaRegisterLayoutUnproven);
    }
    if observation.clean_fpga_chain_uio_present {
        return Err(S9OrdinaryStockProfileError::ConflictingCleanFpgaChainUioPresent);
    }
    if !observation.register_probe_read_only {
        return Err(S9OrdinaryStockProfileError::RegisterProbeNotReadOnly);
    }
    if !observation.ownership.complete() {
        return Err(S9OrdinaryStockProfileError::FabricOwnershipIncomplete);
    }

    let pwm = decode_s9_stock_pwm(observation.fan_control_word)
        .map_err(S9OrdinaryStockProfileError::Pwm)?;
    let fans = assess_s9_stock_fan_sweeps(observation.fan_speed_reads)
        .map_err(S9OrdinaryStockProfileError::FanSweep)?;

    Ok(S9OrdinaryStockStaticAssessment {
        hardware_revision,
        dma_physical_base: observation.dma_physical_base,
        pwm,
        fans,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryEvidenceClass {
    OfflineImplemented,
    BenchRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9OrdinaryFutureIssuerGate {
    ArtifactSiblingDifferential,
    PassiveCarrierTupleParser,
    PassiveFanAndPwmParser,
    RecoverExactOrdinaryMinerAndModuleBytes,
    ExerciseAndMapBothFanConnectors,
    ProveFanStallAndTachFailureResponse,
    IdentifyCalibrateAndAgeAllThermalSensors,
    ProveThermalCutoffBoundaryTimingAndOrder,
    ProvePicHeartbeatCadenceAndLossCut,
    ProveHostWatchdogResetAndRecovery,
    ProveDmaCoherencyShareCorrelationAndSoak,
    ProveCrashLeaseTeardownAndReacquisition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9OrdinaryIssuerRequirement {
    pub gate: S9OrdinaryFutureIssuerGate,
    pub evidence: S9OrdinaryEvidenceClass,
}

/// Current evidence boundary for any future live receipt issuer.
pub const S9_ORDINARY_FUTURE_ISSUER_REQUIREMENTS: [S9OrdinaryIssuerRequirement; 12] = [
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ArtifactSiblingDifferential,
        evidence: S9OrdinaryEvidenceClass::OfflineImplemented,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::PassiveCarrierTupleParser,
        evidence: S9OrdinaryEvidenceClass::OfflineImplemented,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::PassiveFanAndPwmParser,
        evidence: S9OrdinaryEvidenceClass::OfflineImplemented,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::RecoverExactOrdinaryMinerAndModuleBytes,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ExerciseAndMapBothFanConnectors,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ProveFanStallAndTachFailureResponse,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::IdentifyCalibrateAndAgeAllThermalSensors,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ProveThermalCutoffBoundaryTimingAndOrder,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ProvePicHeartbeatCadenceAndLossCut,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ProveHostWatchdogResetAndRecovery,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ProveDmaCoherencyShareCorrelationAndSoak,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
    S9OrdinaryIssuerRequirement {
        gate: S9OrdinaryFutureIssuerGate::ProveCrashLeaseTeardownAndReacquisition,
        evidence: S9OrdinaryEvidenceClass::BenchRequired,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(class: S9MinerArtifactClass) -> S9MinerArtifactFingerprint<'static> {
        match class {
            S9MinerArtifactClass::OrdinaryS9Production20190701CapturedMd5 => {
                S9MinerArtifactFingerprint {
                    size: S9_ORDINARY_20190701_BMMINER_SIZE,
                    sha256: None,
                    md5: Some(S9_ORDINARY_20190701_BMMINER_MD5),
                }
            }
            S9MinerArtifactClass::S9jRecoveryE531 => S9MinerArtifactFingerprint {
                size: S9J_E531_BMMINER_SIZE,
                sha256: Some(S9J_E531_BMMINER_SHA256),
                md5: None,
            },
            S9MinerArtifactClass::S9SeS9kTestJig => S9MinerArtifactFingerprint {
                size: S9_SES9K_TEST_JIG_BMMINER_SIZE,
                sha256: Some(S9_SES9K_TEST_JIG_BMMINER_SHA256),
                md5: None,
            },
            S9MinerArtifactClass::C5Recovery20160607 => S9MinerArtifactFingerprint {
                size: C5_RECOVERY_20160607_BMMINER_SIZE,
                sha256: Some(C5_RECOVERY_20160607_BMMINER_SHA256),
                md5: None,
            },
            S9MinerArtifactClass::Unknown => S9MinerArtifactFingerprint {
                size: 1,
                sha256: None,
                md5: None,
            },
        }
    }

    fn fan_reads(active_ids: &[u8]) -> [u32; S9_STOCK_FAN_READ_COUNT] {
        let mut reads = [0_u32; S9_STOCK_FAN_READ_COUNT];
        for sweep in 0..S9_STOCK_FAN_SWEEP_COUNT {
            for id in 0..S9_STOCK_FAN_READS_PER_SWEEP {
                let raw = if active_ids.contains(&(id as u8)) {
                    45
                } else {
                    0
                };
                reads[sweep * S9_STOCK_FAN_READS_PER_SWEEP + id] = ((id as u32) << 8) | raw;
            }
        }
        reads
    }

    fn six_id_cycling_fan_reads() -> [u32; S9_STOCK_FAN_READ_COUNT] {
        let ids = [0_u8, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3];
        ids.map(|id| {
            let raw = match id {
                4 => 0x1d,
                5 => 0x17,
                _ => 0,
            };
            ((id as u32) << 8) | raw
        })
    }

    fn complete_ownership() -> S9StockFabricOwnershipObservation {
        S9StockFabricOwnershipObservation {
            exclusive_cross_process_lease_retained: true,
            register_aperture_retained: true,
            dma_window_retained: true,
            fan_tach_and_pwm_retained: true,
            asic_i2c_and_pic_heartbeat_retained: true,
            thermal_supervision_retained: true,
            dhash_cut_retained: true,
        }
    }

    fn valid_observation() -> S9OrdinaryStockStaticObservation<'static> {
        S9OrdinaryStockStaticObservation {
            board_target: S9_ORDINARY_BOARD_TARGET,
            miner_artifact: fingerprint(
                S9MinerArtifactClass::OrdinaryS9Production20190701CapturedMd5,
            ),
            hardware_version: 0x0000_c51e,
            access_path: S9StockCarrierAccessPath::KernelCharacterDevices,
            axi_module_loaded: true,
            fpga_mem_module_loaded: true,
            axi_device_path: S9_STOCK_AXI_DEVICE_PATH,
            fpga_mem_device_path: S9_STOCK_FPGA_MEM_DEVICE_PATH,
            register_physical_base: S9_STOCK_AXI_PHYSICAL_BASE,
            register_map_len: S9_STOCK_AXI_MAP_LEN,
            dma_physical_base: 0x1f00_0000,
            dma_map_len: S9_STOCK_FPGA_MEM_MAP_LEN,
            inherited_dma_registers_match: true,
            clean_fpga_chain_uio_present: false,
            register_probe_read_only: true,
            ownership: complete_ownership(),
            fan_control_word: 0x002c_0006,
            fan_speed_reads: fan_reads(&[3, 6]),
        }
    }

    #[test]
    fn artifact_classifier_keeps_ordinary_s9j_jig_and_c5_separate() {
        for class in [
            S9MinerArtifactClass::OrdinaryS9Production20190701CapturedMd5,
            S9MinerArtifactClass::S9jRecoveryE531,
            S9MinerArtifactClass::S9SeS9kTestJig,
            S9MinerArtifactClass::C5Recovery20160607,
            S9MinerArtifactClass::Unknown,
        ] {
            assert_eq!(classify_s9_miner_artifact(fingerprint(class)), class);
        }
    }

    #[test]
    fn artifact_classifier_requires_digest_and_size_together() {
        let mut ordinary =
            fingerprint(S9MinerArtifactClass::OrdinaryS9Production20190701CapturedMd5);
        ordinary.size += 1;
        assert_eq!(
            classify_s9_miner_artifact(ordinary),
            S9MinerArtifactClass::Unknown
        );
    }

    #[test]
    fn only_observed_ordinary_hardware_words_are_accepted() {
        assert_eq!(
            classify_s9_ordinary_hardware_version(0x0000_c51a),
            Ok(S9OrdinaryHardwareRevision::C51A)
        );
        assert_eq!(
            classify_s9_ordinary_hardware_version(0x0000_c51e),
            Ok(S9OrdinaryHardwareRevision::C51E)
        );
        assert_eq!(
            classify_s9_ordinary_hardware_version(0x0008_c510),
            Ok(S9OrdinaryHardwareRevision::C510Flag8)
        );
        assert_eq!(
            classify_s9_ordinary_hardware_version(0x0000_c501),
            Err(S9HardwareVersionError::C501IsC5OrTestJig)
        );
        assert!(matches!(
            classify_s9_ordinary_hardware_version(0x0000_c51b),
            Err(S9HardwareVersionError::UnobservedC5Revision { .. })
        ));
    }

    #[test]
    fn pwm_words_round_trip_even_and_odd_percentages() {
        assert_eq!(
            decode_s9_stock_pwm(0x000e_0024),
            Ok(S9StockPwmDecode {
                high_ticks: 14,
                low_ticks: 36,
                percent: 28,
            })
        );
        assert_eq!(
            decode_s9_stock_pwm(0x000e_0023),
            Ok(S9StockPwmDecode {
                high_ticks: 14,
                low_ticks: 35,
                percent: 29,
            })
        );
        assert!(decode_s9_stock_pwm(0x0033_0000).is_err());
    }

    #[test]
    fn fan_identity_is_stable_but_connector_ids_are_not_hardcoded() {
        let stock = assess_s9_stock_fan_sweeps(fan_reads(&[3, 6])).unwrap();
        assert_eq!(stock.active_id_mask, (1 << 3) | (1 << 6));
        assert_eq!(stock.minimum_active_rpm, 5_400);

        let vnish_observation = assess_s9_stock_fan_sweeps(fan_reads(&[4, 5])).unwrap();
        assert_eq!(vnish_observation.active_id_mask, (1 << 4) | (1 << 5));
        assert_eq!(vnish_observation.active_fan_count, 2);

        let observed_six_id_cycle = assess_s9_stock_fan_sweeps(six_id_cycling_fan_reads()).unwrap();
        assert_eq!(observed_six_id_cycle.active_id_mask, (1 << 4) | (1 << 5));
        assert_eq!(observed_six_id_cycle.minimum_active_rpm, 2_760);
        assert_eq!(observed_six_id_cycle.maximum_active_rpm, 3_480);
    }

    #[test]
    fn fan_sweeps_reject_unstable_single_fan_and_reserved_bits() {
        let mut unstable = fan_reads(&[3, 6]);
        unstable[8 + 6] = 6 << 8;
        assert!(matches!(
            assess_s9_stock_fan_sweeps(unstable),
            Err(S9StockFanSweepError::ActiveFanSetChanged { .. })
        ));
        assert_eq!(
            assess_s9_stock_fan_sweeps(fan_reads(&[3])),
            Err(S9StockFanSweepError::TooFewActiveFans { observed: 1 })
        );

        let mut reserved = fan_reads(&[3, 6]);
        reserved[0] |= 1 << 31;
        assert!(matches!(
            assess_s9_stock_fan_sweeps(reserved),
            Err(S9StockFanSweepError::ReservedBitsSet { .. })
        ));
    }

    #[test]
    fn complete_static_tuple_is_data_only_and_never_a_receipt() {
        let assessment = assess_s9_ordinary_stock_static_profile(valid_observation()).unwrap();
        assert_eq!(
            assessment.hardware_revision(),
            S9OrdinaryHardwareRevision::C51E
        );
        assert_eq!(assessment.dma_physical_base(), 0x1f00_0000);
        assert_eq!(assessment.pwm().percent, 88);
        assert_eq!(assessment.fans().active_fan_count, 2);
        assert!(!assessment.admits_live_receipt());
    }

    #[test]
    fn exact_sibling_artifacts_are_refused_by_name() {
        for (class, expected) in [
            (
                S9MinerArtifactClass::S9jRecoveryE531,
                S9OrdinaryStockProfileError::S9jMinerArtifact,
            ),
            (
                S9MinerArtifactClass::S9SeS9kTestJig,
                S9OrdinaryStockProfileError::TestJigMinerArtifact,
            ),
            (
                S9MinerArtifactClass::C5Recovery20160607,
                S9OrdinaryStockProfileError::C5RecoveryMinerArtifact,
            ),
        ] {
            let mut observation = valid_observation();
            observation.miner_artifact = fingerprint(class);
            assert_eq!(
                assess_s9_ordinary_stock_static_profile(observation),
                Err(expected)
            );
        }
    }

    #[test]
    fn july_2019_artifact_is_not_cross_producted_with_other_fpga_captures() {
        for (hardware_version, expected_revision) in [
            (0x0008_c510, S9OrdinaryHardwareRevision::C510Flag8),
            (0x0000_c51a, S9OrdinaryHardwareRevision::C51A),
        ] {
            let mut observation = valid_observation();
            observation.hardware_version = hardware_version;
            assert_eq!(
                assess_s9_ordinary_stock_static_profile(observation),
                Err(
                    S9OrdinaryStockProfileError::OrdinaryMinerHardwareTupleNotCoObserved {
                        observed: expected_revision,
                    }
                )
            );
        }
    }

    #[test]
    fn vnish_direct_memory_and_clean_uio_paths_are_not_issuer_candidates() {
        let mut direct = valid_observation();
        direct.access_path = S9StockCarrierAccessPath::DirectPhysicalMemory;
        assert_eq!(
            assess_s9_ordinary_stock_static_profile(direct),
            Err(S9OrdinaryStockProfileError::DirectPhysicalMemoryAccess)
        );

        let mut clean = valid_observation();
        clean.access_path = S9StockCarrierAccessPath::CleanImageUio;
        assert_eq!(
            assess_s9_ordinary_stock_static_profile(clean),
            Err(S9OrdinaryStockProfileError::CleanImageUioAccess)
        );
    }

    #[test]
    fn c5_byte_and_dynamic_major_numbers_cannot_replace_exact_geometry() {
        let mut c501 = valid_observation();
        c501.hardware_version = 0x0000_c501;
        assert_eq!(
            assess_s9_ordinary_stock_static_profile(c501),
            Err(S9OrdinaryStockProfileError::HardwareVersion(
                S9HardwareVersionError::C501IsC5OrTestJig
            ))
        );

        let mut wrong_base = valid_observation();
        wrong_base.register_physical_base = 0xff20_0000;
        assert!(matches!(
            assess_s9_ordinary_stock_static_profile(wrong_base),
            Err(S9OrdinaryStockProfileError::RegisterPhysicalBaseMismatch { .. })
        ));
    }

    #[test]
    fn each_retained_ownership_endpoint_is_load_bearing() {
        for index in 0..7 {
            let mut observation = valid_observation();
            match index {
                0 => observation.ownership.exclusive_cross_process_lease_retained = false,
                1 => observation.ownership.register_aperture_retained = false,
                2 => observation.ownership.dma_window_retained = false,
                3 => observation.ownership.fan_tach_and_pwm_retained = false,
                4 => observation.ownership.asic_i2c_and_pic_heartbeat_retained = false,
                5 => observation.ownership.thermal_supervision_retained = false,
                6 => observation.ownership.dhash_cut_retained = false,
                _ => unreachable!(),
            }
            assert_eq!(
                assess_s9_ordinary_stock_static_profile(observation),
                Err(S9OrdinaryStockProfileError::FabricOwnershipIncomplete)
            );
        }
    }

    #[test]
    fn dma_uio_and_read_only_guards_fail_closed() {
        let mut observation = valid_observation();
        observation.dma_physical_base = 0x2000_0000;
        assert!(matches!(
            assess_s9_ordinary_stock_static_profile(observation),
            Err(S9OrdinaryStockProfileError::DmaPhysicalBaseUnsupported { .. })
        ));

        let mut observation = valid_observation();
        observation.clean_fpga_chain_uio_present = true;
        assert_eq!(
            assess_s9_ordinary_stock_static_profile(observation),
            Err(S9OrdinaryStockProfileError::ConflictingCleanFpgaChainUioPresent)
        );

        let mut observation = valid_observation();
        observation.register_probe_read_only = false;
        assert_eq!(
            assess_s9_ordinary_stock_static_profile(observation),
            Err(S9OrdinaryStockProfileError::RegisterProbeNotReadOnly)
        );
    }

    #[test]
    fn future_issuer_matrix_has_no_offline_shortcut_for_bench_gates() {
        assert!(!S9_ORDINARY_THERMAL_ACQUISITION_ROUTE.is_passive_carrier_read());
        assert!(S9_ORDINARY_THERMAL_ACQUISITION_ROUTE.requires_retained_mutating_fabric());
        assert_eq!(
            S9_ORDINARY_THERMAL_CUTOFF_STATUS,
            S9OrdinaryThermalCutoffStatus::ExactOrdinaryMinerAndBenchEvidenceMissing
        );
        assert!(S9_ORDINARY_WATCHDOG_PREREQUISITES
            .iter()
            .all(|prerequisite| !prerequisite.exact_timeout_and_failure_bench_proven));
        assert_eq!(
            S9_ORDINARY_FUTURE_ISSUER_REQUIREMENTS
                .iter()
                .filter(|requirement| {
                    requirement.evidence == S9OrdinaryEvidenceClass::OfflineImplemented
                })
                .count(),
            3
        );
        assert_eq!(
            S9_ORDINARY_FUTURE_ISSUER_REQUIREMENTS
                .iter()
                .filter(|requirement| {
                    requirement.evidence == S9OrdinaryEvidenceClass::BenchRequired
                })
                .count(),
            9
        );
    }
}
