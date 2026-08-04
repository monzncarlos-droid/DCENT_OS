//! BoardDesc — declarative composition identity for a control-board target (ADR-0011).
//!
//! # Purpose
//!
//! New hardware support should be **data + thin backends**, not a new
//! `*_mining.rs` product. This module defines the host-safe, HAL-free shape of
//! that data so packaging, toolbox, TD-003 gates, and the daemon can eventually
//! share one registry.
//!
//! # Status (2026-07-11)
//!
//! Runtime adoption is deliberately narrow. The standard daemon binds an exact
//! registry row to its immutable platform-identity snapshot and uses typed
//! [`BoardFamily`] to reject a declared/observed control-board contradiction
//! before serialized-I2C construction. Main runtime dispatch also admits exact
//! transport/work-engine pairs before constructing a mining arm. The declared
//! ASIC protocol is an admission constraint, not measured-silicon evidence:
//! mutation-capable engines must bind it to configured or observed identity.
//! Remaining fields are migration scaffolding and do not select hashboard, PSU,
//! cooling, network, or complete-miner behavior.
//!
//! # Facets (see `docs/architecture/COMPOSITION_MODEL.md`)
//!
//! `BoardDesc` names a packaged target-composition row. ASIC identity,
//! hashboard SKU, PSU, and cooling are still detected or profiled separately
//! and bound at bring-up time; a target's protocol declaration only narrows
//! what a runtime is permitted to attempt.

#![allow(dead_code)] // Scaffold: fields/enums reserved for migration consumers.

use dcent_schema::hardware::{
    ArtifactKind, ArtifactMaturity, GenericConstruction, HardwareEnablementPolicy,
    ImplementationMaturity, InstallAuthorization, LifecycleLane, RecoveryMaturity, RuntimeStatus,
    StorageTopology, UpdateMechanism,
};

/// High-level SoC / carrier family (mirrors HAL `BoardType` names without
/// depending on `dcentrald-hal`, so Windows host tests stay clean).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoardFamily {
    /// Zynq-7000 am1/am2 class (S9, S17, S19, S19j Pro XIL).
    Zynq,
    /// TI AM335x BeagleBone class.
    BeagleBone,
    /// Amlogic A113D class.
    Amlogic,
    /// CVITEK CV183x class.
    Cvitek,
    /// STM32MP15 / BCB100 lab class.
    Stm32Mp15,
}

impl BoardFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zynq => "zynq",
            Self::BeagleBone => "beaglebone",
            Self::Amlogic => "amlogic",
            Self::Cvitek => "cvitek",
            Self::Stm32Mp15 => "stm32mp15",
        }
    }
}

/// How the daemon talks to the ASIC chain (transport facet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainTransportKind {
    /// Braiins-layout FPGA FIFO via UIO (`FpgaChain`).
    FpgaUio,
    /// AM2 hybrid: PL UART and/or FPGA work (recipe-selected).
    ZynqHybrid,
    /// Linux serial (`/dev/ttyS*` / `ttyO*`) NS16550-class.
    Serial,
    /// Bitmain stock `/dev/axi_fpga_dev` mmap path.
    StockFpga,
    /// CVITEK `uart_trans` kernel helper.
    UartTrans,
    /// Management-only / no chain open.
    None,
}

impl ChainTransportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FpgaUio => "fpga_uio",
            Self::ZynqHybrid => "zynq_hybrid",
            Self::Serial => "serial",
            Self::StockFpga => "stock_fpga",
            Self::UartTrans => "uart_trans",
            Self::None => "none",
        }
    }
}

/// Where mining work is pushed (work-engine facet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkEngineKind {
    FpgaWorkFifo,
    SerialWork,
    StockDma,
    /// API/dashboard only; hash boards not energized by this target default.
    ManagementOnly,
}

/// ASIC wire-protocol identity admitted by a composed board target.
///
/// This is the protocol family a mining engine is allowed to speak, not proof
/// that silicon was observed at runtime.  Mutation-capable constructors must
/// bind this declared identity to independently configured or discovered ASIC
/// evidence before they can open a chain.  Keeping it separate from transport
/// prevents a shared UART/FPGA carrier from accidentally authorizing a
/// different chip family's register map or work codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsicProtocolIdentity {
    Bm1387,
    /// S15 / T15 7nm silicon.
    ///
    /// The numeric mapping below is a *catalog* identity used by declarative
    /// registration and the acceptance matrix. It is deliberately NOT evidence
    /// that a chain reporting `0x1391` is trustworthy: BM1391 enumerates
    /// register-compatible as `0x1387` (see `dcentrald-asic` `bm1387.rs`), so a
    /// raw `0x1391` on a serial chain is refused as an unsupported identity
    /// layout rather than decoded.
    Bm1391,
    Bm1396,
    Bm1397,
    Bm1398,
    Bm1362,
    Bm1366,
    Bm1368,
    Bm1370,
    /// The target marker is insufficient; passive/runtime identity evidence
    /// must select the protocol before any ASIC mutation.
    RuntimeDiscovered,
}

impl AsicProtocolIdentity {
    /// Map the canonical numeric ChipID used by ASIC drivers and configuration
    /// into the protocol identity consumed by runtime admission.
    pub const fn from_chip_id(chip_id: u16) -> Option<Self> {
        match chip_id {
            0x1387 => Some(Self::Bm1387),
            0x1391 => Some(Self::Bm1391),
            0x1396 => Some(Self::Bm1396),
            0x1397 => Some(Self::Bm1397),
            0x1398 => Some(Self::Bm1398),
            0x1362 => Some(Self::Bm1362),
            0x1366 => Some(Self::Bm1366),
            0x1368 => Some(Self::Bm1368),
            0x1370 => Some(Self::Bm1370),
            _ => None,
        }
    }

    /// Reverse map for profile / nominal-hashrate lookup (P2-9 composition).
    ///
    /// [`Self::RuntimeDiscovered`] has no single ChipID — returns `None` so
    /// callers must use measured silicon identity instead of guessing.
    pub const fn to_chip_id(self) -> Option<u16> {
        match self {
            Self::Bm1387 => Some(0x1387),
            Self::Bm1391 => Some(0x1391),
            Self::Bm1396 => Some(0x1396),
            Self::Bm1397 => Some(0x1397),
            Self::Bm1398 => Some(0x1398),
            Self::Bm1362 => Some(0x1362),
            Self::Bm1366 => Some(0x1366),
            Self::Bm1368 => Some(0x1368),
            Self::Bm1370 => Some(0x1370),
            Self::RuntimeDiscovered => None,
        }
    }

    /// Parse the canonical `BMxxxx` label used by configuration and hardware
    /// identity snapshots. Unknown labels remain unknown instead of being
    /// coerced to a nearby protocol family.
    pub fn from_chip_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_uppercase().as_str() {
            "BM1387" => Some(Self::Bm1387),
            "BM1391" => Some(Self::Bm1391),
            "BM1396" => Some(Self::Bm1396),
            "BM1397" => Some(Self::Bm1397),
            "BM1398" => Some(Self::Bm1398),
            "BM1362" => Some(Self::Bm1362),
            "BM1366" => Some(Self::Bm1366),
            "BM1368" => Some(Self::Bm1368),
            "BM1370" => Some(Self::Bm1370),
            _ => None,
        }
    }
}

/// Proof that a board composition and independent runtime identity evidence
/// agree on one exact ASIC protocol.
///
/// The field is private so mutation-capable engines cannot mint the proof from
/// an enum literal.  Proofs are created only by [`BoardDesc::admit_asic_protocol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsicProtocolAdmission {
    identity: AsicProtocolIdentity,
}

impl AsicProtocolAdmission {
    pub const fn identity(self) -> AsicProtocolIdentity {
        self.identity
    }
}

/// Voltage-controller class (power facet; protocol details live in asic crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoltageControllerClass {
    Pic16F1704,
    DsPic33Ep,
    Pic1704,
    /// Exact hardware identity proves no hashboard voltage MCU exists.
    NoPic,
    /// The control-board target alone cannot select a controller protocol.
    /// Runtime subtype/topology discovery must refine this before mutation.
    RuntimeDiscovered,
}

/// Legacy combined slot/update policy.
///
/// New authorization or update decisions MUST use [`BoardDesc::enablement`].
/// This enum remains temporarily for runtime-dispatch compatibility while
/// those call sites migrate; notably, `LabGated` is not a storage topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotPolicy {
    /// Dual-copy U-Boot env + inactive rootfs (classic Zynq DCENT sysupgrade).
    ZynqAbFwSetenv,
    /// Single eMMC/NAND slot — no A/B fallback (e.g. some CV paths).
    SingleSlot,
    /// SD-first / no trusted env map (BB empty fw_env).
    SdOnly,
    /// Lab / undocumented — refuse product install without override.
    LabGated,
}

const ZYNQ_PUBLIC_UPDATE_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::PublicBeta,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
};

const ZYNQ_LAB_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
};

const ZYNQ_RUNTIME_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
};

const AMLOGIC_LAB_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::HostRootfsWindow,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
};

const AMLOGIC_RUNTIME_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::HostRootfsWindow,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
};

const BEAGLEBONE_SD_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::ExternalMediaOnly,
    update_mechanism: UpdateMechanism::SdImage,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::EvidenceOnly,
    artifact_kind: ArtifactKind::SdCardPayload,
    artifact_maturity: ArtifactMaturity::Experimental,
};

const CV1835_EVIDENCE_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::EmmcContentSelectorEvidenceOnly,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
};

/// STM32MP15 / BCB100: every facet refuses, and `storage_topology` is
/// explicitly `Unknown` rather than borrowed from a sibling family.
///
/// The BCB100 carrier is documented as eMMC + microSD boot
/// (`dcentrald-hal/src/platform/stm32mp15.rs:5`), but no bench probe has ever
/// captured its partition map, so we may not claim `SingleSlot` (which would
/// assert we know where a writer would land) nor `ExternalMediaOnly` (which
/// would assert SD is the only surface). `UpdateMechanism::None` is the
/// matching honest value: unlike CVitek there is not even a passive boot
/// selector we have read.
const STM32MP15_UNVERIFIED_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::Unknown,
    update_mechanism: UpdateMechanism::None,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
};

/// Retained CV1835 reverse-engineering evidence backing the deliberate
/// `EvidenceRetainedNotImplemented` refusal on `cv1835-s19jpro`
/// (`CViTekPlatform::new`, `dcentrald-hal/src/platform/cvitek.rs`).
/// Paths are relative to `DCENT_OS_Antminer/dcentrald/` and existence-checked
/// by `cv1835_retained_evidence_paths_exist_on_disk`.
const CV1835_RETAINED_EVIDENCE: &[&str] = &[
    "dcentrald-hal/src/platform/cvitek.rs",
    "dcentrald-hal/src/platform/cvitek_cold_boot.rs",
    "dcentrald-hal/src/platform/cvitek_pinmux.rs",
];

/// The four am1 S15/T15-class control-board datums that remain UNCONFIRMED
/// (`scripts/hw-acceptance/skus.conf` rows `am1-s15` / `am1-t15`: "4
/// control-board datums UNCONFIRMED (capture-first)").
const AM1_S15_CLASS_UNCONFIRMED_DATUMS: &[&str] = &[
    "control-board GPIO map",
    "chain UART transport bases",
    "I2C topology",
    "cold-boot sequence",
];

/// BCB100 datums that no bench probe has captured.
///
/// Sourced from the HAL scaffold's own refusals, not from a family guess:
/// `stm32mp15.rs:31-34` marks `BCB100_CANDIDATE_CHAIN_UARTS` "inferred",
/// `:195` refuses fan control because the PWM/tach map is not live-verified,
/// `:201` refuses GPIO control because the reset/plug map is not
/// live-verified, and the toolbox route notes the exact-pilot posture holds
/// "until a bench probe captures pic_address / plug_detect_gpio /
/// enable_gpio" (`dcent-toolbox/src/dcent_toolbox/core/installer.py:2008-2011`).
const BCB100_UNCONFIRMED_DATUMS: &[&str] = &[
    "hashboard voltage controller address (pic_address)",
    "plug-detect GPIO map",
    "hashboard enable / reset GPIO map",
    "fan PWM and tachometer map",
    "chain UART device mapping (ttySTM* candidates are inferred, not captured)",
    "eMMC/microSD partition map and boot selector",
];

/// Declarative control-board target description.
///
/// `board_target` should match `/etc/dcentos/board_target` and toolbox package
/// identity strings (e.g. `am2-s19j`, `am1-s9`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardDesc {
    /// Canonical target id (`am2-s19j`, `am1-s9`, …).
    pub board_target: &'static str,
    /// Coarse SoC family.
    pub family: BoardFamily,
    /// Default chain transport for this target.
    pub chain_transport: ChainTransportKind,
    /// Default work engine.
    pub work_engine: WorkEngineKind,
    /// ASIC protocol expected by this complete target composition.  This is an
    /// admission constraint only; runtime evidence still has to agree.
    pub asic_protocol: AsicProtocolIdentity,
    /// Informational controller expectation, never mutation authority.
    /// Use `RuntimeDiscovered` when the control-board target is insufficient.
    pub voltage_controller: VoltageControllerClass,
    /// Install / recovery slot policy.
    pub slot_policy: SlotPolicy,
    /// Independent storage, artifact, maturity, authorization, and recovery
    /// facets. This is the authoritative install/update contract.
    pub enablement: HardwareEnablementPolicy,
    /// Whether a public-beta package may be used for first install from a
    /// non-DCENT_OS source. This is intentionally narrower than
    /// `enablement.install_authorization`, which also governs self-update on an
    /// already-running DCENT_OS target.
    pub public_beta_install: bool,
    /// Whether mining is allowed to auto-start on a fresh image (usually false).
    pub mining_default_enabled: bool,
    /// Why this target does or does not run (H7 G8). Distinguishes an
    /// architectural routing refusal (`SpecialisedLifecycle` — e.g. Amlogic,
    /// which mines via the native serial lane and deliberately refuses generic
    /// `Platform` construction) from a genuine fail-closed
    /// `EvidenceRetainedNotImplemented` (e.g. CVitek). Orthogonal to
    /// `enablement` maturity/authorization facets: classification/reporting
    /// only, never mutation authority.
    pub runtime_status: RuntimeStatus,
}

impl BoardDesc {
    /// Well-known beta-tier S9 Xilinx target (am1).
    pub const fn am1_s9() -> Self {
        Self {
            board_target: "am1-s9",
            runtime_status: RuntimeStatus::GenericPlatform,
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1387,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_PUBLIC_UPDATE_ENABLEMENT,
            public_beta_install: true,
            mining_default_enabled: false,
        }
    }

    /// S15 exact composition; management-only, capture-first.
    ///
    /// Registering the row does NOT enable the hardware — every enablement
    /// facet below refuses. What it buys is a *typed* refusal: before this row
    /// existed, `dcent-accept.sh`'s install-hint policy found zero matching
    /// entries for `am1-s15` and exited with an untyped "install policy is not
    /// uniquely declared" error, which reads as a tooling bug rather than a
    /// deliberate decision. Now it resolves to `install_authorization: denied`
    /// plus `artifact_kind: none` and reports PERSISTENT INSTALL REFUSED.
    ///
    /// `chain_transport: None` is the fail-closed choice while the four
    /// control-board datums remain UNCONFIRMED (`scripts/hw-acceptance/skus.conf`).
    /// Declaring a concrete transport here would assert an am1 carrier nobody
    /// has captured; a target that cannot open a chain cannot open the wrong
    /// one. Likewise `voltage_controller: RuntimeDiscovered` — the S9 template's
    /// `Pic16F1704` is a real controller claim and must not be copied across on
    /// family resemblance.
    pub const fn am1_s15() -> Self {
        Self {
            board_target: "am1-s15",
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM1_S15_CLASS_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1391,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// T15 exact composition; management-only sibling of [`Self::am1_s15`].
    ///
    /// Same silicon and the same UNCONFIRMED control-board datums, so it
    /// carries the identical fail-closed facets. Kept as its own row rather
    /// than aliased to `am1-s15` so that when first-light capture promotes one
    /// of the two, the other does not silently inherit the promotion.
    pub const fn am1_t15() -> Self {
        Self {
            board_target: "am1-t15",
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM1_S15_CLASS_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1391,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// S19j Pro Xilinx target (am2): public-beta self-update, but no
    /// vendor-source first-install capsule.
    pub const fn am2_s19jpro() -> Self {
        Self {
            board_target: "am2-s19j",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::S19jHybrid,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_PUBLIC_UPDATE_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// AM3 BeagleBone S19j Pro — runtime mining proven; not public-beta install.
    pub const fn am3_bb_s19jpro() -> Self {
        Self {
            board_target: "am3-bb-s19jpro",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am3BbSerial,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::BeagleBone,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::SdOnly,
            enablement: BEAGLEBONE_SD_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Generic AM3 BeagleBone image — management only without exact carrier proof.
    pub const fn am3_bb() -> Self {
        Self {
            board_target: "am3-bb",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "generic am3-bb image lacks exact carrier proof; am3-bb-s19jpro is the executable route",
            },
            family: BoardFamily::BeagleBone,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::SdOnly,
            enablement: BEAGLEBONE_SD_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S21 — mining evidence exists; public install lab-gated (ADR-0002).
    pub const fn am3_s21() -> Self {
        Self {
            board_target: "am3-s21",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1368,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S21 Pro — runtime identity is subtype/topology discovered.
    pub const fn am3_s21pro() -> Self {
        Self {
            board_target: "am3-s21pro",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1370,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S21 XP — runtime identity is subtype/topology discovered.
    pub const fn am3_s21xp() -> Self {
        Self {
            board_target: "am3-s21xp",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1370,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic T21 — complete target uses BM1368; controller remains runtime-discovered.
    pub const fn am3_t21() -> Self {
        Self {
            board_target: "am3-t21",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1368,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S19k Pro — runtime board target is the stock-compatible `am3-s19k`.
    pub const fn am3_s19kpro() -> Self {
        Self {
            board_target: "am3-s19k",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1366,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S19 XP (BM1366 class) — metadata/runtime only; no artifact lane.
    pub const fn am3_s19xp() -> Self {
        Self {
            board_target: "am3-s19xp",
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1366,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S19j Pro — dedicated controller profile is not implemented.
    pub const fn am3_s19jpro_aml() -> Self {
        Self {
            board_target: "am3-s19jpro-aml",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "dedicated Amlogic S19j Pro controller profile is not implemented",
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// CVITEK CV1835 S19j Pro identity — evidence-only, with no artifact or runtime lane.
    pub const fn cv1835_s19jpro() -> Self {
        Self {
            board_target: "cv1835-s19jpro",
            runtime_status: RuntimeStatus::EvidenceRetainedNotImplemented {
                evidence: CV1835_RETAINED_EVIDENCE,
            },
            family: BoardFamily::Cvitek,
            chain_transport: ChainTransportKind::UartTrans,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::SingleSlot,
            enablement: CV1835_EVIDENCE_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// STM32MP15 / Braiins BCB100 S19-family carrier — capture-first, every
    /// facet denied.
    ///
    /// `BoardFamily::Stm32Mp15` has existed since the HAL scaffold landed
    /// (`board_desc.rs` `BoardFamily::Stm32Mp15`), and the toolbox ships a
    /// double-gated route for `board_target: "bcb100-s19jpro"`
    /// (`dcent-toolbox/src/dcent_toolbox/core/installer.py:1987-2012`), yet the
    /// registry had **no** `stm32mp15` row — so the projected install matrix
    /// had no `stm32mp15` line at all and the family was invisible rather than
    /// visibly refused. Registering the row does NOT enable anything: it turns
    /// a silent absence into a typed, CI-visible refusal.
    ///
    /// Every fail-closed choice below is deliberate and must not be "tidied":
    /// - `chain_transport: None` — the four `/dev/ttySTM*` names in
    ///   `dcentrald-hal/src/platform/stm32mp15.rs:29-40` are explicitly
    ///   *inferred*; declaring `Serial` would assert a carrier nobody captured.
    ///   Same reasoning as [`Self::am1_s15`].
    /// - `asic_protocol: RuntimeDiscovered` — BCB100 is a *replacement* control
    ///   board for the whole S19 family, so the hashboard silicon is a property
    ///   of the donor chassis, not of this carrier. A concrete family here would
    ///   be a guess, and `main.rs`'s serial route explicitly refuses a
    ///   `RuntimeDiscovered` descriptor before hardware construction.
    /// - `voltage_controller: RuntimeDiscovered` — `pic_address` is one of the
    ///   uncaptured datums; the S19-family `DsPic33Ep` must not be inherited on
    ///   family resemblance.
    /// - `enablement: STM32MP15_UNVERIFIED_ENABLEMENT` — `storage_topology`
    ///   stays `Unknown` because no partition map has been read.
    pub const fn bcb100_s19jpro() -> Self {
        Self {
            board_target: "bcb100-s19jpro",
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: BCB100_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Stm32Mp15,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::RuntimeDiscovered,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: STM32MP15_UNVERIFIED_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Zynq S19 Pro AM2 — experimental / identity-gated (TD-003/TD-016 class).
    pub const fn am2_s19pro() -> Self {
        Self {
            board_target: "am2-s19pro",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate:
                    "TD-003/TD-016 identity gate; native BM1398 runtime is refused before admission",
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// TD-003 scaffolding: S17 family — management-only until promotion.
    pub const fn am2_s17() -> Self {
        Self {
            board_target: "am2-s17p",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "TD-003 scaffold; S17/BM1397 promotion pending",
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_LAB_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// S17+ exact composition; management-only until PIC16/BM1396 bench admission.
    pub const fn am2_s17plus() -> Self {
        Self {
            board_target: "am2-s17plus",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "PIC16/BM1397 bench admission pending",
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// T17 exact composition; management-only until PIC16/BM1397 bench admission.
    pub const fn am2_t17() -> Self {
        Self {
            board_target: "am2-t17",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "PIC16/BM1397 bench admission pending",
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// T17+ exact composition; management-only until PIC16/BM1396 bench admission.
    pub const fn am2_t17plus() -> Self {
        Self {
            board_target: "am2-t17plus",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "PIC16/BM1397 bench admission pending",
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// TD-003 scaffolding: T19 — management-only, with no artifact producer.
    pub const fn am2_t19() -> Self {
        Self {
            board_target: "am2-t19",
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "TD-003 scaffold; no artifact producer",
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            public_beta_install: false,
            mining_default_enabled: false,
        }
    }

    /// Whether product install (signed public beta package) is appropriate.
    ///
    /// Distinct from TD-003 mining-enable gates: a target may allow lab mining
    /// evidence without being public-beta install ready.
    pub fn is_public_beta_install_target(board_target: &str) -> bool {
        Self::lookup(board_target)
            .map(|d| d.public_beta_install)
            .unwrap_or(false)
    }

    /// Bind the protocol declared by this target to independent runtime ASIC
    /// evidence and return a non-forgeable admission proof.
    pub fn admit_asic_protocol(
        &self,
        configured_or_observed: Option<AsicProtocolIdentity>,
        required: AsicProtocolIdentity,
    ) -> Result<AsicProtocolAdmission, String> {
        if self.asic_protocol != required {
            return Err(format!(
                "BoardDesc {} declares ASIC protocol {:?}, incompatible with engine requiring {:?}",
                self.board_target, self.asic_protocol, required
            ));
        }
        if configured_or_observed != Some(required) {
            return Err(format!(
                "BoardDesc {} requires exact {:?} runtime ASIC evidence, got {:?}",
                self.board_target, required, configured_or_observed
            ));
        }
        Ok(AsicProtocolAdmission { identity: required })
    }

    /// Lookup a static desc by `board_target` string (trim-sensitive exact match).
    ///
    /// Returns `None` for unknown targets — callers must fail closed or use
    /// management-only defaults (ADR-0002 scaffolding rules).
    pub fn lookup(board_target: &str) -> Option<&'static BoardDesc> {
        Self::all_registered()
            .iter()
            .find(|d| d.board_target == board_target)
    }

    /// All registered descriptors (for matrix generators / tests).
    ///
    /// Grow this static list when adding targets — not a new `*_mining.rs`.
    pub fn all_registered() -> &'static [BoardDesc] {
        static REGISTRY: &[BoardDesc] = &[
            BoardDesc::am1_s9(),
            BoardDesc::am1_s15(),
            BoardDesc::am1_t15(),
            BoardDesc::am2_s19jpro(),
            BoardDesc::am2_s19pro(),
            BoardDesc::am2_s17(),
            BoardDesc::am2_s17plus(),
            BoardDesc::am2_t17(),
            BoardDesc::am2_t17plus(),
            BoardDesc::am2_t19(),
            BoardDesc::am3_bb(),
            BoardDesc::am3_bb_s19jpro(),
            BoardDesc::am3_s21(),
            BoardDesc::am3_s21pro(),
            BoardDesc::am3_s21xp(),
            BoardDesc::am3_t21(),
            BoardDesc::am3_s19kpro(),
            BoardDesc::am3_s19xp(),
            BoardDesc::am3_s19jpro_aml(),
            BoardDesc::cv1835_s19jpro(),
            BoardDesc::bcb100_s19jpro(),
        ];
        REGISTRY
    }

    /// Whether this target is allowed to auto-route first install from a
    /// non-DCENT_OS source without lab overrides.
    pub fn product_install_allowed(&self) -> bool {
        self.public_beta_install
            && matches!(
                self.enablement.install_authorization,
                InstallAuthorization::PublicBeta | InstallAuthorization::Production
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn collect_overlay_board_targets(dir: &Path, targets: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read board overlay tree") {
            let entry = entry.expect("read board overlay entry");
            let file_type = entry.file_type().expect("read overlay entry type");
            if file_type.is_dir() {
                collect_overlay_board_targets(&entry.path(), targets);
            } else if file_type.is_file() && entry.file_name() == "board_target" {
                let target = std::fs::read_to_string(entry.path())
                    .expect("read board_target marker")
                    .trim()
                    .to_string();
                assert!(!target.is_empty(), "board_target marker must not be empty");
                targets.push(target);
            } else if file_type.is_file() && entry.file_name() == "post-build.sh" {
                let post_build =
                    std::fs::read_to_string(entry.path()).expect("read post-build identity stamps");
                for line in post_build.lines().map(str::trim) {
                    if !line.starts_with("echo \"")
                        || !line.contains("${TARGET_DIR}/etc/dcentos/board_target")
                    {
                        continue;
                    }
                    let target = line
                        .strip_prefix("echo \"")
                        .and_then(|rest| rest.split('"').next())
                        .expect("parse post-build board_target stamp");
                    assert!(
                        !target.is_empty(),
                        "post-build board target must not be empty"
                    );
                    targets.push(target.to_string());
                }
            }
        }
    }

    #[test]
    fn beta_targets_are_registered() {
        let s9 = BoardDesc::lookup("am1-s9").expect("am1-s9");
        assert!(s9.public_beta_install);
        assert!(!s9.mining_default_enabled);
        assert_eq!(s9.family, BoardFamily::Zynq);
        assert_eq!(s9.chain_transport, ChainTransportKind::FpgaUio);

        let j = BoardDesc::lookup("am2-s19j").expect("am2-s19j");
        assert!(!j.public_beta_install);
        assert!(!j.product_install_allowed());
        assert_eq!(
            j.enablement.install_authorization,
            InstallAuthorization::PublicBeta
        );
        assert!(j.enablement.allows_persistent_update());
        assert_eq!(j.chain_transport, ChainTransportKind::ZynqHybrid);
        assert_eq!(j.work_engine, WorkEngineKind::SerialWork);
        assert_eq!(j.asic_protocol, AsicProtocolIdentity::Bm1362);
        assert_eq!(j.voltage_controller, VoltageControllerClass::DsPic33Ep);
    }

    #[test]
    fn unknown_target_is_none() {
        assert!(BoardDesc::lookup("am2-not-a-real-sku").is_none());
        assert!(BoardDesc::lookup("").is_none());
    }

    /// H7 G8 required invariant: `EvidenceRetainedNotImplemented` implies a
    /// non-empty evidence list AND NOT `public_beta_install`.
    #[test]
    fn evidence_retained_not_implemented_requires_evidence_and_forbids_public_beta_install() {
        let mut seen = Vec::new();
        for desc in BoardDesc::all_registered() {
            if let RuntimeStatus::EvidenceRetainedNotImplemented { evidence } = desc.runtime_status
            {
                seen.push(desc.board_target);
                assert!(
                    !evidence.is_empty(),
                    "{}: EvidenceRetainedNotImplemented must carry retained evidence",
                    desc.board_target
                );
                for entry in evidence {
                    assert!(
                        !entry.trim().is_empty(),
                        "{}: blank evidence entry",
                        desc.board_target
                    );
                }
                assert!(
                    !desc.public_beta_install,
                    "{}: a not-implemented target must never be a public-beta install target",
                    desc.board_target
                );
                assert!(
                    !desc.product_install_allowed(),
                    "{}: a not-implemented target must never allow product install",
                    desc.board_target
                );
            }
        }
        assert_eq!(
            seen,
            vec!["cv1835-s19jpro"],
            "exactly cv1835-s19jpro is EvidenceRetainedNotImplemented today; \
             grow this pin deliberately when classifying another target"
        );
    }

    /// The two unconditional constructor refusals are DIFFERENT states and
    /// must never be flattened: Amlogic ROUTES ELSEWHERE (native serial lane,
    /// `amlogic/mod.rs` `AmlogicPlatform::new` refusal), CVitek is genuinely
    /// not implemented with retained evidence (`cvitek.rs` `CViTekPlatform::new`).
    #[test]
    fn cvitek_and_amlogic_refusals_are_distinct_status_classes() {
        let cv = BoardDesc::lookup("cv1835-s19jpro").expect("cv1835-s19jpro");
        assert!(matches!(
            cv.runtime_status,
            RuntimeStatus::EvidenceRetainedNotImplemented { .. }
        ));
        assert!(!cv.runtime_status.permits_mining_lane());

        let s21 = BoardDesc::lookup("am3-s21").expect("am3-s21");
        assert_eq!(
            s21.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            }
        );
        assert!(s21.runtime_status.permits_mining_lane());

        assert_ne!(cv.runtime_status, s21.runtime_status);
    }

    /// Every registered status must be structurally well-formed (fail closed
    /// on absent evidence) and must agree with the row's own work engine:
    /// a status that names a mining lane must not sit on a management-only
    /// row, and vice versa.
    #[test]
    fn every_registered_runtime_status_is_well_formed_and_agrees_with_work_engine() {
        for desc in BoardDesc::all_registered() {
            assert!(
                desc.runtime_status.is_well_formed(),
                "{}: runtime_status {:?} is not well-formed",
                desc.board_target,
                desc.runtime_status
            );
            let names_mining_lane = desc.runtime_status.permits_mining_lane();
            let management_only = matches!(desc.work_engine, WorkEngineKind::ManagementOnly);
            assert_eq!(
                names_mining_lane, !management_only,
                "{}: runtime_status {:?} disagrees with work_engine {:?}",
                desc.board_target, desc.runtime_status, desc.work_engine
            );
        }
    }

    /// The Amlogic generic-construction refusal (`AmlogicPlatform::new`) is
    /// family-wide, so every Amlogic row that names the native serial lane
    /// must declare `GenericConstruction::Refused` — never `ManagementOnly`.
    #[test]
    fn amlogic_lifecycle_rows_declare_refused_generic_construction() {
        let mut lane_rows = 0;
        for desc in BoardDesc::all_registered()
            .iter()
            .filter(|d| d.family == BoardFamily::Amlogic)
        {
            match desc.runtime_status {
                RuntimeStatus::SpecialisedLifecycle {
                    lane,
                    generic_construction,
                } => {
                    lane_rows += 1;
                    assert_eq!(
                        lane,
                        LifecycleLane::AmlogicNativeSerial,
                        "{}",
                        desc.board_target
                    );
                    assert_eq!(
                        generic_construction,
                        GenericConstruction::Refused,
                        "{}: Amlogic generic Platform construction is refused by design",
                        desc.board_target
                    );
                }
                RuntimeStatus::ManagementOnlyByPolicy { .. } => {}
                other => panic!(
                    "{}: unexpected Amlogic runtime_status {other:?}",
                    desc.board_target
                ),
            }
        }
        assert_eq!(
            lane_rows, 6,
            "six Amlogic rows route via the native serial lane"
        );
    }

    /// The retained CV1835 evidence must be real files, not decorative
    /// strings — fail closed on absent evidence (CONTEXT §1.4).
    #[test]
    fn cv1835_retained_evidence_paths_exist_on_disk() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let RuntimeStatus::EvidenceRetainedNotImplemented { evidence } =
            BoardDesc::cv1835_s19jpro().runtime_status
        else {
            panic!("cv1835-s19jpro must be EvidenceRetainedNotImplemented");
        };
        for rel in evidence {
            assert!(
                workspace_root.join(rel).is_file(),
                "retained CV1835 evidence path missing on disk: {rel}"
            );
        }
    }

    #[test]
    fn every_shipped_board_target_stamp_has_an_exact_descriptor() {
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let mut targets = Vec::new();
        collect_overlay_board_targets(
            &project_root.join("br2_external_dcentos/board"),
            &mut targets,
        );
        targets.sort();
        targets.dedup();
        assert!(!targets.is_empty(), "expected shipped board_target markers");
        for target in targets {
            assert!(
                BoardDesc::lookup(&target).is_some(),
                "shipped overlay board_target {target:?} is absent from BoardDesc"
            );
        }
    }

    #[test]
    fn s19k_overlay_post_build_and_descriptor_share_runtime_identity() {
        let descriptor = BoardDesc::lookup("am3-s19k").expect("registered S19k runtime target");
        assert_eq!(descriptor, &BoardDesc::am3_s19kpro());
        assert!(
            BoardDesc::lookup("am3-s19kpro").is_none(),
            "build-lane name must not masquerade as the runtime board target"
        );

        let post_build =
            include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh");
        let stamps: Vec<_> = post_build
            .lines()
            .filter(|line| line.contains("${TARGET_DIR}/etc/dcentos/board_target"))
            .collect();
        assert_eq!(
            stamps.len(),
            1,
            "S19k post-build must stamp one unambiguous runtime board target"
        );
        assert!(
            stamps[0].contains(r#"echo "am3-s19k""#),
            "S19k post-build target drifted from BoardDesc: {}",
            stamps[0]
        );
    }

    #[test]
    fn generic_bb_post_build_has_a_management_only_descriptor() {
        let descriptor = BoardDesc::lookup("am3-bb").expect("registered generic BB target");
        assert_eq!(descriptor.family, BoardFamily::BeagleBone);
        assert_eq!(descriptor.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(descriptor.asic_protocol, AsicProtocolIdentity::Bm1362);

        let post_build =
            include_str!("../../../br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh");
        let stamps: Vec<_> = post_build
            .lines()
            .filter(|line| line.contains("${TARGET_DIR}/etc/dcentos/board_target"))
            .collect();
        assert_eq!(stamps.len(), 1, "generic BB must stamp one board target");
        assert!(
            stamps[0].contains(r#"echo "am3-bb""#),
            "generic BB post-build target drifted from BoardDesc: {}",
            stamps[0]
        );
    }

    #[test]
    fn shipped_serial_configs_match_descriptor_asic_identity() {
        let shipped_configs = [
            (
                "am2-s19j",
                include_str!("../../configs/dcentrald_s19jpro_am2_baked_default.toml"),
            ),
            (
                "am2-s19pro",
                include_str!("../../configs/dcentrald_s19pro_am2_baked_default.toml"),
            ),
            (
                "am2-s17p",
                include_str!("../../configs/dcentrald_s17pro_am2_baked_default.toml"),
            ),
            (
                "am3-bb",
                include_str!("../../../br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-bb-s19jpro",
                include_str!("../../../br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s21",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s21pro",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s21xp",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-t21",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-t21/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s19k",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s19jpro-aml",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentrald.toml"),
            ),
        ];

        for (board_target, config) in shipped_configs {
            let descriptor =
                BoardDesc::lookup(board_target).expect("shipped config target is registered");
            let configured_protocols: Vec<_> = config
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.starts_with('#') {
                        return None;
                    }
                    let (key, value) = line.split_once('=')?;
                    if !matches!(key.trim(), "chip" | "serial_chip_type") {
                        return None;
                    }
                    let label = value.trim().trim_matches('"');
                    Some(
                        AsicProtocolIdentity::from_chip_label(label).unwrap_or_else(|| {
                            panic!("{board_target} shipped config has unknown ASIC label {label}")
                        }),
                    )
                })
                .collect();
            assert!(
                !configured_protocols.is_empty(),
                "{board_target} shipped config has no exact ASIC identity"
            );
            assert!(
                configured_protocols
                    .iter()
                    .all(|configured| *configured == descriptor.asic_protocol),
                "{board_target} shipped config ASIC identity {:?} disagrees with descriptor {:?}",
                configured_protocols,
                descriptor.asic_protocol
            );
        }

        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        assert!(
            acceptance_skus
                .lines()
                .any(|line| line.starts_with("T21|am3-t21|aarch64|BM1368|0x1368|")),
            "T21 acceptance inventory must share the descriptor ASIC identity"
        );
    }

    #[test]
    fn acceptance_inventory_matches_registered_asic_protocols() {
        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let mut validated_rows = 0;
        for line in acceptance_skus.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 11, "malformed acceptance row: {line}");
            let runtime_target = match fields[1] {
                "am2-s19jpro-zynq" | "am2-s19jpro" => "am2-s19j",
                "am2-s19" => "am2-s19pro",
                target => target,
            };
            let descriptor = match BoardDesc::lookup(runtime_target) {
                Some(descriptor) => descriptor,
                None if fields[8] == "NOT-IMPLEMENTED" => continue,
                None => panic!(
                    "{} is {} but has no registered BoardDesc for {}",
                    fields[0], fields[8], runtime_target
                ),
            };

            let configured_protocol = AsicProtocolIdentity::from_chip_label(fields[3])
                .unwrap_or_else(|| panic!("{} has unknown ASIC label {}", fields[0], fields[3]));
            let chip_id_text = fields[4]
                .strip_prefix("0x")
                .unwrap_or_else(|| panic!("{} has no exact ChipID", fields[0]));
            let chip_id = u16::from_str_radix(chip_id_text, 16)
                .unwrap_or_else(|_| panic!("{} has malformed ChipID {}", fields[0], fields[4]));
            assert_eq!(
                AsicProtocolIdentity::from_chip_id(chip_id),
                Some(configured_protocol),
                "{} acceptance ASIC label/ChipID mismatch",
                fields[0]
            );
            // The S17Plus/T17Plus exception that briefly lived here is GONE: the
            // descriptors were promoted to Bm1397 by operator decision 2026-08-03,
            // so every row agrees again and no carve-out is needed. Do not
            // reintroduce one — if this assert fires, a layer has drifted.
            assert_eq!(
                descriptor.asic_protocol, configured_protocol,
                "{} acceptance ASIC identity disagrees with BoardDesc {}",
                fields[0], runtime_target
            );
            validated_rows += 1;
        }
        assert_eq!(
            validated_rows, 19,
            "registered acceptance coverage changed; classify new aliases explicitly"
        );
    }

    #[test]
    fn every_claimed_artifact_has_a_primary_build_driver_lane() {
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let build_driver =
            include_str!("../../../scripts/build_in_docker.sh").replace("\r\n", "\n");
        let package_validation_marker = build_driver
            .find("echo \"Package-only validation:\"")
            .expect("package-only validation marker");
        let package_validation_case_start = build_driver[..package_validation_marker]
            .rfind("case ")
            .expect("package-only validation case");
        let package_validation_case =
            &build_driver[package_validation_case_start..package_validation_marker];
        let non_s9_inventory = include_str!("../../../scripts/rebuild_all_non_s9.sh");
        for producer in crate::artifact_producer::PRIMARY_ARTIFACT_PRODUCERS {
            let runtime_target = producer.board_target;
            let build_target = producer.build_target;
            let defconfig = producer.defconfig;
            let overlay = producer.overlay;
            let package_validated = producer.package_validated;
            let tarball = producer.artifact_filename;
            let arm = format!("\n    {build_target})");
            let arm_start = build_driver.find(&arm).unwrap_or_else(|| {
                panic!(
                    "{runtime_target} claims an artifact but build target {build_target} is absent"
                )
            });
            let arm_body = &build_driver[arm_start + arm.len()..];
            let arm_end = arm_body
                .find("\n        ;;")
                .unwrap_or_else(|| panic!("unterminated build target arm {build_target}"));
            let arm_body = &arm_body[..arm_end];
            assert!(
                arm_body.contains(&format!(r#"BR_DEFCONFIG="{defconfig}""#)),
                "{build_target} does not select {defconfig}"
            );
            assert!(
                arm_body.contains(&format!(r#"BOARD_PKG_NAME="{runtime_target}""#)),
                "{build_target} does not package canonical runtime target {runtime_target}"
            );
            assert!(
                project_root
                    .join("br2_external_dcentos/configs")
                    .join(defconfig)
                    .is_file(),
                "{build_target} references missing defconfig {defconfig}"
            );
            let version_overlay =
                format!("/build/dcentos/br2_external_dcentos/{overlay}/rootfs-overlay");
            assert!(
                build_driver.matches(&version_overlay).count() >= 2,
                "{build_target} must synchronize and then verify {overlay}/rootfs-overlay"
            );
            if package_validated {
                assert!(
                    package_validation_case.contains(&format!("|{build_target}|"))
                        || package_validation_case.contains(&format!("|{build_target})"))
                        || package_validation_case.contains(&format!("    {build_target}|"))
                        || package_validation_case.contains(&format!("    {build_target})")),
                    "{build_target} artifact bypasses package-only validation"
                );
            }
            if build_target != "s9" {
                assert!(
                    non_s9_inventory.contains(&format!("\n    {build_target}\n")),
                    "{build_target} is absent from the fail-closed non-S9 inventory"
                );
                assert!(
                    non_s9_inventory.contains(&format!(r#"[{build_target}]="{tarball}""#)),
                    "{build_target} inventory mapping does not name {tarball}"
                );
            }
        }
    }

    #[test]
    fn beta_targets_prefer_ab_fw_setenv() {
        assert_eq!(BoardDesc::am1_s9().slot_policy, SlotPolicy::ZynqAbFwSetenv);
        assert_eq!(
            BoardDesc::am2_s19jpro().slot_policy,
            SlotPolicy::ZynqAbFwSetenv
        );
    }

    #[test]
    fn only_beta_flags_match_public_beta_gate_story() {
        let beta: Vec<_> = BoardDesc::all_registered()
            .iter()
            .filter(|d| d.public_beta_install)
            .map(|d| d.board_target)
            .collect();
        assert_eq!(beta, vec!["am1-s9"]);
    }

    #[test]
    fn bb_is_sd_only_not_public_beta() {
        for id in ["am3-bb", "am3-bb-s19jpro"] {
            let bb = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert!(!bb.public_beta_install);
            assert_eq!(bb.slot_policy, SlotPolicy::SdOnly);
            assert_eq!(bb.family, BoardFamily::BeagleBone);
        }
    }

    #[test]
    fn amlogic_targets_are_runtime_discovered_serial_lab_gated() {
        for id in [
            "am3-s21",
            "am3-s21pro",
            "am3-s21xp",
            "am3-t21",
            "am3-s19k",
            "am3-s19xp",
            "am3-s19jpro-aml",
        ] {
            let d = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(d.family, BoardFamily::Amlogic, "{id}");
            assert_eq!(d.chain_transport, ChainTransportKind::Serial, "{id}");
            assert_eq!(
                d.voltage_controller,
                VoltageControllerClass::RuntimeDiscovered,
                "{id}"
            );
            assert_eq!(d.slot_policy, SlotPolicy::LabGated, "{id}");
            assert!(!d.product_install_allowed(), "{id}");
        }
    }

    #[test]
    fn unimplemented_runtime_targets_are_management_only() {
        for id in [
            "am2-s17plus",
            "am2-t17",
            "am2-t17plus",
            "am3-bb",
            "am3-s19jpro-aml",
            "cv1835-s19jpro",
            "bcb100-s19jpro",
        ] {
            let descriptor = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(
                descriptor.work_engine,
                WorkEngineKind::ManagementOnly,
                "{id} must be rejected before a hardware-owning runtime is constructed"
            );
        }
    }

    /// Mirror of `install_matrix::tests::cv1835_has_no_artifact_or_install_lane`
    /// for the STM32MP15 / BCB100 family (queue rank 12, H6 G-4).
    ///
    /// It asserts against the *projected* install-matrix row rather than the
    /// descriptor, exactly like its CVitek sibling, because the projection is
    /// what docs, CI, and the Toolbox actually consume. Before this row
    /// existed, `install_matrix()` had no `stm32mp15` line at all, so the
    /// family was silently absent instead of visibly refused.
    #[test]
    fn stm32mp15_has_no_artifact_or_install_lane() {
        let row = crate::install_matrix()
            .into_iter()
            .find(|row| row.board_target == "bcb100-s19jpro")
            .expect("STM32MP15 / BCB100 row");
        assert_eq!(row.family, BoardFamily::Stm32Mp15);
        // Unknown, NOT borrowed from a sibling family: no partition map read.
        assert_eq!(row.enablement.storage_topology, StorageTopology::Unknown);
        assert_eq!(row.enablement.update_mechanism, UpdateMechanism::None);
        assert_eq!(
            row.enablement.update_maturity,
            ImplementationMaturity::NotImplemented
        );
        assert_eq!(
            row.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(
            row.enablement.recovery_maturity,
            RecoveryMaturity::NotImplemented
        );
        assert_eq!(row.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(
            row.enablement.artifact_maturity,
            ArtifactMaturity::NotImplemented
        );
        assert!(!row.public_beta_install);
        assert!(!row.persistent_update_allowed);
        assert!(!row.product_install_allowed);
        assert!(!row.ab_sysupgrade);
        assert!(!row.mining_default_enabled);
    }

    /// The all-`Denied` row must genuinely deny, not merely be labelled denied.
    ///
    /// Registering a descriptor is the *only* way a runtime dispatch can get
    /// past `main.rs`'s "no BoardDesc is registered" refusal, so this pins the
    /// three independent facets that keep the next gate closed:
    /// `ManagementOnly` (hard refusal in `runtime_dispatch_admission`),
    /// `RuntimeDiscovered` ASIC protocol (the serial route refuses it, and
    /// `admit_asic_protocol` can never mint a proof for it), and a `None`
    /// transport (no concrete carrier is asserted). Relaxing any one of these
    /// on evidence other than a bench capture re-opens a lane.
    #[test]
    fn bcb100_all_denied_row_cannot_admit_any_mining_lane() {
        let d = BoardDesc::lookup("bcb100-s19jpro").expect("bcb100-s19jpro");
        assert_eq!(d.family, BoardFamily::Stm32Mp15);
        assert_eq!(d.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(d.chain_transport, ChainTransportKind::None);
        assert_eq!(d.asic_protocol, AsicProtocolIdentity::RuntimeDiscovered);
        assert_eq!(
            d.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(d.slot_policy, SlotPolicy::LabGated);
        assert!(!d.enablement.allows_persistent_update());
        assert!(!d.enablement.allows_restore());
        assert!(!d.product_install_allowed());
        assert!(!BoardDesc::is_public_beta_install_target("bcb100-s19jpro"));
        assert!(!d.runtime_status.permits_mining_lane());
        assert!(d.runtime_status.is_well_formed());
        assert!(matches!(
            d.runtime_status,
            RuntimeStatus::CaptureFirst { .. }
        ));

        // No concrete ASIC family can ever be admitted from this row: the
        // declared protocol is RuntimeDiscovered, so the declared/required
        // comparison fails before the runtime-evidence comparison is reached.
        for required in [
            AsicProtocolIdentity::Bm1362,
            AsicProtocolIdentity::Bm1366,
            AsicProtocolIdentity::Bm1368,
            AsicProtocolIdentity::Bm1370,
            AsicProtocolIdentity::Bm1398,
        ] {
            assert!(
                d.admit_asic_protocol(Some(required), required).is_err(),
                "bcb100-s19jpro must not admit {required:?}"
            );
        }
    }

    #[test]
    fn cvitek_is_single_slot_and_requires_runtime_controller_discovery() {
        let d = BoardDesc::lookup("cv1835-s19jpro").expect("cv");
        assert_eq!(d.family, BoardFamily::Cvitek);
        assert_eq!(d.slot_policy, SlotPolicy::SingleSlot);
        assert_eq!(d.enablement.storage_topology, StorageTopology::SingleSlot);
        assert_eq!(
            d.enablement.update_mechanism,
            UpdateMechanism::EmmcContentSelectorEvidenceOnly
        );
        assert_eq!(
            d.enablement.update_maturity,
            ImplementationMaturity::NotImplemented
        );
        assert_eq!(
            d.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(d.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(
            d.enablement.artifact_maturity,
            ArtifactMaturity::NotImplemented
        );
        assert_eq!(
            d.enablement.recovery_maturity,
            RecoveryMaturity::NotImplemented
        );
        assert!(!d.enablement.allows_persistent_update());
        assert!(!d.enablement.allows_restore());
        assert_eq!(
            d.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(d.chain_transport, ChainTransportKind::UartTrans);
        assert_eq!(d.work_engine, WorkEngineKind::ManagementOnly);
    }

    #[test]
    fn registry_has_no_duplicate_targets() {
        let ids: Vec<_> = BoardDesc::all_registered()
            .iter()
            .map(|d| d.board_target)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            ids.len(),
            sorted.len(),
            "duplicate board_target in registry"
        );
    }

    #[test]
    fn asic_protocol_chip_id_roundtrip_for_known_families() {
        for id in [
            0x1387u16, 0x1396, 0x1397, 0x1398, 0x1362, 0x1366, 0x1368, 0x1370,
        ] {
            let identity = AsicProtocolIdentity::from_chip_id(id).expect("known id");
            assert_eq!(identity.to_chip_id(), Some(id));
        }
        assert_eq!(AsicProtocolIdentity::RuntimeDiscovered.to_chip_id(), None);
        // Public-beta board rows expose a profile-usable ChipID.
        assert_eq!(BoardDesc::am1_s9().asic_protocol.to_chip_id(), Some(0x1387));
        assert_eq!(
            BoardDesc::am2_s19jpro().asic_protocol.to_chip_id(),
            Some(0x1362)
        );
    }

    #[test]
    fn registry_artifact_contracts_are_consistent() {
        for board in BoardDesc::all_registered() {
            assert!(
                board.enablement.artifact_contract_is_consistent(),
                "{} has contradictory artifact kind/maturity",
                board.board_target
            );
        }
    }

    #[test]
    fn protocol_admission_requires_declared_and_runtime_identity_to_match() {
        let s19j = BoardDesc::am2_s19jpro();
        let proof = s19j
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1362),
                AsicProtocolIdentity::Bm1362,
            )
            .expect("exact BM1362 composition should admit");
        assert_eq!(proof.identity(), AsicProtocolIdentity::Bm1362);
        assert!(s19j
            .admit_asic_protocol(None, AsicProtocolIdentity::Bm1362)
            .is_err());

        let s19pro = BoardDesc::am2_s19pro();
        assert_eq!(s19pro.asic_protocol, AsicProtocolIdentity::Bm1398);
        assert_eq!(s19pro.work_engine, WorkEngineKind::ManagementOnly);
        assert!(s19pro
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1398),
                AsicProtocolIdentity::Bm1362,
            )
            .is_err());
    }

    #[test]
    fn protocol_identity_parsers_refuse_unknown_or_ambiguous_labels() {
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(0x1398),
            Some(AsicProtocolIdentity::Bm1398)
        );
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(0x1396),
            Some(AsicProtocolIdentity::Bm1396)
        );
        assert_eq!(
            AsicProtocolIdentity::from_chip_label("BM1396"),
            Some(AsicProtocolIdentity::Bm1396)
        );
        assert_eq!(
            AsicProtocolIdentity::from_chip_label(" bm1362 "),
            Some(AsicProtocolIdentity::Bm1362)
        );
        assert_eq!(AsicProtocolIdentity::from_chip_id(0x1390), None);
        assert_eq!(AsicProtocolIdentity::from_chip_label("BM13XX"), None);
    }
}
