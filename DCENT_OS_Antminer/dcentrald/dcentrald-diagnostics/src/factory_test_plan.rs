//! Exact-artifact AMTC factory-plan import (offline and non-authorizing).
//!
//! The held AMTC `Config.ini` files are useful board/topology/process evidence, but
//! they were written for hardware-mutating vendor jig executables. This module
//! admits only nine byte-exact configuration artifacts, converts their passive
//! evidence into typed data, and quarantines every raw vendor leaf. It cannot open
//! a device, dispatch a pattern, command a rail, or mint a factory/repair verdict.
//!
//! This is deliberately separate from the diagnostic executor and `TestType`.
//! Enabling the default-off `factory-test-plan` feature only compiles this pure
//! importer (and the pure `pattern-selftest` data model it references).
//!
//! # Evidence boundary
//!
//! Profile hashes, identities, and pattern manifests come from
//!
//! AMTC_FACTORY_PLAN_EVIDENCE.md` and the exact held T9+ artifact at
//! +`. The importer
//! checks raw bytes before parsing; filenames and caller-provided model labels
//! have no admission value. Sensor arrays are retained as *logical fixture
//! indices*, never inferred I2C addresses. Missing `Has_Pic` remains unknown.

use std::collections::BTreeMap;
use std::str;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::pattern_test::{family_test_standard, FamilyTestStandard, PatternFormat};

/// Version of the pure plan IR. This is not an executable fixture protocol.
pub const FACTORY_TEST_PLAN_SCHEMA: &str = "dcent-amtc-factory-plan-v1";

/// Hard bound applied before hashing or parsing any candidate.
pub const MAX_FACTORY_CONFIG_BYTES: usize = 16 * 1024;
/// Maximum parsed raw leaves retained in quarantine.
pub const MAX_QUARANTINED_LEAVES: usize = 256;
/// Maximum legacy-INI logical lines.
pub const MAX_LEGACY_INI_LINES: usize = 256;
/// Maximum legacy-INI line length.
pub const MAX_LEGACY_INI_LINE_BYTES: usize = 512;

/// The nine byte-exact AMTC profiles represented by held evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FactoryPlanProfileId {
    S19ProPt1,
    S19jProPt1New,
    S19kProNormal,
    S19kProRepair,
    S21Default,
    S21Pt1,
    S21Sweep,
    S9Legacy,
    T9PlusLegacy,
}

impl FactoryPlanProfileId {
    /// Stable machine-readable profile identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S19ProPt1 => "amtc-s19pro-nbp1901-38-pt1",
            Self::S19jProPt1New => "amtc-s19jpro-bhb42601-pt1new",
            Self::S19kProNormal => "amtc-s19kpro-bhb56902-normal",
            Self::S19kProRepair => "amtc-s19kpro-bhb56901-repair",
            Self::S21Default => "amtc-s21-bhb68603-default",
            Self::S21Pt1 => "amtc-s21-bhb68603-pt1",
            Self::S21Sweep => "amtc-s21-bhb68603-sweep",
            Self::S9Legacy => "amtc-s9-bm1387-legacy",
            Self::T9PlusLegacy => "amtc-t9plus-bm1387-legacy",
        }
    }
}

/// Original config dialect, selected only after exact-hash admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactoryConfigDialect {
    Json,
    LegacyIni,
}

/// A value stated explicitly by the admitted config, or absent from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatedValue<T> {
    Stated(T),
    Unknown,
}

/// Immutable artifact provenance carried by every imported plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryArtifactEvidence {
    pub config_sha256: &'static str,
    pub config_bytes: usize,
    pub associated_jig_binary_sha256: StatedValue<&'static str>,
    pub dialect: FactoryConfigDialect,
}

/// Exact identity transcribed from the admitted config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryHardwareIdentity {
    pub miner_type: String,
    pub board_name: StatedValue<String>,
    /// Canonical DCENT family spelling (`BMxxxx`).
    pub asic_family: String,
    /// Original vendor value (`BMxxxx`, or legacy-INI numeric `1387`).
    pub raw_asic_type: String,
}

/// Voltage-domain factorization proof. The admitted legacy configs lack it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoltageDomainTopology {
    /// `domains * asics_per_domain == asic_count`, checked without overflow.
    Checked {
        domains: u16,
        asics_per_domain: u16,
    },
    UnavailableInArtifact,
}

/// Passive topology evidence. It is not live enumeration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryTopologyEvidence {
    pub asic_count: u16,
    pub cores_per_asic: StatedValue<u16>,
    pub voltage_domains: VoltageDomainTopology,
}

/// Logical origin of a vendor sensor array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorySensorSource {
    Pic,
    Asic,
    ControlBoard,
    LegacyFixture,
}

/// Passive sensor evidence. `logical_fixture_indices` must never be used as bus
/// addresses without separate, board-specific reverse-engineering evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactorySensorEvidence {
    pub source: FactorySensorSource,
    pub model: String,
    pub read_requested: StatedValue<bool>,
    pub logical_fixture_indices: Vec<u16>,
}

/// Process labels and mode booleans stated by the vendor config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryProcessEvidence {
    pub vendor_process: String,
    pub factory_mode: StatedValue<bool>,
    pub repair_enabled: StatedValue<bool>,
}

/// Raw vendor grading fields. `invalid_core_number` is deliberately not called a
/// tolerance and cannot mint a chip/board verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFactoryGradingEvidence {
    pub pattern_number: StatedValue<u16>,
    pub least_nonce_per_core: StatedValue<u16>,
    pub invalid_core_number: StatedValue<u16>,
    pub most_hw_num: StatedValue<u16>,
    pub legacy_data_count: StatedValue<u32>,
}

/// Grading evidence links modeled families to the single canonical table in
/// [`crate::pattern_test::FAMILY_TEST_STANDARDS`]. `None` means no modeled
/// standard exists; raw fields remain evidence only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryGradingEvidence {
    pub standard: Option<&'static FamilyTestStandard>,
    pub raw: RawFactoryGradingEvidence,
}

/// Confidence about pattern row ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternRowOrderEvidence {
    DecompileProvenAsicCorePattern,
    NotProven,
}

/// Exact pattern resource requirement. These limits are manifests, not formulas
/// inferred from arbitrary board counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactPatternArtifact {
    pub sha256: &'static str,
    pub bytes: usize,
    pub record_count: usize,
    pub format: PatternFormat,
    pub row_order: PatternRowOrderEvidence,
    /// Exact held-file factorization; BM1366's 126 pool factor is intentionally
    /// distinct from its 77-ASIC board topology.
    pub artifact_factorization: (u16, u16, u8),
}

/// Whether a profile has an admitted factory pattern artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternArtifactEvidence {
    Exact(ExactPatternArtifact),
    NoFormatAdmitted,
}

/// An authority field whose only representable state is denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeniedAuthority {
    Denied,
}

impl DeniedAuthority {
    pub const fn is_authorized(self) -> bool {
        false
    }
}

/// Compile-time-shaped authority ceiling. No field can represent `true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FactoryPlanAuthority {
    pub device_io: DeniedAuthority,
    pub pattern_dispatch: DeniedAuthority,
    pub voltage_control: DeniedAuthority,
    pub frequency_control: DeniedAuthority,
    pub fan_control: DeniedAuthority,
    pub eeprom_mutation: DeniedAuthority,
    pub repair_action: DeniedAuthority,
    pub manufacturing_action: DeniedAuthority,
    pub grading_verdict: DeniedAuthority,
}

impl FactoryPlanAuthority {
    const fn denied() -> Self {
        Self {
            device_io: DeniedAuthority::Denied,
            pattern_dispatch: DeniedAuthority::Denied,
            voltage_control: DeniedAuthority::Denied,
            frequency_control: DeniedAuthority::Denied,
            fan_control: DeniedAuthority::Denied,
            eeprom_mutation: DeniedAuthority::Denied,
            repair_action: DeniedAuthority::Denied,
            manufacturing_action: DeniedAuthority::Denied,
            grading_verdict: DeniedAuthority::Denied,
        }
    }
}

/// Every plan carries this unforgeable-by-data offline scope marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfflineOnlyNonAuthorizing {
    authority: FactoryPlanAuthority,
}

impl OfflineOnlyNonAuthorizing {
    const fn new() -> Self {
        Self {
            authority: FactoryPlanAuthority::denied(),
        }
    }

    pub const fn authority(self) -> FactoryPlanAuthority {
        self.authority
    }
}

/// Read-only flattened vendor leaves. Active-looking settings remain available
/// for research without gaining a typed command/executor interface.
#[derive(Clone, Debug, PartialEq)]
pub struct QuarantinedJigIntent {
    raw_leaves: BTreeMap<String, Value>,
}

impl QuarantinedJigIntent {
    /// Inspect one raw vendor leaf by canonical path.
    pub fn raw_value(&self, path: &str) -> Option<&Value> {
        self.raw_leaves.get(path)
    }

    pub fn len(&self) -> usize {
        self.raw_leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw_leaves.is_empty()
    }

    /// Read-only iteration for reverse-engineering/reporting.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.raw_leaves
            .iter()
            .map(|(path, value)| (path.as_str(), value))
    }
}

/// Pure, passive IR produced from one exact held artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct FactoryTestPlan {
    schema: &'static str,
    profile_id: FactoryPlanProfileId,
    artifact: FactoryArtifactEvidence,
    identity: FactoryHardwareIdentity,
    topology: FactoryTopologyEvidence,
    process: FactoryProcessEvidence,
    sensors: Vec<FactorySensorEvidence>,
    has_pic: StatedValue<bool>,
    grading: FactoryGradingEvidence,
    pattern_artifact: PatternArtifactEvidence,
    authority: OfflineOnlyNonAuthorizing,
    quarantined_intent: QuarantinedJigIntent,
}

impl FactoryTestPlan {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    pub const fn profile_id(&self) -> FactoryPlanProfileId {
        self.profile_id
    }

    pub const fn artifact(&self) -> &FactoryArtifactEvidence {
        &self.artifact
    }

    pub const fn identity(&self) -> &FactoryHardwareIdentity {
        &self.identity
    }

    pub const fn topology(&self) -> &FactoryTopologyEvidence {
        &self.topology
    }

    pub const fn process(&self) -> &FactoryProcessEvidence {
        &self.process
    }

    pub fn sensors(&self) -> &[FactorySensorEvidence] {
        &self.sensors
    }

    pub const fn has_pic(&self) -> &StatedValue<bool> {
        &self.has_pic
    }

    pub const fn grading(&self) -> &FactoryGradingEvidence {
        &self.grading
    }

    pub const fn pattern_artifact(&self) -> &PatternArtifactEvidence {
        &self.pattern_artifact
    }

    pub const fn authority(&self) -> OfflineOnlyNonAuthorizing {
        self.authority
    }

    pub const fn quarantined_intent(&self) -> &QuarantinedJigIntent {
        &self.quarantined_intent
    }
}

/// Fail-closed import errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FactoryPlanError {
    #[error("factory config is empty")]
    Empty,
    #[error("factory config is {bytes} bytes; maximum is {maximum}")]
    TooLarge { bytes: usize, maximum: usize },
    #[error("factory config SHA-256 is not in the exact admission table: {sha256}")]
    UnknownArtifact { sha256: String },
    #[error("admitted {profile} artifact has length {actual}, expected {expected}")]
    AdmittedLengthMismatch {
        profile: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("admitted {profile} artifact is malformed at {field}")]
    MalformedAdmittedArtifact {
        profile: &'static str,
        field: &'static str,
    },
    #[error("admitted {profile} field {field} is {actual}, expected {expected}")]
    ContractMismatch {
        profile: &'static str,
        field: &'static str,
        actual: String,
        expected: String,
    },
    #[error("admitted {profile} topology multiplication overflowed")]
    TopologyOverflow { profile: &'static str },
    #[error("admitted {profile} topology is {domains} x {per_domain}, not {asic_count} ASICs")]
    TopologyMismatch {
        profile: &'static str,
        domains: u16,
        per_domain: u16,
        asic_count: u16,
    },
    #[error("admitted {profile} has more than {maximum} quarantined raw leaves")]
    TooManyRawLeaves {
        profile: &'static str,
        maximum: usize,
    },
    #[error("admitted {profile} legacy INI exceeds a parser resource limit")]
    LegacyIniLimit { profile: &'static str },
}

#[derive(Clone, Copy)]
struct ProfileSpec {
    id: FactoryPlanProfileId,
    config_sha256: &'static str,
    config_bytes: usize,
    binary_sha256: Option<&'static str>,
    dialect: FactoryConfigDialect,
    miner_type: &'static str,
    board_name: Option<&'static str>,
    raw_asic_type: &'static str,
    asic_family: &'static str,
    asic_count: u16,
    voltage_domains: Option<(u16, u16)>,
    cores_per_asic: Option<u16>,
}

const PROFILES: &[ProfileSpec] = &[
    ProfileSpec {
        id: FactoryPlanProfileId::S19ProPt1,
        config_sha256: "5b601ea95578ab1e951d31eb442c2aae96d863c3855b7b0e72638ca9d2cf0dfe",
        config_bytes: 2_290,
        binary_sha256: Some("ddb73ebe334908767360a1b9a15144daa751d45c7f22a4965788371957ff6317"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S19_Pro",
        board_name: Some("NBP1901-38"),
        raw_asic_type: "BM1398",
        asic_family: "BM1398",
        asic_count: 114,
        voltage_domains: Some((38, 3)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S19jProPt1New,
        config_sha256: "3ea4d11ec9aeda71785825bc7fc9e80699e3101048c75b66dbe15b4655f9fa5b",
        config_bytes: 2_228,
        binary_sha256: Some("1bdf1e64d5218772d508f3d3003a07df107684dd31df8a8143e9fc03a4b82b95"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S19j_Pro",
        board_name: Some("BHB42601"),
        raw_asic_type: "BM1362",
        asic_family: "BM1362",
        asic_count: 126,
        voltage_domains: Some((42, 3)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S19kProNormal,
        config_sha256: "873443e20dba75d5eec41414f23cc5a479015c46576e746c5bec851e41be3ee4",
        config_bytes: 4_326,
        binary_sha256: Some("cd1b4c047d40d6de9e040dbda537a4944ff8290b278d22bc885ea9cae020c4eb"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S19k Pro",
        board_name: Some("BHB56902"),
        raw_asic_type: "BM1366",
        asic_family: "BM1366",
        asic_count: 77,
        voltage_domains: Some((11, 7)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S19kProRepair,
        config_sha256: "0aa1dfac98faef16c840c0532c67e7f79b4055d677a1b835ab8a8099dbce0517",
        config_bytes: 4_040,
        binary_sha256: Some("cd1b4c047d40d6de9e040dbda537a4944ff8290b278d22bc885ea9cae020c4eb"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S19k Pro",
        board_name: Some("BHB56901"),
        raw_asic_type: "BM1366",
        asic_family: "BM1366",
        asic_count: 77,
        voltage_domains: Some((11, 7)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S21Default,
        config_sha256: "fab1a64d0514a96fbb11d8f5758cbcbc0c73b2b663abc7216d2bbba88df9e357",
        config_bytes: 3_424,
        binary_sha256: Some("0be428078300f78752ad1b9f9be8ae47e301d4b9db1fdfc351683731a1f4377e"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S21",
        board_name: Some("BHB68603"),
        raw_asic_type: "BM1368",
        asic_family: "BM1368",
        asic_count: 108,
        voltage_domains: Some((12, 9)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S21Pt1,
        config_sha256: "11249e322b4026abe7cc80c1c58b457470a514e2182bc870cc80dc2e4687b6b2",
        config_bytes: 3_424,
        binary_sha256: Some("0be428078300f78752ad1b9f9be8ae47e301d4b9db1fdfc351683731a1f4377e"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S21",
        board_name: Some("BHB68603"),
        raw_asic_type: "BM1368",
        asic_family: "BM1368",
        asic_count: 108,
        voltage_domains: Some((12, 9)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S21Sweep,
        config_sha256: "8d45a684a8f4dde89777ce30251c121390c61fa2069e87526b416f9073dcf45a",
        config_bytes: 3_423,
        binary_sha256: Some("0be428078300f78752ad1b9f9be8ae47e301d4b9db1fdfc351683731a1f4377e"),
        dialect: FactoryConfigDialect::Json,
        miner_type: "S21",
        board_name: Some("BHB68603"),
        raw_asic_type: "BM1368",
        asic_family: "BM1368",
        asic_count: 108,
        voltage_domains: Some((12, 9)),
        cores_per_asic: None,
    },
    ProfileSpec {
        id: FactoryPlanProfileId::S9Legacy,
        config_sha256: "9b77f09fb60d52514d000cb23599ee4edb0580f50c2b4fafd68cb09a7cf8ca55",
        config_bytes: 2_178,
        binary_sha256: None,
        dialect: FactoryConfigDialect::LegacyIni,
        miner_type: "S9 HASH board",
        board_name: None,
        raw_asic_type: "1387",
        asic_family: "BM1387",
        asic_count: 63,
        voltage_domains: None,
        cores_per_asic: Some(114),
    },
    ProfileSpec {
        id: FactoryPlanProfileId::T9PlusLegacy,
        config_sha256: "2c336abff413e5918cd09e28c2d89d4f228cf4a10350630cd8c4bc350d78ba66",
        config_bytes: 2_172,
        binary_sha256: None,
        dialect: FactoryConfigDialect::LegacyIni,
        miner_type: "T9+ HASH board",
        board_name: None,
        raw_asic_type: "1387",
        asic_family: "BM1387",
        asic_count: 18,
        voltage_domains: None,
        cores_per_asic: Some(114),
    },
];

/// Import one raw AMTC config. Only exact held SHA-256 identities are admitted.
pub fn import_factory_test_plan(bytes: &[u8]) -> Result<FactoryTestPlan, FactoryPlanError> {
    if bytes.is_empty() {
        return Err(FactoryPlanError::Empty);
    }
    if bytes.len() > MAX_FACTORY_CONFIG_BYTES {
        return Err(FactoryPlanError::TooLarge {
            bytes: bytes.len(),
            maximum: MAX_FACTORY_CONFIG_BYTES,
        });
    }

    let sha256 = sha256_hex(bytes);
    let spec = PROFILES
        .iter()
        .find(|candidate| candidate.config_sha256 == sha256)
        .copied()
        .ok_or_else(|| FactoryPlanError::UnknownArtifact {
            sha256: sha256.clone(),
        })?;

    if bytes.len() != spec.config_bytes {
        return Err(FactoryPlanError::AdmittedLengthMismatch {
            profile: spec.id.as_str(),
            actual: bytes.len(),
            expected: spec.config_bytes,
        });
    }

    match spec.dialect {
        FactoryConfigDialect::Json => import_json_plan(bytes, spec),
        FactoryConfigDialect::LegacyIni => import_legacy_ini_plan(bytes, spec),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn import_json_plan(bytes: &[u8], spec: ProfileSpec) -> Result<FactoryTestPlan, FactoryPlanError> {
    let root: Value = serde_json::from_slice(bytes).map_err(|_| malformed(spec, "json"))?;

    let miner_type = json_str(&root, "/Hash_Board/Miner_Type", spec)?;
    exact_text(spec, "Hash_Board.Miner_Type", &miner_type, spec.miner_type)?;
    let board_name = json_str(&root, "/Hash_Board/Board_Name", spec)?;
    let expected_board = spec
        .board_name
        .ok_or_else(|| malformed(spec, "Hash_Board.Board_Name expectation"))?;
    exact_text(spec, "Hash_Board.Board_Name", &board_name, expected_board)?;
    let raw_asic_type = json_str(&root, "/Hash_Board/Asic_Type", spec)?;
    exact_text(
        spec,
        "Hash_Board.Asic_Type",
        &raw_asic_type,
        spec.raw_asic_type,
    )?;

    let asic_count = json_u16(&root, "/Hash_Board/Asic_Num", spec)?;
    exact_number(spec, "Hash_Board.Asic_Num", asic_count, spec.asic_count)?;
    let domains = json_u16(&root, "/Hash_Board/Voltage_Domain", spec)?;
    let per_domain = json_u16(&root, "/Hash_Board/Asic_Num_Per_Voltage_Domain", spec)?;
    let expected_domains = spec
        .voltage_domains
        .ok_or_else(|| malformed(spec, "voltage-domain expectation"))?;
    exact_number(
        spec,
        "Hash_Board.Voltage_Domain",
        domains,
        expected_domains.0,
    )?;
    exact_number(
        spec,
        "Hash_Board.Asic_Num_Per_Voltage_Domain",
        per_domain,
        expected_domains.1,
    )?;
    let multiplied = domains
        .checked_mul(per_domain)
        .ok_or(FactoryPlanError::TopologyOverflow {
            profile: spec.id.as_str(),
        })?;
    if multiplied != asic_count {
        return Err(FactoryPlanError::TopologyMismatch {
            profile: spec.id.as_str(),
            domains,
            per_domain,
            asic_count,
        });
    }

    let process = FactoryProcessEvidence {
        vendor_process: json_str(&root, "/Test_Process", spec)?,
        factory_mode: StatedValue::Stated(json_bool(&root, "/Test_Info/Factory_Mode", spec)?),
        repair_enabled: json_optional_bool(&root, "/Repair_Mode/Enable_Repair", spec)?,
    };
    let has_pic = json_optional_bool(&root, "/Hash_Board/Has_Pic", spec)?;
    let sensors = import_json_sensors(&root, spec)?;

    let raw_grading = RawFactoryGradingEvidence {
        pattern_number: StatedValue::Stated(json_u16(
            &root,
            "/Test_Info/Test_Standard/Pattern_Number",
            spec,
        )?),
        least_nonce_per_core: StatedValue::Stated(json_u16(
            &root,
            "/Test_Info/Test_Standard/Least_Nonce_Per_Core",
            spec,
        )?),
        invalid_core_number: StatedValue::Stated(json_u16(
            &root,
            "/Test_Info/Test_Standard/Invalid_Core_Number",
            spec,
        )?),
        most_hw_num: StatedValue::Stated(json_u16(
            &root,
            "/Test_Info/Test_Standard/Most_HW_Num",
            spec,
        )?),
        legacy_data_count: StatedValue::Unknown,
    };
    let standard = family_test_standard(spec.asic_family);
    validate_family_standard(&root, spec, standard, &raw_grading)?;

    let mut raw_leaves = BTreeMap::new();
    flatten_json("", &root, &mut raw_leaves, spec)?;

    Ok(FactoryTestPlan {
        schema: FACTORY_TEST_PLAN_SCHEMA,
        profile_id: spec.id,
        artifact: artifact_evidence(spec),
        identity: FactoryHardwareIdentity {
            miner_type,
            board_name: StatedValue::Stated(board_name),
            asic_family: spec.asic_family.to_owned(),
            raw_asic_type,
        },
        topology: FactoryTopologyEvidence {
            asic_count,
            cores_per_asic: StatedValue::Unknown,
            voltage_domains: VoltageDomainTopology::Checked {
                domains,
                asics_per_domain: per_domain,
            },
        },
        process,
        sensors,
        has_pic,
        grading: FactoryGradingEvidence {
            standard,
            raw: raw_grading,
        },
        pattern_artifact: pattern_artifact_for(spec.asic_family),
        authority: OfflineOnlyNonAuthorizing::new(),
        quarantined_intent: QuarantinedJigIntent { raw_leaves },
    })
}

fn import_legacy_ini_plan(
    bytes: &[u8],
    spec: ProfileSpec,
) -> Result<FactoryTestPlan, FactoryPlanError> {
    let fields = parse_legacy_ini(bytes, spec)?;
    let miner_type = ini_required(&fields, "Name", spec)?.to_owned();
    exact_text(spec, "Name", &miner_type, spec.miner_type)?;
    let raw_asic_type = ini_required(&fields, "AsicType", spec)?.to_owned();
    exact_text(spec, "AsicType", &raw_asic_type, spec.raw_asic_type)?;
    let asic_count = ini_u16(&fields, "AsicNum", spec)?;
    exact_number(spec, "AsicNum", asic_count, spec.asic_count)?;
    let cores_per_asic = ini_u16(&fields, "CoreNum", spec)?;
    let expected_cores = spec
        .cores_per_asic
        .ok_or_else(|| malformed(spec, "CoreNum expectation"))?;
    exact_number(spec, "CoreNum", cores_per_asic, expected_cores)?;

    let sensor_model = match ini_u16(&fields, "sensor_model", spec)? {
        3 => "TMP421".to_owned(),
        _ => return Err(malformed(spec, "sensor_model")),
    };
    let mut logical_fixture_indices = Vec::new();
    for key in ["TempSensor1", "TempSensor2", "TempSensor3"] {
        let index = ini_u16(&fields, key, spec)?;
        if index != 0 {
            logical_fixture_indices.push(index);
        }
    }
    let check_temp = ini_bool01(&fields, "CheckTemp", spec)?;
    let test_mode = ini_u16(&fields, "TestMode", spec)?;

    let raw_grading = RawFactoryGradingEvidence {
        pattern_number: StatedValue::Unknown,
        least_nonce_per_core: StatedValue::Unknown,
        invalid_core_number: StatedValue::Stated(ini_u16(&fields, "Invalid_Core_Num", spec)?),
        most_hw_num: StatedValue::Unknown,
        legacy_data_count: StatedValue::Stated(ini_u32(&fields, "DataCount", spec)?),
    };

    let mut raw_leaves = BTreeMap::new();
    for (key, value) in &fields {
        if raw_leaves.len() >= MAX_QUARANTINED_LEAVES {
            return Err(FactoryPlanError::TooManyRawLeaves {
                profile: spec.id.as_str(),
                maximum: MAX_QUARANTINED_LEAVES,
            });
        }
        raw_leaves.insert(format!("/Config/{key}"), Value::String(value.clone()));
    }

    Ok(FactoryTestPlan {
        schema: FACTORY_TEST_PLAN_SCHEMA,
        profile_id: spec.id,
        artifact: artifact_evidence(spec),
        identity: FactoryHardwareIdentity {
            miner_type,
            board_name: StatedValue::Unknown,
            asic_family: spec.asic_family.to_owned(),
            raw_asic_type,
        },
        topology: FactoryTopologyEvidence {
            asic_count,
            cores_per_asic: StatedValue::Stated(cores_per_asic),
            voltage_domains: VoltageDomainTopology::UnavailableInArtifact,
        },
        process: FactoryProcessEvidence {
            vendor_process: format!("TestMode={test_mode}"),
            factory_mode: StatedValue::Unknown,
            repair_enabled: StatedValue::Unknown,
        },
        sensors: vec![FactorySensorEvidence {
            source: FactorySensorSource::LegacyFixture,
            model: sensor_model,
            read_requested: StatedValue::Stated(check_temp),
            logical_fixture_indices,
        }],
        // Pic_VOLTAGE/IICPic/DAC are active-looking raw intent, not Has_Pic proof.
        has_pic: StatedValue::Unknown,
        grading: FactoryGradingEvidence {
            standard: None,
            raw: raw_grading,
        },
        pattern_artifact: PatternArtifactEvidence::NoFormatAdmitted,
        authority: OfflineOnlyNonAuthorizing::new(),
        quarantined_intent: QuarantinedJigIntent { raw_leaves },
    })
}

fn artifact_evidence(spec: ProfileSpec) -> FactoryArtifactEvidence {
    FactoryArtifactEvidence {
        config_sha256: spec.config_sha256,
        config_bytes: spec.config_bytes,
        associated_jig_binary_sha256: spec
            .binary_sha256
            .map_or(StatedValue::Unknown, StatedValue::Stated),
        dialect: spec.dialect,
    }
}

fn import_json_sensors(
    root: &Value,
    spec: ProfileSpec,
) -> Result<Vec<FactorySensorEvidence>, FactoryPlanError> {
    let mut sensors = Vec::new();
    for (source, prefix, read_path, model_name, indices_name) in [
        (
            FactorySensorSource::Pic,
            "/Hash_Board/Sensor_Info/Pic_Sensor",
            "/Hash_Board/Sensor_Info/Read_Temperature_From_Pic",
            "Pic_Sensor_Model",
            "Pic_Sensor_Addr",
        ),
        (
            FactorySensorSource::Asic,
            "/Hash_Board/Sensor_Info/Asic_Sensor",
            "/Hash_Board/Sensor_Info/Read_Temperature_From_Asic",
            "Asic_Sensor_Model",
            "Asic_Sensor_Addr",
        ),
        (
            FactorySensorSource::ControlBoard,
            "/Hash_Board/Sensor_Info/CtrlBoard_Sensor",
            "/Hash_Board/Sensor_Info/Read_Temperature_From_CtrlBoard",
            "CtrlBoard_Sensor_Model",
            "CtrlBoard_Sensor_Addr",
        ),
    ] {
        let Some(sensor) = root.pointer(prefix) else {
            continue;
        };
        let sensor = sensor
            .as_object()
            .ok_or_else(|| malformed(spec, "Hash_Board.Sensor_Info sensor object"))?;
        let model = sensor
            .get(model_name)
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(spec, "Hash_Board.Sensor_Info sensor model"))?
            .to_owned();
        let raw_indices = sensor
            .get(indices_name)
            .and_then(Value::as_array)
            .ok_or_else(|| malformed(spec, "Hash_Board.Sensor_Info sensor indices"))?;
        if raw_indices.len() > 32 {
            return Err(malformed(spec, "Hash_Board.Sensor_Info sensor index limit"));
        }
        let mut logical_fixture_indices = Vec::with_capacity(raw_indices.len());
        for raw in raw_indices {
            let index = raw
                .as_u64()
                .and_then(|number| u16::try_from(number).ok())
                .ok_or_else(|| malformed(spec, "Hash_Board.Sensor_Info sensor index"))?;
            logical_fixture_indices.push(index);
        }
        sensors.push(FactorySensorEvidence {
            source,
            model,
            read_requested: json_optional_bool(root, read_path, spec)?,
            logical_fixture_indices,
        });
    }
    if sensors.is_empty() {
        return Err(malformed(spec, "Hash_Board.Sensor_Info"));
    }
    Ok(sensors)
}

fn validate_family_standard(
    root: &Value,
    spec: ProfileSpec,
    standard: Option<&'static FamilyTestStandard>,
    raw: &RawFactoryGradingEvidence,
) -> Result<(), FactoryPlanError> {
    let Some(standard) = standard else {
        return Ok(());
    };
    exact_number(
        spec,
        "canonical Asic_Num",
        spec.asic_count,
        standard.asic_num,
    )?;
    let midstate = json_u16(root, "/Test_Info/Test_Method/Midstate_Number", spec)?;
    exact_number(
        spec,
        "Test_Info.Test_Method.Midstate_Number",
        midstate,
        u16::from(standard.midstate_number),
    )?;
    if raw.pattern_number != StatedValue::Stated(u16::from(standard.pattern_number)) {
        return Err(malformed(spec, "Test_Info.Test_Standard.Pattern_Number"));
    }
    if raw.least_nonce_per_core != StatedValue::Stated(standard.least_nonce_per_core) {
        return Err(malformed(
            spec,
            "Test_Info.Test_Standard.Least_Nonce_Per_Core",
        ));
    }
    if raw.most_hw_num != StatedValue::Stated(standard.most_hw_num) {
        return Err(malformed(spec, "Test_Info.Test_Standard.Most_HW_Num"));
    }
    // Invalid_Core_Number intentionally is not compared: BHB56901 repair states
    // 89 while the canonical BM1366 normal profile states 77, and its verdict
    // semantics are not decompiled.
    Ok(())
}

fn pattern_artifact_for(family: &str) -> PatternArtifactEvidence {
    match family {
        "BM1362" => PatternArtifactEvidence::Exact(ExactPatternArtifact {
            sha256: "6f9b500e22884f575e0c5e5dbe43ff118299a0bbdae585ed71f88d3d3ab55d9d",
            bytes: 24_869_376,
            record_count: 518_112,
            format: PatternFormat::Wide48,
            row_order: PatternRowOrderEvidence::NotProven,
            artifact_factorization: (126, 514, 8),
        }),
        "BM1366" => PatternArtifactEvidence::Exact(ExactPatternArtifact {
            sha256: "63f83aa8fbabef784e90553a26eae51a04dfc2e11ebc154470a40b19183f35f8",
            bytes: 43_255_296,
            record_count: 901_152,
            format: PatternFormat::Wide48,
            row_order: PatternRowOrderEvidence::NotProven,
            artifact_factorization: (126, 894, 8),
        }),
        "BM1368" => PatternArtifactEvidence::Exact(ExactPatternArtifact {
            sha256: "6321d1e1cd1c9032a684b7e5aafc4ffe07dd8d218560c63331580f13d1af8ea3",
            bytes: 13_271_040,
            record_count: 1_105_920,
            format: PatternFormat::Compact12,
            row_order: PatternRowOrderEvidence::DecompileProvenAsicCorePattern,
            artifact_factorization: (108, 1_280, 8),
        }),
        _ => PatternArtifactEvidence::NoFormatAdmitted,
    }
}

fn flatten_json(
    prefix: &str,
    value: &Value,
    leaves: &mut BTreeMap<String, Value>,
    spec: ProfileSpec,
) -> Result<(), FactoryPlanError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let path = format!("{prefix}/{key}");
                flatten_json(&path, nested, leaves, spec)?;
            }
        }
        Value::Array(array) => {
            for (index, nested) in array.iter().enumerate() {
                let path = format!("{prefix}/{index}");
                flatten_json(&path, nested, leaves, spec)?;
            }
        }
        _ => {
            if leaves.len() >= MAX_QUARANTINED_LEAVES {
                return Err(FactoryPlanError::TooManyRawLeaves {
                    profile: spec.id.as_str(),
                    maximum: MAX_QUARANTINED_LEAVES,
                });
            }
            leaves.insert(prefix.to_owned(), value.clone());
        }
    }
    Ok(())
}

fn parse_legacy_ini(
    bytes: &[u8],
    spec: ProfileSpec,
) -> Result<BTreeMap<String, String>, FactoryPlanError> {
    let text = str::from_utf8(bytes).map_err(|_| malformed(spec, "utf8"))?;
    let mut fields = BTreeMap::new();
    let mut lines = 0usize;
    for raw_line in text.lines() {
        lines = lines.saturating_add(1);
        if lines > MAX_LEGACY_INI_LINES || raw_line.len() > MAX_LEGACY_INI_LINE_BYTES {
            return Err(FactoryPlanError::LegacyIniLimit {
                profile: spec.id.as_str(),
            });
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line == "[Config]" {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| malformed(spec, "legacy INI key/value"))?;
        let key = key.trim();
        if key.is_empty() || fields.contains_key(key) {
            return Err(malformed(spec, "legacy INI unique key"));
        }
        fields.insert(key.to_owned(), value.trim().to_owned());
    }
    Ok(fields)
}

fn json_str(
    root: &Value,
    pointer: &'static str,
    spec: ProfileSpec,
) -> Result<String, FactoryPlanError> {
    root.pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| malformed(spec, pointer))
}

fn json_u16(
    root: &Value,
    pointer: &'static str,
    spec: ProfileSpec,
) -> Result<u16, FactoryPlanError> {
    root.pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|number| u16::try_from(number).ok())
        .ok_or_else(|| malformed(spec, pointer))
}

fn json_bool(
    root: &Value,
    pointer: &'static str,
    spec: ProfileSpec,
) -> Result<bool, FactoryPlanError> {
    root.pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed(spec, pointer))
}

fn json_optional_bool(
    root: &Value,
    pointer: &'static str,
    spec: ProfileSpec,
) -> Result<StatedValue<bool>, FactoryPlanError> {
    match root.pointer(pointer) {
        Some(value) => value
            .as_bool()
            .map(StatedValue::Stated)
            .ok_or_else(|| malformed(spec, pointer)),
        None => Ok(StatedValue::Unknown),
    }
}

fn ini_required<'a>(
    fields: &'a BTreeMap<String, String>,
    key: &'static str,
    spec: ProfileSpec,
) -> Result<&'a str, FactoryPlanError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| malformed(spec, key))
}

fn ini_u16(
    fields: &BTreeMap<String, String>,
    key: &'static str,
    spec: ProfileSpec,
) -> Result<u16, FactoryPlanError> {
    ini_required(fields, key, spec)?
        .parse::<u16>()
        .map_err(|_| malformed(spec, key))
}

fn ini_u32(
    fields: &BTreeMap<String, String>,
    key: &'static str,
    spec: ProfileSpec,
) -> Result<u32, FactoryPlanError> {
    ini_required(fields, key, spec)?
        .parse::<u32>()
        .map_err(|_| malformed(spec, key))
}

fn ini_bool01(
    fields: &BTreeMap<String, String>,
    key: &'static str,
    spec: ProfileSpec,
) -> Result<bool, FactoryPlanError> {
    match ini_required(fields, key, spec)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(malformed(spec, key)),
    }
}

fn exact_text(
    spec: ProfileSpec,
    field: &'static str,
    actual: &str,
    expected: &'static str,
) -> Result<(), FactoryPlanError> {
    if actual == expected {
        Ok(())
    } else {
        Err(FactoryPlanError::ContractMismatch {
            profile: spec.id.as_str(),
            field,
            actual: actual.to_owned(),
            expected: expected.to_owned(),
        })
    }
}

fn exact_number(
    spec: ProfileSpec,
    field: &'static str,
    actual: u16,
    expected: u16,
) -> Result<(), FactoryPlanError> {
    if actual == expected {
        Ok(())
    } else {
        Err(FactoryPlanError::ContractMismatch {
            profile: spec.id.as_str(),
            field,
            actual: actual.to_string(),
            expected: expected.to_string(),
        })
    }
}

fn malformed(spec: ProfileSpec, field: &'static str) -> FactoryPlanError {
    FactoryPlanError::MalformedAdmittedArtifact {
        profile: spec.id.as_str(),
        field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &[(&str, FactoryPlanProfileId, &str)] = &[
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s19pro-pt1.json.b64"),
            FactoryPlanProfileId::S19ProPt1,
            "5b601ea95578ab1e951d31eb442c2aae96d863c3855b7b0e72638ca9d2cf0dfe",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s19jpro-pt1new.json.b64"),
            FactoryPlanProfileId::S19jProPt1New,
            "3ea4d11ec9aeda71785825bc7fc9e80699e3101048c75b66dbe15b4655f9fa5b",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s19kpro-normal.json.b64"),
            FactoryPlanProfileId::S19kProNormal,
            "873443e20dba75d5eec41414f23cc5a479015c46576e746c5bec851e41be3ee4",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s19kpro-repair.json.b64"),
            FactoryPlanProfileId::S19kProRepair,
            "0aa1dfac98faef16c840c0532c67e7f79b4055d677a1b835ab8a8099dbce0517",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s21-default.json.b64"),
            FactoryPlanProfileId::S21Default,
            "fab1a64d0514a96fbb11d8f5758cbcbc0c73b2b663abc7216d2bbba88df9e357",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s21-pt1.json.b64"),
            FactoryPlanProfileId::S21Pt1,
            "11249e322b4026abe7cc80c1c58b457470a514e2182bc870cc80dc2e4687b6b2",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s21-sweep.json.b64"),
            FactoryPlanProfileId::S21Sweep,
            "8d45a684a8f4dde89777ce30251c121390c61fa2069e87526b416f9073dcf45a",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/s9-legacy.ini.b64"),
            FactoryPlanProfileId::S9Legacy,
            "9b77f09fb60d52514d000cb23599ee4edb0580f50c2b4fafd68cb09a7cf8ca55",
        ),
        (
            include_str!("../tests/fixtures/amtc_factory_plans/t9plus-legacy.ini.b64"),
            FactoryPlanProfileId::T9PlusLegacy,
            "2c336abff413e5918cd09e28c2d89d4f228cf4a10350630cd8c4bc350d78ba66",
        ),
    ];

    fn decode_base64_fixture(text: &str) -> Vec<u8> {
        fn value(byte: u8) -> Option<u8> {
            match byte {
                b'A'..=b'Z' => Some(byte - b'A'),
                b'a'..=b'z' => Some(byte - b'a' + 26),
                b'0'..=b'9' => Some(byte - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }

        let clean: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert_eq!(clean.len() % 4, 0, "fixture base64 length");
        let mut output = Vec::with_capacity(clean.len() / 4 * 3);
        for chunk in clean.chunks_exact(4) {
            let a = value(chunk[0]).expect("base64 a");
            let b = value(chunk[1]).expect("base64 b");
            let c = if chunk[2] == b'=' {
                0
            } else {
                value(chunk[2]).expect("base64 c")
            };
            let d = if chunk[3] == b'=' {
                0
            } else {
                value(chunk[3]).expect("base64 d")
            };
            output.push((a << 2) | (b >> 4));
            if chunk[2] != b'=' {
                output.push((b << 4) | (c >> 2));
            }
            if chunk[3] != b'=' {
                output.push((c << 6) | d);
            }
        }
        output
    }

    fn fixture(id: FactoryPlanProfileId) -> Vec<u8> {
        let encoded = FIXTURES
            .iter()
            .find(|(_, candidate, _)| *candidate == id)
            .map(|(text, _, _)| *text)
            .expect("fixture profile");
        decode_base64_fixture(encoded)
    }

    #[test]
    fn admits_all_nine_exact_artifacts_with_distinct_ids() {
        let mut ids = std::collections::BTreeSet::new();
        for (encoded, expected_id, expected_sha) in FIXTURES {
            let bytes = decode_base64_fixture(encoded);
            assert_eq!(sha256_hex(&bytes), *expected_sha);
            let plan = import_factory_test_plan(&bytes).expect("exact fixture admitted");
            assert_eq!(plan.profile_id, *expected_id);
            assert_eq!(plan.artifact.config_sha256, *expected_sha);
            assert!(ids.insert(plan.profile_id));
        }
        assert_eq!(ids.len(), 9);
    }

    #[test]
    fn exact_hash_is_the_only_admission_key() {
        let mut bytes = fixture(FactoryPlanProfileId::S21Pt1);
        let byte = bytes
            .iter_mut()
            .find(|byte| **byte == b'S')
            .expect("S byte");
        *byte = b's';
        assert!(matches!(
            import_factory_test_plan(&bytes),
            Err(FactoryPlanError::UnknownArtifact { .. })
        ));
        assert!(matches!(
            import_factory_test_plan(&vec![0u8; MAX_FACTORY_CONFIG_BYTES + 1]),
            Err(FactoryPlanError::TooLarge { .. })
        ));
    }

    #[test]
    fn associated_jig_binary_provenance_is_held_or_explicitly_unknown() {
        for id in [
            FactoryPlanProfileId::S19ProPt1,
            FactoryPlanProfileId::S19jProPt1New,
            FactoryPlanProfileId::S19kProNormal,
            FactoryPlanProfileId::S19kProRepair,
            FactoryPlanProfileId::S21Default,
            FactoryPlanProfileId::S21Pt1,
            FactoryPlanProfileId::S21Sweep,
        ] {
            let plan = import_factory_test_plan(&fixture(id)).expect("modern plan");
            let StatedValue::Stated(sha256) = &plan.artifact().associated_jig_binary_sha256 else {
                panic!("held modern jig binary must remain stated");
            };
            assert_eq!(sha256.len(), 64);
            assert!(sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }

        let s9 =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S9Legacy)).expect("S9 plan");
        assert_eq!(
            &s9.artifact().associated_jig_binary_sha256,
            &StatedValue::Unknown
        );
        let t9plus = import_factory_test_plan(&fixture(FactoryPlanProfileId::T9PlusLegacy))
            .expect("T9+ plan");
        assert_eq!(
            &t9plus.artifact().associated_jig_binary_sha256,
            &StatedValue::Unknown
        );
    }

    #[test]
    fn topology_is_checked_and_legacy_profiles_stay_partial() {
        for id in [
            FactoryPlanProfileId::S19ProPt1,
            FactoryPlanProfileId::S19jProPt1New,
            FactoryPlanProfileId::S19kProNormal,
            FactoryPlanProfileId::S19kProRepair,
            FactoryPlanProfileId::S21Default,
            FactoryPlanProfileId::S21Pt1,
            FactoryPlanProfileId::S21Sweep,
        ] {
            let plan = import_factory_test_plan(&fixture(id)).expect("modern plan");
            let VoltageDomainTopology::Checked {
                domains,
                asics_per_domain,
            } = plan.topology.voltage_domains
            else {
                panic!("modern plan must have checked domains");
            };
            assert_eq!(domains * asics_per_domain, plan.topology.asic_count);
        }

        let s9 =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S9Legacy)).expect("S9 plan");
        assert_eq!(s9.identity.board_name, StatedValue::Unknown);
        assert_eq!(s9.topology.cores_per_asic, StatedValue::Stated(114));
        assert_eq!(
            s9.topology.voltage_domains,
            VoltageDomainTopology::UnavailableInArtifact
        );
        assert_eq!(s9.has_pic, StatedValue::Unknown);

        let t9plus = import_factory_test_plan(&fixture(FactoryPlanProfileId::T9PlusLegacy))
            .expect("T9+ plan");
        assert_eq!(t9plus.identity.board_name, StatedValue::Unknown);
        assert_eq!(t9plus.topology.cores_per_asic, StatedValue::Stated(114));
        assert_eq!(
            t9plus.topology.voltage_domains,
            VoltageDomainTopology::UnavailableInArtifact
        );
        assert_eq!(t9plus.has_pic, StatedValue::Unknown);
    }

    #[test]
    fn t9plus_exact_plan_is_passive_quarantined_and_non_authorizing() {
        let bytes = fixture(FactoryPlanProfileId::T9PlusLegacy);
        let plan = import_factory_test_plan(&bytes).expect("exact T9+ plan");

        assert_eq!(plan.profile_id, FactoryPlanProfileId::T9PlusLegacy);
        assert_eq!(plan.identity.miner_type, "T9+ HASH board");
        assert_eq!(plan.identity.asic_family, "BM1387");
        assert_eq!(plan.identity.raw_asic_type, "1387");
        assert_eq!(plan.topology.asic_count, 18);
        assert_eq!(plan.topology.cores_per_asic, StatedValue::Stated(114));
        assert_eq!(plan.process.vendor_process, "TestMode=1");
        assert_eq!(plan.sensors.len(), 1);
        assert_eq!(plan.sensors[0].source, FactorySensorSource::LegacyFixture);
        assert_eq!(plan.sensors[0].model, "TMP421");
        assert_eq!(plan.sensors[0].read_requested, StatedValue::Stated(true));
        assert_eq!(plan.sensors[0].logical_fixture_indices, vec![1]);
        assert_eq!(plan.grading.raw.invalid_core_number, StatedValue::Stated(0));
        assert_eq!(plan.grading.raw.legacy_data_count, StatedValue::Stated(912));
        assert_eq!(plan.grading.standard, None);
        assert_eq!(
            plan.pattern_artifact,
            PatternArtifactEvidence::NoFormatAdmitted
        );

        for (path, expected) in [
            ("/Config/Freq1", "200"),
            ("/Config/Voltage1", "860"),
            ("/Config/Pic_VOLTAGE", "1"),
            ("/Config/IICPic", "1"),
            ("/Config/DAC", "1"),
            ("/Config/write_freq_into_pic", "0"),
        ] {
            assert_eq!(
                plan.quarantined_intent.raw_value(path),
                Some(&Value::String(expected.to_owned())),
                "{path} must remain read-only vendor intent"
            );
        }

        let authority = plan.authority.authority();
        for denied in [
            authority.device_io,
            authority.pattern_dispatch,
            authority.voltage_control,
            authority.frequency_control,
            authority.fan_control,
            authority.eeprom_mutation,
            authority.repair_action,
            authority.manufacturing_action,
            authority.grading_verdict,
        ] {
            assert!(!denied.is_authorized());
        }

        let mut mutated = bytes;
        let byte = mutated
            .iter_mut()
            .find(|byte| **byte == b'T')
            .expect("T9+ artifact contains a T byte");
        *byte = b't';
        assert!(matches!(
            import_factory_test_plan(&mutated),
            Err(FactoryPlanError::UnknownArtifact { .. })
        ));
    }

    #[test]
    fn internal_s19j_identity_overrides_misleading_folder_name() {
        let plan = import_factory_test_plan(&fixture(FactoryPlanProfileId::S19jProPt1New))
            .expect("S19j Pro plan");
        assert_eq!(plan.identity.miner_type, "S19j_Pro");
        assert_eq!(
            plan.identity.board_name,
            StatedValue::Stated("BHB42601".to_owned())
        );
        assert_eq!(plan.identity.asic_family, "BM1362");
    }

    #[test]
    fn bhb56901_and_bhb56902_are_distinct_and_raw_invalid_core_is_not_a_verdict() {
        let normal = import_factory_test_plan(&fixture(FactoryPlanProfileId::S19kProNormal))
            .expect("normal plan");
        let repair = import_factory_test_plan(&fixture(FactoryPlanProfileId::S19kProRepair))
            .expect("repair plan");
        assert_ne!(normal.profile_id, repair.profile_id);
        assert_eq!(
            normal.identity.board_name,
            StatedValue::Stated("BHB56902".to_owned())
        );
        assert_eq!(
            repair.identity.board_name,
            StatedValue::Stated("BHB56901".to_owned())
        );
        assert_eq!(
            normal.grading.raw.invalid_core_number,
            StatedValue::Stated(77)
        );
        assert_eq!(
            repair.grading.raw.invalid_core_number,
            StatedValue::Stated(89)
        );
        assert!(std::ptr::eq(
            normal.grading.standard.expect("BM1366 standard"),
            family_test_standard("BM1366").expect("canonical BM1366 standard")
        ));
        assert!(std::ptr::eq(
            repair.grading.standard.expect("BM1366 standard"),
            family_test_standard("BM1366").expect("canonical BM1366 standard")
        ));
    }

    #[test]
    fn unmodeled_families_do_not_inherit_a_grading_or_pattern_format() {
        for id in [
            FactoryPlanProfileId::S19ProPt1,
            FactoryPlanProfileId::S9Legacy,
        ] {
            let plan = import_factory_test_plan(&fixture(id)).expect("unmodeled plan");
            assert_eq!(plan.grading.standard, None);
            assert_eq!(
                plan.pattern_artifact,
                PatternArtifactEvidence::NoFormatAdmitted
            );
        }
    }

    #[test]
    fn exact_pattern_manifests_pin_format_size_and_non_board_pool_factorization() {
        let bm1362 = import_factory_test_plan(&fixture(FactoryPlanProfileId::S19jProPt1New))
            .expect("BM1362 plan");
        let bm1366 = import_factory_test_plan(&fixture(FactoryPlanProfileId::S19kProNormal))
            .expect("BM1366 plan");
        let bm1368 = import_factory_test_plan(&fixture(FactoryPlanProfileId::S21Default))
            .expect("BM1368 plan");

        let PatternArtifactEvidence::Exact(wide1362) = bm1362.pattern_artifact else {
            panic!("BM1362 exact pattern");
        };
        assert_eq!(wide1362.bytes, 24_869_376);
        assert_eq!(wide1362.artifact_factorization, (126, 514, 8));
        let PatternArtifactEvidence::Exact(wide1366) = bm1366.pattern_artifact else {
            panic!("BM1366 exact pattern");
        };
        assert_eq!(wide1366.artifact_factorization, (126, 894, 8));
        assert_ne!(
            wide1366.artifact_factorization.0,
            bm1366.topology.asic_count
        );
        let PatternArtifactEvidence::Exact(compact1368) = bm1368.pattern_artifact else {
            panic!("BM1368 exact pattern");
        };
        assert_eq!(compact1368.format, PatternFormat::Compact12);
        assert_eq!(
            compact1368.row_order,
            PatternRowOrderEvidence::DecompileProvenAsicCorePattern
        );
        for artifact in [&wide1362, &wide1366, &compact1368] {
            assert_eq!(artifact.sha256.len(), 64);
            assert!(artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }
    }

    #[test]
    fn process_variants_and_pic_presence_are_not_generalized() {
        let default =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S21Default)).expect("default");
        let pt1 = import_factory_test_plan(&fixture(FactoryPlanProfileId::S21Pt1)).expect("PT1");
        let sweep =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S21Sweep)).expect("sweep");
        assert_eq!(default.process.vendor_process, "PT1new");
        assert_eq!(pt1.process.vendor_process, "PT1new");
        assert_eq!(sweep.process.vendor_process, "SWEEP");
        assert_eq!(default.process.factory_mode, StatedValue::Stated(false));
        assert_eq!(sweep.process.factory_mode, StatedValue::Stated(true));
        assert_eq!(default.process.repair_enabled, StatedValue::Stated(true));
        assert_eq!(sweep.process.repair_enabled, StatedValue::Stated(false));
        assert_eq!(default.has_pic, StatedValue::Unknown);

        let s19k = import_factory_test_plan(&fixture(FactoryPlanProfileId::S19kProNormal))
            .expect("S19k normal");
        assert_eq!(s19k.has_pic, StatedValue::Stated(false));
    }

    #[test]
    fn sensor_numbers_are_explicitly_logical_fixture_indices() {
        let plan =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S21Default)).expect("S21 plan");
        let ctrl = plan
            .sensors
            .iter()
            .find(|sensor| sensor.source == FactorySensorSource::ControlBoard)
            .expect("control-board sensor evidence");
        assert_eq!(ctrl.model, "LM75A");
        assert_eq!(ctrl.logical_fixture_indices, vec![0, 4]);
        assert_eq!(plan.has_pic, StatedValue::Unknown);
    }

    #[test]
    fn all_active_controls_are_raw_only_and_all_authorities_are_denied() {
        let s21 =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S21Sweep)).expect("S21 sweep");
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Test_Info/Sweep_Cfg/Sweep_Max_Freq"),
            Some(&Value::from(540))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Test_Info/Test_Standard/Test_Loop/0/Voltage"),
            Some(&Value::from(1320))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Test_Info/Test_Standard/Test_Loop/0/Frequence"),
            Some(&Value::from(450))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Test_Info/Test_Speed/Baudrate"),
            Some(&Value::from(12_000_000))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Test_Info/Asic_Register/Pwth_Sel"),
            Some(&Value::from(4))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Hash_Board/Inc_Freq_Delay"),
            Some(&Value::from(100))
        );
        assert_eq!(
            s21.quarantined_intent.raw_value("/Test_Info/Factory_Mode"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Repair_Mode/Enable_Repair"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            s21.quarantined_intent
                .raw_value("/Repair_Mode/Clear_EEPROM_Data"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            s21.quarantined_intent.raw_value("/Test_Info/Fan/Fan_Speed"),
            Some(&Value::from(100))
        );
        let authority = s21.authority.authority();
        for denied in [
            authority.device_io,
            authority.pattern_dispatch,
            authority.voltage_control,
            authority.frequency_control,
            authority.fan_control,
            authority.eeprom_mutation,
            authority.repair_action,
            authority.manufacturing_action,
            authority.grading_verdict,
        ] {
            assert!(!denied.is_authorized());
        }

        let s9 =
            import_factory_test_plan(&fixture(FactoryPlanProfileId::S9Legacy)).expect("S9 legacy");
        assert_eq!(
            s9.quarantined_intent.raw_value("/Config/Pic_VOLTAGE"),
            Some(&Value::String("1".to_owned()))
        );
        assert_eq!(
            s9.quarantined_intent.raw_value("/Config/DAC"),
            Some(&Value::String("1".to_owned()))
        );
        assert_eq!(
            s9.quarantined_intent
                .raw_value("/Config/write_freq_into_pic"),
            Some(&Value::String("0".to_owned()))
        );
        assert_eq!(
            s9.quarantined_intent.raw_value("/Config/hold_freq_in_pic"),
            Some(&Value::String("1".to_owned()))
        );
    }
}
