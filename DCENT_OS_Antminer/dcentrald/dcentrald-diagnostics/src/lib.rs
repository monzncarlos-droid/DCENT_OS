//! Diagnostic test orchestration and report generation for dcentrald.
//!
//! Manages the lifecycle of diagnostic tests, streams progress via WebSocket,
//! and generates reports. Supports both native Rust tests and Phase 1
//! subprocess-based tests (wrapping existing Python tools).
//!
//! Modules:
//! - `hashreport`   - HashReport schema and current completion-snapshot grading
//! - `chip_health`  - Per-chip health scoring and ChipMap
//! - `board_health` - Per-board snapshot schema and canonical health grading
//! - `troubleshoot` - Instant troubleshooting tools
//! - `report`       - HTML/PDF report generation (askama templates)
//! - `progress`     - Progress tracking and WebSocket push
//! - `subprocess`   - Phase 1 Python subprocess wrapper
//!
//! # Diagnostic evidence migration
//!
//! Passing repair/manufacturing grades require typed, directly measured
//! evidence. Legacy serialized results have no trustworthy provenance, so new
//! evidence fields default to `Unavailable` and A/B grades are withheld when
//! recalculated. Current runtime-snapshot producers deliberately label voltage
//! as `Commanded` and cumulative CRC state as `Inferred`; board model metadata
//! is not treated as EEPROM presence or validation. Consequently snapshots are
//! useful triage records, but cannot claim a measured pass.
//!
//! Production builds intentionally expose no constructor that can mint
//! measured-verdict authority from caller-supplied values. Dedicated hardware
//! producers must first add the run-bound, parser-issued receipt path described
//! by the v3 contract; source text and a timestamp alone are insufficient.
//! Residual producer gap: `SnapshotChain` has no bounded chip-enumeration, typed
//! temperature-sensor, voltage-readback, bounded CRC-window, or EEPROM
//! read/checksum provenance, so snapshot reports remain capped until those
//! data paths expose direct observations.
//! Serialized v2 evidence is offline-unattested and cannot recreate the private,
//! test-only construction witness used to exercise A/B grading rules. Run/capture binding,
//! explicit verification status, and portable attestation belong to the v3
//! envelope described in `docs/architecture/DIAGNOSTIC_EVIDENCE.md`.

pub mod board_health;
pub mod builders;
/// Pure chip anomaly math bridge (`dcentrald-chip-analysis`).
pub mod chip_analysis_bridge;
pub mod chip_health;
/// Honest snapshot vs active-stim labels (P2-5).
pub mod diagnostic_mode;
pub mod evidence;
/// Exact-artifact AMTC factory-plan importer (default-OFF `factory-test-plan`).
/// Pure evidence IR only: structurally offline/non-authorizing, with no executor.
#[cfg(feature = "factory-test-plan")]
pub mod factory_test_plan;
/// First-party fault/diagnostic knowledge layer transcribed from the Bitmain ATA
/// maintenance-training corpus. Pure, declarative, read-only reference data
/// (symptom→suspect→test→remedy chains + reference measurement values). Never a
/// runtime threshold and never a hardware path — see the module docs.
pub mod fault_knowledge;
pub mod hashreport;
/// Exhaustive, non-authorizing manufacturing-interface capability ceiling.
pub mod manufacturing_interface;
/// Offline factory pattern-test parser/grader (default-OFF `pattern-selftest`).
///
/// Pure only: parses held AMTC pattern blobs and grades per-core nonce maps.
/// Does **not** dispatch work or open hardware. The live self-test arm remains
/// a separate, gated item that must consume `admit_work_dispatch`.
#[cfg(feature = "pattern-selftest")]
pub mod pattern_test;
pub mod progress;
/// Physical fault localization from a ChipMap (pure, Inferred-grade diagnoses).
pub mod repair_advisor;
pub mod report;
pub mod snapshot;
pub mod subprocess;
pub mod troubleshoot;

pub use chip_analysis_bridge::{
    analyze_chip, enrich_cell_anomalies, ChipAnalysis, ChipAnomalyScores,
};
pub use diagnostic_mode::{
    admit_report_kind, evidence_kind_from_measurement_provenance, parse_report_kind,
    DiagnosticModeError, DiagnosticRunMode,
};
pub use evidence::{DiagnosticEvidence, EvidenceKind, EvidenceQuality};
pub use fault_knowledge::{
    diagnostic_chain, signal_reference, training_domain_topologies, DiagnosticStep, DomainTopology,
    Guide, GuideRef, Repairability, SignalReference, SymptomClass,
};
pub use repair_advisor::{
    analyze_chipmap, repair_mode_capability, RepairConfidence, RepairContext, RepairModeCapability,
    RepairModeCapabilityState, RepairRecommendation, SuspectedComponent, REPAIR_MODE_CAPABILITIES,
};

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::board_health::BoardHealthResult;
use crate::chip_health::ChipHealthSnapshot;
use crate::progress::{DiagnosticProgress, ProgressTracker};
use crate::troubleshoot::{
    AsicCommSnapshot, FpgaStatusSnapshot, I2cScanSnapshot, NetworkTestSnapshot, PsuProbeSnapshot,
    RuntimeOwnedFpgaTelemetry, RuntimeOwnedI2cTelemetry, UnattestedFpgaTelemetry,
    UnattestedNetworkTelemetry, UnattestedPsuTelemetry,
};

/// Diagnostic subsystem error type.
#[derive(Debug, Error)]
pub enum DiagnosticError {
    /// Test not found.
    #[error("test not found: {test_id}")]
    TestNotFound { test_id: Uuid },

    /// Test already running.
    #[error("a test of type {test_type} is already running")]
    TestAlreadyRunning { test_type: String },

    /// A caller tried to reuse a lifecycle identity that is already recorded.
    #[error("diagnostic test ID already exists: {test_id}")]
    TestIdAlreadyExists { test_id: Uuid },

    /// The public test label does not match the typed job configuration.
    #[error("diagnostic test/config mismatch: requested {requested:?}, config is {configured:?}")]
    TestConfigMismatch {
        requested: TestType,
        configured: TestType,
    },

    /// The asynchronous engine was requested without an active Tokio runtime.
    #[error("diagnostic runtime unavailable for {test_type:?}")]
    RuntimeUnavailable { test_type: TestType },

    /// Internal lifecycle state could not be locked safely.
    #[error("diagnostic lifecycle state unavailable")]
    StateUnavailable,

    /// A prepared snapshot failed the narrow typed-publication contract.
    #[error("diagnostic snapshot admission failed: {reason}")]
    SnapshotAdmission { reason: String },

    /// HAL error during diagnostic test.
    #[error("HAL error: {0}")]
    Hal(#[from] dcentrald_hal::HalError),

    /// ASIC error during diagnostic test.
    #[error("ASIC error: {0}")]
    Asic(#[from] dcentrald_asic::AsicError),

    /// Subprocess execution error.
    #[error("subprocess error: {0}")]
    Subprocess(String),

    /// Report generation error.
    #[error("report generation error: {0}")]
    ReportGeneration(String),

    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DiagnosticError>;

/// Types of diagnostic tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestType {
    /// 15-minute comprehensive test drive.
    HashReport,
    /// Publication of an already-prepared, typed per-chip health snapshot.
    ChipHealth,
    /// Per-board health test (2 min).
    BoardHealth,
    /// Instant network diagnostics.
    NetworkTest,
    /// PSU PMBus readings.
    PsuProbe,
    /// FPGA register status.
    FpgaStatus,
    /// ASIC communication test.
    AsicCommTest,
    /// I2C bus scan.
    I2cScan,
}

impl TestType {
    /// Canonical public test identities.  Exhaustiveness is enforced by
    /// [`diagnostic_interface_capability`]'s compiler-checked match below.
    pub const ALL: [Self; 8] = [
        Self::HashReport,
        Self::ChipHealth,
        Self::BoardHealth,
        Self::NetworkTest,
        Self::PsuProbe,
        Self::FpgaStatus,
        Self::AsicCommTest,
        Self::I2cScan,
    ];
}

/// Source implementation ceiling for one public [`TestType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticInterfaceCapabilityState {
    /// A timed snapshot/report engine is wired, but its current producer cannot
    /// mint typed measured-pass or manufacturing-grade authority.
    RuntimeSnapshotEngineNoMeasuredPass,
    /// A production route persists a prepared typed snapshot before recording
    /// its synchronous, ungraded lifecycle completion.
    PersistedSnapshotPublisherProductionRouteNoMeasuredPass,
    /// A production route publishes an immediate typed snapshot derived from
    /// already-retained daemon telemetry, without active hardware commands.
    ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass,
    /// A synchronous typed publisher accepts explicitly unattested telemetry,
    /// but no production route yet supplies a producer-attested snapshot.
    ImmediateTelemetrySnapshotPublisherNoProductionRouteNoMeasuredPass,
    /// The public type is declared, but no matching [`DiagnosticJobConfig`]
    /// engine is implemented.
    DeclaredNoJobEngine,
}

/// Exact, non-authorizing capability record for one diagnostic interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticInterfaceCapability {
    pub test_type: TestType,
    pub state: DiagnosticInterfaceCapabilityState,
    pub evidence: &'static str,
    /// A typed lifecycle/publisher implementation exists. This does not imply
    /// runtime capture or a production route.
    pub runtime_job_engine_implemented: bool,
    /// A production caller can construct and dispatch the matching config.
    pub production_route_integrated: bool,
    pub typed_measured_pass_authorized: bool,
    pub manufacturing_grade_authorized: bool,
    pub hardware_mutation_authorized: bool,
}

/// Exhaustive capability ceiling for every public diagnostic test identity.
pub const DIAGNOSTIC_INTERFACE_CAPABILITIES: &[DiagnosticInterfaceCapability] = &[
    DiagnosticInterfaceCapability {
        test_type: TestType::HashReport,
        state: DiagnosticInterfaceCapabilityState::RuntimeSnapshotEngineNoMeasuredPass,
        evidence: "timed HashReport job plus snapshot finalizer; direct measured receipts absent",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::ChipHealth,
        state:
            DiagnosticInterfaceCapabilityState::PersistedSnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "production REST route persists a typed ChipHealthSnapshot before synchronous lifecycle publication; publisher has no hardware access",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::BoardHealth,
        state:
            DiagnosticInterfaceCapabilityState::PersistedSnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "production REST route persists typed BoardHealth results before synchronous lifecycle publication; publisher has no hardware access",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::NetworkTest,
        state:
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "bounded production REST route publishes its validated IP/route/gateway/DNS stage outcomes plus explicitly cached pool state through a synchronous typed lifecycle publisher; no hardware or live pool-connect probe is issued by the publisher",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::PsuProbe,
        state:
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "production REST route publishes the retained power_rx sample using its producer timestamp, or explicit Unavailable when no timestamped sample exists; the synchronous typed publisher re-evaluates age and performs no PMBus/I2C/UART/device access",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::FpgaStatus,
        state:
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "standard WorkDispatcher publishes a retained source-owned register snapshot from the FPGA chains it already owns; the production REST route clones that snapshot or records explicit Unavailable, while the synchronous lifecycle publisher performs no MMIO/UIO/devmem/device access and grants no measured-pass authority",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::AsicCommTest,
        state:
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "production REST route publishes a typed snapshot from retained state_rx chain telemetry; no live GetAddress command or hardware access",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
    DiagnosticInterfaceCapability {
        test_type: TestType::I2cScan,
        state:
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass,
        evidence: "serialized I2C service owners retain only successful endpoint operations; the production REST route clones sender-free readers or publishes explicit Unavailable and issues no scan, probe, or new bus transaction",
        runtime_job_engine_implemented: true,
        production_route_integrated: true,
        typed_measured_pass_authorized: false,
        manufacturing_grade_authorized: false,
        hardware_mutation_authorized: false,
    },
];

/// Return the canonical capability row for a public diagnostic identity.
///
/// The explicit match is intentional: adding a [`TestType`] cannot compile
/// until its source capability is classified.  This prevents a new enum
/// variant from being omitted from both a hand-maintained table and its test.
pub const fn diagnostic_interface_capability(
    test_type: TestType,
) -> &'static DiagnosticInterfaceCapability {
    match test_type {
        TestType::HashReport => &DIAGNOSTIC_INTERFACE_CAPABILITIES[0],
        TestType::ChipHealth => &DIAGNOSTIC_INTERFACE_CAPABILITIES[1],
        TestType::BoardHealth => &DIAGNOSTIC_INTERFACE_CAPABILITIES[2],
        TestType::NetworkTest => &DIAGNOSTIC_INTERFACE_CAPABILITIES[3],
        TestType::PsuProbe => &DIAGNOSTIC_INTERFACE_CAPABILITIES[4],
        TestType::FpgaStatus => &DIAGNOSTIC_INTERFACE_CAPABILITIES[5],
        TestType::AsicCommTest => &DIAGNOSTIC_INTERFACE_CAPABILITIES[6],
        TestType::I2cScan => &DIAGNOSTIC_INTERFACE_CAPABILITIES[7],
    }
}

/// Persisted lifecycle state for a diagnostic job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Status snapshot for a diagnostic job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTest {
    /// Unique test identifier.
    pub test_id: Uuid,
    /// Type of test being run.
    pub test_type: TestType,
    /// Current lifecycle state.
    pub status: TestStatus,
    /// Human-readable phase name.
    pub phase_name: String,
    /// Progress percentage (0-100).
    pub progress_pct: u8,
    /// Most recent detail message.
    pub detail: String,
    /// Elapsed seconds at the latest update.
    pub elapsed_s: u64,
    /// Unix timestamp when the job was started.
    pub started_at_epoch_s: u64,
    /// Unix timestamp when the job finished, if complete.
    pub completed_at_epoch_s: Option<u64>,
    /// Final result payload, if complete.
    pub result: Option<TestResult>,
    /// Failure message, if the job failed.
    pub error: Option<String>,
    /// Cancellation token for early termination.
    #[serde(skip)]
    pub cancel_token: CancellationToken,
}

/// Completed test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Unique test identifier.
    pub test_id: Uuid,
    /// Type of test that was run.
    pub test_type: TestType,
    /// Duration of the test in seconds.
    pub duration_s: u64,
    /// Test result data (JSON).
    pub data: serde_json::Value,
    /// Overall grade (if applicable).
    pub grade: Option<String>,
    /// Warnings generated during the test.
    pub warnings: Vec<String>,
    /// Recommendations for the user.
    pub recommendations: Vec<String>,
}

/// Async injected snapshot/report finalizer invoked by a runtime job.
///
/// Report rendering/persistence may use a bounded blocking owner. Returning a
/// future keeps that work off the Tokio worker that drives diagnostic progress.
pub type FinalizeTestFuture = Pin<Box<dyn Future<Output = Result<TestResult>> + Send + 'static>>;
pub type FinalizeTestFn = Arc<dyn Fn(Uuid, u64) -> FinalizeTestFuture + Send + Sync + 'static>;

/// Runtime options for the first timed HashReport engine step.
pub struct HashReportJobConfig {
    /// Total timed mining window for the job.
    pub duration: Duration,
    /// How often progress updates should be emitted while timing runs.
    pub progress_interval: Duration,
    /// Finalizer that converts the finished job into a persisted report/result.
    pub finalize: FinalizeTestFn,
}

/// Prepared input for the synchronous ChipHealth snapshot publisher.
///
/// Its field and constructor remain private. Production publication is exposed
/// only through [`DiagnosticService::record_persisted_chip_health_snapshot`],
/// which preserves the already-persisted report identity and rejects drift.
pub struct ChipHealthJobConfig {
    snapshot: ChipHealthSnapshot,
}

impl ChipHealthJobConfig {
    #[cfg(test)]
    fn from_snapshot(snapshot: ChipHealthSnapshot) -> Self {
        Self { snapshot }
    }

    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        let mut snapshot = self.snapshot;
        snapshot.report_id = test_id;
        snapshot.report_type = "chip_health".to_string();
        let warnings = snapshot.warnings.clone();
        let recommendations = snapshot.recommendations.clone();
        let data = serde_json::to_value(snapshot).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize prepared ChipHealthSnapshot: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::ChipHealth,
            duration_s: 0,
            data,
            grade: None,
            warnings,
            recommendations,
        })
    }
}

/// Prepared input for the synchronous BoardHealth snapshot publisher.
///
/// Its field and constructor remain private. Production publication is exposed
/// only through [`DiagnosticService::record_persisted_board_health_snapshot`],
/// which binds the lifecycle record to the durable artifact identity.
pub struct BoardHealthJobConfig {
    boards: Vec<BoardHealthResult>,
}

/// Prepared input for the synchronous bounded network snapshot publisher.
///
/// The config carries no process, socket, sysfs, or hardware handle. The
/// production REST route completes its independently bounded probes first and
/// then submits only the validated observation value.
pub struct NetworkTestSnapshotJobConfig {
    snapshot: NetworkTestSnapshot,
}

impl NetworkTestSnapshotJobConfig {
    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        self.snapshot
            .validate()
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        let warnings = self.snapshot.publication_warnings();
        let data = serde_json::to_value(self.snapshot).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize bounded network snapshot: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::NetworkTest,
            duration_s: 0,
            data,
            grade: None,
            warnings,
            recommendations: Vec::new(),
        })
    }
}

impl BoardHealthJobConfig {
    #[cfg(test)]
    fn from_results(boards: Vec<BoardHealthResult>) -> Self {
        Self { boards }
    }

    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        let data = serde_json::to_value(self.boards).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize persisted BoardHealth results: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::BoardHealth,
            duration_s: 0,
            data,
            grade: None,
            warnings: Vec::new(),
            recommendations: Vec::new(),
        })
    }
}

/// Prepared input for the synchronous passive PSU snapshot publisher.
///
/// Production construction is exposed only through
/// [`DiagnosticService::publish_psu_probe_telemetry`]. Validation happens
/// before lifecycle insertion and the value carries no hardware handle.
pub struct PsuProbeSnapshotJobConfig {
    snapshot: PsuProbeSnapshot,
}

impl PsuProbeSnapshotJobConfig {
    #[cfg(test)]
    fn from_snapshot(snapshot: PsuProbeSnapshot) -> Self {
        Self { snapshot }
    }

    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        self.snapshot
            .validate()
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        let warnings = self.snapshot.publication_warnings();
        let data = serde_json::to_value(self.snapshot).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize passive PSU snapshot: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::PsuProbe,
            duration_s: 0,
            data,
            grade: None,
            warnings,
            recommendations: Vec::new(),
        })
    }
}

/// Prepared input for the synchronous passive FPGA snapshot publisher.
///
/// This records only caller-supplied, explicitly unattested values after the
/// service has evaluated their claimed capture time. It cannot open MMIO, UIO,
/// `/dev/mem`, or any other device path.
pub struct FpgaStatusSnapshotJobConfig {
    snapshot: FpgaStatusSnapshot,
}

/// Prepared input for the synchronous passive I2C observation publisher.
///
/// This carries only retained positive evidence. It has no request sender and
/// cannot scan, probe, infer absence, identify device models, or mutate a bus.
pub struct I2cScanSnapshotJobConfig {
    snapshot: I2cScanSnapshot,
}

impl I2cScanSnapshotJobConfig {
    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        self.snapshot
            .validate()
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        let warnings = self.snapshot.publication_warnings();
        let data = serde_json::to_value(self.snapshot).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize passive I2C observation snapshot: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::I2cScan,
            duration_s: 0,
            data,
            grade: None,
            warnings,
            recommendations: Vec::new(),
        })
    }
}

impl FpgaStatusSnapshotJobConfig {
    #[cfg(test)]
    fn from_snapshot(snapshot: FpgaStatusSnapshot) -> Self {
        Self { snapshot }
    }

    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        self.snapshot
            .validate()
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        let warnings = self.snapshot.publication_warnings();
        let data = serde_json::to_value(self.snapshot).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize passive FPGA snapshot: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::FpgaStatus,
            duration_s: 0,
            data,
            grade: None,
            warnings,
            recommendations: Vec::new(),
        })
    }
}

/// Prepared input for the synchronous passive ASIC-communication snapshot.
///
/// Production construction is exposed only through
/// [`DiagnosticService::publish_asic_comm_snapshot`]. The typed value is
/// validated before lifecycle insertion and carries no active probe result.
pub struct AsicCommSnapshotJobConfig {
    snapshot: AsicCommSnapshot,
}

impl AsicCommSnapshotJobConfig {
    #[cfg(test)]
    fn from_snapshot(snapshot: AsicCommSnapshot) -> Self {
        Self { snapshot }
    }

    fn into_result(self, test_id: Uuid) -> Result<TestResult> {
        self.snapshot
            .validate()
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        let data = serde_json::to_value(self.snapshot).map_err(|error| {
            DiagnosticError::ReportGeneration(format!(
                "cannot serialize passive ASIC communication snapshot: {error}"
            ))
        })?;
        Ok(TestResult {
            test_id,
            test_type: TestType::AsicCommTest,
            duration_s: 0,
            data,
            grade: None,
            warnings: Vec::new(),
            recommendations: Vec::new(),
        })
    }
}

/// Per-test start configuration.
pub enum DiagnosticJobConfig {
    HashReport(HashReportJobConfig),
    ChipHealth(ChipHealthJobConfig),
    BoardHealth(BoardHealthJobConfig),
    NetworkTest(NetworkTestSnapshotJobConfig),
    PsuProbe(PsuProbeSnapshotJobConfig),
    FpgaStatus(FpgaStatusSnapshotJobConfig),
    AsicCommTest(AsicCommSnapshotJobConfig),
    I2cScan(I2cScanSnapshotJobConfig),
}

impl DiagnosticJobConfig {
    /// Exact public test identity implemented by this configuration.
    pub const fn test_type(&self) -> TestType {
        match self {
            Self::HashReport(_) => TestType::HashReport,
            Self::ChipHealth(_) => TestType::ChipHealth,
            Self::BoardHealth(_) => TestType::BoardHealth,
            Self::NetworkTest(_) => TestType::NetworkTest,
            Self::PsuProbe(_) => TestType::PsuProbe,
            Self::FpgaStatus(_) => TestType::FpgaStatus,
            Self::AsicCommTest(_) => TestType::AsicCommTest,
            Self::I2cScan(_) => TestType::I2cScan,
        }
    }
}

enum PreparedDiagnosticJob {
    HashReport {
        config: HashReportJobConfig,
        runtime: tokio::runtime::Handle,
    },
    SynchronousSnapshot {
        result: TestResult,
    },
}

/// Top-level diagnostic service.
///
/// Manages the lifecycle of diagnostic tests, tracks active and completed
/// tests, and provides progress streaming.
pub struct DiagnosticService {
    /// Shared job store keyed by test_id.
    jobs: Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    /// Recently completed tests (ring buffer, max 10).
    completed_tests: Arc<Mutex<VecDeque<Uuid>>>,
    /// Maximum number of completed tests to keep.
    max_completed: usize,
    /// Broadcast sender for real-time progress updates.
    progress_tx: broadcast::Sender<DiagnosticProgress>,
}

impl DiagnosticService {
    /// Create a new diagnostic service.
    pub fn new(progress_tx: broadcast::Sender<DiagnosticProgress>) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            completed_tests: Arc::new(Mutex::new(VecDeque::with_capacity(10))),
            max_completed: 10,
            progress_tx,
        }
    }

    /// Start a new diagnostic test.
    ///
    /// Returns the test ID if started successfully, or an error if a test
    /// of the same type is already running.
    pub fn start_test(&mut self, test_type: TestType, config: DiagnosticJobConfig) -> Result<Uuid> {
        let configured_test_type = config.test_type();
        if configured_test_type != test_type {
            return Err(DiagnosticError::TestConfigMismatch {
                requested: test_type,
                configured: configured_test_type,
            });
        }
        self.start_test_with_id(Uuid::new_v4(), test_type, config)
    }

    /// Record lifecycle completion for a ChipHealth snapshot that the caller
    /// has already persisted durably.
    ///
    /// The canonical REST route persists and descriptor-readbacks the typed
    /// artifact before calling this method. The diagnostics crate cannot prove
    /// that external side effect itself, so it admits only the exact non-nil
    /// report identity and `chip_health` type carried by the persisted value.
    /// Publication is synchronous, callback-free, and grants no measurement,
    /// manufacturing, hardware-access, or mutation authority.
    pub fn record_persisted_chip_health_snapshot(
        &mut self,
        snapshot: ChipHealthSnapshot,
    ) -> Result<Uuid> {
        if snapshot.report_id.is_nil() {
            return Err(DiagnosticError::SnapshotAdmission {
                reason: "persisted ChipHealthSnapshot report_id is nil".to_string(),
            });
        }
        if snapshot.report_type != "chip_health" {
            return Err(DiagnosticError::SnapshotAdmission {
                reason: format!(
                    "persisted ChipHealthSnapshot report_type is {:?}, expected \"chip_health\"",
                    snapshot.report_type
                ),
            });
        }
        let test_id = snapshot.report_id;
        self.start_test_with_id(
            test_id,
            TestType::ChipHealth,
            DiagnosticJobConfig::ChipHealth(ChipHealthJobConfig { snapshot }),
        )
    }

    /// Record lifecycle completion for BoardHealth results that the caller has
    /// already persisted durably and descriptor-readback.
    ///
    /// The results retain their per-board, evidence-capped grades in `data`,
    /// while the outer diagnostic result remains ungraded. This method is
    /// synchronous and callback-free and confers no hardware or mutation
    /// authority.
    pub fn record_persisted_board_health_snapshot(
        &mut self,
        test_id: Uuid,
        boards: Vec<BoardHealthResult>,
    ) -> Result<Uuid> {
        if test_id.is_nil() {
            return Err(DiagnosticError::SnapshotAdmission {
                reason: "persisted BoardHealth report ID is nil".to_string(),
            });
        }
        self.start_test_with_id(
            test_id,
            TestType::BoardHealth,
            DiagnosticJobConfig::BoardHealth(BoardHealthJobConfig { boards }),
        )
    }

    /// Publish the bounded production route's network observations.
    ///
    /// The publisher samples its own wall clock, validates the supplied stage
    /// relationships, and records an ungraded synchronous result. It opens no
    /// process, socket, sysfs node, or hardware device; pool connectivity stays
    /// explicitly cached rather than becoming a live-connect claim.
    pub fn publish_network_test_telemetry(
        &mut self,
        telemetry: UnattestedNetworkTelemetry,
    ) -> Result<Uuid> {
        self.publish_network_test_telemetry_at(telemetry, unix_now_ms())
    }

    fn publish_network_test_telemetry_at(
        &mut self,
        telemetry: UnattestedNetworkTelemetry,
        publication_time_ms: u64,
    ) -> Result<Uuid> {
        let snapshot = NetworkTestSnapshot::from_unattested_at(telemetry, publication_time_ms)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::NetworkTest,
            DiagnosticJobConfig::NetworkTest(NetworkTestSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish caller-supplied, unattested PSU telemetry.
    ///
    /// The production boundary samples its own wall clock and re-evaluates the
    /// caller-supplied capture timestamp against the fixed freshness policy.
    /// It performs no hardware access and grants no health/pass authority.
    pub fn publish_psu_probe_telemetry(
        &mut self,
        telemetry: UnattestedPsuTelemetry,
    ) -> Result<Uuid> {
        self.publish_psu_probe_telemetry_at(telemetry, unix_now_ms())
    }

    fn publish_psu_probe_telemetry_at(
        &mut self,
        telemetry: UnattestedPsuTelemetry,
        publication_time_ms: u64,
    ) -> Result<Uuid> {
        let snapshot = PsuProbeSnapshot::from_unattested_at(telemetry, publication_time_ms)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::PsuProbe,
            DiagnosticJobConfig::PsuProbe(PsuProbeSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish an explicit PSU telemetry-unavailable snapshot.
    pub fn publish_psu_probe_unavailable(&mut self, reason: impl Into<String>) -> Result<Uuid> {
        let snapshot = PsuProbeSnapshot::try_unavailable(reason)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::PsuProbe,
            DiagnosticJobConfig::PsuProbe(PsuProbeSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish caller-supplied, unattested FPGA telemetry.
    ///
    /// The production boundary samples its own wall clock and re-evaluates the
    /// caller-supplied capture timestamp. It cannot open MMIO, UIO, `/dev/mem`,
    /// or any device path and grants no health/pass authority.
    pub fn publish_fpga_status_telemetry(
        &mut self,
        telemetry: UnattestedFpgaTelemetry,
    ) -> Result<Uuid> {
        self.publish_fpga_status_telemetry_at(telemetry, unix_now_ms())
    }

    fn publish_fpga_status_telemetry_at(
        &mut self,
        telemetry: UnattestedFpgaTelemetry,
        publication_time_ms: u64,
    ) -> Result<Uuid> {
        let snapshot = FpgaStatusSnapshot::from_unattested_at(telemetry, publication_time_ms)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::FpgaStatus,
            DiagnosticJobConfig::FpgaStatus(FpgaStatusSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish a source-owned FPGA snapshot retained by the mining runtime.
    ///
    /// The diagnostics boundary validates carrier-specific CTRL semantics and
    /// required status fields, then re-evaluates age using its own wall clock.
    /// It never opens MMIO/UIO/devmem and grants no measured-pass authority.
    pub fn publish_fpga_status_runtime_telemetry(
        &mut self,
        telemetry: RuntimeOwnedFpgaTelemetry,
    ) -> Result<Uuid> {
        self.publish_fpga_status_runtime_telemetry_at(telemetry, unix_now_ms())
    }

    fn publish_fpga_status_runtime_telemetry_at(
        &mut self,
        telemetry: RuntimeOwnedFpgaTelemetry,
        publication_time_ms: u64,
    ) -> Result<Uuid> {
        let snapshot = FpgaStatusSnapshot::from_runtime_owned_at(telemetry, publication_time_ms)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::FpgaStatus,
            DiagnosticJobConfig::FpgaStatus(FpgaStatusSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish an explicit FPGA telemetry-unavailable snapshot.
    pub fn publish_fpga_status_unavailable(&mut self, reason: impl Into<String>) -> Result<Uuid> {
        let snapshot = FpgaStatusSnapshot::try_unavailable(reason)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::FpgaStatus,
            DiagnosticJobConfig::FpgaStatus(FpgaStatusSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish a passive ASIC communication snapshot from retained telemetry.
    ///
    /// This synchronous path validates the typed aggregate and records a
    /// lifecycle result. It does not issue GetAddress, open a transport, or
    /// grant measured-pass, manufacturing, or mutation authority.
    pub fn publish_asic_comm_snapshot(&mut self, snapshot: AsicCommSnapshot) -> Result<Uuid> {
        self.start_test(
            TestType::AsicCommTest,
            DiagnosticJobConfig::AsicCommTest(AsicCommSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish retained positive endpoint observations from serialized I2C
    /// owners. The publisher performs no scan or bus access and grants no
    /// absence, device-identity, health/pass, or manufacturing authority.
    pub fn publish_i2c_runtime_telemetry(
        &mut self,
        telemetry: RuntimeOwnedI2cTelemetry,
    ) -> Result<Uuid> {
        self.publish_i2c_runtime_telemetry_at(telemetry, unix_now_ms())
    }

    fn publish_i2c_runtime_telemetry_at(
        &mut self,
        telemetry: RuntimeOwnedI2cTelemetry,
        publication_time_ms: u64,
    ) -> Result<Uuid> {
        let snapshot = I2cScanSnapshot::from_runtime_owned_at(telemetry, publication_time_ms)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::I2cScan,
            DiagnosticJobConfig::I2cScan(I2cScanSnapshotJobConfig { snapshot }),
        )
    }

    /// Publish explicit absence of retained positive I2C observations.
    pub fn publish_i2c_observations_unavailable(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<Uuid> {
        let snapshot = I2cScanSnapshot::try_unavailable(reason)
            .map_err(|reason| DiagnosticError::SnapshotAdmission { reason })?;
        self.start_test(
            TestType::I2cScan,
            DiagnosticJobConfig::I2cScan(I2cScanSnapshotJobConfig { snapshot }),
        )
    }

    fn start_test_with_id(
        &mut self,
        test_id: Uuid,
        test_type: TestType,
        config: DiagnosticJobConfig,
    ) -> Result<Uuid> {
        let configured_test_type = config.test_type();
        if configured_test_type != test_type {
            return Err(DiagnosticError::TestConfigMismatch {
                requested: test_type,
                configured: configured_test_type,
            });
        }

        let prepared = match config {
            DiagnosticJobConfig::HashReport(config) => {
                let runtime = tokio::runtime::Handle::try_current()
                    .map_err(|_| DiagnosticError::RuntimeUnavailable { test_type })?;
                PreparedDiagnosticJob::HashReport { config, runtime }
            }
            DiagnosticJobConfig::ChipHealth(config) => PreparedDiagnosticJob::SynchronousSnapshot {
                result: config.into_result(test_id)?,
            },
            DiagnosticJobConfig::BoardHealth(config) => {
                PreparedDiagnosticJob::SynchronousSnapshot {
                    result: config.into_result(test_id)?,
                }
            }
            DiagnosticJobConfig::NetworkTest(config) => {
                PreparedDiagnosticJob::SynchronousSnapshot {
                    result: config.into_result(test_id)?,
                }
            }
            DiagnosticJobConfig::PsuProbe(config) => PreparedDiagnosticJob::SynchronousSnapshot {
                result: config.into_result(test_id)?,
            },
            DiagnosticJobConfig::FpgaStatus(config) => PreparedDiagnosticJob::SynchronousSnapshot {
                result: config.into_result(test_id)?,
            },
            DiagnosticJobConfig::AsicCommTest(config) => {
                PreparedDiagnosticJob::SynchronousSnapshot {
                    result: config.into_result(test_id)?,
                }
            }
            DiagnosticJobConfig::I2cScan(config) => PreparedDiagnosticJob::SynchronousSnapshot {
                result: config.into_result(test_id)?,
            },
        };
        let cancel_token = CancellationToken::new();
        let started_at_epoch_s = unix_now_s();

        let terminal_progress = match &prepared {
            PreparedDiagnosticJob::SynchronousSnapshot { result } => Some(DiagnosticProgress::new(
                test_id,
                result.test_type,
                u8::MAX,
                "snapshot_published",
                100,
                0,
                0,
                "Diagnostic snapshot published; no health or pass verdict implied",
            )),
            PreparedDiagnosticJob::HashReport { .. } => None,
        };
        let mut completed_tests = if terminal_progress.is_some() {
            Some(
                self.completed_tests
                    .lock()
                    .map_err(|_| DiagnosticError::StateUnavailable)?,
            )
        } else {
            None
        };
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| DiagnosticError::StateUnavailable)?;
        if jobs.contains_key(&test_id) {
            return Err(DiagnosticError::TestIdAlreadyExists { test_id });
        }
        if jobs
            .values()
            .any(|test| test.test_type == test_type && test.status == TestStatus::Running)
        {
            return Err(DiagnosticError::TestAlreadyRunning {
                test_type: format!("{:?}", test_type),
            });
        }

        let stored = match (&prepared, terminal_progress.as_ref()) {
            (PreparedDiagnosticJob::HashReport { .. }, None) => StoredTest {
                test_id,
                test_type,
                status: TestStatus::Running,
                phase_name: "queued".to_string(),
                progress_pct: 0,
                detail: "Diagnostic job created".to_string(),
                elapsed_s: 0,
                started_at_epoch_s,
                completed_at_epoch_s: None,
                result: None,
                error: None,
                cancel_token: cancel_token.clone(),
            },
            (PreparedDiagnosticJob::SynchronousSnapshot { result }, Some(progress)) => StoredTest {
                test_id,
                test_type,
                status: TestStatus::Completed,
                phase_name: progress.phase_name.clone(),
                progress_pct: progress.progress_pct,
                detail: progress.detail.clone(),
                elapsed_s: progress.elapsed_s,
                started_at_epoch_s,
                completed_at_epoch_s: Some(started_at_epoch_s),
                result: Some(result.clone()),
                error: None,
                cancel_token: cancel_token.clone(),
            },
            _ => return Err(DiagnosticError::StateUnavailable),
        };
        jobs.insert(test_id, stored);

        if let Some(completed_tests) = completed_tests.as_mut() {
            completed_tests.push_back(test_id);
            if completed_tests.len() > self.max_completed {
                if let Some(oldest_id) = completed_tests.pop_front() {
                    jobs.remove(&oldest_id);
                }
            }
        }
        drop(jobs);
        drop(completed_tests);

        match prepared {
            PreparedDiagnosticJob::HashReport { config, runtime } => {
                let jobs = Arc::clone(&self.jobs);
                let completed_tests = Arc::clone(&self.completed_tests);
                let progress_tx = self.progress_tx.clone();
                let max_completed = self.max_completed;
                runtime.spawn(async move {
                    run_hashreport_job(
                        test_id,
                        config,
                        progress_tx,
                        jobs,
                        completed_tests,
                        max_completed,
                        cancel_token,
                    )
                    .await;
                });
            }
            PreparedDiagnosticJob::SynchronousSnapshot { .. } => {
                if let Some(progress) = terminal_progress {
                    let _ = self.progress_tx.send(progress);
                }
            }
        }

        Ok(test_id)
    }

    /// Get the status of a running test.
    pub fn get_test_status(&self, test_id: &Uuid) -> Option<StoredTest> {
        self.jobs.lock().ok()?.get(test_id).cloned()
    }

    /// Get a completed test result.
    pub fn get_result(&self, test_id: &Uuid) -> Option<TestResult> {
        self.jobs.lock().ok()?.get(test_id)?.result.clone()
    }

    /// Cancel a running test.
    pub fn cancel_test(&mut self, test_id: &Uuid) -> bool {
        let Some(cancel_token) = self.jobs.lock().ok().and_then(|jobs| {
            jobs.get(test_id).and_then(|test| {
                (test.status == TestStatus::Running).then(|| test.cancel_token.clone())
            })
        }) else {
            return false;
        };

        cancel_token.cancel();
        true
    }
}

impl Default for DiagnosticService {
    fn default() -> Self {
        let (progress_tx, _) = broadcast::channel(32);
        Self::new(progress_tx)
    }
}

async fn run_hashreport_job(
    test_id: Uuid,
    config: HashReportJobConfig,
    progress_tx: broadcast::Sender<DiagnosticProgress>,
    jobs: Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    completed_tests: Arc<Mutex<VecDeque<Uuid>>>,
    max_completed: usize,
    cancel_token: CancellationToken,
) {
    let mut tracker = ProgressTracker::new(test_id, TestType::HashReport, 5, progress_tx);

    tracker.next_phase(
        "system_identification",
        "Capturing miner identity and runtime topology",
    );
    update_job_progress(
        &jobs,
        test_id,
        &DiagnosticProgress::new(
            test_id,
            TestType::HashReport,
            1,
            "system_identification",
            5,
            0,
            config.duration.as_secs(),
            "Capturing miner identity and runtime topology",
        ),
    );
    if wait_or_cancel(Duration::from_secs(1), &cancel_token).await {
        tracker.cancel();
        mark_job_cancelled(
            &jobs,
            &completed_tests,
            test_id,
            max_completed,
            tracker.elapsed_s(),
        );
        return;
    }

    tracker.next_phase(
        "baseline_capture",
        "Recording baseline temps, fans, and errors",
    );
    update_job_progress(
        &jobs,
        test_id,
        &DiagnosticProgress::new(
            test_id,
            TestType::HashReport,
            2,
            "baseline_capture",
            10,
            tracker.elapsed_s(),
            config.duration.as_secs(),
            "Recording baseline temps, fans, and errors",
        ),
    );
    if wait_or_cancel(Duration::from_secs(1), &cancel_token).await {
        tracker.cancel();
        mark_job_cancelled(
            &jobs,
            &completed_tests,
            test_id,
            max_completed,
            tracker.elapsed_s(),
        );
        return;
    }

    tracker.next_phase(
        "mining_performance",
        "Timed mining observation is in progress",
    );
    let mining_start = Instant::now();
    while mining_start.elapsed() < config.duration {
        if cancel_token.is_cancelled() {
            tracker.cancel();
            mark_job_cancelled(
                &jobs,
                &completed_tests,
                test_id,
                max_completed,
                tracker.elapsed_s(),
            );
            return;
        }

        let elapsed_window_s = mining_start.elapsed().as_secs();
        let total_window_s = config.duration.as_secs().max(1);
        let mining_pct = ((elapsed_window_s.saturating_mul(80)) / total_window_s).min(80) as u8;
        let overall_pct = 10u8.saturating_add(mining_pct);
        let remaining_s = total_window_s.saturating_sub(elapsed_window_s);
        let detail = format!(
            "Timed observation {}/{}s complete; final report will be generated from runtime state at the end of the window",
            elapsed_window_s.min(total_window_s),
            total_window_s
        );
        tracker.update(overall_pct, detail.clone());
        update_job_progress(
            &jobs,
            test_id,
            &DiagnosticProgress::new(
                test_id,
                TestType::HashReport,
                3,
                "mining_performance",
                overall_pct,
                tracker.elapsed_s(),
                remaining_s,
                detail,
            ),
        );

        if wait_or_cancel(config.progress_interval, &cancel_token).await {
            tracker.cancel();
            mark_job_cancelled(
                &jobs,
                &completed_tests,
                test_id,
                max_completed,
                tracker.elapsed_s(),
            );
            return;
        }
    }

    tracker.next_phase(
        "chip_health_scoring",
        "Summarizing timed observations into per-board health output",
    );
    update_job_progress(
        &jobs,
        test_id,
        &DiagnosticProgress::new(
            test_id,
            TestType::HashReport,
            4,
            "chip_health_scoring",
            92,
            tracker.elapsed_s(),
            1,
            "Summarizing timed observations into per-board health output",
        ),
    );
    if wait_or_cancel(Duration::from_secs(1), &cancel_token).await {
        tracker.cancel();
        mark_job_cancelled(
            &jobs,
            &completed_tests,
            test_id,
            max_completed,
            tracker.elapsed_s(),
        );
        return;
    }

    tracker.next_phase("report_generation", "Persisting final diagnostic artifacts");
    update_job_progress(
        &jobs,
        test_id,
        &DiagnosticProgress::new(
            test_id,
            TestType::HashReport,
            5,
            "report_generation",
            97,
            tracker.elapsed_s(),
            0,
            "Persisting final diagnostic artifacts",
        ),
    );

    match (config.finalize)(test_id, tracker.elapsed_s()).await {
        Ok(result) => {
            tracker.complete();
            mark_job_completed(
                &jobs,
                &completed_tests,
                test_id,
                result,
                max_completed,
                tracker.elapsed_s(),
            );
        }
        Err(error) => {
            tracker.fail(error.to_string());
            mark_job_failed(
                &jobs,
                &completed_tests,
                test_id,
                error.to_string(),
                max_completed,
                tracker.elapsed_s(),
            );
        }
    }
}

async fn wait_or_cancel(duration: Duration, cancel_token: &CancellationToken) -> bool {
    tokio::select! {
        _ = cancel_token.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

fn update_job_progress(
    jobs: &Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    test_id: Uuid,
    progress: &DiagnosticProgress,
) {
    if let Ok(mut jobs) = jobs.lock() {
        if let Some(job) = jobs.get_mut(&test_id) {
            job.phase_name = progress.phase_name.clone();
            job.progress_pct = progress.progress_pct;
            job.detail = progress.detail.clone();
            job.elapsed_s = progress.elapsed_s;
        }
    }
}

fn mark_job_completed(
    jobs: &Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    completed_tests: &Arc<Mutex<VecDeque<Uuid>>>,
    test_id: Uuid,
    result: TestResult,
    max_completed: usize,
    elapsed_s: u64,
) {
    if let Ok(mut jobs) = jobs.lock() {
        if let Some(job) = jobs.get_mut(&test_id) {
            job.status = TestStatus::Completed;
            job.phase_name = "completed".to_string();
            job.progress_pct = 100;
            job.detail = "Test completed successfully".to_string();
            job.elapsed_s = elapsed_s;
            job.completed_at_epoch_s = Some(unix_now_s());
            job.result = Some(result);
            job.error = None;
        }
    }
    push_completed_test(jobs, completed_tests, test_id, max_completed);
}

fn mark_job_failed(
    jobs: &Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    completed_tests: &Arc<Mutex<VecDeque<Uuid>>>,
    test_id: Uuid,
    error: String,
    max_completed: usize,
    elapsed_s: u64,
) {
    if let Ok(mut jobs) = jobs.lock() {
        if let Some(job) = jobs.get_mut(&test_id) {
            job.status = TestStatus::Failed;
            job.phase_name = "failed".to_string();
            job.progress_pct = 0;
            job.detail = error.clone();
            job.elapsed_s = elapsed_s;
            job.completed_at_epoch_s = Some(unix_now_s());
            job.result = None;
            job.error = Some(error);
        }
    }
    push_completed_test(jobs, completed_tests, test_id, max_completed);
}

fn mark_job_cancelled(
    jobs: &Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    completed_tests: &Arc<Mutex<VecDeque<Uuid>>>,
    test_id: Uuid,
    max_completed: usize,
    elapsed_s: u64,
) {
    if let Ok(mut jobs) = jobs.lock() {
        if let Some(job) = jobs.get_mut(&test_id) {
            job.status = TestStatus::Cancelled;
            job.phase_name = "cancelled".to_string();
            job.progress_pct = 0;
            job.detail = "Test cancelled by user".to_string();
            job.elapsed_s = elapsed_s;
            job.completed_at_epoch_s = Some(unix_now_s());
            job.result = None;
            job.error = None;
        }
    }
    push_completed_test(jobs, completed_tests, test_id, max_completed);
}

fn push_completed_test(
    jobs: &Arc<Mutex<HashMap<Uuid, StoredTest>>>,
    completed_tests: &Arc<Mutex<VecDeque<Uuid>>>,
    test_id: Uuid,
    max_completed: usize,
) {
    let evicted = if let Ok(mut completed) = completed_tests.lock() {
        completed.push_back(test_id);
        if completed.len() > max_completed {
            completed.pop_front()
        } else {
            None
        }
    } else {
        None
    };

    if let Some(oldest_id) = evicted {
        if let Ok(mut jobs) = jobs.lock() {
            jobs.remove(&oldest_id);
        }
    }
}

fn unix_now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn diagnostic_interface_capability_ceiling_is_exhaustive() {
        assert_eq!(DIAGNOSTIC_INTERFACE_CAPABILITIES.len(), TestType::ALL.len());
        for test_type in TestType::ALL {
            let matches: Vec<_> = DIAGNOSTIC_INTERFACE_CAPABILITIES
                .iter()
                .filter(|capability| capability.test_type == test_type)
                .collect();
            assert_eq!(matches.len(), 1);
            let capability = matches[0];
            assert_eq!(
                *capability,
                *diagnostic_interface_capability(test_type),
                "compiler-exhaustive resolver and canonical table drifted"
            );
            assert_eq!(
                capability.runtime_job_engine_implemented,
                matches!(
                    test_type,
                    TestType::HashReport
                        | TestType::ChipHealth
                        | TestType::BoardHealth
                        | TestType::NetworkTest
                        | TestType::PsuProbe
                        | TestType::FpgaStatus
                        | TestType::AsicCommTest
                        | TestType::I2cScan
                )
            );
            assert_eq!(
                capability.production_route_integrated,
                matches!(
                    test_type,
                    TestType::HashReport
                        | TestType::ChipHealth
                        | TestType::BoardHealth
                        | TestType::NetworkTest
                        | TestType::PsuProbe
                        | TestType::FpgaStatus
                        | TestType::AsicCommTest
                        | TestType::I2cScan
                )
            );
            assert!(!capability.typed_measured_pass_authorized);
            assert!(!capability.manufacturing_grade_authorized);
            assert!(!capability.hardware_mutation_authorized);
        }
    }

    fn prepared_snapshot() -> ChipHealthSnapshot {
        ChipHealthSnapshot {
            report_id: Uuid::new_v4(),
            generated_at: "2026-08-09T00:00:00Z".to_string(),
            report_type: "untrusted-fixture-type".to_string(),
            source: "prepared-test-snapshot".to_string(),
            total_boards: 0,
            total_chips: 0,
            warnings: vec!["snapshot warning".to_string()],
            recommendations: vec!["snapshot recommendation".to_string()],
            chains: Vec::new(),
        }
    }

    fn passive_asic_comm_snapshot() -> AsicCommSnapshot {
        AsicCommSnapshot::from_chains(vec![
            crate::troubleshoot::AsicCommChainSnapshot {
                chain_id: 6,
                responding_chips: 63,
                comm_ok: true,
                crc_errors: 2,
                status: "Alive".to_string(),
            },
            crate::troubleshoot::AsicCommChainSnapshot {
                chain_id: 7,
                responding_chips: 0,
                comm_ok: false,
                crc_errors: 9,
                status: "Degraded".to_string(),
            },
        ])
    }

    fn unattested_psu_telemetry(
        captured_at_ms: u64,
    ) -> crate::troubleshoot::UnattestedPsuTelemetry {
        crate::troubleshoot::UnattestedPsuTelemetry {
            telemetry_source: "caller-labelled-power-watch".to_string(),
            captured_at_ms,
            detected: Some(true),
            vin_v: Some(240.5),
            vout_v: Some(12.4),
            iout_a: Some(82.0),
            board_power_w: Some(1_016.8),
            wall_power_w: Some(1_075.0),
            efficiency_pct: Some(94.6),
            temp_c: Some(49.0),
            fan_rpm: None,
            faults: Some(Vec::new()),
            status_word: Some(0),
            calibrated: Some(false),
        }
    }

    fn network_stage(
        status: crate::troubleshoot::NetworkProbeStatus,
    ) -> crate::troubleshoot::NetworkProbeStageTelemetry {
        crate::troubleshoot::NetworkProbeStageTelemetry {
            status,
            detail: None,
        }
    }

    fn unattested_network_telemetry(
        captured_at_ms: u64,
    ) -> crate::troubleshoot::UnattestedNetworkTelemetry {
        crate::troubleshoot::UnattestedNetworkTelemetry {
            telemetry_source: "bounded-rest-network-route".to_string(),
            captured_at_ms,
            interface: Some("eth0".to_string()),
            ip_cidr: Some("192.0.2.10/24".to_string()),
            ip_address: Some("192.0.2.10".to_string()),
            mac: Some("02:00:00:00:00:10".to_string()),
            link_up: Some(true),
            gateway: Some("192.0.2.1".to_string()),
            gateway_reachable: Some(true),
            dns_test_host: Some("pool.example.com".to_string()),
            dns_ok: Some(true),
            cached_pool_status: Some("Alive".to_string()),
            cached_pool_connected: true,
            ip_address_probe: network_stage(crate::troubleshoot::NetworkProbeStatus::Ok),
            route_probe: network_stage(crate::troubleshoot::NetworkProbeStatus::Ok),
            gateway_probe: network_stage(crate::troubleshoot::NetworkProbeStatus::Ok),
            dns_probe: network_stage(crate::troubleshoot::NetworkProbeStatus::Ok),
        }
    }

    fn unattested_fpga_chain(chain_id: u8) -> crate::troubleshoot::UnattestedFpgaChainTelemetry {
        crate::troubleshoot::UnattestedFpgaChainTelemetry {
            chain_id,
            register_layout: None,
            identity_word: None,
            version: Some("0x00901002".to_string()),
            build_id: None,
            ctrl_reg: Some(0x0d),
            enabled: Some(true),
            bm139x_mode: None,
            baud_reg: Some(7),
            baud_rate: Some(1_562_500),
            work_time: None,
            error_count: Some(3),
            cmd_tx_empty: None,
            cmd_rx_empty: None,
            work_tx_empty: None,
            work_rx_empty: None,
        }
    }

    fn runtime_owned_fpga_telemetry(
        captured_at_ms: u64,
    ) -> crate::troubleshoot::RuntimeOwnedFpgaTelemetry {
        crate::troubleshoot::RuntimeOwnedFpgaTelemetry {
            telemetry_source: "standard WorkDispatcher retained FPGA register snapshot".to_string(),
            captured_at_ms,
            chains: vec![crate::troubleshoot::UnattestedFpgaChainTelemetry {
                chain_id: 6,
                register_layout: Some(crate::troubleshoot::FpgaRegisterLayout::Am1S9),
                identity_word: Some(0x0090_1002),
                version: Some("0x00901002".to_string()),
                build_id: Some(0x6500_0000),
                ctrl_reg: Some(0x18),
                enabled: Some(true),
                bm139x_mode: Some(true),
                baud_reg: Some(7),
                baud_rate: Some(1_562_500),
                work_time: Some(0x0004_0507),
                error_count: Some(0),
                cmd_tx_empty: Some(true),
                cmd_rx_empty: Some(true),
                work_tx_empty: Some(false),
                work_rx_empty: Some(true),
            }],
        }
    }

    fn runtime_owned_i2c_telemetry(
        captured_at_ms: u64,
    ) -> crate::troubleshoot::RuntimeOwnedI2cTelemetry {
        use crate::troubleshoot::{
            I2cObservedEndpointRole as Role, I2cObservedOperationKind as Operation,
            RuntimeOwnedI2cEndpointObservation,
        };

        crate::troubleshoot::RuntimeOwnedI2cTelemetry {
            telemetry_source: "serialized-owner-test-ledger".to_string(),
            captured_at_ms,
            endpoints: vec![
                RuntimeOwnedI2cEndpointObservation {
                    bus: 0,
                    address: 0x50,
                    operation: Operation::HashboardEepromRead,
                    endpoint_role: Role::HashboardEepromEndpoint,
                    observed_at_ms: captured_at_ms.saturating_sub(10),
                    successful_operation_count: 1,
                },
                RuntimeOwnedI2cEndpointObservation {
                    bus: 0,
                    address: 0x55,
                    operation: Operation::PicHeartbeat,
                    endpoint_role: Role::ControllerProtocolEndpoint,
                    observed_at_ms: captured_at_ms,
                    successful_operation_count: 7,
                },
            ],
        }
    }

    fn runtime_owned_am2_fpga_telemetry(
        captured_at_ms: u64,
    ) -> crate::troubleshoot::RuntimeOwnedFpgaTelemetry {
        let mut telemetry = runtime_owned_fpga_telemetry(captured_at_ms);
        let chain = &mut telemetry.chains[0];
        chain.chain_id = 1;
        chain.register_layout = Some(crate::troubleshoot::FpgaRegisterLayout::Am2);
        chain.identity_word = chain.build_id;
        chain.version = None;
        chain.ctrl_reg = Some(0x0090_1002);
        chain.enabled = Some(true);
        chain.bm139x_mode = None;
        chain.baud_rate = None;
        chain.work_time = None;
        chain.error_count = None;
        telemetry
    }

    fn unattested_fpga_telemetry(
        captured_at_ms: u64,
        chains: Vec<crate::troubleshoot::UnattestedFpgaChainTelemetry>,
    ) -> crate::troubleshoot::UnattestedFpgaTelemetry {
        crate::troubleshoot::UnattestedFpgaTelemetry {
            telemetry_source: "caller-labelled-fpga-watch".to_string(),
            captured_at_ms,
            chains,
        }
    }

    #[test]
    fn job_config_admission_is_exact_in_both_directions() {
        let (progress_tx, _progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);
        let hashreport_config = DiagnosticJobConfig::HashReport(HashReportJobConfig {
            duration: Duration::from_secs(1),
            progress_interval: Duration::from_secs(1),
            finalize: Arc::new(|_, _| Box::pin(async { unreachable!("mismatch must refuse") })),
        });

        let error = service
            .start_test(TestType::BoardHealth, hashreport_config)
            .expect_err("a declared-no-engine TestType must not borrow HashReport");
        assert!(matches!(
            error,
            DiagnosticError::TestConfigMismatch {
                requested: TestType::BoardHealth,
                configured: TestType::HashReport,
            }
        ));

        let chip_health_config = DiagnosticJobConfig::ChipHealth(
            ChipHealthJobConfig::from_snapshot(prepared_snapshot()),
        );
        let error = service
            .start_test(TestType::HashReport, chip_health_config)
            .expect_err("HashReport must not borrow ChipHealth snapshot configuration");
        assert!(matches!(
            error,
            DiagnosticError::TestConfigMismatch {
                requested: TestType::HashReport,
                configured: TestType::ChipHealth,
            }
        ));

        let board_health_config =
            DiagnosticJobConfig::BoardHealth(BoardHealthJobConfig::from_results(Vec::new()));
        let error = service
            .start_test(TestType::ChipHealth, board_health_config)
            .expect_err("ChipHealth must not borrow BoardHealth snapshot configuration");
        assert!(matches!(
            error,
            DiagnosticError::TestConfigMismatch {
                requested: TestType::ChipHealth,
                configured: TestType::BoardHealth,
            }
        ));

        let psu_snapshot =
            PsuProbeSnapshot::from_unattested_at(unattested_psu_telemetry(1_000), 1_100)
                .expect("valid unattested PSU fixture");
        let error = service
            .start_test(
                TestType::FpgaStatus,
                DiagnosticJobConfig::PsuProbe(PsuProbeSnapshotJobConfig::from_snapshot(
                    psu_snapshot,
                )),
            )
            .expect_err("FPGA status must not borrow passive PSU telemetry configuration");
        assert!(matches!(
            error,
            DiagnosticError::TestConfigMismatch {
                requested: TestType::FpgaStatus,
                configured: TestType::PsuProbe,
            }
        ));

        let fpga_snapshot = FpgaStatusSnapshot::from_unattested_at(
            unattested_fpga_telemetry(1_000, vec![unattested_fpga_chain(6)]),
            1_100,
        )
        .expect("valid unattested FPGA fixture");
        let error = service
            .start_test(
                TestType::PsuProbe,
                DiagnosticJobConfig::FpgaStatus(FpgaStatusSnapshotJobConfig::from_snapshot(
                    fpga_snapshot,
                )),
            )
            .expect_err("PSU probe must not borrow passive FPGA telemetry configuration");
        assert!(matches!(
            error,
            DiagnosticError::TestConfigMismatch {
                requested: TestType::PsuProbe,
                configured: TestType::FpgaStatus,
            }
        ));

        let asic_comm_config = DiagnosticJobConfig::AsicCommTest(
            AsicCommSnapshotJobConfig::from_snapshot(passive_asic_comm_snapshot()),
        );
        let error = service
            .start_test(TestType::BoardHealth, asic_comm_config)
            .expect_err("BoardHealth must not borrow passive ASIC telemetry configuration");
        assert!(matches!(
            error,
            DiagnosticError::TestConfigMismatch {
                requested: TestType::BoardHealth,
                configured: TestType::AsicCommTest,
            }
        ));
    }

    #[test]
    fn prepared_chip_health_snapshot_publishes_synchronously_without_runtime() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let snapshot = prepared_snapshot();
        let mut expected_snapshot = snapshot.clone();
        let expected_warnings = snapshot.warnings.clone();
        let expected_recommendations = snapshot.recommendations.clone();
        let config = DiagnosticJobConfig::ChipHealth(ChipHealthJobConfig::from_snapshot(snapshot));

        let test_id = service
            .start_test(TestType::ChipHealth, config)
            .expect("prepared snapshot publication needs no Tokio runtime");
        expected_snapshot.report_id = test_id;
        expected_snapshot.report_type = "chip_health".to_string();
        let expected_data =
            serde_json::to_value(&expected_snapshot).expect("fixture must serialize");
        let stored = service
            .get_test_status(&test_id)
            .expect("synchronous publication must be immediately visible");
        let progress = progress_rx
            .try_recv()
            .expect("publisher must emit one canonical completion event");

        assert_eq!(stored.status, TestStatus::Completed);
        assert_eq!(stored.phase_name, progress.phase_name);
        assert_eq!(stored.progress_pct, progress.progress_pct);
        assert_eq!(stored.detail, progress.detail);
        assert_eq!(stored.elapsed_s, progress.elapsed_s);
        assert_eq!(progress.test_id, test_id);
        assert_eq!(progress.test_type, TestType::ChipHealth);
        assert_eq!(progress.phase_name, "snapshot_published");
        assert_eq!(
            progress.detail,
            "Diagnostic snapshot published; no health or pass verdict implied"
        );
        assert_eq!(progress.progress_pct, 100);
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let result = stored
            .result
            .expect("completed publication must retain a result");
        assert_eq!(result.test_id, test_id);
        assert_eq!(result.test_type, TestType::ChipHealth);
        assert_eq!(result.duration_s, 0);
        assert_eq!(result.data, expected_data);
        assert_eq!(result.data["report_id"], test_id.to_string());
        assert_eq!(result.data["report_type"], "chip_health");
        assert_eq!(result.warnings, expected_warnings);
        assert_eq!(result.recommendations, expected_recommendations);
        assert!(
            result.grade.is_none(),
            "prepared snapshots can never mint a top-level diagnostic grade"
        );
        assert!(
            !service.cancel_test(&test_id),
            "terminal publication is not cancellable"
        );

        let capability = diagnostic_interface_capability(TestType::ChipHealth);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::PersistedSnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.typed_measured_pass_authorized);
        assert!(!capability.manufacturing_grade_authorized);
        assert!(!capability.hardware_mutation_authorized);
    }

    #[test]
    fn persisted_chip_health_snapshot_keeps_exact_identity_and_refuses_replay_or_type_drift() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let mut snapshot = prepared_snapshot();
        snapshot.report_type = "chip_health".to_string();
        let expected = snapshot.clone();

        let test_id = service
            .record_persisted_chip_health_snapshot(snapshot)
            .expect("persisted typed snapshot must publish under its exact identity");
        assert_eq!(test_id, expected.report_id);
        let result = service
            .get_result(&test_id)
            .expect("persisted publication must retain its result");
        assert_eq!(result.data, serde_json::to_value(expected).unwrap());
        assert_eq!(progress_rx.try_recv().unwrap().test_id, test_id);

        let replay = serde_json::from_value(result.data.clone()).unwrap();
        let error = service
            .record_persisted_chip_health_snapshot(replay)
            .expect_err("an existing persisted lifecycle identity must not be overwritten");
        assert!(matches!(
            error,
            DiagnosticError::TestIdAlreadyExists { test_id: duplicate } if duplicate == test_id
        ));
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let mut wrong_type = prepared_snapshot();
        wrong_type.report_type = "hashreport".to_string();
        let error = service
            .record_persisted_chip_health_snapshot(wrong_type)
            .expect_err("persisted report-type drift must fail before insertion");
        assert!(matches!(error, DiagnosticError::SnapshotAdmission { .. }));

        let mut nil_id = prepared_snapshot();
        nil_id.report_id = Uuid::nil();
        nil_id.report_type = "chip_health".to_string();
        let error = service
            .record_persisted_chip_health_snapshot(nil_id)
            .expect_err("nil persisted report identities must fail before insertion");
        assert!(matches!(error, DiagnosticError::SnapshotAdmission { .. }));
    }

    #[test]
    fn persisted_board_health_results_publish_synchronously_ungraded_and_refuse_replay() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let test_id = Uuid::new_v4();

        let published = service
            .record_persisted_board_health_snapshot(test_id, Vec::new())
            .expect("persisted typed BoardHealth results must publish synchronously");
        assert_eq!(published, test_id);
        let stored = service
            .get_test_status(&test_id)
            .expect("BoardHealth publication must be immediately visible");
        assert_eq!(stored.status, TestStatus::Completed);
        let result = stored.result.expect("BoardHealth result must be retained");
        assert_eq!(result.test_type, TestType::BoardHealth);
        assert_eq!(result.duration_s, 0);
        assert_eq!(result.data, serde_json::json!([]));
        assert!(result.grade.is_none());
        assert!(result.warnings.is_empty());
        assert!(result.recommendations.is_empty());
        let progress = progress_rx.try_recv().unwrap();
        assert_eq!(progress.test_id, test_id);
        assert_eq!(progress.test_type, TestType::BoardHealth);
        assert_eq!(progress.progress_pct, 100);

        let error = service
            .record_persisted_board_health_snapshot(test_id, Vec::new())
            .expect_err("an existing BoardHealth lifecycle identity must not be overwritten");
        assert!(matches!(
            error,
            DiagnosticError::TestIdAlreadyExists { test_id: duplicate } if duplicate == test_id
        ));
        let error = service
            .record_persisted_board_health_snapshot(Uuid::nil(), Vec::new())
            .expect_err("nil persisted BoardHealth identities must fail before insertion");
        assert!(matches!(error, DiagnosticError::SnapshotAdmission { .. }));
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let capability = diagnostic_interface_capability(TestType::BoardHealth);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::PersistedSnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.typed_measured_pass_authorized);
        assert!(!capability.manufacturing_grade_authorized);
        assert!(!capability.hardware_mutation_authorized);
    }

    #[test]
    fn bounded_network_publication_is_typed_ungraded_and_pool_cached() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let test_id = service
            .publish_network_test_telemetry_at(unattested_network_telemetry(10_000), 10_125)
            .expect("valid bounded network observation");
        let result = service
            .get_result(&test_id)
            .expect("published network result");

        assert_eq!(result.test_type, TestType::NetworkTest);
        assert_eq!(result.data["source"], NetworkTestSnapshot::SOURCE);
        assert_eq!(result.data["provenance"], "caller_supplied_unattested");
        assert_eq!(result.data["freshness"]["availability"], "fresh_unattested");
        assert_eq!(result.data["freshness"]["age_ms"], 125);
        assert_eq!(result.data["interface"], "eth0");
        assert_eq!(result.data["gateway_reachable"], true);
        assert_eq!(result.data["dns_ok"], true);
        assert_eq!(result.data["cached_pool_connected"], true);
        assert_eq!(
            result.data["pool_connectivity_source"],
            NetworkTestSnapshot::POOL_CONNECTIVITY_SOURCE
        );
        assert_eq!(result.data["live_pool_probe_performed"], false);
        assert!(result.grade.is_none());
        assert_eq!(result.warnings.len(), 2);
        assert!(result.warnings[0].contains("not a miner health or pass verdict"));
        assert!(result.warnings[1].contains("cached runtime state"));

        let progress = progress_rx.try_recv().expect("network publication event");
        assert_eq!(progress.test_type, TestType::NetworkTest);
        assert_eq!(progress.phase_name, "snapshot_published");
        assert!(!progress.detail.contains("success"));

        let capability = diagnostic_interface_capability(TestType::NetworkTest);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.typed_measured_pass_authorized);
        assert!(!capability.manufacturing_grade_authorized);
        assert!(!capability.hardware_mutation_authorized);
    }

    #[test]
    fn bounded_network_publication_refuses_inconsistent_or_unbounded_values() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);

        let mut inconsistent_gateway = unattested_network_telemetry(1_000);
        inconsistent_gateway.gateway_reachable = Some(false);
        assert!(service
            .publish_network_test_telemetry_at(inconsistent_gateway, 1_100)
            .is_err());

        let mut invalid_mac = unattested_network_telemetry(1_000);
        invalid_mac.mac = Some("not-a-mac".to_string());
        assert!(service
            .publish_network_test_telemetry_at(invalid_mac, 1_100)
            .is_err());

        let mut unbound_connected = unattested_network_telemetry(1_000);
        unbound_connected.cached_pool_status = None;
        assert!(service
            .publish_network_test_telemetry_at(unbound_connected, 1_100)
            .is_err());

        assert!(service
            .publish_network_test_telemetry_at(unattested_network_telemetry(2_000), 1_999)
            .is_err());
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn passive_psu_publication_rechecks_age_and_marks_values_unattested() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let mut telemetry = unattested_psu_telemetry(10_000);
        telemetry.vin_v = None;
        telemetry.iout_a = None;
        telemetry.temp_c = None;
        telemetry.status_word = None;

        let test_id = service
            .publish_psu_probe_telemetry_at(telemetry, 10_250)
            .expect("publication boundary should classify the supplied timestamp");
        let result = service.get_result(&test_id).expect("published PSU result");
        assert_eq!(result.test_type, TestType::PsuProbe);
        assert_eq!(result.data["source"], PsuProbeSnapshot::SOURCE);
        assert_eq!(result.data["provenance"], "caller_supplied_unattested");
        assert_eq!(result.data["freshness"]["availability"], "fresh_unattested");
        assert_eq!(result.data["freshness"]["captured_at_ms"], 10_000);
        assert_eq!(result.data["freshness"]["evaluated_at_ms"], 10_250);
        assert_eq!(result.data["freshness"]["age_ms"], 250);
        assert_eq!(
            result.data["freshness"]["stale_after_ms"],
            crate::troubleshoot::PASSIVE_TELEMETRY_STALE_AFTER_MS
        );
        assert!(result.data["vin_v"].is_null());
        assert!(result.data["iout_a"].is_null());
        assert!(result.data["temp_c"].is_null());
        assert!(result.data["status_word"].is_null());
        assert!(result.grade.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("caller-supplied and unattested"));

        let progress = progress_rx.try_recv().expect("neutral publication event");
        assert_eq!(progress.test_type, TestType::PsuProbe);
        assert_eq!(progress.phase_name, "snapshot_published");
        assert_eq!(
            progress.detail,
            "Diagnostic snapshot published; no health or pass verdict implied"
        );

        let before_publication = unix_now_ms();
        let old_capture = before_publication
            .saturating_sub(crate::troubleshoot::PASSIVE_TELEMETRY_STALE_AFTER_MS + 1_000);
        let production_id = service
            .publish_psu_probe_telemetry(unattested_psu_telemetry(old_capture))
            .expect("production method should use its own publication clock");
        let production = service
            .get_result(&production_id)
            .expect("production result");
        assert_eq!(
            production.data["freshness"]["availability"],
            "stale_unattested"
        );
        assert!(production.data["freshness"]["evaluated_at_ms"]
            .as_u64()
            .is_some_and(|evaluated| evaluated >= before_publication));

        let capability = diagnostic_interface_capability(TestType::PsuProbe);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.typed_measured_pass_authorized);
        assert!(!capability.manufacturing_grade_authorized);
        assert!(!capability.hardware_mutation_authorized);
    }

    #[test]
    fn passive_psu_health_bearing_and_unavailable_snapshots_are_neutral() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let mut telemetry = unattested_psu_telemetry(20_000);
        telemetry.detected = Some(false);
        telemetry.faults = Some(vec!["overtemperature".to_string()]);
        telemetry.status_word = Some(1);
        let health_id = service
            .publish_psu_probe_telemetry_at(telemetry, 20_100)
            .expect("health-bearing unattested values remain publishable as warnings");
        let health = service
            .get_result(&health_id)
            .expect("health-bearing result");
        assert!(health.grade.is_none());
        assert_eq!(health.warnings.len(), 4);
        assert!(health
            .warnings
            .iter()
            .any(|warning| warning.contains("detected=false")));
        assert!(health
            .warnings
            .iter()
            .any(|warning| warning.contains("1 non-empty fault")));
        assert!(health
            .warnings
            .iter()
            .any(|warning| warning.contains("non-zero status")));
        let health_progress = progress_rx.try_recv().expect("health publication event");
        assert_eq!(health_progress.phase_name, "snapshot_published");
        assert!(!health_progress.detail.contains("success"));

        let unavailable_id = service
            .publish_psu_probe_unavailable("  power watch has not published a sample  ")
            .expect("valid unavailable reason should normalize and publish");
        let unavailable = service
            .get_result(&unavailable_id)
            .expect("unavailable PSU result");
        assert!(unavailable.grade.is_none());
        assert_eq!(unavailable.warnings.len(), 1);
        assert!(unavailable.warnings[0].contains("unavailable"));
        assert_eq!(unavailable.data["provenance"], "unavailable");
        assert_eq!(
            unavailable.data["freshness"]["unavailable_reason"],
            "power watch has not published a sample"
        );
        assert!(unavailable.data["wall_power_w"].is_null());
        assert!(unavailable.data["vin_v"].is_null());
        let unavailable_progress = progress_rx.try_recv().expect("unavailable event");
        assert_eq!(unavailable_progress.phase_name, "snapshot_published");
        assert!(!unavailable_progress.detail.contains("success"));

        for reason in ["   ".to_string(), "x".repeat(513)] {
            let error = service
                .publish_psu_probe_unavailable(reason)
                .expect_err("invalid unavailable reasons must fail before insertion");
            assert!(matches!(error, DiagnosticError::SnapshotAdmission { .. }));
        }
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn passive_psu_refuses_nonfinite_empty_zero_and_future_samples() {
        let (progress_tx, mut progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);
        let mut invalid = unattested_psu_telemetry(1_000);
        invalid.wall_power_w = Some(f64::NAN);
        assert!(service
            .publish_psu_probe_telemetry_at(invalid, 1_100)
            .is_err());

        let mut empty = unattested_psu_telemetry(1_000);
        empty.detected = None;
        empty.vin_v = None;
        empty.vout_v = None;
        empty.iout_a = None;
        empty.board_power_w = None;
        empty.wall_power_w = None;
        empty.efficiency_pct = None;
        empty.temp_c = None;
        empty.fan_rpm = None;
        empty.faults = None;
        empty.status_word = None;
        empty.calibrated = None;
        assert!(service
            .publish_psu_probe_telemetry_at(empty, 1_100)
            .is_err());
        assert!(service
            .publish_psu_probe_telemetry_at(unattested_psu_telemetry(0), 1_100)
            .is_err());
        assert!(service
            .publish_psu_probe_telemetry_at(unattested_psu_telemetry(2_000), 1_999)
            .is_err());

        let mut too_many_faults = unattested_psu_telemetry(1_000);
        too_many_faults.faults = Some(vec!["fault".to_string(); 129]);
        assert!(service
            .publish_psu_probe_telemetry_at(too_many_faults, 1_100)
            .is_err());
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn passive_fpga_publication_rechecks_age_and_surfaces_error_counters() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let telemetry = unattested_fpga_telemetry(
            30_000,
            vec![unattested_fpga_chain(6), unattested_fpga_chain(7)],
        );
        let test_id = service
            .publish_fpga_status_telemetry_at(telemetry, 30_125)
            .expect("publication boundary should classify FPGA timestamp");
        let result = service.get_result(&test_id).expect("FPGA result");
        assert_eq!(result.test_type, TestType::FpgaStatus);
        assert_eq!(result.data["source"], FpgaStatusSnapshot::SOURCE);
        assert_eq!(result.data["provenance"], "caller_supplied_unattested");
        assert_eq!(result.data["freshness"]["availability"], "fresh_unattested");
        assert_eq!(result.data["chain_count"], 2);
        assert!(result.data["chains"][0]["bm139x_mode"].is_null());
        assert!(result.data["chains"][0]["cmd_tx_empty"].is_null());
        assert!(result.grade.is_none());
        assert_eq!(result.warnings.len(), 2);
        assert!(result.warnings[0].contains("caller-supplied and unattested"));
        assert!(result.warnings[1].contains("non-zero error counters"));
        let progress = progress_rx.try_recv().expect("FPGA publication event");
        assert_eq!(progress.phase_name, "snapshot_published");

        let am2_id = service
            .publish_fpga_status_runtime_telemetry_at(
                runtime_owned_am2_fpga_telemetry(40_000),
                40_125,
            )
            .expect("AM2 telemetry without S9-only interpretations should publish");
        let am2 = service.get_result(&am2_id).expect("AM2 FPGA result");
        assert_eq!(am2.data["chains"][0]["register_layout"], "am2");
        assert!(am2.data["chains"][0]["version"].is_null());
        assert!(am2.data["chains"][0]["baud_rate"].is_null());
        assert!(am2.data["chains"][0]["work_time"].is_null());
        assert!(am2.data["chains"][0]["error_count"].is_null());
        assert!(!progress.detail.contains("success"));

        let before_publication = unix_now_ms();
        let old_capture = before_publication
            .saturating_sub(crate::troubleshoot::PASSIVE_TELEMETRY_STALE_AFTER_MS + 1_000);
        let production_id = service
            .publish_fpga_status_telemetry(unattested_fpga_telemetry(
                old_capture,
                vec![unattested_fpga_chain(6)],
            ))
            .expect("production FPGA method should use its own publication clock");
        let production = service
            .get_result(&production_id)
            .expect("production FPGA result");
        assert_eq!(
            production.data["freshness"]["availability"],
            "stale_unattested"
        );

        let capability = diagnostic_interface_capability(TestType::FpgaStatus);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.hardware_mutation_authorized);
    }

    #[test]
    fn runtime_owned_fpga_publication_is_typed_ungraded_and_layout_bound() {
        let (progress_tx, mut progress_rx) = broadcast::channel(4);
        let mut service = DiagnosticService::new(progress_tx);
        let test_id = service
            .publish_fpga_status_runtime_telemetry_at(runtime_owned_fpga_telemetry(40_000), 40_125)
            .expect("retained runtime-owner FPGA telemetry should publish");
        let result = service.get_result(&test_id).expect("FPGA result");
        assert_eq!(result.test_type, TestType::FpgaStatus);
        assert_eq!(result.data["schema"], FpgaStatusSnapshot::SCHEMA);
        assert_eq!(
            result.data["provenance"],
            "runtime_owned_retained_observation"
        );
        assert_eq!(result.data["chains"][0]["register_layout"], "am1_s9");
        assert_eq!(result.data["chains"][0]["identity_word"], 0x0090_1002);
        assert_eq!(result.data["chains"][0]["build_id"], 0x6500_0000);
        assert_eq!(result.data["chains"][0]["work_time"], 0x0004_0507);
        assert!(result.grade.is_none());
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("retained runtime-owner snapshot")));
        assert!(result
            .warnings
            .iter()
            .all(|warning| !warning.contains("pass verdict")));
        let progress = progress_rx.try_recv().expect("FPGA publication event");
        assert_eq!(progress.phase_name, "snapshot_published");
    }

    #[test]
    fn runtime_owned_fpga_publication_refuses_layout_decode_drift() {
        let (progress_tx, mut progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);

        let mut wrong_enabled = runtime_owned_fpga_telemetry(1_000);
        wrong_enabled.chains[0].enabled = Some(false);
        assert!(service
            .publish_fpga_status_runtime_telemetry_at(wrong_enabled, 1_100)
            .is_err());

        let mut wrong_version = runtime_owned_fpga_telemetry(1_000);
        wrong_version.chains[0].version = Some("0x00000000".to_string());
        assert!(service
            .publish_fpga_status_runtime_telemetry_at(wrong_version, 1_100)
            .is_err());

        let mut relabelled_am2 = runtime_owned_fpga_telemetry(1_000);
        let chain = &mut relabelled_am2.chains[0];
        chain.register_layout = Some(crate::troubleshoot::FpgaRegisterLayout::Am2);
        chain.identity_word = chain.build_id;
        chain.ctrl_reg = Some(0x0090_1002);
        chain.enabled = Some(true);
        assert!(service
            .publish_fpga_status_runtime_telemetry_at(relabelled_am2, 1_100)
            .is_err());

        let mut invented_am2_crc = runtime_owned_am2_fpga_telemetry(1_000);
        invented_am2_crc.chains[0].error_count = Some(0);
        assert!(service
            .publish_fpga_status_runtime_telemetry_at(invented_am2_crc, 1_100)
            .is_err());

        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn passive_fpga_unavailable_snapshot_is_fallible_neutral_and_value_free() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let test_id = service
            .publish_fpga_status_unavailable(
                "daemon does not retain FPGA registers after dispatcher handoff",
            )
            .expect("valid FPGA unavailable reason");
        let result = service
            .get_result(&test_id)
            .expect("unavailable FPGA result");
        assert!(result.grade.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("unavailable"));
        assert_eq!(result.data["provenance"], "unavailable");
        assert!(result.data["chain_count"].is_null());
        assert!(result.data["chains"].is_null());
        let progress = progress_rx.try_recv().expect("unavailable FPGA event");
        assert_eq!(progress.phase_name, "snapshot_published");
        assert!(!progress.detail.contains("success"));

        for reason in ["".to_string(), "x".repeat(513)] {
            let error = service
                .publish_fpga_status_unavailable(reason)
                .expect_err("invalid FPGA unavailable reason must fail closed");
            assert!(matches!(error, DiagnosticError::SnapshotAdmission { .. }));
        }
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn passive_fpga_refuses_empty_duplicate_unobserved_and_overlong_inputs() {
        let (progress_tx, mut progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);
        assert!(service
            .publish_fpga_status_telemetry_at(unattested_fpga_telemetry(1_000, Vec::new()), 1_100)
            .is_err());

        let unobserved = crate::troubleshoot::UnattestedFpgaChainTelemetry {
            chain_id: 6,
            register_layout: None,
            identity_word: None,
            version: None,
            build_id: None,
            ctrl_reg: None,
            enabled: None,
            bm139x_mode: None,
            baud_reg: None,
            baud_rate: None,
            work_time: None,
            error_count: None,
            cmd_tx_empty: None,
            cmd_rx_empty: None,
            work_tx_empty: None,
            work_rx_empty: None,
        };
        assert!(service
            .publish_fpga_status_telemetry_at(
                unattested_fpga_telemetry(1_000, vec![unobserved]),
                1_100,
            )
            .is_err());
        assert!(service
            .publish_fpga_status_telemetry_at(
                unattested_fpga_telemetry(
                    1_000,
                    vec![unattested_fpga_chain(6), unattested_fpga_chain(6)],
                ),
                1_100,
            )
            .is_err());
        let mut overlong = unattested_fpga_telemetry(1_000, vec![unattested_fpga_chain(6)]);
        overlong.telemetry_source = "x".repeat(257);
        assert!(service
            .publish_fpga_status_telemetry_at(overlong, 1_100)
            .is_err());
        assert!(service
            .publish_fpga_status_telemetry_at(
                unattested_fpga_telemetry(2_000, vec![unattested_fpga_chain(6)]),
                1_999,
            )
            .is_err());
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn retained_i2c_publication_is_positive_only_ungraded_and_age_evaluated() {
        let (progress_tx, mut progress_rx) = broadcast::channel(4);
        let mut service = DiagnosticService::new(progress_tx);
        let test_id = service
            .publish_i2c_runtime_telemetry_at(runtime_owned_i2c_telemetry(10_000), 10_125)
            .expect("retained I2C observations should publish");
        let result = service.get_result(&test_id).expect("I2C result");

        assert_eq!(result.test_type, TestType::I2cScan);
        assert_eq!(result.data["schema"], I2cScanSnapshot::SCHEMA);
        assert_eq!(
            result.data["provenance"],
            "runtime_owned_retained_observation"
        );
        assert_eq!(
            result.data["coverage"],
            "successful_runtime_operations_only"
        );
        assert_eq!(result.data["scan_performed"], false);
        assert_eq!(result.data["absence_inference_authorized"], false);
        assert_eq!(result.data["endpoint_count"], 2);
        assert_eq!(result.data["endpoints"][0]["address_hex"], "0x50");
        assert_eq!(result.data["endpoints"][0]["age_ms"], 135);
        assert_eq!(result.data["endpoints"][1]["age_ms"], 125);
        assert!(result.grade.is_none());
        assert!(result.warnings[0].contains("unlisted addresses are unknown, not absent"));
        let progress = progress_rx.try_recv().expect("I2C publication event");
        assert_eq!(progress.phase_name, "snapshot_published");
        assert!(!progress.detail.contains("success"));

        let capability = diagnostic_interface_capability(TestType::I2cScan);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.typed_measured_pass_authorized);
        assert!(!capability.manufacturing_grade_authorized);
        assert!(!capability.hardware_mutation_authorized);
    }

    #[test]
    fn retained_i2c_publication_rejects_relabelled_future_and_empty_evidence() {
        use crate::troubleshoot::I2cObservedEndpointRole;

        let (progress_tx, mut progress_rx) = broadcast::channel(2);
        let mut service = DiagnosticService::new(progress_tx);

        let mut relabelled = runtime_owned_i2c_telemetry(1_000);
        relabelled.endpoints[0].endpoint_role = I2cObservedEndpointRole::TemperatureSensorEndpoint;
        assert!(service
            .publish_i2c_runtime_telemetry_at(relabelled, 1_100)
            .is_err());

        assert!(service
            .publish_i2c_runtime_telemetry_at(runtime_owned_i2c_telemetry(2_000), 1_999)
            .is_err());

        let mut empty = runtime_owned_i2c_telemetry(1_000);
        empty.endpoints.clear();
        assert!(service
            .publish_i2c_runtime_telemetry_at(empty, 1_100)
            .is_err());
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let unavailable_id = service
            .publish_i2c_observations_unavailable("no serialized owner observation yet")
            .expect("explicit I2C unavailability should publish");
        let unavailable = service
            .get_result(&unavailable_id)
            .expect("unavailable I2C result");
        assert_eq!(unavailable.data["coverage"], "unavailable");
        assert_eq!(unavailable.data["scan_performed"], false);
        assert!(unavailable.data["endpoints"].is_null());
        assert!(unavailable.grade.is_none());
    }

    #[test]
    fn passive_asic_comm_snapshot_publishes_immediately_and_rejects_aggregate_drift() {
        let (progress_tx, mut progress_rx) = broadcast::channel(8);
        let mut service = DiagnosticService::new(progress_tx);
        let snapshot = passive_asic_comm_snapshot();
        let expected = serde_json::to_value(&snapshot).expect("fixture must serialize");

        let test_id = service
            .publish_asic_comm_snapshot(snapshot)
            .expect("passive retained telemetry must publish without a runtime");
        let stored = service
            .get_test_status(&test_id)
            .expect("ASIC communication publication must be immediately visible");
        assert_eq!(stored.status, TestStatus::Completed);
        let result = stored
            .result
            .expect("ASIC communication result must be retained");
        assert_eq!(result.test_id, test_id);
        assert_eq!(result.test_type, TestType::AsicCommTest);
        assert_eq!(result.duration_s, 0);
        assert_eq!(result.data, expected);
        assert!(result.grade.is_none());
        assert!(result.warnings.is_empty());
        assert!(result.recommendations.is_empty());
        let progress = progress_rx
            .try_recv()
            .expect("publisher must emit one terminal lifecycle event");
        assert_eq!(progress.test_id, test_id);
        assert_eq!(progress.test_type, TestType::AsicCommTest);
        assert_eq!(progress.progress_pct, 100);
        assert!(!service.cancel_test(&test_id));
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let capability = diagnostic_interface_capability(TestType::AsicCommTest);
        assert_eq!(
            capability.state,
            DiagnosticInterfaceCapabilityState::ImmediateTelemetrySnapshotPublisherProductionRouteNoMeasuredPass
        );
        assert!(capability.runtime_job_engine_implemented);
        assert!(capability.production_route_integrated);
        assert!(!capability.typed_measured_pass_authorized);
        assert!(!capability.manufacturing_grade_authorized);
        assert!(!capability.hardware_mutation_authorized);

        for mutate in [
            |snapshot: &mut AsicCommSnapshot| snapshot.chain_count += 1,
            |snapshot: &mut AsicCommSnapshot| snapshot.chains[0].comm_ok = false,
            |snapshot: &mut AsicCommSnapshot| snapshot.chains[1].chain_id = 6,
        ] {
            let mut invalid = passive_asic_comm_snapshot();
            mutate(&mut invalid);
            let error = service
                .publish_asic_comm_snapshot(invalid)
                .expect_err("inconsistent passive telemetry must fail before insertion");
            assert!(matches!(error, DiagnosticError::SnapshotAdmission { .. }));
        }
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn poisoned_job_store_refuses_publication_without_progress() {
        let (progress_tx, mut progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);
        let jobs = Arc::clone(&service.jobs);
        let _ = std::panic::catch_unwind(move || {
            let _guard = jobs.lock().expect("fixture must acquire job store");
            panic!("poison diagnostic job store");
        });

        let config = DiagnosticJobConfig::ChipHealth(ChipHealthJobConfig::from_snapshot(
            prepared_snapshot(),
        ));
        let error = service
            .start_test(TestType::ChipHealth, config)
            .expect_err("poisoned state must fail closed");
        assert!(matches!(error, DiagnosticError::StateUnavailable));
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn poisoned_completed_store_refuses_publication_without_insertion_or_progress() {
        let (progress_tx, mut progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);
        let completed_tests = Arc::clone(&service.completed_tests);
        let _ = std::panic::catch_unwind(move || {
            let _guard = completed_tests
                .lock()
                .expect("fixture must acquire completed store");
            panic!("poison diagnostic completed store");
        });

        let config = DiagnosticJobConfig::ChipHealth(ChipHealthJobConfig::from_snapshot(
            prepared_snapshot(),
        ));
        let error = service
            .start_test(TestType::ChipHealth, config)
            .expect_err("poisoned completion state must fail closed");
        assert!(matches!(error, DiagnosticError::StateUnavailable));
        assert!(service
            .jobs
            .lock()
            .expect("job store must remain available")
            .is_empty());
        assert!(matches!(
            progress_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn hashreport_without_tokio_runtime_is_rejected_before_insertion() {
        let (progress_tx, _progress_rx) = broadcast::channel(1);
        let mut service = DiagnosticService::new(progress_tx);
        let config = DiagnosticJobConfig::HashReport(HashReportJobConfig {
            duration: Duration::from_secs(1),
            progress_interval: Duration::from_secs(1),
            finalize: Arc::new(|_, _| Box::pin(async { unreachable!("must not spawn") })),
        });

        let error = service
            .start_test(TestType::HashReport, config)
            .expect_err("async engine requires an active Tokio runtime");
        assert!(matches!(
            error,
            DiagnosticError::RuntimeUnavailable {
                test_type: TestType::HashReport
            }
        ));
        assert!(service
            .jobs
            .lock()
            .expect("job store must remain available")
            .is_empty());
    }
}
