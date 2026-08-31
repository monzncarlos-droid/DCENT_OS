//! Receipt-bound S19k Track-1 endurance evidence.
//!
//! The long-running gate deliberately does not reuse the raw Phase-3 UART
//! transcript.  It publishes small, canonical minute aggregates into a
//! hash-chain.  A separately content-bound host collector must acknowledge
//! every segment after copying and hashing it off target.  Missing or
//! contradictory acknowledgement evidence is a terminal mining failure.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const S19K_ENDURANCE_MIN_S: u64 = 24 * 60 * 60;
pub(crate) const S19K_ENDURANCE_MAX_S: u64 = 26 * 60 * 60;
pub(crate) const S19K_ENDURANCE_INTERVAL_S: u64 = 60;
pub(crate) const S19K_ENDURANCE_WINDOW_S: u64 = 6 * 60 * 60;
pub(crate) const S19K_ENDURANCE_WINDOW_COUNT: usize = 4;
pub(crate) const S19K_ENDURANCE_ACK_TIMEOUT_S: u64 = 5 * 60;
pub(crate) const S19K_ENDURANCE_MAX_UNACKED_SEGMENTS: usize = 6;
pub(crate) const S19K_ENDURANCE_MAX_UNACKED_BYTES: u64 = 512 * 1024;
pub(crate) const S19K_ENDURANCE_MAX_SEGMENT_BYTES: usize = 64 * 1024;
pub(crate) const S19K_ENDURANCE_MAX_SEGMENTS: u64 =
    S19K_ENDURANCE_MAX_S / S19K_ENDURANCE_INTERVAL_S + 1;
pub(crate) const S19K_ENDURANCE_EVIDENCE_DIR: &str = "endurance_evidence";
pub(crate) const S19K_ENDURANCE_TERMINAL_FILE: &str = "daemon_terminal";
pub(crate) const S19K_ENDURANCE_FAILURE_FILE: &str = "daemon_failure";
pub(crate) const S19K_ENDURANCE_GENESIS_MANIFEST_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const SEGMENT_SCHEMA: &str = "dcentos.s19k-endurance-segment/v1";
const ACK_SCHEMA: &str = "dcentos.s19k-endurance-segment-ack/v1";
const TERMINAL_SCHEMA: &str = "dcentos.s19k-endurance-daemon-terminal/v1";
const FAILURE_SCHEMA: &str = "dcentos.s19k-endurance-daemon-failure/v1";
const MIN_INTERVAL_MS: u64 = 55_000;
const MAX_INTERVAL_MS: u64 = 75_000;
const MAX_WALL_MONOTONIC_DRIFT_MS: u64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S19kEndurancePathSnapshot {
    pub path: String,
    pub chips: u16,
    pub complete_77_at_work_baud: bool,
    pub tx_frames: u64,
    pub rx_wire_bytes: u64,
    pub rx_frames: u64,
    pub valid_nonces: u64,
    pub shares_submitted: u64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S19kEnduranceSnapshot {
    pub monotonic_ms: u64,
    pub wall_unix_ms: u64,
    pub pool_state: String,
    pub aggregate_hashrate_millighs: u64,
    pub hottest_temp_millic: i64,
    pub dangerous_temp_millic: i64,
    pub fan_pwm: u8,
    pub fan_readings: Vec<(u8, u32)>,
    pub gpio437: u8,
    pub paths: Vec<S19kEndurancePathSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S19kEnduranceShareLineage {
    pub elapsed_s: u64,
    pub accepted: bool,
    pub path: String,
    pub attribution: String,
    pub work_generation: String,
    pub worker_name: String,
    pub job_id: String,
    pub extranonce2: String,
    pub ntime: String,
    pub nonce: String,
    pub version_bits: Option<String>,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S19kEnduranceGateDecision {
    Continue,
    BeginFinalization,
    Pass,
    DeadlineExceeded,
}

pub(crate) fn s19k_endurance_gate_decision(
    elapsed_s: u64,
    acceptance_complete: bool,
    terminal_segment_acked: bool,
) -> S19kEnduranceGateDecision {
    if terminal_segment_acked && elapsed_s >= S19K_ENDURANCE_MIN_S && acceptance_complete {
        return S19kEnduranceGateDecision::Pass;
    }
    if elapsed_s >= S19K_ENDURANCE_MAX_S {
        return S19kEnduranceGateDecision::DeadlineExceeded;
    }
    if elapsed_s >= S19K_ENDURANCE_MIN_S && acceptance_complete {
        S19kEnduranceGateDecision::BeginFinalization
    } else {
        S19kEnduranceGateDecision::Continue
    }
}

#[derive(Debug, Clone)]
struct SealedSegment {
    sequence: u64,
    sha256: String,
    bytes: u64,
    sealed_at: Instant,
    wall_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S19kEnduranceSealReceipt {
    pub sequence: u64,
    pub sha256: String,
    pub bytes: u64,
    pub terminal: bool,
}

#[derive(Debug)]
pub(crate) struct S19kEnduranceEvidence {
    root: PathBuf,
    segments: PathBuf,
    acknowledgements: PathBuf,
    runtime_active_sha256: String,
    runtime_active_bytes: u64,
    live_identity_sha256: String,
    genesis_sha256: String,
    next_sequence: u64,
    predecessor_sha256: String,
    previous_snapshot: S19kEnduranceSnapshot,
    pending_events: Vec<String>,
    pending_lineage: Vec<S19kEnduranceShareLineage>,
    accepted_window_bits: BTreeMap<String, u8>,
    unacknowledged: VecDeque<SealedSegment>,
    unacknowledged_bytes: u64,
    acknowledged_segments: u64,
    manifest_sha256: String,
    manifest_bytes: u64,
    finalizing_sequence: Option<u64>,
}

impl S19kEnduranceEvidence {
    pub(crate) fn create(
        root: PathBuf,
        runtime_active_sha256: String,
        runtime_active_bytes: u64,
        live_identity_sha256: String,
        initial: S19kEnduranceSnapshot,
    ) -> Result<Self> {
        require_sha256(&runtime_active_sha256, "runtime_active")?;
        require_sha256(&live_identity_sha256, "live identity")?;
        anyhow::ensure!(runtime_active_bytes > 0, "runtime_active is empty");
        require_snapshot_shape(&initial, None)?;
        create_private_directory(&root, "endurance evidence root")?;
        let segments = root.join("segments");
        let acknowledgements = root.join("acks");
        create_private_directory(&segments, "endurance segment directory")?;
        create_private_directory(&acknowledgements, "endurance acknowledgement directory")?;
        fsync_directory(&root)?;
        let mut genesis = Sha256::new();
        hash_bound_field(&mut genesis, b"schema", SEGMENT_SCHEMA.as_bytes());
        hash_bound_field(
            &mut genesis,
            b"runtime_active_sha256",
            runtime_active_sha256.as_bytes(),
        );
        hash_bound_field(
            &mut genesis,
            b"runtime_active_bytes",
            runtime_active_bytes.to_string().as_bytes(),
        );
        hash_bound_field(
            &mut genesis,
            b"live_identity_sha256",
            live_identity_sha256.as_bytes(),
        );
        let genesis_sha256 = format!("{:x}", genesis.finalize());
        let accepted_window_bits = initial
            .paths
            .iter()
            .filter(|path| path.complete_77_at_work_baud)
            .map(|path| (path.path.clone(), 0u8))
            .collect();
        Ok(Self {
            root,
            segments,
            acknowledgements,
            runtime_active_sha256,
            runtime_active_bytes,
            live_identity_sha256,
            genesis_sha256: genesis_sha256.clone(),
            next_sequence: 0,
            predecessor_sha256: genesis_sha256,
            previous_snapshot: initial,
            pending_events: vec!["endurance-authority-admitted".to_string()],
            pending_lineage: Vec::new(),
            accepted_window_bits,
            unacknowledged: VecDeque::new(),
            unacknowledged_bytes: 0,
            acknowledged_segments: 0,
            manifest_sha256: S19K_ENDURANCE_GENESIS_MANIFEST_SHA256.to_string(),
            manifest_bytes: 0,
            finalizing_sequence: None,
        })
    }

    pub(crate) fn record_event(&mut self, event: impl Into<String>) -> Result<()> {
        let event = event.into();
        require_safe_text(&event, "endurance lifecycle event")?;
        anyhow::ensure!(
            self.pending_events.len() < 1024,
            "endurance lifecycle event buffer exceeded 1024 entries before the next minute seal"
        );
        self.pending_events.push(event);
        Ok(())
    }

    pub(crate) fn record_share_lineage(
        &mut self,
        lineage: S19kEnduranceShareLineage,
    ) -> Result<()> {
        for (label, value) in [
            ("path", lineage.path.as_str()),
            ("attribution", lineage.attribution.as_str()),
            ("work generation", lineage.work_generation.as_str()),
            ("worker", lineage.worker_name.as_str()),
            ("job", lineage.job_id.as_str()),
            ("extranonce2", lineage.extranonce2.as_str()),
            ("ntime", lineage.ntime.as_str()),
            ("nonce", lineage.nonce.as_str()),
        ] {
            require_bounded_text(value, label, 1024)?;
        }
        if let Some(version_bits) = lineage.version_bits.as_deref() {
            require_bounded_text(version_bits, "version bits", 64)?;
        }
        anyhow::ensure!(
            self.accepted_window_bits.contains_key(&lineage.path),
            "endurance pool result named a non-required UART {}",
            lineage.path
        );
        if lineage.accepted && lineage.elapsed_s < S19K_ENDURANCE_MIN_S {
            let window = usize::try_from(lineage.elapsed_s / S19K_ENDURANCE_WINDOW_S)
                .context("endurance acceptance window does not fit usize")?;
            if window < S19K_ENDURANCE_WINDOW_COUNT {
                let bit = 1u8 << window;
                if let Some(bits) = self.accepted_window_bits.get_mut(&lineage.path) {
                    *bits |= bit;
                }
            }
        }
        anyhow::ensure!(
            self.pending_lineage.len() < 4096,
            "endurance share-lineage buffer exceeded 4096 entries before the next minute seal"
        );
        self.pending_lineage.push(lineage);
        Ok(())
    }

    pub(crate) fn acceptance_complete(&self) -> bool {
        let required = (1u8 << S19K_ENDURANCE_WINDOW_COUNT) - 1;
        !self.accepted_window_bits.is_empty()
            && self
                .accepted_window_bits
                .values()
                .all(|observed| *observed == required)
    }

    pub(crate) fn finalizing_sequence(&self) -> Option<u64> {
        self.finalizing_sequence
    }

    pub(crate) fn finalizing_segment_acked(&self) -> bool {
        self.finalizing_sequence
            .is_some_and(|sequence| self.acknowledged_segments > sequence)
    }

    pub(crate) fn seal_minute(
        &mut self,
        snapshot: S19kEnduranceSnapshot,
        terminal: bool,
        now: Instant,
    ) -> Result<S19kEnduranceSealReceipt> {
        anyhow::ensure!(
            self.next_sequence < S19K_ENDURANCE_MAX_SEGMENTS,
            "endurance segment count exceeded the 26-hour bounded geometry"
        );
        anyhow::ensure!(
            self.finalizing_sequence.is_none(),
            "endurance evidence cannot publish a segment after terminal finalization began"
        );
        require_snapshot_shape(&snapshot, Some(&self.previous_snapshot))?;
        let duration_ms = snapshot
            .monotonic_ms
            .checked_sub(self.previous_snapshot.monotonic_ms)
            .context("endurance monotonic clock regressed")?;
        anyhow::ensure!(
            (MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&duration_ms),
            "endurance telemetry interval is not a complete bounded minute: {duration_ms}ms"
        );
        let wall_duration_ms = snapshot
            .wall_unix_ms
            .checked_sub(self.previous_snapshot.wall_unix_ms)
            .context("endurance wall clock regressed")?;
        anyhow::ensure!(
            wall_duration_ms.abs_diff(duration_ms) <= MAX_WALL_MONOTONIC_DRIFT_MS,
            "endurance wall/monotonic interval disagreement exceeded the declared bound"
        );
        let sequence = self.next_sequence;
        let mut content = String::new();
        push_field(&mut content, "schema", SEGMENT_SCHEMA);
        push_field(&mut content, "sequence", sequence);
        push_field(
            &mut content,
            "segment_kind",
            if terminal { "terminal-pass" } else { "minute" },
        );
        push_field(&mut content, "predecessor_sha256", &self.predecessor_sha256);
        push_field(&mut content, "genesis_sha256", &self.genesis_sha256);
        push_field(
            &mut content,
            "runtime_active_sha256",
            &self.runtime_active_sha256,
        );
        push_field(
            &mut content,
            "runtime_active_bytes",
            self.runtime_active_bytes,
        );
        push_field(
            &mut content,
            "live_identity_sha256",
            &self.live_identity_sha256,
        );
        push_field(
            &mut content,
            "interval_monotonic_start_ms",
            self.previous_snapshot.monotonic_ms,
        );
        push_field(
            &mut content,
            "interval_monotonic_end_ms",
            snapshot.monotonic_ms,
        );
        push_field(&mut content, "interval_duration_ms", duration_ms);
        push_field(
            &mut content,
            "interval_wall_start_unix_ms",
            self.previous_snapshot.wall_unix_ms,
        );
        push_field(
            &mut content,
            "interval_wall_end_unix_ms",
            snapshot.wall_unix_ms,
        );
        push_field(&mut content, "interval_wall_duration_ms", wall_duration_ms);
        push_field(
            &mut content,
            "pool_state_hex",
            hex_bytes(snapshot.pool_state.as_bytes()),
        );
        push_field(
            &mut content,
            "aggregate_hashrate_millighs",
            snapshot.aggregate_hashrate_millighs,
        );
        push_field(
            &mut content,
            "hottest_temp_millic",
            snapshot.hottest_temp_millic,
        );
        push_field(
            &mut content,
            "dangerous_temp_millic",
            snapshot.dangerous_temp_millic,
        );
        push_field(&mut content, "fan_pwm", snapshot.fan_pwm);
        push_field(
            &mut content,
            "fan_readings",
            format_fans(&snapshot.fan_readings),
        );
        push_field(&mut content, "gpio437", snapshot.gpio437);
        push_field(&mut content, "required_path_count", snapshot.paths.len());
        for (index, (before, after)) in self
            .previous_snapshot
            .paths
            .iter()
            .zip(snapshot.paths.iter())
            .enumerate()
        {
            anyhow::ensure!(before.path == after.path, "endurance UART ordering changed");
            push_field(
                &mut content,
                &format!("path_{index}_hex"),
                hex_bytes(after.path.as_bytes()),
            );
            push_field(&mut content, &format!("path_{index}_chips"), after.chips);
            push_field(
                &mut content,
                &format!("path_{index}_complete77"),
                after.complete_77_at_work_baud,
            );
            for (name, old, new) in [
                ("tx_frames", before.tx_frames, after.tx_frames),
                ("rx_wire_bytes", before.rx_wire_bytes, after.rx_wire_bytes),
                ("rx_frames", before.rx_frames, after.rx_frames),
                ("valid_nonces", before.valid_nonces, after.valid_nonces),
                (
                    "shares_submitted",
                    before.shares_submitted,
                    after.shares_submitted,
                ),
                (
                    "shares_accepted",
                    before.shares_accepted,
                    after.shares_accepted,
                ),
                (
                    "shares_rejected",
                    before.shares_rejected,
                    after.shares_rejected,
                ),
            ] {
                let delta = new.checked_sub(old).with_context(|| {
                    format!("endurance counter {name} regressed on {}", after.path)
                })?;
                if matches!(
                    name,
                    "tx_frames" | "rx_wire_bytes" | "rx_frames" | "valid_nonces"
                ) {
                    anyhow::ensure!(
                        delta > 0,
                        "endurance liveness counter {name} made no progress on {}",
                        after.path
                    );
                }
                push_field(&mut content, &format!("path_{index}_{name}_total"), new);
                push_field(&mut content, &format!("path_{index}_{name}_delta"), delta);
            }
            push_field(
                &mut content,
                &format!("path_{index}_accepted_window_bits"),
                format!("{:04b}", self.accepted_window_bits[&after.path]),
            );
        }
        push_field(&mut content, "event_count", self.pending_events.len());
        for (index, event) in self.pending_events.iter().enumerate() {
            push_field(
                &mut content,
                &format!("event_{index}_hex"),
                hex_bytes(event.as_bytes()),
            );
        }
        push_field(
            &mut content,
            "share_lineage_count",
            self.pending_lineage.len(),
        );
        for (index, lineage) in self.pending_lineage.iter().enumerate() {
            push_field(
                &mut content,
                &format!("share_lineage_{index}_hex"),
                hex_bytes(&canonical_lineage(lineage)),
            );
        }
        push_field(
            &mut content,
            "acceptance_complete",
            self.acceptance_complete(),
        );
        push_field(
            &mut content,
            "collector_ack_timeout_s",
            S19K_ENDURANCE_ACK_TIMEOUT_S,
        );
        push_field(
            &mut content,
            "collector_max_unacked_segments",
            S19K_ENDURANCE_MAX_UNACKED_SEGMENTS,
        );
        push_field(
            &mut content,
            "collector_max_unacked_bytes",
            S19K_ENDURANCE_MAX_UNACKED_BYTES,
        );
        push_field(
            &mut content,
            "publication",
            "no-clobber-hard-link-after-fsync",
        );
        anyhow::ensure!(
            content.len() <= S19K_ENDURANCE_MAX_SEGMENT_BYTES,
            "endurance segment exceeded {} bytes",
            S19K_ENDURANCE_MAX_SEGMENT_BYTES
        );
        let prospective_unacknowledged_segments = self
            .unacknowledged
            .len()
            .checked_add(1)
            .context("endurance unacknowledged segment counter overflow")?;
        let prospective_unacknowledged_bytes = self
            .unacknowledged_bytes
            .checked_add(content.len() as u64)
            .context("endurance unacknowledged byte counter overflow")?;
        anyhow::ensure!(
            prospective_unacknowledged_segments <= S19K_ENDURANCE_MAX_UNACKED_SEGMENTS
                && prospective_unacknowledged_bytes <= S19K_ENDURANCE_MAX_UNACKED_BYTES,
            "endurance collector high-water would be exceeded: segments={} bytes={}",
            prospective_unacknowledged_segments,
            prospective_unacknowledged_bytes
        );
        let name = segment_name(sequence);
        // Validate and fsync the private scratch inode before its no-clobber
        // link becomes visible.  Once the link exists it is part of the
        // evidence chain even if the following directory fsync reports an I/O
        // error: commit the matching in-memory state first so a typed terminal
        // failure can describe every published segment exactly.
        publish_no_clobber_linked(&self.segments, &name, content.as_bytes())?;
        let sha256 = format!("{:x}", Sha256::digest(content.as_bytes()));
        let bytes = content.len() as u64;
        self.unacknowledged.push_back(SealedSegment {
            sequence,
            sha256: sha256.clone(),
            bytes,
            sealed_at: now,
            wall_unix_ms: snapshot.wall_unix_ms,
        });
        self.unacknowledged_bytes = prospective_unacknowledged_bytes;
        self.predecessor_sha256 = sha256.clone();
        self.previous_snapshot = snapshot;
        self.pending_events.clear();
        self.pending_lineage.clear();
        self.next_sequence = self.next_sequence.saturating_add(1);
        if terminal {
            self.finalizing_sequence = Some(sequence);
        }
        fsync_directory(&self.segments)
            .context("cannot durably commit the published endurance segment directory entry")?;
        Ok(S19kEnduranceSealReceipt {
            sequence,
            sha256,
            bytes,
            terminal,
        })
    }

    pub(crate) fn poll_acknowledgements(&mut self, now: Instant) -> Result<u64> {
        loop {
            let Some(segment) = self.unacknowledged.front() else {
                break;
            };
            let ack_path = self.acknowledgements.join(ack_name(segment.sequence));
            if !ack_path.exists() {
                anyhow::ensure!(
                    now.saturating_duration_since(segment.sealed_at)
                        < Duration::from_secs(S19K_ENDURANCE_ACK_TIMEOUT_S),
                    "endurance collector failed to acknowledge segment {} within {}s",
                    segment.sequence,
                    S19K_ENDURANCE_ACK_TIMEOUT_S
                );
                break;
            }
            let fields = read_exact_kv(&ack_path, 9, "endurance collector acknowledgement")?;
            require_field(&fields, "schema", ACK_SCHEMA)?;
            require_field(&fields, "sequence", &segment.sequence.to_string())?;
            require_field(&fields, "segment_sha256", &segment.sha256)?;
            require_field(&fields, "segment_bytes", &segment.bytes.to_string())?;
            require_field(
                &fields,
                "predecessor_manifest_sha256",
                &self.manifest_sha256,
            )?;
            require_field(&fields, "publication", "no-clobber-hard-link-after-fsync")?;
            let manifest_sha256 = fields
                .get("off_target_manifest_sha256")
                .context("endurance acknowledgement lacks manifest digest")?;
            require_sha256(manifest_sha256, "off-target manifest")?;
            let manifest_bytes = parse_positive_u64(
                fields
                    .get("off_target_manifest_bytes")
                    .context("endurance acknowledgement lacks manifest size")?,
                "off-target manifest size",
            )?;
            let collector_wall = parse_positive_u64(
                fields
                    .get("collector_wall_unix_ms")
                    .context("endurance acknowledgement lacks collector time")?,
                "collector wall time",
            )?;
            anyhow::ensure!(
                collector_wall
                    >= segment
                        .wall_unix_ms
                        .saturating_sub(MAX_WALL_MONOTONIC_DRIFT_MS),
                "endurance collector wall time predates the sealed segment"
            );
            anyhow::ensure!(
                collector_wall <= unix_time_ms()?.saturating_add(MAX_WALL_MONOTONIC_DRIFT_MS),
                "endurance collector wall time is implausibly in the future"
            );
            self.manifest_sha256 = manifest_sha256.clone();
            self.manifest_bytes = manifest_bytes;
            self.unacknowledged_bytes = self.unacknowledged_bytes.saturating_sub(segment.bytes);
            self.acknowledged_segments = segment.sequence.saturating_add(1);
            self.unacknowledged.pop_front();
        }
        Ok(self.acknowledged_segments)
    }

    pub(crate) fn publish_terminal(&self, elapsed_s: u64) -> Result<()> {
        let terminal_sequence = self
            .finalizing_sequence
            .context("endurance terminal publication lacks a finalizing segment")?;
        anyhow::ensure!(
            self.finalizing_segment_acked() && self.unacknowledged.is_empty(),
            "endurance terminal publication requires every segment acknowledgement"
        );
        anyhow::ensure!(
            elapsed_s >= S19K_ENDURANCE_MIN_S && elapsed_s < S19K_ENDURANCE_MAX_S,
            "endurance terminal publication is outside the 24h/26h bounds"
        );
        anyhow::ensure!(
            self.acceptance_complete(),
            "endurance acceptance windows are incomplete"
        );
        let mut content = String::new();
        push_field(&mut content, "schema", TERMINAL_SCHEMA);
        push_field(&mut content, "outcome", "pass-pending-runner-safeoff");
        push_field(&mut content, "elapsed_s", elapsed_s);
        push_field(&mut content, "minimum_s", S19K_ENDURANCE_MIN_S);
        push_field(&mut content, "maximum_s", S19K_ENDURANCE_MAX_S);
        push_field(&mut content, "segment_count", self.next_sequence);
        push_field(&mut content, "terminal_sequence", terminal_sequence);
        push_field(
            &mut content,
            "segment_chain_head_sha256",
            &self.predecessor_sha256,
        );
        push_field(
            &mut content,
            "off_target_manifest_sha256",
            &self.manifest_sha256,
        );
        push_field(
            &mut content,
            "off_target_manifest_bytes",
            self.manifest_bytes,
        );
        push_field(
            &mut content,
            "runtime_active_sha256",
            &self.runtime_active_sha256,
        );
        push_field(
            &mut content,
            "runtime_active_bytes",
            self.runtime_active_bytes,
        );
        push_field(
            &mut content,
            "live_identity_sha256",
            &self.live_identity_sha256,
        );
        push_field(&mut content, "acceptance_windows", "4x6h-per-required-uart");
        push_field(
            &mut content,
            "publication",
            "no-clobber-hard-link-after-fsync",
        );
        publish_no_clobber(&self.root, S19K_ENDURANCE_TERMINAL_FILE, content.as_bytes())
    }

    /// Publish the daemon half of a failed endurance outcome, but only after
    /// the exact serial shutdown composition has produced a positive watchdog
    /// closeout receipt.  The target wrapper subsequently binds this record to
    /// the independently checked reset/GPIO SafeOff and stock-restart-pending
    /// receipts.  The failure reason is hex encoded so arbitrary anyhow
    /// context cannot inject fields into the canonical record.
    pub(crate) fn publish_failure_terminal(
        &self,
        elapsed_s: u64,
        reason: &str,
        checked_safeoff: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            checked_safeoff,
            "endurance failure publication requires positive checked-SafeOff closeout evidence"
        );
        anyhow::ensure!(
            !reason.is_empty() && reason.len() <= 8192,
            "endurance failure reason has invalid length"
        );
        let mut content = String::new();
        push_field(&mut content, "schema", FAILURE_SCHEMA);
        push_field(&mut content, "outcome", "fail-after-checked-safeoff");
        push_field(&mut content, "elapsed_s", elapsed_s);
        push_field(&mut content, "segment_count", self.next_sequence);
        push_field(
            &mut content,
            "acknowledged_segments",
            self.acknowledged_segments,
        );
        push_field(
            &mut content,
            "unacknowledged_segments",
            self.unacknowledged.len(),
        );
        push_field(
            &mut content,
            "unacknowledged_bytes",
            self.unacknowledged_bytes,
        );
        push_field(
            &mut content,
            "segment_chain_head_sha256",
            &self.predecessor_sha256,
        );
        push_field(
            &mut content,
            "off_target_manifest_sha256",
            &self.manifest_sha256,
        );
        push_field(
            &mut content,
            "off_target_manifest_bytes",
            self.manifest_bytes,
        );
        push_field(
            &mut content,
            "runtime_active_sha256",
            &self.runtime_active_sha256,
        );
        push_field(
            &mut content,
            "runtime_active_bytes",
            self.runtime_active_bytes,
        );
        push_field(
            &mut content,
            "live_identity_sha256",
            &self.live_identity_sha256,
        );
        push_field(&mut content, "checked_safeoff", true);
        push_field(
            &mut content,
            "failure_reason_utf8_hex",
            hex_bytes(reason.as_bytes()),
        );
        push_field(
            &mut content,
            "publication",
            "no-clobber-hard-link-after-fsync",
        );
        publish_no_clobber(&self.root, S19K_ENDURANCE_FAILURE_FILE, content.as_bytes())
    }

    #[cfg(test)]
    fn acknowledgement_dir(&self) -> &Path {
        &self.acknowledgements
    }
}

pub(crate) fn unix_time_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("wall clock is before the Unix epoch")?
        .as_millis();
    u64::try_from(millis).context("wall clock milliseconds overflow u64")
}

fn require_snapshot_shape(
    snapshot: &S19kEnduranceSnapshot,
    previous: Option<&S19kEnduranceSnapshot>,
) -> Result<()> {
    require_safe_text(&snapshot.pool_state, "pool state")?;
    anyhow::ensure!(
        snapshot.gpio437 == 0,
        "endurance requires energized GPIO437=0"
    );
    anyhow::ensure!(snapshot.fan_pwm <= 100, "endurance fan PWM is invalid");
    anyhow::ensure!(
        snapshot.hottest_temp_millic < snapshot.dangerous_temp_millic,
        "endurance snapshot is at or above dangerous temperature"
    );
    anyhow::ensure!(
        !snapshot.fan_readings.is_empty() && snapshot.fan_readings.iter().all(|(_, rpm)| *rpm > 0),
        "endurance snapshot lacks complete spinning-fan evidence"
    );
    let fan_ids = snapshot
        .fan_readings
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        fan_ids.len() == snapshot.fan_readings.len(),
        "endurance snapshot contains duplicate fan channels"
    );
    anyhow::ensure!(
        snapshot
            .paths
            .iter()
            .map(|path| path.path.as_str())
            .eq(["/dev/ttyS1", "/dev/ttyS2"]),
        "endurance snapshot does not contain the exact ordered ttyS1/ttyS2 authority"
    );
    for path in &snapshot.paths {
        require_safe_text(&path.path, "UART path")?;
        anyhow::ensure!(
            path.complete_77_at_work_baud && path.chips == 77,
            "endurance geometry is not Complete77 at work baud on {}",
            path.path
        );
    }
    if let Some(previous) = previous {
        anyhow::ensure!(
            previous.paths.len() == snapshot.paths.len(),
            "endurance required UART count changed"
        );
        anyhow::ensure!(
            previous
                .fan_readings
                .iter()
                .map(|(id, _)| *id)
                .eq(snapshot.fan_readings.iter().map(|(id, _)| *id)),
            "endurance fan channel identity or ordering changed"
        );
    }
    Ok(())
}

fn create_private_directory(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        !path.exists() && std::fs::symlink_metadata(path).is_err(),
        "{label} already exists"
    );
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("cannot create {label} at {}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.gid() == unsafe { libc::getegid() }
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "{label} is not an exact private directory"
    );
    Ok(())
}

fn publish_no_clobber(parent: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    publish_no_clobber_linked(parent, name, bytes)?;
    fsync_directory(parent)
}

/// Publish a fully written, fsynced, and prevalidated inode under a new name.
///
/// This deliberately does not fsync `parent`: the minute-segment caller must
/// first commit the published inode to its in-memory chain so any directory
/// sync failure remains representable in the typed failure terminal.  Other
/// callers use `publish_no_clobber`, which immediately performs that sync.
fn publish_no_clobber_linked(parent: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    require_safe_text(name, "evidence filename")?;
    let destination = parent.join(name);
    anyhow::ensure!(
        !destination.exists() && std::fs::symlink_metadata(&destination).is_err(),
        "endurance evidence destination already exists: {}",
        destination.display()
    );
    let scratch = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    anyhow::ensure!(
        !scratch.exists() && std::fs::symlink_metadata(&scratch).is_err(),
        "endurance evidence scratch already exists"
    );
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&scratch)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.gid() == unsafe { libc::getegid() }
                && metadata.permissions().mode() & 0o7777 == 0o600
                && metadata.len() == bytes.len() as u64,
            "prepared endurance evidence identity is inexact"
        );
        std::fs::hard_link(&scratch, &destination)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&scratch);
    result
}

fn fsync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn read_exact_kv(
    path: &Path,
    expected_fields: usize,
    label: &str,
) -> Result<BTreeMap<String, String>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {label}"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.gid() == unsafe { libc::getegid() }
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.len() <= 4096,
        "{label} has an inexact type/owner/mode/size"
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.ends_with(b"\n"), "{label} lacks a terminal newline");
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("{label} has a malformed field"))?;
        require_safe_text(key, "acknowledgement key")?;
        require_safe_text(value, "acknowledgement value")?;
        anyhow::ensure!(
            !key.is_empty() && fields.insert(key.to_string(), value.to_string()).is_none(),
            "{label} has an empty or duplicate field"
        );
    }
    anyhow::ensure!(
        fields.len() == expected_fields,
        "{label} has an inexact field set"
    );
    Ok(fields)
}

fn require_field(fields: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<()> {
    anyhow::ensure!(
        fields.get(key).map(String::as_str) == Some(expected),
        "endurance acknowledgement {key} mismatch"
    );
    Ok(())
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{label} is not a lowercase SHA-256 digest"
    );
    Ok(())
}

fn parse_positive_u64(value: &str, label: &str) -> Result<u64> {
    anyhow::ensure!(
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value == "0" || !value.starts_with('0')),
        "{label} is not canonical unsigned decimal"
    );
    let parsed = value.parse::<u64>()?;
    anyhow::ensure!(parsed > 0, "{label} must be positive");
    Ok(parsed)
}

fn require_safe_text(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        !value.contains(['\0', '\n', '\r', '=']),
        "{label} contains a forbidden delimiter"
    );
    Ok(())
}

fn require_bounded_text(value: &str, label: &str, maximum: usize) -> Result<()> {
    require_safe_text(value, label)?;
    anyhow::ensure!(
        !value.is_empty() && value.len() <= maximum,
        "{label} has invalid length"
    );
    Ok(())
}

fn hash_bound_field(hasher: &mut Sha256, key: &[u8], value: &[u8]) {
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn canonical_lineage(lineage: &S19kEnduranceShareLineage) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in [
        ("elapsed_s", lineage.elapsed_s.to_string()),
        ("accepted", lineage.accepted.to_string()),
        ("path", lineage.path.clone()),
        ("attribution", lineage.attribution.clone()),
        ("work_generation", lineage.work_generation.clone()),
        ("worker_name", lineage.worker_name.clone()),
        ("job_id", lineage.job_id.clone()),
        ("extranonce2", lineage.extranonce2.clone()),
        ("ntime", lineage.ntime.clone()),
        ("nonce", lineage.nonce.clone()),
        (
            "version_bits",
            lineage
                .version_bits
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
        ("version", format!("{:08x}", lineage.version)),
    ] {
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn segment_name(sequence: u64) -> String {
    format!("segment.{sequence:06}.kv")
}

fn ack_name(sequence: u64) -> String {
    format!("ack.{sequence:06}.kv")
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn format_fans(readings: &[(u8, u32)]) -> String {
    readings
        .iter()
        .map(|(id, rpm)| format!("{id}:{rpm}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn push_field(content: &mut String, key: &str, value: impl std::fmt::Display) {
    use std::fmt::Write as _;
    writeln!(content, "{key}={value}").expect("writing to String cannot fail");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "dcent-s19k-endurance-test-{}-{nonce}-{label}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        parent
    }

    fn snapshot(monotonic_ms: u64, wall_unix_ms: u64) -> S19kEnduranceSnapshot {
        S19kEnduranceSnapshot {
            monotonic_ms,
            wall_unix_ms,
            pool_state: "Alive".to_string(),
            aggregate_hashrate_millighs: monotonic_ms.saturating_mul(1_000),
            hottest_temp_millic: 64_000,
            dangerous_temp_millic: 90_000,
            fan_pwm: 100,
            fan_readings: vec![(0, 3_027), (1, 3_040), (2, 3_055), (3, 3_057)],
            gpio437: 0,
            paths: vec![
                S19kEndurancePathSnapshot {
                    path: "/dev/ttyS1".to_string(),
                    chips: 77,
                    complete_77_at_work_baud: true,
                    tx_frames: monotonic_ms / 10,
                    rx_wire_bytes: monotonic_ms / 2,
                    rx_frames: monotonic_ms / 50,
                    valid_nonces: monotonic_ms / 100,
                    shares_submitted: monotonic_ms / 10_000,
                    shares_accepted: monotonic_ms / 20_000,
                    shares_rejected: 0,
                },
                S19kEndurancePathSnapshot {
                    path: "/dev/ttyS2".to_string(),
                    chips: 77,
                    complete_77_at_work_baud: true,
                    tx_frames: monotonic_ms / 10,
                    rx_wire_bytes: monotonic_ms / 2,
                    rx_frames: monotonic_ms / 50,
                    valid_nonces: monotonic_ms / 100,
                    shares_submitted: monotonic_ms / 10_000,
                    shares_accepted: monotonic_ms / 20_000,
                    shares_rejected: 0,
                },
            ],
        }
    }

    fn create_evidence(parent: &Path) -> S19kEnduranceEvidence {
        S19kEnduranceEvidence::create(
            parent.join(S19K_ENDURANCE_EVIDENCE_DIR),
            "a".repeat(64),
            123,
            "b".repeat(64),
            snapshot(0, 1_700_000_000_000),
        )
        .unwrap()
    }

    fn publish_ack(
        evidence: &S19kEnduranceEvidence,
        receipt: &S19kEnduranceSealReceipt,
        predecessor_manifest: &str,
        manifest: &str,
    ) {
        let mut content = String::new();
        push_field(&mut content, "schema", ACK_SCHEMA);
        push_field(&mut content, "sequence", receipt.sequence);
        push_field(&mut content, "segment_sha256", &receipt.sha256);
        push_field(&mut content, "segment_bytes", receipt.bytes);
        push_field(
            &mut content,
            "predecessor_manifest_sha256",
            predecessor_manifest,
        );
        push_field(&mut content, "off_target_manifest_sha256", manifest);
        push_field(
            &mut content,
            "off_target_manifest_bytes",
            100 + receipt.sequence,
        );
        push_field(&mut content, "collector_wall_unix_ms", 1_700_000_100_000u64);
        push_field(
            &mut content,
            "publication",
            "no-clobber-hard-link-after-fsync",
        );
        publish_no_clobber(
            evidence.acknowledgement_dir(),
            &ack_name(receipt.sequence),
            content.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn endurance_gate_never_passes_before_24h_and_fails_at_26h() {
        assert_eq!(S19K_ENDURANCE_MAX_SEGMENTS, 1_561);
        assert_eq!(
            s19k_endurance_gate_decision(S19K_ENDURANCE_MIN_S - 1, true, true),
            S19kEnduranceGateDecision::Continue
        );
        assert_eq!(
            s19k_endurance_gate_decision(S19K_ENDURANCE_MIN_S, true, false),
            S19kEnduranceGateDecision::BeginFinalization
        );
        assert_eq!(
            s19k_endurance_gate_decision(S19K_ENDURANCE_MIN_S, true, true),
            S19kEnduranceGateDecision::Pass
        );
        assert_eq!(
            s19k_endurance_gate_decision(S19K_ENDURANCE_MAX_S, false, false),
            S19kEnduranceGateDecision::DeadlineExceeded
        );
    }

    #[test]
    fn segment_chain_requires_exact_ack_and_manifest_predecessor() {
        let parent = temp_root("chain");
        let mut evidence = create_evidence(&parent);
        let now = Instant::now();
        let first = evidence
            .seal_minute(snapshot(60_000, 1_700_000_060_000), false, now)
            .unwrap();
        let manifest = "c".repeat(64);
        publish_ack(
            &evidence,
            &first,
            S19K_ENDURANCE_GENESIS_MANIFEST_SHA256,
            &manifest,
        );
        assert_eq!(evidence.poll_acknowledgements(now).unwrap(), 1);
        let second = evidence
            .seal_minute(snapshot(120_000, 1_700_000_120_000), false, now)
            .unwrap();
        publish_ack(
            &evidence,
            &second,
            S19K_ENDURANCE_GENESIS_MANIFEST_SHA256,
            &"d".repeat(64),
        );
        assert!(evidence.poll_acknowledgements(now).is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn collector_timeout_and_high_water_fail_closed() {
        let parent = temp_root("timeout");
        let mut evidence = create_evidence(&parent);
        let now = Instant::now();
        evidence
            .seal_minute(snapshot(60_000, 1_700_000_060_000), false, now)
            .unwrap();
        assert!(evidence
            .poll_acknowledgements(now + Duration::from_secs(S19K_ENDURANCE_ACK_TIMEOUT_S))
            .is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn high_water_refuses_before_publishing_an_unrepresented_segment() {
        let parent = temp_root("high-water-publication");
        let mut evidence = create_evidence(&parent);
        let now = Instant::now();
        for sequence in 0..S19K_ENDURANCE_MAX_UNACKED_SEGMENTS {
            let elapsed_ms = (sequence as u64 + 1) * 60_000;
            evidence
                .seal_minute(
                    snapshot(elapsed_ms, 1_700_000_000_000 + elapsed_ms),
                    false,
                    now,
                )
                .unwrap();
        }
        let refused_sequence = S19K_ENDURANCE_MAX_UNACKED_SEGMENTS as u64;
        let elapsed_ms = (refused_sequence + 1) * 60_000;
        assert!(evidence
            .seal_minute(
                snapshot(elapsed_ms, 1_700_000_000_000 + elapsed_ms),
                false,
                now,
            )
            .is_err());
        assert_eq!(evidence.next_sequence, refused_sequence);
        assert_eq!(evidence.unacknowledged.len(), refused_sequence as usize);
        assert!(!evidence
            .segments
            .join(segment_name(refused_sequence))
            .exists());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn failure_terminal_requires_checked_safeoff_and_hex_encodes_reason() {
        let parent = temp_root("failure-terminal");
        let evidence = create_evidence(&parent);
        assert!(evidence
            .publish_failure_terminal(61, "collector=lost\ncontext", false)
            .is_err());
        assert!(!evidence.root.join(S19K_ENDURANCE_FAILURE_FILE).exists());
        evidence
            .publish_failure_terminal(61, "collector=lost\ncontext", true)
            .unwrap();
        let content =
            std::fs::read_to_string(evidence.root.join(S19K_ENDURANCE_FAILURE_FILE)).unwrap();
        assert!(content.contains("outcome=fail-after-checked-safeoff\n"));
        assert!(content.contains("checked_safeoff=true\n"));
        assert!(content
            .contains("failure_reason_utf8_hex=636f6c6c6563746f723d6c6f73740a636f6e74657874\n"));
        assert!(!content.contains("collector=lost"));
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn accepted_share_is_required_from_each_uart_in_every_six_hour_window() {
        let parent = temp_root("windows");
        let mut evidence = create_evidence(&parent);
        for window in 0..S19K_ENDURANCE_WINDOW_COUNT {
            for path in ["/dev/ttyS1", "/dev/ttyS2"] {
                evidence
                    .record_share_lineage(S19kEnduranceShareLineage {
                        elapsed_s: window as u64 * S19K_ENDURANCE_WINDOW_S + 1,
                        accepted: true,
                        path: path.to_string(),
                        attribution: "raw-job-byte".to_string(),
                        work_generation: "1:1".to_string(),
                        worker_name: "worker".to_string(),
                        job_id: format!("job-{window}"),
                        extranonce2: "00000000".to_string(),
                        ntime: "01020304".to_string(),
                        nonce: "11223344".to_string(),
                        version_bits: None,
                        version: 0x2000_0000,
                    })
                    .unwrap();
            }
        }
        assert!(evidence.acceptance_complete());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn geometry_counter_and_clock_regressions_are_rejected() {
        let parent = temp_root("regression");
        let mut evidence = create_evidence(&parent);
        let now = Instant::now();
        let mut bad = snapshot(60_000, 1_700_000_060_000);
        bad.paths[0].chips = 76;
        assert!(evidence.seal_minute(bad, false, now).is_err());
        let too_short = snapshot(10_000, 1_700_000_010_000);
        assert!(evidence.seal_minute(too_short, false, now).is_err());
        let mut stalled = snapshot(60_000, 1_700_000_060_000);
        stalled.paths[0].valid_nonces = 0;
        assert!(evidence.seal_minute(stalled, false, now).is_err());
        let mut fan_loss = snapshot(60_000, 1_700_000_060_000);
        fan_loss.fan_readings.pop();
        assert!(evidence.seal_minute(fan_loss, false, now).is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }
}
