//! Repair recommendation engine — physical fault localization from a ChipMap.
//!
//! This turns the [`ChipMap`](crate::chip_health::ChipMap) from *a picture* into
//! *a diagnosis*. Every competitor firmware (BraiinsOS / LuxOS / VNish) reports
//! per-chip health as a colored grid and stops there; a D-Central repair tech
//! then spends the first ~30 minutes of every intake translating that grid into
//! "which component is the fault" by hand. This module encodes that bench
//! knowledge as deterministic, pure rules so the firmware does the first pass.
//!
//! # Honesty / evidence grade
//!
//! Every recommendation is **`Inferred`** (see [`crate::evidence::EvidenceKind`])
//! — a *pattern inference* over the ChipMap, never a measurement. It does NOT
//! energize hardware, mutate state, or claim a measured verdict. It is a
//! triage hint that points a tech at the most probable component and the next
//! bench step; it is explicitly not a pass/fail grade. This keeps it inside the
//! diagnostics crate's evidence discipline: it consumes graded snapshot data and
//! emits a clearly-labeled inference, nothing stronger.
//!
//! # The core physical model (Antminer hashboard, BM13xx daisy chain)
//!
//! ChipMap cells are ordered by chip index, which is the CI→CO daisy-chain
//! position along the hashboard. The chain carries the UART clock/data from the
//! first chip to the last. Power is delivered per **voltage domain**: a group of
//! N adjacent chips share one DC-DC step-down. Those two facts drive the rules:
//!
//! * A dead chip / open trace **breaks the chain at that point** — every chip
//!   downstream of it goes dark too. So a contiguous silent run reaching the end
//!   of the chain localizes the fault to the **first** silent chip (the break),
//!   not to all the dark chips after it.
//! * A DC-DC **domain regulator failure** de-powers a whole domain-aligned group
//!   at once, which also breaks the chain there. The discriminator between an
//!   open-trace break and a domain-regulator failure is **granularity**: a dark
//!   region that begins exactly on a voltage-domain boundary and spans a full
//!   domain points at the regulator; one that begins mid-domain points at a
//!   single chip / cold-solder joint.
//! * If chips report but produce ~no nonces while the chain still reaches chips
//!   *after* them, those specific chips are weak/dead silicon (they pass the
//!   daisy chain through but don't hash), not a chain break.
//! * High CRC with healthy nonce production is a **signal-integrity** problem
//!   (connector seating / ribbon / baud), not silicon — the chips compute fine,
//!   the wire corrupts frames.
//! * Uniform low health across the whole board with no healthy outliers points
//!   at the shared **rail / PSU** (sag), not at individual chips.
//!
//! All thresholds are named constants with rationale; the function is a pure,
//! deterministic transform (no clock, no I/O, sorted output) so it is fully
//! host-testable and reproducible.

// clippy::indexing_slicing / expect_used: this module is PURE ANALYSIS over two
// parallel, same-length vectors (`cells` and `dead`, both length `n`); every index
// here is either a loop bound over `0..n`, or a cursor the surrounding code has
// already proven in range (see the `s > 0 is guaranteed here` note), or an
// `unwrap` reached only inside a branch that tested the same `Option`. It performs
// no hardware I/O. Converting these to `.get()` would add unreachable `None` arms
// to a recommendation engine whose whole job is to reason about the vectors it was
// handed.
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use serde::{Deserialize, Serialize};

use crate::chip_health::ChipMap;
use crate::evidence::EvidenceKind;

/// Health score at or below which a chip is treated as dead / non-producing.
/// Matches `builders.rs`'s `dead_chip_addresses` threshold (`<= 0.01`) so the
/// two producers agree on what "dead" means.
const DEAD_SCORE: f32 = 0.01;

/// Health score at or above which a chip is treated as fully healthy (Green).
const HEALTHY_SCORE: f32 = 0.90;

/// Health score below which a non-dead chip is treated as weak (Yellow/Orange/Red).
const WEAK_SCORE: f32 = 0.70;

/// Fraction of non-dead chips that must be weak — with zero healthy chips and
/// low health variance — to call a uniform whole-board rail/PSU sag.
const UNIFORM_SAG_WEAK_FRACTION: f32 = 0.60;

/// Health standard-deviation ceiling for the "uniform" sag signature. Above
/// this the degradation is uneven (scattered silicon), not a shared-rail sag.
const UNIFORM_SAG_STDDEV_MAX: f32 = 0.12;

/// CRC-to-nonce ratio (as a percentage) above which frame corruption dominates
/// enough to implicate signal integrity rather than silicon. 5% is well above
/// a healthy board's residual CRC rate.
const SIGNAL_INTEGRITY_CRC_PERCENT: u64 = 5;

/// Cap on how many chip addresses/indices a single recommendation lists, so a
/// pathological board can't emit an unbounded blob.
const MAX_LISTED_CHIPS: usize = 32;

/// The physical component a repair recommendation implicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspectedComponent {
    /// Open CI→CO daisy-chain break (dead chip / cold-solder joint / damaged
    /// trace) at a specific chip position; everything downstream is dark.
    ChainBreak,
    /// A DC-DC voltage-domain regulator feeding a domain-aligned group of chips.
    VoltageDomain,
    /// The shared board rail or external PSU (uniform whole-board sag, or the
    /// whole chain unpowered).
    PowerRail,
    /// Cooling / heatsink contact / airflow (hot + weak spatial cluster). Only
    /// fires when per-chip thermal data is present.
    Cooling,
    /// Signal integrity: hashboard connector seating, ribbon cable, or baud —
    /// high CRC with healthy nonce production.
    SignalIntegrity,
    /// Genuinely weak/dead individual silicon at specific chip positions, with
    /// healthy neighbors and an intact chain.
    WeakSilicon,
}

impl SuspectedComponent {
    /// Stable machine-readable slug.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChainBreak => "chain_break",
            Self::VoltageDomain => "voltage_domain",
            Self::PowerRail => "power_rail",
            Self::Cooling => "cooling",
            Self::SignalIntegrity => "signal_integrity",
            Self::WeakSilicon => "weak_silicon",
        }
    }

    /// Deterministic priority rank (lower = more structural / higher priority).
    /// Used only to sort recommendations for stable, useful presentation.
    fn priority_rank(self) -> u8 {
        match self {
            Self::PowerRail => 0,
            Self::VoltageDomain => 1,
            Self::ChainBreak => 2,
            Self::SignalIntegrity => 3,
            Self::Cooling => 4,
            Self::WeakSilicon => 5,
        }
    }
}

/// Confidence in a repair recommendation (all recommendations remain `Inferred`
/// evidence-grade regardless — this ranks how strongly the pattern matches).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairConfidence {
    Low,
    Medium,
    High,
}

impl RepairConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Medium => 1,
            Self::Low => 2,
        }
    }
}

/// A single, localized repair recommendation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairRecommendation {
    /// Chain this recommendation is about.
    pub chain_id: u8,
    /// The physical component implicated.
    pub suspected_component: SuspectedComponent,
    /// How strongly the observed pattern matches this diagnosis.
    pub confidence: RepairConfidence,
    /// Evidence grade — always `Inferred`. This is a pattern inference over the
    /// ChipMap, never a measurement (kept explicit for the crate's honesty model).
    pub provenance: EvidenceKind,
    /// One-line human diagnosis.
    pub summary: String,
    /// The specific observations that triggered this diagnosis.
    pub evidence: Vec<String>,
    /// ChipMap cell indices implicated (chain positions), capped.
    pub suspect_chip_indices: Vec<u16>,
    /// Chip hardware addresses implicated, capped.
    pub suspect_chip_addresses: Vec<u8>,
    /// The concrete next bench action for a technician.
    pub bench_next_step: String,
}

/// Optional board context that sharpens localization when known from the
/// silicon profile. All fields are optional; absent context simply disables the
/// rules that need it (no rule ever fabricates data it doesn't have).
#[derive(Debug, Clone, Default)]
pub struct RepairContext {
    /// Chips per voltage domain (contiguous grouping along the chain), from the
    /// board's silicon profile. `None` disables domain-boundary discrimination,
    /// in which case a tail-dark run is reported as a `ChainBreak` only.
    pub voltage_domain_size: Option<u16>,
}

impl RepairContext {
    /// Build context from a known ASIC chip ID's default domain geometry.
    ///
    /// Values match RE-verified autotuner `voltage_domain` topology presets
    /// (chips_per_domain). Unknown IDs yield `None` (domain-boundary rule off).
    pub fn for_chip_id(chip_id: u16) -> Self {
        Self {
            voltage_domain_size: default_voltage_domain_size(chip_id),
        }
    }
}

/// Default chips-per-voltage-domain for a registered ASIC family.
///
/// Pure offline table mirrored from `dcentrald_autotuner::voltage_domain`
/// verified topologies — not a live probe. Enables domain-boundary repair
/// rules without HAL.
pub fn default_voltage_domain_size(chip_id: u16) -> Option<u16> {
    match chip_id {
        0x1387 => Some(63), // S9: 1 domain × 63 chips
        0x1398 => Some(2),  // S19: 38 domains × 2
        0x1362 => Some(3),  // S19j Pro: 42 domains × 3
        0x1366 => Some(10), // S19 XP: 11 domains × 10
        0x1368 => Some(9),  // S21: 12 domains × 9
        0x1370 => Some(7),  // S21 XP: 13 domains × 7
        _ => None,
    }
}

/// Analyze a ChipMap and return localized repair recommendations, most
/// structural / highest-confidence first. An empty result means no fault
/// pattern was recognized (a healthy board, or too little data).
///
/// Pure and deterministic: same input → same output, no clock or I/O.
pub fn analyze_chipmap(map: &ChipMap, ctx: &RepairContext) -> Vec<RepairRecommendation> {
    let cells = &map.cells;
    let n = cells.len();
    if n == 0 {
        return Vec::new();
    }

    let dead: Vec<bool> = cells
        .iter()
        .map(|c| !c.health_score.is_finite() || c.health_score <= DEAD_SCORE)
        .collect();
    let dead_count = dead.iter().filter(|&&d| d).count();

    let mut out: Vec<RepairRecommendation> = Vec::new();

    // ── Rule: whole chain dark → shared rail / PSU / unpowered board ─────────
    if dead_count == n {
        out.push(RepairRecommendation {
            chain_id: map.chain_id,
            suspected_component: SuspectedComponent::PowerRail,
            confidence: RepairConfidence::High,
            provenance: EvidenceKind::Inferred,
            summary: format!(
                "Chain {}: all {} chips silent — the board rail is unpowered or collapsed.",
                map.chain_id, n
            ),
            evidence: vec![format!(
                "Every one of the {n} enumerated chips reports zero/near-zero health; a chain-wide blackout is a shared-power fault, not per-chip silicon."
            )],
            suspect_chip_indices: Vec::new(),
            suspect_chip_addresses: Vec::new(),
            bench_next_step:
                "Verify the hashboard power connector and the board's main rail / PSU output before suspecting any chip; measure the domain rails cold."
                    .to_string(),
        });
        return out;
    }

    // ── Rule: terminal dark run → chain break vs. domain-regulator failure ───
    // Find the start `s` of the contiguous dead run that reaches the last chip.
    let mut s = n;
    while s > 0 && dead[s - 1] {
        s -= 1;
    }
    // `s < n` ⇒ a terminal dark run exists; `s > 0` is guaranteed here because
    // `s == 0` would mean the whole chain is dark (handled above).
    if s < n {
        let run_len = n - s;
        let first = &cells[s];
        let predecessor = &cells[s - 1];
        let domain = ctx.voltage_domain_size.map(usize::from).filter(|&d| d > 0);
        let starts_on_domain_boundary = domain
            .map(|d| s.is_multiple_of(d) && run_len >= d)
            .unwrap_or(false);

        let (indices, addresses) = collect_chips(cells, s..n);

        if starts_on_domain_boundary {
            let d = domain.unwrap();
            out.push(RepairRecommendation {
                chain_id: map.chain_id,
                suspected_component: SuspectedComponent::VoltageDomain,
                confidence: RepairConfidence::High,
                provenance: EvidenceKind::Inferred,
                summary: format!(
                    "Chain {}: chips {}..{} went dark starting exactly on a voltage-domain boundary — the DC-DC domain feeding them likely lost regulation.",
                    map.chain_id, s, n - 1
                ),
                evidence: vec![
                    format!(
                        "The dark region begins at chip {s}, which is aligned to the {d}-chip voltage-domain boundary, and spans {run_len} chips to the end of the chain."
                    ),
                    format!(
                        "Chip {} (index {}) immediately before the boundary is healthy (score {:.2}), so the upstream chain and its domain are fine.",
                        predecessor.index, s - 1, predecessor.health_score
                    ),
                    "A whole domain going dark on its boundary is a DC-DC regulator signature, distinct from a single-chip open-trace break.".to_string(),
                ],
                suspect_chip_indices: indices,
                suspect_chip_addresses: addresses,
                bench_next_step: format!(
                    "Inspect the DC-DC regulator (inductor / MOSFET / feedback) for the voltage domain starting at chip {s}; measure that domain's rail before reflowing chips."
                ),
            });
        } else {
            out.push(RepairRecommendation {
                chain_id: map.chain_id,
                suspected_component: SuspectedComponent::ChainBreak,
                confidence: RepairConfidence::High,
                provenance: EvidenceKind::Inferred,
                summary: format!(
                    "Chain {}: chips {}..{} are silent to the end of the chain while chip {} before them is healthy — an open CI→CO break at chip {}.",
                    map.chain_id, s, n - 1, s - 1, s
                ),
                evidence: vec![
                    format!(
                        "{run_len} contiguous chips (indices {s}..{}) produce nothing, and the break reaches the end of the daisy chain.",
                        n - 1
                    ),
                    format!(
                        "Chip at index {} (address 0x{:02X}) just upstream is healthy (score {:.2}), so the fault is the boundary between it and chip {s}.",
                        s - 1, predecessor.address, predecessor.health_score
                    ),
                    "Everything downstream of a broken chip in a daisy chain goes dark — the first silent chip is the real fault, not the whole dark tail.".to_string(),
                ],
                suspect_chip_indices: vec![first.index],
                suspect_chip_addresses: vec![first.address],
                bench_next_step: format!(
                    "Reflow / inspect the solder and bonding of chip {s} (address 0x{:02X}) and its CI/CO traces first; only replace it if the joint is sound.",
                    first.address
                ),
            });
        }
    }

    // ── Rule: interior dark chips with a live chain past them → weak silicon ─
    // Dead cells that are NOT part of the terminal run: the chain still reaches
    // chips after them, so they enumerate/pass-through but don't hash.
    let terminal_start = if s < n { s } else { n };
    let interior_dead: Vec<usize> = (0..terminal_start).filter(|&i| dead[i]).collect();
    // Also flag clearly-weak (non-dead) outliers when the board is mostly healthy.
    let healthy_count = cells
        .iter()
        .filter(|c| c.health_score.is_finite() && c.health_score >= HEALTHY_SCORE)
        .count();
    let mut weak_positions = interior_dead.clone();
    if healthy_count * 2 >= n {
        for (i, c) in cells.iter().enumerate() {
            if i < terminal_start
                && !dead[i]
                && c.health_score.is_finite()
                && c.health_score < WEAK_SCORE
            {
                weak_positions.push(i);
            }
        }
    }
    weak_positions.sort_unstable();
    weak_positions.dedup();
    if !weak_positions.is_empty() {
        let (indices, addresses) = collect_chips_from_positions(cells, &weak_positions);
        out.push(RepairRecommendation {
            chain_id: map.chain_id,
            suspected_component: SuspectedComponent::WeakSilicon,
            confidence: RepairConfidence::Medium,
            provenance: EvidenceKind::Inferred,
            summary: format!(
                "Chain {}: {} isolated weak/dead chip(s) with an intact chain and healthy neighbors — specific weak silicon.",
                map.chain_id,
                weak_positions.len()
            ),
            evidence: vec![
                format!(
                    "These chips underproduce while the daisy chain still reaches chips downstream of them, so they are individually weak rather than a chain break."
                ),
            ],
            suspect_chip_indices: indices,
            suspect_chip_addresses: addresses,
            bench_next_step:
                "Target these specific chip positions: check their solder/bonding; if joints are sound the dies are degraded and set the board's realistic max frequency."
                    .to_string(),
        });
    }

    // ── Rule: uniform whole-board sag → shared rail / PSU ────────────────────
    if let Some(rail) = detect_uniform_sag(map, &dead, dead_count) {
        out.push(rail);
    }

    // ── Rule: high CRC with healthy nonce production → signal integrity ──────
    if let Some(si) = detect_signal_integrity(map, &dead) {
        out.push(si);
    }

    // ── Rule: hot + weak spatial cluster → cooling (only if thermal data) ────
    if let Some(cooling) = detect_cooling(map, &dead) {
        out.push(cooling);
    }

    // Stable, useful ordering: highest confidence first, then most-structural.
    out.sort_by(|a, b| {
        a.confidence.rank().cmp(&b.confidence.rank()).then(
            a.suspected_component
                .priority_rank()
                .cmp(&b.suspected_component.priority_rank()),
        )
    });
    out
}

/// Uniform whole-board degradation with no healthy outliers ⇒ shared-rail sag.
fn detect_uniform_sag(
    map: &ChipMap,
    dead: &[bool],
    dead_count: usize,
) -> Option<RepairRecommendation> {
    let cells = &map.cells;
    let n = cells.len();
    // Only meaningful when most chips are alive-but-weak; a large dead fraction
    // is already explained by the structural rules above.
    let alive: Vec<f32> = cells
        .iter()
        .zip(dead)
        .filter(|(_, &d)| !d)
        .map(|(c, _)| c.health_score)
        .filter(|s| s.is_finite())
        .collect();
    if alive.len() < 4 || dead_count * 2 > n {
        return None;
    }
    let healthy = alive.iter().filter(|&&s| s >= HEALTHY_SCORE).count();
    let weak = alive.iter().filter(|&&s| s < WEAK_SCORE).count();
    if healthy != 0 {
        return None; // any Green chip on a shared rail argues against a rail sag
    }
    if (weak as f32) < UNIFORM_SAG_WEAK_FRACTION * alive.len() as f32 {
        return None;
    }
    let mean = alive.iter().sum::<f32>() / alive.len() as f32;
    let var = alive.iter().map(|s| (s - mean).powi(2)).sum::<f32>() / alive.len() as f32;
    let stddev = var.sqrt();
    if stddev > UNIFORM_SAG_STDDEV_MAX {
        return None; // uneven degradation → scattered silicon, not a rail sag
    }
    Some(RepairRecommendation {
        chain_id: map.chain_id,
        suspected_component: SuspectedComponent::PowerRail,
        confidence: RepairConfidence::Medium,
        provenance: EvidenceKind::Inferred,
        summary: format!(
            "Chain {}: every chip is uniformly weak (mean health {:.2}, low spread) with no healthy outliers — a shared rail / PSU sag.",
            map.chain_id, mean
        ),
        evidence: vec![
            format!(
                "{weak} of {} live chips are below the weak threshold, none reach healthy, and health variance is low (σ={stddev:.3}) — the signature of every chip being under-fed the same way.",
                alive.len()
            ),
        ],
        suspect_chip_indices: Vec::new(),
        suspect_chip_addresses: Vec::new(),
        bench_next_step:
            "Measure the board input rail and each domain under load; check the PSU output and the hashboard power connector for droop before touching individual chips."
                .to_string(),
    })
}

/// High CRC-to-nonce ratio with the chips otherwise producing ⇒ signal integrity.
fn detect_signal_integrity(map: &ChipMap, dead: &[bool]) -> Option<RepairRecommendation> {
    let cells = &map.cells;
    let n = cells.len();
    let total_nonces: u64 = cells.iter().map(|c| c.nonce_count).sum();
    let total_crc: u64 = cells.iter().map(|c| u64::from(c.crc_errors)).sum();
    if total_nonces == 0 || total_crc == 0 {
        return None;
    }
    // The chips must be largely alive/producing for CRC to implicate the wire
    // rather than silicon.
    let alive = dead.iter().filter(|&&d| !d).count();
    if alive * 2 < n {
        return None;
    }
    if total_crc * 100 < SIGNAL_INTEGRITY_CRC_PERCENT * total_nonces {
        return None;
    }
    let crc_pct = (total_crc as f64 * 100.0) / total_nonces as f64;
    // Point at the worst offenders for the tech.
    let mut offenders: Vec<usize> = (0..n).filter(|&i| cells[i].crc_errors > 0).collect();
    offenders.sort_by(|&a, &b| cells[b].crc_errors.cmp(&cells[a].crc_errors));
    let (indices, addresses) = collect_chips_from_positions(cells, &offenders);
    Some(RepairRecommendation {
        chain_id: map.chain_id,
        suspected_component: SuspectedComponent::SignalIntegrity,
        confidence: RepairConfidence::Medium,
        provenance: EvidenceKind::Inferred,
        summary: format!(
            "Chain {}: chips are producing nonces but the CRC error rate is {crc_pct:.1}% — frame corruption on the wire, not weak silicon.",
            map.chain_id
        ),
        evidence: vec![
            format!(
                "{total_crc} CRC errors against {total_nonces} nonces ({crc_pct:.1}%) while the chain is largely alive: the dies compute correctly, the link corrupts frames."
            ),
        ],
        suspect_chip_indices: indices,
        suspect_chip_addresses: addresses,
        bench_next_step:
            "Reseat the hashboard control connector and ribbon; inspect it for damage; if it persists, drop the chain baud rate before suspecting the chips."
                .to_string(),
    })
}

/// Hot + weak spatial cluster ⇒ cooling. Only fires when per-chip thermal data
/// is present (`die_temp_c` or `anomaly_gradient`); today that data path is
/// usually absent, so this stays honestly inert rather than guessing.
fn detect_cooling(map: &ChipMap, dead: &[bool]) -> Option<RepairRecommendation> {
    let cells = &map.cells;
    let hot_weak: Vec<usize> = (0..cells.len())
        .filter(|&i| {
            if dead[i] {
                return false;
            }
            let c = &cells[i];
            let hot = c
                .die_temp_c
                .map(|t| t.is_finite() && t >= 95.0)
                .unwrap_or(false)
                || c.anomaly_gradient
                    .map(|g| g.is_finite() && g >= 8.0)
                    .unwrap_or(false);
            let weak = c.health_score.is_finite() && c.health_score < HEALTHY_SCORE;
            hot && weak
        })
        .collect();
    if hot_weak.len() < 2 {
        return None;
    }
    let (indices, addresses) = collect_chips_from_positions(cells, &hot_weak);
    Some(RepairRecommendation {
        chain_id: map.chain_id,
        suspected_component: SuspectedComponent::Cooling,
        confidence: RepairConfidence::Medium,
        provenance: EvidenceKind::Inferred,
        summary: format!(
            "Chain {}: a cluster of {} chips is both hot and underperforming — degraded cooling / heatsink contact.",
            map.chain_id,
            hot_weak.len()
        ),
        evidence: vec![
            "These chips run hot relative to the board while also losing hashrate, the signature of poor heatsink contact, dried paste, or blocked airflow over that area.".to_string(),
        ],
        suspect_chip_indices: indices,
        suspect_chip_addresses: addresses,
        bench_next_step:
            "Inspect the heatsink clamp/paste over these chip positions and confirm airflow; cut hash before raising fan noise per the home-thermal policy."
                .to_string(),
    })
}

/// Collect (indices, addresses) for cells in a half-open position range, capped.
fn collect_chips(
    cells: &[crate::chip_health::ChipMapCell],
    range: std::ops::Range<usize>,
) -> (Vec<u16>, Vec<u8>) {
    let positions: Vec<usize> = range.collect();
    collect_chips_from_positions(cells, &positions)
}

/// Collect (indices, addresses) for the given cell positions, capped and ordered
/// by position for determinism.
fn collect_chips_from_positions(
    cells: &[crate::chip_health::ChipMapCell],
    positions: &[usize],
) -> (Vec<u16>, Vec<u8>) {
    let mut indices = Vec::new();
    let mut addresses = Vec::new();
    for &p in positions.iter().take(MAX_LISTED_CHIPS) {
        if let Some(c) = cells.get(p) {
            indices.push(c.index);
            addresses.push(c.address);
        }
    }
    (indices, addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip_health::{ChipColor, ChipMap, ChipMapCell};

    /// Build a cell whose color is derived from the score (as the real builders do).
    fn cell(index: u16, address: u8, score: f32, nonces: u64, crc: u32) -> ChipMapCell {
        ChipMapCell {
            index,
            address,
            health_score: score,
            grade: 'C',
            color: ChipColor::from_score(score),
            frequency_mhz: 500,
            nonce_count: nonces,
            crc_errors: crc,
            expected_nonce_rate_hz: None,
            health_ts: None,
            die_temp_c: None,
            anomaly_gradient: None,
            anomaly_cross_slot_zscore: None,
            anomaly_nonce_deficit: None,
        }
    }

    /// Build a ChipMap from a list of (score, nonces, crc) tuples; chip index and
    /// address are assigned sequentially (address = index for readability).
    fn map_from(chain_id: u8, chips: &[(f32, u64, u32)]) -> ChipMap {
        let cells = chips
            .iter()
            .enumerate()
            .map(|(i, &(score, nonces, crc))| cell(i as u16, i as u8, score, nonces, crc))
            .collect();
        ChipMap {
            chain_id,
            chip_count: chips.len() as u16,
            columns: 8,
            rows: ((chips.len() + 7) / 8) as u8,
            cells,
        }
    }

    fn healthy(n: usize) -> Vec<(f32, u64, u32)> {
        vec![(0.98_f32, 1000, 0); n]
    }

    #[test]
    fn empty_map_yields_nothing() {
        let map = map_from(0, &[]);
        assert!(analyze_chipmap(&map, &RepairContext::default()).is_empty());
    }

    #[test]
    fn default_voltage_domain_size_matches_verified_topologies() {
        assert_eq!(default_voltage_domain_size(0x1362), Some(3));
        assert_eq!(default_voltage_domain_size(0x1368), Some(9));
        assert_eq!(default_voltage_domain_size(0x1398), Some(2));
        assert_eq!(default_voltage_domain_size(0xFFFF), None);
        assert_eq!(
            RepairContext::for_chip_id(0x1362).voltage_domain_size,
            Some(3)
        );
    }

    #[test]
    fn healthy_board_yields_no_recommendations() {
        let map = map_from(1, &healthy(16));
        assert!(analyze_chipmap(&map, &RepairContext::default()).is_empty());
    }

    #[test]
    fn whole_chain_dark_is_power_rail_high() {
        let map = map_from(2, &vec![(0.0_f32, 0, 0); 12]);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].suspected_component, SuspectedComponent::PowerRail);
        assert_eq!(recs[0].confidence, RepairConfidence::High);
        assert_eq!(recs[0].provenance, EvidenceKind::Inferred);
    }

    #[test]
    fn tail_dark_run_mid_domain_is_chain_break_at_first_silent_chip() {
        // 10 chips: 0..6 healthy, 7..9 silent. No domain info → chain break at 7.
        let mut chips = healthy(10);
        for c in chips.iter_mut().skip(7) {
            *c = (0.0, 0, 0);
        }
        let map = map_from(3, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        let brk = recs
            .iter()
            .find(|r| r.suspected_component == SuspectedComponent::ChainBreak)
            .expect("chain break expected");
        assert_eq!(brk.confidence, RepairConfidence::High);
        // Localizes to the FIRST silent chip (index 7), not all three dark chips.
        assert_eq!(brk.suspect_chip_indices, vec![7]);
        assert_eq!(brk.suspect_chip_addresses, vec![7]);
    }

    #[test]
    fn tail_dark_run_on_domain_boundary_is_voltage_domain() {
        // 16 chips, 8-chip domains. Chips 8..15 (the whole second domain) dark.
        let mut chips = healthy(16);
        for c in chips.iter_mut().skip(8) {
            *c = (0.0, 0, 0);
        }
        let map = map_from(4, &chips);
        let ctx = RepairContext {
            voltage_domain_size: Some(8),
        };
        let recs = analyze_chipmap(&map, &ctx);
        let dom = recs
            .iter()
            .find(|r| r.suspected_component == SuspectedComponent::VoltageDomain)
            .expect("voltage domain expected");
        assert_eq!(dom.confidence, RepairConfidence::High);
        assert_eq!(dom.suspect_chip_indices.len(), 8);
        // And it must NOT also emit a chain break for the same region.
        assert!(!recs
            .iter()
            .any(|r| r.suspected_component == SuspectedComponent::ChainBreak));
    }

    #[test]
    fn tail_dark_run_starting_mid_domain_is_chain_break_not_domain() {
        // 16 chips, 8-chip domains, dark from chip 10 (mid second domain) to end.
        let mut chips = healthy(16);
        for c in chips.iter_mut().skip(10) {
            *c = (0.0, 0, 0);
        }
        let map = map_from(5, &chips);
        let ctx = RepairContext {
            voltage_domain_size: Some(8),
        };
        let recs = analyze_chipmap(&map, &ctx);
        assert!(recs
            .iter()
            .any(|r| r.suspected_component == SuspectedComponent::ChainBreak));
        assert!(!recs
            .iter()
            .any(|r| r.suspected_component == SuspectedComponent::VoltageDomain));
    }

    #[test]
    fn interior_dead_chip_with_live_chain_is_weak_silicon_specific() {
        // 12 chips healthy except chip 5 dead; chain still reaches 6..11.
        let mut chips = healthy(12);
        chips[5] = (0.0, 0, 0);
        let map = map_from(6, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        let weak = recs
            .iter()
            .find(|r| r.suspected_component == SuspectedComponent::WeakSilicon)
            .expect("weak silicon expected");
        assert_eq!(weak.suspect_chip_indices, vec![5]);
        // Not a chain break (the chain is intact past chip 5).
        assert!(!recs
            .iter()
            .any(|r| r.suspected_component == SuspectedComponent::ChainBreak));
    }

    #[test]
    fn signal_integrity_fires_on_high_crc_with_healthy_nonces() {
        // All chips producing well but with heavy CRC (>5%).
        let chips: Vec<(f32, u64, u32)> = (0..12).map(|_| (0.95_f32, 1000_u64, 80_u32)).collect();
        let map = map_from(7, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        let si = recs
            .iter()
            .find(|r| r.suspected_component == SuspectedComponent::SignalIntegrity)
            .expect("signal integrity expected");
        assert_eq!(si.provenance, EvidenceKind::Inferred);
        assert!(!si.suspect_chip_addresses.is_empty());
    }

    #[test]
    fn low_crc_does_not_trigger_signal_integrity() {
        // 0.5% CRC — below threshold.
        let chips: Vec<(f32, u64, u32)> = (0..12).map(|_| (0.95_f32, 1000_u64, 5_u32)).collect();
        let map = map_from(8, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        assert!(!recs
            .iter()
            .any(|r| r.suspected_component == SuspectedComponent::SignalIntegrity));
    }

    #[test]
    fn uniform_weak_board_is_power_rail_sag() {
        // Every chip uniformly weak (~0.55), none healthy, none dead, low spread.
        let chips: Vec<(f32, u64, u32)> = (0..12).map(|_| (0.55_f32, 400_u64, 0_u32)).collect();
        let map = map_from(9, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        let rail = recs
            .iter()
            .find(|r| r.suspected_component == SuspectedComponent::PowerRail)
            .expect("power rail sag expected");
        assert_eq!(rail.confidence, RepairConfidence::Medium);
    }

    #[test]
    fn scattered_weak_with_healthy_chips_is_not_a_rail_sag() {
        // Half healthy, half weak → uneven, not a uniform rail sag.
        let mut chips = healthy(12);
        for c in chips.iter_mut().take(6) {
            *c = (0.55, 400, 0);
        }
        let map = map_from(10, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        assert!(!recs
            .iter()
            .any(|r| r.suspected_component == SuspectedComponent::PowerRail));
    }

    #[test]
    fn non_finite_score_is_treated_as_dead_not_healthy() {
        // A NaN-scored tail must localize as a fault, never be ignored as healthy.
        let mut chips = healthy(8);
        chips[7] = (f32::NAN, 0, 0);
        let map = map_from(11, &chips);
        let recs = analyze_chipmap(&map, &RepairContext::default());
        assert!(!recs.is_empty());
    }

    #[test]
    fn output_is_deterministic_and_confidence_sorted() {
        // A board with both a domain failure (High) and CRC noise (Medium):
        // 16 chips, second domain dark, first domain producing with heavy CRC.
        let mut chips: Vec<(f32, u64, u32)> =
            (0..8).map(|_| (0.95_f32, 1000_u64, 90_u32)).collect();
        chips.extend((0..8).map(|_| (0.0_f32, 0_u64, 0_u32)));
        let map = map_from(12, &chips);
        let ctx = RepairContext {
            voltage_domain_size: Some(8),
        };
        let a = analyze_chipmap(&map, &ctx);
        let b = analyze_chipmap(&map, &ctx);
        assert_eq!(a, b, "analysis must be deterministic");
        // Highest-confidence recommendation comes first.
        assert_eq!(a[0].confidence, RepairConfidence::High);
    }
}
