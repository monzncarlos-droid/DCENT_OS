//! Rank-33 (2026-08-03): declarative temperature-sensor topology + shared
//! coverage accounting.
//!
//! # What this is
//!
//! A thermal-facing view over [`crate::hashboard_topology`]: for every one of
//! the 50 registry SKUs it answers *which temperature sensors exist, at which
//! I²C address, through which transport (direct vs I²C-switch/mux), on which
//! physical board site, at which physical position* — plus one shared,
//! fail-closed coverage type ([`SensorSweep`] / [`SweepLedger`]) intended to
//! replace the repo's three bespoke coverage shapes over time:
//!
//! - `dcentrald-hal::platform::amlogic::AmlogicTemperatureCoverage`
//!   (per-slot inlet+outlet availability, 3 slots),
//! - `dcentrald::am3_bb_mining::Am3BbThermalSnapshot`
//!   (per-chain minimum-sample coverage + freshness),
//! - `dcentos-esp` `thermal_safety::MuxedDieFold`
//!   (counted mux-sweep coverage; `covered == expected`).
//!
//! **This pass is data + accounting ONLY.** It changes no thermal control
//! behaviour, fan curve, throttle threshold, or PID. The three call sites
//! above are deliberately NOT rewritten here (they live in files owned by
//! concurrent sessions); the mapping is proven by tests in
//! `tests/sensor_topology_coverage.rs`.
//!
//! # Provenance
//!
//! Every [`SensorSpec`] inherits the registry row's
//! [`DescriptorProvenance`] — currently always
//! `DeskJigDbExperimental` (ePIC-transcribed, v1.22.0-only, real typos; a
//! DCENT live measurement always outranks it). The jig reads the board bank
//! *via* the PIC, but the blanket `PIC1704@0x20` claim is contradicted by the
//! live-proven S21 NoPic finding (registry divergence #6), so this module
//! deliberately does **not** encode a PIC-mediated access path: transport
//! here is *board-level wiring* (direct-addressed vs switch-reached), never
//! controller routing. DCENT platform code remains the sole authority for how
//! a sensor is actually reached on a live unit.
//!
//! # The unknown-is-not-cool invariant (load-bearing)
//!
//! A missing sensor reading must never be confused with a reading of 0 °C,
//! and unknown coverage must never satisfy a safety check. Concretely:
//!
//! - [`SensorSweep::hottest_c`] is `None` when nothing was measured — there
//!   is no 0.0 default anywhere in this module.
//! - Non-finite readings (NaN/±inf) count as *failures*, not coverage —
//!   exactly the `MuxedDieFold` posture, and the opposite of the upstream
//!   `intChipTempMax ? intChipTempMax : tmp1075Max` fail-open this guards
//!   against.
//! - [`SensorSweep::known_cooler_than`] returns `false` whenever coverage is
//!   incomplete, even if every measured sensor is cool: the dies you cannot
//!   see tell you nothing. The converse, [`SensorSweep::measured_reaches`],
//!   stays available so a hot sensor that *was* measured can still trip an
//!   overtemp cut while coverage is incomplete — both flags are honoured,
//!   never traded against each other.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::hashboard_topology::{
    all_descriptors, DescriptorProvenance, HashboardDescriptor, SensorPlacement,
    SwitchSensorPlacement,
};

// ---------------------------------------------------------------------------
// Sensor topology model
// ---------------------------------------------------------------------------

/// Which physical board a sensor sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorSite {
    /// On the hashboard itself (per-chain).
    Hashboard,
    /// On the control board (per-unit, not per-chain).
    CtrlBoard,
}

/// Horizontal position zone, parsed fail-closed from the DB-verbatim label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardEdgeX {
    Left,
    Right,
}

/// Vertical position zone, parsed fail-closed from the DB-verbatim label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardEdgeY {
    Top,
    Bottom,
}

/// Physical position of a sensor on its board, for thermal-gradient work
/// (e.g. pairing a `Top` sensor against a `Bottom` sensor on the same board).
///
/// The corpus resolution is coarse (four quadrant labels), so this is a
/// *zone*, not a coordinate. `parse` fails closed: an unrecognized label
/// yields `None`, never a guessed zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SensorPosition {
    pub x: BoardEdgeX,
    pub y: BoardEdgeY,
}

impl SensorPosition {
    /// Parse the DB-verbatim `x`/`y` labels. Fail-closed: `None` on any
    /// label outside the pinned corpus domain (`left|right` × `top|bottom`).
    pub fn parse(x: &str, y: &str) -> Option<Self> {
        let x = match x {
            "left" => BoardEdgeX::Left,
            "right" => BoardEdgeX::Right,
            _ => return None,
        };
        let y = match y {
            "top" => BoardEdgeY::Top,
            "bottom" => BoardEdgeY::Bottom,
            _ => return None,
        };
        Some(SensorPosition { x, y })
    }
}

/// How a sensor is reached at the board-wiring level.
///
/// Deliberately NOT a controller-routing claim (no "via PIC" variant): the
/// jig reads the hashboard bank through the PIC, but S21 NoPic proves that
/// model is not universal (registry divergence #6). Platform code decides the
/// actual access path; this enum only records what the board's wiring
/// requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SensorTransport {
    /// Directly addressed on the board's sensor bus.
    DirectI2c {
        /// 7-bit device address.
        i2c_addr: u8,
    },
    /// Reached through an on-board I²C switch/mux (jig `switchsensor`).
    /// On the 9 boards that carry this bank, all four muxed sensors share
    /// one address (`0x4C`), so they are unreachable — and mutually
    /// indistinguishable — without driving the switch. A reader that
    /// ignores the mux CANNOT count these sensors as covered.
    I2cMuxed {
        /// 7-bit device address behind the switch.
        i2c_addr: u8,
        /// Chip position the sensor is thermally anchored to (verbatim jig
        /// `asic`; coordinate convention unadjudicated — do not derive
        /// placement math from it without a live cross-check).
        anchor_asic: u16,
        /// Verbatim jig `power_by_ctrlboard` where present. `None` = the
        /// source record omits the field (a transcription gap, NOT `false`).
        power_by_ctrlboard: Option<bool>,
    },
}

impl SensorTransport {
    /// The 7-bit device address, whichever transport reaches it.
    pub fn i2c_addr(&self) -> u8 {
        match *self {
            SensorTransport::DirectI2c { i2c_addr } => i2c_addr,
            SensorTransport::I2cMuxed { i2c_addr, .. } => i2c_addr,
        }
    }

    /// `true` when the sensor requires driving an I²C switch/mux.
    pub fn is_muxed(&self) -> bool {
        matches!(self, SensorTransport::I2cMuxed { .. })
    }
}

/// One declared temperature sensor: identity, site, transport, position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorSpec {
    /// Device type as the DB spells it (`"LM75A"` throughout the corpus).
    pub device: String,
    /// Which board the sensor sits on.
    pub site: SensorSite,
    /// How the board's wiring reaches it.
    pub transport: SensorTransport,
    /// Bank-local index (jig `index`).
    pub index: u8,
    /// Physical position zone on its board.
    pub position: SensorPosition,
    /// Provenance inherited from the registry row. Currently always
    /// desk/Experimental — never present as live-verified.
    pub provenance: DescriptorProvenance,
}

/// The complete declared sensor roster for one SKU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkuSensorTopology {
    /// Bitmain SKU string (registry key).
    pub sku: String,
    /// Row provenance (see [`SensorSpec::provenance`]).
    pub provenance: DescriptorProvenance,
    /// All declared sensors: direct hashboard bank, then muxed hashboard
    /// bank, then control-board bank.
    pub sensors: Vec<SensorSpec>,
}

impl SkuSensorTopology {
    /// All sensors on the hashboard (direct + muxed). Per-chain count.
    pub fn hashboard_sensors(&self) -> impl Iterator<Item = &SensorSpec> {
        self.sensors
            .iter()
            .filter(|s| s.site == SensorSite::Hashboard)
    }

    /// Control-board sensors. Per-unit, NOT per-chain.
    pub fn ctrl_board_sensors(&self) -> impl Iterator<Item = &SensorSpec> {
        self.sensors
            .iter()
            .filter(|s| s.site == SensorSite::CtrlBoard)
    }

    /// Mux-reached sensors only.
    pub fn muxed_sensors(&self) -> impl Iterator<Item = &SensorSpec> {
        self.sensors.iter().filter(|s| s.transport.is_muxed())
    }

    /// Directly-addressed sensors only (either site).
    pub fn direct_sensors(&self) -> impl Iterator<Item = &SensorSpec> {
        self.sensors.iter().filter(|s| !s.transport.is_muxed())
    }

    /// Expected sensor count on ONE hashboard/chain (direct + muxed).
    /// This is the honest per-chain `expected` for coverage accounting.
    pub fn expected_per_hashboard(&self) -> u16 {
        self.hashboard_sensors().count() as u16
    }

    /// Expected directly-addressed sensors on one hashboard.
    pub fn expected_direct_per_hashboard(&self) -> u16 {
        self.hashboard_sensors()
            .filter(|s| !s.transport.is_muxed())
            .count() as u16
    }

    /// Expected mux-reached sensors on one hashboard.
    pub fn expected_muxed_per_hashboard(&self) -> u16 {
        self.muxed_sensors().count() as u16
    }

    /// Expected control-board sensors (per unit).
    pub fn expected_ctrl_board(&self) -> u16 {
        self.ctrl_board_sensors().count() as u16
    }

    /// Expected sensors across a whole unit with `chains` populated
    /// hashboards. `chains` is caller-supplied on purpose: the registry's
    /// `chains_per_unit` is a flagged jig-fixture value (4 where live DCENT
    /// units have 3 slots) and MUST NOT be trusted as a live board count.
    pub fn expected_per_unit(&self, chains: u16) -> u16 {
        self.expected_per_hashboard()
            .saturating_mul(chains)
            .saturating_add(self.expected_ctrl_board())
    }

    /// Sensors at a physical position zone (for gradient work: pair `Top`
    /// against `Bottom` on the same board site).
    pub fn sensors_at(
        &self,
        site: SensorSite,
        x: BoardEdgeX,
        y: BoardEdgeY,
    ) -> impl Iterator<Item = &SensorSpec> {
        self.sensors
            .iter()
            .filter(move |s| s.site == site && s.position.x == x && s.position.y == y)
    }

    /// An all-unknown per-hashboard sweep: `expected` from the declaration,
    /// zero covered, no reading. The honest starting state — NOT 0 °C.
    pub fn empty_hashboard_sweep(&self) -> SensorSweep {
        SensorSweep {
            hottest_c: None,
            covered: 0,
            expected: self.expected_per_hashboard(),
        }
    }
}

/// Build errors surfaced by [`try_build_sensor_topology`]. With the pinned
/// registry corpus these are unreachable (test-pinned); the error path exists
/// so future data imports fail closed instead of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorTopologyError {
    pub sku: String,
    pub detail: String,
}

impl std::fmt::Display for SensorTopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.sku, self.detail)
    }
}

impl std::error::Error for SensorTopologyError {}

fn spec_from_placement(
    s: &SensorPlacement,
    site: SensorSite,
    provenance: DescriptorProvenance,
    sku: &str,
) -> Result<SensorSpec, SensorTopologyError> {
    let position = SensorPosition::parse(&s.x, &s.y).ok_or_else(|| SensorTopologyError {
        sku: sku.to_string(),
        detail: format!("unparseable sensor position x={:?} y={:?}", s.x, s.y),
    })?;
    Ok(SensorSpec {
        device: s.device.clone(),
        site,
        transport: SensorTransport::DirectI2c {
            i2c_addr: s.i2c_addr,
        },
        index: s.index,
        position,
        provenance,
    })
}

fn spec_from_switch(
    s: &SwitchSensorPlacement,
    provenance: DescriptorProvenance,
    sku: &str,
) -> Result<SensorSpec, SensorTopologyError> {
    // v1.22.0-corpus entries carry quadrant placement labels + a chip
    // anchor. The v1.24.0 H6HB70801 new-format bank carries a `channal`
    // number instead of x/y and mostly omits the anchor — that row is
    // excluded from this thermal model (see `SENSOR_MODEL_EXCLUDED_SKUS`)
    // and reaching this arm without labels is a fail-closed error, never
    // a guessed position.
    let (x, y) = match (&s.x, &s.y) {
        (Some(x), Some(y)) => (x, y),
        _ => {
            return Err(SensorTopologyError {
                sku: sku.to_string(),
                detail: format!(
                    "switch-sensor entry has no quadrant position labels \
                     (x={:?} y={:?}, channal={:?}) — the v1.24.0 H6-format \
                     bank is not representable in the v1.22.0 sensor model",
                    s.x, s.y, s.channal
                ),
            })
        }
    };
    let anchor = s.anchor_asic.ok_or_else(|| SensorTopologyError {
        sku: sku.to_string(),
        detail: "switch-sensor entry has no anchor_asic".to_string(),
    })?;
    let position = SensorPosition::parse(x, y).ok_or_else(|| SensorTopologyError {
        sku: sku.to_string(),
        detail: format!("unparseable switch-sensor position x={x:?} y={y:?}"),
    })?;
    Ok(SensorSpec {
        device: s.device.clone(),
        site: SensorSite::Hashboard,
        transport: SensorTransport::I2cMuxed {
            i2c_addr: s.i2c_addr,
            anchor_asic: anchor,
            power_by_ctrlboard: s.power_by_ctrlboard,
        },
        index: s.index,
        position,
        provenance,
    })
}

/// Build one SKU's sensor topology from its registry descriptor. Fail-closed:
/// any label outside the pinned corpus domain is an error, never a guess.
pub fn try_build_sensor_topology(
    d: &HashboardDescriptor,
) -> Result<SkuSensorTopology, SensorTopologyError> {
    let mut sensors = Vec::with_capacity(
        d.board_sensors.len() + d.switch_sensors.len() + d.ctrl_board_sensors.len(),
    );
    for s in &d.board_sensors {
        sensors.push(spec_from_placement(
            s,
            SensorSite::Hashboard,
            d.provenance,
            &d.sku,
        )?);
    }
    for s in &d.switch_sensors {
        sensors.push(spec_from_switch(s, d.provenance, &d.sku)?);
    }
    for s in &d.ctrl_board_sensors {
        sensors.push(spec_from_placement(
            s,
            SensorSite::CtrlBoard,
            d.provenance,
            &d.sku,
        )?);
    }
    Ok(SkuSensorTopology {
        sku: d.sku.clone(),
        provenance: d.provenance,
        sensors,
    })
}

struct SensorRegistry {
    topologies: Vec<SkuSensorTopology>,
    by_sku: HashMap<String, usize>,
}

/// SKUs whose registry rows exist but are **excluded from this thermal
/// model** because their sensor bank is not representable in the
/// v1.22.0-corpus schema this module is built on (quadrant placement
/// labels + chip anchors + LM75A-only device domain).
///
/// `H6HB70801` (v1.24.0 delta) is the only such row today: its 7-entry
/// switch bank is addressed by explicit I²C-switch **channel** with no
/// placement labels and mixes in TMP451 devices (see
/// `hashboard_topology` module docs §"v1.24.0 delta"). Its sensor data
/// is preserved verbatim in the topology registry; modelling it here is
/// thermal-model work, deliberately not part of the roster-completion
/// lane. Pinned by `h6hb70801_is_excluded_from_the_thermal_model`.
const SENSOR_MODEL_EXCLUDED_SKUS: &[&str] = &["H6HB70801"];

fn sensor_registry() -> &'static SensorRegistry {
    static REGISTRY: OnceLock<SensorRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        // The source registry is checked-in generated data and test-pinned;
        // a build failure here is a build-data defect, not a runtime
        // condition (same posture as `hashboard_topology::registry`).
        let topologies: Vec<SkuSensorTopology> = all_descriptors()
            .iter()
            .filter(|d| !SENSOR_MODEL_EXCLUDED_SKUS.contains(&d.sku.as_str()))
            .map(|d| {
                try_build_sensor_topology(d)
                    .expect("pinned hashboard_topology corpus must yield a sensor topology")
            })
            .collect();
        let by_sku = topologies
            .iter()
            .enumerate()
            .map(|(i, t)| (t.sku.clone(), i))
            .collect();
        SensorRegistry { topologies, by_sku }
    })
}

/// Sensor topologies for all representable registry rows (50 v1.22.0 +
/// 10 v1.24.0 delta = 60; `H6HB70801` excluded — see
/// [`SENSOR_MODEL_EXCLUDED_SKUS`]), sorted by SKU.
pub fn all_sensor_topologies() -> &'static [SkuSensorTopology] {
    &sensor_registry().topologies
}

/// Look up one SKU's sensor topology (e.g. `"A3HB70601"`).
pub fn sensor_topology_for_sku(sku: &str) -> Option<&'static SkuSensorTopology> {
    let reg = sensor_registry();
    reg.by_sku.get(sku).map(|&i| &reg.topologies[i])
}

// ---------------------------------------------------------------------------
// Shared coverage accounting
// ---------------------------------------------------------------------------

/// One sweep of temperature readings against a declared expectation.
///
/// The shared replacement shape for `MuxedDieFold` (identical semantics),
/// and — grouped through [`SweepLedger`] — for `AmlogicTemperatureCoverage`
/// and `Am3BbThermalSnapshot`. Pure accounting: no thresholds, limits, or
/// control behaviour live here.
///
/// Invariants (test-pinned):
/// - `hottest_c == None` means *nothing was measured*. There is no 0.0
///   default; `Some(0.0)` is a real reading of 0 °C and is distinct.
/// - `covered` counts only finite readings; NaN/±inf are failures.
/// - [`Self::is_complete`] is `covered == expected` (not `>=`): more
///   readings than declared means the channel map disagrees with the board
///   row and must fail closed, never round up (the `MuxedDieFold` rule).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SensorSweep {
    /// Hottest finite reading in the sweep, or `None` when nothing finite
    /// was measured. Kept even when coverage is incomplete so a hot sensor
    /// that WAS measured can still trip an overtemp response.
    pub hottest_c: Option<f32>,
    /// How many sensors returned a finite reading this sweep.
    pub covered: u16,
    /// How many sensors the board declares for this sweep.
    pub expected: u16,
}

impl SensorSweep {
    /// Fold a per-sensor sweep. `readings` is indexed in whatever order the
    /// caller swept; a failed read is `None`. Non-finite values are failures
    /// — a NaN never counts as coverage and never becomes `hottest_c`.
    pub fn from_readings(readings: &[Option<f32>], expected: u16) -> Self {
        let mut hottest: Option<f32> = None;
        let mut covered: u16 = 0;
        for reading in readings.iter().copied().flatten().filter(|t| t.is_finite()) {
            hottest = Some(match hottest {
                Some(current) => current.max(reading),
                None => reading,
            });
            covered = covered.saturating_add(1);
        }
        SensorSweep {
            hottest_c: hottest,
            covered,
            expected,
        }
    }

    /// Every declared sensor was measured. Deliberately `==`, not `>=`
    /// (over-coverage fails closed), and `expected == 0` is never complete —
    /// a board declaring no sensors has nothing to be complete about.
    pub fn is_complete(&self) -> bool {
        self.expected > 0 && self.covered == self.expected
    }

    /// Threshold-style coverage (the `Am3BbThermalSnapshot` per-chain rule:
    /// a chain counts as covered at `samples >= MIN`). `min` of 0 is never
    /// satisfied — "no requirement" must be stated as a requirement of at
    /// least one reading, not as vacuous truth.
    pub fn meets_minimum(&self, min: u16) -> bool {
        min > 0 && self.covered >= min
    }

    /// `true` only when coverage is COMPLETE and the hottest measured
    /// reading is strictly below `limit_c`. Unknown never satisfies a safety
    /// check: incomplete coverage returns `false` even if every measured
    /// sensor is cool.
    pub fn known_cooler_than(&self, limit_c: f32) -> bool {
        match (self.is_complete(), self.hottest_c) {
            (true, Some(hottest)) => hottest < limit_c,
            _ => false,
        }
    }

    /// `true` when a sensor that WAS measured reads at or above `limit_c` —
    /// valid evidence even while coverage is incomplete (both flags are
    /// honoured; a hot measured die can trip a cut during a blind sweep).
    pub fn measured_reaches(&self, limit_c: f32) -> bool {
        self.hottest_c.is_some_and(|t| t >= limit_c)
    }

    /// Merge two sweeps (sum coverage/expectation, max hottest). `None`
    /// never absorbs a real reading and never fabricates one.
    pub fn merged(self, other: SensorSweep) -> SensorSweep {
        SensorSweep {
            hottest_c: match (self.hottest_c, other.hottest_c) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            covered: self.covered.saturating_add(other.covered),
            expected: self.expected.saturating_add(other.expected),
        }
    }
}

/// Requirement attached to one [`SweepGroup`] in a ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRequirement {
    /// Complete coverage: `covered == expected`, `expected > 0`
    /// (`MuxedDieFold` / Amlogic per-position semantics).
    Exact,
    /// At least this many finite readings (`Am3BbThermalSnapshot` per-chain
    /// semantics). A value of 0 is never satisfied.
    AtLeast(u16),
    /// Recorded for telemetry but never gates completeness (e.g. a bank the
    /// platform cannot reach yet). Distinct from silently dropping the bank:
    /// the unknown stays visible.
    Informational,
}

/// One named sweep inside a [`SweepLedger`] (a slot, a chain, a
/// position-bank...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SweepGroup {
    /// Stable label for diagnostics (`"slot0/inlet"`, `"chain2"`, ...).
    pub label: String,
    pub sweep: SensorSweep,
    pub requirement: GroupRequirement,
}

impl SweepGroup {
    pub fn exact(label: impl Into<String>, sweep: SensorSweep) -> Self {
        SweepGroup {
            label: label.into(),
            sweep,
            requirement: GroupRequirement::Exact,
        }
    }

    pub fn at_least(label: impl Into<String>, sweep: SensorSweep, min: u16) -> Self {
        SweepGroup {
            label: label.into(),
            sweep,
            requirement: GroupRequirement::AtLeast(min),
        }
    }

    pub fn informational(label: impl Into<String>, sweep: SensorSweep) -> Self {
        SweepGroup {
            label: label.into(),
            sweep,
            requirement: GroupRequirement::Informational,
        }
    }

    /// Does this group's sweep satisfy its requirement?
    pub fn is_satisfied(&self) -> bool {
        match self.requirement {
            GroupRequirement::Exact => self.sweep.is_complete(),
            GroupRequirement::AtLeast(min) => self.sweep.meets_minimum(min),
            GroupRequirement::Informational => true,
        }
    }
}

/// A set of named sweeps folded into one honest coverage verdict.
///
/// Expresses the two grouped bespoke shapes:
/// - `AmlogicTemperatureCoverage`: one `Exact` group per required
///   slot×position (inlet / outlet); `is_complete` matches theirs.
/// - `Am3BbThermalSnapshot`: one `AtLeast(min)` group per expected chain;
///   [`Self::is_fresh`] matches their `fresh` rule (every expected chain
///   covered AND a finite max — an empty ledger is never fresh).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SweepLedger {
    pub groups: Vec<SweepGroup>,
}

impl SweepLedger {
    pub fn new(groups: Vec<SweepGroup>) -> Self {
        SweepLedger { groups }
    }

    pub fn push(&mut self, group: SweepGroup) {
        self.groups.push(group);
    }

    /// Every non-informational group satisfies its requirement. An empty
    /// ledger IS complete-by-vacuity here — pair with [`Self::is_fresh`]
    /// (which refuses empty) when "no groups" must fail closed.
    pub fn is_complete(&self) -> bool {
        self.groups.iter().all(SweepGroup::is_satisfied)
    }

    /// Labels of unsatisfied groups, for diagnostics (the
    /// `AmlogicTemperatureCoverage::missing_slots` analogue).
    pub fn missing_labels(&self) -> Vec<&str> {
        self.groups
            .iter()
            .filter(|g| !g.is_satisfied())
            .map(|g| g.label.as_str())
            .collect()
    }

    /// Hottest finite reading across all groups; `None` when nothing was
    /// measured anywhere. Informational groups DO contribute (a real hot
    /// reading is evidence wherever it came from).
    pub fn hottest_c(&self) -> Option<f32> {
        self.groups
            .iter()
            .filter_map(|g| g.sweep.hottest_c)
            .fold(None, |acc, t| {
                Some(match acc {
                    Some(current) => current.max(t),
                    None => t,
                })
            })
    }

    /// Total finite readings across all groups.
    pub fn covered(&self) -> u32 {
        self.groups.iter().map(|g| u32::from(g.sweep.covered)).sum()
    }

    /// Total declared sensors across all groups.
    pub fn expected(&self) -> u32 {
        self.groups
            .iter()
            .map(|g| u32::from(g.sweep.expected))
            .sum()
    }

    /// The `Am3BbThermalSnapshot::fresh` rule generalized: at least one
    /// gating group exists, every group satisfies its requirement, and a
    /// finite hottest reading exists. Only a fresh ledger may guide a new
    /// actuation decision; a stale/incomplete one is logging-only.
    pub fn is_fresh(&self) -> bool {
        let has_gating = self
            .groups
            .iter()
            .any(|g| g.requirement != GroupRequirement::Informational);
        has_gating && self.is_complete() && self.hottest_c().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_parse_is_fail_closed() {
        assert_eq!(
            SensorPosition::parse("left", "top"),
            Some(SensorPosition {
                x: BoardEdgeX::Left,
                y: BoardEdgeY::Top
            })
        );
        assert_eq!(
            SensorPosition::parse("right", "bottom"),
            Some(SensorPosition {
                x: BoardEdgeX::Right,
                y: BoardEdgeY::Bottom
            })
        );
        // Never guess: casing, translations, or new labels fail closed.
        assert_eq!(SensorPosition::parse("Left", "top"), None);
        assert_eq!(SensorPosition::parse("left", "middle"), None);
        assert_eq!(SensorPosition::parse("", ""), None);
    }

    #[test]
    fn unknown_is_not_zero_celsius() {
        // The load-bearing invariant: no reading != a reading of 0 C.
        let unknown = SensorSweep::from_readings(&[None, None], 2);
        assert_eq!(unknown.hottest_c, None);
        assert_eq!(unknown.covered, 0);
        assert!(!unknown.is_complete());

        let zero = SensorSweep::from_readings(&[Some(0.0), None], 2);
        assert_eq!(zero.hottest_c, Some(0.0));
        assert_eq!(zero.covered, 1);
        assert_ne!(unknown, zero);
    }

    #[test]
    fn unknown_never_satisfies_a_safety_check() {
        // Incomplete coverage: even a cool measured subset proves nothing.
        let partial = SensorSweep::from_readings(&[Some(35.0), None, None, None], 4);
        assert!(!partial.known_cooler_than(75.0));
        // ...but a hot MEASURED sensor is still valid trip evidence.
        let hot_partial = SensorSweep::from_readings(&[Some(90.0), None, None, None], 4);
        assert!(hot_partial.measured_reaches(75.0));
        // Complete + cool is the only way to be known-cool.
        let complete = SensorSweep::from_readings(&[Some(35.0), Some(40.0)], 2);
        assert!(complete.known_cooler_than(75.0));
        assert!(!complete.known_cooler_than(40.0)); // strict
                                                    // Zero-expected is never known anything.
        let none_declared = SensorSweep::from_readings(&[], 0);
        assert!(!none_declared.known_cooler_than(200.0));
    }

    #[test]
    fn non_finite_readings_are_failures_not_coverage() {
        let sweep =
            SensorSweep::from_readings(&[Some(f32::NAN), Some(f32::INFINITY), Some(45.0)], 3);
        assert_eq!(sweep.covered, 1);
        assert_eq!(sweep.hottest_c, Some(45.0));
        assert!(!sweep.is_complete());
        // All-NaN is fully unknown, not "hottest NaN".
        let blind = SensorSweep::from_readings(&[Some(f32::NAN)], 1);
        assert_eq!(blind.hottest_c, None);
        assert_eq!(blind.covered, 0);
    }

    #[test]
    fn over_coverage_fails_closed() {
        // More readings than declared = channel map disagrees with the board
        // row; must not round up to complete (MuxedDieFold rule).
        let sweep = SensorSweep::from_readings(&[Some(30.0), Some(31.0), Some(32.0)], 2);
        assert_eq!(sweep.covered, 3);
        assert!(!sweep.is_complete());
    }

    #[test]
    fn meets_minimum_zero_is_never_vacuous() {
        let sweep = SensorSweep::from_readings(&[Some(30.0)], 4);
        assert!(sweep.meets_minimum(1));
        assert!(!sweep.meets_minimum(0));
        assert!(!sweep.meets_minimum(2));
    }

    #[test]
    fn merged_sweeps_sum_and_never_fabricate() {
        let a = SensorSweep::from_readings(&[Some(40.0)], 2);
        let b = SensorSweep::from_readings(&[None, None], 2);
        let m = a.merged(b);
        assert_eq!(m.covered, 1);
        assert_eq!(m.expected, 4);
        assert_eq!(m.hottest_c, Some(40.0));
        let n = b.merged(b);
        assert_eq!(n.hottest_c, None);
    }

    #[test]
    fn ledger_freshness_refuses_empty_and_blind() {
        let empty = SweepLedger::default();
        assert!(empty.is_complete()); // vacuous completeness...
        assert!(!empty.is_fresh()); // ...but never freshness.

        // Complete-but-blind (informational only): not fresh.
        let mut info_only = SweepLedger::default();
        info_only.push(SweepGroup::informational(
            "unreachable-bank",
            SensorSweep::from_readings(&[None; 4], 4),
        ));
        assert!(info_only.is_complete());
        assert!(!info_only.is_fresh());

        // Gating group, satisfied, finite reading: fresh.
        let mut ok = SweepLedger::default();
        ok.push(SweepGroup::exact(
            "chain0",
            SensorSweep::from_readings(&[Some(41.0), Some(44.5)], 2),
        ));
        assert!(ok.is_fresh());
        assert_eq!(ok.hottest_c(), Some(44.5));
    }

    #[test]
    fn ledger_missing_labels_name_the_gaps() {
        let mut ledger = SweepLedger::default();
        ledger.push(SweepGroup::exact(
            "slot0/inlet",
            SensorSweep::from_readings(&[Some(30.0)], 1),
        ));
        ledger.push(SweepGroup::exact(
            "slot0/outlet",
            SensorSweep::from_readings(&[None], 1),
        ));
        assert!(!ledger.is_complete());
        assert_eq!(ledger.missing_labels(), vec!["slot0/outlet"]);
    }

    #[test]
    fn registry_yields_topology_for_every_representable_sku() {
        // 50 v1.22.0 + 10 v1.24.0 delta rows; H6HB70801 is excluded (its
        // channel-addressed bank has no quadrant labels — see
        // `h6hb70801_is_excluded_from_the_thermal_model`).
        assert_eq!(all_sensor_topologies().len(), 60);
        for t in all_sensor_topologies() {
            assert!(
                sensor_topology_for_sku(&t.sku).is_some(),
                "{} must resolve",
                t.sku
            );
            // Every representable board declares at least the 4-sensor
            // direct bank.
            assert!(t.expected_per_hashboard() >= 4, "{}", t.sku);
        }
        assert!(sensor_topology_for_sku("NOT-A-SKU").is_none());
    }

    #[test]
    fn muxed_bank_shape_matches_the_evidence_db() {
        let with_mux: Vec<&SkuSensorTopology> = all_sensor_topologies()
            .iter()
            .filter(|t| t.expected_muxed_per_hashboard() > 0)
            .collect();
        // 9 of 50 v1.22.0 boards + the 4 v1.24.0 delta rows with the same
        // bank shape (A3HB70505, M1HB70602, A3HB70608, A3HB70609).
        assert_eq!(
            with_mux.len(),
            13,
            "13 of 60 representable boards carry the mux bank"
        );
        let total: u16 = with_mux
            .iter()
            .map(|t| t.expected_muxed_per_hashboard())
            .sum();
        assert_eq!(total, 52, "52 muxed entries corpus-wide");
        for t in &with_mux {
            // M1HB70602 (S21 XP Immersion) is the first non-A3HB-prefixed
            // mux-bank board in the corpus.
            assert!(
                t.sku.starts_with("A3HB") || t.sku == "M1HB70602",
                "{}",
                t.sku
            );
            assert_eq!(t.expected_muxed_per_hashboard(), 4, "{}", t.sku);
            // Mux bank shares one address behind the switch...
            for s in t.muxed_sensors() {
                assert_eq!(s.transport.i2c_addr(), 0x4C, "{}", t.sku);
                assert_eq!(s.device, "LM75A", "{}", t.sku);
            }
            // ...while the direct hashboard bank never uses it.
            for s in t.hashboard_sensors().filter(|s| !s.transport.is_muxed()) {
                assert!((0x48..=0x4B).contains(&s.transport.i2c_addr()), "{}", t.sku);
            }
        }
    }

    #[test]
    fn provenance_travels_with_every_spec() {
        let mut v122 = 0;
        let mut v124 = 0;
        for t in all_sensor_topologies() {
            let expected = match t.provenance {
                DescriptorProvenance::DeskJigDbExperimental => {
                    v122 += 1;
                    t.provenance
                }
                DescriptorProvenance::DeskJigDbV124Experimental => {
                    v124 += 1;
                    t.provenance
                }
                other => panic!("{}: unexpected provenance {other:?}", t.sku),
            };
            for s in &t.sensors {
                assert_eq!(s.provenance, expected, "{}", t.sku);
            }
        }
        assert_eq!(v122, 50);
        assert_eq!(v124, 10);
    }

    /// The v1.24.0 `H6HB70801` row exists in the topology registry but its
    /// channel-addressed sensor bank (no quadrant labels, TMP451 devices,
    /// `channal` numbers) is NOT representable in this v1.22.0-corpus
    /// thermal model — so it is excluded, fail-closed, with its data
    /// preserved verbatim upstream. If the model ever grows
    /// channel/label-free sensor support, this test (and
    /// [`SENSOR_MODEL_EXCLUDED_SKUS`]) must be retired together.
    #[test]
    fn h6hb70801_is_excluded_from_the_thermal_model() {
        assert!(crate::hashboard_topology::descriptor_by_sku("H6HB70801").is_some());
        assert_eq!(sensor_topology_for_sku("H6HB70801"), None);
        // And the exclusion is justified: building its topology fails
        // closed on the missing placement labels, not silently.
        let d = crate::hashboard_topology::descriptor_by_sku("H6HB70801").unwrap();
        let err = try_build_sensor_topology(d).expect_err("H6 bank must not be representable");
        assert!(
            err.detail.contains("no quadrant position labels"),
            "unexpected error: {err}"
        );
        // The excluded set is exactly this one SKU — anything else failing
        // to build would have panicked the registry constructor above.
        assert_eq!(SENSOR_MODEL_EXCLUDED_SKUS, &["H6HB70801"]);
    }

    #[test]
    fn per_unit_expectation_is_caller_parameterized() {
        // chains_per_unit from the jig is flagged unreliable (4 vs live 3);
        // the API takes the chain count from the caller instead.
        let t = sensor_topology_for_sku("BHB42601").expect("registry row");
        let per_board = t.expected_per_hashboard();
        assert_eq!(
            t.expected_per_unit(3),
            per_board * 3 + t.expected_ctrl_board()
        );
        assert_eq!(t.expected_per_unit(0), t.expected_ctrl_board());
    }
}
