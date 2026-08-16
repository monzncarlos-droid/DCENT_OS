//! UB-06 (2026-08-02): data-driven hashboard topology registry — 50 SKUs.
//!
//! # What this is
//!
//! A **declarative, capability-first** hashboard descriptor registry keyed by
//! Bitmain SKU string. It replaces the "add another enum arm" growth pattern of
//! [`crate::hashboards::Hashboard`] for topology/identity data: adding
//! hashboard #51 is a **data row** in the checked-in JSON, not new Rust code.
//! The legacy [`crate::hashboards::Hashboard`] enum and its `catalog()` remain
//! load-bearing for existing callers and are untouched; a regression test below
//! pins that this registry never silently disagrees with a live-measured
//! catalog row (where it would, **the DCENT catalog value wins**).
//!
//! # Provenance — DESK EVIDENCE, Experimental. Never claim live verification.
//!
//! Every row is derived offline from the held ePIC UMC OS jig hashboard DB:
//!
//! (supporting analysis: `deliverables/05-HASHBOARD_MODEL_ID_MATRIX.md`), with
//! EEPROM preamble attestation from
//! `evidence/epic-eeprom-matched-samples-20.json`. Caveats that MUST travel
//! with any consumer of this data (per
//! ):
//!
//! - The DB is **Bitmain-derived but ePIC-TRANSCRIBED** and contains real
//!   transcription typos. It does **not** outrank DCENT live measurements —
//!   see the "Known DB-vs-DCENT divergences" section below.
//! - The roster is **v1.22.0-only** (48 published models + NBP1901/NBS1902).
//!   It is NOT a complete Bitmain hashboard roster; absence of a SKU here
//!   proves nothing.
//! - Every row carries [`DescriptorProvenance::DeskJigDbExperimental`] so
//!   downstream code and the dashboard can honestly label it. No row in this
//!   registry is live-verified; live-measured identity lives in
//!   [`crate::hashboards::Hashboard::catalog`].
//! - **Topology/identity only.** The source records also carry `power`
//!   (PSU type/GPIO), `strategy` (freq/voltage ramp tuning) and `fan` blocks —
//!   those are DELIBERATELY NOT imported: tuning presets are a regression-
//!   pinned live-capture residual in this repo ("wrong calibration worse than
//!   none"), and ePIC PSU/GPIO numbers belong to their build. No ePIC PL/AXI
//!   fabric address enters this crate (ePIC ships their own Zynq bitstream;
//!   their addresses do not transfer). `chip_id` below is the ASIC's own
//!   identity code (e.g. `0x1362`), a chip-protocol constant, not a bus or
//!   fabric address.
//!
//! # Known DB-vs-DCENT divergences (adjudicated — our values win)
//!
//! For the 16 SKUs that overlap the live catalog, `chip name` and
//! `chips_per_chain` agree exactly (pinned by test). The divergences are at
//! the per-chip core-count level and one unit-level field:
//!
//! 1. **BM1368 small-cores**: DB says `1276`; DCENT fixture-RE ground truth is
//!    `1280` ([`crate::bm1368::BM1368_CORES_PER_CHIP`], 80×16). The DB value
//!    is also internally inconsistent with its own `80 big × 16 = 1280`.
//!    Registry stores the DB value verbatim (desk provenance); drivers keep
//!    1280.
//! 2. **BM1370 core counts**: DB says `128 big / 2040 small`; DCENT pins
//!    `1280` ([`crate::bm1370::BM1370_CORES_PER_CHIP`], fixture-total ground
//!    truth). DB is again internally inconsistent (128×16 = 2048 ≠ 2040).
//! 3. **BM1398P small-cores**: DB says `623`; that is the **max small-core
//!    index**, not the count — DCENT pins the count `624`
//!    ([`crate::bm1398::BM1398_CORES_PER_CHIP`] =
//!    [`crate::bm1398::BM1398_MAX_SMALL_CORE_INDEX`] + 1). Classic
//!    transcription off-by-one.
//! 4. **`chains_per_unit = 4` on BHB42xxx / NBP1901 / NBS1902**: DCENT live
//!    S19j Pro / S19 Pro units (`a lab unit`, `a lab unit`, `a lab unit`) have **3** hashboard
//!    slots. The jig value likely reflects the test fixture / max control-board
//!    chain count, not the shipped miner chassis. Imported verbatim, flagged.
//! 5. **Enumeration address stride — 16 of 50 boards diverge** (H2 §G-2,
//!    ).
//!    ePIC declares a flat `2` on 49/50 rows (NBS1902 = 3); the DCENT SSOT is
//!    `floor(256/N)` (`dcentrald_common::chain_transport::bm1397plus_addr_interval`,
//!    with BM1387 hardcoding 4, BM1398 a frozen exact plan, BM1373 hardcoding
//!    16). Divergence set: BHB42803 (84: 3→2), BHB569xx (77: 3→2), A3HB706xx
//!    (65: 3→2), A3HB707xx (55: 4→2), A3HB40601 (36: 7→2). The field is
//!    therefore imported as [`ChipDesc::vendor_declared_addr_interval`] —
//!    **DECLARED-BY-VENDOR data only. It MUST NEVER override the
//!    `bm1397plus_addr_interval` SSOT or any per-driver stride**; a wrong
//!    stride breaks chain enumeration.
//!
//!    **ADJUDICATED 2026-08-03 (queue rank 25 / UB-25).** A third, stronger
//!    source settled it: Bitmain's own AMTC `single_board_test` jig binaries,
//!    held on disk, use a chip-count **bucket** (`N>128→1`, `64<N≤128→2`,
//!    `32<N≤64→4`, `N≤32` refuse) — decompile-verified byte-identical across
//!    the BM1362, BM1366, BM1368 and BM1370 jigs. Neither ePIC's flat `2` nor
//!    our `floor(256/N)` is right on its own. Outcome: **12** SKUs where the
//!    jig and ePIC agree against the formula are now DECLARED in
//!    [`dcentrald_common::chain_transport::DECLARED_ADDR_INTERVALS`] (all
//!    `3→2`: `BHB42803`, `BHB569{01,02,03,06,07}`,
//!    `A3HB706{01,02,03,05,06,07}`); the **3** 55-chip `A3HB7070x` rows keep
//!    the fallback because the jig and the formula both say `4` and **ePIC is
//!    the outlier**; and `A3HB40601` (36 chips) is a three-way split
//!    (jig 4 · ePIC 2 · formula 7) left UNRESOLVED on the fallback rather than
//!    guessed. Consume it via [`HashboardDescriptor::resolved_addr_interval`],
//!    never via the raw vendor field. Still desk evidence — no live
//!    enumeration has exercised a declared stride.
//! 6. **The blanket `PIC1704` claim contradicts live-proven S21 NoPic.** The
//!    DB declares `PIC1704 @ 0x20` on all 50 rows including BHB68xxx (S21) —
//!    but DCENT live evidence on S21 `a lab unit` is **NoPic** (TAS5782M DACs;
//!    [`crate::pics::Pic::S21AmlogicNoPic`], routing code refuses PIC
//!    dispatch there). The field is therefore imported as
//!    [`HashboardDescriptor::vendor_declared_pic`] — a vendor claim, never
//!    controller-routing authority. DCENT platform code remains the sole
//!    authority for which voltage controller a live platform drives.
//!
//! Agreements worth noting: BM1362 `65 cores/die × 514 small-cores/core`
//! matches [`crate::bm1362::chip`]; BM1366 `894` small-cores matches
//! [`crate::bm1366::BM1366_CORES_PER_CHIP`]; all 50 rows DECLARE
//! `AT24C02D@0x50` EEPROM + `PIC1704@0x20` (7-bit addresses — but the PIC
//! claim is contradicted on S21, divergence #6); LM75A sensors sit at 7-bit
//! `0x48..=0x4C`. One more transcription defect: **BHB42803's `rows`/
//! `columns` fields are transposed relative to its own `tpl` grid** (12×7
//! grid vs `rows=7`/`columns=12`) — imported verbatim, pinned in tests.
//!
//! # EEPROM preambles — family hint ONLY, and never SKU→format
//!
//! From the 20 held decoded pages: `format_version 1` pages begin
//! `[0x01, 0x41]` (**all A3HB\* BM1370 boards** — NOT `[0x05, 0x11]` as an
//! older comment in `hashboards.rs` claimed), `format 4` begins
//! `[0x04, 0x11]`, `format 5` begins `[0x05, 0x11]`. **BHB56801 was observed
//! as BOTH format 4 and format 5** — a SKU does not map to a format, so
//! `observed_eeprom_preambles` is a list and is attestation-only (empty =
//! no held sample for that SKU, not "no preamble").
//!
//! # Regenerating the data file
//!
//! `src/hashboard_topology_v1_22_0.json` is generated — do not hand-edit.
//! Regenerate from the repo root with (Python 3):
//!
//! ```text
//! python - <<'EOF'
//! import json
//! SRC_DB = ''
//! SRC_EE = ''
//! OUT = 'DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/src/hashboard_topology_v1_22_0.json'
//! db = json.load(open(SRC_DB, encoding='utf-8')); ee = json.load(open(SRC_EE, encoding='utf-8'))
//! observed = {}
//! for key, rec in ee.items():
//!     pre = list(rec['raw_data'][:2]); o = observed.setdefault(rec['board_name'], [])
//!     if pre not in o: o.append(pre)
//! def sensors(lst):
//!     return [{'device': s['type'], 'i2c_addr': s['iic'], 'index': s['index'],
//!              'x': s['x'], 'y': s['y']} for s in (lst or [])]
//! def switch_sensors(lst):
//!     out = []
//!     for s in (lst or []):
//!         e = {'device': s['type'], 'i2c_addr': s['iic'], 'index': s['index'],
//!              'anchor_asic': s['asic'], 'x': s['x'], 'y': s['y']}
//!         if 'power_by_ctrlboard' in s: e['power_by_ctrlboard'] = s['power_by_ctrlboard']
//!         out.append(e)
//!     return out
//! boards = []
//! for sku in sorted(db.keys()):
//!     rec = db[sku]; a, c = rec['asic'], rec['chain']
//!     boards.append({'sku': sku, 'provenance': 'desk_jig_db_experimental',
//!         'chip': {'name': a['asic_id'], 'chip_id': int(a['asic_addr'], 16),
//!                  'vendor_declared_addr_interval': a['asic_addr_interval'],
//!                  'big_cores': a['asic_core_num'],
//!                  'small_cores': a['asic_small_core_num'],
//!                  'small_cores_per_core': a['core_small_core_num'],
//!                  'domains_per_chip': a['asic_domain_num']},
//!         'chain': {'chains_per_unit': c['chain_num'], 'chips_per_chain': c['chain_asic_num'],
//!                   'rows': c['chain_row'], 'columns': c['chain_column'],
//!                   'domains_per_chain': c['chain_domain_num'],
//!                   'chips_per_domain': c['domain_asic_num']},
//!         'tpl': c.get('tpl'), 'domain_placement': c.get('domain'),
//!         'eeprom': {'device': c['eeprom']['type'], 'i2c_addr': c['eeprom']['i2c_addr']},
//!         'vendor_declared_pic': {'device': c['pic']['type'], 'i2c_addr': c['pic']['i2c_addr']},
//!         'board_sensors': sensors(c['pic'].get('sensor')),
//!         'ctrl_board_sensors': sensors(c.get('ctrlboardsensor')),
//!         'switch_sensors': switch_sensors(c.get('switchsensor')),
//!         'observed_eeprom_preambles': observed.get(sku, [])})
//! header = {'schema': 'dcent-hashboard-topology-v1',
//!     'source_db': SRC_DB, 'source_eeprom_samples': SRC_EE,
//!     'roster_scope': 'ePIC UMC OS bms-miner v1.22.0 jig hashboard DB only; '
//!                     'Bitmain-derived, ePIC-transcribed; NOT a complete Bitmain roster'}
//! with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
//!     f.write('{\n')
//!     for k, v in header.items(): f.write(json.dumps(k) + ': ' + json.dumps(v) + ',\n')
//!     f.write('"boards": [\n')
//!     for i, b in enumerate(boards):
//!         f.write(json.dumps(b, separators=(',', ':')) + (',\n' if i + 1 < len(boards) else '\n'))
//!     f.write(']}\n')
//! EOF
//! ```
//!
//! Note: the `chain.sensor` array is empty for all 50 source records; it is
//! deliberately not modeled. `hw_version` / `sw_version` / `processor` are
//! ePIC build metadata and are not imported.
//!
//! # Sensor banks (rank-33 sensor-topology import, 2026-08-03)
//!
//! Three distinct LM75A banks exist in the source DB:
//!
//! - `board_sensors` (jig `chain.pic.sensor`): exactly **4 per board on all
//!   50 rows**, direct 7-bit addresses `0x48..=0x4B`. "Read via the PIC" is
//!   the JIG's access model only — see divergence #6; DCENT platform code
//!   owns the actual access path.
//! - `ctrl_board_sensors` (jig `chain.ctrlboardsensor`): a pair at
//!   `0x48` (right/top) + `0x4C` (left/top) on **33 of 50** rows.
//! - `switch_sensors` (jig `chain.switchsensor`): **4 per board on 9 of 50
//!   rows** (36 entries; all BM1370 A3HB705xx/A3HB706xx), every one an LM75A
//!   at `0x4C` reached **through an on-board I2C switch/mux** and anchored to
//!   a specific chip position (`anchor_asic`). The direct bank on those same
//!   boards occupies `0x48..=0x4B`, so the shared `0x4C` address is only
//!   unambiguous behind the switch — a reader that ignores the mux CANNOT
//!   see this bank. `power_by_ctrlboard` is imported verbatim where present;
//!   **A3HB70601 omits it and orders its `index`→`anchor_asic` mapping
//!   differently from its six A3HB706xx siblings** (transcription defect,
//!   pinned in tests, imported verbatim).
//!
//! The widely-quoted "266 LM75A instances" figure counts only the two direct
//! banks (200 board + 66 ctrl); the switch bank raises the true total to
//! **302**. The thermal abstraction over this data lives in
//! [`crate::sensor_topology`].

use std::collections::HashMap;
use std::sync::OnceLock;

use dcentrald_common::chain_transport::{
    resolve_addr_interval, AddrIntervalDecision, AddrIntervalError, UNRESOLVED_ADDR_INTERVAL_SKUS,
};
use serde::{Deserialize, Serialize};

/// The generated data file (see module docs for the generator command).
const TOPOLOGY_JSON: &str = include_str!("hashboard_topology_v1_22_0.json");

/// Provenance of a registry row. Downstream code and the dashboard MUST use
/// this to label desk-derived rows honestly — none of the current rows are
/// live-verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorProvenance {
    /// Derived offline from the held ePIC UMC OS v1.22.0 jig hashboard DB
    /// (Bitmain-derived, ePIC-transcribed, real typos). Experimental;
    /// never present this as live-verified hardware identity.
    DeskJigDbExperimental,
    /// Derived offline from VNish 1.2.7 firmware model JSONs
    /// (`hwscan --gen-model-info`, re-armada 2026-04-25 corpus) — a
    /// **THIRD-PARTY TRANSCRIPTION** of Bitmain data by VNish, distinct from
    /// both the ePIC-transcribed jig DB and DCENT live measurement. It never
    /// outranks a DCENT live measurement, and where it contradicts an
    /// ePIC-transcribed row neither side is overwritten — the conflict is
    /// recorded and test-pinned (see [`crate::vnish_thermal`]).
    DeskVnishFirmwareExperimental,
    /// Reserved for future rows whose every field has been re-measured on a
    /// DCENT bench unit. No current row qualifies; live-measured identity for
    /// the SKUs we have driven lives in `Hashboard::catalog()`.
    LiveMeasuredDcent,
}

/// ASIC identity + per-chip core geometry, verbatim from the jig DB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChipDesc {
    /// Chip family name as the DB spells it (`"BM1362"`, `"BM1398P"`, ...).
    /// Note ePIC writes `BM1398P` where DCENT modules say `BM1398` — use
    /// [`HashboardDescriptor::dcent_chip_name`] when matching against DCENT
    /// chip modules.
    pub name: String,
    /// The ASIC's own identity code (e.g. `0x1362`) as used by the chip
    /// protocol's chip-ID register. NOT a bus, PL, or AXI address.
    pub chip_id: u16,
    /// ⚠ **DECLARED-BY-VENDOR ONLY — never enumeration authority.** ePIC's
    /// claimed chip-address stride, which disagrees with the DCENT
    /// `floor(256/N)` SSOT on **16 of 50 boards** (module docs, divergence
    /// #5; H2 §G-2). The authoritative stride remains
    /// `dcentrald_common::chain_transport::bm1397plus_addr_interval` plus the
    /// per-driver overrides (BM1387=4, BM1398 frozen plan, BM1373=16). This
    /// field MUST NOT be consumed by any address planner until queue rank 25
    /// adjudicates the divergent set — a wrong stride breaks chain
    /// enumeration. Pinned by
    /// `vendor_declared_stride_never_overrides_the_dcent_ssot`.
    pub vendor_declared_addr_interval: u8,
    /// "Big" core count per chip, DB-verbatim. See module docs for known
    /// divergences vs DCENT fixture ground truth (BM1370 notably).
    pub big_cores: u16,
    /// Small-core count per chip, DB-verbatim. Known divergences: BM1368
    /// 1276 (DCENT: 1280), BM1370 2040 (DCENT: 1280), BM1398P 623 (a max
    /// index; DCENT count: 624). Drivers must keep using the chip modules.
    pub small_cores: u16,
    /// Small cores per core, DB-verbatim.
    pub small_cores_per_core: u16,
    /// Voltage domains inside one chip, DB-verbatim.
    pub domains_per_chip: u8,
}

/// Chain / board-level topology, verbatim from the jig DB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainDesc {
    /// The jig's `chain_num`. ⚠ For BHB42xxx / NBP1901 / NBS1902 the DB says
    /// 4 while DCENT live S19j Pro / S19 Pro units have 3 hashboard slots —
    /// likely the fixture/control-board max, not the shipped chassis. Do not
    /// use as a live board count.
    pub chains_per_unit: u8,
    /// ASICs on one hashboard chain.
    pub chips_per_chain: u16,
    /// Physical placement rows on the board.
    pub rows: u8,
    /// Physical placement columns on the board.
    pub columns: u8,
    /// Voltage domains along the chain.
    pub domains_per_chain: u8,
    /// ASICs per chain voltage domain.
    pub chips_per_domain: u8,
}

/// A temperature-sensor placement (`LM75A` throughout this corpus).
/// `i2c_addr` is the 7-bit device address (0x48..=0x4C observed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorPlacement {
    pub device: String,
    pub i2c_addr: u8,
    pub index: u8,
    /// Horizontal position label, DB-verbatim (`"left"` / `"right"`).
    pub x: String,
    /// Vertical position label, DB-verbatim (`"top"` / `"bottom"`).
    pub y: String,
}

/// An I²C device identity + 7-bit address (EEPROM / PIC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePlacement {
    pub device: String,
    pub i2c_addr: u8,
}

/// A temperature sensor reached **through an on-board I²C switch/mux** (jig
/// `switchsensor`). All 36 entries in the v1.22.0 corpus are LM75A at 7-bit
/// `0x4C`, present only on the 9 BM1370 A3HB705xx/A3HB706xx rows, and each is
/// anchored to a specific chip position on the chain. Because the direct
/// board bank occupies `0x48..=0x4B` and this bank shares one address, these
/// sensors are unreachable without driving the switch — coverage accounting
/// must therefore model them separately (see [`crate::sensor_topology`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchSensorPlacement {
    pub device: String,
    /// 7-bit device address behind the switch (`0x4C` throughout the corpus).
    pub i2c_addr: u8,
    /// Bank index (jig `index`, 0..=3). NOTE: A3HB70601's index ordering
    /// diverges from its A3HB706xx siblings — transcription defect, imported
    /// verbatim and pinned in tests.
    pub index: u8,
    /// The chip position this sensor is thermally anchored to (jig `asic`).
    /// Coordinate convention (0- vs 1-based, tpl-grid vs chain-order) is NOT
    /// adjudicated — carried verbatim; do not derive placement math from it
    /// without a live cross-check.
    pub anchor_asic: u16,
    /// Horizontal position label, DB-verbatim (`"left"` / `"right"`).
    pub x: String,
    /// Vertical position label, DB-verbatim (`"top"` / `"bottom"`).
    pub y: String,
    /// Jig `power_by_ctrlboard`, imported verbatim where the source record
    /// carries it. `None` = the source record omits the field (A3HB70601),
    /// which is a transcription gap, NOT "false".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_by_ctrlboard: Option<bool>,
}

/// One chip's slot in a per-domain placement list (NBP1901/NBS1902 use this
/// representation instead of a `tpl` grid). Field names are DB-verbatim; the
/// coordinate orientation is not adjudicated, so it is carried unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainChip {
    pub index: u16,
    pub coordinate: [u16; 2],
}

/// One voltage domain's chip placements (DB-verbatim `domain` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainPlacement {
    pub index: u16,
    pub asic: Vec<DomainChip>,
}

/// Declarative, topology-complete hashboard descriptor. One registry row per
/// SKU; adding a SKU is a data change in
/// `hashboard_topology_v1_22_0.json`, not new code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashboardDescriptor {
    /// Bitmain SKU string (registry key).
    pub sku: String,
    /// Row provenance — currently always desk/Experimental. See enum docs.
    pub provenance: DescriptorProvenance,
    pub chip: ChipDesc,
    pub chain: ChainDesc,
    /// Physical chip placement grid (row-major; `0` = unpopulated position).
    /// Present for 48/50 SKUs; NBP1901/NBS1902 use `domain_placement`.
    pub tpl: Option<Vec<Vec<u16>>>,
    /// Per-domain chip placement (NBP1901/NBS1902 only).
    pub domain_placement: Option<Vec<DomainPlacement>>,
    /// Chain EEPROM device + 7-bit address (AT24C02D @ 0x50 for all 50 —
    /// corroborated by DCENT live page reads at 0x50-class addresses).
    pub eeprom: DevicePlacement,
    /// ⚠ **VENDOR CLAIM ONLY — never controller-routing authority.** The DB
    /// declares `PIC1704 @ 0x20` on all 50 rows, which CONTRADICTS DCENT
    /// live evidence on S21 (BHB68xxx): `a lab unit` is NoPic (TAS5782M DACs,
    /// [`crate::pics::Pic::S21AmlogicNoPic`]). See module docs, divergence
    /// #6. DCENT platform code remains the sole authority for which voltage
    /// controller a live platform actually drives.
    pub vendor_declared_pic: DevicePlacement,
    /// On-hashboard temperature sensors (read via the PIC in the jig model).
    pub board_sensors: Vec<SensorPlacement>,
    /// Control-board sensors (present on 33/50 rows).
    pub ctrl_board_sensors: Vec<SensorPlacement>,
    /// I2C-switch/mux-reached sensors (present on 9/50 rows, 36 entries,
    /// all BM1370 A3HB boards). See module docs §"Sensor banks".
    pub switch_sensors: Vec<SwitchSensorPlacement>,
    /// EEPROM preambles actually observed for this SKU in the 20 held decoded
    /// pages. ATTESTATION ONLY: empty means "no held sample", and a SKU may
    /// carry more than one (BHB56801 ships as format 4 AND format 5). Never
    /// use as an identity gate; family hint semantics only.
    pub observed_eeprom_preambles: Vec<[u8; 2]>,
}

impl HashboardDescriptor {
    /// Chip name normalized to DCENT chip-module spelling
    /// (`"BM1398P"` → `"BM1398"`; everything else unchanged).
    pub fn dcent_chip_name(&self) -> &str {
        match self.chip.name.as_str() {
            "BM1398P" => "BM1398",
            other => other,
        }
    }

    /// Resolve this board's chain address stride through the DCENT SSOT:
    /// per-board **declared** data first, `floor(256/N)` fallback second.
    ///
    /// This deliberately does **not** read
    /// [`ChipDesc::vendor_declared_addr_interval`] — that field remains a
    /// vendor claim with no authority. The adjudicated declaration table lives
    /// in [`dcentrald_common::chain_transport::DECLARED_ADDR_INTERVALS`], where
    /// a SKU is admitted only when the Bitmain factory-jig bucket rule and the
    /// ePIC DB independently agree (UB-25 / H2 §G-2). See that module for the
    /// jig binaries and decompilation sites.
    ///
    /// Returns `None` when this row's `chips_per_chain` does not fit a `u8`
    /// (no roster row does today) — callers must fail closed, not guess.
    pub fn resolved_addr_interval(
        &self,
    ) -> Option<Result<AddrIntervalDecision, AddrIntervalError>> {
        let n = u8::try_from(self.chain.chips_per_chain).ok()?;
        Some(resolve_addr_interval(Some(self.sku.as_str()), n))
    }

    /// Whether this board's stride is knowingly UNRESOLVED (a source split that
    /// no two independent authorities settle) and therefore left on the
    /// computed fallback. `A3HB40601` is the only such row today.
    pub fn addr_interval_is_unresolved(&self) -> bool {
        UNRESOLVED_ADDR_INTERVAL_SKUS.contains(&self.sku.as_str())
    }
}

/// EEPROM preamble family, per the held decoded pages. A **family hint**,
/// never an exact SKU or an identity gate — exactly the semantics of
/// [`crate::hashboards::classify_by_eeprom_preamble`], but covering the
/// `[0x01, 0x41]` A3HB family which has no `Hashboard` enum stand-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreambleFamily {
    /// `[0x04, 0x11]` — BHB42xxx-class format-4 pages (and at least one
    /// BHB56801 sample!). Spans BM1362 and BM1398-era boards.
    Bhb42Format4,
    /// `[0x05, 0x11]` — format-5 `edf_v5_xxtea` pages. Spans BHB56xxx
    /// (BM1366) and BHB68xxx (BM1368) — multiple ASIC generations.
    EdfV5Format5,
    /// `[0x01, 0x41]` — format-1 pages; all held samples are A3HB\* (BM1370)
    /// boards. The `0x41` byte is the first character of the board name
    /// (`'A'`), NOT a key selector.
    A3hbFormat1,
}

/// Classify a chain-EEPROM preamble into a page-format **family hint**.
///
/// Returns `None` for unknown preambles (caller must fail closed). The result
/// is never identity: within a family the boards span multiple SKUs and, for
/// [`PreambleFamily::EdfV5Format5`], multiple ASIC generations — and BHB56801
/// demonstrates one SKU shipping under two different families.
pub fn classify_preamble_family(preamble: [u8; 2]) -> Option<PreambleFamily> {
    match preamble {
        [0x04, 0x11] => Some(PreambleFamily::Bhb42Format4),
        [0x05, 0x11] => Some(PreambleFamily::EdfV5Format5),
        [0x01, 0x41] => Some(PreambleFamily::A3hbFormat1),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TopologyFile {
    schema: String,
    source_db: String,
    source_eeprom_samples: String,
    roster_scope: String,
    boards: Vec<HashboardDescriptor>,
}

struct Registry {
    boards: Vec<HashboardDescriptor>,
    by_sku: HashMap<String, usize>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        // The data file is generated + checked in + test-pinned; a parse
        // failure is a build-data defect, not a runtime condition.
        let file: TopologyFile = serde_json::from_str(TOPOLOGY_JSON)
            .expect("hashboard_topology_v1_22_0.json is checked-in generated data and must parse");
        assert_eq!(
            file.schema, "dcent-hashboard-topology-v1",
            "unexpected topology data schema"
        );
        let by_sku = file
            .boards
            .iter()
            .enumerate()
            .map(|(i, b)| (b.sku.clone(), i))
            .collect();
        Registry {
            boards: file.boards,
            by_sku,
        }
    })
}

/// All registry rows, sorted by SKU (50 as of the v1.22.0 import).
pub fn all_descriptors() -> &'static [HashboardDescriptor] {
    &registry().boards
}

/// Look up a descriptor by exact Bitmain SKU string (e.g. `"BHB42612"`).
pub fn descriptor_by_sku(sku: &str) -> Option<&'static HashboardDescriptor> {
    let reg = registry();
    reg.by_sku.get(sku).map(|&i| &reg.boards[i])
}

/// All descriptors mounting the given chip family, accepting either DB or
/// DCENT spelling (`"BM1398P"` and `"BM1398"` both match the NB\* boards).
pub fn descriptors_for_chip(chip_name: &str) -> Vec<&'static HashboardDescriptor> {
    all_descriptors()
        .iter()
        .filter(|d| d.chip.name == chip_name || d.dcent_chip_name() == chip_name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashboards::{Hashboard, ALL_HASHBOARDS};
    use dcentrald_common::chain_transport::AddrIntervalSource;

    #[test]
    fn registry_parses_and_has_exactly_50_boards() {
        assert_eq!(all_descriptors().len(), 50);
    }

    #[test]
    fn every_sku_resolves_and_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for d in all_descriptors() {
            assert!(seen.insert(d.sku.as_str()), "duplicate SKU {}", d.sku);
            let looked_up = descriptor_by_sku(&d.sku).expect("sku must resolve");
            assert_eq!(looked_up, d);
        }
        assert_eq!(descriptor_by_sku("NOT-A-SKU"), None);
    }

    #[test]
    fn counts_by_chip_family_match_the_evidence_db() {
        // v1.22.0 roster: 16 BM1362 + 11 BM1366 + 8 BM1368 + 13 BM1370
        // + 2 BM1398P = 50.
        assert_eq!(descriptors_for_chip("BM1362").len(), 16);
        assert_eq!(descriptors_for_chip("BM1366").len(), 11);
        assert_eq!(descriptors_for_chip("BM1368").len(), 8);
        assert_eq!(descriptors_for_chip("BM1370").len(), 13);
        assert_eq!(descriptors_for_chip("BM1398P").len(), 2);
        // DCENT spelling resolves the same two NB* boards.
        assert_eq!(descriptors_for_chip("BM1398").len(), 2);
    }

    #[test]
    fn all_rows_are_desk_experimental_provenance() {
        // No row may claim live verification — the import is desk evidence.
        for d in all_descriptors() {
            assert_eq!(
                d.provenance,
                DescriptorProvenance::DeskJigDbExperimental,
                "{} must carry desk/Experimental provenance",
                d.sku
            );
        }
    }

    #[test]
    fn topology_is_internally_consistent_for_every_board() {
        for d in all_descriptors() {
            let c = &d.chain;
            // Domain arithmetic must reproduce the chain population.
            assert_eq!(
                c.chips_per_domain as u16 * c.domains_per_chain as u16,
                c.chips_per_chain,
                "{}: domains × chips/domain != chips/chain",
                d.sku
            );
            // Exactly one placement representation.
            assert!(
                d.tpl.is_some() ^ d.domain_placement.is_some(),
                "{}: exactly one of tpl/domain_placement expected",
                d.sku
            );
            if let Some(tpl) = &d.tpl {
                let width = tpl.first().map(Vec::len).unwrap_or(0);
                for row in tpl {
                    assert_eq!(row.len(), width, "{}: ragged tpl grid", d.sku);
                }
                let straight = tpl.len() == c.rows as usize && width == c.columns as usize;
                let transposed = tpl.len() == c.columns as usize && width == c.rows as usize;
                if d.sku == "BHB42803" {
                    // Known ePIC transcription defect: BHB42803's rows/columns
                    // fields are TRANSPOSED relative to its own tpl grid
                    // (12×7 grid vs rows=7/columns=12). Imported verbatim;
                    // pinned so a silent "fix" of either side is caught.
                    assert!(
                        !straight && transposed,
                        "BHB42803 transposition defect changed — re-adjudicate"
                    );
                } else {
                    assert!(straight, "{}: tpl grid does not match rows×columns", d.sku);
                }
                let populated = tpl.iter().flatten().filter(|&&v| v != 0).count();
                assert_eq!(
                    populated, c.chips_per_chain as usize,
                    "{}: populated tpl cells != chips/chain",
                    d.sku
                );
            }
            if let Some(domains) = &d.domain_placement {
                assert_eq!(
                    domains.len(),
                    c.domains_per_chain as usize,
                    "{}: domain_placement length",
                    d.sku
                );
                let chips: usize = domains.iter().map(|dm| dm.asic.len()).sum();
                assert_eq!(
                    chips, c.chips_per_chain as usize,
                    "{}: domain_placement chip total",
                    d.sku
                );
            }
        }
    }

    #[test]
    fn all_boards_carry_the_vendor_declared_eeprom_and_pic_claims() {
        // All 50 v1.22.0 rows DECLARE: AT24C02D EEPROM @ 7-bit 0x50 (live-
        // corroborated), PIC1704 @ 0x20 (a VENDOR CLAIM that contradicts the
        // live-proven S21 NoPic finding — see module docs divergence #6; the
        // field name keeps that dishonesty impossible to consume silently).
        for d in all_descriptors() {
            assert_eq!(d.eeprom.device, "AT24C02D", "{}", d.sku);
            assert_eq!(d.eeprom.i2c_addr, 0x50, "{}", d.sku);
            assert_eq!(d.vendor_declared_pic.device, "PIC1704", "{}", d.sku);
            assert_eq!(d.vendor_declared_pic.i2c_addr, 0x20, "{}", d.sku);
            // Sensor corpus is LM75A at 7-bit 0x48..=0x4C throughout.
            for s in d.board_sensors.iter().chain(&d.ctrl_board_sensors) {
                assert_eq!(s.device, "LM75A", "{}", d.sku);
                assert!(
                    (0x48..=0x4C).contains(&s.i2c_addr),
                    "{}: sensor addr {:#x}",
                    d.sku,
                    s.i2c_addr
                );
            }
            // Direct board bank is exactly 4 sensors at 0x48..=0x4B on every
            // row; the switch bank is LM75A at exactly 0x4C on every entry.
            assert_eq!(d.board_sensors.len(), 4, "{}", d.sku);
            for s in &d.board_sensors {
                assert!(
                    (0x48..=0x4B).contains(&s.i2c_addr),
                    "{}: direct board sensor addr {:#x}",
                    d.sku,
                    s.i2c_addr
                );
            }
            for s in &d.switch_sensors {
                assert_eq!(s.device, "LM75A", "{}", d.sku);
                assert_eq!(s.i2c_addr, 0x4C, "{}", d.sku);
            }
        }
    }

    #[test]
    fn spot_check_rows_match_the_evidence_db() {
        // BHB42612 — the one BM1362 SKU our enum catalog was missing.
        let d = descriptor_by_sku("BHB42612").unwrap();
        assert_eq!(d.chip.name, "BM1362");
        assert_eq!(d.chip.chip_id, 0x1362);
        assert_eq!(d.chain.chips_per_chain, 120);
        assert_eq!((d.chain.rows, d.chain.columns), (12, 10));
        assert_eq!(d.chain.domains_per_chain, 40);

        // A3HB40601 — BM1370, 36 chips, 12×3, 12 domains × 3.
        let d = descriptor_by_sku("A3HB40601").unwrap();
        assert_eq!(d.chip.name, "BM1370");
        assert_eq!(d.chip.chip_id, 0x1370);
        assert_eq!(d.chain.chips_per_chain, 36);
        assert_eq!((d.chain.rows, d.chain.columns), (12, 3));

        // BHB56902 — must agree with the live-probed S19k Pro row (77/chain).
        let d = descriptor_by_sku("BHB56902").unwrap();
        assert_eq!(d.chip.name, "BM1366");
        assert_eq!(d.chain.chips_per_chain, 77);
        assert_eq!((d.chain.rows, d.chain.columns), (11, 7));

        // NBS1902 — BM1398P, 76 chips as 38 domains × 2, domain placement.
        let d = descriptor_by_sku("NBS1902").unwrap();
        assert_eq!(d.chip.name, "BM1398P");
        assert_eq!(d.dcent_chip_name(), "BM1398");
        assert_eq!(d.chip.chip_id, 0x1398);
        assert_eq!(d.chain.chips_per_chain, 76);
        assert_eq!(d.chain.chips_per_domain, 2);
        assert!(d.tpl.is_none());
        assert!(d.domain_placement.is_some());
        // NBS1902 is the only roster row where the VENDOR declares a
        // non-2 stride (3 — which happens to equal floor(256/76)).
        assert_eq!(d.chip.vendor_declared_addr_interval, 3);
        assert_eq!(
            descriptor_by_sku("NBP1901")
                .unwrap()
                .chip
                .vendor_declared_addr_interval,
            2
        );
    }

    /// Coordinator trap #1 / H2 §G-2 / queue rank 25: the vendor-declared
    /// stride disagrees with the DCENT `floor(256/N)` SSOT on exactly 16 of
    /// 50 boards. This registry imports the vendor value as DATA ONLY; the
    /// SSOT (`dcentrald_common::chain_transport::bm1397plus_addr_interval`)
    /// and the per-driver overrides remain the only enumeration authority.
    /// Rank 25 adjudicated the 16 (see module docs divergence #5): the raw
    /// vendor field is still never consumed by a planner — the resolved,
    /// two-source-corroborated stride is, via
    /// [`HashboardDescriptor::resolved_addr_interval`].
    #[test]
    fn vendor_declared_stride_never_overrides_the_dcent_ssot() {
        use dcentrald_common::chain_transport::bm1397plus_addr_interval;

        let mut divergent: Vec<&str> = Vec::new();
        for d in all_descriptors() {
            let vendor = d.chip.vendor_declared_addr_interval;
            let n = u8::try_from(d.chain.chips_per_chain).expect("roster chains are <= 255 chips");
            // Vendor's own declaration must at least fit the address space:
            // last assigned address (N-1)×stride must be a valid u8.
            assert!(
                u32::from(n - 1) * u32::from(vendor) <= 255,
                "{}: vendor stride overflows the address space",
                d.sku
            );
            if vendor != bm1397plus_addr_interval(n) {
                divergent.push(d.sku.as_str());
            }
        }
        // The exact H2 §G-2 divergence set — 16 boards, all where ePIC's
        // flat `2` undercuts our computed stride.
        let expected = [
            "A3HB40601",
            "A3HB70601",
            "A3HB70602",
            "A3HB70603",
            "A3HB70605",
            "A3HB70606",
            "A3HB70607",
            "A3HB70701",
            "A3HB70702",
            "A3HB70703",
            "BHB42803",
            "BHB56901",
            "BHB56902",
            "BHB56903",
            "BHB56906",
            "BHB56907",
        ];
        divergent.sort_unstable();
        assert_eq!(
            divergent, expected,
            "G-2 divergence set drifted — re-adjudicate"
        );
    }

    /// UB-25 adjudication, pinned across the whole 50-row roster.
    ///
    /// Partitions every SKU into exactly one of: agrees-everywhere (fallback),
    /// declared (jig + ePIC beat the formula), ePIC-is-the-outlier (fallback,
    /// already equals the jig), or unresolved three-way split (fallback,
    /// corroborated by nobody). If any bucket drifts, re-adjudicate — do not
    /// re-balance the expected lists to make this pass.
    #[test]
    fn resolved_addr_interval_partitions_the_roster_as_adjudicated() {
        use dcentrald_common::chain_transport::{
            bitmain_jig_addr_interval, bm1397plus_addr_interval,
        };

        let mut declared: Vec<&str> = Vec::new();
        let mut epic_outlier: Vec<&str> = Vec::new();
        let mut unresolved: Vec<&str> = Vec::new();
        let mut agrees = 0usize;

        for d in all_descriptors() {
            let n = u8::try_from(d.chain.chips_per_chain).expect("roster chains fit u8");
            let decision = d
                .resolved_addr_interval()
                .expect("every roster row fits u8")
                .expect("every roster row must produce an addressable ladder");
            // Fail-closed gate holds for every row.
            assert!(
                u32::from(n.saturating_sub(1)) * u32::from(decision.interval) <= 255,
                "{}: resolved ladder overflows the address space",
                d.sku
            );

            let formula = bm1397plus_addr_interval(n);
            let vendor = d.chip.vendor_declared_addr_interval;
            let jig = bitmain_jig_addr_interval(n);

            match decision.source {
                AddrIntervalSource::BoardDeclared => {
                    declared.push(d.sku.as_str());
                    assert_eq!(jig, Some(decision.interval), "{}", d.sku);
                    assert_eq!(vendor, decision.interval, "{}", d.sku);
                    assert_ne!(formula, decision.interval, "{}", d.sku);
                    assert!(!d.addr_interval_is_unresolved(), "{}", d.sku);
                }
                AddrIntervalSource::ComputedFallback => {
                    assert_eq!(decision.interval, formula, "{}", d.sku);
                    if d.addr_interval_is_unresolved() {
                        unresolved.push(d.sku.as_str());
                    } else if vendor != formula {
                        // Only legal when the jig backs OUR value, not ePIC's.
                        assert_eq!(
                            jig,
                            Some(formula),
                            "{}: fallback kept against ePIC without jig backing",
                            d.sku
                        );
                        epic_outlier.push(d.sku.as_str());
                    } else {
                        agrees += 1;
                    }
                }
            }
        }
        declared.sort_unstable();
        epic_outlier.sort_unstable();
        unresolved.sort_unstable();

        assert_eq!(
            declared,
            [
                "A3HB70601",
                "A3HB70602",
                "A3HB70603",
                "A3HB70605",
                "A3HB70606",
                "A3HB70607",
                "BHB42803",
                "BHB56901",
                "BHB56902",
                "BHB56903",
                "BHB56906",
                "BHB56907",
            ],
            "declared set drifted — re-adjudicate against both sources"
        );
        // ePIC's flat `2` is wrong here; jig and formula both say 4.
        assert_eq!(epic_outlier, ["A3HB70701", "A3HB70702", "A3HB70703"]);
        // jig 4 · ePIC 2 · formula 7 — never guessed.
        assert_eq!(unresolved, ["A3HB40601"]);
        // 12 declared + 3 ePIC-outlier + 1 unresolved = the 16-board G-2 set.
        assert_eq!(declared.len() + epic_outlier.len() + unresolved.len(), 16);
        assert_eq!(agrees, 34);
        assert_eq!(agrees + 16, all_descriptors().len());
    }

    /// The two catalog-`Exact` rows the queue named by SKU now resolve to the
    /// corroborated stride instead of the formula's value.
    #[test]
    fn the_named_exact_rows_resolve_to_two_not_three() {
        for (sku, n) in [("BHB56902", 77u16), ("A3HB70601", 65)] {
            let d = descriptor_by_sku(sku).expect("sku");
            assert_eq!(d.chain.chips_per_chain, n, "{sku}");
            let r = d
                .resolved_addr_interval()
                .expect("fits u8")
                .expect("addressable");
            assert_eq!(r.interval, 2, "{sku}");
            assert_eq!(r.source, AddrIntervalSource::BoardDeclared, "{sku}");
            assert_eq!(
                dcentrald_common::chain_transport::bm1397plus_addr_interval(n as u8),
                3,
                "{sku}: the formula this replaces"
            );
        }
    }

    /// The "our value wins" contract: wherever a registry row overlaps a
    /// live-measured `Hashboard::catalog()` row, chip name and chips/chain
    /// must agree. Today they do for all 16 overlapping SKUs; if either side
    /// ever changes, this test forces a fresh adjudication instead of a
    /// silent divergence (the catalog side wins — it is the live-measured
    /// authority, the registry is desk evidence).
    #[test]
    fn registry_never_silently_disagrees_with_the_live_catalog() {
        let mut overlapping = 0;
        for hb in ALL_HASHBOARDS {
            let cat = hb.catalog();
            let Some(d) = descriptor_by_sku(cat.sku) else {
                // BHB-S9 / BHB-S11 / BHB-S17 / BHB-T15 are pre-AT24C02D-era
                // placeholders outside the v1.22.0 roster.
                continue;
            };
            overlapping += 1;
            assert_eq!(
                d.dcent_chip_name(),
                cat.chip_name,
                "{}: registry chip vs catalog chip",
                cat.sku
            );
            assert_eq!(
                d.chain.chips_per_chain, cat.chips_per_chain as u16,
                "{}: registry chips/chain vs catalog",
                cat.sku
            );
            // Where the catalog pins a preamble AND we hold a decoded sample,
            // the sample must corroborate the pin.
            if let (Some(pin), false) =
                (cat.eeprom_preamble, d.observed_eeprom_preambles.is_empty())
            {
                assert!(
                    d.observed_eeprom_preambles.contains(&pin),
                    "{}: held sample preambles {:?} do not include catalog pin {:?}",
                    cat.sku,
                    d.observed_eeprom_preambles,
                    pin
                );
            }
        }
        // 15 BHB42xxx + BHB56902 overlap today.
        assert_eq!(overlapping, 16);
    }

    /// Pin the adjudicated DB-vs-DCENT core-count divergences (module docs
    /// §"Known DB-vs-DCENT divergences"). The registry stores the DB values
    /// VERBATIM as desk evidence; the chip modules keep the DCENT ground
    /// truth and always win for driver behavior. If either side changes,
    /// re-adjudicate — do not "fix" one side to match the other blindly.
    #[test]
    fn known_core_count_divergences_are_pinned_not_reconciled() {
        // BM1368: DB 1276 vs DCENT fixture-RE 1280 (also internally
        // inconsistent with the DB's own 80 × 16).
        let d = descriptor_by_sku("BHB68606").unwrap();
        assert_eq!(d.chip.small_cores, 1276);
        assert_eq!(
            d.chip.big_cores as u32 * d.chip.small_cores_per_core as u32,
            1280
        );
        assert_eq!(crate::bm1368::BM1368_CORES_PER_CHIP, 1280);

        // BM1370: DB 128/2040 vs DCENT fixture-total 1280.
        let d = descriptor_by_sku("A3HB70501").unwrap();
        assert_eq!((d.chip.big_cores, d.chip.small_cores), (128, 2040));
        assert_eq!(crate::bm1370::BM1370_CORES_PER_CHIP, 1280);

        // BM1398P: DB 623 is the max small-core INDEX; DCENT count is 624.
        let d = descriptor_by_sku("NBP1901").unwrap();
        assert_eq!(d.chip.small_cores, 623);
        assert_eq!(
            u32::from(d.chip.small_cores),
            crate::bm1398::BM1398_MAX_SMALL_CORE_INDEX
        );
        assert_eq!(crate::bm1398::BM1398_CORES_PER_CHIP, 624);

        // Agreements (no divergence): BM1362 65 × 514, BM1366 894.
        let d = descriptor_by_sku("BHB42601").unwrap();
        assert_eq!(d.chip.big_cores, crate::bm1362::chip::CORES_PER_DIE);
        assert_eq!(
            d.chip.small_cores,
            crate::bm1362::chip::SMALL_CORES_PER_CORE
        );
        let d = descriptor_by_sku("BHB56902").unwrap();
        assert_eq!(
            u32::from(d.chip.small_cores),
            crate::bm1366::BM1366_CORES_PER_CHIP
        );
    }

    /// Pin the chains_per_unit divergence: the jig DB says 4 for the
    /// BHB42xxx / NB* families while DCENT live S19j Pro/S19 Pro units have
    /// 3 hashboard slots. Imported verbatim; never consume as a live board
    /// count.
    #[test]
    fn jig_chains_per_unit_is_verbatim_and_flagged() {
        assert_eq!(
            descriptor_by_sku("BHB42601").unwrap().chain.chains_per_unit,
            4
        );
        assert_eq!(
            descriptor_by_sku("NBP1901").unwrap().chain.chains_per_unit,
            4
        );
        // The 3-chain repair-class row matches our catalog comment exactly.
        assert_eq!(
            descriptor_by_sku("BHB42803").unwrap().chain.chains_per_unit,
            3
        );
        // BM1366/BM1368/BM1370 families are 3-board units in the DB too.
        assert_eq!(
            descriptor_by_sku("BHB56902").unwrap().chain.chains_per_unit,
            3
        );
        assert_eq!(
            descriptor_by_sku("BHB68606").unwrap().chain.chains_per_unit,
            3
        );
        assert_eq!(
            descriptor_by_sku("A3HB70601")
                .unwrap()
                .chain
                .chains_per_unit,
            3
        );
    }

    #[test]
    fn observed_preambles_match_held_pages_and_never_imply_sku_to_format() {
        // A3HB format-1 pages begin [0x01, 0x41] — NOT [0x05, 0x11].
        for sku in ["A3HB70501", "A3HB70601", "A3HB70701"] {
            assert_eq!(
                descriptor_by_sku(sku).unwrap().observed_eeprom_preambles,
                vec![[0x01, 0x41]],
                "{sku}"
            );
        }
        // No A3HB row may ever claim a [0x05, 0x11] observation.
        for d in all_descriptors()
            .iter()
            .filter(|d| d.sku.starts_with("A3HB"))
        {
            assert!(
                !d.observed_eeprom_preambles.contains(&[0x05, 0x11]),
                "{}",
                d.sku
            );
        }
        // BHB56801 was held as BOTH format 4 and format 5 — the proof that a
        // SKU does not map to a format.
        let both = &descriptor_by_sku("BHB56801")
            .unwrap()
            .observed_eeprom_preambles;
        assert!(both.contains(&[0x04, 0x11]) && both.contains(&[0x05, 0x11]));
        // Family staples.
        assert_eq!(
            descriptor_by_sku("BHB42601")
                .unwrap()
                .observed_eeprom_preambles,
            vec![[0x04, 0x11]]
        );
        assert_eq!(
            descriptor_by_sku("BHB68606")
                .unwrap()
                .observed_eeprom_preambles,
            vec![[0x05, 0x11]]
        );
        // Unattested SKUs stay honestly empty.
        assert!(descriptor_by_sku("BHB56907")
            .unwrap()
            .observed_eeprom_preambles
            .is_empty());
    }

    #[test]
    fn preamble_family_classifier_covers_all_three_families() {
        assert_eq!(
            classify_preamble_family([0x04, 0x11]),
            Some(PreambleFamily::Bhb42Format4)
        );
        assert_eq!(
            classify_preamble_family([0x05, 0x11]),
            Some(PreambleFamily::EdfV5Format5)
        );
        assert_eq!(
            classify_preamble_family([0x01, 0x41]),
            Some(PreambleFamily::A3hbFormat1)
        );
        assert_eq!(classify_preamble_family([0x00, 0x00]), None);
        assert_eq!(classify_preamble_family([0xFF, 0xFF]), None);
        // The enum-level classifier stays fail-closed for the A3HB family
        // (no Hashboard enum stand-in exists); the family-level classifier
        // here is the A3HB-aware path.
        assert_eq!(
            crate::hashboards::classify_by_eeprom_preamble([0x01, 0x41]),
            None
        );
    }

    /// Regression pin: the legacy `Hashboard` enum has 21 catalog entries after
    /// adding the official-guide-backed S15 host-data row; canonical EEPROM
    /// routing remains intact. The topology registry is additive.
    #[test]
    fn legacy_enum_catalog_is_unchanged_by_the_registry() {
        assert_eq!(ALL_HASHBOARDS.len(), 21);
        assert_eq!(
            crate::hashboards::classify_by_eeprom_preamble([0x04, 0x11]),
            Some(Hashboard::Bhb42601)
        );
        assert_eq!(
            crate::hashboards::classify_by_eeprom_preamble([0x05, 0x11]),
            Some(Hashboard::Bhb56902)
        );
        assert_eq!(Hashboard::Bhb56902.catalog().chips_per_chain, 77);
        assert_eq!(Hashboard::Bhb42801.catalog().chips_per_chain, 88);
    }
}
